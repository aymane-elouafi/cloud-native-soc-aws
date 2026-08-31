#!/usr/bin/env python3

import json
import os
from datetime import datetime, timezone
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, ProxyHandler, build_opener

HOST = "0.0.0.0"
PORT = 8090
LOG_FILE = os.path.expanduser("~/scenario2-ssrf/access.json")

# Disable proxy inheritance so the lab demonstrates direct server-side requests.
opener = build_opener(ProxyHandler({}))


def write_audit(event_type, **fields):
    event = {
        "integration": "finance_reporting_portal",
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **fields,
    }

    with open(LOG_FILE, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")


def dummy_reports():
    return {
        "reports": [
            {
                "id": "FIN-2026-06",
                "name": "Monthly Finance Summary",
                "department": "Finance",
                "status": "Published",
            },
            {
                "id": "TRE-2026-06",
                "name": "Treasury Liquidity Review",
                "department": "Treasury",
                "status": "Published",
            },
            {
                "id": "AUD-2026-06",
                "name": "Internal Audit Findings",
                "department": "Audit",
                "status": "Restricted",
            },
        ]
    }


class Handler(BaseHTTPRequestHandler):

    def send_bytes(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status, payload):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_bytes(status, body, "application/json")

    def send_html(self, html):
        self.send_bytes(200, html.encode("utf-8"), "text/html; charset=utf-8")

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == "/":
            self.send_html(self.dashboard())
            return

        if parsed.path == "/health":
            self.send_json(200, {"status": "ok", "service": "finance-reporting"})
            return

        if parsed.path == "/api/reports":
            self.send_json(200, dummy_reports())
            return

        # Deliberately vulnerable document-preview endpoint.
        if parsed.path in ("/api/preview", "/fetch"):
            target_url = query.get("url", [None])[0]

            if not target_url:
                self.send_json(400, {"error": "A document URL is required"})
                return

            scheme = urlparse(target_url).scheme.lower()

            if scheme not in ("http", "https"):
                self.send_json(400, {"error": "Only HTTP and HTTPS URLs are supported"})
                return

            client_ip = self.client_address[0]

            write_audit(
                "remote_document_preview_requested",
                client_ip=client_ip,
                target_url=target_url,
            )

            try:
                request = Request(
                    target_url,
                    headers={"User-Agent": "FinanceReportPreview/1.0"},
                )

                with opener.open(request, timeout=5) as response:
                    content = response.read(8192)
                    status_code = response.status
                    content_type = response.headers.get_content_type()

                preview = content.decode("utf-8", errors="replace")

                write_audit(
                    "remote_document_preview_completed",
                    client_ip=client_ip,
                    target_url=target_url,
                    upstream_status=status_code,
                    response_bytes=len(content),
                )

                self.send_json(
                    200,
                    {
                        "success": True,
                        "source": target_url,
                        "upstream_status": status_code,
                        "content_type": content_type,
                        "preview": preview,
                    },
                )

            except Exception as error:
                write_audit(
                    "remote_document_preview_failed",
                    client_ip=client_ip,
                    target_url=target_url,
                    error_type=type(error).__name__,
                )

                self.send_json(
                    502,
                    {
                        "success": False,
                        "error": "The remote document could not be retrieved",
                    },
                )

            return

        self.send_json(404, {"error": "Not found"})

    def dashboard(self):
        return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Finance Operations Hub</title>
<style>
:root {
  --bg: #f4f7fb;
  --card: #ffffff;
  --ink: #172033;
  --muted: #6b778c;
  --primary: #174ea6;
  --primary-dark: #103b82;
  --border: #dfe6ef;
  --success: #16845b;
  --warning: #b66a00;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, sans-serif;
}
header {
  background: linear-gradient(120deg, #123d7a, #1768a8);
  color: white;
  padding: 22px 7%;
}
.nav {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.brand {
  font-size: 21px;
  font-weight: 750;
  letter-spacing: .2px;
}
.badge {
  border: 1px solid rgba(255,255,255,.35);
  border-radius: 999px;
  padding: 7px 12px;
  font-size: 12px;
}
main {
  max-width: 1180px;
  margin: 34px auto;
  padding: 0 24px 60px;
}
.hero h1 {
  margin: 0 0 8px;
  font-size: 34px;
}
.hero p {
  color: var(--muted);
  margin: 0 0 25px;
}
.grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
  margin-bottom: 24px;
}
.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 15px;
  padding: 20px;
  box-shadow: 0 6px 18px rgba(28, 52, 84, .05);
}
.metric {
  font-size: 27px;
  font-weight: 750;
  margin-top: 7px;
}
.label {
  color: var(--muted);
  font-size: 13px;
}
.status {
  color: var(--success);
  font-weight: 700;
}
.workspace {
  display: grid;
  grid-template-columns: 1.1fr .9fr;
  gap: 20px;
}
h2 {
  font-size: 20px;
  margin-top: 0;
}
input {
  width: 100%;
  padding: 13px 14px;
  border: 1px solid var(--border);
  border-radius: 9px;
  font-size: 14px;
  margin: 10px 0;
}
button {
  background: var(--primary);
  color: white;
  border: 0;
  border-radius: 9px;
  padding: 12px 17px;
  font-weight: 700;
  cursor: pointer;
}
button:hover { background: var(--primary-dark); }
.quick {
  background: #eef4ff;
  color: var(--primary);
  margin: 5px 5px 5px 0;
  padding: 9px 12px;
}
pre {
  background: #101827;
  color: #d9e5f8;
  border-radius: 10px;
  padding: 16px;
  min-height: 220px;
  overflow: auto;
  white-space: pre-wrap;
  font-size: 12px;
}
.report {
  display: flex;
  justify-content: space-between;
  padding: 13px 0;
  border-bottom: 1px solid var(--border);
}
.restricted { color: var(--warning); font-weight: 700; }
@media (max-width: 800px) {
  .grid, .workspace { grid-template-columns: 1fr; }
}
</style>
</head>
<body>
<header>
  <div class="nav">
    <div class="brand">Northstar Finance Operations</div>
    <div class="badge">Internal reporting platform</div>
  </div>
</header>

<main>
  <section class="hero">
    <h1>Finance Operations Hub</h1>
    <p>Review approved reports and preview documents supplied by internal reporting services.</p>
  </section>

  <section class="grid">
    <div class="card">
      <div class="label">Reporting service</div>
      <div class="metric status">Operational</div>
    </div>
    <div class="card">
      <div class="label">Published reports</div>
      <div class="metric">24</div>
    </div>
    <div class="card">
      <div class="label">Last synchronization</div>
      <div class="metric">09:42 UTC</div>
    </div>
  </section>

  <section class="workspace">
    <div class="card">
      <h2>Remote document preview</h2>
      <p class="label">Preview an approved report URL before attaching it to a finance workflow.</p>
      <input id="target" value="http://127.0.0.1:8090/api/reports">
      <button onclick="preview()">Preview document</button>
      <div>
        <button class="quick" onclick="setTarget('http://127.0.0.1:8090/api/reports')">Report catalog</button>
        <button class="quick" onclick="setTarget('http://127.0.0.1:8090/health')">Service health</button>
      </div>
      <pre id="result">Preview results will appear here.</pre>
    </div>

    <div class="card">
      <h2>Available report sets</h2>
      <div class="report">
        <span>Monthly Finance Summary</span>
        <span class="status">Published</span>
      </div>
      <div class="report">
        <span>Treasury Liquidity Review</span>
        <span class="status">Published</span>
      </div>
      <div class="report">
        <span>Internal Audit Findings</span>
        <span class="restricted">Restricted</span>
      </div>
    </div>
  </section>
</main>

<script>
function setTarget(value) {
  document.getElementById("target").value = value;
}

async function preview() {
  const value = document.getElementById("target").value;
  const result = document.getElementById("result");
  result.textContent = "Fetching preview...";

  try {
    const response = await fetch("/api/preview?url=" + encodeURIComponent(value));
    const data = await response.json();
    result.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    result.textContent = "Preview failed";
  }
}
</script>
</body>
</html>"""


if __name__ == "__main__":
    print(f"Finance reporting portal listening on {HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
