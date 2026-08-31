#!/usr/bin/env python3
"""
SSTI Finder - a small, benign SSTI discovery helper for the lab report.

Purpose:
  - Replay a real HTTP request, usually /profile from OWASP Juice Shop.
  - Replace one parameter with safe template probes.
  - Report whether payloads are reflected, evaluated, or trigger template errors.

This tool does not run shell commands and does not use child_process payloads.
It is meant to document discovery evidence before the controlled exploitation phase.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple


DEFAULT_USER_AGENT = "SSTI-Finder-Lab/1.0"


@dataclass
class Probe:
    name: str
    engine_hint: str
    payload: str
    expected_text: Optional[str] = None
    expected_regex: Optional[str] = None
    error_probe: bool = False
    note: str = ""


@dataclass
class ProbeResult:
    name: str
    engine_hint: str
    payload: str
    status: int
    reflected: bool
    html_encoded_reflection: bool
    confirmed: bool
    suspected: bool
    evidence: str
    note: str


PROBES: List[Probe] = [
    Probe(
        name="pug_node_arithmetic",
        engine_hint="Pug / Node-style",
        payload="#{7*7}",
        expected_text="49",
        note="Arithmetic evaluation inside #{...}.",
    ),
    Probe(
        name="pug_node_process_version",
        engine_hint="Pug / Node-style",
        payload="#{global.process.version}",
        expected_regex=r"v\d+\.\d+\.\d+",
        note="Safe Node runtime fingerprint. Strong evidence of server-side JS template execution.",
    ),
    Probe(
        name="pug_node_process_platform",
        engine_hint="Pug / Node-style",
        payload="#{global.process.platform}",
        expected_regex=r"\b(linux|darwin|win32|freebsd|openbsd)\b",
        note="Safe Node platform fingerprint.",
    ),
    Probe(
        name="jinja_twig_arithmetic",
        engine_hint="Jinja2 / Twig-style",
        payload="{{7*7}}",
        expected_text="49",
        note="Common double-curly arithmetic probe.",
    ),
    Probe(
        name="erb_arithmetic",
        engine_hint="ERB / EJS-style",
        payload="<%= 7*7 %>",
        expected_text="49",
        note="Common ERB/EJS arithmetic probe.",
    ),
    Probe(
        name="freemarker_expression",
        engine_hint="FreeMarker / EL-style",
        payload="${7*7}",
        expected_text="49",
        note="Common ${...} expression probe.",
    ),
    Probe(
        name="template_error_polyglot",
        engine_hint="Generic template error probe",
        payload="<%'${{/#{@}}%>{{",
        error_probe=True,
        note="A 5xx response can indicate template parser interaction.",
    ),
]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_headers(header_args: List[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for item in header_args:
        if ":" not in item:
            raise SystemExit(f"Invalid header {item!r}. Use 'Name: value'.")
        name, value = item.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def split_raw_request(raw: str) -> Tuple[str, str, Dict[str, str], str]:
    raw = raw.replace("\r\n", "\n")
    if "\n\n" in raw:
        head, body = raw.split("\n\n", 1)
    else:
        head, body = raw, ""

    lines = [line for line in head.split("\n") if line.strip()]
    if not lines:
        raise SystemExit("Raw request file is empty.")

    parts = lines[0].split()
    if len(parts) < 2:
        raise SystemExit("Raw request first line must look like: POST /profile HTTP/1.1")

    method = parts[0].upper()
    target = parts[1]
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()

    return method, target, headers, body


def url_from_raw_target(target: str, headers: Dict[str, str], scheme: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    host = headers.get("Host") or headers.get("host")
    if not host:
        raise SystemExit("Raw request uses a relative path but has no Host header.")
    return f"{scheme}://{host}{target}"


def clean_headers(headers: Dict[str, str]) -> Dict[str, str]:
    cleaned = {}
    blocked = {"content-length", "connection", "accept-encoding"}
    for key, value in headers.items():
        if key.lower() in blocked:
            continue
        cleaned[key] = value
    cleaned.setdefault("User-Agent", DEFAULT_USER_AGENT)
    cleaned["Accept-Encoding"] = "identity"
    return cleaned


def update_form_encoded(body: str, param: str, payload: str) -> bytes:
    pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
    found = False
    updated = []
    for key, value in pairs:
        if key == param:
            updated.append((key, payload))
            found = True
        else:
            updated.append((key, value))

    if not found:
        updated.append((param, payload))

    return urllib.parse.urlencode(updated).encode()


def update_url_query(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    found = False
    updated = []
    for key, value in pairs:
        if key == param:
            updated.append((key, payload))
            found = True
        else:
            updated.append((key, value))
    if not found:
        updated.append((param, payload))
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(updated), parsed.fragment)
    )


def make_absolute_url(base_url: str, maybe_path: str) -> str:
    if maybe_path.startswith("http://") or maybe_path.startswith("https://"):
        return maybe_path
    return urllib.parse.urljoin(base_url, maybe_path)


def fetch_url(
    url: str,
    headers: Dict[str, str],
    timeout: float,
    follow_redirects: bool,
) -> Tuple[int, str, str]:
    get_headers = {
        key: value
        for key, value in headers.items()
        if key.lower() not in {"content-type", "content-length"}
    }
    req = urllib.request.Request(url, headers=get_headers, method="GET")
    opener = urllib.request.build_opener() if follow_redirects else urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.getcode(), raw.decode("utf-8", errors="replace"), resp.geturl()
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, raw.decode("utf-8", errors="replace"), url


def request_once(
    url: str,
    method: str,
    headers: Dict[str, str],
    body_template: str,
    param: str,
    payload: str,
    timeout: float,
    follow_redirects: bool,
    confirm_url: Optional[str] = None,
) -> Tuple[int, str, str]:
    method = method.upper()
    data: Optional[bytes] = None
    request_url = url
    request_headers = dict(headers)

    if method == "GET":
        request_url = update_url_query(url, param, payload)
    else:
        data = update_form_encoded(body_template, param, payload)
        request_headers["Content-Type"] = request_headers.get(
            "Content-Type", "application/x-www-form-urlencoded"
        )

    req = urllib.request.Request(request_url, data=data, headers=request_headers, method=method)

    # If confirm_url is set, do not follow the first response automatically.
    # This models apps like Juice Shop where POST /profile returns 302 and
    # the actual rendered evidence appears on the next GET /profile page.
    opener = (
        urllib.request.build_opener(NoRedirect)
        if confirm_url
        else urllib.request.build_opener()
        if follow_redirects
        else urllib.request.build_opener(NoRedirect)
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read()
            final_url = resp.geturl()
            first_result = resp.getcode(), raw.decode("utf-8", errors="replace"), final_url
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        first_result = exc.code, raw.decode("utf-8", errors="replace"), request_url
    except urllib.error.URLError as exc:
        raise RuntimeError(str(exc)) from exc

    if confirm_url:
        return fetch_url(
            make_absolute_url(url, confirm_url),
            headers=headers,
            timeout=timeout,
            follow_redirects=follow_redirects,
        )

    return first_result


def visible_text(response_text: str) -> str:
    no_script = re.sub(r"(?is)<(script|style).*?</\1>", " ", response_text)
    no_tags = re.sub(r"(?s)<[^>]+>", " ", no_script)
    unescaped = html.unescape(no_tags)
    return re.sub(r"\s+", " ", unescaped).strip()


def make_snippet(text: str, needles: List[str], width: int = 180) -> str:
    flat = visible_text(text)
    if not flat:
        flat = text[:width].replace("\n", " ")

    positions = []
    lowered = flat.lower()
    for needle in needles:
        if not needle:
            continue
        pos = lowered.find(needle.lower())
        if pos >= 0:
            positions.append(pos)

    if positions:
        pos = min(positions)
        start = max(pos - width // 2, 0)
        end = min(pos + width // 2, len(flat))
        return flat[start:end]
    return flat[:width]


def analyze_probe(probe: Probe, status: int, body: str) -> ProbeResult:
    escaped_payload = html.escape(probe.payload, quote=True)
    reflected = probe.payload in body or probe.payload in visible_text(body)
    html_encoded_reflection = escaped_payload in body or escaped_payload in visible_text(body)

    confirmed = False
    suspected = False
    evidence = ""
    needles: List[str] = []

    if probe.expected_text and probe.expected_text in visible_text(body):
        confirmed = True
        needles.append(probe.expected_text)
        evidence = f"Expected value {probe.expected_text!r} appeared in response."

    if probe.expected_regex:
        match = re.search(probe.expected_regex, visible_text(body), flags=re.IGNORECASE)
        if match:
            confirmed = True
            needles.append(match.group(0))
            evidence = f"Expected pattern {probe.expected_regex!r} matched {match.group(0)!r}."

    if probe.error_probe and status >= 500:
        suspected = True
        evidence = f"Server returned HTTP {status} for template polyglot."

    if not evidence:
        if reflected or html_encoded_reflection:
            evidence = "Payload was reflected, but not proven evaluated."
            needles.append(probe.payload)
            needles.append(escaped_payload)
        else:
            evidence = "No clear evidence in response."

    snippet = make_snippet(body, needles)
    if snippet:
        evidence = f"{evidence} Snippet: {snippet}"

    return ProbeResult(
        name=probe.name,
        engine_hint=probe.engine_hint,
        payload=probe.payload,
        status=status,
        reflected=reflected,
        html_encoded_reflection=html_encoded_reflection,
        confirmed=confirmed,
        suspected=suspected,
        evidence=evidence,
        note=probe.note,
    )


def print_report(
    target: str,
    param: str,
    baseline_reflected: bool,
    results: List[ProbeResult],
    confirm_url: Optional[str] = None,
) -> None:
    confirmed = [r for r in results if r.confirmed]
    suspected = [r for r in results if r.suspected]

    print("\nSSTI Finder - Lab Discovery Report")
    print("=" * 42)
    print(f"Target:     {target}")
    print(f"Parameter:  {param}")
    if confirm_url:
        print(f"Evidence:   follow-up GET {confirm_url}")
    print(f"Reflection: {'yes' if baseline_reflected else 'not observed'}")
    print()

    for result in results:
        if result.confirmed:
            marker = "[CONFIRMED]"
        elif result.suspected:
            marker = "[SUSPECTED]"
        elif result.reflected or result.html_encoded_reflection:
            marker = "[REFLECTED]"
        else:
            marker = "[NO HIT]"
        print(f"{marker:12} {result.name:28} HTTP {result.status}  {result.engine_hint}")
        print(f"             payload: {result.payload}")
        print(f"             evidence: {result.evidence}")

    print()
    if confirmed:
        engines = ", ".join(sorted({r.engine_hint for r in confirmed}))
        print(f"Finding: CONFIRMED SSTI behavior. Strongest hints: {engines}")
    elif suspected:
        print("Finding: SUSPECTED SSTI behavior. The target reacted to template polyglots, but evaluation was not confirmed.")
    else:
        print("Finding: SSTI not confirmed by these safe probes.")

    print("\nReport wording:")
    if confirmed:
        best = confirmed[0]
        print(
            f"The scanner replayed the authenticated request and replaced the '{param}' parameter "
            f"with benign SSTI probes. "
            + (
                f"Because the application redirects after updating the field, the scanner checked "
                f"the follow-up GET page ({confirm_url}) for evidence. "
                if confirm_url
                else ""
            )
            + f"The payload {best.payload!r} produced server-side evidence "
            f"({best.evidence.split(' Snippet: ')[0]}), confirming a server-side template injection."
        )
    elif suspected:
        print(
            f"The scanner replayed the authenticated request and observed abnormal template-parser behavior "
            f"when probing the '{param}' parameter. This justified manual validation in the controlled lab."
        )
    else:
        print(
            f"The scanner did not confirm SSTI for '{param}' with the current request. Verify cookies, URL, "
            "HTTP scheme, and that the parameter is rendered by the application."
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benign SSTI discovery scanner for the controlled OWASP Juice Shop lab."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--raw-request", help="Path to a raw HTTP request file, e.g. profile.req")
    source.add_argument("--url", help="Target URL, e.g. http://100.85.61.41/profile")

    parser.add_argument("--scheme", default="http", choices=["http", "https"], help="Scheme for raw relative requests.")
    parser.add_argument("--method", default="POST", choices=["GET", "POST"], help="HTTP method for --url mode.")
    parser.add_argument("--param", default="username", help="Parameter to replace with SSTI probes.")
    parser.add_argument("--data", default="", help="Form body for --url POST mode, e.g. 'email=a@a&username=test'.")
    parser.add_argument("--header", action="append", default=[], help="Extra header, format 'Name: value'.")
    parser.add_argument("--cookie", default="", help="Cookie header value for --url mode.")
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds.")
    parser.add_argument("--delay", type=float, default=0.4, help="Delay between probes in seconds.")
    parser.add_argument("--no-follow-redirects", action="store_true", help="Do not follow HTTP redirects.")
    parser.add_argument(
        "--confirm-url",
        help=(
            "Optional GET path/URL to fetch after each probe, e.g. /profile. "
            "Use this when POST returns 302 and the evidence appears on the next page."
        ),
    )
    parser.add_argument("--json-out", help="Optional path to write JSON evidence.")
    args = parser.parse_args()

    if args.raw_request:
        with open(args.raw_request, "r", encoding="utf-8", errors="replace") as handle:
            raw = handle.read()
        method, target, headers, body_template = split_raw_request(raw)
        url = url_from_raw_target(target, headers, args.scheme)
        headers = clean_headers(headers)
    else:
        method = args.method
        url = args.url
        body_template = args.data
        headers = clean_headers(parse_headers(args.header))
        if args.cookie:
            headers["Cookie"] = args.cookie

    baseline_marker = "ssti_finder_baseline_1701"
    try:
        status, body, final_url = request_once(
            url=url,
            method=method,
            headers=headers,
            body_template=body_template,
            param=args.param,
            payload=baseline_marker,
            timeout=args.timeout,
            follow_redirects=not args.no_follow_redirects,
            confirm_url=args.confirm_url,
        )
    except RuntimeError as exc:
        print(f"[ERROR] Baseline request failed: {exc}", file=sys.stderr)
        return 2

    baseline_reflected = baseline_marker in body or baseline_marker in visible_text(body)

    results: List[ProbeResult] = []
    for probe in PROBES:
        time.sleep(max(args.delay, 0))
        try:
            status, probe_body, _ = request_once(
                url=url,
                method=method,
                headers=headers,
                body_template=body_template,
                param=args.param,
                payload=probe.payload,
                timeout=args.timeout,
                follow_redirects=not args.no_follow_redirects,
                confirm_url=args.confirm_url,
            )
        except RuntimeError as exc:
            results.append(
                ProbeResult(
                    name=probe.name,
                    engine_hint=probe.engine_hint,
                    payload=probe.payload,
                    status=0,
                    reflected=False,
                    html_encoded_reflection=False,
                    confirmed=False,
                    suspected=False,
                    evidence=f"Request failed: {exc}",
                    note=probe.note,
                )
            )
            continue

        results.append(analyze_probe(probe, status, probe_body))

    print_report(final_url, args.param, baseline_reflected, results, args.confirm_url)

    if args.json_out:
        data = {
            "target": final_url,
            "parameter": args.param,
            "confirm_url": args.confirm_url,
            "baseline_reflected": baseline_reflected,
            "results": [asdict(result) for result in results],
        }
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
        print(f"\nJSON evidence written to: {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
