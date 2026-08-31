# Scenario 4 — Serverless Identity Pivot / Confused Deputy

**Complete technical documentation: attack chain, vulnerability, environment, IAM, detection, and decoders.**

> Lab / training simulation. AWS account `819404925444`, region `eu-north-1`. All
> credentials shown below are disposable lab values. This chain is transcribed
> from the scenario design; verify the first run against the live API and
> CloudTrail/CloudWatch before relying on the exact field offsets.
>
> **Naming note:** the source PDF and the Lambda log tag both say
> `scenario3_serverless` / "Scenario 3" — a naming carryover. This is the **4th**
> lab scenario. The detection rules match the names loosely so they survive the
> drift.

---

## Table of contents
1. [Executive summary](#1-executive-summary)
2. [Environment & architecture](#2-environment--architecture)
3. [IAM & the trust boundary](#3-iam--the-trust-boundary)
4. [The vulnerability — a confused deputy](#4-the-vulnerability--a-confused-deputy)
5. [The attack chain, step by step](#5-the-attack-chain-step-by-step)
6. [Detection architecture — two telemetry layers](#6-detection-architecture--two-telemetry-layers)
7. [Decoders](#7-decoders)
8. [Detection rules — every rule explained](#8-detection-rules--every-rule-explained)
9. [The attack automation script](#9-the-attack-automation-script)
10. [Remediation](#10-remediation)

---

## 1. Executive summary

Scenario 4 is the **serverless authorization** scenario. There is no exploit
against the infrastructure — no injection, no stolen credential, no CVE. The
attacker is a legitimate, low-privilege application user who simply **flips one
JSON field** in a request. The backend trusts that field to decide *how
privileged* the work should be, so the request escalates itself.

This is the classic **confused deputy**: a privileged component (the
`AuditWorker` Lambda) performs a sensitive action **on behalf of** a caller who
is not authorized for it, because authorization was delegated to untrusted
client input.

The full path:

```
Cognito user viewer1 (NOT in AuditTeam)
  → API Gateway (JWT authorizer)         → authenticates the user
  → ReportApi Lambda (public front door) → trusts body.requested_scope, queues the job
  → SQS Scenario3-ReportQueue
  → AuditWorker Lambda (private, VPC, over-privileged)
  → STS AssumeRole  FinanceAuditReadRole            ← the identity pivot
  → Secrets Manager GetSecretValue (FinanceAuditRdsReader)
  → RDS  finance_lab.audit_records                  ← restricted data read
  → DynamoDB Scenario3-ReportJobs (result stored)
  → GET /jobs/{jobId}                               ← attacker reads restricted records back
```

The exploit is `requested_scope: "audit"` sent by a user whose Cognito groups do
**not** include `AuditTeam`.

---

## 2. Environment & architecture

A fully serverless report pipeline. The attacker needs **no AWS credentials** —
Cognito `USER_PASSWORD_AUTH` is a public, unauthenticated API, and everything
after login is plain HTTPS against the public API Gateway URL.

| Component | Value | Role in scenario |
|---|---|---|
| Identity | Amazon **Cognito** user pool; user `viewer1`, client id `7m2hap80308jea8phvom23ei13` | Low-privilege front-end user, **not** in the `AuditTeam` group |
| Front door | **API Gateway** HTTP API `https://whc8v11gfa.execute-api.eu-north-1.amazonaws.com` with a **JWT authorizer** | Authenticates callers; rejects unauthenticated requests (401) |
| `ReportApi` Lambda | `reportapi_lambda_function.py` (public) | Reads the JWT claims, **trusts** `body.requested_scope`, writes a job to DynamoDB, enqueues it to SQS |
| Queue | **SQS** `Scenario3-ReportQueue` | Decouples the front door from the worker |
| `AuditWorker` Lambda | `auditworker_lambda_function.py` (private, in VPC) | Consumes the queue; if `requested_scope=="audit"`, runs the **privileged** path |
| Sensitive identity | **STS** → `FinanceAuditReadRole` | The role `AuditWorker` assumes to reach the finance DB secret |
| Secret | **Secrets Manager** `Scenario3/FinanceAuditRdsReader` | Finance-audit RDS credentials |
| Data | **RDS MySQL** `finance_lab.audit_records` | Restricted audit records (`department`, `risk_rating`, `internal_note`, …) |
| Result store | **DynamoDB** `Scenario3-ReportJobs` | Where the job result is written and read back via `GET /jobs/{jobId}` |

Both Lambdas emit one JSON object per log line
(`print(json.dumps(...))`) tagged `integration:"scenario3_serverless"` with a
`component` of `report_api` or `audit_worker` — the source for the
application-layer detection.

---

## 3. IAM & the trust boundary

The IAM design is *correct on paper* — the interesting part is the trust
boundary that the confused deputy walks straight through.

| Role | Trusted by | Purpose |
|---|---|---|
| `ReportApiRole` | Lambda (`ReportApi`) | Front-door permissions: DynamoDB put/get, SQS send |
| `AuditWorkerRole` | Lambda (`AuditWorker`) | Worker permissions: DynamoDB update, **and `sts:AssumeRole` on `FinanceAuditReadRole`** |
| `FinanceAuditReadRole` | **only** `AuditWorkerRole` | Reads the finance-audit secret/DB. Its trust policy names *only* the worker as principal |

The trust chain is deliberately tight: only `AuditWorker` can assume
`FinanceAuditReadRole`. That is exactly what makes this a *confused deputy* and
not a privilege-escalation bug — the attacker never assumes the role; they
**convince the worker to do it for them**. The IAM boundary held; the
application logic didn't.

---

## 4. The vulnerability — a confused deputy

Two places trust user-controlled `requested_scope`:

1. **`ReportApi`** (front door) reads the Cognito group claim and *computes*
   `actor_is_audit_user` — but then queues the job with whatever
   `requested_scope` the client sent, **without enforcing** that only audit users
   may request the `audit` scope. (It logs the mismatch; it does not block it.)
2. **`AuditWorker`** (backend) sees `requested_scope == "audit"` arriving over
   SQS and runs the privileged path **regardless of who asked** — it never
   re-checks the caller's group.

So authorization is *observed* (the group claim is even computed and logged) but
never *enforced*. A single flipped field turns a low-privilege "standard" report
request into a privileged "audit" one.

---

## 5. The attack chain, step by step

Runner: `scenario4_attack_runner.py`. Phase 0 (auth) always runs first.

| Phase | Action | Expected result |
|---|---|---|
| **0 · auth** | Cognito `USER_PASSWORD_AUTH` for `viewer1` (raw HTTPS to the IDP endpoint) → `AccessToken` | Token acquired, cached ≤50 min. No AWS creds involved. |
| **1 · unauth** | `POST /jobs` with **no** `Authorization` header | **HTTP 401** — the JWT authorizer correctly rejects it (control that *works*) |
| **2 · standard** | `POST /jobs {requested_scope:"standard"}`, then poll `GET /jobs/{jobId}` | Job `COMPLETED` with **0 records** — the sanctioned path |
| **3 · audit (EXPLOIT)** | `POST /jobs {requested_scope:"audit"}` as `viewer1` (not an audit user), then poll `GET /jobs/{jobId}` | Job `COMPLETED` with **restricted audit records** returned to a low-privilege user → **confused deputy confirmed** |

The only difference between the benign Phase 2 and the exploit Phase 3 is the
value `"standard"` → `"audit"`. Nothing else about the request changes.

---

## 6. Detection architecture — two telemetry layers

The two layers are **complementary**, and neither is sufficient alone:

1. **AWS CloudTrail** (`scenario4_confused_deputy.xml`) sees the **privileged
   downstream** the flipped field triggers — `AuditWorkerRole` assuming
   `FinanceAuditReadRole`, then that role reading the secret. These are STS /
   Secrets Manager **management** events (regional), so they arrive *without*
   data-event logging. **But CloudTrail cannot see who asked or what scope** —
   from its point of view the worker is just doing its job.
2. **Lambda application logs** (`scenario4_lambda_app_rules.xml`, via CloudWatch
   Logs) are the **only** place the confused deputy itself is visible: the
   authoritative signal is `component=report_api` **and** `requested_scope=audit`
   **and** `actor_is_audit_user=false` — a non-audit user asking for audit.

So CloudTrail proves the privileged action *happened*; the app log proves it was
*requested by someone who shouldn't have*. Correlating them is the full story.

---

## 7. Decoders

| Decoder | Source | Matches on | Key fields |
|---|---|---|---|
| `aws_cloudtrail_json` | CloudTrail (via `aws-s3` wodle) | `integration:"aws"` | `aws.eventSource`, `aws.eventName`, `aws.requestParameters.roleArn`, `…secretId` |
| `serverless_report` | ReportApi / AuditWorker CloudWatch logs | `integration:"scenario3_serverless"` | `component`, `event_type`, `requested_scope`, `actor_is_audit_user`, `record_count` |

**Prerequisite for the app layer:** a CloudWatch-Logs source in `ossec.conf`
(a `<service type="cloudwatchlogs">` inside the `aws-s3` wodle) for the
`/aws/lambda/ReportApi` and `/aws/lambda/AuditWorker` log groups. If the module
wraps each raw line in an outer `integration:"aws"` envelope, the decoder offset
may need adjusting against one real archived line.

---

## 8. Detection rules — every rule explained

### CloudTrail layer — `scenario4_confused_deputy.xml` (110830–110836)
| Rule | Level | Fires when | ATT&CK |
|---|---|---|---|
| `110830` | 10 | A role assumed **`FinanceAuditReadRole`** (the identity pivot, `soar_candidate`) | T1548, T1550.001 |
| `110831` | 12 | `GetSecretValue` on **`FinanceAuditRdsReader`** (`soar_candidate`) | T1552.005, T1555.006 |
| `110832` | 14 | **CRITICAL** — 110831 within 3 min of 110830: the confused-deputy chain executed end to end (`soar_candidate`) | T1548, T1552.005 |
| `110835` | 6 | SQS `SendMessage` to `ReportQueue` — *only if data-event logging is on* | — |
| `110836` | 6 | DynamoDB `PutItem`/`UpdateItem` on `ReportJobs` — *only if data-event logging is on* | — |

### Application layer — `scenario4_lambda_app_rules.xml` (110840–110846)
| Rule | Level | Fires when | ATT&CK |
|---|---|---|---|
| `110840` | 0 | Base: any serverless report-pipeline log line | — |
| `110841` | 3 | ReportApi logged a scope request (any scope) | — |
| `110842` | 14 | **CRITICAL** — `requested_scope=audit` **and** `actor_is_audit_user=false` (the confused deputy, `soar_candidate`) | T1548, T1078 |
| `110843` | 4 | Audit scope requested by a genuine `AuditTeam` member (benign baseline) | — |
| `110844` | 10 | AuditWorker started the restricted path for a job (`soar_candidate`) | T1078 |
| `110845` | 12 | **HIGH** — AuditWorker returned N restricted records (`soar_candidate`) | T1213, T1530 |
| `110846` | 13 | Repeated confused-deputy requests from the same `actor_sub` (deliberate abuse, `soar_candidate`) | T1078 |

---

## 9. The attack automation script

`scenario4_attack_runner.py` — standard-library only, no AWS CLI, no `~/.aws`
profile. Runs cleanly from an attacker VM that has never held AWS credentials.

```bash
export COGNITO_LAB_PASSWORD='<viewer1 password>'
python3 scenario4_attack_runner.py              # phases 0→1→2→3
python3 scenario4_attack_runner.py --phase 3    # exploit only (reuses cached token)
python3 scenario4_attack_runner.py --scope audit --dept finance   # custom single job
python3 scenario4_attack_runner.py --list       # list phases
```

- Phase 0 authenticates over raw HTTPS to the Cognito IDP endpoint and caches the
  access token to `.scenario4_token` (chmod 600) for ≤50 minutes.
- The worker is asynchronous (SQS → AuditWorker → DynamoDB), so `submit_and_fetch`
  polls `GET /jobs/{jobId}` up to 8 times until `status=COMPLETED`.
- Side effects: creates report jobs in DynamoDB and drives one SQS message +
  AuditWorker invocation per POST. Nothing is deleted.

---

## 10. Remediation

| Vulnerability | Fix |
|---|---|
| Authorization delegated to client input (`requested_scope`) | **Enforce server-side**: in `ReportApi`, reject the `audit` scope unless `actor_is_audit_user` is true (the value is already computed — gate on it, don't just log it) |
| Worker trusts scope from SQS | Re-derive entitlement in `AuditWorker` from a trusted source (the caller's identity/claims propagated as a signed context), never from a free-text field |
| Over-privileged worker | Split the privileged read behind an explicit, audited authorization step; keep `FinanceAuditReadRole`'s trust to `AuditWorker` **and** require the worker to prove the request was authorized |
| Blind spots in CloudTrail | Enable **data-event logging** for the queue and table so 110835/110836 corroborate the app-layer signal |
| Detection | Keep both layers — the app log is the *only* place the deputy is visible; CloudTrail proves the privileged action ran |
