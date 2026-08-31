# Scenario 2 — SSRF → IMDSv1 → Stolen Role Credentials → S3 Exfiltration

**Complete technical documentation: attack chain, vulnerability, environment, IAM, detection, and decoders.**

> Lab / training simulation. AWS account `819404925444`, region `eu-north-1`. All
> credentials shown below are disposable lab values; the real AWS access keys and
> secret keys are masked. This chain was exercised against the live target on
> 2026-08-14.

---

## Table of contents
1. [Executive summary](#1-executive-summary)
2. [Environment & architecture](#2-environment--architecture)
3. [IAM: the role that gets stolen](#3-iam-the-role-that-gets-stolen)
4. [The vulnerabilities](#4-the-vulnerabilities)
5. [The attack chain, step by step](#5-the-attack-chain-step-by-step)
6. [Detection architecture — two telemetry layers](#6-detection-architecture--two-telemetry-layers)
7. [Decoders](#7-decoders)
8. [Detection rules — every rule explained](#8-detection-rules--every-rule-explained)
9. [The attack automation script](#9-the-attack-automation-script)
10. [Remediation](#10-remediation)

---

## 1. Executive summary

Scenario 2 is the **cloud-credential-theft** scenario. A single **Server-Side
Request Forgery (SSRF)** flaw in an internet-facing finance web app is used to
reach the EC2 **Instance Metadata Service (IMDS)**, steal the instance role's
temporary AWS credentials, and then use those credentials — directly against the
AWS API — to read a confidential object out of a private S3 bucket.

The full kill chain:

```
SSRF (/api/preview?url=)          → server fetches any URL we give it
  → IMDS role discovery            → GET .../iam/security-credentials/  (role name)
  → IMDS credential theft          → GET .../security-credentials/<role> (AKIA/ASIA + token)
  → [now acting as the EC2 role, off-box, via AWS CLI]
  → STS GetCallerIdentity          → confirm the stolen identity
  → S3 ListBuckets                 → discover buckets
  → S3 ListObjectsV2               → find the confidential object
  → S3 GetObject                   → exfiltrate confidential-data/super_secret.txt
```

The chain is detected across **two independent telemetry sources**: the web
app's own SSRF audit log (catches the theft *as it happens, in the app*), and
AWS CloudTrail (catches the *use* of the stolen credentials against AWS). The
critical, `soar_candidate` alerts are the confirmed credential retrieval
(110704) and the S3 object read (110805).

---

## 2. Environment & architecture

The vulnerable app is the **Finance Operations Hub** (a.k.a. the "Finance
Reporting Portal"), a small Python `http.server` app (`finance_operations_hub.py`)
listening on **port 8090** on the target EC2 instance.

| Component | Value | Role in scenario |
|---|---|---|
| Target instance | `Target-VM-JuiceShop` (`i-01e8ec10a4cfc7577`, `10.0.1.28`) | Runs the Finance Operations Hub on `:8090`. Its instance profile carries the role the attacker steals. |
| App endpoint | `GET /api/preview?url=…` (alias `/fetch`) | **The SSRF sink** — the server fetches whatever URL you pass and returns the body under `preview`. |
| IMDS | `HttpTokens=optional` (**IMDSv1 permitted**) | A plain unauthenticated `GET http://169.254.169.254/…` works — no token handshake required. *This is the scenario-2 misconfiguration.* (Scenario 3 later flips the same instance to IMDSv2-required to show that even that is bypassable via a host-network container.) |
| Instance role | `Scenario3-Ec2-S3Reader` | Reachable via IMDS; grants `s3:GetObject` on the confidential prefix. |
| Crown jewel | `s3://company-internal-data-lab/confidential-data/super_secret.txt` | The private object exfiltrated with the stolen credentials. |
| App audit log | `~/scenario2-ssrf/access.json` (JSON lines, `integration:"finance_reporting_portal"`) | Every preview request/response is logged — the source for the SSRF-layer detection. |

The app disables proxy inheritance (`ProxyHandler({})`) so every preview is a
genuine **direct server-side request**, and it only checks that the URL scheme is
`http`/`https` — it does **not** block link-local / metadata addresses.

---

## 3. IAM: the role that gets stolen

The instance profile attaches **`Scenario3-Ec2-S3Reader`**, whose
`Scenario3-S3ReadOnly` policy grants:
- `s3:ListAllMyBuckets` (bucket discovery),
- `s3:ListBucket` on `company-internal-data-lab` (scoped to the `confidential-data` prefix),
- `s3:GetObject` on `company-internal-data-lab/confidential-data/*`.

That is *technically* a least-privilege S3 read policy — the flaw is not the
policy's breadth but that **its credentials are reachable from a web SSRF** and
that the data behind it is confidential. (The same role also carries
`Priv-EscalationPolicy`, but that is the Scenario 3 story; Scenario 2 stops at
S3 read.)

---

## 4. The vulnerabilities

| # | Vulnerability | Enables |
|---|---|---|
| 1 | **SSRF** in `/api/preview` — fetches any attacker-supplied URL server-side, no host allow-list, link-local not blocked | Reaching `169.254.169.254` from the app |
| 2 | **IMDSv1 permitted** (`HttpTokens=optional`) | Stealing role credentials with a single unauthenticated GET — no token exchange |
| 3 | **Instance role credentials expose real data** (`s3:GetObject` on a confidential prefix) | Turning stolen credentials into a data breach |
| 4 | **Confidential data in S3** with no additional guardrail (no VPC-endpoint restriction, no separate encryption boundary) | Exfiltration succeeds once the role is assumed |

The lesson: SSRF + IMDSv1 + a role that can read real data = full cloud data
breach from an unauthenticated web request. Enforcing **IMDSv2** alone breaks
this specific chain (see Scenario 3 for why IMDSv2 is necessary but not
sufficient).

---

## 5. The attack chain, step by step

Runner: `scenario2_attack_runner.py`. Stage 1 goes **through the app's SSRF**;
Stage 2 uses the **stolen credentials directly** with the real AWS CLI (so the
resulting CloudTrail looks exactly like hand-run `aws s3api …` commands).

### Stage 1 — through the SSRF (in-app)

| Step | Request | Result | Rule |
|---|---|---|---|
| `imds-role-list` | `/api/preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/` | Returns the attached role name (`Scenario3-Ec2-S3Reader`) | **110702** |
| `imds-creds-theft` | `/api/preview?url=…/security-credentials/Scenario3-Ec2-S3Reader` | Returns `AccessKeyId` / `SecretAccessKey` / `Token` (cached locally, chmod 600) | **110703** → **110704** |

Rule 110703 fires on the *request* for a specific role's credentials; **110704**
(CRITICAL, `soar_candidate`) fires when the corresponding
`remote_document_preview_completed` event shows a `2xx` upstream status — i.e.
the credentials were actually returned.

### Stage 2 — using the stolen credentials against AWS (off-box)

| Step | Command | Result | Rule |
|---|---|---|---|
| `sts-whoami` | `aws sts get-caller-identity` | Confirms the session is the assumed instance role | **110802** |
| `s3-buckets` | `aws s3 ls` | Lists buckets (`company-internal-data-lab`, the CloudTrail bucket…) | **110803** |
| `s3-objects` | `aws s3api list-objects-v2 --bucket company-internal-data-lab` | Finds `confidential-data/super_secret.txt` (skips the CloudTrail infra bucket) | **110804** |
| `s3-read` | `aws s3 cp s3://…/confidential-data/super_secret.txt -` | **Exfiltrates the object's bytes** | **110805** |

Rule **110805** (HIGH, `soar_candidate`) is the "data actually left" signal. Every
Stage-2 call is made with temporary `ASIA…` credentials, so CloudTrail tags them
as assumed-role sessions (base rule 110801) — which is exactly what the rules key
on.

---

## 6. Detection architecture — two telemetry layers

1. **Application SSRF log** (`integration:"finance_reporting_portal"`) — the app
   records every preview as `remote_document_preview_requested` /
   `…_completed` / `…_failed` with `client_ip`, `target_url`, `upstream_status`,
   `response_bytes`. This layer sees the **theft as it happens**, before any AWS
   call — it is what catches an SSRF that reaches IMDS even if the stolen
   credentials are never used.
2. **AWS CloudTrail** (`integration:"aws"`, source `cloudtrail`) — sees the
   **use** of the stolen credentials: STS identity check, S3 enumeration, S3
   GetObject. This layer catches the breach even if the app log were unavailable.

Defence-in-depth: either layer alone detects the attack; together they tell the
full story (SSRF origin → cloud data exfiltration).

---

## 7. Decoders

Both layers rely on the **decoder-first principle** — every JSON source gets its
own dedicated decoder in `detection/decoders/0006-json_decoders.xml` (the generic
`json` decoder matches by name but does not extract fields):

| Decoder | Source | Matches on | Key fields |
|---|---|---|---|
| `finance_reporting_json` | Finance Operations Hub SSRF log | `integration:"finance_reporting_portal"` | `event_type`, `target_url`, `upstream_status`, `client_ip` |
| `aws_cloudtrail_json` | CloudTrail (via `aws-s3` wodle) | `integration:"aws"` | `aws.eventSource`, `aws.eventName`, `aws.userIdentity.type` |

---

## 8. Detection rules — every rule explained

### SSRF / IMDS layer (`detection/rules/scenario2-ssrf-s3/scenario2_ssrf_imds.xml`)
| Rule | Level | Fires when | ATT&CK |
|---|---|---|---|
| `110700` | 0 | A server-side fetch targeted `169.254.169.254` (base) | — |
| `110701` | 8 | …reached `/latest/meta-data/` (generic metadata browse, not the creds path) | T1190, T1552.005 |
| `110702` | 9 | …enumerated the IAM role (`security-credentials/`) | T1526 |
| `110703` | 12 | …requested a **specific** role's credentials (`security-credentials/<role>`) | T1552.005 |
| `110704` | 14 | **CRITICAL** — the `_completed` event returned `2xx`: credentials actually retrieved (`soar_candidate`) | T1552.005, T1530 |

### CloudTrail layer (`detection/rules/cloud-cloudtrail/cloudtrail_rules.xml`)
| Rule | Level | Fires when | ATT&CK / group |
|---|---|---|---|
| `110800` / `110801` | 0 | Base: CloudTrail event / assumed-role (temporary) credentials | — |
| `110802` | 3 | Assumed-role session ran `sts:GetCallerIdentity` | discovery |
| `110803` | 5 | …`s3:ListBuckets` | discovery |
| `110804` | 6 | …`s3:ListObjects(V2)` | collection |
| `110805` | 10 | **HIGH** — …`s3:GetObject` (object retrieved, `soar_candidate`) | s3_data_access |

---

## 9. The attack automation script

`scenario2_attack_runner.py` replays the whole chain for repeatable detection
testing.

```bash
python3 scenario2_attack_runner.py                 # full chain (Stage 1 + Stage 2)
python3 scenario2_attack_runner.py --stage1-only   # SSRF/IMDS only, no real AWS calls
python3 scenario2_attack_runner.py imds-creds-theft # a single step
python3 scenario2_attack_runner.py --list          # list step names
```

- **Stage 1** is standard-library only and goes through the app's SSRF endpoint.
  Stolen credentials are cached to `.scenario2_stolen_creds.json` (chmod 600) so
  Stage 2 can run in a separate invocation.
- **Stage 2** requires the `aws` CLI on PATH and makes **real, authenticated**
  calls with the genuinely-stolen temporary credentials — `s3-read` actually
  downloads the object's bytes (discarded, not written to disk). If the role
  can't perform an action, the step logs `AccessDenied` and moves on (a failed
  attempt is still useful detection signal).
- Default inter-step delay is **150 s**, matching the Scenario 1 cadence so the
  SOAR pipeline isn't fired faster than it runs.

---

## 10. Remediation

| Vulnerability | Fix |
|---|---|
| SSRF fetches any URL | Allow-list destination hosts; block link-local/metadata ranges (`169.254.0.0/16`, `fd00:ec2::254`), private ranges, and redirects to them; fetch only through an egress proxy |
| IMDSv1 permitted | Enforce **IMDSv2** (`HttpTokens=required`) and set `HttpPutResponseHopLimit=1` so containers can't reach IMDS |
| Role reads real data | Least-privilege the instance role; separate the confidential data behind a role that a web tier never holds |
| S3 confidential object | Bucket policy restricting access to a VPC endpoint; enable S3 **data-event** CloudTrail logging (already scoped to `confidential-data/` here); consider object-level KMS with a separate key policy |
