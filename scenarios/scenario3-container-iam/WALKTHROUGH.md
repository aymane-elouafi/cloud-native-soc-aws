# Scenario 3 — SSTI → Container Escape → Host → Full Cloud Compromise

**Complete technical documentation: attack chain, vulnerabilities, environment, IAM, detection, and decoders.**

> Lab / training simulation. AWS account `819404925444`, region `eu-north-1`. All
> credentials shown below are disposable lab values; the real AWS access keys and
> secret keys are masked in this document.

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Environment & architecture](#2-environment--architecture)
3. [IAM: roles, policies, users](#3-iam-roles-policies-users)
4. [The vulnerabilities that made the chain possible](#4-the-vulnerabilities-that-made-the-chain-possible)
5. [The attack chain, step by step](#5-the-attack-chain-step-by-step)
6. [Detection architecture — four telemetry layers](#6-detection-architecture--four-telemetry-layers)
7. [Decoders — how Wazuh extracts fields](#7-decoders--how-wazuh-extracts-fields)
8. [Detection rules — every rule explained](#8-detection-rules--every-rule-explained)
9. [Three infrastructure gotchas we solved](#9-three-infrastructure-gotchas-we-solved)
10. [The attack automation script](#10-the-attack-automation-script)
11. [Remediation summary](#11-remediation-summary)

---

## 1. Executive summary

Scenario 3 is the "everything chained together" scenario. A single Server-Side
Template Injection (SSTI) vulnerability in an internet-facing web application is
leveraged, one step at a time, all the way to full cloud-account compromise and
theft of confidential financial data from an isolated internal host.

The full kill chain:

```
SSTI (web)                 → Server-side JS execution in the Juice Shop container
  → RCE                    → Arbitrary Node.js code execution
  → Container recon        → Attacker discovers it's inside a container
  → Docker socket abuse    → /var/run/docker.sock is mounted into the container
  → Container escape       → New container mounts host /etc/passwd (root on host)
  → IMDS credential theft  → host-network container steals the EC2 role's AWS creds
  → Cloud identity pivot   → Attacker now acts as the EC2 IAM role
  → IAM privilege escalation → Role rewrites its own policy to admin (*:*)
  → Cloud reconnaissance   → Enumerate users, instances, SSM targets
  → Lateral movement (SSM) → Port-forward into an isolated internal EC2
  → Finance portal breach  → Brute-force login → exfiltrate confidential finance data
```

Every stage of this chain is detected, across **four independent telemetry
sources**: the ModSecurity WAF, the Docker daemon event stream, AWS CloudTrail,
and the finance portal's own auth log. Detection was validated live end-to-end.

---

## 2. Environment & architecture

Three EC2 instances in the same AWS VPC, plus supporting cloud services.

| Instance ID | Name | Private IP | Role in scenario |
|---|---|---|---|
| `i-01e8ec10a4cfc7577` | **Target-VM-JuiceShop** | `10.0.1.28` | The entry point. Runs OWASP Juice Shop in Docker behind an nginx + ModSecurity WAF. This is where SSTI → RCE → container escape happens. |
| `i-06d2264262a773d3e` | **Reporting-EC2** | `10.0.3.54` | The internal, isolated target. Runs the Finance Reporting Portal (`127.0.0.1:8080`, not network-exposed). Reached only via SSM lateral movement. |
| `i-008a02eb91a200d00` | **SOC-VM-Stack** | `10.0.2.107` | The defensive stack: Wazuh manager/indexer/dashboard, Shuffle SOAR, DFIR-IRIS, Cortex — all in Docker. |

### Target-VM-JuiceShop (`ip-10-0-1-28`) — how it's set up to be exploitable

- **OWASP Juice Shop** runs as a Docker container. Its `/profile` route is
  server-rendered with a Pug template — the SSTI sink.
- **The Docker socket (`/var/run/docker.sock`) is mounted into the Juice Shop
  container.** This is the single most dangerous misconfiguration: it gives any
  code inside the container root-equivalent control of the host's Docker daemon.
  Observed socket permissions: `mode 660, uid 0, gid 986` (the `docker` group).
- **nginx + ModSecurity (OWASP CRS v4)** sit in front of Juice Shop as a WAF,
  in **DetectionOnly** mode (it logs but does not block — so the lab can observe
  the full attack). Audit log: `/var/log/modsec_audit.log` (JSON format).
- **Instance Metadata Service (IMDS):** the instance profile attaches the
  `Scenario3-Ec2-S3Reader` role. For Scenario 3 the instance is set to
  **IMDSv2-required** (`HttpTokens=required`, `HttpPutResponseHopLimit=2`,
  `HttpEndpoint=enabled`). This is deliberate — Scenario 3 demonstrates that
  IMDSv2 hardening is defeated anyway, because a `NetworkMode:host` container
  shares the instance's network stack and can complete the IMDSv2 token
  handshake normally. (Scenario 2, by contrast, was the IMDSv1-misconfiguration
  story.)
- **Wazuh agent** ships: nginx access/error logs, the ModSecurity audit log,
  and (crucially for Scenario 3) it runs the **`docker-listener` wodle**, which
  subscribes to the Docker daemon's event API and forwards container/image
  lifecycle events to the Wazuh manager.

### Reporting-EC2 (`ip-10-0-3-54`) — the internal target

- Runs `/opt/finance-portal/app.py` (a Flask app) as the `finance-portal.service`
  systemd unit, bound to **`127.0.0.1:8080` only** (localhost — not reachable
  from the network). This is why the attacker *must* use SSM port-forwarding to
  reach it.
- Pulls its database credentials from **AWS Secrets Manager**
  (`ScenarioChain/FinanceRdsReader`) and queries an **RDS MySQL** database
  (`finance_lab`, table `finance_records`) for the dashboard.
- Logs every login attempt as JSON to **`/var/log/finance-portal/auth.json`**
  (the source for the `finance_portal` decoder).
- Is **SSM-managed** (has the SSM agent + `AmazonSSMManagedInstanceCore`), which
  is what makes the SSM port-forwarding lateral movement possible.

### Cloud services in play

- **AWS CloudTrail** — trail `Scenario3-Security-Trail` (multi-region), delivering
  logs to the S3 bucket `aws-cloudtrail-logs-819404925444-7b6d1cf3`. This is the
  telemetry for all the cloud-layer detection (identity pivot, IAM escalation,
  SSM lateral movement). **Data-event logging** is enabled but narrowly scoped:
  only `GetObject` on `company-internal-data-lab/confidential-data/`.
- **Amazon S3** — bucket `company-internal-data-lab` holds
  `confidential-data/super_secret.txt` (the "crown jewel" for the Scenario 2
  overlap; Scenario 3 focuses past it).
- **AWS Secrets Manager** — `ScenarioChain/FinanceRdsReader` (finance DB creds).
- **Amazon RDS (MySQL)** — the `finance_lab` database behind the portal.
- **AWS Systems Manager (SSM)** — used by the attacker for `StartSession`
  port-forwarding into the internal Reporting-EC2.

---

## 3. IAM: roles, policies, users

The IAM design *is* the vulnerability for the cloud half of this scenario.

### Roles

| Role | Attached to | Policies | Purpose |
|---|---|---|---|
| **`Scenario3-Ec2-S3Reader`** | Target-VM-JuiceShop instance profile | `Scenario3-S3ReadOnly` + **`Priv-EscalationPolicy`** | The role the attacker **steals via IMDS**. Its second policy is the privilege-escalation flaw. |
| **`ReportingRole`** | Reporting-EC2 instance profile | `AmazonSSMManagedInstanceCore` + `ReadFinanceRdsSecret` (inline) | Lets the internal host be SSM-managed and read the finance DB secret. |
| `AuditWorkerRole`, `ReportApiRole`, `Vulnerable-Invoice-Generator-role` | Lambda | — | Serverless (Scenario 4) infrastructure; not exercised here. |

### Policies

**`Scenario3-S3ReadOnly`** (least-privilege S3 read — *not* the flaw):
- `s3:ListAllMyBuckets` (bucket discovery)
- `s3:ListBucket` on `company-internal-data-lab`, restricted to the
  `confidential-data` prefix via a condition
- `s3:GetObject` on `company-internal-data-lab/confidential-data/*`

**`Priv-EscalationPolicy`** — **the privilege-escalation vulnerability.** Two
statements:
1. `AllowRolePolicyEnumeration`: `iam:ListAttachedRolePolicies` on the
   `Scenario3-Ec2-S3Reader` role.
2. `AllowManagingThisPolicyVersions`: `iam:GetPolicy`, `GetPolicyVersion`,
   `ListPolicyVersions`, **`CreatePolicyVersion`**, **`SetDefaultPolicyVersion`**,
   `DeletePolicyVersion` — **on itself** (`arn:aws:iam::819404925444:policy/Priv-EscalationPolicy`).

That self-referential permission is the entire flaw: the role is allowed to
*rewrite its own permissions*. The attacker creates a new version of the policy
containing `{"Action":"*","Resource":"*"}` and sets it as default — instantly
becoming account admin. During testing the policy went from `v2` (the narrow,
intended baseline / default) to `v6` (the injected `*:*` admin version), then was
reverted back to `v2`.

**`Wazuh-Read-Scenario3-CloudTrail`** — read access for the log-shipping user
(see below). Despite the scenario-specific *name*, it actually grants
`s3:ListBucket` + `s3:GetObject` across the **entire** CloudTrail bucket
(`AWSLogs/*`), all regions. (Worth renaming to something region/scenario-neutral;
the misleading name caused confusion during troubleshooting.)

### Users

| User | Type | Purpose |
|---|---|---|
| `soc-admin` | IAMUser | Lab operator / admin identity. **Not used by the attack** (only for lab housekeeping like pruning old policy versions). |
| `wazuh-cloudtrail-reader` | IAMUser (access key `AKIA…MASKED`) | The identity the Wazuh `aws-s3` wodle uses to read the CloudTrail bucket. Has `Wazuh-Read-Scenario3-CloudTrail` + an inline `WazuhReadScenario3LambdaLogs` (CloudWatch Logs read for Scenario 4 Lambda log groups). |
| `crc-builder` | IAMUser | Lab build identity. |

---

## 4. The vulnerabilities that made the chain possible

Each link in the chain is a distinct, real-world misconfiguration or flaw:

| # | Vulnerability | Enables |
|---|---|---|
| 1 | **SSTI** in Juice Shop `/profile` username (server-side Pug template renders attacker input) | Initial server-side code execution |
| 2 | **No egress/allow-listing** on the app; the template engine exposes full Node.js (`global.process.mainModule.require`) | SSTI escalates to arbitrary RCE |
| 3 | **Docker socket mounted into the app container** (`/var/run/docker.sock`, group-readable) | The container escape — this is the crux |
| 4 | **Docker socket = root on host**: the daemon can create containers that mount any host path or join the host network | Reading host `/etc/passwd`; host-network access |
| 5 | **IMDS reachable from a host-network container** — even IMDSv2-required is defeated because `NetworkMode:host` shares the instance's network stack | Theft of the EC2 role's temporary AWS credentials |
| 6 | **Self-managing IAM policy** (`Priv-EscalationPolicy` lets the role rewrite its own permissions) | Privilege escalation to account admin |
| 7 | **SSM Session Manager** available + over-broad post-escalation permissions | Lateral movement (port-forward) into an isolated internal host with no inbound network exposure |
| 8 | **Finance portal weaknesses**: hardcoded default credentials (`finance_admin`/`finance2026`), no rate limiting or account lockout, weak default Flask `secret_key` | Trivial brute-force → data breach |

The lesson the scenario teaches: **no single control would have stopped this.**
SSTI prevention, IMDSv2 enforcement, least-privilege IAM, container-socket
hardening, and internal-host monitoring must all be in place — defense in depth.

---

## 5. The attack chain, step by step

All web steps are delivered through the **same mechanism**: the payload is stored
as the profile "username" (`POST /profile`), then `GET /profile` renders the
server-side Pug template and *executes* the embedded JavaScript, reflecting the
result back in the HTML. Attacker source IP throughout: `100.92.188.8`.

### Phase A — SSTI → RCE

| Step | Payload (abridged) | Result |
|---|---|---|
| `ssti-probe` | `#{6*6}` | Renders `36` — confirms template injection |
| `ssti-procinfo` | `#{JSON.stringify({uid:...getuid()...})}` | `{"uid":65532,"gid":65532,"cwd":"/juice-shop","node":"v24.17.0","platform":"linux"}` |
| `rce-proof` | `#{...child_process').execFileSync('/nodejs/bin/node',['-e','console.log("RCE_OK:"+...')...}` | Prints `RCE_OK:v24.17.0:/juice-shop` — proven arbitrary process execution |

*Note:* traditional `id`-style binaries weren't reliable inside the container, so
the attacker spawned the existing Node.js binary with `-e` to run arbitrary JS —
still full RCE.

### Phase B — Container reconnaissance

The attacker confirms it's inside a container and maps the host:

- `#{...fs.existsSync('/.dockerenv')...}` → `true`
- `#{...readFileSync('/proc/1/cgroup')...}` → containerd/overlayfs paths
- `#{...readFileSync('/proc/self/mountinfo')...}` → **reveals `/var/run/docker.sock` is mounted in**, plus overlayfs and container layout
- `#{...os.networkInterfaces()...}` → `eth0 172.17.0.2` (Docker bridge)
- `#{...Object.keys(process.env)...}` → environment inventory

### Phase C — Docker socket / API probe

- `#{...statSync('/var/run/docker.sock')...}` → `{exists:true, isSocket:true, mode:"660", uid:0, gid:986}`
- `#{...http.request({socketPath:'/var/run/docker.sock', path:'/version'})...}` → Docker Engine `29.6.1`, API `1.55` — the daemon answers
- `#{...path:'/containers/json'...}` → lists running containers → confirms full Docker API access from inside the container

### Phase D — Container escape (host filesystem read)

This is the escape. Using the Docker API over the socket:

1. `docker-pull-alpine` — `POST /images/create?fromImage=alpine&tag=3.20`
2. `docker-create-pp` — create a container named `pp` from `alpine`, with
   **`HostConfig:{Binds:['/etc/passwd:/p:ro']}`** — mounting the **host's**
   `/etc/passwd` into the container.
3. `docker-start-pp` — `POST /containers/pp/start` (returns `204`)
4. `docker-logs-pp` — read the container's logs (it ran `cat /p`) →
   **the host's `/etc/passwd`** is exfiltrated (`root:x:0:0:...`, plus `ubuntu`,
   `wazuh`, `ec2-instance-connect` — confirming this is the host, not the
   container). The attacker now has arbitrary read of the host filesystem.

### Phase E — IMDS credential theft (from a host-network container)

1. `docker-imds-create` — create `imds-v2-creds-proof` from `curlimages/curl`,
   with **`HostConfig:{NetworkMode:'host'}`**, running an IMDSv2 handshake:
   ```
   TOKEN=$(curl -X PUT .../latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
   ROLE=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" .../iam/security-credentials/)
   curl -H "X-aws-ec2-metadata-token: $TOKEN" .../iam/security-credentials/$ROLE
   ```
2. `docker-imds-start` / `docker-imds-logs` → the container's logs contain
   `Role=Scenario3-Ec2-S3Reader` and the **temporary AWS credentials**
   (`AccessKeyId` / `SecretAccessKey` / `Token`). **IMDSv2 being enforced did not
   help** — host-network mode put the container on the instance's own network
   stack, so the token handshake worked normally.

### Phase F — Cloud abuse & privilege escalation

Now running as the stolen role (`arn:aws:sts::819404925444:assumed-role/Scenario3-Ec2-S3Reader/i-01e8ec10a4cfc7577`):

1. `sts get-caller-identity` — the **identity pivot**: AWS confirms the session is
   the EC2 role, not a human.
2. `iam list-attached-role-policies` + `iam get-policy` — recon that finds
   `Priv-EscalationPolicy` and its current default `v2`.
3. **`iam create-policy-version --set-as-default`** with an admin document
   (`{"Action":"*","Resource":"*"}`) — **the privilege escalation.** The role is
   now account admin. (Before escalation, `iam list-users` returns AccessDenied;
   after, it succeeds — proving the escalation took effect. IAM changes are
   eventually consistent, so a short readiness wait is needed.)
4. `iam list-users`, `ec2 describe-instances`, `ssm describe-instance-information`
   — admin-level reconnaissance. Discovers the three instances (including
   `Reporting-EC2 / 10.0.3.54`) and that it's SSM-managed.

### Phase G — Lateral movement & the data breach

1. **`aws ssm start-session --document-name AWS-StartPortForwardingSession`** to
   `i-06d2264262a773d3e`, forwarding remote `8080` → local `8080`. This tunnels
   into the internal Finance Portal *without any inbound network exposure* — SSM
   rides the outbound SSM agent connection.
2. **Brute-force** `finance_admin` against `http://127.0.0.1:8080/login` →
   password `finance2026`.
3. **Access the dashboard** → confidential department finance records exfiltrated.
4. (Attacker covers tracks: `iam set-default-policy-version` back to `v2` — which
   the now-admin stolen role can do itself.)

---

## 6. Detection architecture — four telemetry layers

The power of the detection is that it does not rely on any single sensor. The
same attack is caught independently at four different points, so bypassing one
layer does not blind the SOC:

| Layer | Sensor | Log source | Catches |
|---|---|---|---|
| **Web / WAF** | ModSecurity (OWASP CRS) | `/var/log/modsec_audit.log` | The *attempt* — SSTI, RCE, docker-API payloads, escape payloads |
| **Container runtime** | Wazuh `docker-listener` wodle | Docker daemon events API | The *confirmation* — a container was really pulled/created/started on the host |
| **Cloud control plane** | Wazuh `aws-s3` wodle | CloudTrail (eu-north-1 **and us-east-1**) | Identity pivot, IAM escalation, EC2/SSM recon, SSM lateral movement |
| **Internal app** | Finance portal app | `/var/log/finance-portal/auth.json` | The brute-force and successful breach |

The most important design property is the **attempt → confirmation correlation**:
the WAF says "a payload *tried* to create a host-mounted container" (rule 100305)
and the Docker runtime independently says "a container was *actually created and
started*" (rules 100312/100313). Two unrelated sensors describing the same event
is high-confidence detection.

---

## 7. Decoders — how Wazuh extracts fields

### The core problem

In this Wazuh deployment, the built-in generic `json` decoder matches JSON logs
*by name* but does **not** extract their fields into rule-usable variables. The
real base `json` decoder is excluded in `ossec.conf`
(`<decoder_exclude>ruleset/decoders/0006-json_decoders.xml</decoder_exclude>`),
and the copy in the custom decoder dir is effectively a name-only shell. Symptom:
`wazuh-logtest` Phase 2 shows `name: 'json'` with **no fields listed**, so any
rule using `<field name="...">` matches nothing.

### The fix pattern

Every distinct JSON log shape needs its **own** decoder that force-runs the JSON
plugin, placed **inside** `/var/ossec/etc/decoders/0006-json_decoders.xml` (a
decoder in a separate standalone file did not take effect — confirmed the hard
way). The pattern:

```xml
<decoder name="<source>_json">
  <prematch type="pcre2">^\{"<distinctive key>"\s*:\s*"<value>"</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
  <use_own_name>true</use_own_name>
</decoder>
```

`JSON_Decoder` flattens nested objects with dot notation
(e.g. `aws.userIdentity.type`, `docker.Actor.Attributes.name`), which the rules
then match on. Because `use_own_name` renames the decoder, rules must key on a
**field** rather than `<decoded_as>json</decoded_as>`.

### The four decoders used in Scenario 3

| Decoder | Prematch (source) | Produces fields | Feeds rules |
|---|---|---|---|
| **`modsecurity_decoder`** | `^\{"transaction":` (ModSecurity JSON audit log) | `transaction.request.body`, `transaction.client_ip`, `transaction.messages[]` (CRS tags), … | 100301–100306 (WAF) |
| **`docker_listener_json`** | `^\{"integration":"docker"` (docker-listener wodle) | `docker.Type`, `docker.Action`, `docker.Actor.Attributes.image`, `docker.Actor.Attributes.name` | 100311–100314 (runtime) |
| **`aws_cloudtrail_json`** | `^\{"integration":"aws"` (aws-s3 wodle) | `aws.source`, `aws.eventName`, `aws.eventSource`, `aws.userIdentity.type`, `aws.userIdentity.arn`, `aws.requestParameters.*` | 110800–110813 (cloud) |
| **`finance_portal`** | `^\{"integration":"finance_portal"` (portal auth log) | `event_type`, `outcome`, `username`, `source_ip` | 100320–100324 (finance) |

> Historical note: the finance decoder originally used `<parent>json</parent>` +
> a manual `<regex>`. That form **failed** in this deployment because the `json`
> parent is excluded — it was converted to the `plugin_decoder JSON_Decoder`
> pattern above, which is why its rule fields are the flat names
> (`event_type`, not `finance.event_type`).

---

## 8. Detection rules — every rule explained

### 8.1 Web / WAF layer — `scenario3_ssti_rce.xml`

Decoder: `modsecurity_decoder`. All rules **chain off the existing ModSecurity
base rule `100020`** ("ModSecurity JSON audit event from Juice Shop target") —
*not* a new base rule (two base rules for the same event compete, and Wazuh only
follows one; see §9). Rules match on the request **body**, deliberately **not**
on the CRS `attack-ssti` tag, because complex container-create payloads have
nested `{}` that breaks CRS's SSTI regex and therefore never get that tag.

| Rule | Level | What it matches | Meaning |
|---|---|---|---|
| **100301** | 5 | `<match>attack-ssti</match>` | SSTI attempt detected by the WAF (only fires for payloads CRS tags as SSTI). |
| **100302** | 10 | body ~ `child_process\|execFileSync\|execSync\|/nodejs/bin/node` | RCE-capable Node.js payload — actual process-execution keywords (deliberately *not* `global.process`, so recon-only payloads don't over-match). |
| **100303** | 8 | body ~ `/.dockerenv\|/proc/1/cgroup\|/proc/self/mountinfo` | Container-detection reconnaissance. |
| **100304** | 10 | body ~ `docker.sock\|/containers/(create\|json)\|/images/create` | Docker socket / Docker API indicators — an attempt to talk to the daemon. |
| **100305** | **13** | body ~ `HostConfig.{0,25}Binds` | **CRITICAL** — payload tries to create a container with a **host bind mount** (container escape). `soar_candidate`. |
| **100306** | **13** | body ~ `NetworkMode.{0,12}host` | **CRITICAL** — payload tries to create a **host-network** container (metadata/credential vector). `soar_candidate`. |

**Chaining rationale:** 100301/302/303/304/305/306 each chain from `100020`
independently, and the escape rules (100305/306) are level 13 so they win Wazuh's
"highest-level match" selection over the level-10 RCE/docker rules on the same
event. This is what makes the escape-*attempt* surface as the alert rather than
being shadowed by the generic RCE rule.

### 8.2 Container-runtime layer — `scenario3_docker_runtime.xml`

Decoder: `docker_listener_json`. This is the **confirmation** layer — it proves
the Docker action actually happened, regardless of whether the WAF saw the
payload.

| Rule | Level | Matches (`docker.Type` / `docker.Action`) | Meaning |
|---|---|---|---|
| **100310** | 0 | (base) | Docker daemon runtime event. |
| **100311** | 7 | `image` / `pull` | Image pulled on the host (e.g. `alpine`, `curlimages/curl`). |
| **100312** | **10** | `container` / `create` | **CONFIRMED**: a container was created on the host (image + name captured). `soar_candidate` — independently flags an escape even if the WAF was bypassed. |
| **100313** | 10 | `container` / `start` | **CONFIRMED**: container started (name captured). |
| **100314** | 5 | `container` / `die\|kill\|stop\|destroy` | Container exited/stopped/removed. |

### 8.3 Cloud control-plane layer — `cloudtrail_rules.xml`

Decoder: `aws_cloudtrail_json`. General-purpose (keyed on structural fields, not
scenario names). Base rule 110800 fires on any CloudTrail event; 110801 narrows
to **assumed-role** activity (the stolen-credential signal).

| Rule | Level | Matches | Meaning |
|---|---|---|---|
| **110800** | 0 | `aws.source == cloudtrail` | CloudTrail event received. |
| **110801** | 0 | `aws.userIdentity.type == AssumedRole` | API call using temporary assumed-role credentials. |
| **110802** | 3 | `GetCallerIdentity` | Assumed-role session verified its own identity (the pivot). |
| **110803** | 5 | S3 `ListBuckets` | S3 bucket discovery *(Scenario 2 overlap)*. |
| **110804** | 6 | S3 `ListBucket\|ListObjects*` | S3 object enumeration *(overlap)*. |
| **110805** | 10 | S3 `GetObject` | **HIGH** — S3 object read *(overlap)*. `soar_candidate`. |
| **110806** | 5 | IAM `ListUsers\|...\|GetPolicy\|...` | Assumed-role enumerated IAM principals/policies. **Noisy** — see 110820. |
| **110807** | 10 | IAM `CreatePolicyVersion` | **HIGH** — IAM policy version created by assumed-role credentials. |
| **110808** | **14** | 110807 + `requestParameters.setAsDefault == true` | **CRITICAL** — new policy version set as default = **privilege escalation**. `soar_candidate`. |
| **110809** | **14** | IAM `SetDefaultPolicyVersion` | **CRITICAL** — policy default version changed by assumed-role (escalation / track-covering). `soar_candidate`. |
| **110810** | 5 | EC2 `DescribeInstances` | Assumed-role enumerated EC2 instances. |
| **110811** | 5 | SSM `DescribeInstanceInformation` | Assumed-role enumerated SSM-managed instances. |
| **110812** | 10 | SSM `StartSession` | **HIGH** — SSM session started. `soar_candidate`. |
| **110813** | **14** | 110812 + `documentName == AWS-StartPortForwardingSession*` | **CRITICAL** — SSM **port-forwarding** session (lateral movement). `soar_candidate`. |
| **110820** | 0 | 110806 + `aws.userIdentity.arn ~ aws-service-role\|AWSServiceRole\|AWSReservedSSO\|resource-explorer` | **Noise suppression** — mutes benign IAM enumeration by AWS service-linked roles and SSO console sessions, so 110806 only alerts on genuine (attacker) assumed-role recon. |

### 8.4 Internal-app layer — `scenario3_finance_portal.xml`

Decoder: `finance_portal`. Detects the brute-force lateral-movement endpoint.

| Rule | Level | Matches | Meaning |
|---|---|---|---|
| **100320** | 0 | (base, `decoded_as finance_portal`) | Finance Portal event. |
| **100321** | 5 | `event_type=authentication` + `outcome=failure` | Failed login (with username + source IP). |
| **100322** | 5 | `event_type=authentication` + `outcome=success` | Successful login. |
| **100323** | **12** | 5× 100321 in 60s, `same_field username` | **HIGH** — brute-force attack against the account. |
| **100324** | **14** | 100322 after 5× 100321 (same username), 600s | **CRITICAL** — login **succeeded after repeated failures** = successful brute-force / valid-account compromise. `soar_candidate`. |

---

## 9. Three infrastructure gotchas we solved

Getting this detection working surfaced three genuinely non-obvious problems.
They're documented here (and in the project memory) because each cost real
debugging time and at least the last two recur in Scenario 4.

### 9.1 JSON decoders don't extract fields by default

The generic `json` decoder matches by name but produces no usable fields (the
real base decoder is excluded via `ossec.conf`). **Fix:** a dedicated
`plugin_decoder JSON_Decoder` decoder per JSON source, placed inside
`0006-json_decoders.xml` (not a standalone file). See §7.

### 9.2 ModSecurity rules must chain off the existing base, and can't rely on the SSTI tag

Two subtleties bit us:
- **Competing base rules:** an already-existing base rule (`100020`) captures every
  ModSec event; Wazuh follows only *one* base tree per event, so a second base
  rule (`decoded_as modsecurity_decoder`) with its own children was orphaned and
  never fired. Fix: chain everything off `100020`.
- **Complex payloads don't get `attack-ssti`:** CRS's SSTI rule (934200) uses
  `#{[^}]*?…}` which stops at the first `}`; the container-create payloads have
  nested `{}` and so are never tagged `attack-ssti`. Fix: the RCE/docker/escape
  rules key on the request **body**, not the tag.
- **Sibling-level competition:** RCE (100302, L10) and docker (100304, L10) are
  siblings; when both match, the lower ID wins and the docker rule's escape
  children never evaluate. Fix: root the escape rules (100305/306) at the base at
  **level 13** so they win outright.

### 9.3 CloudTrail: IAM / global-service events go to `us-east-1`

The single biggest gap. **AWS global services (IAM, Organizations, CloudFront,
Route 53, the legacy global STS endpoint) write their CloudTrail events to
`us-east-1` only**, regardless of operating region. The `aws-s3` wodle was
configured `<regions>eu-north-1</regions>`, so it never read
`CloudTrail/us-east-1/` — making the **entire IAM side invisible** (no error,
events just never arrived).

The tell: every `eu-north-1` event fired (STS GetCallerIdentity, EC2, SSM) but
every IAM event was missing (the privilege escalation itself!). STS worked because
AWS CLI v2 uses the *regional* STS endpoint; IAM has no regional endpoint.

**Fix:** add `us-east-1` to the wodle's `<regions>` (both the live
`/var/ossec/etc/ossec.conf` in the container **and** the host template
`wazuh_manager.conf`), then restart. After the fix, 110807/110808/110809 fired
correctly for the escalation. **This applies to Scenario 4 too** (serverless
leans on IAM/STS global events).

> Related tuning: the us-east-1 backfill floods benign IAM-read noise. Rule
> 110806 fired 203× — 173 from `AWSServiceRoleForResourceExplorer` (AWS's own
> automation) vs. 30 from the attacker's role. Rule **110820** suppresses the
> service-role/SSO noise so 110806 only alerts on genuine assumed-role recon.

---

## 10. The attack automation script

`scenario3_attack_runner.py` — a standard-library-only Python script that replays
the entire 7-phase kill chain for repeatable detection testing.

Key properties:
- **Phases A–E** drive the SSTI/RCE/escape/IMDS-theft entirely through the Juice
  Shop `/profile` SSTI (no manual Burp/Kali work).
- **Phase F/G** use the *stolen* role credentials for the cloud abuse — parsed and
  cached from the IMDS-theft step. The destructive privilege escalation is gated
  behind `--escalate` (off by default); a `--restore-policy` reverts it.
- **Self-contained / attacker-realistic:** it needs **no pre-provisioned AWS
  credentials** on the machine it runs from. Everything bootstraps from the IMDS
  theft. The auto-revert uses the *stolen (now-admin)* credentials — exactly as a
  real attacker covering their tracks would — so it works from a clean attacker
  VM with zero `soc-admin` access. (The only `soc-admin` touchpoint left is
  optional lab housekeeping — pruning old policy versions to stay under AWS's
  5-version cap — which soft-skips if unavailable.)
- The SSM tunnel is auto-opened in its own process group and reliably torn down
  (a plain `terminate()` leaks the `session-manager-plugin` child; the script
  kills the whole group).
- The finance brute-force is pure-Python (no hydra dependency) and produces the
  same `finance_portal` failed-login telemetry.

Usage:
```bash
python3 scenario3_attack_runner.py            # A–G, escalation skipped (safe)
python3 scenario3_attack_runner.py --escalate # full chain, auto-reverts at the end
python3 scenario3_attack_runner.py --list     # list all step names
python3 scenario3_attack_runner.py --phase D  # run just one phase
```

Cleanup after a run: `docker rm -f pp imds-v2-creds-proof` on the target host.

---

## 11. Remediation summary

Mapped to the vulnerabilities in §4:

1. **SSTI** — never render user input in a server-side template; use a sandboxed
   or logic-less template engine; validate/encode the username field.
2. **RCE reach** — run the app with a minimal runtime; restrict egress; drop
   dangerous Node globals where possible.
3–4. **Docker socket exposure** — **never mount `/var/run/docker.sock` into an
   application container.** If Docker access is truly required, use a brokered,
   least-privilege proxy (e.g. a socket proxy with an allow-list), never the raw
   socket. Run containers non-root, read-only, with `no-new-privileges`.
5. **IMDS** — enforce IMDSv2 (already done) *and* set the hop limit to 1 for
   containers, and prevent containers from using host networking; consider
   blocking `169.254.169.254` egress from workloads that don't need it.
6. **IAM privilege escalation** — never grant an identity `iam:CreatePolicyVersion`
   / `SetDefaultPolicyVersion` on a policy attached to itself (or on policies at
   all, without tight conditions). Split application roles from any policy-management
   rights. Use permission boundaries.
7. **SSM lateral movement** — scope `ssm:StartSession` tightly; alert on
   `StartPortForwardingSession` (rule 110813 already does); segment the network so
   an admin-equivalent role can't freely reach internal hosts.
8. **Finance portal** — remove hardcoded credentials; add rate limiting + account
   lockout; set a strong `secret_key`; put it behind proper authentication and
   don't rely on network isolation alone.

**Detection posture:** with all four layers deployed and tuned, every stage of
this chain generates at least one alert, the two most dangerous stages (container
escape and IAM escalation) generate CRITICAL (level 13–14) `soar_candidate`
alerts, and the attempt→confirmation correlation across WAF + Docker-runtime gives
high-confidence detection of the escape even if one sensor is bypassed.
