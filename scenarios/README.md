# Attack Scenarios

Each scenario is a self-contained purple-team exercise: a **deliberate misconfiguration**, an
**attack runner** that exploits it end to end, and (in `../detection/`) the Wazuh rules that catch
each stage. Runners target the lab hosts over the private overlay; they are for the isolated lab only.

| # | Folder | What it does | Runner |
|---|--------|--------------|--------|
| 1 | `scenario1-web/` | Web attacks on OWASP Juice Shop (brute force, SQLi, NoSQLi, LFI, SSRF, XSS, XXE) | `scenario1_attack_runner.py` |
| 2 | `scenario2-ssrf-s3/` | SSRF in the **Finance Operations Hub** → IMDSv1 → steal EC2 role → read private S3 | `scenario2_attack_runner.py` (app: `finance_operations_hub.py`) |
| 3 | `scenario3-container-iam/` | SSTI → RCE → Docker-socket escape → host → IMDS theft → IAM privesc → SSM → finance DB | `scenario3_attack_runner.py` (app: `finance_portal_app.py`; helpers: `ssti_finder.py`; see `WALKTHROUGH.md`) |
| 4 | `scenario4-serverless/` | Serverless confused-deputy: low-priv user → API Gateway/Cognito → Lambda deputy reads privileged data | `scenario4_attack_runner.py` (Lambdas: `reportapi_lambda_function.py`, `auditworker_lambda_function.py`) |

**Note:** the finance apps ship with intentionally weak defaults (e.g. `finance_admin` / `finance2026`)
— that weakness is the point of the scenario. Never reuse these values.
