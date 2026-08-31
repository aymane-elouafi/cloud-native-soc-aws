# Detection Engineering

The core of the project. These are the **live rules and decoders** exported from the Wazuh manager
(`/var/ossec/etc/rules` and `/var/ossec/etc/decoders`).

## The decoder-first principle

In this Wazuh deployment the built-in generic `json` decoder matches JSON events *by name* but does
**not** reliably populate nested fields — so any rule using `<field name="...">` never fires. The fix,
applied across the whole project, is that **every JSON source gets its own dedicated decoder** that
force-runs the JSON plugin and flattens the object to dot-notation (`transaction.request.uri`,
`aws.userIdentity.type`, …). All of them live in [`decoders/0006-json_decoders.xml`](decoders/0006-json_decoders.xml):

| Decoder | Source | Matches on |
|---|---|---|
| `modsecurity_decoder` | ModSecurity WAF audit log | `{"transaction":…}` |
| `aws_cloudtrail_json` | CloudTrail (via aws-s3 wodle) | `integration:"aws"` |
| `docker_listener_json` | Wazuh Docker listener wodle | `integration:"docker"` |
| `finance_portal` | Scenario 3 internal finance portal | `integration:"finance_portal"` |
| `finance_reporting_json` | Scenario 2 Finance Ops Hub (SSRF app) | `integration:"finance_reporting_portal"` |
| `serverless_report` | Scenario 4 Lambda app logs | `integration:"scenario3_serverless"` |

## Rules, by scenario

| Folder | File | Covers |
|---|---|---|
| `rules/scenario1-web/` | `web_attack_rules.xml` | ModSecurity SQLi/NoSQLi/XSS/SSRF/LFI/XXE + brute-force + per-source correlation |
| `rules/scenario2-ssrf-s3/` | `scenario2_ssrf_imds.xml` | SSRF → IMDS access → S3 object read |
| `rules/scenario3-container-iam/` | `scenario3_ssti_rce.xml`, `scenario3_docker_runtime.xml`, `scenario3_finance_portal.xml` | SSTI/RCE, Docker-socket abuse, finance-portal auth/brute-force |
| `rules/scenario4-serverless/` | `scenario4_confused_deputy.xml`, `scenario4_lambda_app_rules.xml` | confused-deputy Secrets-Manager read, Lambda app-log detections |
| `rules/cloud-cloudtrail/` | `cloudtrail_rules.xml` | shared CloudTrail: AssumeRole, CreatePolicyVersion, S3 GetObject, SSM, GetSecretValue |

Every rule carries `<mitre><id>…</id></mitre>` metadata, and correlation/critical rules are tagged
`soar_candidate` so the SOAR pipeline only triages what matters.

## Install (Wazuh manager)

```bash
# copy decoders and rules into the manager, then restart
sudo cp decoders/*.xml     /var/ossec/etc/decoders/
sudo cp rules/**/*.xml      /var/ossec/etc/rules/
sudo /var/ossec/bin/wazuh-control restart
# validate a sample event
/var/ossec/bin/wazuh-logtest
```

## Gotcha worth knowing

`ossec.conf.redacted.xml` shows the `aws-s3` wodle (CloudTrail bucket + CloudWatch-Logs service) and
the Shuffle integration. **CloudTrail writes global-service events (IAM, STS) to `us-east-1`
regardless of the account's Region** — the wodle's `<regions>` must include `us-east-1` or all IAM/STS
detection silently fails. (AWS keys, the webhook token, and passwords are redacted in that file.)
