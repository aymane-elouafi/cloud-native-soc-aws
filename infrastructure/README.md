# Infrastructure & Lab Configuration

Live configuration from the lab hosts (secrets redacted).

- `iam/` — IAM policy examples: `ec2-trust-policy.json` (who may assume the EC2 role) and
  `scenario3-lab-permissions.json` (a least-privilege, read-only identity policy). See §3.5 of the report.
- `waf/` — the target VM's WAF stack: the Nginx reverse-proxy site (`nginx-juiceshop-site.conf`,
  `modsecurity on` → `proxy_pass 127.0.0.1:3000`), plus `modsecurity.conf` and `modsecurity_includes.conf`
  (engine + OWASP CRS wiring). The full CRS ruleset is upstream OWASP and not vendored here.
- `wazuh-agent/target-vm-ossec.conf` — the Wazuh **agent** config on the target VM: the `localfile`
  blocks that ship the ModSecurity audit log and app logs to the manager.

The lab: one AWS account, one Region, one VPC (`10.0.0.0/16`) split into three subnets — target
(`10.0.1.0/24`), SOC (`10.0.2.0/24`), internal (`10.0.3.0/24`). The account has been decommissioned;
all IDs/credentials shown are lab-only.

- `aws/` — **live AWS configuration** enumerated from the account (IAM users/roles/policies, S3, EC2, Lambda, Cognito, API Gateway, SQS, DynamoDB, Secrets Manager metadata, CloudTrail). See [`aws/README.md`](aws/README.md).
