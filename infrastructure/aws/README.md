# Live AWS Configuration

Enumerated read-only from the lab account (`819404925444`, `eu-north-1`) with `aws iam/ec2/... list|describe|get`.
Secret **values** are never dumped (Secrets Manager is metadata-only); the account is decommissioned.
JSON for every resource is in the sub-folders; this file summarises the model.

## IAM — the heart of the lab

**3 users**, **6 custom roles**, **4 customer-managed policies** (`iam/`).

### Roles (`iam/roles/*.json` — each has trust policy + attached + inline)
| Role | Trusted by | Purpose |
|---|---|---|
| `Scenario3-Ec2-S3Reader` | EC2 service | The over-permissioned host role stolen via IMDS in Scenario 3 |
| `Priv-Escalation…` (via policy) | — | Target of the IAM privilege-escalation step |
| `FinanceAuditReadRole` | **only** `AuditWorkerRole` | Reads the finance secret/DB; the "deputy" of Scenario 4 |
| `AuditWorkerRole` | Lambda service | The private worker Lambda (`AuditWorker`) |
| `ReportApiRole` | Lambda service | The public front-door Lambda (`ReportApi`) |
| `ReportingRole` / `Vulnerable-Invoice-Generator-role` | Lambda/EC2 | Supporting reporting workloads |

### Customer-managed policies (`iam/policies/*.json`) — the deliberate weaknesses
- **`Priv-EscalationPolicy`** — allows `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion` **on itself**.
  This is the classic privilege-escalation primitive: the role can rewrite its own policy to `Action:* Resource:*`
  and become account administrator (Scenario 3, step 5).
- **`Scenario3-S3ReadOnly`** — `s3:GetObject` on `company-internal-data-lab/confidential-data/*`: the sensitive
  object the stolen host role reads.
- **`Wazuh-Read-Scenario3-CloudTrail`** — least-privilege, read-only on the CloudTrail log bucket only:
  how the SOC ingests logs without being able to change anything.
- `AWSLambdaBasicExecutionRole-…` — CloudWatch Logs write for the Lambdas.

Trust policies are the other half of the model — e.g. `FinanceAuditReadRole` names **only** `AuditWorkerRole`
as its principal, which is exactly the trust boundary Scenario 4 abuses.

## Other services
- **S3** (`s3/`) — two buckets: `aws-cloudtrail-logs-…` (audit-log delivery) and `company-internal-data-lab`
  (the sensitive `confidential-data/` object). Both keep **Block Public Access on** — the data is stolen through
  over-permissioned credentials, not a public bucket.
- **EC2 / VPC** (`ec2/`) — 3 instances across the 3 subnets, 9 security groups, VPC/subnets/route tables.
- **Lambda** (`lambda/`) — `ReportApi` (public, behind API Gateway) and `AuditWorker` (private, VPC-attached),
  wired by an SQS event-source mapping (`Scenario3-ReportQueue`). Env vars are ARNs only, no secrets.
- **Cognito** (`cognito/`) — the user pool + `AuditTeam` group used by the serverless auth flow.
- **API Gateway** (`apigateway/`) — the HTTP API fronting `ReportApi` with a JWT authorizer.
- **SQS / DynamoDB** (`sqs/`, `dynamodb/`) — the report queue and `Scenario3-ReportJobs` table.
- **Secrets Manager** (`secretsmanager/`) — `Scenario3/FinanceAuditRdsReader` (RDS creds) — **metadata only**.
- **CloudTrail** (`cloudtrail/`) — the account trail delivering management events to S3 (the SOC's primary
  cloud detection source; remember global-service events land in `us-east-1`).
