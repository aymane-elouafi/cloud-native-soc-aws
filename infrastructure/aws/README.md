# Live AWS Configuration

Enumerated read-only from the lab account (`819404925444`, `eu-north-1`) with `aws iam/ec2/rds/... list|describe|get`.
Secret **values** are never dumped (Secrets Manager and RDS are metadata-only, no `get-secret-value`, no passwords);
the account is decommissioned. JSON for every resource is in the sub-folders; this file summarises the model.

## IAM — the heart of the lab

**3 users** (`iam/users.json`), **6 custom roles** (`iam/roles/`), **4 customer-managed policies** (`iam/policies/`).

### Roles (each file has trust policy + attached + inline policies)
| Role | Trusted by | Purpose |
|---|---|---|
| `Scenario3-Ec2-S3Reader` | EC2 service | The over-permissioned host role stolen via IMDS in Scenario 3. Carries **`Priv-EscalationPolicy`** (the privesc primitive) and `Scenario3-S3ReadOnly`. |
| `ReportingRole` | EC2 (internal reporting host) | `AmazonSSMManagedInstanceCore` + inline `ReadFinanceRdsSecret` — SSM-managed host that can read the finance DB secret; the SSM-pivot target in Scenario 3. |
| `FinanceAuditReadRole` | **only** `AuditWorkerRole` | Reads the finance audit secret/DB — the "deputy" whose trust boundary Scenario 4 abuses. |
| `AuditWorkerRole` | Lambda service | The private worker Lambda (`AuditWorker`); the only principal permitted to assume `FinanceAuditReadRole`. |
| `ReportApiRole` | Lambda service | The public front-door Lambda (`ReportApi`), behind API Gateway. |
| `Vulnerable-Invoice-Generator-role-qgv9igyv` | Lambda | Supporting vulnerable reporting/invoice workload. |

### Customer-managed policies (`iam/policies/*.json`) — the deliberate weaknesses
- **`Priv-EscalationPolicy`** (attached to `Scenario3-Ec2-S3Reader`) — allows `iam:CreatePolicyVersion` +
  `iam:SetDefaultPolicyVersion` **on itself**. The classic privilege-escalation primitive: the stolen host role
  rewrites its own policy to `Action:* Resource:*` and becomes account administrator (Scenario 3, step 5).
- **`Scenario3-S3ReadOnly`** — `s3:GetObject` on `company-internal-data-lab/confidential-data/*`: the sensitive
  object the stolen host role reads.
- **`Wazuh-Read-Scenario3-CloudTrail`** — least-privilege, read-only on the CloudTrail log bucket only:
  how the SOC ingests logs without being able to change anything.
- `AWSLambdaBasicExecutionRole-…` — CloudWatch Logs write for the Lambdas.

Trust policies are the other half of the model — e.g. `FinanceAuditReadRole` names **only** `AuditWorkerRole`
as its principal, which is exactly the trust boundary Scenario 4 abuses.

## Other services
- **RDS** (`rds/instances.json`) — `finance-db1`, **MySQL 8.4.9** (`db.t4g.micro`), database `finance`.
  Not publicly accessible, storage-encrypted, reachable only from inside the VPC via its security group. This holds
  the confidential department finance records the internal portal serves (and that Scenario 3 ultimately exfiltrates).
- **S3** (`s3/`) — two buckets: `aws-cloudtrail-logs-…` (audit-log delivery) and `company-internal-data-lab`
  (the sensitive `confidential-data/` object). Both keep **Block Public Access on** — the data is stolen through
  over-permissioned credentials, not a public bucket.
- **EC2 / VPC** (`ec2/`) — 3 instances across the 3 subnets, security groups, VPC/subnets/route tables.
- **Lambda** (`lambda/`) — `ReportApi` (public, behind API Gateway) and `AuditWorker` (private, VPC-attached),
  wired by an SQS event-source mapping. Env vars are ARNs only, no secrets.
- **Cognito** (`cognito/`) — the user pool + `AuditTeam` group used by the serverless auth flow.
- **API Gateway** (`apigateway/`) — the HTTP API fronting `ReportApi` with a JWT authorizer.
- **SQS / DynamoDB** (`sqs/`, `dynamodb/`) — the report queue and `Scenario3-ReportJobs` table.
- **Secrets Manager** (`secretsmanager/secrets-metadata.json`) — **metadata only**, two secrets:
  `ScenarioChain/FinanceRdsReader` (Scenario 3 finance-DB creds the internal portal uses) and
  `Scenario3/FinanceAuditRdsReader` (the Scenario 4 audit-path secret read through the deputy role).
- **CloudTrail** (`cloudtrail/`) — the account trail delivering management events to S3 (the SOC's primary
  cloud detection source; remember global-service events land in `us-east-1`).
