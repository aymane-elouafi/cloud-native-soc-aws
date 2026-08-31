# SOAR + AI + DFIR-IRIS Full Workflow Build

Use this guide to rebuild the Shuffle workflow cleanly from beginning to end.

Do not use the old `v3` or `v4` folders. Use only:

```text
SOAR-AI/FINAL
```

The final objective is:

```text
Wazuh alert
  -> IRIS alert intake
  -> normalized evidence
  -> case correlation
  -> Cortex enrichment
  -> local AI decision
  -> keep alert OR merge into case OR create case
  -> timeline / graph / summary / tasks
  -> Slack + Gmail notification
```

This replaces the old design where every alert created a new IRIS case.

---

## 1. Clean the current Shuffle canvas

Keep these existing nodes:

```text
Wazuh Alerts
Receive Wazuh Alerts
Run Cortex VirusTotal
Get Cortex VirusTotal Report
Run Cortex AbuseIPDB
Get Cortex AbuseIPDB
LM Studio AI Triage / LM Studio Case Decision
Notify Slack
Gmail
```

Remove or disconnect these old nodes:

```text
Build Incident Context
Build IRIS Case Lookup
Decide Case Route
Build Existing Incident Timeline Event
Append IRIS Timeline Event
Build AI Evidence Package
Build LM Studio Triage Request
Validate AI Triage
DFIR IRIS old case creation node
Build Incident Notification
```

We are replacing them with the new IRIS-alert-first workflow.

---

## 2. Create the main linear chain

Create these nodes in this exact order. Node names matter because Shuffle variable names are generated from them.

```text
Wazuh Alerts
  -> Receive Wazuh Alerts
  -> IRIS Local Configuration
  -> Normalize Alert
  -> Build IRIS Alert Payload
  -> Create IRIS Alert
  -> Resolve IRIS Alert
  -> Get IRIS Alert
  -> Build Correlation Key
  -> Search Open Cases
  -> Resolve Open Case
  -> Run Cortex VirusTotal
  -> Get Cortex VirusTotal Report
  -> Run Cortex AbuseIPDB
  -> Get Cortex AbuseIPDB
  -> Build AI Case Decision Request
  -> LM Studio Case Decision
  -> Validate AI Case Decision
  -> Build IRIS Action Payloads
```

---

## 3. Python nodes

Use `Shuffle Tools -> Execute Python`.

Paste each file into the node with the matching name:

| Node name | File |
|---|---|
| `IRIS Local Configuration` | `00_iris_local_configuration.py` |
| `Normalize Alert` | `01_normalize_alert.py` |
| `Build IRIS Alert Payload` | `02_build_iris_alert_payload.py` |
| `Resolve IRIS Alert` | `03_resolve_iris_alert.py` |
| `Build Correlation Key` | `04_build_correlation_key.py` |
| `Resolve Open Case` | `05_resolve_open_case.py` |
| `Build AI Case Decision Request` | `06_build_ai_case_decision_request.py` |
| `Validate AI Case Decision` | `07_validate_ai_case_decision.py` |
| `Build IRIS Action Payloads` | `08_build_iris_action_payloads.py` |
| `Resolve Created Case` | `09_resolve_created_case.py` |
| `Resolve Merged Case` | `10_resolve_merged_case.py` |
| `Build New Case Setup` | `11_build_new_case_setup.py` |
| `Build Case Artifact Plan` | `12_build_case_artifact_plan_merged.py` |
| `Build New Case Artifact Plan` | `13_build_case_artifact_plan_created.py` |
| `Build Case Task Payload` | `14_build_case_task_payload.py` |
| `Build New Case Task Payload` | `14b_build_new_case_task_payload.py` |
| `Build New Case Notification` | `15_build_new_case_notification.py` |
| `Build Case Update Notification` | `16_build_case_update_notification.py` |

---

## 4. IRIS Local Configuration

This is not an IRIS server file and it is not a DFIR-IRIS feature.

It is simply one Shuffle Tools → Execute Python node where we store local IRIS IDs once, so the other nodes do not hardcode IDs everywhere.

Before the final full test, fill the IDs from your own IRIS instance. Do not guess them. IRIS local IDs can differ between installations.

Run this on the SOC EC2:

```bash
export IRIS_URL="https://10.0.2.107:8000"
read -rsp "IRIS API key: " IRIS_KEY
echo

echo "=== IOC types ==="
curl -sk -H "Authorization: Bearer $IRIS_KEY" \
  "$IRIS_URL/manage/ioc-types/list" | jq .

echo "=== Asset types ==="
curl -sk -H "Authorization: Bearer $IRIS_KEY" \
  "$IRIS_URL/manage/asset-type/list?cid=1" | jq .

echo "=== Task statuses ==="
curl -sk -H "Authorization: Bearer $IRIS_KEY" \
  "$IRIS_URL/manage/task-status/list?cid=1" | jq .

echo "=== Users ==="
curl -sk -H "Authorization: Bearer $IRIS_KEY" \
  "$IRIS_URL/manage/users/list?cid=1" | jq .
```

Then update the `IRIS Local Configuration` Shuffle Python node.

Keep:

```python
"iris_base_url": "https://10.0.2.107:8000",
"customer_id": 1,
```

Fill these values:

```python
"default_tlp_id": <TLP ID to use for imported IOCs>,
"ioc_type_ids": {
    "ip": <IOC type ID for IP address>,
    "domain": <IOC type ID for domain>,
    "url": <IOC type ID for URL>,
    "hash": <IOC type ID for hash, if your IRIS has a generic hash type>,
    "email": <IOC type ID for email, if present>,
    "aws_role_arn": <custom IOC type ID if you created it, otherwise None>,
    "s3_bucket": <custom IOC type ID if you created it, otherwise None>,
    "s3_object": <custom IOC type ID if you created it, otherwise None>,
},
"asset_type_ids": {
    "host": <asset type ID for Linux server/host>,
    "container": <custom asset type ID for container, otherwise None>,
    "cloud_resource": <custom asset type ID for cloud resource, otherwise None>,
},
"task_status_id": <task status ID for To do / Open>,
"task_assignee_ids": [<administrator or analyst user ID>],
```

If your IRIS instance does not already have custom IOC/asset types for AWS role ARN, S3 bucket, S3 object, container, or cloud resource, create those in the IRIS UI first or leave only those specific custom values as `None`. IP/URL/host/task should be filled for the final test.

---

## 5. IRIS HTTP nodes

All IRIS HTTP nodes use:

```text
Authorization: Bearer YOUR_IRIS_API_KEY
Content-Type: application/json
```

Use `Verify: false` if your IRIS HTTPS certificate is self-signed.

### Create IRIS Alert

Action: HTTP POST

URL:

```text
https://10.0.2.107:8000/alerts/add
```

Body:

```text
$build_iris_alert_payload.message
```

### Get IRIS Alert

Action: HTTP GET

URL:

```text
https://10.0.2.107:8000/alerts/$resolve_iris_alert.message.iris_alert_id
```

### Search Open Cases

Action: HTTP GET

URL:

```text
https://10.0.2.107:8000/manage/cases/filter?case_soc_id=$build_correlation_key.message.correlation_key_urlencoded&case_customer_id=1&page=1&per_page=10
```

This is the deduplication point. It searches by a stable correlation key, not by the Wazuh alert ID.

---

## 6. Cortex HTTP nodes

Keep your existing working Cortex URLs and headers.

For both analyzer run nodes, Body should use normalized source IP:

```json
{
  "data": "$normalize_alert.message.source.ip",
  "dataType": "ip",
  "tlp": 2
}
```

Then keep your existing report nodes:

```text
Get Cortex VirusTotal Report
Get Cortex AbuseIPDB
```

The AI request reads both report outputs.

---

## 7. LM Studio AI node

Rename your AI HTTP node to:

```text
LM Studio Case Decision
```

Action: HTTP POST

URL:

```text
http://100.92.188.8:1234/v1/chat/completions
```

Body:

```text
$build_ai_case_decision_request.message
```

Headers:

```text
Content-Type: application/json
```

Timeout:

```text
180
```

If the Qwen model is slow, use:

```text
240
```

---

## 8. Branch after `Build IRIS Action Payloads`

From `Build IRIS Action Payloads`, create three branches.

### Branch A: Keep as IRIS alert only

Condition:

```text
$build_iris_action_payloads.message.route == keep_as_alert
```

HTTP node name:

```text
Update IRIS Alert
```

Method:

```text
POST
```

URL:

```text
https://10.0.2.107:8000/alerts/update/$build_iris_action_payloads.message.iris_alert_id
```

Body:

```text
$build_iris_action_payloads.message.keep_alert_payload
```

This is for low-value/noisy alerts. No IRIS case is created.

---

### Branch B: Merge into existing case

Condition:

```text
$build_iris_action_payloads.message.route == merge_existing
```

HTTP node name:

```text
Merge IRIS Alert
```

Method:

```text
POST
```

URL:

```text
https://10.0.2.107:8000/alerts/merge/$build_iris_action_payloads.message.iris_alert_id
```

Body:

```text
$build_iris_action_payloads.message.merge_payload
```

Then connect:

```text
Merge IRIS Alert
  -> Resolve Merged Case
  -> Get Merged Case Export
  -> Build Case Artifact Plan
  -> Add Timeline Event
  -> Build Case Task Payload
  -> Add Case Task
  -> Build Case Update Notification
  -> Notify Slack + Gmail
```

#### Get Merged Case Export

Method:

```text
GET
```

URL:

```text
https://10.0.2.107:8000/case/export?cid=$resolve_merged_case.message.case_id
```

#### Add Timeline Event

Method:

```text
POST
```

URL:

```text
https://10.0.2.107:8000/case/timeline/events/add?cid=$build_case_artifact_plan.message.case_id
```

Body:

```text
$build_case_artifact_plan.message.timeline_payload
```

#### Add Case Task

Method:

```text
POST
```

URL:

```text
https://10.0.2.107:8000/case/tasks/add?cid=$build_case_task_payload.message.case_id
```

Body:

```text
$build_case_task_payload.message.payload
```

Line condition:

```text
$build_case_task_payload.message.enabled == true
```

#### Existing case Slack/Gmail notification

Line condition:

```text
$build_case_update_notification.message.notify == true
```

Slack body:

```text
$build_case_update_notification.message.message
```

Gmail subject:

```text
$build_case_update_notification.message.subject
```

Gmail body:

```text
$build_case_update_notification.message.message
```

---

### Branch C: Create a new case

Condition:

```text
$build_iris_action_payloads.message.route == create_case
```

HTTP node name:

```text
Escalate IRIS Alert
```

Method:

```text
POST
```

URL:

```text
https://10.0.2.107:8000/alerts/escalate/$build_iris_action_payloads.message.iris_alert_id
```

Body:

```text
$build_iris_action_payloads.message.escalate_payload
```

Then connect:

```text
Escalate IRIS Alert
  -> Resolve Created Case
  -> Build New Case Setup
  -> Update New Case Metadata
  -> Update New Case Summary
  -> Get Created Case Export
  -> Build New Case Artifact Plan
  -> Add New Case Timeline Event
  -> Build New Case Task Payload
  -> Add New Case Task
  -> Build New Case Notification
  -> Notify Slack + Gmail
```

#### Update New Case Metadata

Method:

```text
POST
```

URL:

```text
https://10.0.2.107:8000/manage/cases/update/$build_new_case_setup.message.case_id
```

Body:

```text
$build_new_case_setup.message.metadata_payload
```

#### Update New Case Summary

Method:

```text
POST
```

URL:

```text
https://10.0.2.107:8000/case/summary/update?cid=$build_new_case_setup.message.case_id
```

Body:

```text
$build_new_case_setup.message.summary_payload
```

Only do this on new cases. Do not overwrite summaries every time a related alert arrives.

#### Get Created Case Export

Method:

```text
GET
```

URL:

```text
https://10.0.2.107:8000/case/export?cid=$resolve_created_case.message.case_id
```

#### Add New Case Timeline Event

Method:

```text
POST
```

URL:

```text
https://10.0.2.107:8000/case/timeline/events/add?cid=$build_new_case_artifact_plan.message.case_id
```

Body:

```text
$build_new_case_artifact_plan.message.timeline_payload
```

#### Add New Case Task

Method:

```text
POST
```

URL:

```text
https://10.0.2.107:8000/case/tasks/add?cid=$build_new_case_task_payload.message.case_id
```

Body:

```text
$build_new_case_task_payload.message.payload
```

Line condition:

```text
$build_new_case_task_payload.message.enabled == true
```

#### New case Slack/Gmail notification

Slack body:

```text
$build_new_case_notification.message.message
```

Gmail subject:

```text
$build_new_case_notification.message.subject
```

Gmail body:

```text
$build_new_case_notification.message.message
```

---

## 9. First end-to-end test

Run the Scenario 1 SQL injection attack once.

Expected:

```text
Create IRIS Alert: SUCCESS
Search Open Cases: 0 cases
AI route: create_case
Escalate IRIS Alert: SUCCESS
Update New Case Summary: SUCCESS
Add New Case Timeline Event: SUCCESS
Slack/Gmail: SUCCESS
```

In IRIS you should see:

- one new alert;
- one new case;
- detailed case summary;
- timeline entry;
- graph timeline event;
- Slack/Gmail notification.

---

## 10. Second end-to-end test

Run the same Scenario 1 SQL injection attack again from the same source/target.

Expected:

```text
Create IRIS Alert: SUCCESS
Search Open Cases: 1 matching open case
AI route: merge_existing
Merge IRIS Alert: SUCCESS
Add Timeline Event: SUCCESS
No duplicate case
Slack/Gmail only if notification gate is true
```

This proves the workflow is fixed.

---

## 11. Final verification checklist

Before you call the workflow complete, verify all of this:

- `Create IRIS Alert` succeeds.
- `Get IRIS Alert` returns the alert with `alert_id`, `alert_uuid`, `iocs`, and `assets`.
- `Search Open Cases` returns zero cases for the first test.
- AI route is `create_case` for the first matching incident.
- `Escalate IRIS Alert` succeeds.
- `Update New Case Metadata` sets the stable `case_soc_id` correlation key, not the one-alert Wazuh ID.
- `Update New Case Summary` writes the detailed AI summary only for the new case.
- `Get Created Case Export` returns the created case.
- `Add New Case Timeline Event` succeeds and has `event_in_graph: true`.
- `Add New Case Task` succeeds if `task_status_id` and `task_assignee_ids` are configured.
- Slack and Gmail both send the new-case notification.
- Running the same Scenario 1 attack again does not create a second case.
- The second run routes to `merge_existing`.
- `Merge IRIS Alert` succeeds.
- `Add Timeline Event` appends a new chronological update to the existing case.
- The existing case Graph tab shows the timeline event and any imported native IOCs/assets.

The important success condition is:

```text
many related Wazuh alerts -> one IRIS case with updated timeline / IOCs / assets / tasks
```

not:

```text
one Wazuh alert -> one new IRIS case every time
```
