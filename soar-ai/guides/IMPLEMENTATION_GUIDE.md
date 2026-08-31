# Final SOAR + AI Workflow Implementation

Use this folder only:

```text
SOAR-AI/FINAL
```

Ignore `SOAR-AI/v3` and `SOAR-AI/v4`. They are scratch drafts.

The final workflow goal is:

```text
Wazuh alert
  -> IRIS alert intake
  -> correlation key
  -> exact open-case lookup
  -> Cortex enrichment
  -> local LM Studio AI case decision
  -> keep alert OR merge existing case OR create new case
  -> timeline + graph links + task + Slack/Gmail notification
```

This fixes the old problem where every Wazuh alert created one new IRIS case.

---

## 0. Keep the current Wazuh integration for Scenario 1 testing

Your current integration is good for testing Scenario 1:

```xml
<integration>
  <name>shuffle</name>
  <hook_url>hiddenwebhook</hook_url>
  <level>5</level>
  <group>juice_shop</group>
  <alert_format>json</alert_format>
  <timeout>10</timeout>
  <retries>3</retries>
</integration>
```

Later, when Scenario 2/3/4 detections are fixed, replace `juice_shop` with a more generic group such as `soar_candidate`.

---

## 1. Final Shuffle node order

Create these nodes in this order. Keep the exact node names because Shuffle variables depend on the node name.

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
      -> keep_as_alert branch
      -> merge_existing branch
      -> create_case branch
```

---

## 2. Python nodes

Use **Shuffle Tools -> Execute Python** for each Python node.

Paste the matching file content into each node:

| Shuffle node name | File to paste |
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

## 3. IRIS Local Configuration

Open `00_iris_local_configuration.py`.

Keep:

```python
"iris_base_url": "https://10.0.2.107:8000",
"customer_id": 1,
```

That keeps SOC components talking over the private AWS network.

Leave IOC/asset/task IDs as `None` until you verify the IDs from your IRIS instance. The workflow will still work; artifacts stay in `alert_context`, summaries, and timeline. Once IDs are mapped, IRIS will also create native IOCs/assets and the graph becomes richer.

---

## 4. HTTP nodes

All IRIS HTTP nodes keep:

```text
Authorization: Bearer YOUR_IRIS_API_KEY
Content-Type: application/json
```

### Create IRIS Alert

Method:

```text
POST
```

URL:

```text
https://10.0.2.107:8000/alerts/add
```

Body:

```text
$build_iris_alert_payload.message
```

### Get IRIS Alert

Method:

```text
GET
```

URL:

```text
https://10.0.2.107:8000/alerts/$resolve_iris_alert.message.iris_alert_id
```

### Search Open Cases

Method:

```text
GET
```

URL:

```text
https://10.0.2.107:8000/manage/cases/filter?case_soc_id=$build_correlation_key.message.correlation_key_urlencoded&case_customer_id=1&page=1&per_page=10
```

This is the main deduplication fix. It searches by a stable SOC correlation key, not by one Wazuh alert ID.

---

## 5. Cortex nodes

Keep your existing working Cortex HTTP nodes.

For both VirusTotal and AbuseIPDB run nodes, use the normalized source IP:

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

The AI decision request reads:

```text
$get_cortex_virustotal_report.body
$get_cortex_abuseipdb.body
```

---

## 6. LM Studio node

Method:

```text
POST
```

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

If the local model is slow, use 240 seconds.

---

## 7. Branching after Build IRIS Action Payloads

Create three outgoing branches from `Build IRIS Action Payloads`.

### Branch A: keep as alert

Condition:

```text
$build_iris_action_payloads.message.route == keep_as_alert
```

HTTP node: `Update IRIS Alert`

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

This keeps low-confidence/noisy alerts in IRIS without opening a case.

### Branch B: merge existing case

Condition:

```text
$build_iris_action_payloads.message.route == merge_existing
```

HTTP node: `Merge IRIS Alert`

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

Then:

```text
Resolve Merged Case
  -> Get Merged Case Export
  -> Build Case Artifact Plan
  -> Add Timeline Event
  -> Build Case Task Payload
  -> Add Case Task, if enabled
  -> Build Case Update Notification, if notify=true
  -> Slack + Gmail, if notify=true
```

`Get Merged Case Export`:

```text
GET https://10.0.2.107:8000/case/export?cid=$resolve_merged_case.message.case_id
```

`Add Timeline Event`:

```text
POST https://10.0.2.107:8000/case/timeline/events/add?cid=$build_case_artifact_plan.message.case_id
```

Body:

```text
$build_case_artifact_plan.message.timeline_payload
```

`Add Case Task`:

```text
POST https://10.0.2.107:8000/case/tasks/add?cid=$build_case_task_payload.message.case_id
```

Body:

```text
$build_case_task_payload.message.payload
```

Line condition:

```text
$build_case_task_payload.message.enabled == true
```

### Branch C: create case

Condition:

```text
$build_iris_action_payloads.message.route == create_case
```

HTTP node: `Escalate IRIS Alert`

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

Then:

```text
Resolve Created Case
  -> Build New Case Setup
  -> Update New Case Metadata
  -> Update New Case Summary
  -> Get Created Case Export
  -> Build New Case Artifact Plan
  -> Add New Case Timeline Event
  -> Build New Case Task Payload
  -> Add New Case Task, if enabled
  -> Build New Case Notification
  -> Slack + Gmail
```

`Update New Case Metadata`:

```text
POST https://10.0.2.107:8000/manage/cases/update/$build_new_case_setup.message.case_id
```

Body:

```text
$build_new_case_setup.message.metadata_payload
```

`Update New Case Summary`:

```text
POST https://10.0.2.107:8000/case/summary/update?cid=$build_new_case_setup.message.case_id
```

Body:

```text
$build_new_case_setup.message.summary_payload
```

Only do this for new cases. Do not overwrite the summary for every related alert.

`Get Created Case Export`:

```text
GET https://10.0.2.107:8000/case/export?cid=$resolve_created_case.message.case_id
```

`Add New Case Timeline Event`:

```text
POST https://10.0.2.107:8000/case/timeline/events/add?cid=$build_new_case_artifact_plan.message.case_id
```

Body:

```text
$build_new_case_artifact_plan.message.timeline_payload
```

`Add New Case Task`:

```text
POST https://10.0.2.107:8000/case/tasks/add?cid=$build_new_case_task_payload.message.case_id
```

Body:

```text
$build_new_case_task_payload.message.payload
```

Line condition:

```text
$build_new_case_task_payload.message.enabled == true
```

---

## 8. Slack and Gmail

For Slack message body:

```text
$build_new_case_notification.message.message
```

For Gmail:

Subject:

```text
$build_new_case_notification.message.subject
```

Body:

```text
$build_new_case_notification.message.message
```

For existing case update notifications, use:

```text
$build_case_update_notification.message.message
```

and gate Slack/Gmail with:

```text
$build_case_update_notification.message.notify == true
```

This prevents Slack/Gmail spam for repeated low-level alerts.

---

## 9. How this uses IRIS components

| IRIS component | How the workflow uses it |
|---|---|
| Alerts | Every Wazuh alert becomes an IRIS alert first. |
| Cases | AI decides whether to create, merge, or keep as alert. |
| Timeline | Every related alert becomes a timeline event. |
| IOCs | Native IOCs are imported during merge/escalation after you configure local type IDs. |
| Assets | Native assets are imported during merge/escalation after you configure local type IDs. |
| Graph | Timeline events set `event_in_graph: true`; imported IOCs/assets enrich the graph. |
| Tasks | AI proposes analyst tasks; task nodes create them when local status/assignee IDs are configured. |
| Summary | New cases get detailed WAF/CloudTrail/container evidence. Existing case summaries are not overwritten. |

---

## 10. Recommended first test

Use Scenario 1 SQL injection twice from the same source.

Expected behavior:

1. First alert:
   - creates IRIS alert;
   - no matching open case found;
   - AI chooses `create_case`;
   - IRIS case is created;
   - case summary is written;
   - timeline event is added;
   - Slack/Gmail notify.

2. Second related alert:
   - creates IRIS alert;
   - same correlation key is found;
   - AI route becomes `merge_existing`;
   - no duplicate case;
   - case timeline is updated;
   - notification happens only if severity is high/critical or analyst action is required.

