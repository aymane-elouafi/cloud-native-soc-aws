# Rebuilding the AI-Augmented SOC Workflow (Shuffle)

The single, authoritative guide to rebuild the Shuffle workflow from an empty
canvas. It builds the **current (living-case) design directly** — there is no
separate "v1 then upgrade" step; the node files in [`../nodes/`](../nodes/)
already contain the entity-correlation / living-case logic described here.

> Endpoints used below (change to match your lab):
> **IRIS** `https://10.0.2.107:8000` · **local LLM** `http://100.92.188.8:1234`
> (LM Studio, `qwen/qwen3-vl-8b`) · **Cortex** your existing analyzer URLs.
> In Shuffle the workflow is the one named `SOAR-AI/FINAL` (ignore any `v3`/`v4`
> scratch copies).

## What it does

```
Wazuh alert
  → IRIS alert intake        (every alert becomes an IRIS alert)
  → normalized evidence
  → entity/campaign correlation
  → Cortex enrichment        (VirusTotal, AbuseIPDB)
  → local AI decision        (grounded, anti-hallucination)
  → keep alert  OR  merge into the campaign case  OR  create a new case
  → living summary / attacker timeline / IOCs+assets / analyst task
  → Slack + Gmail notification
  → human analyst decides
```

The design goal — the one success condition — is:

```
many related Wazuh alerts → ONE living IRIS case (growing timeline / IOCs / assets)
NOT: one Wazuh alert → one new IRIS case every time
```

Correlation is **entity-based**: alerts are grouped by shared attacker IP / host /
IAM role / resource (or a family-free campaign anchor), so a multi-stage kill
chain (e.g. Scenario 3: SSTI → container escape → IMDS theft → IAM privesc → S3
exfil) collapses into a single case that grows stage by stage.

---

## 0. Prerequisites

Before building the canvas, make sure the surrounding pieces are running:

- **DFIR-IRIS**, **Cortex** (with VirusTotal + AbuseIPDB analyzers), and **LM
  Studio** serving `qwen/qwen3-vl-8b` are all reachable from Shuffle.
- **Wazuh forwards the right alerts to Shuffle.** The correlation groups by
  entity, so forward the *broad* set of real security events (not only the
  `soar_candidate`-tagged ones) — this no longer causes case sprawl. In the
  Wazuh manager's `ossec.conf`, gate the Shuffle `<integration>` on a **level
  floor** instead of the `soar_candidate` group:

  ```xml
  <integration>
    <name>shuffle</name>
    <hook_url>https://10.0.2.107:3443/api/v1/hooks/webhook_...</hook_url>
    <level>7</level>              <!-- forward all real security events -->
    <alert_format>json</alert_format>
  </integration>
  ```
  then `sudo /var/ossec/bin/wazuh-control restart`.

  **Pick the floor** (the local model takes ~24 s/alert):
  - **`7` (recommended)** — all real security events across every family; system
    noise dropped. Correlation rules still roll floods into single incidents.
  - **`5`** — maximum coverage; also forwards every individual attack request
    (heavy AI load during brute-force/floods).
  - **`12`** — lightest; only critical/correlated events (still catches every
    campaign, fewer FP/TP triage samples).

  Leave the `soar_candidate` tags on the rules — harmless; the integration just
  no longer filters on them.

---

## 1. Clean the Shuffle canvas

**Keep** these existing nodes:
```
Wazuh Alerts · Receive Wazuh Alerts
Run Cortex VirusTotal · Get Cortex VirusTotal Report
Run Cortex AbuseIPDB · Get Cortex AbuseIPDB
LM Studio Case Decision · Notify Slack · Gmail
```

**Remove / disconnect** any old one-case-per-alert nodes (Build Incident Context,
Build IRIS Case Lookup, Decide Case Route, Build AI Evidence Package, Validate AI
Triage, the old case-creation and notification builders, etc.). They are replaced
by the IRIS-alert-first chain below.

---

## 2. The main linear chain

Create these nodes in **this exact order** — node names matter because Shuffle
generates variable names (`$normalize_alert.message…`) from them:

```
Wazuh Alerts → Receive Wazuh Alerts → IRIS Local Configuration → Normalize Alert
  → Build IRIS Alert Payload → Create IRIS Alert → Resolve IRIS Alert → Get IRIS Alert
  → Build Correlation Key → Search Open Cases → Resolve Open Case
  → Run Cortex VirusTotal → Get Cortex VirusTotal Report
  → Run Cortex AbuseIPDB → Get Cortex AbuseIPDB
  → Build AI Case Decision Request → LM Studio Case Decision → Validate AI Case Decision
  → Build IRIS Action Payloads
```

After `Build IRIS Action Payloads` the flow splits into **three branches** (§8).

---

## 3. Python nodes

Use `Shuffle Tools → Execute Python`. Paste each file from [`../nodes/`](../nodes/)
into the node with the matching name:

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
| `Build Case Artifact Plan` (merge branch) | `12_build_case_artifact_plan_merged.py` |
| `Build New Case Artifact Plan` (create branch) | `13_build_case_artifact_plan_created.py` |
| `Build Case Task Payload` | `14_build_case_task_payload.py` |
| `Build New Case Task Payload` | `14b_build_new_case_task_payload.py` |
| `Build New Case Notification` | `15_build_new_case_notification.py` |
| `Build New Case Slack Body` | `15b_build_new_case_slack_body.py` |
| `Build Case Update Notification` | `16_build_case_update_notification.py` |
| `Build Case Update Slack Body` | `16b_build_case_update_slack_body.py` |

Key nodes and what they do (living-case logic lives here, not in the model):
- **`04_build_correlation_key`** — emits a family-free **campaign anchor** + a
  typed **entity set** (`ent:ip / ent:host / ent:id / ent:res`) + `strong_tokens`.
- **`05_resolve_open_case`** — scores **every** open case by anchor match + entity
  overlap; outputs ranked `candidates`, `strong_single`, `ambiguous`.
- **`06/07`** — feed the model the candidates + `detector_evidence` + a curated
  `suggested_mitre`; validate the reply and **overwrite MITRE** from a curated
  family table (see §10).
- **`11_build_new_case_setup`** (create) / **`12_build_case_artifact_plan_merged`**
  (merge) — compose the colored, structured summary (badges, glance table,
  attacker timeline, entity inventory, collapsible evidence) in Python and store
  the `ent:*` tokens as **case tags**. On merge, node 12 parses the prior
  `<!-- soc-state -->`, folds in the new alert, and **re-renders the whole
  summary** — this is what makes the case "living."

---

## 4. IRIS Local Configuration

This is **not** an IRIS feature — it is one Execute-Python node where you store
your instance's local IDs once, so the other nodes don't hardcode them. IRIS IDs
differ between installations; **don't guess them.** Discover them on the SOC box:

```bash
export IRIS_URL="https://10.0.2.107:8000"
read -rsp "IRIS API key: " IRIS_KEY; echo
for path in "manage/ioc-types/list" "manage/asset-type/list?cid=1" \
            "manage/task-status/list?cid=1" "manage/users/list?cid=1"; do
  echo "=== $path ==="
  curl -sk -H "Authorization: Bearer $IRIS_KEY" "$IRIS_URL/$path" | jq .
done
```

Then edit the `IRIS Local Configuration` node. Keep `iris_base_url` /
`customer_id`, and fill `default_tlp_id`, the `ioc_type_ids` (ip/domain/url/hash/
email + any custom aws_role_arn / s3_bucket / s3_object types), `asset_type_ids`
(host + any custom container / cloud_resource), `task_status_id`, and
`task_assignee_ids`. Leave custom types you haven't created in IRIS as `None`;
ip/url/host/task must be filled for the live test.

---

## 5. IRIS HTTP nodes

All IRIS HTTP nodes use `Authorization: Bearer <IRIS_API_KEY>` +
`Content-Type: application/json`, and `Verify: false` for a self-signed cert.
**The API key lives only in these node headers — never in the repo.**

**Create IRIS Alert** — `POST https://10.0.2.107:8000/alerts/add`
body `$build_iris_alert_payload.message`

**Get IRIS Alert** — `GET https://10.0.2.107:8000/alerts/$resolve_iris_alert.message.iris_alert_id`

**Search Open Cases** — `GET` — fetch **all** open cases so entity overlap can
see cases whose anchor differs (do *not* filter by `case_soc_id`):
```
https://10.0.2.107:8000/manage/cases/filter?case_customer_id=1&page=1&per_page=50&sort=desc
```
`Resolve Open Case` (node 05) then does the entity-overlap scoring in Python.

---

## 6. Cortex HTTP nodes

Keep your existing Cortex URLs/headers. Both analyzer-run nodes take the
normalized source IP:
```json
{ "data": "$normalize_alert.message.source.ip", "dataType": "ip", "tlp": 2 }
```
Keep the two report nodes (`Get Cortex VirusTotal Report`, `Get Cortex AbuseIPDB`);
the AI request reads both.

---

## 7. LM Studio AI node

Node `LM Studio Case Decision` — `POST http://100.92.188.8:1234/v1/chat/completions`,
`Content-Type: application/json`, body `$build_ai_case_decision_request.message`,
**timeout 180** (use 240 if the model is slow).

---

## 8. The three branches after `Build IRIS Action Payloads`

The `08_build_iris_action_payloads` node emits `route` ∈
`{keep_as_alert, merge_existing, create_case}`. Create one branch per route.

### Branch A — keep as alert (`route == keep_as_alert`)
Low-value/noisy alert; no case created.
`Update IRIS Alert` — `POST /alerts/update/$build_iris_action_payloads.message.iris_alert_id`
body `…keep_alert_payload`.

### Branch B — merge into the campaign case (`route == merge_existing`)
```
Merge IRIS Alert → Resolve Merged Case → Get Merged Case Export
  → Build Case Artifact Plan → Update Merged Case Summary → Update Merged Case Metadata
  → Add Timeline Event → Build Case Task Payload → Add Case Task
  → Build Case Update Notification → Notify Slack + Gmail
```
- **Merge IRIS Alert** — `POST /alerts/merge/…iris_alert_id` body `…merge_payload`
- **Get Merged Case Export** — `GET /case/export?cid=$resolve_merged_case.message.case_id`
- **Update Merged Case Summary** *(the living update)* —
  `POST /case/summary/update?cid=$build_case_artifact_plan.message.case_id`
  body `$build_case_artifact_plan.message.summary_payload`
- **Update Merged Case Metadata** — `POST /manage/cases/update/$build_case_artifact_plan.message.case_id`
  body `$build_case_artifact_plan.message.metadata_payload`
  (always carries refreshed `case_tags`; also carries `severity_id` when escalating)
- **Add Timeline Event** — `POST /case/timeline/events/add?cid=$build_case_artifact_plan.message.case_id`
  body `…timeline_payload`
- **Add Case Task** — `POST /case/tasks/add?cid=$build_case_task_payload.message.case_id`
  body `…payload`, line condition `…enabled == true`
- **Notify** — line condition `$build_case_update_notification.message.notify == true`;
  Slack/Gmail body `…message`, Gmail subject `…subject`.

### Branch C — create a new case (`route == create_case`)
```
Escalate IRIS Alert → Resolve Created Case → Build New Case Setup
  → Update New Case Metadata → Update New Case Summary → Get Created Case Export
  → Build New Case Artifact Plan → Add New Case Timeline Event
  → Build New Case Task Payload → Add New Case Task
  → Build New Case Notification → Notify Slack + Gmail
```
- **Escalate IRIS Alert** — `POST /alerts/escalate/…iris_alert_id` body `…escalate_payload`
- **Update New Case Metadata** — `POST /manage/cases/update/$build_new_case_setup.message.case_id`
  body `…metadata_payload` (sets the stable `case_soc_id` correlation anchor + `ent:*` tags)
- **Update New Case Summary** — `POST /case/summary/update?cid=$build_new_case_setup.message.case_id`
  body `…summary_payload` *(new case only — never overwrite on every related alert)*
- **Get Created Case Export** — `GET /case/export?cid=$resolve_created_case.message.case_id`
- **Add New Case Timeline Event** — `POST /case/timeline/events/add?cid=$build_new_case_artifact_plan.message.case_id`
  body `…timeline_payload`
- **Add New Case Task** — `POST /case/tasks/add?cid=$build_new_case_task_payload.message.case_id`
  body `…payload`, line condition `…enabled == true`
- **Notify** — Slack/Gmail body `$build_new_case_notification.message.message`, subject `…subject`.

---

## 9. Anti-hallucination & deterministic MITRE

The model *triages*; it never authors the case record:
- It may cite **only** facts present in the evidence JSON; unknowns go to
  `evidence_gaps` (enforced by the system prompt in node 06).
- **MITRE IDs are code, not model output** — overwritten from a curated family
  table in node 07 (e.g. the model emitted `T1566.001` for S3 exfil; it's forced
  to `T1530`).
- The **entire case summary/timeline is composed in Python** (nodes 11/12) from
  validated fields — the model never writes the case body directly.
- Case **severity** is driven by the deterministic Wazuh `rule_level` bucket, not
  the model's opinion.

Enterprise patterns behind this: Microsoft Sentinel entity-based incident
grouping; Cortex XSOAR IOC/IOB/TTP correlation + evidence board; NIST 800-61
evidence discipline.

---

## 10. End-to-end tests

**Test 1 — create.** Run the Scenario 1 SQLi attack once. Expect:
`Create IRIS Alert` ok → `Search Open Cases` 0 → AI route `create_case` →
`Escalate` ok → summary + timeline written → Slack/Gmail sent. IRIS shows one
alert, one case with a detailed summary, a timeline entry, and a graph event.

**Test 2 — merge (proves the fix).** Run the same attack again from the same
source/target. Expect: route `merge_existing`, `Merge IRIS Alert` ok, a new
timeline event appended, and **no second case**.

**Test 3 — living campaign case.** Empty IRIS, then run **Scenario 3** end to
end. Expect **one** case that grows stage by stage (SSTI → container escape →
IMDS theft → IAM privesc → S3 exfil): `Alerts correlated` climbs, the attacker
timeline fills in, entities accumulate, MITRE unions
(T1190, T1611, T1552.005, T1078.004/T1098, T1530), and the "Current assessment"
is rewritten each merge. Unrelated alerts get their own case. Run one benign
request → triaged `likely_false_positive`, kept as an alert (no case).

---

## 11. Final verification checklist

- `Create IRIS Alert` succeeds; `Get IRIS Alert` returns `alert_id`, `alert_uuid`, `iocs`, `assets`.
- First run: `Search Open Cases` → 0; AI route `create_case`; `Escalate` ok.
- `Update New Case Metadata` sets the stable `case_soc_id` anchor (not the one-alert Wazuh ID) and the `ent:*` tags.
- `Update New Case Summary` writes the AI summary **only** for the new case.
- `Add New Case Timeline Event` succeeds with `event_in_graph: true`.
- `Add New Case Task` succeeds (if `task_status_id` + `task_assignee_ids` are set).
- Slack + Gmail send the new-case notification.
- Second identical run routes `merge_existing`, `Merge IRIS Alert` succeeds, **no** second case.
- On merge, the summary is re-rendered and `Add Timeline Event` appends a chronological update; the Graph tab shows the event + imported IOCs/assets.
- Multi-stage Scenario 3 lands in **one** growing case.
