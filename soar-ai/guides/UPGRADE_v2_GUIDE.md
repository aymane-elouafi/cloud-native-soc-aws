# SOAR-AI Workflow Upgrade v2 — Intelligent, Living Case Management

**Date:** 2026-08-28  ·  **Model:** `qwen/qwen3-vl-8b` @ `http://100.92.188.8:1234`  ·  **IRIS:** `https://100.100.67.0:8000`

This upgrade turns the pipeline from *one-case-per-attack-stage* into an **entity-correlated, living case management system** for an AI-augmented SOC (human-in-the-loop — no autonomous response). Original nodes are backed up in `_backup_pre_upgrade_2026-08-28/`.

---

## The 5 problems this fixes

| # | Was | Now |
|---|---|---|
| 1 | Correlation key baked in `attack_family`+`telemetry` → every kill-chain stage = a **new case** (fragmentation) | **Entity/campaign correlation**: match on shared attacker IP / host / IAM role / resource **or** a family-free campaign anchor. Scenario 3 (SSTI→escape→IMDS→IAM→S3) collapses into **one** case. |
| 2 | AI saw only the single alert, guessed FP/TP | FP/TP **grounded in the actual detector evidence** (Wazuh rule level, WAF findings, CloudTrail event) with a strict **anti-hallucination** prompt. |
| 3 | Case summary **frozen** after creation | **Living case**: every merged alert re-composes the whole summary + refreshes evidence & evidence-gaps + appends a timeline event. |
| 4 | Thin "alert added" note | **Attacker timeline** table: each stage = when · phase · technique · target · outcome. |
| 5 | Plain text, model-invented ATT&CK IDs | **Colored/structured** case (severity & FP/TP badges, glance table, entity inventory) and **deterministic MITRE** from a curated family table (the model's IDs are overwritten — it emitted `T1566.001` for S3 exfil; now forced to `T1530`). |

**Enterprise patterns borrowed:** Microsoft Sentinel entity-based incident grouping; Cortex XSOAR IOC/IOB/TTP correlation + war-room/evidence board; NIST 800-61 evidence discipline.

---

## Nodes changed (paste each file into its Shuffle "Execute Python" node)

| File | Shuffle node | What changed |
|---|---|---|
| `04_build_correlation_key.py` | **Build Correlation Key** | Emits a family-free **campaign anchor** + typed **entity set** (`ent:ip/host/id/res`) + `strong_tokens`. Keeps `correlation_key` for back-compat. |
| `05_resolve_open_case.py` | **Resolve Open Case** | Scores **every** open case by anchor match + entity overlap; outputs ranked `candidates`, `strong_single`, `ambiguous` (+ back-compat `has_open_case`/`selected_case`). |
| `06_build_ai_case_decision_request.py` | **Build AI Case Decision Request** | Feeds candidates + `detector_evidence` + curated `suggested_mitre`; anti-hallucination system prompt; new schema fields `updated_case_summary`, `timeline_entry`. |
| `07_validate_ai_case_decision.py` | **Validate AI Case Decision** | Candidate-aware guardrails; **overwrites MITRE** from curated family table; passes entity tokens through to 11/12. |
| `11_build_new_case_setup.py` | **Build New Case Setup** | Colored/structured summary (badges, glance table, timeline, entities, collapsible evidence); stores `ent:*` **case tags**; embeds `<!-- soc-state:v1 … -->`. |
| `12_build_case_artifact_plan_merged.py` | **Build Case Artifact Plan** | **Living update**: parses prior `soc-state`, folds in the new alert, re-renders the whole summary; emits `summary_payload` + refreshed `metadata_payload` (tags). |

Nodes **08, 09, 10, 13, 14/14b, 15/16** are unchanged (back-compat preserved via `correlation_key` + `selected_case`).

---

## Shuffle wiring changes (do these too — code alone isn't enough)

### A. Search Open Cases — fetch ALL open cases (was: exact soc_id filter)
Entity overlap needs to see cases whose anchor differs. Change that HTTP node's URL to **drop** `case_soc_id=…`:
```
GET https://10.0.2.107:8000/manage/cases/filter?case_customer_id=1&page=1&per_page=50&sort=desc
```

### B. NEW node on the MERGE branch — "Update Merged Case Summary"
The merge branch must now write the living summary (mirror of the create branch's "Update New Case Summary"). Add an HTTP node **after** `Build Case Artifact Plan`:
```
POST https://10.0.2.107:8000/case/summary/update?cid=$build_case_artifact_plan.message.case_id
Headers: Authorization: Bearer <IRIS_API_KEY> ; Content-Type: application/json
Body:   $build_case_artifact_plan.message.summary_payload
```

### C. Repurpose "Update_Merged_Case_Severity" → "Update Merged Case Metadata"
Post the refreshed tags (and severity when escalating) every merge so later stages keep correlating:
```
POST https://10.0.2.107:8000/manage/cases/update/$build_case_artifact_plan.message.case_id
Body:   $build_case_artifact_plan.message.metadata_payload
```
(`metadata_payload` always carries `case_tags`; it also carries `severity_id` when `needs_case_severity_update` is true.)

### D. Forward ALL alerts (Wazuh → Shuffle)
Today the `<integration>` forwards only alerts carrying the **`soar_candidate`** group, and that tag sits only on the correlation/critical rules — so most alerts never reach the AI. Switch the gate from *group* to a *level floor*:

```xml
<integration>
  <name>shuffle</name>
  <hook_url>https://10.0.2.107:3443/api/v1/hooks/webhook_...</hook_url>
  <level>7</level>              <!-- REPLACES <group>soar_candidate</group> -->
  <alert_format>json</alert_format>
</integration>
```
Then `wazuh-control restart`. (Leave the `soar_candidate` tags on the rules — harmless; the integration just no longer filters on them.)

**One knob to pick** — the local model takes ~24 s/alert, so choose the floor:
- **`7` (recommended):** all real security events across every family; system noise dropped. The correlation rules still roll floods into single level-12 incidents.
- **`5`:** maximum coverage — also forwards every individual attack request (heavy AI load during brute-force/floods).
- **`12`:** lightest — only critical/correlated; still catches every campaign, just fewer FP/TP triage samples.

Because the correlation now groups by entity, forwarding the broader set no longer creates case sprawl — every related alert lands in the **one** campaign case.

---

## Anti-hallucination guarantees
- The model may cite **only** facts in the evidence JSON; unknowns go to `evidence_gaps` (enforced by system prompt).
- **MITRE IDs are code, not model output** — overwritten from a curated family table in node 07.
- The **entire case summary/timeline is composed in Python** from validated fields (nodes 11/12) — the model never writes the case body directly.
- Severity on the IRIS case field is driven by the deterministic Wazuh `rule_level` bucket, not the model's opinion.

---

## Test plan (needs the IRIS API key)
0. **Empty IRIS** — delete all cases + alerts (UI, or API with the key).
1. Paste the 6 nodes; apply wiring A–D.
2. Confirm the AI is loaded in LM Studio (`qwen/qwen3-vl-8b`).
3. Run **Scenario 3** end-to-end (`scenario*_attack_runner.py`).
4. **Expected:** ONE case that grows stage by stage — SSTI → container escape → IMDS theft → IAM privesc → S3 exfil — with `Alerts correlated` climbing, the attacker timeline filling in, entities accumulating, MITRE union (T1190, T1611, T1552.005, T1078.004/T1098, T1530), and the "Current assessment" rewritten each merge. Unrelated alerts get their own case.
5. Verify FP/TP: run a benign request → alert triaged `likely_false_positive`, kept as alert (no case).

**Validated offline against the live model:** routing (merge→correct case via shared role identity), FP/TP grounding, MITRE correction (`T1566.001`→`T1530`), and the living merge (2 stages → one case, count→2, unioned timeline/entities/MITRE).

## Still needed from you
- **IRIS API key** — to empty IRIS and run the live end-to-end test (it's not stored anywhere in the repo by design; it lives only in the Shuffle HTTP nodes' Authorization headers).
- **Confirm the forward-all level** (7 / 5 / 12).
