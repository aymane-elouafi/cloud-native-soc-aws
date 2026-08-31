import json

# Shuffle node name: Build New Case Artifact Plan
# Input contract for the CREATE branch:
#   Validate AI Case Decision message
#   Get Created Case Export body
# This consumes an IRIS case export after the alert was merged/escalated.

def unpack(value):
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}

def clip(value, limit=9000):
    text = json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= limit else text[:limit] + "...[truncated]"

def bullet(values, fallback):
    values = values if isinstance(values, list) else []
    lines = ["- " + str(item) for item in values if str(item).strip()]
    return "\n".join(lines) or "- " + fallback

def dedup_mitre(values):
    seen = set()
    output = []
    for item in values if isinstance(values, list) else []:
        if not isinstance(item, dict):
            continue
        key = (str(item.get("technique_id", "")).strip().lower(), str(item.get("tactic", "")).strip().lower())
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output

record = unpack(r'''$validate_ai_case_decision.message''')
export = unpack(r'''$get_created_case_export.body''')
case = export.get("data", export.get("message", export))
if not isinstance(case, dict):
    case = {}

ai = record.get("ai", {})
normalized = record.get("normalized_alert", {})
alert = normalized.get("alert", {})
classification = normalized.get("classification", {})
case_id = case.get("case_id") or case.get("id") or (case.get("case") or {}).get("case_id")
if case_id is None:
    raise ValueError("Case export did not contain a case_id")

def numeric_ids(items, preferred):
    output = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        value = next((item.get(key) for key in preferred if item.get(key) is not None), None)
        try:
            value = int(value)
        except Exception:
            continue
        if value not in output:
            output.append(value)
    return output

case_ioc_ids = numeric_ids(case.get("iocs", []), ("ioc_id", "id"))
case_asset_ids = numeric_ids(case.get("assets", []), ("asset_id", "id"))
existing_task_titles = {
    str(item.get("task_title", "")).strip().lower()
    for item in case.get("tasks", []) if isinstance(item, dict)
    and not item.get("task_close_date") and not item.get("close_date")
}

family = classification.get("attack_family", "generic_security_event")
telemetry = classification.get("telemetry", "generic")
correlation_key = record.get("correlation_key", "unknown")

# Phase-based timeline entry, identical in shape to the merge branch (node 12)
# so every event in the IRIS Timeline tab reads consistently. This is the FIRST
# detection for the case, not a correlation update.
PHASE_ICON = {
    "initial_access": "🚪 Initial access",
    "exploitation": "💥 Exploitation",
    "container_escape": "📦 Container escape",
    "credential_access": "🔑 Credential access",
    "collection_exfiltration": "📤 Collection / exfiltration",
    "activity": "• Activity",
}
te = ai.get("timeline_entry") if isinstance(ai.get("timeline_entry"), dict) else {}
phase_label = PHASE_ICON.get(record.get("kill_chain_phase") or "activity", record.get("kill_chain_phase") or "activity")
timeline_markdown = "**{phase}** — {title}\n\n- Target: `{target}`\n- Outcome: {outcome}\n- Technique: `{tech}`\n- Wazuh alert `{aid}` (rule `{rid}`), assessment: {assess}\n- First detection for this case.".format(
    phase=phase_label,
    title=te.get("title") or alert.get("title") or "Security alert",
    target=te.get("target") or "n/a",
    outcome=te.get("outcome") or "n/a",
    tech=te.get("technique_id") or "n/a",
    aid=alert.get("alert_id", "unknown"), rid=alert.get("rule_id", "unknown"),
    assess=str(ai.get("assessment", "uncertain")).replace("_", " "),
)

timeline_payload = {
    "event_title": "Wazuh alert {0} — {1}".format(alert.get("alert_id", "unknown"), alert.get("title", "Security alert"))[:250],
    "event_date": str(alert.get("timestamp") or "").replace("+0000", ""),
    "event_tz": "+00:00",
    "event_source": "Wazuh / Shuffle AI triage",
    "event_content": timeline_markdown,
    "event_raw": clip(normalized.get("sanitized_raw_event", {})),
    "event_assets": case_asset_ids,
    "event_iocs": case_ioc_ids,
    "event_in_summary": False,
    "event_in_graph": True,
    "event_sync_iocs_assets": False,
    "event_category_id": 1,  # Unspecified -- required by this IRIS instance
    "event_tags": "wazuh,ai-triaged,{0},{1}".format(telemetry, family),
    "custom_attributes": {
        "correlation_key": correlation_key,
        "wazuh_alert_id": alert.get("alert_id"),
        "rule_id": alert.get("rule_id"),
    },
}

# A task is deliberately created only if it is not already open. The task API
# requires locally verified status/assignee IDs, so the HTTP task node is gated
# by has_task rather than guessing those IDs.
proposed = ai.get("analyst_tasks", []) if isinstance(ai.get("analyst_tasks"), list) else []
new_task = next((item for item in proposed if isinstance(item, dict)
                 and str(item.get("title", "")).strip().lower() not in existing_task_titles), None)

print(json.dumps({
    "schema_version": "soc.case-artifacts/v1",
    "case_id": int(case_id),
    "timeline_payload": timeline_payload,
    "case_ioc_ids": case_ioc_ids,
    "case_asset_ids": case_asset_ids,
    "proposed_task": new_task,
    "has_task": bool(new_task),
}, ensure_ascii=False, default=str))
