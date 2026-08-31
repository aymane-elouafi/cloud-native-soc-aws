import json
import re

# Use this file, not 06_build_iris_action_payloads.py. The *_final version
# preserves the exact v2.4 IRIS alert merge/escalate field names already proven
# in the prior SOAR-AI workflow.
# Shuffle node name: Build IRIS Action Payloads

def unpack(value):
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}

record = unpack(r'''$validate_ai_case_decision.message''')
resolved = unpack(r'''$resolve_iris_alert.message''')

def unwrap_alert(value):
    if not isinstance(value, dict):
        return {}
    for candidate in (value.get("data"), value.get("message"), value.get("alert"), value):
        if isinstance(candidate, dict) and candidate.get("alert_id") is not None:
            return candidate
    return {}

def find(value, names):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in names and item not in (None, ""):
                return item
            result = find(item, names)
            if result not in (None, ""):
                return result
    elif isinstance(value, list):
        for item in value:
            result = find(item, names)
            if result not in (None, ""):
                return result
    return None

def uuids(values, field):
    output = []
    for value in values if isinstance(values, list) else []:
        candidate = value.get(field) if isinstance(value, dict) else None
        if isinstance(candidate, str) and re.fullmatch(r"[0-9a-fA-F-]{32,40}", candidate):
            if candidate not in output:
                output.append(candidate)
    return output

def bullets(values, fallback):
    values = values if isinstance(values, list) else []
    return "\n".join("- " + str(value) for value in values if str(value).strip()) or "- " + fallback

def mitre_table(values):
    rows = ["| Technique | Name | Tactic | Rationale |", "|---|---|---|---|"]
    seen = set()
    for item in values if isinstance(values, list) else []:
        if not isinstance(item, dict):
            continue
        technique_id = str(item.get("technique_id", ""))
        tactic = str(item.get("tactic", ""))
        dedup_key = (technique_id.strip().lower(), tactic.strip().lower())
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        rows.append("| {0} | {1} | {2} | {3} |".format(
            technique_id.replace("|", "/"),
            str(item.get("technique_name", "")).replace("|", "/"),
            tactic.replace("|", "/"),
            str(item.get("rationale", "")).replace("|", "/")[:350],
        ))
    if len(rows) == 2:
        rows.append("| Not determined |  |  | Insufficient evidence |")
    return "\n".join(rows)

def clip(value, limit=5000):
    output = json.dumps(value, ensure_ascii=False, default=str)
    return output if len(output) <= limit else output[:limit] + "...[truncated]"

normalized = record.get("normalized_alert", {})
alert = normalized.get("alert", {})
classification = normalized.get("classification", {})
ai = record.get("ai", {})
iris = unwrap_alert(record.get("iris_alert", {}))

iris_alert_id = find(resolved, {"iris_alert_id", "alert_id"}) or iris.get("alert_id")
if iris_alert_id is None:
    raise ValueError("Cannot determine IRIS alert ID")

severity = str(ai.get("severity") or "medium").upper()
# Markdown parses single underscores as italics, so "likely_true_positive"
# silently loses its underscores when IRIS renders it in narrative text.
# Keep the slug form for tags/custom_attributes and a spaced form for prose.
assessment_slug = str(ai.get("assessment") or "uncertain")
assessment = assessment_slug.replace("_", " ")
confidence = str(ai.get("confidence") or "low")
title = str(alert.get("title") or "Security incident")
telemetry = str(classification.get("telemetry") or "generic")
family = str(classification.get("attack_family") or "generic_security_event")

timeline_note = """# Automated correlation and triage

- **Wazuh alert ID:** `{alert_id}`
- **IRIS alert ID:** `{iris_alert_id}`
- **AI decision:** `{route}`
- **Assessment:** {assessment}
- **Confidence:** {confidence}
- **Recommended severity:** {severity}
- **Correlation key:** `{correlation_key}`

## Decision rationale
{rationale}

## Technical summary
{technical}

## Key evidence
{evidence}

## MITRE ATT&CK mapping
{mitre}
""".format(
    alert_id=alert.get("alert_id", "unknown"),
    iris_alert_id=iris_alert_id,
    route=record.get("route"),
    assessment=assessment,
    confidence=confidence,
    severity=severity,
    correlation_key=record.get("correlation_key", "unknown"),
    rationale=ai.get("decision_rationale", "No rationale was supplied."),
    technical=ai.get("technical_summary", "No technical summary was supplied."),
    evidence=bullets(ai.get("key_evidence"), "No key evidence was extracted."),
    mitre=mitre_table(ai.get("mitre_attack")),
)

case_description = """# Automated SOC Triage

## Incident overview
- **Wazuh alert ID:** `{alert_id}`
- **Rule ID:** `{rule_id}`
- **AI assessment:** {assessment}
- **AI confidence:** {confidence}
- **Recommended severity:** {severity}
- **Telemetry:** {telemetry}
- **Incident family:** {family}
- **Human analyst review:** Required

## Executive summary
{summary}

## Attack chain
{chain}

## MITRE ATT&CK mapping
{mitre}

## Key evidence
{evidence}

## Evidence gaps
{gaps}

## WAF / web telemetry
```json
{web}
```

## CloudTrail telemetry
```json
{cloud}
```
""".format(
    alert_id=alert.get("alert_id", "unknown"), rule_id=alert.get("rule_id", "unknown"),
    assessment=assessment, confidence=confidence, severity=severity,
    telemetry=telemetry, family=family,
    summary=ai.get("executive_summary", "No executive summary was supplied."),
    chain=bullets(ai.get("attack_chain"), "No chain determined."),
    mitre=mitre_table(ai.get("mitre_attack")),
    evidence=bullets(ai.get("key_evidence"), "No key evidence extracted."),
    gaps=bullets(ai.get("evidence_gaps"), "No gaps identified."),
    web=clip(normalized.get("web", {})), cloud=clip(normalized.get("cloud", {})),
)

existing_context = iris.get("alert_context", {})
if not isinstance(existing_context, dict):
    existing_context = {}
context = dict(existing_context)
context["ai_triage_v4"] = {
    "route": record.get("route"), "assessment": assessment_slug,
    "confidence": confidence, "severity": severity.lower(),
    "rationale": ai.get("decision_rationale"), "validation": record.get("validation", {}),
}

tags = set(filter(None, str(iris.get("alert_tags", "")).split(",")))
tags.update(["wazuh", "ai-triaged", "route-{}".format(record.get("route")), assessment_slug, family])

result = {
    "schema_version": "soc.iris.action-payloads/v4",
    "route": record.get("route"),
    "iris_alert_id": int(iris_alert_id),
    "case_description": case_description,
    "timeline_note": timeline_note,
    "merge_payload": {
        "iocs_import_list": uuids(iris.get("iocs") or iris.get("alert_iocs") or [], "ioc_uuid"),
        "assets_import_list": uuids(iris.get("assets") or iris.get("alert_assets") or [], "asset_uuid"),
        "note": timeline_note,
        "import_as_event": True,
        "target_case_id": (record.get("selected_case") or {}).get("case_id"),
    },
    "escalate_payload": {
        "iocs_import_list": uuids(iris.get("iocs") or iris.get("alert_iocs") or [], "ioc_uuid"),
        "assets_import_list": uuids(iris.get("assets") or iris.get("alert_assets") or [], "asset_uuid"),
        "note": timeline_note,
        "import_as_event": True,
        "case_tags": ",".join(sorted({"wazuh", telemetry, family, assessment_slug, "ai-managed"})),
        "case_template_id": 0,
        "case_title": "[{}] {}".format(severity, title)[:250],
    },
    "keep_alert_payload": {
        "alert_note": timeline_note,
        "alert_tags": ",".join(sorted(tags)),
        "alert_context": context,
    },
}
print(json.dumps(result, ensure_ascii=False, default=str))
