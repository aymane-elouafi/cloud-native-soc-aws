import json

# Shuffle node name: Build AI Case Decision Request   (v2)
# Inputs:
#   Normalize Alert message              ($normalize_alert.message)
#   Resolve IRIS Alert message           ($resolve_iris_alert.message)
#   Build Correlation Key message        ($build_correlation_key.message)
#   Resolve Open Case message            ($resolve_open_case.message)  <- now candidates
#   Get Cortex VirusTotal Report body    ($get_cortex_virustotal_report.body)
#   Get Cortex AbuseIPDB body            ($get_cortex_abuseipdb.body)
#
# The decision point of the AI-augmented SOC (human-in-the-loop). The model
# routes the alert (merge / create / keep) and produces evidence-grounded case
# content. v2 adds: entity-overlap candidates, a strict anti-hallucination
# system prompt, FP/TP grounded in the actual detector evidence, and two fields
# that drive the LIVING case (updated_case_summary + timeline_entry).

def unpack(value):
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}

def clip(value, limit=6500):
    text = json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= limit else text[:limit] + "...[truncated]"

normalized = unpack(r'''$normalize_alert.message''')
iris_alert = unpack(r'''$resolve_iris_alert.message''')
correlation = unpack(r'''$build_correlation_key.message''')
case_lookup = unpack(r'''$resolve_open_case.message''')
vt = unpack(r'''$get_cortex_virustotal_report.body''')
abuse = unpack(r'''$get_cortex_abuseipdb.body''')

alert = normalized.get("alert", {}) if isinstance(normalized.get("alert"), dict) else {}
web = normalized.get("web", {}) if isinstance(normalized.get("web"), dict) else {}
cloud = normalized.get("cloud", {}) if isinstance(normalized.get("cloud"), dict) else {}

# A compact, explicit summary of WHICH detector sources actually backed this
# alert. The model must ground its FP/TP call in this, not in assumptions.
detector_evidence = {
    "wazuh_rule_id": alert.get("rule_id"),
    "wazuh_rule_level": alert.get("rule_level"),
    "telemetry": correlation.get("telemetry"),
    "attack_family": correlation.get("attack_family"),
    "has_waf_findings": bool(web.get("waf_findings")),
    "waf_findings": web.get("waf_findings") or [],
    "has_cloudtrail_event": bool(cloud.get("event_name")),
    "cloudtrail_event": {k: cloud.get(k) for k in ("event_source", "event_name", "region", "principal_arn", "bucket", "object_key") if cloud.get(k)},
    "web_request": {k: web.get(k) for k in ("method", "uri", "response_status") if web.get(k)},
}

# Curated MITRE ATT&CK suggestions keyed on the deterministic attack_family from
# node 01. Small local models mis-recall technique IDs, so we hand the model a
# verified shortlist to prefer instead of guessing from memory.
MITRE_BY_FAMILY = {
    "authentication": [{"technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access"}],
    "sql_injection": [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "nosql_injection": [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "cross_site_scripting": [{"technique_id": "T1059.007", "technique_name": "Command and Scripting Interpreter: JavaScript", "tactic": "Execution"}],
    "server_side_request_forgery": [{"technique_id": "T1552.005", "technique_name": "Unsecured Credentials: Cloud Instance Metadata API", "tactic": "Credential Access"}],
    "file_access": [{"technique_id": "T1083", "technique_name": "File and Directory Discovery", "tactic": "Discovery"}],
    "cloud_storage": [{"technique_id": "T1530", "technique_name": "Data from Cloud Storage", "tactic": "Collection"}],
    "cloud_identity": [
        {"technique_id": "T1078.004", "technique_name": "Valid Accounts: Cloud Accounts", "tactic": "Privilege Escalation"},
        {"technique_id": "T1098", "technique_name": "Account Manipulation", "tactic": "Persistence"},
    ],
    "container_security": [{"technique_id": "T1611", "technique_name": "Escape to Host", "tactic": "Privilege Escalation"}],
}
suggested_mitre = MITRE_BY_FAMILY.get(correlation.get("attack_family"), [])

# The ranked open-case candidates, restated compactly so the model can pick a
# real case_id and see WHY each is a candidate.
candidates = case_lookup.get("candidates", []) if isinstance(case_lookup.get("candidates"), list) else []
correlation_candidates = [{
    "case_id": c.get("case_id"),
    "case_name": c.get("case_name"),
    "anchor_match": c.get("anchor_match"),
    "shared_entities": c.get("overlap_strong") or c.get("overlap_any") or [],
    "score": c.get("score"),
} for c in candidates[:8]]

evidence = {
    "new_alert": normalized,
    "iris_alert_id": iris_alert.get("iris_alert_id"),
    "campaign_correlation": {
        "campaign_anchor": correlation.get("campaign_anchor"),
        "entities": correlation.get("entities"),
        "kill_chain_phase": correlation.get("kill_chain_phase"),
    },
    "detector_evidence": detector_evidence,
    "correlation_candidates": correlation_candidates,
    "candidate_summary": {
        "has_candidates": case_lookup.get("has_candidates"),
        "strong_single": case_lookup.get("strong_single"),
        "ambiguous": case_lookup.get("ambiguous"),
        "best_candidate_case_id": (case_lookup.get("best_candidate") or {}).get("case_id"),
    },
    "suggested_mitre": suggested_mitre,
    "cortex_enrichment": {"virustotal": vt, "abuseipdb": abuse},
}

system_prompt = """You are a SOC case-correlation and triage assistant for an AI-augmented SOC that keeps a human analyst in the loop. You never take autonomous containment, closure, or destructive action. You prepare an accurate, evidence-grounded case so the analyst understands it at a glance.

GROUNDING RULES (critical - the analyst trusts these):
- Use ONLY facts present in the provided evidence JSON: the normalized alert, its detector_evidence (Wazuh rule, WAF/ModSecurity findings, CloudTrail event), the campaign_correlation entities, the correlation_candidates, and the Cortex enrichment.
- NEVER invent IP addresses, ARNs, usernames, hostnames, file paths, rule IDs, or any value that is not in the evidence. Copy identifiers exactly as they appear.
- If a fact needed for a conclusion is missing from the evidence, do NOT assume it - list it in evidence_gaps.
- Ground the assessment in detector_evidence and its strength. A high Wazuh rule level with a concrete WAF match or a sensitive CloudTrail event (e.g. IAM change, S3 GetObject on a secret) is strong. A low-level generic event is weak. When the evidence is thin or could be benign, choose "uncertain" rather than guessing "likely_true_positive".

ROUTE (choose exactly one):
- merge_existing: a candidate in correlation_candidates clearly belongs to the SAME attacker campaign as this alert (shared attacker IP, host, IAM identity/role, resource, or the same campaign anchor). Set selected_case_id to that candidate's case_id.
- create_case: no candidate is a genuine match AND the alert is a likely true positive, or uncertain but important enough to investigate.
- keep_as_alert: weak, benign, or duplicate noise with no investigation value, or the correlation is genuinely ambiguous between different campaigns.

IMPORTANT: if correlation_candidates is EMPTY there is no open case to merge into - never choose merge_existing in that case; choose create_case (if important) or keep_as_alert. A campaign_anchor alone is NOT an existing case.

CASE CONTENT:
- updated_case_summary: a cumulative, analyst-facing assessment of the case WITH this alert included - what the attacker appears to be doing and how confident we are - grounded only in evidence.
- timeline_entry: describe THIS alert as one attacker action (what happened, the ATT&CK technique, the target, the observed outcome).
- Map MITRE ATT&CK using suggested_mitre when it fits the evidence. Only use a different technique if you are certain of it. If you are not sure of an exact technique_id, set technique_id to "" and still give technique_name and tactic - never guess an ID.

STYLE: concise, 1-3 sentences per summary field, respect each list's max item count, no duplication across fields. Return strict JSON only."""

user_prompt = "Analyze this SOC evidence and decide the IRIS route:\n\n" + clip(evidence, 14000)

request = {
    "model": "qwen/qwen3-vl-8b",
    "temperature": 0.1,
    "max_tokens": 2200,
    "stream": False,
    "response_format": {
        "type": "json_schema",
        "json_schema": {
            "name": "soc_case_decision",
            "strict": True,
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "route": {"type": "string", "enum": ["merge_existing", "create_case", "keep_as_alert"]},
                    "selected_case_id": {"type": ["integer", "null"]},
                    "relation_confidence": {"type": "string", "enum": ["none", "low", "medium", "high"]},
                    "assessment": {"type": "string", "enum": ["likely_false_positive", "uncertain", "likely_true_positive"]},
                    "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                    "executive_summary": {"type": "string"},
                    "technical_summary": {"type": "string"},
                    "updated_case_summary": {"type": "string"},
                    "decision_rationale": {"type": "string"},
                    "attack_chain": {"type": "array", "maxItems": 4, "items": {"type": "string"}},
                    "key_evidence": {"type": "array", "maxItems": 5, "items": {"type": "string"}},
                    "evidence_gaps": {"type": "array", "maxItems": 3, "items": {"type": "string"}},
                    "timeline_entry": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "title": {"type": "string"},
                            "description": {"type": "string"},
                            "technique_id": {"type": "string"},
                            "target": {"type": "string"},
                            "outcome": {"type": "string"}
                        },
                        "required": ["title", "description", "technique_id", "target", "outcome"]
                    },
                    "mitre_attack": {
                        "type": "array",
                        "maxItems": 3,
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "technique_id": {"type": "string"},
                                "technique_name": {"type": "string"},
                                "tactic": {"type": "string"},
                                "rationale": {"type": "string"}
                            },
                            "required": ["technique_id", "technique_name", "tactic", "rationale"]
                        }
                    },
                    "analyst_tasks": {
                        "type": "array",
                        "maxItems": 3,
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "title": {"type": "string"},
                                "description": {"type": "string"},
                                "priority": {"type": "string", "enum": ["low", "medium", "high"]}
                            },
                            "required": ["title", "description", "priority"]
                        }
                    },
                    "requires_analyst_action": {"type": "boolean"}
                },
                "required": [
                    "route", "selected_case_id", "relation_confidence", "assessment",
                    "confidence", "severity", "executive_summary", "technical_summary",
                    "updated_case_summary", "decision_rationale", "attack_chain",
                    "key_evidence", "evidence_gaps", "timeline_entry", "mitre_attack",
                    "analyst_tasks", "requires_analyst_action"
                ]
            }
        }
    },
    "messages": [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt}
    ]
}

print(json.dumps(request, ensure_ascii=False, default=str))
