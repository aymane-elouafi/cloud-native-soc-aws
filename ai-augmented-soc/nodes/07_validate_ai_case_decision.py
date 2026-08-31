import json

# Shuffle node name: Validate AI Case Decision   (v2)
# Inputs:
#   LM Studio Case Decision body   ($lm_studio_case_decision.body)
#   Normalize Alert message        ($normalize_alert.message)
#   Resolve Open Case message      ($resolve_open_case.message)   <- candidates
#   Resolve IRIS Alert message     ($resolve_iris_alert.message)
#   Get IRIS Alert body            ($get_iris_alert.body)
#   Build Correlation Key message  ($build_correlation_key.message)
#
# The AI proposes the route; this node enforces the safety envelope:
#   - a confident single candidate forces a merge (no duplicate case);
#   - among several confident candidates, the AI must pick a real one, else the
#     alert is kept for analyst review (no blind merge);
#   - low-confidence low-severity noise never creates a case;
#   - MITRE ATT&CK IDs are overwritten from a curated family table because the
#     local model mis-recalls technique IDs (verified: it emitted T1566.001 for
#     an S3 exfiltration). The analyst must never see a wrong technique ID.

def unpack(value):
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}

def parse_ai_response(response):
    body = unpack(response)
    content = None
    try:
        content = body["choices"][0]["message"]["content"]
    except Exception:
        content = body.get("content") or body.get("message")
    if isinstance(content, dict):
        return content
    if isinstance(content, str):
        try:
            return json.loads(content)
        except Exception:
            start = content.find("{")
            end = content.rfind("}")
            if start >= 0 and end > start:
                try:
                    return json.loads(content[start:end + 1])
                except Exception:
                    return {}
    return {}

def severity_rank(value):
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(str(value).lower(), 1)

def to_int(value):
    try:
        return int(value) if value is not None else None
    except Exception:
        return value

# Curated MITRE ATT&CK by attack_family (must stay in sync with node 06's copy).
# Authoritative: the model's technique IDs are advisory only.
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

ai = parse_ai_response(r'''$lm_studio_case_decision.body''')
normalized = unpack(r'''$normalize_alert.message''')
lookup = unpack(r'''$resolve_open_case.message''')
resolved_iris_alert = unpack(r'''$resolve_iris_alert.message''')
iris_alert = unpack(r'''$get_iris_alert.body''')
correlation = unpack(r'''$build_correlation_key.message''')

errors = []
route = str(ai.get("route") or "keep_as_alert")

candidates = lookup.get("candidates", []) if isinstance(lookup.get("candidates"), list) else []
by_id = {to_int(c.get("case_id")): c for c in candidates if isinstance(c, dict)}
confident = [c for c in candidates if c.get("confident")]
confident_ids = {to_int(c.get("case_id")) for c in confident}
strong_single = bool(lookup.get("strong_single"))
ambiguous = bool(lookup.get("ambiguous"))

ai_selected_id = to_int(ai.get("selected_case_id"))
chosen_case = {}

if strong_single:
    # exactly one confident candidate -> always merge into it
    only = confident[0]
    if route != "merge_existing":
        errors.append("A confident single campaign match exists; routing to merge_existing.")
    if ai_selected_id not in (None, to_int(only.get("case_id"))):
        errors.append("AI selected a different case ID than the confident match; corrected.")
    route = "merge_existing"
    chosen_case = only
    ai["selected_case_id"] = to_int(only.get("case_id"))
elif ambiguous:
    # several confident candidates -> trust the AI only if it named a real one
    if route == "merge_existing" and ai_selected_id in confident_ids:
        chosen_case = by_id.get(ai_selected_id, {})
        errors.append("Multiple campaign matches; used the AI-selected candidate %s." % ai_selected_id)
    else:
        route = "keep_as_alert"
        errors.append("Multiple campaign matches and the AI did not select a valid one; kept for analyst review.")
elif route == "merge_existing":
    # AI wants merge but there is no confident candidate.
    if ai_selected_id in confident_ids:
        chosen_case = by_id.get(ai_selected_id, {})
    elif not candidates:
        # The model mislabeled the route: there is no open case to merge into
        # (it confuses "has a campaign anchor" with "has an open case"). It
        # clearly treats this as an incident, so re-evaluate as create_case;
        # the creation gate below still decides whether a case is actually made.
        route = "create_case"
        errors.append("AI said merge_existing but no case exists to merge into; re-evaluating as create_case.")
    else:
        route = "keep_as_alert"
        errors.append("AI requested merge into a non-candidate case; kept for analyst review.")
elif route not in ("create_case", "keep_as_alert"):
    route = "keep_as_alert"
    errors.append("Unknown AI route; defaulted to keep_as_alert.")

# Creation gate: applies whether the AI asked to create or we reassigned above.
if route == "create_case":
    important = (
        ai.get("assessment") in ("likely_true_positive", "uncertain")
        and severity_rank(ai.get("severity")) >= 2
        and ai.get("confidence") in ("medium", "high")
    )
    if not important:
        route = "keep_as_alert"
        errors.append("Case creation gate not passed (assessment/severity/confidence); kept as alert.")

# ---- enforce authoritative MITRE ATT&CK -----------------------------------
family = correlation.get("attack_family") or (normalized.get("classification") or {}).get("attack_family")
curated = MITRE_BY_FAMILY.get(family, [])
if curated:
    allow = {t["technique_id"] for t in curated}
    ai_rationale = {t.get("technique_id"): t.get("rationale")
                    for t in (ai.get("mitre_attack") or []) if isinstance(t, dict) and t.get("technique_id") in allow}
    corrected = []
    for t in curated:
        corrected.append({
            "technique_id": t["technique_id"],
            "technique_name": t["technique_name"],
            "tactic": t["tactic"],
            "rationale": ai_rationale.get(t["technique_id"]) or ("Mapped from detected activity family '%s'." % family),
        })
    if not ai_rationale:
        errors.append("Overwrote AI MITRE mapping with curated techniques for family '%s'." % family)
    ai["mitre_attack"] = corrected
    te = ai.get("timeline_entry")
    if isinstance(te, dict) and te.get("technique_id") not in allow:
        te["technique_id"] = curated[0]["technique_id"]
else:
    # unknown/generic family: show no technique rather than a wrong one
    if ai.get("mitre_attack"):
        errors.append("No curated MITRE mapping for family '%s'; cleared unverified techniques." % family)
    ai["mitre_attack"] = []
    te = ai.get("timeline_entry")
    if isinstance(te, dict):
        te["technique_id"] = ""

result = {
    "schema_version": "soc.validated.case-decision/v2",
    "route": route,
    "correlation_key": correlation.get("campaign_anchor") or correlation.get("correlation_key"),
    "campaign_anchor": correlation.get("campaign_anchor"),
    "attack_family": family,
    "kill_chain_phase": correlation.get("kill_chain_phase"),
    "entities": correlation.get("entities", {}),
    "entity_tokens": correlation.get("entity_tokens", []),
    "strong_tokens": correlation.get("strong_tokens", []),
    "selected_case": chosen_case if route == "merge_existing" else {},
    "ai": ai,
    "validation": {
        "valid": len(errors) == 0,
        "errors": errors,
        "guardrails_applied": True,
    },
    "normalized_alert": normalized,
    "iris_alert": iris_alert,
    "resolved_iris_alert": resolved_iris_alert,
    "case_lookup": lookup,
}

print(json.dumps(result, ensure_ascii=False, default=str))
