import json

# Shuffle node name: Resolve Merged Case
# Input: Merge IRIS Alert body and Validate AI Case Decision message

def unpack(value):
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}

def locate_case_id(value):
    if isinstance(value, dict):
        for key in ("case_id", "target_case_id", "id"):
            candidate = value.get(key)
            if candidate not in (None, ""):
                return candidate
        for child in value.values():
            candidate = locate_case_id(child)
            if candidate is not None:
                return candidate
    elif isinstance(value, list):
        for child in value:
            candidate = locate_case_id(child)
            if candidate is not None:
                return candidate
    return None

decision = unpack(r'''$validate_ai_case_decision.message''')
merge_response = unpack(r'''$merge_iris_alert.body''')
selected = decision.get("selected_case") if isinstance(decision.get("selected_case"), dict) else {}

# The selected open case is authoritative; the response is a fallback because
# legacy IRIS merge responses differ slightly between 2.4 point releases.
case_id = selected.get("case_id") or locate_case_id(merge_response)
if case_id is None:
    raise ValueError("Cannot determine merged IRIS case ID")

print(json.dumps({"case_id": int(case_id), "route": "merge_existing"}))
