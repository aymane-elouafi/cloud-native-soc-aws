import json

# Shuffle node name: Resolve Created Case
# Input: Escalate IRIS Alert body

def unpack(value):
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}

def locate_case_id(value):
    if isinstance(value, dict):
        for key in ("case_id", "id"):
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

case_id = locate_case_id(unpack(r'''$escalate_iris_alert.body'''))
if case_id is None:
    raise ValueError("IRIS escalation did not return a case_id")

print(json.dumps({"case_id": int(case_id), "route": "create_case"}))
