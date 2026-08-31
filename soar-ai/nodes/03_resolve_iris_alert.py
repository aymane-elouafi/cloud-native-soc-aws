import json

# Shuffle node name: Resolve IRIS Alert
# Input: Create IRIS Alert body

def unpack(value):
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}

def locate_id(value):
    if isinstance(value, dict):
        for key in ("alert_id", "id"):
            if value.get(key) not in (None, ""):
                return value[key]
        for item in value.values():
            result = locate_id(item)
            if result is not None:
                return result
    elif isinstance(value, list):
        for item in value:
            result = locate_id(item)
            if result is not None:
                return result
    return None

result = locate_id(unpack(r'''$create_iris_alert.body'''))
if result is None:
    raise ValueError("IRIS did not return an alert_id")

print(json.dumps({"iris_alert_id": int(result)}))
