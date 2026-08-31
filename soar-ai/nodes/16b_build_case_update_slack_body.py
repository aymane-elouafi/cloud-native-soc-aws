import json

# Shuffle node name: Build Case Update Slack Body
# Input: Build Case Update Notification message
#
# Adapter node, same reason as 15b_build_new_case_slack_body.py: keeps the
# Notify Slack HTTP node referencing a full top-level `.message` so Shuffle
# doesn't re-serialize (and corrupt) a nested field reference.

def unpack(value):
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}

notification = unpack(r'''$build_case_update_notification.message''')
slack_payload = notification.get("slack_payload") or {}

print(json.dumps(slack_payload, ensure_ascii=False))
