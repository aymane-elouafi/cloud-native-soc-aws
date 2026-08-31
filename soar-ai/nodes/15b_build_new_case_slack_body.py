import json

# Shuffle node name: Build New Case Slack Body
# Input: Build New Case Notification message
#
# Adapter node. Shuffle safely passes through a node's full `.message` output
# untouched, but re-serializes (and corrupts) a nested field reference like
# `.message.slack_payload_json`. This node exists solely so the Notify Slack
# HTTP node can reference a full, top-level `.message` again.

def unpack(value):
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}

notification = unpack(r'''$build_new_case_notification.message''')
slack_payload = notification.get("slack_payload") or {}

print(json.dumps(slack_payload, ensure_ascii=False))
