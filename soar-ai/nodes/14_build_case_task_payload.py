import json

# Shuffle node name: Build Case Task Payload
# Inputs:
#   Build Case Artifact Plan message
#   IRIS Local Configuration message
#
# Duplicate this same code for the CREATE branch and change the first input to
# Use the new-case artifact plan message if your node name differs.

def unpack(value):
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}

plan = unpack(r'''$build_case_artifact_plan.message''')
config = unpack(r'''$iris_local_configuration.message''')
task = plan.get("proposed_task") if isinstance(plan.get("proposed_task"), dict) else {}

enabled = bool(plan.get("has_task")) and bool(task)
status_id = config.get("task_status_id")
assignees = config.get("task_assignee_ids") if isinstance(config.get("task_assignee_ids"), list) else []

if status_id is None:
    enabled = False

payload = {
    "task_title": str(task.get("title") or "Review automated SOC finding")[:250],
    "task_description": str(task.get("description") or "Review the alert evidence and update the case.")[:4000],
    "task_status_id": status_id,
    "task_assignees_id": assignees,
    "task_tags": "wazuh,ai-generated,{}".format(str(task.get("priority") or "medium")),
    "custom_attributes": {
        "source": "Shuffle AI triage",
        "priority": task.get("priority") or "medium",
        "correlation_key": plan.get("timeline_payload", {}).get("custom_attributes", {}).get("correlation_key"),
    },
}

print(json.dumps({
    "schema_version": "soc.iris.task-payload/v1",
    "enabled": enabled,
    "case_id": plan.get("case_id"),
    "payload": payload,
    "skip_reason": None if enabled else "No new task or IRIS task_status_id is not configured.",
}, ensure_ascii=False, default=str))
