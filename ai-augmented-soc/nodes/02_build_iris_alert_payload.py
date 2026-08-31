import json

# Shuffle node name: Build IRIS Alert Payload
#
# Creates an IRIS *alert* first.  The workflow only escalates or merges the
# alert after the AI correlation decision.  Use this file instead of the older
# 02_build_iris_alert_payload.py file.

def unpack(value):
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}

def clip(value, limit=7000):
    text = json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= limit else text[:limit] + "...[truncated]"

def add_unique(items, value):
    if value not in (None, "") and value not in items:
        items.append(value)

def severity_bucket(rule_level):
    try:
        level = int(rule_level)
    except (TypeError, ValueError):
        return "unspecified"
    if level >= 12:
        return "critical"
    if level >= 9:
        return "high"
    if level >= 6:
        return "medium"
    if level >= 3:
        return "low"
    return "informational"

normalized = unpack(r'''$normalize_alert.message''')
config = unpack(r'''$iris_local_configuration.message''')
alert = normalized.get("alert", {})
classification = normalized.get("classification", {})

source_ref = "wazuh:{}".format(alert.get("alert_id") or "unknown")
telemetry = str(classification.get("telemetry") or "generic")
family = str(classification.get("attack_family") or "generic_security_event")
tags = ["wazuh", "automated-intake", telemetry, family]
for group in alert.get("groups", []) if isinstance(alert.get("groups"), list) else []:
    add_unique(tags, str(group))

context = {
    "schema_version": "soc.iris.alert-context/v4",
    "wazuh_alert_id": alert.get("alert_id"),
    "wazuh_rule_id": alert.get("rule_id"),
    "wazuh_rule_level": alert.get("rule_level"),
    "telemetry": telemetry,
    "attack_family": family,
    "correlation_features": normalized.get("correlation_features", {}),
    "source": normalized.get("source", {}),
    "destination": normalized.get("destination", {}),
    "asset": normalized.get("asset", {}),
    "web": normalized.get("web", {}),
    "cloud": normalized.get("cloud", {}),
    "observables": normalized.get("observables", []),
    "sanitized_raw_event": normalized.get("sanitized_raw_event", {}),
    "pipeline_state": "awaiting_ai_correlation",
}

severity_ids = config.get("severity_ids", {})
severity_id = severity_ids.get(severity_bucket(alert.get("rule_level")))
if severity_id is None:
    severity_id = severity_ids.get("unspecified", 2)

payload = {
    "alert_title": str(alert.get("title") or "Wazuh security alert")[:250],
    "alert_description": (
        "Automated Wazuh intake. Redacted detector evidence and normalized "
        "observables are stored in alert_context pending correlation-aware AI triage."
    ),
    "alert_source": "Wazuh",
    "alert_source_ref": source_ref,
    "alert_customer_id": config.get("customer_id", 1),
    "alert_source_event_time": alert.get("timestamp"),
    "alert_source_content": clip(normalized.get("sanitized_raw_event", {})),
    "alert_context": context,
    "alert_note": "Created by Shuffle; awaiting AI case-correlation decision.",
    "alert_tags": ",".join(tags),
    # Required by this IRIS instance's alert schema (400 without them).
    "alert_severity_id": severity_id,
    "alert_status_id": config.get("default_alert_status_id", 2),
}

# Native IRIS IOCs are optional until you map the exact type/TLP IDs from your
# own IRIS instance.  Unknown values stay in alert_context rather than being
# assigned an incorrect IOC type.
ioc_type_ids = config.get("ioc_type_ids", {})
default_tlp_id = config.get("default_tlp_id")
native_iocs = []
for observable in normalized.get("observables", []):
    if not isinstance(observable, dict):
        continue
    kind = observable.get("type")
    value = observable.get("value")
    type_id = ioc_type_ids.get(kind)
    if value and type_id is not None and default_tlp_id is not None:
        native_iocs.append({
            "ioc_value": str(value)[:2048],
            "ioc_description": "Observed in {}".format(source_ref),
            "ioc_tlp_id": default_tlp_id,
            "ioc_type_id": type_id,
            "ioc_tags": "wazuh,{},{}".format(telemetry, kind),
            "ioc_enrichment": {},
        })
if native_iocs:
    payload["alert_iocs"] = native_iocs

# Native assets provide the relationships IRIS needs for its graph.  They are
# imported with the alert during merge/escalation when type IDs are configured.
asset_type_ids = config.get("asset_type_ids", {})
asset = normalized.get("asset", {}) if isinstance(normalized.get("asset"), dict) else {}
native_assets = []
host_name = asset.get("name") or (normalized.get("destination") or {}).get("ip")
host_type = asset_type_ids.get("host")
if host_name and host_type is not None:
    native_assets.append({
        "asset_name": str(host_name)[:250],
        "asset_description": "Wazuh-monitored asset associated with {}".format(source_ref),
        "asset_type_id": host_type,
        "asset_ip": str(asset.get("ip") or (normalized.get("destination") or {}).get("ip") or ""),
        "asset_domain": "",
        "asset_info": "Telemetry: {}; family: {}".format(telemetry, family),
        "asset_tags": "wazuh,{}".format(telemetry),
        "asset_enrichment": {},
    })

container = asset.get("container") if isinstance(asset.get("container"), dict) else {}
container_name = container.get("name") or container.get("container_name") or container.get("id")
container_type = asset_type_ids.get("container")
if container_name and container_type is not None:
    native_assets.append({
        "asset_name": str(container_name)[:250],
        "asset_description": "Container observed in {}".format(source_ref),
        "asset_type_id": container_type,
        "asset_ip": "",
        "asset_domain": "",
        "asset_info": clip(container, 1500),
        "asset_tags": "wazuh,container",
        "asset_enrichment": {},
    })

cloud = normalized.get("cloud", {}) if isinstance(normalized.get("cloud"), dict) else {}
cloud_name = cloud.get("bucket") or cloud.get("principal_arn")
cloud_type = asset_type_ids.get("cloud_resource")
if cloud_name and cloud_type is not None:
    native_assets.append({
        "asset_name": str(cloud_name)[:250],
        "asset_description": "Cloud resource observed in {}".format(source_ref),
        "asset_type_id": cloud_type,
        "asset_ip": "",
        "asset_domain": "",
        "asset_info": clip(cloud, 1500),
        "asset_tags": "wazuh,cloudtrail",
        "asset_enrichment": {},
    })
if native_assets:
    payload["alert_assets"] = native_assets

print(json.dumps(payload, ensure_ascii=False, default=str))
