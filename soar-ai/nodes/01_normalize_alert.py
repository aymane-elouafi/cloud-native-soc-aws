import json
import re
from urllib.parse import urlparse

def load_json(value):
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}

primary_text = r'''$receive_wazuh_alerts'''
fallback_text = r'''$exec'''

raw = load_json(primary_text)

if (
    not raw
    or (
        raw.get("success") is True
        and "CLEANED after finishing" in str(raw.get("reason", ""))
    )
):
    raw = load_json(fallback_text)

event = raw.get("all_fields", raw) if isinstance(raw, dict) else {}

if isinstance(event, str):
    try:
        event = json.loads(event)
    except Exception:
        event = {}

if not isinstance(event, dict):
    event = {}

def get_path(obj, dotted_path):
    current = obj
    for key in dotted_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current

def first_value(*paths):
    for source in (event, raw):
        if not isinstance(source, dict):
            continue
        for dotted_path in paths:
            value = get_path(source, dotted_path)
            if value not in (None, "", [], {}):
                return value
    return None

def walk_strings(value):
    if isinstance(value, dict):
        result = []
        for item in value.values():
            result.extend(walk_strings(item))
        return result
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(walk_strings(item))
        return result
    return [value] if isinstance(value, str) else []

SENSITIVE_KEYS = {
    "authorization", "cookie", "setcookie", "password", "passwd", "token",
    "secret", "accesskeyid", "secretaccesskey", "session", "xapikey"
}

def redact(value):
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            key_normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            cleaned[key] = "[REDACTED]" if key_normalized in SENSITIVE_KEYS else redact(item)
        return cleaned
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return value[:6000]
    return value

rule = first_value("rule") or {}
if not isinstance(rule, dict):
    rule = {}

groups = rule.get("groups") or first_value("groups") or []
if isinstance(groups, str):
    groups = [groups]
groups = [str(item) for item in groups]

transaction = first_value("data.transaction", "transaction", "text.transaction") or {}
if not isinstance(transaction, dict):
    transaction = {}

request = transaction.get("request", {}) if isinstance(transaction.get("request"), dict) else {}
response = transaction.get("response", {}) if isinstance(transaction.get("response"), dict) else {}
aws = first_value("data.aws", "aws") or {}
if not isinstance(aws, dict):
    aws = {}

source_ip = first_value(
    "data.transaction.client_ip", "transaction.client_ip", "text.transaction.client_ip",
    "data.aws.source_ip_address", "aws.source_ip_address",
    "data.aws.sourceIPAddress", "aws.sourceIPAddress", "srcip"
)
destination_ip = first_value(
    "data.transaction.host_ip", "transaction.host_ip", "text.transaction.host_ip", "dstip"
)
agent_name = first_value("agent.name", "host.name", "hostname")
agent_ip = first_value("agent.ip", "host.ip")

uri = request.get("uri")
method = request.get("method")
body = request.get("body")
headers = request.get("headers", {})
messages = transaction.get("messages", [])

event_source = aws.get("eventSource")
event_name = aws.get("eventName")
bucket = get_path(aws, "requestParameters.bucketName")
object_key = get_path(aws, "requestParameters.key")
role_arn = (
    get_path(aws, "userIdentity.arn")
    or get_path(aws, "userIdentity.sessionContext.sessionIssuer.arn")
)

blob = " ".join(walk_strings(event) + walk_strings(raw) + groups).lower()

if transaction:
    telemetry = "web_application"
elif aws or "cloudtrail" in blob:
    telemetry = "cloudtrail"
elif any(term in blob for term in ("docker", "container", "kubernetes", "trivy")):
    telemetry = "container"
else:
    telemetry = "generic"

family_map = [
    ("authentication", ("authentication", "login_failure", "brute_force", "credential_attack")),
    ("sql_injection", ("sql_injection", "attack-sqli")),
    ("nosql_injection", ("nosql", "nosqli")),
    ("cross_site_scripting", ("xss", "attack-xss")),
    ("server_side_request_forgery", ("ssrf", "imds", "metadata_access")),
    ("file_access", ("lfi", "path_traversal", "attack-lfi", "xxe")),
    ("cloud_storage", ("s3", "getobject", "listobjects", "bucket")),
    ("cloud_identity", ("iam", "assumedrole", "credential_access")),
    ("container_security", ("docker", "container", "kubernetes", "trivy"))
]
attack_family = next(
    (name for name, terms in family_map if any(term in blob for term in terms)),
    "generic_security_event"
)

observables = []

def add_observable(kind, value, source):
    if value in (None, ""):
        return
    observable = {"type": kind, "value": str(value)[:2048], "source": source}
    if observable not in observables:
        observables.append(observable)

add_observable("ip", source_ip, "alert.source")
add_observable("ip", destination_ip, "alert.destination")
add_observable("aws_role_arn", role_arn, "cloudtrail")
add_observable("s3_bucket", bucket, "cloudtrail")
if bucket and object_key:
    add_observable("s3_object", "s3://%s/%s" % (bucket, object_key), "cloudtrail")

for text in walk_strings(event) + walk_strings(raw):
    for url in re.findall(r"https?://[^\s\"'<>]+", text):
        url = url.rstrip(".,)")
        add_observable("url", url, "event")
        hostname = urlparse(url).hostname
        if hostname:
            add_observable("domain", hostname, "event")

waf_findings = []
for finding in messages if isinstance(messages, list) else []:
    if not isinstance(finding, dict):
        continue
    details = finding.get("details", {})
    if not isinstance(details, dict):
        details = {}
    waf_findings.append({
        "message": finding.get("message"),
        "crs_rule_id": details.get("ruleId"),
        "severity": details.get("severity"),
        "tags": details.get("tags", []),
        "matched_data": details.get("data"),
        "match_context": details.get("match"),
        "rule_file": details.get("file")
    })

normalized = {
    "schema_version": "soc.normalized.alert/v4",
    "alert": {
        "source": "wazuh",
        "alert_id": str(first_value("id", "alert.id") or "unknown"),
        "timestamp": first_value("timestamp", "event.created", "event_time"),
        "rule_id": str(rule.get("id") or first_value("rule_id") or "unknown"),
        "rule_level": rule.get("level") or first_value("severity", "level"),
        "title": rule.get("description") or first_value("title", "pretext") or "Security alert received",
        "groups": groups,
        "location": first_value("location")
    },
    "classification": {"telemetry": telemetry, "attack_family": attack_family},
    "source": {"ip": source_ip},
    "destination": {"ip": destination_ip},
    "asset": {"name": agent_name, "ip": agent_ip},
    "web": {
        "client_ip": source_ip,
        "server_ip": destination_ip,
        "method": method,
        "uri": uri,
        "request_body": redact(body),
        "request_headers": redact(headers),
        "response_status": response.get("http_code"),
        "waf_findings": redact(waf_findings)
    } if telemetry == "web_application" else {},
    "cloud": {
        "event_source": event_source,
        "event_name": event_name,
        "region": aws.get("awsRegion"),
        "principal_arn": role_arn,
        "bucket": bucket,
        "object_key": object_key,
        "request_parameters": redact(aws.get("requestParameters", {}))
    } if telemetry == "cloudtrail" else {},
    "observables": observables,
    "correlation_features": {
        "attack_family": attack_family,
        "telemetry": telemetry,
        "source": source_ip or "unknown",
        "asset": agent_name or agent_ip or destination_ip or "unknown",
        "target": (uri or bucket or agent_name or destination_ip or "unknown")[:512]
    },
    "sanitized_raw_event": redact(event)
}

print(json.dumps(normalized, ensure_ascii=False, default=str))
