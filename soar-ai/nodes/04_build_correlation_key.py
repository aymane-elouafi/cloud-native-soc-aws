import json
import re
from urllib.parse import urlparse, quote

# Shuffle node name: Build Correlation Key   (v2 - entity/campaign correlation)
# Input: Normalize Alert message
#
# WHY THIS CHANGED
# The old scheme built ONE exact key "soc:v1:{family}:{telemetry}:{asset}:{source}:{target}".
# Because it baked the attack_family and telemetry into the key, every stage of
# a single attacker campaign (brute force -> SSTI -> container escape -> IMDS
# theft -> IAM privesc -> S3 exfil) produced a DIFFERENT key and therefore a
# separate IRIS case. That is the kill-chain fragmentation bug.
#
# The v2 model instead emits:
#   (a) a coarse CAMPAIGN ANCHOR keyed on the attacker<->target pair only
#       (no family, no telemetry) so repeated activity against the same target
#       shares one anchor, and
#   (b) an ENTITY SET (attacker IPs, target hosts, IAM identities, resources).
# Node 05 correlates a new alert to an open case when they share the anchor OR
# any entity (entities are persisted on the case as `ent:*` tags). This is the
# entity-overlap grouping model used by Microsoft Sentinel and Cortex XSOAR.
#
# The host stage is the pivot: an IMDS-theft / host alert carries BOTH the host
# (shared with the web stages) AND the stolen role (shared with the cloud
# stages), so overlap transitively links the full chain into one case.

def unpack(value):
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}

def norm(value):
    # stable, comparable token fragment
    return re.sub(r"[^a-z0-9._:@/-]+", "-", str(value or "").strip().lower()).strip("-")[:160]

alert = unpack(r'''$normalize_alert.message''')
classification = alert.get("classification", {}) or {}
features = alert.get("correlation_features", {}) or {}
source = alert.get("source", {}) or {}
destination = alert.get("destination", {}) or {}
asset = alert.get("asset", {}) or {}
cloud = alert.get("cloud", {}) or {}
observables = alert.get("observables", []) or []

family = classification.get("attack_family") or "generic_security_event"
telemetry = classification.get("telemetry") or "generic"

attacker_ips, assets, identities, resources = [], [], [], []

def push(bucket, value):
    v = norm(value)
    if v and v not in bucket:
        bucket.append(v)

# attacker IP(s): the external actor driving the web/host stages
push(attacker_ips, source.get("ip") or features.get("source"))

# target host(s): the compromised endpoint - the pivot that ties web -> host
push(assets, asset.get("name"))
push(assets, asset.get("ip"))
push(assets, destination.get("ip"))

# IAM identities: link the host stage to the cloud stages
def role_tokens(arn):
    if not arn:
        return
    push(identities, arn)                                  # full ARN
    push(identities, str(arn).rsplit("/", 1)[-1])          # role/session name
    m = re.search(r"assumed-role/([^/]+)", str(arn))
    if m:
        push(identities, m.group(1))                       # role name only

role_tokens(cloud.get("principal_arn"))

# resources: buckets, objects, domains, url hosts
push(resources, cloud.get("bucket"))
if cloud.get("bucket") and cloud.get("object_key"):
    push(resources, "s3://%s/%s" % (cloud.get("bucket"), cloud.get("object_key")))

for ob in observables:
    if not isinstance(ob, dict):
        continue
    kind, val = ob.get("type"), ob.get("value")
    if kind == "ip":
        # the destination/server IP is the TARGET host, not the attacker.
        if ob.get("source") == "alert.destination":
            push(assets, val)
        else:
            push(attacker_ips, val)
    elif kind == "aws_role_arn":
        role_tokens(val)
    elif kind in ("s3_bucket", "s3_object"):
        push(resources, val)
    elif kind == "domain":
        push(resources, val)
    elif kind == "url":
        host = urlparse(str(val)).hostname
        push(resources, host)

def toks(prefix, values):
    return ["ent:%s:%s" % (prefix, v) for v in values if v]

entity_tokens = toks("ip", attacker_ips) + toks("host", assets) + toks("id", identities) + toks("res", resources)
# strong entities are trusted to correlate across stages; a bare domain/url is
# weaker so it is still emitted but scored lower by node 05.
strong_tokens = toks("ip", attacker_ips) + toks("host", assets) + toks("id", identities)

# Coarse anchor for the common case (same attacker on same target). Priority:
# target host (the kill-chain pivot) > attacker IP > normalized target.
anchor_basis = (assets[0] if assets else "") or (attacker_ips[0] if attacker_ips else "") or norm(features.get("target")) or "unknown"
campaign_anchor = "soc:v2:campaign:%s" % anchor_basis

phase_map = [
    ("initial_access", ("authentication",)),
    ("exploitation", ("sql_injection", "nosql_injection", "cross_site_scripting", "file_access", "server_side_request_forgery")),
    ("container_escape", ("container_security",)),
    ("credential_access", ("cloud_identity",)),
    ("collection_exfiltration", ("cloud_storage",)),
]
kill_chain_phase = next((p for p, fams in phase_map if family in fams), "activity")

print(json.dumps({
    "schema_version": "soc.correlation-entities/v2",
    "campaign_anchor": campaign_anchor,
    "campaign_anchor_urlencoded": quote(campaign_anchor, safe=""),
    "attack_family": family,
    "telemetry": telemetry,
    "kill_chain_phase": kill_chain_phase,
    "entities": {
        "attacker_ips": attacker_ips,
        "assets": assets,
        "identities": identities,
        "resources": resources,
    },
    "entity_tokens": entity_tokens,
    "strong_tokens": strong_tokens,
    # backward-compat: any node still reading correlation_key gets the anchor.
    "correlation_key": campaign_anchor,
    "correlation_key_urlencoded": quote(campaign_anchor, safe=""),
}, ensure_ascii=False))
