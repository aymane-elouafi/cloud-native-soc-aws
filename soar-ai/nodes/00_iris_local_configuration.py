import json

# Shuffle node name: IRIS Local Configuration
#
# Replace the placeholder IDs below with IDs from *your* IRIS instance before
# enabling real IRIS IOCs, Assets, or Tasks.  Keeping a value as None is safe:
# the related artifact is retained in alert_context/evidence but is not created
# with a potentially wrong IRIS type.
#
# This node contains no secrets. Keep the IRIS API key in each HTTP node's
# Authorization header, not in Shuffle Python or workflow variables.

configuration = {
    "iris_base_url": "https://10.0.2.107:8000",
    "customer_id": 1,

    # Mapped from the live IRIS instance (100.100.67.0:8000 / 10.0.2.107:8000)
    # via /manage/tlp/list, /manage/ioc-types/list, /manage/asset-type/list,
    # /manage/task-status/list, /manage/users/list. Kept in sync with the
    # values already pasted into the live Shuffle "IRIS Local Configuration"
    # node so the repo file and the running workflow agree.
    "default_tlp_id": 2,  # amber
    "ioc_type_ids": {
        "ip": 76,             # ip-any (used by 01/02 for source+destination IP observables)
        "source_ip": 79,      # ip-src
        "destination_ip": 77, # ip-dst
        "domain": 20,         # domain
        "hostname": 69,       # hostname
        "url": 141,           # url
        "uri": 140,           # uri
        "md5": 90,            # md5
        "sha1": 111,          # sha1
        "sha256": 113,        # sha256
        "hash": 113,          # generic hash -> sha256
        "email": 31,          # email-src
        "aws_role_arn": None,
        "s3_bucket": None,
        "s3_object": None,
    },
    "asset_type_ids": {
        "host": 3,            # Linux - Server
        "linux_server": 3,    # Linux - Server
        "linux_computer": 4,  # Linux - Computer
        "waf": 15,            # WAF
        "account": 1,         # Account
        "vpn": 14,            # VPN
        "container": 3,       # reused: Linux - Server (no dedicated container type in IRIS)
        "cloud_resource": 3,  # reused: Linux - Server (no dedicated cloud-resource type in IRIS)
    },

    # Set both fields together if automated analyst tasks should be created.
    # task_assignee_ids is an array even when it contains one analyst.
    "task_status_id": 1,        # To do
    "task_assignee_ids": [1],   # administrator

    # This IRIS instance requires alert_severity_id and alert_status_id on
    # POST /alerts/add (400 "Missing data for required field" without them).
    # From /manage/severities/list: 1 Medium, 2 Unspecified, 3 Informational,
    # 4 Low, 5 High, 6 Critical.
    "severity_ids": {
        "critical": 6,
        "high": 5,
        "medium": 1,
        "low": 4,
        "informational": 3,
        "unspecified": 2,
    },
    # From /manage/alert-status/list: 2 New (unassigned, correct default for
    # freshly created alerts awaiting AI triage).
    "default_alert_status_id": 2,

    # Bounded context keeps local-model triage responsive.
    "max_open_case_candidates": 12,
    "max_case_context_events": 5,
}

print(json.dumps(configuration, ensure_ascii=False))
