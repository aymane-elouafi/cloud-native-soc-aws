import json
import os
import uuid
from datetime import datetime, timezone

import boto3


dynamodb = boto3.resource("dynamodb")
sqs = boto3.client("sqs")

JOB_TABLE = os.environ["JOB_TABLE"]
QUEUE_URL = os.environ["QUEUE_URL"]
AUDIT_GROUP = os.environ.get("AUDIT_GROUP", "AuditTeam")


def response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(body, default=str)
    }


def get_claim_groups(claims):
    raw_groups = claims.get("cognito:groups", [])

    if isinstance(raw_groups, list):
        return [str(group).strip() for group in raw_groups if str(group).strip()]

    if not raw_groups:
        return []

    return [
        group.strip().strip('"').strip("'")
        for group in str(raw_groups).strip("[]").split(",")
        if group.strip()
    ]


def write_security_event(event_type, **fields):
    event_record = {
        "integration": "scenario3_serverless",
        "component": "report_api",
        "event_type": event_type,
        "event_time": datetime.now(timezone.utc).isoformat(),
        **fields
    }

    # Goes to CloudWatch. Do not log tokens, passwords, secrets, or report data.
    print(json.dumps(event_record, default=str))


def lambda_handler(event, context):
    claims = (
        event.get("requestContext", {})
        .get("authorizer", {})
        .get("jwt", {})
        .get("claims", {})
    )

    owner_sub = claims.get("sub")

    if not owner_sub:
        return response(401, {"message": "Missing authenticated user identity"})

    actor_username = (
        claims.get("username")
        or claims.get("cognito:username")
        or "unknown"
    )

    actor_groups = get_claim_groups(claims)
    actor_is_audit_user = AUDIT_GROUP in actor_groups

    method = event.get("requestContext", {}).get("http", {}).get("method", "")
    source_ip = (
        event.get("requestContext", {})
        .get("http", {})
        .get("sourceIp", "unknown")
    )

    path_parameters = event.get("pathParameters") or {}
    table = dynamodb.Table(JOB_TABLE)

    # Create a report job.
    if method == "POST":
        try:
            body = json.loads(event.get("body") or "{}")
        except json.JSONDecodeError:
            return response(400, {"message": "Request body must be valid JSON"})

        # DELIBERATE LAB VULNERABILITY:
        # User-controlled scope is still trusted. We only add detection logging.
        requested_scope = body.get("requested_scope", "standard")
        target_department = body.get("target_department", "general")

        job_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()

        write_security_event(
            "report_scope_requested",
            job_id=job_id,
            actor_sub=owner_sub,
            actor_username=actor_username,
            actor_groups=actor_groups,
            actor_is_audit_user=actor_is_audit_user,
            requested_scope=requested_scope,
            target_department=target_department,
            source_ip=source_ip
        )

        job = {
            "job_id": job_id,
            "owner_sub": owner_sub,
            "status": "QUEUED",
            "requested_scope": requested_scope,
            "target_department": target_department,
            "created_at": created_at
        }

        table.put_item(Item=job)

        sqs.send_message(
            QueueUrl=QUEUE_URL,
            MessageBody=json.dumps({
                "job_id": job_id,
                "owner_sub": owner_sub,
                "requested_scope": requested_scope,
                "target_department": target_department
            })
        )

        return response(202, {
            "job_id": job_id,
            "status": "QUEUED"
        })

    # Return only the job owned by the authenticated user.
    if method == "GET":
        job_id = path_parameters.get("jobId")

        if not job_id:
            return response(400, {"message": "Missing job ID"})

        result = table.get_item(Key={"job_id": job_id})
        job = result.get("Item")

        if not job:
            return response(404, {"message": "Job not found"})

        if job.get("owner_sub") != owner_sub:
            return response(403, {"message": "You do not own this job"})

        return response(200, job)

    return response(405, {"message": "Method not allowed"})
