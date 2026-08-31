import json
import os
from datetime import datetime, timezone

import boto3
import pymysql


JOB_TABLE = os.environ["JOB_TABLE"]
AUDIT_ROLE_ARN = os.environ["AUDIT_ROLE_ARN"]
DB_SECRET_ARN = os.environ["DB_SECRET_ARN"]

dynamodb = boto3.resource("dynamodb")
sts = boto3.client("sts")


def write_security_event(event_type, **fields):
    event_record = {
        "integration": "scenario3_serverless",
        "component": "audit_worker",
        "event_type": event_type,
        "event_time": datetime.now(timezone.utc).isoformat(),
        **fields
    }

    # Safe telemetry only: never log secrets, tokens, passwords, or RDS records.
    print(json.dumps(event_record, default=str))


def get_audit_database_secret():
    assumed = sts.assume_role(
        RoleArn=AUDIT_ROLE_ARN,
        RoleSessionName="Scenario3AuditWorker"
    )["Credentials"]

    secrets = boto3.client(
        "secretsmanager",
        aws_access_key_id=assumed["AccessKeyId"],
        aws_secret_access_key=assumed["SecretAccessKey"],
        aws_session_token=assumed["SessionToken"]
    )

    response = secrets.get_secret_value(SecretId=DB_SECRET_ARN)
    return json.loads(response["SecretString"])


def query_audit_records():
    secret = get_audit_database_secret()

    connection = pymysql.connect(
        host=secret["host"],
        port=int(secret.get("port", 3306)),
        user=secret["username"],
        password=secret["password"],
        connect_timeout=8,
        read_timeout=15,
        write_timeout=15,
        cursorclass=pymysql.cursors.DictCursor
    )

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT audit_id, department, report_period,
                       risk_rating, internal_note
                FROM finance_lab.audit_records
                ORDER BY audit_id
            """)
            return cursor.fetchall()
    finally:
        connection.close()


def update_job(job_id, status, result):
    table = dynamodb.Table(JOB_TABLE)

    table.update_item(
        Key={"job_id": job_id},
        UpdateExpression=(
            "SET #status = :status, "
            "completed_at = :completed_at, "
            "report_result = :report_result"
        ),
        ExpressionAttributeNames={
            "#status": "status"
        },
        ExpressionAttributeValues={
            ":status": status,
            ":completed_at": datetime.now(timezone.utc).isoformat(),
            ":report_result": result
        }
    )


def lambda_handler(event, context):
    for record in event["Records"]:
        message = json.loads(record["body"])

        job_id = message["job_id"]
        actor_sub = message.get("owner_sub", "unknown")
        requested_scope = message.get("requested_scope", "standard")

        # DELIBERATE LAB VULNERABILITY:
        # The worker still trusts user-controlled scope received through SQS.
        if requested_scope == "audit":
            write_security_event(
                "restricted_report_job_started",
                job_id=job_id,
                actor_sub=actor_sub,
                requested_scope=requested_scope
            )

            try:
                records = query_audit_records()

                write_security_event(
                    "restricted_report_job_completed",
                    job_id=job_id,
                    actor_sub=actor_sub,
                    requested_scope=requested_scope,
                    record_count=len(records)
                )

            except Exception as error:
                write_security_event(
                    "restricted_report_job_failed",
                    job_id=job_id,
                    actor_sub=actor_sub,
                    requested_scope=requested_scope,
                    error_type=type(error).__name__
                )
                raise

            result = {
                "scope": "audit",
                "records": records
            }

        else:
            write_security_event(
                "standard_report_job_completed",
                job_id=job_id,
                actor_sub=actor_sub,
                requested_scope=requested_scope
            )

            result = {
                "scope": "standard",
                "message": "Standard report completed.",
                "records": []
            }

        update_job(job_id, "COMPLETED", result)

    return {"statusCode": 200}
