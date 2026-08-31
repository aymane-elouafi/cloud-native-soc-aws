import json
import html

# Shuffle node name: Build New Case Notification
# Inputs:
#   Validate AI Case Decision message
#   Resolve Created Case message

def unpack(value):
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}

SEVERITY_COLORS = {
    "CRITICAL": "#E01E5A",
    "HIGH": "#E8912D",
    "MEDIUM": "#ECB22E",
    "LOW": "#2EB67D",
}
SEVERITY_EMOJI = {
    "CRITICAL": ":rotating_light:",
    "HIGH": ":warning:",
    "MEDIUM": ":large_yellow_circle:",
    "LOW": ":large_green_circle:",
}

record = unpack(r'''$validate_ai_case_decision.message''')
created = unpack(r'''$resolve_created_case.message''')
ai = record.get("ai", {})
normalized = record.get("normalized_alert", {})
alert = normalized.get("alert", {})
source_ip = (normalized.get("source") or {}).get("ip") or "unknown"
case_id = created.get("case_id")
severity = str(ai.get("severity") or "medium").upper()
color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["MEDIUM"])
emoji = SEVERITY_EMOJI.get(severity, ":large_yellow_circle:")
case_url = "https://10.0.2.107:8000/case?cid={}".format(case_id) if case_id else None

title = alert.get("title", "Security alert")
soc_id = record.get("correlation_key", "unknown")
assessment = str(ai.get("assessment", "uncertain")).replace("_", " ")
confidence = str(ai.get("confidence", "low"))
summary = ai.get("executive_summary", "No AI summary was supplied.")

actions = ai.get("analyst_tasks") if isinstance(ai.get("analyst_tasks"), list) else []
action_lines = []
for item in actions[:5]:
    if isinstance(item, dict):
        action_lines.append("{}: {}".format(item.get("title", "Review finding"), item.get("description", "")))
    else:
        action_lines.append(str(item))
if not action_lines:
    action_lines = ["Review the IRIS case evidence"]

# ---- Slack: Block Kit inside a colored attachment (gives the vertical color bar) ----
slack_blocks = [
    {"type": "header", "text": {"type": "plain_text", "text": "{} New SOC Case Created".format(emoji), "emoji": True}},
    {"type": "section", "fields": [
        {"type": "mrkdwn", "text": "*Severity:*\n{}".format(severity)},
        {"type": "mrkdwn", "text": "*Assessment:*\n{}".format(assessment)},
        {"type": "mrkdwn", "text": "*Confidence:*\n{}".format(confidence)},
        {"type": "mrkdwn", "text": "*Source IP:*\n{}".format(source_ip)},
    ]},
    {"type": "section", "text": {"type": "mrkdwn", "text": "*{}*".format(title)}},
    {"type": "section", "text": {"type": "mrkdwn", "text": summary[:2900]}},
    {"type": "section", "text": {"type": "mrkdwn", "text": "*Recommended actions:*\n" + "\n".join("- " + a for a in action_lines)[:2900]}},
    {"type": "context", "elements": [{"type": "mrkdwn", "text": "SOC ID: `{}`".format(soc_id)}]},
]
if case_url:
    slack_blocks.append({"type": "actions", "elements": [
        {"type": "button", "text": {"type": "plain_text", "text": "Open in IRIS", "emoji": True}, "url": case_url, "style": "primary"}
    ]})

slack_payload = {
    "text": "[{}] New SOC case created: {}".format(severity, title)[:250],
    "attachments": [{"color": color, "blocks": slack_blocks}],
}

# ---- Gmail: inline-styled HTML card ----
esc = html.escape
action_items_html = "".join("<li style=\"margin-bottom:4px;\">{}</li>".format(esc(a)) for a in action_lines)
case_button_html = (
    "<a href=\"{url}\" style=\"display:inline-block;background:{color};color:#ffffff;text-decoration:none;"
    "padding:10px 22px;border-radius:6px;font-weight:600;font-size:14px;\">Open in IRIS &rarr;</a>".format(
        url=esc(case_url), color=color
    ) if case_url else ""
)

html_message = """
<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:600px;margin:0 auto;
            border:1px solid #e5e5e5;border-radius:10px;overflow:hidden;">
  <div style="background:{color};padding:18px 24px;">
    <span style="color:#ffffff;font-weight:700;font-size:11px;letter-spacing:1px;text-transform:uppercase;
                 opacity:0.9;">{severity} &middot; New SOC Case</span>
    <h2 style="color:#ffffff;margin:6px 0 0;font-size:18px;font-weight:600;">{title}</h2>
  </div>
  <div style="padding:22px 24px;background:#ffffff;">
    <table style="width:100%;border-collapse:collapse;margin-bottom:18px;font-size:14px;">
      <tr><td style="padding:5px 0;color:#888;width:130px;">Assessment</td><td style="padding:5px 0;font-weight:600;color:#222;">{assessment}</td></tr>
      <tr><td style="padding:5px 0;color:#888;">Confidence</td><td style="padding:5px 0;font-weight:600;color:#222;">{confidence}</td></tr>
      <tr><td style="padding:5px 0;color:#888;">Source IP</td><td style="padding:5px 0;font-weight:600;color:#222;">{source_ip}</td></tr>
      <tr><td style="padding:5px 0;color:#888;vertical-align:top;">SOC ID</td><td style="padding:5px 0;font-family:monospace;font-size:12px;color:#555;word-break:break-all;">{soc_id}</td></tr>
    </table>
    <p style="color:#333;line-height:1.55;font-size:14px;margin:0 0 16px;">{summary}</p>
    <div style="background:#f6f7f9;border-radius:8px;padding:14px 18px;margin:0 0 20px;">
      <div style="font-weight:700;margin-bottom:8px;color:#222;font-size:13px;text-transform:uppercase;letter-spacing:0.4px;">Recommended actions</div>
      <ul style="margin:0;padding-left:18px;color:#444;font-size:14px;">{actions}</ul>
    </div>
    {button}
    <p style="color:#999;font-size:12px;margin:18px 0 0;">Human analyst review is required before containment or closure.</p>
  </div>
</div>
""".format(
    color=color, severity=severity, title=esc(title), assessment=esc(assessment), confidence=esc(confidence),
    source_ip=esc(source_ip), soc_id=esc(soc_id), summary=esc(summary), actions=action_items_html,
    button=case_button_html,
)

print(json.dumps({
    "schema_version": "soc.notification/v2",
    "notify": True,
    "subject": "[{}] SOC case created: {}".format(severity, title)[:250],
    "message": slack_payload["text"],
    "slack_payload": slack_payload,
    # Pre-serialized so the Slack HTTP node body is already valid JSON text
    # instead of relying on Shuffle to re-serialize a nested object when
    # resolving a dotted path into this node's output.
    "slack_payload_json": json.dumps(slack_payload, ensure_ascii=False),
    "html_message": html_message,
    "case_url": case_url or "IRIS case URL unavailable",
}, ensure_ascii=False, default=str))
