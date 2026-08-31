import json
import html

# Shuffle node name: Build Case Update Notification
# Inputs:
#   Validate AI Case Decision message
#   Resolve Merged Case message
#
# Existing cases should not spam Slack/Gmail for every low-level event. This
# emits only high/critical updates or explicit analyst-action updates.

def unpack(value):
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}

def rank(value):
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(str(value).lower(), 1)

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
merged = unpack(r'''$resolve_merged_case.message''')
ai = record.get("ai", {})
normalized = record.get("normalized_alert", {})
alert = normalized.get("alert", {})
case_id = merged.get("case_id") or (record.get("selected_case") or {}).get("case_id")
severity = str(ai.get("severity") or "medium").upper()
notify = rank(severity) >= 3 or bool(ai.get("requires_analyst_action"))
color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["MEDIUM"])
emoji = SEVERITY_EMOJI.get(severity, ":large_yellow_circle:")
case_url = "https://10.0.2.107:8000/case?cid={}".format(case_id) if case_id else None

title = alert.get("title", "Security alert")
soc_id = record.get("correlation_key", "unknown")
assessment = str(ai.get("assessment", "uncertain")).replace("_", " ")
confidence = str(ai.get("confidence", "low"))
technical = ai.get("technical_summary", "New correlated evidence was appended to the timeline.")

# ---- Slack ----
slack_blocks = [
    {"type": "header", "text": {"type": "plain_text", "text": "{} SOC Case Updated".format(emoji), "emoji": True}},
    {"type": "section", "fields": [
        {"type": "mrkdwn", "text": "*Severity:*\n{}".format(severity)},
        {"type": "mrkdwn", "text": "*Assessment:*\n{}".format(assessment)},
        {"type": "mrkdwn", "text": "*Confidence:*\n{}".format(confidence)},
        {"type": "mrkdwn", "text": "*Route:*\nmerge_existing"},
    ]},
    {"type": "section", "text": {"type": "mrkdwn", "text": "*{}*".format(title)}},
    {"type": "section", "text": {"type": "mrkdwn", "text": "*What changed:*\n" + technical[:2900]}},
    {"type": "context", "elements": [{"type": "mrkdwn", "text": "SOC ID: `{}`".format(soc_id)}]},
]
if case_url:
    slack_blocks.append({"type": "actions", "elements": [
        {"type": "button", "text": {"type": "plain_text", "text": "Open in IRIS", "emoji": True}, "url": case_url, "style": "primary"}
    ]})

slack_payload = {
    "text": "[{}] SOC case updated: {}".format(severity, title)[:250],
    "attachments": [{"color": color, "blocks": slack_blocks}],
}

# ---- Gmail ----
esc = html.escape
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
                 opacity:0.9;">{severity} &middot; SOC Case Updated</span>
    <h2 style="color:#ffffff;margin:6px 0 0;font-size:18px;font-weight:600;">{title}</h2>
  </div>
  <div style="padding:22px 24px;background:#ffffff;">
    <table style="width:100%;border-collapse:collapse;margin-bottom:18px;font-size:14px;">
      <tr><td style="padding:5px 0;color:#888;width:130px;">Assessment</td><td style="padding:5px 0;font-weight:600;color:#222;">{assessment}</td></tr>
      <tr><td style="padding:5px 0;color:#888;">Confidence</td><td style="padding:5px 0;font-weight:600;color:#222;">{confidence}</td></tr>
      <tr><td style="padding:5px 0;color:#888;">Route</td><td style="padding:5px 0;font-weight:600;color:#222;">merge_existing</td></tr>
      <tr><td style="padding:5px 0;color:#888;vertical-align:top;">SOC ID</td><td style="padding:5px 0;font-family:monospace;font-size:12px;color:#555;word-break:break-all;">{soc_id}</td></tr>
    </table>
    <div style="background:#f6f7f9;border-radius:8px;padding:14px 18px;margin:0 0 20px;">
      <div style="font-weight:700;margin-bottom:8px;color:#222;font-size:13px;text-transform:uppercase;letter-spacing:0.4px;">What changed</div>
      <p style="margin:0;color:#444;font-size:14px;line-height:1.5;">{technical}</p>
    </div>
    {button}
  </div>
</div>
""".format(
    color=color, severity=severity, title=esc(title), assessment=esc(assessment), confidence=esc(confidence),
    soc_id=esc(soc_id), technical=esc(technical), button=case_button_html,
)

print(json.dumps({
    "schema_version": "soc.notification/v2",
    "notify": notify,
    "subject": "[{}] SOC case updated: {}".format(severity, title)[:250],
    "message": slack_payload["text"],
    "slack_payload": slack_payload,
    "slack_payload_json": json.dumps(slack_payload, ensure_ascii=False),
    "html_message": html_message,
    "case_url": case_url or "IRIS case URL unavailable",
}, ensure_ascii=False, default=str))
