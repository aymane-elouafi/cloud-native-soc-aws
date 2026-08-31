import json
import re

# Shuffle node name: Build New Case Setup   (v2 - colored, structured, living)
# Inputs: Validate AI Case Decision message ($validate_ai_case_decision.message)
#         Resolve Created Case message      ($resolve_created_case.message)
#
# create_case branch. Builds a colored, analyst-first case summary AND embeds a
# machine-readable soc-state block at the end. Node 12 (merge) parses that block
# to grow the SAME case on every new alert (living summary + timeline + gaps),
# so the two nodes share the render_case_description()/SOC_STATE contract below.

SOC_STATE_RE = re.compile(r"<!--\s*soc-state:v1\s*(\{.*?\})\s*-->", re.DOTALL)

SEV_BADGE = {"critical": "🔴 CRITICAL", "high": "🟠 HIGH", "medium": "🟡 MEDIUM", "low": "🟢 LOW"}
ASSESS_BADGE = {
    "likely_true_positive": "🔴 Likely TRUE POSITIVE",
    "uncertain": "🟡 UNCERTAIN — needs analyst review",
    "likely_false_positive": "🟢 Likely false positive",
}
PHASE_ICON = {
    "initial_access": "🚪 Initial access",
    "exploitation": "💥 Exploitation",
    "container_escape": "📦 Container escape",
    "credential_access": "🔑 Credential access",
    "collection_exfiltration": "📤 Collection / exfiltration",
    "activity": "• Activity",
}

def unpack(value):
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}

def esc(text):
    return str(text).replace("|", "\\|").replace("\n", " ").strip()

def bullets(values, fallback):
    out = []
    for v in values if isinstance(values, list) else []:
        if isinstance(v, dict):
            title = str(v.get("title") or "").strip()
            desc = str(v.get("description") or "").strip()
            prio = str(v.get("priority") or "").strip()
            line = title + (" `[{}]`".format(prio) if prio else "") + (" — " + desc if desc else "")
        else:
            line = str(v).strip()
        if line:
            out.append("- " + line)
    return "\n".join(out) if out else "- _" + fallback + "_"

def mitre_table(values):
    rows = ["| Technique | Name | Tactic | Rationale |", "|---|---|---|---|"]
    seen = set()
    for it in values if isinstance(values, list) else []:
        if not isinstance(it, dict):
            continue
        tid = str(it.get("technique_id", "")).strip()
        tac = str(it.get("tactic", "")).strip()
        if (tid.lower(), tac.lower()) in seen:
            continue
        seen.add((tid.lower(), tac.lower()))
        rows.append("| `{}` | {} | {} | {} |".format(
            esc(tid), esc(it.get("technique_name", "")), esc(tac), esc(it.get("rationale", ""))[:300]))
    if len(rows) == 2:
        rows.append("| _n/a_ | _Not determined_ | | _Insufficient evidence_ |")
    return "\n".join(rows)

def timeline_table(timeline):
    rows = ["| # | Time (UTC) | Phase | Technique | Target | Outcome |", "|---|---|---|---|---|---|"]
    for i, e in enumerate(timeline if isinstance(timeline, list) else [], 1):
        phase = PHASE_ICON.get(e.get("phase"), e.get("phase") or "•")
        rows.append("| {} | {} | {} | `{}` — {} | {} | {} |".format(
            i, esc(e.get("ts") or "?"), esc(phase), esc(e.get("technique_id") or ""),
            esc(e.get("title") or ""), esc(e.get("target") or ""), esc(e.get("outcome") or "")))
    if len(rows) == 2:
        rows.append("| 1 | | | | _pending_ | |")
    return "\n".join(rows)

def entities_block(entities):
    e = entities if isinstance(entities, dict) else {}
    def fmt(vals):
        vals = [v for v in (vals or []) if v]
        return ", ".join("`{}`".format(v) for v in vals[:12]) if vals else "_none observed_"
    return "\n".join([
        "- 🌐 **Attacker IPs:** " + fmt(e.get("attacker_ips")),
        "- 🖥️ **Hosts / assets:** " + fmt(e.get("assets")),
        "- 🔑 **IAM identities:** " + fmt(e.get("identities")),
        "- 📦 **Resources:** " + fmt(e.get("resources")),
    ])

def pretty(value, limit=2500):
    r = json.dumps(value, ensure_ascii=False, indent=2, default=str)
    return r if len(r) <= limit else r[:limit] + "\n...[truncated]"

def evidence_entry(normalized, family):
    """Compact, per-alert detector evidence kept permanently in the case state so
    later merges never erase an earlier alert's WAF/log detail."""
    web = normalized.get("web", {}) if isinstance(normalized.get("web"), dict) else {}
    cloud = normalized.get("cloud", {}) if isinstance(normalized.get("cloud"), dict) else {}
    alert = normalized.get("alert", {}) if isinstance(normalized.get("alert"), dict) else {}
    raw = normalized.get("sanitized_raw_event", {})
    raw_txt = raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=False, default=str)
    findings = []
    for f in (web.get("waf_findings") or [])[:8]:
        if isinstance(f, dict):
            findings.append({
                "crs_rule_id": f.get("crs_rule_id"),
                "message": f.get("message"),
                "severity": f.get("severity"),
                "matched_data": str(f.get("matched_data") or "")[:200],
            })
    return {
        "alert_id": alert.get("alert_id"),
        "ts": alert.get("timestamp"),
        "family": family,
        "title": alert.get("title"),
        "rule_id": alert.get("rule_id"),
        "rule_level": alert.get("rule_level"),
        "web": {"method": web.get("method"), "uri": web.get("uri"),
                "response_status": web.get("response_status"), "waf_findings": findings} if web else {},
        "cloud": {k: cloud.get(k) for k in ("event_source", "event_name", "region", "principal_arn", "bucket", "object_key") if cloud.get(k)},
        "raw_excerpt": raw_txt.replace("```", "`\u200b``")[:1100],
    }

def evidence_log_block(entries):
    # Plain markdown only -- IRIS does NOT render <details>/HTML, it prints the
    # raw tags. Tables and ``` code fences DO render.
    entries = entries if isinstance(entries, list) else []
    if not entries:
        return "_No per-alert detector evidence recorded yet._"
    blocks = []
    for i, e in enumerate(entries, 1):
        if not isinstance(e, dict):
            continue
        parts = ["### 🔹 Alert {n} - {fam} - {title}".format(
            n=i, fam=e.get("family", "?"), title=esc((e.get("title") or "")[:90]))]
        parts.append("*Wazuh rule `{rid}` (level {lvl}) - alert `{aid}` - {ts}*".format(
            rid=e.get("rule_id") or "?", lvl=e.get("rule_level") if e.get("rule_level") is not None else "?",
            aid=e.get("alert_id") or "?", ts=e.get("ts") or "?"))
        web = e.get("web") or {}
        if web.get("uri") or web.get("method"):
            parts.append("**Request:** `{m} {u}` -> HTTP {s}".format(
                m=web.get("method") or "?", u=web.get("uri") or "?", s=web.get("response_status") or "?"))
        findings = web.get("waf_findings") or []
        if findings:
            waf = ["**WAF / ModSecurity findings:**"]
            for f in findings[:8]:
                if isinstance(f, dict):
                    waf.append("- `{r}` {m} - `{d}`".format(
                        r=f.get("crs_rule_id") or "?", m=esc(f.get("message") or ""),
                        d=esc(str(f.get("matched_data") or ""))[:180]))
            parts.append("\n".join(waf))
        elif web:
            parts.append("**WAF / ModSecurity findings:** none - detection came from the Wazuh rule, not an OWASP CRS match.")
        cloud = e.get("cloud") or {}
        if cloud.get("event_name"):
            tgt = cloud.get("bucket") or cloud.get("object_key") or cloud.get("event_source") or ""
            parts.append("**Cloud event:** `{e}` {t} by `{p}`".format(
                e=cloud.get("event_name"), t=esc(str(tgt)), p=esc(cloud.get("principal_arn") or "")))
        raw = e.get("raw_excerpt")
        if raw:
            parts.append("**Alert log (excerpt - full raw log is in the Timeline tab):**\n```\n{r}\n```".format(r=raw))
        blocks.append("\n\n".join(parts))
    return "\n\n---\n\n".join(blocks)

def render_case_description(state, latest_evidence):
    sev = str(state.get("severity") or "medium").lower()
    assess = str(state.get("assessment") or "uncertain")
    fam = ", ".join(state.get("families_seen") or []) or "generic_security_event"
    tele = ", ".join(state.get("telemetry_seen") or []) or "generic"
    body = """# 🛡️ {title}

> **AI-augmented SOC — a human analyst must review this case before any containment or closure.** This summary is composed only from detector evidence and enrichment collected by the pipeline.

## 🎯 Case at a glance
| Field | Value |
|---|---|
| **Severity** | {sev_badge} |
| **Assessment** | {assess_badge} (confidence: {conf}) |
| **Alerts correlated** | {alert_count} |
| **First seen / last update (UTC)** | {first_seen} → {last_seen} |
| **Telemetry** | {tele} |
| **Attack families** | {fam} |
| **Campaign key** | `{anchor}` |

## 📝 Current assessment
{summary}

## ⛓️ Attack timeline
{timeline}

## 🧩 MITRE ATT&CK
{mitre}

## 🖥️ Entities involved
{entities}

## 🔎 Key evidence
{evidence}

## ❔ Evidence gaps
{gaps}

## ✅ Recommended analyst actions
{tasks}

## 📁 Evidence by alert
{evidence_by_alert}
""".format(
        title=state.get("title") or "Security incident",
        sev_badge=SEV_BADGE.get(sev, "⚪ " + sev.upper()),
        assess_badge=ASSESS_BADGE.get(assess, assess.replace("_", " ")),
        conf=state.get("confidence") or "low",
        alert_count=state.get("alert_count") or 1,
        first_seen=state.get("first_seen") or "?",
        last_seen=state.get("last_seen") or "?",
        tele=tele, fam=fam,
        anchor=state.get("campaign_anchor") or "unknown",
        summary=state.get("current_summary") or "_No summary was produced._",
        timeline=timeline_table(state.get("timeline")),
        mitre=mitre_table(state.get("mitre")),
        entities=entities_block(state.get("entities")),
        evidence=bullets(state.get("key_evidence"), "No key evidence was extracted."),
        gaps=bullets(state.get("evidence_gaps"), "No open evidence gaps."),
        tasks=bullets(state.get("analyst_tasks"), "Review the original Wazuh alert and preserved evidence."),
        evidence_by_alert=evidence_log_block(state.get("evidence_log")),
    )
    body += "\n\n<!-- soc-state:v1 {} -->".format(json.dumps(state, ensure_ascii=False, default=str))
    return body

# ---------------------------------------------------------------- create branch
record = unpack(r'''$validate_ai_case_decision.message''')
created = unpack(r'''$resolve_created_case.message''')
case_id = created.get("case_id")
if case_id is None:
    raise ValueError("Missing case_id from Resolve Created Case")

normalized = record.get("normalized_alert", {})
alert = normalized.get("alert", {})
classification = normalized.get("classification", {})
ai = record.get("ai", {})

severity = str(ai.get("severity") or "medium").lower()
assessment_slug = str(ai.get("assessment") or "uncertain")
confidence = str(ai.get("confidence") or "low")
family = str(classification.get("attack_family") or "generic_security_event")
telemetry = str(classification.get("telemetry") or "generic")
title = str(alert.get("title") or "Security incident")
ts = alert.get("timestamp") or ""

te = ai.get("timeline_entry") if isinstance(ai.get("timeline_entry"), dict) else {}
seed_timeline = [{
    "ts": ts,
    "phase": record.get("kill_chain_phase") or "activity",
    "technique_id": te.get("technique_id") or "",
    "title": te.get("title") or title,
    "target": te.get("target") or "",
    "outcome": te.get("outcome") or "",
    "alert_id": alert.get("alert_id"),
}]

state = {
    "schema": "soc.case-state/v1",
    "title": title,
    "campaign_anchor": record.get("campaign_anchor") or record.get("correlation_key"),
    "severity": severity,
    "assessment": assessment_slug,
    "confidence": confidence,
    "alert_count": 1,
    "first_seen": ts,
    "last_seen": ts,
    "telemetry_seen": [telemetry],
    "families_seen": [family],
    "entities": record.get("entities", {}) or {},
    "entity_tokens": record.get("entity_tokens", []) or [],
    "timeline": seed_timeline,
    "mitre": ai.get("mitre_attack", []) or [],
    "key_evidence": ai.get("key_evidence", []) or [],
    "evidence_gaps": ai.get("evidence_gaps", []) or [],
    "analyst_tasks": ai.get("analyst_tasks", []) or [],
    "current_summary": ai.get("updated_case_summary") or ai.get("executive_summary") or "",
    "evidence_log": [evidence_entry(normalized, family)],
}

latest_evidence = {
    "web": normalized.get("web", {}),
    "cloud": normalized.get("cloud", {}),
    "raw": normalized.get("sanitized_raw_event", {}),
}
summary = render_case_description(state, latest_evidence)

# tags = descriptive tags + entity tokens (so node 05 can correlate later stages)
base_tags = {"wazuh", "ai-managed", telemetry, family, assessment_slug, "severity-" + severity}
entity_tags = [t for t in state["entity_tokens"] if t][:30]
tags = sorted(base_tags) + entity_tags

metadata_payload = {
    "case_name": "[{}] {}".format(severity.upper(), title)[:250],
    "case_soc_id": state["campaign_anchor"],
    "case_tags": ",".join(tags),
    "custom_attributes": {
        "schema_version": "soc.case-metadata/v5",
        "campaign_anchor": state["campaign_anchor"],
        "telemetry": telemetry,
        "incident_family": family,
        "ai_assessment": assessment_slug,
        "ai_confidence": confidence,
        "entity_tokens": ",".join(entity_tags),
        "automation": "Shuffle + Wazuh + local LM Studio (human-in-the-loop)",
    },
}

print(json.dumps({
    "case_id": int(case_id),
    "metadata_payload": metadata_payload,
    "summary_payload": {"case_description": summary},
}, ensure_ascii=False, default=str))
