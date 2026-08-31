import json
import re

# Shuffle node name: Build Case Artifact Plan   (v2 - LIVING case summary)
# MERGE-branch input contract:
#   Validate AI Case Decision message  ($validate_ai_case_decision.message)
#   Get Merged Case Export body        ($get_merged_case_export.body)
#   IRIS Local Configuration message   ($iris_local_configuration.message)
#
# WHAT CHANGED (the "living case" the analyst asked for)
# The old node only appended a timeline event and never touched the summary.
# v2 parses the soc-state block embedded by node 11 in the case description,
# folds THIS alert into it (timeline, entities, MITRE, evidence, gaps, severity,
# assessment, running summary), and re-renders the WHOLE structured/colored
# summary via the shared render_case_description(). It also emits refreshed
# case_tags so later kill-chain stages keep correlating on the new entities.
# The recomposition is done in code from validated AI fields -> no hallucination.

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

# ----------------------------------------------------- merge-branch logic ----
def clip(value, limit=9000):
    text = json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= limit else text[:limit] + "...[truncated]"

def find_soc_state(obj):
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, str):
            m = SOC_STATE_RE.search(cur)
            if m:
                try:
                    return json.loads(m.group(1))
                except Exception:
                    pass
        elif isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return None

def union_list(prior, new, cap=40):
    out = list(prior) if isinstance(prior, list) else []
    for v in (new if isinstance(new, list) else []):
        if v not in out:
            out.append(v)
    return out[:cap]

def union_entities(prior, new):
    prior = prior if isinstance(prior, dict) else {}
    new = new if isinstance(new, dict) else {}
    return {k: union_list(prior.get(k, []), new.get(k, []), 20)
            for k in ("attacker_ips", "assets", "identities", "resources")}

def union_mitre(prior, new):
    seen, out = set(), []
    for it in (prior or []) + (new or []):
        if not isinstance(it, dict):
            continue
        key = (str(it.get("technique_id", "")).lower(), str(it.get("tactic", "")).lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out[:10]

def union_tasks(prior, new):
    seen, out = set(), []
    for it in (prior or []) + (new or []):
        if not isinstance(it, dict):
            continue
        t = str(it.get("title", "")).strip().lower()
        if not t or t in seen:
            continue
        seen.add(t)
        out.append(it)
    return out[:8]

ASSESS_RANK = {"likely_false_positive": 1, "uncertain": 2, "likely_true_positive": 3}
SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

record = unpack(r'''$validate_ai_case_decision.message''')
export = unpack(r'''$get_merged_case_export.body''')
config = unpack(r'''$iris_local_configuration.message''')
case = export.get("data", export.get("message", export))
if not isinstance(case, dict):
    case = {}

ai = record.get("ai", {})
normalized = record.get("normalized_alert", {})
alert = normalized.get("alert", {})
classification = normalized.get("classification", {})
case_id = case.get("case_id") or case.get("id") or (case.get("case") or {}).get("case_id")
if case_id is None:
    raise ValueError("Case export did not contain a case_id")

family = str(classification.get("attack_family") or "generic_security_event")
telemetry = str(classification.get("telemetry") or "generic")
anchor = record.get("campaign_anchor") or record.get("correlation_key") or "unknown"
ts = alert.get("timestamp") or ""

# ---- load prior state (or reconstruct a minimal one) ------------------------
prior = find_soc_state(export)
reconstructed = prior is None
if reconstructed:
    prior = {
        "schema": "soc.case-state/v1", "title": alert.get("title") or "Security incident",
        "campaign_anchor": anchor, "severity": "low", "assessment": "uncertain",
        "confidence": "low", "alert_count": 1, "first_seen": ts, "last_seen": ts,
        "telemetry_seen": [], "families_seen": [], "entities": {},
        "entity_tokens": [], "timeline": [], "mitre": [], "key_evidence": [],
        "evidence_gaps": [], "analyst_tasks": [], "current_summary": "",
    }

te = ai.get("timeline_entry") if isinstance(ai.get("timeline_entry"), dict) else {}
new_event = {
    "ts": ts, "phase": record.get("kill_chain_phase") or "activity",
    "technique_id": te.get("technique_id") or "", "title": te.get("title") or alert.get("title") or "",
    "target": te.get("target") or "", "outcome": te.get("outcome") or "",
    "alert_id": alert.get("alert_id"),
}
timeline = list(prior.get("timeline") or [])
if not any(ev.get("alert_id") == new_event["alert_id"] and new_event["alert_id"] is not None for ev in timeline):
    timeline.append(new_event)

_families_union = union_list(prior.get("families_seen"), [family], 12)
_asset_label = str(anchor).split("campaign:")[-1] if "campaign:" in str(anchor) else "target"
_campaign_title = "Attack campaign on %s: %s" % (_asset_label, ", ".join(_families_union[:4]) or "security event")
_new_entry = evidence_entry(normalized, family)
_prior_log = [e for e in (prior.get("evidence_log") or []) if isinstance(e, dict) and e.get("alert_id") != _new_entry.get("alert_id")]
_evidence_log = (_prior_log + [_new_entry])[-30:]

new_assess = str(ai.get("assessment") or "uncertain")
new_sev = str(ai.get("severity") or "medium").lower()
gaps_new = ai.get("evidence_gaps") if isinstance(ai.get("evidence_gaps"), list) and ai.get("evidence_gaps") else prior.get("evidence_gaps")

state = {
    "schema": "soc.case-state/v1",
    "title": _campaign_title,
    "campaign_anchor": anchor,
    "severity": new_sev if SEV_RANK.get(new_sev, 0) >= SEV_RANK.get(prior.get("severity"), 0) else prior.get("severity"),
    "assessment": new_assess if ASSESS_RANK.get(new_assess, 0) >= ASSESS_RANK.get(prior.get("assessment"), 0) else prior.get("assessment"),
    "confidence": ai.get("confidence") or prior.get("confidence") or "low",
    "alert_count": int(prior.get("alert_count") or 1) + 1,
    "first_seen": prior.get("first_seen") or ts,
    "last_seen": ts or prior.get("last_seen"),
    "telemetry_seen": union_list(prior.get("telemetry_seen"), [telemetry], 12),
    "families_seen": _families_union,
    "entities": union_entities(prior.get("entities"), record.get("entities", {})),
    "entity_tokens": union_list(prior.get("entity_tokens"), record.get("entity_tokens", []), 60),
    "timeline": timeline[:60],
    "mitre": union_mitre(prior.get("mitre"), ai.get("mitre_attack", [])),
    "key_evidence": union_list(prior.get("key_evidence"), ai.get("key_evidence", []), 14),
    "evidence_gaps": (gaps_new or [])[:8],
    "analyst_tasks": union_tasks(prior.get("analyst_tasks"), ai.get("analyst_tasks", [])),
    "current_summary": ai.get("updated_case_summary") or prior.get("current_summary") or ai.get("executive_summary") or "",
    "evidence_log": _evidence_log,
}

latest_evidence = {"web": normalized.get("web", {}), "cloud": normalized.get("cloud", {}), "raw": normalized.get("sanitized_raw_event", {})}
case_description = render_case_description(state, latest_evidence)

# refreshed tags (base + all accumulated entity tokens) so node 05 keeps matching
base_tags = {"wazuh", "ai-managed", state["assessment"], "severity-" + str(state["severity"])}
base_tags.update(state["telemetry_seen"]); base_tags.update(state["families_seen"])
entity_tags = [t for t in state["entity_tokens"] if t][:40]
case_tags = ",".join(sorted(base_tags) + entity_tags)

# ---- IRIS timeline event for THIS alert (per-stage detail) -------------------
def numeric_ids(items, preferred):
    output = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        value = next((item.get(k) for k in preferred if item.get(k) is not None), None)
        try:
            value = int(value)
        except Exception:
            continue
        if value not in output:
            output.append(value)
    return output

case_ioc_ids = numeric_ids(case.get("iocs", []), ("ioc_id", "id"))
case_asset_ids = numeric_ids(case.get("assets", []), ("asset_id", "id"))
existing_task_titles = {str(i.get("task_title", "")).strip().lower() for i in case.get("tasks", []) if isinstance(i, dict) and not i.get("task_close_date") and not i.get("close_date")}

phase_label = PHASE_ICON.get(new_event["phase"], new_event["phase"])
timeline_event_md = "**{phase}** — {title}\n\n- Target: `{target}`\n- Outcome: {outcome}\n- Technique: `{tech}`\n- Wazuh alert `{aid}` (rule `{rid}`), assessment: {assess}".format(
    phase=phase_label, title=new_event["title"], target=new_event["target"] or "n/a",
    outcome=new_event["outcome"] or "n/a", tech=new_event["technique_id"] or "n/a",
    aid=alert.get("alert_id", "unknown"), rid=alert.get("rule_id", "unknown"),
    assess=str(state["assessment"]).replace("_", " "))

timeline_payload = {
    "event_title": "Wazuh alert {0} — {1}".format(alert.get("alert_id", "unknown"), alert.get("title", "Security alert"))[:250],
    "event_date": str(alert.get("timestamp") or "").replace("+0000", ""),
    "event_tz": "+00:00",
    "event_source": "Wazuh / Shuffle AI triage",
    "event_content": timeline_event_md,
    "event_raw": clip(normalized.get("sanitized_raw_event", {})),
    "event_assets": case_asset_ids,
    "event_iocs": case_ioc_ids,
    "event_in_summary": True,
    "event_in_graph": True,
    "event_sync_iocs_assets": False,
    "event_category_id": 1,
    "event_tags": "wazuh,ai-triaged,{0},{1}".format(telemetry, family),
    "custom_attributes": {"campaign_anchor": anchor, "wazuh_alert_id": alert.get("alert_id"), "rule_id": alert.get("rule_id")},
}

proposed = ai.get("analyst_tasks", []) if isinstance(ai.get("analyst_tasks"), list) else []
new_task = next((i for i in proposed if isinstance(i, dict) and str(i.get("title", "")).strip().lower() not in existing_task_titles), None)

# severity_id escalation on the IRIS case field (rule_level driven, as before)
SEVERITY_RANK = {"unspecified": 0, "informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
def severity_bucket(rule_level):
    try:
        level = int(rule_level)
    except (TypeError, ValueError):
        return "unspecified"
    return "critical" if level >= 12 else "high" if level >= 9 else "medium" if level >= 6 else "low" if level >= 3 else "informational"

severity_ids = config.get("severity_ids", {}) if isinstance(config.get("severity_ids"), dict) else {}
id_to_bucket = {v: k for k, v in severity_ids.items() if v is not None}
current_bucket = id_to_bucket.get((case.get("severity") or {}).get("severity_id"), "unspecified")
new_bucket = severity_bucket(alert.get("rule_level"))
new_severity_id = severity_ids.get(new_bucket)
case_severity_update = None
needs_case_severity_update = False
if new_severity_id is not None and SEVERITY_RANK.get(new_bucket, 0) > SEVERITY_RANK.get(current_bucket, 0):
    case_severity_update = {"severity_id": new_severity_id}
    needs_case_severity_update = True

# metadata update posted every merge: refreshed tags, a campaign-style case
# name that reflects what the case has become, (+ severity_id when escalating)
campaign_name = "[%s] %s" % (str(state["severity"]).upper(), _campaign_title)
metadata_payload = {"case_tags": case_tags, "case_name": campaign_name[:250]}
if needs_case_severity_update:
    metadata_payload["severity_id"] = new_severity_id

print(json.dumps({
    "schema_version": "soc.case-artifacts/v2",
    "case_id": int(case_id),
    "summary_payload": {"case_description": case_description},
    "metadata_payload": metadata_payload,
    "timeline_payload": timeline_payload,
    "case_ioc_ids": case_ioc_ids,
    "case_asset_ids": case_asset_ids,
    "proposed_task": new_task,
    "has_task": bool(new_task),
    "case_severity_update": case_severity_update,
    "needs_case_severity_update": needs_case_severity_update,
    "state_debug": {"alert_count": state["alert_count"], "reconstructed_state": reconstructed},
}, ensure_ascii=False, default=str))

