import json
import re

# Shuffle node name: Resolve Open Case   (v2 - entity-overlap candidate ranking)
# Inputs:
#   Search Open Cases body        ($search_open_cases.body)
#   Build Correlation Key message ($build_correlation_key.message)
#
# WHY THIS CHANGED
# The old node accepted a case only on an EXACT soc_id match, and the search
# node pre-filtered server-side by that exact key -- so a later kill-chain stage
# (different family => different old key) never matched and spawned a new case.
#
# v2 instead scores EVERY open case for overlap with the new alert:
#   * anchor match  -> same attacker<->target campaign (reliable, soc_id based)
#   * entity overlap-> shares an attacker IP / host / IAM identity / resource,
#                      read from the case's ent:* tags (persisted by nodes 11/12)
# The strongest candidates are surfaced for the AI (06/07) to confirm, keeping
# a human-reviewable merge decision instead of a blind auto-merge.
#
# IMPORTANT: the "Search Open Cases" HTTP node must now fetch ALL open cases for
# the customer (no ?case_soc_id= server filter), e.g.
#   /manage/cases/filter?case_customer_id=1&page=1&per_page=50&sort=desc
# so this node can see cases whose anchor differs but whose entities overlap.

def unpack(value):
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}

def as_list(value):
    return value if isinstance(value, list) else []

def case_id_of(case):
    for key in ("case_id", "id"):
        if isinstance(case, dict) and case.get(key) not in (None, ""):
            try:
                return int(case.get(key))
            except Exception:
                return case.get(key)
    return None

ENT_RE = re.compile(r"ent:[a-z]+:[^\s,;|]+")

def entity_tokens_of(case):
    """Pull ent:* tokens from wherever IRIS surfaces them (tags / description).
    Robust to string or list shapes; degrades to empty if none are exposed."""
    found = set()
    for field in ("tags", "case_tags", "soc_id", "case_soc_id",
                  "case_description", "description", "classification"):
        val = case.get(field)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    item = item.get("tag_title") or item.get("tag") or item.get("name") or ""
                found.update(ENT_RE.findall(str(item).lower()))
        elif val:
            found.update(ENT_RE.findall(str(val).lower()))
    return found

search = unpack(r'''$search_open_cases.body''')
correlation = unpack(r'''$build_correlation_key.message''')

new_anchor = correlation.get("campaign_anchor") or correlation.get("correlation_key")
new_tokens = set(t.lower() for t in correlation.get("entity_tokens", []) if t)
new_strong = set(t.lower() for t in correlation.get("strong_tokens", []) if t)

# IRIS shape: {"status":..,"data":{"total":N,"cases":[...]}}. "data" wraps the
# list; grabbing "data" directly yields no list.
data = search.get("data") if isinstance(search.get("data"), dict) else {}
message = search.get("message") if isinstance(search.get("message"), dict) else {}
cases = data.get("cases") or message.get("cases") or search.get("cases") or []

candidates = []
for idx, case in enumerate(as_list(cases)):
    if not isinstance(case, dict):
        continue
    # state_id 9 == Closed (per /manage/case-states/list). 3 is the default
    # OPEN state for a fresh case -- never treat it as closed.
    closed = case.get("close_date") not in (None, "", "null") or case.get("state_id") in (9, "9")
    if closed:
        continue

    case_anchor = case.get("soc_id") or case.get("case_soc_id")
    case_tokens = entity_tokens_of(case)

    anchor_match = bool(new_anchor) and case_anchor == new_anchor
    overlap_strong = sorted(new_strong & case_tokens)
    overlap_any = sorted(new_tokens & case_tokens)
    confident = anchor_match or len(overlap_strong) >= 1

    if not (anchor_match or overlap_any):
        continue

    score = (5 if anchor_match else 0) + 3 * len(overlap_strong) + len(overlap_any)
    # earlier in a desc-sorted list == more recent -> small tiebreak bonus
    score += max(0, 5 - idx) * 0.1

    candidates.append({
        "case_id": case_id_of(case),
        "soc_id": case_anchor,
        "case_name": case.get("case_name") or case.get("name"),
        "state": case.get("state") or case.get("state_name"),
        "state_id": case.get("state_id"),
        "severity": case.get("severity") or case.get("severity_id"),
        "open_date": case.get("open_date") or case.get("case_open_date"),
        "owner": case.get("owner"),
        "anchor_match": anchor_match,
        "overlap_strong": overlap_strong,
        "overlap_any": overlap_any,
        "confident": confident,
        "score": round(score, 2),
    })

candidates.sort(key=lambda c: c["score"], reverse=True)
confident_candidates = [c for c in candidates if c["confident"]]
best = candidates[0] if candidates else {}

result = {
    "schema_version": "soc.iris.case-candidates/v2",
    "campaign_anchor": new_anchor,
    "candidates": candidates[:10],
    "has_candidates": len(candidates) > 0,
    "best_candidate": best,
    # exactly one confident candidate -> safe to propose a merge
    "strong_single": len(confident_candidates) == 1,
    # several confident candidates -> let the AI / analyst disambiguate
    "ambiguous": len(confident_candidates) > 1,

    # ---- backward-compat with the old contract read by 06/07 --------------
    "correlation_key": new_anchor,
    "has_open_case": len(confident_candidates) == 1,
    "selected_case": confident_candidates[0] if len(confident_candidates) == 1 else {},
    "matching_cases": candidates[:10],
    "total_matching_cases": len(candidates),
}

print(json.dumps(result, ensure_ascii=False, default=str))
