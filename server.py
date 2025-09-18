#!/usr/bin/env python3
"""
STIG Automation Server using FastMCP - PostgreSQL Backed
- Adds tools to ingest failed rules, map to NIST controls, and populate/update the nist_controls table.
"""

import json
from typing import List, Dict, Optional, Tuple

import psycopg2
from psycopg2.extras import Json

# Optional export dependency (only used by export_*)
try:
    import pandas as pd
    HAVE_PANDAS = True
except Exception:
    HAVE_PANDAS = False

from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("STIG-Automation-Server")

# Database connection details
DB_CONFIG = {
    "dbname": "stigdb",
    "user": "stig_user",
    "password": "root",  # Replace securely in production
    "host": "localhost",
    "port": 5432
}

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

def row_to_dict(row, cursor) -> Dict:
    columns = [desc[0] for desc in cursor.description]
    return {col: val for col, val in zip(columns, row)}

# ---------- schema helpers ----------

def ensure_schema():
    """
    Create the mapping table if it doesn't exist.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS rule_control_map (
            rule_id TEXT PRIMARY KEY,
            control_acronym TEXT NOT NULL
        );
    """)
    # Ensure nist_controls exists (created by the loader). We won't redefine it here.
    conn.commit()
    cur.close()
    conn.close()

def fetch_rule(cur, rule_id: str) -> Optional[Dict]:
    cur.execute("SELECT * FROM stig_rules WHERE id = %s", (rule_id,))
    row = cur.fetchone()
    if not row:
        return None
    # capture columns BEFORE closing cursor
    cols = [d[0] for d in cur.description]
    rec = dict(zip(cols, row))
    # parse JSON fields if needed
    if "rule_references" in rec and isinstance(rec["rule_references"], str):
        try:
            rec["rule_references"] = json.loads(rec["rule_references"])
        except Exception:
            pass
    return rec

def map_rule_to_control_in_db(cur, rule_id: str) -> Optional[str]:
    """
    1) Try explicit rule_control_map.
    2) Else infer from stig_rules.rule_references->NIST (e.g., ["AC-2", ...]) and take the first token.
    """
    cur.execute("SELECT control_acronym FROM rule_control_map WHERE rule_id = %s", (rule_id,))
    row = cur.fetchone()
    if row and row[0]:
        return row[0]

    # Try inference from stig_rules
    rec = fetch_rule(cur, rule_id)
    if not rec:
        return None

    # infer from references.NIST array if present
    ref = rec.get("rule_references")
    if isinstance(ref, dict):
        nist_refs = ref.get("NIST")
        if isinstance(nist_refs, list) and nist_refs:
            # Take first like "AC-2" or "AC-2(1)"; normalize to "AC-2"
            raw = str(nist_refs[0]).strip()
            # strip any parentheses part
            base = raw.split("(")[0].strip()
            return base if base else None

    return None

def upsert_mapping(cur, rule_id: str, control_acronym: str):
    cur.execute("""
        INSERT INTO rule_control_map (rule_id, control_acronym)
        VALUES (%s, %s)
        ON CONFLICT (rule_id) DO UPDATE SET control_acronym = EXCLUDED.control_acronym;
    """, (rule_id, control_acronym))

def control_exists(cur, control_acronym: str) -> bool:
    cur.execute("SELECT 1 FROM nist_controls WHERE LOWER(control_acronym) = LOWER(%s) LIMIT 1", (control_acronym,))
    return cur.fetchone() is not None

def upsert_control(cur, updates: Dict):
    """
    Upsert the nist_controls record by control_acronym.
    Unspecified columns remain unchanged.
    """
    # Fetch existing
    cur.execute("SELECT * FROM nist_controls WHERE LOWER(control_acronym) = LOWER(%s)", (updates["control_acronym"],))
    row = cur.fetchone()
    cols = [d[0] for d in cur.description] if cur.description else []
    existing = dict(zip(cols, row)) if row else {}

    # Merge: favor incoming non-None values, keep existing otherwise
    merged = dict(existing)
    for k, v in updates.items():
        if k == "extra":
            # merge JSONB
            old_extra = existing.get("extra") or {}
            if isinstance(old_extra, str):
                try:
                    old_extra = json.loads(old_extra)
                except Exception:
                    old_extra = {}
            new_extra = v or {}
            if isinstance(new_extra, str):
                try:
                    new_extra = json.loads(new_extra)
                except Exception:
                    new_extra = {}
            merged["extra"] = {**old_extra, **new_extra}
        elif v is not None:
            merged[k] = v

    # Build column list for insert/update
    all_cols = [
        "control_acronym", "control_title", "control_information", "compliance_status",
        "implementation_status", "common_control_provider", "security_control_designation",
        "test_method", "na_justification", "estimated_completion_date", "implementation_narrative",
        "responsible_entities", "criticality", "frequency", "method", "reporting", "tracking",
        "slcm_comments", "severity", "relevance_of_threat", "likelihood", "impact",
        "residual_risk_level", "vulnerability_summary", "mitigations", "impact_description",
        "recommendations", "extra"
    ]

    # Ensure required PK present
    merged["control_acronym"] = merged.get("control_acronym") or updates["control_acronym"]

    # INSERT ... ON CONFLICT DO UPDATE
    placeholders = ", ".join(["%s"] * len(all_cols))
    update_set = ", ".join([f"{c} = EXCLUDED.{c}" for c in all_cols if c != "control_acronym"])
    values = []
    for c in all_cols:
        v = merged.get(c)
        if c == "extra" and v is not None and not isinstance(v, (dict, list)):
            # try to parse string JSON
            try:
                v = json.loads(v)
            except Exception:
                # store raw as string
                pass
        values.append(Json(v) if c == "extra" else v)

    cur.execute(f"""
        INSERT INTO nist_controls ({", ".join(all_cols)})
        VALUES ({placeholders})
        ON CONFLICT (control_acronym) DO UPDATE SET
        {update_set};
    """, values)

# ---------- existing tools ----------

@mcp.tool()
async def get_stig_rule(rule_id: str) -> Optional[Dict]:
    """Fetch STIG rule by ID from database (stig_rules)."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM stig_rules WHERE id = %s", (rule_id,))
    row = cur.fetchone()
    result = None
    if row:
        cols = [d[0] for d in cur.description]
        result = dict(zip(cols, row))
        if isinstance(result.get("rule_references"), str):
            try:
                result["rule_references"] = json.loads(result["rule_references"])
            except Exception:
                pass
    cur.close()
    conn.close()
    return result

@mcp.tool()
async def search_stig_rules(query: str) -> List[Dict]:
    """Search STIG rules by title or description (case-insensitive)."""
    conn = get_db_connection()
    cur = conn.cursor()
    pattern = f"%{query.lower()}%"
    cur.execute("""
        SELECT * FROM stig_rules
        WHERE LOWER(title) LIKE %s OR LOWER(description) LIKE %s
    """, (pattern, pattern))
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description]
    results = []
    for row in rows:
        rule = dict(zip(cols, row))
        if isinstance(rule.get("rule_references"), str):
            try:
                rule["rule_references"] = json.loads(rule["rule_references"])
            except Exception:
                pass
        results.append(rule)
    cur.close()
    conn.close()
    return results

@mcp.tool()
async def apply_stig_fix(rule_id: str, dry_run: bool = True) -> Dict:
    """Simulate applying a STIG fix (returns the shell fix)."""
    rule = await get_stig_rule(rule_id)
    if not rule:
        return {"error": "Rule not found"}
    return {"rule": rule_id, "fix": rule.get("fix"), "applied": not dry_run, "dry_run": dry_run}

# ---------- NEW: mapping + populate controls from failed rules ----------

@mcp.tool()
async def link_rule_to_control(rule_id: str, control_acronym: str) -> Dict:
    """
    Manually link a STIG rule id (e.g., xccdf_org.ssgproject.content_rule_...) to a NIST control acronym (e.g., AC-2).
    """
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor()
    upsert_mapping(cur, rule_id, control_acronym)
    conn.commit()
    cur.close()
    conn.close()
    return {"linked": True, "rule_id": rule_id, "control_acronym": control_acronym}

def _derive_control_updates_from_rule(rule: Dict, control_acronym: str) -> Dict:
    """
    Build a sane set of defaults to write into nist_controls from a failed STIG rule.
    """
    description = rule.get("description")
    severity = rule.get("severity")
    fix = rule.get("fix")
    title = rule.get("title")

    updates = {
        "control_acronym": control_acronym,
        # We'll keep existing 'control_title' if already present, else seed from rule title
        "control_title": title,
        "compliance_status": "Non-Compliant",
        "implementation_status": "Planned",
        "vulnerability_summary": description,
        "mitigations": fix,
        "severity": severity,
        # Put raw rule payload in extra for traceability
        "extra": {
            "source": "stig_rule_ingest",
            "rule_id": rule.get("id"),
            "rule_title": title,
            "rule_severity": severity,
            "rule_fix": fix
        }
    }
    return updates

@mcp.tool()
async def ingest_failed_rules(failed_rules_json: str,
                              default_control_status: str = "Non-Compliant",
                              default_impl_status: str = "Planned") -> Dict:
    """
    Ingest failed STIG rules and populate/update corresponding rows in nist_controls.

    Input failed_rules_json format (stringified JSON):
    [
      {"rule_id": "xccdf_org.ssgproject.content_rule_mount_option_dev_shm_nodev",
       "control_acronym": "CM-7"},   // optional; if absent we'll try mapping/inference
      {"rule_id": "xccdf_org.ssgproject.content_rule_sshd_set_idle_timeout"}
    ]

    Returns summary of processed items with mapping decisions.
    """
    ensure_schema()
    try:
        items = json.loads(failed_rules_json)
        assert isinstance(items, list)
    except Exception as e:
        return {"error": f"failed_rules_json must be a JSON list: {e}"}

    conn = get_db_connection()
    cur = conn.cursor()

    processed = []
    for item in items:
        rid = item.get("rule_id")
        if not rid:
            processed.append({"ok": False, "reason": "missing rule_id", "item": item})
            continue

        # 1) Load the rule
        rule = fetch_rule(cur, rid)
        if not rule:
            processed.append({"ok": False, "rule_id": rid, "reason": "rule not found in stig_rules"})
            continue

        # 2) Determine control acronym
        control = item.get("control_acronym")
        if not control:
            control = map_rule_to_control_in_db(cur, rid)
        if not control:
            processed.append({"ok": False, "rule_id": rid, "reason": "no control mapping; use link_rule_to_control"})
            continue

        # 3) Make sure mapping table reflects it
        upsert_mapping(cur, rid, control)

        # 4) Build updates from the rule; apply overrides for default statuses
        updates = _derive_control_updates_from_rule(rule, control)
        if default_control_status:
            updates["compliance_status"] = default_control_status
        if default_impl_status:
            updates["implementation_status"] = default_impl_status

        # 5) If a row already exists, keep its title unless empty
        cur.execute("SELECT control_title FROM nist_controls WHERE LOWER(control_acronym)=LOWER(%s)", (control,))
        row = cur.fetchone()
        if row and row[0]:
            # preserve existing title
            updates["control_title"] = None  # leave unchanged in upsert merge

        # 6) Upsert into nist_controls
        upsert_control(cur, updates)

        processed.append({
            "ok": True,
            "rule_id": rid,
            "control_acronym": control,
            "derived_from": "rule_references.NIST" if "control_acronym" not in item else "explicit",
        })

    conn.commit()
    cur.close()
    conn.close()

    return {
        "ingested": [p for p in processed if p.get("ok")],
        "failed": [p for p in processed if not p.get("ok")]
    }

# ---------- convenience: read/update controls directly ----------

@mcp.tool()
async def get_control(control_acronym: str) -> Optional[Dict]:
    """Fetch a single NIST control row by acronym from nist_controls."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM nist_controls WHERE LOWER(control_acronym) = LOWER(%s)", (control_acronym,))
    row = cur.fetchone()
    res = row_to_dict(row, cur) if row else None
    cur.close()
    conn.close()
    return res

@mcp.tool()
async def update_control_fields(control_acronym: str, updates_json) -> Dict:
    """
    Partially update fields for a control.

    Accepts either:
      - a JSON object (preferred): {"recommendations": "...", "implementation_narrative": "..."}
      - a JSON string: "{\"recommendations\":\"...\"}"
      - even a double-encoded JSON string: "\"{\\\"recommendations\\\":\\\"...\\\"}\""
    """
    import ast

    def parse_updates_arg(arg):
        # Already a dict? great.
        if isinstance(arg, dict):
            return arg

        # Not a dict — treat as string
        text = str(arg)

        # Try normal JSON
        try:
            obj = json.loads(text)
        except Exception:
            # Try un-escaping (handles over-escaped inputs produced by some clients)
            try:
                obj = json.loads(bytes(text, "utf-8").decode("unicode_escape"))
            except Exception:
                # Last resort: Python literal (handles single quotes)
                try:
                    obj = ast.literal_eval(text)
                except Exception as e:
                    raise ValueError(f"updates_json must be a JSON object: {e}")

        # If we decoded to another string (double-encoded), peel layers up to 3 times
        for _ in range(3):
            if isinstance(obj, str):
                obj = json.loads(obj)
            else:
                break

        if not isinstance(obj, dict):
            raise ValueError("updates_json must decode to a JSON object")
        return obj

    try:
        updates = parse_updates_arg(updates_json)
    except Exception as e:
        return {"error": str(e)}

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor()
    updates["control_acronym"] = control_acronym
    try:
        upsert_control(cur, updates)
        conn.commit()
        return {"ok": True, "control_acronym": control_acronym, "applied_updates": updates}
    finally:
        cur.close()
        conn.close()

# ---------- optional: export controls back to an Excel ----------

@mcp.tool()
async def export_controls_to_excel(path: str) -> Dict:
    """
    Export nist_controls to an .xlsx at `path`.
    Requires pandas+openpyxl installed in the server environment.
    """
    if not HAVE_PANDAS:
        return {"error": "pandas not available. Install pandas and openpyxl."}
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM nist_controls ORDER BY control_acronym")
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description]
    cur.close()
    conn.close()

    # Convert JSONB to plain dicts for xlsx
    def _clean(v):
        if isinstance(v, dict):
            return json.dumps(v, ensure_ascii=False)
        return v

    data = [{c: _clean(v) for c, v in zip(cols, r)} for r in rows]
    df = pd.DataFrame(data)
    df.to_excel(path, index=False)
    return {"ok": True, "path": path, "rows": len(df)}

# ---------- resources ----------

@mcp.resource("stig://rules")
async def list_all_rules() -> List[Dict]:
    """List all STIG rules from PostgreSQL (stig_rules)."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM stig_rules")
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description]
    results = []
    for row in rows:
        rule = dict(zip(cols, row))
        if isinstance(rule.get("rule_references"), str):
            try:
                rule["rule_references"] = json.loads(rule["rule_references"])
            except Exception:
                pass
        results.append(rule)
    cur.close()
    conn.close()
    return results

@mcp.resource("stig://rule/{rule_id}")
async def get_rule_resource(rule_id: str) -> Optional[Dict]:
    """Return specific STIG rule resource from database."""
    return await get_stig_rule(rule_id)

# ---------- main ----------

if __name__ == "__main__":
    ensure_schema()
    print("🚀 STIG Automation Server running with PostgreSQL backend...")
    mcp.run(transport="stdio")
