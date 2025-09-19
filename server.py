#!/usr/bin/env python3
"""
STIG Automation Server using FastMCP - PostgreSQL Backed
- Tools to ingest failed rules, map to NIST controls, and populate/update nist_controls.
- Exposes an MCP server over HTTP (Render provides HTTPS at the edge).
"""

import os
import json
from typing import List, Dict, Optional

import psycopg2
from psycopg2.extras import Json

# Optional export dependency (only used by export_controls_to_excel)
try:
    import pandas as pd
    HAVE_PANDAS = True
except Exception:
    HAVE_PANDAS = False

# Use the real FastMCP package (matches your 2.12.3 install)
from fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("STIG-Automation-Server")

# ------------- Database config (read from env on Render) -------------
DB_CONFIG = {
    "dbname":   os.getenv("PGDATABASE", "stigdb"),
    "user":     os.getenv("PGUSER", "stig_user"),
    "password": os.getenv("PGPASSWORD", ""),
    "host":     os.getenv("PGHOST", "localhost"),
    "port":     int(os.getenv("PGPORT", "5432")),
    "sslmode":  os.getenv("PGSSLMODE", "require"),
}

def get_db_connection():
    # You can also support DATABASE_URL if you prefer:
    dsn = os.getenv("DATABASE_URL")
    if dsn:
        return psycopg2.connect(dsn, sslmode=os.getenv("PGSSLMODE", "require"))
    return psycopg2.connect(**DB_CONFIG)

def row_to_dict(row, cursor) -> Dict:
    columns = [desc[0] for desc in cursor.description]
    return {col: val for col, val in zip(columns, row)}

# -------------------- schema helpers --------------------

def ensure_schema():
    """
    Create the mapping table if it doesn't exist.
    Assumes stig_rules and nist_controls are created elsewhere (loader/migrations).
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS rule_control_map (
            rule_id TEXT PRIMARY KEY,
            control_acronym TEXT NOT NULL
        );
    """)
    conn.commit()
    cur.close()
    conn.close()

def fetch_rule(cur, rule_id: str) -> Optional[Dict]:
    cur.execute("SELECT * FROM stig_rules WHERE id = %s", (rule_id,))
    row = cur.fetchone()
    if not row:
        return None
    cols = [d[0] for d in cur.description]
    rec = dict(zip(cols, row))
    if "rule_references" in rec and isinstance(rec["rule_references"], str):
        try:
            rec["rule_references"] = json.loads(rec["rule_references"])
        except Exception:
            pass
    return rec

def map_rule_to_control_in_db(cur, rule_id: str) -> Optional[str]:
    """
    1) Try explicit rule_control_map.
    2) Else infer from stig_rules.rule_references->NIST (e.g., ["AC-2", ...]) and take first token (normalize parens).
    """
    cur.execute("SELECT control_acronym FROM rule_control_map WHERE rule_id = %s", (rule_id,))
    row = cur.fetchone()
    if row and row[0]:
        return row[0]

    rec = fetch_rule(cur, rule_id)
    if not rec:
        return None

    ref = rec.get("rule_references")
    if isinstance(ref, dict):
        nist_refs = ref.get("NIST")
        if isinstance(nist_refs, list) and nist_refs:
            raw = str(nist_refs[0]).strip()
            base = raw.split("(")[0].strip()  # "AC-2(1)" -> "AC-2"
            return base or None
    return None

def upsert_mapping(cur, rule_id: str, control_acronym: str):
    cur.execute("""
        INSERT INTO rule_control_map (rule_id, control_acronym)
        VALUES (%s, %s)
        ON CONFLICT (rule_id) DO UPDATE SET control_acronym = EXCLUDED.control_acronym;
    """, (rule_id, control_acronym))

def upsert_control(cur, updates: Dict):
    """
    Upsert the nist_controls record by control_acronym.
    Unspecified columns remain unchanged (merge).
    """
    cur.execute("SELECT * FROM nist_controls WHERE LOWER(control_acronym) = LOWER(%s)", (updates["control_acronym"],))
    row = cur.fetchone()
    cols = [d[0] for d in cur.description] if cur.description else []
    existing = dict(zip(cols, row)) if row else {}

    merged = dict(existing)
    for k, v in updates.items():
        if k == "extra":
            old_extra = existing.get("extra") or {}
            if isinstance(old_extra, str):
                try: old_extra = json.loads(old_extra)
                except Exception: old_extra = {}
            new_extra = v or {}
            if isinstance(new_extra, str):
                try: new_extra = json.loads(new_extra)
                except Exception: new_extra = {}
            merged["extra"] = {**old_extra, **new_extra}
        elif v is not None:
            merged[k] = v

    all_cols = [
        "control_acronym", "control_title", "control_information", "compliance_status",
        "implementation_status", "common_control_provider", "security_control_designation",
        "test_method", "na_justification", "estimated_completion_date", "implementation_narrative",
        "responsible_entities", "criticality", "frequency", "method", "reporting", "tracking",
        "slcm_comments", "severity", "relevance_of_threat", "likelihood", "impact",
        "residual_risk_level", "vulnerability_summary", "mitigations", "impact_description",
        "recommendations", "extra"
    ]

    merged["control_acronym"] = merged.get("control_acronym") or updates["control_acronym"]

    placeholders = ", ".join(["%s"] * len(all_cols))
    update_set = ", ".join([f"{c} = EXCLUDED.{c}" for c in all_cols if c != "control_acronym"])
    values = []
    for c in all_cols:
        v = merged.get(c)
        if c == "extra" and v is not None and not isinstance(v, (dict, list)):
            try: v = json.loads(v)
            except Exception: pass
        values.append(Json(v) if c == "extra" else v)

    cur.execute(f"""
        INSERT INTO nist_controls ({", ".join(all_cols)})
        VALUES ({placeholders})
        ON CONFLICT (control_acronym) DO UPDATE SET
        {update_set};
    """, values)

# -------------------- MCP tools --------------------

@mcp.tool()
async def get_stig_rule(rule_id: str) -> Optional[Dict]:
    """Fetch STIG rule by ID from database (stig_rules)."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM stig_rules WHERE id = %s", (rule_id,))
    row = cur.fetchone()
    res = None
    if row:
        cols = [d[0] for d in cur.description]
        res = dict(zip(cols, row))
        if isinstance(res.get("rule_references"), str):
            try: res["rule_references"] = json.loads(res["rule_references"])
            except Exception: pass
    cur.close(); conn.close()
    return res

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
            try: rule["rule_references"] = json.loads(rule["rule_references"])
            except Exception: pass
        results.append(rule)
    cur.close(); conn.close()
    return results

@mcp.tool()
async def apply_stig_fix(rule_id: str, dry_run: bool = True) -> Dict:
    """Simulate applying a STIG fix (returns the shell fix)."""
    rule = await get_stig_rule(rule_id)
    if not rule:
        return {"error": "Rule not found"}
    return {"rule": rule_id, "fix": rule.get("fix"), "applied": not dry_run, "dry_run": dry_run}

@mcp.tool()
async def link_rule_to_control(rule_id: str, control_acronym: str) -> Dict:
    """Manually link a STIG rule id to a NIST control acronym (e.g., AC-2)."""
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor()
    upsert_mapping(cur, rule_id, control_acronym)
    conn.commit()
    cur.close(); conn.close()
    return {"linked": True, "rule_id": rule_id, "control_acronym": control_acronym}

def _derive_control_updates_from_rule(rule: Dict, control_acronym: str) -> Dict:
    description = rule.get("description")
    severity = rule.get("severity")
    fix = rule.get("fix")
    title = rule.get("title")
    return {
        "control_acronym": control_acronym,
        "control_title": title,
        "compliance_status": "Non-Compliant",
        "implementation_status": "Planned",
        "vulnerability_summary": description,
        "mitigations": fix,
        "severity": severity,
        "extra": {
            "source": "stig_rule_ingest",
            "rule_id": rule.get("id"),
            "rule_title": title,
            "rule_severity": severity,
            "rule_fix": fix
        }
    }

@mcp.tool()
async def ingest_failed_rules(
    failed_rules_json: str,
    default_control_status: str = "Non-Compliant",
    default_impl_status: str = "Planned"
) -> Dict:
    """
    Ingest failed STIG rules and populate/update corresponding rows in nist_controls.

    Input failed_rules_json format (stringified JSON):
    [
      {"rule_id": "xccdf_org.ssgproject.content_rule_mount_option_dev_shm_nodev",
       "control_acronym": "CM-7"},   // optional; if absent we'll try mapping/inference
      {"rule_id": "xccdf_org.ssgproject.content_rule_sshd_set_idle_timeout"}
    ]
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

        rule = fetch_rule(cur, rid)
        if not rule:
            processed.append({"ok": False, "rule_id": rid, "reason": "rule not found in stig_rules"})
            continue

        control = item.get("control_acronym") or map_rule_to_control_in_db(cur, rid)
        if not control:
            processed.append({"ok": False, "rule_id": rid, "reason": "no control mapping; use link_rule_to_control"})
            continue

        upsert_mapping(cur, rid, control)

        updates = _derive_control_updates_from_rule(rule, control)
        if default_control_status: updates["compliance_status"] = default_control_status
        if default_impl_status:    updates["implementation_status"] = default_impl_status

        cur.execute("SELECT control_title FROM nist_controls WHERE LOWER(control_acronym)=LOWER(%s)", (control,))
        row = cur.fetchone()
        if row and row[0]:
            updates["control_title"] = None  # preserve existing

        upsert_control(cur, updates)

        processed.append({
            "ok": True,
            "rule_id": rid,
            "control_acronym": control,
            "derived_from": "rule_references.NIST" if "control_acronym" not in item else "explicit",
        })

    conn.commit()
    cur.close(); conn.close()

    return {"ingested": [p for p in processed if p.get("ok")],
            "failed":   [p for p in processed if not p.get("ok")]}

@mcp.tool()
async def get_control(control_acronym: str) -> Optional[Dict]:
    """Fetch a single NIST control row by acronym from nist_controls."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM nist_controls WHERE LOWER(control_acronym) = LOWER(%s)", (control_acronym,))
    row = cur.fetchone()
    res = row_to_dict(row, cur) if row else None
    cur.close(); conn.close()
    return res

@mcp.tool()
async def update_control_fields(control_acronym: str, updates_json) -> Dict:
    """
    Partially update fields for a control.
    Accepts:
      - a JSON object (preferred): {"recommendations": "...", "implementation_narrative": "..."}
      - a JSON string: "{\"recommendations\":\"...\"}"
      - even a double-encoded JSON string: "\"{\\\"recommendations\\\":\\\"...\\\"}\""
    """
    import ast

    def parse_updates_arg(arg):
        if isinstance(arg, dict):
            return arg
        text = str(arg)
        try:
            obj = json.loads(text)
        except Exception:
            try:
                obj = json.loads(bytes(text, "utf-8").decode("unicode_escape"))
            except Exception:
                try:
                    obj = ast.literal_eval(text)
                except Exception as e:
                    raise ValueError(f"updates_json must be a JSON object: {e}")
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
        cur.close(); conn.close()

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
    cur.close(); conn.close()

    def _clean(v):
        if isinstance(v, dict):
            return json.dumps(v, ensure_ascii=False)
        return v

    data = [{c: _clean(v) for c, v in zip(cols, r)} for r in rows]
    df = pd.DataFrame(data)
    df.to_excel(path, index=False)
    return {"ok": True, "path": path, "rows": len(data)}

# -------------------- MCP resources --------------------

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
            try: rule["rule_references"] = json.loads(rule["rule_references"])
            except Exception: pass
        results.append(rule)
    cur.close(); conn.close()
    return results

@mcp.resource("stig://rule/{rule_id}")
async def get_rule_resource(rule_id: str) -> Optional[Dict]:
    """Return specific STIG rule resource from database."""
    return await get_stig_rule(rule_id)

# -------------------- health / debug helpers --------------------

@mcp.tool()
async def db_ping() -> dict:
    """DB connectivity check."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT version();")
    ver = cur.fetchone()[0]
    cur.close(); conn.close()
    return {"ok": True, "version": ver}

# -------------------- main --------------------

if __name__ == "__main__":
    ensure_schema()
    print("DB cfg:", DB_CONFIG.get("host"), DB_CONFIG.get("dbname"), DB_CONFIG.get("user"), DB_CONFIG.get("sslmode"))
    print("🚀 STIG Automation Server running with PostgreSQL backend...")

    # IMPORTANT: with fastmcp 2.12.3, run() supports transport + port only.
    # Render terminates TLS -> external clients use HTTPS.
    mcp.run(
        transport="http",                      # or "sse"
        port=int(os.getenv("PORT", "8000"))    # Render injects PORT
    )
