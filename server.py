#!/usr/bin/env python3
"""
STIG Automation Server using FastMCP - PostgreSQL Backed
"""

import psycopg2
import json
from typing import List, Dict, Optional
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

@mcp.tool()
async def get_stig_rule(rule_id: str) -> Optional[Dict]:
    """Fetch STIG rule by ID from database"""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM stig_rules WHERE id = %s", (rule_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if row:
        result = row_to_dict(row, cur)
        result["rule_references"] = json.loads(result["rule_references"])
        return result
    return None


@mcp.tool()
async def search_stig_rules(query: str) -> List[Dict]:
    """Search STIG rules by title or description (case-insensitive)"""
    conn = get_db_connection()
    cur = conn.cursor()
    pattern = f"%{query.lower()}%"
    cur.execute("""
        SELECT * FROM stig_rules
        WHERE LOWER(title) LIKE %s OR LOWER(description) LIKE %s
    """, (pattern, pattern))
    rows = cur.fetchall()

    columns = [desc[0] for desc in cur.description]
    cur.close()
    conn.close()

    results = []
    for row in rows:
        rule = dict(zip(columns, row))
        if isinstance(rule["rule_references"], str):
            rule["rule_references"] = json.loads(rule["rule_references"])
        results.append(rule)

    return results

@mcp.tool()
async def apply_stig_fix(rule_id: str, dry_run: bool = True) -> Dict:
    """Simulate applying a STIG fix"""
    rule = await get_stig_rule(rule_id)
    if not rule:
        return {"error": "Rule not found"}
    return {
        "rule": rule_id,
        "fix": rule["fix"],
        "applied": not dry_run,
        "dry_run": dry_run
    }

@mcp.resource("stig://rules")
async def list_all_rules() -> List[Dict]:
    """List all STIG rules from PostgreSQL"""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM stig_rules")
    rows = cur.fetchall()
    results = []
    for row in rows:
        rule = row_to_dict(row, cur)
        rule["rule_references"] = json.loads(rule["rule_references"])
        results.append(rule)
    cur.close()
    conn.close()
    return results

@mcp.resource("stig://rule/{rule_id}")
async def get_rule_resource(rule_id: str) -> Optional[Dict]:
    """Return specific STIG rule resource from database"""
    return await get_stig_rule(rule_id)

if __name__ == "__main__":
    print("🚀 STIG Automation Server running with PostgreSQL backend...")
    mcp.run(transport="stdio")
