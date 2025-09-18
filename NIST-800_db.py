#!/usr/bin/env python3
# Load NIST 800-53 Excel (.xlsx/.xlsm) -> PostgreSQL with robust header detection.
#
# Example:
#   python3 NIST-800_db.py \
#     --excel "/Users/manohar/Desktop/STIG automation/nist_excel_sheet.xlsm" \
#     --pg-dsn "dbname=stigdb user=stig_user password=root host=localhost port=5432"
#
# Notes:
# - Auto-detects header row even if headers have newlines/quotes/merged cells.
# - Looks for BOTH "Control Acronym" and "Control Title" (normalized).
# - Unmapped columns are stored in JSONB column `extra`.
# - Re-runnable; upserts by Control Acronym.

import argparse
import re
import sys
from datetime import datetime
from typing import Dict, List, Optional, Union

import pandas as pd
import psycopg2
from psycopg2.extras import execute_values, Json

REQUIRED_COLS = ["Control Acronym", "Control Title"]

COLUMN_MAP = {
    "Control Acronym": "control_acronym",
    "Control Title": "control_title",
    "Control Information": "control_information",
    "Compliance Status": "compliance_status",
    "Implementation Status": "implementation_status",
    "Common Control Provider": "common_control_provider",
    "Security Control Designation": "security_control_designation",
    "Test Method": "test_method",
    "N/A Justification": "na_justification",
    "Estimated Completion Date": "estimated_completion_date",
    "Implementation Narrative": "implementation_narrative",
    "Responsible Entities": "responsible_entities",
    "Criticality": "criticality",
    "Frequency": "frequency",
    "Method": "method",
    "Reporting": "reporting",
    "Tracking": "tracking",
    "SLCM Comments": "slcm_comments",
    "Severity": "severity",
    "Relevance of Threat": "relevance_of_threat",
    "Likelihood": "likelihood",
    "Impact": "impact",
    "Residual Risk Level": "residual_risk_level",
    "Vulnerability Summary": "vulnerability_summary",
    "Mitigations": "mitigations",
    "Impact Description": "impact_description",
    "Recommendations": "recommendations",
}

CREATE_TABLE_SQL = '''
CREATE TABLE IF NOT EXISTS nist_controls (
    control_acronym TEXT PRIMARY KEY,
    control_title TEXT,
    control_information TEXT,
    compliance_status TEXT,
    implementation_status TEXT,
    common_control_provider TEXT,
    security_control_designation TEXT,
    test_method TEXT,
    na_justification TEXT,
    estimated_completion_date DATE,
    implementation_narrative TEXT,
    responsible_entities TEXT,
    criticality TEXT,
    frequency TEXT,
    method TEXT,
    reporting TEXT,
    tracking TEXT,
    slcm_comments TEXT,
    severity TEXT,
    relevance_of_threat TEXT,
    likelihood TEXT,
    impact TEXT,
    residual_risk_level TEXT,
    vulnerability_summary TEXT,
    mitigations TEXT,
    impact_description TEXT,
    recommendations TEXT,
    extra JSONB
);
'''

UPSERT_SQL = '''
INSERT INTO nist_controls (
    control_acronym, control_title, control_information, compliance_status,
    implementation_status, common_control_provider, security_control_designation,
    test_method, na_justification, estimated_completion_date, implementation_narrative,
    responsible_entities, criticality, frequency, method, reporting, tracking,
    slcm_comments, severity, relevance_of_threat, likelihood, impact,
    residual_risk_level, vulnerability_summary, mitigations, impact_description,
    recommendations, extra
) VALUES %s
ON CONFLICT (control_acronym) DO UPDATE SET
    control_title = EXCLUDED.control_title,
    control_information = EXCLUDED.control_information,
    compliance_status = EXCLUDED.compliance_status,
    implementation_status = EXCLUDED.implementation_status,
    common_control_provider = EXCLUDED.common_control_provider,
    security_control_designation = EXCLUDED.security_control_designation,
    test_method = EXCLUDED.test_method,
    na_justification = EXCLUDED.na_justification,
    estimated_completion_date = EXCLUDED.estimated_completion_date,
    implementation_narrative = EXCLUDED.implementation_narrative,
    responsible_entities = EXCLUDED.responsible_entities,
    criticality = EXCLUDED.criticality,
    frequency = EXCLUDED.frequency,
    method = EXCLUDED.method,
    reporting = EXCLUDED.reporting,
    tracking = EXCLUDED.tracking,
    slcm_comments = EXCLUDED.slcm_comments,
    severity = EXCLUDED.severity,
    relevance_of_threat = EXCLUDED.relevance_of_threat,
    likelihood = EXCLUDED.likelihood,
    impact = EXCLUDED.impact,
    residual_risk_level = EXCLUDED.residual_risk_level,
    vulnerability_summary = EXCLUDED.vulnerability_summary,
    mitigations = EXCLUDED.mitigations,
    impact_description = EXCLUDED.impact_description,
    recommendations = EXCLUDED.recommendations,
    extra = COALESCE(nist_controls.extra, '{}'::jsonb) || COALESCE(EXCLUDED.extra, '{}'::jsonb);
'''

def parse_args():
    ap = argparse.ArgumentParser(description="Load NIST 800-53 Excel into PostgreSQL")
    ap.add_argument("--excel", required=True, help="Path to .xlsx/.xlsm")
    ap.add_argument("--sheet", default=None, help="Sheet name; default=first sheet")
    ap.add_argument("--pg-dsn", required=True, help="psycopg2 DSN")
    ap.add_argument("--batch-size", type=int, default=1000)
    ap.add_argument("--header-scan-rows", type=int, default=300)
    return ap.parse_args()

def norm_header(s: str) -> str:
    """Normalize a header cell: lower, strip quotes, collapse whitespace, strip non-alnum."""
    if s is None or str(s).lower() == "nan":
        return ""
    s = str(s)
    s = s.replace("\n", " ").replace("\r", " ")
    s = s.strip().strip('"').strip("'")
    s = re.sub(r"\s+", " ", s)          # collapse spaces
    s = s.lower()
    s = re.sub(r"[^a-z0-9]", "", s)     # keep only a-z0-9
    return s

def target_forms() -> Dict[str, str]:
    # normalized targets: "control acronym" -> "controlacronym"
    return {
        "controlacronym": "Control Acronym",
        "controltitle": "Control Title",
    }

def read_single_sheet(excel_path: str, sheet: Optional[str]) -> pd.DataFrame:
    sheet_name: Union[int, str] = 0 if sheet is None else sheet
    df_or_dict = pd.read_excel(excel_path, sheet_name=sheet_name, header=None, dtype=str)
    if isinstance(df_or_dict, dict):
        first_key = next(iter(df_or_dict.keys()))
        return df_or_dict[first_key]
    return df_or_dict

def find_header_row(raw: pd.DataFrame, scan_rows: int) -> Optional[int]:
    tgt = set(target_forms().keys())
    max_row = min(scan_rows, len(raw))
    for r in range(max_row):
        vals = [norm_header(v) for v in list(raw.iloc[r].values)]
        present = set(v for v in vals if v in tgt)
        if {"controlacronym", "controltitle"}.issubset(present):
            return r
    return None

def build_dataframe_from_header(raw: pd.DataFrame, header_row: int) -> pd.DataFrame:
    display_names = []
    for v in list(raw.iloc[header_row].values):
        n = norm_header(v)
        # Map normalized back to pretty display if it’s one of our targets
        pretty = target_forms().get(n, None)
        display_names.append(pretty if pretty else (str(v).strip() if v is not None else ""))
    df = raw.iloc[header_row + 1:].copy()
    df.columns = display_names
    df = df.reset_index(drop=True)
    # If there are duplicate/empty column names, make them unique
    seen = {}
    new_cols = []
    for c in df.columns:
        base = c if c else "Unnamed"
        if base not in seen:
            seen[base] = 1
            new_cols.append(base)
        else:
            seen[base] += 1
            new_cols.append(f"{base}_{seen[base]}")
    df.columns = new_cols
    return df

def best_effort_date(x):
    if pd.isna(x):
        return None
    if isinstance(x, (pd.Timestamp, datetime)):
        return x.date()
    s = str(x).strip().strip('"').strip("'")
    if not s or s.lower() == "nan":
        return None
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%d-%m-%Y", "%d/%m/%Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    try:
        dt = pd.to_datetime(s, errors="coerce")
        return None if pd.isna(dt) else dt.date()
    except Exception:
        return None

def validate_required(df: pd.DataFrame):
    cols_lower = {c.lower(): c for c in df.columns}
    missing = [r for r in REQUIRED_COLS if r.lower() not in cols_lower]
    if missing:
        raise SystemExit(f"ERROR: Missing required columns after header detection: {missing}\n"
                         f"Found columns: {list(df.columns)}")

def row_to_record(row: pd.Series, original_columns: List[str]) -> Dict:
    mapped: Dict[str, object] = {}
    extra: Dict[str, object] = {}
    col_lookup = {c.lower(): c for c in original_columns}

    for human_col, pg_col in COLUMN_MAP.items():
        src = col_lookup.get(human_col.lower())
        val = row[src] if (src is not None and src in row) else None
        if pd.isna(val):
            val = None
        if human_col == "Estimated Completion Date":
            val = best_effort_date(val)
        mapped[pg_col] = val

    known_lower = set(k.lower() for k in COLUMN_MAP.keys())
    for c in original_columns:
        if c.lower() not in known_lower:
            val = row[c]
            if pd.isna(val):
                continue
            if isinstance(val, (pd.Timestamp, datetime)):
                val = val.isoformat()
            extra[c] = val

    mapped["extra"] = extra if extra else None
    return mapped

def main():
    args = parse_args()

    # Read sheet with header=None so banners are preserved.
    raw = read_single_sheet(args.excel, args.sheet)
    if not isinstance(raw, pd.DataFrame) or raw.empty:
        raise SystemExit("ERROR: Could not read a worksheet or it is empty.")

    # Find header row robustly
    header_row = find_header_row(raw, args.header_scan_rows)
    if header_row is None:
        first_row = [str(v) for v in list(raw.iloc[0].values)] if len(raw) else []
        raise SystemExit(
            "ERROR: Could not find a header row containing both 'Control Acronym' and 'Control Title'.\n"
            f"Top row seen: {first_row}\n"
            "Hint: Ensure your first true header row literally contains those two phrases (any spacing/newlines are okay)."
        )

    # Build normalized DataFrame
    df = build_dataframe_from_header(raw, header_row)
    # Trim whitespace in string cells
    df = df.applymap(lambda x: x.strip() if isinstance(x, str) else x)

    validate_required(df)

    # Create table
    conn = psycopg2.connect(dsn=args.pg_dsn)
    conn.autocommit = True
    with conn, conn.cursor() as cur:
        cur.execute(CREATE_TABLE_SQL)

    # Prepare records
    records = []
    original_cols = list(df.columns)
    for _, row in df.iterrows():
        rec = row_to_record(row, original_cols)
        if not rec.get("control_acronym"):
            continue
        records.append(rec)

    if not records:
        print("No valid rows to load (missing 'Control Acronym').")
        sys.exit(0)

    cols_order = [
        "control_acronym", "control_title", "control_information", "compliance_status",
        "implementation_status", "common_control_provider", "security_control_designation",
        "test_method", "na_justification", "estimated_completion_date", "implementation_narrative",
        "responsible_entities", "criticality", "frequency", "method", "reporting", "tracking",
        "slcm_comments", "severity", "relevance_of_threat", "likelihood", "impact",
        "residual_risk_level", "vulnerability_summary", "mitigations", "impact_description",
        "recommendations", "extra"
    ]

    def to_tuple(rec: Dict):
        return tuple(rec.get(k) if k != "extra" else Json(rec.get("extra")) for k in cols_order)

    with psycopg2.connect(dsn=args.pg_dsn) as conn2:
        with conn2.cursor() as cur:
            for i in range(0, len(records), args.batch_size):
                chunk = records[i:i + args.batch_size]
                execute_values(cur, UPSERT_SQL, [to_tuple(r) for r in chunk])
        conn2.commit()

    print(f"✅ Loaded {len(records)} rows into nist_controls.")

if __name__ == "__main__":
    main()
