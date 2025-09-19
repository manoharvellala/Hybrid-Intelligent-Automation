import os
import json
from datetime import datetime
from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from sqlalchemy import (
    create_engine, Column, Text, Date, Integer, func, or_, select
)
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import IntegrityError
from sqlalchemy.dialects.postgresql import JSONB

# ---- Config ----
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://stig_user:root@localhost:5432/stigdb"
)

app = Flask(__name__)
CORS(app)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ---- Model ----
class NistControl(Base):
    __tablename__ = "nist_controls"

    # Treat control_acronym as the primary key (non-null). If your table uses a different PK,
    # adjust this accordingly.
    control_acronym = Column(Text, primary_key=True)

    # All remaining columns are nullable=True per your schema dump
    estimated_completion_date = Column(Date, nullable=True)
    extra = Column(JSONB, nullable=True)
    control_information = Column(Text, nullable=True)
    compliance_status = Column(Text, nullable=True)
    implementation_status = Column(Text, nullable=True)
    common_control_provider = Column(Text, nullable=True)
    security_control_designation = Column(Text, nullable=True)
    test_method = Column(Text, nullable=True)
    na_justification = Column(Text, nullable=True)
    implementation_narrative = Column(Text, nullable=True)
    responsible_entities = Column(Text, nullable=True)
    criticality = Column(Text, nullable=True)
    frequency = Column(Text, nullable=True)
    reporting = Column(Text, nullable=True)
    tracking = Column(Text, nullable=True)
    slcm_comments = Column(Text, nullable=True)
    severity = Column(Text, nullable=True)
    relevance_of_threat = Column(Text, nullable=True)
    likelihood = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    residual_risk_level = Column(Text, nullable=True)
    vulnerability_summary = Column(Text, nullable=True)
    mitigations = Column(Text, nullable=True)
    impact_description = Column(Text, nullable=True)
    recommendations = Column(Text, nullable=True)
    method = Column(Text, nullable=True)
    control_title = Column(Text, nullable=True)

    def to_dict(self):
        return {
            "control_acronym": self.control_acronym,
            "estimated_completion_date": (
                self.estimated_completion_date.isoformat()
                if self.estimated_completion_date else None
            ),
            "extra": self.extra,
            "control_information": self.control_information,
            "compliance_status": self.compliance_status,
            "implementation_status": self.implementation_status,
            "common_control_provider": self.common_control_provider,
            "security_control_designation": self.security_control_designation,
            "test_method": self.test_method,
            "na_justification": self.na_justification,
            "implementation_narrative": self.implementation_narrative,
            "responsible_entities": self.responsible_entities,
            "criticality": self.criticality,
            "frequency": self.frequency,
            "reporting": self.reporting,
            "tracking": self.tracking,
            "slcm_comments": self.slcm_comments,
            "severity": self.severity,
            "relevance_of_threat": self.relevance_of_threat,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "residual_risk_level": self.residual_risk_level,
            "vulnerability_summary": self.vulnerability_summary,
            "mitigations": self.mitigations,
            "impact_description": self.impact_description,
            "recommendations": self.recommendations,
            "method": self.method,
            "control_title": self.control_title,
        }

# ---- Helpers ----
TEXT_COLUMNS = [
    NistControl.control_acronym,
    NistControl.control_information,
    NistControl.compliance_status,
    NistControl.implementation_status,
    NistControl.common_control_provider,
    NistControl.security_control_designation,
    NistControl.test_method,
    NistControl.na_justification,
    NistControl.implementation_narrative,
    NistControl.responsible_entities,
    NistControl.criticality,
    NistControl.frequency,
    NistControl.reporting,
    NistControl.tracking,
    NistControl.slcm_comments,
    NistControl.severity,
    NistControl.relevance_of_threat,
    NistControl.likelihood,
    NistControl.impact,
    NistControl.residual_risk_level,
    NistControl.vulnerability_summary,
    NistControl.mitigations,
    NistControl.impact_description,
    NistControl.recommendations,
    NistControl.method,
    NistControl.control_title,
]

def parse_date(value):
    if value in (None, "", "null"):
        return None
    # Accept "YYYY-MM-DD" or RFC3339-like strings
    try:
        return datetime.fromisoformat(value).date()
    except Exception:
        raise ValueError("estimated_completion_date must be ISO date (YYYY-MM-DD)")

def get_session():
    return SessionLocal()

# ---- Routes ----
@app.route("/health", methods=["GET"])
def health():
    return {"status": "ok"}

@app.route("/controls", methods=["GET"])
def list_controls():
    """
    Query params:
      page (default 1), page_size (default 20, max 200)
      q = free-text search across text columns (ILIKE %q%)
      compliance_status, implementation_status (exact matches)
    """
    page = max(int(request.args.get("page", 1)), 1)
    page_size = min(max(int(request.args.get("page_size", 20)), 1), 200)
    q = request.args.get("q")
    compliance_status = request.args.get("compliance_status")
    implementation_status = request.args.get("implementation_status")

    session = get_session()
    try:
        query = session.query(NistControl)
        if q:
            like = f"%{q}%"
            query = query.filter(or_(*[col.ilike(like) for col in TEXT_COLUMNS]))
        if compliance_status:
            query = query.filter(NistControl.compliance_status == compliance_status)
        if implementation_status:
            query = query.filter(NistControl.implementation_status == implementation_status)

        total = query.with_entities(func.count(NistControl.control_acronym)).scalar()
        items = (
            query.order_by(NistControl.control_acronym.asc())
                 .offset((page - 1) * page_size)
                 .limit(page_size)
                 .all()
        )
        return jsonify({
            "page": page,
            "page_size": page_size,
            "total": total,
            "items": [i.to_dict() for i in items]
        })
    finally:
        session.close()

@app.route("/controls/<control_acronym>", methods=["GET"])
def get_control(control_acronym):
    session = get_session()
    try:
        row = session.get(NistControl, control_acronym)
        if not row:
            abort(404, description="Not found")
        return jsonify(row.to_dict())
    finally:
        session.close()

@app.route("/controls", methods=["POST"])
def create_control():
    """
    Body: JSON object. control_acronym is required. estimated_completion_date must be YYYY-MM-DD (optional).
    """
    data = request.get_json(force=True, silent=True) or {}
    if "control_acronym" not in data or not data["control_acronym"]:
        abort(400, description="control_acronym is required")

    session = get_session()
    try:
        row = NistControl(
            control_acronym=data["control_acronym"],
        )

        if "estimated_completion_date" in data:
            row.estimated_completion_date = parse_date(data["estimated_completion_date"])

        # Assign other simple text fields
        for field in [
            "control_information","compliance_status","implementation_status",
            "common_control_provider","security_control_designation","test_method",
            "na_justification","implementation_narrative","responsible_entities",
            "criticality","frequency","reporting","tracking","slcm_comments",
            "severity","relevance_of_threat","likelihood","impact","residual_risk_level",
            "vulnerability_summary","mitigations","impact_description","recommendations",
            "method","control_title"
        ]:
            if field in data:
                setattr(row, field, data[field])

        # JSONB
        if "extra" in data:
            if isinstance(data["extra"], dict):
                row.extra = data["extra"]
            else:
                abort(400, description="extra must be a JSON object")

        session.add(row)
        session.commit()
        return jsonify(row.to_dict()), 201
    except IntegrityError as e:
        session.rollback()
        abort(409, description="control_acronym already exists or constraint failed")
    finally:
        session.close()

@app.route("/controls/<control_acronym>", methods=["PATCH"])
def patch_control(control_acronym):
    """
    Partial update. Accepts any subset of fields.
    For JSONB 'extra':
      - Send a full object to replace OR
      - Send {"$merge": { ... }} to merge shallowly into existing extra
    """
    data = request.get_json(force=True, silent=True) or {}
    session = get_session()
    try:
        row = session.get(NistControl, control_acronym)
        if not row:
            abort(404, description="Not found")

        if "estimated_completion_date" in data:
            row.estimated_completion_date = parse_date(data["estimated_completion_date"])

        # Simple text fields
        for field in [
            "control_information","compliance_status","implementation_status",
            "common_control_provider","security_control_designation","test_method",
            "na_justification","implementation_narrative","responsible_entities",
            "criticality","frequency","reporting","tracking","slcm_comments",
            "severity","relevance_of_threat","likelihood","impact","residual_risk_level",
            "vulnerability_summary","mitigations","impact_description","recommendations",
            "method","control_title"
        ]:
            if field in data:
                setattr(row, field, data[field])

        # JSONB logic
        if "extra" in data:
            if isinstance(data["extra"], dict):
                row.extra = data["extra"]
            else:
                abort(400, description="extra must be a JSON object")
        elif "$merge" in data:
            if not isinstance(data["$merge"], dict):
                abort(400, description="$merge must be a JSON object")
            base = row.extra or {}
            base.update(data["$merge"])
            row.extra = base

        session.commit()
        return jsonify(row.to_dict())
    finally:
        session.close()

@app.route("/controls/<control_acronym>", methods=["DELETE"])
def delete_control(control_acronym):
    session = get_session()
    try:
        row = session.get(NistControl, control_acronym)
        if not row:
            abort(404, description="Not found")
        session.delete(row)
        session.commit()
        return jsonify({"deleted": control_acronym})
    finally:
        session.close()

if __name__ == "__main__":
    # We’re not creating tables here because you already have one.
    # If you *do* want to create the table from the model, uncomment:
    # Base.metadata.create_all(engine)
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "7654")), debug=True)
