"""
Forensic Audit Log & Compliance Exporter (.JSON / .CSV)
Project: Cybersecurity 2 — Secure Telemetry/Command Validation Simulator
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List
import pandas as pd

from src.validator import ValidationDecision


def decisions_to_records(decisions: List[ValidationDecision]) -> List[Dict[str, Any]]:
    """Convert a list of ValidationDecision objects into flat serializable dictionaries."""
    records: List[Dict[str, Any]] = []
    for idx, dec in enumerate(decisions, start=1):
        iso_time = datetime.fromtimestamp(dec.evaluated_at_epoch, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"
        records.append(
            {
                "audit_index": idx,
                "evaluated_utc": iso_time,
                "decision": "ACCEPTED" if dec.accepted else "REJECTED",
                "status_code": dec.status_code,
                "failed_gate": dec.failed_gate or "ALL_PASSED",
                "severity": dec.compliance.get("severity", "NONE"),
                "packet_id": dec.packet_id,
                "segment_origin": dec.segment_origin,
                "target_asset": dec.target_asset,
                "command_type": dec.command_type,
                "operator_id": dec.operator_id,
                "operator_role": dec.operator_role,
                "sequence_number": dec.sequence_number,
                "timestamp_delta_sec": dec.timestamp_delta_sec,
                "reason": dec.reason,
                "nist_csf_mapping": dec.compliance.get("nist_csf", ""),
                "owasp_mapping": dec.compliance.get("owasp", ""),
                "sparta_mapping": dec.compliance.get("sparta", ""),
                "gate_1_status": dec.gate_results[0].status if len(dec.gate_results) > 0 else "N/A",
                "gate_2_status": dec.gate_results[1].status if len(dec.gate_results) > 1 else "N/A",
                "gate_3_status": dec.gate_results[2].status if len(dec.gate_results) > 2 else "N/A",
                "gate_4_status": dec.gate_results[3].status if len(dec.gate_results) > 3 else "N/A",
            }
        )
    return records


def decisions_to_dataframe(decisions: List[ValidationDecision]) -> pd.DataFrame:
    """Convert ValidationDecision list to a Pandas DataFrame for dashboard filtering & charts."""
    records = decisions_to_records(decisions)
    if not records:
        return pd.DataFrame(
            columns=[
                "audit_index",
                "evaluated_utc",
                "decision",
                "status_code",
                "failed_gate",
                "severity",
                "packet_id",
                "segment_origin",
                "target_asset",
                "command_type",
                "operator_id",
                "operator_role",
                "sequence_number",
                "timestamp_delta_sec",
                "reason",
                "nist_csf_mapping",
                "owasp_mapping",
                "sparta_mapping",
            ]
        )
    return pd.DataFrame(records)


def export_audit_json(decisions: List[ValidationDecision]) -> str:
    """Serialize full forensic audit report with summary metrics and compliance mappings to JSON."""
    records = decisions_to_records(decisions)
    total = len(records)
    accepted = sum(1 for r in records if r["decision"] == "ACCEPTED")
    rejected = total - accepted

    report = {
        "report_metadata": {
            "simulator": "ORBITAL SENTINEL // Zero-Trust Telecommand & Telemetry Validation Simulator",
            "project": "Cybersecurity 2 — Secure Telemetry/Command Validation Simulator",
            "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "mode": "LOCAL_SYNTHETIC_SIMULATION_ONLY (No Live Command Channel)",
            "total_packets_evaluated": total,
            "accepted_count": accepted,
            "rejected_count": rejected,
            "block_rate_pct": round((rejected / total * 100.0), 2) if total > 0 else 0.0,
        },
        "audit_events": records,
    }
    return json.dumps(report, indent=2)


def export_audit_csv(decisions: List[ValidationDecision]) -> str:
    """Serialize forensic audit log to CSV string."""
    df = decisions_to_dataframe(decisions)
    return df.to_csv(index=False)
