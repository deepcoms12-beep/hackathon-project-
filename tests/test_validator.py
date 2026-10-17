"""
Comprehensive Unit & Integration Tests for Cybersecurity 2:
Secure Telemetry/Command Validation Simulator
"""

import json
import time
import pytest

from src.audit_logger import decisions_to_dataframe, export_audit_csv, export_audit_json
from src.crypto_auth import canonicalize_payload, compute_hmac_sha256, sign_packet, verify_hmac_sha256
from src.evaluator import run_verification_suite
from src.schema import (
    COVERED_SEGMENTS,
    DEFAULT_SECRET_KEY,
    REQUIRED_FIELDS,
    SecurityPolicy,
    get_json_schema_documentation,
)
from src.simulator_data import (
    build_preset_attack_payload,
    build_valid_packet,
    generate_seeded_scenario_suite,
)
from src.validator import TelemetryCommandValidator


def test_covered_segments_completeness():
    """Verify all 5 operational space segments (Ground, Link, Space, User, Launch) are defined."""
    segment_ids = {s["id"] for s in COVERED_SEGMENTS}
    assert segment_ids == {
        "GROUND_SEGMENT",
        "LINK_SEGMENT",
        "SPACE_SEGMENT",
        "USER_SEGMENT",
        "LAUNCH_SEGMENT",
    }


def test_canonical_hmac_signing_and_verification():
    """Verify deterministic canonical JSON serialization and constant-time HMAC-SHA256 verification."""
    pkt = build_valid_packet(packet_id="PKT-2001", sequence_number=1)
    is_valid, prov, exp = verify_hmac_sha256(pkt, secret_key=DEFAULT_SECRET_KEY)
    assert is_valid is True
    assert prov == exp
    assert len(exp) == 64

    # Key order independence check
    reordered = {k: pkt[k] for k in reversed(list(pkt.keys()))}
    assert canonicalize_payload(pkt) == canonicalize_payload(reordered)

    # Wrong key rejection
    is_valid_wrong, _, _ = verify_hmac_sha256(pkt, secret_key="WRONG-KEY")
    assert is_valid_wrong is False


def test_valid_telecommand_acceptance():
    """Verify that a properly structured, fresh, signed, authorized packet passes all 4 gates."""
    now = time.time()
    validator = TelemetryCommandValidator()
    pkt = build_valid_packet(
        packet_id="PKT-1001",
        command_type="FIRE_THRUSTER",
        operator_role="FLIGHT_DIRECTOR",
        sequence_number=10,
        timestamp_epoch=now - 1.0,
    )
    decision = validator.validate_message(pkt, reference_time=now)
    assert decision.accepted is True
    assert decision.status_code == "VALID_ACCEPTED"
    assert decision.failed_gate is None
    assert all(g.status == "PASSED" for g in decision.gate_results)
    assert 10 in validator.seen_sequence_numbers


def test_gate1_malformed_json_rejected():
    """Verify Gate 1 rejects corrupted/invalid JSON syntax."""
    validator = TelemetryCommandValidator()
    decision = validator.validate_message('{"packet_id": "PKT-BAD", "parameters": [UNCLOSED}')
    assert decision.accepted is False
    assert decision.status_code == "MALFORMED_JSON"
    assert decision.failed_gate == "GATE_1_SCHEMA"
    assert decision.gate_results[0].status == "FAILED"
    assert decision.gate_results[1].status == "SKIPPED"


def test_gate1_missing_required_fields_rejected():
    """Verify Gate 1 rejects JSON missing required schema fields."""
    validator = TelemetryCommandValidator()
    decision = validator.validate_message({"packet_id": "PKT-01", "version": "2.0"})
    assert decision.accepted is False
    assert decision.status_code == "MISSING_REQUIRED_FIELD"
    assert decision.failed_gate == "GATE_1_SCHEMA"


def test_gate1_unknown_field_injection_rejected():
    """Verify Gate 1 rejects unexpected/injected top-level fields."""
    now = time.time()
    validator = TelemetryCommandValidator()
    pkt = build_valid_packet(sequence_number=1, timestamp_epoch=now)
    pkt["injected_shell"] = "bin/sh"
    pkt = sign_packet(pkt)
    decision = validator.validate_message(pkt, reference_time=now)
    assert decision.accepted is False
    assert decision.status_code == "UNKNOWN_FIELD_INJECTION"
    assert decision.failed_gate == "GATE_1_SCHEMA"


def test_gate1_out_of_range_thrust_rejected():
    """Verify Gate 1 rejects physical thruster parameters exceeding safety bounds."""
    now = time.time()
    validator = TelemetryCommandValidator()
    pkt = build_valid_packet(
        command_type="FIRE_THRUSTER",
        operator_role="FLIGHT_DIRECTOR",
        sequence_number=1,
        timestamp_epoch=now,
        parameters={"thrust_pct": 250.0, "burn_duration_ms": 1000, "axis": "PROGRADE"},
    )
    decision = validator.validate_message(pkt, reference_time=now)
    assert decision.accepted is False
    assert decision.status_code == "OUT_OF_RANGE_VALUE"
    assert decision.failed_gate == "GATE_1_SCHEMA"


def test_gate1_strict_type_checking_bool_vs_int():
    """Verify Gate 1 does not allow Python boolean True/False to masquerade as integer sequence_number."""
    now = time.time()
    validator = TelemetryCommandValidator()
    pkt = build_valid_packet(sequence_number=1, timestamp_epoch=now)
    pkt["sequence_number"] = True
    pkt = sign_packet(pkt)
    decision = validator.validate_message(pkt, reference_time=now)
    assert decision.accepted is False
    assert decision.status_code == "INVALID_DATA_TYPE"
    assert decision.failed_gate == "GATE_1_SCHEMA"


def test_gate2_stale_timestamp_rejected():
    """Verify Gate 2 rejects messages older than policy.max_age_seconds."""
    now = time.time()
    validator = TelemetryCommandValidator(policy=SecurityPolicy(max_age_seconds=30.0))
    pkt = build_valid_packet(sequence_number=1, timestamp_epoch=now - 120.0)
    decision = validator.validate_message(pkt, reference_time=now)
    assert decision.accepted is False
    assert decision.status_code == "STALE_TIMESTAMP"
    assert decision.failed_gate == "GATE_2_TEMPORAL"


def test_gate2_future_clock_skew_rejected():
    """Verify Gate 2 rejects messages with timestamps far in the future."""
    now = time.time()
    validator = TelemetryCommandValidator()
    pkt = build_valid_packet(sequence_number=1, timestamp_epoch=now + 60.0)
    decision = validator.validate_message(pkt, reference_time=now)
    assert decision.accepted is False
    assert decision.status_code == "FUTURE_TIMESTAMP_DRIFT"
    assert decision.failed_gate == "GATE_2_TEMPORAL"


def test_gate2_replay_duplicate_sequence_rejected_and_policy_toggle():
    """Verify Gate 2 blocks replay of duplicate or lower sequence numbers unless disabled via Policy Editor."""
    now = time.time()
    validator = TelemetryCommandValidator()
    pkt1 = build_valid_packet(packet_id="PKT-10", sequence_number=10, timestamp_epoch=now)
    res1 = validator.validate_message(pkt1, reference_time=now)
    assert res1.accepted is True

    # Replay same packet with duplicate sequence_number 10
    res2 = validator.validate_message(pkt1, reference_time=now)
    assert res2.accepted is False
    assert res2.status_code == "REPLAY_SEQUENCE_ID"
    assert res2.failed_gate == "GATE_2_TEMPORAL"

    # Toggle off replay protection in policy editor -> replay now succeeds
    validator.policy.enforce_replay_protection = False
    res3 = validator.validate_message(pkt1, reference_time=now)
    assert res3.accepted is True


def test_gate3_mitm_tampering_rejected():
    """Verify Gate 3 catches in-transit MITM parameter modifications when HMAC does not match."""
    now = time.time()
    validator = TelemetryCommandValidator()
    pkt = build_valid_packet(
        command_type="FIRE_THRUSTER",
        operator_role="FLIGHT_DIRECTOR",
        sequence_number=5,
        timestamp_epoch=now,
        parameters={"thrust_pct": 20.0, "burn_duration_ms": 1000, "axis": "PROGRADE"},
    )
    # Tamper with thrust_pct in transit without re-signing
    pkt["parameters"]["thrust_pct"] = 95.0
    decision = validator.validate_message(pkt, reference_time=now)
    assert decision.accepted is False
    assert decision.status_code == "INVALID_HMAC_SIGNATURE"
    assert decision.failed_gate == "GATE_3_CRYPTO"


def test_gate4_unauthorized_role_and_segment_rejected():
    """Verify Gate 4 enforces Role-Based ACL and Segment Origin isolation."""
    now = time.time()
    validator = TelemetryCommandValidator()

    # Telemetry Observer trying to fire thrusters
    pkt_role = build_valid_packet(
        command_type="FIRE_THRUSTER",
        operator_role="TELEMETRY_OBSERVER",
        sequence_number=1,
        timestamp_epoch=now,
    )
    dec_role = validator.validate_message(pkt_role, reference_time=now)
    assert dec_role.accepted is False
    assert dec_role.status_code == "UNAUTHORIZED_ROLE_ACL"
    assert dec_role.failed_gate == "GATE_4_ACL"

    # User Segment trying to send SAFE_MODE_OVERRIDE
    pkt_seg = build_valid_packet(
        segment_origin="USER_SEGMENT",
        command_type="SAFE_MODE_OVERRIDE",
        operator_role="FLIGHT_DIRECTOR",
        sequence_number=2,
        timestamp_epoch=now,
    )
    dec_seg = validator.validate_message(pkt_seg, reference_time=now)
    assert dec_seg.accepted is False
    assert dec_seg.status_code == "UNAUTHORIZED_SEGMENT_ORIGIN"
    assert dec_seg.failed_gate == "GATE_4_ACL"


def test_full_seeded_verification_suite_and_audit_export():
    """Verify all 16 seeded valid and attack scenarios pass 100% and export cleanly to JSON/CSV."""
    report = run_verification_suite()
    assert report["total_tests"] == 16
    assert report["all_passed"] is True
    assert report["pass_rate_pct"] == 100.0

    # Test preset attack builder and audit exporters
    validator = TelemetryCommandValidator()
    # First accept a baseline valid packet at sequence 10 so REPLAY_DUPLICATE_SEQ is a true replay
    baseline_pkt = build_valid_packet(packet_id="PKT-BASE-10", sequence_number=10)
    base_dec = validator.validate_message(baseline_pkt)
    assert base_dec.accepted is True

    for atk in [
        "CORRUPTED_JSON",
        "OUT_OF_RANGE_THRUST",
        "UNKNOWN_FIELD_INJECTION",
        "EXPIRED_TIMESTAMP",
        "REPLAY_DUPLICATE_SEQ",
        "SPOOFED_SIGNATURE_MITM",
        "UNAUTHORIZED_ROLE",
        "UNAUTHORIZED_SEGMENT",
    ]:
        payload, desc = build_preset_attack_payload(atk, next_seq=50, last_accepted_seq=10)
        assert desc
        dec = validator.validate_message(payload)
        assert dec.accepted is False

    df = decisions_to_dataframe(validator.audit_log)
    assert len(df) == 9
    json_str = export_audit_json(validator.audit_log)
    parsed_json = json.loads(json_str)
    assert parsed_json["report_metadata"]["accepted_count"] == 1
    assert parsed_json["report_metadata"]["rejected_count"] == 8
    csv_str = export_audit_csv(validator.audit_log)
    assert "INVALID_HMAC_SIGNATURE" in csv_str
    assert "schema" in json.dumps(get_json_schema_documentation()).lower()
