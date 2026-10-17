"""
Synthetic Telecommand & Adversarial Attack Scenario Generator
Project: Cybersecurity 2 — Secure Telemetry/Command Validation Simulator

Provides deterministic seeded valid and invalid examples for testing, live demo
streams, and interactive red-team attack simulations. Strictly local synthetic data.
"""

import json
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from src.crypto_auth import sign_packet
from src.schema import DEFAULT_SECRET_KEY


def build_valid_packet(
    packet_id: str = "PKT-1001",
    segment_origin: str = "GROUND_SEGMENT",
    target_asset: str = "SAT-SENTINEL-01",
    message_class: str = "TELECOMMAND",
    command_type: str = "PING_HEARTBEAT",
    operator_id: str = "OP-FD-01",
    operator_role: str = "FLIGHT_DIRECTOR",
    sequence_number: int = 1,
    timestamp_epoch: Optional[float] = None,
    parameters: Optional[Dict[str, Any]] = None,
    secret_key: str = DEFAULT_SECRET_KEY,
) -> Dict[str, Any]:
    """Construct and cryptographically sign a valid synthetic packet."""
    ts = round(timestamp_epoch if timestamp_epoch is not None else time.time(), 3)

    default_params_map = {
        "PING_HEARTBEAT": {"echo_token": "ECHO-ALPHA-01", "subsystem": "ALL"},
        "REQUEST_TELEMETRY": {"subsystem": "ADCS", "sample_rate_hz": 10},
        "ADJUST_ANTENNA_GAIN": {"gain_db": 14.5, "band": "KA-BAND"},
        "CALIBRATE_PAYLOAD": {"sensor_id": "OPTICAL-NIR", "exposure_ms": 250.0, "gain_db": 6.0},
        "ORIENT_SOLAR_ARRAY": {"sun_angle_deg": 42.5, "array_wing": "BOTH"},
        "FIRE_THRUSTER": {"thrust_pct": 65.0, "burn_duration_ms": 2400, "axis": "PROGRADE"},
        "SAFE_MODE_OVERRIDE": {"override_code": "SAFE-OMEGA-99", "shed_non_essential_loads": True},
        "CRYPTO_KEY_ROTATE": {"TargetKeySlot": 2, "zeroize_previous": False},
        "TELEMETRY_HEARTBEAT": {
            "bus_voltage_v": 28.4,
            "battery_temp_c": 18.2,
            "attitude_error_deg": 0.04,
        },
    }

    params = parameters if parameters is not None else default_params_map.get(
        command_type, {"echo_token": "DEFAULT", "subsystem": "OBC"}
    )

    unsigned = {
        "packet_id": packet_id,
        "version": "2.0",
        "segment_origin": segment_origin,
        "target_asset": target_asset,
        "message_class": message_class,
        "command_type": command_type,
        "operator_id": operator_id,
        "operator_role": operator_role,
        "sequence_number": sequence_number,
        "timestamp_epoch": ts,
        "parameters": params,
    }
    return sign_packet(unsigned, secret_key=secret_key)


def generate_seeded_scenario_suite(
    base_time: Optional[float] = None,
    secret_key: str = DEFAULT_SECRET_KEY,
) -> List[Dict[str, Any]]:
    """
    Generate a deterministic 16-message benchmark suite containing 6 valid packets
    across segments/roles and 10 seeded attack/malformed packets covering every
    defensive validation gate.
    """
    now = round(base_time if base_time is not None else time.time(), 3)

    scenarios: List[Dict[str, Any]] = []

    # 1. Valid Ground Station Ping
    scenarios.append(
        {
            "scenario_id": "SCN-01",
            "title": "Nominal Ground Link Heartbeat",
            "category": "VALID",
            "expected_accepted": True,
            "expected_code": "VALID_ACCEPTED",
            "payload": build_valid_packet(
                packet_id="PKT-1001",
                segment_origin="GROUND_SEGMENT",
                target_asset="SAT-SENTINEL-01",
                command_type="PING_HEARTBEAT",
                operator_id="OP-FD-01",
                operator_role="FLIGHT_DIRECTOR",
                sequence_number=101,
                timestamp_epoch=now - 1.2,
                secret_key=secret_key,
            ),
        }
    )

    # 2. Valid Payload Calibration
    scenarios.append(
        {
            "scenario_id": "SCN-02",
            "title": "Authorized Optical Payload Calibration",
            "category": "VALID",
            "expected_accepted": True,
            "expected_code": "VALID_ACCEPTED",
            "payload": build_valid_packet(
                packet_id="PKT-1002",
                segment_origin="GROUND_SEGMENT",
                target_asset="SAT-SENTINEL-01",
                command_type="CALIBRATE_PAYLOAD",
                operator_id="OP-PL-04",
                operator_role="PAYLOAD_ENGINEER",
                sequence_number=102,
                timestamp_epoch=now - 0.9,
                parameters={"sensor_id": "OPTICAL-NIR", "exposure_ms": 420.0, "gain_db": 8.5},
                secret_key=secret_key,
            ),
        }
    )

    # 3. Valid GNC Solar Array Orientation
    scenarios.append(
        {
            "scenario_id": "SCN-03",
            "title": "GNC Solar Array Sun-Tracking Slew",
            "category": "VALID",
            "expected_accepted": True,
            "expected_code": "VALID_ACCEPTED",
            "payload": build_valid_packet(
                packet_id="PKT-1003",
                segment_origin="GROUND_SEGMENT",
                target_asset="SAT-RECON-04",
                command_type="ORIENT_SOLAR_ARRAY",
                operator_id="OP-GNC-02",
                operator_role="GNC_SPECIALIST",
                sequence_number=103,
                timestamp_epoch=now - 0.7,
                parameters={"sun_angle_deg": 37.5, "array_wing": "BOTH"},
                secret_key=secret_key,
            ),
        }
    )

    # 4. Attack: Corrupted / Truncated JSON Frame (Gate 1)
    scenarios.append(
        {
            "scenario_id": "SCN-04",
            "title": "Attack: Corrupted RF Frame / Malformed JSON",
            "category": "GATE_1_ATTACK",
            "expected_accepted": False,
            "expected_code": "MALFORMED_JSON",
            "payload": '{"packet_id": "PKT-9001", "version": "2.0", "command_type": "FIRE_THRUSTER", "parameters": {"thrust_pct": 95.0, CORRUPTED_BYTES_0xFF',
        }
    )

    # 5. Attack: Missing Required Header Fields (Gate 1)
    incomplete_pkt = {
        "packet_id": "PKT-9002",
        "version": "2.0",
        "segment_origin": "GROUND_SEGMENT",
        "command_type": "PING_HEARTBEAT",
        # Missing target_asset, operator_id, operator_role, sequence_number, etc.
    }
    scenarios.append(
        {
            "scenario_id": "SCN-05",
            "title": "Attack: Stripped Header Fields",
            "category": "GATE_1_ATTACK",
            "expected_accepted": False,
            "expected_code": "MISSING_REQUIRED_FIELD",
            "payload": incomplete_pkt,
        }
    )

    # 6. Attack: Thruster Over-Burn Out-of-Range Value (Gate 1)
    overburn_pkt = build_valid_packet(
        packet_id="PKT-9003",
        segment_origin="GROUND_SEGMENT",
        target_asset="SAT-SENTINEL-01",
        command_type="FIRE_THRUSTER",
        operator_id="OP-FD-01",
        operator_role="FLIGHT_DIRECTOR",
        sequence_number=104,
        timestamp_epoch=now - 0.5,
        parameters={"thrust_pct": 450.0, "burn_duration_ms": 95000, "axis": "PROGRADE"},
        secret_key=secret_key,
    )
    scenarios.append(
        {
            "scenario_id": "SCN-06",
            "title": "Attack: Kinetic Thruster Over-Burn (450% Thrust)",
            "category": "GATE_1_ATTACK",
            "expected_accepted": False,
            "expected_code": "OUT_OF_RANGE_VALUE",
            "payload": overburn_pkt,
        }
    )

    # 7. Valid Orbital Thruster Delta-V Burn
    scenarios.append(
        {
            "scenario_id": "SCN-07",
            "title": "Authorized Prograde Station-Keeping Burn",
            "category": "VALID",
            "expected_accepted": True,
            "expected_code": "VALID_ACCEPTED",
            "payload": build_valid_packet(
                packet_id="PKT-1004",
                segment_origin="GROUND_SEGMENT",
                target_asset="SAT-SENTINEL-01",
                command_type="FIRE_THRUSTER",
                operator_id="OP-FD-01",
                operator_role="FLIGHT_DIRECTOR",
                sequence_number=104,
                timestamp_epoch=now - 0.5,
                parameters={"thrust_pct": 72.0, "burn_duration_ms": 3200, "axis": "PROGRADE"},
                secret_key=secret_key,
            ),
        }
    )

    # 8. Attack: Replay Attack — Duplicate Sequence ID #104 (Gate 2)
    replay_pkt = build_valid_packet(
        packet_id="PKT-9004",
        segment_origin="GROUND_SEGMENT",
        target_asset="SAT-SENTINEL-01",
        command_type="FIRE_THRUSTER",
        operator_id="OP-FD-01",
        operator_role="FLIGHT_DIRECTOR",
        sequence_number=104,  # Duplicate of PKT-1004!
        timestamp_epoch=now - 0.4,
        parameters={"thrust_pct": 72.0, "burn_duration_ms": 3200, "axis": "PROGRADE"},
        secret_key=secret_key,
    )
    scenarios.append(
        {
            "scenario_id": "SCN-08",
            "title": "Attack: Captured Telecommand Replay (Seq #104)",
            "category": "GATE_2_ATTACK",
            "expected_accepted": False,
            "expected_code": "REPLAY_SEQUENCE_ID",
            "payload": replay_pkt,
        }
    )

    # 9. Attack: Stale / Expired Timestamp Injection (Gate 2)
    stale_pkt = build_valid_packet(
        packet_id="PKT-9005",
        segment_origin="GROUND_SEGMENT",
        target_asset="SAT-SENTINEL-01",
        command_type="ORIENT_SOLAR_ARRAY",
        operator_id="OP-GNC-02",
        operator_role="GNC_SPECIALIST",
        sequence_number=105,
        timestamp_epoch=now - 380.0,  # 380 seconds old (> 30s MAX_AGE)
        parameters={"sun_angle_deg": -90.0, "array_wing": "PORT"},
        secret_key=secret_key,
    )
    scenarios.append(
        {
            "scenario_id": "SCN-09",
            "title": "Attack: Delayed Stale Packet (Age 380s > 30s TTL)",
            "category": "GATE_2_ATTACK",
            "expected_accepted": False,
            "expected_code": "STALE_TIMESTAMP",
            "payload": stale_pkt,
        }
    )

    # 10. Attack: Future Clock-Skew Spoofing (Gate 2)
    future_pkt = build_valid_packet(
        packet_id="PKT-9006",
        segment_origin="GROUND_SEGMENT",
        target_asset="SAT-SENTINEL-01",
        command_type="PING_HEARTBEAT",
        operator_id="OP-FD-01",
        operator_role="FLIGHT_DIRECTOR",
        sequence_number=106,
        timestamp_epoch=now + 120.0,  # 120s in the future
        secret_key=secret_key,
    )
    scenarios.append(
        {
            "scenario_id": "SCN-10",
            "title": "Attack: Future Timestamp Desync (+120s Skew)",
            "category": "GATE_2_ATTACK",
            "expected_accepted": False,
            "expected_code": "FUTURE_TIMESTAMP_DRIFT",
            "payload": future_pkt,
        }
    )

    # 11. Attack: MITM Tampered Payload with Invalid HMAC Signature (Gate 3)
    mitm_pkt = build_valid_packet(
        packet_id="PKT-9007",
        segment_origin="GROUND_SEGMENT",
        target_asset="SAT-SENTINEL-01",
        command_type="FIRE_THRUSTER",
        operator_id="OP-FD-01",
        operator_role="FLIGHT_DIRECTOR",
        sequence_number=107,
        timestamp_epoch=now - 0.3,
        parameters={"thrust_pct": 15.0, "burn_duration_ms": 500, "axis": "PROGRADE"},
        secret_key=secret_key,
    )
    # Tamper in transit without re-signing with the secret key
    mitm_pkt["parameters"] = {"thrust_pct": 99.0, "burn_duration_ms": 14000, "axis": "RETROGRADE"}
    scenarios.append(
        {
            "scenario_id": "SCN-11",
            "title": "Attack: Link-Segment MITM Payload Tampering",
            "category": "GATE_3_ATTACK",
            "expected_accepted": False,
            "expected_code": "INVALID_HMAC_SIGNATURE",
            "payload": mitm_pkt,
        }
    )

    # 12. Attack: Rogue Ground Station Spoofed Key (Gate 3)
    rogue_pkt = build_valid_packet(
        packet_id="PKT-9008",
        segment_origin="GROUND_SEGMENT",
        target_asset="SAT-RECON-04",
        command_type="SAFE_MODE_OVERRIDE",
        operator_id="OP-ROGUE-99",
        operator_role="FLIGHT_DIRECTOR",
        sequence_number=108,
        timestamp_epoch=now - 0.3,
        secret_key="ADVERSARY-GUESSED-WRONG-KEY-0000",
    )
    scenarios.append(
        {
            "scenario_id": "SCN-12",
            "title": "Attack: Rogue Station Spoofed HMAC Key",
            "category": "GATE_3_ATTACK",
            "expected_accepted": False,
            "expected_code": "INVALID_HMAC_SIGNATURE",
            "payload": rogue_pkt,
        }
    )

    # 13. Valid Space Segment Downlink Telemetry Heartbeat
    scenarios.append(
        {
            "scenario_id": "SCN-13",
            "title": "Space Segment Bus State-of-Health Downlink",
            "category": "VALID",
            "expected_accepted": True,
            "expected_code": "VALID_ACCEPTED",
            "payload": build_valid_packet(
                packet_id="PKT-1005",
                segment_origin="SPACE_SEGMENT",
                target_asset="SAT-SENTINEL-01",
                message_class="TELEMETRY",
                command_type="TELEMETRY_HEARTBEAT",
                operator_id="OBC-AUTO-01",
                operator_role="TELEMETRY_OBSERVER",
                sequence_number=105,
                timestamp_epoch=now - 0.2,
                parameters={"bus_voltage_v": 28.6, "battery_temp_c": 19.4, "attitude_error_deg": 0.02},
                secret_key=secret_key,
            ),
        }
    )

    # 14. Attack: Role Privilege Escalation — Observer Firing Thrusters (Gate 4)
    unauth_role_pkt = build_valid_packet(
        packet_id="PKT-9009",
        segment_origin="GROUND_SEGMENT",
        target_asset="SAT-SENTINEL-01",
        command_type="FIRE_THRUSTER",
        operator_id="OP-OBS-12",
        operator_role="TELEMETRY_OBSERVER",  # Observer role cannot execute FIRE_THRUSTER
        sequence_number=106,
        timestamp_epoch=now - 0.2,
        parameters={"thrust_pct": 50.0, "burn_duration_ms": 2000, "axis": "NORMAL"},
        secret_key=secret_key,
    )
    scenarios.append(
        {
            "scenario_id": "SCN-14",
            "title": "Attack: Privilege Escalation (Observer -> FIRE_THRUSTER)",
            "category": "GATE_4_ATTACK",
            "expected_accepted": False,
            "expected_code": "UNAUTHORIZED_ROLE_ACL",
            "payload": unauth_role_pkt,
        }
    )

    # 15. Attack: Cross-Segment Lateral Injection — User Terminal Uplinking Override (Gate 4)
    unauth_seg_pkt = build_valid_packet(
        packet_id="PKT-9010",
        segment_origin="USER_SEGMENT",  # User segment cannot originate SAFE_MODE_OVERRIDE
        target_asset="SAT-SENTINEL-01",
        command_type="SAFE_MODE_OVERRIDE",
        operator_id="OP-FD-01",
        operator_role="FLIGHT_DIRECTOR",
        sequence_number=107,
        timestamp_epoch=now - 0.1,
        secret_key=secret_key,
    )
    scenarios.append(
        {
            "scenario_id": "SCN-15",
            "title": "Attack: User Segment Lateral Bus Override Injection",
            "category": "GATE_4_ATTACK",
            "expected_accepted": False,
            "expected_code": "UNAUTHORIZED_SEGMENT_ORIGIN",
            "payload": unauth_seg_pkt,
        }
    )

    # 16. Valid Cryptographic Key Rotation by Security Admin
    scenarios.append(
        {
            "scenario_id": "SCN-16",
            "title": "Authorized Zero-Trust Key Slot Rotation",
            "category": "VALID",
            "expected_accepted": True,
            "expected_code": "VALID_ACCEPTED",
            "payload": build_valid_packet(
                packet_id="PKT-1006",
                segment_origin="GROUND_SEGMENT",
                target_asset="SAT-SENTINEL-01",
                command_type="CRYPTO_KEY_ROTATE",
                operator_id="OP-SEC-01",
                operator_role="SECURITY_ADMIN",
                sequence_number=106,
                timestamp_epoch=now - 0.1,
                parameters={"TargetKeySlot": 3, "zeroize_previous": True},
                secret_key=secret_key,
            ),
        }
    )

    return scenarios


def build_preset_attack_payload(
    attack_type: str,
    next_seq: int,
    last_accepted_seq: int,
    secret_key: str = DEFAULT_SECRET_KEY,
) -> Tuple[Union[str, Dict[str, Any]], str]:
    """
    Build a specific one-click attack vector payload and human-readable description
    for the interactive Attack Simulator Controller.
    """
    now = round(time.time(), 3)

    if attack_type == "CORRUPTED_JSON":
        raw_corrupt = (
            '{\n  "packet_id": "PKT-ATK-401",\n  "version": "2.0",\n'
            '  "segment_origin": "GROUND_SEGMENT",\n  "command_type": "FIRE_THRUSTER",\n'
            '  "parameters": {"thrust_pct": 100.0, "burn_duration_ms": [UNCLOSED_ARRAY_0xFF}\n}'
        )
        return raw_corrupt, "Injected truncated/malformed JSON frame simulating RF bit-corruption or parser exploit."

    if attack_type == "OUT_OF_RANGE_THRUST":
        pkt = build_valid_packet(
            packet_id=f"PKT-ATK-{next_seq}",
            command_type="FIRE_THRUSTER",
            operator_role="FLIGHT_DIRECTOR",
            sequence_number=next_seq,
            timestamp_epoch=now,
            parameters={"thrust_pct": 999.0, "burn_duration_ms": 60000, "axis": "RETROGRADE"},
            secret_key=secret_key,
        )
        return pkt, "Signed packet with extreme out-of-bounds thruster parameters (999% thrust, 60s burn) to test Gate 1 physical safety bounds."

    if attack_type == "UNKNOWN_FIELD_INJECTION":
        pkt = build_valid_packet(
            packet_id=f"PKT-ATK-{next_seq}",
            command_type="PING_HEARTBEAT",
            operator_role="FLIGHT_DIRECTOR",
            sequence_number=next_seq,
            timestamp_epoch=now,
            secret_key=secret_key,
        )
        pkt["debug_shell_exec"] = "rm -rf /obc/flight_control"
        pkt = sign_packet(pkt, secret_key=secret_key)
        return pkt, "Injected undocumented top-level property `debug_shell_exec` to test strict schema whitelisting."

    if attack_type == "EXPIRED_TIMESTAMP":
        pkt = build_valid_packet(
            packet_id=f"PKT-ATK-{next_seq}",
            command_type="ORIENT_SOLAR_ARRAY",
            operator_role="GNC_SPECIALIST",
            sequence_number=next_seq,
            timestamp_epoch=now - 450.0,
            parameters={"sun_angle_deg": -145.0, "array_wing": "BOTH"},
            secret_key=secret_key,
        )
        return pkt, "Validly signed packet captured 450 seconds ago and re-transmitted past the MAX_AGE expiration window."

    if attack_type == "REPLAY_DUPLICATE_SEQ":
        dup_seq = max(1, last_accepted_seq)
        pkt = build_valid_packet(
            packet_id=f"PKT-RPL-{dup_seq}",
            command_type="FIRE_THRUSTER",
            operator_role="FLIGHT_DIRECTOR",
            sequence_number=dup_seq,
            timestamp_epoch=now,
            parameters={"thrust_pct": 65.0, "burn_duration_ms": 2400, "axis": "PROGRADE"},
            secret_key=secret_key,
        )
        return pkt, f"Re-transmitted previously accepted sequence_number #{dup_seq} to test Gate 2 anti-replay tracking."

    if attack_type == "SPOOFED_SIGNATURE_MITM":
        pkt = build_valid_packet(
            packet_id=f"PKT-MITM-{next_seq}",
            command_type="PING_HEARTBEAT",
            operator_role="FLIGHT_DIRECTOR",
            sequence_number=next_seq,
            timestamp_epoch=now,
            secret_key=secret_key,
        )
        # Modify command and parameters in transit without knowing the secret key
        pkt["command_type"] = "FIRE_THRUSTER"
        pkt["parameters"] = {"thrust_pct": 85.0, "burn_duration_ms": 5000, "axis": "RETROGRADE"}
        return pkt, "Intercepted a benign PING_HEARTBEAT in the Link Segment and mutated it into FIRE_THRUSTER without re-signing."

    if attack_type == "UNAUTHORIZED_ROLE":
        pkt = build_valid_packet(
            packet_id=f"PKT-ACL-{next_seq}",
            command_type="FIRE_THRUSTER",
            operator_id="OP-OBS-77",
            operator_role="TELEMETRY_OBSERVER",
            sequence_number=next_seq,
            timestamp_epoch=now,
            parameters={"thrust_pct": 55.0, "burn_duration_ms": 2000, "axis": "PROGRADE"},
            secret_key=secret_key,
        )
        return pkt, "Authenticated TELEMETRY_OBSERVER attempting unauthorized execution of critical FIRE_THRUSTER command."

    if attack_type == "UNAUTHORIZED_SEGMENT":
        pkt = build_valid_packet(
            packet_id=f"PKT-SEG-{next_seq}",
            segment_origin="USER_SEGMENT",
            command_type="SAFE_MODE_OVERRIDE",
            operator_id="OP-FD-01",
            operator_role="FLIGHT_DIRECTOR",
            sequence_number=next_seq,
            timestamp_epoch=now,
            secret_key=secret_key,
        )
        return pkt, "Cross-segment lateral injection attempting to uplink SAFE_MODE_OVERRIDE from a read-only USER_SEGMENT terminal."

    # Default fallback: valid packet
    pkt = build_valid_packet(
        packet_id=f"PKT-VAL-{next_seq}",
        command_type="PING_HEARTBEAT",
        sequence_number=next_seq,
        timestamp_epoch=now,
        secret_key=secret_key,
    )
    return pkt, "Standard valid heartbeat telecommand."
