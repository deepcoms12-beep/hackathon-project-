"""
4-Gate Zero-Trust Telemetry & Telecommand Validation Engine
Project: Cybersecurity 2 — Secure Telemetry/Command Validation Simulator

Validates synthetic JSON messages through four sequential security gates:
  - Gate 1: Structural & Range Validation (JSON parsing, required fields, types, physical bounds)
  - Gate 2: Temporal & Anti-Replay Verification (MAX_AGE freshness, future skew, monotonic sequence tracking)
  - Gate 3: Cryptographic Authentication (HMAC-SHA256 constant-time signature verification)
  - Gate 4: Role-Based Authorization & Segment Isolation (Operator role ACL & origin segment rules)
"""

from dataclasses import dataclass, field
import json
import time
from typing import Any, Dict, List, Optional, Set, Union

from src.crypto_auth import verify_hmac_sha256
from src.schema import (
    ALLOWED_MESSAGE_CLASSES,
    ALLOWED_SEGMENTS,
    ALLOWED_TARGET_ASSETS,
    COMMAND_SPECIFICATIONS,
    COMPLIANCE_MAPPING,
    REQUIRED_FIELDS,
    SEGMENT_ORIGIN_RULES,
    SecurityPolicy,
)


@dataclass
class GateResult:
    """Status of an individual validation gate."""

    gate_id: str
    gate_number: int
    gate_name: str
    status: str  # "PASSED", "FAILED", "BYPASSED", "SKIPPED"
    detail: str
    code_check: str


@dataclass
class ValidationDecision:
    """Comprehensive forensic outcome for a single telemetry/command message."""

    accepted: bool
    status_code: str
    failed_gate: Optional[str]
    reason: str
    packet_id: str
    segment_origin: str
    target_asset: str
    command_type: str
    operator_id: str
    operator_role: str
    sequence_number: Optional[int]
    timestamp_epoch: Optional[float]
    timestamp_delta_sec: Optional[float]
    evaluated_at_epoch: float
    gate_results: List[GateResult]
    compliance: Dict[str, str]
    raw_payload_preview: str
    parsed_packet: Optional[Dict[str, Any]] = None


class TelemetryCommandValidator:
    """
    Stateful local simulator validating telecommands and telemetry packets across
    4 sequential defensive gates, maintaining anti-replay sequence state and an audit log.
    """

    def __init__(self, policy: Optional[SecurityPolicy] = None) -> None:
        self.policy: SecurityPolicy = policy if policy is not None else SecurityPolicy()
        self.seen_sequence_numbers: Set[int] = set()
        self.highest_sequence_number: int = 0
        self.audit_log: List[ValidationDecision] = []

    def reset_state(self) -> None:
        """Reset anti-replay sequence state and clear audit history."""
        self.seen_sequence_numbers.clear()
        self.highest_sequence_number = 0
        self.audit_log.clear()

    def _is_strict_int(self, val: Any) -> bool:
        """Return True if val is an integer and not a boolean."""
        return isinstance(val, int) and not isinstance(val, bool)

    def _is_strict_number(self, val: Any) -> bool:
        """Return True if val is an int or float and not a boolean."""
        return isinstance(val, (int, float)) and not isinstance(val, bool)

    def validate_message(
        self,
        raw_input: Union[str, Dict[str, Any]],
        reference_time: Optional[float] = None,
        record_audit: bool = True,
    ) -> ValidationDecision:
        """
        Execute the 4-Gate validation pipeline on a raw JSON string or dictionary.
        """
        now = reference_time if reference_time is not None else time.time()
        gates: List[GateResult] = []

        # Default metadata in case Gate 1 fails early
        packet_id = "UNKNOWN"
        segment_origin = "UNKNOWN"
        target_asset = "UNKNOWN"
        command_type = "UNKNOWN"
        operator_id = "UNKNOWN"
        operator_role = "UNKNOWN"
        seq_num: Optional[int] = None
        ts_epoch: Optional[float] = None
        ts_delta: Optional[float] = None

        # Step 0: Parse JSON if string
        if isinstance(raw_input, str):
            raw_preview = raw_input[:400]
            try:
                packet = json.loads(raw_input)
            except json.JSONDecodeError as exc:
                gates.extend(
                    [
                        GateResult(
                            "GATE_1_SCHEMA",
                            1,
                            "Gate 1: Structural & Range Check",
                            "FAILED",
                            f"JSON syntax error at line {exc.lineno} col {exc.colno}: {exc.msg}",
                            "json.loads(raw_input) -> JSONDecodeError",
                        ),
                        GateResult("GATE_2_TEMPORAL", 2, "Gate 2: Temporal & Anti-Replay", "SKIPPED", "Halted at Gate 1", "N/A"),
                        GateResult("GATE_3_CRYPTO", 3, "Gate 3: Cryptographic Auth", "SKIPPED", "Halted at Gate 1", "N/A"),
                        GateResult("GATE_4_ACL", 4, "Gate 4: Role-Based ACL", "SKIPPED", "Halted at Gate 1", "N/A"),
                    ]
                )
                return self._finalize(
                    accepted=False,
                    status_code="MALFORMED_JSON",
                    failed_gate="GATE_1_SCHEMA",
                    reason=f"Malformed JSON payload: {exc.msg} (line {exc.lineno}, col {exc.colno})",
                    packet_id=packet_id,
                    segment_origin=segment_origin,
                    target_asset=target_asset,
                    command_type=command_type,
                    operator_id=operator_id,
                    operator_role=operator_role,
                    seq_num=seq_num,
                    ts_epoch=ts_epoch,
                    ts_delta=ts_delta,
                    now=now,
                    gates=gates,
                    raw_preview=raw_preview,
                    parsed_packet=None,
                    record_audit=record_audit,
                )
            if not isinstance(packet, dict):
                gates.extend(
                    [
                        GateResult(
                            "GATE_1_SCHEMA",
                            1,
                            "Gate 1: Structural & Range Check",
                            "FAILED",
                            "Top-level JSON structure must be an object/dictionary.",
                            "isinstance(packet, dict) == False",
                        ),
                        GateResult("GATE_2_TEMPORAL", 2, "Gate 2: Temporal & Anti-Replay", "SKIPPED", "Halted at Gate 1", "N/A"),
                        GateResult("GATE_3_CRYPTO", 3, "Gate 3: Cryptographic Auth", "SKIPPED", "Halted at Gate 1", "N/A"),
                        GateResult("GATE_4_ACL", 4, "Gate 4: Role-Based ACL", "SKIPPED", "Halted at Gate 1", "N/A"),
                    ]
                )
                return self._finalize(
                    accepted=False,
                    status_code="MALFORMED_JSON",
                    failed_gate="GATE_1_SCHEMA",
                    reason="Top-level JSON payload must be a JSON object.",
                    packet_id=packet_id,
                    segment_origin=segment_origin,
                    target_asset=target_asset,
                    command_type=command_type,
                    operator_id=operator_id,
                    operator_role=operator_role,
                    seq_num=seq_num,
                    ts_epoch=ts_epoch,
                    ts_delta=ts_delta,
                    now=now,
                    gates=gates,
                    raw_preview=raw_preview,
                    parsed_packet=None,
                    record_audit=record_audit,
                )
        elif isinstance(raw_input, dict):
            packet = dict(raw_input)
            raw_preview = json.dumps(packet)[:400]
        else:
            gates.extend(
                [
                    GateResult(
                        "GATE_1_SCHEMA",
                        1,
                        "Gate 1: Structural & Range Check",
                        "FAILED",
                        f"Unsupported input type: {type(raw_input).__name__}",
                        "isinstance(raw_input, (str, dict)) == False",
                    ),
                    GateResult("GATE_2_TEMPORAL", 2, "Gate 2: Temporal & Anti-Replay", "SKIPPED", "Halted at Gate 1", "N/A"),
                    GateResult("GATE_3_CRYPTO", 3, "Gate 3: Cryptographic Auth", "SKIPPED", "Halted at Gate 1", "N/A"),
                    GateResult("GATE_4_ACL", 4, "Gate 4: Role-Based ACL", "SKIPPED", "Halted at Gate 1", "N/A"),
                ]
            )
            return self._finalize(
                accepted=False,
                status_code="MALFORMED_JSON",
                failed_gate="GATE_1_SCHEMA",
                reason="Unsupported message container type.",
                packet_id=packet_id,
                segment_origin=segment_origin,
                target_asset=target_asset,
                command_type=command_type,
                operator_id=operator_id,
                operator_role=operator_role,
                seq_num=seq_num,
                ts_epoch=ts_epoch,
                ts_delta=ts_delta,
                now=now,
                gates=gates,
                raw_preview=str(raw_input)[:200],
                parsed_packet=None,
                record_audit=record_audit,
            )

        # Extract basic identifiers safely for telemetry logging
        packet_id = str(packet.get("packet_id", "MISSING"))
        segment_origin = str(packet.get("segment_origin", "MISSING"))
        target_asset = str(packet.get("target_asset", "MISSING"))
        command_type = str(packet.get("command_type", "MISSING"))
        operator_id = str(packet.get("operator_id", "MISSING"))
        operator_role = str(packet.get("operator_role", "MISSING"))
        if self._is_strict_int(packet.get("sequence_number")):
            seq_num = int(packet["sequence_number"])
        if self._is_strict_number(packet.get("timestamp_epoch")):
            ts_epoch = float(packet["timestamp_epoch"])
            ts_delta = round(now - ts_epoch, 3)

        # =====================================================================
        # GATE 1: Structural & Range Validation
        # =====================================================================
        if self.policy.enforce_schema_and_ranges:
            g1_ok, g1_code, g1_reason, g1_snippet = self._check_gate1_schema_and_ranges(packet)
            if not g1_ok:
                gates.extend(
                    [
                        GateResult("GATE_1_SCHEMA", 1, "Gate 1: Structural & Range Check", "FAILED", g1_reason, g1_snippet),
                        GateResult("GATE_2_TEMPORAL", 2, "Gate 2: Temporal & Anti-Replay", "SKIPPED", "Halted at Gate 1", "N/A"),
                        GateResult("GATE_3_CRYPTO", 3, "Gate 3: Cryptographic Auth", "SKIPPED", "Halted at Gate 1", "N/A"),
                        GateResult("GATE_4_ACL", 4, "Gate 4: Role-Based ACL", "SKIPPED", "Halted at Gate 1", "N/A"),
                    ]
                )
                return self._finalize(
                    accepted=False,
                    status_code=g1_code,
                    failed_gate="GATE_1_SCHEMA",
                    reason=g1_reason,
                    packet_id=packet_id,
                    segment_origin=segment_origin,
                    target_asset=target_asset,
                    command_type=command_type,
                    operator_id=operator_id,
                    operator_role=operator_role,
                    seq_num=seq_num,
                    ts_epoch=ts_epoch,
                    ts_delta=ts_delta,
                    now=now,
                    gates=gates,
                    raw_preview=raw_preview,
                    parsed_packet=packet,
                    record_audit=record_audit,
                )
            gates.append(
                GateResult(
                    "GATE_1_SCHEMA",
                    1,
                    "Gate 1: Structural & Range Check",
                    "PASSED",
                    f"All {len(REQUIRED_FIELDS)} schema fields, strict types, and parameter ranges verified.",
                    "validate_schema_and_bounds(packet) == PASS",
                )
            )
        else:
            gates.append(
                GateResult(
                    "GATE_1_SCHEMA",
                    1,
                    "Gate 1: Structural & Range Check",
                    "BYPASSED",
                    "Policy override: Schema & range checks disabled.",
                    "policy.enforce_schema_and_ranges == False",
                )
            )

        # =====================================================================
        # GATE 2: Temporal & Anti-Replay Verification
        # =====================================================================
        if self.policy.enforce_temporal_checks or self.policy.enforce_replay_protection:
            g2_ok, g2_code, g2_reason, g2_snippet = self._check_gate2_temporal_and_replay(packet, now)
            if not g2_ok:
                gates.extend(
                    [
                        GateResult("GATE_2_TEMPORAL", 2, "Gate 2: Temporal & Anti-Replay", "FAILED", g2_reason, g2_snippet),
                        GateResult("GATE_3_CRYPTO", 3, "Gate 3: Cryptographic Auth", "SKIPPED", "Halted at Gate 2", "N/A"),
                        GateResult("GATE_4_ACL", 4, "Gate 4: Role-Based ACL", "SKIPPED", "Halted at Gate 2", "N/A"),
                    ]
                )
                return self._finalize(
                    accepted=False,
                    status_code=g2_code,
                    failed_gate="GATE_2_TEMPORAL",
                    reason=g2_reason,
                    packet_id=packet_id,
                    segment_origin=segment_origin,
                    target_asset=target_asset,
                    command_type=command_type,
                    operator_id=operator_id,
                    operator_role=operator_role,
                    seq_num=seq_num,
                    ts_epoch=ts_epoch,
                    ts_delta=ts_delta,
                    now=now,
                    gates=gates,
                    raw_preview=raw_preview,
                    parsed_packet=packet,
                    record_audit=record_audit,
                )
            gates.append(
                GateResult(
                    "GATE_2_TEMPORAL",
                    2,
                    "Gate 2: Temporal & Anti-Replay",
                    "PASSED",
                    f"Freshness delta={ts_delta if ts_delta is not None else 0.0:.2f}s (<= {self.policy.max_age_seconds}s) & Seq #{seq_num} unique.",
                    "abs(now - ts) <= MAX_AGE and seq > last_seq",
                )
            )
        else:
            gates.append(
                GateResult(
                    "GATE_2_TEMPORAL",
                    2,
                    "Gate 2: Temporal & Anti-Replay",
                    "BYPASSED",
                    "Policy override: Temporal & replay checks disabled.",
                    "policy.enforce_temporal_checks == False",
                )
            )

        # =====================================================================
        # GATE 3: Cryptographic Authentication (HMAC-SHA256)
        # =====================================================================
        if self.policy.enforce_hmac_auth:
            is_valid_sig, provided_sig, expected_sig = verify_hmac_sha256(
                packet, secret_key=self.policy.shared_secret_key
            )
            if not is_valid_sig:
                short_prov = str(provided_sig)[:12] + "..." if provided_sig else "NONE"
                short_exp = expected_sig[:12] + "..."
                g3_reason = (
                    f"HMAC-SHA256 signature mismatch! Provided '{short_prov}' != Expected '{short_exp}'. "
                    "Possible MITM payload tampering or rogue transmitter."
                )
                gates.extend(
                    [
                        GateResult(
                            "GATE_3_CRYPTO",
                            3,
                            "Gate 3: Cryptographic Auth",
                            "FAILED",
                            g3_reason,
                            "hmac.compare_digest(provided_hmac, expected_hmac) == False",
                        ),
                        GateResult("GATE_4_ACL", 4, "Gate 4: Role-Based ACL", "SKIPPED", "Halted at Gate 3", "N/A"),
                    ]
                )
                return self._finalize(
                    accepted=False,
                    status_code="INVALID_HMAC_SIGNATURE",
                    failed_gate="GATE_3_CRYPTO",
                    reason=g3_reason,
                    packet_id=packet_id,
                    segment_origin=segment_origin,
                    target_asset=target_asset,
                    command_type=command_type,
                    operator_id=operator_id,
                    operator_role=operator_role,
                    seq_num=seq_num,
                    ts_epoch=ts_epoch,
                    ts_delta=ts_delta,
                    now=now,
                    gates=gates,
                    raw_preview=raw_preview,
                    parsed_packet=packet,
                    record_audit=record_audit,
                )
            gates.append(
                GateResult(
                    "GATE_3_CRYPTO",
                    3,
                    "Gate 3: Cryptographic Auth",
                    "PASSED",
                    f"HMAC-SHA256 verified ({expected_sig[:16]}...) via constant-time digest check.",
                    "hmac.compare_digest(sig, expected) == True",
                )
            )
        else:
            gates.append(
                GateResult(
                    "GATE_3_CRYPTO",
                    3,
                    "Gate 3: Cryptographic Auth",
                    "BYPASSED",
                    "Policy override: HMAC-SHA256 verification disabled.",
                    "policy.enforce_hmac_auth == False",
                )
            )

        # =====================================================================
        # GATE 4: Role-Based Authorization & Segment Isolation
        # =====================================================================
        if self.policy.enforce_role_acl or self.policy.enforce_segment_isolation:
            g4_ok, g4_code, g4_reason, g4_snippet = self._check_gate4_acl_and_segment(packet)
            if not g4_ok:
                gates.append(
                    GateResult("GATE_4_ACL", 4, "Gate 4: Role-Based ACL", "FAILED", g4_reason, g4_snippet)
                )
                return self._finalize(
                    accepted=False,
                    status_code=g4_code,
                    failed_gate="GATE_4_ACL",
                    reason=g4_reason,
                    packet_id=packet_id,
                    segment_origin=segment_origin,
                    target_asset=target_asset,
                    command_type=command_type,
                    operator_id=operator_id,
                    operator_role=operator_role,
                    seq_num=seq_num,
                    ts_epoch=ts_epoch,
                    ts_delta=ts_delta,
                    now=now,
                    gates=gates,
                    raw_preview=raw_preview,
                    parsed_packet=packet,
                    record_audit=record_audit,
                )
            gates.append(
                GateResult(
                    "GATE_4_ACL",
                    4,
                    "Gate 4: Role-Based ACL",
                    "PASSED",
                    f"Role '{operator_role}' & Segment '{segment_origin}' authorized for '{command_type}'.",
                    "cmd in policy.role_acl_matrix[role] and segment_allowed",
                )
            )
        else:
            gates.append(
                GateResult(
                    "GATE_4_ACL",
                    4,
                    "Gate 4: Role-Based ACL",
                    "BYPASSED",
                    "Policy override: Role ACL & Segment checks disabled.",
                    "policy.enforce_role_acl == False",
                )
            )

        # Commit sequence number only when packet passes all active gates
        if seq_num is not None:
            self.seen_sequence_numbers.add(seq_num)
            if seq_num > self.highest_sequence_number:
                self.highest_sequence_number = seq_num

        return self._finalize(
            accepted=True,
            status_code="VALID_ACCEPTED",
            failed_gate=None,
            reason=f"Packet {packet_id} ({command_type}) validated across all active defensive gates and forwarded to {target_asset}.",
            packet_id=packet_id,
            segment_origin=segment_origin,
            target_asset=target_asset,
            command_type=command_type,
            operator_id=operator_id,
            operator_role=operator_role,
            seq_num=seq_num,
            ts_epoch=ts_epoch,
            ts_delta=ts_delta,
            now=now,
            gates=gates,
            raw_preview=raw_preview,
            parsed_packet=packet,
            record_audit=record_audit,
        )

    def _check_gate1_schema_and_ranges(self, packet: Dict[str, Any]):
        """Validate required fields, unknown fields, strict types, and parameter ranges."""
        # 1. Check required fields
        missing = [f for f in REQUIRED_FIELDS if f not in packet or packet[f] is None]
        if missing:
            return (
                False,
                "MISSING_REQUIRED_FIELD",
                f"Missing required schema field(s): {', '.join(missing)}",
                f"missing = [f for f in REQUIRED_FIELDS if f not in packet] -> {missing}",
            )

        # 2. Reject unwhitelisted top-level fields
        if self.policy.reject_unknown_fields:
            unknown = [k for k in packet.keys() if k not in REQUIRED_FIELDS]
            if unknown:
                return (
                    False,
                    "UNKNOWN_FIELD_INJECTION",
                    f"Unrecognized top-level field(s) injected: {', '.join(unknown)}",
                    f"unknown_fields = set(packet.keys()) - set(REQUIRED_FIELDS) -> {unknown}",
                )

        # 3. Validate top-level field types
        str_fields = [
            "packet_id",
            "version",
            "segment_origin",
            "target_asset",
            "message_class",
            "command_type",
            "operator_id",
            "operator_role",
            "hmac_sha256",
        ]
        for sf in str_fields:
            if not isinstance(packet.get(sf), str) or not str(packet.get(sf)).strip():
                return (
                    False,
                    "INVALID_DATA_TYPE",
                    f"Field '{sf}' must be a non-empty string (received {type(packet.get(sf)).__name__}).",
                    f"isinstance(packet['{sf}'], str) == False",
                )

        if packet["version"] != "2.0":
            return (
                False,
                "UNKNOWN_COMMAND_OR_ENUM",
                f"Unsupported protocol schema version '{packet['version']}'. Expected '2.0'.",
                "packet['version'] != '2.0'",
            )

        if not self._is_strict_int(packet.get("sequence_number")):
            return (
                False,
                "INVALID_DATA_TYPE",
                f"Field 'sequence_number' must be a strict integer (received {type(packet.get('sequence_number')).__name__}).",
                "isinstance(packet['sequence_number'], int) == False",
            )

        if packet["sequence_number"] < 1:
            return (
                False,
                "OUT_OF_RANGE_VALUE",
                f"Field 'sequence_number' ({packet['sequence_number']}) must be >= 1.",
                "packet['sequence_number'] < 1",
            )

        if not self._is_strict_number(packet.get("timestamp_epoch")):
            return (
                False,
                "INVALID_DATA_TYPE",
                f"Field 'timestamp_epoch' must be a numeric Unix timestamp (received {type(packet.get('timestamp_epoch')).__name__}).",
                "isinstance(packet['timestamp_epoch'], (int, float)) == False",
            )

        if not isinstance(packet.get("parameters"), dict):
            return (
                False,
                "INVALID_DATA_TYPE",
                f"Field 'parameters' must be a JSON object/dict (received {type(packet.get('parameters')).__name__}).",
                "isinstance(packet['parameters'], dict) == False",
            )

        # 4. Validate enumerations
        if packet["segment_origin"] not in ALLOWED_SEGMENTS:
            return (
                False,
                "UNKNOWN_COMMAND_OR_ENUM",
                f"Invalid segment_origin '{packet['segment_origin']}'. Must be one of {sorted(ALLOWED_SEGMENTS)}.",
                "packet['segment_origin'] not in ALLOWED_SEGMENTS",
            )

        if packet["target_asset"] not in ALLOWED_TARGET_ASSETS:
            return (
                False,
                "UNKNOWN_COMMAND_OR_ENUM",
                f"Invalid target_asset '{packet['target_asset']}'. Must be one of {sorted(ALLOWED_TARGET_ASSETS)}.",
                "packet['target_asset'] not in ALLOWED_TARGET_ASSETS",
            )

        if packet["message_class"] not in ALLOWED_MESSAGE_CLASSES:
            return (
                False,
                "UNKNOWN_COMMAND_OR_ENUM",
                f"Invalid message_class '{packet['message_class']}'. Must be TELECOMMAND or TELEMETRY.",
                "packet['message_class'] not in ALLOWED_MESSAGE_CLASSES",
            )

        cmd = packet["command_type"]
        if cmd not in COMMAND_SPECIFICATIONS:
            return (
                False,
                "UNKNOWN_COMMAND_OR_ENUM",
                f"Unrecognized command_type '{cmd}'. Blocked by command opcode whitelist.",
                "packet['command_type'] not in COMMAND_SPECIFICATIONS",
            )

        cmd_spec = COMMAND_SPECIFICATIONS[cmd]
        if packet["message_class"] != cmd_spec["message_class"]:
            return (
                False,
                "UNKNOWN_COMMAND_OR_ENUM",
                f"Command '{cmd}' requires message_class '{cmd_spec['message_class']}', got '{packet['message_class']}'.",
                "packet['message_class'] != cmd_spec['message_class']",
            )

        # 5. Validate command-specific parameters & physical bounds
        params = packet["parameters"]
        req_params = cmd_spec["required_params"]

        for p_name, p_rules in req_params.items():
            if p_name not in params:
                return (
                    False,
                    "MISSING_REQUIRED_FIELD",
                    f"Command '{cmd}' missing required parameter '{p_name}'.",
                    f"'{p_name}' not in packet['parameters']",
                )
            val = params[p_name]
            expected_type = p_rules["type"]

            # Strict bool vs int check in Python
            if expected_type is bool:
                if not isinstance(val, bool):
                    return (
                        False,
                        "INVALID_DATA_TYPE",
                        f"Parameter '{p_name}' must be boolean (got {type(val).__name__}).",
                        f"isinstance(params['{p_name}'], bool) == False",
                    )
            elif expected_type is int:
                if not self._is_strict_int(val):
                    return (
                        False,
                        "INVALID_DATA_TYPE",
                        f"Parameter '{p_name}' must be integer (got {type(val).__name__}).",
                        f"isinstance(params['{p_name}'], int) == False",
                    )
            elif expected_type == (int, float):
                if not self._is_strict_number(val):
                    return (
                        False,
                        "INVALID_DATA_TYPE",
                        f"Parameter '{p_name}' must be numeric int/float (got {type(val).__name__}).",
                        f"isinstance(params['{p_name}'], (int, float)) == False",
                    )
            elif not isinstance(val, expected_type):
                return (
                    False,
                    "INVALID_DATA_TYPE",
                    f"Parameter '{p_name}' has invalid type {type(val).__name__}.",
                    f"isinstance(params['{p_name}'], expected_type) == False",
                )

            # Allowed enum check
            if "allowed" in p_rules and val not in p_rules["allowed"]:
                return (
                    False,
                    "UNKNOWN_COMMAND_OR_ENUM",
                    f"Parameter '{p_name}' value '{val}' not in allowed set {p_rules['allowed']}.",
                    f"params['{p_name}'] not in {p_rules['allowed']}",
                )

            # Max length check
            if "max_len" in p_rules and isinstance(val, str) and len(val) > p_rules["max_len"]:
                return (
                    False,
                    "OUT_OF_RANGE_VALUE",
                    f"Parameter '{p_name}' length ({len(val)}) exceeds max_len ({p_rules['max_len']}).",
                    f"len(params['{p_name}']) > {p_rules['max_len']}",
                )

            # Numeric min/max bounds
            if self._is_strict_number(val):
                min_bound = p_rules.get("min")
                max_bound = p_rules.get("max")
                # Apply live policy overrides for thruster safety limits
                if cmd == "FIRE_THRUSTER" and p_name == "thrust_pct":
                    max_bound = min(float(max_bound), float(self.policy.max_thrust_pct_limit))
                if cmd == "FIRE_THRUSTER" and p_name == "burn_duration_ms":
                    max_bound = min(int(max_bound), int(self.policy.max_burn_duration_ms_limit))

                if min_bound is not None and val < min_bound:
                    return (
                        False,
                        "OUT_OF_RANGE_VALUE",
                        f"Parameter '{p_name}'={val} is below minimum safe threshold ({min_bound}).",
                        f"params['{p_name}'] ({val}) < {min_bound}",
                    )
                if max_bound is not None and val > max_bound:
                    return (
                        False,
                        "OUT_OF_RANGE_VALUE",
                        f"Parameter '{p_name}'={val} exceeds maximum safe limit ({max_bound}).",
                        f"params['{p_name}'] ({val}) > {max_bound}",
                    )

        if self.policy.reject_unknown_fields:
            extra_params = [k for k in params.keys() if k not in req_params]
            if extra_params:
                return (
                    False,
                    "UNKNOWN_FIELD_INJECTION",
                    f"Unexpected parameter(s) in '{cmd}': {', '.join(extra_params)}",
                    f"extra_params = set(params.keys()) - set(req_params) -> {extra_params}",
                )

        return True, "OK", "Schema and bounds valid", "PASS"

    def _check_gate2_temporal_and_replay(self, packet: Dict[str, Any], now: float):
        """Validate message timestamp freshness, future clock drift, and sequence replay."""
        ts = packet.get("timestamp_epoch")
        seq = packet.get("sequence_number")

        if self.policy.enforce_temporal_checks and self._is_strict_number(ts):
            age_sec = now - float(ts)
            if age_sec > self.policy.max_age_seconds:
                return (
                    False,
                    "STALE_TIMESTAMP",
                    f"Packet timestamp is stale: age {age_sec:.2f}s exceeds MAX_AGE ({self.policy.max_age_seconds:.1f}s).",
                    f"(now - timestamp_epoch) [{age_sec:.2f}s] > policy.max_age_seconds [{self.policy.max_age_seconds}s]",
                )
            if age_sec < -self.policy.max_future_skew_seconds:
                return (
                    False,
                    "FUTURE_TIMESTAMP_DRIFT",
                    f"Packet timestamp is {abs(age_sec):.2f}s in the future (exceeds max skew {self.policy.max_future_skew_seconds:.1f}s).",
                    f"(timestamp_epoch - now) [{abs(age_sec):.2f}s] > policy.max_future_skew_seconds",
                )

        if self.policy.enforce_replay_protection and self._is_strict_int(seq):
            if seq in self.seen_sequence_numbers:
                return (
                    False,
                    "REPLAY_SEQUENCE_ID",
                    f"Replay attack blocked: duplicate sequence_number #{seq} has already been processed.",
                    f"sequence_number ({seq}) in seen_sequence_numbers",
                )
            if seq <= self.highest_sequence_number:
                return (
                    False,
                    "REPLAY_SEQUENCE_ID",
                    f"Out-of-order / replay sequence #{seq} rejected (must be > highest seen #{self.highest_sequence_number}).",
                    f"sequence_number ({seq}) <= highest_sequence_number ({self.highest_sequence_number})",
                )

        return True, "OK", "Temporal and anti-replay checks passed", "PASS"

    def _check_gate4_acl_and_segment(self, packet: Dict[str, Any]):
        """Validate operator role permissions and operational segment isolation rules."""
        role = str(packet.get("operator_role", ""))
        cmd = str(packet.get("command_type", ""))
        segment = str(packet.get("segment_origin", ""))

        if self.policy.enforce_role_acl:
            allowed_cmds = self.policy.role_acl_matrix.get(role, [])
            if cmd not in allowed_cmds:
                return (
                    False,
                    "UNAUTHORIZED_ROLE_ACL",
                    f"Role '{role}' (Operator '{packet.get('operator_id')}') is NOT authorized to execute '{cmd}'.",
                    f"'{cmd}' not in policy.role_acl_matrix['{role}']",
                )

        if self.policy.enforce_segment_isolation:
            seg_allowed = SEGMENT_ORIGIN_RULES.get(segment, [])
            if cmd not in seg_allowed:
                return (
                    False,
                    "UNAUTHORIZED_SEGMENT_ORIGIN",
                    f"Segment boundary violation: '{segment}' is prohibited from originating '{cmd}'.",
                    f"'{cmd}' not in SEGMENT_ORIGIN_RULES['{segment}']",
                )

        return True, "OK", "Role ACL and Segment Origin verified", "PASS"

    def _finalize(
        self,
        accepted: bool,
        status_code: str,
        failed_gate: Optional[str],
        reason: str,
        packet_id: str,
        segment_origin: str,
        target_asset: str,
        command_type: str,
        operator_id: str,
        operator_role: str,
        seq_num: Optional[int],
        ts_epoch: Optional[float],
        ts_delta: Optional[float],
        now: float,
        gates: List[GateResult],
        raw_preview: str,
        parsed_packet: Optional[Dict[str, Any]],
        record_audit: bool,
    ) -> ValidationDecision:
        compliance_info = COMPLIANCE_MAPPING.get(
            status_code,
            {
                "gate": failed_gate or "UNKNOWN",
                "nist_csf": "PR.DS-06",
                "owasp": "OWASP Input Validation",
                "sparta": "SPARTA Defense-in-Depth",
                "severity": "HIGH",
            },
        )
        decision = ValidationDecision(
            accepted=accepted,
            status_code=status_code,
            failed_gate=failed_gate,
            reason=reason,
            packet_id=packet_id,
            segment_origin=segment_origin,
            target_asset=target_asset,
            command_type=command_type,
            operator_id=operator_id,
            operator_role=operator_role,
            sequence_number=seq_num,
            timestamp_epoch=ts_epoch,
            timestamp_delta_sec=ts_delta,
            evaluated_at_epoch=now,
            gate_results=gates,
            compliance=compliance_info,
            raw_payload_preview=raw_preview,
            parsed_packet=parsed_packet,
        )
        if record_audit:
            self.audit_log.append(decision)
        return decision
