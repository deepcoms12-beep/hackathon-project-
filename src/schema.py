"""
Schema, Constants, Compliance Mappings, and Security Policy Models
Project: Cybersecurity 2 — Secure Telemetry/Command Validation Simulator
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

# Pre-shared secret key used exclusively for local synthetic HMAC-SHA256 signing
DEFAULT_SECRET_KEY = "ORBITAL-SENTINEL-2026-ZERO-TRUST-PSK-9F8A7B6C5D4E"

# Required top-level fields in every synthetic telecommand / telemetry packet
REQUIRED_FIELDS: List[str] = [
    "packet_id",
    "version",
    "segment_origin",
    "target_asset",
    "message_class",
    "command_type",
    "operator_id",
    "operator_role",
    "sequence_number",
    "timestamp_epoch",
    "parameters",
    "hmac_sha256",
]

# Five Covered Operational Sites (Segments) per SPARTA / CISA Space Systems Defense-in-Depth
COVERED_SEGMENTS: List[Dict[str, str]] = [
    {
        "id": "GROUND_SEGMENT",
        "name": "Ground Segment",
        "code": "SEG-01 // GND",
        "role": "Mission control centers, monitoring stations, and ground terminals that generate telecommands and receive telemetry.",
        "security_posture": "Local validation simulator & pre-transmission cryptographic signing boundary.",
    },
    {
        "id": "LINK_SEGMENT",
        "name": "Link Segment",
        "code": "SEG-02 // LNK",
        "role": "Bi-directional RF/Laser communication networks (Ground-to-Space, Space-to-Space, Ground-to-Ground).",
        "security_posture": "Zero-trust untrusted transit zone exposed to jamming, MITM tampering, and replay injection.",
    },
    {
        "id": "SPACE_SEGMENT",
        "name": "Space Segment",
        "code": "SEG-03 // SPC",
        "role": "Orbital assets (satellites, payloads, ISS) that validate incoming telecommands and execute physical bus actions.",
        "security_posture": "On-board 4-Gate defensive firewall rejecting malformed, stale, unauthenticated, or unauthorized packets.",
    },
    {
        "id": "USER_SEGMENT",
        "name": "User Segment",
        "code": "SEG-04 // USR",
        "role": "End-user infrastructure receiving satellite downlinks, GPS receivers, and local satcom terminals.",
        "security_posture": "Read-only telemetry consumer; strictly blocked from uplinking orbital bus or payload commands.",
    },
    {
        "id": "LAUNCH_SEGMENT",
        "name": "Launch Segment",
        "code": "SEG-05 // LNC",
        "role": "Launch site infrastructure, physical support equipment, and launch vehicles responsible for orbital insertion.",
        "security_posture": "Restricted to pre-deployment telemetry handshakes and fairing/separation beacon checks.",
    },
]

ALLOWED_SEGMENTS: Set[str] = {seg["id"] for seg in COVERED_SEGMENTS}
ALLOWED_TARGET_ASSETS: Set[str] = {"SAT-SENTINEL-01", "SAT-RECON-04", "ISS-COLUMBUS-NODE"}
ALLOWED_MESSAGE_CLASSES: Set[str] = {"TELECOMMAND", "TELEMETRY"}

# Detailed parameter validation rules per command_type
COMMAND_SPECIFICATIONS: Dict[str, Dict[str, Any]] = {
    "PING_HEARTBEAT": {
        "message_class": "TELECOMMAND",
        "description": "Low-impact link liveness check and clock synchronization ping.",
        "required_params": {
            "echo_token": {"type": str, "max_len": 32},
            "subsystem": {"type": str, "allowed": ["OBC", "COMM", "ADCS", "EPS", "ALL"]},
        },
    },
    "REQUEST_TELEMETRY": {
        "message_class": "TELECOMMAND",
        "description": "Request immediate downlink snapshot of specified spacecraft subsystem.",
        "required_params": {
            "subsystem": {"type": str, "allowed": ["OBC", "COMM", "ADCS", "EPS", "THERMAL", "PAYLOAD"]},
            "sample_rate_hz": {"type": (int, float), "min": 1, "max": 100},
        },
    },
    "ADJUST_ANTENNA_GAIN": {
        "message_class": "TELECOMMAND",
        "description": "Modify S-Band / Ka-Band transceiver gain and beam steering offset.",
        "required_params": {
            "gain_db": {"type": (int, float), "min": -10.0, "max": 35.0},
            "band": {"type": str, "allowed": ["S-BAND", "X-BAND", "KA-BAND"]},
        },
    },
    "CALIBRATE_PAYLOAD": {
        "message_class": "TELECOMMAND",
        "description": "Run optical/thermal sensor radiometric calibration routine.",
        "required_params": {
            "sensor_id": {"type": str, "allowed": ["OPTICAL-NIR", "SAR-ARRAY", "MWIR-IMAGER"]},
            "exposure_ms": {"type": (int, float), "min": 1.0, "max": 5000.0},
            "gain_db": {"type": (int, float), "min": 0.0, "max": 24.0},
        },
    },
    "ORIENT_SOLAR_ARRAY": {
        "message_class": "TELECOMMAND",
        "description": "Rotate solar array drive assembly (SADA) to target sun-tracking gimbal angle.",
        "required_params": {
            "sun_angle_deg": {"type": (int, float), "min": -180.0, "max": 180.0},
            "array_wing": {"type": str, "allowed": ["PORT", "STARBOARD", "BOTH"]},
        },
    },
    "FIRE_THRUSTER": {
        "message_class": "TELECOMMAND",
        "description": "Execute orbital delta-V burn using reaction control thrusters.",
        "required_params": {
            "thrust_pct": {"type": (int, float), "min": 1.0, "max": 100.0},
            "burn_duration_ms": {"type": int, "min": 50, "max": 15000},
            "axis": {"type": str, "allowed": ["PROGRADE", "RETROGRADE", "NORMAL", "RADIAL"]},
        },
    },
    "SAFE_MODE_OVERRIDE": {
        "message_class": "TELECOMMAND",
        "description": "Transition spacecraft bus into or out of sun-safe survival configuration.",
        "required_params": {
            "override_code": {"type": str, "max_len": 24},
            "shed_non_essential_loads": {"type": bool},
        },
    },
    "CRYPTO_KEY_ROTATE": {
        "message_class": "TELECOMMAND",
        "description": "Trigger zero-trust key slot rollover to secondary pre-shared key index.",
        "required_params": {
            "TargetKeySlot": {"type": int, "min": 1, "max": 8},
            "zeroize_previous": {"type": bool},
        },
    },
    "TELEMETRY_HEARTBEAT": {
        "message_class": "TELEMETRY",
        "description": "Periodic spacecraft state-of-health telemetry report.",
        "required_params": {
            "bus_voltage_v": {"type": (int, float), "min": 22.0, "max": 36.0},
            "battery_temp_c": {"type": (int, float), "min": -40.0, "max": 65.0},
            "attitude_error_deg": {"type": (int, float), "min": 0.0, "max": 180.0},
        },
    },
}

# Default Role-Based Access Control (ACL) matrix mapping operator_role -> allowed command_types
DEFAULT_ROLE_ACL: Dict[str, List[str]] = {
    "FLIGHT_DIRECTOR": [
        "PING_HEARTBEAT",
        "REQUEST_TELEMETRY",
        "ADJUST_ANTENNA_GAIN",
        "CALIBRATE_PAYLOAD",
        "ORIENT_SOLAR_ARRAY",
        "FIRE_THRUSTER",
        "SAFE_MODE_OVERRIDE",
    ],
    "GNC_SPECIALIST": [
        "PING_HEARTBEAT",
        "REQUEST_TELEMETRY",
        "ORIENT_SOLAR_ARRAY",
        "FIRE_THRUSTER",
        "TELEMETRY_HEARTBEAT",
    ],
    "PAYLOAD_ENGINEER": [
        "PING_HEARTBEAT",
        "REQUEST_TELEMETRY",
        "CALIBRATE_PAYLOAD",
        "ADJUST_ANTENNA_GAIN",
    ],
    "TELEMETRY_OBSERVER": [
        "PING_HEARTBEAT",
        "REQUEST_TELEMETRY",
        "TELEMETRY_HEARTBEAT",
    ],
    "SECURITY_ADMIN": [
        "PING_HEARTBEAT",
        "REQUEST_TELEMETRY",
        "SAFE_MODE_OVERRIDE",
        "CRYPTO_KEY_ROTATE",
    ],
}

# Allowed origin segments per message class / role
SEGMENT_ORIGIN_RULES: Dict[str, List[str]] = {
    "GROUND_SEGMENT": [
        "PING_HEARTBEAT",
        "REQUEST_TELEMETRY",
        "ADJUST_ANTENNA_GAIN",
        "CALIBRATE_PAYLOAD",
        "ORIENT_SOLAR_ARRAY",
        "FIRE_THRUSTER",
        "SAFE_MODE_OVERRIDE",
        "CRYPTO_KEY_ROTATE",
    ],
    "SPACE_SEGMENT": [
        "TELEMETRY_HEARTBEAT",
        "PING_HEARTBEAT",
    ],
    "LAUNCH_SEGMENT": [
        "PING_HEARTBEAT",
        "REQUEST_TELEMETRY",
        "TELEMETRY_HEARTBEAT",
    ],
    "USER_SEGMENT": [
        "PING_HEARTBEAT",
        "REQUEST_TELEMETRY",
    ],
    "LINK_SEGMENT": [
        "PING_HEARTBEAT",
    ],
}

# Compliance & Threat Mappings (NIST CSF 2.0, OWASP, SPARTA Space Framework)
COMPLIANCE_MAPPING: Dict[str, Dict[str, str]] = {
    "VALID_ACCEPTED": {
        "gate": "ALL_GATES_PASSED",
        "nist_csf": "PR.DS-01 / DE.CM-01 (Verified Execution)",
        "owasp": "OWASP ASVS V1.1 — Defense-in-Depth Validation",
        "sparta": "SPARTA REC-0001 — Authenticated Telecommand Processing",
        "severity": "NONE",
    },
    "MALFORMED_JSON": {
        "gate": "GATE_1_SCHEMA",
        "nist_csf": "PR.DS-06 (Data Integrity & Parsing Verification)",
        "owasp": "OWASP Input Validation — Syntactic & Deserialization Check",
        "sparta": "SPARTA EX-0004 — Flight Software Parser Exploitation Prevention",
        "severity": "CRITICAL",
    },
    "MISSING_REQUIRED_FIELD": {
        "gate": "GATE_1_SCHEMA",
        "nist_csf": "PR.DS-06 (Structural Schema Enforcement)",
        "owasp": "OWASP API4 / ASVS V5.1 — Mass Assignment & Schema Completeness",
        "sparta": "SPARTA T-1012 — Telecommand Frame Header Completeness",
        "severity": "HIGH",
    },
    "UNKNOWN_FIELD_INJECTION": {
        "gate": "GATE_1_SCHEMA",
        "nist_csf": "PR.DS-06 (Strict Schema Whitelisting)",
        "owasp": "OWASP API3:2023 — Broken Object Property Level Authorization",
        "sparta": "SPARTA T-1015 — Unrecognized Command Parameter Injection",
        "severity": "HIGH",
    },
    "INVALID_DATA_TYPE": {
        "gate": "GATE_1_SCHEMA",
        "nist_csf": "PR.DS-06 (Strict Type Safety Validation)",
        "owasp": "OWASP Input Validation — Strong Type Checking",
        "sparta": "SPARTA EX-0004 — Type Confusion / Buffer Corruption Defense",
        "severity": "HIGH",
    },
    "OUT_OF_RANGE_VALUE": {
        "gate": "GATE_1_SCHEMA",
        "nist_csf": "PR.DS-06 / PR.IR-01 (Physical Safety Bounds Enforcement)",
        "owasp": "OWASP ASVS V5.1.4 — Numerical Range & Boundary Validation",
        "sparta": "SPARTA IM-0002 — Kinetic / Thruster Over-Burn Prevention",
        "severity": "CRITICAL",
    },
    "UNKNOWN_COMMAND_OR_ENUM": {
        "gate": "GATE_1_SCHEMA",
        "nist_csf": "PR.PS-01 (Configuration & Command Whitelisting)",
        "owasp": "OWASP Input Validation — Allowlist Verification",
        "sparta": "SPARTA T-1008 — Undocumented Opcode / Sub-system Access Block",
        "severity": "HIGH",
    },
    "STALE_TIMESTAMP": {
        "gate": "GATE_2_TEMPORAL",
        "nist_csf": "DE.CM-01 / PR.AC-03 (Temporal Freshness Enforcement)",
        "owasp": "OWASP Authentication Cheat Sheet — Message Expiration & TTL",
        "sparta": "SPARTA T-1003 — Telecommand Capture & Delayed Replay Mitigation",
        "severity": "CRITICAL",
    },
    "FUTURE_TIMESTAMP_DRIFT": {
        "gate": "GATE_2_TEMPORAL",
        "nist_csf": "DE.CM-01 (Clock Skew & Time-Spoofing Protection)",
        "owasp": "OWASP ASVS V2.2 — Temporal Synchronization Verification",
        "sparta": "SPARTA T-1021 — On-Board Time Correlation Manipulation",
        "severity": "HIGH",
    },
    "REPLAY_SEQUENCE_ID": {
        "gate": "GATE_2_TEMPORAL",
        "nist_csf": "PR.AC-07 / DE.AE-02 (Monotonic Anti-Replay Tracking)",
        "owasp": "OWASP Cryptographic Storage — Anti-Replay Sequence Window",
        "sparta": "SPARTA T-1003 — Command Replay Attack Neutralization",
        "severity": "CRITICAL",
    },
    "INVALID_HMAC_SIGNATURE": {
        "gate": "GATE_3_CRYPTO",
        "nist_csf": "PR.DS-02 / PR.AA-03 (Cryptographic Message Authentication)",
        "owasp": "OWASP Key Management / HMAC Constant-Time Verification",
        "sparta": "SPARTA T-1001 — Rogue Ground Station / MITM Spoofing Prevention",
        "severity": "CRITICAL",
    },
    "UNAUTHORIZED_ROLE_ACL": {
        "gate": "GATE_4_ACL",
        "nist_csf": "PR.AA-05 (Role-Based Access Control & Least Privilege)",
        "owasp": "OWASP API5:2023 — Broken Function Level Authorization",
        "sparta": "SPARTA T-1019 — Privilege Escalation & Unauthorized Bus Actuation",
        "severity": "CRITICAL",
    },
    "UNAUTHORIZED_SEGMENT_ORIGIN": {
        "gate": "GATE_4_ACL",
        "nist_csf": "PR.IR-01 (Network & Operational Segment Isolation)",
        "owasp": "OWASP Zero Trust Architecture — Segment Boundary Enforcement",
        "sparta": "SPARTA T-1005 — Cross-Segment Lateral Command Injection",
        "severity": "CRITICAL",
    },
}


@dataclass
class SecurityPolicy:
    """Configurable defense-in-depth policy for the 4-Gate validation pipeline."""

    # Gate 1: Structural & Range Checks
    enforce_schema_and_ranges: bool = True
    reject_unknown_fields: bool = True
    max_thrust_pct_limit: float = 100.0
    max_burn_duration_ms_limit: int = 15000

    # Gate 2: Temporal & Anti-Replay Checks
    enforce_temporal_checks: bool = True
    max_age_seconds: float = 30.0
    max_future_skew_seconds: float = 5.0
    enforce_replay_protection: bool = True

    # Gate 3: Cryptographic Authentication
    enforce_hmac_auth: bool = True
    shared_secret_key: str = DEFAULT_SECRET_KEY

    # Gate 4: Role-Based Authorization & Segment Isolation
    enforce_role_acl: bool = True
    enforce_segment_isolation: bool = True
    role_acl_matrix: Dict[str, List[str]] = field(
        default_factory=lambda: {k: list(v) for k, v in DEFAULT_ROLE_ACL.items()}
    )


def get_json_schema_documentation() -> Dict[str, Any]:
    """Return formal JSON Schema specification for UI display and documentation."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "OrbitalSentinelTelecommandSchema",
        "version": "2.0",
        "type": "object",
        "additionalProperties": False,
        "required": REQUIRED_FIELDS,
        "properties": {
            "packet_id": {"type": "string", "pattern": "^PKT-[0-9]{4,8}$"},
            "version": {"type": "string", "const": "2.0"},
            "segment_origin": {"type": "string", "enum": sorted(list(ALLOWED_SEGMENTS))},
            "target_asset": {"type": "string", "enum": sorted(list(ALLOWED_TARGET_ASSETS))},
            "message_class": {"type": "string", "enum": sorted(list(ALLOWED_MESSAGE_CLASSES))},
            "command_type": {"type": "string", "enum": sorted(list(COMMAND_SPECIFICATIONS.keys()))},
            "operator_id": {"type": "string", "minLength": 3, "maxLength": 32},
            "operator_role": {"type": "string", "enum": sorted(list(DEFAULT_ROLE_ACL.keys()))},
            "sequence_number": {"type": "integer", "minimum": 1},
            "timestamp_epoch": {"type": "number", "description": "UTC Unix timestamp in seconds"},
            "parameters": {"type": "object", "description": "Command-specific typed & bounded parameters"},
            "hmac_sha256": {
                "type": "string",
                "pattern": "^[a-f0-9]{64}$",
                "description": "HMAC-SHA256 hex digest over canonical JSON payload (excluding hmac_sha256)",
            },
        },
    }
