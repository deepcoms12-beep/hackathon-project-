"""
Cryptographic Authentication Module (Standard Library `hmac` + `hashlib`)
Project: Cybersecurity 2 — Secure Telemetry/Command Validation Simulator

Uses Python's recognized standard library `hmac` and `hashlib.sha256` with
`hmac.compare_digest` for constant-time comparison. No custom cryptography is invented.
"""

import hashlib
import hmac
import json
from typing import Any, Dict, Tuple

from src.schema import DEFAULT_SECRET_KEY


def canonicalize_payload(packet: Dict[str, Any]) -> bytes:
    """
    Serialize packet dictionary (excluding `hmac_sha256` field) into deterministic
    canonical UTF-8 JSON bytes with sorted keys and compact separators.
    """
    payload_copy = {k: v for k, v in packet.items() if k != "hmac_sha256"}
    canonical_str = json.dumps(payload_copy, sort_keys=True, separators=(",", ":"))
    return canonical_str.encode("utf-8")


def compute_hmac_sha256(packet: Dict[str, Any], secret_key: str = DEFAULT_SECRET_KEY) -> str:
    """
    Compute standard HMAC-SHA256 hex digest over the canonicalized packet payload.
    """
    canonical_bytes = canonicalize_payload(packet)
    key_bytes = secret_key.encode("utf-8")
    digest = hmac.new(key_bytes, canonical_bytes, hashlib.sha256).hexdigest()
    return digest


def sign_packet(packet: Dict[str, Any], secret_key: str = DEFAULT_SECRET_KEY) -> Dict[str, Any]:
    """
    Return a copy of the packet dictionary signed with a valid `hmac_sha256` tag.
    """
    signed = dict(packet)
    signed["hmac_sha256"] = compute_hmac_sha256(signed, secret_key=secret_key)
    return signed


def verify_hmac_sha256(
    packet: Dict[str, Any], secret_key: str = DEFAULT_SECRET_KEY
) -> Tuple[bool, str, str]:
    """
    Verify packet's `hmac_sha256` tag using constant-time `hmac.compare_digest`.

    Returns:
        (is_valid, provided_signature, expected_signature)
    """
    provided_sig = packet.get("hmac_sha256", "")
    if not isinstance(provided_sig, str) or not provided_sig:
        expected_sig = compute_hmac_sha256(packet, secret_key=secret_key)
        return False, str(provided_sig), expected_sig

    expected_sig = compute_hmac_sha256(packet, secret_key=secret_key)
    is_valid = hmac.compare_digest(provided_sig.lower(), expected_sig.lower())
    return is_valid, provided_sig, expected_sig
