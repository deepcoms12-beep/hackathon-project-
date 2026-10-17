"""
Automated Self-Test & Verification Suite Runner
Project: Cybersecurity 2 — Secure Telemetry/Command Validation Simulator
"""

import time
from typing import Any, Dict, List

from src.schema import SecurityPolicy
from src.simulator_data import generate_seeded_scenario_suite
from src.validator import TelemetryCommandValidator


def run_verification_suite() -> Dict[str, Any]:
    """
    Execute all 16 seeded valid and adversarial scenarios against a fresh
    TelemetryCommandValidator with default strict SecurityPolicy and verify
    that every outcome matches expectations.
    """
    base_time = time.time()
    validator = TelemetryCommandValidator(policy=SecurityPolicy())
    scenarios = generate_seeded_scenario_suite(base_time=base_time)

    results: List[Dict[str, Any]] = []
    passed_count = 0

    for scn in scenarios:
        decision = validator.validate_message(
            scn["payload"],
            reference_time=base_time,
            record_audit=True,
        )
        matched = (
            decision.accepted == scn["expected_accepted"]
            and decision.status_code == scn["expected_code"]
        )
        if matched:
            passed_count += 1

        results.append(
            {
                "scenario_id": scn["scenario_id"],
                "title": scn["title"],
                "category": scn["category"],
                "expected": f"{'ACCEPT' if scn['expected_accepted'] else 'REJECT'} ({scn['expected_code']})",
                "actual": f"{'ACCEPT' if decision.accepted else 'REJECT'} ({decision.status_code})",
                "failed_gate": decision.failed_gate or "ALL_PASSED",
                "assertion": "PASS" if matched else "FAIL",
                "reason": decision.reason,
            }
        )

    total = len(scenarios)
    return {
        "total_tests": total,
        "passed_tests": passed_count,
        "failed_tests": total - passed_count,
        "pass_rate_pct": round((passed_count / total) * 100.0, 1) if total else 0.0,
        "all_passed": passed_count == total,
        "details": results,
    }
