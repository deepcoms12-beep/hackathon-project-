"""
CLI Terminal Dashboard & Seeded Scenario Runner
Project: Cybersecurity 2 — Secure Telemetry/Command Validation Simulator

Provides a formatted terminal security dashboard displaying live 4-Gate validation
decisions, system health metrics, and NIST CSF / OWASP / SPARTA compliance mappings.
"""

from pathlib import Path
from src.audit_logger import export_audit_csv, export_audit_json
from src.evaluator import run_verification_suite
from src.schema import SecurityPolicy
from src.simulator_data import generate_seeded_scenario_suite
from src.validator import TelemetryCommandValidator


def main() -> None:
    print("=" * 96)
    print("  ORBITAL SENTINEL // ZERO-TRUST TELEMETRY & COMMAND VALIDATION SIMULATOR (CLI DASHBOARD)")
    print("  Project: Cybersecurity 2 | Mode: LOCAL SYNTHETIC SIMULATION ONLY (No Live Command Channel)")
    print("=" * 96)

    validator = TelemetryCommandValidator(policy=SecurityPolicy())
    scenarios = generate_seeded_scenario_suite()

    print(f"\n{'ID':<7} | {'STATUS':<10} | {'GATE':<15} | {'CODE':<27} | {'PACKET / COMMAND'}")
    print("-" * 96)

    for scn in scenarios:
        dec = validator.validate_message(scn["payload"])
        status_str = "ACCEPTED" if dec.accepted else "REJECTED"
        gate_str = dec.failed_gate or "ALL_4_PASSED"
        print(
            f"{scn['scenario_id']:<7} | {status_str:<10} | {gate_str:<15} | {dec.status_code:<27} | {dec.packet_id} ({dec.command_type})"
        )

    report = run_verification_suite()
    print("-" * 96)
    print(
        f"  SUMMARY: {report['passed_tests']}/{report['total_tests']} Seeded Verification Scenarios Matched Expected Decision ({report['pass_rate_pct']}%)"
    )

    out_dir = Path(__file__).resolve().parent / "audit_exports"
    out_dir.mkdir(exist_ok=True)
    json_path = out_dir / "forensic_audit_log.json"
    csv_path = out_dir / "forensic_audit_log.csv"
    json_path.write_text(export_audit_json(validator.audit_log), encoding="utf-8")
    csv_path.write_text(export_audit_csv(validator.audit_log), encoding="utf-8")
    print(f"  EXPORTED: {json_path}")
    print(f"  EXPORTED: {csv_path}")
    print("=" * 96)


if __name__ == "__main__":
    main()
