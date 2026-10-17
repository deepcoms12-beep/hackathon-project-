"""
ORBITAL SENTINEL // Zero-Trust Telemetry & Command Validation Simulator
Project: Cybersecurity 2 — Secure Telemetry/Command Validation Simulator

Interactive local security simulator demonstrating 4-Gate defense-in-depth validation
across Space, Ground, Link, User, and Launch segments with MITM Link Interceptor,
live Policy Editor, dynamic Plotly telemetry graphing, and NIST CSF / OWASP / SPARTA
forensic audit reporting.
"""

import json
import time
from html import escape
from textwrap import dedent
from typing import Any, Dict, List, Optional
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.audit_logger import decisions_to_dataframe, export_audit_csv, export_audit_json
from src.crypto_auth import sign_packet
from src.evaluator import run_verification_suite
from src.schema import (
    ALLOWED_SEGMENTS,
    ALLOWED_TARGET_ASSETS,
    COMMAND_SPECIFICATIONS,
    COMPLIANCE_MAPPING,
    COVERED_SEGMENTS,
    DEFAULT_ROLE_ACL,
    DEFAULT_SECRET_KEY,
    SecurityPolicy,
    get_json_schema_documentation,
)
from src.simulator_data import (
    build_preset_attack_payload,
    build_valid_packet,
    generate_seeded_scenario_suite,
)
from src.validator import TelemetryCommandValidator, ValidationDecision


# ---------------------------------------------------------------------------
# Page Configuration & Tactical HUD Styling
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="ORBITAL SENTINEL // Telemetry & Command Validation Simulator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');

    /* Global Dark Tactical Grid Theme */
    .stApp {
        background-color: #060A12;
        background-image:
            linear-gradient(rgba(0, 240, 255, 0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 240, 255, 0.03) 1px, transparent 1px);
        background-size: 28px 28px;
        color: #E2E8F0;
    }

    .block-container {
        padding-top: 3rem !important;
        padding-bottom: 1.5rem !important;
        max-width: 98% !important;
    }

    /* Tactical HUD Header Banner */
    .hud-header {
        background: linear-gradient(135deg, rgba(10, 17, 32, 0.96) 0%, rgba(15, 25, 45, 0.92) 100%);
        border: 1px solid rgba(0, 240, 255, 0.35);
        border-left: 5px solid #00F0FF;
        border-radius: 6px;
        padding: 0.75rem 1.15rem;
        margin-bottom: 0.75rem;
        box-shadow: 0 0 22px rgba(0, 240, 255, 0.08), inset 0 0 12px rgba(0, 240, 255, 0.04);
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 0.5rem;
    }
    .hud-header-rejected {
        border-color: rgba(255, 42, 109, 0.65) !important;
        border-left: 5px solid #FF2A6D !important;
        box-shadow: 0 0 25px rgba(255, 42, 109, 0.18), inset 0 0 15px rgba(255, 42, 109, 0.08) !important;
    }
    .hud-header-accepted {
        border-color: rgba(5, 213, 170, 0.6) !important;
        border-left: 5px solid #05D5AA !important;
        box-shadow: 0 0 25px rgba(5, 213, 170, 0.14), inset 0 0 12px rgba(5, 213, 170, 0.06) !important;
    }
    .hud-title {
        font-family: 'Space Grotesk', sans-serif;
        font-size: 1.35rem;
        font-weight: 700;
        letter-spacing: 0.06em;
        color: #F8FAFC;
        margin: 0;
    }
    .hud-subtitle {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.74rem;
        color: #94A3B8;
        margin-top: 0.15rem;
    }
    .hud-badge-group {
        display: flex;
        gap: 0.45rem;
        align-items: center;
        flex-wrap: wrap;
    }
    .hud-pill {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        font-weight: 600;
        padding: 0.25rem 0.65rem;
        border-radius: 4px;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }
    .pill-cyan {
        background: rgba(0, 240, 255, 0.12);
        border: 1px solid #00F0FF;
        color: #00F0FF;
    }
    .pill-green {
        background: rgba(5, 213, 170, 0.15);
        border: 1px solid #05D5AA;
        color: #05D5AA;
    }
    .pill-red {
        background: rgba(255, 42, 109, 0.18);
        border: 1px solid #FF2A6D;
        color: #FF2A6D;
    }
    .pill-amber {
        background: rgba(255, 184, 0, 0.15);
        border: 1px solid #FFB800;
        color: #FFB800;
    }

    /* Compact Metric Cards */
    .kpi-grid {
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 0.6rem;
        margin-bottom: 0.75rem;
    }
    .kpi-card {
        background: rgba(11, 18, 33, 0.92);
        border: 1px solid rgba(148, 163, 184, 0.22);
        border-top: 2px solid #00F0FF;
        border-radius: 5px;
        padding: 0.55rem 0.75rem;
        position: relative;
    }
    .kpi-label {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.68rem;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .kpi-value {
        font-family: 'Space Grotesk', sans-serif;
        font-size: 1.35rem;
        font-weight: 700;
        color: #F8FAFC;
        line-height: 1.2;
        margin-top: 0.15rem;
    }
    .kpi-sub {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.65rem;
        color: #64748B;
        margin-top: 0.1rem;
    }

    /* Space Segment Architecture Pipeline */
    .pipeline-box {
        background: rgba(10, 16, 29, 0.95);
        border: 1px solid rgba(0, 240, 255, 0.28);
        border-radius: 6px;
        padding: 0.7rem 0.95rem;
        margin-bottom: 0.75rem;
    }
    .pipeline-title {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.74rem;
        font-weight: 700;
        color: #00F0FF;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-bottom: 0.5rem;
        display: flex;
        justify-content: space-between;
    }
    .arch-flow {
        display: grid;
        grid-template-columns: 1fr auto 1fr auto 1.15fr auto 1fr;
        align-items: center;
        gap: 0.35rem;
    }
    .arch-node {
        background: rgba(15, 23, 42, 0.9);
        border: 1px solid rgba(148, 163, 184, 0.3);
        border-radius: 5px;
        padding: 0.5rem 0.65rem;
        text-align: center;
    }
    .arch-node-active-green {
        border: 1px solid #05D5AA;
        background: rgba(5, 213, 170, 0.09);
        box-shadow: 0 0 14px rgba(5, 213, 170, 0.16);
    }
    .arch-node-active-red {
        border: 1px solid #FF2A6D;
        background: rgba(255, 42, 109, 0.12);
        box-shadow: 0 0 16px rgba(255, 42, 109, 0.22);
    }
    .arch-node-active-amber {
        border: 1px solid #FFB800;
        background: rgba(255, 184, 0, 0.12);
        box-shadow: 0 0 14px rgba(255, 184, 0, 0.18);
    }
    .arch-node-title {
        font-family: 'Space Grotesk', sans-serif;
        font-size: 0.82rem;
        font-weight: 700;
        color: #F1F5F9;
    }
    .arch-node-meta {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.66rem;
        color: #94A3B8;
        margin-top: 0.15rem;
    }
    .arch-arrow {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        font-weight: 700;
        text-align: center;
        padding: 0 0.2rem;
    }

    /* 4-Gate Step-by-Step Pipeline Cards */
    .gate-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 0.6rem;
        margin-bottom: 0.8rem;
    }
    .gate-card {
        background: rgba(11, 18, 33, 0.95);
        border: 1px solid rgba(148, 163, 184, 0.25);
        border-radius: 5px;
        padding: 0.6rem 0.75rem;
    }
    .gate-PASSED {
        border: 1px solid #05D5AA !important;
        border-left: 4px solid #05D5AA !important;
        background: linear-gradient(180deg, rgba(5, 213, 170, 0.09) 0%, rgba(11, 18, 33, 0.95) 100%) !important;
    }
    .gate-FAILED {
        border: 1px solid #FF2A6D !important;
        border-left: 4px solid #FF2A6D !important;
        background: linear-gradient(180deg, rgba(255, 42, 109, 0.14) 0%, rgba(11, 18, 33, 0.95) 100%) !important;
        box-shadow: 0 0 16px rgba(255, 42, 109, 0.18);
    }
    .gate-BYPASSED {
        border: 1px dashed #FFB800 !important;
        border-left: 4px solid #FFB800 !important;
        background: linear-gradient(180deg, rgba(255, 184, 0, 0.1) 0%, rgba(11, 18, 33, 0.95) 100%) !important;
    }
    .gate-SKIPPED {
        border: 1px solid rgba(100, 116, 139, 0.25) !important;
        opacity: 0.65;
    }
    .gate-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-family: 'Space Grotesk', sans-serif;
        font-size: 0.8rem;
        font-weight: 700;
        color: #F8FAFC;
        margin-bottom: 0.25rem;
    }
    .gate-detail {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.68rem;
        color: #CBD5E1;
        min-height: 2.1rem;
        line-height: 1.35;
    }
    .gate-code {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.64rem;
        color: #00F0FF;
        background: rgba(0, 0, 0, 0.45);
        border: 1px solid rgba(0, 240, 255, 0.18);
        border-radius: 3px;
        padding: 0.2rem 0.4rem;
        margin-top: 0.35rem;
        overflow-x: auto;
        white-space: nowrap;
    }

    /* Tactical Panel Containers */
    .tactical-panel {
        background: rgba(11, 18, 33, 0.92);
        border: 1px solid rgba(0, 240, 255, 0.25);
        border-radius: 6px;
        padding: 0.7rem 0.9rem;
        margin-bottom: 0.7rem;
    }
    .panel-heading {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.75rem;
        font-weight: 700;
        color: #00F0FF;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        border-bottom: 1px solid rgba(0, 240, 255, 0.18);
        padding-bottom: 0.35rem;
        margin-bottom: 0.55rem;
    }

    @media (max-width: 900px) {
        .kpi-grid {
            grid-template-columns: repeat(3, minmax(0, 1fr));
        }
        .arch-flow {
            grid-template-columns: minmax(0, 1fr);
        }
        .arch-arrow {
            font-size: 0;
            line-height: 0.8;
        }
        .arch-arrow span {
            display: none;
        }
        .arch-arrow::after {
            content: "↓";
            color: #00F0FF;
            font-size: 1rem;
        }
        .arch-node {
            min-width: 0;
            overflow-wrap: anywhere;
        }
        .gate-grid {
            grid-template-columns: repeat(2, minmax(0, 1fr));
        }
        .stTabs [data-baseweb="tab-list"] {
            overflow-x: auto;
        }
        .stTabs [data-baseweb="tab"] {
            white-space: nowrap;
        }
    }

    @media (max-width: 600px) {
        .block-container {
            padding-left: 0.75rem !important;
            padding-right: 0.75rem !important;
        }
        .hud-header {
            align-items: flex-start;
        }
        .hud-title {
            font-size: 1.05rem;
        }
        .kpi-grid {
            grid-template-columns: repeat(2, minmax(0, 1fr));
        }
        .gate-grid {
            grid-template-columns: minmax(0, 1fr);
        }
        .pipeline-title {
            display: block;
        }
        .pipeline-title > span {
            display: block;
            margin-bottom: 0.25rem;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Session State Initialization
# ---------------------------------------------------------------------------
def init_session_state() -> None:
    """Initialize stateful validator, seeded benchmark history, and MITM buffer."""
    if "validator" not in st.session_state:
        validator = TelemetryCommandValidator(policy=SecurityPolicy())
        # Seed initial realistic telemetry & attack stream so dashboard is populated on first load
        base_now = time.time()
        scenarios = generate_seeded_scenario_suite(base_time=base_now)
        for scn in scenarios:
            validator.validate_message(scn["payload"], reference_time=base_now, record_audit=True)
        st.session_state.validator = validator
        st.session_state.next_seq_counter = validator.highest_sequence_number + 1
        st.session_state.last_decision = validator.audit_log[-1] if validator.audit_log else None
        st.session_state.last_action_desc = "Loaded 16 seeded telemetry & red-team attack scenarios."
        st.session_state.thruster_burn_trigger = False

    if "mitm_buffer_json" not in st.session_state:
        sample_pkt = build_valid_packet(
            packet_id="PKT-MITM-201",
            segment_origin="GROUND_SEGMENT",
            target_asset="SAT-SENTINEL-01",
            command_type="FIRE_THRUSTER",
            operator_id="OP-FD-01",
            operator_role="FLIGHT_DIRECTOR",
            sequence_number=st.session_state.next_seq_counter,
            parameters={"thrust_pct": 45.0, "burn_duration_ms": 1800, "axis": "PROGRADE"},
        )
        st.session_state.mitm_buffer_json = json.dumps(sample_pkt, indent=2)
        st.session_state.mitm_is_intercepted = False


init_session_state()
validator: TelemetryCommandValidator = st.session_state.validator


# ---------------------------------------------------------------------------
# Sidebar: Live Policy Editor & Simulator Controls
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown(
        """
        <div style="border:1px solid #00F0FF; background:rgba(0,240,255,0.08); padding:0.55rem 0.75rem; border-radius:5px; margin-bottom:0.75rem;">
            <div style="font-family:'Space Grotesk',sans-serif; font-weight:700; font-size:0.95rem; color:#00F0FF;">
                ⚙️ LIVE POLICY EDITOR
            </div>
            <div style="font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#94A3B8;">
                ZERO-TRUST FIREWALL CONFIGURATION
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.caption("Toggle security gates on the fly to observe attacks get blocked or slip through:")

    p_g1 = st.toggle(
        "Gate 1: Schema & Range Enforcement",
        value=validator.policy.enforce_schema_and_ranges,
        help="Validate required fields, strict data types, and physical thruster limits.",
    )
    p_unknown = st.toggle(
        "Gate 1b: Reject Unknown JSON Fields",
        value=validator.policy.reject_unknown_fields,
        help="Block undocumented property injection in top-level or parameter objects.",
    )
    p_max_thrust = st.slider(
        "Max Safe Thruster Limit (%)",
        min_value=20.0,
        max_value=100.0,
        value=float(validator.policy.max_thrust_pct_limit),
        step=5.0,
    )

    st.divider()
    p_g2_temp = st.toggle(
        "Gate 2a: Temporal Freshness Check",
        value=validator.policy.enforce_temporal_checks,
        help="Reject stale packets older than MAX_AGE_SECONDS or future-skewed timestamps.",
    )
    p_max_age = st.slider(
        "MAX_AGE_SECONDS (TTL Window)",
        min_value=5.0,
        max_value=120.0,
        value=float(validator.policy.max_age_seconds),
        step=5.0,
    )
    p_g2_replay = st.toggle(
        "Gate 2b: Anti-Replay Sequence Check",
        value=validator.policy.enforce_replay_protection,
        help="Reject duplicate or out-of-order sequence numbers. Turn OFF to let Replay Attacks succeed!",
    )

    st.divider()
    p_g3_hmac = st.toggle(
        "Gate 3: HMAC-SHA256 Signature Auth",
        value=validator.policy.enforce_hmac_auth,
        help="Verify constant-time HMAC-SHA256 digest. Turn OFF to see MITM tampered packets compromise the satellite!",
    )

    st.divider()
    p_g4_acl = st.toggle(
        "Gate 4a: Role-Based ACL Enforcement",
        value=validator.policy.enforce_role_acl,
        help="Verify operator_role is permitted to execute command_type.",
    )
    p_g4_seg = st.toggle(
        "Gate 4b: Segment Boundary Isolation",
        value=validator.policy.enforce_segment_isolation,
        help="Enforce SPARTA 5-Segment origin restrictions (e.g. block User Segment from bus overrides).",
    )

    # Apply live policy updates immediately
    validator.policy.enforce_schema_and_ranges = p_g1
    validator.policy.reject_unknown_fields = p_unknown
    validator.policy.max_thrust_pct_limit = p_max_thrust
    validator.policy.enforce_temporal_checks = p_g2_temp
    validator.policy.max_age_seconds = p_max_age
    validator.policy.enforce_replay_protection = p_g2_replay
    validator.policy.enforce_hmac_auth = p_g3_hmac
    validator.policy.enforce_role_acl = p_g4_acl
    validator.policy.enforce_segment_isolation = p_g4_seg

    st.divider()
    col_sb1, col_sb2 = st.columns(2)
    with col_sb1:
        if st.button("🔄 Reset & Re-Seed", use_container_width=True):
            validator.reset_state()
            base_now = time.time()
            for scn in generate_seeded_scenario_suite(base_time=base_now):
                validator.validate_message(scn["payload"], reference_time=base_now, record_audit=True)
            st.session_state.next_seq_counter = validator.highest_sequence_number + 1
            st.session_state.last_decision = validator.audit_log[-1]
            st.session_state.last_action_desc = "Reset firewall state and re-ran 16 seeded scenarios."
            st.rerun()
    with col_sb2:
        if st.button("🗑️ Clear Audit Log", use_container_width=True):
            validator.reset_state()
            st.session_state.next_seq_counter = 101
            st.session_state.last_decision = None
            st.session_state.last_action_desc = "Cleared audit log and sequence history."
            st.rerun()


# ---------------------------------------------------------------------------
# Top Tactical HUD Header (Dynamic Color Context on Accept / Reject)
# ---------------------------------------------------------------------------
last_dec: Optional[ValidationDecision] = st.session_state.get("last_decision")
header_class = ""
status_pill_html = '<span class="hud-pill pill-cyan">STANDBY // READY</span>'

if last_dec is not None:
    if last_dec.accepted:
        header_class = "hud-header-accepted"
        status_pill_html = f'<span class="hud-pill pill-green">✅ ACCEPTED // {escape(last_dec.packet_id)} ({escape(last_dec.command_type)})</span>'
    else:
        header_class = "hud-header-rejected"
        status_pill_html = f'<span class="hud-pill pill-red">🚨 BLOCKED AT {escape(last_dec.failed_gate or "UNKNOWN")} // {escape(last_dec.status_code)}</span>'

active_gates_count = sum(
    [
        validator.policy.enforce_schema_and_ranges,
        validator.policy.enforce_temporal_checks or validator.policy.enforce_replay_protection,
        validator.policy.enforce_hmac_auth,
        validator.policy.enforce_role_acl or validator.policy.enforce_segment_isolation,
    ]
)
posture_pill = (
    f'<span class="hud-pill pill-cyan">DEFENSE GATES: {active_gates_count}/4 ACTIVE</span>'
    if active_gates_count == 4
    else f'<span class="hud-pill pill-amber">⚠️ POLICY DEGRADED: {active_gates_count}/4 GATES</span>'
)

st.markdown(
    f"""
    <div class="hud-header {header_class}">
        <div>
            <div class="hud-title">🛰️ ORBITAL SENTINEL // TELEMETRY & COMMAND VALIDATION SIMULATOR</div>
            <div class="hud-subtitle">
                CYBERSECURITY 2 • ZERO-TRUST 4-GATE SPACE SEGMENT FIREWALL • LOCAL SYNTHETIC INPUTS ONLY (NO LIVE CHANNEL)
            </div>
        </div>
        <div class="hud-badge-group">
            {status_pill_html}
            {posture_pill}
            <span class="hud-pill pill-cyan">HMAC-SHA256 // STDLIB</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Top Real-Time KPI Metric Cards
# ---------------------------------------------------------------------------
total_checked = len(validator.audit_log)
accepted_count = sum(1 for d in validator.audit_log if d.accepted)
rejected_count = total_checked - accepted_count
block_rate = (rejected_count / total_checked * 100.0) if total_checked > 0 else 0.0
highest_seq = validator.highest_sequence_number

st.markdown(
    f"""
    <div class="kpi-grid">
        <div class="kpi-card" style="border-top-color:#00F0FF;">
            <div class="kpi-label">TOTAL PACKETS EVALUATED</div>
            <div class="kpi-value">{total_checked}</div>
            <div class="kpi-sub">Synthetic Telecommands & Telemetry</div>
        </div>
        <div class="kpi-card" style="border-top-color:#05D5AA;">
            <div class="kpi-label">VALIDATED & EXECUTED</div>
            <div class="kpi-value" style="color:#05D5AA;">{accepted_count}</div>
            <div class="kpi-sub">Passed All 4 Security Gates</div>
        </div>
        <div class="kpi-card" style="border-top-color:#FF2A6D;">
            <div class="kpi-label">THREATS & ERRORS BLOCKED</div>
            <div class="kpi-value" style="color:#FF2A6D;">{rejected_count}</div>
            <div class="kpi-sub">Neutralized at Edge Firewall ({block_rate:.1f}%)</div>
        </div>
        <div class="kpi-card" style="border-top-color:#FFB800;">
            <div class="kpi-label">ANTI-REPLAY HIGH WATERMARK</div>
            <div class="kpi-value" style="color:#FFB800;">SEQ #{highest_seq}</div>
            <div class="kpi-sub">TTL Window: ≤ {validator.policy.max_age_seconds:.0f}s | Skew: ±{validator.policy.max_future_skew_seconds:.0f}s</div>
        </div>
        <div class="kpi-card" style="border-top-color:#A855F7;">
            <div class="kpi-label">ACTIVE SECURITY POSTURE</div>
            <div class="kpi-value" style="color:#E9D5FF;">{active_gates_count} / 4 GATES</div>
            <div class="kpi-sub">{'ZERO-TRUST STRICT ENFORCEMENT' if active_gates_count == 4 else 'WARNING: GATES BYPASSED'}</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Interactive Space Segment Architecture Visualizer (Ground -> Link -> Firewall -> Space)
# ---------------------------------------------------------------------------
def render_space_architecture_pipeline(decision: Optional[ValidationDecision], is_intercepted: bool) -> None:
    """Render the visual Ground -> Link -> Validation Firewall -> Orbital Satellite pipeline."""
    if is_intercepted:
        gnd_cls = "arch-node-active-amber"
        lnk_cls = "arch-node-active-amber"
        fw_cls = ""
        sat_cls = ""
        arrow1 = '<span style="color:#FFB800;">━━▶ [INTERCEPTED]</span>'
        arrow2 = '<span style="color:#64748B;">┅┅▷ [PAUSED]</span>'
        arrow3 = '<span style="color:#64748B;">┅┅▷</span>'
        fw_status = "AWAITING LINK FORWARD"
        sat_status = "BUS ISOLATED // SAFE"
    elif decision is None:
        gnd_cls = ""
        lnk_cls = ""
        fw_cls = ""
        sat_cls = ""
        arrow1 = '<span style="color:#64748B;">━━▶</span>'
        arrow2 = '<span style="color:#64748B;">━━▶</span>'
        arrow3 = '<span style="color:#64748B;">━━▶</span>'
        fw_status = "4 GATES ARMED"
        sat_status = "AWAITING COMMAND"
    elif decision.accepted:
        gnd_cls = "arch-node-active-green"
        lnk_cls = "arch-node-active-green"
        fw_cls = "arch-node-active-green"
        sat_cls = "arch-node-active-green"
        arrow1 = '<span style="color:#05D5AA;">━━━▶ RF/KA-BAND</span>'
        arrow2 = '<span style="color:#05D5AA;">━━━▶ VERIFIED</span>'
        arrow3 = '<span style="color:#05D5AA;">━━━▶ BUS EXEC</span>'
        fw_status = "ALL 4 GATES PASSED"
        sat_status = f"EXECUTED: {decision.command_type}"
    else:
        gnd_cls = "arch-node-active-amber"
        lnk_cls = "arch-node-active-red"
        fw_cls = "arch-node-active-red"
        sat_cls = ""
        arrow1 = '<span style="color:#FFB800;">━━━▶ TRANSIT</span>'
        arrow2 = '<span style="color:#FF2A6D;">━━━✖ THREAT</span>'
        arrow3 = '<span style="color:#475569;">╌╌✕ BLOCKED</span>'
        fw_status = f"SHIELD TRIGGERED ({decision.failed_gate})"
        sat_status = "PROTECTED // UNTOUCHED"

    origin_label = decision.segment_origin if decision else "GROUND_SEGMENT"
    target_label = decision.target_asset if decision else "SAT-SENTINEL-01"
    pkt_label = f"{decision.packet_id} // SEQ #{decision.sequence_number}" if decision else "NO ACTIVE PACKET"

    st.markdown(
        f"""
        <div class="pipeline-box">
            <div class="pipeline-title">
                <span>📡 END-TO-END SPACE TELEMETRY & COMMAND VALIDATION PIPELINE</span>
                <span style="color:#94A3B8;">LAST TRACE: {escape(pkt_label)}</span>
            </div>
            <div class="arch-flow">
                <div class="arch-node {gnd_cls}">
                    <div class="arch-node-title">1. ORIGIN SEGMENT</div>
                    <div class="arch-node-meta">{escape(origin_label)}</div>
                    <div class="arch-node-meta" style="color:#00F0FF;">HMAC Sign & Sequence Tag</div>
                </div>
                <div class="arch-arrow">{arrow1}</div>
                <div class="arch-node {lnk_cls}">
                    <div class="arch-node-title">2. LINK SEGMENT</div>
                    <div class="arch-node-meta">RF / Optical Crosslink</div>
                    <div class="arch-node-meta" style="color:#FFB800;">{'⚠️ MITM BUFFER ACTIVE' if is_intercepted else 'Zero-Trust Transit'}</div>
                </div>
                <div class="arch-arrow">{arrow2}</div>
                <div class="arch-node {fw_cls}">
                    <div class="arch-node-title">3. 4-GATE FIREWALL</div>
                    <div class="arch-node-meta">Schema • TTL • HMAC • ACL</div>
                    <div class="arch-node-meta" style="font-weight:700;">{escape(fw_status)}</div>
                </div>
                <div class="arch-arrow">{arrow3}</div>
                <div class="arch-node {sat_cls}">
                    <div class="arch-node-title">4. SPACE SEGMENT</div>
                    <div class="arch-node-meta">{escape(target_label)}</div>
                    <div class="arch-node-meta" style="font-weight:700;">{escape(sat_status)}</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


render_space_architecture_pipeline(last_dec, st.session_state.get("mitm_is_intercepted", False))


# ---------------------------------------------------------------------------
# 4-Gate Step-by-Step Visual Pipeline Inspection
# ---------------------------------------------------------------------------
def render_four_gates_inspection(decision: Optional[ValidationDecision]) -> None:
    """Render the 4 sequential security gates with live status and exact code check triggered."""
    if decision is None or not decision.gate_results:
        return

    cards_html = []
    badge_colors = {
        "PASSED": ("#05D5AA", "✅ PASSED"),
        "FAILED": ("#FF2A6D", "🛑 BLOCKED"),
        "BYPASSED": ("#FFB800", "⚠️ BYPASSED"),
        "SKIPPED": ("#64748B", "⏸️ HALTED"),
    }

    for g in decision.gate_results:
        color, label = badge_colors.get(g.status, ("#94A3B8", g.status))
        cards_html.append(
            dedent(
                f"""
            <div class="gate-card gate-{g.status}">
                <div class="gate-header">
                    <span>{escape(g.gate_name)}</span>
                    <span style="color:{color}; font-family:'JetBrains Mono',monospace; font-size:0.72rem;">{label}</span>
                </div>
                <div class="gate-detail">{escape(g.detail)}</div>
                <div class="gate-code">&gt; {escape(g.code_check)}</div>
            </div>
            """
            ).strip()
        )

    st.markdown(
        f'<div class="gate-grid">{"".join(cards_html)}</div>',
        unsafe_allow_html=True,
    )

    # Compliance banner for the inspected decision
    comp = decision.compliance
    border_col = "#05D5AA" if decision.accepted else "#FF2A6D"
    st.markdown(
        f"""
        <div style="background:rgba(11,18,33,0.9); border:1px solid {border_col}; border-left:4px solid {border_col}; border-radius:5px; padding:0.45rem 0.8rem; margin-bottom:0.85rem; display:flex; justify-content:space-between; flex-wrap:wrap; gap:0.5rem; font-family:'JetBrains Mono',monospace; font-size:0.71rem;">
            <span><strong>DECISION REASON:</strong> {escape(decision.reason)}</span>
            <span style="color:#00F0FF;"><strong>NIST CSF:</strong> {escape(comp.get('nist_csf', ''))} | <strong>OWASP:</strong> {escape(comp.get('owasp', ''))} | <strong>SPARTA:</strong> {escape(comp.get('sparta', ''))}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


render_four_gates_inspection(last_dec)

# Optional Thruster Execution Progress Bar when FIRE_THRUSTER is accepted
if st.session_state.get("thruster_burn_trigger") and last_dec and last_dec.accepted and last_dec.command_type == "FIRE_THRUSTER":
    burn_bar = st.progress(0, text="🚀 EXECUTING VERIFIED ORBITAL THRUSTER DELTA-V BURN...")
    for pct in (25, 55, 85, 100):
        time.sleep(0.05)
        burn_bar.progress(pct, text=f"🚀 ORBITAL THRUSTER BURN COMPLETE ({pct}%) — ATTITUDE NOMINAL")
    st.session_state.thruster_burn_trigger = False


# ---------------------------------------------------------------------------
# Main Interactive Workspace Tabs (Compact, Zero-Clutter Layout)
# ---------------------------------------------------------------------------
tab_sim, tab_analytics, tab_segments, tab_audit = st.tabs(
    [
        "🎯 1. Attack Simulator & MITM Link Interceptor",
        "📈 2. Dynamic Telemetry Graphs & Threat Analytics",
        "🛰️ 3. Covered Space Segments (5 Sites) & Schema",
        "📋 4. Forensic Audit Log, Compliance & Self-Tests",
    ]
)


# ===========================================================================
# TAB 1: Interactive Attack Simulator & Real-Time MITM Interceptor
# ===========================================================================
with tab_sim:
    col_left, col_right = st.columns([1.05, 1.15], gap="medium")

    with col_left:
        st.markdown(
            """
            <div class="tactical-panel">
                <div class="panel-heading">⚡ ONE-CLICK RED-TEAM ATTACK SIMULATOR CONTROLLER</div>
                <div style="font-size:0.78rem; color:#94A3B8; margin-bottom:0.4rem;">
                    Inject synthetic valid commands or adversarial attack vectors directly into the 4-Gate Validation Firewall:
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Row 1: Valid Telecommand Generators
        st.caption("🟢 **NOMINAL AUTHORIZED TELECOMMANDS & TELEMETRY**")
        v_col1, v_col2, v_col3 = st.columns(3)
        with v_col1:
            if st.button("📡 Valid Heartbeat", use_container_width=True):
                seq = st.session_state.next_seq_counter
                pkt = build_valid_packet(
                    packet_id=f"PKT-{1000 + seq}",
                    command_type="PING_HEARTBEAT",
                    operator_role="FLIGHT_DIRECTOR",
                    sequence_number=seq,
                    secret_key=validator.policy.shared_secret_key,
                )
                dec = validator.validate_message(pkt)
                st.session_state.next_seq_counter += 1
                st.session_state.last_decision = dec
                st.session_state.mitm_is_intercepted = False
                st.rerun()
        with v_col2:
            if st.button("🚀 Valid Thruster Burn", use_container_width=True):
                seq = st.session_state.next_seq_counter
                pkt = build_valid_packet(
                    packet_id=f"PKT-{1000 + seq}",
                    command_type="FIRE_THRUSTER",
                    operator_role="FLIGHT_DIRECTOR",
                    sequence_number=seq,
                    parameters={"thrust_pct": 60.0, "burn_duration_ms": 2500, "axis": "PROGRADE"},
                    secret_key=validator.policy.shared_secret_key,
                )
                dec = validator.validate_message(pkt)
                st.session_state.next_seq_counter += 1
                st.session_state.last_decision = dec
                st.session_state.thruster_burn_trigger = True
                st.session_state.mitm_is_intercepted = False
                st.rerun()
        with v_col3:
            if st.button("🛰️ Valid Solar Slew", use_container_width=True):
                seq = st.session_state.next_seq_counter
                pkt = build_valid_packet(
                    packet_id=f"PKT-{1000 + seq}",
                    command_type="ORIENT_SOLAR_ARRAY",
                    operator_role="GNC_SPECIALIST",
                    sequence_number=seq,
                    parameters={"sun_angle_deg": 28.0, "array_wing": "BOTH"},
                    secret_key=validator.policy.shared_secret_key,
                )
                dec = validator.validate_message(pkt)
                st.session_state.next_seq_counter += 1
                st.session_state.last_decision = dec
                st.session_state.mitm_is_intercepted = False
                st.rerun()

        st.caption("🔴 **ADVERSARIAL ATTACK VECTORS (BY TARGET GATE)**")
        a_col1, a_col2 = st.columns(2)
        attack_buttons = [
            ("💥 Gate 1: Corrupted JSON Syntax", "CORRUPTED_JSON", a_col1),
            ("🔥 Gate 1: Thruster Over-Burn (999%)", "OUT_OF_RANGE_THRUST", a_col2),
            ("🧬 Gate 1: Unknown Field Injection", "UNKNOWN_FIELD_INJECTION", a_col1),
            ("⏳ Gate 2: Expired Timestamp (-450s)", "EXPIRED_TIMESTAMP", a_col2),
            ("🔁 Gate 2: Replay Duplicate Sequence", "REPLAY_DUPLICATE_SEQ", a_col1),
            ("🕵️ Gate 3: Spoofed HMAC / MITM Tamper", "SPOOFED_SIGNATURE_MITM", a_col2),
            ("🚫 Gate 4: Unauthorized Role Escalation", "UNAUTHORIZED_ROLE", a_col1),
            ("🌐 Gate 4: User Segment Bus Override", "UNAUTHORIZED_SEGMENT", a_col2),
        ]
        for btn_label, atk_key, target_col in attack_buttons:
            with target_col:
                if st.button(btn_label, key=f"atk_{atk_key}", use_container_width=True):
                    seq = st.session_state.next_seq_counter
                    last_seq = validator.highest_sequence_number or 101
                    payload, desc = build_preset_attack_payload(
                        atk_key,
                        next_seq=seq,
                        last_accepted_seq=last_seq,
                        secret_key=validator.policy.shared_secret_key,
                    )
                    dec = validator.validate_message(payload)
                    if dec.accepted:
                        st.session_state.next_seq_counter += 1
                        if dec.command_type == "FIRE_THRUSTER":
                            st.session_state.thruster_burn_trigger = True
                    st.session_state.last_decision = dec
                    st.session_state.last_action_desc = desc
                    st.session_state.mitm_is_intercepted = False
                    st.rerun()

        # Custom Valid Command Builder to Stage into Link Segment
        st.markdown("---")
        st.caption("🛠️ **STAGE CUSTOM COMMAND INTO LINK SEGMENT (MITM INTERCEPTOR)**")
        b_col1, b_col2, b_col3 = st.columns(3)
        with b_col1:
            sel_cmd = st.selectbox("Command Type", list(COMMAND_SPECIFICATIONS.keys()), index=5)
        with b_col2:
            sel_role = st.selectbox("Operator Role", list(DEFAULT_ROLE_ACL.keys()), index=0)
        with b_col3:
            sel_seg = st.selectbox("Origin Segment", sorted(list(ALLOWED_SEGMENTS)), index=0)

        if st.button("⏸️ Generate & Pause Packet in Link Segment (Intercept)", use_container_width=True):
            seq = st.session_state.next_seq_counter
            staged_pkt = build_valid_packet(
                packet_id=f"PKT-LNK-{seq}",
                segment_origin=sel_seg,
                target_asset="SAT-SENTINEL-01",
                message_class=COMMAND_SPECIFICATIONS[sel_cmd]["message_class"],
                command_type=sel_cmd,
                operator_id=f"OP-{sel_role[:3]}-01",
                operator_role=sel_role,
                sequence_number=seq,
                secret_key=validator.policy.shared_secret_key,
            )
            st.session_state.mitm_buffer_json = json.dumps(staged_pkt, indent=2)
            st.session_state.mitm_is_intercepted = True
            st.rerun()

    with col_right:
        st.markdown(
            """
            <div class="tactical-panel">
                <div class="panel-heading">🕵️ REAL-TIME MIDDLEMAN (MITM) LINK INTERCEPTOR EDITOR</div>
                <div style="font-size:0.78rem; color:#94A3B8;">
                    Act as an adversary in the <strong>Link Segment</strong>: edit the raw JSON payload in transit
                    (e.g., change <code>"thrust_pct": 45.0</code> to <code>999.0</code> or <code>"command_type"</code>)
                    without knowing the pre-shared secret key, then click <strong>Forward Packet to Space Firewall</strong>.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Quick MITM Tamper helper buttons
        t_col1, t_col2, t_col3 = st.columns(3)
        with t_col1:
            if st.button("✏️ Tamper: Thrust -> 95% (Keep Old HMAC)", use_container_width=True):
                try:
                    obj = json.loads(st.session_state.mitm_buffer_json)
                    obj["command_type"] = "FIRE_THRUSTER"
                    obj["parameters"] = {"thrust_pct": 95.0, "burn_duration_ms": 8000, "axis": "RETROGRADE"}
                    st.session_state.mitm_buffer_json = json.dumps(obj, indent=2)
                    st.session_state.mitm_is_intercepted = True
                    st.rerun()
                except Exception:
                    pass
        with t_col2:
            if st.button("🔑 Re-Sign with Valid Ground PSK", use_container_width=True):
                try:
                    obj = json.loads(st.session_state.mitm_buffer_json)
                    obj["timestamp_epoch"] = round(time.time(), 3)
                    signed_obj = sign_packet(obj, secret_key=validator.policy.shared_secret_key)
                    st.session_state.mitm_buffer_json = json.dumps(signed_obj, indent=2)
                    st.rerun()
                except Exception:
                    pass
        with t_col3:
            if st.button("🏴‍☠️ Sign with Rogue Adversary Key", use_container_width=True):
                try:
                    obj = json.loads(st.session_state.mitm_buffer_json)
                    rogue_obj = sign_packet(obj, secret_key="ROGUE-HACKER-KEY-666")
                    st.session_state.mitm_buffer_json = json.dumps(rogue_obj, indent=2)
                    st.session_state.mitm_is_intercepted = True
                    st.rerun()
                except Exception:
                    pass

        edited_raw_json = st.text_area(
            "In-Transit Raw JSON Frame (Link Segment Buffer)",
            value=st.session_state.mitm_buffer_json,
            height=290,
            label_visibility="collapsed",
        )
        st.session_state.mitm_buffer_json = edited_raw_json

        if st.button("🚀 Forward Packet from Link Segment to 4-Gate Space Firewall", type="primary", use_container_width=True):
            dec = validator.validate_message(edited_raw_json)
            if dec.accepted:
                st.session_state.next_seq_counter = max(
                    st.session_state.next_seq_counter,
                    (dec.sequence_number or 0) + 1,
                )
                if dec.command_type == "FIRE_THRUSTER":
                    st.session_state.thruster_burn_trigger = True
            st.session_state.last_decision = dec
            st.session_state.mitm_is_intercepted = False
            st.rerun()


# ===========================================================================
# TAB 2: Dynamic Telemetry Graphing & Threat Analytics
# ===========================================================================
with tab_analytics:
    df_audit = decisions_to_dataframe(validator.audit_log)
    if df_audit.empty:
        st.info("No packets evaluated yet. Use the Attack Simulator or click 'Reset & Re-Seed' in the sidebar.")
    else:
        g_col1, g_col2 = st.columns([1.35, 1.0], gap="medium")

        with g_col1:
            st.markdown(
                """
                <div class="tactical-panel">
                    <div class="panel-heading">📈 LIVE TELECOMMAND SEQUENCE TIMELINE & REPLAY ANOMALY DETECTOR</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            seq_df = df_audit.dropna(subset=["sequence_number"]).copy()
            if not seq_df.empty:
                fig_seq = go.Figure()
                # Line connecting all sequence numbers
                fig_seq.add_trace(
                    go.Scatter(
                        x=seq_df["audit_index"],
                        y=seq_df["sequence_number"],
                        mode="lines",
                        name="Sequence Trajectory",
                        line=dict(color="rgba(0, 240, 255, 0.35)", width=2, dash="dot"),
                    )
                )
                # Accepted points
                acc_df = seq_df[seq_df["decision"] == "ACCEPTED"]
                fig_seq.add_trace(
                    go.Scatter(
                        x=acc_df["audit_index"],
                        y=acc_df["sequence_number"],
                        mode="markers",
                        name="Accepted (Valid Monotonic)",
                        marker=dict(color="#05D5AA", size=11, symbol="circle", line=dict(width=1.5, color="#FFFFFF")),
                        text=acc_df["packet_id"] + " | " + acc_df["command_type"],
                        hovertemplate="<b>%{text}</b><br>Event #%{x}<br>Seq #%{y}<extra>ACCEPTED</extra>",
                    )
                )
                # Replay attacks highlighted with giant red warning markers
                rep_df = seq_df[seq_df["status_code"] == "REPLAY_SEQUENCE_ID"]
                if not rep_df.empty:
                    fig_seq.add_trace(
                        go.Scatter(
                            x=rep_df["audit_index"],
                            y=rep_df["sequence_number"],
                            mode="markers",
                            name="Replay Attack Blocked",
                            marker=dict(color="#FF2A6D", size=16, symbol="x-thin", line=dict(width=3, color="#FF2A6D")),
                            text=rep_df["packet_id"] + " | " + rep_df["reason"],
                            hovertemplate="<b>🚨 REPLAY BLOCKED</b><br>%{text}<br>Duplicate Seq #%{y}<extra></extra>",
                        )
                    )
                # Other rejected packets with sequence numbers
                other_rej = seq_df[(seq_df["decision"] == "REJECTED") & (seq_df["status_code"] != "REPLAY_SEQUENCE_ID")]
                if not other_rej.empty:
                    fig_seq.add_trace(
                        go.Scatter(
                            x=other_rej["audit_index"],
                            y=other_rej["sequence_number"],
                            mode="markers",
                            name="Blocked (Other Gate Failure)",
                            marker=dict(color="#FFB800", size=12, symbol="diamond", line=dict(width=1.5, color="#1E293B")),
                            text=other_rej["packet_id"] + " | " + other_rej["status_code"],
                            hovertemplate="<b>⚠️ BLOCKED</b><br>%{text}<br>Seq #%{y}<extra></extra>",
                        )
                    )

                fig_seq.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="rgba(11,18,33,0.85)",
                    plot_bgcolor="rgba(6,10,18,0.85)",
                    height=310,
                    margin=dict(l=20, r=20, t=25, b=20),
                    xaxis_title="Audit Event Index",
                    yaxis_title="Packet Sequence Number",
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
                )
                st.plotly_chart(fig_seq, use_container_width=True)

        with g_col2:
            st.markdown(
                """
                <div class="tactical-panel">
                    <div class="panel-heading">🛡️ REJECTION REASON & SECURITY GATE BREAKDOWN</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            rej_only = df_audit[df_audit["decision"] == "REJECTED"]
            if rej_only.empty:
                st.success("Zero rejections recorded in current session.")
            else:
                reason_counts = (
                    rej_only.groupby(["status_code", "failed_gate"])
                    .size()
                    .reset_index(name="count")
                    .sort_values("count", ascending=True)
                )
                gate_color_map = {
                    "GATE_1_SCHEMA": "#38BDF8",
                    "GATE_2_TEMPORAL": "#FFB800",
                    "GATE_3_CRYPTO": "#FF2A6D",
                    "GATE_4_ACL": "#A855F7",
                }
                fig_bar = px.bar(
                    reason_counts,
                    x="count",
                    y="status_code",
                    color="failed_gate",
                    orientation="h",
                    color_discrete_map=gate_color_map,
                    text="count",
                )
                fig_bar.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="rgba(11,18,33,0.85)",
                    plot_bgcolor="rgba(6,10,18,0.85)",
                    height=310,
                    margin=dict(l=10, r=15, t=25, b=20),
                    xaxis_title="Blocked Packet Count",
                    yaxis_title="",
                    legend_title_text="Blocking Gate",
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
                )
                st.plotly_chart(fig_bar, use_container_width=True)

        # Second Row: Timestamp Freshness Delta vs MAX_AGE Threshold
        st.markdown(
            """
            <div class="tactical-panel">
                <div class="panel-heading">⏱️ TEMPORAL FRESHNESS DELTA (SECONDS) VS. POLICY MAX_AGE THRESHOLD</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        ts_df = df_audit.dropna(subset=["timestamp_delta_sec"]).copy()
        if not ts_df.empty:
            fig_ts = px.scatter(
                ts_df,
                x="audit_index",
                y="timestamp_delta_sec",
                color="decision",
                symbol="failed_gate",
                color_discrete_map={"ACCEPTED": "#05D5AA", "REJECTED": "#FF2A6D"},
                hover_data=["packet_id", "command_type", "status_code", "reason"],
            )
            fig_ts.add_hline(
                y=validator.policy.max_age_seconds,
                line_dash="dash",
                line_color="#FF2A6D",
                annotation_text=f"MAX_AGE Limit (+{validator.policy.max_age_seconds}s)",
                annotation_position="top left",
            )
            fig_ts.add_hline(
                y=-validator.policy.max_future_skew_seconds,
                line_dash="dot",
                line_color="#FFB800",
                annotation_text=f"Future Skew Limit (-{validator.policy.max_future_skew_seconds}s)",
                annotation_position="bottom left",
            )
            fig_ts.update_traces(marker=dict(size=11))
            fig_ts.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(11,18,33,0.85)",
                plot_bgcolor="rgba(6,10,18,0.85)",
                height=250,
                margin=dict(l=20, r=20, t=20, b=20),
                xaxis_title="Audit Event Index",
                yaxis_title="Packet Age Delta (s)",
            )
            st.plotly_chart(fig_ts, use_container_width=True)


# ===========================================================================
# TAB 3: Covered Space Segments (5 Operational Sites) & Documented Schema
# ===========================================================================
with tab_segments:
    st.markdown(
        """
        <div class="tactical-panel">
            <div class="panel-heading">🛰️ FIVE COVERED SPACE OPERATIONAL SEGMENTS (SPARTA / CISA DEFENSE-IN-DEPTH)</div>
            <div style="font-size:0.78rem; color:#94A3B8;">
                Space security applies across all five operational sites that generate, transit, or consume telemetry and telecommands:
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    seg_cols = st.columns(5)
    for idx, seg in enumerate(COVERED_SEGMENTS):
        allowed_cmds = ", ".join(
            [c for c in COMMAND_SPECIFICATIONS.keys() if c in ["PING_HEARTBEAT", "REQUEST_TELEMETRY", "TELEMETRY_HEARTBEAT"]]
            if seg["id"] != "GROUND_SEGMENT"
            else ["ALL AUTHORIZED TELECOMMANDS"]
        )
        with seg_cols[idx]:
            st.markdown(
                f"""
                <div style="background:rgba(11,18,33,0.95); border:1px solid rgba(0,240,255,0.3); border-top:3px solid #00F0FF; border-radius:6px; padding:0.7rem; height:100%;">
                    <div style="font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#00F0FF;">{seg['code']}</div>
                    <div style="font-family:'Space Grotesk',sans-serif; font-size:0.95rem; font-weight:700; color:#F8FAFC; margin:0.2rem 0;">{seg['name']}</div>
                    <div style="font-size:0.74rem; color:#CBD5E1; margin-bottom:0.45rem; line-height:1.35;">{seg['role']}</div>
                    <div style="font-family:'JetBrains Mono',monospace; font-size:0.66rem; color:#05D5AA; border-top:1px solid rgba(148,163,184,0.2); padding-top:0.35rem;">
                        <strong>Posture:</strong> {seg['security_posture']}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)
    sc_col1, sc_col2 = st.columns([1.05, 1.15], gap="medium")
    with sc_col1:
        st.markdown(
            """
            <div class="tactical-panel">
                <div class="panel-heading">🔐 ROLE-BASED ACCESS CONTROL (ACL) & COMMAND BOUNDS</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        acl_rows = []
        for cmd_name, spec in COMMAND_SPECIFICATIONS.items():
            roles_permitted = [r for r, cmds in validator.policy.role_acl_matrix.items() if cmd_name in cmds]
            acl_rows.append(
                {
                    "Command Type": cmd_name,
                    "Class": spec["message_class"],
                    "Required Parameters": ", ".join(spec["required_params"].keys()),
                    "Authorized Roles": ", ".join(roles_permitted),
                }
            )
        st.dataframe(pd.DataFrame(acl_rows), use_container_width=True, hide_index=True)

    with sc_col2:
        st.markdown(
            """
            <div class="tactical-panel">
                <div class="panel-heading">📜 FORMAL SYNTHETIC TELECOMMAND JSON SCHEMA (DRAFT 2020-12)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.code(json.dumps(get_json_schema_documentation(), indent=2), language="json")


# ===========================================================================
# TAB 4: Forensic Audit Log, Compliance Mapping & Self-Test Suite
# ===========================================================================
with tab_audit:
    f_col1, f_col2, f_col3, f_col4 = st.columns([1.2, 1.2, 1.0, 1.0])
    df_log = decisions_to_dataframe(validator.audit_log)

    with f_col1:
        filter_decision = st.selectbox(
            "Filter by Decision",
            ["ALL DECISIONS", "REJECTED ONLY", "ACCEPTED ONLY"],
        )
    with f_col2:
        status_options = ["ALL STATUS CODES"] + sorted(list(COMPLIANCE_MAPPING.keys()))
        filter_status = st.selectbox("Filter by Status / Threat Type", status_options)
    with f_col3:
        st.download_button(
            "📥 Export Forensic Audit (.JSON)",
            data=export_audit_json(validator.audit_log),
            file_name="orbital_sentinel_forensic_audit.json",
            mime="application/json",
            use_container_width=True,
        )
    with f_col4:
        st.download_button(
            "📊 Export Compliance Log (.CSV)",
            data=export_audit_csv(validator.audit_log),
            file_name="orbital_sentinel_compliance_audit.csv",
            mime="text/csv",
            use_container_width=True,
        )

    filtered_df = df_log.copy()
    if filter_decision == "REJECTED ONLY":
        filtered_df = filtered_df[filtered_df["decision"] == "REJECTED"]
    elif filter_decision == "ACCEPTED ONLY":
        filtered_df = filtered_df[filtered_df["decision"] == "ACCEPTED"]

    if filter_status != "ALL STATUS CODES":
        filtered_df = filtered_df[filtered_df["status_code"] == filter_status]

    st.dataframe(
        filtered_df.iloc[::-1],  # Show newest events at top
        use_container_width=True,
        hide_index=True,
        height=280,
    )

    st.markdown("---")
    st.markdown(
        """
        <div class="tactical-panel">
            <div class="panel-heading">🧪 AUTOMATED SELF-TEST & VERIFICATION SUITE (16 SEEDED SCENARIOS)</div>
            <div style="font-size:0.78rem; color:#94A3B8;">
                Verifies deterministic acceptance of valid multi-segment telecommands and 100% rejection of malformed,
                out-of-range, stale, replayed, MITM-tampered, and unauthorized messages.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    suite_report = run_verification_suite()
    st.success(
        f"✅ Verification Suite Status: **{suite_report['passed_tests']} / {suite_report['total_tests']} Passed ({suite_report['pass_rate_pct']}%)** across all 4 Security Gates."
    )
    st.dataframe(pd.DataFrame(suite_report["details"]), use_container_width=True, hide_index=True)
