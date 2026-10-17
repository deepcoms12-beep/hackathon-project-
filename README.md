# 🛰️ ORBITAL SENTINEL — Secure Telemetry & Command Validation Simulator

**Project:** Cybersecurity 2 — Secure Telemetry/Command Validation Simulator  
**Operational Mode:** 100% Local Synthetic Simulation (No live satellite or operational command channel)

---

## 1. Overview & Architecture

Systems that exchange spacecraft telemetry or telecommands must enforce zero-trust defensive validation before any command reaches the flight computer or spacecraft bus. **ORBITAL SENTINEL** simulates end-to-end defensive validation across all **five covered space operational segments** ([SPARTA](https://sparta.aerospace.org/related-work/did-space) / [CISA Space Systems](https://www.cisa.gov/topics/risk-management/space-systems)):

| Segment Code | Operational Site | Role & Security Boundary |
| :--- | :--- | :--- |
| `SEG-01 // GND` | **Ground Segment** | Mission control centers & ground stations that sign and transmit telecommands. |
| `SEG-02 // LNK` | **Link Segment** | Bi-directional RF / optical crosslinks exposed to jamming, replay, and MITM tampering. |
| `SEG-03 // SPC` | **Space Segment** | Orbital assets (`SAT-SENTINEL-01`, `SAT-RECON-04`, `ISS-COLUMBUS-NODE`) protected by the 4-Gate Firewall. |
| `SEG-04 // USR` | **User Segment** | End-user downlink terminals; strictly blocked from uplinking orbital bus commands. |
| `SEG-05 // LNC` | **Launch Segment** | Launch site & vehicle telemetry interfaces restricted to pre-deployment handshakes. |

---

## 2. 4-Gate Defense-in-Depth Validation Pipeline

Every incoming JSON message is evaluated sequentially through four security gates in [`src/validator.py`](src/validator.py):

1. **Gate 1 — Structural & Range Validation (`GATE_1_SCHEMA`)**
   - Verifies JSON syntax, all 12 required header fields, strict data types (preventing boolean-to-integer confusion), unknown field injection blocking, and command-specific numerical safety limits (e.g., `thrust_pct` $\in [1.0, 100.0]$, `burn_duration_ms` $\in [50, 15000]$).
2. **Gate 2 — Temporal & Anti-Replay Verification (`GATE_2_TEMPORAL`)**
   - Verifies packet freshness ($\Delta t \le \text{MAX\_AGE\_SECONDS}$, default `30.0s`), blocks future clock-skew spoofing ($\le 5.0\text{s}$), and enforces strictly monotonic sequence numbers (`sequence_number`) to neutralize replay attacks.
3. **Gate 3 — Cryptographic Authentication (`GATE_3_CRYPTO`)**
   - Computes canonical UTF-8 JSON serialization (`sort_keys=True`) and verifies the `hmac_sha256` signature using Python's standard library `hmac.new(..., hashlib.sha256)` and constant-time `hmac.compare_digest` in [`src/crypto_auth.py`](src/crypto_auth.py). No custom cryptography is invented.
4. **Gate 4 — Role-Based Authorization & Segment Isolation (`GATE_4_ACL`)**
   - Cross-references `operator_role` (`FLIGHT_DIRECTOR`, `GNC_SPECIALIST`, `PAYLOAD_ENGINEER`, `TELEMETRY_OBSERVER`, `SECURITY_ADMIN`) and `segment_origin` against the command Access Control List (ACL).

---

## 3. Interactive Web Dashboard Features (`app.py`)

- **Space Segment Architecture Visualizer:** Live visual pipeline (`[Origin Segment] ➔ [Link Segment] ➔ [4-Gate Firewall] ➔ [Orbital Satellite]`) with dynamic green execution pulses and red threat-shield blocks.
- **4-Gate Step-by-Step Inspector:** Lights up each security gate green (`PASSED`), red (`BLOCKED`), or amber (`BYPASSED`) and displays the exact Python validation check that caught the threat.
- **One-Click Red-Team Attack Simulator:** Instant injection buttons for Corrupted JSON, Thruster Over-Burn (999%), Unknown Field Injection, Expired Timestamp, Duplicate Sequence Replay, MITM Signature Tampering, Role Privilege Escalation, and User-Segment Lateral Injection.
- **Real-Time Middleman (MITM) Link Interceptor:** Pause valid packets in the Link Segment, tamper with the raw JSON payload in transit without knowing the secret key, and forward to watch Gate 3 (`HMAC-SHA256`) catch the modification.
- **Live Sidebar Policy Editor:** Adjust `MAX_AGE_SECONDS`, `Max Safe Thruster Limit (%)`, or toggle individual gates off/on to demonstrate how attacks compromise the satellite when defenses are lowered and get blocked when re-enabled.
- **Dynamic Plotly Telemetry Graphs & Exportable Forensic Audit Log:** Sequence number timeline with replay anomaly markers, gate breakdown bar charts, and one-click `.JSON` / `.CSV` exports mapped to **NIST CSF 2.0**, **OWASP ASVS**, and **SPARTA** controls.

---

## 4. Quick Start & Running Tests

```powershell
# Create and activate a project-local virtual environment (first run only)
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

# Run the interactive Streamlit dashboard from the project root
python -m streamlit run app.py

# Optional: run the CLI dashboard and automated tests
python cli_simulator.py
python -m pytest -v
```
