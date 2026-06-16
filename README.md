# Project KaVacH: Two-Surface Security Assessment

## 00. Overview & Architecture
Project KaVacH is a comprehensive, multi-surface security evaluation combining network forensics and web application security testing. The engagement is modeled against a real-world infrastructure scenario to identify attack vectors, validate architectural flaws, and build unified, data-backed remediation defenses.

### Client Profile
* **Target Organization:** Meridian FinServe Pvt. Ltd. (Fictional mid-sized Indian NBFC)
* **Operations:** Headquartered in Mumbai with 720 employees across 9 cities serving 180,000 borrowers and 22,000 merchants.
* **Core Infrastructure:** Customer-facing lending/EMI portal, partner onboarding portal, branch office flows, public cloud footprints, and co-located data centers.

### Engagement Triggers
1. **Network Anomaly:** Anomalous east-west and outbound traffic flows detected over a 72-hour window inside a historically quiet server segment.
2. **Coordinated Web Disclosure:** Coordinated bug-bounty reporting indicating high-severity vulnerabilities (SQL Injection and IDOR) exposed on the customer application portals.

---

## 01. Engagement Objectives & Scope
The final success criteria mandates that an independent reader can fully reconstruct what was discovered, trace the logical chain of evidence, and deploy identical fixes within 15 minutes.

### In-Scope Deliverables
* **Workstream A (Network Forensics):** 72-hour packet capture triage, hypothesis execution, confidence-scored Indicator of Compromise (IOC) matrices, and network architecture diffs.
* **Workstream B (Web App Assessment):** Stand up testing environments, demonstrate exploits over a minimum of 5 OWASP Top 10 categories, produce source patches, and review automated SAST report shifts.
* **Workstream C (Synthesis):** Comprehensive cross-surface STRIDE/PASTA threat model and a multi-layered Defense-in-Depth framework mapping back to specific technical findings.

---

## 02. Repository Directory Structure
Every phase of execution adheres strictly to this modular framework to ensure immediate reproducibility:

```text
project-kavach/
├── README.md               # Engagement charter & change log
├── network/                # Workstream A: Forensics & Infrastructure hardened diffs
│   ├── triage-notes.md     # Protocol distribution, top talkers, baseline metrics
│   ├── hypotheses.md       # Competing hypotheses testing & analysis logs
│   ├── iocs.csv            # Structured, confidence-scored indicators
│   ├── architecture/       # Before vs After architecture diagrams (Mermaid format)
│   └── report.md           # Consolidated network assessment report
├── webapp/                 # Workstream B: Vulnerability lab & patch registry
│   ├── env/                # Docker-compose configurations (DVWA + OWASP Juice Shop)
│   ├── findings/           # Modular evidence mapping (Requests, Payloads, Impact)
│   │   ├── F-01-sqli/
│   │   ├── F-02-xss-stored/
│   │   └── F-03-idor/
│   ├── sast/               # Static Application Security Testing JSON logs (Before/After)
│   └── report.md           # Web security flaws analysis and review
├── synthesis/              # Workstream C: Joint models & executive strategy
│   ├── threat-model.md     # Unified cross-surface pivot threat models
│   ├── defense-in-depth.md # 7-layer control proposals (Effort vs Trade-off)
│   └── exec-readout.pdf    # Jargon-free board level presentation 
├── prompts/                # Individual per-member LLM interaction logs
└── retro.md                # Post-mortem cadence (Keep, Stop, Start parameters)
```
---
## 03. Tooling Matrix
**Operating entirely under local hardware constraints using open-source utilities:**

| Security Phase / Category | Tools & Utilities Used | Purpose & Functionality |
| :--- | :--- | :--- |
| **Packet Capture Triage** | Wireshark, `tshark`, Zeek, Suricata | Network packet analysis, session filtering, and traffic baselining. |
| **Vulnerability Target Interfaces** | DVWA, OWASP Juice Shop | Local target replication hosted completely via Docker Desktop. |
| **Interception & Probing** | Burp Suite Community, OWASP ZAP, `curl` | Web request interception, proxy modification, and manual injection testing. |
| **Static Analysis Engines** | Semgrep CE, Bandit, ESLint Security | Automated SAST review to catch hardcoded flaws and insecure code paths. |
| **Modeling & Visualizations** | Mermaid, Draw.io | Generating clear before-vs-after architecture diffs and timeline layouts. |

---

## 04. Unified Project Agile Timeline
**Execution flows across 4 milestones bound to clear system exit parameters:**

* **Iteration 1 (Frame):** Charter freeze, environment replication verified under 15 minutes, target PCAP validation.
* **Iteration 2 (Network):** Tshark session filtering completed, structured IOC list generated, network segment mapping.
* **Iteration 3 (Web):** Full execution of exploit proofs, SAST metrics captures, source code patch remediation branches.
* **Iteration 4 (Synthesize):** Convergence into a single board readout, structural threat dependencies defined, retrospectives held.

---
* **Disclaimer:** Proprietary engagement framework created by Futurense AI Clinic in collaboration with IIT Roorkee × Futurense Technologies.*
