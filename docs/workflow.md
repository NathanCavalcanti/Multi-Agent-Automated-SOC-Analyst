## Workflow (v1.0.2)

┌─────────────────┐
│   User Input    │
│      (CLI)      │
└────────┬────────┘
         │ input_text
         ▼
    ┌───────────────┐
    │ LangGraph     │
    │ (SOC State)   │
    └──────┬────────┘
           │
           ▼
    ┌───────────────────────────────────────────┐
    │               Agents Layer                │
    │                                           │
    │  ┌─────────────┐                          │
    │  │  IOC Agent  │ ─► Extract IPs,          │
    │  │             │    domains, hashes,      │
    │  │             │    URLs, emails, paths   │
    │  └──────┬──────┘                          │
    │         │ iocs                            │
    │         ▼                                  │
    │  ┌─────────────┐                          │
    │  │ MITRE Agent │ ─► Map ATT&CK            │
    │  │             │    techniques (Txxxx)    │
    │  │             │    + enrich via          │
    │  │             │    enterprise-attack.json│
    │  └──────┬──────┘                          │
    │         │ ttps                            │
    │         ▼                                  │
    │  ┌─────────────┐                          │
    │  │  CVE Agent  │ ─► Fetch CVEs from       │
    │  │             │    NVD API (real data)   │
    │  └──────┬──────┘                          │
    │         │ cves                            │
    │         ▼                                  │
    │  ┌─────────────────────┐                  │
    │  │ Investigation Agent │ ─► DFIR/SOC plan │
    │  │                     │    (steps,       │
    │  │                     │     containment, │
    │  │                     │     recovery)    │
    │  └──────┬──────────────┘                  │
    │         │ investigation_plan              │
    │         ▼                                  │
    │  ┌───────────────┐                        │
    │  │ Report Agent  │ ─► Build JSON report   │
    │  │               │    + Render TXT report │
    │  └───────────────┘                        │
    └───────────────────────────────────────────┘
                      │
                      ▼
      ┌───────────────────────────────────┐
      │             /output/             │
      │  - incident_report_YYYY-MM-DD_  │
      │      HH-MM-SS.json               │
      │  - incident_report_YYYY-MM-DD_  │
      │      HH-MM-SS.txt                │
      └───────────────────────────────────┘
