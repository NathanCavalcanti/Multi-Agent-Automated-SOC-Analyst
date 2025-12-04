# 🏛️ Architecture – Multi-Agent Automated SOC Analyst

This document provides the full technical architecture of the system.

---

# 1. Core Architecture

The application is a terminal-based SOC triage system built on:

- **LangGraph** → deterministic multi-agent workflows
- **LangChain** → LLM tool abstraction
- **LangGraph** → deterministic multi-agent workflows
- **LangChain** → LLM tool abstraction
- **Groq Llama 3.3** → Reasoning & Reporting (Analysis)
- **Google Gemini 2.0 Flash** → Data Extraction (IOCs, MITRE, CVEs)
- **Local/offline validated datasets**:
  - MITRE ATT&CK Enterprise
  - Sigma rules
  - NVD CVE retrieval

---

# 2. LangGraph Pipeline

```
[SOCState]
   ↓
ioc_agent
   ↓
mitre_agent
   ↓
cve_agent
   ↓
investigation_agent
   ↓
report_agent
   ↓
END
```

Each node writes to the shared **SOCState**, which holds:

- input_text
- iocs
- ttps (MITRE)
- cves
- investigation_plan
- report
- timestamps

---

# 3. External Integrations

## 3.1 MITRE ATT&CK Loader

Module: `integrations/mitre_local_db.py`

- Downloads `enterprise-attack.json` from GitHub ATT&CK repository.
- If offline, falls back to `data/enterprise-attack.json`.
- Maps:
  - Technique ID → name, tactic, platforms
  - Tactic → TAxxxx
- Marks each TTP as:
  - `"source": "Enterprise MITRE"`
  - `"source": "LLM supposition"`

---

## 3.2 NVD Client (Real CVE Data)

Module: `integrations/nvd_client.py`

Provides:

```
search_cves(keyword, max_results=5)
```

Returns real:

- CVE ID
- CVSS 3.x score
- Description
- Source keyword
- Confidence score

This prevents AI hallucinations.

---

## 3.3 VirusTotal API (Hash Intelligence)

Module: `integrations/virustotal_client.py`

- **Trigger**: Automatically called by `ioc_agent` when hashes are detected.
- **Function**: `get_file_report(hash)`
- **Data Retrieved**:
  - Malicious detection count (e.g., 55/70)
  - Threat label (e.g., "trojan.win32.emotet")
  - Sandbox verdicts
- **Constraint**: Checks top 3 hashes to respect API rate limits.

---

# 4. Output Persistence

Every execution creates:

```
output/incident_report_YYYY-MM-DD_HH-MM-SS.json
output/incident_report_YYYY-MM-DD_HH-MM-SS.txt
```

Stored as immutable analysis evidence.

---

# 5. Execution Flow

1. User starts CLI
2. Pastes incident until `END`
3. The graph runs sequentially
4. Output printed + saved to disk

---
