# 🛰️ SOC Multi-Agent AI Assistant – Version 1.0  
A fully functional, terminal-based multi-agent SOC assistant built using **LangGraph**, **LangChain**, and **Groq Llama 3.3**.  
The system performs automated triage of security incidents, including:

- IOC extraction  
- MITRE ATT&CK technique mapping (validated against Enterprise ATT&CK)  
- Real CVE retrieval using the **NVD API** (no hallucinations)  
- Investigation/containment planning  
- Full SOC-grade incident report generation (JSON + text)  
- Output persistence under `/output/`  

This application is designed as an educational and portfolio-ready SOC Automation framework.

---

# 🚀 Features (v1.0)

### ✔️ **Terminal-driven (CLI) workflow**
The app prompts the analyst to paste incident data and signal completion with the keyword:

```
END
```

The system then executes the **entire LangGraph** pipeline and prints:

- A console-rendered SOC incident report  
- Paths to generated files in `/output/`  
  - `incident_report_YYYY-MM-DD_HH-MM-SS.txt`  
  - `incident_report_YYYY-MM-DD_HH-MM-SS.json`  

---

# 🔗 Multi-Agent Pipeline

The LangGraph orchestrates the following agents:

```
ioc_agent
→ mitre_agent
→ cve_agent
→ investigation_agent
→ report_agent
→ END
```

Each agent updates the global **SOCState** object.

---

# 🤖 Agent Overview

### **Agent 1 — IOC Extractor**
- Powered by Llama 3.3 (Groq)
- Extracts strict JSON:
  - ips, domains, urls, hashes  
  - file_paths, registry_keys, user_agents  
  - process names, suspicious commands  

### **Agent 2 — MITRE/TTP Mapper**
- LLM proposes technique IDs (Txxxx / Txxxx.xx)  
- Enriched with MITRE ATT&CK Enterprise:
  - Name, tactic, platforms
  - Validated or marked as “LLM supposition”
- Uses:
  - `integrations/mitre_local_db.py`  
  - Online → download ATT&CK JSON  
  - Offline → fallback to `data/enterprise-attack.json`  

### **Agent 3 — CVE Agent**
- Uses LLM only to extract technology keywords  
- Queries **NVD API** via `integrations/nvd_client.py`
- Never invents CVEs  
- Returns real:
  - CVE ID  
  - CVSS v3.x  
  - Official NVD description  
  - Source keyword  
  - Confidence score  

### **Agent 4 — Investigation Agent**
Produces structured DFIR content:
- Investigation steps  
- Containment actions  
- Eradication & recovery  
- Notes  

### **Agent 5 — Report Agent**
Generates complete SOC-grade report:
- Executive summary  
- Technical summary  
- MITRE mapping  
- Verified CVEs  
- Timeline  
- IOC table  
- Investigation & containment  
- Recommendations  

Persists:
- JSON (machine-readable)
- TXT (human SOC analyst readable)

---

# 🧠 LLM Provider — Groq

The entire system uses **free real-time inference** via:

- `llama-3.3-70b-versatile` (default)  
- `llama-3.3-8b` (fast extraction tasks)

Environment:

```
GROQ_API_KEY=your_key
LLM_MODEL=llama-3.3-70b-versatile
```

---

# 📁 Repository structure

```
/soc-multiagent-assistant
│
├── README.md
├── requirements.txt
│
├── app/
│   ├── main.py          # CLI entrypoint
│   ├── config.py        # Groq LLM handler
│   └── frontend/        # (future Web UI)
│
├── agents/
│   ├── ioc_agent.py
│   ├── mitre_agent.py
│   ├── cve_agent.py
│   ├── investigation_agent.py
│   └── report_agent.py
│
├── integrations/
│   ├── mitre_local_db.py    # ATT&CK loader + validation
│   └── nvd_client.py        # NVD API client
│
├── graph/
│   ├── graph_builder.py
│   └── state.py
│
├── tools/
│   ├── ioc_extractor.py
│   ├── sigma_loader.py
│   └── osint_utils.py
│
├── data/
│   ├── enterprise-attack.json
│   └── sigma/
│
├── output/
│   └── incident_report_*.json/.txt
│
└── docs/
    ├── architecture.md
    ├── agents.md
    ├── api.md
    └── roadmap.md
```

---

# 🛠 Usage

Run the CLI:

```
python app/main.py
```

Paste logs or alert:

```
Suspicious PowerShell execution detected:
powershell -enc KABDA...
END
```

Output:

- Full structured SOC report  
- Path to JSON + TXT under `/output/`

---

# 🔥 Version  
**Current release: v1.0**

