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

