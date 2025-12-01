# 🛡️ SOC Multi-Agent AI Assistant

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![LangGraph](https://img.shields.io/badge/LangGraph-0.1.15+-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-v1.0-success.svg)

A fully functional, terminal-based **Security Operations Center (SOC) Multi-Agent AI Assistant** built with **LangGraph**, **LangChain**, and **Groq Llama 3.3**. This system performs automated security incident triage including IOC extraction, MITRE ATT&CK technique mapping, CVE retrieval, and comprehensive incident reporting.

> 🎓 **Educational & Portfolio Project**: Demonstrates advanced AI agent orchestration, SOC automation workflows, and integration with real security data sources (NVD, MITRE ATT&CK).

---

## ✨ Key Features

- 🔍 **IOC Extraction** - Automatically identifies IPs, domains, URLs, file hashes, emails, and file paths
- 🎯 **MITRE ATT&CK Mapping** - Maps techniques validated against official Enterprise ATT&CK framework
- 🔐 **Real CVE Intelligence** - Fetches actual vulnerabilities from **NVD API** (no hallucinations)
- 📋 **DFIR Planning** - Generates investigation and containment action plans
- 📊 **SOC-Grade Reports** - Produces structured JSON and human-readable text reports
- 💾 **Persistent Output** - All reports saved with timestamps under `/output/`
- 🔄 **Multi-Agent Orchestration** - LangGraph pipeline with 5 specialized agents

---

## 🏗️ Architecture

```
┌─────────────────┐
│  User Input     │
│  (CLI)          │
└────────┬────────┘
         │
         ▼
    ┌────────┐
    │  Graph │
    └────┬───┘
         │
    ┌────▼──────────────────────────────────┐
    │                                       │
    │  ┌─────────────┐                     │
    │  │ IOC Agent   │ ► Extract IPs,      │
    │  └──────┬──────┘   domains, hashes   │
    │         │                             │
    │  ┌──────▼──────┐                     │
    │  │ MITRE Agent │ ► Map techniques    │
    │  └──────┬──────┘   (validated)       │
    │         │                             │
    │  ┌──────▼──────┐                     │
    │  │  CVE Agent  │ ► Fetch CVEs        │
    │  └──────┬──────┘   from NVD API      │
    │         │                             │
    │  ┌──────▼───────────┐                │
    │  │ Investigation    │ ► DFIR Plan    │
    │  │ Agent            │                │
    │  └──────┬───────────┘                │
    │         │                             │
    │  ┌──────▼──────┐                     │
    │  │ Report Agent│ ► Generate JSON/TXT │
    │  └──────┬──────┘                     │
    └─────────┼─────────────────────────────┘
              │
              ▼
      ┌─────────────────────────┐
      │ /output/                │
      │ - report_timestamp.json │
      │ - report_timestamp.txt  │
      └─────────────────────────┘
```

**Agent Pipeline**: `IOC → MITRE → CVE → Investigation → Report → END`

---

## 📋 Prerequisites

- **Python 3.10+**
- **Groq API Key** (free tier available at [console.groq.com](https://console.groq.com))
- **Gemini API Key** (free tier available at [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey))
- **Optional**: NVD API Key for higher rate limits ([nvd.nist.gov/developers](https://nvd.nist.gov/developers/request-an-api-key))

---

## 🚀 Installation

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/soc-multiagent-assistant
cd soc-multiagent-assistant
```

### 2. Create Virtual Environment

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux/Mac
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

```bash
# Copy template
copy .env.example .env   # Windows
# cp .env.example .env   # Linux/Mac

# Edit .env and add your GROQ_API_KEY
```

**Required in `.env`:**
```bash
GROQ_API_KEY=your_groq_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here
```

---

## 💻 Usage

### Run the CLI Assistant

```bash
python app/main.py
```

### Example Workflow

1. **Paste incident data** (logs, alerts, event descriptions)
2. **Type `END`** to signal completion
3. **Wait for analysis** (multi-agent pipeline executes)
4. **Review output** in console + `/output/` directory

**Example Input:**
```
Suspicious PowerShell execution detected:
powershell -enc KABDA...
Source IP: 192.168.1.100
Target: malicious-domain.com
END
```

**Output:**
- Console: Structured SOC incident report
- Files: 
  - `output/incident_report_2024-12-01_19-30-45.txt`
  - `output/incident_report_2024-12-01_19-30-45.json`

---

## 📁 Project Structure

```
soc-multiagent-assistant/
├── agents/                    # Specialized SOC agents
│   ├── ioc_agent.py          # IOC extraction
│   ├── mitre_agent.py        # MITRE ATT&CK mapping
│   ├── cve_agent.py          # CVE intelligence
│   ├── investigation_agent.py # DFIR planning
│   └── report_agent.py       # Report generation
├── app/
│   ├── config.py             # LLM configuration
│   ├── main.py               # CLI entry point
│   └── api.py                # FastAPI server (optional)
├── graph/
│   ├── graph_builder.py      # LangGraph pipeline
│   └── state.py              # Shared state management
├── integrations/
│   ├── mitre_local_db.py     # MITRE ATT&CK data handler
│   └── nvd_client.py         # NVD API client
├── data/                      # MITRE ATT&CK dataset (auto-downloaded)
├── output/                    # Generated reports
├── .env.example               # Environment template
└── requirements.txt
```

---

## 🛠️ Technology Stack

- **Orchestration**: [LangGraph](https://github.com/langchain-ai/langgraph) (Multi-agent state management)
- **LLM**: 
  - **Gemini 1.5 Flash** - Data extraction agents (IOC, MITRE, CVE)
  - **Groq Llama 3.3 70B** - Analysis agents (Investigation, Reports)
- **Data Sources**: 
  - [MITRE ATT&CK](https://attack.mitre.org/) Enterprise framework
  - [NVD API 2.0](https://nvd.nist.gov/developers) for CVE data
- **Framework**: Python 3.10+ with Pydantic, LangChain

---

## 📄 License

This project is licensed under the MIT License - feel free to use it for learning and portfolio purposes.

---

## 🙏 Acknowledgments

- **MITRE Corporation** - ATT&CK Framework
- **NIST** - National Vulnerability Database
- **Groq** - Fast LLM inference

---

## 🔗 Resources

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [LangGraph Documentation](https://langchain-ai.github.io/langgraph/)

---

**Version**: 1.0 | **Status**: Production-ready for portfolio demonstration
