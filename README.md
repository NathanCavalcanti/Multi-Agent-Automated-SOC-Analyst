# 🛡️ Multi-Agent Automated SOC Analyst - CLI

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![LangGraph](https://img.shields.io/badge/LangGraph-0.1.15+-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-v1.0-success.svg)

A fully functional, terminal-based **Security Operations Center (SOC) Multi-Agent AI Assistant** built with **LangGraph**, **LangChain**, and **IA Agents Free-tier**. This system performs automated security incident triage including IOC extraction, MITRE ATT&CK technique mapping, CVE retrieval, and comprehensive incident reporting.

> 🎓 **Educational & Portfolio Project**: Demonstrates advanced AI agent orchestration, SOC automation workflows, and integration with real security data sources (NVD, MITRE ATT&CK).

---

## ✨ Key Features

- 🔍 **IOC Extraction** - Automatically identifies IPs, domains, URLs, file hashes, emails, file paths, and user accounts
- 🦠 **VirusTotal Integration** - Automated hash analysis with threat intelligence enrichment
- 🎯 **MITRE ATT&CK Mapping** - Maps techniques validated against official Enterprise ATT&CK framework
- 🔐 **Real CVE Intelligence** - Fetches actual vulnerabilities from **NVD API** (no hallucinations)
- 📋 **DFIR Planning** - Generates investigation and containment action plans
- 📊 **SOC-Grade Reports** - Produces structured JSON and human-readable text reports
- 📝 **5W1H Framework** - Complete incident documentation following industry best practices (NIST, SANS, ISO 27035)
- 💾 **Persistent Output** - All reports saved with timestamps under `/output/`
- 🔄 **Multi-Agent Orchestration** - LangGraph pipeline with 5 specialized agents

---

**Agent Pipeline**: `IOC → MITRE → CVE → Investigation → Report → END`

---

## 📋 Prerequisites

- **Python 3.12+**
- **Groq API Key** free tier available at [console.groq.com](https://console.groq.com)
- **Gemini API Key** free tier available at [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
- **NVD API Key** (Optional): For higher rate limits [nvd.nist.gov/developers](https://nvd.nist.gov/developers/request-an-api-key)
- **VirusTotal API Key** (Optional): For hash analysis [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)

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

**Optional (for enhanced features):**

```bash
NVD_API_KEY=your_nvd_api_key_here  # Higher CVE query rate limits
VIRUSTOTAL_API_KEY=your_vt_api_key_here  # Automated hash analysis
```

---

## 💻 Usage

### Run the CLI Assistant

```bash
python app/main.py
```

### Example [Workflow](/docs/workflow.md)

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
  - `output/incident_report_YYYY-MM-DD_HH-MM-SS.txt`
  - `output/incident_report_YYYY-MM-DD_HH-MM-SS.json`

---

## 🛠️ Technology Stack

- **Orchestration**: [LangGraph](https://github.com/langchain-ai/langgraph) (Multi-agent state management)
- **LLM**:
  - **Gemini 2.0 Flash** - Data extraction agents (IOC, MITRE, CVE)
  - **Groq Llama 3.3 70B** - Analysis agents (Investigation, Reports)
- **Data Sources**:
  - [MITRE ATT&CK](https://attack.mitre.org/) Enterprise framework
  - [NVD API 2.0](https://nvd.nist.gov/developers) for CVE data
  - [VirusTotal API v3](https://developers.virustotal.com/reference/overview) for hash intelligence
- **Framework**: Python 3.12+ with Pydantic, LangChain

---

## 🔗 Resources

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [LangGraph Documentation](https://langchain-ai.github.io/langgraph/)

---

## 📄 License

This project is licensed under the MIT License - feel free to use it for learning and portfolio purposes.

---

**Version**: 1.1.0 | **Status**: Production-ready for portfolio demonstration
