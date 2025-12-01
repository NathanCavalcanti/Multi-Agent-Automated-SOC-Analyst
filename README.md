# 🛰️ SOC Multi-Agent AI Assistant  
Multi-agent SOC/DFIR automation system built with LangChain, LangGraph, and **Groq Llama 3.1 models (free, ultra-fast LLM inference)**.

This project automates:
- IOC extraction  
- MITRE ATT&CK mapping  
- CVE correlation using OSINT feeds  
- DFIR investigation planning  
- Professional incident report generation  

The system uses **GroqCloud API** to run Llama 3.1 for free while maintaining high performance.

---

## 🚀 LLM Provider

This project uses **Groq** instead of OpenAI.

### Models used (Groq):
- `llama3-70b-8192` → Reasoning + Agents  
- `llama3-8b-8192` → Fast low-cost extraction  
- `mixtral-8x7b-32768` (optional) → Structured DFIR output

You must export your Groq API key:

```
set GROQ_API_KEY=your_key_here
```

---

## 📦 Installation

```
pip install langchain langgraph groq fastapi uvicorn chromadb python-dotenv
```

---

## 🔧 Configuration

Create `.env`:

```
GROQ_API_KEY=your_key_here
LLM_MODEL=llama3-70b-8192
```

---

## 📁 Repository Structure

(same structure as before)

---

## 🤖 Agents (Groq-powered)

- Agent 1: IOC Extractor → llama3-8b  
- Agent 2: MITRE Mapper → llama3-70b  
- Agent 3: CVE Retriever → llama3-70b  
- Agent 4: DFIR Planner → mixtral-8x7b  
- Agent 5: Report Writer → llama3-70b

---

## 🌐 API

POST `/api/process_incident` → runs entire LangGraph multi-agent pipeline using Groq LLMs.

---

## ⚡ Why Groq?

- Free tier (no credits)
- Ultra-low latency (<40 ms)
- State-of-the-art Llama 3.1 models
- Stable inference for multi-agent workflows
