# 🏛️ Architecture — SOC Multi-Agent AI Assistant (Groq Edition)

This system is built on:

- **LangChain** → Tools + Agents  
- **LangGraph** → Multi-agent orchestration  
- **GroqCloud Llama 3.1** → Main LLM provider  
- **ChromaDB** → Vectorstore for MITRE & CVE  
- **FastAPI** → API interface  

---

# 1. LLM Layer (Groq)

The framework uses Groq’s ultra-fast models:

| Component | Model |
|----------|--------|
| IOC Extraction | llama3-8b-8192 |
| MITRE Mapping | llama3-70b-8192 |
| CVE Intelligence | llama3-70b-8192 |
| DFIR Planning | mixtral-8x7b |
| Report Generation | llama3-70b |

---

# 2. Multi-Agent Pipeline

```
User Input
   ↓
Agent 1 – IOC Extractor (Groq Llama3-8B)
   ↓
Agent 2 – MITRE/TTP Mapper (Groq Llama3-70B)
   ↓
Agent 3 – CVE Retriever (Groq)
   ↓
Agent 4 – DFIR Planner (Mixtral)
   ↓
Agent 5 – Report Writer (Groq Llama3-70B)
```

---

# 3. API Integration

A FastAPI service exposes:

```
POST /api/process_incident
```

---

# 4. External Integrations (Future)

Compatible with:

- n8n  
- Suricata  
- Wazuh  
- Splunk > HTTP Event Collector  
