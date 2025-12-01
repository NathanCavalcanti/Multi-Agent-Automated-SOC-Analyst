
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
