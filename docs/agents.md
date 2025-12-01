# 🤖 Agents – SOC Multi-Agent AI Assistant (v1.0)

This document describes each agent’s role and responsibilities.

---

# 1. IOC Agent (agents/ioc_agent.py)

### Model  
`llama-3.3-8b` (Groq)

### Responsibilities  
Extract strictly-structured JSON:

- ips  
- domains  
- urls  
- hashes  
- file_paths  
- registry_keys  
- commands  
- process_names  
- user_agents  

### Output  
Guaranteed JSON block extracted using a sanitizing function.

---

# 2. MITRE Agent (agents/mitre_agent.py)

### Model  
`llama-3.3-70b-versatile`

### Steps  

1. LLM proposes MITRE technique IDs  
2. `integrations/mitre_local_db.py` validates  
   - name  
   - tactic  
   - description  
3. Tags each as:
   - `"Enterprise MITRE"`  
   - `"LLM supposition"`  

### Output  
- Verified mapping  
- Full enrichment  

---

# 3. CVE Agent (agents/cve_agent.py)

### Model  
`llama-3.3-70b-versatile`

### Steps  
1. LLM extracts product keywords  
2. Calls NVD client:  
   - `search_cves(keyword)`  
3. Returns multiple CVEs per keyword:

```
id, cvss, description, source_keyword, confidence
```

100% real data.

---

# 4. Investigation Agent (agents/investigation_agent.py)

### Model  
`mixtral-8x7b`

### Generates  
- Investigation steps  
- Containment  
- Eradication & recovery  
- Analyst notes  

---

# 5. Report Agent (agents/report_agent.py)

### Responsibilities  

Build a full SOC incident report:

- Executive summary  
- Timeline  
- IOC table  
- MITRE mapping  
- CVEs  
- Containment  
- Recommendations  

Persists:

```
incident_report_*.json
incident_report_*.txt
```

---

# Version  

**v1.0**
