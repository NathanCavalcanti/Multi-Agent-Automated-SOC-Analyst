# 🤖 Agents — SOC Multi-Agent AI Assistant (Groq Edition)

This project uses Groq LLMs to power each specialized LLM agent.

---

# 1. Agent 1 — IOC Extractor  
**Model:** llama3-8b-8192  
**Purpose:** extract IPs, domains, URLs, hashes, filenames, commands.

---

# 2. Agent 2 — MITRE/TTP Mapper  
**Model:** llama3-70b-8192  
Maps evidence to MITRE ATT&CK techniques using vector embeddings.

---

# 3. Agent 3 — CVE & Intelligence Retriever  
**Model:** llama3-70b  
Pulls relevant CVEs based on:

- IOCs  
- MITRE TTPs  
- OSINT feeds  
- CWE/CPE detection  

---

# 4. Agent 4 — Investigation Planner  
**Model:** mixtral-8x7b  
Generates:

- DFIR workflow  
- Timeline  
- Queries (SPL, KQL, Elastic)  
- Sysmon / Security log correlation  

---

# 5. Agent 5 — Report Writer  
**Model:** llama3-70b  
Creates a structured markdown/PDF security report.
