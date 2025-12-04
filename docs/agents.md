# 🤖 Agents – Multi-Agent Automated SOC Analyst

This document describes each agent’s role and responsibilities.

---

# 1. IOC Agent (agents/ioc_agent.py)

### Model

`gemini-2.0-flash` (Google Gemini)

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

### Integrations

- **VirusTotal**: Automatically checks extracted hashes (MD5, SHA1, SHA256) against VirusTotal API (if configured) to retrieve detection ratios and threat labels.

### Output

Guaranteed JSON block extracted using a sanitizing function.

---

# 2. MITRE Agent (agents/mitre_agent.py)

### Model

`gemini-2.0-flash` (Google Gemini)

### Steps

1. LLM proposes MITRE technique IDs
2. `integrations/mitre_local_db.py` validates
   - Online → download ATT&CK JSON
   - Offline → fallback to `data/enterprise-attack.json`
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

`gemini-2.0-flash` (Google Gemini)

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

`llama-3.3-70b-versatile` (Groq)

### Generates

- Investigation steps
- Containment
- Eradication & recovery
- Analyst notes

---

# 5. Report Agent (agents/report_agent.py)

### Model

`llama-3.3-70b-versatile` (Groq)

### Responsibilities

Build a full SOC incident report:

- Executive summary
- Timeline
- IOC table
- MITRE mapping
- CVEs
- VirusTotal Analysis
- Containment
- Recommendations

Persists:

```
incident_report_*.json
incident_report_*.txt
```

---
