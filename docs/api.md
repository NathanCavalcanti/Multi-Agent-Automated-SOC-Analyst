# 🌐 API – SOC Multi-Agent AI Assistant (v1.0)

The system is CLI-first, but provides a FastAPI module for future expansion.

---

# 1. Main endpoint (future)

POST `/api/process_incident`

### Body  
```
{
  "incident_text": "...",
  "source": "wazuh|suricata|manual"
}
```

### Response  
```
{
  "report": { ... full JSON ... }
}
```

---

# 2. Current Status  

API is prepared but not yet exposed in v1.0.  
CLI is the default interface.

