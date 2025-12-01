# 🌐 API — SOC Multi-Agent Assistant (Groq Edition)

## Endpoint

### POST `/api/process_incident`

Executes the full LangGraph multi-agent pipeline using Groq LLMs.

---

## Request Example

```json
{
  "logs": "Suspicious PowerShell execution detected...",
  "metadata": {
    "source": "suricata",
    "timestamp": "2025-01-01T12:00:00Z"
  }
}
```

---

## Response

```json
{
  "iocs": {...},
  "mitre": [...],
  "cves": [...],
  "investigation": {...},
  "report_markdown": "..."
}
```

---

## Environment Variables

```
GROQ_API_KEY=your_key
LLM_MODEL=llama-3.3-70b-versatile
```

---

## Notes

Optimized for n8n, Wazuh, Suricata, and SIEM integrations.
