# 🌐 API – SOC Multi-Agent AI Assistant

El sistema expone una API REST que permite la integración con plataformas externas como n8n, Wazuh, Suricata o SIEMs.

---

# 1. Endpoint principal

### POST `/api/process_incident`

Procesa un incidente completo usando el pipeline multi-agente.

### Body (JSON)
```json
{
  "logs": "texto con logs o alerta",
  "metadata": {
    "source": "suricata",
    "alert_id": "ET MALWARE EXE Download",
    "timestamp": "2025-01-01T10:00:00Z"
  }
}
```

---

# 2. Respuesta (JSON)

```json
{
  "iocs": {...},
  "mitre": [...],
  "cves": [...],
  "investigation": {...},
  "report_markdown": "contenido del informe"
}
```

---

# 3. Integración con n8n

Ejemplo de flujo:

1. Suricata → Webhook n8n  
2. Webhook n8n → Node "HTTP Request"  
3. Node → POST `/api/process_incident`  
4. n8n recibe:
   - JSON con análisis
   - Informe Markdown  
   - → lo envía a Slack/Teams/Jira

---

# 4. Seguridad

Recomendaciones:
- Validar longitud del texto
- Aplicar límite de peticiones
- Deshabilitar logging sensible
- Aplicar autenticación en producción

