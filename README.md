# 🛰️ SOC Multi-Agent AI Assistant  
Sistema multi-agente basado en LLMs para automatizar análisis SOC/DFIR, extracción de IOCs, mapeo MITRE ATT&CK, correlación de CVEs, planificación de investigación y generación de reportes profesionales.

Este proyecto implementa una arquitectura modular con **LangChain**, **LangGraph** y modelos **OpenAI GPT-5.1 / GPT-4o**, preparado para integrarse con plataformas de automatización como **n8n**, y para ingestión de alertas desde **Suricata**, **Wazuh**, **Zeek**, SIEMs y herramientas de seguridad.

---

# 📂 Índice

- [1. Objetivo del proyecto](#1-objetivo-del-proyecto)
- [2. Arquitectura general](#2-arquitectura-general)
- [3. Flujo funcional multi-agente](#3-flujo-funcional-multi-agente)
- [4. Stack tecnológico](#4-stack-tecnológico)
- [5. Estructura del repositorio](#5-estructura-del-repositorio)
- [6. Descripción de los agentes](#6-descripción-de-los-agentes)
- [7. Integración futura con n8n](#7-integración-futura-con-n8n)
- [8. Instalación](#8-instalación)
- [9. Uso](#9-uso)
- [10. Roadmap](#10-roadmap)
- [11. Licencia](#11-licencia)

---

# 1. Objetivo del proyecto

El objetivo de este sistema es automatizar tareas críticas de un **Security Operations Center (SOC)** y un equipo **DFIR**, permitiendo:

- Extracción inteligente de **IOCs**
- Identificación de tácticas y técnicas MITRE ATT&CK
- Correlación con vulnerabilidades **CVE**
- Planificación de investigación estructurada
- Generación de informes formales en Markdown/PDF
- Preparación para ingestión automatizada desde IDS/IPS/SIEM

---

# 2. Arquitectura general

```
User Input (logs, eventos, alertas)
            ↓
     [Agente 1: IOC Extractor]
            ↓
   [Agente 2: MITRE/TTP Mapper]
            ↓
[Agente 3: CVE & Threat Intelligence]
            ↓
 [Agente 4: Investigation Planner]
            ↓
   [Agente 5: Report Generator]
            ↓
  Output: JSON + Reporte final
```

Todo el flujo es orquestado mediante **LangGraph**, garantizando un pipeline determinista, reproducible y modular.

---

# 3. Flujo funcional multi-agente

1. **Entrada (logs/alertas)**
2. El grafo activa el **Agente 1** para extraer IOCs.
3. El **Agente 2** realiza búsqueda vectorial en el dataset MITRE ATT&CK.
4. El **Agente 3** correlaciona CVEs relevantes usando OSINT.
5. El **Agente 4** crea un plan DFIR profesional.
6. El **Agente 5** genera el reporte final.

---

# 4. Stack tecnológico

| Tecnología | Uso |
|-----------|-----|
| LangChain | agentes, herramientas y prompts |
| LangGraph | orquestación determinista multi-agente |
| OpenAI GPT-5.1 / GPT-4o | LLM principal |
| ChromaDB | vectorstore MITRE + CVE |
| FastAPI | API REST |
| Python 3.11 | backend |
| SigmaHQ | reglas Sigma |
| MITRE CTI JSON | dataset ATT&CK |

---

# 5. Estructura del repositorio

```
/soc-multiagent-assistant
│
├── README.md
├── requirements.txt
│
├── app/
│   ├── api.py
│   ├── frontend/
│   └── main.py
│
├── graph/
│   ├── graph_builder.py
│   └── state.py
│
├── agents/
│   ├── ioc_agent.py
│   ├── mitre_agent.py
│   ├── cve_agent.py
│   ├── investigation_agent.py
│   └── report_agent.py
│
├── tools/
│   ├── ioc_extractor.py
│   ├── mitre_loader.py
│   ├── cve_search.py
│   ├── osint_tools.py
│   └── sigma_loader.py
│
├── data/
│   ├── mitre_enterprise.json
│   ├── nvdcve.json
│   └── sigma/
│
└── docs/
    ├── architecture.md
    ├── agents.md
    ├── api.md
    └── roadmap.md
```

---

# 6. Descripción de los agentes

Breve resumen (ver `docs/agents.md` para versión completa):

- **Agente 1 — IOC Extractor:** extrae hashes, IPs, URLs, procesos, rutas, UA.
- **Agente 2 — MITRE/TTP Mapper:** correlación ATT&CK vía embeddings.
- **Agente 3 — CVE Retriever:** NVD, KEV, MalwareBazaar, PoC GitHub.
- **Agente 4 — Investigation Planner:** queries DFIR, timeline, técnicas.
- **Agente 5 — Report Writer:** informe final profesional en Markdown/PDF.

---

# 7. Integración futura con n8n

El proyecto está preparado mediante:
- API REST estándar (`/api/process_incident`)
- Objeto incidente normalizado
- Respuesta en JSON compatible con automatización

Permite:

- Suricata/Wazuh → Webhook n8n → LangGraph API
- Generación automática de informes
- Envío a Slack, Teams, Jira, etc.

---

# 8. Instalación

```bash
git clone https://github.com/tuusuario/soc-multiagent-assistant
cd soc-multiagent-assistant
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Añadir clave de OpenAI:

```bash
export OPENAI_API_KEY="tu_clave"
```

---

# 9. Uso

### CLI
```bash
python app/main.py --input logs.txt
```

### API
```bash
uvicorn app.api:app --host 0.0.0.0 --port 8000
```

---

# 10. Roadmap

Consultar `docs/roadmap.md`.

---

# 11. Licencia
MIT License.
