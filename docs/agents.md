# 🤖 Agentes del Sistema – SOC Multi-Agent AI Assistant

A continuación se describe cada agente del sistema, su función, entradas y salidas, y las herramientas que utiliza.

---

# 1. Agente 1 – IOC Extractor

## Objetivo
Extraer de forma automática todos los **Indicadores de Compromiso (IOCs)** desde un bloque de texto.

## Entradas
- Logs
- Mensajes de alerta
- Descripciones de incidentes

## Salida (JSON)
```json
{
  "ips": [],
  "domains": [],
  "urls": [],
  "hashes": [],
  "filenames": [],
  "registry_keys": [],
  "commands": []
}
```

## Herramientas utilizadas
- Regex avanzada
- OSINT IOC Extractor (intezer/ioc-extractor)
- Funciones LangChain

---

# 2. Agente 2 – MITRE/TTP Mapper

## Objetivo
Mapear los IOCs a técnicas MITRE ATT&CK.

## Entradas
- IOCs extraídos por el Agente 1

## Salida
Lista priorizada de técnicas:
```json
[
  {"id": "T1059.001", "technique": "PowerShell"},
  {"id": "T1105", "technique": "Ingress Tool Transfer"}
]
```

## Herramientas utilizadas
- Embeddings MITRE ATT&CK
- ChromaDB
- Similarity Search

---

# 3. Agente 3 – CVE & Threat Intelligence Retriever

## Objetivo
Correlacionar IOCs y técnicas MITRE con vulnerabilidades y amenazas conocidas.

## Fuentes
- NVD JSON Feed
- CISA KEV
- MalwareBazaar
- ThreatFox
- PoCs GitHub OSINT

## Salida
```json
[
  {
    "cve": "CVE-2024-21413",
    "score": 9.8,
    "description": "Remote Code Execution..."
  }
]
```

---

# 4. Agente 4 – Investigation Planner

## Objetivo
Construir una metodología DFIR clara junto con queries y pasos recomendados.

## Incluye
- Queries Splunk, KQL, Elastic
- Eventos relevantes (Windows/Sysmon/Linux)
- Timeline sugerido
- Comandos Live Response
- Indicadores de persistencia

---

# 5. Agente 5 – Report Generator

## Objetivo
Transformar todos los resultados anteriores en un **informe profesional**.

### Formatos:
- Markdown
- PDF

### Estructura del informe:
- Resumen ejecutivo
- IOCs
- Mapeo MITRE
- CVEs
- Plan de investigación
- Recomendaciones

