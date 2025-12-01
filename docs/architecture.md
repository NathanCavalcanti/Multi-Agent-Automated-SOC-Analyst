# 🏛️ Arquitectura del Sistema – SOC Multi-Agent AI Assistant

Este documento describe la arquitectura interna del sistema, los componentes principales, la comunicación entre módulos y las tecnologías empleadas.

---

# 1. Visión general

El sistema se construye sobre una arquitectura **multi-agente**, donde cada agente es responsable de una tarea separada dentro del pipeline SOC/DFIR.

La orquestación se realiza mediante **LangGraph**, permitiendo un flujo determinista:

```
│ Entrada de datos
│      ↓
├─ Agente 1: IOC Extractor
│      ↓
├─ Agente 2: MITRE Mapper
│      ↓
├─ Agente 3: CVE Retriever
│      ↓
├─ Agente 4: Investigation Planner
│      ↓
└─ Agente 5: Report Writer
```

---

# 2. Componentes principales

## 2.1. Backend Python
Implementado en:
- **LangChain**  
- **LangGraph**  
- **FastAPI**

El backend ejecuta los agentes, carga herramientas OSINT y sirve la API REST.

## 2.2. Vectorstore (ChromaDB)
Se utiliza un almacén de vectores para:
- MITRE ATT&CK Enterprise JSON
- Vulnerabilidades relevantes (CVE)
- Glosarios SOC/DFIR

## 2.3. Modelos OpenAI
El proyecto utiliza modelos avanzados:
- **GPT-5.1 (reasoning profundo)**
- **GPT-4o (procesamiento eficiente y económico)**

---

# 3. Flujo detallado del pipeline

## 3.1. Ingesta
La entrada puede provenir de:
- Logs en texto
- Alertas Suricata/Wazuh
- Entradas manuales desde interfaz

## 3.2. Agente 1 — IOC Extractor
- Limpieza de texto
- Detección de patrones
- Uso de herramientas OSINT (interfaz en Python)
- Normalización STIX-like

## 3.3. Agente 2 — MITRE Mapper
- Transformación de IOCs en embeddings
- Búsqueda vectorial en MITRE ATT&CK
- Selección de técnicas con mayor score

## 3.4. Agente 3 — CVE Retriever
- Búsqueda local en NVD JSON
- Correlación con servicios, puertos, procesos
- Detección de PoCs públicos en GitHub

## 3.5. Agente 4 — Investigation Planner
Genera:
- Queries SPL, KQL y ElasticSearch
- Pasos Live Response
- Hipótesis analítica
- Timeline sugerido

## 3.6. Agente 5 — Report Writer
Salida profesional:
- Markdown
- PDF (WeasyPrint/Pandoc)

---

# 4. API REST

El backend expone:
```
POST /api/process_incident
```

Permite integración futura con:
- n8n
- Wazuh
- Suricata
- SIEMs

Ver `docs/api.md`.

---

# 5. Integración con n8n

La arquitectura está diseñada para admitir Webhooks:
```
Suricata/Wazuh → n8n → LangGraph API → Informe
```

---

# 6. Seguridad

Recomendaciones:
- Validar tamaño de entrada
- No permitir ejecución directa de comandos shell
- Limitar logs sensibles
- Aplicar rate-limiting en API
