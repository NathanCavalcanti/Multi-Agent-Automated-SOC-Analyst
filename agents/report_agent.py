# agents/report_agent.py
from __future__ import annotations

import json
from typing import Any, Dict, Optional, List

from app.config import call_llm, extract_json_block


def run_report_agent(
    incident_text: str,
    iocs: Optional[Dict[str, Any]] = None,
    mitre_context: Optional[Dict[str, Any]] = None,
    cve_context: Optional[Dict[str, Any]] = None,
    investigation_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Agente 5: Report Agent
    Genera un informe estructurado (en JSON) a partir de:
    - Descripción del incidente
    - IOCs
    - Mapeo MITRE
    - CVEs relevantes
    - Plan de investigación / respuesta
    """

    ioc_snippet = json.dumps(iocs, ensure_ascii=False) if iocs else "{}"
    mitre_snippet = json.dumps(mitre_context, ensure_ascii=False) if mitre_context else "{}"
    cve_snippet = json.dumps(cve_context, ensure_ascii=False) if cve_context else "{}"
    investigation_snippet = (
        json.dumps(investigation_context, ensure_ascii=False)
        if investigation_context
        else "{}"
    )

    system_prompt = (
        "Eres un analista SOC L2 encargado de redactar informes de incidentes. "
        "Debes generar un informe claro, estructurado y accionable para un entorno SOC, "
        "separando una parte ejecutiva (para managers) y una parte técnica (para analistas). "
        "Utiliza un tono profesional y conciso."
    )

    user_prompt = f"""
Descripción original del incidente:
{incident_text}

IOCs (JSON):
{ioc_snippet}

Contexto MITRE (JSON):
{mitre_snippet}

Contexto CVEs (JSON):
{cve_snippet}

Plan de investigación / respuesta (JSON):
{investigation_snippet}

Genera ÚNICAMENTE un JSON válido con la siguiente estructura:

{{
  "metadata": {{
    "title": "Incidente de posible compromiso por malware",
    "severity": "alta",
    "status": "en_investigacion",
    "tlp": "TLP:AMBER",
    "detected_by": "SOC L1 - alerta SIEM",
    "environment": "producción"
  }},
  "executive_summary": "Resumen en 5-8 líneas, orientado a responsables no técnicos.",
  "technical_summary": "Resumen técnico del ataque, vectores, IOCs, MITRE y CVEs.",
  "timeline": [
    {{
      "timestamp": "2025-11-30T08:14:00Z",
      "event": "Primera alerta SIEM por tráfico sospechoso a IP maliciosa."
    }}
  ],
  "ioc_section": {{
    "ips": [],
    "domains": [],
    "urls": [],
    "emails": [],
    "hashes": {{
      "md5": [],
      "sha1": [],
      "sha256": []
    }},
    "file_paths": []
  }},
  "mitre_mapping": [
    {{
      "id": "T1059.001",
      "name": "Command Shell",
      "tactic": "Execution",
      "tactic_id": "TA0002",
      "justification": "Breve explicación de por qué aplica."
    }}
  ],
  "cve_section": [
    {{
      "id": "CVE-XXXX-YYYY",
      "cvss": 9.8,
      "description": "Resumen de la vulnerabilidad.",
      "related_techniques": ["T1059.001"],
      "confidence": "alta"
    }}
  ],
  "investigation_summary": [
    "Lista breve de las acciones de investigación realizadas / planificadas."
  ],
  "containment_and_recovery": {{
    "containment_actions": [
      "Aislar host afectado de la red corporativa."
    ],
    "eradication": [
      "Reinstalar la máquina o limpiar artefactos maliciosos según playbook."
    ],
    "recovery": [
      "Reincorporar sistemas a producción tras validar integridad."
    ]
  }},
  "recommendations": {{
    "short_term": [
      "Acciones inmediatas de mejora."
    ],
    "long_term": [
      "Medidas estratégicas de largo plazo."
    ]
  }}
}}
"""

    response = call_llm(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
    )

    try:
        json_str = extract_json_block(response)
        parsed = json.loads(json_str)
    except json.JSONDecodeError:
        parsed = {
            "parse_error": "El LLM no devolvió JSON válido",
            "raw_response": response,
        }

    return parsed


def render_report_text(report: Dict[str, Any]) -> str:
    """
    Convierte el JSON del informe en un texto plano estructurado,
    listo para copiar en un ticket, documento o correo.
    """

    meta = report.get("metadata", {})
    exec_sum = report.get("executive_summary", "")
    tech_sum = report.get("technical_summary", "")
    timeline = report.get("timeline", [])
    ioc_sec = report.get("ioc_section", {})
    mitre_map = report.get("mitre_mapping", [])
    cve_sec = report.get("cve_section", [])
    inv_sum = report.get("investigation_summary", [])
    cont_rec = report.get("containment_and_recovery", {})
    recs = report.get("recommendations", {})

    lines: List[str] = []

    # Cabecera
    lines.append("=== INCIDENT REPORT ===")
    lines.append("")

    # Metadatos
    lines.append(">> Metadata")
    lines.append(f"  Title      : {meta.get('title', 'N/A')}")
    lines.append(f"  Severity   : {meta.get('severity', 'N/A')}")
    lines.append(f"  Status     : {meta.get('status', 'N/A')}")
    lines.append(f"  TLP        : {meta.get('tlp', 'N/A')}")
    lines.append(f"  Detected by: {meta.get('detected_by', 'N/A')}")
    lines.append(f"  Environment: {meta.get('environment', 'N/A')}")
    lines.append("")

    # Executive summary
    lines.append(">> Executive Summary")
    lines.append(exec_sum or "N/A")
    lines.append("")

    # Technical summary
    lines.append(">> Technical Summary")
    lines.append(tech_sum or "N/A")
    lines.append("")

    # Timeline
    lines.append(">> Timeline")
    if timeline:
        for ev in timeline:
            ts = ev.get("timestamp", "N/A")
            ev_desc = ev.get("event", "N/A")
            lines.append(f"  - [{ts}] {ev_desc}")
    else:
        lines.append("  - N/A")
    lines.append("")

    # IOCs
    lines.append(">> Indicators of Compromise (IOCs)")
    lines.append(f"  IPs      : {', '.join(ioc_sec.get('ips', [])) or 'N/A'}")
    lines.append(f"  Domains  : {', '.join(ioc_sec.get('domains', [])) or 'N/A'}")
    lines.append(f"  URLs     : {', '.join(ioc_sec.get('urls', [])) or 'N/A'}")
    lines.append(f"  Emails   : {', '.join(ioc_sec.get('emails', [])) or 'N/A'}")

    hashes = ioc_sec.get("hashes", {})
    lines.append("  Hashes:")
    lines.append(f"    MD5    : {', '.join(hashes.get('md5', [])) or 'N/A'}")
    lines.append(f"    SHA1   : {', '.join(hashes.get('sha1', [])) or 'N/A'}")
    lines.append(f"    SHA256 : {', '.join(hashes.get('sha256', [])) or 'N/A'}")

    file_paths = ioc_sec.get("file_paths", [])
    lines.append("  File paths:")
    if file_paths:
        for p in file_paths:
            lines.append(f"    - {p}")
    else:
        lines.append("    - N/A")
    lines.append("")

    # MITRE
    lines.append(">> MITRE ATT&CK Mapping")
    if mitre_map:
        for t in mitre_map:
            tech_id = t.get("id", "TXXXX")
            name = t.get("name", "N/A")
            tactic_id = t.get("tactic_id", "TAXXXX")
            tactic_name = t.get("tactic", "N/A")

            source_raw = t.get("source", "")
            if source_raw == "Enterprise MITRE":
                source_label = "Enterprise MITRE"
            elif source_raw == "LLM supposition":
                source_label = "LLM supposition"
            else:
                source_label = source_raw or "Unknown"

            lines.append(
                f"  - {tech_id} ({name}) "
                f"[{tactic_id} - {tactic_name}] "
                f"[Source: {source_label}]"
            )
            lines.append(f"    Justification: {t.get('justification', 'N/A')}")
    else:
        lines.append("  - N/A")
    lines.append("")

    # CVEs
    lines.append(">> Vulnerabilities (CVEs)")
    if cve_sec:
        for c in cve_sec:
            lines.append(
                f"  - {c.get('id', 'CVE-XXXX-YYYY')} "
                f"(CVSS {c.get('cvss', 'N/A')}, confidence: {c.get('confidence', 'N/A')})"
            )
            lines.append(f"    Description       : {c.get('description', 'N/A')}")
            lines.append(
                f"    Related techniques: {', '.join(c.get('related_techniques', [])) or 'N/A'}"
            )
    else:
        lines.append("  - N/A")
    lines.append("")

    # Investigation summary
    lines.append(">> Investigation Summary")
    if inv_sum:
        for item in inv_sum:
            lines.append(f"  - {item}")
    else:
        lines.append("  - N/A")
    lines.append("")

    # Containment & Recovery
    lines.append(">> Containment & Recovery")
    cont_actions = cont_rec.get("containment_actions", [])
    erad = cont_rec.get("eradication", [])
    recv = cont_rec.get("recovery", [])

    lines.append("  Containment Actions:")
    if cont_actions:
        for a in cont_actions:
            lines.append(f"    - {a}")
    else:
        lines.append("    - N/A")

    lines.append("  Eradication:")
    if erad:
        for a in erad:
            lines.append(f"    - {a}")
    else:
        lines.append("    - N/A")

    lines.append("  Recovery:")
    if recv:
        for a in recv:
            lines.append(f"    - {a}")
    else:
        lines.append("    - N/A")
    lines.append("")

    # Recommendations
    lines.append(">> Recommendations")
    short_term = recs.get("short_term", [])
    long_term = recs.get("long_term", [])

    lines.append("  Short-term:")
    if short_term:
        for r in short_term:
            lines.append(f"    - {r}")
    else:
        lines.append("    - N/A")

    lines.append("  Long-term:")
    if long_term:
        for r in long_term:
            lines.append(f"    - {r}")
    else:
        lines.append("    - N/A")

    return "\n".join(lines)
