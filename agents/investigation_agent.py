# agents/investigation_agent.py
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from app.config import call_llm, extract_json_block


def run_investigation_agent(
    event_text: Optional[str] = None,
    incident_text: Optional[str] = None,
    iocs: Optional[Dict[str, Any]] = None,
    ttps: Optional[Dict[str, Any]] = None,
    cves: Optional[Dict[str, Any]] = None,
    mitre_context: Optional[Dict[str, Any]] = None,
    cve_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Agente 4: DFIR Planner / Investigation Agent

    Firma flexible para adaptarse a las llamadas desde el grafo:

    - Algunos grafos pasan `event_text=...`
    - Otros pueden pasar `incident_text=...`
    - MITRE puede llegar como `ttps` o como `mitre_context`
    - CVEs pueden llegar como `cves` o como `cve_context`

    Devuelve un dict con un plan de investigación y contención.
    """

    # Unificar nombres de parámetros
    text = incident_text or event_text or ""
    mitre_data: Optional[Dict[str, Any]] = mitre_context or ttps
    cve_data: Optional[Dict[str, Any]] = cve_context or cves

    ioc_snippet = json.dumps(iocs, ensure_ascii=False) if iocs else "{}"
    mitre_snippet = json.dumps(mitre_data, ensure_ascii=False) if mitre_data else "{}"
    cve_snippet = json.dumps(cve_data, ensure_ascii=False) if cve_data else "{}"

    system_prompt = (
        "Eres un analista DFIR senior en un SOC. "
        "A partir de la descripción del incidente/evento, de los IOCs, del mapeo MITRE "
        "y de las vulnerabilidades (CVEs), debes proponer un plan de investigación "
        "y respuesta estructurado, orientado a un L1/L2."
    )

    user_prompt = f"""
Descripción del incidente / evento:
{text}

IOCs extraídos:
{ioc_snippet}

Contexto MITRE (TTPs):
{mitre_snippet}

Contexto CVEs:
{cve_snippet}

Devuelve ÚNICAMENTE un JSON válido con la estructura:

{{
  "investigation_steps": [
    {{
      "step": 1,
      "category": "Recolección de artefactos",
      "description": "Descripción detallada de la acción.",
      "tools": ["Splunk", "EDR", "Volatility"],
      "expected_outcome": "Qué se espera encontrar."
    }}
  ],
  "containment_actions": [
    {{
      "priority": "alta",
      "description": "Acción de contención.",
      "depends_on": [1]
    }}
  ],
  "eradication_and_recovery": [
    "Acción de erradicación 1",
    "Acción de recuperación 1"
  ],
  "notes": "Notas adicionales (por ejemplo, comunicación, reporting, etc.)."
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
