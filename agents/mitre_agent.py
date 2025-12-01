# agents/mitre_agent.py
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from app.config import call_llm, extract_json_block
from integrations.mitre_local_db import enrich_techniques


def run_mitre_agent(
    incident_text: str,
    iocs: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Agente 2: MITRE/TTP Mapper (versión híbrida LLM + base MITRE oficial)

    Flujo:
    1) El LLM propone una lista de técnicas por ID (Txxxx / Txxxx.xx) + justificación.
    2) Se enriquece cada ID con nombre, táctica y tactic_id usando el dataset oficial
       enterprise-attack.json de MITRE.
    3) Se devuelve un dict:
       {
         "techniques": [...enriquecidas...],
         "summary": "Resumen breve..."
       }
    """

    ioc_snippet = json.dumps(iocs, ensure_ascii=False) if iocs else "{}"

    system_prompt = (
        "Eres un analista de ciberseguridad experto en MITRE ATT&CK. "
        "A partir de la descripción del incidente y de los IOCs, identifica las técnicas "
        "y sub-técnicas más probables (ID Txxxx / Txxxx.xx). "
        "NO inventes IDs; usa solo IDs válidos de MITRE ATT&CK Enterprise. "
        "No des nombres ni tácticas, solo IDs y justificación: el sistema las enriquecerá después."
    )

    user_prompt = f"""
Descripción del incidente:

{incident_text}

IOCs extraídos (JSON):

{ioc_snippet}

Devuelve ÚNICAMENTE un JSON válido con la estructura:

{{
  "techniques": [
    {{
      "id": "T1059.001",
      "justification": "Explica brevemente por qué esta técnica aplica"
    }}
  ],
  "summary": "Resumen en 3-5 líneas del patrón MITRE observado."
}}
"""

    # 1) Llamada al modelo para obtener IDs + justificación
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
        # Respuesta no parseable → devolvemos objeto mínimo de error
        return {
            "parse_error": "El LLM no devolvió JSON válido",
            "raw_response": response,
        }

    raw_techniques = parsed.get("techniques", [])
    summary = parsed.get("summary", "")

    # Normalizar estructura mínima
    norm_techniques = []
    for t in raw_techniques:
        if not isinstance(t, dict):
            continue
        tech_id = t.get("id")
        if not tech_id:
            continue
        norm_techniques.append(
            {
                "id": str(tech_id).strip(),
                "justification": t.get("justification", ""),
            }
        )

    # 2) Enriquecer contra la base MITRE oficial local
    enriched = enrich_techniques(norm_techniques)

    return {
        "techniques": enriched,
        "summary": summary,
    }
