# agents/ioc_agent.py
from __future__ import annotations

import json
from typing import Any, Dict

from app.config import call_llm, extract_json_block


def run_ioc_agent(incident_text: str) -> Dict[str, Any]:
    """
    Agente 1: IOC Extractor
    Extrae IPs, dominios, URLs, hashes, emails, rutas de fichero, etc.
    Devuelve un dict con los IOCs estructurados.
    """

    system_prompt = (
        "Eres un analista SOC especializado en extracción de IOCs. "
        "Tu tarea es leer la descripción de un incidente y extraer indicadores de compromiso "
        "(IPs, dominios, URLs, emails, hashes de malware, rutas de fichero) "
        "en un JSON válido."
    )

    user_prompt = f"""
Texto del incidente:

{incident_text}

Devuelve ÚNICAMENTE un JSON válido con la estructura:

{{
  "ips": ["1.2.3.4", ...],
  "domains": ["example.com", ...],
  "urls": ["http://example.com/malware.exe", ...],
  "emails": ["user@example.com", ...],
  "hashes": {{
    "md5": ["..."],
    "sha1": ["..."],
    "sha256": ["..."]
  }},
  "file_paths": ["C:\\\\Windows\\\\System32\\\\...", "/tmp/malicioso", ...]
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
