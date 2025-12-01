# agents/cve_agent.py
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from app.config import call_llm, extract_json_block
from integrations.nvd_client import search_cves


def _build_cve_keywords_with_llm(
    software_info: str,
    mitre_context: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """
    Usa el LLM para extraer palabras clave de producto/tecnología
    a partir del texto del incidente y del contexto MITRE.

    Ejemplo de salida:
    ["Microsoft Office", "Windows 10", "Microsoft Edge"]
    """

    mitre_snippet = ""
    if mitre_context:
        try:
            mitre_snippet = json.dumps(mitre_context, ensure_ascii=False)
        except TypeError:
            mitre_snippet = str(mitre_context)

    system_prompt = (
        "Eres un analista de vulnerabilidades. "
        "A partir de la descripción de un incidente y del contexto MITRE, "
        "debes extraer nombres de productos/tecnologías relevantes para buscar CVEs en NVD. "
        "No inventes versiones si no están claras; céntrate en producto y fabricante."
    )

    user_prompt = f"""
Texto del incidente / software afectado:
{software_info}

Contexto MITRE (JSON):
{mitre_snippet}

Devuelve ÚNICAMENTE un JSON con esta estructura:

{{
  "keywords": [
    "Producto1",
    "Producto2",
    "Producto3"
  ]
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
        keywords = parsed.get("keywords", [])
        # Normalizar a lista de strings
        return [str(k).strip() for k in keywords if str(k).strip()]
    except json.JSONDecodeError:
        # Fallback mínimo: usar texto bruto como keyword
        return [software_info[:200]]


def run_cve_agent(
    software_info: str,
    mitre_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Agente 3: CVE Retriever (versión realista con NVD)

    1) Usa el LLM para extraer palabras clave de tecnología/producto.
    2) Llama a la API de NVD con esas keywords.
    3) Devuelve CVEs reales (id, cvss, description) y anota la keyword usada.

    La lógica de mapeo con MITRE (related_techniques) se deja opcional,
    porque NVD no devuelve MITRE directamente; se podría derivar si quieres.
    """

    keywords = _build_cve_keywords_with_llm(software_info, mitre_context)

    all_cves: List[Dict[str, Any]] = []
    for kw in keywords:
        try:
            cves = search_cves(kw, max_results=3)
        except Exception as e:
            # No queremos romper el flujo por un fallo de red o rate-limit
            all_cves.append(
                {
                    "id": None,
                    "cvss": None,
                    "description": f"Error al consultar NVD con keyword '{kw}': {e}",
                    "source_keyword": kw,
                    "confidence": "baja",
                }
            )
            continue

        for c in cves:
            c2 = dict(c)
            c2["source_keyword"] = kw
            # Aquí podrías añadir heurística para related_techniques usando mitre_context
            c2["related_techniques"] = []
            c2["confidence"] = "media"
            all_cves.append(c2)

    result: Dict[str, Any] = {
        "cves": all_cves,
        "notes": (
            "CVEs obtenidos de la API oficial de NVD usando keywords extraídas "
            "del incidente. Es necesario revisar manualmente cuáles son realmente relevantes "
            "para el incidente concreto."
        ),
    }

    return result
