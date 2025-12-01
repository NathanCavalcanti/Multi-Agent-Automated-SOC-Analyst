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
    Uses the LLM to extract product/technology keywords
    from the incident text and MITRE context.

    Example output:
    ["Microsoft Office", "Windows 10", "Microsoft Edge"]
    """

    mitre_snippet = ""
    if mitre_context:
        try:
            mitre_snippet = json.dumps(mitre_context, ensure_ascii=False)
        except TypeError:
            mitre_snippet = str(mitre_context)

    system_prompt = (
        "You are a vulnerability analyst. "
        "Based on an incident description and MITRE context, "
        "you must extract relevant product/technology names to search for CVEs in NVD. "
        "Do not invent versions if they are not clear; focus on product and vendor."
    )

    user_prompt = f"""
Incident text / affected software:
{software_info}

MITRE Context (JSON):
{mitre_snippet}

Return ONLY a JSON with this structure:

{{
  "keywords": [
    "Product1",
    "Product2",
    "Product3"
  ]
}}
"""

    response = call_llm(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        provider="gemini"  # Gemini for keyword extraction
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
    Agent 3: CVE Retriever (Realistic version with NVD)

    1) Uses LLM to extract technology/product keywords.
    2) Calls NVD API with those keywords.
    3) Returns real CVEs (id, cvss, description) and annotates the used keyword.

    Mapping logic with MITRE (related_techniques) is left optional,
    as NVD does not return MITRE directly; it could be derived if needed.
    """

    keywords = _build_cve_keywords_with_llm(software_info, mitre_context)

    all_cves: List[Dict[str, Any]] = []
    for kw in keywords:
        try:
            cves = search_cves(kw, max_results=3)
        except Exception as e:
            # We don't want to break the flow due to network or rate-limit issues
            all_cves.append(
                {
                    "id": None,
                    "cvss": None,
                    "description": f"Error querying NVD with keyword '{kw}': {e}",
                    "source_keyword": kw,
                    "confidence": "low",
                }
            )
            continue

        for c in cves:
            c2 = dict(c)
            c2["source_keyword"] = kw
            # Here you could add heuristics for related_techniques using mitre_context
            c2["related_techniques"] = []
            c2["confidence"] = "medium"
            all_cves.append(c2)

    result: Dict[str, Any] = {
        "cves": all_cves,
        "notes": (
            "CVEs obtained from official NVD API using keywords extracted "
            "from the incident. Manual review is required to determine relevance "
            "to the specific incident."
        ),
    }

    return result
