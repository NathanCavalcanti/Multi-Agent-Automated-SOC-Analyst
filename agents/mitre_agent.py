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
    Agent 2: MITRE/TTP Mapper (Hybrid version: LLM + Official MITRE DB)

    Flow:
    1) LLM proposes a list of techniques by ID (Txxxx / Txxxx.xx) + justification.
    2) Each ID is enriched with name, tactic, and tactic_id using the official
       MITRE enterprise-attack.json dataset.
    3) Returns a dict:
       {
         "techniques": [...enriched...],
         "summary": "Brief summary..."
       }
    """

    ioc_snippet = json.dumps(iocs, ensure_ascii=False) if iocs else "{}"

    system_prompt = (
        "You are a cybersecurity analyst expert in MITRE ATT&CK. "
        "Based on the incident description and IOCs, identify the most probable techniques "
        "and sub-techniques (ID Txxxx / Txxxx.xx). "
        "Do NOT invent IDs; use only valid MITRE ATT&CK Enterprise IDs. "
        "Do not provide names or tactics, only IDs and justification: the system will enrich them later."
    )

    user_prompt = f"""
Incident description:

{incident_text}

Extracted IOCs (JSON):

{ioc_snippet}

Return ONLY a valid JSON with the following structure:

{{
  "techniques": [
    {{
      "id": "T1059.001",
      "justification": "Briefly explain why this technique applies"
    }}
  ],
  "summary": "Summary in 3-5 lines of the observed MITRE pattern."
}}
"""

    # 1) Call model to get IDs + justification
    response = call_llm(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        provider="gemini"  # Gemini for technique extraction
    )

    try:
        json_str = extract_json_block(response)
        parsed = json.loads(json_str)
    except json.JSONDecodeError:
        # Unparseable response -> return minimal error object
        return {
            "parse_error": "LLM did not return valid JSON",
            "raw_response": response,
        }

    raw_techniques = parsed.get("techniques", [])
    summary = parsed.get("summary", "")

    # Normalize minimal structure
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

    # 2) Enrich against local official MITRE DB
    enriched = enrich_techniques(norm_techniques)

    return {
        "techniques": enriched,
        "summary": summary,
    }
