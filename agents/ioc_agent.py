from __future__ import annotations

import json
from typing import Any, Dict

from app.config import call_llm, extract_json_block


def run_ioc_agent(incident_text: str) -> Dict[str, Any]:
    """
    Agent 1: IOC Extractor
    Extracts IPs, domains, URLs, hashes, emails, file paths, etc.
    Returns a dictionary with structured IOCs.
    """

    system_prompt = (
        "You are a SOC analyst specializing in IOC extraction. "
        "Your task is to read the incident description and extract indicators of compromise "
        "(IPs, domains, URLs, emails, malware hashes, file paths) "
        "into a valid JSON format."
    )

    user_prompt = f"""
Incident text:

{incident_text}

Return ONLY a valid JSON with the following structure:

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
  "file_paths": ["C:\\\\Windows\\\\System32\\\\...", "/tmp/malicious", ...]
}}
"""

    response = call_llm(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        provider="gemini"  # Gemini for data extraction
    )

    try:
        json_str = extract_json_block(response)
        parsed = json.loads(json_str)
    except json.JSONDecodeError:
        parsed = {
            "parse_error": "LLM did not return valid JSON",
            "raw_response": response,
        }

    return parsed
