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
        "into a valid JSON format.\n\n"
        "IMPORTANT RULES:\n"
        "- Do NOT extract memory addresses (e.g., 0x...) as hashes.\n"
        "- Do NOT extract usernames (e.g., 'john.doe') as emails. Emails MUST contain '@' and a domain.\n"
        "- Only extract valid IPv4 or IPv6 addresses."
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
        parsed = validate_iocs(parsed)
    except json.JSONDecodeError:
        parsed = {
            "parse_error": "LLM did not return valid JSON",
            "raw_response": response,
        }

    return parsed


def validate_iocs(iocs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates and cleans extracted IOCs.
    - Removes emails without '@'.
    - Removes hashes that look like memory addresses or have invalid lengths.
    """
    # Validate Emails
    if "emails" in iocs and isinstance(iocs["emails"], list):
        valid_emails = []
        for email in iocs["emails"]:
            if isinstance(email, str) and "@" in email and "." in email.split("@")[-1]:
                valid_emails.append(email)
        iocs["emails"] = valid_emails

    # Validate Hashes
    if "hashes" in iocs and isinstance(iocs["hashes"], dict):
        for hash_type, hash_list in iocs["hashes"].items():
            if not isinstance(hash_list, list):
                continue
            
            valid_hashes = []
            for h in hash_list:
                if not isinstance(h, str):
                    continue
                
                # Skip memory addresses
                if h.lower().startswith("0x"):
                    continue
                
                # Basic length validation (optional but good)
                # MD5=32, SHA1=40, SHA256=64
                l = len(h)
                if hash_type == "md5" and l != 32:
                    continue
                if hash_type == "sha1" and l != 40:
                    continue
                if hash_type == "sha256" and l != 64:
                    continue
                    
                valid_hashes.append(h)
            
            iocs["hashes"][hash_type] = valid_hashes

    return iocs
