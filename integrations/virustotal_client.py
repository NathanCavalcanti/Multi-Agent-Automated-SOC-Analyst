# integrations/virustotal_client.py
from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

import requests

# VirusTotal API v3 URL
VT_API_URL = "https://www.virustotal.com/api/v3"


def get_file_report(file_hash: str) -> Dict[str, Any]:
    """
    Retrieves the file report from VirusTotal for a given hash (MD5, SHA1, SHA256).
    
    Returns a dictionary with:
    - malicious_count: number of engines detecting it as malicious
    - total_engines: total number of engines
    - permalink: URL to the VT report
    - error: error message if any
    """
    from app.config import VIRUSTOTAL_API_KEY
    
    if not VIRUSTOTAL_API_KEY:
        return {
            "error": "Missing VIRUSTOTAL_API_KEY",
            "malicious_count": 0,
            "total_engines": 0,
            "permalink": ""
        }

    url = f"{VT_API_URL}/files/{file_hash}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 404:
            return {
                "error": "Hash not found in VirusTotal",
                "malicious_count": 0,
                "total_engines": 0,
                "permalink": ""
            }
        
        if response.status_code == 429:
            return {
                "error": "Rate limit exceeded",
                "malicious_count": 0,
                "total_engines": 0,
                "permalink": ""
            }
            
        if response.status_code == 403:
             return {
                "error": "Forbidden (Invalid API Key)",
                "malicious_count": 0,
                "total_engines": 0,
                "permalink": ""
            }

        response.raise_for_status()
        data = response.json()
        
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        # Extract richer context
        threat_label = attributes.get("popular_threat_classification", {}).get("suggested_threat_label", "")
        
        # Sandbox verdicts (e.g. "Metasploit", "Rozena")
        sandbox_verdicts = []
        for _, verdict in attributes.get("sandbox_verdicts", {}).items():
            if "malware_names" in verdict:
                sandbox_verdicts.extend(verdict["malware_names"])
        sandbox_verdicts = list(set(sandbox_verdicts))
        
        # Sigma rules (behavioral)
        sigma_rules = []
        for rule in attributes.get("sigma_analysis_results", []):
            if rule.get("rule_title"):
                sigma_rules.append(rule.get("rule_title"))
                
        # Signature info (masquerading check)
        signature_info = attributes.get("signature_info", {}).get("description", "")
        
        return {
            "malicious_count": stats.get("malicious", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
            "scan_date": attributes.get("last_analysis_date", 0),
            "names": attributes.get("names", [])[:5],
            "threat_label": threat_label,
            "sandbox_verdicts": sandbox_verdicts[:5],
            "sigma_rules": sigma_rules[:3],
            "signature_description": signature_info
        }

    except Exception as e:
        return {
            "error": str(e),
            "malicious_count": 0,
            "total_engines": 0,
            "permalink": ""
        }
