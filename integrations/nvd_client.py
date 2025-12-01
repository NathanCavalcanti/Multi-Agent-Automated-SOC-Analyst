# integrations/nvd_client.py
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _get_nvd_api_key() -> Optional[str]:
    """
    Devuelve la API key de NVD desde la variable de entorno NVD_API_KEY.
    Es opcional: sin key hay más rate-limit, pero para laboratorio es suficiente.
    """
    return os.getenv("NVD_API_KEY")


def search_cves(
    keyword: str,
    max_results: int = 5,
) -> List[Dict[str, Any]]:
    """
    Busca CVEs en NVD usando keywordSearch.
    Devuelve una lista de dicts simplificados: id, cvss, description.
    """

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }

    api_key = _get_nvd_api_key()
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=20)
    resp.raise_for_status()
    data = resp.json()

    cves: List[Dict[str, Any]] = []

    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id")

        descriptions = cve_data.get("descriptions", [])
        desc_text = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break
        if not desc_text and descriptions:
            desc_text = descriptions[0].get("value", "")

        metrics = cve_data.get("metrics", {})
        cvss = None

        # NVD API 2.0: CVSS en distintas claves según versión
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                break

        cves.append(
            {
                "id": cve_id,
                "cvss": cvss,
                "description": desc_text,
            }
        )

    return cves
