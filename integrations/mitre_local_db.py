# integrations/mitre_local_db.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

# URL oficial de Enterprise ATT&CK en GitHub (bundle STIX)
MITRE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Ruta al fichero local en el proyecto
DATA_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "enterprise-attack.json"
)

# Estructuras en memoria
_TECHNIQUES_BY_ID: Dict[str, Dict[str, Any]] = {}
_TACTICS_BY_SHORTNAME: Dict[str, Dict[str, Any]] = {}
_LOADED: bool = False


# ---------------------------------------------------------------------------
# Descarga y carga del bundle MITRE
# ---------------------------------------------------------------------------

def _fetch_remote_bundle() -> Optional[Dict[str, Any]]:
    """
    Intenta descargar el bundle Enterprise ATT&CK desde GitHub.
    Si hay cualquier problema (red, GitHub, JSON inválido), devuelve None
    y escribe un aviso en consola.
    """
    print(f"[MITRE] Intentando descargar Enterprise ATT&CK desde GitHub:\n        {MITRE_URL}")
    try:
        resp = requests.get(MITRE_URL, timeout=60)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[MITRE] Aviso: no se ha podido descargar ATT&CK desde GitHub ({e}).")
        return None

    try:
        data = resp.json()
    except json.JSONDecodeError as e:
        print(f"[MITRE] Aviso: la respuesta de GitHub no es JSON válido ({e}).")
        return None

    if "objects" not in data or not isinstance(data["objects"], list):
        print("[MITRE] Aviso: el JSON descargado no parece un bundle ATT&CK válido (no hay 'objects').")
        return None

    print(f"[MITRE] Descarga correcta desde GitHub. Objetos en bundle: {len(data['objects'])}")
    return data


def _save_bundle_to_disk(data: Dict[str, Any]) -> None:
    """Guarda el bundle en data/enterprise-attack.json."""
    DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DATA_PATH.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[MITRE] Bundle actualizado guardado en {DATA_PATH}")


def _load_bundle_from_disk() -> Optional[Dict[str, Any]]:
    """Carga el bundle desde disco si existe y es válido. Si no, devuelve None."""
    if not DATA_PATH.exists():
        print(f"[MITRE] Aviso: no existe copia local en {DATA_PATH}.")
        return None

    try:
        with DATA_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[MITRE] Aviso: error leyendo la copia local ({e}).")
        return None

    if "objects" not in data or not isinstance(data["objects"], list):
        print("[MITRE] Aviso: la copia local no parece un bundle ATT&CK válido (no hay 'objects').")
        return None

    print(f"[MITRE] Bundle cargado desde copia local: {DATA_PATH}")
    return data


def _load_bundle() -> Dict[str, Any]:
    """
    Lógica de carga del bundle:
    1) Intentar descarga desde GitHub.
       - Si va bien -> guardar en disco y usar ese.
    2) Si falla la descarga o es inválida:
       - Intentar cargar copia local.
    3) Si tampoco hay copia local válida:
       - Lanzar error.
    """
    # 1) Intentar remoto
    data = _fetch_remote_bundle()
    if data is not None:
        # Guardar en disco para futuras ejecuciones offline
        _save_bundle_to_disk(data)
        print("[MITRE] Se utilizará el bundle descargado de GitHub.")
        return data

    # 2) Fallback a copia local
    print("[MITRE] Aviso: se usará copia local de ATT&CK (sin conectividad a GitHub).")
    local_data = _load_bundle_from_disk()
    if local_data is not None:
        print("[MITRE] Bundle MITRE cargado correctamente desde copia local.")
        return local_data

    # 3) No hay ni remoto ni local válido
    raise RuntimeError(
        "[MITRE] Error crítico: no se ha podido obtener el bundle ATT&CK "
        "ni desde GitHub ni desde una copia local. Verifica la conectividad "
        "y que exista data/enterprise-attack.json válido."
    )


# ---------------------------------------------------------------------------
# Construcción de índices MITRE (tácticas y técnicas)
# ---------------------------------------------------------------------------

def _load_data() -> None:
    """Carga ATT&CK Enterprise y construye índices en memoria."""
    global _LOADED, _TECHNIQUES_BY_ID, _TACTICS_BY_SHORTNAME

    if _LOADED:
        return

    bundle = _load_bundle()
    objects = bundle.get("objects", [])

    # 1) Tácticas por shortname (execution, persistence, etc.)
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            shortname = obj.get("x_mitre_shortname")
            if not shortname:
                continue

            tactic_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    tactic_id = ref["external_id"]
                    break

            _TACTICS_BY_SHORTNAME[shortname] = {
                "tactic_id": tactic_id,
                "tactic": obj.get("name"),
                "shortname": shortname,
            }

    # 2) Técnicas por external_id (Txxxx / Txxxx.xx)
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        external_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                external_id = ref["external_id"]
                break

        if not external_id:
            continue

        tactics: List[Dict[str, Any]] = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                phase_name = phase.get("phase_name")
                tac = _TACTICS_BY_SHORTNAME.get(phase_name)
                if tac:
                    tactics.append(
                        {
                            "tactic_id": tac["tactic_id"],
                            "tactic": tac["tactic"],
                            "shortname": tac["shortname"],
                        }
                    )

        _TECHNIQUES_BY_ID[external_id] = {
            "id": external_id,
            "name": obj.get("name"),
            "tactics": tactics,
            "raw": obj,
        }

    _LOADED = True


def get_technique_by_id(tech_id: str) -> Optional[Dict[str, Any]]:
    """Devuelve la técnica MITRE por ID (ej. 'T1059.001'), o None si no existe."""
    _load_data()
    return _TECHNIQUES_BY_ID.get(tech_id)


def enrich_techniques(
    techniques: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Enriquecimiento de técnicas propuestas por el LLM con datos oficiales MITRE.

    Entrada típica:
      [{"id": "T1059.001", "justification": "..."}]

    Salida:
      [
        {
          "id": "T1059.001",
          "name": "Command Shell",
          "tactic_id": "TA0002",
          "tactic": "Execution",
          "justification": "...",
          "source": "Enterprise MITRE"  # o "LLM supposition"
        },
        ...
      ]
    """
    _load_data()
    enriched: List[Dict[str, Any]] = []

    for t in techniques:
        tech_id = t.get("id")
        justification = t.get("justification", "")

        base = get_technique_by_id(str(tech_id)) if tech_id else None

        if base:
            tactics = base.get("tactics") or []
            tactic_id = tactics[0].get("tactic_id") if tactics else None
            tactic_name = tactics[0].get("tactic") if tactics else None

            enriched.append(
                {
                    "id": base.get("id"),
                    "name": base.get("name"),
                    "tactic_id": tactic_id,
                    "tactic": tactic_name,
                    "justification": justification,
                    "source": "Enterprise MITRE",
                }
            )
        else:
            # ID no encontrado en la base MITRE (posible error / suposición del LLM)
            enriched.append(
                {
                    "id": tech_id,
                    "name": t.get("name"),
                    "tactic_id": None,
                    "tactic": None,
                    "justification": justification,
                    "source": "LLM supposition",
                }
            )

    return enriched
