# graph/graph_builder.py
from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel
from langgraph.graph import StateGraph, END

from agents.ioc_agent import run_ioc_agent
from agents.mitre_agent import run_mitre_agent
from agents.cve_agent import run_cve_agent
from agents.investigation_agent import run_investigation_agent
from agents.report_agent import run_report_agent, render_report_text


class SOCState(BaseModel):
    """
    Estado compartido entre los nodos del grafo.

    Todas las salidas de agentes se guardan como dict (JSON parseado)
    y el informe final también se guarda como texto plano.
    """

    # Entrada inicial
    input_text: str

    # Salidas de agentes
    iocs: Optional[Dict[str, Any]] = None
    ttps: Optional[Dict[str, Any]] = None
    cves: Optional[Dict[str, Any]] = None
    investigation_plan: Optional[Dict[str, Any]] = None

    # Informe final
    report: Optional[Dict[str, Any]] = None
    report_text: Optional[str] = None


# ===== NODOS DEL GRAFO =====


def node_iocs(state: SOCState) -> Dict[str, Any]:
    """
    Nodo IOC Agent: extrae IOCs a partir del texto del incidente.
    """
    iocs = run_ioc_agent(state.input_text)
    return {"iocs": iocs}


def node_mitre(state: SOCState) -> Dict[str, Any]:
    """
    Nodo MITRE Agent: mapea TTPs a partir del texto e IOCs.
    """
    ttps = run_mitre_agent(state.input_text, state.iocs)
    return {"ttps": ttps}


def node_cve(state: SOCState) -> Dict[str, Any]:
    """
    Nodo CVE Agent: propone CVEs a partir del texto y del contexto MITRE.
    """
    cves = run_cve_agent(
        software_info=state.input_text,
        mitre_context=state.ttps,
    )
    return {"cves": cves}


def node_investigation(state: SOCState) -> Dict[str, Any]:
    """
    Nodo Investigation Agent: genera un plan DFIR de investigación y contención.
    """
    plan = run_investigation_agent(
        event_text=state.input_text,
        iocs=state.iocs,
        ttps=state.ttps,
        cves=state.cves,
    )
    return {"investigation_plan": plan}


def node_report(state: SOCState) -> Dict[str, Any]:
    """
    Nodo Report Agent:
    - Genera un informe JSON (report)
    - Lo convierte a texto plano estructurado (report_text)
    """
    report_json = run_report_agent(
        incident_text=state.input_text,
        iocs=state.iocs,
        mitre_context=state.ttps,
        cve_context=state.cves,
        investigation_context=state.investigation_plan,
    )

    if "parse_error" in report_json:
        report_text = (
            "No se pudo generar informe estructurado a partir de JSON.\n"
            "Respuesta del modelo:\n\n"
            f"{report_json.get('raw_response', '')}"
        )
    else:
        report_text = render_report_text(report_json)

    return {
        "report": report_json,
        "report_text": report_text,
    }


# ===== CONSTRUCCIÓN DEL GRAFO =====


def create_graph():
    """
    Construye y compila el grafo de LangGraph para el sistema SOC.
    """

    workflow = StateGraph(SOCState)

    # Registrar nodos
    workflow.add_node("ioc_agent", node_iocs)
    workflow.add_node("mitre_agent", node_mitre)
    workflow.add_node("cve_agent", node_cve)
    workflow.add_node("investigation_agent", node_investigation)
    workflow.add_node("report_agent", node_report)

    # Definir flujo
    workflow.set_entry_point("ioc_agent")
    workflow.add_edge("ioc_agent", "mitre_agent")
    workflow.add_edge("mitre_agent", "cve_agent")
    workflow.add_edge("cve_agent", "investigation_agent")
    workflow.add_edge("investigation_agent", "report_agent")
    workflow.add_edge("report_agent", END)

    # Compilar grafo
    return workflow.compile()
