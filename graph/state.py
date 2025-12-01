# graph/state.py

from typing import Dict, Optional
from pydantic import BaseModel

class SOCState(BaseModel):
    """
    Global state object shared across all agents in the SOC pipeline.
    Each agent adds or modifies fields during the LangGraph execution.
    """

    input_text: str

    # Agent outputs
    iocs: Optional[Dict] = None
    ttps: Optional[Dict] = None
    cves: Optional[Dict] = None
    investigation_plan: Optional[str] = None
    report: Optional[str] = None
