# app/api.py

from fastapi import FastAPI
from dotenv import load_dotenv
load_dotenv()

from graph.graph_builder import create_graph
from graph.state import SOCState

app = FastAPI(title="MAA-SOC Multi-Agent System API")


@app.post("/analyze")
async def analyze_incident(payload: dict):
    """
    POST /analyze
    {
        "incident": "event log text here..."
    }
    """
    incident = payload.get("incident", "")

    graph = create_graph()
    state = SOCState(input_text=incident)

    output = graph.invoke(state)

    return output.model_dump()
