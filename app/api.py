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

    # Create graph and initial state (dict, same as main.py)
    graph = create_graph()
    initial_state = {"input_text": incident}

    # Invoke graph
    # Note: For production, you should add the same error handling as in main.py
    output = graph.invoke(initial_state)

    return output
