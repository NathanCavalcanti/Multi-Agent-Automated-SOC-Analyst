# app/api.py

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from dotenv import load_dotenv
load_dotenv()

from graph.graph_builder import create_graph
from graph.state import SOCState
from typing import Dict, Any

app = FastAPI(
    title="SOC Multi-Agent System API",
    description="RESTful API for automated security incident analysis",
    version="1.0.5"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class IncidentRequest(BaseModel):
    """Request model for incident analysis"""
    incident: str = Field(..., min_length=10, max_length=50000, description="Incident text to analyze")
    
    @validator("incident")
    def validate_incident_text(cls, v):
        if not v or not v.strip():
            raise ValueError("Incident text cannot be empty")
        return v.strip()


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    version: str


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint for monitoring and load balancers
    
    Returns:
        HealthResponse with status and version
    """
    return HealthResponse(status="healthy", version="1.0.5")


@app.post("/analyze")
async def analyze_incident(request: IncidentRequest) -> Dict[str, Any]:
    """
    Analyzes a security incident using the multi-agent system
    
    POST /analyze
    {
        "incident": "event log text here..."
    }
    
    Returns:
        Complete analysis including IOCs, MITRE techniques, CVEs, and investigation plan
    """
    try:
        # Create graph and initial state
        graph = create_graph()
        initial_state = {"input_text": request.incident}
        
        # Execute graph with error handling
        try:
            output = graph.invoke(initial_state)
            return output
            
        except RuntimeError as e:
            msg = str(e)
            
            if msg.startswith("LLM_RATE_LIMIT:"):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "rate_limit_exceeded",
                        "message": "LLM API rate limit reached. Please try again later.",
                        "provider_detail": msg
                    }
                )
            
            if msg.startswith("LLM_API_ERROR:"):
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail={
                        "error": "llm_api_error",
                       "message": "LLM provider API error. Please try again later.",
                        "provider_detail": msg
                    }
                )
            
            if msg.startswith("LLM_ERROR:") or msg.startswith("LLM_UNKNOWN_ERROR:"):
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail={
                        "error": "llm_error",
                        "message": "Error communicating with LLM provider.",
                        "provider_detail": msg
                    }
                )
            
            # Generic RuntimeError
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": "analysis_error",
                    "message": "Error during incident analysis",
                    "detail": msg
                }
            )
            
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
        
    except Exception as e:
        # Catch-all for unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "internal_error",
                "message": "Unexpected error during analysis",
                "detail": str(e)
            }
        )
