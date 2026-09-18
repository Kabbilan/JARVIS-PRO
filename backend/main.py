from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Literal
from correlation import analyze_scenario, get_scenarios

app = FastAPI(title="AEGIS SOC API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ReviewRequest(BaseModel):
    incident_id: str
    decision: Literal["approved", "rejected"]


@app.get("/api/health")
def health():
    return {"status": "online", "service": "AEGIS correlation engine"}


@app.get("/api/scenarios")
def scenarios():
    return get_scenarios()


@app.post("/api/analyze/{scenario_id}")
def analyze(scenario_id: str):
    result = analyze_scenario(scenario_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return result


@app.post("/api/review")
def review(payload: ReviewRequest):
    return {
        "incident_id": payload.incident_id,
        "decision": payload.decision,
        "message": "Response plan approved for simulated execution"
        if payload.decision == "approved"
        else "Response plan rejected; incident remains under analyst review",
    }

