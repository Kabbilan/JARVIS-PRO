import asyncio
import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Any, Literal
from ai_agent import fallback_investigation, generate_investigation
from correlation import analyze_events, analyze_scenario, get_scenarios
from database import incident_summary, list_incidents, save_incident, save_investigation, save_review
from report_generator import generate_incident_report
from fastapi.responses import Response

app = FastAPI(title="SentraPixel SOC API", version="0.6.0")

frontend_origins = ["http://localhost:5173", "http://127.0.0.1:5173"]
frontend_origin = os.getenv("FRONTEND_ORIGIN", "").strip().rstrip("/")
if frontend_origin:
    frontend_origins.append(frontend_origin)

app.add_middleware(
    CORSMiddleware,
    allow_origins=frontend_origins,
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ReviewRequest(BaseModel):
    incident_id: str
    decision: Literal["approved", "rejected"]


class RawAlert(BaseModel):
    id: str | None = None
    time: str = Field(pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    source: str | None = None
    type: str
    label: str | None = None
    user: str | None = None
    ip: str | None = None
    device: str | None = None
    resource: str | None = None
    base_severity: int | None = Field(default=None, ge=0, le=100)

    def as_event(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True)


class AnalyzeAlertsRequest(BaseModel):
    alerts: list[RawAlert] = Field(min_length=1, max_length=500)


async def investigation_with_timeout(incident: dict[str, Any]) -> dict[str, Any]:
    timeout_seconds = float(os.getenv("GEMINI_DEADLINE_SECONDS", "12"))
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(generate_investigation, incident),
            timeout=timeout_seconds,
        )
    except TimeoutError:
        return fallback_investigation(incident)


@app.get("/api/health")
def health():
    return {"status": "online", "service": "SentraPixel correlation engine", "version": "0.6.0"}


@app.get("/api/scenarios")
def scenarios():
    return get_scenarios()


@app.get("/api/incidents")
def incidents():
    rows = list_incidents()
    return {"incidents": rows, "summary": incident_summary(rows)}


@app.post("/api/analyze/{scenario_id}")
def analyze(scenario_id: str):
    result = analyze_scenario(scenario_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scenario not found")
    save_incident(result)
    return result


@app.post("/api/analyze-alerts")
def analyze_raw_alerts(payload: AnalyzeAlertsRequest):
    result = analyze_events([alert.as_event() for alert in payload.alerts])
    if not result:
        raise HTTPException(status_code=400, detail="No valid alerts supplied")
    save_incident(result)
    return result


@app.post("/api/investigate/{scenario_id}")
async def investigate(scenario_id: str):
    incident = analyze_scenario(scenario_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Scenario not found")
    save_incident(incident)
    investigation = await investigation_with_timeout(incident)
    save_investigation(incident["incident_id"], investigation)
    return {"incident_id": incident["incident_id"], "investigation": investigation}


@app.post("/api/investigate-alerts")
async def investigate_raw_alerts(payload: AnalyzeAlertsRequest):
    incident = analyze_events([alert.as_event() for alert in payload.alerts])
    if not incident:
        raise HTTPException(status_code=400, detail="No valid alerts supplied")
    investigation = await investigation_with_timeout(incident)
    save_investigation(incident["incident_id"], investigation)
    return {"incident_id": incident["incident_id"], "investigation": investigation}


@app.post("/api/review")
def review(payload: ReviewRequest):
    save_review(payload.incident_id, payload.decision)
    return {
        "incident_id": payload.incident_id,
        "decision": payload.decision,
        "message": "Response plan approved for simulated execution"
        if payload.decision == "approved"
        else "Response plan rejected; incident remains under analyst review",
    }


@app.get("/api/report/{scenario_id}")
async def report(scenario_id: str):
    incident = analyze_scenario(scenario_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Scenario not found")
    investigation = await investigation_with_timeout(incident)
    pdf = generate_incident_report(incident, investigation)
    filename = f"SentraPixel-{incident['incident_id']}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/report-alerts")
async def report_raw_alerts(payload: AnalyzeAlertsRequest):
    incident = analyze_events([alert.as_event() for alert in payload.alerts])
    if not incident:
        raise HTTPException(status_code=400, detail="No valid alerts supplied")
    investigation = await investigation_with_timeout(incident)
    pdf = generate_incident_report(incident, investigation)
    filename = f"SentraPixel-{incident['incident_id']}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
