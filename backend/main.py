import asyncio
import os

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Any, Literal
from ai_agent import fallback_investigation, fallback_response_plan, generate_agent_pipeline, generate_investigation, verify_agent_outputs
from correlation import analyze_event_batch, analyze_events, analyze_scenario, get_scenarios
from database import get_incident, incident_summary, list_incidents, save_incident, save_investigation, save_review
from report_generator import generate_incident_report\nfrom normalizer import normalize_upload, UnsupportedAlertSchema
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
    decision: Literal["approved", "rejected", "false_positive"]
    action: Literal["monitor", "temporary_containment", "permanent_block", "restore_access"] = "monitor"
    reason: str = Field(default="", max_length=500)
    acknowledged: bool = False


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


async def agent_pipeline_with_timeout(incident: dict[str, Any]) -> dict[str, Any]:
    timeout_seconds = float(os.getenv("AGENT_PIPELINE_DEADLINE_SECONDS", "22"))
    try:
        return await asyncio.wait_for(asyncio.to_thread(generate_agent_pipeline, incident), timeout=timeout_seconds)
    except TimeoutError:
        investigation = fallback_investigation(incident)
        response_plan = fallback_response_plan(incident)
        return {
            "investigation": investigation,
            "response_plan": response_plan,
            "verification": verify_agent_outputs(incident, investigation, response_plan),
        }


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


@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id: str):
    incident = get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.get("/api/incidents/{incident_id}/report")
async def incident_report(incident_id: str):
    incident = get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    investigation = incident.get("investigation")
    if not investigation:
        pipeline = await agent_pipeline_with_timeout(incident)
        investigation = {**pipeline["investigation"], "response_plan": pipeline["response_plan"], "verification": pipeline["verification"]}
    pdf = generate_incident_report(incident, investigation)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="SentraPixel-{incident_id}.pdf"'},
    )


@app.post("/api/analyze/{scenario_id}")
def analyze(scenario_id: str):
    result = analyze_scenario(scenario_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scenario not found")
    save_incident(result)
    return result


@app.post("/api/analyze-alerts")
async def analyze_raw_alerts(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON.")
    try:
        alerts, normalization = normalize_upload(payload)
    except UnsupportedAlertSchema as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    batch = analyze_event_batch(alerts)
    if not batch:
        raise HTTPException(status_code=400, detail="No valid alerts supplied")
    batch["normalization"] = normalization
    for incident in batch["incidents"]:
        save_incident(incident)
    return batch


@app.post("/api/incidents/{incident_id}/investigate")
async def investigate_incident(incident_id: str):
    incident = get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    pipeline = await agent_pipeline_with_timeout(incident)
    combined = {**pipeline["investigation"], "response_plan": pipeline["response_plan"], "verification": pipeline["verification"]}
    save_investigation(incident_id, combined)
    return {"incident_id": incident_id, **pipeline}


@app.post("/api/investigate/{scenario_id}")
async def investigate(scenario_id: str):
    incident = analyze_scenario(scenario_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Scenario not found")
    save_incident(incident)
    pipeline = await agent_pipeline_with_timeout(incident)
    save_investigation(incident["incident_id"], {**pipeline["investigation"], "response_plan": pipeline["response_plan"], "verification": pipeline["verification"]})
    return {"incident_id": incident["incident_id"], **pipeline}


@app.post("/api/investigate-alerts")
async def investigate_raw_alerts(payload: AnalyzeAlertsRequest):
    incident = analyze_events([alert.as_event() for alert in payload.alerts])
    if not incident:
        raise HTTPException(status_code=400, detail="No valid alerts supplied")
    save_incident(incident)
    pipeline = await agent_pipeline_with_timeout(incident)
    save_investigation(incident["incident_id"], {**pipeline["investigation"], "response_plan": pipeline["response_plan"], "verification": pipeline["verification"]})
    return {"incident_id": incident["incident_id"], **pipeline}


@app.post("/api/review")
def review(payload: ReviewRequest):
    incident = get_incident(payload.incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    confidence = int(incident.get("confidence", 0))
    if payload.action == "permanent_block":
        raise HTTPException(status_code=409, detail="Permanent blocking requires separate second-party authorization and is never executed by SentraPixel")
    if payload.decision == "approved" and payload.action == "temporary_containment":
        if confidence < 60:
            raise HTTPException(status_code=409, detail="Low-confidence incidents can only be monitored or marked for review")
        if not payload.acknowledged:
            raise HTTPException(status_code=400, detail="Containment impact must be acknowledged")
    if payload.decision == "false_positive" and not payload.reason.strip():
        raise HTTPException(status_code=400, detail="A false-positive reason is required")
    if not save_review(payload.incident_id, payload.decision):
        raise HTTPException(status_code=500, detail="Review could not be saved")
    messages = {
        "approved": "Monitoring saved" if payload.action == "monitor" else "Temporary containment approved with rollback available",
        "rejected": "Response plan rejected; incident remains under analyst review",
        "false_positive": "False positive recorded and access restoration requested",
    }
    return {
        "incident_id": payload.incident_id,
        "decision": payload.decision,
        "action": payload.action,
        "reason": payload.reason.strip(),
        "rollback_available": payload.action == "temporary_containment",
        "message": messages[payload.decision],
    }


@app.get("/api/report/{scenario_id}")
async def report(scenario_id: str):
    incident = analyze_scenario(scenario_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Scenario not found")
    pipeline = await agent_pipeline_with_timeout(incident)
    investigation = {**pipeline["investigation"], "response_plan": pipeline["response_plan"], "verification": pipeline["verification"]}
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
    pipeline = await agent_pipeline_with_timeout(incident)
    investigation = {**pipeline["investigation"], "response_plan": pipeline["response_plan"], "verification": pipeline["verification"]}
    pdf = generate_incident_report(incident, investigation)
    filename = f"SentraPixel-{incident['incident_id']}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
