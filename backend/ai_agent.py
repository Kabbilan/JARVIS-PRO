import json
import logging
import os
import hashlib
import time

from pydantic import BaseModel, Field


logger = logging.getLogger("sentrapixel.ai")
_investigation_cache = {}
_rate_limited_until = 0.0


class InvestigationResult(BaseModel):
    provider: str
    narrative: str
    evidence: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)


class ResponsePlanResult(BaseModel):
    provider: str
    priority: str
    immediate_actions: list[str] = Field(default_factory=list)
    evidence_to_preserve: list[str] = Field(default_factory=list)
    recovery_steps: list[str] = Field(default_factory=list)
    human_approval_required: bool = True


class VerificationResult(BaseModel):
    provider: str
    verdict: str
    supported_checks: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    checks_passed: int
    checks_total: int


def fallback_investigation(incident):
    events = incident.get("events", [])
    links = incident.get("links", [])
    stages = [event.get("stage", "Unknown") for event in events]
    evidence = [link.get("reason", "") for link in links[:4] if link.get("reason")]
    if not evidence:
        evidence = ["No strong cross-alert correlation evidence was found."]

    if incident.get("metrics", {}).get("incidents", 0):
        narrative = (
            f"SentraPixel identified a {incident.get('severity', 'unknown')} incident with score "
            f"{incident.get('score', 0)}. The observed sequence was: {' -> '.join(stages)}. "
            "The investigation is based on deterministic correlation evidence from the security events."
        )
        next_steps = [
            "Verify the affected identity and device",
            "Review the correlated event timeline and source IP",
            "Validate sensitive-resource access and outbound traffic",
            "Keep containment actions behind analyst approval",
        ]
    else:
        narrative = (
            "SentraPixel did not identify a high-confidence malicious incident. "
            "The activity should be verified by an analyst before closure."
        )
        next_steps = [
            "Verify the user activity",
            "Continue routine monitoring",
            "Close as benign if analyst verification confirms normal behavior",
        ]

    return InvestigationResult(
        provider="fallback",
        narrative=narrative,
        evidence=evidence,
        next_steps=next_steps,
    ).model_dump()


def investigation_cache_key(incident):
    normalized = json.dumps(incident, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(normalized.encode()).hexdigest()


def fallback_response_plan(incident):
    sources = sorted({event.get("source", "Unknown") for event in incident.get("events", [])})
    malicious = incident.get("metrics", {}).get("incidents", 0) > 0
    return ResponsePlanResult(
        provider="fallback",
        priority=incident.get("severity", "low"),
        immediate_actions=incident.get("recommended_actions", [])[:4],
        evidence_to_preserve=[f"Preserve {source} telemetry" for source in sources[:4]],
        recovery_steps=(
            ["Reset affected credentials after containment", "Review privilege changes", "Restore and validate security controls"]
            if malicious else ["Continue monitoring", "Close only after analyst verification"]
        ),
    ).model_dump()


def generate_response_plan(incident, investigation):
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or time.monotonic() < _rate_limited_until:
        return fallback_response_plan(incident)
    try:
        from google import genai
        from google.genai import types
        client = genai.Client(api_key=api_key, http_options=types.HttpOptions(timeout=int(os.getenv("GEMINI_TIMEOUT_MS", "10000"))))
        prompt = (
            "You are the response-planner agent inside SentraPixel SOC. Use only the supplied incident and "
            "investigation. Create a proportional, reversible containment and recovery plan. Never claim an "
            "action was executed. Every action requires human approval.\n\n"
            f"INCIDENT:\n{json.dumps(incident, indent=2)}\n\nINVESTIGATION:\n{json.dumps(investigation, indent=2)}"
        )
        schema = {
            "type": "object",
            "properties": {
                "priority": {"type": "string"},
                "immediate_actions": {"type": "array", "items": {"type": "string"}},
                "evidence_to_preserve": {"type": "array", "items": {"type": "string"}},
                "recovery_steps": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["priority", "immediate_actions", "evidence_to_preserve", "recovery_steps"],
            "additionalProperties": False,
        }
        interaction = client.interactions.create(
            model=os.getenv("GEMINI_MODEL", "gemini-3.8-flash"), input=prompt,
            response_format={"type": "text", "mime_type": "application/json", "schema": schema},
        )
        return ResponsePlanResult(provider="gemini", **json.loads(interaction.output_text)).model_dump()
    except Exception as exc:
        logger.warning("Response planner fallback (%s): %s", type(exc).__name__, exc)
        return fallback_response_plan(incident)


def verify_agent_outputs(incident, investigation, response_plan):
    links = incident.get("links", [])
    techniques = incident.get("mitre_techniques", [])
    actions = response_plan.get("immediate_actions", [])
    supported = []
    warnings = []
    if links:
        supported.append(f"Investigation is grounded by {len(links)} correlation links")
    else:
        warnings.append("No cross-alert correlation links support a malicious chain")
    if investigation.get("evidence"):
        supported.append(f"Investigation cites {len(investigation['evidence'])} evidence statements")
    else:
        warnings.append("Investigation contains no explicit evidence statements")
    if techniques:
        supported.append(f"{len(techniques)} MITRE mappings include source-event evidence")
    else:
        warnings.append("No MITRE technique evidence is available")
    if actions and response_plan.get("human_approval_required") is True:
        supported.append("Response actions remain behind human approval")
    else:
        warnings.append("Response plan is missing actions or the approval safeguard")
    if incident.get("confidence", 0) < 60:
        warnings.append("Low correlation confidence requires additional analyst validation")
    total = len(supported) + len(warnings)
    verdict = "verified" if not warnings else "needs_review"
    return VerificationResult(
        provider="evidence-policy",
        verdict=verdict,
        supported_checks=supported,
        warnings=warnings,
        checks_passed=len(supported),
        checks_total=total,
    ).model_dump()


def generate_agent_pipeline(incident):
    investigation = generate_investigation(incident)
    response_plan = generate_response_plan(incident, investigation)
    verification = verify_agent_outputs(incident, investigation, response_plan)
    return {"investigation": investigation, "response_plan": response_plan, "verification": verification}


def generate_investigation(incident):
    global _rate_limited_until
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        logger.warning("Gemini investigation fallback: GEMINI_API_KEY is not configured")
        return fallback_investigation(incident)

    cache_key = investigation_cache_key(incident)
    if cache_key in _investigation_cache:
        return _investigation_cache[cache_key]

    if time.monotonic() < _rate_limited_until:
        return fallback_investigation(incident)

    try:
        from google import genai
        from google.genai import types

        timeout_ms = int(os.getenv("GEMINI_TIMEOUT_MS", "10000"))
        client = genai.Client(
            api_key=api_key,
            http_options=types.HttpOptions(timeout=timeout_ms),
        )
        prompt = (
            "You are the investigation agent inside SentraPixel SOC. Analyze only the supplied incident JSON. "
            "Do not invent evidence or facts not present in the data. Explain what happened, cite the strongest "
            "correlation evidence, and give safe analyst investigation next steps. Any response action must remain "
            "subject to human approval.\n\n"
            f"INCIDENT JSON:\n{json.dumps(incident, indent=2)}"
        )
        schema = {
            "type": "object",
            "properties": {
                "narrative": {"type": "string"},
                "evidence": {"type": "array", "items": {"type": "string"}},
                "next_steps": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["narrative", "evidence", "next_steps"],
            "additionalProperties": False,
        }
        interaction = client.interactions.create(
            model=os.getenv("GEMINI_MODEL", "gemini-3.8-flash"),
            input=prompt,
            response_format={"type": "text", "mime_type": "application/json", "schema": schema},
        )
        parsed = json.loads(interaction.output_text)
        result = InvestigationResult(provider="gemini", **parsed).model_dump()
        _investigation_cache[cache_key] = result
        return result
    except Exception as exc:
        error_text = str(exc).lower()
        if "429" in error_text or "rate limit" in error_text or "resource_exhausted" in error_text:
            cooldown = max(60, int(os.getenv("GEMINI_RATE_LIMIT_COOLDOWN_SECONDS", "300")))
            _rate_limited_until = time.monotonic() + cooldown
            logger.warning("Gemini quota/rate limit reached; using fallback during cooldown")
        else:
            logger.exception("Gemini investigation failed (%s): %s", type(exc).__name__, exc)
        return fallback_investigation(incident)
