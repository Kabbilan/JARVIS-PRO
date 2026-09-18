import json
import logging
import os

from pydantic import BaseModel, Field


logger = logging.getLogger("sentrapixel.ai")


class InvestigationResult(BaseModel):
    provider: str
    narrative: str
    evidence: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)


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


def generate_investigation(incident):
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        logger.warning("Gemini investigation fallback: GEMINI_API_KEY is not configured")
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
        return InvestigationResult(provider="gemini", **parsed).model_dump()
    except Exception as exc:
        logger.exception("Gemini investigation failed (%s): %s", type(exc).__name__, exc)
        return fallback_investigation(incident)
