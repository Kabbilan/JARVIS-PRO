# SentraPixel SOC

Explainable autonomous SOC assistant for FC-04. It correlates fragmented security alerts, reconstructs attack chains, scores incident severity, and recommends human-approved response actions.

## Production

- Frontend: https://sentrapixel-soc.onrender.com
- API: https://aegis-soc-api-s0vp.onrender.com
- API docs: https://aegis-soc-api-s0vp.onrender.com/docs

## Run locally

Backend:

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

## Demo flow

1. Open **Live Events** to view the SOC event stream, severity, source, event details, search, and filters.
2. Select **Analyze events** or return to **Command Center**.
3. Select a prepared scenario or open **JSON Alerts** to paste/upload 1–500 SIEM alerts.
4. Run correlation and inspect alert links, attack chain, severity factors, and timeline.
5. Review the AI investigation. Gemini is used when available; a deterministic fallback keeps the demo functional if the provider is unavailable or rate-limited.
6. Review recommended actions and approve or reject them.
7. Download the evidence-backed incident report as a PDF.
8. Open **Incidents** to review saved cases and analyst decisions.

Each custom alert requires `time` (`HH:MM`) and `type`. Optional fields include `id`, `source`, `label`, `user`, `ip`, `device`, `resource`, and `base_severity` (0–100).

Incident history uses Supabase when `SUPABASE_URL` and `SUPABASE_SECRET_KEY` are configured. Without them, the backend keeps a demo-safe in-memory history for the current server session.

## Demo readiness

The production build includes correlation, explainable scoring, AI investigation with fallback protection, analyst approval/rejection, persistent incident history, PDF reports, Live Events, and responsive navigation.
