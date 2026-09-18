# SentraPixel SOC

Explainable autonomous SOC assistant for FC-04. It correlates fragmented security alerts, reconstructs attack chains, scores incident severity, and recommends human-approved response actions.

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

1. Select a prepared scenario or open **JSON Alerts** to paste/upload 1–500 SIEM alerts.
2. Run correlation.
3. Inspect alert links, attack chain, severity factors, AI investigation, and timeline.
4. Review recommended actions and approve or reject them.
5. Download the evidence-backed incident report as a PDF.

Each custom alert requires `time` (`HH:MM`) and `type`. Optional fields include `id`, `source`, `label`, `user`, `ip`, `device`, `resource`, and `base_severity` (0–100).
