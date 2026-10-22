# Public HTTPS Incident Agent (starter)

This project implements a FastAPI service with the required routes:
- `POST /v2/incidents`
- `POST /v2/incidents/{runId}/receipts`
- `GET /v2/incidents/{runId}`

## Important
This is a starter implementation, not a verified full-score submission. It must be tested against the grader's actual tool catalog and receipts before spending a Check/Save. The grader's supplied API contract requires receipt-driven execution and exact OTLP correlation; this scaffold needs a final verification pass for the particular catalog/receipt behavior.

## Free deployment: Render + Gemini
1. Create a free GitHub account if needed.
2. Create a new empty repository named `public-incident-agent`.
3. Upload all files from this folder to the repository root.
4. Get a Gemini API key from Google AI Studio. Keep it secret; do not paste it into code or chat.
5. In Render, choose **New + → Web Service**, connect the repository, and use:
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
6. Add environment variables in Render:
   - `GEMINI_API_KEY` = your private key
   - `MODEL` = `gemini-2.5-flash`
   - `DATABASE_PATH` = `/tmp/incident_agent.db`
7. Deploy. Render gives you an HTTPS URL. Open `https://YOUR-SERVICE.onrender.com/` and confirm JSON says `"status":"ready"`.
8. Paste that HTTPS URL into the assignment's deployed base URL field.

## Local smoke test
Install Python 3.11+, then in this folder:
```bash
python -m venv .venv
# Windows:
.venv\\Scripts\\activate
pip install -r requirements.txt
set GEMINI_API_KEY=YOUR_KEY
uvicorn main:app --reload
```
Open http://127.0.0.1:8000/ to verify it starts. Local HTTP is only for testing; the grader needs a public HTTPS URL.

## Privacy
The `sensitive` object is not included in the model request. Never commit API keys. Free web services may sleep or have ephemeral disk; a persistent database is required for robust replay/conflict tests. Before final Save, verify persistence and OTLP behavior.
