# Agentic SOC Console (React)

Analyst dashboard for the Agentic SOC detection API.

## Run it

1. Start the API from the project root: `python app.py` (serves on port 8000).
2. In this folder: `npm install` (first time only), then `npm run dev`.
3. Open http://localhost:5173 and sign in with any username and a password of 4+ characters.
4. Click **Stream demo traffic** to send sample logs through the pipeline.

Vite forwards every `/api` request to `http://localhost:8000`, so no CORS setup is needed.

## Screens

- **Overview** – KPIs, containment actions, attack types, time per pipeline stage, latest incidents.
- **Incidents** – full investigation: pipeline trace with timings, SHAP chart, OSINT matches,
  LLM briefing and reasoning, YARA rule, and analyst actions (confirm, false positive, undo).
- **Attack graph** – hosts and flagged traffic, coloured by the containment applied.
- **Learning loop** – analyst corrections waiting for retraining and the model configuration.

Fonts are bundled locally, so the console works with no internet connection during a demo.
