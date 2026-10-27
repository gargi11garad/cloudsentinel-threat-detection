# CloudSentinel

A reproducible defensive cloud-audit detection and investigation demo. It combines explainable rules with Isolation Forest behavioral ranking, optional IOC enrichment, JSON investigation reports, a Streamlit console, and a small FastAPI API.

> **Safe demo data:** the default dataset is synthetic. The built-in IOC uses `203.0.113.77`, a reserved documentation address, and is explicitly labeled synthetic. Do not interpret demo alerts as real incident findings.

## Run locally

```bash
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Optional API: `uvicorn api:app --reload` then open `/docs`.

## Input formats

Events CSV needs `timestamp,account,source_ip,action,status`; `resource` and `request_count` are optional. Timestamps are interpreted as UTC when no timezone is supplied. IOC CSV needs `indicator,type,source`; `retrieved_at` is recommended. Only exact IP indicators are matched. No external intelligence is fetched automatically: upload indicators from a source you trust and retain its retrieval timestamp.

## Detection notes

The initial rule thresholds and limitations are listed in the app. Isolation Forest uses request volume, failed-event rate, after-hours rate, and privilege-related action count, aggregated by account. Its score is relative to the uploaded population, and it is not an attack probability or proof of compromise. Small populations under five accounts are not assigned anomaly flags. Tune thresholds to the environment before operational use.

## API

- `GET /health`
- `POST /analyze` with `{"events": [...], "iocs": [...]}`

The API returns account scores, alerts, and investigation reports. Input validation errors return HTTP 422.

## Tests and container

```bash
pip install -r requirements.txt pytest httpx
python -m pytest -q
docker build -t cloudsentinel .
docker run --rm -p 8501:8501 cloudsentinel
```

GitHub Actions runs the test suite on pushes and pull requests.

## Deployment

Push this repository to GitHub, then on Streamlit Community Cloud choose **Create app**, select the repository/branch, and set the main file to `app.py`. No secrets are required for the synthetic demo. For API hosting, deploy the container with `uvicorn api:app --host 0.0.0.0 --port 8000` and configure the platform's health check to `/health`.

## Security lab boundary

The requested vulnerable-API exercise is intentionally not exposed in this first deployment. It can be developed as a separate localhost-only lab with an explicit opt-in, root-cause write-up, fix, and regression test. Keep all exercises on systems you own or are authorized to assess.

## Scope

This starter keeps the first four project priorities runnable with synthetic or uploaded data. PostgreSQL persistence, provider-specific cloud log ingestion, long-lived baselines, authenticated multi-tenant API access, and production incident automation are not implemented. Reports are triage aids and require human validation.
