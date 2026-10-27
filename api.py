"""Optional FastAPI interface for the same detection pipeline."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from cloudsentinel.engine import detect, investigation_report

app = FastAPI(title="CloudSentinel API", version="0.1.0", description="Defensive audit-event triage demo")

class AnalysisRequest(BaseModel):
    events: list[dict]
    iocs: list[dict] = []

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/analyze")
def analyze(request: AnalysisRequest):
    try:
        import pandas as pd
        alerts, stats = detect(pd.DataFrame(request.events), pd.DataFrame(request.iocs) if request.iocs else None)
        reports = [investigation_report(pd.DataFrame(request.events), alert) for _, alert in alerts.iterrows()]
        return {"alerts": alerts.to_dict(orient="records"), "accounts": stats.reset_index(names="account").to_dict(orient="records"), "reports": reports}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
