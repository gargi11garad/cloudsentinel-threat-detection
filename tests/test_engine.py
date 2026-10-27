import pandas as pd
import pytest

from cloudsentinel.engine import detect, investigation_report, normalize_events
from cloudsentinel.sample_data import sample_events, sample_iocs


def test_synthetic_dataset_triggers_transparent_alerts_and_ioc():
    alerts, scores = detect(sample_events(), sample_iocs())
    demo = alerts[alerts.account == "analyst-demo@example.test"]
    assert {"authentication_failures", "privilege_change", "threat_intel_match"} <= set(demo.type)
    assert "anomaly_score" in scores.columns


def test_report_contains_timeline_and_actions():
    events = sample_events()
    alerts, _ = detect(events)
    alert = alerts[alerts.type == "authentication_failures"].iloc[0]
    report = investigation_report(events, alert)
    assert report["timeline"]
    assert report["recommended_actions"]
    assert report["affected_resources"]


def test_invalid_timestamp_is_rejected():
    frame = pd.DataFrame([{"timestamp": "yesterday-ish", "account": "a", "source_ip": "1.2.3.4", "action": "read", "status": "success"}])
    with pytest.raises(ValueError, match="timestamp"):
        normalize_events(frame)


def test_ioc_schema_is_checked():
    with pytest.raises(ValueError, match="IOC file"):
        detect(sample_events(), pd.DataFrame([{"ip": "203.0.113.77"}]))
