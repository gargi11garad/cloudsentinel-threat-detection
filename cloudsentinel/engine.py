"""Transparent rules, behavioral anomaly scoring, IOC matching, and reports."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURES = ["request_count", "failed_login_rate", "after_hours_rate", "privilege_changes"]


def _truth(value: Any) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def normalize_events(frame: pd.DataFrame) -> pd.DataFrame:
    """Validate and normalize the accepted event schema."""
    required = {"timestamp", "account", "source_ip", "action", "status"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"Missing required event columns: {', '.join(sorted(missing))}")
    out = frame.copy()
    out["timestamp"] = pd.to_datetime(out["timestamp"], utc=True, errors="coerce")
    if out["timestamp"].isna().any():
        raise ValueError("Every timestamp must be a valid date/time.")
    for col in ("account", "source_ip", "action", "status"):
        out[col] = out[col].fillna("").astype(str).str.strip()
    if (out[["account", "source_ip", "action", "status"]] == "").any().any():
        raise ValueError("Account, source_ip, action, and status cannot be blank.")
    if "resource" not in out:
        out["resource"] = "unknown"
    else:
        out["resource"] = out["resource"].fillna("unknown").astype(str)
    out["is_failure"] = out["status"].str.lower().isin({"failure", "failed", "denied", "blocked"})
    out["is_privilege_change"] = out["action"].str.lower().str.contains(r"privilege|role|iam|policy|admin", regex=True)
    out["is_after_hours"] = (out["timestamp"].dt.hour < 6) | (out["timestamp"].dt.hour >= 22)
    if "request_count" not in out:
        out["request_count"] = 1
    out["request_count"] = pd.to_numeric(out["request_count"], errors="coerce").fillna(1).clip(lower=0)
    return out.sort_values("timestamp").reset_index(drop=True)


def _features(events: pd.DataFrame) -> pd.DataFrame:
    return events.groupby("account", sort=False).apply(
        lambda g: pd.Series({
            "request_count": g["request_count"].sum(),
            "failed_login_rate": g["is_failure"].mean(),
            "after_hours_rate": g["is_after_hours"].mean(),
            "privilege_changes": g["is_privilege_change"].sum(),
        }), include_groups=False
    ).reindex(columns=FEATURES).fillna(0)


def detect(events: pd.DataFrame, iocs: pd.DataFrame | None = None, contamination: float = 0.12) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return account-level alerts and account feature rows with anomaly scores."""
    events = normalize_events(events)
    stats = _features(events)
    # A fixed random seed and explicit feature matrix make the demo reproducible.
    scaled = StandardScaler().fit_transform(stats[FEATURES])
    if len(stats) >= 5:
        model = IsolationForest(n_estimators=150, contamination=min(max(contamination, 0.01), 0.49), random_state=42)
        model.fit(scaled)
        stats["anomaly_score"] = -model.decision_function(scaled)
        stats["is_anomaly"] = model.predict(scaled) == -1
    else:
        stats["anomaly_score"] = 0.0
        stats["is_anomaly"] = False
    stats["is_anomaly"] = stats["is_anomaly"].astype(bool)
    alerts: list[dict[str, Any]] = []

    def add(account: str, kind: str, reason: str, evidence: str, severity: str, confidence: str) -> None:
        alerts.append({"alert_id": f"CS-{len(alerts)+1:04d}", "account": account, "type": kind, "reason": reason,
                       "evidence": evidence, "severity": severity, "confidence": confidence})

    # Windows use the latest 15 minutes per account. Thresholds are demo defaults, not universal policy.
    for account, group in events.groupby("account"):
        group = group.sort_values("timestamp")
        failed = group[group["is_failure"]]
        burst = False
        for idx, row in failed.iterrows():
            n = failed[(failed["timestamp"] >= row["timestamp"] - pd.Timedelta(minutes=15)) & (failed["timestamp"] <= row["timestamp"])].shape[0]
            if n >= 5:
                burst = True
                break
        if burst:
            add(account, "authentication_failures", "Five or more failed events within 15 minutes.", f"{len(failed)} failed event(s); threshold reached in a 15-minute window.", "high", "medium")
        priv = group[group["is_privilege_change"]]
        if not priv.empty:
            add(account, "privilege_change", "A role, IAM, policy, admin, or privilege change was observed.", f"{len(priv)} privilege-related event(s); latest: {priv.iloc[-1]['action']}.", "high", "medium")
        if group["source_ip"].nunique() >= 4:
            add(account, "access_pattern", "The account accessed the system from at least four source IPs in this dataset.", f"{group['source_ip'].nunique()} distinct source IPs observed.", "medium", "low")

    for account, row in stats[stats["is_anomaly"]].iterrows():
        add(account, "behavioral_anomaly", "Activity differs from other accounts in this dataset.",
            f"Isolation Forest anomaly score {row['anomaly_score']:.3f}; features: requests={row['request_count']:.0f}, failure_rate={row['failed_login_rate']:.0%}, after_hours={row['after_hours_rate']:.0%}, privilege_changes={row['privilege_changes']:.0f}.", "medium", "low")

    if iocs is not None and not iocs.empty:
        required = {"indicator", "type", "source"}
        if not required.issubset(iocs.columns):
            raise ValueError("IOC file must include indicator, type, source columns.")
        lookup = {str(r.indicator).strip().lower(): r for r in iocs.itertuples()}
        for account, group in events.groupby("account"):
            matches = []
            for ip in group["source_ip"].unique():
                if ip.lower() in lookup and str(lookup[ip.lower()].type).lower() in {"ip", "ipv4", "ipv6", "ip_address"}:
                    matches.append(ip)
            for ip in matches:
                src = lookup[ip.lower()]
                add(account, "threat_intel_match", f"Observed source IP matches an uploaded indicator: {ip}.", f"Indicator {ip}; source: {src.source}; retrieved_at: {getattr(src, 'retrieved_at', 'not provided')}.", "high", "medium")
    alert_frame = pd.DataFrame(alerts, columns=["alert_id", "account", "type", "reason", "evidence", "severity", "confidence"])
    return alert_frame, stats.sort_values("anomaly_score", ascending=False)


def investigation_report(events: pd.DataFrame, alert: pd.Series) -> dict[str, Any]:
    """Build a compact evidence-backed report for one alert."""
    normalized = normalize_events(events)
    timeline = normalized[normalized.account == alert["account"]]
    recs = {
        "authentication_failures": "Review identity provider sign-in logs, verify the user through a trusted channel, and apply rate limiting or a temporary lockout if policy permits.",
        "privilege_change": "Verify the change with its owner, inspect the change request and actor session, then revert unauthorized grants and rotate affected credentials.",
        "access_pattern": "Confirm expected egress/VPN routes with the account owner and investigate unfamiliar sessions or access locations.",
        "behavioral_anomaly": "Compare the activity with this account's longer-term baseline and adjacent service events before taking action; an anomaly score alone does not prove compromise.",
        "threat_intel_match": "Validate indicator freshness and source reliability, preserve relevant logs, and investigate related sessions before blocking the address.",
    }
    return {"alert_id": alert["alert_id"], "account": alert["account"], "affected_resources": sorted(timeline.resource.unique().tolist()),
            "type": alert["type"], "reason": alert["reason"], "evidence": alert["evidence"], "severity": alert["severity"],
            "confidence": alert["confidence"], "recommended_actions": recs.get(alert["type"], "Review the supporting events and verify with the system owner."),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "timeline": timeline[["timestamp", "source_ip", "action", "status", "resource"]].astype({"timestamp": str}).to_dict(orient="records")}
