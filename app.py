"""CloudSentinel Streamlit investigation console."""
import json

import pandas as pd
import streamlit as st

from cloudsentinel.engine import detect, investigation_report
from cloudsentinel.sample_data import sample_events, sample_iocs

st.set_page_config(page_title="CloudSentinel", page_icon="🛡️", layout="wide")
st.title("🛡️ CloudSentinel")
st.caption("Cloud audit event detection and investigation · synthetic data by default")

with st.sidebar:
    st.header("Data sources")
    uploaded_events = st.file_uploader("Audit events (CSV)", type="csv")
    uploaded_iocs = st.file_uploader("Threat indicators (CSV, optional)", type="csv")
    use_demo_ioc = st.checkbox("Include synthetic demo IOC", value=not bool(uploaded_iocs))
    contamination = st.slider("Anomaly fraction", 0.01, 0.40, 0.12, 0.01,
                               help="Isolation Forest setting, not an attack probability.")
    st.caption("Event columns: timestamp, account, source_ip, action, status; resource is optional.")

try:
    events = pd.read_csv(uploaded_events) if uploaded_events else sample_events()
    iocs = pd.read_csv(uploaded_iocs) if uploaded_iocs else (sample_iocs() if use_demo_ioc else pd.DataFrame())
    alerts, account_stats = detect(events, iocs, contamination)
except Exception as exc:
    st.error(f"Could not analyze this input: {exc}")
    st.stop()

a, b, c, d = st.columns(4)
a.metric("Events", len(events))
b.metric("Accounts", events["account"].nunique())
c.metric("Alerts", len(alerts))
d.metric("High severity", int((alerts.severity == "high").sum()) if not alerts.empty else 0)

st.info("Anomaly scores rank unusual behavior within this dataset. They are not probabilities and do not establish that an account is compromised.")
left, right = st.columns([1.05, 0.95])
with left:
    st.subheader("Detection alerts")
    if alerts.empty:
        st.success("No configured detections fired for this input.")
    else:
        st.dataframe(alerts, hide_index=True, use_container_width=True)
with right:
    st.subheader("Account behavior")
    st.dataframe(account_stats.reset_index(names="account"), hide_index=True, use_container_width=True)

if not alerts.empty:
    st.subheader("Investigation report")
    choices = alerts["alert_id"].tolist()
    selected_id = st.selectbox("Select an alert", choices)
    selected = alerts.loc[alerts.alert_id == selected_id].iloc[0]
    report = investigation_report(events, selected)
    st.json(report)
    st.download_button("Download report JSON", json.dumps(report, indent=2), f"{selected_id.lower()}-report.json", "application/json")

with st.expander("Detection logic and limitations"):
    st.markdown("""
    - **Authentication failures:** five or more failed events for one account in a rolling 15-minute window. Legitimate retries can trigger it; distributed failures across accounts are not detected.
    - **Privilege changes:** action names containing role, IAM, policy, admin, or privilege. This is a broad heuristic and may miss provider-specific names.
    - **Access pattern:** four or more distinct source IPs per account in the uploaded dataset. VPNs, NAT, and short datasets can make this noisy.
    - **Isolation Forest:** ranks accounts using request volume, failure rate, after-hours activity, and privilege-change count. Sparse datasets are not scored; scores depend on which peers are present.
    - **Threat intelligence:** compares uploaded IP indicators exactly. Verify source, age, and context before blocking; the built-in match is an invented documentation IP for demonstration only.
    """)

st.caption("For defensive research and triage only. Apply actions through your organization's approved incident process.")
