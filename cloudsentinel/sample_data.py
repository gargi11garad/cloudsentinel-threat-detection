"""Small synthetic audit-log fixture; all identities and addresses are fictional."""
import pandas as pd

def sample_events() -> pd.DataFrame:
    rows = []
    # 12 ordinary accounts with repeatable variation establish a baseline.
    for account_no in range(1, 13):
        account = f"user{account_no:02d}@example.test"
        for i in range(8):
            rows.append({"timestamp": f"2026-10-{10 + (i % 5):02d}T{9 + (i % 8):02d}:15:00Z", "account": account,
                         "source_ip": f"198.51.100.{10 + account_no}", "action": "ListObjects", "status": "success", "resource": "bucket:reports"})
    # Synthetic attack-like sequence, isolated to an invented account and TEST-NET addresses.
    for i in range(6):
        rows.append({"timestamp": f"2026-10-27T02:{i:02d}:00Z", "account": "analyst-demo@example.test", "source_ip": "203.0.113.77", "action": "ConsoleLogin", "status": "failure", "resource": "identity:demo"})
    rows.extend([
        {"timestamp": "2026-10-27T02:08:00Z", "account": "analyst-demo@example.test", "source_ip": "203.0.113.77", "action": "AttachAdminRole", "status": "success", "resource": "role:demo-admin"},
        {"timestamp": "2026-10-27T02:12:00Z", "account": "analyst-demo@example.test", "source_ip": "203.0.113.77", "action": "ListSecrets", "status": "success", "resource": "vault:demo"},
    ])
    return pd.DataFrame(rows)

def sample_iocs() -> pd.DataFrame:
    # Deliberately reserved documentation address, never a real-world threat indicator.
    return pd.DataFrame([{"indicator": "203.0.113.77", "type": "ip", "source": "CloudSentinel synthetic demo fixture", "retrieved_at": "2026-10-27T00:00:00Z"}])
