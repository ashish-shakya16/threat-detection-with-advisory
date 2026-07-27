# SecureX Desktop Application

**Version:** 1.2.0  
**Status:** Ready to Use  
**Platform:** Windows, macOS, Linux

Professional desktop application for SecureX Threat Advisor with real-time monitoring, threat management, and ML model control.

---

## Installation

### Requirements
- Python 3.8+
- PyQt6 (desktop framework)
- 50MB disk space

### Setup

1. **Install desktop dependencies:**
```bash
pip install -r requirements-desktop.txt
```

2. **Launch the application:**
```bash
python desktop_app.py
```

That's it! The GUI window will open.

---

## Features

### 📊 Dashboard Tab
- **Threat Summary** — Total, critical, high, medium, low counts
- **System Metrics** — Real-time CPU, memory, disk usage
- **Recent Threats Table** — Last 10 threats with details
- **Auto-refresh** — Updates every 5 seconds

### 🚨 Threats Tab
- **Full Threat List** — All detected threats with filtering
- **Severity Filter** — Show only Critical/High/Medium/Low
- **Time Range Filter** — View threats from last N hours
- **Threat Details** — Double-click for full information
- **Advisory** — Security recommendations per threat

### 📈 Statistics Tab
- **Threat Metrics** — Total, average risk, detection rate
- **Timeline Chart** — Threat trends over 24 hours
- **By Severity** — Count breakdown by risk level

### 🧠 ML Model Tab
- **Model Status** — Trained/Not Trained
- **Sample Count** — Historical events used
- **Training History** — Recent training sessions
- **Reload** — Reload model from disk
- **Retrain** — Train on latest data (50+ samples needed)

### 📧 Notifications Tab
- **Notification Status** — Enabled/Disabled
- **Recipients List** — Current email recipients
- **Add Recipient** — Add new email address
- **Test Alert** — Send sample critical threat notification

### ⚙️ Settings Tab
- **Refresh Interval** — 5s, 10s, 30s, 1 minute options
- **Theme** — Light/Dark mode
- **Alert Sounds** — Toggle sound notifications
- **Database Path** — View/optimize database
- **About** — Application version and status

---

## Operations

### Run a Threat Scan

1. Click **🔍 Scan Now** button
2. Monitor progress in status bar
3. View results in Dashboard or Threats tabs
4. Critical threats show popup alert

**Scan Time:** ~30-60 seconds depending on system size

### Train ML Model

1. Click **🧠 Train ML Model** button
2. Requires 50+ historical threats in database
3. Model saves automatically
4. Status updates in ML Model tab

**Training Time:** ~10-20 seconds for 100+ samples

### Manage Email Recipients

1. Go to **Notifications** tab
2. Enter email in text field
3. Click **Add** button
4. Recipient added to list
5. Click **Send Test Notification** to verify

### View Threat Details

1. Go to **Threats** tab
2. Double-click any threat in table
3. Popup shows:
   - Full threat name & category
   - Risk score & severity
   - Detection time
   - Description & advisory

### Filter Threats

**By Severity:**
1. Select severity in dropdown (Critical/High/Medium/Low)
2. Table updates instantly

**By Time Range:**
1. Adjust "Hours" spinner (1-168 hours)
2. Table shows threats from that period

---

## Dashboard Interpretation

### Threat Summary Colors
- 🔴 **Critical** (Red) — Immediate action required
- 🟠 **High** (Orange) — Investigate soon
- 🟡 **Medium** (Yellow) — Monitor closely
- 🟢 **Low** (Green) — Note for records

### Risk Scores
- **0.75-1.0** — Critical (rule-based + ML)
- **0.50-0.75** — High
- **0.25-0.50** — Medium
- **0.0-0.25** — Low

### System Metrics
- **CPU:** Green <70%, Yellow 70-90%, Red >90%
- **Memory:** Green <80%, Yellow 80-95%, Red >95%
- **Disk:** Green <90%, Yellow 90-95%, Red >95%

---

## Configuration

Desktop app reads from `config/config.yaml`. Key settings:

```yaml
# Monitoring
monitoring:
  system:
    interval: 5  # Scan interval in seconds
    
# Database
database:
  path: "data/db/threats.db"
  
# Notifications (optional)
notifications:
  enabled: true
  recipients:
    - "security@company.com"
  smtp:
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    sender_email: "alerts@gmail.com"
    sender_password: "your-app-password"
```

Changes take effect on next scan/refresh.

---

## Troubleshooting

### App Won't Start

**"ModuleNotFoundError: No module named 'PyQt6'"**
```bash
pip install -r requirements-desktop.txt
```

**"No module named 'psutil'"**
```bash
pip install psutil
```

### Scan Shows No Threats

1. Check if monitoring is enabled in config
2. Run multiple scans to collect events
3. Ensure rules.json is loaded correctly
4. Check logs: `tail -f data/logs/app.log`

### ML Model Won't Train

**"Insufficient Data"** — Need 50+ threats:
- Run scans repeatedly to accumulate data
- Wait for background events to generate threats

**"Feature extraction failed"** — Invalid threat data:
- Ensure threats have required fields
- Check database integrity: click Optimize

### Notifications Not Working

1. Verify `notifications.enabled: true` in config
2. Test SMTP settings (Gmail needs app password)
3. Check firewall allows SMTP port 587
4. View logs for delivery errors

### High CPU Usage

1. Increase scan interval in config (default 5s)
2. Reduce number of processes monitored
3. Disable unnecessary monitors in config

---

## Performance

### Typical Metrics
- **Scan Time:** 30-60 seconds
- **Threat Processing:** <100ms per threat
- **Dashboard Refresh:** <1 second
- **ML Training:** 10-20 seconds (100+ samples)
- **Memory Usage:** 100-200MB idle

### Optimization Tips
1. Scan interval — Increase from 5s to 30s if not critical monitoring
2. Database — Click Optimize in Settings to clean old data
3. Chart rendering — Switch to summary view for large datasets
4. Historical data — Archive threats older than 30 days

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Shift+S` | Start scan |
| `Ctrl+Shift+M` | Train ML model |
| `Ctrl+R` | Refresh data |
| `Ctrl+Q` | Exit application |

---

## Data Privacy

- **No cloud uploads** — All data stays local
- **No telemetry** — No usage tracking
- **Encrypted storage** — Database uses SQLite with optional encryption
- **Credential security** — SMTP passwords stored in config only (use env vars)

**Recommendation:** Use environment variables for sensitive credentials:
```bash
export SENDER_PASSWORD="your-app-password"
```

Then in config:
```yaml
sender_password: ${SENDER_PASSWORD}
```

---

## Advanced Usage

### Custom Monitoring

Extend the ScanWorker class in `src/desktop/main_window.py`:

```python
class CustomScanWorker(ScanWorker):
    def run(self):
        # Add custom monitoring logic
        custom_events = self.monitor_custom_source()
        # Process events...
```

### Database Queries

Access threat data directly:

```python
from src.database.db_manager import DatabaseManager

db = DatabaseManager('data/db/threats.db')
threats = db.get_recent_threats(limit=100, hours=24)
stats = db.get_threat_statistics()
```

### ML Model Integration

Use trained model outside dashboard:

```python
from src.ml_models.ml_integration import MLIntegration

ml = MLIntegration()
risk_score = ml.calculate_ml_risk_score(event)
threat = ml.enrich_threat_with_ml_score(threat, risk_score)
```

---

## Support & Issues

### Check Application Logs
```bash
tail -f data/logs/app.log | grep -i "error\|warning"
```

### Run in Debug Mode
```bash
python desktop_app.py --debug
```

### Report Issues
1. Capture log output
2. Note system specs (OS, Python version)
3. Include error message
4. Submit at: https://github.com/cybersecurity-threat-advisor/issues

---

## Roadmap (v1.3)

- [ ] Dark mode theme
- [ ] Custom dashboards
- [ ] Alert notifications (system tray)
- [ ] Export reports (PDF, CSV)
- [ ] Remote monitoring (multiple machines)
- [ ] Performance graphs (historical charts)
- [ ] Threat correlation analysis
- [ ] Predictive alerts (ML forecasting)

---

**Version:** 1.2.0  
**Last Updated:** 2026-07-27  
**Status:** Production Ready ✅
