# SecureX v1.2 Quick Start Guide

Get SecureX v1.2 running in 10 minutes.

---

## 1. Initialize System

```bash
python main.py --init
# ✓ Directories created
# ✓ System initialized
```

---

## 2. Configure Notifications (Optional)

Edit `config/config.yaml`:

```yaml
notifications:
  enabled: true
  notify_on_critical: true
  notify_on_high: true
  recipients:
    - "your-email@example.com"
  smtp:
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    sender_email: "alerts@gmail.com"
    sender_password: "your-app-password"  # NOT your account password
```

**Gmail setup:**
1. Enable 2FA: myaccount.google.com/security
2. Generate app password: myaccount.google.com/apppasswords
3. Use 16-char password above

---

## 3. Run Single Scan

```bash
python main.py --scan
# --- Scan #1 ---
# Collected 15 events
# Detected 3 threats
# Scan complete: 3 threats detected
```

---

## 4. Train ML Model (Recommended)

Improves threat detection accuracy with anomaly scoring:

```bash
python main.py --train-ml
# Training ML anomaly detection model...
# ✓ ML model trained successfully
```

Check status:
```bash
python main.py --ml-status
# ML Model Status:
#   Trained: True
#   Status: Ready
#   Model Path: src/ml_models/saved_models/anomaly_detector.pkl
```

---

## 5. View Recent Threats

```bash
python main.py --list-threats --hours 24
# Recent Threats (last 24 hours)
# 1. [High] Suspicious Process Detected
#    Time: 2026-07-27T10:30:00
#    Category: System Monitoring
#    Risk Score: 0.85
```

---

## 6. View Statistics

```bash
python main.py --stats --hours 24
# Threat Statistics (last 24 hours)
# Total Threats: 5
# Active Critical Threats: 1
# 
# By Severity:
#   - Critical: 1
#   - High: 2
#   - Medium: 2
#   - Low: 0
```

---

## 7. Start Continuous Monitoring

```bash
python main.py --monitor --interval 5
# Starting continuous monitoring (interval: 5s)
# Press Ctrl+C to stop
# 
# --- Scan #1 ---
# --- Scan #2 ---
# ...
```

---

## 8. Dashboard (Optional)

Run in separate terminal:

```bash
python src/dashboard/app.py
# ==================== Cybersecurity Threat Advisor - Web Dashboard ====================
#   Dashboard URL: http://localhost:5000
#   Backend: Integrated monitoring system
#   Real-time: WebSocket enabled
# ==================================================================================
```

Visit: http://localhost:5000

**Dashboard Features:**
- Real-time threat feed
- Statistics dashboard
- Historical analytics
- AI security advisor
- Settings & configuration

---

## 9. Test Email Notifications

```bash
curl -X POST http://localhost:5000/api/notifications/test
# Response:
# {
#   "success": true,
#   "message": "Test notification sent"
# }
```

Check email inbox (may be in spam folder).

---

## 10. API Endpoints Cheat Sheet

### Threats
```bash
GET /api/threats                    # List recent threats
GET /api/threats/<id>               # Get threat details
PUT /api/threats/<id>/status        # Update threat status
```

### Statistics
```bash
GET /api/stats                      # Overall statistics
GET /api/threat-timeline            # Trends over time
```

### Notifications
```bash
GET /api/notifications/status       # Notification status
GET /api/notifications/recipients   # Current recipients
POST /api/notifications/recipients  # Add recipient
DELETE /api/notifications/recipients/<email>  # Remove recipient
POST /api/notifications/test        # Send test alert
```

### ML Model
```bash
GET /api/ml/status                  # Model status
POST /api/ml/train                  # Train model
POST /api/ml/predict                # Predict anomaly
```

### System
```bash
GET /api/system-metrics             # CPU, memory, disk
```

---

## Common Tasks

### Enable SMS Alerts

1. Create Twilio account (twilio.com)
2. Get SID and auth token
3. Add to config.yaml:

```yaml
sms:
  enabled: true
  account_sid: "your-sid"
  auth_token: "your-token"
  from_number: "+1234567890"
```

4. Restart monitoring

### Send Threats to SIEM

1. Configure webhook:

```yaml
webhooks:
  enabled: true
  endpoints:
    - "https://siem.company.com/api/events"
```

2. System automatically posts threats to endpoint

### Schedule Daily Digest

```python
# Add to your monitoring loop:
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()

def send_daily_digest():
    threats = db.get_recent_threats(limit=1000, hours=24)
    notification_manager.notify_digest(threats, 'daily')

scheduler.add_job(send_daily_digest, 'cron', hour=9, minute=0)
scheduler.start()
```

---

## Monitoring in Production

### Log File

```bash
tail -f data/logs/app.log

# Monitor specific events:
tail -f data/logs/app.log | grep -i "critical\|error\|notification"
```

### Database Queries

```python
from src.utils import Config
from src.database import DatabaseManager

db = DatabaseManager()

# Recent threats
threats = db.get_recent_threats(limit=10, hours=24)
print(f"Latest threat: {threats[0]['threat_name']}")

# Statistics
stats = db.get_threat_statistics(hours=24)
print(f"Total critical: {stats['by_severity'].get('Critical', 0)}")
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Scan shows no threats | Increase monitoring time or force event generation in config |
| Emails not sent | Check SMTP settings, verify sender email/password valid |
| ML model not training | Need 50+ historical events in database. Run multiple scans first. |
| Dashboard won't start | Check port 5000 available: `netstat -ano \| findstr 5000` |
| High CPU usage | Reduce monitoring interval in config.yaml |

---

## Next Steps

1. **Read Documentation** → `docs/EMAIL_NOTIFICATIONS.md` and `docs/V12_COMPLETE_FEATURES.md`
2. **Deploy to Production** → Secure credentials, enable logging, set up backups
3. **Integrate with SIEM** → Configure webhooks for your security platform
4. **Train Team** → Users can access dashboard for real-time alerts
5. **Monitor & Tune** → Adjust threat levels, notification rules as needed

---

**Version:** v1.2.0  
**Status:** Ready to Deploy 🚀
