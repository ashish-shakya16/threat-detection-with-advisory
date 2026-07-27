# SecureX Desktop App — Quick Start (2 Minutes)

## Installation

```bash
# 1. Install desktop dependencies
pip install -r requirements-desktop.txt

# 2. Launch the app
python desktop_app.py
```

Done! The app window opens with full threat monitoring dashboard.

---

## Your First Scan

**Click 🔍 Scan Now**

Watch the status bar fill as SecureX:
- Scans your system for suspicious processes
- Monitors network activity
- Detects threats against 50+ security rules
- Scores each threat with AI/ML enrichment
- Shows results in Dashboard tab

First scan takes ~30-60 seconds. ✅

---

## What You See

### Dashboard Tab (Default)
```
┌─ Threat Summary ─────────────────────┐
│ Total: 3    🔴 Critical: 1    ⚠️ High: 2  │
├──────────────────────────────────────┤
│ System: CPU 35%  Memory 62%  Disk 45%│
├──────────────────────────────────────┤
│ Recent Threats (table)                │
│ - Suspicious Process | Critical | 0.95│
└──────────────────────────────────────┘
```

### Threats Tab
- See all detected threats
- Filter by severity (Critical/High/Medium/Low)
- Filter by time (1-168 hours)
- Double-click threat for full details

### Stats Tab
- Total threats, average risk score
- Threat timeline chart (24h view)
- By-severity breakdown

---

## Train the AI Model

**Click 🧠 Train ML Model**

This improves threat detection accuracy:
- Needs 50+ historical threats first
- Run 5-10 scans to collect data
- Training takes ~10-20 seconds
- Status shows "Trained ✓" when complete

---

## Enable Email Alerts (Optional)

1. Go to **Notifications** tab
2. Enter your email: `your@email.com`
3. Click **Add**
4. Click **Send Test Notification** to verify
5. Check your inbox (may be in spam)

**Setup Gmail:**
1. Enable 2FA: [myaccount.google.com/security](https://myaccount.google.com/security)
2. Create app password: [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
3. Paste 16-char password into `config/config.yaml`:
```yaml
notifications:
  enabled: true
  smtp:
    sender_password: "your-16-char-password"
```

---

## Interpret Threat Levels

| Level | Icon | Action |
|-------|------|--------|
| **Critical** | 🔴 | Check immediately |
| **High** | 🟠 | Investigate soon |
| **Medium** | 🟡 | Monitor |
| **Low** | 🟢 | FYI |

---

## Commands

| Button | Action |
|--------|--------|
| 🔍 **Scan Now** | Run threat detection scan |
| 🧠 **Train ML** | Train AI model (50+ threats needed) |
| 🗑️ **Clear Old** | Delete threats >30 days old |

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Q` | Quit app |

---

## Troubleshooting

**App won't start?**
```bash
pip install PyQt6 PyQt6-Charts
python desktop_app.py
```

**No threats detected?**
- Run multiple scans (events accumulate)
- Check logs: `tail -f data/logs/app.log`

**ML model won't train?**
- Need 50+ threats: run 5-10 scans first
- Check status: "Samples: X" in ML tab

**Email not sending?**
- Verify SMTP settings in `config/config.yaml`
- Gmail: use app password, not account password
- Check status in Notifications tab

---

## Next Steps

1. **Read full docs** → [DESKTOP_APP.md](DESKTOP_APP.md)
2. **View alerts** → Enable notifications
3. **Schedule scans** → Set monitoring interval
4. **Export data** → Check Statistics tab

---

**Version:** 1.2.0  
**Status:** Ready to use ✅
