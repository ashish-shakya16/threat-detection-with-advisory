# 🖥️ SecureX Desktop Application — Launch Guide

**Status:** ✅ Ready to Run  
**Version:** 1.2.0  
**Framework:** PyQt6

---

## Quick Start (2 Steps)

### Step 1: Install Dependencies
```bash
C:\Python313\python.exe -m pip install -r requirements-desktop.txt
```

### Step 2: Launch App
```bash
C:\Python313\python.exe desktop_app.py
```

Done! The desktop window opens with full threat monitoring.

---

## What Opens

A professional desktop application with:
- 📊 **Dashboard** — Real-time threat summary and system metrics
- 🚨 **Threats** — Full threat history with advanced filtering
- 📈 **Statistics** — Threat trends and analytics
- 🧠 **ML Model** — Train AI anomaly detector
- 📧 **Notifications** — Email alert setup
- ⚙️ Settings — Configuration options

---

## First Scan

1. Click **🔍 Scan Now** button (top-left)
2. Watch progress bar
3. View results in Dashboard tab
4. Check Threats tab for full details

**Takes 30-60 seconds for first scan.**

---

## Train AI Model

1. Run 5-10 scans (need 50+ threats minimum)
2. Click **🧠 Train ML Model** button
3. Wait 10-20 seconds for training
4. Status in ML tab changes to "Trained ✓"

---

## Enable Email Alerts

1. Go to **Notifications** tab
2. Enter email address
3. Click **Add**
4. Click **Send Test Notification**
5. Check your inbox (may be in spam)

---

## Documentation

- **Full Guide:** `docs/DESKTOP_APP.md` (600+ lines)
- **Quick Start:** `docs/DESKTOP_QUICKSTART.md` (2 minutes)
- **Summary:** `DESKTOP_APP_SUMMARY.md` (overview)

---

## System Requirements

- Python 3.8+
- 50MB disk space
- 150MB RAM
- Windows 10+, macOS 10.14+, or Linux

---

## Features

✅ Real-time monitoring  
✅ ML-based anomaly detection  
✅ Email notifications  
✅ System metrics display  
✅ Advanced threat search  
✅ Professional UI  
✅ Error handling  
✅ Production-ready  

---

## Troubleshooting

**App won't start?**
```bash
C:\Python313\python.exe -m pip install PyQt6 PyQt6-Charts
C:\Python313\python.exe desktop_app.py
```

**No threats showing?**
- Run multiple scans to collect data
- Check logs: `tail -f data/logs/app.log`

**ML model won't train?**
- Need 50+ threats: run 5-10 scans first
- Check ML tab for status

**Emails not sending?**
- Verify SMTP settings in `config/config.yaml`
- Use app-specific passwords for Gmail
- Check Notifications tab status

---

**Version:** 1.2.0  
**Status:** Production Ready ✅  
**Ready to Deploy** 🚀
