# SecureX Desktop App — Quick Start

## What This Is

The desktop app is the same React/Flask web dashboard, opened in a native
window instead of a browser tab. There is no separate desktop UI to learn —
whatever you can do on the web dashboard (Dashboard, Threats, Analytics, AI
Assistant, Settings) works identically here.

## Installation

```bash
# 1. Build the frontend once (only needed after pulling frontend changes)
cd frontend && npm install && npm run build && cd ..

# 2. Install desktop dependencies
pip install -r requirements-desktop.txt

# 3. Launch the app
python desktop_app.py
```

On first launch, a `SECRET_KEY` is generated automatically and saved to
`.env` in the project root so your session survives app restarts. If a Flask
server is already running on `127.0.0.1:5000` (e.g. from `python
src/dashboard/app.py`), the desktop app reuses it instead of starting a
second one.

## Using It

Log in with an existing account (see `scripts/create_admin_user.py` if you
need to create one), then use the sidebar exactly as on the web dashboard:

- **Dashboard** — run a scan, start/stop monitoring, view live stats
- **Threats** — filter and inspect detected threats
- **Analytics** — trend charts, category/risk breakdowns
- **AI Assistant** — chat about detected threats
- **Settings** — system info, notification recipients

## Troubleshooting

**App won't start / `ModuleNotFoundError: PyQt6.QtWebEngineWidgets`**
```bash
pip install -r requirements-desktop.txt
```
If it still fails to import with a DLL error, `PyQt6-WebEngine`'s Qt6
runtime version must match `PyQt6-Qt6` exactly — reinstall the exact pinned
version: `pip install --force-reinstall PyQt6-WebEngine==6.7.0`.

**"frontend build not found" error on launch**
```bash
cd frontend && npm run build
```

**Blank window / stuck loading**
Check that nothing else is already listening on port 5000 in a broken state:
```bash
netstat -ano | findstr :5000
```

**Backend errors on first run**
Check `data/logs/app.log` — the desktop app runs the identical Flask backend,
so any error there behaves exactly like the web dashboard.

---

**Version:** 1.2.0
