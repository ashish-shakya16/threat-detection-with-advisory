# SecureX Desktop Application

**Version:** 1.2.0
**Platform:** Windows, macOS, Linux

The desktop app is the same React/Flask web dashboard, embedded in a native
window via `QWebEngineView` (PyQt6's Chromium-based web view) instead of a
separate hand-built GUI. There is exactly one UI to maintain — everything on
the web dashboard (Dashboard, Threats, Analytics, AI Assistant, Settings)
works identically here, with no feature gap between the two.

See [DESKTOP_QUICKSTART.md](DESKTOP_QUICKSTART.md) for setup and usage, or
[BUILD_EXE.md](BUILD_EXE.md) to package it into a standalone Windows `.exe`.

## Architecture

`desktop_app.py`:
1. Ensures a `SECRET_KEY` exists (generates and persists one to `.env` on
   first run if missing — the desktop app has no shell for an operator to
   export it in beforehand).
2. Checks whether a Flask server is already listening on `127.0.0.1:5000`;
   if not, imports and runs `src.dashboard.app` (the identical backend the
   web dashboard uses) in a background thread.
3. Opens a `QWebEngineView` window pointed at that server.

No business logic, routes, or database access live in the desktop layer —
`desktop_app.py` only handles process bootstrapping and window creation.

## Requirements

- Python 3.8+
- `PyQt6` + `PyQt6-WebEngine` (must be matching versions — see
  `requirements-desktop.txt` for why the exact pin matters)
- The frontend built at least once: `cd frontend && npm run build`

## Why PyQt6-WebEngine needs an exact version pin

`PyQt6-WebEngine`'s bundled Qt6 runtime must match `PyQt6-Qt6`'s version
exactly. Installing the latest `PyQt6-WebEngine` alongside an older `PyQt6`
pulls a mismatched Qt6 build and fails to import with a DLL/procedure-not-found
error on Windows. `requirements-desktop.txt` pins both to `6.7.0` /
`PyQt6-Qt6 6.7.3` to keep them in lockstep.

## Troubleshooting

See the Troubleshooting section in
[DESKTOP_QUICKSTART.md](DESKTOP_QUICKSTART.md).
