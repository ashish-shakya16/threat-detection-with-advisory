# Building the Windows Desktop .exe

Packages the desktop app (the real web dashboard embedded in a native
`QWebEngineView`, see [DESKTOP_APP.md](DESKTOP_APP.md)) into a standalone
Windows build via PyInstaller, so it can run on a machine without Python
installed.

## Prerequisites

```bash
pip install -r requirements-desktop.txt
pip install pyinstaller
cd frontend && npm install && npm run build && cd ..
```

The frontend must be built **before** packaging — `desktop_app.spec` bundles
whatever is currently in `frontend/dist/`.

## Build

```bash
pyinstaller desktop_app.spec --noconfirm
```

Output: `dist/SecureX Threat Advisor/SecureX Threat Advisor.exe`, plus an
`_internal/` folder holding the Qt6/QtWebEngine runtime and bundled
resources. Distribute the whole `SecureX Threat Advisor/` folder — the exe
does not work standalone without `_internal/` alongside it.

A full build takes several minutes and produces roughly 600MB, most of
which is the Chromium-based QtWebEngine runtime.

## Why `--onedir`, not `--onefile`

The spec builds `--onedir` on purpose. `--onefile` would re-extract the
entire ~500MB+ QtWebEngine runtime to a temp folder on **every launch**,
making startup slow and defeating the point of a native app. `--onedir`
keeps everything unpacked once, so subsequent launches are fast.

## Where things end up at runtime

PyInstaller's `--onedir` layout splits bundled content from the exe itself:

```
SecureX Threat Advisor/
├── SecureX Threat Advisor.exe
├── .env                          ← generated on first run (SECRET_KEY)
├── data/db/threats.db             ← created on first run
└── _internal/
    ├── config/                    ← bundled (read-only)
    ├── frontend/dist/             ← bundled (read-only)
    ├── assets_build/securex.ico   ← bundled (read-only)
    └── (Qt6/WebEngine runtime, Python stdlib, dependencies)
```

`desktop_app.py` distinguishes two locations when frozen:

- **`RESOURCE_DIR`** (`sys._MEIPASS`, i.e. `_internal/`) — where bundled
  read-only files (`config/`, `frontend/dist/`, the icon) are read from.
- **`APP_DIR`** (the exe's own folder) — where writable state lives:
  `.env` (the generated `SECRET_KEY`) and `data/db/threats.db` (via the
  `THREAT_DB_PATH` environment variable, set automatically when frozen).

This split matters because `_internal/` is bundle content — treating it as
writable would mean threat history and generated secrets vanish on a
reinstall/update of the app. In an unfrozen (`python desktop_app.py`)
dev run, both point at the same repo root, so this has no effect there.

## Why dependencies are excluded

The app's only real ML dependency is `sklearn.ensemble.IsolationForest`
(`src/ml_models/anomaly_detector.py`). PyInstaller's static analysis
nonetheless pulled in `torch`, `onnxruntime`, `pyarrow`, `numba`, and
`psycopg2` from site-packages — none of which any code here imports —
inflating the build from ~600MB to ~1.3GB. `desktop_app.spec`'s `excludes`
list drops them. If a future dependency genuinely needs one of these
packages, remove it from `excludes` rather than fighting PyInstaller.

## First run on a fresh machine

A freshly built exe has an empty database and **no user accounts** — there
is no in-app account-creation flow yet. Before distributing a build, either:

- Run `python scripts/create_admin_user.py <username> <email>` against the
  same `data/db/threats.db` the exe will use and ship that database file, or
- Document that the recipient must run the script themselves once (requires
  a Python environment — not currently possible from the packaged exe alone).

## Rebuilding after changes

Any frontend change requires `npm run build` before re-running PyInstaller
— the spec bundles whatever is in `frontend/dist/` at build time, it does
not watch for changes. Any change to `desktop_app.py` or `desktop_app.spec`
itself requires a full `pyinstaller desktop_app.spec --noconfirm` re-run.

## Troubleshooting

**Built exe prints "frontend build not found" and exits immediately**
The frontend wasn't built before packaging, or `frontend/dist` is missing
from `desktop_app.spec`'s `datas` list. Run `npm run build` and rebuild.

**Build balloons to 1GB+**
Check `desktop_app.spec`'s `excludes` list is still present — a dependency
update may have reintroduced one of the excluded packages transitively.

**`ImportError`/DLL error when importing `QWebEngineWidgets`**
`PyQt6-WebEngine`'s bundled Qt6 runtime must match `PyQt6-Qt6` exactly (see
[DESKTOP_APP.md](DESKTOP_APP.md)). Reinstall the pinned version in
`requirements-desktop.txt` before building.
