# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for the SecureX Threat Advisor desktop app.

Build with: pyinstaller desktop_app.spec
Output: dist/SecureX Threat Advisor/SecureX Threat Advisor.exe (--onedir)

--onedir (not --onefile) is intentional: the app embeds a ~400MB QtWebEngine
Chromium runtime, which --onefile would re-extract to a temp folder on every
launch. --onedir keeps it unpacked alongside the exe for fast startup.
"""

import os

block_cipher = None

ROOT = os.path.abspath(os.getcwd())

datas = [
    (os.path.join(ROOT, "config"), "config"),
    (os.path.join(ROOT, "frontend", "dist"), os.path.join("frontend", "dist")),
    (os.path.join(ROOT, "frontend", "public", "favicon.svg"), os.path.join("frontend", "public")),
    (os.path.join(ROOT, "assets_build", "securex.ico"), "assets_build"),
]

a = Analysis(
    ["desktop_app.py"],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "engineio.async_drivers.threading",
        "src.dashboard.routes.api_threats",
        "src.dashboard.routes.api_stats",
        "src.dashboard.routes.api_analytics",
        "src.dashboard.routes.api_notifications",
        "src.dashboard.routes.api_ml",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # The app only uses sklearn.ensemble.IsolationForest (src/ml_models) —
    # these are unrelated packages PyInstaller's sklearn/scipy hooks pull in
    # transitively from site-packages even though no code here imports them.
    # Excluding them cuts the build from ~1.3GB to a fraction of that.
    excludes=[
        "torch", "torchvision", "torchaudio",
        "onnxruntime",
        "pyarrow",
        "numba", "llvmlite",
        "psycopg2", "psycopg2_binary",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SecureX Threat Advisor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(ROOT, "assets_build", "securex.ico") if os.path.exists(
        os.path.join(ROOT, "assets_build", "securex.ico")
    ) else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="SecureX Threat Advisor",
)
