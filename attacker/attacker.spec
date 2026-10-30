# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for the SecureX Attack Tester (separate from the main app).

Build with: pyinstaller attacker/attacker.spec
Output: dist/SecureX Attack Tester.exe (single file, standard library only)
"""

import os

HERE = os.path.abspath(SPECPATH)

a = Analysis(
    [os.path.join(HERE, "attacker_app.py")],
    pathex=[HERE],
    hiddenimports=["simulator"],
    excludes=["numpy", "scipy", "sklearn", "pandas", "PyQt6", "PIL", "matplotlib"],
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name="SecureX Attack Tester",
    console=False,
    upx=False,
)
