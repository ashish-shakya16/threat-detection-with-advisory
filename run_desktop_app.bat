@echo off
setlocal
set "APP_DIR=%~dp0dist\SecureX Threat Advisor"
set "APP_EXE=%APP_DIR%\SecureX Threat Advisor.exe"

if not exist "%APP_EXE%" (
    echo Desktop build not found.
    echo Run: pyinstaller desktop_app.spec --noconfirm
    exit /b 1
)

start "SecureX Threat Advisor" "%APP_EXE%"
endlocal
