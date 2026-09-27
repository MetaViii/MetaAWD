@echo off
REM ============================================================
REM  AWD Defence Tool v3.1 - one click launcher (GUI)
REM  Keep this file pure ASCII: cmd decodes .bat with the
REM  code page active at startup, so non-ASCII here may break
REM  on systems whose default code page differs.
REM ============================================================
setlocal
cd /d "%~dp0"
title AWD Defence Tool v3.1

set "PY="
where python >nul 2>&1 && set "PY=python"
if not defined PY (
    where py >nul 2>&1 && set "PY=py"
)
if not defined PY (
    echo [ERROR] Python not found.
    echo         Please install Python 3.9+ and check "Add Python to PATH"
    echo         https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

%PY% launcher.py gui
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
    echo.
    echo [ERROR] Exited with code %RC%. See messages above.
    echo.
    pause
)

endlocal
