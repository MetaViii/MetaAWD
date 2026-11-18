@echo off
REM ============================================================
REM  MetaAWD desktop workspace launcher
REM  Keep this file pure ASCII: cmd decodes .bat with the
REM  code page active at startup, so non-ASCII here may break
REM  on systems whose default code page differs.
REM ============================================================
setlocal
pushd "%~dp0" || exit /b 1
title MetaAWD

set "DESKTOP_ARGS="
if /i "%~1"=="--check" set "DESKTOP_ARGS=--check"

set "PY="
if exist ".venv\Scripts\python.exe" set "PY=%CD%\.venv\Scripts\python.exe"
if not defined PY (
    where python >nul 2>&1 && set "PY=python"
)
if not defined PY (
    where py >nul 2>&1 && set "PY=py"
)
if not defined PY (
    echo [ERROR] Python not found.
    echo         Please install Python 3.9+ and check "Add Python to PATH"
    echo         https://www.python.org/downloads/
    echo.
    if not defined DESKTOP_ARGS pause
    popd
    exit /b 1
)

"%PY%" launcher.py desktop %DESKTOP_ARGS%
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
    echo.
    echo [ERROR] Exited with code %RC%. See messages above.
    echo.
    if not defined DESKTOP_ARGS pause
)

popd
endlocal & exit /b %RC%
