@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  py -3 -m venv .venv
  if errorlevel 1 goto failed
  .venv\Scripts\python.exe -m pip install -e ".[test]" -c requirements-lock.txt
  if errorlevel 1 goto failed
)
echo Open http://127.0.0.1:8766 after the server starts. Press Ctrl+C to stop.
.venv\Scripts\python.exe -m signaldesk.cli serve
if errorlevel 1 goto failed
exit /b 0
:failed
echo Startup failed. Check Python 3.11+ and the error above. See README.md for setup.
pause
exit /b 1
