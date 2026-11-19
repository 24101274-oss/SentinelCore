@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Primero instala las dependencias siguiendo README.md.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m lab.local --lan --block-seconds 60
pause
