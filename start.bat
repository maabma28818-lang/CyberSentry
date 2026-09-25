@echo off
echo Starting CyberSentry Backend & Frontend...
start "CyberSentry Backend" cmd /k "cd /d %~dp0backend && python app.py"
start "CyberSentry Frontend" cmd /k "cd /d %~dp0frontend && npm start"
echo CyberSentry services launched!
