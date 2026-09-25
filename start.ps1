Write-Host "Starting CyberSentry Backend & Frontend..." -ForegroundColor Cyan
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\backend'; python app.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\frontend'; npm start"
Write-Host "CyberSentry services launched successfully!" -ForegroundColor Green
