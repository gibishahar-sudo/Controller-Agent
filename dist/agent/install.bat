@echo off
echo Agent install - House B
echo Controller 176.229.98.54:4444 TLS
agent.exe -controller 176.229.98.54:4444 -ca server.crt -insecure
echo ---
echo For production:
echo   agent.exe -controller 176.229.98.54:4444 -ca server.crt
echo   agent.exe -controller 176.229.98.54:4444 -ca server.crt -fps 1
echo Persistence:
echo   agent.exe -persist
pause
