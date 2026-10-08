@echo off
chcp 65001 >nul
title Firma Digitale CNS - Riavvio

:: Termina eventuali istanze precedenti
taskkill /f /fi "WINDOWTITLE eq Firma Digitale CNS" >nul 2>&1
powershell -Command "Get-Process powershell | Where-Object { $_.MainWindowTitle -eq '' -and $_.CommandLine -like '*firma_server*' } | Stop-Process -Force" 2>nul

:: Avvia in background (nascosto)
cscript //nologo "%~dp0AvviaFirma.vbs"

echo.
echo  Servizio Firma Digitale avviato in background!
echo  (questa finestra si chiude in 3 secondi)
echo.
timeout /t 3 >nul
