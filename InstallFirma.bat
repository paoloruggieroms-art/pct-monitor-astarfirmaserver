@echo off
chcp 65001 >nul
title Installazione Firma Digitale CNS

echo.
echo  ╔══════════════════════════════════════════════╗
echo  ║   INSTALLAZIONE FIRMA DIGITALE CNS          ║
echo  ║   Studio Legale - PCT Monitor                ║
echo  ╚══════════════════════════════════════════════╝
echo.

set SCRIPT_DIR=%~dp0
set STARTUP_LINK=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\FirmaDigitale.vbs
set OPENSC_URL=https://github.com/OpenSC/OpenSC/releases/download/0.25.1/OpenSC-0.25.1_win64.msi
set OPENSC_MSI=%TEMP%\OpenSC-0.25.1_win64.msi
set PKCS11_TOOL=C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe

:: ============================================
:: STEP 1: Verifica/Installa OpenSC
:: ============================================
echo [1/4] Verifica OpenSC...
if exist "%PKCS11_TOOL%" (
    echo       OpenSC gia' installato. OK
) else (
    echo       OpenSC non trovato. Download in corso...
    powershell -Command "Invoke-WebRequest -Uri '%OPENSC_URL%' -OutFile '%OPENSC_MSI%'" 2>nul
    if exist "%OPENSC_MSI%" (
        echo       Installazione OpenSC...
        msiexec /i "%OPENSC_MSI%" /quiet /norestart
        timeout /t 5 /nobreak >nul
        if exist "%PKCS11_TOOL%" (
            echo       OpenSC installato con successo!
        ) else (
            echo       ATTENZIONE: Installazione automatica fallita.
            echo       Installa manualmente da: %OPENSC_URL%
            echo       Poi riesegui questo script.
            pause
            exit /b 1
        )
    ) else (
        echo       ERRORE: Download fallito. Verifica la connessione internet.
        echo       Scarica manualmente: %OPENSC_URL%
        pause
        exit /b 1
    )
)

:: ============================================
:: STEP 2: Esclusioni Windows Defender
:: ============================================
echo [2/4] Configurazione Windows Defender...
powershell -Command "Add-MpPreference -ExclusionPath '%SCRIPT_DIR%'" 2>nul
powershell -Command "Add-MpPreference -ExclusionPath '%TEMP%\firma_digitale'" 2>nul
echo       Esclusioni configurate. OK

:: ============================================
:: STEP 3: Avvio automatico (nascosto)
:: ============================================
echo [3/4] Configurazione avvio automatico...
echo Set WshShell = CreateObject("WScript.Shell") > "%STARTUP_LINK%"
echo WshShell.Run "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File ""%SCRIPT_DIR%firma_server.ps1""", 0, False >> "%STARTUP_LINK%"
echo       Avvio automatico configurato. OK

:: ============================================
:: STEP 4: Crea collegamento Desktop
:: ============================================
echo [4/4] Creazione collegamento sul Desktop...
powershell -Command "$WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut([Environment]::GetFolderPath('Desktop') + '\Firma Digitale CNS.lnk'); $Shortcut.TargetPath = 'wscript.exe'; $Shortcut.Arguments = '\"%SCRIPT_DIR%AvviaFirma.vbs\"'; $Shortcut.WorkingDirectory = '%SCRIPT_DIR%'; $Shortcut.IconLocation = 'shell32.dll,48'; $Shortcut.Description = 'Avvia il servizio Firma Digitale CNS (background)'; $Shortcut.Save()"
echo       Collegamento creato sul Desktop. OK

:: ============================================
:: COMPLETATO
:: ============================================
echo.
echo  ============================================
echo    INSTALLAZIONE COMPLETATA CON SUCCESSO!
echo  ============================================
echo.
echo  Il servizio si avvia automaticamente con Windows.
echo  Se necessario, puoi avviarlo manualmente dal
echo  collegamento "Firma Digitale CNS" sul Desktop.
echo.
echo  Requisiti per firmare:
echo    - Smart card CNS inserita nel lettore
echo    - Browser aperto sulla pagina Firma Digitale
echo.
echo  Avvio del servizio in corso...
echo.

:: Avvia il servizio in background (nessuna finestra da chiudere)
wscript "%SCRIPT_DIR%AvviaFirma.vbs"

echo  Servizio avviato! Puoi chiudere questa finestra.
echo.
timeout /t 5
