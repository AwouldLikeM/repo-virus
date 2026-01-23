@echo off
setlocal enabledelayedexpansion

:: --- KONFIGURACJA ---
set VENV_DIR=.venv
set FLUTTER_APP_DIR=virus_repo
set GENERATE_COUNT=10
set MAX_SIZE_MB=0.3

:: --- OBSLUGA ARGUMENTOW ---
if "%~1"=="help" goto :display_help
if "%~1"=="--help" goto :display_help
if "%~1"=="-h" goto :display_help

echo ===================================================
echo     VIRUS REPOSITORY - AUTOMATION SCRIPT v0.1
echo ===================================================

:: 1. SPRAWDZANIE SRODOWISKA
echo [*] Sprawdzanie srodowiska...

where python >nul 2>nul
if errorlevel 1 goto :error_python
echo [+] Python znaleziony.

:: 2. KONFIGURACJA VIRTUALENV
if exist %VENV_DIR%\Scripts\activate.bat goto :activate_venv
echo [*] Tworzenie wirtualnego srodowiska...
python -m venv %VENV_DIR%

:activate_venv
echo [*] Aktywacja srodowiska...
call %VENV_DIR%\Scripts\activate.bat
if errorlevel 1 goto :error_venv

echo [*] Instalacja zaleznosci...
pip install -r requirements.txt >nul

:: 3. PROCES BATCH
echo.
echo [1/4] Czyszczenie srodowiska...
python cleanup.py --cloud

echo.
echo [2/4] Generowanie %GENERATE_COUNT% probek...
python generator.py --count %GENERATE_COUNT% --max-size %MAX_SIZE_MB%

echo.
echo [3/4] Uploadowanie do Firebase...
python uploader.py

:: 4. URUCHOMIENIE FLUTTERA
echo.
echo [4/4] Uruchamianie aplikacji Flutter...
where flutter >nul 2>nul
if errorlevel 1 echo [WARN] Flutter nie jest w PATH. & goto :end_script

if not exist %FLUTTER_APP_DIR% goto :error_no_flutter_dir

pushd %FLUTTER_APP_DIR%
echo     (Wcisnij 'q' w oknie Fluttera aby zakonczyc)
call flutter run
popd

:end_script
echo.
echo [DONE] Skrypt zakonczyl dzialanie.
exit /b 0

:: --- OBSLUGA BLEDOW ---
:error_python
echo [ERROR] Python nie jest zainstalowany lub nie ma go w PATH.
pause
exit /b 1

:error_venv
echo [ERROR] Blad podczas aktywacji VENV.
pause
exit /b 1

:error_no_flutter_dir
echo [ERROR] Nie znaleziono folderu %FLUTTER_APP_DIR%
pause
exit /b 1

:display_help
echo.
echo Uzycie: start.bat [help ^| --help ^| -h]
echo Skrypt automatyzuje potok danych od generatora do aplikacji.
exit /b 0