@echo off
setlocal enabledelayedexpansion

:: --- CONFIGURATION ---
set VENV_DIR=.venv
set FLUTTER_APP_DIR=virus_repo
set GENERATE_COUNT=10
set MAX_SIZE_KB=512

:: --- ARGUMENT HANDLING ---
if "%~1"=="help" goto :display_help
if "%~1"=="--help" goto :display_help
if "%~1"=="-h" goto :display_help

echo ===================================================
echo      VIRUS REPOSITORY - start.bat
echo ===================================================

:: 1. ENVIRONMENT CHECK
echo [*] Checking environment...
where python >nul 2>nul || goto :error_python
echo [+] Python found.

:: 2. VIRTUALENV SETUP
if exist %VENV_DIR%\Scripts\activate.bat goto :activate_venv
echo [*] Creating virtual environment...
python -m venv %VENV_DIR% || goto :error_venv

:activate_venv
echo [*] Activating virtual environment...
call %VENV_DIR%\Scripts\activate.bat || goto :error_venv

echo [*] Installing dependencies...
pip install -r requirements.txt >nul || goto :error_deps

:: 3. BATCH PROCESS
echo.
echo [1/4] Clearing previous data...
python cleanup.py --cloud --local || goto :error_step

echo.
echo [2/4] Generating %GENERATE_COUNT% files (max size %MAX_SIZE_KB% KB)...
:: Note: If generator.py still fails, check if it accepts floats for --max-size
python generator.py --count %GENERATE_COUNT% --max-size %MAX_SIZE_KB% || goto :error_step

echo.
echo [3/4] Firebase Upload...
python uploader.py || goto :error_step

:: 4. RUNNING FLUTTER
echo.
echo [4/4] Running Flutter application...
where flutter >nul 2>nul || (echo [WARN] Flutter not in PATH & goto :end_script)

if not exist %FLUTTER_APP_DIR% goto :error_no_flutter_dir

pushd %FLUTTER_APP_DIR%
echo      (Press 'q' in the Flutter window to quit)
call flutter run
popd

:end_script
echo.
echo [DONE] Script has completed successfully.
exit /b 0

:: --- ERROR HANDLING ---

:error_python
echo [ERROR] Python is not installed or not in PATH.
pause
exit /b 1

:error_venv
echo [ERROR] Error during VENV creation or activation.
pause
exit /b 1

:error_deps
echo [ERROR] Failed to install dependencies.
pause
exit /b 1

:error_step
echo.
echo [CRITICAL ERROR] The previous Python script failed. 
echo Execution halted to prevent data corruption.
pause
exit /b 1

:error_no_flutter_dir
echo [ERROR] Flutter directory %FLUTTER_APP_DIR% not found.
pause
exit /b 1

:display_help
echo.
echo Usage: start.bat [help ^| --help ^| -h]
echo The script automates the data pipeline from generator to application.
exit /b 0