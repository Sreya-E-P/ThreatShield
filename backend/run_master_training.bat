@echo off
echo ========================================================
echo    ULTIMATE THREATSHIELD TRAINING - ONE COMMAND
echo ========================================================
echo.
echo This will train everything with optimal parameters:
echo   • 1,000,000 synthetic threats
echo   • Real API data from MISP, VirusTotal, AlienVault
echo   • Zero-day predictor: 500 epochs
echo   • Defense agent: 10,000 episodes
echo.
echo Estimated time: 4-6 hours
echo.
pause

cd /d C:\Users\LENOVO\Desktop\threatshield-project\backend
call .\venv\Scripts\activate.bat

echo.
echo ========================================================
echo Starting ULTIMATE training...
echo ========================================================
echo.

python scripts\train_everything.py

echo.
echo ========================================================
echo Training complete! Check the logs for details.
echo ========================================================
pause