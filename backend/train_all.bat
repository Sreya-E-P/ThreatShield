@echo off
echo ========================================================
echo 🚀 THREATSHIELD - TRAIN EVERYTHING IN ONE GO
echo ========================================================
echo.

cd /d C:\Users\LENOVO\Desktop\threatshield-project\backend

echo Activating virtual environment...
call .\venv\Scripts\activate.bat

echo.
echo Installing requirements...
pip install -r requirements.txt

echo.
echo ========================================================
echo Starting ONE-SHOT training (this will take 2-4 hours)...
echo ========================================================
echo.

python scripts/one_shot_training.py

echo.
echo ========================================================
echo ✅ TRAINING COMPLETE!
echo ========================================================
pause