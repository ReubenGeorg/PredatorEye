@echo off
echo ============================================
echo   PredatorEye  --  Desktop App Builder
echo ============================================
echo.

echo [1/3] Installing dependencies...
pip install -r requirements_desktop.txt

echo.
echo [2/3] Building PredatorEye.exe with PyInstaller...

pyinstaller ^
  --onefile ^
  --windowed ^
  --name "PredatorEye" ^
  --add-data "web/templates;web/templates" ^
  --add-data "scanners;scanners" ^
  --add-data "analyzers;analyzers" ^
  --add-data "predictors;predictors" ^
  --add-data "prevention;prevention" ^
  --add-data "reports;reports" ^
  --add-data "config.py;." ^
  --hidden-import "webview" ^
  --hidden-import "psutil" ^
  --hidden-import "flask" ^
  --hidden-import "winreg" ^
  --collect-all "webview" ^
  desktop_app.py

echo.
echo [3/3] Done!
echo.
echo  Output: dist\PredatorEye.exe
echo  Share that single .exe file with anyone.
echo.
pause
