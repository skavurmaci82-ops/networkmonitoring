@echo off
setlocal
cd /d "%~dp0"
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if not errorlevel 1 (
    py -3 -m pip install -r requirements-collectors.txt
    if errorlevel 1 goto finished
    echo Kurulum tamamlandi. BASLAT.cmd ile AgAtlas'i yeniden baslatin.
    goto finished
)
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if not errorlevel 1 (
    python -m pip install -r requirements-collectors.txt
    if errorlevel 1 goto finished
    echo Kurulum tamamlandi. BASLAT.cmd ile AgAtlas'i yeniden baslatin.
    goto finished
)
echo Python 3.10 veya uzeri bulunamadi.
:finished
pause
