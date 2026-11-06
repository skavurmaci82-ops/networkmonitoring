@echo off
setlocal
cd /d "%~dp0"
title AgAtlas
echo AgAtlas - Yerel ag izleme
echo.
echo Bu pencereyi acik birakin.
echo Sunucu basladiginda tarayicida http://127.0.0.1:8080 adresini acin.
echo Durdurmak icin Ctrl+C kullanin.
echo.
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if not errorlevel 1 (
    py -3 app.py
    goto finished
)
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if not errorlevel 1 (
    python app.py
    goto finished
)
echo Python 3.10 veya uzeri bulunamadi.
echo https://www.python.org/downloads/ adresinden Python kurun.
echo Kurulumda "Add python.exe to PATH" secenegini isaretleyin.
echo Kurulumdan sonra bu dosyayi yeniden acin.
:finished
echo.
echo Hata varsa bu penceredeki metni destek icin paylasin.
pause
