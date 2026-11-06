@echo off
setlocal
cd /d "%~dp0"
where docker >nul 2>&1
if errorlevel 1 (
    echo Once Docker Desktop kurun ve Linux containers modunda baslatin.
    echo https://www.docker.com/products/docker-desktop/
    goto finished
)
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if not errorlevel 1 (
    py -3 -m pip install -r requirements-gateway.txt
    if errorlevel 1 goto finished
    py -3 gateway_setup.py
    goto finished
)
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if not errorlevel 1 (
    python -m pip install -r requirements-gateway.txt
    if errorlevel 1 goto finished
    python gateway_setup.py
    goto finished
)
echo Python 3.10 veya uzeri bulunamadi.
:finished
echo.
pause
