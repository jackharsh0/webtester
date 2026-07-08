@echo off
color 0A
title WebTester - Website Security Scanner

:menu
cls
echo ============================================================
echo.
echo   WEBTESTER - Website Security Scanner v2.0
echo   Built by jackharsh0
echo.
echo ============================================================
echo.
echo   [1] Basic Security Scan
echo   [2] Full Scan (Security + SQL Injection)
echo   [3] API Security Test (REST, GraphQL, JWT, OAuth)
echo   [4] SQL Injection Test Only
echo   [5] Generate CSP Header
echo   [6] Exit
echo.
echo ============================================================
echo.

set /p choice="Select option (1-6): "

if "%choice%"=="1" goto basic
if "%choice%"=="2" goto full
if "%choice%"=="3" goto api
if "%choice%"=="4" goto sqli
if "%choice%"=="5" goto csp
if "%choice%"=="6" goto exit

echo Invalid option!
pause
goto menu

:basic
cls
echo ============================================================
echo   BASIC SECURITY SCAN
echo ============================================================
echo.
set /p url="Enter website URL (e.g., https://example.com): "
echo.
python webtester.py %url%
echo.
pause
goto menu

:full
cls
echo ============================================================
echo   FULL SCAN (Security + SQL Injection)
echo ============================================================
echo.
set /p url="Enter website URL (e.g., https://example.com): "
echo.
python webtester.py %url% --sqli
echo.
pause
goto menu

:api
cls
echo ============================================================
echo   API SECURITY TEST
echo ============================================================
echo.
set /p url="Enter website URL (e.g., https://example.com): "
echo.
python -c "from api_security import scan_api_security; scan_api_security('%url%')"
echo.
pause
goto menu

:sqli
cls
echo ============================================================
echo   SQL INJECTION TEST
echo ============================================================
echo.
set /p url="Enter website URL (e.g., https://example.com): "
echo.
python -c "from sqli_scanner import scan_sqli; scan_sqli('%url%')"
echo.
pause
goto menu

:csp
cls
echo ============================================================
echo   CSP HEADER GENERATOR
echo ============================================================
echo.
set /p url="Enter website URL (e.g., https://example.com): "
echo.
python webtester.py %url% --csp
echo.
pause
goto menu

:exit
echo.
echo Thank you for using WebTester!
echo Built by jackharsh0
echo.
exit