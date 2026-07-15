@echo off
color 0A
title WebTester - Website Security Scanner v3.0

:menu
cls
echo ============================================================
echo.
echo   WEBTESTER - Website Security Scanner v3.0
echo   Built by jackharsh0
echo.
echo ============================================================
echo.
echo   [1] Basic Security Scan
echo   [2] Full Scan (All Modules)
echo   [3] SQL Injection Test
echo   [4] API Security Test (REST, GraphQL, JWT, OAuth)
echo   [5] Reconnaissance (Subdomains, Ports, Directories)
echo   [6] Advanced Attacks (CORS, XXE, SSTI, CSRF)
echo   [7] Generate CSP Header
echo   [8] Batch Scan (Multiple URLs)
echo   [9] Exit
echo.
echo ============================================================
echo.

set /p choice="Select option (1-9): "

if "%choice%"=="1" goto basic
if "%choice%"=="2" goto full
if "%choice%"=="3" goto sqli
if "%choice%"=="4" goto api
if "%choice%"=="5" goto recon
if "%choice%"=="6" goto advanced
if "%choice%"=="7" goto csp
if "%choice%"=="8" goto batch
if "%choice%"=="9" goto exit

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
echo   FULL SCAN (All Modules)
echo ============================================================
echo.
echo   This will run ALL security checks:
echo   - Website downloading
echo   - 65+ security checks
echo   - SQL injection testing
echo   - API security (REST, GraphQL, JWT, OAuth)
echo   - Reconnaissance (subdomains, ports, directories)
echo   - Advanced attacks (CORS, XXE, SSTI, CSRF)
echo   - Intelligence analysis
echo   - Report generation
echo.
set /p url="Enter website URL (e.g., https://example.com): "
echo.
python webtester.py %url% --full
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
echo   Testing:
echo   - REST API endpoints
echo   - GraphQL (introspection, depth abuse, batching)
echo   - JWT (none algorithm, weak secrets, expiration)
echo   - OAuth (redirect URI, state parameter)
echo   - WebSocket security
echo.
set /p url="Enter website URL (e.g., https://example.com): "
echo.
python webtester.py %url% --api
echo.
pause
goto menu

:recon
cls
echo ============================================================
echo   RECONNAISSANCE
echo ============================================================
echo.
echo   Scanning:
echo   - Subdomains
echo   - Open ports
echo   - Hidden directories
echo   - WAF detection
echo.
set /p url="Enter website URL (e.g., https://example.com): "
echo.
python webtester.py %url% --recon
echo.
pause
goto menu

:advanced
cls
echo ============================================================
echo   ADVANCED ATTACKS
echo ============================================================
echo.
echo   Testing:
echo   - CORS exploitation
echo   - CSRF vulnerabilities
echo   - XXE injection
echo   - Server-Side Template Injection (SSTI)
echo   - File upload exploits
echo   - Insecure deserialization
echo.
set /p url="Enter website URL (e.g., https://example.com): "
echo.
python webtester.py %url% --advanced
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

:batch
cls
echo ============================================================
echo   BATCH SCAN
echo ============================================================
echo.
echo   Create a file with URLs (one per line):
echo   - URLs starting with http:// or https://
echo   - Lines starting with # are ignored
echo.
set /p batchfile="Enter path to URLs file (e.g., urls.txt): "
echo.
python webtester.py --batch %batchfile%
echo.
pause
goto menu

:exit
echo.
echo Thank you for using WebTester!
echo Built by jackharsh0
echo.
exit