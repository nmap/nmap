@echo off
REM R-Map UA Testing Suite for Windows
REM Simple batch script for comprehensive testing

setlocal enabledelayedexpansion

set BINARY=target\release\rmap.exe
set OUTPUT_DIR=ua_test_results
set PASS_COUNT=0
set FAIL_COUNT=0

REM Create output directory
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo ============================================
echo R-Map UA Test Suite
echo ============================================
echo Binary: %BINARY%
echo Output: %OUTPUT_DIR%
echo ============================================
echo.

REM Check binary exists
if not exist "%BINARY%" (
    echo ERROR: Binary not found at %BINARY%
    echo Please run: cargo build --release
    exit /b 1
)

REM ====================
REM Test 1: Version Check
REM ====================
echo [TEST 1] Version check...
%BINARY% --version > "%OUTPUT_DIR%\01-version.txt" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Version check
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Version check
    set /a FAIL_COUNT+=1
)

REM ====================
REM Test 2: Help Output
REM ====================
echo [TEST 2] Help output...
%BINARY% --help > "%OUTPUT_DIR%\02-help.txt" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Help output
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Help output
    set /a FAIL_COUNT+=1
)

REM ====================
REM Test 3: Basic Scan
REM ====================
echo [TEST 3] Basic localhost scan...
%BINARY% 127.0.0.1 -p 80 > "%OUTPUT_DIR%\03-basic-scan.txt" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Basic scan
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Basic scan
    set /a FAIL_COUNT+=1
)

REM ====================
REM Test 4: Multiple Ports
REM ====================
echo [TEST 4] Multiple ports scan...
%BINARY% 127.0.0.1 -p 80,443,22,3389 > "%OUTPUT_DIR%\04-multiple-ports.txt" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Multiple ports
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Multiple ports
    set /a FAIL_COUNT+=1
)

REM ====================
REM Test 5: Port Range
REM ====================
echo [TEST 5] Port range scan...
%BINARY% 127.0.0.1 -p 80-85 > "%OUTPUT_DIR%\05-port-range.txt" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Port range
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Port range
    set /a FAIL_COUNT+=1
)

REM ====================
REM Test 6: JSON Output
REM ====================
echo [TEST 6] JSON output format...
%BINARY% 127.0.0.1 -p 80 -o json > "%OUTPUT_DIR%\06-json-output.txt" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] JSON output
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] JSON output
    set /a FAIL_COUNT+=1
)

REM ====================
REM Test 7: XML Output
REM ====================
echo [TEST 7] XML output format...
%BINARY% 127.0.0.1 -p 80 -o xml > "%OUTPUT_DIR%\07-xml-output.txt" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] XML output
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] XML output
    set /a FAIL_COUNT+=1
)

REM ====================
REM Test 8: Grepable Output
REM ====================
echo [TEST 8] Grepable output format...
%BINARY% 127.0.0.1 -p 80 -o grepable > "%OUTPUT_DIR%\08-grepable-output.txt" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Grepable output
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Grepable output
    set /a FAIL_COUNT+=1
)

REM ====================
REM Test 9: Service Detection
REM ====================
echo [TEST 9] Service detection...
%BINARY% 127.0.0.1 -p 80,443 -A > "%OUTPUT_DIR%\09-service-detection.txt" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Service detection
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Service detection
    set /a FAIL_COUNT+=1
)

REM ====================
REM Test 10: Verbose Mode
REM ====================
echo [TEST 10] Verbose mode...
%BINARY% 127.0.0.1 -p 80 -v > "%OUTPUT_DIR%\10-verbose.txt" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Verbose mode
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Verbose mode
    set /a FAIL_COUNT+=1
)

REM ====================
REM Test 11: File Output
REM ====================
echo [TEST 11] File output...
%BINARY% 127.0.0.1 -p 80 -o json -f "%OUTPUT_DIR%\11-file-output.json" > "%OUTPUT_DIR%\11-file-output-log.txt" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] File output
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] File output
    set /a FAIL_COUNT+=1
)

REM ====================
REM Test 12: Timeout Setting
REM ====================
echo [TEST 12] Custom timeout...
%BINARY% 127.0.0.1 -p 80 -t 5 > "%OUTPUT_DIR%\12-timeout.txt" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Custom timeout
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Custom timeout
    set /a FAIL_COUNT+=1
)

REM ====================
REM Test 13: Google DNS
REM ====================
echo [TEST 13] Public host scan (8.8.8.8)...
%BINARY% 8.8.8.8 -p 53 > "%OUTPUT_DIR%\13-google-dns.txt" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Public host scan
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Public host scan
    set /a FAIL_COUNT+=1
)

REM ====================
REM Test 14: Hostname Resolution
REM ====================
echo [TEST 14] Hostname resolution...
%BINARY% localhost -p 80 > "%OUTPUT_DIR%\14-hostname.txt" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Hostname resolution
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Hostname resolution
    set /a FAIL_COUNT+=1
)

REM ====================
REM Test 15: scanme.nmap.org
REM ====================
echo [TEST 15] Real-world scan (scanme.nmap.org)...
%BINARY% scanme.nmap.org -p 22,80 > "%OUTPUT_DIR%\15-scanme.txt" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Real-world scan
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Real-world scan
    set /a FAIL_COUNT+=1
)

REM ====================
REM Results Summary
REM ====================
set /a TOTAL_COUNT=PASS_COUNT+FAIL_COUNT
echo.
echo ============================================
echo TEST RESULTS SUMMARY
echo ============================================
echo Total Tests: %TOTAL_COUNT%
echo Passed: %PASS_COUNT%
echo Failed: %FAIL_COUNT%
echo ============================================

REM Generate HTML report
echo ^<!DOCTYPE html^> > "%OUTPUT_DIR%\results.html"
echo ^<html^>^<head^>^<title^>R-Map UA Test Results^</title^> >> "%OUTPUT_DIR%\results.html"
echo ^<style^>body{font-family:Arial;margin:20px;background:#f5f5f5;}.header{background:#2c3e50;color:white;padding:20px;border-radius:5px;}.summary{background:white;padding:20px;margin:20px 0;}.pass{color:#27ae60;}.fail{color:#e74c3c;}^</style^> >> "%OUTPUT_DIR%\results.html"
echo ^</head^>^<body^> >> "%OUTPUT_DIR%\results.html"
echo ^<div class="header"^>^<h1^>R-Map UA Test Results^</h1^>^<p^>Binary: %BINARY%^</p^>^</div^> >> "%OUTPUT_DIR%\results.html"
echo ^<div class="summary"^>^<h2^>Summary^</h2^> >> "%OUTPUT_DIR%\results.html"
echo ^<p^>Total Tests: %TOTAL_COUNT%^</p^> >> "%OUTPUT_DIR%\results.html"
echo ^<p class="pass"^>Passed: %PASS_COUNT%^</p^> >> "%OUTPUT_DIR%\results.html"
echo ^<p class="fail"^>Failed: %FAIL_COUNT%^</p^> >> "%OUTPUT_DIR%\results.html"
echo ^</div^>^</body^>^</html^> >> "%OUTPUT_DIR%\results.html"

echo.
echo HTML Report generated: %OUTPUT_DIR%\results.html
echo All test outputs saved to: %OUTPUT_DIR%\
echo.

if %FAIL_COUNT% == 0 (
    echo All tests PASSED!
    exit /b 0
) else (
    echo Some tests FAILED. See output files for details.
    exit /b 1
)
