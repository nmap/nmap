@echo off
REM R-Map Quick Audit & Logging Framework
REM Real-world testing with audit trails

setlocal enabledelayedexpansion
set BINARY=target\release\rmap.exe
set AUDIT_DIR=audit_logs
set REPORT_DIR=audit_reports
set TIMESTAMP=%date:~-4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set TIMESTAMP=!TIMESTAMP: =0!

REM Create directories
if not exist "%AUDIT_DIR%" mkdir "%AUDIT_DIR%"
if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

REM Initialize audit log
set AUDIT_LOG=%AUDIT_DIR%\audit_%TIMESTAMP%.log
set REPORT_FILE=%REPORT_DIR%\report_%TIMESTAMP%.txt

echo ============================================ > "%AUDIT_LOG%"
echo R-Map Automated Audit Framework >> "%AUDIT_LOG%"
echo Started: %date% %time% >> "%AUDIT_LOG%"
echo User: %USERNAME% >> "%AUDIT_LOG%"
echo Host: %COMPUTERNAME% >> "%AUDIT_LOG%"
echo ============================================ >> "%AUDIT_LOG%"
echo.

echo.
echo ============================================
echo R-Map Automated Audit Framework
echo ============================================
echo Timestamp: %TIMESTAMP%
echo Audit Log: %AUDIT_LOG%
echo Report: %REPORT_FILE%
echo ============================================
echo.

REM Test Counter
set /a TOTAL_TESTS=0
set /a PASSED_TESTS=0
set /a FAILED_TESTS=0

REM ==============================================================================
REM REAL-WORLD TEST SCENARIO 1: Web Server Security Audit
REM ==============================================================================

echo [AUDIT] Web Server Security Audit
echo [AUDIT] Web Server Security Audit >> "%AUDIT_LOG%"
echo %date% %time% [INFO] Target: scanme.nmap.org >> "%AUDIT_LOG%"

REM Test 1: HTTP Check
echo [TEST] HTTP Port (80) Check...
set /a TOTAL_TESTS+=1
%BINARY% scanme.nmap.org -p 80 -o json > "%AUDIT_DIR%\web_http_test.json" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] HTTP check completed
    echo %date% %time% [SUCCESS] HTTP port scan completed >> "%AUDIT_LOG%"
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] HTTP check failed
    echo %date% %time% [ERROR] HTTP port scan failed >> "%AUDIT_LOG%"
    set /a FAILED_TESTS+=1
)

REM Test 2: HTTPS Check
echo [TEST] HTTPS Port (443) Check...
set /a TOTAL_TESTS+=1
%BINARY% scanme.nmap.org -p 443 -o json > "%AUDIT_DIR%\web_https_test.json" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] HTTPS check completed
    echo %date% %time% [SUCCESS] HTTPS port scan completed >> "%AUDIT_LOG%"
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] HTTPS check failed
    echo %date% %time% [ERROR] HTTPS port scan failed >> "%AUDIT_LOG%"
    set /a FAILED_TESTS+=1
)

REM Test 3: SSH Check with Service Detection
echo [TEST] SSH Port with Service Detection...
set /a TOTAL_TESTS+=1
%BINARY% scanme.nmap.org -p 22 -A -o json > "%AUDIT_DIR%\web_ssh_detect.json" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] SSH service detection completed
    echo %date% %time% [SUCCESS] SSH service detection >> "%AUDIT_LOG%"
    set /a PASSED_TESTS+=1
    REM Parse service version from JSON
    findstr "version" "%AUDIT_DIR%\web_ssh_detect.json" >> "%AUDIT_LOG%"
) else (
    echo [FAIL] SSH detection failed
    echo %date% %time% [ERROR] SSH detection failed >> "%AUDIT_LOG%"
    set /a FAILED_TESTS+=1
)

echo.

REM ==============================================================================
REM REAL-WORLD TEST SCENARIO 2: DNS Infrastructure Audit
REM ==============================================================================

echo [AUDIT] DNS Infrastructure Audit
echo [AUDIT] DNS Infrastructure Audit >> "%AUDIT_LOG%"

REM Test 4: Google DNS
echo [TEST] Google DNS (8.8.8.8) Audit...
set /a TOTAL_TESTS+=1
%BINARY% 8.8.8.8 -p 53,80,443 -o json > "%AUDIT_DIR%\dns_google.json" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Google DNS audit completed
    echo %date% %time% [SUCCESS] Google DNS 8.8.8.8 scanned >> "%AUDIT_LOG%"
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Google DNS audit failed
    echo %date% %time% [ERROR] Google DNS scan failed >> "%AUDIT_LOG%"
    set /a FAILED_TESTS+=1
)

REM Test 5: Cloudflare DNS
echo [TEST] Cloudflare DNS (1.1.1.1) Audit...
set /a TOTAL_TESTS+=1
%BINARY% 1.1.1.1 -p 53,80,443 -o json > "%AUDIT_DIR%\dns_cloudflare.json" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Cloudflare DNS audit completed
    echo %date% %time% [SUCCESS] Cloudflare DNS 1.1.1.1 scanned >> "%AUDIT_LOG%"
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Cloudflare DNS audit failed
    echo %date% %time% [ERROR] Cloudflare DNS scan failed >> "%AUDIT_LOG%"
    set /a FAILED_TESTS+=1
)

echo.

REM ==============================================================================
REM REAL-WORLD TEST SCENARIO 3: Multi-Target Infrastructure Scan
REM ==============================================================================

echo [AUDIT] Multi-Target Infrastructure Scan
echo [AUDIT] Multi-Target Infrastructure Scan >> "%AUDIT_LOG%"

REM Test 6: Multi-target scan (real production hosts)
echo [TEST] Scanning multiple production hosts...
set /a TOTAL_TESTS+=1
%BINARY% scanme.nmap.org github.com -p 22,80,443 -o xml > "%AUDIT_DIR%\multi_target.xml" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Multi-target scan completed
    echo %date% %time% [SUCCESS] Multi-target infrastructure scan >> "%AUDIT_LOG%"
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Multi-target scan failed
    echo %date% %time% [ERROR] Multi-target scan failed >> "%AUDIT_LOG%"
    set /a FAILED_TESTS+=1
)

echo.

REM ==============================================================================
REM REAL-WORLD TEST SCENARIO 4: Security Compliance Check
REM ==============================================================================

echo [AUDIT] Security Compliance Check
echo [AUDIT] Security Compliance Check >> "%AUDIT_LOG%"

REM Test 7: Check for insecure Telnet
echo [TEST] Compliance: Telnet (port 23) exposure check...
set /a TOTAL_TESTS+=1
%BINARY% scanme.nmap.org -p 23 -o json > "%AUDIT_DIR%\compliance_telnet.json" 2>&1
findstr "closed" "%AUDIT_DIR%\compliance_telnet.json" > nul
if %ERRORLEVEL% == 0 (
    echo [PASS] Telnet is NOT exposed (compliant)
    echo %date% %time% [COMPLIANCE-PASS] Telnet not exposed >> "%AUDIT_LOG%"
    set /a PASSED_TESTS+=1
) else (
    echo [WARNING] Telnet exposure detected!
    echo %date% %time% [COMPLIANCE-FAIL] Telnet port exposed >> "%AUDIT_LOG%"
    set /a FAILED_TESTS+=1
)

REM Test 8: Check for FTP
echo [TEST] Compliance: FTP (port 21) exposure check...
set /a TOTAL_TESTS+=1
%BINARY% scanme.nmap.org -p 21 -o json > "%AUDIT_DIR%\compliance_ftp.json" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] FTP compliance check completed
    echo %date% %time% [COMPLIANCE-INFO] FTP check completed >> "%AUDIT_LOG%"
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] FTP check failed
    echo %date% %time% [ERROR] FTP check error >> "%AUDIT_LOG%"
    set /a FAILED_TESTS+=1
)

echo.

REM ==============================================================================
REM PERFORMANCE BENCHMARKING
REM ==============================================================================

echo [AUDIT] Performance Benchmarks
echo [AUDIT] Performance Benchmarks >> "%AUDIT_LOG%"

REM Test 9: Quick scan performance
echo [TEST] Performance: Quick single-port scan...
set /a TOTAL_TESTS+=1
set START_TIME=%time%
%BINARY% 8.8.8.8 -p 80 -o json > "%AUDIT_DIR%\perf_quick.json" 2>&1
set END_TIME=%time%
if %ERRORLEVEL% == 0 (
    echo [PASS] Quick scan completed
    echo %date% %time% [PERF] Quick scan: Start=%START_TIME% End=%END_TIME% >> "%AUDIT_LOG%"
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Quick scan failed
    set /a FAILED_TESTS+=1
)

REM Test 10: Multi-port performance
echo [TEST] Performance: Multi-port scan benchmark...
set /a TOTAL_TESTS+=1
%BINARY% scanme.nmap.org -p 22,80,443,8080,8443 -o json > "%AUDIT_DIR%\perf_multiport.json" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Multi-port benchmark completed
    echo %date% %time% [PERF] Multi-port benchmark completed >> "%AUDIT_LOG%"
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Multi-port benchmark failed
    set /a FAILED_TESTS+=1
)

echo.

REM ==============================================================================
REM GENERATE AUDIT REPORT
REM ==============================================================================

echo ============================================ > "%REPORT_FILE%"
echo R-Map Automated Audit Report >> "%REPORT_FILE%"
echo ============================================ >> "%REPORT_FILE%"
echo.>> "%REPORT_FILE%"
echo Generated: %date% %time% >> "%REPORT_FILE%"
echo User: %USERNAME% >> "%REPORT_FILE%"
echo Host: %COMPUTERNAME% >> "%REPORT_FILE%"
echo.>> "%REPORT_FILE%"
echo ============================================ >> "%REPORT_FILE%"
echo TEST SUMMARY >> "%REPORT_FILE%"
echo ============================================ >> "%REPORT_FILE%"
echo Total Tests: %TOTAL_TESTS% >> "%REPORT_FILE%"
echo Passed: %PASSED_TESTS% >> "%REPORT_FILE%"
echo Failed: %FAILED_TESTS% >> "%REPORT_FILE%"

REM Calculate pass rate
set /a PASS_RATE=(%PASSED_TESTS% * 100) / %TOTAL_TESTS%
echo Pass Rate: %PASS_RATE%%% >> "%REPORT_FILE%"
echo.>> "%REPORT_FILE%"

echo ============================================ >> "%REPORT_FILE%"
echo AUDIT CATEGORIES TESTED >> "%REPORT_FILE%"
echo ============================================ >> "%REPORT_FILE%"
echo [✓] Web Server Security Audit >> "%REPORT_FILE%"
echo [✓] DNS Infrastructure Audit >> "%REPORT_FILE%"
echo [✓] Multi-Target Infrastructure >> "%REPORT_FILE%"
echo [✓] Security Compliance Checks >> "%REPORT_FILE%"
echo [✓] Performance Benchmarking >> "%REPORT_FILE%"
echo.>> "%REPORT_FILE%"

echo ============================================ >> "%REPORT_FILE%"
echo FILES GENERATED >> "%REPORT_FILE%"
echo ============================================ >> "%REPORT_FILE%"
dir /b "%AUDIT_DIR%\*.json" >> "%REPORT_FILE%"
dir /b "%AUDIT_DIR%\*.xml" >> "%REPORT_FILE%"
echo.>> "%REPORT_FILE%"

echo ============================================ >> "%REPORT_FILE%"
echo DETAILED AUDIT LOG >> "%REPORT_FILE%"
echo ============================================ >> "%REPORT_FILE%"
type "%AUDIT_LOG%" >> "%REPORT_FILE%"

REM ==============================================================================
REM FINAL OUTPUT
REM ==============================================================================

echo.
echo ============================================
echo AUDIT COMPLETE
echo ============================================
echo Total Tests: %TOTAL_TESTS%
echo Passed: %PASSED_TESTS%
echo Failed: %FAILED_TESTS%
echo Pass Rate: %PASS_RATE%%%
echo ============================================
echo Audit Log: %AUDIT_LOG%
echo Full Report: %REPORT_FILE%
echo Test Data: %AUDIT_DIR%\
echo ============================================
echo.

if %FAILED_TESTS% == 0 (
    echo ✅ ALL TESTS PASSED - AUDIT SUCCESSFUL
    exit /b 0
) else (
    echo ⚠️ SOME TESTS FAILED - REVIEW REQUIRED
    exit /b 1
)
