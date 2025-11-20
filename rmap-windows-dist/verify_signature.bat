@echo off
REM ============================================
REM R-Map Signature Verification Script
REM ============================================
REM This script verifies the PGP signature of rmap.exe
REM For users who want to verify the authenticity
REM
REM ============================================

echo.
echo ============================================
echo R-Map Executable Signature Verification
echo ============================================
echo.

REM Check if rmap.exe exists
if not exist "rmap.exe" (
    echo [ERROR] rmap.exe not found
    exit /b 1
)

REM Check if signature exists
if not exist "rmap.exe.asc" (
    echo [ERROR] Signature file rmap.exe.asc not found
    echo.
    echo This executable has not been signed yet.
    echo To sign it, the developer must run: sign_executable.bat
    echo.
    exit /b 1
)

REM Check if GPG is available
where gpg >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] GPG not found in PATH
    echo Please install GnuPG from https://gnupg.org/download/
    exit /b 1
)

echo [INFO] GPG version:
gpg --version | findstr "gpg"
echo.

REM Check if public key is imported
echo [INFO] Checking for public key 0xACAFF196...
gpg --list-keys 0xACAFF196 >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Public key not found, importing...

    if exist "PyroDIFR (PyroDIFR)_0xACAFF196_public.asc" (
        gpg --import "PyroDIFR (PyroDIFR)_0xACAFF196_public.asc"
        if %ERRORLEVEL% EQU 0 (
            echo [SUCCESS] Public key imported
        ) else (
            echo [ERROR] Failed to import public key
            exit /b 1
        )
    ) else (
        echo [ERROR] Public key file not found
        echo Please obtain: PyroDIFR (PyroDIFR)_0xACAFF196_public.asc
        exit /b 1
    )
)

echo.
echo [INFO] Public key details:
gpg --list-keys 0xACAFF196
echo.

REM Verify the signature
echo ============================================
echo Verifying signature...
echo ============================================
echo.

gpg --verify rmap.exe.asc rmap.exe

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ============================================
    echo [SUCCESS] Signature is VALID!
    echo ============================================
    echo.
    echo This executable was signed by:
    echo   PyroDIFR ^(PyroDIFR^) ^<PyroDIFR@proton.me^>
    echo   Key ID: 0xACAFF196
    echo.
    echo The executable is authentic and has not been tampered with.
    echo.
) else (
    echo.
    echo ============================================
    echo [WARNING] Signature verification FAILED!
    echo ============================================
    echo.
    echo Possible reasons:
    echo   - File has been modified
    echo   - Wrong signature file
    echo   - Corrupted download
    echo.
    echo DO NOT USE this executable!
    echo Please re-download from official source.
    echo.
    exit /b 1
)

REM Also verify SHA256 checksum if available
if exist "rmap.exe.sha256" (
    echo ============================================
    echo Additional SHA256 Checksum Verification
    echo ============================================
    echo.
    echo Expected SHA256:
    type rmap.exe.sha256
    echo.
    echo Calculated SHA256:
    powershell -Command "(Get-FileHash -Algorithm SHA256 rmap.exe).Hash.ToLower()"
    echo.
)

echo ============================================
echo Verification complete
echo ============================================
pause
