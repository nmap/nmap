@echo off
REM ============================================
REM R-Map Executable Signing Script
REM ============================================
REM This script signs rmap.exe with PGP key 0xACAFF196
REM
REM Requirements:
REM   - GPG installed (GnuPG)
REM   - Private key imported: gpg --import PyroDIFR_0xACAFF196_private.asc
REM   - This script must be run from rmap-windows-dist\ directory
REM
REM ============================================

echo.
echo ============================================
echo R-Map Executable PGP Signing
echo ============================================
echo.

REM Check if rmap.exe exists
if not exist "rmap.exe" (
    echo [ERROR] rmap.exe not found in current directory
    echo Please run this script from the rmap-windows-dist\ folder
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

REM Check if private key is available
echo [INFO] Checking for private key 0xACAFF196...
gpg --list-secret-keys 0xACAFF196 >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [WARNING] Private key 0xACAFF196 not found!
    echo.
    echo To import the private key, run:
    echo   gpg --import PyroDIFR_0xACAFF196_private.asc
    echo.
    echo If you don't have the private key file, you cannot sign the executable.
    echo Only the key owner (PyroDIFR) can sign this release.
    echo.
    pause
    exit /b 1
)

echo [SUCCESS] Private key found
echo.

REM Display key information
echo [INFO] Key details:
gpg --list-secret-keys 0xACAFF196
echo.

REM Sign the executable
echo [INFO] Signing rmap.exe...
echo.

gpg --detach-sign --armor -u 0xACAFF196 rmap.exe

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ============================================
    echo [SUCCESS] Signature created: rmap.exe.asc
    echo ============================================
    echo.

    REM Verify the signature
    echo [INFO] Verifying signature...
    gpg --verify rmap.exe.asc rmap.exe

    if %ERRORLEVEL% EQU 0 (
        echo.
        echo ============================================
        echo [SUCCESS] Signature verified successfully!
        echo ============================================
        echo.
        echo Distribution files ready:
        echo   - rmap.exe (executable)
        echo   - rmap.exe.asc (PGP signature)
        echo   - PyroDIFR (PyroDIFR)_0xACAFF196_public.asc (public key)
        echo.
        echo Users can verify with:
        echo   gpg --import "PyroDIFR (PyroDIFR)_0xACAFF196_public.asc"
        echo   gpg --verify rmap.exe.asc rmap.exe
        echo.
    ) else (
        echo [ERROR] Signature verification failed!
        exit /b 1
    )
) else (
    echo.
    echo [ERROR] Signing failed!
    echo.
    echo Possible reasons:
    echo   - Private key not available
    echo   - GPG passphrase incorrect
    echo   - Permission issues
    echo.
    exit /b 1
)

echo ============================================
echo Signing process complete
echo ============================================
pause
