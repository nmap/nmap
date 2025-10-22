@echo off
set TARGET=%1
set VCCONFIG=%2

:: Set defaults if not provided
if "%TARGET%" == "" set TARGET=Build
if "%VCCONFIG%" == "" set VCCONFIG=Release

:: Find and initialize Visual Studio environment first
:: Try VS 2019 first, then fall back to latest
"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -version "[16.0,17.0)" -property installationPath > "%TEMP%\vspath.txt" 2>nul
for /f "usebackq delims=" %%i in ("%TEMP%\vspath.txt") do (
  call "%%i\VC\Auxiliary\Build\vcvarsall.bat" x86
  set VS_GENERATOR=Visual Studio 16 2019
  goto :generator_set
)

:: VS 2019 not found, use latest
"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -version "[16.0,)" -latest -property installationPath > "%TEMP%\vspath.txt" 2>nul
"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -version "[16.0,)" -latest -property installationVersion > "%TEMP%\vsver.txt" 2>nul

for /f "usebackq delims=" %%i in ("%TEMP%\vspath.txt") do call "%%i\VC\Auxiliary\Build\vcvarsall.bat" x86

:: Determine generator from version
set VS_GENERATOR=Visual Studio 17 2022
for /f "usebackq delims=" %%v in ("%TEMP%\vsver.txt") do (
  set VSVER=%%v
  if "%%v:~0,2%%" == "16" set VS_GENERATOR=Visual Studio 16 2019
  if "%%v:~0,2%%" == "17" set VS_GENERATOR=Visual Studio 17 2022
  if "%%v:~0,2%%" == "18" set VS_GENERATOR=Visual Studio 18 2025
)

:generator_set
del "%TEMP%\vspath.txt" 2>nul
del "%TEMP%\vsver.txt" 2>nul

:: Check and install dependencies
set NMAP_AUX_DIR=%~dp0..\..\nmap-mswin32-aux
if not exist "%NMAP_AUX_DIR%" (
  echo.
  echo ========================================
  echo Installing required dependencies...
  echo ========================================
  call :install_dependencies
  if errorlevel 1 goto :QUIT
)

:: Verify dependencies are present
if not exist "%NMAP_AUX_DIR%\Npcap\Include\pcap.h" (
  echo ERROR: Npcap SDK not found after installation
  exit /b 1
)
if not exist "%NMAP_AUX_DIR%\OpenSSL\include\openssl\ssl.h" (
  echo ERROR: OpenSSL not found after installation
  exit /b 1
)

echo Dependencies verified successfully.
echo.

:next

echo Detected Visual Studio Generator: %VS_GENERATOR%
@echo on
if "%TARGET%" == "Vars" ( goto :vars )

if "%TARGET%" == "Clean" (
  rd /S /Q build-pcre2
) else (
echo Using CMake Generator: %VS_GENERATOR%
mkdir build-pcre2
cd build-pcre2
cmake.exe -A Win32 -G "%VS_GENERATOR%" ..\..\libpcre\ || goto :QUIT
cd ..
)
msbuild -nologo nmap.sln -m -t:%TARGET% -p:Configuration="%VCCONFIG%" -p:Platform="Win32" -fl
goto :QUIT

:vars
cl.exe /nologo /EP make-vars.h > make-vars.make

:install_dependencies
echo.
echo Creating auxiliary directory: %NMAP_AUX_DIR%
mkdir "%NMAP_AUX_DIR%" 2>nul

:: Install Npcap SDK
echo Downloading Npcap SDK...
set NPCAP_URL=https://npcap.com/dist/npcap-sdk-1.13.zip
set NPCAP_ZIP=%TEMP%\npcap-sdk.zip
powershell -Command "Invoke-WebRequest -Uri '%NPCAP_URL%' -OutFile '%NPCAP_ZIP%'"
if errorlevel 1 (
  echo ERROR: Failed to download Npcap SDK
  exit /b 1
)

echo Extracting Npcap SDK...
powershell -Command "Expand-Archive -Path '%NPCAP_ZIP%' -DestinationPath '%NMAP_AUX_DIR%\Npcap' -Force"
if errorlevel 1 (
  echo ERROR: Failed to extract Npcap SDK
  exit /b 1
)
del "%NPCAP_ZIP%" 2>nul

:: Install OpenSSL - Use nmap's SVN repository
echo Downloading OpenSSL from nmap SVN repository...
set OPENSSL_SVN_URL=https://svn.nmap.org/nmap-mswin32-aux/OpenSSL

:: Check if svn is available
where svn >nul 2>&1
if %ERRORLEVEL% EQU 0 (
  echo Using SVN to download OpenSSL...
  svn export "%OPENSSL_SVN_URL%" "%NMAP_AUX_DIR%\OpenSSL" --force
  if errorlevel 1 (
    echo WARNING: SVN export failed, trying alternative method...
    goto :openssl_fallback
  )
  goto :openssl_done
)

:openssl_fallback
echo SVN not available, downloading OpenSSL headers manually...
mkdir "%NMAP_AUX_DIR%\OpenSSL\include\openssl" 2>nul
mkdir "%NMAP_AUX_DIR%\OpenSSL\lib" 2>nul

:: Download from nmap SVN via HTTP
set SVN_BASE=https://svn.nmap.org/nmap-mswin32-aux/OpenSSL
echo Downloading OpenSSL files from nmap repository...

:: Use PowerShell to recursively download the directory structure
powershell -Command "$ErrorActionPreference='SilentlyContinue'; $wc=New-Object System.Net.WebClient; $wc.DownloadFile('%SVN_BASE%/include/openssl/ssl.h','%NMAP_AUX_DIR%\OpenSSL\include\openssl\ssl.h'); $wc.DownloadFile('%SVN_BASE%/include/openssl/crypto.h','%NMAP_AUX_DIR%\OpenSSL\include\openssl\crypto.h'); $wc.DownloadFile('%SVN_BASE%/include/openssl/opensslconf.h','%NMAP_AUX_DIR%\OpenSSL\include\openssl\opensslconf.h')"

if not exist "%NMAP_AUX_DIR%\OpenSSL\include\openssl\ssl.h" (
  echo ERROR: Failed to download OpenSSL files
  echo Please install SVN or manually download OpenSSL to %NMAP_AUX_DIR%\OpenSSL
  exit /b 1
)

:openssl_done

echo.
echo Dependencies installed successfully!
echo.
exit /b 0

:QUIT
exit /b %errorlevel%
