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

:QUIT
exit /b %errorlevel%
