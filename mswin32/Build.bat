@echo off
set TARGET=%1
set VCCONFIG=%2

for /f "usebackq delims=#" %%a in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere" -version 16 -property installationPath`) do call "%%a\VC\Auxiliary\Build\vcvarsall.bat" x86

@echo on
if "%TARGET%" == "Vars" ( goto :vars )

msbuild -nologo nmap.sln -m -t:%TARGET% -p:Configuration="%VCCONFIG%" -p:Platform="Win32" -fl
exit /b %errorlevel%

:vars
cl.exe /nologo /EP make-vars.h > make-vars.make
exit /b %errorlevel%
