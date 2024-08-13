@echo off
set TARGET=%1
set VCCONFIG=%2

for /f "usebackq delims=#" %%a in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere" -version 16 -property installationPath`) do call "%%a\VC\Auxiliary\Build\vcvarsall.bat" x86 && goto :next
:next

@echo on
if "%TARGET%" == "Vars" ( goto :vars )

mkdir build-pcre2
cd build-pcre2
cmake.exe -A Win32 -G "Visual Studio 16 2019" ..\..\libpcre\ || goto :QUIT
cd ..
msbuild -nologo nmap.sln -m -t:%TARGET% -p:Configuration="%VCCONFIG%" -p:Platform="Win32" -fl
goto :QUIT

:vars
cl.exe /nologo /EP make-vars.h > make-vars.make

:QUIT
exit /b %errorlevel%
