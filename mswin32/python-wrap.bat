@echo off

rem This batch file searches for a Python interpreter and uses it to run a
rem script. It displays an error message if not Python is found. The script
rem to run must have the same filename as the batch file, with an extension of
rem .py rather than .bat.

setlocal

rem %0 is the name of the batch file. "dpn" means drive, path, filename
rem (excluding extension).
set PROG=%~dpn0.py

if not exist "%PROG%" (
	echo Cannot run %PROG%
	echo because that file does not exist.
	exit /B 1
)

set PATH=%PATH%;C:\Python27;C:\Python26;C:\Python25;C:\Python24
for %%P in ( python.exe ) do set PYTHON=%%~f$PATH:P

if not exist "%PYTHON%" (
	echo Cannot run %PROG%
	echo because python.exe was not found anywhere in
	echo %PATH%.
	echo.
	echo To run this program, download and install Python from
	echo http://www.python.org/download.
	exit /B 1
)

rem This command chaining allows the exit code to propagate.
endlocal & "%PYTHON%" "%PROG%" %*
