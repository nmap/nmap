@echo off

rem This batch file searches for a Python interpreter and uses it to run a
rem script. It displays an error message if not Python is found. The script
rem to run must have the same filename as the batch file, with an extension of
rem .py rather than .bat.

setlocal EnableDelayedExpansion

rem %0 is the name of the batch file. "dpn" means drive, path, filename
rem (excluding extension).
set PROG=%~dpn0.py

if not exist "%PROG%" (
	echo Cannot run %PROG%
	echo because that file does not exist.
	exit /B 1
)
set NMAPDIR=%~dp0

rem Use Python installed with Nmap - Zenmap GUI.
set PYTHON=%NMAPDIR%zenmap\bin\python.exe

if not exist "%PYTHON%" GOTO:NOPYTHON

GOTO:EXEC

:NOPYTHON
	echo Cannot run %PROG%
	echo because python.exe was not found in %NMAPDIR%\zenmap\bin.
	echo This should not have happened unless Python was removed from Nmap - Zenmap GUI!!!
	exit /B 1

:EXEC
rem This command chaining allows the exit code to propagate.
endlocal & "%PYTHON%" "%PROG%" %*
