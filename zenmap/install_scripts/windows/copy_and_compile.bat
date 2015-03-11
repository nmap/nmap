@echo off

echo Setting installation variables...
set PythonDir=..\..\nmap-mswin32-aux\Python
set PythonEXE=%PythonDir%\python.exe
set DistDir=dist
set LibraryDir=%DistDir%\py2exe
set GTKDir=%PythonDir%\Lib\site-packages\gtk-2.0\runtime
set Output=win_install.log

IF EXIST %PythonEXE% GOTO GGTK
ECHO No Python found!
EXIT 1

:GGTK
IF EXIST %GTKDir% GOTO GWork
ECHO No GTK found!
EXIT 1

:GWork

echo Writing output to %Output%

echo Removing old compilation...
IF EXIST %DistDir% rd %DistDir% /s /q > %Output%

echo Creating dist directory tree...
mkdir %LibraryDir%\etc
mkdir %LibraryDir%\share
mkdir %LibraryDir%\share\themes
mkdir %LibraryDir%\share\icons
mkdir %LibraryDir%\lib

echo Copying GTK files to dist directory...
xcopy %GTKDir%\bin\*.dll %LibraryDir% /S >> %Output%
rem intl.dll is a special case; has to be in the executable directory instead of
rem the py2exe subdirectory.
xcopy %GTKDir%\etc %LibraryDir%\etc /S /I >> %Output%
xcopy %GTKDir%\lib\gtk-2.0 %LibraryDir%\lib\gtk-2.0 /S /I >> %Output%
xcopy %GTKDir%\share\themes\Default %LibraryDir%\share\themes\Default /S /I >> %Output%
xcopy %GTKDir%\share\themes\MS-Windows %LibraryDir%\share\themes\MS-Windows /S /I >> %Output%
xcopy %GTKDir%\share\icons\hicolor %LibraryDir%\share\icons\hicolor /S /I >> %Output%

echo Compiling using py2exe...
%PythonEXE% setup.py py2exe >> %Output%

echo Removing the build directory...
rd build /s /q >> %Output%

rem Check that the gtkrc file was manually created so Zenmap will look pretty
IF EXIST %DistDir%\etc\gtk-2.0\gtkrc GOTO gtkrc
echo gtk-theme-name = "MS-Windows" > %DistDir%\py2exe\etc\gtk-2.0\gtkrc
echo Created the missing file %DistDir%\py2exe\etc\gtk-2.0\gtkrc >> %Output%
:gtkrc

echo Done!

