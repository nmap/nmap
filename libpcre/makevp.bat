@echo off

REM This file was contributed by Alexander Tokarev for building PCRE for use
REM with Virtual Pascal. It has not been tested with the latest PCRE release.

REM CHANGE THIS FOR YOUR BORLAND C++ COMPILER PATH

SET BORLAND=c:\usr\apps\bcc55

sh configure

bcc32 -DDFTABLES -DSTATIC -DVPCOMPAT -I%BORLAND%\include -L%BORLAND%\lib dftables.c

dftables > chartables.c

bcc32 -c -RT- -y- -v- -u- -P- -O2 -5 -DSTATIC -DVPCOMPAT -UDFTABLES -I%BORLAND%\include get.c maketables.c pcre.c study.c

tlib %BORLAND%\lib\cw32.lib *calloc *del *strncmp *memcpy *memmove *memset
tlib pcre.lib +get.obj +maketables.obj +pcre.obj +study.obj +calloc.obj +del.obj +strncmp.obj +memcpy.obj +memmove.obj +memset.obj

del *.obj *.exe *.tds *.bak >nul 2>nul

echo ---
echo Now the library should be complete. Please check all messages above.
echo Don't care for warnings, it's OK.
