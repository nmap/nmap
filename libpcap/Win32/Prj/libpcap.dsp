# Microsoft Developer Studio Project File - Name="libpcap" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=libpcap - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE
!MESSAGE NMAKE /f "libpcap.mak".
!MESSAGE
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE
!MESSAGE NMAKE /f "libpcap.mak" CFG="libpcap - Win32 Debug"
!MESSAGE
!MESSAGE Possible choices for configuration are:
!MESSAGE
!MESSAGE "libpcap - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "libpcap - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libpcap - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "../../" /I "../../lbl/" /I "../../bpf/" /I "../include/" /I "../../../../common" /I "../../../../dag/include" /I "../../../../dag/drv/windows" /D "NDEBUG" /D "YY_NEVER_INTERACTIVE" /D yylval=pcap_lval /D "_USRDLL" /D "LIBPCAP_EXPORTS" /D "HAVE_STRERROR" /D "__STDC__" /D "INET6" /D "_WINDOWS" /D "_MBCS" /D "HAVE_ADDRINFO" /D "WIN32" /D _U_= /D "HAVE_SNPRINTF" /D "HAVE_VSNPRINTF" /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "libpcap - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../../" /I "../../lbl/" /I "../../bpf/" /I "../include/" /I "../../../../common" /I "../../../../dag/include" /I "../../../../dag/drv/windows" /D "_DEBUG" /D "YY_NEVER_INTERACTIVE" /D yylval=pcap_lval /D "_USRDLL" /D "LIBPCAP_EXPORTS" /D "HAVE_STRERROR" /D "__STDC__" /D "INET6" /D "_WINDOWS" /D "_MBCS" /D "HAVE_ADDRINFO" /D "WIN32" /D _U_= /D "HAVE_SNPRINTF" /D "HAVE_VSNPRINTF" /YX /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF

# Begin Target

# Name "libpcap - Win32 Release"
# Name "libpcap - Win32 Debug"
# Begin Source File

SOURCE=..\..\bpf_dump.c
# End Source File
# Begin Source File

SOURCE=..\..\bpf\net\bpf_filter.c
# End Source File
# Begin Source File

SOURCE=..\..\bpf_image.c
# End Source File
# Begin Source File

SOURCE=..\..\etherent.c
# End Source File
# Begin Source File

SOURCE="..\..\fad-win32.c"
# End Source File
# Begin Source File

SOURCE=..\Src\ffs.c
# End Source File
# Begin Source File

SOURCE=..\..\gencode.c
# End Source File
# Begin Source File

SOURCE=..\Src\getnetbynm.c
# End Source File
# Begin Source File

SOURCE=..\Src\getnetent.c
# End Source File
# Begin Source File

SOURCE=..\Src\getservent.c
# End Source File
# Begin Source File

SOURCE=..\..\grammar.c
# End Source File
# Begin Source File

SOURCE=..\..\inet.c
# End Source File
# Begin Source File

SOURCE=..\Src\inet_aton.c
# End Source File
# Begin Source File

SOURCE=..\Src\inet_net.c
# End Source File
# Begin Source File

SOURCE=..\Src\inet_pton.c
# End Source File
# Begin Source File

SOURCE=..\..\nametoaddr.c
# End Source File
# Begin Source File

SOURCE=..\..\optimize.c
# End Source File
# Begin Source File

SOURCE="..\..\Pcap-win32.c"
# End Source File
# Begin Source File

SOURCE=..\..\pcap.c
# End Source File
# Begin Source File

SOURCE=..\..\savefile.c
# End Source File
# Begin Source File

SOURCE=..\..\scanner.c
# End Source File
# End Target
# End Project
