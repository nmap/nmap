;; Custom winpcap for nmap
;; Started by Doug Hoyte, April 2006

;; Eddie Bell
;; Updated to 4.0, June 2007
;; Updated to 4.01, July 2007
;; Updated to 4.02, November 2007

;-------------------------------- 
;Include Modern UI 
 
  !include "MUI.nsh" 

;--------------------------------
;General

; The name of the installer
Name "WinPcap (Nmap) 4.0.2"

; The file to write
OutFile "winpcap-nmap-4.02.exe"

RequestExecutionLevel admin

; The default installation directory
InstallDir $PROGRAMFILES\WinPcap

;Get installation folder from registry if available 
InstallDirRegKey HKLM "Software\WinPcap" "" 

VIProductVersion "4.0.0.1040"
VIAddVersionKey /LANG=1033 "FileVersion" "4.0.0.1040"
VIAddVersionKey /LANG=1033 "ProductName" "WinPcap" 
VIAddVersionKey /LANG=1033 "FileDescription" "WinPcap 4.0.2 installer" 
VIAddVersionKey /LANG=1033 "LegalCopyright" ""


;-------------------------------- 
;Interface Settings 
 
  !define MUI_ABORTWARNING 

;--------------------------------
;Pages

!insertmacro MUI_PAGE_LICENSE "LICENSE" 
!insertmacro MUI_PAGE_DIRECTORY 
!insertmacro MUI_PAGE_INSTFILES 
!insertmacro MUI_UNPAGE_CONFIRM 
!insertmacro MUI_UNPAGE_INSTFILES 
Page custom optionsPage doOptions
Page custom finalPage doFinal

;-------------------------------- 
;Languages 
  
  !insertmacro MUI_LANGUAGE "English" 

;--------------------------------
;Reserves

ReserveFile "options.ini"
ReserveFile "final.ini"
!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS

;--------------------------------

; This function is called on startup. IfSilent checks
; if the flag /S was specified. If so, it sets the installer
; to run in "silent mode" which displays no windows and accepts
; all defaults.

; We also check if there is a previously installed winpcap
; on this system. If it's the same as the version we're installing,
; abort the install. If not, prompt the user about whether to
; replace it or not.

Function .onInit
  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "options.ini"
  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "final.ini"

  var /GLOBAL inst_ver
  var /GLOBAL my_ver
  StrCpy $my_ver "4.0.0.1040" 
  
  IfSilent do_silent no_silent

  do_silent:
    SetSilent silent
    IfFileExists "$SYSDIR\wpcap.dll" finish
    return

  no_silent:

    IfFileExists "$SYSDIR\wpcap.dll" do_version_check
    return

  do_version_check:

    GetDllVersion "$SYSDIR\wpcap.dll" $R0 $R1
    IntOp $R2 $R0 / 0x00010000
    IntOp $R3 $R0 & 0x0000FFFF
    IntOp $R4 $R1 / 0x00010000
    IntOp $R5 $R1 & 0x0000FFFF
    StrCpy $inst_ver "$R2.$R3.$R4.$R5"

    StrCmp $inst_ver $my_ver same_ver

    MessageBox MB_YESNO|MB_ICONQUESTION "WinPcap version $inst_ver exists on this system. Replace with version $my_ver?" IDYES finish
    quit

  same_ver:
    MessageBox MB_OK "Skipping WinPcap installation since version $inst_ver already exists on this system.  Uninstall that version first if you wish to force install."
    quit

  finish:
    ReadRegStr $0 "HKLM" "Software\WinPcap" ""

    IfFileExists "$0\Uninstall.exe" run_uninstaller
    return

  run_uninstaller:
    ExecWait '"$0\Uninstall.exe" _?=$INSTDIR'

FunctionEnd

Function optionsPage
  !insertmacro MUI_HEADER_TEXT "WinPcap Options" ""
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "options.ini"
FunctionEnd

Function doOptions
  ReadINIStr $0 "$PLUGINSDIR\options.ini" "Field 1" "State"
  StrCmp $0 "0" do_options_end
  WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\NPF" "Start" 2
  ReadINIStr $0 "$PLUGINSDIR\options.ini" "Field 2" "State"
  StrCmp $0 "0" do_options_end
  nsExec::Exec "net start npf"
  do_options_end:
FunctionEnd

Function finalPage
  ; diplay a page saying everything's finished
  !insertmacro MUI_HEADER_TEXT "Finished" "Thank you for installing WinPcap"
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "final.ini"
FunctionEnd

Function doFinal
 ; don't need to do anything
FunctionEnd

Function registerServiceSC
    nsExec::Exec "sc create npf binpath= system32\drivers\npf.sys type= kernel DisplayName= $\"NetGroup Packet Filter Driver$\""
FunctionEnd

Function un.registerServiceSC
    nsExec::Exec "sc stop npf"
    nsExec::Exec "sc delete npf"
FunctionEnd

Function autoStartWinPcap
    WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\NPF" "Start" 2
    ; silently fails on 2000 if the service isn't registered
    nsExec::Exec "net start npf"
FunctionEnd


;--------------------------------
; The stuff to install
Section "WinPcap" SecWinPcap

  ; Set output path to the installation directory.
  SetOutPath $INSTDIR
  
  ; Put file there
  File rpcapd.exe
  File LICENSE

  WriteUninstaller "uninstall.exe"

  SetOutPath $SYSDIR

  File pthreadVC.dll
  File wpcap.dll

  ; Check windows version
  ReadRegStr $R0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentVersion
  StrCmp $R0 '6.0' vista_files

  File Packet.dll
  File WanPacket.dll
  Goto install

  vista_files:
    File vista\Packet.dll

  install:
    SetOutPath $SYSDIR\drivers

    ; check for x64, install the correct npf.sys file into system32\drivers
    System::Call "kernel32::GetCurrentProcess() i .s"
    System::Call "kernel32::IsWow64Process(i s, *i .r0)"
    StrCmp $0 "0" is32bit is64bit

    is32bit:
      File npf.sys ; x86 NT5/NT6 version
      Goto npfdone

    is64bit:
      ; disable Wow64FsRedirection
      System::Call kernel32::Wow64EnableWow64FsRedirection(i0)
      File x64\npf.sys ; x64 NT5/NT6 version
      ; re-enable Wow64FsRedirection
      System::Call kernel32::Wow64EnableWow64FsRedirection(i1)

    npfdone:

    ; Install some basic registry keys
    WriteRegStr HKLM "Software\WinPcap" "" '"$INSTDIR"'

    ; register the driver as a system service using sc.exe on xp or higher
    ; this will silently fail on 2000 (unless they installed sc.exe from the resource kit)
    Call registerServiceSC

    ; automatically start the service if performing a silent install
    IfSilent auto_start skip_auto_start
    auto_start:
      Call autoStartWinPcap
    skip_auto_start:

    ; Write the uninstall keys for Windows
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\winpcap-nmap" "DisplayName" "winpcap-nmap 4.02"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\winpcap-nmap" "UninstallString" '"$INSTDIR\uninstall.exe"'
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\winpcap-nmap" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\winpcap-nmap" "NoRepair" 1

SectionEnd ; end the section


;-------------------------------- 
;Uninstaller Section 

Section "Uninstall"

  ; unregister the driver as a system service using sc.exe on xp or higher
  ; this will silently fail on 2000 (unless they installed sc.exe from the resource kit)
  Call un.registerServiceSC

  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\winpcap-nmap"
  DeleteRegKey HKLM "Software\WinPcap"

  Delete $INSTDIR\rpcapd.exe
  Delete $INSTDIR\LICENSE
  Delete $INSTDIR\uninstall.exe

  Delete $SYSDIR\Packet.dll
  Delete $SYSDIR\pthreadVC.dll
  Delete $SYSDIR\WanPacket.dll
  Delete $SYSDIR\wpcap.dll

  ; check for x64, delete npf.sys file from system32\drivers
  System::Call "kernel32::GetCurrentProcess() i .s"
  System::Call "kernel32::IsWow64Process(i s, *i .r0)"
  StrCmp $0 "0" del32bitnpf del64bitnpf
  del64bitnpf:
  ; disable Wow64FsRedirection
  System::Call kernel32::Wow64EnableWow64FsRedirection(i0)

  Delete $SYSDIR\drivers\npf.sys

  ; re-enable Wow64FsRedirection
  System::Call kernel32::Wow64EnableWow64FsRedirection(i1)
  Goto npfdeleted
  del32bitnpf:

  Delete $SYSDIR\drivers\npf.sys

  npfdeleted:

  RMDir "$INSTDIR"

SectionEnd
