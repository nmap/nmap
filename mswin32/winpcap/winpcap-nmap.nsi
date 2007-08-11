;; Custom winpcap for nmap
;; Started by Doug Hoyte, April 2006
;; Updated to 4.0, June 2007

;--------------------------------

; The name of the installer
Name "winpcap-nmap-4.0"

; The file to write
OutFile "winpcap-nmap-4.0.exe"

; The default installation directory
InstallDir $PROGRAMFILES\WinPcap

LicenseText "Winpcap License"
LicenseData "LICENSE"

;--------------------------------

Page license
Page directory
Page instfiles

UninstPage uninstConfirm
UninstPage instfiles

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
  var /GLOBAL inst_ver
  var /GLOBAL my_ver

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

    GetDllVersion "wpcap.dll" $R0 $R1
    IntOp $R2 $R0 / 0x00010000
    IntOp $R3 $R0 & 0x0000FFFF
    IntOp $R4 $R1 / 0x00010000
    IntOp $R5 $R1 & 0x0000FFFF
    StrCpy $my_ver "$R2.$R3.$R4.$R5"

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
    ExecWait '"$0\Uninstall.exe"'

FunctionEnd

;--------------------------------

; The stuff to install
Section "" ;No components page, name is not important

  ; Set output path to the installation directory.
  SetOutPath $INSTDIR
  
  ; Put file there
  File rpcapd.exe
  File LICENSE

  WriteUninstaller "uninstall.exe"

  SetOutPath $SYSDIR

  File Packet.dll
  File pthreadVC.dll
  File WanPacket.dll
  File wpcap.dll

  SetOutPath $SYSDIR\drivers

  File npf.sys

  ; Install some basic registry keys
  WriteRegStr HKLM "Software\WinPcap" "" '"$INSTDIR"'

  ; Write the uninstall keys for Windows
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\winpcap-nmap" "DisplayName" "winpcap-nmap 4.0"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\winpcap-nmap" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\winpcap-nmap" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\winpcap-nmap" "NoRepair" 1

SectionEnd ; end the section


;--------------------------------

Section "Uninstall"

  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\winpcap-nmap"
  DeleteRegKey HKLM "Software\WinPcap"

  Delete $INSTDIR\rpcapd.exe
  Delete $INSTDIR\LICENSE
  Delete $INSTDIR\uninstall.exe

  Delete $SYSDIR\Packet.dll
  Delete $SYSDIR\pthreadVC.dll
  Delete $SYSDIR\WanPacket.dll
  Delete $SYSDIR\wpcap.dll

  Delete $SYSDIR\drivers\npf.sys

  RMDir "$INSTDIR"

SectionEnd