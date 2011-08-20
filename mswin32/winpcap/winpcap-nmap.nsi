;; Custom winpcap for nmap
;; Recognizes the options (case sensitive):
;;   /S              silent install
;;   /NPFSTARTUP=NO  start NPF now and at startup (only has effect with /S)

;; Started by Doug Hoyte, April 2006

;; Eddie Bell
;; Updated to 4.0, June 2007
;; Updated to 4.01, July 2007
;; Updated to 4.02, November 2007

;; Rob Nicholls
;; Updated to 4.1.1, October 2009
;; Updated to 4.1.2, July 2010

SetCompressor /SOLID /FINAL lzma

;--------------------------------
;Include Modern UI

  !include "MUI.nsh"
  !include "FileFunc.nsh"

;--------------------------------
;General

; The name of the installer
Name "WinPcap (Nmap) 4.1.2"

; The file to write
OutFile "winpcap-nmap-4.12.exe"

RequestExecutionLevel admin

; These leave either "1" or "0" in $0.
Function is64bit
  System::Call "kernel32::GetCurrentProcess() i .s"
  System::Call "kernel32::IsWow64Process(i s, *i .r0)"
FunctionEnd
Function un.is64bit
  System::Call "kernel32::GetCurrentProcess() i .s"
  System::Call "kernel32::IsWow64Process(i s, *i .r0)"
FunctionEnd

VIProductVersion "4.1.0.2001"
VIAddVersionKey /LANG=1033 "FileVersion" "4.1.0.2001"
VIAddVersionKey /LANG=1033 "ProductName" "WinPcap"
VIAddVersionKey /LANG=1033 "FileDescription" "WinPcap 4.1.2 installer"
VIAddVersionKey /LANG=1033 "LegalCopyright" ""

;--------------------------------
; Windows API Definitions

!define SC_MANAGER_ALL_ACCESS           0x3F
!define SERVICE_ALL_ACCESS              0xF01FF

; Service Types
!define SERVICE_FILE_SYSTEM_DRIVER      0x00000002
!define SERVICE_KERNEL_DRIVER           0x00000001
!define SERVICE_WIN32_OWN_PROCESS       0x00000010
!define SERVICE_WIN32_SHARE_PROCESS     0x00000020
!define SERVICE_INTERACTIVE_PROCESS     0x00000100

; Service start options
!define SERVICE_AUTO_START              0x00000002
!define SERVICE_BOOT_START              0x00000000
!define SERVICE_DEMAND_START            0x00000003
!define SERVICE_DISABLED                0x00000004
!define SERVICE_SYSTEM_START            0x00000001

; Service Error control
!define SERVICE_ERROR_CRITICAL          0x00000003
!define SERVICE_ERROR_IGNORE            0x00000000
!define SERVICE_ERROR_NORMAL            0x00000001
!define SERVICE_ERROR_SEVERE            0x00000002

; Service Control Options
!define SERVICE_CONTROL_STOP            0x00000001
!define SERVICE_CONTROL_PAUSE           0x00000002



;--------------------------------
;Interface Settings

  !define MUI_ABORTWARNING

;--------------------------------
;Pages

!insertmacro MUI_PAGE_LICENSE "LICENSE"
; Don't let user choose where to install the files. WinPcap doesn't let people, and it's one less thing for us to worry about.
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

!insertmacro GetParameters
!insertmacro GetOptions

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
  var /GLOBAL npf_startup
  StrCpy $my_ver "4.1.0.2001"
  StrCpy $npf_startup "YES"

  ; Always use the requested /D= $INSTDIR if given.
  StrCmp $INSTDIR "" "" instdir_nochange
  ; On 64-bit Windows, $PROGRAMFILES is "C:\Program Files (x86)" and
  ; $PROGRAMFILES64 is "C:\Program Files". We want "C:\Program Files"
  ; on 32-bit or 64-bit.
  StrCpy $INSTDIR "$PROGRAMFILES\WinPcap"
  Call is64bit
  StrCmp $0 "0" instdir_nochange
  StrCpy $INSTDIR "$PROGRAMFILES64\WinPcap"
  instdir_nochange:

  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/NPFSTARTUP=" $npf_startup

  IfSilent do_silent no_silent

  do_silent:
    SetSilent silent
    IfFileExists "$SYSDIR\wpcap.dll" silent_checks
    return
    silent_checks:
      ; check for the presence of Nmap's custom WinPcapInst registry key:
      ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "InstalledBy"
      StrCmp $0 "Nmap" silent_uninstall winpcap_installedby_keys_not_present

      winpcap_installedby_keys_not_present:
      ; check for the presence of WinPcapInst's UninstallString
      ; and manually cleanup registry entries to avoid running
      ; the GUI uninstaller and assume our installer will overwrite
      ; the files. Needs to be checked in case someone (force)
      ; installs WinPcap over the top of our installation
      ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "UninstallString"
      StrCmp $0 "" winpcap_keys_not_present

      DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst"

      ReadRegStr $0 "HKLM" "Software\WinPcap" ""
      StrCmp $0 "" winpcap_keys_not_present

      Delete $0\rpcapd.exe
      Delete $0\LICENSE
      Delete $0\uninstall.exe
      ; Official 4.1 installer creates an install.log
      Delete $0\install.log
      RMDir "$0"
      DeleteRegKey HKLM "Software\WinPcap"

      ; because we've deleted their uninstaller, skip the next
      ; registry key check (we'll still need to overwrite stuff)
      Goto winpcap-nmap_keys_not_present

      winpcap_keys_not_present:

      ; if our old registry key is present then assume all is well
      ; (we got this far so the official WinPcap wasn't installed)
      ; and use our uninstaller to (magically) silently uninstall
      ; everything cleanly and avoid having to overwrite files
      ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\winpcap-nmap" "UninstallString"
      StrCmp $0 "" winpcap-nmap_keys_not_present silent_uninstall

      winpcap-nmap_keys_not_present:

      ; setoverwrite on to try and avoid any problems when trying to install the files
      ; wpcap.dll is still present at this point, but unclear where it came from
      SetOverwrite on

      ; try to ensure that npf has been stopped before we install/overwrite files
      ExecWait '"net stop npf"'

      return

      silent_uninstall:
        ; Our InstalledBy string is present, UninstallString should have quotes and uninstall.exe location
        ; and this file should support a silent uninstall by passing /S to it.
        ; we could read QuietUninstallString, but this should be exactly the same as UninstallString with /S on the end.
        ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "UninstallString"
        ExecWait '$0 /S _?=$INSTDIR'
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

    MessageBox MB_YESNO|MB_ICONQUESTION "WinPcap version $inst_ver exists on this system. Replace with version $my_ver?" IDYES try_uninstallers
    quit

  same_ver:
    MessageBox MB_OK "Skipping WinPcap installation since version $inst_ver already exists on this system.  Uninstall that version first if you wish to force install."
    quit

  try_uninstallers:

    ; check for UninstallString and use that in preference (should already have double quotes and uninstall.exe)
    ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "UninstallString"
    StrCmp $0 "" no_uninstallstring
    IfFileExists "$0" uninstaller_exists no_uninstallstring
    uninstaller_exists:
    ExecWait '$0 _?=$INSTDIR'
    return

    no_uninstallstring:
    ; didn't find an UninstallString, check for our old UninstallString and if uninstall.exe exists:
    ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\winpcap-nmap" "UninstallString"
    StrCmp $0 "" still_no_uninstallstring
    IfFileExists "$0" old_uninstaller_exists still_no_uninstallstring
    old_uninstaller_exists:
    MessageBox MB_OK "Using our old UninstallString, file exists"
    ExecWait '$0 _?=$INSTDIR'
    return

    still_no_uninstallstring:
    ; still didn't find anything, try looking for an uninstall.exe file at:
      ReadRegStr $0 "HKLM" "Software\WinPcap" ""
    ; Strip any surrounding double quotes from around the install string,
    ; as WinPcap hasn't used quotes in the past, but our old installers did.
    ; Check the first and last character for safety!
    StrCpy $1 $0 1
    StrCmp $1 "$\"" maybestripquotes nostrip
    maybestripquotes:
    StrLen $1 $0
    IntOp $1 $1 - 1
    StrCpy $1 $0 1 $1
    StrCmp $1 "$\"" stripquotes nostrip
    stripquotes:
    StrCpy $0 $0 -1 1
    nostrip:
    IfFileExists "$0\uninstall.exe" run_last_uninstaller no_uninstall_exe
    run_last_uninstaller:
    ExecWait '"$0\Uninstall.exe" _?=$INSTDIR'
    no_uninstall_exe:
    ; give up now, we've tried our hardest to determine a valid uninstaller!
    return

FunctionEnd

Function optionsPage
  !insertmacro MUI_HEADER_TEXT "WinPcap Options" ""
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "options.ini"
FunctionEnd

Function doOptions
  ReadINIStr $0 "$PLUGINSDIR\options.ini" "Field 1" "State"
  StrCmp $0 "0" do_options_next
  WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\NPF" "Start" 2
  do_options_next:
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

Function registerServiceAPI
  ; delete the npf service to avoid an error message later if it already exists
  System::Call 'advapi32::OpenSCManagerA(,,i ${SC_MANAGER_ALL_ACCESS})i.r0'
  System::Call 'advapi32::OpenServiceA(i r0,t "npf", i ${SERVICE_ALL_ACCESS}) i.r1'
  System::Call 'advapi32::DeleteService(i r1) i.r6'
  System::Call 'advapi32::CloseServiceHandle(i r1) n'
  System::Call 'advapi32::CloseServiceHandle(i r0) n'
  ; create the new npf service
  System::Call 'advapi32::OpenSCManagerA(,,i ${SC_MANAGER_ALL_ACCESS})i.R0'
  System::Call 'advapi32::CreateServiceA(i R0,t "npf",t "NetGroup Packet Filter Driver",i ${SERVICE_ALL_ACCESS},i ${SERVICE_KERNEL_DRIVER}, i ${SERVICE_DEMAND_START},i ${SERVICE_ERROR_NORMAL}, t "system32\drivers\npf.sys",,,,,) i.r1'
  StrCmp $1 "0" register_fail register_success
  register_fail:
    DetailPrint "Failed to create the npf service"
    IfSilent close_register_handle register_fail_messagebox
    register_fail_messagebox:
      MessageBox MB_OK "Failed to create the npf service. Please try installing WinPcap again, or use the official WinPcap installer from www.winpcap.org"
    Goto close_register_handle
  register_success:
    DetailPrint "The npf service was successfully created"
  close_register_handle:
  System::Call 'advapi32::CloseServiceHandle(i R0) n'
FunctionEnd

Function un.registerServiceAPI
  System::Call 'advapi32::OpenSCManagerA(,,i ${SC_MANAGER_ALL_ACCESS})i.r0'
  System::Call 'advapi32::OpenServiceA(i r0,t "npf", i ${SERVICE_ALL_ACCESS}) i.r1'
  System::Call 'advapi32::DeleteService(i r1) i.r6'
  StrCmp $6 "0" unregister_fail unregister_success
  unregister_fail:
    DetailPrint "Failed to delete the npf service"
    Goto close_unregister_handle
  unregister_success:
    DetailPrint "The npf service was successfully deleted"
  close_unregister_handle:
  System::Call 'advapi32::CloseServiceHandle(i r1) n'
  System::Call 'advapi32::CloseServiceHandle(i r0) n'
FunctionEnd

Function autoStartWinPcap
    WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\NPF" "Start" 2
    nsExec::Exec "net start npf"
FunctionEnd


;--------------------------------
; The stuff to install
Section "WinPcap" SecWinPcap

  ; stop the service, in case it's still registered, so files can be
  ; safely overwritten and the service can be deleted.
  nsExec::Exec "net stop npf"

  ; NB: We may need to introduce a check here to ensure that NPF
  ; has been stopped before we continue, otherwise we Sleep for a
  ; while and try the check again. This might help prevent any race
  ; conditions during a silent install (and potentially during the
  ; slower GUI installation.

  ; These x86 files are automatically redirected to the right place on x64
  SetOutPath $SYSDIR
  File pthreadVC.dll
  File wpcap.dll

  ; Check windows version
  ReadRegStr $R0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentVersion
  DetailPrint "Windows CurrentVersion: $R0"
  StrCpy $R0 $R0 2
  StrCmp $R0 '6.' vista_files

  File nt5\x86\Packet.dll
  Goto install

  vista_files:
    File vista\x86\Packet.dll

  install:
    Call is64bit
    StrCmp $0 "0" install_32bit install_64bit

    ; Note, NSIS states: "You should always quote the path to make sure spaces
    ; in the path will not disrupt Windows to find the uninstaller."
    ; See: http://nsis.sourceforge.net/Add_uninstall_information_to_Add/Remove_Programs
    ; This matches (most) Windows installations. Rather inconsistently,
    ; DisplayIcon doesn't usually have quotes (even on Microsoft installations) and
    ; HKLM Software\PackageName doesn't usually have quotes either.

    install_32bit:
      SetOutPath $INSTDIR
      File rpcapd.exe
      File LICENSE
      WriteUninstaller "$INSTDIR\uninstall.exe"
      DetailPrint "Installing x86 driver"
      SetOutPath $SYSDIR\drivers
      File npf.sys ; x86 NT5/NT6 version
      WriteRegStr HKLM "Software\WinPcap" "" "$INSTDIR"
      WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
      WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
      WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "DisplayIcon" "$INSTDIR\uninstall.exe"
      Goto npfdone

    install_64bit:
      SetOutPath $INSTDIR
      File rpcapd.exe
      File LICENSE
      WriteUninstaller "$INSTDIR\uninstall.exe"
      DetailPrint "Installing x64 driver"
      SetOutPath $SYSDIR\drivers
      ; disable Wow64FsRedirection
      System::Call kernel32::Wow64EnableWow64FsRedirection(i0)
      File x64\npf.sys ; x64 NT5/NT6 version
      ; The x86 versions of wpcap.dll and packet.dll are
      ; installed into the right place further above.
      ; install the 64-bit version of wpcap.dll into System32
      SetOutPath $SYSDIR
      File x64\wpcap.dll ; x64 NT5/NT6 version
      ; install the 64-bit version of packet.dll into System32
      ; check for vista, otherwise install the NT5 version (for XP and 2003)
      StrCpy $R0 $R0 2
      StrCmp $R0 '6.' vista_x64_packet
      File nt5\x64\Packet.dll ; x64 XP/2003 version
      Goto nt5_x64_packet_done
      vista_x64_packet:
      File vista\x64\Packet.dll ; x64 Vista version
      nt5_x64_packet_done:
      WriteRegStr HKLM "Software\WinPcap" "" "$INSTDIR"
      ; re-enable Wow64FsRedirection
      System::Call kernel32::Wow64EnableWow64FsRedirection(i1)
      WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
      WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
      WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "DisplayIcon" "$INSTDIR\uninstall.exe"

    npfdone:

    ; register the driver as a system service using Windows API calls
    ; this will work on Windows 2000 (that lacks sc.exe) and higher
    Call registerServiceAPI

    ; Create the default NPF startup setting of 3 (SERVICE_DEMAND_START)
    WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\NPF" "Start" 3

    ; automatically start the service if performing a silent install, unless
    ; /NPFSTARTUP=NO was given.
    IfSilent 0 skip_auto_start
    StrCmp $npf_startup "NO" skip_auto_start
      Call autoStartWinPcap
    skip_auto_start:

    ; Write the rest of the uninstall keys for Windows

    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "DisplayName" "WinPcap 4.1.2"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "DisplayVersion" "4.1.0.2001"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "Publisher" "CACE Technologies"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "URLInfoAbout" "http://www.cacetech.com"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "URLUpdateInfo" "http://www.winpcap.org"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "VersionMajor" "4"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "VersionMinor" "1"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "InstalledBy" "Nmap"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "NoRepair" 1

  ; delete our  legacy winpcap-nmap keys if they still exist (e.g. official 4.0.2 force installed over our 4.0.2):
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\winpcap-nmap"

SectionEnd ; end the section


;--------------------------------
;Uninstaller Section

Section "Uninstall"

  ; stop npf before we delete the service from the registry
  nsExec::Exec "net stop npf"
  ; unregister the driver as a system service using Windows API calls, so it works on Windows 2000
  Call un.registerServiceAPI

  ; delete our winpcap-nmap and any WinPcapInst registry keys
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\winpcap-nmap"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst"
  DeleteRegKey HKLM "Software\WinPcap"

  Delete $INSTDIR\rpcapd.exe
  Delete $INSTDIR\LICENSE
  Delete $INSTDIR\uninstall.exe

  ; This deletes the x86 files from SysWOW64 if we're on x64.
  Delete $SYSDIR\Packet.dll
  Delete $SYSDIR\pthreadVC.dll
  Delete $SYSDIR\wpcap.dll

  ; check for x64, delete npf.sys file from system32\drivers
  Call un.is64bit
  StrCmp $0 "0" del32bitnpf del64bitnpf
  del64bitnpf:
  ; disable Wow64FsRedirection
  System::Call kernel32::Wow64EnableWow64FsRedirection(i0)

  Delete $SYSDIR\drivers\npf.sys
  ; Also delete the x64 files in System32
  Delete $SYSDIR\wpcap.dll
  Delete $SYSDIR\Packet.dll

  ; re-enable Wow64FsRedirection
  System::Call kernel32::Wow64EnableWow64FsRedirection(i1)
  Goto npfdeleted
  del32bitnpf:

  Delete $SYSDIR\drivers\npf.sys

  npfdeleted:

  RMDir "$INSTDIR"

SectionEnd
