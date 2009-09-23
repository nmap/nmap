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
; Windows API Definitions

!define SC_MANAGER_ALL_ACCESS		0x3F
!define SERVICE_ALL_ACCESS		0xF01FF

; Service Types
!define SERVICE_FILE_SYSTEM_DRIVER	0x00000002
!define SERVICE_KERNEL_DRIVER		0x00000001
!define SERVICE_WIN32_OWN_PROCESS	0x00000010
!define SERVICE_WIN32_SHARE_PROCESS	0x00000020
!define SERVICE_INTERACTIVE_PROCESS	0x00000100

; Service start options
!define SERVICE_AUTO_START		0x00000002
!define SERVICE_BOOT_START		0x00000000
!define SERVICE_DEMAND_START		0x00000003
!define SERVICE_DISABLED		0x00000004
!define SERVICE_SYSTEM_START		0x00000001

; Service Error control
!define SERVICE_ERROR_CRITICAL		0x00000003
!define SERVICE_ERROR_IGNORE		0x00000000
!define SERVICE_ERROR_NORMAL		0x00000001
!define SERVICE_ERROR_SEVERE		0x00000002

; Service Control Options
!define SERVICE_CONTROL_STOP		0x00000001
!define SERVICE_CONTROL_PAUSE		0x00000002



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
    IfFileExists "$SYSDIR\wpcap.dll" silent_checks
    return
    silent_checks:

      ; check for the presence of WinPcapInst's UninstallString
      ; first and manually cleanup registry entries to avoid running 
      ; the GUI uninstaller and assume our installer will overwrite 
      ; the files. Needs to be checked first in case someone (force) 
      ; installs WinPcap over the top of our installation
      ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "UninstallString"
      StrCmp $0 "" winpcap_keys_not_present

      DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst"

      ReadRegStr $0 "HKLM" "Software\WinPcap" ""
      StrCmp $0 "" winpcap_keys_not_present

      Delete $0\rpcapd.exe
      Delete $0\LICENSE
      Delete $0\uninstall.exe
      RMDir "$0"
      DeleteRegKey HKLM "Software\WinPcap"

      ; because we've deleted their uninstaller, skip the next 
      ; registry key check (we'll still need to overwrite stuff)
      Goto winpcap-nmap_keys_not_present

      winpcap_keys_not_present:

      ; if our registry key is present then assume all is well 
      ; (we got this far so the official WinPcap wasn't installed) 
      ; and use our uninstaller to (magically) silently uninstall 
      ; everything cleanly and avoid having to overwrite files
      ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\winpcap-nmap" "UninstallString"
      StrCmp $0 "" winpcap-nmap_keys_not_present finish

      winpcap-nmap_keys_not_present:

      ; setoverwrite on to avoid any problems when trying to install the files
      ; wpcap.dll is still present at this point, but unclear where it came from
      SetOverwrite on

      ; try to ensure that npf has been stopped before we install/overwrite files
      ExecWait '"net stop npf"'

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
    return

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
  DetailPrint "Windows CurrentVersion: $R0"
  StrCpy $R0 $R0 2 
  StrCmp $R0 '6.' vista_files

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
      DetailPrint "Installing x86 driver"
      File npf.sys ; x86 NT5/NT6 version
      Goto npfdone

    is64bit:
      DetailPrint "Installing x64 driver"
      ; disable Wow64FsRedirection
      System::Call kernel32::Wow64EnableWow64FsRedirection(i0)
      File x64\npf.sys ; x64 NT5/NT6 version
      ; re-enable Wow64FsRedirection
      System::Call kernel32::Wow64EnableWow64FsRedirection(i1)

    npfdone:

    ; Install some basic registry keys
    WriteRegStr HKLM "Software\WinPcap" "" '"$INSTDIR"'

    ; stop the service, in case it's still registered, so it can be deleted 
    nsExec::Exec "net stop npf"

    ; register the driver as a system service using Windows API calls
    ; this will work on Windows 2000 (that lacks sc.exe) and higher
    Call registerServiceAPI

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

  ; stop npf before we delete the service from the registry
  nsExec::Exec "net stop npf"
  ; unregister the driver as a system service using Windows API calls, so it works on Windows 2000
  Call un.registerServiceAPI

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
