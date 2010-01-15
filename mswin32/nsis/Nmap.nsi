;Nmap Installer 
;Started by Bo Jiang @ 08/26/2005 06:07PM 
 
;-------------------------------- 
;Include Modern UI 
 
  !include "MUI.nsh" 
  !include "AddToPath.nsh" 
  !include "FileFunc.nsh" 
 
;-------------------------------- 
;General 
 
  ;Name and file 
  Name "Nmap" 
  OutFile "NmapInstaller.exe" 

  ;Required for removing shortcuts
  RequestExecutionLevel admin

  ;Default installation folder 
  InstallDir "$PROGRAMFILES\Nmap" 
   
  ;Get installation folder from registry if available 
  InstallDirRegKey HKCU "Software\Nmap" "" 
 
  !define VERSION "5.10BETA2"  
  VIProductVersion "5.10.0.2"
  VIAddVersionKey /LANG=1033 "FileVersion" "${VERSION}"
  VIAddVersionKey /LANG=1033 "ProductName" "Nmap" 
  VIAddVersionKey /LANG=1033 "CompanyName" "Insecure.org" 
  VIAddVersionKey /LANG=1033 "InternalName" "NmapInstaller.exe" 
  VIAddVersionKey /LANG=1033 "LegalCopyright" "Copyright (c) Insecure.Com LLC (fyodor@insecure.org)" 
  VIAddVersionKey /LANG=1033 "LegalTrademark" "NMAP" 
  VIAddVersionKey /LANG=1033 "FileDescription" "Nmap installer" 
   
;-------------------------------- 
;Interface Settings 
 
  !define MUI_ABORTWARNING 
 
;-------------------------------- 
;Pages 
 
  !insertmacro MUI_PAGE_LICENSE "..\LICENSE" 
  !insertmacro MUI_PAGE_COMPONENTS 
  !insertmacro MUI_PAGE_DIRECTORY 
  !insertmacro MUI_PAGE_INSTFILES 
  !insertmacro MUI_UNPAGE_CONFIRM 
  !insertmacro MUI_UNPAGE_INSTFILES 
  Page custom shortcutsPage makeShortcuts
  Page custom finalPage doFinal
   
;-------------------------------- 
;Languages 
  
  !insertmacro MUI_LANGUAGE "English" 

!insertmacro GetParameters
!insertmacro GetOptions

;--------------------------------
;Variables

Var zenmapset

;--------------------------------
;Reserves

ReserveFile "shortcuts.ini"
ReserveFile "final.ini"
!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS

;--------------------------------
;Functions

Function .onInit
  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "shortcuts.ini"
  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "final.ini"
FunctionEnd


Function shortcutsPage
  StrCmp $zenmapset "" skip

  !insertmacro MUI_HEADER_TEXT "Create Shortcuts" ""
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "shortcuts.ini"  

  skip:
FunctionEnd

Function makeShortcuts
  StrCmp $zenmapset "" skip

  SetOutPath "$INSTDIR"

  ReadINIStr $0 "$PLUGINSDIR\shortcuts.ini" "Field 1" "State"
  StrCmp $0 "0" skipdesktop
  CreateShortCut "$DESKTOP\Nmap - Zenmap GUI.lnk" "$INSTDIR\zenmap.exe"

  skipdesktop:

  ReadINIStr $0 "$PLUGINSDIR\shortcuts.ini" "Field 2" "State"
  StrCmp $0 "0" skipstartmenu
  CreateDirectory "$SMPROGRAMS\Nmap"
  CreateShortCut "$SMPROGRAMS\Nmap\Nmap - Zenmap GUI.lnk" "$INSTDIR\zenmap.exe"

  skipstartmenu:

  skip:
FunctionEnd

Function finalPage
  ; diplay a page saying everything's finished
  !insertmacro MUI_HEADER_TEXT "Finished" "Thank you for installing Nmap"
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "final.ini"
FunctionEnd

Function doFinal
 ; don't need to do anything
FunctionEnd

;-------------------------------- 
;Installer Sections 
 
Section "Nmap Core Files" SecCore 

  StrCpy $R0 $INSTDIR "" -2
  StrCmp $R0 ":\" bad_key_install
  StrCpy $R0 $INSTDIR "" -14
  StrCmp $R0 "\Program Files" bad_key_install
  StrCpy $R0 $INSTDIR "" -8
  StrCmp $R0 "\Windows" bad_key_install
  StrCpy $R0 $INSTDIR "" -6
  StrCmp $R0 "\WinNT" bad_key_install
  StrCpy $R0 $INSTDIR "" -9
  StrCmp $R0 "\system32" bad_key_install
  StrCpy $R0 $INSTDIR "" -8
  StrCmp $R0 "\Desktop" bad_key_install
  StrCpy $R0 $INSTDIR "" -22
  StrCmp $R0 "\Documents and Settings" bad_key_install
  StrCpy $R0 $INSTDIR "" -13
  StrCmp $R0 "\My Documents" bad_key_install probably_safe_key_install
  bad_key_install:
    MessageBox MB_YESNO "It may not be safe to uninstall the previous installation of Nmap from the directory '$INSTDIR'.$\r$\nContinue anyway (not recommended)?" IDYES probably_safe_key_install 
    Abort "Install aborted by user" 
  probably_safe_key_install:

  ;Delete specific subfolders (NB: custom scripts in scripts folder will be lost)
  RMDir /r "$INSTDIR\nselib"
  ; nselib-bin held NSE C modules up through version 4.68.
  RMDir /r "$INSTDIR\nselib-bin"
  RMDir /r "$INSTDIR\scripts"
  RMDir /r "$INSTDIR\zenmap"

  SetOutPath "$INSTDIR" 

  SetOverwrite on 
  File ..\..\CHANGELOG 
  File ..\..\COPYING 
  File ..\..\nmap-mac-prefixes 
  File ..\..\nmap-os-db 
  File ..\..\nmap-protocols 
  File ..\..\nmap-rpc 
  File ..\..\nmap-service-probes 
  File ..\..\nmap-services 
  File ..\Release\nmap.exe
  File ..\Release\nse_main.lua
  File ..\..\docs\nmap.xsl 
  File ..\nmap_performance.reg 
  File ..\..\README-WIN32 
  File libeay32.dll
  File ssleay32.dll
  File /r /x mswin32 /x .svn /x ncat ..\..\scripts
  File /r /x mswin32 /x .svn ..\Release\nselib
  File ..\icon1.ico 
  
  ;Store installation folder 
  WriteRegStr HKCU "Software\Nmap" "" $INSTDIR 

  ;Check if VC++ 2008 runtimes are already installed - NOTE Both the UID in the registry key and the DisplayName string must be updated here (and below)
  ;whenever the Redistributable package is upgraded:
    ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{9A25302D-30C0-39D9-BD6F-21E6EC160475}" "DisplayName"
    StrCmp $0 "Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.17" create_uninstaller vcredist_silent_install

  ;If VC++ 2008 runtimes are not installed...
  vcredist_silent_install:
    DetailPrint "Installing Microsoft Visual C++ 2008 Redistributable"
    File ..\vcredist_x86.exe
    ExecWait '"$INSTDIR\vcredist_x86.exe" /q' $0
    ;Check for successful installation of our vcredist_x86.exe...
    ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{9A25302D-30C0-39D9-BD6F-21E6EC160475}" "DisplayName"
    StrCmp $0 "Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.17" vcredist_success vcredist_not_present
    vcredist_not_present:
      DetailPrint "Microsoft Visual C++ 2008 Redistributable failed to install"
      IfSilent create_uninstaller vcredist_messagebox
      vcredist_messagebox:
        MessageBox MB_OK "Microsoft Visual C++ 2008 Redistributable Package (x86) failed to install ($INSTDIR\vcredist_x86.exe). Please ensure your system meets the minimum requirements before running the installer again."
        Goto create_uninstaller
    vcredist_success:
      Delete "$INSTDIR\vcredist_x86.exe" 
      DetailPrint "Microsoft Visual C++ 2008 Redistributable was successfully installed"

  create_uninstaller:
  ;Create uninstaller 
  WriteUninstaller "$INSTDIR\Uninstall.exe" 
   
  ; Register Nmap with add/remove programs 
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Nmap" "DisplayName" "Nmap ${VERSION}" 
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Nmap" "UninstallString" '"$INSTDIR\uninstall.exe"' 
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Nmap" "DisplayIcon" '"$INSTDIR\icon1.ico"' 
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Nmap" "NoModify" 1 
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Nmap" "NoRepair" 1 
SectionEnd 
 
Section "Register Nmap Path" SecRegisterPath 
  PUSH $INSTDIR 
  Call AddToPath 
SectionEnd 
 
Section "WinPcap 4.1.1" SecWinPcap 
  SetOutPath "$INSTDIR" 
  SetOverwrite on 
  File ..\winpcap\winpcap-nmap-4.11.exe 
  ; If the Nmap installer was launched using /S then pass some arguments to WinPcap
  IfSilent winpcap_silent winpcap_loud
  winpcap_silent:
    StrCpy $1 ""
    ${GetParameters} $R0
    ClearErrors
    ${GetOptions} $R0 "/NPFSTARTUP=" $2
    StrCmp $2 "NO" 0 NoSkipNPFStartup
    StrCpy $1 "/NPFSTARTUP=NO $1"
    NoSkipNPFStartup:

    ; check for x64 so we install files into C:\Program Files on both platforms
    ; as this is consistent with WinPcap 4.1 (even though rpcapd is a 32-bit
    ; executable that probably should be in C:\Program Files (x86)\ (where we've
    ; installed it in the past). Otherwise install in the normal x86 location.
    System::Call "kernel32::GetCurrentProcess() i .s"
    System::Call "kernel32::IsWow64Process(i s, *i .r0)"
    StrCmp $0 "0" InstDir32bit InstDir64bit
      InstDir64bit:
        ExecWait '"$INSTDIR\winpcap-nmap-4.11.exe" $1 /S /D=$\""$PROGRAMFILES64\WinPcap\"$\"' 
	    Goto InstDirDone
      InstDir32bit:
	    ExecWait '"$INSTDIR\winpcap-nmap-4.11.exe" $1 /S /D=$\""$PROGRAMFILES\WinPcap\"$\"' 
    InstDirDone:
  Goto delete_winpcap
  winpcap_loud:
    ExecWait '"$INSTDIR\winpcap-nmap-4.11.exe"' 
  delete_winpcap:
  Delete "$INSTDIR\winpcap-nmap-4.11.exe" 
SectionEnd 

Section "Network Performance Improvements" SecPerfRegistryMods 
  SetOutPath "$INSTDIR" 
  SetOverwrite on 
  File ..\nmap_performance.reg 
  Exec 'regedt32 /S "$INSTDIR\nmap_performance.reg"' 
SectionEnd 

Section "Zenmap (GUI Frontend)" SecZenmap
  SetOutPath "$INSTDIR" 
  SetOverwrite on 
  File ..\nmap-${VERSION}\zenmap.exe
  File ..\nmap-${VERSION}\ZENMAP_README
  File ..\nmap-${VERSION}\COPYING_HIGWIDGETS
  File ..\nmap-${VERSION}\python26.dll
  File /r ..\nmap-${VERSION}\share
  File /r ..\nmap-${VERSION}\py2exe
  StrCpy $zenmapset "true"
SectionEnd

Section "Ncat (Modern Netcat reincarnation)" SecNcat
  SetOutPath "$INSTDIR"
  SetOverwrite on
  File ..\nmap-${VERSION}\ncat.exe
  File ..\nmap-${VERSION}\ca-bundle.crt
SectionEnd

Section "Ndiff (Scan comparison tool)" SecNdiff
  SetOutPath "$INSTDIR" 
  SetOverwrite on 
  File ..\nmap-${VERSION}\ndiff.exe
  File ..\nmap-${VERSION}\NDIFF_README
  File ..\nmap-${VERSION}\python26.dll
  File /r ..\nmap-${VERSION}\py2exe
SectionEnd
 
;-------------------------------- 
;Descriptions 
 
  ;Component strings 
  LangString DESC_SecCore ${LANG_ENGLISH} "Installs Nmap executable, NSE scripts and Visual C++ 2008 runtime components"
  LangString DESC_SecRegisterPath ${LANG_ENGLISH} "Registers Nmap path to System path so you can execute it from any directory" 
  LangString DESC_SecWinPcap ${LANG_ENGLISH} "Installs WinPcap 4.1 (required for most Nmap scans unless it is already installed)" 
  LangString DESC_SecPerfRegistryMods ${LANG_ENGLISH} "Modifies Windows registry values to improve TCP connect scan performance.  Recommended." 
  LangString DESC_SecZenmap ${LANG_ENGLISH} "Installs Zenmap, the official Nmap graphical user interface.  Recommended." 
  LangString DESC_SecNcat ${LANG_ENGLISH} "Installs Ncat, Nmap's Netcat replacement." 
  LangString DESC_SecNdiff ${LANG_ENGLISH} "Installs Ndiff, a tool for comparing Nmap XML files."

  ;Assign language strings to sections 
  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} $(DESC_SecCore) 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecWinPcap} $(DESC_SecWinPcap) 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecRegisterPath} $(DESC_SecRegisterPath) 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecPerfRegistryMods} $(DESC_SecPerfRegistryMods) 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecZenmap} $(DESC_SecZenmap) 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecNcat} $(DESC_SecNcat) 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecNdiff} $(DESC_SecNdiff) 
  !insertmacro MUI_FUNCTION_DESCRIPTION_END 
;-------------------------------- 
;Uninstaller Section 
 
Section "Uninstall" 

  StrCpy $R0 $INSTDIR "" -2
  StrCmp $R0 ":\" bad_key_uninstall
  StrCpy $R0 $INSTDIR "" -14
  StrCmp $R0 "\Program Files" bad_key_uninstall
  StrCpy $R0 $INSTDIR "" -8
  StrCmp $R0 "\Windows" bad_key_uninstall
  StrCpy $R0 $INSTDIR "" -6
  StrCmp $R0 "\WinNT" bad_key_uninstall
  StrCpy $R0 $INSTDIR "" -9
  StrCmp $R0 "\system32" bad_key_uninstall
  StrCpy $R0 $INSTDIR "" -8
  StrCmp $R0 "\Desktop" bad_key_uninstall
  StrCpy $R0 $INSTDIR "" -22
  StrCmp $R0 "\Documents and Settings" bad_key_uninstall
  StrCpy $R0 $INSTDIR "" -13
  StrCmp $R0 "\My Documents" bad_key_uninstall probably_safe_key_uninstall
  bad_key_uninstall:
    MessageBox MB_YESNO "It may not be safe to uninstall Nmap from the directory '$INSTDIR'.$\r$\nContinue anyway (not recommended)?" IDYES probably_safe_key_uninstall 
    Abort "Uninstall aborted by user" 
  probably_safe_key_uninstall:

  IfFileExists $INSTDIR\nmap.exe nmap_installed 
    MessageBox MB_YESNO "It does not appear that Nmap is installed in the directory '$INSTDIR'.$\r$\nContinue anyway (not recommended)?" IDYES nmap_installed 
    Abort "Uninstall aborted by user" 

  SetDetailsPrint textonly 
  DetailPrint "Uninstalling Files..." 
  SetDetailsPrint listonly 
   
  nmap_installed: 
  Delete "$INSTDIR\CHANGELOG" 
  Delete "$INSTDIR\COPYING" 
  Delete "$INSTDIR\nmap-mac-prefixes" 
  Delete "$INSTDIR\nmap-os-db" 
  Delete "$INSTDIR\nmap-protocols" 
  Delete "$INSTDIR\nmap-rpc" 
  Delete "$INSTDIR\nmap-service-probes" 
  Delete "$INSTDIR\nmap-services" 
  Delete "$INSTDIR\nmap.exe" 
  Delete "$INSTDIR\nmap.xsl" 
  Delete "$INSTDIR\nmap_performance.reg"  
  Delete "$INSTDIR\nse_main.lua"  
  Delete "$INSTDIR\README-WIN32" 
  Delete "$INSTDIR\icon1.ico"
  Delete "$INSTDIR\libeay32.dll"
  Delete "$INSTDIR\ssleay32.dll"
  Delete "$INSTDIR\winpcap-nmap*.exe"
  Delete "$INSTDIR\zenmap.exe"
  Delete "$INSTDIR\ndiff.exe"
  Delete "$INSTDIR\python26.dll"
  Delete "$INSTDIR\NDIFF_README"
  Delete "$INSTDIR\ZENMAP_README"
  Delete "$INSTDIR\COPYING_HIGWIDGETS"
  Delete "$INSTDIR\ncat.exe"
  Delete "$INSTDIR\ca-bundle.crt"
  ;Delete specific subfolders (NB: custom scripts in scripts folder will be lost)
  RMDir /r "$INSTDIR\nselib"
  RMDir /r "$INSTDIR\scripts"
  RMDir /r "$INSTDIR\share"
  RMDir /r "$INSTDIR\py2exe"
 
  Delete "$INSTDIR\Uninstall.exe" 

  ;Removes folder if it's now empty
  RMDir "$INSTDIR"
 
  SetDetailsPrint textonly 
  DetailPrint "Deleting Registry Keys..." 
  SetDetailsPrint listonly 
  DeleteRegKey /ifempty HKCU "Software\Nmap" 
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Nmap" 
  SetDetailsPrint textonly 
  DetailPrint "Unregistering Nmap Path..." 
  Push $INSTDIR 
  Call un.RemoveFromPath 

  Delete "$DESKTOP\Nmap - Zenmap GUI.lnk"
  Delete "$SMPROGRAMS\Nmap\Nmap - Zenmap GUI.lnk"
  RMDIR "$SMPROGRAMS\Nmap"

  SetDetailsPrint both 
SectionEnd 
