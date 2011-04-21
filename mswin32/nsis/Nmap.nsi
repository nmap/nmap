;Nmap Installer 
;Started by Bo Jiang @ 08/26/2005 06:07PM 
;;
;; Recognizes the options (case sensitive):
;;   /S                silent install
;;   /NPFSTARTUP=NO    start NPF now and at startup (ignored with /WINPCAP=NO)
;;   /NMAP=NO          don't install Nmap
;;   /REGISTERPATH=NO  don't add the installation directory to PATH
;;   /WINPCAP=NO       don't install WinPcap
;;   /REGISTRYMODS=NO  don't install performance-related registry mods
;;   /ZENMAP=NO        don't install Zenmap
;;   /NCAT=NO          don't install Ncat
;;   /NDIFF=NO         don't install Ndiff
;;   /NPING=NO         don't install Nping
;;   /D=C:\dir\...     install to C:\dir\... (overrides InstallDir)
;;
;;/D is a built-in NSIS option and has these restrictions:
;;(http://nsis.sourceforge.net/Docs/Chapter3.html)
;;  It must be the last parameter used in the command line and must not
;;  contain any quotes, even if the path contains spaces. Only absolute
;;  paths are supported.
 
; The default compressor is zlib; lzma gives about 15% better compression.
; http://nsis.sourceforge.net/Docs/Chapter4.html#4.8.2.4
SetCompressor /SOLID /FINAL lzma

;-------------------------------- 
;Include Modern UI 
 
  !include "MUI.nsh" 
  !include "AddToPath.nsh" 
  !include "FileFunc.nsh" 
  !include "Sections.nsh"
 
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
 
  !define VERSION "5.51SVN"  
  VIProductVersion "5.51.0.0"
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
Var addremoveset
Var vcredist2010set
Var vcredist2008set

;--------------------------------
;Reserves

ReserveFile "shortcuts.ini"
ReserveFile "final.ini"
!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS

;--------------------------------
;Functions

;The .onInit function is below the Sections because it needs to refer to
;the Section IDs which are not defined yet.

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
  RMDir /r "$INSTDIR\py2exe"
  RMDir /r "$INSTDIR\share"
  RMDir /r "$INSTDIR\licenses"

  SetOutPath "$INSTDIR" 

  SetOverwrite on 
  File ..\..\CHANGELOG 
  File ..\..\COPYING 
  File ..\..\nmap-mac-prefixes 
  File ..\..\nmap-os-db 
  File ..\..\nmap-payloads 
  File ..\..\nmap-protocols 
  File ..\..\nmap-rpc 
  File ..\..\nmap-service-probes 
  File ..\..\nmap-services 
  File ..\Release\nmap.exe
  File ..\Release\nse_main.lua
  File ..\..\docs\nmap.xsl 
  File ..\nmap_performance.reg 
  File ..\..\README-WIN32 
  File ..\..\docs\3rd-party-licenses.txt
  File /r ..\..\docs\licenses
  File libeay32.dll
  File ssleay32.dll
  File /r /x mswin32 /x .svn /x ncat ..\..\scripts
  File /r /x mswin32 /x .svn ..\Release\nselib
  File ..\icon1.ico 
  
  ;Store installation folder 
  WriteRegStr HKCU "Software\Nmap" "" $INSTDIR 

  Call vcredist2010installer
  Call create_uninstaller
   
SectionEnd 
 
Section "Register Nmap Path" SecRegisterPath 
  PUSH $INSTDIR 
  Call AddToPath 
SectionEnd 
 
Section "WinPcap 4.1.2" SecWinPcap 
  SetOutPath "$INSTDIR" 
  SetOverwrite on 
  File ..\winpcap\winpcap-nmap-4.12.exe 
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
    ExecWait '"$INSTDIR\winpcap-nmap-4.12.exe" $1 /S' 
    Goto delete_winpcap
  winpcap_loud:
    ExecWait '"$INSTDIR\winpcap-nmap-4.12.exe"' 
  delete_winpcap:
  Delete "$INSTDIR\winpcap-nmap-4.12.exe" 
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
  File ..\nmap-${VERSION}\python27.dll
  File /r ..\nmap-${VERSION}\share
  File /r ..\nmap-${VERSION}\py2exe
  StrCpy $zenmapset "true"
  Call vcredist2008installer
  Call create_uninstaller
SectionEnd

Section "Ncat (Modern Netcat reincarnation)" SecNcat
  SetOutPath "$INSTDIR"
  SetOverwrite on
  File ..\nmap-${VERSION}\ncat.exe
  File ..\nmap-${VERSION}\ca-bundle.crt
  Call vcredist2010installer
  Call create_uninstaller
SectionEnd

Section "Ndiff (Scan comparison tool)" SecNdiff
  SetOutPath "$INSTDIR" 
  SetOverwrite on 
  File ..\nmap-${VERSION}\ndiff.exe
  File ..\nmap-${VERSION}\NDIFF_README
  File ..\nmap-${VERSION}\python27.dll
  File /r ..\nmap-${VERSION}\py2exe
  Call vcredist2008installer
  Call create_uninstaller
SectionEnd

Section "Nping (Packet generator)" SecNping
  SetOutPath "$INSTDIR" 
  SetOverwrite on 
  File ..\nmap-${VERSION}\nping.exe
  Call vcredist2010installer
  Call create_uninstaller
SectionEnd

Function vcredist2010installer
  StrCmp $vcredist2010set "" 0 vcredist_done
  StrCpy $vcredist2010set "true"
  ;Check if VC++ 2010 runtimes are already installed.
  ;NOTE VC++ 2010 appears to use a single UID even after installing security updates such as MS11-025.
  ;However, please check whenever the Redistributable package is upgraded as both the UID in the registry key and the DisplayName string must be updated here (and below)
  ;whenever the Redistributable package is upgraded:
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{196BB40D-1578-3D01-B289-BEFC77A11A1E}" "DisplayName"
  StrCmp $0 "Microsoft Visual C++ 2010  x86 Redistributable - 10.0.30319" vcredist_done vcredist_silent_install
  ;If VC++ 2010 runtimes are not installed...
  vcredist_silent_install:
    DetailPrint "Installing Microsoft Visual C++ 2010 Redistributable"
    File ..\vcredist_x86.exe
    ExecWait '"$INSTDIR\vcredist_x86.exe" /q' $0
    ;Check for successful installation of our vcredist_x86.exe...
    ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{196BB40D-1578-3D01-B289-BEFC77A11A1E}" "DisplayName"
    StrCmp $0 "Microsoft Visual C++ 2010  x86 Redistributable - 10.0.30319" vcredist_success vcredist_not_present
    vcredist_not_present:
      DetailPrint "Microsoft Visual C++ 2010 Redistributable failed to install"
      IfSilent vcredist_done vcredist_messagebox
      vcredist_messagebox:
        MessageBox MB_OK "Microsoft Visual C++ 2010 Redistributable Package (x86) failed to install ($INSTDIR\vcredist_x86.exe). Please ensure your system meets the minimum requirements before running the installer again."
        Goto vcredist_done
    vcredist_success:
      Delete "$INSTDIR\vcredist_x86.exe" 
      DetailPrint "Microsoft Visual C++ 2010 Redistributable was successfully installed"
  vcredist_done:
FunctionEnd

Function vcredist2008installer
  StrCmp $vcredist2008set "" 0 vcredist2008_done
  StrCpy $vcredist2008set "true"
  ;Check if VC++ 2008 runtimes are already installed.
  ;NOTE Both the UID in the registry key and the DisplayName string must be updated here (and below)
  ;whenever the Redistributable package is upgraded:
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{86CE85E6-DBAC-3FFD-B977-E4B79F83C909}" "DisplayName"
  StrCmp $0 "Microsoft Visual C++ 2008 Redistributable - KB2467174 - x86 9.0.30729.5570" vcredist2008_done vcredist2008_silent_install
  ;If VC++ 2008 runtimes are not installed...
  vcredist2008_silent_install:
    DetailPrint "Installing Microsoft Visual C++ 2008 Redistributable"
    File ..\vcredist2008_x86.exe
    ExecWait '"$INSTDIR\vcredist2008_x86.exe" /q' $0
    ;Check for successful installation of our 2008 version of vcredist_x86.exe...
    ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{86CE85E6-DBAC-3FFD-B977-E4B79F83C909}" "DisplayName"
    StrCmp $0 "Microsoft Visual C++ 2008 Redistributable - KB2467174 - x86 9.0.30729.5570" vcredist2008_success vcredist2008_not_present
    vcredist2008_not_present:
      DetailPrint "Microsoft Visual C++ 2008 Redistributable failed to install"
      IfSilent vcredist2008_done vcredist2008_messagebox
      vcredist2008_messagebox:
        MessageBox MB_OK "Microsoft Visual C++ 2008 Redistributable Package (x86) failed to install ($INSTDIR\vcredist2008_x86.exe). Please ensure your system meets the minimum requirements before running the installer again."
        Goto vcredist2008_done
    vcredist2008_success:
      Delete "$INSTDIR\vcredist2008_x86.exe" 
      DetailPrint "Microsoft Visual C++ 2008 Redistributable was successfully installed"
  vcredist2008_done:
FunctionEnd

Function create_uninstaller
  StrCmp $addremoveset "" 0 skipaddremove
  ; Register Nmap with add/remove programs 
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Nmap" "DisplayName" "Nmap ${VERSION}" 
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Nmap" "UninstallString" '"$INSTDIR\uninstall.exe"' 
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Nmap" "DisplayIcon" '"$INSTDIR\icon1.ico"' 
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Nmap" "NoModify" 1 
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Nmap" "NoRepair" 1 
  ;Create uninstaller 
  WriteUninstaller "$INSTDIR\Uninstall.exe" 
  StrCpy $addremoveset "true"
  skipaddremove:
FunctionEnd

;Disable a named section if the command line option Opt has the value "NO".
;See http://nsis.sourceforge.net/Macro_vs_Function for the ID label technique.
!macro OptionDisableSection Params Opt Sec
  !define ID ${__LINE__}
  ${GetOptions} ${Params} ${Opt} $1
  StrCmp $1 "NO" "" OptionDisableSection_keep_${ID}
  SectionGetFlags ${Sec} $2
  IntOp $2 $2 & ${SECTION_OFF}
  SectionSetFlags ${Sec} $2
OptionDisableSection_keep_${ID}:
  !undef ID
!macroend

Function .onInit
  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "shortcuts.ini"
  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "final.ini"

  ;Disable section checkboxes based on options. For example /ZENMAP=NO to avoid
  ;installing Zenmap.
  ${GetParameters} $0
  !insertmacro OptionDisableSection $0 "/NMAP=" ${SecCore}
  !insertmacro OptionDisableSection $0 "/REGISTERPATH=" ${SecRegisterPath}
  !insertmacro OptionDisableSection $0 "/WINPCAP=" ${SecWinPcap}
  !insertmacro OptionDisableSection $0 "/REGISTRYMODS=" ${SecPerfRegistryMods}
  !insertmacro OptionDisableSection $0 "/ZENMAP=" ${SecZenmap}
  !insertmacro OptionDisableSection $0 "/NCAT=" ${SecNcat}
  !insertmacro OptionDisableSection $0 "/NDIFF=" ${SecNdiff}
  !insertmacro OptionDisableSection $0 "/NPING=" ${SecNping}
FunctionEnd

;-------------------------------- 
;Descriptions 
 
  ;Component strings 
  LangString DESC_SecCore ${LANG_ENGLISH} "Installs Nmap executable, NSE scripts and Visual C++ 2010 runtime components"
  LangString DESC_SecRegisterPath ${LANG_ENGLISH} "Registers Nmap path to System path so you can execute it from any directory" 
  LangString DESC_SecWinPcap ${LANG_ENGLISH} "Installs WinPcap 4.1.2 (required for most Nmap scans unless it is already installed)" 
  LangString DESC_SecPerfRegistryMods ${LANG_ENGLISH} "Modifies Windows registry values to improve TCP connect scan performance.  Recommended." 
  LangString DESC_SecZenmap ${LANG_ENGLISH} "Installs Zenmap, the official Nmap graphical user interface, and Visual C++ 2008 runtime components.  Recommended." 
  LangString DESC_SecNcat ${LANG_ENGLISH} "Installs Ncat, Nmap's Netcat replacement." 
  LangString DESC_SecNdiff ${LANG_ENGLISH} "Installs Ndiff, a tool for comparing Nmap XML files."
  LangString DESC_SecNping ${LANG_ENGLISH} "Installs Nping, a packet generation tool."

  ;Assign language strings to sections 
  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} $(DESC_SecCore) 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecWinPcap} $(DESC_SecWinPcap) 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecRegisterPath} $(DESC_SecRegisterPath) 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecPerfRegistryMods} $(DESC_SecPerfRegistryMods) 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecZenmap} $(DESC_SecZenmap) 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecNcat} $(DESC_SecNcat) 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecNdiff} $(DESC_SecNdiff) 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecNping} $(DESC_SecNping) 
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
  IfFileExists $INSTDIR\zenmap.exe nmap_installed 
  IfFileExists $INSTDIR\ncat.exe nmap_installed 
  IfFileExists $INSTDIR\nping.exe nmap_installed 
  IfFileExists $INSTDIR\ndiff.exe nmap_installed 
    MessageBox MB_YESNO "It does not appear that Nmap is installed in the directory '$INSTDIR'.$\r$\nContinue anyway (not recommended)?" IDYES nmap_installed 
    Abort "Uninstall aborted by user" 

  SetDetailsPrint textonly 
  DetailPrint "Uninstalling Files..." 
  SetDetailsPrint listonly 
   
  nmap_installed: 
  Delete "$INSTDIR\3rd-party-licenses.txt"
  Delete "$INSTDIR\CHANGELOG" 
  Delete "$INSTDIR\COPYING" 
  Delete "$INSTDIR\nmap-mac-prefixes" 
  Delete "$INSTDIR\nmap-os-db" 
  Delete "$INSTDIR\nmap-payloads" 
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
  Delete "$INSTDIR\python27.dll"
  Delete "$INSTDIR\NDIFF_README"
  Delete "$INSTDIR\ZENMAP_README"
  Delete "$INSTDIR\COPYING_HIGWIDGETS"
  Delete "$INSTDIR\ncat.exe"
  Delete "$INSTDIR\nping.exe"
  Delete "$INSTDIR\ca-bundle.crt"
  ;Delete specific subfolders (NB: custom scripts in scripts folder will be lost)
  RMDir /r "$INSTDIR\nselib"
  RMDir /r "$INSTDIR\scripts"
  RMDir /r "$INSTDIR\share"
  RMDir /r "$INSTDIR\py2exe"
  RMDir /r "$INSTDIR\licenses"
 
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
