;Nmap Installer 
;Started by Bo Jiang @ 08/26/2005 06:07PM 
 
;-------------------------------- 
;Include Modern UI 
 
  !include "MUI.nsh" 
  !include "AddToPath.nsh" 
 
;-------------------------------- 
;General 
 
  ;Name and file 
  Name "Nmap" 
  OutFile "NmapInstaller.exe" 
 
  ;Default installation folder 
  InstallDir "$PROGRAMFILES\Nmap" 
   
  ;Get installation folder from registry if available 
  InstallDirRegKey HKCU "Software\Nmap" "" 
 
  !define VERSION "4.23RC1"  
  VIProductVersion "4.23.0.1"
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
 
;  !insertmacro MUI_PAGE_LICENSE "${NSISDIR}\Docs\Modern UI\License.txt" 
  !insertmacro MUI_PAGE_LICENSE "..\..\COPYING" 
  !insertmacro MUI_PAGE_COMPONENTS 
  !insertmacro MUI_PAGE_DIRECTORY 
  !insertmacro MUI_PAGE_INSTFILES 
   
  !insertmacro MUI_UNPAGE_CONFIRM 
  !insertmacro MUI_UNPAGE_INSTFILES 
  Page custom shortcutsPage makeShortcuts
   
;-------------------------------- 
;Languages 
  
  !insertmacro MUI_LANGUAGE "English" 

;--------------------------------
;Variables

Var zenmapset

;--------------------------------
;Reserves

ReserveFile "shortcuts.ini"
!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS

;--------------------------------
;Functions

Function .onInit
  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "shortcuts.ini"
FunctionEnd


Function shortcutsPage
  StrCmp $zenmapset "" skip

  !insertmacro MUI_HEADER_TEXT "Create Shortcuts" ""
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "shortcuts.ini"  

  skip:
FunctionEnd

Function makeShortcuts
  StrCmp $zenmapset "" skip

  SetOutPath "$INSTDIR\zenmap"

  ReadINIStr $0 "$PLUGINSDIR\shortcuts.ini" "Field 1" "State"
  StrCmp $0 "0" skipdesktop
  CreateShortCut "$DESKTOP\Nmap - Zenmap GUI.lnk" "$INSTDIR\zenmap\zenmap.exe"

  skipdesktop:

  ReadINIStr $0 "$PLUGINSDIR\shortcuts.ini" "Field 2" "State"
  StrCmp $0 "0" skipstartmenu
  CreateDirectory "$SMPROGRAMS\Nmap"
  CreateShortCut "$SMPROGRAMS\Nmap\Nmap - Zenmap GUI.lnk" "$INSTDIR\zenmap\zenmap.exe"

  skipstartmenu:

  skip:
FunctionEnd

;-------------------------------- 
;Installer Sections 
 
Section "Nmap Core Files" SecCore 
 
  SetOutPath "$INSTDIR" 
  RMDir /r $PROGRAMFILES\Nmap 
   
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
  File ..\..\docs\nmap.xsl 
  File ..\nmap_performance.reg 
  File ..\..\README-WIN32 
  File /r scripts 
  File /r ..\Release\nselib
  File ..\icon1.ico 
  
  ;Store installation folder 
  WriteRegStr HKCU "Software\Nmap" "" $INSTDIR 
   
  ;Create uninstaller 
  WriteUninstaller "$INSTDIR\Uninstall.exe" 
   
  ; Register Nmap with add/remove programs 
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Nmap" "DisplayName" "Nmap ${VERSION}" 
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Nmap" "UninstallString" '"$INSTDIR\uninstall.exe"' 
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Nmap" "DisplayIcon" '"$INSTDIR\icon1.ico"' 
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Nmap" "NoModify" 1 
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Nmap" "NoRepair" 1 

  ;Register .usr files with Zenmap
  ;This is commented out till Zenmap supports opening log files from the command-line
  ;WriteRegStr HKCR ".usr" "" "UmitScan"
  ;WriteRegStr HKCR "UmitScan" "" "Umit Saved Port Scan"
  ;WriteRegStr HKCR "UmitScan\DefaultIcon" "" "$INSTDIR\umit_128.ico,0"
  ;WriteRegStr HKCR "UmitScan\shell\open\command" "" '"$INSTDIR\zenmap.exe" "%1"'
  ;WriteRegStr HKCR "UmitScan\shell" "" "open"
  ;System::Call 'Shell32::SHChangeNotify(i 0x8000000, i 0, i 0, i 0)'
  
SectionEnd 
 
Section "Register Nmap Path" SecRegisterPath 
  PUSH $INSTDIR 
  Call AddToPath 
SectionEnd 
 
Section "WinPcap 4.02" SecWinPcap 
  File ..\winpcap\winpcap-nmap-4.02.exe 
  Exec '"$INSTDIR\winpcap-nmap-4.02.exe"' 
  Delete "$INSTDIR\winpcap-nmap-4.02.exe" 
SectionEnd 
 
Section "Network Performance Improvements (Registry Changes)" SecPerfRegistryMods 
  File ..\nmap_performance.reg 
  Exec 'regedt32 /S "$INSTDIR\nmap_performance.reg"' 
SectionEnd 

Section "Zenmap (GUI frontend)" SecZenmap
  File /r ..\nmap-${VERSION}\zenmap
  StrCpy $zenmapset "true"
SectionEnd

 
;-------------------------------- 
;Descriptions 
 
  ;Component strings 
  LangString DESC_SecCore ${LANG_ENGLISH} "Installs Nmap executables and script files" 
  LangString DESC_SecRegisterPath ${LANG_ENGLISH} "Registers Nmap path to System path so you can execute it from any directory" 
  LangString DESC_SecWinPcap ${LANG_ENGLISH} "Installs WinPcap 4.0 (required for most Nmap scans unless it is already installed)" 
  LangString DESC_SecPerfRegistryMods ${LANG_ENGLISH} "Modifies Windows registry values to improve TCP connect scan performance.  Recommended." 
 
  ;Assign language strings to sections 
  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} $(DESC_SecCore) 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecWinPcap} $(DESC_SecWinPcap) 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecRegisterPath} $(DESC_SecRegisterPath) 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecPerfRegistryMods} $(DESC_SecPerfRegistryMods) 
  !insertmacro MUI_FUNCTION_DESCRIPTION_END 
;-------------------------------- 
;Uninstaller Section 
 
Section "Uninstall" 
 
  SetDetailsPrint textonly 
  DetailPrint "Uninstalling Files..." 
  SetDetailsPrint listonly 
 
  IfFileExists $INSTDIR\nmap.exe nmap_installed 
    MessageBox MB_YESNO "It does not appear that Nmap is installed in the directory '$INSTDIR'.$\r$\nContinue anyway (not recommended)?" IDYES nmap_installed 
    Abort "Uninstall aborted by user" 
   
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
  Delete "$INSTDIR\README-WIN32" 
  Delete "$INSTDIR\icon1.ico" 
 
  Delete "$INSTDIR\Uninstall.exe" 
 
  RMDir /r $PROGRAMFILES\Nmap 
 
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

  ;Remove file association
  ;This is commented out till Zenmap supports opening log files from the command-line
  ;DeleteRegKey HKCR ".usr"
  ;DeleteRegKey HKCR "UmitScan"
  ;System::Call 'Shell32::SHChangeNotify(i 0x8000000, i 0, i 0, i 0)'

  SetDetailsPrint both 
SectionEnd 
