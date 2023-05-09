;Nmap Installer
;Started by Bo Jiang @ 08/26/2005 06:07PM
;;
;; Recognizes the options (case sensitive):
;;   /S                silent install
;;   /NMAP=NO          don't install Nmap
;;   /REGISTERPATH=NO  don't add the installation directory to PATH
;;   /NPCAP=NO         don't install Npcap
;;   /REGISTRYMODS=NO  don't install performance-related registry mods
;;   /ZENMAP=NO        don't install Zenmap (non-OEM only)
;;   /NCAT=NO          don't install Ncat
;;   /NDIFF=NO         don't install Ndiff (non-OEM only)
;;   /NPING=NO         don't install Nping
;;   /D=C:\dir\...     install to C:\dir\... (overrides InstallDir)
;;
;;/D is a built-in NSIS option and has these restrictions:
;;(http://nsis.sourceforge.net/Docs/Chapter3.html)
;;  It must be the last parameter used in the command line and must not
;;  contain any quotes, even if the path contains spaces. Only absolute
;;  paths are supported.

; Ensure large strings build is used
!if ${NSIS_MAX_STRLEN} < 8192
!error "Need to use large strings build of NSIS."
!endif

!define STAGE_DIR ..\nmap-${VERSION}

!ifdef NMAP_OEM
!include "..\..\..\nmap-build\nmap-oem.nsh"
!define STAGE_DIR_OEM ${STAGE_DIR}-oem
!else
!define STAGE_DIR_OEM ${STAGE_DIR}
!endif

;--------------------------------
;Include Modern UI

  !include "MUI.nsh"
  !include "AddToPath.nsh"
  !include "FileFunc.nsh"

;--------------------------------
;General
  ;Name and file
  Name "${NMAP_NAME}"
  Unicode true

!ifdef INNER
  # Write an uninstaller only
  !insertmacro MUI_UNPAGE_CONFIRM
  !insertmacro MUI_UNPAGE_INSTFILES
  !echo "Inner invocation"                  ; just to see what's going on
  OutFile "${STAGE_DIR_OEM}\tempinstaller.exe" ; Ensure we don't confuse these
  SetCompress off                           ; for speed
  RequestExecutionLevel user
Section "dummy"
SectionEnd
!else
  !echo "Outer invocation"

  !include "WordFunc.nsh"
  !include "Sections.nsh"

  ; Good.  Now we can carry on writing the real installer.

  OutFile ${STAGE_DIR_OEM}-setup.exe
  SetCompressor /SOLID /FINAL lzma

  ;Required for removing shortcuts
  RequestExecutionLevel admin
!endif

  ;Default installation folder
  InstallDir "$PROGRAMFILES\${NMAP_NAME}"

  ;Get installation folder from registry if available
  InstallDirRegKey HKCU "Software\${NMAP_NAME}" ""

  VIProductVersion ${NUM_VERSION}
  VIAddVersionKey /LANG=1033 "FileVersion" "${VERSION}"
  VIAddVersionKey /LANG=1033 "ProductName" "${NMAP_NAME}"
  VIAddVersionKey /LANG=1033 "CompanyName" "Insecure.org"
  VIAddVersionKey /LANG=1033 "InternalName" "NmapInstaller.exe"
  VIAddVersionKey /LANG=1033 "LegalCopyright" "Copyright (c) Nmap Software LLC (fyodor@nmap.org)"
  VIAddVersionKey /LANG=1033 "LegalTrademark" "NMAP"
  VIAddVersionKey /LANG=1033 "FileDescription" "${NMAP_NAME} installer"

;--------------------------------
;Interface Settings

  !define MUI_ABORTWARNING

;--------------------------------
;Pages

  !insertmacro MUI_PAGE_LICENSE "..\LICENSE.formatted"
  !insertmacro MUI_PAGE_COMPONENTS
  !insertmacro MUI_PAGE_DIRECTORY
  !insertmacro MUI_PAGE_INSTFILES
!ifndef INNER
!ifndef NMAP_OEM
  Page custom shortcutsPage makeShortcuts
!endif
  Page custom finalPage doFinal
!endif

;--------------------------------
;Languages

  !insertmacro MUI_LANGUAGE "English"

!ifndef INNER
!insertmacro GetParameters
!insertmacro GetOptions

;--------------------------------
;Variables

!ifndef NMAP_OEM
Var zenmapset
!endif
Var addremoveset
Var vcredistset
!define NMAP_ARCH x86
!define VCREDISTEXE VC_redist.${NMAP_ARCH}.exe
!define VCREDISTVER 14.0
!define VCREDISTYEAR 2019

;--------------------------------
;Reserves

!ifndef NMAP_OEM
ReserveFile "shortcuts.ini"
!endif
ReserveFile "final.ini"
!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS

;--------------------------------
;Functions

;The .onInit function is below the Sections because it needs to refer to
;the Section IDs which are not defined yet.

!ifndef NMAP_OEM
Function shortcutsPage
  StrCmp $zenmapset "" skip

  !insertmacro MUI_HEADER_TEXT "Create Shortcuts" ""
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "shortcuts.ini"

  skip:
FunctionEnd

!macro writeZenmapShortcut _lnk
  CreateShortcut `${_lnk}` "$INSTDIR\zenmap\bin\pythonw.exe" '-c "from zenmapGUI.App import run;run()"' "$INSTDIR\nmap.exe" 0 "" "" "Launch Zenmap, the Nmap GUI"
!macroend
Function makeShortcuts
  StrCmp $zenmapset "" skip

  ReadINIStr $0 "$PLUGINSDIR\shortcuts.ini" "Field 1" "State"
  StrCmp $0 "0" skipdesktop
  !insertmacro writeZenmapShortcut "$DESKTOP\${NMAP_NAME} - Zenmap GUI.lnk"

  skipdesktop:

  ReadINIStr $0 "$PLUGINSDIR\shortcuts.ini" "Field 2" "State"
  StrCmp $0 "0" skipstartmenu
  CreateDirectory "$SMPROGRAMS\${NMAP_NAME}"
  !insertmacro writeZenmapShortcut "$SMPROGRAMS\${NMAP_NAME}\${NMAP_NAME} - Zenmap GUI.lnk"

  skipstartmenu:

  skip:
FunctionEnd
!endif

Function finalPage
  ; diplay a page saying everything's finished
  !insertmacro MUI_HEADER_TEXT "Finished" "Thank you for installing ${NMAP_NAME}"
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
    MessageBox MB_YESNO "It may not be safe to uninstall the previous installation of ${NMAP_NAME} from the directory '$INSTDIR'.$\r$\nContinue anyway (not recommended)?" IDYES probably_safe_key_install
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
  File ${STAGE_DIR}\CHANGELOG
  File ${STAGE_DIR}\LICENSE
  File ${STAGE_DIR}\nmap-mac-prefixes
  File ${STAGE_DIR}\nmap-os-db
  File ${STAGE_DIR}\nmap-protocols
  File ${STAGE_DIR}\nmap-rpc
  File ${STAGE_DIR}\nmap-service-probes
  File ${STAGE_DIR}\nmap-services
  File ${STAGE_DIR_OEM}\nmap.exe
  File ${STAGE_DIR}\nse_main.lua
  File ${STAGE_DIR}\nmap.xsl
  File ${STAGE_DIR}\nmap_performance.reg
  File ${STAGE_DIR}\README-WIN32
  File ${STAGE_DIR}\3rd-party-licenses.txt
  File /r /x .svn ${STAGE_DIR}\licenses
  File ${STAGE_DIR}\libssh2.dll
  File ${STAGE_DIR}\zlibwapi.dll
  File ${STAGE_DIR}\libcrypto-3.dll
  File ${STAGE_DIR}\libssl-3.dll
  File /r /x mswin32 /x .svn /x ncat ${STAGE_DIR}\scripts
  File /r /x mswin32 /x .svn ${STAGE_DIR}\nselib
  File ${STAGE_DIR}\icon1.ico

  ;Store installation folder
  WriteRegStr HKCU "Software\${NMAP_NAME}" "" $INSTDIR

  Call vcredistinstaller
  Call create_uninstaller

SectionEnd

Section "Register Nmap Path" SecRegisterPath
  PUSH $INSTDIR
  Call AddToPath
SectionEnd

!ifdef NMAP_OEM
Section "Npcap ${NPCAP_VERSION} OEM" SecNpcap
  !insertmacro NPCAP_OEM_INSTALL "npcap-${NPCAP_VERSION}-oem.exe"
SectionEnd
!else
Section "Npcap ${NPCAP_VERSION}" SecNpcap
  SetOutPath "$PLUGINSDIR"
  SetOverwrite on
  File "..\npcap-${NPCAP_VERSION}.exe"
  ExecWait '"$PLUGINSDIR\npcap-${NPCAP_VERSION}.exe" /loopback_support=no'
SectionEnd
!endif

Section /o "Check online for newer Npcap" SecNewNpcap
  ExecShell "open" "https://npcap.com/#download"
SectionEnd

Section "Network Performance Improvements" SecPerfRegistryMods
  SetOutPath "$PLUGINSDIR"
  SetOverwrite on
  File ${STAGE_DIR}\nmap_performance.reg
  ; Apply the changes from the random PLUGINSDIR for better security
  Exec 'regedt32 /S "$PLUGINSDIR\nmap_performance.reg"'
  ; Keep a copy in the installation directory for users to inspect
  CopyFiles /SILENT "$PLUGINSDIR\nmap_performance.reg" "$INSTDIR"
SectionEnd

!ifndef NMAP_OEM
Section "Zenmap (GUI Frontend)" SecZenmap
  SetOutPath "$INSTDIR"
  SetOverwrite on
  File ${STAGE_DIR}\ZENMAP_README
  File ${STAGE_DIR}\COPYING_HIGWIDGETS
  File /r ${STAGE_DIR}\zenmap
  WriteINIStr "$INSTDIR\zenmap\share\zenmap\config\zenmap.conf" paths nmap_command_path "$INSTDIR\nmap.exe"
  WriteINIStr "$INSTDIR\zenmap\share\zenmap\config\zenmap.conf" paths ndiff_command_path "$INSTDIR\ndiff.bat"
  !insertmacro writeZenmapShortcut "$INSTDIR\Zenmap.lnk"
  StrCpy $zenmapset "true"
  Call create_uninstaller
SectionEnd

Section "Ndiff (Scan comparison tool)" SecNdiff
  SetOutPath "$INSTDIR"
  SetOverwrite on
  File ${STAGE_DIR}\ndiff.py
  File ${STAGE_DIR}\ndiff.bat
  File ${STAGE_DIR}\NDIFF_README
  Call create_uninstaller
SectionEnd
!endif

Section "Ncat (Modern Netcat reincarnation)" SecNcat
  SetOutPath "$INSTDIR"
  SetOverwrite on
  File ${STAGE_DIR}\ncat.exe
  File ${STAGE_DIR}\ca-bundle.crt
  Call vcredistinstaller
  Call create_uninstaller
SectionEnd

Section "Nping (Packet generator)" SecNping
  SetOutPath "$INSTDIR"
  SetOverwrite on
  File ${STAGE_DIR}\nping.exe
  Call vcredistinstaller
  Call create_uninstaller
SectionEnd

# Custom LogicLib test macro
!macro _VCRedistInstalled _a _b _t _f
  SetRegView 32
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\VisualStudio\${VCREDISTVER}\VC\Runtimes\${NMAP_ARCH}" "Installed"
  StrCmp $0 "1" `${_t}` `${_f}`
!macroend
# add dummy parameters for our test
!define VCRedistInstalled `"" VCRedistInstalled ""`

Function vcredistinstaller
  ${If} $vcredistset != ""
    Return
  ${EndIf}
  StrCpy $vcredistset "true"
  ;Check if VC++ runtimes are already installed.
  ;This version creates a registry key that makes it easy to check whether a version (not necessarily the
  ;one we may be about to install) of the VC++ redistributables have been installed.
  ;Only run our installer if a version isn't already present, to prevent installing older versions resulting in error messages.
  ;If VC++ runtimes are not installed...
  ${IfNot} ${VCRedistInstalled}
    DetailPrint "Installing Microsoft Visual C++ ${VCREDISTYEAR} Redistributable"
    SetOutPath $PLUGINSDIR
    File ..\${VCREDISTEXE}
    ExecWait '"$PLUGINSDIR\${VCREDISTEXE}" /quiet' $0
    ;Check for successful installation of our package...
    Delete "$PLUGINSDIR\${VCREDISTEXE}"

    ${IfNot} ${VCRedistInstalled}
      DetailPrint "Microsoft Visual C++ ${VCREDISTYEAR} Redistributable failed to install"
      MessageBox MB_OK "Microsoft Visual C++ ${VCREDISTYEAR} Redistributable Package (${NMAP_ARCH}) failed to install. Please ensure your system meets the minimum requirements before running the installer again."
    ${Else}
      DetailPrint "Microsoft Visual C++ ${VCREDISTYEAR} Redistributable was successfully installed"
    ${EndIf}
  ${EndIf}
FunctionEnd

Function create_uninstaller
  StrCmp $addremoveset "" 0 skipaddremove
  ; Register Nmap with add/remove programs
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${NMAP_NAME}" "DisplayName" "${NMAP_NAME} ${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${NMAP_NAME}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${NMAP_NAME}" "Publisher" "Nmap Project"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${NMAP_NAME}" "URLInfoAbout" "https://nmap.org/"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${NMAP_NAME}" "URLUpdateInfo" "https://nmap.org/download.html"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${NMAP_NAME}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${NMAP_NAME}" "DisplayIcon" '"$INSTDIR\icon1.ico"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${NMAP_NAME}" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${NMAP_NAME}" "NoRepair" 1
  ;Create uninstaller
  SetOutPath $INSTDIR

  ; this packages the signed uninstaller

  File "${STAGE_DIR_OEM}\Uninstall.exe"
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
  ${GetParameters} $R0
  ; Make /S (silent install) case-insensitive
  ${GetOptions} $R0 "/s" $R1
  ${IfNot} ${Errors}
    SetSilent silent
  ${EndIf}
!ifndef NMAP_OEM
  ; shortcuts apply only to Zenmap, not included in NMAP_OEM
  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "shortcuts.ini"
!endif

  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "final.ini"

  ; Check if Npcap is already installed.
  ReadRegStr $0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "DisplayVersion"
  ${If} $0 != ""
    ${VersionCompare} $0 ${NPCAP_VERSION} $1
    ; If our version is not newer than the installed version, don't offer to install Npcap.
    ${If} $1 != 2
      SectionGetFlags ${SecNpcap} $2
      IntOp $2 $2 & ${SECTION_OFF}
      SectionSetFlags ${SecNpcap} $2
    ${EndIf}
!ifndef NMAP_OEM
  ; If Npcap is not installed, Nmap can't be installed silently.
  ${ElseIf} ${Silent}
	  SetSilent normal
	  MessageBox MB_OK|MB_ICONEXCLAMATION "Silent installation of Nmap requires the Npcap packet capturing software. See https://nmap.org/nmap-silent-install"
	  Quit
!endif
  ${EndIf}

  ;Disable section checkboxes based on options. For example /ZENMAP=NO to avoid
  ;installing Zenmap.
  !insertmacro OptionDisableSection $R0 "/NMAP=" ${SecCore}
  !insertmacro OptionDisableSection $R0 "/REGISTERPATH=" ${SecRegisterPath}
  !insertmacro OptionDisableSection $R0 "/NPCAP=" ${SecNpcap}
  !insertmacro OptionDisableSection $R0 "/REGISTRYMODS=" ${SecPerfRegistryMods}
!ifndef NMAP_OEM
  !insertmacro OptionDisableSection $R0 "/ZENMAP=" ${SecZenmap}
  !insertmacro OptionDisableSection $R0 "/NDIFF=" ${SecNdiff}
!endif
  !insertmacro OptionDisableSection $R0 "/NCAT=" ${SecNcat}
  !insertmacro OptionDisableSection $R0 "/NPING=" ${SecNping}
FunctionEnd

;--------------------------------
;Descriptions

  ;Component strings
  LangString DESC_SecCore ${LANG_ENGLISH} "Installs Nmap executable, NSE scripts and Visual C++ ${VCREDISTYEAR} runtime components"
  LangString DESC_SecRegisterPath ${LANG_ENGLISH} "Registers Nmap path to System path so you can execute it from any directory"
  LangString DESC_SecNpcap ${LANG_ENGLISH} "Installs Npcap ${NPCAP_VERSION} (required for most Nmap scans unless it is already installed)"
  LangString DESC_SecNewNpcap ${LANG_ENGLISH} "Opens npcap.com in your web browser so you can check for a newer version of Npcap."
  LangString DESC_SecPerfRegistryMods ${LANG_ENGLISH} "Modifies Windows registry values to improve TCP connect scan performance.  Recommended."
!ifndef NMAP_OEM
  LangString DESC_SecZenmap ${LANG_ENGLISH} "Installs Zenmap, the official Nmap graphical user interface.  Recommended."
  LangString DESC_SecNdiff ${LANG_ENGLISH} "Installs Ndiff, a tool for comparing Nmap XML files."
!endif
  LangString DESC_SecNcat ${LANG_ENGLISH} "Installs Ncat, Nmap's Netcat replacement."
  LangString DESC_SecNping ${LANG_ENGLISH} "Installs Nping, a packet generation tool."

  ;Assign language strings to sections
  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} $(DESC_SecCore)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecNpcap} $(DESC_SecNpcap)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecNewNpcap} $(DESC_SecNewNpcap)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecRegisterPath} $(DESC_SecRegisterPath)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecPerfRegistryMods} $(DESC_SecPerfRegistryMods)
!ifndef NMAP_OEM
    !insertmacro MUI_DESCRIPTION_TEXT ${SecZenmap} $(DESC_SecZenmap)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecNdiff} $(DESC_SecNdiff)
!endif
    !insertmacro MUI_DESCRIPTION_TEXT ${SecNcat} $(DESC_SecNcat)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecNping} $(DESC_SecNping)
  !insertmacro MUI_FUNCTION_DESCRIPTION_END
;--------------------------------
;Uninstaller Section

!else ;INNER
Function .onInit
  ; If INNER is defined, then we aren't supposed to do anything except write out
  ; the installer.  This is better than processing a command line option as it means
  ; this entire code path is not present in the final (real) installer.

  ${GetParent} "$EXEPATH" $0
  WriteUninstaller "$0\Uninstall.exe"
  Quit  ; just bail out quickly when running the "inner" installer
FunctionEnd

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
    MessageBox MB_YESNO "It may not be safe to uninstall ${NMAP_NAME} from the directory '$INSTDIR'.$\r$\nContinue anyway (not recommended)?" IDYES probably_safe_key_uninstall
    Abort "Uninstall aborted by user"
  probably_safe_key_uninstall:

  IfFileExists $INSTDIR\nmap.exe nmap_installed
  IfFileExists $INSTDIR\zenmap.exe nmap_installed
  IfFileExists $INSTDIR\ncat.exe nmap_installed
  IfFileExists $INSTDIR\nping.exe nmap_installed
  IfFileExists $INSTDIR\ndiff.exe nmap_installed
    MessageBox MB_YESNO "It does not appear that ${NMAP_NAME} is installed in the directory '$INSTDIR'.$\r$\nContinue anyway (not recommended)?" IDYES nmap_installed
    Abort "Uninstall aborted by user"

  SetDetailsPrint textonly
  DetailPrint "Uninstalling Files..."
  SetDetailsPrint listonly

  nmap_installed:
  Delete "$INSTDIR\3rd-party-licenses.txt"
  Delete "$INSTDIR\CHANGELOG"
  Delete "$INSTDIR\LICENSE"
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
  Delete "$INSTDIR\libssh2.dll"
  Delete "$INSTDIR\zlibwapi.dll"
  Delete "$INSTDIR\libcrypto-*dll"
  Delete "$INSTDIR\libssl-*dll"
  Delete "$INSTDIR\npcap-*.exe"
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
  DeleteRegKey HKCU "Software\${NMAP_NAME}"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${NMAP_NAME}"
  SetDetailsPrint textonly
  DetailPrint "Unregistering Nmap Path..."
  Push $INSTDIR
  Call un.RemoveFromPath

  Delete "$DESKTOP\${NMAP_NAME} - Zenmap GUI.lnk"
  Delete "$SMPROGRAMS\${NMAP_NAME}\${NMAP_NAME} - Zenmap GUI.lnk"
  RMDIR "$SMPROGRAMS\${NMAP_NAME}"

  SetDetailsPrint both
SectionEnd
!endif
