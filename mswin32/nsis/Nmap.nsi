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

!define REG_UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall"
!define NMAP_UNINSTALL_KEY "${REG_UNINSTALL_KEY}\${NMAP_NAME}"

;--------------------------------
;Include Modern UI

  !include "MUI.nsh"
  !include "AddToPath.nsh"
  !include "FileFunc.nsh"
  !include "nmap-common.nsh"

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
!ifdef NMAP_OEM
  ; OEM installer is less than 32MB uncompressed, so extra dict is wasted
  SetCompressorDictSize 32
!else
  SetCompressorDictSize 64
!endif

  ;Required for removing shortcuts
  RequestExecutionLevel admin
!endif

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
ReserveFile /plugin "System.dll"

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

ReserveFile "${STAGE_DIR_OEM}\Uninstall.exe"
ReserveFile "..\npcap-${NPCAP_VERSION}.exe"
ReserveFile ..\${VCREDISTEXE}

!insertmacro SanityCheckInstdir ""
Section "Nmap Core Files" SecCore
  Call SanityCheckInstdir
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
  !insertmacro SecCoreFiles

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

Section "Ncat (Modern Netcat reincarnation)" SecNcat
  SetOutPath "$INSTDIR"
  SetOverwrite on
  !insertmacro SecNcatFiles
  Call vcredistinstaller
  Call create_uninstaller
SectionEnd

Section "Nping (Packet generator)" SecNping
  SetOutPath "$INSTDIR"
  SetOverwrite on
  !insertmacro SecNpingFiles
  Call vcredistinstaller
  Call create_uninstaller
SectionEnd

!ifndef NMAP_OEM
Section "Zenmap (GUI Frontend)" SecZenmap
  SetOutPath "$INSTDIR"
  SetOverwrite on
  !insertmacro SecZenmapFiles
  WriteINIStr "$INSTDIR\zenmap\share\zenmap\config\zenmap.conf" paths nmap_command_path "$INSTDIR\nmap.exe"
  WriteINIStr "$INSTDIR\zenmap\share\zenmap\config\zenmap.conf" paths ndiff_command_path "$INSTDIR\ndiff.bat"
  !insertmacro writeZenmapShortcut "$INSTDIR\Zenmap.lnk"
  StrCpy $zenmapset "true"
  ${If} ${Silent}
    File "/oname=$PLUGINSDIR\shortcuts.ini" "shortcuts.ini"
    Call makeShortcuts
  ${EndIf}
  Call create_uninstaller
SectionEnd

Section "Ndiff (Scan comparison tool)" SecNdiff
  SetOutPath "$INSTDIR"
  SetOverwrite on
  !insertmacro SecNdiffFiles
  Call create_uninstaller
SectionEnd
!endif

# Custom LogicLib test macro
!macro _VCRedistInstalled _a _b _t _f
  SetRegView 32
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\VisualStudio\${VCREDISTVER}\VC\Runtimes\${NMAP_ARCH}" "Installed"
  StrCmp $0 "1" `${_t}` `${_f}`
!macroend
# add dummy parameters for our test
!define VCRedistInstalled `"" VCRedistInstalled ""`

Function create_uninstaller
  StrCmp $addremoveset "" 0 skipaddremove
  ; Register Nmap with add/remove programs
  WriteRegStr HKLM "${NMAP_UNINSTALL_KEY}" "DisplayName" "${NMAP_NAME} ${VERSION}"
  WriteRegStr HKLM "${NMAP_UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${NMAP_UNINSTALL_KEY}" "Publisher" "Nmap Project"
  WriteRegStr HKLM "${NMAP_UNINSTALL_KEY}" "URLInfoAbout" "https://nmap.org/"
  WriteRegStr HKLM "${NMAP_UNINSTALL_KEY}" "URLUpdateInfo" "https://nmap.org/download.html"
  WriteRegStr HKLM "${NMAP_UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${NMAP_UNINSTALL_KEY}" "InstallLocation" $INSTDIR
  WriteRegStr HKLM "${NMAP_UNINSTALL_KEY}" "DisplayIcon" '"$INSTDIR\icon1.ico"'
  WriteRegDWORD HKLM "${NMAP_UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${NMAP_UNINSTALL_KEY}" "NoRepair" 1
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

Function _GetFileVersionProductName
  System::Store S ; Stash registers
  Pop $R0 ; file path
  Push "" ; return value (bad)
  System::Call 'version::GetFileVersionInfoSize(t"$R0", i.r2) i.r0'
  ${If} $0 <> 0
    System::Alloc $0 ; Alloc buffer to top of stack
    ; Arg 4 pops the buffer off stack and puts it in $1. Pushes return of GetLastError
    System::Call 'version::GetFileVersionInfo(t"$R0", ir2, ir0, isr1) i.r0 ? e'
    Pop $2 ; GetLastError
    ${If} $2 == 0
    ${AndIf} $0 <> 0
      ; 0409 = English; 04b0 = Unicode
      System::Call 'version::VerQueryValue(ir1, t"\StringFileInfo\040904b0\ProductName", *i0r2, *i0r3) i.r0'
      ${If} $0 <> 0
        Pop $0 ; Take the "" off the stack
        ; Push the Unicode string at r2 of length r3
        System::Call '*$2(&t$3.r0)'
        Push $0
      ${EndIf}
    ${EndIf}
    System::Free $1
  ${EndIf}
  System::Store L ; Restore registers
FunctionEnd
!macro GetFileVersionProductName _file _outvar
  Push ${_file}
  Call _GetFileVersionProductName
  Pop ${_outvar}
!macroend
!define GetFileVersionProductName "!insertmacro GetFileVersionProductName"

!macro stripQuotes string
  Push $R0
  ; Strip double quotes
  StrCpy $R0 ${string} 1
  ${If} $R0 == "$\""
    StrLen $R0 ${string}
    IntOp $R0 $R0 - 1
    StrCpy $R0 ${string} 1 $R0
    ${If} $R0 == "$\""
      StrCpy ${string} ${string} -1 1
    ${EndIf}
  ${EndIf}
  Pop $R0
!macroend

Function RunUninstaller
  System::Store S ; stash registers
  Pop $2 ; old instdir
  Pop $1 ; params
  Pop $0 ; Uninstaller
  !insertmacro stripQuotes $0
  !insertmacro stripQuotes $2

  ; Try to run and delete, but ignore errors.
  ExecWait '"$0" $1 _?=$2'
  Delete $0
  RmDir $2
  System::Store L ; restore registers
FunctionEnd

; GH#2982: Nmap 7.95 OEM installer uses "Nmap" for NMAP_NAME, not "Nmap OEM"
; We have to look for this specific problem and correct it.
Function RepairBug2982
  System::Store S ; stash registers
  ; See what's installed as "Nmap"
  ReadRegStr $0 HKLM "${REG_UNINSTALL_KEY}\Nmap" "UninstallString"
  ; Nothing? Done.
  StrCmp $0 "" repair_2982_done
  Push $0 ; UninstallString
  ; Check product name on the uninstaller
  !insertmacro stripQuotes $0
  ${GetFileVersionProductName} $0 $3
  Push $3 ; ProductName
  ; If it's not "Nmap OEM" it's not a buggy install
  StrCmp $3 "Nmap OEM" 0 repair_2982_done
  ; Ok, it's a screwed-up install. We need to fix it up first.
  ; Finish getting the old install info
  ReadRegStr $2 HKLM "${REG_UNINSTALL_KEY}\Nmap" "DisplayVersion"
  ${GetParent} $0 $1 ; Get InstallLocation from the path to Uninstall.exe
  ; Rename the old install reg keys
  ; winreg.h: #define HKEY_LOCAL_MACHINE (( HKEY ) (ULONG_PTR)((LONG)0x80000002) )
  System::Call 'advapi32::RegRenameKey(p0x80000002, t"${REG_UNINSTALL_KEY}\Nmap", t"Nmap OEM") i.r3'
  ${If} $3 <> 0
	  ; Failed to rename!
	  goto repair_2982_done
  ${EndIf}
  ; Change appropriate entries
  WriteRegStr HKLM "${REG_UNINSTALL_KEY}\Nmap OEM" "DisplayName" "Nmap OEM $2"
  WriteRegStr HKLM "${REG_UNINSTALL_KEY}\Nmap OEM" "InstallLocation" $1

  ; winreg.h: #define HKEY_CURRENT_USER (( HKEY ) (ULONG_PTR)((LONG)0x80000001) )
  System::Call 'advapi32::RegRenameKey(p0x80000001, t"SOFTWARE\Nmap", t"Nmap OEM") i.r3'
  ${If} $3 <> 0
	  ; Failed to rename!
	  goto repair_2982_done
  ${EndIf}
 
  repair_2982_done:
  System::Store L ; restore registers
FunctionEnd

Function _TryUninstall
  System::Store S ; stash registers
  Pop $3 ; ProductName
  Pop $2 ; Old version
  Pop $1 ; Uninstall dir
  Pop $0 ; Uninstaller path
  ${If} ${Silent}
    StrCpy $5 $3 4
    ${If} $5 != "Nmap"
      ; In silent mode, abort the install
      ; if INSTDIR contains an uninstaller that's not Nmap.
      Abort
    ${EndIf}
  ${Else}
    ${If} $2 == "UNKNOWN"
      ${GetFileVersion} $0 $2
    ${EndIf}
    MessageBox MB_YESNOCANCEL|MB_ICONQUESTION \
        '$3 $2 is already installed in "$1". $\n$\nWould you like to uninstall it first?' \
        /SD IDYES IDYES tryuninstall_go IDNO tryuninstall_end
    Abort
  ${EndIf}
  tryuninstall_go:
  Push $0 ; Uninstaller
  Push "/S" ; Params
  Push $1 ; Old instdir
  Call RunUninstaller

  tryuninstall_end:
  System::Store L ; restore registers
FunctionEnd
; If _version is "", we use the uninstaller's file version, which is X.X.X.X
; so for Nmap itself, use the DisplayVersion if known.
!macro TryUninstall _uninstaller _uninstdir _version _productname
  Push ${_uninstaller}
  Push ${_uninstdir}
  Push ${_version}
  Push ${_productname}
  Call _TryUninstall
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
  ReadRegStr $0 HKLM "${REG_UNINSTALL_KEY}\NpcapInst" "DisplayVersion"
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

  Call RepairBug2982
  ClearErrors
  Pop $3 ; ProductName?
  Pop $0 ; UninstallString?
  ${If} ${Errors}
  ${OrIf} $3 != "${NMAP_NAME}"
    ; RepairBug2982 did not get info, so we get it here instead
    ; $0 = old uninstall.exe path
    ReadRegStr $1 HKLM "${NMAP_UNINSTALL_KEY}" "UninstallString"
    ; If it's the same as what RepairBug2982 got, then $3 is valid, too.
    ${If} $1 != $0
      StrCpy $0 $1
      ; $3 is obviously not valid
      StrCpy $3 ""
    ${EndIf}
  ${EndIf}

  ; If no uninstall key was found, assume it's a new install
  StrCmp $0 "" set_instdir

  !insertmacro stripQuotes $0
  ; $1 = old instdir
  ; We want to use this location going forward:
  ReadRegStr $1 HKLM "${NMAP_UNINSTALL_KEY}" "InstallLocation"
  StrCmp $1 "" 0 get_old_version
  ; But old installers used this location instead:
  ReadRegStr $1 HKCU "Software\${NMAP_NAME}" ""
  StrCmp $1 "" 0 get_old_version
  ; Last chance, parent dir of uninstaller
  ${GetParent} $0 $1

get_old_version:
  ; $2 = old version
  ReadRegStr $2 HKLM "${NMAP_UNINSTALL_KEY}" "DisplayVersion"

  ${If} $3 == ""
    ${GetFileVersionProductName} $0 $3
  ${EndIf}
  !insertmacro TryUninstall $0 $1 $2 $3

set_instdir:
  ; If it's already set, user specified with /D=
  StrCmp $INSTDIR "" 0 done
  ; If we got the old instdir from the registry, use that.
  ${If} $1 != ""
    StrCpy $INSTDIR $1
  ${Else}
    ; Default InstallDir set here
    StrCpy $INSTDIR "$PROGRAMFILES\${NMAP_NAME}"
  ${EndIf}

done:
  ; If we didn't already try to uninstall, check to see if there's something in
  ; $INSTDIR that needs to be uninstalled.
  ${If} $INSTDIR != $1
  ${AndIf} ${FileExists} "$INSTDIR\Uninstall.exe"
    ${If} $3 == ""
      ${GetFileVersionProductName} $INSTDIR\Uninstall.exe $3
    ${EndIf}
    !insertmacro TryUninstall "$INSTDIR\Uninstall.exe" $INSTDIR "UNKNOWN" $3
  ${EndIf}

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

; Keep this at the end: vcredist is big and not needed in many cases, so we can
; speed install up by not extracting it.
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

!insertmacro SanityCheckInstdir "un."

Section "Uninstall"

  Call un.SanityCheckInstdir

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
!insertmacro SecCoreFiles
!insertmacro SecNcatFiles
!insertmacro SecNpingFiles
!ifndef NMAP_OEM
!insertmacro SecZenmapFiles
!insertmacro SecNdiffFiles
!endif
  Delete "$INSTDIR\nmap_performance.reg"

  Delete "$INSTDIR\Uninstall.exe"

  ;Removes folder if it's now empty
  RMDir "$INSTDIR"

  SetDetailsPrint textonly
  DetailPrint "Deleting Registry Keys..."
  SetDetailsPrint listonly
  DeleteRegKey HKCU "Software\${NMAP_NAME}"
  DeleteRegKey HKLM "${NMAP_UNINSTALL_KEY}"
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
