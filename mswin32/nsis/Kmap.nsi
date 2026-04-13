;Kmap Installer
;Started by Bo Jiang @ 08/26/2005 06:07PM
;;
;; Recognizes the options (case sensitive):
;;   /S                silent install
;;   /KMAP=NO          don't install Kmap
;;   /REGISTERPATH=NO  don't add the installation directory to PATH
;;   /NPCAP=NO         don't install Npcap
;;   /REGISTRYMODS=NO  don't install performance-related registry mods
;;   /ZEKMAP=NO        don't install Zekmap (non-OEM only)
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

!define STAGE_DIR ..\kmap-${VERSION}

!ifdef KMAP_OEM
!include "..\..\..\kmap-build\kmap-oem.nsh"
!define STAGE_DIR_OEM ${STAGE_DIR}-oem
!else
!define STAGE_DIR_OEM ${STAGE_DIR}
!endif

!define REG_UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall"
!define KMAP_UNINSTALL_KEY "${REG_UNINSTALL_KEY}\${KMAP_NAME}"

;--------------------------------
;Include Modern UI

  !include "MUI.nsh"
  !include "AddToPath.nsh"
  !include "FileFunc.nsh"
  !include "kmap-common.nsh"

;--------------------------------
;General
  ;Name and file
  Name "${KMAP_NAME}"
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
!ifdef KMAP_OEM
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
  VIAddVersionKey /LANG=1033 "ProductName" "${KMAP_NAME}"
  VIAddVersionKey /LANG=1033 "CompanyName" "Insecure.org"
  VIAddVersionKey /LANG=1033 "InternalName" "KmapInstaller.exe"
  VIAddVersionKey /LANG=1033 "LegalCopyright" "Copyright (c) Kmap Software LLC (fyodor@kmap.org)"
  VIAddVersionKey /LANG=1033 "LegalTrademark" "KMAP"
  VIAddVersionKey /LANG=1033 "FileDescription" "${KMAP_NAME} installer"

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
!ifndef KMAP_OEM
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

!ifndef KMAP_OEM
Var zekmapset
!endif
Var addremoveset
Var vcredistset
!define KMAP_ARCH x86
!define VCREDISTEXE VC_redist.${KMAP_ARCH}.exe
!define VCREDISTVER 14.0
!define VCREDISTYEAR 2019

;--------------------------------
;Reserves

!ifndef KMAP_OEM
ReserveFile "shortcuts.ini"
!endif
ReserveFile "final.ini"
!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS
ReserveFile /plugin "System.dll"

;--------------------------------
;Functions

;The .onInit function is below the Sections because it needs to refer to
;the Section IDs which are not defined yet.

!ifndef KMAP_OEM
Function shortcutsPage
  StrCmp $zekmapset "" skip

  !insertmacro MUI_HEADER_TEXT "Create Shortcuts" ""
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "shortcuts.ini"

  skip:
FunctionEnd

!macro writeZekmapShortcut _lnk
  CreateShortcut `${_lnk}` "$INSTDIR\zekmap\bin\pythonw.exe" '-c "from zekmapGUI.App import run;run()"' "$INSTDIR\kmap.exe" 0 "" "" "Launch Zekmap, the Kmap GUI"
!macroend
Function makeShortcuts
  StrCmp $zekmapset "" skip

  ReadINIStr $0 "$PLUGINSDIR\shortcuts.ini" "Field 1" "State"
  StrCmp $0 "0" skipdesktop
  !insertmacro writeZekmapShortcut "$DESKTOP\${KMAP_NAME} - Zekmap GUI.lnk"

  skipdesktop:

  ReadINIStr $0 "$PLUGINSDIR\shortcuts.ini" "Field 2" "State"
  StrCmp $0 "0" skipstartmenu
  CreateDirectory "$SMPROGRAMS\${KMAP_NAME}"
  !insertmacro writeZekmapShortcut "$SMPROGRAMS\${KMAP_NAME}\${KMAP_NAME} - Zekmap GUI.lnk"

  skipstartmenu:

  skip:
FunctionEnd
!endif

Function finalPage
  ; diplay a page saying everything's finished
  !insertmacro MUI_HEADER_TEXT "Finished" "Thank you for installing ${KMAP_NAME}"
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
Section "Kmap Core Files" SecCore
  Call SanityCheckInstdir
  ;Delete specific subfolders (NB: custom scripts in scripts folder will be lost)
  RMDir /r "$INSTDIR\nselib"
  ; nselib-bin held NSE C modules up through version 4.68.
  RMDir /r "$INSTDIR\nselib-bin"
  RMDir /r "$INSTDIR\scripts"
  RMDir /r "$INSTDIR\zekmap"
  RMDir /r "$INSTDIR\py2exe"
  RMDir /r "$INSTDIR\share"
  RMDir /r "$INSTDIR\licenses"

  SetOutPath "$INSTDIR"

  SetOverwrite on
  !insertmacro SecCoreFiles

  Call vcredistinstaller
  Call create_uninstaller

SectionEnd

Section "Register Kmap Path" SecRegisterPath
  PUSH $INSTDIR
  Call AddToPath
SectionEnd

!ifdef KMAP_OEM
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
  File ${STAGE_DIR}\kmap_performance.reg
  ; Apply the changes from the random PLUGINSDIR for better security
  Exec 'regedt32 /S "$PLUGINSDIR\kmap_performance.reg"'
  ; Keep a copy in the installation directory for users to inspect
  CopyFiles /SILENT "$PLUGINSDIR\kmap_performance.reg" "$INSTDIR"
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

!ifndef KMAP_OEM
Section "Zekmap (GUI Frontend)" SecZekmap
  SetOutPath "$INSTDIR"
  SetOverwrite on
  !insertmacro SecZekmapFiles
  WriteINIStr "$INSTDIR\zekmap\share\zekmap\config\zekmap.conf" paths kmap_command_path "$INSTDIR\kmap.exe"
  WriteINIStr "$INSTDIR\zekmap\share\zekmap\config\zekmap.conf" paths ndiff_command_path "$INSTDIR\ndiff.bat"
  !insertmacro writeZekmapShortcut "$INSTDIR\Zekmap.lnk"
  StrCpy $zekmapset "true"
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
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\VisualStudio\${VCREDISTVER}\VC\Runtimes\${KMAP_ARCH}" "Installed"
  StrCmp $0 "1" `${_t}` `${_f}`
!macroend
# add dummy parameters for our test
!define VCRedistInstalled `"" VCRedistInstalled ""`

Function create_uninstaller
  StrCmp $addremoveset "" 0 skipaddremove
  ; Register Kmap with add/remove programs
  WriteRegStr HKLM "${KMAP_UNINSTALL_KEY}" "DisplayName" "${KMAP_NAME} ${VERSION}"
  WriteRegStr HKLM "${KMAP_UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${KMAP_UNINSTALL_KEY}" "Publisher" "Kmap Project"
  WriteRegStr HKLM "${KMAP_UNINSTALL_KEY}" "URLInfoAbout" "https://kmap.org/"
  WriteRegStr HKLM "${KMAP_UNINSTALL_KEY}" "URLUpdateInfo" "https://kmap.org/download.html"
  WriteRegStr HKLM "${KMAP_UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${KMAP_UNINSTALL_KEY}" "InstallLocation" $INSTDIR
  WriteRegStr HKLM "${KMAP_UNINSTALL_KEY}" "DisplayIcon" '"$INSTDIR\icon1.ico"'
  WriteRegDWORD HKLM "${KMAP_UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${KMAP_UNINSTALL_KEY}" "NoRepair" 1
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

; GH#2982: Kmap 7.95 OEM installer uses "Kmap" for KMAP_NAME, not "Kmap OEM"
; We have to look for this specific problem and correct it.
Function RepairBug2982
  System::Store S ; stash registers
  ; See what's installed as "Kmap"
  ReadRegStr $0 HKLM "${REG_UNINSTALL_KEY}\Kmap" "UninstallString"
  ; Nothing? Done.
  StrCmp $0 "" repair_2982_done
  Push $0 ; UninstallString
  ; Check product name on the uninstaller
  !insertmacro stripQuotes $0
  ${GetFileVersionProductName} $0 $3
  Push $3 ; ProductName
  ; If it's not "Kmap OEM" it's not a buggy install
  StrCmp $3 "Kmap OEM" 0 repair_2982_done
  ; Ok, it's a screwed-up install. We need to fix it up first.
  ; Finish getting the old install info
  ReadRegStr $2 HKLM "${REG_UNINSTALL_KEY}\Kmap" "DisplayVersion"
  ${GetParent} $0 $1 ; Get InstallLocation from the path to Uninstall.exe
  ; Rename the old install reg keys
  ; winreg.h: #define HKEY_LOCAL_MACHINE (( HKEY ) (ULONG_PTR)((LONG)0x80000002) )
  System::Call 'advapi32::RegRenameKey(p0x80000002, t"${REG_UNINSTALL_KEY}\Kmap", t"Kmap OEM") i.r3'
  ${If} $3 <> 0
	  ; Failed to rename!
	  goto repair_2982_done
  ${EndIf}
  ; Change appropriate entries
  WriteRegStr HKLM "${REG_UNINSTALL_KEY}\Kmap OEM" "DisplayName" "Kmap OEM $2"
  WriteRegStr HKLM "${REG_UNINSTALL_KEY}\Kmap OEM" "InstallLocation" $1

  ; winreg.h: #define HKEY_CURRENT_USER (( HKEY ) (ULONG_PTR)((LONG)0x80000001) )
  System::Call 'advapi32::RegRenameKey(p0x80000001, t"SOFTWARE\Kmap", t"Kmap OEM") i.r3'
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
    ${If} $5 != "Kmap"
      ; In silent mode, abort the install
      ; if INSTDIR contains an uninstaller that's not Kmap.
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
; so for Kmap itself, use the DisplayVersion if known.
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
!ifndef KMAP_OEM
  ; shortcuts apply only to Zekmap, not included in KMAP_OEM
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
!ifndef KMAP_OEM
  ; If Npcap is not installed, Kmap can't be installed silently.
  ${ElseIf} ${Silent}
	  SetSilent normal
	  MessageBox MB_OK|MB_ICONEXCLAMATION "Silent installation of Kmap requires the Npcap packet capturing software. See https://kmap.org/kmap-silent-install"
	  Quit
!endif
  ${EndIf}

  ;Disable section checkboxes based on options. For example /ZEKMAP=NO to avoid
  ;installing Zekmap.
  !insertmacro OptionDisableSection $R0 "/KMAP=" ${SecCore}
  !insertmacro OptionDisableSection $R0 "/REGISTERPATH=" ${SecRegisterPath}
  !insertmacro OptionDisableSection $R0 "/NPCAP=" ${SecNpcap}
  !insertmacro OptionDisableSection $R0 "/REGISTRYMODS=" ${SecPerfRegistryMods}
!ifndef KMAP_OEM
  !insertmacro OptionDisableSection $R0 "/ZEKMAP=" ${SecZekmap}
  !insertmacro OptionDisableSection $R0 "/NDIFF=" ${SecNdiff}
!endif
  !insertmacro OptionDisableSection $R0 "/NCAT=" ${SecNcat}
  !insertmacro OptionDisableSection $R0 "/NPING=" ${SecNping}

  Call RepairBug2982
  ClearErrors
  Pop $3 ; ProductName?
  Pop $0 ; UninstallString?
  ${If} ${Errors}
  ${OrIf} $3 != "${KMAP_NAME}"
    ; RepairBug2982 did not get info, so we get it here instead
    ; $0 = old uninstall.exe path
    ReadRegStr $1 HKLM "${KMAP_UNINSTALL_KEY}" "UninstallString"
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
  ReadRegStr $1 HKLM "${KMAP_UNINSTALL_KEY}" "InstallLocation"
  StrCmp $1 "" 0 get_old_version
  ; But old installers used this location instead:
  ReadRegStr $1 HKCU "Software\${KMAP_NAME}" ""
  StrCmp $1 "" 0 get_old_version
  ; Last chance, parent dir of uninstaller
  ${GetParent} $0 $1

get_old_version:
  ; $2 = old version
  ReadRegStr $2 HKLM "${KMAP_UNINSTALL_KEY}" "DisplayVersion"

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
    StrCpy $INSTDIR "$PROGRAMFILES\${KMAP_NAME}"
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
  LangString DESC_SecCore ${LANG_ENGLISH} "Installs Kmap executable, NSE scripts and Visual C++ ${VCREDISTYEAR} runtime components"
  LangString DESC_SecRegisterPath ${LANG_ENGLISH} "Registers Kmap path to System path so you can execute it from any directory"
  LangString DESC_SecNpcap ${LANG_ENGLISH} "Installs Npcap ${NPCAP_VERSION} (required for most Kmap scans unless it is already installed)"
  LangString DESC_SecNewNpcap ${LANG_ENGLISH} "Opens npcap.com in your web browser so you can check for a newer version of Npcap."
  LangString DESC_SecPerfRegistryMods ${LANG_ENGLISH} "Modifies Windows registry values to improve TCP connect scan performance.  Recommended."
!ifndef KMAP_OEM
  LangString DESC_SecZekmap ${LANG_ENGLISH} "Installs Zekmap, the official Kmap graphical user interface.  Recommended."
  LangString DESC_SecNdiff ${LANG_ENGLISH} "Installs Ndiff, a tool for comparing Kmap XML files."
!endif
  LangString DESC_SecNcat ${LANG_ENGLISH} "Installs Ncat, Kmap's Netcat replacement."
  LangString DESC_SecNping ${LANG_ENGLISH} "Installs Nping, a packet generation tool."

  ;Assign language strings to sections
  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} $(DESC_SecCore)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecNpcap} $(DESC_SecNpcap)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecNewNpcap} $(DESC_SecNewNpcap)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecRegisterPath} $(DESC_SecRegisterPath)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecPerfRegistryMods} $(DESC_SecPerfRegistryMods)
!ifndef KMAP_OEM
    !insertmacro MUI_DESCRIPTION_TEXT ${SecZekmap} $(DESC_SecZekmap)
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
      MessageBox MB_OK "Microsoft Visual C++ ${VCREDISTYEAR} Redistributable Package (${KMAP_ARCH}) failed to install. Please ensure your system meets the minimum requirements before running the installer again."
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

  IfFileExists $INSTDIR\kmap.exe kmap_installed
  IfFileExists $INSTDIR\zekmap.exe kmap_installed
  IfFileExists $INSTDIR\ncat.exe kmap_installed
  IfFileExists $INSTDIR\nping.exe kmap_installed
  IfFileExists $INSTDIR\ndiff.exe kmap_installed
    MessageBox MB_YESNO "It does not appear that ${KMAP_NAME} is installed in the directory '$INSTDIR'.$\r$\nContinue anyway (not recommended)?" IDYES kmap_installed
    Abort "Uninstall aborted by user"

  SetDetailsPrint textonly
  DetailPrint "Uninstalling Files..."
  SetDetailsPrint listonly

  kmap_installed:
!insertmacro SecCoreFiles
!insertmacro SecNcatFiles
!insertmacro SecNpingFiles
!ifndef KMAP_OEM
!insertmacro SecZekmapFiles
!insertmacro SecNdiffFiles
!endif
  Delete "$INSTDIR\kmap_performance.reg"

  Delete "$INSTDIR\Uninstall.exe"

  ;Removes folder if it's now empty
  RMDir "$INSTDIR"

  SetDetailsPrint textonly
  DetailPrint "Deleting Registry Keys..."
  SetDetailsPrint listonly
  DeleteRegKey HKCU "Software\${KMAP_NAME}"
  DeleteRegKey HKLM "${KMAP_UNINSTALL_KEY}"
  SetDetailsPrint textonly
  DetailPrint "Unregistering Kmap Path..."
  Push $INSTDIR
  Call un.RemoveFromPath

  Delete "$DESKTOP\${KMAP_NAME} - Zekmap GUI.lnk"
  Delete "$SMPROGRAMS\${KMAP_NAME}\${KMAP_NAME} - Zekmap GUI.lnk"
  RMDIR "$SMPROGRAMS\${KMAP_NAME}"

  SetDetailsPrint both
SectionEnd
!endif
