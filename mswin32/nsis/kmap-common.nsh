!macro SanityCheckInstdir un
Function ${un}SanityCheckInstdir
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
    MessageBox MB_YESNO "It may not be safe to uninstall ${KMAP_NAME} from the directory '$INSTDIR'.$\r$\nContinue anyway (not recommended)?" /SD IDYES IDYES probably_safe_key_install
    Abort "Install aborted by user"
  probably_safe_key_install:
FunctionEnd
!macroend

!ifdef INNER
; building uninstaller
!macro DoFile _from _name
  Delete "$INSTDIR\${_name}"
!macroend
!define _File "!insertmacro DoFile"

!macro DoDir _from _name
  RMDir /r "$INSTDIR\${_name}"
!macroend
!define _Dir  "!insertmacro DoDir"

!else ; INNER
; building installer
!macro DoFile _from _name
  File "${_from}\${_name}"
!macroend
!define _File "!insertmacro DoFile"

!macro DoDir _from _name
  File /r /x mswin32 /x .svn "${_from}\${_name}"
!macroend
!define _Dir  "!insertmacro DoDir"
!endif ; INNER

!macro SecCoreFiles
  ${_File} ${STAGE_DIR} CHANGELOG
  ${_File} ${STAGE_DIR} LICENSE
  ${_File} ${STAGE_DIR} kmap-mac-prefixes
  ${_File} ${STAGE_DIR} kmap-os-db
  ${_File} ${STAGE_DIR} kmap-protocols
  ${_File} ${STAGE_DIR} kmap-rpc
  ${_File} ${STAGE_DIR} kmap-service-probes
  ${_File} ${STAGE_DIR} kmap-services
  ${_File} ${STAGE_DIR_OEM} kmap.exe
  ${_File} ${STAGE_DIR} nse_main.lua
  ${_File} ${STAGE_DIR} kmap.xsl
  ${_File} ${STAGE_DIR} kmap_performance.reg
  ${_File} ${STAGE_DIR} README-WIN32
  ${_File} ${STAGE_DIR} 3rd-party-licenses.txt
  ${_Dir} ${STAGE_DIR} licenses
  ${_File} ${STAGE_DIR} libssh2.dll
  ${_File} ${STAGE_DIR} zlibwapi.dll
  ${_File} ${STAGE_DIR} libcrypto-3.dll
  ${_File} ${STAGE_DIR} libssl-3.dll
  ${_Dir} ${STAGE_DIR} scripts
  ${_Dir} ${STAGE_DIR} nselib
  ${_File} ${STAGE_DIR} icon1.ico
!macroend

!macro SecZekmapFiles
  ${_File} ${STAGE_DIR} ZEKMAP_README
  ${_File} ${STAGE_DIR} COPYING_HIGWIDGETS
  ${_Dir} ${STAGE_DIR} zekmap
  ; always remove Zekmap.lnk
  ; It'll be created by the installer after this.
  Delete "$INSTDIR\Zekmap.lnk"
!macroend

!macro SecNdiffFiles
  ${_File} ${STAGE_DIR} ndiff.py
  ${_File} ${STAGE_DIR} ndiff.bat
  ${_File} ${STAGE_DIR} NDIFF_README
!macroend

!macro SecNcatFiles
  ${_File} ${STAGE_DIR} ncat.exe
  ${_File} ${STAGE_DIR} ca-bundle.crt
!macroend

!macro SecNpingFiles
  ${_File} ${STAGE_DIR} nping.exe
!macroend
