@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "TARGET=%~1"
set "VCCONFIG=%~2"
if not defined TARGET set "TARGET=Build"
if not defined VCCONFIG set "VCCONFIG=Release"

:: Resolve every relative path against this script, even when called elsewhere.
pushd "%~dp0" || exit /b 1
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo ERROR: Visual Studio Installer's vswhere.exe was not found.
  goto :FAIL
)

:: Select an installation that actually has the C++ x86/x64 build tools.
:: Read directly from vswhere; shared vspath.txt/vsver.txt files race across builds.
set "VS_PATH="
set "VS_MAJOR="
pushd "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer" || goto :FAIL
for /f "usebackq delims=" %%i in (`vswhere.exe -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -version "[16.0,)" -property installationPath`) do set "VS_PATH=%%i"
for /f "usebackq tokens=1 delims=." %%i in (`vswhere.exe -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -version "[16.0,)" -property installationVersion`) do set "VS_MAJOR=%%i"
popd
set "VS_GENERATOR="
if "%VS_MAJOR%"=="16" set "VS_GENERATOR=Visual Studio 16 2019"
if "%VS_MAJOR%"=="17" set "VS_GENERATOR=Visual Studio 17 2022"
if "%VS_MAJOR%"=="18" set "VS_GENERATOR=Visual Studio 18 2026"
if not defined VS_GENERATOR (
  echo ERROR: No supported Visual Studio C++ toolchain was found.
  goto :FAIL
)
if not exist "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" (
  echo ERROR: vcvarsall.bat was not found in "%VS_PATH%".
  goto :FAIL
)
:: Optional x64 host tools still produce Win32 binaries. Useful when the local
:: x86-host toolchain is unavailable; supported by each VS generator above.
set "KMAP_VC_ARCH=x86"
set "KMAP_CMAKE_TOOLSET="
set "KMAP_MSBUILD_HOST="
if /i "%KMAP_VC_HOST%"=="x64" (
  set "KMAP_VC_ARCH=x64_x86"
  set "KMAP_CMAKE_TOOLSET=-T host=x64"
  set "KMAP_MSBUILD_HOST=-p:PreferredToolArchitecture=x64"
)
call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" %KMAP_VC_ARCH%
if errorlevel 1 goto :QUIT

:: Vars only preprocesses make-vars.h. It must never fall into the installer.
if /i "%TARGET%"=="Vars" goto :vars

where cmake.exe >nul 2>&1
if errorlevel 1 (
  echo ERROR: CMake is required on PATH.
  goto :FAIL
)
set "KMAP_AUX_DIR=%~dp0..\..\kmap-mswin32-aux"
call :check_dependencies
if not errorlevel 1 goto :dependencies_ready
call :install_dependencies
if errorlevel 1 goto :QUIT
call :check_dependencies
if errorlevel 1 goto :QUIT

:dependencies_ready
echo Dependencies verified successfully.
echo Detected Visual Studio Generator: %VS_GENERATOR%
:: The solution references the generated PCRE project even for Clean. Keep it
:: present and let MSBuild clean its outputs instead of deleting the project.
cmake.exe -A Win32 -G "%VS_GENERATOR%" %KMAP_CMAKE_TOOLSET% -S "..\libpcre" -B "build-pcre2"
if errorlevel 1 goto :QUIT
msbuild -nologo kmap.sln -m:3 -t:"%TARGET%" -p:Configuration="%VCCONFIG%" -p:Platform="Win32" %KMAP_MSBUILD_HOST% -fl
goto :QUIT

:vars
cl.exe /nologo /EP make-vars.h > make-vars.make
goto :QUIT

:check_dependencies
call :check_npcap
if errorlevel 1 exit /b 1
call :check_openssl
exit /b %errorlevel%

:check_npcap
for %%f in ("Npcap\Include\pcap.h" "Npcap\Include\Packet32.h" "Npcap\Lib\wpcap.lib" "Npcap\Lib\Packet.lib") do (
  if not exist "%KMAP_AUX_DIR%\%%~f" exit /b 1
)
exit /b 0

:check_openssl
for %%f in ("OpenSSL\include\openssl\ssl.h" "OpenSSL\include\openssl\crypto.h" "OpenSSL\include\openssl\opensslconf.h" "OpenSSL\lib\libssl.lib" "OpenSSL\lib\libcrypto.lib") do (
  if not exist "%KMAP_AUX_DIR%\%%~f" exit /b 1
)
exit /b 0

:install_dependencies
:: An existing directory may be an interrupted installation. Validate each
:: component and retry only the incomplete one.
call :check_openssl
if not errorlevel 1 goto :install_npcap
where svn >nul 2>&1
if errorlevel 1 (
  echo ERROR: Complete OpenSSL headers and x86 libraries are missing.
  echo Install Subversion on PATH, or provide the complete OpenSSL tree in:
  echo   "%KMAP_AUX_DIR%\OpenSSL"
  echo Three downloaded headers alone cannot build or link Kmap.
  exit /b 1
)
echo Downloading the complete OpenSSL build dependency...
if not exist "%KMAP_AUX_DIR%" mkdir "%KMAP_AUX_DIR%"
if not exist "%KMAP_AUX_DIR%" exit /b 1
svn export "https://svn.nmap.org/nmap-mswin32-aux/OpenSSL" "%KMAP_AUX_DIR%\OpenSSL" --force
if errorlevel 1 exit /b %errorlevel%
call :check_openssl
if errorlevel 1 (
  echo ERROR: OpenSSL export is incomplete; required headers or libraries are missing.
  exit /b 1
)

:install_npcap
call :check_npcap
if not errorlevel 1 exit /b 0
echo Downloading Npcap SDK headers and libraries...
set "NPCAP_ZIP=%TEMP%\kmap-npcap-%RANDOM%-%RANDOM%.zip"
powershell -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; try { Invoke-WebRequest -Uri 'https://npcap.com/dist/npcap-sdk-1.13.zip' -OutFile $env:NPCAP_ZIP; Expand-Archive -LiteralPath $env:NPCAP_ZIP -DestinationPath ($env:KMAP_AUX_DIR + '\Npcap') -Force } finally { if (Test-Path -LiteralPath $env:NPCAP_ZIP) { Remove-Item -LiteralPath $env:NPCAP_ZIP -Force } }"
if errorlevel 1 exit /b %errorlevel%
call :check_npcap
if errorlevel 1 (
  echo ERROR: Npcap SDK extraction is incomplete; required headers or libraries are missing.
  exit /b 1
)
exit /b 0

:FAIL
set "KMAP_EXIT_CODE=1"
goto :FINISH

:QUIT
set "KMAP_EXIT_CODE=%errorlevel%"
:FINISH
popd
endlocal & exit /b %KMAP_EXIT_CODE%
