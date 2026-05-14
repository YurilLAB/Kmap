@echo off
REM Direct kmap.sln build, bypassing Build.bat's broken vswhere dependency.
REM Uses the known VS 2022 BuildTools path and standard cmake + msbuild flow.

setlocal
cd /d "%~dp0"

set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
if not exist "%VCVARS%" goto :no_vcvars

echo === Initializing VS 2022 BuildTools env (x86 / Win32 target) ===
call "%VCVARS%" x86 >nul
if errorlevel 1 goto :vcvars_fail

echo === Verifying deps ===
set "AUX=%~dp0..\..\kmap-mswin32-aux"
if not exist "%AUX%\Npcap\Include\pcap.h" goto :no_npcap
if not exist "%AUX%\OpenSSL\include\openssl\ssl.h" goto :no_openssl
echo   Npcap SDK   OK
echo   OpenSSL     OK

echo === Building libpcre2 via CMake ===
if exist build-pcre2 goto :skip_cmake
mkdir build-pcre2
cd build-pcre2
cmake.exe -A Win32 -G "Visual Studio 17 2022" ..\..\libpcre\
if errorlevel 1 goto :cmake_fail
cd ..
:skip_cmake

echo === Running msbuild kmap.sln (Win32 / Release / v143 toolset) ===
REM YurilLAB vcxproj files use $(DefaultPlatformToolset) so they auto-select,
REM but the vendored vcxprojs (liblua/libdnet-stripped/liblinear/libz) still
REM pin v142. Passing -p:PlatformToolset=v143 forces VS2022's toolset for the
REM whole solution. Drop this flag once vendored projects are retargeted (or
REM let users run "Retarget solution" from the VS IDE on fresh VS2022 installs).
msbuild -nologo kmap.sln -m -t:Build -p:Configuration=Release -p:Platform=Win32 -p:PlatformToolset=v143 -p:WindowsTargetPlatformVersion=10.0 -fl
exit /b %errorlevel%

:no_vcvars
echo ERROR: vcvarsall.bat not found at "%VCVARS%"
exit /b 11

:vcvars_fail
echo ERROR: vcvarsall init failed
exit /b 12

:no_npcap
echo MISSING Npcap header at "%AUX%\Npcap\Include\pcap.h"
exit /b 13

:no_openssl
echo MISSING OpenSSL header at "%AUX%\OpenSSL\include\openssl\ssl.h"
exit /b 14

:cmake_fail
cd ..
echo cmake configure failed
exit /b 15
