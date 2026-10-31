# Windows developer build

The native solution builds **Win32/x86**. Install Visual Studio 2019, 2022,
or 2026 with the C++ x86/x64 build tools and a Windows SDK, and put CMake on
`PATH`. `mswin32\Build.bat` finds the latest installed C++ toolchain using
Microsoft's [vswhere component query](https://github.com/microsoft/vswhere/wiki/Find-VC).
It selects the matching CMake Visual Studio generator and limits MSBuild to
three workers.

To use x64-hosted tools while still producing Win32 binaries, set
`KMAP_VC_HOST=x64` before invoking the script. Use a fresh `build-pcre2`
directory when changing CMake host toolsets; CMake caches this choice.

From the repository root, or any other working directory:

```bat
mswin32\Build.bat Build Release
mswin32\Build.bat Clean Release
```

`Clean` keeps the generated PCRE project because `kmap.sln` references that
project even when cleaning. CMake/MSBuild/toolchain failures return nonzero.
`Build.bat Vars` only preprocesses `make-vars.h`; that legacy packaging target
also needs the separately maintained `kmap-build\kmap-oem.h`. It does not
install dependencies, and a preprocessing failure is returned to its caller.

## Build dependencies

The Visual Studio project paths expect this sibling layout:

```text
workspace/
  Kmap/
  kmap-mswin32-aux/
    Npcap/Include/pcap.h
    Npcap/Include/Packet32.h
    Npcap/Lib/wpcap.lib
    Npcap/Lib/Packet.lib
    OpenSSL/include/openssl/...
    OpenSSL/lib/libssl.lib
    OpenSSL/lib/libcrypto.lib
    OpenSSL/bin/libssl-3.dll
    OpenSSL/bin/libcrypto-3.dll
```

These must be the **x86** libraries. Complete OpenSSL headers are required;
three individual headers do not constitute a usable dependency. When OpenSSL
is absent or incomplete, the script requires Subversion on `PATH` and exports
the complete [upstream build dependency](https://svn.nmap.org/nmap-mswin32-aux/OpenSSL/).
If Subversion is unavailable, it fails with the missing prerequisite instead
of reporting a successful installation. A partial dependency directory is
checked again on the next run.

The Npcap [SDK archive](https://npcap.com/dist/npcap-sdk-1.13.zip) is downloaded
only when its required headers or import libraries are missing. This extracts
build files; it does not install the capture driver. Keep OpenSSL runtime DLLs
available to the process (for example, by putting the dependency's `bin`
directory on the launching shell's `PATH`). Library existence checks detect
incomplete downloads; they are not a cryptographic verification or ABI check.

## Offline setup regression tests

Run from a Visual Studio developer prompt:

```bat
python tests\windows_build_test.py
```

Or, when a native GCC C compiler is already available:

```bat
python tests\windows_build_test.py --cc gcc
```

The tests execute the batch script with inert compiler/build/downloader
fixtures. They assert exit-code propagation, rejection of header-only
OpenSSL trees, isolation of the `Vars` path, and preservation of the generated
project on `Clean`. They cannot download dependencies or build the application.
Results and per-case logs are written to `test-results/windows-build/`.
The application build and runtime tests remain separate checks.
