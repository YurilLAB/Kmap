"""Offline Windows batch control-flow tests, using inert executable fixtures.

Run with Python from an x64 MSVC developer prompt, or pass --cc gcc.
No fixture can download dependencies or invoke a real CMake/MSBuild command.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

STUB = r'''
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
  char name[MAX_PATH]; GetModuleFileNameA(NULL, name, sizeof(name));
  char *base = strrchr(name, '\\'); base = base ? base + 1 : name;
  FILE *log = fopen(getenv("KMAP_FIXTURE_LOG"), "a");
  if (!log) return 99;
  fprintf(log, "%s\n", base); fclose(log);
  if (!_stricmp(base, "vswhere.exe")) {
    for (int i=1; i<argc; ++i) if (!strcmp(argv[i], "installationVersion")) {
      puts("18.0.0"); return 0;
    }
    puts(getenv("KMAP_FIXTURE_VS")); return 0;
  }
  const char *rc = NULL;
  if (!_stricmp(base, "cl.exe")) { puts("fixture preprocessor"); rc=getenv("KMAP_FIXTURE_CL"); }
  else if (!_stricmp(base, "cmake.exe")) rc=getenv("KMAP_FIXTURE_CMAKE");
  else if (!_stricmp(base, "msbuild.exe")) rc=getenv("KMAP_FIXTURE_MSBUILD");
  else return 96; /* network command attempted: fail without doing anything */
  return rc ? atoi(rc) : 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="cl")
    parser.add_argument("--script", type=Path, default=Path(__file__).resolve().parents[1] / "mswin32/Build.bat")
    parser.add_argument("--output", type=Path, default=Path("test-results/windows-build"))
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("these tests require Windows cmd.exe")
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="kmap-build-test-", dir=args.output) as tmp:
        root = Path(tmp)
        source = root / "stub.c"
        source.write_text(STUB, encoding="utf-8")
        stub = root / "stub.exe"
        cc = shutil.which(args.cc)
        if not cc:
            parser.error(f"compiler unavailable: {args.cc}")
        command = ([cc, "/nologo", str(source), "/Fe:" + str(stub)]
                   if Path(cc).stem.lower() == "cl" else
                   [cc, str(source), "-o", str(stub)])
        built = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=60)
        (args.output / "fixture-build.log").write_text(built.stdout + built.stderr, encoding="utf-8")
        if built.returncode:
            raise RuntimeError("fixture compiler failed; see fixture-build.log")

        cases = [
            ("vars-success", "Vars", {"CL": "0"}, True, 0, {"cl.exe"}, {"cmake.exe", "powershell.exe", "svn.exe", "msbuild.exe"}),
            ("vars-error", "Vars", {"CL": "23"}, True, 23, {"cl.exe"}, {"cmake.exe", "powershell.exe", "svn.exe", "msbuild.exe"}),
            ("vcvars-error", "Build", {"VCVARS": "17"}, True, 17, set(), {"cl.exe", "cmake.exe", "msbuild.exe"}),
            ("headers-without-libraries", "Build", {}, False, 1, set(), {"cmake.exe", "msbuild.exe", "powershell.exe", "svn.exe"}),
            ("partial-npcap", "Build", {}, True, 96, {"powershell.exe"}, {"cmake.exe", "msbuild.exe"}),
            ("cmake-error", "Build", {"CMAKE": "47"}, True, 47, {"cmake.exe"}, {"msbuild.exe"}),
            ("msbuild-error", "Build", {"MSBUILD": "31"}, True, 31, {"cmake.exe", "msbuild.exe"}, set()),
            ("clean-keeps-project", "Clean", {}, True, 0, {"cmake.exe", "msbuild.exe"}, set()),
        ]
        for name, target, overrides, complete, expected, required, forbidden in cases:
            case = root / name
            script = case / "repo/mswin32/Build.bat"
            script.parent.mkdir(parents=True)
            shutil.copy2(args.script, script)
            bindir = case / "bin"
            bindir.mkdir()
            # Deliberately no svn: an incomplete OpenSSL tree must fail clearly.
            for tool in ("cl.exe", "cmake.exe", "msbuild.exe", "powershell.exe"):
                shutil.copy2(stub, bindir / tool)
            programfiles = case / "Program Files (x86)"
            vswhere = programfiles / "Microsoft Visual Studio/Installer/vswhere.exe"
            vswhere.parent.mkdir(parents=True)
            shutil.copy2(stub, vswhere)
            vs = case / "Visual Studio"
            vcvars = vs / "VC/Auxiliary/Build/vcvarsall.bat"
            vcvars.parent.mkdir(parents=True)
            vcvars.write_text("@exit /b " + overrides.get("VCVARS", "0") + "\n", encoding="ascii")
            aux = case / "kmap-mswin32-aux"
            files = ["Npcap/Include/pcap.h", "Npcap/Include/Packet32.h", "Npcap/Lib/wpcap.lib", "Npcap/Lib/Packet.lib",
                     "OpenSSL/include/openssl/ssl.h", "OpenSSL/include/openssl/crypto.h", "OpenSSL/include/openssl/opensslconf.h"]
            if complete:
                files += ["OpenSSL/lib/libssl.lib", "OpenSSL/lib/libcrypto.lib"]
            for relative in files:
                p = aux / relative
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("fixture", encoding="ascii")
            if name == "partial-npcap":
                (aux / "Npcap/Lib/wpcap.lib").unlink()
            project = script.parent / "build-pcre2/pcre2-8-static.vcxproj"
            project.parent.mkdir()
            project.write_text("fixture", encoding="ascii")
            log = case / "calls.log"
            env = {key.upper(): value for key, value in os.environ.items()}
            env.update({"PROGRAMFILES(X86)": str(programfiles), "PATH": str(bindir) + os.pathsep + str(Path(env["SYSTEMROOT"]) / "System32"),
                        "KMAP_FIXTURE_LOG": str(log), "KMAP_FIXTURE_VS": str(vs), "TEMP": str(case), "TMP": str(case)})
            env.update({"KMAP_FIXTURE_" + key: value for key, value in overrides.items()})
            cmd = Path(env["SYSTEMROOT"]) / "System32/cmd.exe"
            # Supply cmd.exe's documented outer quote pair directly. Python's
            # argv quoting uses backslash escapes, which cmd does not interpret.
            command = f'"{cmd}" /d /s /c ""{script}" {target}"'
            run = subprocess.run(command, cwd=script.parent if target == "Clean" else case,
                                 env=env, capture_output=True, text=True, timeout=20)
            calls = set(log.read_text().splitlines()) if log.exists() else set()
            passed = run.returncode == expected and required <= calls and not (forbidden & calls)
            if target == "Clean":
                passed = passed and project.exists()
            if name == "headers-without-libraries":
                passed = passed and "Complete OpenSSL headers and x86 libraries are missing" in run.stdout
            (args.output / (name + ".log")).write_text(run.stdout + run.stderr, encoding="utf-8")
            results.append({"case": name, "passed": passed, "returncode": run.returncode, "expected": expected, "calls": sorted(calls)})
            print(f"{'PASS' if passed else 'FAIL'} {name}: exit {run.returncode}, expected {expected}")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return 0 if all(item["passed"] for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
