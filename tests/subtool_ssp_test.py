#!/usr/bin/env python3
"""Link actual Nping/Ncat recipes against a simulated separate SSP runtime.

Protected archives require an extra symbol, supplied by the compiler wrapper
only when its stack-protector driver option reaches final linking. This models
toolchains whose libc does not provide SSP, using real compilation/linking.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys


def require(value, message):
    if not value:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, default=Path('test-results/subtool-ssp'))
    parser.add_argument('--autoconf', default='autoconf')
    parser.add_argument('--cc', default=os.environ.get('CC', 'cc'))
    parser.add_argument('--cxx', default=os.environ.get('CXX', 'c++'))
    args = parser.parse_args()
    root, out = args.root.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    results = []

    def run(folder, name, command, env=None, expected=0):
        p = subprocess.run(command, cwd=folder, env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
        (folder / (name + '.log')).write_bytes(p.stdout)
        require((p.returncode == 0) == (expected == 0), f'{name}: exit {p.returncode}; see {folder}')
        return p

    try:
        for tool, language, variable in (('nping', 'C++', 'CXXFLAGS'), ('ncat', 'C', 'CFLAGS')):
            folder = out / tool
            folder.mkdir()
            source = (root / tool / 'configure.ac').read_text()
            invocation = f'KMAP_CHECK_SSP_LINK([{language}], [{variable}])'
            require(invocation in source, tool + ': production configure must call tested macro')
            shutil.copy2(root / 'm4/kmap_hardening.m4', folder / 'kmap_hardening.m4')
            (folder / 'configure.ac').write_text('AC_INIT([subtool-ssp-fixture], [1])\n'
                'AC_PROG_CC\nAC_PROG_CXX\nm4_include([kmap_hardening.m4])\n' + invocation +
                '\nAC_CONFIG_FILES([Makefile])\nAC_OUTPUT\n')
            (folder / 'runtime.c').write_text('int kmap_fixture_ssp_runtime(void) { return 0; }\n')
            (folder / 'archive.c').write_text('extern int kmap_fixture_ssp_runtime(void);\n'
                'int protected_archive(void) { volatile char b[64]; b[0]=0; '
                'return b[0] + kmap_fixture_ssp_runtime(); }\n')
            (folder / 'main.c').write_text('extern int protected_archive(void);\n'
                                          'int main(void) { return protected_archive(); }\n')
            cc, cxx = shlex.split(args.cc), shlex.split(args.cxx)
            run(folder, 'runtime-build', cc + ['-c', 'runtime.c', '-o', 'runtime.o'])
            run(folder, 'archive-build', cc + ['-fstack-protector', '-c', 'archive.c', '-o', 'archive.o'])
            run(folder, 'archive-pack', ['ar', 'rcs', 'protected.a', 'archive.o'])
            run(folder, 'main-build', cc + ['-c', 'main.c', '-o', 'main.o'])
            env = dict(os.environ)
            for key in ('CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'LIBS', 'CONFIG_SITE'):
                env.pop(key, None)
            env.update(CFLAGS='-O2 -DKMAP_C_OVERRIDE=1', CXXFLAGS='-O2 -DKMAP_CXX_OVERRIDE=1',
                       CONFIG_SITE='/dev/null', LC_ALL='C')
            for name, command in (('CC', cc), ('CXX', cxx)):
                wrapper = folder / name.lower()
                wrapper.write_text(f'''#!{sys.executable}
import os, sys
arguments = sys.argv[1:]
if '-c' not in arguments and any(a.startswith('-fstack-protector') for a in arguments):
    arguments.append({str(folder / 'runtime.o')!r})
command = {command!r}
os.execvp(command[0], command + arguments)
''')
                wrapper.chmod(0o700)
                env[name] = shlex.quote(str(wrapper))
            template = (root / tool / 'Makefile.in').read_text().splitlines()
            ldflags = next(line for line in template if line.startswith('LDFLAGS = '))
            # Execute the production executable link recipe with inert objects
            # and archives; no copied replacement link command can hide a gap.
            target_index = next(i for i, line in enumerate(template) if line.startswith('$(TARGET):'))
            recipe = next(line for line in template[target_index + 1:]
                          if line.startswith('\t$(CXX) ') or line.startswith('\t$(CC) '))
            makefile = ('CC = @CC@\nCXX = @CXX@\nCFLAGS = @CFLAGS@\nCXXFLAGS = @CXXFLAGS@\n'
                + ldflags + '\nOBJS = main.o\nLIBS = protected.a\nall: helper\nhelper:\n' + recipe + '\n')
            (folder / 'Makefile.in').write_text(makefile)
            run(folder, 'autoconf', [args.autoconf], env)
            run(folder, 'configure', ['sh', './configure'], env)
            configured = (folder / 'Makefile').read_text()
            flags = dict(line.split(' = ', 1) for line in configured.splitlines() if ' = ' in line)
            require(flags['CFLAGS'] == env['CFLAGS'] and flags['CXXFLAGS'] == env['CXXFLAGS'],
                    tool + ': link-only detection changed compile flags')
            # The old missing-hint configuration must fail at the real linker.
            without_hint = configured.replace('-fstack-protector-strong', '').replace('-fstack-protector', '')
            (folder / 'Makefile.without-hint').write_text(without_hint)
            negative = run(folder, 'without-runtime-hint', ['make', '-f', 'Makefile.without-hint'], env, expected=1)
            require(b'kmap_fixture_ssp_runtime' in negative.stdout, 'negative control failed for unrelated reason')
            run(folder, 'with-runtime-hint', ['make'], env)
            run(folder, 'execute', [str(folder / 'helper')], env)
            results.append({'tool': tool, 'status': 'passed', 'flags': flags,
                            'negative_returncode': negative.returncode})
            print('PASS separate SSP runtime: ' + tool)
    finally:
        (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
