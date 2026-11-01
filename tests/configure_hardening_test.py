#!/usr/bin/env python3
"""Exercise production configure hardening with real compilers and reject controls.

Builds only tiny local C/C++ fixtures, never the application. Requires Autoconf,
make and readelf (Linux CI). Logs, generated flags and ELF reports are retained.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time


SOURCE = r'''#include <stdio.h>
int main(void) {
  char buffer[128];
  if (fgets(buffer, sizeof(buffer), stdin)) return printf("%s", buffer) < 0;
  return 0;
}
'''

WRAPPER = r'''#!{python}
import os, sys
command = {command!r}
mode = {mode!r}
arguments = sys.argv[1:]
protected = [arg for arg in arguments if arg.startswith('-fstack-protector') or
             arg == '-Wl,-z,relro,-z,now']
if mode == 'reject-strong' and '-fstack-protector-strong' in arguments:
    sys.exit(61)
if mode == 'unsupported' and protected:
    sys.exit(62)
if mode == 'warn-ignore' and protected:
    print('fixture: warning: ignored unsupported hardening option', file=sys.stderr)
    arguments = [arg for arg in arguments if arg not in protected]
if mode == 'non-elf':
    arguments.insert(0, '-U__ELF__')
if mode == 'require-stack-link' and any(arg.endswith('.o') for arg in arguments) and '-c' not in arguments:
    if not any(arg.startswith('-fstack-protector') for arg in arguments):
        print('fixture: stack runtime driver option missing at final link', file=sys.stderr)
        sys.exit(63)
os.execvp(command[0], command + arguments)
'''


def require(value, message):
    if not value:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, default=Path('test-results/configure-hardening'))
    parser.add_argument('--autoconf', default='autoconf')
    parser.add_argument('--cc', default=os.environ.get('CC', 'cc'))
    parser.add_argument('--cxx', default=os.environ.get('CXX', 'c++'))
    args = parser.parse_args()
    root, out = args.root.resolve(), args.output.resolve()
    for tool in (args.autoconf, 'make', 'readelf'):
        require(shutil.which(tool), 'required tool unavailable: ' + tool)
    require('m4_include([m4/kmap_hardening.m4])' in (root / 'configure.ac').read_text() and
            '\nKMAP_CHECK_HARDENING\n' in (root / 'configure.ac').read_text(),
            'production configure must invoke the tested hardening macro')
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    records = []

    def run(folder, name, command, env=None):
        result = subprocess.run(command, cwd=folder, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
        (folder / (name + '.log')).write_bytes(result.stdout)
        require(result.returncode == 0, f'{name} exited {result.returncode}; see {folder}')
        return result.stdout.decode(errors='replace')

    try:
        # Defaults, fallback, wholly unsupported flags, warning-only acceptance,
        # non-ELF target selection, an opt-out and explicit user overrides.
        cases = [('default', 'normal'), ('runtime-link', 'require-stack-link'), ('fallback', 'reject-strong'),
                 ('unsupported', 'unsupported'), ('warning-only', 'warn-ignore'),
                 ('non-elf', 'non-elf'), ('disabled', 'normal'), ('user-flags', 'normal'),
                 ('cxx-disabled', 'require-stack-link')]
        for name, mode in cases:
            folder = out / name
            folder.mkdir()
            record = {'case': name, 'status': 'running'}
            records.append(record)
            shutil.copy2(root / 'm4/kmap_hardening.m4', folder / 'kmap_hardening.m4')
            (folder / 'configure.ac').write_text('''AC_INIT([hardening-fixture], [1])
AC_PROG_CC
AC_PROG_CXX
m4_include([kmap_hardening.m4])
KMAP_CHECK_HARDENING
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
''')
            production_ldflags = next(line for line in (root / 'Makefile.in').read_text().splitlines()
                                      if line.startswith('LDFLAGS = '))
            (folder / 'Makefile.in').write_text('''CC = @CC@
CXX = @CXX@
CFLAGS = @CFLAGS@
CXXFLAGS = @CXXFLAGS@
CPPFLAGS = @CPPFLAGS@
LDFLAGS = @LDFLAGS@
SSP_LDFLAGS = @KMAP_SSP_LDFLAGS@
all:
\t$(CC) $(CPPFLAGS) $(CFLAGS) -c fixture.c -o fixture-c.o
\t$(CXX) $(LDFLAGS) fixture-c.o -o fixture-c
\t$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c fixture.cc -o fixture-cxx.o
\t$(CXX) $(LDFLAGS) fixture-cxx.o -o fixture-cxx
'''.replace('LDFLAGS = @LDFLAGS@', production_ldflags))
            for suffix in ('c', 'cc'):
                (folder / ('fixture.' + suffix)).write_text(SOURCE)
            env = dict(os.environ)
            for key in ('CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'LIBS', 'CONFIG_SITE'):
                env.pop(key, None)
            env.update(CFLAGS='-O2 -DKMAP_USER_C=1', CXXFLAGS='-O2 -DKMAP_USER_CXX=1',
                       CPPFLAGS='-DKMAP_USER_CPP=1', CONFIG_SITE='/dev/null', LC_ALL='C')
            for variable, command in (('CC', args.cc), ('CXX', args.cxx)):
                wrapper = folder / variable.lower()
                wrapper.write_text(WRAPPER.format(python=sys.executable,
                                                  command=shlex.split(command), mode=mode))
                wrapper.chmod(0o700)
                env[variable] = shlex.quote(str(wrapper))
            configure_args = ['sh', './configure']
            if name == 'disabled':
                configure_args.append('--disable-hardening')
            if name == 'user-flags':
                env['CFLAGS'] += ' -fno-stack-protector'
                env['CXXFLAGS'] += ' -fno-stack-protector'
                env['LDFLAGS'] = '-Wl,-z,norelro,-z,lazy'
            if name == 'cxx-disabled':
                env['CXXFLAGS'] += ' -fno-stack-protector'
            run(folder, 'autoconf', [args.autoconf], env)
            run(folder, 'configure', configure_args, env)
            flags = dict(line.split(' = ', 1) for line in (folder / 'Makefile').read_text().splitlines()
                         if ' = ' in line)
            record['flags'] = flags
            require('-DKMAP_USER_C=1' in flags['CFLAGS'] and
                    '-DKMAP_USER_CXX=1' in flags['CXXFLAGS'] and
                    '-DKMAP_USER_CPP=1' in flags['CPPFLAGS'], 'user flags lost')
            stack = '-fstack-protector-strong' if name != 'fallback' else '-fstack-protector'
            if name in ('disabled', 'unsupported', 'warning-only'):
                require('-fstack-protector' not in flags['CFLAGS'] + flags['CXXFLAGS'],
                        name + ': unsupported/disabled stack flags leaked')
                require(not flags['SSP_LDFLAGS'], name + ': stack link default leaked')
            else:
                require(stack in shlex.split(flags['CFLAGS']) and
                        stack in shlex.split(flags['CXXFLAGS']), name + ': missing stack defaults')
                require(flags['SSP_LDFLAGS'] == stack,
                        name + ': supported stack runtime driver option missing')
            if name in ('non-elf', 'disabled', 'unsupported', 'warning-only'):
                require('-Wl,-z,relro,-z,now' not in flags['LDFLAGS'], name + ': RELRO flag leaked')
            else:
                require('-Wl,-z,relro,-z,now' in flags['LDFLAGS'], name + ': missing RELRO default')
            run(folder, 'make', ['make'], env)
            record['binaries'] = {}
            for binary in ('fixture-c', 'fixture-cxx'):
                segments = run(folder, binary + '-segments', ['readelf', '-lW', binary], env)
                dynamic = run(folder, binary + '-dynamic', ['readelf', '-dW', binary], env)
                symbols = run(folder, binary + '-symbols', ['readelf', '-sW', binary], env)
                actual = {'canary': '__stack_chk_fail' in symbols,
                          'relro': 'GNU_RELRO' in segments, 'bind_now': 'BIND_NOW' in dynamic}
                record['binaries'][binary] = actual
                if name in ('default', 'runtime-link', 'fallback'):
                    require(all(actual.values()), name + ': binary hardening missing')
                if name == 'user-flags':
                    require(not any(actual.values()), 'explicit disable flags did not win')
                if name == 'cxx-disabled':
                    require(actual['canary'] == (binary == 'fixture-c'),
                            'CXX-only disable did not preserve C protection and disable C++ protection')
                    require(actual['relro'] and actual['bind_now'], 'CXX-only disable lost RELRO')
            record['status'] = 'passed'
            print('PASS configure hardening: ' + name)
    finally:
        (out / 'results.json').write_text(json.dumps({'cases': records,
            'elapsed_seconds': time.monotonic() - started}, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
