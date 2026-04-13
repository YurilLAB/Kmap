# Feature: `--default-creds`

**Date:** 2026-04-13  
**Status:** Approved

## Summary

Post-scan phase that probes detected services for default/common credentials. Runs after `-sV` service detection (auto-enabled if not specified). Findings reported inline in all output formats.

## Services Covered

SSH, FTP, Telnet, HTTP Basic Auth, MySQL, PostgreSQL, MSSQL, MongoDB

## Credential Data

- Bundled file: `kmap-default-creds` (same pattern as `kmap-services`)
- Format: `# service  username  password` — empty password represented as `(empty)`
- ~50 pairs per service covering universal defaults + common vendor defaults
- `--creds-file <path>` overrides with user-supplied wordlist (SecLists compatible)

## Probe Methods

| Service   | Method |
|-----------|--------|
| SSH       | libssh2 (existing kmap dependency) |
| FTP       | Raw TCP via nsock — USER/PASS commands |
| Telnet    | Raw TCP via nsock — banner read + login sequence |
| HTTP Basic| nsock HTTP GET with `Authorization: Basic` header |
| MySQL     | Raw MySQL protocol handshake |
| PostgreSQL| Raw PG startup packet + MD5 auth |
| MSSQL     | Raw TDS protocol handshake |
| MongoDB   | Raw wire protocol — isMaster + auth |

## Behavior

- Auto-enables `-sV` if not specified (no warning, silent)
- Timeout: 3s per attempt (configurable via `--creds-timeout`)
- Rate: sequential per host; parallel across hosts follows `-T` timing template
- Stops trying a service after first successful match (configurable)

## CLI

```
--default-creds          Use built-in credential list
--creds-file <file>      Use custom wordlist (overrides built-in)
--creds-timeout <sec>    Per-attempt timeout (default: 3)
```

## New Files

- `default_creds.h` / `default_creds.cc` — probe engine
- `kmap-default-creds` — bundled credential data file

## Output

Normal output — findings shown under each port:
```
22/tcp open  ssh  OpenSSH 7.4
  └─ DEFAULT CREDS: root:root [FOUND]
```

JSON — under each port object: `"default_creds": {"found": true, "username": "root", "password": "root"}`

XML — `<defaultcreds found="true" username="root" password="root"/>`
