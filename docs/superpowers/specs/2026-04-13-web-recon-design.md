# Feature: `--web-recon`

**Date:** 2026-04-13  
**Status:** Approved

## Summary

Post-scan HTTP/HTTPS reconnaissance phase. Activates on any port identified as `http` or `https` by service detection. Uses nsock for raw TCP — no new network library dependency.

## Probe Sequence

1. `GET /` — page title, Server/X-Powered-By/X-Generator headers, redirect chain, cookie flags
2. `GET /robots.txt` — display Disallow entries (reveals hidden paths)
3. TLS info (HTTPS only) — CN, SANs, issuer, expiry, protocol version, cipher. Self-signed certs noted but not fatal; verification skipped by default
4. Path probe — sequential GET against 40-path curated list, report any non-404 response:

```
/admin /login /phpMyAdmin /.env /.git/HEAD /wp-login.php
/api/v1 /actuator /console /manager/html /config.php
/backup /server-status /.htaccess /api/swagger.json /api/docs
/graphql /.well-known/security.txt /crossdomain.xml /elmah.axd
/trace.axd /_profiler /debug /staging /test /dev /old
/phpmyadmin /adminer.php /webadmin /cpanel /plesk
/jmx-console /web-console /admin-console /invoker/JMXInvokerServlet
/.DS_Store /.svn/entries /WEB-INF/web.xml /web.config
```

## Behavior

- TLS certificate errors ignored by default (self-signed common in internal nets)
- Each path probe: 5s timeout, sequential (not parallel) to avoid IDS triggers
- Follows one level of redirects, reports final destination

## CLI

```
--web-recon              Enable HTTP/S recon on detected web ports
--web-paths <file>       Append custom path list to built-in list
```

## New Files

- `web_recon.h` / `web_recon.cc` — probe engine

## Output

Normal output — shown under each web port:
```
80/tcp open  http  Apache httpd 2.4.49
  Web Recon:
    Title:   "Apache2 Default Page"
    Server:  Apache/2.4.49 (Ubuntu)
    Robots:  /admin [disallowed]
    Paths:   /.env [200] /.git/HEAD [200] /admin [301→/admin/]
```

JSON — `"web_recon": { "title": "...", "server": "...", "tls": {...}, "paths": [...] }`

XML — `<webrecon>` block with child elements mirroring JSON structure.
