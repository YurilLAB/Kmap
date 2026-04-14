#!/usr/bin/env python3
"""
add_cves.py -- Insert additional pentest-relevant CVEs into kmap-cve.db.
Run from the Kmap root directory: python scripts/add_cves.py
"""
import sqlite3
import sys
import os

DB = os.path.join(os.path.dirname(__file__), '..', 'kmap-cve.db')

NEW_CVES = [
    # (cve_id, product, vendor, version_min, version_max, cvss_score, severity, description)

    # --- Redis ---
    ('CVE-2022-0543', 'redis', 'debian', None, None, 10.0, 'CRITICAL',
     'Redis Lua sandbox escape via the Lua library loaded from Debian package, allowing arbitrary code execution.'),
    ('CVE-2023-28858', 'redis', 'redis', None, '7.0.11', 9.8, 'CRITICAL',
     'Redis unauthenticated access possible when protected-mode is disabled and no requirepass is set.'),
    ('CVE-2022-35169', 'redis', 'redis', None, '7.0.4', 9.8, 'CRITICAL',
     'Redis SRANDMEMBER / ZRANDMEMBER out-of-bounds read leads to heap-based buffer overflow.'),
    ('CVE-2023-36824', 'redis', 'redis', None, '7.0.12', 8.8, 'HIGH',
     'Redis heap overflow in COMMAND GETKEYS and ACL evaluation affects authenticated users.'),
    ('CVE-2022-24736', 'redis', 'redis', None, '6.2.7', 7.5, 'HIGH',
     'Redis denial of service via OBJECT HELP command with crafted input.'),
    ('CVE-2021-32627', 'redis', 'redis', None, '6.2.6', 7.5, 'HIGH',
     'Redis integer overflow in SINTERCARD command enables heap overflow.'),
    ('CVE-2021-32628', 'redis', 'redis', None, '6.2.6', 7.5, 'HIGH',
     'Redis integer overflow in quicklist ziplist entries leads to heap corruption.'),
    ('CVE-2021-32687', 'redis', 'redis', None, '6.2.6', 7.5, 'HIGH',
     'Redis integer overflow in intsets allows heap corruption with authenticated access.'),
    ('CVE-2022-31144', 'redis', 'redis', None, '7.0.3', 7.5, 'HIGH',
     'Redis heap overflow via XAUTOCLAIM command with negative count argument.'),
    ('CVE-2023-41056', 'redis', 'redis', None, '7.2.3', 8.1, 'HIGH',
     'Redis heap overflow in SINTERCARD command processing with many keys.'),

    # --- Elasticsearch ---
    ('CVE-2021-22145', 'elasticsearch', 'elastic', None, '7.13.4', 9.1, 'CRITICAL',
     'Elasticsearch allows unauthenticated remote file read via directory traversal in audit log.'),
    ('CVE-2022-23712', 'elasticsearch', 'elastic', None, '8.2.0', 7.5, 'HIGH',
     'Elasticsearch unauthenticated cluster state access via cross-cluster replication.'),
    ('CVE-2021-37937', 'elasticsearch', 'elastic', None, '7.15.1', 8.8, 'HIGH',
     'Kibana SSRF allows authenticated users to reach internal network hosts.'),
    ('CVE-2022-38778', 'elasticsearch', 'elastic', None, '8.4.1', 7.5, 'HIGH',
     'Elasticsearch arbitrary file read via response filtering in _search endpoint.'),
    ('CVE-2023-31419', 'elasticsearch', 'elastic', None, '8.9.0', 7.5, 'HIGH',
     'Elasticsearch StackOverflow DoS via deeply nested query string parsing.'),
    ('CVE-2021-22147', 'elasticsearch', 'elastic', None, '7.14.0', 7.5, 'HIGH',
     'Elasticsearch document-level security bypass allows unauthorized document access.'),
    ('CVE-2023-46673', 'elasticsearch', 'elastic', None, '8.10.2', 7.5, 'HIGH',
     'Elasticsearch privilege escalation in Fleet Server via crafted requests.'),

    # --- OpenSSH (additional) ---
    ('CVE-2023-38408', 'openssh', 'openbsd', None, '9.3p2', 9.8, 'CRITICAL',
     'OpenSSH ssh-agent remote code execution via crafted PKCS#11 provider loading.'),
    ('CVE-2024-6387', 'openssh', 'openbsd', None, '9.7p1', 8.1, 'HIGH',
     'regreSSHion: race condition in OpenSSH signal handler allows unauthenticated RCE as root.'),
    ('CVE-2023-51767', 'openssh', 'openbsd', None, '9.6p1', 7.5, 'HIGH',
     'OpenSSH PermitRootLogin=prohibit-password bypass via keyboard-interactive authentication.'),
    ('CVE-2021-28041', 'openssh', 'openbsd', None, '8.5p1', 7.1, 'HIGH',
     'OpenSSH agent forwarding double-free vulnerability via crafted responses.'),

    # --- nginx (additional) ---
    ('CVE-2021-23017', 'nginx', 'f5', None, '1.21.0', 9.4, 'CRITICAL',
     'nginx resolver off-by-one heap write in DNS response parsing allows remote code execution.'),
    ('CVE-2022-41742', 'nginx', 'f5', None, '1.23.2', 7.1, 'HIGH',
     'nginx ngx_http_mp4_module memory disclosure via crafted MP4 file.'),
    ('CVE-2022-41741', 'nginx', 'f5', None, '1.23.2', 7.1, 'HIGH',
     'nginx ngx_http_mp4_module heap corruption via crafted MP4 file in MP4 streaming.'),

    # --- MySQL (additional) ---
    ('CVE-2022-21540', 'mysql', 'oracle', '8.0.0', '8.0.28', 7.5, 'HIGH',
     'MySQL Server Optimizer DoS via crafted queries by low-privileged user.'),
    ('CVE-2022-21547', 'mysql', 'oracle', '8.0.0', '8.0.28', 7.5, 'HIGH',
     'MySQL Server Federated plugin unauthorized read access to sensitive data.'),
    ('CVE-2023-21980', 'mysql', 'oracle', None, '8.0.32', 8.8, 'HIGH',
     'MySQL client-side heap-based buffer overflow allows client compromise.'),
    ('CVE-2023-22084', 'mysql', 'oracle', None, '8.1.0', 7.2, 'HIGH',
     'MySQL Server InnoDB privilege escalation via crafted queries.'),
    ('CVE-2024-20963', 'mysql', 'oracle', None, '8.0.35', 7.2, 'HIGH',
     'MySQL Server Security component privilege escalation via authenticated access.'),

    # --- PostgreSQL (additional) ---
    ('CVE-2022-1552', 'postgresql', 'postgresql_global_development_group', None, '14.2', 9.8, 'CRITICAL',
     'PostgreSQL Autovacuum and index operations allow privilege escalation to superuser.'),
    ('CVE-2021-23222', 'postgresql', 'postgresql_global_development_group', None, '14.0', 8.1, 'HIGH',
     'PostgreSQL cleartext protocol allows MITM injection of arbitrary SQL commands.'),
    ('CVE-2023-2454', 'postgresql', 'postgresql_global_development_group', None, '15.2', 7.2, 'HIGH',
     'PostgreSQL schema variable allows privilege escalation via schema manipulation.'),
    ('CVE-2024-0985', 'postgresql', 'postgresql_global_development_group', None, '16.1', 8.0, 'HIGH',
     'PostgreSQL REFRESH MATERIALIZED VIEW CONCURRENTLY allows arbitrary SQL execution.'),

    # --- Samba (additional) ---
    ('CVE-2021-44142', 'samba', 'samba', None, '4.13.17', 9.9, 'CRITICAL',
     'Samba vfs_fruit out-of-bounds read/write allows unauthenticated RCE via crafted EA metadata.'),
    ('CVE-2022-38023', 'samba', 'samba', None, '4.15.13', 8.1, 'HIGH',
     'Samba NetLogon Secure Channel session key forgery vulnerability.'),
    ('CVE-2022-32744', 'samba', 'samba', None, '4.16.4', 8.8, 'HIGH',
     'Samba Kerberos rc4-hmac downgrade allows privilege escalation.'),

    # --- Apache Struts ---
    ('CVE-2023-50164', 'struts', 'apache', None, '6.3.0.1', 9.8, 'CRITICAL',
     'Apache Struts file upload path traversal allows unauthenticated RCE via crafted parameters.'),
    ('CVE-2021-31805', 'struts', 'apache', None, '2.5.29', 9.8, 'CRITICAL',
     'Apache Struts OGNL injection incomplete patch allows RCE via forced double evaluation.'),
    ('CVE-2022-22968', 'struts', 'apache', None, '2.5.29', 7.5, 'HIGH',
     'Apache Struts DoS bypass via specially crafted request bypassing action exclusion.'),

    # --- Jenkins (additional) ---
    ('CVE-2024-23897', 'jenkins', 'jenkins', None, '2.441', 9.8, 'CRITICAL',
     'Jenkins arbitrary file read via CLI path traversal allows unauthenticated RCE.'),
    ('CVE-2024-23898', 'jenkins', 'jenkins', None, '2.441', 8.8, 'HIGH',
     'Jenkins CLI WebSocket endpoint cross-site WebSocket hijacking.'),
    ('CVE-2023-27899', 'jenkins', 'jenkins', None, '2.393', 8.8, 'HIGH',
     'Jenkins temporary files in system temp directory accessible to other local users.'),

    # --- GitLab ---
    ('CVE-2023-7028', 'gitlab', 'gitlab', None, '16.7.2', 10.0, 'CRITICAL',
     'GitLab account takeover via password reset without email confirmation.'),
    ('CVE-2023-5009', 'gitlab', 'gitlab', None, '16.3.4', 9.6, 'CRITICAL',
     'GitLab security policies bypass allows unauthorized pipeline code execution.'),
    ('CVE-2022-2185', 'gitlab', 'gitlab', None, '15.1.1', 9.9, 'CRITICAL',
     'GitLab CE/EE arbitrary code execution via crafted wiki page content.'),
    ('CVE-2021-22205', 'gitlab', 'gitlab', None, '13.9.6', 10.0, 'CRITICAL',
     'GitLab Exiftool RCE via crafted image file in merge request pipeline.'),

    # --- Atlassian Confluence (additional) ---
    ('CVE-2022-26134', 'confluence', 'atlassian', None, '7.18.1', 10.0, 'CRITICAL',
     'Atlassian Confluence OGNL injection allows unauthenticated remote code execution.'),
    ('CVE-2023-22515', 'confluence', 'atlassian', None, '8.5.3', 10.0, 'CRITICAL',
     'Atlassian Confluence broken access control allows privilege escalation to admin.'),
    ('CVE-2023-22518', 'confluence', 'atlassian', None, '8.5.3', 9.1, 'CRITICAL',
     'Atlassian Confluence improper authorization allows unauthenticated data destruction.'),
    ('CVE-2021-26084', 'confluence', 'atlassian', None, '7.12.5', 9.8, 'CRITICAL',
     'Atlassian Confluence OGNL template injection allows unauthenticated RCE.'),

    # --- Atlassian Jira ---
    ('CVE-2022-36804', 'jira', 'atlassian', None, '8.22.2', 9.9, 'CRITICAL',
     'Atlassian Bitbucket Server command injection via git operations.'),
    ('CVE-2021-26086', 'jira', 'atlassian', None, '8.13.22', 7.5, 'HIGH',
     'Atlassian Jira path traversal allows unauthenticated read of arbitrary files.'),

    # --- Microsoft Exchange (additional) ---
    ('CVE-2021-26857', 'exchange_server', 'microsoft', None, None, 7.8, 'HIGH',
     'Microsoft Exchange insecure deserialization allows SYSTEM-level RCE.'),
    ('CVE-2021-27065', 'exchange_server', 'microsoft', None, None, 7.8, 'HIGH',
     'Microsoft Exchange post-auth arbitrary file write allows SYSTEM RCE.'),
    ('CVE-2022-41082', 'exchange_server', 'microsoft', None, None, 8.8, 'HIGH',
     'ProxyNotShell: Microsoft Exchange authenticated SOAP RCE.'),
    ('CVE-2022-41040', 'exchange_server', 'microsoft', None, None, 8.8, 'HIGH',
     'ProxyNotShell: Microsoft Exchange SSRF bypassing authentication restrictions.'),

    # --- VMware vCenter (additional) ---
    ('CVE-2021-22005', 'vcenter_server', 'vmware', None, '6.7u3', 9.8, 'CRITICAL',
     'VMware vCenter arbitrary file upload via analytics service allows unauthenticated RCE.'),
    ('CVE-2022-22954', 'vcenter_server', 'vmware', None, '8.0', 9.8, 'CRITICAL',
     'VMware Workspace ONE Access server-side template injection allows unauthenticated RCE.'),
    ('CVE-2023-20887', 'vcenter_server', 'vmware', None, '8.0u1', 9.8, 'CRITICAL',
     'VMware Aria Operations Networks command injection allows unauthenticated RCE.'),

    # --- Oracle WebLogic ---
    ('CVE-2023-21839', 'weblogic_server', 'oracle', None, '14.1.1.0.0', 9.8, 'CRITICAL',
     'Oracle WebLogic Server unauthenticated RCE via T3/IIOP protocol deserialization.'),
    ('CVE-2021-2428', 'weblogic_server', 'oracle', None, '14.1.1.0.0', 9.8, 'CRITICAL',
     'Oracle WebLogic Server unauthorized T3/IIOP access allows unauthenticated RCE.'),
    ('CVE-2021-2109', 'weblogic_server', 'oracle', None, '12.2.1.4.0', 7.2, 'HIGH',
     'Oracle WebLogic console component allows admin-level remote code execution.'),

    # --- ProFTPd ---
    ('CVE-2023-51713', 'proftpd', 'proftpd', None, '1.3.8b', 7.5, 'HIGH',
     'ProFTPD out-of-bounds read in mod_radius allows crash or information disclosure.'),

    # --- Drupal (additional) ---
    ('CVE-2023-29197', 'drupal', 'drupal', None, '10.0.7', 9.8, 'CRITICAL',
     'Drupal improper input validation allows RCE via crafted request parameters.'),
    ('CVE-2022-25278', 'drupal', 'drupal', None, '9.4.0', 8.8, 'HIGH',
     'Drupal access bypass via crafted form submissions allows privilege escalation.'),

    # --- OpenSSL ---
    ('CVE-2022-0778', 'openssl', 'openssl', None, '3.0.1', 7.5, 'HIGH',
     'OpenSSL BN_mod_sqrt infinite loop via crafted certificate causes DoS.'),
    ('CVE-2022-2274', 'openssl', 'openssl', None, '3.0.5', 9.8, 'CRITICAL',
     'OpenSSL RSA private key operation heap corruption on AVX512IFMA machines.'),
    ('CVE-2023-0286', 'openssl', 'openssl', None, '3.0.8', 9.8, 'CRITICAL',
     'OpenSSL X.400 GeneralName type confusion allows read of arbitrary memory.'),
    ('CVE-2023-0215', 'openssl', 'openssl', None, '3.0.8', 7.5, 'HIGH',
     'OpenSSL use-after-free during BIO_new_NDEF operation causes DoS.'),
    ('CVE-2023-2650', 'openssl', 'openssl', None, '3.1.0', 7.5, 'HIGH',
     'OpenSSL DoS via processing of specially crafted ASN.1 object identifiers.'),
    ('CVE-2024-0727', 'openssl', 'openssl', None, '3.2.0', 7.5, 'HIGH',
     'OpenSSL NULL pointer dereference in PKCS12 parsing allows DoS.'),

    # --- Lighttpd (new — was 0 CVEs in DB) ---
    ('CVE-2014-2323', 'lighttpd', 'lighttpd', None, '1.4.34', 9.8, 'CRITICAL',
     'Lighttpd SQL injection in mod_mysql_vhost via hostname in Host header allows arbitrary SQL execution.'),
    ('CVE-2018-19052', 'lighttpd', 'lighttpd', None, '1.4.51', 7.5, 'HIGH',
     'Lighttpd path traversal in mod_alias when alias with trailing slash maps to directory without trailing slash.'),
    ('CVE-2015-3200', 'lighttpd', 'lighttpd', None, '1.4.35', 7.5, 'HIGH',
     'Lighttpd log injection via specially crafted HTTP basic authentication credentials containing newlines.'),
    ('CVE-2013-4508', 'lighttpd', 'lighttpd', None, '1.4.34', 7.5, 'HIGH',
     'Lighttpd uses weak SSL ciphers when SNI is enabled, compromising session confidentiality.'),
    ('CVE-2013-4559', 'lighttpd', 'lighttpd', None, '1.4.34', 7.5, 'HIGH',
     'Lighttpd does not check return values of setuid/setgid/setgroups allowing privilege escalation.'),
    ('CVE-2013-4560', 'lighttpd', 'lighttpd', None, '1.4.34', 5.0, 'MEDIUM',
     'Lighttpd use-after-free vulnerability on FAM stat cache engine failure causes DoS.'),
    ('CVE-2007-3949', 'lighttpd', 'lighttpd', None, '1.4.16', 8.3, 'HIGH',
     'Lighttpd trailing slash URL bypass circumvents mod_access deny rules for protected paths.'),

    # --- IIS (new — was 0 CVEs in DB) ---
    ('CVE-2021-31166', 'iis', 'microsoft', None, None, 9.8, 'CRITICAL',
     'Windows HTTP Protocol Stack (http.sys) RCE affects IIS. Wormable unauthenticated remote code execution via crafted packets.'),
    ('CVE-2015-1635', 'iis', 'microsoft', None, None, 9.8, 'CRITICAL',
     'HTTP.sys RCE in IIS allows unauthenticated remote code execution via crafted HTTP request with Range header.'),
    ('CVE-2017-7269', 'iis', 'microsoft', None, None, 9.8, 'CRITICAL',
     'IIS 6.0 WebDAV buffer overflow in ScStoragePathFromUrl allows unauthenticated remote code execution.'),
    ('CVE-2022-21907', 'iis', 'microsoft', None, None, 9.8, 'CRITICAL',
     'HTTP Protocol Stack (http.sys) RCE, wormable vulnerability affecting IIS on Windows Server.'),
    ('CVE-2020-0645', 'iis', 'microsoft', None, None, 7.5, 'HIGH',
     'IIS tampering vulnerability when improperly processing malformed request headers allows security bypass.'),
    ('CVE-2016-0152', 'iis', 'microsoft', None, None, 7.8, 'HIGH',
     'IIS mishandles library loading allowing local privilege escalation through crafted application.'),

    # --- PHP (additional — was 1 CVE in DB) ---
    ('CVE-2012-1823', 'php', 'php_group', None, '5.3.12', 9.8, 'CRITICAL',
     'PHP-CGI query string parameter injection allows remote code execution when configured as CGI.'),
    ('CVE-2016-7479', 'php', 'php_group', None, '7.0.14', 9.8, 'CRITICAL',
     'PHP use-after-free during unserialization of properties hash table resizing allows remote code execution.'),
    ('CVE-2019-11043', 'php', 'php_group', None, '7.3.11', 9.8, 'CRITICAL',
     'PHP-FPM buffer underflow in env_path_info allows remote code execution via crafted URL.'),
    ('CVE-2023-3824', 'php', 'php_group', None, '8.2.9', 9.8, 'CRITICAL',
     'PHP heap buffer overflow in phar_dir_read during PHAR archive parsing enables RCE.'),
    ('CVE-2024-2756', 'php', 'php_group', None, '8.3.5', 8.1, 'HIGH',
     'PHP __Host-/__Secure- cookie prefix bypass allows session fixation attacks.'),
    ('CVE-2023-3247', 'php', 'php_group', None, '8.2.8', 7.5, 'HIGH',
     'PHP SOAP missing error check in php_libxml_ctx_error allows XML parsing bypass.'),

    # --- vsftpd (additional — was 2 CVEs in DB) ---
    ('CVE-2011-2523', 'vsftpd', 'beez182', '2.3.4', '2.3.4', 10.0, 'CRITICAL',
     'vsftpd 2.3.4 backdoor: malicious code opens a shell on port 6200/tcp when triggered by :) in username.'),
    ('CVE-2015-1419', 'vsftpd', 'vsftpd_project', None, '3.0.2', 5.0, 'MEDIUM',
     'vsftpd deny_file parsing bypass allows restricted file access when configuration uses {}.'),
    ('CVE-2008-2375', 'vsftpd', 'vsftpd_project', None, '2.0.6', 7.1, 'HIGH',
     'vsftpd memory leak from invalid authentication attempts when using PAM causes denial of service.'),

    # --- OpenSSH (additional — expanding from 9 CVEs) ---
    ('CVE-2006-5051', 'openssh', 'openbsd', None, '4.4', 8.1, 'HIGH',
     'OpenSSH signal handler race condition causes double-free, potential RCE when GSSAPI authentication enabled.'),
    ('CVE-2016-10009', 'openssh', 'openbsd', None, '7.4', 7.3, 'HIGH',
     'OpenSSH ssh-agent untrusted search path allows loading arbitrary PKCS#11 modules via agent forwarding.'),
    ('CVE-2016-10012', 'openssh', 'openbsd', None, '7.4', 7.8, 'HIGH',
     'OpenSSH shared memory manager buffer overflow in pre-authentication compression code path.'),
    ('CVE-2016-10708', 'openssh', 'openbsd', None, '7.4', 7.5, 'HIGH',
     'OpenSSH NULL pointer dereference via out-of-sequence NEWKEYS message causing sshd crash.'),
    ('CVE-2016-6515', 'openssh', 'openbsd', None, '7.3', 7.5, 'HIGH',
     'OpenSSH auth_password has no length limit allowing DoS via CPU exhaustion with very long passwords.'),
    ('CVE-2020-15778', 'openssh', 'openbsd', None, '8.3p1', 7.8, 'HIGH',
     'OpenSSH scp command injection via filenames with backtick characters allows arbitrary command execution.'),
    ('CVE-2023-25136', 'openssh', 'openbsd', None, '9.2p1', 9.8, 'CRITICAL',
     'OpenSSH pre-authentication double-free in options.kex_algorithms allows potential unauthenticated RCE.'),

    # --- MongoDB (additional) ---
    ('CVE-2024-1351', 'mongodb', 'mongodb', None, '7.0.5', 9.1, 'CRITICAL',
     'MongoDB Server authentication bypass via crafted commands allows unauthorized access.'),
    ('CVE-2023-1409', 'mongodb', 'mongodb', None, '6.0.4', 7.5, 'HIGH',
     'MongoDB TLS certificate verification bypass when peer certificate has non-matching hostname.'),

    # --- MariaDB (additional) ---
    ('CVE-2022-27449', 'mariadb', 'mariadb', None, '10.7.3', 7.5, 'HIGH',
     'MariaDB Server crash in sql/item_func.cc via crafted query leads to denial of service.'),
    ('CVE-2022-27447', 'mariadb', 'mariadb', None, '10.7.3', 7.5, 'HIGH',
     'MariaDB Server use-after-free in Binary_string::free_buffer leads to crash.'),
]


def main():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    inserted = 0
    skipped = 0
    for row in NEW_CVES:
        c.execute('INSERT OR IGNORE INTO cves VALUES (?,?,?,?,?,?,?,?)', row)
        if c.rowcount > 0:
            inserted += 1
        else:
            skipped += 1

    conn.commit()
    print(f'Inserted: {inserted}, Skipped (already present): {skipped}')

    c.execute('SELECT COUNT(*) FROM cves')
    print(f'Total CVEs: {c.fetchone()[0]}')

    products = [
        'redis', 'elasticsearch', 'openssh', 'nginx', 'mysql',
        'postgresql', 'samba', 'struts', 'jenkins', 'gitlab',
        'confluence', 'jira', 'exchange_server', 'vcenter_server',
        'weblogic_server', 'drupal', 'openssl', 'proftpd',
        'lighttpd', 'iis', 'php', 'vsftpd', 'mongodb', 'mariadb',
    ]
    c.execute(
        'SELECT product, COUNT(*) FROM cves WHERE product IN ({}) GROUP BY product ORDER BY product'.format(
            ','.join('?' * len(products))
        ),
        products
    )
    print('\nProduct coverage after update:')
    for row in c.fetchall():
        print(f'  {row[0]}: {row[1]}')

    conn.close()


if __name__ == '__main__':
    main()
