/***************************************************************************
 * ncat_ssl.h                                                              *
 ***********************IMPORTANT KMAP LICENSE TERMS************************
 *
 * The Kmap Security Scanner is (C) 1996-2026 Kmap Software LLC ("The Kmap
 * Project"). Kmap is also a registered trademark of the Kmap Project.
 *
 * This program is distributed under the terms of the Kmap Public Source
 * License (NPSL). The exact license text applying to a particular Kmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Kmap or source code control
 * revision. More Kmap copyright/legal information is available from
 * https://github.com/YurilLAB/Kmap/blob/master/LICENSE, and further information on the
 * NPSL license itself can be found at https://github.com/YurilLAB/Kmap/blob/master/LICENSE . This
 * header summarizes some key points from the Kmap license, but is no
 * substitute for the actual license text.
 *
 * Kmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://github.com/YurilLAB/Kmap.
 *
 * The Kmap license generally prohibits companies from using and
 * redistributing Kmap in commercial products, but we sell a special Kmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://github.com/YurilLAB/Kmap
 *
 * If you have received a written Kmap license agreement or contract
 * stating terms other than these (such as an Kmap OEM license), you may
 * choose to use and redistribute Kmap under those terms instead.
 *
 * The official Kmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Kmap Windows builds may not be redistributed
 * without special permission (such as an Kmap OEM license).
 *
 * Source is provided to this software because we believe users have a
 * right to know exactly what a program is going to do before they run it.
 * This also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Kmap to new platforms, fix bugs, and
 * add new features. You are highly encouraged to submit your changes as a
 * Github PR at https://github.com/YurilLAB/Kmap for possible incorporation
 * into the main distribution. Unless you specify otherwise, it
 * is understood that you are offering us very broad rights to use your
 * submissions as described in the Kmap Public Source License Contributor
 * Agreement. This is important because we fund the project by selling licenses
 * with various terms, and also because the inability to relicense code has
 * caused devastating problems for other Free Software projects (such as KDE
 * and NASM).
 *
 * The free version of Kmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Kmap project -- see https://github.com/YurilLAB/Kmap
 *
 ***************************************************************************/

/* $Id$ */
#ifndef NCAT_SSL_H
#define NCAT_SSL_H

#include "ncat_config.h"

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>

#define NCAT_CA_CERTS_FILE "ca-bundle.crt"

enum {
    SHA1_BYTES = 160 / 8,
    /* 40 bytes for hex digits and 9 bytes for ' '. */
    SHA1_STRING_LENGTH = SHA1_BYTES * 2 + (SHA1_BYTES / 2 - 1)
};

/* These status variables are returned by ssl_handshake() to describe the
 * status of a pending non-blocking ssl handshake(SSL_accept()). */
enum {
    NCAT_SSL_HANDSHAKE_COMPLETED      = 0,
    NCAT_SSL_HANDSHAKE_PENDING_READ   = 1,
    NCAT_SSL_HANDSHAKE_PENDING_WRITE  = 2,
    NCAT_SSL_HANDSHAKE_FAILED         = 3
};

extern SSL_CTX *setup_ssl_listen(const SSL_METHOD *method);

extern SSL *new_ssl(int fd);

extern int ssl_post_connect_check(SSL *ssl, const char *hostname);

extern char *ssl_cert_fp_str_sha1(const X509 *cert, char *strbuf, size_t len);

extern int ssl_load_default_ca_certs(SSL_CTX *ctx);

/* Try to complete an ssl handshake in a non-blocking way for the socket given
 * in sinfo. Initialize the socket too with new_ssl() if it hasn't been done
 * already. */
extern int ssl_handshake(struct fdinfo *sinfo);

#endif
#endif
