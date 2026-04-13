#ifndef PROBESPEC_H
#define PROBESPEC_H
/***************************************************************************
 * probespec.h -- Defines structures which specify probes to network ports *
 * and protocols.                                                          *
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
 * https://kmap.org/book/man-legal.html, and further information on the
 * NPSL license itself can be found at https://kmap.org/npsl/ . This
 * header summarizes some key points from the Kmap license, but is no
 * substitute for the actual license text.
 *
 * Kmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://kmap.org.
 *
 * The Kmap license generally prohibits companies from using and
 * redistributing Kmap in commercial products, but we sell a special Kmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://kmap.org/oem/
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
 * Github PR or by email to the dev@kmap.org mailing list for possible
 * incorporation into the main distribution. Unless you specify otherwise, it
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
 * Npcap OEM program--see https://kmap.org/oem/
 *
 ***************************************************************************/
#include <nbase.h>

struct probespec_tcpdata {
  u16 dport;
  u8 flags;
};

struct probespec_udpdata {
  u16 dport;
};

struct probespec_sctpdata {
  u16 dport;
  u8 chunktype;
};

struct probespec_icmpdata {
  u8 type;
  u8 code;
};

struct probespec_icmpv6data {
  u8 type;
  u8 code;
};

#define PS_NONE 0
#define PS_TCP 1
#define PS_UDP 2
#define PS_PROTO 3
#define PS_ICMP 4
#define PS_ARP 5
#define PS_CONNECTTCP 6
#define PS_SCTP 7
#define PS_ICMPV6 8
#define PS_ND 9

/* The size of this structure is critical, since there can be tens of
   thousands of them stored together ... */
typedef struct probespec {
  /* To save space, I changed this from private enum (took 4 bytes) to
     u8 that uses #defines above */
  u8 type;
  u8 proto; /* If not PS_ARP -- Protocol number ... eg IPPROTO_TCP, etc. */
  union {
    struct probespec_tcpdata tcp; /* If type is PS_TCP or PS_CONNECTTCP. */
    struct probespec_udpdata udp; /* PS_UDP */
    struct probespec_sctpdata sctp; /* PS_SCTP */
    struct probespec_icmpdata icmp; /* PS_ICMP */
    struct probespec_icmpv6data icmpv6; /* PS_ICMPV6 */
    /* Nothing needed for PS_ARP, since src mac and target IP are
       avail from target structure anyway */
  } pd;
} probespec;

#endif
