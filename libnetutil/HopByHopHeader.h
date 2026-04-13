/***************************************************************************
 * HopByHopHeader.h -- The HopByHopHeader Class represents an IPv6         *
 * Hop-by-Hop extension header.                                            *
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
/* This code was originally part of the Nping tool.                        */

#ifndef __HOP_BY_HOP_HEADER_H__
#define __HOP_BY_HOP_HEADER_H__ 1

#include "IPv6ExtensionHeader.h"

#define HOP_BY_HOP_MAX_OPTIONS_LEN 256*8
#define HOPBYHOP_MIN_HEADER_LEN 8
#define HOPBYHOP_MAX_HEADER_LEN (HOPBYHOP_MIN_HEADER_LEN + HOP_BY_HOP_MAX_OPTIONS_LEN)
#define HOPBYHOP_MAX_OPTION_LEN 256

class HopByHopHeader : public IPv6ExtensionHeader {

    protected:
     /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Next Header  |  Hdr Ext Len  |                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
        |                                                               |
        .                                                               .
        .                            Options                            .
        .                                                               .
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        struct nping_ipv6_ext_hopbyhop_hdr{
            u8 nh;
            u8 len;
            u8 options[HOP_BY_HOP_MAX_OPTIONS_LEN];
        }__attribute__((__packed__));
        typedef struct nping_ipv6_ext_hopbyhop_hdr nping_ipv6_ext_hopbyhop_hdr_t;


     /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
        |  Option Type  |  Opt Data Len |  Option Data
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - - */
        struct nping_ipv6_ext_hopbyhop_opt{
            u8 type;
            u8 len;
            u8 data[HOPBYHOP_MAX_OPTION_LEN];
        }__attribute__((__packed__));
        typedef struct nping_ipv6_ext_hopbyhop_opt nping_ipv6_ext_hopbyhop_opt_t;

        nping_ipv6_ext_hopbyhop_hdr_t h;
        u8 *curr_option;

    public:
        HopByHopHeader();
        ~HopByHopHeader();
        void reset();
        u8 *getBufferPointer();
        int storeRecvData(const u8 *buf, size_t len);
        int protocol_id() const;
        int validate();
        int print(FILE *output, int detail) const;

        /* Protocol specific methods */
        int setNextHeader(u8 val);
        u8 getNextHeader();

        int addOption(u8 type, u8 len, const u8 *data);
        int addPadding();

}; /* End of class HopByHopHeader */

#endif
