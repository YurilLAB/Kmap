/***************************************************************************
 * PacketParser.h -- The PacketParser Class offers methods to parse        *
 * received network packets. Its main purpose is to facilitate the         *
 * conversion of raw sequences of bytes into chains of objects of the      *
 * PacketElement family.                                                   *
 *                                                                         *
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
/* This code was originally part of the Nping tool.                        */

#ifndef __PACKETPARSER_H__
#define __PACKETPARSER_H__ 1

#include "ApplicationLayerElement.h"
#include "ARPHeader.h"
#include "DataLinkLayerElement.h"
#include "EthernetHeader.h"
#include "ICMPHeader.h"
#include "ICMPv4Header.h"
#include "ICMPv6Header.h"
#include "ICMPv6Option.h"
#include "ICMPv6RRBody.h"
#include "IPv4Header.h"
#include "IPv6Header.h"
#include "NetworkLayerElement.h"
#include "PacketElement.h"
#include "RawData.h"
#include "TCPHeader.h"
#include "TransportLayerElement.h"
#include "UDPHeader.h"
#include "HopByHopHeader.h"
#include "DestOptsHeader.h"
#include "FragmentHeader.h"
#include "RoutingHeader.h"


#define LINK_LAYER         2
#define NETWORK_LAYER      3
#define TRANSPORT_LAYER    4
#define APPLICATION_LAYER  5
#define EXTHEADERS_LAYER   6

typedef struct header_type_string{
    u32 type;
    const char *str;
}header_type_string_t;


typedef struct packet_type{
    u32 type;
    u32 length;
}pkt_type_t;


class PacketParser {

    private:

    public:

    /* Misc */
    PacketParser();
    ~PacketParser();
    void reset();

    static const char *header_type2string(int val);
    static pkt_type_t *parse_packet(const u8 *pkt, size_t pktlen, bool eth_included);
    static int dummy_print_packet_type(const u8 *pkt, size_t pktlen, bool eth_included); /* TODO: remove */
    static int dummy_print_packet(const u8 *pkt, size_t pktlen, bool eth_included); /* TODO: remove */
    static int payload_offset(const u8 *pkt, size_t pktlen, bool link_included);
    static PacketElement *split(const u8 *pkt, size_t pktlen, bool eth_included);
    static PacketElement *split(const u8 *pkt, size_t pktlen);
    static int freePacketChain(PacketElement *first);
    static const char *test_packet_parser(PacketElement *test_pkt);
    static bool is_response(PacketElement *sent, PacketElement *rcvd);
    static PacketElement *find_transport_layer(PacketElement *chain);

}; /* End of class PacketParser */

#endif /* __PACKETPARSER_H__ */
