
/***************************************************************************
 * utils_net.cc -- Miscellaneous network-related functions that perform    *
 * various tasks.                                                          *
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

#include "NpingTarget.h"

#ifndef UTILS_NET_H
#define UTILS_NET_H 1

#ifndef NETINET_IN_SYSTM_H  /* This guarding is needed for at least some versions of OpenBSD */
#include <netinet/in_systm.h> /* defines n_long needed for netinet/ip.h */
#define NETINET_IN_SYSTM_H
#endif
#ifndef NETINET_IP_H  /* This guarding is needed for at least some versions of OpenBSD */
#include <netinet/ip.h>
#define NETINET_IP_H
#endif

int atoIP(const char *hostname, struct in_addr *dst);
int atoIP(const char *hostname, struct sockaddr_storage *ss, int family);
char *IPtoa(u32 i);
char *IPtoa(struct sockaddr_storage *ss);
char *IPtoa(struct in_addr addr);
char *IPtoa(struct in6_addr addr);
char *IPtoa(struct sockaddr_storage ss);
char *IPtoa(struct sockaddr_storage *ss, int family);
char *IPtoa(u8 *ipv6addr);
u16 sockaddr2port(struct sockaddr_storage *ss);
u16 sockaddr2port(struct sockaddr_storage ss);
u16 sockaddr2port(struct sockaddr_in *s4);
u16 sockaddr2port(struct sockaddr_in6 *s6);
int setsockaddrfamily(struct sockaddr_storage *ss, int family);
int setsockaddrany(struct sockaddr_storage *ss);
bool isICMPType(u8 type);
bool isICMPCode(u8 code);
bool isICMPCode(u8 code, u8 type);
int getPacketStrInfo(const char *proto, const u8 *packet, u32 len, u8 *dstbuff, u32 dstlen, struct sockaddr_storage *ss_src, struct sockaddr_storage *ss_dst);
int getPacketStrInfo(const char *proto, const u8 *packet, u32 len, u8 *dstbuff, u32 dstlen);
int getNetworkInterfaceName(u32 destination, char *dev);
int getNetworkInterfaceName(struct sockaddr_storage *dst, char *dev);
int nping_getpts_simple(const char *origexpr, u16 **list, int *count);
int resolveCached(char *host, struct sockaddr_storage *ss, size_t *sslen,int pf) ;
struct hostent *gethostbynameCached(char *host);
struct hostent *hostentcpy(struct hostent *src);
int hostentfree(struct hostent *src);
int parseMAC(const char *txt, u8 *targetbuff);
char *MACtoa(u8 *mac);
const char *arppackethdrinfo(const u8 *packet, u32 len, int detail );
int arppackethdrinfo(const u8 *packet, u32 len, u8 *dstbuff, u32 dstlen);
int tcppackethdrinfo(const u8 *packet, size_t len, u8 *dstbuff, size_t dstlen, int detail, struct sockaddr_storage *src, struct sockaddr_storage *dst);
int udppackethdrinfo(const u8 *packet, size_t len, u8 *dstbuff, size_t dstlen, int detail, struct sockaddr_storage *src, struct sockaddr_storage *dst);
const char *getRandomTextPayload();
int send_packet(NpingTarget *target, int rawfd, u8 *pkt, size_t pktLen);
int print_dnet_interface(const struct intf_entry *entry, void *arg) ;
int print_interfaces_dnet();
struct sockaddr_storage *getSrcSockAddrFromIPPacket(u8 *pkt, size_t pktLen);
u8 *getUDPheaderLocation(u8 *pkt, size_t pktLen);
u8 *getTCPheaderLocation(u8 *pkt, size_t pktLen);
u8 getProtoFromIPPacket(u8 *pkt, size_t pktLen);
u16 *getSrcPortFromIPPacket(u8 *pkt, size_t pktLen);
u16 *getDstPortFromIPPacket(u8 *pkt, size_t pktLen);
u16 *getDstPortFromTCPHeader(u8 *pkt, size_t pktLen);
u16 *getDstPortFromUDPHeader(u8 *pkt, size_t pktLen);
int obtainRawSocket();

#define DEVNAMELEN 16
#define PATH_PROC_IFINET6 "/proc/net/if_inet6"
typedef struct ipv6_interface{
  char devname[DEVNAMELEN];            /* Interface name                    */
  struct sockaddr_storage ss;          /* Address as a sockaddr_storage var */
  u8 addr[16];                         /* Address as a 128bit array         */        
  u16 netmask_bits;                    /* Prefix length                     */
  u8 dev_no;                           /* Netlink device number             */
  u8 scope;                            /* Scope                             */
  u8 flags;                            /* Interface flags                   */
  u8 mac[6];                           /* MAC addr. (I wish we could get it)*/
}if6_t;

int getinterfaces_inet6_linux(if6_t *ifbuf, int max_ifaces);

#define PATH_PROC_IPV6ROUTE "/proc/net/ipv6_route"

typedef struct sys_route6 {
  struct in6_addr dst_net;             /* Destination Network               */
  u8 dst_prefix;                       /* Destination Prefix Length         */
  struct in6_addr src_net;             /* Source Network                    */
  u8 src_prefix;                       /* Source Prefix Length              */
  struct in6_addr next_hop;            /* Gateway - 0 if none               */
  u32 metric;                          /* Metric                            */
  u32 ref_count;                       /* Reference Counter                 */
  u32 use_count;                       /* Use Counter                       */
  u32 flags;                           /* Flags                             */
  char devname[DEVNAMELEN];            /* Device name                       */
}route6_t;

int getroutes_inet6_linux(route6_t *rtbuf, int max_routes);
route6_t *route_dst_ipv6_linux(const struct sockaddr_storage *const dst);

#endif /* UTILS_NET_H */
