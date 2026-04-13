
/***************************************************************************
 * EchoServer.h --                                                         *
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
#ifndef __ECHOSERVER_H__
#define __ECHOSERVER_H__ 1



#include "nping.h"
#include "nsock.h"
#include <vector>
#include "NEPContext.h"

#define LISTEN_QUEUE_SIZE 10

class EchoServer  {

    private:
        /* Attributes */
        std::vector<NEPContext> client_ctx;
        clientid_t client_id_count;

        /* Methods */
        int nep_listen_socket();
        int addClientContext(NEPContext ctx);
        NEPContext *getClientContext(clientid_t clnt);
        NEPContext *getClientContext(nsock_iod iod);
        int destroyClientContext(clientid_t clnt);
        nsock_iod getClientNsockIOD(clientid_t clnt);
        clientid_t getNewClientID();
        clientid_t nep_match_packet(const u8 *pkt, size_t pktlen);
        clientid_t nep_match_headers(IPv4Header *ip4, IPv6Header *ip6, TCPHeader *tcp, UDPHeader *udp, ICMPv4Header *icmp4, RawData *payload);
        int parse_hs_client(u8 *pkt, size_t pktlen, NEPContext *ctx);
        int parse_packet_spec(u8 *pkt, size_t pktlen, NEPContext *ctx);

        int generate_hs_server(EchoHeader *h, NEPContext *ctx);
        int generate_hs_final(EchoHeader *h, NEPContext *ctx);
        int generate_ready(EchoHeader *h, NEPContext *ctx);
        int generate_echo(EchoHeader *h, const u8 *pkt, size_t pktlen, NEPContext *ctx);

    public:

        EchoServer();
        ~EchoServer();
        void reset();
        int start();
        int cleanup();

        int nep_capture_handler(nsock_pool nsp, nsock_event nse, void *param);
        int nep_echo_handler(nsock_pool nsp, nsock_event nse, void *param);
        int nep_hs_server_handler(nsock_pool nsp, nsock_event nse, void *param);
        int nep_hs_client_handler(nsock_pool nsp, nsock_event nse, void *param);
        int nep_hs_final_handler(nsock_pool nsp, nsock_event nse, void *param);
        int nep_packetspec_handler(nsock_pool nsp, nsock_event nse, void *param);
        int nep_ready_handler(nsock_pool nsp, nsock_event nse, void *param);
        int nep_session_ended_handler(nsock_pool nsp, nsock_event nse, void *param);

}; /* End of class EchoServer */

typedef struct handler_arg{
  EchoServer *me;
  void *param;
} handler_arg_t;

/* Handler wrappers */
void capture_handler(nsock_pool nsp, nsock_event nse, void *arg);
void echo_handler(nsock_pool nsp, nsock_event nse, void *arg);
void hs_server_handler(nsock_pool nsp, nsock_event nse, void *arg);
void hs_client_handler(nsock_pool nsp, nsock_event nse, void *arg);
void hs_final_handler(nsock_pool nsp, nsock_event nse, void *arg);
void packetspec_handler(nsock_pool nsp, nsock_event nse, void *arg);
void ready_handler(nsock_pool nsp, nsock_event nse, void *arg);
void empty_handler(nsock_pool nsp, nsock_event nse, void *arg);
void session_ended_handler(nsock_pool nsp, nsock_event nse, void *arg);

#endif /* __ECHOSERVER_H__ */
