/***************************************************************************
 * TransportLayerElement.cc -- Class TransportLayerElement is a generic    *
 * class that represents a transport layer protocol header. Classes like   *
 * TCPHeader or UDPHeader inherit from it.                                 *
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
/* This code was originally part of the Nping tool.                        */

#include "TransportLayerElement.h"
#include "IPv4Header.h"
#include "IPv6Header.h"


/** Computes and returns the Internet checksum.
 * @warning  This method requires the object to be linked to either an IPv6Header
 * object or an IPv4Header one, so the caller must ensure that objects are
 * properly linked with calls to setNextElement() like this:
 *
 * IPv6Header ip6;
 * TCPHeader tcp;
 * [...] # Set header fields
 * ip6.setNextElement(&tcp);
 * tcp.setSum();
 *
 * Note that there can be a number of other headers (like IPv6 extension headers)
 * between the transport header and the network one, but all of them need to
 * be linked in order for this method to traverse the list of headers and find
 * the IP source and destination address, required to compute the checksum. So
 * things like the following are OK:
 *
 * IPv6Header ip6;
 * HopByHopHeader hop;
 * RoutingHeader rte;
 * FragmentHeader frg;
 * UDPHeader udp;
 * [...] # Set whatever header fields you need
 * ip6.setNextElement(&hop);
 * hop.setNextElement(&rte);
 * rte.setNextElement(&frg);
 * frg.setNextElement(&udp);
 * udp.setSum(); # setSum() will be able to reach the IPv6Header. */
u16 TransportLayerElement::compute_checksum(){
  PacketElement *hdr;
  hdr=this->getPrevElement();
  u16 final_sum=0;
  /* Traverse the list of headers backwards until we find an IP header */
  while(hdr!=NULL){
      if (hdr->protocol_id()==HEADER_TYPE_IPv6){
            IPv6Header *v6hdr=(IPv6Header *)hdr;
            struct in6_addr i6src, i6dst;
            memcpy(i6src.s6_addr, v6hdr->getSourceAddress(), 16);
            memcpy(i6dst.s6_addr, v6hdr->getDestinationAddress(), 16);
            u8 *buff=(u8 *)safe_malloc(this->getLen());
            this->dumpToBinaryBuffer(buff, this->getLen());
            final_sum=ipv6_pseudoheader_cksum(&i6src, &i6dst, this->protocol_id(), this->getLen(), buff);
            free(buff);
            return final_sum;
      }else if(hdr->protocol_id()==HEADER_TYPE_IPv4){
            IPv4Header *v4hdr=(IPv4Header *)hdr;
            struct in_addr i4src, i4dst;
            memcpy(&(i4src.s_addr), v4hdr->getSourceAddress(), 4);
            memcpy(&(i4dst.s_addr), v4hdr->getDestinationAddress(), 4);
            u8 *buff=(u8 *)safe_malloc(this->getLen());
            this->dumpToBinaryBuffer(buff, this->getLen());
            final_sum=ipv4_pseudoheader_cksum(&i4src, &i4dst, this->protocol_id(), this->getLen(), buff);
            free(buff);
            return final_sum;
      }else{
          hdr=hdr->getPrevElement();
      }
  }
  return 0;
} /* End of setSum() */
