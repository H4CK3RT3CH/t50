/*
 *  T50 - Experimental Mixed Packet Injector
 *
 *  Copyright (C) 2010 - 2014 - T50 developers
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <common.h>

/*
 * prototypes.
 */
static size_t tcp_options_len(const uint8_t, const uint8_t, const uint8_t);

/* Function Name: TCP packet header configuration.

Description:   This function configures and sends the TCP packet header.

Targets:       N/A */
int tcp(const socket_t fd, const struct config_options *o)
{
  size_t greoptlen,   /* GRE options size. */
         tcpolen,     /* TCP options size. */
         tcpopt,      /* TCP options total size. */
         packet_size,
         offset,
         counter;

  mptr_t buffer;

  /* Socket address, IP header. */
  struct sockaddr_in sin;
  struct iphdr *ip;

  /* GRE Encapsulated IP Header. */
  struct iphdr *gre_ip;

  /* TCP header and PSEUDO header. */
  struct tcphdr *tcp;
  struct psdhdr *pseudo;

  assert(o != NULL);

  greoptlen = gre_opt_len(o->gre.options, o->encapsulated);
  tcpolen = tcp_options_len(o->tcp.options, o->tcp.md5, o->tcp.auth);
  tcpopt = tcpolen + TCPOLEN_PADDING(tcpolen);
  packet_size = sizeof(struct iphdr) + 
    greoptlen             + 
    sizeof(struct tcphdr) + 
    tcpopt;

  /* Try to reallocate packet, if necessary */
  alloc_packet(packet_size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, packet_size, o);

  gre_ip = gre_encapsulation(packet, o, 
        sizeof(struct iphdr) + 
        sizeof(struct tcphdr) + 
        tcpopt);

  /* 
   * The RFC 793 has defined a 4-bit field in the TCP header which encodes the size
   * of the header in 4-byte words.  Thus the maximum header size is 15*4=60 bytes. 
   * Of this, 20 bytes are taken up by non-options fields of the TCP header,  which
   * leaves 40 bytes (TCP header * 2) for options.
   */
  if (tcpopt > (sizeof(struct tcphdr) * 2))
  {
    fprintf(stderr,
        "%s(): TCP Options size (%u bytes) is bigger than two times TCP Header size\n",
        __FUNCTION__,
        (unsigned int)tcpopt);
    fflush(stderr);
    exit(EXIT_FAILURE);
  }

  /* TCP Header structure making a pointer to IP Header structure. */
  tcp          = (struct tcphdr *)((void *)ip + sizeof(struct iphdr) + greoptlen);
  tcp->source  = htons(IPPORT_RND(o->source));
  tcp->dest    = htons(IPPORT_RND(o->dest));
  tcp->res1    = TCP_RESERVED_BITS;
  tcp->doff    = o->tcp.doff ? o->tcp.doff : ((sizeof(struct tcphdr) + tcpopt) / 4);
  tcp->fin     = o->tcp.fin;
  tcp->syn     = o->tcp.syn;
  tcp->seq     = o->tcp.syn ? htonl(__32BIT_RND(o->tcp.sequence)) : 0;
  tcp->rst     = o->tcp.rst;
  tcp->psh     = o->tcp.psh;
  tcp->ack     = o->tcp.ack;
  tcp->ack_seq = o->tcp.ack ? htonl(__32BIT_RND(o->tcp.acknowledge)) : 0;
  tcp->urg     = o->tcp.urg;
  tcp->urg_ptr = o->tcp.urg ? htons(__16BIT_RND(o->tcp.urg_ptr)) : 0;
  tcp->ece     = o->tcp.ece;
  tcp->cwr     = o->tcp.cwr;
  tcp->window  = htons(__16BIT_RND(o->tcp.window));
  tcp->check   = 0;

  buffer.ptr = (void *)tcp + sizeof(struct tcphdr);

  /*
   * Transmission Control Protocol (TCP) (RFC 793)
   *
   *    TCP Maximum Segment Size
   *
   *    Kind: 2
   *
   *    Length: 4 bytes
   *
   *    +--------+--------+---------+--------+
   *    |00000010|00000100|   max seg size   |
   *    +--------+--------+---------+--------+
   */
  if (TEST_BITS(o->tcp.options, TCP_OPTION_MSS))
  {
    *buffer.byte_ptr++ = TCPOPT_MSS;
    *buffer.byte_ptr++ = TCPOLEN_MSS;
    *buffer.word_ptr++ = htons(__16BIT_RND(o->tcp.mss));
  }

  /*
   * TCP Extensions for High Performance (RFC 1323)
   *
   *    TCP Window Scale Option (WSopt):
   *
   *    Kind: 3
   *
   *    Length: 3 bytes
   *
   *    +--------+--------+--------+
   *    |00000011|00000011| shift  |
   *    +--------+--------+--------+
   */
  if (TEST_BITS(o->tcp.options, TCP_OPTION_WSOPT))
  {
    *buffer.byte_ptr++ = TCPOPT_WSOPT;
    *buffer.byte_ptr++ = TCPOLEN_WSOPT;
    *buffer.byte_ptr++ = __8BIT_RND(o->tcp.wsopt);
  }

  /*
   * TCP Extensions for High Performance (RFC 1323)
   *
   *    TCP Timestamps Option (TSopt):
   *
   *    Kind: 8
   *
   *    Length: 10 bytes
   *
   *                      +--------+--------+
   *                      |00001000|00001010|
   *    +--------+--------+--------+--------+
   *    |         TS Value (TSval)          |
   *    +--------+--------+--------+--------+
   *    |       TS Echo Reply (TSecr)       |
   *    +--------+--------+--------+--------+
   */
  if (TEST_BITS(o->tcp.options, TCP_OPTION_TSOPT))
  {
    /*
     * TCP Extensions for High Performance (RFC 1323)
     *
     * APPENDIX A:  IMPLEMENTATION SUGGESTIONS
     *
     *   The following layouts are recommended for sending options on non-SYN
     *   segments, to achieve maximum feasible alignment of 32-bit and 64-bit
     *   machines.
     *
     *
     *       +--------+--------+--------+--------+
     *       |   NOP  |  NOP   |  TSopt |   10   |
     *       +--------+--------+--------+--------+
     *       |          TSval   timestamp        |
     *       +--------+--------+--------+--------+
     *       |          TSecr   timestamp        |
     *       +--------+--------+--------+--------+
     */
    if (!o->tcp.syn)
      for (; tcpolen & 3; tcpolen++)
        *buffer.byte_ptr++ = TCPOPT_NOP;
    *buffer.byte_ptr++ = TCPOPT_TSOPT;
    *buffer.byte_ptr++ = TCPOLEN_TSOPT;
    *buffer.dword_ptr++ = htonl(__32BIT_RND(o->tcp.tsval));
    *buffer.dword_ptr++ = htonl(__32BIT_RND(o->tcp.tsecr));
  }

  /*
   * TCP Extensions for Transactions Functional Specification (RFC 1644)
   *
   *    CC Option:
   *
   *    Kind: 11
   *
   *    Length: 6 bytes
   *
   *                      +--------+--------+
   *                      |00001011|00000110|
   *    +--------+--------+--------+--------+
   *    |     Connection Count:  SEG.CC     |
   *    +--------+--------+--------+--------+
   */
  if (TEST_BITS(o->tcp.options, TCP_OPTION_CC))
  {
    *buffer.byte_ptr++ = TCPOPT_CC;
    *buffer.byte_ptr++ = TCPOLEN_CC;
    *buffer.dword_ptr++ = htonl(__32BIT_RND(o->tcp.cc));

    /*
     * TCP Extensions for Transactions Functional Specification (RFC 1644)
     *
     * 3.1  Data Structures
     *
     * This option may be sent in an initial SYN segment,  and it may be sent
     * in other segments if a  CC or CC.NEW option has been received for this
     * incarnation of the connection.  Its  SEG.CC  value  is  the TCB.CCsend
     *  value from the sender's TCB.
     */
    tcp->syn     = 1;
    tcp->seq     = htonl(__32BIT_RND(o->tcp.sequence));
  }

  /*
   * TCP Extensions for Transactions Functional Specification (RFC 1644)
   *
   *    CC.NEW Option:
   *
   *    Kind: 12
   *
   *    Length: 6 bytes
   *
   *                      +--------+--------+
   *                      |00001100|00000110|
   *    +--------+--------+--------+--------+
   *    |     Connection Count:  SEG.CC     |
   *    +--------+--------+--------+--------+
   *
   *    CC.ECHO Option:
   *
   *    Kind: 13
   *
   *    Length: 6 bytes
   *
   *                      +--------+--------+
   *                      |00001101|00000110|
   *    +--------+--------+--------+--------+
   *    |     Connection Count:  SEG.CC     |
   *    +--------+--------+--------+--------+
   */
  if (TEST_BITS(o->tcp.options, TCP_OPTION_CC_NEXT))
  {
    *buffer.byte_ptr++ = o->tcp.cc_new ? TCPOPT_CC_NEW : TCPOPT_CC_ECHO;
    *buffer.byte_ptr++ = TCPOLEN_CC;
    *buffer.dword_ptr++ = htonl(o->tcp.cc_new ? 
      __32BIT_RND(o->tcp.cc_new) : __32BIT_RND(o->tcp.cc_echo));

    tcp->syn = 1;
    tcp->seq = htonl(__32BIT_RND(o->tcp.sequence));

    /*
     * TCP Extensions for Transactions Functional Specification (RFC 1644)
     *
     * 3.1  Data Structures
     *
     * This  option  may be sent instead of a CC option in an  initial  <SYN> 
     * segment (i.e., SYN but not ACK bit), to indicate that the SEG.CC value
     * may not be larger than the previous value.   Its  SEG.CC  value is the
     * TCB.CCsend value from the sender's TCB.
     */
    if (!o->tcp.cc_new)
    {
      /*
       * TCP Extensions for Transactions Functional Specification (RFC 1644)
       *
       * 3.1  Data Structures
       *
       * This  option  may be sent instead of a CC option in an  initial  <SYN> 
       * This  option must be sent  (in addition to a CC option)  in a  segment 
       * containing both a  SYN and an  ACK bit,  if  the initial  SYN  segment
       * contained a CC or CC.NEW option.  Its SEG.CC value is the SEG.CC value
       * from the initial SYN.
       */
      tcp->ack     = 1;
      tcp->ack_seq = htonl(__32BIT_RND(o->tcp.acknowledge));
    }
  }

  /*
   * TCP Selective Acknowledgement Options (SACK) (RFC 2018)
   *
   *    TCP Sack-Permitted Option:
   *
   *    Kind: 4
   *
   *    Length: 2 bytes
   *
   *    +--------+--------+
   *    |00000100|00000010|
   *    +--------+--------+
   */
  if (TEST_BITS(o->tcp.options, TCP_OPTION_SACK_OK))
  {
    *buffer.byte_ptr++ = TCPOPT_SACK_OK;
    *buffer.byte_ptr++ = TCPOLEN_SACK_OK;
  }

  /*
   * TCP Selective Acknowledgement Options (SACK) (RFC 2018)
   *
   *    TCP SACK Option:
   *
   *    Kind: 5
   *
   *    Length: Variable
   *
   *                      +--------+--------+
   *                      |00000101| Length |
   *    +--------+--------+--------+--------+
   *    |      Left Edge of 1st Block       |
   *    +--------+--------+--------+--------+
   *    |      Right Edge of 1st Block      |
   *    +--------+--------+--------+--------+
   *    |                                   |
   *    /            . . .                  /
   *    |                                   |
   *    +--------+--------+--------+--------+
   *    |      Left Edge of nth Block       |
   *    +--------+--------+--------+--------+
   *    |      Right Edge of nth Block      |
   *    +--------+--------+--------+--------+
   */
  if (TEST_BITS(o->tcp.options, TCP_OPTION_SACK_EDGE))
  {
    *buffer.byte_ptr++ = TCPOPT_SACK_EDGE;
    *buffer.byte_ptr++ = TCPOLEN_SACK_EDGE(1);
    *buffer.dword_ptr++ = htonl(__32BIT_RND(o->tcp.sack_left));
    *buffer.dword_ptr++ = htonl(__32BIT_RND(o->tcp.sack_right));
  }

  /*
   *  Protection of BGP Sessions via the TCP MD5 Signature Option (RFC 2385)
   *
   *    TCP MD5 Option:
   *
   *    Kind: 19
   *
   *    Length: 18 bytes
   *
   *    +--------+--------+--------+--------+
   *    |00010011|00010010|   MD5 digest... |
   *    +--------+--------+--------+--------+
   *    |        ...digest (con't)...       |
   *    +-----------------------------------+
   *    |                ...                |
   *    +-----------------------------------+
   *    |                ...                |
   *    +-----------------+-----------------+
   *    |...digest (con't)|
   *    +-----------------+
   */
  if (o->tcp.md5)
  {
    size_t stemp;

    *buffer.byte_ptr++ = TCPOPT_MD5;
    *buffer.byte_ptr++ = TCPOLEN_MD5;
    /*
     * The Authentication key uses HMAC-MD5 digest.
     */
    stemp = auth_hmac_md5_len(o->tcp.md5);
    for (counter = 0; counter < stemp; counter++)
      *buffer.byte_ptr++ = __8BIT_RND(0);
  }

  /*
   *  The TCP Authentication Option (RFC 5925)
   *
   *    TCP-AO Option:
   *
   *    Kind: 29
   *
   *    Length: 20 bytes
   *
   *    +--------+--------+--------+--------+
   *    |00011101|00010100| Key ID |Next Key|
   *    +--------+--------+--------+--------+
   *    |              MAC ...              |
   *    +-----------------------------------+
   *    |                ...                |
   *    +-----------------------------------+
   *    |                ...                |
   *    +-----------------+-----------------+
   *    |    ... MAC      |
   *    +-----------------+
   */
  if (o->tcp.auth)
  {
    size_t stemp;

    *buffer.byte_ptr++ = TCPOPT_AO;
    *buffer.byte_ptr++ = TCPOLEN_AO;
    *buffer.byte_ptr++ = __8BIT_RND(o->tcp.key_id);
    *buffer.byte_ptr++ = __8BIT_RND(o->tcp.next_key);
    /*
     * The Authentication key uses HMAC-MD5 digest.
     */
    stemp = auth_hmac_md5_len(o->tcp.auth);
    for (counter = 0; counter < stemp; counter++)
      *buffer.byte_ptr++ = __8BIT_RND(0);
  }

  /* Padding the TCP Options. */
  for (; tcpolen & 3; tcpolen++)
    *buffer.byte_ptr++ = o->tcp.nop;

  offset = sizeof(struct tcphdr) + tcpolen;

  /* Fill PSEUDO Header structure. */
  pseudo           = (struct psdhdr *)buffer.ptr;
  pseudo->saddr    = o->encapsulated ? gre_ip->saddr : ip->saddr;
  pseudo->daddr    = o->encapsulated ? gre_ip->daddr : ip->daddr;
  pseudo->zero     = 0;
  pseudo->protocol = o->ip.protocol;
  pseudo->len      = htons(offset);

  offset += sizeof(struct psdhdr);

  /* Computing the checksum. */
  tcp->check   = o->bogus_csum ? __16BIT_RND(0) : cksum(tcp, offset);

  gre_checksum(packet, o, packet_size);

  /* Setting SOCKADDR structure. */
  sin.sin_family      = AF_INET;
  sin.sin_port        = htons(IPPORT_RND(o->dest));
  sin.sin_addr.s_addr = o->ip.daddr;

  /* Sending packet. */
  if (sendto(fd, packet, packet_size, 0|MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1 && errno != EPERM)
    return 1;

  return 0;
}

/* Function Name: TCP options size calculation.

Description:   This function calculates the size of TCP options.

Targets:       N/A */
static size_t tcp_options_len(const uint8_t foo, const uint8_t bar, const uint8_t baz)
{
  size_t size;

  /*
   * The code starts with size '0' and it accumulates all the required
   * size if the conditionals match. Otherwise, it returns size '0'.
   */
  size = 0;

  /*
   * TCP Options has Maximum Segment Size (MSS) Option defined.
   */
  if (TEST_BITS(foo, TCP_OPTION_MSS)) 
    size += TCPOLEN_MSS;

  /*
   * TCP Options has Window Scale (WSopt) Option defined.
   */
  if (TEST_BITS(foo, TCP_OPTION_WSOPT)) 
    size += TCPOLEN_WSOPT;

  /*
   * TCP Options has Timestamp (TSopt) Option defined.
   */
  if (TEST_BITS(foo, TCP_OPTION_TSOPT)) 
    size += TCPOLEN_TSOPT;

  /*
   * TCP Options has Selective Acknowledgement (SACK-Permitted) Option
   * defined.
   */
  if (TEST_BITS(foo, TCP_OPTION_SACK_OK)) 
    size += TCPOLEN_SACK_OK;

  /*
   * TCP Options has Connection Count (CC) Option defined.
   */
  if (TEST_BITS(foo, TCP_OPTION_CC)) 
    size += TCPOLEN_CC;

  /*
   * TCP Options has CC.NEW or CC.ECHO Option defined.
   */
  if (TEST_BITS(foo, TCP_OPTION_CC_NEXT)) 
    size += TCPOLEN_CC;

  /*
   * TCP Options has Selective Acknowledgement (SACK) Option defined.
   */
  if (TEST_BITS(foo, TCP_OPTION_SACK_EDGE)) 
    size += TCPOLEN_SACK_EDGE(1);

  /*
   * Defining it the size should use MD5 Signature Option or the brand
   * new TCP Authentication Option (TCP-AO).
   */
  if (bar) 
    size += TCPOLEN_MD5;

  if (baz) 
    size += TCPOLEN_AO;

  return size;
}

