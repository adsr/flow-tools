/*
 * Copyright (c) 2001 Mark Fullmer and The Ohio State University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      $Id: pcap.h,v 1.5 2002/02/10 03:50:06 maf Exp $
 */

#include <sys/time.h>
#include <ftlib.h>

#define TCPDUMP_MAGIC 0xa1b2c3d4
#define TCPDUMP_VERSION_MAJOR 2
#define TCPDUMP_VERSION_MINOR 2

struct pcap_file_header {
  u_long magic;
  u_short version_major;
  u_short version_minor;
  long thiszone;    /* gmt to local correction */
  u_long sigfigs;   /* accuracy of timestamps */
  u_long snaplen;   /* max length saved portion of each pkt */
  u_long linktype;
};

struct pcap_packet_header {
  struct timeval ts;  /* time stamp */
  u_long len;         /* length this packet (off wire) */
  u_long caplen;      /* length of portion present */
};

/* eth header */
struct pcap_data1 {
  /* eth header */
  u_int8 eth_dst[6];
  u_int8 eth_src[6];
  u_int16 eth_prot;
};

/* ip header */
struct pcap_data2 {
  u_int8 version;
  u_int8 tos;
  u_int16 len;
  u_int16 id;
  u_int16 flags_fragment;
  u_int8 ttl;
  u_int8 prot;
  u_int16 csum;
  uint32_t srcaddr;
  uint32_t dstaddr;
};

/* tcp header */
struct pcap_data3 {
  u_int16 srcport;
  u_int16 dstport;
  uint32_t hold1; /* seq */
  uint32_t hold2; /* ack */
  uint32_t hold3; /* data, reserved, flags, window */
  uint32_t hold4; /* csum, urg pointer */
  uint32_t hold5; /* options, padding */
};


/* udp header */
struct pcap_data4 {
  u_int16 srcport;
  u_int16 dstport;
  uint32_t hold1; /* len */
  uint32_t hold2; /* csum */
  uint32_t hold3; /* data ...*/
  uint32_t hold4; /* data ... */
  uint32_t hold5; /* data ... */
#ifdef XXX
  uint32_t hold6; /* data */
#endif /* XXX */
};


