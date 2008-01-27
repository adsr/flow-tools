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
 *      $Id: ftswap.c,v 1.14 2003/02/13 02:38:42 maf Exp $
 */

#include "ftconfig.h"
#include "ftlib.h"

/*
 * function: ftpdu_swap
 *
 * Swap bytes in any PDU structure.  cur is the current
 * byte order of the PDU
 *
*/
void ftpdu_swap(void *pdu, int cur)
{
  struct ftpdu_header *ph;
  int16_t i;
  char agg_method, agg_version;

  ph = pdu;
  i = ph->version;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  switch (i) {

    case 1:
      ftpdu_v1_swap(pdu, cur);
      break;

    case 5:
      ftpdu_v5_swap(pdu, cur);
      break;

    case 6:
      ftpdu_v6_swap(pdu, cur);
      break;

    case 7:
      ftpdu_v7_swap(pdu, cur);
      break;

    case 8:
      agg_method = *((char*)pdu+22);
      agg_version = *((char*)pdu+23);

      switch (agg_method) {

        case 1:
          ftpdu_v8_1_swap(pdu, cur);
          break;

        case 2:
          ftpdu_v8_2_swap(pdu, cur);
          break;

        case 3:
          ftpdu_v8_3_swap(pdu, cur);
          break;

        case 4:
          ftpdu_v8_4_swap(pdu, cur);
          break;

        case 5:
          ftpdu_v8_5_swap(pdu, cur);
          break;

        case 6:
          ftpdu_v8_6_swap(pdu, cur);
          break;

        case 7:
          ftpdu_v8_7_swap(pdu, cur);
          break;

        case 8:
          ftpdu_v8_8_swap(pdu, cur);
          break;

        case 9:
          ftpdu_v8_9_swap(pdu, cur);
          break;

        case 10:
          ftpdu_v8_10_swap(pdu, cur);
          break;

        case 11:
          ftpdu_v8_11_swap(pdu, cur);
          break;

        case 12:
          ftpdu_v8_12_swap(pdu, cur);
          break;

        case 13:
          ftpdu_v8_13_swap(pdu, cur);
          break;

        case 14:
          ftpdu_v8_14_swap(pdu, cur);
          break;

        default:
          fterr_warnx("Internal error agg_method=%d", (int)agg_method);
          break;

      } /* switch */
      break;

    default:
      fterr_warnx("Internal error i=%d", (int)i);
      break;

  } /* switch */

} /* ftpdu_swap */

/*
 * function: ftpdu_v1_swap
 *
 * Swap bytes in a V1 PDU.  cur is the current
 * byte order of the PDU
 *
*/
void ftpdu_v1_swap(struct ftpdu_v1 *pdu, int cur)
{
  int16_t i;

  i = pdu->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  SWAPINT16(pdu->version);
  SWAPINT16(pdu->count);
  SWAPINT32(pdu->sysUpTime);
  SWAPINT32(pdu->unix_secs);
  SWAPINT32(pdu->unix_nsecs);

  for (--i; i >= 0; --i) {
    SWAPINT32(pdu->records[i].srcaddr);
    SWAPINT32(pdu->records[i].dstaddr);
    SWAPINT32(pdu->records[i].nexthop);
    SWAPINT16(pdu->records[i].input);
    SWAPINT16(pdu->records[i].output);
    SWAPINT32(pdu->records[i].dPkts);
    SWAPINT32(pdu->records[i].dOctets);
    SWAPINT32(pdu->records[i].First);
    SWAPINT32(pdu->records[i].Last);
    SWAPINT16(pdu->records[i].dstport);
    SWAPINT16(pdu->records[i].srcport);
  }
} /* ftpdu_v1_swap */

void ftpdu_v5_swap(struct ftpdu_v5 *pdu, int cur)
{
  int16_t i;

  i = pdu->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  SWAPINT16(pdu->version);
  SWAPINT16(pdu->count);
  SWAPINT32(pdu->sysUpTime);
  SWAPINT32(pdu->unix_secs);
  SWAPINT32(pdu->unix_nsecs);
  SWAPINT32(pdu->flow_sequence);

  for (--i; i >= 0; --i) {
    SWAPINT32(pdu->records[i].srcaddr);
    SWAPINT32(pdu->records[i].dstaddr);
    SWAPINT32(pdu->records[i].nexthop);
    SWAPINT16(pdu->records[i].input)   ;
    SWAPINT16(pdu->records[i].output);
    SWAPINT32(pdu->records[i].dPkts);
    SWAPINT32(pdu->records[i].dOctets);
    SWAPINT32(pdu->records[i].First);
    SWAPINT32(pdu->records[i].Last);
    SWAPINT16(pdu->records[i].dstport);
    SWAPINT16(pdu->records[i].srcport);
    SWAPINT16(pdu->records[i].src_as);
    SWAPINT16(pdu->records[i].dst_as);
    SWAPINT16(pdu->records[i].drops);
  }

} /* ftpdu_v5_swap */

/*
 * function: ftpdu_v6_swap
 *
 * Swap bytes in a V6 PDU.  cur is the current
 * byte order of the PDU
 *
*/
void ftpdu_v6_swap(struct ftpdu_v6 *pdu, int cur)
{
  int16_t i;

  i = pdu->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  SWAPINT16(pdu->version);
  SWAPINT16(pdu->count);
  SWAPINT32(pdu->sysUpTime);
  SWAPINT32(pdu->unix_secs);
  SWAPINT32(pdu->unix_nsecs);
  SWAPINT32(pdu->flow_sequence);

  for (--i; i >= 0; --i) {
    SWAPINT32(pdu->records[i].srcaddr);
    SWAPINT32(pdu->records[i].dstaddr);
    SWAPINT32(pdu->records[i].nexthop);
    SWAPINT16(pdu->records[i].input);
    SWAPINT16(pdu->records[i].output);
    SWAPINT32(pdu->records[i].dPkts);
    SWAPINT32(pdu->records[i].dOctets);
    SWAPINT32(pdu->records[i].First);
    SWAPINT32(pdu->records[i].Last);
    SWAPINT16(pdu->records[i].dstport);
    SWAPINT16(pdu->records[i].srcport);
    SWAPINT16(pdu->records[i].src_as);
    SWAPINT16(pdu->records[i].dst_as);
    SWAPINT32(pdu->records[i].peer_nexthop);
  }
} /* ftpdu_v6_swap */

/*
 * function: ftpdu_v7_swap
 *
 * Swap bytes in a V7 PDU.  cur is the current
 * byte order of the PDU
 *
*/
void ftpdu_v7_swap(struct ftpdu_v7 *pdu, int cur)
{
  int16_t i;

  i = pdu->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  SWAPINT16(pdu->version);
  SWAPINT16(pdu->count);
  SWAPINT32(pdu->sysUpTime);
  SWAPINT32(pdu->unix_secs);
  SWAPINT32(pdu->unix_nsecs);
  SWAPINT32(pdu->flow_sequence);

  for (--i; i >= 0; --i) {
    SWAPINT32(pdu->records[i].srcaddr);
    SWAPINT32(pdu->records[i].dstaddr);
    SWAPINT32(pdu->records[i].nexthop);
    SWAPINT16(pdu->records[i].input)   ;
    SWAPINT16(pdu->records[i].output);
    SWAPINT32(pdu->records[i].dPkts);
    SWAPINT32(pdu->records[i].dOctets);
    SWAPINT32(pdu->records[i].First);
    SWAPINT32(pdu->records[i].Last);
    SWAPINT16(pdu->records[i].dstport);
    SWAPINT16(pdu->records[i].srcport);
    SWAPINT16(pdu->records[i].src_as);
    SWAPINT16(pdu->records[i].dst_as);
    SWAPINT16(pdu->records[i].drops);
    SWAPINT32(pdu->records[i].router_sc);
  }
} /* ftpdu_v7_swap */

/*
 * function: ftpdu_v8_1_swap
 *
 * Swap bytes in a V8 agg method 1 PDU.  cur is the current
 * byte order of the PDU
 *
*/
void ftpdu_v8_1_swap(struct ftpdu_v8_1 *pdu, int cur)
{
  int16_t i;

  i = pdu->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  SWAPINT16(pdu->version);
  SWAPINT16(pdu->count);
  SWAPINT32(pdu->sysUpTime);
  SWAPINT32(pdu->unix_secs);
  SWAPINT32(pdu->unix_nsecs);
  SWAPINT32(pdu->flow_sequence);

  for (--i; i >= 0; --i) {
    SWAPINT32(pdu->records[i].dFlows);
    SWAPINT32(pdu->records[i].dPkts);
    SWAPINT32(pdu->records[i].dOctets);
    SWAPINT32(pdu->records[i].First);
    SWAPINT32(pdu->records[i].Last);
    SWAPINT16(pdu->records[i].src_as);
    SWAPINT16(pdu->records[i].dst_as);
    SWAPINT16(pdu->records[i].input);
    SWAPINT16(pdu->records[i].output);
  }

} /* ftpdu_v8_1_swap */

/*
 * function: ftpdu_v8_2_swap
 *
 * Swap bytes in a V8 agg method 2 PDU.  cur is the current
 * byte order of the PDU
 *
*/
void ftpdu_v8_2_swap(struct ftpdu_v8_2 *pdu, int cur)
{
  int16_t i;

  i = pdu->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  SWAPINT16(pdu->version);
  SWAPINT16(pdu->count);
  SWAPINT32(pdu->sysUpTime);
  SWAPINT32(pdu->unix_secs);
  SWAPINT32(pdu->unix_nsecs);
  SWAPINT32(pdu->flow_sequence);

  for (--i; i >= 0; --i) {
    SWAPINT32(pdu->records[i].dFlows);
    SWAPINT32(pdu->records[i].dPkts);
    SWAPINT32(pdu->records[i].dOctets);
    SWAPINT32(pdu->records[i].First);
    SWAPINT32(pdu->records[i].Last);
    SWAPINT16(pdu->records[i].srcport);
    SWAPINT16(pdu->records[i].dstport);
  }

} /* ftpdu_v8_2_swap */

/*
 * function: ftpdu_v8_3_swap
 *
 * Swap bytes in a V8 agg method 3 PDU.  cur is the current
 * byte order of the PDU
 *
*/
void ftpdu_v8_3_swap(struct ftpdu_v8_3 *pdu, int cur)
{
  int16_t i;

  i = pdu->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  SWAPINT16(pdu->version);
  SWAPINT16(pdu->count);
  SWAPINT32(pdu->sysUpTime);
  SWAPINT32(pdu->unix_secs);
  SWAPINT32(pdu->unix_nsecs);
  SWAPINT32(pdu->flow_sequence);

  for (--i; i >= 0; --i) {
    SWAPINT32(pdu->records[i].dFlows);
    SWAPINT32(pdu->records[i].dPkts);
    SWAPINT32(pdu->records[i].dOctets);
    SWAPINT32(pdu->records[i].First);
    SWAPINT32(pdu->records[i].Last);
    SWAPINT32(pdu->records[i].src_prefix);
    SWAPINT16(pdu->records[i].src_as);
    SWAPINT16(pdu->records[i].input);
  }

} /* ftpdu_v8_3_swap */

/*
 * function: ftpdu_v8_4_swap
 *
 * Swap bytes in a V8 agg method 4 PDU.  cur is the current
 * byte order of the PDU
 *
*/
void ftpdu_v8_4_swap(struct ftpdu_v8_4 *pdu, int cur)
{
  int16_t i;

  i = pdu->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  SWAPINT16(pdu->version);
  SWAPINT16(pdu->count);
  SWAPINT32(pdu->sysUpTime);
  SWAPINT32(pdu->unix_secs);
  SWAPINT32(pdu->unix_nsecs);
  SWAPINT32(pdu->flow_sequence);

  for (--i; i >= 0; --i) {
    SWAPINT32(pdu->records[i].dFlows);
    SWAPINT32(pdu->records[i].dPkts);
    SWAPINT32(pdu->records[i].dOctets);
    SWAPINT32(pdu->records[i].First);
    SWAPINT32(pdu->records[i].Last);
    SWAPINT32(pdu->records[i].dst_prefix);
    SWAPINT16(pdu->records[i].dst_as);
    SWAPINT16(pdu->records[i].output);
  }

} /* ftpdu_v8_4_swap */

/*
 * function: ftpdu_v8_5_swap
 *
 * Swap bytes in a V8 agg method 5 PDU.  cur is the current
 * byte order of the PDU
 *
*/
void ftpdu_v8_5_swap(struct ftpdu_v8_5 *pdu, int cur)
{
  int16_t i;

  i = pdu->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  SWAPINT16(pdu->version);
  SWAPINT16(pdu->count);
  SWAPINT32(pdu->sysUpTime);
  SWAPINT32(pdu->unix_secs);
  SWAPINT32(pdu->unix_nsecs);
  SWAPINT32(pdu->flow_sequence);

  for (--i; i >= 0; --i) {
    SWAPINT32(pdu->records[i].dFlows);
    SWAPINT32(pdu->records[i].dPkts);
    SWAPINT32(pdu->records[i].dOctets);
    SWAPINT32(pdu->records[i].First);
    SWAPINT32(pdu->records[i].Last);
    SWAPINT32(pdu->records[i].src_prefix);
    SWAPINT32(pdu->records[i].dst_prefix);
    SWAPINT16(pdu->records[i].src_as);
    SWAPINT16(pdu->records[i].dst_as);
    SWAPINT16(pdu->records[i].input);
    SWAPINT16(pdu->records[i].output);
  }

} /* ftpdu_v8_5_swap */

/*
 * function: ftpdu_v8_6_swap
 *
 * Swap bytes in a V8 agg method 6 PDU.  cur is the current
 * byte order of the PDU
 *
*/
void ftpdu_v8_6_swap(struct ftpdu_v8_6 *pdu, int cur)
{
  int16_t i;

  i = pdu->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  SWAPINT16(pdu->version);
  SWAPINT16(pdu->count);
  SWAPINT32(pdu->sysUpTime);
  SWAPINT32(pdu->unix_secs);
  SWAPINT32(pdu->unix_nsecs);
  SWAPINT32(pdu->flow_sequence);

  for (--i; i >= 0; --i) {
    SWAPINT32(pdu->records[i].dstaddr);
    SWAPINT32(pdu->records[i].dPkts);
    SWAPINT32(pdu->records[i].dOctets);
    SWAPINT32(pdu->records[i].First);
    SWAPINT32(pdu->records[i].Last);
    SWAPINT16(pdu->records[i].output);
    SWAPINT32(pdu->records[i].extra_pkts);
    SWAPINT32(pdu->records[i].router_sc);
  }

} /* ftpdu_v8_6_swap */


/*
 * function: ftpdu_v8_7_swap
 *
 * Swap bytes in a V8 agg method 7 PDU.  cur is the current
 * byte order of the PDU
 *
*/
void ftpdu_v8_7_swap(struct ftpdu_v8_7 *pdu, int cur)
{
  int16_t i;

  i = pdu->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  SWAPINT16(pdu->version);
  SWAPINT16(pdu->count);
  SWAPINT32(pdu->sysUpTime);
  SWAPINT32(pdu->unix_secs);
  SWAPINT32(pdu->unix_nsecs);
  SWAPINT32(pdu->flow_sequence);

  for (--i; i >= 0; --i) {
    SWAPINT32(pdu->records[i].dstaddr);
    SWAPINT32(pdu->records[i].srcaddr);
    SWAPINT32(pdu->records[i].dPkts);
    SWAPINT32(pdu->records[i].dOctets);
    SWAPINT32(pdu->records[i].First);
    SWAPINT32(pdu->records[i].Last);
    SWAPINT16(pdu->records[i].input);
    SWAPINT16(pdu->records[i].output);
    SWAPINT32(pdu->records[i].extra_pkts);
    SWAPINT32(pdu->records[i].router_sc);
  }

} /* ftpdu_v8_7_swap */

/*
 * function: ftpdu_v8_8_swap
 *
 * Swap bytes in a V8 agg method 7 PDU.  cur is the current
 * byte order of the PDU
 *
*/
void ftpdu_v8_8_swap(struct ftpdu_v8_8 *pdu, int cur)
{
  int16_t i;

  i = pdu->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  SWAPINT16(pdu->version);
  SWAPINT16(pdu->count);
  SWAPINT32(pdu->sysUpTime);
  SWAPINT32(pdu->unix_secs);
  SWAPINT32(pdu->unix_nsecs);
  SWAPINT32(pdu->flow_sequence);

  for (--i; i >= 0; --i) {
    SWAPINT32(pdu->records[i].dstaddr);
    SWAPINT32(pdu->records[i].srcaddr);
    SWAPINT16(pdu->records[i].dstport);
    SWAPINT16(pdu->records[i].srcport);
    SWAPINT32(pdu->records[i].dPkts);
    SWAPINT32(pdu->records[i].dOctets);
    SWAPINT32(pdu->records[i].First);
    SWAPINT32(pdu->records[i].Last);
    SWAPINT16(pdu->records[i].input);
    SWAPINT16(pdu->records[i].output);
    SWAPINT32(pdu->records[i].extra_pkts);
    SWAPINT32(pdu->records[i].router_sc);
  }

} /* ftpdu_v8_8_swap */

/*
 * function: ftpdu_v8_9_swap
 *
 * Swap bytes in a V8 agg method 9 PDU.  cur is the current
 * byte order of the PDU
 *
*/
void ftpdu_v8_9_swap(struct ftpdu_v8_9 *pdu, int cur)
{
  int16_t i;

  i = pdu->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  SWAPINT16(pdu->version);
  SWAPINT16(pdu->count);
  SWAPINT32(pdu->sysUpTime);
  SWAPINT32(pdu->unix_secs);
  SWAPINT32(pdu->unix_nsecs);
  SWAPINT32(pdu->flow_sequence);

  for (--i; i >= 0; --i) {
    SWAPINT32(pdu->records[i].dFlows);
    SWAPINT32(pdu->records[i].dPkts);
    SWAPINT32(pdu->records[i].dOctets);
    SWAPINT32(pdu->records[i].First);
    SWAPINT32(pdu->records[i].Last);
    SWAPINT16(pdu->records[i].src_as);
    SWAPINT16(pdu->records[i].dst_as);
    SWAPINT16(pdu->records[i].input);
    SWAPINT16(pdu->records[i].output);
  }

} /* ftpdu_v8_9_swap */

/*
 * function: ftpdu_v8_10_swap
 *
 * Swap bytes in a V8 agg method 10 PDU.  cur is the current
 * byte order of the PDU
 *
*/
void ftpdu_v8_10_swap(struct ftpdu_v8_10 *pdu, int cur)
{
  int16_t i;

  i = pdu->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  SWAPINT16(pdu->version);
  SWAPINT16(pdu->count);
  SWAPINT32(pdu->sysUpTime);
  SWAPINT32(pdu->unix_secs);
  SWAPINT32(pdu->unix_nsecs);
  SWAPINT32(pdu->flow_sequence);

  for (--i; i >= 0; --i) {
    SWAPINT32(pdu->records[i].dFlows);
    SWAPINT32(pdu->records[i].dPkts);
    SWAPINT32(pdu->records[i].dOctets);
    SWAPINT32(pdu->records[i].First);
    SWAPINT32(pdu->records[i].Last);
    SWAPINT32(pdu->records[i].srcport);
    SWAPINT32(pdu->records[i].dstport);
    SWAPINT16(pdu->records[i].input);
    SWAPINT16(pdu->records[i].output);
  }

} /* ftpdu_v8_10_swap */

/*
 * function: ftpdu_v8_11_swap
 *
 * Swap bytes in a V8 agg method 11 PDU.  cur is the current
 * byte order of the PDU
 *
*/
void ftpdu_v8_11_swap(struct ftpdu_v8_11 *pdu, int cur)
{
  int16_t i;

  i = pdu->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  SWAPINT16(pdu->version);
  SWAPINT16(pdu->count);
  SWAPINT32(pdu->sysUpTime);
  SWAPINT32(pdu->unix_secs);
  SWAPINT32(pdu->unix_nsecs);
  SWAPINT32(pdu->flow_sequence);

  for (--i; i >= 0; --i) {
    SWAPINT32(pdu->records[i].dFlows);
    SWAPINT32(pdu->records[i].dPkts);
    SWAPINT32(pdu->records[i].dOctets);
    SWAPINT32(pdu->records[i].First);
    SWAPINT32(pdu->records[i].Last);
    SWAPINT32(pdu->records[i].src_prefix);
    SWAPINT16(pdu->records[i].src_as);
    SWAPINT16(pdu->records[i].input);
  }

} /* ftpdu_v8_11_swap */

/*
 * function: ftpdu_v8_12_swap
 *
 * Swap bytes in a V8 agg method 12 PDU.  cur is the current
 * byte order of the PDU
 *
*/
void ftpdu_v8_12_swap(struct ftpdu_v8_12 *pdu, int cur)
{
  int16_t i;

  i = pdu->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  SWAPINT16(pdu->version);
  SWAPINT16(pdu->count);
  SWAPINT32(pdu->sysUpTime);
  SWAPINT32(pdu->unix_secs);
  SWAPINT32(pdu->unix_nsecs);
  SWAPINT32(pdu->flow_sequence);

  for (--i; i >= 0; --i) {
    SWAPINT32(pdu->records[i].dFlows);
    SWAPINT32(pdu->records[i].dPkts);
    SWAPINT32(pdu->records[i].dOctets);
    SWAPINT32(pdu->records[i].First);
    SWAPINT32(pdu->records[i].Last);
    SWAPINT32(pdu->records[i].dst_prefix);
    SWAPINT16(pdu->records[i].dst_as);
    SWAPINT16(pdu->records[i].output);
  }

} /* ftpdu_v8_12_swap */

/*
 * function: ftpdu_v8_13_swap
 *
 * Swap bytes in a V8 agg method 13 PDU.  cur is the current
 * byte order of the PDU
 *
*/
void ftpdu_v8_13_swap(struct ftpdu_v8_13 *pdu, int cur)
{
  int16_t i;

  i = pdu->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  SWAPINT16(pdu->version);
  SWAPINT16(pdu->count);
  SWAPINT32(pdu->sysUpTime);
  SWAPINT32(pdu->unix_secs);
  SWAPINT32(pdu->unix_nsecs);
  SWAPINT32(pdu->flow_sequence);

  for (--i; i >= 0; --i) {
    SWAPINT32(pdu->records[i].dFlows);
    SWAPINT32(pdu->records[i].dPkts);
    SWAPINT32(pdu->records[i].dOctets);
    SWAPINT32(pdu->records[i].First);
    SWAPINT32(pdu->records[i].Last);
    SWAPINT32(pdu->records[i].src_prefix);
    SWAPINT32(pdu->records[i].dst_prefix);
    SWAPINT16(pdu->records[i].src_as);
    SWAPINT16(pdu->records[i].dst_as);
    SWAPINT16(pdu->records[i].input);
    SWAPINT16(pdu->records[i].output);
  }

} /* ftpdu_v8_13_swap */

/*
 * function: ftpdu_v8_14_swap
 *
 * Swap bytes in a V8 agg method 14 PDU.  cur is the current
 * byte order of the PDU
 *
*/
void ftpdu_v8_14_swap(struct ftpdu_v8_14 *pdu, int cur)
{
  int16_t i;

  i = pdu->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  if (cur == BIG_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
  if (cur == LITTLE_ENDIAN)
    SWAPINT16(i);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  SWAPINT16(pdu->version);
  SWAPINT16(pdu->count);
  SWAPINT32(pdu->sysUpTime);
  SWAPINT32(pdu->unix_secs);
  SWAPINT32(pdu->unix_nsecs);
  SWAPINT32(pdu->flow_sequence);

  for (--i; i >= 0; --i) {
    SWAPINT32(pdu->records[i].dFlows);
    SWAPINT32(pdu->records[i].dPkts);
    SWAPINT32(pdu->records[i].dOctets);
    SWAPINT32(pdu->records[i].First);
    SWAPINT32(pdu->records[i].Last);
    SWAPINT32(pdu->records[i].src_prefix);
    SWAPINT32(pdu->records[i].dst_prefix);
    SWAPINT16(pdu->records[i].srcport);
    SWAPINT16(pdu->records[i].dstport);
    SWAPINT16(pdu->records[i].input);
    SWAPINT16(pdu->records[i].output);
  }

} /* ftpdu_v8_14_swap */


/*
 * function: fts3rec_swap_v1
 *
 * Swap bytes in a fts3rec_v1 struct
 *
*/
void fts3rec_swap_v1(struct fts3rec_v1 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->exaddr);
  SWAPINT32(rec->srcaddr);
  SWAPINT32(rec->dstaddr);
  SWAPINT32(rec->nexthop);
  SWAPINT16(rec->input);
  SWAPINT16(rec->output);
  
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);

  SWAPINT16(rec->srcport);
  SWAPINT16(rec->dstport);
}

/*
 * function: fts3rec_swap_v5
 *
 * Swap bytes in a fts3rec_v5 struct
 *
*/
void fts3rec_swap_v5(struct fts3rec_v5 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->exaddr);
  SWAPINT32(rec->srcaddr);
  SWAPINT32(rec->dstaddr);
  SWAPINT32(rec->nexthop);
  SWAPINT16(rec->input);
  SWAPINT16(rec->output);
  
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);

  SWAPINT16(rec->srcport);
  SWAPINT16(rec->dstport);

  SWAPINT16(rec->src_as);
  SWAPINT16(rec->dst_as);
}

/*
 * function: fts3rec_swap_v6
 *
 * Swap bytes in a fts3rec_v6 struct
 *
*/
void fts3rec_swap_v6(struct fts3rec_v6 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->exaddr);
  SWAPINT32(rec->srcaddr);
  SWAPINT32(rec->dstaddr);
  SWAPINT32(rec->nexthop);
  SWAPINT16(rec->input);
  SWAPINT16(rec->output);
  
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);

  SWAPINT16(rec->srcport);
  SWAPINT16(rec->dstport);

  SWAPINT16(rec->src_as);
  SWAPINT16(rec->dst_as);

  SWAPINT32(rec->peer_nexthop);
}

/*
 * function: fts3rec_swap_v7
 *
 * Swap bytes in a fts3rec_v7 struct
 *
*/
void fts3rec_swap_v7(struct fts3rec_v7 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->exaddr);
  SWAPINT32(rec->srcaddr);
  SWAPINT32(rec->dstaddr);
  SWAPINT32(rec->nexthop);
  SWAPINT16(rec->input);
  SWAPINT16(rec->output);
  
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);

  SWAPINT16(rec->srcport);
  SWAPINT16(rec->dstport);

  SWAPINT16(rec->src_as);
  SWAPINT16(rec->dst_as);

  SWAPINT32(rec->router_sc);
}

/*
 * function: fts3rec_swap_v8_1
 *
 * Swap bytes in a fts3rec_v8_1 struct
 *
*/
void fts3rec_swap_v8_1(struct fts3rec_v8_1 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->exaddr);
  SWAPINT32(rec->dFlows);
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);
  SWAPINT16(rec->src_as);
  SWAPINT16(rec->dst_as);
  SWAPINT16(rec->input);
  SWAPINT16(rec->output);
}

/*
 * function: fts3rec_swap_v8_2
 *
 * Swap bytes in a fts3rec_v8_2 struct
 *
*/
void fts3rec_swap_v8_2(struct fts3rec_v8_2 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->exaddr);
  SWAPINT32(rec->dFlows);
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);
  SWAPINT16(rec->srcport);
  SWAPINT16(rec->dstport);
}

/*
 * function: fts3rec_swap_v8_3
 *
 * Swap bytes in a fts3rec_v8_3 struct
 *
*/
void fts3rec_swap_v8_3(struct fts3rec_v8_3 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->exaddr);
  SWAPINT32(rec->dFlows);
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);
  SWAPINT32(rec->srcaddr);
  SWAPINT16(rec->src_as);
  SWAPINT16(rec->input);
}

/*
 * function: fts3rec_swap_v8_4
 *
 * Swap bytes in a fts3rec_v8_4 struct
 *
*/
void fts3rec_swap_v8_4(struct fts3rec_v8_4 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->exaddr);
  SWAPINT32(rec->dFlows);
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);
  SWAPINT32(rec->dstaddr);
  SWAPINT16(rec->dst_as);
  SWAPINT16(rec->output);
}

/*
 * function: fts3rec_swap_v8_5
 *
 * Swap bytes in a fts3rec_v8_5 struct
 *
*/
void fts3rec_swap_v8_5(struct fts3rec_v8_5 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->exaddr);
  SWAPINT32(rec->dFlows);
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);
  SWAPINT32(rec->srcaddr);
  SWAPINT32(rec->dstaddr);
  SWAPINT16(rec->src_as);
  SWAPINT16(rec->dst_as);
  SWAPINT16(rec->input);
  SWAPINT16(rec->output);
}

/*
 * function: fts3rec_swap_v8_6
 *
 * Swap bytes in a fts3rec_v8_6 struct
 *
*/
void fts3rec_swap_v8_6(struct fts3rec_v8_6 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->exaddr);
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);
  SWAPINT32(rec->dstaddr);
  SWAPINT32(rec->extra_pkts);
  SWAPINT32(rec->router_sc);
  SWAPINT16(rec->output);
}

/*
 * function: fts3rec_swap_v8_7
 *
 * Swap bytes in a fts3rec_v8_7 struct
 *
*/
void fts3rec_swap_v8_7(struct fts3rec_v8_7 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->exaddr);
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);
  SWAPINT32(rec->dstaddr);
  SWAPINT32(rec->srcaddr);
  SWAPINT32(rec->extra_pkts);
  SWAPINT32(rec->router_sc);
  SWAPINT16(rec->input);
  SWAPINT16(rec->output);
}

/*
 * function: fts3rec_swap_v8_8
 *
 * Swap bytes in a fts3rec_v8_8 struct
 *
*/
void fts3rec_swap_v8_8(struct fts3rec_v8_8 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->exaddr);
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);
  SWAPINT32(rec->dstaddr);
  SWAPINT32(rec->srcaddr);
  SWAPINT32(rec->extra_pkts);
  SWAPINT32(rec->router_sc);
  SWAPINT16(rec->srcport);
  SWAPINT16(rec->dstport);
  SWAPINT16(rec->input);
  SWAPINT16(rec->output);
}

/*
 * function: fts3rec_swap_v8_9
 *
 * Swap bytes in a fts3rec_v8_9 struct
 *
*/
void fts3rec_swap_v8_9(struct fts3rec_v8_9 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->exaddr);
  SWAPINT32(rec->dFlows);
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);
  SWAPINT16(rec->src_as);
  SWAPINT16(rec->dst_as);
  SWAPINT16(rec->input);
  SWAPINT16(rec->output);
}

/*
 * function: fts3rec_swap_v8_10
 *
 * Swap bytes in a fts3rec_v8_10 struct
 *
*/
void fts3rec_swap_v8_10(struct fts3rec_v8_10 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->exaddr);
  SWAPINT32(rec->dFlows);
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);
  SWAPINT16(rec->srcport);
  SWAPINT16(rec->dstport);
  SWAPINT16(rec->input);
  SWAPINT16(rec->output);
}

/*
 * function: fts3rec_swap_v8_11
 *
 * Swap bytes in a fts3rec_v8_11 struct
 *
*/
void fts3rec_swap_v8_11(struct fts3rec_v8_11 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->exaddr);
  SWAPINT32(rec->dFlows);
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);
  SWAPINT32(rec->srcaddr);
  SWAPINT16(rec->src_as);
  SWAPINT16(rec->input);
}

/*
 * function: fts3rec_swap_v8_12
 *
 * Swap bytes in a fts3rec_v8_12 struct
 *
*/
void fts3rec_swap_v8_12(struct fts3rec_v8_12 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->exaddr);
  SWAPINT32(rec->dFlows);
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);
  SWAPINT32(rec->dstaddr);
  SWAPINT16(rec->output);
}

/*
 * function: fts3rec_swap_v8_13
 *
 * Swap bytes in a fts3rec_v8_13 struct
 *
*/
void fts3rec_swap_v8_13(struct fts3rec_v8_13 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->exaddr);
  SWAPINT32(rec->dFlows);
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);
  SWAPINT32(rec->srcaddr);
  SWAPINT32(rec->dstaddr);
  SWAPINT16(rec->src_as);
  SWAPINT16(rec->dst_as);
  SWAPINT16(rec->input);
  SWAPINT16(rec->output);
}

/*
 * function: fts3rec_swap_v8_14
 *
 * Swap bytes in a fts3rec_v8_14 struct
 *
*/
void fts3rec_swap_v8_14(struct fts3rec_v8_14 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->exaddr);
  SWAPINT32(rec->dFlows);
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);
  SWAPINT32(rec->srcaddr);
  SWAPINT32(rec->dstaddr);
  SWAPINT16(rec->srcport);
  SWAPINT16(rec->dstport);
  SWAPINT16(rec->input);
  SWAPINT16(rec->output);
}


/*
 * function: fts3rec_swap_v1005
 *
 * Swap bytes in a fts3rec_v1005 struct
 *
*/
void fts3rec_swap_v1005(struct fts3rec_v1005 *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_nsecs);
  SWAPINT32(rec->sysUpTime);
  SWAPINT32(rec->srcaddr);
  SWAPINT32(rec->dstaddr);
  SWAPINT32(rec->nexthop);
  SWAPINT16(rec->input);
  SWAPINT16(rec->output);
  
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);

  SWAPINT16(rec->srcport);
  SWAPINT16(rec->dstport);

  SWAPINT16(rec->src_as);
  SWAPINT16(rec->dst_as);

  SWAPINT16(rec->src_tag);
  SWAPINT16(rec->dst_tag);

}

/*
 * function: fts3rec_swap_compat
 *
 * Swap bytes in a fts3rec_compat struct
 *
*/
void fts1rec_swap_compat(struct fts1rec_compat *rec)
{
  SWAPINT32(rec->unix_secs);
  SWAPINT32(rec->unix_msecs);
  SWAPINT32(rec->srcaddr);
  SWAPINT32(rec->dstaddr);
  SWAPINT32(rec->nexthop);
  SWAPINT16(rec->input);
  SWAPINT16(rec->output);
  
  SWAPINT32(rec->dPkts);
  SWAPINT32(rec->dOctets);
  SWAPINT32(rec->First);
  SWAPINT32(rec->Last);

  SWAPINT16(rec->srcport);
  SWAPINT16(rec->dstport);
  SWAPINT16(rec->pad);

  SWAPINT16(rec->src_as);
  SWAPINT16(rec->dst_as);
  SWAPINT16(rec->drops);
}

