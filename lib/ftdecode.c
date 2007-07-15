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
 *      $Id: ftdecode.c,v 1.25 2005/05/10 15:45:47 maf Exp $
 */

#include "ftconfig.h"
#include "ftlib.h"

#include <stddef.h>
#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif

/*
 * function ftpdu_check_seq
 *
 * Check sequence number in decoded PDU
 *
 * ftpdu_verify must be called first 
 *
 * Returns  0  - sequence number matched expected
 *          -1 - sequence number did not match expected
 *               seq_rcv, seq_exp updated
*/
int ftpdu_check_seq(struct ftpdu *ftpdu, struct ftseq *ftseq)
{
  struct ftpdu_header *ph;
  int ret;
  u_int seq_index;

  /* version 1 exports do not have sequence numbers */
  if (ftpdu->ftv.d_version == 1)
    return 0;

  ph = (struct ftpdu_header*)&ftpdu->buf;

#if BYTE_ORDER == LITTLE_ENDIAN
  SWAPINT32(ph->flow_sequence);
  SWAPINT16(ph->count);
#endif /* LITTLE_ENDIAN */

  seq_index = ph->engine_id<<8 | ph->engine_type;

  /* first time always okay */
  if (!ftseq->seq_set[seq_index]) {
    ftseq->seq_set[seq_index] = 1;
    ftseq->seq[seq_index] = ph->flow_sequence + ph->count;
    ret = 0;
  } else {
    /* if cur == expecting then okay, else reset */
    if (ph->flow_sequence == ftseq->seq[seq_index]) {
      ftseq->seq[seq_index] += ph->count;
      ret = 0;
    } else {
      ftseq->seq_rcv = ph->flow_sequence;
      ftseq->seq_exp = ftseq->seq[seq_index];
      ftseq->seq[seq_index] = ph->flow_sequence + ph->count;

      /* calculate lost sequence numbers, account for wraparound at 2^32 */
      if (ftseq->seq_rcv > ftseq->seq_exp)
        ftseq->seq_lost = ftseq->seq_rcv - ftseq->seq_exp;
      else
        ftseq->seq_lost = (0xFFFFFFFF - ftseq->seq_exp) + ftseq->seq_rcv;
      ret = -1;
    }
  }

#if BYTE_ORDER == LITTLE_ENDIAN
  SWAPINT32(ph->flow_sequence);
  SWAPINT16(ph->count);
#endif /* LITTLE_ENDIAN */

  return ret;

} /* ftpdu_check_seq */

/*
 * function: ftpdu_verify
 *
 * verify PDU is valid
 *   count is not too high
 *   version is valid
 *   sizeof structure is valid
 *
 * iff the verification checks pass then ftpdu->ftver is initialized to the
 * pdu version * and ftpdu->decodef() is initialized to the decode function
 *
 * pdu must be in network byte order and is returned in network byte order
 *
*/
int ftpdu_verify(struct ftpdu *ftpdu)
{
  struct ftpdu_header *ph;
  int size, ret;

  ret = -1;

  /* enough bytes to decode the count and version? */
  if (ftpdu->bused < 4)
    goto ftpdu_verify_out_quick;

  ph = (struct ftpdu_header*)&ftpdu->buf;

#if BYTE_ORDER == LITTLE_ENDIAN
  SWAPINT16(ph->version);
  SWAPINT16(ph->count);
#endif /* LITTLE_ENDIAN */

  bzero(&ftpdu->ftv, sizeof (struct ftver));
  ftpdu->ftv.s_version = FT_IO_SVERSION;

  switch (ph->version) {

    case 1:

      /* max PDU's in record */
      if (ph->count > FT_PDU_V1_MAXFLOWS)
        goto ftpdu_verify_out;

      size = offsetof(struct ftpdu_v1, records) +
             ph->count * sizeof (struct ftrec_v1);

      /* PDU received size == PDU expected size? */
      if (size != ftpdu->bused)
        goto ftpdu_verify_out;

      ftpdu->ftv.d_version = 1;
      ftpdu->decodef = fts3rec_pdu_v1_decode;

      break;

    case 5:

      /* max PDU's in record */
      if (ph->count > FT_PDU_V5_MAXFLOWS)
        goto ftpdu_verify_out;

      size = offsetof(struct ftpdu_v5, records) +
             ph->count * sizeof (struct ftrec_v5);

      /* PDU received size == PDU expected size? */
      if (size != ftpdu->bused)
        goto ftpdu_verify_out;

      ftpdu->ftv.d_version = 5;
      ftpdu->decodef = fts3rec_pdu_v5_decode;

      break;

    case 6:

      /* max PDU's in record */
      if (ph->count > FT_PDU_V6_MAXFLOWS)
        goto ftpdu_verify_out;

      size = offsetof(struct ftpdu_v6, records) +
             ph->count * sizeof (struct ftrec_v6);

      /* PDU received size == PDU expected size? */
      if (size != ftpdu->bused)
        goto ftpdu_verify_out;

      ftpdu->ftv.d_version = 6;
      ftpdu->decodef = fts3rec_pdu_v6_decode;

      break;

    case 7:

      /* max PDU's in record */
      if (ph->count > FT_PDU_V7_MAXFLOWS)
        goto ftpdu_verify_out;

      size = offsetof(struct ftpdu_v7, records) +
             ph->count * sizeof (struct ftrec_v7);

      /* PDU received size == PDU expected size? */
      if (size != ftpdu->bused)
        goto ftpdu_verify_out;

      ftpdu->ftv.d_version = 7;
      ftpdu->decodef = fts3rec_pdu_v7_decode;

      break;

    case 8:

      /* enough bytes to decode the aggregation method and version? */
      if (ftpdu->bused < (offsetof(struct ftpdu_v8_gen, agg_version) + 
                        sizeof ((struct ftpdu_v8_gen *)0)->agg_version))
        goto ftpdu_verify_out;

      ftpdu->ftv.agg_method = ((struct ftpdu_v8_gen *)&ftpdu->buf)->aggregation;
      ftpdu->ftv.agg_version =
        ((struct ftpdu_v8_gen *)&ftpdu->buf)->agg_version;

      /* XXX Juniper hack */
      if (ftpdu->ftv.agg_version == 0)
        ftpdu->ftv.agg_version = 2;

      /* can only decode version 2 aggregation method packets */
      if (ftpdu->ftv.agg_version != 2)
        goto ftpdu_verify_out;

      switch (ftpdu->ftv.agg_method) {

        case 1:

          /* max PDU's in record */
          if (ph->count > FT_PDU_V8_1_MAXFLOWS)
            goto ftpdu_verify_out;

          size = offsetof(struct ftpdu_v8_1, records) +
                 ph->count * sizeof (struct ftrec_v8_1);

          /* PDU received size == PDU expected size? */
          if (size != ftpdu->bused)
            goto ftpdu_verify_out;

          ftpdu->ftv.d_version = 8;
          ftpdu->ftv.agg_method = 1;
          ftpdu->decodef = fts3rec_pdu_v8_1_decode;

          break;

        case 2:

          /* max PDU's in record */
          if (ph->count > FT_PDU_V8_2_MAXFLOWS)
            goto ftpdu_verify_out;

          size = offsetof(struct ftpdu_v8_2, records) +
                 ph->count * sizeof (struct ftrec_v8_2);

          /* PDU received size == PDU expected size? */
          if (size != ftpdu->bused)
            goto ftpdu_verify_out;

          ftpdu->ftv.d_version = 8;
          ftpdu->ftv.agg_method = 2;
          ftpdu->decodef = fts3rec_pdu_v8_2_decode;

          break;

        case 3:

          /* max PDU's in record */
          if (ph->count > FT_PDU_V8_3_MAXFLOWS)
            goto ftpdu_verify_out;

          size = offsetof(struct ftpdu_v8_3, records) +
                 ph->count * sizeof (struct ftrec_v8_3);

          /* PDU received size == PDU expected size? */
          if (size != ftpdu->bused)
            goto ftpdu_verify_out;

          ftpdu->ftv.d_version = 8;
          ftpdu->ftv.agg_method = 3;
          ftpdu->decodef = fts3rec_pdu_v8_3_decode;

          break;

        case 4:

          /* max PDU's in record */
          if (ph->count > FT_PDU_V8_4_MAXFLOWS)
            goto ftpdu_verify_out;

          size = offsetof(struct ftpdu_v8_4, records) +
                 ph->count * sizeof (struct ftrec_v8_4);

          /* PDU received size == PDU expected size? */
          if (size != ftpdu->bused)
            goto ftpdu_verify_out;

          ftpdu->ftv.d_version = 8;
          ftpdu->ftv.agg_method = 4;
          ftpdu->decodef = fts3rec_pdu_v8_4_decode;

          break;

        case 5:

          /* max PDU's in record */
          if (ph->count > FT_PDU_V8_5_MAXFLOWS)
            goto ftpdu_verify_out;

          size = offsetof(struct ftpdu_v8_5, records) +
                 ph->count * sizeof (struct ftrec_v8_5);

          /* PDU received size == PDU expected size? */
          if (size != ftpdu->bused)
            goto ftpdu_verify_out;

          ftpdu->ftv.d_version = 8;
          ftpdu->ftv.agg_method = 5;
          ftpdu->decodef = fts3rec_pdu_v8_5_decode;

          break;

        case 6:

          /* max PDU's in record */
          if (ph->count > FT_PDU_V8_6_MAXFLOWS)
            goto ftpdu_verify_out;

          size = offsetof(struct ftpdu_v8_6, records) +
                 ph->count * sizeof (struct ftrec_v8_6);

          /* PDU received size == PDU expected size? */
          /* Catalyst pads exports, so use > instead of != */
          if (size > ftpdu->bused)
            goto ftpdu_verify_out;

          ftpdu->ftv.d_version = 8;
          ftpdu->ftv.agg_method = 6;
          ftpdu->decodef = fts3rec_pdu_v8_6_decode;

          break;


        case 7:

          /* max PDU's in record */
          if (ph->count > FT_PDU_V8_7_MAXFLOWS)
            goto ftpdu_verify_out;

          size = offsetof(struct ftpdu_v8_7, records) +
                 ph->count * sizeof (struct ftrec_v8_7);

          /* PDU received size == PDU expected size? */
          /* Catalyst pads exports, so use > instead of != */
          if (size > ftpdu->bused)
            goto ftpdu_verify_out;

          ftpdu->ftv.d_version = 8;
          ftpdu->ftv.agg_method = 7;
          ftpdu->decodef = fts3rec_pdu_v8_7_decode;

          break;


        case 8:

          /* max PDU's in record */
          if (ph->count > FT_PDU_V8_8_MAXFLOWS)
            goto ftpdu_verify_out;

          size = offsetof(struct ftpdu_v8_8, records) +
                 ph->count * sizeof (struct ftrec_v8_8);

          /* PDU received size == PDU expected size? */
          /* Catalyst pads exports, so use > instead of != */
          if (size > ftpdu->bused)
            goto ftpdu_verify_out;

          ftpdu->ftv.d_version = 8;
          ftpdu->ftv.agg_method = 8;
          ftpdu->decodef = fts3rec_pdu_v8_8_decode;

          break;


        case 9:

          /* max PDU's in record */
          if (ph->count > FT_PDU_V8_9_MAXFLOWS)
            goto ftpdu_verify_out;

          size = offsetof(struct ftpdu_v8_9, records) +
                 ph->count * sizeof (struct ftrec_v8_9);

          /* PDU received size == PDU expected size? */
          if (size != ftpdu->bused)
            goto ftpdu_verify_out;

          ftpdu->ftv.d_version = 8;
          ftpdu->ftv.agg_method = 9;
          ftpdu->decodef = fts3rec_pdu_v8_9_decode;

          break;


        case 10:

          /* max PDU's in record */
          if (ph->count > FT_PDU_V8_10_MAXFLOWS)
            goto ftpdu_verify_out;

          size = offsetof(struct ftpdu_v8_10, records) +
                 ph->count * sizeof (struct ftrec_v8_10);

          /* PDU received size == PDU expected size? */
          if (size != ftpdu->bused)
            goto ftpdu_verify_out;

          ftpdu->ftv.d_version = 8;
          ftpdu->ftv.agg_method = 10;
          ftpdu->decodef = fts3rec_pdu_v8_10_decode;

          break;


        case 11:

          /* max PDU's in record */
          if (ph->count > FT_PDU_V8_11_MAXFLOWS)
            goto ftpdu_verify_out;

          size = offsetof(struct ftpdu_v8_11, records) +
                 ph->count * sizeof (struct ftrec_v8_11);

          /* PDU received size == PDU expected size? */
          if (size != ftpdu->bused)
            goto ftpdu_verify_out;

          ftpdu->ftv.d_version = 8;
          ftpdu->ftv.agg_method = 11;
          ftpdu->decodef = fts3rec_pdu_v8_11_decode;

          break;


        case 12:

          /* max PDU's in record */
          if (ph->count > FT_PDU_V8_12_MAXFLOWS)
            goto ftpdu_verify_out;

          size = offsetof(struct ftpdu_v8_12, records) +
                 ph->count * sizeof (struct ftrec_v8_12);

          /* PDU received size == PDU expected size? */
          if (size != ftpdu->bused)
            goto ftpdu_verify_out;

          ftpdu->ftv.d_version = 8;
          ftpdu->ftv.agg_method = 12;
          ftpdu->decodef = fts3rec_pdu_v8_12_decode;

          break;


        case 13:

          /* max PDU's in record */
          if (ph->count > FT_PDU_V8_13_MAXFLOWS)
            goto ftpdu_verify_out;

          size = offsetof(struct ftpdu_v8_13, records) +
                 ph->count * sizeof (struct ftrec_v8_13);

          /* PDU received size == PDU expected size? */
          if (size != ftpdu->bused)
            goto ftpdu_verify_out;

          ftpdu->ftv.d_version = 8;
          ftpdu->ftv.agg_method = 13;
          ftpdu->decodef = fts3rec_pdu_v8_13_decode;

          break;


        case 14:

          /* max PDU's in record */
          if (ph->count > FT_PDU_V8_14_MAXFLOWS)
            goto ftpdu_verify_out;

          size = offsetof(struct ftpdu_v8_14, records) +
                 ph->count * sizeof (struct ftrec_v8_14);

          /* PDU received size == PDU expected size? */
          if (size != ftpdu->bused)
            goto ftpdu_verify_out;

          ftpdu->ftv.d_version = 8;
          ftpdu->ftv.agg_method = 14;
          ftpdu->decodef = fts3rec_pdu_v8_14_decode;

          break;


        default:
          goto ftpdu_verify_out;

      } /* switch ph->agg_method */

      break; /* 8 */

      default:
          goto ftpdu_verify_out;

  } /* switch ph->version */

  ret = 0;

ftpdu_verify_out:

#if BYTE_ORDER == LITTLE_ENDIAN
  SWAPINT16(ph->version);
  SWAPINT16(ph->count);
#endif /* LITTLE_ENDIAN */

ftpdu_verify_out_quick:

  return ret;

}

/*
 * function: fts3rec_pdu_decode
 *
 * pdu must be in network byte order.  Caller must initialize
 * ftpdu->ftd.byte_order and ftpdu->ftd.as_sub
 *
 * stream records are returned in the byte order defined by
 * ftpdu->ftd.byte_order
 *
 * AS 0 is substituted with ftpdu->ftd.as_sub
 * 
 * ftpdu_verify() must be called first to ensure the packet will
 * not overrun buffers and to initialize the decode jump table
 *
 * returns: # of stream records decoded.  PDU is no longer valid
 * after calling (bytes may be swapped)
*/
int fts3rec_pdu_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;

  n = -1;

  bzero(&ftpdu->ftd.buf, FT_IO_MAXDECODE);

  /* take advantage that all pdu's have a common header. */

  ph = (struct ftpdu_header*)&ftpdu->buf;

/*
 * If this is a LITTLE_ENDIAN architecture ph->version and ph->count
 * need to be swapped before being used.
 *
 * ftpdu->ftd->exporter_ip and ftpdu->ftd->as_sub are in LITTLE_ENDIAN, the
 * rest of the PDU is BIG_ENDIAN.  Flip these to BIG_ENDIAN to make the
 * conversions below easier (everything in the PDU is BIG)
 */

#if BYTE_ORDER == LITTLE_ENDIAN
  SWAPINT16(ph->version);
  SWAPINT16(ph->count);

  SWAPINT16(ftpdu->ftd.as_sub);
  SWAPINT32(ftpdu->ftd.exporter_ip);
#endif /* LITTLE_ENDIAN */

  ftpdu->ftd.count = ph->count;

  /* decode it */
  n = ftpdu->decodef(ftpdu);

  /* restore ftd */
#if BYTE_ORDER == LITTLE_ENDIAN
  SWAPINT16(ftpdu->ftd.as_sub);
  SWAPINT32(ftpdu->ftd.exporter_ip);
#endif /* LITTLE_ENDIAN */

  return n;

} /* fts3rec_pdu_decode */

/*
 * function: fts3rec_pdu_v1_decode
 *
 * subfunction to fts3rec_pdu_decode
 *
 * returns: # of stream records decoded
*/
int fts3rec_pdu_v1_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;
  struct ftpdu_v1 *pdu_v1;
  struct fts3rec_v1 *rec_v1;

  ftpdu->ftd.rec_size = sizeof (struct fts3rec_v1);
  pdu_v1 = (struct ftpdu_v1*)&ftpdu->buf;
  ph = (struct ftpdu_header*)&ftpdu->buf;

  /* preswap */
  if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(ph->sysUpTime);
    SWAPINT32(ph->unix_secs);
    SWAPINT32(ph->unix_nsecs);
  }

  for (n = 0; n < ftpdu->ftd.count; ++n) {

    rec_v1 = (struct fts3rec_v1*) (ftpdu->ftd.buf + (n*ftpdu->ftd.rec_size));

    rec_v1->unix_nsecs = ph->unix_nsecs;
    rec_v1->unix_secs = ph->unix_secs;
    rec_v1->sysUpTime = ph->sysUpTime;

    rec_v1->srcaddr = pdu_v1->records[n].srcaddr;
    rec_v1->dstaddr = pdu_v1->records[n].dstaddr;
    rec_v1->nexthop = pdu_v1->records[n].nexthop;
    rec_v1->input = pdu_v1->records[n].input;
    rec_v1->output = pdu_v1->records[n].output;
    rec_v1->dPkts = pdu_v1->records[n].dPkts;
    rec_v1->dOctets = pdu_v1->records[n].dOctets;
    rec_v1->First = pdu_v1->records[n].First;
    rec_v1->Last = pdu_v1->records[n].Last;
    rec_v1->dstport = pdu_v1->records[n].dstport;
    rec_v1->srcport = pdu_v1->records[n].srcport;
    rec_v1->prot = pdu_v1->records[n].prot;
    rec_v1->tos = pdu_v1->records[n].tos;
    rec_v1->tcp_flags = pdu_v1->records[n].flags;

    /* copy in exporter IP */
    rec_v1->exaddr = ftpdu->ftd.exporter_ip;

    if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {

      SWAPINT32(rec_v1->srcaddr);
      SWAPINT32(rec_v1->dstaddr);
      SWAPINT32(rec_v1->nexthop);
      SWAPINT16(rec_v1->input);
      SWAPINT16(rec_v1->output);
      SWAPINT32(rec_v1->dPkts);
      SWAPINT32(rec_v1->dOctets);
      SWAPINT32(rec_v1->First);
      SWAPINT32(rec_v1->Last);
      SWAPINT16(rec_v1->dstport);
      SWAPINT16(rec_v1->srcport);

      SWAPINT32(rec_v1->exaddr);

    }

  } /* for n */

  return ftpdu->ftd.count;

} /* fts3rec_pdu_v1_decode */

/*
 * function: fts3rec_pdu_v5_decode
 *
 * subfunction to fts3rec_pdu_decode
 *
 * returns: # of stream records decoded
*/
int fts3rec_pdu_v5_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;
  struct ftpdu_v5 *pdu_v5;
  struct fts3rec_v5 *rec_v5;

  ftpdu->ftd.rec_size = sizeof (struct fts3rec_v5);
  pdu_v5 = (struct ftpdu_v5*)&ftpdu->buf;
  ph = (struct ftpdu_header*)&ftpdu->buf;

  /* preswap */
  if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(ph->sysUpTime);
    SWAPINT32(ph->unix_secs);
    SWAPINT32(ph->unix_nsecs);
  }

  for (n = 0; n < pdu_v5->count; ++n) {

    rec_v5 = (struct fts3rec_v5*) (ftpdu->ftd.buf + (n*ftpdu->ftd.rec_size));

    rec_v5->unix_nsecs = ph->unix_nsecs;
    rec_v5->unix_secs = ph->unix_secs;
    rec_v5->sysUpTime = ph->sysUpTime;

    rec_v5->engine_type = pdu_v5->engine_type;
    rec_v5->engine_id = pdu_v5->engine_id;


    rec_v5->srcaddr = pdu_v5->records[n].srcaddr;
    rec_v5->dstaddr = pdu_v5->records[n].dstaddr;
    rec_v5->nexthop = pdu_v5->records[n].nexthop;
    rec_v5->input = pdu_v5->records[n].input;
    rec_v5->output = pdu_v5->records[n].output;
    rec_v5->dPkts = pdu_v5->records[n].dPkts;
    rec_v5->dOctets = pdu_v5->records[n].dOctets;
    rec_v5->First = pdu_v5->records[n].First;
    rec_v5->Last = pdu_v5->records[n].Last;
    rec_v5->dstport = pdu_v5->records[n].dstport;
    rec_v5->srcport = pdu_v5->records[n].srcport;
    rec_v5->prot = pdu_v5->records[n].prot;
    rec_v5->tos = pdu_v5->records[n].tos;
    rec_v5->tcp_flags = pdu_v5->records[n].tcp_flags;
    rec_v5->src_as = pdu_v5->records[n].src_as;
    rec_v5->dst_as = pdu_v5->records[n].dst_as;
    rec_v5->src_mask = pdu_v5->records[n].src_mask;
    rec_v5->dst_mask = pdu_v5->records[n].dst_mask;

    /* perform AS substitution */
    rec_v5->src_as = (rec_v5->src_as) ? rec_v5->src_as : ftpdu->ftd.as_sub;
    rec_v5->dst_as = (rec_v5->dst_as) ? rec_v5->dst_as : ftpdu->ftd.as_sub;

    /* copy in exporter IP */
    rec_v5->exaddr = ftpdu->ftd.exporter_ip;

    if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {

      SWAPINT32(rec_v5->srcaddr);
      SWAPINT32(rec_v5->dstaddr);
      SWAPINT32(rec_v5->nexthop);
      SWAPINT16(rec_v5->input);
      SWAPINT16(rec_v5->output);
      SWAPINT32(rec_v5->dPkts);
      SWAPINT32(rec_v5->dOctets);
      SWAPINT32(rec_v5->First);
      SWAPINT32(rec_v5->Last);
      SWAPINT16(rec_v5->dstport);
      SWAPINT16(rec_v5->srcport);
      SWAPINT16(rec_v5->src_as);
      SWAPINT16(rec_v5->dst_as);

      SWAPINT32(rec_v5->exaddr);

    }

  } /* for n */

  return ftpdu->ftd.count;

} /* fts3rec_pdu_v5_decode */

/*
 * function: fts3rec_pdu_v6_decode
 *
 * subfunction to fts3rec_pdu_decode
 *
 * returns: # of stream records decoded
*/
int fts3rec_pdu_v6_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;
  struct ftpdu_v6 *pdu_v6;
  struct fts3rec_v6 *rec_v6;

  ftpdu->ftd.rec_size = sizeof (struct fts3rec_v6);
  pdu_v6 = (struct ftpdu_v6*)&ftpdu->buf;
  ph = (struct ftpdu_header*)&ftpdu->buf;

  /* preswap */
  if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(ph->sysUpTime);
    SWAPINT32(ph->unix_secs);
    SWAPINT32(ph->unix_nsecs);
  }

  for (n = 0; n < pdu_v6->count; ++n) {

    rec_v6 = (struct fts3rec_v6*) (ftpdu->ftd.buf + (n*ftpdu->ftd.rec_size));

    rec_v6->unix_nsecs = ph->unix_nsecs;
    rec_v6->unix_secs = ph->unix_secs;
    rec_v6->sysUpTime = ph->sysUpTime;

    rec_v6->engine_type = pdu_v6->engine_type;
    rec_v6->engine_type = pdu_v6->engine_id;


    rec_v6->srcaddr = pdu_v6->records[n].srcaddr;
    rec_v6->dstaddr = pdu_v6->records[n].dstaddr;
    rec_v6->nexthop = pdu_v6->records[n].nexthop;
    rec_v6->input = pdu_v6->records[n].input;
    rec_v6->output = pdu_v6->records[n].output;
    rec_v6->dPkts = pdu_v6->records[n].dPkts;
    rec_v6->dOctets = pdu_v6->records[n].dOctets;
    rec_v6->First = pdu_v6->records[n].First;
    rec_v6->Last = pdu_v6->records[n].Last;
    rec_v6->dstport = pdu_v6->records[n].dstport;
    rec_v6->srcport = pdu_v6->records[n].srcport;
    rec_v6->prot = pdu_v6->records[n].prot;
    rec_v6->tos = pdu_v6->records[n].tos;
    rec_v6->tcp_flags = pdu_v6->records[n].tcp_flags;
    rec_v6->src_as = pdu_v6->records[n].src_as;
    rec_v6->dst_as = pdu_v6->records[n].dst_as;
    rec_v6->src_mask = pdu_v6->records[n].src_mask;
    rec_v6->dst_mask = pdu_v6->records[n].dst_mask;

    /* perform AS substitution */
    rec_v6->src_as = (rec_v6->src_as) ? rec_v6->src_as : ftpdu->ftd.as_sub;
    rec_v6->dst_as = (rec_v6->dst_as) ? rec_v6->dst_as : ftpdu->ftd.as_sub;

    /* copy in exporter IP */
    rec_v6->exaddr = ftpdu->ftd.exporter_ip;

    if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {

      SWAPINT32(rec_v6->srcaddr);
      SWAPINT32(rec_v6->dstaddr);
      SWAPINT32(rec_v6->nexthop);
      SWAPINT16(rec_v6->input);
      SWAPINT16(rec_v6->output);
      SWAPINT32(rec_v6->dPkts);
      SWAPINT32(rec_v6->dOctets);
      SWAPINT32(rec_v6->First);
      SWAPINT32(rec_v6->Last);
      SWAPINT16(rec_v6->dstport);
      SWAPINT16(rec_v6->srcport);
      SWAPINT16(rec_v6->src_as);
      SWAPINT16(rec_v6->dst_as);

      SWAPINT32(rec_v6->exaddr);

    }

  } /* for n */

  return ftpdu->ftd.count;

} /* fts3rec_pdu_v6_decode */

/*
 * function: fts3rec_pdu_v7_decode
 *
 * subfunction to fts3rec_pdu_decode
 *
 * returns: # of stream records decoded
*/
int fts3rec_pdu_v7_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;
  struct ftpdu_v7 *pdu_v7;
  struct fts3rec_v7 *rec_v7;

  ftpdu->ftd.rec_size = sizeof (struct fts3rec_v7);
  pdu_v7 = (struct ftpdu_v7*)&ftpdu->buf;
  ph = (struct ftpdu_header*)&ftpdu->buf;

  /* preswap */
  if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(ph->sysUpTime);
    SWAPINT32(ph->unix_secs);
    SWAPINT32(ph->unix_nsecs);
  }

  for (n = 0; n < pdu_v7->count; ++n) {

    rec_v7 = (struct fts3rec_v7*) (ftpdu->ftd.buf + (n*ftpdu->ftd.rec_size));

    rec_v7->unix_nsecs = ph->unix_nsecs;
    rec_v7->unix_secs = ph->unix_secs;
    rec_v7->sysUpTime = ph->sysUpTime;

    rec_v7->engine_type = pdu_v7->engine_type;
    rec_v7->engine_type = pdu_v7->engine_id;

    rec_v7->srcaddr = pdu_v7->records[n].srcaddr;
    rec_v7->dstaddr = pdu_v7->records[n].dstaddr;
    rec_v7->nexthop = pdu_v7->records[n].nexthop;
    rec_v7->input = pdu_v7->records[n].input;
    rec_v7->output = pdu_v7->records[n].output;
    rec_v7->dPkts = pdu_v7->records[n].dPkts;
    rec_v7->dOctets = pdu_v7->records[n].dOctets;
    rec_v7->First = pdu_v7->records[n].First;
    rec_v7->Last = pdu_v7->records[n].Last;
    rec_v7->dstport = pdu_v7->records[n].dstport;
    rec_v7->srcport = pdu_v7->records[n].srcport;
    rec_v7->prot = pdu_v7->records[n].prot;
    rec_v7->tos = pdu_v7->records[n].tos;
    rec_v7->tcp_flags = pdu_v7->records[n].tcp_flags;
    rec_v7->src_as = pdu_v7->records[n].src_as;
    rec_v7->dst_as = pdu_v7->records[n].dst_as;
    rec_v7->src_mask = pdu_v7->records[n].src_mask;
    rec_v7->dst_mask = pdu_v7->records[n].dst_mask;
    rec_v7->router_sc = pdu_v7->records[n].router_sc;

    /* perform AS substitution */
    rec_v7->src_as = (rec_v7->src_as) ? rec_v7->src_as : ftpdu->ftd.as_sub;
    rec_v7->dst_as = (rec_v7->dst_as) ? rec_v7->dst_as : ftpdu->ftd.as_sub;

    /* copy in exporter IP */
    rec_v7->exaddr = ftpdu->ftd.exporter_ip;

    if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {

      SWAPINT32(rec_v7->srcaddr);
      SWAPINT32(rec_v7->dstaddr);
      SWAPINT32(rec_v7->nexthop);
      SWAPINT16(rec_v7->input);
      SWAPINT16(rec_v7->output);
      SWAPINT32(rec_v7->dPkts);
      SWAPINT32(rec_v7->dOctets);
      SWAPINT32(rec_v7->First);
      SWAPINT32(rec_v7->Last);
      SWAPINT16(rec_v7->dstport);
      SWAPINT16(rec_v7->srcport);
      SWAPINT16(rec_v7->src_as);
      SWAPINT16(rec_v7->dst_as);
      SWAPINT32(rec_v7->router_sc);

      SWAPINT32(rec_v7->exaddr);

    }
  } /* for */

  return ftpdu->ftd.count;

} /* fts3rec_pdu_v7_decode */

/*
 * function: fts3rec_pdu_v8_1_decode
 *
 * subfunction to fts3rec_pdu_decode
 *
 * returns: # of stream records decoded
*/
int fts3rec_pdu_v8_1_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;
  struct ftpdu_v8_1 *pdu_v8_1;
  struct fts3rec_v8_1 *rec_v8_1;

  ftpdu->ftd.rec_size = sizeof (struct fts3rec_v8_1);
  pdu_v8_1 = (struct ftpdu_v8_1*)&ftpdu->buf;
  ph = (struct ftpdu_header*)&ftpdu->buf;

  /* preswap */
  if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(ph->sysUpTime);
    SWAPINT32(ph->unix_secs);
    SWAPINT32(ph->unix_nsecs);
  }

  for (n = 0; n < pdu_v8_1->count; ++n) {

    rec_v8_1 = (struct fts3rec_v8_1*) (ftpdu->ftd.buf +
      (n*ftpdu->ftd.rec_size));

    rec_v8_1->unix_nsecs = ph->unix_nsecs;
    rec_v8_1->unix_secs = ph->unix_secs;
    rec_v8_1->sysUpTime = ph->sysUpTime;

    rec_v8_1->engine_type = pdu_v8_1->engine_type;
    rec_v8_1->engine_type = pdu_v8_1->engine_id;

    rec_v8_1->dFlows = pdu_v8_1->records[n].dFlows;
    rec_v8_1->dPkts = pdu_v8_1->records[n].dPkts;
    rec_v8_1->dOctets = pdu_v8_1->records[n].dOctets;
    rec_v8_1->First = pdu_v8_1->records[n].First;
    rec_v8_1->Last = pdu_v8_1->records[n].Last;
    rec_v8_1->src_as = pdu_v8_1->records[n].src_as;
    rec_v8_1->dst_as = pdu_v8_1->records[n].dst_as;
    rec_v8_1->input = pdu_v8_1->records[n].input;
    rec_v8_1->output = pdu_v8_1->records[n].output;

    /* perform AS substitution */
    rec_v8_1->src_as = (rec_v8_1->src_as) ? rec_v8_1->src_as :
      ftpdu->ftd.as_sub;
    rec_v8_1->dst_as = (rec_v8_1->dst_as) ? rec_v8_1->dst_as :
      ftpdu->ftd.as_sub;

    /* copy in exporter IP */
    rec_v8_1->exaddr = ftpdu->ftd.exporter_ip;

    if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {

      SWAPINT32(rec_v8_1->dFlows);
      SWAPINT32(rec_v8_1->dPkts);
      SWAPINT32(rec_v8_1->dOctets);
      SWAPINT32(rec_v8_1->First);
      SWAPINT32(rec_v8_1->Last);
      SWAPINT16(rec_v8_1->src_as);
      SWAPINT16(rec_v8_1->dst_as);
      SWAPINT16(rec_v8_1->input);
      SWAPINT16(rec_v8_1->output);

      SWAPINT32(rec_v8_1->exaddr);

    }

  } /* for */

  return ftpdu->ftd.count;

} /* fts3rec_pdu_v8_1_decode */

/*
 * function: fts3rec_pdu_v8_2_decode
 *
 * subfunction to fts3rec_pdu_decode
 *
 * returns: # of stream records decoded
*/
int fts3rec_pdu_v8_2_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;
  struct ftpdu_v8_2 *pdu_v8_2;
  struct fts3rec_v8_2 *rec_v8_2;

  ftpdu->ftd.rec_size = sizeof (struct fts3rec_v8_2);
  pdu_v8_2 = (struct ftpdu_v8_2*)&ftpdu->buf;
  ph = (struct ftpdu_header*)&ftpdu->buf;

  /* preswap */
  if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(ph->sysUpTime);
    SWAPINT32(ph->unix_secs);
    SWAPINT32(ph->unix_nsecs);
  }

  for (n = 0; n < pdu_v8_2->count; ++n) {

    rec_v8_2 = (struct fts3rec_v8_2*) (ftpdu->ftd.buf +
      (n*ftpdu->ftd.rec_size));

    rec_v8_2->unix_nsecs = ph->unix_nsecs;
    rec_v8_2->unix_secs = ph->unix_secs;
    rec_v8_2->sysUpTime = ph->sysUpTime;

    rec_v8_2->engine_type = pdu_v8_2->engine_type;
    rec_v8_2->engine_type = pdu_v8_2->engine_id;

    rec_v8_2->dFlows = pdu_v8_2->records[n].dFlows;
    rec_v8_2->dPkts = pdu_v8_2->records[n].dPkts;
    rec_v8_2->dOctets = pdu_v8_2->records[n].dOctets;
    rec_v8_2->First = pdu_v8_2->records[n].First;
    rec_v8_2->Last = pdu_v8_2->records[n].Last;
    rec_v8_2->srcport = pdu_v8_2->records[n].srcport;
    rec_v8_2->dstport = pdu_v8_2->records[n].dstport;
    rec_v8_2->prot = pdu_v8_2->records[n].prot;

    /* copy in exporter IP */
    rec_v8_2->exaddr = ftpdu->ftd.exporter_ip;

    if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {

      SWAPINT32(rec_v8_2->dFlows);
      SWAPINT32(rec_v8_2->dPkts);
      SWAPINT32(rec_v8_2->dOctets);
      SWAPINT32(rec_v8_2->First);
      SWAPINT32(rec_v8_2->Last);
      SWAPINT16(rec_v8_2->srcport);
      SWAPINT16(rec_v8_2->dstport);

      SWAPINT32(rec_v8_2->exaddr);

    }

  } /* for */

  return ftpdu->ftd.count;

} /* fts3rec_pdu_v8_2_decode */

/*
 * function: fts3rec_pdu_v8_3_decode
 *
 * subfunction to fts3rec_pdu_decode
 *
 * returns: # of stream records decoded
*/
int fts3rec_pdu_v8_3_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;
  struct ftpdu_v8_3 *pdu_v8_3;
  struct fts3rec_v8_3 *rec_v8_3;

  ftpdu->ftd.rec_size = sizeof (struct fts3rec_v8_3);
  pdu_v8_3 = (struct ftpdu_v8_3*)&ftpdu->buf;
  ph = (struct ftpdu_header*)&ftpdu->buf;

  /* preswap */
  if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(ph->sysUpTime);
    SWAPINT32(ph->unix_secs);
    SWAPINT32(ph->unix_nsecs);
  }

  for (n = 0; n < pdu_v8_3->count; ++n) {

    rec_v8_3 = (struct fts3rec_v8_3*) (ftpdu->ftd.buf +
      (n*ftpdu->ftd.rec_size));

    rec_v8_3->unix_nsecs = ph->unix_nsecs;
    rec_v8_3->unix_secs = ph->unix_secs;
    rec_v8_3->sysUpTime = ph->sysUpTime;

    rec_v8_3->engine_type = pdu_v8_3->engine_type;
    rec_v8_3->engine_type = pdu_v8_3->engine_id;

    rec_v8_3->dFlows = pdu_v8_3->records[n].dFlows;
    rec_v8_3->dPkts = pdu_v8_3->records[n].dPkts;
    rec_v8_3->dOctets = pdu_v8_3->records[n].dOctets;
    rec_v8_3->First = pdu_v8_3->records[n].First;
    rec_v8_3->Last = pdu_v8_3->records[n].Last;
    rec_v8_3->srcaddr = pdu_v8_3->records[n].src_prefix;
    rec_v8_3->src_mask = pdu_v8_3->records[n].src_mask;
    rec_v8_3->src_as = pdu_v8_3->records[n].src_as;
    rec_v8_3->input = pdu_v8_3->records[n].input;

    /* perform AS substitution */
    rec_v8_3->src_as = (rec_v8_3->src_as) ? rec_v8_3->src_as :
      ftpdu->ftd.as_sub;

    /* copy in exporter IP */
    rec_v8_3->exaddr = ftpdu->ftd.exporter_ip;

    if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {

      SWAPINT32(rec_v8_3->dFlows);
      SWAPINT32(rec_v8_3->dPkts);
      SWAPINT32(rec_v8_3->dOctets);
      SWAPINT32(rec_v8_3->First);
      SWAPINT32(rec_v8_3->Last);
      SWAPINT32(rec_v8_3->srcaddr);
      SWAPINT16(rec_v8_3->src_as);
      SWAPINT16(rec_v8_3->input);

      SWAPINT32(rec_v8_3->exaddr);

    }

  } /* for */

  return ftpdu->ftd.count;

} /* fts3rec_pdu_v8_3_decode */

/*
 * function: fts3rec_pdu_v8_4_decode
 *
 * subfunction to fts3rec_pdu_decode
 *
 * returns: # of stream records decoded
*/
int fts3rec_pdu_v8_4_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;
  struct ftpdu_v8_4 *pdu_v8_4;
  struct fts3rec_v8_4 *rec_v8_4;

  ftpdu->ftd.rec_size = sizeof (struct fts3rec_v8_4);
  pdu_v8_4 = (struct ftpdu_v8_4*)&ftpdu->buf;
  ph = (struct ftpdu_header*)&ftpdu->buf;

  /* preswap */
  if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(ph->sysUpTime);
    SWAPINT32(ph->unix_secs);
    SWAPINT32(ph->unix_nsecs);
  }

  for (n = 0; n < pdu_v8_4->count; ++n) {

    rec_v8_4 = (struct fts3rec_v8_4*) (ftpdu->ftd.buf +
      (n*ftpdu->ftd.rec_size));

    rec_v8_4->unix_nsecs = ph->unix_nsecs;
    rec_v8_4->unix_secs = ph->unix_secs;
    rec_v8_4->sysUpTime = ph->sysUpTime;

    rec_v8_4->engine_type = pdu_v8_4->engine_type;
    rec_v8_4->engine_type = pdu_v8_4->engine_id;

    rec_v8_4->dFlows = pdu_v8_4->records[n].dFlows;
    rec_v8_4->dPkts = pdu_v8_4->records[n].dPkts;
    rec_v8_4->dOctets = pdu_v8_4->records[n].dOctets;
    rec_v8_4->First = pdu_v8_4->records[n].First;
    rec_v8_4->Last = pdu_v8_4->records[n].Last;
    rec_v8_4->dstaddr = pdu_v8_4->records[n].dst_prefix;
    rec_v8_4->dst_mask = pdu_v8_4->records[n].dst_mask;
    rec_v8_4->dst_as = pdu_v8_4->records[n].dst_as;
    rec_v8_4->output = pdu_v8_4->records[n].output;

    /* perform AS substitution */
    rec_v8_4->dst_as = (rec_v8_4->dst_as) ? rec_v8_4->dst_as :
      ftpdu->ftd.as_sub;

    /* copy in exporter IP */
    rec_v8_4->exaddr = ftpdu->ftd.exporter_ip;

    if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {

      SWAPINT32(rec_v8_4->dFlows);
      SWAPINT32(rec_v8_4->dPkts);
      SWAPINT32(rec_v8_4->dOctets);
      SWAPINT32(rec_v8_4->First);
      SWAPINT32(rec_v8_4->Last);
      SWAPINT32(rec_v8_4->dstaddr);
      SWAPINT16(rec_v8_4->dst_as);
      SWAPINT16(rec_v8_4->output);

      SWAPINT32(rec_v8_4->exaddr);

    }

  } /* for */

  return ftpdu->ftd.count;

} /* fts3rec_pdu_v8_4_decode */

/*
 * function: fts3rec_pdu_v8_5_decode
 *
 * subfunction to fts3rec_pdu_decode
 *
 * returns: # of stream records decoded
*/
int fts3rec_pdu_v8_5_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;
  struct ftpdu_v8_5 *pdu_v8_5;
  struct fts3rec_v8_5 *rec_v8_5;

  ftpdu->ftd.rec_size = sizeof (struct fts3rec_v8_5);
  pdu_v8_5 = (struct ftpdu_v8_5*)&ftpdu->buf;
  ph = (struct ftpdu_header*)&ftpdu->buf;

  /* preswap */
  if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(ph->sysUpTime);
    SWAPINT32(ph->unix_secs);
    SWAPINT32(ph->unix_nsecs);
  }

  for (n = 0; n < pdu_v8_5->count; ++n) {

    rec_v8_5 = (struct fts3rec_v8_5*) (ftpdu->ftd.buf +
      (n*ftpdu->ftd.rec_size));

    rec_v8_5->unix_nsecs = ph->unix_nsecs;
    rec_v8_5->unix_secs = ph->unix_secs;
    rec_v8_5->sysUpTime = ph->sysUpTime;

    rec_v8_5->engine_type = pdu_v8_5->engine_type;
    rec_v8_5->engine_type = pdu_v8_5->engine_id;

    rec_v8_5->dFlows = pdu_v8_5->records[n].dFlows;
    rec_v8_5->dPkts = pdu_v8_5->records[n].dPkts;
    rec_v8_5->dOctets = pdu_v8_5->records[n].dOctets;
    rec_v8_5->First = pdu_v8_5->records[n].First;
    rec_v8_5->Last = pdu_v8_5->records[n].Last;
    rec_v8_5->srcaddr = pdu_v8_5->records[n].src_prefix;
    rec_v8_5->dstaddr = pdu_v8_5->records[n].dst_prefix;
    rec_v8_5->src_mask = pdu_v8_5->records[n].src_mask;
    rec_v8_5->dst_mask = pdu_v8_5->records[n].dst_mask;
    rec_v8_5->src_as = pdu_v8_5->records[n].src_as;
    rec_v8_5->dst_as = pdu_v8_5->records[n].dst_as;
    rec_v8_5->input = pdu_v8_5->records[n].input;
    rec_v8_5->output = pdu_v8_5->records[n].output;

    /* perform AS substitution */
    rec_v8_5->src_as = (rec_v8_5->src_as) ? rec_v8_5->src_as :
      ftpdu->ftd.as_sub;
    rec_v8_5->dst_as = (rec_v8_5->dst_as) ? rec_v8_5->dst_as :
      ftpdu->ftd.as_sub;

    /* copy in exporter IP */
    rec_v8_5->exaddr = ftpdu->ftd.exporter_ip;

    if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {

      SWAPINT32(rec_v8_5->dFlows);
      SWAPINT32(rec_v8_5->dPkts);
      SWAPINT32(rec_v8_5->dOctets);
      SWAPINT32(rec_v8_5->First);
      SWAPINT32(rec_v8_5->Last);
      SWAPINT32(rec_v8_5->srcaddr);
      SWAPINT32(rec_v8_5->dstaddr);
      SWAPINT16(rec_v8_5->src_as);
      SWAPINT16(rec_v8_5->dst_as);
      SWAPINT16(rec_v8_5->input);
      SWAPINT16(rec_v8_5->output);

      SWAPINT32(rec_v8_5->exaddr);

    }

  } /* for */

  return ftpdu->ftd.count;

} /* fts3rec_pdu_v8_5_decode */

/*
 * function: fts3rec_pdu_v8_6_decode
 *
 * subfunction to fts3rec_pdu_decode
 *
 * returns: # of stream records decoded
*/
int fts3rec_pdu_v8_6_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;
  struct ftpdu_v8_6 *pdu_v8_6;
  struct fts3rec_v8_6 *rec_v8_6;

  ftpdu->ftd.rec_size = sizeof (struct fts3rec_v8_6);
  pdu_v8_6 = (struct ftpdu_v8_6*)&ftpdu->buf;
  ph = (struct ftpdu_header*)&ftpdu->buf;

  /* preswap */
  if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(ph->sysUpTime);
    SWAPINT32(ph->unix_secs);
    SWAPINT32(ph->unix_nsecs);
  }

  for (n = 0; n < pdu_v8_6->count; ++n) {

    rec_v8_6 = (struct fts3rec_v8_6*) (ftpdu->ftd.buf +
      (n*ftpdu->ftd.rec_size));

    rec_v8_6->unix_nsecs = ph->unix_nsecs;
    rec_v8_6->unix_secs = ph->unix_secs;
    rec_v8_6->sysUpTime = ph->sysUpTime;

    rec_v8_6->engine_type = pdu_v8_6->engine_type;
    rec_v8_6->engine_type = pdu_v8_6->engine_id;

    rec_v8_6->dPkts = pdu_v8_6->records[n].dPkts;
    rec_v8_6->dOctets = pdu_v8_6->records[n].dOctets;
    rec_v8_6->First = pdu_v8_6->records[n].First;
    rec_v8_6->Last = pdu_v8_6->records[n].Last;
    rec_v8_6->dstaddr = pdu_v8_6->records[n].dstaddr;
    rec_v8_6->extra_pkts = pdu_v8_6->records[n].extra_pkts;
    rec_v8_6->router_sc = pdu_v8_6->records[n].router_sc;
    rec_v8_6->output = pdu_v8_6->records[n].output;
    rec_v8_6->tos = pdu_v8_6->records[n].tos;
    rec_v8_6->marked_tos = pdu_v8_6->records[n].marked_tos;

    /* copy in exporter IP */
    rec_v8_6->exaddr = ftpdu->ftd.exporter_ip;

    if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {

      SWAPINT32(rec_v8_6->dPkts);
      SWAPINT32(rec_v8_6->dOctets);
      SWAPINT32(rec_v8_6->First);
      SWAPINT32(rec_v8_6->Last);
      SWAPINT32(rec_v8_6->dstaddr);
      SWAPINT32(rec_v8_6->extra_pkts);
      SWAPINT32(rec_v8_6->router_sc);
      SWAPINT16(rec_v8_6->output);

      SWAPINT32(rec_v8_6->exaddr);

    }

  } /* for */

  return ftpdu->ftd.count;

} /* fts3rec_pdu_v8_6_decode */

/*
 * function: fts3rec_pdu_v8_7_decode
 *
 * subfunction to fts3rec_pdu_decode
 *
 * returns: # of stream records decoded
*/
int fts3rec_pdu_v8_7_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;
  struct ftpdu_v8_7 *pdu_v8_7;
  struct fts3rec_v8_7 *rec_v8_7;

  ftpdu->ftd.rec_size = sizeof (struct fts3rec_v8_7);
  pdu_v8_7 = (struct ftpdu_v8_7*)&ftpdu->buf;
  ph = (struct ftpdu_header*)&ftpdu->buf;

  /* preswap */
  if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(ph->sysUpTime);
    SWAPINT32(ph->unix_secs);
    SWAPINT32(ph->unix_nsecs);
  }

  for (n = 0; n < pdu_v8_7->count; ++n) {

    rec_v8_7 = (struct fts3rec_v8_7*) (ftpdu->ftd.buf +
      (n*ftpdu->ftd.rec_size));

    rec_v8_7->unix_nsecs = ph->unix_nsecs;
    rec_v8_7->unix_secs = ph->unix_secs;
    rec_v8_7->sysUpTime = ph->sysUpTime;

    rec_v8_7->engine_type = pdu_v8_7->engine_type;
    rec_v8_7->engine_type = pdu_v8_7->engine_id;

    rec_v8_7->dPkts = pdu_v8_7->records[n].dPkts;
    rec_v8_7->dOctets = pdu_v8_7->records[n].dOctets;
    rec_v8_7->First = pdu_v8_7->records[n].First;
    rec_v8_7->Last = pdu_v8_7->records[n].Last;
    rec_v8_7->dstaddr = pdu_v8_7->records[n].dstaddr;
    rec_v8_7->srcaddr = pdu_v8_7->records[n].srcaddr;
    rec_v8_7->extra_pkts = pdu_v8_7->records[n].extra_pkts;
    rec_v8_7->router_sc = pdu_v8_7->records[n].router_sc;
    rec_v8_7->output = pdu_v8_7->records[n].output;
    rec_v8_7->input = pdu_v8_7->records[n].input;
    rec_v8_7->tos = pdu_v8_7->records[n].tos;
    rec_v8_7->marked_tos = pdu_v8_7->records[n].marked_tos;

    /* copy in exporter IP */
    rec_v8_7->exaddr = ftpdu->ftd.exporter_ip;

    if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {

      SWAPINT32(rec_v8_7->dPkts);
      SWAPINT32(rec_v8_7->dOctets);
      SWAPINT32(rec_v8_7->First);
      SWAPINT32(rec_v8_7->Last);
      SWAPINT32(rec_v8_7->dstaddr);
      SWAPINT32(rec_v8_7->srcaddr);
      SWAPINT32(rec_v8_7->extra_pkts);
      SWAPINT32(rec_v8_7->router_sc);
      SWAPINT16(rec_v8_7->output);
      SWAPINT16(rec_v8_7->input);

      SWAPINT32(rec_v8_7->exaddr);

    }

  } /* for */

  return ftpdu->ftd.count;

} /* fts3rec_pdu_v8_7_decode */

/*
 * function: fts3rec_pdu_v8_8_decode
 *
 * subfunction to fts3rec_pdu_decode
 *
 * returns: # of stream records decoded
*/
int fts3rec_pdu_v8_8_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;
  struct ftpdu_v8_8 *pdu_v8_8;
  struct fts3rec_v8_8 *rec_v8_8;

  ftpdu->ftd.rec_size = sizeof (struct fts3rec_v8_8);
  pdu_v8_8 = (struct ftpdu_v8_8*)&ftpdu->buf;
  ph = (struct ftpdu_header*)&ftpdu->buf;

  /* preswap */
  if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(ph->sysUpTime);
    SWAPINT32(ph->unix_secs);
    SWAPINT32(ph->unix_nsecs);
  }

  for (n = 0; n < pdu_v8_8->count; ++n) {

    rec_v8_8 = (struct fts3rec_v8_8*) (ftpdu->ftd.buf +
      (n*ftpdu->ftd.rec_size));

    rec_v8_8->unix_nsecs = ph->unix_nsecs;
    rec_v8_8->unix_secs = ph->unix_secs;
    rec_v8_8->sysUpTime = ph->sysUpTime;

    rec_v8_8->engine_type = pdu_v8_8->engine_type;
    rec_v8_8->engine_type = pdu_v8_8->engine_id;

    rec_v8_8->dstaddr = pdu_v8_8->records[n].dstaddr;
    rec_v8_8->srcaddr = pdu_v8_8->records[n].srcaddr;
    rec_v8_8->dstport = pdu_v8_8->records[n].dstport;
    rec_v8_8->srcport = pdu_v8_8->records[n].srcport;
    rec_v8_8->dPkts = pdu_v8_8->records[n].dPkts;
    rec_v8_8->dOctets = pdu_v8_8->records[n].dOctets;
    rec_v8_8->First = pdu_v8_8->records[n].First;
    rec_v8_8->Last = pdu_v8_8->records[n].Last;
    rec_v8_8->output = pdu_v8_8->records[n].output;
    rec_v8_8->input = pdu_v8_8->records[n].input;
    rec_v8_8->tos = pdu_v8_8->records[n].tos;
    rec_v8_8->prot = pdu_v8_8->records[n].prot;
    rec_v8_8->marked_tos = pdu_v8_8->records[n].marked_tos;
    rec_v8_8->extra_pkts = pdu_v8_8->records[n].extra_pkts;
    rec_v8_8->router_sc = pdu_v8_8->records[n].router_sc;

    /* copy in exporter IP */
    rec_v8_8->exaddr = ftpdu->ftd.exporter_ip;

    if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {

      SWAPINT32(rec_v8_8->dstaddr);
      SWAPINT32(rec_v8_8->srcaddr);
      SWAPINT16(rec_v8_8->dstport);
      SWAPINT16(rec_v8_8->srcport);
      SWAPINT32(rec_v8_8->dPkts);
      SWAPINT32(rec_v8_8->dOctets);
      SWAPINT32(rec_v8_8->First);
      SWAPINT32(rec_v8_8->Last);
      SWAPINT16(rec_v8_8->output);
      SWAPINT16(rec_v8_8->input);
      SWAPINT32(rec_v8_8->extra_pkts);
      SWAPINT32(rec_v8_8->router_sc);

      SWAPINT32(rec_v8_8->exaddr);

    }

  } /* for */

  return ftpdu->ftd.count;

} /* fts3rec_pdu_v8_8_decode */

/*
 * function: fts3rec_pdu_v8_9_decode
 *
 * subfunction to fts3rec_pdu_decode
 *
 * returns: # of stream records decoded
*/
int fts3rec_pdu_v8_9_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;
  struct ftpdu_v8_9 *pdu_v8_9;
  struct fts3rec_v8_9 *rec_v8_9;

  ftpdu->ftd.rec_size = sizeof (struct fts3rec_v8_9);
  pdu_v8_9 = (struct ftpdu_v8_9*)&ftpdu->buf;
  ph = (struct ftpdu_header*)&ftpdu->buf;

  /* preswap */
  if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(ph->sysUpTime);
    SWAPINT32(ph->unix_secs);
    SWAPINT32(ph->unix_nsecs);
  }

  for (n = 0; n < pdu_v8_9->count; ++n) {

    rec_v8_9 = (struct fts3rec_v8_9*) (ftpdu->ftd.buf +
      (n*ftpdu->ftd.rec_size));

    rec_v8_9->unix_nsecs = ph->unix_nsecs;
    rec_v8_9->unix_secs = ph->unix_secs;
    rec_v8_9->sysUpTime = ph->sysUpTime;

    rec_v8_9->engine_type = pdu_v8_9->engine_type;
    rec_v8_9->engine_type = pdu_v8_9->engine_id;

    rec_v8_9->dFlows = pdu_v8_9->records[n].dFlows;
    rec_v8_9->dPkts = pdu_v8_9->records[n].dPkts;
    rec_v8_9->dOctets = pdu_v8_9->records[n].dOctets;
    rec_v8_9->First = pdu_v8_9->records[n].First;
    rec_v8_9->Last = pdu_v8_9->records[n].Last;
    rec_v8_9->src_as = pdu_v8_9->records[n].src_as;
    rec_v8_9->dst_as = pdu_v8_9->records[n].dst_as;
    rec_v8_9->input = pdu_v8_9->records[n].input;
    rec_v8_9->output = pdu_v8_9->records[n].output;
    rec_v8_9->tos = pdu_v8_9->records[n].tos;

    /* perform AS substitution */
    rec_v8_9->src_as = (rec_v8_9->src_as) ? rec_v8_9->src_as :
      ftpdu->ftd.as_sub;
    rec_v8_9->dst_as = (rec_v8_9->dst_as) ? rec_v8_9->dst_as :
      ftpdu->ftd.as_sub;

    /* copy in exporter IP */
    rec_v8_9->exaddr = ftpdu->ftd.exporter_ip;

    if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {

      SWAPINT32(rec_v8_9->dFlows);
      SWAPINT32(rec_v8_9->dPkts);
      SWAPINT32(rec_v8_9->dOctets);
      SWAPINT32(rec_v8_9->First);
      SWAPINT32(rec_v8_9->Last);
      SWAPINT16(rec_v8_9->src_as);
      SWAPINT16(rec_v8_9->dst_as);
      SWAPINT16(rec_v8_9->input);
      SWAPINT16(rec_v8_9->output);

      SWAPINT32(rec_v8_9->exaddr);

    }

  } /* for */

  return ftpdu->ftd.count;

} /* fts3rec_pdu_v8_9_decode */

/*
 * function: fts3rec_pdu_v8_10_decode
 *
 * subfunction to fts3rec_pdu_decode
 *
 * returns: # of stream records decoded
*/
int fts3rec_pdu_v8_10_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;
  struct ftpdu_v8_10 *pdu_v8_10;
  struct fts3rec_v8_10 *rec_v8_10;

  ftpdu->ftd.rec_size = sizeof (struct fts3rec_v8_10);
  pdu_v8_10 = (struct ftpdu_v8_10*)&ftpdu->buf;
  ph = (struct ftpdu_header*)&ftpdu->buf;

  /* preswap */
  if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(ph->sysUpTime);
    SWAPINT32(ph->unix_secs);
    SWAPINT32(ph->unix_nsecs);
  }

  for (n = 0; n < pdu_v8_10->count; ++n) {

    rec_v8_10 = (struct fts3rec_v8_10*) (ftpdu->ftd.buf +
      (n*ftpdu->ftd.rec_size));

    rec_v8_10->unix_nsecs = ph->unix_nsecs;
    rec_v8_10->unix_secs = ph->unix_secs;
    rec_v8_10->sysUpTime = ph->sysUpTime;

    rec_v8_10->engine_type = pdu_v8_10->engine_type;
    rec_v8_10->engine_type = pdu_v8_10->engine_id;

    rec_v8_10->dFlows = pdu_v8_10->records[n].dFlows;
    rec_v8_10->dPkts = pdu_v8_10->records[n].dPkts;
    rec_v8_10->dOctets = pdu_v8_10->records[n].dOctets;
    rec_v8_10->First = pdu_v8_10->records[n].First;
    rec_v8_10->Last = pdu_v8_10->records[n].Last;
    rec_v8_10->prot = pdu_v8_10->records[n].prot;
    rec_v8_10->tos = pdu_v8_10->records[n].tos;
    rec_v8_10->srcport = pdu_v8_10->records[n].srcport;
    rec_v8_10->dstport = pdu_v8_10->records[n].dstport;
    rec_v8_10->prot = pdu_v8_10->records[n].prot;

    /* copy in exporter IP */
    rec_v8_10->exaddr = ftpdu->ftd.exporter_ip;

    if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {

      SWAPINT32(rec_v8_10->dFlows);
      SWAPINT32(rec_v8_10->dPkts);
      SWAPINT32(rec_v8_10->dOctets);
      SWAPINT32(rec_v8_10->First);
      SWAPINT32(rec_v8_10->Last);
      SWAPINT16(rec_v8_10->srcport);
      SWAPINT16(rec_v8_10->dstport);

      SWAPINT32(rec_v8_10->exaddr);

    }

  } /* for */

  return ftpdu->ftd.count;

} /* fts3rec_pdu_v8_10_decode */

/*
 * function: fts3rec_pdu_v8_11_decode
 *
 * subfunction to fts3rec_pdu_decode
 *
 * returns: # of stream records decoded
*/
int fts3rec_pdu_v8_11_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;
  struct ftpdu_v8_11 *pdu_v8_11;
  struct fts3rec_v8_11 *rec_v8_11;

  ftpdu->ftd.rec_size = sizeof (struct fts3rec_v8_11);
  pdu_v8_11 = (struct ftpdu_v8_11*)&ftpdu->buf;
  ph = (struct ftpdu_header*)&ftpdu->buf;

  /* preswap */
  if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(ph->sysUpTime);
    SWAPINT32(ph->unix_secs);
    SWAPINT32(ph->unix_nsecs);
  }

  for (n = 0; n < pdu_v8_11->count; ++n) {

    rec_v8_11 = (struct fts3rec_v8_11*) (ftpdu->ftd.buf +
      (n*ftpdu->ftd.rec_size));

    rec_v8_11->unix_nsecs = ph->unix_nsecs;
    rec_v8_11->unix_secs = ph->unix_secs;
    rec_v8_11->sysUpTime = ph->sysUpTime;

    rec_v8_11->engine_type = pdu_v8_11->engine_type;
    rec_v8_11->engine_type = pdu_v8_11->engine_id;

    rec_v8_11->dFlows = pdu_v8_11->records[n].dFlows;
    rec_v8_11->dPkts = pdu_v8_11->records[n].dPkts;
    rec_v8_11->dOctets = pdu_v8_11->records[n].dOctets;
    rec_v8_11->First = pdu_v8_11->records[n].First;
    rec_v8_11->Last = pdu_v8_11->records[n].Last;
    rec_v8_11->srcaddr = pdu_v8_11->records[n].src_prefix;
    rec_v8_11->src_mask = pdu_v8_11->records[n].src_mask;
    rec_v8_11->tos = pdu_v8_11->records[n].tos;
    rec_v8_11->src_as = pdu_v8_11->records[n].src_as;
    rec_v8_11->input = pdu_v8_11->records[n].input;

    /* perform AS substitution */
    rec_v8_11->src_as = (rec_v8_11->src_as) ? rec_v8_11->src_as :
      ftpdu->ftd.as_sub;

    /* copy in exporter IP */
    rec_v8_11->exaddr = ftpdu->ftd.exporter_ip;

    if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {

      SWAPINT32(rec_v8_11->dFlows);
      SWAPINT32(rec_v8_11->dPkts);
      SWAPINT32(rec_v8_11->dOctets);
      SWAPINT32(rec_v8_11->First);
      SWAPINT32(rec_v8_11->Last);
      SWAPINT32(rec_v8_11->srcaddr);
      SWAPINT16(rec_v8_11->src_as);
      SWAPINT16(rec_v8_11->input);

      SWAPINT32(rec_v8_11->exaddr);

    }

  } /* for */

  return ftpdu->ftd.count;

} /* fts3rec_pdu_v8_11_decode */

/*
 * function: fts3rec_pdu_v8_12_decode
 *
 * subfunction to fts3rec_pdu_decode
 *
 * returns: # of stream records decoded
*/
int fts3rec_pdu_v8_12_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;
  struct ftpdu_v8_12 *pdu_v8_12;
  struct fts3rec_v8_12 *rec_v8_12;

  ftpdu->ftd.rec_size = sizeof (struct fts3rec_v8_12);
  pdu_v8_12 = (struct ftpdu_v8_12*)&ftpdu->buf;
  ph = (struct ftpdu_header*)&ftpdu->buf;

  /* preswap */
  if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(ph->sysUpTime);
    SWAPINT32(ph->unix_secs);
    SWAPINT32(ph->unix_nsecs);
  }

  for (n = 0; n < pdu_v8_12->count; ++n) {

    rec_v8_12 = (struct fts3rec_v8_12*) (ftpdu->ftd.buf +
      (n*ftpdu->ftd.rec_size));

    rec_v8_12->unix_nsecs = ph->unix_nsecs;
    rec_v8_12->unix_secs = ph->unix_secs;
    rec_v8_12->sysUpTime = ph->sysUpTime;

    rec_v8_12->engine_type = pdu_v8_12->engine_type;
    rec_v8_12->engine_type = pdu_v8_12->engine_id;

    rec_v8_12->dFlows = pdu_v8_12->records[n].dFlows;
    rec_v8_12->dPkts = pdu_v8_12->records[n].dPkts;
    rec_v8_12->dOctets = pdu_v8_12->records[n].dOctets;
    rec_v8_12->First = pdu_v8_12->records[n].First;
    rec_v8_12->Last = pdu_v8_12->records[n].Last;
    rec_v8_12->dstaddr = pdu_v8_12->records[n].dst_prefix;
    rec_v8_12->tos = pdu_v8_12->records[n].tos;
    rec_v8_12->dst_mask = pdu_v8_12->records[n].dst_mask;
    rec_v8_12->dst_as = pdu_v8_12->records[n].dst_as;
    rec_v8_12->output = pdu_v8_12->records[n].output;

    /* perform AS substitution */
    rec_v8_12->dst_as = (rec_v8_12->dst_as) ? rec_v8_12->dst_as :
      ftpdu->ftd.as_sub;

    /* copy in exporter IP */
    rec_v8_12->exaddr = ftpdu->ftd.exporter_ip;

    if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {

      SWAPINT32(rec_v8_12->dFlows);
      SWAPINT32(rec_v8_12->dPkts);
      SWAPINT32(rec_v8_12->dOctets);
      SWAPINT32(rec_v8_12->First);
      SWAPINT32(rec_v8_12->Last);
      SWAPINT32(rec_v8_12->dstaddr);
      SWAPINT16(rec_v8_12->dst_as);
      SWAPINT16(rec_v8_12->output);

      SWAPINT32(rec_v8_12->exaddr);

    }

  } /* for */

  return ftpdu->ftd.count;

} /* fts3rec_pdu_v8_12_decode */

/*
 * function: fts3rec_pdu_v8_13_decode
 *
 * subfunction to fts3rec_pdu_decode
 *
 * returns: # of stream records decoded
*/
int fts3rec_pdu_v8_13_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;
  struct ftpdu_v8_13 *pdu_v8_13;
  struct fts3rec_v8_13 *rec_v8_13;

  ftpdu->ftd.rec_size = sizeof (struct fts3rec_v8_13);
  pdu_v8_13 = (struct ftpdu_v8_13*)&ftpdu->buf;
  ph = (struct ftpdu_header*)&ftpdu->buf;

  /* preswap */
  if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(ph->sysUpTime);
    SWAPINT32(ph->unix_secs);
    SWAPINT32(ph->unix_nsecs);
  }

  for (n = 0; n < pdu_v8_13->count; ++n) {

    rec_v8_13 = (struct fts3rec_v8_13*) (ftpdu->ftd.buf +
      (n*ftpdu->ftd.rec_size));

    rec_v8_13->unix_nsecs = ph->unix_nsecs;
    rec_v8_13->unix_secs = ph->unix_secs;
    rec_v8_13->sysUpTime = ph->sysUpTime;

    rec_v8_13->engine_type = pdu_v8_13->engine_type;
    rec_v8_13->engine_type = pdu_v8_13->engine_id;

    rec_v8_13->dFlows = pdu_v8_13->records[n].dFlows;
    rec_v8_13->dPkts = pdu_v8_13->records[n].dPkts;
    rec_v8_13->dOctets = pdu_v8_13->records[n].dOctets;
    rec_v8_13->First = pdu_v8_13->records[n].First;
    rec_v8_13->Last = pdu_v8_13->records[n].Last;
    rec_v8_13->srcaddr = pdu_v8_13->records[n].src_prefix;
    rec_v8_13->dstaddr = pdu_v8_13->records[n].dst_prefix;
    rec_v8_13->src_mask = pdu_v8_13->records[n].src_mask;
    rec_v8_13->dst_mask = pdu_v8_13->records[n].dst_mask;
    rec_v8_13->tos = pdu_v8_13->records[n].tos;
    rec_v8_13->src_as = pdu_v8_13->records[n].src_as;
    rec_v8_13->dst_as = pdu_v8_13->records[n].dst_as;
    rec_v8_13->input = pdu_v8_13->records[n].input;
    rec_v8_13->output = pdu_v8_13->records[n].output;

    /* perform AS substitution */
    rec_v8_13->src_as = (rec_v8_13->src_as) ? rec_v8_13->src_as :
      ftpdu->ftd.as_sub;
    rec_v8_13->dst_as = (rec_v8_13->dst_as) ? rec_v8_13->dst_as :
      ftpdu->ftd.as_sub;

    /* copy in exporter IP */
    rec_v8_13->exaddr = ftpdu->ftd.exporter_ip;

    if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {

      SWAPINT32(rec_v8_13->dFlows);
      SWAPINT32(rec_v8_13->dPkts);
      SWAPINT32(rec_v8_13->dOctets);
      SWAPINT32(rec_v8_13->First);
      SWAPINT32(rec_v8_13->Last);
      SWAPINT32(rec_v8_13->srcaddr);
      SWAPINT32(rec_v8_13->dstaddr);
      SWAPINT16(rec_v8_13->src_as);
      SWAPINT16(rec_v8_13->dst_as);
      SWAPINT16(rec_v8_13->input);
      SWAPINT16(rec_v8_13->output);

      SWAPINT32(rec_v8_13->exaddr);

    }

  } /* for */

  return ftpdu->ftd.count;

} /* fts3rec_pdu_v8_13_decode */

/*
 * function: fts3rec_pdu_v8_14_decode
 *
 * subfunction to fts3rec_pdu_decode
 *
 * returns: # of stream records decoded
*/
int fts3rec_pdu_v8_14_decode(struct ftpdu *ftpdu)
{
  int n;
  struct ftpdu_header *ph;
  struct ftpdu_v8_14 *pdu_v8_14;
  struct fts3rec_v8_14 *rec_v8_14;

  ftpdu->ftd.rec_size = sizeof (struct fts3rec_v8_14);
  pdu_v8_14 = (struct ftpdu_v8_14*)&ftpdu->buf;
  ph = (struct ftpdu_header*)&ftpdu->buf;

  /* preswap */
  if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(ph->sysUpTime);
    SWAPINT32(ph->unix_secs);
    SWAPINT32(ph->unix_nsecs);
  }

  for (n = 0; n < pdu_v8_14->count; ++n) {

    rec_v8_14 = (struct fts3rec_v8_14*) (ftpdu->ftd.buf +
      (n*ftpdu->ftd.rec_size));

    rec_v8_14->unix_nsecs = ph->unix_nsecs;
    rec_v8_14->unix_secs = ph->unix_secs;
    rec_v8_14->sysUpTime = ph->sysUpTime;

    rec_v8_14->engine_type = pdu_v8_14->engine_type;
    rec_v8_14->engine_type = pdu_v8_14->engine_id;

    rec_v8_14->dFlows = pdu_v8_14->records[n].dFlows;
    rec_v8_14->dPkts = pdu_v8_14->records[n].dPkts;
    rec_v8_14->dOctets = pdu_v8_14->records[n].dOctets;
    rec_v8_14->First = pdu_v8_14->records[n].First;
    rec_v8_14->Last = pdu_v8_14->records[n].Last;
    rec_v8_14->srcaddr = pdu_v8_14->records[n].src_prefix;
    rec_v8_14->dstaddr = pdu_v8_14->records[n].dst_prefix;
    rec_v8_14->src_mask = pdu_v8_14->records[n].src_mask;
    rec_v8_14->dst_mask = pdu_v8_14->records[n].dst_mask;
    rec_v8_14->tos = pdu_v8_14->records[n].tos;
    rec_v8_14->prot = pdu_v8_14->records[n].prot;
    rec_v8_14->srcport = pdu_v8_14->records[n].srcport;
    rec_v8_14->dstport = pdu_v8_14->records[n].dstport;
    rec_v8_14->input = pdu_v8_14->records[n].input;
    rec_v8_14->output = pdu_v8_14->records[n].output;

    /* copy in exporter IP */
    rec_v8_14->exaddr = ftpdu->ftd.exporter_ip;

    if (ftpdu->ftd.byte_order == FT_HEADER_LITTLE_ENDIAN) {

      SWAPINT32(rec_v8_14->dFlows);
      SWAPINT32(rec_v8_14->dPkts);
      SWAPINT32(rec_v8_14->dOctets);
      SWAPINT32(rec_v8_14->First);
      SWAPINT32(rec_v8_14->Last);
      SWAPINT32(rec_v8_14->srcaddr);
      SWAPINT32(rec_v8_14->dstaddr);
      SWAPINT16(rec_v8_14->srcport);
      SWAPINT16(rec_v8_14->dstport);
      SWAPINT16(rec_v8_14->input);
      SWAPINT16(rec_v8_14->output);

      SWAPINT32(rec_v8_14->exaddr);

    }

  } /* for */

  return ftpdu->ftd.count;

} /* fts3rec_pdu_v8_14_decode */

