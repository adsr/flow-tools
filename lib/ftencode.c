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
 *      $Id: ftencode.c,v 1.13 2003/02/13 02:38:41 maf Exp $
 */

#include "ftconfig.h"
#include "ftlib.h"

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif

/*
 * function: ftencode_init
 * 
 * Initialize a ftencode structure, must be called before
 * first attempt to encode pdu with fts3rec_*_encode()
*/
void ftencode_init(struct ftencode *enc, int flags)
{

  bzero(enc, sizeof (struct ftencode));

  enc->flags = flags;

  if (enc->flags & FT_ENC_FLAGS_IPHDR)
    enc->buf_enc = (char*)&enc->buf + FT_ENC_IPHDR_LEN;
  else
    enc->buf_enc = (char*)&enc->buf;
  
} /* ftencode_init */

/*
 * function: ftencode_reset
 * 
 * Use between successive calls to f2s2rec_*_encode()
*/
void ftencode_reset(struct ftencode *enc)
{
  int len;

  if (enc->flags & FT_ENC_FLAGS_IPHDR)
    len = FT_IO_MAXENCODE -  FT_ENC_IPHDR_LEN;
  else
    len = FT_IO_MAXENCODE;

  bzero (enc->buf_enc, len);

  enc->buf_size = 0;

} /* ftencode_reset */

/*
 * function: ftencode_sum_data
 *          
 * calculate checksum of PDU (just the data)
 *
 */
void ftencode_sum_data(struct ftencode *enc)
{         
  int size;
  u_short *word;
  int sum;
  
  sum = 0;
  size = enc->buf_size;
  word = (u_short*)enc->buf_enc;
            
  for (size = enc->buf_size; size > 1; size -=2)
    sum += *word++;
            
  /* odd byte */
  if (size == 1)
    sum += htons(*(u_char*)word<<8);

  enc->d_sum = sum;

} /* ftencode_cksum_data */


/*
 * function: fts3rec_pdu_encode
 *
 * Encode any type f2s2rec_* into a PDU
 * wrapper function for other f2s2rec_pdu_*_encode
 *
 * Note ftencode_init() must be called on the ftencode
 * first, and ftencode_reset() must be called after each
 * PDU is processed by the caller before calling this
 * function again.
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_encode(struct ftencode *enc, void *rec)
{

  switch (enc->ver.d_version) {

    case 1:
      return (fts3rec_pdu_v1_encode(enc, (struct fts3rec_v1*)rec));
      break;

    case 5:
      return (fts3rec_pdu_v5_encode(enc, (struct fts3rec_v5*)rec));
      break;

    case 6:
      return (fts3rec_pdu_v6_encode(enc, (struct fts3rec_v6*)rec));
      break;

    case 7:
      return (fts3rec_pdu_v7_encode(enc, (struct fts3rec_v7*)rec));
      break;

    case 8:

      switch (enc->ver.agg_method) {

        case 1:
          return (fts3rec_pdu_v8_1_encode(enc, (struct fts3rec_v8_1*)rec));
          break;

        case 2:
          return (fts3rec_pdu_v8_2_encode(enc, (struct fts3rec_v8_2*)rec));
          break;

        case 3:
          return (fts3rec_pdu_v8_3_encode(enc, (struct fts3rec_v8_3*)rec));
          break;

        case 4:
          return (fts3rec_pdu_v8_4_encode(enc, (struct fts3rec_v8_4*)rec));
          break;

        case 5:
          return (fts3rec_pdu_v8_5_encode(enc, (struct fts3rec_v8_5*)rec));
          break;

        case 6:
          return (fts3rec_pdu_v8_6_encode(enc, (struct fts3rec_v8_6*)rec));
          break;

        case 7:
          return (fts3rec_pdu_v8_7_encode(enc, (struct fts3rec_v8_7*)rec));
          break;

        case 8:
          return (fts3rec_pdu_v8_8_encode(enc, (struct fts3rec_v8_8*)rec));
          break;

        case 9:
          return (fts3rec_pdu_v8_9_encode(enc, (struct fts3rec_v8_9*)rec));
          break;

        case 10:
          return (fts3rec_pdu_v8_10_encode(enc, (struct fts3rec_v8_10*)rec));
          break;

        case 11:
          return (fts3rec_pdu_v8_11_encode(enc, (struct fts3rec_v8_11*)rec));
          break;

        case 12:
          return (fts3rec_pdu_v8_12_encode(enc, (struct fts3rec_v8_12*)rec));
          break;

        case 13:
          return (fts3rec_pdu_v8_13_encode(enc, (struct fts3rec_v8_13*)rec));
          break;

        case 14:
          return (fts3rec_pdu_v8_14_encode(enc, (struct fts3rec_v8_14*)rec));
          break;

      } /* switch */
      break;

  } /* switch */

  return -1;

} /* fts3rec_pdu_encode */

/*
 * function: fts3rec_pdu_v1_encode
 *
 * Encode a fts3rec into a version 1 PDU
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_v1_encode(struct ftencode *enc, struct fts3rec_v1 *rec_v1)
{
  struct ftpdu_v1 *pdu_v1;
  int i;

  pdu_v1 = (struct ftpdu_v1*) enc->buf_enc;

  i = pdu_v1->count;

  /* space to encode more ? */
  if (i >= FT_PDU_V1_MAXFLOWS)
    return -1;

  /* if this is the first record, fill in the header */
  if (!i) {

    pdu_v1->version = 1;
    pdu_v1->sysUpTime = rec_v1->sysUpTime;
    pdu_v1->unix_secs = rec_v1->unix_secs;
    pdu_v1->unix_nsecs = rec_v1->unix_nsecs;
    enc->buf_size = 16; /* pdu header size */

  } else {

    /*  sysUpTime, unix_secs, and unix_nsecs must match for
     *  each pdu.  If a stream is being re-encoded this will normally
     *  work out fine, if the stream was sorted or changed in some way
     *  the PDU may only be able to hold one record.
    */

    if ((pdu_v1->sysUpTime != rec_v1->sysUpTime) ||
        (pdu_v1->unix_secs != rec_v1->unix_secs) ||
        (pdu_v1->unix_nsecs != rec_v1->unix_nsecs))
        return -1;

  }

  pdu_v1->records[i].srcaddr = rec_v1->srcaddr;
  pdu_v1->records[i].dstaddr = rec_v1->dstaddr;
  pdu_v1->records[i].nexthop = rec_v1->nexthop;
  pdu_v1->records[i].input = rec_v1->input;
  pdu_v1->records[i].output = rec_v1->output;
  pdu_v1->records[i].dPkts = rec_v1->dPkts;
  pdu_v1->records[i].dOctets = rec_v1->dOctets;
  pdu_v1->records[i].First = rec_v1->First;
  pdu_v1->records[i].Last = rec_v1->Last;
  pdu_v1->records[i].srcport = rec_v1->srcport;
  pdu_v1->records[i].dstport = rec_v1->dstport;
  pdu_v1->records[i].prot = rec_v1->prot;
  pdu_v1->records[i].tos = rec_v1->tos;
  pdu_v1->records[i].flags = rec_v1->tcp_flags;

  pdu_v1->count ++;
  enc->buf_size += sizeof (struct ftrec_v1);

  if (pdu_v1->count >= FT_PDU_V1_MAXFLOWS)
    return 0;
  else
    return 1;
}

/*
 * function: fts3rec_pdu_v5_encode
 *
 * Encode a fts3rec into a version 5 PDU
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_v5_encode(struct ftencode *enc, struct fts3rec_v5 *rec_v5)
{
  struct ftpdu_v5 *pdu_v5;
  u_int seq_index;
  int i;

  pdu_v5 = (struct ftpdu_v5*) enc->buf_enc;

  i = pdu_v5->count;

  /* index to sequence # */
  seq_index = rec_v5->engine_id<<8 | rec_v5->engine_type;

  /* space to encode more ? */
  if (i >= FT_PDU_V5_MAXFLOWS)
    return -1;

  /* if this is the first record, fill in the header */
  if (!i) {

    pdu_v5->version = 5;
    pdu_v5->sysUpTime = rec_v5->sysUpTime;
    pdu_v5->unix_secs = rec_v5->unix_secs;
    pdu_v5->unix_nsecs = rec_v5->unix_nsecs;
    pdu_v5->engine_type = rec_v5->engine_type;
    pdu_v5->engine_id = rec_v5->engine_id;
    pdu_v5->flow_sequence = enc->seq_next[seq_index];
    enc->buf_size = 24; /* pdu header size */

  } else {

    /*  sysUpTime, unix_secs, unix_nsecs, and engine_* must match for
     *  each pdu.  If a stream is being re-encoded this will normally
     *  work out fine, if the stream was sorted or changed in some way
     *  the PDU may only be able to hold one record.
    */

    if ((pdu_v5->sysUpTime != rec_v5->sysUpTime) ||
        (pdu_v5->unix_secs != rec_v5->unix_secs) ||
        (pdu_v5->unix_nsecs != rec_v5->unix_nsecs) ||
        (pdu_v5->engine_id != rec_v5->engine_id) ||
        (pdu_v5->engine_type != rec_v5->engine_type))
        return -1;

  }

  pdu_v5->records[i].srcaddr = rec_v5->srcaddr;
  pdu_v5->records[i].dstaddr = rec_v5->dstaddr;
  pdu_v5->records[i].nexthop = rec_v5->nexthop;
  pdu_v5->records[i].input = rec_v5->input;
  pdu_v5->records[i].output = rec_v5->output;
  pdu_v5->records[i].dPkts = rec_v5->dPkts;
  pdu_v5->records[i].dOctets = rec_v5->dOctets;
  pdu_v5->records[i].First = rec_v5->First;
  pdu_v5->records[i].Last = rec_v5->Last;
  pdu_v5->records[i].srcport = rec_v5->srcport;
  pdu_v5->records[i].dstport = rec_v5->dstport;
  pdu_v5->records[i].prot = rec_v5->prot;
  pdu_v5->records[i].tos = rec_v5->tos;
  pdu_v5->records[i].tcp_flags = rec_v5->tcp_flags;
  pdu_v5->records[i].src_as = rec_v5->src_as;
  pdu_v5->records[i].dst_as = rec_v5->dst_as;
  pdu_v5->records[i].src_mask = rec_v5->src_mask;
  pdu_v5->records[i].dst_mask = rec_v5->dst_mask;

  /* increment sequence # */
  enc->seq_next[seq_index]++;

  pdu_v5->count ++;
  enc->buf_size += sizeof (struct ftrec_v5);

  if (pdu_v5->count >= FT_PDU_V5_MAXFLOWS)
    return 0;
  else
    return 1;

} /* fts3rec_pdu_v5_encode */

/*
 * function: fts3rec_pdu_v6_encode
 *
 * Encode a fts3rec into a version 6 PDU
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_v6_encode(struct ftencode *enc, struct fts3rec_v6 *rec_v6)
{
  struct ftpdu_v6 *pdu_v6;
  u_int seq_index;
  int i;

  pdu_v6 = (struct ftpdu_v6*) enc->buf_enc;

  /* index to sequence # */
  seq_index = rec_v6->engine_id<<8 | rec_v6->engine_type;

  i = pdu_v6->count;

  /* space to encode more ? */
  if (i >= FT_PDU_V6_MAXFLOWS)
    return -1;

  /* if this is the first record, fill in the header */
  if (!i) {

    pdu_v6->version = 6;
    pdu_v6->sysUpTime = rec_v6->sysUpTime;
    pdu_v6->unix_secs = rec_v6->unix_secs;
    pdu_v6->unix_nsecs = rec_v6->unix_nsecs;
    pdu_v6->engine_type = rec_v6->engine_type;
    pdu_v6->engine_id = rec_v6->engine_id;
    pdu_v6->flow_sequence = enc->seq_next[seq_index];
    enc->buf_size = 24; /* pdu header size */

  } else {

    /*  sysUpTime, unix_secs, unix_nsecs, and engine_* must match for
     *  each pdu.  If a stream is being re-encoded this will normally
     *  work out fine, if the stream was sorted or changed in some way
     *  the PDU may only be able to hold one record.
    */

    if ((pdu_v6->sysUpTime != rec_v6->sysUpTime) ||
        (pdu_v6->unix_secs != rec_v6->unix_secs) ||
        (pdu_v6->unix_nsecs != rec_v6->unix_nsecs) ||
        (pdu_v6->engine_id != rec_v6->engine_id) ||
        (pdu_v6->engine_type != rec_v6->engine_type))
        return -1;

  }

  pdu_v6->records[i].srcaddr = rec_v6->srcaddr;
  pdu_v6->records[i].dstaddr = rec_v6->dstaddr;
  pdu_v6->records[i].nexthop = rec_v6->nexthop;
  pdu_v6->records[i].input = rec_v6->input;
  pdu_v6->records[i].output = rec_v6->output;
  pdu_v6->records[i].dPkts = rec_v6->dPkts;
  pdu_v6->records[i].dOctets = rec_v6->dOctets;
  pdu_v6->records[i].First = rec_v6->First;
  pdu_v6->records[i].Last = rec_v6->Last;
  pdu_v6->records[i].srcport = rec_v6->srcport;
  pdu_v6->records[i].dstport = rec_v6->dstport;
  pdu_v6->records[i].prot = rec_v6->prot;
  pdu_v6->records[i].tos = rec_v6->tos;
  pdu_v6->records[i].tcp_flags = rec_v6->tcp_flags;
  pdu_v6->records[i].src_as = rec_v6->src_as;
  pdu_v6->records[i].dst_as = rec_v6->dst_as;
  pdu_v6->records[i].src_mask = rec_v6->src_mask;
  pdu_v6->records[i].dst_mask = rec_v6->dst_mask;
  pdu_v6->records[i].in_encaps = rec_v6->in_encaps;
  pdu_v6->records[i].out_encaps = rec_v6->out_encaps;
  pdu_v6->records[i].peer_nexthop = rec_v6->peer_nexthop;

  /* increment sequence # */
  enc->seq_next[seq_index]++;

  pdu_v6->count ++;
  enc->buf_size += sizeof (struct ftrec_v6);

  if (pdu_v6->count >= FT_PDU_V6_MAXFLOWS)
    return 0;
  else
    return 1;
}

/*
 * function: fts3rec_pdu_v7_encode
 *
 * Encode a fts3rec into a version 7 PDU
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_v7_encode(struct ftencode *enc, struct fts3rec_v7 *rec_v7)
{
  struct ftpdu_v7 *pdu_v7;
  u_int seq_index;
  int i;

  pdu_v7 = (struct ftpdu_v7*) enc->buf_enc;

  /* index to sequence # */
  seq_index = rec_v7->engine_id<<8 | rec_v7->engine_type;

  i = pdu_v7->count;

  /* space to encode more ? */
  if (i >= FT_PDU_V7_MAXFLOWS)
    return -1;

  /* if this is the first record, fill in the header */
  if (!i) {

    pdu_v7->version = 7;
    pdu_v7->sysUpTime = rec_v7->sysUpTime;
    pdu_v7->unix_secs = rec_v7->unix_secs;
    pdu_v7->unix_nsecs = rec_v7->unix_nsecs;
    pdu_v7->engine_type = rec_v7->engine_type;
    pdu_v7->engine_id = rec_v7->engine_id;
    pdu_v7->flow_sequence = enc->seq_next[seq_index];
    enc->buf_size = 24; /* pdu header size */

  } else {

    /*  sysUpTime, unix_secs, unix_nsecs, and engine_* must match for
     *  each pdu.  If a stream is being re-encoded this will normally
     *  work out fine, if the stream was sorted or changed in some way
     *  the PDU may only be able to hold one record.
    */

    if ((pdu_v7->sysUpTime != rec_v7->sysUpTime) ||
        (pdu_v7->unix_secs != rec_v7->unix_secs) ||
        (pdu_v7->unix_nsecs != rec_v7->unix_nsecs) ||
        (pdu_v7->engine_id != rec_v7->engine_id) ||
        (pdu_v7->engine_type != rec_v7->engine_type))
        return -1;

  }

  pdu_v7->records[i].srcaddr = rec_v7->srcaddr;
  pdu_v7->records[i].dstaddr = rec_v7->dstaddr;
  pdu_v7->records[i].nexthop = rec_v7->nexthop;
  pdu_v7->records[i].input = rec_v7->input;
  pdu_v7->records[i].output = rec_v7->output;
  pdu_v7->records[i].dPkts = rec_v7->dPkts;
  pdu_v7->records[i].dOctets = rec_v7->dOctets;
  pdu_v7->records[i].First = rec_v7->First;
  pdu_v7->records[i].Last = rec_v7->Last;
  pdu_v7->records[i].srcport = rec_v7->srcport;
  pdu_v7->records[i].dstport = rec_v7->dstport;
  pdu_v7->records[i].prot = rec_v7->prot;
  pdu_v7->records[i].tos = rec_v7->tos;
  pdu_v7->records[i].tcp_flags = rec_v7->tcp_flags;
  pdu_v7->records[i].src_as = rec_v7->src_as;
  pdu_v7->records[i].dst_as = rec_v7->dst_as;
  pdu_v7->records[i].src_mask = rec_v7->src_mask;
  pdu_v7->records[i].dst_mask = rec_v7->dst_mask;
  pdu_v7->records[i].router_sc = rec_v7->router_sc;

  /* increment sequence # */
  enc->seq_next[seq_index]++;

  pdu_v7->count ++;
  enc->buf_size += sizeof (struct ftrec_v7);

  if (pdu_v7->count >= FT_PDU_V7_MAXFLOWS)
    return 0;
  else
    return 1;
}

/*
 * function: fts3rec_pdu_v8_1_encode
 *
 * Encode a fts3rec into a version 8 Agg method 1
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_v8_1_encode(struct ftencode *enc,
  struct fts3rec_v8_1 *rec_v8_1)
{
  struct ftpdu_v8_1 *pdu_v8_1;
  u_int seq_index;
  int i;

  pdu_v8_1 = (struct ftpdu_v8_1*) enc->buf_enc;

  /* index to sequence # */
  seq_index = rec_v8_1->engine_id<<8 | rec_v8_1->engine_type;

  i = pdu_v8_1->count;

  /* space to encode more ? */
  if (i >= FT_PDU_V8_1_MAXFLOWS)
    return -1;

  /* if this is the first record, fill in the header */
  if (!i) {

    pdu_v8_1->version = 8;
    pdu_v8_1->sysUpTime = rec_v8_1->sysUpTime;
    pdu_v8_1->unix_secs = rec_v8_1->unix_secs;
    pdu_v8_1->unix_nsecs = rec_v8_1->unix_nsecs;
    pdu_v8_1->engine_type = rec_v8_1->engine_type;
    pdu_v8_1->engine_id = rec_v8_1->engine_id;
    pdu_v8_1->aggregation = 1;
    pdu_v8_1->agg_version = 2;
    pdu_v8_1->flow_sequence = enc->seq_next[seq_index];
    enc->buf_size = 28; /* pdu header size */

  } else {

    /*  sysUpTime, unix_secs, unix_nsecs, and engine_* must match for
     *  each pdu.  If a stream is being re-encoded this will normally
     *  work out fine, if the stream was sorted or changed in some way
     *  the PDU may only be able to hold one record.
    */

    if ((pdu_v8_1->sysUpTime != rec_v8_1->sysUpTime) ||
        (pdu_v8_1->unix_secs != rec_v8_1->unix_secs) ||
        (pdu_v8_1->unix_nsecs != rec_v8_1->unix_nsecs) ||
        (pdu_v8_1->engine_id != rec_v8_1->engine_id) ||
        (pdu_v8_1->engine_type != rec_v8_1->engine_type))
        return -1;

  }

  pdu_v8_1->records[i].dFlows = rec_v8_1->dFlows;
  pdu_v8_1->records[i].dPkts = rec_v8_1->dPkts;
  pdu_v8_1->records[i].dOctets = rec_v8_1->dOctets;
  pdu_v8_1->records[i].First = rec_v8_1->First;
  pdu_v8_1->records[i].Last = rec_v8_1->Last;
  pdu_v8_1->records[i].src_as = rec_v8_1->src_as;
  pdu_v8_1->records[i].dst_as = rec_v8_1->dst_as;
  pdu_v8_1->records[i].input = rec_v8_1->input;
  pdu_v8_1->records[i].output = rec_v8_1->output;

  /* increment sequence # */
  enc->seq_next[seq_index]++;

  pdu_v8_1->count ++;
  enc->buf_size += sizeof (struct ftrec_v8_1);

  if (pdu_v8_1->count >= FT_PDU_V8_1_MAXFLOWS)
    return 0;
  else
    return 1;
} /* fts3rec_pdu_v8_1_encode */

/*
 * function: fts3rec_pdu_v8_2_encode
 *
 * Encode a fts3rec into a version 8 Agg method 2
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_v8_2_encode(struct ftencode *enc,
  struct fts3rec_v8_2 *rec_v8_2)
{
  struct ftpdu_v8_2 *pdu_v8_2;
  u_int seq_index;
  int i;

  pdu_v8_2 = (struct ftpdu_v8_2*) enc->buf_enc;

  /* index to sequence # */
  seq_index = rec_v8_2->engine_id<<8 | rec_v8_2->engine_type;

  i = pdu_v8_2->count;

  /* space to encode more ? */
  if (i >= FT_PDU_V8_2_MAXFLOWS)
    return -1;

  /* if this is the first record, fill in the header */
  if (!i) {

    pdu_v8_2->version = 8;
    pdu_v8_2->sysUpTime = rec_v8_2->sysUpTime;
    pdu_v8_2->unix_secs = rec_v8_2->unix_secs;
    pdu_v8_2->unix_nsecs = rec_v8_2->unix_nsecs;
    pdu_v8_2->engine_type = rec_v8_2->engine_type;
    pdu_v8_2->engine_id = rec_v8_2->engine_id;
    pdu_v8_2->aggregation = 2;
    pdu_v8_2->agg_version = 2;
    pdu_v8_2->flow_sequence = enc->seq_next[seq_index];
    enc->buf_size = 28; /* pdu header size */

  } else {

    /*  sysUpTime, unix_secs, unix_nsecs, and engine_* must match for
     *  each pdu.  If a stream is being re-encoded this will normally
     *  work out fine, if the stream was sorted or changed in some way
     *  the PDU may only be able to hold one record.
    */

    if ((pdu_v8_2->sysUpTime != rec_v8_2->sysUpTime) ||
        (pdu_v8_2->unix_secs != rec_v8_2->unix_secs) ||
        (pdu_v8_2->unix_nsecs != rec_v8_2->unix_nsecs) ||
        (pdu_v8_2->engine_id != rec_v8_2->engine_id) ||
        (pdu_v8_2->engine_type != rec_v8_2->engine_type))
        return -1;

  }

  pdu_v8_2->records[i].dFlows = rec_v8_2->dFlows;
  pdu_v8_2->records[i].dPkts = rec_v8_2->dPkts;
  pdu_v8_2->records[i].dOctets = rec_v8_2->dOctets;
  pdu_v8_2->records[i].First = rec_v8_2->First;
  pdu_v8_2->records[i].Last = rec_v8_2->Last;
  pdu_v8_2->records[i].prot = rec_v8_2->prot;
  pdu_v8_2->records[i].srcport = rec_v8_2->srcport;
  pdu_v8_2->records[i].dstport = rec_v8_2->dstport;

  /* increment sequence # */
  enc->seq_next[seq_index]++;

  pdu_v8_2->count ++;
  enc->buf_size += sizeof (struct ftrec_v8_2);

  if (pdu_v8_2->count >= FT_PDU_V8_2_MAXFLOWS)
    return 0;
  else
    return 1;
} /* fts3rec_pdu_v8_2_encode */

/*
 * function: fts3rec_pdu_v8_3_encode
 *
 * Encode a fts3rec into a version 8 Agg method 3
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_v8_3_encode(struct ftencode *enc,
  struct fts3rec_v8_3 *rec_v8_3)
{
  struct ftpdu_v8_3 *pdu_v8_3;
  u_int seq_index;
  int i;

  pdu_v8_3 = (struct ftpdu_v8_3*) enc->buf_enc;

  /* index to sequence # */
  seq_index = rec_v8_3->engine_id<<8 | rec_v8_3->engine_type;

  i = pdu_v8_3->count;

  /* space to encode more ? */
  if (i >= FT_PDU_V8_3_MAXFLOWS)
    return -1;

  /* if this is the first record, fill in the header */
  if (!i) {

    pdu_v8_3->version = 8;
    pdu_v8_3->sysUpTime = rec_v8_3->sysUpTime;
    pdu_v8_3->unix_secs = rec_v8_3->unix_secs;
    pdu_v8_3->unix_nsecs = rec_v8_3->unix_nsecs;
    pdu_v8_3->engine_type = rec_v8_3->engine_type;
    pdu_v8_3->engine_id = rec_v8_3->engine_id;
    pdu_v8_3->aggregation = 3;
    pdu_v8_3->agg_version = 2;
    pdu_v8_3->flow_sequence = enc->seq_next[seq_index];
    enc->buf_size = 28; /* pdu header size */

  } else {

    /*  sysUpTime, unix_secs, unix_nsecs, and engine_* must match for
     *  each pdu.  If a stream is being re-encoded this will normally
     *  work out fine, if the stream was sorted or changed in some way
     *  the PDU may only be able to hold one record.
    */

    if ((pdu_v8_3->sysUpTime != rec_v8_3->sysUpTime) ||
        (pdu_v8_3->unix_secs != rec_v8_3->unix_secs) ||
        (pdu_v8_3->unix_nsecs != rec_v8_3->unix_nsecs) ||
        (pdu_v8_3->engine_id != rec_v8_3->engine_id) ||
        (pdu_v8_3->engine_type != rec_v8_3->engine_type))
        return -1;

  }

  pdu_v8_3->records[i].dFlows = rec_v8_3->dFlows;
  pdu_v8_3->records[i].dPkts = rec_v8_3->dPkts;
  pdu_v8_3->records[i].dOctets = rec_v8_3->dOctets;
  pdu_v8_3->records[i].First = rec_v8_3->First;
  pdu_v8_3->records[i].Last = rec_v8_3->Last;
  pdu_v8_3->records[i].src_prefix = rec_v8_3->srcaddr;
  pdu_v8_3->records[i].src_mask = rec_v8_3->src_mask;
  pdu_v8_3->records[i].src_as = rec_v8_3->src_as;
  pdu_v8_3->records[i].input = rec_v8_3->input;

  /* increment sequence # */
  enc->seq_next[seq_index]++;

  pdu_v8_3->count ++;
  enc->buf_size += sizeof (struct ftrec_v8_3);

  if (pdu_v8_3->count >= FT_PDU_V8_3_MAXFLOWS)
    return 0;
  else
    return 1;
} /* fts3rec_pdu_v8_3_encode */

/*
 * function: fts3rec_pdu_v8_4_encode
 *
 * Encode a fts3rec into a version 8 Agg method 4
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_v8_4_encode(struct ftencode *enc,
  struct fts3rec_v8_4 *rec_v8_4)
{
  struct ftpdu_v8_4 *pdu_v8_4;
  u_int seq_index;
  int i;

  pdu_v8_4 = (struct ftpdu_v8_4*) enc->buf_enc;

  /* index to sequence # */
  seq_index = rec_v8_4->engine_id<<8 | rec_v8_4->engine_type;

  i = pdu_v8_4->count;

  /* space to encode more ? */
  if (i >= FT_PDU_V8_4_MAXFLOWS)
    return -1;

  /* if this is the first record, fill in the header */
  if (!i) {

    pdu_v8_4->version = 8;
    pdu_v8_4->sysUpTime = rec_v8_4->sysUpTime;
    pdu_v8_4->unix_secs = rec_v8_4->unix_secs;
    pdu_v8_4->unix_nsecs = rec_v8_4->unix_nsecs;
    pdu_v8_4->engine_type = rec_v8_4->engine_type;
    pdu_v8_4->engine_id = rec_v8_4->engine_id;
    pdu_v8_4->aggregation = 4;
    pdu_v8_4->agg_version = 2;
    pdu_v8_4->flow_sequence = enc->seq_next[seq_index];
    enc->buf_size = 28; /* pdu header size */

  } else {

    /*  sysUpTime, unix_secs, unix_nsecs, and engine_* must match for
     *  each pdu.  If a stream is being re-encoded this will normally
     *  work out fine, if the stream was sorted or changed in some way
     *  the PDU may only be able to hold one record.
    */

    if ((pdu_v8_4->sysUpTime != rec_v8_4->sysUpTime) ||
        (pdu_v8_4->unix_secs != rec_v8_4->unix_secs) ||
        (pdu_v8_4->unix_nsecs != rec_v8_4->unix_nsecs) ||
        (pdu_v8_4->engine_id != rec_v8_4->engine_id) ||
        (pdu_v8_4->engine_type != rec_v8_4->engine_type))
        return -1;

  }

  pdu_v8_4->records[i].dFlows = rec_v8_4->dFlows;
  pdu_v8_4->records[i].dPkts = rec_v8_4->dPkts;
  pdu_v8_4->records[i].dOctets = rec_v8_4->dOctets;
  pdu_v8_4->records[i].First = rec_v8_4->First;
  pdu_v8_4->records[i].Last = rec_v8_4->Last;
  pdu_v8_4->records[i].dst_prefix = rec_v8_4->dstaddr;
  pdu_v8_4->records[i].dst_mask = rec_v8_4->dst_mask;
  pdu_v8_4->records[i].dst_as = rec_v8_4->dst_as;
  pdu_v8_4->records[i].output = rec_v8_4->output;

  /* increment sequence # */
  enc->seq_next[seq_index]++;

  pdu_v8_4->count ++;
  enc->buf_size += sizeof (struct ftrec_v8_4);

  if (pdu_v8_4->count >= FT_PDU_V8_4_MAXFLOWS)
    return 0;
  else
    return 1;
} /* fts3rec_pdu_v8_4_encode */

/*
 * function: fts3rec_pdu_v8_5_encode
 *
 * Encode a fts3rec into a version 8 Agg method 5
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_v8_5_encode(struct ftencode *enc,
  struct fts3rec_v8_5 *rec_v8_5)
{
  struct ftpdu_v8_5 *pdu_v8_5;
  u_int seq_index;
  int i;

  pdu_v8_5 = (struct ftpdu_v8_5*) enc->buf_enc;

  /* index to sequence # */
  seq_index = rec_v8_5->engine_id<<8 | rec_v8_5->engine_type;

  i = pdu_v8_5->count;

  /* space to encode more ? */
  if (i >= FT_PDU_V8_5_MAXFLOWS)
    return -1;

  /* if this is the first record, fill in the header */
  if (!i) {

    pdu_v8_5->version = 8;
    pdu_v8_5->sysUpTime = rec_v8_5->sysUpTime;
    pdu_v8_5->unix_secs = rec_v8_5->unix_secs;
    pdu_v8_5->unix_nsecs = rec_v8_5->unix_nsecs;
    pdu_v8_5->engine_type = rec_v8_5->engine_type;
    pdu_v8_5->engine_id = rec_v8_5->engine_id;
    pdu_v8_5->aggregation = 5;
    pdu_v8_5->agg_version = 2;
    pdu_v8_5->flow_sequence = enc->seq_next[seq_index];
    enc->buf_size = 28; /* pdu header size */

  } else {

    /*  sysUpTime, unix_secs, unix_nsecs, and engine_* must match for
     *  each pdu.  If a stream is being re-encoded this will normally
     *  work out fine, if the stream was sorted or changed in some way
     *  the PDU may only be able to hold one record.
    */

    if ((pdu_v8_5->sysUpTime != rec_v8_5->sysUpTime) ||
        (pdu_v8_5->unix_secs != rec_v8_5->unix_secs) ||
        (pdu_v8_5->unix_nsecs != rec_v8_5->unix_nsecs) ||
        (pdu_v8_5->engine_id != rec_v8_5->engine_id) ||
        (pdu_v8_5->engine_type != rec_v8_5->engine_type))
        return -1;

  }

  pdu_v8_5->records[i].dFlows = rec_v8_5->dFlows;
  pdu_v8_5->records[i].dPkts = rec_v8_5->dPkts;
  pdu_v8_5->records[i].dOctets = rec_v8_5->dOctets;
  pdu_v8_5->records[i].First = rec_v8_5->First;
  pdu_v8_5->records[i].Last = rec_v8_5->Last;
  pdu_v8_5->records[i].src_prefix = rec_v8_5->srcaddr;
  pdu_v8_5->records[i].dst_prefix = rec_v8_5->dstaddr;
  pdu_v8_5->records[i].dst_mask = rec_v8_5->dst_mask;
  pdu_v8_5->records[i].src_mask = rec_v8_5->src_mask;
  pdu_v8_5->records[i].src_as = rec_v8_5->src_as;
  pdu_v8_5->records[i].dst_as = rec_v8_5->dst_as;
  pdu_v8_5->records[i].input = rec_v8_5->input;
  pdu_v8_5->records[i].output = rec_v8_5->output;

  /* increment sequence # */
  enc->seq_next[seq_index]++;

  pdu_v8_5->count ++;
  enc->buf_size += sizeof (struct ftrec_v8_5);

  if (pdu_v8_5->count >= FT_PDU_V8_5_MAXFLOWS)
    return 0;
  else
    return 1;
} /* fts3rec_pdu_v8_5_encode */


/*
 * function: fts3rec_pdu_v8_6_encode
 *
 * Encode a fts3rec into a version 8 Agg method 6
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_v8_6_encode(struct ftencode *enc,
  struct fts3rec_v8_6 *rec_v8_6)
{
  struct ftpdu_v8_6 *pdu_v8_6;
  u_int seq_index;
  int i;

  pdu_v8_6 = (struct ftpdu_v8_6*) enc->buf_enc;

  /* index to sequence # */
  seq_index = rec_v8_6->engine_id<<8 | rec_v8_6->engine_type;

  i = pdu_v8_6->count;

  /* space to encode more ? */
  if (i >= FT_PDU_V8_6_MAXFLOWS)
    return -1;

  /* if this is the first record, fill in the header */
  if (!i) {

    pdu_v8_6->version = 8;
    pdu_v8_6->sysUpTime = rec_v8_6->sysUpTime;
    pdu_v8_6->unix_secs = rec_v8_6->unix_secs;
    pdu_v8_6->unix_nsecs = rec_v8_6->unix_nsecs;
    pdu_v8_6->engine_type = rec_v8_6->engine_type;
    pdu_v8_6->engine_id = rec_v8_6->engine_id;
    pdu_v8_6->aggregation = 6;
    pdu_v8_6->agg_version = 2;
    pdu_v8_6->flow_sequence = enc->seq_next[seq_index];
    enc->buf_size = 28; /* pdu header size */

  } else {

    /*  sysUpTime, unix_secs, unix_nsecs, and engine_* must match for
     *  each pdu.  If a stream is being re-encoded this will normally
     *  work out fine, if the stream was sorted or changed in some way
     *  the PDU may only be able to hold one record.
    */

    if ((pdu_v8_6->sysUpTime != rec_v8_6->sysUpTime) ||
        (pdu_v8_6->unix_secs != rec_v8_6->unix_secs) ||
        (pdu_v8_6->unix_nsecs != rec_v8_6->unix_nsecs) ||
        (pdu_v8_6->engine_id != rec_v8_6->engine_id) ||
        (pdu_v8_6->engine_type != rec_v8_6->engine_type))
        return -1;

  }

  pdu_v8_6->records[i].dstaddr = rec_v8_6->dstaddr;
  pdu_v8_6->records[i].dPkts = rec_v8_6->dPkts;
  pdu_v8_6->records[i].dOctets = rec_v8_6->dOctets;
  pdu_v8_6->records[i].First = rec_v8_6->First;
  pdu_v8_6->records[i].Last = rec_v8_6->Last;
  pdu_v8_6->records[i].output = rec_v8_6->output;
  pdu_v8_6->records[i].tos = rec_v8_6->tos;
  pdu_v8_6->records[i].marked_tos = rec_v8_6->marked_tos;
  pdu_v8_6->records[i].extra_pkts = rec_v8_6->extra_pkts;
  pdu_v8_6->records[i].router_sc = rec_v8_6->router_sc;

  /* increment sequence # */
  enc->seq_next[seq_index]++;

  pdu_v8_6->count ++;
  enc->buf_size += sizeof (struct ftrec_v8_6);

  if (pdu_v8_6->count >= FT_PDU_V8_6_MAXFLOWS)
    return 0;
  else
    return 1;
} /* fts3rec_pdu_v8_6_encode */

/*
 * function: fts3rec_pdu_v8_7_encode
 *
 * Encode a fts3rec into a version 8 Agg method 7
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_v8_7_encode(struct ftencode *enc,
  struct fts3rec_v8_7 *rec_v8_7)
{
  struct ftpdu_v8_7 *pdu_v8_7;
  u_int seq_index;
  int i;

  pdu_v8_7 = (struct ftpdu_v8_7*) enc->buf_enc;

  /* index to sequence # */
  seq_index = rec_v8_7->engine_id<<8 | rec_v8_7->engine_type;

  i = pdu_v8_7->count;

  /* space to encode more ? */
  if (i >= FT_PDU_V8_7_MAXFLOWS)
    return -1;

  /* if this is the first record, fill in the header */
  if (!i) {

    pdu_v8_7->version = 8;
    pdu_v8_7->sysUpTime = rec_v8_7->sysUpTime;
    pdu_v8_7->unix_secs = rec_v8_7->unix_secs;
    pdu_v8_7->unix_nsecs = rec_v8_7->unix_nsecs;
    pdu_v8_7->engine_type = rec_v8_7->engine_type;
    pdu_v8_7->engine_id = rec_v8_7->engine_id;
    pdu_v8_7->aggregation = 7;
    pdu_v8_7->agg_version = 2;
    pdu_v8_7->flow_sequence = enc->seq_next[seq_index];
    enc->buf_size = 28; /* pdu header size */

  } else {

    /*  sysUpTime, unix_secs, unix_nsecs, and engine_* must match for
     *  each pdu.  If a stream is being re-encoded this will normally
     *  work out fine, if the stream was sorted or changed in some way
     *  the PDU may only be able to hold one record.
    */

    if ((pdu_v8_7->sysUpTime != rec_v8_7->sysUpTime) ||
        (pdu_v8_7->unix_secs != rec_v8_7->unix_secs) ||
        (pdu_v8_7->unix_nsecs != rec_v8_7->unix_nsecs) ||
        (pdu_v8_7->engine_id != rec_v8_7->engine_id) ||
        (pdu_v8_7->engine_type != rec_v8_7->engine_type))
        return -1;

  }

  pdu_v8_7->records[i].dstaddr = rec_v8_7->dstaddr;
  pdu_v8_7->records[i].srcaddr = rec_v8_7->srcaddr;
  pdu_v8_7->records[i].dPkts = rec_v8_7->dPkts;
  pdu_v8_7->records[i].dOctets = rec_v8_7->dOctets;
  pdu_v8_7->records[i].First = rec_v8_7->First;
  pdu_v8_7->records[i].Last = rec_v8_7->Last;
  pdu_v8_7->records[i].output = rec_v8_7->output;
  pdu_v8_7->records[i].input = rec_v8_7->input;
  pdu_v8_7->records[i].tos = rec_v8_7->tos;
  pdu_v8_7->records[i].marked_tos = rec_v8_7->marked_tos;
  pdu_v8_7->records[i].extra_pkts = rec_v8_7->extra_pkts;
  pdu_v8_7->records[i].router_sc = rec_v8_7->router_sc;

  /* increment sequence # */
  enc->seq_next[seq_index]++;

  pdu_v8_7->count ++;
  enc->buf_size += sizeof (struct ftrec_v8_7);

  if (pdu_v8_7->count >= FT_PDU_V8_7_MAXFLOWS)
    return 0;
  else
    return 1;
} /* fts3rec_pdu_v8_7_encode */

/*
 * function: fts3rec_pdu_v8_8_encode
 *
 * Encode a fts3rec into a version 8 Agg method 8
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_v8_8_encode(struct ftencode *enc,
  struct fts3rec_v8_8 *rec_v8_8)
{
  struct ftpdu_v8_8 *pdu_v8_8;
  u_int seq_index;
  int i;

  pdu_v8_8 = (struct ftpdu_v8_8*) enc->buf_enc;

  /* index to sequence # */
  seq_index = rec_v8_8->engine_id<<8 | rec_v8_8->engine_type;

  i = pdu_v8_8->count;

  /* space to encode more ? */
  if (i >= FT_PDU_V8_8_MAXFLOWS)
    return -1;

  /* if this is the first record, fill in the header */
  if (!i) {

    pdu_v8_8->version = 8;
    pdu_v8_8->sysUpTime = rec_v8_8->sysUpTime;
    pdu_v8_8->unix_secs = rec_v8_8->unix_secs;
    pdu_v8_8->unix_nsecs = rec_v8_8->unix_nsecs;
    pdu_v8_8->engine_type = rec_v8_8->engine_type;
    pdu_v8_8->engine_id = rec_v8_8->engine_id;
    pdu_v8_8->aggregation = 8;
    pdu_v8_8->agg_version = 2;
    pdu_v8_8->flow_sequence = enc->seq_next[seq_index];
    enc->buf_size = 28; /* pdu header size */

  } else {

    /*  sysUpTime, unix_secs, unix_nsecs, and engine_* must match for
     *  each pdu.  If a stream is being re-encoded this will normally
     *  work out fine, if the stream was sorted or changed in some way
     *  the PDU may only be able to hold one record.
    */

    if ((pdu_v8_8->sysUpTime != rec_v8_8->sysUpTime) ||
        (pdu_v8_8->unix_secs != rec_v8_8->unix_secs) ||
        (pdu_v8_8->unix_nsecs != rec_v8_8->unix_nsecs) ||
        (pdu_v8_8->engine_id != rec_v8_8->engine_id) ||
        (pdu_v8_8->engine_type != rec_v8_8->engine_type))
        return -1;

  }

  pdu_v8_8->records[i].dstaddr = rec_v8_8->dstaddr;
  pdu_v8_8->records[i].srcaddr = rec_v8_8->srcaddr;
  pdu_v8_8->records[i].dstport = rec_v8_8->dstport;
  pdu_v8_8->records[i].srcport = rec_v8_8->srcport;
  pdu_v8_8->records[i].dPkts = rec_v8_8->dPkts;
  pdu_v8_8->records[i].dOctets = rec_v8_8->dOctets;
  pdu_v8_8->records[i].First = rec_v8_8->First;
  pdu_v8_8->records[i].Last = rec_v8_8->Last;
  pdu_v8_8->records[i].output = rec_v8_8->output;
  pdu_v8_8->records[i].input = rec_v8_8->input;
  pdu_v8_8->records[i].tos = rec_v8_8->tos;
  pdu_v8_8->records[i].marked_tos = rec_v8_8->marked_tos;
  pdu_v8_8->records[i].extra_pkts = rec_v8_8->extra_pkts;
  pdu_v8_8->records[i].router_sc = rec_v8_8->router_sc;

  /* increment sequence # */
  enc->seq_next[seq_index]++;

  pdu_v8_8->count ++;
  enc->buf_size += sizeof (struct ftrec_v8_8);

  if (pdu_v8_8->count >= FT_PDU_V8_8_MAXFLOWS)
    return 0;
  else
    return 1;
} /* fts3rec_pdu_v8_8_encode */

/*
 * function: fts3rec_pdu_v8_9_encode
 *
 * Encode a fts3rec into a version 8 Agg method 9
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_v8_9_encode(struct ftencode *enc,
  struct fts3rec_v8_9 *rec_v8_9)
{
  struct ftpdu_v8_9 *pdu_v8_9;
  u_int seq_index;
  int i;

  pdu_v8_9 = (struct ftpdu_v8_9*) enc->buf_enc;

  /* index to sequence # */
  seq_index = rec_v8_9->engine_id<<8 | rec_v8_9->engine_type;

  i = pdu_v8_9->count;

  /* space to encode more ? */
  if (i >= FT_PDU_V8_9_MAXFLOWS)
    return -1;

  /* if this is the first record, fill in the header */
  if (!i) {

    pdu_v8_9->version = 8;
    pdu_v8_9->sysUpTime = rec_v8_9->sysUpTime;
    pdu_v8_9->unix_secs = rec_v8_9->unix_secs;
    pdu_v8_9->unix_nsecs = rec_v8_9->unix_nsecs;
    pdu_v8_9->engine_type = rec_v8_9->engine_type;
    pdu_v8_9->engine_id = rec_v8_9->engine_id;
    pdu_v8_9->aggregation = 9;
    pdu_v8_9->agg_version = 2;
    pdu_v8_9->flow_sequence = enc->seq_next[seq_index];
    enc->buf_size = 28; /* pdu header size */

  } else {

    /*  sysUpTime, unix_secs, unix_nsecs, and engine_* must match for
     *  each pdu.  If a stream is being re-encoded this will normally
     *  work out fine, if the stream was sorted or changed in some way
     *  the PDU may only be able to hold one record.
    */

    if ((pdu_v8_9->sysUpTime != rec_v8_9->sysUpTime) ||
        (pdu_v8_9->unix_secs != rec_v8_9->unix_secs) ||
        (pdu_v8_9->unix_nsecs != rec_v8_9->unix_nsecs) ||
        (pdu_v8_9->engine_id != rec_v8_9->engine_id) ||
        (pdu_v8_9->engine_type != rec_v8_9->engine_type))
        return -1;

  }

  pdu_v8_9->records[i].dFlows = rec_v8_9->dFlows;
  pdu_v8_9->records[i].dPkts = rec_v8_9->dPkts;
  pdu_v8_9->records[i].dOctets = rec_v8_9->dOctets;
  pdu_v8_9->records[i].First = rec_v8_9->First;
  pdu_v8_9->records[i].Last = rec_v8_9->Last;
  pdu_v8_9->records[i].src_as = rec_v8_9->src_as;
  pdu_v8_9->records[i].dst_as = rec_v8_9->dst_as;
  pdu_v8_9->records[i].input = rec_v8_9->input;
  pdu_v8_9->records[i].output = rec_v8_9->output;
  pdu_v8_9->records[i].tos = rec_v8_9->tos;

  /* increment sequence # */
  enc->seq_next[seq_index]++;

  pdu_v8_9->count ++;
  enc->buf_size += sizeof (struct ftrec_v8_9);

  if (pdu_v8_9->count >= FT_PDU_V8_9_MAXFLOWS)
    return 0;
  else
    return 1;
} /* fts3rec_pdu_v8_9_encode */

/*
 * function: fts3rec_pdu_v8_10_encode
 *
 * Encode a fts3rec into a version 8 Agg method 10
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_v8_10_encode(struct ftencode *enc,
  struct fts3rec_v8_10 *rec_v8_10)
{
  struct ftpdu_v8_10 *pdu_v8_10;
  u_int seq_index;
  int i;

  pdu_v8_10 = (struct ftpdu_v8_10*) enc->buf_enc;

  /* index to sequence # */
  seq_index = rec_v8_10->engine_id<<8 | rec_v8_10->engine_type;

  i = pdu_v8_10->count;

  /* space to encode more ? */
  if (i >= FT_PDU_V8_10_MAXFLOWS)
    return -1;

  /* if this is the first record, fill in the header */
  if (!i) {

    pdu_v8_10->version = 8;
    pdu_v8_10->sysUpTime = rec_v8_10->sysUpTime;
    pdu_v8_10->unix_secs = rec_v8_10->unix_secs;
    pdu_v8_10->unix_nsecs = rec_v8_10->unix_nsecs;
    pdu_v8_10->engine_type = rec_v8_10->engine_type;
    pdu_v8_10->engine_id = rec_v8_10->engine_id;
    pdu_v8_10->aggregation = 10;
    pdu_v8_10->agg_version = 2;
    pdu_v8_10->flow_sequence = enc->seq_next[seq_index];
    enc->buf_size = 28; /* pdu header size */

  } else {

    /*  sysUpTime, unix_secs, unix_nsecs, and engine_* must match for
     *  each pdu.  If a stream is being re-encoded this will normally
     *  work out fine, if the stream was sorted or changed in some way
     *  the PDU may only be able to hold one record.
    */

    if ((pdu_v8_10->sysUpTime != rec_v8_10->sysUpTime) ||
        (pdu_v8_10->unix_secs != rec_v8_10->unix_secs) ||
        (pdu_v8_10->unix_nsecs != rec_v8_10->unix_nsecs) ||
        (pdu_v8_10->engine_id != rec_v8_10->engine_id) ||
        (pdu_v8_10->engine_type != rec_v8_10->engine_type))
        return -1;

  }

  pdu_v8_10->records[i].dFlows = rec_v8_10->dFlows;
  pdu_v8_10->records[i].dPkts = rec_v8_10->dPkts;
  pdu_v8_10->records[i].dOctets = rec_v8_10->dOctets;
  pdu_v8_10->records[i].First = rec_v8_10->First;
  pdu_v8_10->records[i].Last = rec_v8_10->Last;
  pdu_v8_10->records[i].srcport = rec_v8_10->srcport;
  pdu_v8_10->records[i].dstport = rec_v8_10->dstport;
  pdu_v8_10->records[i].prot = rec_v8_10->prot;
  pdu_v8_10->records[i].tos = rec_v8_10->tos;

  /* increment sequence # */
  enc->seq_next[seq_index]++;

  pdu_v8_10->count ++;
  enc->buf_size += sizeof (struct ftrec_v8_10);

  if (pdu_v8_10->count >= FT_PDU_V8_10_MAXFLOWS)
    return 0;
  else
    return 1;
} /* fts3rec_pdu_v8_10_encode */

/*
 * function: fts3rec_pdu_v8_11_encode
 *
 * Encode a fts3rec into a version 8 Agg method 11
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_v8_11_encode(struct ftencode *enc,
  struct fts3rec_v8_11 *rec_v8_11)
{
  struct ftpdu_v8_11 *pdu_v8_11;
  u_int seq_index;
  int i;

  pdu_v8_11 = (struct ftpdu_v8_11*) enc->buf_enc;

  /* index to sequence # */
  seq_index = rec_v8_11->engine_id<<8 | rec_v8_11->engine_type;

  i = pdu_v8_11->count;

  /* space to encode more ? */
  if (i >= FT_PDU_V8_11_MAXFLOWS)
    return -1;

  /* if this is the first record, fill in the header */
  if (!i) {

    pdu_v8_11->version = 8;
    pdu_v8_11->sysUpTime = rec_v8_11->sysUpTime;
    pdu_v8_11->unix_secs = rec_v8_11->unix_secs;
    pdu_v8_11->unix_nsecs = rec_v8_11->unix_nsecs;
    pdu_v8_11->engine_type = rec_v8_11->engine_type;
    pdu_v8_11->engine_id = rec_v8_11->engine_id;
    pdu_v8_11->aggregation = 11;
    pdu_v8_11->agg_version = 2;
    pdu_v8_11->flow_sequence = enc->seq_next[seq_index];
    enc->buf_size = 28; /* pdu header size */

  } else {

    /*  sysUpTime, unix_secs, unix_nsecs, and engine_* must match for
     *  each pdu.  If a stream is being re-encoded this will normally
     *  work out fine, if the stream was sorted or changed in some way
     *  the PDU may only be able to hold one record.
    */

    if ((pdu_v8_11->sysUpTime != rec_v8_11->sysUpTime) ||
        (pdu_v8_11->unix_secs != rec_v8_11->unix_secs) ||
        (pdu_v8_11->unix_nsecs != rec_v8_11->unix_nsecs) ||
        (pdu_v8_11->engine_id != rec_v8_11->engine_id) ||
        (pdu_v8_11->engine_type != rec_v8_11->engine_type))
        return -1;

  }

  pdu_v8_11->records[i].dFlows = rec_v8_11->dFlows;
  pdu_v8_11->records[i].dPkts = rec_v8_11->dPkts;
  pdu_v8_11->records[i].dOctets = rec_v8_11->dOctets;
  pdu_v8_11->records[i].First = rec_v8_11->First;
  pdu_v8_11->records[i].Last = rec_v8_11->Last;
  pdu_v8_11->records[i].src_prefix = rec_v8_11->srcaddr;
  pdu_v8_11->records[i].src_mask = rec_v8_11->src_mask;
  pdu_v8_11->records[i].tos = rec_v8_11->tos;
  pdu_v8_11->records[i].src_as = rec_v8_11->src_as;
  pdu_v8_11->records[i].input = rec_v8_11->input;

  /* increment sequence # */
  enc->seq_next[seq_index]++;

  pdu_v8_11->count ++;
  enc->buf_size += sizeof (struct ftrec_v8_11);

  if (pdu_v8_11->count >= FT_PDU_V8_11_MAXFLOWS)
    return 0;
  else
    return 1;
} /* fts3rec_pdu_v8_11_encode */

/*
 * function: fts3rec_pdu_v8_12_encode
 *
 * Encode a fts3rec into a version 8 Agg method 12
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_v8_12_encode(struct ftencode *enc,
  struct fts3rec_v8_12 *rec_v8_12)
{
  struct ftpdu_v8_12 *pdu_v8_12;
  u_int seq_index;
  int i;

  pdu_v8_12 = (struct ftpdu_v8_12*) enc->buf_enc;

  /* index to sequence # */
  seq_index = rec_v8_12->engine_id<<8 | rec_v8_12->engine_type;

  i = pdu_v8_12->count;

  /* space to encode more ? */
  if (i >= FT_PDU_V8_12_MAXFLOWS)
    return -1;

  /* if this is the first record, fill in the header */
  if (!i) {

    pdu_v8_12->version = 8;
    pdu_v8_12->sysUpTime = rec_v8_12->sysUpTime;
    pdu_v8_12->unix_secs = rec_v8_12->unix_secs;
    pdu_v8_12->unix_nsecs = rec_v8_12->unix_nsecs;
    pdu_v8_12->engine_type = rec_v8_12->engine_type;
    pdu_v8_12->engine_id = rec_v8_12->engine_id;
    pdu_v8_12->aggregation = 12;
    pdu_v8_12->agg_version = 2;
    pdu_v8_12->flow_sequence = enc->seq_next[seq_index];
    enc->buf_size = 28; /* pdu header size */

  } else {

    /*  sysUpTime, unix_secs, unix_nsecs, and engine_* must match for
     *  each pdu.  If a stream is being re-encoded this will normally
     *  work out fine, if the stream was sorted or changed in some way
     *  the PDU may only be able to hold one record.
    */

    if ((pdu_v8_12->sysUpTime != rec_v8_12->sysUpTime) ||
        (pdu_v8_12->unix_secs != rec_v8_12->unix_secs) ||
        (pdu_v8_12->unix_nsecs != rec_v8_12->unix_nsecs) ||
        (pdu_v8_12->engine_id != rec_v8_12->engine_id) ||
        (pdu_v8_12->engine_type != rec_v8_12->engine_type))
        return -1;

  }

  pdu_v8_12->records[i].dFlows = rec_v8_12->dFlows;
  pdu_v8_12->records[i].dPkts = rec_v8_12->dPkts;
  pdu_v8_12->records[i].dOctets = rec_v8_12->dOctets;
  pdu_v8_12->records[i].First = rec_v8_12->First;
  pdu_v8_12->records[i].Last = rec_v8_12->Last;
  pdu_v8_12->records[i].dst_prefix = rec_v8_12->dstaddr;
  pdu_v8_12->records[i].output = rec_v8_12->output;
  pdu_v8_12->records[i].dst_mask = rec_v8_12->dst_mask;
  pdu_v8_12->records[i].dst_as = rec_v8_12->dst_as;
  pdu_v8_12->records[i].tos = rec_v8_12->tos;

  /* increment sequence # */
  enc->seq_next[seq_index]++;

  pdu_v8_12->count ++;
  enc->buf_size += sizeof (struct ftrec_v8_12);

  if (pdu_v8_12->count >= FT_PDU_V8_12_MAXFLOWS)
    return 0;
  else
    return 1;
} /* fts3rec_pdu_v8_12_encode */

/*
 * function: fts3rec_pdu_v8_13_encode
 *
 * Encode a fts3rec into a version 8 Agg method 13
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_v8_13_encode(struct ftencode *enc,
  struct fts3rec_v8_13 *rec_v8_13)
{
  struct ftpdu_v8_13 *pdu_v8_13;
  u_int seq_index;
  int i;

  pdu_v8_13 = (struct ftpdu_v8_13*) enc->buf_enc;

  /* index to sequence # */
  seq_index = rec_v8_13->engine_id<<8 | rec_v8_13->engine_type;

  i = pdu_v8_13->count;

  /* space to encode more ? */
  if (i >= FT_PDU_V8_13_MAXFLOWS)
    return -1;

  /* if this is the first record, fill in the header */
  if (!i) {

    pdu_v8_13->version = 8;
    pdu_v8_13->sysUpTime = rec_v8_13->sysUpTime;
    pdu_v8_13->unix_secs = rec_v8_13->unix_secs;
    pdu_v8_13->unix_nsecs = rec_v8_13->unix_nsecs;
    pdu_v8_13->engine_type = rec_v8_13->engine_type;
    pdu_v8_13->engine_id = rec_v8_13->engine_id;
    pdu_v8_13->aggregation = 13;
    pdu_v8_13->agg_version = 2;
    pdu_v8_13->flow_sequence = enc->seq_next[seq_index];
    enc->buf_size = 28; /* pdu header size */

  } else {

    /*  sysUpTime, unix_secs, unix_nsecs, and engine_* must match for
     *  each pdu.  If a stream is being re-encoded this will normally
     *  work out fine, if the stream was sorted or changed in some way
     *  the PDU may only be able to hold one record.
    */

    if ((pdu_v8_13->sysUpTime != rec_v8_13->sysUpTime) ||
        (pdu_v8_13->unix_secs != rec_v8_13->unix_secs) ||
        (pdu_v8_13->unix_nsecs != rec_v8_13->unix_nsecs) ||
        (pdu_v8_13->engine_id != rec_v8_13->engine_id) ||
        (pdu_v8_13->engine_type != rec_v8_13->engine_type))
        return -1;

  }

  pdu_v8_13->records[i].dFlows = rec_v8_13->dFlows;
  pdu_v8_13->records[i].dPkts = rec_v8_13->dPkts;
  pdu_v8_13->records[i].dOctets = rec_v8_13->dOctets;
  pdu_v8_13->records[i].First = rec_v8_13->First;
  pdu_v8_13->records[i].Last = rec_v8_13->Last;
  pdu_v8_13->records[i].src_prefix = rec_v8_13->srcaddr;
  pdu_v8_13->records[i].dst_prefix = rec_v8_13->dstaddr;
  pdu_v8_13->records[i].dst_mask = rec_v8_13->dst_mask;
  pdu_v8_13->records[i].src_mask = rec_v8_13->src_mask;
  pdu_v8_13->records[i].tos = rec_v8_13->tos;
  pdu_v8_13->records[i].src_as = rec_v8_13->src_as;
  pdu_v8_13->records[i].dst_as = rec_v8_13->dst_as;
  pdu_v8_13->records[i].input = rec_v8_13->input;
  pdu_v8_13->records[i].output = rec_v8_13->output;

  /* increment sequence # */
  enc->seq_next[seq_index]++;

  pdu_v8_13->count ++;
  enc->buf_size += sizeof (struct ftrec_v8_13);

  if (pdu_v8_13->count >= FT_PDU_V8_13_MAXFLOWS)
    return 0;
  else
    return 1;
} /* fts3rec_pdu_v8_13_encode */

/*
 * function: fts3rec_pdu_v8_14_encode
 *
 * Encode a fts3rec into a version 8 Agg method 14
 *
 * returns: -1 error encoding, PDU not encoded.
 *           0 PDU encoded.  Hint next call will fail.
 *           1 PDU encoded.  Room for more.
 * 
*/
int fts3rec_pdu_v8_14_encode(struct ftencode *enc,
  struct fts3rec_v8_14 *rec_v8_14)
{
  struct ftpdu_v8_14 *pdu_v8_14;
  u_int seq_index;
  int i;

  pdu_v8_14 = (struct ftpdu_v8_14*) enc->buf_enc;

  /* index to sequence # */
  seq_index = rec_v8_14->engine_id<<8 | rec_v8_14->engine_type;

  i = pdu_v8_14->count;

  /* space to encode more ? */
  if (i >= FT_PDU_V8_14_MAXFLOWS)
    return -1;

  /* if this is the first record, fill in the header */
  if (!i) {

    pdu_v8_14->version = 8;
    pdu_v8_14->sysUpTime = rec_v8_14->sysUpTime;
    pdu_v8_14->unix_secs = rec_v8_14->unix_secs;
    pdu_v8_14->unix_nsecs = rec_v8_14->unix_nsecs;
    pdu_v8_14->engine_type = rec_v8_14->engine_type;
    pdu_v8_14->engine_id = rec_v8_14->engine_id;
    pdu_v8_14->aggregation = 14;
    pdu_v8_14->agg_version = 2;
    pdu_v8_14->flow_sequence = enc->seq_next[seq_index];
    enc->buf_size = 28; /* pdu header size */

  } else {

    /*  sysUpTime, unix_secs, unix_nsecs, and engine_* must match for
     *  each pdu.  If a stream is being re-encoded this will normally
     *  work out fine, if the stream was sorted or changed in some way
     *  the PDU may only be able to hold one record.
    */

    if ((pdu_v8_14->sysUpTime != rec_v8_14->sysUpTime) ||
        (pdu_v8_14->unix_secs != rec_v8_14->unix_secs) ||
        (pdu_v8_14->unix_nsecs != rec_v8_14->unix_nsecs) ||
        (pdu_v8_14->engine_id != rec_v8_14->engine_id) ||
        (pdu_v8_14->engine_type != rec_v8_14->engine_type))
        return -1;

  }

  pdu_v8_14->records[i].dFlows = rec_v8_14->dFlows;
  pdu_v8_14->records[i].dPkts = rec_v8_14->dPkts;
  pdu_v8_14->records[i].dOctets = rec_v8_14->dOctets;
  pdu_v8_14->records[i].First = rec_v8_14->First;
  pdu_v8_14->records[i].Last = rec_v8_14->Last;
  pdu_v8_14->records[i].src_prefix = rec_v8_14->srcaddr;
  pdu_v8_14->records[i].dst_prefix = rec_v8_14->dstaddr;
  pdu_v8_14->records[i].srcport = rec_v8_14->srcport;
  pdu_v8_14->records[i].dstport = rec_v8_14->dstport;
  pdu_v8_14->records[i].input = rec_v8_14->input;
  pdu_v8_14->records[i].output = rec_v8_14->output;
  pdu_v8_14->records[i].dst_mask = rec_v8_14->dst_mask;
  pdu_v8_14->records[i].src_mask = rec_v8_14->src_mask;
  pdu_v8_14->records[i].tos = rec_v8_14->tos;
  pdu_v8_14->records[i].prot = rec_v8_14->prot;

  /* increment sequence # */
  enc->seq_next[seq_index]++;

  pdu_v8_14->count ++;
  enc->buf_size += sizeof (struct ftrec_v8_14);

  if (pdu_v8_14->count >= FT_PDU_V8_14_MAXFLOWS)
    return 0;
  else
    return 1;
} /* fts3rec_pdu_v8_14_encode */
