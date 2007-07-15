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
 *      $Id: ftrec.c,v 1.13 2003/11/30 22:56:45 maf Exp $
 */

#include "ftconfig.h"
#include "ftlib.h"

#include <sys/time.h>
#include <sys/types.h>
#include <limits.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif

#define FT_OFFSET(A,B)\
  o->A = offsetof(struct B, A);

void ftrec_xlate_1to5(struct fts3rec_v1 *rec_v1, struct fts3rec_v5 *rec_v5);
void ftrec_xlate_1to6(struct fts3rec_v1 *rec_v1, struct fts3rec_v6 *rec_v6);
void ftrec_xlate_1to7(struct fts3rec_v1 *rec_v1, struct fts3rec_v7 *rec_v7);
void ftrec_xlate_1to1005(struct fts3rec_v1 *rec_v1,
  struct fts3rec_v1005 *rec_v1005);

void ftrec_xlate_5to1(struct fts3rec_v5 *rec_v5, struct fts3rec_v1 *rec_v1);
void ftrec_xlate_5to6(struct fts3rec_v5 *rec_v5, struct fts3rec_v6 *rec_v6);
void ftrec_xlate_5to7(struct fts3rec_v5 *rec_v5, struct fts3rec_v7 *rec_v7);
void ftrec_xlate_5to1005(struct fts3rec_v5 *rec_v5,
  struct fts3rec_v1005 *rec_v1005);

void ftrec_xlate_6to1(struct fts3rec_v6 *rec_v6, struct fts3rec_v1 *rec_v1);
void ftrec_xlate_6to5(struct fts3rec_v6 *rec_v6, struct fts3rec_v5 *rec_v5);
void ftrec_xlate_6to7(struct fts3rec_v6 *rec_v6, struct fts3rec_v7 *rec_v7);
void ftrec_xlate_6to1005(struct fts3rec_v6 *rec_v6,
  struct fts3rec_v1005 *rec_v1005);

void ftrec_xlate_7to1(struct fts3rec_v7 *rec_v7, struct fts3rec_v1 *rec_v1);
void ftrec_xlate_7to5(struct fts3rec_v7 *rec_v7, struct fts3rec_v5 *rec_v5);
void ftrec_xlate_7to6(struct fts3rec_v7 *rec_v7, struct fts3rec_v6 *rec_v6);
void ftrec_xlate_7to1005(struct fts3rec_v7 *rec_v7,
  struct fts3rec_v1005 *rec_v1005);

void ftrec_xlate_1005to5(struct fts3rec_v1005 *rec_v1005,
  struct fts3rec_v5 *rec_v5);

/*
 * function ftrec_compute_mask
 *
 * configure ftipmask for given byte order
 *
 * used to precompute mask and test to avoid byte swapping
 * in certain code paths
 *
 */
void ftrec_compute_mask(struct ftipmask *m, u_int32 src, u_int32 dst, int
  byte_order)
{

  m->src_mask = src;
  m->dst_mask = dst;
  m->mcast_mask =  0xf0000000;
  m->mcast_val = 0xe0000000;

#if BYTE_ORDER == BIG_ENDIAN
  if (byte_order == FT_HEADER_LITTLE_ENDIAN) {
    SWAPINT32(m->src_mask);
    SWAPINT32(m->dst_mask);
    SWAPINT32(m->mcast_mask);
    SWAPINT32(m->mcast_val);
  }
#endif /* BYTE_ORDER == BIG_ENDIAN */
      
#if BYTE_ORDER == LITTLE_ENDIAN
  if (byte_order == FT_HEADER_BIG_ENDIAN) {
    SWAPINT32(m->src_mask);
    SWAPINT32(m->dst_mask);
    SWAPINT32(m->mcast_mask);
    SWAPINT32(m->mcast_val);
  }
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

} /* ftrec_compute_mask */

/*
 * function: ftrec_mask_ip
 *
 * AND non multicast IP addresses in a flow record with mask
 *
 * mask and record must be in the same byte order
 *
 * returns -1 on error, 0 otherwise.
 */
int ftrec_mask_ip(void *rec, struct ftver *ftv, struct ftipmask *m)
{

  int ret;
  struct fts3rec_gen *rec_gen;

  ret = -1;

  switch (ftv->d_version) {

    case 1:
    case 5:
    case 6:
    case 7:
    case 1005:
      rec_gen = rec;
      if (!((rec_gen->dstaddr & m->mcast_mask) == m->mcast_val)) {
        rec_gen->srcaddr &= m->src_mask;
        rec_gen->dstaddr &= m->dst_mask;
      }
      ret = 0;
      break;

  } /* switch */

  return ret;

} /* ftrec_mask_ip */

/*
 * function: ftrec_xlate_func
 *
 * return function to translate among v1, v5, v6, and v7 formats
 * 
 */
void *ftrec_xlate_func(struct ftver *in_ftv, struct ftver *out_ftv)
{

  if (in_ftv->d_version == 1) {

    if (out_ftv->d_version == 5)
      return ftrec_xlate_1to5;
    else if (out_ftv->d_version == 6)
      return ftrec_xlate_1to6;
    else if (out_ftv->d_version == 7)
      return ftrec_xlate_1to7;
    else if (out_ftv->d_version == 1)
      return (void*)0L;
    else if (out_ftv->d_version == 1005)
      return ftrec_xlate_5to1005;

  } else if (in_ftv->d_version == 5) {

    if (out_ftv->d_version == 1)
      return ftrec_xlate_5to1;
    else if (out_ftv->d_version == 6)
      return ftrec_xlate_5to6;
    else if (out_ftv->d_version == 7)
      return ftrec_xlate_5to7;
    else if (out_ftv->d_version == 1005)
      return ftrec_xlate_5to1005;
    else if (out_ftv->d_version == 5)
      return (void*)0L;

  } else if (in_ftv->d_version == 6) {

    if (out_ftv->d_version == 1)
      return ftrec_xlate_6to1;
    else if (out_ftv->d_version == 5)
      return ftrec_xlate_6to5;
    else if (out_ftv->d_version == 7)
      return ftrec_xlate_6to7;
    else if (out_ftv->d_version == 6)
      return (void*)0L;
    else if (out_ftv->d_version == 1005)
      return ftrec_xlate_6to1005;

  } else if (in_ftv->d_version == 7) {

    if (out_ftv->d_version == 1)
      return ftrec_xlate_7to1;
    else if (out_ftv->d_version == 5)
      return ftrec_xlate_7to5;
    else if (out_ftv->d_version == 6)
      return ftrec_xlate_7to6;
    else if (out_ftv->d_version == 7)
      return (void*)0L;
    else if (out_ftv->d_version == 1005)
      return ftrec_xlate_7to1005;

  } else if (in_ftv->d_version == 1005) {

    if (out_ftv->d_version == 5)
      return ftrec_xlate_1005to5;
  }

  return (void*)0L;

} /* ftrec_xlate_func */

/*
 * function: ftrec_xlate
 *
 * translate among v1, v5, v6, and v7 formats
 * 
 */
void ftrec_xlate(void *in_rec, struct ftver *in_ftv, void *out_rec,
  struct ftver *out_ftv)
{

  void (*func)(void *in_rec, void *out_rec);

  func = ftrec_xlate_func(in_ftv, out_ftv);
  if (!func)
    return; /* XXX: should provide a return code */
  func(in_rec, out_rec);

} /* ftrec_xlate */

void ftrec_xlate_5to1(struct fts3rec_v5 *rec_v5, struct fts3rec_v1 *rec_v1)
{

  bzero(rec_v1, sizeof (struct fts3rec_v1));

  rec_v1->unix_secs = rec_v5->unix_secs;
  rec_v1->unix_nsecs = rec_v5->unix_nsecs;
  rec_v1->sysUpTime = rec_v5->sysUpTime;
  rec_v1->exaddr = rec_v5->exaddr;
  rec_v1->srcaddr = rec_v5->srcaddr;
  rec_v1->dstaddr = rec_v5->dstaddr;
  rec_v1->nexthop = rec_v5->nexthop;
  rec_v1->input = rec_v5->input;
  rec_v1->output = rec_v5->output;
  rec_v1->dPkts = rec_v5->dPkts;
  rec_v1->dOctets = rec_v5->dOctets;
  rec_v1->First = rec_v5->First;
  rec_v1->Last = rec_v5->Last;
  rec_v1->srcport = rec_v5->srcport;
  rec_v1->dstport = rec_v5->dstport;
  rec_v1->prot = rec_v5->prot;
  rec_v1->tos = rec_v5->tos;
  rec_v1->tcp_flags = rec_v5->tcp_flags;

} /* ftrec_xlate_5to1 */

void ftrec_xlate_5to6(struct fts3rec_v5 *rec_v5, struct fts3rec_v6 *rec_v6)
{

  bzero(rec_v6, sizeof (struct fts3rec_v6));

  rec_v6->unix_secs = rec_v5->unix_secs;
  rec_v6->unix_nsecs = rec_v5->unix_nsecs;
  rec_v6->sysUpTime = rec_v5->sysUpTime;
  rec_v6->exaddr = rec_v5->exaddr;
  rec_v6->srcaddr = rec_v5->srcaddr;
  rec_v6->dstaddr = rec_v5->dstaddr;
  rec_v6->nexthop = rec_v5->nexthop;
  rec_v6->input = rec_v5->input;
  rec_v6->output = rec_v5->output;
  rec_v6->dPkts = rec_v5->dPkts;
  rec_v6->dOctets = rec_v5->dOctets;
  rec_v6->First = rec_v5->First;
  rec_v6->Last = rec_v5->Last;
  rec_v6->srcport = rec_v5->srcport;
  rec_v6->dstport = rec_v5->dstport;
  rec_v6->prot = rec_v5->prot;
  rec_v6->tos = rec_v5->tos;
  rec_v6->tcp_flags = rec_v5->tcp_flags;
  rec_v6->engine_type = rec_v5->engine_type;
  rec_v6->engine_id = rec_v5->engine_id;
  rec_v6->src_mask = rec_v5->src_mask;
  rec_v6->dst_mask = rec_v5->dst_mask;
  rec_v6->src_as = rec_v5->src_as;
  rec_v6->dst_as = rec_v5->dst_as;

} /* ftrec_xlate_5to6 */

void ftrec_xlate_5to1005(struct fts3rec_v5 *rec_v5,
  struct fts3rec_v1005 *rec_v1005)
{

  bzero(rec_v1005, sizeof (struct fts3rec_v1005));

  rec_v1005->unix_secs = rec_v5->unix_secs;
  rec_v1005->unix_nsecs = rec_v5->unix_nsecs;
  rec_v1005->sysUpTime = rec_v5->sysUpTime;
  rec_v1005->exaddr = rec_v5->exaddr;
  rec_v1005->srcaddr = rec_v5->srcaddr;
  rec_v1005->dstaddr = rec_v5->dstaddr;
  rec_v1005->nexthop = rec_v5->nexthop;
  rec_v1005->input = rec_v5->input;
  rec_v1005->output = rec_v5->output;
  rec_v1005->dPkts = rec_v5->dPkts;
  rec_v1005->dOctets = rec_v5->dOctets;
  rec_v1005->First = rec_v5->First;
  rec_v1005->Last = rec_v5->Last;
  rec_v1005->srcport = rec_v5->srcport;
  rec_v1005->dstport = rec_v5->dstport;
  rec_v1005->prot = rec_v5->prot;
  rec_v1005->tos = rec_v5->tos;
  rec_v1005->tcp_flags = rec_v5->tcp_flags;
  rec_v1005->engine_type = rec_v5->engine_type;
  rec_v1005->engine_id = rec_v5->engine_id;
  rec_v1005->src_mask = rec_v5->src_mask;
  rec_v1005->dst_mask = rec_v5->dst_mask;
  rec_v1005->src_as = rec_v5->src_as;
  rec_v1005->dst_as = rec_v5->dst_as;

} /* ftrec_xlate_5to1005 */


void ftrec_xlate_5to7(struct fts3rec_v5 *rec_v5, struct fts3rec_v7 *rec_v7)
{

  bzero(rec_v7, sizeof (struct fts3rec_v7));

  rec_v7->unix_secs = rec_v5->unix_secs;
  rec_v7->unix_nsecs = rec_v5->unix_nsecs;
  rec_v7->sysUpTime = rec_v5->sysUpTime;
  rec_v7->exaddr = rec_v5->exaddr;
  rec_v7->srcaddr = rec_v5->srcaddr;
  rec_v7->dstaddr = rec_v5->dstaddr;
  rec_v7->nexthop = rec_v5->nexthop;
  rec_v7->input = rec_v5->input;
  rec_v7->output = rec_v5->output;
  rec_v7->dPkts = rec_v5->dPkts;
  rec_v7->dOctets = rec_v5->dOctets;
  rec_v7->First = rec_v5->First;
  rec_v7->Last = rec_v5->Last;
  rec_v7->srcport = rec_v5->srcport;
  rec_v7->dstport = rec_v5->dstport;
  rec_v7->prot = rec_v5->prot;
  rec_v7->tos = rec_v5->tos;
  rec_v7->tcp_flags = rec_v5->tcp_flags;
  rec_v7->engine_type = rec_v5->engine_type;
  rec_v7->engine_id = rec_v5->engine_id;
  rec_v7->src_mask = rec_v5->src_mask;
  rec_v7->dst_mask = rec_v5->dst_mask;
  rec_v7->src_as = rec_v5->src_as;
  rec_v7->dst_as = rec_v5->dst_as;

} /* ftrec_xlate_5to7 */


void ftrec_xlate_1to5(struct fts3rec_v1 *rec_v1, struct fts3rec_v5 *rec_v5)
{

  bzero(rec_v5, sizeof (struct fts3rec_v5));

  rec_v5->unix_secs = rec_v1->unix_secs;
  rec_v5->unix_nsecs = rec_v1->unix_nsecs;
  rec_v5->sysUpTime = rec_v1->sysUpTime;
  rec_v5->exaddr = rec_v1->exaddr;
  rec_v5->srcaddr = rec_v1->srcaddr;
  rec_v5->dstaddr = rec_v1->dstaddr;
  rec_v5->nexthop = rec_v1->nexthop;
  rec_v5->input = rec_v1->input;
  rec_v5->output = rec_v5->output;
  rec_v5->dPkts = rec_v1->dPkts;
  rec_v5->dOctets = rec_v1->dOctets;
  rec_v5->First = rec_v1->First;
  rec_v5->Last = rec_v1->Last;
  rec_v5->srcport = rec_v1->srcport;
  rec_v5->dstport = rec_v1->dstport;
  rec_v5->prot = rec_v1->prot;
  rec_v5->tos = rec_v1->tos;
  rec_v5->tcp_flags = rec_v1->tcp_flags;

} /* ftrec_xlate_1to5 */


void ftrec_xlate_1to6(struct fts3rec_v1 *rec_v1, struct fts3rec_v6 *rec_v6)
{

  bzero(rec_v6, sizeof (struct fts3rec_v6));

  rec_v6->unix_secs = rec_v1->unix_secs;
  rec_v6->unix_nsecs = rec_v1->unix_nsecs;
  rec_v6->sysUpTime = rec_v1->sysUpTime;
  rec_v6->exaddr = rec_v1->exaddr;
  rec_v6->srcaddr = rec_v1->srcaddr;
  rec_v6->dstaddr = rec_v1->dstaddr;
  rec_v6->nexthop = rec_v1->nexthop;
  rec_v6->input = rec_v1->input;
  rec_v6->output = rec_v6->output;
  rec_v6->dPkts = rec_v1->dPkts;
  rec_v6->dOctets = rec_v1->dOctets;
  rec_v6->First = rec_v1->First;
  rec_v6->Last = rec_v1->Last;
  rec_v6->srcport = rec_v1->srcport;
  rec_v6->dstport = rec_v1->dstport;
  rec_v6->prot = rec_v1->prot;
  rec_v6->tos = rec_v1->tos;
  rec_v6->tcp_flags = rec_v1->tcp_flags;

} /* ftrec_xlate_1to6 */

void ftrec_xlate_1to7(struct fts3rec_v1 *rec_v1, struct fts3rec_v7 *rec_v7)
{

  bzero(rec_v7, sizeof (struct fts3rec_v7));

  rec_v7->unix_secs = rec_v1->unix_secs;
  rec_v7->unix_nsecs = rec_v1->unix_nsecs;
  rec_v7->sysUpTime = rec_v1->sysUpTime;
  rec_v7->exaddr = rec_v1->exaddr;
  rec_v7->srcaddr = rec_v1->srcaddr;
  rec_v7->dstaddr = rec_v1->dstaddr;
  rec_v7->nexthop = rec_v1->nexthop;
  rec_v7->input = rec_v1->input;
  rec_v7->output = rec_v7->output;
  rec_v7->dPkts = rec_v1->dPkts;
  rec_v7->dOctets = rec_v1->dOctets;
  rec_v7->First = rec_v1->First;
  rec_v7->Last = rec_v1->Last;
  rec_v7->srcport = rec_v1->srcport;
  rec_v7->dstport = rec_v1->dstport;
  rec_v7->prot = rec_v1->prot;
  rec_v7->tos = rec_v1->tos;
  rec_v7->tcp_flags = rec_v1->tcp_flags;

} /* ftrec_xlate_1to7 */

void ftrec_xlate_1to1005(struct fts3rec_v1 *rec_v1,
  struct fts3rec_v1005 *rec_v1005)
{

  bzero(rec_v1005, sizeof (struct fts3rec_v1005));

  rec_v1005->unix_secs = rec_v1->unix_secs;
  rec_v1005->unix_nsecs = rec_v1->unix_nsecs;
  rec_v1005->sysUpTime = rec_v1->sysUpTime;
  rec_v1005->exaddr = rec_v1->exaddr;
  rec_v1005->srcaddr = rec_v1->srcaddr;
  rec_v1005->dstaddr = rec_v1->dstaddr;
  rec_v1005->nexthop = rec_v1->nexthop;
  rec_v1005->input = rec_v1->input;
  rec_v1005->output = rec_v1->output;
  rec_v1005->dPkts = rec_v1->dPkts;
  rec_v1005->dOctets = rec_v1->dOctets;
  rec_v1005->First = rec_v1->First;
  rec_v1005->Last = rec_v1->Last;
  rec_v1005->srcport = rec_v1->srcport;
  rec_v1005->dstport = rec_v1->dstport;
  rec_v1005->prot = rec_v1->prot;
  rec_v1005->tos = rec_v1->tos;
  rec_v1005->tcp_flags = rec_v1->tcp_flags;

} /* ftrec_xlate_1to1005 */

void ftrec_xlate_6to1(struct fts3rec_v6 *rec_v6, struct fts3rec_v1 *rec_v1)
{

  bzero(rec_v1, sizeof (struct fts3rec_v1));

  rec_v1->unix_secs = rec_v6->unix_secs;
  rec_v1->unix_nsecs = rec_v6->unix_nsecs;
  rec_v1->sysUpTime = rec_v6->sysUpTime;
  rec_v1->exaddr = rec_v6->exaddr;
  rec_v1->srcaddr = rec_v6->srcaddr;
  rec_v1->dstaddr = rec_v6->dstaddr;
  rec_v1->nexthop = rec_v6->nexthop;
  rec_v1->input = rec_v6->input;
  rec_v1->output = rec_v6->output;
  rec_v1->dPkts = rec_v6->dPkts;
  rec_v1->dOctets = rec_v6->dOctets;
  rec_v1->First = rec_v6->First;
  rec_v1->Last = rec_v6->Last;
  rec_v1->srcport = rec_v6->srcport;
  rec_v1->dstport = rec_v6->dstport;
  rec_v1->prot = rec_v6->prot;
  rec_v1->tos = rec_v6->tos;
  rec_v1->tcp_flags = rec_v6->tcp_flags;

} /* ftrec_xlate_6to1 */

void ftrec_xlate_6to5(struct fts3rec_v6 *rec_v6, struct fts3rec_v5 *rec_v5)
{

  bzero(rec_v5, sizeof (struct fts3rec_v5));

  rec_v5->unix_secs = rec_v6->unix_secs;
  rec_v5->unix_nsecs = rec_v6->unix_nsecs;
  rec_v5->sysUpTime = rec_v6->sysUpTime;
  rec_v5->exaddr = rec_v6->exaddr;
  rec_v5->srcaddr = rec_v6->srcaddr;
  rec_v5->dstaddr = rec_v6->dstaddr;
  rec_v5->nexthop = rec_v6->nexthop;
  rec_v5->input = rec_v6->input;
  rec_v5->output = rec_v6->output;
  rec_v5->dPkts = rec_v6->dPkts;
  rec_v5->dOctets = rec_v6->dOctets;
  rec_v5->First = rec_v6->First;
  rec_v5->Last = rec_v6->Last;
  rec_v5->srcport = rec_v6->srcport;
  rec_v5->dstport = rec_v6->dstport;
  rec_v5->prot = rec_v6->prot;
  rec_v5->tos = rec_v6->tos;
  rec_v5->tcp_flags = rec_v6->tcp_flags;
  rec_v5->engine_type = rec_v6->engine_type;
  rec_v5->engine_id = rec_v6->engine_id;
  rec_v5->src_mask = rec_v6->src_mask;
  rec_v5->dst_mask = rec_v6->dst_mask;
  rec_v5->src_as = rec_v6->src_as;
  rec_v5->dst_as = rec_v6->dst_as;

} /* ftrec_xlate_6to5 */

void ftrec_xlate_6to7(struct fts3rec_v6 *rec_v6, struct fts3rec_v7 *rec_v7)
{

  bzero(rec_v7, sizeof (struct fts3rec_v7));

  rec_v7->unix_secs = rec_v6->unix_secs;
  rec_v7->unix_nsecs = rec_v6->unix_nsecs;
  rec_v7->sysUpTime = rec_v6->sysUpTime;
  rec_v7->exaddr = rec_v6->exaddr;
  rec_v7->srcaddr = rec_v6->srcaddr;
  rec_v7->dstaddr = rec_v6->dstaddr;
  rec_v7->nexthop = rec_v6->nexthop;
  rec_v7->input = rec_v6->input;
  rec_v7->output = rec_v6->output;
  rec_v7->dPkts = rec_v6->dPkts;
  rec_v7->dOctets = rec_v6->dOctets;
  rec_v7->First = rec_v6->First;
  rec_v7->Last = rec_v6->Last;
  rec_v7->srcport = rec_v6->srcport;
  rec_v7->dstport = rec_v6->dstport;
  rec_v7->prot = rec_v6->prot;
  rec_v7->tos = rec_v6->tos;
  rec_v7->tcp_flags = rec_v6->tcp_flags;
  rec_v7->engine_type = rec_v6->engine_type;
  rec_v7->engine_id = rec_v6->engine_id;
  rec_v7->src_mask = rec_v6->src_mask;
  rec_v7->dst_mask = rec_v6->dst_mask;
  rec_v7->src_as = rec_v6->src_as;
  rec_v7->dst_as = rec_v6->dst_as;

} /* ftrec_xlate_6to7 */

void ftrec_xlate_6to1005(struct fts3rec_v6 *rec_v6,
  struct fts3rec_v1005 *rec_v1005)
{

  bzero(rec_v1005, sizeof (struct fts3rec_v1005));

  rec_v1005->unix_secs = rec_v6->unix_secs;
  rec_v1005->unix_nsecs = rec_v6->unix_nsecs;
  rec_v1005->sysUpTime = rec_v6->sysUpTime;
  rec_v1005->exaddr = rec_v6->exaddr;
  rec_v1005->srcaddr = rec_v6->srcaddr;
  rec_v1005->dstaddr = rec_v6->dstaddr;
  rec_v1005->nexthop = rec_v6->nexthop;
  rec_v1005->input = rec_v6->input;
  rec_v1005->output = rec_v6->output;
  rec_v1005->dPkts = rec_v6->dPkts;
  rec_v1005->dOctets = rec_v6->dOctets;
  rec_v1005->First = rec_v6->First;
  rec_v1005->Last = rec_v6->Last;
  rec_v1005->srcport = rec_v6->srcport;
  rec_v1005->dstport = rec_v6->dstport;
  rec_v1005->prot = rec_v6->prot;
  rec_v1005->tos = rec_v6->tos;
  rec_v1005->tcp_flags = rec_v6->tcp_flags;
  rec_v1005->engine_type = rec_v6->engine_type;
  rec_v1005->engine_id = rec_v6->engine_id;
  rec_v1005->src_mask = rec_v6->src_mask;
  rec_v1005->dst_mask = rec_v6->dst_mask;
  rec_v1005->src_as = rec_v6->src_as;
  rec_v1005->dst_as = rec_v6->dst_as;

} /* ftrec_xlate_6to1005 */

void ftrec_xlate_7to1(struct fts3rec_v7 *rec_v7, struct fts3rec_v1 *rec_v1)
{

  bzero(rec_v1, sizeof (struct fts3rec_v1));

  rec_v1->unix_secs = rec_v7->unix_secs;
  rec_v1->unix_nsecs = rec_v7->unix_nsecs;
  rec_v1->sysUpTime = rec_v7->sysUpTime;
  rec_v1->exaddr = rec_v7->exaddr;
  rec_v1->srcaddr = rec_v7->srcaddr;
  rec_v1->dstaddr = rec_v7->dstaddr;
  rec_v1->nexthop = rec_v7->nexthop;
  rec_v1->input = rec_v7->input;
  rec_v1->output = rec_v7->output;
  rec_v1->dPkts = rec_v7->dPkts;
  rec_v1->dOctets = rec_v7->dOctets;
  rec_v1->First = rec_v7->First;
  rec_v1->Last = rec_v7->Last;
  rec_v1->srcport = rec_v7->srcport;
  rec_v1->dstport = rec_v7->dstport;
  rec_v1->prot = rec_v7->prot;
  rec_v1->tos = rec_v7->tos;
  rec_v1->tcp_flags = rec_v7->tcp_flags;

} /* ftrec_xlate_7to1 */


void ftrec_xlate_7to5(struct fts3rec_v7 *rec_v7, struct fts3rec_v5 *rec_v5)
{

  bzero(rec_v5, sizeof (struct fts3rec_v5));

  rec_v5->unix_secs = rec_v7->unix_secs;
  rec_v5->unix_nsecs = rec_v7->unix_nsecs;
  rec_v5->sysUpTime = rec_v7->sysUpTime;
  rec_v5->exaddr = rec_v7->exaddr;
  rec_v5->srcaddr = rec_v7->srcaddr;
  rec_v5->dstaddr = rec_v7->dstaddr;
  rec_v5->nexthop = rec_v7->nexthop;
  rec_v5->input = rec_v7->input;
  rec_v5->output = rec_v7->output;
  rec_v5->dPkts = rec_v7->dPkts;
  rec_v5->dOctets = rec_v7->dOctets;
  rec_v5->First = rec_v7->First;
  rec_v5->Last = rec_v7->Last;
  rec_v5->srcport = rec_v7->srcport;
  rec_v5->dstport = rec_v7->dstport;
  rec_v5->prot = rec_v7->prot;
  rec_v5->tos = rec_v7->tos;
  rec_v5->tcp_flags = rec_v7->tcp_flags;
  rec_v5->engine_type = rec_v7->engine_type;
  rec_v5->engine_id = rec_v7->engine_id;
  rec_v5->src_mask = rec_v7->src_mask;
  rec_v5->dst_mask = rec_v7->dst_mask;
  rec_v5->src_as = rec_v7->src_as;
  rec_v5->dst_as = rec_v7->dst_as;

} /* ftrec_xlate_7to5 */

void ftrec_xlate_7to6(struct fts3rec_v7 *rec_v7, struct fts3rec_v6 *rec_v6)
{

  bzero(rec_v6, sizeof (struct fts3rec_v6));

  rec_v6->unix_secs = rec_v7->unix_secs;
  rec_v6->unix_nsecs = rec_v7->unix_nsecs;
  rec_v6->sysUpTime = rec_v7->sysUpTime;
  rec_v6->exaddr = rec_v7->exaddr;
  rec_v6->srcaddr = rec_v7->srcaddr;
  rec_v6->dstaddr = rec_v7->dstaddr;
  rec_v6->nexthop = rec_v7->nexthop;
  rec_v6->input = rec_v7->input;
  rec_v6->output = rec_v7->output;
  rec_v6->dPkts = rec_v7->dPkts;
  rec_v6->dOctets = rec_v7->dOctets;
  rec_v6->First = rec_v7->First;
  rec_v6->Last = rec_v7->Last;
  rec_v6->srcport = rec_v7->srcport;
  rec_v6->dstport = rec_v7->dstport;
  rec_v6->prot = rec_v7->prot;
  rec_v6->tos = rec_v7->tos;
  rec_v6->tcp_flags = rec_v7->tcp_flags;
  rec_v6->engine_type = rec_v7->engine_type;
  rec_v6->engine_id = rec_v7->engine_id;
  rec_v6->src_mask = rec_v7->src_mask;
  rec_v6->dst_mask = rec_v7->dst_mask;
  rec_v6->src_as = rec_v7->src_as;
  rec_v6->dst_as = rec_v7->dst_as;

} /* ftrec_xlate_7to6 */

void ftrec_xlate_7to1005(struct fts3rec_v7 *rec_v7,
  struct fts3rec_v1005 *rec_v1005)
{

  bzero(rec_v1005, sizeof (struct fts3rec_v1005));

  rec_v1005->unix_secs = rec_v7->unix_secs;
  rec_v1005->unix_nsecs = rec_v7->unix_nsecs;
  rec_v1005->sysUpTime = rec_v7->sysUpTime;
  rec_v1005->exaddr = rec_v7->exaddr;
  rec_v1005->srcaddr = rec_v7->srcaddr;
  rec_v1005->dstaddr = rec_v7->dstaddr;
  rec_v1005->nexthop = rec_v7->nexthop;
  rec_v1005->input = rec_v7->input;
  rec_v1005->output = rec_v7->output;
  rec_v1005->dPkts = rec_v7->dPkts;
  rec_v1005->dOctets = rec_v7->dOctets;
  rec_v1005->First = rec_v7->First;
  rec_v1005->Last = rec_v7->Last;
  rec_v1005->srcport = rec_v7->srcport;
  rec_v1005->dstport = rec_v7->dstport;
  rec_v1005->prot = rec_v7->prot;
  rec_v1005->tos = rec_v7->tos;
  rec_v1005->tcp_flags = rec_v7->tcp_flags;
  rec_v1005->engine_type = rec_v7->engine_type;
  rec_v1005->engine_id = rec_v7->engine_id;
  rec_v1005->src_mask = rec_v7->src_mask;
  rec_v1005->dst_mask = rec_v7->dst_mask;
  rec_v1005->src_as = rec_v7->src_as;
  rec_v1005->dst_as = rec_v7->dst_as;

} /* ftrec_xlate_7to1005 */

void ftrec_xlate_1005to5(struct fts3rec_v1005 *rec_v1005,
  struct fts3rec_v5 *rec_v5)
{
  bzero(rec_v5, sizeof (struct fts3rec_v5));

  rec_v5->unix_secs = rec_v1005->unix_secs;
  rec_v5->unix_nsecs = rec_v1005->unix_nsecs;
  rec_v5->sysUpTime = rec_v1005->sysUpTime;
  rec_v5->exaddr = rec_v1005->exaddr;
  rec_v5->srcaddr = rec_v1005->srcaddr;
  rec_v5->dstaddr = rec_v1005->dstaddr;
  rec_v5->nexthop = rec_v1005->nexthop;
  rec_v5->input = rec_v1005->input;
  rec_v5->output = rec_v1005->output;
  rec_v5->dPkts = rec_v1005->dPkts;
  rec_v5->dOctets = rec_v1005->dOctets;
  rec_v5->First = rec_v1005->First;
  rec_v5->Last = rec_v1005->Last;
  rec_v5->srcport = rec_v1005->srcport;
  rec_v5->dstport = rec_v1005->dstport;
  rec_v5->prot = rec_v1005->prot;
  rec_v5->tos = rec_v1005->tos;
  rec_v5->tcp_flags = rec_v1005->tcp_flags;
  rec_v5->engine_type = rec_v1005->engine_type;
  rec_v5->engine_id = rec_v1005->engine_id;
  rec_v5->src_mask = rec_v1005->src_mask;
  rec_v5->dst_mask = rec_v1005->dst_mask;
  rec_v5->src_as = rec_v1005->src_as;
  rec_v5->dst_as = rec_v1005->dst_as;

} /* flow_xlate_1005to5 */

/*
 * function fts3rec_compute_offsets
 *
 * populate a fts3rec_offset structure with structure offsets appropriate
 * for the version in ftv.
 *
 * returns 0 for success, < 0 otherwise.
 */
int fts3rec_compute_offsets(struct fts3rec_offsets *o, struct ftver *ftv)
{
  int ret;

  ret = -1;

  switch (ftv->d_version) {

    case 1:
      FT_OFFSET(unix_secs, fts3rec_v1)
      FT_OFFSET(unix_nsecs, fts3rec_v1)
      FT_OFFSET(sysUpTime, fts3rec_v1)
      FT_OFFSET(exaddr, fts3rec_v1)
      FT_OFFSET(srcaddr, fts3rec_v1)
      FT_OFFSET(dstaddr, fts3rec_v1)
      FT_OFFSET(nexthop, fts3rec_v1)
      FT_OFFSET(input, fts3rec_v1)
      FT_OFFSET(output, fts3rec_v1)
      FT_OFFSET(dPkts, fts3rec_v1)
      FT_OFFSET(dOctets, fts3rec_v1)
      FT_OFFSET(First, fts3rec_v1)
      FT_OFFSET(Last, fts3rec_v1)
      FT_OFFSET(srcport, fts3rec_v1)
      FT_OFFSET(dstport, fts3rec_v1)
      FT_OFFSET(prot, fts3rec_v1)
      FT_OFFSET(tos, fts3rec_v1)
      FT_OFFSET(tcp_flags, fts3rec_v1)
      ret = 0;
      break;

    case 5:
      FT_OFFSET(unix_secs, fts3rec_v5)
      FT_OFFSET(unix_nsecs, fts3rec_v5)
      FT_OFFSET(sysUpTime, fts3rec_v5)
      FT_OFFSET(exaddr, fts3rec_v5)
      FT_OFFSET(srcaddr, fts3rec_v5)
      FT_OFFSET(dstaddr, fts3rec_v5)
      FT_OFFSET(nexthop, fts3rec_v5)
      FT_OFFSET(input, fts3rec_v5)
      FT_OFFSET(output, fts3rec_v5)
      FT_OFFSET(dPkts, fts3rec_v5)
      FT_OFFSET(dOctets, fts3rec_v5)
      FT_OFFSET(First, fts3rec_v5)
      FT_OFFSET(Last, fts3rec_v5)
      FT_OFFSET(srcport, fts3rec_v5)
      FT_OFFSET(dstport, fts3rec_v5)
      FT_OFFSET(prot, fts3rec_v5)
      FT_OFFSET(tos, fts3rec_v5)
      FT_OFFSET(tcp_flags, fts3rec_v5)
      FT_OFFSET(engine_type, fts3rec_v5)
      FT_OFFSET(engine_id, fts3rec_v5)
      FT_OFFSET(src_mask, fts3rec_v5)
      FT_OFFSET(dst_mask, fts3rec_v5)
      FT_OFFSET(src_as, fts3rec_v5)
      FT_OFFSET(dst_as, fts3rec_v5)
      ret = 0;
      break;

    case 6:
      FT_OFFSET(unix_secs, fts3rec_v6)
      FT_OFFSET(unix_nsecs, fts3rec_v6)
      FT_OFFSET(sysUpTime, fts3rec_v6)
      FT_OFFSET(exaddr, fts3rec_v6)
      FT_OFFSET(srcaddr, fts3rec_v6)
      FT_OFFSET(dstaddr, fts3rec_v6)
      FT_OFFSET(nexthop, fts3rec_v6)
      FT_OFFSET(input, fts3rec_v6)
      FT_OFFSET(output, fts3rec_v6)
      FT_OFFSET(dPkts, fts3rec_v6)
      FT_OFFSET(dOctets, fts3rec_v6)
      FT_OFFSET(First, fts3rec_v6)
      FT_OFFSET(Last, fts3rec_v6)
      FT_OFFSET(srcport, fts3rec_v6)
      FT_OFFSET(dstport, fts3rec_v6)
      FT_OFFSET(prot, fts3rec_v6)
      FT_OFFSET(tos, fts3rec_v6)
      FT_OFFSET(tcp_flags, fts3rec_v6)
      FT_OFFSET(engine_type, fts3rec_v6)
      FT_OFFSET(engine_id, fts3rec_v6)
      FT_OFFSET(src_mask, fts3rec_v6)
      FT_OFFSET(dst_mask, fts3rec_v6)
      FT_OFFSET(src_as, fts3rec_v6)
      FT_OFFSET(dst_as, fts3rec_v6)
      FT_OFFSET(in_encaps, fts3rec_v6)
      FT_OFFSET(out_encaps, fts3rec_v6)
      FT_OFFSET(peer_nexthop, fts3rec_v6)
      ret = 0;
      break;

    case 7:
      FT_OFFSET(unix_secs, fts3rec_v7)
      FT_OFFSET(unix_nsecs, fts3rec_v7)
      FT_OFFSET(sysUpTime, fts3rec_v7)
      FT_OFFSET(exaddr, fts3rec_v7)
      FT_OFFSET(srcaddr, fts3rec_v7)
      FT_OFFSET(dstaddr, fts3rec_v7)
      FT_OFFSET(nexthop, fts3rec_v7)
      FT_OFFSET(input, fts3rec_v7)
      FT_OFFSET(output, fts3rec_v7)
      FT_OFFSET(dPkts, fts3rec_v7)
      FT_OFFSET(dOctets, fts3rec_v7)
      FT_OFFSET(First, fts3rec_v7)
      FT_OFFSET(Last, fts3rec_v7)
      FT_OFFSET(srcport, fts3rec_v7)
      FT_OFFSET(dstport, fts3rec_v7)
      FT_OFFSET(prot, fts3rec_v7)
      FT_OFFSET(tos, fts3rec_v7)
      FT_OFFSET(tcp_flags, fts3rec_v7)
      FT_OFFSET(engine_type, fts3rec_v7)
      FT_OFFSET(engine_id, fts3rec_v7)
      FT_OFFSET(src_mask, fts3rec_v7)
      FT_OFFSET(dst_mask, fts3rec_v7)
      FT_OFFSET(src_as, fts3rec_v7)
      FT_OFFSET(dst_as, fts3rec_v7)
      FT_OFFSET(router_sc, fts3rec_v7)
      ret = 0;
      break;

    case 8:

      switch (ftv->agg_method) {

        case 1:
          FT_OFFSET(unix_secs, fts3rec_v8_1)
          FT_OFFSET(unix_nsecs, fts3rec_v8_1)
          FT_OFFSET(sysUpTime, fts3rec_v8_1)
          FT_OFFSET(exaddr, fts3rec_v8_1)
          FT_OFFSET(dFlows, fts3rec_v8_1)
          FT_OFFSET(dOctets, fts3rec_v8_1)
          FT_OFFSET(dPkts, fts3rec_v8_1)
          FT_OFFSET(First, fts3rec_v8_1)
          FT_OFFSET(Last, fts3rec_v8_1)
          FT_OFFSET(src_as, fts3rec_v8_1)
          FT_OFFSET(dst_as, fts3rec_v8_1)
          FT_OFFSET(input, fts3rec_v8_1)
          FT_OFFSET(output, fts3rec_v8_1)
          FT_OFFSET(engine_id, fts3rec_v8_1)
          FT_OFFSET(engine_type, fts3rec_v8_1)
          ret = 0;
          break;

        case 2:
          FT_OFFSET(unix_secs, fts3rec_v8_2)
          FT_OFFSET(unix_nsecs, fts3rec_v8_2)
          FT_OFFSET(sysUpTime, fts3rec_v8_2)
          FT_OFFSET(exaddr, fts3rec_v8_2)
          FT_OFFSET(dFlows, fts3rec_v8_2)
          FT_OFFSET(dOctets, fts3rec_v8_2)
          FT_OFFSET(dPkts, fts3rec_v8_2)
          FT_OFFSET(First, fts3rec_v8_2)
          FT_OFFSET(Last, fts3rec_v8_2)
          FT_OFFSET(prot, fts3rec_v8_2)
          FT_OFFSET(srcport, fts3rec_v8_2)
          FT_OFFSET(dstport, fts3rec_v8_2)
          FT_OFFSET(engine_id, fts3rec_v8_2)
          FT_OFFSET(engine_type, fts3rec_v8_2)
          ret = 0;
          break;

        case 3:
          FT_OFFSET(unix_secs, fts3rec_v8_3)
          FT_OFFSET(unix_nsecs, fts3rec_v8_3)
          FT_OFFSET(sysUpTime, fts3rec_v8_3)
          FT_OFFSET(exaddr, fts3rec_v8_3)
          FT_OFFSET(dFlows, fts3rec_v8_3)
          FT_OFFSET(dOctets, fts3rec_v8_3)
          FT_OFFSET(dPkts, fts3rec_v8_3)
          FT_OFFSET(First, fts3rec_v8_3)
          FT_OFFSET(Last, fts3rec_v8_3)
          FT_OFFSET(srcaddr, fts3rec_v8_3)
          FT_OFFSET(src_mask, fts3rec_v8_3)
          FT_OFFSET(src_as, fts3rec_v8_3)
          FT_OFFSET(input, fts3rec_v8_3)
          FT_OFFSET(engine_id, fts3rec_v8_3)
          FT_OFFSET(engine_type, fts3rec_v8_3)
          ret = 0;
          break;

        case 4:
          FT_OFFSET(unix_secs, fts3rec_v8_4)
          FT_OFFSET(unix_nsecs, fts3rec_v8_4)
          FT_OFFSET(sysUpTime, fts3rec_v8_4)
          FT_OFFSET(exaddr, fts3rec_v8_4)
          FT_OFFSET(dFlows, fts3rec_v8_4)
          FT_OFFSET(dOctets, fts3rec_v8_4)
          FT_OFFSET(dPkts, fts3rec_v8_4)
          FT_OFFSET(First, fts3rec_v8_4)
          FT_OFFSET(Last, fts3rec_v8_4)
          FT_OFFSET(dstaddr, fts3rec_v8_4)
          FT_OFFSET(dst_mask, fts3rec_v8_4)
          FT_OFFSET(dst_as, fts3rec_v8_4)
          FT_OFFSET(output, fts3rec_v8_4)
          FT_OFFSET(engine_id, fts3rec_v8_4)
          FT_OFFSET(engine_type, fts3rec_v8_4)
          ret = 0;
          break;

        case 5:
          FT_OFFSET(unix_secs, fts3rec_v8_5)
          FT_OFFSET(unix_nsecs, fts3rec_v8_5)
          FT_OFFSET(sysUpTime, fts3rec_v8_5)
          FT_OFFSET(exaddr, fts3rec_v8_5)
          FT_OFFSET(dFlows, fts3rec_v8_5)
          FT_OFFSET(dOctets, fts3rec_v8_5)
          FT_OFFSET(dPkts, fts3rec_v8_5)
          FT_OFFSET(First, fts3rec_v8_5)
          FT_OFFSET(Last, fts3rec_v8_5)
          FT_OFFSET(srcaddr, fts3rec_v8_5)
          FT_OFFSET(src_mask, fts3rec_v8_5)
          FT_OFFSET(src_as, fts3rec_v8_5)
          FT_OFFSET(dstaddr, fts3rec_v8_5)
          FT_OFFSET(dst_mask, fts3rec_v8_5)
          FT_OFFSET(dst_as, fts3rec_v8_5)
          FT_OFFSET(input, fts3rec_v8_5)
          FT_OFFSET(output, fts3rec_v8_5)
          FT_OFFSET(engine_id, fts3rec_v8_5)
          FT_OFFSET(engine_type, fts3rec_v8_5)
          ret = 0;
          break;

        case 6:
          FT_OFFSET(unix_secs, fts3rec_v8_6)
          FT_OFFSET(unix_nsecs, fts3rec_v8_6)
          FT_OFFSET(sysUpTime, fts3rec_v8_6)
          FT_OFFSET(exaddr, fts3rec_v8_6)
          FT_OFFSET(dPkts, fts3rec_v8_6)
          FT_OFFSET(dOctets, fts3rec_v8_6)
          FT_OFFSET(First, fts3rec_v8_6)
          FT_OFFSET(Last, fts3rec_v8_6)
          FT_OFFSET(dstaddr, fts3rec_v8_6)
          FT_OFFSET(extra_pkts, fts3rec_v8_6)
          FT_OFFSET(router_sc, fts3rec_v8_6)
          FT_OFFSET(output, fts3rec_v8_6)
          FT_OFFSET(tos, fts3rec_v8_6)
          FT_OFFSET(marked_tos, fts3rec_v8_6)
          FT_OFFSET(engine_type, fts3rec_v8_6)
          FT_OFFSET(engine_id, fts3rec_v8_6)
          ret = 0;
          break;

        case 7:
          FT_OFFSET(unix_secs, fts3rec_v8_7)
          FT_OFFSET(unix_nsecs, fts3rec_v8_7)
          FT_OFFSET(sysUpTime, fts3rec_v8_7)
          FT_OFFSET(exaddr, fts3rec_v8_7)
          FT_OFFSET(dPkts, fts3rec_v8_7)
          FT_OFFSET(dOctets, fts3rec_v8_7)
          FT_OFFSET(First, fts3rec_v8_7)
          FT_OFFSET(Last, fts3rec_v8_7)
          FT_OFFSET(dstaddr, fts3rec_v8_7)
          FT_OFFSET(srcaddr, fts3rec_v8_7)
          FT_OFFSET(extra_pkts, fts3rec_v8_7)
          FT_OFFSET(router_sc, fts3rec_v8_7)
          FT_OFFSET(output, fts3rec_v8_7)
          FT_OFFSET(input, fts3rec_v8_7)
          FT_OFFSET(tos, fts3rec_v8_7)
          FT_OFFSET(marked_tos, fts3rec_v8_7)
          FT_OFFSET(engine_type, fts3rec_v8_7)
          FT_OFFSET(engine_id, fts3rec_v8_7)
          ret = 0;
          break;

        case 8:
          FT_OFFSET(unix_secs, fts3rec_v8_8)
          FT_OFFSET(unix_nsecs, fts3rec_v8_8)
          FT_OFFSET(sysUpTime, fts3rec_v8_8)
          FT_OFFSET(exaddr, fts3rec_v8_8)
          FT_OFFSET(dPkts, fts3rec_v8_8)
          FT_OFFSET(dOctets, fts3rec_v8_8)
          FT_OFFSET(First, fts3rec_v8_8)
          FT_OFFSET(Last, fts3rec_v8_8)
          FT_OFFSET(dstaddr, fts3rec_v8_8)
          FT_OFFSET(srcaddr, fts3rec_v8_8)
          FT_OFFSET(extra_pkts, fts3rec_v8_8)
          FT_OFFSET(router_sc, fts3rec_v8_8)
          FT_OFFSET(srcport, fts3rec_v8_8)
          FT_OFFSET(dstport, fts3rec_v8_8)
          FT_OFFSET(output, fts3rec_v8_8)
          FT_OFFSET(input, fts3rec_v8_8)
          FT_OFFSET(tos, fts3rec_v8_8)
          FT_OFFSET(marked_tos, fts3rec_v8_8)
          FT_OFFSET(engine_type, fts3rec_v8_8)
          FT_OFFSET(engine_id, fts3rec_v8_8)
          FT_OFFSET(prot, fts3rec_v8_8)
          ret = 0;
          break;

        case 9:
          FT_OFFSET(unix_secs, fts3rec_v8_9)
          FT_OFFSET(unix_nsecs, fts3rec_v8_9)
          FT_OFFSET(sysUpTime, fts3rec_v8_9)
          FT_OFFSET(exaddr, fts3rec_v8_9)
          FT_OFFSET(dFlows, fts3rec_v8_9)
          FT_OFFSET(dPkts, fts3rec_v8_9)
          FT_OFFSET(dOctets, fts3rec_v8_9)
          FT_OFFSET(First, fts3rec_v8_9)
          FT_OFFSET(Last, fts3rec_v8_9)
          FT_OFFSET(src_as, fts3rec_v8_9)
          FT_OFFSET(dst_as, fts3rec_v8_9)
          FT_OFFSET(input, fts3rec_v8_9)
          FT_OFFSET(output, fts3rec_v8_9)
          FT_OFFSET(engine_type, fts3rec_v8_9)
          FT_OFFSET(engine_id, fts3rec_v8_9)
          FT_OFFSET(tos, fts3rec_v8_9)
          ret = 0;
          break;

        case 10:
          FT_OFFSET(unix_secs, fts3rec_v8_10)
          FT_OFFSET(unix_nsecs, fts3rec_v8_10)
          FT_OFFSET(sysUpTime, fts3rec_v8_10)
          FT_OFFSET(exaddr, fts3rec_v8_10)
          FT_OFFSET(dFlows, fts3rec_v8_10)
          FT_OFFSET(dPkts, fts3rec_v8_10)
          FT_OFFSET(dOctets, fts3rec_v8_10)
          FT_OFFSET(First, fts3rec_v8_10)
          FT_OFFSET(Last, fts3rec_v8_10)
          FT_OFFSET(srcport, fts3rec_v8_10)
          FT_OFFSET(dstport, fts3rec_v8_10)
          FT_OFFSET(input, fts3rec_v8_10)
          FT_OFFSET(output, fts3rec_v8_10)
          FT_OFFSET(engine_type, fts3rec_v8_10)
          FT_OFFSET(engine_id, fts3rec_v8_10)
          FT_OFFSET(prot, fts3rec_v8_10)
          FT_OFFSET(tos, fts3rec_v8_10)
          ret = 0;
          break;

        case 11:
          FT_OFFSET(unix_secs, fts3rec_v8_11)
          FT_OFFSET(unix_nsecs, fts3rec_v8_11)
          FT_OFFSET(sysUpTime, fts3rec_v8_11)
          FT_OFFSET(exaddr, fts3rec_v8_11)
          FT_OFFSET(dFlows, fts3rec_v8_11)
          FT_OFFSET(dPkts, fts3rec_v8_11)
          FT_OFFSET(dOctets, fts3rec_v8_11)
          FT_OFFSET(First, fts3rec_v8_11)
          FT_OFFSET(Last, fts3rec_v8_11)
          FT_OFFSET(srcaddr, fts3rec_v8_11)
          FT_OFFSET(src_mask, fts3rec_v8_11)
          FT_OFFSET(tos, fts3rec_v8_11)
          FT_OFFSET(src_as, fts3rec_v8_11)
          FT_OFFSET(input, fts3rec_v8_11)
          FT_OFFSET(engine_type, fts3rec_v8_11)
          FT_OFFSET(engine_id, fts3rec_v8_11)
          ret = 0;
          break;

        case 12:
          FT_OFFSET(unix_secs, fts3rec_v8_12)
          FT_OFFSET(unix_nsecs, fts3rec_v8_12)
          FT_OFFSET(sysUpTime, fts3rec_v8_12)
          FT_OFFSET(exaddr, fts3rec_v8_12)
          FT_OFFSET(dFlows, fts3rec_v8_12)
          FT_OFFSET(dPkts, fts3rec_v8_12)
          FT_OFFSET(dOctets, fts3rec_v8_12)
          FT_OFFSET(First, fts3rec_v8_12)
          FT_OFFSET(Last, fts3rec_v8_12)
          FT_OFFSET(dstaddr, fts3rec_v8_12)
          FT_OFFSET(output, fts3rec_v8_12)
          FT_OFFSET(dst_as, fts3rec_v8_12)
          FT_OFFSET(dst_mask, fts3rec_v8_12)
          FT_OFFSET(tos, fts3rec_v8_12)
          FT_OFFSET(engine_type, fts3rec_v8_12)
          FT_OFFSET(engine_id, fts3rec_v8_12)
          ret = 0;
          break;

        case 13:
          FT_OFFSET(unix_secs, fts3rec_v8_13)
          FT_OFFSET(unix_nsecs, fts3rec_v8_13)
          FT_OFFSET(sysUpTime, fts3rec_v8_13)
          FT_OFFSET(exaddr, fts3rec_v8_13)
          FT_OFFSET(dFlows, fts3rec_v8_13)
          FT_OFFSET(dPkts, fts3rec_v8_13)
          FT_OFFSET(dOctets, fts3rec_v8_13)
          FT_OFFSET(First, fts3rec_v8_13)
          FT_OFFSET(Last, fts3rec_v8_13)
          FT_OFFSET(srcaddr, fts3rec_v8_13)
          FT_OFFSET(dstaddr, fts3rec_v8_13)
          FT_OFFSET(src_as, fts3rec_v8_13)
          FT_OFFSET(dst_as, fts3rec_v8_13)
          FT_OFFSET(input, fts3rec_v8_13)
          FT_OFFSET(output, fts3rec_v8_13)
          FT_OFFSET(dst_mask, fts3rec_v8_13)
          FT_OFFSET(src_mask, fts3rec_v8_13)
          FT_OFFSET(engine_type, fts3rec_v8_13)
          FT_OFFSET(engine_id, fts3rec_v8_13)
          FT_OFFSET(tos, fts3rec_v8_13)
          ret = 0;
          break;

        case 14:
          FT_OFFSET(unix_secs, fts3rec_v8_14)
          FT_OFFSET(unix_nsecs, fts3rec_v8_14)
          FT_OFFSET(sysUpTime, fts3rec_v8_14)
          FT_OFFSET(exaddr, fts3rec_v8_14)
          FT_OFFSET(dFlows, fts3rec_v8_14)
          FT_OFFSET(dPkts, fts3rec_v8_14)
          FT_OFFSET(dOctets, fts3rec_v8_14)
          FT_OFFSET(First, fts3rec_v8_14)
          FT_OFFSET(Last, fts3rec_v8_14)
          FT_OFFSET(srcaddr, fts3rec_v8_14)
          FT_OFFSET(dstaddr, fts3rec_v8_14)
          FT_OFFSET(srcport, fts3rec_v8_14)
          FT_OFFSET(dstport, fts3rec_v8_14)
          FT_OFFSET(input, fts3rec_v8_14)
          FT_OFFSET(output, fts3rec_v8_14)
          FT_OFFSET(dst_mask, fts3rec_v8_14)
          FT_OFFSET(src_mask, fts3rec_v8_14)
          FT_OFFSET(engine_type, fts3rec_v8_14)
          FT_OFFSET(engine_id, fts3rec_v8_14)
          FT_OFFSET(tos, fts3rec_v8_14)
          FT_OFFSET(prot, fts3rec_v8_14)
          ret = 0;
          break;

      }
      break;

    case 1005:
      FT_OFFSET(unix_secs, fts3rec_v1005)
      FT_OFFSET(unix_nsecs, fts3rec_v1005)
      FT_OFFSET(sysUpTime, fts3rec_v1005)
      FT_OFFSET(exaddr, fts3rec_v1005)
      FT_OFFSET(srcaddr, fts3rec_v1005)
      FT_OFFSET(dstaddr, fts3rec_v1005)
      FT_OFFSET(nexthop, fts3rec_v1005)
      FT_OFFSET(input, fts3rec_v1005)
      FT_OFFSET(output, fts3rec_v1005)
      FT_OFFSET(dPkts, fts3rec_v1005)
      FT_OFFSET(dOctets, fts3rec_v1005)
      FT_OFFSET(First, fts3rec_v1005)
      FT_OFFSET(Last, fts3rec_v1005)
      FT_OFFSET(srcport, fts3rec_v1005)
      FT_OFFSET(dstport, fts3rec_v1005)
      FT_OFFSET(prot, fts3rec_v1005)
      FT_OFFSET(tos, fts3rec_v1005)
      FT_OFFSET(tcp_flags, fts3rec_v1005)
      FT_OFFSET(engine_type, fts3rec_v1005)
      FT_OFFSET(engine_id, fts3rec_v1005)
      FT_OFFSET(src_mask, fts3rec_v1005)
      FT_OFFSET(dst_mask, fts3rec_v1005)
      FT_OFFSET(src_as, fts3rec_v1005)
      FT_OFFSET(dst_as, fts3rec_v1005)
      FT_OFFSET(src_tag, fts3rec_v1005)
      FT_OFFSET(dst_tag, fts3rec_v1005)
      ret = 0;
      break;

  } /* switch */

  o->xfields = ftrec_xfield(ftv);

  bcopy(ftv, &o->ftv, sizeof *ftv);

  return ret;

} /* fts3rec_compute_offsets */

