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
 *      $Id: flow-dscan.h,v 1.9 2003/04/02 18:03:01 maf Exp $
 */

#include <sys/types.h>

#define DSCAN_FLAGS_HOSTSCAN  1   /* host scan */
#define DSCAN_FLAGS_PORTSCAN  2   /* port scan */

#define DSCAN_IP_DEPTH 200        /* IP's store,  IP scan trigger */
#define DSCAN_PORT_TRIGGER  64    /* port scan trigger */
#define DSCAN_HASHSIZE    65536   /* size of hash table */
#define DSCAN_STATEFILE "/var/tmp/dscan.state"
#define DSCAN_AGER_TIMEOUT 90000U /* max active flows before aging */
#define DSCAN_AGER_WORK 500       /* ammount of work ager does in a run */
#define DSCAN_HASHFUNC(a) ((a>>16) ^ (a & 0xFFFF))

#define DSCAN_SUP_FILE "./dscan.suppress" /* suppress file */
#define DSCAN_SUP_SRCIP   1     /* match src ip */
#define DSCAN_SUP_DSTIP   2     /* match dst ip */
#define DSCAN_SUP_SRCPORT 4     /* match src port */
#define DSCAN_SUP_DSTPORT 8     /* match dst port */
#define DSCAN_SUP_PROTOCOL  16  /* match protocol */


struct dscan_state {
  FT_SLIST_HEAD(shead, dscan_rec) hash_scan[DSCAN_HASHSIZE];
  FT_SLIST_HEAD(sup_src_head, dscan_sup) hash_sup_src[DSCAN_HASHSIZE];
  FT_SLIST_HEAD(sup_dst_head, dscan_sup) hash_sup_dst[DSCAN_HASHSIZE];
  unsigned int stat_malloc;        /* # of times malloc called */
  unsigned int stat_free;          /* # of times free called */
  unsigned int stat_malloc_dst;    /* # of times dst struct allocated */
  unsigned int stat_malloc_rec;    /* # of times rec struct allocated */
  unsigned int stat_free_dst;      /* # of times dst struct freed */
  unsigned int stat_free_rec;      /* # of times rec struct freed */
  unsigned int stat_aged_ip;       /* # dst ip in the list is removed */
  unsigned int stat_aged_dsr;      /* # of dscan records removed */
  uint32_t   ager_timeout;   /* how long to keep flows around */
  uint32_t   dscan_ip_depth; /* lengh of ip destination list */
  uint32_t   dscan_port_trigger; /* # ports hit before scan trggers */
  char    *statefile;       /* where to store/load state */
  char    *supfile;         /* suppress list file */
};

struct dscan_dst {
    uint32_t ip_dst;                /* destination IP */
    uint32_t ip_time;               /* last time dst IP seen */
    struct bit1024 portmap;        /* active destination ports */
  FT_STAILQ_ENTRY  (dscan_dst) chain; /* chain */
};

struct dscan_rec {
  uint8_t    depth;             /* 0..255 depth of list */
  uint8_t    flags;             /* DSCAN_FLAGS_* */
  uint32_t   ip_src;            /* src ip address (key) */
  FT_STAILQ_HEAD(dhead, dscan_dst) dlhead; /* head of dst list */
  FT_SLIST_ENTRY (dscan_rec) chain;  /* chain */
};

struct dscan_sup {
  uint32_t ip;
  uint16_t srcport;
  uint16_t dstport;
  uint8_t  flags;
  uint8_t  protocol;
  FT_SLIST_ENTRY (dscan_sup) chain;  /* chain */
};

