/*
 * Copyright (c) 2002 Mark Fullmer and The Ohio State University
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
 *      $Id: ftstat.c,v 1.44 2005/05/10 15:48:12 maf Exp $
 */

#include "ftconfig.h"
#include "ftlib.h"

#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stddef.h>
#include <syslog.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <zlib.h>

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif

#if !HAVE_STRSEP
  char    *strsep (char **, const char *);
#endif

#if HAVE_LL_STRTOUL
  #define strtoull strtoul
#endif /* HAVE_LL_STRTOULL */

#define FMT_SYM_LEN 64

/*
 * ****  Datastructures and other implementation notes  ***
 *
 * Each report requires
 *
 *   struct ftstat_rpt_n which is allocated dynamically at run time.
 *  
 *   ftstat_rpt_n_new() -   allocated ftstat_rpt_n
 *   ftstat_rpt_n_accum() - called for each flow
 *   ftstat_rpt_n_calc()  - final calculations after all flows
 *   ftstat_rpt_n_dump()  - report to file
 *   ftstat_rpt_n_free()  - free storage allocated by ftstat_rpt_n_new()
 *     and others during the report run.
 *
 * The reports are grouped by a definition.  Typically the caller will
 * invoke all reports in a group by calling ftstat_def_new(),
 * ftstat_def_accum(), ftstat_def_calc(), ftstat_def_dump(), and
 * ftstat_def_free().
 *
 * The reports in the configuration file are stored in a linked
 * list of ftstat_rpt with the head in struct ftstat.
 *
 * The definitions in the configuration file are stored in a linked
 * list of ftstat_def with the head in struct ftstat.
 *
 * Each definition contains a linked list of ftstat_rpt_item
 * which points to a report (struct ftstat_rpt).
 *
 * Definitions reference reports.  Initially the report name is stored
 * in the definition and then when EOF is reached resolve_reports()
 * is called to fill in the pointers.
 *
 * The config file can reference a filter file and a tag file.  These
 * are loaded when the first tag or filter is specified.
 *
 * Each report can have a filter and a definition can have a filter
 * for all the reports.  Configuration of both is allowed.
 *
 * Each definition can invoke a tag definition. (add tags)
 *
 * Each definition can invoke a mask definition. (replace masks)
 *
 * Each report type is defined by the enum ftstat_rpt_type
 * and then the struct typelookup (tlookup) is used to configure
 * all the other report specific data items such as its ASCII
 * name, fields required, function pointers to the report specific
 * functions, options supported, etc.
 *
 * Special note for the *ps (ie min_pps, max_pps, avg_pps, min_bps,
 *  max_bps, avg_bps) calculations.  A memory optimization exists that
 *  removes the sizeof struct ftps bytes from the end of all the hash
 *  and bucket allocations (for bucket, they're not allocated).  This
 *  means that struct _must_ exist or the subtraction bytes will end
 *  up trashing real data.  An example is ftchash_rec_int where the
 *  ftps would never be used, yet it's there so the code that subtracts
 *  it off works properly.
 *
 */

static struct fts3rec_offsets nfo;
static u_int64 *sort_i64;
static double *sort_idouble;

#define DUMP_STD_OUT()\
if (rpt->out->fields & FT_STAT_FIELD_INDEX) {\
  len += fmt_uint64(fmt_buf, rpt->idx++, FMT_JUST_LEFT);\
  comma = 1;\
}\
if (rpt->out->fields & FT_STAT_FIELD_FIRST) {\
  if (comma) fmt_buf[len++] = ',';\
  len += fmt_uint32(fmt_buf+len, rpt->time_start, FMT_JUST_LEFT);\
  comma = 1;\
}\
if (rpt->out->fields & FT_STAT_FIELD_LAST) {\
  if (comma) fmt_buf[len++] = ',';\
  len += fmt_uint32(fmt_buf+len, rpt->time_end, FMT_JUST_LEFT);\
  comma = 1;\
}\


#define CHASH_DUMP_INIT(A,B)\
  struct A *B;\
  struct tally tally;\
  char fmt_buf1[32], fmt_buf[1024];\
  int len, fmt, sort_flags, sort_offset, comma;\
  fmt = FMT_JUST_LEFT;\
  fmt_buf1[0] = fmt_buf[0] = 0;\
  bzero(&tally, sizeof tally);\
  tally.t_recs = ftch->entries;\
  if (rpt->out->options & FT_STAT_OPT_NAMES)\
    fmt |= FMT_SYM;\


#define CHASH_DUMP_STD_SORT(A) \
    if (rpt->out->sort_field == FT_STAT_FIELD_FLOWS) {\
      sort_offset = offsetof(struct A, nflows);\
      sort_flags |= FT_CHASH_SORT_64;\
    } else if (rpt->out->sort_field == FT_STAT_FIELD_OCTETS) {\
      sort_offset = offsetof(struct A, noctets);\
      sort_flags |= FT_CHASH_SORT_64;\
    } else if (rpt->out->sort_field == FT_STAT_FIELD_PACKETS) {\
      sort_offset = offsetof(struct A, npackets);\
      sort_flags |= FT_CHASH_SORT_64;\
    } else if (rpt->out->sort_field == FT_STAT_FIELD_DURATION) {\
      sort_offset = offsetof(struct A, etime);\
      sort_flags |= FT_CHASH_SORT_64;\
    } else if (rpt->out->sort_field == FT_STAT_FIELD_AVG_PPS) {\
      sort_offset = offsetof(struct A, ps.avg_pps);\
      sort_flags |= FT_CHASH_SORT_DOUBLE;\
    } else if (rpt->out->sort_field == FT_STAT_FIELD_MIN_PPS) {\
      sort_offset = offsetof(struct A, ps.min_pps);\
      sort_flags |= FT_CHASH_SORT_DOUBLE;\
    } else if (rpt->out->sort_field == FT_STAT_FIELD_MAX_PPS) {\
      sort_offset = offsetof(struct A, ps.max_pps);\
      sort_flags |= FT_CHASH_SORT_DOUBLE;\
    } else if (rpt->out->sort_field == FT_STAT_FIELD_AVG_BPS) {\
      sort_offset = offsetof(struct A, ps.avg_bps);\
      sort_flags |= FT_CHASH_SORT_DOUBLE;\
    } else if (rpt->out->sort_field == FT_STAT_FIELD_MIN_BPS) {\
      sort_offset = offsetof(struct A, ps.min_bps);\
      sort_flags |= FT_CHASH_SORT_DOUBLE;\
    } else if (rpt->out->sort_field == FT_STAT_FIELD_MAX_BPS) {\
      sort_offset = offsetof(struct A, ps.max_bps);\
      sort_flags |= FT_CHASH_SORT_DOUBLE;\
    } else {\
      fterr_errx(1,"chash_xxx_dump(): internal error");\
    }

#define CHASH_STD_OUT(A,B)\
      if ((rpt->out->options & FT_STAT_OPT_TALLY) && tally.rt_recs &&\
        (!(tally.rt_recs % rpt->out->tally))) {\
        if (rpt->all_fields & FT_STAT_FIELD_PS)\
          fprintf(fp, "#TALLY %%recs=%3.3f %%flows=%3.3f %%octets=%3.3f %%packets=%3.3f %%avg-bps=%3.3f %%avg-pps=%3.3f\n",\
            ((double)tally.rt_recs/(double)tally.t_recs)*100,\
            ((double)tally.rt_flows/(double)rpt->t_flows)*100,\
            ((double)tally.rt_octets/(double)rpt->t_octets)*100,\
            ((double)tally.rt_packets/(double)rpt->t_packets)*100,\
            (((double)tally.ravg_bps/(double)tally.rt_frecs)/\
              (double)rpt->avg_bps)*100,\
            (((double)tally.ravg_pps/(double)tally.rt_frecs)/\
              (double)rpt->avg_pps)*100);\
         else\
          fprintf(fp, "#TALLY %%recs=%3.3f %%flows=%3.3f %%octets=%3.3f %%packets=%3.3f\n",\
            ((double)tally.rt_recs/(double)tally.t_recs)*100,\
            ((double)tally.rt_flows/(double)rpt->t_flows)*100,\
            ((double)tally.rt_octets/(double)rpt->t_octets)*100,\
            ((double)tally.rt_packets/(double)rpt->t_packets)*100);\
\
      } /* tally */\
      tally.rt_flows += A->nflows;\
      tally.rt_octets += A->noctets;\
      tally.rt_packets += A->npackets;\
      tally.rt_recs ++;\
      tally.rt_frecs += A->nrecs;\
      if (rpt->all_fields & FT_STAT_FIELD_PS) {\
        tally.ravg_bps += A->ps.avg_bps * A->nrecs;\
        tally.ravg_pps += A->ps.avg_pps * A->nrecs;\
      }\
\
    if (rpt->out->fields & FT_STAT_FIELD_FLOWS) {\
      if (B) fmt_buf[len++] = ',';\
      len += fmt_uint64(fmt_buf+len, A->nflows, FMT_JUST_LEFT);\
      comma = 1;\
    }\
    if (rpt->out->fields & FT_STAT_FIELD_OCTETS) {\
      if (comma) fmt_buf[len++] = ',';\
      len += fmt_uint64(fmt_buf+len, A->noctets, FMT_JUST_LEFT);\
      comma = 1;\
    }\
    if (rpt->out->fields & FT_STAT_FIELD_PACKETS) {\
      if (comma) fmt_buf[len++] = ',';\
      len += fmt_uint64(fmt_buf+len, A->npackets, FMT_JUST_LEFT);\
      comma = 1;\
    }\
    if (rpt->out->fields & FT_STAT_FIELD_DURATION) {\
      if (comma) fmt_buf[len++] = ',';\
      len += fmt_uint64(fmt_buf+len, A->etime, FMT_JUST_LEFT);\
      comma = 1;\
    }\
    if (rpt->out->fields & FT_STAT_FIELD_AVG_BPS) {\
      if (comma) fmt_buf[len++] = ',';\
      len += sprintf(fmt_buf+len, "%f", A->ps.avg_bps);\
      comma = 1;\
    }\
    if (rpt->out->fields & FT_STAT_FIELD_MIN_BPS) {\
      if (comma) fmt_buf[len++] = ',';\
      len += sprintf(fmt_buf+len, "%f", A->ps.min_bps);\
      comma = 1;\
    }\
    if (rpt->out->fields & FT_STAT_FIELD_MAX_BPS) {\
      if (comma) fmt_buf[len++] = ',';\
      len += sprintf(fmt_buf+len, "%f", A->ps.max_bps);\
      comma = 1;\
    }\
    if (rpt->out->fields & FT_STAT_FIELD_AVG_PPS) {\
      if (comma) fmt_buf[len++] = ',';\
      len += sprintf(fmt_buf+len, "%f", A->ps.avg_pps);\
      comma = 1;\
    }\
    if (rpt->out->fields & FT_STAT_FIELD_MIN_PPS) {\
      if (comma) fmt_buf[len++] = ',';\
      len += sprintf(fmt_buf+len, "%f", A->ps.min_pps);\
      comma = 1;\
    }\
    if (rpt->out->fields & FT_STAT_FIELD_MAX_PPS) {\
      if (comma) fmt_buf[len++] = ',';\
      len += sprintf(fmt_buf+len, "%f", A->ps.max_pps);\
      comma = 1;\
    }\
    if (rpt->out->fields & FT_STAT_FIELD_FRECS) {\
      if (comma) fmt_buf[len++] = ',';\
      len += fmt_uint64(fmt_buf+len, A->nrecs, FMT_JUST_LEFT);\
      comma = 1;\
    }\
    fmt_buf[len++] = '\n';\
    fmt_buf[len] = 0;\
    fputs(fmt_buf, fp);\
    if (rpt->out->records && (tally.rt_recs == rpt->out->records)) {\
      fprintf(fp, "# stop, hit record limit.\n");\
      break;\
    }

#define CHASH_STDP_OUT(A,B)\
      if ((rpt->out->options & FT_STAT_OPT_TALLY) && tally.rt_recs &&\
        (!(tally.rt_recs % rpt->out->tally))) {\
        if (rpt->all_fields & FT_STAT_FIELD_PS)\
          fprintf(fp, "#TALLY %%recs=%3.3f %%flows=%3.3f %%octets=%3.3f %%packets=%3.3f %%avg-bps=%3.3f %%avg-pps=%3.3f\n",\
            ((double)tally.rt_recs/(double)tally.t_recs)*100,\
            ((double)tally.rt_flows/(double)rpt->t_flows)*100,\
            ((double)tally.rt_octets/(double)rpt->t_octets)*100,\
            ((double)tally.rt_packets/(double)rpt->t_packets)*100,\
            (((double)tally.ravg_bps/(double)tally.rt_frecs)/\
              (double)rpt->avg_bps)*100,\
            (((double)tally.ravg_pps/(double)tally.rt_frecs)/\
              (double)rpt->avg_pps)*100);\
         else\
          fprintf(fp, "#TALLY %%recs=%3.3f %%flows=%3.3f %%octets=%3.3f %%packets=%3.3f\n",\
            ((double)tally.rt_recs/(double)tally.t_recs)*100,\
            ((double)tally.rt_flows/(double)rpt->t_flows)*100,\
            ((double)tally.rt_octets/(double)rpt->t_octets)*100,\
            ((double)tally.rt_packets/(double)rpt->t_packets)*100);\
\
      } /* tally */\
      tally.rt_flows += A->nflows;\
      tally.rt_octets += A->noctets;\
      tally.rt_packets += A->npackets;\
      tally.ravg_bps += A->ps.avg_bps * A->nrecs;\
      tally.ravg_pps += A->ps.avg_pps * A->nrecs;\
      tally.rt_recs ++;\
      tally.rt_frecs += A->nrecs;\
\
  if (rpt->out->fields & FT_STAT_FIELD_FLOWS) {\
    if (B) fmt_buf[len++] = ',';\
    len += sprintf(fmt_buf+len, "%f",\
     ((double)A->nflows / (double)rpt->t_flows)*100.0);\
    comma = 1;\
  }\
  if (rpt->out->fields & FT_STAT_FIELD_OCTETS) {\
    if (comma) fmt_buf[len++] = ',';\
    len += sprintf(fmt_buf+len, "%f",\
     ((double)A->noctets / (double)rpt->t_octets)*100.0);\
    comma = 1;\
  }\
  if (rpt->out->fields & FT_STAT_FIELD_PACKETS) {\
    if (comma) fmt_buf[len++] = ',';\
    len += sprintf(fmt_buf+len, "%f",\
     ((double)A->npackets / (double)rpt->t_packets)*100.0);\
    comma = 1;\
  }\
  if (rpt->out->fields & FT_STAT_FIELD_DURATION) {\
    if (comma) fmt_buf[len++] = ',';\
    len += sprintf(fmt_buf+len, "%f",\
     ((double)A->etime / (double)rpt->t_duration)*100.0);\
    comma = 1;\
  }\
  if (rpt->out->fields & FT_STAT_FIELD_AVG_BPS) {\
    if (comma) fmt_buf[len++] = ',';\
    len += sprintf(fmt_buf+len, "%f",\
     ((double)A->ps.avg_bps / (double)rpt->avg_bps)*100.0);\
    comma = 1;\
  }\
  if (rpt->out->fields & FT_STAT_FIELD_MIN_BPS) {\
    if (comma) fmt_buf[len++] = ',';\
    len += sprintf(fmt_buf+len, "%f",\
     ((double)A->ps.min_bps / (double)rpt->min_bps)*100.0);\
    comma = 1;\
  }\
  if (rpt->out->fields & FT_STAT_FIELD_MAX_BPS) {\
    if (comma) fmt_buf[len++] = ',';\
    len += sprintf(fmt_buf+len, "%f",\
     ((double)A->ps.max_bps / (double)rpt->max_bps)*100.0);\
    comma = 1;\
  }\
  if (rpt->out->fields & FT_STAT_FIELD_AVG_PPS) {\
    if (comma) fmt_buf[len++] = ',';\
    len += sprintf(fmt_buf+len, "%f",\
     ((double)A->ps.avg_pps / (double)rpt->avg_pps)*100.0);\
    comma = 1;\
  }\
  if (rpt->out->fields & FT_STAT_FIELD_MIN_PPS) {\
    if (comma) fmt_buf[len++] = ',';\
    len += sprintf(fmt_buf+len, "%f",\
     ((double)A->ps.min_pps / (double)rpt->min_pps)*100.0);\
    comma = 1;\
  }\
  if (rpt->out->fields & FT_STAT_FIELD_MAX_PPS) {\
    if (comma) fmt_buf[len++] = ',';\
    len += sprintf(fmt_buf+len, "%f",\
     ((double)A->ps.max_pps / (double)rpt->max_pps)*100.0);\
    comma = 1;\
  }\
  if (rpt->out->fields & FT_STAT_FIELD_FRECS) {\
    if (comma) fmt_buf[len++] = ',';\
    len += fmt_uint64(fmt_buf+len, A->nrecs, FMT_JUST_LEFT);\
    comma = 1;\
  }\
  fmt_buf[len++] = '\n';\
  fmt_buf[len] = 0;\
  fputs(fmt_buf, fp);\
  if (rpt->out->records && (tally.rt_recs == rpt->out->records)) {\
    fprintf(fp, "# stop, hit record limit.\n");\
    break;\
  }

#define NEXT_WORD(A,B)\
  for (;;) {\
    B = strsep(A, " \t");\
    if ((B && *B != 0) || (!B))\
      break;\
  }\

/*
 * A = ftstat_rpt_n (struct to allocate)
 * B = rptn (local var name for A)
 * C = hash bits
 * D = size of hash record (passed to sizeof (struct)
 * E = size of hash key
 * F = num hash recs in a chunk
 *
 */
#define STD_NEW_HASH(A,B,C,D,E,F)\
  struct A *B;\
  int slen;\
  if (!(B = (struct A*)malloc(sizeof (*B)))) {\
    fterr_warnx("malloc(rpt): failed");\
    return (struct A*)0L;\
  }\
  bzero(B, sizeof *B);\
  if (rpt->all_fields & FT_STAT_FIELD_PS)\
    slen = sizeof (struct D);\
  else\
    slen = sizeof (struct D) - sizeof (struct ftps);\
  if (!(B->ftch = ftchash_new(C, slen, E, F))) {\
    free(B);\
    fterr_warnx("ftchash_new(): failed");\
    return (struct A*)0L;\
  }\
  return B;\

/*
 * A = ftstat_rpt_n (struct to allocate)
 * B = rptn (local var name for A)
 * C = bucket size
 *
 */
#define STD_NEW_BUCKET(A,B,C,D)\
  struct A *B;\
  if (!(B = (struct A*)malloc(sizeof (*B)))) {\
    fterr_warnx("malloc(rpt): failed");\
    return (struct A*)0L;\
  }\
  bzero(B, sizeof *B);\
  if (bucket_alloc(&B->bucket, (u_int32)C, D)) {\
    fterr_warnx("bucket_alloc(): failed");\
    free(B);\
    return (struct A*)0L;\
  }\
  return B;\

#define STD_CALC_BUCKET(A,B,C)\
  struct A *B;\
  register int i;\
  if (rpt->t_recs)\
    rpt->avg_pps /= (double)rpt->t_recs;\
  if (rpt->t_recs)\
    rpt->avg_bps /= (double)rpt->t_recs;\
  B = rpt->data;\
  for (i = 0; i < C; ++i) {\
    if ((B->bucket.duration[i]) && (rpt->all_fields & FT_STAT_FIELD_PS)) {\
      B->bucket.avg_pps[i] /= (double)B->bucket.recs[i];\
      B->bucket.avg_bps[i] /= (double)B->bucket.recs[i];\
    }\
    if (B->bucket.packets[i])\
      rpt->recs ++;\
  }\
  return 0;\

/*
 * A = ftstat_rpt_n
 * B = rptn (local var name for A)
 * C = ftchash_rec_x
 * D = ftch_recn (local var name for C)
 * note rpt_66, 67 have this expanded by hand
 */
#define STD_CALC_HASH(A,B,C,D)\
  struct C *D;\
  struct A *B;\
  B = rpt->data;\
  if (rpt->t_recs)\
    rpt->avg_pps /= (double)rpt->t_recs;\
  if (rpt->t_recs)\
    rpt->avg_bps /= (double)rpt->t_recs;\
  rpt->recs = B->ftch->entries;\
  if (rpt->all_fields & FT_STAT_FIELD_PS) {\
    ftchash_first(B->ftch);\
    while ((D = ftchash_foreach(B->ftch))) {\
      if (D->etime) {\
        D->ps.avg_pps /= (double)D->nrecs;\
        D->ps.avg_bps /= (double)D->nrecs;\
      }\
    }\
  }\
  return 0;

#define STD_FREE_BUCKET(A)\
  if (A) {\
    bucket_free(&A->bucket);\
    free(A);\
  }\

#define STD_FREE_HASH(A)\
  if (A) {\
    if (A->ftch)\
      ftchash_free(A->ftch);\
    free (A);\
  }\

/*
 * A = ftstat_rpt_n
 * B = rptn (local var name for A)
 * D = size of bucket
 * KEY* = ascii key name
 */
#define STD_DUMP_BUCKET(A,B,C,SYM,KEY,KEY1,KEY2,KEY3,KEY4,KEY5,KEY6)\
  struct A *B;\
  B = rpt->data;\
  recn_dump(fp, rpt->out->fields, KEY, KEY1, KEY2, KEY3, KEY4,KEY5,KEY6);\
  bucket_dump1(fp, rpt, &B->bucket, C, SYM);\
  return 0;\

/*
 * A = ftstat_rpt_n
 * B = rptn (local var name for A)
 * C = hash dump function
 * KEY* = ascii key name
 */
#define STD_DUMP_HASH0(A,B,C,KEY,KEY1,KEY2,KEY3,KEY4,KEY5,KEY6)\
  struct A *B;\
  B = rpt->data;\
  recn_dump(fp, rpt->out->fields, KEY, KEY1, KEY2, KEY3, KEY4, KEY5, KEY6);\
  C(fp, rpt, B->ftch);\
  return 0;

#define STD_DUMP_HASH0P(A,B,C,D,KEY,KEY1,KEY2,KEY3,KEY4,KEY5,KEY6)\
  struct A *B;\
  B = rpt->data;\
  recn_dump(fp, rpt->out->fields, KEY, KEY1, KEY2, KEY3, KEY4, KEY5, KEY6);\
  C(fp, rpt, B->ftch, D);\
  return 0;


#define STD_DUMP_HASH1(A,B,C,SYM1,KEY,KEY1,KEY2,KEY3,KEY4,KEY5,KEY6)\
  struct A *B;\
  B = rpt->data;\
  recn_dump(fp, rpt->out->fields, KEY, KEY1, KEY2, KEY3, KEY4, KEY5, KEY6);\
  C(fp, rpt, B->ftch, SYM1);\
  return 0;

#define STD_DUMP_HASH1P(A,B,C,D,SYM1,KEY,KEY1,KEY2,KEY3,KEY4,KEY5,KEY6)\
  struct A *B;\
  B = rpt->data;\
  recn_dump(fp, rpt->out->fields, KEY, KEY1, KEY2, KEY3, KEY4, KEY5, KEY6);\
  C(fp, rpt, B->ftch, SYM1, D);\
  return 0;

#define STD_DUMP_HASH2(A,B,C,SYM1,SYM2,KEY,KEY1,KEY2,KEY3,KEY4,KEY5,KEY6)\
  struct A *B;\
  B = rpt->data;\
  recn_dump(fp, rpt->out->fields, KEY, KEY1, KEY2, KEY3, KEY4, KEY5, KEY6);\
  C(fp, rpt, B->ftch, SYM1, SYM2);\
  return 0;

#define STD_DUMP_HASH2P(A,B,C,D,SYM1,SYM2,KEY,KEY1,KEY2,KEY3,KEY4,KEY5,KEY6)\
  struct A *B;\
  B = rpt->data;\
  recn_dump(fp, rpt->out->fields, KEY, KEY1, KEY2, KEY3, KEY4, KEY5, KEY6);\
  C(fp, rpt, B->ftch, SYM1, SYM2, D);\
  return 0;

#define STD_DUMP_HASH3(A,B,C,SYM1,SYM2,SYM3,KEY,KEY1,KEY2,KEY3,KEY4,KEY5,KEY6)\
  struct A *B;\
  B = rpt->data;\
  recn_dump(fp, rpt->out->fields, KEY, KEY1, KEY2, KEY3, KEY4, KEY5, KEY6);\
  C(fp, rpt, B->ftch, SYM1, SYM2, SYM3);\
  return 0;

#define STD_DUMP_HASH4(A,B,C,SYM1,SYM2,SYM3,SYM4,KEY,KEY1,KEY2,KEY3,KEY4,KEY5,KEY6)\
  struct A *B;\
  B = rpt->data;\
  recn_dump(fp, rpt->out->fields, KEY, KEY1, KEY2, KEY3, KEY4, KEY5, KEY6);\
  C(fp, rpt, B->ftch, SYM1, SYM2, SYM3,SYM4);\
  return 0;

#define STD_ACCUM\
  cur.dFlows64 = 1;\
  FT_RECGET_LAST(cur,rec,*fo);\
  FT_RECGET_FIRST(cur,rec,*fo);\
  FT_RECGET64_DPKTS(cur,rec,*fo);\
  FT_RECGET64_DOCTETS(cur,rec,*fo);\
  FT_RECGET_UNIX_SECS(cur,rec,*fo);\
  if (fo->xfields &  FT_XFIELD_DFLOWS) {\
    FT_RECGET64_DFLOWS(cur,rec,*fo);\
  } else {\
    cur.dFlows64 = 1;\
  }\
  if (rpt->scale) {\
    cur.dPkts64 *= rpt->scale;\
    cur.dOctets64 *= rpt->scale;\
  }\
  if (!cur.dPkts64) {\
    rpt->t_ignores ++;\
    return 0;\
  }\
  if (cur.unix_secs > rpt->time_end)\
    rpt->time_end = cur.unix_secs;\
  if (cur.unix_secs < rpt->time_start)\
    rpt->time_start = cur.unix_secs;\
  {\
  duration_tmp = (cur.Last - cur.First);\
  if (duration_tmp) {\
    rpt->t_recs ++;\
    rpt->t_duration += duration_tmp;\
    if (rpt->all_fields & FT_STAT_FIELD_PS) {\
      pps_tmp = (double)cur.dPkts64/((double)(duration_tmp)/1000.0);\
      bps_tmp = (double)cur.dOctets64*8/((double)(duration_tmp)/1000.0);\
      if (pps_tmp > rpt->max_pps)\
        rpt->max_pps = pps_tmp;\
      if ((pps_tmp < rpt->min_pps) || (!rpt->min_pps))\
        rpt->min_pps = pps_tmp;\
      rpt->avg_pps += pps_tmp;\
      if (bps_tmp > rpt->max_bps)\
        rpt->max_bps = bps_tmp;\
      if ((bps_tmp < rpt->min_bps) || (!rpt->min_bps))\
        rpt->min_bps = bps_tmp;\
      rpt->avg_bps += bps_tmp;\
    }\
  }\
  }\
  rpt->t_flows += cur.dFlows64;\
  rpt->t_octets += cur.dOctets64;\
  rpt->t_packets += cur.dPkts64;\

#define STD_ACCUM_BUCKET1(A,B)\
  struct fts3rec_all2 cur;\
  struct A *B;\
  u_int32 duration_tmp;\
  double bps_tmp = 0, pps_tmp = 0;\
  B = rpt->data;\
  STD_ACCUM;

#define STD_ACCUM_BUCKET2(A,B)\
  if (duration_tmp) {\
    A.duration[B] += duration_tmp;\
    A.recs[B] ++;\
    if (rpt->all_fields & FT_STAT_FIELD_PS) {\
      if (pps_tmp > A.max_pps[B])\
        A.max_pps[B] = pps_tmp;\
      if ((pps_tmp < A.min_pps[B]) || (!A.min_pps[B]))\
        A.min_pps[B] = pps_tmp;\
      A.avg_pps[B] += pps_tmp;\
      if (bps_tmp > A.max_bps[B])\
        A.max_bps[B] = bps_tmp;\
      if ((bps_tmp < A.min_bps[B]) || (!A.min_bps[B]))\
        A.min_bps[B] = bps_tmp;\
      A.avg_bps[B] += bps_tmp;\
    }\
  }\
  A.flows[B] += cur.dFlows64;\
  A.octets[B] += cur.dOctets64;\
  A.packets[B] += cur.dPkts64;\

#define STD_ACCUM_HASH1(A,B,C,D,E)\
  struct fts3rec_all2 cur;\
  struct C D, *E;\
  struct A *B;\
  u_int32 hash;\
  u_int32 duration_tmp;\
  double bps_tmp, pps_tmp;\
  bzero(&D, sizeof D);\
  B = rpt->data;\
  STD_ACCUM;

#define STD_ACCUM_HASH2(A,B,C)\
  if (!(C = ftchash_update(A->ftch, &B, hash))) {\
    fterr_warnx("ftch_update(): failed");\
    return -1;\
  }\
  STD_ACCUM_INCP(C);\

#define STD_ACCUM_INCP(A)\
  if (duration_tmp) {\
    A->etime += (duration_tmp);\
    A->nrecs ++;\
    if (rpt->all_fields & FT_STAT_FIELD_PS) {\
      if (pps_tmp > A->ps.max_pps)\
        A->ps.max_pps = pps_tmp;\
      if ((pps_tmp < A->ps.min_pps) || (!A->ps.min_pps))\
        A->ps.min_pps = pps_tmp;\
      A->ps.avg_pps += pps_tmp;\
      if (bps_tmp > A->ps.max_bps)\
        A->ps.max_bps = bps_tmp;\
      if ((bps_tmp < A->ps.min_bps) || (!A->ps.min_bps))\
        A->ps.min_bps = bps_tmp;\
      A->ps.avg_bps += bps_tmp;\
    }\
  }\
  A->nflows += cur.dFlows64;\
  A->noctets += cur.dOctets64;\
  A->npackets += cur.dPkts64;\

#define STD_CALC\
  if (rpt->t_recs)\
    rpt->avg_pps /= (double)rpt->t_recs;\
  if (rpt->t_recs)\
    rpt->avg_bps /= (double)rpt->t_recs;

#define STD_DUMP_TOTALS_HEADER\
  if (ftsrpt->all_fields & FT_STAT_FIELD_PS)\
    fprintf(fp, "# rec1: records,ignores,flows,octets,packets,duration,avg_bps,min_bps,max_bps,avg_pps,min_pps,max_pps\n");\
  else\
    fprintf(fp, "# rec1: records,ignores,flows,octets,packets,duration\n");\

#define STD_DUMP_TOTALS_VAL\
  fmt_uint64(fmt_buf, ftsrpt->recs, FMT_JUST_LEFT);\
  strcat(fmt_buf, ",");\
  fmt_uint64(fmt_tmp, ftsrpt->t_ignores, FMT_JUST_LEFT);\
  strcat(fmt_buf, fmt_tmp);\
  strcat(fmt_buf, ",");\
  fmt_uint64(fmt_tmp, ftsrpt->t_flows, FMT_JUST_LEFT);\
  strcat(fmt_buf, fmt_tmp);\
  strcat(fmt_buf, ",");\
  fmt_uint64(fmt_tmp, ftsrpt->t_octets, FMT_JUST_LEFT);\
  strcat(fmt_buf, fmt_tmp);\
  strcat(fmt_buf, ",");\
  fmt_uint64(fmt_tmp, ftsrpt->t_packets, FMT_JUST_LEFT);\
  strcat(fmt_buf, fmt_tmp);\
  strcat(fmt_buf, ",");\
  fmt_uint64(fmt_tmp, ftsrpt->t_duration, FMT_JUST_LEFT);\
  strcat(fmt_buf, fmt_tmp);\
  if (ftsrpt->all_fields & FT_STAT_FIELD_PS) {\
    fprintf(fp, "%s,%f,%f,%f,%f,%f,%f\n", fmt_buf,\
      ftsrpt->avg_bps, ftsrpt->min_bps, ftsrpt->max_bps,\
      ftsrpt->avg_pps, ftsrpt->min_pps, ftsrpt->max_pps);\
  } else {\
    fprintf(fp, "%s\n", fmt_buf);\
  }\


enum ftstat_parse_state { PARSE_STATE_UNSET, PARSE_STATE_REPORT,
                          PARSE_STATE_DEFINITION, PARSE_STATE_OUTPUT };

#define FT_STAT_OPT_PERCENT             0x001
#define FT_STAT_OPT_NAMES               0x002
#define FT_STAT_OPT_SORT                0x004
#define FT_STAT_OPT_HEADER              0x008
#define FT_STAT_OPT_XHEADER             0x010
#define FT_STAT_OPT_TOTALS              0x020
#define FT_STAT_OPT_TALLY               0x080
#define FT_STAT_OPT_TAG_MASK            0x100
#define FT_STAT_OPT_SRC_PREFIX_LEN      0x200
#define FT_STAT_OPT_SRC_PREFIX_MASK     0x400
#define FT_STAT_OPT_DST_PREFIX_LEN      0x800
#define FT_STAT_OPT_DST_PREFIX_MASK     0x1000
#define FT_STAT_OPT_ALL                 0x16FF
#define FT_STAT_OPT_GENERIC             0x00FF
#define FT_STAT_OPT_GENERIC_IP_ADDR     0x07FF
#define FT_STAT_OPT_NONE                0x0

#define FT_STAT_FIELD_INDEX      0x00000001
#define FT_STAT_FIELD_FIRST      0x00000002
#define FT_STAT_FIELD_LAST       0x00000004

#define FT_STAT_FIELD_FLOWS      0x00000010
#define FT_STAT_FIELD_OCTETS     0x00000020
#define FT_STAT_FIELD_PACKETS    0x00000040
#define FT_STAT_FIELD_DURATION   0x00000080

#define FT_STAT_FIELD_AVG_PPS    0x00000100
#define FT_STAT_FIELD_AVG_BPS    0x00000200
#define FT_STAT_FIELD_MAX_PPS    0x00000400
#define FT_STAT_FIELD_MAX_BPS    0x00000800

#define FT_STAT_FIELD_MIN_PPS    0x00001000
#define FT_STAT_FIELD_MIN_BPS    0x00002000
#define FT_STAT_FIELD_OTHER      0x00004000
#define FT_STAT_FIELD_KEY        0x00008000 /* reports with a single key */

#define FT_STAT_FIELD_KEY1       0x00010000
#define FT_STAT_FIELD_KEY2       0x00020000
#define FT_STAT_FIELD_KEY3       0x00040000
#define FT_STAT_FIELD_KEY4       0x00080000

#define FT_STAT_FIELD_KEY5       0x00100000
#define FT_STAT_FIELD_KEY6       0x00200000

#define FT_STAT_FIELD_COUNT      0x01000000 /* reports that do a count */
#define FT_STAT_FIELD_FRECS      0x02000000 /* flow records in report line */

#define FT_STAT_FIELD_PPS        0x00001500 /* any *_PPS */
#define FT_STAT_FIELD_BPS        0x00002A00 /* any *_BPS */
#define FT_STAT_FIELD_PS         (FT_STAT_FIELD_PPS|FT_STAT_FIELD_BPS)

#define FT_STAT_FIELD_GENERIC    0x0200FFF7 /* most reports */
#define FT_STAT_FIELD_GENERIC2   0x02037FF7 /* reports with 2 key fields */
#define FT_STAT_FIELD_GENERIC3   0x02077FF7 /* reports with 3 key fields */
#define FT_STAT_FIELD_GENERIC4   0x020F7FF7 /* reports with 4 key fields */
#define FT_STAT_FIELD_GENERIC5   0x021F7FF7 /* reports with 5 key fields */
#define FT_STAT_FIELD_GENERIC6   0x023F7FF7 /* reports with 6 key fields */

#define FT_STAT_SORT_ASCEND      0x1
#define FT_STAT_SORT_DESCEND     0x2

struct tally {
  u_int64 rt_flows, rt_octets, rt_packets, rt_recs, t_recs;
  double ravg_bps, ravg_pps, rt_frecs;
};

struct flow_bucket {
  u_int64 *recs, *flows, *octets, *packets, *duration;
  double *avg_pps, *avg_bps;
  double *min_pps, *min_bps;
  double *max_pps, *max_bps;
  u_int32 *index;
}; /* flow_bucket */

struct line_parser {
  enum ftstat_parse_state state;
  struct ftstat_rpt *cur_rpt;
  struct ftstat_def *cur_def;
  struct ftstat_rpt_out *cur_rpt_out;
  int lineno;
  char *buf, *fname, *word;
};

struct jump {
  char *name;
  enum ftstat_parse_state state;
  int (*func)(struct line_parser *lp, struct ftstat *ftstat);
};

struct typelookup {
  char *name;
  void* (*f_new)();
  void* (*f_accum)();
  void* (*f_calc)();
  void* (*f_dump)();
  void* (*f_free)();
  int allowed_fields; /* FT_STAT_FIELD_* */
  int allowed_options;/* FT_STAT_OPT_* */
  u_int64 xfields; /* FT_XFIELD_* */
};

struct ftstat_rpt_1 {
  u_int64 time;       /* total time in 1/1000 of flows */

  double  aflowtime;  /* average time of flow */
  double  aps;        /* average packet size */
  double  afs;        /* average flow size */
  double  apf;        /* average packets per flow */
  double  fps;        /* average flows per second */
  double  fps_real;   /* average flows per second (realtime) */

  u_int64 start;      /* earliest flow time */
  u_int64 end;        /* latest flow time */

  u_int32 time_start; /* earliest flow (realtime) */
  u_int32 time_end;   /* last flow (realtime) */

  u_int32 time_real;  /* realtime duration */

  /* average packet sizes */
  u_int64 psize32;    /* bytes/packet 1    <= p <= 32 */
  u_int64 psize64;    /* bytes/packet 32   < p <= 64  */
  u_int64 psize96; u_int64 psize128; u_int64 psize160; u_int64 psize192;
  u_int64 psize224; u_int64 psize256; u_int64 psize288; u_int64 psize320;
  u_int64 psize352; u_int64 psize384; u_int64 psize416; u_int64 psize448;
  u_int64 psize480; u_int64 psize512; u_int64 psize544; u_int64 psize576;
  u_int64 psize1024; u_int64 psize1536; u_int64 psize2048; u_int64 psize2560;
  u_int64 psize3072; u_int64 psize3584; u_int64 psize4096; u_int64 psize4608;

  /* packets per flow */
  u_int64 fpsize1;    /* packets/flow = 1 */
  u_int64 fpsize2;    /* packets/flow = 2 */
  u_int64 fpsize4;    /* packets/flow 2 < p <= 4 */
  u_int64 fpsize8;    /* packets/flow 4 < p <= 8 */
  u_int64 fpsize12; u_int64 fpsize16; u_int64 fpsize20; u_int64 fpsize24;
  u_int64 fpsize28; u_int64 fpsize32; u_int64 fpsize36; u_int64 fpsize40;
  u_int64 fpsize44; u_int64 fpsize48; u_int64 fpsize52; u_int64 fpsize60;
  u_int64 fpsize100; u_int64 fpsize200; u_int64 fpsize300; u_int64 fpsize400;
  u_int64 fpsize500; u_int64 fpsize600; u_int64 fpsize700; u_int64 fpsize800;
  u_int64 fpsize900;
  u_int64 fpsize_other; /* packets/flow 200 < p */

  /* octets per flow */
  u_int64 fosize32;     /* octets/flow 1    <= p <= 32 */
  u_int64 fosize64;     /* octets/flow 32   < p <= 64 */
  u_int64 fosize128;    /* octets/flow 64   < p <= 128 */
  u_int64 fosize256;    /* octets/flow 128   < p <= 256 */
  u_int64 fosize512; u_int64 fosize1280; u_int64 fosize2048;
  u_int64 fosize2816; u_int64 fosize3584; u_int64 fosize4352;
  u_int64 fosize5120; u_int64 fosize5888; u_int64 fosize6656;
  u_int64 fosize7424; u_int64 fosize8192; u_int64 fosize8960;
  u_int64 fosize9728; u_int64 fosize10496; u_int64 fosize11264;
  u_int64 fosize12032; u_int64 fosize12800; u_int64 fosize13568;
  u_int64 fosize14336; u_int64 fosize15104; u_int64 fosize15872;
  u_int64 fosize_other; /* octets/flow 15872   < p */

  /* time per flow */
  u_int64 ftime10;    /* time/flow 1 <= p <= 10 */
  u_int64 ftime50;    /* time/flow 10 < p <= 50 */
  u_int64 ftime100; u_int64 ftime200; u_int64 ftime500; u_int64 ftime1000;
  u_int64 ftime2000; u_int64 ftime3000; u_int64 ftime4000; u_int64 ftime5000;
  u_int64 ftime6000; u_int64 ftime7000; u_int64 ftime8000; u_int64 ftime9000;
  u_int64 ftime10000; u_int64 ftime12000; u_int64 ftime14000;
  u_int64 ftime16000; u_int64 ftime18000; u_int64 ftime20000;
  u_int64 ftime22000; u_int64 ftime24000; u_int64 ftime26000;
  u_int64 ftime28000; u_int64 ftime30000;
  u_int64 ftime_other;  /* time/flow 2000 < p */
};

struct ftstat_rpt_2 {
  int foo; /* malloc place holder */
};

struct ftstat_rpt_3 {
  struct ftchash *ftch;
};

struct ftstat_rpt_4 {
  struct ftchash *ftch;
};

struct ftstat_rpt_5 {
  struct ftchash *ftch;
};

struct ftstat_rpt_6 {
  struct flow_bucket bucket;
};

struct ftstat_rpt_7 {
  struct flow_bucket bucket;
};

struct ftstat_rpt_8 {
  struct ftchash *ftch;
};

struct ftstat_rpt_9 {
  struct ftchash *ftch;
};

struct ftstat_rpt_10 {
  struct ftchash *ftch;
};

struct ftstat_rpt_11 {
  struct flow_bucket bucket;
};

struct ftstat_rpt_12 {
  struct flow_bucket bucket;
};

struct ftstat_rpt_13 {
  struct flow_bucket bucket;
};

struct ftstat_rpt_14 {
  struct ftchash *ftch;
};

struct ftstat_rpt_15 {
  struct ftchash *ftch;
};

struct ftstat_rpt_16 {
  struct ftchash *ftch;
};

struct ftstat_rpt_17 {
  struct ftchash *ftch;
};

struct ftstat_rpt_18 {
  struct ftchash *ftch;
};

struct ftstat_rpt_19 {
  struct flow_bucket bucket;
};

struct ftstat_rpt_20 {
  struct flow_bucket bucket;
};

struct ftstat_rpt_21 {
  struct ftchash *ftch;
};

struct ftstat_rpt_22 {
  struct flow_bucket bucket;
};

struct ftstat_rpt_23 {
  struct flow_bucket bucket;
};

struct ftstat_rpt_24 {
  struct ftchash *ftch;
};

struct ftstat_rpt_25 {
  struct ftchash *ftch;
};

struct ftstat_rpt_26 {
  struct ftchash *ftch;
};

struct ftstat_rpt_27 {
  struct ftchash *ftch;
};

struct ftstat_rpt_28 {
  struct ftchash *ftch;
};

struct ftstat_rpt_29 {
  struct ftchash *ftch;
};

struct ftstat_rpt_30 {
  struct ftchash *ftch;
};

struct ftstat_rpt_31 {
  struct ftchash *ftch;
};

struct ftstat_rpt_32 {
  struct ftchash *ftch;
};

struct ftstat_rpt_33 {
  struct ftchash *ftch;
};

struct ftstat_rpt_34 {
  struct ftchash *ftch;
};

struct ftstat_rpt_35 {
  struct ftchash *ftch;
};

struct ftstat_rpt_36 {
  struct ftchash *ftch;
};

struct ftstat_rpt_37 {
  struct ftchash *ftch;
};

struct ftstat_rpt_38 {
  struct ftchash *ftch;
};

struct ftstat_rpt_39 {
  struct ftchash *ftch;
};

struct ftstat_rpt_40 {
  struct ftchash *ftch;
};

struct ftstat_rpt_41 {
  struct ftchash *ftch;
};

struct ftstat_rpt_42 {
  struct ftchash *ftch;
};

struct ftstat_rpt_43 {
  struct ftchash *ftch;
};

struct ftstat_rpt_44 {
  struct ftchash *ftch;
};

struct ftstat_rpt_45 {
  struct ftchash *ftch;
};

struct ftstat_rpt_46 {
  struct flow_bucket bucket;
};

struct ftstat_rpt_47 {
  struct flow_bucket bucket;
};

struct ftstat_rpt_48 {
  struct ftchash *ftch;
};

struct ftstat_rpt_49 {
  struct ftchash *ftch;
};

struct ftstat_rpt_50 {
  struct ftchash *ftch;
};

struct ftstat_rpt_51 {
  struct ftchash *ftch;
};

struct ftstat_rpt_52 {
  struct ftchash *ftch;
};

struct ftstat_rpt_53 {
  struct ftchash *ftch;
};

struct ftstat_rpt_54 {
  struct ftchash *ftch;
};

struct ftstat_rpt_55 {
  struct ftchash *ftch;
};

struct ftstat_rpt_56 {
  struct ftchash *ftch;
};

struct ftstat_rpt_57 {
  struct ftchash *ftch;
};

struct ftstat_rpt_58 {
  struct ftchash *ftch;
};

struct ftstat_rpt_59 {
  struct ftchash *ftch;
};

struct ftstat_rpt_60 {
  struct ftchash *ftch;
};

struct ftstat_rpt_61 {
  struct ftchash *ftch;
};

struct ftstat_rpt_62 {
  struct ftchash *ftch;
};

struct ftstat_rpt_63 {
  struct ftchash *ftch;
};

struct ftstat_rpt_64 {
  struct ftchash *ftch;
};

struct ftstat_rpt_65 {
  struct flow_bucket bucket;
};

struct ftstat_rpt_66 {
  struct ftchash *ftch;
};

struct ftstat_rpt_67 {
  struct ftchash *ftch;
};

struct ftstat_rpt_68 {
  struct ftchash *ftch;
};

struct ftstat_rpt_69 {
  struct ftchash *ftch;
};

struct ftstat_rpt_70 {
  struct ftchash *ftch;
};

struct ftstat_rpt_71 {
  struct ftchash *ftch;
};

struct ftstat_rpt_72 {
  struct ftchash *ftch;
};

struct ftstat_rpt_73 {
  struct ftchash *ftch;
};

struct ftstat_rpt_74 {
  struct ftchash *ftch;
};

struct ftstat_rpt_75 {
  struct ftchash *ftch;
};

struct ftstat_rpt_76 {
  struct ftchash *ftch;
};

struct ftstat_rpt_77 {
  struct ftchash *ftch;
};

struct ftstat_rpt_78 {
  struct ftchash *ftch;
};

int parse_rpt(struct line_parser *lp, struct ftstat *ftstat);
int parse_rpt_type(struct line_parser *lp, struct ftstat *ftstat);
int parse_rpt_filter(struct line_parser *lp, struct ftstat *ftstat);
int parse_rpt_scale(struct line_parser *lp, struct ftstat *ftstat);
int parse_rpt_tag_mask(struct line_parser *lp, struct ftstat *ftstat);
int parse_rpt_ip_src_addr_fmt(struct line_parser *lp, struct ftstat *ftstat);
int parse_rpt_ip_dst_addr_fmt(struct line_parser *lp, struct ftstat *ftstat);
int parse_rpt_output(struct line_parser *lp, struct ftstat *ftstat);
int parse_rpt_out_options(struct line_parser *lp, struct ftstat *ftstat);
int parse_rpt_out_sort(struct line_parser *lp, struct ftstat *ftstat);
int parse_rpt_out_fields(struct line_parser *lp, struct ftstat *ftstat);
int parse_rpt_out_format(struct line_parser *lp, struct ftstat *ftstat);
int parse_rpt_out_path(struct line_parser *lp, struct ftstat *ftstat);
int parse_rpt_out_records(struct line_parser *lp, struct ftstat *ftstat);
int parse_rpt_out_tally(struct line_parser *lp, struct ftstat *ftstat);
int parse_rpt_out_time(struct line_parser *lp, struct ftstat *ftstat);
int parse_def(struct line_parser *lp, struct ftstat *ftstat);
int parse_def_mask(struct line_parser *lp, struct ftstat *ftstat);
int parse_def_tag(struct line_parser *lp, struct ftstat *ftstat);
int parse_def_filter(struct line_parser *lp, struct ftstat *ftstat);
int parse_def_report(struct line_parser *lp, struct ftstat *ftstat);
int parse_def_time_series(struct line_parser *lp, struct ftstat *ftstat);
int parse_include_tag(struct line_parser *lp, struct ftstat *ftstat);
int parse_include_filter(struct line_parser *lp, struct ftstat *ftstat);
int parse_include_mask(struct line_parser *lp, struct ftstat *ftstat);

void ftstat_free(struct ftstat *ftstat);
static int load_masks(struct ftstat *ftstat);
static int load_filters(struct ftstat *ftstat);
static int load_tags(struct ftstat *ftstat);
static int resolve_reports(struct ftstat *ftstat);
static int dump_ascii_header(FILE *fp, struct ftio *ftio,
  struct ftstat_def *active_def, struct ftstat_rpt *rpt);

static int recn_dump(FILE *fp, int fields, char *key, char *key1,
  char *key2, char *key3, char *key4, char *key5, char *key6);

static int sort_cmp64(const void *a, const void *b);
static int sort_cmp_double(const void *a, const void *b);
void bucket_free(struct flow_bucket *b);
int bucket_alloc(struct flow_bucket *b, u_int32 n, struct ftstat_rpt *rpt);
static int bucket_dump1(FILE *fp, struct ftstat_rpt *rpt, struct flow_bucket *b,
  u_int32 nindex, char *symfile);
static int chash_c64_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch);
static int chash_c32_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1);
static int chash_c322_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1, char *sym2);
static int chash_c162_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1, char *sym2);
static int chash_c163_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1, char *sym2, char *sym3);
static int chash_c164_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1, char *sym2, char *sym3, char *sym4);
static int chash_ip_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch);
static int chash_prefix_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, int f1);
static int chash_prefix2_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch);
static int chash_prefix16_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1, int f1);
static int chash_prefix162_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1, char *sym2, int f1 );
static int chash_prefix216_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1);
static int chash_prefix2162_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1, char *sym2);
static int chash_flow1_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1, char *sym2);
static int chash_flow12_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1);
static int chash_prefixh_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, int f1);
static int chash_prefix_tag_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1, int f1);
static int chash_prefix2tag2_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1);
static int chash_int_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch);

struct ftstat_rpt_1 *ftstat_rpt_1_new(struct ftstat_rpt *rpt);
int ftstat_rpt_1_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_1_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_1_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_1_free(struct ftstat_rpt_1 *rpt);

struct ftstat_rpt_2 *ftstat_rpt_2_new(struct ftstat_rpt *rpt);
int ftstat_rpt_2_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_2_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_2_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_2_free(struct ftstat_rpt_2 *rpt);

struct ftstat_rpt_3 *ftstat_rpt_3_new(struct ftstat_rpt *rpt);
int ftstat_rpt_3_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_3_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_3_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_3_free(struct ftstat_rpt_3 *rpt);

struct ftstat_rpt_4 *ftstat_rpt_4_new(struct ftstat_rpt *rpt);
int ftstat_rpt_4_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_4_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_4_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_4_free(struct ftstat_rpt_4 *rpt);

struct ftstat_rpt_5 *ftstat_rpt_5_new(struct ftstat_rpt *rpt);
int ftstat_rpt_5_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_5_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_5_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_5_free(struct ftstat_rpt_5 *rpt);

struct ftstat_rpt_6 *ftstat_rpt_6_new(struct ftstat_rpt *rpt);
int ftstat_rpt_6_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_6_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_6_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_6_free(struct ftstat_rpt_6 *rpt);

struct ftstat_rpt_7 *ftstat_rpt_7_new(struct ftstat_rpt *rpt);
int ftstat_rpt_7_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_7_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_7_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_7_free(struct ftstat_rpt_7 *rpt);

struct ftstat_rpt_8 *ftstat_rpt_8_new(struct ftstat_rpt *rpt);
int ftstat_rpt_8_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_8_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_8_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_8_free(struct ftstat_rpt_8 *rpt);

struct ftstat_rpt_9 *ftstat_rpt_9_new(struct ftstat_rpt *rpt);
int ftstat_rpt_9_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_9_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_9_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_9_free(struct ftstat_rpt_9 *rpt);

struct ftstat_rpt_10 *ftstat_rpt_10_new(struct ftstat_rpt *rpt);
int ftstat_rpt_10_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_10_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_10_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_10_free(struct ftstat_rpt_10 *rpt);

struct ftstat_rpt_11 *ftstat_rpt_11_new(struct ftstat_rpt *rpt);
int ftstat_rpt_11_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_11_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_11_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_11_free(struct ftstat_rpt_11 *rpt);

struct ftstat_rpt_12 *ftstat_rpt_12_new(struct ftstat_rpt *rpt);
int ftstat_rpt_12_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_12_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_12_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_12_free(struct ftstat_rpt_12 *rpt);

struct ftstat_rpt_13 *ftstat_rpt_13_new(struct ftstat_rpt *rpt);
int ftstat_rpt_13_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_13_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_13_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_13_free(struct ftstat_rpt_13 *rpt);

struct ftstat_rpt_14 *ftstat_rpt_14_new(struct ftstat_rpt *rpt);
int ftstat_rpt_14_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_14_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_14_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_14_free(struct ftstat_rpt_14 *rpt);

struct ftstat_rpt_15 *ftstat_rpt_15_new(struct ftstat_rpt *rpt);
int ftstat_rpt_15_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_15_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_15_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_15_free(struct ftstat_rpt_15 *rpt);

struct ftstat_rpt_16 *ftstat_rpt_16_new(struct ftstat_rpt *rpt);
int ftstat_rpt_16_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_16_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_16_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_16_free(struct ftstat_rpt_16 *rpt);

struct ftstat_rpt_17 *ftstat_rpt_17_new(struct ftstat_rpt *rpt);
int ftstat_rpt_17_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_17_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_17_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_17_free(struct ftstat_rpt_17 *rpt);

struct ftstat_rpt_18 *ftstat_rpt_18_new(struct ftstat_rpt *rpt);
int ftstat_rpt_18_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_18_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_18_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_18_free(struct ftstat_rpt_18 *rpt);

struct ftstat_rpt_19 *ftstat_rpt_19_new(struct ftstat_rpt *rpt);
int ftstat_rpt_19_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_19_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_19_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_19_free(struct ftstat_rpt_19 *rpt);

struct ftstat_rpt_20 *ftstat_rpt_20_new(struct ftstat_rpt *rpt);
int ftstat_rpt_20_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_20_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_20_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_20_free(struct ftstat_rpt_20 *rpt);

struct ftstat_rpt_21 *ftstat_rpt_21_new(struct ftstat_rpt *rpt);
int ftstat_rpt_21_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_21_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_21_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_21_free(struct ftstat_rpt_21 *rpt);

struct ftstat_rpt_22 *ftstat_rpt_22_new(struct ftstat_rpt *rpt);
int ftstat_rpt_22_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_22_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_22_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_22_free(struct ftstat_rpt_22 *rpt);

struct ftstat_rpt_23 *ftstat_rpt_23_new(struct ftstat_rpt *rpt);
int ftstat_rpt_23_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_23_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_23_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_23_free(struct ftstat_rpt_23 *rpt);

struct ftstat_rpt_24 *ftstat_rpt_24_new(struct ftstat_rpt *rpt);
int ftstat_rpt_24_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_24_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_24_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_24_free(struct ftstat_rpt_24 *rpt);

struct ftstat_rpt_25 *ftstat_rpt_25_new(struct ftstat_rpt *rpt);
int ftstat_rpt_25_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_25_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_25_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_25_free(struct ftstat_rpt_25 *rpt);

struct ftstat_rpt_26 *ftstat_rpt_26_new(struct ftstat_rpt *rpt);
int ftstat_rpt_26_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_26_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_26_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_26_free(struct ftstat_rpt_26 *rpt);

struct ftstat_rpt_27 *ftstat_rpt_27_new(struct ftstat_rpt *rpt);
int ftstat_rpt_27_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_27_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_27_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_27_free(struct ftstat_rpt_27 *rpt);

struct ftstat_rpt_28 *ftstat_rpt_28_new(struct ftstat_rpt *rpt);
int ftstat_rpt_28_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_28_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_28_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_28_free(struct ftstat_rpt_28 *rpt);

struct ftstat_rpt_29 *ftstat_rpt_29_new(struct ftstat_rpt *rpt);
int ftstat_rpt_29_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_29_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_29_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_29_free(struct ftstat_rpt_29 *rpt);

struct ftstat_rpt_30 *ftstat_rpt_30_new(struct ftstat_rpt *rpt);
int ftstat_rpt_30_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_30_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_30_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_30_free(struct ftstat_rpt_30 *rpt);

struct ftstat_rpt_31 *ftstat_rpt_31_new(struct ftstat_rpt *rpt);
int ftstat_rpt_31_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_31_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_31_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_31_free(struct ftstat_rpt_31 *rpt);

struct ftstat_rpt_32 *ftstat_rpt_32_new(struct ftstat_rpt *rpt);
int ftstat_rpt_32_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_32_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_32_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_32_free(struct ftstat_rpt_32 *rpt);

struct ftstat_rpt_33 *ftstat_rpt_33_new(struct ftstat_rpt *rpt);
int ftstat_rpt_33_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_33_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_33_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_33_free(struct ftstat_rpt_33 *rpt);

struct ftstat_rpt_34 *ftstat_rpt_34_new(struct ftstat_rpt *rpt);
int ftstat_rpt_34_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_34_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_34_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_34_free(struct ftstat_rpt_34 *rpt);

struct ftstat_rpt_35 *ftstat_rpt_35_new(struct ftstat_rpt *rpt);
int ftstat_rpt_35_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_35_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_35_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_35_free(struct ftstat_rpt_35 *rpt);

struct ftstat_rpt_36 *ftstat_rpt_36_new(struct ftstat_rpt *rpt);
int ftstat_rpt_36_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_36_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_36_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_36_free(struct ftstat_rpt_36 *rpt);

struct ftstat_rpt_37 *ftstat_rpt_37_new(struct ftstat_rpt *rpt);
int ftstat_rpt_37_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_37_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_37_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_37_free(struct ftstat_rpt_37 *rpt);

struct ftstat_rpt_38 *ftstat_rpt_38_new(struct ftstat_rpt *rpt);
int ftstat_rpt_38_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_38_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_38_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_38_free(struct ftstat_rpt_38 *rpt);

struct ftstat_rpt_39 *ftstat_rpt_39_new(struct ftstat_rpt *rpt);
int ftstat_rpt_39_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_39_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_39_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_39_free(struct ftstat_rpt_39 *rpt);

struct ftstat_rpt_40 *ftstat_rpt_40_new(struct ftstat_rpt *rpt);
int ftstat_rpt_40_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_40_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_40_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_40_free(struct ftstat_rpt_40 *rpt);

struct ftstat_rpt_41 *ftstat_rpt_41_new(struct ftstat_rpt *rpt);
int ftstat_rpt_41_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_41_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_41_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_41_free(struct ftstat_rpt_41 *rpt);

struct ftstat_rpt_42 *ftstat_rpt_42_new(struct ftstat_rpt *rpt);
int ftstat_rpt_42_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_42_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_42_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_42_free(struct ftstat_rpt_42 *rpt);

struct ftstat_rpt_43 *ftstat_rpt_43_new(struct ftstat_rpt *rpt);
int ftstat_rpt_43_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_43_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_43_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_43_free(struct ftstat_rpt_43 *rpt);

struct ftstat_rpt_44 *ftstat_rpt_44_new(struct ftstat_rpt *rpt);
int ftstat_rpt_44_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_44_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_44_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_44_free(struct ftstat_rpt_44 *rpt);

struct ftstat_rpt_45 *ftstat_rpt_45_new(struct ftstat_rpt *rpt);
int ftstat_rpt_45_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_45_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_45_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_45_free(struct ftstat_rpt_45 *rpt);

struct ftstat_rpt_46 *ftstat_rpt_46_new(struct ftstat_rpt *rpt);
int ftstat_rpt_46_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_46_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_46_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_46_free(struct ftstat_rpt_46 *rpt);

struct ftstat_rpt_47 *ftstat_rpt_47_new(struct ftstat_rpt *rpt);
int ftstat_rpt_47_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_47_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_47_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_47_free(struct ftstat_rpt_47 *rpt);

struct ftstat_rpt_48 *ftstat_rpt_48_new(struct ftstat_rpt *rpt);
int ftstat_rpt_48_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_48_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_48_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_48_free(struct ftstat_rpt_48 *rpt);

struct ftstat_rpt_49 *ftstat_rpt_49_new(struct ftstat_rpt *rpt);
int ftstat_rpt_49_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_49_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_49_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_49_free(struct ftstat_rpt_49 *rpt);

struct ftstat_rpt_50 *ftstat_rpt_50_new(struct ftstat_rpt *rpt);
int ftstat_rpt_50_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_50_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_50_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_50_free(struct ftstat_rpt_50 *rpt);

struct ftstat_rpt_51 *ftstat_rpt_51_new(struct ftstat_rpt *rpt);
int ftstat_rpt_51_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_51_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_51_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_51_free(struct ftstat_rpt_51 *rpt);

struct ftstat_rpt_52 *ftstat_rpt_52_new(struct ftstat_rpt *rpt);
int ftstat_rpt_52_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_52_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_52_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_52_free(struct ftstat_rpt_52 *rpt);

struct ftstat_rpt_53 *ftstat_rpt_53_new(struct ftstat_rpt *rpt);
int ftstat_rpt_53_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_53_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_53_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_53_free(struct ftstat_rpt_53 *rpt);

struct ftstat_rpt_54 *ftstat_rpt_54_new(struct ftstat_rpt *rpt);
int ftstat_rpt_54_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_54_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_54_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_54_free(struct ftstat_rpt_54 *rpt);

struct ftstat_rpt_55 *ftstat_rpt_55_new(struct ftstat_rpt *rpt);
int ftstat_rpt_55_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_55_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_55_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_55_free(struct ftstat_rpt_55 *rpt);

struct ftstat_rpt_56 *ftstat_rpt_56_new(struct ftstat_rpt *rpt);
int ftstat_rpt_56_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_56_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_56_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_56_free(struct ftstat_rpt_56 *rpt);

struct ftstat_rpt_57 *ftstat_rpt_57_new(struct ftstat_rpt *rpt);
int ftstat_rpt_57_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_57_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_57_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_57_free(struct ftstat_rpt_57 *rpt);

struct ftstat_rpt_58 *ftstat_rpt_58_new(struct ftstat_rpt *rpt);
int ftstat_rpt_58_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_58_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_58_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_58_free(struct ftstat_rpt_58 *rpt);

struct ftstat_rpt_59 *ftstat_rpt_59_new(struct ftstat_rpt *rpt);
int ftstat_rpt_59_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_59_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_59_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_59_free(struct ftstat_rpt_59 *rpt);

struct ftstat_rpt_60 *ftstat_rpt_60_new(struct ftstat_rpt *rpt);
int ftstat_rpt_60_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_60_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_60_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_60_free(struct ftstat_rpt_60 *rpt);

struct ftstat_rpt_61 *ftstat_rpt_61_new(struct ftstat_rpt *rpt);
int ftstat_rpt_61_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_61_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_61_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_61_free(struct ftstat_rpt_61 *rpt);

struct ftstat_rpt_62 *ftstat_rpt_62_new(struct ftstat_rpt *rpt);
int ftstat_rpt_62_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_62_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_62_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_62_free(struct ftstat_rpt_62 *rpt);

struct ftstat_rpt_63 *ftstat_rpt_63_new(struct ftstat_rpt *rpt);
int ftstat_rpt_63_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_63_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_63_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_63_free(struct ftstat_rpt_63 *rpt);

struct ftstat_rpt_64 *ftstat_rpt_64_new(struct ftstat_rpt *rpt);
int ftstat_rpt_64_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_64_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_64_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_64_free(struct ftstat_rpt_64 *rpt);

struct ftstat_rpt_65 *ftstat_rpt_65_new(struct ftstat_rpt *rpt);
int ftstat_rpt_65_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_65_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_65_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_65_free(struct ftstat_rpt_65 *rpt);

struct ftstat_rpt_66 *ftstat_rpt_66_new(struct ftstat_rpt *rpt);
int ftstat_rpt_66_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_66_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_66_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_66_free(struct ftstat_rpt_66 *rpt);

struct ftstat_rpt_67 *ftstat_rpt_67_new(struct ftstat_rpt *rpt);
int ftstat_rpt_67_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_67_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_67_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_67_free(struct ftstat_rpt_67 *rpt);

struct ftstat_rpt_68 *ftstat_rpt_68_new(struct ftstat_rpt *rpt);
int ftstat_rpt_68_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_68_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_68_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_68_free(struct ftstat_rpt_68 *rpt);

struct ftstat_rpt_69 *ftstat_rpt_69_new(struct ftstat_rpt *rpt);
int ftstat_rpt_69_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_69_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_69_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_69_free(struct ftstat_rpt_69 *rpt);

struct ftstat_rpt_70 *ftstat_rpt_70_new(struct ftstat_rpt *rpt);
int ftstat_rpt_70_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_70_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_70_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_70_free(struct ftstat_rpt_70 *rpt);

struct ftstat_rpt_71 *ftstat_rpt_71_new(struct ftstat_rpt *rpt);
int ftstat_rpt_71_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_71_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_71_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_71_free(struct ftstat_rpt_71 *rpt);

struct ftstat_rpt_72 *ftstat_rpt_72_new(struct ftstat_rpt *rpt);
int ftstat_rpt_72_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_72_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_72_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_72_free(struct ftstat_rpt_72 *rpt);

struct ftstat_rpt_73 *ftstat_rpt_73_new(struct ftstat_rpt *rpt);
int ftstat_rpt_73_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_73_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_73_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_73_free(struct ftstat_rpt_73 *rpt);

struct ftstat_rpt_74 *ftstat_rpt_74_new(struct ftstat_rpt *rpt);
int ftstat_rpt_74_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_74_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_74_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_74_free(struct ftstat_rpt_74 *rpt);

struct ftstat_rpt_75 *ftstat_rpt_75_new(struct ftstat_rpt *rpt);
int ftstat_rpt_75_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_75_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_75_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_75_free(struct ftstat_rpt_75 *rpt);

struct ftstat_rpt_76 *ftstat_rpt_76_new(struct ftstat_rpt *rpt);
int ftstat_rpt_76_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_76_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_76_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_76_free(struct ftstat_rpt_76 *rpt);

struct ftstat_rpt_77 *ftstat_rpt_77_new(struct ftstat_rpt *rpt);
int ftstat_rpt_77_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_77_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_77_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_77_free(struct ftstat_rpt_77 *rpt);

struct ftstat_rpt_78 *ftstat_rpt_78_new(struct ftstat_rpt *rpt);
int ftstat_rpt_78_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo);
int ftstat_rpt_78_calc(struct ftstat_rpt *rpt);
int ftstat_rpt_78_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt);
void ftstat_rpt_78_free(struct ftstat_rpt_78 *rpt);

struct typelookup tlookup[] = {
  {"summary-detail",
    (void*)ftstat_rpt_1_new,
    (void*)ftstat_rpt_1_accum,
    (void*)ftstat_rpt_1_calc,
    (void*)ftstat_rpt_1_dump,
    (void*)ftstat_rpt_1_free,
    FT_STAT_FIELD_OTHER|FT_STAT_FIELD_PS,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS},
  {"summary-counters",
    (void*)ftstat_rpt_2_new,
    (void*)ftstat_rpt_2_accum,
    (void*)ftstat_rpt_2_calc,
    (void*)ftstat_rpt_2_dump,
    (void*)ftstat_rpt_2_free,
    FT_STAT_FIELD_PS,
    FT_STAT_OPT_HEADER|FT_STAT_OPT_XHEADER|FT_STAT_OPT_TOTALS,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS},
  {"packet-size",
    (void*)ftstat_rpt_3_new,
    (void*)ftstat_rpt_3_accum,
    (void*)ftstat_rpt_3_calc,
    (void*)ftstat_rpt_3_dump,
    (void*)ftstat_rpt_3_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS},
  {"octets",
    (void*)ftstat_rpt_4_new,
    (void*)ftstat_rpt_4_accum,
    (void*)ftstat_rpt_4_calc,
    (void*)ftstat_rpt_4_dump,
    (void*)ftstat_rpt_4_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS},
  {"packets",
    (void*)ftstat_rpt_5_new,
    (void*)ftstat_rpt_5_accum,
    (void*)ftstat_rpt_5_calc,
    (void*)ftstat_rpt_5_dump,
    (void*)ftstat_rpt_5_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS},
  {"ip-source-port",
    (void*)ftstat_rpt_6_new,
    (void*)ftstat_rpt_6_accum,
    (void*)ftstat_rpt_6_calc,
    (void*)ftstat_rpt_6_dump,
    (void*)ftstat_rpt_6_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRCPORT},
  {"ip-destination-port",
    (void*)ftstat_rpt_7_new,
    (void*)ftstat_rpt_7_accum,
    (void*)ftstat_rpt_7_calc,
    (void*)ftstat_rpt_7_dump,
    (void*)ftstat_rpt_7_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DSTPORT},
  {"ip-source/destination-port",
    (void*)ftstat_rpt_8_new,
    (void*)ftstat_rpt_8_accum,
    (void*)ftstat_rpt_8_calc,
    (void*)ftstat_rpt_8_dump,
    (void*)ftstat_rpt_8_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRCPORT|
      FT_XFIELD_DSTPORT},
  {"bps",
    (void*)ftstat_rpt_9_new,
    (void*)ftstat_rpt_9_accum,
    (void*)ftstat_rpt_9_calc,
    (void*)ftstat_rpt_9_dump,
    (void*)ftstat_rpt_9_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS},
  {"pps",
    (void*)ftstat_rpt_10_new,
    (void*)ftstat_rpt_10_accum,
    (void*)ftstat_rpt_10_calc,
    (void*)ftstat_rpt_10_dump,
    (void*)ftstat_rpt_10_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS},
  {"ip-destination-address-type",
    (void*)ftstat_rpt_11_new,
    (void*)ftstat_rpt_11_accum,
    (void*)ftstat_rpt_11_calc,
    (void*)ftstat_rpt_11_dump,
    (void*)ftstat_rpt_11_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DSTADDR},
  {"ip-protocol",
    (void*)ftstat_rpt_12_new,
    (void*)ftstat_rpt_12_accum,
    (void*)ftstat_rpt_12_calc,
    (void*)ftstat_rpt_12_dump,
    (void*)ftstat_rpt_12_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_PROT},
  {"ip-tos",
    (void*)ftstat_rpt_13_new,
    (void*)ftstat_rpt_13_accum,
    (void*)ftstat_rpt_13_calc,
    (void*)ftstat_rpt_13_dump,
    (void*)ftstat_rpt_13_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_TOS},
  {"ip-next-hop-address",
    (void*)ftstat_rpt_14_new,
    (void*)ftstat_rpt_14_accum,
    (void*)ftstat_rpt_14_calc,
    (void*)ftstat_rpt_14_dump,
    (void*)ftstat_rpt_14_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_NEXTHOP},
  {"ip-source-address",
    (void*)ftstat_rpt_15_new,
    (void*)ftstat_rpt_15_accum,
    (void*)ftstat_rpt_15_calc,
    (void*)ftstat_rpt_15_dump,
    (void*)ftstat_rpt_15_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRCADDR},
  {"ip-destination-address",
    (void*)ftstat_rpt_16_new,
    (void*)ftstat_rpt_16_accum,
    (void*)ftstat_rpt_16_calc,
    (void*)ftstat_rpt_16_dump,
    (void*)ftstat_rpt_16_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DSTADDR},
  {"ip-source/destination-address",
    (void*)ftstat_rpt_17_new,
    (void*)ftstat_rpt_17_accum,
    (void*)ftstat_rpt_17_calc,
    (void*)ftstat_rpt_17_dump,
    (void*)ftstat_rpt_17_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRCADDR|
      FT_XFIELD_DSTADDR},
  {"ip-exporter-address",
    (void*)ftstat_rpt_18_new,
    (void*)ftstat_rpt_18_accum,
    (void*)ftstat_rpt_18_calc,
    (void*)ftstat_rpt_18_dump,
    (void*)ftstat_rpt_18_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_EXADDR},
  {"input-interface",
    (void*)ftstat_rpt_19_new,
    (void*)ftstat_rpt_19_accum,
    (void*)ftstat_rpt_19_calc,
    (void*)ftstat_rpt_19_dump,
    (void*)ftstat_rpt_19_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_INPUT},
  {"output-interface",
    (void*)ftstat_rpt_20_new,
    (void*)ftstat_rpt_20_accum,
    (void*)ftstat_rpt_20_calc,
    (void*)ftstat_rpt_20_dump,
    (void*)ftstat_rpt_20_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_OUTPUT},
  {"input/output-interface",
    (void*)ftstat_rpt_21_new,
    (void*)ftstat_rpt_21_accum,
    (void*)ftstat_rpt_21_calc,
    (void*)ftstat_rpt_21_dump,
    (void*)ftstat_rpt_21_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_INPUT|
      FT_XFIELD_OUTPUT},
  {"source-as",
    (void*)ftstat_rpt_22_new,
    (void*)ftstat_rpt_22_accum,
    (void*)ftstat_rpt_22_calc,
    (void*)ftstat_rpt_22_dump,
    (void*)ftstat_rpt_22_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRC_AS},
  {"destination-as",
    (void*)ftstat_rpt_23_new,
    (void*)ftstat_rpt_23_accum,
    (void*)ftstat_rpt_23_calc,
    (void*)ftstat_rpt_23_dump,
    (void*)ftstat_rpt_23_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DST_AS},
  {"source/destination-as",
    (void*)ftstat_rpt_24_new,
    (void*)ftstat_rpt_24_accum,
    (void*)ftstat_rpt_24_calc,
    (void*)ftstat_rpt_24_dump,
    (void*)ftstat_rpt_24_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRC_AS|
      FT_XFIELD_DST_AS},
  {"ip-source-address/source-as",
    (void*)ftstat_rpt_25_new,
    (void*)ftstat_rpt_25_accum,
    (void*)ftstat_rpt_25_calc,
    (void*)ftstat_rpt_25_dump,
    (void*)ftstat_rpt_25_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRC_AS|
      FT_XFIELD_SRCADDR},
  {"ip-destination-address/source-as",
    (void*)ftstat_rpt_26_new,
    (void*)ftstat_rpt_26_accum,
    (void*)ftstat_rpt_26_calc,
    (void*)ftstat_rpt_26_dump,
    (void*)ftstat_rpt_26_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRC_AS|
      FT_XFIELD_DSTADDR},
  {"ip-source-address/destination-as",
    (void*)ftstat_rpt_27_new,
    (void*)ftstat_rpt_27_accum,
    (void*)ftstat_rpt_27_calc,
    (void*)ftstat_rpt_27_dump,
    (void*)ftstat_rpt_27_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DST_AS|
      FT_XFIELD_SRCADDR},
  {"ip-destination-address/destination-as",
    (void*)ftstat_rpt_28_new,
    (void*)ftstat_rpt_28_accum,
    (void*)ftstat_rpt_28_calc,
    (void*)ftstat_rpt_28_dump,
    (void*)ftstat_rpt_28_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DST_AS|
      FT_XFIELD_DSTADDR},
  {"ip-source/destination-address/source-as",
    (void*)ftstat_rpt_29_new,
    (void*)ftstat_rpt_29_accum,
    (void*)ftstat_rpt_29_calc,
    (void*)ftstat_rpt_29_dump,
    (void*)ftstat_rpt_29_free,
    FT_STAT_FIELD_GENERIC3,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRC_AS|
      FT_XFIELD_SRCADDR|FT_XFIELD_DSTADDR},
  {"ip-source/destination-address/destination-as",
    (void*)ftstat_rpt_30_new,
    (void*)ftstat_rpt_30_accum,
    (void*)ftstat_rpt_30_calc,
    (void*)ftstat_rpt_30_dump,
    (void*)ftstat_rpt_30_free,
    FT_STAT_FIELD_GENERIC3,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DST_AS|
      FT_XFIELD_SRCADDR|FT_XFIELD_DSTADDR},
  {"ip-source/destination-address/source/destination-as",
    (void*)ftstat_rpt_31_new,
    (void*)ftstat_rpt_31_accum,
    (void*)ftstat_rpt_31_calc,
    (void*)ftstat_rpt_31_dump,
    (void*)ftstat_rpt_31_free,
    FT_STAT_FIELD_GENERIC4,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRC_AS|
      FT_XFIELD_DST_AS|FT_XFIELD_SRCADDR|FT_XFIELD_DSTADDR},
  {"ip-source-address/input-interface",
    (void*)ftstat_rpt_32_new,
    (void*)ftstat_rpt_32_accum,
    (void*)ftstat_rpt_32_calc,
    (void*)ftstat_rpt_32_dump,
    (void*)ftstat_rpt_32_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_INPUT|
      FT_XFIELD_SRCADDR},
  {"ip-destination-address/input-interface",
    (void*)ftstat_rpt_33_new,
    (void*)ftstat_rpt_33_accum,
    (void*)ftstat_rpt_33_calc,
    (void*)ftstat_rpt_33_dump,
    (void*)ftstat_rpt_33_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_INPUT|
      FT_XFIELD_DSTADDR},
  {"ip-source-address/output-interface",
    (void*)ftstat_rpt_34_new,
    (void*)ftstat_rpt_34_accum,
    (void*)ftstat_rpt_34_calc,
    (void*)ftstat_rpt_34_dump,
    (void*)ftstat_rpt_34_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_OUTPUT|
      FT_XFIELD_SRCADDR},
  {"ip-destination-address/output-interface",
    (void*)ftstat_rpt_35_new,
    (void*)ftstat_rpt_35_accum,
    (void*)ftstat_rpt_35_calc,
    (void*)ftstat_rpt_35_dump,
    (void*)ftstat_rpt_35_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_OUTPUT|
      FT_XFIELD_DSTADDR},
  {"ip-source/destination-address/input-interface",
    (void*)ftstat_rpt_36_new,
    (void*)ftstat_rpt_36_accum,
    (void*)ftstat_rpt_36_calc,
    (void*)ftstat_rpt_36_dump,
    (void*)ftstat_rpt_36_free,
    FT_STAT_FIELD_GENERIC3,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_INPUT|
      FT_XFIELD_SRCADDR|FT_XFIELD_DSTADDR},
  {"ip-source/destination-address/output-interface",
    (void*)ftstat_rpt_37_new,
    (void*)ftstat_rpt_37_accum,
    (void*)ftstat_rpt_37_calc,
    (void*)ftstat_rpt_37_dump,
    (void*)ftstat_rpt_37_free,
    FT_STAT_FIELD_GENERIC3,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_OUTPUT|
      FT_XFIELD_SRCADDR|FT_XFIELD_DSTADDR},
  {"ip-source/destination-address/input/output-interface",
    (void*)ftstat_rpt_38_new,
    (void*)ftstat_rpt_38_accum,
    (void*)ftstat_rpt_38_calc,
    (void*)ftstat_rpt_38_dump,
    (void*)ftstat_rpt_38_free,
    FT_STAT_FIELD_GENERIC4,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_INPUT|
      FT_XFIELD_OUTPUT|FT_XFIELD_SRCADDR|FT_XFIELD_DSTADDR},
  {"input-interface/source-as",
    (void*)ftstat_rpt_39_new,
    (void*)ftstat_rpt_39_accum,
    (void*)ftstat_rpt_39_calc,
    (void*)ftstat_rpt_39_dump,
    (void*)ftstat_rpt_39_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_INPUT|
      FT_XFIELD_SRC_AS},
  {"input-interface/destination-as",
    (void*)ftstat_rpt_40_new,
    (void*)ftstat_rpt_40_accum,
    (void*)ftstat_rpt_40_calc,
    (void*)ftstat_rpt_40_dump,
    (void*)ftstat_rpt_40_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_INPUT|
      FT_XFIELD_DST_AS},
  {"output-interface/source-as",
    (void*)ftstat_rpt_41_new,
    (void*)ftstat_rpt_41_accum,
    (void*)ftstat_rpt_41_calc,
    (void*)ftstat_rpt_41_dump,
    (void*)ftstat_rpt_41_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_OUTPUT|
      FT_XFIELD_SRC_AS},
  {"output-interface/destination-as",
    (void*)ftstat_rpt_42_new,
    (void*)ftstat_rpt_42_accum,
    (void*)ftstat_rpt_42_calc,
    (void*)ftstat_rpt_42_dump,
    (void*)ftstat_rpt_42_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_OUTPUT|
      FT_XFIELD_DST_AS},
  {"input-interface/source/destination-as",
    (void*)ftstat_rpt_43_new,
    (void*)ftstat_rpt_43_accum,
    (void*)ftstat_rpt_43_calc,
    (void*)ftstat_rpt_43_dump,
    (void*)ftstat_rpt_43_free,
    FT_STAT_FIELD_GENERIC3,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_INPUT|
      FT_XFIELD_SRC_AS|FT_XFIELD_DST_AS},
  {"output-interface/source/destination-as",
    (void*)ftstat_rpt_44_new,
    (void*)ftstat_rpt_44_accum,
    (void*)ftstat_rpt_44_calc,
    (void*)ftstat_rpt_44_dump,
    (void*)ftstat_rpt_44_free,
    FT_STAT_FIELD_GENERIC3,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_OUTPUT|
      FT_XFIELD_SRC_AS|FT_XFIELD_DST_AS},
  {"input/output-interface/source/destination-as",
    (void*)ftstat_rpt_45_new,
    (void*)ftstat_rpt_45_accum,
    (void*)ftstat_rpt_45_calc,
    (void*)ftstat_rpt_45_dump,
    (void*)ftstat_rpt_45_free,
    FT_STAT_FIELD_GENERIC4,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_INPUT|
      FT_XFIELD_OUTPUT|FT_XFIELD_SRC_AS|FT_XFIELD_DST_AS},
  {"engine-id",
    (void*)ftstat_rpt_46_new,
    (void*)ftstat_rpt_46_accum,
    (void*)ftstat_rpt_46_calc,
    (void*)ftstat_rpt_46_dump,
    (void*)ftstat_rpt_46_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_ENGINE_ID},
  {"engine-type",
    (void*)ftstat_rpt_47_new,
    (void*)ftstat_rpt_47_accum,
    (void*)ftstat_rpt_47_calc,
    (void*)ftstat_rpt_47_dump,
    (void*)ftstat_rpt_47_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_ENGINE_TYPE},
  {"source-tag",
    (void*)ftstat_rpt_48_new,
    (void*)ftstat_rpt_48_accum,
    (void*)ftstat_rpt_48_calc,
    (void*)ftstat_rpt_48_dump,
    (void*)ftstat_rpt_48_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRC_TAG},
  {"destination-tag",
    (void*)ftstat_rpt_49_new,
    (void*)ftstat_rpt_49_accum,
    (void*)ftstat_rpt_49_calc,
    (void*)ftstat_rpt_49_dump,
    (void*)ftstat_rpt_49_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DST_TAG},
  {"source/destination-tag",
    (void*)ftstat_rpt_50_new,
    (void*)ftstat_rpt_50_accum,
    (void*)ftstat_rpt_50_calc,
    (void*)ftstat_rpt_50_dump,
    (void*)ftstat_rpt_50_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRC_TAG|
      FT_XFIELD_DST_TAG},
  {"ip-source-address/ip-source-port",
    (void*)ftstat_rpt_51_new,
    (void*)ftstat_rpt_51_accum,
    (void*)ftstat_rpt_51_calc,
    (void*)ftstat_rpt_51_dump,
    (void*)ftstat_rpt_51_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRCADDR|
      FT_XFIELD_SRCPORT},
  {"ip-source-address/ip-destination-port",
    (void*)ftstat_rpt_52_new,
    (void*)ftstat_rpt_52_accum,
    (void*)ftstat_rpt_52_calc,
    (void*)ftstat_rpt_52_dump,
    (void*)ftstat_rpt_52_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRCADDR|
      FT_XFIELD_DSTPORT},
  {"ip-destination-address/ip-source-port",
    (void*)ftstat_rpt_53_new,
    (void*)ftstat_rpt_53_accum,
    (void*)ftstat_rpt_53_calc,
    (void*)ftstat_rpt_53_dump,
    (void*)ftstat_rpt_53_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DSTADDR|
      FT_XFIELD_SRCPORT},
  {"ip-destination-address/ip-destination-port",
    (void*)ftstat_rpt_54_new,
    (void*)ftstat_rpt_54_accum,
    (void*)ftstat_rpt_54_calc,
    (void*)ftstat_rpt_54_dump,
    (void*)ftstat_rpt_54_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DSTADDR|
      FT_XFIELD_DSTPORT},
  {"ip-source-address/ip-source/destination-port",
    (void*)ftstat_rpt_55_new,
    (void*)ftstat_rpt_55_accum,
    (void*)ftstat_rpt_55_calc,
    (void*)ftstat_rpt_55_dump,
    (void*)ftstat_rpt_55_free,
    FT_STAT_FIELD_GENERIC3,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRCADDR|
      FT_XFIELD_SRCPORT|FT_XFIELD_DSTPORT},
  {"ip-destination-address/ip-source/destination-port",
    (void*)ftstat_rpt_56_new,
    (void*)ftstat_rpt_56_accum,
    (void*)ftstat_rpt_56_calc,
    (void*)ftstat_rpt_56_dump,
    (void*)ftstat_rpt_56_free,
    FT_STAT_FIELD_GENERIC3,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DSTADDR|
      FT_XFIELD_SRCPORT|FT_XFIELD_DSTPORT},
  {"ip-source/destination-address/ip-source-port",
    (void*)ftstat_rpt_57_new,
    (void*)ftstat_rpt_57_accum,
    (void*)ftstat_rpt_57_calc,
    (void*)ftstat_rpt_57_dump,
    (void*)ftstat_rpt_57_free,
    FT_STAT_FIELD_GENERIC3,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRCADDR|
      FT_XFIELD_DSTADDR|FT_XFIELD_DSTPORT},
  {"ip-source/destination-address/ip-destination-port",
    (void*)ftstat_rpt_58_new,
    (void*)ftstat_rpt_58_accum,
    (void*)ftstat_rpt_58_calc,
    (void*)ftstat_rpt_58_dump,
    (void*)ftstat_rpt_58_free,
    FT_STAT_FIELD_GENERIC3,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRCADDR|
      FT_XFIELD_DSTADDR|FT_XFIELD_DSTPORT},
  {"ip-source/destination-address/ip-source/destination-port",
    (void*)ftstat_rpt_59_new,
    (void*)ftstat_rpt_59_accum,
    (void*)ftstat_rpt_59_calc,
    (void*)ftstat_rpt_59_dump,
    (void*)ftstat_rpt_59_free,
    FT_STAT_FIELD_GENERIC4,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRCADDR|
      FT_XFIELD_DSTADDR|FT_XFIELD_SRCPORT|FT_XFIELD_DSTPORT},
  {"ip-source-address/input/output-interface",
    (void*)ftstat_rpt_60_new,
    (void*)ftstat_rpt_60_accum,
    (void*)ftstat_rpt_60_calc,
    (void*)ftstat_rpt_60_dump,
    (void*)ftstat_rpt_60_free,
    FT_STAT_FIELD_GENERIC3,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRCADDR|
      FT_XFIELD_INPUT|FT_XFIELD_OUTPUT},
  {"ip-destination-address/input/output-interface",
    (void*)ftstat_rpt_61_new,
    (void*)ftstat_rpt_61_accum,
    (void*)ftstat_rpt_61_calc,
    (void*)ftstat_rpt_61_dump,
    (void*)ftstat_rpt_61_free,
    FT_STAT_FIELD_GENERIC3,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DSTADDR|
      FT_XFIELD_INPUT|FT_XFIELD_OUTPUT},
  {"ip-source-address/source/destination-as",
    (void*)ftstat_rpt_62_new,
    (void*)ftstat_rpt_62_accum,
    (void*)ftstat_rpt_62_calc,
    (void*)ftstat_rpt_62_dump,
    (void*)ftstat_rpt_62_free,
    FT_STAT_FIELD_GENERIC3,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRCADDR|
      FT_XFIELD_SRC_AS|FT_XFIELD_DST_AS},
  {"ip-destination-address/source/destination-as",
    (void*)ftstat_rpt_63_new,
    (void*)ftstat_rpt_63_accum,
    (void*)ftstat_rpt_63_calc,
    (void*)ftstat_rpt_63_dump,
    (void*)ftstat_rpt_63_free,
    FT_STAT_FIELD_GENERIC3,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DSTADDR|
      FT_XFIELD_SRC_AS|FT_XFIELD_DST_AS},
  {"ip-address",
    (void*)ftstat_rpt_64_new,
    (void*)ftstat_rpt_64_accum,
    (void*)ftstat_rpt_64_calc,
    (void*)ftstat_rpt_64_dump,
    (void*)ftstat_rpt_64_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DSTADDR|
      FT_XFIELD_SRCADDR},
  {"ip-port",
    (void*)ftstat_rpt_65_new,
    (void*)ftstat_rpt_65_accum,
    (void*)ftstat_rpt_65_calc,
    (void*)ftstat_rpt_65_dump,
    (void*)ftstat_rpt_65_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DSTPORT|
      FT_XFIELD_SRCPORT},
  {"ip-source-address-destination-count",
    (void*)ftstat_rpt_66_new,
    (void*)ftstat_rpt_66_accum,
    (void*)ftstat_rpt_66_calc,
    (void*)ftstat_rpt_66_dump,
    (void*)ftstat_rpt_66_free,
    FT_STAT_FIELD_GENERIC|FT_STAT_FIELD_COUNT,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DSTADDR|
      FT_XFIELD_SRCADDR},
  {"ip-destination-address-source-count",
    (void*)ftstat_rpt_67_new,
    (void*)ftstat_rpt_67_accum,
    (void*)ftstat_rpt_67_calc,
    (void*)ftstat_rpt_67_dump,
    (void*)ftstat_rpt_67_free,
    FT_STAT_FIELD_GENERIC|FT_STAT_FIELD_COUNT,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DSTADDR|
      FT_XFIELD_SRCADDR},
  {"ip-source/destination-address/ip-protocol/ip-tos/ip-source/destination-port",
    (void*)ftstat_rpt_68_new,
    (void*)ftstat_rpt_68_accum,
    (void*)ftstat_rpt_68_calc,
    (void*)ftstat_rpt_68_dump,
    (void*)ftstat_rpt_68_free,
    FT_STAT_FIELD_GENERIC6,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DSTADDR|
      FT_XFIELD_SRCADDR|FT_XFIELD_PROT|FT_XFIELD_TOS|FT_XFIELD_SRCPORT|
      FT_XFIELD_DSTPORT},
  {"ip-source/destination-address/ip-protocol/ip-tos",
    (void*)ftstat_rpt_69_new,
    (void*)ftstat_rpt_69_accum,
    (void*)ftstat_rpt_69_calc,
    (void*)ftstat_rpt_69_dump,
    (void*)ftstat_rpt_69_free,
    FT_STAT_FIELD_GENERIC4,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DSTADDR|
      FT_XFIELD_SRCADDR|FT_XFIELD_PROT|FT_XFIELD_TOS},
  {"ip-source-address/source-tag",
    (void*)ftstat_rpt_70_new,
    (void*)ftstat_rpt_70_accum,
    (void*)ftstat_rpt_70_calc,
    (void*)ftstat_rpt_70_dump,
    (void*)ftstat_rpt_70_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRCADDR|
      FT_XFIELD_SRC_TAG},
  {"ip-source-address/destination-tag",
    (void*)ftstat_rpt_71_new,
    (void*)ftstat_rpt_71_accum,
    (void*)ftstat_rpt_71_calc,
    (void*)ftstat_rpt_71_dump,
    (void*)ftstat_rpt_71_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SRCADDR|
      FT_XFIELD_DST_TAG},
  {"ip-destination-address/source-tag",
    (void*)ftstat_rpt_72_new,
    (void*)ftstat_rpt_72_accum,
    (void*)ftstat_rpt_72_calc,
    (void*)ftstat_rpt_72_dump,
    (void*)ftstat_rpt_72_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DSTADDR|
      FT_XFIELD_SRC_TAG},
  {"ip-destination-address/destination-tag",
    (void*)ftstat_rpt_73_new,
    (void*)ftstat_rpt_73_accum,
    (void*)ftstat_rpt_73_calc,
    (void*)ftstat_rpt_73_dump,
    (void*)ftstat_rpt_73_free,
    FT_STAT_FIELD_GENERIC2,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DSTADDR|
      FT_XFIELD_DST_TAG},
  {"ip-source/destination-address/source/destination-tag",
    (void*)ftstat_rpt_74_new,
    (void*)ftstat_rpt_74_accum,
    (void*)ftstat_rpt_74_calc,
    (void*)ftstat_rpt_74_dump,
    (void*)ftstat_rpt_74_free,
    FT_STAT_FIELD_GENERIC4,
    FT_STAT_OPT_GENERIC_IP_ADDR,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_DSTADDR|
      FT_XFIELD_SRCADDR|FT_XFIELD_SRC_TAG|FT_XFIELD_DST_TAG},
  {"linear-interpolated-flows-octets-packets",
    (void*)ftstat_rpt_75_new,
    (void*)ftstat_rpt_75_accum,
    (void*)ftstat_rpt_75_calc,
    (void*)ftstat_rpt_75_dump,
    (void*)ftstat_rpt_75_free,
    FT_STAT_FIELD_FLOWS|FT_STAT_FIELD_OCTETS|FT_STAT_FIELD_PACKETS|
      FT_STAT_FIELD_KEY,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS},
  {"first",
    (void*)ftstat_rpt_76_new,
    (void*)ftstat_rpt_76_accum,
    (void*)ftstat_rpt_76_calc,
    (void*)ftstat_rpt_76_dump,
    (void*)ftstat_rpt_76_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS},
  {"last",
    (void*)ftstat_rpt_77_new,
    (void*)ftstat_rpt_77_accum,
    (void*)ftstat_rpt_77_calc,
    (void*)ftstat_rpt_77_dump,
    (void*)ftstat_rpt_77_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS},
  {"duration",
    (void*)ftstat_rpt_78_new,
    (void*)ftstat_rpt_78_accum,
    (void*)ftstat_rpt_78_calc,
    (void*)ftstat_rpt_78_dump,
    (void*)ftstat_rpt_78_free,
    FT_STAT_FIELD_GENERIC,
    FT_STAT_OPT_GENERIC,
    FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS|FT_XFIELD_FIRST|FT_XFIELD_LAST|
      FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS},

  {(char*)0L, 0, (void*)0L},
};


static struct jump pjump[] = {
          {"include-mask", 0, parse_include_mask},
          {"include-tag", 0, parse_include_tag},
          {"include-filter", 0, parse_include_filter},
          {"stat-report", 0, parse_rpt},
          {"type", PARSE_STATE_REPORT, parse_rpt_type},
          {"filter", PARSE_STATE_REPORT, parse_rpt_filter},
          {"scale", PARSE_STATE_REPORT, parse_rpt_scale},
          {"output", PARSE_STATE_REPORT, parse_rpt_output},
          {"tag-mask", PARSE_STATE_REPORT, parse_rpt_tag_mask},
          {"ip-source-address-format", PARSE_STATE_REPORT,
            parse_rpt_ip_src_addr_fmt},
          {"ip-destination-address-format", PARSE_STATE_REPORT,
            parse_rpt_ip_dst_addr_fmt},
          {"format", PARSE_STATE_OUTPUT, parse_rpt_out_format},
          {"sort", PARSE_STATE_OUTPUT, parse_rpt_out_sort},
          {"records", PARSE_STATE_OUTPUT, parse_rpt_out_records},
          {"tally", PARSE_STATE_OUTPUT, parse_rpt_out_tally},
          {"fields", PARSE_STATE_OUTPUT, parse_rpt_out_fields},
          {"options", PARSE_STATE_OUTPUT, parse_rpt_out_options},
          {"path", PARSE_STATE_OUTPUT, parse_rpt_out_path},
          {"time", PARSE_STATE_OUTPUT, parse_rpt_out_time},
          {"stat-definition", 0, parse_def},
          {"filter", PARSE_STATE_DEFINITION, parse_def_filter},
          {"tag", PARSE_STATE_DEFINITION, parse_def_tag},
          {"mask", PARSE_STATE_DEFINITION, parse_def_mask},
          {"report", PARSE_STATE_DEFINITION, parse_def_report},
          {"time-series", PARSE_STATE_DEFINITION, parse_def_time_series},
          {0, 0, 0},
          };

/*
 *************************************************************************
                              public ftstat_*
 *************************************************************************
 */


/*
 * function: ftstat_load
 *
 * Process fname into ftstat.
 *
 * returns: 0  ok
 *          <0 fail
 */
int ftstat_load(struct ftstat *ftstat, struct ftvar *ftvar, char *fname)
{
  struct stat sb;
  struct jump *jmp;
  struct line_parser lp;
  int fd, ret, found;
  char *buf, *buf2, *c;
  char sbuf[FT_LP_MAXLINE];

  ret = -1;
  buf = (char*)0L;
  bzero(&lp, sizeof lp);
  bzero(ftstat, sizeof *ftstat);

  FT_SLIST_INIT(&ftstat->defs);
  FT_SLIST_INIT(&ftstat->rpts);

  ftstat->ftvar = ftvar;

  lp.fname = fname;

  if ((fd = open(fname, O_RDONLY, 0)) < 0) {
    fterr_warn("open(%s)", fname);
    goto load_stat_out;
  }

  if (fstat(fd, &sb) < 0) {
    fterr_warn("stat(%s)", fname);
    goto load_stat_out;
  }
  
  /* allocate storage for file */
  if (!(buf = malloc(sb.st_size+1))) {
    fterr_warn("malloc()");
    goto load_stat_out;
  }

  /* read in file */
  if (read(fd, buf, sb.st_size) != sb.st_size) {
    fterr_warnx("read(%s): short", fname);
    goto load_stat_out;
  }

  /* null terminate file */
  buf[sb.st_size] = 0;

  buf2 = buf;

  for (;;) {
  
    /* rip a line */
    for (;;) {
      c = strsep(&buf2, "\n");
      ++lp.lineno;
      if ((c && *c != 0) || (!c))
        break;
    }

    /* no more lines */
    if (!c) {
      goto load_stat_done;
    }

    /* do variable substitutions first */
    if (ftvar) {
      if (ftvar_evalstr(ftvar, c, sbuf, sizeof(sbuf)) < 0) {
        fterr_warnx("ftvar_evalstr(): failed");
        goto load_stat_done;
      }
    } else {
      strncpy(sbuf, c, sizeof(sbuf));
      sbuf[sizeof(sbuf)-1] = 0;
    }

    lp.buf = sbuf;

    /* first word */
    NEXT_WORD(&lp.buf, c);

    /* whitespace only line */
    if (!c) {
      continue;
    }

    /* comment line */
    if (c && *c == '#')
      continue;

    for (jmp = pjump; jmp->name; ++jmp) {

      found = 0;

      if (((!jmp->state) || (jmp->state & lp.state))
        && (!strcasecmp(c, jmp->name))) {

        found = 1;

        if (jmp->func(&lp, ftstat))
          goto load_stat_out;

        NEXT_WORD(&lp.buf, c);

        if (c) {
          fterr_warnx("%s line %d: Unexpected \"%s\".", lp.fname, lp.lineno, c);
          goto load_stat_out;
        }

        break;

      }

    } /* test each word */

    if (!found) {
      fterr_warnx("%s line %d: Unexpected \"%s\".", lp.fname, lp.lineno, c);
      goto load_stat_out;
    }
   
  } /* more lines */

load_stat_done:

  if (resolve_reports(ftstat)) {
    fterr_warnx("resolve_reports(): failed");
    goto load_stat_out;
  }

  ret = 0;

load_stat_out:

  if (fd != -1)
    close(fd);

  if (buf)
    free(buf);

  if (ret == -1)
    ftstat_free(ftstat);

  return ret;

} /* ftstat_load */

void ftstat_free(struct ftstat *ftstat)
{
  struct ftstat_def *ftsd;
  struct ftstat_rpt *ftsr;
  struct ftstat_rpt_out *ftsro;
  struct ftstat_rpt_item *ftsrpti;

  if (ftstat->ftfil_init)
    ftfil_free(&ftstat->ftfil);

  if (ftstat->fttag_init)
    fttag_free(&ftstat->fttag);

  if (ftstat->ftmask_init)
    ftmask_free(&ftstat->ftmask);

  if (ftstat->filter_fname)
    free(ftstat->filter_fname);

  if (ftstat->tag_fname)
    free(ftstat->tag_fname);

  if (ftstat->mask_fname)
    free(ftstat->mask_fname);

  /* free each definition */
  while (!FT_SLIST_EMPTY(&ftstat->defs)) {

    ftsd = FT_SLIST_FIRST(&ftstat->defs);
    FT_SLIST_REMOVE_HEAD(&ftstat->defs, chain);

    /* free each item in the definition */
    while (!FT_STAILQ_EMPTY(&ftsd->items)) {

      ftsrpti = FT_STAILQ_FIRST(&ftsd->items);
      FT_STAILQ_REMOVE_HEAD(&ftsd->items, chain);
      free(ftsrpti->tmp_report);
      free(ftsrpti);

    }

    free(ftsd->name);
    free(ftsd);

  } /* definitions */

  /* free each report */
  while (!FT_SLIST_EMPTY(&ftstat->rpts)) {

    ftsr = FT_SLIST_FIRST(&ftstat->rpts);
    FT_SLIST_REMOVE_HEAD(&ftstat->rpts, chain);

    /* free each output in the report */
    while (!FT_STAILQ_EMPTY(&ftsr->outs)) {

      ftsro =  FT_STAILQ_FIRST(&ftsr->outs);
      FT_STAILQ_REMOVE_HEAD(&ftsr->outs, chain);
      if (ftsro->path)
        free(ftsro->path);
      free(ftsro);

    }

    free(ftsr->name);
    free(ftsr);

  } /* reports */

} /* ftstat_free */

struct ftstat_def *ftstat_def_find(struct ftstat *ftstat, char *name)
{
  struct ftstat_def *ftsd;
  int found;

  found = 0;

  FT_SLIST_FOREACH(ftsd, &ftstat->defs, chain) {

    if (!strcasecmp(name, ftsd->name))
      return ftsd;

  } /* ftsd */

  return (struct ftstat_def*)0L;

} /* ftstat_def_find */

/*
 * function: ftstat_def_test_xfields
 *
 * Check if fields in current flow are valid for a stat definition -- ie
 * the filter does not reference a field not contained in the flow.
 *
 * returns: 0 okay
 *          1 fail
 */
int ftstat_def_test_xfields(struct ftstat_def *active_def, u_int64 test)
{

  /* if the definition has tagging enabled _accum() will add the tags */
  if (active_def->ftd)
    test |= FT_XFIELD_SRC_TAG|FT_XFIELD_DST_TAG;

  if ((active_def->xfields & test) != active_def->xfields)
    return 1;
  else
    return 0;

} /* ftstat_def_test_xfields */

/*
 * function: ftstat_def_new
 *
 * Call the new method for each report.
 *
 * returns: 0 okay
 *          1 fail
 */
int ftstat_def_new(struct ftstat_def *active_def)
{
  struct ftstat_rpt *ftsrpt;
  struct ftstat_rpt_item *ftsrpti;
  struct ftstat_rpt_out *ftsro;
  int ret;

  ret = 1; /* err */

  /* foreach report in the definition */
  FT_STAILQ_FOREACH(ftsrpti, &active_def->items, chain) {

    ftsrpt = ftsrpti->rpt;

    /* initialize */
    ftsrpt->t_ignores = 0;
    ftsrpt->t_recs = 0;
    ftsrpt->t_flows = 0;
    ftsrpt->t_octets = 0;
    ftsrpt->t_packets = 0;
    ftsrpt->t_duration = 0;
    ftsrpt->t_count = 0;
    ftsrpt->time_start = 0xFFFFFFFF;
    ftsrpt->time_end = 0;
    ftsrpt->recs = 0;
    ftsrpt->avg_pps = 0;
    ftsrpt->avg_bps = 0;
    ftsrpt->max_pps = 0;
    ftsrpt->max_bps = 0;
    ftsrpt->min_pps = 0;
    ftsrpt->min_bps = 0;
    ftsrpt->all_fields = 0;

    /* foreach output in the report, sum the fields */
    FT_STAILQ_FOREACH(ftsro, &ftsrpt->outs, chain) {
      ftsrpt->all_fields |= ftsro->fields;
      /* could sort and not display */
      ftsrpt->all_fields |= ftsro->sort_field;
    }

    /* run the new function */
    if (!(ftsrpt->data = ftsrpt->f_new(ftsrpt))) {
      fterr_warnx("f_new(%s): failed.", ftsrpt->name);
      goto out;
    }

  }

  ret = 0;

out:

  return ret;

} /* ftstat_def_new */

/*
 * function: ftstat_def_accum
 *
 * Call the accum method for each report.
 *
 * returns: 0 okay
 *          <0 fail
 *          1 next report.
 */
int ftstat_def_accum(struct ftstat_def *active_def,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftver ftv;
  struct ftstat_rpt *ftsrpt;
  struct ftstat_rpt_item *ftsrpti;
  struct fts3rec_all2 cur;
  char xl_rec[FT_IO_MAXREC];
  int ret;

  FT_RECGET_UNIX_SECS(cur,rec,*fo);

  if (!active_def->start_time)
    active_def->start_time = cur.unix_secs;

  /* time series split? */
  if ((active_def->max_time && (cur.unix_secs > active_def->start_time) &&
    (cur.unix_secs - active_def->start_time) > active_def->max_time)) {

    active_def->start_time = cur.unix_secs;
    return 1;

  }

  ret = -1; /* err */

  /* if mask replacement is enabled, do it */
  if (active_def->ftmd)
    ftmask_def_eval(active_def->ftmd, rec, fo);

  /* if tagging is enabled, translate and tag */
  if (active_def->ftd) {

    /* translate to 1005 is not allready */
    if (fo->ftv.d_version != 1005) {

      ftv.d_version = 1005;
      ftrec_xlate(rec, &fo->ftv, &xl_rec, &ftv);
      rec = (char*)&xl_rec;
      fo = &nfo;

    }

    fttag_def_eval(active_def->ftd, (void*)rec);

  }
  
  /* if a filter is defined, evaluate it first */
  if (active_def->ftfd)
    if (ftfil_def_eval(active_def->ftfd, rec, fo) == FT_FIL_MODE_DENY)
      goto done;

  /* foreach report in the definition */
  FT_STAILQ_FOREACH(ftsrpti, &active_def->items, chain) {

    ftsrpt = ftsrpti->rpt;

    /*
     * if the tag mask option is set apply the masks, not this can only
     * be set if the tags exist.
     *
     */
    if (ftsrpt->options & FT_STAT_OPT_TAG_MASK) {

      /* preserve tags */
      FT_RECGET_SRC_TAG(cur,rec,*fo);
      FT_RECGET_DST_TAG(cur,rec,*fo);

      *((u_int32*)(rec+(*fo).src_tag)) &= ftsrpt->tag_mask_src;
      *((u_int32*)(rec+(*fo).dst_tag)) &= ftsrpt->tag_mask_dst;

    }

    /* if a filter is defined, evaluate */
    if (ftsrpt->ftfd)
      if (ftfil_def_eval(ftsrpt->ftfd, rec, fo) == FT_FIL_MODE_DENY)
        goto restore_tag;

    /* run the accum function */
    if (ftsrpt->f_accum(ftsrpt, rec, fo)) {
      fterr_warnx("f_accum(%s): failed.", ftsrpt->name);
      goto out;
    }

    /* restore tags */
restore_tag:
    if (ftsrpt->options & FT_STAT_OPT_TAG_MASK) {

      *((u_int32*)(rec+(*fo).src_tag)) = cur.src_tag;
      *((u_int32*)(rec+(*fo).dst_tag)) = cur.dst_tag;

    }

  }

done:

  ret = 0;

out:

  return ret;

} /* ftstat_def_accum */

/*
 * function: ftstat_def_calc
 *
 * Call the calc method for each report.
 *
 * returns: 0 okay
 *          1 fail
 */
int ftstat_def_calc(struct ftstat_def *active_def)
{
  struct ftstat_rpt *ftsrpt;
  struct ftstat_rpt_item *ftsrpti;
  int ret;

  ret = 1; /* err */

  /* foreach report in the definition */
  FT_STAILQ_FOREACH(ftsrpti, &active_def->items, chain) {

    ftsrpt = ftsrpti->rpt;

    /* run the new function */
    if (ftsrpt->f_calc(ftsrpt)) {
      fterr_warnx("f_calc(%s): failed.", ftsrpt->name);
      goto out;
    }

  }

  ret = 0;

out:

  return ret;

} /* ftstat_def_calc */

/*
 * function: ftstat_def_dump
 *
 * Call the dump method for each report.
 *
 * returns: 0 okay
 *          1 fail
 */
int ftstat_def_dump(struct ftio *ftio, struct ftstat_def *active_def)
{
  struct tm *tm;
  time_t now;
  FILE *fp;
  struct ftstat_rpt *ftsrpt;
  struct ftstat_rpt_item *ftsrpti;
  struct ftstat_rpt_out *ftsro;
  int ret, noclose, pipe, status;
  char fmt_tmp[64], fmt_buf[1024], path_buf[1024], *path_run;
  char *mode;

  noclose = 0; /* fclose fp */
  ret = 1; /* err */
  fp = (FILE*)0L;

  /* foreach report in the definition */
  FT_STAILQ_FOREACH(ftsrpti, &active_def->items, chain) {

    ftsrpt = ftsrpti->rpt;

    /* foreach output listed */
    FT_STAILQ_FOREACH(ftsro, &ftsrpt->outs, chain) {

      /* current output is this one */
      ftsrpt->out = ftsro;

      if (ftsro->path) {

        strncpy(fmt_buf, ftsro->path, sizeof(fmt_buf));
        fmt_buf[sizeof(fmt_buf)-1] = 0;

        if (ftsro->time == FT_STAT_TIME_NOW)
          now = time((time_t*)0L);
        else if (ftsro->time == FT_STAT_TIME_START)
          now = ftsrpt->time_start;
        else if (ftsro->time == FT_STAT_TIME_END)
          now = ftsrpt->time_end;
        else if (ftsro->time == FT_STAT_TIME_MID)
          now = ftsrpt->time_start + (ftsrpt->time_end - ftsrpt->time_start)/2;

        tm = localtime(&now);

        if (!(strftime(path_buf, sizeof path_buf, fmt_buf, tm))) {
          fterr_warnx("strftime(): failed");
          goto out;
        }

        if (path_buf[0] == '|') {
          pipe = 1;
          path_run = path_buf+1;
        } else {
          pipe = 0;
          path_run = path_buf;
        }

        if (!pipe) {

          if (mkpath(path_run, 0755) < 0) {
            fterr_warnx("mkpath(%s): failed", path_run);
            goto out;
          }

          /* write first interval, append the rest */
          if (!active_def->interval)
            mode = "w";
          else
            mode = "a";

          if (!(fp = fopen(path_run, mode))) {
            fterr_warn("fopen(%s)", path_run);
            goto out;
          }

          noclose = 0;

        } else { /* pipe */

          if (!(fp = popen(path_run, "w"))) {
            fterr_warn("popen(%s)", path_run);
            goto out;
          }

          noclose = 0;

        } /* !pipe */

      } else { /* path specified */

        fp = stdout;
        pipe = 0;
        noclose = 1;

      }

      /* display header bits */
      dump_ascii_header(fp, ftio, active_def, ftsrpt);

      /* display totals? */
      if (ftsro->options & FT_STAT_OPT_TOTALS) {
        STD_DUMP_TOTALS_HEADER;
        STD_DUMP_TOTALS_VAL;
      }

      /* run the dump function */
      if (ftsro->f_dump(fp, ftio, ftsrpt)) {
        fterr_warnx("f_dump(%s): failed.", path_run);
        goto out;
      }

      if ((!noclose) && fp) {

        if (!pipe) {
          if (fclose(fp))
            fterr_warn("fclose(%s)", path_run);
        } else {
          status = pclose(fp);
          if (status == -1)
            fterr_warn("pclose(%s)", path_run);
          if (WIFEXITED(status))
             if (WEXITSTATUS(status) != 0)
              fterr_warnx("pclose(%s): failed exit code=%d.", path_run,
                WEXITSTATUS(status));
        }

      } /* !noclose && fp */

    } /* foreach output */

  } /* foreach report */

  ret = 0;

out:

  return ret;

} /* ftstat_def_dump */

/*
 * function: ftstat_def_free
 *
 * Call the free method for each report.
 *
 * returns: 0 okay
 *          1 fail
 */
int ftstat_def_free(struct ftstat_def *active_def)
{
  struct ftstat_rpt *ftsrpt;
  struct ftstat_rpt_item *ftsrpti;

  /* foreach report in the definition */
  FT_STAILQ_FOREACH(ftsrpti, &active_def->items, chain) {

    ftsrpt = ftsrpti->rpt;

    /* run the free function */
    ftsrpt->f_free(ftsrpt->data);

  }

  return 0;

} /* ftstat_def_free */

/*
 * function: ftstat_def_reset
 *
 * Reset reports between time series intervals
 *
 * returns: 0 okay
 *          1 fail
 */
int ftstat_def_reset(struct ftstat_def *active_def)
{

  if (ftstat_def_free(active_def)) {
    fterr_warnx("ftstat_def_free(%s): failed.", active_def->name);
    return -1;
  }

  if (ftstat_def_new(active_def)) {
    fterr_warnx("ftstat_def_new(%s): failed.", active_def->name);
    return -1;
  }

  ++active_def->interval;

  return 0;

} /* ftstat_def_reset */

/*
 * function: ftstat_list_reports
 *
 * List available reports
 *
 */

void ftstat_list_reports(FILE *out)
{
  struct typelookup *tl;

  for (tl = tlookup; tl->name; ++tl)
    fprintf(out, "  %s\n", tl->name);

} /* ftstat_list_reports */

/*
 *************************************************************************
                             parse_rpt_* 
 *************************************************************************
 */

/* 
 * function: parse_rpt
 *
 * process the 'stat-report' line.  Each report has a unique name
 * which is added to the ftstat->rpts linked list.  The current
 * report is updated in lp.  Reports by themself do nothing,
 * they must be invoked by a definition.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_rpt(struct line_parser *lp, struct ftstat *ftstat)
{

  char *c;
  struct ftstat_rpt *ftsr;
   
  NEXT_WORD(&lp->buf, c);
  
  if (!c) {
    fterr_warnx("%s line %d: Expecting name.", lp->fname, lp->lineno);
    return -1;
  }

  /* check if it exists */
  FT_SLIST_FOREACH(ftsr, &ftstat->rpts, chain) {

    if (!strcasecmp(c, ftsr->name)) {
      fterr_warnx("%s line %d: Name (%s) previously defined.", lp->fname,
        lp->lineno, c);
      return -1;
    }

  }

  /* no, add a new entry to the list */
  if (!(ftsr = (struct ftstat_rpt*)malloc(sizeof *ftsr))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftsr, sizeof *ftsr);

  FT_STAILQ_INIT(&ftsr->outs);

  if (!(ftsr->name = (char*)malloc(strlen(c)+1))) {
    fterr_warn("malloc()");
    free(ftsr);
    return -1;
  }

  strcpy(ftsr->name, c);

  FT_SLIST_INSERT_HEAD(&ftstat->rpts, ftsr, chain);

  lp->state = PARSE_STATE_REPORT;
  lp->cur_rpt = ftsr;
  lp->cur_rpt_out = (struct ftstat_rpt_out*)0L;

  return 0;

} /* parse_rpt */

/* 
 * function: parse_rpt_type
 *
 * process the 'type' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_rpt_type(struct line_parser *lp, struct ftstat *ftstat)
{
  struct typelookup *tl;
  int found;

  if (!lp->cur_rpt) {
    fterr_warnx("%s line %d: Must set name first.", lp->fname, lp->lineno);
    return -1;
  }
   
  NEXT_WORD(&lp->buf, lp->word);
  
  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting type.", lp->fname, lp->lineno);
    return -1;
  }

  if (lp->cur_rpt->f_new) {
    fterr_warnx("%s line %d: Type previously defined.", lp->fname,
    lp->lineno);
    return -1;
  }

  found = 0;

  for (tl = tlookup; tl->name; ++tl) {

    if (!strcasecmp(lp->word, tl->name)) {

      lp->cur_rpt->allowed_fields = tl->allowed_fields;
      lp->cur_rpt->allowed_options = tl->allowed_options;
      lp->cur_rpt->xfields = tl->xfields;
      lp->cur_rpt->f_new = tl->f_new;
      lp->cur_rpt->f_accum = tl->f_accum;
      lp->cur_rpt->f_calc = tl->f_calc;
      lp->cur_rpt->f_dump = tl->f_dump;
      lp->cur_rpt->f_free = tl->f_free;
      lp->cur_rpt->format_name = tl->name;

      found = 1;

      break;

    }

  } /* for */

  if (!found) {
    fterr_warnx("%s line %d: Unrecognized type.", lp->fname, lp->lineno);
    return -1;
  }

  return 0;

} /* parse_rpt_type */

/* 
 * function: parse_rpt_filter
 *
 * process the 'filter' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_rpt_filter(struct line_parser *lp, struct ftstat *ftstat)
{

  if (!lp->cur_rpt) {
    fterr_warnx("%s line %d: Must set name first.", lp->fname, lp->lineno);
    return -1;
  }
   
  NEXT_WORD(&lp->buf, lp->word);
  
  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting filter name.", lp->fname, lp->lineno);
    return -1;
  }

  if (lp->cur_rpt->ftfd) {
    fterr_warnx("%s line %d: Filter previously defined for report .",
    lp->fname, lp->lineno);
    return -1;
  }

  /* delay loading the filters until one is requested */
  if (load_filters(ftstat)) {
    fterr_warnx("%s line %d: Filters not loaded.", lp->fname, lp->lineno);
    return -1;
  }

  if (!(lp->cur_rpt->ftfd = ftfil_def_find(&ftstat->ftfil,
    lp->word))) {
    fterr_warnx("%s line %d: Filter definition not found.", lp->fname,
    lp->lineno);
    return -1;
  }

  return 0;

} /* parse_rpt_filter */

/* 
 * function: parse_rpt_tag_mask
 *
 * process the 'output' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_rpt_tag_mask(struct line_parser *lp, struct ftstat *ftstat)
{

  if (!lp->cur_rpt) {
    fterr_warnx("%s line %d: Must set name first.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting source mask.", lp->fname,
    lp->lineno);
    return -1;
  }

  lp->cur_rpt->tag_mask_src = strtoul(lp->word, (char**)0L, 0);

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting destination mask.", lp->fname,
    lp->lineno);
    return -1;
  }

  lp->cur_rpt->tag_mask_dst = strtoul(lp->word, (char**)0L, 0);

  lp->cur_rpt->options |= FT_STAT_OPT_TAG_MASK;
  lp->cur_rpt->xfields |= FT_XFIELD_SRC_TAG|FT_XFIELD_DST_TAG;

  return 0;

} /* parse_rpt_tag_mask */


/* 
 * function: parse_rpt_scale
 *
 * process the 'scale' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_rpt_scale(struct line_parser *lp, struct ftstat *ftstat)
{

  if (!lp->cur_rpt) {
    fterr_warnx("%s line %d: Must set name first.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);
  
  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting scaling factor.", lp->fname,
    lp->lineno);
    return -1;
  }

  lp->cur_rpt->scale = atoi(lp->word);

  return 0;

} /* parse_rpt_scale */

/* 
 * function: parse_rpt_ip_src_addr_fmt
 *
 * process the 'ip-source-address-format' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_rpt_ip_src_addr_fmt(struct line_parser *lp, struct ftstat *ftstat)
{

  if (!lp->cur_rpt) {
    fterr_warnx("%s line %d: Not in report.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting address format.", lp->fname,
    lp->lineno);
    return -1;
  }

  if (!(strcasecmp(lp->word, "prefix-len")))
    lp->cur_rpt->options |= FT_STAT_OPT_SRC_PREFIX_LEN;
  else if (!(strcasecmp(lp->word, "prefix-mask")))
    lp->cur_rpt->options |= FT_STAT_OPT_SRC_PREFIX_MASK;
  else if (!(strcasecmp(lp->word, "address")))
    lp->cur_rpt->options &=
      ~(FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN);
  else {
    fterr_warnx("%s line %d: Invalid address format.", lp->fname, lp->lineno);
    return -1;
  }

  /*
   * if the PREFIX_LEN or PREFIX_MASK option is set then this report
   *  requires the FT_XFIELD_XXX_MASK bits.
   */

  if (lp->cur_rpt->options &
    (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {

    if (lp->cur_rpt->xfields & FT_XFIELD_SRCADDR)
      lp->cur_rpt->xfields |= FT_XFIELD_SRC_MASK;

  } else {

    lp->cur_rpt->xfields &= ~ FT_XFIELD_SRC_MASK;

  } /* OPT_PREFIX_* */

  return 0;

} /* parse_rpt_ip_src_addr_fmt */

/* 
 * function: parse_rpt_ip_dst_addr_fmt
 *
 * process the 'ip-address-format' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_rpt_ip_dst_addr_fmt(struct line_parser *lp, struct ftstat *ftstat)
{

  if (!lp->cur_rpt) {
    fterr_warnx("%s line %d: Not in report.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting address format.", lp->fname,
    lp->lineno);
    return -1;
  }

  if (!(strcasecmp(lp->word, "prefix-len")))
    lp->cur_rpt->options |= FT_STAT_OPT_DST_PREFIX_LEN;
  else if (!(strcasecmp(lp->word, "prefix-mask")))
    lp->cur_rpt->options |= FT_STAT_OPT_DST_PREFIX_MASK;
  else if (!(strcasecmp(lp->word, "address")))
    lp->cur_rpt->options
      &= ~(FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN);
  else {
    fterr_warnx("%s line %d: Invalid address format.", lp->fname, lp->lineno);
    return -1;
  }

  /*
   * if the PREFIX_LEN or PREFIX_MASK option is set then this report
   *  requires the FT_XFIELD_XXX_MASK bits.
   */

  if (lp->cur_rpt->options &
    (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {

    if (lp->cur_rpt->xfields & FT_XFIELD_DSTADDR)
      lp->cur_rpt->xfields |= FT_XFIELD_DST_MASK;

  } else {

    lp->cur_rpt->xfields &= ~ FT_XFIELD_DST_MASK;

  } /* OPT_PREFIX_* */

  return 0;

} /* parse_rpt_ip_dst_addr_fmt */

/*
 *************************************************************************
                        parse_rpt_output and friends
 *************************************************************************
 */

/* 
 * function: parse_rpt_output
 *
 * process the 'output' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_rpt_output(struct line_parser *lp, struct ftstat *ftstat)
{
  struct ftstat_rpt_out *ftsro;

  if (!lp->cur_rpt) {
    fterr_warnx("%s line %d: Not in a report.", lp->fname, lp->lineno);
    return -1;
  }

  /* add a new entry to the list */
  if (!(ftsro = (struct ftstat_rpt_out*)malloc(sizeof *ftsro))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftsro, sizeof *ftsro);
  ftsro->f_dump = lp->cur_rpt->f_dump;
  ftsro->fields = lp->cur_rpt->allowed_fields;
  ftsro->fields &= ~(FT_STAT_FIELD_FRECS|
                     FT_STAT_FIELD_INDEX|
                     FT_STAT_FIELD_FIRST|
                     FT_STAT_FIELD_LAST|
                     FT_STAT_FIELD_PPS|
                     FT_STAT_FIELD_BPS); /* default some off */
  ftsro->time = FT_STAT_TIME_MID;
  lp->cur_rpt_out = ftsro;

  FT_STAILQ_INSERT_TAIL(&lp->cur_rpt->outs, ftsro, chain);

  return 0;

} /* parse_rpt_output */

/* 
 * function: parse_rpt_out_format
 *
 * process the 'format' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_rpt_out_format(struct line_parser *lp, struct ftstat *ftstat)
{
  enum ftstat_rpt_format format;

  if (!lp->cur_rpt_out) {
    fterr_warnx("%s line %d: Not in report output.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting format.", lp->fname,
    lp->lineno);
    return -1;
  }

  if (!(strcasecmp(lp->word, "ascii")))
    format = FT_STAT_FMT_ASCII;
  else if (!(strcasecmp(lp->word, "binary")))
    format = FT_STAT_FMT_BINARY;
  else {
    fterr_warnx("%s line %d: Unrecognized format.", lp->fname, lp->lineno);
    return -1;
  }

  lp->cur_rpt->format = format;

  return 0;

} /* parse_rpt_out_format */

/* 
 * function: parse_rpt_out_sort
 *
 * process the 'sort' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_rpt_out_sort(struct line_parser *lp, struct ftstat *ftstat)
{
  int sort_field, sort_order;
  char *c;

  if (!lp->cur_rpt_out) {
    fterr_warnx("%s line %d: Not in report output.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);
  
  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting sort field.", lp->fname,
    lp->lineno);
    return -1;
  }

  c = lp->word;

  if (*c == '+')
    sort_order = FT_STAT_SORT_ASCEND;
  else if (*c == '-')
    sort_order = FT_STAT_SORT_DESCEND;
  else {
    fterr_warnx("%s line %d: Expecting + or -.", lp->fname, lp->lineno);
    return -1;
  }

  ++c;

  if (!(strcasecmp(c, "key")))
    sort_field = FT_STAT_FIELD_KEY;
  else if (!(strcasecmp(c, "key1")))
    sort_field = FT_STAT_FIELD_KEY1;
  else if (!(strcasecmp(c, "key2")))
    sort_field = FT_STAT_FIELD_KEY2;
  else if (!(strcasecmp(c, "key3")))
    sort_field = FT_STAT_FIELD_KEY3;
  else if (!(strcasecmp(c, "key4")))
    sort_field = FT_STAT_FIELD_KEY4;
  else if (!(strcasecmp(c, "key5")))
    sort_field = FT_STAT_FIELD_KEY5;
  else if (!(strcasecmp(c, "key6")))
    sort_field = FT_STAT_FIELD_KEY6;
  else if (!(strcasecmp(c, "flows")))
    sort_field = FT_STAT_FIELD_FLOWS;
  else if (!(strcasecmp(c, "octets")))
    sort_field = FT_STAT_FIELD_OCTETS;
  else if (!(strcasecmp(c, "packets")))
    sort_field = FT_STAT_FIELD_PACKETS;
  else if (!(strcasecmp(c, "duration")))
    sort_field = FT_STAT_FIELD_DURATION;
  else if (!(strcasecmp(c, "avg-pps")))
    sort_field = FT_STAT_FIELD_AVG_PPS;
  else if (!(strcasecmp(c, "min-pps")))
    sort_field = FT_STAT_FIELD_MIN_PPS;
  else if (!(strcasecmp(c, "max-pps")))
    sort_field = FT_STAT_FIELD_MAX_PPS;
  else if (!(strcasecmp(c, "avg-bps")))
    sort_field = FT_STAT_FIELD_AVG_BPS;
  else if (!(strcasecmp(c, "min-bps")))
    sort_field = FT_STAT_FIELD_MIN_BPS;
  else if (!(strcasecmp(c, "max-bps")))
    sort_field = FT_STAT_FIELD_MAX_BPS;
  else if (!(strcasecmp(c, "other")))
    sort_field = FT_STAT_FIELD_OTHER;
  else if (!(strcasecmp(c, "count")))
    sort_field = FT_STAT_FIELD_COUNT;
  else if (!(strcasecmp(c, "")))
    sort_field = 0;
  else {
    fterr_warnx("%s line %d: Unrecognized field.", lp->fname, lp->lineno);
    return -1;
  }

  if (sort_field) {

    /* make sure that the field selected is valid for this report type */
    if ((lp->cur_rpt->allowed_fields & sort_field) != sort_field) {
      fterr_warnx("%s line %d: field \"%s\" selected not available for report.",
        lp->fname, lp->lineno, c);
      return -1;
    }

    lp->cur_rpt_out->sort_field = sort_field;
    lp->cur_rpt_out->sort_order = sort_order;
    lp->cur_rpt_out->options |= FT_STAT_OPT_SORT;

  }

  return 0;

} /* parse_rpt_out_sort */

/* 
 * function: parse_rpt_out_records
 *
 * process the 'records' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_rpt_out_records(struct line_parser *lp, struct ftstat *ftstat)
{

  if (!lp->cur_rpt_out) {
    fterr_warnx("%s line %d: Not in report output.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting num records.", lp->fname,
    lp->lineno);
    return -1;
  }

  lp->cur_rpt_out->records = strtoull(lp->word, (char**)0L, 0);

  return 0;

} /* parse_rpt_out_records */

/* 
 * function: parse_rpt_out_tally
 *
 * process the 'tally' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_rpt_out_tally(struct line_parser *lp, struct ftstat *ftstat)
{

  if (!lp->cur_rpt_out) {
    fterr_warnx("%s line %d: Not in report output.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting tally increment.", lp->fname,
    lp->lineno);
    return -1;
  }

  lp->cur_rpt_out->tally = strtoul(lp->word, (char**)0L, 0);

  if (lp->cur_rpt_out->tally)
    lp->cur_rpt_out->options |= FT_STAT_OPT_TALLY;
  else
    lp->cur_rpt_out->options &= ~FT_STAT_OPT_TALLY;

  return 0;

} /* parse_rpt_out_tally */

/* 
 * function: parse_rpt_out_fields
 *
 * process the 'fields' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_rpt_out_fields(struct line_parser *lp, struct ftstat *ftstat)
{
  char *c, op;
  u_int32 nfields;

  if (!lp->cur_rpt_out) {
    fterr_warnx("%s line %d: Not in report output.", lp->fname, lp->lineno);
    return -1;
  }

  if (!lp->buf) {
    fterr_warnx("%s line %d: Expecting display fields.", lp->fname,
    lp->lineno);
    return -1;
  }

  c = lp->buf;

  while (c) {

    for (;;) {
      c = strsep(&lp->buf, " ,");
      if ((c && *c) || (!c))
        break;
    }

    if (!c)
      break;

    /* + to select, - to remove */
    op = *c++;

    if ((op != '+') && (op != '-')) {
      fterr_warnx("%s line %d: Expecting +field or -field.", lp->fname,
        lp->lineno);
      return -1;
    }

    nfields = 0;

    if (!(strcasecmp(c, "index")))
      nfields |= FT_STAT_FIELD_INDEX;
    else if (!(strcasecmp(c, "first")))
      nfields |= FT_STAT_FIELD_FIRST;
    else if (!(strcasecmp(c, "last")))
      nfields |= FT_STAT_FIELD_LAST;
    else if (!(strcasecmp(c, "key")))
      nfields |= FT_STAT_FIELD_KEY;
    else if (!(strcasecmp(c, "key1")))
      nfields |= FT_STAT_FIELD_KEY1;
    else if (!(strcasecmp(c, "key2")))
      nfields |= FT_STAT_FIELD_KEY2;
    else if (!(strcasecmp(c, "key3")))
      nfields |= FT_STAT_FIELD_KEY3;
    else if (!(strcasecmp(c, "key4")))
      nfields |= FT_STAT_FIELD_KEY4;
    else if (!(strcasecmp(c, "key5")))
      nfields |= FT_STAT_FIELD_KEY5;
    else if (!(strcasecmp(c, "key6")))
      nfields |= FT_STAT_FIELD_KEY6;
    else if (!(strcasecmp(c, "flows")))
      nfields |= FT_STAT_FIELD_FLOWS;
    else if (!(strcasecmp(c, "octets")))
      nfields |= FT_STAT_FIELD_OCTETS;
    else if (!(strcasecmp(c, "packets")))
      nfields |= FT_STAT_FIELD_PACKETS;
    else if (!(strcasecmp(c, "duration")))
      nfields |= FT_STAT_FIELD_DURATION;
    else if (!(strcasecmp(c, "pps")))
      nfields |= FT_STAT_FIELD_PPS;
    else if (!(strcasecmp(c, "avg-pps")))
      nfields |= FT_STAT_FIELD_AVG_PPS;
    else if (!(strcasecmp(c, "min-pps")))
      nfields |= FT_STAT_FIELD_MIN_PPS;
    else if (!(strcasecmp(c, "max-pps")))
      nfields |= FT_STAT_FIELD_MAX_PPS;
    else if (!(strcasecmp(c, "bps")))
      nfields |= FT_STAT_FIELD_BPS;
    else if (!(strcasecmp(c, "avg-bps")))
      nfields |= FT_STAT_FIELD_AVG_BPS;
    else if (!(strcasecmp(c, "min-bps")))
      nfields |= FT_STAT_FIELD_MIN_BPS;
    else if (!(strcasecmp(c, "max-bps")))
      nfields |= FT_STAT_FIELD_MAX_BPS;
    else if (!(strcasecmp(c, "other")))
      nfields |= FT_STAT_FIELD_OTHER;
    else if (!(strcasecmp(c, "generic")))
      nfields |= FT_STAT_FIELD_GENERIC;
    else if (!(strcasecmp(c, "count")))
      nfields |= FT_STAT_FIELD_COUNT;
    else if (!(strcasecmp(c, "frecs")))
      nfields |= FT_STAT_FIELD_FRECS;
    else if (!(strcasecmp(c, "")))
      nfields |= 0;
    else {
      fterr_warnx("%s line %d: Unrecognized field.", lp->fname, lp->lineno);
      return -1;
    }

    /* make sure that the field is valid for this report type */

    if ((lp->cur_rpt->allowed_fields & nfields) != nfields) {
      fterr_warnx(
        "%s line %d: field \"%s\" selected not available for report.",
        lp->fname, lp->lineno, c);
      return -1;
    }

    if (op == '+')
      lp->cur_rpt_out->fields |= nfields;
    else if (op == '-')
      lp->cur_rpt_out->fields &= ~nfields;

    nfields = 0;

  } /* c */

  return 0;

} /* parse_rpt_out_fields */

/* 
 * function: parse_rpt_out_options
 *
 * process the 'options' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_rpt_out_options(struct line_parser *lp, struct ftstat *ftstat)
{
  int options;
  char *c, op;

  if (!lp->cur_rpt_out) {
    fterr_warnx("%s line %d: Not in report output.", lp->fname, lp->lineno);
    return -1;
  }

  if (!lp->buf) {
    fterr_warnx("%s line %d: Expecting options.", lp->fname,
    lp->lineno);
    return -1;
  }

  c = lp->buf;

  while (c) {

    for (;;) {
      c = strsep(&lp->buf, " ,");
      if ((c && *c) || (!c))
        break;
    }

    if (!c)
      break;

    /* + to select, - to remove */
    op = *c++;

    if ((op != '+') && (op != '-')) {
      fterr_warnx("%s line %d: Expecting +option or -option.", lp->fname,
        lp->lineno);
      return -1;
    }

    options = 0;

    if (!(strcasecmp(c, "percent-total")))
      options |= FT_STAT_OPT_PERCENT;
    else if (!(strcasecmp(c, "names")))
      options |= FT_STAT_OPT_NAMES;
    else if (!(strcasecmp(c, "header")))
      options |= FT_STAT_OPT_HEADER;
    else if (!(strcasecmp(c, "xheader")))
      options |= FT_STAT_OPT_XHEADER;
    else if (!(strcasecmp(c, "totals")))
      options |= FT_STAT_OPT_TOTALS;
    else {
      fterr_warnx("%s line %d: Unrecognized option.", lp->fname, lp->lineno);
      return -1;
    }

    /* make sure that the option is valid for this report type */

    if ((lp->cur_rpt->allowed_options & options) != options) {
      fterr_warnx("%s line %d: option selected not available for report.",
        lp->fname, lp->lineno);
      return -1;
    }

    if (op == '+') 
      lp->cur_rpt_out->options |= options;
    else if (op == '-')
      lp->cur_rpt_out->options &= ~options;

    options = 0;

  } /* c */

  return 0;

} /* parse_rpt_out_options */

/* 
 * function: parse_rpt_out_path
 *
 * process the 'path' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_rpt_out_path(struct line_parser *lp, struct ftstat *ftstat)
{
  char *c;
  int len;

  if (!lp->cur_rpt_out) {
    fterr_warnx("%s line %d: Not in report output.", lp->fname, lp->lineno);
    return -1;
  }

  if (!lp->buf) {
    fterr_warnx("%s line %d: Expecting pathname.", lp->fname, lp->lineno);
    return -1;
  }

  len = strlen(lp->buf);

  if (!(c = malloc(len+1))) {
    fterr_warn("malloc()");
    return -1;
  }

  strcpy(c, lp->buf);

  lp->cur_rpt_out->path = c;

  /* eat the line */
  for (; *(lp->buf); ++lp->buf);

  return 0;

} /* parse_rpt_out_path */

/* 
 * function: parse_rpt_out_time
 *
 * process the 'time' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_rpt_out_time(struct line_parser *lp, struct ftstat *ftstat)
{

  if (!lp->cur_rpt_out) {
    fterr_warnx("%s line %d: Not in report output.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting time specifier.", lp->fname,
    lp->lineno);
    return -1;
  }

  if (!(strcasecmp(lp->word, "now")))
    lp->cur_rpt_out->time = FT_STAT_TIME_NOW;
  else if (!(strcasecmp(lp->word, "start")))
    lp->cur_rpt_out->time = FT_STAT_TIME_START;
  else if (!(strcasecmp(lp->word, "end")))
    lp->cur_rpt_out->time = FT_STAT_TIME_END;
  else if (!(strcasecmp(lp->word, "mid")))
    lp->cur_rpt_out->time = FT_STAT_TIME_MID;
  else {
    fterr_warnx("%s line %d: Invalid time specifier.", lp->fname, lp->lineno);
    return -1;
  }

  return 0;

} /* parse_rpt_out_time */

/*
 *************************************************************************
                             parse_def_* 
 *************************************************************************
 */

/* 
 * function: parse_def
 *
 * process the 'stat-definition' line.  Each definition has a unique name
 * which is added to the ftstat->defs linked list.  The current
 * definition is updated in lp.  Definitions reference reports
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_def(struct line_parser *lp, struct ftstat *ftstat)
{
  char *c;
  struct ftstat_def *ftsd;
   
  NEXT_WORD(&lp->buf, c);
  
  if (!c) {
    fterr_warnx("%s line %d: Expecting name.", lp->fname, lp->lineno);
    return -1;
  }

  /* check if it exists */
  FT_SLIST_FOREACH(ftsd, &ftstat->defs, chain) {

    if (!strcasecmp(c, ftsd->name)) {
      fterr_warnx("%s line %d: Name (%s) previously defined.", lp->fname,
        lp->lineno, c);
      return -1;
    }

  }

  /* no, add a new entry to the list */
  if (!(ftsd = (struct ftstat_def*)malloc(sizeof *ftsd))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftsd, sizeof *ftsd);
  FT_STAILQ_INIT(&ftsd->items);

  if (!(ftsd->name = (char*)malloc(strlen(c)+1))) {
    fterr_warn("malloc()");
    free(ftsd);
    return -1;
  }

  strcpy(ftsd->name, c);
  ftsd->ftstat = ftstat;

  FT_SLIST_INSERT_HEAD(&ftstat->defs, ftsd, chain);

  lp->state = PARSE_STATE_DEFINITION;
  lp->cur_def = ftsd;

  return 0;

} /* parse_def */

/* 
 * function: parse_def_filter
 *
 * process the 'filter' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_def_filter(struct line_parser *lp, struct ftstat *ftstat)
{

  if (!lp->cur_def) {
    fterr_warnx("%s line %d: Must set name first.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting filter name.", lp->fname,
    lp->lineno);
    return -1;
  }

  if (lp->cur_def->ftfd) {
    fterr_warnx("%s line %d: Filter previously defined for definition.",
    lp->fname, lp->lineno);
    return -1;
  }

  /* delay loading the filters until one is requested */
  if (load_filters(ftstat)) {
    fterr_warnx("%s line %d: Filters not loaded.", lp->fname, lp->lineno);
    return -1;
  }

  if (!(lp->cur_def->ftfd = ftfil_def_find(&ftstat->ftfil,
    lp->word))) {
    fterr_warnx("%s line %d: Filter definition not found.", lp->fname,
    lp->lineno);
    return -1;
  }

  return 0;

} /* parse_def_filter */

/* 
 * function: parse_def_tag
 *
 * process the 'tag' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_def_tag(struct line_parser *lp, struct ftstat *ftstat)
{

  if (!lp->cur_def) {
    fterr_warnx("%s line %d: Must set name first.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting tag name.", lp->fname,
    lp->lineno);
    return -1;
  }

  if (lp->cur_def->ftd) {
    fterr_warnx("%s line %d: Tag previously defined for definition.",
    lp->fname, lp->lineno);
    return -1;
  }

  /* delay loading the tags until one is requested */
  if (load_tags(ftstat)) {
    fterr_warnx("%s line %d: Tags not loaded.", lp->fname, lp->lineno);
    return -1;
  }

  if (!(lp->cur_def->ftd = fttag_def_find(&ftstat->fttag, lp->word))) {
    fterr_warnx("%s line %d: Tag definition not found.", lp->fname,
    lp->lineno);
    return -1;
  }

  return 0;

} /* parse_def_tag */

/* 
 * function: parse_def_mask
 *
 * process the 'mask' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_def_mask(struct line_parser *lp, struct ftstat *ftstat)
{

  if (!lp->cur_def) {
    fterr_warnx("%s line %d: Must set name first.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting mask name.", lp->fname,
    lp->lineno);
    return -1;
  }

  if (lp->cur_def->ftd) {
    fterr_warnx("%s line %d: Mask previously defined for definition.",
    lp->fname, lp->lineno);
    return -1;
  }

  /* delay loading the tags until one is requested */
  if (load_masks(ftstat)) {
    fterr_warnx("%s line %d: Masks not loaded.", lp->fname, lp->lineno);
    return -1;
  }

  if (!(lp->cur_def->ftmd = ftmask_def_find(&ftstat->ftmask, lp->word))) {
    fterr_warnx("%s line %d: Mask definition not found.", lp->fname,
    lp->lineno);
    return -1;
  }

  return 0;

} /* parse_def_mask */

/* 
 * function: parse_def_time_series
 *
 * process the 'time-series' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_def_time_series(struct line_parser *lp, struct ftstat *ftstat)
{

  if (!lp->cur_def) {
    fterr_warnx("%s line %d: Must set name first.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting time in seconds.", lp->fname,
    lp->lineno);
    return -1;
  }

  if (lp->cur_def->max_time) {
    fterr_warnx("%s line %d: Time previously defined for definition.",
    lp->fname, lp->lineno);
    return -1;
  }

  lp->cur_def->max_time = strtoul(lp->word, (char**)0L, 0);
  lp->cur_def->xfields |= FT_XFIELD_UNIX_SECS;

  return 0;

} /* parse_def_time_series */


/* 
 * function: parse_def_report
 *
 * process the 'report' line.
 *
 * resolve_reports() _must_ be called after the configuration file has
 * been parsed and before the parse buffer is released.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_def_report(struct line_parser *lp, struct ftstat *ftstat)
{
  struct ftstat_rpt_item *ftsrpti;
  int n;

  if (!lp->cur_def) {
    fterr_warnx("%s line %d: Must set name first.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting report name.", lp->fname,
    lp->lineno);
    return -1;
  }

  /* make sure this report is only added once */
  FT_STAILQ_FOREACH(ftsrpti, &lp->cur_def->items, chain) {

    if (!(strcasecmp(lp->word, ftsrpti->tmp_report))) {
      fterr_warnx("%s line %d: Duplicate report in definition.", lp->fname,
        lp->lineno);
      return -1;
    }

  }

  /* add this report to the list */
  if (!(ftsrpti = (struct ftstat_rpt_item*)malloc (sizeof *ftsrpti))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftsrpti, sizeof *ftsrpti);

  /* resolve this later in resolve_reports(); */
  n = strlen(lp->word);
  if (!(ftsrpti->tmp_report = malloc(n+1)))
    fterr_errx(1, "malloc(tmp_report): failed");
  strcpy(ftsrpti->tmp_report, lp->word);

  FT_STAILQ_INSERT_TAIL(&lp->cur_def->items, ftsrpti, chain);

  return 0;

} /* parse_def_report */


/* 
 * function: parse_include_tag
 *
 * process the 'include-tag' line.  Allow the default tag location
 * to be changed.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_include_tag(struct line_parser *lp, struct ftstat *ftstat)
{

  NEXT_WORD(&lp->buf, lp->word);
  
  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting pathname.", lp->fname, lp->lineno);
    return -1;
  }

  if (ftstat->tag_fname) {
    fterr_warnx("%s line %d: Tag pathname previously specified.",
    lp->fname, lp->lineno);
    return -1;
  }

  if (!(ftstat->tag_fname = malloc(strlen(lp->word)+1)))
    fterr_errx(1, "malloc(tag_fname): failed");
  strcpy(ftstat->tag_fname, lp->word);

  return 0;

} /* parse_include_tag */

/* 
 * function: parse_include_filter
 *
 * process the 'include-filter' line.  Allow the default filter location
 * to be changed.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_include_filter(struct line_parser *lp, struct ftstat *ftstat)
{

  NEXT_WORD(&lp->buf, lp->word);
  
  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting pathname.", lp->fname, lp->lineno);
    return -1;
  }

  if (ftstat->filter_fname) {
    fterr_warnx("%s line %d: Filter pathname previously specified.",
    lp->fname, lp->lineno);
    return -1;
  }

  if (!(ftstat->filter_fname = malloc(strlen(lp->word)+1)))
    fterr_errx(1, "malloc(filter_fname): failed");
  strcpy(ftstat->filter_fname, lp->word);

  return 0;

} /* parse_include_filter */

/* 
 * function: parse_include_mask
 *
 * process the 'include-mask' line.  Allow the default mask location
 * to be changed.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_include_mask(struct line_parser *lp, struct ftstat *ftstat)
{

  NEXT_WORD(&lp->buf, lp->word);
  
  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting pathname.", lp->fname, lp->lineno);
    return -1;
  }

  if (ftstat->mask_fname) {
    fterr_warnx("%s line %d: Mask pathname previously specified.",
    lp->fname, lp->lineno);
    return -1;
  }

  if (!(ftstat->mask_fname = malloc(strlen(lp->word)+1)))
    fterr_errx(1, "malloc(mask_fname): failed");
  strcpy(ftstat->mask_fname, lp->word);

  return 0;

} /* parse_include_mask */

/*
 *************************************************************************
                     ftstat_rpt_*_new/free/accum/dump 
 *************************************************************************
 */


/* function: ftstat_rpt_1_new
 *
 * Allocate and initialize data structures for rpt 1.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_1 *ftstat_rpt_1_new(struct ftstat_rpt *rpt)
{
  struct ftstat_rpt_1 *rpt1;

  if (!(rpt1 = (struct ftstat_rpt_1*)malloc(sizeof (*rpt1)))) {
    fterr_warnx("malloc(rpt1): failed");
    return (struct ftstat_rpt_1*)0L;
  }

  bzero(rpt1, sizeof *rpt1);

  return rpt1;

} /* ftstat_rpt_1_new */


/* function: ftstat_rpt_1_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_1_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{
  struct ftstat_rpt_1 *rpt1;
  struct fts3rec_all2 cur;
  u_int32 time_tmp, duration_tmp;
  double pps_tmp, bps_tmp;
  u_long p;

  STD_ACCUM;

  rpt1 = rpt->data;

  time_tmp = cur.unix_secs;
  
  if (time_tmp < rpt1->time_start)
    rpt1->time_start = time_tmp;
  
  if (time_tmp > rpt1->time_end)
    rpt1->time_end = time_tmp;

  if (cur.First < rpt1->start)
    rpt1->start = cur.First;
  
  if (cur.Last > rpt1->end)
    rpt1->end = cur.Last;

  p = cur.dOctets64 / cur.dPkts64;

  if (p <= 32) ++ rpt1->psize32;
  else if (p <= 64) ++ rpt1->psize64;
  else if (p <= 96) ++ rpt1->psize96;
  else if (p <= 128) ++ rpt1->psize128;
  else if (p <= 160) ++ rpt1->psize160;
  else if (p <= 192) ++ rpt1->psize192;
  else if (p <= 224) ++ rpt1->psize224;
  else if (p <= 256) ++ rpt1->psize256;
  else if (p <= 288) ++ rpt1->psize288;
  else if (p <= 320) ++ rpt1->psize320;
  else if (p <= 352) ++ rpt1->psize352;
  else if (p <= 384) ++ rpt1->psize384;
  else if (p <= 416) ++ rpt1->psize416;
  else if (p <= 448) ++ rpt1->psize448;
  else if (p <= 480) ++ rpt1->psize480;
  else if (p <= 512) ++ rpt1->psize512;
  else if (p <= 544) ++ rpt1->psize544;
  else if (p <= 576) ++ rpt1->psize576;
  else if (p <= 1024) ++ rpt1->psize1024;
  else if (p <= 1536) ++ rpt1->psize1536;
  else if (p <= 2048) ++ rpt1->psize2048;
  else if (p <= 2560) ++ rpt1->psize2560;
  else if (p <= 3072) ++ rpt1->psize3072;
  else if (p <= 3584) ++ rpt1->psize3584;
  else if (p <= 4096) ++ rpt1->psize4096;
  else if (p <= 4608) ++ rpt1->psize4608;

  p = cur.dPkts64;

  if (p <= 1) ++ rpt1->fpsize1;
  else if (p <= 2) ++ rpt1->fpsize2;
  else if (p <= 4) ++ rpt1->fpsize4;
  else if (p <= 8) ++ rpt1->fpsize8;  
  else if (p <= 12) ++ rpt1->fpsize12;
  else if (p <= 16) ++ rpt1->fpsize16;
  else if (p <= 20) ++ rpt1->fpsize20;
  else if (p <= 24) ++ rpt1->fpsize24;
  else if (p <= 28) ++ rpt1->fpsize28;
  else if (p <= 32) ++ rpt1->fpsize32;
  else if (p <= 36) ++ rpt1->fpsize36;
  else if (p <= 40) ++ rpt1->fpsize40;
  else if (p <= 44) ++ rpt1->fpsize44;
  else if (p <= 48) ++ rpt1->fpsize48;
  else if (p <= 52) ++ rpt1->fpsize52;
  else if (p <= 60) ++ rpt1->fpsize60;
  else if (p <= 100) ++ rpt1->fpsize100;
  else if (p <= 200) ++ rpt1->fpsize200;
  else if (p <= 300) ++ rpt1->fpsize300;
  else if (p <= 400) ++ rpt1->fpsize400;
  else if (p <= 500) ++ rpt1->fpsize500;
  else if (p <= 600) ++ rpt1->fpsize600;
  else if (p <= 700) ++ rpt1->fpsize700;
  else if (p <= 800) ++ rpt1->fpsize800;
  else if (p <= 900) ++ rpt1->fpsize900;
  else ++ rpt1->fpsize_other;

  p = cur.dOctets64;

  if (p <= 32) ++ rpt1->fosize32;
  else if (p <= 64) ++ rpt1->fosize64;
  else if (p <= 128) ++ rpt1->fosize128;
  else if (p <= 256) ++ rpt1->fosize256;
  else if (p <= 512) ++ rpt1->fosize512;
  else if (p <= 1280) ++ rpt1->fosize1280;
  else if (p <= 2048) ++ rpt1->fosize2048;
  else if (p <= 2816) ++ rpt1->fosize2816;
  else if (p <= 3584) ++ rpt1->fosize3584;
  else if (p <= 4352) ++ rpt1->fosize4352;
  else if (p <= 5120) ++ rpt1->fosize5120;
  else if (p <= 5888) ++ rpt1->fosize5888;
  else if (p <= 6656) ++ rpt1->fosize6656;
  else if (p <= 7424) ++ rpt1->fosize7424;
  else if (p <= 8192) ++ rpt1->fosize8192;
  else if (p <= 8960) ++ rpt1->fosize8960;
  else if (p <= 9728) ++ rpt1->fosize9728;
  else if (p <= 10496) ++ rpt1->fosize10496;
  else if (p <= 11264) ++ rpt1->fosize11264;
  else if (p <= 12032) ++ rpt1->fosize12032;
  else if (p <= 12800) ++ rpt1->fosize12800;
  else if (p <= 13568) ++ rpt1->fosize13568;
  else if (p <= 14336) ++ rpt1->fosize14336;
  else if (p <= 15104) ++ rpt1->fosize15104;
  else if (p <= 15872) ++ rpt1->fosize15872;
  else ++ rpt1->fosize_other;

  p = cur.Last - cur.First;
  rpt1->time += p;
    
  if (p <= 10) ++ rpt1->ftime10;
  else if (p <= 50) ++ rpt1->ftime50;
  else if (p <= 100) ++ rpt1->ftime100;
  else if (p <= 200) ++ rpt1->ftime200;
  else if (p <= 500) ++ rpt1->ftime500;
  else if (p <= 1000) ++ rpt1->ftime1000;
  else if (p <= 2000) ++ rpt1->ftime2000;
  else if (p <= 3000) ++ rpt1->ftime3000;
  else if (p <= 4000) ++ rpt1->ftime4000;
  else if (p <= 5000) ++ rpt1->ftime5000;
  else if (p <= 6000) ++ rpt1->ftime6000;
  else if (p <= 7000) ++ rpt1->ftime7000;
  else if (p <= 8000) ++ rpt1->ftime8000;
  else if (p <= 9000) ++ rpt1->ftime9000;
  else if (p <= 10000) ++ rpt1->ftime10000;
  else if (p <= 12000) ++ rpt1->ftime12000;
  else if (p <= 14000) ++ rpt1->ftime14000;
  else if (p <= 16000) ++ rpt1->ftime16000;
  else if (p <= 18000) ++ rpt1->ftime18000;
  else if (p <= 20000) ++ rpt1->ftime20000;
  else if (p <= 22000) ++ rpt1->ftime22000;
  else if (p <= 24000) ++ rpt1->ftime24000;
  else if (p <= 26000) ++ rpt1->ftime26000;
  else if (p <= 28000) ++ rpt1->ftime28000;
  else if (p <= 30000) ++ rpt1->ftime30000;
  else ++ rpt1->ftime_other;

  return 0;

} /* ftstat_rpt_1_accum */

/* function: ftstat_rpt_1_calc
 *
 * Perform final calculations for rpt1
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_1_calc(struct ftstat_rpt *rpt)
{
  struct ftstat_rpt_1 *rpt1;
  u_int32 dif;

  rpt1 = rpt->data;

  STD_CALC;

  rpt1->time_real = rpt1->time_end - rpt1->time_start;
  dif = rpt1->end - rpt1->start;

  if (rpt->t_flows) {
    rpt1->aflowtime = rpt1->time / rpt->t_flows;
    rpt1->afs = rpt->t_octets / rpt->t_flows;
    rpt1->apf = rpt->t_packets / rpt->t_flows;
  }

  if (rpt->t_packets)
    rpt1->aps = rpt->t_octets / rpt->t_packets;
 
  if (dif) 
    rpt1->fps = (double)rpt->t_flows / (dif / 1000.0);

  if (rpt1->time_real)
    rpt1->fps_real = (double)rpt->t_flows / (double)rpt1->time_real;

  return 0;

} /* ftstat_rpt_1_calc */

/* function: ftstat_rpt_1_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_1_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{
  struct ftstat_rpt_1 *rpt1;
  char fmt_buf[1024];

  rpt1 = rpt->data;

  fprintf(fp, "# rec2: time_real,aflowtime,aps,afs,apf,fps,fps_real,");
  fprintf(fp, "psize32,psize64,psize96,psize128,psize160,psize192,psize224,psize256,psize288,psize320,psize352,psize384,psize416,psize448,psize480,psize512,psize544,psize576,psize1024,psize1536,psize2048,psize2560,psize3072,psize3584,>psize4096,psize4608,");
  fprintf(fp, "fpsize1,fpsize2,fpsize4,fpsize8,fpsize12,fpsize16,fpsize20,fpsize24,fpsize28,fpsize32,fpsize36,fpsize40,fpsize44,fpsize48,fpsize52,fpsize60,fpsize100,fpsize200,fpsize300,fpsize400,fpsize500,fpsize600,fpsize700,fpsize800,fpsize900,fpsize_other,");
  fprintf(fp, "fosize32,fosize64,fosize128,fosize256,fosize512,fosize1280,fosize2048,fosize2816,fosize3584,fosize4352,fosize5120,fosize5888,fosize6656,fosize7424,fosize8192,fosize8960,fosize9728,fosize10496,fosize11264,fosize12032,fosize12800,fosize13568,fosize14336,fosize15104,fosize15872,fosize_other,");
  fprintf(fp, "ftime10,ftime50,ftime100,ftime200,ftime500,ftime1000,ftime2000,ftime3000,ftime4000,ftime5000,ftime6000,ftime7000,ftime8000,ftime9000,ftime10000,ftime12000,ftime14000,ftime16000,ftime18000,ftime20000,ftime22000,ftime24000,ftime26000,ftime28000,ftime30000,ftime_other\n");

  fmt_uint64(fmt_buf, rpt1->time_real, FMT_JUST_LEFT);

  fprintf(fp, "%s,%f,%f,%f,%f,%f,%f,", fmt_buf, rpt1->aflowtime,
    rpt1->aps, rpt1->afs, rpt1->apf, rpt1->fps, rpt1->fps_real);

  fprintf(fp, "%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,",
    (double)rpt1->psize32 / (double)rpt->t_flows,
    (double)rpt1->psize64 / (double)rpt->t_flows,
    (double)rpt1->psize96 / (double)rpt->t_flows,
    (double)rpt1->psize128 / (double)rpt->t_flows,
    (double)rpt1->psize160 / (double)rpt->t_flows,
    (double)rpt1->psize192 / (double)rpt->t_flows,
    (double)rpt1->psize224 / (double)rpt->t_flows,
    (double)rpt1->psize256 / (double)rpt->t_flows,
    (double)rpt1->psize288 / (double)rpt->t_flows,
    (double)rpt1->psize320 / (double)rpt->t_flows,
    (double)rpt1->psize352 / (double)rpt->t_flows,
    (double)rpt1->psize384 / (double)rpt->t_flows,
    (double)rpt1->psize416 / (double)rpt->t_flows,
    (double)rpt1->psize448 / (double)rpt->t_flows,
    (double)rpt1->psize480 / (double)rpt->t_flows,
    (double)rpt1->psize512 / (double)rpt->t_flows,
    (double)rpt1->psize544 / (double)rpt->t_flows,
    (double)rpt1->psize576 / (double)rpt->t_flows,
    (double)rpt1->psize1024 / (double)rpt->t_flows,
    (double)rpt1->psize1536 / (double)rpt->t_flows,
    (double)rpt1->psize2048 / (double)rpt->t_flows,
    (double)rpt1->psize2560 / (double)rpt->t_flows,
    (double)rpt1->psize3072 / (double)rpt->t_flows,
    (double)rpt1->psize3584 / (double)rpt->t_flows,
    (double)rpt1->psize4096 / (double)rpt->t_flows,
    (double)rpt1->psize4608 / (double)rpt->t_flows);

  fprintf(fp, "%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,",
    (double)rpt1->fpsize1 / (double)rpt->t_flows,
    (double)rpt1->fpsize2 / (double)rpt->t_flows,
    (double)rpt1->fpsize4 / (double)rpt->t_flows,
    (double)rpt1->fpsize8 / (double)rpt->t_flows,
    (double)rpt1->fpsize12 / (double)rpt->t_flows,
    (double)rpt1->fpsize16 / (double)rpt->t_flows,
    (double)rpt1->fpsize20 / (double)rpt->t_flows,
    (double)rpt1->fpsize24 / (double)rpt->t_flows,
    (double)rpt1->fpsize28 / (double)rpt->t_flows,
    (double)rpt1->fpsize32 / (double)rpt->t_flows,
    (double)rpt1->fpsize36 / (double)rpt->t_flows,
    (double)rpt1->fpsize40 / (double)rpt->t_flows,
    (double)rpt1->fpsize44 / (double)rpt->t_flows,
    (double)rpt1->fpsize48 / (double)rpt->t_flows,
    (double)rpt1->fpsize52 / (double)rpt->t_flows,
    (double)rpt1->fpsize60 / (double)rpt->t_flows,
    (double)rpt1->fpsize100 / (double)rpt->t_flows,
    (double)rpt1->fpsize200 / (double)rpt->t_flows,
    (double)rpt1->fpsize300 / (double)rpt->t_flows,
    (double)rpt1->fpsize400 / (double)rpt->t_flows,
    (double)rpt1->fpsize500 / (double)rpt->t_flows,
    (double)rpt1->fpsize600 / (double)rpt->t_flows,
    (double)rpt1->fpsize700 / (double)rpt->t_flows,
    (double)rpt1->fpsize800 / (double)rpt->t_flows,
    (double)rpt1->fpsize900 / (double)rpt->t_flows,
    (double)rpt1->fpsize_other / (double)rpt->t_flows);

  fprintf(fp, "%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,",
    (double)rpt1->fosize32 / (double)rpt->t_flows,
    (double)rpt1->fosize64 / (double)rpt->t_flows,
    (double)rpt1->fosize128 / (double)rpt->t_flows,
    (double)rpt1->fosize256 / (double)rpt->t_flows,
    (double)rpt1->fosize512 / (double)rpt->t_flows,
    (double)rpt1->fosize1280 / (double)rpt->t_flows,
    (double)rpt1->fosize2048 / (double)rpt->t_flows,
    (double)rpt1->fosize2816 / (double)rpt->t_flows,
    (double)rpt1->fosize3584 / (double)rpt->t_flows,
    (double)rpt1->fosize4352 / (double)rpt->t_flows,
    (double)rpt1->fosize5120 / (double)rpt->t_flows,
    (double)rpt1->fosize5888 / (double)rpt->t_flows,
    (double)rpt1->fosize6656 / (double)rpt->t_flows,
    (double)rpt1->fosize7424 / (double)rpt->t_flows,
    (double)rpt1->fosize8192 / (double)rpt->t_flows,
    (double)rpt1->fosize8960 / (double)rpt->t_flows,
    (double)rpt1->fosize9728 / (double)rpt->t_flows,
    (double)rpt1->fosize10496 / (double)rpt->t_flows,
    (double)rpt1->fosize11264 / (double)rpt->t_flows,
    (double)rpt1->fosize12032 / (double)rpt->t_flows,
    (double)rpt1->fosize12800 / (double)rpt->t_flows,
    (double)rpt1->fosize13568 / (double)rpt->t_flows,
    (double)rpt1->fosize14336 / (double)rpt->t_flows,
    (double)rpt1->fosize15104 / (double)rpt->t_flows,
    (double)rpt1->fosize15872 / (double)rpt->t_flows,
    (double)rpt1->fosize_other / (double)rpt->t_flows);

  fprintf(fp, "%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f\n",
    (double)rpt1->ftime10 / (double)rpt->t_flows,
    (double)rpt1->ftime50 / (double)rpt->t_flows,
    (double)rpt1->ftime100 / (double)rpt->t_flows,
    (double)rpt1->ftime200 / (double)rpt->t_flows,
    (double)rpt1->ftime500 / (double)rpt->t_flows,
    (double)rpt1->ftime1000 / (double)rpt->t_flows,
    (double)rpt1->ftime2000 / (double)rpt->t_flows,
    (double)rpt1->ftime3000 / (double)rpt->t_flows,
    (double)rpt1->ftime4000 / (double)rpt->t_flows,
    (double)rpt1->ftime5000 / (double)rpt->t_flows,
    (double)rpt1->ftime6000 / (double)rpt->t_flows,
    (double)rpt1->ftime7000 / (double)rpt->t_flows,
    (double)rpt1->ftime8000 / (double)rpt->t_flows,
    (double)rpt1->ftime9000 / (double)rpt->t_flows,
    (double)rpt1->ftime10000 / (double)rpt->t_flows,
    (double)rpt1->ftime12000 / (double)rpt->t_flows,
    (double)rpt1->ftime14000 / (double)rpt->t_flows,
    (double)rpt1->ftime16000 / (double)rpt->t_flows,
    (double)rpt1->ftime18000 / (double)rpt->t_flows,
    (double)rpt1->ftime20000 / (double)rpt->t_flows,
    (double)rpt1->ftime22000 / (double)rpt->t_flows,
    (double)rpt1->ftime24000 / (double)rpt->t_flows,
    (double)rpt1->ftime26000 / (double)rpt->t_flows,
    (double)rpt1->ftime28000 / (double)rpt->t_flows,
    (double)rpt1->ftime30000 / (double)rpt->t_flows,
    (double)rpt1->ftime_other / (double)rpt->t_flows);


  return 0;

} /* ftstat_rpt_1_dump */


/* function: ftstat_rpt_1_free
 *
 * Free data structures for report allocated by ftstat_rpt_1_new
 *
 */
void ftstat_rpt_1_free(struct ftstat_rpt_1 *rpt1)
{
  if (rpt1)
    free(rpt1);
} /* ftstat_rpt_1_free */


/* function: ftstat_rpt_2_new
 *
 * Allocate and initialize data structures for rpt 2.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_2 *ftstat_rpt_2_new(struct ftstat_rpt *rpt)
{
  struct ftstat_rpt_2 *rpt2;

  if (!(rpt2 = (struct ftstat_rpt_2*)malloc(sizeof (*rpt2)))) {
    fterr_warnx("malloc(rpt2): failed");
    return (struct ftstat_rpt_2*)0L;
  }

  bzero(rpt2, sizeof *rpt2);

  return rpt2;

} /* ftstat_rpt_2_new */


/* function: ftstat_rpt_2_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_2_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{
  struct fts3rec_all2 cur;
  u_int32 duration_tmp;
  double pps_tmp, bps_tmp;

  STD_ACCUM;

  return 0;
} /* ftstat_rpt_2_accum */

/* function: ftstat_rpt_2_calc
 *
 * Perform final calculations for rpt2
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_2_calc(struct ftstat_rpt *rpt)
{

  STD_CALC;

  return 0;

} /* ftstat_rpt_2_calc */


/* function: ftstat_rpt_2_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_2_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{
  return 0;
} /* ftstat_rpt_2_dump */


/* function: ftstat_rpt_2_free
 *
 * Free data structures for report allocated by ftstat_rpt_2_new
 *
 */
void ftstat_rpt_2_free(struct ftstat_rpt_2 *rpt2)
{
  if (rpt2)
    free(rpt2);
} /* ftstat_rpt_2_free */


/* function: ftstat_rpt_3_new
 *
 * Allocate and initialize data structures for rpt 3.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_3 *ftstat_rpt_3_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_3, rpt3, 65536, ftchash_rec_c32, 4, 65536);

} /* ftstat_rpt_3_new */


/* function: ftstat_rpt_3_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_3_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_3, rpt3, ftchash_rec_c32, ftch_recc32,
    ftch_recc32p);

  ftch_recc32.c32 = cur.dOctets64 / cur.dPkts64;

  hash = (ftch_recc32.c32>>16) ^ (ftch_recc32.c32 & 0xFFFF);

  STD_ACCUM_HASH2(rpt3, ftch_recc32, ftch_recc32p);

  return 0;

} /* ftstat_rpt_3_accum */

/* function: ftstat_rpt_3_calc
 *
 * Perform final calculations for rpt3
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_3_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_3, rpt3, ftchash_rec_c32, ftch_recc32);

} /* ftstat_rpt_3_calc */

/* function: ftstat_rpt_3_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_3_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1(ftstat_rpt_3, rpt3, chash_c32_dump, (char*)0L,
    "packet size/flow", "", "", "", "", "", "");

} /* ftstat_rpt_3_dump */


/* function: ftstat_rpt_3_free
 *
 * Free data structures for report allocated by ftstat_rpt_3_new
 *
 */
void ftstat_rpt_3_free(struct ftstat_rpt_3 *rpt3)
{

  STD_FREE_HASH(rpt3);

} /* ftstat_rpt_3_free */


/* function: ftstat_rpt_4_new
 *
 * Allocate and initialize data structures for rpt 4.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_4 *ftstat_rpt_4_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_4, rpt4, 65536, ftchash_rec_c64, 8, 65536);

} /* ftstat_rpt_4_new */


/* function: ftstat_rpt_4_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_4_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_4, rpt4, ftchash_rec_c64, ftch_recc64,
    ftch_recc64p);

  ftch_recc64.c64 = cur.dOctets64;
     
  hash = ftch_recc64.c64 & 0x000000FFFFFFLL; 
  hash = (hash>>16) ^ (hash & 0xFFFF);

  STD_ACCUM_HASH2(rpt4, ftch_recc64, ftch_recc64p);
  
  return 0;

} /* ftstat_rpt_4_accum */

/* function: ftstat_rpt_4_calc
 *
 * Perform final calculations for rpt4
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_4_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_4, rpt4, ftchash_rec_c64, ftch_recc64);

} /* ftstat_rpt_4_calc */

/* function: ftstat_rpt_4_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_4_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH0(ftstat_rpt_4, rpt4, chash_c64_dump,
    "octets/flow", "", "", "", "", "", "");

} /* ftstat_rpt_4_dump */


/* function: ftstat_rpt_4_free
 *
 * Free data structures for report allocated by ftstat_rpt_4_new
 *
 */
void ftstat_rpt_4_free(struct ftstat_rpt_4 *rpt4)
{

  STD_FREE_HASH(rpt4);

} /* ftstat_rpt_4_free */


/* function: ftstat_rpt_5_new
 *
 * Allocate and initialize data structures for rpt 5.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_5 *ftstat_rpt_5_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_5, rpt5, 65536, ftchash_rec_c64, 8, 65536);

} /* ftstat_rpt_5_new */


/* function: ftstat_rpt_5_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_5_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_5, rpt5, ftchash_rec_c64, ftch_recc64,
    ftch_recc64p);

  ftch_recc64.c64 = cur.dPkts64;
  
  hash = ftch_recc64.c64 & 0x000000FFFFFFLL; 
  hash = (hash>>16) ^ (hash & 0xFFFF);

  STD_ACCUM_HASH2(rpt5, ftch_recc64, ftch_recc64p);
  
  return 0;

} /* ftstat_rpt_5_accum */

/* function: ftstat_rpt_5_calc
 *
 * Perform final calculations for rpt5
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_5_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_5, rpt5, ftchash_rec_c64, ftch_recc64);

} /* ftstat_rpt_5_calc */

/* function: ftstat_rpt_5_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_5_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH0(ftstat_rpt_5, rpt5, chash_c64_dump,
    "packets/flow", "", "", "", "", "", "");

} /* ftstat_rpt_5_dump */


/* function: ftstat_rpt_5_free
 *
 * Free data structures for report allocated by ftstat_rpt_5_new
 *
 */
void ftstat_rpt_5_free(struct ftstat_rpt_5 *rpt5)
{

  STD_FREE_HASH(rpt5);

} /* ftstat_rpt_5_free */


/* function: ftstat_rpt_6_new
 *
 * Allocate and initialize data structures for rpt 6.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_6 *ftstat_rpt_6_new(struct ftstat_rpt *rpt)
{

  STD_NEW_BUCKET(ftstat_rpt_6, rpt6, 65536, rpt);

} /* ftstat_rpt_6_new */


/* function: ftstat_rpt_6_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_6_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_BUCKET1(ftstat_rpt_6, rpt6);

  FT_RECGET_SRCPORT(cur,rec,*fo);

  STD_ACCUM_BUCKET2(rpt6->bucket, cur.srcport);

  return 0;

} /* ftstat_rpt_6_accum */

/* function: ftstat_rpt_6_calc
 *
 * Perform final calculations for rpt6
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_6_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_BUCKET(ftstat_rpt_6, rpt6, 65536);

} /* ftstat_rpt_6_calc */

/* function: ftstat_rpt_6_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_6_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_BUCKET(ftstat_rpt_6, rpt6, 65536, FT_PATH_SYM_TCP_PORT,
    "ip-source-port", "", "", "", "", "", "");

} /* ftstat_rpt_6_dump */


/* function: ftstat_rpt_6_free
 *
 * Free data structures for report allocated by ftstat_rpt_6_new
 *
 */
void ftstat_rpt_6_free(struct ftstat_rpt_6 *rpt6)
{

  STD_FREE_BUCKET(rpt6);

} /* ftstat_rpt_6_free */


/* function: ftstat_rpt_7_new
 *
 * Allocate and initialize data structures for rpt 7.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_7 *ftstat_rpt_7_new(struct ftstat_rpt *rpt)
{

  STD_NEW_BUCKET(ftstat_rpt_7, rpt7, 65536, rpt);

} /* ftstat_rpt_7_new */


/* function: ftstat_rpt_7_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_7_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_BUCKET1(ftstat_rpt_7, rpt7);

  FT_RECGET_DSTPORT(cur,rec,*fo);

  STD_ACCUM_BUCKET2(rpt7->bucket, cur.dstport);

  return 0;

} /* ftstat_rpt_7_accum */

/* function: ftstat_rpt_7_calc
 *
 * Perform final calculations for rpt7
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_7_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_BUCKET(ftstat_rpt_7, rpt7, 65536);

} /* ftstat_rpt_7_calc */

/* function: ftstat_rpt_7_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_7_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_BUCKET(ftstat_rpt_7, rpt7, 65536, FT_PATH_SYM_TCP_PORT,
    "ip-destination-port", "", "", "", "", "", "");

} /* ftstat_rpt_7_dump */


/* function: ftstat_rpt_7_free
 *
 * Free data structures for report allocated by ftstat_rpt_7_new
 *
 */
void ftstat_rpt_7_free(struct ftstat_rpt_7 *rpt7)
{
} /* ftstat_rpt_7_free */


/* function: ftstat_rpt_8_new
 *
 * Allocate and initialize data structures for rpt 8.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_8 *ftstat_rpt_8_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_8, rpt8, 65536, ftchash_rec_c162, 4, 65536);

} /* ftstat_rpt_8_new */


/* function: ftstat_rpt_8_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_8_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_8, rpt8, ftchash_rec_c162, ftch_recc162,
    ftch_recc162p);

  FT_RECGET_DSTPORT(cur,rec,*fo);
  FT_RECGET_SRCPORT(cur,rec,*fo);

  ftch_recc162.c16a = cur.srcport;
  ftch_recc162.c16b = cur.dstport;
  
  hash = (ftch_recc162.c16a>>16) ^ (ftch_recc162.c16a & 0xFFFF) ^
    (ftch_recc162.c16b>>16) ^ (ftch_recc162.c16b & 0xFFFF);


  STD_ACCUM_HASH2(rpt8, ftch_recc162, ftch_recc162p);

  return 0;
   
} /* ftstat_rpt_8_accum */

/* function: ftstat_rpt_8_calc
 *
 * Perform final calculations for rpt8
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_8_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_8, rpt8, ftchash_rec_c162, ftch_recc162);

} /* ftstat_rpt_8_calc */

/* function: ftstat_rpt_8_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_8_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH2(ftstat_rpt_8, rpt8, chash_c162_dump,
    FT_PATH_SYM_TCP_PORT, FT_PATH_SYM_TCP_PORT,
    "", "ip-source-port", "ip-destination-port", "", "", "", "");

} /* ftstat_rpt_8_dump */


/* function: ftstat_rpt_8_free
 *
 * Free data structures for report allocated by ftstat_rpt_8_new
 *
 */
void ftstat_rpt_8_free(struct ftstat_rpt_8 *rpt8)
{

  STD_FREE_HASH(rpt8);

} /* ftstat_rpt_8_free */


/* function: ftstat_rpt_9_new
 *
 * Allocate and initialize data structures for rpt 9.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_9 *ftstat_rpt_9_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_9, rpt9, 65536, ftchash_rec_c64, 8, 65536);

} /* ftstat_rpt_9_new */


/* function: ftstat_rpt_9_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_9_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_9, rpt9, ftchash_rec_c64, ftch_recc64,
    ftch_recc64p);

  ftch_recc64.c64 = (duration_tmp) ?
    (double)cur.dOctets64*8/((double)(duration_tmp)/1000.0) : 0;

  hash = ftch_recc64.c64 & 0x000000FFFFFFLL;
  hash = (hash>>16) ^ (hash & 0xFFFF);

  STD_ACCUM_HASH2(rpt9, ftch_recc64, ftch_recc64p);

  return 0;
   
} /* ftstat_rpt_9_accum */

/* function: ftstat_rpt_9_calc
 *
 * Perform final calculations for rpt9
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_9_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_9, rpt9, ftchash_rec_c64, ftch_recc64);

} /* ftstat_rpt_9_calc */


/* function: ftstat_rpt_9_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_9_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH0(ftstat_rpt_9, rpt9, chash_c64_dump,
    "bps/flow", "", "", "", "", "", "");

} /* ftstat_rpt_9_dump */


/* function: ftstat_rpt_9_free
 *
 * Free data structures for report allocated by ftstat_rpt_9_new
 *
 */
void ftstat_rpt_9_free(struct ftstat_rpt_9 *rpt9)
{

  STD_FREE_HASH(rpt9);

} /* ftstat_rpt_9_free */


/* function: ftstat_rpt_10_new
 *
 * Allocate and initialize data structures for rpt 10.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_10 *ftstat_rpt_10_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_10, rpt10, 65536, ftchash_rec_c64, 8, 65536);

} /* ftstat_rpt_10_new */


/* function: ftstat_rpt_10_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_10_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_10, rpt10, ftchash_rec_c64, ftch_recc64,
    ftch_recc64p);

  ftch_recc64.c64 = (duration_tmp) ?
    (double)cur.dPkts64/((double)(duration_tmp)/1000.0) : 0;

  hash = ftch_recc64.c64 & 0x000000FFFFFFLL;
  hash = (hash>>16) ^ (hash & 0xFFFF);

  STD_ACCUM_HASH2(rpt10, ftch_recc64, ftch_recc64p);
  
  return 0;
   
} /* ftstat_rpt_10_accum */

/* function: ftstat_rpt_10_calc
 *
 * Perform final calculations for rpt10
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_10_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_10, rpt10, ftchash_rec_c64, ftch_recc64);

} /* ftstat_rpt_10_calc */

/* function: ftstat_rpt_10_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_10_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH0(ftstat_rpt_10, rpt10, chash_c64_dump,
    "pps/flow", "", "", "", "", "", "");

} /* ftstat_rpt_10_dump */


/* function: ftstat_rpt_10_free
 *
 * Free data structures for report allocated by ftstat_rpt_10_new
 *
 */
void ftstat_rpt_10_free(struct ftstat_rpt_10 *rpt10)
{

  STD_FREE_HASH(rpt10);

} /* ftstat_rpt_10_free */


/* function: ftstat_rpt_11_new
 *
 * Allocate and initialize data structures for rpt 11.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_11 *ftstat_rpt_11_new(struct ftstat_rpt *rpt)
{

  STD_NEW_BUCKET(ftstat_rpt_11, rpt11, 7, rpt);

} /* ftstat_rpt_11_new */


/* function: ftstat_rpt_11_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_11_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{
  u_int16 tmp;

  STD_ACCUM_BUCKET1(ftstat_rpt_11, rpt11);

  FT_RECGET_DSTADDR(cur,rec,*fo);

  if ((cur.dstaddr & 0xf0000000) == 0xf0000000)
    tmp = 5; /* Class E Reserved */
  else if ((cur.dstaddr & 0xff000000) == 0xe8000000)
    tmp = 4; /* Class D Multicast-SSM */
  else if ((cur.dstaddr & 0xf0000000) == 0xe0000000)
    tmp = 3; /* Class D Multicast-ASM */
  else if ((cur.dstaddr & 0xe0000000) == 0xc0000000)
    tmp = 2; /* Class C Unicast */
  else if ((cur.dstaddr & 0xc0000000) == 0x80000000)
    tmp = 1; /* Class B Unicast */
  else if ((cur.dstaddr & 0x80000000) == 0x00000000)
    tmp = 0; /* Class A Unicast */
  else
    tmp = 6; /* not reached */
  
  STD_ACCUM_BUCKET2(rpt11->bucket, tmp);

  return 0;

} /* ftstat_rpt_11_accum */

/* function: ftstat_rpt_11_calc
 *
 * Perform final calculations for rpt11
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_11_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_BUCKET(ftstat_rpt_11, rpt11, 7);

} /* ftstat_rpt_11_calc */

/* function: ftstat_rpt_11_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_11_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_BUCKET(ftstat_rpt_11, rpt11, 7, FT_PATH_SYM_IP_TYPE,
    "ip-destination-address-type", "", "", "", "", "", "");

} /* ftstat_rpt_11_dump */


/* function: ftstat_rpt_11_free
 *
 * Free data structures for report allocated by ftstat_rpt_11_new
 *
 */
void ftstat_rpt_11_free(struct ftstat_rpt_11 *rpt11)
{

  STD_FREE_BUCKET(rpt11);

} /* ftstat_rpt_11_free */


/* function: ftstat_rpt_12_new
 *
 * Allocate and initialize data structures for rpt 12.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_12 *ftstat_rpt_12_new(struct ftstat_rpt *rpt)
{

  STD_NEW_BUCKET(ftstat_rpt_12, rpt12, 256, rpt);

} /* ftstat_rpt_12_new */


/* function: ftstat_rpt_12_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_12_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_BUCKET1(ftstat_rpt_12, rpt12);

  FT_RECGET_PROT(cur,rec,*fo);

  STD_ACCUM_BUCKET2(rpt12->bucket, cur.prot);

  return 0;

} /* ftstat_rpt_12_accum */

/* function: ftstat_rpt_12_calc
 *
 * Perform final calculations for rpt12
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_12_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_BUCKET(ftstat_rpt_12, rpt12, 256);

} /* ftstat_rpt_12_calc */

/* function: ftstat_rpt_12_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_12_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_BUCKET(ftstat_rpt_12, rpt12, 256, FT_PATH_SYM_IP_PROT,
    "ip-protocol", "", "", "", "", "", "");
} /* ftstat_rpt_12_dump */


/* function: ftstat_rpt_12_free
 *
 * Free data structures for report allocated by ftstat_rpt_12_new
 *
 */
void ftstat_rpt_12_free(struct ftstat_rpt_12 *rpt12)
{

  STD_FREE_BUCKET(rpt12);

} /* ftstat_rpt_12_free */


/* function: ftstat_rpt_13_new
 *
 * Allocate and initialize data structures for rpt 13.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_13 *ftstat_rpt_13_new(struct ftstat_rpt *rpt)
{

  STD_NEW_BUCKET(ftstat_rpt_13, rpt13, 256, rpt);

} /* ftstat_rpt_13_new */


/* function: ftstat_rpt_13_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_13_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_BUCKET1(ftstat_rpt_13, rpt13);

  FT_RECGET_TOS(cur,rec,*fo);

  STD_ACCUM_BUCKET2(rpt13->bucket, cur.tos);

  return 0;

} /* ftstat_rpt_13_accum */

/* function: ftstat_rpt_13_calc
 *
 * Perform final calculations for rpt13
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_13_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_BUCKET(ftstat_rpt_13, rpt13, 256);

} /* ftstat_rpt_13_calc */

/* function: ftstat_rpt_13_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_13_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_BUCKET(ftstat_rpt_13, rpt13, 256, (char*)0L,
    "ip-tos", "", "", "", "", "", "");

} /* ftstat_rpt_13_dump */


/* function: ftstat_rpt_13_free
 *
 * Free data structures for report allocated by ftstat_rpt_13_new
 *
 */
void ftstat_rpt_13_free(struct ftstat_rpt_13 *rpt13)
{

  STD_FREE_BUCKET(rpt13);

} /* ftstat_rpt_13_free */


/* function: ftstat_rpt_14_new
 *
 * Allocate and initialize data structures for rpt 14.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_14 *ftstat_rpt_14_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_14, rpt14, 65536, ftchash_rec_c32, 4, 65536);

} /* ftstat_rpt_14_new */


/* function: ftstat_rpt_14_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_14_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_14, rpt14, ftchash_rec_c32, ftch_recc32,
    ftch_recc32p);

  FT_RECGET_NEXTHOP(cur,rec,*fo);

  ftch_recc32.c32 = cur.nexthop;

  hash = (ftch_recc32.c32>>16) ^ (ftch_recc32.c32 & 0xFFFF);

  STD_ACCUM_HASH2(rpt14, ftch_recc32, ftch_recc32p);

  return 0;
   
} /* ftstat_rpt_14_accum */

/* function: ftstat_rpt_14_calc
 *
 * Perform final calculations for rpt14
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_14_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_14, rpt14, ftchash_rec_c32, ftch_recc32);

} /* ftstat_rpt_14_calc */

/* function: ftstat_rpt_14_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_14_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH0(ftstat_rpt_14, rpt14, chash_ip_dump,
    "ip-next-hop-address", "", "", "", "", "", "");

} /* ftstat_rpt_14_dump */


/* function: ftstat_rpt_14_free
 *
 * Free data structures for report allocated by ftstat_rpt_14_new
 *
 */
void ftstat_rpt_14_free(struct ftstat_rpt_14 *rpt14)
{

  STD_FREE_HASH(rpt14);

} /* ftstat_rpt_14_free */


/* function: ftstat_rpt_15_new
 *
 * Allocate and initialize data structures for rpt 15.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_15 *ftstat_rpt_15_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_15, rpt15, 65536, ftchash_rec_prefix, 5, 65536);

} /* ftstat_rpt_15_new */


/* function: ftstat_rpt_15_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_15_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_15, rpt15, ftchash_rec_prefix, ftch_recprefix,
    ftch_recprefixp);

  FT_RECGET_SRCADDR(cur,rec,*fo);
 
  ftch_recprefix.prefix = cur.srcaddr;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix.mask = cur.src_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK)
    ftch_recprefix.prefix &= ipv4_len2mask(ftch_recprefix.mask);

  hash = (ftch_recprefix.prefix>>16) ^ (ftch_recprefix.prefix & 0xFFFF);
  hash = hash ^ (ftch_recprefix.mask);

  STD_ACCUM_HASH2(rpt15, ftch_recprefix, ftch_recprefixp);

  return 0;
   
} /* ftstat_rpt_15_accum */

/* function: ftstat_rpt_15_calc
 *
 * Perform final calculations for rpt15
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_15_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_15, rpt15, ftchash_rec_prefix, ftch_recprefix);

} /* ftstat_rpt_15_calc */

/* function: ftstat_rpt_15_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_15_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH0P(ftstat_rpt_15, rpt15, chash_prefix_dump,
    FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK,
    "ip-source-address", "", "", "", "", "", "");

} /* ftstat_rpt_15_dump */


/* function: ftstat_rpt_15_free
 *
 * Free data structures for report allocated by ftstat_rpt_15_new
 *
 */
void ftstat_rpt_15_free(struct ftstat_rpt_15 *rpt15)
{

  STD_FREE_HASH(rpt15);

} /* ftstat_rpt_15_free */


/* function: ftstat_rpt_16_new
 *
 * Allocate and initialize data structures for rpt 16.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_16 *ftstat_rpt_16_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_16, rpt16, 65536, ftchash_rec_prefix, 5, 65536);

} /* ftstat_rpt_16_new */


/* function: ftstat_rpt_16_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_16_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_16, rpt16, ftchash_rec_prefix, ftch_recprefix,
    ftch_recprefixp);

  FT_RECGET_DSTADDR(cur,rec,*fo);

  ftch_recprefix.prefix = cur.dstaddr;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix.mask = cur.dst_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK)
    ftch_recprefix.prefix &= ipv4_len2mask(ftch_recprefix.mask);

  hash = (ftch_recprefix.prefix>>16) ^ (ftch_recprefix.prefix & 0xFFFF);
  hash = hash ^ (ftch_recprefix.mask);

  STD_ACCUM_HASH2(rpt16, ftch_recprefix, ftch_recprefixp);

  return 0;
   
} /* ftstat_rpt_16_accum */

/* function: ftstat_rpt_16_calc
 *
 * Perform final calculations for rpt16
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_16_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_16, rpt16, ftchash_rec_prefix, ftch_recprefix);

} /* ftstat_rpt_16_calc */

/* function: ftstat_rpt_16_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_16_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH0P(ftstat_rpt_16, rpt16, chash_prefix_dump,
    FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK,
    "ip-destination-address", "", "", "", "", "", "");

} /* ftstat_rpt_16_dump */


/* function: ftstat_rpt_16_free
 *
 * Free data structures for report allocated by ftstat_rpt_16_new
 *
 */
void ftstat_rpt_16_free(struct ftstat_rpt_16 *rpt16)
{

  STD_FREE_HASH(rpt16);

} /* ftstat_rpt_16_free */


/* function: ftstat_rpt_17_new
 *
 * Allocate and initialize data structures for rpt 17.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_17 *ftstat_rpt_17_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_17, rpt17, 65536, ftchash_rec_prefix2, 16, 65536);

} /* ftstat_rpt_17_new */


/* function: ftstat_rpt_17_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_17_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_17, rpt17, ftchash_rec_prefix2, ftch_recprefix2,
    ftch_recprefix2p);

  FT_RECGET_DSTADDR(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);

  ftch_recprefix2.src_prefix = cur.srcaddr;
  ftch_recprefix2.dst_prefix = cur.dstaddr;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix2.src_mask = cur.src_mask;
  }

  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix2.dst_mask = cur.dst_mask;
  }
  
  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK) {
    ftch_recprefix2.src_prefix &= ipv4_len2mask(ftch_recprefix2.src_mask);
  }

  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK) {
    ftch_recprefix2.dst_prefix &= ipv4_len2mask(ftch_recprefix2.dst_mask);
  }

  hash = (ftch_recprefix2.src_prefix>>16)^
          (ftch_recprefix2.src_prefix & 0xFFFF)^
          (ftch_recprefix2.dst_prefix>>16)^
          (ftch_recprefix2.dst_prefix & 0xFFFF)^
          (ftch_recprefix2.src_mask)^
          (u_int32)(ftch_recprefix2.dst_mask<<8);

  STD_ACCUM_HASH2(rpt17, ftch_recprefix2, ftch_recprefix2p);

  return 0;
   
} /* ftstat_rpt_17_accum */

/* function: ftstat_rpt_17_calc
 *
 * Perform final calculations for rpt17
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_17_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_17, rpt17, ftchash_rec_prefix2, ftch_recprefix2);

} /* ftstat_rpt_17_calc */

/* function: ftstat_rpt_17_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_17_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH0(ftstat_rpt_17, rpt17, chash_prefix2_dump,
    "", "ip-source-address", "ip-destination-address", "", "", "", "");

} /* ftstat_rpt_17_dump */


/* function: ftstat_rpt_17_free
 *
 * Free data structures for report allocated by ftstat_rpt_17_new
 *
 */
void ftstat_rpt_17_free(struct ftstat_rpt_17 *rpt17)
{
} /* ftstat_rpt_17_free */


/* function: ftstat_rpt_18_new
 *
 * Allocate and initialize data structures for rpt 18.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_18 *ftstat_rpt_18_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_18, rpt18, 65536, ftchash_rec_c32, 4, 65536);

} /* ftstat_rpt_18_new */


/* function: ftstat_rpt_18_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_18_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_18, rpt18, ftchash_rec_c32, ftch_recc32,
    ftch_recc32p);

  FT_RECGET_EXADDR(cur,rec,*fo);

  ftch_recc32.c32 = cur.exaddr;
  
  hash = (ftch_recc32.c32>>16) ^ (ftch_recc32.c32 & 0xFFFF);

  STD_ACCUM_HASH2(rpt18, ftch_recc32, ftch_recc32p);
  
  return 0;
   
} /* ftstat_rpt_18_accum */

/* function: ftstat_rpt_18_calc
 *
 * Perform final calculations for rpt18
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_18_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_18, rpt18, ftchash_rec_c32, ftch_recc32);

} /* ftstat_rpt_18_calc */

/* function: ftstat_rpt_18_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_18_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH0(ftstat_rpt_18, rpt18, chash_ip_dump,
    "ip-exporter-address", "", "", "", "", "", "");

} /* ftstat_rpt_18_dump */


/* function: ftstat_rpt_18_free
 *
 * Free data structures for report allocated by ftstat_rpt_18_new
 *
 */
void ftstat_rpt_18_free(struct ftstat_rpt_18 *rpt18)
{

  STD_FREE_HASH(rpt18);

} /* ftstat_rpt_18_free */


/* function: ftstat_rpt_19_new
 *
 * Allocate and initialize data structures for rpt 19.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_19 *ftstat_rpt_19_new(struct ftstat_rpt *rpt)
{

  STD_NEW_BUCKET(ftstat_rpt_19, rpt19, 65536, rpt);

} /* ftstat_rpt_19_new */


/* function: ftstat_rpt_19_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_19_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_BUCKET1(ftstat_rpt_19, rpt19);

  FT_RECGET_INPUT(cur,rec,*fo);

  STD_ACCUM_BUCKET2(rpt19->bucket, cur.input);

  return 0;

} /* ftstat_rpt_19_accum */

/* function: ftstat_rpt_19_calc
 *
 * Perform final calculations for rpt19
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_19_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_BUCKET(ftstat_rpt_19, rpt19, 65536);

} /* ftstat_rpt_19_calc */

/* function: ftstat_rpt_19_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_19_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_BUCKET(ftstat_rpt_19, rpt19, 65536, (char*)0L,
    "input-interface", "", "", "", "", "", "");

} /* ftstat_rpt_19_dump */


/* function: ftstat_rpt_19_free
 *
 * Free data structures for report allocated by ftstat_rpt_19_new
 *
 */
void ftstat_rpt_19_free(struct ftstat_rpt_19 *rpt19)
{

  STD_FREE_BUCKET(rpt19);

} /* ftstat_rpt_19_free */


/* function: ftstat_rpt_20_new
 *
 * Allocate and initialize data structures for rpt 20.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_20 *ftstat_rpt_20_new(struct ftstat_rpt *rpt)
{

  STD_NEW_BUCKET(ftstat_rpt_20, rpt20, 65536, rpt);

} /* ftstat_rpt_20_new */


/* function: ftstat_rpt_20_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_20_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_BUCKET1(ftstat_rpt_20, rpt20);

  FT_RECGET_OUTPUT(cur,rec,*fo);

  STD_ACCUM_BUCKET2(rpt20->bucket, cur.output);

  return 0;

} /* ftstat_rpt_20_accum */

/* function: ftstat_rpt_20_calc
 *
 * Perform final calculations for rpt20
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_20_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_BUCKET(ftstat_rpt_20, rpt20, 65536);

} /* ftstat_rpt_20_calc */

/* function: ftstat_rpt_20_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_20_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_BUCKET(ftstat_rpt_20, rpt20, 65536, (char*)0L,
    "output-interface", "", "", "", "", "", "");

} /* ftstat_rpt_20_dump */


/* function: ftstat_rpt_20_free
 *
 * Free data structures for report allocated by ftstat_rpt_20_new
 *
 */
void ftstat_rpt_20_free(struct ftstat_rpt_20 *rpt20)
{
} /* ftstat_rpt_20_free */


/* function: ftstat_rpt_21_new
 *
 * Allocate and initialize data structures for rpt 21.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_21 *ftstat_rpt_21_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_21, rpt21, 65536, ftchash_rec_c162, 4, 65536);

} /* ftstat_rpt_21_new */


/* function: ftstat_rpt_21_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_21_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_21, rpt21, ftchash_rec_c162, ftch_recc162,
    ftch_recc162p);

  FT_RECGET_INPUT(cur,rec,*fo);
  FT_RECGET_OUTPUT(cur,rec,*fo);

  ftch_recc162.c16a = cur.input;
  ftch_recc162.c16b = cur.output;

  hash = (ftch_recc162.c16a>>16) ^ (ftch_recc162.c16a & 0xFFFF) ^
    (ftch_recc162.c16b>>16) ^ (ftch_recc162.c16b & 0xFFFF);

  STD_ACCUM_HASH2(rpt21, ftch_recc162, ftch_recc162p);
 
  return 0;
   
} /* ftstat_rpt_21_accum */

/* function: ftstat_rpt_21_calc
 *
 * Perform final calculations for rpt21
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_21_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_21, rpt21, ftchash_rec_c162, ftch_recc162);

} /* ftstat_rpt_21_calc */

/* function: ftstat_rpt_21_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_21_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH2(ftstat_rpt_21, rpt21, chash_c162_dump,
    (char*)0L, (char*)0L,
    "", "input-interface", "output-interface", "", "", "", "");

} /* ftstat_rpt_21_dump */


/* function: ftstat_rpt_21_free
 *
 * Free data structures for report allocated by ftstat_rpt_21_new
 *
 */
void ftstat_rpt_21_free(struct ftstat_rpt_21 *rpt21)
{

  STD_FREE_HASH(rpt21);

} /* ftstat_rpt_21_free */


/* function: ftstat_rpt_22_new
 *
 * Allocate and initialize data structures for rpt 22.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_22 *ftstat_rpt_22_new(struct ftstat_rpt *rpt)
{

  STD_NEW_BUCKET(ftstat_rpt_22, rpt22, 65536, rpt);

} /* ftstat_rpt_22_new */


/* function: ftstat_rpt_22_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_22_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_BUCKET1(ftstat_rpt_22, rpt22);
  
  FT_RECGET_SRC_AS(cur,rec,*fo);

  STD_ACCUM_BUCKET2(rpt22->bucket, cur.src_as);

  return 0;

} /* ftstat_rpt_22_accum */

/* function: ftstat_rpt_22_calc
 *
 * Perform final calculations for rpt22
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_22_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_BUCKET(ftstat_rpt_22, rpt22, 65536);

} /* ftstat_rpt_22_calc */

/* function: ftstat_rpt_22_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_22_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_BUCKET(ftstat_rpt_22, rpt22, 65536, FT_PATH_SYM_ASN,
    "source-as", "", "", "", "", "", "");

} /* ftstat_rpt_22_dump */


/* function: ftstat_rpt_22_free
 *
 * Free data structures for report allocated by ftstat_rpt_22_new
 *
 */
void ftstat_rpt_22_free(struct ftstat_rpt_22 *rpt22)
{

  STD_FREE_BUCKET(rpt22);

} /* ftstat_rpt_22_free */


/* function: ftstat_rpt_23_new
 *
 * Allocate and initialize data structures for rpt 23.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_23 *ftstat_rpt_23_new(struct ftstat_rpt *rpt)
{

  STD_NEW_BUCKET(ftstat_rpt_23, rpt23, 65536, rpt);

} /* ftstat_rpt_23_new */


/* function: ftstat_rpt_23_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_23_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_BUCKET1(ftstat_rpt_23, rpt23);
  
  FT_RECGET_DST_AS(cur,rec,*fo);

  STD_ACCUM_BUCKET2(rpt23->bucket, cur.dst_as);

  return 0;

} /* ftstat_rpt_23_accum */

/* function: ftstat_rpt_23_calc
 *
 * Perform final calculations for rpt23
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_23_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_BUCKET(ftstat_rpt_23, rpt23, 65536);

} /* ftstat_rpt_23_calc */

/* function: ftstat_rpt_23_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_23_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_BUCKET(ftstat_rpt_23, rpt23, 65536, FT_PATH_SYM_ASN,
    "destination-as", "", "", "", "", "", "");
 
} /* ftstat_rpt_23_dump */


/* function: ftstat_rpt_23_free
 *
 * Free data structures for report allocated by ftstat_rpt_23_new
 *
 */
void ftstat_rpt_23_free(struct ftstat_rpt_23 *rpt23)
{

  STD_FREE_BUCKET(rpt23);

} /* ftstat_rpt_23_free */


/* function: ftstat_rpt_24_new
 *
 * Allocate and initialize data structures for rpt 24.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_24 *ftstat_rpt_24_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_24, rpt24, 65536, ftchash_rec_c162, 4, 65536);

} /* ftstat_rpt_24_new */


/* function: ftstat_rpt_24_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_24_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_24, rpt24, ftchash_rec_c162, ftch_recc162,
    ftch_recc162p);

  FT_RECGET_SRC_AS(cur,rec,*fo);
  FT_RECGET_DST_AS(cur,rec,*fo);

  ftch_recc162.c16a = cur.src_as;
  ftch_recc162.c16b = cur.dst_as;

  hash = (ftch_recc162.c16a>>16) ^ (ftch_recc162.c16a & 0xFFFF) ^
    (ftch_recc162.c16b>>16) ^ (ftch_recc162.c16b & 0xFFFF);

  STD_ACCUM_HASH2(rpt24, ftch_recc162, ftch_recc162p);

  return 0;
   
} /* ftstat_rpt_24_accum */

/* function: ftstat_rpt_24_calc
 *
 * Perform final calculations for rpt24
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_24_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_24, rpt24, ftchash_rec_c162, ftch_recc162);

} /* ftstat_rpt_24_calc */

/* function: ftstat_rpt_24_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_24_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH2(ftstat_rpt_24, rpt24, chash_c162_dump,
    FT_PATH_SYM_ASN, FT_PATH_SYM_ASN,
    "", "source-as", "destination-AS", "", "", "", "");

} /* ftstat_rpt_24_dump */


/* function: ftstat_rpt_24_free
 *
 * Free data structures for report allocated by ftstat_rpt_24_new
 *
 */
void ftstat_rpt_24_free(struct ftstat_rpt_24 *rpt24)
{

  STD_FREE_HASH(rpt24);

} /* ftstat_rpt_24_free */


/* function: ftstat_rpt_25_new
 *
 * Allocate and initialize data structures for rpt 25.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_25 *ftstat_rpt_25_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_25, rpt25, 65536, ftchash_rec_prefix16, 8, 65536);

} /* ftstat_rpt_25_new */


/* function: ftstat_rpt_25_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_25_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_25, rpt25, ftchash_rec_prefix16, ftch_recprefix16,
    ftch_prefix16p);

  FT_RECGET_SRC_AS(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);

  ftch_recprefix16.prefix = cur.srcaddr;
  ftch_recprefix16.c16 = cur.src_as;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix16.mask = cur.src_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK)
    ftch_recprefix16.prefix &= ipv4_len2mask(ftch_recprefix16.mask);

  hash = (ftch_recprefix16.prefix>>16) ^ (ftch_recprefix16.prefix & 0xFFFF) ^
    (ftch_recprefix16.mask) ^ (ftch_recprefix16.c16);

  STD_ACCUM_HASH2(rpt25, ftch_recprefix16, ftch_prefix16p);

  return 0;
   
} /* ftstat_rpt_25_accum */

/* function: ftstat_rpt_25_calc
 *
 * Perform final calculations for rpt25
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_25_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_25, rpt25, ftchash_rec_prefix16, ftch_recprefix16);

} /* ftstat_rpt_25_calc */

/* function: ftstat_rpt_25_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_25_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1P(ftstat_rpt_25, rpt25, chash_prefix16_dump,
    FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK,
    FT_PATH_SYM_ASN,
    "", "ip-source-address", "source-as", "", "", "", "");

} /* ftstat_rpt_25_dump */


/* function: ftstat_rpt_25_free
 *
 * Free data structures for report allocated by ftstat_rpt_25_new
 *
 */
void ftstat_rpt_25_free(struct ftstat_rpt_25 *rpt25)
{

  STD_FREE_HASH(rpt25);

} /* ftstat_rpt_25_free */


/* function: ftstat_rpt_26_new
 *
 * Allocate and initialize data structures for rpt 26.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_26 *ftstat_rpt_26_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_26, rpt26, 65536, ftchash_rec_prefix16, 8, 65536);

} /* ftstat_rpt_26_new */


/* function: ftstat_rpt_26_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_26_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_26, rpt26, ftchash_rec_prefix16, ftch_recprefix16,
    ftch_recprefix16p);

  FT_RECGET_SRC_AS(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);

  ftch_recprefix16.prefix = cur.dstaddr;
  ftch_recprefix16.c16 = cur.src_as;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix16.mask = cur.dst_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK)
    ftch_recprefix16.prefix &= ipv4_len2mask(ftch_recprefix16.mask);

  hash = (ftch_recprefix16.prefix>>16) ^ (ftch_recprefix16.prefix & 0xFFFF) ^
    (ftch_recprefix16.mask) ^ (ftch_recprefix16.c16);

  STD_ACCUM_HASH2(rpt26, ftch_recprefix16, ftch_recprefix16p);

  return 0;
   
} /* ftstat_rpt_26_accum */

/* function: ftstat_rpt_26_calc
 *
 * Perform final calculations for rpt26
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_26_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_26, rpt26, ftchash_rec_prefix16, ftch_recprefix16);

} /* ftstat_rpt_26_calc */

/* function: ftstat_rpt_26_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_26_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1P(ftstat_rpt_26, rpt26, chash_prefix16_dump,
    FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK,
    FT_PATH_SYM_ASN,
    "", "ip-source-address", "destination-as", "", "", "", "");

} /* ftstat_rpt_26_dump */


/* function: ftstat_rpt_26_free
 *
 * Free data structures for report allocated by ftstat_rpt_26_new
 *
 */
void ftstat_rpt_26_free(struct ftstat_rpt_26 *rpt26)
{

  STD_FREE_HASH(rpt26);

} /* ftstat_rpt_26_free */


/* function: ftstat_rpt_27_new
 *
 * Allocate and initialize data structures for rpt 27.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_27 *ftstat_rpt_27_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_27, rpt27, 65536, ftchash_rec_prefix16, 8, 65536);

} /* ftstat_rpt_27_new */


/* function: ftstat_rpt_27_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_27_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_26, rpt26, ftchash_rec_prefix16, ftch_recprefix16,
    ftch_recprefix16p);

  FT_RECGET_DST_AS(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);
 
  ftch_recprefix16.prefix = cur.srcaddr;
  ftch_recprefix16.c16 = cur.dst_as;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix16.mask = cur.src_mask;
  }
    
  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK)
    ftch_recprefix16.prefix &= ipv4_len2mask(ftch_recprefix16.mask);
 
  hash = (ftch_recprefix16.prefix>>16) ^ (ftch_recprefix16.prefix & 0xFFFF) ^
    (ftch_recprefix16.mask) ^ (ftch_recprefix16.c16);

  STD_ACCUM_HASH2(rpt26, ftch_recprefix16, ftch_recprefix16p);

  return 0;
   
} /* ftstat_rpt_27_accum */

/* function: ftstat_rpt_27_calc
 *
 * Perform final calculations for rpt27
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_27_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_27, rpt27, ftchash_rec_prefix16, ftch_recprefix16);

} /* ftstat_rpt_27_calc */

/* function: ftstat_rpt_27_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_27_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1P(ftstat_rpt_27, rpt27, chash_prefix16_dump,
    FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK,
    FT_PATH_SYM_ASN,
    "", "ip-source-address", "destination-as", "", "", "", "");


} /* ftstat_rpt_27_dump */


/* function: ftstat_rpt_27_free
 *
 * Free data structures for report allocated by ftstat_rpt_27_new
 *
 */
void ftstat_rpt_27_free(struct ftstat_rpt_27 *rpt27)
{

  STD_FREE_HASH(rpt27);

} /* ftstat_rpt_27_free */


/* function: ftstat_rpt_28_new
 *
 * Allocate and initialize data structures for rpt 28.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_28 *ftstat_rpt_28_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_28, rpt28, 65536, ftchash_rec_prefix16, 8, 65536);

} /* ftstat_rpt_28_new */


/* function: ftstat_rpt_28_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_28_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_28, rpt28, ftchash_rec_prefix16, ftch_recprefix16,
    ftch_recprefix16p);

  FT_RECGET_DST_AS(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);
  
  ftch_recprefix16.prefix = cur.dstaddr;
  ftch_recprefix16.c16 = cur.dst_as;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix16.mask = cur.dst_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK)
    ftch_recprefix16.prefix &= ipv4_len2mask(ftch_recprefix16.mask);

  hash = (ftch_recprefix16.prefix>>16) ^ (ftch_recprefix16.prefix & 0xFFFF) ^
    (ftch_recprefix16.mask) ^ (ftch_recprefix16.c16);

  STD_ACCUM_HASH2(rpt28, ftch_recprefix16, ftch_recprefix16p);
  
  return 0;
   
} /* ftstat_rpt_28_accum */

/* function: ftstat_rpt_28_calc
 *
 * Perform final calculations for rpt28
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_28_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_28, rpt28, ftchash_rec_prefix16, ftch_recprefix16);

} /* ftstat_rpt_28_calc */

/* function: ftstat_rpt_28_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_28_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1P(ftstat_rpt_28, rpt28, chash_prefix16_dump,
   FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK,
   FT_PATH_SYM_ASN,
    "", "ip-destination-address", "source-as", "", "", "", "");

} /* ftstat_rpt_28_dump */


/* function: ftstat_rpt_28_free
 *
 * Free data structures for report allocated by ftstat_rpt_28_new
 *
 */
void ftstat_rpt_28_free(struct ftstat_rpt_28 *rpt28)
{

  STD_FREE_HASH(rpt28);

} /* ftstat_rpt_28_free */


/* function: ftstat_rpt_29_new
 *
 * Allocate and initialize data structures for rpt 29.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_29 *ftstat_rpt_29_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_29, rpt29, 65536, ftchash_rec_prefix216, 13, 65536);

} /* ftstat_rpt_29_new */


/* function: ftstat_rpt_29_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_29_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_29, rpt29, ftchash_rec_prefix216,
    ftch_recprefix216, ftch_recprefix216p);

  FT_RECGET_SRC_AS(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);
  
  ftch_recprefix216.src_prefix = cur.srcaddr;
  ftch_recprefix216.dst_prefix = cur.dstaddr;
  ftch_recprefix216.c16 = cur.src_as;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix216.src_mask = cur.src_mask;
  }

  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix216.dst_mask = cur.dst_mask;
  }
 
  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK) {
    ftch_recprefix216.src_prefix &= ipv4_len2mask(ftch_recprefix216.src_mask);
  }

  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK) {
    ftch_recprefix216.dst_prefix &= ipv4_len2mask(ftch_recprefix216.dst_mask);
  }
 
  hash = (ftch_recprefix216.src_prefix>>16)^
          (ftch_recprefix216.src_prefix & 0xFFFF)^
          (ftch_recprefix216.dst_prefix>>16)^
          (ftch_recprefix216.dst_prefix & 0xFFFF)^
          (ftch_recprefix216.c16)^
          (ftch_recprefix216.src_mask)^
          (u_int32)(ftch_recprefix216.dst_mask<<8);

  STD_ACCUM_HASH2(rpt29, ftch_recprefix216, ftch_recprefix216p);
  
  return 0;
   
} /* ftstat_rpt_29_accum */

/* function: ftstat_rpt_29_calc
 *
 * Perform final calculations for rpt29
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_29_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_29, rpt29, ftchash_rec_prefix216, ftch_recprefix216);

} /* ftstat_rpt_29_calc */

/* function: ftstat_rpt_29_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_29_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1(ftstat_rpt_29, rpt29, chash_prefix216_dump, FT_PATH_SYM_ASN,
    "", "ip-source-address", "ip-destination-address", "source-as", "", "", "");

} /* ftstat_rpt_29_dump */


/* function: ftstat_rpt_29_free
 *
 * Free data structures for report allocated by ftstat_rpt_29_new
 *
 */
void ftstat_rpt_29_free(struct ftstat_rpt_29 *rpt29)
{

  STD_FREE_HASH(rpt29);

} /* ftstat_rpt_29_free */


/* function: ftstat_rpt_30_new
 *
 * Allocate and initialize data structures for rpt 30.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_30 *ftstat_rpt_30_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_30, rpt30, 65536, ftchash_rec_prefix216, 13, 65536);

} /* ftstat_rpt_30_new */


/* function: ftstat_rpt_30_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_30_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_30, rpt30, ftchash_rec_prefix216,
    ftch_recprefix216, ftch_recprefix216p);

  FT_RECGET_DST_AS(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);
    
  ftch_recprefix216.src_prefix = cur.srcaddr;
  ftch_recprefix216.dst_prefix = cur.dstaddr;
  ftch_recprefix216.c16 = cur.dst_as;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix216.src_mask = cur.src_mask;
  }
  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix216.dst_mask = cur.dst_mask;
  }
 
  /* remove host bits */  
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK) {
    ftch_recprefix216.src_prefix &= ipv4_len2mask(ftch_recprefix216.src_mask);
  }

  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK) {
    ftch_recprefix216.dst_prefix &= ipv4_len2mask(ftch_recprefix216.dst_mask);
  }
  
  hash = (ftch_recprefix216.src_prefix>>16)^
          (ftch_recprefix216.src_prefix & 0xFFFF)^
          (ftch_recprefix216.dst_prefix>>16)^
          (ftch_recprefix216.dst_prefix & 0xFFFF)^
          (ftch_recprefix216.c16)^
          (ftch_recprefix216.src_mask)^
          (u_int32)(ftch_recprefix216.dst_mask<<8);

  STD_ACCUM_HASH2(rpt30, ftch_recprefix216, ftch_recprefix216p);
  
  return 0;
   
} /* ftstat_rpt_30_accum */

/* function: ftstat_rpt_30_calc
 *
 * Perform final calculations for rpt30
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_30_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_30, rpt30, ftchash_rec_prefix216, ftch_recprefix216);

} /* ftstat_rpt_30_calc */

/* function: ftstat_rpt_30_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_30_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1(ftstat_rpt_30, rpt30, chash_prefix216_dump, FT_PATH_SYM_ASN,
    "", "ip-source-address", "ip-destination-address", "destination-as", "",
    "", "");

} /* ftstat_rpt_30_dump */


/* function: ftstat_rpt_30_free
 *
 * Free data structures for report allocated by ftstat_rpt_30_new
 *
 */
void ftstat_rpt_30_free(struct ftstat_rpt_30 *rpt30)
{

  STD_FREE_HASH(rpt30);

} /* ftstat_rpt_30_free */


/* function: ftstat_rpt_31_new
 *
 * Allocate and initialize data structures for rpt 31.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_31 *ftstat_rpt_31_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_31, rpt31, 65536, ftchash_rec_prefix2162, 16, 65536);

} /* ftstat_rpt_31_new */


/* function: ftstat_rpt_31_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_31_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_31, rpt31, ftchash_rec_prefix2162,
    ftch_recprefix2162, ftch_recprefix2162p);

  FT_RECGET_SRC_AS(cur,rec,*fo);
  FT_RECGET_DST_AS(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);
    
  ftch_recprefix2162.src_prefix = cur.srcaddr;
  ftch_recprefix2162.dst_prefix = cur.dstaddr;
  ftch_recprefix2162.c16a = cur.src_as;
  ftch_recprefix2162.c16b = cur.dst_as;
 
  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix2162.src_mask = cur.src_mask;
  }

  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix2162.dst_mask = cur.dst_mask;
  }

  /* remove host bits */  
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK) {
    ftch_recprefix2162.src_prefix &= ipv4_len2mask(ftch_recprefix2162.src_mask);
  }

  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK) {
    ftch_recprefix2162.dst_prefix &= ipv4_len2mask(ftch_recprefix2162.dst_mask);
  }
  
  hash = (ftch_recprefix2162.src_prefix>>16)^
          (ftch_recprefix2162.src_prefix & 0xFFFF)^
          (ftch_recprefix2162.dst_prefix>>16)^
          (ftch_recprefix2162.dst_prefix & 0xFFFF)^
          (ftch_recprefix2162.c16b)^
          (ftch_recprefix2162.c16a)^
          (ftch_recprefix2162.src_mask)^
          (u_int32)(ftch_recprefix2162.dst_mask<<8);

  STD_ACCUM_HASH2(rpt31, ftch_recprefix2162, ftch_recprefix2162p);
  
  return 0;
   
} /* ftstat_rpt_31_accum */

/* function: ftstat_rpt_31_calc
 *
 * Perform final calculations for rpt31
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_31_calc(struct ftstat_rpt *rpt)
{
  
  STD_CALC_HASH(ftstat_rpt_31, rpt31, ftchash_rec_prefix2162,
    ftch_recprefix2162);

} /* ftstat_rpt_31_calc */

/* function: ftstat_rpt_31_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_31_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH2(ftstat_rpt_31, rpt31, chash_prefix2162_dump,
    FT_PATH_SYM_ASN, FT_PATH_SYM_ASN,
    "", "ip-source-address", "ip-destination-address", "source-as",
    "destination-as", "", "");

} /* ftstat_rpt_31_dump */


/* function: ftstat_rpt_31_free
 *
 * Free data structures for report allocated by ftstat_rpt_31_new
 *
 */
void ftstat_rpt_31_free(struct ftstat_rpt_31 *rpt31)
{

  STD_FREE_HASH(rpt31);

} /* ftstat_rpt_31_free */


/* function: ftstat_rpt_32_new
 *
 * Allocate and initialize data structures for rpt 32.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_32 *ftstat_rpt_32_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_32, rpt32, 65536, ftchash_rec_prefix16, 8, 65536);

} /* ftstat_rpt_32_new */


/* function: ftstat_rpt_32_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_32_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_32, rpt32, ftchash_rec_prefix16,
    ftch_recprefix16, ftch_recprefix16p);

  FT_RECGET_INPUT(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);
    
  ftch_recprefix16.prefix = cur.srcaddr;
  ftch_recprefix16.c16 = cur.input;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix16.mask = cur.src_mask;
  }

  /* remove host bits */ 
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK)
    ftch_recprefix16.prefix &= ipv4_len2mask(ftch_recprefix16.mask);
  
  hash = (ftch_recprefix16.prefix>>16) ^ (ftch_recprefix16.prefix & 0xFFFF) ^
    (ftch_recprefix16.mask) ^ (ftch_recprefix16.c16);

  STD_ACCUM_HASH2(rpt32, ftch_recprefix16, ftch_recprefix16p);
  
  return 0;
   
} /* ftstat_rpt_32_accum */

/* function: ftstat_rpt_32_calc
 *
 * Perform final calculations for rpt32
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_32_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_32, rpt32, ftchash_rec_prefix16, ftch_recprefix16);

} /* ftstat_rpt_32_calc */

/* function: ftstat_rpt_32_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_32_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1P(ftstat_rpt_32, rpt32, chash_prefix16_dump,
   FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK,
   (char*)0L,
    "", "ip-source-address", "input-interface", "", "", "", "");

} /* ftstat_rpt_32_dump */


/* function: ftstat_rpt_32_free
 *
 * Free data structures for report allocated by ftstat_rpt_32_new
 *
 */
void ftstat_rpt_32_free(struct ftstat_rpt_32 *rpt32)
{

  STD_FREE_HASH(rpt32);

} /* ftstat_rpt_32_free */


/* function: ftstat_rpt_33_new
 *
 * Allocate and initialize data structures for rpt 33.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_33 *ftstat_rpt_33_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_33, rpt33, 65536, ftchash_rec_prefix16, 8, 65536);

} /* ftstat_rpt_33_new */


/* function: ftstat_rpt_33_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_33_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_33, rpt33, ftchash_rec_prefix16,
    ftch_recprefix16, ftch_recprefix16p);

  FT_RECGET_INPUT(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);
  
  ftch_recprefix16.prefix = cur.dstaddr;
  ftch_recprefix16.c16 = cur.input;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix16.mask = cur.dst_mask;
  }
 
  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK)
    ftch_recprefix16.prefix &= ipv4_len2mask(ftch_recprefix16.mask);
  
  hash = (ftch_recprefix16.prefix>>16) ^ (ftch_recprefix16.prefix & 0xFFFF) ^
    (ftch_recprefix16.mask) ^ (ftch_recprefix16.c16);

  STD_ACCUM_HASH2(rpt33, ftch_recprefix16, ftch_recprefix16p);
  
  return 0;
   
} /* ftstat_rpt_33_accum */

/* function: ftstat_rpt_33_calc
 *
 * Perform final calculations for rpt33
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_33_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_33, rpt33, ftchash_rec_prefix16, ftch_recprefix16);

} /* ftstat_rpt_33_calc */

/* function: ftstat_rpt_33_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_33_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1P(ftstat_rpt_33, rpt33, chash_prefix16_dump,
   FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK,
   (char*)0L,
    "", "ip-destination-address", "input-interface", "", "", "", "");

} /* ftstat_rpt_33_dump */


/* function: ftstat_rpt_33_free
 *
 * Free data structures for report allocated by ftstat_rpt_33_new
 *
 */
void ftstat_rpt_33_free(struct ftstat_rpt_33 *rpt33)
{
} /* ftstat_rpt_33_free */


/* function: ftstat_rpt_34_new
 *
 * Allocate and initialize data structures for rpt 34.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_34 *ftstat_rpt_34_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_34, rpt34, 65536, ftchash_rec_prefix16, 8, 65536);

} /* ftstat_rpt_34_new */


/* function: ftstat_rpt_34_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_34_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_33, rpt33, ftchash_rec_prefix16,
    ftch_recprefix16, ftch_recprefix16p);

  FT_RECGET_OUTPUT(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);
  
  ftch_recprefix16.prefix = cur.srcaddr;
  ftch_recprefix16.c16 = cur.output;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix16.mask = cur.src_mask;
  }
 
  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK)
    ftch_recprefix16.prefix &= ipv4_len2mask(ftch_recprefix16.mask);
  
  hash = (ftch_recprefix16.prefix>>16) ^ (ftch_recprefix16.prefix & 0xFFFF) ^
    (ftch_recprefix16.mask) ^ (ftch_recprefix16.c16);

  STD_ACCUM_HASH2(rpt33, ftch_recprefix16, ftch_recprefix16p);
  
  return 0;
   
} /* ftstat_rpt_34_accum */

/* function: ftstat_rpt_34_calc
 *
 * Perform final calculations for rpt34
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_34_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_34, rpt34, ftchash_rec_prefix16, ftch_recprefix16);

} /* ftstat_rpt_34_calc */

/* function: ftstat_rpt_34_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_34_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1P(ftstat_rpt_28, rpt28, chash_prefix16_dump,
   FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK,
   (char*)0L,
    "", "ip-source-address", "output-interface", "", "", "", "");

} /* ftstat_rpt_34_dump */


/* function: ftstat_rpt_34_free
 *
 * Free data structures for report allocated by ftstat_rpt_34_new
 *
 */
void ftstat_rpt_34_free(struct ftstat_rpt_34 *rpt34)
{

  STD_FREE_HASH(rpt34);

} /* ftstat_rpt_34_free */


/* function: ftstat_rpt_35_new
 *
 * Allocate and initialize data structures for rpt 35.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_35 *ftstat_rpt_35_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_35, rpt35, 65536, ftchash_rec_prefix16, 8, 65536);

} /* ftstat_rpt_35_new */


/* function: ftstat_rpt_35_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_35_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_35, rpt35, ftchash_rec_prefix16,
    ftch_recprefix16, ftch_recprefix16p);

  FT_RECGET_OUTPUT(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);
  
  ftch_recprefix16.prefix = cur.dstaddr;
  ftch_recprefix16.c16 = cur.output;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix16.mask = cur.dst_mask;
  }
 
  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK)
    ftch_recprefix16.prefix &= ipv4_len2mask(ftch_recprefix16.mask);
  
  hash = (ftch_recprefix16.prefix>>16) ^ (ftch_recprefix16.prefix & 0xFFFF) ^
    (ftch_recprefix16.mask) ^ (ftch_recprefix16.c16);

  STD_ACCUM_HASH2(rpt35, ftch_recprefix16, ftch_recprefix16p);
  
  return 0;
   
} /* ftstat_rpt_35_accum */

/* function: ftstat_rpt_35_calc
 *
 * Perform final calculations for rpt35
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_35_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_35, rpt35, ftchash_rec_prefix16, ftch_recprefix16);

} /* ftstat_rpt_35_calc */

/* function: ftstat_rpt_35_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_35_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1P(ftstat_rpt_35, rpt35, chash_prefix16_dump,
   FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK,
   (char*)0L,
    "", "ip-destination-address", "output-interface", "", "", "", "");

} /* ftstat_rpt_35_dump */


/* function: ftstat_rpt_35_free
 *
 * Free data structures for report allocated by ftstat_rpt_35_new
 *
 */
void ftstat_rpt_35_free(struct ftstat_rpt_35 *rpt35)
{

  STD_FREE_HASH(rpt35);

} /* ftstat_rpt_35_free */


/* function: ftstat_rpt_36_new
 *
 * Allocate and initialize data structures for rpt 36.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_36 *ftstat_rpt_36_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_36, rpt36, 65536, ftchash_rec_prefix216, 13, 65536);

} /* ftstat_rpt_36_new */


/* function: ftstat_rpt_36_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_36_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_36, rpt36, ftchash_rec_prefix216,
    ftch_recprefix216, ftch_recprefix216p);

  FT_RECGET_INPUT(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);
    
  ftch_recprefix216.src_prefix = cur.srcaddr;
  ftch_recprefix216.dst_prefix = cur.dstaddr;
  ftch_recprefix216.c16 = cur.input;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix216.src_mask = cur.src_mask;
  }

  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix216.dst_mask = cur.dst_mask;
  }
 
  /* remove host bits */  
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK) {
    ftch_recprefix216.src_prefix &= ipv4_len2mask(ftch_recprefix216.src_mask);
  }

  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK) {
    ftch_recprefix216.dst_prefix &= ipv4_len2mask(ftch_recprefix216.dst_mask);
  }
  
  hash = (ftch_recprefix216.src_prefix>>16)^
          (ftch_recprefix216.src_prefix & 0xFFFF)^
          (ftch_recprefix216.dst_prefix>>16)^
          (ftch_recprefix216.dst_prefix & 0xFFFF)^
          (ftch_recprefix216.c16)^
          (ftch_recprefix216.src_mask)^
          (u_int32)(ftch_recprefix216.dst_mask<<8);

  STD_ACCUM_HASH2(rpt36, ftch_recprefix216, ftch_recprefix216p);
  
  return 0;
   
} /* ftstat_rpt_36_accum */

/* function: ftstat_rpt_36_calc
 *
 * Perform final calculations for rpt36
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_36_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_36, rpt36, ftchash_rec_prefix216, ftch_recprefix216);

} /* ftstat_rpt_36_calc */

/* function: ftstat_rpt_36_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_36_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1(ftstat_rpt_36, rpt36, chash_prefix216_dump,
    (char*)0L,
    "", "ip-source-address", "ip-destination-address", "input-interface", "",
    "", "");

} /* ftstat_rpt_36_dump */


/* function: ftstat_rpt_36_free
 *
 * Free data structures for report allocated by ftstat_rpt_36_new
 *
 */
void ftstat_rpt_36_free(struct ftstat_rpt_36 *rpt36)
{

  STD_FREE_HASH(rpt36);

} /* ftstat_rpt_36_free */


/* function: ftstat_rpt_37_new
 *
 * Allocate and initialize data structures for rpt 37.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_37 *ftstat_rpt_37_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_37, rpt37, 65536, ftchash_rec_prefix216, 13, 65536);

} /* ftstat_rpt_37_new */


/* function: ftstat_rpt_37_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_37_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_37, rpt37, ftchash_rec_prefix216,
    ftch_recprefix216, ftch_recprefix216p);

  FT_RECGET_OUTPUT(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);

  ftch_recprefix216.src_prefix = cur.srcaddr;
  ftch_recprefix216.dst_prefix = cur.dstaddr;
  ftch_recprefix216.c16 = cur.output;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix216.src_mask = cur.src_mask;
  }

  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix216.dst_mask = cur.dst_mask;
  }
 
  /* remove host bits */  
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK) {
    ftch_recprefix216.src_prefix &= ipv4_len2mask(ftch_recprefix216.src_mask);
  }

  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK) {
    ftch_recprefix216.dst_prefix &= ipv4_len2mask(ftch_recprefix216.dst_mask);
  }
  
  hash = (ftch_recprefix216.src_prefix>>16)^
          (ftch_recprefix216.src_prefix & 0xFFFF)^
          (ftch_recprefix216.dst_prefix>>16)^
          (ftch_recprefix216.dst_prefix & 0xFFFF)^
          (ftch_recprefix216.c16)^
          (ftch_recprefix216.src_mask)^
          (u_int32)(ftch_recprefix216.dst_mask<<8);
  
  STD_ACCUM_HASH2(rpt37, ftch_recprefix216, ftch_recprefix216p);

  return 0;
   
} /* ftstat_rpt_37_accum */

/* function: ftstat_rpt_37_calc
 *
 * Perform final calculations for rpt37
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_37_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_37, rpt37, ftchash_rec_prefix216, ftch_recprefix216);

} /* ftstat_rpt_37_calc */

/* function: ftstat_rpt_37_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_37_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1(ftstat_rpt_37, rpt37, chash_prefix216_dump,
    (char*)0L,
    "", "ip-source-address", "ip-destination-address", "output-interface", "",
    "", "");

} /* ftstat_rpt_37_dump */


/* function: ftstat_rpt_37_free
 *
 * Free data structures for report allocated by ftstat_rpt_37_new
 *
 */
void ftstat_rpt_37_free(struct ftstat_rpt_37 *rpt37)
{

  STD_FREE_HASH(rpt37);

} /* ftstat_rpt_37_free */


/* function: ftstat_rpt_38_new
 *
 * Allocate and initialize data structures for rpt 38.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_38 *ftstat_rpt_38_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_38, rpt38, 65536, ftchash_rec_prefix2162, 16, 65536);

} /* ftstat_rpt_38_new */


/* function: ftstat_rpt_38_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_38_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_38, rpt38, ftchash_rec_prefix2162,
    ftch_recprefix2162, ftch_recprefix2162p);

  FT_RECGET_INPUT(cur,rec,*fo);
  FT_RECGET_OUTPUT(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);
 
  ftch_recprefix2162.src_prefix = cur.srcaddr;
  ftch_recprefix2162.dst_prefix = cur.dstaddr;
  ftch_recprefix2162.c16a = cur.input;
  ftch_recprefix2162.c16b = cur.output;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix2162.src_mask = cur.src_mask;
  }

  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix2162.dst_mask = cur.dst_mask;
  }
  
  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK) {
    ftch_recprefix2162.src_prefix &= ipv4_len2mask(ftch_recprefix2162.src_mask);
  }

  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK) {
    ftch_recprefix2162.dst_prefix &= ipv4_len2mask(ftch_recprefix2162.dst_mask);
  }
  
  hash = (ftch_recprefix2162.src_prefix>>16)^
          (ftch_recprefix2162.src_prefix & 0xFFFF)^
          (ftch_recprefix2162.dst_prefix>>16)^
          (ftch_recprefix2162.dst_prefix & 0xFFFF)^
          (ftch_recprefix2162.c16b)^
          (ftch_recprefix2162.c16a)^
          (ftch_recprefix2162.src_mask)^
          (u_int32)(ftch_recprefix2162.dst_mask<<8);
  
  STD_ACCUM_HASH2(rpt38, ftch_recprefix2162, ftch_recprefix2162p);

  return 0;
   
} /* ftstat_rpt_38_accum */

/* function: ftstat_rpt_38_calc
 *
 * Perform final calculations for rpt38
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_38_calc(struct ftstat_rpt *rpt)
{
  
  STD_CALC_HASH(ftstat_rpt_38, rpt38, ftchash_rec_prefix2162,
    ftch_recprefix2162);
    
} /* ftstat_rpt_38_calc */

/* function: ftstat_rpt_38_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_38_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH2(ftstat_rpt_31, rpt31, chash_prefix2162_dump,
    (char*)0L, (char*)0L,
    "", "ip-source-address", "ip-destination-address", "input-interface",
    "output-interface", "", "");

} /* ftstat_rpt_38_dump */


/* function: ftstat_rpt_38_free
 *
 * Free data structures for report allocated by ftstat_rpt_38_new
 *
 */
void ftstat_rpt_38_free(struct ftstat_rpt_38 *rpt38)
{

  STD_FREE_HASH(rpt38);

} /* ftstat_rpt_38_free */


/* function: ftstat_rpt_39_new
 *
 * Allocate and initialize data structures for rpt 39.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_39 *ftstat_rpt_39_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_39, rpt39, 65536, ftchash_rec_c162, 4, 65536);

} /* ftstat_rpt_39_new */


/* function: ftstat_rpt_39_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_39_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_39, rpt39, ftchash_rec_c162,
    ftch_recc162, ftch_recc162p);

  FT_RECGET_INPUT(cur,rec,*fo);
  FT_RECGET_SRC_AS(cur,rec,*fo);

  ftch_recc162.c16a = cur.input;
  ftch_recc162.c16b = cur.src_as;
 
  hash = (ftch_recc162.c16a>>16) ^ (ftch_recc162.c16a & 0xFFFF) ^
    (ftch_recc162.c16b>>16) ^ (ftch_recc162.c16b & 0xFFFF);

  STD_ACCUM_HASH2(rpt39, ftch_recc162, ftch_recc162p);
  
  return 0;
   
} /* ftstat_rpt_39_accum */

/* function: ftstat_rpt_39_calc
 *
 * Perform final calculations for rpt39
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_39_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_39, rpt39, ftchash_rec_c162, ftch_recc162);

} /* ftstat_rpt_39_calc */

/* function: ftstat_rpt_39_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_39_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH2(ftstat_rpt_8, rpt8, chash_c162_dump,
    (char*)0L, FT_PATH_SYM_ASN,
    "", "input-interface", "source-as", "", "", "", "");

} /* ftstat_rpt_39_dump */


/* function: ftstat_rpt_39_free
 *
 * Free data structures for report allocated by ftstat_rpt_39_new
 *
 */
void ftstat_rpt_39_free(struct ftstat_rpt_39 *rpt39)
{

  STD_FREE_HASH(rpt39);

} /* ftstat_rpt_39_free */


/* function: ftstat_rpt_40_new
 *
 * Allocate and initialize data structures for rpt 40.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_40 *ftstat_rpt_40_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_40, rpt40, 65536, ftchash_rec_c162, 4, 65536);

} /* ftstat_rpt_40_new */


/* function: ftstat_rpt_40_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_40_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_40, rpt40, ftchash_rec_c162,
    ftch_recc162, ftch_recc162p);

  FT_RECGET_INPUT(cur,rec,*fo);
  FT_RECGET_DST_AS(cur,rec,*fo);

  ftch_recc162.c16a = cur.input;
  ftch_recc162.c16b = cur.dst_as;
  
  hash = (ftch_recc162.c16a>>16) ^ (ftch_recc162.c16a & 0xFFFF) ^
    (ftch_recc162.c16b>>16) ^ (ftch_recc162.c16b & 0xFFFF);
    
  STD_ACCUM_HASH2(rpt40, ftch_recc162, ftch_recc162p);

  return 0;
   
} /* ftstat_rpt_40_accum */

/* function: ftstat_rpt_40_calc
 *
 * Perform final calculations for rpt40
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_40_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_40, rpt40, ftchash_rec_c162, ftch_recc162);

} /* ftstat_rpt_40_calc */

/* function: ftstat_rpt_40_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_40_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH2(ftstat_rpt_40, rpt40, chash_c162_dump,
    (char*)0L, FT_PATH_SYM_ASN,
    "", "input-interface", "destination-as", "", "", "", "");

} /* ftstat_rpt_40_dump */


/* function: ftstat_rpt_40_free
 *
 * Free data structures for report allocated by ftstat_rpt_40_new
 *
 */
void ftstat_rpt_40_free(struct ftstat_rpt_40 *rpt40)
{

  STD_FREE_HASH(rpt40);

} /* ftstat_rpt_40_free */


/* function: ftstat_rpt_41_new
 *
 * Allocate and initialize data structures for rpt 41.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_41 *ftstat_rpt_41_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_41, rpt41, 65536, ftchash_rec_c162, 4, 65536);

} /* ftstat_rpt_41_new */


/* function: ftstat_rpt_41_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_41_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_41, rpt41, ftchash_rec_c162,
    ftch_recc162, ftch_recc162p);

  FT_RECGET_OUTPUT(cur,rec,*fo);
  FT_RECGET_SRC_AS(cur,rec,*fo);

  ftch_recc162.c16a = cur.output;
  ftch_recc162.c16b = cur.src_as;
  
  hash = (ftch_recc162.c16a>>16) ^ (ftch_recc162.c16a & 0xFFFF) ^
    (ftch_recc162.c16b>>16) ^ (ftch_recc162.c16b & 0xFFFF);

  STD_ACCUM_HASH2(rpt41, ftch_recc162, ftch_recc162p);
   
  return 0;
   
} /* ftstat_rpt_41_accum */

/* function: ftstat_rpt_41_calc
 *
 * Perform final calculations for rpt41
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_41_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_41, rpt41, ftchash_rec_c162, ftch_recc162);

} /* ftstat_rpt_41_calc */

/* function: ftstat_rpt_41_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_41_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH2(ftstat_rpt_41, rpt41, chash_c162_dump,
    (char*)0L, FT_PATH_SYM_ASN,
    "", "output-interface", "source-as", "", "", "", "");

} /* ftstat_rpt_41_dump */


/* function: ftstat_rpt_41_free
 *
 * Free data structures for report allocated by ftstat_rpt_41_new
 *
 */
void ftstat_rpt_41_free(struct ftstat_rpt_41 *rpt41)
{

  STD_FREE_HASH(rpt41);

} /* ftstat_rpt_41_free */


/* function: ftstat_rpt_42_new
 *
 * Allocate and initialize data structures for rpt 42.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_42 *ftstat_rpt_42_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_42, rpt42, 65536, ftchash_rec_c162, 4, 65536);

} /* ftstat_rpt_42_new */


/* function: ftstat_rpt_42_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_42_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_42, rpt42, ftchash_rec_c162,
    ftch_recc162, ftch_recc162p);

  FT_RECGET_OUTPUT(cur,rec,*fo);
  FT_RECGET_DST_AS(cur,rec,*fo);

  ftch_recc162.c16a = cur.output;
  ftch_recc162.c16b = cur.dst_as;
  
  hash = (ftch_recc162.c16a>>16) ^ (ftch_recc162.c16a & 0xFFFF) ^
    (ftch_recc162.c16b>>16) ^ (ftch_recc162.c16b & 0xFFFF);

  STD_ACCUM_HASH2(rpt42, ftch_recc162, ftch_recc162p);
   
  return 0;
   
} /* ftstat_rpt_42_accum */

/* function: ftstat_rpt_42_calc
 *
 * Perform final calculations for rpt42
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_42_calc(struct ftstat_rpt *rpt)
{
    
  STD_CALC_HASH(ftstat_rpt_42, rpt42, ftchash_rec_c162, ftch_recc162);

} /* ftstat_rpt_42_calc */

/* function: ftstat_rpt_42_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_42_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  
  STD_DUMP_HASH2(ftstat_rpt_42, rpt42, chash_c162_dump,
    (char*)0L, FT_PATH_SYM_ASN,
    "", "output-interface", "destination-as", "", "", "", "");
 

} /* ftstat_rpt_42_dump */


/* function: ftstat_rpt_42_free
 *
 * Free data structures for report allocated by ftstat_rpt_42_new
 *
 */
void ftstat_rpt_42_free(struct ftstat_rpt_42 *rpt42)
{

  STD_FREE_HASH(rpt42);

} /* ftstat_rpt_42_free */


/* function: ftstat_rpt_43_new
 *
 * Allocate and initialize data structures for rpt 43.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_43 *ftstat_rpt_43_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_43, rpt43, 65536, ftchash_rec_c163, 6, 65536);

} /* ftstat_rpt_43_new */


/* function: ftstat_rpt_43_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_43_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_43, rpt43, ftchash_rec_c163,
    ftch_recc163, ftch_recc163p);

  FT_RECGET_INPUT(cur,rec,*fo);
  FT_RECGET_SRC_AS(cur,rec,*fo);
  FT_RECGET_DST_AS(cur,rec,*fo);

  ftch_recc163.c16a = cur.input;
  ftch_recc163.c16b = cur.src_as;
  ftch_recc163.c16c = cur.dst_as;
  
  hash = ftch_recc163.c16a ^ ftch_recc163.c16b ^ ftch_recc163.c16c;
   
  STD_ACCUM_HASH2(rpt43, ftch_recc163, ftch_recc163p);

  return 0;
   
} /* ftstat_rpt_43_accum */

/* function: ftstat_rpt_43_calc
 *
 * Perform final calculations for rpt43
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_43_calc(struct ftstat_rpt *rpt)
{
  
  STD_CALC_HASH(ftstat_rpt_43, rpt43, ftchash_rec_c163, ftch_recc163);

} /* ftstat_rpt_43_calc */

/* function: ftstat_rpt_43_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_43_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH3(ftstat_rpt_43, rpt43, chash_c163_dump,
    (char*)0L, FT_PATH_SYM_ASN, FT_PATH_SYM_ASN,
    "", "input-interface", "source-as", "destination-as", "", "", "");
  
} /* ftstat_rpt_43_dump */


/* function: ftstat_rpt_43_free
 *
 * Free data structures for report allocated by ftstat_rpt_43_new
 *
 */
void ftstat_rpt_43_free(struct ftstat_rpt_43 *rpt43)
{

  STD_FREE_HASH(rpt43);

} /* ftstat_rpt_43_free */


/* function: ftstat_rpt_44_new
 *
 * Allocate and initialize data structures for rpt 44.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_44 *ftstat_rpt_44_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_44, rpt44, 65536, ftchash_rec_c163, 6, 65536);

} /* ftstat_rpt_44_new */


/* function: ftstat_rpt_44_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_44_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_44, rpt44, ftchash_rec_c163,
    ftch_recc163, ftch_recc163p);

  FT_RECGET_OUTPUT(cur,rec,*fo);
  FT_RECGET_SRC_AS(cur,rec,*fo);
  FT_RECGET_DST_AS(cur,rec,*fo);
    
  ftch_recc163.c16a = cur.output;
  ftch_recc163.c16b = cur.src_as;
  ftch_recc163.c16c = cur.dst_as;
 
  hash = ftch_recc163.c16a ^ ftch_recc163.c16b ^ ftch_recc163.c16c;

  STD_ACCUM_HASH2(rpt44, ftch_recc163, ftch_recc163p);

  return 0;
   
} /* ftstat_rpt_44_accum */

/* function: ftstat_rpt_44_calc
 *
 * Perform final calculations for rpt44
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_44_calc(struct ftstat_rpt *rpt)
{
  
  STD_CALC_HASH(ftstat_rpt_44, rpt44, ftchash_rec_c163, ftch_recc163);
  
} /* ftstat_rpt_44_calc */

/* function: ftstat_rpt_44_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_44_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH3(ftstat_rpt_44, rpt44, chash_c163_dump,
    (char*)0L, FT_PATH_SYM_ASN, FT_PATH_SYM_ASN,
    "", "output-interface", "source-as", "destination-as", "", "", "");
 
} /* ftstat_rpt_44_dump */


/* function: ftstat_rpt_44_free
 *
 * Free data structures for report allocated by ftstat_rpt_44_new
 *
 */
void ftstat_rpt_44_free(struct ftstat_rpt_44 *rpt44)
{

  STD_FREE_HASH(rpt44);

} /* ftstat_rpt_44_free */


/* function: ftstat_rpt_45_new
 *
 * Allocate and initialize data structures for rpt 45.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_45 *ftstat_rpt_45_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_45, rpt45, 65536, ftchash_rec_c164, 8, 65536);

} /* ftstat_rpt_45_new */


/* function: ftstat_rpt_45_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_45_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_45, rpt45, ftchash_rec_c164,
    ftch_recc164, ftch_recc164p);

  FT_RECGET_INPUT(cur,rec,*fo);
  FT_RECGET_OUTPUT(cur,rec,*fo);
  FT_RECGET_SRC_AS(cur,rec,*fo);
  FT_RECGET_DST_AS(cur,rec,*fo);
  
  ftch_recc164.c16a = cur.input;
  ftch_recc164.c16b = cur.output;
  ftch_recc164.c16c = cur.src_as;
  ftch_recc164.c16d = cur.dst_as;
 
  hash = ftch_recc164.c16a ^ ftch_recc164.c16b ^ ftch_recc164.c16c ^
         ftch_recc164.c16c;;

  STD_ACCUM_HASH2(rpt45, ftch_recc164, ftch_recc164p);

  return 0;
   
} /* ftstat_rpt_45_accum */

/* function: ftstat_rpt_45_calc
 *
 * Perform final calculations for rpt45
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_45_calc(struct ftstat_rpt *rpt)
{
  
  STD_CALC_HASH(ftstat_rpt_45, rpt45, ftchash_rec_c164, ftch_recc164);

} /* ftstat_rpt_45_calc */

/* function: ftstat_rpt_45_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_45_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH4(ftstat_rpt_45, rpt45, chash_c164_dump,
    (char*)0L, (char*)0L, FT_PATH_SYM_ASN, FT_PATH_SYM_ASN,
    "", "input-interface", "output-interface", "source-as", "destination-as",
    "", "");

} /* ftstat_rpt_45_dump */


/* function: ftstat_rpt_45_free
 *
 * Free data structures for report allocated by ftstat_rpt_45_new
 *
 */
void ftstat_rpt_45_free(struct ftstat_rpt_45 *rpt45)
{

  STD_FREE_HASH(rpt45);

} /* ftstat_rpt_45_free */


/* function: ftstat_rpt_46_new
 *
 * Allocate and initialize data structures for rpt 46.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_46 *ftstat_rpt_46_new(struct ftstat_rpt *rpt)
{

  STD_NEW_BUCKET(ftstat_rpt_46, rpt46, 256, rpt);

} /* ftstat_rpt_46_new */


/* function: ftstat_rpt_46_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_46_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_BUCKET1(ftstat_rpt_46, rpt46);
  
  FT_RECGET_ENGINE_ID(cur,rec,*fo);

  STD_ACCUM_BUCKET2(rpt46->bucket, cur.engine_id);

  return 0;

} /* ftstat_rpt_46_accum */

/* function: ftstat_rpt_46_calc
 *
 * Perform final calculations for rpt46
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_46_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_BUCKET(ftstat_rpt_46, rpt46, 256);

} /* ftstat_rpt_46_calc */

/* function: ftstat_rpt_46_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_46_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_BUCKET(ftstat_rpt_46, rpt46, 256, (char*)0L,
    "engine-id", "", "", "", "", "", "");

} /* ftstat_rpt_46_dump */


/* function: ftstat_rpt_46_free
 *
 * Free data structures for report allocated by ftstat_rpt_46_new
 *
 */
void ftstat_rpt_46_free(struct ftstat_rpt_46 *rpt46)
{

  STD_FREE_BUCKET(rpt46);

} /* ftstat_rpt_46_free */


/* function: ftstat_rpt_47_new
 *
 * Allocate and initialize data structures for rpt 47.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_47 *ftstat_rpt_47_new(struct ftstat_rpt *rpt)
{

  STD_NEW_BUCKET(ftstat_rpt_47, rpt47, 256, rpt);

} /* ftstat_rpt_47_new */


/* function: ftstat_rpt_47_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_47_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_BUCKET1(ftstat_rpt_47, rpt47);
   
  FT_RECGET_ENGINE_TYPE(cur,rec,*fo);

  STD_ACCUM_BUCKET2(rpt47->bucket, cur.engine_type);

  return 0;

} /* ftstat_rpt_47_accum */

/* function: ftstat_rpt_47_calc
 *
 * Perform final calculations for rpt47
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_47_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_BUCKET(ftstat_rpt_47, rpt47, 256);

} /* ftstat_rpt_47_calc */

/* function: ftstat_rpt_47_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_47_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_BUCKET(ftstat_rpt_47, rpt47, 256, (char*)0L,
    "engine-type", "", "", "", "", "", "");

} /* ftstat_rpt_47_dump */


/* function: ftstat_rpt_47_free
 *
 * Free data structures for report allocated by ftstat_rpt_47_new
 *
 */
void ftstat_rpt_47_free(struct ftstat_rpt_47 *rpt47)
{

  STD_FREE_BUCKET(rpt47);

} /* ftstat_rpt_47_free */


/* function: ftstat_rpt_48_new
 *
 * Allocate and initialize data structures for rpt 48.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_48 *ftstat_rpt_48_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_48, rpt48, 65536, ftchash_rec_c32, 4, 65536);

} /* ftstat_rpt_48_new */


/* function: ftstat_rpt_48_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_48_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_48, rpt48, ftchash_rec_c32,
    ftch_recc32, ftch_recc32p);

  FT_RECGET_SRC_TAG(cur,rec,*fo);

  ftch_recc32.c32 = cur.src_tag;

  hash = (ftch_recc32.c32>>16) ^ (ftch_recc32.c32 & 0xFFFF);

  STD_ACCUM_HASH2(rpt48, ftch_recc32, ftch_recc32p);
  
  return 0;
   
} /* ftstat_rpt_48_accum */

/* function: ftstat_rpt_48_calc
 *
 * Perform final calculations for rpt48
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_48_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_48, rpt48, ftchash_rec_c32, ftch_recc32);

} /* ftstat_rpt_48_calc */

/* function: ftstat_rpt_48_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_48_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1(ftstat_rpt_48, rpt48, chash_c32_dump, FT_PATH_SYM_TAG,
    "source-tag", "", "", "", "", "", "");

} /* ftstat_rpt_48_dump */


/* function: ftstat_rpt_48_free
 *
 * Free data structures for report allocated by ftstat_rpt_48_new
 *
 */
void ftstat_rpt_48_free(struct ftstat_rpt_48 *rpt48)
{

  STD_FREE_HASH(rpt48);

} /* ftstat_rpt_48_free */


/* function: ftstat_rpt_49_new
 *
 * Allocate and initialize data structures for rpt 49.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_49 *ftstat_rpt_49_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_49, rpt49, 65536, ftchash_rec_c32, 4, 65536);

} /* ftstat_rpt_49_new */


/* function: ftstat_rpt_49_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_49_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_49, rpt49, ftchash_rec_c32,
    ftch_recc32, ftch_recc32p);

  FT_RECGET_DST_TAG(cur,rec,*fo);

  ftch_recc32.c32 = cur.dst_tag;
  
  hash = (ftch_recc32.c32>>16) ^ (ftch_recc32.c32 & 0xFFFF);

  STD_ACCUM_HASH2(rpt49, ftch_recc32, ftch_recc32p);
  
  return 0;
   
} /* ftstat_rpt_49_accum */

/* function: ftstat_rpt_49_calc
 *
 * Perform final calculations for rpt49
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_49_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_49, rpt49, ftchash_rec_c32, ftch_recc32);

} /* ftstat_rpt_49_calc */

/* function: ftstat_rpt_49_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_49_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1(ftstat_rpt_49, rpt49, chash_c32_dump, FT_PATH_SYM_TAG,
    "destination-tag", "", "", "", "", "", "");

} /* ftstat_rpt_49_dump */


/* function: ftstat_rpt_49_free
 *
 * Free data structures for report allocated by ftstat_rpt_49_new
 *
 */
void ftstat_rpt_49_free(struct ftstat_rpt_49 *rpt49)
{

  STD_FREE_HASH(rpt49);

} /* ftstat_rpt_49_free */


/* function: ftstat_rpt_50_new
 *
 * Allocate and initialize data structures for rpt 50.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_50 *ftstat_rpt_50_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_50, rpt50, 65536, ftchash_rec_c322, 8, 65536);

} /* ftstat_rpt_50_new */


/* function: ftstat_rpt_50_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_50_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_50, rpt50, ftchash_rec_c322,
    ftch_recc322, ftch_recc322p);

  FT_RECGET_DST_TAG(cur,rec,*fo);
  FT_RECGET_SRC_TAG(cur,rec,*fo);
 
  ftch_recc322.c32a = cur.src_tag;
  ftch_recc322.c32b = cur.dst_tag;

  hash = (ftch_recc322.c32a>>16) ^ (ftch_recc322.c32a & 0xFFFF) ^
    (ftch_recc322.c32b>>16) ^ (ftch_recc322.c32b & 0xFFFF);

  STD_ACCUM_HASH2(rpt50, ftch_recc322, ftch_recc322p);

  return 0;
   
} /* ftstat_rpt_50_accum */

/* function: ftstat_rpt_50_calc
 *
 * Perform final calculations for rpt50
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_50_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_50, rpt50, ftchash_rec_c322, ftch_recc322);

} /* ftstat_rpt_50_calc */

/* function: ftstat_rpt_50_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_50_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH2(ftstat_rpt_50, rpt50, chash_c322_dump,
    FT_PATH_SYM_TAG, FT_PATH_SYM_TAG,
    "", "source-tag", "destination-tag", "", "", "", "");

} /* ftstat_rpt_50_dump */


/* function: ftstat_rpt_50_free
 *
 * Free data structures for report allocated by ftstat_rpt_50_new
 *
 */
void ftstat_rpt_50_free(struct ftstat_rpt_50 *rpt50)
{

  STD_FREE_HASH(rpt50);

} /* ftstat_rpt_50_free */

/* function: ftstat_rpt_51_new
 * 
 * Allocate and initialize data structures for rpt 51.
 * 
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_51 *ftstat_rpt_51_new(struct ftstat_rpt *rpt)
{
  
  STD_NEW_HASH(ftstat_rpt_51, rpt51, 65536, ftchash_rec_prefix16, 8, 65536);

} /* ftstat_rpt_51_new */

/* function: ftstat_rpt_51_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_51_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_51, rpt51, ftchash_rec_prefix16, ftch_recprefix16,
    ftch_prefix16p);

  FT_RECGET_SRCPORT(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);

  ftch_recprefix16.prefix = cur.srcaddr;
  ftch_recprefix16.c16 = cur.srcport;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix16.mask = cur.src_mask;
  }
 
  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK)
    ftch_recprefix16.prefix &= ipv4_len2mask(ftch_recprefix16.mask);
  
  hash = (ftch_recprefix16.prefix>>16) ^ (ftch_recprefix16.prefix & 0xFFFF) ^
    (ftch_recprefix16.mask) ^ (ftch_recprefix16.c16);

  STD_ACCUM_HASH2(rpt51, ftch_recprefix16, ftch_prefix16p);
   
  return 0;
   
} /* ftstat_rpt_51_accum */

/* function: ftstat_rpt_51_calc
 *
 * Perform final calculations for rpt51
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_51_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_51, rpt51, ftchash_rec_prefix16, ftch_recprefix16); 
 
} /* ftstat_rpt_51_calc */

/* function: ftstat_rpt_51_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_51_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1P(ftstat_rpt_51, rpt51, chash_prefix16_dump,
    FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK,
    FT_PATH_SYM_TCP_PORT,
    "", "ip-source-address", "ip-source-port", "", "", "", "");
 
} /* ftstat_rpt_51_dump */

/* function: ftstat_rpt_51_free
 *
 * Free data structures for report allocated by ftstat_rpt_51_new
 *
 */
void ftstat_rpt_51_free(struct ftstat_rpt_51 *rpt51)
{ 
 
  STD_FREE_HASH(rpt51);
   
} /* ftstat_rpt_51_free */


/* function: ftstat_rpt_52_new
 * 
 * Allocate and initialize data structures for rpt 52.
 * 
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_52 *ftstat_rpt_52_new(struct ftstat_rpt *rpt)
{
  
  STD_NEW_HASH(ftstat_rpt_52, rpt52, 65536, ftchash_rec_prefix16, 8, 65536);

} /* ftstat_rpt_52_new */

/* function: ftstat_rpt_52_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_52_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_52, rpt52, ftchash_rec_prefix16, ftch_recprefix16,
    ftch_prefix16p);
    
  FT_RECGET_DSTPORT(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);
  
  ftch_recprefix16.prefix = cur.srcaddr;
  ftch_recprefix16.c16 = cur.dstport;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix16.mask = cur.src_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK)
    ftch_recprefix16.prefix &= ipv4_len2mask(ftch_recprefix16.mask);
    
  hash = (ftch_recprefix16.prefix>>16) ^ (ftch_recprefix16.prefix & 0xFFFF) ^
    (ftch_recprefix16.mask) ^ (ftch_recprefix16.c16);

  STD_ACCUM_HASH2(rpt52, ftch_recprefix16, ftch_prefix16p);

  return 0;
   
} /* ftstat_rpt_52_accum */

/* function: ftstat_rpt_52_calc
 *
 * Perform final calculations for rpt52
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_52_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_52, rpt52, ftchash_rec_prefix16, ftch_recprefix16);
 
} /* ftstat_rpt_52_calc */

/* function: ftstat_rpt_52_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_52_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1P(ftstat_rpt_51, rpt51, chash_prefix16_dump,
    FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK,
    FT_PATH_SYM_TCP_PORT,
    "", "ip-source-address", "ip-destination-port", "", "", "", "");

} /* ftstat_rpt_52_dump */

/* function: ftstat_rpt_52_free
 *
 * Free data structures for report allocated by ftstat_rpt_52_new
 *
 */
void ftstat_rpt_52_free(struct ftstat_rpt_52 *rpt52)
{ 
 
  STD_FREE_HASH(rpt52);
   
} /* ftstat_rpt_52_free */

/* function: ftstat_rpt_53_new
 * 
 * Allocate and initialize data structures for rpt 53.
 * 
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_53 *ftstat_rpt_53_new(struct ftstat_rpt *rpt)
{
  
  STD_NEW_HASH(ftstat_rpt_53, rpt53, 65536, ftchash_rec_prefix16, 8, 65536);

} /* ftstat_rpt_53_new */

/* function: ftstat_rpt_53_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_53_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_53, rpt53, ftchash_rec_prefix16, ftch_recprefix16,
    ftch_prefix16p);
    
  FT_RECGET_SRCPORT(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);
  
  ftch_recprefix16.prefix = cur.dstaddr;
  ftch_recprefix16.c16 = cur.srcport;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix16.mask = cur.dst_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK)
    ftch_recprefix16.prefix &= ipv4_len2mask(ftch_recprefix16.mask);

  hash = (ftch_recprefix16.prefix>>16) ^ (ftch_recprefix16.prefix & 0xFFFF) ^
    (ftch_recprefix16.mask) ^ (ftch_recprefix16.c16);

  STD_ACCUM_HASH2(rpt53, ftch_recprefix16, ftch_prefix16p);

  return 0;
   
} /* ftstat_rpt_53_accum */

/* function: ftstat_rpt_53_calc
 *
 * Perform final calculations for rpt53
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_53_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_53, rpt53, ftchash_rec_prefix16, ftch_recprefix16);

} /* ftstat_rpt_53_calc */

/* function: ftstat_rpt_53_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_53_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1P(ftstat_rpt_53, rpt53, chash_prefix16_dump,
    FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK,
    FT_PATH_SYM_TCP_PORT,
    "", "ip-destination-address", "ip-source-port", "", "", "", "");

} /* ftstat_rpt_53_dump */

/* function: ftstat_rpt_53_free
 *
 * Free data structures for report allocated by ftstat_rpt_53_new
 *
 */
void ftstat_rpt_53_free(struct ftstat_rpt_53 *rpt53)
{ 
 
  STD_FREE_HASH(rpt53);
   
} /* ftstat_rpt_53_free */


/* function: ftstat_rpt_54_new
 * 
 * Allocate and initialize data structures for rpt 52.
 * 
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_54 *ftstat_rpt_54_new(struct ftstat_rpt *rpt)
{
  
  STD_NEW_HASH(ftstat_rpt_54, rpt54, 65536, ftchash_rec_prefix16, 8, 65536);

} /* ftstat_rpt_54_new */

/* function: ftstat_rpt_54_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_54_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_54, rpt54, ftchash_rec_prefix16, ftch_recprefix16,
    ftch_prefix16p);
    
  FT_RECGET_DSTPORT(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);
  
  ftch_recprefix16.prefix = cur.dstaddr;
  ftch_recprefix16.c16 = cur.dstport;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix16.mask = cur.dst_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK)
    ftch_recprefix16.prefix &= ipv4_len2mask(ftch_recprefix16.mask);

  hash = (ftch_recprefix16.prefix>>16) ^ (ftch_recprefix16.prefix & 0xFFFF) ^
    (ftch_recprefix16.mask) ^ (ftch_recprefix16.c16);

  STD_ACCUM_HASH2(rpt54, ftch_recprefix16, ftch_prefix16p);

  return 0;
   
} /* ftstat_rpt_54_accum */

/* function: ftstat_rpt_54_calc
 *
 * Perform final calculations for rpt54
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_54_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_54, rpt54, ftchash_rec_prefix16, ftch_recprefix16);
 
} /* ftstat_rpt_54_calc */

/* function: ftstat_rpt_54_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_54_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1P(ftstat_rpt_54, rpt54, chash_prefix16_dump,
    FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK,
    FT_PATH_SYM_TCP_PORT,
    "", "ip-destination-address", "ip-destination-port", "", "", "", "");

} /* ftstat_rpt_54_dump */

/* function: ftstat_rpt_54_free
 *
 * Free data structures for report allocated by ftstat_rpt_54_new
 *
 */
void ftstat_rpt_54_free(struct ftstat_rpt_54 *rpt54)
{ 
 
  STD_FREE_HASH(rpt54);
   
} /* ftstat_rpt_54_free */


/* function: ftstat_rpt_55_new
 * 
 * Allocate and initialize data structures for rpt 52.
 * 
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_55 *ftstat_rpt_55_new(struct ftstat_rpt *rpt)
{
  
  STD_NEW_HASH(ftstat_rpt_55, rpt55, 65536, ftchash_rec_prefix162, 10, 65536);

} /* ftstat_rpt_55_new */

/* function: ftstat_rpt_55_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_55_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_55, rpt55, ftchash_rec_prefix162,
    ftch_recprefix162, ftch_prefix162p);
    
  FT_RECGET_SRCPORT(cur,rec,*fo);
  FT_RECGET_DSTPORT(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);
  
  ftch_recprefix162.prefix = cur.srcaddr;
  ftch_recprefix162.c16a = cur.srcport;
  ftch_recprefix162.c16b = cur.dstport;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix162.mask = cur.src_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK)
    ftch_recprefix162.prefix &= ipv4_len2mask(ftch_recprefix162.mask);

  hash = (ftch_recprefix162.prefix>>16) ^ (ftch_recprefix162.prefix & 0xFFFF) ^
    (ftch_recprefix162.mask) ^ (ftch_recprefix162.c16a) ^ 
    (ftch_recprefix162.c16b);

  STD_ACCUM_HASH2(rpt55, ftch_recprefix162, ftch_prefix162p);

  return 0;
   
} /* ftstat_rpt_55_accum */

/* function: ftstat_rpt_55_calc
 *
 * Perform final calculations for rpt55
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_55_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_55, rpt55, ftchash_rec_prefix162,
    ftch_recprefix162);
 
} /* ftstat_rpt_55_calc */

/* function: ftstat_rpt_55_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_55_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH2P(ftstat_rpt_55, rpt55, chash_prefix162_dump,
    FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK,
    FT_PATH_SYM_TCP_PORT, FT_PATH_SYM_TCP_PORT,
    "", "ip-source-address", "ip-source-port", "ip-destination-port", "", "",
    "");
 
} /* ftstat_rpt_55_dump */

/* function: ftstat_rpt_55_free
 *
 * Free data structures for report allocated by ftstat_rpt_55_new
 *
 */
void ftstat_rpt_55_free(struct ftstat_rpt_55 *rpt55)
{ 
 
  STD_FREE_HASH(rpt55);
   
} /* ftstat_rpt_55_free */


/* function: ftstat_rpt_56_new
 * 
 * Allocate and initialize data structures for rpt 52.
 * 
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_56 *ftstat_rpt_56_new(struct ftstat_rpt *rpt)
{
  
  STD_NEW_HASH(ftstat_rpt_56, rpt56, 65536, ftchash_rec_prefix162, 10, 65536);

} /* ftstat_rpt_56_new */

/* function: ftstat_rpt_56_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_56_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_56, rpt56, ftchash_rec_prefix162,
    ftch_recprefix162, ftch_prefix162p);

  FT_RECGET_SRCPORT(cur,rec,*fo);
  FT_RECGET_DSTPORT(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);
    
  ftch_recprefix162.prefix = cur.dstaddr;
  ftch_recprefix162.c16a = cur.srcport;
  ftch_recprefix162.c16b = cur.dstport;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix162.mask = cur.dst_mask; 
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK)
    ftch_recprefix162.prefix &= ipv4_len2mask(ftch_recprefix162.mask);
    
  hash = (ftch_recprefix162.prefix>>16) ^ (ftch_recprefix162.prefix & 0xFFFF) ^
    (ftch_recprefix162.mask) ^ (ftch_recprefix162.c16a) ^
    (ftch_recprefix162.c16b);   
  
  STD_ACCUM_HASH2(rpt56, ftch_recprefix162, ftch_prefix162p);

  return 0;
   
} /* ftstat_rpt_56_accum */

/* function: ftstat_rpt_56_calc
 *
 * Perform final calculations for rpt56
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_56_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_56, rpt56, ftchash_rec_prefix162,
    ftch_recprefix162);
 
} /* ftstat_rpt_56_calc */

/* function: ftstat_rpt_56_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_56_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH2P(ftstat_rpt_56, rpt56, chash_prefix162_dump,
    FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK,
    FT_PATH_SYM_TCP_PORT, FT_PATH_SYM_TCP_PORT,
    "", "ip-destination-address", "ip-source-port", "ip-destination-port", "",
    "", "");

} /* ftstat_rpt_56_dump */

/* function: ftstat_rpt_56_free
 *
 * Free data structures for report allocated by ftstat_rpt_56_new
 *
 */
void ftstat_rpt_56_free(struct ftstat_rpt_56 *rpt56)
{ 
 
  STD_FREE_HASH(rpt56);
   
} /* ftstat_rpt_56_free */


/* function: ftstat_rpt_57_new
 * 
 * Allocate and initialize data structures for rpt 52.
 * 
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_57 *ftstat_rpt_57_new(struct ftstat_rpt *rpt)
{
  
  STD_NEW_HASH(ftstat_rpt_57, rpt57, 65536, ftchash_rec_prefix216, 13, 65536);

} /* ftstat_rpt_57_new */

/* function: ftstat_rpt_57_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_57_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_57, rpt57, ftchash_rec_prefix216,
    ftch_recprefix216, ftch_recprefix216p);
 
  FT_RECGET_SRCPORT(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);

  ftch_recprefix216.src_prefix = cur.srcaddr;
  ftch_recprefix216.dst_prefix = cur.dstaddr;
  ftch_recprefix216.c16 = cur.srcport;
  
  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix216.src_mask = cur.src_mask;
  }

  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix216.dst_mask = cur.dst_mask;
  }
  
  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK) {
    ftch_recprefix216.src_prefix &= ipv4_len2mask(ftch_recprefix216.src_mask);
  }

  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK) {
    ftch_recprefix216.dst_prefix &= ipv4_len2mask(ftch_recprefix216.dst_mask);
  }
  
  hash = (ftch_recprefix216.src_prefix>>16)^
          (ftch_recprefix216.src_prefix & 0xFFFF)^
          (ftch_recprefix216.dst_prefix>>16)^
          (ftch_recprefix216.dst_prefix & 0xFFFF)^
          (ftch_recprefix216.c16)^
          (ftch_recprefix216.src_mask)^
          (u_int32)(ftch_recprefix216.dst_mask<<8);
 
  STD_ACCUM_HASH2(rpt57, ftch_recprefix216, ftch_recprefix216p);

  return 0;
   
} /* ftstat_rpt_57_accum */

/* function: ftstat_rpt_57_calc
 *
 * Perform final calculations for rpt57
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_57_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_57, rpt57, ftchash_rec_prefix216,
    ftch_recprefix216);

} /* ftstat_rpt_57_calc */

/* function: ftstat_rpt_57_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_57_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1(ftstat_rpt_57, rpt57, chash_prefix216_dump,
    FT_PATH_SYM_TCP_PORT,
    "", "ip-source-address", "ip-destination-address", "ip-source-port", "",
    "", "");

} /* ftstat_rpt_57_dump */

/* function: ftstat_rpt_57_free
 *
 * Free data structures for report allocated by ftstat_rpt_57_new
 *
 */
void ftstat_rpt_57_free(struct ftstat_rpt_57 *rpt57)
{ 
 
  STD_FREE_HASH(rpt57);
   
} /* ftstat_rpt_57_free */

/* function: ftstat_rpt_58_new
 * 
 * Allocate and initialize data structures for rpt 58.
 * 
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_58 *ftstat_rpt_58_new(struct ftstat_rpt *rpt)
{
  
  STD_NEW_HASH(ftstat_rpt_58, rpt58, 65536, ftchash_rec_prefix216, 13, 65536);

} /* ftstat_rpt_58_new */

/* function: ftstat_rpt_58_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_58_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_58, rpt58, ftchash_rec_prefix216,
    ftch_recprefix216, ftch_recprefix216p);

  FT_RECGET_DSTPORT(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);

  ftch_recprefix216.src_prefix = cur.srcaddr;
  ftch_recprefix216.dst_prefix = cur.dstaddr;
  ftch_recprefix216.c16 = cur.dstport;
 
  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix216.src_mask = cur.src_mask;
  }

  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix216.dst_mask = cur.dst_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK) {
    ftch_recprefix216.src_prefix &= ipv4_len2mask(ftch_recprefix216.src_mask);
  }

  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK) {
    ftch_recprefix216.dst_prefix &= ipv4_len2mask(ftch_recprefix216.dst_mask);
  }

  hash = (ftch_recprefix216.src_prefix>>16)^
          (ftch_recprefix216.src_prefix & 0xFFFF)^
          (ftch_recprefix216.dst_prefix>>16)^
          (ftch_recprefix216.dst_prefix & 0xFFFF)^
          (ftch_recprefix216.c16)^
          (ftch_recprefix216.src_mask)^
          (u_int32)(ftch_recprefix216.dst_mask<<8);
  
  STD_ACCUM_HASH2(rpt58, ftch_recprefix216, ftch_recprefix216p);

  return 0;
   
} /* ftstat_rpt_58_accum */

/* function: ftstat_rpt_58_calc
 *
 * Perform final calculations for rpt58
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_58_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_58, rpt58, ftchash_rec_prefix216,
    ftch_recprefix216);

} /* ftstat_rpt_58_calc */

/* function: ftstat_rpt_58_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_58_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1(ftstat_rpt_58, rpt58, chash_prefix216_dump,
    FT_PATH_SYM_TCP_PORT,
    "", "ip-source-address", "ip-destination-address", "ip-destination-port",
    "", "", "");

} /* ftstat_rpt_58_dump */

/* function: ftstat_rpt_58_free
 *
 * Free data structures for report allocated by ftstat_rpt_58_new
 *
 */
void ftstat_rpt_58_free(struct ftstat_rpt_58 *rpt58)
{ 
 
  STD_FREE_HASH(rpt58);
   
} /* ftstat_rpt_58_free */



/* function: ftstat_rpt_59_new
 * 
 * Allocate and initialize data structures for rpt 52.
 * 
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_59 *ftstat_rpt_59_new(struct ftstat_rpt *rpt)
{
  
  STD_NEW_HASH(ftstat_rpt_59, rpt59, 65536, ftchash_rec_prefix2162, 16, 65536);

} /* ftstat_rpt_59_new */

/* function: ftstat_rpt_59_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_59_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_59, rpt59, ftchash_rec_prefix2162,
    ftch_recprefix2162, ftch_recprefix2162p);
 
  FT_RECGET_SRCPORT(cur,rec,*fo);
  FT_RECGET_DSTPORT(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);
  
  ftch_recprefix2162.src_prefix = cur.srcaddr;
  ftch_recprefix2162.dst_prefix = cur.dstaddr;
  ftch_recprefix2162.c16a = cur.srcport;
  ftch_recprefix2162.c16b = cur.dstport;
  
  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix2162.src_mask = cur.src_mask;
  }

  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix2162.dst_mask = cur.dst_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK) {
    ftch_recprefix2162.src_prefix &= ipv4_len2mask(ftch_recprefix2162.src_mask);
  }

  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK) {
    ftch_recprefix2162.dst_prefix &= ipv4_len2mask(ftch_recprefix2162.dst_mask);
  }
  
  hash = (ftch_recprefix2162.src_prefix>>16)^
          (ftch_recprefix2162.src_prefix & 0xFFFF)^
          (ftch_recprefix2162.dst_prefix>>16)^
          (ftch_recprefix2162.dst_prefix & 0xFFFF)^
          (ftch_recprefix2162.c16b)^
          (ftch_recprefix2162.c16a)^
          (ftch_recprefix2162.src_mask)^
          (u_int32)(ftch_recprefix2162.dst_mask<<8);

  STD_ACCUM_HASH2(rpt59, ftch_recprefix2162, ftch_recprefix2162p);

  return 0;
   
} /* ftstat_rpt_59_accum */

/* function: ftstat_rpt_59_calc
 *
 * Perform final calculations for rpt59
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_59_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_59, rpt59, ftchash_rec_prefix2162,
    ftch_recprefix2162);
 
} /* ftstat_rpt_59_calc */

/* function: ftstat_rpt_59_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_59_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH2(ftstat_rpt_31, rpt31, chash_prefix2162_dump,
    FT_PATH_SYM_TCP_PORT, FT_PATH_SYM_TCP_PORT,
    "", "ip-source-address", "ip-destination-address", "ip-source-port",
    "ip-destination-port", "", "");

} /* ftstat_rpt_59_dump */

/* function: ftstat_rpt_59_free
 *
 * Free data structures for report allocated by ftstat_rpt_59_new
 *
 */
void ftstat_rpt_59_free(struct ftstat_rpt_59 *rpt59)
{ 
 
  STD_FREE_HASH(rpt59);
   
} /* ftstat_rpt_59_free */


/* function: ftstat_rpt_60_new
 * 
 * Allocate and initialize data structures for rpt 52.
 * 
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_60 *ftstat_rpt_60_new(struct ftstat_rpt *rpt)
{
  
  STD_NEW_HASH(ftstat_rpt_60, rpt60, 65536, ftchash_rec_prefix162, 10, 65536);

} /* ftstat_rpt_60_new */

/* function: ftstat_rpt_60_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_60_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_60, rpt60, ftchash_rec_prefix162,
    ftch_recprefix162, ftch_prefix162p);

  FT_RECGET_INPUT(cur,rec,*fo);
  FT_RECGET_OUTPUT(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);
  
  ftch_recprefix162.prefix = cur.srcaddr;
  ftch_recprefix162.c16a = cur.input;
  ftch_recprefix162.c16b = cur.output;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix162.mask = cur.src_mask; 
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK)
    ftch_recprefix162.prefix &= ipv4_len2mask(ftch_recprefix162.mask);
 
  hash = (ftch_recprefix162.prefix>>16) ^ (ftch_recprefix162.prefix & 0xFFFF) ^
    (ftch_recprefix162.mask) ^ (ftch_recprefix162.c16a) ^
    (ftch_recprefix162.c16b);   
   
  STD_ACCUM_HASH2(rpt60, ftch_recprefix162, ftch_prefix162p);

  return 0;
   
} /* ftstat_rpt_60_accum */

/* function: ftstat_rpt_60_calc
 *
 * Perform final calculations for rpt60
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_60_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_60, rpt60, ftchash_rec_prefix162,
    ftch_recprefix162);

} /* ftstat_rpt_60_calc */

/* function: ftstat_rpt_60_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_60_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH2P(ftstat_rpt_60, rpt60, chash_prefix162_dump,
    FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK,
    (char*)0L, (char*)0L,
    "", "ip-source-address", "input-interface", "output-interface", "", "",
    "");

} /* ftstat_rpt_60_dump */

/* function: ftstat_rpt_60_free
 *
 * Free data structures for report allocated by ftstat_rpt_60_new
 *
 */
void ftstat_rpt_60_free(struct ftstat_rpt_60 *rpt60)
{ 
 
  STD_FREE_HASH(rpt60);
   
} /* ftstat_rpt_60_free */


/* function: ftstat_rpt_61_new
 * 
 * Allocate and initialize data structures for rpt 52.
 * 
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_61 *ftstat_rpt_61_new(struct ftstat_rpt *rpt)
{
  
  STD_NEW_HASH(ftstat_rpt_61, rpt61, 65536, ftchash_rec_prefix162, 10, 65536);

} /* ftstat_rpt_61_new */

/* function: ftstat_rpt_61_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_61_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_61, rpt61, ftchash_rec_prefix162,
    ftch_recprefix162, ftch_prefix162p);

  FT_RECGET_INPUT(cur,rec,*fo);
  FT_RECGET_OUTPUT(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);
 
  ftch_recprefix162.prefix = cur.dstaddr;
  ftch_recprefix162.c16a = cur.input;
  ftch_recprefix162.c16b = cur.output;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix162.mask = cur.dst_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK)
    ftch_recprefix162.prefix &= ipv4_len2mask(ftch_recprefix162.mask);

  hash = (ftch_recprefix162.prefix>>16) ^ (ftch_recprefix162.prefix & 0xFFFF) ^
    (ftch_recprefix162.mask) ^ (ftch_recprefix162.c16a) ^
    (ftch_recprefix162.c16b);

  STD_ACCUM_HASH2(rpt61, ftch_recprefix162, ftch_prefix162p);

  return 0;
   
} /* ftstat_rpt_61_accum */

/* function: ftstat_rpt_61_calc
 *
 * Perform final calculations for rpt61
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_61_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_61, rpt61, ftchash_rec_prefix162,
    ftch_recprefix162);

} /* ftstat_rpt_61_calc */

/* function: ftstat_rpt_61_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_61_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH2P(ftstat_rpt_61, rpt61, chash_prefix162_dump,
    FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK,
    (char*)0L, (char*)0L,
    "", "ip-destination-address", "input-interface", "output-interface", "",
    "", "");
   
} /* ftstat_rpt_61_dump */

/* function: ftstat_rpt_61_free
 *
 * Free data structures for report allocated by ftstat_rpt_61_new
 *
 */
void ftstat_rpt_61_free(struct ftstat_rpt_61 *rpt61)
{ 
 
  STD_FREE_HASH(rpt61);
   
} /* ftstat_rpt_61_free */


/* function: ftstat_rpt_62_new
 * 
 * Allocate and initialize data structures for rpt 52.
 * 
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_62 *ftstat_rpt_62_new(struct ftstat_rpt *rpt)
{
  
  STD_NEW_HASH(ftstat_rpt_62, rpt62, 65536, ftchash_rec_prefix162, 10, 65536);

} /* ftstat_rpt_62_new */

/* function: ftstat_rpt_62_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_62_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_62, rpt62, ftchash_rec_prefix162,
    ftch_recprefix162, ftch_prefix162p);

  FT_RECGET_SRC_AS(cur,rec,*fo);
  FT_RECGET_DST_AS(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);
 
  ftch_recprefix162.prefix = cur.srcaddr;
  ftch_recprefix162.c16a = cur.src_as;
  ftch_recprefix162.c16b = cur.dst_as;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix162.mask = cur.src_mask; 
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK)
    ftch_recprefix162.prefix &= ipv4_len2mask(ftch_recprefix162.mask);

  hash = (ftch_recprefix162.prefix>>16) ^ (ftch_recprefix162.prefix & 0xFFFF) ^
    (ftch_recprefix162.mask) ^ (ftch_recprefix162.c16a) ^
    (ftch_recprefix162.c16b);   
  
  STD_ACCUM_HASH2(rpt62, ftch_recprefix162, ftch_prefix162p);

  return 0;
   
} /* ftstat_rpt_62_accum */

/* function: ftstat_rpt_62_calc
 *
 * Perform final calculations for rpt62
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_62_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_62, rpt55, ftchash_rec_prefix162,
    ftch_recprefix162);
 
} /* ftstat_rpt_62_calc */

/* function: ftstat_rpt_62_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_62_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH2P(ftstat_rpt_62, rpt62, chash_prefix162_dump,
    FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK,
    FT_PATH_SYM_ASN, FT_PATH_SYM_ASN,
    "", "ip-source-address", "source-as", "destination-as", "", "", "");

} /* ftstat_rpt_62_dump */

/* function: ftstat_rpt_62_free
 *
 * Free data structures for report allocated by ftstat_rpt_62_new
 *
 */
void ftstat_rpt_62_free(struct ftstat_rpt_62 *rpt62)
{ 
 
  STD_FREE_HASH(rpt62);
   
} /* ftstat_rpt_62_free */

/* function: ftstat_rpt_63_new
 * 
 * Allocate and initialize data structures for rpt 63
 * 
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_63 *ftstat_rpt_63_new(struct ftstat_rpt *rpt)
{
  
  STD_NEW_HASH(ftstat_rpt_63, rpt63, 65536, ftchash_rec_prefix162, 10, 65536);

} /* ftstat_rpt_63_new */

/* function: ftstat_rpt_63_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_63_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_63, rpt63, ftchash_rec_prefix162,
    ftch_recprefix162, ftch_prefix162p);

  FT_RECGET_SRC_AS(cur,rec,*fo);
  FT_RECGET_DST_AS(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);
 
  ftch_recprefix162.prefix = cur.dstaddr;
  ftch_recprefix162.c16a = cur.src_as;
  ftch_recprefix162.c16b = cur.dst_as;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix162.mask = cur.dst_mask; 
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK)
    ftch_recprefix162.prefix &= ipv4_len2mask(ftch_recprefix162.mask);

  hash = (ftch_recprefix162.prefix>>16) ^ (ftch_recprefix162.prefix & 0xFFFF) ^
    (ftch_recprefix162.mask) ^ (ftch_recprefix162.c16a) ^
    (ftch_recprefix162.c16b);   
  
  STD_ACCUM_HASH2(rpt63, ftch_recprefix162, ftch_prefix162p);

  return 0;
   
} /* ftstat_rpt_63_accum */

/* function: ftstat_rpt_63_calc
 *
 * Perform final calculations for rpt63
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_63_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_63, rpt55, ftchash_rec_prefix162,
    ftch_recprefix162);
 
} /* ftstat_rpt_63_calc */

/* function: ftstat_rpt_63_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_63_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH2P(ftstat_rpt_63, rpt63, chash_prefix162_dump,
    FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK,
    FT_PATH_SYM_ASN, FT_PATH_SYM_ASN,
    "", "ip-destination-address", "source-as", "destination-as", "", "", "");

} /* ftstat_rpt_63_dump */

/* function: ftstat_rpt_63_free
 *
 * Free data structures for report allocated by ftstat_rpt_62_new
 *
 */
void ftstat_rpt_63_free(struct ftstat_rpt_63 *rpt63)
{ 
 
  STD_FREE_HASH(rpt63);
   
} /* ftstat_rpt_63_free */

/* function: ftstat_rpt_64_new
 *
 * Allocate and initialize data structures for rpt 15.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_64 *ftstat_rpt_64_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_64, rpt64, 65536, ftchash_rec_prefix, 5, 65536);

} /* ftstat_rpt_64_new */


/* function: ftstat_rpt_64_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_64_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_64, rpt64, ftchash_rec_prefix, ftch_recprefix,
    ftch_recprefixp);

  FT_RECGET_SRCADDR(cur,rec,*fo);
 
  ftch_recprefix.prefix = cur.srcaddr;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix.mask = cur.src_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK)
    ftch_recprefix.prefix &= ipv4_len2mask(ftch_recprefix.mask);

  hash = (ftch_recprefix.prefix>>16) ^ (ftch_recprefix.prefix & 0xFFFF);
  hash = hash ^ (ftch_recprefix.mask);

  STD_ACCUM_HASH2(rpt64, ftch_recprefix, ftch_recprefixp);

  bzero(&ftch_recprefix, sizeof ftch_recprefix);

  FT_RECGET_DSTADDR(cur,rec,*fo);
 
  ftch_recprefix.prefix = cur.dstaddr;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix.mask = cur.dst_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK)
    ftch_recprefix.prefix &= ipv4_len2mask(ftch_recprefix.mask);

  hash = (ftch_recprefix.prefix>>16) ^ (ftch_recprefix.prefix & 0xFFFF);
  hash = hash ^ (ftch_recprefix.mask);

  STD_ACCUM_HASH2(rpt64, ftch_recprefix, ftch_recprefixp);

  return 0;
   
} /* ftstat_rpt_64_accum */

/* function: ftstat_rpt_64_calc
 *
 * Perform final calculations for rpt64
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_64_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_64, rpt64, ftchash_rec_prefix, ftch_recprefix);

} /* ftstat_rpt_64_calc */

/* function: ftstat_rpt_64_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_64_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH0P(ftstat_rpt_64, rpt64, chash_prefix_dump,
    FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK|
    FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK,
    "ip-address", "", "", "", "", "", "");

} /* ftstat_rpt_64_dump */


/* function: ftstat_rpt_64_free
 *
 * Free data structures for report allocated by ftstat_rpt_64_new
 *
 */
void ftstat_rpt_64_free(struct ftstat_rpt_64 *rpt64)
{

  STD_FREE_HASH(rpt64);

} /* ftstat_rpt_64_free */

/* function: ftstat_rpt_65_new
 *
 * Allocate and initialize data structures for rpt 6.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_65 *ftstat_rpt_65_new(struct ftstat_rpt *rpt)
{

  STD_NEW_BUCKET(ftstat_rpt_65, rpt65, 65536, rpt);

} /* ftstat_rpt_65_new */


/* function: ftstat_rpt_65_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_65_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_BUCKET1(ftstat_rpt_65, rpt65);

  FT_RECGET_SRCPORT(cur,rec,*fo);

  STD_ACCUM_BUCKET2(rpt65->bucket, cur.srcport);

  FT_RECGET_DSTPORT(cur,rec,*fo);

  STD_ACCUM_BUCKET2(rpt65->bucket, cur.dstport);

  return 0;

} /* ftstat_rpt_65_accum */

/* function: ftstat_rpt_65_calc
 *
 * Perform final calculations for rpt65
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_65_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_BUCKET(ftstat_rpt_65, rpt65, 65536);

} /* ftstat_rpt_65_calc */

/* function: ftstat_rpt_65_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_65_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_BUCKET(ftstat_rpt_65, rpt65, 65536, FT_PATH_SYM_TCP_PORT,
    "ip-port", "", "", "", "", "", "");

} /* ftstat_rpt_65_dump */


/* function: ftstat_rpt_65_free
 *
 * Free data structures for report allocated by ftstat_rpt_65_new
 *
 */
void ftstat_rpt_65_free(struct ftstat_rpt_65 *rpt65)
{

  STD_FREE_BUCKET(rpt65);

} /* ftstat_rpt_65_free */

/* function: ftstat_rpt_66_new
 *
 * Allocate and initialize data structures for rpt 15.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_66 *ftstat_rpt_66_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_66, rpt66, 65536, ftchash_rec_prefixh, 5, 65536);

} /* ftstat_rpt_66_new */


/* function: ftstat_rpt_66_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_66_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{
  struct ftchash_rec_prefixs *ftch_recprefixsp, ftch_recprefixs;

  STD_ACCUM_HASH1(ftstat_rpt_66, rpt66, ftchash_rec_prefixh, ftch_recprefixh,
    ftch_recprefixhp);

  FT_RECGET_SRCADDR(cur,rec,*fo);
 
  ftch_recprefixh.prefix = cur.srcaddr;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefixh.mask = cur.src_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK)
    ftch_recprefixh.prefix &= ipv4_len2mask(ftch_recprefixh.mask);

  hash = (ftch_recprefixh.prefix>>16) ^ (ftch_recprefixh.prefix & 0xFFFF);
  hash = hash ^ (ftch_recprefixh.mask);

  STD_ACCUM_HASH2(rpt66, ftch_recprefixh, ftch_recprefixhp);

  /* new second hash */
  if (!ftch_recprefixhp->ftch) {
    if (!(ftch_recprefixhp->ftch = ftchash_new(256,
      sizeof (struct ftchash_rec_prefixs), 5, 64))) {
      fterr_warnx("ftchash_new(): failed");
      return -1;
    }
  }

  FT_RECGET_DSTADDR(cur,rec,*fo);

  bzero(&ftch_recprefixs, sizeof ftch_recprefixs);
 
  ftch_recprefixs.prefix = cur.dstaddr;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefixs.mask = cur.dst_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK)
    ftch_recprefixs.prefix &= ipv4_len2mask(ftch_recprefixs.mask);

  hash = (ftch_recprefixs.prefix>>16) ^ (ftch_recprefixs.prefix & 0xFFFF);
  hash = hash ^ (ftch_recprefixs.mask);
  hash = (hash >> 8) ^ (hash & 0xFF);

  if (!(ftch_recprefixsp = ftchash_update(ftch_recprefixhp->ftch,
    &ftch_recprefixs, hash))) {
    fterr_warnx("ftch_update(): failed");
    return -1;
  }

  return 0;
   
} /* ftstat_rpt_66_accum */

/* function: ftstat_rpt_66_calc
 *
 * Perform final calculations for rpt66
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_66_calc(struct ftstat_rpt *rpt)
{
  struct ftchash_rec_prefixh *ftch_recprefixh;
  struct ftstat_rpt_66 *rpt66;

  rpt66 = rpt->data;

  STD_CALC;

  rpt->recs = rpt66->ftch->entries;

  ftchash_first(rpt66->ftch);

  while ((ftch_recprefixh = ftchash_foreach(rpt66->ftch))) {

    if (ftch_recprefixh->etime) {
      if (rpt->all_fields & FT_STAT_FIELD_PS) {
        ftch_recprefixh->ps.avg_pps /= (double)ftch_recprefixh->nrecs;
        ftch_recprefixh->ps.avg_bps /= (double)ftch_recprefixh->nrecs;
      }
    }

    ftch_recprefixh->nprefixes = ftch_recprefixh->ftch->entries;
    rpt->t_count += ftch_recprefixh->ftch->entries;
    
  }

  return 0;

} /* ftstat_rpt_66_calc */

/* function: ftstat_rpt_66_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_66_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH0P(ftstat_rpt_66, rpt66, chash_prefixh_dump,
    FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK,
    "ip-source-address", "ip-destination-address-count", "", "", "", "", "");

} /* ftstat_rpt_66_dump */


/* function: ftstat_rpt_66_free
 *
 * Free data structures for report allocated by ftstat_rpt_66_new
 *
 */
void ftstat_rpt_66_free(struct ftstat_rpt_66 *rpt66)
{
  struct ftchash_rec_prefixh *ftch_recprefixh;

  if (rpt66) {

    if (rpt66->ftch) {

      ftchash_first(rpt66->ftch);

      while ((ftch_recprefixh = ftchash_foreach(rpt66->ftch))) {

        if (ftch_recprefixh->ftch)
          ftchash_free(ftch_recprefixh->ftch);

      }

      ftchash_free(rpt66->ftch);

    }

    free (rpt66);

  }

} /* ftstat_rpt_66_free */

/* function: ftstat_rpt_67_new
 *
 * Allocate and initialize data structures for rpt 15.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_67 *ftstat_rpt_67_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_67, rpt67, 65536, ftchash_rec_prefixh, 5, 65536);

} /* ftstat_rpt_67_new */


/* function: ftstat_rpt_67_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_67_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{
  struct ftchash_rec_prefixs *ftch_recprefixsp, ftch_recprefixs;

  STD_ACCUM_HASH1(ftstat_rpt_67, rpt67, ftchash_rec_prefixh, ftch_recprefixh,
    ftch_recprefixhp);

  FT_RECGET_DSTADDR(cur,rec,*fo);
 
  ftch_recprefixh.prefix = cur.dstaddr;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefixh.mask = cur.dst_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK)
    ftch_recprefixh.prefix &= ipv4_len2mask(ftch_recprefixh.mask);

  hash = (ftch_recprefixh.prefix>>16) ^ (ftch_recprefixh.prefix & 0xFFFF);
  hash = hash ^ (ftch_recprefixh.mask);

  STD_ACCUM_HASH2(rpt67, ftch_recprefixh, ftch_recprefixhp);

  /* new second hash */
  if (!ftch_recprefixhp->ftch) {
    if (!(ftch_recprefixhp->ftch = ftchash_new(256,
      sizeof (struct ftchash_rec_prefixs), 5, 64))) {
      fterr_warnx("ftchash_new(): failed");
      return -1;
    }
  }

  FT_RECGET_SRCADDR(cur,rec,*fo);

  bzero(&ftch_recprefixs, sizeof ftch_recprefixs);
 
  ftch_recprefixs.prefix = cur.srcaddr;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefixs.mask = cur.src_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK)
    ftch_recprefixs.prefix &= ipv4_len2mask(ftch_recprefixs.mask);

  hash = (ftch_recprefixs.prefix>>16) ^ (ftch_recprefixs.prefix & 0xFFFF);
  hash = hash ^ (ftch_recprefixs.mask);
  hash = (hash >> 8) ^ (hash & 0xFF);

  if (!(ftch_recprefixsp = ftchash_update(ftch_recprefixhp->ftch,
    &ftch_recprefixs, hash))) {
    fterr_warnx("ftch_update(): failed");
    return -1;
  }

  return 0;
   
} /* ftstat_rpt_67_accum */

/* function: ftstat_rpt_67_calc
 *
 * Perform final calculations for rpt67
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_67_calc(struct ftstat_rpt *rpt)
{
  struct ftchash_rec_prefixh *ftch_recprefixh;
  struct ftstat_rpt_67 *rpt67;

  rpt67 = rpt->data;

  STD_CALC;

  rpt->recs = rpt67->ftch->entries;

  ftchash_first(rpt67->ftch);

  while ((ftch_recprefixh = ftchash_foreach(rpt67->ftch))) {

    if (ftch_recprefixh->etime) {
      if (rpt->all_fields & FT_STAT_FIELD_PS) {
        ftch_recprefixh->ps.avg_pps /= (double)ftch_recprefixh->nrecs;
        ftch_recprefixh->ps.avg_bps /= (double)ftch_recprefixh->nrecs;
      }
    }

    ftch_recprefixh->nprefixes = ftch_recprefixh->ftch->entries;
    rpt->t_count += ftch_recprefixh->ftch->entries;
    
  }

  return 0;

} /* ftstat_rpt_67_calc */

/* function: ftstat_rpt_67_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_67_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH0P(ftstat_rpt_67, rpt67, chash_prefixh_dump,
    FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK,
    "ip-destination-address", "ip-source-address-count", "", "", "", "", "");

} /* ftstat_rpt_67_dump */


/* function: ftstat_rpt_67_free
 *
 * Free data structures for report allocated by ftstat_rpt_67_new
 *
 */
void ftstat_rpt_67_free(struct ftstat_rpt_67 *rpt67)
{
  struct ftchash_rec_prefixh *ftch_recprefixh;

  if (rpt67) {

    if (rpt67->ftch) {

      ftchash_first(rpt67->ftch);

      while ((ftch_recprefixh = ftchash_foreach(rpt67->ftch))) {

        if (ftch_recprefixh->ftch)
          ftchash_free(ftch_recprefixh->ftch);

      }

      ftchash_free(rpt67->ftch);

    }

    free (rpt67);

  }

} /* ftstat_rpt_67_free */


/* function: ftstat_rpt_68_new
 * 
 * Allocate and initialize data structures for rpt 68.
 * 
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_68 *ftstat_rpt_68_new(struct ftstat_rpt *rpt)
{
  
  STD_NEW_HASH(ftstat_rpt_68, rpt68, 65536, ftchash_rec_flow1, 16, 65536);

} /* ftstat_rpt_68_new */

/* function: ftstat_rpt_68_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_68_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_68, rpt68, ftchash_rec_flow1,
    ftch_recflow1, ftch_recflow1p);
 
  FT_RECGET_SRCPORT(cur,rec,*fo);
  FT_RECGET_DSTPORT(cur,rec,*fo);
  FT_RECGET_SRCADDR(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);
  FT_RECGET_TOS(cur,rec,*fo);
  FT_RECGET_PROT(cur,rec,*fo);
  
  ftch_recflow1.src_prefix = cur.srcaddr;
  ftch_recflow1.dst_prefix = cur.dstaddr;
  ftch_recflow1.src_port = cur.srcport;
  ftch_recflow1.dst_port = cur.dstport;
  ftch_recflow1.tos = cur.tos;
  ftch_recflow1.prot = cur.prot;
  
  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recflow1.src_mask = cur.src_mask;
  }

  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recflow1.dst_mask = cur.dst_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK) {
    ftch_recflow1.src_prefix &= ipv4_len2mask(ftch_recflow1.src_mask);
  }

  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK) {
    ftch_recflow1.dst_prefix &= ipv4_len2mask(ftch_recflow1.dst_mask);
  }
  
  hash = (ftch_recflow1.src_prefix>>16)^
          (ftch_recflow1.src_prefix & 0xFFFF)^
          (ftch_recflow1.dst_prefix>>16)^
          (ftch_recflow1.dst_prefix & 0xFFFF)^
          (ftch_recflow1.src_port)^
          (ftch_recflow1.dst_port)^
          (ftch_recflow1.src_mask)^
          (ftch_recflow1.tos)^
          (ftch_recflow1.prot)^
          (u_int32)(ftch_recflow1.dst_mask<<8);

  STD_ACCUM_HASH2(rpt68, ftch_recflow1, ftch_recflow1p);

  return 0;
   
} /* ftstat_rpt_68_accum */

/* function: ftstat_rpt_68_calc
 *
 * Perform final calculations for rpt68
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_68_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_68, rpt68, ftchash_rec_flow1,
    ftch_recflow1);
 
} /* ftstat_rpt_68_calc */

/* function: ftstat_rpt_68_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_68_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH2(ftstat_rpt_68, rpt68, chash_flow1_dump,
    FT_PATH_SYM_TCP_PORT, FT_PATH_SYM_IP_PROT,
    "", "ip-source-address", "ip-destination-address", "ip-source-port",
    "ip-destination-port", "ip-protocol", "ip-tos");

} /* ftstat_rpt_68_dump */

/* function: ftstat_rpt_68_free
 *
 * Free data structures for report allocated by ftstat_rpt_68_new
 *
 */
void ftstat_rpt_68_free(struct ftstat_rpt_68 *rpt68)
{ 
 
  STD_FREE_HASH(rpt68);
   
} /* ftstat_rpt_68_free */

/* function: ftstat_rpt_69_new
 * 
 * Allocate and initialize data structures for rpt 69.
 * 
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_69 *ftstat_rpt_69_new(struct ftstat_rpt *rpt)
{
  
  STD_NEW_HASH(ftstat_rpt_69, rpt69, 65536, ftchash_rec_flow1, 16, 65536);

} /* ftstat_rpt_69_new */

/* function: ftstat_rpt_69_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_69_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_69, rpt69, ftchash_rec_flow1,
    ftch_recflow1, ftch_recflow1p);
 
  FT_RECGET_SRCADDR(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);
  FT_RECGET_TOS(cur,rec,*fo);
  FT_RECGET_PROT(cur,rec,*fo);
  
  ftch_recflow1.src_prefix = cur.srcaddr;
  ftch_recflow1.dst_prefix = cur.dstaddr;
  ftch_recflow1.tos = cur.tos;
  ftch_recflow1.prot = cur.prot;
  
  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recflow1.src_mask = cur.src_mask;
  }

  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recflow1.dst_mask = cur.dst_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK) {
    ftch_recflow1.src_prefix &= ipv4_len2mask(ftch_recflow1.src_mask);
  }

  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK) {
    ftch_recflow1.dst_prefix &= ipv4_len2mask(ftch_recflow1.dst_mask);
  }
  
  hash = (ftch_recflow1.src_prefix>>16)^
          (ftch_recflow1.src_prefix & 0xFFFF)^
          (ftch_recflow1.dst_prefix>>16)^
          (ftch_recflow1.dst_prefix & 0xFFFF)^
          (ftch_recflow1.src_mask)^
          (ftch_recflow1.tos)^
          (ftch_recflow1.prot)^
          (u_int32)(ftch_recflow1.dst_mask<<8);

  STD_ACCUM_HASH2(rpt69, ftch_recflow1, ftch_recflow1p);

  return 0;
   
} /* ftstat_rpt_69_accum */

/* function: ftstat_rpt_69_calc
 *
 * Perform final calculations for rpt69
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_69_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_69, rpt69, ftchash_rec_flow1,
    ftch_recflow1);
 
} /* ftstat_rpt_69_calc */

/* function: ftstat_rpt_69_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_69_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1(ftstat_rpt_69, rpt69, chash_flow12_dump,
    FT_PATH_SYM_IP_PROT,
    "", "ip-source-address", "ip-destination-address", "ip-protocol",
    "ip-tos", "", "");

} /* ftstat_rpt_69_dump */

/* function: ftstat_rpt_69_free
 *
 * Free data structures for report allocated by ftstat_rpt_69_new
 *
 */
void ftstat_rpt_69_free(struct ftstat_rpt_69 *rpt69)
{ 
 
  STD_FREE_HASH(rpt69);
   
} /* ftstat_rpt_69_free */

/* function: ftstat_rpt_70_new
 *
 * Allocate and initialize data structures for rpt 70.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_70 *ftstat_rpt_70_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_70, rpt70, 65536, ftchash_rec_prefix_tag, 12, 65536);

} /* ftstat_rpt_70_new */


/* function: ftstat_rpt_70_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_70_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_70, rpt70, ftchash_rec_prefix_tag,
    ftch_recprefix_tag, ftch_recprefix_tagp);

  FT_RECGET_SRCADDR(cur,rec,*fo);
  FT_RECGET_SRC_TAG(cur,rec,*fo);
 
  ftch_recprefix_tag.prefix = cur.srcaddr;
  ftch_recprefix_tag.tag = cur.src_tag;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix_tag.mask = cur.src_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK)
    ftch_recprefix_tag.prefix &= ipv4_len2mask(ftch_recprefix_tag.mask);

  hash = (ftch_recprefix_tag.tag>>16) ^ (ftch_recprefix_tag.tag & 0xFFFF) ^
    (ftch_recprefix_tag.prefix>>16) ^ (ftch_recprefix_tag.prefix & 0xFFFF) ^
    (ftch_recprefix_tag.mask);

  STD_ACCUM_HASH2(rpt70, ftch_recprefix_tag, ftch_recprefix_tagp);

  return 0;
   
} /* ftstat_rpt_70_accum */

/* function: ftstat_rpt_70_calc
 *
 * Perform final calculations for rpt70
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_70_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_70, rpt70, ftchash_rec_prefix_tag,
    ftch_recprefix_tag);

} /* ftstat_rpt_70_calc */

/* function: ftstat_rpt_70_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_70_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1P(ftstat_rpt_70, rpt70, chash_prefix_tag_dump,
    FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK,
    FT_PATH_SYM_TAG,
    "", "ip-source-address", "source-tag", "", "", "", "");

} /* ftstat_rpt_70_dump */


/* function: ftstat_rpt_70_free
 *
 * Free data structures for report allocated by ftstat_rpt_70_new
 *
 */
void ftstat_rpt_70_free(struct ftstat_rpt_70 *rpt70)
{

  STD_FREE_HASH(rpt70);

} /* ftstat_rpt_70_free */


/* function: ftstat_rpt_71_new
 *
 * Allocate and initialize data structures for rpt 71.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_71 *ftstat_rpt_71_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_71, rpt71, 65536, ftchash_rec_prefix_tag, 12, 65536);

} /* ftstat_rpt_71_new */


/* function: ftstat_rpt_71_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_71_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_71, rpt71, ftchash_rec_prefix_tag,
    ftch_recprefix_tag, ftch_recprefix_tagp);

  FT_RECGET_SRCADDR(cur,rec,*fo);
  FT_RECGET_DST_TAG(cur,rec,*fo);
 
  ftch_recprefix_tag.prefix = cur.srcaddr;
  ftch_recprefix_tag.tag = cur.dst_tag;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix_tag.mask = cur.src_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK)
    ftch_recprefix_tag.prefix &= ipv4_len2mask(ftch_recprefix_tag.mask);

  hash = (ftch_recprefix_tag.tag>>16) ^ (ftch_recprefix_tag.tag & 0xFFFF) ^
    (ftch_recprefix_tag.prefix>>16) ^ (ftch_recprefix_tag.prefix & 0xFFFF) ^
    (ftch_recprefix_tag.mask);

  STD_ACCUM_HASH2(rpt71, ftch_recprefix_tag, ftch_recprefix_tagp);

  return 0;
   
} /* ftstat_rpt_71_accum */

/* function: ftstat_rpt_71_calc
 *
 * Perform final calculations for rpt71
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_71_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_71, rpt71, ftchash_rec_prefix_tag,
    ftch_recprefix_tag);

} /* ftstat_rpt_71_calc */

/* function: ftstat_rpt_71_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_71_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1P(ftstat_rpt_71, rpt71, chash_prefix_tag_dump,
    FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK,
    FT_PATH_SYM_TAG,
    "", "ip-source-address", "destination-tag", "", "", "", "");

} /* ftstat_rpt_71_dump */


/* function: ftstat_rpt_71_free
 *
 * Free data structures for report allocated by ftstat_rpt_71_new
 *
 */
void ftstat_rpt_71_free(struct ftstat_rpt_71 *rpt71)
{

  STD_FREE_HASH(rpt71);

} /* ftstat_rpt_71_free */

/* function: ftstat_rpt_72_new
 *
 * Allocate and initialize data structures for rpt 72.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_72 *ftstat_rpt_72_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_72, rpt72, 65536, ftchash_rec_prefix_tag, 12, 65536);

} /* ftstat_rpt_72_new */


/* function: ftstat_rpt_72_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_72_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_72, rpt72, ftchash_rec_prefix_tag,
    ftch_recprefix_tag, ftch_recprefix_tagp);

  FT_RECGET_DSTADDR(cur,rec,*fo);
  FT_RECGET_SRC_TAG(cur,rec,*fo);
 
  ftch_recprefix_tag.prefix = cur.dstaddr;
  ftch_recprefix_tag.tag = cur.src_tag;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix_tag.mask = cur.dst_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK)
    ftch_recprefix_tag.prefix &= ipv4_len2mask(ftch_recprefix_tag.mask);

  hash = (ftch_recprefix_tag.tag>>16) ^ (ftch_recprefix_tag.tag & 0xFFFF) ^
    (ftch_recprefix_tag.prefix>>16) ^ (ftch_recprefix_tag.prefix & 0xFFFF) ^
    (ftch_recprefix_tag.mask);

  STD_ACCUM_HASH2(rpt72, ftch_recprefix_tag, ftch_recprefix_tagp);

  return 0;
   
} /* ftstat_rpt_72_accum */

/* function: ftstat_rpt_72_calc
 *
 * Perform final calculations for rpt72
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_72_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_72, rpt72, ftchash_rec_prefix_tag,
    ftch_recprefix_tag);

} /* ftstat_rpt_72_calc */

/* function: ftstat_rpt_72_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_72_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1P(ftstat_rpt_72, rpt72, chash_prefix_tag_dump,
    FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK,
    FT_PATH_SYM_TAG,
    "", "ip-destination-address", "source-tag", "", "", "", "");

} /* ftstat_rpt_72_dump */


/* function: ftstat_rpt_72_free
 *
 * Free data structures for report allocated by ftstat_rpt_72_new
 *
 */
void ftstat_rpt_72_free(struct ftstat_rpt_72 *rpt72)
{

  STD_FREE_HASH(rpt72);

} /* ftstat_rpt_72_free */

/* function: ftstat_rpt_73_new
 *
 * Allocate and initialize data structures for rpt 73.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_73 *ftstat_rpt_73_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_73, rpt73, 65536, ftchash_rec_prefix_tag, 12, 65536);

} /* ftstat_rpt_73_new */


/* function: ftstat_rpt_73_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_73_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_73, rpt73, ftchash_rec_prefix_tag,
    ftch_recprefix_tag, ftch_recprefix_tagp);

  FT_RECGET_DSTADDR(cur,rec,*fo);
  FT_RECGET_DST_TAG(cur,rec,*fo);
 
  ftch_recprefix_tag.prefix = cur.dstaddr;
  ftch_recprefix_tag.tag = cur.dst_tag;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix_tag.mask = cur.dst_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK)
    ftch_recprefix_tag.prefix &= ipv4_len2mask(ftch_recprefix_tag.mask);

  hash = (ftch_recprefix_tag.tag>>16) ^ (ftch_recprefix_tag.tag & 0xFFFF) ^
    (ftch_recprefix_tag.prefix>>16) ^ (ftch_recprefix_tag.prefix & 0xFFFF) ^
    (ftch_recprefix_tag.mask);

  STD_ACCUM_HASH2(rpt73, ftch_recprefix_tag, ftch_recprefix_tagp);

  return 0;
   
} /* ftstat_rpt_73_accum */

/* function: ftstat_rpt_73_calc
 *
 * Perform final calculations for rpt73
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_73_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_73, rpt73, ftchash_rec_prefix_tag,
    ftch_recprefix_tag);

} /* ftstat_rpt_73_calc */

/* function: ftstat_rpt_73_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_73_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1P(ftstat_rpt_73, rpt73, chash_prefix_tag_dump,
    FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK,
    FT_PATH_SYM_TAG,
    "", "ip-destination-address", "destination-tag", "", "", "", "");

} /* ftstat_rpt_73_dump */


/* function: ftstat_rpt_73_free
 *
 * Free data structures for report allocated by ftstat_rpt_73_new
 *
 */
void ftstat_rpt_73_free(struct ftstat_rpt_73 *rpt73)
{

  STD_FREE_HASH(rpt73);

} /* ftstat_rpt_73_free */

/* function: ftstat_rpt_74_new
 *
 * Allocate and initialize data structures for rpt 74.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_74 *ftstat_rpt_74_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_74, rpt74, 65536, ftchash_rec_prefix2tag2, 24, 65536);

} /* ftstat_rpt_74_new */


/* function: ftstat_rpt_74_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_74_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_74, rpt74, ftchash_rec_prefix2tag2,
    ftch_recprefix2tag2, ftch_recprefix2tag2p);

  FT_RECGET_SRCADDR(cur,rec,*fo);
  FT_RECGET_DSTADDR(cur,rec,*fo);
  FT_RECGET_SRC_TAG(cur,rec,*fo);
  FT_RECGET_DST_TAG(cur,rec,*fo);
 
  ftch_recprefix2tag2.src_prefix = cur.srcaddr;
  ftch_recprefix2tag2.src_tag = cur.src_tag;
  ftch_recprefix2tag2.dst_prefix = cur.dstaddr;
  ftch_recprefix2tag2.dst_tag = cur.dst_tag;

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_SRC_PREFIX_MASK|FT_STAT_OPT_SRC_PREFIX_LEN)) {
    FT_RECGET_SRC_MASK(cur,rec,*fo);
    ftch_recprefix2tag2.src_mask = cur.src_mask;
  }

  /* only use mask if option set */
  if (rpt->options & (FT_STAT_OPT_DST_PREFIX_MASK|FT_STAT_OPT_DST_PREFIX_LEN)) {
    FT_RECGET_DST_MASK(cur,rec,*fo);
    ftch_recprefix2tag2.src_mask = cur.dst_mask;
  }

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK)
    ftch_recprefix2tag2.src_prefix &=
      ipv4_len2mask(ftch_recprefix2tag2.src_mask);

  /* remove host bits */
  if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK)
    ftch_recprefix2tag2.dst_prefix
      &= ipv4_len2mask(ftch_recprefix2tag2.dst_mask);

  hash = (ftch_recprefix2tag2.src_tag>>16) ^
         (ftch_recprefix2tag2.src_tag & 0xFFFF) ^
         (ftch_recprefix2tag2.dst_tag>>16) ^
         (ftch_recprefix2tag2.dst_tag & 0xFFFF) ^
         (ftch_recprefix2tag2.src_prefix>>16) ^
         (ftch_recprefix2tag2.src_prefix & 0xFFFF) ^
         (ftch_recprefix2tag2.dst_prefix>>16) ^
         (ftch_recprefix2tag2.dst_prefix & 0xFFFF) ^
         (ftch_recprefix2tag2.src_mask) ^
         (ftch_recprefix2tag2.dst_mask);

  STD_ACCUM_HASH2(rpt74, ftch_recprefix2tag2, ftch_recprefix2tag2p);

  return 0;
   
} /* ftstat_rpt_74_accum */

/* function: ftstat_rpt_74_calc
 *
 * Perform final calculations for rpt74
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_74_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_74, rpt74, ftchash_rec_prefix2tag2,
    ftch_recprefix2tag2);

} /* ftstat_rpt_74_calc */

/* function: ftstat_rpt_74_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_74_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1(ftstat_rpt_74, rpt74, chash_prefix2tag2_dump,
    FT_PATH_SYM_TAG,
    "", "ip-source-address", "ip-destination-address", "source-tag",
    "destination-tag", "", "");

} /* ftstat_rpt_74_dump */


/* function: ftstat_rpt_74_free
 *
 * Free data structures for report allocated by ftstat_rpt_74_new
 *
 */
void ftstat_rpt_74_free(struct ftstat_rpt_74 *rpt74)
{

  STD_FREE_HASH(rpt74);

} /* ftstat_rpt_74_free */

/* function: ftstat_rpt_75_new
 *
 * Allocate and initialize data structures for rpt 75.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_75 *ftstat_rpt_75_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_75, rpt75, 65536, ftchash_rec_int, 4, 65536);

} /* ftstat_rpt_75_new */


/* function: ftstat_rpt_75_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_75_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{
  struct fttime start, end;
  u_int32 i;
  double p_flows, p_octets, p_packets, d;

  STD_ACCUM_HASH1(ftstat_rpt_75, rpt75, ftchash_rec_int,
    ftch_recint, ftch_recintp);

  FT_RECGET_SYSUPTIME(cur,rec,*fo);
  FT_RECGET_UNIX_SECS(cur,rec,*fo);
  FT_RECGET_UNIX_NSECS(cur,rec,*fo);
  FT_RECGET_FIRST(cur,rec,*fo);
  FT_RECGET_LAST(cur,rec,*fo);

  start = ftltime(cur.sysUpTime, cur.unix_secs, cur.unix_nsecs, cur.First);
  end = ftltime(cur.sysUpTime, cur.unix_secs, cur.unix_nsecs, cur.Last);

  d = (end.secs - start.secs) + 1;

  p_flows = (double)cur.dFlows64 / d;
  p_octets = (double)cur.dOctets64 / d;
  p_packets = (double)cur.dPkts64 / d;

  for (i = start.secs; i <= end.secs; ++i) {

    ftch_recint.time = i;

    hash = (i>>16) ^ (i & 0xFFFF);

    if (!(ftch_recintp = ftchash_update(rpt75->ftch, &ftch_recint, hash))) {
      fterr_warnx("ftch_update(): failed");
      return -1;
    }

    ftch_recintp->nflows += p_flows;
    ftch_recintp->noctets += p_octets;
    ftch_recintp->npackets += p_packets;

  }
  
  return 0;
   
} /* ftstat_rpt_75_accum */

/* function: ftstat_rpt_75_calc
 *
 * Perform final calculations for rpt75
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_75_calc(struct ftstat_rpt *rpt)
{
  struct ftstat_rpt_75 *rpt75;

  rpt75 = rpt->data;

  STD_CALC;

  rpt->recs = rpt75->ftch->entries;

  return 0;

} /* ftstat_rpt_75_calc */

/* function: ftstat_rpt_75_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_75_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH0(ftstat_rpt_75, rpt75, chash_int_dump,
    "unix-secs", "", "", "", "", "", "");

} /* ftstat_rpt_75_dump */


/* function: ftstat_rpt_75_free
 *
 * Free data structures for report allocated by ftstat_rpt_75_new
 *
 */
void ftstat_rpt_75_free(struct ftstat_rpt_75 *rpt75)
{

  STD_FREE_HASH(rpt75);

} /* ftstat_rpt_75_free */

/* function: ftstat_rpt_76_new
 *
 * Allocate and initialize data structures for rpt 76.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_76 *ftstat_rpt_76_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_76, rpt76, 65536, ftchash_rec_c32, 4, 65536);

} /* ftstat_rpt_76_new */


/* function: ftstat_rpt_76_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_76_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_76, rpt76, ftchash_rec_c32,
    ftch_recc32, ftch_recc32p);

  ftch_recc32.c32 = cur.First;

  hash = (ftch_recc32.c32>>16) ^ (ftch_recc32.c32 & 0xFFFF);

  STD_ACCUM_HASH2(rpt76, ftch_recc32, ftch_recc32p);
  
  return 0;
   
} /* ftstat_rpt_76_accum */

/* function: ftstat_rpt_76_calc
 *
 * Perform final calculations for rpt76
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_76_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_76, rpt76, ftchash_rec_c32, ftch_recc32);

} /* ftstat_rpt_76_calc */

/* function: ftstat_rpt_76_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_76_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1(ftstat_rpt_76, rpt76, chash_c32_dump, (char*)0L,
    "First", "", "", "", "", "", "");

} /* ftstat_rpt_76_dump */


/* function: ftstat_rpt_76_free
 *
 * Free data structures for report allocated by ftstat_rpt_76_new
 *
 */
void ftstat_rpt_76_free(struct ftstat_rpt_76 *rpt76)
{

  STD_FREE_HASH(rpt76);

} /* ftstat_rpt_76_free */


/* function: ftstat_rpt_77_new
 *
 * Allocate and initialize data structures for rpt 77.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_77 *ftstat_rpt_77_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_77, rpt77, 65536, ftchash_rec_c32, 4, 65536);

} /* ftstat_rpt_77_new */


/* function: ftstat_rpt_77_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_77_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_77, rpt77, ftchash_rec_c32,
    ftch_recc32, ftch_recc32p);

  ftch_recc32.c32 = cur.Last;

  hash = (ftch_recc32.c32>>16) ^ (ftch_recc32.c32 & 0xFFFF);

  STD_ACCUM_HASH2(rpt77, ftch_recc32, ftch_recc32p);
  
  return 0;
   
} /* ftstat_rpt_77_accum */

/* function: ftstat_rpt_77_calc
 *
 * Perform final calculations for rpt77
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_77_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_77, rpt77, ftchash_rec_c32, ftch_recc32);

} /* ftstat_rpt_77_calc */

/* function: ftstat_rpt_77_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_77_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1(ftstat_rpt_77, rpt77, chash_c32_dump, (char*)0L,
    "Last", "", "", "", "", "", "");

} /* ftstat_rpt_77_dump */


/* function: ftstat_rpt_77_free
 *
 * Free data structures for report allocated by ftstat_rpt_77_new
 *
 */
void ftstat_rpt_77_free(struct ftstat_rpt_77 *rpt77)
{

  STD_FREE_HASH(rpt77);

} /* ftstat_rpt_77_free */


/* function: ftstat_rpt_78_new
 *
 * Allocate and initialize data structures for rpt 78.
 *
 * returns allocated struct or 0L for error
 */
struct ftstat_rpt_78 *ftstat_rpt_78_new(struct ftstat_rpt *rpt)
{

  STD_NEW_HASH(ftstat_rpt_78, rpt78, 65536, ftchash_rec_c32, 4, 65536);

} /* ftstat_rpt_78_new */


/* function: ftstat_rpt_78_accum
 *
 * Accumulate counters for report by processing flow.
 *
 * returns 0: ok
 *        !0: error
 */
int ftstat_rpt_78_accum(struct ftstat_rpt *rpt, char *rec,
  struct fts3rec_offsets *fo)
{

  STD_ACCUM_HASH1(ftstat_rpt_78, rpt78, ftchash_rec_c32,
    ftch_recc32, ftch_recc32p);

  ftch_recc32.c32 = cur.Last - cur.First;

  hash = (ftch_recc32.c32>>16) ^ (ftch_recc32.c32 & 0xFFFF);

  STD_ACCUM_HASH2(rpt78, ftch_recc32, ftch_recc32p);
  
  return 0;
   
} /* ftstat_rpt_78_accum */

/* function: ftstat_rpt_78_calc
 *
 * Perform final calculations for rpt78
 *
 * returns allocated struct or 0L for error
 */
int ftstat_rpt_78_calc(struct ftstat_rpt *rpt)
{

  STD_CALC_HASH(ftstat_rpt_78, rpt78, ftchash_rec_c32, ftch_recc32);

} /* ftstat_rpt_78_calc */

/* function: ftstat_rpt_78_dump
 *
 * Dump data for report.
 *
 */
int ftstat_rpt_78_dump(FILE *fp, struct ftio *ftio, struct ftstat_rpt *rpt)
{

  STD_DUMP_HASH1(ftstat_rpt_78, rpt78, chash_c32_dump, (char*)0L,
    "Duration", "", "", "", "", "", "");

} /* ftstat_rpt_78_dump */


/* function: ftstat_rpt_78_free
 *
 * Free data structures for report allocated by ftstat_rpt_78_new
 *
 */
void ftstat_rpt_78_free(struct ftstat_rpt_78 *rpt78)
{

  STD_FREE_HASH(rpt78);

} /* ftstat_rpt_78_free */

/*
 * function: resolve_reports
 *
 * resolve the dangling pointers to rpts in definitions --
 * allows definitions to be defined before reports.
 *
 * _must_ be called after work done by parse_def_report
 *
 * returns: 0  ok
 *          <0 fail
 */
static int resolve_reports(struct ftstat *ftstat)
{
  struct ftstat_rpt_item *ftsrpti;
  struct ftstat_def *ftsd;
  struct ftstat_rpt *ftsrpt;
  int found;

  /* foreach definition */
  FT_SLIST_FOREACH(ftsd, &ftstat->defs, chain) {

    /* foreach report in the definition */
    FT_STAILQ_FOREACH(ftsrpti, &ftsd->items, chain) {

      /* find the report */
      found = 0;

      FT_SLIST_FOREACH(ftsrpt, &ftstat->rpts, chain) {

        if (!strcasecmp(ftsrpti->tmp_report, ftsrpt->name)) {

          found = 1;
          break;

        } /* if */

      } /* ftsrpt */

      if (!found) {
        fterr_warnx(
          "Unable to resolve report \"%s\" in stat-definition \"%s\".",
          ftsrpti->tmp_report, ftsd->name);
        return -1;
      } /* !found */

      /* report found */
      ftsrpti->rpt = ftsrpt;
      ftsd->xfields |= ftsrpt->xfields;

    } /* ftsrpti */

  } /* ftsd */

  return 0;

} /* resolve_reports */

static int dump_ascii_header(FILE *fp, struct ftio *ftio,
  struct ftstat_def *active_def, struct ftstat_rpt *rpt)
{
  int comma, sort_field;
  char *buf, fmt_buf[32];
  time_t now, time_flow;

  /* shortcut */
  if (!(rpt->out->options & FT_STAT_OPT_HEADER))
    return 0;

  if (!active_def->interval) {

    fprintf(fp, "#  --- ---- ---- Report Information --- --- ---\n");
    fprintf(fp, "# build-version:        flow-tools %s\n", VERSION);
    fprintf(fp, "# name:                 %s\n", rpt->name);
    fprintf(fp, "# type:                 %s\n", rpt->format_name);
    if (rpt->scale)
      fprintf(fp, "# scale:                %lu\n", (unsigned long)rpt->scale);
 
    if (rpt->out->options) {

      fprintf(fp, "# options:              ");

      comma = 0;

      if (rpt->out->options & FT_STAT_OPT_PERCENT) {
        fprintf(fp, "+percent-total");
        comma=1;
      }

      if (rpt->out->options & FT_STAT_OPT_NAMES) {
        fprintf(fp, "%snames", comma ? ",+" : "+");
        comma=1;
      }

      if (rpt->out->options & FT_STAT_OPT_HEADER) {
        fprintf(fp, "%sheader", comma ? ",+" : "+");
        comma=1;
      }

      if (rpt->out->options & FT_STAT_OPT_XHEADER) {
        fprintf(fp, "%sxheader", comma ? ",+" : "+");
        comma=1;
      }

      if (rpt->out->options & FT_STAT_OPT_TOTALS) {
        fprintf(fp, "%stotals", comma ? ",+" : "+");
        comma=1;
      }

      fprintf(fp, "\n");

    } /* options */

    if (rpt->xfields & FT_XFIELD_SRCADDR) {

      fprintf(fp, "# ip-src-addr-type:     ");

      if (rpt->options & FT_STAT_OPT_SRC_PREFIX_LEN)
        fprintf(fp, "prefix-len\n");
      else if (rpt->options & FT_STAT_OPT_SRC_PREFIX_MASK)
        fprintf(fp, "prefix-mask\n");
      else
        fprintf(fp, "address\n");

    }

    if (rpt->xfields & FT_XFIELD_DSTADDR) {

      fprintf(fp, "# ip-dst-addr-type:     ");

      if (rpt->options & FT_STAT_OPT_DST_PREFIX_LEN)
        fprintf(fp, "prefix-len\n");
      else if (rpt->options & FT_STAT_OPT_DST_PREFIX_MASK)
        fprintf(fp, "prefix-mask\n");
      else
        fprintf(fp, "address\n");

    }


    if (rpt->out->options & FT_STAT_OPT_SORT) {
  
      sort_field = rpt->out->sort_field;
      if (sort_field < 0)
        sort_field *= -1;
  
      if (sort_field & FT_STAT_FIELD_KEY)
        buf = "key";
      else if (sort_field & FT_STAT_FIELD_KEY1)
        buf = "key1";
      else if (sort_field & FT_STAT_FIELD_KEY2)
        buf = "key2";
      else if (sort_field & FT_STAT_FIELD_KEY3)
        buf = "key3";
      else if (sort_field & FT_STAT_FIELD_KEY4)
        buf = "key4";
      else if (sort_field & FT_STAT_FIELD_KEY5)
        buf = "key5";
      else if (sort_field & FT_STAT_FIELD_KEY6)
        buf = "key6";
      else if (sort_field & FT_STAT_FIELD_FLOWS)
        buf = "flows";
      else if (sort_field & FT_STAT_FIELD_OCTETS)
        buf = "octets";
      else if (sort_field & FT_STAT_FIELD_PACKETS)
        buf = "packets";
      else if (sort_field & FT_STAT_FIELD_DURATION)
        buf = "duration";
      else if (sort_field & FT_STAT_FIELD_AVG_PPS)
        buf = "avg-pps";
      else if (sort_field & FT_STAT_FIELD_MIN_PPS)
        buf = "min-pps";
      else if (sort_field & FT_STAT_FIELD_MAX_PPS)
        buf = "max-pps";
      else if (sort_field & FT_STAT_FIELD_AVG_BPS)
        buf = "avg-bps";
      else if (sort_field & FT_STAT_FIELD_MIN_BPS)
        buf = "min-bps";
      else if (sort_field & FT_STAT_FIELD_MAX_BPS)
        buf = "max-bps";
      else if (sort_field & FT_STAT_FIELD_OTHER)
        buf = "other";
      else if (sort_field & FT_STAT_FIELD_COUNT)
        buf = "count";
      else
        buf = "error";

      fprintf(fp, "# sort_field:           %c%s\n",
        (rpt->out->sort_field < 0) ? '-' : '+', buf);

    } /* FT_STAT_OPT_SORT */

    if (rpt->out->fields) {

      fprintf(fp, "# fields:               ");

      comma = 0;
      if (rpt->out->fields & FT_STAT_FIELD_KEY) {
        fprintf(fp, "+key");
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_KEY1) {
        fprintf(fp, "%skey1", comma ? ",+" : "+");
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_KEY2) {
        fprintf(fp, "%skey2", comma ? ",+" : "+");
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_KEY3) {
        fprintf(fp, "%skey3", comma ? ",+" : "+");
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_KEY4) {
        fprintf(fp, "%skey4", comma ? ",+" : "+");
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_KEY5) {
        fprintf(fp, "%skey5", comma ? ",+" : "+");
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_KEY6) {
        fprintf(fp, "%skey6", comma ? ",+" : "+");
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_FLOWS) {
        fprintf(fp, "%sflows", comma ? ",+" : "+");
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_OCTETS) {
        fprintf(fp, "%soctets", comma ? ",+" : "+");
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_PACKETS) {
        fprintf(fp, "%spackets", comma ? ",+" : "+");
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_DURATION) {
        fprintf(fp, "%sduration", comma ? ",+" : "+");
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_AVG_PPS) {
        fprintf(fp, "%savg-pps", comma ? ",+" : "+");
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_MIN_PPS) {
        fprintf(fp, "%smin-pps", comma ? ",+" : "+");
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_MAX_PPS) {
        fprintf(fp, "%smax-pps", comma ? ",+" : "+");
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_AVG_BPS) {
        fprintf(fp, "%savg-bps", comma ? ",+" : "+");
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_MIN_BPS) {
        fprintf(fp, "%smin-bps", comma ? ",+" : "+");
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_MAX_BPS) {
        fprintf(fp, "%smax-bps", comma ? ",+" : "+");
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_FRECS) {
        fprintf(fp, "%sfrecs", comma ? ",+" : "+");
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_OTHER) {
        fprintf(fp, "%sother", comma ? ",+" : "+");
        comma = 1;
      }

      fprintf(fp, "\n");

    } /* rpt->out->fields */

    if (rpt->out->options & FT_STAT_OPT_TALLY)
      fprintf(fp, "# tally:                %lu\n",
        (unsigned long)rpt->out->tally);

    if (active_def->ftd)
      fprintf(fp, "# tag:                  %s\n", active_def->ftd->name);

    if (active_def->ftfd)
      fprintf(fp, "# pre-filter:           %s\n", active_def->ftfd->name);

    if (rpt->ftfd)
      fprintf(fp, "# filter:               %s\n", rpt->ftfd->name);

  } /* !active_def->interval */

  fmt_uint64(fmt_buf, rpt->recs, FMT_JUST_LEFT);
    fprintf(fp, "# records:              %s\n", fmt_buf);

  if (rpt->out->records) {
    fmt_uint64(fmt_buf, rpt->out->records, FMT_JUST_LEFT);
    fprintf(fp, "# records_shown:      %s\n", fmt_buf);
  }

  time_flow = rpt->time_start;
  fprintf(fp, "# first-flow:           %lu %s",
    (unsigned long)rpt->time_start, ctime(&time_flow));

  time_flow = rpt->time_end;
  fprintf(fp, "# last-flow:            %lu %s",
    (unsigned long)rpt->time_end, ctime(&time_flow));

  now = time((time_t*)0L);

  fprintf(fp, "# now:                  %lu %s", (unsigned long)now,
    ctime(&now));

  if (active_def->max_time)
    fprintf(fp, "# time-series:          %lu seconds / interval %lu\n",
      (unsigned long)active_def->max_time,
      (unsigned long)active_def->interval);

  if (!active_def->interval) {

    if (rpt->out->options & FT_STAT_OPT_XHEADER)
      ftio_header_print(ftio, fp, '#');

  } /* !active_def->interval */

  return 0;

} /* dump_ascii_header */

static int chash_c32_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1)
{
  struct ftsym *ftsym1;

  CHASH_DUMP_INIT(ftchash_rec_c32, ftch_recc32);

  ftsym1 = (struct ftsym*)0L;

  if (rpt->out->options & FT_STAT_OPT_NAMES)
    ftsym1 = ftsym_new(sym1);

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY) {
      sort_offset = offsetof(struct ftchash_rec_c32, c32);
      sort_flags |= FT_CHASH_SORT_32;
    } else

    CHASH_DUMP_STD_SORT(ftchash_rec_c32);

    ftchash_sort(ftch, sort_offset, sort_flags);

  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recc32 = ftchash_foreach(ftch))) {

    len = comma = 0;

    DUMP_STD_OUT();

    if (rpt->out->fields & FT_STAT_FIELD_KEY) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint32s(ftsym1, FMT_SYM_LEN, fmt_buf+len, ftch_recc32->c32,
        FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->options & FT_STAT_OPT_PERCENT) {

      CHASH_STDP_OUT(ftch_recc32, comma);

    } else {

      CHASH_STD_OUT(ftch_recc32, comma);

    }

  }

  if (ftsym1)
    ftsym_free(ftsym1);

  return 0;

} /* chash_c32_dump */

static int chash_c322_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1, char *sym2)
{
  struct ftsym *ftsym1, *ftsym2;

  CHASH_DUMP_INIT(ftchash_rec_c322, ftch_recc322);

  ftsym1 = ftsym2 = (struct ftsym*)0L;

  if (rpt->out->options & FT_STAT_OPT_NAMES) {
    ftsym1 = ftsym_new(sym1);
    ftsym2 = ftsym_new(sym2);
  }

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY1) {
      sort_offset = offsetof(struct ftchash_rec_c322, c32a);
      sort_flags |= FT_CHASH_SORT_32;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY2) {
      sort_offset = offsetof(struct ftchash_rec_c322, c32b);
      sort_flags |= FT_CHASH_SORT_32;
    } else

    CHASH_DUMP_STD_SORT(ftchash_rec_c322);

    ftchash_sort(ftch, sort_offset, sort_flags);

  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recc322 = ftchash_foreach(ftch))) {
  
    len = comma = 0;
 
    DUMP_STD_OUT();

    if (rpt->out->fields & FT_STAT_FIELD_KEY1) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint32s(ftsym1, FMT_SYM_LEN, fmt_buf+len, ftch_recc322->c32a,
        FMT_JUST_LEFT);
      comma = 1;
    }
  
    if (rpt->out->fields & FT_STAT_FIELD_KEY2) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint32s(ftsym2, FMT_SYM_LEN, fmt_buf+len, ftch_recc322->c32b,
        FMT_JUST_LEFT);
      comma = 1;
    }
  
    if (rpt->out->options & FT_STAT_OPT_PERCENT) {

      CHASH_STDP_OUT(ftch_recc322, comma);

    } else {

      CHASH_STD_OUT(ftch_recc322, comma);

    }

  }

  if (ftsym1)
    ftsym_free(ftsym1);

  if (ftsym2)
    ftsym_free(ftsym2);

  return 0;

} /* chash_c322_dump */

static int chash_c162_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1, char *sym2)
{
  struct ftsym *ftsym1, *ftsym2;

  CHASH_DUMP_INIT(ftchash_rec_c162, ftch_recc162);

  ftsym1 = ftsym2 = (struct ftsym*)0L;

  if (rpt->out->options & FT_STAT_OPT_NAMES) {
    ftsym1 = ftsym_new(sym1);
    ftsym2 = ftsym_new(sym2);
  }

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY1) {
      sort_offset = offsetof(struct ftchash_rec_c162, c16a);
      sort_flags |= FT_CHASH_SORT_16;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY2) {
      sort_offset = offsetof(struct ftchash_rec_c162, c16b);
      sort_flags |= FT_CHASH_SORT_16;
    } else

    CHASH_DUMP_STD_SORT(ftchash_rec_c162);

    ftchash_sort(ftch, sort_offset, sort_flags);

  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recc162 = ftchash_foreach(ftch))) {

    len = comma = 0;

    DUMP_STD_OUT()
 
    if (rpt->out->fields & FT_STAT_FIELD_KEY1) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint16s(ftsym1, FMT_SYM_LEN, fmt_buf+len, ftch_recc162->c16a,
        FMT_JUST_LEFT);
      comma = 1;
    }
  
    if (rpt->out->fields & FT_STAT_FIELD_KEY2) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint16s(ftsym2, FMT_SYM_LEN, fmt_buf+len, ftch_recc162->c16b,
        FMT_JUST_LEFT);
      comma = 1;
    }
  
    if (rpt->out->options & FT_STAT_OPT_PERCENT) {

      CHASH_STDP_OUT(ftch_recc162, comma);

    } else {

      CHASH_STD_OUT(ftch_recc162, comma);

    }
  
  }
  
  if (ftsym1)
    ftsym_free(ftsym1);

  if (ftsym2)
    ftsym_free(ftsym2);

  return 0;

} /* chash_c162_dump */

static int chash_c163_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1, char *sym2, char *sym3)
{
  struct ftsym *ftsym1, *ftsym2, *ftsym3;

  CHASH_DUMP_INIT(ftchash_rec_c163, ftch_recc163);

  ftsym1 = ftsym2 = ftsym3 = (struct ftsym*)0L;

  if (rpt->out->options & FT_STAT_OPT_NAMES) {
    ftsym1 = ftsym_new(sym1);
    ftsym2 = ftsym_new(sym2);
    ftsym3 = ftsym_new(sym3);
  }

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY1) {
      sort_offset = offsetof(struct ftchash_rec_c163, c16a);
      sort_flags |= FT_CHASH_SORT_16;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY2) {
      sort_offset = offsetof(struct ftchash_rec_c163, c16b);
      sort_flags |= FT_CHASH_SORT_16;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY3) {
      sort_offset = offsetof(struct ftchash_rec_c163, c16c);
      sort_flags |= FT_CHASH_SORT_16;
    } else 

    CHASH_DUMP_STD_SORT(ftchash_rec_c163);

    ftchash_sort(ftch, sort_offset, sort_flags);

  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recc163 = ftchash_foreach(ftch))) {

    len = comma = 0;

    DUMP_STD_OUT()
 
    if (rpt->out->fields & FT_STAT_FIELD_KEY1) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint16s(ftsym1, FMT_SYM_LEN, fmt_buf+len, ftch_recc163->c16a,
        FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY2) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint16s(ftsym2, FMT_SYM_LEN, fmt_buf+len, ftch_recc163->c16b,
        FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY3) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint16s(ftsym3, FMT_SYM_LEN, fmt_buf+len, ftch_recc163->c16c,
        FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->options & FT_STAT_OPT_PERCENT) {

      CHASH_STDP_OUT(ftch_recc163, comma);

    } else {

      CHASH_STD_OUT(ftch_recc163, comma);

    }

  }

  if (ftsym1)
    ftsym_free(ftsym1);

  if (ftsym2)
    ftsym_free(ftsym2);

  if (ftsym3)
    ftsym_free(ftsym3);

  return 0;

} /* chash_c163_dump */

static int chash_c164_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1, char *sym2, char *sym3, char *sym4)
{
  struct ftsym *ftsym1, *ftsym2, *ftsym3, *ftsym4;

  CHASH_DUMP_INIT(ftchash_rec_c164, ftch_recc164);

  ftsym1 = ftsym2 = ftsym3 = ftsym4 = (struct ftsym*)0L;

  if (rpt->out->options & FT_STAT_OPT_NAMES) {
    ftsym1 = ftsym_new(sym1);
    ftsym2 = ftsym_new(sym2);
    ftsym3 = ftsym_new(sym3);
    ftsym4 = ftsym_new(sym4);
  }

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY1) {
      sort_offset = offsetof(struct ftchash_rec_c164, c16a);
      sort_flags |= FT_CHASH_SORT_16;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY2) {
      sort_offset = offsetof(struct ftchash_rec_c164, c16b);
      sort_flags |= FT_CHASH_SORT_16;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY3) {
      sort_offset = offsetof(struct ftchash_rec_c164, c16c);
      sort_flags |= FT_CHASH_SORT_16;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY4) {
      sort_offset = offsetof(struct ftchash_rec_c164, c16d);
      sort_flags |= FT_CHASH_SORT_16;
    } else

    CHASH_DUMP_STD_SORT(ftchash_rec_c164);

    ftchash_sort(ftch, sort_offset, sort_flags);

  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recc164 = ftchash_foreach(ftch))) {

    len = comma = 0;

    DUMP_STD_OUT();
 
    if (rpt->out->fields & FT_STAT_FIELD_KEY1) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint16s(ftsym1, FMT_SYM_LEN, fmt_buf+len, ftch_recc164->c16a,
        FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY2) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint16s(ftsym2, FMT_SYM_LEN, fmt_buf+len, ftch_recc164->c16b,
        FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY3) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint16s(ftsym3, FMT_SYM_LEN, fmt_buf+len, ftch_recc164->c16c,
        FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY4) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint16s(ftsym4, FMT_SYM_LEN, fmt_buf+len, ftch_recc164->c16d,
        FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->options & FT_STAT_OPT_PERCENT) {

      CHASH_STDP_OUT(ftch_recc164, comma);

    } else {

      CHASH_STD_OUT(ftch_recc164, comma);

    }

  }

  if (ftsym1)
    ftsym_free(ftsym1);

  if (ftsym2)
    ftsym_free(ftsym2);

  if (ftsym3)
    ftsym_free(ftsym3);

  if (ftsym4)
    ftsym_free(ftsym4);


  return 0;

} /* chash_c163_dump */



static int chash_ip_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch)
{

  CHASH_DUMP_INIT(ftchash_rec_c32, ftch_recc32);

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY) {
      sort_offset = offsetof(struct ftchash_rec_c32, c32);
      sort_flags |= FT_CHASH_SORT_32;
    } else

    CHASH_DUMP_STD_SORT(ftchash_rec_c32);

    ftchash_sort(ftch, sort_offset, sort_flags);

  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recc32 = ftchash_foreach(ftch))) {

    len = comma = 0;

    DUMP_STD_OUT();
 
    if (rpt->out->fields & FT_STAT_FIELD_KEY) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_ipv4s(fmt_buf+len, ftch_recc32->c32, 64, fmt);
      comma = 1;
    }

    if (rpt->out->options & FT_STAT_OPT_PERCENT) {

      CHASH_STDP_OUT(ftch_recc32, comma);

    } else {

      CHASH_STD_OUT(ftch_recc32, comma);

    }

  }

  return 0;

} /* chash_ip_dump */

static int chash_prefix_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, int f1)
{

  CHASH_DUMP_INIT(ftchash_rec_prefix, ftch_recprefix);

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY) {
      sort_offset = offsetof(struct ftchash_rec_prefix, prefix);
      sort_flags |= FT_CHASH_SORT_40;
    } else 

    CHASH_DUMP_STD_SORT(ftchash_rec_prefix);

    ftchash_sort(ftch, sort_offset, sort_flags);

  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recprefix = ftchash_foreach(ftch))) {

    len = comma = 0;

    DUMP_STD_OUT();
 
    if (rpt->out->fields & FT_STAT_FIELD_KEY) {
      if (comma) fmt_buf[len++] = ',';
      if (rpt->options & f1)
        len += fmt_ipv4prefixs(fmt_buf+len, ftch_recprefix->prefix,
          ftch_recprefix->mask, 64, fmt);
      else
        len += fmt_ipv4s(fmt_buf+len, ftch_recprefix->prefix, 64, fmt);
      comma = 1;
    }

    if (rpt->out->options & FT_STAT_OPT_PERCENT) {

      CHASH_STDP_OUT(ftch_recprefix, comma);

    } else {

      CHASH_STD_OUT(ftch_recprefix, comma);

    }

  }

  return 0;

} /* chash_prefix_dump */

static int chash_prefix_tag_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1, int f1)
{
  struct ftsym *ftsym1;

  CHASH_DUMP_INIT(ftchash_rec_prefix_tag, ftch_recprefix_tag);

  ftsym1 = (struct ftsym*)0L;

  if (rpt->out->options & FT_STAT_OPT_NAMES)
    ftsym1 = ftsym_new(sym1);

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY1) {
      sort_offset = offsetof(struct ftchash_rec_prefix_tag, prefix);
      sort_flags |= FT_CHASH_SORT_40;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY2) {
      sort_offset = offsetof(struct ftchash_rec_prefix_tag, tag);
      sort_flags |= FT_CHASH_SORT_32;
    } else

    CHASH_DUMP_STD_SORT(ftchash_rec_prefix_tag);

    ftchash_sort(ftch, sort_offset, sort_flags);

  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recprefix_tag = ftchash_foreach(ftch))) {

    len = comma = 0;

    DUMP_STD_OUT();
 
    if (rpt->out->fields & FT_STAT_FIELD_KEY1) {
      if (comma) fmt_buf[len++] = ',';
      if (rpt->options & f1)
        len += fmt_ipv4prefixs(fmt_buf+len, ftch_recprefix_tag->prefix,
          ftch_recprefix_tag->mask, 64, fmt);
      else
        len += fmt_ipv4s(fmt_buf+len, ftch_recprefix_tag->prefix, 64, fmt);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY2) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint32s(ftsym1, FMT_SYM_LEN, fmt_buf+len,
        ftch_recprefix_tag->tag, FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->options & FT_STAT_OPT_PERCENT) {

      CHASH_STDP_OUT(ftch_recprefix_tag, comma);

    } else {

      CHASH_STD_OUT(ftch_recprefix_tag, comma);

    }

  }

  if (ftsym1)
    ftsym_free(ftsym1);

  return 0;

} /* chash_prefix_tag_dump */

static int chash_prefix2tag2_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1)
{
  struct ftsym *ftsym1;

  CHASH_DUMP_INIT(ftchash_rec_prefix2tag2, ftch_recprefix2tag2);

  ftsym1 = (struct ftsym*)0L;

  if (rpt->out->options & FT_STAT_OPT_NAMES)
    ftsym1 = ftsym_new(sym1);

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY1) {
      sort_offset = offsetof(struct ftchash_rec_prefix2tag2, src_prefix);
      sort_flags |= FT_CHASH_SORT_40;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY2) {
      sort_offset = offsetof(struct ftchash_rec_prefix2tag2, dst_prefix);
      sort_flags |= FT_CHASH_SORT_40;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY3) {
      sort_offset = offsetof(struct ftchash_rec_prefix2tag2, src_tag);
      sort_flags |= FT_CHASH_SORT_32;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY4) {
      sort_offset = offsetof(struct ftchash_rec_prefix2tag2, dst_tag);
      sort_flags |= FT_CHASH_SORT_32;
    } else

    CHASH_DUMP_STD_SORT(ftchash_rec_prefix2tag2);

    ftchash_sort(ftch, sort_offset, sort_flags);

  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recprefix2tag2 = ftchash_foreach(ftch))) {

    len = comma = 0;

    DUMP_STD_OUT();
 
    if (rpt->out->fields & FT_STAT_FIELD_KEY1) {
      if (comma) fmt_buf[len++] = ',';
      if (rpt->options &
        (FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK))
        len += fmt_ipv4prefixs(fmt_buf+len, ftch_recprefix2tag2->src_prefix,
          ftch_recprefix2tag2->src_mask, 64, fmt);
      else
        len += fmt_ipv4s(fmt_buf+len, ftch_recprefix2tag2->src_prefix,
          64, fmt);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY2) {
      if (comma) fmt_buf[len++] = ',';
      if (rpt->options &
        (FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK))
        len += fmt_ipv4prefixs(fmt_buf+len, ftch_recprefix2tag2->dst_prefix,
          ftch_recprefix2tag2->dst_mask, 64, fmt);
      else
        len += fmt_ipv4s(fmt_buf+len, ftch_recprefix2tag2->dst_prefix,
          64, fmt);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY3) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint32s(ftsym1, FMT_SYM_LEN, fmt_buf+len,
        ftch_recprefix2tag2->src_tag, FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY4) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint32s(ftsym1, FMT_SYM_LEN, fmt_buf+len,
        ftch_recprefix2tag2->dst_tag, FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->options & FT_STAT_OPT_PERCENT) {

      CHASH_STDP_OUT(ftch_recprefix2tag2, comma);

    } else {

      CHASH_STD_OUT(ftch_recprefix2tag2, comma);

    }

  }

  if (ftsym1)
    ftsym_free(ftsym1);

  return 0;

} /* chash_prefix2tag2_dump */



static int chash_prefixh_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, int f1)
{

  CHASH_DUMP_INIT(ftchash_rec_prefixh, ftch_recprefixh);

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY) {
      sort_offset = offsetof(struct ftchash_rec_prefixh, prefix);
      sort_flags |= FT_CHASH_SORT_40;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_COUNT) {
      sort_offset = offsetof(struct ftchash_rec_prefixh, nprefixes);
      sort_flags |= FT_CHASH_SORT_64;
    } else

    CHASH_DUMP_STD_SORT(ftchash_rec_prefixh);

    ftchash_sort(ftch, sort_offset, sort_flags);

  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recprefixh = ftchash_foreach(ftch))) {

    len = comma = 0;

    DUMP_STD_OUT();
 
    if (rpt->out->fields & FT_STAT_FIELD_KEY) {
      if (comma) fmt_buf[len++] = ',';
      if (rpt->options & f1)
        len += fmt_ipv4prefixs(fmt_buf+len, ftch_recprefixh->prefix,
          ftch_recprefixh->mask, 64, fmt);
      else
        len += fmt_ipv4s(fmt_buf+len, ftch_recprefixh->prefix, 64, fmt);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_COUNT) {

      if (rpt->out->options & FT_STAT_OPT_PERCENT) {

        if (comma) fmt_buf[len++] = ',';
        len += sprintf(fmt_buf+len, "%f",
          ((double)ftch_recprefixh->nprefixes / rpt->t_count)*100.0);
        comma = 1;

      } else {

        if (comma) fmt_buf[len++] = ',';
        len += fmt_uint64(fmt_buf+len, ftch_recprefixh->nprefixes,
          FMT_JUST_LEFT);
        comma = 1;

      }
    }

    if (rpt->out->options & FT_STAT_OPT_PERCENT) {

      CHASH_STDP_OUT(ftch_recprefixh, comma);

    } else {

      CHASH_STD_OUT(ftch_recprefixh, comma);

    }

  }

  return 0;

} /* chash_prefixh_dump */

static int chash_prefix2_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch)
{

  CHASH_DUMP_INIT(ftchash_rec_prefix2, ftch_recprefix2);

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY1) {
      sort_offset = offsetof(struct ftchash_rec_prefix2, src_prefix);
      sort_flags |= FT_CHASH_SORT_40;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY2) {
      sort_offset = offsetof(struct ftchash_rec_prefix2, dst_prefix);
      sort_flags |= FT_CHASH_SORT_40;
    } else

    CHASH_DUMP_STD_SORT(ftchash_rec_prefix2);

    ftchash_sort(ftch, sort_offset, sort_flags);

  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recprefix2 = ftchash_foreach(ftch))) {

    len = comma = 0;

    DUMP_STD_OUT();
 
    if (rpt->out->fields & FT_STAT_FIELD_KEY1) {
      if (comma) fmt_buf[len++] = ',';
      if (rpt->options &
        (FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK))
        len += fmt_ipv4prefixs(fmt_buf+len, ftch_recprefix2->src_prefix,
          ftch_recprefix2->src_mask, 64, fmt);
      else
        len += fmt_ipv4s(fmt_buf+len, ftch_recprefix2->src_prefix, 64, fmt);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY2) {
      if (comma)
        fmt_buf[len++] = ',';
      if (rpt->options &
        (FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK))
        len += fmt_ipv4prefixs(fmt_buf+len, ftch_recprefix2->dst_prefix,
          ftch_recprefix2->dst_mask, 64, fmt);
      else
        len += fmt_ipv4s(fmt_buf+len, ftch_recprefix2->dst_prefix, 64, fmt);
      comma = 1;
    }

    if (rpt->out->options & FT_STAT_OPT_PERCENT) {

      CHASH_STDP_OUT(ftch_recprefix2, comma);

    } else {

      CHASH_STD_OUT(ftch_recprefix2, comma);

    }

  }

  return 0;

} /* chash_prefix2_dump */

static int chash_prefix16_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1, int f1)
{
  struct ftsym *ftsym1;

  CHASH_DUMP_INIT(ftchash_rec_prefix16, ftch_recprefix16);

  ftsym1 = (struct ftsym*)0L;

  if (rpt->out->options & FT_STAT_OPT_NAMES)
    ftsym1 = ftsym_new(sym1);

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY2) {
      sort_offset = offsetof(struct ftchash_rec_prefix16, c16);
      sort_flags |= FT_CHASH_SORT_16;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY1) {
      sort_offset = offsetof(struct ftchash_rec_prefix16, prefix);
      sort_flags |= FT_CHASH_SORT_40;
    } else

    CHASH_DUMP_STD_SORT(ftchash_rec_prefix16);

    ftchash_sort(ftch, sort_offset, sort_flags);

  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recprefix16 = ftchash_foreach(ftch))) {

    len = comma = 0;

    DUMP_STD_OUT();

    if (rpt->out->fields & FT_STAT_FIELD_KEY1) {
      if (comma) fmt_buf[len++] = ',';
      if (rpt->options & f1)
        len += fmt_ipv4prefixs(fmt_buf+len, ftch_recprefix16->prefix,
          ftch_recprefix16->mask, 64, fmt);
      else
        len += fmt_ipv4s(fmt_buf+len, ftch_recprefix16->prefix, 64, fmt);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY2) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint16s(ftsym1, FMT_SYM_LEN, fmt_buf+len,
        ftch_recprefix16->c16, FMT_JUST_LEFT);
      comma = 1;
    }
 
    if (rpt->out->options & FT_STAT_OPT_PERCENT) {

      CHASH_STDP_OUT(ftch_recprefix16, comma);

    } else {

      CHASH_STD_OUT(ftch_recprefix16, comma);

    }

  }

  if (ftsym1)
    ftsym_free(ftsym1);

  return 0;

} /* chash_prefix16_dump */

static int chash_prefix162_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1, char *sym2, int f1)
{
  struct ftsym *ftsym1, *ftsym2;

  CHASH_DUMP_INIT(ftchash_rec_prefix162, ftch_recprefix162);

  ftsym1 = ftsym2 = (struct ftsym*)0L;

  if (rpt->out->options & FT_STAT_OPT_NAMES) {
    ftsym1 = ftsym_new(sym1);
    ftsym2 = ftsym_new(sym2);
  }

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY3) {
      sort_offset = offsetof(struct ftchash_rec_prefix162, c16b);
      sort_flags |= FT_CHASH_SORT_16;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY2) {
      sort_offset = offsetof(struct ftchash_rec_prefix162, c16a);
      sort_flags |= FT_CHASH_SORT_16;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY1) {
      sort_offset = offsetof(struct ftchash_rec_prefix162, prefix);
      sort_flags |= FT_CHASH_SORT_40;
    } else

    CHASH_DUMP_STD_SORT(ftchash_rec_prefix162);

    ftchash_sort(ftch, sort_offset, sort_flags);

  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recprefix162 = ftchash_foreach(ftch))) {

    len = comma = 0;

    DUMP_STD_OUT();

    if (rpt->out->fields & FT_STAT_FIELD_KEY1) {
      if (comma) fmt_buf[len++] = ',';
      if (rpt->options & f1)
        len += fmt_ipv4prefixs(fmt_buf+len, ftch_recprefix162->prefix,
          ftch_recprefix162->mask, 64, fmt);
      else
        len += fmt_ipv4s(fmt_buf+len, ftch_recprefix162->prefix, 64, fmt);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY2) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint16s(ftsym2, FMT_SYM_LEN, fmt_buf+len,
        ftch_recprefix162->c16a, FMT_JUST_LEFT);
      comma = 1;
    }


    if (rpt->out->fields & FT_STAT_FIELD_KEY3) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint16s(ftsym1, FMT_SYM_LEN, fmt_buf+len,
        ftch_recprefix162->c16b, FMT_JUST_LEFT);
      comma = 1;
    }


    if (rpt->out->options & FT_STAT_OPT_PERCENT) {

      CHASH_STDP_OUT(ftch_recprefix162, comma);

    } else {

      CHASH_STD_OUT(ftch_recprefix162, comma);

    }

  }

  if (ftsym1)
    ftsym_free(ftsym1);

  if (ftsym2)
    ftsym_free(ftsym2);

  return 0;

} /* chash_prefix162_dump */



static int chash_prefix216_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1)
{
  struct ftsym *ftsym1;

  CHASH_DUMP_INIT(ftchash_rec_prefix216, ftch_recprefix216);

  ftsym1 = (struct ftsym*)0L;

  if (rpt->out->options & FT_STAT_OPT_NAMES)
    ftsym1 = ftsym_new(sym1);

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY3) {
      sort_offset = offsetof(struct ftchash_rec_prefix216, c16);
      sort_flags |= FT_CHASH_SORT_16;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY1) {
      sort_offset = offsetof(struct ftchash_rec_prefix216, src_prefix);
      sort_flags |= FT_CHASH_SORT_40;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY2) {
      sort_offset = offsetof(struct ftchash_rec_prefix216, dst_prefix);
      sort_flags |= FT_CHASH_SORT_40;
    } else

    CHASH_DUMP_STD_SORT(ftchash_rec_prefix216);

    ftchash_sort(ftch, sort_offset, sort_flags);

  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recprefix216 = ftchash_foreach(ftch))) {

    len = comma = 0;

    DUMP_STD_OUT();

    if (rpt->out->fields & FT_STAT_FIELD_KEY1) {
      if (comma) fmt_buf[len++] = ',';
      if (rpt->options &
        (FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK))
        len += fmt_ipv4prefixs(fmt_buf+len, ftch_recprefix216->src_prefix,
          ftch_recprefix216->src_mask, 64, fmt);
      else
        len += fmt_ipv4s(fmt_buf+len, ftch_recprefix216->src_prefix, 64, fmt);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY2) {
      if (comma) fmt_buf[len++] = ',';
      if (rpt->options &
        (FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK))
        len += fmt_ipv4prefixs(fmt_buf+len, ftch_recprefix216->dst_prefix,
          ftch_recprefix216->dst_mask, 64, fmt);
      else
        len += fmt_ipv4s(fmt_buf+len, ftch_recprefix216->dst_prefix,
          64, fmt);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY3) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint16s(ftsym1, FMT_SYM_LEN, fmt_buf+len,
        ftch_recprefix216->c16, FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->options & FT_STAT_OPT_PERCENT) {

      CHASH_STDP_OUT(ftch_recprefix216, comma);

    } else {

      CHASH_STD_OUT(ftch_recprefix216, comma);

    }

  }

  if (ftsym1)
    ftsym_free(ftsym1);

  return 0;

} /* chash_prefix216_dump */

static int chash_prefix2162_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1, char *sym2)
{
  struct ftsym *ftsym1, *ftsym2;

  CHASH_DUMP_INIT(ftchash_rec_prefix2162, ftch_recprefix2162);

  ftsym1 = ftsym2 = (struct ftsym*)0L;

  if (rpt->out->options & FT_STAT_OPT_NAMES) {
    ftsym1 = ftsym_new(sym1);
    ftsym2 = ftsym_new(sym2);
  }

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY3) {
      sort_offset = offsetof(struct ftchash_rec_prefix2162, c16a);
      sort_flags |= FT_CHASH_SORT_16;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY4) {
      sort_offset = offsetof(struct ftchash_rec_prefix2162, c16b);
      sort_flags |= FT_CHASH_SORT_16;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY1) {
      sort_offset = offsetof(struct ftchash_rec_prefix2162, src_prefix);
      sort_flags |= FT_CHASH_SORT_40;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY2) {
      sort_offset = offsetof(struct ftchash_rec_prefix2162, dst_prefix);
      sort_flags |= FT_CHASH_SORT_40;
    } else

    CHASH_DUMP_STD_SORT(ftchash_rec_prefix2162);

    ftchash_sort(ftch, sort_offset, sort_flags);

  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recprefix2162 = ftchash_foreach(ftch))) {

    len = comma = 0;

    DUMP_STD_OUT();

    if (rpt->out->fields & FT_STAT_FIELD_KEY1) {
      if (comma) fmt_buf[len++] = ',';
      if (rpt->options &
        (FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK))
        len += fmt_ipv4prefixs(fmt_buf+len, ftch_recprefix2162->src_prefix,
          ftch_recprefix2162->src_mask, 64, fmt);
      else
        len += fmt_ipv4s(fmt_buf+len, ftch_recprefix2162->src_prefix, 64, fmt);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY2) {
      if (comma) fmt_buf[len++] = ',';
      if (rpt->options &
        (FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK))
        len += fmt_ipv4prefixs(fmt_buf+len, ftch_recprefix2162->dst_prefix,
          ftch_recprefix2162->dst_mask, 64, fmt);
      else
        len += fmt_ipv4s(fmt_buf+len, ftch_recprefix2162->dst_prefix, 64, fmt);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY3) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint16s(ftsym1, FMT_SYM_LEN, fmt_buf+len,
        ftch_recprefix2162->c16a, FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY4) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint16s(ftsym2, FMT_SYM_LEN, fmt_buf+len,
        ftch_recprefix2162->c16b, FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->options & FT_STAT_OPT_PERCENT) {

      CHASH_STDP_OUT(ftch_recprefix2162, comma);

    } else {

      CHASH_STD_OUT(ftch_recprefix2162, comma);

    }

  }

  if (ftsym1)
    ftsym_free(ftsym1);

  if (ftsym2)
    ftsym_free(ftsym2);

  return 0;

} /* chash_prefix2162_dump */

static int chash_c64_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch)
{

  CHASH_DUMP_INIT(ftchash_rec_c64, ftch_recc64);

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY) {
      sort_offset = offsetof(struct ftchash_rec_c64, c64);
      sort_flags |= FT_CHASH_SORT_64;
    } else

    CHASH_DUMP_STD_SORT(ftchash_rec_c64);

    ftchash_sort(ftch, sort_offset, sort_flags);


  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recc64 = ftchash_foreach(ftch))) {

    len = comma = 0;

    DUMP_STD_OUT();

    if (rpt->out->fields & FT_STAT_FIELD_KEY) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint64(fmt_buf+len, ftch_recc64->c64, FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->options & FT_STAT_OPT_PERCENT) {

      CHASH_STDP_OUT(ftch_recc64, comma);

    } else {

      CHASH_STD_OUT(ftch_recc64, comma);

    }

  }

  return 0;

} /* chash_c64_dump */

static int chash_int_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch)
{

  CHASH_DUMP_INIT(ftchash_rec_int, ftch_recint);

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY) {
      sort_offset = offsetof(struct ftchash_rec_int, time);
      sort_flags |= FT_CHASH_SORT_32;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_FLOWS) {\
      sort_offset = offsetof(struct ftchash_rec_int, nflows);\
      sort_flags |= FT_CHASH_SORT_DOUBLE;\
    } else if (rpt->out->sort_field == FT_STAT_FIELD_OCTETS) {\
      sort_offset = offsetof(struct ftchash_rec_int, noctets);\
      sort_flags |= FT_CHASH_SORT_DOUBLE;\
    } else if (rpt->out->sort_field == FT_STAT_FIELD_PACKETS) {\
      sort_offset = offsetof(struct ftchash_rec_int, npackets);\
      sort_flags |= FT_CHASH_SORT_DOUBLE;\
    }

    ftchash_sort(ftch, sort_offset, sort_flags);


  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recint = ftchash_foreach(ftch))) {

    len = comma = 0;

    DUMP_STD_OUT();

    if (rpt->out->fields & FT_STAT_FIELD_KEY) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint32(fmt_buf+len, ftch_recint->time, FMT_JUST_LEFT);
      comma = 1;
    }

/* XXX percent totals? */

    if (rpt->out->fields & FT_STAT_FIELD_FLOWS) {
      if (comma) fmt_buf[len++] = ',';
      len += sprintf(fmt_buf+len, "%f", ftch_recint->nflows);\
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_OCTETS) {
      if (comma) fmt_buf[len++] = ',';
      len += sprintf(fmt_buf+len, "%f", ftch_recint->noctets);\
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_PACKETS) {
      if (comma) fmt_buf[len++] = ',';
      len += sprintf(fmt_buf+len, "%f", ftch_recint->npackets);\
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_FRECS) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint64(fmt_buf+len, ftch_recint->nrecs, FMT_JUST_LEFT);
      comma = 1;\
    }

    fmt_buf[len++] = '\n';
    fmt_buf[len] = 0;

    fputs(fmt_buf, fp);

    if (rpt->out->records && (tally.rt_recs == rpt->out->records)) {
      fprintf(fp, "# stop, hit record limit.\n");
      break;
    }

  }

  return 0;

} /* chash_int_dump */

static int chash_flow1_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1, char *sym2)
{
  struct ftsym *ftsym1, *ftsym2;

  CHASH_DUMP_INIT(ftchash_rec_flow1, ftch_recflow1);

  ftsym1 = ftsym2 = (struct ftsym*)0L;

  if (rpt->out->options & FT_STAT_OPT_NAMES) {
    ftsym1 = ftsym_new(sym1);
    ftsym2 = ftsym_new(sym2);
  }

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY1) {
      sort_offset = offsetof(struct ftchash_rec_flow1, src_prefix);
      sort_flags |= FT_CHASH_SORT_40;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY2) {
      sort_offset = offsetof(struct ftchash_rec_flow1, dst_prefix);
      sort_flags |= FT_CHASH_SORT_40;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY3) {
      sort_offset = offsetof(struct ftchash_rec_flow1, src_port);
      sort_flags |= FT_CHASH_SORT_16;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY4) {
      sort_offset = offsetof(struct ftchash_rec_flow1, dst_port);
      sort_flags |= FT_CHASH_SORT_16;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY5) {
      sort_offset = offsetof(struct ftchash_rec_flow1, prot);
      sort_flags |= FT_CHASH_SORT_8;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY6) {
      sort_offset = offsetof(struct ftchash_rec_flow1, tos);
      sort_flags |= FT_CHASH_SORT_8;
    } else

    CHASH_DUMP_STD_SORT(ftchash_rec_flow1);

    ftchash_sort(ftch, sort_offset, sort_flags);

  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recflow1 = ftchash_foreach(ftch))) {

    len = comma = 0;

    DUMP_STD_OUT();

    if (rpt->out->fields & FT_STAT_FIELD_KEY1) {
      if (comma) fmt_buf[len++] = ',';
      if (rpt->options &
        (FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK))
        len += fmt_ipv4prefixs(fmt_buf+len, ftch_recflow1->src_prefix,
          ftch_recflow1->src_mask, 64, fmt);
      else
        len += fmt_ipv4s(fmt_buf+len, ftch_recflow1->src_prefix, 64, fmt);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY2) {
      if (comma) fmt_buf[len++] = ',';
      if (rpt->options &
        (FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK))
        len += fmt_ipv4prefixs(fmt_buf+len, ftch_recflow1->dst_prefix,
          ftch_recflow1->dst_mask, 64, fmt);
      else
        len += fmt_ipv4s(fmt_buf+len, ftch_recflow1->dst_prefix, 64, fmt);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY3) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint16s(ftsym1, FMT_SYM_LEN, fmt_buf+len,
        ftch_recflow1->src_port, FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY4) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint16s(ftsym1, FMT_SYM_LEN, fmt_buf+len,
        ftch_recflow1->dst_port, FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY5) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint8s(ftsym2, FMT_SYM_LEN, fmt_buf+len, ftch_recflow1->prot,
        FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY6) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint8(fmt_buf+len, ftch_recflow1->tos,
        FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->options & FT_STAT_OPT_PERCENT) {

      CHASH_STDP_OUT(ftch_recflow1, comma);

    } else {

      CHASH_STD_OUT(ftch_recflow1, comma);

    }

  }

  if (ftsym1)
    ftsym_free(ftsym1);

  if (ftsym2)
    ftsym_free(ftsym2);

  return 0;

} /* chash_flow1_dump */

static int chash_flow12_dump(FILE *fp, struct ftstat_rpt *rpt,
  struct ftchash *ftch, char *sym1)
{
  struct ftsym *ftsym1;

  CHASH_DUMP_INIT(ftchash_rec_flow1, ftch_recflow1);

  ftsym1 = (struct ftsym*)0L;

  if (rpt->out->options & FT_STAT_OPT_NAMES) {
    ftsym1 = ftsym_new(sym1);
  }

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      sort_flags = FT_CHASH_SORT_ASCENDING;
    else
      sort_flags = 0;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY1) {
      sort_offset = offsetof(struct ftchash_rec_flow1, src_prefix);
      sort_flags |= FT_CHASH_SORT_40;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY2) {
      sort_offset = offsetof(struct ftchash_rec_flow1, dst_prefix);
      sort_flags |= FT_CHASH_SORT_40;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY3) {
      sort_offset = offsetof(struct ftchash_rec_flow1, prot);
      sort_flags |= FT_CHASH_SORT_8;
    } else if (rpt->out->sort_field == FT_STAT_FIELD_KEY4) {
      sort_offset = offsetof(struct ftchash_rec_flow1, tos);
      sort_flags |= FT_CHASH_SORT_8;
    } else

    CHASH_DUMP_STD_SORT(ftchash_rec_flow1);

    ftchash_sort(ftch, sort_offset, sort_flags);

  } /* FT_STAT_OPT_SORT */

  ftchash_first(ftch);

  while ((ftch_recflow1 = ftchash_foreach(ftch))) {

    len = comma = 0;

    DUMP_STD_OUT();

    if (rpt->out->fields & FT_STAT_FIELD_KEY1) {
      if (comma) fmt_buf[len++] = ',';
      if (rpt->options &
        (FT_STAT_OPT_SRC_PREFIX_LEN|FT_STAT_OPT_SRC_PREFIX_MASK))
        len += fmt_ipv4prefixs(fmt_buf+len, ftch_recflow1->src_prefix,
          ftch_recflow1->src_mask, 64, fmt);
      else
        len += fmt_ipv4s(fmt_buf+len, ftch_recflow1->src_prefix,
          64, fmt);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY2) {
      if (comma) fmt_buf[len++] = ',';
      if (rpt->options &
        (FT_STAT_OPT_DST_PREFIX_LEN|FT_STAT_OPT_DST_PREFIX_MASK))
        len += fmt_ipv4prefixs(fmt_buf+len, ftch_recflow1->dst_prefix,
          ftch_recflow1->dst_mask, 64, fmt);
      else
        len += fmt_ipv4s(fmt_buf+len, ftch_recflow1->dst_prefix, 64, fmt);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY3) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint8s(ftsym1, FMT_SYM_LEN, fmt_buf+len, ftch_recflow1->prot,
        FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->fields & FT_STAT_FIELD_KEY4) {
      if (comma) fmt_buf[len++] = ',';
      len += fmt_uint8(fmt_buf+len, ftch_recflow1->tos,
        FMT_JUST_LEFT);
      comma = 1;
    }

    if (rpt->out->options & FT_STAT_OPT_PERCENT) {

      CHASH_STDP_OUT(ftch_recflow1, comma);

    } else {

      CHASH_STD_OUT(ftch_recflow1, comma);

    }

  }

  if (ftsym1)
    ftsym_free(ftsym1);

  return 0;

} /* chash_flow12_dump */


static int bucket_dump1(FILE *fp, struct ftstat_rpt *rpt, struct flow_bucket *b,
  u_int32 nindex, char *symfile)
{
  struct ftsym *ftsym;
  struct tally tally;
  char fmt_buf1[32], fmt_buf[1024];
  int len, comma;
  int32 i, start, end, increment;
  u_int32 *index;

  ftsym = (struct ftsym*)0L;
  fmt_buf1[0] = fmt_buf[0] = 0;
  index = b->index;
  bzero(&tally, sizeof tally);

  if (rpt->out->options & FT_STAT_OPT_NAMES)
    ftsym = ftsym_new(symfile);

  start = 0; end = nindex, increment = 1;

  if (rpt->out->options & FT_STAT_OPT_SORT) {

    if (rpt->out->sort_order & FT_STAT_SORT_ASCEND)
      start = nindex - 1, end = -1, increment = -1;

    if (rpt->out->sort_field == FT_STAT_FIELD_KEY) {
      ; /* sorted by default */
    } else if (rpt->out->sort_field == FT_STAT_FIELD_FLOWS) {
      sort_i64 = b->flows;
      qsort(b->index, nindex, sizeof (u_int32), sort_cmp64);
    } else if (rpt->out->sort_field == FT_STAT_FIELD_OCTETS) {
      sort_i64 = b->octets;
      qsort(b->index, nindex, sizeof (u_int32), sort_cmp64);
    } else if (rpt->out->sort_field == FT_STAT_FIELD_PACKETS) {
      sort_i64 = b->packets;
      qsort(b->index, nindex, sizeof (u_int32), sort_cmp64);
    } else if (rpt->out->sort_field == FT_STAT_FIELD_DURATION) {
      sort_i64 = b->duration;
      qsort(b->index, nindex, sizeof (u_int32), sort_cmp64);
    } else if (rpt->out->sort_field == FT_STAT_FIELD_AVG_PPS) {
      sort_idouble = b->avg_pps;
      qsort(b->index, nindex, sizeof (u_int32), sort_cmp_double);
    } else if (rpt->out->sort_field == FT_STAT_FIELD_MIN_PPS) {
      sort_idouble = b->min_pps;
      qsort(b->index, nindex, sizeof (u_int32), sort_cmp_double);
    } else if (rpt->out->sort_field == FT_STAT_FIELD_MAX_PPS) {
      sort_idouble = b->max_pps;
      qsort(b->index, nindex, sizeof (u_int32), sort_cmp_double);
    } else if (rpt->out->sort_field == FT_STAT_FIELD_AVG_BPS) {
      sort_idouble = b->avg_bps;
      qsort(b->index, nindex, sizeof (u_int32), sort_cmp_double);
    } else if (rpt->out->sort_field == FT_STAT_FIELD_MIN_BPS) {
      sort_idouble = b->min_bps;
      qsort(b->index, nindex, sizeof (u_int32), sort_cmp_double);
    } else if (rpt->out->sort_field == FT_STAT_FIELD_MAX_BPS) {
      sort_idouble = b->max_bps;
      qsort(b->index, nindex, sizeof (u_int32), sort_cmp_double);
    } else {
      fterr_errx(1,"bucket_dump1(): internal error");
    }

  } /* FT_STAT_OPT_SORT */

  /* need to know the total number of records first */
  if (rpt->out->options & FT_STAT_OPT_TALLY) {

    for (i = start; i != end; i += increment) {

      if (!b->flows[index[i]])
        continue;

      ++tally.t_recs;

    }

  }

  if (rpt->out->options & FT_STAT_OPT_PERCENT) {

    for (i = start; i != end; i += increment) {

      if (!b->flows[index[i]])
        continue;

      if ((rpt->out->options & FT_STAT_OPT_TALLY) && tally.rt_recs &&
        (!(tally.rt_recs % rpt->out->tally))) {

        if (rpt->all_fields & FT_STAT_FIELD_PS)
          fprintf(fp, "#TALLY %%recs=%3.3f %%flows=%3.3f %%octets=%3.3f %%packets=%3.3f %%avg-bps=%3.3f %%avg-pps=%3.3f\n",
            ((double)tally.rt_recs/(double)tally.t_recs)*100,
            ((double)tally.rt_flows/(double)rpt->t_flows)*100,
            ((double)tally.rt_octets/(double)rpt->t_octets)*100,
            ((double)tally.rt_packets/(double)rpt->t_packets)*100,
            (((double)tally.ravg_bps/(double)tally.rt_frecs)/
              (double)rpt->avg_bps)*100,
            (((double)tally.ravg_pps/(double)tally.rt_frecs)/
              (double)rpt->avg_pps)*100);
         else
          fprintf(fp, "#TALLY %%recs=%3.3f %%flows=%3.3f %%octets=%3.3f %%packets=%3.3f\n",
            ((double)tally.rt_recs/(double)tally.t_recs)*100,
            ((double)tally.rt_flows/(double)rpt->t_flows)*100,
            ((double)tally.rt_octets/(double)rpt->t_octets)*100,
            ((double)tally.rt_packets/(double)rpt->t_packets)*100);

      } /* tally */

      tally.rt_flows += b->flows[index[i]];
      tally.rt_octets += b->octets[index[i]];
      tally.rt_packets += b->packets[index[i]];
      tally.rt_frecs += b->recs[index[i]];
      tally.rt_recs ++;
      if (rpt->all_fields & FT_STAT_FIELD_PS) {
        tally.ravg_bps += b->avg_bps[index[i]] * b->recs[index[i]];
        tally.ravg_pps += b->avg_pps[index[i]] * b->recs[index[i]];
      }

      len = comma = 0;

      DUMP_STD_OUT();

      if (rpt->out->fields & FT_STAT_FIELD_KEY) {
        if (comma) fmt_buf[len++] = ',';
        len += fmt_uint32s(ftsym, FMT_SYM_LEN, fmt_buf+len, b->index[i],
          FMT_JUST_LEFT);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_FLOWS) {
        if (comma) fmt_buf[len++] = ',';
        len += sprintf(fmt_buf+len, "%f",
         ((double)b->flows[index[i]] / (double)rpt->t_flows)*100.0);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_OCTETS) {
        if (comma) fmt_buf[len++] = ',';
        len += sprintf(fmt_buf+len, "%f",
         ((double)b->octets[index[i]] / (double)rpt->t_octets)*100.0);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_PACKETS) {
        if (comma) fmt_buf[len++] = ',';
        len += sprintf(fmt_buf+len, "%f",
         ((double)b->packets[index[i]] / (double)rpt->t_packets)*100.0);
        comma = 1;
      }


      if (rpt->out->fields & FT_STAT_FIELD_DURATION) {
        if (comma) fmt_buf[len++] = ',';
        len += sprintf(fmt_buf+len, "%f",
         ((double)b->duration[index[i]] / (double)rpt->t_duration)*100.0);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_AVG_BPS) {
        if (comma) fmt_buf[len++] = ',';
        len += sprintf(fmt_buf+len, "%f",
         ((double)b->avg_bps[index[i]] / (double)rpt->avg_bps)*100.0);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_MIN_BPS) {
        if (comma) fmt_buf[len++] = ',';
        len += sprintf(fmt_buf+len, "%f",
         ((double)b->min_bps[index[i]] / (double)rpt->min_bps)*100.0);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_MAX_BPS) {
        if (comma) fmt_buf[len++] = ',';
        len += sprintf(fmt_buf+len, "%f",
         ((double)b->max_bps[index[i]] / (double)rpt->max_bps)*100.0);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_AVG_PPS) {
        if (comma) fmt_buf[len++] = ',';
        len += sprintf(fmt_buf+len, "%f",
         ((double)b->avg_pps[index[i]] / (double)rpt->avg_pps)*100.0);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_MIN_PPS) {
        if (comma) fmt_buf[len++] = ',';
        len += sprintf(fmt_buf+len, "%f",
         ((double)b->min_pps[index[i]] / (double)rpt->min_pps)*100.0);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_MAX_PPS) {
        if (comma) fmt_buf[len++] = ',';
        len += sprintf(fmt_buf+len, "%f",
         ((double)b->max_pps[index[i]] / (double)rpt->max_pps)*100.0);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_FRECS) {
        if (comma) fmt_buf[len++] = ',';
        len += fmt_uint64(fmt_buf+len, b->recs[index[i]], FMT_JUST_LEFT);\
        comma = 1;
      }

      fmt_buf[len++] = '\n';
      fmt_buf[len] = 0;

      fputs(fmt_buf, fp);

      if (rpt->out->records && (tally.rt_recs == rpt->out->records)) {
        fprintf(fp, "# stop, hit record limit.\n");
        break;
      }

    }

  } else {

    for (i = start; i != end; i += increment) {

      if (!b->flows[index[i]])
        continue;

      if ((rpt->out->options & FT_STAT_OPT_TALLY) && tally.rt_recs &&
        (!(tally.rt_recs % rpt->out->tally))) {

        if (rpt->all_fields & FT_STAT_FIELD_PS)
          fprintf(fp, "#TALLY %%recs=%3.3f %%flows=%3.3f %%octets=%3.3f %%packets=%3.3f %%avg-bps=%3.3f %%avg-pps=%3.3f\n",
            ((double)tally.rt_recs/(double)tally.t_recs)*100,
            ((double)tally.rt_flows/(double)rpt->t_flows)*100,
            ((double)tally.rt_octets/(double)rpt->t_octets)*100,
            ((double)tally.rt_packets/(double)rpt->t_packets)*100,
            (((double)tally.ravg_bps/(double)tally.rt_frecs)/
              (double)rpt->avg_bps)*100,
            (((double)tally.ravg_pps/(double)tally.rt_frecs)/
              (double)rpt->avg_pps)*100);
         else
          fprintf(fp, "#TALLY %%recs=%3.3f %%flows=%3.3f %%octets=%3.3f %%packets=%3.3f\n",
            ((double)tally.rt_recs/(double)tally.t_recs)*100,
            ((double)tally.rt_flows/(double)rpt->t_flows)*100,
            ((double)tally.rt_octets/(double)rpt->t_octets)*100,
            ((double)tally.rt_packets/(double)rpt->t_packets)*100);

      } /* tally */

      tally.rt_flows += b->flows[index[i]];
      tally.rt_octets += b->octets[index[i]];
      tally.rt_packets += b->packets[index[i]];
      tally.rt_recs ++;
      tally.rt_frecs += b->recs[index[i]];
      if (rpt->all_fields & FT_STAT_FIELD_PS) {
        tally.ravg_bps += b->avg_bps[index[i]] * b->recs[index[i]];
        tally.ravg_pps += b->avg_pps[index[i]] * b->recs[index[i]];
      }

      len = comma = 0;

      DUMP_STD_OUT();

      if (rpt->out->fields & FT_STAT_FIELD_KEY) {
        if (comma) fmt_buf[len++] = ',';
        len += fmt_uint32s(ftsym, FMT_SYM_LEN, fmt_buf+len, b->index[i],
          FMT_JUST_LEFT);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_FLOWS) {
        if (comma) fmt_buf[len++] = ',';
        len += fmt_uint64(fmt_buf+len, b->flows[index[i]], FMT_JUST_LEFT);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_OCTETS) {
        if (comma) fmt_buf[len++] = ',';
        len += fmt_uint64(fmt_buf+len, b->octets[index[i]], FMT_JUST_LEFT);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_PACKETS) {
        if (comma) fmt_buf[len++] = ',';
        len += fmt_uint64(fmt_buf+len, b->packets[index[i]], FMT_JUST_LEFT);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_DURATION) {
        if (comma) fmt_buf[len++] = ',';
        len += fmt_uint64(fmt_buf+len, b->duration[index[i]], FMT_JUST_LEFT);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_AVG_BPS) {
        if (comma) fmt_buf[len++] = ',';
        len += sprintf(fmt_buf+len, "%f", b->avg_bps[index[i]]);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_MIN_BPS) {
        if (comma) fmt_buf[len++] = ',';
        len += sprintf(fmt_buf+len, "%f", b->min_bps[index[i]]);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_MAX_BPS) {
        if (comma) fmt_buf[len++] = ',';
        len += sprintf(fmt_buf+len, "%f", b->max_bps[index[i]]);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_AVG_PPS) {
        if (comma) fmt_buf[len++] = ',';
        len += sprintf(fmt_buf+len, "%f", b->avg_pps[index[i]]);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_MIN_PPS) {
        if (comma) fmt_buf[len++] = ',';
        len += sprintf(fmt_buf+len, "%f", b->min_pps[index[i]]);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_MAX_PPS) {
        if (comma) fmt_buf[len++] = ',';
        len += sprintf(fmt_buf+len, "%f", b->max_pps[index[i]]);
        comma = 1;
      }

      if (rpt->out->fields & FT_STAT_FIELD_FRECS) {
        if (comma) fmt_buf[len++] = ',';
        len += fmt_uint64(fmt_buf+len, b->recs[index[i]], FMT_JUST_LEFT);\
        comma = 1;
      }

      fmt_buf[len++] = '\n';
      fmt_buf[len] = 0;

      fputs(fmt_buf, fp);

      if (rpt->out->records && (tally.rt_recs == rpt->out->records)) {
        fprintf(fp, "# stop, hit record limit.\n");
        break;
      }

    } /* foreach record */

  } /* totals */

  if (ftsym)
    ftsym_free(ftsym);

  return 0;

} /* bucket_dump1 */

static int recn_dump(FILE *fp, int fields, char *key, char *key1,
  char *key2, char *key3, char *key4, char *key5, char *key6)
{
  int comma;

  fprintf(fp, "# recn: ");
  comma = 0;

  if (fields & FT_STAT_FIELD_INDEX) {
    fprintf(fp, "%sindex", comma ? "," : "");
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_FIRST) {
    fprintf(fp, "%sfirst", comma ? "," : "");
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_LAST) {
    fprintf(fp, "%slast", comma ? "," : "");
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_KEY) {
    fprintf(fp, "%s%s*", comma ? "," : "", key);
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_KEY1) {
    fprintf(fp, "%s%s*", comma ? "," : "", key1);
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_KEY2) {
    fprintf(fp, "%s%s*", comma ? "," : "", key2);
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_KEY3) {
    fprintf(fp, "%s%s*", comma ? "," : "", key3);
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_KEY4) {
    fprintf(fp, "%s%s*", comma ? "," : "", key4);
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_KEY5) {
    fprintf(fp, "%s%s*", comma ? "," : "", key5);
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_KEY6) {
    fprintf(fp, "%s%s*", comma ? "," : "", key6);
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_COUNT) {
    fprintf(fp, "%s%s", comma ? "," : "", key1);
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_FLOWS) {
    fprintf(fp, "%sflows", comma ? "," : "");
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_OCTETS) {
    fprintf(fp, "%soctets", comma ? "," : "");
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_PACKETS) {
    fprintf(fp, "%spackets", comma ? "," : "");
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_DURATION) {
    fprintf(fp, "%sduration", comma ? "," : "");
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_AVG_BPS) {
    fprintf(fp, "%savg-bps", comma ? "," : "");
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_MIN_BPS) {
    fprintf(fp, "%smin-bps", comma ? "," : "");
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_MAX_BPS) {
    fprintf(fp, "%smax-bps", comma ? "," : "");
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_AVG_PPS) {
    fprintf(fp, "%savg-pps", comma ? "," : "");
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_MIN_PPS) {
    fprintf(fp, "%smin-pps", comma ? "," : "");
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_MAX_PPS) {
    fprintf(fp, "%smax-pps", comma ? "," : "");
    comma = 1;
  }

  if (fields & FT_STAT_FIELD_FRECS) {
    fprintf(fp, "%sfrecs", comma ? "," : "");
    comma = 1;
  }

  fprintf(fp, "\n");

  return 0;

} /* recn_dump */

int bucket_alloc(struct flow_bucket *b, u_int32 n, struct ftstat_rpt *rpt)
{
  register int i;

  bzero(b, sizeof (*b));

  if (!(b->recs = (u_int64*)malloc(n*sizeof(u_int64)))) {
    fterr_warn("malloc(b->recs):");
    return -1;
  }

  if (!(b->flows = (u_int64*)malloc(n*sizeof(u_int64)))) {
    fterr_warn("malloc(b->flows):");
    return -1;
  }

  if (!(b->octets = (u_int64*)malloc(n*sizeof(u_int64)))) {
    fterr_warn("malloc(fopdi):");
    bucket_free(b);
    return -1;
  }

  if (!(b->packets = (u_int64*)malloc(n*sizeof(u_int64)))) {
    fterr_warn("malloc(b->packets):");
    bucket_free(b);
    return -1;
  }

  if (!(b->duration = (u_int64*)malloc(n*sizeof(u_int64)))) {
    fterr_warn("malloc(b->duration):");
    bucket_free(b);
    return -1;
  }

  if (!(b->index = (u_int32*)malloc(n*sizeof(u_int32)))) {
    fterr_warn("malloc(b->index):");
    bucket_free(b);
    return -1;
  }

  if (rpt->all_fields & FT_STAT_FIELD_PS) {

    if (!(b->avg_pps = (double*)malloc(n*sizeof(double)))) {
      fterr_warn("malloc(b->avg_pps):");
      bucket_free(b);
      return -1;
    }

    if (!(b->min_pps = (double*)malloc(n*sizeof(double)))) {
      fterr_warn("malloc(b->min_pps):");
      bucket_free(b);
      return -1;
    }

    if (!(b->max_pps = (double*)malloc(n*sizeof(double)))) {
      fterr_warn("malloc(b->max_pps):");
      bucket_free(b);
      return -1;
    }

    if (!(b->avg_bps = (double*)malloc(n*sizeof(double)))) {
      fterr_warn("malloc(b->avg_bps):");
      bucket_free(b);
      return -1;
    }

    if (!(b->min_bps = (double*)malloc(n*sizeof(double)))) {
      fterr_warn("malloc(b->min_bps):");
      bucket_free(b);
      return -1;
    }

    if (!(b->max_bps = (double*)malloc(n*sizeof(double)))) {
      fterr_warn("malloc(b->max_bps):");
      bucket_free(b);
      return -1;
    }

    bzero(b->avg_pps, n*sizeof(double));
    bzero(b->min_pps, n*sizeof(double));
    bzero(b->max_pps, n*sizeof(double));
    bzero(b->avg_bps, n*sizeof(double));
    bzero(b->min_bps, n*sizeof(double));
    bzero(b->max_bps, n*sizeof(double));

  }

  bzero(b->recs, n*sizeof(u_int64));
  bzero(b->flows, n*sizeof(u_int64));
  bzero(b->octets, n*sizeof(u_int64));
  bzero(b->packets, n*sizeof(u_int64));
  bzero(b->duration, n*sizeof(u_int64));

  for (i = 0; i < n; ++i)
    b->index[i] = i;

  return 0;

} /* bucket_alloc */

void bucket_free(struct flow_bucket *b)
{
  if (b->recs)
    free(b->recs);
  if (b->flows)
    free(b->flows);
  if (b->octets)
    free(b->octets);
  if (b->packets)
    free(b->packets);
  if (b->duration)
    free(b->duration);
  if (b->avg_pps)
    free(b->avg_pps);
  if (b->min_pps)
    free(b->min_pps);
  if (b->max_pps)
    free(b->max_pps);
  if (b->avg_bps)
    free(b->avg_bps);
  if (b->min_bps)
    free(b->min_bps);
  if (b->max_bps)
    free(b->max_bps);
  if (b->index)
    free(b->index);

  bzero(b, sizeof (*b));

} /* bucket_free */

static int sort_cmp64(const void *a, const void *b)
{
  u_int32 l, r;
        
  l = *(u_int32*)a;
  r = *(u_int32*)b;
        
  if (sort_i64[l] < sort_i64[r])
    return -1;
  if (sort_i64[l] > sort_i64[r])
    return 1;
  return 0;

} /* sort_cmp64 */

static int sort_cmp_double(const void *a, const void *b)
{
  u_int32 l, r;
        
  l = *(u_int32*)a;
  r = *(u_int32*)b;
        
  if (sort_idouble[l] < sort_idouble[r])
    return -1;
  if (sort_idouble[l] > sort_idouble[r])
    return 1;
  return 0;

} /* sort_cmp_double */

/*
 * function: load_tags
 *
 * load the filter definitions if they have not been loaded
 *
 * return value of fttag_load()
 *
 */
static int load_tags(struct ftstat *ftstat)
{
  struct ftver ftv;

  /* work to do? */
  if (ftstat->fttag_init)
    return 0;

  if (fttag_load(&ftstat->fttag, ftstat->ftvar, (ftstat->tag_fname) ?
    ftstat->tag_fname : FT_PATH_CFG_TAG)) {
    return 1;
  }

  /* required later by accum when tags are enabled */
  ftv.d_version = 1005;
  fts3rec_compute_offsets(&nfo, &ftv);

  ftstat->fttag_init = 1;
  return 0;

} /* load_tags */

/*
 * function: load_masks
 *
 * load the mask definitions if they have not been loaded
 *
 * return value of ftmask_load()
 *
 */
static int load_masks(struct ftstat *ftstat)
{

  /* work to do? */
  if (ftstat->ftmask_init)
    return 0;

  if (ftmask_load(&ftstat->ftmask, (ftstat->mask_fname) ?
    ftstat->mask_fname : FT_PATH_CFG_MASK)) {
    return 1;
  }

  ftstat->ftmask_init = 1;
  return 0;

} /* load_masks */

/*
 * function: load_filters
 *
 * load the filter definitions if they have not been loaded
 *
 * return value of ftfil_load()
 *
 */

static int load_filters(struct ftstat *ftstat)
{
 
  /* work to do? */
  if (ftstat->ftfil_init)
    return 0;

  if (ftfil_load(&ftstat->ftfil, ftstat->ftvar, (ftstat->filter_fname) ?
    ftstat->filter_fname : FT_PATH_CFG_FILTER)) {
    return 1;
  }

  ftstat->ftfil_init = 1;
  return 0;

} /* load_filters */

