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
 *      $Id: ftfil.c,v 1.20 2004/01/05 17:55:23 maf Exp $
 */

#include "ftinclude.h"
#include "ftlib.h"

#include "radix.h"

#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <ctype.h>
#include <syslog.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <zlib.h>

#if !HAVE_STRSEP
  char    *strsep (char **, const char *);
#endif

#define PARSE_PRIMITIVE_TYPE_INIT(A)\
  if (!(A = malloc (sizeof *A))) {\
    fterr_warn("malloc()");\
    return -1;\
  }\
  bzero(A, sizeof *A);\
  A->init = 1;\
  A->default_mode = FT_FIL_MODE_DENY;\
  lp->cur_primitive->lookup = A;\

#define RADIX_TRIE_INIT\
  if (!rn_init_called) {\
    max_keylen = sizeof(struct radix_sockaddr_in);\
    rn_init();\
    rn_init_called = 1;\
  }\

extern int max_keylen;
extern uint32_t mask_lookup[];
static int rn_init_called;
static struct radix_node_head *rhead;


enum ftfil_op { FT_FIL_OP_UNSET, FT_FIL_OP_LT, FT_FIL_OP_GT,
                   FT_FIL_OP_EQ, FT_FIL_OP_NE, FT_FIL_OP_GE,
                   FT_FIL_OP_LE };
    
enum ftfil_parse_state { PARSE_STATE_UNSET, PARSE_STATE_PRIMITIVE,
                          PARSE_STATE_DEFINITION };
    

enum ftfil_def_match { FT_FIL_DEFINITION_MATCH_UNSET,
                               FT_FIL_DEFINITION_MATCH_SRC_AS,
                               FT_FIL_DEFINITION_MATCH_DST_AS,
                               FT_FIL_DEFINITION_MATCH_IP_SRC_ADDR,
                               FT_FIL_DEFINITION_MATCH_IP_DST_ADDR,
                               FT_FIL_DEFINITION_MATCH_IP_EXPORTER_ADDR,
                               FT_FIL_DEFINITION_MATCH_IP_NEXT_HOP_ADDR,
                               FT_FIL_DEFINITION_MATCH_IP_SC_ADDR,
                               FT_FIL_DEFINITION_MATCH_IP_PROTOCOL,
                               FT_FIL_DEFINITION_MATCH_IP_SRC_PREFIX_LEN,
                               FT_FIL_DEFINITION_MATCH_IP_DST_PREFIX_LEN,
                               FT_FIL_DEFINITION_MATCH_IP_TOS,
                               FT_FIL_DEFINITION_MATCH_IP_MARKED_TOS,
                               FT_FIL_DEFINITION_MATCH_IP_TCP_FLAGS,
                               FT_FIL_DEFINITION_MATCH_IP_SRC_PORT,
                               FT_FIL_DEFINITION_MATCH_IP_DST_PORT,
                               FT_FIL_DEFINITION_MATCH_INPUT_IF,
                               FT_FIL_DEFINITION_MATCH_OUTPUT_IF,
                               FT_FIL_DEFINITION_MATCH_START_TIME,
                               FT_FIL_DEFINITION_MATCH_END_TIME,
                               FT_FIL_DEFINITION_MATCH_FLOWS,
                               FT_FIL_DEFINITION_MATCH_OCTETS,
                               FT_FIL_DEFINITION_MATCH_PACKETS,
                               FT_FIL_DEFINITION_MATCH_XTRA_PACKETS,
                               FT_FIL_DEFINITION_MATCH_DURATION,
                               FT_FIL_DEFINITION_MATCH_ENGINE_ID,
                               FT_FIL_DEFINITION_MATCH_ENGINE_TYPE,
                               FT_FIL_DEFINITION_MATCH_SRC_TAG,
                               FT_FIL_DEFINITION_MATCH_DST_TAG,
                               FT_FIL_DEFINITION_MATCH_PPS,
                               FT_FIL_DEFINITION_MATCH_BPS,
                               FT_FIL_DEFINITION_MATCH_RANDOM_SAMPLE };

char *op_name_lookup[] = {"Unset", "lt", "gt", "eq", "ne", "ge", "le"};
char *mode_name_lookup[] = {"Unset", "permit", "deny"};


struct line_parser {
  enum ftfil_parse_state state;
  enum ftfil_primitive_type type;
  enum ftfil_mode mode;
  struct ftfil_primitive *cur_primitive;
  struct ftfil_def *cur_def;
  struct ftfil_match *cur_def_match;
  struct ftsym *sym_ip_prot;
  struct ftsym *sym_ip_tcp_port;
#ifdef FT_PATH_SYM_ASN
  struct ftsym *sym_asn;
#endif
  struct ftsym *sym_tag;
  struct ftsym *sym_cur;
  int lineno;
  char *buf, *word;
  const char *fname;
  
};

struct ftfil_lookup_ip_address {
  struct ftchash *ftch;
  enum ftfil_mode default_mode; /* FT_FIL_MODE_PERMIT/DENY */
  int init; /* initialized? */
};

struct ftfil_lookup_ip_mask {
  FT_STAILQ_HEAD(filipmhead, ftfil_lookup_ip_mask_rec) list;
  enum ftfil_mode default_mode; /* FT_FIL_MODE_PERMIT/DENY */
  int init; /* initialized? */
};

struct ftfil_lookup_ip_mask_rec {
  FT_STAILQ_ENTRY(ftfil_lookup_ip_mask_rec) chain;
  uint32_t ip, mask;
  int mode; /* FT_FIL_MODE_PERMIT/DENY */
};

struct ftfil_lookup_ip_prefix_rec {
  struct radix_node rt_nodes[2]; /* radix tree glue */
  struct radix_sockaddr_in addr;
  uint8_t masklen;
  int mode; /* FT_FIL_MODE_PERMIT/DENY */
};

struct ftfil_lookup_ip_prefix {
  struct radix_node_head *rhead;
  enum ftfil_mode default_mode; /* FT_FIL_MODE_PERMIT/DENY */
  int init; /* initialized? */
};

struct ftfil_lookup_as {
  uint8_t mode[65536];
  enum ftfil_mode default_mode; /* FT_FIL_MODE_PERMIT/DENY */
  int init; /* initialized? */
};

struct ftfil_lookup_ip_prot {
  uint8_t mode[256];
  enum ftfil_mode default_mode; /* FT_FIL_MODE_PERMIT/DENY */
  int init; /* initialized? */
};

struct ftfil_lookup_ip_port {
  uint8_t mode[65536];
  enum ftfil_mode default_mode; /* FT_FIL_MODE_PERMIT/DENY */
  int init; /* initialized? */
};

struct ftfil_lookup_ip_tos {
  uint8_t mask;
  uint8_t mode[256];
  enum ftfil_mode default_mode; /* FT_FIL_MODE_PERMIT/DENY */
  int init; /* initialized? */
};

struct ftfil_lookup_ip_tcp_flags {
  uint8_t mask;
  uint8_t mode[256];
  enum ftfil_mode default_mode; /* FT_FIL_MODE_PERMIT/DENY */
  int init; /* initialized? */
};

struct ftfil_lookup_if_index {
  uint8_t mode[65536];
  enum ftfil_mode default_mode; /* FT_FIL_MODE_PERMIT/DENY */
  int init; /* initialized? */
};

struct ftfil_lookup_engine {
  uint8_t mode[256];
  enum ftfil_mode default_mode; /* FT_FIL_MODE_PERMIT/DENY */
  int init; /* initialized? */
};

struct ftfil_lookup_ip_prefix_len {
  uint8_t mode[33];
  enum ftfil_mode default_mode; /* FT_FIL_MODE_PERMIT/DENY */
  int init; /* initialized? */
};

struct ftfil_lookup_counter_rec {
  FT_STAILQ_ENTRY(ftfil_lookup_counter_rec) chain;
  uint32_t val;
  enum ftfil_op op; /* FT_FIL_OP */
  int mode;
};

struct ftfil_lookup_counter {
  FT_STAILQ_HEAD(fillchead, ftfil_lookup_counter_rec) list;
  enum ftfil_mode default_mode; /* FT_FIL_MODE_PERMIT/DENY */
  int init; /* initialized? */
};

struct ftfil_lookup_double_rec {
  FT_STAILQ_ENTRY(ftfil_lookup_double_rec) chain;
  double val;
  enum ftfil_op op; /* FT_FIL_OP */
  int mode;
};

struct ftfil_lookup_double {
  FT_STAILQ_HEAD(filldhead, ftfil_lookup_double_rec) list;
  enum ftfil_mode default_mode; /* FT_FIL_MODE_PERMIT/DENY */
  int init; /* initialized? */
};

struct ftfil_lookup_tag {
  struct ftchash *ftch;
  enum ftfil_mode default_mode; /* FT_FIL_MODE_PERMIT/DENY */
  int init; /* initialized? */
};

struct ftfil_lookup_tag_mask_rec {
  FT_STAILQ_ENTRY(ftfil_lookup_tag_mask_rec) chain;
  uint32_t tag, mask;
  int mode; /* FT_FIL_MODE_PERMIT/DENY */
};

struct ftfil_lookup_tag_mask {
  FT_STAILQ_HEAD(filtmhead, ftfil_lookup_tag_mask_rec) list;
  enum ftfil_mode default_mode; /* FT_FIL_MODE_PERMIT/DENY */
  int init; /* initialized? */
};

struct ftfil_lookup_time_rec {
  FT_STAILQ_ENTRY(ftfil_lookup_time_rec) chain;
  int hour, min, sec;
  enum ftfil_op op; /* FT_FIL_OP */
  int mode;
};

struct ftfil_lookup_time {
  FT_STAILQ_HEAD(filltmehead, ftfil_lookup_time_rec) list;
  enum ftfil_mode default_mode; /* FT_FIL_MODE_PERMIT/DENY */
  int init; /* initialized? */
};

struct ftfil_lookup_rate {
  int rate;
  enum ftfil_mode mode; /* FT_FIL_MODE_PERMIT/DENY */
  enum ftfil_mode default_mode; /* FT_FIL_MODE_PERMIT/DENY */
  int init; /* initialized? */
};

struct ftfil_match_item_cache {
  FT_SLIST_ENTRY(ftfil_match_item_cache) chain;
  uint32_t time; /* cache time -- only valid for flow == curflow+1 */
  void *flow; /* address of flow evaluating -- used to invalidate cache */
  enum ftfil_mode mode; /* result FT_FIL_MODE_* */
  void *lookup; /* data for evaluator */
  int (*eval)(void *lookup, void *rec, struct fts3rec_offsets *fo);
};

static int walk_free(struct radix_node *rn, struct walkarg *UNUSED);

static int ftfil_load_lookup(struct line_parser *lp, char *s, int size,
  uint8_t *list, int mode);

static int parse_definition(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_definition_match(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_definition_or(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_definition_invert(struct line_parser *lp,
  struct ftfil *ftfil);

static int parse_primitive(struct line_parser *lp, struct ftfil *ftfil);
static int parse_primitive_type(struct line_parser *lp, struct ftfil *ftfil);
static int parse_primitive_deny(struct line_parser *lp, struct ftfil *ftfil);
static int parse_primitive_permit(struct line_parser *lp, struct ftfil *ftfil);
static int parse2_primitive_permitdeny(struct line_parser *lp,
  struct ftfil *ftfil, int flag);
static int parse_primitive_default(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_primitive_mask(struct line_parser *lp, struct ftfil *ftfil);

static int parse_primitive_type_asn(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_primitive_type_ip_prot(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_primitive_type_ip_port(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_primitive_type_ip_prefix_len(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_primitive_type_if_index(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_primitive_type_ip_tos(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_primitive_type_ip_tcp_flags(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_primitive_type_engine(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_primitive_type_ip_address(struct line_parser *lp,
  struct ftfil *ftfil);
int parse_primitive_type_ip_mask(struct line_parser *lp,
  struct ftfil *ftfil);
int parse_primitive_type_ip_prefix(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_primitive_type_tag(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_primitive_type_tag_mask(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_primitive_type_counter(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_primitive_type_time_date(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_primitive_type_time(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_primitive_type_double(struct line_parser *lp,
  struct ftfil *ftfil);
static int parse_primitive_type_rate(struct line_parser *lp,
  struct ftfil *ftfil);

static int eval_match_src_as(struct ftfil_lookup_as *lookup, char *rec,
  struct fts3rec_offsets *fo);
static int eval_match_dst_as(struct ftfil_lookup_as *lookup, char *rec,
  struct fts3rec_offsets *fo);
static int eval_match_engine_type(struct ftfil_lookup_engine *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_engine_id(struct ftfil_lookup_engine *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_dst_if_index(struct ftfil_lookup_if_index *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_src_if_index(struct ftfil_lookup_if_index *lookup,
  char *rec, struct fts3rec_offsets *fo); 
static int eval_match_ip_dst_port(struct ftfil_lookup_ip_port *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_ip_src_port(struct ftfil_lookup_ip_port *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_ip_tcp_flags(struct ftfil_lookup_ip_tcp_flags *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_ip_marked_tos(struct ftfil_lookup_ip_tos *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_ip_tos(struct ftfil_lookup_ip_tos *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_ip_dst_prefix_len(struct ftfil_lookup_ip_prefix_len
  *lookup, char *rec, struct fts3rec_offsets *fo);
static int eval_match_ip_src_prefix_len(struct ftfil_lookup_ip_prefix_len
  *lookup, char *rec, struct fts3rec_offsets *fo);
static int eval_match_ip_prot(struct ftfil_lookup_ip_prot *lookup, char *rec,
  struct fts3rec_offsets *fo);
static int eval_match_flows(struct ftfil_lookup_counter *lookup, char *rec,
  struct fts3rec_offsets *fo);
static int eval_match_octets(struct ftfil_lookup_counter *lookup, char *rec,
  struct fts3rec_offsets *fo);
static int eval_match_packets(struct ftfil_lookup_counter *lookup, char *rec,
  struct fts3rec_offsets *fo);
static int eval_match_xtra_packets(struct ftfil_lookup_counter *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_duration(struct ftfil_lookup_counter *lookup, char *rec,
  struct fts3rec_offsets *fo);

static int eval_match_start_time_date(struct ftfil_lookup_counter *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_end_time_date(struct ftfil_lookup_counter *lookup,
  char *rec, struct fts3rec_offsets *fo);

static int eval_match_start_time(struct ftfil_lookup_time *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_end_time(struct ftfil_lookup_time *lookup,
  char *rec, struct fts3rec_offsets *fo);

static int eval_match_src_tag_l(struct ftfil_lookup_tag_mask *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_src_tag_h(struct ftfil_lookup_tag *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_dst_tag_l(struct ftfil_lookup_tag_mask *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_dst_tag_h(struct ftfil_lookup_tag *lookup,
  char *rec, struct fts3rec_offsets *fo);

static int eval_match_ip_sc_addr_l(struct ftfil_lookup_ip_mask *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_ip_sc_addr_h(struct ftfil_lookup_ip_address *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_ip_sc_addr_r(struct ftfil_lookup_ip_prefix *lookup,
  char *rec, struct fts3rec_offsets *fo);

static int eval_match_ip_nexthop_addr_l(struct ftfil_lookup_ip_mask *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_ip_nexthop_addr_h(struct ftfil_lookup_ip_address *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_ip_nexthop_addr_r(struct ftfil_lookup_ip_prefix *lookup,
  char *rec, struct fts3rec_offsets *fo);

static int eval_match_ip_src_addr_l(struct ftfil_lookup_ip_mask *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_ip_src_addr_h(struct ftfil_lookup_ip_address *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_ip_src_addr_r(struct ftfil_lookup_ip_prefix *lookup,
  char *rec, struct fts3rec_offsets *fo);

static int eval_match_ip_dst_addr_l(struct ftfil_lookup_ip_mask *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_ip_dst_addr_h(struct ftfil_lookup_ip_address *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_ip_dst_addr_r(struct ftfil_lookup_ip_prefix *lookup,
  char *rec, struct fts3rec_offsets *fo);

static int eval_match_ip_exporter_addr_l(struct ftfil_lookup_ip_mask *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_ip_exporter_addr_h(struct ftfil_lookup_ip_address *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_ip_exporter_addr_r(struct ftfil_lookup_ip_prefix *lookup,
  char *rec, struct fts3rec_offsets *fo);

static int eval_match_pps(struct ftfil_lookup_double *lookup,
  char *rec, struct fts3rec_offsets *fo);
static int eval_match_bps(struct ftfil_lookup_double *lookup,
  char *rec, struct fts3rec_offsets *fo);

static int eval_match_random_sample(struct ftfil_lookup_rate *lookup,
  char *rec, struct fts3rec_offsets *fo);

static int resolve_primitives(struct ftfil *ftfil);

#define NEXT_WORD(A,B)\
  for (;;) {\
    B = strsep(A, " \t");\
    if ((B && *B != 0) || (!B))\
      break;\
  }\
 
struct jump {
  char *name;
  enum ftfil_parse_state state;
  int (*func)(struct line_parser *lp, struct ftfil *ftfil);
};

static struct jump pjump[] = {
          {"filter-primitive", 0, parse_primitive},
          {"type", PARSE_STATE_PRIMITIVE, parse_primitive_type},
          {"permit", PARSE_STATE_PRIMITIVE, parse_primitive_permit},
          {"deny", PARSE_STATE_PRIMITIVE, parse_primitive_deny},
          {"default", PARSE_STATE_PRIMITIVE, parse_primitive_default},
          {"mask", PARSE_STATE_PRIMITIVE, parse_primitive_mask},
          {"filter-definition", 0, parse_definition},
          {"match", PARSE_STATE_DEFINITION, parse_definition_match},
          {"or", PARSE_STATE_DEFINITION, parse_definition_or},
          {"invert", PARSE_STATE_DEFINITION, parse_definition_invert},
          {0, 0, 0},
          };
/*
 * data structures:
 *
 * Each primitive is stored in a linked list of struct ftfil_primitive.  The
 * head is ftfil.primitives.  Each primitive has a lookup entry which 
 * points to a struct ftfil_lookup_* based on the enum ftfil_primitive_type
 * stored as type.  Some lookup entries allocate further storage (ie
 * a hash, radix tree, or linked list for the linear lookups).
 *
 * Each definition is stored in a linked list of struct ftfil_def.
 * The head is ftfil.defs.  Each definition has a list of
 * ftfil_match matches.  The matches have a list of ftfil_match_items.
 * For a match to be satisfied each each item in the match must evaluate
 * true (AND).  For a definition to be satisfied (permitted) one of the
 * entries in the match list must be satisfied (OR).
 *
 * Each primitive (enum ftfil_primitive_type) has an associated
 * parse_primitive_type_xxx().
 *
 * Each match type (enum ftfil_def_match) has an associated
 * eval_match_xxx().
 *
 * ftfil_eval() walks the matches and the match items for the definition
 * passed to it looking for a match.  If every match item in a match
 * evaluated to permit (enum ftfil_mode) a permit is returned, else
 * a deny.
 *
 * The current evaluator code does not cache results.  For example
 *
 * match src-ip-addr test1
 * match ip-protocol test2
 * or
 * match src-ip-addr test1
 * match ip-port test3
 *
 * If the first two matches fail the result from "match src-ip-addr test1"
 * will need to be calculated a second time.  In practice this doesn't
 * seem to be a problem -- the performance impact is minimal for real
 * world definitions.  Adding a cache would most likely reduce performance
 * for most cases due to overhead of the cache test/update code.
 *
 * Also note that in the above example if the first two matches pass
 * the the next two will not be evaluated at all - short circuit.
 */

/*
 *************************************************************************
                                eval_*
 *************************************************************************
 */

/*
 * function: eval_match_src_as
 *
 * Evalute src_as
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_src_as(struct ftfil_lookup_as *lookup, char *rec,
  struct fts3rec_offsets *fo)
{
  uint16_t *src_as;
  int val;

  src_as = ((uint16_t*)(rec+fo->src_as));

  val = lookup->mode[*src_as];

  if (val == FT_FIL_MODE_PERMIT)
    return FT_FIL_MODE_PERMIT;
  else if (val == FT_FIL_MODE_DENY)
    return FT_FIL_MODE_DENY;
  else
    return lookup->default_mode;

} /* eval_match_src_as */

/*
 * function: eval_match_dst_as
 *
 * Evalute dst_as
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_dst_as(struct ftfil_lookup_as *lookup, char *rec,
  struct fts3rec_offsets *fo)
{
  uint16_t *dst_as;
  int val;

  dst_as = ((uint16_t*)(rec+fo->dst_as));

  val = lookup->mode[*dst_as];

  if (val == FT_FIL_MODE_PERMIT)
    return FT_FIL_MODE_PERMIT;
  else if (val == FT_FIL_MODE_DENY)
    return FT_FIL_MODE_DENY;
  else
    return lookup->default_mode;

} /* eval_match_dst_as */


/*
 * function: eval_match_ip_prot
 *
 * Evalute ip_prot
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_prot(struct ftfil_lookup_ip_prot *lookup, char *rec,
  struct fts3rec_offsets *fo)
{
  uint8_t *ip_prot;
  int val;

  ip_prot = ((uint8_t*)(rec+fo->prot));

  val = lookup->mode[*ip_prot];

  if (val == FT_FIL_MODE_PERMIT)
    return FT_FIL_MODE_PERMIT;
  else if (val == FT_FIL_MODE_DENY)
    return FT_FIL_MODE_DENY;
  else
    return lookup->default_mode;

} /* eval_match_ip_prot */


/*
 * function: eval_match_ip_src_prefix_len
 *
 * Evalute ip_src_prefix_len
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_src_prefix_len(struct ftfil_lookup_ip_prefix_len *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  uint8_t *src_mask;
  int val;

  src_mask = ((uint8_t*)(rec+fo->src_mask));

  val = lookup->mode[*src_mask];

  if (val == FT_FIL_MODE_PERMIT)
    return FT_FIL_MODE_PERMIT;
  else if (val == FT_FIL_MODE_DENY)
    return FT_FIL_MODE_DENY;
  else
    return lookup->default_mode;

} /* eval_match_ip_src_prefix_len */


/*
 * function: eval_match_ip_dst_prefix_len
 *
 * Evalute ip_dst_prefix_len
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_dst_prefix_len(struct ftfil_lookup_ip_prefix_len *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  uint8_t *dst_mask;
  int val;

  dst_mask = ((uint8_t*)(rec+fo->dst_mask));

  val = lookup->mode[*dst_mask];

  if (val == FT_FIL_MODE_PERMIT)
    return FT_FIL_MODE_PERMIT;
  else if (val == FT_FIL_MODE_DENY)
    return FT_FIL_MODE_DENY;
  else
    return lookup->default_mode;

} /* eval_match_ip_dst_prefix_len */


/*
 * function: eval_match_ip_tos
 *
 * Evalute ip_tos
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_tos(struct ftfil_lookup_ip_tos *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  uint8_t tos;
  int val;

  tos = *((uint8_t*)(rec+fo->tos));
  tos &= lookup->mask;

  val = lookup->mode[tos];

  if (val == FT_FIL_MODE_PERMIT)
    return FT_FIL_MODE_PERMIT;
  else if (val == FT_FIL_MODE_DENY)
    return FT_FIL_MODE_DENY;
  else
    return lookup->default_mode;

} /* eval_match_ip_tos */

/*
 * function: eval_match_marked_ip_tos
 *
 * Evalute marked_ip_tos
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_marked_tos(struct ftfil_lookup_ip_tos *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  uint8_t marked_tos;
  int val;

  marked_tos = *((uint8_t*)(rec+fo->marked_tos));
  marked_tos &= lookup->mask;

  val = lookup->mode[marked_tos];

  if (val == FT_FIL_MODE_PERMIT)
    return FT_FIL_MODE_PERMIT;
  else if (val == FT_FIL_MODE_DENY)
    return FT_FIL_MODE_DENY;
  else
    return lookup->default_mode;

} /* eval_match_ip_marked_tos */


/*
 * function: eval_match_ip_tcp_flags
 *
 * Evalute ip_tcp_flags
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_tcp_flags(struct ftfil_lookup_ip_tcp_flags *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  uint8_t tcp_flags;
  int val;

  tcp_flags = *((uint8_t*)(rec+fo->tcp_flags));
  tcp_flags &= lookup->mask;

  val = lookup->mode[tcp_flags];

  if (val == FT_FIL_MODE_PERMIT)
    return FT_FIL_MODE_PERMIT;
  else if (val == FT_FIL_MODE_DENY)
    return FT_FIL_MODE_DENY;
  else
    return lookup->default_mode;

} /* eval_match_ip_tcp_flags */


/*
 * function: eval_match_ip_src_port
 *
 * Evalute ip_src_port
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_src_port(struct ftfil_lookup_ip_port *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  uint16_t *src_port;
  int val;

  src_port = ((uint16_t*)(rec+fo->srcport));

  val = lookup->mode[*src_port];

  if (val == FT_FIL_MODE_PERMIT)
    return FT_FIL_MODE_PERMIT;
  else if (val == FT_FIL_MODE_DENY)
    return FT_FIL_MODE_DENY;
  else
    return lookup->default_mode;

} /* eval_match_ip_src_port */

/*
 * function: eval_match_ip_dst_port
 *
 * Evalute ip_dst_port
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_dst_port(struct ftfil_lookup_ip_port *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  uint16_t *dst_port;
  int val;

  dst_port = ((uint16_t*)(rec+fo->dstport));

  val = lookup->mode[*dst_port];

  if (val == FT_FIL_MODE_PERMIT)
    return FT_FIL_MODE_PERMIT;
  else if (val == FT_FIL_MODE_DENY)
    return FT_FIL_MODE_DENY;
  else
    return lookup->default_mode;

} /* eval_match_ip_dst_port */


/*
 * function: eval_match_src_if_index
 *
 * Evalute src_if_index
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_src_if_index(struct ftfil_lookup_if_index *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  uint16_t *src_if_index;
  int val;

  src_if_index = ((uint16_t*)(rec+fo->input));

  val = lookup->mode[*src_if_index];

  if (val == FT_FIL_MODE_PERMIT)
    return FT_FIL_MODE_PERMIT;
  else if (val == FT_FIL_MODE_DENY)
    return FT_FIL_MODE_DENY;
  else
    return lookup->default_mode;

} /* eval_match_src_if_index */

/*
 * function: eval_match_dst_if_index
 *
 * Evalute dst_if_index
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_dst_if_index(struct ftfil_lookup_if_index *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  uint16_t *dst_if_index;
  int val;

  dst_if_index = ((uint16_t*)(rec+fo->output));

  val = lookup->mode[*dst_if_index];

  if (val == FT_FIL_MODE_PERMIT)
    return FT_FIL_MODE_PERMIT;
  else if (val == FT_FIL_MODE_DENY)
    return FT_FIL_MODE_DENY;
  else
    return lookup->default_mode;

} /* eval_match_dst_if_index */


/*
 * function: eval_match_engine_id
 *
 * Evalute engine_id
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_engine_id(struct ftfil_lookup_engine *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  uint8_t *engine_id;
  int val;

  engine_id = ((uint8_t*)(rec+fo->engine_id));

  val = lookup->mode[*engine_id];

  if (val == FT_FIL_MODE_PERMIT)
    return FT_FIL_MODE_PERMIT;
  else if (val == FT_FIL_MODE_DENY)
    return FT_FIL_MODE_DENY;
  else
    return lookup->default_mode;

} /* eval_match_engine_id */


/*
 * function: eval_match_engine_type
 *
 * Evalute engine_type
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_engine_type(struct ftfil_lookup_engine *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  uint8_t *engine_type;
  int val;

  engine_type = ((uint8_t*)(rec+fo->engine_type));

  val = lookup->mode[*engine_type];

  if (val == FT_FIL_MODE_PERMIT)
    return FT_FIL_MODE_PERMIT;
  else if (val == FT_FIL_MODE_DENY)
    return FT_FIL_MODE_DENY;
  else
    return lookup->default_mode;

} /* eval_match_engine_type */

/*
 * function: eval_match_flows
 *
 * Evalute flows
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_flows(struct ftfil_lookup_counter *lookup, char *rec,
  struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_counter_rec *ftflcr;
  uint32_t *flows;
  int t, match;

  flows = ((uint32_t*)(rec+fo->dFlows));

  match = 0;

  FT_STAILQ_FOREACH(ftflcr, &lookup->list, chain) {

    switch (ftflcr->op) {

      case FT_FIL_OP_LT:
        t = (*flows < ftflcr->val);
        break;
      case FT_FIL_OP_GT:
        t = (*flows > ftflcr->val);
        break;
      case FT_FIL_OP_EQ:
        t = (*flows == ftflcr->val);
        break;
      case FT_FIL_OP_NE:
        t = (*flows != ftflcr->val);
        break;
      case FT_FIL_OP_GE:
        t = (*flows >= ftflcr->val);
        break;
      case FT_FIL_OP_LE:
        t = (*flows <= ftflcr->val);
        break;
      default:
        fterr_warnx("eval_match_flows: internal error");
        return -1;
        break;

    } /* switch */

    /* did this line match? */
    if (t) {
      match = 1;
      break;
    }

  } /* ftflcr */

  /* if there was a match, then return that mode */
  if (match)
    return ftflcr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_flows */

/*
 * function: eval_match_octets
 *
 * Evalute octets
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_octets(struct ftfil_lookup_counter *lookup, char *rec,
  struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_counter_rec *ftflcr;
  uint32_t *octets;
  int t, match;

  octets = ((uint32_t*)(rec+fo->dOctets));

  match = 0;

  FT_STAILQ_FOREACH(ftflcr, &lookup->list, chain) {

    switch (ftflcr->op) {

      case FT_FIL_OP_LT:
        t = (*octets < ftflcr->val);
        break;
      case FT_FIL_OP_GT:
        t = (*octets > ftflcr->val);
        break;
      case FT_FIL_OP_EQ:
        t = (*octets == ftflcr->val);
        break;
      case FT_FIL_OP_NE:
        t = (*octets != ftflcr->val);
        break;
      case FT_FIL_OP_GE:
        t = (*octets >= ftflcr->val);
        break;
      case FT_FIL_OP_LE:
        t = (*octets <= ftflcr->val);
        break;
      default:
        fterr_warnx("eval_match_octets: internal error");
        return -1;
        break;

    } /* switch */

    /* did this line match? */
    if (t) {
      match = 1;
      break;
    }

  } /* ftflcr */

  /* if there was a match, then return that mode */
  if (match)
    return ftflcr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_octets */

/*
 * function: eval_match_packets
 *
 * Evalute packets
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_packets(struct ftfil_lookup_counter *lookup, char *rec,
  struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_counter_rec *ftflcr;
  uint32_t *packets;
  int t, match;

  packets = ((uint32_t*)(rec+fo->dPkts));

  match = 0;

  FT_STAILQ_FOREACH(ftflcr, &lookup->list, chain) {

    switch (ftflcr->op) {

      case FT_FIL_OP_LT:
        t = (*packets < ftflcr->val);
        break;
      case FT_FIL_OP_GT:
        t = (*packets > ftflcr->val);
        break;
      case FT_FIL_OP_EQ:
        t = (*packets == ftflcr->val);
        break;
      case FT_FIL_OP_NE:
        t = (*packets != ftflcr->val);
        break;
      case FT_FIL_OP_GE:
        t = (*packets >= ftflcr->val);
        break;
      case FT_FIL_OP_LE:
        t = (*packets <= ftflcr->val);
        break;
      default:
        fterr_warnx("eval_match_packets: internal error");
        return -1;
        break;

    } /* switch */

    /* did this line match? */
    if (t) {
      match = 1;
      break;
    }

  } /* ftflcr */

  /* if there was a match, then return that mode */
  if (match)
    return ftflcr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_packets */

/*
 * function: eval_match_xtra_packets
 *
 * Evalute xtra_packets
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_xtra_packets(struct ftfil_lookup_counter *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_counter_rec *ftflcr;
  uint32_t *xtra_packets;
  int t, match;

  xtra_packets = ((uint32_t*)(rec+fo->extra_pkts));

  match = 0;

  FT_STAILQ_FOREACH(ftflcr, &lookup->list, chain) {

    switch (ftflcr->op) {

      case FT_FIL_OP_LT:
        t = (*xtra_packets < ftflcr->val);
        break;
      case FT_FIL_OP_GT:
        t = (*xtra_packets > ftflcr->val);
        break;
      case FT_FIL_OP_EQ:
        t = (*xtra_packets == ftflcr->val);
        break;
      case FT_FIL_OP_NE:
        t = (*xtra_packets != ftflcr->val);
        break;
      case FT_FIL_OP_GE:
        t = (*xtra_packets >= ftflcr->val);
        break;
      case FT_FIL_OP_LE:
        t = (*xtra_packets <= ftflcr->val);
        break;
      default:
        fterr_warnx("eval_match_xtra_packets: internal error");
        return -1;
        break;

    } /* switch */

    /* did this line match? */
    if (t) {
      match = 1;
      break;
    }

  } /* ftflcr */

  /* if there was a match, then return that mode */
  if (match)
    return ftflcr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_xtra_packets */

/*
 * function: eval_match_duration
 *
 * Evalute duration
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_duration(struct ftfil_lookup_counter *lookup, char *rec,
  struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_counter_rec *ftflcr;
  uint32_t duration, *first, *last;
  int t, match;

  first = ((uint32_t*)(rec+fo->First));
  last = ((uint32_t*)(rec+fo->Last));
  duration = *last - *first;

  match = 0;

  FT_STAILQ_FOREACH(ftflcr, &lookup->list, chain) {

    switch (ftflcr->op) {

      case FT_FIL_OP_LT:
        t = (duration < ftflcr->val);
        break;
      case FT_FIL_OP_GT:
        t = (duration > ftflcr->val);
        break;
      case FT_FIL_OP_EQ:
        t = (duration == ftflcr->val);
        break;
      case FT_FIL_OP_NE:
        t = (duration != ftflcr->val);
        break;
      case FT_FIL_OP_GE:
        t = (duration >= ftflcr->val);
        break;
      case FT_FIL_OP_LE:
        t = (duration <= ftflcr->val);
        break;
      default:
        fterr_warnx("eval_match_duration: internal error");
        return -1;
        break;

    } /* switch */

    /* did this line match? */
    if (t) {
      match = 1;
      break;
    }

  } /* ftflcr */

  /* if there was a match, then return that mode */
  if (match)
    return ftflcr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_duration */

/*
 * function: eval_match_start_time_date
 *
 * Evalute start_time_date
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_start_time_date(struct ftfil_lookup_counter *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_counter_rec *ftflcr;
  struct fttime ftt;
  uint32_t *sysUpTime, *unix_secs, *unix_nsecs, *First;
  int t, match;

  sysUpTime = ((uint32_t*)(rec+fo->sysUpTime));
  unix_secs = ((uint32_t*)(rec+fo->unix_secs));
  unix_nsecs = ((uint32_t*)(rec+fo->unix_nsecs));
  First = ((uint32_t*)(rec+fo->First));

  ftt = ftltime(*sysUpTime, *unix_secs, *unix_nsecs, *First);

  match = 0;

  FT_STAILQ_FOREACH(ftflcr, &lookup->list, chain) {

    switch (ftflcr->op) {

      case FT_FIL_OP_LT:
        t = (ftt.secs < ftflcr->val);
        break;
      case FT_FIL_OP_GT:
        t = (ftt.secs > ftflcr->val);
        break;
      case FT_FIL_OP_EQ:
        t = (ftt.secs == ftflcr->val);
        break;
      case FT_FIL_OP_NE:
        t = (ftt.secs != ftflcr->val);
        break;
      case FT_FIL_OP_GE:
        t = (ftt.secs >= ftflcr->val);
        break;
      case FT_FIL_OP_LE:
        t = (ftt.secs <= ftflcr->val);
        break;
      default:
        fterr_warnx("eval_match_start_time_date: internal error");
        return -1;
        break;

    } /* switch */

    /* did this line match? */
    if (t) {
      match = 1;
      break;
    }

  } /* ftflcr */

  /* if there was a match, then return that mode */
  if (match)
    return ftflcr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_start_time_date */

/*
 * function: eval_match_end_time_date
 *
 * Evalute end_time_date
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_end_time_date(struct ftfil_lookup_counter *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_counter_rec *ftflcr;
  struct fttime ftt;
  uint32_t *sysUpTime, *unix_secs, *unix_nsecs, *Last;
  int t, match;

  sysUpTime = ((uint32_t*)(rec+fo->sysUpTime));
  unix_secs = ((uint32_t*)(rec+fo->unix_secs));
  unix_nsecs = ((uint32_t*)(rec+fo->unix_nsecs));
  Last = ((uint32_t*)(rec+fo->Last));

  ftt = ftltime(*sysUpTime, *unix_secs, *unix_nsecs, *Last);

  match = 0;

  FT_STAILQ_FOREACH(ftflcr, &lookup->list, chain) {

    switch (ftflcr->op) {

      case FT_FIL_OP_LT:
        t = (ftt.secs < ftflcr->val);
        break;
      case FT_FIL_OP_GT:
        t = (ftt.secs > ftflcr->val);
        break;
      case FT_FIL_OP_EQ:
        t = (ftt.secs == ftflcr->val);
        break;
      case FT_FIL_OP_NE:
        t = (ftt.secs != ftflcr->val);
        break;
      case FT_FIL_OP_GE:
        t = (ftt.secs >= ftflcr->val);
        break;
      case FT_FIL_OP_LE:
        t = (ftt.secs <= ftflcr->val);
        break;
      default:
        fterr_warnx("eval_match_end_time_date: internal error");
        return -1;
        break;

    } /* switch */

    /* did this line match? */
    if (t) {
      match = 1;
      break;
    }

  } /* ftflcr */

  /* if there was a match, then return that mode */
  if (match)
    return ftflcr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_end_time_date */

/*
 * function: eval_match_start_time
 *
 * Evalute start_time
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_start_time(struct ftfil_lookup_time *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  time_t t1, t2;
  struct tm *tm;
  struct ftfil_lookup_time_rec *ftfltmer;
  struct fttime ftt;
  uint32_t *sysUpTime, *unix_secs, *unix_nsecs, *First;
  int t, match;

  sysUpTime = ((uint32_t*)(rec+fo->sysUpTime));
  unix_secs = ((uint32_t*)(rec+fo->unix_secs));
  unix_nsecs = ((uint32_t*)(rec+fo->unix_nsecs));
  First = ((uint32_t*)(rec+fo->First));

  ftt = ftltime(*sysUpTime, *unix_secs, *unix_nsecs, *First);

  t1 = ftt.secs;

  /* tm is now "today" for the flow */
  tm = localtime(&t1);
  tm->tm_hour = 0;
  tm->tm_min = 0;
  tm->tm_sec = 0;

  match = 0;

  FT_STAILQ_FOREACH(ftfltmer, &lookup->list, chain) {

    /*
     * find where the hh:mm:ss for this filter falls relative to day start,
     * store as t2
     */
    tm->tm_hour = ftfltmer->hour;
    tm->tm_min = ftfltmer->min;
    tm->tm_sec = ftfltmer->sec;
    t2 = mktime(tm);

    switch (ftfltmer->op) {

      case FT_FIL_OP_LT:
        t = (t1 < t2);
        break;
      case FT_FIL_OP_GT:
        t = (t1 > t2);
        break;
      case FT_FIL_OP_EQ:
        t = (t1 == t2);
        break;
      case FT_FIL_OP_NE:
        t = (t1 != t2);
        break;
      case FT_FIL_OP_GE:
        t = (t1 >= t2);
        break;
      case FT_FIL_OP_LE:
        t = (t1 <= t2);
        break;
      default:
        fterr_warnx("eval_match_start_time: internal error");
        return -1;
        break;

    } /* switch */

    /* did this line match? */
    if (t) {
      match = 1;
      break;
    }

  } /* ftfltmer */

  /* if there was a match, then return that mode */
  if (match)
    return ftfltmer->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_start_time */

/*
 * function: eval_match_end_time
 *
 * Evalute end_time
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_end_time(struct ftfil_lookup_time *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  time_t t1, t2;
  struct tm *tm;
  struct ftfil_lookup_time_rec *ftfltmer;
  struct fttime ftt;
  uint32_t *sysUpTime, *unix_secs, *unix_nsecs, *Last;
  int t, match;

  sysUpTime = ((uint32_t*)(rec+fo->sysUpTime));
  unix_secs = ((uint32_t*)(rec+fo->unix_secs));
  unix_nsecs = ((uint32_t*)(rec+fo->unix_nsecs));
  Last = ((uint32_t*)(rec+fo->Last));

  ftt = ftltime(*sysUpTime, *unix_secs, *unix_nsecs, *Last);

  t1 = ftt.secs;

  /* tm is now "today" for the flow */
  tm = localtime(&t1);
  tm->tm_hour = 0;
  tm->tm_min = 0;
  tm->tm_sec = 0;

  match = 0;

  FT_STAILQ_FOREACH(ftfltmer, &lookup->list, chain) {

    /*
     * find where the hh:mm:ss for this filter falls relative to day start,
     * store as t2
     */
    tm->tm_hour = ftfltmer->hour;
    tm->tm_min = ftfltmer->min;
    tm->tm_sec = ftfltmer->sec;
    t2 = mktime(tm);

    switch (ftfltmer->op) {

      case FT_FIL_OP_LT:
        t = (t1 < t2);
        break;
      case FT_FIL_OP_GT:
        t = (t1 > t2);
        break;
      case FT_FIL_OP_EQ:
        t = (t1 == t2);
        break;
      case FT_FIL_OP_NE:
        t = (t1 != t2);
        break;
      case FT_FIL_OP_GE:
        t = (t1 >= t2);
        break;
      case FT_FIL_OP_LE:
        t = (t1 <= t2);
        break;
      default:
        fterr_warnx("eval_match_end_time: internal error");
        return -1;
        break;

    } /* switch */

    /* did this line match? */
    if (t) {
      match = 1;
      break;
    }

  } /* ftfltmer */

  /* if there was a match, then return that mode */
  if (match)
    return ftfltmer->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_end_time */

/*
 * function: eval_match_src_tag_l
 *
 * Evalute src_tag as list
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_src_tag_l(struct ftfil_lookup_tag_mask *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_tag_mask_rec *ftfltmr;
  uint32_t *src_tag;
  int match;

  src_tag = ((uint32_t*)(rec+fo->src_tag));

  match = 0;

  FT_STAILQ_FOREACH(ftfltmr, &lookup->list, chain) {

    /* match? */
    if ((*src_tag & ftfltmr->mask) == ftfltmr->tag) {
      match = 1;
      break;
    }

  } /* ftfltmr */

  /* if there was a match, then return that mode */
  if (match)
    return ftfltmr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_src_tag_l */

/*
 * function: eval_match_src_tag_h
 *
 * Evalute src_tag as hash
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_src_tag_h(struct ftfil_lookup_tag *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftchash_rec_fil_c32 *ftch_recfc32p;
  uint32_t *src_tag, hash;
  int match;

  src_tag = ((uint32_t*)(rec+fo->src_tag));

  match = 0;

  hash = (*src_tag>>16) ^ (*src_tag & 0xFFFF);
  hash = ((hash >>8) ^ (hash & 0x0FFF));

  if ((ftch_recfc32p = ftchash_lookup(lookup->ftch, src_tag, hash)))
    match = 1;

  /* if there was a match, then return that mode */
  if (match)
    return ftch_recfc32p->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_src_tag_h */

/*
 * function: eval_match_dst_tag_h
 *
 * Evalute dst_tag as hash
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_dst_tag_h(struct ftfil_lookup_tag *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftchash_rec_fil_c32 *ftch_recfc32p;
  uint32_t *dst_tag, hash;
  int match;

  dst_tag = ((uint32_t*)(rec+fo->dst_tag));

  match = 0;

  hash = (*dst_tag>>16) ^ (*dst_tag & 0xFFFF);
  hash = ((hash >>8) ^ (hash & 0x0FFF));

  if ((ftch_recfc32p = ftchash_lookup(lookup->ftch, dst_tag, hash)))
    match = 1;

  /* if there was a match, then return that mode */
  if (match)
    return ftch_recfc32p->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_dst_tag_h */

/*
 * function: eval_match_dst_tag_l
 *
 * Evalute dst_tag as list
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_dst_tag_l(struct ftfil_lookup_tag_mask *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_tag_mask_rec *ftfltmr;
  uint32_t *dst_tag;
  int match;

  dst_tag = ((uint32_t*)(rec+fo->dst_tag));

  match = 0;

  FT_STAILQ_FOREACH(ftfltmr, &lookup->list, chain) {

    /* match? */
    if ((*dst_tag & ftfltmr->mask) == ftfltmr->tag) {
      match = 1;
      break;
    }

  } /* ftfltmr */

  /* if there was a match, then return that mode */
  if (match)
    return ftfltmr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_dst_tag_l */

/*
 * function: eval_match_nexthop_l
 *
 * Evalute nexthop as list
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_nexthop_addr_l(struct ftfil_lookup_ip_mask *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_ip_mask_rec *ftflipmr;
  uint32_t *nexthop;
  int match;

  nexthop = ((uint32_t*)(rec+fo->nexthop));

  match = 0;

  FT_STAILQ_FOREACH(ftflipmr, &lookup->list, chain) {

    /* match? */
    if ((*nexthop & ftflipmr->mask) == ftflipmr->ip) {
      match = 1;
      break;
    }

  } /* ftflipmr */

  /* if there was a match, then return that mode */
  if (match)
    return ftflipmr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_ip_nexthop_addr_l */

/*
 * function: eval_match_ip_nexthop_addr_h
 *
 * Evalute nexthop as hash
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_nexthop_addr_h(struct ftfil_lookup_ip_address *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftchash_rec_fil_c32 *ftch_recfc32p;
  uint32_t *nexthop, hash;
  int match;

  nexthop = ((uint32_t*)(rec+fo->nexthop));

  match = 0;

  hash = (*nexthop>>16) ^ (*nexthop & 0xFFFF);
  hash = ((hash >>8) ^ (hash & 0x0FFF));

  if ((ftch_recfc32p = ftchash_lookup(lookup->ftch, nexthop, hash)))
    match = 1;

  /* if there was a match, then return that mode */
  if (match)
    return ftch_recfc32p->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_ip_nexthop_addr_h */

/*
 * function: eval_match_ip_nexthop_addr_r
 *
 * Evalute nexthop as hash
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_nexthop_addr_r(struct ftfil_lookup_ip_prefix *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_ip_prefix_rec *ftflipprr;
  struct radix_node_head *rhead;
  struct radix_sockaddr_in sock1;
  int match;

  sock1.sin_addr.s_addr = *((uint32_t*)(rec+fo->nexthop));
  sock1.sin_len = sizeof sock1;
  sock1.sin_family = AF_INET;

  match = 0;

  rhead = lookup->rhead;

  if ((ftflipprr = (struct ftfil_lookup_ip_prefix_rec*)rhead->rnh_matchaddr(
    &sock1, rhead)))
    match = 1;

  /* if there was a match, then return that mode */
  if (match)
    return ftflipprr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_ip_nexthop_addr_r */

/*
 * function: eval_match_ip_sc_addr_l
 *
 * Evalute sc as list
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_sc_addr_l(struct ftfil_lookup_ip_mask *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_ip_mask_rec *ftflipmr;
  uint32_t *sc;
  int match;

  sc = ((uint32_t*)(rec+fo->router_sc));

  match = 0;

  FT_STAILQ_FOREACH(ftflipmr, &lookup->list, chain) {

    /* match? */
    if ((*sc & ftflipmr->mask) == ftflipmr->ip) {
      match = 1;
      break;
    }

  } /* ftflipmr */

  /* if there was a match, then return that mode */
  if (match)
    return ftflipmr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_ip_sc_addr_l */

/*
 * function: eval_match_ip_sc_addr_h
 *
 * Evalute sc as hash
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_sc_addr_h(struct ftfil_lookup_ip_address *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftchash_rec_fil_c32 *ftch_recfc32p;
  uint32_t *sc, hash;
  int match;

  sc = ((uint32_t*)(rec+fo->router_sc));

  match = 0;

  hash = (*sc>>16) ^ (*sc & 0xFFFF);
  hash = ((hash >>8) ^ (hash & 0x0FFF));

  if ((ftch_recfc32p = ftchash_lookup(lookup->ftch, sc, hash)))
    match = 1;

  /* if there was a match, then return that mode */
  if (match)
    return ftch_recfc32p->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_ip_sc_addr_h */

/*
 * function: eval_match_ip_sc_addr_r
 *
 * Evalute sc as hash
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_sc_addr_r(struct ftfil_lookup_ip_prefix *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_ip_prefix_rec *ftflipprr;
  struct radix_node_head *rhead;
  struct radix_sockaddr_in sock1;
  int match;

  sock1.sin_addr.s_addr = *((uint32_t*)(rec+fo->router_sc));
  sock1.sin_len = sizeof sock1;
  sock1.sin_family = AF_INET;

  match = 0;

  rhead = lookup->rhead;

  if ((ftflipprr = (struct ftfil_lookup_ip_prefix_rec*)rhead->rnh_matchaddr(
    &sock1, rhead)))
    match = 1;

  /* if there was a match, then return that mode */
  if (match)
    return ftflipprr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_ip_sc_addr_r */

/*
 * function: eval_match_ip_src_addr_l
 *
 * Evalute ip_src_addr as list
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_src_addr_l(struct ftfil_lookup_ip_mask *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_ip_mask_rec *ftflipmr;
  uint32_t *ip_src_addr;
  int match;

  ip_src_addr = ((uint32_t*)(rec+fo->srcaddr));

  match = 0;

  FT_STAILQ_FOREACH(ftflipmr, &lookup->list, chain) {

    /* match? */
    if ((*ip_src_addr & ftflipmr->mask) == ftflipmr->ip) {
      match = 1;
      break;
    }

  } /* ftflipmr */

  /* if there was a match, then return that mode */
  if (match)
    return ftflipmr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_ip_src_addr_l */

/*
 * function: eval_match_ip_src_addr_h
 *
 * Evalute ip_src_addr as hash
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_src_addr_h(struct ftfil_lookup_ip_address *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftchash_rec_fil_c32 *ftch_recfc32p;
  uint32_t *ip_src_addr, hash;
  int match;

  ip_src_addr = ((uint32_t*)(rec+fo->srcaddr));

  match = 0;

  hash = (*ip_src_addr>>16) ^ (*ip_src_addr & 0xFFFF);
  hash = ((hash >>8) ^ (hash & 0x0FFF));

  if ((ftch_recfc32p = ftchash_lookup(lookup->ftch, ip_src_addr, hash)))
    match = 1;

  /* if there was a match, then return that mode */
  if (match)
    return ftch_recfc32p->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_ip_src_addr_h */

/*
 * function: eval_match_ip_src_addr_r
 *
 * Evalute ip_src_addr as hash
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_src_addr_r(struct ftfil_lookup_ip_prefix *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_ip_prefix_rec *ftflipprr;
  struct radix_node_head *rhead;
  struct radix_sockaddr_in sock1;
  int match;

  sock1.sin_addr.s_addr = *((uint32_t*)(rec+fo->srcaddr));
  sock1.sin_len = sizeof sock1;
  sock1.sin_family = AF_INET;

  match = 0;

  rhead = lookup->rhead;

  if ((ftflipprr = (struct ftfil_lookup_ip_prefix_rec*)rhead->rnh_matchaddr(
    &sock1, rhead)))
    match = 1;

  /* if there was a match, then return that mode */
  if (match)
    return ftflipprr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_ip_src_addr_r */

/*
 * function: eval_match_ip_dst_addr_l
 *
 * Evalute ip_dst_addr as list
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_dst_addr_l(struct ftfil_lookup_ip_mask *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_ip_mask_rec *ftflipmr;
  uint32_t *ip_dst_addr;
  int match;

  ip_dst_addr = ((uint32_t*)(rec+fo->dstaddr));

  match = 0;

  FT_STAILQ_FOREACH(ftflipmr, &lookup->list, chain) {

    /* match? */
    if ((*ip_dst_addr & ftflipmr->mask) == ftflipmr->ip) {
      match = 1;
      break;
    }

  } /* ftflipmr */

  /* if there was a match, then return that mode */
  if (match)
    return ftflipmr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_ip_dst_addr_l */

/*
 * function: eval_match_ip_dst_addr_h
 *
 * Evalute ip_dst_addr as hash
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_dst_addr_h(struct ftfil_lookup_ip_address *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftchash_rec_fil_c32 *ftch_recfc32p;
  uint32_t *ip_dst_addr, hash;
  int match;

  ip_dst_addr = ((uint32_t*)(rec+fo->dstaddr));

  match = 0;

  hash = (*ip_dst_addr>>16) ^ (*ip_dst_addr & 0xFFFF);
  hash = ((hash >>8) ^ (hash & 0x0FFF));

  if ((ftch_recfc32p = ftchash_lookup(lookup->ftch, ip_dst_addr, hash)))
    match = 1;

  /* if there was a match, then return that mode */
  if (match)
    return ftch_recfc32p->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_ip_dst_addr_h */

/*
 * function: eval_match_ip_dst_addr_r
 *
 * Evalute ip_dst_addr as hash
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_dst_addr_r(struct ftfil_lookup_ip_prefix *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_ip_prefix_rec *ftflipprr;
  struct radix_node_head *rhead;
  struct radix_sockaddr_in sock1;
  int match;

  sock1.sin_addr.s_addr = *((uint32_t*)(rec+fo->dstaddr));
  sock1.sin_len = sizeof sock1;
  sock1.sin_family = AF_INET;

  match = 0;

  rhead = lookup->rhead;

  if ((ftflipprr = (struct ftfil_lookup_ip_prefix_rec*)rhead->rnh_matchaddr(
    &sock1, rhead)))
    match = 1;

  /* if there was a match, then return that mode */
  if (match)
    return ftflipprr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_ip_dst_addr_r */

/*
 * function: eval_match_ip_exporter_addr_l
 *
 * Evalute ip_exporter_addr as list
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_exporter_addr_l(struct ftfil_lookup_ip_mask *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_ip_mask_rec *ftflipmr;
  uint32_t *ip_exporter_addr;
  int match;

  ip_exporter_addr = ((uint32_t*)(rec+fo->exaddr));

  match = 0;

  FT_STAILQ_FOREACH(ftflipmr, &lookup->list, chain) {

    /* match? */
    if ((*ip_exporter_addr & ftflipmr->mask) == ftflipmr->ip) {
      match = 1;
      break;
    }

  } /* ftflipmr */

  /* if there was a match, then return that mode */
  if (match)
    return ftflipmr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_ip_exporter_addr_l */

/*
 * function: eval_match_ip_exporter_addr_h
 *
 * Evalute ip_exporter_addr as hash
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_exporter_addr_h(struct ftfil_lookup_ip_address *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftchash_rec_fil_c32 *ftch_recfc32p;
  uint32_t *ip_exporter_addr, hash;
  int match;

  ip_exporter_addr = ((uint32_t*)(rec+fo->exaddr));

  match = 0;

  hash = (*ip_exporter_addr>>16) ^ (*ip_exporter_addr & 0xFFFF);
  hash = ((hash >>8) ^ (hash & 0x0FFF));

  if ((ftch_recfc32p = ftchash_lookup(lookup->ftch, ip_exporter_addr, hash)))
    match = 1;

  /* if there was a match, then return that mode */
  if (match)
    return ftch_recfc32p->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_ip_exporter_addr_h */

/*
 * function: eval_match_ip_exporter_addr_r
 *
 * Evalute ip_exporter_addr as hash
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_ip_exporter_addr_r(struct ftfil_lookup_ip_prefix *lookup,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_ip_prefix_rec *ftflipprr;
  struct radix_node_head *rhead;
  struct radix_sockaddr_in sock1;
  int match;

  sock1.sin_addr.s_addr = *((uint32_t*)(rec+fo->exaddr));
  sock1.sin_len = sizeof sock1;
  sock1.sin_family = AF_INET;

  match = 0;

  rhead = lookup->rhead;

  if ((ftflipprr = (struct ftfil_lookup_ip_prefix_rec*)rhead->rnh_matchaddr(
    &sock1, rhead)))
    match = 1;

  /* if there was a match, then return that mode */
  if (match)
    return ftflipprr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_ip_exporter_addr_r */

/*
 * function: eval_match_bps
 *
 * Evalute Bits Per Second
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_bps(struct ftfil_lookup_double *lookup, char *rec,
  struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_double_rec *ftfldr;
  double bps;
  uint32_t dOctets, Last, First, duration;
  int t, match;

  dOctets = *((uint32_t*)(rec+fo->dOctets));
  Last = *((uint32_t*)(rec+fo->Last));
  First = *((uint32_t*)(rec+fo->First));
  duration = Last - First;

  if (duration)
    bps = (double)dOctets*8 / ((double)duration / 1000.0);
  else
    bps = 0;

  match = 0;

  FT_STAILQ_FOREACH(ftfldr, &lookup->list, chain) {

    switch (ftfldr->op) {

      case FT_FIL_OP_LT:
        t = (bps < ftfldr->val);
        break;
      case FT_FIL_OP_GT:
        t = (bps > ftfldr->val);
        break;
      case FT_FIL_OP_EQ:
        t = (bps == ftfldr->val);
        break;
      case FT_FIL_OP_NE:
        t = (bps != ftfldr->val);
        break;
      case FT_FIL_OP_GE:
        t = (bps >= ftfldr->val);
        break;
      case FT_FIL_OP_LE:
        t = (bps <= ftfldr->val);
        break;
      default:
        fterr_warnx("eval_match_flows: internal error");
        return -1;
        break;

    } /* switch */

    /* did this line match? */
    if (t) {
      match = 1;
      break;
    }

  } /* ftflcr */

  /* if there was a match, then return that mode */
  if (match)
    return ftfldr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_bps */

/*
 * function: eval_match_pps
 *
 * Evalute Packets Per Second
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_pps(struct ftfil_lookup_double *lookup, char *rec,
  struct fts3rec_offsets *fo)
{
  struct ftfil_lookup_double_rec *ftfldr;
  double pps;
  uint32_t dPkts, Last, First, duration;
  int t, match;

  dPkts = *((uint32_t*)(rec+fo->dPkts));
  Last = *((uint32_t*)(rec+fo->Last));
  First = *((uint32_t*)(rec+fo->First));
  duration = Last - First;

  if (duration)
    pps = (double)dPkts / ((double)duration / 1000.0);
  else
    pps = 0;

  match = 0;

  FT_STAILQ_FOREACH(ftfldr, &lookup->list, chain) {

    switch (ftfldr->op) {

      case FT_FIL_OP_LT:
        t = (pps < ftfldr->val);
        break;
      case FT_FIL_OP_GT:
        t = (pps > ftfldr->val);
        break;
      case FT_FIL_OP_EQ:
        t = (pps == ftfldr->val);
        break;
      case FT_FIL_OP_NE:
        t = (pps != ftfldr->val);
        break;
      case FT_FIL_OP_GE:
        t = (pps >= ftfldr->val);
        break;
      case FT_FIL_OP_LE:
        t = (pps <= ftfldr->val);
        break;
      default:
        fterr_warnx("eval_match_flows: internal error");
        return -1;
        break;

    } /* switch */

    /* did this line match? */
    if (t) {
      match = 1;
      break;
    }

  } /* ftflcr */

  /* if there was a match, then return that mode */
  if (match)
    return ftfldr->mode;

  /* else return the default */
  return lookup->default_mode;

} /* eval_match_pps */

/*
 * function: eval_match_random_sample
 *
 * Evalute random_sample
 *
 * returns: FT_FIL_MODE_PERMIT
 *          FT_FIL_MODE_DENY
 */
static int eval_match_random_sample(struct ftfil_lookup_rate *lookup, char *rec,
  struct fts3rec_offsets *fo)
{
  int val;

  /* val is a random number from 0..lookup->rate-1 */
  val = rand() % lookup->rate;

  /* pick 0 as the "pass" value -- could have picked any number in the range */
  if (!val)
    return (lookup->mode == FT_FIL_MODE_PERMIT) ? FT_FIL_MODE_PERMIT :
      FT_FIL_MODE_DENY;
  else
    return (lookup->mode == FT_FIL_MODE_PERMIT) ? FT_FIL_MODE_DENY :
      FT_FIL_MODE_PERMIT;

} /* eval_match_random_sample */

/*
 *************************************************************************
                              public ftfil_*
 *************************************************************************
 */

/*
 * function: ftfil_load
 *
 * Process fname into ftfil.
 *
 * returns: 0  ok
 *          <0 fail
 */
int ftfil_load(struct ftfil *ftfil, struct ftvar *ftvar, const char *fname)
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
  bzero(ftfil, sizeof *ftfil);

  FT_SLIST_INIT(&ftfil->defs);
  FT_SLIST_INIT(&ftfil->primitives);

  lp.sym_ip_prot = ftsym_new(FT_PATH_SYM_IP_PROT);
  lp.sym_ip_tcp_port = ftsym_new(FT_PATH_SYM_TCP_PORT);
#ifdef FT_PATH_SYM_ASN
  lp.sym_asn = ftsym_new(FT_PATH_SYM_ASN);
#endif
  lp.sym_tag = ftsym_new(FT_PATH_SYM_TAG);

  lp.fname = fname;

  if ((fd = open(fname, O_RDONLY, 0)) < 0) {
    fterr_warn("open(%s)", fname);
    goto load_fil_out;
  }

  if (fstat(fd, &sb) < 0) {
    fterr_warn("stat(%s)", fname);
    goto load_fil_out;
  }
  
  /* allocate storage for file */
  if (!(buf = malloc(sb.st_size+1))) {
    fterr_warn("malloc()");
    goto load_fil_out;
  }

  /* read in file */
  if (read(fd, buf, sb.st_size) != sb.st_size) {
    fterr_warnx("read(%s): short", fname);
    goto load_fil_out;
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
      goto load_fil_done;
    }

    /* do variable substitutions first */
    if (ftvar) {
      if (ftvar_evalstr(ftvar, c, sbuf, sizeof(sbuf)) < 0) {
        fterr_warnx("ftvar_evalstr(): failed");
        goto load_fil_done;
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

        if (jmp->func(&lp, ftfil))
          goto load_fil_out;

        NEXT_WORD(&lp.buf, c);

        if (c) {
          fterr_warnx("%s line %d: Unexpected \"%s\".", lp.fname, lp.lineno, c);
          goto load_fil_out;;
        }

        break;

      }

    } /* test each word */

    if (!found) {
      fterr_warnx("%s line %d: Unexpected \"%s\".", lp.fname, lp.lineno, c);
      goto load_fil_out;
    }
   
  } /* more lines */

load_fil_done:

  if (resolve_primitives(ftfil)) {
    fterr_warnx("resolve_primitives(): failed");
    goto load_fil_out;
  }

  ret = 0;

load_fil_out:

  if (fd != -1)
    close(fd);

  if (buf)
    free(buf);

  if (ret == -1)
    ftfil_free(ftfil);

  if (lp.sym_ip_prot)
    ftsym_free(lp.sym_ip_prot);

  if (lp.sym_ip_tcp_port)
    ftsym_free(lp.sym_ip_tcp_port);

#ifdef FT_PATH_SYM_ASN
  if (lp.sym_asn)
    ftsym_free(lp.sym_asn);
#endif

  if (lp.sym_tag)
    ftsym_free(lp.sym_tag);

  return ret;

} /* ftfil_load */

void ftfil_free(struct ftfil *ftfil)
{
  struct ftfil_primitive *ftfp;
  struct ftfil_lookup_ip_address *ftflipa;
  struct ftfil_lookup_ip_prefix *ftflippr;
  struct ftfil_lookup_ip_mask *ftflipm;
  struct ftfil_lookup_counter *ftflc;
  struct ftfil_lookup_counter_rec *ftflcr;
  struct ftfil_lookup_tag *ftflt;
  struct ftfil_lookup_tag_mask *ftfltm;
  struct ftfil_lookup_tag_mask_rec *ftfltmr;
  struct ftfil_lookup_ip_mask_rec *ftflipmr;
  struct ftfil_def *ftfd;
  struct ftfil_match *ftm;
  struct ftfil_match_item *ftmi;
  struct ftfil_lookup_time *ftfltme;
  struct ftfil_lookup_time_rec *ftfltmer;
  struct ftfil_lookup_double *ftfld;
  struct ftfil_lookup_double_rec *ftfldr;

  /*
   * walk the primitive list, free each entry
   */

  while (!FT_SLIST_EMPTY(&ftfil->primitives)) {

    ftfp = FT_SLIST_FIRST(&ftfil->primitives);

    switch (ftfp->type) {

      case FT_FIL_PRIMITIVE_TYPE_IP_PREFIX:
        ftflippr = ftfp->lookup;
        if (ftflippr->init) {
          rhead = ftflippr->rhead;
          rhead->rnh_walktree(rhead, walk_free, 0);
        }
        break;

      case FT_FIL_PRIMITIVE_TYPE_IP_ADDRESS:
        ftflipa = ftfp->lookup;
        if (ftflipa->init)
          ftchash_free(ftflipa->ftch);
        break;

      case FT_FIL_PRIMITIVE_TYPE_IP_MASK:
        ftflipm = ftfp->lookup;
        while (!FT_STAILQ_EMPTY(&ftflipm->list)) {
          ftflipmr = FT_STAILQ_FIRST(&ftflipm->list);
          FT_STAILQ_REMOVE_HEAD(&ftflipm->list, chain);
          free(ftflipmr);
        }
        break;

      case FT_FIL_PRIMITIVE_TYPE_COUNTER:
      case FT_FIL_PRIMITIVE_TYPE_TIME_DATE:
        ftflc = ftfp->lookup;
        while (!FT_STAILQ_EMPTY(&ftflc->list)) {
          ftflcr = FT_STAILQ_FIRST(&ftflc->list);
          FT_STAILQ_REMOVE_HEAD(&ftflc->list, chain);
          free(ftflcr);
        }
        break;
      
      case FT_FIL_PRIMITIVE_TYPE_TAG:
        ftflt = ftfp->lookup;
        if (ftflt->init)
          ftchash_free(ftflt->ftch);
        break;

      case FT_FIL_PRIMITIVE_TYPE_TAG_MASK:
        ftfltm = ftfp->lookup;
        while (!FT_STAILQ_EMPTY(&ftfltm->list)) {
          ftfltmr = FT_STAILQ_FIRST(&ftfltm->list);
          FT_STAILQ_REMOVE_HEAD(&ftfltm->list, chain);
          free(ftfltmr);
        }
        break;

      case FT_FIL_PRIMITIVE_TYPE_TIME:
        ftfltme = ftfp->lookup;
        while (!FT_STAILQ_EMPTY(&ftfltme->list)) {
          ftfltmer = FT_STAILQ_FIRST(&ftfltme->list);
          FT_STAILQ_REMOVE_HEAD(&ftfltme->list, chain);
          free(ftfltmer);
        }
        break;

      case FT_FIL_PRIMITIVE_TYPE_DOUBLE:
        ftfld = ftfp->lookup;
        while (!FT_STAILQ_EMPTY(&ftfld->list)) {
          ftfldr = FT_STAILQ_FIRST(&ftfld->list);
          FT_STAILQ_REMOVE_HEAD(&ftfld->list, chain);
          free(ftfldr);
        }
        break;

      case FT_FIL_PRIMITIVE_TYPE_UNSET:
      case FT_FIL_PRIMITIVE_TYPE_AS:
      case FT_FIL_PRIMITIVE_TYPE_IP_PROTOCOL:
      case FT_FIL_PRIMITIVE_TYPE_IP_PORT:
      case FT_FIL_PRIMITIVE_TYPE_IP_PREFIX_LEN:
      case FT_FIL_PRIMITIVE_TYPE_IP_TOS:
      case FT_FIL_PRIMITIVE_TYPE_IP_TCP_FLAGS:
      case FT_FIL_PRIMITIVE_TYPE_IF_INDEX:
      case FT_FIL_PRIMITIVE_TYPE_ENGINE:
      case FT_FIL_PRIMITIVE_TYPE_RATE:
        /* no work */
        break;

    } /* ftfp->type */

    FT_SLIST_REMOVE_HEAD(&ftfil->primitives, chain);

    if (ftfp->name)
      free(ftfp->name);
    free(ftfp->lookup);
    free(ftfp);

  } /* !ftfil->primitives list empty */

  /*
   * walk the definitions list, free each entry
   */

  while (!FT_SLIST_EMPTY(&ftfil->defs)) {

    ftfd = FT_SLIST_FIRST(&ftfil->defs);

    while (!FT_STAILQ_EMPTY(&ftfd->matches)) {

      ftm = FT_STAILQ_FIRST(&ftfd->matches);

      while (!FT_STAILQ_EMPTY(&ftm->items)) {

        ftmi = FT_STAILQ_FIRST(&ftm->items);

        if (ftmi->tmp_primitive)
          free(ftmi->tmp_primitive);

        if (ftmi->tmp_type)
          free(ftmi->tmp_type);

        FT_STAILQ_REMOVE_HEAD(&ftm->items, chain);
        free(ftmi);

      } /* !ftm->items list empty */

      FT_STAILQ_REMOVE_HEAD(&ftfd->matches, chain);
      free(ftm);

    } /* !ftfd->matches list empty */

    FT_SLIST_REMOVE_HEAD(&ftfil->defs, chain);

    if (ftfd->name)
      free(ftfd->name);
    free(ftfd);

  } /* !ftfil->defs list empty */

} /* ftfil_free */

struct ftfil_def *ftfil_def_find(struct ftfil *ftfil, const char *name)
{
  struct ftfil_def *ftfd;
  int found;

  found = 0;

  FT_SLIST_FOREACH(ftfd, &ftfil->defs, chain) {

    if (!strcasecmp(name, ftfd->name))
      return ftfd;

  } /* ftfd */

  return (struct ftfil_def*)0L;

} /* ftfil_def_find */

/*
 * function: ftfil_def_eval
 *
 * Evaluate a flow with a filter definition
 *
 * returns: FT_FIL_MODE_PERMIT or FT_FIL_MODE_DENY
 *          <0 fail
 */
int ftfil_def_eval(struct ftfil_def *active_def,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftfil_match_item *ftmi;
  struct ftfil_match *ftm;
  int done;

  /* for each match (OR path) */
  FT_STAILQ_FOREACH(ftm, &active_def->matches, chain) {

    done = 1;

    /* for each matchi (AND path) */
    FT_STAILQ_FOREACH(ftmi, &ftm->items, chain) {

      if (ftmi->eval(ftmi->lookup, rec, fo) == FT_FIL_MODE_DENY) {
        done = 0;
        break;
      }

    } /* matchi */

    if (done)
      return active_def->invert ? FT_FIL_MODE_DENY : FT_FIL_MODE_PERMIT;

  } /* match */

  return active_def->invert ? FT_FIL_MODE_PERMIT : FT_FIL_MODE_DENY;

} /* ftfil_def_eval */

/*
 * function: ftfil_test_xfields
 *
 * Check if fields in current flow are valid for a filter -- ie
 * the filter does not reference a field not contained in the flow.
 *
 * returns: 0 okay
 *          1 fail
 */
int ftfil_def_test_xfields(struct ftfil_def *active_def, uint64_t test)
{

  if ((active_def->xfields & test) != active_def->xfields)
    return 1;
  else
    return 0;

} /* ftfil_def_test_xfields */

/*
 *************************************************************************
                             parse_definition_*
 *************************************************************************
 */

/*
 * function: parse_definition
 *
 * process the 'filter-definition' line.  Each primitive has a unique name
 * which is added to the ftfil->definitions linked list.  The current
 * definition is updated in lp.  Filter definitions reference filter
 * primitives
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_definition(struct line_parser *lp, struct ftfil *ftfil)
{
  char *c;
  struct ftfil_def *ftfd;

  NEXT_WORD(&lp->buf, c);

  if (!c) {
    fterr_warnx("%s line %d: Expecting name.", lp->fname, lp->lineno);
    return -1;
  }

  /* check if it exists */
  FT_SLIST_FOREACH(ftfd, &ftfil->defs, chain) {

    if (!strcasecmp(c, ftfd->name)) {
      fterr_warnx("%s line %d: Name (%s) previously defined.", lp->fname,
        lp->lineno, c);
      return -1;
    }

  }

  /* no, add a new entry to the list */
  if (!(ftfd = (struct ftfil_def*)malloc(sizeof
    (struct ftfil_def)))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftfd, sizeof *ftfd);
  FT_STAILQ_INIT(&ftfd->matches);

  if (!(ftfd->name = (char*)malloc(strlen(c)+1))) {
    fterr_warn("malloc()");
    free(ftfd);
    return -1;
  }

  strcpy(ftfd->name, c);

  FT_SLIST_INSERT_HEAD(&ftfil->defs, ftfd, chain);

  lp->state = PARSE_STATE_DEFINITION;
  lp->cur_def = ftfd;
  lp->cur_def_match = (void*)0L;

  return 0;

} /* parse_definition */

/*
 * function: parse_definition_match
 *
 * process the definition match lines
 *
 * _must_ call resolve_primitives when done with all lines and before
 * destroying the file parser buffer.
 *
 * returns: 0  ok
 *          <0 fail
 */
static int parse_definition_match(struct line_parser *lp, struct ftfil *ftfil)
{
  struct ftfil_match_item *ftmi;
  struct ftfil_match *ftm;
  char *c;

  if (!lp->cur_def) {
    fterr_warnx("%s line %d: Not in filter-definition mode.", lp->fname,
    lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, c);
  
  if (!c) {
    fterr_warnx("%s line %d: Expecting match type.", lp->fname,
    lp->lineno); 
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);
  
  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting match primitive.", lp->fname,
    lp->lineno); 
    return -1;
  }

  /*
   * if cur_match is not set, allocate a new match.  This is either the
   * first match line or a match after an or statement (OR path)
   */

  if (!lp->cur_def_match) {

    if (!(ftm = (struct ftfil_match*)malloc(sizeof *ftm))) {
      fterr_warn("malloc()");
      return -1;
    }

    bzero(ftm, sizeof *ftm);
    FT_STAILQ_INIT(&ftm->items);

    lp->cur_def_match = ftm;

    FT_STAILQ_INSERT_TAIL(&lp->cur_def->matches, ftm, chain);

  }

  /* add this match line to the current items list (AND path) */
  if (!(ftmi = (struct ftfil_match_item*)malloc(sizeof *ftmi))) {
    fterr_warn("malloc()");
    if (!lp->cur_def_match)
      free(ftm);
    /* the potential ftm allocation will get cleaned up in ftfil_free() */
    return -1;
  }

  bzero(ftmi, sizeof *ftmi);

  if (!(ftmi->tmp_type = malloc(strlen(c)+1))) {
    if (!lp->cur_def_match)
      free(ftm);
    free(ftmi);
    fterr_warn("malloc()");
    return -1;
  }
  strcpy(ftmi->tmp_type, c);

  if (!(ftmi->tmp_primitive = malloc(strlen(lp->word)+1))) {
    if (!lp->cur_def_match)
      free(ftm);
    free(ftmi->tmp_type);
    free(ftmi);
    fterr_warn("malloc()");
    return -1;
  }
  strcpy(ftmi->tmp_primitive, lp->word);

  FT_STAILQ_INSERT_TAIL(&lp->cur_def_match->items, ftmi, chain);

  return 0;

} /* parse_definition_match */

/*
 * function: parse_definition_invert
 *
 * process the definition invert
 *
 * returns: 0  ok
 *          <0 fail
 */
static int parse_definition_invert(struct line_parser *lp, struct ftfil *ftfil)
{

  if (!lp->cur_def) {
    fterr_warnx("%s line %d: Not in filter-definition mode.", lp->fname,
    lp->lineno);
    return -1;
  }

  lp->cur_def->invert = 1;

  return 0;

} /* parse_definition_invert */

/*
 * function: resolve_primitives
 *
 * resolve the dangling pointers to primitives in definitions --
 * allows definitions to be defined before primitives.
 *
 * _must_ be called after work done by parse_definition_match
 *
 * returns: 0  ok
 *          <0 fail
 */
static int resolve_primitives(struct ftfil *ftfil)
{
  struct ftfil_match_item *ftmi;
  struct ftfil_match *ftm;
  struct ftfil_primitive *ftfp;
  struct ftfil_def *ftfd;
  int type, found, valid;
  void *eval;

  /* foreach definition */
  FT_SLIST_FOREACH(ftfd, &ftfil->defs, chain) {

    /* foreach match line in the definition */
    FT_STAILQ_FOREACH(ftm, &ftfd->matches, chain) {

      /* for each match item in the match line */
      FT_STAILQ_FOREACH(ftmi, &ftm->items, chain) {

        /* Find the primitive */
        found = 0;
        FT_SLIST_FOREACH(ftfp, &ftfil->primitives, chain) {

          if (!strcasecmp(ftmi->tmp_primitive, ftfp->name)) {
            found = 1;
            break;
          } /* if */

        } /* ftfp */

        if (!found) {
          fterr_warnx(
            "Unable to resolve primitive \"%s\" in filter-definition \"%s\".",
            ftmi->tmp_primitive, ftfd->name);
          return -1;
        }

        /*
         * primitive found, set it and make rest of checks
         */

        /* match on what? */
        if (!strcasecmp(ftmi->tmp_type, "src-as")) {
          type = FT_FIL_DEFINITION_MATCH_SRC_AS;
          eval =  eval_match_src_as;
          ftfd->xfields |= FT_XFIELD_SRC_AS;
        } else if (!strcasecmp(ftmi->tmp_type, "source-as")) {
          type = FT_FIL_DEFINITION_MATCH_SRC_AS;
          eval =  eval_match_src_as;
          ftfd->xfields |= FT_XFIELD_SRC_AS;
        } else if (!strcasecmp(ftmi->tmp_type, "dst-as")) {
          type = FT_FIL_DEFINITION_MATCH_DST_AS;
          eval =  eval_match_dst_as;
          ftfd->xfields |= FT_XFIELD_DST_AS;
        } else if (!strcasecmp(ftmi->tmp_type, "destination-as")) {
          type = FT_FIL_DEFINITION_MATCH_DST_AS;
          eval =  eval_match_dst_as;
          ftfd->xfields |= FT_XFIELD_DST_AS;
        } else if (!strcasecmp(ftmi->tmp_type, "ip-protocol")) {
          type = FT_FIL_DEFINITION_MATCH_IP_PROTOCOL;
          eval =  eval_match_ip_prot;
          ftfd->xfields |= FT_XFIELD_PROT;
        } else if (!strcasecmp(ftmi->tmp_type, "src-ip-addr-prefix-len")) {
          type = FT_FIL_DEFINITION_MATCH_IP_SRC_PREFIX_LEN;
          eval =  eval_match_ip_src_prefix_len;
          ftfd->xfields |= FT_XFIELD_SRC_MASK;
        } else if (!strcasecmp(ftmi->tmp_type, "ip-source-address-prefix-len")) {
          type = FT_FIL_DEFINITION_MATCH_IP_SRC_PREFIX_LEN;
          eval =  eval_match_ip_src_prefix_len;
          ftfd->xfields |= FT_XFIELD_SRC_MASK;
        } else if (!strcasecmp(ftmi->tmp_type, "dst-ip-addr-prefix-len")) {
          type = FT_FIL_DEFINITION_MATCH_IP_DST_PREFIX_LEN;
          eval =  eval_match_ip_dst_prefix_len;
          ftfd->xfields |= FT_XFIELD_DST_MASK;
        } else if (!strcasecmp(ftmi->tmp_type, "ip-destination-address-prefix-len")) {
          type = FT_FIL_DEFINITION_MATCH_IP_DST_PREFIX_LEN;
          eval =  eval_match_ip_dst_prefix_len;
          ftfd->xfields |= FT_XFIELD_DST_MASK;
        } else if (!strcasecmp(ftmi->tmp_type, "ip-tos")) {
          type = FT_FIL_DEFINITION_MATCH_IP_TOS;
          eval =  eval_match_ip_tos;
          ftfd->xfields |= FT_XFIELD_TOS;
        } else if (!strcasecmp(ftmi->tmp_type, "ip-marked-tos")) {
          type = FT_FIL_DEFINITION_MATCH_IP_MARKED_TOS;
          eval =  eval_match_ip_marked_tos;
          ftfd->xfields |= FT_XFIELD_MARKED_TOS;
        } else if (!strcasecmp(ftmi->tmp_type, "ip-tcp-flags")) {
          type = FT_FIL_DEFINITION_MATCH_IP_TCP_FLAGS;
          eval =  eval_match_ip_tcp_flags;
          ftfd->xfields |= FT_XFIELD_TCP_FLAGS;
        } else if (!strcasecmp(ftmi->tmp_type, "src-ip-port")) {
          type = FT_FIL_DEFINITION_MATCH_IP_SRC_PORT;
          eval =  eval_match_ip_src_port;
          ftfd->xfields |= FT_XFIELD_SRCPORT;
        } else if (!strcasecmp(ftmi->tmp_type, "ip-source-port")) {
          type = FT_FIL_DEFINITION_MATCH_IP_SRC_PORT;
          eval =  eval_match_ip_src_port;
          ftfd->xfields |= FT_XFIELD_SRCPORT;
        } else if (!strcasecmp(ftmi->tmp_type, "dst-ip-port")) {
          type = FT_FIL_DEFINITION_MATCH_IP_DST_PORT;
          eval =  eval_match_ip_dst_port;
          ftfd->xfields |= FT_XFIELD_DSTPORT;
        } else if (!strcasecmp(ftmi->tmp_type, "ip-destination-port")) {
          type = FT_FIL_DEFINITION_MATCH_IP_DST_PORT;
          eval =  eval_match_ip_dst_port;
          ftfd->xfields |= FT_XFIELD_DSTPORT;
        } else if (!strcasecmp(ftmi->tmp_type, "src-ifindex")) {
          type = FT_FIL_DEFINITION_MATCH_INPUT_IF;
          eval =  eval_match_src_if_index;
          ftfd->xfields |= FT_XFIELD_INPUT;
        } else if (!strcasecmp(ftmi->tmp_type, "input-interface")) {
          type = FT_FIL_DEFINITION_MATCH_INPUT_IF;
          eval =  eval_match_src_if_index;
          ftfd->xfields |= FT_XFIELD_INPUT;
        } else if (!strcasecmp(ftmi->tmp_type, "dst-ifindex")) {
          type = FT_FIL_DEFINITION_MATCH_OUTPUT_IF;
          eval =  eval_match_dst_if_index;
          ftfd->xfields |= FT_XFIELD_OUTPUT;
        } else if (!strcasecmp(ftmi->tmp_type, "output-interface")) {
          type = FT_FIL_DEFINITION_MATCH_OUTPUT_IF;
          eval =  eval_match_dst_if_index;
          ftfd->xfields |= FT_XFIELD_OUTPUT;
        } else if (!strcasecmp(ftmi->tmp_type, "engine-id")) {
          type = FT_FIL_DEFINITION_MATCH_ENGINE_ID;
          eval =  eval_match_engine_id;
          ftfd->xfields |= FT_XFIELD_ENGINE_ID;
        } else if (!strcasecmp(ftmi->tmp_type, "engine-type")) {
          type = FT_FIL_DEFINITION_MATCH_ENGINE_TYPE;
          eval =  eval_match_engine_type;
          ftfd->xfields |= FT_XFIELD_ENGINE_TYPE;
        } else if (!strcasecmp(ftmi->tmp_type, "flows")) {
          type = FT_FIL_DEFINITION_MATCH_FLOWS;
          eval =  eval_match_flows;
          ftfd->xfields |= FT_XFIELD_DFLOWS;
        } else if (!strcasecmp(ftmi->tmp_type, "octets")) {
          type = FT_FIL_DEFINITION_MATCH_OCTETS;
          eval =  eval_match_octets;
          ftfd->xfields |= FT_XFIELD_DOCTETS;
        } else if (!strcasecmp(ftmi->tmp_type, "packets")) {
          type = FT_FIL_DEFINITION_MATCH_PACKETS;
          eval =  eval_match_packets;
          ftfd->xfields |= FT_XFIELD_DPKTS;
        } else if (!strcasecmp(ftmi->tmp_type, "extra-packets")) {
          type = FT_FIL_DEFINITION_MATCH_XTRA_PACKETS;
          eval =  eval_match_xtra_packets;
          ftfd->xfields |= FT_XFIELD_EXTRA_PKTS;
        } else if (!strcasecmp(ftmi->tmp_type, "duration")) {
          type = FT_FIL_DEFINITION_MATCH_DURATION;
          eval =  eval_match_duration;
          ftfd->xfields |= (FT_XFIELD_FIRST|FT_XFIELD_LAST);
        } else if (!strcasecmp(ftmi->tmp_type, "start-time")) {
          type = FT_FIL_DEFINITION_MATCH_START_TIME;
          if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_TIME_DATE)
            eval =  eval_match_start_time_date;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_TIME)
            eval =  eval_match_start_time;
          ftfd->xfields |= (FT_XFIELD_FIRST|FT_XFIELD_UNIX_SECS|
            FT_XFIELD_UNIX_NSECS|FT_XFIELD_SYSUPTIME);
        } else if (!strcasecmp(ftmi->tmp_type, "end-time")) {
          type = FT_FIL_DEFINITION_MATCH_END_TIME;
          if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_TIME_DATE)
            eval =  eval_match_end_time_date;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_TIME)
            eval =  eval_match_end_time;
          ftfd->xfields |= (FT_XFIELD_LAST|FT_XFIELD_UNIX_SECS|
            FT_XFIELD_UNIX_NSECS|FT_XFIELD_SYSUPTIME);
        } else if (!strcasecmp(ftmi->tmp_type, "src-tag")) {
          type = FT_FIL_DEFINITION_MATCH_SRC_TAG;
          ftfd->xfields |= FT_XFIELD_SRC_TAG;
          if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_TAG_MASK)
            eval =  eval_match_src_tag_l;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_TAG)
            eval =  eval_match_src_tag_h;
        } else if (!strcasecmp(ftmi->tmp_type, "source-tag")) {
          type = FT_FIL_DEFINITION_MATCH_SRC_TAG;
          ftfd->xfields |= FT_XFIELD_SRC_TAG;
          if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_TAG_MASK)
            eval =  eval_match_src_tag_l;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_TAG)
            eval =  eval_match_src_tag_h;
        } else if (!strcasecmp(ftmi->tmp_type, "dst-tag")) {
          type = FT_FIL_DEFINITION_MATCH_SRC_TAG;
          ftfd->xfields |= FT_XFIELD_DST_TAG;
          if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_TAG_MASK)
            eval =  eval_match_dst_tag_l;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_TAG)
            eval =  eval_match_dst_tag_h;
        } else if (!strcasecmp(ftmi->tmp_type, "destination-tag")) {
          type = FT_FIL_DEFINITION_MATCH_SRC_TAG;
          ftfd->xfields |= FT_XFIELD_DST_TAG;
          if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_TAG_MASK)
            eval =  eval_match_dst_tag_l;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_TAG)
            eval =  eval_match_dst_tag_h;
        } else if (!strcasecmp(ftmi->tmp_type, "nexthop-ip-addr")) {
          type = FT_FIL_DEFINITION_MATCH_IP_NEXT_HOP_ADDR;
          ftfd->xfields |= FT_XFIELD_NEXTHOP;
          if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_MASK)
            eval =  eval_match_ip_nexthop_addr_l;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_ADDRESS)
            eval =  eval_match_ip_nexthop_addr_h;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_PREFIX)
            eval =  eval_match_ip_nexthop_addr_r;
        } else if (!strcasecmp(ftmi->tmp_type, "ip-nexthop-address")) {
          type = FT_FIL_DEFINITION_MATCH_IP_NEXT_HOP_ADDR;
          ftfd->xfields |= FT_XFIELD_NEXTHOP;
          if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_MASK)
            eval =  eval_match_ip_nexthop_addr_l;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_ADDRESS)
            eval =  eval_match_ip_nexthop_addr_h;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_PREFIX)
            eval =  eval_match_ip_nexthop_addr_r;
        } else if (!strcasecmp(ftmi->tmp_type, "shortcut-ip-addr")) {
          type = FT_FIL_DEFINITION_MATCH_IP_SC_ADDR;
          ftfd->xfields |= FT_XFIELD_ROUTER_SC;
          if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_MASK)
            eval =  eval_match_ip_sc_addr_l;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_ADDRESS)
            eval =  eval_match_ip_sc_addr_h;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_PREFIX)
            eval =  eval_match_ip_sc_addr_r;
        } else if (!strcasecmp(ftmi->tmp_type, "ip-shortcut-address")) {
          type = FT_FIL_DEFINITION_MATCH_IP_SC_ADDR;
          ftfd->xfields |= FT_XFIELD_ROUTER_SC;
          if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_MASK)
            eval =  eval_match_ip_sc_addr_l;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_ADDRESS)
            eval =  eval_match_ip_sc_addr_h;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_PREFIX)
            eval =  eval_match_ip_sc_addr_r;
        } else if (!strcasecmp(ftmi->tmp_type, "src-ip-addr")) {
          type = FT_FIL_DEFINITION_MATCH_IP_SRC_ADDR;
          ftfd->xfields |= FT_XFIELD_SRCADDR;
          if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_MASK)
            eval =  eval_match_ip_src_addr_l;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_ADDRESS)
            eval =  eval_match_ip_src_addr_h;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_PREFIX)
            eval =  eval_match_ip_src_addr_r;
        } else if (!strcasecmp(ftmi->tmp_type, "ip-source-address")) {
          type = FT_FIL_DEFINITION_MATCH_IP_SRC_ADDR;
          ftfd->xfields |= FT_XFIELD_SRCADDR;
          if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_MASK)
            eval =  eval_match_ip_src_addr_l;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_ADDRESS)
            eval =  eval_match_ip_src_addr_h;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_PREFIX)
            eval =  eval_match_ip_src_addr_r;
        } else if (!strcasecmp(ftmi->tmp_type, "dst-ip-addr")) {
          type = FT_FIL_DEFINITION_MATCH_IP_DST_ADDR;
          ftfd->xfields |= FT_XFIELD_DSTADDR;
          if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_MASK)
            eval =  eval_match_ip_dst_addr_l;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_ADDRESS)
            eval =  eval_match_ip_dst_addr_h;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_PREFIX)
            eval =  eval_match_ip_dst_addr_r;
        } else if (!strcasecmp(ftmi->tmp_type, "ip-destination-address")) {
          type = FT_FIL_DEFINITION_MATCH_IP_DST_ADDR;
          ftfd->xfields |= FT_XFIELD_DSTADDR;
          if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_MASK)
            eval =  eval_match_ip_dst_addr_l;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_ADDRESS)
            eval =  eval_match_ip_dst_addr_h;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_PREFIX)
            eval =  eval_match_ip_dst_addr_r;
        } else if (!strcasecmp(ftmi->tmp_type, "exporter-ip-addr")) {
          type = FT_FIL_DEFINITION_MATCH_IP_EXPORTER_ADDR;
          ftfd->xfields |= FT_XFIELD_EXADDR;
          if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_MASK)
            eval =  eval_match_ip_exporter_addr_l;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_ADDRESS)
            eval =  eval_match_ip_exporter_addr_h;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_PREFIX)
            eval =  eval_match_ip_exporter_addr_r;
        } else if (!strcasecmp(ftmi->tmp_type, "ip-exporter-address")) {
          type = FT_FIL_DEFINITION_MATCH_IP_EXPORTER_ADDR;
          ftfd->xfields |= FT_XFIELD_EXADDR;
          if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_MASK)
            eval =  eval_match_ip_exporter_addr_l;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_ADDRESS)
            eval =  eval_match_ip_exporter_addr_h;
          else if (ftfp->type == FT_FIL_PRIMITIVE_TYPE_IP_PREFIX)
            eval =  eval_match_ip_exporter_addr_r;
        } else if (!strcasecmp(ftmi->tmp_type, "bps")) {
          type = FT_FIL_DEFINITION_MATCH_BPS;
          eval =  eval_match_bps;
          ftfd->xfields |= FT_XFIELD_DOCTETS|FT_XFIELD_LAST|FT_XFIELD_FIRST;
        } else if (!strcasecmp(ftmi->tmp_type, "pps")) {
          type = FT_FIL_DEFINITION_MATCH_PPS;
          eval =  eval_match_pps;
          ftfd->xfields |= FT_XFIELD_DPKTS|FT_XFIELD_LAST|FT_XFIELD_FIRST;
        } else if (!strcasecmp(ftmi->tmp_type, "random-sample")) {
          type = FT_FIL_DEFINITION_MATCH_RANDOM_SAMPLE;
          eval =  eval_match_random_sample;
        } else {
          fterr_warnx(
            "Unknown match criteria \"%s\" in filter-definition \"%s\".",
            ftmi->tmp_type, ftfd->name);
          return -1;
        }
      
        /*
         * the match type must be valid for the primitive
         */
      
        valid = 0;
      
        switch (ftfp->type) {
      
          case FT_FIL_PRIMITIVE_TYPE_AS:
            if ((type == FT_FIL_DEFINITION_MATCH_SRC_AS) ||
                (type == FT_FIL_DEFINITION_MATCH_DST_AS))
              valid = 1;
            break;
      
          case FT_FIL_PRIMITIVE_TYPE_IP_PROTOCOL:
            if (type == FT_FIL_DEFINITION_MATCH_IP_PROTOCOL)
              valid = 1;
            break;
      
          case FT_FIL_PRIMITIVE_TYPE_IP_MASK:
            if ((type == FT_FIL_DEFINITION_MATCH_IP_NEXT_HOP_ADDR) || 
                (type == FT_FIL_DEFINITION_MATCH_IP_SRC_ADDR) ||
                (type == FT_FIL_DEFINITION_MATCH_IP_DST_ADDR) ||
                (type == FT_FIL_DEFINITION_MATCH_IP_EXPORTER_ADDR) ||
                (type == FT_FIL_DEFINITION_MATCH_IP_SC_ADDR))
              valid = 1;
              break;
      
          case FT_FIL_PRIMITIVE_TYPE_IP_ADDRESS:
            if ((type == FT_FIL_DEFINITION_MATCH_IP_NEXT_HOP_ADDR) || 
                (type == FT_FIL_DEFINITION_MATCH_IP_SRC_ADDR) ||
                (type == FT_FIL_DEFINITION_MATCH_IP_DST_ADDR) ||
                (type == FT_FIL_DEFINITION_MATCH_IP_EXPORTER_ADDR) ||
                (type == FT_FIL_DEFINITION_MATCH_IP_SC_ADDR))
              valid = 1;
              break;
      
          case FT_FIL_PRIMITIVE_TYPE_IP_PREFIX:
            if ((type == FT_FIL_DEFINITION_MATCH_IP_NEXT_HOP_ADDR) || 
                (type == FT_FIL_DEFINITION_MATCH_IP_SRC_ADDR) ||
                (type == FT_FIL_DEFINITION_MATCH_IP_DST_ADDR) ||
                (type == FT_FIL_DEFINITION_MATCH_IP_EXPORTER_ADDR) ||
                (type == FT_FIL_DEFINITION_MATCH_IP_SC_ADDR))
              valid = 1;
              break;
      
      
          case FT_FIL_PRIMITIVE_TYPE_IP_PORT:
            if ((type == FT_FIL_DEFINITION_MATCH_IP_SRC_PORT) || 
                (type == FT_FIL_DEFINITION_MATCH_IP_DST_PORT))
              valid = 1;
            break;
      
          case FT_FIL_PRIMITIVE_TYPE_IP_PREFIX_LEN:
            if ((type == FT_FIL_DEFINITION_MATCH_IP_SRC_PREFIX_LEN) ||
                (type == FT_FIL_DEFINITION_MATCH_IP_DST_PREFIX_LEN))
              valid = 1;
            break;
      
          case FT_FIL_PRIMITIVE_TYPE_IP_TOS:
            if ((type == FT_FIL_DEFINITION_MATCH_IP_TOS) || 
                (type == FT_FIL_DEFINITION_MATCH_IP_MARKED_TOS))
              valid = 1;
            break;
      
          case FT_FIL_PRIMITIVE_TYPE_IP_TCP_FLAGS:
            if (type == FT_FIL_DEFINITION_MATCH_IP_TCP_FLAGS)
              valid = 1;
            break;
      
          case FT_FIL_PRIMITIVE_TYPE_IF_INDEX:
            if ((type == FT_FIL_DEFINITION_MATCH_INPUT_IF) || 
                (type == FT_FIL_DEFINITION_MATCH_OUTPUT_IF))
              valid = 1;
            break;
      
          case FT_FIL_PRIMITIVE_TYPE_COUNTER:
            if ((type == FT_FIL_DEFINITION_MATCH_FLOWS) || 
                (type == FT_FIL_DEFINITION_MATCH_OCTETS) ||
                (type == FT_FIL_DEFINITION_MATCH_PACKETS) ||
                (type == FT_FIL_DEFINITION_MATCH_XTRA_PACKETS) ||
                (type == FT_FIL_DEFINITION_MATCH_START_TIME) ||
                (type == FT_FIL_DEFINITION_MATCH_DURATION)) 
              valid = 1;
            break;
      
          case FT_FIL_PRIMITIVE_TYPE_TIME:
          case FT_FIL_PRIMITIVE_TYPE_TIME_DATE:
            if ((type == FT_FIL_DEFINITION_MATCH_START_TIME) || 
                (type == FT_FIL_DEFINITION_MATCH_END_TIME))
              valid = 1;
            break;
      
          case FT_FIL_PRIMITIVE_TYPE_ENGINE:
            if ((type == FT_FIL_DEFINITION_MATCH_ENGINE_ID) || 
                (type == FT_FIL_DEFINITION_MATCH_ENGINE_TYPE))
              valid = 1;
            break;
      
          case FT_FIL_PRIMITIVE_TYPE_TAG_MASK:
            if ((type == FT_FIL_DEFINITION_MATCH_SRC_TAG) || 
                (type == FT_FIL_DEFINITION_MATCH_DST_TAG))
              valid = 1;
            break;
      
          case FT_FIL_PRIMITIVE_TYPE_TAG:
            if ((type == FT_FIL_DEFINITION_MATCH_SRC_TAG) || 
                (type == FT_FIL_DEFINITION_MATCH_DST_TAG))
              valid = 1;
            break;

          case FT_FIL_PRIMITIVE_TYPE_DOUBLE:
            if ((type == FT_FIL_DEFINITION_MATCH_PPS) || 
                (type == FT_FIL_DEFINITION_MATCH_BPS))
              valid = 1;
            break;

          case FT_FIL_PRIMITIVE_TYPE_RATE:
            if (type == FT_FIL_DEFINITION_MATCH_RANDOM_SAMPLE)
              valid = 1;
      
          default:
            break;
      
        } /* switch */
      
        /* make sure primitive is valid for match type */
        if (!valid) {
          fterr_warnx(
            "Primitive \"%s\" incompatible with match in filter-definition \"%s\".",
            ftmi->tmp_type, ftfd->name);
          return -1;
        }

        ftmi->lookup = ftfp->lookup;
        ftmi->eval = eval;

      } /* ftmi */

    } /* ftm */

  } /* ftfd */

  return 0;

} /* resolve_primitives */

/*
 * function: parse_definition_or
 *
 * process the definition or lines
 *
 * returns: 0  ok
 *          <0 fail
 */
static int parse_definition_or(struct line_parser *lp, struct ftfil *ftfil)
{
  lp->cur_def_match = (struct ftfil_match*)0L;
  return 0;
} /* parse_definition_or */

/*
 *************************************************************************
                            parse_primitive_*
 *************************************************************************
 */

/*
 * function: parse_primitive_type_asn
 *
 * process the asn primitive
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type_asn(struct line_parser *lp, struct ftfil *ftfil)
{
  struct ftfil_lookup_as *ftfla;

  /* enable symbol lookups */
  lp->sym_cur = lp->sym_tag;

  ftfla = (struct ftfil_lookup_as*)lp->cur_primitive->lookup;

  if (ftfil_load_lookup(lp, lp->word, 65536, ftfla->mode, lp->mode)) {
    fterr_warnx("load_lookup(): failed");
    return -1;
  }

  return 0;

} /* parse_primitive_type_asn */

/*
 * function: parse_primitive_type_ip_prot
 *
 * process the ip_prot primitive
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type_ip_prot(struct line_parser *lp,
  struct ftfil *ftfil)
{
  struct ftfil_lookup_ip_prot *ftflipp;

  /* enable symbol lookups */
  lp->sym_cur = lp->sym_ip_prot;

  ftflipp = (struct ftfil_lookup_ip_prot*)lp->cur_primitive->lookup;

  if (ftfil_load_lookup(lp, lp->word, 256, ftflipp->mode, lp->mode)) {
    fterr_warnx("load_lookup(): failed");
    return -1;
  }

  return 0;

} /* parse_primitive_type_ip_prot */

/*
 * function: parse_primitive_type_ip_port
 *
 * process the ip_port primitive
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type_ip_port(struct line_parser *lp,
  struct ftfil *ftfil)
{
  struct ftfil_lookup_ip_port *ftflippo;

  /* enable symbol lookups */
  lp->sym_cur = lp->sym_ip_tcp_port;

  ftflippo = (struct ftfil_lookup_ip_port*)lp->cur_primitive->lookup;

  if (ftfil_load_lookup(lp, lp->word, 65536, ftflippo->mode, lp->mode)) {
    fterr_warnx("load_lookup(): failed");
    return -1;
  }

  return 0;

} /* parse_primitive_type_ip_port */

/*
 * function: parse_primitive_type_ip_prefix_len
 *
 * process the ip_prefix_len primitive
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type_ip_prefix_len(struct line_parser *lp,
  struct ftfil *ftfil)
{
  struct ftfil_lookup_ip_prefix_len *ftflipl;

  /* disable symbol lookups */
  lp->sym_cur = (struct ftsym*)0L;

  ftflipl = (struct ftfil_lookup_ip_prefix_len*)lp->cur_primitive->lookup;

  if (ftfil_load_lookup(lp, lp->word, 33, ftflipl->mode, lp->mode)) {
    fterr_warnx("load_lookup(): failed");
    return -1;
  }

  return 0;

} /* parse_primitive_type_ip_prefix_len */

/*
 * function: parse_primitive_type_ip_tos
 *
 * process the ip_tos primitive
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type_ip_tos(struct line_parser *lp,
  struct ftfil *ftfil)
{
  struct ftfil_lookup_ip_tos *ftflipt;

  /* disable symbol lookups */
  lp->sym_cur = (struct ftsym*)0L;

  ftflipt = (struct ftfil_lookup_ip_tos*)lp->cur_primitive->lookup;

  if (ftfil_load_lookup(lp, lp->word, 256, ftflipt->mode, lp->mode)) {
    fterr_warnx("load_lookup(): failed");
    return -1;
  }

  return 0;

} /* parse_primitive_type_ip_tos */

/*
 * function: parse_primitive_type_ip_tcp_flags
 *
 * process the ip_tcp_flags primitive
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type_ip_tcp_flags(struct line_parser *lp,
  struct ftfil *ftfil)
{
  struct ftfil_lookup_ip_tcp_flags *ftfliptcp;

  /* disable symbol lookups */
  lp->sym_cur = (struct ftsym*)0L;

  ftfliptcp = (struct ftfil_lookup_ip_tcp_flags*)lp->cur_primitive->lookup;

  if (ftfil_load_lookup(lp, lp->word, 256, ftfliptcp->mode, lp->mode)) {
    fterr_warnx("load_lookup(): failed");
    return -1;
  }

  return 0;

} /* parse_primitive_type_ip_tcp_flags */

/*
 * function: parse_primitive_type_if_index
 *
 * process the if_index primitive
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type_if_index(struct line_parser *lp,
  struct ftfil *ftfil)
{
  struct ftfil_lookup_if_index *ftflif;

  /* disable symbol lookups */
  lp->sym_cur = (struct ftsym*)0L;

  ftflif = (struct ftfil_lookup_if_index*)lp->cur_primitive->lookup;

  if (ftfil_load_lookup(lp, lp->word, 65536, ftflif->mode, lp->mode)) {
    fterr_warnx("load_lookup(): failed");
    return -1;
  }

  return 0;

} /* parse_primitive_type_if_index */

/*
 * function: parse_primitive_type_engine
 *
 * process the engine primitive
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type_engine(struct line_parser *lp,
  struct ftfil *ftfil)
{
  struct ftfil_lookup_engine *ftfle;

  /* disable symbol lookups */
  lp->sym_cur = (struct ftsym*)0L;

  ftfle = (struct ftfil_lookup_engine*)lp->cur_primitive->lookup;

  if (ftfil_load_lookup(lp, lp->word, 65536, ftfle->mode, lp->mode)) {
    fterr_warnx("load_lookup(): failed");
    return -1;
  }

  return 0;

} /* parse_primitive_type_engine */

/*
 * function: parse_primitive_type_ip_address
 *
 * process the ip-address primitive
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type_ip_address(struct line_parser *lp,
  struct ftfil *ftfil)
{
  struct ftfil_lookup_ip_address *ftflipa;
  struct ftchash_rec_fil_c32 ftch_recfc32, *ftch_recfc32p;
  uint32_t hash;
  char fmt_buf[32];

  ftflipa = (struct ftfil_lookup_ip_address*)lp->cur_primitive->lookup;

  bzero(&ftch_recfc32, sizeof ftch_recfc32);

  ftch_recfc32.c32 = scan_ip(lp->word);

  hash = (ftch_recfc32.c32>>16) ^ (ftch_recfc32.c32 & 0xFFFF);
  hash = ((hash >>8) ^ (hash & 0x0FFF));

  if ((ftch_recfc32p = ftchash_lookup(ftflipa->ftch, &ftch_recfc32.c32,
    hash))) {
    fmt_ipv4(fmt_buf, ftch_recfc32p->c32, FMT_JUST_LEFT);
    fterr_warnx("%s line %d: entry %s previously set as %s.", lp->fname,
      lp->lineno, fmt_buf, mode_name_lookup[ftch_recfc32p->mode]);
  }

  if (!(ftch_recfc32p = ftchash_update(ftflipa->ftch, &ftch_recfc32, hash))) {
    fterr_warnx("ftch_update(): failed");
    return -1;
  }

  ftch_recfc32p->mode = lp->mode;

  return 0;

} /* parse_primitive_type_ip_address */

/*
 * function: parse_primitive_type_tag
 *
 * process the tag primitive
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type_tag(struct line_parser *lp,
  struct ftfil *ftfil)
{
  struct ftfil_lookup_tag *ftflt;
  struct ftchash_rec_fil_c32 ftch_recfc32, *ftch_recfc32p;
  uint32_t hash, val;

  ftflt = (struct ftfil_lookup_tag*)lp->cur_primitive->lookup;

  bzero(&ftch_recfc32, sizeof ftch_recfc32);

  if (isalpha((int)lp->word[0])) {
    if (lp->sym_tag && ftsym_findbyname(lp->sym_tag, lp->word, &val))
      ftch_recfc32.c32 = val;
    else {
      fterr_warnx("%s line %d: symbol lookup for \"%s\" failed.", lp->fname,
        lp->lineno, lp->word);
      return -1;
    }
  } else
    ftch_recfc32.c32 = strtoul(lp->word, (char**)0L, 0);

  hash = (ftch_recfc32.c32>>16) ^ (ftch_recfc32.c32 & 0xFFFF);
  hash = ((hash >>8) ^ (hash & 0x0FFF));

  if ((ftch_recfc32p = ftchash_lookup(ftflt->ftch, &ftch_recfc32.c32, hash)))
    fterr_warnx("%s line %d: entry 0x%lX previously set as %s.", lp->fname,
      lp->lineno, ftch_recfc32.c32, mode_name_lookup[ftch_recfc32p->mode]);

  if (!(ftch_recfc32p = ftchash_update(ftflt->ftch, &ftch_recfc32, hash))) {
    fterr_warnx("ftch_update(): failed");
    return -1;
  }

  ftch_recfc32p->mode = lp->mode;

  return 0;

} /* parse_primitive_type_tag */

/*
 * function: parse_primitive_type_ip_mask
 *
 * process the ip-mask primitive
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type_ip_mask(struct line_parser *lp,
  struct ftfil *ftfil)
{
  struct ftfil_lookup_ip_mask *ftflipm;
  struct ftfil_lookup_ip_mask_rec *ftflipmr, *ftflipmr2;
  char fmt_buf1[32], fmt_buf2[32];
  char *ip;

  ip = lp->word;

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting mask.", lp->fname, lp->lineno);
    return -1;
  }

  ftflipm = (struct ftfil_lookup_ip_mask*)lp->cur_primitive->lookup;

  if (!(ftflipmr = (struct ftfil_lookup_ip_mask_rec*)
    malloc(sizeof *ftflipmr))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftflipmr, sizeof *ftflipmr);

  ftflipmr->ip = scan_ip(ip);
  ftflipmr->mask = scan_ip(lp->word);
  ftflipmr->mode = lp->mode;

  FT_STAILQ_FOREACH(ftflipmr2, &ftflipm->list, chain) {

    if ((ftflipmr2->ip == ftflipmr->ip) &&
        (ftflipmr2->mask == ftflipmr->mask)) {

      fmt_ipv4(fmt_buf1, ftflipmr2->ip, FMT_JUST_LEFT);
      fmt_ipv4(fmt_buf2, ftflipmr2->mask, FMT_JUST_LEFT);

      fterr_warnx("%s line %d: entry %s %s previously set as %s.", lp->fname,
        lp->lineno, fmt_buf1, fmt_buf2, mode_name_lookup[ftflipmr2->mode]);

    }
  }

  FT_STAILQ_INSERT_TAIL(&ftflipm->list, ftflipmr, chain);

  return 0;

} /* parse_primitive_type_ip_mask */

/*
 * function: parse_primitive_type_tag_mask
 *
 * process the tag-mask primitive
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type_tag_mask(struct line_parser *lp,
  struct ftfil *ftfil)
{
  struct ftfil_lookup_tag_mask *ftfltm;
  struct ftfil_lookup_tag_mask_rec *ftfltmr, *ftfltmr2;
  uint32_t val, tval;
  char *tag;

  tag = lp->word;

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting mask.", lp->fname, lp->lineno);
    return -1;
  }

  ftfltm = (struct ftfil_lookup_tag_mask*)lp->cur_primitive->lookup;

  if (isalpha((int)tag[0])) {
    if (lp->sym_tag && ftsym_findbyname(lp->sym_tag, tag, &val))
      tval = val;
    else {
      fterr_warnx("%s line %d: symbol lookup for \"%s\" failed.", lp->fname,
        lp->lineno, tag);
      return -1;
    }
  } else
    tval = strtoul(tag, (char**)0L, 0);

  if (!(ftfltmr = (struct ftfil_lookup_tag_mask_rec*)
    malloc(sizeof *ftfltmr))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftfltmr, sizeof *ftfltmr);

  ftfltmr->tag = tval;
  ftfltmr->mask = strtoul(lp->word, (char**)0L, 0);
  ftfltmr->mode = lp->mode;

  FT_STAILQ_FOREACH(ftfltmr2, &ftfltm->list, chain) {

    if ((ftfltmr2->tag == ftfltmr->tag) &&
        (ftfltmr2->mask == ftfltmr->mask)) {

      fterr_warnx("%s line %d: entry 0x%lX 0x%lX previously set as %s.",
        lp->fname, lp->lineno, ftfltmr2->tag, ftfltmr2->mask,
        mode_name_lookup[ftfltmr2->mode]);

    }
  }

  FT_STAILQ_INSERT_TAIL(&ftfltm->list, ftfltmr, chain);

  return 0;

} /* parse_primitive_type_tag_mask */

/*
 * function: parse_primitive_type_ip_prefix
 *
 * process the ip-prefix primitive
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type_ip_prefix(struct line_parser *lp,
  struct ftfil *ftfil)
{
  struct ftfil_lookup_ip_prefix *ftflippr;
  struct ftfil_lookup_ip_prefix_rec *ftflipprr, *ftflipprr2;
  struct ip_prefix ipp;
  struct radix_sockaddr_in sock1, sock2;
  char fmt_buf[32];

  ftflippr = (struct ftfil_lookup_ip_prefix*)lp->cur_primitive->lookup;

  if (!(ftflipprr = (struct ftfil_lookup_ip_prefix_rec*)
     malloc(sizeof *ftflipprr))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero (ftflipprr, sizeof *ftflipprr);

  ipp = scan_ip_prefix(lp->word);

  ftflipprr->rt_nodes->rn_key = (caddr_t)&ftflipprr->addr;
  ftflipprr->addr.sin_addr.s_addr = ipp.addr;
  ftflipprr->addr.sin_len = sizeof (struct radix_sockaddr_in);
  ftflipprr->addr.sin_family = AF_INET;
  ftflipprr->masklen = ipp.len;
  ftflipprr->mode = lp->mode;

  bzero(&sock1, sizeof sock1);
  bzero(&sock2, sizeof sock2);

  sock1.sin_addr.s_addr = ipp.addr;
  sock1.sin_family = AF_INET;
  sock1.sin_len = sizeof sock1;

  sock2.sin_addr.s_addr = (!ipp.len) ? 0 : mask_lookup[ipp.len];
  sock2.sin_family = AF_INET;
  sock2.sin_len = sizeof sock2;

  ftflipprr2 = (struct ftfil_lookup_ip_prefix_rec*)
    ftflippr->rhead->rnh_lookup(&sock1, &sock2, ftflippr->rhead);

  if (ftflipprr2 && (ftflipprr2->addr.sin_addr.s_addr == ipp.addr) &&
     (ftflipprr2->masklen == ipp.len)) {

    fmt_ipv4prefix(fmt_buf, ftflipprr2->addr.sin_addr.s_addr,
      ftflipprr2->masklen, FMT_JUST_LEFT);

    fterr_warnx("%s line %d: entry %s previously set as %s.", lp->fname,
      lp->lineno, fmt_buf, mode_name_lookup[ftflipprr2->mode]);

    /* can't add this again */
    free(ftflipprr);
    return 0;

  }

  if (!ftflippr->rhead->rnh_addaddr(&ftflipprr->addr, &sock2, ftflippr->rhead,
    ftflipprr->rt_nodes)) {
    free(ftflipprr);
    fterr_warnx("rnh_addaddr(): failed for %s", lp->word);
    return -1;
  }

  return 0;

} /* parse_primitive_type_ip_prefix */

/*
 * function: parse_primitive_type_counter
 *
 * process the counter primitive
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type_counter(struct line_parser *lp,
  struct ftfil *ftfil)
{
  struct ftfil_lookup_counter *ftflc;
  struct ftfil_lookup_counter_rec *ftflcr, *ftflcr2;
  char *c;
  enum ftfil_op op;

  c = lp->word;

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting counter.", lp->fname, lp->lineno);
    return -1;
  }

  if (!strcasecmp(c, "lt"))
    op = FT_FIL_OP_LT;
  else if (!strcasecmp(c, "gt"))
    op = FT_FIL_OP_GT;
  else if (!strcasecmp(c, "eq"))
    op = FT_FIL_OP_EQ;
  else if (!strcasecmp(c, "ne"))
    op = FT_FIL_OP_NE;
  else if (!strcasecmp(c, "le"))
    op = FT_FIL_OP_LE;
  else if (!strcasecmp(c, "ge"))
    op = FT_FIL_OP_GE;
  else {
    fterr_warnx("%s line %d: Expecting one of {lt,gt,eq,ne,le,ge}",
      lp->fname, lp->lineno);
    return -1;
  }

  ftflc = (struct ftfil_lookup_counter*)lp->cur_primitive->lookup;

  if (!(ftflcr = (struct ftfil_lookup_counter_rec*) malloc(sizeof *ftflcr))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftflcr, sizeof *ftflcr);

  ftflcr->val = strtoul(lp->word, (char**)0L, 0);
  ftflcr->op = op;
  ftflcr->mode = lp->mode;

  FT_STAILQ_FOREACH(ftflcr2, &ftflc->list, chain) {

    if ((ftflcr2->val == ftflcr->val) &&
        (ftflcr2->op == ftflcr->op)) {

      fterr_warnx("%s line %d: entry %s %lu previously set as %s.",
        lp->fname, lp->lineno, op_name_lookup[ftflcr2->op], ftflcr2->val,
        mode_name_lookup[ftflcr2->mode]);

    }
  }


  FT_STAILQ_INSERT_TAIL(&ftflc->list, ftflcr, chain);

  return 0;

} /* parse_primitive_type_counter */

/*
 * function: parse_primitive_type_time_date
 *
 * process the time/date primitive
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type_time_date(struct line_parser *lp,
  struct ftfil *ftfil)
{
  struct ftfil_lookup_counter *ftflc;
  struct ftfil_lookup_counter_rec *ftflcr, *ftflcr2;
  time_t t;
  enum ftfil_op op;

  if (!lp->buf) {
    fterr_warnx("%s line %d: Expecting time/date.", lp->fname, lp->lineno);
    return -1;
  }

  if ((t = get_date(lp->buf, (time_t*)0L)) == -1) {
    fterr_warnx("%s line %d: Cannot parse time/date.", lp->fname, lp->lineno);
    return -1;
  }

  /* eat the line */
  for (; *(lp->buf); ++lp->buf);

  if (!strcasecmp(lp->word, "lt"))
    op = FT_FIL_OP_LT;
  else if (!strcasecmp(lp->word, "gt"))
    op = FT_FIL_OP_GT;
  else if (!strcasecmp(lp->word, "eq"))
    op = FT_FIL_OP_EQ;
  else if (!strcasecmp(lp->word, "ne"))
    op = FT_FIL_OP_NE;
  else if (!strcasecmp(lp->word, "le"))
    op = FT_FIL_OP_LE;
  else if (!strcasecmp(lp->word, "ge"))
    op = FT_FIL_OP_GE;
  else {
    fterr_warnx("%s line %d: Expecting one of {lt,gt,eq,ne,le,ge}",
      lp->fname, lp->lineno);
    return -1;
  }
  
  ftflc = (struct ftfil_lookup_counter*)lp->cur_primitive->lookup;

  if (!(ftflcr = (struct ftfil_lookup_counter_rec*) malloc(sizeof *ftflcr))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftflcr, sizeof *ftflcr);

  ftflcr->val = t;
  ftflcr->op = op;
  ftflcr->mode = lp->mode;

  FT_STAILQ_FOREACH(ftflcr2, &ftflc->list, chain) {

    if ((ftflcr2->val == ftflcr->val) &&
        (ftflcr2->op == ftflcr->op)) {

      fterr_warnx("%s line %d: entry %s %lu previously set as %s.",
        lp->fname, lp->lineno, op_name_lookup[ftflcr2->op], ftflcr2->val,
        mode_name_lookup[ftflcr2->mode]);

    }
  }

  FT_STAILQ_INSERT_TAIL(&ftflc->list, ftflcr, chain);

  return 0;

} /* parse_primitive_type_time_date */

/*
 * function: parse_primitive_type_time
 *
 * process the time primitive
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type_time(struct line_parser *lp,
  struct ftfil *ftfil)
{
  struct ftfil_lookup_time *ftfltme;
  struct ftfil_lookup_time_rec *ftfltmer, *ftfltmer2;
  enum ftfil_op op;
  char *c, *cop;
  int hour, min, sec;

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting time op.", lp->fname, lp->lineno);
    return -1;
  }

  cop = lp->word;

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting time value.", lp->fname, lp->lineno);
    return -1;
  }

  /* parse out time */
  hour = min = sec = 0;

  if (!(c = strsep(&lp->word, ":")))
    goto done;
  
  hour = atoi(c);

  if (!(c = strsep(&lp->word, ":")))
    goto done;

  min = atoi(c);

  if (!(c = strsep(&lp->word, ":")))
    goto done;

  sec = atoi(c);

  if (lp->word) {
    fterr_warnx("%s line %d: Unexpected text: %s", lp->fname, lp->lineno, 
      lp->word);
    return -1;
  }

done:

  if (!strcasecmp(cop, "lt"))
    op = FT_FIL_OP_LT;
  else if (!strcasecmp(cop, "gt"))
    op = FT_FIL_OP_GT;
  else if (!strcasecmp(cop, "eq"))
    op = FT_FIL_OP_EQ;
  else if (!strcasecmp(cop, "ne"))
    op = FT_FIL_OP_NE;
  else if (!strcasecmp(cop, "le"))
    op = FT_FIL_OP_LE;
  else if (!strcasecmp(cop, "ge"))
    op = FT_FIL_OP_GE;
  else {
    fterr_warnx("%s line %d: Expecting one of {lt,gt,eq,ne,le,ge}",
      lp->fname, lp->lineno);
    return -1;
  }

  ftfltme = (struct ftfil_lookup_time*)lp->cur_primitive->lookup;

  if (!(ftfltmer = (struct ftfil_lookup_time_rec*) malloc(sizeof *ftfltmer))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftfltmer, sizeof *ftfltmer);

  ftfltmer->hour = hour;
  ftfltmer->min = min;
  ftfltmer->sec = sec;
  ftfltmer->op = op;
  ftfltmer->mode = lp->mode;

  FT_STAILQ_FOREACH(ftfltmer2, &ftfltme->list, chain) {

    if ((ftfltmer2->hour == ftfltmer->hour) &&
        (ftfltmer2->min == ftfltmer->min) &&
        (ftfltmer2->sec == ftfltmer->sec) &&
        (ftfltmer2->op == ftfltmer->op)) {

      fterr_warnx("%s line %d: entry %d:%d:%d %lu previously set as %s.",
        lp->fname, lp->lineno, op_name_lookup[ftfltmer2->op], ftfltmer2->hour,
        ftfltmer2->min, ftfltmer2->sec, mode_name_lookup[ftfltmer2->mode]);

    }
  }

  FT_STAILQ_INSERT_TAIL(&ftfltme->list, ftfltmer, chain);

  return 0;

} /* parse_primitive_type_time */

/*
 * function: parse_primitive_type_double
 *
 * process the double primitive
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type_double(struct line_parser *lp,
  struct ftfil *ftfil)
{
  struct ftfil_lookup_double *ftfld;
  struct ftfil_lookup_double_rec *ftfldr, *ftfldr2;
  char *c;
  enum ftfil_op op;

  c = lp->word;

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting counter.", lp->fname, lp->lineno);
    return -1;
  }

  if (!strcasecmp(c, "lt"))
    op = FT_FIL_OP_LT;
  else if (!strcasecmp(c, "gt"))
    op = FT_FIL_OP_GT;
  else if (!strcasecmp(c, "eq"))
    op = FT_FIL_OP_EQ;
  else if (!strcasecmp(c, "ne"))
    op = FT_FIL_OP_NE;
  else if (!strcasecmp(c, "le"))
    op = FT_FIL_OP_LE;
  else if (!strcasecmp(c, "ge"))
    op = FT_FIL_OP_GE;
  else {
    fterr_warnx("%s line %d: Expecting one of {lt,gt,eq,ne,le,ge}",
      lp->fname, lp->lineno);
    return -1;
  }

  ftfld = (struct ftfil_lookup_double*)lp->cur_primitive->lookup;

  if (!(ftfldr = (struct ftfil_lookup_double_rec*) malloc(sizeof *ftfldr))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftfldr, sizeof *ftfldr);

  ftfldr->val = strtod(lp->word, (char**)0L);
  ftfldr->op = op;
  ftfldr->mode = lp->mode;

  FT_STAILQ_FOREACH(ftfldr2, &ftfld->list, chain) {

    if ((ftfldr2->val == ftfldr->val) &&
        (ftfldr2->op == ftfldr->op)) {

      fterr_warnx("%s line %d: entry %s %f previously set as %s.",
        lp->fname, lp->lineno, op_name_lookup[ftfldr2->op], ftfldr2->val,
        mode_name_lookup[ftfldr2->mode]);

    }
  }


  FT_STAILQ_INSERT_TAIL(&ftfld->list, ftfldr, chain);

  return 0;

} /* parse_primitive_type_double */

/*
 * function: parse_primitive_type_rate
 *
 * process the rate primitive
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type_rate(struct line_parser *lp,
  struct ftfil *ftfil)
{
  struct ftfil_lookup_rate *ftflr;

  /* disable symbol lookups */
  lp->sym_cur = (struct ftsym*)0L;

  ftflr = (struct ftfil_lookup_rate*)lp->cur_primitive->lookup;

  if (ftflr->rate)
    fterr_warnx("%s line %d: Rate previously set.", lp->fname, lp->lineno);

  ftflr->rate = atoi(lp->word);

  if (!ftflr->rate)
    fterr_errx(1, "%s line %d: Rate can not be 0.", lp->fname, lp->lineno);
  ftflr->mode = lp->mode;

  return 0;

} /* parse_primitive_type_rate */

/*
 * function: parse_primitive
 *
 * process the 'filter-primitive' line.  Each primitive has a unique name
 * which is added to the ftfil->primitives linked list.  The current
 * primitive definition is updated in lp.  Primitives by themself do nothing,
 * they must be invoked by a definition.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive(struct line_parser *lp, struct ftfil *ftfil)
{
  char *c;
  struct ftfil_primitive *ftfp;

  NEXT_WORD(&lp->buf, c);

  if (!c) {
    fterr_warnx("%s line %d: Expecting name.", lp->fname, lp->lineno);
    return -1;
  }

  /* check if it exists */
  FT_SLIST_FOREACH(ftfp, &ftfil->primitives, chain) {

    if (!strcasecmp(c, ftfp->name)) {
      fterr_warnx("%s line %d: Name (%s) previously defined.", lp->fname,
        lp->lineno, c);
      return -1;
    }

  }

  /* no, add a new entry to the list */
  if (!(ftfp = (struct ftfil_primitive*)malloc(sizeof
    (struct ftfil_primitive)))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftfp, sizeof *ftfp);

  if (!(ftfp->name = (char*)malloc(strlen(c)+1))) {
    fterr_warn("malloc()");
    free(ftfp);
    return -1;
  }

  strcpy(ftfp->name, c);

  FT_SLIST_INSERT_HEAD(&ftfil->primitives, ftfp, chain);

  lp->state = PARSE_STATE_PRIMITIVE;
  lp->cur_primitive = ftfp;

  return 0;

} /* parse_primitive */

/*
 * function: parse_primitive_type
 *
 * process the 'type' line.  When the type is set the initial storage
 * is allocated.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_type(struct line_parser *lp, struct ftfil *ftfil)
{
  struct ftfil_lookup_ip_address *ftflipa;
  struct ftfil_lookup_ip_prefix *ftflippr;
  struct ftfil_lookup_ip_mask *ftflipm;
  struct ftfil_lookup_as *ftfla;
  struct ftfil_lookup_ip_prefix_len *ftflipl;
  struct ftfil_lookup_ip_prot *ftflipp;
  struct ftfil_lookup_ip_tos *ftflipt;
  struct ftfil_lookup_ip_tcp_flags *ftfliptcp;
  struct ftfil_lookup_if_index *ftflif;
  struct ftfil_lookup_engine *ftfle;
  struct ftfil_lookup_ip_port *ftflippo;
  struct ftfil_lookup_counter *ftflc;
  struct ftfil_lookup_tag *ftflt;
  struct ftfil_lookup_tag_mask *ftfltm;
  struct ftfil_lookup_counter *ftfltme;
  struct ftfil_lookup_double *ftfld;
  struct ftfil_lookup_rate *ftflr;

  if (!lp->cur_primitive) {
    fterr_warnx("%s line %d: Must set name first.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting type.", lp->fname, lp->lineno);
    return -1;
  }

  if (lp->cur_primitive->type) {
    fterr_warnx("%s line %d: Type previously defined.", lp->fname, lp->lineno);
    return -1;
  }

  if (!strcasecmp(lp->word, "as")) {

    lp->cur_primitive->type = FT_FIL_PRIMITIVE_TYPE_AS;
    PARSE_PRIMITIVE_TYPE_INIT(ftfla);

  } else if (!strcasecmp(lp->word, "ip-address-prefix")) {

    lp->cur_primitive->type = FT_FIL_PRIMITIVE_TYPE_IP_PREFIX;
    PARSE_PRIMITIVE_TYPE_INIT(ftflippr);

    RADIX_TRIE_INIT;

    if (rn_inithead((void**)&ftflippr->rhead, 32) < 0) {  
      fterr_warnx("rn_inithead(): failed");
      return -1;
    }

  } else if (!strcasecmp(lp->word, "ip-address")) {

    lp->cur_primitive->type = FT_FIL_PRIMITIVE_TYPE_IP_ADDRESS;
    PARSE_PRIMITIVE_TYPE_INIT(ftflipa);

    if (!(ftflipa->ftch = ftchash_new(4096,
      sizeof (struct ftchash_rec_fil_c32), 4, 12))) {
      fterr_warnx("ftchash_new(): failed");
      return -1;
    }

  } else if (!strcasecmp(lp->word, "ip-address-mask")) {

    lp->cur_primitive->type = FT_FIL_PRIMITIVE_TYPE_IP_MASK;
    PARSE_PRIMITIVE_TYPE_INIT(ftflipm);
    FT_STAILQ_INIT(&ftflipm->list);

  } else if (!strcasecmp(lp->word, "ip-protocol")) {

    lp->cur_primitive->type = FT_FIL_PRIMITIVE_TYPE_IP_PROTOCOL;
    PARSE_PRIMITIVE_TYPE_INIT(ftflipp);

  } else if (!strcasecmp(lp->word, "ip-port")) {

    lp->cur_primitive->type = FT_FIL_PRIMITIVE_TYPE_IP_PORT;
    PARSE_PRIMITIVE_TYPE_INIT(ftflippo);

  } else if (!strcasecmp(lp->word, "ip-address-prefix-len")) {

    lp->cur_primitive->type = FT_FIL_PRIMITIVE_TYPE_IP_PREFIX_LEN;
    PARSE_PRIMITIVE_TYPE_INIT(ftflipl);

  } else if (!strcasecmp(lp->word, "ip-tos")) {

    lp->cur_primitive->type = FT_FIL_PRIMITIVE_TYPE_IP_TOS;
    PARSE_PRIMITIVE_TYPE_INIT(ftflipt);

    ftflipt->mask = 0xFF;

  } else if (!strcasecmp(lp->word, "ip-tcp-flags")) {

    lp->cur_primitive->type = FT_FIL_PRIMITIVE_TYPE_IP_TCP_FLAGS;
    PARSE_PRIMITIVE_TYPE_INIT(ftfliptcp);

    ftfliptcp->mask = 0xFF;

  } else if (!strcasecmp(lp->word, "ifindex")) {

    lp->cur_primitive->type = FT_FIL_PRIMITIVE_TYPE_IF_INDEX;
    PARSE_PRIMITIVE_TYPE_INIT(ftflif);

  } else if (!strcasecmp(lp->word, "counter")) {

    lp->cur_primitive->type = FT_FIL_PRIMITIVE_TYPE_COUNTER;
    PARSE_PRIMITIVE_TYPE_INIT(ftflc);

    FT_STAILQ_INIT(&ftflc->list);

  } else if (!strcasecmp(lp->word, "time-date")) {

    lp->cur_primitive->type = FT_FIL_PRIMITIVE_TYPE_TIME_DATE;
    PARSE_PRIMITIVE_TYPE_INIT(ftflc);

    FT_STAILQ_INIT(&ftflc->list);

  } else if (!strcasecmp(lp->word, "engine")) {

    lp->cur_primitive->type = FT_FIL_PRIMITIVE_TYPE_ENGINE;
    PARSE_PRIMITIVE_TYPE_INIT(ftfle);

  } else if (!strcasecmp(lp->word, "tag")) {

    lp->cur_primitive->type = FT_FIL_PRIMITIVE_TYPE_TAG;
    PARSE_PRIMITIVE_TYPE_INIT(ftflt);

    if (!(ftflt->ftch = ftchash_new(4096,
      sizeof (struct ftchash_rec_fil_c32), 4, 12))) {
      fterr_warnx("ftchash_new(): failed");
      return -1;
    }

  } else if (!strcasecmp(lp->word, "tag-mask")) {

    lp->cur_primitive->type = FT_FIL_PRIMITIVE_TYPE_TAG_MASK;
    PARSE_PRIMITIVE_TYPE_INIT(ftfltm);

    FT_STAILQ_INIT(&ftfltm->list);

  } else if (!strcasecmp(lp->word, "time")) {

    lp->cur_primitive->type = FT_FIL_PRIMITIVE_TYPE_TIME;
    PARSE_PRIMITIVE_TYPE_INIT(ftfltme);

    FT_STAILQ_INIT(&ftfltme->list);

  } else if (!strcasecmp(lp->word, "double")) {

    lp->cur_primitive->type = FT_FIL_PRIMITIVE_TYPE_DOUBLE;
    PARSE_PRIMITIVE_TYPE_INIT(ftfld);

    FT_STAILQ_INIT(&ftfld->list);

  } else if (!strcasecmp(lp->word, "rate")) {

    lp->cur_primitive->type = FT_FIL_PRIMITIVE_TYPE_RATE;
    PARSE_PRIMITIVE_TYPE_INIT(ftflr);

    /* initialize random number generator */
    srand(getpid() ^ time((time_t*)0L));

  } else {

    fterr_warnx("%s line %d: Unrecognized type.", lp->fname, lp->lineno);
    return -1;

  } 

  return 0;

} /* parse_primitive_type */

int parse_primitive_permit(struct line_parser *lp, struct ftfil *ftfil)
{
  return parse2_primitive_permitdeny(lp, ftfil, FT_FIL_MODE_PERMIT);
}

int parse_primitive_deny(struct line_parser *lp, struct ftfil *ftfil)
{
  return parse2_primitive_permitdeny(lp, ftfil, FT_FIL_MODE_DENY);
}

static int parse_primitive_default(struct line_parser *lp, struct ftfil *ftfil)
{
  struct ftfil_lookup_ip_address *ftflipa;
  struct ftfil_lookup_ip_prefix *ftflippr;
  struct ftfil_lookup_ip_mask *ftflipm;
  struct ftfil_lookup_as *ftfla;
  struct ftfil_lookup_ip_prefix_len *ftflipl;
  struct ftfil_lookup_ip_prot *ftflipp;
  struct ftfil_lookup_ip_tos *ftflipt;
  struct ftfil_lookup_ip_tcp_flags *ftfliptcp;
  struct ftfil_lookup_if_index *ftflif;
  struct ftfil_lookup_engine *ftfle;
  struct ftfil_lookup_ip_port *ftflippo;
  struct ftfil_lookup_counter *ftflc;
  struct ftfil_lookup_tag *ftflt;
  struct ftfil_lookup_tag_mask *ftfltm;
  struct ftfil_lookup_counter *ftfltme;
  struct ftfil_lookup_counter *ftfld;

  int flag;

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting permit or deny.", lp->fname,
    lp->lineno);
    return -1;
  }

  if (!strcasecmp(lp->word, "permit"))
    flag = FT_FIL_MODE_PERMIT;
  else if (!strcasecmp(lp->word, "deny"))
    flag = FT_FIL_MODE_DENY;
  else {
    fterr_warnx("%s line %d: Expecting permit or deny.", lp->fname,
    lp->lineno);
    return -1;
  }

  switch (lp->cur_primitive->type) {

    case FT_FIL_PRIMITIVE_TYPE_IP_ADDRESS:
      ftflipa = lp->cur_primitive->lookup;
      ftflipa->default_mode = flag;
      break;

    case FT_FIL_PRIMITIVE_TYPE_IP_PREFIX:
      ftflippr = lp->cur_primitive->lookup;
      ftflippr->default_mode = flag;
      break;

    case FT_FIL_PRIMITIVE_TYPE_IP_MASK:
      ftflipm = lp->cur_primitive->lookup;
      ftflipm->default_mode = flag;
      break;

    case FT_FIL_PRIMITIVE_TYPE_AS:
      ftfla = lp->cur_primitive->lookup;
      ftfla->default_mode = flag;
      break;

    case FT_FIL_PRIMITIVE_TYPE_IP_PROTOCOL:
      ftflipp = lp->cur_primitive->lookup;
      ftflipp->default_mode = flag;
      break;

    case FT_FIL_PRIMITIVE_TYPE_IP_PREFIX_LEN:
      ftflipl = lp->cur_primitive->lookup;
      ftflipl->default_mode = flag;
      break;

    case FT_FIL_PRIMITIVE_TYPE_IP_TOS:
      ftflipt = lp->cur_primitive->lookup;
      ftflipt->default_mode = flag;
      break;

    case FT_FIL_PRIMITIVE_TYPE_IP_TCP_FLAGS:
      ftfliptcp = lp->cur_primitive->lookup;
      ftfliptcp->default_mode = flag;
      break;

    case FT_FIL_PRIMITIVE_TYPE_IF_INDEX:
      ftflif = lp->cur_primitive->lookup;
      ftflif->default_mode = flag;
      break;

    case FT_FIL_PRIMITIVE_TYPE_IP_PORT:
      ftflippo = lp->cur_primitive->lookup;
      ftflippo->default_mode = flag;
      break;

    case FT_FIL_PRIMITIVE_TYPE_ENGINE:
      ftfle = lp->cur_primitive->lookup;
      ftfle->default_mode = flag;
      break;

    case FT_FIL_PRIMITIVE_TYPE_TAG:
      ftflt = lp->cur_primitive->lookup;
      ftflt->default_mode = flag;
      break;

    case FT_FIL_PRIMITIVE_TYPE_TAG_MASK:
      ftfltm = lp->cur_primitive->lookup;
      ftfltm->default_mode = flag;
      break;

    case FT_FIL_PRIMITIVE_TYPE_COUNTER:
      ftflc = lp->cur_primitive->lookup;
      ftflc->default_mode = flag;
      break;

    case FT_FIL_PRIMITIVE_TYPE_TIME_DATE:
      ftflc = lp->cur_primitive->lookup;
      ftflc->default_mode = flag;
      break;

    case FT_FIL_PRIMITIVE_TYPE_TIME:
      ftfltme = lp->cur_primitive->lookup;
      ftfltme->default_mode = flag;
      break;

    case FT_FIL_PRIMITIVE_TYPE_DOUBLE:
      ftfld = lp->cur_primitive->lookup;
      ftfld->default_mode = flag;
      break;

    case FT_FIL_PRIMITIVE_TYPE_RATE:
      fterr_warnx("%s line %d: No default mode for rate.", lp->fname,
        lp->lineno);
      break;

    default:
      fterr_errx(1, "parse_primitive_default(): internal error");
      break;

  } /* switch */

  return 0;
  
} /* parse_primitive_default */


/*
 * function: parse2_primitive_permitdeny
 *
 * process the permit and deny lines
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse2_primitive_permitdeny(struct line_parser *lp, struct ftfil *ftfil,
  int mode)
{
  int ret;

  ret = -1;

  if (!lp->cur_primitive) {
    fterr_warnx("%s line %d: Must set type first.", lp->fname, lp->lineno);
    return -1;
  }

  lp->mode = mode;

  NEXT_WORD(&lp->buf, lp->word);
  
  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting permit/deny data.", lp->fname,
    lp->lineno); 
    return -1;
  }

  switch (lp->cur_primitive->type) {

    case FT_FIL_PRIMITIVE_TYPE_AS:
      ret = parse_primitive_type_asn(lp, ftfil);
      break;

    case FT_FIL_PRIMITIVE_TYPE_IP_PREFIX:
      ret = parse_primitive_type_ip_prefix(lp, ftfil);
      break;

    case FT_FIL_PRIMITIVE_TYPE_IP_ADDRESS:
      ret = parse_primitive_type_ip_address(lp, ftfil);
      break;

    case FT_FIL_PRIMITIVE_TYPE_IP_MASK:
      ret = parse_primitive_type_ip_mask(lp, ftfil);
      break;

    case FT_FIL_PRIMITIVE_TYPE_IP_PROTOCOL:
      ret = parse_primitive_type_ip_prot(lp, ftfil);
      break;

    case FT_FIL_PRIMITIVE_TYPE_IP_PORT:
      ret = parse_primitive_type_ip_port(lp, ftfil);
      break;

    case FT_FIL_PRIMITIVE_TYPE_IP_PREFIX_LEN:
      ret = parse_primitive_type_ip_prefix_len(lp, ftfil);
      break;

    case FT_FIL_PRIMITIVE_TYPE_IP_TOS:
      ret = parse_primitive_type_ip_tos(lp, ftfil);
      break;

    case FT_FIL_PRIMITIVE_TYPE_IP_TCP_FLAGS:
      ret = parse_primitive_type_ip_tcp_flags(lp, ftfil);
      break;

    case FT_FIL_PRIMITIVE_TYPE_IF_INDEX:
      ret = parse_primitive_type_if_index(lp, ftfil);
      break;

    case FT_FIL_PRIMITIVE_TYPE_COUNTER:
      ret = parse_primitive_type_counter(lp, ftfil);
      break;

    case FT_FIL_PRIMITIVE_TYPE_TIME_DATE:
      ret = parse_primitive_type_time_date(lp, ftfil);
      break;

    case FT_FIL_PRIMITIVE_TYPE_ENGINE:
      ret = parse_primitive_type_engine(lp, ftfil);
      break;

    case FT_FIL_PRIMITIVE_TYPE_TAG:
      ret = parse_primitive_type_tag(lp, ftfil);
      break;

    case FT_FIL_PRIMITIVE_TYPE_TAG_MASK:
      ret = parse_primitive_type_tag_mask(lp, ftfil);
      break;

    case FT_FIL_PRIMITIVE_TYPE_TIME:
      ret = parse_primitive_type_time(lp, ftfil);
      break;

    case FT_FIL_PRIMITIVE_TYPE_DOUBLE:
      ret = parse_primitive_type_double(lp, ftfil);
      break;

    case FT_FIL_PRIMITIVE_TYPE_RATE:
      ret = parse_primitive_type_rate(lp, ftfil);
      break;

    default:
      fterr_errx(1, "parse_primitive_permitdeny(): internal error");
      break;

  } /* switch */

  return ret;

} /* parse_primitive_permitdeny */

/*
 * function: parse_primitive_mask
 *
 * process the 'mask' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_primitive_mask(struct line_parser *lp, struct ftfil *ftfil)
{

  struct ftfil_lookup_ip_tos *ftflipt;
  struct ftfil_lookup_ip_tcp_flags *ftfliptcp;


  if (!lp->cur_primitive) {
    fterr_warnx("%s line %d: Must set name first.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting mask value.", lp->fname, lp->lineno);
    return -1;
  }

  switch (lp->cur_primitive->type) {

    case FT_FIL_PRIMITIVE_TYPE_IP_TOS:
      ftflipt = lp->cur_primitive->lookup;
      ftflipt->mask = strtoul(lp->word, (char**)0L, 0);
      break;

    case FT_FIL_PRIMITIVE_TYPE_IP_TCP_FLAGS:
      ftfliptcp = lp->cur_primitive->lookup;
      ftfliptcp->mask = strtoul(lp->word, (char**)0L, 0);
      break;

    default:
      fterr_warnx("%s line %d: Mask not supported for primitive.", lp->fname,
        lp->lineno);
      return -1;

  } /* switch */

  return 0;

} /* parse_primitive_mask */

/*
 *************************************************************************
                            internal support
 *************************************************************************
 */

/*
 * function: ftfil_load_lookup
 *
 *  loads a list of , seperated numbers into an array
 *  ! will invert the list
 *  - can be used as a range operator
 *
 *  example
 *   1,5-10   == 1,5,6,7,8,9,10
 *   !1       == all numbers in the range except for 1
 *
 * Only ranges that have been specified will be initialized.
 *
 * The array will either be unset, or set
 * to FT_FL_MODE_PERMIT or FT_FL_MODE_DENY
 */
static int ftfil_load_lookup(struct line_parser *lp, char *s, int size,
  uint8_t *list, int mode)
{
  char *p, *q, *r, c;
  int j, flag;
  unsigned i, i2;
  int permit,deny;
  uint32_t val;

  if (mode == FT_FIL_MODE_DENY) {
    permit = FT_FIL_MODE_DENY;
    deny = FT_FIL_MODE_PERMIT;
  } else if (mode == FT_FIL_MODE_PERMIT) {
    permit = FT_FIL_MODE_PERMIT;
    deny = FT_FIL_MODE_DENY;
  } else {
    fterr_errx(1, "ftfil_load_lookup(): internal error mode not set");
  }

  p = s;

  while ((*p == ' ') || (*p == '\t')) ++p;
  if (*p == '!') {
    flag = deny;
    ++p;
  } else {
    flag = permit;
  }

  while (*p) {

    /* skip white space */
    for (q = p; *q && (*q == ' ' || *q == '\t'); ++q);

    /* skip to the end of the word */
    for (r = q; *r && (*r != ',' && *r != '-'); ++r);

    /* save the character */
    c = *r;

    /* q is the null terminated word now */
    *r = 0;

    /* looks like a symbol? then try a lookup */
    if (isalpha((int)*q)) {
      if (lp->sym_cur && ftsym_findbyname(lp->sym_cur, q, &val))
        i = val;
      else {
        fterr_warnx("%s line %d: symbol lookup for \"%s\" failed.", lp->fname,
          lp->lineno, q);
        return -1;
      }
    } else
      i = (unsigned)strtoul(q, (char**)0L, 0);

    if (i >= size) {
      fterr_warnx("%s line %d: Value out of range.", lp->fname, lp->lineno);
      return -1;
    }

    if (list[i] != FT_FIL_MODE_UNSET)
      fterr_warnx("%s line %d: index %u previously set as %s.", lp->fname,
        lp->lineno, i, mode_name_lookup[list[i]]);
      
    list[i] = flag;

    /* if the next char was a null terminator, then done */
    if (!c)
      break;

    /* skip to next word */
    p = r+1;

    if (c == '-') {

      /* skip white space */
      for (q = p; *q && (*q == ' ' || *q == '\t'); ++q);

      /* skip to the end of the word */
      for (r = q; *r && (*r != ',' && *r != '-'); ++r);
  
      /* save the character */
      c = *r;
  
      /* q is the null terminated word now */
      *r = 0;

      /* looks like a symbol? then try a lookup */
      if (isalpha((int)*q)) {
        if (lp->sym_cur && ftsym_findbyname(lp->sym_cur, q, &val))
          i2 = val;
        else {
          fterr_warnx("%s line %d: symbol lookup for \"%s\" failed.", lp->fname,
            lp->lineno, q);
          return -1;
        }
      } else
        i2 = (unsigned)strtoul(q, (char**)0L, 0);

      if (i2 >= size) {
        fterr_warnx("%s line %d: Value out of range.", lp->fname, lp->lineno);
        return -1;
      }

      for (j = i; j <= i2; ++j) {

        if ((j != i) && (list[j] != FT_FIL_MODE_UNSET))
          fterr_warnx("%s line %d: index %u previously set as %s.", lp->fname,
            lp->lineno, j, mode_name_lookup[list[j]]);

        list[j] = flag;

      }

      /* skip to next word */
      p = r+1;

      /* if the next char was a null terminator, then done */
      if (!c)
        break;

    }

  } /* *p */

  return 0;

} /* ftfil_load_lookup */

static int walk_free(struct radix_node *rn, struct walkarg *UNUSED)
{
  struct ftfil_lookup_ip_prefix_rec *r;
  struct radix_sockaddr_in sock1, sock2;

  r = (struct ftfil_lookup_ip_prefix_rec*)rn;
  bzero(&sock1, sizeof sock1);
  bzero(&sock2, sizeof sock2);

  sock1.sin_addr.s_addr = r->addr.sin_addr.s_addr;
  sock1.sin_len = sizeof sock1;
  sock1.sin_family = AF_INET;

  sock2.sin_addr.s_addr = (!r->masklen) ? 0: mask_lookup[r->masklen];
  sock2.sin_len = sizeof sock2;
  sock2.sin_family = AF_INET;

  if (r != (struct ftfil_lookup_ip_prefix_rec*)rhead->rnh_deladdr(&sock1,
    &sock2, rhead))
    fterr_errx(1, "rn_deladdr(): failed.");
  else
    free(r);

  return 0;
} /* walk_free */
