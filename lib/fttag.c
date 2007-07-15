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
 *      $Id: fttag.c,v 1.19 2004/01/05 17:55:37 maf Exp $
 */

#include "ftconfig.h"
#include "ftlib.h"

#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
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

extern int max_keylen;
extern u_int32 mask_lookup[];

static struct radix_node_head *rhead;

struct line_parser {
  struct fttag_action *cur_action;
  struct fttag_def *cur_def;
  struct fttag_def_term *cur_def_term;
  int state, type;
  int lineno;
  char *buf, *fname;
};

#define FT_TAG_OR_SRCDST (FT_TAG_OR_SRC_TAG|FT_TAG_OR_DST_TAG)
#define FT_TAG_SET_SRCDST (FT_TAG_SET_SRC_TAG|FT_TAG_SET_DST_TAG)

static int parse_action(struct line_parser *lp, struct fttag *fttag);
static int parse_action_type(struct line_parser *lp, struct fttag *fttag);
static int parse_action_match(struct line_parser *lp, struct fttag *fttag);
static int parse_def(struct line_parser *lp, struct fttag *fttag);
static int parse_def_exporter(struct line_parser *lp, struct fttag *fttag);
static int parse_def_term(struct line_parser *lp, struct fttag *fttag);
static int parse_def_input_filter(struct line_parser *lp, struct fttag *fttag);
static int parse_def_output_filter(struct line_parser *lp, struct fttag *fttag);
static int parse_def_action(struct line_parser *lp, struct fttag *fttag);
static int resolve_actions(struct fttag *fttag);
  
static int walk_free(struct radix_node *rn, struct walkarg *UNUSED);

static inline void eval_match_src_as(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_dst_as(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_src_prefix(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_dst_prefix(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_nexthop(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_as(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_prefix(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_tcp_src_port(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_tcp_dst_port(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_tcp_port(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_udp_src_port(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_udp_dst_port(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_udp_port(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_tos(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_any(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_in_interface(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_out_interface(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_interface(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_exporter(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_src_ip(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_dst_ip(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);
static inline void eval_match_ip(struct fttag_action *fta, 
  struct fts3rec_v1005 *rec);

#define PARSE_STATE_ACTION          0x1
#define PARSE_STATE_DEFINITION      0x2

#define NEXT_WORD(A,B)\
  for (;;) {\
    B = strsep(A, " \t");\
    if ((B && *B != 0) || (!B))\
      break;\
  }\
 
struct jump {
  char *name;
  int state;
  int (*func)(struct line_parser *lp, struct fttag *fttag);
};

static struct jump pjump[] = {{"tag-action", 0, parse_action},
          {"type", PARSE_STATE_ACTION, parse_action_type},
          {"match", PARSE_STATE_ACTION, parse_action_match},
          {"tag-definition", 0, parse_def},
          {"exporter", PARSE_STATE_DEFINITION, parse_def_exporter},
          {"term", PARSE_STATE_DEFINITION, parse_def_term},
          {"input-filter", PARSE_STATE_DEFINITION, parse_def_input_filter},
          {"output-filter", PARSE_STATE_DEFINITION, parse_def_output_filter},
          {"action", PARSE_STATE_DEFINITION, parse_def_action},
          {0, 0, 0},
          };
/*
 * data structures:
 *
 *
 * fttag holds the head pointers to a list of actions, and definitions.
 *
 * Each definition holds a list of terms.  A term is a combination of
 * an input filter, output filter and list of actions.
 *
 * struct fttag_def               : linked list of definitions
 * struct fttag_action            : linked list of actions
 * struct fttag_def_term          : each term in a definition
 * struct fttag_def_term_actions  : each action in a term
 *
 * actions contain one of the following:
 *
 * struct fttag_prefix_look              : prefix radix trie lookup entry
 * struct fttag_as_look                  : AS table lookup
 * struct fttag_port_look                : port table lookup
 * struct fttag_tos_look                 : tos table lookup
 * struct fttag_next_hop_look            : next hop hash lookup entry
 * struct fttag_interface_look           : interface table lookup entry
 * struct fttag_exporter                 : exporter hash lookup entry
 * struct fttag_ip_look                  : IP address hash lookup entry
 *
 * struct fftag_exp_hash                 : hash table mapping exporter_ip
 *                                         to list of definitions.  Used
 *                                         when processing flows.  ie, lookup
 *                                         by exporter, test input/output
 *                                         filter then use action to add
 *                                         tags.
 *
 */


/*
 * function: fttag_load
 *
 * Process fname into fttag.
 *
 * returns: 0  ok
 *          <0 fail
 */
int fttag_load(struct fttag *fttag, struct ftvar *ftvar, char *fname)
{
  static int rn_init_called;
  struct stat sb;
  struct jump *jmp;
  struct line_parser lp;
  int fd, ret, found;
  char *buf, *buf2, *c;
  char sbuf[FT_LP_MAXLINE];

  ret = -1;
  buf = (char*)0L;
  bzero(&lp, sizeof lp);
  bzero(fttag, sizeof *fttag);

  if (!rn_init_called) {
    max_keylen = sizeof(struct radix_sockaddr_in);
    rn_init();
    rn_init_called = 1;
  }

  FT_SLIST_INIT(&fttag->defs);
  FT_SLIST_INIT(&fttag->actions);

  lp.fname = fname;

  if ((fd = open(fname, O_RDONLY, 0)) < 0) {
    fterr_warn("open(%s)", fname);
    goto load_tags_out;
  }

  if (fstat(fd, &sb) < 0) {
    fterr_warn("stat(%s)", fname);
    goto load_tags_out;
  }
  
  /* allocate storage for file */
  if (!(buf = malloc(sb.st_size+1))) {
    fterr_warn("malloc()");
    goto load_tags_out;
  }

  /* read in file */
  if (read(fd, buf, sb.st_size) != sb.st_size) {
    fterr_warnx("read(%s): short", fname);
    goto load_tags_out;
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
      goto load_tags_done;
    }

    /* do variable substitutions first */
    if (ftvar) {
      if (ftvar_evalstr(ftvar, c, sbuf, sizeof(sbuf)) < 0) {
        fterr_warnx("ftvar_evalstr(): failed");
        goto load_tags_done;
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

        if (jmp->func(&lp, fttag))
          goto load_tags_out;

        NEXT_WORD(&lp.buf, c);

        if (c) {
          fterr_warnx("%s line %d: Unexpected \"%s\".", lp.fname, lp.lineno, c);
          goto load_tags_out;
        }

        break;

      }

    } /* test each word */

    if (!found) {
      fterr_warnx("%s line %d: Unexpected \"%s\".", lp.fname, lp.lineno, c);
      goto load_tags_out;
    }
   
  } /* more lines */

load_tags_done:

  if (resolve_actions(fttag))
    goto load_tags_out;

  ret = 0;

load_tags_out:

  if (fd != -1)
    close(fd);

  if (buf)
    free(buf);

  if (ret == -1)
    fttag_free(fttag);

  return ret;

} /* fttag_load */

/*
 * function: fttag_defintion_find
 *
 * Return a pointer to a fttag_def_lookup for use later with
 * fttag_def_eval
 *
 * Note this allocates storage and precomputes a hash table
 * to speed up the eval phase.  Storage is freed by fttag_free()
 *
 * returns : pointer to fttag_def_lookup or null if not found or error.
 *
 */
struct fttag_def *fttag_def_find(struct fttag *fttag, char *name)
{
  struct fttag_def *ftd;

  /* foreach definition */
  FT_SLIST_FOREACH(ftd, &fttag->defs, chain) {

    if (!(strcasecmp(ftd->name, name))) 
      return ftd;

  }

  return (struct fttag_def*)0L;

} /* fttag_def_find */

/*
 * function: parse_action
 *
 * process the 'action' line.  Each action has a unique name which
 * is added to the fttag->actions linked list.  The current action is
 * updated in lp.  Actions by themself do nothing, they must be pointed
 * to by a definition.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_action(struct line_parser *lp, struct fttag *fttag)
{
  char *c;
  struct fttag_action *fta;

  NEXT_WORD(&lp->buf, c);

  if (!c) {
    fterr_warnx("%s line %d: Expecting name.", lp->fname, lp->lineno);
    return -1;
  }

  /* check if it exists */
  FT_SLIST_FOREACH(fta, &fttag->actions, chain) {

    if (!strcasecmp(c, fta->name)) {
      fterr_warnx("%s line %d: Name (%s) previously defined.", lp->fname,
        lp->lineno, c);
      return -1;
    }

  }

  /* no, add a new entry to the list */
  if (!(fta = (struct fttag_action*)malloc(sizeof (struct fttag_action)))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(fta, sizeof *fta);

  if (!(fta->name = (char*)malloc(strlen(c)+1))) {
    fterr_warn("malloc()");
    free(fta);
    return -1;
  }

  strcpy(fta->name, c);

  FT_SLIST_INSERT_HEAD(&fttag->actions, fta, chain);

  lp->state = PARSE_STATE_ACTION;
  lp->cur_action = fta;

  return 0;

} /* parse_action */

/*
 * function: parse_action_type
 *
 * process the 'type' line.  When the type is set the initial storage
 * (table/hash/radix trie) is allocated.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_action_type(struct line_parser *lp, struct fttag *fttag)
{
  char *c;

  if (!lp->cur_action) {
    fterr_warnx("%s line %d: Must set name first.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, c);

  if (!c) {
    fterr_warnx("%s line %d: Expecting type.", lp->fname, lp->lineno);
    return -1;
  }

  if (lp->cur_action->type) {
    fterr_warnx("%s line %d: Type previously defined.", lp->fname, lp->lineno);
    return -1;
  }

  if (!strcasecmp(c, "src-prefix")) {
    lp->cur_action->type = FT_TAG_TYPE_MATCH_SRC_PREFIX;
    lp->cur_action->eval = eval_match_src_prefix;
  } else if (!strcasecmp(c, "source-prefix")) {
      lp->cur_action->type = FT_TAG_TYPE_MATCH_SRC_PREFIX;
      lp->cur_action->eval = eval_match_src_prefix;
  } else if (!strcasecmp(c, "dst-prefix")) {
      lp->cur_action->type = FT_TAG_TYPE_MATCH_DST_PREFIX;
      lp->cur_action->eval = eval_match_dst_prefix;
  } else if (!strcasecmp(c, "destination-prefix")) {
      lp->cur_action->type = FT_TAG_TYPE_MATCH_DST_PREFIX;
      lp->cur_action->eval = eval_match_dst_prefix;
  } else if (!strcasecmp(c, "prefix")) {
      lp->cur_action->eval = eval_match_prefix;
      lp->cur_action->type = FT_TAG_TYPE_MATCH_PREFIX;
  } else if (!strcasecmp(c, "next-hop")) {
      lp->cur_action->eval = eval_match_nexthop;
      lp->cur_action->type = FT_TAG_TYPE_MATCH_NEXTHOP;
  } else if (!strcasecmp(c, "src-as")) {
      lp->cur_action->type = FT_TAG_TYPE_MATCH_SRC_AS;
      lp->cur_action->eval = eval_match_src_as;
  } else if (!strcasecmp(c, "source-as")) {
      lp->cur_action->type = FT_TAG_TYPE_MATCH_SRC_AS;
      lp->cur_action->eval = eval_match_src_as;
  } else if (!strcasecmp(c, "dst-as")) {
      lp->cur_action->type = FT_TAG_TYPE_MATCH_DST_AS;
      lp->cur_action->eval = eval_match_dst_as;
  } else if (!strcasecmp(c, "destination-as")) {
      lp->cur_action->type = FT_TAG_TYPE_MATCH_DST_AS;
      lp->cur_action->eval = eval_match_dst_as;
  } else if (!strcasecmp(c, "as")) {
      lp->cur_action->eval = eval_match_as;
      lp->cur_action->type = FT_TAG_TYPE_MATCH_AS;
  } else if (!strcasecmp(c, "tcp-src-port")) {
      lp->cur_action->type = FT_TAG_TYPE_MATCH_SRC_TCP_PORT;
      lp->cur_action->eval = eval_match_tcp_src_port;
  } else if (!strcasecmp(c, "tcp-source-port")) {
      lp->cur_action->type = FT_TAG_TYPE_MATCH_SRC_TCP_PORT;
      lp->cur_action->eval = eval_match_tcp_src_port;
  } else if (!strcasecmp(c, "tcp-dst-port")) {
      lp->cur_action->type = FT_TAG_TYPE_MATCH_DST_TCP_PORT;
      lp->cur_action->eval = eval_match_tcp_dst_port;
  } else if (!strcasecmp(c, "tcp-destination-port")) {
      lp->cur_action->type = FT_TAG_TYPE_MATCH_DST_TCP_PORT;
      lp->cur_action->eval = eval_match_tcp_dst_port;
  } else if (!strcasecmp(c, "tcp-port")) {
      lp->cur_action->eval = eval_match_tcp_port;
      lp->cur_action->type = FT_TAG_TYPE_MATCH_TCP_PORT;
  } else if (!strcasecmp(c, "udp-src-port")) {
      lp->cur_action->type = FT_TAG_TYPE_MATCH_SRC_UDP_PORT;
      lp->cur_action->eval = eval_match_udp_src_port;
  } else if (!strcasecmp(c, "udp-source-port")) {
      lp->cur_action->type = FT_TAG_TYPE_MATCH_SRC_UDP_PORT;
      lp->cur_action->eval = eval_match_udp_src_port;
  } else if (!strcasecmp(c, "udp-dst-port")) {
      lp->cur_action->type = FT_TAG_TYPE_MATCH_DST_UDP_PORT;
      lp->cur_action->eval = eval_match_udp_dst_port;
  } else if (!strcasecmp(c, "udp-destination-port")) {
      lp->cur_action->type = FT_TAG_TYPE_MATCH_DST_UDP_PORT;
      lp->cur_action->eval = eval_match_udp_dst_port;
  } else if (!strcasecmp(c, "udp-port")) {
      lp->cur_action->eval = eval_match_udp_port;
      lp->cur_action->type = FT_TAG_TYPE_MATCH_TCP_PORT;
  } else if (!strcasecmp(c, "tos")) {
      lp->cur_action->eval = eval_match_tos;
      lp->cur_action->type = FT_TAG_TYPE_MATCH_TOS;
  } else if (!strcasecmp(c, "any")) {
      lp->cur_action->eval = eval_match_any;
      lp->cur_action->type = FT_TAG_TYPE_MATCH_ANY;
  } else if (!strcasecmp(c, "src-ip")) {
      lp->cur_action->eval = eval_match_src_ip;
      lp->cur_action->type = FT_TAG_TYPE_MATCH_SRC_IP;
  } else if (!strcasecmp(c, "source-ip-address")) {
      lp->cur_action->eval = eval_match_src_ip;
      lp->cur_action->type = FT_TAG_TYPE_MATCH_SRC_IP;
  } else if (!strcasecmp(c, "dst-ip")) {
      lp->cur_action->eval = eval_match_dst_ip;
      lp->cur_action->type = FT_TAG_TYPE_MATCH_DST_IP;
  } else if (!strcasecmp(c, "destination-ip-address")) {
      lp->cur_action->eval = eval_match_dst_ip;
      lp->cur_action->type = FT_TAG_TYPE_MATCH_DST_IP;
  } else if (!strcasecmp(c, "ip")) {
      lp->cur_action->eval = eval_match_ip;
      lp->cur_action->type = FT_TAG_TYPE_MATCH_IP;
  } else if (!strcasecmp(c, "exporter")) {
      lp->cur_action->eval = eval_match_exporter;
      lp->cur_action->type = FT_TAG_TYPE_MATCH_EXPORTER;
  } else if (!strcasecmp(c, "input-interface")) {
      lp->cur_action->eval = eval_match_in_interface;
      lp->cur_action->type = FT_TAG_TYPE_MATCH_IN_INTERFACE;
  } else if (!strcasecmp(c, "output-interface")) {
      lp->cur_action->eval = eval_match_out_interface;
      lp->cur_action->type = FT_TAG_TYPE_MATCH_OUT_INTERFACE;
  } else if (!strcasecmp(c, "interface")) {
      lp->cur_action->eval = eval_match_interface;
      lp->cur_action->type = FT_TAG_TYPE_MATCH_INTERFACE;
  } else {
    fterr_warnx("%s line %d: Unrecognized type.", lp->fname, lp->lineno);
    return -1;
  } 

  /* allocate storage for lookup */

  if ((lp->cur_action->type & FT_TAG_TYPE_MATCH_AS)) {

    if (!(lp->cur_action->look = malloc(sizeof (struct fttag_as_look)))) {
      fterr_warn("malloc()");
      return -1;
    }

    bzero(lp->cur_action->look, sizeof (struct fttag_as_look));

  } else if (lp->cur_action->type & FT_TAG_TYPE_MATCH_TOS) {

    if (!(lp->cur_action->look = malloc(sizeof (struct fttag_tos_look)))) {
      fterr_warn("malloc()");
      return -1;
    }

    bzero(lp->cur_action->look, sizeof (struct fttag_tos_look));

  } else if (lp->cur_action->type & FT_TAG_TYPE_MATCH_ANY) {

    if (!(lp->cur_action->look = malloc(sizeof (struct fttag_any_look)))) {
      fterr_warn("malloc()");
      return -1;
    }

    bzero(lp->cur_action->look, sizeof (struct fttag_any_look));

  } else if (lp->cur_action->type &
    (FT_TAG_TYPE_MATCH_TCP_PORT|FT_TAG_TYPE_MATCH_UDP_PORT)) {

    if (!(lp->cur_action->look = malloc(sizeof (struct fttag_port_look)))) {
      fterr_warn("malloc()");
      return -1;
    }

    bzero(lp->cur_action->look, sizeof (struct fttag_port_look));

  } else if (lp->cur_action->type & FT_TAG_TYPE_MATCH_PREFIX) {

    if (rn_inithead((void**)&lp->cur_action->look, 32) < 0) {
      fterr_warnx("rn_inithead(): failed");
      return -1;
    }

  } else if (lp->cur_action->type & FT_TAG_TYPE_MATCH_NEXTHOP) {

    if (!(lp->cur_action->look = ftchash_new(256, sizeof
      (struct fttag_next_hop_look), 4, 16))) {
      fterr_warnx("ftchash_new(): failed");
      return -1;
    }

  } else if (lp->cur_action->type & FT_TAG_TYPE_MATCH_EXPORTER) {

    if (!(lp->cur_action->look = ftchash_new(256, sizeof
      (struct fttag_exporter_look), 4, 16))) {
      fterr_warnx("ftchash_new(): failed");
      return -1;
    }

  } else if (lp->cur_action->type & FT_TAG_TYPE_MATCH_IP) {

    if (!(lp->cur_action->look = ftchash_new(256, sizeof
      (struct fttag_ip_look), 4, 16))) {
      fterr_warnx("ftchash_new(): failed");
      return -1;
    }

  } else if (lp->cur_action->type & FT_TAG_TYPE_MATCH_INTERFACE) {

    if (!(lp->cur_action->look = malloc(sizeof (struct fttag_interface_look)))) {
      fterr_warn("malloc()");
      return -1;
    }

    bzero(lp->cur_action->look, sizeof (struct fttag_interface_look));
  }

  return 0;

} /* parse_action_type */

/*
 * function: parse_action_match
 *
 * process the 'match/set' line.  The match action depends on the type which
 * must be configured first.  An AS match is added to a table, a next-hop
 * is added to a hash (chash_*) and a prefix is added to a radix trie, etc.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_action_match(struct line_parser *lp, struct fttag *fttag)
{
  struct radix_sockaddr_in sock1, sock2;
  struct fttag_as_look *as_look;
  struct fttag_next_hop_look *nh_look, nh_look2;
  struct fttag_prefix_look *prefix_look;
  struct fttag_port_look *port_look;
  struct fttag_tos_look *tos_look;
  struct fttag_interface_look *interface_look;
  struct fttag_exporter_look *exporter_look, exporter_look2;
  struct fttag_ip_look *ip_look, ip_look2;
  struct fttag_any_look *any_look;
  struct ip_prefix ipp;
  struct radix_node_head *rhead;
  u_int32 tag, hash, ipaddr;
  u_int16 as, port, interface;
  u_int8 tos;
  int sflag, new, tflag2, tmpflag, tflag;
  char *c, *match;

  if (!lp->cur_action->type) {
    fterr_warnx("%s line %d: Must set type first.", lp->fname, lp->lineno);
    return -1;
  }

  bzero(&sock1, sizeof sock1);
  bzero(&sock2, sizeof sock2);

  sock1.sin_family = AF_INET;
  sock1.sin_len = sizeof (struct radix_sockaddr_in);

  sock2.sin_family = AF_INET;
  sock2.sin_len = sizeof (struct radix_sockaddr_in);

  as_look = lp->cur_action->look;
  nh_look = lp->cur_action->look;
  prefix_look = lp->cur_action->look;
  port_look = lp->cur_action->look;
  tos_look = lp->cur_action->look;
  any_look = lp->cur_action->look;
  interface_look = lp->cur_action->look;
  ip_look = lp->cur_action->look;
  exporter_look = lp->cur_action->look;

  NEXT_WORD(&lp->buf, c);

  if (!c) {
    fterr_warnx("%s line %d: Expecting match data.", lp->fname, lp->lineno);
    return -1;
  }

  match = c;

  NEXT_WORD(&lp->buf, c);

  if (!c) {
    fterr_warnx("%s line %d: Expecting [set|or]-[source|destination].",
    lp->fname, lp->lineno);
    return -1;
  }

  if (!strcasecmp(c, "set-src")) {
    sflag = FT_TAG_SET_SRC_TAG;
    tflag = FT_TAG_SET_SRC_TAG;
    tflag2 = FT_TAG_OR_SRC_TAG;
  } else if (!strcasecmp(c, "set-source")) {
    sflag = FT_TAG_SET_SRC_TAG;
    tflag = FT_TAG_SET_SRC_TAG;
    tflag2 = FT_TAG_OR_SRC_TAG;
  } else if (!strcasecmp(c, "set-dst")) {
    sflag = FT_TAG_SET_DST_TAG;
    tflag = FT_TAG_SET_DST_TAG;
    tflag2 = FT_TAG_OR_DST_TAG;
  } else if (!strcasecmp(c, "set-destination")) {
    sflag = FT_TAG_SET_DST_TAG;
    tflag = FT_TAG_SET_DST_TAG;
    tflag2 = FT_TAG_OR_DST_TAG;
  } else if (!strcasecmp(c, "or-src")) {
    sflag = FT_TAG_OR_SRC_TAG;
    tflag = FT_TAG_SET_SRC_TAG;
    tflag2 = 0;
  } else if (!strcasecmp(c, "or-source")) {
    sflag = FT_TAG_OR_SRC_TAG;
    tflag = FT_TAG_SET_SRC_TAG;
    tflag2 = 0;
  } else if (!strcasecmp(c, "or-dst")) {
    sflag = FT_TAG_OR_DST_TAG;
    tflag = FT_TAG_SET_DST_TAG;
    tflag2 = 0;
  } else if (!strcasecmp(c, "or-destination")) {
    sflag = FT_TAG_OR_DST_TAG;
    tflag = FT_TAG_SET_DST_TAG;
    tflag2 = 0;
  } else {
    fterr_warnx("%s line %d: Expecting [set|or]-[source|destination].",
    lp->fname, lp->lineno);
    return -1;
  }


/*
 * The data structure allows one SET or multiple OR's per
 * source/destination tag.  Enforce this in the config parser
 *
 *         Error conditions
 *        current     sflag
 *      ------------------------
 *       SET_SRC and SET_SRC
 *       SET_DST and SET_DST
 *            or
 *       SET_SRC and OR_SRC
 *       SET_DST and OR_DST
 *            or
 *       OR_SRC and  SET_SRC
 *       OR_DST and  SET_DST
*/

  NEXT_WORD(&lp->buf, c);

  if (!c) {
    fterr_warnx("%s line %d: Expecting set data.", lp->fname, lp->lineno);
    return -1;
  }

  tag = strtoul(c, (char **)0L, 0);

  if (lp->cur_action->type & FT_TAG_TYPE_MATCH_AS) {

    as = atoi(match);

    tmpflag = as_look->set_flags_lookup[as];

    if (((tmpflag & FT_TAG_SET_SRCDST) & tflag) ||
       ((tmpflag & FT_TAG_OR_SRCDST) & tflag2)) {
      fterr_warnx(
        "%s line %d: Only one set per source/destination per match.",
        lp->fname, lp->lineno);
      return -1;
    }

    as_look->set_flags_lookup[as] |= sflag;

    if (sflag & FT_TAG_SET_SRC_TAG)
      as_look->src_tag_lookup[as] = tag;

    if (sflag & FT_TAG_OR_SRC_TAG)
      as_look->src_tag_lookup[as] |= tag;

    if (sflag & FT_TAG_SET_DST_TAG)
      as_look->dst_tag_lookup[as] = tag;
  
    if (sflag & FT_TAG_OR_DST_TAG)
      as_look->dst_tag_lookup[as] |= tag;

  } else if (lp->cur_action->type & FT_TAG_TYPE_MATCH_INTERFACE) {

    interface = atoi(match);

    tmpflag = interface_look->set_flags_lookup[interface];

    if (((tmpflag & FT_TAG_SET_SRCDST) & tflag) ||
       ((tmpflag & FT_TAG_OR_SRCDST) & tflag2)) {
      fterr_warnx(
        "%s line %d: Only one set per source/destination per match.",
        lp->fname, lp->lineno);
      return -1;
    }

    interface_look->set_flags_lookup[interface] |= sflag;

    if (sflag & FT_TAG_SET_SRC_TAG)
      interface_look->src_tag_lookup[interface] = tag;

    if (sflag & FT_TAG_OR_SRC_TAG)
      interface_look->src_tag_lookup[interface] |= tag;
  
    if (sflag & FT_TAG_SET_DST_TAG)
      interface_look->dst_tag_lookup[interface] = tag;
  
    if (sflag & FT_TAG_OR_DST_TAG)
      interface_look->dst_tag_lookup[interface] |= tag;


  } else if (lp->cur_action->type &
    (FT_TAG_TYPE_MATCH_TCP_PORT|FT_TAG_TYPE_MATCH_UDP_PORT)) {

    port = atoi(match);

    tmpflag = port_look->set_flags_lookup[port];

    if (((tmpflag & FT_TAG_SET_SRCDST) & tflag) ||
       ((tmpflag & FT_TAG_OR_SRCDST) & tflag2)) {
      fterr_warnx(
        "%s line %d: Only one set per source/destination per match.",
        lp->fname, lp->lineno);
      return -1;
    }

    port_look->set_flags_lookup[port] |= sflag;

    if (sflag & FT_TAG_SET_SRC_TAG)
      port_look->src_tag_lookup[port] = tag;

    if (sflag & FT_TAG_OR_SRC_TAG)
      port_look->src_tag_lookup[port] |= tag;
  
    if (sflag & FT_TAG_SET_DST_TAG)
      port_look->dst_tag_lookup[port] = tag;
  
    if (sflag & FT_TAG_OR_DST_TAG)
      port_look->dst_tag_lookup[port] |= tag;

  } else if (lp->cur_action->type & FT_TAG_TYPE_MATCH_TOS) {

    tos = atoi(match);

    tmpflag = tos_look->set_flags_lookup[tos];

    if (((tmpflag & FT_TAG_SET_SRCDST) & tflag) ||
       ((tmpflag & FT_TAG_OR_SRCDST) & tflag2)) {
      fterr_warnx(
        "%s line %d: Only one set per source/destination per match.",
        lp->fname, lp->lineno);
      return -1;
    }

    tos_look->set_flags_lookup[tos] |= sflag;

    if (sflag & FT_TAG_SET_SRC_TAG)
      tos_look->src_tag_lookup[tos] = tag;

    if (sflag & FT_TAG_OR_SRC_TAG)
      tos_look->src_tag_lookup[tos] |= tag;

    if (sflag & FT_TAG_SET_DST_TAG)
      tos_look->dst_tag_lookup[tos] = tag;

    if (sflag & FT_TAG_OR_DST_TAG)
      tos_look->dst_tag_lookup[tos] |= tag;

  } else if (lp->cur_action->type & FT_TAG_TYPE_MATCH_ANY) {

    if (strcasecmp(match, "any")) {
      fterr_warnx("%s line %d: Match must be any.", lp->fname, lp->lineno);
      return -1;
    }

    tmpflag = any_look->set_flags;

    if (((tmpflag & FT_TAG_SET_SRCDST) & tflag) ||
       ((tmpflag & FT_TAG_OR_SRCDST) & tflag2)) {
      fterr_warnx(
        "%s line %d: Only one set per source/destination per match.",
        lp->fname, lp->lineno);
      return -1;
    }

    any_look->set_flags |= sflag;

    if (sflag & FT_TAG_SET_SRC_TAG)
      any_look->src_tag = tag;

    if (sflag & FT_TAG_OR_SRC_TAG)
      any_look->src_tag |= tag;

    if (sflag & FT_TAG_SET_DST_TAG)
      any_look->dst_tag = tag;

    if (sflag & FT_TAG_OR_DST_TAG)
      any_look->dst_tag |= tag;

  } else if (lp->cur_action->type & FT_TAG_TYPE_MATCH_PREFIX) {

    ipp = scan_ip_prefix(match);
    sock1.sin_addr.s_addr = ipp.addr;
    sock2.sin_addr.s_addr = (!ipp.len) ? 0 : mask_lookup[ipp.len];

    rhead = lp->cur_action->look;

    /* try to retrieve from trie */
    prefix_look = (struct fttag_prefix_look*)rhead->rnh_lookup(&sock1,
    &sock2, rhead);

    new = 1;

    /* if it exists, make sure not a duplicate set */
    if (prefix_look && (prefix_look->addr.sin_addr.s_addr == ipp.addr) && 
       (prefix_look->masklen == ipp.len)) {

      tmpflag = prefix_look->set_flags;

      if (((tmpflag & FT_TAG_SET_SRCDST) & tflag) ||
         ((tmpflag & FT_TAG_OR_SRCDST) & tflag2)) {
        fterr_warnx(
          "%s line %d: Only one set per source/destination per match.",
          lp->fname, lp->lineno);
        return -1;
      } else {
        new = 0;
      }

    }

    /* allocate a new prefix lookup */
    if (new) {

      if (!(prefix_look = (struct fttag_prefix_look*)malloc(sizeof
        (struct fttag_prefix_look)))) {
        fterr_warn("malloc(prefix_look)");
        return -1;
      }

      bzero(prefix_look, sizeof *prefix_look);

      prefix_look->rt_nodes->rn_key = (caddr_t)&prefix_look->addr;

      prefix_look->addr.sin_addr.s_addr = ipp.addr;
      prefix_look->addr.sin_len = sizeof (struct radix_sockaddr_in);
      prefix_look->addr.sin_family = AF_INET;

      sock1.sin_addr.s_addr = (!ipp.len) ? 0 : mask_lookup[ipp.len];

      prefix_look->masklen = ipp.len;

      /* add it to the trie */
      if (!rhead->rnh_addaddr(&prefix_look->addr, &sock1, rhead,
        prefix_look->rt_nodes)) {
        free(prefix_look);
        fterr_warnx("rnh_addaddr(): failed for %s",match);
        return -1;
      }

    } /* new */

    /* finish filling in */

    prefix_look->set_flags |= sflag;

    if (sflag & FT_TAG_SET_SRC_TAG)
      prefix_look->src_tag = tag;
        
    if (sflag & FT_TAG_OR_SRC_TAG)
      prefix_look->src_tag |= tag;
      
    if (sflag & FT_TAG_SET_DST_TAG)
      prefix_look->dst_tag = tag;
      
    if (sflag & FT_TAG_OR_DST_TAG)
      prefix_look->dst_tag |= tag;


  } else if (lp->cur_action->type & FT_TAG_TYPE_MATCH_NEXTHOP) {

    ipaddr = scan_ip(match);

    hash = (ipaddr>>16) ^ (ipaddr & 0xFFFF);
    hash = (hash>>8) ^ (hash & 0xFF);

    nh_look = ftchash_lookup(lp->cur_action->look, &ipaddr, hash);

    new = 1;

    /* if it exists, make sure not a duplicate set */
    if (nh_look) {

      tmpflag = nh_look->set_flags;

      if (((tmpflag & FT_TAG_SET_SRCDST) & tflag) ||
         ((tmpflag & FT_TAG_OR_SRCDST) & tflag2)) {
        fterr_warnx(
          "%s line %d: Only one set per source/destination per match.",
          lp->fname, lp->lineno);
        return -1;
      } else {
        new = 0;
      }

    }

    if (new) {

      bzero(&nh_look2, sizeof nh_look2);

      nh_look2.addr = ipaddr;

      if (!(nh_look = ftchash_update(lp->cur_action->look, &nh_look2, hash))) {
        fterr_warnx("ftch_update(): failed");
        return -1;
      }

    }

    /* finish filling in fields */

    nh_look->set_flags |= sflag;

    if (sflag & FT_TAG_SET_SRC_TAG)
      nh_look->src_tag = tag;
    
    if (sflag & FT_TAG_OR_SRC_TAG)
      nh_look->src_tag |= tag;

    if (sflag & FT_TAG_SET_DST_TAG)
      nh_look->dst_tag = tag;

    if (sflag & FT_TAG_OR_DST_TAG)
      nh_look->dst_tag |= tag;

  } else if (lp->cur_action->type & FT_TAG_TYPE_MATCH_EXPORTER) {

    ipaddr = scan_ip(match);

    hash = (ipaddr>>16) ^ (ipaddr & 0xFFFF);
    hash = (hash>>8) ^ (hash & 0xFF);

    exporter_look = ftchash_lookup(lp->cur_action->look, &ipaddr, hash);

    new = 1;

    /* if it exists, make sure not a duplicate set */
    if (exporter_look) {

      tmpflag = exporter_look->set_flags;

      if (((tmpflag & FT_TAG_SET_SRCDST) & tflag) ||
         ((tmpflag & FT_TAG_OR_SRCDST) & tflag2)) {
        fterr_warnx(
          "%s line %d: Only one set per source/destination per match.",
          lp->fname, lp->lineno);
        return -1;
      } else {
        new = 0;
      }

    }

    if (new) {

      bzero(&exporter_look2, sizeof exporter_look2);

      exporter_look2.addr = ipaddr;

      if (!(exporter_look = ftchash_update(lp->cur_action->look,
        &exporter_look2, hash))) {
        fterr_warnx("ftch_update(): failed");
        return -1;
      }

    }

    /* finish filling in fields */

    exporter_look->set_flags |= sflag;

    if (sflag & FT_TAG_SET_SRC_TAG)
      exporter_look->src_tag = tag;

    if (sflag & FT_TAG_OR_SRC_TAG)
      exporter_look->src_tag |= tag;
      
    if (sflag & FT_TAG_SET_DST_TAG)
      exporter_look->dst_tag = tag;

    if (sflag & FT_TAG_OR_DST_TAG)
      exporter_look->dst_tag |= tag;

  } else if (lp->cur_action->type & FT_TAG_TYPE_MATCH_IP) {

    ipaddr = scan_ip(match);

    hash = (ipaddr>>16) ^ (ipaddr & 0xFFFF);
    hash = (hash>>8) ^ (hash & 0xFF);

    ip_look = ftchash_lookup(lp->cur_action->look, &ipaddr, hash);

    new = 1;

    /* if it exists, make sure not a duplicate set */
    if (ip_look) {

      tmpflag = ip_look->set_flags;

      if (((tmpflag & FT_TAG_SET_SRCDST) & tflag) ||
         ((tmpflag & FT_TAG_OR_SRCDST) & tflag2)) {
        fterr_warnx(
          "%s line %d: Only one set per source/destination per match.",
          lp->fname, lp->lineno);
        return -1;
      } else {
        new = 0;
      }

    }

    if (new) {

      bzero(&ip_look2, sizeof ip_look2);

      ip_look2.addr = ipaddr;

      if (!(ip_look = ftchash_update(lp->cur_action->look,
        &ip_look2, hash))) {
        fterr_warnx("ftch_update(): failed");
        return -1;
      }

    }

    /* finish filling in fields */

    ip_look->set_flags |= sflag;

    if (sflag & FT_TAG_SET_SRC_TAG)
      ip_look->src_tag = tag;

    if (sflag & FT_TAG_OR_SRC_TAG)
      ip_look->src_tag |= tag;
      
    if (sflag & FT_TAG_SET_DST_TAG)
      ip_look->dst_tag = tag;
       
    if (sflag & FT_TAG_OR_DST_TAG)
      ip_look->dst_tag |= tag;

  }

  return 0;

} /* parse_action_match */

/*
 * function: parse_def
 *
 * process the 'definition' line.  Each definition has a unique name which
 * is added to the fttag->defs linked list.  The current definition is
 * updated in lp.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_def(struct line_parser *lp, struct fttag *fttag)
{
  char *c;
  struct fttag_def *ftd;

  NEXT_WORD(&lp->buf, c);

  if (!c) {
    fterr_warnx("%s line %d: Expecting name.", lp->fname, lp->lineno);
    return -1;
  }

  /* check if it exists */
  FT_SLIST_FOREACH(ftd, &fttag->defs, chain) {

    if (!strcasecmp(c, ftd->name)) {
      fterr_warnx("%s line %d: Name (%s) previously defined.", lp->fname,
        lp->lineno, c);
      return -1;
    }

  }

  /* no, add a new entry to the list */
  if (!(ftd = (struct fttag_def*)malloc(sizeof
    (struct fttag_def)))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftd, sizeof *ftd);

  FT_STAILQ_INIT(&ftd->terms);

  if (!(ftd->name = (char*)malloc(strlen(c)+1))) {
    fterr_warn("malloc()");
    free(ftd);
    return -1;
  }

  strcpy(ftd->name, c);

  FT_SLIST_INSERT_HEAD(&fttag->defs, ftd, chain);

  lp->state = PARSE_STATE_DEFINITION;
  lp->cur_def = ftd;

  return 0;

} /* parse_def */

/*
 * function: parse_def_term
 *
 * process the term line.  Each definition has a list of terms, the
 * terms have a common input, output, and exporter IP filter and
 * may have one or more actions.  Without an action a term has
 * no purpose.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_def_term(struct line_parser *lp, struct fttag *fttag)
{
  struct fttag_def_term *ftdt;

  if (!lp->cur_def) {
    fterr_warnx("%s line %d: Must set name first.", lp->fname, lp->lineno);
    return -1;
  }

  /* no, add a new term entry to this definition */
  if (!(ftdt = (struct fttag_def_term*)malloc(sizeof *ftdt))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftdt, sizeof *ftdt);

  FT_STAILQ_INIT(&ftdt->actions);

  FT_STAILQ_INSERT_TAIL(&lp->cur_def->terms, ftdt, chain);

  lp->cur_def_term = ftdt;

  return 0;

} /* parse_def_term */

/*
 * function: parse_def_exporter
 *
 * process the 'exporter' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_def_exporter(struct line_parser *lp, struct fttag *fttag)
{
  char *c;

  if (!lp->cur_def_term) {
    fterr_warnx("%s line %d: Must start term.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, c);

  if (!c) {
    fterr_warnx("%s line %d: Expecting exporter.", lp->fname, lp->lineno);
    return -1;
  }

  if (lp->cur_def_term->flags & FT_TAG_DEF_FILTER_EXPORTER) {
    fterr_warnx("%s line %d: Exporter previously defined.", lp->fname,
    lp->lineno);
    return -1;
  }

  lp->cur_def_term->exporter_ip = scan_ip(c);

  lp->cur_def_term->flags |= FT_TAG_DEF_FILTER_EXPORTER;

  return 0;

} /* parse_def_exporter */

/*
 * function: parse_def_input_filter
 *
 * process the 'input-filter' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_def_input_filter(struct line_parser *lp, struct fttag *fttag)
{
  char *c;

  if (!lp->cur_def_term) {
    fterr_warnx("%s line %d: Must start term.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, c);

  if (!c) {
    fterr_warnx("%s line %d: Expecting filter list.", lp->fname, lp->lineno);
    return -1;
  }

  if (lp->cur_def_term->flags & FT_TAG_DEF_FILTER_INPUT) {
    fterr_warnx("%s line %d: Input filter previously defined.", lp->fname,
    lp->lineno);
    return -1;
  }

  if (load_lookup(c, 65536, lp->cur_def_term->in_tbl)) {
    fterr_warnx("load_lookup(): failed");
    return -1;
  }

  lp->cur_def_term->flags |= FT_TAG_DEF_FILTER_INPUT;

  return 0;

} /* parse_def_input_filter */

/*
 * function: parse_def_output_filter
 *
 * process the 'output-filter' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_def_output_filter(struct line_parser *lp, struct fttag *fttag)
{
  char *c;

  if (!lp->cur_def_term) {
    fterr_warnx("%s line %d: Must start term.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, c);

  if (!c) {
    fterr_warnx("%s line %d: Expecting filter list.", lp->fname, lp->lineno);
    return -1;
  }

  if (lp->cur_def_term->flags & FT_TAG_DEF_FILTER_OUTPUT) {
    fterr_warnx("%s line %d: Output filter previously defined.", lp->fname,
    lp->lineno);
    return -1;
  }

  if (load_lookup(c, 65536, lp->cur_def_term->out_tbl)) {
    fterr_warnx("load_lookup(): failed");
    return -1;
  }

  lp->cur_def_term->flags |= FT_TAG_DEF_FILTER_OUTPUT;

  return 0;

} /* parse_def_output_filter */

/*
 * function: parse_def_action
 *
 * foreach action listed, add it to a linked list of actions for the
 * definition.  Note resolve_actions() must be called before the actions
 * are valid.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_def_action(struct line_parser *lp, struct fttag *fttag)
{
  struct fttag_def_term_actions *ftdta;
  char *c;

  if (!lp->cur_def_term) {
    fterr_warnx("%s line %d: Must start term.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, c);

  if (!c) {
    fterr_warnx("%s line %d: Expecting action.", lp->fname, lp->lineno);
    return -1;
  }

  /* add a new entry to the list */
  if (!(ftdta = (struct fttag_def_term_actions*)malloc(sizeof *ftdta))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftdta, sizeof *ftdta);

  if (!(ftdta->name = (char*)malloc(strlen(c)+1))) {
    fterr_warn("malloc()");
    free(ftdta);
    return -1;
  }
  strcpy(ftdta->name, c);

  FT_STAILQ_INSERT_TAIL(&lp->cur_def_term->actions, ftdta, chain);

  /* resolve the ftdta->action later in resolve_actions */

  return 0;

} /* parse_def_action */

/*
 * function: resolve_actions
 *
 * The parser points to the name of the action in the definition to allow
 * for definitions to be defined before actions in the config file.  This
 * fixes the pointers so the definitions point to the actions
 *
 * returns: 0  ok
 *          <0 fail (an action could not be resolved)
 */
int resolve_actions(struct fttag *fttag)
{
  struct fttag_def *ftd;
  struct fttag_def_term *ftdt;
  struct fttag_def_term_actions *ftdta;
  struct fttag_action *fta;
  int i, found;

  /* foreach definition */
  FT_SLIST_FOREACH(ftd, &fttag->defs, chain) {

    /* foreach term in the definition */
    FT_STAILQ_FOREACH(ftdt, &ftd->terms, chain) {

      /*
       * pre-init filter to all 1's to minimize test in eval later
       */

      if (!(ftdt->flags & FT_TAG_DEF_FILTER_INPUT))
        for (i = 0; i < 65536; ++i)
          ftdt->in_tbl[i] = 1;

      if (!(ftdt->flags & FT_TAG_DEF_FILTER_OUTPUT))
        for (i = 0; i < 65536; ++i)
          ftdt->out_tbl[i] = 1;

      /* foreach action in the term */
      FT_STAILQ_FOREACH(ftdta, &ftdt->actions, chain) {

        found = 0;

        /* foreach action */
        FT_SLIST_FOREACH(fta, &fttag->actions, chain) {

          if (!(strcasecmp(fta->name, ftdta->name))) {

            ftdta->action = fta;
            found = 1;
            break;

          }

        }

      }

      if (!found) {

        fterr_warnx("Unable to resolve action \"%s\" in tag-definition \"%s\".", ftdta->name, ftd->name);
        return -1;

      }

    }

  }

  return 0;

} /* resolve actions */

/*
 * function: fttag_free
 *
 * free resources allocated by fttag_load()
 *
 */
void fttag_free(struct fttag *fttag)
{
  struct fttag_action *fta;
  struct fttag_def *ftd;
  struct fttag_def_term *ftdt;
  struct fttag_def_term_actions *ftdta;

  /* foreach action, remove the action and associated storge */
  while (!FT_SLIST_EMPTY(&fttag->actions)) {

    fta = FT_SLIST_FIRST(&fttag->actions);

    FT_SLIST_REMOVE_HEAD(&fttag->actions, chain);

    if (fta->type & FT_TAG_TYPE_MATCH_AS)
      free(fta->look);
    else if (fta->type & FT_TAG_TYPE_MATCH_NEXTHOP)
      ftchash_free(fta->look);
    else if (fta->type & FT_TAG_TYPE_MATCH_EXPORTER)
      ftchash_free(fta->look);
    else if (fta->type & FT_TAG_TYPE_MATCH_IP)
      ftchash_free(fta->look);
    else if (fta->type & FT_TAG_TYPE_MATCH_PREFIX) {
      rhead = fta->look;
      rhead->rnh_walktree(rhead, walk_free, 0);
    }

    free(fta->name);
    free(fta);

  } /* while */

  /* foreach definition, remove the definition and associated storage */
  while (!FT_SLIST_EMPTY(&fttag->defs)) {

    ftd = FT_SLIST_FIRST(&fttag->defs);

    FT_SLIST_REMOVE_HEAD(&fttag->defs, chain);

    /* foreach term in the definition */
    while (!FT_STAILQ_EMPTY(&ftd->terms)) {

      ftdt = FT_STAILQ_FIRST(&ftd->terms);

      while (!FT_STAILQ_EMPTY(&ftdt->actions)) {

        ftdta = FT_STAILQ_FIRST(&ftdt->actions);

        if (ftdta->name)
          free(ftdta->name);

        FT_STAILQ_REMOVE_HEAD(&ftdt->actions, chain);

        free(ftdta);

      }

      FT_STAILQ_REMOVE_HEAD(&ftd->terms, chain);

      free (ftdt);

    }

    free(ftd->name);
    free(ftd);

  } /* while */

} /* fttag_free */

/*
 * function: fttag_def_eval
 *
 * perform tag actions on a flow
 *
 * run down each term in the definition
 *  evaluate the filter, if okay
 *    run every action
 *
 * the filter is activated by
 *  FT_TAG_DEF_FILTER_INPUT - check input
 *  FT_TAG_DEF_FILTER_OUTPUT check output
 *  FT_TAG_DEF_FILTER_EXPORTER check exporter
 *
 *
 * returns 0
 */
inline int fttag_def_eval(struct fttag_def *ftd,
  struct fts3rec_v1005 *rec)
{
  struct fttag_def_term *ftdt;
  struct fttag_def_term_actions *ftdta;
  struct fttag_action *fta;

  /* foreach term in the definition */
  FT_STAILQ_FOREACH(ftdt, &ftd->terms, chain) {

    /* in_tbl is preloaded with "permit any" so don't check the flags bit */
    if (!ftdt->in_tbl[rec->input])
      continue;

    /* out_tbl is preloaded with "permit any" so don't check the flags bit */
    if (!ftdt->out_tbl[rec->output])
      continue;

    if (ftdt->flags & FT_TAG_DEF_FILTER_EXPORTER)
      if (ftdt->exporter_ip != rec->exaddr)
        continue;

    /* for every action chained to this term */
    FT_STAILQ_FOREACH(ftdta, &ftdt->actions, chain) {
  
      /* the action */
      fta = ftdta->action;
  
      /* based on the type do the action if a match is made */
      fta->eval(fta, rec);

    } /* foreach action references by the term */

  } /* foreach term */
  
  return 0;

} /* fttag_def_eval */

inline void eval_match_src_as(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  struct fttag_as_look *as_look;
  u_int16 set_tmp;
 
  as_look = fta->look;
 
  set_tmp = as_look->set_flags_lookup[rec->src_as];
 
  if (set_tmp & FT_TAG_SET_DST_TAG)
    rec->dst_tag = as_look->dst_tag_lookup[rec->src_as];
  else if (set_tmp & FT_TAG_OR_DST_TAG)
    rec->dst_tag |= as_look->dst_tag_lookup[rec->src_as];
 
  if (set_tmp & FT_TAG_SET_SRC_TAG)
    rec->src_tag = as_look->src_tag_lookup[rec->src_as];
  if (set_tmp & FT_TAG_OR_SRC_TAG)
    rec->src_tag |= as_look->src_tag_lookup[rec->src_as];

} /* eval_match_src_as */

inline void eval_match_dst_as(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  struct fttag_as_look *as_look;
  u_int16 set_tmp;
 
  as_look = fta->look;
 
  set_tmp = as_look->set_flags_lookup[rec->dst_as];
 
  if (set_tmp & FT_TAG_SET_DST_TAG)
    rec->dst_tag = as_look->dst_tag_lookup[rec->dst_as];
  else if (set_tmp & FT_TAG_OR_DST_TAG)
    rec->dst_tag |= as_look->dst_tag_lookup[rec->dst_as];
 
  if (set_tmp & FT_TAG_SET_SRC_TAG)
    rec->src_tag = as_look->src_tag_lookup[rec->dst_as];
  if (set_tmp & FT_TAG_OR_SRC_TAG)
    rec->src_tag |= as_look->src_tag_lookup[rec->dst_as];

} /* eval_match_dst_as */

inline void eval_match_src_prefix(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  struct radix_sockaddr_in dst_sock;
  struct fttag_prefix_look *prefix_look;
  struct radix_node_head *rhead;
  u_int16 set_tmp;

  rhead = fta->look;

  dst_sock.sin_addr.s_addr = rec->srcaddr;
  dst_sock.sin_len = sizeof (struct radix_sockaddr_in);
  dst_sock.sin_family = AF_INET;

  prefix_look = (struct fttag_prefix_look *)
    rhead->rnh_matchaddr(&dst_sock, rhead);

  if (prefix_look) {

    set_tmp = prefix_look->set_flags;

    if (set_tmp & FT_TAG_SET_DST_TAG)
      rec->dst_tag = prefix_look->dst_tag;
    else if (set_tmp & FT_TAG_OR_DST_TAG)
      rec->dst_tag |= prefix_look->dst_tag;

    if (set_tmp & FT_TAG_SET_SRC_TAG)
      rec->src_tag = prefix_look->src_tag;
    else if (set_tmp & FT_TAG_OR_SRC_TAG)
     rec->src_tag |= prefix_look->src_tag;

  }

} /* eval_match_src_prefix */

inline void eval_match_dst_prefix(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  struct radix_sockaddr_in dst_sock;
  struct fttag_prefix_look *prefix_look;
  struct radix_node_head *rhead;
  u_int16 set_tmp;

  rhead = fta->look;

  dst_sock.sin_addr.s_addr = rec->dstaddr;
  dst_sock.sin_len = sizeof (struct radix_sockaddr_in);
  dst_sock.sin_family = AF_INET;

  prefix_look = (struct fttag_prefix_look *)
    rhead->rnh_matchaddr(&dst_sock, rhead);

  if (prefix_look) {

    set_tmp = prefix_look->set_flags;

    if (set_tmp & FT_TAG_SET_DST_TAG)
      rec->dst_tag = prefix_look->dst_tag;
    else if (set_tmp & FT_TAG_OR_DST_TAG)
      rec->dst_tag |= prefix_look->dst_tag;

    if (set_tmp & FT_TAG_SET_SRC_TAG)
      rec->src_tag = prefix_look->src_tag;
    else if (set_tmp & FT_TAG_OR_SRC_TAG)
     rec->src_tag |= prefix_look->src_tag;

  }

} /* eval_match_dst_prefix */

inline void eval_match_nexthop(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  struct ftchash *ftch;
  u_int32 hash, ipaddr;
  struct fttag_next_hop_look *nh_look;
  u_int16 set_tmp;

  ftch = fta->look;
  ipaddr = rec->nexthop;

  hash = (ipaddr>>16) ^ (ipaddr & 0xFFFF);
  hash = (hash>>8) ^ (hash & 0xFF);

  /* lookup next hop */
  nh_look = ftchash_lookup(ftch, &ipaddr, hash);

  if (nh_look) {

    set_tmp = nh_look->set_flags;

    if (set_tmp & FT_TAG_SET_DST_TAG)
      rec->dst_tag = nh_look->dst_tag;
    else if (set_tmp & FT_TAG_OR_DST_TAG)
      rec->dst_tag |= nh_look->dst_tag;
 
    if (set_tmp & FT_TAG_SET_SRC_TAG)
      rec->src_tag = nh_look->src_tag;
    else if (set_tmp & FT_TAG_OR_SRC_TAG)
      rec->src_tag |= nh_look->src_tag;   

  }

} /* eval_match_nexthop */

inline void eval_match_exporter(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  struct ftchash *ftch;
  u_int32 hash, ipaddr;
  struct fttag_exporter_look *exporter_look;
  u_int16 set_tmp;

  ftch = fta->look;
  ipaddr = rec->exaddr;

  hash = (ipaddr>>16) ^ (ipaddr & 0xFFFF);
  hash = (hash>>8) ^ (hash & 0xFF);

  /* lookup next hop */
  exporter_look = ftchash_lookup(ftch, &ipaddr, hash);

  if (exporter_look) {

    set_tmp = exporter_look->set_flags;


    if (set_tmp & FT_TAG_SET_DST_TAG)
      rec->dst_tag = exporter_look->dst_tag;
    else if (set_tmp & FT_TAG_OR_DST_TAG)
      rec->dst_tag |= exporter_look->dst_tag;
 
    if (set_tmp & FT_TAG_SET_SRC_TAG)
      rec->src_tag = exporter_look->src_tag;
    else if (set_tmp & FT_TAG_OR_SRC_TAG)
      rec->src_tag |= exporter_look->src_tag;   

  }

} /* eval_match_exporter */

inline void eval_match_src_ip(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  struct ftchash *ftch;
  u_int32 hash, ipaddr;
  struct fttag_ip_look *ip_look;
  u_int16 set_tmp;

  ftch = fta->look;
  ipaddr = rec->srcaddr;

  hash = (ipaddr>>16) ^ (ipaddr & 0xFFFF);
  hash = (hash>>8) ^ (hash & 0xFF);

  /* lookup next hop */
  ip_look = ftchash_lookup(ftch, &ipaddr, hash);

  if (ip_look) {

    set_tmp = ip_look->set_flags;


    if (set_tmp & FT_TAG_SET_DST_TAG)
      rec->dst_tag = ip_look->dst_tag;
    else if (set_tmp & FT_TAG_OR_DST_TAG)
      rec->dst_tag |= ip_look->dst_tag;
 
    if (set_tmp & FT_TAG_SET_SRC_TAG)
      rec->src_tag = ip_look->src_tag;
    else if (set_tmp & FT_TAG_OR_SRC_TAG)
      rec->src_tag |= ip_look->src_tag;   

  }

} /* eval_match_src_ip */

inline void eval_match_dst_ip(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  struct ftchash *ftch;
  u_int32 hash, ipaddr;
  struct fttag_ip_look *ip_look;
  u_int16 set_tmp;

  ftch = fta->look;
  ipaddr = rec->dstaddr;

  hash = (ipaddr>>16) ^ (ipaddr & 0xFFFF);
  hash = (hash>>8) ^ (hash & 0xFF);

  /* lookup next hop */
  ip_look = ftchash_lookup(ftch, &ipaddr, hash);

  if (ip_look) {

    set_tmp = ip_look->set_flags;


    if (set_tmp & FT_TAG_SET_DST_TAG)
      rec->dst_tag = ip_look->dst_tag;
    else if (set_tmp & FT_TAG_OR_DST_TAG)
      rec->dst_tag |= ip_look->dst_tag;
 
    if (set_tmp & FT_TAG_SET_SRC_TAG)
      rec->src_tag = ip_look->src_tag;
    else if (set_tmp & FT_TAG_OR_SRC_TAG)
      rec->src_tag |= ip_look->src_tag;   

  }

} /* eval_match_dst_ip */

inline void eval_match_prefix(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  eval_match_src_prefix(fta, rec);
  eval_match_dst_prefix(fta, rec);
} /* eval_match_prefix */

inline void eval_match_as(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  eval_match_src_as(fta, rec);
  eval_match_dst_as(fta, rec);
} /* eval_match_as */

inline void eval_match_tcp_src_port(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  struct fttag_port_look *port_look;
  u_int16 set_tmp;
 
  port_look = fta->look;

  /* only TCP here */
  if (rec->prot != 6)
    return;
 
  set_tmp = port_look->set_flags_lookup[rec->srcport];
 
  if (set_tmp & FT_TAG_SET_DST_TAG)
    rec->dst_tag = port_look->dst_tag_lookup[rec->srcport];
  else if (set_tmp & FT_TAG_OR_DST_TAG)
    rec->dst_tag |= port_look->dst_tag_lookup[rec->srcport];
 
  if (set_tmp & FT_TAG_SET_SRC_TAG)
    rec->src_tag = port_look->src_tag_lookup[rec->srcport];
  if (set_tmp & FT_TAG_OR_SRC_TAG)
    rec->src_tag |= port_look->src_tag_lookup[rec->srcport];

} /* eval_match_tcp_src_port */

inline void eval_match_tcp_dst_port(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  struct fttag_port_look *port_look;
  u_int16 set_tmp;
 
  port_look = fta->look;

  /* only TCP here */
  if (rec->prot != 6)
    return;
 
  set_tmp = port_look->set_flags_lookup[rec->dstport];
 
  if (set_tmp & FT_TAG_SET_DST_TAG)
    rec->dst_tag = port_look->dst_tag_lookup[rec->dstport];
  else if (set_tmp & FT_TAG_OR_DST_TAG)
    rec->dst_tag |= port_look->dst_tag_lookup[rec->dstport];
 
  if (set_tmp & FT_TAG_SET_SRC_TAG)
    rec->src_tag = port_look->src_tag_lookup[rec->dstport];
  if (set_tmp & FT_TAG_OR_SRC_TAG)
    rec->src_tag |= port_look->src_tag_lookup[rec->dstport];

} /* eval_match_tcp_dst_port */

inline void eval_match_udp_src_port(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  struct fttag_port_look *port_look;
  u_int16 set_tmp;
 
  port_look = fta->look;

  /* only UDP here */
  if (rec->prot != 17)
    return;
 
  set_tmp = port_look->set_flags_lookup[rec->srcport];
 
  if (set_tmp & FT_TAG_SET_DST_TAG)
    rec->dst_tag = port_look->dst_tag_lookup[rec->srcport];
  else if (set_tmp & FT_TAG_OR_DST_TAG)
    rec->dst_tag |= port_look->dst_tag_lookup[rec->srcport];
 
  if (set_tmp & FT_TAG_SET_SRC_TAG)
    rec->src_tag = port_look->src_tag_lookup[rec->srcport];
  if (set_tmp & FT_TAG_OR_SRC_TAG)
    rec->src_tag |= port_look->src_tag_lookup[rec->srcport];

} /* eval_match_udp_src_port */

inline void eval_match_udp_dst_port(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  struct fttag_port_look *port_look;
  u_int16 set_tmp;
 
  port_look = fta->look;

  /* only UDP here */
  if (rec->prot != 17)
    return;
 
  set_tmp = port_look->set_flags_lookup[rec->dstport];
 
  if (set_tmp & FT_TAG_SET_DST_TAG)
    rec->dst_tag = port_look->dst_tag_lookup[rec->dstport];
  else if (set_tmp & FT_TAG_OR_DST_TAG)
    rec->dst_tag |= port_look->dst_tag_lookup[rec->dstport];
 
  if (set_tmp & FT_TAG_SET_SRC_TAG)
    rec->src_tag = port_look->src_tag_lookup[rec->dstport];
  if (set_tmp & FT_TAG_OR_SRC_TAG)
    rec->src_tag |= port_look->src_tag_lookup[rec->dstport];

} /* eval_match_udp_dst_port */

inline void eval_match_tcp_port(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  eval_match_tcp_src_port(fta, rec);
  eval_match_tcp_dst_port(fta, rec);
} /* eval_match_tcp_port */

inline void eval_match_udp_port(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  eval_match_udp_src_port(fta, rec);
  eval_match_udp_dst_port(fta, rec);
} /* eval_match_udp_port */

inline void eval_match_in_interface(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  struct fttag_interface_look *interface_look;
  u_int16 set_tmp;
 
  interface_look = fta->look;

  set_tmp = interface_look->set_flags_lookup[rec->input];
 
  if (set_tmp & FT_TAG_SET_DST_TAG)
    rec->dst_tag = interface_look->dst_tag_lookup[rec->input];
  else if (set_tmp & FT_TAG_OR_DST_TAG)
    rec->dst_tag |= interface_look->dst_tag_lookup[rec->input];
 
  if (set_tmp & FT_TAG_SET_SRC_TAG)
    rec->src_tag = interface_look->src_tag_lookup[rec->input];
  if (set_tmp & FT_TAG_OR_SRC_TAG)
    rec->src_tag |= interface_look->src_tag_lookup[rec->input];

} /* eval_match_in_interface */

inline void eval_match_out_interface(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  struct fttag_interface_look *interface_look;
  u_int16 set_tmp;
 
  interface_look = fta->look;

  set_tmp = interface_look->set_flags_lookup[rec->output];
 
  if (set_tmp & FT_TAG_SET_DST_TAG)
    rec->dst_tag = interface_look->dst_tag_lookup[rec->output];
  else if (set_tmp & FT_TAG_OR_DST_TAG)
    rec->dst_tag |= interface_look->dst_tag_lookup[rec->output];
 
  if (set_tmp & FT_TAG_SET_SRC_TAG)
    rec->src_tag = interface_look->src_tag_lookup[rec->output];
  if (set_tmp & FT_TAG_OR_SRC_TAG)
    rec->src_tag |= interface_look->src_tag_lookup[rec->output];

} /* eval_match_out_interface */

inline void eval_match_interface(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  eval_match_in_interface(fta, rec);
  eval_match_out_interface(fta, rec);
} /* eval_match_interface */

inline void eval_match_ip(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  eval_match_src_ip(fta, rec);
  eval_match_dst_ip(fta, rec);
} /* eval_match_ip */

inline void eval_match_tos(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  struct fttag_tos_look *tos_look;
  u_int16 set_tmp;
 
  tos_look = fta->look;

  set_tmp = tos_look->set_flags_lookup[rec->tos];
 
  if (set_tmp & FT_TAG_SET_DST_TAG)
    rec->dst_tag = tos_look->dst_tag_lookup[rec->tos];
  else if (set_tmp & FT_TAG_OR_DST_TAG)
    rec->dst_tag |= tos_look->dst_tag_lookup[rec->tos];
 
  if (set_tmp & FT_TAG_SET_SRC_TAG)
    rec->src_tag = tos_look->src_tag_lookup[rec->tos];
  if (set_tmp & FT_TAG_OR_SRC_TAG)
    rec->src_tag |= tos_look->src_tag_lookup[rec->tos];

} /* eval_match_tos */

inline void eval_match_any(struct fttag_action *fta,
  struct fts3rec_v1005 *rec)
{
  struct fttag_any_look *any_look;
  u_int16 set_tmp;
 
  any_look = fta->look;

  set_tmp = any_look->set_flags;
 
  if (set_tmp & FT_TAG_SET_DST_TAG)
    rec->dst_tag = any_look->dst_tag;
  else if (set_tmp & FT_TAG_OR_DST_TAG)
    rec->dst_tag |= any_look->dst_tag;
 
  if (set_tmp & FT_TAG_SET_SRC_TAG)
    rec->src_tag = any_look->src_tag;
  if (set_tmp & FT_TAG_OR_SRC_TAG)
    rec->src_tag |= any_look->src_tag;

} /* eval_match_any */


static int walk_free(struct radix_node *rn, struct walkarg *UNUSED)
{
  struct fttag_prefix_look *r;
  struct radix_sockaddr_in sock1, sock2;

  r = (struct  fttag_prefix_look*)rn;
  bzero(&sock1, sizeof sock1);
  bzero(&sock2, sizeof sock2);

  sock1.sin_addr.s_addr = r->addr.sin_addr.s_addr;
  sock1.sin_len = sizeof sock1;
  sock1.sin_family = AF_INET;

  sock2.sin_addr.s_addr = (!r->masklen) ? 0: mask_lookup[r->masklen];
  sock2.sin_len = sizeof sock2;
  sock2.sin_family = AF_INET;

  if (r != (struct fttag_prefix_look*)rhead->rnh_deladdr(&sock1,
    &sock2, rhead))
    fterr_errx(1, "rn_deladdr(): failed.");
  else
    free(r);

  return 0;
} /* walk_free */

