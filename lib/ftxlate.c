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
 *      $Id: ftxlate.c,v 1.6 2005/05/11 14:03:30 maf Exp $
 */

#include "ftconfig.h"
#include "ftlib.h"
#include "ftpaths.h"

#ifdef HAVE_OPENSSL
#define free_func ssl_free_func /* hack, zlib uses free_func also */
#include <openssl/ssl.h>
#include <openssl/evp.h>
#undef free_func
#endif /* HAVE_OPENSSL */

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

struct cryptopan {
  u_int8_t m_key[16]; /* 128 bit secret key */
  u_int8_t m_pad[16]; /* 128 bit secret pad */
#ifdef HAVE_OPENSSL
  EVP_CIPHER_CTX *cipher_ctx; /* openssl cipher context */
#endif /* HAVE_OPENSSL */
};

static int cryptopan_anon(struct cryptopan *cp, u_int32_t orig_addr,
  u_int32_t *new_addr);
static int cryptopan_free(struct cryptopan *cp);
static int cryptopan_init(struct cryptopan *cp, unsigned char *key);

static int load_key_file(char *fname, unsigned char *key);

struct line_parser {
  struct ftxlate_action *cur_action;
  struct ftxlate_def *cur_def;
  struct ftxlate_def_term *cur_def_term;
  int state, type;
  int lineno;
  char *buf, *fname, *word;
};

#define FT_XLATE_TYPE_IP_SRC_ADDR2NET    0x1
#define FT_XLATE_TYPE_IP_DST_ADDR2NET    0x2
#define FT_XLATE_TYPE_IP_SRC_ADDR2CNET   0x3
#define FT_XLATE_TYPE_IP_DST_ADDR2CNET   0x4
#define FT_XLATE_TYPE_IP_ADDR_PRIV_MASK  0x5
#define FT_XLATE_TYPE_TAG_MASK           0x6
#define FT_XLATE_TYPE_SCALE              0x7
#define FT_XLATE_TYPE_SRC_AS             0x8
#define FT_XLATE_TYPE_DST_AS             0x9
#define FT_XLATE_TYPE_IP_PORT_PRIV_MASK  0xA
#define FT_XLATE_TYPE_IP_ADDR_ANON       0xB
#define FT_XLATE_TYPE_IP_SRC_ADDR_ANON   0xC
#define FT_XLATE_TYPE_IP_DST_ADDR_ANON   0xD
#define FT_XLATE_FLAG_STOP               0x1
#define FT_XLATE_ALG_CRYPTOPAN_AES128    0x1

struct ftxlate_action {
  FT_SLIST_ENTRY(ftxlate_action) chain; /* list of all actions */
  int type; /* FT_XLATE_TYPE_MATCH_* */
  char *name;
  void *action;
  void (*eval)(struct ftxlate_action *ftxa, char *rec,
    struct fts3rec_offsets *fo);
  u_int64 xfields;
};

struct ftxlate_def_term {
  FT_STAILQ_ENTRY(ftxlate_def_term) chain; /* list of terms */
  FT_STAILQ_HEAD(xactdhead, ftxlate_def_term_actions) actions; /* actions */
  int type; /* FT_XLATE_TYPE_MATCH_* */
  struct ftfil_def *ftfd; /* filter definition */
  int flags;
  u_int64 xfields;
};

struct ftxlate_def_term_actions {
  FT_STAILQ_ENTRY(ftxlate_def_term_actions) chain; /* all actions */
  struct ftxlate_action *action; /* filled in by resolve_actions */
  char *name; /* temporary, invalid after config file is closed */
};

struct ftxlate_def {
  FT_SLIST_ENTRY(ftxlate_def) chain;
  FT_STAILQ_HEAD(xdthead, ftxlate_def_term) terms; /* terms */
  char *name;
  u_int64 xfields;
};

struct ftxlate_act_scale {
  int scale;
};

struct ftxlate_act_asn {
  u_int16 as;
};
struct ftxlate_act_tag_mask {
  u_int32 src_mask;
  u_int32 dst_mask;
};

struct ftxlate_act_ip_addr_priv_mask {
  u_int32 src_mask;
  u_int32 dst_mask;
};

struct ftxlate_act_ip_port_priv_mask {
  u_int16 src_mask;
  u_int16 dst_mask;
};
struct ftxlate_act_ip_addr_anon {
  int init;
  int algorithm;               /* algorithm - cryptopan only for now */
  char *key_fname;             /* file containing a key, null if not used */
  char key[32];                /* key */
  time_t key_refresh_next;     /* next key refresh */
  time_t key_refresh_interval; /* key refresh check rate */
  struct cryptopan cp;         /* cryptopan context */
};


static int parse_action(struct line_parser *lp, struct ftxlate *ftxlate);
static int parse_action_type(struct line_parser *lp, struct ftxlate *ftxlate);
static int parse_action_mask(struct line_parser *lp, struct ftxlate *ftxlate);
static int parse_action_scale(struct line_parser *lp, struct ftxlate *ftxlate);
static int parse_action_asn(struct line_parser *lp, struct ftxlate *ftxlate);
static int parse_action_algorithm(struct line_parser *lp,
  struct ftxlate *ftxlate);
static int parse_action_key(struct line_parser *lp,
  struct ftxlate *ftxlate);
static int parse_action_key_file(struct line_parser *lp,
  struct ftxlate *ftxlate);
static int parse_action_key_refresh(struct line_parser *lp,
  struct ftxlate *ftxlate);

static int decode_hex(char *in, int in_len, unsigned char *out, int out_len);

static int parse_def(struct line_parser *lp, struct ftxlate *ftxlate);
static int parse_def_term(struct line_parser *lp, struct ftxlate *ftxlate);
static int parse_def_filter(struct line_parser *lp, struct ftxlate *ftxlate);
static int parse_def_action(struct line_parser *lp, struct ftxlate *ftxlate);
static int parse_def_stop(struct line_parser *lp, struct ftxlate *ftxlate);
static int resolve_actions(struct ftxlate *ftxlate);
static int parse_include_filter(struct line_parser *lp,
  struct ftxlate *ftxlate);

static int load_filters(struct ftxlate *ftxlate);
  
static void eval_ip_src_addr2net(struct ftxlate_action *ftxa, 
  char *rec, struct fts3rec_offsets *fo);
static void eval_ip_dst_addr2net(struct ftxlate_action *ftxa, 
  char *rec, struct fts3rec_offsets *fo);
static void eval_ip_src_addr2cnet(struct ftxlate_action *ftxa, 
  char *rec, struct fts3rec_offsets *fo);
static void eval_ip_dst_addr2cnet(struct ftxlate_action *ftxa, 
  char *rec, struct fts3rec_offsets *fo);
static void eval_ip_addr_privacy_mask(struct ftxlate_action *ftxa, 
  char *rec, struct fts3rec_offsets *fo);
static void eval_ip_port_privacy_mask(struct ftxlate_action *ftxa, 
  char *rec, struct fts3rec_offsets *fo);
static void eval_scale(struct ftxlate_action *ftxa, 
  char *rec, struct fts3rec_offsets *fo);
static void eval_tag_mask(struct ftxlate_action *ftxa, 
  char *rec, struct fts3rec_offsets *fo);
static void eval_src_asn(struct ftxlate_action *ftxa, 
  char *rec, struct fts3rec_offsets *fo);
static void eval_dst_asn(struct ftxlate_action *ftxa, 
  char *rec, struct fts3rec_offsets *fo);
static void eval_ip_src_addr_anon(struct ftxlate_action *ftxa, 
  char *rec, struct fts3rec_offsets *fo);
static void eval_ip_dst_addr_anon(struct ftxlate_action *ftxa, 
  char *rec, struct fts3rec_offsets *fo);
static void eval_ip_addr_anon(struct ftxlate_action *ftxa, 
  char *rec, struct fts3rec_offsets *fo);

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
  int (*func)(struct line_parser *lp, struct ftxlate *ftxlate);
};

static struct jump pjump[] = {
          {"include-filter", 0, parse_include_filter},
          {"xlate-action", 0, parse_action},
          {"type", PARSE_STATE_ACTION, parse_action_type},
          {"mask", PARSE_STATE_ACTION, parse_action_mask},
          {"scale", PARSE_STATE_ACTION, parse_action_scale},
          {"as", PARSE_STATE_ACTION, parse_action_asn},
          {"key", PARSE_STATE_ACTION, parse_action_key},
          {"key-file", PARSE_STATE_ACTION, parse_action_key_file},
          {"key-file-refresh", PARSE_STATE_ACTION, parse_action_key_refresh},
          {"algorithm", PARSE_STATE_ACTION, parse_action_algorithm},
          {"xlate-definition", 0, parse_def},
          {"term", PARSE_STATE_DEFINITION, parse_def_term},
          {"filter", PARSE_STATE_DEFINITION, parse_def_filter},
          {"stop", PARSE_STATE_DEFINITION, parse_def_stop},
          {"action", PARSE_STATE_DEFINITION, parse_def_action},
          {0, 0, 0},
          };
/*
 * data structures:
 *
 *
 * ftxlate holds the head pointers to a list of actions, and definitions.
 *
 * Each definition holds a list of terms.  A term is a combination of
 * a filter and a list of actions
 *
 * struct ftxlate_def               : linked list of definitions
 * struct ftxlate_action            : linked list of actions
 * struct ftxlate_def_term          : each term in a definition
 * struct ftxlate_def_term_actions  : each action in a term
 *
 * actions contain one of the following:
 *  - note for some actions no additional data is required and action
 *    will be null
 *
 * struct ftxlate_act_scale         : scale
 * struct ftxlate_act_tag_mask      : source and destination tag mask
 * struct ftxlate_act_priv_mask     : source and destination privacy mask
 * struct ftxlate_port_priv_mask    : source and destination privacy mask
 * struct ftxlate_act_asn           : replacement ASN
 *
 *
 */

/*
 * function: ftxlate_load
 * 
 * Process fname into ftxlate.
 *
 * returns: 0  ok
 *          <0 fail
*/
int ftxlate_load(struct ftxlate *ftxlate, struct ftvar *ftvar, char *fname)
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
  bzero(ftxlate, sizeof *ftxlate);

  FT_SLIST_INIT(&ftxlate->defs);
  FT_SLIST_INIT(&ftxlate->actions);

  lp.fname = fname;

  if ((fd = open(fname, O_RDONLY, 0)) < 0) {
    fterr_warn("open(%s)", fname);
    goto load_xlate_out;
  }

  if (fstat(fd, &sb) < 0) {
    fterr_warn("stat(%s)", fname);
    goto load_xlate_out;
  }
  
  /* allocate storage for file */
  if (!(buf = malloc(sb.st_size+1))) {
    fterr_warn("malloc()");
    goto load_xlate_out;
  }

  /* read in file */
  if (read(fd, buf, sb.st_size) != sb.st_size) {
    fterr_warnx("read(%s): short", fname);
    goto load_xlate_out;
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
      goto load_xlate_done;
    }

    /* do variable substitutions first */
    if (ftvar) {
      if (ftvar_evalstr(ftvar, c, sbuf, sizeof(sbuf)) < 0) {
        fterr_warnx("ftvar_evalstr(): failed");
        goto load_xlate_done;
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

        if (jmp->func(&lp, ftxlate))
          goto load_xlate_out;

        NEXT_WORD(&lp.buf, c);

        if (c) {
          fterr_warnx("%s line %d: Unexpected \"%s\".", lp.fname, lp.lineno, c);
          goto load_xlate_out;
        }

        break;

      }

    } /* test each word */

    if (!found) {
      fterr_warnx("%s line %d: Unexpected \"%s\".", lp.fname, lp.lineno, c);
      goto load_xlate_out;
    }
   
  } /* more lines */

load_xlate_done:

  if (resolve_actions(ftxlate))
    goto load_xlate_out;

  ret = 0;

load_xlate_out:

  if (fd != -1)
    close(fd);

  if (buf)
    free(buf);

  if (ret == -1)
    ftxlate_free(ftxlate);

  return ret;

} /* ftxlate_load */

/*
 * function: ftxlate_defintion_find
 *
 * Return a pointer to a ftxlate_def_actionup for use later with
 * ftxlate_def_eval
 *
 */
struct ftxlate_def *ftxlate_def_find(struct ftxlate *ftxlate, char *name)
{
  struct ftxlate_def *ftx;

  /* foreach definition */
  FT_SLIST_FOREACH(ftx, &ftxlate->defs, chain) {

    if (!(strcasecmp(ftx->name, name))) 
      return ftx;

  }

  return (struct ftxlate_def*)0L;

} /* ftxlate_def_find */

/*
 * function: ftxlate_def_test_xfields
 *
 * Check if fields in current flow are valid for a xlate definition -- ie
 * the definition does not reference a field not contained in the flow.
 *
 * returns: 0 okay
 *          1 fail
 */
int ftxlate_def_test_xfields(struct ftxlate_def *active_def, u_int64 test)
{
  
  if ((active_def->xfields & test) != active_def->xfields)
    return 1;
  else
    return 0;

} /* ftxlate_def_test_xfields */

/*
 * function: ftxlate_free
 *
 * free resources allocated by ftxlate_load()
 *
 */
void ftxlate_free(struct ftxlate *ftxlate)
{
  struct ftxlate_action *ftxa;
  struct ftxlate_def *ftx;
  struct ftxlate_def_term *ftxt;
  struct ftxlate_def_term_actions *ftxta;
  struct ftxlate_act_ip_addr_anon *ftxiaa;

  if (ftxlate->ftfil_init)
    ftfil_free(&ftxlate->ftfil);

  if (ftxlate->filter_fname)
    free(ftxlate->filter_fname);

  /* foreach action, remove the action and associated storge */
  while (!FT_SLIST_EMPTY(&ftxlate->actions)) {

    ftxa = FT_SLIST_FIRST(&ftxlate->actions);

    FT_SLIST_REMOVE_HEAD(&ftxlate->actions, chain);

    if (ftxa->action) {

      /* *_ANON allocated internal resources */
      if ((ftxa->type == FT_XLATE_TYPE_IP_ADDR_ANON) || 
          (ftxa->type == FT_XLATE_TYPE_IP_SRC_ADDR_ANON) ||
          (ftxa->type == FT_XLATE_TYPE_IP_DST_ADDR_ANON)) {

        ftxiaa = ftxa->action;

        if (ftxiaa->key_fname)
          free(ftxiaa->key_fname);

        if (ftxiaa->init)
          cryptopan_free(&ftxiaa->cp);

      } /* type *_ANON */

      free(ftxa->action);

    }

    free(ftxa->name);
    free(ftxa);

  } /* while */

  /* foreach definition, remove the definition and associated storage */
  while (!FT_SLIST_EMPTY(&ftxlate->defs)) {

    ftx = FT_SLIST_FIRST(&ftxlate->defs);

    FT_SLIST_REMOVE_HEAD(&ftxlate->defs, chain);

    /* foreach term in the definition */
    while (!FT_STAILQ_EMPTY(&ftx->terms)) {

      ftxt = FT_STAILQ_FIRST(&ftx->terms);

      while (!FT_STAILQ_EMPTY(&ftxt->actions)) {

        ftxta = FT_STAILQ_FIRST(&ftxt->actions);

        if (ftxta->name)
          free(ftxta->name);

        FT_STAILQ_REMOVE_HEAD(&ftxt->actions, chain);

        free(ftxta);

      }

      FT_STAILQ_REMOVE_HEAD(&ftx->terms, chain);

      free (ftxt);

    }

    free(ftx->name);
    free(ftx);

  } /* while */

} /* ftxlate_free */

/*
 * function: ftxlate_def_eval
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
int ftxlate_def_eval(struct ftxlate_def *ftx,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftxlate_def_term *ftxt;
  struct ftxlate_def_term_actions *ftxta;
  struct ftxlate_action *ftxa;
  int fpermit, stop;

  /* early termination? */
  stop = 0;

  /* foreach term in the definition */
  FT_STAILQ_FOREACH(ftxt, &ftx->terms, chain) {

    /*
     * if the filter allows this flow then call the xlate evaluation, else
     * leave it alone.
     */

    /* this filter did not permit an action */
    fpermit = 0;

    if (ftxt->ftfd &&
      ftfil_def_eval(ftxt->ftfd, rec, fo) == FT_FIL_MODE_DENY)
        continue;
    else
      fpermit = 1;

    /* stop after this term? */
    if (fpermit && (ftxt->flags & FT_XLATE_FLAG_STOP))
      stop = 1;

    /* for every action chained to this term */
    FT_STAILQ_FOREACH(ftxta, &ftxt->actions, chain) {
  
      /* the action */
      ftxa = ftxta->action;

      /* based on the type do the action if a match is made */
      ftxa->eval(ftxa, rec, fo);

    } /* foreach action references by the term */

    /* early termination due to stop keyword? */
    if (stop)
      break;

  } /* foreach term */
  
  return 0;

} /* ftxlate_def_eval */


/*
 * function: parse_action
 *
 * process the 'action' line.  Each action has a unique name which
 * is added to the ftxlate->actions linked list.  The current action is
 * updated in lp.  Actions by themself do nothing, they must be pointed
 * to by a definition.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_action(struct line_parser *lp, struct ftxlate *ftxlate)
{
  struct ftxlate_action *ftxa;

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting name.", lp->fname, lp->lineno);
    return -1;
  }

  /* check if it exists */
  FT_SLIST_FOREACH(ftxa, &ftxlate->actions, chain) {

    if (!strcasecmp(lp->word, ftxa->name)) {
      fterr_warnx("%s line %d: Name (%s) previously defined.", lp->fname,
        lp->lineno, lp->word);
      return -1;
    }

  }

  /* no, add a new entry to the list */
  if (!(ftxa = (struct ftxlate_action*)malloc(sizeof
    (struct ftxlate_action)))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftxa, sizeof *ftxa);

  if (!(ftxa->name = (char*)malloc(strlen(lp->word)+1))) {
    fterr_warn("malloc()");
    free(ftxa);
    return -1;
  }

  strcpy(ftxa->name, lp->word);

  FT_SLIST_INSERT_HEAD(&ftxlate->actions, ftxa, chain);

  lp->state = PARSE_STATE_ACTION;
  lp->cur_action = ftxa;

  return 0;

} /* parse_action */

/*
 * function: parse_action_type
 *
 * process the 'type' line.  When the type is set the initial storage
 * is allocated if necessary.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_action_type(struct line_parser *lp, struct ftxlate *ftxlate)
{

  if (!lp->cur_action) {
    fterr_warnx("%s line %d: Must set name first.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting type.", lp->fname, lp->lineno);
    return -1;
  }

  if (lp->cur_action->type) {
    fterr_warnx("%s line %d: Type previously defined.", lp->fname, lp->lineno);
    return -1;
  }

  if (!strcasecmp(lp->word, "ip-source-address-to-network")) {
    lp->cur_action->type = FT_XLATE_TYPE_IP_SRC_ADDR2NET;
    lp->cur_action->eval = eval_ip_src_addr2net;
    lp->cur_action->xfields |= (FT_XFIELD_SRCADDR|FT_XFIELD_SRC_MASK);
  } else if (!strcasecmp(lp->word, "ip-destination-address-to-network")) {
      lp->cur_action->type = FT_XLATE_TYPE_IP_DST_ADDR2NET;
      lp->cur_action->eval = eval_ip_dst_addr2net;
      lp->cur_action->xfields |= (FT_XFIELD_DSTADDR|FT_XFIELD_DST_MASK);
  } else if (!strcasecmp(lp->word, "ip-source-address-to-class-network")) {
      lp->cur_action->type = FT_XLATE_TYPE_IP_SRC_ADDR2CNET;
      lp->cur_action->eval = eval_ip_src_addr2cnet;
      lp->cur_action->xfields |= FT_XFIELD_SRCADDR;
  } else if (!strcasecmp(lp->word, "ip-destination-address-to-class-network")) {
      lp->cur_action->type = FT_XLATE_TYPE_IP_DST_ADDR2CNET;
      lp->cur_action->eval = eval_ip_dst_addr2cnet;
      lp->cur_action->xfields |= FT_XFIELD_DSTADDR;
  } else if (!strcasecmp(lp->word, "ip-address-privacy-mask")) {
      lp->cur_action->type = FT_XLATE_TYPE_IP_ADDR_PRIV_MASK;
      lp->cur_action->eval = eval_ip_addr_privacy_mask;
      lp->cur_action->xfields |= (FT_XFIELD_DSTADDR|FT_XFIELD_SRCADDR);
  } else if (!strcasecmp(lp->word, "ip-port-privacy-mask")) {
      lp->cur_action->type = FT_XLATE_TYPE_IP_PORT_PRIV_MASK;
      lp->cur_action->eval = eval_ip_port_privacy_mask;
      lp->cur_action->xfields |= (FT_XFIELD_DSTPORT|FT_XFIELD_SRCPORT);
  } else if (!strcasecmp(lp->word, "scale")) {
      lp->cur_action->type = FT_XLATE_TYPE_SCALE;
      lp->cur_action->eval = eval_scale;
      lp->cur_action->xfields |= (FT_XFIELD_DPKTS|FT_XFIELD_DOCTETS);
  } else if (!strcasecmp(lp->word, "tag-mask")) {
      lp->cur_action->type = FT_XLATE_TYPE_TAG_MASK;
      lp->cur_action->eval = eval_tag_mask;
      lp->cur_action->xfields |= (FT_XFIELD_SRC_TAG|FT_XFIELD_DST_TAG);
  } else if (!strcasecmp(lp->word, "replace-source-as0")) {
      lp->cur_action->type = FT_XLATE_TYPE_SRC_AS;
      lp->cur_action->eval = eval_src_asn;
      lp->cur_action->xfields |= FT_XFIELD_SRC_AS;
  } else if (!strcasecmp(lp->word, "replace-destination-as0")) {
      lp->cur_action->type = FT_XLATE_TYPE_DST_AS;
      lp->cur_action->eval = eval_dst_asn;
      lp->cur_action->xfields |= FT_XFIELD_DST_AS;
  } else if (!strcasecmp(lp->word, "ip-source-address-anonymize")) {
      lp->cur_action->type = FT_XLATE_TYPE_IP_SRC_ADDR_ANON;
      lp->cur_action->eval = eval_ip_src_addr_anon;
      lp->cur_action->xfields |= FT_XFIELD_SRCADDR;
  } else if (!strcasecmp(lp->word, "ip-destination-address-anonymize")) {
      lp->cur_action->type = FT_XLATE_TYPE_IP_DST_ADDR_ANON;
      lp->cur_action->eval = eval_ip_dst_addr_anon;
      lp->cur_action->xfields |= FT_XFIELD_DSTADDR;
  } else if (!strcasecmp(lp->word, "ip-address-anonymize")) {
      lp->cur_action->type = FT_XLATE_TYPE_IP_ADDR_ANON;
      lp->cur_action->eval = eval_ip_addr_anon;
      lp->cur_action->xfields |= (FT_XFIELD_SRCADDR|FT_XFIELD_DSTADDR);
  } else {
      fterr_warnx("%s line %d: Unrecognized type.", lp->fname, lp->lineno);
      return -1;
  } 

  /* allocate storage for action if required */

  if ((lp->cur_action->type == FT_XLATE_TYPE_IP_ADDR_PRIV_MASK)) {

    if (!(lp->cur_action->action = malloc(sizeof
      (struct ftxlate_act_ip_addr_priv_mask)))) {
      fterr_warn("malloc()");
      return -1;
    }

    bzero(lp->cur_action->action, sizeof
      (struct ftxlate_act_ip_addr_priv_mask));

  } else if ((lp->cur_action->type == FT_XLATE_TYPE_IP_PORT_PRIV_MASK)) {

    if (!(lp->cur_action->action = malloc(sizeof
      (struct ftxlate_act_ip_port_priv_mask)))) {
      fterr_warn("malloc()");
      return -1;
    }

    bzero(lp->cur_action->action, sizeof
      (struct ftxlate_act_ip_port_priv_mask));

  } else if (lp->cur_action->type == FT_XLATE_TYPE_TAG_MASK) {

    if (!(lp->cur_action->action = malloc(sizeof
      (struct ftxlate_act_tag_mask)))) {
      fterr_warn("malloc()");
      return -1;
    }

    bzero(lp->cur_action->action, sizeof (struct ftxlate_act_tag_mask));

  } else if (lp->cur_action->type == FT_XLATE_TYPE_SCALE) {

    if (!(lp->cur_action->action = malloc(sizeof (struct ftxlate_act_scale)))) {
      fterr_warn("malloc()");
      return -1;
    }

    bzero(lp->cur_action->action, sizeof (struct ftxlate_act_scale));

  } else if ((lp->cur_action->type == FT_XLATE_TYPE_SRC_AS) ||
             (lp->cur_action->type == FT_XLATE_TYPE_DST_AS)) {

    if (!(lp->cur_action->action = malloc(sizeof (struct ftxlate_act_asn)))) {
      fterr_warn("malloc()");
      return -1;
    }

    bzero(lp->cur_action->action, sizeof (struct ftxlate_act_asn));

  } else if ((lp->cur_action->type == FT_XLATE_TYPE_IP_SRC_ADDR_ANON) ||
             (lp->cur_action->type == FT_XLATE_TYPE_IP_ADDR_ANON) || 
             (lp->cur_action->type == FT_XLATE_TYPE_IP_DST_ADDR_ANON)) {

    if (!(lp->cur_action->action =
      malloc(sizeof (struct ftxlate_act_ip_addr_anon)))) {
      fterr_warn("malloc()");
      return -1;
    }

    bzero(lp->cur_action->action, sizeof (struct ftxlate_act_ip_addr_anon));

  }


  return 0;

} /* parse_action_type */

/*
 * function: parse_action_mask
 *
 * process the 'mask' line in an action.  Handles the tag-mask
 * ip-address-privacy-mask and port-number-privacy-mask actions.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_action_mask(struct line_parser *lp, struct ftxlate *ftxlate)
{
  struct ftxlate_act_tag_mask *ftxatm;
  struct ftxlate_act_ip_addr_priv_mask *ftxaiapm;
  struct ftxlate_act_ip_port_priv_mask *ftxaippm;
  u_int32 src_mask, dst_mask;
  char *src_maskc, *dst_maskc;

  if (!lp->cur_action->type) {
    fterr_warnx("%s line %d: Must set type first.", lp->fname, lp->lineno);
    return -1;
  }

  if ((lp->cur_action->type != FT_XLATE_TYPE_IP_ADDR_PRIV_MASK) &&
      (lp->cur_action->type != FT_XLATE_TYPE_TAG_MASK) &&
      (lp->cur_action->type != FT_XLATE_TYPE_IP_PORT_PRIV_MASK)) {
    fterr_warnx("%s line %d: Illegal keyword.", lp->fname, lp->lineno);
    return -1;
  }

  ftxatm = lp->cur_action->action;
  ftxaiapm = lp->cur_action->action;
  ftxaippm = lp->cur_action->action;

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting source mask.", lp->fname, lp->lineno);
    return -1;
  }

  src_maskc = lp->word;

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting destination mask.",
    lp->fname, lp->lineno);
    return -1;
  }

  dst_maskc = lp->word;

  src_mask = strtoull(src_maskc, (char**)0L, 0);
  dst_mask = strtoull(dst_maskc, (char**)0L, 0);

  if (lp->cur_action->type == FT_XLATE_TYPE_TAG_MASK) {
    ftxatm->src_mask = src_mask;
    ftxatm->dst_mask = dst_mask;
  } else if (lp->cur_action->type == FT_XLATE_TYPE_IP_ADDR_PRIV_MASK) {
    ftxaiapm->src_mask = src_mask;
    ftxaiapm->dst_mask = dst_mask;
  } else if (lp->cur_action->type == FT_XLATE_TYPE_IP_PORT_PRIV_MASK) {
    ftxaippm->src_mask = src_mask;
    ftxaippm->dst_mask = dst_mask;
  } else {
    fterr_errx(1, "parse_action_match(): internal error");
  }

  return 0;

} /* parse_action_mask */

/*
 * function: parse_action_scale
 *
 * process the 'scale' line in an action.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_action_scale(struct line_parser *lp, struct ftxlate *ftxlate)
{
  struct ftxlate_act_scale *ftxs;

  if (!lp->cur_action->type) {
    fterr_warnx("%s line %d: Must set type first.", lp->fname, lp->lineno);
    return -1;
  }

  if (lp->cur_action->type != FT_XLATE_TYPE_SCALE) {
    fterr_warnx("%s line %d: Illegal keyword.", lp->fname, lp->lineno);
    return -1;
  }

  ftxs = lp->cur_action->action;

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting scale.", lp->fname, lp->lineno);
    return -1;
  }

  ftxs->scale = atoi(lp->word);

  return 0;

} /* parse_action_scale */

/*
 * function: parse_action_asn
 *
 * process the 'as' line in an action.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_action_asn(struct line_parser *lp, struct ftxlate *ftxlate)
{
  struct ftxlate_act_asn *ftxasn;

  if (!lp->cur_action->type) {
    fterr_warnx("%s line %d: Must set type first.", lp->fname, lp->lineno);
    return -1;
  }

  if ((lp->cur_action->type != FT_XLATE_TYPE_SRC_AS) &&
      (lp->cur_action->type != FT_XLATE_TYPE_DST_AS)) {
    fterr_warnx("%s line %d: Illegal keyword.", lp->fname, lp->lineno);
    return -1;
  }

  ftxasn = lp->cur_action->action;

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting AS.", lp->fname, lp->lineno);
    return -1;
  }

  ftxasn->as = atoi(lp->word);

  return 0;

} /* parse_action_asn */

/*
 * function: parse_action_key
 *
 * process the 'key' line in an action.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_action_key(struct line_parser *lp, struct ftxlate *ftxlate)
{
  struct ftxlate_act_ip_addr_anon *ftxiaa;

  if (!lp->cur_action->type) {
    fterr_warnx("%s line %d: Must set type first.", lp->fname, lp->lineno);
    return -1;
  }

  if ((lp->cur_action->type != FT_XLATE_TYPE_IP_ADDR_ANON) &&
      (lp->cur_action->type != FT_XLATE_TYPE_IP_SRC_ADDR_ANON) &&
      (lp->cur_action->type != FT_XLATE_TYPE_IP_DST_ADDR_ANON)) {
    fterr_warnx("%s line %d: Illegal keyword.", lp->fname, lp->lineno);
    return -1;
  }

  ftxiaa = lp->cur_action->action;

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting Key.", lp->fname, lp->lineno);
    return -1;
  }

  if (decode_hex(lp->word, 64, ftxiaa->key, 32) < 0) {
    fterr_warnx("%s line %d: decode_hex() failed.", lp->fname, lp->lineno);
    return -1;
  }

  return 0;

} /* parse_action_key */

/*
 * function: parse_action_key_file
 *
 * process the 'key-file' line in an action.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_action_key_file(struct line_parser *lp, struct ftxlate *ftxlate)
{
  struct ftxlate_act_ip_addr_anon *ftxiaa;

  if (!lp->cur_action->type) {
    fterr_warnx("%s line %d: Must set type first.", lp->fname, lp->lineno);
    return -1;
  }

  ftxiaa = lp->cur_action->action;

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting key-file.", lp->fname, lp->lineno);
    return -1;
  }

  if (!(ftxiaa->key_fname = (char*)malloc(strlen(lp->word)+1))) {
    fterr_warn("malloc()");
    return -1;
  }

  strcpy(ftxiaa->key_fname, lp->word);

  if (load_key_file(ftxiaa->key_fname, (char*)&ftxiaa->key) < 0) {
    fterr_warnx("Failed to load key from %s.", ftxiaa->key_fname);
  }

  return 0;

} /* parse_action_key_file */

/*
 * function: parse_action_algorithm
 *
 * process the 'algorithm' line in an action.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_action_algorithm(struct line_parser *lp, struct ftxlate *ftxlate)
{
  struct ftxlate_act_ip_addr_anon *ftxiaa;

  if (!lp->cur_action->type) {
    fterr_warnx("%s line %d: Must set type first.", lp->fname, lp->lineno);
    return -1;
  }

  ftxiaa = lp->cur_action->action;

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting algorithm.", lp->fname, lp->lineno);
    return -1;
  }

#ifdef HAVE_OPENSSL
  if (strcasecmp(lp->word, "cryptopan-aes128")) {
    fterr_warnx("%s line %d: Expecting CryptoPAn-aes128", lp->fname,
      lp->lineno);
    return -1;
  }
#else
  fterr_warnx("%s line %d: OpenSSL not compiled in.", lp->fname, lp->lineno);
  return -1;
#endif /* HAVE_OPENSSL */

  ftxiaa->algorithm = FT_XLATE_ALG_CRYPTOPAN_AES128;

  return 0;

} /* parse_action_algorithm */

/*
 * function: parse_action_key_refresh
 *
 * process the 'key-refresh' line in an action.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_action_key_refresh(struct line_parser *lp, struct ftxlate *ftxlate)
{
  time_t now, t1;
  struct tm *tm;
  struct ftxlate_act_ip_addr_anon *ftxiaa;
  char *c;
  int hour, min, sec, interval;

  if (!lp->cur_action->type) {
    fterr_warnx("%s line %d: Must set type first.", lp->fname, lp->lineno);
    return -1;
  }

  ftxiaa = lp->cur_action->action;

  /* key-refresh interval start-time */

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting interval.", lp->fname, lp->lineno);
    return -1;
  }

  interval = ftxiaa->key_refresh_interval = atoi(lp->word);

  NEXT_WORD(&lp->buf, lp->word);

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

  now = time((time_t)0L);
  tm = localtime(&now);

  /* calculate start time based on user input? */
  if (hour|min|sec) {

    tm->tm_hour = hour;
    tm->tm_min = min;
    tm->tm_sec = sec;

    t1 = mktime(tm);

    /* start time is always in the future */
    if (t1 < now)
      t1 += 86400;

  /* else it's on next interval minutes */
  } else {

    tm->tm_min = (tm->tm_min / interval)*interval + interval;
    tm->tm_sec = 0;

    if (tm->tm_min >= 60)
      tm->tm_min -= 60;

    t1 = mktime(tm);

    /* start time is always in the future */
    if (t1 < now)
      t1 += 3600; /* minute rollover */

  }

  ftxiaa->key_refresh_next = t1;

  fterr_info("cryptopan key refresh at %lu.", ftxiaa->key_refresh_next);

  return 0;

} /* parse_action_key_refresh */


/*
 * function: parse_def
 *
 * process the 'definition' line.  Each definition has a unique name which
 * is added to the ftxlate->defs linked list.  The current definition is
 * updated in lp.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_def(struct line_parser *lp, struct ftxlate *ftxlate)
{
  struct ftxlate_def *ftx;

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting name.", lp->fname, lp->lineno);
    return -1;
  }

  /* check if it exists */
  FT_SLIST_FOREACH(ftx, &ftxlate->defs, chain) {

    if (!strcasecmp(lp->word, ftx->name)) {
      fterr_warnx("%s line %d: Name (%s) previously defined.", lp->fname,
        lp->lineno, lp->word);
      return -1;
    }

  }

  /* no, add a new entry to the list */
  if (!(ftx = (struct ftxlate_def*)malloc(sizeof
    (struct ftxlate_def)))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftx, sizeof *ftx);

  FT_STAILQ_INIT(&ftx->terms);

  if (!(ftx->name = (char*)malloc(strlen(lp->word)+1))) {
    fterr_warn("malloc()");
    free(ftx);
    return -1;
  }

  strcpy(ftx->name, lp->word);

  FT_SLIST_INSERT_HEAD(&ftxlate->defs, ftx, chain);

  lp->state = PARSE_STATE_DEFINITION;
  lp->cur_def = ftx;
  lp->cur_def_term = ( struct ftxlate_def_term*)0L;

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
int parse_def_term(struct line_parser *lp, struct ftxlate *ftxlate)
{
  struct ftxlate_def_term *ftxt;

  if (!lp->cur_def) {
    fterr_warnx("%s line %d: Must set name first.", lp->fname, lp->lineno);
    return -1;
  }

  /* no, add a new term entry to this definition */
  if (!(ftxt = (struct ftxlate_def_term*)malloc(sizeof *ftxt))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftxt, sizeof *ftxt);

  FT_STAILQ_INIT(&ftxt->actions);

  FT_STAILQ_INSERT_TAIL(&lp->cur_def->terms, ftxt, chain);

  lp->cur_def_term = ftxt;

  return 0;

} /* parse_def_term */

/*
 * function: parse_def_stop
 *
 * process the stop line.  When the filter for this term matches
 * and a 'stop' is defined no further actions are performed.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_def_stop(struct line_parser *lp, struct ftxlate *ftxlate)
{

  if (!lp->cur_def_term) {
    fterr_warnx("%s line %d: Must start term.", lp->fname, lp->lineno);
    return -1;
  }

  lp->cur_def_term->flags |= FT_XLATE_FLAG_STOP;

  return 0;

} /* parse_def_term */


/*
 * function: parse_def_filter
 *
 * process the 'filter' line.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_def_filter(struct line_parser *lp, struct ftxlate *ftxlate)
{

  if (!lp->cur_def_term) {
    fterr_warnx("%s line %d: Must start term.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting filter name.", lp->fname, lp->lineno);
    return -1;
  }

  if (lp->cur_def_term->ftfd) {
    fterr_warnx("%s line %d: Filter previously defined for term.",
    lp->fname, lp->lineno);
    return -1;
  }

  /* delay loading the filters until one is requested */
  if (load_filters(ftxlate)) {
    fterr_warnx("%s line %d: Filters not loaded.", lp->fname, lp->lineno);
    return -1;
  }

  if (!(lp->cur_def_term->ftfd = ftfil_def_find(&ftxlate->ftfil,
    lp->word))) {
    fterr_warnx("%s line %d: Filter definition not found.", lp->fname,
    lp->lineno);
    return -1;
  }

  /* any fields referenced in the filter are now required for the xlate */
  lp->cur_def->xfields |= lp->cur_def_term->ftfd->xfields;

  return 0;

} /* parse_def_filter */

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
int parse_def_action(struct line_parser *lp, struct ftxlate *ftxlate)
{
  struct ftxlate_def_term_actions *ftxta;

  if (!lp->cur_def_term) {
    fterr_warnx("%s line %d: Must start term.", lp->fname, lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);

  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting action.", lp->fname, lp->lineno);
    return -1;
  }

  /* add a new entry to the list */
  if (!(ftxta = (struct ftxlate_def_term_actions*)malloc(sizeof *ftxta))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftxta, sizeof *ftxta);

  if (!(ftxta->name = (char*)malloc(strlen(lp->word)+1))) {
    fterr_warn("malloc()");
    free(ftxta);
    return -1;
  }
  strcpy(ftxta->name, lp->word);

  FT_STAILQ_INSERT_TAIL(&lp->cur_def_term->actions, ftxta, chain);

  /* resolve the ftxta->action later in resolve_actions */

  return 0;

} /* parse_def_action */

/*
 * function: parse_include_filter
 *
 * process the 'include-filter' line.  Allow the default filter location
 * to be changed.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_include_filter(struct line_parser *lp, struct ftxlate *ftxlate)
{
            
  NEXT_WORD(&lp->buf, lp->word);
            
  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting pathname.", lp->fname, lp->lineno);
    return -1;
  }

  if (ftxlate->filter_fname) {
    fterr_warnx("%s line %d: Filter pathname previously specified.",
    lp->fname, lp->lineno);
    return -1;
  }

  if (!(ftxlate->filter_fname = (char*)malloc(strlen(lp->word)+1))) {
    fterr_warn("malloc()");
    return -1;
  }
  strcpy(ftxlate->filter_fname, lp->word);

  return 0;

} /* parse_include_filter */


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
int resolve_actions(struct ftxlate *ftxlate)
{
  struct ftxlate_def *ftx;
  struct ftxlate_def_term *ftxt;
  struct ftxlate_def_term_actions *ftxta;
  struct ftxlate_action *ftxa;
  struct ftxlate_act_ip_addr_anon *ftxiaa;
  int i, found;

  /* foreach action do any additional initialization */
  FT_SLIST_FOREACH(ftxa, &ftxlate->actions, chain) {

    /* *_ANON types need some extra work */
    if ((ftxa->type == FT_XLATE_TYPE_IP_ADDR_ANON) ||
        (ftxa->type == FT_XLATE_TYPE_IP_SRC_ADDR_ANON) ||
        (ftxa->type == FT_XLATE_TYPE_IP_DST_ADDR_ANON)) {

      ftxiaa = ftxa->action;

      /* only supported alg is cryptopan-eas128 */
      if (ftxiaa->algorithm != FT_XLATE_ALG_CRYPTOPAN_AES128) {
        fterr_warnx("Action %s: unknown anonymization algorithm", ftxa->name);
        return -1;
      }

      /* check for key of all 0's */
      found = 0;
      for (i = 0; i < 32; ++i)
        if (ftxiaa->key[i] != 0)
          found = 1;

      if (found == 0) {
        fterr_warnx("Action %s: uninitialized key.", ftxa->name);
        return -1;
      }

      /* initialize cryptopan */
      if (cryptopan_init(&ftxiaa->cp, ftxiaa->key) < 0) {
        fterr_warnx("Action %s: cryptopan_init() failed.", ftxa->name);
        return -1;
      }

      ftxiaa->init = 1;

    } /* *_ANON work */
  }

  /* foreach definition */
  FT_SLIST_FOREACH(ftx, &ftxlate->defs, chain) {

    /* foreach term in the definition */
    FT_STAILQ_FOREACH(ftxt, &ftx->terms, chain) {

      /* foreach action in the term */
      FT_STAILQ_FOREACH(ftxta, &ftxt->actions, chain) {

        found = 0;

        /* foreach action */
        FT_SLIST_FOREACH(ftxa, &ftxlate->actions, chain) {

          if (!(strcasecmp(ftxa->name, ftxta->name))) {

            ftxta->action = ftxa;
            ftx->xfields |= ftxa->xfields;
            found = 1;
            break;

          }

        }

      }

      if (!found) {

        fterr_warnx("Unable to resolve action \"%s\" in xlate-definition \"%s\".", ftxta->name, ftx->name);
        return -1;

      }

    }

  }

  return 0;

} /* resolve actions */

static void eval_ip_src_addr2net(struct ftxlate_action *ftxa,
  char *rec, struct fts3rec_offsets *fo)
{
  struct fts3rec_all2 cur;

  FT_RECGET_SRC_MASK(cur,rec,*fo);

  *((u_int32*)(rec+(*fo).srcaddr)) &= ipv4_len2mask(cur.src_mask);
 
} /* eval_ip_src_addr2net */

static void eval_ip_dst_addr2net(struct ftxlate_action *ftxa,
  char *rec, struct fts3rec_offsets *fo)
{
  struct fts3rec_all2 cur;

  FT_RECGET_DST_MASK(cur,rec,*fo);

  *((u_int32*)(rec+(*fo).dstaddr)) &= ipv4_len2mask(cur.dst_mask);
 
} /* eval_ip_dst_addr2net */

static void eval_ip_src_addr2cnet(struct ftxlate_action *ftxa,
  char *rec, struct fts3rec_offsets *fo)
{
  struct fts3rec_all2 cur;

  FT_RECGET_SRCADDR(cur,rec,*fo);

  if ((cur.srcaddr & 0x80000000) == 0)
    *((u_int32*)(rec+(*fo).srcaddr)) &= 0xFF000000;
  else if ((cur.srcaddr & 0xC0000000) == 0x80000000)
   *((u_int32*)(rec+(*fo).srcaddr)) &= 0xFFFF0000;
  else if ((cur.srcaddr & 0xC0000000) == 0xC0000000)
    *((u_int32*)(rec+(*fo).srcaddr)) &= 0xFFFFFF00;

} /* eval_ip_src_addr2cnet */

static void eval_ip_dst_addr2cnet(struct ftxlate_action *ftxa,
  char *rec, struct fts3rec_offsets *fo)
{
  struct fts3rec_all2 cur;

  FT_RECGET_DSTADDR(cur,rec,*fo);

  if ((cur.dstaddr & 0x80000000) == 0)
    *((u_int32*)(rec+(*fo).dstaddr)) &= 0xFF000000;
  else if ((cur.dstaddr & 0xC0000000) == 0x80000000)
   *((u_int32*)(rec+(*fo).dstaddr)) &= 0xFFFF0000;
  else if ((cur.dstaddr & 0xC0000000) == 0xC0000000)
    *((u_int32*)(rec+(*fo).dstaddr)) &= 0xFFFFFF00;
 
} /* eval_ip_dst_addr2cnet */

static void eval_ip_addr_privacy_mask(struct ftxlate_action *ftxa,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftxlate_act_ip_addr_priv_mask *ftxiapm;

  ftxiapm = ftxa->action;

  *((u_int32*)(rec+(*fo).srcaddr)) &= ftxiapm->src_mask;
  *((u_int32*)(rec+(*fo).dstaddr)) &= ftxiapm->dst_mask;

} /* eval_ip_addr_privacy_mask */

static void eval_ip_port_privacy_mask(struct ftxlate_action *ftxa,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftxlate_act_ip_port_priv_mask *ftxaipm;

  ftxaipm = ftxa->action;

  *((u_int16*)(rec+(*fo).srcport)) &= ftxaipm->src_mask;
  *((u_int16*)(rec+(*fo).dstport)) &= ftxaipm->dst_mask;

} /* eval_ip_port_privacy_mask */

static void eval_tag_mask(struct ftxlate_action *ftxa,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftxlate_act_tag_mask *ftxatm;

  ftxatm = ftxa->action;

  *((u_int32*)(rec+(*fo).src_tag)) &= ftxatm->src_mask;
  *((u_int32*)(rec+(*fo).dst_tag)) &= ftxatm->dst_mask;

} /*  eval_tag_mask */

static void eval_scale(struct ftxlate_action *ftxa,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftxlate_act_scale *ftxs;

  ftxs = ftxa->action;

  *((u_int32*)(rec+(*fo).dOctets)) *= ftxs->scale;
  *((u_int32*)(rec+(*fo).dPkts)) *= ftxs->scale;

} /* eval_scale */

static void eval_src_asn(struct ftxlate_action *ftxa,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftxlate_act_asn *ftxasn;

  if (*((u_int16*)(rec+(*fo).src_as)) == 0) {
    ftxasn = ftxa->action;
    *((u_int16*)(rec+(*fo).src_as)) = ftxasn->as;
  }

} /* eval_src_asn */

static void eval_dst_asn(struct ftxlate_action *ftxa,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftxlate_act_asn *ftxasn;

  if (*((u_int16*)(rec+(*fo).dst_as)) == 0) {
    ftxasn = ftxa->action;
    *((u_int16*)(rec+(*fo).dst_as)) = ftxasn->as;
  }

} /* eval_dst_asn */

static void eval_ip_src_addr_anon(struct ftxlate_action *ftxa,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftxlate_act_ip_addr_anon *ftxiaa;
  u_int32 new;
  time_t now;

  ftxiaa = ftxa->action;

  /* if key_refresh_next is set check for key to be loaded */
  if (ftxiaa->key_refresh_next) {

    now = time((time_t)0L);

    if (now > ftxiaa->key_refresh_next) {

      /* get next interval, handle skipped intervals (no flows to trigger) */
      while (now > ftxiaa->key_refresh_next)
        ftxiaa->key_refresh_next += ftxiaa->key_refresh_interval*60;

      /*
       * load new key and re-init cryptopan.  If key load fails continue
       * using existing key
       */
      if (load_key_file(ftxiaa->key_fname, (char*)&ftxiaa->key) < 0) {

        fterr_warnx("Failed to load key from %s.", ftxiaa->key_fname);

      } else {

        fterr_info("cryptopan key reload from %s successful.  Next refresh at %lu.", ftxiaa->key_fname, ftxiaa->key_refresh_next);

        cryptopan_free(&ftxiaa->cp);

        if (cryptopan_init(&ftxiaa->cp, ftxiaa->key) < 0)
          fterr_warnx("cryptopan_init(): failed.");
        
      }
    }
  } /* refresh key? */

  if (cryptopan_anon(&ftxiaa->cp, *((u_int32*)(rec+(*fo).srcaddr)),
    &new) < 0) {
    fterr_errx(1, "cryptopan_anon(): failed");
  }

  *((u_int32*)(rec+(*fo).srcaddr)) = new;

} /* eval_ip_src_addr_anon */

static void eval_ip_dst_addr_anon(struct ftxlate_action *ftxa,
  char *rec, struct fts3rec_offsets *fo)
{
  struct ftxlate_act_ip_addr_anon *ftxiaa;
  u_int32 new;
  time_t now;

  ftxiaa = ftxa->action;

  /* if key_refresh_next is set check for key to be loaded */
  if (ftxiaa->key_refresh_next) {

    now = time((time_t)0L);

    if (now > ftxiaa->key_refresh_next) {

      /* get next interval, handle skipped intervals (no flows to trigger) */
      while (now > ftxiaa->key_refresh_next)
        ftxiaa->key_refresh_next += ftxiaa->key_refresh_interval*60;

      /*
       * load new key and re-init cryptopan.  If key load fails continue
       * using existing key
       */
      if (load_key_file(ftxiaa->key_fname, (char*)&ftxiaa->key) < 0) {

        fterr_warnx("Failed to load key from %s.", ftxiaa->key_fname);

      } else {

        fterr_info("cryptopan key reload from %s successful.  Next refresh at %lu.", ftxiaa->key_fname, ftxiaa->key_refresh_next);

        cryptopan_free(&ftxiaa->cp);

        if (cryptopan_init(&ftxiaa->cp, ftxiaa->key) < 0)
          fterr_warnx("cryptopan_init(): failed.");
        
      }
    }
  } /* refresh key? */

  if (cryptopan_anon(&ftxiaa->cp, *((u_int32*)(rec+(*fo).dstaddr)),
    &new) < 0) {
    fterr_errx(1, "cryptopan_anon(): failed");
  }

  *((u_int32*)(rec+(*fo).dstaddr)) = new;

} /* eval_ip_dst_addr_anon */

static void eval_ip_addr_anon(struct ftxlate_action *ftxa,
  char *rec, struct fts3rec_offsets *fo)
{

  eval_ip_src_addr_anon(ftxa, rec, fo);
  eval_ip_dst_addr_anon(ftxa, rec, fo);

} /* eval_ip_addr_anon */

/*
 * function: load_filters
 *
 * load the filter definitions if they have not been loaded
 *
 * return value of ftfil_load()
 *
 */
static int load_filters(struct ftxlate *ftxlate)
{
  
  /* work to do? */
  if (ftxlate->ftfil_init)
    return 0;
    
  if (ftfil_load(&ftxlate->ftfil, ftxlate->ftvar, (ftxlate->filter_fname) ?
    ftxlate->filter_fname : FT_PATH_CFG_FILTER)) {
    return 1;
  }
    
  ftxlate->ftfil_init = 1;
  return 0;
    
} /* load_filters */

/* 
 * function: load_key_file
 *
 * load 32 byte hex key from fname
 *
 * returns: 0 okay
 *         -1 fail
 */
static int load_key_file(char *fname, unsigned char *key)
{
  struct stat sb; 
  int fd, ret;
  char *buf;

  buf = (char*)0L;
  ret = -1;

  if ((fd = open(fname, O_RDONLY, 0)) < 0) {
    fterr_warn("open(%s)", fname);
    goto load_key_file_out;
  }

  if (fstat(fd, &sb) < 0) {
    fterr_warn("stat(%s)", fname);
    goto load_key_file_out;
  }
 
  /* allocate storage for file */
  if (!(buf = malloc(sb.st_size+1))) {
    fterr_warn("malloc()");
    goto load_key_file_out;
  }

  /* read in file */
  if (read(fd, buf, sb.st_size) != sb.st_size) {
    fterr_warnx("read(%s): short", fname);
    goto load_key_file_out;
  }

  /* null terminate file */
  buf[sb.st_size] = 0;

  /* only using 64 hex digits */
  if (sb.st_size > 64)
    buf[64] = 0;

  if (decode_hex(buf, 64, key, 32) < 0) {
    fterr_warnx("decode_hex(): failed for %s.", fname);
    goto load_key_file_out;
  }

  ret = 0; /* good */

load_key_file_out:

  if (fd != -1)
    close(fd);

  if (buf)
    free(buf);

  return ret;

} /* load_key_file */


/*
 * function: decode_hex()
 *
 * decode max of in_len bytes from in as hex, store result in out.
 * out is out_len bytes
 *
 * in      - null terminated character string to decode.
 * in_len  - max hex digits to decode (may be > strlen(in)
 * out     - decoded bits
 * out_len - length of out buffer
 *
 * return -1 - error (non hex digit encountered)
 *         0 - successful decode
 *
 */
static int decode_hex(char *in, int in_len, unsigned char *out, int out_len)
{  
  int i, l;
  unsigned char v, odd;

  bzero(out, out_len);
  l = strlen(in);
  odd = 0;
  out += out_len-1;

  if (l > in_len)
    return -1;

  in += l-1;

  for (i = 0; i < l; ++i) {

    if (*in >= '0' && *in <= '9')
      v = *in - '0';
    else if (*in >= 'a' && *in <= 'f')
      v = *in - 'a' + 10;
    else if (*in >= 'A' && *in <= 'F')
      v = *in - 'A' + 10;
    else return -1;

    if (!odd) {
      *out |= v;
    } else {
      *out |= v<<4;
      --out;
    }

    --in;
    odd = odd ? 0 : 1;

  }

  return 0;

} /* decode_hex */

/*
 * cryptopan_* code closely based on Crypto-PAn.1.0 by Jinliang Fan
 *
 * Crypto-PAn copyright:
 *
 * Name of Software: Crypto-PAn, hereafter (Software)
 *
 * Copyright 2002
 * Georgia Tech Research Corporation
 * Atlanta, Georgia 30332.
 * All Rights Reserved
 *
 * The following Software is posted on the Internet by the Georgia
 * Tech Research Corporation (GTRC). It was developed by employees
 * of the Georgia Institute of Technology in the College of Computing.
 * GTRC hereby grants to the user a non-exclusive, royalty-free
 * license to utilize such Software for the User's own purposes
 * pursuant to the following conditions.
 *
 *
 * THE SOFTWARE IS LICENSED ON AN "AS IS" BASIS. GTRC MAKES NO WARRANTY
 * THAT ALL ERRORS CAN BE OR HAVE BEEN ELIMINATED FROM THE SOFTWARE.
 * GTRC SHALL NOT BE RESPONSIBLE FOR LOSSES OF ANY KIND RESULTING FROM
 * THE USE OF THE SOFTWARE AND ITS ACCOMPANYING DOCUMENTATION, AND CAN 
 * IN NO WAY PROVIDE COMPENSATION FOR ANY LOSSES SUSTAINED, INCLUDING 
 * BUT NOT LIMITED TO ANY OBLIGATION, LIABILITY, RIGHT, CLAIM OR REMEDY 
 * FOR TORT, OF FOR ANY ACTUAL OR ALLEGED INFRINGEMENT OF PATENTS, COPYRIGHTS,
 * TRADE SECRETS, OR SIMILAR RIGHTS OF THIRD PARTIES, NOR ANY BUSINESS 
 * EXPENSE, MACHINE DOWNTIME, OR DAMAGES CAUSED LICENSEE BY ANY DEFICIENCY,
 * DEFECT OR ERROR IN THE SOFTWARE OR MALFUNCTION THEREOF, NOR ANY 
 * INCIDENTAL OR CONSEQUENTIAL DAMAGES, HOWEVER CAUSED. GTRC DISCLAIMS
 * ALL WARRANTIES, BOTH EXPRESS AND IMPLIED RESPECTING THE USE AND
 * OPERATION OF THE SOFTWARE AND ANY ACCOMPANYING DOCUMENTATION,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * PARTICULAR PURPOSE AND ANY IMPLIED WARRANTY ARISING FROM COURSE
 * OF PERFORMANCE, COURSE OF DEALING OR USAGE OF TRADE. GTRC MAKES NO
 * WARRANTY THAT THE SOFTWARE IS ADEQUATELY OR COMPLETELY DESCRIBED 
 * IN, OR BEHAVES IN ACCORDANCE WITH ANY OF THE ACCOMPANYING 
 * DOCUMENTATION. THE USER OF THE SOFTWARE IS EXPECTED TO MAKE THE FINAL
 * EVALUATION OF THE SOFTWARE'S USEFULNESS IN USER'S OWN ENVIRONMENT.
 *
 */

/* 
 * function: cryptopan_init
 *
 * Initializes cryptopan structure.  cryptopan_free() must be called
 * to deallocate resources
 *
 * returns: 0 okay
 *         -1 fail
 */
static int cryptopan_init(struct cryptopan *cp, unsigned char *key)
{
#ifdef HAVE_OPENSSL
  int i;

  /* clear */
  bzero(cp, sizeof *cp);

  /* copy in key */
  bcopy(key, cp->m_key, 16);


  /* init crypto */
  if (!(cp->cipher_ctx = (EVP_CIPHER_CTX*) malloc(sizeof(EVP_CIPHER_CTX)))) {
    return -1;
  }

  EVP_CIPHER_CTX_init(cp->cipher_ctx);

  /* disable padding */
  if (!(EVP_CIPHER_CTX_set_padding(cp->cipher_ctx, 0))) {
    cryptopan_free(cp);
    return -1;
  }

  /* init encryption */
  if (!(EVP_EncryptInit(cp->cipher_ctx, EVP_aes_128_ecb(), key, NULL))) {
    cryptopan_free(cp);
    return -1;
  }

  /* set pad */
  i = 16;
  if (!(EVP_EncryptUpdate(cp->cipher_ctx, cp->m_pad, &i, key+16, i))) {
    cryptopan_free(cp);
    return -1;
  }

#endif /* HAVE_OPENSSL */

  return 0;

} /* cryptopan_init */

/* 
 * function: cryptopan_free
 *
 * Frees resources allocated by cryptopan_init()
 *
 * returns: 0 okay
 *         -1 fail
 */
static int cryptopan_free(struct cryptopan *cp)
{

#ifdef HAVE_OPENSSL
  EVP_CIPHER_CTX_cleanup(cp->cipher_ctx);

  if (cp->cipher_ctx)
    free (cp->cipher_ctx);
#endif /* HAVE_OPENSSL */

  return 0;

} /* cryptopan_free */

/* 
 * function: cryptopan_free
 *
 * Anonymize orig_addr, storing result in new_addr
 * see - http://www.cc.gatech.edu/computing/Telecomm/cryptopan/
 *
 * returns: 0 okay
 *         -1 fail
 */
static int cryptopan_anon(struct cryptopan *cp, u_int32_t orig_addr, u_int32_t *new_addr)
{
  u_int8_t rin_output[16];
  u_int8_t rin_input[16];
  u_int8_t *m_pad;
  u_int32_t result, first4bytes_pad, first4bytes_input;
  int i, pos;

  result = 0;
  m_pad = cp->m_pad;

  bcopy(m_pad, rin_input, 16);

  first4bytes_pad = (((u_int32_t) m_pad[0]) << 24) +
                    (((u_int32_t) m_pad[1]) << 16) +
                    (((u_int32_t) m_pad[2]) << 8) +
                    (u_int32_t) m_pad[3]; 

  /*
   * For each prefixes with length from 0 to 31, generate a bit using the
   * Rijndael cipher, which is used as a pseudorandom function here. The
   * bits generated in every rounds are combineed into a pseudorandom
   * one-time-pad.
   */
  for (pos = 0; pos <= 31 ; pos++) { 

    /*
     * Padding: The most significant pos bits are taken from orig_addr.
     * The other 128-pos bits are taken from m_pad. The variables
     * first4bytes_pad and first4bytes_input are used to handle the
     * annoying byte order problem.
     */

    if (pos == 0)
      first4bytes_input =  first4bytes_pad; 
    else
      first4bytes_input = ((orig_addr >> (32-pos)) << (32-pos)) |
        ((first4bytes_pad<<pos) >> pos);

    rin_input[0] = (u_int8_t) (first4bytes_input >> 24);
    rin_input[1] = (u_int8_t) ((first4bytes_input << 8) >> 24);
    rin_input[2] = (u_int8_t) ((first4bytes_input << 16) >> 24);
    rin_input[3] = (u_int8_t) ((first4bytes_input << 24) >> 24);

    /*
     * Encryption: The Rijndael cipher is used as pseudorandom function.
     * During each round, only the first bit of rin_output is used.
     */

    i = 16;
#ifdef HAVE_OPENSSL
    if (!(EVP_EncryptUpdate(cp->cipher_ctx, rin_output, &i, rin_input, i))) {
      cryptopan_free(cp);
      return -1;
    }
#endif /* HAVE_OPENSSL */
    /* Combination: the bits are combined into a pseudorandom one-time-pad */
    result |=  (rin_output[0] >> 7) << (31-pos);

  }

  /* XOR the orginal address with the pseudorandom one-time-pad */
  *new_addr = result ^ orig_addr;

  return 0;

} /* cryptopan_anon */

