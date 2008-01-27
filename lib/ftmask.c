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
 *      $Id: ftmask.c,v 1.3 2003/02/13 02:38:42 maf Exp $
 */

#include "ftconfig.h"
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
static int rn_init_called;
static struct radix_node_head *rhead;

enum ftmask_parse_state { PARSE_STATE_UNSET, PARSE_STATE_DEFINITION };

struct line_parser {
  enum ftmask_parse_state state;
  struct ftmask_def *cur_def;
  int lineno;
  char *buf, *word;
  const char* fname;
  
};

static int walk_free(struct radix_node *rn, struct walkarg *UNUSED);

static int parse_definition(struct line_parser *lp,
  struct ftmask *ftmask);
static int parse_definition_prefix(struct line_parser *lp,
  struct ftmask *ftmask);

#define NEXT_WORD(A,B)\
  for (;;) {\
    B = strsep(A, " \t");\
    if ((B && *B != 0) || (!B))\
      break;\
  }\
 
struct jump {
  char *name;
  enum ftmask_parse_state state;
  int (*func)(struct line_parser *lp, struct ftmask *ftmask);
};

static struct jump pjump[] = {
          {"mask-definition", 0, parse_definition},
          {"prefix", PARSE_STATE_DEFINITION, parse_definition_prefix},
          {0, 0, 0},
          };

/*
 * data structures:
 * 
 *  Each definition is stored in a linked list of struct ftmask_def.  The
 *  head is in struct ftmask.defs.
 *
 *  Each definition stores a radix trie which provides a new mask for
 *  the prefix.
 *
 *  ftmask_eval() will do the substitutions if the field exists in the
 *  flow record.
 *
 */

struct ftmask_prefix_rec {
  struct radix_node rt_nodes[2]; /* radix tree glue */
  struct radix_sockaddr_in addr;
  u_int8 new_mask;
  u_int8 masklen;
};

/*
 *************************************************************************
                              public ftmask_*
 *************************************************************************
 */

/*
 * function: ftmask_load
 *
 * Process fname into ftmask.
 *
 * returns: 0  ok
 *          <0 fail
 */
int ftmask_load(struct ftmask *ftmask, const char *fname)
{
  struct stat sb;
  struct jump *jmp;
  struct line_parser lp;
  int fd, ret, found;
  char *buf, *buf2, *c;

  ret = -1;
  buf = (char*)0L;
  bzero(&lp, sizeof lp);
  bzero(ftmask, sizeof *ftmask);

  if (!rn_init_called) { 
    max_keylen = sizeof(struct radix_sockaddr_in);
    rn_init();
    rn_init_called = 1;
  }

  FT_SLIST_INIT(&ftmask->defs);

  lp.fname = fname;

  if ((fd = open(fname, O_RDONLY, 0)) < 0) {
    fterr_warn("open(%s)", fname);
    goto load_mask_out;
  }

  if (fstat(fd, &sb) < 0) {
    fterr_warn("stat(%s)", fname);
    goto load_mask_out;
  }
  
  /* allocate storage for file */
  if (!(buf = malloc(sb.st_size+1))) {
    fterr_warn("malloc()");
    goto load_mask_out;
  }

  /* read in file */
  if (read(fd, buf, sb.st_size) != sb.st_size) {
    fterr_warnx("read(%s): short", fname);
    goto load_mask_out;
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
      goto load_mask_done;
    }

    lp.buf = c;

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

        if (jmp->func(&lp, ftmask))
          goto load_mask_out;

        NEXT_WORD(&lp.buf, c);

        if (c) {
          fterr_warnx("%s line %d: Unexpected \"%s\".", lp.fname, lp.lineno, c);
          goto load_mask_out;;
        }

        break;

      }

    } /* test each word */

    if (!found) {
      fterr_warnx("%s line %d: Unexpected \"%s\".", lp.fname, lp.lineno, c);
      goto load_mask_out;
    }
   
  } /* more lines */

load_mask_done:

  ret = 0;

load_mask_out:

  if (fd != -1)
    close(fd);

  if (buf)
    free(buf);

  if (ret == -1)
    ftmask_free(ftmask);

  return ret;

} /* ftmask_load */

void ftmask_free(struct ftmask *ftmask)
{
  struct ftmask_def *ftmd;

  /* walk the definition list, free each entry */
  while (!FT_SLIST_EMPTY(&ftmask->defs)) {

    ftmd = FT_SLIST_FIRST(&ftmask->defs);

    if (ftmd->name)
      free (ftmd->name);

    if (ftmd->rhead) {
      rhead = ftmd->rhead;
      rhead->rnh_walktree(rhead, walk_free, 0);
    }

    FT_SLIST_REMOVE_HEAD(&ftmask->defs, chain);

  } /* ftmask->defs */

} /* ftmask_free */

struct ftmask_def *ftmask_def_find(struct ftmask *ftmask, const char *name)
{
  struct ftmask_def *ftmd;
  int found;

  found = 0;

  FT_SLIST_FOREACH(ftmd, &ftmask->defs, chain) {

    if (!strcasecmp(name, ftmd->name))
      return ftmd;

  } /* ftmd */

  return (struct ftmask_def*)0L;

} /* ftmask_def_find */

/*
 * function: ftmask_def_eval
 *
 * Evaluate a flow with a mask definition
 *
 * returns: FT_FIL_MODE_PERMIT or FT_FIL_MODE_DENY
 *          <0 fail
 */
int ftmask_def_eval(struct ftmask_def *active_def,
  char *rec, struct fts3rec_offsets *fo)
{
  struct radix_node_head *rhead;
  struct radix_sockaddr_in sock1;
  struct ftmask_prefix_rec *prefix_rec;

  if ((fo->xfields & FT_XFIELD_SRCADDR) &&
      (fo->xfields & FT_XFIELD_SRC_MASK)) {

    rhead = active_def->rhead;

    sock1.sin_addr.s_addr = *((u_int32*)(rec+fo->srcaddr));
    sock1.sin_len = sizeof sock1;
    sock1.sin_family = AF_INET;

    if ((prefix_rec = (struct ftmask_prefix_rec*)rhead->rnh_matchaddr(
      &sock1, rhead))) {

      *((u_int8*)(rec+fo->src_mask)) = prefix_rec->new_mask;

    }

  }

  if ((fo->xfields & FT_XFIELD_DSTADDR) &&
      (fo->xfields & FT_XFIELD_DST_MASK)) {

    rhead = active_def->rhead;

    sock1.sin_addr.s_addr = *((u_int32*)(rec+fo->dstaddr));
    sock1.sin_len = sizeof sock1;
    sock1.sin_family = AF_INET;

    if ((prefix_rec = (struct ftmask_prefix_rec*)rhead->rnh_matchaddr(
      &sock1, rhead))) {

      *((u_int8*)(rec+fo->dst_mask)) = prefix_rec->new_mask;

    }

  }
  
  return 0;

} /* ftmask_def_eval */

/*
 *************************************************************************
                             parse_definition_*
 *************************************************************************
 */

/*
 * function: parse_definition
 *
 * process the 'mask-definition' line.  Each primitive has a unique name
 * which is added to the ftmask->definitions linked list.  The current
 * definition is updated in lp.
 *
 * returns: 0  ok
 *          <0 fail
 */
int parse_definition(struct line_parser *lp, struct ftmask *ftmask)
{
  char *c;
  struct ftmask_def *ftmd;

  NEXT_WORD(&lp->buf, c);

  if (!c) {
    fterr_warnx("%s line %d: Expecting name.", lp->fname, lp->lineno);
    return -1;
  }

  /* check if it exists */
  FT_SLIST_FOREACH(ftmd, &ftmask->defs, chain) {

    if (!strcasecmp(c, ftmd->name)) {
      fterr_warnx("%s line %d: Name (%s) previously defined.", lp->fname,
        lp->lineno, c);
      return -1;
    }

  }

  /* no, add a new entry to the list */
  if (!(ftmd = (struct ftmask_def*)malloc(sizeof
    (struct ftmask_def)))) {
    fterr_warn("malloc()");
    return -1;
  }

  bzero(ftmd, sizeof *ftmd);

  if (!(ftmd->name = (char*)malloc(strlen(c)+1))) {
    fterr_warn("malloc()");
    free(ftmd);
    return -1;
  }

  strcpy(ftmd->name, c);

  if (rn_inithead((void**)&ftmd->rhead, 32) < 0) {
    fterr_warnx("rn_inithead(): failed");
    free(ftmd->name);
    free(ftmd);
    return -1;
  }

  FT_SLIST_INSERT_HEAD(&ftmask->defs, ftmd, chain);

  lp->state = PARSE_STATE_DEFINITION;
  lp->cur_def = ftmd;

  return 0;

} /* parse_definition */

/*
 * function: parse_definition_prefix
 *
 * process the definition prefix lines
 *
 * returns: 0  ok
 *          <0 fail
 */
static int parse_definition_prefix(struct line_parser *lp,
  struct ftmask *ftmask)
{
  struct radix_sockaddr_in sock1, sock2;
  struct ip_prefix ipp;
  struct ftmask_prefix_rec *prefix_rec;
  u_int8 new_mask;
  char *prefix;
  int new;

  if (!lp->cur_def) {
    fterr_warnx("%s line %d: Not in definition mode.", lp->fname,
    lp->lineno);
    return -1;
  }

  NEXT_WORD(&lp->buf, lp->word);

  prefix = lp->word;
  
  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting prefix.", lp->fname,
    lp->lineno); 
    return -1;
  }

  bzero(&sock1, sizeof sock1);
  bzero(&sock2, sizeof sock2);
  
  sock1.sin_family = AF_INET;
  sock1.sin_len = sizeof (struct radix_sockaddr_in);
  
  sock2.sin_family = AF_INET;
  sock2.sin_len = sizeof (struct radix_sockaddr_in);

  ipp = scan_ip_prefix(lp->word);
  sock1.sin_addr.s_addr = ipp.addr;
  sock2.sin_addr.s_addr = (!ipp.len) ? 0 : mask_lookup[ipp.len];

  rhead = lp->cur_def->rhead;

  NEXT_WORD(&lp->buf, lp->word);
  
  if (!lp->word) {
    fterr_warnx("%s line %d: Expecting mask.", lp->fname,
    lp->lineno); 
    return -1;
  }

  new_mask = atoi(lp->word);

  /* try to retrieve from trie */
  prefix_rec = (struct ftmask_prefix_rec*)rhead->rnh_lookup(&sock1,
    &sock2, rhead);

  new = 1;

  /* if it exists, then invalid */
  if (prefix_rec && (prefix_rec->addr.sin_addr.s_addr == ipp.addr) &&
     (prefix_rec->masklen == ipp.len)) {
 
    fterr_warnx("%s line %d: Only one match.", lp->fname, lp->lineno);   
    return -1;

  }

   /* allocate a new prefix rec */
  if (new) {
  
    if (!(prefix_rec = (struct ftmask_prefix_rec*)malloc(sizeof
      (struct ftmask_prefix_rec)))) {
      fterr_warn("malloc(prefix_rec)");
      return -1;
    }
    
    bzero(prefix_rec, sizeof *prefix_rec);

    prefix_rec->rt_nodes->rn_key = (caddr_t)&prefix_rec->addr;

    prefix_rec->addr.sin_addr.s_addr = ipp.addr;
    prefix_rec->addr.sin_len = sizeof (struct radix_sockaddr_in);
    prefix_rec->addr.sin_family = AF_INET;

    sock1.sin_addr.s_addr = (!ipp.len) ? 0 : mask_lookup[ipp.len];

    prefix_rec->masklen = ipp.len;
    prefix_rec->new_mask = new_mask;

    /* add it to the trie */
    if (!rhead->rnh_addaddr(&prefix_rec->addr, &sock1, rhead,
      prefix_rec->rt_nodes)) {
      free(prefix_rec);
      fterr_warnx("rnh_addaddr(): failed for %s", prefix);
      return -1;
    }

  } /* new */

  return 0;

} /* parse_definition_prefix */

static int walk_free(struct radix_node *rn, struct walkarg *UNUSED)
{
  struct ftmask_prefix_rec *r;
  struct radix_sockaddr_in sock1, sock2;

  r = (struct ftmask_prefix_rec*)rn;
  bzero(&sock1, sizeof sock1);
  bzero(&sock2, sizeof sock2);

  sock1.sin_addr.s_addr = r->addr.sin_addr.s_addr;
  sock1.sin_len = sizeof sock1;
  sock1.sin_family = AF_INET;

  sock2.sin_addr.s_addr = (!r->masklen) ? 0: mask_lookup[r->masklen];
  sock2.sin_len = sizeof sock2;
  sock2.sin_family = AF_INET;

  if (r != (struct ftmask_prefix_rec*)rhead->rnh_deladdr(&sock1,
    &sock2, rhead))
    fterr_errx(1, "rn_deladdr(): failed.");
  else
    free(r);

  return 0;
} /* walk_free */

