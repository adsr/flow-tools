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
 *      $Id: ftxfield.c,v 1.2 2003/02/13 02:38:43 maf Exp $
 */

#include "ftconfig.h"
#include "ftlib.h"

#include <stdlib.h>

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
 
#if HAVE_STRING_H
  #include <string.h>
#endif

#if !HAVE_STRSEP
  char    *strsep (char **, const char *);
#endif

struct ftxfield_table ftxfield_table[] = {
  {FT_XFIELD_ASC_UNIX_SECS, FT_XFIELD_UNIX_SECS},
  {FT_XFIELD_ASC_UNIX_NSECS, FT_XFIELD_UNIX_NSECS},
  {FT_XFIELD_ASC_SYSUPTIME, FT_XFIELD_SYSUPTIME},
  {FT_XFIELD_ASC_EXADDR, FT_XFIELD_EXADDR},
  {FT_XFIELD_ASC_DFLOWS, FT_XFIELD_DFLOWS},
  {FT_XFIELD_ASC_DPKTS, FT_XFIELD_DPKTS},
  {FT_XFIELD_ASC_DOCTETS, FT_XFIELD_DOCTETS},
  {FT_XFIELD_ASC_FIRST, FT_XFIELD_FIRST},
  {FT_XFIELD_ASC_LAST, FT_XFIELD_LAST},
  {FT_XFIELD_ASC_ENGINE_TYPE, FT_XFIELD_ENGINE_TYPE},
  {FT_XFIELD_ASC_ENGINE_ID, FT_XFIELD_ENGINE_ID},
  {FT_XFIELD_ASC_SRCADDR, FT_XFIELD_SRCADDR},
  {FT_XFIELD_ASC_DSTADDR, FT_XFIELD_DSTADDR},
  {FT_XFIELD_ASC_NEXTHOP, FT_XFIELD_NEXTHOP},
  {FT_XFIELD_ASC_INPUT, FT_XFIELD_INPUT},
  {FT_XFIELD_ASC_OUTPUT, FT_XFIELD_OUTPUT},
  {FT_XFIELD_ASC_SRCPORT, FT_XFIELD_SRCPORT},
  {FT_XFIELD_ASC_DSTPORT, FT_XFIELD_DSTPORT},
  {FT_XFIELD_ASC_PROT, FT_XFIELD_PROT},
  {FT_XFIELD_ASC_TOS, FT_XFIELD_TOS},
  {FT_XFIELD_ASC_TCP_FLAGS, FT_XFIELD_TCP_FLAGS},
  {FT_XFIELD_ASC_SRC_MASK, FT_XFIELD_SRC_MASK},
  {FT_XFIELD_ASC_DST_MASK, FT_XFIELD_DST_MASK},
  {FT_XFIELD_ASC_SRC_AS, FT_XFIELD_SRC_AS},
  {FT_XFIELD_ASC_DST_AS, FT_XFIELD_DST_AS},
  {FT_XFIELD_ASC_IN_ENCAPS, FT_XFIELD_IN_ENCAPS},
  {FT_XFIELD_ASC_OUT_ENCAPS, FT_XFIELD_OUT_ENCAPS},
  {FT_XFIELD_ASC_PEER_NEXTHOP, FT_XFIELD_PEER_NEXTHOP},
  {FT_XFIELD_ASC_ROUTER_SC, FT_XFIELD_ROUTER_SC},
  {FT_XFIELD_ASC_MARKED_TOS, FT_XFIELD_MARKED_TOS},
  {FT_XFIELD_ASC_EXTRA_PKTS, FT_XFIELD_EXTRA_PKTS},
  {FT_XFIELD_ASC_SRC_TAG, FT_XFIELD_SRC_TAG},
  {FT_XFIELD_ASC_DST_TAG, FT_XFIELD_DST_TAG},
  {(char*)0L, 0LL},
};


/*
 * function: parse_xfield
 *
 * convert an ascii xfield representation to binary
 *
 * returns 0  ok
 *         <0 fail
 */

int ftxfield_parse(char *line, uint64_t *xfields)
{
  extern struct ftxfield_table ftxfield_table[];
  char *c, *p, *save;
  int i, ret, match;

  ret = -1;
  *xfields = 0L;
  save = (char*)0L;

  /* make a local copy of the string since it will be modified */
  if (!(p = malloc(strlen(line)+1))) {
    fterr_warnx("malloc()");
    goto parse_xfield_out;
  }

  strcpy(p, line);
  c = save = p;

  while (c) {

    c = strsep(&p, ",");

    if (!c)
      break;

    for (i = match = 0; ftxfield_table[i].name; ++i) {

      if (!strcasecmp(c, ftxfield_table[i].name)) {

        /* implication other code can output the fields twice */
        if (ftxfield_table[i].val & *xfields) {
          fterr_warnx("Duplicate field: %s", c);
          goto parse_xfield_out;
        }

        /*
         *  specifying these out of order implies they would be displayed as
         *  such which is not the case.
         */
        if (ftxfield_table[i].val < *xfields) {
          fterr_warnx("Out of order field: %s", c);
          goto parse_xfield_out;
        }

        *xfields |= ftxfield_table[i].val;
        match = 1;
        break;
      }

    } /* for */

    if (!match) {
      fterr_warnx("Unrecognized field: %s", c);
      goto parse_xfield_out;
    } 

  } /* while */

  ret = 0;

parse_xfield_out:

  if (save)
    free(save);

  return ret;

} /* ftxfield_parse */
