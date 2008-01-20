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
 *      $Id: ftsym.c,v 1.5 2003/04/26 03:12:03 maf Exp $
 */

#include "ftconfig.h"

#if HAVE_INTTYPES_H
# include <inttypes.h> /* C99 uint8_t uint16_t uint32_t uint64_t */
#elif HAVE_STDINT_H
# include <stdint.h> /* or here */
#endif /* else commit suicide. later */

#include "ftlib.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <ctype.h>
#include <stddef.h>
#include <stdlib.h>

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif


/*
 * function: ftsym_new
 *
 *   allocate and initialize new symbol table structure
 *
 * fname - filename to load ASCII table
 * returns allocated structure or 0L for error.
 *
 */
struct ftsym *ftsym_new(const char *fname)
{
  struct stat sb;
  struct ftsym *ftsym;
  struct ftchash_rec_sym ftch_recsym, *ftch_recsymp;
  char *c, *buf, *end;
  int fd, ret;
  uint32_t hash;

  /* no filename? */
  if (!fname)
    return (struct ftsym*)0L;

  fd = -1;
  ret = -1;

  /* allocate ftsym structure */
  if (!(ftsym = (struct ftsym*)malloc(sizeof (struct ftsym)))) {
    fterr_warn("malloc(struct ftsym)");
    goto ftsym_new_out;
  }

  /* init */
  bzero(ftsym, sizeof (struct ftsym));
  bzero(&ftch_recsym, sizeof ftch_recsym);

  if ((fd = open(fname, O_RDONLY, 0)) < 0) {
    fterr_warn("open(%s)", fname);
    goto ftsym_new_out;
  }

  if (fstat(fd, &sb) < 0) {
    fterr_warn("stat(%s)", fname);
    goto ftsym_new_out;
  }
  
  /* allocate storage for file */
  if (!(ftsym->fbuf = malloc(sb.st_size+1))) {
    fterr_warn("malloc()");
    goto ftsym_new_out;
  }

  /*
   * file format:
   *
   * value<white space>symbol\n
   * # comment\n
   */

  /* read in file */
  if (read(fd, ftsym->fbuf, sb.st_size) != sb.st_size) {
    fterr_warnx("read(): short");
    goto ftsym_new_out;
  }

  /* null terminate file */
  ftsym->fbuf[sb.st_size] = 0;

  /* init hash table */
  if (!(ftsym->ftch = ftchash_new(4096, sizeof (struct ftchash_rec_sym),
    4, 256))) {
    fterr_warnx("ftchash_new(): failed");
    goto ftsym_new_out;
  }

  buf = ftsym->fbuf;
  c = buf;

  for (;;) {

    /* skip to first char */
    for (; *buf && isspace((int)*buf); ++buf);

    /* done? */
    if (!*buf)
      break;

    /* comment line */
    if (*buf == '#') {
      for (; *buf && *buf != '\n'; ++buf);
      continue;
    }

    /* at first token (value), null terminate it */
    c = buf;
    for (; *c && !isspace((int)*c); ++c);
    if (!*c) {
      fterr_warnx("Missing field");
      goto ftsym_new_out;
    }
    *c = 0;
    ftch_recsym.val = strtoul(buf, (char **)0L, 0);

    /* compute hash */
    hash = ((ftch_recsym.val>>16) ^ (ftch_recsym.val & 0xFFFF)) & 0x0FFF;

    /* store it in hash table */
    if (!(ftch_recsymp = ftchash_update(ftsym->ftch, &ftch_recsym, hash))) {
      fterr_warnx("ftch_update(): failed");
      goto ftsym_new_out;
    }

    buf = ++c;

    /* skip past white space */
    for (; *buf && ((*buf == ' ') || (*buf == '\t')); ++buf);
    if (!*buf) {
      fterr_warnx("Missing field");
      goto ftsym_new_out;
    }

    c = buf;

    /* skip to next token (name), null terminate it */
    for (; *c && (*c != '\n'); ++c);

    /* prime for next line */
    end = c;
    if (*end)
      ++end;

    *c = 0;

    /* backup over trailing white space */
    --c;
    for (; isspace((int)*c);--c);

    /* update hash rec to point at string */
    ftch_recsymp->str = buf;

    buf = end;
 
  }

  ret = 0; /* good */

ftsym_new_out:

  if (fd != -1)
    close(fd);

  if (ret != 0) {

    if (ftsym) {

      if (ftsym->fbuf)
        free(ftsym->fbuf);

      if (ftsym->ftch)
        ftchash_free(ftsym->ftch);

      free(ftsym);
      ftsym = (struct ftsym*)0L;

    }

  }

  return ftsym;

} /* ftsym_new */

/*
 * function: ftsym_findbyname
 *
 * lookup entry by name (linear search)
 *
 * returns pointer to record found or null if not found.
 */
int ftsym_findbyname(struct ftsym *ftsym, const char *name, uint32_t *val)
{
  struct ftchash_rec_sym *ftch_recsymp;

  if (!ftsym)
    return 0;

  ftchash_first(ftsym->ftch);

  while ((ftch_recsymp = ftchash_foreach(ftsym->ftch))) {

    if (!strcasecmp(ftch_recsymp->str, name)) {
      *val = ftch_recsymp->val;
      return 1;
    }

  }

  return 0;

} /* ftsym_findbyname */

/*
 * function: ftsym_findbyval
 *
 * lookup entry by value (hashed search)
 *
 * returns pointer to record found or null if not found.
 */
int ftsym_findbyval(struct ftsym *ftsym, uint32_t val, char **name)
{
  struct ftchash_rec_sym *ftch_recsymp;
  uint32_t hash;

  if (!ftsym)
    return 0;

  hash = ((val>>16) ^ (val & 0xFFFF)) & 0x0FFF;

  if (!(ftch_recsymp = ftchash_lookup(ftsym->ftch, &val, hash)))
    return 0;

  *name = ftch_recsymp->str;
  return 1;

} /* ftsym_findbyval */

/*
 * function: ftsym_free
 *
 *   free resources allocated by ftsym_init
 *
 */
void ftsym_free(struct ftsym *ftsym)
{
  if (ftsym) {

    if (ftsym->fbuf)
      free(ftsym->fbuf);

    if (ftsym->ftch)
      ftchash_free(ftsym->ftch);

    free(ftsym);

  }
} /* ftsym_free */

