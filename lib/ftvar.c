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
 *      $Id: ftvar.c,v 1.5 2004/01/05 17:56:19 maf Exp $
 */

#include "ftconfig.h"
#include "ftlib.h"

#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif

/*
 * function: ftvar_new()
 *
 * Create a new variable set.
 *
 * Caller must call ftvar_free() to release memory.
 *
 * returns: initialized struct
 *
 */
int ftvar_new(struct ftvar *ftvar)
{

  bzero(ftvar, sizeof *ftvar);

  FT_SLIST_INIT(&ftvar->entries);

  return 0;

} /* ftvar_new */

/*
 * function: ftvar_free()
 *
 * Free storage created by ftvar_new() and calls to ftvar_set()
 *
 */
void ftvar_free(struct ftvar *ftvar)
{
  struct ftvar_entry *ftve;

  while (!FT_SLIST_EMPTY(&ftvar->entries)) {

    ftve = FT_SLIST_FIRST(&ftvar->entries);

    if (ftve->name)
      free(ftve->name);

    if (ftve->val)
      free(ftve->val);

    FT_SLIST_REMOVE_HEAD(&ftvar->entries, chain);

    free(ftve);

  }

} /* ftvar_free */

/*
 * function: ftvar_pset()
 *
 * Parse variable binding in form VAR=VALUE and perform a set
 *
 * returns <0  error
 *         >=0 ok
 */
int ftvar_pset(struct ftvar *ftvar, char *binding)
{
  char *sm, *n, *v;
  int ret;

  ret = -1;

  /* preserve source string */
  if (!(sm = (char*)malloc(strlen(binding)+1))) {
    fterr_warnx("malloc(%d)", strlen(binding)+1);
    return -1;
  }

  strcpy(sm, binding);

  for (v = sm; *v && (*v != '='); ++v);

  /* end of string reached? */
  if (!*v)
    goto out;

  /* terminate name */
  *v = 0;

  /* value is rest */
  v++;

  /* name is start */
  n = sm;

  ret = ftvar_set(ftvar, n, v);

out:
  free(sm);
  return ret;

} /* ftvar_pset */

/*
 * function: ftvar_set()
 *
 * Add or update variable name with value.
 *
 * returns <0  error
 *         >=0 ok
 */
int ftvar_set(struct ftvar *ftvar, char *name, char *val)
{
  struct ftvar_entry *ftve;
  int new;

  new = 0;

  if ((!*name) || (!name[0]))
    return -1;

  if ((!*val) || (!val[0]))
    return -1;

  /* if the entry exists then this is an update */
  if ((ftve = ftvar_find(ftvar, name))) {

    free(ftve->val);
    ftve->val = (char*)0L;

  } else {

    new = 1;

    if (!(ftve = (struct ftvar_entry*)malloc(sizeof *ftve))) {
      fterr_warnx("malloc(ftve)");
      return -1;
    }

    bzero(ftve, sizeof *ftve);

    if (!(ftve->name = (char*)malloc(strlen(name)+1))) {
      fterr_warnx("malloc(ftve->name)");
      free(ftve);
      return -1;
    }

    strcpy(ftve->name, name);

  }

  /* always allocate the new value */
  if (!(ftve->val = (char*)malloc(strlen(val)+1))) {
    fterr_warnx("malloc(ftve->val)");
    free(ftve->name);
    free(ftve);
    return -1;
  }

  strcpy(ftve->val, val);

  if (new)
    FT_SLIST_INSERT_HEAD(&ftvar->entries, ftve, chain);

  return 0;

} /* ftvar_set */

/*
 * function: ftvar_find()
 *
 * Find an entry by name
 *
 * returns entry or 0L if not found
 */
struct ftvar_entry *ftvar_find(struct ftvar *ftvar, char *name)
{
  struct ftvar_entry *ftve;

  FT_SLIST_FOREACH(ftve, &ftvar->entries, chain) {

    if (!strcmp(ftve->name, name))
      return ftve;

  }

  return (struct ftvar_entry*)0L;

} /* ftvar_find */

/*
 * function: ftvar_clear()
 *
 * Clear/Remove a variable.  Variables which are cleared that do not
 * exist will not produce an error.
 *
 */
void ftvar_clear(struct ftvar *ftvar, char *name)
{
  struct ftvar_entry *ftve;

  if ((ftve = ftvar_find(ftvar, name))) {

    if (ftve->name)
      free(ftve->name);

    if (ftve->val)
      free(ftve->val);

    FT_SLIST_REMOVE(&ftvar->entries, ftve, ftvar_entry, chain);

    free(ftve);

  }

} /* ftvar_clear */

/*
 * function: ftvar_evalstr()
 *
 * Perform variable substitution on string.  Variables start with
 * @ and end with a non alphanumeric character, ie @TEST.
 *
 * If the variable set contains TEST=foo then the evaluated string
 * "This is a @TEST." will result in "This is a foo."
 *
 */
int ftvar_evalstr(struct ftvar *ftvar, char *src, char *dst, int dstlen)
{
  struct ftvar_entry *ftve;
  char *s, *d, *v, *ve, *sm, *tmp;
  int len, ret, inbrace, x;
  char *vexp, *varname, *def;

  d = dst;
  len = 0;
  ret = -1;
  inbrace = 0;
  vexp = (char*)0L;
  sm = (char*)0L;
  def = (char*)0L;

  /* preserve source string */
  if (!(sm = (char*)malloc(strlen(src)+1))) {
    fterr_warnx("ftvar: malloc(%d)", strlen(src)+1);
    return -1;
  }

  s = sm;

  strcpy(s, src);

  while (1) {

    /* end of source string? */
    if (!*s) {
      ret = 0;
      goto done;
    }

    /* end of dst buf? */
    if ((len+1) == dstlen)
      goto done;

    /* start of var? */
    if (*s == '@') {

      /* variable starts after the @ */
      v = ++s;

      /* end of variable initialized to start */
      ve = v;

      /* is variable in a brace? yes then must end on a brace */
      if (*v && (*v == '{')) {

        inbrace = 1;

        while (*ve && (*ve != '}'))
          ++ve;

        if (*ve != '}')
          fterr_errx(1, "ftvar: %s: Missing }", v);

        ++ve;

      /* else it ends on the first non alphanumeric char */
      } else {

        while (*ve && isalnum(*ve))
          ++ve;

      }

      /* copy out the variable expression, braces and all */
      x = ve - v;
      if (!(vexp = (char*)malloc(x+1)))
        fterr_errx(1, "ftvar: malloc(%d)", x+1);

      strncpy(vexp, v, x);
      vexp[x] = 0;

      /*
       * either have form !inbrace VARIABLE
       *    or
       * inbrace VARIABLE:-foo
       *
       * if it's the former can just proceed with substitution.
       *
       * The latter requires checking for the :, processing the
       * command (now only -) if the variable substitution fails
       *
       * there's also a special case of @{VAR}
       */

      varname = vexp;

      if (inbrace) {

        /* skip over opening brace */
        ++varname;

        /* find the first non alphanumeric */
        tmp = varname;
        while (*tmp && isalnum(*tmp))
          ++tmp;

        /* if its an end brace then done with special processing */
        if (*tmp == '}') {
          *tmp = 0;
          goto skipspecial;
        }

        /* better be a : */
        if (*tmp != ':')
          fterr_errx(1, "ftvar: %s: missing :", vexp);

        /* : to null so the variable name is null terminated */
        *tmp++ = 0;

        /* only special type is - (default) */

        if (*tmp != '-')
          fterr_errx(1, "ftvar: %s: expecting -", vexp);

        /* default expression is after the - */
        def = ++tmp;

        /* drop the trailing } */
        while (*tmp && *tmp != '}')
          ++tmp;
        *tmp = 0;

      }

skipspecial:

      /* lookup var */
      if ((ftve = ftvar_find(ftvar, varname)))
        tmp = ftve->val; /* found it, copy in the value */
      else
        tmp = (def) ? def : (char*)0L;

      /* got a substitution */
      if (tmp)
        while (*tmp && ((len+1) != dstlen))
          d[len++] = *tmp++;

      /* end of dst buf? */
      if ((len+1) == dstlen)
        goto done;

      /* skip variable name in original string */
      s = ve;

      /* reset */
      inbrace = 0;
      def = (char*)0L;
      if (vexp)
        free(vexp);
      vexp = (char*)0L;

    } else {

      d[len++] = *s++; /* no, copy */

      /* end of dst buf? */
      if ((len+1) == dstlen)
        goto done;

    }
    
  }

  ret = 0;

done:

  dst[len] = 0;

  if (sm)
    free(sm);

  if (vexp)
    free(vexp);

  return ret;

} /* ftvar_evalstr */

