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
 *      $Id: fterr.c,v 1.9 2003/02/13 02:38:41 maf Exp $
 */

#include "ftconfig.h"
#include "ftlib.h"

#include <errno.h>
#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif


#define FTERR_FILE   1
#define FTERR_SYSLOG 2

static int fterr_flags = FTERR_FILE;
static FILE *fterr_file;
static char *fterr_id = "";
static void (*fterr_exit)(int);

void fterr_setexit(void (*f)(int))
{
        fterr_exit = f;
} /* fterr_set_exit */


void fterr_setid(char *id)
{
  char *c;

  /* skip to end */
  for (c = id; *c; ++c);

  /* skip back to first / or begining */
  for (; (c != id) && (*c != '/'); --c);

  if (c != id)
    fterr_id = c+1;
  else
    fterr_id = c;

}

void fterr_setfile(int enable, void *fp)
{
  if (enable) {
    fterr_flags |= FTERR_FILE;
    fterr_file = fp;
  }
  else
    fterr_flags &= ~FTERR_FILE;
}

void fterr_setsyslog(int enable, int logopt, int facility)
{
  if (enable) {
    fterr_flags |= FTERR_SYSLOG;
    openlog(fterr_id, logopt, facility);
  } else {
    if (fterr_flags & FTERR_SYSLOG)
      closelog();
    fterr_flags &= ~FTERR_SYSLOG;
  }
}

void fterr_info(const char *fmt, ...)
{
  va_list ap;
  char buf[1025];
  char buf2[1025];
 
  va_start(ap, fmt);
  vsnprintf(buf, (size_t)1024, fmt, ap);
  va_end(ap);

  snprintf(buf2, 1024, "%s: %s", fterr_id, buf);

  if (fterr_flags & FTERR_FILE)
    fprintf(((fterr_file) ? fterr_file : stderr), "%s\n", buf2);

  if (fterr_flags & FTERR_SYSLOG)
    syslog(LOG_INFO, buf);

} /* fterr_info */

void fterr_err(int code, const char *fmt, ...)
{
  va_list ap;
  char buf[1025];
  char buf2[1025];
 
  va_start(ap, fmt);
  vsnprintf(buf, (size_t)1024, fmt, ap);
  va_end(ap);


  if (fterr_flags & FTERR_FILE) {
    snprintf(buf2, 1024, "%s: %s: %s", fterr_id, buf, strerror(errno));
    fprintf(((fterr_file) ? fterr_file : stderr), "%s\n", buf2);
  }

  if (fterr_flags & FTERR_SYSLOG) {
    snprintf(buf2, 1024, "%s: %s", buf, strerror(errno));
    syslog(LOG_INFO, buf2);
  }

  if (fterr_exit)
    fterr_exit(code);
  exit (code);

} /* fterr_err */

void fterr_errx(int code, const char *fmt, ...)
{
  va_list ap;
  char buf[1025];
  char buf2[1025];
 
  va_start(ap, fmt);
  vsnprintf(buf, (size_t)1024, fmt, ap);
  va_end(ap);

  if (fterr_flags & FTERR_FILE) {
    snprintf(buf2, 1024, "%s: %s", fterr_id, buf);
    fprintf(((fterr_file) ? fterr_file : stderr), "%s\n", buf2);
  }

  if (fterr_flags & FTERR_SYSLOG)
    syslog(LOG_INFO, buf);

  if (fterr_exit)
    fterr_exit(code);
  exit (code);

} /* fterr_errx */

void fterr_warnx(const char *fmt, ...)
{
  va_list ap;
  char buf[1025];
  char buf2[1025];
 
  va_start(ap, fmt);
  vsnprintf(buf, (size_t)1024, fmt, ap);
  va_end(ap);

  if (fterr_flags & FTERR_FILE) {
    snprintf(buf2, 1024, "%s: %s", fterr_id, buf);
    fprintf(((fterr_file) ? fterr_file : stderr), "%s\n", buf2);
  }

  if (fterr_flags & FTERR_SYSLOG)
    syslog(LOG_INFO, buf);

} /* fterr_warnx */

void fterr_warn(const char *fmt, ...)
{
  va_list ap;
  char buf[1025];
  char buf2[1025];
 
  va_start(ap, fmt);
  vsnprintf(buf, (size_t)1024, fmt, ap);
  va_end(ap);


  if (fterr_flags & FTERR_FILE) {
    snprintf(buf2, 1024, "%s: %s: %s", fterr_id, buf, strerror(errno));
    fprintf(((fterr_file) ? fterr_file : stderr), "%s\n", buf2);
  }

  if (fterr_flags & FTERR_SYSLOG) {
    snprintf(buf2, 1024, "%s: %s", buf, strerror(errno));
    syslog(LOG_INFO, buf2);
  }

} /* fterr_warn */

