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
 *      $Id: ftprof.c,v 1.7 2003/02/13 02:38:42 maf Exp $
 */

#include "ftconfig.h"
#include "ftlib.h"

#include <sys/time.h>
#include <stdio.h>

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif

#if HAVE_INTTYPES_H
# include <inttypes.h> /* C99 uint8_t uint16_t uint32_t uint64_t */
#elif HAVE_STDINT_H
# include <stdint.h> /* or here */
#endif /* else commit suicide. later */

/*
 * function: ftprof_start
 *
 * Call before flow processing to initialize profiling.
 * 
 * returns: < 0 error
 *          >= 0 ok  
*/
int ftprof_start(struct ftprof *ftp)
{
  bzero (ftp, sizeof (struct ftprof));
  return gettimeofday(&ftp->t0, (struct timezone*)0L);
}

/*
 * function: ftprof_end
 *
 * Call after flow processing to finish profiling.
 * 
 * returns: < 0 error
 *          >= 0 ok  
*/
int ftprof_end(struct ftprof *ftp, u_int64 nflows)
{
  int ret;

  if ((ret = gettimeofday(&ftp->t1, (struct timezone*)0L)) == -1)
    return -1;

  if ((ret = getrusage(RUSAGE_SELF, &ftp->r0)) == -1)
    return -1;

  ftp->nflows = nflows;

  return 0;
}

/*
 * function: ftprof_print
 *
 * Dump ftprof contents to std
 * 
 * returns: < 0 error
 *          >= 0 ok  
*/

static void ftprof_print_time(FILE* std, const char * prefix, uint32_t sec, uint32_t usec, uint64_t nflows) {
  fprintf(std, "  %s: seconds=%" PRIu32 ".%-3.3" PRIu32 " flows/second=%f\n",
    prefix, sec, usec/1000, 
    (double) nflows / ((double)sec + ((double)usec/1000000)));
}

void ftprof_print(struct ftprof *ftp, char *prog, FILE *std)
{

  char fmt_buf[256];
  uint32_t usec, sec;

  fmt_uint64(fmt_buf, ftp->nflows, FMT_JUST_LEFT);

  usec = ftp->r0.ru_utime.tv_usec + ftp->r0.ru_stime.tv_usec;
  sec = ftp->r0.ru_utime.tv_sec + ftp->r0.ru_stime.tv_sec;

  if (usec > 1000000)
    usec -= 1000000, ++sec;

  fprintf(std, "%s: processed %s flows\n", prog, fmt_buf);
  ftprof_print_time(std, "sys", sec, usec/1000, ftp->nflows);

  if (ftp->t1.tv_usec < ftp->t0.tv_usec) 
    ftp->t1.tv_usec += 1000000, --ftp->t1.tv_sec;

  usec = ftp->t1.tv_usec - ftp->t0.tv_usec;
  sec = ftp->t1.tv_sec - ftp->t0.tv_sec;

  ftprof_print_time(std, "sys", sec, usec/1000, ftp->nflows);
}

