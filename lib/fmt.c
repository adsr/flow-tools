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
 *      $Id: fmt.c,v 1.17 2003/03/06 22:57:25 maf Exp $
 */

#include "ftinclude.h"
#include "ftlib.h"

#include <netdb.h>

unsigned int fmt_uint8(char *s, uint8_t u, int format)
{
  int len = 0;
  char *s1;

  if (!s)
    return 0;

  s1 = s;

  s += FMT_UINT8 - 1;
  do {

    ++len;
    *--s = '0' + (u % 10);
    u /= 10;

  } while(u); 

  if ((format == FMT_PAD_RIGHT) || (format == FMT_JUST_LEFT)) {
    bcopy(s, s1, len);
    if (format == FMT_PAD_RIGHT)
      for (; len < (FMT_UINT8 - 1); ++len)
        s1[len] = ' ';
    s1[len] = 0;
    return len;
  }

  return len;

} /* fmt_uint8 */

unsigned int fmt_uint16s(struct ftsym *ftsym, int max, char *s, uint16_t u,
  int format)
{
  int ret;
  char *str;

  if (ftsym && ftsym_findbyval(ftsym, (uint32_t) u, &str) == 1) {

    strncpy(s, str, max);
    s[max-1] = 0;

    ret = strlen(s);

    if (format == FMT_PAD_RIGHT)
      for (; ret < (max-1); ++ret)
        s[ret] = ' ';

    if (format == FMT_PAD_RIGHT)
      return max-1;
    else
      return ret;

  } else {
    return fmt_uint16(s, u, format);
  }

} /* fmt_uint16s */

unsigned int fmt_uint8s(struct ftsym *ftsym, int max, char *s, uint8_t u,
  int format)
{
  int ret;
  char *str;

  if (ftsym && ftsym_findbyval(ftsym, (uint32_t) u, &str) == 1) {

    strncpy(s, str, max);
    s[max-1] = 0;

    ret = strlen(s);

    if (format == FMT_PAD_RIGHT)
      for (; ret < (max-1); ++ret)
        s[ret] = ' ';

    if (format == FMT_PAD_RIGHT)
      return max-1;
    else
      return ret;

  } else {
    return fmt_uint8(s, u, format);
  }

} /* fmt_uint8s */

unsigned int fmt_uint32s(struct ftsym *ftsym, int max, char *s, uint32_t u,
  int format)
{
  int ret;
  char *str;

  if (ftsym && ftsym_findbyval(ftsym, (uint32_t) u, &str) == 1) {

    strncpy(s, str, max);
    s[max-1] = 0;

    ret = strlen(s);

    if (format == FMT_PAD_RIGHT)
      for (; ret < (max-1); ++ret)
        s[ret] = ' ';

    if (format == FMT_PAD_RIGHT)
      return max-1;
    else
      return ret;

  } else {
    return fmt_uint32(s, u, format);
  }

} /* fmt_uint32s */


unsigned int fmt_uint16(char *s, uint16_t u, int format)
{
  int len = 0;
  char *s1;

  if (!s)
    return 0;

  s1 = s;

  s += FMT_UINT16 - 1;
  do {

    ++len;
    *--s = '0' + (u % 10);
    u /= 10;

  } while(u); 

  if ((format == FMT_PAD_RIGHT) || (format == FMT_JUST_LEFT)) {
    bcopy(s, s1, len);
    if (format == FMT_PAD_RIGHT)
      for (; len < (FMT_UINT16 - 1); ++len)
        s1[len] = ' ';
    s1[len] = 0;
    return len;
  }

  return len;

} /* fmt_uint16_t */



unsigned int fmt_uint32(char *s, uint32_t u, int format)
{
  int len = 0;
  char *s1;
  int i;

  if (!s)
    return 0;

  s1 = s;

  s += FMT_UINT32 - 1;
  do {

    ++len;
    *--s = '0' + (u % 10);
    u /= 10;

  } while(u); 

  if ((format == FMT_PAD_RIGHT) || (format == FMT_JUST_LEFT)) {
    bcopy(s, s1, len);
    if (format == FMT_PAD_RIGHT)
      for (; len < (FMT_UINT32 - 1); ++len)
        s1[len] = ' ';
    s1[len] = 0;
    return len;
  }

  if (format == FMT_PAD_LEFT) {
    for (i = 0; i < ((FMT_UINT32 - 1) - len); ++i)
      s1[i] = ' ';
    s1[(FMT_UINT32 - 1)] = 0;
    return (FMT_UINT32 - 1);
  }

  return 0;

} /* fmt_uint32 */

unsigned int fmt_uint64(char *s, uint64_t u, int format)
{
  int len = 0;
  char *s1;
  int i;

  if (!s)
    return 0;

  s1 = s;

  s += FMT_UINT64 - 1;

  do {

    ++len;
    *--s = '0' + (u % 10);
    u /= 10;

  } while(u); 

  if ((format == FMT_PAD_RIGHT) || (format == FMT_JUST_LEFT)) {
    bcopy(s, s1, len);
    if (format == FMT_PAD_RIGHT)
      for (; len < (FMT_UINT64 - 1); ++len)
        s1[len] = ' ';
    s1[len] = 0;
    return len;
  }

  if (format == FMT_PAD_LEFT) {
    for (i = 0; i < ((FMT_UINT64 - 1) - len); ++i)
      s1[i] = ' ';
    s1[(FMT_UINT64 - 1)] = 0;
    return (FMT_UINT64 - 1);
  }

  return 0;

} /* fmt_uint64 */

unsigned int fmt_ipv4s(char *s, uint32_t u, int len,
  int format)
{
  struct sockaddr_in in;
  struct hostent *he;

  /* need at least this much */
  if (len < FMT_IPV4) {
    if (len > 0)
      s[0] = 0;
    return 0;
  }

  /* symbol lookups disabled? */
  if (!(format & FMT_SYM))
    return fmt_ipv4(s, u, format);

  in.sin_addr.s_addr = htonl(u);

  if (!(he = gethostbyaddr((char*)&in.sin_addr.s_addr,
    sizeof (in.sin_addr.s_addr), AF_INET)))
    return fmt_ipv4(s, u, format);

  strncpy(s, he->h_name, len);
  s[len-1] = 0;

  return (strlen(s));

} /* fmt_ipv4s */

unsigned int fmt_ipv4(char *s, uint32_t u, int format)
{
  int len = 0;
  char *s1;
  int i, j;
  uint8_t e[4];
  char c[4][4];

  if (!s)
    return 0;

  j = 0;

  e[0] = (u & 0xFF000000)>>24; e[1] = (u & 0x00FF0000)>>16;
  e[2] = (u & 0x0000FF00)>>8; e[3] = (u & 0x000000FF);

  for (i = 0; i < 4; ++i) {
    s1 = &c[i][3];
    len = 0;
    do {
      ++len;
      *--s1 = '0' + (e[i] % 10);
      e[i] /= 10;
    } while(e[i]); 

    bcopy(s1, s+j, len);
    j += len;
    *(s+j) = '.';
    ++j;
  }

  --j;
  s[j] = 0;

  if (format == FMT_JUST_LEFT)
    return j;

  if (format == FMT_PAD_RIGHT) {
    for (; j < (FMT_IPV4-1); ++j)
      s[j] = ' ';
    s[j] = 0;
    return (FMT_IPV4-1);
  }

  if (format == FMT_JUST_RIGHT) {
    bcopy(s, s+(FMT_IPV4-1)-j, j);
    for (i = 0; i < (FMT_IPV4-1)-j; ++i)
      s[i] = ' ';
    s[FMT_IPV4-1] = 0;
    return (FMT_IPV4-1);
  }

  return j;

} /* fmt_ipv4 */

unsigned int fmt_ipv4prefixs(char *s, uint32_t u, 
  unsigned char mask, int len, int format)
{
  struct sockaddr_in in;
  struct hostent *he;

  /* need at least this much */
  if (len < FMT_IPV4_PREFIX) {
    if (len > 0)
      s[0] = 0;
    return 0;
  }

  /* symbol lookups disabled? */
  if (!(format & FMT_SYM))
    return fmt_ipv4prefix(s, u, mask, format);

  in.sin_addr.s_addr = htonl(u & ipv4_len2mask(mask));

  if (!(he = gethostbyaddr((char*)&in.sin_addr.s_addr,
    sizeof (in.sin_addr.s_addr), AF_INET)))
    return fmt_ipv4(s, u, format);

  strncpy(s, he->h_name, len);
  s[len-1] = 0;

  return (strlen(s));

} /* int fmt_ipv4prefixs */

unsigned int fmt_ipv4prefix(char *s, uint32_t u, 
  unsigned char mask, int format)
{
  int len = 0;
  char *s1;
  int i, j, k, done;
  uint8_t e[4];
  char c[5][4];

  if (!s)
    return 0;

  j = 0;
  done = 0;

  if (mask > 32)
    mask = 0;

  e[0] = (u & 0xFF000000)>>24; e[1] = (u & 0x00FF0000)>>16;
  e[2] = (u & 0x0000FF00)>>8; e[3] = (u & 0x000000FF);

  for (i = 0; i < 4; ++i) {

    s1 = &c[i][3];

    /* check for last octets are all 0, make sure to encode at least one 0 */
    if (i > 0)
      for (done = 1, k = 1; k < 4; ++k)
        if (e[k] != 0)
          done = 0;

    if (done)
      break;

    len = 0;
    do {
      ++len;
      *--s1 = '0' + (e[i] % 10);
      e[i] /= 10;
    } while(e[i]); 

    bcopy(s1, s+j, len);
    j += len;
    *(s+j) = '.';
    ++j;
  }

  /* backup over the last . and replace with / */
  --j;
  s[j++] = '/';

  s1 = &c[4][3];
  len = 0;
  do {
    ++len;
    *--s1 = '0' + (mask % 10);
    mask /= 10;
  } while(mask); 
  bcopy(s1, s+j, len);
  j += len;

  s[j] = 0;

  if (format == FMT_JUST_LEFT)
    return j;

  if (format == FMT_PAD_RIGHT) {
    for (; j < (FMT_IPV4_PREFIX-1); ++j)
      s[j] = ' ';
    s[j] = 0;
    return (FMT_IPV4_PREFIX-1);
  }

  if (format == FMT_JUST_RIGHT) {
    bcopy(s, s+(FMT_IPV4_PREFIX-1)-j, j);
    for (i = 0; i < (FMT_IPV4_PREFIX-1)-j; ++i)
      s[i] = ' ';
    s[FMT_IPV4_PREFIX-1] = 0;
    return (FMT_IPV4_PREFIX-1);
  }

  return j;

} /* fmt_ipv4prefix */

