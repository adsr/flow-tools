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
 *      $Id: support.c,v 1.35 2003/02/13 02:38:43 maf Exp $
 */

#include "ftconfig.h"
#include "ftlib.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif

#if !HAVE_STRSEP
  char    *strsep (char **, const char *);
#endif

#ifndef IN_CLASSD_NET
#define IN_CLASSD_NET 0xf0000000
#endif

/*
 * lookup table for mask length to mask
 *
 *               (first 8)
 *  128.0.0.0 192.0.0.0 224.0.0.0 240.0.0.0
 *  248.0.0.0 252.0.0.0 254.0.0.0 255.0.0.0
 *
 */
uint32_t mask_lookup[] = { 0xffffffff,
     0x80000000, 0xc0000000, 0xe0000000, 0xf0000000,
     0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
     0xff800000, 0xffc00000, 0xffe00000, 0xfff00000,
     0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
     0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000,
     0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
     0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0,
     0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff };

/*
 * function ipv4_len2mask
 *
 * returns the 32 bit network mask given a length
 *
*/
uint32_t ipv4_len2mask(u_int8 len)
{
  return mask_lookup[(len > 32) ? 0 : len];
}

/*
 * function: load_lookup
 *
 *  loads a list of , seperated numbers into an array
 *  ! will invert the list
 *  - can be used as a range operator
 *
 *  example
 *   1,5-10   == 1,5,6,7,8,9,10
 *   !1       == all numbers in the range except for 1
 */
int load_lookup(char *s, int size, char *list)
{
  char *p;
  int j, k;
  unsigned i, i2;

  p = s;

  while ((*p == ' ') || (*p == '\t')) ++p;
  if (*p == '!') {
    for (k = 0; k < size; ++k)
      list[k] = 1;
    k = 0;
    ++p;
  } else {
    for (k = 0; k < size; ++k)
      list[k] = 0;
    k = 1;
  }

  while (*p) {

    i = (unsigned)strtol(p, (char**)0L, 0);
    if (i >= size) return -1;
    list[i] = k;

    /* skip to , or - */
    while (*p && (*p != ',') && (*p != '-')) ++p;

    if (*p == '-') {

      ++p;
      i2 = (unsigned)strtol(p, (char**)0L, 0);
      if (i2 >= size) return -1;
      for (j = i; j <= i2; ++j) list[j] = k;

      /* skip to , or - */
      while (*p && (*p != ',') && (*p != '-')) ++p;
    }

    /* skip past , and - */
    while (*p && ((*p == ',') || (*p == '-'))) ++p;

  } /* *p */

  return 0;

} /* load_lookup */

/*
 * function: scan_peeri
 *
 * scan peer identifier
 *
 * scan 1.2.3.4/1.2.3.4/nn[/nnl]
 *      locip   remip   port  ttl
 * into ftpeer struct
 */
struct ftpeeri scan_peeri(char *input)
{
  struct ftpeeri ftpi;
  char *s, *s2, *locip, *remip, *dstport, *ttl;

  bzero (&ftpi, sizeof ftpi);
  ftpi.dst_port = FT_PORT;

  locip = remip = dstport = ttl = (char*)0L;

  if (!(s = malloc(strlen(input)+1))) {
    fterr_warn("malloc");
    return ftpi;
  }

  /* keep track of original pointer to free */
  s2 = s;

  strcpy(s, input);

  locip = s;
  if (*s) {
  }

  for (; *s && *s != '/'; ++s);
  if (*s) {
    *s = 0;
    remip = ++s;
  }

  for (; *s && *s != '/'; ++s);
  if (*s) {
    *s = 0;
    dstport = ++s;
  }

  for (; *s && *s != '/'; ++s);
  if (*s) {
    *s = 0;
    ttl = ++s;
  }

  if (locip)
    ftpi.loc_ip = scan_ip(locip);
  if (remip)
    ftpi.rem_ip = scan_ip(remip);
  if (dstport)
    ftpi.dst_port = atoi(dstport);
  if (ttl)
    ftpi.ttl = atoi(ttl);

  free (s2);

  return ftpi;
  
} /* scan_peer */

struct ip_prefix scan_ip_prefix(char *input)
{
  struct ip_prefix p;
  char *s, *s2;
  int has_slash;

  has_slash = 0;

  bzero(&p, sizeof p);

  for (s = input; *s; ++s)
    if (*s == '/') {
      has_slash = 1;
      break;
    }

  if (!has_slash) {
    p.addr = scan_ip(input);
    if ((IN_CLASSA(p.addr)) && (p.addr == (p.addr & IN_CLASSA_NET)))
      p.len = 8;
    else if ((IN_CLASSB(p.addr)) && (p.addr == (p.addr & IN_CLASSB_NET)))
      p.len = 16;
    else if ((IN_CLASSC(p.addr)) && (p.addr == (p.addr & IN_CLASSC_NET)))
      p.len = 24;
    else if ((IN_CLASSD(p.addr)) && (p.addr == (p.addr & IN_CLASSD_NET)))
      p.len = 28;
    else
      p.len = 32;
  } else {

    if (!(s = malloc(strlen(input)+1))) {
      fterr_warn("malloc");
      return p;
    }

    s2 = s;

    strcpy(s, input);

    for (; *s2 && *s2 != '/'; ++s2);
    if (*s2) {
      *s2 = 0;
      ++s2;
    }

    p.addr = scan_ip(s);
    p.len = atoi(s2);

    free (s);
  }

  if (p.len > 32)
    p.len = 32;

  return p;

} /* scan_ip_prefix */

/*
 * function: scan_ip
 *
 *  IP address in string S is converted to a u_long
 *  (borrowed from tcpdump)
 *
 *  left shift any partial dotted quads, ie 10 is 0x0a000000 not 0x0a
 *  so scan_ip_prefix() works for standard prefix notation, ie 10/8
 */
uint32_t scan_ip(char *s)
{
  struct hostent *he;
  struct in_addr *ina;
  uint32_t addr = 0;
  u_int n;
  int dns, shift = 0;
  char *t;

  /* if there is anything ascii in here, this may be a hostname */
  for (dns = 0, t = s; *t; ++t) {
    if (islower((int)*t) || isupper((int)*t)) {
      dns = 1;
      break;
    }
  }

  if (dns) {

    if (!(he = gethostbyname(s)))
      goto numeric;

    if (he->h_addrtype != AF_INET)
      goto numeric;

    if (he->h_length != sizeof (uint32_t))
      goto numeric;

    ina = (struct in_addr*)*he->h_addr_list;
    return (ntohl(ina->s_addr));

  } /* dns */

numeric:
  while (1) {

    /* n is the nibble */
    n = 0;

    /* nibble's are . bounded */
    while (*s && (*s != '.') && (*s != ' ') && (*s != '\t'))
      n = n * 10 + *s++ - '0';

    /* shift in the nibble */
    addr <<=8;
    addr |= n & 0xff;
    ++shift;

    /* return on end of string */
    if ((!*s) || (*s == ' ') || (*s == '\t'))
      goto ndone;

    /* skip the . */
    ++s;
  } /* forever */

ndone:

  for (; shift < 4; ++shift)
    addr <<=8;

  return addr;

} /* scan_ip */


/*
 * function: print_3float
 *
 *  format a floating point # to stdout w. 1 trailing space
 *
 */
void print_3float(float f)
{

  char s[10], *c;
  sprintf(s, "%-3.3f", f);
  c = s + 1;
  printf("%s ", c);

} /* print_3float */

/*
 * function: print_3float2
 *
 *  format a floating point # to stdout w. 2 trailing spaces
 *
 */
void print_3float2(float f)
{

  char s[10], *c;
  sprintf(s, "%-3.3f", f);
  c = s + 1;
  printf("%s  ", c);

} /* print_3float */

/* adapted from dd */
int64_t scan_size(char *val)
{
  uint64_t num, t;
  char *expr;

  if ((num = strtoul(val, &expr, 0)) == ULONG_MAX)
    goto erange;

  switch(*expr) {

    case 0:
      break;

    case 'b':
      t = num;
      num *= 512;
      if (t > num)
        goto erange;
      break;
    case 'G':
      t = num;
      num *= 1024;
      num *= 1024;
      num *= 1024;
      if (t > num)
        goto erange;
      break;
    case 'K':
      t = num;
      num *= 1024;
      if (t > num)
        goto erange;
      break;
    case 'M':
      t = num;
      num *= 1024;
      num *= 1024;
      if (t > num)
        goto erange;
      break;
    default:
      goto erange;
  }

  return num;

erange: 

  return (int64_t)-1;

} /* scan_size */

#if HAVE_SIGACTION
/*
 * Function: mysignal()
 *  POSIX style signals.
 *
 *  signal() has different semantics over different versions of unix.
 *  this emulates signal() with sigaction() to behave like BSD.
 *
 * From Stevens Advanced Programming in the UNIX environment 
 *
 */
void *mysignal(int signo, void *func)
{
  struct sigaction act, oact;
  
  act.sa_handler = (void*)func;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;

  if (signo == SIGALRM) {
#ifdef  SA_INTERRUPT
  act.sa_flags |= SA_INTERRUPT; /* SunOS */
#endif
  } else {
#ifdef SA_RESTART
  act.sa_flags |= SA_RESTART; /* SVR4, 4.3+BSD */
#endif
  }

  if (sigaction(signo, &act, &oact) < 0)
    return SIG_ERR;

  return oact.sa_handler;
} /* signal */

#else /* SIGACTION */

void *mysignal(int signo, void *func)
{ return signal(signo, func) };

#endif /* SIGACTION */



int unlink_pidfile(int pid, char *file, u_int16 port)
{
  char *c;
  int ret;

  if (!(c = (char*)malloc(strlen(file)+16)))
    return -1;

  sprintf(c, "%s.%d", file, (int)port);

  if ((ret = unlink(c)) < 0)
    fterr_warn("unlink(%s)", c);

  free (c);

  return ret;

} /* unlink_pidfile */
 

int write_pidfile(int pid, char *file, u_int16 port)
{
  int fd, len;
  char str[16], *c;
  
  if (!(c = (char*)malloc(strlen(file)+16)))
    return -1;

  sprintf(c, "%s.%d", file, (int)port);
    
  len = sprintf(str, "%u\n", (unsigned)pid);

  if ((fd = open(c, O_WRONLY|O_CREAT|O_TRUNC, 0644)) < 0 ) {
    fterr_warn("open(%s)", c);
    free (c);
    return -1; 
  }


  if (write(fd, str, len) != len) {
    fterr_warn("write(%s)", c);
    close (fd);
    free (c);
    return -1;
  }

  return close (fd);

} /* write_pidfile */


/*
 * function get_gmtoff
 *
 * return offset from GMT in seconds
 *
 * based on compute_tz() code by Michael R. Elkins
 */
int get_gmtoff(time_t t) 
{
  struct tm *tmp, local, gmt;
  time_t t2;
  int yday;
  tmp = gmtime(&t);
  bcopy(tmp, &gmt, sizeof gmt);

  tmp = localtime(&t);
  bcopy(tmp, &local, sizeof local);

  /* calculate difference in seconds */
  t2 = (local.tm_hour - gmt.tm_hour) * 60; /* to minutes */
  t2 += (local.tm_min - gmt.tm_min); /* minutes */
  t2 *= 60; /* to seconds */

  /* diff day */
  yday = (local.tm_yday - gmt.tm_yday);

  if ((yday == -1) || (yday > 1))
    t2 -= 86400; /* sub one day */
  else if (yday != 0)
    t2 += 86400; /* add one day */

  return t2;

} /* get_gmtoff */

/*
 * function: bigsockbuf
 *
 * There is no portable way to determine the max send and receive buffers
 * that can be set for a socket, so guess then decrement that guess by
 * 2K until the call succeeds.  If n > 1MB then the decrement by .5MB
 * instead.
 *
 * returns size or -1 for error
*/
int bigsockbuf(int fd, int dir, int size)
{
  int n, tries;

  /* initial size */
  n = size;
  tries = 0;

  while (n > 4096) {

    if (setsockopt(fd, SOL_SOCKET, dir, (char*)&n, sizeof (n)) < 0) {

      /* anything other than no buffers available is fatal */
      if (errno != ENOBUFS) {
        fterr_warn("setsockopt(size=%d)", n);
        return -1;
      }

      /* try a smaller value */

      if (n > 1024*1024) /* most systems not > 256K bytes w/o tweaking */
        n -= 1024*1024;
      else
        n -= 2048;

      ++tries;

    } else {

      fterr_info("setsockopt(size=%d)", n);
      return n;

    }

  } /* while */

  /* no increase in buffer size */
  return 0;

} /* bigsockbuf */

/*
 * function: mkpath
 *
 * make the path to a filename.
 *
 * returns 0: ok
 *         -1 fail
 *
*/
int mkpath(const char *path, mode_t mode)
{
  char *c, *cs = NULL, *c2 = NULL, *p, *p2;
  int len, ret, done, nodir;
 
  len = strlen(path);
  c = (char*)0L;
  ret = -1;
  done = 0;

  if (!(c = (char*)malloc(len+1))) {
    fterr_warn("malloc()");
    goto mkpath_out;
  }

  if (!(c2 = (char*)malloc(len+1))) {
    fterr_warn("malloc()");
    goto mkpath_out;
  }

  cs = c;
  strcpy(c, path);
  c2[0] = 0;

  while (c && !done) {

    /* break out pathname components in p */
    if (!(p = strsep(&c, "/")))
      break;

    /* end of string? */
    if (!c)
      break;

    for (done = 1, p2 = c; p2 && *p2; ++p2)
      if (*p2 == '/') {
        done = 0;
        break;
      }

    /* build path */
    strcat(c2, p);
    nodir = 0;

    if (p[0] == '.' && p[1] == 0)
      nodir = 1;

    if (p[0] == '.' && p[1] == '.' && p[2] == 0)
      nodir = 1;

    if (p[0] == 0)
      nodir = 1;

    if (!nodir) {

      if (mkdir(c2, mode) < 0) {
        if (errno != EEXIST) {
          fterr_warn("mkdir(%s)", c2);
          goto mkpath_out;
        }
      }
 
    } /* nodir */

    strcat(c2, "/");

  }

  ret = 0;

mkpath_out:

  if (cs)
    free(cs);

  if (c2)
    free(c2);

  return ret;

} /* mkpath */

/*    
 * function: udp_cksum
 *
 * calculate checksum of IP pseudo header plus UDP header
 *
 */
int udp_cksum(struct ip *ip, struct udphdr *up, int len)
{
  u_int16 *word;
  int sum;
  
  word = (u_int16*)&ip->ip_src.s_addr;
  sum = *word++;
  sum += *word;

  word = (u_int16*)&ip->ip_dst.s_addr;
  sum += *word++;
  sum += *word;

  sum += htons(len);

  sum += IPPROTO_UDP<<8;

  word = (u_short*)up;
  sum += *word++;
  sum += *word++;
  sum += *word++;

  return sum;
} /* udp_cksum */

