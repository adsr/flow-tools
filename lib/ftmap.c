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
 *      $Id: ftmap.c,v 1.7 2003/02/13 02:38:42 maf Exp $
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

static struct ftmap_ifname *parse_ifname(char **buf2);
static struct ftmap_ifalias *parse_ifalias(char **buf2);
static struct ftmap_ifname *ftmap_ifname_new2(char *ip, char *ifIndex,
  char *name);
struct ftmap_ifalias *ftmap_ifalias_new2(char *ip, char *ifIndex_list,
  char *name);
static void ftmap_ifalias_free(struct ftmap_ifalias *ftmia);
static void ftmap_ifname_free(struct ftmap_ifname *ftmin);

/* function: ftmap_new
 *
 * allocate and initialize struct ftmap
 *
 * returns allocated ftmap or NULL for error
 *
*/
struct ftmap *ftmap_new(void)
{
  struct ftmap *ftmap;

  if (!(ftmap = malloc(sizeof (struct ftmap))))
    return ftmap;

  bzero(ftmap, sizeof (struct ftmap));
  FT_LIST_INIT(&ftmap->ifalias);
  FT_LIST_INIT(&ftmap->ifname);

  return ftmap;

} /* ftmap_new */

/*
 * function: ftmap_ifalias_new2
 *
 * Allocate and initialize a ftmap_ifalias.  Free this with
 * ftmap_ifalias_free().  Used internally to convert from char*
 *
 * returns allocated structure, or NULL for error.
 */
struct ftmap_ifalias *ftmap_ifalias_new2(char *ip, char *ifIndex_list,
  char *name)
{
  struct ftmap_ifalias *ftmia;
  u_int32 bip;
  u_int16 *list, entries;
  int n;
  char *c, *buf;

  entries = 0;

  /* count entries in list */
  for (n = 1, c = ifIndex_list; *c; ++c)
    if (*c == ',')
      ++entries;

  if (!(list = malloc(entries * sizeof (u_int16))))
    return (struct ftmap_ifalias*)0L;

  buf = ifIndex_list;
  n = 0;

  for (;;) {

    c = strsep(&buf, ",");

    if (!c)
      break;

    list[n++] = atoi(c);

  }

  bip = scan_ip(ip);

  ftmia = ftmap_ifalias_new(bip, list, entries, name);
  free (list);
  return ftmia;

} /* ftmap_ifalias_new2 */

/*
 * function: ftmap_ifalias_new
 *
 * Allocate and initialize a ftmap_ifalias.  Free this with
 * ftmap_ifalias_free()
 *
 * returns allocated structure, or NULL for error.
 */
struct ftmap_ifalias *ftmap_ifalias_new(u_int32 ip, u_int16 *ifIndex_list,
  u_int16 entries, char *name)
{
  struct ftmap_ifalias *ftmia;
  int ret, n;

  ret = -1;
  ftmia = (struct ftmap_ifalias*)0L;

  if (!(ftmia = malloc(sizeof (struct ftmap_ifalias))))
    goto ftmap_ifalias_new_out;

  bzero(ftmia, sizeof (struct ftmap_ifalias));

  n = strlen(name);

  if (!(ftmia->name = malloc(n)))
    goto ftmap_ifalias_new_out;

  if (!(ftmia->ifIndex_list = malloc(entries * sizeof (u_int16))))
    goto ftmap_ifalias_new_out;

  ftmia->ip = ip;
  ftmia->entries = entries;
  strcpy(ftmia->name, name);
  for (n = 0; n < entries; ++n)
    ftmia->ifIndex_list[n] = ifIndex_list[n];

  ret = 0;

ftmap_ifalias_new_out:

  if (ret == -1) {

    if (ftmia->name)
      free(ftmia->name);

    if (ftmia->ifIndex_list)
      free(ftmia->ifIndex_list);

    if (ftmia)
      free (ftmia);
  }

  return ftmia;

} /* ftmap_ifalias_new */

/*
 * function: ftmap_ifalias_free
 *
 * Free resources allocated by ftmap_ifalias_new()
 */
static void ftmap_ifalias_free(struct ftmap_ifalias *ftmia)
{

  if (ftmia) {

  if (ftmia->name)
    free(ftmia->name);

  if (ftmia->ifIndex_list)
    free(ftmia->ifIndex_list);

    free (ftmia);

  }

} /* ftmap_ifalias_free */

/*
 * function: ftmap_ifname_new2
 *
 * Allocate and initialize a ftmap_ifname.  Free this with
 * ftmap_ifname_free().  Used internally to convert from char values.
 *
 * returns allocated structure, or NULL for error.
 */
struct ftmap_ifname *ftmap_ifname_new2(char *ip, char *ifIndex, char *name)
{
  u_int32 bip;
  u_int16 bifIndex;

  bip = scan_ip(ip);
  bifIndex = atoi(ifIndex);

  return ftmap_ifname_new(bip, bifIndex, name);

} /* ftmap_ifname_new2 */

/*
 * function: ftmap_ifname_new
 *
 * Allocate and initialize a ftmap_ifname.  Free this with
 * ftmap_ifname_free()
 *
 * returns allocated structure, or NULL for error.
 */
struct ftmap_ifname *ftmap_ifname_new(u_int32 ip, u_int16 ifIndex, char *name)
{
  struct ftmap_ifname *ftmin;
  int ret, n;

  ret = -1;
  ftmin = (struct ftmap_ifname*)0L;

  if (!(ftmin = malloc(sizeof (struct ftmap_ifname))))
    goto ftmap_ifname_new_out;

  bzero(ftmin, sizeof (struct ftmap_ifname));

  n = strlen(name);

  if (!(ftmin->name = malloc(n)))
    goto ftmap_ifname_new_out;

  ftmin->ip = ip;
  ftmin->ifIndex = ifIndex;
  strcpy(ftmin->name, name);

  ret = 0;

ftmap_ifname_new_out:

  if (ret == -1) {

    if (ftmin->name)
      free(ftmin->name);

    if (ftmin)
      free (ftmin);
  }

  return ftmin;

} /* ftmap_ifname_new */

/*
 * function: ftmap_ifname_free
 *
 * Free resources allocated by ftmap_ifname_new()
 */
static void ftmap_ifname_free(struct ftmap_ifname *ftmin)
{

  if (ftmin) {

    if (ftmin->name)
      free(ftmin->name);

    free(ftmin);

  }

} /* ftmap_ifname_free */

/*
 * function: ftmap_load
 *
 * Allocate a struct ftmap, open fname, read and parse the file.
 * Free resources allocated with ftmap_free().  Only entries with ip
 * are returned if ip != 0.
 *
 * returns initalized ftmap with entries loaded from fname or NULL on error.
 * 
 */
struct ftmap *ftmap_load(char *fname, u_int32 ip)
{
  struct stat sb;
  struct ftmap *ftmap;
  struct ftmap_ifname *ftmin;
  struct ftmap_ifalias *ftmia;
  int fd, ret;
  char *buf, *buf2, *c;

  ret = -1;
  fd = -1;
  buf = NULL;

  if (!(ftmap = ftmap_new()))
    goto ftmap_load_out;

  if ((fd = open(fname, O_RDONLY, 0)) < 0) {
    fterr_warn("open(%s)", fname);
    goto ftmap_load_out;
  }
  
  if (fstat(fd, &sb) < 0) {
    fterr_warn("stat(%s)", fname);
    goto ftmap_load_out;
  }

  /* allocate storage for file */
  if (!(buf = malloc(sb.st_size+1))) {
    fterr_warn("malloc()");
    goto ftmap_load_out;
  }

  /*
   * file format
   *
   *  ifmap 1.2.3.4 99 FastEthernet0/0
   *  ifmap 1.2.3.4 100 ATM0/0/0
   *
   *  ifalias 1.2.3.4 6,7,8,9 outside
   *
  */

  /* read in file */
  if (read(fd, buf, sb.st_size) != sb.st_size) {
    fterr_warnx("read(): short");
    goto ftmap_load_out;
  }
   
  /* null terminate file */
  buf[sb.st_size] = 0;

  buf2 = buf;

  for (;;) {

    for (;;) {
      c = strsep(&buf2, " \t\n");
      if ((c && *c != 0) || (!c))
        break;
    }

    /* no more tokens to parse */
    if (!c)
      break;

    if (c && !strcmp(c, "ifname")) {
      ftmin = parse_ifname(&buf2);
      if (ftmin) {
        /* add to list */
        if (!ip || (ip && ftmin->ip == ip))
          FT_LIST_INSERT_HEAD(&ftmap->ifname, ftmin, chain);
        else
          free(ftmin);
      } else {
        /* error */
        goto ftmap_load_out;
      }
    } else if (c && !strcmp(c, "ifalias")) {
      ftmia = parse_ifalias(&buf2);
      if (ftmia) {
        /* add to list */
        if (!ip || (ip && ftmia->ip == ip))
          FT_LIST_INSERT_HEAD(&ftmap->ifalias, ftmia, chain);
        else
          free(ftmia);
      } else {
        /* error */
        goto ftmap_load_out;
      }
    } else if (c && (*c == '#')) {
      /* comment line */
      continue;
    } else {
      fterr_warnx("Unexpected token: %s", c);
      goto ftmap_load_out;
    }

/* allow # comments */

    /* end of file */
    if (buf2 >= (buf+sb.st_size))
      break;

  }

  ret = 0;
 
ftmap_load_out:

  if (fd != -1)
    close (fd);

  if (buf)
    free(buf);

  if (ret == -1) {
    ftmap_free(ftmap);
    ftmap = (struct ftmap*)0L;
  }

  return ftmap;

} /* ftmap_load */

/*
 * function: ftmap_free
 *
 * frees resources allocated with ftmap_load()
 *
 */
void ftmap_free(struct ftmap *ftmap)
{
  struct ftmap_ifalias *ftmia, *ftmia2;
  struct ftmap_ifname *ftmin, *ftmin2;

  if (!ftmap)
    return;

  /* running down the ifalias list free all entries */
  FT_LIST_FOREACH(ftmin, &ftmap->ifname, chain) {
    FT_LIST_REMOVE(ftmin, chain);
    ftmin2 = ftmin;
    if (!(ftmin = FT_LIST_NEXT(ftmin, chain)))
      break;
    ftmap_ifname_free(ftmin2);
  }

  /* running down the ifname list free all entries */
  FT_LIST_FOREACH(ftmia, &ftmap->ifalias, chain) {
    FT_LIST_REMOVE(ftmia, chain);
    ftmia2 = ftmia;
    if (!(ftmia = FT_LIST_NEXT(ftmia, chain)))
      break;
    /* XXX memory leak? */
    ftmap_ifalias_free(ftmia2);
  }

  free(ftmap);

} /* ftmap_free */

/*
 * function: parse_ifname()
 *
 * Parse a single line terminted with 0 or \n.  Allocate a 
 * struct ftmap_ifname initialized with elements from the parsed
 * line.  If the line ends in \n, that \n will be replaced by a 0.
 *
 * returns struct ftmap_ifname allocated and initialized, or NULL for error.
 * 
 */
struct ftmap_ifname *parse_ifname(char **buf2)
{
  struct ftmap_ifname *ftmin;
  char *c, *ip, *ifIndex, *ifName;

  ftmin = (struct ftmap_ifname*)0L;

  for (;;) {
    c = strsep(buf2, " \t");
    if ((c && *c != 0) || (!c))
      break;
  }

  if (!c) {
    fterr_warnx("Expecting IP Address");
    return ftmin;
  }
  ip = c;

  for (;;) {
    c = strsep(buf2, " \t");
    if ((c && *c != 0) || (!c))
      break;
  }

  if (!c) {
    fterr_warnx("Expecting ifIndex");
    return ftmin;
  }
  ifIndex = c;

  for (;;) {
    c = strsep(buf2, " \t\n");
    if ((c && *c != 0) || (!c))
      break;
  }

  if (!c) {
    fterr_warnx("Expecting ifName");
    return ftmin;
  }
  ifName = c;

  ftmin = ftmap_ifname_new2(ip, ifIndex, ifName);

  return ftmin;

} /* parse_ifname */

/*
 * function: parse_ifalias()
 *
 * Parse a single line terminted with 0 or \n.  Allocate a 
 * struct ftmap_ifalias initialized with elements from the parsed
 * line.  If the line ends in \n, that \n will be replaced by a 0.
 *
 * returns struct ftmap_ifalias allocated and initialized, or NULL for error.
 * 
 */
struct ftmap_ifalias *parse_ifalias(char **buf2)
{
  struct ftmap_ifalias *ftmia;
  char *c, *ip, *index_list, *name;

  ftmia = (struct ftmap_ifalias*)0L;

  for (;;) {
    c = strsep(buf2, " \t");
    if ((c && *c != 0) || (!c))
      break;
  }

  if (!c) {
    fterr_warnx("Expecting IP Address");
    return ftmia;
  }
  ip = c;

  for (;;) {
    c = strsep(buf2, " \t");
    if ((c && *c != 0) || (!c))
      break;
  }

  if (!c) {
    fterr_warnx("Expecting ifIndex list");
    return ftmia;
  }
  index_list = c;

  for (;;) {
    c = strsep(buf2, " \t\n");
    if ((c && *c != 0) || (!c))
      break;
  }

  if (!c) {
    fterr_warnx("Expecting Alias");
    return ftmia;
  }
  name = c;

  ftmia = ftmap_ifalias_new2(ip, index_list, name);

  return ftmia;

} /* parse_ifalias */

