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
 *      $Id: ftfile.c,v 1.24 2003/02/13 02:38:42 maf Exp $
 */

#include "ftconfig.h"
#include "ftlib.h"

#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif

int load_dir(char *prefix, struct ftfile_entries *fte, int flags, int *depth);

#define debug 0

/*
 * function: ftfile_entry_new
 * 
 * allocate ftfile_entry struct.  see also ftfile_entry_free
*/
struct ftfile_entry *ftfile_entry_new(int len)
{
  struct ftfile_entry *e;

  if (!(e = (struct ftfile_entry*)malloc(sizeof (struct ftfile_entry))))
    return (struct ftfile_entry*)0L;

  bzero(e, sizeof *e);

  if (!(e->name = (char*)malloc(len+1))) {
    free (e);
    return (struct ftfile_entry*)0L;
  }

  return e;

} /* ftfile_entry_new */

/*
 * function: ftfile_entry_free
 * 
 * deallocate ftfile_entry struct allocated by ftfile_entry_new()
*/
void ftfile_entry_free(struct ftfile_entry *entry)
{
  free(entry->name);
  free(entry);
} /* ftfile_entry_free */

/*
 * function: ftfile_loadfile
 * 
 * Load filename into the file entries data structures
 * Files that do not match the flow-tools naming convention or
 * do not have the correct magic word in the header are not loaded
 * to prevent accidental removal.
 *
 * returns: < 0 error
 *          >= 0 ok
 */
int ftfile_loadfile(struct ftfile_entries *fte, char *fname, int flags)
{
  struct stat sb;
  struct ftfile_entry *n1, *n2;
  struct ftiheader head;
  int fd, done, len;

  if (flags & FT_FILE_INIT)
    FT_TAILQ_INIT(&fte->head);

  if (fname[0]) {

    /* skip anything that doesn't begin with "ft" "cf" and "tmp" */
    if (flags & FT_FILE_CHECKNAMES)
      if ((strncmp(fname, "ft", 2)) &&
         (strncmp(fname, "cf", 2)) &&
         (strncmp(fname, "tmp", 3))) {
        fterr_warnx("ignoring: %s", fname);
        return 0;
      }

      /* skip tmp files? */
      if (flags & FT_FILE_SKIPTMP)
        if (!strncmp(fname, "tmp", 3))
          return 0;

    /* make sure the file is actually a flow file */
    if ((fd = open (fname,  O_RDONLY, 0)) == -1) {
      fterr_warn("open(%s)", fname);
      return 0;
    }

    if (fstat(fd, &sb) < 0) {
      fterr_warn("fstat(%s)", fname);
      close(fd);
      return -1;
    }

    if (ftiheader_read(fd, &head) < 0) {
      fterr_warnx("ftiheader_read(%s): Failed, ignoring file.", fname);
      close(fd);
      return 0;
    }

    close (fd);

  } else { /* empty filename -- stdin */

    bzero(&head, sizeof head);
    bzero(&sb, sizeof sb);

  }

  len = strlen(fname);

  /* insert the entry in the list sorted by start time of flow file */
  done = 0;

  if (flags & FT_FILE_SORT) {

    FT_TAILQ_FOREACH(n1, &fte->head, chain) {

      if (n1->start > head.cap_start) {

        if (!(n2 = ftfile_entry_new(len))) {
          fterr_warnx("ftfile_entry_new(): failed");
          return -1;
        }

        n2->size = sb.st_size;
        n2->start = head.cap_start;
        strcpy(n2->name, fname);

        FT_TAILQ_INSERT_BEFORE(n1, n2, chain);
        done = 1;
        break;
      }
    } /* FT_TAILQ_FOREACH */
  } /* FT_FILE_SORT */

  if ((!done) || (!(flags & FT_FILE_SORT))) {

    if (!(n2 = ftfile_entry_new(len))) {
      fterr_warnx("ftfile_entry_new(): failed");
      return -1;
    }

    n2->size = sb.st_size;
    n2->start = head.cap_start;
    strcpy(n2->name, fname);
    FT_TAILQ_INSERT_TAIL(&fte->head, n2, chain);

  } /* !done or !FT_FILE_SORT */

  fte->num_bytes += sb.st_size;
  fte->num_files ++;

  return 0;

} /* ftfile_loadfile */

/*
 * function: ftfile_loaddir
 * 
 * Load directory contents into the file entries data structures
 * Files that do not match the flow-tools naming convention or
 * do not have the correct magic word in the header are not loaded
 * to prevent accidental removal.
 *
 * returns: < 0 error
 *          >= 0 ok
 */
int ftfile_loaddir(struct ftfile_entries *fte, char *dir, int flags)
{
  int depth, here;
  DIR *dirp;

  depth = 0;

  if (flags & FT_FILE_INIT)
    FT_TAILQ_INIT(&fte->head);

  /* remember current dir */
  if (!(dirp = opendir("."))) {
    fterr_warn("opendir(.)");
    return -1;
  }

  if ((here = open(".", O_RDONLY, 0)) < 0) {
    fterr_warn("open(.)");
    return -1;
  }

  /* go to working dir */
  if (chdir (dir) < 0) {
    fterr_warn("chdir(%s)", dir);
    close(here);
    closedir(dirp);
    return -1;
  }

  /* load entries */
  if (load_dir(dir, fte, flags, &depth)) {
    fterr_warn("load_dir(): failed");
    fchdir(here);
    close(here);
    closedir(dirp);
    return -1;
  }

  if (debug)
    fterr_info("ftfile_loaddir(): loaded %lu files", fte->num_files);

  /* return */
  if (fchdir(here) < 0) {
    fterr_warn("fchdir()");
    close(here);
    closedir(dirp);
    return -1;
  }

  closedir(dirp);
  close(here);
  return 0;

} /* ftfile_loaddir */

/*
 * function: ftfile_add_tail
 *
 * Add a file to the end of the list
 *
 * returns: < 0 error
 *          >= 0 ok
*/
int ftfile_add_tail(struct ftfile_entries *fte, char *fname, off_t size,
  uint32_t start)
{
  struct ftfile_entry *n1;

  if (!(n1 = ftfile_entry_new(strlen(fname)))) {
    fterr_warnx("ftfile_entry_new(): failed");
    return -1;
  }

  n1->size = size;
  n1->start = start;
  strcpy(n1->name, fname);

  FT_TAILQ_INSERT_TAIL(&fte->head, n1, chain);
  fte->num_files ++;
  fte->num_bytes += size;

  return 0;

} /* ftfile_add_tail */

/*
 * function: ftfile_expire
 *
 * If doit is set, and the directory has exceeded the maximum size
 * of files, or maximum storage size remove files until the limits
 * are under the mark.  curbytes is a hint (fudge factor) to account
 * for the existing open flow export.
 *
 * returns: < 0 error
 *          >= 0 ok
*/
int ftfile_expire (struct ftfile_entries *fte, int doit, int curbytes)
{
  unsigned int i;
  struct ftfile_entry *n1, *n2;
  uint64_t bytes;

  /*
   * if max_files is set, remove files starting at the head of the list until
   * max_files <= num_files.  update num_files, num_bytes
   */

  i = 0;
  bytes = 0;

  if (fte->max_files && (fte->num_files > fte->max_files)) {
    n2 = NULL;
    FT_TAILQ_FOREACH(n1, &fte->head, chain) {
      if (n2 != NULL) {
	ftfile_entry_free(n2);
	n2 = NULL;
      }
      fterr_info("remove/1 %s", n1->name);
      bytes += n1->size;
      ++i;
      if (doit) {
        n2 = n1;
        FT_TAILQ_REMOVE(&fte->head, n1, chain);
        if (unlink(n1->name) == -1) 
          fterr_warn("unlink(%s)", n1->name);
      } /* doit */
      if ((fte->num_files - i) <= fte->max_files)
        break;
    } /* FT_TAILQ_FOREACH */
    if (doit) {
      fte->num_files -= i;
      fte->num_bytes -= bytes;
    } /* doit */
    if (n2 != NULL) {
      ftfile_entry_free(n2);
      n2 = NULL;
    }
  } /* if */

  if (debug)
    fterr_info("remove/1 %u files", i);

  i = 0;
  bytes = 0;

  /*
   * if max_bytes is set, remove files starting at the head of the list until
   * max_bytes <= num_bytes
   */

  if (fte->max_bytes && (fte->num_bytes+curbytes > fte->max_bytes)) {
    n2 = NULL;
    FT_TAILQ_FOREACH(n1, &fte->head, chain) {
      if (n2 != NULL) {
	ftfile_entry_free(n2);
	n2 = NULL;
      }
      fterr_info("remove/2 %s", n1->name);
      bytes += n1->size;
      ++i;
      if (doit) {
        n2 = n1;
        FT_TAILQ_REMOVE(&fte->head, n1, chain);
        if (unlink(n1->name) == -1) 
          fterr_warn("unlink(%s)", n1->name);
      } /* doit */
      if ((fte->num_bytes+curbytes - bytes) <= fte->max_bytes)
        break;
    } /* FT_TAILQ_FOREACH */
    if (doit) {
      fte->num_files -= i;
      fte->num_bytes -= bytes;
    } /* doit */
    if (n2 != NULL) {
      ftfile_entry_free(n2);
      n2 = NULL;
    }
  } /* if */

  if (debug)
    fterr_info("remove/2 %u files", i);

  return 0;

} /* ftfile_expire */

/*
 * function: ftfile_dump
 *
 * Dump the contents of the file entries data struct.
 *
 * returns: < 0 error
 *          >= 0 ok
*/
int ftfile_dump(struct ftfile_entries *fte)
{
  struct ftfile_entry *n1;

  FT_TAILQ_FOREACH(n1, &fte->head, chain) {

    fterr_info("name=%s  size=%ld  time=%lu", n1->name, (long)n1->size,
      (unsigned long)n1->start);

  } /* FT_TAILQ_FOREACH */

  return 0;

} /* ftfile_dump */

/*
 * function: ftfile_pathname
 *
 * Generate export file pathname based on ftv, time, nest, and done flag.
 * 
 */
void ftfile_pathname(char *buf, int bsize, int nest, struct ftver ftv,
 int done, time_t ftime)
{
  struct tm *tm;
  char *prefix, dbuf[64];
  long gmt_val;
  char gmt_sign;
  int tm_gmtoff;
  
  if (!(tm = localtime (&ftime))) {
    snprintf(buf, bsize, ".");
  }

  tm_gmtoff = get_gmtoff(ftime);

  /* compute GMT offset */
  if (tm_gmtoff >= 0) {
    gmt_val = tm_gmtoff;
    gmt_sign = '+';
  } else {
    gmt_val = -tm_gmtoff;
    gmt_sign = '-';
  }

  /* compute directory prefix to pathname */
  if (nest == 0) {
    dbuf[0] = 0;
  } else if (nest == 1) {
    sprintf(dbuf, "%2.2d/", (int)tm->tm_year+1900);
  } else if (nest == 2) {
    sprintf(dbuf, "%2.2d/%2.2d-%2.2d/", (int)tm->tm_year+1900,
      (int)tm->tm_year+1900, (int)tm->tm_mon+1);
  } else if ((nest == 3) || (nest == -3)) {
    sprintf(dbuf, "%2.2d/%2.2d-%2.2d/%2.2d-%2.2d-%2.2d/",
      (int)tm->tm_year+1900, (int)tm->tm_year+1900,
      (int)tm->tm_mon+1, (int)tm->tm_year+1900, (int)tm->tm_mon+1,
      (int)tm->tm_mday);
  } else if (nest == -2) {
    sprintf(dbuf, "%2.2d-%2.2d/%2.2d-%2.2d-%2.2d/",
      (int)tm->tm_year+1900, (int)tm->tm_mon+1,
      (int)tm->tm_year+1900, (int)tm->tm_mon+1, (int)tm->tm_mday);
  } else if (nest == -1) {
    sprintf(dbuf, "%2.2d-%2.2d-%2.2d/",
      (int)tm->tm_year+1900, (int)tm->tm_mon+1, (int)tm->tm_mday);
  } else { /* really an error */
    dbuf[0] = 0;
  }

  /* prefix differs if file is active */
  prefix = (done) ? "ft-v" : "tmp-v";

  if (ftv.d_version == 8) {

    /* ft-vNNmNN.YYYY-DD-MM.HHMMSS.+|-NNNN */
    snprintf(buf, bsize,
        "%s%s%2.2dm%2.2d.%4.4d-%2.2d-%2.2d.%2.2d%2.2d%2.2d%c%2.2d%2.2d",
        dbuf, prefix, ftv.d_version, ftv.agg_method,
        (int)tm->tm_year+1900, (int)tm->tm_mon+1, (int)tm->tm_mday,
        (int)tm->tm_hour, (int)tm->tm_min, (int)tm->tm_sec,
        gmt_sign, (int)(gmt_val/3600), (int)((gmt_val %3600) / 60));
  } else {
    /* ft-vNN.YYYY-DD-MM.HHMMSS.+|-NNNN */
      snprintf(buf, bsize,
        "%s%s%2.2d.%4.4d-%2.2d-%2.2d.%2.2d%2.2d%2.2d%c%2.2d%2.2d",
        dbuf, prefix, ftv.d_version,
        (int)tm->tm_year+1900, (int)tm->tm_mon+1, (int)tm->tm_mday,
        (int)tm->tm_hour, (int)tm->tm_min, (int)tm->tm_sec,
        gmt_sign, (int)(gmt_val/3600), (int)((gmt_val %3600) / 60));

  } /* ver != 8 */

} /* ftfile_name */

/*
 * function: ftfile_mkpath
 *
 * Create directory components for pathname.
 *
 * nest controls depth
 * -3    YYYY/YYYY-MM/YYYY-MM-DD
 * -2    YYYY-MM/YYYY-MM-DD
 * -1    YYYY-MM-DD
 *  0    no directories are created
 *  1    YYYY
 *  2    YYYY/YYYY-MM
 *  3    YYYY/YYYY-MM/YYYY-MM-DD
 *
 * returns -1 on error
 * 
 */
int ftfile_mkpath(time_t ftime, int nest)
{
  struct tm *tm;
  char buf[32];

  /* no directories */
  if (nest == 0)
    return 0;

  /* illegal */
  if ((nest > 3) || (nest < -3))
    return -1;

  if (!(tm = localtime (&ftime)))
    return -1;

  if (nest == -1)
    /* YYYY-MM-DD */
    sprintf(buf, "%2.2d-%2.2d-%2.2d", 
      (int)tm->tm_year+1900, (int)tm->tm_mon+1, (int)tm->tm_mday);
  else if (nest == -2)
    /* YYYY-MM */
    sprintf(buf, "%2.2d-%2.2d", (int)tm->tm_year+1900, (int)tm->tm_mon+1);
  else if ((nest == -3) || (nest > 0))
    /* YYYY */
    sprintf(buf, "%2.2d", (int)tm->tm_year+1900);
  else 
    /* not reached */
    return -1;

  if (mkdir(buf, 0755) < 0) {
    if (errno != EEXIST) {
      fterr_warn("mkdir(%s)", buf);
      return -1;
    }
  }

  if ((nest == 1) || (nest == -1))
    return 0;

  if (nest == -2)
    /* YYYY-MM/YYYY-MM-DD */
    sprintf(buf, "%2.2d-%2.2d/%2.2d-%2.2d-%2.2d",
      (int)tm->tm_year+1900, (int)tm->tm_mon+1,
      (int)tm->tm_year+1900, (int)tm->tm_mon+1, (int)tm->tm_mday);
  else if ((nest == -3) || (nest > 0))
    /* YYYY/YYYY-MM */
    sprintf(buf, "%2.2d/%2.2d-%2.2d", (int)tm->tm_year+1900,
      (int)tm->tm_year+1900, (int)tm->tm_mon+1);
  else
    /* not reached */
    return -1;

  if (mkdir(buf, 0755) < 0) {
    if (errno != EEXIST) {
      fterr_warn("mkdir(%s)", buf);
      return -1;
    }
  }

  if ((nest == 2) || (nest == -2))
    return 0;

  if ((nest == 3) || (nest == -3))
    /* YYYY/YYYY-MM/YYYY-MM-DD */
    sprintf(buf, "%2.2d/%2.2d-%2.2d/%2.2d-%2.2d-%2.2d", (int)tm->tm_year+1900,
      (int)tm->tm_year+1900, (int)tm->tm_mon+1, (int)tm->tm_year+1900,
      (int)tm->tm_mon+1, (int)tm->tm_mday);
  else
    /* not reached */
    return -1;
  
  if (mkdir(buf, 0755) < 0) {
    if (errno != EEXIST) {
      fterr_warn("mkdir(%s)", buf);
      return -1;
    }
  }

  return 0;

} /* ftfile_mkpath */

int load_dir(char *prefix, struct ftfile_entries *fte, int flags, int *depth)
{
  DIR *dirp;
  struct dirent *dirent;
  struct stat sb;
  struct ftfile_entry *n1, *n2;
  struct ftiheader head;
  char *path_new;
  int fd, done, ret, here;
  int prefix_len, name_len, path_len;

  if (++ *depth > 50) {
    fterr_warnx("Limit of 50 nested directories reached.");
    return -1;
  }

  ret = -1;
  here = -1;

  prefix_len = strlen(prefix);

  dirp = opendir(".");

  for (dirent = readdir(dirp); dirent; dirent = readdir(dirp)) {

    /* skip . and .. */
    if (dirent->d_name[0] == '.')
      if (!dirent->d_name[1])
        continue;
      if (dirent->d_name[1] == '.')
        if (!dirent->d_name[2])
          continue;

    if (stat(dirent->d_name, &sb) < 0) {
      fterr_warn("stat(%s)", dirent->d_name);
      goto errout;
    }

    name_len = strlen(dirent->d_name);

    path_len = prefix_len + name_len + 1;

    if (S_ISDIR(sb.st_mode)) {

      if (!(path_new = (char*)malloc(path_len+1))) {
        fterr_warn("malloc()");
        goto errout;
      }
      sprintf(path_new, "%s/%s", prefix, dirent->d_name);

      /* remember where we are */
      if ((here = open(".", O_RDONLY, 0)) < 0) {
        fterr_warn("open(.)");
        goto errout;
      }

      if (chdir(dirent->d_name) < 0) {
        fterr_warn("chdir(%s)", path_new);
        free(path_new);
        goto errout;
      }

      if (load_dir(path_new, fte, flags, depth) < 0) {
        fterr_warnx("load_dir(%s)", path_new);
        free(path_new);
        goto errout;
      }

      if (fchdir(here) < 0) {
        fterr_warn("chdir(..)");
        free(path_new);
        goto errout;
      }

      close (here);
      here = -1;

      free (path_new);

    } else { /* S_ISDIR */

      /* skip non plain files */
      if (!S_ISREG(sb.st_mode)) {
        fterr_warnx("not plain, skipping: %s", dirent->d_name);
        continue;
      }

      /* skip anything that doesn't begin with "ft" "cf" and "tmp" */
      if (flags & FT_FILE_CHECKNAMES)
        if ((strncmp(dirent->d_name, "ft", 2)) &&
           (strncmp(dirent->d_name, "cf", 2)) &&
           (strncmp(dirent->d_name, "tmp", 3))) {
          fterr_warnx("ignoring: %s", dirent->d_name);
          continue;
        }

      /* skip tmp files? */
      if (flags & FT_FILE_SKIPTMP)
        if (!strncmp(dirent->d_name, "tmp", 3))
          continue;

      /* make sure the file is actually a flow file */
      if ((fd = open (dirent->d_name,  O_RDONLY, 0)) == -1) {
        fterr_warn("open(%s)", dirent->d_name);
        continue;
      }

      if (ftiheader_read(fd, &head) < 0) {
        fterr_warnx("ftiheader_read(%s): Failed, ignoring file.", dirent->d_name);
        close(fd);
        continue;
      }

      close (fd);

      /* insert the entry in the list sorted by start time of flow file */
      done = 0;

      if (flags & FT_FILE_SORT) {

        FT_TAILQ_FOREACH(n1, &fte->head, chain) {

          if (n1->start > head.cap_start) {

            if (!(n2 = ftfile_entry_new(path_len))) {
              fterr_warnx("ftfile_entry_new(): failed");
              goto errout;
            }

            n2->size = sb.st_size;
            n2->start = head.cap_start;
            sprintf(n2->name, "%s/%s", prefix, dirent->d_name);

            FT_TAILQ_INSERT_BEFORE(n1, n2, chain);
            done = 1;
            break;
          }
        } /* FT_TAILQ_FOREACH */
      } /* FT_FILE_SORT */

      if ((!done) || (!(flags & FT_FILE_SORT))) {

        if (!(n2 = ftfile_entry_new(path_len))) {
          fterr_warnx("ftfile_entry_new(): failed");
          goto errout;
        }

        n2->size = sb.st_size;
        n2->start = head.cap_start; 
        sprintf(n2->name, "%s/%s", prefix, dirent->d_name);
        FT_TAILQ_INSERT_TAIL(&fte->head, n2, chain);

      } /* !done or !FT_FILE_SORT */

      fte->num_bytes += sb.st_size;
      fte->num_files ++;

    } /* ! S_ISDIR */

  } /* for */

  ret = 0;

errout:

  closedir(dirp);

  if (here != -1)
    close (here);

  -- *depth;

  return ret;

} /* main */

void ftfile_free(struct ftfile_entries *fte)
{
  struct ftfile_entry *n1, *n2;

  n2 = NULL;
  FT_TAILQ_FOREACH(n1, &fte->head, chain) {
    if (n2 != NULL) {
      ftfile_entry_free(n2);
      n2 = NULL;
    }
    FT_TAILQ_REMOVE(&fte->head, n1, chain);
    n2 = n1;
  }

  if (n2 != NULL) {
    ftfile_entry_free(n2);
    n2 = NULL;
  }

} /* ftfile_free */

