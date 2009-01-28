/* $Id: flow-iptime.c,v 1.2 2002/05/14 02:37:46 wyy Exp $ */
/**
 *
 * Inter.net Philippines Patches to Flow-tools
 *
 * Miguel A. Paraz <map@internet.org.ph>
 * Inter.net Philippines 
 * 
 * William Emmanuel S. YU <wyu@ateneo.edu>
 * Ateneo de Manila University, Philippines
 *
 * Requires Flow-Tools-0.57
 * Copyright (c) 2001 Mark Fullmer and The Ohio State University
 * All rights reserved.
 *
**/

/**
 * flow-iptime source-ip destination-ip start-time stop-time
 * flow-ipfime -f spec
 *
 *    where spec: source-ip destination-ip start-time stop-time
 *                ...
 * 
 * IP can be decimal or dotted quad
 * ip = 0 means any
 *
 * TODO:
 * Support netmasks/wildcards?
 *
 * Command line for: if input is guaranteed to be sequential, skip over
 * searches whose time is older than the flow.  Stop when flow is 
 * older than oldest entry. Need to sort spec file for this.
**/

/* Maximum entries in spec file 
   TODO: allocate dynamically, or specify max on command line (?)
*/
#define MAX_SPEC 256
#define MAX_SPEC_LINE 64

#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif
#include <time.h>
#include <fcntl.h>

/* flow-tools related includes */
#include "ftlib.h"
#include "ftbuild.h"
#include "ftconfig.h"

/* might not portable. for inet_ntoa. */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int debug;

/* lookup structure */
struct iptime_lookup {
  u_int32 srcaddr;
  u_int32 dstaddr;
  int start;
  int stop;
};

/* malloc() a lookup structure and fill it up */
struct iptime_lookup *make_lookup
(const char *text_src, const char *text_dst,
 const char *text_start,
 const char *text_stop) {

  struct in_addr ia;
  struct iptime_lookup *ret;
  char *endptr;

  if ((ret = malloc(sizeof(struct iptime_lookup))) == NULL) {
    /* Out of memory! */
    return NULL;
  }

  /* Try dotted quad on src.
   This isn't pretty since it passes through endian conversion  */

    if (inet_aton(text_src, &ia) == 0) {
      /* Try decimal */
      ret->srcaddr = strtol(text_src, &endptr, 10);
      
      if (*endptr != 0) {
	free(ret);
	return NULL;
      }
    }
    else {
      ret->srcaddr = ntohl(ia.s_addr);
    }

    /* Try dotted quad on dst. */

    if (inet_aton(text_dst, &ia) == 0) {
      /* Try decimal */
      ret->dstaddr = strtol(text_dst, &endptr, 10);
      
      if (*endptr != 0) {
	free(ret);
	return NULL;
      }
    }
    else {
      ret->dstaddr = ntohl(ia.s_addr);
    }

    ret->start = strtol(text_start, &endptr, 10);
    if (*endptr != 0) {
      free(ret);
      return NULL;
    }

    ret->stop = strtol(text_stop, &endptr, 10);
    if (*endptr != 0) {
      free(ret);
      return NULL;
    }

    return ret;
}

void usage();

int main(int argc, char **argv)
{
  extern char *optarg;
  struct ftio ftio_in, ftio_out;
  struct ftset ftset;
  struct ftver ftv;
  struct ftprof ftp;
  struct fts3rec_v5 *rec_v5;
  struct fts3rec_gen *rec_gen;
  int i;
  void *rec;

  u_int64 total_flows;
  int as_present;

  char *spec_fname = "";
  extern int optind;
  struct iptime_lookup **itlp, **itlp_p, *itl_sp;
  int n_itl;


  /* init fterr */
  fterr_setid(argv[0]);

  /* profile */
  ftprof_start (&ftp);

  bzero(&ftv, sizeof ftv);

  /* defaults + no compression */
  ftset_init(&ftset, 0);

  /* init */
  total_flows = 0;

  while ((i = getopt(argc, argv, "f:")) != -1)
    switch (i) {

    case 'f': /* acl file name */
      spec_fname = optarg;
      break;

    case 'd': /* debug */
      debug = atoi(optarg);
      break;


    } /* switch */


  i = optind;
  if (i < argc) {

    /* use the command line.  check that there are 4 parameters */

    if (argc - i != 4) {
      usage();
      exit(1);
    }

    /* get ip, start, stop; store into the static pointer */
    if ((itl_sp = make_lookup(argv[i], argv[i + 1], argv[i + 2], argv[i + 3]))
	== NULL) {

      usage();
      exit(1);
    }

    /* Exactly one entry, point to it */
    n_itl = 1;
    itlp = &itl_sp;
  }
  else {
    FILE *fp;
    char spec_line[MAX_SPEC_LINE];


    /* load the spec file, point working pointer */
    if ((itlp = itlp_p =
	 malloc(MAX_SPEC * sizeof(struct iptime_lookup *))) == NULL) {

      fputs ("Out of memory for spec list\n", stderr);
      exit (1);
    }

    /* Open file */
    if ((fp = fopen (argv[i - 1], "r")) == NULL) {
      fprintf (stderr, "Cannot open spec file: %s\n", argv[i]);
      exit (1);
    }

    /* Parse.  Ignore blank lines.
     * TODO: More flexible parser.
     */
    while ((fgets (spec_line, MAX_SPEC_LINE, fp)) != NULL) {
      char *p, *p2, *p3, *p4;
      char spec_line_work[MAX_SPEC_LINE];

      if (spec_line[0] == '\n') {
	continue;
      }
      
      /* We need a working copy since we'll add zeroes and we might
       * need the original.
       */

      strcpy (spec_line_work, spec_line);

      /* load four parameters, separated by EXACTLY ONE SPACE each, and
	 NO SPACE at the end.  FIXME. */
       
      if ((p = (char *)strchr(spec_line_work, ' ')) == NULL) {
	fprintf (stderr, "Cannot parse line: %s\n", spec_line);
      }

      *p++ = 0;

      /* At this point, p points to the start of the IP number. */
      if ((p2 = (char *)strchr(p, ' ')) == NULL) {
	fprintf (stderr, "Cannot parse line: %s\n", spec_line);
      }

      *p2++ = 0;

      /* At this point, p2 points to the start of the first time. */
      if ((p3 = (char *)strchr(p2, ' ')) == NULL) {
	fprintf (stderr, "Cannot parse line: %s\n", spec_line);
      }
      *p3++ = 0;

      /* At this point, p3 points to the start of the second time.
       * Replace the newline with an end-of-string zero.
       */
      if ((p4 = (char *)strchr (p3, '\n')) != NULL) {
	*p4 = 0;
      }

      /* Parse. */
      if (((*itlp_p++) = make_lookup(spec_line_work, p, p2, p3)) == NULL) {
	fprintf (stderr, "Cannot understand line: %s\n", spec_line);
	exit (1);
      }

      /* Check if we have hit our maximum line count. */
      if (++n_itl == MAX_SPEC) {
	fprintf (stderr, "Reached maximum line count of %d\n", MAX_SPEC);
	exit (1);
      }
    }

      
    fclose(fp);
    
  }

  /* if have spec filename, use it.  for testing, just use command line */

  /* input from stdin */
  if (ftio_init(&ftio_in, 0, FT_IO_FLAG_READ) < 0)
    fterr_errx(1, "ftio_init(): failed");

  if (ftio_check_generic(&ftio_in) < 0)
    fterr_errx(1, "flow-filter does not yet support PDU format");

  ftio_get_ver(&ftio_in, &ftv);
  ftv.s_version = FT_IO_SVERSION;

  if ((ftv.d_version == 5) || (ftv.d_version == 6) || (ftv.d_version == 7))
    as_present = 1;

  /* output to stdout */
  if (ftio_init(&ftio_out, 1, FT_IO_FLAG_WRITE |
    ((ftset.z_level) ? FT_IO_FLAG_ZINIT : 0) ) < 0)
    fterr_errx(1, "ftio_init(): failed");

  ftio_set_comment(&ftio_out, ftset.comments);
  ftio_set_byte_order(&ftio_out, ftset.byte_order);
  ftio_set_z_level(&ftio_out, ftset.z_level);
  ftio_set_streaming(&ftio_out, 1);
  ftio_set_debug(&ftio_out, debug);

  if (ftio_set_ver(&ftio_out, &ftv) < 0)
    fterr_errx(1, "ftio_set_ver(): failed");

  /*
   * normalize masks
   */
  /* XXX TODO */

  /* header first */
  if (ftio_write_header(&ftio_out) < 0)
    fterr_errx(1, "ftio_write_header(): failed");


  /* grab 1 flow */
  while ((rec = ftio_read(&ftio_in))) {
    struct fttime ftt;
    int is_output;

    rec_v5 = rec;
    rec_gen = rec;


    ++ total_flows;

    ftt = ftltime(rec_gen->sysUpTime, rec_gen->unix_secs, rec_gen->unix_nsecs,
		  rec_gen->First);
    
    /* Check against itlp */

    /* Time before IP. Or should it be the other way around? 
       This is not as efficient as can be. */

    /* recycle i */
    i = n_itl;
    itlp_p = itlp;
    is_output = 0;

    while ((is_output == 0) && (i--)) {

      if ((ftt.secs > (*itlp_p)->start) && (ftt.secs < (*itlp_p)->stop)) {
	if ((*itlp_p)->srcaddr == 0) {
	  if ((*itlp_p)->dstaddr == 0) {
	    /* both 0, don't check IP's */
	    is_output = 1;
	  }
	  else if ((*itlp_p)->dstaddr == rec_gen->dstaddr) {
	    is_output = 1;
	  }
	}
	else if ((*itlp_p)->dstaddr == 0) {
	  /* case of srcaddr also == 0 covered above */
	  if ((*itlp_p)->srcaddr == rec_gen->srcaddr) {
	    is_output = 1;
	  }
	}
	else {
	/* both > 0 */
	  if (((*itlp_p)->srcaddr == rec_gen->srcaddr) &&
	      ((*itlp_p)->dstaddr == rec_gen->dstaddr)) {
	    is_output = 1;
	  }
	}
      }
      else {
	/* Didn't match the time. */
      }

      itlp_p++;
    } /* while () */


    /*
     * made it by the filters, write it
     */

    if (is_output) {
      if (ftio_write(&ftio_out, rec) < 0)
	fterr_errx(1, "ftio_write(): failed");
    }

  } /* while more flows to read */

  if (ftio_close(&ftio_in) < 0)
    fterr_errx(1, "ftio_close(): failed");

  if (ftio_close(&ftio_out) < 0)
    fterr_errx(1, "ftio_close(): failed");

  if (debug > 0) {
    ftprof_end (&ftp, total_flows);
    ftprof_print(&ftp, argv[0], stderr);
  }   


  return 0;

} /* main */

void usage() {
  fprintf(stderr, "flow-iptime [-f spec-file | ip1 ip2 start stop]");
  fprintf(stderr, "\n");
  fprintf(stderr, "%s version %s: built by %s\n", PACKAGE, VERSION, FT_PROG_BUILD);
} /* usage */

