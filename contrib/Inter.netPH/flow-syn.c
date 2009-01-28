/* $Id: flow-syn.c,v 1.2 2002/05/14 02:37:46 wyy Exp $ */
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
 * flow-syn [-t]
 * no parameters: output in raw format for piping to other tools
 * -t: output in text mode
 *
**/

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

#include "ftlib.h"
#include "ftbuild.h"
#include "ftconfig.h"

int debug;

/* lookup structure */
struct iptime_lookup {
  u_int32 srcaddr;
  u_int32 dstaddr;
  int start;
  int stop;
};

void usage();

int main(int argc, char **argv)
{
  extern char *optarg;
  struct ftio ftio_in, ftio_out;
  struct ftset ftset;
  struct ftver ftv;
  struct ftprof ftp;
  struct fts3rec_v5 *rec_v5;
  int i, is_text;
  void *rec;

  u_int64 total_flows;

  extern int optind;


  /* init fterr */
  fterr_setid(argv[0]);

  /* profile */
  ftprof_start (&ftp);

  bzero(&ftv, sizeof ftv);

  /* defaults + no compression */
  ftset_init(&ftset, 0);

  /* init */
  total_flows = 0;

  while ((i = getopt(argc, argv, "tf:")) != -1)
    switch (i) {

    case 't': /* text */
      is_text = 1;
      break;

    case 'd': /* debug */
      debug = atoi(optarg);
      break;


    } /* switch */

  /* input from stdin */
  if (ftio_init(&ftio_in, 0, FT_IO_FLAG_READ) < 0)
    fterr_errx(1, "ftio_init(): failed");

  if (ftio_check_generic(&ftio_in) < 0)
    fterr_errx(1, "flow-filter does not yet support PDU format");

  ftio_get_ver(&ftio_in, &ftv);
  ftv.s_version = FT_IO_SVERSION;

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

  /* header first */
  if (!is_text) {
    if (ftio_write_header(&ftio_out) < 0)
      fterr_errx(1, "ftio_write_header(): failed");
  }


  /* grab 1 flow */
  while ((rec = ftio_read(&ftio_in))) {
    rec_v5 = rec;

    ++ total_flows;

    /* Output if and only if the flag is SYN alone */
    if ((rec_v5->prot == IPPROTO_TCP) && (rec_v5->tcp_flags == 2)) {
      if (is_text) {
	  struct fttime ftt;
	  char fmt_buf1[64], fmt_buf2[64];

	  fmt_ipv4(fmt_buf1, rec_v5->srcaddr, FMT_PAD_RIGHT);
	  fmt_ipv4(fmt_buf2, rec_v5->dstaddr, FMT_PAD_RIGHT);

	  ftt = ftltime(rec_v5->sysUpTime, rec_v5->unix_secs,
			rec_v5->unix_nsecs, rec_v5->First);

	  /* Time, source IP, dest IP, source port, dest port */
	  printf ("%10d %-15s %-15s %5d %5d\n", ftt.secs, fmt_buf1, fmt_buf2,
		  (int)rec_v5->srcport, (int)rec_v5->dstport);
		  
	  
      }
      else {
	if (ftio_write(&ftio_out, rec) < 0)
	  fterr_errx(1, "ftio_write(): failed");
      }
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
  fprintf(stderr, "flow-syn");
  fprintf(stderr, "\n");
  fprintf(stderr, "%s version %s: built by %s\n", PACKAGE, VERSION, FT_PROG_BUILD);
  exit(1);
} /* usage */

