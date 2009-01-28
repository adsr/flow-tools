/* $Id: flow-divide.c,v 1.3 2002/05/15 08:29:34 wyy Exp $ */
/**
 *
 * Inter.net Philippines Patches to Flow-tools
 *
 * William Emmanuel S. YU <wyu@ateneo.edu>
 * Ateneo de Manila University, Philippines
 *
 * Miguel A. Paraz <map@internet.org.ph>
 * Inter.net Philippines 
 * 
 * Requires Flow-Tools-0.57
 * Copyright (c) 2001 Mark Fullmer and The Ohio State University
 * All rights reserved.
 *
 * 05142002 wyu added flow-split incoming and outgoing packets
 * 05142002 wyu intelligent append to if flow file exists
 * 06142002 wyu renamed flow-divide to not conflict with flow-split
 * 09292003 wyu build fixes
 *
**/

/**
 * redone version of flow-divide. dues to problems with the 
 * original i rewrote it. flow-split receives flow data and
 * then splits it into multiple files based on the a spec
 * file definted below. by default flow-split collects incoming
 * packets.
 * 
 * file on command line will contain:
 * 
 * file1 net1 net2 net3...
 * file2 net1 net2 net3...
 * 
**/

/* generic defines */
#define FTIO_OUT_MAX 65535
#define UNKNOWN_FILE "others.dump"

/* generic includes */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>

/* network related includes */
#include <netinet/in.h>

/* flow-tools related includes */
#include "ftlib.h"
#include "ftbuild.h"
#include "ftconfig.h"

/* patricia tree related includes */
#include "patricia.h"

/* function declarations */
void usage();

int main(int argc, char *argv[])
{
  extern char *optarg;
  struct ftio ftio;

  char *inputfile;
  FILE *desc_file;
  int others_fd;
  struct ftio others_file;
  struct ftio ftio_out[FTIO_OUT_MAX];
  struct fts3rec_v5 *rec;
  char buf[512];
  int ftio_out_count, i;
  patricia_tree_t *pt;
  patricia_node_t *pn;
  prefix_t *pref;
  struct ftver ftv;
  struct ftset ftset;
  int flag_reverse = 0;
  
  if (argc <= 1) {
        usage();
        return(0);
  }

  while ((i = getopt(argc, argv, "f:rgvh")) != -1)
  switch (i) {
    case 'v': 
      printf("%s version %s: built by %s\n", PACKAGE, VERSION, FT_PROG_BUILD);
      return(0);
      break;
    case 'f':
      inputfile = optarg;
      break;
    case 'r':
      flag_reverse = 1;
      break;
    case 'h':
    default:
      usage();
      return(0);
      break;
  }

  if ((desc_file = fopen(inputfile, "r")) == NULL) {
    fprintf (stderr, "could not open description filename: %s\n", argv[1]);
    return 1;
  }

  /* generate the others.dump file for the unaccounted packets. */
  others_fd = open(UNKNOWN_FILE, O_WRONLY | O_TRUNC | O_CREAT, 0644);

  if (others_fd < 0) {
     fprintf (stderr, "cannot open for writing dump file \n");
     return 1;
  }

  ftset_init(&ftset, 0);
  memset(&ftv, 0, sizeof(ftv));
  ftv.s_version = FT_IO_SVERSION;
  ftv.d_version = 5;
  ftv.agg_method = 1;
  ftv.agg_version = 2;

  if (ftio_init(&others_file, others_fd, FT_IO_FLAG_WRITE) < 0)
  {
     fprintf (stderr, "cannot initialize for writing dump file\n");
     return 1;
  }

  if (ftio_set_ver(&others_file, &ftv) < 0) {
     fprintf (stderr, "cannot set version dump file \n");
     return 1;
  }

  ftio_set_byte_order(&others_file, ftset.byte_order);
  ftio_set_streaming(&others_file, 1);

  if (ftio_write_header(&others_file) < 0) {
     fprintf (stderr, "cannot write header of dump file \n");
     return 1;
  }
  /* end of segment to initialize others file */

  /** 
        this segment parses the configuration file 
        the format of the configuration file is as follows:

        filename prefix1 prefix2 prefix3
  */
  pt = New_Patricia(32);
  ftio_out_count = 0;

  while (fgets (buf, 160, desc_file) != NULL) {
    char *s, *s2;
    int fd;

    /* Format: filename prefix1 prefix2 prefix3... */

    s = strchr(buf, '\n');
    *s = 0;

    s = strchr(buf, ' ');
    if (s == NULL) 
      break;

    /* Null terminate the filename and move to the first prefix */
    *s++ = 0; 

	/* manipulate flow file if exists then append if not create */
	if ( (fd = open(buf, O_WRONLY | O_CREAT | O_EXCL, 0644)) < 0) {

#ifdef DEBUG
	fprintf (stderr,"file exists appending\n");
#endif

      close (fd);
	  fd = open (buf, O_WRONLY | O_APPEND, 0644);

      if (fd < 0) {
        fprintf (stderr, "cannot open for writing: %s\n", buf);
        return 1;
      }

      if (ftio_init(ftio_out + ftio_out_count, fd, FT_IO_FLAG_WRITE) < 0) {
        fprintf (stderr, "cannot initialize for writing: %s\n", buf);
        return 1;
      }

      if (ftio_set_ver(ftio_out + ftio_out_count, &ftv) < 0) {
        fprintf (stderr, "cannot set version: %s\n", buf);
        return 1;
      }

      ftio_set_byte_order(ftio_out + ftio_out_count, ftset.byte_order);
      ftio_set_streaming(ftio_out + ftio_out_count, 1);


    } else {

#ifdef DEBUG
	fprintf (stderr,"file does not exists creating\n");
#endif

      /* creating flow file header */
      ftset_init(&ftset, 0);
      memset(&ftv, 0, sizeof(ftv));
      ftv.s_version = FT_IO_SVERSION;
      ftv.d_version = 5;
      ftv.agg_method = 1;
      ftv.agg_version = 2;

      if (ftio_init(ftio_out + ftio_out_count, fd, FT_IO_FLAG_WRITE) < 0) {
        fprintf (stderr, "cannot initialize for writing: %s\n", buf);
        return 1;
      }

      if (ftio_set_ver(ftio_out + ftio_out_count, &ftv) < 0) {
        fprintf (stderr, "cannot set version: %s\n", buf);
        return 1;
      }

      ftio_set_byte_order(ftio_out + ftio_out_count, ftset.byte_order);
      ftio_set_streaming(ftio_out + ftio_out_count, 1);

      if (ftio_write_header(ftio_out + ftio_out_count) < 0) {
        fprintf (stderr, "cannot write header: %s\n", buf);
        return 1;
      }

    }

    while (s != NULL) {
      s2 = strchr(s,' ');
      if (s2 != NULL) { 
        *s2++=0;
      }

#ifdef DEBUG
      printf("s = %s.\n",s);
      printf("s2 = %s.\n",s2);
#endif

      if ((pref = ascii2prefix(AF_INET, s)) == NULL) {
        fprintf (stderr, "invalid prefix: %s\n", s);
        return 1;
      }

      if ((pn = patricia_lookup(pt, pref)) == NULL) {
        fprintf (stderr, "could not create node for prefix: %s\n", s);
      }

      /* All we really want to store */
      pn->data = ftio_out + ftio_out_count;
      s = s2;
    }

    if (++ftio_out_count == FTIO_OUT_MAX) {
      fputs ("too many files, ignoring the rest.\n", stderr);
      break;
    }
  }
  fclose (desc_file);


  /* At this point we have the tree */

  /* read flowfile from stdin */
  if (ftio_init(&ftio, 0, FT_IO_FLAG_READ) < 0) {
    fprintf(stderr, "ftio_init(): failed\n");
    exit (1);
  }

  while ((rec = ftio_read(&ftio))) {
    prefix_t pref_tmp;

    if (flag_reverse) 
      pref_tmp.add.sin.s_addr = ntohl(rec->srcaddr);
    else
      pref_tmp.add.sin.s_addr = ntohl(rec->dstaddr);
	
    pref_tmp.bitlen = 32;

    if ((pn = patricia_search_best(pt, &pref_tmp)) != NULL) {
      if(ftio_write((struct ftio *)pn->data, rec) < 0) {
        fprintf(stderr,"Error writing flow file.\n");
        exit(-1);
      }
    }
    else {
      /* writing all other packets to the others file */
      if(ftio_write(&others_file, rec) < 0) {
        fprintf(stderr,"Error writing flow file.\n");
        exit(-1);
      }
    }
  }


  /* We are done, close down. */
  for (i = 0; i < ftio_out_count; i++) {
    ftio_close(ftio_out + i);
  }
  ftio_close(&others_file);

  return 0;

} /* main */


/** 
        usage() - displayed usage message 
 */
void usage()
{
  fprintf(stderr, "flow-divide:\n");
  fprintf(stderr, " -f filename  input filename\n");
  fprintf(stderr, " -r           reverse packet collection to incoming\n");
  fprintf(stderr, " -v           show version number\n");
  fprintf(stderr, " -h           help\n");
  fprintf(stderr, "%s version %s: built by %s\n", PACKAGE, VERSION, FT_PROG_BUILD);
} /* usage() */
