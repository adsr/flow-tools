/* $Id: flow-cidr.c,v 1.2 2002/05/14 02:37:46 wyy Exp $ */
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
 * 07042002 wyu remove flow-divide functionality
 * 07042002 wyu added output compression and classes 
 * 07042002 wyu added tag filtering support
 * 08292003 wyu build fixes
**/


/**
 * flow-cidr is a supplement to flow-filter that supports
 * CIDR addresses and tags
**/

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
#include <netdb.h>

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

  char *inputfile;
  char *clientname;
  char *ipblock; 
  FILE *desc_file;
  int out_fd,i,debug;
  int dstflag=0;
  int tagflag = 0; 
  u_int32 tagnum;
  u_int64 xflag;
  struct ftio ftio_in, ftio_out;
  struct fts3rec_all cur;
  struct fts3rec_offsets fo;
  char *rec;
  char buf[512];
  patricia_tree_t *pt;
  patricia_node_t *pn;
  prefix_t *pref;
  struct ftver ftv;
  struct ftset ftset;
  int opt; 
  int clientname_exist=0;

  if (argc <= 1) {
        usage();
        return(0);
  }

  while ((i = getopt(argc, argv, "f:i:I:t:T:vhbCdz")) != -1)
  switch (i) {
    case 'v': 
      printf("%s version %s: built by %s\n", PACKAGE, VERSION, FT_PROG_BUILD);
      return(0);
      break;
    case 'b': /* output byte order */
      if (!strcasecmp(optarg, "little"))
        ftset.byte_order = FT_HEADER_LITTLE_ENDIAN;
      else if (!strcasecmp(optarg, "big"))
        ftset.byte_order = FT_HEADER_BIG_ENDIAN;
      else
        fterr_errx(1, "expecting \"big\" or \"little\"");
      break;
    case 'C': /* comment field */
      ftset.comments = optarg;
      break;
    case 'd': /* debug */
      debug = atoi(optarg);
      break;
    case 'z': /* compress level */
      ftset.z_level = atoi(optarg);
      if ((ftset.z_level < 0) || (ftset.z_level > 9))
        fterr_errx(1, "Compression level must be between 0 and 9");
      break;
    case 't':
      opt=2;
      tagflag = 0;
      tagnum = (unsigned)strtol(optarg, (char**)0L, 0); 
      break;
    case 'T': 
      opt=2;
      tagflag = 1;
      tagnum = (unsigned)strtol(optarg, (char**)0L, 0);
      break;
    case 'h':
    default:
      usage();
      return(0);
      break;
    case 'i':
      opt=1;
      dstflag = 0;
      ipblock = optarg;
      break;
    case 'I':
      opt=1;
      dstflag = 1;
      ipblock = optarg;
      break;
  }

  /* generate the output stream for the match packets. */
  ftset_init(&ftset, 0);
  memset(&ftv, 0, sizeof(ftv));
  ftv.s_version = FT_IO_SVERSION;
  ftv.d_version = 5;
  ftv.agg_method = 1;
  ftv.agg_version = 2;

  /* read flowfile from stdin */
  if (ftio_init(&ftio_in, 0, FT_IO_FLAG_READ) < 0)
    fterr_errx(1, "ftio_init(): failed");

  ftio_get_ver(&ftio_in, &ftv);
  ftv.s_version = FT_IO_SVERSION;

  xflag = 0;
  if (opt == 2) {
    xflag |= FT_XFIELD_SRC_TAG;
    xflag |= FT_XFIELD_DST_TAG;
  }

  if (opt == 1) {
    xflag |= FT_XFIELD_SRCADDR;
    xflag |= FT_XFIELD_DSTADDR;
  }

  if (ftio_check_xfield(&ftio_in, xflag)) {
    fterr_warnx("Flow record missing required field for format.");
    exit (1);
  }

  fts3rec_compute_offsets(&fo, &ftv);

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
  if (ftio_write_header(&ftio_out) < 0)
    fterr_errx(1, "ftio_write_header(): failed");

  /* actual reading from the flow source */
  while ((rec = ftio_read(&ftio_in))) {
    prefix_t *pref_out,pref_tmp;
    char* temp_string;

    /* Compute the following for a valid address. CIDR. */
    if(opt==1){
      u_int netmask;

      cur.dstaddr = ((u_int32*)(rec+fo.dstaddr));
      cur.srcaddr = ((u_int32*)(rec+fo.srcaddr));

      if (dstflag == 1) 
        pref_tmp.add.sin.s_addr = *cur.dstaddr;
      else pref_tmp.add.sin.s_addr = *cur.srcaddr;

      pref_tmp.bitlen = 32;

      pref_out=ascii2prefix(AF_INET,ipblock);
      pref_out->add.sin.s_addr = ntohl(pref_out->add.sin.s_addr);
      netmask = (0xffffffff ^ ((1 << (32 - pref_out->bitlen)) - 1));
      pref_tmp.add.sin.s_addr &= netmask;
      pref_tmp.bitlen=32;

      if (pref_out->add.sin.s_addr==pref_tmp.add.sin.s_addr){
	if(ftio_write(&ftio_out, rec) < 0) {
	    fprintf(stderr,"Error writing flow file.\n");
	    exit(-1);
	}
      }
    }
    
    /* Compute the following for a valid address. CIDR. */
    if (opt == 2) {
      int tagcurr;
	
      cur.dst_tag = ((u_int32*)(rec+fo.dst_tag));
      cur.src_tag = ((u_int32*)(rec+fo.src_tag));

      if (tagflag == 1) 
        tagcurr = *cur.dst_tag;
      else tagcurr = *cur.src_tag;
 
      if (tagcurr == tagnum) 
	if (ftio_write(&ftio_out, rec) < 0) {
	    fprintf(stderr,"Error writing flow file.\n");
	    exit(-1);
	}
    }

  } 

  if (ftio_close(&ftio_in) < 0)
    fterr_errx(1, "ftio_close(): failed");

  if (ftio_close(&ftio_out) < 0)
    fterr_errx(1, "ftio_close(): failed");
  
  return 0;

} /* main */


/**
 *  usage() - displayed usage message 
**/


void usage()
{
  fprintf(stderr, "flow-cidr:\n");
  fprintf(stderr, " -i ipblock   filter by source IP block\n ");
  fprintf(stderr, " -I ipblock   filter by destination IP block\n");
  fprintf(stderr, " -t tag       filter by source tag\n ");
  fprintf(stderr, " -T tag       filter by destination tag\n");
  fprintf(stderr, " -v           show version number\n");
  fprintf(stderr, " -h           help\n");
  fprintf(stderr, "%s version %s: built by %s\n", PACKAGE, VERSION, FT_PROG_BUILD);
} /* usage() */
