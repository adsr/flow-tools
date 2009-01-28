/* $Id: flow-as-if.c,v 1.2 2002/05/14 02:37:46 wyy Exp $ */
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

/* subnets summary, with ASN and source interface.  must specify
   interfaces on the command line */

/* generic defines */
#define IF_MAX             16
#define ARRAY_NODE_TOPSIZE 64

/* generic includes */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <time.h>

/* network related includes */
#include <netinet/in.h>

/* flow-tools related includes */
#include <fcntl.h>
#include "ftlib.h"
#include "ftbuild.h"
#include "ftconfig.h"

/* patricia tree related includes */
#include "patricia.h"

struct array_node {				/* array node of the tree */
  u_int16 src_as;
  u_int32 dOctets;
  u_int32 exaddr;
  /* Whatever other data */
};

struct leaf_node {				/* leaf node of the tree */
  
  /* Actual data */
  struct array_node a_node[ARRAY_NODE_TOPSIZE];

  /* How many we have in here.  If in excess, follow the linked list */
  int n_arrays;
  struct leaf_node *next;
};

struct output_record {				/* record for storing output */
  u_int32 dOctets;
  u_int32 dstaddr;
  u_int8  dstmask;
  u_int16 src_as;
  u_int32 exaddr;
  u_int16 input;
};

/* function declarations */
extern prefix_t * New_Prefix (int family, void *dest, int bitlen);
int sort_compare_output_record (const void *pa, const void *pb);
int process(struct ftio *ftio);
void usage();

/* define debugging version of malloc */
#ifdef DEBUG
int mem;

void *MALLOC (size_t size) {
  mem += size;
  return malloc (size);
}

#else
#define MALLOC(x) malloc(x)
#endif

/* globally defined variables */
int n_total_nodes;				/* total number of nodes */
static struct output_record *p_o_r;		/* pointer for array-ll */
patricia_tree_t *inside_tree[IF_MAX];		/* one tree per interface */
int n_if_table=0;				/* number of interfaces */
int if_table[IF_MAX];				/* table of interfaces */
int match_client=0;
int match_exact=0;
prefix_t pref_tmp;				/* multipurpose addr holder */

patricia_tree_t *client_pt;                     /* variables for desc tree */
patricia_node_t *client_pn;

/* the main function */
int main(int argc, char *argv[])
{
  int i, ret;
  extern char *optarg;
  struct ftio ftio;

  patricia_node_t *node;
  struct output_record *o_r;
  int *p_i;

  prefix_t *pref;
  FILE *desc_file;

  char *inputfile;				/* manipulating args */
  char *int_string;
  char *s;
  char buf[512];

  int n_entries=0;

#ifdef DEBUG
  int debug_counter;
#endif

  if (argc <= 1) {
        usage();
        return(0);
  }

  while ((i = getopt(argc, argv, "i:f:vhec")) != -1)
  switch (i) {
    case 'v': 
      printf("Version 0.01 Copyright 2001 William Emmanuel S. Yu\n");
      return(0);
      break;
    case 'i':
      int_string = optarg;
      break;
    case 'f':
      inputfile = optarg;
      break;
    case 'e':
      match_exact = 1;
      break;
    case 'c':
      match_client = 1;
      break;
    case 'h':
    default:
      usage();
      return(0);
      break;
  }

  /* check the number of interfaces */
  p_i = if_table;

  while (int_string != NULL) {
    s = strchr(int_string, ',');
    if (s != NULL) {
       *s++=0;
    }

    *(p_i++)=atoi(int_string);
    n_if_table++;

    int_string = s; 
  };

  if (n_if_table > IF_MAX) {
    fputs("too many SNMP interface IDs on command line\n", stderr);
    return 1;
  }

  if (n_if_table <= 0) {
    fputs("need at least one SNMP interface ID on command line\n", stderr);
    return 1;
  }

  /** 
     generate patricia tree for our descriptions based on 
     the description file 

     filename prefix1 prefix2 prefix3

    */
  if ((desc_file = fopen(inputfile, "r")) == NULL) {
    fprintf (stderr, "could not open description filename: %s\n", argv[1]);
    return 1;
  }

  client_pt = New_Patricia(32);

  while (fgets (buf, 160, desc_file) != NULL) {
    char *s, *s2;

    s = strchr(buf, '\n');
    *s = 0;

    s = strchr(buf, ' ');
    if (s == NULL) 
      break;

    *s++ = 0; 
  
    while (s != NULL) {
      char *client_string;

      s2 = strchr(s,' ');
      if (s2 != NULL) { 
        *s2++=0;
      }

      if ((pref = ascii2prefix(AF_INET, s)) == NULL) {
        fprintf (stderr, "invalid prefix: %s\n", s);
        return 1;
      }

      if ((client_pn = patricia_lookup(client_pt, pref)) == NULL) {
        fprintf (stderr, "could not create node for prefix: %s\n", s);
      }

      /* All we really want to store */
      client_string = MALLOC(sizeof(buf)+1);
      strcpy(client_string,buf);
      client_pn->data = client_string;
      s = s2;
    }
  }
  fclose(desc_file);
  /* end generating patricia tree */ 

  /* start reading flow file and do analysis */
  /* read from stdin */
  if (ftio_init(&ftio, 0, FT_IO_FLAG_READ) < 0) {
    fprintf(stderr, "ftio_init(): failed\n");
    exit (1);
  }

  /* Create */
  n_total_nodes = 0;
  ret = process(&ftio);

  /* Calculate how many entries we need - worst case estimate */

  o_r = p_o_r = MALLOC (n_total_nodes * ARRAY_NODE_TOPSIZE * sizeof(*o_r));

  for (i = 0; i < IF_MAX; i++) {
    if (inside_tree[i] == NULL)
      continue;

    /* Dump the trees to the output record */
    PATRICIA_WALK(inside_tree[i]->head, node) {
      struct leaf_node *pn = (struct leaf_node *)(node->data);

      while (pn != NULL) {
	int j;

	for (j = 0; j < pn->n_arrays; j++) {

	  u_int32 o = pn->a_node[j].dOctets;

	  if (o > 0) {
	    p_o_r->dOctets = o;
	    p_o_r->exaddr  = pn->a_node[j].exaddr;
	    p_o_r->src_as  = pn->a_node[j].src_as;
	    p_o_r->dstaddr = node->prefix->add.sin.s_addr;
	    p_o_r->dstmask = node->prefix->bitlen;
	    p_o_r->input   = if_table[i];

	    p_o_r++;
	    n_entries++;
	  }
	}
	pn = pn->next;
      }
    }
    PATRICIA_WALK_END;
  }

#ifdef DEBUG
  debug_counter=0;
  printf("end walk: %d entries.\n",n_entries);
#endif

  /* Sort */ 
  qsort(o_r, n_entries, sizeof(*o_r), sort_compare_output_record);

  /* Output */
  p_o_r = o_r;
  while (n_entries--) {
    char fmt_buf1[64];
    char fmt_buf2[64];

#ifdef DEBUG
  debug_counter++;
#endif

    /* converting IP to string */
    fmt_ipv4(fmt_buf1, p_o_r->dstaddr, FMT_PAD_RIGHT);
    fmt_ipv4(fmt_buf2, p_o_r->exaddr, FMT_PAD_RIGHT);

    /* this "if" should be unnecessary but they are not eliminated above */
    if (p_o_r->dOctets > 0) {
      printf ("%12d %5d %5d %s/%2d ", p_o_r->dOctets, p_o_r->input,
	      p_o_r->src_as, fmt_buf1, p_o_r->dstmask); 

      /* generate readable form */
      pref_tmp.add.sin.s_addr = ntohl(p_o_r->dstaddr);
    
      if ((pref_tmp.bitlen = p_o_r->dstmask) == 0) {
         pref_tmp.bitlen = 32;
      }

      if ((client_pn = patricia_search_best(client_pt, &pref_tmp)) != NULL) {
      	 printf ("%15.15s",(char *)client_pn->data);
      } else {
         printf ("        unknown");
      }

      printf (" %s\n",fmt_buf2);
    }
    p_o_r++;

  }

  /* done! */

#ifdef DEBUG
  fprintf (stderr, "mem: %d\n", mem);
#endif

  return 0;

} /* main */




/**
	process() - function for reading the flow file and propagating
	the patricia tree
 */
int process(struct ftio *ftio)
{
  struct fts3rec_v5 *rec;
  prefix_t pref_out;
  patricia_node_t *pn;
  int if_e, *p;

#ifdef LIMIT
  int n = 0;
#endif

  if (ftio_check_generic(ftio) < 0)
    return -1;

  pref_out.family = AF_INET;
  pref_out.ref_count = 0;

  while ((rec = ftio_read(ftio))

#ifdef LIMIT
	 && (n++ < LIMIT)
#endif
	 ) {

    /* Find the interface entry */
    if_e = 0;
    p = if_table;

    while ((if_e < n_if_table) && (*p++ != rec->input)) {
      if_e++;
    }
    if (if_e == n_if_table) {
      /* Ignore this unspecified interface */
      continue;
    }
    
    pref_out.add.sin.s_addr = rec->dstaddr;

    if ((match_exact!=1) && (match_client!=1)) {
       pref_out.bitlen = rec->dst_mask;

       /* Don't process 0 or 32 masks */
       if (pref_out.bitlen == 0) {
           pref_out.bitlen = 32;
       }
    } 
    
    if (match_client==1) {

      /* FIXME - must be able to change this to srcaddr later */
      pref_tmp.add.sin.s_addr = ntohl(rec->dstaddr);
      pref_tmp.bitlen = 32;

      if ((client_pn = patricia_search_best(client_pt, &pref_tmp)) != NULL) {
         pref_out.bitlen = client_pn->prefix->bitlen;
      } else {
         pref_out.bitlen = 32; 
      }
      
    } 
    
    if (match_exact==1) {
       pref_out.bitlen = 32;
    }

    /* Mask the pref_in by its netmask */
    pref_out.add.sin.s_addr &=
      (0xffffffff ^ ((1 << (32 - pref_out.bitlen)) - 1));

    /* Does this interface have a tree yet? */
    if (inside_tree[if_e] == NULL) {
      if ((inside_tree[if_e] = New_Patricia(32)) == NULL) {
	fputs ("inside tree New failed\n", stderr);
      }
      pn = NULL;
    }

    if (pn != NULL) {
      /* Search for the best network */
      pn = patricia_search_best(inside_tree[if_e], &pref_out);
    }

    if (pn == NULL) {
      
      /* Add a node */
      if ((pn = patricia_lookup(inside_tree[if_e], &pref_out)) == NULL) {
	fputs ("inside patricia_lookup failed", stderr);
	exit(1);
      }
   
      /* Create the leaf node data */
      if ((pn->data = MALLOC(sizeof(struct leaf_node))) == NULL) {
	fputs ("MALLOC pn->data failed", stderr);
	exit (1);
      }

      /* Just one element, points to nothing */
      ((struct leaf_node *)pn->data)->n_arrays = 1;
      ((struct leaf_node *)pn->data)->next = NULL;

      /* Content */
      ((struct leaf_node *)pn->data)->a_node[0].src_as  = rec->src_as;
      ((struct leaf_node *)pn->data)->a_node[0].dOctets = rec->dOctets;
      ((struct leaf_node *)pn->data)->a_node[0].exaddr = rec->exaddr; 

      /* Need this for tracking: sort buffer and tree walk */
      n_total_nodes++;

    }
    else {
      /* We have the starting leaf node, look if we have the ASN already */
      struct array_node *anp;
      struct leaf_node *lnpb, *lnp = (struct leaf_node *)pn->data;
      int found = 0;

      while ((lnp != NULL) && !found) {
	int  i = 0;

	anp = lnp->a_node;
	i   = lnp->n_arrays;

	while ((i--) && !found) {
	  if (anp->src_as == rec->src_as) {
	    found = 1;
	  }
	  else {
	    anp++;
	  }
	}

	if (!found) {
	  lnpb = lnp;
	  lnp  = lnp->next;
	}
      }

      if (!found) {
	/* Not found, see if the array is full already */
	if (lnpb->n_arrays == ARRAY_NODE_TOPSIZE) {

	  /* Full, create a new leaf node */
	  if ((lnp = MALLOC(sizeof(*lnp))) == NULL) {
	    fputs ("MALLOC lnp failed\n", stderr);
	    exit (1);
	  }

	  /* Fill in the data */
	  lnp->n_arrays          = 1;
	  lnp->next              = NULL;
	  lnp->a_node[0].src_as  = rec->src_as;
	  lnp->a_node[0].dOctets = rec->dOctets;
	  lnp->a_node[0].exaddr  = rec->exaddr;

	  /* Backlink */
	  lnpb->next = lnp;
	  n_total_nodes++;
	}
	else {
	  /* Not full, just add to the last node */
	  int i = lnpb->n_arrays;
#ifdef DEBUG
	if (i >= ARRAY_NODE_TOPSIZE) {
	    fputs ("GOTCHA 2", stderr);
	  }
#endif

	  lnpb->a_node[i].src_as  = rec->src_as;
	  lnpb->a_node[i].dOctets = rec->dOctets;
          lnpb->a_node[i].exaddr  = rec->exaddr;
	  lnpb->n_arrays++;
	
	}
      }
      else {
	/* Found, just update */
	anp->dOctets += rec->dOctets;
      }
    }

  } /* while */

  return 0;

} /* process() */

/**
	sort_compare_output_record() - function to be feed to qsort 
	function for sorting records by octet size.
 */
int sort_compare_output_record (const void *pa, const void *pb) {
  if (((struct output_record *)pb)->dOctets <
      ((struct output_record *)pa)->dOctets) {
    return -1;
  }
  else if (((struct output_record *)pb)->dOctets >
      ((struct output_record *)pa)->dOctets) {
    return 1;
  }
  else return 0;
} /* sort_compare_output_record() */

/** 
        usage() - displayed usage message 
 */
void usage()
{
  fprintf(stderr, "flow-as-if:\n");
  fprintf(stderr, " -f filename    input definition file\n");
  fprintf(stderr, " -i interfaces  interface list\n");
  fprintf(stderr, " -e 		   exactly match IPs\n");
  fprintf(stderr, " -c 		   exactly match client\n");
  fprintf(stderr, " -v             show version number\n");
  fprintf(stderr, " -h             help\n");
  fprintf(stderr, "%s version %s: built by %s\n", PACKAGE, VERSION, FT_PROG_BUILD);
} /* usage() */
