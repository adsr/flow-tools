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
 *      $Id: acl2.c,v 1.10 2003/04/02 18:03:01 maf Exp $
 */

#include "ftconfig.h"
#include <ftlib.h>

#include <stdio.h>
#include <stdlib.h>

#if HAVE_STRINGS_H
 #include <strings.h>
#endif

#if HAVE_STRING_H
  #include <string.h>
#endif

#ifdef NEED_MALLOC_H
#include <malloc.h>
#endif /* NEED_MALLOC_H */

#include "acl2.h"

struct acl_list acl_list;

#define E acl_list.acl_ip_ext[index]

#ifdef YYDEBUG
main() {

  extern struct acl_list acl_list;
  extern FILE *yyin;

  /* init */
  bzero(&acl_list, sizeof acl_list);

  yyin = stdin;

  while (!feof(yyin)) {
    yyparse();
  }

  acl_dump(acl_list);
  acl_delete_list(&acl_list);

  return 0;
} /* main */
#endif /* YYDEBUG */

#ifdef FOO
int main (int argc, char **argv)
{
  struct acl_list acl_list;
  struct acl_ip_std_entry std_entry;
  int x;

  /* init fterr */
  fterr_setid(argv[0]);

  /* init */
  bzero(&acl_list, sizeof acl_list);
  bzero(&std_entry, sizeof std_entry);

  x = acl_create(&acl_list, "99", ACL_TYPE_STD);
  acl_add_line_std(acl_list, x, std_entry);
  acl_add_line_std(acl_list, x, std_entry);

  x = acl_create(&acl_list, "name1", ACL_TYPE_STD);
  std_entry.flag = ACL_FLAG_PERMIT;
  std_entry.src_addr = 0xFFFFFFFF;
  std_entry.src_mask = 0x00FF00FF;
  acl_add_line_std(acl_list, x, std_entry);
  acl_add_line_std(acl_list, x, std_entry); 

  x = acl_create(&acl_list, "name2", ACL_TYPE_STD);
  acl_add_line_std(acl_list, x, std_entry);
  acl_add_line_std(acl_list, x, std_entry); 

  x = acl_create(&acl_list, "1", ACL_TYPE_STD);
  std_entry.flag = ACL_FLAG_PERMIT;
  std_entry.src_addr = 0x11111111;
  std_entry.src_mask = 0x01010101;
  acl_add_line_std(acl_list, x, std_entry);
  acl_add_line_std(acl_list, x, std_entry); 


  acl_dump(acl_list);
  acl_delete_list(&acl_list);

  return 0;
}
#endif /* FOO */

/*
 * create an access list, return the index on creation,
 * or -1 for error
 */
int acl_create(struct acl_list *acl_list, char *name, int type)
{
  int x, new;

  new = 0;   /* not a new entry */

  /* if this name allready exists, then return the index */
  if ((x = acl_find(*acl_list, name)) != -1)
    return x;

  if ((type != ACL_TYPE_STD) && (type != ACL_TYPE_EXT))
    return -1;

  /* initial? */
  if (!acl_list->num) {

    if (!(acl_list->names = (struct acl_names*)
      malloc(sizeof (struct acl_names)))) {
      fterr_warn("malloc(acl_list->names)");
      return -1;
    }

    if (!(acl_list->acl_ip_std = (struct acl_ip_std*)
      malloc(sizeof (struct acl_ip_std)))) {
      fterr_warn("malloc(acl_list->acl_ip_std)");
      return -1;
    }

    if (!(acl_list->acl_ip_ext = (struct acl_ip_ext*)
      malloc(sizeof (struct acl_ip_ext)))) {
      fterr_warn("malloc(acl_list->acl_ip_ext)");
      return -1;
    }

    ++acl_list->num;

    if (type == ACL_TYPE_STD)
      ++ acl_list->num_std;
    else if (type == ACL_TYPE_EXT)
      ++ acl_list->num_ext;
    
    
  } else { /* add */

    if (!(acl_list->names = (struct acl_names*) realloc(acl_list->names,
      (++acl_list->num) * sizeof (struct acl_names)))) {
      fterr_warn("realloc(acl_list->names)");
      return -1;
    }

    if (type == ACL_TYPE_STD) {

      if (!(acl_list->acl_ip_std = (struct acl_ip_std*)
        realloc(acl_list->acl_ip_std, (++acl_list->num_std) *
          sizeof (struct acl_ip_std)))) {
        fterr_warn("realloc(acl_list->ip_std)");
        return -1;
      }

    } else if (type == ACL_TYPE_EXT) {

      if (!(acl_list->acl_ip_ext = (struct acl_ip_ext*)
        realloc(acl_list->acl_ip_ext, (++acl_list->num_ext) *
          sizeof (struct acl_ip_ext)))) {
        fterr_warn("realloc(acl_list->ip_ext)");
        return -1;
      }

    }
  }

  acl_list->names[acl_list->num-1].name = strdup(name);
  acl_list->names[acl_list->num-1].type = type;

  if (type == ACL_TYPE_STD) {
    acl_list->names[acl_list->num-1].num = acl_list->num_std -1;
    acl_list->acl_ip_std[acl_list->num_std-1].num_lines = 0;
  } else if (type == ACL_TYPE_EXT) {
    acl_list->names[acl_list->num-1].num = acl_list->num_ext -1;
    acl_list->acl_ip_ext[acl_list->num_ext-1].num_lines = 0;
  }


  return acl_list->num-1;
  
} /* acl_create */

/*
 * free all memory associated with the acl's
 */
int acl_delete_list(struct acl_list acl_list)
{
  int x;

  for (x = 0; x < acl_list.num; ++x) {
    free(acl_list.names[x].name);
  }

  for (x = 0; x < acl_list.num_std; ++x)
    free(acl_list.acl_ip_std[x].line);

  for (x = 0; x < acl_list.num_ext; ++x)
    free(acl_list.acl_ip_ext[x].line);

  if (acl_list.names)
    free (acl_list.names);

  if (acl_list.acl_ip_std)
    free (acl_list.acl_ip_std);

  if (acl_list.acl_ip_ext)
    free (acl_list.acl_ip_ext);

  return 0;
  
} /* acl_delete_list */

/*
 * print out all access lists
 */

void acl_dump(struct acl_list acl_list)
{
  int x;

  for (x = 0; x < acl_list.num; ++x) {

    if (acl_list.names[x].type == ACL_TYPE_STD) {
      acl_dump_std(acl_list, x);
      fprintf(stderr, "\n");
    } else if (acl_list.names[x].type == ACL_TYPE_EXT) {
      acl_dump_ext(acl_list, x);
      fprintf(stderr, "\n");
    }
  } /* for */

} /* acl_dump */


/*
 * print out standard acl 
 */
void acl_dump_std(struct acl_list acl_list, int x)
{
  char fmt_buf[32], fmt_buf2[32], fmt_buf3[32];
  int y, i, numeric;
    
  /* named or numeric access list? */
  if (atoi(acl_list.names[x].name))
    numeric = 1;
  else
    numeric = 0;

  i = acl_list.names[x].num;
      
  for (y = 0; y < acl_list.acl_ip_std[i].num_lines; ++y) {

    fmt_ipv4(fmt_buf, acl_list.acl_ip_std[i].line[y].src_addr,
      FMT_JUST_LEFT);
    fmt_ipv4(fmt_buf2, acl_list.acl_ip_std[i].line[y].src_mask,
      FMT_JUST_LEFT);

    fmt_uint64(fmt_buf3, acl_list.acl_ip_std[i].line[y].matches,
      FMT_JUST_LEFT);
    
    if (numeric) 
      fprintf(stderr, "access-list %s %s %s %s",
        acl_list.names[x].name,
        (acl_list.acl_ip_std[i].line[y].flag &
          ACL_FLAG_PERMIT) ?
        "permit" : "deny", fmt_buf, fmt_buf2);
    else
      fprintf(stderr, "access-list standard %s %s %s %s",
        acl_list.names[x].name,
        (acl_list.acl_ip_std[i].line[y].flag &
          ACL_FLAG_PERMIT) ?
        "permit" : "deny", fmt_buf, fmt_buf2);

    if (acl_list.acl_ip_std[i].line[y].matches)
      fprintf(stderr, "   (%s matches)", fmt_buf3);

    fprintf(stderr, "\n");

  } /* for y */

} /* acl_dump_std */

/*
 * print out extended acl
 */
void acl_dump_ext(struct acl_list acl_list, int x)
{

  char fmt_buf[32], fmt_buf2[32], fmt_buf3[32], fmt_buf4[32];
  int y, i, numeric;
    
  /* named or numeric access list? */
  if (atoi(acl_list.names[x].name))
    numeric = 1;
  else
    numeric = 0;

  i = acl_list.names[x].num;


  for (y = 0; y < acl_list.acl_ip_ext[i].num_lines; ++y) {

    fmt_ipv4(fmt_buf, acl_list.acl_ip_ext[i].line[y].src_addr,
      FMT_JUST_LEFT);
    fmt_ipv4(fmt_buf2, acl_list.acl_ip_ext[i].line[y].src_mask,
      FMT_JUST_LEFT);
    fmt_ipv4(fmt_buf3, acl_list.acl_ip_ext[i].line[y].dst_addr,
      FMT_JUST_LEFT);
    fmt_ipv4(fmt_buf4, acl_list.acl_ip_ext[i].line[y].dst_mask,
      FMT_JUST_LEFT);

    if (numeric) 
      fprintf(stderr, "access-list %s %s xx %s %s  %s %s\n",
          acl_list.names[x].name, (acl_list.acl_ip_ext[i].line[y].flag &
          ACL_FLAG_PERMIT) ?  "permit" : "deny",
          fmt_buf, fmt_buf2, fmt_buf3, fmt_buf4);
    else 
      fprintf(stderr, "access-list extended %s %s xx %s %s  %s %s\n",
        acl_list.names[x].name, (acl_list.acl_ip_ext[i].line[y].flag &
        ACL_FLAG_PERMIT) ?  "permit" : "deny",
        fmt_buf, fmt_buf2, fmt_buf3, fmt_buf4);
  } /* for y */
  
} /* acl_dump_ext */

/*
 * return the index into acl_list that is "name", or
 * -1 for not found
 */
int acl_find(struct acl_list acl_list, char *name)
{

  int x;

  for (x = 0; x < acl_list.num; ++x)
    if (!strcmp(acl_list.names[x].name, name))
      return x;

  return -1;

} /* acl_find */

/*
 * add a filter list entry to a standard acl
 * returns -1 for error
 */
int acl_add_line_std(struct acl_list acl_list, int acl_index,
  struct acl_ip_std_entry acl_ip_std_entry)
{
  int index, line;

  /* index for this acl */
  index = acl_list.names[acl_index].num;

  /* initial? */
  if (!acl_list.acl_ip_std[index].num_lines) {

    if (!(acl_list.acl_ip_std[index].line = (struct acl_ip_std_entry*)
      malloc(sizeof (struct acl_ip_std_entry)))) {
      fterr_warn("malloc(acl_list.acl_ip_std[index].line)");
      return -1;
    }

    ++ acl_list.acl_ip_std[index].num_lines;

  } else {
  
    if (!(acl_list.acl_ip_std[index].line = (struct acl_ip_std_entry*)
      realloc(acl_list.acl_ip_std[index].line,
        ++ acl_list.acl_ip_std[index].num_lines *
        sizeof (struct acl_ip_std_entry)))) {
      fterr_warn("realloc(acl_list.acl_ip_std[index].line)");
      return -1;
    }
  }

  line = acl_list.acl_ip_std[index].num_lines - 1;

  bcopy(&acl_ip_std_entry, &acl_list.acl_ip_std[index].line[line], sizeof
    acl_ip_std_entry);

  return 0;


} /* acl_add_line_std */

/*
 * add a filter list entry to a extended acl
 * returns -1 for error
 */
int acl_add_line_ext(struct acl_list acl_list, int acl_index,
  struct acl_ip_ext_entry acl_ip_ext_entry)
{
  int index, line;

  /* index for this acl */
  index = acl_list.names[acl_index].num;

  /* initial? */
  if (!acl_list.acl_ip_ext[index].num_lines) {

    if (!(acl_list.acl_ip_ext[index].line = (struct acl_ip_ext_entry*)
      malloc(sizeof (struct acl_ip_ext_entry)))) {
      fterr_warn("malloc(acl_list.acl_ip_ext[index].line)");
      return -1;
    }

    ++ acl_list.acl_ip_ext[index].num_lines;

  } else {
  
    if (!(acl_list.acl_ip_ext[index].line = (struct acl_ip_ext_entry*)
      realloc(acl_list.acl_ip_ext[index].line,
        ++ acl_list.acl_ip_ext[index].num_lines *
        sizeof (struct acl_ip_ext_entry)))) {
      fterr_warn("realloc(acl_list.acl_ip_ext[index].line)");
      return -1;
    }
  }

  line = acl_list.acl_ip_ext[index].num_lines - 1;

  bcopy(&acl_ip_ext_entry, &acl_list.acl_ip_ext[index].line[line], sizeof
    acl_ip_ext_entry);

  return 0;


} /* acl_add_line_ext */

/*
 * evaluate a standard access list with an IP address
 *
 * returns 0 for permit, 1 for deny
 */
int acl_eval_std(struct acl_list acl_list, int index, u_int32 ip)
{
  int x;
#ifdef DEBUG
  extern int debug;
  char fmt_buf[32], fmt_buf2[32], fmt_buf3[32], fmt_buf4[32];
#endif /* DEUBG */

  for (x = 0; x < acl_list.acl_ip_std[index].num_lines; ++x) {

#ifdef DEBUG
    if (debug > 5) {
      fmt_ipv4(fmt_buf, acl_list.acl_ip_std[index].line[x].src_addr,
        FMT_JUST_LEFT);
      fmt_ipv4(fmt_buf2, acl_list.acl_ip_std[index].line[x].src_mask,
        FMT_JUST_LEFT);
      fmt_ipv4(fmt_buf3, ip, FMT_JUST_LEFT);

      fterr_info("ip=%s src_addr=%s src_mask=%s", fmt_buf3, fmt_buf, fmt_buf2);
    }
#endif /* DEBUG */

    if ((ip & (~acl_list.acl_ip_std[index].line[x].src_mask)) ==
      (acl_list.acl_ip_std[index].line[x].src_addr &
        (~acl_list.acl_ip_std[index].line[x].src_mask))) {

      /* it matched */
#ifdef DEBUG
      ++ acl_list.acl_ip_std[index].line[x].matches;
#endif /* DEBUG */
      if (acl_list.acl_ip_std[index].line[x].flag & ACL_FLAG_PERMIT)
        return 0;
      else
        return 1;
    }
  }

  /* all others are denied */
  return 1;

} /* acl_eval_std */


/*
 * evaluate a extended access list
 *
 * returns 0 for permit, 1 for deny
 */
int acl_eval_ext(struct acl_list acl_list, int index,
  struct acl_ip_ext_entry entry)
{
  int x;

  /* for each line in the acl */
  for (x = 0; x < acl_list.acl_ip_ext[index].num_lines; ++x) {

    if (

    /* match IP protocol */
      ((E.line[x].flag & ACL_FLAG_IP_ALL) ||
        (entry.protocol == E.line[x].protocol)) &&

    /* match src IP */
      ((entry.src_addr & ~E.line[x].src_mask) == E.line[x].src_addr) &&

    /* match dst IP */
      ((entry.dst_addr & ~E.line[x].dst_mask) == E.line[x].dst_addr)

    ) {
    /* it matched */

#ifdef DEBUG
      ++ acl_list.acl_ip_std[index].line[x].matches;
#endif /* DEBUG */

      if (E.line[x].flag & ACL_FLAG_PERMIT)
        return 0;
      else
        return 1;
    }
  }

  /* all others are denied */
  return 1;

} /* acl_eval_ext */

