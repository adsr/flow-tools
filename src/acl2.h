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
 *      $Id: acl2.h,v 1.6 2002/02/10 03:50:00 maf Exp $
 */

#include <netinet/in.h>

#include <ftlib.h>


#define ACL_FLAG_PERMIT     0x1     /* else deny */
#define ACL_FLAG_SRC_PORT   0x2     /* do source port filtering */
#define ACL_FLAG_DST_PORT   0x4     /* do destination port filtering */
#define ACL_FLAG_ESTABLISHED  0x8   /* do "established" filtering */
#define ACL_FLAG_PRECEDENCE   0x10  /* do "precedence" filtering */
#define ACL_FLAG_TOS      0x20      /* do "tos" filtering */
#define ACL_FLAG_IP_ALL     0x40    /* all ip protocols */

#define ACL_OP_LT   1
#define ACL_OP_GT   1
#define ACL_OP_EQ   1
#define ACL_OP_NEQ    1
#define ACL_OP_RANGE  1

#define ACL_TYPE_STD  1
#define ACL_TYPE_EXT  2

struct acl_list {
  int num;                          /* number of entries */
  int num_std;                      /* number of standard acl entries */
  int num_ext;                      /* number of extended acl entries */
  struct acl_names *names;          /* name of acl (num of these) */
  struct acl_ip_std *acl_ip_std;    /* list of standard acl's (not || names) */
                                    /* num_std of these */
  struct acl_ip_ext *acl_ip_ext;    /* list of extended acl's (not || names) */
                                    /* num_ext of these */
};

struct acl_names {
  int num;       /* index into standard or extended list */
  char *name;    /* name of this acl */
  int type;      /* ACL_TYPE_* */
};

struct acl_ip_std {
  int           num_lines;        /* # of allocated entries */
  struct acl_ip_std_entry *line;
};

struct acl_ip_std_entry {
  uint32_t   src_addr;       /* source address */
  uint32_t   src_mask;       /* source address mask */
  uint64_t   matches;        /* # of matches */
  int     flag;             /* permit/deny */
};

struct acl_ip_ext {
  int           num_lines;  /* # of allocated entries */
  struct acl_ip_ext_entry *line;
};

struct acl_ip_ext_entry {

  u_int8    protocol;      /* IP protocol */
  u_int8    precedence;    /* IP precedence */
  u_int8    tos;           /* IP type of service */

  u_int8    type;
  u_int8    type_code;
  u_int8    message;

  u_int8    src_op;
  u_int8    dst_op;

  uint32_t   src_addr;    /* source address */
  uint32_t   src_mask;    /* source address mask */
  uint16_t   src_port;    /* source port */
  uint16_t   src_port2;   /* source port (end of range) */

  uint32_t   dst_addr;    /* destination address */
  uint32_t   dst_mask;    /* destinan address mask */
  uint16_t   dst_port;    /* destination port */
  uint16_t   dst_port2;   /* destination port (end of range) */

  uint64_t   matches;     /* # of matches */
  int     flag;          /* permit/deny, etc */
};

int acl_create(struct acl_list *acl_list, char *name, int type);
int acl_delete_list(struct acl_list acl_list);
void acl_dump(struct acl_list acl_list);
void acl_dump_std(struct acl_list acl_list, int x);
void acl_dump_ext(struct acl_list acl_list, int x);
int acl_find(struct acl_list acl_list, char *name);
int acl_add_line_std(struct acl_list acl_list, int acl_index,
  struct acl_ip_std_entry acl_ip_std_entry);
int acl_add_line_ext(struct acl_list acl_list, int acl_index,
  struct acl_ip_ext_entry acl_ip_ext_entry);
int acl_eval_std(struct acl_list acl_list, int index, uint32_t ip);
int acl_eval_ext(struct acl_list acl_list, int index,
  struct acl_ip_ext_entry entry);
