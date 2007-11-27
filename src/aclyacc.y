%{
#include <ftlib.h>
#include "acl2.h"
#include <stdio.h> /* XXX REMOVE */

/* XXX remove */
unsigned char fmt_buf[32];
unsigned char fmt_buf2[32];

extern struct acl_list acl_list;

int x;

%}

%union {
	char *c;
	uint32_t ip;
	int i;
	u_int u;
	struct acl_ip_std_entry std_entry;
	struct acl_ip_ext_entry ext_entry;
}

%token <c> HOST ANY
%token <ip> IPADDR
%token <c> NUM
%token <c> NAME
%token ACCESSLIST IP PERMIT DENY COMMENT
%token ICMP IGMP TCP UDP PRECEDENCE TOS LOG ICMPTYPE
%token LT GT EQ NEQ RANGE
%token ESTABLISHED EXTENDED STANDARD
%token NL

%type <ext_entry> ext_acl ext_acl_ip ext_acl_igmp ext_acl_udp ext_acl_tcp
%type <ext_entry> ext_acl_icmp prec_tos_log
%type <std_entry> std_acl
%type <i> action
%type <std_entry> ext_ip_mask

%%

config: acl nl
	| config acl nl
	| comment nl
	| config comment nl
	| nl
	;

comment: COMMENT | COMMENT comment;

nl: NL | NL nl;

acl: ACCESSLIST NUM action std_acl {
		/* XXX add code to check NUM is in range 0..99 */
		$4.flag |= $3;
		x = acl_create(&acl_list, $2, ACL_TYPE_STD);
		acl_add_line_std(acl_list, x, $4);
	}
	| ACCESSLIST NUM action ext_acl {
		/* XXX add code to check NUM is in range 100-199 */
		$4.flag |= $3;
		x = acl_create(&acl_list, $2, ACL_TYPE_EXT);
		acl_add_line_ext(acl_list, x, $4);
	}
	| IP ACCESSLIST STANDARD NAME action std_acl {
		$6.flag |= $5;
		x = acl_create(&acl_list, $4, ACL_TYPE_STD);
		acl_add_line_std(acl_list, x, $6);
	}
	| IP ACCESSLIST EXTENDED NAME action ext_acl {
		$6.flag |= $5;
		x = acl_create(&acl_list, $4, ACL_TYPE_EXT);
		acl_add_line_ext(acl_list, x, $6);
	}
	;


std_acl :  ANY 	 		{
		$$.src_addr = 0x0;
		$$.src_mask = 0xFFFFFFFF;
		$$.matches = 0;
		$$.flag = 0;
	}
	|	HOST IPADDR		{ 
		$$.src_addr = $2;
		$$.src_mask = 0x0;
		$$.matches = 0;
		$$.flag = 0;
	}
	|	IPADDR IPADDR	{ 
		$$.src_addr = $1;
		$$.src_mask = $2;
		$$.matches = 0;
		$$.flag = 0;
	}
	|	IPADDR 			{
		$$.src_addr = $1;
		$$.src_mask = 0x0;
		$$.matches = 0;
		$$.flag = 0;
	}
	;

action: PERMIT {
		$$ = ACL_FLAG_PERMIT;
	}
	| DENY {
		$$ = 0;
	}
	;

ext_acl:	ext_acl_ip
	|	ext_acl_icmp
	|	ext_acl_igmp
	|	ext_acl_tcp
	|	ext_acl_udp
	;

	
ext_acl_ip: 	IP ext_ip_mask ext_ip_mask {
		$$.protocol = 0;
		$$.precedence = 0;
		$$.tos = 0;
		$$.type = 0;
		$$.type_code = 0;
		$$.message = 0;
		$$.src_op = 0;
		$$.dst_op = 0;
		$$.src_addr = $2.src_addr;
		$$.src_mask = $2.src_mask;
		$$.src_port = 0;
		$$.src_port2 = 0;
		$$.dst_addr = $3.src_addr;
		$$.dst_mask = $3.src_mask;
		$$.dst_port = 0;
		$$.dst_port2 = 0;
		$$.matches = 0;
		$$.flag = ACL_FLAG_IP_ALL;
	}
	|	IP ext_ip_mask ext_ip_mask prec_tos_log {
		$$.protocol = 0;
		$$.precedence = $4.precedence;
		$$.tos = $4.tos;
		$$.type = 0;
		$$.type_code = 0;
		$$.message = 0;
		$$.src_op = 0;
		$$.dst_op = 0;
		$$.src_addr = $2.src_addr;
		$$.src_mask = $2.src_mask;
		$$.src_port = 0;
		$$.src_port2 = 0;
		$$.dst_addr = $3.src_addr;
		$$.dst_mask = $3.src_mask;
		$$.dst_port = 0;
		$$.dst_port2 = 0;
		$$.matches = 0;
		$$.flag = ACL_FLAG_IP_ALL | $3.flag;
	}
	;

ext_acl_icmp:	ICMP ext_ip_mask ext_ip_mask {
		$$.protocol = IPPROTO_ICMP;
		$$.precedence = 0;
		$$.tos = 0;
		$$.type = 0;
		$$.type_code = 0;
		$$.message = 0;
		$$.src_op = 0;
		$$.dst_op = 0;
		$$.src_addr = $2.src_addr;
		$$.src_mask = $2.src_mask;
		$$.src_port = 0;
		$$.src_port2 = 0;
		$$.dst_addr = $3.src_addr;
		$$.dst_mask = $3.src_mask;
		$$.dst_port = 0;
		$$.dst_port2 = 0;
		$$.matches = 0;
		$$.flag = 0;
	}
	|	ICMP ext_ip_mask ext_ip_mask icmp_val {}
	|	ICMP ext_ip_mask ext_ip_mask prec_tos_log {}
	|	ICMP ext_ip_mask ext_ip_mask icmp_val prec_tos_log {}
	;

ext_acl_igmp:	IGMP ext_ip_mask ext_ip_mask {
		$$.protocol = IPPROTO_IGMP;
		$$.precedence = 0;
		$$.tos = 0;
		$$.type = 0;
		$$.type_code = 0;
		$$.message = 0;
		$$.src_op = 0;
		$$.dst_op = 0;
		$$.src_addr = $2.src_addr;
		$$.src_mask = $2.src_mask;
		$$.src_port = 0;
		$$.src_port2 = 0;
		$$.dst_addr = $3.src_addr;
		$$.dst_mask = $3.src_mask;
		$$.dst_port = 0;
		$$.dst_port2 = 0;
		$$.matches = 0;
		$$.flag = 0;
	}
	|	IGMP ext_ip_mask ext_ip_mask igmp_val {}
	|	IGMP ext_ip_mask ext_ip_mask prec_tos_log {}
	|	IGMP ext_ip_mask ext_ip_mask igmp_val prec_tos_log {}
	;

ext_acl_tcp:	TCP ext_ip_mask ext_ip_mask {
		$$.protocol = IPPROTO_TCP;
		$$.precedence = 0;
		$$.tos = 0;
		$$.type = 0;
		$$.type_code = 0;
		$$.message = 0;
		$$.src_op = 0;
		$$.dst_op = 0;
		$$.src_addr = $2.src_addr;
		$$.src_mask = $2.src_mask;
		$$.src_port = 0;
		$$.src_port2 = 0;
		$$.dst_addr = $3.src_addr;
		$$.dst_mask = $3.src_mask;
		$$.dst_port = 0;
		$$.dst_port2 = 0;
		$$.matches = 0;
		$$.flag = 0;
	}
	|	TCP ext_ip_mask ext_ip_mask tcp_port_tail {}
	|	TCP ext_ip_mask tcp_port_op ext_ip_mask {}
	|	TCP ext_ip_mask tcp_port_op ext_ip_mask tcp_port_tail {}
	;

ext_acl_udp:	UDP ext_ip_mask ext_ip_mask {
		$$.protocol = IPPROTO_UDP;
		$$.precedence = 0;
		$$.tos = 0;
		$$.type = 0;
		$$.type_code = 0;
		$$.message = 0;
		$$.src_op = 0;
		$$.dst_op = 0;
		$$.src_addr = $2.src_addr;
		$$.src_mask = $2.src_mask;
		$$.src_port = 0;
		$$.src_port2 = 0;
		$$.dst_addr = $3.src_addr;
		$$.dst_mask = $3.src_mask;
		$$.dst_port = 0;
		$$.dst_port2 = 0;
		$$.matches = 0;
		$$.flag = 0;
	}
	|	UDP ext_ip_mask ext_ip_mask udp_port_tail {}
	|	UDP ext_ip_mask tcp_port_op ext_ip_mask {}
	|	UDP ext_ip_mask tcp_port_op ext_ip_mask udp_port_tail {}
	;

tcp_port_tail: tcp_port_op
	| ESTABLISHED
	| tcp_port_op ESTABLISHED
	| prec_tos_log
	| tcp_port_op prec_tos_log
	| ESTABLISHED prec_tos_log
	| tcp_port_op ESTABLISHED prec_tos_log
	;

udp_port_tail: tcp_port_op
	| prec_tos_log
	| tcp_port_op prec_tos_log
	;

s_operator:	LT
	| GT
	| EQ
	| NEQ
	;

tcp_port_op:	s_operator tcp_val
	| RANGE tcp_val tcp_val
	;

tcp_val: NUM
	| NAME
	;
	

prec_tos_log: precedence {}
	| tos {}
	| LOG {}
	| precedence tos {}
	| precedence LOG {}
	| precedence tos LOG {}
	| tos LOG {}
	;

precedence:	PRECEDENCE precedence_val {}
	;

precedence_val:     NUM
    | NAME
    ;

tos:	TOS tos_val
	;

tos_val:	NUM
	|	NAME
	;

ext_ip_mask:	IPADDR IPADDR {
		$$.src_addr = $1;
		$$.src_mask = $2;
		$$.matches = 0;
		$$.flag = 0;
	}
	| ANY {
		$$.src_addr = 0x0;
		$$.src_mask = 0xFFFFFFFF;
		$$.matches = 0;
		$$.flag = 0;
	}
	| HOST IPADDR {
		$$.src_addr = $2;
		$$.src_mask = 0x0;
		$$.matches = 0;
		$$.flag = 0;
	}
	;


icmp_val: NUM
	| NAME
	;

igmp_val: NUM
	| NAME
	;


%%
