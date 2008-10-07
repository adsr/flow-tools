%{
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <err.h>

#define ELOG(fmt, args...) warnx(fmt, ##args)
#define WLOG(fmt, args...) warnx(fmt, ##args)

#include "ippffunc.h"

enum action 
	{ ALLOW = 1, DENY = 0 };
enum ltype 
	{ LTYPE_PROTO, LTYPE_IPNET, LTYPE_PORT };

struct proto {
	enum action	act;
	int		proto;
};
struct ipnet {
	enum action	act;
	in_addr_t	addr;
	in_addr_t	mask;
};
struct port {
	enum action 	act;
	int 		port;
};

struct node {
	int 	n;
	union {
		enum action	act;
		struct proto 	proto;
		struct ipnet 	ipnet;
		struct port 	port;
	} 	ar[0x10];
	STAILQ_ENTRY(node) ent;
};
STAILQ_HEAD(list, node);


static
int
list_add(struct list *list, enum ltype ltype, ...)
{
	struct node *p;
	va_list ap;

	p = STAILQ_LAST(list, node, ent);
	if (!p || p->n == sizeof p->ar / sizeof p->ar[0]) {
		p = malloc(sizeof *p);
		if (!p)
			return 1;
		p->n = 0;
		STAILQ_INSERT_TAIL(list, p, ent);
	}
	va_start(ap, ltype);
	if (ltype == LTYPE_PROTO)
		p->ar[p->n].proto = *va_arg(ap, typeof(p->ar[0].proto) *);
	else if (ltype == LTYPE_IPNET)
		p->ar[p->n].ipnet = *va_arg(ap, typeof(p->ar[0].ipnet) *);
	else /* if (ltype == LTYPE_PORT) */
		p->ar[p->n].port = *va_arg(ap, typeof(p->ar[0].port) *);
	va_end(ap);
	p->n++;
	return 0;
}

static
void
list_clear(struct list *list)
{
	struct node *p, *q;

	for (p = STAILQ_FIRST(list); p; p = q) {
	     q = STAILQ_NEXT(p, ent);
	     free(p);
	}
	STAILQ_INIT(list);
}


enum exprtype {
	EXPR_NONE,
	EXPR_PROTO,
	EXPR_IP,
	EXPR_SRCIP,
	EXPR_DSTIP,
	EXPR_PORT,
	EXPR_SRCPORT,
	EXPR_DSTPORT,
	EXPR_NOT,
	EXPR_OR,
	EXPR_AND
};

struct expr_proto {
	enum exprtype	type;
	struct list	list[1];
};
struct expr_ip {
	enum exprtype	type;
	struct list	list[1];
};
struct expr_srcip {
	enum exprtype	type;
	struct list	list[1];
};
struct expr_dstip {
	enum exprtype	type;
	struct list	list[1];
};
struct expr_port {
	enum exprtype	type;
	struct list	list[1];
};
struct expr_srcport {
	enum exprtype	type;
	struct list	list[1];
};
struct expr_dstport {
	enum exprtype	type;
	struct list	list[1];
};
struct expr_not {
	enum exprtype	type;
	union expr *	op;
};
struct expr_or {
	enum exprtype	type;
	union expr *	op[2];
};
struct expr_and {
	enum exprtype	type;
	union expr *	op[2];
};

union expr {
	enum exprtype		type;
	struct expr_proto	expr_proto;
	struct expr_ip		expr_ip;
	struct expr_srcip	expr_srcip;
	struct expr_dstip	expr_dstip;
	struct expr_port	expr_port;
	struct expr_srcport	expr_srcport;
	struct expr_dstport	expr_dstport;
	struct expr_not		expr_not;
	struct expr_or		expr_or;
	struct expr_and		expr_and;
};

static
void
expr_clear(union expr *expr)
{
	if (expr->type == EXPR_PROTO)
		list_clear(expr->expr_proto.list);
	else if (expr->type == EXPR_IP)
		list_clear(expr->expr_ip.list);
	else if (expr->type == EXPR_SRCIP)
		list_clear(expr->expr_srcip.list);
	else if (expr->type == EXPR_DSTIP)
		list_clear(expr->expr_dstip.list);
	else if (expr->type == EXPR_PORT)
		list_clear(expr->expr_port.list);
	else if (expr->type == EXPR_SRCPORT)
		list_clear(expr->expr_srcport.list);
	else if (expr->type == EXPR_DSTPORT)
		list_clear(expr->expr_dstport.list);
	else if (expr->type == EXPR_NOT) {
		expr_clear(expr->expr_not.op);
		free(expr->expr_not.op);
	} else if (expr->type == EXPR_OR) {
		expr_clear(expr->expr_or.op[0]);
		free(expr->expr_or.op[0]);
		expr_clear(expr->expr_or.op[1]);
		free(expr->expr_or.op[1]);
	} else if (expr->type == EXPR_AND) {
		expr_clear(expr->expr_and.op[0]);
		free(expr->expr_and.op[0]);
		expr_clear(expr->expr_and.op[1]);
		free(expr->expr_and.op[1]);
	} else if (expr->type == EXPR_NONE)
		WLOG("expr_clear(): EXPR_NONE: ???");
	else
		WLOG("expr_clear(): %d: unknown enum exprtype", expr->type);
	expr->type = EXPR_NONE;
}
static
void
expr_destroy(union expr *expr)
{
	if (expr) {
		expr_clear(expr);
		free(expr);
	}
}

static
int
expr_calc(union expr *expr, int proto, in_addr_t srcip, int srcport, in_addr_t dstip, int dstport)
{
	int rc;
	struct node *p;
	int i;

	rc = DENY;
	if (!expr)
		rc = ALLOW;
	else if (expr->type == EXPR_PROTO) {
		STAILQ_FOREACH(p, expr->expr_proto.list, ent)
			for (i = 0; i < p->n; i++)
				if (!p->ar[i].proto.proto || p->ar[i].proto.proto == proto) {
					rc = p->ar[i].act;
					goto L1;
				}
	} else if (expr->type == EXPR_IP) {
		STAILQ_FOREACH(p, expr->expr_ip.list, ent)
			for (i = 0; i < p->n; i++)
				if (p->ar[i].ipnet.addr == (srcip & p->ar[i].ipnet.mask) || 
						p->ar[i].ipnet.addr == (dstip & p->ar[i].ipnet.mask)) {
					rc = p->ar[i].act;
					goto L1;
				}
	} else if (expr->type == EXPR_SRCIP) {
		STAILQ_FOREACH(p, expr->expr_srcip.list, ent)
			for (i = 0; i < p->n; i++)
				if (p->ar[i].ipnet.addr == (srcip & p->ar[i].ipnet.mask)) {
					rc = p->ar[i].act;
					goto L1;
				}
	} else if (expr->type == EXPR_DSTIP) {
		STAILQ_FOREACH(p, expr->expr_dstip.list, ent)
			for (i = 0; i < p->n; i++)
				if (p->ar[i].ipnet.addr == (dstip & p->ar[i].ipnet.mask)) {
					rc = p->ar[i].act;
					goto L1;
				}
	} else if (expr->type == EXPR_PORT) {
		STAILQ_FOREACH(p, expr->expr_port.list, ent)
			for (i = 0; i < p->n; i++)
				if (p->ar[i].port.port == 0 
					|| p->ar[i].port.port == srcport 
						|| p->ar[i].port.port == dstport) {
					rc = p->ar[i].act;
					goto L1;
				}
	} else if (expr->type == EXPR_SRCPORT) {
		STAILQ_FOREACH(p, expr->expr_srcport.list, ent)
			for (i = 0; i < p->n; i++)
				if (p->ar[i].port.port == 0 || p->ar[i].port.port == srcport) {
					rc = p->ar[i].act;
					goto L1;
				}
	} else if (expr->type == EXPR_DSTPORT) {
		STAILQ_FOREACH(p, expr->expr_dstport.list, ent)
			for (i = 0; i < p->n; i++)
				if (p->ar[i].port.port == 0 || p->ar[i].port.port == dstport) {
					rc = p->ar[i].act;
					goto L1;
				}
	} else if (expr->type == EXPR_NOT)
		rc = !expr_calc(expr->expr_not.op, proto, srcip, srcport, dstip, dstport);
	else if (expr->type == EXPR_OR)
		rc = expr_calc(expr->expr_or.op[0], proto, srcip, srcport, dstip, dstport) ||
			expr_calc(expr->expr_or.op[1], proto, srcip, srcport, dstip, dstport);
	else if (expr->type == EXPR_AND)
		rc = expr_calc(expr->expr_and.op[0], proto, srcip, srcport, dstip, dstport) &&
			expr_calc(expr->expr_and.op[1], proto, srcip, srcport, dstip, dstport);
L1:	
	return rc;
}
%}

%union {
	union expr *		expr_p;
	struct list 		list;
	struct proto		proto;
	struct ipnet		ipnet;
	struct port		port;
	in_addr_t 		ipaddr;
	int 			d;
}

%type <expr_p>		cond
%type <expr_p>		expr
%type <list>		protos
%type <list>		listprotos
%type <list> 		ipnets
%type <list> 		listipnets
%type <list> 		ports
%type <list> 		listports
%type <proto>		proto
%type <ipnet> 		ipnet
%type <port> 		port
%type <ipaddr> 		ipaddr
%type <d> 		netbits
%type <d> 		netmask
%type <d> 		byte
%type <d> 		number

%token <d> 		DIGIT
%token 			SP


%destructor { expr_destroy($$); } expr cond
%destructor { list_clear(&$$); } listports ports listipnets ipnets listprotos protos

%pure-parser
%locations
%parse-param { FILE *fp }
%parse-param { union expr **expr }
%lex-param { FILE *fp }
%error-verbose
%initial-action
{
}

%{
static int yyparse(FILE *fp, union expr **expr);
static int yyerror(YYLTYPE *llocp, FILE *fp, union expr **expr, char const *msg);
static int yylex(YYSTYPE *lvalp, YYLTYPE *llocp, FILE *fp);
%}

%%

start		: sp
			{
				*expr = 0;
			}
		| sp cond sp
			{
				*expr = $2;
				$2 = 0;
			}
		;

cond		: expr
			{
				$$ = $1;
				$1 = 0;
			}
		| cond spaces expr
			{
				if (!($$ = malloc(sizeof *$$))) {
					ELOG("(l%d,c%d): unable create expr_and",
						@$.first_line, @$.first_column);
					YYABORT;
				}
				$$->type = EXPR_AND;
				$$->expr_and.op[0] = $1;
				$1 = 0;
				$$->expr_and.op[1] = $3;
				$3 = 0;
					
			}
		| cond sp '|' '|' sp expr
			{
				if (!($$ = malloc(sizeof *$$))) {
					ELOG("(l%d,c%d): unable create expr_and",
						@$.first_line, @$.first_column);
					YYABORT;
				}
				$$->type = EXPR_OR;
				$$->expr_or.op[0] = $1;
				$1 = 0;
				$$->expr_or.op[1] = $6;
				$6 = 0;
					
			}
		;


expr		: 'p' 'r' 'o' 't' 'o' spaces protos
			{
				if (!($$ = malloc(sizeof *$$))) {
					ELOG("(l%d,c%d): unable create expr_proto",
							@$.first_line, @$.first_column);
					YYABORT;
				}
				$$->type = EXPR_PROTO;
				STAILQ_INIT($$->expr_proto.list);
				STAILQ_CONCAT($$->expr_proto.list, &$7);
				STAILQ_INIT(&$7);
			}
		| 'i' 'p' spaces ipnets
			{
				if (!($$ = malloc(sizeof *$$))) {
					ELOG("(l%d,c%d): unable create expr_ip",
							@$.first_line, @$.first_column);
					YYABORT;
				}
				$$->type = EXPR_IP;
				STAILQ_INIT($$->expr_ip.list);
				STAILQ_CONCAT($$->expr_ip.list, &$4);
				STAILQ_INIT(&$4);
			}
		| 's' 'r' 'c' '-' 'i' 'p' spaces ipnets
			{
				if (!($$ = malloc(sizeof *$$))) {
					ELOG("(l%d,c%d): unable create expr_srcip",
							@$.first_line, @$.first_column);
					YYABORT;
				}
				$$->type = EXPR_SRCIP;
				STAILQ_INIT($$->expr_srcip.list);
				STAILQ_CONCAT($$->expr_srcip.list, &$8);
				STAILQ_INIT(&$8);
			}
		| 'd' 's' 't' '-' 'i' 'p' spaces ipnets
			{
				if (!($$ = malloc(sizeof *$$))) {
					ELOG("(l%d,c%d): unable create expr_dstip",
							@$.first_line, @$.first_column);
					YYABORT;
				}
				$$->type = EXPR_DSTIP;
				STAILQ_INIT($$->expr_dstip.list);
				STAILQ_CONCAT($$->expr_dstip.list, &$8);
				STAILQ_INIT(&$8);
			}
		| 'p' 'o' 'r' 't' spaces ports
			{
				if (!($$ = malloc(sizeof *$$))) {
					ELOG("(l%d,c%d): unable create expr_srcport",
							@$.first_line, @$.first_column);
					YYABORT;
				}
				$$->type = EXPR_PORT;
				STAILQ_INIT($$->expr_srcport.list);
				STAILQ_CONCAT($$->expr_srcport.list, &$6);
				STAILQ_INIT(&$6);
			}
		| 's' 'r' 'c' '-' 'p' 'o' 'r' 't' spaces ports
			{
				if (!($$ = malloc(sizeof *$$))) {
					ELOG("(l%d,c%d): unable create expr_srcport",
							@$.first_line, @$.first_column);
					YYABORT;
				}
				$$->type = EXPR_SRCPORT;
				STAILQ_INIT($$->expr_srcport.list);
				STAILQ_CONCAT($$->expr_srcport.list, &$10);
				STAILQ_INIT(&$10);
			}
		| 'd' 's' 't' '-' 'p' 'o' 'r' 't' spaces ports
			{
				if (!($$ = malloc(sizeof *$$))) {
					ELOG("(l%d,c%d): unable create expr_dstport",
							@$.first_line, @$.first_column);
					YYABORT;
				}
				$$->type = EXPR_DSTPORT;
				STAILQ_INIT($$->expr_dstport.list);
				STAILQ_CONCAT($$->expr_dstport.list, &$10);
				STAILQ_INIT(&$10);
			}
		| '!' sp expr
			{
				if ($3->type == EXPR_NOT) {
					$$ = $3->expr_not.op;
					free($3);
				} else {
					if (!($$ = malloc(sizeof *$$))) {
						ELOG("(l%d,c%d): unable create expr_not",
							@$.first_line, @$.first_column);
						YYABORT;
					}
					$$->type = EXPR_NOT;
					$$->expr_not.op = $3;
					$3 = 0;
				}
			}
		| '(' sp cond sp ')'
			{
				$$ = $3;
				$3 = 0;
			}
		;

protos		: proto
			{
				STAILQ_INIT(&$$);
				if (list_add(&$$, LTYPE_PORT, &$1)) {
					ELOG("(l%d,c%d): %d: unable insert proto in list",
						@$.first_line, @$.first_column, $1.proto);
					YYABORT;
				}
			}
		| '{' sp listprotos sp '}'
			{
				STAILQ_INIT(&$$);
				STAILQ_CONCAT(&$$, &$3);
				STAILQ_INIT(&$3);
			}
		;

listprotos	: proto
			{
				STAILQ_INIT(&$$);
				if (list_add(&$$, LTYPE_PORT, &$1)) {
					ELOG("(l%d,c%d): %d: unable insert proto in list",
						@$.first_line, @$.first_column, $1.proto);
					YYABORT;
				}
			}
		| listprotos sp ',' sp proto
			{
				STAILQ_INIT(&$$);
				if (list_add(&$1, LTYPE_PORT, &$5)) {
					ELOG("(l%d,c%d): %d: unable insert proto in list",
						@$.first_line, @$.first_column, $5.proto);
					YYABORT;
				}
				STAILQ_CONCAT(&$$, &$1);
				STAILQ_INIT(&$1);
			}
		;

proto		: 'i' 'p'
			{
				struct protoent *p;
				if (!(p = getprotobyname("ip"))) {
					ELOG("(l%d,c%d): getprotobyname(\"ip\"): not found\n",
						@$.first_line, @$.first_column);
					YYABORT;
				}
				$$.proto = p->p_proto;
				$$.act = ALLOW;
			}
		| 'i' 'c' 'm' 'p'
			{
				struct protoent *p;
				if (!(p = getprotobyname("icmp"))) {
					ELOG("(l%d,c%d): getprotobyname(\"icmp\"): not found\n",
						@$.first_line, @$.first_column);
					YYABORT;
				}
				$$.proto = p->p_proto;
				$$.act = ALLOW;
			}
		| 't' 'c' 'p'
			{
				struct protoent *p;
				if (!(p = getprotobyname("tcp"))) {
					ELOG("(l%d,c%d): getprotobyname(\"tcp\"): not found\n",
						@$.first_line, @$.first_column);
					YYABORT;
				}
				$$.proto = p->p_proto;
				$$.act = ALLOW;
			}
		| 'u' 'd' 'p'
			{
				struct protoent *p;
				if (!(p = getprotobyname("udp"))) {
					ELOG("(l%d,c%d): getprotobyname(\"udp\"): not found\n",
						@$.first_line, @$.first_column);
					YYABORT;
				}
				$$.proto = p->p_proto;
				$$.act = ALLOW;
			}
		| 'i' 'p' 'e' 'n' 'c' 'a' 'p'
			{
				struct protoent *p;
				if (!(p = getprotobyname("ipencap"))) {
					ELOG("(l%d,c%d): getprotobyname(\"ipencap\"): not found\n",
						@$.first_line, @$.first_column);
					YYABORT;
				}
				$$.proto = p->p_proto;
				$$.act = ALLOW;
			}
		| 'g' 'r' 'e'
			{
				struct protoent *p;
				if (!(p = getprotobyname("gre"))) {
					ELOG("(l%d,c%d): getprotobyname(\"gre\"): not found\n",
						@$.first_line, @$.first_column);
					YYABORT;
				}
				$$.proto = p->p_proto;
				$$.act = ALLOW;
			}
		| '*'
			{
				struct protoent *p;
				if (!(p = getprotobyname("ip"))) {
					ELOG("(l%d,c%d): getprotobyname(\"ip\"): not found\n",
						@$.first_line, @$.first_column);
					YYABORT;
				}
				$$.proto = p->p_proto;
				$$.act = ALLOW;
			}
		| number
			{
				$$.proto = $1;
				$$.act = ALLOW;
			}
		| '!' proto
			{
				$$.proto = $2.proto;
				$$.act = !$2.act;
			}
		;


ipnets		: ipnet
			{
				STAILQ_INIT(&$$);
				if (list_add(&$$, LTYPE_IPNET, &$1)) {
					in_addr_t addr = htonl($1.addr);
					in_addr_t mask = htonl($1.mask);
					char addrbuf[0x10], maskbuf[0x10];

					ELOG("(l%d,c%d): %s/%s: unable insert ipnetwork in list",
						@$.first_line, @$.first_column, 
							inet_ntop(AF_INET, &addr, addrbuf, sizeof addrbuf),
							inet_ntop(AF_INET, &mask, maskbuf, sizeof maskbuf));
					YYABORT;
				}
			}
		| '{' sp listipnets sp '}'
			{
				STAILQ_INIT(&$$);
				STAILQ_CONCAT(&$$, &$3);
				STAILQ_INIT(&$3);
			}
		;

listipnets	: ipnet
			{
				STAILQ_INIT(&$$);
				if (list_add(&$$, LTYPE_IPNET, &$1)) {
					in_addr_t addr = htonl($1.addr);
					in_addr_t mask = htonl($1.mask);
					char addrbuf[0x10], maskbuf[0x10];

					ELOG("(l%d,c%d): %s/%s: unable insert ipnetwork in list",
						@$.first_line, @$.first_column, 
							inet_ntop(AF_INET, &addr, addrbuf, sizeof addrbuf),
							inet_ntop(AF_INET, &mask, maskbuf, sizeof maskbuf));
					YYABORT;
				}
			}
		| listipnets sp ',' sp ipnet
			{
				STAILQ_INIT(&$$);
				if (list_add(&$1, LTYPE_IPNET, &$5)) {
					in_addr_t addr = htonl($5.addr);
					in_addr_t mask = htonl($5.mask);
					char addrbuf[0x10], maskbuf[0x10];

					ELOG("(l%d,c%d): %s/%s: unable insert ipnetwork in list",
						@$.first_line, @$.first_column, 
							inet_ntop(AF_INET, &addr, addrbuf, sizeof addrbuf),
							inet_ntop(AF_INET, &mask, maskbuf, sizeof maskbuf));
					YYABORT;
				}
				STAILQ_CONCAT(&$$, &$1);
				STAILQ_INIT(&$1);
			}
		;

ipnet		: ipaddr
			{
				$$.addr = $1;
				$$.mask = -1;
				$$.act = ALLOW;
			}
		| ipaddr '/' netbits
			{
				$$.addr = $1;
				$$.mask = $3 ? -1<<(32-$3) : 0;
				$$.act = ALLOW;
			}
		| ipaddr '/' netmask
			{
				$$.addr = $1;
				$$.mask = $3;
				$$.act = ALLOW;
			}
		| '*'
			{
				$$.addr = 0;
				$$.mask = 0;
				$$.act = ALLOW;
			}
		| '!' ipnet
			{
				$$.addr = $2.addr;
				$$.mask = $2.mask;
				$$.act = !$2.act;
			}
		;


ports		: port
			{
				STAILQ_INIT(&$$);
				if (list_add(&$$, LTYPE_PORT, &$1)) {
					ELOG("(l%d,c%d): %d: unable insert port in list",
						@$.first_line, @$.first_column, $1.port);
					YYABORT;
				}
			}
		| '{' sp listports sp '}'
			{
				STAILQ_INIT(&$$);
				STAILQ_CONCAT(&$$, &$3);
				STAILQ_INIT(&$3);
			}
		;

listports	: port
			{
				STAILQ_INIT(&$$);
				if (list_add(&$$, LTYPE_PORT, &$1)) {
					ELOG("(l%d,c%d): %d: unable insert port in list",
						@$.first_line, @$.first_column, $1.port);
					YYABORT;
				}
			}
		| listports sp ',' sp port
			{
				STAILQ_INIT(&$$);
				if (list_add(&$1, LTYPE_PORT, &$5)) {
					ELOG("(l%d,c%d): %d: unable insert port in list",
						@$.first_line, @$.first_column, $5.port);
					YYABORT;
				}
				STAILQ_CONCAT(&$$, &$1);
				STAILQ_INIT(&$1);
			}
		;

port		: number
			{
				if ($1 > 65535) {
					ELOG("(l%d,c%d): %d: wrong port number",
						@$.first_line, @$.first_column, $1);
					YYABORT;
				}
				$$.port = $1;
				$$.act = ALLOW;
			}
		| '*'
			{
				$$.port = 0;
				$$.act = ALLOW;
			}
		| '!' port
			{
				$$.port = $2.port;
				$$.act = !$2.act;
			}
		;

netbits		: number
			{
				$$ = $1;
				if ($1 > 32) {
					ELOG("(l%d,c%d): %d: wrong bitmask",
						@$.first_line, @$.first_column, $1);
					YYABORT;
				}
			}
		;

netmask		: byte '.' byte '.' byte '.' byte
			{
				$$ = (($7&0377)<<24) | (($5&0377)<<16) | (($3&0377)<<8) | ($1&0377);
				$$ = ntohl($$);
			}
		;

ipaddr		: byte '.' byte '.' byte '.' byte
			{
				$$ = (($7&0377)<<24) | (($5&0377)<<16) | (($3&0377)<<8) | ($1&0377);
				$$ = ntohl($$);
			}
		;

byte		: number
			{
				$$ = $1;
				if ($1 > 255) {
					ELOG("(l%d,c%d): %d: expect byte",
						@$.first_line, @$.first_column, $1);
					YYABORT;
				}
			}
		;

number		: DIGIT 
			{ 
				$$ = $1; 
			}
		| number DIGIT 
			{
				$$ = $1 * 10 + $2; 
				if ($$ < $1) {
					ELOG("(l%d,c%d): big number", @$.first_line, @$.first_column);
					YYABORT;
				}
			}
		;

sp		:
		| spaces
		;
spaces		: SP
		| spaces SP
		;

%%

int
yyerror(YYLTYPE *llocp, FILE *fp, union expr **expr, char const *msg)
{
	fprintf(stderr, "ERROR(%d:%d-%d:%d): %s\n", 
		llocp->first_line, llocp->first_column, 
		llocp->last_line,  llocp->last_column, 
			msg);
	return 0;
}

int
yylex(YYSTYPE *lvalp, YYLTYPE *llocp, FILE *fp)
{
	int c;

	if ((c = fgetc(fp)) >= 0) {
		if (c == '\n') {
			llocp->first_line = ++llocp->last_line;
			llocp->first_column = llocp->last_column = 0;
		} else
			llocp->first_column = ++llocp->last_column;

		if (isspace(c)) {
			c = SP;
		} else if (isdigit(c)) {
			lvalp->d = c - '0';
			c = DIGIT;
		}
	} 
	return c;
}

struct ippf *
ippf_create(FILE *fp)
{
	union expr *expr;

        if (yyparse(fp, &expr)) {
                expr_destroy(expr);
                expr = 0;
        }
        return (struct ippf *)expr;
}
void
ippf_destroy(struct ippf *filt)
{
	if (filt)
        	expr_destroy((union expr *)filt);
}

static
int
str_readfn(void *cookie, char *buf, int n)
{
        int r;

        r = strlcpy(buf, *(char **)cookie, n);
        *(char **)cookie += r;
        return r;
}

struct ippf *
ippf_create_str(char const *s)
{
	struct ippf *filt;
	FILE *fp;

	filt = 0;
	if ((fp = fropen(&s, str_readfn)) != 0) {
		filt = ippf_create(fp);
		fclose(fp);
	}
	return filt;
}

int
ippf_calc(struct ippf *filt, int proto, in_addr_t srcip, int srcport, in_addr_t dstip, int dstport)
{
	return expr_calc((union expr *)filt, proto, srcip, srcport, dstip, dstport);
}
