#ifndef lint
static char const 
yyrcsid[] = "$FreeBSD: src/usr.bin/yacc/skeleton.c,v 1.28.2.1 2001/07/19 05:46:39 peter Exp $";
#endif
#include <stdlib.h>
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYLEX yylex()
#define YYEMPTY -1
#define yyclearin (yychar=(YYEMPTY))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING() (yyerrflag!=0)
#if defined(__cplusplus) || __STDC__
static int yygrowstack(void);
#else
static int yygrowstack();
#endif
#define YYPREFIX "yy"
#line 2 "aclyacc.y"

#include "ftconfig.h"
#include <ftlib.h>

#include "acl2.h"
#include <stdio.h> /* XXX REMOVE */

/* XXX remove */
unsigned char fmt_buf[32];
unsigned char fmt_buf2[32];

extern struct acl_list acl_list;

int x;

#line 16 "aclyacc.y"
typedef union {
	char *c;
	u_long long ip;
	int i;
	u_int u;
	struct acl_ip_std_entry std_entry;
	struct acl_ip_ext_entry ext_entry;
} YYSTYPE;
#line 43 "y.tab.c"
#define YYERRCODE 256
#define HOST 257
#define ANY 258
#define IPADDR 259
#define NUM 260
#define NAME 261
#define ACCESSLIST 262
#define IP 263
#define PERMIT 264
#define DENY 265
#define COMMENT 266
#define ICMP 267
#define IGMP 268
#define TCP 269
#define UDP 270
#define PRECEDENCE 271
#define TOS 272
#define LOG 273
#define ICMPTYPE 274
#define LT 275
#define GT 276
#define EQ 277
#define NEQ 278
#define RANGE 279
#define ESTABLISHED 280
#define EXTENDED 281
#define STANDARD 282
#define NL 283
const short yylhs[] = {                                        -1,
    0,    0,    0,    0,    0,   13,   13,   12,   12,   11,
   11,   11,   11,    8,    8,    8,    8,    9,    9,    1,
    1,    1,    1,    1,    2,    2,    6,    6,    6,    6,
    3,    3,    3,    3,    5,    5,    5,    5,    4,    4,
    4,    4,   16,   16,   16,   16,   16,   16,   16,   18,
   18,   18,   19,   19,   19,   19,   17,   17,   20,   20,
    7,    7,    7,    7,    7,    7,    7,   21,   23,   23,
   22,   24,   24,   10,   10,   10,   14,   14,   15,   15,
};
const short yylen[] = {                                         2,
    2,    3,    2,    3,    1,    1,    2,    1,    2,    4,
    4,    6,    6,    1,    2,    2,    1,    1,    1,    1,
    1,    1,    1,    1,    3,    4,    3,    4,    4,    5,
    3,    4,    4,    5,    3,    4,    4,    5,    3,    4,
    4,    5,    1,    1,    2,    1,    2,    2,    3,    1,
    1,    2,    1,    1,    1,    1,    2,    3,    1,    1,
    1,    1,    1,    2,    2,    3,    2,    2,    1,    1,
    2,    1,    1,    2,    1,    2,    1,    1,    1,    1,
};
const short yydefred[] = {                                      0,
    0,    0,    0,    0,    0,    0,    5,    0,    0,    0,
    7,    9,    0,    0,    1,    3,   18,   19,    0,    0,
    0,    2,    4,    0,   14,    0,    0,    0,    0,    0,
    0,   11,   20,   22,   24,   23,   21,   10,    0,    0,
   15,   16,    0,   75,    0,    0,    0,    0,    0,    0,
    0,    0,   76,   74,    0,    0,    0,   53,   54,   55,
   56,    0,    0,    0,    0,    0,    0,   13,   12,    0,
    0,   63,   26,    0,    0,   77,   78,   29,    0,   79,
   80,   33,    0,   59,   60,    0,    0,   46,   36,    0,
    0,   57,   51,    0,   40,    0,   69,   70,   68,   72,
   73,   71,   65,    0,   67,   30,   34,   58,   48,    0,
   47,   38,   52,   42,   66,   49,
};
const short yydgoto[] = {                                       5,
   32,   33,   34,   35,   36,   37,   88,   38,   19,   46,
    6,    7,    8,   79,   83,   89,   90,   95,   65,   86,
   74,   75,   99,  102,
};
const short yysindex[] = {                                   -255,
 -251, -244, -239, -254, -231, -254,    0, -254, -186, -226,
    0,    0, -254, -254,    0,    0,    0,    0, -182, -228,
 -225,    0,    0, -217,    0, -211, -219, -219, -219, -219,
 -219,    0,    0,    0,    0,    0,    0,    0, -186, -186,
    0,    0, -206,    0, -175, -219, -219, -219, -208, -208,
 -209, -185,    0,    0, -177, -171, -168,    0,    0,    0,
    0, -163, -165, -219, -163, -155, -219,    0,    0, -135,
 -133,    0,    0, -143, -191,    0,    0,    0, -177,    0,
    0,    0, -177,    0,    0, -163, -177,    0,    0, -256,
 -165,    0,    0, -177,    0, -155,    0,    0,    0,    0,
    0,    0,    0, -174,    0,    0,    0,    0,    0, -177,
    0,    0,    0,    0,    0,    0,
};
const short yyrindex[] = {                                      0,
    0,    0, -192,    1,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0, -164,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -150, -149, -148,    0,    0,    0,
    0,    0, -147,    0,    0, -146,    0,    0,    0,    0,
    0,    0,    0, -145, -144,    0,    0,    0, -142,    0,
    0,    0, -141,    0,    0,    0, -140,    0,    0, -139,
 -138,    0,    0, -137,    0, -136,    0,    0,    0,    0,
    0,    0,    0, -134,    0,    0,    0,    0,    0, -132,
    0,    0,    0,    0,    0,    0,
};
const short yygindex[] = {                                      0,
   58,    0,    0,    0,    0,    0,  -53,   88,   92,   16,
  143,    6,   20,    0,    0,   59,  -44,   56,    0,  -65,
    0,   79,    0,    0,
};
#define YYTABLESIZE 267
const short yytable[] = {                                      92,
    8,   73,   78,   82,   64,   67,    1,    2,    9,   12,
    3,   15,   93,   16,   70,   71,   72,   10,   22,   23,
  108,   94,   11,  110,   14,  106,    3,    4,    4,  107,
    1,    2,   39,  109,    3,   40,  111,   43,   44,   45,
  113,   41,   93,   47,   48,   49,   50,   42,   43,   44,
   45,   94,   53,   27,   20,   21,  116,   28,   29,   30,
   31,   55,   56,   57,   63,   66,   58,   59,   60,   61,
   62,   24,   25,   26,   24,   25,   26,   17,   18,   91,
   27,  105,   96,   54,   28,   29,   30,   31,   76,   77,
    6,   80,   81,   70,   71,   72,   84,   85,  115,   70,
   71,   72,   70,   71,   72,   70,   71,   72,   68,   58,
   59,   60,   61,   62,   87,   70,   71,   72,   17,   58,
   59,   60,   61,   62,   97,   98,  100,  101,   71,  103,
   51,   52,   25,   27,   31,   35,   39,   61,   62,   69,
   28,   32,   44,   43,   37,   50,   41,   13,   64,  112,
   45,  114,  104,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    8,    8,    0,    0,    8,
};
const short yycheck[] = {                                      65,
    0,   55,   56,   57,   49,   50,  262,  263,  260,    4,
  266,    6,   66,    8,  271,  272,  273,  262,   13,   14,
   86,   66,    3,  280,    5,   79,  266,  283,  283,   83,
  262,  263,  261,   87,  266,  261,   90,  257,  258,  259,
   94,  259,   96,   28,   29,   30,   31,  259,  257,  258,
  259,   96,  259,  263,  281,  282,  110,  267,  268,  269,
  270,   46,   47,   48,   49,   50,  275,  276,  277,  278,
  279,  257,  258,  259,  257,  258,  259,  264,  265,   64,
  263,  273,   67,  259,  267,  268,  269,  270,  260,  261,
  283,  260,  261,  271,  272,  273,  260,  261,  273,  271,
  272,  273,  271,  272,  273,  271,  272,  273,   51,  275,
  276,  277,  278,  279,  280,  271,  272,  273,  283,  275,
  276,  277,  278,  279,  260,  261,  260,  261,  272,  273,
   39,   40,  283,  283,  283,  283,  283,  283,  283,   52,
  283,  283,  283,  283,  283,  283,  283,    5,  283,   91,
  283,   96,   74,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  262,  263,   -1,   -1,  266,
};
#define YYFINAL 5
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 283
#if YYDEBUG
const char * const yyname[] = {
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"HOST","ANY","IPADDR","NUM",
"NAME","ACCESSLIST","IP","PERMIT","DENY","COMMENT","ICMP","IGMP","TCP","UDP",
"PRECEDENCE","TOS","LOG","ICMPTYPE","LT","GT","EQ","NEQ","RANGE","ESTABLISHED",
"EXTENDED","STANDARD","NL",
};
const char * const yyrule[] = {
"$accept : config",
"config : acl nl",
"config : config acl nl",
"config : comment nl",
"config : config comment nl",
"config : nl",
"comment : COMMENT",
"comment : COMMENT comment",
"nl : NL",
"nl : NL nl",
"acl : ACCESSLIST NUM action std_acl",
"acl : ACCESSLIST NUM action ext_acl",
"acl : IP ACCESSLIST STANDARD NAME action std_acl",
"acl : IP ACCESSLIST EXTENDED NAME action ext_acl",
"std_acl : ANY",
"std_acl : HOST IPADDR",
"std_acl : IPADDR IPADDR",
"std_acl : IPADDR",
"action : PERMIT",
"action : DENY",
"ext_acl : ext_acl_ip",
"ext_acl : ext_acl_icmp",
"ext_acl : ext_acl_igmp",
"ext_acl : ext_acl_tcp",
"ext_acl : ext_acl_udp",
"ext_acl_ip : IP ext_ip_mask ext_ip_mask",
"ext_acl_ip : IP ext_ip_mask ext_ip_mask prec_tos_log",
"ext_acl_icmp : ICMP ext_ip_mask ext_ip_mask",
"ext_acl_icmp : ICMP ext_ip_mask ext_ip_mask icmp_val",
"ext_acl_icmp : ICMP ext_ip_mask ext_ip_mask prec_tos_log",
"ext_acl_icmp : ICMP ext_ip_mask ext_ip_mask icmp_val prec_tos_log",
"ext_acl_igmp : IGMP ext_ip_mask ext_ip_mask",
"ext_acl_igmp : IGMP ext_ip_mask ext_ip_mask igmp_val",
"ext_acl_igmp : IGMP ext_ip_mask ext_ip_mask prec_tos_log",
"ext_acl_igmp : IGMP ext_ip_mask ext_ip_mask igmp_val prec_tos_log",
"ext_acl_tcp : TCP ext_ip_mask ext_ip_mask",
"ext_acl_tcp : TCP ext_ip_mask ext_ip_mask tcp_port_tail",
"ext_acl_tcp : TCP ext_ip_mask tcp_port_op ext_ip_mask",
"ext_acl_tcp : TCP ext_ip_mask tcp_port_op ext_ip_mask tcp_port_tail",
"ext_acl_udp : UDP ext_ip_mask ext_ip_mask",
"ext_acl_udp : UDP ext_ip_mask ext_ip_mask udp_port_tail",
"ext_acl_udp : UDP ext_ip_mask tcp_port_op ext_ip_mask",
"ext_acl_udp : UDP ext_ip_mask tcp_port_op ext_ip_mask udp_port_tail",
"tcp_port_tail : tcp_port_op",
"tcp_port_tail : ESTABLISHED",
"tcp_port_tail : tcp_port_op ESTABLISHED",
"tcp_port_tail : prec_tos_log",
"tcp_port_tail : tcp_port_op prec_tos_log",
"tcp_port_tail : ESTABLISHED prec_tos_log",
"tcp_port_tail : tcp_port_op ESTABLISHED prec_tos_log",
"udp_port_tail : tcp_port_op",
"udp_port_tail : prec_tos_log",
"udp_port_tail : tcp_port_op prec_tos_log",
"s_operator : LT",
"s_operator : GT",
"s_operator : EQ",
"s_operator : NEQ",
"tcp_port_op : s_operator tcp_val",
"tcp_port_op : RANGE tcp_val tcp_val",
"tcp_val : NUM",
"tcp_val : NAME",
"prec_tos_log : precedence",
"prec_tos_log : tos",
"prec_tos_log : LOG",
"prec_tos_log : precedence tos",
"prec_tos_log : precedence LOG",
"prec_tos_log : precedence tos LOG",
"prec_tos_log : tos LOG",
"precedence : PRECEDENCE precedence_val",
"precedence_val : NUM",
"precedence_val : NAME",
"tos : TOS tos_val",
"tos_val : NUM",
"tos_val : NAME",
"ext_ip_mask : IPADDR IPADDR",
"ext_ip_mask : ANY",
"ext_ip_mask : HOST IPADDR",
"icmp_val : NUM",
"icmp_val : NAME",
"igmp_val : NUM",
"igmp_val : NAME",
};
#endif
#if YYDEBUG
#include <stdio.h>
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH 10000
#endif
#endif
#define YYINITSTACKSIZE 200
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
short *yyss;
short *yysslim;
YYSTYPE *yyvs;
int yystacksize;
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack()
{
    int newsize, i;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
    i = yyssp - yyss;
    newss = yyss ? (short *)realloc(yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss);
    if (newss == NULL)
        return -1;
    yyss = newss;
    yyssp = newss + i;
    newvs = yyvs ? (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs);
    if (newvs == NULL)
        return -1;
    yyvs = newvs;
    yyvsp = newvs + i;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab

#ifndef YYPARSE_PARAM
#if defined(__cplusplus) || __STDC__
#define YYPARSE_PARAM_ARG void
#define YYPARSE_PARAM_DECL
#else	/* ! ANSI-C/C++ */
#define YYPARSE_PARAM_ARG
#define YYPARSE_PARAM_DECL
#endif	/* ANSI-C/C++ */
#else	/* YYPARSE_PARAM */
#ifndef YYPARSE_PARAM_TYPE
#define YYPARSE_PARAM_TYPE void *
#endif
#if defined(__cplusplus) || __STDC__
#define YYPARSE_PARAM_ARG YYPARSE_PARAM_TYPE YYPARSE_PARAM
#define YYPARSE_PARAM_DECL
#else	/* ! ANSI-C/C++ */
#define YYPARSE_PARAM_ARG YYPARSE_PARAM
#define YYPARSE_PARAM_DECL YYPARSE_PARAM_TYPE YYPARSE_PARAM;
#endif	/* ANSI-C/C++ */
#endif	/* ! YYPARSE_PARAM */

int
yyparse (YYPARSE_PARAM_ARG)
    YYPARSE_PARAM_DECL
{
    register int yym, yyn, yystate;
#if YYDEBUG
    register const char *yys;

    if ((yys = getenv("YYDEBUG")))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if ((yyn = yydefred[yystate])) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yyssp >= yysslim && yygrowstack())
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = (-1);
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;
#if defined(lint) || defined(__GNUC__)
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#if defined(lint) || defined(__GNUC__)
    goto yyerrlab;
#endif
yyerrlab:
    ++yynerrs;
yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yysslim && yygrowstack())
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = (-1);
        goto yyloop;
    }
yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    yyval = yyvsp[1-yym];
    switch (yyn)
    {
case 10:
#line 54 "aclyacc.y"
{
		/* XXX add code to check NUM is in range 0..99 */
		yyvsp[0].std_entry.flag |= yyvsp[-1].i;
		x = acl_create(&acl_list, yyvsp[-2].c, ACL_TYPE_STD);
		acl_add_line_std(acl_list, x, yyvsp[0].std_entry);
	}
break;
case 11:
#line 60 "aclyacc.y"
{
		/* XXX add code to check NUM is in range 100-199 */
		yyvsp[0].ext_entry.flag |= yyvsp[-1].i;
		x = acl_create(&acl_list, yyvsp[-2].c, ACL_TYPE_EXT);
		acl_add_line_ext(acl_list, x, yyvsp[0].ext_entry);
	}
break;
case 12:
#line 66 "aclyacc.y"
{
		yyvsp[0].std_entry.flag |= yyvsp[-1].i;
		x = acl_create(&acl_list, yyvsp[-2].c, ACL_TYPE_STD);
		acl_add_line_std(acl_list, x, yyvsp[0].std_entry);
	}
break;
case 13:
#line 71 "aclyacc.y"
{
		yyvsp[0].ext_entry.flag |= yyvsp[-1].i;
		x = acl_create(&acl_list, yyvsp[-2].c, ACL_TYPE_EXT);
		acl_add_line_ext(acl_list, x, yyvsp[0].ext_entry);
	}
break;
case 14:
#line 79 "aclyacc.y"
{
		yyval.std_entry.src_addr = 0x0;
		yyval.std_entry.src_mask = 0xFFFFFFFF;
		yyval.std_entry.matches = 0;
		yyval.std_entry.flag = 0;
	}
break;
case 15:
#line 85 "aclyacc.y"
{ 
		yyval.std_entry.src_addr = yyvsp[0].ip;
		yyval.std_entry.src_mask = 0x0;
		yyval.std_entry.matches = 0;
		yyval.std_entry.flag = 0;
	}
break;
case 16:
#line 91 "aclyacc.y"
{ 
		yyval.std_entry.src_addr = yyvsp[-1].ip;
		yyval.std_entry.src_mask = yyvsp[0].ip;
		yyval.std_entry.matches = 0;
		yyval.std_entry.flag = 0;
	}
break;
case 17:
#line 97 "aclyacc.y"
{
		yyval.std_entry.src_addr = yyvsp[0].ip;
		yyval.std_entry.src_mask = 0x0;
		yyval.std_entry.matches = 0;
		yyval.std_entry.flag = 0;
	}
break;
case 18:
#line 105 "aclyacc.y"
{
		yyval.i = ACL_FLAG_PERMIT;
	}
break;
case 19:
#line 108 "aclyacc.y"
{
		yyval.i = 0;
	}
break;
case 25:
#line 121 "aclyacc.y"
{
		yyval.ext_entry.protocol = 0;
		yyval.ext_entry.precedence = 0;
		yyval.ext_entry.tos = 0;
		yyval.ext_entry.type = 0;
		yyval.ext_entry.type_code = 0;
		yyval.ext_entry.message = 0;
		yyval.ext_entry.src_op = 0;
		yyval.ext_entry.dst_op = 0;
		yyval.ext_entry.src_addr = yyvsp[-1].std_entry.src_addr;
		yyval.ext_entry.src_mask = yyvsp[-1].std_entry.src_mask;
		yyval.ext_entry.src_port = 0;
		yyval.ext_entry.src_port2 = 0;
		yyval.ext_entry.dst_addr = yyvsp[0].std_entry.src_addr;
		yyval.ext_entry.dst_mask = yyvsp[0].std_entry.src_mask;
		yyval.ext_entry.dst_port = 0;
		yyval.ext_entry.dst_port2 = 0;
		yyval.ext_entry.matches = 0;
		yyval.ext_entry.flag = ACL_FLAG_IP_ALL;
	}
break;
case 26:
#line 141 "aclyacc.y"
{
		yyval.ext_entry.protocol = 0;
		yyval.ext_entry.precedence = yyvsp[0].ext_entry.precedence;
		yyval.ext_entry.tos = yyvsp[0].ext_entry.tos;
		yyval.ext_entry.type = 0;
		yyval.ext_entry.type_code = 0;
		yyval.ext_entry.message = 0;
		yyval.ext_entry.src_op = 0;
		yyval.ext_entry.dst_op = 0;
		yyval.ext_entry.src_addr = yyvsp[-2].std_entry.src_addr;
		yyval.ext_entry.src_mask = yyvsp[-2].std_entry.src_mask;
		yyval.ext_entry.src_port = 0;
		yyval.ext_entry.src_port2 = 0;
		yyval.ext_entry.dst_addr = yyvsp[-1].std_entry.src_addr;
		yyval.ext_entry.dst_mask = yyvsp[-1].std_entry.src_mask;
		yyval.ext_entry.dst_port = 0;
		yyval.ext_entry.dst_port2 = 0;
		yyval.ext_entry.matches = 0;
		yyval.ext_entry.flag = ACL_FLAG_IP_ALL | yyvsp[-1].std_entry.flag;
	}
break;
case 27:
#line 163 "aclyacc.y"
{
		yyval.ext_entry.protocol = IPPROTO_ICMP;
		yyval.ext_entry.precedence = 0;
		yyval.ext_entry.tos = 0;
		yyval.ext_entry.type = 0;
		yyval.ext_entry.type_code = 0;
		yyval.ext_entry.message = 0;
		yyval.ext_entry.src_op = 0;
		yyval.ext_entry.dst_op = 0;
		yyval.ext_entry.src_addr = yyvsp[-1].std_entry.src_addr;
		yyval.ext_entry.src_mask = yyvsp[-1].std_entry.src_mask;
		yyval.ext_entry.src_port = 0;
		yyval.ext_entry.src_port2 = 0;
		yyval.ext_entry.dst_addr = yyvsp[0].std_entry.src_addr;
		yyval.ext_entry.dst_mask = yyvsp[0].std_entry.src_mask;
		yyval.ext_entry.dst_port = 0;
		yyval.ext_entry.dst_port2 = 0;
		yyval.ext_entry.matches = 0;
		yyval.ext_entry.flag = 0;
	}
break;
case 28:
#line 183 "aclyacc.y"
{}
break;
case 29:
#line 184 "aclyacc.y"
{}
break;
case 30:
#line 185 "aclyacc.y"
{}
break;
case 31:
#line 188 "aclyacc.y"
{
		yyval.ext_entry.protocol = IPPROTO_IGMP;
		yyval.ext_entry.precedence = 0;
		yyval.ext_entry.tos = 0;
		yyval.ext_entry.type = 0;
		yyval.ext_entry.type_code = 0;
		yyval.ext_entry.message = 0;
		yyval.ext_entry.src_op = 0;
		yyval.ext_entry.dst_op = 0;
		yyval.ext_entry.src_addr = yyvsp[-1].std_entry.src_addr;
		yyval.ext_entry.src_mask = yyvsp[-1].std_entry.src_mask;
		yyval.ext_entry.src_port = 0;
		yyval.ext_entry.src_port2 = 0;
		yyval.ext_entry.dst_addr = yyvsp[0].std_entry.src_addr;
		yyval.ext_entry.dst_mask = yyvsp[0].std_entry.src_mask;
		yyval.ext_entry.dst_port = 0;
		yyval.ext_entry.dst_port2 = 0;
		yyval.ext_entry.matches = 0;
		yyval.ext_entry.flag = 0;
	}
break;
case 32:
#line 208 "aclyacc.y"
{}
break;
case 33:
#line 209 "aclyacc.y"
{}
break;
case 34:
#line 210 "aclyacc.y"
{}
break;
case 35:
#line 213 "aclyacc.y"
{
		yyval.ext_entry.protocol = IPPROTO_TCP;
		yyval.ext_entry.precedence = 0;
		yyval.ext_entry.tos = 0;
		yyval.ext_entry.type = 0;
		yyval.ext_entry.type_code = 0;
		yyval.ext_entry.message = 0;
		yyval.ext_entry.src_op = 0;
		yyval.ext_entry.dst_op = 0;
		yyval.ext_entry.src_addr = yyvsp[-1].std_entry.src_addr;
		yyval.ext_entry.src_mask = yyvsp[-1].std_entry.src_mask;
		yyval.ext_entry.src_port = 0;
		yyval.ext_entry.src_port2 = 0;
		yyval.ext_entry.dst_addr = yyvsp[0].std_entry.src_addr;
		yyval.ext_entry.dst_mask = yyvsp[0].std_entry.src_mask;
		yyval.ext_entry.dst_port = 0;
		yyval.ext_entry.dst_port2 = 0;
		yyval.ext_entry.matches = 0;
		yyval.ext_entry.flag = 0;
	}
break;
case 36:
#line 233 "aclyacc.y"
{}
break;
case 37:
#line 234 "aclyacc.y"
{}
break;
case 38:
#line 235 "aclyacc.y"
{}
break;
case 39:
#line 238 "aclyacc.y"
{
		yyval.ext_entry.protocol = IPPROTO_UDP;
		yyval.ext_entry.precedence = 0;
		yyval.ext_entry.tos = 0;
		yyval.ext_entry.type = 0;
		yyval.ext_entry.type_code = 0;
		yyval.ext_entry.message = 0;
		yyval.ext_entry.src_op = 0;
		yyval.ext_entry.dst_op = 0;
		yyval.ext_entry.src_addr = yyvsp[-1].std_entry.src_addr;
		yyval.ext_entry.src_mask = yyvsp[-1].std_entry.src_mask;
		yyval.ext_entry.src_port = 0;
		yyval.ext_entry.src_port2 = 0;
		yyval.ext_entry.dst_addr = yyvsp[0].std_entry.src_addr;
		yyval.ext_entry.dst_mask = yyvsp[0].std_entry.src_mask;
		yyval.ext_entry.dst_port = 0;
		yyval.ext_entry.dst_port2 = 0;
		yyval.ext_entry.matches = 0;
		yyval.ext_entry.flag = 0;
	}
break;
case 40:
#line 258 "aclyacc.y"
{}
break;
case 41:
#line 259 "aclyacc.y"
{}
break;
case 42:
#line 260 "aclyacc.y"
{}
break;
case 61:
#line 292 "aclyacc.y"
{}
break;
case 62:
#line 293 "aclyacc.y"
{}
break;
case 63:
#line 294 "aclyacc.y"
{}
break;
case 64:
#line 295 "aclyacc.y"
{}
break;
case 65:
#line 296 "aclyacc.y"
{}
break;
case 66:
#line 297 "aclyacc.y"
{}
break;
case 67:
#line 298 "aclyacc.y"
{}
break;
case 68:
#line 301 "aclyacc.y"
{}
break;
case 74:
#line 315 "aclyacc.y"
{
		yyval.std_entry.src_addr = yyvsp[-1].ip;
		yyval.std_entry.src_mask = yyvsp[0].ip;
		yyval.std_entry.matches = 0;
		yyval.std_entry.flag = 0;
	}
break;
case 75:
#line 321 "aclyacc.y"
{
		yyval.std_entry.src_addr = 0x0;
		yyval.std_entry.src_mask = 0xFFFFFFFF;
		yyval.std_entry.matches = 0;
		yyval.std_entry.flag = 0;
	}
break;
case 76:
#line 327 "aclyacc.y"
{
		yyval.std_entry.src_addr = yyvsp[0].ip;
		yyval.std_entry.src_mask = 0x0;
		yyval.std_entry.matches = 0;
		yyval.std_entry.flag = 0;
	}
break;
#line 853 "y.tab.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yysslim && yygrowstack())
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;
yyoverflow:
    yyerror("yacc stack overflow");
yyabort:
    return (1);
yyaccept:
    return (0);
}
