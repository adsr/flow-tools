#ifndef YYERRCODE
#define YYERRCODE 256
#endif

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
typedef union {
	char *c;
	u_long long ip;
	int i;
	u_int u;
	struct acl_ip_std_entry std_entry;
	struct acl_ip_ext_entry ext_entry;
} YYSTYPE;
extern YYSTYPE yylval;
