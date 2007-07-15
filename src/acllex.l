%{
#include <ftlib.h>

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
 
#if HAVE_STRING_H
  #include <string.h>
#endif

#include "acl2.h"
#include "aclyacc.h"
%}

byte	([0-9]+)

%%
\n					{ return NL;}
!.*					{ return COMMENT;}
[ \t\n\r]	;		/* ignore whitespace */
access-list			{return ACCESSLIST;}
{byte}\.{byte}\.{byte}\.{byte}		{yylval.ip = scan_ip(yytext); return IPADDR;}
[0-9]+				{ yylval.c = strdup (yytext); return NUM;}
permit				{ return PERMIT;}
deny				{ return DENY;}
host				{ yylval.c = strdup (yytext); return HOST;}
any					{ yylval.c = strdup (yytext); return ANY;}
ip					{ return IP;}
tcp					{ return TCP;}
udp					{ return UDP;}
igmp				{ return IGMP;}
icmp				{ return ICMP;}
precedence			{ return PRECEDENCE;}
tos					{ return TOS;}
log					{ return LOG;}
icmp-type			{ return ICMPTYPE;}
lt								{return LT;}
gt								{return GT;}
eq								{return EQ;}
neq								{return NEQ;}
range							{return RANGE;}
established						{return ESTABLISHED;}
extended						{return EXTENDED;}
standard						{return STANDARD;}
[a-zA-Z]+[_0-9a-zA-Z]*			{yylval.c = strdup (yytext); return NAME;}
.	{fprintf(stderr, "\"%s\": ", yytext); return 0;}
%%

