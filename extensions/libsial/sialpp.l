%{
/*
 * Copyright 2001 Silicon Graphics, Inc. All rights reserved.
 */

#define YY_NO_UNPUT
%}

%{
#include <string.h>

#ifdef linux
#define YY_INPUT(buf,result,max_size) \
{ \
	int c = sial_input(); \
	result = (c == EOF) ? YY_NULL : (buf[0] = c, 1); \
}
#endif

#include	"sial.h"
#include	"sialpp.tab.h"
#if linux
#define yylval sialpplval
#endif

#define retok(t) return(t)
int nomacs=0;
extern int sial_chkmacvar(char *);
extern node_t *sial_newchar(void);
%}

ABC		[a-zA-Z_]
ABCN		[a-zA-Z0-9_]
N		[0-9]
X		[0-9a-fA-F]

%%

[ \t\n]+	{ ; }

"defined"	{ retok(P_DEFINED); }
"&&"		{ retok(P_BAND); }
"||"		{ retok(P_BOR); }
"<"		{ retok(P_LT); }
"<="		{ retok(P_LE); }
"=="		{ retok(P_EQ); }
">="		{ retok(P_GE); }
">"		{ retok(P_GT); }
"!="		{ retok(P_NE); }
"|"		{ retok(P_OR); }
"!"		{ retok(P_NOT); }
"^"		{ retok(P_XOR); }
">>"		{ retok(P_SHR); }
"<<"		{ retok(P_SHL); }
"+"		{ retok(P_ADD); }
"-"		{ retok(P_SUB); }
"/"		{ retok(P_DIV); }
"%"		{ retok(P_MOD); }
"*"		{ retok(P_MUL); }

(("0x"+){X}+[lL]*|{N}+[lL]*)	{ yylval.n = sial_newnum(yytext); retok(P_NUMBER); }

{ABC}{ABCN}*	{ 
				if(strlen(yytext) > MAX_SYMNAMELEN) {

					sial_error("Symbol name too long");
				}
				if(nomacs || !sial_chkmacvar(yytext)) {

					yylval.n = sial_newvnode(yytext); 
					retok(P_VAR);
				}
		}

\'.\'		{ yylval.n = sial_makenum(B_SC, yytext[1]); retok(P_NUMBER); }
\'\\.\'		{ yylval.n = sial_makenum(B_SC, sial_getseq(yytext[2])); retok(P_NUMBER); }


.		{ retok(yylval.i = yytext[0]); }

%%
#undef input
#undef unput
#define input()       sial_input()
#define unput(c)      sial_unput(c)
