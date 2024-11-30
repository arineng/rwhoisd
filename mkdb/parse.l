%{
/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-1998 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "parse.h"

#include "auth_area.h"
#include "defines.h"
#include "misc.h"
#include "schema.h"
#include "y.tab.h"

extern YYSTYPE yylval;

int yywrap PROTO((void));

/* the lexer input buffer */
static char *lexstring = NULL;
static int   lexlen    = 0;

#ifdef FLEX_SCANNER
static int parse_yyinput PROTO((char *buf, int max_size));
#  define YY_INPUT(b, r, ms) (r = parse_yyinput(b, ms))
#else /* using AT&T style lex */
#  undef input
#  undef unput
#  define input() (*lexstring++)
#  define unput(c) (*--lexstring = c)
#endif

%}

WSP         [ \t\n]
VALUE       \*?[^ \t=*\n]+\*?
QUOTEDVALUE \*?\"\*?[^"*\n]+\*?\"\*?
AND         AND
OR          OR
EQ          =
NEQ         !=
WILD        \*

%%

{AND}           { return(AND); }
{OR}            { return(OR); }
{EQ}            { return(EQ); }
{NEQ}           { return(NEQ); }
{QUOTEDVALUE}   { yylval.val = xstrdup(yytext); return(QUOTEDVALUE); }
^{VALUE}        { yylval.val = xstrdup(yytext);
                  if (find_global_class_by_name(yytext)) {
                    return(CLASS);
                  } else if (find_truly_global_attr_by_name(yytext)) {
                    return(ATTR);
                  }
                  return(VALUE);
                }
{VALUE}         { yylval.val = xstrdup(yytext);
                  if (find_truly_global_attr_by_name(yytext)) {
                    return(ATTR);
                  }
                  return(VALUE);
                }
{WILD}          { return(WILD);        }
{WSP}           { /* eat whitespace */ }

%%

int
set_lexstring(s)
  char *s;
{
  lexstring = s;
  lexlen = strlen(lexstring);

#ifdef FLEX_SCANNER
  if (YY_CURRENT_BUFFER)
    YY_FLUSH_BUFFER;
#else
  /* This is a hack to get AT&T generated lexers to reset the newline
     state on subsequent calls to the parser.  I have no idea if this
     is portable */
  {
     extern int yyprevious;
         NLSTATE;
  }
#endif /* FLEX */  

  return TRUE;
}

int
yywrap()
{
  return 1;
}

#ifdef FLEX_SCANNER
static int
parse_yyinput(buf, max_size)
  char  *buf;
  int   max_size;
{
  int n = (lexlen < max_size) ? lexlen : max_size;

  if (n > 0)
  {
    bcopy(lexstring, buf, n);
    lexstring += n;
    lexlen -= n;
  }

  return(n);
}
#endif
