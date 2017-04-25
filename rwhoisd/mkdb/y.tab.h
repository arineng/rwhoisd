typedef union {
  char              *val;
  query_term_struct *qt;
} YYSTYPE;
#define	AND	258
#define	OR	259
#define	EQ	260
#define	NEQ	261
#define	CLASS	262
#define	ATTR	263
#define	VALUE	264
#define	QUOTEDVALUE	265
#define	WILD	266


extern YYSTYPE yylval;
