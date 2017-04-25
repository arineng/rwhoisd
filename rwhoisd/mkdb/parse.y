%{
/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-1998 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "parse.h"

#include "client_msgs.h"
#include "defines.h"
#include "log.h"
#include "misc.h"
#include "read_config.h"
#include "strutil.h"
  
static int set_query PROTO((char *class_name, char *auth_area_name));

static query_term_struct *set_query_term PROTO((char *attribute_name,
                                                char *value,
                                                mkdb_operator_type op));

static void add_term PROTO((query_term_struct *term));

static void add_and_term PROTO((void));

static void add_or_term PROTO((void));

static void display_query_term PROTO((query_term_struct *term));

static void display_query PROTO((void));

%}

%token AND
%token OR
%token EQ
%token NEQ
%token CLASS
%token ATTR
%token VALUE
%token QUOTEDVALUE
%token WILD

%union {
  char              *val;
  query_term_struct *qt;
}

%type <val> VALUE QUOTEDVALUE ATTR CLASS value
%type <qt> querystr

%%

total: CLASS query        { set_query($1, NULL); }
    | query 
    ;

query: query AND querystr { add_term($3); add_and_term(); }
    |  query OR querystr  { add_term($3); add_or_term();  }
    |  querystr           { add_term($1); }
    ;

querystr:  ATTR EQ value { $$ = set_query_term($1, $3, MKDB_EQ_OP);   }
    | ATTR NEQ value     { $$ = set_query_term($1, $3, MKDB_NOT_EQ_OP); }
    | value              { $$ = set_query_term(NULL, $1, MKDB_EQ_OP); }
    | ATTR               { $$ = set_query_term(NULL, $1, MKDB_EQ_OP); }
    ;

value: VALUE             { $$ = $1; }   
    | QUOTEDVALUE        { $$ = $1; }
    ;

%%

static query_struct        *parse_result;
static query_term_struct   *current_or;
static query_term_struct   *current_and;
static query_term_struct   *working_term;
static int                 parse_status;
  
static int
set_query(class_name, auth_area_name)
  char *class_name;
  char *auth_area_name;
{
  if (auth_area_name && *auth_area_name)
  {
    parse_result->auth_area_name = auth_area_name;
  }

  if (class_name && *class_name)
  {
    parse_result->class_name = class_name;
  }

  return TRUE;
}

static query_term_struct *
set_query_term(attribute_name, value, op)
  char               *attribute_name;
  char               *value;
  mkdb_operator_type op;
{
  query_term_struct *qt;
  
  if (!value || !*value)
  {
    return NULL;
  }

  qt = xcalloc(1, sizeof(*qt));
  
  if (attribute_name && *attribute_name)
  {
    qt->attribute_name = attribute_name;
  }

  /* examine the value to set the search and comp types */
  qt->search_type  = MKDB_BINARY_SEARCH;
  qt->attribute_id = -2;

  /* remove quotes, and then remove leading and trailing whitespace */
  stripchar(value, '"');
  trim(value);
  
  if (value[strlen(value)-1] == '*')
  {
    qt->comp_type   = MKDB_PARTIAL_COMPARE;
    strip_trailing(value, '*');
  }

  if (value[0] == '*')
  {
    qt->search_type = MKDB_FULL_SCAN;
    qt->comp_type   = MKDB_SUBSTR_COMPARE;
    strip_leading(value, '*');
  }
  
  qt->search_value = value;

  if (op == MKDB_NOT_EQ_OP)
  {
    /* FIXME: this can easily become totally wrong */
    qt->comp_type += MKDB_NEGATION_OFFSET; 
  }
  
  return(qt);
}

/* sets working term to the term, and if necessary sets the first term */
static void
add_term(term)
  query_term_struct *term;
{
  if (working_term)
  {
    log(L_LOG_WARNING, QUERY, "losing term (search_value => %s)\n",
        working_term->search_value);
  }
  
  if (!parse_result->query_tree)
  {
    parse_result->query_tree = term;
    current_or = current_and = term;
  }
  else
  {
    working_term = term;
  }
}

static void
add_and_term()
{
  if (!current_and)
  {
    log(L_LOG_ERR, QUERY, "current_and not set\n");
  }
  
  current_and->and_list = working_term;
  current_and = working_term;
  working_term = NULL;
}

static void
add_or_term()
{
  if (!current_or)
  {
    log(L_LOG_ERR, QUERY, "current_or not set\n");
  }
  
  current_or->or_list = working_term;
  current_or = current_and = working_term;
  working_term = NULL;
}

static void
display_query_term(term)
  query_term_struct *term;
{

  printf(" ");
  if (!term)
  {
    printf("NULL\n");
    return;
  }
  
  if (term->search_value) printf("val: '%s' ", term->search_value);
  if (term->attribute_name) printf("attr: '%s' ", term->attribute_name);
  if (term->comp_type == MKDB_PARTIAL_COMPARE) printf("(partial) ");
  
  printf("\n");
}


static void
display_query()
{
  query_term_struct *qt;
  query_term_struct *top;

  top = parse_result->query_tree;
  qt = top;

  if (parse_result->class_name) printf("query: class restrictor '%s'\n",
                                       parse_result->class_name);
  
  while (top)
  {
    while (qt)
    {
      display_query_term(qt);
      qt = qt->and_list;
      if (qt) printf(" -and-\n");
    }

    top = top->or_list;
    qt  = top;
    if (qt) printf(" -or-\n");
  }
}
  

int
parse_query(line, result)
  char         *line;
  query_struct *result;
{
  /* reset global variables */
  parse_result = result;
  bzero(parse_result, sizeof(*parse_result));
  current_and = current_or = working_term = NULL;   
  parse_status = TRUE;
  
  /* set the lexer input buffer */
  strupr(line);
  set_lexstring(line);

  /* perform the actual parse */
  yyparse();

  return(parse_status);
}

int
yyerror(s)
  char *s;
{
  print_error(INVALID_QUERY_SYNTAX, "");
  parse_status = FALSE;
  return(0);
}

int
destroy_query_term(qt)
  query_term_struct *qt;
{
  if (!qt) return TRUE;

  if (qt->attribute_name)
  {
    free(qt->attribute_name);
  }

  if (qt->search_value)
  {
    free(qt->search_value);
  }

  free(qt);

  return TRUE;
}

int
destroy_query(q)
  query_struct  *q;
{
  query_term_struct *horiz;
  query_term_struct *vert;
  query_term_struct *cur;

  if (!q) return TRUE;
  
  horiz = vert = q->query_tree;

  /* free the tree; assumes that the tree is really a matrix, which is
     true, for now */
  while (horiz)
  {
    horiz = horiz->or_list;
    
    while (vert)
    {
      cur  = vert;
      vert = vert->and_list;
      destroy_query_term(cur);
    }

    vert = horiz;
  }
  
  if (q->class_name)
  {
    free(q->class_name);
  }

  if (q->auth_area_name)
  {
    free(q->auth_area_name);
  }

  free(q);

  return TRUE;
}
