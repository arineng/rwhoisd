/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _PARSE_H_
#define _PARSE_H_

/* includes */

#include "common.h"
#include "mkdb_types.h"

/* prototypes */

/* these are really defined in parse.y */
int parse_query PROTO((char *line, query_struct *result));

int destroy_query_term PROTO((query_term_struct *qt));

int destroy_query PROTO((query_struct *q));

/* these are really defined in parse.l */
int set_lexstring PROTO((char *s));

#endif /* _PARSE_H_ */
