/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _DIRECTIVE_H_
#define _DIRECTIVE_H_

/* includes */
#include "common.h"
#include "types.h"

/* prototypes */

void init_directive_functions PROTO((void));

int is_directive PROTO((char *str));

int run_directive PROTO((char *query_str));

int directive_directive PROTO((char *str));

#endif /* _DIRECTIVE_H_ */
