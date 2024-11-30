/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _FORWARD_H_
#define _FORWARD_H_

/* includes */

#include "common.h"

/* prototypes */

int forward_directive PROTO((char *str));

/* useless
int forward_request PROTO((char *host, char *query, char *auth_area));
int save_original_query PROTO((char *query_str));
char *original_query PROTO((void));
*/

#endif /* _FORWARD_H_ */
