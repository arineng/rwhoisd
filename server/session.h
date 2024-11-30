/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */


#ifndef _SESSION_H_
#define _SESSION_H_

/* includes */

#include "common.h"
#include "types.h"
#include "mkdb_types.h"

/* prototypes */

void run_session PROTO((int real_flag));

void print_welcome_header PROTO((void));

#endif /* _SESSION_H_ */
