/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _DAEMON_H_
#define _DAEMON_H_

/* includes */

#include "common.h"

/* prototypes */

int run_daemon PROTO((void));

void no_zombies PROTO((void));

#endif /* _DAEMON_H_ */
