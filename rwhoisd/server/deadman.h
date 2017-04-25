/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _DEADMAN_H_
#define _DEADMAN_H

/* includes */

#include "common.h"

/* prototypes */

void set_timer PROTO((int seconds, void *function));

void is_a_deadman PROTO((void));

void unset_timer PROTO((void));

void set_deadman_time PROTO((char *secs));

int get_deadman_time PROTO((void));

void set_initial_time PROTO(());

long get_time_elapsed PROTO(());

#endif /* _DEADMAN_H_ */
