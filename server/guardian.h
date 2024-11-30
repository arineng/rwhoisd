/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _GUARDIAN_H_
#define _GUARDIAN_H_

/* includes */

#include "common.h"
#include "types.h"

/* prototypes */

int check_guardian PROTO((record_struct *record));

int set_auth_info PROTO((char *auth_info));

int is_guardian_record PROTO((record_struct *record));

int transform_guardian_record PROTO((record_struct *record));

#endif /* _GUARDIAN_H_ */

