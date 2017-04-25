/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _SECURITY_H_
#define _SECURITY_H_

/* includes */

#include "common.h"

/* prototypes */

int setup_security PROTO((void));

int authorized_directive PROTO((char *directive));

int authorized_client PROTO((void));

#endif /* _SECURITY_H_ */
