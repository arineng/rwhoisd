/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _SECURITY_DIRECTIVE_H_
#define _SECURITY_DIRECTIVE_H_

/* includes */

#include "common.h"
#include "types.h"

/* prototypes */

int security_directive PROTO((char *str));

auth_struct * get_request_auth_struct PROTO((void));

auth_struct * get_response_auth_struct PROTO((void));



#endif /* _SECURITY_DIRECTIVE_H_ */
