/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _REGISTER_H_
#define _REGISTER_H_

/* includes */

#include "common.h"
#include "reg_utils.h"

/* prototypes */

int process_registration PROTO((char                 *reg_action,
                                register_action_type action));
                               

#endif /* _REGISTER_H_ */

