/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _REG_EXT_H_
#define _REG_EXT_H_

/* includes */

#include "common.h"
#include "reg_utils.h"
#include "types.h"

/* types */

typedef enum
{
  EXT_PARSE_OK,
  EXT_PARSE_DEFERRED,
  EXT_PARSE_ERROR
} ext_parse_response_type;

/* prototypes */

ext_parse_response_type
run_external_parser PROTO((char                 *parse_prog,
                           register_action_type action,
                           char                 *reg_email,
                           record_struct        *old_rec,
                           record_struct        **new_rec_p));

#endif /* _REG_EXT_H_ */
