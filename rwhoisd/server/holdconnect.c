/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "holdconnect.h"

#include "client_msgs.h"
#include "defines.h"
#include "directive_conf.h"
#include "log.h"
#include "main_config.h"
#include "strutil.h"

/* set_holdconnect: sets the holdconnect value */
int 
holdconnect_directive( str )
  char  *str;
{
  log(L_LOG_DEBUG, CLIENT, "holdconnect directive: %s", str);
  
  if (!set_holdconnect(str) )
  {
    print_error(INVALID_DIRECTIVE_PARAM, "");
    return FALSE;
  }

/*   print_ok(); */
  return TRUE;
}

