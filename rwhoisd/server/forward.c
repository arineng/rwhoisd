/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "forward.h"

#include "client_msgs.h"
#include "conf.h"
#include "defines.h"
#include "directive_conf.h"
#include "holdconnect.h"
#include "log.h"
#include "main_config.h"
#include "misc.h"
#include "procutils.h"
#include "strutil.h"

static char original_query_buf[MAX_LINE];

/**************************************************************************
  sets the cache value
   toggles it for now
**************************************************************************/
int
forward_directive( str )
  char *str;
{
  if ( !set_forward(str) )
  {
    print_error(INVALID_DIRECTIVE_PARAM, "");
    return FALSE;
  }

  log(L_LOG_DEBUG, CLIENT, "forward directive: %s", str);
    
/*   print_ok(); */
  return TRUE;
}

/**************************************************************************
  forwards the request
**************************************************************************/
int
forward_request(host, query, auth_area)
  char *host;
  char *query;
  char *auth_area;

{
  char param_str[MAX_LINE];

  sprintf(param_str, "-h %s %s", host, query);
  run_program(DEFAULT_CLIENT_PROG, param_str);

  return TRUE;
}

/**************************************************************************
  saves the query
**************************************************************************/
int
save_original_query (query_str)
  char *query_str;

{
  strcpy(original_query_buf, query_str);

  return TRUE;
}

/**************************************************************************
  retrieves the query
**************************************************************************/
char *
original_query()
{
  return(original_query_buf);
}
