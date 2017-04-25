/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "limit.h"

#include "client_msgs.h"
#include "defines.h"
#include "log.h"
#include "main_config.h"
#include "misc.h"

/* limit_directive: allow client to request the server to allocat enough 
 * space to collect more responses than would currently be collected by
 * the server. 
 * Input:   -limit <value>
 * Response: %ok  
 *      -OR- 
 *       error messages.
 */
int 
limit_directive(str)
  char  *str;
{
  int hits;
  int ceiling;
  int argc;
  char **argv;

  log(L_LOG_DEBUG, CLIENT, "limit directive: %s", str);
  
  split_arg_list(str, &argc, &argv);

  if ( argc != 1 )
  { 
    print_error(INVALID_DIRECTIVE_PARAM,"");
    return FALSE;
  }

  hits = atoi(argv[0]);
  ceiling = get_max_hits_ceiling();

  if (ceiling == 0 && hits >= 0)
  {
    set_hit_limit(hits);
    return TRUE;
  }
  
  if ( (ceiling > 0) && (hits > 0 && hits <= ceiling) )
  {
    set_hit_limit(hits);
    return TRUE;
  }     

  /* otherwise, the limit is bad */
  print_error(INVALID_LIMIT, "");
  return FALSE;
}
