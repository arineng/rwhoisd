/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "display.h"

#include "client_msgs.h"
#include "defines.h"
#include "log.h"
#include "main_config.h"
#include "misc.h"
#include "strutil.h"

/* display_directive: set the display mode of server or identify display mode
 * the client is capable of. 
 * Input:   -display [name]
 *          name: {%s}
 * Response:
 *      %display name: <name>
 *      %display description:<discription>
 *      %display
 *  -OR-
 *      %error if non-RWhois client.
 */
int
display_directive( str)
  char  *str;
{
  int   argc;
  char  **argv;
 
  /* FIXME, for now, only "dump" display. */
  split_arg_list(str, &argc, &argv);

  
  if ( argc > 1 )
  {
    print_error(INVALID_DIRECTIVE_PARAM,"");
    return FALSE;
  }

  log(L_LOG_DEBUG, CLIENT, "display directive: %s", str);
 
  /* no argument, list all the display format */
  if ( argc == 0 )
  {
    print_response(RESP_DISPLAY, "name:%s", get_display() );
    print_response(RESP_DISPLAY, "length:%d", strlen(get_display()) );
    print_response(RESP_DISPLAY, 
        "description:display in %s format", get_display() );
    print_response(RESP_DISPLAY, "");
    
/*     print_ok(); */
    return TRUE;
  }
  else  /* argc = 1 */
  {
    if (STR_EQ(argv[0], "dump") )
    {
      /* FIXME: enable dump mode */
      set_display( argv[0] );

/*       print_ok(); */
      return TRUE;
    }
    else 
    {
      print_error(UNAUTH_DISPLAY, "");
      return FALSE;
    }
  }

/*   print_ok(); */
  return TRUE;
}
