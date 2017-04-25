/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "directive.h"

#include "client_msgs.h"
#include "defines.h"
#include "directive_conf.h"
#include "dl_list.h"
#include "log.h"
#include "misc.h"
#include "procutils.h"
#include "security.h"
#include "strutil.h"

/** these are included for function names **/
#include "class_directive.h"
#include "display.h"
#include "exit.h"
#include "forward.h"
#include "holdconnect.h"
#include "limit.h"
#include "security_directive.h"
#include "notify.h"
#include "register_directive.h"
#include "rwhois_directive.h"
#include "schema_directive.h"
#include "soa.h"
#include "status.h"
#include "xfer.h"

/* --------------------- Local Functions ------------------ */

static int
add_directive_func(name, func)
  char *name;
  int  (*func)();
{
  directive_struct  *item;

  if (!name || !*name)
  {
    return FALSE;
  }

  item = find_directive(name);
  if (!item)
  {
    return FALSE;
  }

  item->function = func;

  return TRUE;
}

/* --------------------- Public Functions ----------------- */

/* initializes the native commands */
void
init_directive_functions()
{
  add_directive_func("class", class_directive);
  add_directive_func("directive", directive_directive);
  add_directive_func("display", display_directive);
  add_directive_func("forward", forward_directive);
  add_directive_func("holdconnect", holdconnect_directive);
  add_directive_func("limit", limit_directive);
  add_directive_func("security", security_directive);
  add_directive_func("notify", notify_directive); 
  add_directive_func("quit", quit_directive);
  add_directive_func("register", register_directive);
  add_directive_func("rwhois", rwhois_directive);
  add_directive_func("schema", schema_directive);
  add_directive_func("soa", soa_directive);
  add_directive_func("status", status_directive);
  add_directive_func("xfer", xfer_directive);

}

/* is_directive: returns TRUE if is directive command, FALSE otherwise */
int
is_directive(str)
  char *str;
{
  if (!str || !*str)
  {
    return FALSE;
  }

  if (*str == '-' && isalpha(*(str + 1)))
  {
    return TRUE;
  }
 
  return FALSE;
}

/* run directive: given a query string that is a directive, decode the
      directive and run it */
int
run_directive(query_str)
  char  *query_str;
{
  directive_struct  *di;
  char              *directive;
  char              *value;

  if (!query_str[0] == '-')
  {
    return FALSE;
  }
  
  directive = query_str + 1;

  /* skip over the directive itself */
  value = directive;
  while (!isspace(*value) && (*value != '\0')) value++;

  /* terminate the directive */
  *value++ = '\0';
  
  value  = skip_whitespace(value);
  
  if ( (di = find_directive(directive)) == NULL )
  {
    log(L_LOG_DEBUG, CLIENT, "invalid directive: %s", directive);
    print_error(INVALID_DIRECTIVE, "");
    return FALSE;
  }
  else
  {
    if (di->disabled_flag)
    {
      log(L_LOG_DEBUG, CLIENT, "disabled directive: %s", directive);
      print_error(INVALID_DIRECTIVE,"");
      return FALSE;
    }
  }

  if (!di->function && !di->program)
  {
    log(L_LOG_WARNING, CLIENT, "directive has no program or function: %s",
        directive);
    print_error(INVALID_DIRECTIVE, "");
    return FALSE;
  }

#ifdef USE_TCP_WRAPPERS
  if (!authorized_directive(directive))
  {
    log(L_LOG_DEBUG, CLIENT, "rejected directive: %s", directive);
    print_error(UNAUTH_DIRECTIVE, "");
    
    return FALSE;
  }
#endif /* USE_TCP_WRAPPERS */

  if (di->function)
  {
    return(di->function(value));
  }

  log(L_LOG_DEBUG, CLIENT, "X-directive: X-%s %s", directive, value);
  if (run_program(di->program, value) != 0)
  {
    /* returning 0 means that the program worked, or, more to the
       point, that it wants us to print "%ok" */
    return FALSE;
  }

  return TRUE;
}


/* directive_directive: display directives allowed on the server.
   Input:   -directive [directive name]
   Response:    %directive directive:<name>
                %directive description:<description>
                %directive */
int
directive_directive( str)
  char *str;
{
  dl_list_type      *full_list;
  directive_struct  *dir_struct;
  int               not_done;
   int               argc;
  char              **argv;
 
  split_arg_list(str, &argc, &argv);
 
  if ( argc > 1 )
  {
    print_error(INVALID_DIRECTIVE_PARAM,"");
    return FALSE;
  }
 
  /* if we are asking about a specific directive, display it */
  if (argc == 1)
  {
    dir_struct = find_directive(argv[0]);
    print_response(RESP_DIRECTIVE, "directive:%s", dir_struct->name);
    print_response(RESP_DIRECTIVE, "description:%s",dir_struct->description);
    print_response(RESP_DIRECTIVE, "");

/*     print_ok(); */
    return TRUE;
  }
 
  /* argc == 0, display them all */

  full_list = get_directive_list();
 
  not_done = dl_list_first(full_list);
  while (not_done)
  {
    dir_struct = dl_list_value(full_list);
    print_response(RESP_DIRECTIVE, "directive:%s", dir_struct->name);
    print_response(RESP_DIRECTIVE, "description:%s",dir_struct->description);
    print_response(RESP_DIRECTIVE, "");

    not_done = dl_list_next(full_list);
  }
 
/*   print_ok(); */
  return TRUE;
}
