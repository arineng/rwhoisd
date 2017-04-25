/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "rwhois_directive.h"

#include "client_msgs.h"
#include "defines.h"
#include "dl_list.h"
#include "log.h"
#include "misc.h"
#include "session.h"
#include "state.h"
#include "strutil.h"
#include "types.h"

#include "conf.h"

typedef struct _client_cap_struct
{
  char *version_str;
  char *impl_str;
} client_cap_struct;

/* ------------------- Local Functions -------------------------*/

/* rwhois_parse_args:  this function parses the input argument 
   string and stores the arguments in rwhois_arg. */

static client_cap_struct *
rwhois_parse_args(str)
  char *str;
{
  int               argc;
  char              **argv;
  char              version[24]; /* FIXME: magic number */
  char              *p;
  client_cap_struct *cap;
  
  split_arg_list(str, &argc, &argv);

  if (argc < 1)
  {
    print_error(INVALID_DIRECTIVE_PARAM, "");
    free_arg_list(argv);
    return NULL;
  }

  cap = xcalloc(1, sizeof(*cap));
  
  sprintf(version, "V-%s", RWHOIS_PROTOCOL_VERSION);

  /* compare the requested version with our version */
  if (!STR_EQ(argv[0], version))
  {
    print_error(UNCOMPAT_VERSION, "");
    log(L_LOG_NOTICE, CLIENT,
        "rwhois_directive: incompatible version identifier: %s", argv[0]);
    free_arg_list(argv);
    return NULL;
  }

  cap->version_str = xstrdup(argv[0]);
  
  /* the rest of the arguments are the implementation string */
  if (argc > 1)
  {
    p = str + strlen(argv[0]);

    cap->impl_str = xstrdup(trim(p));
  }
 
  free_arg_list(argv);
  
  return(cap);
}  /* end of rwhois_parse_args. */

static void
destroy_client_cap_struct(cap)
  client_cap_struct *cap;
{
  if (!cap) return;

  if (cap->version_str) free(cap->version_str);

  if (cap->impl_str)  free(cap->impl_str);

  free(cap);
}

/* ------------------- Public Functions ------------------- */
 
 
/* soa_directive:  This is the main directive function which processes the
     -soa directive.  */


int rwhois_directive(str)
  char *str;
{
  client_cap_struct *cap;

  if (NOT_STR_EXISTS(str))
  {
    print_error(INVALID_DIRECTIVE_PARAM, "");
    return FALSE;
  }

  log(L_LOG_DEBUG, CLIENT, "rwhois directive: %s", str);

  cap = rwhois_parse_args(str);

  if (!cap)
  {
    return FALSE;
  }

  if (STR_EXISTS(cap->impl_str))
  {
    set_client_vendor_id(cap->impl_str);
  }
  
  print_welcome_header();
  
  destroy_client_cap_struct(cap);
  
  return TRUE;
}
