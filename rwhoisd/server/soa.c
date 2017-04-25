/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "soa.h"

#include "attributes.h"
#include "auth_area.h"
#include "client_msgs.h"
#include "defines.h"
#include "dl_list.h"
#include "misc.h"
#include "types.h"


/* ------------------- Local Functions -------------------- */


/* soa_parse_args: this function parses the input argument string 
   and stores the arguments in soa_arg_struct. */
static dl_list_type * 
soa_parse_args(str)
    char *str;
{
  int              argc;
  char             **argv;
  dl_list_type     *soa_arg;
  auth_area_struct *auth_area;
  int              i;

  split_arg_list(str, &argc, &argv);

  if (argc < 1)
  {
    print_error(INVALID_DIRECTIVE_PARAM, "");
    free_arg_list(argv);
    return NULL;
  }

  soa_arg = xcalloc(1, sizeof(*soa_arg));
  dl_list_default(soa_arg, TRUE, null_destroy_data);
  
  for (i = 0; i < argc; i++)
  {
    auth_area = find_auth_area_by_name(argv[i]);
    if (!auth_area)
    {
      print_error(INVALID_AUTH_AREA, "");
      free_arg_list(argv);
      dl_list_destroy(soa_arg);
      return NULL;
    }
    
    dl_list_insert(soa_arg, auth_area);
  }

  free_arg_list(argv);
  
  return(soa_arg);
}  /* end of soa_parse_args. */


/* soa_display_autharea: Function to display the auth_area information. */
static int 
soa_display_auth_area(aa)
  auth_area_struct *aa;
{
  if (!aa)
  {
    return FALSE;
  }

  if (!aa->serial_no || !*aa->serial_no) 
  {
    return FALSE;
  }

  print_response(RESP_SOA, "authority:%s", SAFE_STR_NONE(aa->name));
  print_response(RESP_SOA, "ttl:%ld", aa->time_to_live);
  print_response(RESP_SOA, "serial:%s", aa->serial_no);
  print_response(RESP_SOA, "refresh:%ld", aa->refresh_interval);
  print_response(RESP_SOA, "increment:%ld", aa->increment_interval);
  print_response(RESP_SOA, "retry:%ld", aa->retry_interval);
  print_response(RESP_SOA, "hostmaster:%s", SAFE_STR_NONE(aa->hostmaster));
  print_response(RESP_SOA, "primary:%s", 
                 SAFE_STR_NONE(aa->primary_server));
  print_response(RESP_SOA, "");
  
  return TRUE;
} /* end of soa_display_autharea */



/* soa_display_auth_areas displays the auth-area info for the list of
     authority areas. */
static void 
soa_display_auth_areas(auth_area_list)
  dl_list_type  *auth_area_list;
{
  int           not_done;

  not_done = dl_list_first(auth_area_list);
  while (not_done)
  {
    soa_display_auth_area(dl_list_value(auth_area_list));

    not_done = dl_list_next(auth_area_list);
  }
}



/* update_soa_auth_area: update soa for one auth_area */
static int 
update_soa_auth_area(aa)
  auth_area_struct *aa;
{
  if (!aa)
  {
    return FALSE;
  }

  destroy_soa_in_auth_area(aa);

  /* now actually read the SOA data */
  if (!read_soa_file(aa))
  {
      return FALSE;
  }
 
  return TRUE;
} 


/* update_soa_auth_area_list: update soa record for the list of 
 *  authority areas. 
 */
static void 
update_soa_auth_area_list(auth_area_list)
  dl_list_type  *auth_area_list;
{
  int           not_done;

  not_done = dl_list_first(auth_area_list);
  while (not_done)
  {
    update_soa_auth_area(dl_list_value(auth_area_list));

    not_done = dl_list_next(auth_area_list);
  }
}

  
/* ------------------- Public Functions ------------------- */


/* soa_directive:  This is the main directive function which processes the
     -soa directive.  */
int soa_directive(str)
    char *str;
{
  dl_list_type     *aa_list      = NULL;

  if (!str || !*str)
  {
    /* re-read the soa file first. 'cause -register may change the soa record
     */
    update_soa_auth_area_list(get_auth_area_list());

    soa_display_auth_areas(get_auth_area_list());

    /* print_ok(); */

    return TRUE;
  }

  aa_list = soa_parse_args(str);

  if (!aa_list || dl_list_empty(aa_list)) 
  {
    return FALSE;
  }

  update_soa_auth_area_list(aa_list);

  soa_display_auth_areas(aa_list);

  /* print_ok(); */

  dl_list_destroy(aa_list);
  
  return TRUE;
} /* end of soa_directive */
