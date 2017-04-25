/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "status.h"
#include "client_msgs.h"

#include "auth_area.c"
#include "defines.h"
#include "display.h"
#include "fileinfo.h"
#include "misc.h"
#include "main_config.h"
#include "fileinfo.h"
#include "mkdb_types.h"


/****************************************************************************
  return number of records
****************************************************************************/
static long
get_rec_num()
{
  dl_list_type     *aa_list;
  auth_area_struct *auth_area;
  int              not_done;
  long             num_recs    = 0;

  aa_list = get_auth_area_list();

  if (dl_list_empty(aa_list))
  {
    return 0;
  }
 
  not_done = dl_list_first(aa_list);
  while (not_done)
  {
    auth_area = dl_list_value(aa_list); 
    num_recs += records_in_auth_area(auth_area);

    not_done = dl_list_next(aa_list);
  }
 
  return(num_recs);
}


/* status_directive: poll all the server for its status.
 * Input:   -status
 * Response:    %status limit: <current limit>
 *      %status load:  <load>
 *      %status cache: <cache>
 *      %status holdconnect: <holdconnect>
 *      %status forward:  <forward>
 *      %status Authority:  <SOA number>
 *      %status Cached:  <cacheed number>
 *      %status Display:  <mode>: <type>
 */     
int
status_directive ( str )
  char  *str;
{
   
  /* -status don't have any argument */
  if (STR_EXISTS(str))
  {
    print_error(INVALID_DIRECTIVE_PARAM,"");
    return FALSE;
  }

  print_response(RESP_STATUS, "limit:%d", get_hit_limit());
  print_response(RESP_STATUS, "holdconnect:%s", on_off(get_holdconnect()));
  print_response(RESP_STATUS, "forward:%s", on_off(get_forward()));
  print_response(RESP_STATUS, "objects:%ld", get_rec_num());
  print_response(RESP_STATUS, "display:%s", get_display());
  print_response(RESP_STATUS, "contact:%s", get_server_contact());
  
  return TRUE;
}
