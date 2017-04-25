/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "session.h"

#include "client_msgs.h"
#include "deadman.h"
#include "defines.h"
#include "directive.h"
#include "directive_conf.h"
#include "dl_list.h"
#include "dump.h"
#include "log.h"
#include "main_config.h"
#include "misc.h"
#include "parse.h"
#include "records.h"
#include "referral.h"
#include "search.h"
#include "security_directive.h"
#include "state.h"
#include "strutil.h"

#include "conf.h"

static int processline PROTO((char *str));
static int run_query PROTO((char *str));
 
/* ------------------- LOCAL FUNCTIONS -------------------- */


static int
processline(str)
  char *str;
{
  int                status = FALSE;
  rwhois_state_type  state  = get_rwhois_state();
  FILE              *fp     = NULL;

  if (!str || !*str)
  {
    return TRUE;
  }

  trim(str);

  if (is_directive(str))
  {
    status = run_directive(str);
    
    if (status == TRUE)
    {
      print_ok();
    }
    if (status == QUIT)
    {
      return FALSE;
    }
  }
  else
  {
    if (state == SPOOL_STATE)
    {
      fp = open_spool_file("w+");
      if (fp)
      {
        fprintf(fp, "%s", str);
        fprintf(fp, "\n");
      }
    }
    else
    {
      run_query(str);
      return(get_holdconnect());
    }
  } 

  return TRUE;
}


static int
run_query(str)
  char *str;
{
  query_struct      *query;
  dl_list_type      record_list;
  record_struct     *record;
  int               not_done;
  int               ret_code;
  int               num_hits;
  int               obj_found_flag = FALSE;
  
  query = xcalloc(1, sizeof(*query));
  
  dl_list_default(&record_list, FALSE, destroy_record_data);
  
  if (!str || !*str)
  {
    log(L_LOG_ERR, QUERY, "run_query: null data detected");
    print_error(INVALID_QUERY_SYNTAX, "");
    return FALSE;
  }

  log(L_LOG_INFO, CLIENT, "query: %s", str);
  if (!parse_query(str, query))
  {
    log(L_LOG_INFO, CLIENT, "invalid query syntax: %s", str);
    return FALSE;
  }

  if (!check_query_complexity(query))
  {
    destroy_query(query);
    return FALSE;
  }

  
  num_hits = search(query, &record_list, get_hit_limit(), &ret_code);
  log(L_LOG_INFO, CLIENT, "query response: %d hits", num_hits);

  /* display the object results */
  if (!dl_list_empty(&record_list))
  {
    obj_found_flag = TRUE;
    
    not_done = dl_list_first(&record_list);
    while (not_done)
    {
      record = dl_list_value(&record_list);
      display_dump_format(record);
      not_done = dl_list_next(&record_list);
    }

    dl_list_destroy(&record_list);
  }

  /* always check for referrals -- except when the query could have
     returned referral objects! Except of course, when the server is
     configured to not search for referrals */

  if (!get_skip_referral_search() &&
      (NOT_STR_EXISTS(query->auth_area_name) ||
      !STR_EQ(query->class_name, "Referral")))
  {
    if (refer_query(query))
    {
      obj_found_flag = TRUE;
    }
  }

  /* print the resulting error or ok terminator. */
  switch (ret_code)
  {
  case SEARCH_SUCCESSFUL:
    if (obj_found_flag)
    {
      print_ok();
    }
    else
    {
      print_error(NO_OBJECTS_FOUND, "");
    }
    break;
  case HIT_LIMIT_EXCEEDED:
    print_error(EXCEEDED_MAXOBJ, "");
    break;
  default:
    print_error(UNIDENT_ERROR, "");
    break;
  }   

  destroy_query(query);
  return TRUE;
}
 

/* ------------------- PUBLIC FUNCTIONS ------------------- */


/* run_session: runs a rwhois client session */
void
run_session(real_flag)
  int real_flag;
{
  char target[MAX_LINE];
  int  not_finished    = TRUE;

  randomize(); /* in case we need to generate salts, or something */

  set_out_fp(stdout);

  print_welcome_header();

  /* set the input to line buffering, not block buffering */
#ifdef SETVBUF_REVERSED
  setvbuf(stdin, _IOLBF, (char *)NULL, 0);
#else
  setvbuf(stdin, (char *)NULL, _IOLBF, 0);
#endif

  /* unbuffer the output */
#ifdef SETVBUF_REVERSED
  setvbuf(stdout, _IONBF, (char *)NULL, 0);
#else
  setvbuf(stdout, (char *)NULL, _IONBF, 0);
#endif

  if (!real_flag)
  {
    print_error(SERVICE_NOT_AVAIL, "exceeded max client sessions");

    return;
  }
  
  do
  {
    set_timer(get_deadman_time(), is_a_deadman);

    /* this is kind of a hack, but, hey, it works */
    clear_printed_error_flag();
    
    if (readline(stdin, target, MAX_LINE) == NULL)
    {
      not_finished = FALSE;
    }
    else
    {
      unset_timer();
      not_finished = processline(target);
    }    
  } while (not_finished);
}


/* print_welcome_header: prints the standard rwhois banner greeting */
void
print_welcome_header()
{
  char             *hostname;
  dl_list_type     *dir_list;
  directive_struct *dir;
  int              not_done;
  long             capid      = 0x00;


  hostname = get_local_hostname();
  
  dir_list = get_directive_list();

  not_done = dl_list_first(dir_list);
  while (not_done)
  {
    dir = dl_list_value(dir_list);
    if (!(dir->disabled_flag))
    {
      if (dir->cap_bit > 0) 
      {
        capid = capid | dir->cap_bit;
      }
    }
    not_done = dl_list_next(dir_list);
  }

  print_response(RESP_RWHOIS, 
                 "V-%s:%6.6x:00 %s (by Network Solutions, Inc. V-%s)",
                 RWHOIS_PROTOCOL_VERSION, capid, hostname,
                 RWHOIS_SERVER_VERSION);

  fflush(stdout);
}
