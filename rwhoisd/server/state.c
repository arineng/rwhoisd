/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "state.h"

#include "defines.h"
#include "fileutils.h"
#include "log.h"
#include "types.h"


/* local types */
typedef struct _rwhois_state_struct
{
  rwhois_state_type     state;
  char                  spool_file_name[MAX_FILE];
  FILE                  *spool_fp;
  int                   secure_mode;
  char                  client_vendor_id[MAX_LINE];
  char                  register_email[MAX_LINE];
  register_action_type  register_action;
} rwhois_state_struct;

/* local statics */

static rwhois_state_struct  state_info;

int 
get_rwhois_secure_mode()
{
  return(state_info.secure_mode);
}

void
set_rwhois_secure_mode(int mode)
{
  state_info.secure_mode = mode;
}
        
rwhois_state_type
get_rwhois_state()
{
  return(state_info.state);
}

int
set_rwhois_state(s)
  rwhois_state_type s;
{
  state_info.state = s;

  return TRUE;
}

char *
get_rwhois_spool_file_name()
{
  return(state_info.spool_file_name);
}

int
set_rwhois_spool_file_name(file)
  char *file;
{
  strncpy(state_info.spool_file_name, file,
          sizeof(state_info.spool_file_name));

  return TRUE;
}

FILE *
open_spool_file(char *mode)
{
  FILE  *fp;
  
  if (state_info.spool_fp)
  {
    /* already open, do not open again */
    return(state_info.spool_fp);
  }

  fp = fopen(state_info.spool_file_name, mode);
  if (! fp)
  {
    log(L_LOG_ERR, UNKNOWN, "could not open spool file '%s': %s",
        state_info.spool_file_name,
        strerror(errno));
    return NULL;
  }

  state_info.spool_fp = fp;

  return(fp);
}

void
close_spool_file()
{
  if (state_info.spool_fp)
  {
    fclose(state_info.spool_fp);
    state_info.spool_fp = NULL;
  }
}

int
move_spool_file(new_file_name)
  char *new_file_name;
{
  if (! *(state_info.spool_file_name))
  {
    return FALSE;
  }

  if (! file_exists(state_info.spool_file_name))
  {
    return FALSE;
  }

  if (file_exists(new_file_name))
  {
    return FALSE;
  }

  if (state_info.spool_fp)
  {
    close_spool_file();
  }
  
  if (! link(state_info.spool_file_name, new_file_name))
  {
    log(L_LOG_ERR, UNKNOWN,
        "move_spool_file: failed to move: %s", strerror(errno));
    return FALSE;
  }
  
  unlink(state_info.spool_file_name);
  set_rwhois_spool_file_name(new_file_name);

  return TRUE;
}

int
remove_spool_file()
{
  if (! *(state_info.spool_file_name))
  {
    return FALSE;
  }

  if (! file_exists(state_info.spool_file_name))
  {
    return FALSE;
  }

  if (state_info.spool_fp)
  {
    close_spool_file();
  }

  unlink(state_info.spool_file_name);

  bzero(state_info.spool_file_name, sizeof(state_info.spool_file_name));

  return TRUE;
}

char *
get_client_vendor_id()
{
  return(state_info.client_vendor_id);
}

void
set_client_vendor_id(id)
  char *id;
{
  strncpy(state_info.client_vendor_id, id,
          sizeof(state_info.client_vendor_id));
}

char *
get_register_email()
{
  return(state_info.register_email);
}

void
set_register_email(email)
  char *email;
{
  strncpy(state_info.register_email, email, sizeof(state_info.register_email));
}

register_action_type
get_register_action()
{
  return(state_info.register_action);
}

void
set_register_action(action)
  register_action_type action;
{
  state_info.register_action = action;
}
