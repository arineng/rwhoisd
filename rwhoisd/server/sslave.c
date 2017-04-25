#include "sslave.h"

#include "auth_area.h"
#include "deadman.h"
#include "defines.h"
#include "fileutils.h"
#include "log.h"
#include "misc.h"
#include "schema.h"
#include "sschema.h"
#include "ssoa.h"
#include "sstate.h"
#include "sxfer.h"


/* ------------------- PUBLIC FUNCTIONS ------------------- */


/* init_slave_auth_areas: This function initially creates
   SOA file, schema file, attribute definitions directory,
   and data directory for each slave authority area */
int
init_slave_auth_areas()
{
  dl_list_type       *aa_list;
  dl_list_type       slave_aa_list;
  auth_area_struct   *aa;
  server_struct      *server;
  slave_state_struct *slave_state;
  int                not_done;
  int                childpid;
  int                count;

  /* Set initial time */
  set_initial_time();

  /* Get slave authority areas */
  aa_list = get_auth_area_list();
  if (dl_list_empty(aa_list))
  {
    return(FALSE);
  }
 
  dl_list_default(&slave_aa_list, FALSE, null_destroy_data);
 
  not_done = dl_list_first(aa_list);
  while (not_done)
  {
    aa = dl_list_value(aa_list);
    if (aa->type == AUTH_AREA_SECONDARY)
    {
      dl_list_append(&slave_aa_list, aa);
    }
 
    not_done = dl_list_next(aa_list);
  }
 
  if (dl_list_empty(&slave_aa_list))
  {
    return(TRUE);
  }

  /* Initialize slave authority area state list */
  init_slave_state_list(&slave_aa_list);

  /* Create SOA files */
  count = 0;
  not_done = dl_list_first(&slave_aa_list);
  while (not_done)
  {
    aa = dl_list_value(&slave_aa_list);

    if ((childpid = fork()) < 0)
    {
      log(L_LOG_ERR, SECONDARY,
          "init_slave_auth_areas: fork error: %s", strerror(errno));
      exit(1);
    }
    else if (childpid == 0)
    {
      /* Child process */
      signal(SIGCHLD, SIG_DFL);

      if (dl_list_empty(aa->master))
      {
        exit(1);
      }
      dl_list_first(aa->master);
      server = dl_list_value(aa->master);

      if (!create_soa_file(aa, server))
      {
        exit(1);
      }

      exit(0);
    }
    else
    {
      /* Parent process */
      set_slave_state(aa->name, childpid, ACTION_SOA, STATUS_WAIT);
      count++;
    }

    not_done = dl_list_next(&slave_aa_list);
  }

  /* Wait for each child process */
  wait_for_child_processes(count, get_deadman_time(), ACTION_SOA);

  /* Read SOA files */
  not_done = dl_list_first(&slave_aa_list);
  while (not_done)
  {
    aa = dl_list_value(&slave_aa_list);

    /* Check slave authority area state */
    slave_state = get_slave_state(aa->name);
    if (slave_state->status != STATUS_OK)
    {
      not_done = dl_list_next(&slave_aa_list);
      continue;
    }

    if (!read_soa_file(aa))
    {
      return(FALSE);
    }
 
    not_done = dl_list_next(&slave_aa_list);
  }

  /* Create schema files */
  count = 0;
  not_done = dl_list_first(&slave_aa_list);
  while (not_done)
  {
    aa = dl_list_value(&slave_aa_list);

    /* Check slave authority area state */
    slave_state = get_slave_state(aa->name);
    if (slave_state->status != STATUS_OK)
    {
      not_done = dl_list_next(&slave_aa_list);
      continue;
    }

    if ((childpid = fork()) < 0)
    {
      log(L_LOG_ERR, SECONDARY,
          "init_slave_auth_areas: fork error: %s", strerror(errno));
      exit(1);
    }
    else if (childpid == 0)
    {
      /* Child process */
      signal(SIGCHLD, SIG_DFL);

      if (dl_list_empty(aa->master))
      {
        exit(1);
      }
      dl_list_first(aa->master);
      server = dl_list_value(aa->master);

      if (!create_schema_file(aa, server))
      {
        exit(1);
      }
 
      exit(0);
    }
    else
    {
      /* Parent process */
      set_slave_state(aa->name, childpid, ACTION_SCHEMA, STATUS_WAIT);
      count++;
    }

    not_done = dl_list_next(&slave_aa_list);
  }

  /* Wait for each child process */
  wait_for_child_processes(count, get_deadman_time(), ACTION_SCHEMA);

  /* Read schema files */
  not_done = dl_list_first(&slave_aa_list);
  while (not_done)
  {
    aa = dl_list_value(&slave_aa_list);

    /* Check slave authority area state */
    slave_state = get_slave_state(aa->name);
    if (slave_state->status != STATUS_OK)
    {
      not_done = dl_list_next(&slave_aa_list);
      continue;
    }

    aa->schema = xcalloc(1, sizeof(*(aa->schema)));
 
    if (!read_schema(aa))
    {
      return(FALSE);
    }

    not_done = dl_list_next(&slave_aa_list);
  }

  /* Create data files */
  not_done = dl_list_first(&slave_aa_list);
  while (not_done)
  {
    aa = dl_list_value(&slave_aa_list);

    /* Check slave authority area state */
    slave_state = get_slave_state(aa->name);
    if (slave_state->status != STATUS_OK)
    {
      not_done = dl_list_next(&slave_aa_list);
      continue;
    }

    if ((childpid = fork()) < 0)
    {
      log(L_LOG_ERR, SECONDARY,
          "init_slave_auth_areas: fork error: %s", strerror(errno));
      exit(1);
    }
    else if (childpid == 0)
    {
      /* Child process */
      signal(SIGCHLD, SIG_DFL);
 
      if (dl_list_empty(aa->master))
      {
        exit(1);
      }
      dl_list_first(aa->master);
      server = dl_list_value(aa->master);
 
      if (!create_data_files(aa, server, TRUE))
      {
        exit(1);
      }
 
      exit(0);
    }
    else
    {
      /* Parent process */
      set_slave_state(aa->name, childpid, ACTION_XFER, STATUS_WAIT);
    }
 
    not_done = dl_list_next(&slave_aa_list);
  }

  /* Set new xfer times */
  not_done = dl_list_first(&slave_aa_list);
  while (not_done)
  {
    aa = dl_list_value(&slave_aa_list);
 
    /* If error, increment xfer time by retry interval.
       Else, increment xfer time by refresh interval */
    slave_state = get_slave_state(aa->name);
    if (slave_state->status == STATUS_ERROR)
    {
      aa->xfer_time = get_time_elapsed() + aa->retry_interval;
    }
    else
    {
      aa->xfer_time = get_time_elapsed() + aa->refresh_interval;
    }
 
    not_done = dl_list_next(&slave_aa_list);
  }

  dl_list_destroy(&slave_aa_list);

  /* Set poll time */
  set_timer(3600, update_slave_auth_areas);

  return(TRUE);
}


/* update_slave_auth_areas: This function updates data for a
   slave authority area if serial number has been incremented
   at the master server */
int
update_slave_auth_areas()
{
  dl_list_type       *aa_list;
  dl_list_type       slave_aa_list;
  auth_area_struct   *aa;
  server_struct      *server;
  slave_state_struct *slave_state;
  long               current_time;
  int                not_done;
  int                childpid;
  int                count;
  char               *old_serial_no;

  /* Get current time */
  current_time = get_time_elapsed();

  /* Get slave authority areas with xfer time <= current time */
  aa_list = get_auth_area_list();
  if (dl_list_empty(aa_list))
  {
    return(FALSE);
  }
 
  dl_list_default(&slave_aa_list, FALSE, null_destroy_data);
 
  not_done = dl_list_first(aa_list);
  while (not_done)
  {
    aa = dl_list_value(aa_list);
    if (aa->type == AUTH_AREA_SECONDARY)
    {
      if (aa->xfer_time <= current_time)
      {
        dl_list_append(&slave_aa_list, aa);
      }
    }
 
    not_done = dl_list_next(aa_list);
  }
 
  if (dl_list_empty(&slave_aa_list))
  {
    set_timer(3600, update_slave_auth_areas);
    return(TRUE);
  }

  /* Create SOA files */
  count = 0;
  not_done = dl_list_first(&slave_aa_list);
  while (not_done)
  {
    aa = dl_list_value(&slave_aa_list);

    /* Do not interrupt an ongoing xfer */
    slave_state = get_slave_state(aa->name);
    if (slave_state->action == ACTION_XFER &&
        dot_lock_exists(aa->name))
    {
      not_done = dl_list_next(&slave_aa_list);
      continue;
    }

    if ((childpid = fork()) < 0)
    {
      log(L_LOG_ERR, SECONDARY,
          "update_slave_auth_areas: fork error: %s", strerror(errno));
      exit(1);
    }
    else if (childpid == 0)
    {
      /* Child process */
      signal(SIGCHLD, SIG_DFL);

      if (dl_list_empty(aa->master))
      {
        exit(1);
      }
      dl_list_first(aa->master);
      server = dl_list_value(aa->master);

      if (!create_soa_file(aa, server))
      {
        exit(1);
      }

      exit(0);
    }
    else
    {
      /* Parent process */
      set_slave_state(aa->name, childpid, ACTION_SOA, STATUS_WAIT);
      count++;
    }

    not_done = dl_list_next(&slave_aa_list);
  }

  /* Wait for each child process */
  wait_for_child_processes(count, get_deadman_time(), ACTION_SOA);

  not_done = dl_list_first(&slave_aa_list);
  while (not_done)
  {
    aa = dl_list_value(&slave_aa_list);

    /* Do not interrupt an ongoing xfer */
    slave_state = get_slave_state(aa->name);
    if (slave_state->action == ACTION_XFER &&
        dot_lock_exists(aa->name))
    {
      not_done = dl_list_next(&slave_aa_list);
      continue;
    }

    /* Check slave authority area state */
    if (slave_state->status != STATUS_OK)
    {
      not_done = dl_list_next(&slave_aa_list);
      continue;
    }

    /* Save old serial no */
    old_serial_no = NEW_STRING(aa->serial_no);

    /* Read SOA file */
    if (!read_soa_file(aa))
    {
      return(FALSE);
    }

    /* Create data files if serial no > old serial no */
    if (strcmp(aa->serial_no, old_serial_no) > 0)
    {
      if ((childpid = fork()) < 0)
      {
        log(L_LOG_ERR, SECONDARY,
            "update_slave_auth_areas: fork error: %s", strerror(errno));
        exit(1);
      }
      else if (childpid == 0)
      {
        /* Child process */
        signal(SIGCHLD, SIG_DFL);
 
        if (dl_list_empty(aa->master))
        {
          exit(1);
        }
        dl_list_first(aa->master);
        server = dl_list_value(aa->master);
 
        if (!create_data_files(aa, server, FALSE))
        {
          exit(1);
        }
 
        exit(0);
      }
      else
      {
        /* Parent process */
        set_slave_state(aa->name, childpid, ACTION_XFER, STATUS_WAIT);
      }
    }

    not_done = dl_list_next(&slave_aa_list);
  }

  /* Set new xfer times */
  not_done = dl_list_first(&slave_aa_list);
  while (not_done)
  {
    aa = dl_list_value(&slave_aa_list);
 
    /* If error, increment xfer time by retry interval.
       Else, increment xfer time by refresh interval */
    slave_state = get_slave_state(aa->name);
    if (slave_state->status == STATUS_ERROR)
    {
      aa->xfer_time = get_time_elapsed() + aa->retry_interval;
    }
    else
    {
      aa->xfer_time = get_time_elapsed() + aa->refresh_interval;
    }

    not_done = dl_list_next(&slave_aa_list);
  }

  dl_list_destroy(&slave_aa_list);

  /* Set poll time */
  set_timer(3600, update_slave_auth_areas);

  return(TRUE);
}
