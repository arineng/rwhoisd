#include "sstate.h"

#include "auth_area.h"
#include "daemon.h"
#include "deadman.h"
#include "defines.h"
#include "log.h"
#include "misc.h"

static dl_list_type slave_state_list;
static int          childpid;
static int          childstatus;

static int
destroy_slave_state_data PROTO((slave_state_struct *slave_state));

static void sigalrm_handler();

static void sigchld_handler();


/* ------------------- LOCAL FUNCTIONS -------------------- */


/* destroy_slave_state_data: This function frees a slave state
   structure */
static int
destroy_slave_state_data(slave_state)
  slave_state_struct *slave_state;
{
  if (!slave_state)
  {
    return(TRUE);
  }
 
  if (slave_state->name)
  {
    free(slave_state->name);
  }
 
  free(slave_state);
 
  return(TRUE);
}


/* sigalrm_handler: This function handles SIGALRM signal */
static void
sigalrm_handler(signo)
  int signo;
{
  return;
}


/* sigchld_handler: This function handles SIGCHLD signal */
static void
sigchld_handler(signo)
  int signo;
{
  childpid = wait(&childstatus);

  return;
}


/* ------------------- PUBLIC FUNCTIONS ------------------- */


/* set_slave_state: This function sets slave authority area state */
int
set_slave_state(name, pid, action, status)
  char *name;
  int  pid;
  int  action;
  int  status;
{
  slave_state_struct *slave_state;
  int                not_done;
 
  not_done = dl_list_first(&slave_state_list);
  while (not_done)
  {
    slave_state = dl_list_value(&slave_state_list);
 
    if (STR_EQ(slave_state->name, name))
    {
      slave_state->pid    = pid;
      slave_state->action = (action_type) action;
      slave_state->status = (status_type) status;
      return(TRUE);
    }
 
    not_done = dl_list_next(&slave_state_list);
  }
 
  return(FALSE);
}


/* get_slave_state: This function gets slave authority area state */
slave_state_struct *
get_slave_state(name)
  char *name;
{
  slave_state_struct *slave_state;
  int                not_done;
 
  not_done = dl_list_first(&slave_state_list);
  while (not_done)
  {
    slave_state = dl_list_value(&slave_state_list);
 
    if (STR_EQ(slave_state->name, name))
    {
      return(slave_state);
    }
 
    not_done = dl_list_next(&slave_state_list);
  }
 
  return(NULL);
}


/* init_slave_state_list: This function initializes slave
   authority area state list */
void
init_slave_state_list(slave_aa_list)
  dl_list_type *slave_aa_list;
{
  auth_area_struct   *aa;
  slave_state_struct *slave_state;
  int                not_done;
 
  if (dl_list_empty(slave_aa_list))
  {
    return;
  }
 
  dl_list_default(&slave_state_list, FALSE, destroy_slave_state_data);
 
  not_done = dl_list_first(slave_aa_list);
  while (not_done)
  {
    aa = dl_list_value(slave_aa_list);
 
    slave_state         = xcalloc(1, sizeof(*slave_state));
    slave_state->name   = NEW_STRING(aa->name);
    dl_list_append(&slave_state_list, slave_state);
 
    not_done = dl_list_next(slave_aa_list);
  }
}


/* wait_for_child_processes: This function waits for child processes for
   slave authority areas */
void
wait_for_child_processes(count, seconds, action)
  int count;
  int seconds;
  int action;
{
  slave_state_struct *slave_state;
  int                not_done;

  for (; count > 0; count--)
  {
    /* Wait for a child process */
    signal(SIGCHLD, sigchld_handler);
    set_timer(seconds, sigalrm_handler);
    pause();
    unset_timer();

    /* Record status if wait returned gracefully */
    if (childpid > 0)
    {
      childstatus = (childstatus >> 8) & 255;

      not_done = dl_list_first(&slave_state_list);
      while (not_done)
      {
        slave_state = dl_list_value(&slave_state_list);

        /* Find slave state structure corresponding to pid of
           the exited child process and record its exit status */
        if (slave_state->pid == childpid)
        {
          if (childstatus == 0)
          {
            slave_state->status = STATUS_OK;
          }
          else
          {
            slave_state->status = STATUS_ERROR;
          }
        }
 
        not_done = dl_list_next(&slave_state_list);
      }
    }
  }

  /* Record status if wait timed out */
  not_done = dl_list_first(&slave_state_list);
  while (not_done)
  {
    slave_state = dl_list_value(&slave_state_list);

    if (slave_state->action == action &&
        slave_state->status == STATUS_WAIT)
    {
      slave_state->status = STATUS_ERROR;
      log(L_LOG_ERR, SECONDARY,
          "wait_for_child_processes: time out for authority area '%s'",
          slave_state->name);
    }

    not_done = dl_list_next(&slave_state_list);
  }

  no_zombies();
}
