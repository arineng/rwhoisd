/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "deadman.h"

#include "client_msgs.h"
#include "conf.h"
#include "log.h"
#include "main_config.h"
#include "types.h"

static int  deadman_time = -1;
static long initial_time = -1;

/******************************************************************************
  sets the timer for seconds before calling function
******************************************************************************/
void
set_timer(seconds, function)
  int   seconds;
  void  *function;
{
  if (seconds)
  {
    signal(SIGALRM, function);
    alarm(seconds);
  }
  return;
}

/******************************************************************************
 notifies user that deadman time has come - logs it and bye!
******************************************************************************/
void
is_a_deadman()
{
  print_error (DEADMAN_TIME, "");
  log(L_LOG_INFO, CLIENT, "deadman time exceeded - terminating connection.");
  exit(0);
}

/******************************************************************************
 unsets the timer
******************************************************************************/
void
unset_timer()
{
  signal(SIGALRM, SIG_IGN);
}

/******************************************************************************
 sets seconds before exiting (read from config file)
******************************************************************************/
void
set_deadman_time(secs)
  char *secs;
{
  if (atoi (secs))
  {
    deadman_time = atoi(secs);
  }
}

/******************************************************************************
 recovers the deadman second timer
******************************************************************************/
int
get_deadman_time ()
{
  /* value is uninitialized -- pull default from config */
  if (deadman_time < 0)
  {
    deadman_time = get_default_deadman_time();
  }
  return (deadman_time);
}


void
set_initial_time()
{
  initial_time = time((time_t *) NULL);
}


long
get_time_elapsed()
{
  long current_time;
 
  current_time = time((time_t *) NULL);
 
  return(current_time - initial_time);
}
