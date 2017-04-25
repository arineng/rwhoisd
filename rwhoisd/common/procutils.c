/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "procutils.h"

#include "defines.h"
#include "log.h"
#include "misc.h"
#include "main_config.h"
#include "types.h"

#define MAX_ENV_SET     20
#define MAX_PATH_LEN    1024
#define PATH_STR        "PATH"

int
initialize_environment_list(envptr, env_size)
  char  ***envptr;
  int   env_size;
{
  char  **env;

  env = xcalloc(env_size + 1, sizeof(char *));

  *envptr = env;

  return TRUE;
}

int
add_env_value(env, env_size, var, value)
  char  **env;
  int   env_size;
  char  *var;
  char  *value;
{
  int   i;
  char  buf[MAX_LINE];
  int   var_len;

  if (!var || !value || !*var || !*value)
  {
    return FALSE;
  }

  var_len   = strlen(var);
  
  /* scan to end of the env list */
  for (i = 0; env[i] != NULL && i < env_size; i++);

  if (i >= env_size)
  {
    return FALSE;
  }
  
  strncpy(buf, var, sizeof(buf));
  strncat(buf, "=", sizeof(buf) - var_len);
  strncat(buf, value, sizeof(buf) - var_len - 1);

  env[i] = xstrdup(buf);
  
  return TRUE;
}


void
free_environment_list(env)
  char  **env;
{
  int   i = 0;
  
  while (env[i] != NULL)
  {
    free(env[i++]);
  }

  free(env);
}

/* run_program: runs the program 'program', using parameters 'param'.
   It also passes on the environment. */
int
run_program(program, param)
  char *program;
  char *param;
{
  extern char   **environ;
  char          **myenv;
  char          **argv;
  int           argc;
  char          buf[MAX_LINE];
  int           i;
  int           pid;
  int           wait_ret;
  int           proc_stat;

  /* set the SIGCHLD back it the default */
  signal(SIGCHLD, SIG_DFL);
  /* mask off the SIGQUIT signal */
  signal(SIGQUIT, SIG_IGN);

  /* enviroment stuff */
  initialize_environment_list(&myenv, MAX_ENV_SET);
  
  for (i = 0; environ[i] != NULL && i < MAX_ENV_SET; i++)
  {
    myenv[i] = xstrdup(environ[i]);
  }
  myenv[i] = NULL;

  strcpy(buf, program);
  strcat(buf, " ");
  strcat(buf, param);

  /* split_arg_list should leave argv NULL terminated */
  split_arg_list(buf, &argc, &argv);
  
  pid = fork();

  if ( pid == -1 )
  {
    /* Fork failed. */
    if (errno == ENOMEM)
    {
      log(L_LOG_ALERT, UNKNOWN, "fork failed: memory allocation problem");
    }
    else
    {
      log(L_LOG_ALERT, UNKNOWN, "fork failed: %s", strerror(errno));
    }
  }
  else if (pid == 0)
  {
    /* Child. */
    execve(argv[0], argv, myenv);
    /* try it again with the bin-path */
    {
      char  path[MAX_LINE];

      sprintf(path, "%s/%s", get_bin_path(), argv[0]);
      execve(path, argv, myenv);
      log(L_LOG_ERR, UNKNOWN, "exec of '%s' failed: %s", path,
          strerror(errno));
    }

    exit(-1);
  }
  else
  {
    /* Parent. */

    /* free the environment space */
    free_environment_list(myenv);

    free_arg_list(argv);

    /* wait for the program to return */
    while ( (wait_ret = wait(&proc_stat)) != pid  && wait_ret != -1);

    if (wait_ret == -1)
    {
      log(L_LOG_ERR, UNKNOWN, "wait failed: %s", strerror(errno));
      return(-1);
    }

    if (!WIFEXITED(proc_stat))
    {
      return(-1);
    }

    return(WEXITSTATUS(proc_stat));
  }

  return(-1);
}

/* run_env_program: like "run_program", but explicitly sets additional
   environment variables; also, it will take the arguments in argv,
   argc format. */
int
run_env_program(argv, envargv)
  char  **argv;
  char  **envargv;
{
  char          **myenv;
  extern char   **environ;
  int           i;
  int           j;
  int           pid;
  int           wait_ret;
  int           proc_stat;

  /* set the SIGCHLD back it the default */
  signal(SIGCHLD, SIG_DFL);
  /* mask off the SIGQUIT signal */
  signal(SIGQUIT, SIG_IGN);

  initialize_environment_list(&myenv, MAX_ENV_SET);
  
  /* copy the supplied environment into the enviro set */
  for (i = 0 ; i < (MAX_ENV_SET - 2) && envargv[i] != NULL; i++)
  {
    myenv[i] = xstrdup(envargv[i]);
  }

  /* copy the current environment into the environment set

     NOTE: we may only want to do this for selected environment
     values, or not at all */
  for (j = 0; (environ[j] != NULL) && (i < MAX_ENV_SET - 2); j++)
  {
    myenv[i++] = xstrdup(environ[j]);
  }
  
  /* do the fork thing */
  pid = fork();
  
  if (pid < 0)
  {
    log(L_LOG_ALERT, UNKNOWN, "fork failed: %s", strerror(errno));
    return FALSE;
  }

  if (pid == 0)
  {
    /* child */
    execve(argv[0], argv, myenv);
    /* try it again with the bin-path */
    {
      char  path[MAX_LINE];

      sprintf(path, "%s/%s", get_bin_path(), argv[0]);
      execve(path, argv, myenv);
      log(L_LOG_ERR, UNKNOWN, "exec of '%s' failed: %s", path,
          strerror(errno));
    }
    exit(-1);
  }

  /* parent */

  free_environment_list(myenv);

  while ( (wait_ret = wait(&proc_stat)) != pid && wait_ret != -1 );

  if (wait_ret == -1)
  {
    log(L_LOG_ERR, UNKNOWN, "wait failed: %s", strerror(errno));
    return(-1);
  }

  if (!WIFEXITED(proc_stat))
  {
    return(-1);
  }

  return(WEXITSTATUS(proc_stat));
}

