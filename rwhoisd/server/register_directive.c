/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "register_directive.h"

#include "misc.h"
#include "client_msgs.h"
#include "state.h"
#include "defines.h"
#include "log.h"
#include "reg_utils.h"
#include "register.h"
#include "common_regexps.h"
#include "main_config.h"
#include "fileutils.h"

#define SPOOL_FILE_TEMPLATE "%s/%s.XXXXXX"

/* ------------------- Local Functions -------------------- */

/************* Directive String Parsing/Processing Routines */
  
/* verify that the action is one of "add", "mod", and "del" */
static int
valid_registration_action(action_str)
  char *action_str;
{
  register_action_type  action;

  action = translate_action_str(action_str);
  if (action == UNKNOWN_ACTION)
  {
    return FALSE;
  }

  return TRUE;
}

/* verifies that the email address is an email address */
static int
valid_registration_email_address(email)
  char *email;
{
  static regexp     *prog   = NULL;
  int               status  = FALSE;

  if (!email || !*email)
  {
    return FALSE;
  }

  /* we will cache the compiled regular expression */
  if (!prog)
  {
    prog = regcomp(EMAIL_REGEXP);
  }

  status = regexec(prog, email);
 
  return(status);
}

/* given the truncated argument list (argv[0] should be the first arg
    *after* the on/off arg, check to see if the remaining arguments
    are valid, and write the header to the spool file */
static int
handle_registration_header(reg_action, reg_email, argc, argv)
  char  *reg_action;
  char  *reg_email;
  int   argc;
  char  **argv;
{
  char  *action     = NULL;
  char  *email      = NULL;

  /* action and email are *required* */
  if (argc < 2)
  {
    print_error(INVALID_DIRECTIVE_PARAM, "");
    return FALSE;
  }

  action = argv[0];

  if (!valid_registration_action(action))
  {
    print_error(INVALID_DIRECTIVE_PARAM, "");
    return FALSE;
  }

  strncpy(reg_action, action, MAX_LINE);

  email = argv[1];
  if (!valid_registration_email_address(email))
  {
    print_error(INVALID_DIRECTIVE_PARAM, "");
    return FALSE;
  }

  strncpy(reg_email, email, MAX_LINE);
  return (TRUE);
}

static int
register_on(argc, argv)
  int   argc;
  char  **argv;
{
  FILE  *spool_fp;
  char  fname[MAX_FILE];
  char  *spool_dir = get_register_spool();
  char  reg_action[MAX_LINE];
  char  reg_email[MAX_LINE];

  /* prevent trying to register on twice without a register off, thus
     confusing the spool file info */
  if (get_rwhois_state() == SPOOL_STATE)
  {
    log(L_LOG_ERR, DIRECTIVES, "attempted a '-register on' without completing the previous registration attempt");
    print_error(INVALID_DIRECTIVE, "");
    return FALSE;
  }

  if (NOT_STR_EXISTS(spool_dir))
  {
    log(L_LOG_ERR, DIRECTIVES,
        "registration spool directory is null; registration is impossible");
    print_error(INVALID_DIRECTIVE, "");
    return FALSE;
  }

  bzero(reg_action, sizeof(reg_action));
  bzero(reg_email,  sizeof(reg_email));
  
  /* make sure the registration directive line is OK */
  if (!handle_registration_header(reg_action, reg_email, argc, argv))
  {
    return FALSE;
  }

  if (STR_EXISTS(reg_email))
  {
    set_register_email(reg_email);
  }

  if (STR_EXISTS(reg_action))
  {
    set_register_action(translate_action_str(reg_action));
  }
  
  if (!directory_exists(spool_dir))
  {
    if (file_exists(spool_dir))
    {
      log(L_LOG_ERR, DIRECTIVES,
          "register spool directory '%s' is not a directory", spool_dir);
      print_error(UNIDENT_ERROR, "");
      return FALSE;
    }   

    /* otherwise we attempt to create the directory */
    if (!mkdir(spool_dir, 0755))
    {
      log(L_LOG_ERR, DIRECTIVES,
          "register spool directory '%s' could not be created: %s",
          spool_dir, strerror(errno));
      print_error(UNIDENT_ERROR, "");
      return FALSE;
    }
  }
    
  if (create_filename(fname, SPOOL_FILE_TEMPLATE, spool_dir) == NULL)
  {
    log(L_LOG_ERR, DIRECTIVES, "could not create register spool file name");
    print_error(UNIDENT_ERROR, "");
    return FALSE;
  }

  if (!set_rwhois_spool_file_name(fname))
  {
    print_error(UNIDENT_ERROR, "");
    return FALSE;
  }

  if (! (spool_fp = open_spool_file("w+")) )
  {
    print_error(UNIDENT_ERROR, "");
    return FALSE;
  }
  
  
  set_rwhois_state(SPOOL_STATE);

  return TRUE;
}

static int
register_off()
{
  /* if we weren't in the correct state, this directive is invalid */
  if (get_rwhois_state() != SPOOL_STATE)
  {
    print_error(INVALID_DIRECTIVE_PARAM, "");
    return FALSE;
  }

  /* if necessary, close the file off (to flush it, etc). */
  close_spool_file();
  set_rwhois_state(QUERY_STATE);

  /* if it ain't there, we can't do anything */
  if (!file_exists(get_rwhois_spool_file_name()))
  {
    log(L_LOG_ERR, DIRECTIVES, "rwhois spool file missing");
    /* FIXME: I'm not sure what to report here */
    print_error(UNIDENT_ERROR, "spool file missing");  
    return FALSE;
  }

  if (!process_registration(get_register_email(), get_register_action()))
  {
/*     remove_spool_file(); */
    return FALSE;
  }

/*   remove_spool_file(); */

  return TRUE; 
}

/* ------------------- PUBLIC FUNCTIONS ----------------- */

int
register_directive(str)
  char *str;
{
  int   argc;
  char  **argv;
  int   status = TRUE;

  split_arg_list(str, &argc, &argv);

  if (argc < 1)
  {
    print_error(INVALID_DIRECTIVE_PARAM, "");
    free_arg_list(argv);
    return FALSE;
  }

  if (STR_EQ(argv[0], "ON"))
  { 
    status = register_on(argc - 1, &argv[1]);
  }
  else if (STR_EQ(argv[0], "OFF"))
  {
    status = register_off();
  }
  else
  {
    print_error(INVALID_DIRECTIVE_PARAM, "");
    free_arg_list(argv);
    return FALSE;
  }
  
  free_arg_list(argv);
  return(status);
}
