/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "reg_ext.h"

#include "anon_record.h"
#include "client_msgs.h"
#include "fileutils.h"
#include "log.h"
#include "main_config.h"
#include "misc.h"
#include "procutils.h"
#include "records.h"
#include "state.h"

#define ENV_SIZE           10
#define TMP_FILE_TEMPLATE   "%s/tmp%s.XXXXXX"


ext_parse_response_type
run_external_parser(parse_prog, action, reg_email, old_rec, new_rec_p)
  char                 *parse_prog;
  register_action_type action;
  char                 *reg_email;
  record_struct        *old_rec;
  record_struct        **new_rec_p;
{
  FILE                    *tmp_fp;
  char                    *action_str;
  char                    **argv;
  char                    **env;
  char                    command[MAX_LINE];
  char                    tmp_fname[MAX_FILE];
  ext_parse_response_type result;
  int                     argc;
  int                     status;
  record_struct           *new_rec=NULL;
  anon_record_struct      *old_anon_rec=NULL;
  
  if (new_rec_p)
  {
    new_rec = *new_rec_p;
  }

  action_str = action_to_string(action);
  
  /* dump records to tmp file */
  if (create_filename(tmp_fname, TMP_FILE_TEMPLATE, get_register_spool())
      == NULL)
  {
    log(L_LOG_ERR, DIRECTIVES, "could not create register spool file name");
    print_error(UNIDENT_ERROR, "could not create register spool file name");

    return EXT_PARSE_ERROR;
  }

  tmp_fp = fopen(tmp_fname, "w");
  if (!tmp_fp)
  {
    log(L_LOG_ERR, DIRECTIVES, "couldn't open tmp file '%s': %s", tmp_fname,
        strerror(errno));
    print_error(UNIDENT_ERROR, "couldn't open tmp file"); /* FIXME */
  }
  
  if (old_rec)
  {
    mkdb_write_record(old_rec, tmp_fp);

    if (new_rec)
    {
      fprintf(tmp_fp, "_NEW_\n");
    }
  }

  if (new_rec)
  {
    mkdb_write_record(new_rec, tmp_fp);
  }

  fclose(tmp_fp);

  /* setup environment */
  initialize_environment_list(&env, ENV_SIZE);

  add_env_value(env, ENV_SIZE, "BIN_PATH", get_bin_path());
  add_env_value(env, ENV_SIZE, "ACTION", action_str);
  add_env_value(env, ENV_SIZE, "EMAIL", reg_email);
  add_env_value(env, ENV_SIZE, "CLIENT_VENDOR",
                SAFE_STR(get_client_vendor_id(), ""));
  /*   add_env_value(env, ENV_SIZE, "", ); */
  
  sprintf(command, "%s %s", parse_prog, tmp_fname);
  split_arg_list(command, &argc, &argv);
  
  result = (ext_parse_response_type) run_env_program(argv, env);

  free_arg_list(argv);
  free_arg_list(env);
  
  /* if the result was OK, then read the new_record back in, in case
     the external parse routine changed it */
  if (result == EXT_PARSE_OK)
  {
    tmp_fp = fopen(tmp_fname, "r");
    if (!tmp_fp)
    {
      log(L_LOG_ERR, DIRECTIVES, "couldn't open tmp file '%s': %s",
          tmp_fname, strerror(errno));
      print_error(UNIDENT_ERROR, "couldn't open tmp file"); /* FIXME */
    }

    switch (action)
    {
    case ADD:
      destroy_record_data(new_rec);
      status = read_add_spool(tmp_fp, &new_rec);
      break;
    case MOD:
      destroy_record_data(new_rec);
      status = read_mod_spool(tmp_fp, &new_rec, &old_anon_rec);
      destroy_anon_record_data(old_anon_rec);
      break;
    case DEL:
      /* since we aren't handling changes to the 'old record' stuff,
         no need to read anything back here */
      break;
    default:
      log(L_LOG_WARNING, DIRECTIVES, "unknown action: %s", action_str);
      break;
    }
    
    fclose(tmp_fp);

    /* check to see if anything went wrong with the rewrite */
    if (! status)
    {
      log(L_LOG_ERR, DIRECTIVES, "external parse mangled the record");
      print_error(UNIDENT_ERROR, "");
      return(EXT_PARSE_ERROR);
    }
    
    if (new_rec)
    {
      *new_rec_p = new_rec;
    }
  }

/*   unlink(tmp_fname); */

  /* check for total script failure (hope that error code is unusual) */
  if (result > EXT_PARSE_ERROR)
  {
    log(L_LOG_ERR, DIRECTIVES, "external parse failed: %s", strerror(errno));
    print_error(UNIDENT_ERROR, "");
  }
  
  return(result);
}
