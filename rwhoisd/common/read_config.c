/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "read_config.h"

#include "auth_area.h"
#include "client_msgs.h"
#include "defines.h"
#include "dir_security.h"
#include "directive_conf.h"
#include "fileutils.h"
#include "log.h"
#include "main_config.h"
#include "misc.h"
#include "punt_ref.h"
#include "schema.h"

static int verify_all_path_names PROTO((void));

static int moveto_new_configuration PROTO((char *suffix, 
                                           dl_list_type *paths_list));

static void remove_tmp_config PROTO((char *suffix, dl_list_type *paths_list));

/* ------------------- Local Functions --------------------- */

/* ------------------- Public Functions -------------------- */

/* read_all_config_files: get all the possible configuration */
int
read_all_config_files(config_file, chrooted)
  char *config_file;
  int  chrooted;
{
  
  /* read the main config file (rwhois.conf) to get the every location */
  log(L_LOG_DEBUG, CONFIG, "reading main config file (%s)", config_file);
  
  if (!read_main_config_file(config_file, chrooted))
  {
    log(L_LOG_DEBUG, CONFIG, "main config file read failed");
    return FALSE;
  }
  else if (!verify_server_config_data())
  {
    log(L_LOG_DEBUG, CONFIG, "main config file read did not verify");
    return FALSE;
  }

  store_current_wd();
  chdir_root_dir();
  
  /*  get the directives */
  log(L_LOG_DEBUG, CONFIG, "reading directive config file (%s)",
      get_directive_file());
  if (!read_directive_file(get_directive_file())  )
  {
    restore_current_wd();
    return FALSE;
  } 
  /*  get the extended directives */
  log(L_LOG_DEBUG, CONFIG, "reading extended directive config file (%s)",
      get_x_directive_file());
  if (!read_extended_directive_file(get_x_directive_file()) )
  {
    restore_current_wd();
    return FALSE;
  } 

  /* read the schema file to load the entire schema */
  /* check aa syntax is finished in add_auth_area() */
  log(L_LOG_DEBUG, CONFIG, "reading auth-area config file (%s)",
      get_auth_area_file());
  if (!read_auth_areas(get_auth_area_file()))
  {
    log(L_LOG_DEBUG, CONFIG, "auth-area file read failed");
    restore_current_wd();
    return FALSE;
  }
  
  restore_current_wd();
  
  return TRUE;
}

/* read all rwhois configuration files, schema files, punt-referral and 
   directive allow and deny files. Does a check on the configuration after
   it is read-in. */
int
read_rwhois_config_files(config_file, rwconf, chrooted)
  char                  *config_file; 
  rwhois_configs_struct *rwconf;
  int                   chrooted;
{
  char         *punt_file;
  char         *allow_file;
  char         *deny_file;
  dl_list_type **punt_list = NULL;
  dl_list_type **dir_allow = NULL;
  dl_list_type **dir_deny = NULL;

  if (!config_file || !rwconf) return FALSE;

  /* set initial configuration data values */
  init_server_config_data();

  /* read all configuration files, except punt and directive security files */
  if (!read_all_config_files(config_file, chrooted))
  {
    return FALSE;
  }

  /* move to root directory */
  store_current_wd();
  chdir_root_dir();
  
  /* read the punt referral file */
  punt_file = get_punt_file();
  punt_list = &rwconf->ref_list;
  if (!read_punt_file(punt_file, punt_list))
  {
    restore_current_wd();
    return FALSE;
  }

  /* read the directive allow security file */
  allow_file = get_security_allow();
  dir_allow = &rwconf->dir_allow;
  if (!read_dir_security_file(allow_file, dir_allow, S_DIRECTIVE_ALLOW))
  {
    restore_current_wd();
    return FALSE;
  }

  /* read the directive deny security file */
  deny_file = get_security_deny();
  dir_deny = &rwconf->dir_deny;
  if (!read_dir_security_file(deny_file, dir_deny, S_DIRECTIVE_DENY))
  {
    restore_current_wd();
    return FALSE;
  }

  if (!verify_all_config(rwconf)) 
  {
    destroy_all_config(rwconf);
    restore_current_wd();
    return FALSE;
  }

  restore_current_wd();
  return TRUE;
}

/* write all rwhois configuration files, schema files, punt-referral and 
   directive allow and deny files. The configuration is written in two
   passes. In the first pass all configuration is written to temporary
   files with the given suffix. Then in the second pass the
   configuration in the temp files is renamed to be current after the
   backup of the old configuration ofcourse. Removes temporary
   configuration if unsuccessful. */
int
write_all_config_files(config_file, suffix, rwconf)
  char                  *config_file; 
  char                  *suffix;
  rwhois_configs_struct *rwconf;
{
  char         *dir_file;
  char         *xdir_file;
  char         *auth_file;
  char         *punt_file;
  char         *allow_file;
  char         *deny_file;
  dl_list_type *dir_allow;
  dl_list_type *dir_deny;
  dl_list_type *punt_list;
  dl_list_type *paths_list = NULL;

  if (!config_file || !suffix || !rwconf) return FALSE;

  paths_list = xcalloc(1, sizeof(*paths_list));

  if (!dl_list_default(paths_list, TRUE, simple_destroy_data)) 
  {
    log(L_LOG_ERR, CONFIG, 
        "Error in creating temporary configuration path names list");
    free(paths_list);
    return FALSE;
  }

  /* move to root directory */
  store_current_wd();
  chdir_root_dir();

  /* write main configuration file */
  if (!write_main_config_file(config_file, suffix, rwconf, paths_list))
  {
    restore_current_wd();
    remove_tmp_config(suffix, paths_list);
    dl_list_destroy(paths_list);
    return FALSE;
  }
  
  /* write directives file */
  dir_file = get_directive_file();
  if (!write_directive_file(dir_file, suffix, paths_list))
  {
    restore_current_wd();
    remove_tmp_config(suffix, paths_list);
    dl_list_destroy(paths_list);
    return FALSE;
  }

  /* write extended directive file */
  xdir_file = get_x_directive_file();
  if (!write_extended_directive_file(xdir_file, suffix, paths_list))
  {
    restore_current_wd();
    remove_tmp_config(suffix, paths_list);
    dl_list_destroy(paths_list);
    return FALSE;
  }

  /* write all authority areas */
  auth_file = get_auth_area_file();
  if (!write_all_auth_areas(auth_file, suffix, paths_list))
  {
    restore_current_wd();
    remove_tmp_config(suffix, paths_list);
    dl_list_destroy(paths_list);
    return FALSE;
  }

  /* write punt referral file */
  punt_file = get_punt_file();
  punt_list = rwconf->ref_list;
  if (!write_punt_file(punt_file, suffix, punt_list, paths_list))
  {
    restore_current_wd();
    remove_tmp_config(suffix, paths_list);
    dl_list_destroy(paths_list);
    return FALSE;
  }

  /* write directive allow security file */
  allow_file = get_security_allow();
  dir_allow = rwconf->dir_allow;
  if (!write_dir_security_file(allow_file, suffix, dir_allow,
      S_DIRECTIVE_ALLOW, paths_list))
  {
    restore_current_wd();
    remove_tmp_config(suffix, paths_list);
    dl_list_destroy(paths_list);
    return FALSE;
  }

  /* write directive deny security file */
  deny_file = get_security_deny();
  dir_deny = rwconf->dir_deny;
  if (!write_dir_security_file(deny_file, suffix, dir_deny, 
      S_DIRECTIVE_ALLOW, paths_list))
  {
    restore_current_wd();
    remove_tmp_config(suffix, paths_list);
    dl_list_destroy(paths_list);
    return FALSE;
  }

  /* successful in creating new/temp configuration */
  /* backup current config and rename new/temp config to current */
  if (!moveto_new_configuration(suffix, paths_list))
  {
    /* if you get here the configuration must be messed up */
    restore_current_wd();
    remove_tmp_config(suffix, paths_list);
    dl_list_destroy(paths_list);
    return FALSE;
  }

  dl_list_destroy(paths_list);
  restore_current_wd();

  return TRUE;
}

/* top level function which calls other verify functions to verify 
   complete rwhois configuration. Also calls a function to verify that
   there is no repeated usage of file names in the configuration. */
int
verify_all_config(rwconf)
  rwhois_configs_struct *rwconf;
{
  dl_list_type *dir_allow = rwconf->dir_allow;
  dl_list_type *dir_deny  = rwconf->dir_deny;
  dl_list_type *punt_list = rwconf->ref_list;

  /* move to root directory */
  store_current_wd();
  chdir_root_dir();

  /* verify the main server configuration */
  if (!verify_main_config()) 
  {
    restore_current_wd();
    return FALSE;
  }

  /* verify all directives information */
  if (!verify_all_directives())
  {
    restore_current_wd();
    return FALSE;
  }

  /* verify all authority areas */
  if (!verify_all_auth_areas())
  {
    restore_current_wd();
    return FALSE;
  }

  /* verify punt referral information */
  if (!verify_punt_ref_list(punt_list))
  {
    restore_current_wd();
    return FALSE;
  }

  /* verify directive allow security information */
  if (!verify_dir_security_list(dir_allow, S_DIRECTIVE_ALLOW))
  {
    restore_current_wd();
    return FALSE;
  }

  /* verify directive deny security information */
  if (!verify_dir_security_list(dir_deny, S_DIRECTIVE_DENY))
  {
    restore_current_wd();
    return FALSE;
  }

  /* verify all path names for any duplicates */
  if (!verify_all_path_names())
  {
    restore_current_wd();
    return FALSE;
  }

  restore_current_wd();
  return TRUE;
}

/*
   destroy/free-up all rwhois configuration.
*/
void
destroy_all_config(rwconf)
  rwhois_configs_struct *rwconf;
{
  /* destroy directive and extended directive list list */
  destroy_directive_list();

  /* destroy authority area list */
  destroy_auth_area_list();

  /* destroy class reference list */
  destroy_class_ref_list();

  /* destroy punt referral structure */
  destroy_punt_ref_list(&rwconf->ref_list);

  /* destroy allow directive security list */
  destroy_dir_security_list(&rwconf->dir_allow);

  /* destroy deny directive security list */
  destroy_dir_security_list(&rwconf->dir_deny);
}

/* initialize the rwhois configuration with defaults */
int
def_init_all_config(rwconf)
  rwhois_configs_struct *rwconf;
{
  /* destroy all configuration first */
  destroy_all_config(rwconf);

  /* set initial configuration data values */
  init_server_config_data();

  /* set default directive list */
  if (!default_directive_list()) 
  {
    log(L_LOG_ERR, CONFIG, 
        "Error in initializing the directive list");
    return FALSE;
  }

  /* default initialize directive security lists */
  if (!def_dir_allow_security_list(&rwconf->dir_allow))
  {
    log(L_LOG_ERR, CONFIG,
        "Error in initializing the directive allow security list");
    return FALSE;
  }
  if (!def_dir_deny_security_list(&rwconf->dir_deny))
  {
    log(L_LOG_ERR, CONFIG,
        "Error in initializing the directive deny security list");
    return FALSE;
  }

  /* set default punt referral information */
  if (!def_init_punt_ref(&rwconf->ref_list))
  {
    log(L_LOG_ERR, CONFIG,
        "Error in initializing the root/punt referral list");    
    return FALSE;
  }

  return TRUE;
}

/* function to make sure there is no repeated use of file names in the 
   configuration and to make sure configuration files written out by the
   admin server do not overwrite files written-out by rwhois server.
   Since the log files are opened in append mode, the log file names need
   not be unique. */
static int
verify_all_path_names()
{
  int          ret = 0;
  dl_list_type *paths_list = NULL;

  paths_list = xcalloc(1, sizeof(*paths_list));

  if (!dl_list_default(paths_list, TRUE, simple_destroy_data)) 
  {
    log(L_LOG_ERR, CONFIG, 
      "Error in creating file and directory paths list");
    free(paths_list);
    return FALSE;
  }

  ret += verify_main_config_paths(paths_list);
  ret += verify_all_auth_area_paths(paths_list);

  /* separate treatment for - log files and external programs
     these are not in the paths_list, but check to make sure they are
     not being used as config file names in the paths_list
     by the admin server. */
  ret += verify_non_admin_paths(paths_list);

  dl_list_destroy(paths_list);

  return( ret ? FALSE : TRUE );
}

/* move the temporary configuration files as new configuration
   files after backing up the current configuration files. It makes
   use of the temporary configurations file list 'paths_list' in 
   deciding which files need to be renamed for new configuration. */
static int 
moveto_new_configuration(suffix, paths_list)
  char *suffix;
  dl_list_type *paths_list;
{
  int not_done, idx, len;
  char *path, file[MAX_FILE], bkp_file[MAX_FILE];

  if (!paths_list || !suffix) return FALSE;  

  if (dl_list_empty(paths_list)) return FALSE;

  not_done = dl_list_first(paths_list);
  while (not_done)
  {
    path = dl_list_value(paths_list);

    len = strlen(suffix);
    idx = strlen(path)-len;
    if ( (idx > 0) && (strncmp(suffix, &path[idx], len) == 0) )
    {
      /* is a config file */
      bzero(file, sizeof(file));
      if (idx < sizeof(file))
      {
        strncpy(file, path, idx);
      }
      else
      {
        /* truncate file name */
        strncpy(file, path, sizeof(file)-1);
      }
      /* check if configuration file exists on disk */
      if (file_exists(file))
      {
        /* is the new configuration file contents same as the current */
        if (!file_cmpr(file, path)) 
        {
          /* backup current config file */
          bzero(bkp_file, sizeof(bkp_file));
          strncpy(bkp_file, file, sizeof(bkp_file)-1);
          strncat(bkp_file, ".old", sizeof(bkp_file)-1);
          if (rename(file, bkp_file))
          {
            log(L_LOG_ERR, CONFIG,
           "moveto_new_configuration: error in renaming file '%s' to '%s': %s",
                file, bkp_file, strerror(errno));
            return FALSE;
          }
          /* rename temporary config file name to current */
          if (rename(path, file))
          {
            log(L_LOG_ERR, CONFIG,
           "moveto_new_configuration: error in renaming file '%s' to '%s': %s",
                path, file, strerror(errno));
            return FALSE;
          }
        }
        else
        {
          /* if new configuration file is same as current */   
          unlink(path);
        }
      }
      else 
      {
        /* set new configuration file name as current */
        if (rename(path, file))
        {
          log(L_LOG_ERR, CONFIG,
          "moveto_new_configuration: error in renaming file '%s' to '%s': %s",
              path, file, strerror(errno));
          return FALSE;
        }
      }
    }
    else
    {
      /* is a config directory, it must exists on disk */
      if (!directory_exists(path))
      {
        log(L_LOG_ERR, CONFIG,
            "'%s' directory must exist - internal error");
        return FALSE;
      }
    }
 
    not_done = dl_list_next(paths_list);
  }
  
  return TRUE;
}

/* remove all temorary (new) configuration files/directories 
   (in the paths_list) from disk. */
static void
remove_tmp_config(suffix, paths_list)
  char         *suffix;
  dl_list_type *paths_list;
{
  int  idx;
  int  len;
  char *path;

  if (!paths_list || !suffix) return;  

  if (dl_list_empty(paths_list)) return;

  /* pop each path name and delete it from disk and this list */
  while (!dl_list_empty(paths_list))
  {
    dl_list_last(paths_list);
    path = dl_list_value(paths_list);
    len  = strlen(suffix);
    idx  = strlen(path)-len;
    if ( (idx > 0) && (strncmp(suffix, &path[idx], len) == 0) )
    {
      /* temporary config file */
      if (file_exists(path))
      {
        unlink(path);
      }
    }
    else 
    {
      /* config directory created for temp config */
      if (directory_exists(path))
      {
        rmdir(path);
      }
    }
    dl_list_delete(paths_list);
  }

  return;
}
