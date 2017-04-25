/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "main_config.h"

#include "auth_area.h"
#include "compat.h"
#include "defines.h"
#include "fileutils.h"
#include "log.h"
#include "misc.h"
#include "strutil.h"
#include "types.h"

#include "conf.h"

/* static variables */

/* this is the data read from the main configuration files */
static server_config_struct   server_config_data;
static server_config_struct   save_server_config_data;

/* this is the state derived data (stuff that can change during a
   client session) */
static server_state_struct    server_state_data;
static server_state_struct    save_server_state_data;

/* -------------------- Local Functions ------------------- */

/* canonicalize_conf_path: a wrapper around canonicalize path that
      fills in much of the required data, and changes the path "in
      place". */
static int
canonicalize_conf_path(path, path_len, is_file, null_allowed)
  char  *path;
  int   path_len;
  int   is_file;
  int   null_allowed;
{
  int   status;
  char  canon_path[MAX_FILE + 1];
  char  full_path[MAX_FILE + 1];
  char  *the_full_path;

  status = canonicalize_path(canon_path, sizeof(canon_path), path,
                             server_config_data.root_dir, is_chrooted(),
                             null_allowed);

  /* if it failed, it failed because the data was bad, or it failed
     the chroot criteria.  We will assume the latter. */
  if (!status)
  {
    log(L_LOG_ERR, CONFIG, "'%s' isn't in the chroot environment %s", path,
        file_context_str());
    return(status);
  }

  /* canonicalize path will return a "relative to root" path, if it
     can.  Since we don't want to make any assumptions about what the
     cwd is, we will convert it back to a full path */
  if (is_rel_path(canon_path))
  {
    path_rel_to_full(full_path, sizeof(full_path), canon_path,
                     get_root_dir());
    the_full_path = full_path;
  }
  else
  {
    /* the canon_path was already a full path */
    the_full_path = canon_path;
  }


  /* now check the full path to see if it exists */
  if (!null_allowed)
  {
    if (is_file && ! file_exists(the_full_path))
    {
      log(L_LOG_ERR, CONFIG, "file '%s' does not exist %s", the_full_path,
          file_context_str());
      return FALSE;
    }
    else if (!is_file && ! directory_exists(the_full_path))
    {
      log(L_LOG_ERR, CONFIG, "directory '%s' does not exist %s",
          the_full_path, file_context_str());
      return FALSE;
    }
  }

  /* copy the canonicalized *relative* path back */
  strncpy(path, canon_path, path_len);

  return TRUE;
}


/* -------------------- Public Functions ------------------ */

/* read_main_config_file: read the main configuration file.  Does not
      take care of second pass validation (for now). */
int
read_main_config_file(config_file, chrooted)
  char  *config_file;
  int   chrooted;
{
  FILE  *fp;
  char  line[BUFSIZ + 1];
  char  tag[MAX_TEMPLATE_DESC];
  char  datum[MAX_TEMPLATE_DESC];
  int   fatal                       = FALSE;

  /* attempt to open the configuration file */
  if ((fp = fopen(config_file, "r")) == NULL)
  {
    log(L_LOG_ERR, CONFIG, "could not open config file '%s': %s", config_file,
        strerror(errno));
    return FALSE;
  }

  set_log_context(config_file, 0, -1);

  bzero(line, sizeof(line));

  while ((readline(fp, line, BUFSIZ)) != NULL && !fatal)
  {
    inc_log_context_line_num(1);

    /* parse line will automatically skip commented lines and invalid
       (no ':') lines */
    if (parse_line(line, tag, datum))
    {
      if (STR_EQ(tag, I_DEFAULT_DIR) || STR_EQ(tag, I_ROOT_DIR))
      {
        /* if we are already chrooted (we must trust the flag), then
           we must assume that the root dir is "/", so we don't need
           to set it again */
        if (!chrooted)
        {
          fatal = (! set_root_dir(datum));
        }
        else
        {
          set_root_dir("/");
        }
      }
      else if (STR_EQ(tag, I_BIN_LOC) || STR_EQ(tag, I_BIN_PATH))
      {
        set_bin_path(datum);
      }
      else if (STR_EQ(tag, I_NOTIFY_LOG))
      {
        set_notify_log(datum);
      }
      else if (STR_EQ(tag, I_DIRECTIVE_FILE))
      {
        set_directive_file(datum);
      }
      else if (STR_EQ(tag, I_X_DIRECTIVE_FILE))
      {
        set_x_directive_file(datum);
      }
      else if (STR_EQ(tag, I_AUTH_AREA_FILE))
      {
        set_auth_area_file(datum);
      }
      else if (STR_EQ(tag, I_REGISTER_LOG))
      {
        set_register_log(datum);
      }
      else if (STR_EQ(tag, I_REGISTER_SPOOL))
      {
        set_register_spool(datum);
      }
      else if (STR_EQ(tag, I_PUNT_FILE))
      {
        set_punt_file(datum);
      }
      else if (STR_EQ(tag, I_SECURITY_ALLOW))
      {
        set_security_allow(datum);
      }
      else if (STR_EQ(tag, I_SECURITY_DENY))
      {
        set_security_deny(datum);
      }
      else if (STR_EQ(tag, I_HOSTNAME))
      {
        set_local_hostname(datum);
      }
      else if (STR_EQ(tag, I_PROC_USERID))
      {
        set_process_userid(datum);
      }
      else if (STR_EQ(tag, I_CHROOTED))
      {
        set_chrooted_str(datum);
      }
      else if (STR_EQ(tag, I_DEADMAN))
      {
        set_default_deadman_time(atoi(datum));
      }
      else if (STR_EQ(tag, I_MAX_HITS_CEILING))
      {
        set_max_hits_ceiling (atoi(datum));
      }
      else if (STR_EQ(tag, I_MAX_HITS_DEFAULT))
      {
        set_max_hits_default(atoi(datum));
      }
      else if (STR_EQ(tag, I_PORT))
      {
        set_port(atoi(datum));
      }
      else if (STR_EQ(tag, I_SERVER_TYPE))
      {
        set_server_type_str(datum);
      }
      else if (STR_EQ(tag, I_BACKGROUND))
      {
        set_background(true_false(datum));
      }
      else if (STR_EQ(tag, I_VERBOSITY))
      {
        set_verbosity(atoi(datum));
      }
      else if (STR_EQ(tag, I_PID_FILE))
      {
        set_pid_file(datum);
      }
      else if (STR_EQ(tag, I_SERVER_CONTACT))
      {
        set_server_contact(datum);
      }
      else if (STR_EQ(tag, I_LOG_DEFAULT_FILE))
      {
        set_log_default(datum);
      }
      else if (STR_EQ(tag, I_LOG_EMERG))
      {
        set_log_emerg(datum);
      }
      else if (STR_EQ(tag, I_LOG_ALERT))
      {
        set_log_alert(datum);
      }
      else if (STR_EQ(tag, I_LOG_CRIT))
      {
        set_log_crit(datum);
      }
      else if (STR_EQ(tag, I_LOG_ERR))
      {
        set_log_err(datum);
      }
      else if (STR_EQ(tag, I_LOG_WARN))
      {
        set_log_warn(datum);
      }
      else if (STR_EQ(tag, I_LOG_NOTICE))
      {
        set_log_notice(datum);
      }
      else if (STR_EQ(tag, I_LOG_INFO))
      {
        set_log_info(datum);
      }
      else if (STR_EQ(tag, I_LOG_DEBUG))
      {
        set_log_debug(datum);
      }
      else if (STR_EQ(tag, I_USE_SYSLOG))
      {
        set_use_syslog(datum);
      }
      else if (STR_EQ(tag, I_SYSLOG_FACILITY))
      {
        set_log_facility(datum);
      }
      else if (STR_EQ(tag, I_QUERY_ALLOW_WILD))
      {
        set_query_allow_wild(true_false(datum));
      }
      else if (STR_EQ(tag, I_QUERY_ALLOW_SUBSTR))
      {
        set_query_allow_substr(true_false(datum));
      }
      else if (STR_EQ(tag, I_MAX_CHILDREN))
      {
        set_max_children(atoi(datum));
      }
      else if (STR_EQ(tag, I_CIDR_SEARCH_DIR))
      {
        log(L_LOG_NOTICE, CONFIG, "cidr-search-direction no longer supported");
      }
      else if (STR_EQ(tag, I_SKIP_REFERAL_SEARCH))
      {
        set_skip_referral_search(true_false(datum));
      }
      else if (STR_EQ(tag, I_LISTEN_QUEUE))
      {
        set_listen_queue_length(atoi(datum));
      }
      else if (STR_EQ(tag, I_CHILD_PRIORITY))
      {
        set_child_priority(atoi(datum));
      }
      else
      {
        log(L_LOG_WARNING, CONFIG, "config file tag '%s' unrecognized %s",
            tag, file_context_str());
      }
    }

    if (fatal)
    {
      log(L_LOG_ERR, CONFIG,
          "terminating due to fatal error processing conf. file");
      return FALSE;
    }
  }

  fclose(fp);
  return (TRUE);
}

/* clean and default config data */
void
init_server_config_data()
{
  /* clear everything */
  bzero(&server_config_data, sizeof(server_config_data));

  /* set the compiled defaults */
  set_root_dir(RWHOIS_ROOT_DIR);
  set_bin_path(DEFAULT_BIN_PATH);
/*   set_notify_log(DEFAULT_NOTIFY_LOG); */
  set_directive_file(DEFAULT_DIRECTIVE_FILE);
  set_x_directive_file(DEFAULT_X_DIRECTIVE_FILE);

  set_punt_file(DEFAULT_PUNT_FILE);
  set_auth_area_file(DEFAULT_AUTH_AREA_FILE);
/*   set_register_log(DEFAULT_REGISTER_LOG); */
  set_register_spool(DEFAULT_REGISTER_SPOOL);
  set_security_allow(DEFAULT_SECURITY_ALLOW);
  set_security_deny(DEFAULT_SECURITY_DENY);
  set_local_hostname(sys_gethostname());
  set_chrooted(DEFAULT_CHROOT);
  set_default_deadman_time(DEFAULT_DEADMAN_TIME);
  set_max_hits_ceiling(CEILING_MAX_HITS);
  set_max_hits_default(DEFAULT_MAX_HITS);
  set_port(DEFAULT_PORT);
  set_server_type(DEFAULT_SERVER_TYPE);
  set_background(TRUE);
  set_verbosity(DEFAULT_VERBOSITY);
  set_pid_file(DEFAULT_PID_FILE);
  set_server_contact(DEFAULT_SERVER_CONTACT);
  set_query_allow_wild(DEFAULT_QUERY_ALLOW_WILD);
  set_query_allow_substr(DEFAULT_QUERY_ALLOW_SUBSTR);
  set_max_children(DEFAULT_MAX_CHILDREN);
  set_skip_referral_search(FALSE);
  set_listen_queue_length(5);
  set_child_priority(0);

  /* logging variables */
  set_use_syslog(DEFAULT_USE_SYSLOG);
  set_log_facility(DEFAULT_LOG_FACILITY);
  set_log_default(DEFAULT_RWHOIS_LOG_FILE);
  set_log_emerg("");
  set_log_alert("");
  set_log_crit("");
  set_log_err("");
  set_log_warn("");
  set_log_notice("");
  set_log_info("");
  set_log_debug("");

  bcopy(&server_config_data, &save_server_config_data,
        sizeof(save_server_config_data));
}

/* initialize server state */
void
init_server_state()
{

  bzero(&server_state_data, sizeof(server_state_data));

  set_hit_limit(DEFAULT_MAX_HITS);
  set_holdconnect(DEFAULT_HOLDCONNECT);
  set_forward(DEFAULT_FORWARD);
  set_display(DEFAULT_DISPLAY);
}

/* verify_server_config_data: This is a pass through the config data to
     canonicalize paths, and detect errors that can not be detected
     immediately; it will return TRUE if there were no fatal errors,
     FALSE if not. */
int
verify_server_config_data()
{
  int   status;

  /* if the root directory is "" then we will explictly set it to the CWD */
  if (!*server_config_data.root_dir)
  {
    char    buf[MAX_FILE + 1];

    getcwd(buf, sizeof(buf));
    set_root_dir(buf);
  }

  /* now we will fix all the paths, and issue errors or warnings */
  status = canonicalize_conf_path(server_config_data.bin_path,
                                  sizeof(server_config_data.bin_path),
                                  FALSE,
                                  TRUE);
  if (!status) return(status);

  status = canonicalize_conf_path(server_config_data.directive_file,
                                  sizeof(server_config_data.directive_file),
                                  TRUE,
                                  TRUE);
  if (!status) return(status);

  status = canonicalize_conf_path(server_config_data.x_directive_file,
                                  sizeof(server_config_data.x_directive_file),
                                  TRUE,
                                  TRUE);
  if (!status) return(status);

  status = canonicalize_conf_path(server_config_data.auth_area_file,
                                  sizeof(server_config_data.auth_area_file),
                                  TRUE,
                                  FALSE);
  if (!status) return(status);

  status = canonicalize_conf_path(server_config_data.punt_file,
                                  sizeof(server_config_data.punt_file),
                                  TRUE,
                                  FALSE);
  if (!status) return(status);

  /* check the root referral syntax: <host>:<port>:<protocol> */
  store_current_wd();
  chdir_root_dir();

  /* FIXME: this routine appears to not be working */
/*   if (!check_root_referral(server_config_data.punt_file)) */
/*   { */
/*     return FALSE; */
/*   } */
  restore_current_wd();

  status = canonicalize_conf_path(server_config_data.register_spool,
                                  sizeof(server_config_data.register_spool),
                                  FALSE,
                                  TRUE);
  if (!status) return(status);

  status = canonicalize_conf_path(server_config_data.security_allow,
                                  sizeof(server_config_data.security_allow),
                                  TRUE,
                                  FALSE);
  if (!status) return(status);

  status = canonicalize_conf_path(server_config_data.security_deny,
                                  sizeof(server_config_data.security_deny),
                                  TRUE,
                                  FALSE);
  return(status);
}


void
display_server_config_data(file)
  FILE  *file;
{
  fprintf(file, "--------------------------------\n");

  if (*server_config_data.root_dir)
  {
    fprintf(file, "root-dir:         %s\n", server_config_data.root_dir);
  }
  if (*server_config_data.auth_area_file)
  {
    fprintf(file, "auth-area-file:   %s\n", server_config_data.auth_area_file);
  }
  if (*server_config_data.directive_file)
  {
    fprintf(file, "directive-file:   %s\n", server_config_data.directive_file);
  }
  if (*server_config_data.x_directive_file)
  {
    fprintf(file, "x_directive-file: %s\n",
        server_config_data.x_directive_file);
  }

  if (*server_config_data.register_log)
  {
    fprintf(file, "register-log:     %s\n", server_config_data.register_log);
  }
  if (*server_config_data.register_spool)
  {
    fprintf(file, "register-spool:   %s\n",
            server_config_data.register_spool);
  }
  if (*server_config_data.notify_log)
  {
    fprintf(file, "notify-log:       %s\n", server_config_data.notify_log);
  }
  if (*server_config_data.security_allow)
  {
    fprintf(file, "security-allow:   %s\n",
            server_config_data.security_allow);
  }
  if (*server_config_data.security_deny)
  {
    fprintf(file, "security-deny:    %s\n",
            server_config_data.security_deny);
  }
  if (*server_config_data.bin_path)
  {
    fprintf(file, "bin-path:         %s\n", server_config_data.bin_path);
  }
  if (*server_config_data.hostname)
  {
    fprintf(file, "local-host:       %s\n", server_config_data.hostname);
  }

  fprintf(file, "local-port:       %d\n", server_config_data.port);

  if (*server_config_data.process_userid)
  {
    fprintf(file, "userid:           %s\n",
            server_config_data.process_userid);
  }

  fprintf(file, "max-hits-ceiling: %d\n", server_config_data.max_hits_ceiling);
  fprintf(file, "max-hits-default: %d\n", server_config_data.max_hits_default);

  fprintf(file, "chrooted:         %s\n",
          (server_config_data.chrooted ? "YES" : "NO"));

  fprintf(file, "server-type:      %s\n",
          (server_config_data.server_type ? "INETD" : "DAEMON"));

  if (*server_config_data.pid_file)
  {
    fprintf(file, "pid-file:         %s\n", server_config_data.pid_file);
  }

  if (*server_config_data.server_contact)
  {
    fprintf(file, "server-contact:   %s\n", server_config_data.server_contact);
  }

  fprintf(file, "verbosity-level:  %d\n", server_config_data.verbose);
  if (server_config_data.use_syslog)
  {
    fprintf(file, "use_syslog: YES\n");
    fprintf(file, "syslog-facility: %d\n", get_log_facility());

  }
  else
  {
    fprintf(file, "use_syslog: NO\n");

    if (*server_config_data.log_default_file)
    {
      fprintf(file, "default-log-file: %s\n", get_log_default());
    }
    if (*server_config_data.log_emerg_file)
    {
      fprintf(file, "emergency-log-file: %s\n", get_log_emerg());
    }
    if (*server_config_data.log_alert_file)
    {
      fprintf(file, "alert-log-file: %s\n", get_log_alert());
    }
    if (*server_config_data.log_crit_file)
    {
      fprintf(file, "crit-log-file: %s\n", get_log_crit());
    }
    if (*server_config_data.log_err_file)
    {
      fprintf(file, "err-log-file: %s\n", get_log_err());
    }
    if (*server_config_data.log_warn_file)
    {
      fprintf(file, "warn-log-file: %s\n", get_log_warn());
    }
    if (*server_config_data.log_notice_file)
    {
      fprintf(file, "notice-log-file: %s\n", get_log_notice());
    }
    if (*server_config_data.log_info_file)
    {
      fprintf(file, "info-log-file: %s\n", get_log_info());
    }
    if (*server_config_data.log_debug_file)
    {
      fprintf(file, "debug-log-file: %s\n", get_log_debug());
    }
  }

  fprintf(file, "--------------------------------\n");
}


int
save_server_state()
{
  bcopy(&server_state_data, &save_server_state_data,
        sizeof(save_server_state_data));

  return TRUE;
}

int
restore_server_state()
{
  bcopy(&save_server_state_data, &server_state_data,
        sizeof(server_state_data));

  return TRUE;
}


/* ---------------- The Guard Functions ----------------- */

/* set_root_dir: We can actually detect errors on this one. */
int
set_root_dir(dir)
  char  *dir;
{
  if (dir && *dir)
  {
    if (directory_exists(dir))
    {
      strncpy(server_config_data.root_dir, dir, MAX_FILE);

      /* strip leading and trailing spaces, and strip trailing '/' */
      trim(server_config_data.root_dir);
      if (strlen(dir) > 1)
      {
        strip_trailing(server_config_data.root_dir, '/');
      }
    }
    else
    {
      log(L_LOG_ERR, CONFIG, "root directory '%s' does not exist %s", dir,
          file_context_str());
      return FALSE;
    }
  }

  return TRUE;
}

char *
get_root_dir()
{
  return(server_config_data.root_dir);
}

int
chdir_root_dir()
{
  char  *dir = get_root_dir();

  /* attempt to set the working directory to the root dir */
  if (chdir(dir) < 0)
  {
    log(L_LOG_ERR, FILES, "chdir to '%s' failed: %s %s", dir, strerror(errno),
        file_context_str());
    return FALSE;
  }

  return TRUE;
}

int
set_bin_path(path)
  char  *path;
{
  strncpy(server_config_data.bin_path, path, MAX_FILE);
  return TRUE;
}

char *
get_bin_path()
{
  return(server_config_data.bin_path);
}

int
set_notify_log(log)
  char  *log;
{
  strncpy(server_config_data.notify_log, log, MAX_FILE);
  return TRUE;
}

char *
get_notify_log()
{
  return(server_config_data.notify_log);
}

int
set_log_default(file)
  char *file;
{
  strncpy(server_config_data.log_default_file, file, MAX_FILE);
  return TRUE;
}

char *
get_log_default()
{
  return(server_config_data.log_default_file);
}

int
set_log_facility(facility)
   char *facility;
{
  if (STR_EQ(facility,"LOG_KERN"))
  {
    server_config_data.log_facility = LOG_KERN;
    return TRUE;
  }
  if (STR_EQ(facility,"LOG_USER"))
  {
    server_config_data.log_facility = LOG_USER;
    return TRUE;
  }
  if (STR_EQ(facility,"LOG_MAIL"))
  {
    server_config_data.log_facility = LOG_MAIL;
    return TRUE;
  }
  if (STR_EQ(facility,"LOG_DAEMON"))
  {
    server_config_data.log_facility = LOG_DAEMON;
    return TRUE;
  }
  if (STR_EQ(facility,"LOG_AUTH"))
  {
    server_config_data.log_facility = LOG_AUTH;
    return TRUE;
  }
  if (STR_EQ(facility,"LOG_LPR"))
  {
    server_config_data.log_facility = LOG_LPR;
    return TRUE;
  }
  if (STR_EQ(facility,"LOG_NEWS"))
  {
    server_config_data.log_facility =LOG_NEWS;
    return TRUE;
  }
  if (STR_EQ(facility,"LOG_UUCP"))
  {
    server_config_data.log_facility =LOG_UUCP;
    return TRUE;
  }
  if (STR_EQ(facility,"LOG_CRON"))
  {
    server_config_data.log_facility =LOG_CRON;
    return TRUE;
  }
  if (STR_EQ(facility,"LOG_LOCAL0")) {
    server_config_data.log_facility =LOG_LOCAL0;
    return TRUE;
  }
  if (STR_EQ(facility,"LOG_LOCAL1"))
  {
    server_config_data.log_facility =LOG_LOCAL1;
    return TRUE;
  }
  if (STR_EQ(facility,"LOG_LOCAL2"))
  {
    server_config_data.log_facility =LOG_LOCAL2;
    return TRUE;
  }
  if (STR_EQ(facility,"LOG_LOCAL3"))
  {
    server_config_data.log_facility =LOG_LOCAL3;
    return TRUE;
  }
  if (STR_EQ(facility,"LOG_LOCAL4"))
  {
    server_config_data.log_facility =LOG_LOCAL4;
    return TRUE;
  }
  if (STR_EQ(facility,"LOG_LOCAL5"))
  {
    server_config_data.log_facility =LOG_LOCAL5;
    return TRUE;
  }
  if (STR_EQ(facility,"LOG_LOCAL6"))
  {
    server_config_data.log_facility =LOG_LOCAL6;
    return TRUE;
  }
  if (STR_EQ(facility,"LOG_LOCAL7"))
  {
    server_config_data.log_facility =LOG_LOCAL7;
    return TRUE;
  }

  fprintf(stderr, "Error: invalid log facility specified %s\n", facility);
  return(-1);
}

int
get_log_facility()
{
   return(server_config_data.log_facility);
}

int
set_log_emerg(log)
  char  *log;
{
  strncpy(server_config_data.log_emerg_file, log, MAX_FILE);
  return TRUE;
}
char *
get_log_emerg()
{
  return(server_config_data.log_emerg_file);
}

int
set_log_alert(log)
  char  *log;
{
  strncpy(server_config_data.log_alert_file, log, MAX_FILE);
  return TRUE;
}
char *
get_log_alert()
{
  return(server_config_data.log_alert_file);
}

int
set_log_crit(log)
  char  *log;
{
  strncpy(server_config_data.log_crit_file, log, MAX_FILE);
  return TRUE;
}

char *
get_log_crit()
{
  return(server_config_data.log_crit_file);
}

int
set_log_err(log)
  char  *log;
{
  strncpy(server_config_data.log_err_file, log, MAX_FILE);
  return TRUE;
}

char *
get_log_err()
{
  return(server_config_data.log_err_file);
}

int
set_log_warn(log)
  char  *log;
{
  strncpy(server_config_data.log_warn_file, log, MAX_FILE);
  return TRUE;
}

char *
get_log_warn()
{
  return(server_config_data.log_warn_file);
}

int
set_log_notice(log)
  char  *log;
{
  strncpy(server_config_data.log_notice_file, log, MAX_FILE);
  return TRUE;
}
char *
get_log_notice()
{
  return(server_config_data.log_notice_file);
}

int
set_log_info(log)
  char  *log;
{
  strncpy(server_config_data.log_info_file, log, MAX_FILE);
  return TRUE;
}
char *
get_log_info()
{
  return(server_config_data.log_info_file);
}

int
set_log_debug(log)
  char  *log;
{
  strncpy(server_config_data.log_debug_file, log, MAX_FILE);
  return TRUE;
}

char *
get_log_debug()
{
  return(server_config_data.log_debug_file);
}

int
set_directive_file(file)
  char *file;
{
  strncpy(server_config_data.directive_file, file, MAX_FILE);
  return TRUE;
}

char *
get_directive_file()
{
  return(server_config_data.directive_file);
}

int
set_x_directive_file(file)
  char *file;
{
  strncpy(server_config_data.x_directive_file, file, MAX_FILE);
  return TRUE;
}

char *
get_x_directive_file()
{
  return(server_config_data.x_directive_file);
}

int
set_auth_area_file(file)
  char  *file;
{
  strncpy(server_config_data.auth_area_file, file, MAX_FILE);
  return TRUE;
}

char *
get_auth_area_file()
{
  return(server_config_data.auth_area_file);
}

int
set_register_log(log)
  char  *log;
{
  strncpy(server_config_data.register_log, log, MAX_FILE);
  return TRUE;
}

char *
get_register_log()
{
  return(server_config_data.register_log);
}

int
set_register_spool(spool)
  char  *spool;
{
  strncpy(server_config_data.register_spool, spool, MAX_FILE);
  return TRUE;
}

char *
get_register_spool()
{
  return(server_config_data.register_spool);
}

int
set_punt_file(file)
  char  *file;
{
  strncpy(server_config_data.punt_file, file, MAX_FILE);
  return TRUE;
}

char *
get_punt_file()
{
  return(server_config_data.punt_file);
}

int
set_security_allow(file)
  char  *file;
{
  strncpy(server_config_data.security_allow, file, MAX_FILE);
  return TRUE;
}

char *
get_security_allow()
{
  return(server_config_data.security_allow);
}

int
set_security_deny(file)
  char  *file;
{
  strncpy(server_config_data.security_deny, file, MAX_FILE);
  return TRUE;
}

char *
get_security_deny()
{
  return(server_config_data.security_deny);
}

int
set_local_hostname(name)
  char  *name;
{
  strncpy(server_config_data.hostname, name, MAX_LINE);
  return TRUE;
}

char *
get_local_hostname()
{
  return(server_config_data.hostname);
}

int
set_process_userid(id)
  char  *id;
{
  strncpy(server_config_data.process_userid, id, MAX_LINE);
  return TRUE;
}

char *
get_process_userid()
{
  return(server_config_data.process_userid);
}

int
set_chrooted(val)
  int   val;
{
  server_config_data.chrooted = val;
  return TRUE;
}

int
set_chrooted_str(str)
  char  *str;
{
  server_config_data.chrooted = true_false(str);
  return TRUE;
}

int
is_chrooted()
{
  return(server_config_data.chrooted);
}


int
set_use_syslog(str)
  char  *str;
{
#ifndef NO_SYSLOG
  server_config_data.use_syslog = FALSE;
#endif
  server_config_data.use_syslog = true_false(str);
  return TRUE;
}

int
is_syslog_used()
{
  return(server_config_data.use_syslog);
}

int
set_default_deadman_time(sec)
  int   sec;
{
  server_config_data.default_deadman_time = sec;
  return TRUE;
}

int
get_default_deadman_time()
{
  return(server_config_data.default_deadman_time);
}

int
set_max_hits_ceiling(hits)
  int   hits;
{
  server_config_data.max_hits_ceiling = hits;
  return TRUE;
}

int
get_max_hits_ceiling()
{
  return(server_config_data.max_hits_ceiling);
}

int
set_max_hits_default(hits)
  int   hits;
{
  server_config_data.max_hits_default = hits;
  return TRUE;
}

int
get_max_hits_default()
{
  return(server_config_data.max_hits_default);
}

int
set_port(p)
  int   p;
{
  server_config_data.port = p;
  return TRUE;
}

int
get_port()
{
  return(server_config_data.port);
}

int
set_root_server(val)
  int   val;
{
  server_config_data.root_server = val;
  return TRUE;
}

int
set_root_server_str(str)
  char  *str;
{
  server_config_data.root_server = true_false(str);
  return TRUE;
}

int
is_root_server()
{
  return(server_config_data.root_server);
}

int
set_server_type(type)
  rwhois_server_type type;
{
  server_config_data.server_type = type;
  return TRUE;
}

int
set_server_type_str(str)
  char *str;

{
  if (STR_EQ(str, "INETD") ) {
    server_config_data.server_type = INETD_SERVER;
  }
  else {
    server_config_data.server_type = DAEMON_SERVER;
  }

  return TRUE;
}

rwhois_server_type
get_server_type()
{
  return((rwhois_server_type) server_config_data.server_type);
}

/* is_daemon_server: true if DAEMON, false if not */
int
is_daemon_server()
{
  if (get_server_type() == DAEMON_SERVER) {
    return (TRUE);
  }
  return (FALSE);
}

int
set_background(val)
  int   val;
{
  server_config_data.background = val;
  return TRUE;
}

int
get_background()
{
  return server_config_data.background;
}

int
set_verbosity(val)
  int   val;
{
  server_config_data.verbose = val;
  return TRUE;
}

int
get_verbosity()
{
  return server_config_data.verbose;
}

int
set_pid_file(file)
  char  *file;
{
  strncpy(server_config_data.pid_file, file, MAX_FILE);
  return TRUE;
}

char *
get_pid_file()
{
  return(server_config_data.pid_file);
}

int
set_server_contact(contact)
  char *contact;
{
  strncpy(server_config_data.server_contact, contact, MAX_LINE);

  return TRUE;
}

char *
get_server_contact()
{
  return(server_config_data.server_contact);
}


/* sever_state functions. */

int
set_hit_limit(limit)
  int   limit;
{
  server_state_data.limit = limit;
  return TRUE;
}

int
get_hit_limit()
{
  return(server_state_data.limit);
}

int
set_holdconnect(val)
  char *val;
{
  if(STR_EQ(val, "OFF")){
    server_state_data.holdconnect = FALSE;
  }
  else if (STR_EQ(val, "ON") ){
    server_state_data.holdconnect = TRUE;
  }
  else
    /* wrong val */
    return FALSE;

  return TRUE;
}

int
get_holdconnect()
{
  return(server_state_data.holdconnect);
}


int
set_forward(val)
  char *val;
{
  if (STR_EQ(val, "OFF"))
  {
    server_state_data.forward = FALSE;
  }
  else if (STR_EQ(val, "ON"))
  {
    server_state_data.forward = TRUE;
  }
  else
  {
    /* wrong val */
    return FALSE;
  }

  return TRUE;
}

int
get_forward()
{
  return(server_state_data.forward);
}


int
set_display(mode)
  char *mode;
{
  strncpy(server_state_data.display, mode, MAX_LINE);

  return TRUE;
}

char *
get_display()
{
  return server_state_data.display;
}

int
set_query_allow_wild(val)
  int val;
{
  server_config_data.query_allow_wild = val;
  return TRUE;
}

int
get_query_allow_wild()
{
  return(server_config_data.query_allow_wild);
}

int
set_query_allow_substr(val)
  int val;
{
  server_config_data.query_allow_substr = val;
  return TRUE;
}

int
get_query_allow_substr()
{
  return(server_config_data.query_allow_substr);
}

int
get_max_children()
{
  return(server_config_data.max_children);
}

int
set_max_children(val)
  int val;
{
  server_config_data.max_children = val;

  return TRUE;
}


int
get_skip_referral_search()
{
  return(server_config_data.skip_referral_search);
}

int
set_skip_referral_search(val)
  int val;
{
  server_config_data.skip_referral_search = val;
  return TRUE;
}


int
get_listen_queue_length()
{
  return(server_config_data.listen_queue_length);
}

int
set_listen_queue_length(val)
  int val;
{
  server_config_data.listen_queue_length = val;
  return TRUE;
}


int
get_child_priority()
{
  return(server_config_data.child_priority_offset);
}

int
set_child_priority(val)
  int val;
{
  server_config_data.child_priority_offset = val;
  return TRUE;
}

/* returns the server type string associated with the server type */
char *
get_server_type_str(serv_type)
  rwhois_server_type serv_type;
{
  switch (serv_type)
  {
  case INETD_SERVER:
    return( "inetd" );
  case DAEMON_SERVER:
    return( "daemon" );
  default:
    log(L_LOG_ERR, CONFIG, "server type '%d' invalid", serv_type);
    return( "" );
  }
}

/* returns the server log facility string associated with the server log
   facility type */
char *
get_log_facility_str(facility_val)
  int facility_val;
{
  char *facility_str = NULL;

  switch (facility_val)
  {
    case LOG_KERN:
      facility_str = "log_kern";
      break;
    case LOG_USER:
      facility_str = "log_user";
      break;
    case LOG_MAIL:
      facility_str = "log_mail";
      break;
    case LOG_DAEMON:
      facility_str = "log_daemon";
      break;
    case LOG_AUTH:
      facility_str = "log_auth";
      break;
    case LOG_LPR:
      facility_str = "log_lpr";
      break;
    case LOG_NEWS:
      facility_str = "log_news";
      break;
    case LOG_UUCP:
      facility_str = "log_uucp";
      break;
    case LOG_CRON:
      facility_str = "log_cron";
      break;
    case LOG_LOCAL0:
      facility_str = "log_local0";
      break;
    case LOG_LOCAL1:
      facility_str = "log_local1";
      break;
    case LOG_LOCAL2:
      facility_str = "log_local2";
      break;
    case LOG_LOCAL3:
      facility_str = "log_local3";
      break;
    case LOG_LOCAL4:
      facility_str = "log_local4";
      break;
    case LOG_LOCAL5:
      facility_str = "log_local5";
      break;
    case LOG_LOCAL6:
      facility_str = "log_local6";
      break;
    case LOG_LOCAL7:
      facility_str = "log_local7";
      break;
    default:
      facility_str = "unknown";
      log(L_LOG_ERR, CONFIG,
          "invalid log facility value specified %d", facility_val);
      break;
  }
  return( facility_str );
}

/* writes main configuration file to disk. It writes all defined main
   configuration parameters. Also appends the main config file name
   to paths_list if it was successful in creating a file on disk. */
int
write_main_config_file(file, suffix, rwconf, paths_list)
  char                  *file;
  char                  *suffix;
  rwhois_configs_struct *rwconf;
  dl_list_type          *paths_list;
{
  FILE *fptr;
  char new_file[MAX_FILE];

  if (!file || !*file || !rwconf) return FALSE;

  bzero(new_file, sizeof(new_file));
  strncpy(new_file, file, sizeof(new_file)-1);
  strncat(new_file, suffix, sizeof(new_file)-1);

  if ((fptr = open_file_to_write(new_file, 60, paths_list)) == NULL)
  {
    log(L_LOG_ERR, CONFIG,
        "cannot create main configuration file '%s': %s", new_file,
        strerror(errno));
    return FALSE;
  }

  if (*server_config_data.root_dir)
  {
    fprintf(fptr, "%s: %s\n", I_ROOT_DIR, server_config_data.root_dir);
  }
  if (*server_config_data.bin_path)
  {
    fprintf(fptr, "%s: %s\n", I_BIN_PATH, server_config_data.bin_path);
  }
  if (*server_config_data.auth_area_file)
  {
    fprintf(fptr, "%s: %s\n", I_AUTH_AREA_FILE,
            server_config_data.auth_area_file);
  }
  if (*server_config_data.directive_file)
  {
    fprintf(fptr, "%s: %s\n", I_DIRECTIVE_FILE,
            server_config_data.directive_file);
  }
  if (*server_config_data.x_directive_file)
  {
    fprintf(fptr, "%s: %s\n", I_X_DIRECTIVE_FILE,
            server_config_data.x_directive_file);
  }

  fprintf(fptr, "%s: %d\n", I_MAX_HITS_DEFAULT,
          server_config_data.max_hits_default);
  fprintf(fptr, "%s: %d\n", I_MAX_HITS_CEILING,
          server_config_data.max_hits_ceiling);

  if (*server_config_data.notify_log)
  {
    fprintf(fptr, "%s: %s\n", I_NOTIFY_LOG, server_config_data.notify_log);
  }
  if (*server_config_data.register_log)
  {
    fprintf(fptr, "%s: %s\n", I_REGISTER_LOG, server_config_data.register_log);
  }
  if (*server_config_data.register_spool)
  {
    fprintf(fptr, "%s: %s\n", I_REGISTER_SPOOL,
                                         server_config_data.register_spool);
  }
  if (*server_config_data.punt_file)
  {
    fprintf(fptr, "%s: %s\n", I_PUNT_FILE,
            server_config_data.punt_file);
  }
  if (*server_config_data.hostname)
  {
    fprintf(fptr, "%s: %s\n", I_HOSTNAME, server_config_data.hostname);
  }

  fprintf(fptr, "%s: %d\n", I_PORT, server_config_data.port);

  if (*server_config_data.security_allow)
  {
    fprintf(fptr, "%s: %s\n", I_SECURITY_ALLOW,
            server_config_data.security_allow);
  }
  if (*server_config_data.security_deny)
  {
    fprintf(fptr, "%s: %s\n", I_SECURITY_DENY,
            server_config_data.security_deny);
  }

  fprintf(fptr, "%s: %d\n", I_DEADMAN,
          server_config_data.default_deadman_time);

  fprintf(fptr, "%s: %s\n", I_SERVER_TYPE,
          get_server_type_str(server_config_data.server_type));

  fprintf(fptr, "%s: %s\n", I_CHROOTED,
          (server_config_data.chrooted ? "YES" : "NO"));

  fprintf(fptr, "%s: %s\n", I_QUERY_ALLOW_WILD,
          (server_config_data.query_allow_wild ? "YES" : "NO"));

  fprintf(fptr, "%s: %s\n", I_QUERY_ALLOW_SUBSTR,
          (server_config_data.query_allow_substr ? "YES" : "NO"));

  if (*server_config_data.process_userid)
  {
    fprintf(fptr, "%s: %s\n", I_PROC_USERID,
            server_config_data.process_userid);
  }

  if (*server_config_data.pid_file)
  {
    fprintf(fptr, "%s: %s\n", I_PID_FILE, server_config_data.pid_file);
  }

  fprintf(fptr, "%s: %d\n", I_VERBOSITY, server_config_data.verbose);
  if (*server_config_data.log_default_file)
  {
    fprintf(fptr, "%s: %s\n", I_LOG_DEFAULT_FILE,
            server_config_data.log_default_file);
  }
  if (!server_config_data.use_syslog)
  {
    fprintf(fptr, "%s: %s\n", I_USE_SYSLOG, "YES");
  }
  else
  {
    fprintf(fptr, "%s: %s\n", I_USE_SYSLOG, "NO");
  }
  if (*server_config_data.log_emerg_file)
  {
    fprintf(fptr, "%s: %s\n", I_LOG_EMERG,
            server_config_data.log_emerg_file);
  }
  if (*server_config_data.log_alert_file)
  {
    fprintf(fptr, "%s: %s\n", I_LOG_ALERT,
            server_config_data.log_alert_file);
  }
  if (*server_config_data.log_crit_file)
  {
    fprintf(fptr, "%s: %s\n", I_LOG_CRIT,
            server_config_data.log_crit_file);
  }
  if (*server_config_data.log_err_file)
  {
    fprintf(fptr, "%s: %s\n", I_LOG_ERR,
            server_config_data.log_err_file);
  }
  if (*server_config_data.log_warn_file)
  {
    fprintf(fptr, "%s: %s\n", I_LOG_WARN,
            server_config_data.log_warn_file);
  }
  if (*server_config_data.log_notice_file)
  {
    fprintf(fptr, "%s: %s\n", I_LOG_NOTICE,
            server_config_data.log_notice_file);
  }
  if (*server_config_data.log_info_file)
  {
    fprintf(fptr, "%s: %s\n", I_LOG_INFO,
            server_config_data.log_info_file);
  }
  if (*server_config_data.log_debug_file)
  {
    fprintf(fptr, "%s: %s\n", I_LOG_DEBUG,
            server_config_data.log_debug_file);
  }
  if (*server_config_data.server_contact)
  {
    fprintf(fptr, "%s: %s\n", I_SERVER_CONTACT,
            server_config_data.server_contact);
  }

  release_file_lock(new_file, fptr);

  dl_list_append(paths_list, xstrdup(new_file));

  return TRUE;
}

/* examine the format of user id string. Returns non-zero value if failed. */
int
examin_userid(uid)
  char *uid;
{
  if (NOT_STR_EXISTS(uid)) return ERW_EMTYSTR;
  if (!is_id_str(uid)) return ERW_IDSTR;

  return( 0 );
}

/* examine the rwhois log file name format. Check if it is under the
   root directory. Returns non-zero value on failure. */
int
examin_rwlog_file(file)
  char *file;
{
  int ret;

  if ((ret = examin_file_name(file))) return( ret );
  if (!path_under_root_dir(file, get_root_dir())) return ERW_UNDROOT;

  return( 0 );
}

/* examine the rwhois config file name format. Check if it is under the
   root directory. Returns non-zero value on failure. */
int
examin_rwconf_file(file)
  char *file;
{
  int ret;

  if ((ret = examin_file_name(file))) return( ret );
  if (!path_under_root_dir(file, get_root_dir())) return ERW_UNDROOT;

  return( 0 );
}

/* examine the rwhois config directory name format. Check if it is under the
   root directory. Returns non-zero value on failure. */
int
examin_rwconf_dir(dir)
  char *dir;
{
  int ret;

  if ((ret = examin_directory_name(dir))) return( ret );
  if (!path_under_root_dir(dir, get_root_dir())) return ERW_UNDROOT;

  return( 0 );
}

/* examine the rwhois executable program format. Check if it is
   an executable on disk. Returns non-zero value on failure. */
int
examin_rwexe_file(file)
  char *file;
{
  int ret;

  if ((ret = examin_file_name(file))) return( ret );
  if ((ret = examin_executable_name(file))) return( ret );

  return( 0 );
}

/* examine the rwhois executable program format. Check if it is
   an executable on disk. Returns non-zero value on failure. */
int
examin_server_contact(contact)
  char *contact;
{
  int ret;

  if (NOT_STR_EXISTS(contact)) return ERW_EMTYSTR;
  if ((ret = examin_email_address(contact))) return( ret );

  return( 0 );
}

/* verify the contents of main server configuration variables.
   Returns false if any errors encountered. */
int
verify_main_config()
{
  int errnum;

  if (*server_config_data.root_dir &&
      (errnum = examin_directory_writable(server_config_data.root_dir)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server root/default directory '%s': %s",
        server_config_data.root_dir, examin_error_string(errnum));
    return FALSE;
  }
  if ((errnum = examin_rwconf_dir(server_config_data.bin_path)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server bin-path directory '%s': %s",
        server_config_data.bin_path, examin_error_string(errnum));
    return FALSE;
  }
  if ((errnum = examin_rwconf_file(server_config_data.directive_file)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server directive file path '%s': %s",
        server_config_data.directive_file, examin_error_string(errnum));
    return FALSE;
  }
  if ((errnum = examin_rwconf_file(server_config_data.x_directive_file)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server extended directive file path '%s': %s",
        server_config_data.x_directive_file, examin_error_string(errnum));
    return FALSE;
  }
  if ((errnum = examin_rwconf_file(server_config_data.auth_area_file)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server authority area file path '%s': %s",
        server_config_data.auth_area_file, examin_error_string(errnum));
    return FALSE;
  }
  if ((errnum = examin_rwconf_file(server_config_data.punt_file)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server punt or root referral file path '%s': %s",
        server_config_data.punt_file, examin_error_string(errnum));
    return FALSE;
  }
  if ((errnum = examin_rwconf_file(server_config_data.security_allow)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server security allow file path '%s': %s",
        server_config_data.security_allow, examin_error_string(errnum));
    return FALSE;
  }
  if ((errnum = examin_rwconf_file(server_config_data.security_deny)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server security deny file path '%s': %s",
        server_config_data.security_deny, examin_error_string(errnum));
    return FALSE;
  }
  if ((errnum = examin_rwconf_file(server_config_data.pid_file)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server process id file path '%s': %s",
        server_config_data.pid_file, examin_error_string(errnum));
    return FALSE;
  }
  if ((errnum = examin_rwconf_dir(server_config_data.register_spool)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server register spool directory '%s': %s",
        server_config_data.register_spool, examin_error_string(errnum));
    return FALSE;
  }
  if ((errnum = examin_hostname(server_config_data.hostname)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server host name '%s': %s",
        server_config_data.hostname, examin_error_string(errnum));
    return FALSE;
  }
  if (*server_config_data.process_userid &&
      (errnum = examin_userid(server_config_data.process_userid)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server process user id '%s': %s",
        server_config_data.process_userid, examin_error_string(errnum));
    return FALSE;
  }
  if (*server_config_data.server_contact &&
      (errnum = examin_server_contact(server_config_data.server_contact)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server contact email address '%s': %s",
        server_config_data.server_contact, examin_error_string(errnum));
    return FALSE;
  }
  if (server_config_data.port <= 0)
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server port '%d': %s",
        server_config_data.port, examin_error_string(ERW_NUMVAL));
    return FALSE;
  }
  if (server_config_data.default_deadman_time < 1)
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server deadman_time '%d': %s",
        server_config_data.default_deadman_time,
        examin_error_string(ERW_NUMVAL));
    return FALSE;
  }
  if (server_config_data.max_hits_ceiling < 1)
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server max-hits-ceiling '%d': %s",
        server_config_data.max_hits_ceiling, examin_error_string(ERW_NUMVAL));
    return FALSE;
  }

  if (server_config_data.max_hits_default < 1)
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server max-hits-default '%d': %s",
        server_config_data.max_hits_default, examin_error_string(ERW_NUMVAL));
    return FALSE;
  }

  if (server_config_data.max_hits_default >
      server_config_data.max_hits_ceiling)
  {
    log(L_LOG_ERR, CONFIG,
   "server max-hits-default '%d' must be less than max-hits-ceiling '%d': %s",
        server_config_data.max_hits_default,
        server_config_data.max_hits_ceiling,
    examin_error_string(ERW_NUMRANGE));
    return FALSE;
  }

  if (*server_config_data.notify_log &&
      (errnum = examin_rwlog_file(server_config_data.notify_log)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server notify log file name '%s': %s",
        server_config_data.notify_log, examin_error_string(errnum));
    return FALSE;
  }
  if (*server_config_data.register_log &&
      (errnum = examin_rwlog_file(server_config_data.register_log)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server register log file name '%s': %s",
        server_config_data.register_log, examin_error_string(errnum));
    return FALSE;
  }
  if (*server_config_data.register_log &&
      (errnum = examin_rwlog_file(server_config_data.log_default_file)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server default log file name '%s': %s",
        server_config_data.log_default_file, examin_error_string(errnum));
    return FALSE;
  }

  if (*server_config_data.log_emerg_file &&
      (errnum = examin_rwlog_file(server_config_data.log_emerg_file)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server emergency log file name '%s': %s",
        server_config_data.log_emerg_file, examin_error_string(errnum));
    return FALSE;
  }
  if (*server_config_data.log_alert_file &&
      (errnum = examin_rwlog_file(server_config_data.log_alert_file)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server alert log file name '%s': %s",
        server_config_data.log_alert_file, examin_error_string(errnum));
    return FALSE;
  }
  if (*server_config_data.log_crit_file &&
      (errnum = examin_rwlog_file(server_config_data.log_crit_file)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server critical log file name '%s': %s",
        server_config_data.log_crit_file, examin_error_string(errnum));
    return FALSE;
  }
  if (*server_config_data.log_err_file &&
      (errnum = examin_rwlog_file(server_config_data.log_err_file)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server error log file name '%s': %s",
        server_config_data.log_err_file, examin_error_string(errnum));
    return FALSE;
  }
  if (*server_config_data.log_warn_file &&
      (errnum = examin_rwlog_file(server_config_data.log_warn_file)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server warning log file name '%s': %s",
        server_config_data.log_warn_file, examin_error_string(errnum));
    return FALSE;
  }
  if (*server_config_data.log_notice_file &&
      (errnum = examin_rwlog_file(server_config_data.log_notice_file)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server notice log file name '%s': %s",
        server_config_data.log_notice_file, examin_error_string(errnum));
    return FALSE;
  }
  if (*server_config_data.log_info_file &&
      (errnum = examin_rwlog_file(server_config_data.log_info_file)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server info log file name '%s': %s",
        server_config_data.log_info_file, examin_error_string(errnum));
    return FALSE;
  }
  if (*server_config_data.log_debug_file &&
      (errnum = examin_rwlog_file(server_config_data.log_debug_file)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid server debug log file name '%s': %s",
        server_config_data.log_debug_file, examin_error_string(errnum));
    return FALSE;
  }

  return TRUE;
}

/* checks for duplicates paths in the configuration. Returns non-zero value
   if duplicates found. If path not in the configuration then it is added
   to the paths_list. Class parse-programs, log file names are no added
   considered here. */
int
verify_main_config_paths(paths_list)
  dl_list_type *paths_list;
{
  int ret = 0;

  if (!paths_list) return( 1 );

  ret += dup_config_path_name(paths_list, server_config_data.root_dir,
                              I_ROOT_DIR);
  ret += dup_config_path_name(paths_list, server_config_data.bin_path,
                              I_BIN_PATH);
  ret += dup_config_path_name(paths_list, server_config_data.notify_log,
                              I_NOTIFY_LOG);
  ret += dup_config_path_name(paths_list, server_config_data.directive_file,
                              I_DIRECTIVE_FILE);
  ret += dup_config_path_name(paths_list, server_config_data.x_directive_file,
                              I_X_DIRECTIVE_FILE);
  ret += dup_config_path_name(paths_list, server_config_data.auth_area_file,
                              I_AUTH_AREA_FILE);
  ret += dup_config_path_name(paths_list, server_config_data.register_log,
                              I_REGISTER_LOG);
  ret += dup_config_path_name(paths_list, server_config_data.register_spool,
                              I_REGISTER_SPOOL);
  ret += dup_config_path_name(paths_list, server_config_data.punt_file,
                              I_PUNT_FILE);
  ret += dup_config_path_name(paths_list, server_config_data.security_allow,
                              I_SECURITY_ALLOW);
  ret += dup_config_path_name(paths_list, server_config_data.security_deny,
                              I_SECURITY_DENY);
  ret += dup_config_path_name(paths_list, server_config_data.pid_file,
                              I_PID_FILE);

  return( ret );
}

/* check to find out if any of the log file names and parse-program names
   are already in the configuration paths_list. Returns non-zero value
   on failure. */
int
verify_non_admin_paths(paths_list)
  dl_list_type *paths_list;
{
  int ret = 0;

  if (!paths_list) return( 1 );

  /* check if any log file name is already in use in the config */
  ret += in_config_path_list(paths_list, server_config_data.log_default_file,
                             I_LOG_DEFAULT_FILE);
  ret += in_config_path_list(paths_list, server_config_data.log_emerg_file,
                             I_LOG_EMERG);
  ret += in_config_path_list(paths_list, server_config_data.log_alert_file,
                             I_LOG_ALERT);
  ret += in_config_path_list(paths_list, server_config_data.log_crit_file,
                             I_LOG_CRIT);
  ret += in_config_path_list(paths_list, server_config_data.log_err_file,
                             I_LOG_ERR);
  ret += in_config_path_list(paths_list, server_config_data.log_warn_file,
                             I_LOG_WARN);
  ret += in_config_path_list(paths_list, server_config_data.log_notice_file,
                             I_LOG_NOTICE);
  ret += in_config_path_list(paths_list, server_config_data.log_info_file,
                             I_LOG_INFO);
  ret += in_config_path_list(paths_list, server_config_data.log_debug_file,
                             I_LOG_DEBUG);

  /* check if any class parse programs are in the list */
  ret += verify_aa_parse_progs(paths_list);

  return( ret );
}
