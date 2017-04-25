/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _MAIN_CONFIG_H_
#define _MAIN_CONFIG_H_

/* includes */

#include "common.h"
#include "defines.h"
#include "config_types.h"

/* defines */

#define I_DEFAULT_DIR       "default-dir"   /* same as "root-dir" */
#define I_ROOT_DIR          "root-dir"
#define I_BIN_LOC           "bin-loc"       /* same as "bin-path" */
#define I_BIN_PATH          "bin-path"
#define I_NOTIFY_LOG        "notify-log"
#define I_DIRECTIVE_FILE    "directive-file"
#define I_X_DIRECTIVE_FILE  "x-directive-file"
#define I_AUTH_AREA_FILE    "auth-area-file"
#define I_REGISTER_LOG      "register-log"
#define I_REGISTER_SPOOL    "register-spool"
#define I_PUNT_FILE         "punt-file"
#define I_SECURITY_ALLOW    "security-allow"
#define I_SECURITY_DENY     "security-deny"
#define I_HOSTNAME          "local-host"
#define I_PROC_USERID       "userid"
#define I_CHROOTED          "chrooted"
#define I_DEADMAN           "deadman-time"
#define I_MAX_HITS_CEILING  "max-hits-ceiling"
#define I_MAX_HITS_DEFAULT  "max-hits-default"
#define I_PORT              "local-port"
#define I_IS_ROOT_SERVER    "root-server"
#define I_SERVER_TYPE       "server-type"
#define I_BACKGROUND        "background"
#define I_VERBOSITY         "verbosity"
#define I_PID_FILE          "pid-file"
#define I_SERVER_CONTACT    "server-contact"
#define I_USE_SYSLOG        "use-syslog"
#define I_SYSLOG_FACILITY   "syslog-facility"
#define I_LOG_DEFAULT_FILE  "default-log-file"
#define I_LOG_EMERG         "emergency-log-file"
#define I_LOG_ALERT         "alert-log-file"
#define I_LOG_CRIT          "crit-log-file"
#define I_LOG_ERR           "err-log-file"
#define I_LOG_WARN          "warn-log-file"
#define I_LOG_NOTICE        "notice-log-file"
#define I_LOG_INFO          "info-log-file"
#define I_LOG_DEBUG         "debug-log-file"
#define I_QUERY_ALLOW_WILD  "query-allow-wildcard"
#define I_QUERY_ALLOW_SUBSTR "query-allow-substr"
#define I_MAX_CHILDREN      "max-children"
#define I_CIDR_SEARCH_DIR   "cidr-search-direction"
#define I_SKIP_REFERAL_SEARCH "skip-referral-search"
#define I_LISTEN_QUEUE      "listen-queue-length"
#define I_CHILD_PRIORITY    "child-priority-offset"

/* structures */

/* All data read from configuration file rwhois.conf at the
   server level.  For example, root-dir, deadman-time, etc */
typedef struct _server_config_struct
{
  char   root_dir[MAX_FILE];
  char   bin_path[MAX_FILE];
  char   notify_log[MAX_FILE];
  char   directive_file[MAX_FILE];
  char   x_directive_file[MAX_FILE];
  char   auth_area_file[MAX_FILE];
  char   register_log[MAX_FILE];
  char   register_spool[MAX_FILE];
  char   punt_file[MAX_FILE];
  char   security_allow[MAX_FILE];
  char   security_deny[MAX_FILE];
  char   hostname[MAX_LINE];
  char   process_userid[MAX_LINE];
  char   pid_file[MAX_FILE];
  char   log_default_file[MAX_FILE];
  char   log_emerg_file[MAX_FILE];
  char   log_alert_file[MAX_FILE];
  char   log_crit_file[MAX_FILE];
  char   log_err_file[MAX_FILE];
  char   log_warn_file[MAX_FILE];
  char   log_notice_file[MAX_FILE];
  char   log_info_file[MAX_FILE];
  char   log_debug_file[MAX_FILE];
  char   server_contact[MAX_LINE];
  int    use_syslog;
  int    log_facility;
  int    chrooted;
  int    default_deadman_time;
  int    max_hits_ceiling;
  int    max_hits_default;
  int    port;
  int    root_server;
  int    server_type;
  int    background;
  int    verbose;
  int    query_allow_wild;
  int    query_allow_substr;
  int    max_children;
  int    skip_referral_search;
  int    listen_queue_length;
  int    child_priority_offset;
} server_config_struct;


/*   All volatile data at the server level. For example,
   holdconnect status, etc.  Note that the contents of
   this structure are basically left up to the directives
   and other processes that need to keep globally visible
   dynamic type values.
 */
typedef struct _server_state_struct
{
  int    limit;
  int    holdconnect;
  int    forward;
  char   display[MAX_LINE];
} server_state_struct;

typedef enum
{
  DAEMON_SERVER,
  INETD_SERVER
} rwhois_server_type;


/* prototypes */

int read_main_config_file PROTO((char *config_file, int chrooted));

void init_server_config_data PROTO((void));
void init_server_state PROTO( (void));

int  verify_server_config_data PROTO((void));
void display_server_config_data PROTO((FILE *file));

int save_server_state PROTO((void));
int restore_server_state PROTO((void));

int  set_root_dir PROTO((char *dir));
char *get_root_dir PROTO((void));
int  chdir_root_dir PROTO((void));

int  set_bin_path PROTO((char *path));
char *get_bin_path PROTO((void));

int  set_notify_log PROTO((char *log));
char *get_notify_log PROTO((void));

int set_log_default PROTO((char *file));
char *get_log_default PROTO((void));

int set_log_facility PROTO((char *facility));
int get_log_facility PROTO((void));

int set_log_emerg PROTO((char *log));
char *get_log_emerg PROTO((void));

int set_log_alert PROTO((char *log));
char *get_log_alert PROTO((void));

int set_log_crit PROTO((char *log));
char *get_log_crit PROTO((void));

int set_log_err PROTO((char *log));
char *get_log_err PROTO((void));

int set_log_warn PROTO((char *log));
char *get_log_warn PROTO((void));

int set_log_notice PROTO((char *log));
char *get_log_notice PROTO((void));

int set_log_info PROTO((char *log));
char *get_log_info PROTO((void));

int set_log_debug PROTO((char *log));
char *get_log_debug PROTO((void));

int  set_directive_file PROTO((char *file));
char *get_directive_file PROTO((void));

int  set_x_directive_file PROTO((char *file));
char *get_x_directive_file PROTO((void));

int  set_auth_area_file PROTO((char *file));
char *get_auth_area_file PROTO((void));

int  set_register_log PROTO((char *log));
char *get_register_log PROTO((void));

int  set_register_spool PROTO((char *spool));
char *get_register_spool PROTO((void));

int  set_punt_file PROTO((char *file));
char *get_punt_file PROTO((void));

int  set_security_allow PROTO((char *file));
char *get_security_allow PROTO((void));

int  set_security_deny PROTO((char *file));
char *get_security_deny PROTO((void));

int  set_local_hostname PROTO((char *name));
char *get_local_hostname PROTO((void));

int  set_process_userid PROTO((char *id));
char *get_process_userid PROTO((void));

int  set_chrooted PROTO((int val));
int  set_chrooted_str PROTO((char *str));
int  is_chrooted PROTO((void));

int  set_use_syslog PROTO((char *str));
int  is_syslog_used PROTO((void));

int  set_default_deadman_time PROTO((int sec));
int  get_default_deadman_time PROTO((void));

int  set_max_hits_ceiling PROTO((int hits));
int  get_max_hits_ceiling PROTO((void));

int  set_max_hits_default PROTO((int hits));
int  get_max_hits_default PROTO((void));

int  set_port PROTO((int p));
int  get_port PROTO((void));

int  set_root_server PROTO((int val));
int  set_root_server_str PROTO((char *str));
int  is_root_server PROTO((void));

int  set_server_type PROTO((rwhois_server_type type));
int  set_server_type_str PROTO((char *str));
rwhois_server_type  get_server_type PROTO((void));
int  is_daemon_server PROTO((void));

int  set_background PROTO((int val));
int  get_background PROTO((void));

int  set_verbosity PROTO((int val));
int  get_verbosity PROTO((void));

int  set_config_file PROTO((char *file));
char *get_config_file PROTO((void));

int  set_pid_file PROTO((char *file));
char *get_pid_file PROTO((void));

int  set_server_contact PROTO((char *contact));
char *get_server_contact PROTO((void));

int  set_skip_referral_search PROTO((int val));
int  get_skip_referral_search PROTO((void));

int  set_listen_queue_length PROTO((int val));
int  get_listen_queue_length PROTO((void));

int  set_child_priority PROTO((int val));
int  get_child_priority PROTO((void));

/* server_state guards */
int  set_hit_limit PROTO((int limit));
int  get_hit_limit PROTO((void));

int  set_holdconnect PROTO((char *val));
int  get_holdconnect PROTO((void));

int  set_forward PROTO((char *val));
int  get_forward PROTO((void));

int  set_display PROTO((char *mode));
char *get_display PROTO((void));

int set_query_allow_wild PROTO((int val));
int get_query_allow_wild PROTO((void));

int set_query_allow_substr PROTO((int val));
int get_query_allow_substr PROTO((void));

int set_max_children PROTO((int val));
int get_max_children PROTO((void));

char *get_server_type_str PROTO((rwhois_server_type serv_type));

char *get_log_facility_str PROTO((int facility_val));

int write_main_config_file PROTO((char *file, char *suffix,
        rwhois_configs_struct *rwconf, dl_list_type *paths_list));

int examin_userid PROTO((char *uid));

int examin_rwlog_file PROTO((char *file));

int examin_rwconf_file PROTO((char *file));

int examin_rwconf_dir PROTO((char *path));

int examin_rwexe_file PROTO((char *file));

int examin_hostname PROTO((char *name));

int examin_server_contact PROTO((char *contact));

int verify_main_config PROTO((void));

int verify_main_config_paths PROTO((dl_list_type *paths_list));

int verify_non_admin_paths PROTO((dl_list_type *paths_list));

#endif /* _MAIN_CONFIG_H_ */
