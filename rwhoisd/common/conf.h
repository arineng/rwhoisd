/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */



/* ****************** USER CONFIGURABLE CHANGES ******************** */

/* This is the directory that all relative paths are relative from.
   It is normally not necessary to set this to anything, but this can
   be set if you wish to default *everything* and run without a
   conf. file.  That is, "" is equivalent to the current directory. */
#define RWHOIS_ROOT_DIR ""

/* Note that relative pathnames (or bare filenames) are considered to
   be relative (or in) the rwhois root directory */

/* the location for the logging file, when not using syslog */
#define DEFAULT_RWHOIS_LOG_FILE  "rwhoisd.log"

/* the location for the configuration file */
#define DEFAULT_RWHOIS_CONFIG_FILE "rwhoisd.conf"

/* the path where the binaries run from the server are located
   (think "cgi-bin path") */
#define DEFAULT_BIN_PATH "bin"

/* the file that the badref, recuref stuff gets logged */
/* this is currently unused */
/* #define DEFAULT_NOTIFY_LOG "notify.log" */

/* the file that contains X- directive definitions */
#define DEFAULT_X_DIRECTIVE_FILE "rwhoisd.x.dir"

/* the file that contains directive options */
#define DEFAULT_DIRECTIVE_FILE "rwhoisd.dir"

/* the top-level file describing the database schema */
#define DEFAULT_AUTH_AREA_FILE "rwhoisd.auth_area"

/* the file that register commands will be logged to */
/* this is currently unused */
/* #define DEFAULT_REGISTER_LOG "register.log" */

/* the temporary directory used in the register process */
#define DEFAULT_REGISTER_SPOOL "register_spool"

/* the punt file */
#define DEFAULT_PUNT_FILE "rwhoisd.root"

/* the file describing what hosts are allowed to do what
   directives */
#define DEFAULT_SECURITY_ALLOW "hosts.allow"

/* the file describing what hosts are not allowed to do what
   directives */
#define DEFAULT_SECURITY_DENY "hosts.deny"

/* the port to listen to */
#define DEFAULT_PORT 4321

/* the idle time, in seconds */
#define DEFAULT_DEADMAN_TIME 200

/* max number of hits allowed to set to */
#define CEILING_MAX_HITS 2048

/* default maximum number of hits - change with -limit command */
#define DEFAULT_MAX_HITS 20

/* default rwhois pid file - hold server process id */
#define DEFAULT_PID_FILE "rwhoisd.pid"

/* default server contact - admin contact */
#define DEFAULT_SERVER_CONTACT " "

/* default syslog facility */
#define DEFAULT_LOG_FACILITY "LOG_DAEMON"

/* whether or not the server attempts to chroot by default */
#define DEFAULT_CHROOT  FALSE

/* whether to run standalone or from inetd (standalone recommended) */
#define DEFAULT_SERVER_TYPE DAEMON_SERVER

/* the lowest level to log; set to L_LOG_DEBUG to get verbose logging */
#define DEFAULT_VERBOSITY  L_LOG_INFO

/* whether or not to use syslog */
/* #define DEFAULT_USE_SYSLOG "NO" */
#define DEFAULT_USE_SYSLOG "YES"

/* whether or not to allow wildcards in queries at all */
#define DEFAULT_QUERY_ALLOW_WILD TRUE

/* whether or not to allow queries that result in inefficient
   substring searches (query strings start with a wildcard) */
#define DEFAULT_QUERY_ALLOW_SUBSTR FALSE

/* where the client software is (for -forward) */
#define DEFAULT_CLIENT_PROG "/usr/local/bin/rwhois"

/* server_state_default */
#define DEFAULT_HOLDCONNECT "OFF"
#define DEFAULT_FORWARD     "OFF"
#define DEFAULT_DISPLAY     "DUMP" /* not much choice here :-) */

/* the maximum number of children, if a daemon.  0 means no limit */
#define DEFAULT_MAX_CHILDREN 0

/* define this if you wish to use system file locking (lockf() or
   flock()) for basic concurrency control during registration.  This
   is more efficient and reliable, normally, but may not work at all
   over NFS.
   Note: This should now be handled by autoconf entirely. */
/* #define USE_SYS_LOCK 1 */

/* ****************** END USER CONFIGURABLE CHANGES ************** */

/*  compliant RWhois protocol version - leave alone */
#define RWHOIS_PROTOCOL_VERSION "1.5"

