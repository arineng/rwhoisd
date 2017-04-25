/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */


/* 0 all critical errors                                                     */
/* 1 warnings (older clients trying to use the new register directive)       */
/* 2 info (list the connects from a host)                                    */
/* 3 more-info (show the directives/queries by the client)                   */
/* 4 detailed info (ie logging the query reduction queries)                  */
/* 5 more-detailed info (all the above plus listing the answers)             */
/*****************************************************************************/
 
#ifndef _LOG_H_
#define _LOG_H_

/* includes */

#include "common.h"
#include "types.h"

/* types */
 
typedef enum
{
  L_LOG_EMERG,
  L_LOG_ALERT,
  L_LOG_CRIT,
  L_LOG_ERR,
  L_LOG_WARNING,
  L_LOG_NOTICE,
  L_LOG_INFO,
  L_LOG_DEBUG
} internal_log_levels;

typedef enum
{
  NET,
  QUERY,
  CONFIG,
  MKDB,
  REFERRAL,
  SECONDARY,
  REDUCTION,
  CLIENT,
  OLD_STYLE,
  LOG,
  DIRECTIVES,
  FILES,
  UNKNOWN
} log_section;

typedef enum
{
  ERW_NOFILE = 1,
  ERW_NOPROG,
  ERW_NODIR,
  ERW_FMTFILE,
  ERW_FMTDIR,
  ERW_UNDROOT,
  ERW_NDEF,
  ERW_IDSTR,
  ERW_EMTYSTR,
  ERW_FMTSERV,
  ERW_NUMSTR,
  ERW_FMTMAIL,
  ERW_SPACESTR,
  ERW_SHORTSTR,
  ERW_LONGSTR,
  ERW_XPRESTR,
  ERW_EXEPROG,
  ERW_WTRDIR,
  ERW_LENSTR,
  ERW_DNSSTR,
  ERW_PUNTSTR,
  ERW_NUMVAL,
  ERW_NUMRANGE,
  ERW_FILEWSN,
  ERW_DIRWSN
} examin_nums;

typedef struct _log_context_struct
{
  long          cur_line_num;
  log_section   cur_section;
  char          cur_file[1024];
} log_context_struct;


/* old prototypes for backward compatibility */

#define l_strerror strerror
#ifndef HAVE_STDARG_H
	void log_error PROTO(());
	void log_warning PROTO(());
#else
	void log_error(char *, ...);
	void log_warning(char *, ...);
#endif
char *get_client_hostname PROTO((int sock));
char *timestamp PROTO(());

/* new prototypes for new syslog support                                     */

/* log(LEVEL, SECTION, FORMAT, ARGS) where LEVEL is one of
     (L_LOG_EMERG, L_LOG_ALERT, etc. [see internal_log_level in
     types.h) and SECTION is one of (NETWORK, QUERY, CONFIG, etc [see
     log_section in types.h) */
#ifndef HAVE_STDARG_H
	void log PROTO(());
#else
	void log (internal_log_levels, int, char *, ...);
#endif

void setup_logging PROTO((void));

log_context_struct *get_log_context PROTO((void));

int set_log_context PROTO((char *file, long line_num, log_section section));

void clear_log_context PROTO((void));

void save_log_context PROTO((log_context_struct *save));

void restore_log_context PROTO((log_context_struct *save));

void inc_log_context_line_num PROTO((int inc));

char *file_context_str PROTO((void));

int get_log_setup PROTO((void));

char *level_to_name(internal_log_levels local_level);

char *section_to_name(log_section section);

char *get_log_filename(internal_log_levels level);

int local_to_syslog(internal_log_levels local_level);

char *examin_error_string PROTO((int err_num));

#endif /* _LOG_H_ */
