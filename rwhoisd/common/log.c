/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "log.h"

#include "client_msgs.h"
#include "compat.h"
#include "defines.h"
#include "main_config.h"
#include "misc.h"
#include "types.h"

/* local globals */
static int                  log_setup = FALSE;
static log_context_struct   context;


char *timestamp PROTO((void));

/* examin messages structure */
typedef struct _examin_mesg_struct {
  int  err_num;
  char *mesg;
} examin_mesg_struct;

static examin_mesg_struct examin_mesgs[] = {
  {ERW_NOFILE,   "file does not exist"},
  {ERW_NOPROG,   "program does not exist"},
  {ERW_NODIR,    "directory does not exist"},
  {ERW_FMTFILE,  "not a valid file name format"},
  {ERW_FMTDIR,   "not a valid directory name format"},
  {ERW_UNDROOT,  "path not under server root directory"},
  {ERW_NDEF,     "not defined"},
  {ERW_IDSTR,    "not an identifier string"},
  {ERW_EMTYSTR,  "empty string"},
  {ERW_FMTSERV,  "expecting 'hostname:port' server format"},
  {ERW_NUMSTR,   "not a numerical string"},
  {ERW_FMTMAIL,  "not a valid email format"},
  {ERW_SPACESTR, "string has white-spaces"},
  {ERW_SHORTSTR, "string too short"},
  {ERW_LONGSTR,  "string too long"},
  {ERW_XPRESTR,  "expecting a 'X-' prefix"},
  {ERW_EXEPROG,  "not an executable program"},
  {ERW_WTRDIR,   "directory is not writable"},
  {ERW_LENSTR,   "string length does not match expected length '17'"},
  {ERW_DNSSTR,   "not a valid dns host name"},
  {ERW_PUNTSTR,  "not a valid punt referral format"},
  {ERW_NUMVAL,   "value less than '1' is not valid"},
  {ERW_NUMRANGE, "value is out of range"},
  {ERW_FILEWSN,  "file exists with same name"},
  {ERW_DIRWSN,   "directory exists with same name"},
};

static int n_examin_mesgs = sizeof(examin_mesgs)/sizeof(*examin_mesgs);

log_context_struct *
get_log_context()
{
  return(&context);
}

int
set_log_context(file, line_num, section)
  char          *file;
  long          line_num;
  log_section   section;
{
  if (STR_EXISTS(file))
  {
    strncpy(context.cur_file, file, MAX_FILE);
  }

  if (line_num >= 0)
  {
    context.cur_line_num = line_num;
  }
    
  if (section >= 0)
  {
    context.cur_section = section;
  }

  return TRUE;
}

void
clear_log_context()
{
  bzero(&context, sizeof(context));
}

void
save_log_context(log_context_struct *save)
{
  bcopy(&context, save, sizeof(*save));
}

void
restore_log_context(log_context_struct *save)
{
  bcopy(save, &context, sizeof(context));
}

void
inc_log_context_line_num(inc)
  int inc;
{
  context.cur_line_num += inc;
}

char *
file_context_str()
{
  static char buf[MAX_LINE];

  if (NOT_STR_EXISTS(context.cur_file))
  {
    return "";
  }

  if (context.cur_line_num >= 0)
  {
    sprintf(buf, "(%s:%ld)", context.cur_file, context.cur_line_num);
  }
  else
  {
    sprintf(buf, "(%s)", context.cur_file);
  }

  return(buf);
}

/* log_error: prints a error message to the console. This is intended
     for server side errors only. */
void
#ifndef HAVE_STDARG_H
log_error(va_alist)
  va_dcl
#else
log_error(char *format, ...)
#endif
{
  va_list   list;
  char      err_buf[MAX_LINE];
#ifndef HAVE_STDARG_H
  char      *format;
  va_start(list);
  format = va_arg(list, char *);
#else
  va_start(list, format);
#endif

#ifdef HAVE_VSNPRINTF
  vsnprintf(err_buf, sizeof(err_buf), format, list);
#else
  vsprintf(err_buf, format, list);
#endif
  
  va_end(list);

  log(L_LOG_ERR, OLD_STYLE, "error: %s\n", err_buf);
}


/* log_warning: prints a warning message to the console. This is intended
   for server side warnings only. */
void
#ifndef HAVE_STDARG_H
log_warning(va_alist)
  va_dcl
#else
log_warning(char *format, ...)
#endif
{
  va_list   list;
  char      err_buf[MAX_LINE];
#ifndef HAVE_STDARG_H
  char      *format;
  
  va_start(list);
  format = va_arg(list, char *);
#else
  va_start(list, format);
#endif

#ifdef HAVE_VSNPRINTF
  vsnprintf(err_buf, sizeof(err_buf), format, list);
#else
  vsprintf(err_buf, format, list);
#endif
  
  va_end(list);

  log(L_LOG_WARNING, OLD_STYLE, "warning: %s\n", err_buf);
}


/* gets hostname of the *client* */
char *
get_client_hostname(sock)
  int sock;             /* peer socket */
{
  static char           buf[MAX_LINE];
  static int            tried_once = FALSE;
#ifdef HAVE_SOCKADDR_STORAGE
  struct sockaddr_storage   name;
  struct sockaddr_in6   *name2;
  struct sockaddr_in    *name3;
#else
  struct sockaddr_in    name;
#endif
  int                   namelen = sizeof(name);


  if (tried_once)
  {
    return (buf);
  }

  tried_once = TRUE;

  if (getpeername(sock, (struct sockaddr *)&name, &namelen) != 0)
  {
    if( errno == EBADF || 
        errno == ENOTCONN || 
        errno == ENOTSOCK || 
        errno == EINVAL)
    {
      log(L_LOG_ERR, LOG, 
          "error: get_client_hostname not given a real socket: %s", 
          strerror(errno));
      strcpy(buf,"<no host>");
      return(buf);
    }
    else
    {
      log(L_LOG_ERR, LOG, 
          "error: get_client_hostname error looking up host: %d:%s", errno,
          strerror(errno));
      strcpy(buf,"<error>");
      return(buf);
    }
  }
  else
  {
#ifdef HAVE_IPV6
    name2 = (struct sockaddr_in6 *)&name;

    if ( name2->sin6_family == AF_INET6 ){
	inet_ntop( name2->sin6_family, &(name2->sin6_addr),
                   buf, sizeof buf );
    } else {
	name3 = (struct sockaddr_in *)&name;
	sprintf(buf, "%s", inet_ntoa( name3->sin_addr) );
    }
#else
    sprintf(buf, "%s", inet_ntoa(name.sin_addr) );
#endif
  }

  return (buf);
}

/* logs time of query */
char *
timestamp()
{
  time_t        now;
  struct tm     *ts;
  static char   val[16];
  static char   *months[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
  };

  now = time((time_t*)NULL);      /* current time */
  ts  = localtime(&now);          /* get now in pieces */

  /* trying to emulate syslog format */
  sprintf(val, "%s %2d %02d:%02d:%02d", months[ts->tm_mon], ts->tm_mday,
          ts->tm_hour, ts->tm_min, ts->tm_sec);

  return(val);
}
 
char *
section_to_name(section)
  log_section  section;
{
  char  *ret_val;
 
  switch (section)
  {
  case NET:
    ret_val = "NETWORK";
    break;
  case CLIENT:
    ret_val = "CLIENT";
    break;
  case MKDB:
    ret_val = "MKDB";
    break;
  case CONFIG:
    ret_val = "CONFIG";
    break;
  case OLD_STYLE:
    ret_val = "OLD_STYLE";
    break;
  case QUERY:
    ret_val = "QUERY";
    break;
  case REFERRAL:    /* referrals, where to, how many local   */
    ret_val = "REFERRAL";
    break;
  case SECONDARY:   /* secondary connects, commands, usage   */
    ret_val = "SECONDARY";
    break;
  case REDUCTION:   /* reduction statistics, errors          */
    ret_val = "REDUCTION";
    break;
  case FILES:       /* corrupt files, file usage, part of mkdb? */
    ret_val = "FILES";
    break;
  case LOG:
    ret_val = "LOG";
    break;
  case DIRECTIVES:
    ret_val = "DIRECTIVES";
    break;
  case UNKNOWN:
    ret_val = "NONE";
    break;
  default:
    log(L_LOG_ERR,LOG,
        "section_to_name: given wrong log section: %d",
        section);
    ret_val = "UNKNOWN";
    break;
  }

  return(ret_val);
}
 
char *
level_to_name(local_level)
  internal_log_levels local_level;
{
  switch(local_level)
  {
  case L_LOG_EMERG:
    return("emerg");
  case L_LOG_ALERT:
    return("alert");
  case L_LOG_CRIT:
    return("crit");
  case L_LOG_ERR:
    return("error");
  case L_LOG_WARNING:
    return("warning");
  case L_LOG_NOTICE:
    return("notice");
  case L_LOG_INFO:
    return("info");
  case L_LOG_DEBUG:
    return("debug");
  }
  
  return("unknown");
}

int
local_to_syslog(local_level)
  internal_log_levels local_level;
{
  switch(local_level)
  {
  case L_LOG_EMERG:
    return(LOG_EMERG);
  case L_LOG_ALERT:
    return(LOG_ALERT);
  case L_LOG_CRIT:
    return(LOG_CRIT);
  case L_LOG_ERR:
    return(LOG_ERR);
  case L_LOG_WARNING:
    return(LOG_WARNING);
  case L_LOG_NOTICE:
    return(LOG_NOTICE);
  case L_LOG_INFO:
    return(LOG_INFO);
  case L_LOG_DEBUG:
    return(LOG_DEBUG);
  default:
    log(L_LOG_WARNING,LOG,
        "local_to_syslog: invalid level: %d\n",local_level);
    return(-1);
  }
}
 
 
char *
get_log_filename(level)
  internal_log_levels level;
{
  char *ret;

  switch(level)
  {
  case L_LOG_EMERG:
    ret = get_log_emerg();
    break;
  case L_LOG_ALERT:
    ret = get_log_alert();
    break;
  case L_LOG_CRIT:
    ret = get_log_crit();
    break;
  case L_LOG_ERR:
    ret = get_log_err();
    break;
  case L_LOG_WARNING:
    ret = get_log_warn();
    break;
  case L_LOG_NOTICE:
    ret = get_log_notice();
    break;
  case L_LOG_INFO:
    ret = get_log_info();
    break;
  case L_LOG_DEBUG:
    ret = get_log_debug();
    break;
  default:
    log(L_LOG_ERR,
        0,
        "get_log_filename was given an invalid level %d",
        level);
    return(NULL);
  }

  if (ret && *ret)
  {
    return(ret);
  }
  else
  {
    ret = get_log_default();
    return(ret);
  }
}
 
void
setup_logging()
{
#ifndef NO_SYSLOG
  openlog("rwhoisd", LOG_PID, get_log_facility());
#endif

  log_setup = TRUE;
  
  log(L_LOG_INFO, LOG, "logging setup");
}
 
/*
    get the value of log_setup variable
 */
int
get_log_setup()
{       
  return( log_setup );
}
  
/* this function returns the error string corresponding to the error number
   given. It stuffs the error number into the string before returning. 
   The error numbers correspond to return values of examin_?? functions. */
char *
examin_error_string(err_num)
  int err_num;
{
  int         i;
  static char buff[BUFSIZ]; 
  char        numstr[BUFSIZ];
  
  sprintf(numstr, "[E:%d]", err_num);
  for (i = 0; i < n_examin_mesgs; i++) 
  {
    if (examin_mesgs[i].err_num == err_num)
    {
      bzero(buff, sizeof(buff));
      strncpy(buff, examin_mesgs[i].mesg, sizeof(buff)-1);
      strncat(buff, " ", sizeof(buff)-1);
      strncat(buff, numstr, sizeof(buff)-1);

      return( buff ); 
    }
  }
  
  bzero(buff, sizeof(buff));
  strncpy(buff, "unknown ", sizeof(buff)-1);
  strncat(buff, numstr, sizeof(buff)-1);
  return( buff );
}
