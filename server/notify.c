/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "notify.h"

#include "client_msgs.h"
#include "types.h"

#include "defines.h"
#include "fileutils.h"
#include "holdconnect.h"
#include "log.h"
#include "main_config.h"
#include "misc.h"

/**************************************************************************
  records the bad referrral
**************************************************************************/

/* -notify directive: 
 * Input:  -notify badref [referral-url query]
 *         -notify recurref [referral-url query]
 *         -notify update [host-port:auth_area]
 *         -notify inssec [host-port:auth_area]
 *         -notify delsec [host-port:auth_area]
 * Output:
 *         %ok     
 *         %error <err-num> <error>
 */


int notify_directive (char *str)
{
  char  word[MAX_LINE];
  char  *cp;
  char  *next;

  cp   = str;
  next = get_word(cp, word);

  if ( !*str || !*next)
  {
    print_error(INVALID_DIRECTIVE_PARAM, "");
    return FALSE;
  }

  log(L_LOG_DEBUG, CLIENT, "notify directive: %s", str);
  
  if (STR_EQ(word, "badref"));
  else if (STR_EQ(word, "recurref"));
  else if (STR_EQ(word, "update"));
  else if (STR_EQ(word, "inssec"));
  else if (STR_EQ(word, "delsec"));
  else if (STR_EQ(word, "badref"));
  else
  {
    print_error(INVALID_DIRECTIVE_PARAM, "");
    return FALSE;
  }

  /* FIXME: for now, log all the information to syslog */
  log(L_LOG_INFO, REFERRAL, "%s: %s", word, next);

/*   print_ok(); */
  return(TRUE);
}

/* log notify information */
int
#ifndef HAVE_STDARG_H
log_entry(va_alist)
  va_dcl
#else
log_entry(char *filename, char *format, ...)
#endif
{
  va_list   ap;
  FILE      *fp;
  char      *hostname;
#ifndef HAVE_STDARG_H
  char      *format;
  char      *filename;

  va_start(ap);
  filename  = va_arg (ap, char*);
  format    = va_arg(ap, char*);
#else
  va_start(ap, format);
#endif
  /* lock the file */
  fp = get_file_lock(filename, "a", 60);
  if (!fp)
  {
    log(L_LOG_ERR, DIRECTIVES, "could not open file '%s' for writing: %s",
              filename, strerror(errno));
	va_end(ap);
    return FALSE;
  }

  hostname = get_client_hostname(1);  /* fileno of stdout is the client sock */

  fprintf(fp, "%s  ", timestamp());
  fprintf(fp, " [%-15s] PID: %-8d", hostname, (int) getpid());
  vfprintf(fp, format, ap);
  fprintf(fp, "\n");

  release_file_lock(filename, fp);

	va_end(ap);
  return (TRUE);
}

