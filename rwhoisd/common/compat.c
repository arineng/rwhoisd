/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "compat.h"

/* attempt to get the local hostname; returns a static string */

/*    sekiya@ISI.EDU (IPv6 conversion):
 *    I don't modify this function. This function includes gethostbyname
 *    which is IPv4 only function. But in this function, gethostbuname
 *    is used in order to get local FQDN name. I think it has no need to
 *    modify only in order to get local FQDN.
 */
char *sys_gethostname (void)
{
  static char       hostname[MAX_HOSTNAME + 1];
  struct hostent    *hp;

  /* first we get the base hostname */

#ifdef HAVE_GETHOSTNAME
  gethostname(hostname, MAX_HOSTNAME);
#else /* HAVE_GETHOSTNAME */
#ifdef HAVE_UNAME
  struct utsname uts;
  uname (&uts);
  hostname = strncpy(hostname, uts.nodename, MAX_HOSTNAME);
#else
  strncpy(hostname, "UNKNOWN", MAX_HOSTNAME);
#endif /* HAVE_UNAME */
#endif /* HAVE_GETHOSTNAME */


  /* now we attempt to get the FQDN */
  hp = gethostbyname(hostname);
  if (hp)
  {
    char *fqdn = (char *) hp->h_name;

    if (!index (fqdn, '.'))
    {
      /* We still don't have a fully qualified domain name.
         Try to find one in the list of alternate names */
      char **alias = hp->h_aliases;
      while (*alias && !index (*alias, '.'))
        alias++;
      if (*alias)
        fqdn = *alias;
    }
    strncpy(hostname, fqdn, MAX_HOSTNAME);

  }
  return(hostname);
}

int
sys_file_lock(
  int           fd,
  file_lock_t   op)
{
  /* we should have one or the other (flock or lockf) always */
#ifdef HAVE_LOCKF
  if (op == FILE_LOCK) {
    return(lockf(fd, F_LOCK, 0));
  }
  else if (op == FILE_UNLOCK) {
    return(lockf(fd, F_ULOCK, 0));
  }
  else if (op == FILE_TEST) {
    return(lockf(fd, F_TEST, 0));
  }
#elif HAVE_FLOCK
  if (op == FILE_LOCK) {
    return(flock(fd, LOCK_EX));
  }
  else if (op == FILE_UNLOCK) {
    return(flock(fd, LOCK_UN));
  }
  else if (op == FILE_TEST) {
    return(flock(fd, LOCK_SH | LOCK_NB));
  }
#else /* we can't do file locking */
  return(-1);
#endif /* HAVE_FLOCK */
  else {
    return(-1);
  }
}
