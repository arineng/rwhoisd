/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "security.h"

#ifdef USE_TCP_WRAPPERS
#include "../tools/tcpd_wrapper/tcpd.h"
#include "defines.h"
#endif /* USE_TCP_WRAPPERS */

#include "log.h"
#include "read_config.h"
#include "main_config.h"
#include "types.h"

/***************************************************************************
sets up a security playground by doing a chroot and setuid (taken
from W.Z. Venema's chrootuid code.

returns TRUE if ok
        FALSE otherwise
****************************************************************************/
int
setup_security()
{
  struct passwd *pwd    = NULL;
  char          *userid = NULL;
  int           id      = getuid();

  /* get the userid information *before* chrooting */
  userid = get_process_userid();
  if (id == 0 && STR_EXISTS(userid))
  {
    if ((pwd = getpwnam(userid)) == 0)
    {
      log(L_LOG_WARNING, CONFIG,
          "'%s' user id is unknown -- unable to change id", 
          userid);
    }
  }

  /* attempt to chroot(), if asked to do so */
  if (is_chrooted())
  {
    if (id != 0)
    {
      log(L_LOG_ERR, CONFIG, "Must be root to perform chroot");
    }

    /* now attempt to chroot() */
    if (chroot(get_root_dir())) {
      log(L_LOG_ERR, CONFIG, "chroot to (%s) failed: %s", get_root_dir(),
          strerror(errno));
      return FALSE;
    }

    /* now that we've chrooted, the root directory is now '/' only */
    set_root_dir("/");
    chdir_root_dir();
  }
  
  /* change the user id of the process, if we can */
  if (id == 0)
  {
    /* don't change user id if the value is NULL */
    if (STR_EXISTS(userid) && pwd)
    {
      /* change group id first */
      if (setgid(pwd->pw_gid))
      {
        log(L_LOG_ERR, CONFIG, "setup_security: setgid failed");
        return FALSE;
      }
      /* now change user id */
      if (setuid(pwd->pw_uid))
      {
        log(L_LOG_ERR, CONFIG, "setup_security: setuid failed");
        return (FALSE);
      }
      /* In case we still have the /etc/passwd file still open. */
      endpwent();
    }
    else
    {
      log(L_LOG_WARNING, CONFIG, "running as root");
    }
  }

  /* if we got this far, everything went OK */
  return TRUE;
}

/****************************************************************************
 restricts who can run the command
   returns TRUE if can
           FALSE if not
****************************************************************************/
int
authorized_directive(directive)
  char *directive;
{
#ifdef USE_TCP_WRAPPERS
  char                    *hosts_allow;
  char                    *hosts_deny;
  extern char             *hosts_allow_table;
  extern char             *hosts_deny_table;
#  ifdef HAVE_IPV6
  struct sockaddr_in      *sin;
  struct sockaddr_storage  ss;
  struct sockaddr_in6     *sin6;
  struct sockaddr         *sa;
  socklen_t                salen = sizeof ss;
  char                     addr[INET6_ADDRSTRLEN];
  char                     wrapper_addr[INET6_ADDRSTRLEN + 2];
  char                     client_name[NI_MAXHOST];
#  else
  struct request_info      req;
#  endif /* HAVE_IPV6 */
  
  hosts_allow = get_security_allow();
  hosts_deny  = get_security_deny();

  /* hosts_access from tcp_wrapper changed its interface to make it
     harder to change the access list files.  Fortunately, they are
     external global variables */

  hosts_allow_table = hosts_allow;
  hosts_deny_table  = hosts_deny;

#  ifdef HAVE_IPV6
  /* Do this the new way, which specifically knows how to format IPv6
     addresses. */
  
  /* get the client address */
  sa = (struct sockaddr *) &ss;
  if ( getpeername( 0, sa, &salen ) ) {
    log( L_LOG_ERR, CONFIG, "getpeername failed: %s", strerror( errno ) );
    return FALSE;
  }

  /* get the client hostname */
  if ( getnameinfo( sa, salen, client_name, sizeof client_name,
                    NULL, 0, 0 ) ) {
    log( L_LOG_WARNING, CONFIG, "getnameinfo failed: %s", strerror( errno ) );
  }
  log( L_LOG_DEBUG, CONFIG, "client hostname: %s", client_name );

  /* convert the address to a presentation format that tcp wrapper 
     understands */
  switch ( sa->sa_family ) {
    case AF_INET: {
      sin = (struct sockaddr_in *) sa;
      strncpy( wrapper_addr,
               inet_ntop( AF_INET, (void *) sin->sin_addr.s_addr, addr, 
                          sizeof addr ),
               sizeof wrapper_addr ) ;
    }
    case AF_INET6: {
      sin6 = (struct sockaddr_in6 *) sa;
      inet_ntop( AF_INET6, (void *) sin6->sin6_addr.s6_addr, addr, sizeof
                 addr );
      /* If it's an IPv4 mapped address, drop the leading '::ffff:' */
      if ( IN6_IS_ADDR_V4MAPPED( &(sin6->sin6_addr) ) )
        strncpy( wrapper_addr, addr + 7, sizeof wrapper_addr );
      /* otherwise surround the address with braces to hopefully match 
         what tcp wrapper expects */
      else sprintf( wrapper_addr, "%s", addr );
    }
  }
  log( L_LOG_WARNING, CONFIG, "client tcp wrapper address: %s", wrapper_addr );

  return( hosts_ctl( directive, client_name, wrapper_addr, STRING_UNKNOWN ) );
#  else /* HAVE_IPV6 */
  
  /* Do this the old way, which still seems to work */
  
  /* set up the request structure */
  request_init(&req, RQ_FILE, 0, RQ_DAEMON, directive, 0);
       
  /* fill in the client info */
  fromhost(&req);

  /* return the results of the access check */
  return(hosts_access(&req));
#  endif /* HAVE_IPV6 */

#else  /* USE_TCP_WRAPPERS */
  return TRUE;
#endif /* USE_TCP_WRAPPERS */
}

int
authorized_client()
{
  return( authorized_directive( "rwhoisd" ) );
}
