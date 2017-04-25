 /*
  * hosts_info() returns a string with as much information about the origin
  * of a connection as we have: the user name, if known, and the host name,
  * or the host address if the name is not available.
  * 
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  */

#ifndef lint
static char sccsid[] = "@(#) hosts_info.c 1.1 92/06/11 22:21:44";
#endif

#include <stdio.h>

#include "log_tcp.h"

/* hosts_info - return string with as much about the client as we know */

char   *hosts_info(client)
struct from_host *client;
{
    static char buf[BUFSIZ];		/* XXX */

    if (client->user[0] && strcmp(client->user, FROM_UNKNOWN)) {
	sprintf(buf, "%s@%s", client->user, FROM_HOST(client));
	return (buf);
    } else {
	return (FROM_HOST(client));
    }
}
