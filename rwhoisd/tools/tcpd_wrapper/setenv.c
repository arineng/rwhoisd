 /*
  * Some systems do not have setenv(). This one is modeled after 4.4 BSD, but
  * is implemented in terms of portable primitives only: getenv(), putenv()
  * and malloc(). It should therefore be safe to use on every UNIX system.
  * 
  * If clobber == 0, do not overwrite an existing variable.
  * 
  * Returns nonzero if memory allocation fails.
  * 
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  */

#include <stdio.h>
#include <string.h>
#ifndef lint
static char sccsid[] = "@(#) setenv.c 1.1 93/03/07 22:47:58";
#endif

#include <stdlib.h>

/* setenv - update or insert environment (name,value) pair */

int setenv (const char *__name, const char *__value, int __replace)
{
    void   *malloc(size_t size);
    char   *getenv(const char *name);
    char   *cp;

    if (__replace == 0 && getenv(__name) != 0)
	return (0);
    if ((cp = malloc(strlen(__name) + strlen(__value) + 2)) == 0)
	return (1);
    sprintf(cp, "%s=%s", __name, __value);
    return (putenv(cp));
}
