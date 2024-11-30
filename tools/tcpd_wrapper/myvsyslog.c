/*
  * vsyslog() for sites without. In order to enable this code, build with
  * -Dvsyslog=myvsyslog. We use a different name so that no accidents will
  * happen when vsyslog() exists. On systems with vsyslog(), syslog() is
  * typically implemented in terms of vsyslog().
  *
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  */

#ifndef lint
static char sccsid[] = "@(#) myvsyslog.c 1.1 94/12/28 17:42:33";
#endif

#ifdef vsyslog

#include <stdio.h>
#include <syslog.h>

#include "tcpd.h"
#include "mystdarg.h"
void myvsyslog(int __pri, const char *__fmt, __gnuc_va_list __ap)
{
    char    fbuf[BUFSIZ];
    char    obuf[3 * STRING_LENGTH];

    vsprintf(obuf, percent_m(fbuf, __fmt), __ap);
    syslog(__pri, "%s", obuf);
}

#endif
