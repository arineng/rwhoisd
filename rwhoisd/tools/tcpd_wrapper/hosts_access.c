 /*
  * This module implements a simple access control language that is based on
  * host (or domain) names, NIS (host) netgroup names, IP addresses (or
  * network numbers) and daemon process names. When a match is found the
  * search is terminated, and depending on whether PROCESS_OPTIONS is defined,
  * a list of options is executed or an optional shell command is executed.
  * 
  * Host and user names are looked up on demand, provided that suitable endpoint
  * information is available as sockaddr_in structures or TLI netbufs. As a
  * side effect, the pattern matching process may change the contents of
  * request structure fields.
  * 
  * Diagnostics are reported through syslog(3).
  * 
  * Compile with -DNETGROUP if your library provides support for netgroups.
  * 
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  */

#ifndef lint
static char sccsid[] = "@(#) hosts_access.c 1.21 97/02/12 02:13:22";
#endif

/* System libraries. */

#define _XOPEN_SOURCE 500
#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <syslog.h>
#include <ctype.h>
#include <errno.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>

#ifndef HAVE_UCHAR_T
typedef unsigned char uchar_t;
#endif

extern char *fgets (char *__restrict __s, int __n, FILE *__restrict __stream);
extern int errno;

#ifndef	INADDR_NONE
#define	INADDR_NONE	(-1)		/* XXX should be 0xffffffff */
#endif

/* Local stuff. */

#include "tcpd.h"

/* Error handling. */

extern jmp_buf tcpd_buf;

/* Delimiters for lists of daemons or clients. */

static char sep[] = ", \t\r\n";

/* Constants to be used in assignments only, not in comparisons... */

#define	YES		1
#define	NO		0

 /*
  * These variables are globally visible so that they can be redirected in
  * verification mode.
  */

char   *hosts_allow_table = HOSTS_ALLOW;
char   *hosts_deny_table = HOSTS_DENY;
int     hosts_access_verbose = 0;

 /*
  * In a long-running process, we are not at liberty to just go away.
  */

int     resident = (-1);		/* -1, 0: unknown; +1: yes */

/* Forward declarations. */

static int table_match (char *table, struct request_info *request);
static int list_match (char *list, struct request_info *request, int (*match_fn)(char *tok, struct request_info *req));
static int server_match (char *tok, struct request_info *request);
static int client_match (char *tok, struct request_info *request);
static int host_match (char *tok, struct host_info *host);
static int string_match (char *tok, char *string);
static int masked_match (char *net_tok, char *mask_tok, char *string);
#ifdef HAVE_IPV6
static void ipv6_mask (struct in6_addr *in6p, int maskbits);
#endif

/* Size of logical line buffer. */

#define	BUFLEN 2048

/* hosts_access - host access control facility */

int hosts_access (struct request_info *request)
{
    int     verdict;

    /*
     * If the (daemon, client) pair is matched by an entry in the file
     * /etc/hosts.allow, access is granted. Otherwise, if the (daemon,
     * client) pair is matched by an entry in the file /etc/hosts.deny,
     * access is denied. Otherwise, access is granted. A non-existent
     * access-control file is treated as an empty file.
     * 
     * After a rule has been matched, the optional language extensions may
     * decide to grant or refuse service anyway. Or, while a rule is being
     * processed, a serious error is found, and it seems better to play safe
     * and deny service. All this is done by jumping back into the
     * hosts_access() routine, bypassing the regular return from the
     * table_match() function calls below.
     */

    if (resident <= 0)
	resident++;
    verdict = setjmp(tcpd_buf);
    if (verdict != 0)
	return (verdict == AC_PERMIT);
    if (table_match(hosts_allow_table, request))
	return (YES);
    if (table_match(hosts_deny_table, request))
	return (NO);
    return (YES);
}

/* table_match - match table entries with (daemon, client) pair */

static int table_match (char *table, struct request_info *request)
{
    FILE   *fp;
    char    sv_list[BUFLEN];		/* becomes list of daemons */
    char   *cl_list;			/* becomes list of clients */
    char   *sh_cmd;			/* becomes optional shell command */
    int     match = NO;
    struct tcpd_context saved_context;

    saved_context = tcpd_context;		/* stupid compilers */

    /*
     * Between the fopen() and fclose() calls, avoid jumps that may cause
     * file descriptor leaks.
     */

    if ((fp = fopen(table, "r")) != 0) {
	tcpd_context.file = table;
	tcpd_context.line = 0;
	while (match == NO && xgets(sv_list, sizeof(sv_list), fp) != 0) {
	    if (sv_list[strlen(sv_list) - 1] != '\n') {
		tcpd_warn("missing newline or line too long");
		continue;
	    }
	    if (sv_list[0] == '#' || sv_list[strspn(sv_list, " \t\r\n")] == 0)
		continue;
	    if ((cl_list = split_at(sv_list, ':')) == 0) {
		tcpd_warn("missing \":\" separator");
		continue;
	    }
	    sh_cmd = split_at(skip_ipv6_addrs(cl_list), ':');
	    match = list_match(sv_list, request, server_match)
		&& list_match(cl_list, request, client_match);
	}
	(void) fclose(fp);
    } else if (errno != ENOENT) {
	tcpd_warn("cannot open %s: %m", table);
    }
    if (match) {
	if (hosts_access_verbose > 1)
	    syslog(LOG_DEBUG, "matched:  %s line %d",
		   tcpd_context.file, tcpd_context.line);
	if (sh_cmd) {
#ifdef PROCESS_OPTIONS
	    process_options(sh_cmd, request);
#else
	    char    cmd[BUFSIZ];
	    shell_cmd(percent_x(cmd, sizeof(cmd), sh_cmd, request));
#endif
	}
    }
    tcpd_context = saved_context;
    return (match);
}

/* list_match - match a request against a list of patterns with exceptions */

static int list_match (char *list, struct request_info *request, int (*match_fn)(char *tok, struct request_info *req))
{
    char   *tok;

    /*
     * Process tokens one at a time. We have exhausted all possible matches
     * when we reach an "EXCEPT" token or the end of the list. If we do find
     * a match, look for an "EXCEPT" list and recurse to determine whether
     * the match is affected by any exceptions.
     */

    for (tok = strtok(list, sep); tok != 0; tok = strtok((char *) 0, sep)) {
	if (STR_EQ(tok, "EXCEPT"))		/* EXCEPT: give up */
	    return (NO);
	if (match_fn(tok, request)) {		/* YES: look for exceptions */
	    while ((tok = strtok((char *) 0, sep)) && STR_NE(tok, "EXCEPT"))
		 /* VOID */ ;
	    return (tok == 0 || list_match((char *) 0, request, match_fn) == 0);
	}
    }
    return (NO);
}

/* server_match - match server information */

static int server_match (char *tok, struct request_info *request)
{
    char   *host;

    if ((host = split_at(tok + 1, '@')) == 0) {	/* plain daemon */
	return (string_match(tok, eval_daemon(request)));
    } else {					/* daemon@host */
	return (string_match(tok, eval_daemon(request))
		&& host_match(host, request->server));
    }
}

/* client_match - match client information */

static int client_match (char *tok, struct request_info *request)
{
    char   *host;

    if ((host = split_at(tok + 1, '@')) == 0) {	/* plain host */
	return (host_match(tok, request->client));
    } else {					/* user@host */
	return (host_match(host, request->client)
		&& string_match(tok, eval_user(request)));
    }
}

/* host_match - match host name and/or address against pattern */

static int host_match (char *tok, struct host_info *host)
{
    char   *mask;

    /*
     * This code looks a little hairy because we want to avoid unnecessary
     * hostname lookups.
     * 
     * The KNOWN pattern requires that both address AND name be known; some
     * patterns are specific to host names or to host addresses; all other
     * patterns are satisfied when either the address OR the name match.
     */

    if (tok[0] == '@') {			/* netgroup: look it up */
#ifdef  NETGROUP
	static char *mydomain = 0;
	if (mydomain == 0)
	    yp_get_default_domain(&mydomain);
	return (innetgr(tok + 1, eval_hostname(host), (char *) 0, mydomain));
#else
	tcpd_warn("netgroup support is disabled");	/* not tcpd_jump() */
	return (NO);
#endif
    } else if (STR_EQ(tok, "KNOWN")) {		/* check address and name */
	char   *name = eval_hostname(host);
	return (STR_NE(eval_hostaddr(host), unknown) && HOSTNAME_KNOWN(name));
    } else if (STR_EQ(tok, "LOCAL")) {		/* local: no dots in name */
	char   *name = eval_hostname(host);
	return (strchr(name, '.') == 0 && HOSTNAME_KNOWN(name));
#ifdef HAVE_IPV6
    } else if (tok[0] == '[') {			/* IPv6 address */
	    struct in6_addr in6, hostin6, *hip;
	    char *cbr;
	    char *slash;
	    int mask = IPV6_ABITS;

	    /*
	     * In some cases we don't get the sockaddr, only the addr.
	     * We use inet_pton to convert it to its binary representation
	     * and match against that.
	     */
	    if (host->sin == NULL) {
		if (host->addr == NULL ||
		    inet_pton(AF_INET6, host->addr, &hostin6) != 1) {
		    return (NO);
		}
		hip = &hostin6;
	    } else {
		if (SGFAM(host->sin) != AF_INET6)
		    return (NO);
		hip = &host->sin->sg_sin6.sin6_addr;
	    }

	    if (cbr = strchr(tok, ']'))
		*cbr = '\0';

	    /*
	     * A /nnn prefix specifies how many bits of the address we
	     * need to check. 
	     */
	    if (slash = strchr(tok, '/')) {
		*slash = '\0';
		mask = atoi(slash+1);
		if (mask < 0 || mask > IPV6_ABITS) {
		    tcpd_warn("bad IP6 prefix specification");
		    return (NO);
		}
		/* Copy, because we need to modify it below */
		if (host->sin != NULL) {
		    hostin6 = host->sin->sg_sin6.sin6_addr;
		    hip = &hostin6;
		}
	    }

	    if (cbr == NULL || inet_pton(AF_INET6, tok+1, &in6) != 1) {
		tcpd_warn("bad IP6 address specification");
		return (NO);
	    }
	    /*
	     * Zero the bits we're not interested in in both addresses
	     * then compare.  Note that we take a copy of the host info
	     * in that case.
	     */
	    if (mask != IPV6_ABITS) {
		ipv6_mask(&in6, mask);
		ipv6_mask(hip, mask);
	    }
	    if (memcmp(&in6, hip, sizeof(in6)) == 0)
		return (YES);
	    return (NO);
#endif
    } else if ((mask = split_at(tok, '/')) != 0) {	/* net/mask */
	return (masked_match(tok, mask, eval_hostaddr(host)));
    } else {					/* anything else */
	return (string_match(tok, eval_hostaddr(host))
	    || (NOT_INADDR(tok) && string_match(tok, eval_hostname(host))));
    }
}

/* string_match - match string against pattern */

static int string_match (char *tok, char *string)
{
    int     n;

    if (tok[0] == '.') {			/* suffix */
	n = strlen(string) - strlen(tok);
	return (n > 0 && STR_EQ(tok, string + n));
    } else if (STR_EQ(tok, "ALL")) {		/* all: match any */
	return (YES);
    } else if (STR_EQ(tok, "KNOWN")) {		/* not unknown */
	return (STR_NE(string, unknown));
    } else if (tok[(n = strlen(tok)) - 1] == '.') {	/* prefix */
	return (STRN_EQ(tok, string, n));
    } else {					/* exact match */
	return (STR_EQ(tok, string));
    }
}

/* masked_match - match address against netnumber/netmask */

static int masked_match (char *net_tok, char *mask_tok, char *string)
{
    unsigned long net;
    unsigned long mask;
    unsigned long addr;

    /*
     * Disallow forms other than dotted quad: the treatment that inet_addr()
     * gives to forms with less than four components is inconsistent with the
     * access control language. John P. Rouillard <rouilj@cs.umb.edu>.
     */

    if ((addr = dot_quad_addr(string)) == INADDR_NONE)
	return (NO);
    if ((net = dot_quad_addr(net_tok)) == INADDR_NONE
	|| (mask = dot_quad_addr(mask_tok)) == INADDR_NONE) {
	tcpd_warn("bad net/mask expression: %s/%s", net_tok, mask_tok);
	return (NO);				/* not tcpd_jump() */
    }
    return ((addr & mask) == net);
}

#ifdef HAVE_IPV6
/*
 * Function that zeros all but the first "maskbits" bits of the IPV6 address
 * This function can be made generic by specifying an address length as
 * extra parameter. (So Wietse can implement 1.2.3.4/16)
 */
static void ipv6_mask (struct in6_addr *in6p, int maskbits)
{
    uchar_t *p = (uchar_t*) in6p;

    if (maskbits < 0 || maskbits >= IPV6_ABITS)
	return;

    p += maskbits / 8;
    maskbits %= 8;

    if (maskbits != 0)
	*p++ &= 0xff << (8 - maskbits);

    while (p < (((uchar_t*) in6p)) + sizeof(*in6p))
	*p++ = 0;
}
#endif
