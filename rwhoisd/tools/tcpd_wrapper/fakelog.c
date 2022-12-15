__END_DECLS openlog (char *name, int logopt, int facility)
{
    /* void */
}

/* vsyslog - format one record */

int vsyslog (int severity, char *fmt, va_list ap)
{
    char    buf[BUFSIZ];

    vprintf(percent_m(buf, fmt), ap);
    printf("\n");
    fflush(stdout);
}

/* syslog - format one record */

/* VARARGS */

VARARGS(syslog, int, severity)
{
    va_list ap;
    char   *fmt;

    VASTART(ap, int, severity);
    fmt = va_arg(ap, char *);
    vsyslog(severity, fmt, ap);
    VAEND(ap);
}

/* closelog - dummy */

int closelog (void)
{
    /* void */
}
