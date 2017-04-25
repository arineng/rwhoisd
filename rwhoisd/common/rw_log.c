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

void
#ifndef HAVE_STDARG_H
log(va_alist)
  va_dcl
#else
log(internal_log_levels level, int section, char *format, ...)
#endif
{
  va_list             ap;
  FILE                *fp;
  char                *filename;
  char                *hostname;
  char                message[MAX_LINE];
  char                tmp[MAX_LINE];
  char                *section_name;
  int                 fd;
  int                 use_syslog;
  int                 syslog_level;
#ifndef HAVE_STDARG_H
  int                 section;
  internal_log_levels level;
  char                *format;

  va_start(ap);
  level   = (internal_log_levels) va_arg(ap, int);
  section = (int) va_arg(ap, int);
  format  = va_arg(ap, char*);
#else
  va_start(ap, format);
#endif
  /* verbosity sets the level at which we ignore log messages */
  if (level > get_verbosity())
  {
    goto end_proc;	/* single point for va_end(ap) and return */
  }

  /* first we check to see if we're loggin to syslog or not */
  use_syslog = is_syslog_used();

  if (!get_log_setup())
  {
    /* at this point, we cannot be sure of having any kind of log facility
       or being connected to anyone */

    fprintf(stderr,
            "%s: ",
            level_to_name(level));

    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");
  }
  else if (use_syslog)
  {
    /* if syslog support was not compiled in then we will never get here */
    section_name = section_to_name(section);
    sprintf(tmp, "%s:", section_name);
    if (section == NET || section == CLIENT)
    {
      hostname = get_client_hostname(1);  /* stdout is client sock */
      strcat(tmp, hostname);
      strcat(tmp, ": ");
    }
    strcat(tmp, format);

#ifdef HAVE_VSNPRINTF
    vsnprintf(message, sizeof(message), tmp, ap);
#else
    vsprintf(message, tmp, ap);
#endif
    
#ifndef NO_SYSLOG
    syslog_level = local_to_syslog(level);
    if (syslog_level < 0)
    {
      goto end_proc;	/* single point for va_end(ap) and return */
    }
    
    syslog(syslog_level, "%s", message);
#endif /* NO_SYSLOG */
  }
  else  /* log to file(s) */
  {
    filename = get_log_filename(level);

    if (filename == NULL) goto end_proc;	/* single point for va_end(ap) and return */

    if (STR_EQ(filename, "stderr"))
    {
      fp = stderr;
    }
    else
    {
      fp = fopen(filename, "a");
      if (!fp)
      {
        fprintf(stderr, "error: could not open file %s\n",
                filename);
        fprintf(stderr, "error: fatal error; terminating\n");
        exit(1);
      }
    }

    fd = fileno(fp);

    /* lock for exclusive use  - default is to wait */
    /* FIXME:  maybe should use more general get_file_lock() routine */
/*     if (sys_file_lock(fd, FILE_LOCK) != 0) */
/*     { */
/*       fprintf(stderr, "save_into_log: could not start lock %s\n", filename); */
/*     } */

    fprintf(fp,
            "%s %s rwhoisd[%d]: %s: ",
            timestamp(),
            get_local_hostname(),
            (int) getpid(),
            section_to_name(section));

    if (section == NET || section == CLIENT)
    {
      hostname = get_client_hostname(1);  /* stdout is client sock */
      fprintf(fp, "%s: ",hostname);
    }
    vfprintf(fp, format, ap);
    fprintf(fp, "\n");

/*     if (sys_file_lock(fd, FILE_UNLOCK) != 0) */
/*     { */
/*       fprintf(stderr,"save_into_log: could not release lock %s\n", filename); */
/*     } */

    fclose(fp);
  }
end_proc:	/* single point for va_end(ap) and return */
	va_end(ap);
	return;
}
