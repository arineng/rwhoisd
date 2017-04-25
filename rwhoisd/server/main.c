/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "main.h"

#include "auth_area.h"
#include "conf.h"
#include "daemon.h"
#include "defines.h"
#include "directive.h"
#include "log.h"
#include "main_config.h"
#include "read_config.h"
#include "security.h"
#include "session.h"

#include "conf.h"

/* local types */

typedef struct _options_struct
{
  char  *opt_c;
  int   opt_r;
  int   opt_s;
  int   opt_n;
  int   opt_vq;
  int   opt_vq_val;
  int   opt_di;
  int   opt_di_val;
} options_struct;

static options_struct    opts;
static char              orig_cwd[MAX_FILE];

#ifdef USE_TCP_WRAPPERS
/* Define these variables for libwrap. */
int allow_severity = LOG_INFO;
int deny_severity  = LOG_INFO;
#endif

/* local prototypes */

/* usage: prints the usage statement */
static void
usage(prog_name)
  char *prog_name;
{
  fprintf(stderr,
          "usage: %s [-c config_file] [-r] [-s] [-Vvq] [-di]\n", prog_name);
  fprintf(stderr,
          "       -c config_file: location of the base configuration file\n");
  fprintf(stderr,
          "       -r: root server; do not generate punt referrals\n");
  fprintf(stderr,
          "       -s: chroot\n");
  fprintf(stderr,
          "       -V: very verbose (level set to 7)\n");
  fprintf(stderr,
          "       -v: verbose (level set to 6)\n");
  fprintf(stderr,
          "       -q: quiet (level set to 2)\n");
  fprintf(stderr,
          "       -d: run as daemon (standalone)\n");
  fprintf(stderr,
          "       -n: no backgrounding\n");
  fprintf(stderr,
          "       -i: run as single shot (inetd)\n");
  exit(64);
}

static void
parse_cl_options(argc, argv)
  int  argc;
  char *argv[];
{
  extern char       *optarg;
  extern int        optind;
  int               badopts      = FALSE;
  int               c;

  bzero(&opts, sizeof(opts));
  
  /* parse command line options */
  while ((c = getopt(argc, argv, "c:rsdivVn")) != EOF)
  {
    switch (c)
    {
    case 'c':
      opts.opt_c = optarg;
      break;
    case 'r':
      opts.opt_r = TRUE;
      break;
    case 's':
      opts.opt_s = TRUE;
      break;
    case 'n':
      opts.opt_n = TRUE;
      break;
    case 'd':
      opts.opt_di = TRUE;
      opts.opt_di_val = DAEMON_SERVER;
      break;
    case 'i':
      opts.opt_di = TRUE;
      opts.opt_di_val = INETD_SERVER;
      break;
    case 'V':
      opts.opt_vq = TRUE;
      opts.opt_vq_val = L_LOG_DEBUG;
      break;
    case 'v':
      opts.opt_vq = TRUE;
      opts.opt_vq_val = L_LOG_INFO;
      break;
    case 'q':
      opts.opt_vq = TRUE;
      opts.opt_vq_val = L_LOG_ALERT;
      break;
    default:
      badopts = TRUE;
      break;
    }
  }
  
  if (badopts)
  {
    usage(argv[0]);
  }
}

static void
set_cl_options()
{
  if (opts.opt_r)
  {
    set_root_server(TRUE);
  }
  if (opts.opt_s)
  {
    set_chrooted(TRUE);
  }
  if (opts.opt_vq)
  {
    set_verbosity(opts.opt_vq_val);
  }
  if (opts.opt_di)
  {
    set_server_type(opts.opt_di_val);
  }
  if (opts.opt_n)
  {
    set_background(FALSE);
  }
}

/* initialize: read all configuration files and (re)set the server
   state

   note: this routine (and the other option routines) should probably
   be in another file. */
void
initialize()
{
  char  *config_file = NULL;

  /* set initial configuration data values */
  init_server_config_data();

  /* first attempt to get back to our original current working directory */
  if (STR_EXISTS(orig_cwd))
  {
    chdir(orig_cwd);
  }

  /* default section */
  if (opts.opt_c == NULL)
  {
    config_file = DEFAULT_RWHOIS_CONFIG_FILE;
  }
  else
  {
    config_file = opts.opt_c;
  }

  /* do 1-time initialization */
  
  if (!read_all_config_files(config_file, FALSE))
  {
    exit(1);
  }

  init_directive_functions();

  /* set the command line opts -- doing this here lets us override the
     config file */

  set_cl_options();
  
  init_server_state(); 
  
  chdir_root_dir();
}

  
int
main(argc, argv)
  int  argc;
  char *argv[];
{
  bzero(orig_cwd, sizeof(orig_cwd));

  /* save our original cwd */
  getcwd(orig_cwd, sizeof(orig_cwd));
    
  parse_cl_options(argc, argv);
  
  initialize();
  
  if (get_verbosity() >= L_LOG_DEBUG)
  {
    display_server_config_data(stderr);
  }
  
  /* do security stuff -- chroot() or just change id, or nothing */
  if (!setup_security())
  {
    log(L_LOG_ERR, CONFIG, "Security setup failed! Exiting.");
    exit(1);
  }

  setup_logging();

  if (is_daemon_server())
  {
    /* start message logged within daemon code in order to get correct pid */
    run_daemon();
  }
  else
  {
    run_session(TRUE);
  }

  exit(0);
  
  /* this is just to suppress warnings */
  return(0);
}
