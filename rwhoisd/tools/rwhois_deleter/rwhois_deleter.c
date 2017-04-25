/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "common.h"

#include "auth_area.h"
#include "defines.h"
#include "delete.h"
#include "fileinfo.h"
#include "fileutils.h"
#include "index.h"
#include "log.h"
#include "main_config.h"
#include "misc.h"
#include "phonetic.h"
#include "parse.h"
#include "read_config.h"
#include "records.h"
#include "schema.h"
#include "search.h"
#include "strutil.h"
#include "validate_rec.h"

#include "conf.h"

/* local defines */

#define FILE_MODE   1
#define SUFFIX_MODE 2

/* local prototypes */

/* usage: prints the usage statement */
static int
usage(prog_name)
  char *prog_name;
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr,
   "   %s [-c config_file] [-l #] [-nq] <query>",
          prog_name);
  fprintf(stderr, "\n options:\n");
  fprintf(stderr,  
   "   -c config_file: location of the base (rwhoisd) configuration file\n");
  fprintf(stderr,
   "   -l set limit: sets the limit (max number of objects) for the query\n                 default is 1\n");
  fprintf(stderr,
   "   -n trial run: don't actually delete anything\n");
  fprintf(stderr,
   "   -q quit: just delete, don't ask.\n");
  
  exit(64);
}

char *
assemble_query_string(argc, argv)
  int argc;
  char **argv;
{
  int i;
  char buf[MAX_LINE];
  char *p;
  int len = 0;
  int t;
  
  buf[0] = '\0';
  
  for (i = 0; i < argc; i++)
  {
    p = argv[i];

    if (STR_EXISTS(p))
    {
      t = strlen(p);

      if (len + t + 1< MAX_LINE)
      {
        strcat(buf, p);
        strcat(buf, " ");
        len += t + 1;
      }
    }
  }

  if (STR_EXISTS(buf))
  {
    return xstrdup(trim(buf));
  }

  return NULL;
}

static dl_list_type *
query_for_records(query_string, limit, total)
  char *query_string;
  int  limit;
  int  *total;
{
  query_struct query;
  int   num_recs;
  int   status;
  dl_list_type *record_list;

  *total = 0;

  record_list = (dl_list_type *) xcalloc(1, sizeof(*record_list));
  dl_list_default(record_list, TRUE, destroy_record_data);
  
  if (!parse_query(query_string, &query))
  {
    log(L_LOG_ERR, UNKNOWN, "could not parse: '%s'",
        query_string);
    return NULL;
  }

  num_recs = search(&query, record_list, limit, &status);

  if (num_recs == 0)
  {
    log(L_LOG_WARNING, UNKNOWN, "no objects found for query '%s'",
        query_string);
    return NULL;
  }

  *total = num_recs;
  return record_list;
}

void show_result_list(record_list, total)
  dl_list_type *record_list;
  int total;
{
  int not_done;
  record_struct *rec;
  av_pair_struct *av;
  
  if (!record_list || total == 0)
  {
    return;
  }
  
  printf("Total: %d record(s) will be deleted\n", total);

  not_done = dl_list_first(record_list);

  while (not_done)
  {
    rec = (record_struct *)dl_list_value(record_list);

    av = find_attr_in_record_by_name(rec, "ID");

    if (!av)
    {
      log(L_LOG_ERR, UNKNOWN, "record found without an ID!");
      dl_list_delete(record_list);
      not_done = !dl_list_empty(record_list);
    }
    else
    {
      printf(" ID: %s\n", (char *) av->value);
      not_done = dl_list_next(record_list);
    }
  }
}

int
main(argc, argv)
  int  argc;
  char *argv[];
{
  extern char   *optarg;
#ifndef optind
  extern int optind;
#endif
  char          cwd[MAX_FILE];
  char          *config_file    = NULL;
  char          *prog_name      = argv[0];
  char          *query_str      = NULL;
  dl_list_type  *record_list    = NULL;
  char          c;
  int           badopts         = FALSE;
  int           status          = TRUE;
  int           quiet           = FALSE;
  int           fake            = FALSE;
  int           limit           = 1;
  int           total           = 0;
  
  /* set initial configuration data values */
  init_server_config_data();

  /* parse command line options */
  while ((c = getopt(argc, argv, "c:l:qn")) != EOF) {
    switch (c) {
    case 'c':
      config_file = optarg;
      break;
    case 'q':
      quiet = TRUE;
      set_verbosity(L_LOG_ALERT);
      break;
    case 'l':
      limit = atoi(optarg);
      break;
    case 'n':
      fake = TRUE;
      set_verbosity(L_LOG_INFO);
      break;
    default:
      badopts = TRUE;
      break;
    }
  }

  /* reset the argument list */
  argc -= optind;
  argv = &argv[optind];
  
  if (badopts || argc < 1)
  {
    usage(prog_name);
  }

  /* default section */

  if (config_file == NULL)
  {
    config_file = DEFAULT_RWHOIS_CONFIG_FILE;
  }

  if (!read_all_config_files(config_file, FALSE))
  {
    exit(99);
  }

  getcwd(cwd, MAX_FILE);

  chdir_root_dir();

  /* Here we go.  First concat the remaining arguments together to get
     the query string */
  query_str = assemble_query_string(argc, argv);
  if (NOT_STR_EXISTS(query_str))
  {
    exit(99);
  }

  printf("debug: query string = '%s'\n", query_str);

  record_list = query_for_records(query_str, limit, &total);

  if (!quiet || fake)
  {
    show_result_list(record_list);
  }

  if (!fake && !quiet && total > 0)
  {
    /* prompt for change */

    printf("OK to delete %d objects? ", total);
    c = getc(stdin);

    if (c == 'y' || c == 'Y')
    {
      fake = FALSE;
    }
    else
    {
      fake = TRUE;
    }
  }

  if (!fake && total > 0)
  {
    status = mkdb_delete_record_list(record_list);

    if (!status)
    {
      if (!quiet) printf("deletions failed\n");
      exit(99);
    }
  }
  else
  {
    printf("no objects deleted.\n");
  }
  
  if (!quiet) printf("done.\n");

  exit(0);
}
