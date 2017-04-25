/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "common.h"

#include "auth_area.h"
#include "defines.h"
#include "fileinfo.h"
#include "fileutils.h"
#include "index.h"
#include "log.h"
#include "main_config.h"
#include "phonetic.h"
#include "read_config.h"
#include "schema.h"
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
  fprintf(stderr, " file list mode:\n");
  fprintf(stderr,
   "   %s [-c config_file] -C class -A auth_area [-ivqn] files...\n",
          prog_name);
  fprintf(stderr, "\n suffix mode:\n");
  fprintf(stderr,
   "   %s [-c config_file] [-C class] [-A auth_area] [-ivqn] -s suffix\n",
          prog_name);
  fprintf(stderr, "\n options:\n");
  fprintf(stderr,  
   "   -c config_file: location of the base (rwhoisd) configuration file\n");
  fprintf(stderr,
   "   -C class_name: restrict to this class; required for file list mode\n");
  fprintf(stderr,
   "   -A auth_area_name: restrict to this auth area; required for file list\n");
  fprintf(stderr,
          "   -i initialize: remove all old index files first\n");
  fprintf(stderr,
          "   -v: verbose\n");
  fprintf(stderr, "   -q: quiet\n");
  fprintf(stderr, "   -n: no validity checks\n");

  exit(64);
}

static int
delete_index_files(class, auth_area)
  class_struct     *class;
  auth_area_struct *auth_area;
{
  dl_list_type master_file_list;
  dl_list_type index_file_list;
  file_struct  *index_file;
  int          not_done;
  
  dl_list_default(&master_file_list, FALSE, destroy_file_struct_data);
  dl_list_default(&index_file_list, FALSE, destroy_file_struct_data);

  /* get the index file_structs for the particular class */
  if (! get_file_list(class, auth_area, &master_file_list))
  {
    log(L_LOG_WARNING, MKDB, "could not delete index files");
    return FALSE;
  }
  filter_file_list(&index_file_list, MKDB_ALL_INDEX_FILES, &master_file_list);
  dl_list_destroy(&master_file_list);
  
  /* get out now if there is nothing to do */
  if (dl_list_empty(&index_file_list))
  {
    return TRUE;
  }
  
  /* now actually unlink them */
  not_done = dl_list_first(&index_file_list);
  while (not_done)
  {
    index_file = dl_list_value(&index_file_list);

    if (index_file && index_file->filename &&
        file_exists(index_file->filename))
    {
      unlink(index_file->filename);
    }
    
    not_done = dl_list_next(&index_file_list);
  }

  dl_list_destroy(&index_file_list);

  /* unlink the master file list as well */
  unlink_master_file_list(class, auth_area);
  
  return TRUE;
}

static int
run_file_index(class_name, auth_area_name, validate_flag, init_flag,
               base_dir, argc, argv)
  char  *class_name;
  char  *auth_area_name;
  int   validate_flag;
  int   init_flag;
  char  *base_dir;
  int   argc;
  char  *argv[];
{
  class_struct     *class               = NULL;
  auth_area_struct *auth_area           = NULL;
  
  if (argc < 1) return FALSE;

  auth_area = find_auth_area_by_name(auth_area_name);
  if (!auth_area)
  {
    fprintf(stderr, "error: authority area '%s' is not found\n",
            auth_area_name);
    return FALSE;
  }

  if (!auth_area->schema)
  {
    fprintf(stderr,
            "error: authority area '%s' does not have a valid schema\n",
            auth_area_name);
    return FALSE;
  }

  class = find_class_by_name(auth_area->schema, class_name);
  if (!class)
  {
    fprintf(stderr, "error: class '%s' is not found in auth area '%s'\n",
            class_name, auth_area_name);
    return FALSE;
  }
  
  if (init_flag)
  {
    if (!delete_index_files(class, auth_area))
    {
      return FALSE;
    }
  }

  return(index_files_by_name(class->name, auth_area->name, base_dir,
                             argc, argv, validate_flag));
}

static int
run_suffix_index_class(class, auth_area, validate_flag, init_flag, suffix)
  class_struct     *class;
  auth_area_struct *auth_area;
  int              validate_flag;
  int              init_flag;
  char             *suffix;
{
  if (init_flag)
  {
    if (!delete_index_files(class, auth_area))
    {
      return FALSE;
    }
  }
    
  return(index_files_by_suffix(class->name, auth_area->name, 
                               suffix, validate_flag));
}

static int
run_suffix_index_auth_area(auth_area, class_name, validate_flag, init_flag,
                           suffix)
  auth_area_struct *auth_area;
  char             *class_name;
  int              validate_flag;
  int              init_flag;
  char             *suffix;
{
  class_struct *class;
  dl_list_type *class_list;
  int          not_done;
  
  if (!auth_area) return FALSE;
  if (!auth_area->schema)
  {
    fprintf(stderr,
            "error: authority area '%s' does not have a valid schema\n",
            auth_area->name);
    return FALSE;
  }

  if (!class_name || !*class_name)
  {
    class_list = &(auth_area->schema->class_list);

    not_done = dl_list_first(class_list);
    while (not_done)
    {
      class = dl_list_value(class_list);
      if (!run_suffix_index_class(class, auth_area, validate_flag, init_flag,
                                  suffix))
      {
        return FALSE;
      }

      not_done = dl_list_next(class_list);
    }

    return TRUE;
  }

  class = find_class_by_name(auth_area->schema, class_name);
  return(run_suffix_index_class(class, auth_area, validate_flag, init_flag,
                                suffix));
}

static int
run_suffix_index(class_name, auth_area_name, validate_flag, init_flag, suffix)
  char *class_name;
  char *auth_area_name;
  int  validate_flag;
  int  init_flag;
  char *suffix;
{
  auth_area_struct *auth_area = NULL;
  class_ref_struct *class_ref = NULL;
  dl_list_type     *auth_area_list;
  int              not_done;
  
  /* the 3 cases: auth, !auth && class, !auth && !class */

  if (auth_area_name && *auth_area_name)
  {
    auth_area = find_auth_area_by_name(auth_area_name);
    if (!auth_area)
    {
      fprintf(stderr, "authority area '%s' not found\n", auth_area_name);
      return FALSE;
    }
  }
  else if (class_name && *class_name)
  {
    class_ref = find_global_class_by_name(class_name);
    if (!class_ref)
    {
      fprintf(stderr, "class '%s' not found\n", class_name);
      return FALSE;
    }

    auth_area_list = &(class_ref->auth_area_list);
  }
  else
  {
    auth_area_list = get_auth_area_list();
  }

  if (auth_area)
  {
    return(run_suffix_index_auth_area(auth_area, class_name, validate_flag,
                                      init_flag, suffix));
  }

  not_done = dl_list_first(auth_area_list);

  while (not_done)
  {
    auth_area = dl_list_value(auth_area_list);
    if (!run_suffix_index_auth_area(auth_area, class_name, validate_flag,
                                    init_flag, suffix))
    {
      return FALSE;
    }

    not_done = dl_list_next(auth_area_list);
  }

  return TRUE;
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
  char          *auth_area_name = NULL;
  char          *class_name     = NULL;
  char          *config_file    = NULL;
  char          *prog_name      = argv[0];
  char          *suffix         = NULL;
  int           c;
  int           badopts         = FALSE;
  int           initialize      = FALSE;
  int           mode            = FILE_MODE;
  int           status          = TRUE;
  int           validate_flag;
  int           validate        = TRUE;
  int           quiet           = FALSE;
  
  /* set initial configuration data values */
  init_server_config_data();

  /* parse command line options */
  while ((c = getopt(argc, argv, "c:C:A:s:iqvn")) != EOF) {
    switch (c) {
    case 'c':
      config_file = optarg;
      break;
    case 'C':
      class_name = optarg;
      break;
    case 'A':
      auth_area_name = optarg;
      break;
    case 'q':
      quiet = TRUE;
      set_verbosity(L_LOG_ALERT);
      break;
    case 'v':
      quiet = FALSE;
      set_verbosity(L_LOG_INFO);
      break;
    case 'i':
      initialize = TRUE;
      break;
    case 's':
      mode = SUFFIX_MODE;
      suffix = optarg;
      break;
    case 'n':
      validate = FALSE;
      break;
    default:
      badopts = TRUE;
      break;
    }
  }

  /* reset the argument list */
  argc -= optind;
  argv = &argv[optind];
  
  if (badopts)
  {
    usage(prog_name);
  }

  if (mode == SUFFIX_MODE && (!suffix || argc > 0))
  {
    usage(prog_name);
  }

  if (mode == FILE_MODE &&
      (suffix || argc <= 0 || !class_name || !auth_area_name))
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

  if (validate)
  {
    validate_flag = encode_validate_flag(quiet, FALSE, TRUE);
  }
  else
  {
    validate_flag = 0;
  }

  switch (mode) {
  case FILE_MODE:
    status = run_file_index(class_name, auth_area_name, validate_flag,
                            initialize, cwd, argc, argv);
    break;
  case SUFFIX_MODE:
    status = run_suffix_index(class_name, auth_area_name, validate_flag,
                              initialize, suffix);
    break;
  default:
    break;
  }

  if (!status)
  {
    if (!quiet) printf("indexing failed\n");
    exit(99);
  }

  if (!quiet) printf("done.\n");

  exit(0);
}
