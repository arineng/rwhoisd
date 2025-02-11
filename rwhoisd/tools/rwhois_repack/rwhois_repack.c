/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-1998 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */
#include "rwhois_repack.h"

/* from rwhoisd/common */
#include "auth_area.h"
#include "common.h"
#include "conf.h"
#include "defines.h"
#include "fileutils.h"
#include "log.h"
#include "main_config.h"
#include "misc.h"
#include "read_config.h"
#include "schema.h"
#include "strutil.h"
#include "validate_rec.h"

/* from rwhoisd/mkdb */
#include "mkdb_types.h"
#include "fileinfo.h"
#include "index_file.h"
#include "index.h"

/* number of seconds to wait between removing index files from master file 
   list and actually physically deleting them. */
#define DELETE_WAIT_TIME 2
/* --------------- local prototypes ----------------------- */

/* usage: prints the usage statement */
static int
usage(prog_name)
  char *prog_name;
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr,
    "   %s [-c config_file] [-C class] [-A auth_area] [-m size limit] [-s substring ] [-vndN]\n", prog_name);

  fprintf(stderr, "\n options:\n");
  fprintf(stderr, "   -c config_file: location of configuration file\n");
  fprintf(stderr, "   -C class_name: restrict to this class\n");
  fprintf(stderr, "   -A auth_area_name: restrict to this auth area\n");
  fprintf(stderr, "   -m size limit.  Only repack files less than this (bytes).\n");
  fprintf(stderr, "   -s substring.  Only repack files that contain this substring in its path.\n");
  fprintf(stderr, "   -v: verbose\n");
  fprintf(stderr, "   -n: no validate check\n");
  fprintf(stderr, "   -d: do not delete files\n");
  fprintf(stderr, "   -N: dry run\n");

  exit(64);
}

static void
print_config(options)
  repack_options_struct *options;
{
  fprintf(stderr, "rwhois conf file:  %s\n",
          SAFE_STR(options->config_file, "default"));
  fprintf(stderr, "authority area:    %s\n",
          SAFE_STR(options->aa_name, "none"));
  fprintf(stderr, "class:             %s\n",
          SAFE_STR(options->class_name, "none"));
  fprintf(stderr, "\n");
  fprintf(stderr, "verbose:           %s\n",
          true_false_str(options->verbose_flag));
  fprintf(stderr, "validate:          %s\n",
          true_false_str(options->validate_flag));
  fprintf(stderr, "size threshold:    %ld\n", options->size_threshold);
  fprintf(stderr, "dry run:           %s\n",
          true_false_str(options->dry_run_flag));
  fprintf(stderr, "substring:         %s\n",
          SAFE_STR(options->substring, ""));
}

/* FIXME: this should be added to the dl_list package */
static int
dl_list_size(dl_list_type *list)
{
  dl_node_type *old_pos;
  int           not_done;
  int           size;

  if (!list) return -1;

  if (dl_list_empty(list)) return 0;

  old_pos = list->current;
  not_done = dl_list_first(list);
  size = 0;
  while (not_done)
  {
    size++;
    not_done = dl_list_next(list);
  }
  list->current = old_pos;

  return size;
}

static repack_options_struct *
parse_command_line(int argc, char *argv[])
{
  extern char   *optarg;
#ifndef optind
  extern int optind;
#endif
  char          *prog_name      = argv[0];
  int           badopts         = FALSE;
  repack_options_struct *options;
  int           validate        = TRUE;
  int           quiet           = TRUE;
  int           c;

  options = xcalloc(1, sizeof(*options));

  options->delete_flag = TRUE;

  /* parse command line options */
  while ((c = getopt(argc, argv, "c:C:A:vnNdm:s:")) != EOF) {
    switch (c) {
    case 'c':
      options->config_file = optarg;
      break;
    case 'C':
      options->class_name = optarg;
      break;
    case 'A':
      options->aa_name = optarg;
      break;
    case 'v':
      options->verbose_flag = TRUE;
      set_verbosity(L_LOG_INFO);
      quiet = FALSE;
      break;
    case 'n':
      validate = FALSE;
      break;
    case 'N':
      options->dry_run_flag = TRUE;
      break;
    case 'm':
      options->size_threshold = atol(optarg);
      break;
    case 'd':
      options->delete_flag = FALSE;
      break;
    case 's':
      options->substring = optarg;
      break;
    default:
      badopts = TRUE;
      break;
    }
  }

  if (badopts)
  {
    usage(prog_name);
  }

  if (validate)
  {
    options->validate_flag = encode_validate_flag(quiet, FALSE, TRUE);
  }
  else
  {
    options->validate_flag = 0;
  }

  if (options->verbose_flag)
  {
    print_config(options);
  }

  return options;
}

/* concat all files in file list into dest_file. */
static void
append_files(dl_list_type *file_list, char *dest_filename,
             repack_options_struct *options)
{
  int not_done;
  char command[MAX_LINE];

  if (!file_list || NOT_STR_EXISTS(dest_filename))
  {
    /* FIXME: should complain here */
    return;
  }
  /* currently we just use shell commands to do this */
  not_done = dl_list_first(file_list);

  while (not_done)
  {
    file_struct *f;
    int res;

    f = dl_list_value(file_list);

    if (file_exists(f->filename))
    {
      sprintf(command, "cat %s >> %s", f->filename, dest_filename);

      if (options->dry_run_flag)
      {
        printf("append_files: %s\n", command);
        res = 0;
      }
      else
      {
        res = system(command);
      }

      if (res != 0)
      {
        fprintf(stderr, "could not append file %s to %s\n",
                SAFE_STR(f->filename, "null"),
                SAFE_STR(dest_filename, "null"));
      }
    }

    not_done = dl_list_next(file_list);
  }
}

static int
delete_files_in_list(dl_list_type *file_list, repack_options_struct *options)
{
  int not_done;

  not_done = dl_list_first(file_list);
  while (not_done)
  {
    file_struct *f = (file_struct *)dl_list_value(file_list);

    if (options->dry_run_flag)
    {
      if (options->verbose_flag)
      {
        printf("removing %s\n", f->filename);
      }
      not_done = dl_list_next(file_list);
      continue;
    }

    if (file_exists(f->filename))
    {
      if (options->verbose_flag)
      {
        printf("removing %s\n", f->filename);
      }

      if (! options->dry_run_flag)
      {
        unlink(f->filename);
      }
    }

    not_done = dl_list_next(file_list);
  }

  return TRUE;
}

/* removes elements from a file list based on the file be less than or
   equal to a given size (in bytes) */
static int
filter_file_list_by_size(dl_list_type *file_list, long max_size)
{
  file_struct *file;
  int         not_done = TRUE;

  if (!file_list) {
    return FALSE;
  }

  if (max_size <= 0) return TRUE;

  not_done = dl_list_first(file_list);
  while (not_done)
  {
    file = dl_list_value(file_list);
    if (!file)
    {
      not_done = dl_list_next(file_list);
      continue;
    }

    if (file->num_recs > max_size)
    {
      dl_list_delete(file_list);
      not_done = (! dl_list_empty(file_list));
      continue;
    }

    not_done = dl_list_next(file_list);
  }

  return TRUE;
}

static int
filter_file_list_by_substring(dl_list_type *file_list, char *substring)
{
  file_struct *file;
  int         not_done = TRUE;

  if (! file_list || NOT_STR_EXISTS(substring)) {
    return FALSE;
  }

  not_done = dl_list_first(file_list);
  while (not_done)
  {
    file = dl_list_value(file_list);
    if (!file)
    {
      not_done = dl_list_next(file_list);
      continue;
    }

    if ( ! strstr(file->filename, substring) )
    {
      dl_list_delete(file_list);
      not_done = (! dl_list_empty(file_list));
      continue;
    }

    not_done = dl_list_next(file_list);
  }

  return TRUE;
}

static int
repack_index_files(class_struct *class,
                   auth_area_struct *auth_area,
                   dl_list_type *index_file_list,
                   repack_options_struct *options)
{
  mkdb_file_type  t;
  dl_list_type    sub_index_file_list;
  dl_list_type    base_index_file_list;
  dl_list_type    new_index_file_list;
  dl_list_type    add_file_list;
  index_fp_struct *index_fp;
  file_struct     *index_file;
  int             res;
  int             not_done;
  long            num_recs[MKDB_MAX_FILE_TYPE];

  if (!auth_area || !class || !index_file_list)
  {
    return FALSE;
  }

  /* short circuit if the list is empty */
  if (dl_list_empty(index_file_list)) return TRUE;


  dl_list_default(&sub_index_file_list, FALSE, (int(*)(void *))destroy_file_struct_data);
  dl_list_default(&base_index_file_list, FALSE, (int(*)(void *))destroy_index_fp_data);
  dl_list_default(&new_index_file_list, FALSE, (int(*)(void *))destroy_index_fp_data);
  dl_list_default(&add_file_list, FALSE, (int(*)(void *))destroy_file_struct_data);

  /* generate the various possible index files we could create */
  if (! build_index_list(class, auth_area, &base_index_file_list,
                         class->db_dir, "addind") )
  {
    fprintf(stderr,
            "repack_index_files: could not generate list of new index files");
    dl_list_destroy(&sub_index_file_list);
    dl_list_destroy(&base_index_file_list);
    dl_list_destroy(&new_index_file_list);
    dl_list_destroy(&add_file_list);
    return FALSE;
  }

  /* for each index file type, isolate the list */
  for (t = MKDB_EXACT_INDEX_FILE; t < MKDB_MAX_FILE_TYPE; t++)
  {
    /* clear the list; this works because list->destroy_head_flag =
       FALSE */
    dl_list_destroy(&sub_index_file_list);

    if (! filter_file_list(&sub_index_file_list, t, index_file_list)) {
      continue;
    }

    if (dl_list_size(&sub_index_file_list) < 2) {
      continue;
    }

    index_fp = find_index_file_by_type(&base_index_file_list, t);
    if (! index_fp) {
      continue;
    }

    append_files(&sub_index_file_list, index_fp->tmp_filename, options);
    dl_list_append(&new_index_file_list, index_fp);

    /* calculate num recs */
    not_done = dl_list_first(&sub_index_file_list);
    num_recs[t] = 0;
    while (not_done)
    {
      file_struct *f = dl_list_value(&sub_index_file_list);
      num_recs[t] += f->num_recs;
      not_done = dl_list_next(&sub_index_file_list);
    }
  }

  /* nothing the "new_index_file_list" means that we haven't created
     any new consolodated index files, so we are done */
  if (dl_list_size(&new_index_file_list) <= 0)
  {
    dl_list_destroy(&sub_index_file_list);
    dl_list_destroy(&base_index_file_list);
    dl_list_destroy(&new_index_file_list);
    dl_list_destroy(&add_file_list);
    return TRUE;
  }

  /* this is far as we can go in the dry run */
  if (options->dry_run_flag)
  {
    not_done = dl_list_first(&new_index_file_list);
    while (not_done)
    {
      index_fp = dl_list_value(&new_index_file_list);
      printf("sorting %s to %s\n", index_fp->tmp_filename,
             index_fp->real_filename);
      not_done = dl_list_next(&new_index_file_list);
    }
    /* delete_files_in_list honors the dry_run flag */
    delete_files_in_list(index_file_list, options);

    dl_list_destroy(&sub_index_file_list);
    dl_list_destroy(&base_index_file_list);
    dl_list_destroy(&new_index_file_list);
    dl_list_destroy(&add_file_list);
    return TRUE;
  }
  else
  {
    /* now that we've created the new (tmp) index files (by
       concatenating all of the old index files together, we now sort
       them into the real files */
    res = sort_index_files(&new_index_file_list);
  }

  if (!res)
  {
    /* back out */
    unlink_index_tmp_files(&new_index_file_list);
    dl_list_destroy(&sub_index_file_list);
    dl_list_destroy(&base_index_file_list);
    dl_list_destroy(&new_index_file_list);
    dl_list_destroy(&add_file_list);
    return FALSE;
  }

  /* add the new index files to the add_file_list, making sure to put
     the sort results in the tmp_filename slot, and making the
     'modify_file_list' step actually create the correct final name */
  not_done = dl_list_first(&new_index_file_list);
  while (not_done)
  {
    index_fp = dl_list_value(&new_index_file_list);

    index_file
      = build_tmp_base_file_struct(index_fp->real_filename, NULL,
                                   index_fp->type, num_recs[index_fp->type]);

    /* this forces the late filename generation */
    index_file->base_filename
      = generate_index_file_basename(index_file->type, class->db_dir,
                                     index_fp->prefix);
    index_file->filename = NULL;

    dl_list_append(&add_file_list, index_file);
    not_done = dl_list_next(&new_index_file_list);
  }

  /* now add the files to the master file list. This will activate them */
  modify_file_list(class, auth_area, &add_file_list, index_file_list, NULL,
                   &add_file_list, NULL);

  /* delete the old files (data, index and those in master index file) */
  if (options->delete_flag)
  {
    sleep(DELETE_WAIT_TIME);
    res = delete_files_in_list(index_file_list, options);
  }

  dl_list_destroy(&sub_index_file_list);
  dl_list_destroy(&base_index_file_list);
  dl_list_destroy(&new_index_file_list);
  dl_list_destroy(&add_file_list);
  return res;
}

/* data repack within 'class' and 'auth_area' */
static int
run_repack_class_aa(class_struct          *class,
                    auth_area_struct      *auth_area,
                    repack_options_struct *options)
{
  int          status;
  dl_list_type all_file_list;
  dl_list_type index_file_list;

  log(L_LOG_DEBUG, UNKNOWN,
      "run_repack_class_aa: within auth_area '%s' and class '%s'",
      auth_area->name, class->name);

  if (!auth_area || !auth_area->schema)
  {
    log(L_LOG_ERR, UNKNOWN, "run_pack_class_aa: no auth_area");
    return FALSE;
  }

  if (!class)
  {
    log(L_LOG_ERR, UNKNOWN, "run_repack_class_aa: no class");
    return FALSE;
  }

  /* initialize the list */
  dl_list_default(&index_file_list, FALSE, (int(*)(void *))destroy_file_struct_data);
  dl_list_default(&all_file_list, FALSE, (int(*)(void *))destroy_file_struct_data);

  /* get the file list from master index file (local.db) */
  if (! get_file_list(class, auth_area, &all_file_list) )
  {
    return FALSE;
  }

  /* strip out the non-index files */
  if (! filter_file_list(&index_file_list, MKDB_ALL_INDEX_FILES,
                         &all_file_list))
  {
    return FALSE;
  }

  /* filter out the ones that don't contain the substring (if there is
     a substring) */
  if (STR_EXISTS(options->substring))
  {
    if (! filter_file_list_by_substring(&index_file_list, options->substring) )
    {
      return FALSE;
    }
  }

  /* filter out the ones that are too big */
  if (! filter_file_list_by_size(&index_file_list, options->size_threshold) )
  {
    return FALSE;
  }

  if (dl_list_empty(&index_file_list))
  {
    if (options->verbose_flag) {
      fprintf(stderr, "no index files to repack for %s:%s\n", auth_area->name,
              class->name);
    }
    return TRUE;
  }

  status = repack_index_files(class, auth_area, &index_file_list, options);

  dl_list_destroy(&index_file_list);
  dl_list_destroy(&all_file_list);
  if (!status)
  {
    return FALSE;
  }

  return TRUE;

}

/* run_repack_auth_area: repack in one auth_area */
static int
run_repack_auth_area(auth_area_struct *auth_area,
                     repack_options_struct *options)
{
  class_struct *class = NULL;
  dl_list_type *class_list;
  int          not_done;

  if (!auth_area || !options) return FALSE;

  if (!auth_area->schema)
  {
    fprintf(stderr,
            "error: authority area '%s' does not have a valid schema\n",
            auth_area->name);
    return FALSE;
  }

  /* no class_name, all the classes will repack */
  if (NOT_STR_EXISTS(options->class_name))
  {
    class_list = &(auth_area->schema->class_list);

    not_done = dl_list_first(class_list);
    while (not_done)
    {
      class = dl_list_value(class_list);
      if (!run_repack_class_aa(class, auth_area, options))
      {
        return FALSE;
      }

      not_done = dl_list_next(class_list);
    }

    return TRUE;
  }

  /* otherwise, repack only the specified class */
  class = find_class_by_name(auth_area->schema, options->class_name);
  return run_repack_class_aa( class, auth_area, options);
}


/* iterate over the affected authoriy areas */
static int
run_repack(repack_options_struct *options)
{
  auth_area_struct *auth_area = NULL;
  class_ref_struct *class_ref = NULL;
  dl_list_type     *auth_area_list;
  int              not_done;

  if (!options) return FALSE;

  if (STR_EXISTS(options->aa_name))
  {
    /* if we've specified an authority area, defer the binding to a
       particular class until later. */
    auth_area = find_auth_area_by_name(options->aa_name);
    if (!auth_area)
    {
      fprintf(stderr, "authority area '%s' not found\n", options->aa_name);
      return FALSE;
    }
  }
  else if (STR_EXISTS(options->class_name))
  {
    /* a class was specified, but no authority area, so we get the
       global class reference just to get the aa's for that class. */
    class_ref = find_global_class_by_name(options->class_name);
    if (!class_ref)
    {
      fprintf(stderr, "class '%s' not found\n", options->class_name);
      return FALSE;
    }

    auth_area_list = &(class_ref->auth_area_list);
  }
  else
  {
    /* otherwise, no class or aa was specified so we just get all auth
       areas.  */
    auth_area_list = get_auth_area_list();
  }


  /* the single aa case */
  if (auth_area) {
    return run_repack_auth_area(auth_area, options);
  }

  /* otherwise, we iterate over a list of authority areas */
  not_done = dl_list_first(auth_area_list);
  while (not_done)
  {
    auth_area = dl_list_value(auth_area_list);
    if (!run_repack_auth_area( auth_area, options))
    {
      return FALSE;
    }

    not_done = dl_list_next(auth_area_list);
  }

  return TRUE;
}



int
main(int argc, char *argv[])
{
  int           status          = TRUE;
  repack_options_struct *options;

  /* set initial configuration data values */
  init_server_config_data();

  options = parse_command_line(argc, argv);

  if (options->config_file == NULL) {
    options->config_file = DEFAULT_RWHOIS_CONFIG_FILE;
  }

  if (!read_all_config_files(options->config_file, FALSE)) {
    exit(99);
  }

  /* get to a predictable workding directory */
  chdir_root_dir();


  /* actually do the work */
  status = run_repack(options);

  if (!status) {
    printf("repack failed\n");
    exit(99);
  }

  printf("done.\n");

  exit(0);
}

