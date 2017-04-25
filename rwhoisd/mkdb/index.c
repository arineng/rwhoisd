/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "index.h"

#include "auth_area.h"
#include "defines.h"
#include "fileinfo.h"
#include "fileutils.h"
#include "index_file.h"
#include "ip_network.h"
#include "log.h"
#include "misc.h"
#include "phonetic.h"
#include "records.h"
#include "schema.h"
#include "search.h"
#include "strutil.h"
#include "validate_rec.h"

#define MAX_RECORD_BLOCK         100 /* read & index 100 at a time */

#ifdef NEW_STYLE_BIN_SORT
#define SORT_COMMAND "sort -o %s -k 5,5 -k 4,4n -t : %s"
#else
#define SORT_COMMAND "sort -o %s +4 +3 -t : %s "
#endif

/* ------------------------ Local Functions ------------------ */

/* write_index_line: output one index line to the file */
static int
write_index_line(fp, item)
  FILE          *fp;
  index_struct  *item;
{
  char      line[MAX_LINE + 1];

  encode_index_line(line, item);

  fprintf(fp, "%s\n", line);

  return TRUE;
}

/* ********************************************************************** */
/* indexing functions.

   These are the functions that actually index a given item->value
   according to the type(s) listed in a index_fp_struct and the
   attributes index value.  If you want to add a new indexing type you
   need to add a new function here, add the call to the case statement
   in index_record, and add the type to the index types list. */

/* exact_index: given a value return the string to put into the
   index This was the old normal case for everything */
static char *
exact_index(line)
  char      *line;
{
  char      *a;
  char      *b;
  a = strupr(line);

  b = xstrdup(a);

  strip_control(b);
  trim(b);
  return(b);
}

/* cidr_index: given a value return the string to put into the index*/
static char *
cidr_index(line)
  char      *line;
{
  struct netinfo prefix;
  char          buf[MAX_LINE];

  if (NOT_STR_EXISTS(line))
  {
    return NULL;
  }

  if (!is_network_valid_for_index(line))
  {
    return NULL;
  }

  if ( ! get_network_prefix_and_len( line, &prefix ) )
  {
    return NULL;
  }

  write_network( buf, &prefix );

  return(xstrdup(buf));
}


static char *
strip_non_soundex(str)
  char *str;
{
  int i;
  int j;
  int len;

  if (!str)
  {
    return NULL;
  }

  len = strlen(str);

  for (i = 0, j = 0; i < len; i++)
  {
    if (isalpha((int) str[i]) || isspace((int) str[i]))
    {
      str[j++] = str[i];
    }
    else if (!iscntrl((int) str[i]))
    {
      str[j++] = ' ';
    }
  }
  str[j] = '\0';

  return(str);
}

static char *
soundex_index(value)
  char *value;
{
  char  buf[MAX_LINE];
  char  tmp_buf[MAX_LINE];
  char  *result;
  char  **argv;
  int   argc;
  int   first = TRUE;
  int   i;

  buf[0]     = '\0';
  tmp_buf[0] = '\0';

  /* we strip all the non alphabetic or whitespace characters from the
     value first */
  strip_non_soundex(value);

  /* then we tokenize on ws. Don't have to worry about
     split_arg_list's handling of quotes and the like, because those
     would have been stripped. */
  if (!split_arg_list(value, &argc, &argv))
  {
    return NULL;
  }

  for (i = 0; i < argc; i++)
  {
    metaphone(argv[i], tmp_buf, 1);

    if (!first)
    {
      strcat(buf, " ");
    }
    else
    {
      first = FALSE;
    }

    strcat(buf, tmp_buf);
    tmp_buf[0] = '\0';
  }

  free_arg_list(argv);

  result = xstrdup(buf);

  trim(result);
  return(result);
}

char *
soundex_index_to_var(result, value)
  char      *result;
  char      *value;
{
  char *res;

  if (NOT_STR_EXISTS(value) || !result)
  {
    return NULL;
  }

  res = soundex_index(value);

  strcpy(result, res);
  free(res);

  return(result);
}

int
is_soundexable(str)
  char *str;
{
  int i;
  int len;

  if (!str)
  {
    return FALSE;
  }

  len = strlen(str);

  for (i = 0; i < len; i++)
  {
    if (!isalpha((int) str[i]) && !isspace((int) str[i]))
    {
      return FALSE;
    }
  }

  return TRUE;
}

/* ********************************************************************* */

/* sort_index_file: given a list of files, sort each tmp file, move it
   to its real filename, and unlink the original unsorted file */
int
sort_index_files(files)
  dl_list_type *files;
{
  char            command_str[BUFSIZ + 1];
  index_fp_struct *index_file;
  int             not_done;
  struct stat     sb;
  int             status;

  not_done = dl_list_first(files);

  while (not_done)
  {
    index_file = dl_list_value(files);
    status = stat(index_file->tmp_filename, &sb);

    if (status < 0)
    {
      /* stat itself failed (file doesn't exist). go to the next file */
      not_done = dl_list_next(files);
      continue;
    }

    fclose(index_file->fp);
    index_file->fp = NULL;

    sprintf(command_str, SORT_COMMAND, index_file->real_filename,
            index_file->tmp_filename);

    if (system(command_str) != 0)
    {
      log(L_LOG_ERR, MKDB, "sort failed: %s", strerror(errno));
      return FALSE;
    }

    unlink(index_file->tmp_filename);
    not_done = dl_list_next(files);
  }

  return TRUE;
}

/* index record: given a record, a hit_struct (the index_file_no is
   unnecessary), write to each index the appropriate lines for each
   attribute.  Return the number of index lines written */
static long
index_record(rec, auth_area, files, status)
  record_struct    *rec;
  auth_area_struct *auth_area;
  dl_list_type     *files;
  int              *status;
{
  dl_list_type     *global_attr_list;
  dl_list_type     *av_pair_list;
  av_pair_struct   *av;
  index_struct     item;
  long             num_lines = 0;
  index_fp_struct  *index_file;
  attr_index_type  i;

  *status = TRUE;  /* be optimistic */

  if (!rec || !files || !auth_area || !auth_area->schema)
  {
    *status = FALSE;
    log(L_LOG_ERR, MKDB, "index_record: detected null data");
    return(0);
  }

  global_attr_list = &(auth_area->schema->attribute_ref_list);
  av_pair_list     = &(rec->av_pair_list);

  if (dl_list_empty(av_pair_list) || dl_list_empty(files))
  {
    return(0);
  }

  dl_list_first(av_pair_list);

  do
  {
    av = dl_list_value(av_pair_list);

    if (!av || !av->attr || !av->value ||
        (av->attr->index == INDEX_NONE) ||
        (av->attr->index == INDEX_MAX_TYPE))
    {
      continue;
    }

    /* for this attribute get the first index file to deal with */

    item.offset       = rec->offset;
    item.data_file_no = rec->data_file_no;
    item.attribute_id = av->attr->global_id;
    item.deleted_flag = FALSE;

    switch (av->attr->index)
    {
    case INDEX_ALL:
      i = INDEX_EXACTLY;
      for ( ; i != INDEX_MAX_TYPE; i++)
      {
        /* this checks a CIDR index type to make sure it looks right */
        if (i == INDEX_CIDR && !is_network_valid_for_searching(av->value))
        {
          continue;
        }

        /* get the correct index_file to write to */
        index_file = find_index_file_by_type(files, convert_file_type(i));
        if (!index_file->fp)
        {
          if (!(index_file->fp = fopen(index_file->tmp_filename, "a")))
          {
            log(L_LOG_ERR, MKDB, "could not open index file '%s': %s",
                index_file->tmp_filename, strerror(errno));
            continue;
          }
        }

        /* index the value and set it to the item value */
        switch(i)
        {
        case INDEX_EXACTLY:
          item.value = exact_index((char *) av->value);
          break;
        case INDEX_CIDR:
          item.value = cidr_index((char *) av->value);
          break;
        case INDEX_SOUNDEX:
          item.value = soundex_index((char *) av->value);
          break;
        default:
          log(L_LOG_ERR, MKDB, "unknown index type encountered: %d", i);
          break;
        }

        if (NOT_STR_EXISTS(item.value))
        {
          continue;
        }

        /* write the value to the correct index file */
        write_index_line(index_file->fp, &item);
        if (item.value)
        {
          free(item.value);
          item.value = NULL;
        }

        /* keep track of the number of lines written */
        num_lines++;
      }
      break;
    case INDEX_EXACTLY:
      index_file = (index_fp_struct *) find_index_file_by_type(files,
                    convert_file_type(av->attr->index));
      if (!index_file->fp)
      {
        if (!(index_file->fp = fopen(index_file->tmp_filename, "a")))
        {
          log(L_LOG_ERR, MKDB, "could not open index file '%s': %s",
              index_file->tmp_filename, strerror(errno));
          continue;
        }
      }
      item.value = exact_index((char *) av->value);
      if (NOT_STR_EXISTS(item.value))
      {
        continue;
      }

      write_index_line(index_file->fp, &item);
      num_lines++;
      break;
    case INDEX_CIDR:
      index_file = find_index_file_by_type(files,
                                           convert_file_type(av->attr->index));
      if (!index_file->fp)
      {
        if (!(index_file->fp = fopen(index_file->tmp_filename, "a")))
        {
          log(L_LOG_ERR, MKDB, "could not open index file '%s': %s",
              index_file->tmp_filename, strerror(errno));
          continue;
        }
      }

      item.value = cidr_index(av->value);
      if (NOT_STR_EXISTS(item.value))
      {
        continue;
      }

      write_index_line(index_file->fp, &item);
      num_lines++;

      break;
    case INDEX_SOUNDEX:
      index_file = find_index_file_by_type(files,
                                           convert_file_type(av->attr->index));
      if (!index_file->fp)
      {
        if (!(index_file->fp = fopen(index_file->tmp_filename,"a")))
        {
          log(L_LOG_ERR, MKDB, "could not open index file '%s': %s",
              index_file->tmp_filename, strerror(errno));
          continue;
        }
      }
      item.value = soundex_index((char *) av->value);
      if (NOT_STR_EXISTS(item.value))
      {
         continue;
      }

      write_index_line(index_file->fp, &item);
      num_lines++;

      break;
    default:        /* should never get here */
      log(L_LOG_ERR, MKDB,
          "index_record: invalid index type in switch(type)");
      continue;
    }

    if (item.value)
    {
      free(item.value);
      item.value = NULL;
    }

  } while (dl_list_next(av_pair_list));

  return(num_lines);
}


/* index_data_file: index one data file, writing index lines to any
   number of the index files listed in 'files', and updating the
   full_file_list (but not committing it).  Returns the number of
   lines written, status in the variable.  */
long
index_data_file(class, auth_area, data_file, files, validate_flag, status)
  class_struct      *class;
  auth_area_struct  *auth_area;
  file_struct       *data_file;
  dl_list_type      *files;
  int               validate_flag;
  int               *status;
{
  record_struct    *record;
  long              num_index_lines = 0;
  rec_parse_result read_status;

  /* check for bad parameters */
  if (!class || !auth_area || !data_file || !files || !status)
  {
    log(L_LOG_ERR, MKDB, "index_data_file: null data detected");
    if (status) *status = FALSE;
    return(0);
  }

  /* default variables */
  *status = TRUE;

  /* we have to make sure we are open for reading */
  if (data_file->fp)
  {
    fclose(data_file->fp);
  }
  data_file->fp = fopen(data_file->filename, "r");
  if (!data_file->fp)
  {
    log(L_LOG_ERR, MKDB, "could not open data file '%s' for reading: %s",
        data_file->filename, strerror(errno));
    *status = FALSE;
    return(0);
  }

  set_log_context(data_file->filename, 0, -1);

  /* read until a null record is returned (indicating the end-of-file) */
  while ( (record = mkdb_read_next_record(class,
                                          auth_area,
                                          data_file->file_no,
                                          validate_flag,
                                          &read_status,
                                          data_file->fp)) )
  {
    data_file->num_recs++;

    num_index_lines += index_record(record, auth_area, files, status);

    destroy_record_data(record);

    if (! *status)
    {
      log(L_LOG_ERR, MKDB, "error indexing data file '%s'",
          data_file->filename);
      fclose(data_file->fp);
      data_file->fp = NULL;
      return(0);
    }

  }

  fclose(data_file->fp);
  data_file->fp = NULL;

  return(num_index_lines);
}

/* ------------------------ Public Functions ----------------- */

int
decode_index_line(line, item)
  char              *line;
  index_struct *item;
{
  int   argc;
  char  **argv;

  if (!item || !line)
  {
    return FALSE;
  }

  if (!split_list(line, ':', 5, &argc, &argv) || argc != 5)
  {
    return FALSE;
  }

#if defined(OFF_T64) && defined(HAVE_ATOLL)
  item->offset       = atoll(argv[0]);
#else
  item->offset       = atol(argv[0]);
#endif
  item->data_file_no = atoi(argv[1]);
  item->deleted_flag = atoi(argv[2]);
  item->attribute_id = atoi(argv[3]);
  item->value        = xstrdup(argv[4]);

  free_arg_list(argv);

  return TRUE;
}

int
encode_index_line(line, item)
  char          *line;
  index_struct  *item;
{
  if (!item || !line)
  {
    return FALSE;
  }

#ifdef OFF_T64
  sprintf(line, "%lld:%d:%d:%d:%s", item->offset, item->data_file_no,
          item->deleted_flag, item->attribute_id, item->value);
#else
  sprintf(line, "%ld:%d:%d:%d:%s", item->offset, item->data_file_no,
          item->deleted_flag, item->attribute_id, item->value);
#endif

  return TRUE;
}


int
index_files(class, auth_area, index_file_list, data_file_list, validate_flag,
            hold_lock_flag)
  class_struct      *class;
  auth_area_struct  *auth_area;
  dl_list_type      *index_file_list;
  dl_list_type      *data_file_list;
  int               validate_flag;
  int               hold_lock_flag;
{
  file_struct   *data_file;
  file_struct   *index_file;
  file_struct   *delete_file;
  index_fp_struct *index_fp_file;
  dl_list_type  delete_list;
  dl_list_type  add_list;
  dl_list_type  unlock_list;
  int           status                          = TRUE;
  long          index_num_recs                  = 0;
  long          num_recs                        = 0;

  if (!class || !auth_area)
  {
    log(L_LOG_ERR, MKDB, "index_files: detected null data");
    return FALSE;
  }

  if (dl_list_empty(data_file_list) || dl_list_empty(index_file_list))
  {
    /* even if there are no files to index, create a 0 length master
       index file to differentiate between an indexed, but empty,
       area, and an indexed, but in transition, area. */
    modify_file_list(class, auth_area, NULL, NULL, NULL, NULL, NULL);
    return TRUE;
  }

  dl_list_default(&delete_list, FALSE, destroy_file_struct_data);
  dl_list_default(&add_list, FALSE, destroy_file_struct_data);
  dl_list_default(&unlock_list, FALSE, destroy_file_struct_data);

  /* add/update all of our data files to the master file list(s) */
  if (! modify_file_list(class, auth_area, data_file_list, NULL, NULL, NULL,
                         NULL))
  {
    log(L_LOG_ERR, MKDB, "could not add data files to master list");
    return FALSE;
  }

  /* for each data file, open and index */
  dl_list_first(data_file_list);

  do
  {
    data_file = dl_list_value(data_file_list);
    if (!data_file)
    {
      continue;
    }

    num_recs = index_data_file(class, auth_area, data_file, index_file_list,
                               validate_flag, &status);
    if (!status)
    {
      /* indexing failure: back out */
      break;
    }

    if (num_recs == 0)
    {
      /* copy the file struct so it doesn't get free()d twice */
      delete_file = xmemdup(data_file, sizeof(*delete_file));
      delete_file->filename = xstrdup(data_file->filename);
      delete_file->fp = NULL;

      dl_list_append(&delete_list, delete_file);
      dl_list_delete(data_file_list);
    }

    index_num_recs += num_recs;

  } while (dl_list_next(data_file_list));

  /* close temp file and sort into index file */

  /* sort all tmp files and move to file (does an explicit fclose) */
  if (!status || !sort_index_files(index_file_list))
  {
    /* back out */
    unlink_index_tmp_files(index_file_list);
    dl_list_append_list(data_file_list, &delete_list);
    modify_file_list(class, auth_area, NULL, &delete_list, NULL, NULL, NULL);
    /* dl_list_destroy(&delete_list); */ /* getting done in the caller */

    return FALSE;
  }

  /* update the data files and add the index file */

  dl_list_first(index_file_list);
  do
  {
    index_fp_file = dl_list_value(index_file_list);
    index_file = build_tmp_base_file_struct(index_fp_file->real_filename,
                                            NULL,
                                            index_fp_file->type,
                                            index_num_recs);
    if (index_file)
    {
      index_file->base_filename
        = generate_index_file_basename(index_file->type, class->db_dir,
                                       index_fp_file->prefix);
      index_file->filename = NULL;

      dl_list_append(&add_list, index_file);
    }
  } while (dl_list_next(index_file_list));

  if (!hold_lock_flag)
  {
    copy_file_list(&unlock_list, data_file_list);
    modify_file_list(class, auth_area, &add_list, &delete_list, data_file_list,
                     &unlock_list, NULL);
  }
  else
  {
    modify_file_list(class, auth_area, &add_list, &delete_list,
                     data_file_list, NULL, NULL);
  }

  dl_list_destroy(&delete_list);
  dl_list_destroy(&add_list);
  dl_list_destroy(&unlock_list);

  return TRUE;
}


int
index_files_by_name(class_name, auth_area_name, base_dir,
                    num_data_files, file_names, validate_flag)
  char  *class_name;
  char  *auth_area_name;
  char  *base_dir;
  int   num_data_files;
  char  **file_names;
  int   validate_flag;
{
  class_struct      *class;
  auth_area_struct  *auth_area;
  dl_list_type      data_file_list;
  dl_list_type      index_file_list;
  int               quiet_mode;
  int               status;

  decode_validate_flag(validate_flag, &quiet_mode, NULL, NULL);

  if (!auth_area_name || !*auth_area_name)
  {
    if (!quiet_mode) log(L_LOG_ERR, MKDB,
                         "index_files_by_name: no auth-area specified");
    return FALSE;
  }

  if (!class_name || !*class_name)
  {
    if (!quiet_mode) log(L_LOG_ERR, MKDB,
                         "index_files_by_name: no class specified");
    return FALSE;
  }


  auth_area = find_auth_area_by_name(auth_area_name);
  if (!auth_area)
  {
    if (!quiet_mode) log(L_LOG_ERR, MKDB,
                         "index_files_by_name: auth-area '%s' unknown",
                         auth_area_name);
    return FALSE;
  }

  class = find_class_by_name(auth_area->schema, class_name);
  if (!class)
  {
    if (!quiet_mode)
      log(L_LOG_ERR, MKDB,
          "index_files_by_name: class '%s' not part of auth-area '%s'",
          class_name, auth_area_name);
    return FALSE;
  }

  dl_list_default(&data_file_list, FALSE, destroy_file_struct_data);
  if (! build_file_list_by_names(&data_file_list, MKDB_DATA_FILE,
                                 base_dir, num_data_files, file_names))
  {
    if (!quiet_mode)
      log(L_LOG_ERR, MKDB,
          "index_files_by_name: could not generate list of data files");
    return FALSE;
  }


  dl_list_default(&index_file_list, FALSE, destroy_index_fp_data);
  if (!build_index_list(class, auth_area, &index_file_list, class->db_dir,
                        NULL))
  {
    if (!quiet_mode)
      log(L_LOG_ERR, MKDB,
          "index_files_by_name: could not generate list of index files");
    return FALSE;
  }

  status = index_files(class, auth_area, &index_file_list, &data_file_list,
                       validate_flag, FALSE);

  dl_list_destroy(&data_file_list);
  dl_list_destroy(&index_file_list);

  return(status);
}

int
index_files_by_suffix(class_name, auth_area_name, suffix, validate_flag)
  char *class_name;
  char *auth_area_name;
  char *suffix;
  int  validate_flag;
{
  class_struct     *class;
  auth_area_struct *auth_area;
  dl_list_type     data_file_list;
  dl_list_type     index_file_list;
  int              quiet_mode;
  int              status;

  decode_validate_flag(validate_flag, &quiet_mode, NULL, NULL);

  auth_area = find_auth_area_by_name(auth_area_name);
  if (!auth_area || !auth_area->schema)
  {
    if (!quiet_mode)
      log(L_LOG_ERR, MKDB,
          "index_files_by_suffix: auth-area '%s' unknown", auth_area_name);
    return FALSE;
  }

  class = find_class_by_name(auth_area->schema, class_name);
  if (!class)
  {
    if (!quiet_mode)
      log(L_LOG_ERR, MKDB,
          "index_files_by_suffix: class '%s' not part of auth-area '%s'",
          class_name, auth_area_name);
    return FALSE;
  }


  /* create and build the data file list */
  dl_list_default(&data_file_list, FALSE, destroy_file_struct_data);
  if (!build_file_list_by_suffix(&data_file_list, MKDB_DATA_FILE,
                                 class->db_dir, suffix))
  {
    if (!quiet_mode)
      log(L_LOG_ERR, MKDB,
          "index_files_by_suffix: could not generate file list");

    return FALSE;
  }


  /* create and build the index file list */
  dl_list_default(&index_file_list, FALSE, destroy_index_fp_data);

  if (!build_index_list(class, auth_area, &index_file_list, class->db_dir,
                        NULL))
  {
    if (!quiet_mode)
    {
      log(L_LOG_ERR, MKDB,
          "index_files_by_name: could not generate list of index files");
    }
    return FALSE;
  }

  status = index_files(class, auth_area, &index_file_list, &data_file_list,
                       validate_flag, FALSE);

  dl_list_destroy(&data_file_list);
  dl_list_destroy(&index_file_list);

  return(status);
}

/* --------------- Destructor Components ------------ */

int
destroy_index_item(item)
  index_struct *item;
{
  if (!item)
  {
    return TRUE;
  }

  if (item->value)
  {
    free(item->value);
  }

  free(item);

  return TRUE;
}
