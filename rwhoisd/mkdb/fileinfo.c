/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "fileinfo.h"

#include "auth_area.h"
#include "schema.h"
#include "defines.h"
#include "fileutils.h"
#include "log.h"
#include "misc.h"
#include "strutil.h"
#include "main_config.h"

#define MASTER_FILE_LIST    "local.db"
#define MASTER_FILE_LIST_W  "local.db.write"
#define MASTER_FILE_LIST_B  "local.db.bak"

#define LOCK_BLOCKING_TIME  5 /* in USLEEP_WAIT_PERIODs */


typedef enum
{
  MFL_READ,
  MFL_WRITE,
  MFL_BACKUP
} master_inst_type;

/* ------------------- Local Functions ---------------- */

static mkdb_file_type select_type PROTO((char *ftype));
static char *select_str_from_type PROTO((mkdb_file_type type));
static file_struct *read_file_struct PROTO((FILE *fp));
static int write_file_struct PROTO((FILE *fp, file_struct *fi, int not_last));
static int read_file_list PROTO((char *index_file, dl_list_type *file_list));
static void write_file_list PROTO((char *filename, dl_list_type *file_list));
static int next_file_no PROTO((dl_list_type *file_list));
static char *generate_file_name PROTO((char *tmp_filename, char *base_filename,
                                       dl_list_type *full_file_list));
static int get_master_index_file PROTO((class_struct     *class,
                                        auth_area_struct *auth_area,
                                        master_inst_type instance_type,
                                        char             *index_file));
static int add_file_struct PROTO((file_struct    *file,
                                  dl_list_type   *file_list,
                                  mkdb_lock_type lock_mode));
static int delete_file_no PROTO((int file_no, dl_list_type *file_list));
static int lock_unlock_file_no PROTO((int            file_no,
                                      mkdb_lock_type lock,
                                      dl_list_type   *file_list));
static int update_file_no PROTO((file_struct  *update_file,
                                 dl_list_type *file_list));
static int add_file_list PROTO((dl_list_type   *file_list,
                                dl_list_type   *full_file_list,
                                mkdb_lock_type lock_mode));
static int delete_file_list PROTO((dl_list_type *file_list,
                                  dl_list_type *full_file_list));
static int mod_file_list PROTO((dl_list_type *file_list,
                                dl_list_type *full_file_list));
static int lock_unlock_file_list PROTO((dl_list_type   *file_list,
                                        dl_list_type   *full_file_list,
                                        mkdb_lock_type lock));
static int install_write_file_list PROTO((class_struct     *class,
                                          auth_area_struct *auth_area));

/* ---- file list reading and writing primitives --- */

/* select_mkdb_file_type: returns the database file type (data or
   index) based on the tag. */
static mkdb_file_type
select_type(ftype)
  char  *ftype;
{
  if (STR_EQ(ftype, MKDB_EXACT_INDEX_STR) ||
      STR_EQ(ftype, MKDB_OLD_INDEX_STR) ||
      STR_EQ(ftype, MKDB_OLD_INDEX_FIRST_STR) ||
      STR_EQ(ftype, MKDB_OLD_INDEX_WORD_STR))
  {
    return MKDB_EXACT_INDEX_FILE;
  }
  if (STR_EQ(ftype, MKDB_SOUNDEX_INDEX_STR))
  {
    return MKDB_SOUNDEX_INDEX_FILE;
  }
  if (STR_EQ(ftype, MKDB_CIDR_INDEX_STR))
  {
    return MKDB_CIDR_INDEX_FILE;
  }

  if (STR_EQ(ftype, MKDB_DATA_FILE_STR))
  {
    return MKDB_DATA_FILE;
  }

  return MKDB_NO_FILE;
}

static char *
select_str_from_type(type)
  mkdb_file_type    type;
{
  switch (type)
  {
  case MKDB_EXACT_INDEX_FILE:
    return MKDB_EXACT_INDEX_STR;
  case MKDB_SOUNDEX_INDEX_FILE:
    return MKDB_SOUNDEX_INDEX_STR;
  case MKDB_CIDR_INDEX_FILE:
    return MKDB_CIDR_INDEX_STR;
  case MKDB_DATA_FILE:
    return MKDB_DATA_FILE_STR;
  default:
    return NULL;
  }
}

static file_struct *
read_file_struct(fp)
  FILE  *fp;
{
  char        line[MAX_LINE + 1];
  char        tag[MAX_LINE];
  char        datum[MAX_LINE];
  file_struct *fi;

  bzero(line, sizeof(line));

  fi = xcalloc(1, sizeof(*fi));

  while ((readline(fp, line, MAX_LINE)) != NULL)
  {
    if (new_record(line))
    {
      break;
    }

    if (parse_line(line, tag, datum))
    {
      if (STR_EQ(tag, MKDB_TYPE_TAG))
      {
        fi->type = select_type(datum);
      }
      else if (STR_EQ(tag, MKDB_FILE_TAG))
      {
        fi->filename = xstrdup(datum);
      }
      else if (STR_EQ(tag, MKDB_NUMRECS_TAG))
      {
        fi->num_recs = atol(datum);
      }
      else if (STR_EQ(tag, MKDB_FILE_NO_TAG))
      {
        fi->file_no = atoi(datum);
      }
      else if (STR_EQ(tag, MKDB_SIZE_TAG))
      {
#if defined(OFF_T64) && defined(HAVE_ATOLL)
        fi->size = atoll(datum);
#else
        fi->size = atol(datum);
#endif
      }
      else if (STR_EQ(tag, MKDB_LOCK_TAG))
      {
        fi->lock = true_false(datum);
      }
      else
      {
        log(L_LOG_WARNING, MKDB, "unknown file list tag: %s",
            tag);
      }
    }
    else
    {
      log(L_LOG_WARNING, MKDB, "malformed file list line: %s",
          line);
      return NULL;
    }
  }

  /* check to see if we have a valid file_struct; for now, this means
     a real type, a real name, and a positive file number */
  if (fi->filename && *fi->filename &&
      (fi->type > MKDB_NO_FILE) &&
      (fi->file_no >= 0))
  {
    return(fi);
  }

  /* otherwise, we trash the record */
  destroy_file_struct_data(fi);

  return NULL;
}

static int
write_file_struct(fp, fi, not_last)
  FILE        *fp;
  file_struct *fi;
  int         not_last;
{

  if (!fp || !fi)
  {
    return FALSE;
  }

  fprintf(fp, "%s:%s\n", MKDB_TYPE_TAG, select_str_from_type(fi->type));
  fprintf(fp, "%s:%s\n", MKDB_FILE_TAG, fi->filename);
  fprintf(fp, "%s:%d\n", MKDB_FILE_NO_TAG, fi->file_no);
#ifdef OFF_T64
  fprintf(fp, "%s:%lld\n", MKDB_SIZE_TAG, fi->size);
#else
  fprintf(fp, "%s:%ld\n", MKDB_SIZE_TAG, fi->size);
#endif
  fprintf(fp, "%s:%ld\n", MKDB_NUMRECS_TAG, fi->num_recs);
  fprintf(fp, "%s:%s\n", MKDB_LOCK_TAG, on_off(fi->lock));

  if (not_last)
  {
    fprintf(fp, "---\n");
  }

  return TRUE;
}

/* read_file_list: reads a file_list data file into the file_list
   structure, by type.  Returns TRUE on success. */
static int
read_file_list(index_file, file_list)
  char            *index_file;
  dl_list_type    *file_list;
{
  FILE              *fp = NULL;
  file_struct       *fi;
  int               tries = 5; /* in USLEEP_WAIT_PERIODs */

  /* can't work with null ptrs */
  if (!index_file || !file_list)
  {
    log(L_LOG_ERR, MKDB, "read_file_list: null data detected");
    return FALSE;
  }

  /* adjust for the lack of usleep */
#ifndef HAVE_USLEEP
  tries = tries / USLEEP_SEC_CONV; if (tries == 0) tries++;
#endif

  fp = fopen(index_file, "r");
  while (fp == NULL && errno == ENOENT && tries > 0)
  {
    tries--;
#ifdef HAVE_USLEEP
    usleep(USLEEP_WAIT_PERIOD);
#else
    sleep(1);
#endif
    fp = fopen(index_file, "r");
  }

  if (!fp)
  {
    if (errno == ENOENT)
    {
/*       log(L_LOG_DEBUG, MKDB, */
/*           "master file list '%s' not present; area assumed to be unindexed", */
/*           index_file); */
      return TRUE;
    }
    else
    {
      log(L_LOG_ERR, MKDB,
          "could not open master index file '%s': %s", index_file,
          strerror(errno));

      return FALSE;
    }
  }

  while ( (fi = read_file_struct(fp)) )
  {
    dl_list_append(file_list, fi);
  }

  fclose(fp);

  return TRUE;
}

/* write_file_list: writes a file list to the master index file. The
   entire file_list must be given to this routine. */
static void
write_file_list(filename, file_list)
  char         *filename;
  dl_list_type *file_list;
{
  FILE         *fp;
  file_struct  *fi;
  int          not_done;

  /* note: locking should be taken care of in the enclosing routine */
  fp = fopen(filename, "w");
  if (!fp)
  {
    log(L_LOG_ERR, MKDB, "could not open '%s' for write: %s", filename,
        strerror(errno));
    return;
  }

  not_done = dl_list_first(file_list);
  while (not_done)
  {
    fi = dl_list_value(file_list);

    not_done = dl_list_next(file_list);

    write_file_struct(fp, fi, not_done);
  }

  fclose(fp);
}

/* next_file_no: returns the next file number.  Assumes a) the
   file_list is the full file list, and b) that they are sequentially
   increasing (that is, the last element has the highest number */
static int
next_file_no(file_list)
  dl_list_type  *file_list;
{
  file_struct   *file;

  if (dl_list_empty(file_list))
  {
    return(0);
  }

  dl_list_last(file_list);

  file = dl_list_value(file_list);
  if (!file)
  {
    /* FIXME: maybe should log error here */
    return(0);
  }

  return(file->file_no + 1);
}

static char *
generate_file_name(tmp_filename, base_filename, full_file_list)
  char         *tmp_filename;
  char         *base_filename;
  dl_list_type *full_file_list;
{
  file_struct  *f;
  char         template[MAX_FILE + 1];
  char         real_fname[MAX_FILE + 1];
  char         dir[MAX_FILE];
  char         file[MAX_FILE];
  char         base_file[MAX_FILE];
  char         base_dir[MAX_FILE];
  int          not_done;
  int          index_no = 0;

  if (NOT_STR_EXISTS(base_filename))
  {
    log(L_LOG_DEBUG, MKDB,
        "generate_file_name: falling back to temporary file name");
    return xstrdup(tmp_filename);
  }

  split_path(base_filename, base_dir, base_file);

  index_no = 0;
  not_done = dl_list_last(full_file_list);

  /* find the last instance of a file matching the base_filename template */
  while (not_done)
  {
    f = dl_list_value(full_file_list);
    split_path(f->filename, dir, file);

    log(L_LOG_DEBUG, MKDB, "comparing '%s' with '%s'", file, base_file);

    if (sscanf(file, base_file, &index_no) > 0)
    {
      log(L_LOG_DEBUG, MKDB, "comparison succeeed, index no = %d", index_no);
      index_no++;
      break;
    }

    not_done = dl_list_prev(full_file_list);
  }
  sprintf(template, "%s/%s", dir, base_file);
  sprintf(real_fname, template, index_no);

  log(L_LOG_DEBUG, MKDB, "generate_file_name: generated '%s'",
      real_fname);

  return xstrdup(real_fname);
}

/* fills the 'index_file' varible with the path and name of the master
   index file, given the instance type (read, write, backup, etc) */
static int
get_master_index_file(class, auth_area, instance_type, index_file)
  class_struct     *class;
  auth_area_struct *auth_area;
  master_inst_type instance_type;
  char             *index_file;
{
  if (!class || !class->name || !index_file)
  {
    return FALSE;
  }

  switch (instance_type)
  {
  case MFL_READ:
    sprintf(index_file, "%s/%s", class->db_dir, MASTER_FILE_LIST);
    break;
  case MFL_WRITE:
    sprintf(index_file, "%s/%s", class->db_dir, MASTER_FILE_LIST_W);
    break;
  case MFL_BACKUP:
    sprintf(index_file, "%s/%s", class->db_dir, MASTER_FILE_LIST_B);
    break;
  }

  return TRUE;
}

/* adds a file structure to a list, checking for duplication and
   assigning the index number.  */
static int
add_file_struct(file, file_list, lock_mode)
  file_struct    *file;
  dl_list_type   *file_list;
  mkdb_lock_type lock_mode;
{
  file_struct *tmp_file;
  char        file_path[MAX_FILE + 1];

  if (NOT_STR_EXISTS(file->filename) && NOT_STR_EXISTS(file->tmp_filename))
  {
    log(L_LOG_ERR, MKDB, "generate_file_name: null data detected");
    return FALSE;
  }

  /* check to see if we must generate a "real" filename first */
  if (NOT_STR_EXISTS(file->filename))
  {
    file->filename = generate_file_name(file->tmp_filename,
                                        file->base_filename,
                                        file_list);

    if (STR_EXISTS(file->filename))
    {
      if (link(file->tmp_filename, file->filename) >= 0)
      {
        unlink(file->tmp_filename);
      }
      else
      {
        log(L_LOG_WARNING, MKDB,
            "attempt to move temporary file '%s' to '%s' failed: %s",
            file->tmp_filename, file->filename, strerror(errno));
        free(file->filename);
        file->filename = xstrdup(file->tmp_filename);
      }
    }
  }

  /* standardize the file name */
  if (!canonicalize_path(file_path, MAX_FILE, file->filename,
                         get_root_dir(), FALSE, FALSE))
  {
    return(-1);
  }

  tmp_file = find_file_by_name(file_list, file_path, MKDB_ALL_FILES);

  /* file was already in there */
  if (tmp_file)
  {

    /* either way, we would like the file_no to be filled out */
    file->file_no = tmp_file->file_no;

    /* if it is equivalent, then we are done */
    if (tmp_file->type     == file->type &&
        tmp_file->size     == file->size &&
        tmp_file->num_recs == file->num_recs)
    {
      return TRUE;
    }

    /* update the sucker */
    tmp_file->type     = file->type;
    tmp_file->size     = file->size;
    tmp_file->num_recs = file->num_recs;
  }
  else
  {
    /* otherwise, we add it */
    file->lock         = lock_mode;
    file->file_no      = next_file_no(file_list);

    tmp_file           = copy_file_struct(file);

    dl_list_append(file_list, tmp_file);
  }

  return TRUE;
}

/* deletes a given file from a file list */
static int
delete_file_no(file_no, file_list)
  int          file_no;
  dl_list_type *file_list;
{
  file_struct *file;
  int         not_done;

  not_done = dl_list_first(file_list);
  while (not_done)
  {
    file = dl_list_value(file_list);

    if (file->file_no == file_no)
    {
      dl_list_delete(file_list);
      return TRUE;
    }

    not_done = dl_list_next(file_list);
  }

  return FALSE;
}

/* locks or unlocks a given file number with a file list */
static int
lock_unlock_file_no(file_no, lock, file_list)
  int            file_no;
  mkdb_lock_type lock;
  dl_list_type   *file_list;
{
  file_struct *file;
  int         not_done;

  not_done = dl_list_first(file_list);
  while (not_done)
  {
    file = dl_list_value(file_list);

    if (file->file_no == file_no)
    {
      file->lock = lock;
      return TRUE;
    }

    not_done = dl_list_next(file_list);
  }

  return FALSE;
}

/* updates the statistics of the corresponding (by file no) file
   structure in list.  */
static int
update_file_no(update_file, file_list)
  file_struct  *update_file;
  dl_list_type *file_list;
{
  file_struct *file;
  int         not_done;

  not_done = dl_list_first(file_list);
  while (not_done)
  {
    file = dl_list_value(file_list);

    if (file->file_no == update_file->file_no)
    {
      file->size     = update_file->size;
      file->num_recs = update_file->num_recs;
      return TRUE;
    }

    not_done = dl_list_next(file_list);
  }

  return FALSE;
}

/* add the files in the list to the full file list */
static int
add_file_list(file_list, full_file_list, lock_mode)
  dl_list_type     *file_list;
  dl_list_type     *full_file_list;
  mkdb_lock_type   lock_mode;
{
  file_struct   *file;
  int           not_done;

  not_done = dl_list_first(file_list);
  while (not_done)
  {
    file = dl_list_value(file_list);

    if (!add_file_struct(file, full_file_list, lock_mode))
    {
      return FALSE;
    }

    not_done = dl_list_next(file_list);
  }

  return TRUE;
}

/* delete the files in the list from the full file list */
static int
delete_file_list(file_list, full_file_list)
  dl_list_type *file_list;
  dl_list_type *full_file_list;
{
  file_struct *file;
  int         not_done;

  not_done = dl_list_first(file_list);

  while (not_done)
  {
    file = dl_list_value(file_list);
    if (!file)
    {
      log(L_LOG_WARNING, MKDB,
          "attempted to delete non-existent file %s from master file list",
          file->filename);
      not_done = dl_list_next(file_list);
      continue;
    }

    delete_file_no(file->file_no, full_file_list);
    not_done = dl_list_next(file_list);
  }

  return TRUE;
}

/* modifies the statistics of the files in the list in the full file
   list */
static int
mod_file_list(file_list, full_file_list)
  dl_list_type *file_list;
  dl_list_type *full_file_list;
{
  file_struct   *file;
  int           not_done;

  not_done = dl_list_first(file_list);
  while (not_done)
  {
    file = dl_list_value(file_list);

    if (!update_file_no(file, full_file_list))
    {
      log(L_LOG_WARNING, MKDB,
          "failed to update file number %d in master file list",
          file->file_no);
      continue;
    }

    not_done = dl_list_next(file_list);
  }

  return TRUE;
}

static int
lock_unlock_file_list(file_list, full_file_list, lock)
  dl_list_type   *file_list;
  dl_list_type   *full_file_list;
  mkdb_lock_type lock;
{
  file_struct   *file;
  int           not_done;

  not_done = dl_list_first(file_list);
  while (not_done)
  {
    file = dl_list_value(file_list);

    if (!lock_unlock_file_no(file->file_no, lock, full_file_list))
    {
      log(L_LOG_WARNING, MKDB,
          "failed to lock/unlock file number %d in master file list",
          file->file_no);
      not_done = dl_list_next(file_list);
      continue;
    }

    not_done = dl_list_next(file_list);
  }

  return TRUE;
}

static int
install_write_file_list(class, auth_area)
  class_struct     *class;
  auth_area_struct *auth_area;
{
  char w_index_file_name[MAX_FILE + 1];
  char r_index_file_name[MAX_FILE + 1];
  char b_index_file_name[MAX_FILE + 1];

  if (!get_master_index_file(class, auth_area, MFL_READ, r_index_file_name))
  {
    log(L_LOG_ERR, MKDB, "");
    return FALSE;
  }

  get_master_index_file(class, auth_area, MFL_WRITE, w_index_file_name);
  get_master_index_file(class, auth_area, MFL_BACKUP, b_index_file_name);

  /* first remove the backup file, if it exists */
  if (file_exists(b_index_file_name))
  {
    if (unlink(b_index_file_name) < 0)
    {
      log(L_LOG_WARNING, MKDB,
          "could not remove master file list backup '%s': %s",
          b_index_file_name, strerror(errno));
    }
  }

  /* now move the current read file into the backup position */
  if (file_exists(r_index_file_name))
  {
    if (link(r_index_file_name, b_index_file_name) < 0 ||
        unlink(r_index_file_name) < 0)
    {
      log(L_LOG_WARNING, MKDB,
          "could not move read master file list '%s' to backup: %s",
          r_index_file_name, strerror(errno));
    }
  }

  /* finally, move the current write file into the read file position */
  if (link(w_index_file_name, r_index_file_name) < 0 ||
      unlink(w_index_file_name) < 0)
  {
    log(L_LOG_ERR, MKDB,
        "could not move write master file list '%s' to read: %s",
        w_index_file_name, strerror(errno));
    return FALSE;
  }

  return TRUE;
}

/* check to see if an area is indexed at all.  This is so we don't
   have to spin looking for a possibly transient master index file. (3
   stat() calls are much cheaper than any amount of waiting... */
static int
is_area_indexed(class, auth_area)
  class_struct *class;
  auth_area_struct *auth_area;
{
  char w_index_file_name[MAX_FILE + 1];
  char r_index_file_name[MAX_FILE + 1];
  char b_index_file_name[MAX_FILE + 1];

  /* first we attempt to calculate all the names of the master index
     files. */
  if (!get_master_index_file(class, auth_area, MFL_READ, r_index_file_name))
  {
    log(L_LOG_ERR, MKDB, "");
    return FALSE;
  }

  get_master_index_file(class, auth_area, MFL_WRITE, w_index_file_name);
  get_master_index_file(class, auth_area, MFL_BACKUP, b_index_file_name);

  /* now we see if any of them exist.  It is theortically possible to
     miss all three due to some wacky process scheduling, but is is
     probably very unlikely */

  if (file_exists(r_index_file_name))
  {
    return TRUE;
  }

  if (file_exists(b_index_file_name))
  {
    return TRUE;
  }

  if (file_exists(w_index_file_name))
  {
    return TRUE;
  }

  return FALSE;
}

/* ------------------- Public Functions --------------- */


int
mkdb_file_type_equals(type1, type2)
  mkdb_file_type type1;
  mkdb_file_type type2;
{
  if (type1 == type2) return TRUE;

  if (type1 == MKDB_NO_FILE || type2 == MKDB_NO_FILE) return FALSE;

  if (type1 == MKDB_ALL_FILES || type2 == MKDB_ALL_FILES) return TRUE;

  if (type1 == MKDB_ALL_INDEX_FILES)
  {
    if (type2 >= MKDB_EXACT_INDEX_FILE && type2 < MKDB_MAX_FILE_TYPE)
    {
      return TRUE;
    }
    return FALSE;
  }

  if (type2 == MKDB_ALL_INDEX_FILES)
  {
    if (type1 >= MKDB_EXACT_INDEX_FILE && type1 < MKDB_MAX_FILE_TYPE)
    {
      return TRUE;
    }
    return FALSE;
  }

  return FALSE;
}

file_struct *
copy_file_struct(fi)
  file_struct *fi;
{
  file_struct *copy;

  copy = xcalloc(1, sizeof(*fi));

  /* copy the main result */
  bcopy(fi, copy, sizeof(*copy));

  /* realloc sub allocations */
  if (fi->filename)
  {
    copy->filename = xstrdup(fi->filename);
  }

  if (fi->tmp_filename)
  {
    copy->tmp_filename = xstrdup(fi->tmp_filename);
  }

  if (fi->base_filename)
  {
    copy->base_filename = xstrdup(fi->base_filename);
  }

  return(copy);
}

int
copy_file_list(target_file_list, source_file_list)
  dl_list_type *target_file_list;
  dl_list_type *source_file_list;
{
  int         not_done;
  file_struct *f;
  file_struct *f_copy;

  if (!target_file_list || !source_file_list)
  {
    log(L_LOG_ERR, MKDB, "copy_file_list: null data detected");
    return FALSE;
  }

  not_done = dl_list_first(source_file_list);

  while (not_done)
  {
    f = dl_list_value(source_file_list);

    f_copy = copy_file_struct(f);

    dl_list_append(target_file_list, f_copy);

    not_done = dl_list_next(source_file_list);
  }

  return TRUE;
}
/* get_dir: given class and auth_area (or just auth_area) return the
     data directory in 'dir'.  Return TRUE on success. */
int
get_dir(class_name, auth_area_name, dir)
  char  *class_name;
  char  *auth_area_name;
  char  *dir;
{
  auth_area_struct *auth_area;
  class_struct     *class;

  if (!auth_area_name ||
      !*auth_area_name)
  {
    return(FALSE);
  }

  auth_area = find_auth_area_by_name(auth_area_name);
  if (auth_area == NULL)
  {
    log(L_LOG_ERR, MKDB, "no auth-area '%s'", auth_area_name);
    return(FALSE);
  }
  if (!class_name ||
      !*class_name)
  {
    if (!(auth_area->data_dir))
    {
      return(FALSE);
    }

    strcpy(dir, auth_area->data_dir);

    return(TRUE);
  }

  class = find_class_by_name(auth_area->schema, class_name);
  if (class == NULL)
  {
   log(L_LOG_ERR, MKDB, "no class '%s' in auth-area '%s'",
             class_name, auth_area_name);
    return(FALSE);
  }
  if (!(class->db_dir))
  {
    return(FALSE);
  }

  strcpy(dir, class->db_dir);

  return(TRUE);
}

/* get_file_list: reads in records from the master file list
     pointed to by class & auth_area, and appends them to file_list,
     which should already be initialized. */
int
get_file_list(class, auth_area, file_list)
  class_struct     *class;
  auth_area_struct *auth_area;
  dl_list_type     *file_list;
{
  char  index_file[MAX_FILE + 1];

  /* calculate the master file list name */
  bzero((char *)index_file, sizeof(index_file));
  if (!get_master_index_file(class, auth_area, MFL_READ, index_file))
  {
    return FALSE;
  }

  /* first check to see if the area appears to be indexed in order to
     avoid a possibly lengthy read_file_list() call */
  if (! is_area_indexed(class, auth_area))
  {
    return TRUE;
  }

  if (!read_file_list(index_file, file_list))
  {
    dl_list_destroy(file_list);
    return FALSE;
  }

  return TRUE;
}

/* get_file: fills 'file_list' with entries of type 'type' given class
     and auth_area (by name), or just auth_area.  Returns TRUE on
     success. */
int
get_file(class_name, auth_area_name, file_list)
  char            *class_name;
  char            *auth_area_name;
  dl_list_type    *file_list;
{
  auth_area_struct *auth_area;
  schema_struct    *schema;
  class_struct     *class;
  dl_list_type     *class_list;
  int              not_done;

  if (!auth_area_name ||
      !*auth_area_name)
  {
    return(FALSE);
  }

  if (!file_list)
  {
    return(FALSE);
  }

  /* initialize the list */
  dl_list_default(file_list, FALSE, (int(*)(void *))destroy_file_struct_data);

  auth_area = find_auth_area_by_name(auth_area_name);
  if (auth_area == NULL)
  {
    log(L_LOG_ERR, MKDB, "no auth-area '%s'", auth_area_name);
    return(FALSE);
  }

  if (class_name && *class_name)
  {
    class = find_class_by_name(auth_area->schema, class_name);
    if (class == NULL)
    {
      log(L_LOG_ERR, MKDB, "no class '%s' in auth-area '%s'",
                class_name, auth_area_name);
      return(FALSE);
    }

    if (!get_file_list(class, auth_area, file_list))
    {
      return FALSE;
    }
  }
  else
  {
    schema = auth_area->schema;
    if (!schema)
    {
      return(FALSE);
    }

    class_list = &(schema->class_list);

    not_done = dl_list_first(class_list);
    while (not_done)
    {
      class = dl_list_value(class_list);

      if (!get_file_list(class, auth_area, file_list))
      {
        return FALSE;
      }

      not_done = dl_list_next(class_list);
    }
  }

  return TRUE;
}

int
filter_file_list(result_list, type, master_list)
  dl_list_type   *result_list;
  mkdb_file_type type;
  dl_list_type   *master_list;
{
  int         not_done;
  file_struct *fi;
  file_struct *copy;

  /* reject null data */
  if (!result_list || !master_list)
  {
    log(L_LOG_WARNING, MKDB, "filter_file_list: null data detected");
    return FALSE;
  }

  not_done = dl_list_first(master_list);
  while (not_done)
  {
    fi = dl_list_value(master_list);
    /* IF a) they're looking for all files or
          b) its the right type and it isn't locked or
          c) they looking for all index files and it isn't locked
       THEN add it to the result list */
    if ( (type == MKDB_ALL_FILES) ||
         (mkdb_file_type_equals(type, fi->type) && fi->lock == MKDB_LOCK_OFF) )
    {
      copy = copy_file_struct(fi);
      dl_list_append(result_list, copy);
    }

    not_done = dl_list_next(master_list);
  } /* while (not_done) */

  return TRUE;
}


int
unlink_master_file_list(class, auth_area)
  class_struct     *class;
  auth_area_struct *auth_area;
{
  char  index_file[MAX_FILE];

  if (!get_master_index_file(class, auth_area, MFL_READ, index_file))
  {
    return FALSE;
  }

  if (unlink(index_file) < 0)
  {
    log(L_LOG_WARNING, MKDB, "could not delete master file list '%s': %s",
        index_file, strerror(errno));

    return FALSE;
  }

  /* delete the write and backup files, too, if possible */
  if (get_master_index_file(class, auth_area, MFL_WRITE, index_file))
  {
    unlink(index_file);
  }

  if (get_master_index_file(class, auth_area, MFL_BACKUP, index_file))
  {
    unlink(index_file);
  }

  return TRUE;
}


file_struct *
add_single_file(class, auth_area, file_name, type, num_recs)
  class_struct     *class;
  auth_area_struct *auth_area;
  char             *file_name;
  mkdb_file_type   type;
  long             num_recs;
{
  file_struct  *file;
  file_struct  *list_file;
  dl_list_type file_list;

  dl_list_default(&file_list, FALSE, (int(*)(void *))destroy_file_struct_data);

  file = build_base_file_struct(file_name, type, num_recs);
  if (!file)
  {
    return NULL;
  }

  dl_list_append(&file_list, file);

  if (!modify_file_list(class, auth_area, &file_list, NULL, NULL, NULL,
                        NULL))
  {
    dl_list_destroy(&file_list);
    return NULL;
  }

  dl_list_first(&file_list);
  list_file = dl_list_value(&file_list);

  /* copy the list copy of the file_struct, because the list copy will
     be free()d when the list is destroyed */
  file           = xmemdup(list_file, sizeof(*file));
  file->filename = xstrdup(list_file->filename);

  dl_list_destroy(&file_list);

  return(file);
}



int
modify_file_list(class, auth_area, add_list, delete_list,
                 mod_list, unlock_list, lock_list)
  class_struct     *class;
  auth_area_struct *auth_area;
  dl_list_type     *add_list;
  dl_list_type     *delete_list;
  dl_list_type     *mod_list;
  dl_list_type     *unlock_list;
  dl_list_type     *lock_list;
{
  dl_list_type   full_file_list;
  char           write_index_file[MAX_FILE + 1];
  int            lock_fd   = -1;
  mkdb_lock_type lock_mode = MKDB_LOCK_ON;

  if (!class || !auth_area)
  {
    return FALSE;
  }

  dl_list_default(&full_file_list, FALSE, (int(*)(void *))destroy_file_struct_data);

  /* first, we establish the write lock; This prevents staleness
     problems. */
  if (!get_master_index_file(class, auth_area, MFL_WRITE, write_index_file))
  {
    return FALSE;
  }

  if (!get_placeholder_lock(write_index_file, LOCK_BLOCKING_TIME, &lock_fd))
  {
    log(L_LOG_ERR, MKDB,
        "could not obtain lock for master index file '%s': %s",
        write_index_file, strerror(errno));
    return FALSE;
  }

  log(L_LOG_DEBUG, MKDB, "master file write start: %d", (int) getpid());

  /* read the current master file list */
  if (!get_file_list(class, auth_area, &full_file_list))
  {
    release_placeholder_lock(write_index_file, lock_fd);
    return FALSE;
  }

  /* guess if we want to add files locked (inactive) or not.  If we
     passed in an unlock list, then we probably want to unlock added
     files too.

     FIXME: this should be done via a parameter, or some other logic */
  if (unlock_list && !dl_list_empty(unlock_list))
  {
    lock_mode = MKDB_LOCK_OFF;
  }

  /* add loop */
  if (add_list)
  {
    add_file_list(add_list, &full_file_list, lock_mode);
  }

  /* delete loop */
  if (delete_list)
  {
    delete_file_list(delete_list, &full_file_list);
  }

  /* modify loop */
  if (mod_list)
  {
    mod_file_list(mod_list, &full_file_list);
  }

  /* unlock loop */
  if (unlock_list)
  {
    lock_unlock_file_list(unlock_list, &full_file_list, MKDB_LOCK_OFF);
  }

  /* lock loop */
  if (lock_list)
  {
    lock_unlock_file_list(lock_list, &full_file_list, MKDB_LOCK_ON);
  }

  /* write the file list back out */
  write_file_list(write_index_file, &full_file_list);
  install_write_file_list(class, auth_area);

  /* now, we can release the lock */
  log(L_LOG_DEBUG, MKDB, "master file write end: %d", (int) getpid());

  release_placeholder_lock(write_index_file, lock_fd);

  dl_list_destroy(&full_file_list);

  return TRUE;
}


void
unlink_file_list(file_list)
  dl_list_type *file_list;
{
  file_struct  *file;
  int          not_done;

  if (!file_list)
  {
    return;
  }

  if (!dl_list_empty(file_list))
  {
    not_done = dl_list_first(file_list);
    while (not_done)
    {
      file = dl_list_value(file_list);

      if (file && file->filename &&
          file_exists(file->filename))
      {
        unlink(file->filename);
      }

      not_done = dl_list_next(file_list);
    }
  }
}


/* find_file_by_id: searches a file list for a file_struct with
     'id'.  Returns NULL if not found. */
file_struct *
find_file_by_id(list, id, type)
  dl_list_type   *list;
  int            id;
  mkdb_file_type type;
{
  int           not_done;
  file_struct   *fi;

  not_done = dl_list_first(list);

  while (not_done)
  {
    fi = dl_list_value(list);
    if (fi && fi->file_no == id && mkdb_file_type_equals(type, fi->type))
    {
      return(fi);
    }

    not_done = dl_list_next(list);
  }

  return NULL;
}


/* find_file_by_name: searches a file list for a file_struct with
   filename 'name'.  Returns NULL if not found. */
file_struct *
find_file_by_name(list, name, type)
  dl_list_type   *list;
  char           *name;
  mkdb_file_type type;
{
  int           not_done;
  file_struct   *fi;

  not_done = dl_list_first(list);

  while (not_done)
  {
    fi = dl_list_value(list);
    if (fi && STR_EQ(fi->filename, name) &&
        mkdb_file_type_equals(type, fi->type))
    {
      return(fi);
    }

    not_done = dl_list_next(list);
  }

  return NULL;
}

long
records_in_auth_area(auth_area)
  auth_area_struct *auth_area;
{
  dl_list_type master_file_list;
  dl_list_type data_file_list;
  file_struct  *fi;
  long         count    = 0;
  int          not_done;

  dl_list_default(&master_file_list, FALSE, (int(*)(void *))destroy_file_struct_data);
  dl_list_default(&data_file_list, FALSE, (int(*)(void *))destroy_file_struct_data);

  if (!get_file(NULL, auth_area->name, &master_file_list))
  {
    return 0;
  }

  filter_file_list(&data_file_list, MKDB_DATA_FILE, &master_file_list);

  not_done = dl_list_first(&data_file_list);
  while (not_done)
  {
    fi = dl_list_value(&data_file_list);
    count += fi->num_recs;

    not_done = dl_list_next(&data_file_list);
  }

  dl_list_destroy(&master_file_list);
  dl_list_destroy(&data_file_list);

  return(count);
}

/* --------------- File List Constructors ------------- */

/* build_base_file_struct: given a path, a type and the number of
     records, allocate and return a resultant file structure. */
file_struct *
build_base_file_struct(file_name, type, num_recs)
  char           *file_name;
  mkdb_file_type type;
  long           num_recs;
{
  struct stat    sb;
  int            status;
  file_struct    *file;

  status = stat(file_name, &sb);

  if (status < 0) {
    /* stat itself failed (file doesn't exist) */
    return NULL;
  }

  file = xcalloc(1, sizeof(*file));

  file->filename  = xstrdup(file_name);
  file->type      = type;
  file->size      = sb.st_size;
  file->num_recs  = num_recs;

  return(file);
}

file_struct *
build_tmp_base_file_struct(tmp_filename, base_template, type, num_recs)
  char           *tmp_filename;
  char           *base_template;
  mkdb_file_type type;
  long           num_recs;
{
  struct stat    sb;
  int            status;
  file_struct    *file;

  status = stat(tmp_filename, &sb);

  if (status < 0) {
    /* stat itself failed (file doesn't exist) */
    return NULL;
  }

  file = xcalloc(1, sizeof(*file));

  file->filename      = NULL;
  file->type          = type;
  file->size          = sb.st_size;
  file->num_recs      = num_recs;
  file->tmp_filename  = xstrdup(tmp_filename);
  if (base_template)
  {
    file->base_filename = xstrdup(base_template);
  }

  return(file);
}


int
build_file_list_by_names(file_list, type, base_dir, num_names, names)
  dl_list_type      *file_list;
  mkdb_file_type    type;
  char              *base_dir;
  int               num_names;
  char              **names;
{
  file_struct   *df;
  char          path[MAX_FILE + 1];
  int           status = FALSE;
  int           i;

  bzero(path, sizeof(path));

  for (i = 0; i < num_names; i++)
  {
    /* since add_file_struct will normalize the path, we just take the
       easy way out and convert it to a full path */
    if (names[i] && *names[i])
    {
      path_rel_to_full(path, MAX_FILE, names[i], base_dir);
      df = build_base_file_struct(path, type, 0);

      if (df)
      {
        dl_list_append(file_list, df);
        status = TRUE;
      }
    }
  }

  return(status);
}

int
build_file_list_by_suffix(file_list, type, base_dir, suffix)
  dl_list_type   *file_list;
  mkdb_file_type type;
  char           *base_dir;
  char           *suffix;
{
  file_struct   *fi;
  DIR           *dir_fp;
  struct dirent *entry;
  char          path[MAX_FILE + 1];
  char          rev_suffix[MAX_FILE];
  char          *d_name;
  int           suffix_len;

  if (!file_list || !base_dir || !*base_dir || !suffix || !*suffix)
  {
    return FALSE;
  }

  bzero(path, sizeof(path));
  suffix_len = strlen(suffix);
  strcpy(rev_suffix, suffix);
  strrev(rev_suffix);

  dir_fp = opendir(base_dir);
  if (!dir_fp)
  {
    log(L_LOG_ERR, MKDB, "could not open directory '%s': %s", base_dir,
              strerror(errno));
    return FALSE;
  }

  while ( (entry = readdir(dir_fp)) != NULL )
  {
    d_name = (char *)(entry->d_name);
    if (!strncmp(rev_suffix, strrev(d_name), suffix_len))
    {
      path_rel_to_full(path, MAX_FILE, strrev(d_name), base_dir);
      fi = build_base_file_struct(path, type, 0);

      if (fi)
      {
        dl_list_append(file_list, fi);
      }
    }
  }

  closedir(dir_fp);
  return TRUE;
}

/* --------------- Destructor Components  ------------- */

int
destroy_file_struct_data(data)
  file_struct   *data;
{
  if (!data)
  {
    return TRUE;
  }

  if (data->filename)
  {
    free(data->filename);
  }

  if (data->tmp_filename)
  {
    free(data->tmp_filename);
  }

  if (data->base_filename)
  {
    free(data->base_filename);
  }

  if (data->fp)
  {
    fclose(data->fp);
  }

  free(data);

  return TRUE;
}


