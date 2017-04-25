/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "delete.h"

#include "defines.h"
#include "fileinfo.h"
#include "index.h"
#include "log.h"
#include "misc.h"
#include "search.h"

/* local prototypes */
static int mkdb_delete_index_entry PROTO((dl_list_type *fi_list,
                                          int          index_file_index,
                                          int          data_file_index,
                                          off_t        offset,
                                          dl_list_type *changed_fi_list));

static int mkdb_delete_data_entry PROTO((dl_list_type  *fi_list,
                                         record_struct *hit_item,
                                         dl_list_type  *changed_fi_list));

int
mkdb_delete_record_list (record_list)
  dl_list_type *record_list;
{
  record_struct *record;
  dl_list_type  all_file_list;
  dl_list_type  changed_fi_list;
  int           not_done;
  int           status      = FALSE;

  not_done = dl_list_first(record_list);

  while (not_done)
  {
    record = dl_list_value(record_list);

    dl_list_default(&all_file_list, FALSE, destroy_file_struct_data);
    dl_list_default(&changed_fi_list, FALSE, destroy_file_struct_data);

    if (!get_file_list(record->class, record->auth_area, &all_file_list))
    {
      log(L_LOG_ERR, MKDB,
          "cannot open master index file for class '%s' in auth-area '%s': %s",
          record->class->name, record->auth_area->name, strerror(errno));
      return FALSE;
    }

    status = mkdb_delete_record(&all_file_list, record, &changed_fi_list);

    /* post the change in number of records to the master file list */
    if (!dl_list_empty(&changed_fi_list))
    {
      modify_file_list(record->class, record->auth_area, NULL, NULL,
                       &changed_fi_list, NULL, NULL);
    }

    dl_list_destroy(&all_file_list);
    dl_list_destroy(&changed_fi_list);
    not_done = dl_list_next(record_list);
  }

  return(status);
}

int
mkdb_delete_record(file_list, hit_item, changed_fi_list)
  dl_list_type  *file_list;
  record_struct *hit_item;
  dl_list_type  *changed_fi_list;
{
  int   status;

  /* for now, we only delete the data entry */

/*   status = mkdb_delete_index_entry(file_list, hit_item->index_file_no, */
/*                                 hit_item->data_file_no, hit_item->offset, */
/*                                 changed_fi_list); */
/*   if (!status) return(status); */

  status = mkdb_delete_data_entry(file_list, hit_item, changed_fi_list);

  return(status);
}

static int
mkdb_delete_index_entry(fi_list, index_file_index, data_file_index, offset,
                        changed_fi_list)
  dl_list_type      *fi_list;
  int               index_file_index;
  int               data_file_index;
  off_t             offset;
  dl_list_type      *changed_fi_list;
{
  file_struct       *fi             = NULL;
  index_struct      index_item;
  char              line[MAX_LINE];
  off_t             index_offset;
  FILE              *fp;
  int               changed_flag = FALSE;

  fi = find_file_by_id(fi_list, index_file_index, MKDB_ALL_INDEX_FILES);
  if (!fi)
  {
    return FALSE;
  }

  /* open the index file for update */
  if (fi->fp)
  {
    fclose(fi->fp);
    fi->fp = NULL;
  }

  if ( (fp = fopen(fi->filename, "r+")) == NULL )
  {
    log(L_LOG_ERR, MKDB,
        "could not open index file '%s' for update: %s",
        fi->filename, strerror(errno));
    return FALSE;
  }

  /* make the file write through the cache */
  setbuf(fp, NULL);

  index_offset = 0;

  while (readline(fp, line, MAX_LINE))
  {
    if (decode_index_line(line, &index_item) &&
        (index_item.offset == offset &&
         index_item.data_file_no == data_file_index &&
         !index_item.deleted_flag))
    {
      index_item.deleted_flag = TRUE;
      encode_index_line(line, &index_item);
      fseek(fp, index_offset, SEEK_SET);
      fprintf(fp, "%s", line);
      fseek(fp, index_offset, SEEK_SET);
      fi->num_recs--; changed_flag = TRUE;
    }
    index_offset = ftell(fp);
    if (index_item.value) free(index_item.value);
  }

  fclose(fp);

  if (changed_flag)
  {
    dl_list_append(changed_fi_list, copy_file_struct(fi));
  }

  return TRUE;
}


int
mkdb_delete_data_entry(fi_list, hit_item, changed_fi_list)
  dl_list_type      *fi_list;
  record_struct     *hit_item;
  dl_list_type      *changed_fi_list;
{
  FILE        *fp;
  file_struct *fi;
  off_t       pos;
  char        buffer[MAX_LINE];

  /* open the file for updating */
  fi = find_file_by_id(fi_list, hit_item->data_file_no, MKDB_DATA_FILE);

  if (!fi)
  {
    log(L_LOG_ERR, MKDB, "could not find entry for file with id %s",
        hit_item->data_file_no);
    return FALSE;
  }

  if (fi->fp) /* this will undoubtedly be true, but test anyway */
  {
    fclose(fi->fp);
    fi->fp = NULL;
  }

  if ( (fp = fopen(fi->filename, "r+")) == NULL )
  {
    log(L_LOG_ERR, MKDB,
        "could not open data file '%s' for update: %s",
        fi->filename, strerror(errno));
    return FALSE;
  }

  /* make file write through the cache */
  setbuf(fp, NULL);

  fseek(fp, hit_item->offset, SEEK_SET);
  pos = ftell(fp);
  fgets(buffer,MAX_LINE,fp);
  while (strcspn(buffer,"---") > 0)
  {
    buffer[0] = '_';
    fseek(fp,pos,SEEK_SET);
    fputs(buffer,fp);
    pos = ftell(fp);

    if (!(fgets(buffer,MAX_LINE,fp)))
    {
      break;
    }
  }

  fi->num_recs--;

  dl_list_append(changed_fi_list, copy_file_struct(fi));

  fclose(fp);

  return TRUE;
}


