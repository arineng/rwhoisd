/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "search_prim.h"

#include "attributes.h"
#include "defines.h"
#include "fileinfo.h"
#include "index.h"
#include "log.h"
#include "misc.h"
#include "records.h"
#include "strutil.h"


static int hit_count = 0;

/* --------------------- Private Functions ------------------- */

static int
open_fp(file)
  file_struct *file;
{
  /* open the file, if necessary */
  if (!file->fp)
  {
    if ( (file->fp = fopen(file->filename, "r")) == NULL)
    {
      log(L_LOG_ERR, MKDB, "could not open file '%s': %s", file->filename,
          strerror(errno));
      return FALSE;
    }
  }
  return TRUE;
}

static int
close_fp(file)
  file_struct *file;
{
  if (file->fp)
  {
    fclose(file->fp);
    file->fp = NULL;
  }

  return TRUE;
}


/* check_hit_list_for_hit: returns TRUE if the index_item already
   exists in the record_list */
static int
check_hit_list_for_hit(class, auth_area, record_list, index_item)
  class_struct     *class;
  auth_area_struct *auth_area;
  dl_list_type     *record_list;
  index_struct     index_item;
{
  int           not_done;
  record_struct *record;

  not_done = dl_list_first(record_list);
  while (not_done)
  {
    record = dl_list_value(record_list);
    if ( (STR_EQ(record->auth_area->name, auth_area->name)) &&
         (STR_EQ(record->class->name, class->name))         &&
         (record->data_file_no == index_item.data_file_no)  &&
         (record->offset == index_item.offset) )
    {
      return(TRUE);
    }

    not_done = dl_list_next(record_list);
  }

  return FALSE;
}

/* validate_search_cond: compares the hit against the search item that
   found it, and returns true if the two form a 'valid' pair.  This
   allows us to invalidate certain kinds of searches (e.g.,
   unspecified searches on a type ID attribute) */
static int
validate_search_cond(class, auth_area, query_item, index_item)
  class_struct      *class;
  auth_area_struct  *auth_area;
  query_term_struct *query_item;
  index_struct      *index_item;
{
  attribute_struct *attr;

  attr = find_attribute_by_global_id(class, index_item->attribute_id);

  /* if the index item belongs to a ID attribute, and that attribute
     wasn't specified directly, then it isn't valid */
  if (attr && attr->type == TYPE_ID &&
      query_item->attribute_id != attr->global_id)
  {
    return FALSE;
  }

  return TRUE;
}

/* validate_and_list: compares the record against all of the AND
   conditions, returns true if the record matches all of the
   conditions */
static int
validate_and_list(record, query_list)
  record_struct     *record;
  query_term_struct *query_list;
{
  dl_list_type   *pair_list;
  av_pair_struct *pair;
  int            valid       = FALSE;
  int            not_done;

  while (query_list)
  {
    valid     = FALSE;
    pair_list = &(record->av_pair_list);
    not_done  = dl_list_first(pair_list);

    while (not_done)
    {
      pair = dl_list_value(pair_list);

      if ( (query_list->attribute_id == -2) ||
           (query_list->attribute_id == pair->attr->global_id) )
      {
        if ( (pair->value != NULL) &&
             (!search_compare(query_list, strupr((char *) pair->value))) )
        {
          valid = TRUE;
          break;
        }
      }
      not_done = dl_list_next(pair_list);
    }

    if (!valid)
    {
      return FALSE;
    }

    query_list = query_list->and_list;
  }

  return TRUE;
}


/* note: this routine should probably reside in some form in records.c */
static record_struct *
fill_out_record(class, auth_area, index_item, data_fi_list, status)
  class_struct     *class;
  auth_area_struct *auth_area;
  index_struct     *index_item;
  dl_list_type     *data_fi_list;
  rec_parse_result *status;
{
  file_struct      *fi;
  record_struct    *result;

  fi = find_file_by_id(data_fi_list, index_item->data_file_no, MKDB_DATA_FILE);

  if (!fi || !open_fp(fi))
  {
    return NULL;
  }

  /* seek to the start of the record */
  if (fseek(fi->fp, index_item->offset, SEEK_SET))
  {
#ifdef OFF_T64
    log(L_LOG_ERR, MKDB, "could not get to offset '%lld' in file '%s': %s",
        index_item->offset, fi->filename, strerror(errno));
#else
    log(L_LOG_ERR, MKDB, "could not get to offset '%ld' in file '%s': %s",
        index_item->offset, fi->filename, strerror(errno));
#endif
    return FALSE;
  }

  result = mkdb_read_record(class, auth_area, index_item->data_file_no, 0,
                            status, fi->fp);
  close_fp(fi);

  return(result);
}


/* --------------------- Public Functions -------------------- */

void
set_hit_count(value)
  int value;
{
  hit_count = value;
}

void
inc_hit_count()
{
  hit_count++;
}

int
get_hit_count()
{
  return(hit_count);
}

/* binary_search: This function performs a binary search of an index
   file. It returns the file position that points to the first hit in
   the index. The business of actually checking AND operations and
   such is done in the linear scan which should be called next. */
off_t
binary_search(file, query_item)
  file_struct       *file;
  query_term_struct *query_item;
{
  FILE              *fp         = NULL;
  char              buf[MAX_BUF];
  index_struct      index_item;
  int               found;
  int               y;
  off_t             high;
  off_t             low;
  off_t             mid;
  off_t             beg_of_line = -1;
  off_t             end_of_line = -1;
  off_t             save = -1;

  low   = 0;
  high  = file->size;
  found = FALSE;

  bzero(&index_item, sizeof(index_item));

  if (!open_fp(file))
  {
    return(-1);
  }
  fp = file->fp;

  /* do the binary search -- the search will only end if there is an
     error or the search space has collapsed.  This allows us to
     always end at the top of the sequence of equal search keys.  */

  while (low < high)
  {
    /* avoid overflow: K&R 2nd Ed. p. 138 */
    mid = low + (high - low) / 2;

    /* note that 'mid' and the file pointer will be set to the
       beginning of the line that contained the original mid */
    if (!scan_for_bol(fp, low, &mid, high) ||
        beg_of_line == mid || mid == high)
    {
      break;
    }
    beg_of_line = mid;

    /* scan_for_bol should have left the fp at the correct position */
    if (!readline(fp, buf, MAX_BUF))
    {
#ifdef OFF_T64
      log(L_LOG_ERR, MKDB, "failed to read index line at offset %lld: %s", mid,
          strerror(errno));
#else
      log(L_LOG_ERR, MKDB, "failed to read index line at offset %ld: %s", mid,
          strerror(errno));
#endif
      close_fp(file);
      return(-1);
    }

    end_of_line = ftell(fp);

    /* this routine allocates space for index_item.value */
    decode_index_line(buf, &index_item);

    y = search_compare(query_item, index_item.value);

    free(index_item.value);
    index_item.value = NULL;

    if (y == 0)
    {
      found = TRUE;
      save = high = beg_of_line;
    }
    else
    {
      if  (y < 0)
      {
        high = beg_of_line;
      }
      else
      {
        low = end_of_line;
      }
    }
  }

  close_fp(file);

  if (!found)
  {
    return(-1);
  }

  return(save);
}


/* full_scan: perform a linear search on the index, starting at
   start_pos, and ending either when the EOF is reached, or a key
   doesn't match (if find_all_flag is false). Returns the number of
   hits it added to 'hit_list', -1 on error. */
ret_code_type
full_scan(class, auth_area, file, data_fi_list, query_item, record_list,
          max_hits, start_pos, find_all_flag)
  class_struct      *class;
  auth_area_struct  *auth_area;
  file_struct       *file;
  dl_list_type      *data_fi_list;
  query_term_struct *query_item;
  dl_list_type      *record_list;
  int               max_hits;
  off_t             start_pos;
  int               find_all_flag;
{
  FILE             *fp;
  char             line[MAX_LINE];
  record_struct    *hi_ptr         = NULL;
  index_struct     index_item;
  rec_parse_result status;
  int              hit_limit_flag  = FALSE;
  int              y;

  bzero(&index_item, sizeof(index_item));

  if (!open_fp(file))
  {
    return UNKNOWN_SEARCH_ERROR;
  }

  fp = file->fp;

  fseek(fp, start_pos, SEEK_SET);

  while (TRUE)
  {
    if (!readline(fp, line, MAX_LINE))
    {
      /* we've hit the end of the file, most likely */
      break;
    }

    if (index_item.value)
    {
      free(index_item.value);
      index_item.value = NULL;
    }

    /* this routine allocates space for .value */
    decode_index_line(line, &index_item);

    /* skip it if it was deleted */
    if (index_item.deleted_flag)
    {
      continue;
    }

    /* if we have an attribute type */
    if (query_item->attribute_id)
    {
      /* then skip it if it doesn't match the attribute type for this hit */
      if ((query_item->attribute_id != -2) &&
          (query_item->attribute_id != index_item.attribute_id))
      {
        continue;
      }
    }

    /* check it */
    y = search_compare(query_item, index_item.value);

    /* if the index value doesn't match what we are looking for, then   */
    /* we have hit the end of the range                 */
    if (y && !find_all_flag)
    {
      break;
    }

    if (y) continue;

    /* if the match was good */
    if (!y)
    {
      /* then check and see if the search condition was valid */
      if (!validate_search_cond(class, auth_area, query_item, &index_item))
      {
        continue;
      }

      /* then check and see if we already have it. If so then just continue*/
      if (check_hit_list_for_hit(class, auth_area, record_list, index_item))
      {
        continue;
      }

      /* then fill out the rest of the actual record */
      hi_ptr = fill_out_record(class, auth_area, &index_item, data_fi_list,
                               &status);
      if (!hi_ptr)
      {
        if (status == REC_NULL || status == REC_EOF)
        {
          /* the record was deleted */
          continue;
        }
        else
        {
          /* the record was actually bad */
          close_fp(file);
          if (index_item.value) free(index_item.value);
          return UNKNOWN_SEARCH_ERROR;
        }
      }

      /* if there's an AND tree in this query validate this record
         against it and if it isn't then go to the next hit if it is
         valid then fall through below and add it to the hit list */
      if (query_item->and_list && !validate_and_list(hi_ptr,
                                                     query_item->and_list))
      {
        destroy_record_data(hi_ptr);
        continue;
      }
    }


    /* add the hit to the hit list */
    hi_ptr->index_file_no = file->file_no;

    /* don't add the record that would bring hit_count up to max hits
       (max number of records is really (max_hits - 1) */
    if ((max_hits == 0) || (get_hit_count() < max_hits))
    {
      dl_list_append(record_list, hi_ptr);
      inc_hit_count();
    }
    else
    {
      hit_limit_flag = TRUE;
      destroy_record_data(hi_ptr);
      break;
    }
  }

  if (index_item.value)
  {
    free(index_item.value);
    index_item.value = NULL;
  }

  close_fp(file);

  if (hit_limit_flag)
  {
    return HIT_LIMIT_EXCEEDED;
  }

  return SEARCH_SUCCESSFUL;
}

/* scan_for_bol: search backwards for newline - if none found then
   reverse direction and start over. */

#define     MAX_BACKUP_BUFFER   512
#define     BUF_MID             (int) MAX_BACKUP_BUFFER / 2

int
scan_for_bol(fp, low, offset, high)
  FILE          *fp;
  register off_t low;
  register off_t *offset;
  register off_t high;
{
  register off_t c;
  register int  inc = -1;
  off_t          save = *offset;
  off_t          buf_start_offset;
  register off_t internal_offset;
  off_t          buf_size;
  char          buf[MAX_BACKUP_BUFFER];

  if (*offset == 0)
  {
    return(TRUE);
  }

  /* calculate the offset (in the index file) of the buffer, taking
     into account the beginning of the file */
  buf_start_offset = *offset - BUF_MID;
  internal_offset = BUF_MID;
  if (buf_start_offset < 0)
  {
    internal_offset = *offset;
    buf_start_offset = 0;
  }

  /* read in the buffer */
  fseek(fp, buf_start_offset, SEEK_SET);
  buf_size = fread(buf, 1, MAX_BACKUP_BUFFER, fp);
  if (!buf_size)
  {
    /* we couldn't read anything from our offset */
#ifdef OFF_T64
    log(L_LOG_ERR, MKDB, "binary search hit invalid position '%lld': %s",
        *offset, strerror(errno));
#else
    log(L_LOG_ERR, MKDB, "binary search hit invalid position '%ld': %s",
        *offset, strerror(errno));
#endif
    return(FALSE);
  }

  /* scan for the beginning of the line
     Note: internal_offet + buf_start_offset = actual file position. */
  for (;
       internal_offset + buf_start_offset < high;
       internal_offset += inc)
  {

    /* check to see if we've run off the front of the buffer, if so,
       read the the preceding block and continue.  Note that this case
       is only likely to be exercised if there are index lines >
       MAX_BACKUP_BUFFER / 2 */
    if (internal_offset < 0)
    {
      buf_start_offset -= MAX_BACKUP_BUFFER;
      internal_offset = BUF_MID;
      if (buf_start_offset < 0)
      {
        internal_offset = buf_start_offset + MAX_BACKUP_BUFFER;
        buf_start_offset = 0;
      }
      fseek(fp, buf_start_offset, SEEK_SET);
      buf_size = fread(buf, 1, MAX_BACKUP_BUFFER, fp);
      if (!buf_size)
      {
        /* failed to read */
        return(FALSE);
      }
    }

    /* check to see if we've run off the back of the buffer, if so,
       read the next block.  Note that this is only likely to happen
       if there are index lines > MAX_BACKUP_BUFFER */
    if (internal_offset >= buf_size)
    {
      if (buf_size < MAX_BACKUP_BUFFER)
      {
        /* we're at the end of the file, so terminate unsuccessfully */
        return(FALSE);
      }
      buf_start_offset += MAX_BACKUP_BUFFER;
      internal_offset = 0;
      fseek(fp, buf_start_offset, SEEK_SET);
      buf_size = fread(buf, 1, MAX_BACKUP_BUFFER, fp);
      if (!buf_size)
      {
        /* error reading */
        return(FALSE);
      }
    }

    /* see if we've hit the preceding newline or the beginning of it all */
    c = buf[internal_offset];
    if (c == '\n')
    {
      /* we are one before the beginning of the line, so set the real
         offset, and move the file pointer appropriately */
      *offset = buf_start_offset + internal_offset + 1;
      fseek(fp, *offset, SEEK_SET);
      return(TRUE);
    }
    if (internal_offset == 0 && buf_start_offset == 0)
    {
      /* we are at the beginning of the file */
      *offset = 0;
      fseek(fp, *offset, SEEK_SET);
      return(TRUE);
    }

    /* see if we've hit the lower bound; note that is case is also
       unlikely to occur, as the binary search algorthm tends to place
       'low' at the end of a line anyway */
    if ( (buf_start_offset + internal_offset) < low )
    {
      *offset = save;
      inc = 1;

      buf_start_offset = *offset - BUF_MID;
      internal_offset = BUF_MID;
      if (buf_start_offset < 0)
      {
        internal_offset = *offset;
        buf_start_offset = 0;
      }

      fseek(fp, buf_start_offset, SEEK_SET);
      buf_size = fread(buf, 1, MAX_BACKUP_BUFFER, fp);
      if (!buf_size)
      {
        return(FALSE);
      }
    }
  }

  return(FALSE);
}


/* this function will return an integer based on the relationship of
   of the query_item to the actual value given in the second
   argument.
   If the query value is 'lower' than the index value then
     return(-1)
   If the query value is 'higher' than the index value then
     return(1)
   If there is an exact match then return(0)
   If there is no order (e.g. substring) then
   If there is an exact match then return(0)
   If there isn't a match then return(1) */

int
search_compare(query_item, index_value)
  query_term_struct *query_item;
  char              *index_value;
{
  int  relationship = 0;
  char *substring;

  switch (query_item->comp_type)
  {
  case MKDB_FULL_COMPARE:
    relationship = strcmp(query_item->search_value,index_value);
    if (relationship == 0)
    {
      return(0);
    }
    if (relationship < 0)
    {
      return(-1);
    }
    if (relationship > 0)
    {
      return(1);
    }
    break;
  case MKDB_PARTIAL_COMPARE:
    relationship = strncmp(query_item->search_value, index_value,
                           strlen(query_item->search_value));
    if (relationship == 0)
    {
      return(0);
    }
    if (relationship < 0)
    {
      return(-1);
    }
    if (relationship > 0)
    {
      return(1);
    }
    break;
  case MKDB_SUBSTR_COMPARE:
    substring = strSTR((char *) index_value,
                       (char *) query_item->search_value);
    if (substring == NULL)
    {
      return(1);
    }
    else
    {
      return(0);
    }
    break;

  default:
    log(L_LOG_ERR, MKDB, "invalid search type '%d'", query_item->comp_type);
    break;
  }

  return(-2);
}

