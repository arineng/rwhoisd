/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "records.h"

#include "anon_record.h"
#include "attributes.h"
#include "client_msgs.h"
#include "defines.h"
#include "log.h"
#include "misc.h"
#include "schema.h"
#include "validate_rec.h"

/* ----------------------- Local Functions ---------------------- */

static int
encode_av_pair(class, av, line)
  class_struct      *class;
  av_pair_struct    *av;
  char              *line;
{
  /* Right now this routine is very simple; however, I expect that it
     will become more complex as more space and flexiblity issues move
     to the forefront. */
  if ((char *)av->value && *((char *)av->value))
  {
    sprintf(line, "%s:%s", av->attr->name, (char *)av->value);
  }

  return TRUE;
}

static av_pair_struct *
translate_anon_av_pair(anon_av, class, auth_area, validate_flag, status)
  anon_av_pair_struct *anon_av;
  class_struct        *class;
  auth_area_struct    *auth_area;
  int                 validate_flag;
  av_parse_result     *status;
{
  av_pair_struct   *av;
  attribute_struct *attr;
  int              protocol_error_flag;
  int              quiet_mode_flag;

  if (!anon_av || !class || !status)
  {
    log(L_LOG_ERR, MKDB, "translate_anon_av_pair: null data detected");
    if (status) *status = AV_STOP;
    return NULL;
  }
  
  decode_validate_flag(validate_flag, &quiet_mode_flag, &protocol_error_flag,
                       NULL);
  
  attr = find_attribute_by_name(class, anon_av->attr_name);

  if (!attr)
  {
    *status = AV_IGNORE;
    if (protocol_error_flag)
    {
      print_error(INVALID_ATTRIBUTE, anon_av->attr_name);
      *status = AV_STOP;
    }
    
    if (!quiet_mode_flag)
    {
      log(L_LOG_ERR, MKDB,
          "attribute name '%s' not valid for class '%s'", anon_av->attr_name,
          class->name);
    }
    return NULL;
  }

  if (NOT_STR_EXISTS(anon_av->value))
  {
    /* ignore null attributes on read */
    *status = AV_IGNORE;
    return NULL;
  }

  /* fill out the av_pair */
  av        = xcalloc(1, sizeof(*av));
  av->attr  = attr;
  av->value = xstrdup(anon_av->value);

  return(av);
}
  
/* ----------------------- Global Functions --------------------- */


/* mkdb_translate_anon_record: given an anonymous record, translate it
   to a real record structure. This routine will handle records that
   were stored without explict class name or authority area
   attributes. */
record_struct *
mkdb_translate_anon_record(anon, class, auth_area, validate_flag)
  anon_record_struct *anon;
  class_struct       *class;
  auth_area_struct   *auth_area;
  int                validate_flag;
{
  record_struct       *rec;
  anon_av_pair_struct *anon_av;
  av_pair_struct      *av;
  dl_list_type        *anon_av_list;
  dl_list_type        *av_list;
  int                 find_all_flag;
  int                 not_done;
  av_parse_result     av_status;
  
  if (!anon || !auth_area || !class)
  {
    log(L_LOG_ERR, MKDB, "mkdb_translate_anon_record: null data detected");
    return NULL;
  }

  decode_validate_flag(validate_flag, NULL, NULL, &find_all_flag);

  rec               = xcalloc(1, sizeof(*rec));
  rec->data_file_no = anon->data_file_no;
  rec->offset       = anon->offset;
  rec->auth_area    = auth_area;
  rec->class        = class;

  av_list           = &(rec->av_pair_list);
  dl_list_default(av_list, FALSE, destroy_av_pair_data);
  
  /* handle auth_area */
  anon_av = find_anon_auth_area_in_rec(anon);
  if (!anon_av)
  {
    append_attribute_to_record(rec, class, "Auth-Area", auth_area->name);
  }
  
  /* handle class */
  anon_av = find_anon_class_in_rec(anon);
  if (!anon_av)
  {
    append_attribute_to_record(rec, class, "Class-Name", class->name);
  }
  
  /* translate rest of av_pairs */
  anon_av_list = &(anon->anon_av_pair_list);
  
  not_done = dl_list_first(anon_av_list);
  while (not_done)
  {
    anon_av = dl_list_value(anon_av_list);
    av = translate_anon_av_pair(anon_av, class, auth_area, validate_flag,
                                &av_status);
    
    if (av)
    {
      dl_list_append(av_list, av);
    }

    not_done = dl_list_next(anon_av_list);
  }

  return(rec);
}


record_struct *
mkdb_read_record(class, auth_area, data_file_no, validate_flag, status, fp)
  class_struct      *class;
  auth_area_struct  *auth_area;
  int               data_file_no;
  int               validate_flag;
  rec_parse_result  *status;
  FILE              *fp;
{
  anon_record_struct *anon;
  record_struct      *rec;
  av_pair_struct     *av;
  char               *id = NULL;
  
  if (!class || !auth_area || !status || !fp)
  {
    log(L_LOG_ERR, MKDB, "mkdb_read_record: null data detected");
    if (status) *status = REC_FATAL;
    return NULL;
  }

  /* actually read the record */
  anon = mkdb_read_anon_record(data_file_no, validate_flag, status, fp);
  if (!anon)
  {
    /* status is already set */
    return NULL;
  }

  /* translate it; this does not check the record for syntactic validity */
  rec = mkdb_translate_anon_record(anon, class, auth_area, validate_flag);
  destroy_anon_record_data(anon);
  
  if (!rec)
  {
    *status = REC_FATAL;
    return NULL;
  }

  /* validate the record, if necessary */
  if (validate_flag)
  {
    if (!check_record(rec, validate_flag))
    {
      av = find_attr_in_record_by_name(rec, "ID");
      if (av)
      {
        id = (char *)av->value;
      }
      log(L_LOG_ERR, MKDB,
          "error found in record '%s'",
          SAFE_STR(id, "unknown"));

      destroy_record_data(rec);
      *status = REC_INVAL;
      return NULL;
    }
  }

  return(rec);
}

record_struct *
mkdb_read_next_record(class, auth_area, data_file_no, validate_flag,
                      status, fp)
  class_struct      *class;
  auth_area_struct  *auth_area;
  int               data_file_no;
  int               validate_flag;
  rec_parse_result  *status;
  FILE              *fp;
{
  record_struct *rec;

  if (!status)
  {
    return NULL;
  }
  
  *status = REC_NULL;

  while (*status != REC_OK && *status != REC_EOF)
  {
    rec = mkdb_read_record(class, auth_area, data_file_no, validate_flag,
                           status, fp);
    if (*status != REC_OK && rec)
    {
      destroy_record_data(rec);
    }
  }

  return(rec);
}

/* mkdb_write_record: given a record structure, write it to file
     stream 'fp', which needs to have been opened for writing. */
int
mkdb_write_record(record, fp)
  record_struct *record;
  FILE          *fp;
{
  char          line[MAX_LINE + 1];
  dl_list_type  *av_list = &(record->av_pair_list);
  int           not_done;
    
  bzero(line, sizeof(line));

  not_done = dl_list_first(av_list);
  while (not_done)
  {
    encode_av_pair(record->class, dl_list_value(av_list), line);
    fprintf(fp, "%s\n", line);
    
    not_done = dl_list_next(av_list);
  }

  return TRUE;
}

av_pair_struct *
find_attr_in_record_by_name(record, attr_name)
  record_struct *record;
  char          *attr_name;
{
  av_pair_struct *av;
  dl_list_type   *av_list;
  int            not_done;

  if (!record || !attr_name | !*attr_name)
  {
    return NULL;
  }

  av_list = &(record->av_pair_list);

  not_done = dl_list_first(av_list);

  while (not_done)
  {
    av = dl_list_value(av_list);
    if (STR_EQ(av->attr->name, attr_name))
    {
      return(av);
    }

    not_done = dl_list_next(av_list);
  }

  return NULL;
}

av_pair_struct *
find_attr_in_record_by_id(record, id)
  record_struct *record;
  int           id;
{
  av_pair_struct *av;
  dl_list_type   *av_list;
  int            not_done;

  if (!record)
  {
    return NULL;
  }

  av_list = &(record->av_pair_list);

  not_done = dl_list_first(av_list);

  while (not_done)
  {
    av = dl_list_value(av_list);
    if (av->attr->local_id == id)
    {
      return(av);
    }

    not_done = dl_list_next(av_list);
  }

  return NULL;
}


int
append_attribute_to_record(record, class, attrib_name, value)
  record_struct *record;
  class_struct  *class;
  char          *attrib_name;
  char          *value;
{
  av_pair_struct    *av;

  av = xcalloc(1, sizeof(*av));
  
  if ((av->attr = find_attribute_by_name(class, attrib_name)) == NULL) 
  {
    return FALSE;
  }

  av->value = xstrdup(value);
  dl_list_append(&(record->av_pair_list), av);

  return TRUE;
}

int
delete_attribute_from_record(record, attrib_name)
  record_struct *record;
  char          *attrib_name;
{
  av_pair_struct *av;
  dl_list_type   *av_list;
  int            not_done;
  int            status    = FALSE;
  
  av_list = &(record->av_pair_list);

  not_done = dl_list_first(av_list);
  while (not_done)
  {
    av = dl_list_value(av_list);
    if (STR_EQ(av->attr->name, attrib_name))
    {
      dl_list_delete(av_list);
      status = TRUE;
      continue; /* dl_list_delete contains explicit next() op */
    }
    not_done = dl_list_next(av_list);
  }

  return(status);
}

av_pair_struct *
copy_av_pair(av)
  av_pair_struct *av;
{
  av_pair_struct *copy;

  if (!av)
  {
    return NULL;
  }
  
  copy = xcalloc(1, sizeof(*copy));
  bcopy(av, copy, sizeof(*copy));

  /* since the value typically gets freed, duplicate it */
  /* FIXME: this routine definately assumes that the value is a
     string, but so far, this is always true.  If it isn't a string,
     then the struct would probably need a length field */
  copy->value = xstrdup((char *)av->value);
  
  return(copy);
}

record_struct *
copy_record(rec)
  record_struct *rec;
{
  record_struct  *copy;
  av_pair_struct *av;
  av_pair_struct *av_copy;
  int            not_done;
  
  if (!rec)
  {
    return NULL;
  }
  
  /* first copy the main body */
  copy = xcalloc(1, sizeof(*copy));
  bcopy(rec, copy, sizeof(*copy));

  /* copy the av_pair list */
  dl_list_default(&(copy->av_pair_list), FALSE, destroy_av_pair_data);

  not_done = dl_list_first(&(rec->av_pair_list));
  while (not_done)
  {
    av = dl_list_value(&(rec->av_pair_list));
    av_copy = copy_av_pair(av);
    dl_list_append(&(copy->av_pair_list), av_copy);

    not_done = dl_list_next(&(rec->av_pair_list));
  }

  return(copy);
}       

int
destroy_record_data(rec)
  record_struct *rec;
{
  if (!rec) return TRUE;

  /* don't free the class reference; it is probably anchored somewhere
     else */

  dl_list_destroy(&(rec->av_pair_list));

  free(rec);

  return TRUE;
}

int
destroy_av_pair_data(av)
  av_pair_struct    *av;
{
  if (!av) return TRUE;

  if (av->value)
  {
    free(av->value);
  }

  free(av);

  return TRUE;
}

