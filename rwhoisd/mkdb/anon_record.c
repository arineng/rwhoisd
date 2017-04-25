/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "anon_record.h"

#include "attributes.h"
#include "client_msgs.h"
#include "defines.h"
#include "log.h"
#include "misc.h"
#include "schema.h"
#include "validate_rec.h"

anon_av_pair_struct *
get_anon_av_pair(line, validate_flag, status)
  char            *line;
  int             validate_flag;
  av_parse_result *status;
{
  anon_av_pair_struct *av_pair = NULL;
  char                attr_name[MAX_LINE];
  char                value[MAX_LINE];
  int                 quiet_mode_flag;
  int                 protocol_error_flag;

  decode_validate_flag(validate_flag, &quiet_mode_flag, &protocol_error_flag,
                       NULL);
  
  *attr_name = *value = '\0';
  *status = AV_OK; /* be optimistic */
  
  if (! parse_line(line, attr_name, value))
  {
    *status = AV_IGNORE;
    if (!quiet_mode_flag && !strchr(line, '#'))
    {
      log(L_LOG_ERR, MKDB, "malformed data file line: '%s' %s",
          line, file_context_str());
    }
    return NULL;
  }

  av_pair = xcalloc(1, sizeof(*av_pair));

  av_pair->attr_name = xstrdup(attr_name);
  av_pair->value = xstrdup(value);
  
  return(av_pair);
}


/* mkdb_read_anon_record: given a data_file_no, a validate flag, and a
   file pointer set at the beginning of a record in a data file, read
   the anonymous record into the structure. */
anon_record_struct *
mkdb_read_anon_record(data_file_no, validate_flag, status, fp)
  int              data_file_no;
  int              validate_flag;
  rec_parse_result *status;
  FILE             *fp;
{
  anon_record_struct  *rec;
  anon_av_pair_struct *av;
  dl_list_type        *av_list;
  av_parse_result     av_status;
  char                line[MAX_LINE + 1];
  int                 read_flag = FALSE;
  int                 find_all_flag;
  int                 eof_flag;
  
  if (!fp || !status)
  {
    log(L_LOG_ERR, MKDB, "mkdb_read_anon_record: null data detected");
    if (status) *status = REC_FATAL;
    return NULL;
  }

  decode_validate_flag(validate_flag, NULL, NULL, &find_all_flag);
  
  rec               = xcalloc(1, sizeof(*rec));

  rec->data_file_no = data_file_no;
  rec->offset       = ftell(fp);
  
  av_list = &(rec->anon_av_pair_list);
  dl_list_default(av_list, FALSE, destroy_anon_av_pair_data);

  eof_flag = TRUE;  /* flag is set differently if loop ends for a different
                       reason */

  /* fp is assumed to start at the top of a record */
  while (readline(fp, line, MAX_LINE))
  {
    inc_log_context_line_num(1); /* assuming we are tracking a log contxt... */
    
    if (new_record(line))
    {
      eof_flag = FALSE;
      break;
    }

    if (line[0] == '_')
    {
      /* skip deleted lines */
      continue;
    }

    av = get_anon_av_pair(line, validate_flag, &av_status);
    if (!av || (av_status != AV_OK))
    {
      /* bad av pairs are not normally fatal, but we want to stop if we are
         not finding all errors; currently this will never happen. */
      
/*       if (validate_flag && !find_all_flag && (av_status == AV_STOP)) */
/*       { */
/*         *status = REC_INVAL; */
/*         return NULL; */
/*       } */
      
      continue;
    }

    if (!read_flag) read_flag++;

    dl_list_append(av_list, av);
  }

  if (! read_flag)
  {
    destroy_anon_record_data(rec);
    if (eof_flag)
    {
      *status = REC_EOF;
    }
    else
    {
      *status = REC_NULL;
    }
    return NULL;
  }

  *status = REC_OK;
  return(rec);
}

anon_av_pair_struct *
find_anon_attr_in_rec(anon_rec, attr_name)
  anon_record_struct *anon_rec;
  char               *attr_name;
{
  anon_av_pair_struct *av;
  dl_list_type        *av_list;
  int                 not_done;
  
  if (!anon_rec || !attr_name)
  {
    return NULL;
  }

  av_list = &(anon_rec->anon_av_pair_list);
  
  not_done = dl_list_first(av_list);
  while (not_done)
  {
    av = dl_list_value(av_list);
    if (av && STR_EXISTS(av->attr_name) && STR_EQ(av->attr_name, attr_name))
    {
      return(av);
    }

    not_done = dl_list_next(av_list);
  }

  return NULL;
}

anon_av_pair_struct *
find_anon_auth_area_in_rec(anon_rec)
  anon_record_struct *anon_rec;
{
  anon_av_pair_struct *av;
  dl_list_type        *av_list;
  int                 not_done;

  if (!anon_rec)
  {
    return NULL;
  }

  av_list = &(anon_rec->anon_av_pair_list);

  not_done = dl_list_first(av_list);
  while (not_done)
  {
    av = dl_list_value(av_list);

    if (av && STR_EXISTS(av->attr_name) &&
        (STR_EQ(av->attr_name, "Auth-Area") ||
         STR_EQ(av->attr_name, "AA")))
    {
      return(av);
    }

    not_done = dl_list_next(av_list);
  }

  return NULL;
}

anon_av_pair_struct *
find_anon_class_in_rec(anon_rec)
  anon_record_struct *anon_rec;
{
  anon_av_pair_struct *av;
  dl_list_type        *av_list;
  int                 not_done;

  if (!anon_rec)
  {
    return NULL;
  }

  av_list = &(anon_rec->anon_av_pair_list);

  not_done = dl_list_first(av_list);
  while (not_done)
  {
    av = dl_list_value(av_list);

    if (av && STR_EXISTS(av->attr_name) &&
        (STR_EQ(av->attr_name, "Class-Name") ||
         STR_EQ(av->attr_name, "cn") ||
         STR_EQ(av->attr_name, "Schema-Name") ||
         STR_EQ(av->attr_name, "Object-Type")))
    {
      return(av);
    }

    not_done = dl_list_next(av_list);
  }

  return NULL;
}

anon_av_pair_struct *
find_anon_updated_in_rec(anon_rec)
  anon_record_struct *anon_rec;
{
  anon_av_pair_struct *av;
  dl_list_type        *av_list;
  int                 not_done;

  if (!anon_rec)
  {
    return NULL;
  }

  av_list = &(anon_rec->anon_av_pair_list);

  not_done = dl_list_first(av_list);
  while (not_done)
  {
    av = dl_list_value(av_list);

    if (av && STR_EXISTS(av->attr_name) &&
        (STR_EQ(av->attr_name, "Updated") ||
         STR_EQ(av->attr_name, "UP")))
    {
      return(av);
    }

    not_done = dl_list_next(av_list);
  }

  return NULL;
}


int
destroy_anon_record_data(rec)
  anon_record_struct    *rec;
{
  if (!rec) return TRUE;
  
  dl_list_destroy(&(rec->anon_av_pair_list));

  free(rec);

  return TRUE;
}

int
destroy_anon_av_pair_data(av)
  anon_av_pair_struct   *av;
{
  if (!av) return TRUE;

  if (av->attr_name) free(av->attr_name);
  if (av->value) free(av->value);

  free(av);

  return TRUE;
}
