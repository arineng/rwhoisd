/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "validate_rec.h"

#include "client_msgs.h"
#include "dl_list.h"
#include "defines.h"
#include "log.h"
#include "misc.h"
#include "strutil.h"

/* ----------------- Local Functions ------------------ */

/* validate_format: given a format string and the value, see if the
     strings match.  If so, return TRUE, else FALSE.

     NOTE: currently returns true on all but tagged regular
     expressions, i.e., format string = "re: <regular expression>" */
static int
validate_format(format_str, value)
  char  *format_str;
  char  *value;
{
  regexp    *prog;
  char      tag[MAX_LINE];
  char      datum[MAX_LINE];
  int       status;
  
  if (parse_line(format_str, tag, datum) && STR_EQ(tag, "re"))
  {
    ltrim(datum);

    prog = regcomp(datum);
    if (!prog)
    {
      return(-1);
    }

    status = regexec(prog, strupr(value));
    free(prog);

    return(status);
  }

  return TRUE;
}

/* ----------------- Public Functions ----------------- */

int
encode_validate_flag(quiet_mode_flag, protocol_error_flag, find_all_flag)
  int   quiet_mode_flag;
  int   protocol_error_flag;
  int   find_all_flag;
{
  int   result  = VALIDATE_ON;

  if (quiet_mode_flag)
  {
    result |= VALIDATE_QUIET;
  }
  
  if (!quiet_mode_flag && protocol_error_flag)
  {
    result |= VALIDATE_PROTOCOL_ERROR;
  }

  if (find_all_flag && !protocol_error_flag)
  {
    result |= VALIDATE_FIND_ALL;
  }

  return(result);
}

void
decode_validate_flag(validate_flag, quiet_mode_flag, protocol_error_flag,
                     find_all_flag)
  int   validate_flag;
  int   *quiet_mode_flag;
  int   *protocol_error_flag;
  int   *find_all_flag;
{
  if (quiet_mode_flag)
  {
    if (validate_flag & VALIDATE_QUIET)
    {
      *quiet_mode_flag = TRUE;
    }
    else
    {
      *quiet_mode_flag = FALSE;
    }
  }

  if (protocol_error_flag)
  { 
    if (validate_flag & VALIDATE_PROTOCOL_ERROR)
    {
      *protocol_error_flag = TRUE;
    }
    else
    {
      *protocol_error_flag = FALSE;
    }
  }
  
  if (find_all_flag)
  {
    if (validate_flag & VALIDATE_FIND_ALL)
    {
      *find_all_flag = TRUE;
    }
    else
    {
      *find_all_flag = FALSE;
    }
  }
}

/* find_record_attr_by_id: given a rec, return the av_pair that
     matches local_id 'id', NULL if not found. */
av_pair_struct *
find_record_attr_by_id(record, id)
  record_struct *record;
  int           id;
{
  av_pair_struct    *av;
  int               not_done;

  not_done = dl_list_first(&record->av_pair_list);
  while (not_done)
  {
    av = dl_list_value(&record->av_pair_list);
    if (!av || !av->attr)
    {
      return NULL;
    }

    if (av->attr->local_id == id)
    {
      return(av);
    }

    not_done = dl_list_next(&record->av_pair_list);
  }

  return NULL;
}

int
count_record_attr_by_id(record, id)
  record_struct *record;
  int           id;
{
  av_pair_struct    *av;
  dl_list_type      *av_pair_list;
  int               not_done;
  int               count           = 0;
  if (!record)
  {
    return(0);
  }

  av_pair_list = &(record->av_pair_list);

  not_done = dl_list_first(av_pair_list);
  while (not_done)
  {
    av = dl_list_value(av_pair_list);

    if (av->attr->local_id == id)
    {
      count++;
    }

    not_done = dl_list_next(av_pair_list);
  }

  return(count);
}

  

/* check_required: make sure record conforms to the "required"
     attributes the hte schema defintion of record->class.
     'protocol_error_flag' controls whether the detected errors are
     reported to a client or simply logged as server errors.
     'find_all_flag' controls whether the detection of an error
     short-circuits the process. */
int
check_required(record, validate_flag)
  record_struct *record;
  int           validate_flag;
{
  attribute_struct  *attr;
  av_pair_struct    *av;
  dl_list_type      *attr_list;
  int               protocol_error_flag;
  int               quiet_mode_flag;
  int               find_all_flag;
  int               not_done;
  int               status      = TRUE; 

  decode_validate_flag(validate_flag, &quiet_mode_flag, &protocol_error_flag,
                       &find_all_flag);
  
  if (!record || !record->class)
  {
    if (protocol_error_flag)
    {
      print_error(UNIDENT_ERROR, "");
    }
    return FALSE;
  }

  attr_list = &(record->class->attribute_list);
  
  not_done = dl_list_first(attr_list);
  av = NULL;
  
  while (not_done)
  {
    attr = dl_list_value(attr_list);
    
    if (attr->is_required)
    {
      av = find_record_attr_by_id(record, attr->local_id);
      if (! av)
      {
        if (protocol_error_flag)
        {
          print_error(MISSING_REQ_ATTRIB, attr->name);
        }
        else if (!quiet_mode_flag)
        {
          log(L_LOG_ERR, UNKNOWN, "required attribute missing: %s %s",
              attr->name, file_context_str());
        }

        if (!find_all_flag)
        {
          return FALSE;
        }
        else
        {
          status = FALSE;
        }
      }
    }

    not_done = dl_list_next(attr_list);
  }

  return(status);
}

int
check_repeated(record, validate_flag)
  record_struct *record;
  int           validate_flag;
{
  attribute_struct  *attr;
  dl_list_type      *attr_list;
  int               protocol_error_flag;
  int               quiet_mode_flag;
  int               find_all_flag;
  int               not_done;
  int               status      = TRUE;

  decode_validate_flag(validate_flag, &quiet_mode_flag, &protocol_error_flag,
                       &find_all_flag);

  if (!record || !record->class)
  {
    if (protocol_error_flag)
    {
      print_error(UNIDENT_ERROR, "");
    }
    return FALSE;
  }

  attr_list = &(record->class->attribute_list);

  not_done = dl_list_first(attr_list);

  while (not_done)
  {
    attr = dl_list_value(attr_list);

    if (!attr->is_repeatable && !attr->is_multi_line)
    {
      if (count_record_attr_by_id(record, attr->local_id) > 1)
      {
        if (protocol_error_flag)
        {
          print_error(INVALID_ATTRIBUTE, attr->name);
        }
        else if (!quiet_mode_flag)
        {
          log(L_LOG_ERR, UNKNOWN, "attribute '%s' cannot be repeated %s",
              attr->name, file_context_str());
        }

        if (!find_all_flag)
        {
          return FALSE;
        }
        else
        {
          status = FALSE;
        }
      }
    }

    not_done = dl_list_next(attr_list);
  }

  return(status);
}

int
check_formats(record, validate_flag)
  record_struct *record;
  int           validate_flag;
{
  av_pair_struct    *av;
  dl_list_type      *av_pair_list;
  int               protocol_error_flag;
  int               quiet_mode_flag;
  int               find_all_flag;
  int               not_done;
  int               status          = TRUE;

  decode_validate_flag(validate_flag, &quiet_mode_flag, &protocol_error_flag,
                       &find_all_flag);

  if (!record)
  {
    return FALSE;
  }

  av_pair_list = &(record->av_pair_list);

  not_done = dl_list_first(av_pair_list);

  while (not_done)
  {
    av = dl_list_value(av_pair_list);

    if (!av || !av->attr)
    {
      return FALSE;
    }

    if (av->attr->format)
    {
      if (! validate_format(av->attr->format, av->value))
      {
        if (protocol_error_flag)
        {
          print_error(INVALID_ATTR_SYNTAX, av->attr->name);
        }
        else
        {
          log(L_LOG_ERR, UNKNOWN, "invalid attribute format: <%s:%s> %s",
              av->attr->name, av->value, file_context_str());
        }

        if (!find_all_flag)
        {
          return FALSE;
        }
        else
        {
          status = FALSE;
        }
      }
    }

    not_done = dl_list_next(av_pair_list);
  }

  return(status);
}
  
int
check_record(record, validate_flag)
  record_struct *record;
  int           validate_flag;
{   
  int           find_all_flag;
  int           found_error   = FALSE;
  
  decode_validate_flag(validate_flag, NULL, NULL, &find_all_flag);

  if (!record)
  {
    return FALSE;
  }

  if (!check_required(record, validate_flag))
  {
    if (!find_all_flag)
    {
      return FALSE;
    }

    found_error++;
  }

  
  if (!check_repeated(record, validate_flag))
  {
    if (!find_all_flag)
    {
      return FALSE;
    }
    
    found_error++;
  }

  if (!check_formats(record, validate_flag))
  {
    if (!find_all_flag)
    {
      return FALSE;
    }

    found_error++;
  }

  return(!found_error);
}
