/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */


/* Implementation of xfer.
   -----------------------
   -xfer <auth-area> *[[class=] *[attr=]] [Serial-Num] */

#include <ctype.h>
#include "xfer.h"

#include "attributes.h"
#include "auth_area.h"
#include "client_msgs.h"
#include "defines.h"
#include "dl_list.h"
#include "fileinfo.h"
#include "log.h"
#include "misc.h"
#include "mkdb_types.h"
#include "records.h"
#include "types.h"
#include "strutil.h"
#include "schema.h"
#include "fileutils.h"

/* Data structure for a class; each class consists of a list of
   attributes; This class is an element in a linked-list of classes */
 
typedef struct xfer_class_struct 
{
  class_struct *class;
  dl_list_type attr_list;
} xfer_class_struct;
 

/* Data structure for the entire argument list.  The required auth-area is
   stored in auth_area, and the optional serial_num is stored in serial_num.
   The pointer to the head of the class list is first_class; */

typedef struct xfer_arg_struct 
{
  auth_area_struct *auth_area;
  char             *serial_no;
  dl_list_type     xfer_class_list;
} xfer_arg_struct;



/* ------------------- Local Functions -------------------- */


static int
destroy_xfer_class_data(xclass)
  xfer_class_struct *xclass;
{
  if (!xclass) return TRUE;

  dl_list_destroy(&(xclass->attr_list));
  free(xclass);

  return TRUE;
}

static int
destroy_xfer_arg_data(xarg)
  xfer_arg_struct *xarg;
{
  if (!xarg) return TRUE;

  if (xarg->serial_no)
  {
    free(xarg->serial_no);
  }

  dl_list_destroy(&(xarg->xfer_class_list));

  free(xarg);

  return TRUE;
}

/* xfer_split_av: splits a string into its attribute and 
value components. */

static void 
xfer_split_av(in_str, attr, value)
  char *in_str;
  char *attr;
  char *value;
{
  char  *eq = NULL;

  /* First see if there is an '=' in in_str.  If not, then copy the 
     whole string to value.  */
  eq = strchr(in_str, '=');
  
  if (!eq)
  {
    strcpy(value, in_str);
    attr[0] = '\0';
    return;
  }

  *eq++ = '\0';
  strcpy(attr, in_str);
  trim(attr);

  strcpy(value, eq);
  trim(value);

} /* end of xfer_split_av */


/* xfer_parse_args: function parses the argument list to the -xfer 
     directive.  It checks for all required arguments and stores the
     optional arguments in the appropriate data structure as defined
     in xfer_arg_struct.*/
static xfer_arg_struct * 
xfer_parse_args(str)
  char *str;
{
  xfer_arg_struct   *xs;
  xfer_class_struct *cur_xclass = NULL;
  auth_area_struct  *aa;
  class_struct      *class;
  attribute_struct  *a;
  int               argc;
  char              **argv;
  char              attr[MAX_LINE];
  char              value[MAX_LINE];
  int               i;
  int               j;
  char              *world = "0.0.0.0/0";  

  split_arg_list(str, &argc, &argv);

  if (argc < 1)
  {
    print_error(INVALID_DIRECTIVE_PARAM, "");
    free_arg_list(argv);
    return NULL;
  }

  xs = xcalloc(1, sizeof(*xs));
  dl_list_default(&(xs->xfer_class_list), FALSE, (int(*)(void *))destroy_xfer_class_data);

  if (STR_EQ(world, argv[0]))
  {
    print_error(INVALID_AUTH_AREA, "No world dumps allowed");
    return NULL;
  }

  /* locate the authority area */
  aa = find_auth_area_by_name(argv[0]);
  if (!aa)
  {
    print_error(INVALID_AUTH_AREA, "");
    free_arg_list(argv);
    destroy_xfer_arg_data(xs);
    return NULL;
  }
    if (aa->type == AUTH_AREA_SECONDARY)
    {
        print_error(NOT_MASTER_AUTH_AREA, "");
    free_arg_list(argv);
    destroy_xfer_arg_data(xs);
    return NULL;
  }

  xs->auth_area = aa;

  /* short-circuit check */
  if (argc == 1)
  {
    free_arg_list(argv);
    return(xs);
  }

  /* Split each argv into an AV pair.  Compare the A with "class" 
     or "attr" and store it in the appropriate variables.  If it
     is a Serial-Num, then store it in Serial-Num.  */

  for (i = 1; i < argc; i++)
  {
    xfer_split_av(argv[i], attr, value);

    if (!*attr)
    {
            if (strlen(value) != 17)
            {
                print_error(INVALID_DIRECTIVE_PARAM, "Wrong Version Number Format");
                free_arg_list(argv);
                destroy_xfer_class_data(cur_xclass);
                destroy_xfer_arg_data(xs);
                return NULL;
            }
            for (j = 0; j < strlen(value); j++)
            {
                if (!isdigit(value[j]))
                {
                    print_error(INVALID_DIRECTIVE_PARAM, "Wrong Version Number Format");
          free_arg_list(argv);
          destroy_xfer_class_data(cur_xclass);
          destroy_xfer_arg_data(xs);
          return NULL;
              }
      }
      xs->serial_no = xstrdup(value);
    }
    else
    {
      if (STR_EQ(attr, "class"))
      {
        cur_xclass = xcalloc(1, sizeof(*cur_xclass));
        dl_list_default(&(cur_xclass->attr_list), FALSE, (int(*)(void *))null_destroy_data);
        
        class = find_class_by_name(aa->schema, value);
        if (!class)
        {
          print_error(INVALID_CLASS, "");
          free_arg_list(argv);
          destroy_xfer_class_data(cur_xclass);
          destroy_xfer_arg_data(xs);
          return NULL;
        }

        cur_xclass->class = class;
        dl_list_append(&(xs->xfer_class_list), cur_xclass);
      } /* end of if (STR_EQ(attr, "class")) */
      else if (STR_EQ(attr, "attr"))
      {
        if (!cur_xclass)
        {
          print_error(INVALID_DIRECTIVE_PARAM, "");
          free_arg_list(argv);
          destroy_xfer_arg_data(xs);
          return NULL;
        }
        
        a = find_attribute_by_name(class, value);
        if (!a)
        {
          print_error(INVALID_ATTRIBUTE, "");
          free_arg_list(argv);
          destroy_xfer_arg_data(xs);
          return NULL;
        }
        dl_list_append(&(cur_xclass->attr_list), a);
      } /* end of else if (STR_EQ(attr, "attr")) */
    }  /* end of else. */
  } /* end of for loop */

  free_arg_list(argv);
  
  return(xs);
}  /* end of xfer_parse_args */


/* attr_in_xfer_class: check to see if attr is in the list of named
     attributes; if the xfer_class's attribute list is empty, assume
     that we want all attributes */
static int
attr_in_xfer_class(attr, xfer_class)
  attribute_struct  *attr;
  xfer_class_struct *xfer_class;
{
  dl_list_type     *attr_list;
  attribute_struct *a;
  int              not_done;
  
  attr_list = &(xfer_class->attr_list);

  if (dl_list_empty(attr_list)) return TRUE;
  
  not_done = dl_list_first(attr_list);
  while (not_done)
  {
    a = dl_list_value(attr_list);
    if (attr->local_id == a->local_id)
    {
      return TRUE;
    }

    not_done = dl_list_next(attr_list);
  }

  return FALSE;
}

static int
is_record_new(rec, serial_no)
  record_struct *rec;
  char          *serial_no;
{
  av_pair_struct *av;

  if (!rec || !serial_no || !*serial_no)
  {
    return FALSE;
  }

  av = find_attr_in_record_by_name(rec, "updated");
  if (av && av->value && (strcmp(av->value, serial_no) >= 0))
  {
    return TRUE;
  }

  return FALSE;
}

/* xfer_display_record:  xfer_display_record prints the record to the
     standard output.  This record belongs to the class class and
     displays only those fields which match the attributes given in
     curr_class.  It returns TRUE if any data is displayed. */
static int 
xfer_display_record(rec, class, curr_class)
  record_struct     *rec;
  class_struct      *class;
  xfer_class_struct *curr_class;
{
  av_pair_struct *av_pair;
  int            not_done;
  int            found_attr = FALSE;
  
  not_done = dl_list_first(&(rec->av_pair_list));

  while (not_done)
  {
    av_pair = dl_list_value(&(rec->av_pair_list));

    /* if curr_class is null, we want to transfer all attributes */
    if (!curr_class || attr_in_xfer_class(av_pair->attr, curr_class))
    {
      found_attr++;
      print_response(RESP_XFER, "%s:%s:%s", rec->class->name,
                     av_pair->attr->name, SAFE_STR(av_pair->value, ""));
    }

    not_done = dl_list_next(&(rec->av_pair_list));

  } /* end of while (not_done_rec) */

  if (found_attr)
  {
    print_response(RESP_XFER, "");
  }

  return(found_attr);
}  /* end of xfer_display_record */


/* xfer_file_xfer:  This function xfers data from curr_file containing data
     of curr_class in authority area aa, depending on the value of serial_no.
     It returns TRUE if any data is xferred. */ 
static int 
xfer_file_xfer(aa, curr_file, class, curr_class, serial_no)
  auth_area_struct  *aa;
  file_struct       *curr_file; 
  class_struct      *class;
  xfer_class_struct *curr_class;
  char              *serial_no;
{
  record_struct    *rec;
  FILE             *fp;
  rec_parse_result status;
  int              found = 0;
  
  fp = fopen(curr_file->filename, "r");
  if (!fp)
  {
    /* FIXME: log and print_error */
    return FALSE;
  }

  while ( (rec = mkdb_read_next_record(class, aa, curr_file->file_no, 0,
                                       &status, fp)) 
          != NULL )
  {
    if (!serial_no || is_record_new(rec, serial_no))
    {
      found += xfer_display_record(rec, class, curr_class);
    }

    destroy_record_data(rec);
  }  /* end of while ((rec = mkdb_read_record(class, ... ) */

  fclose(fp);   

  return(found);
}  /* end of xfer_file_xfer */


/* xfer_class:  This function xfers data from a class curr_class in an
   authority area aa, depending upon the value of the serial number.  It
   returns TRUE on successful xfer of data. */
static int 
xfer_class(aa, class, curr_class, serial_no)
  auth_area_struct  *aa;
  class_struct      *class;
  xfer_class_struct *curr_class; 
  char              *serial_no;
{
  int          not_done;
  int          found_data       = 0;
  dl_list_type master_file_list;
  dl_list_type file_list;
  file_struct  *curr_file;
  
  if (!aa || !class)
  {
    return FALSE;
  }

  dl_list_default(&master_file_list, FALSE, (int(*)(void *))destroy_file_struct_data);
  dl_list_default(&file_list, FALSE, (int(*)(void *))destroy_file_struct_data);
  
  /* pull all of the data files for the current class */
  if (!get_file_list(class, aa, &master_file_list))
  {
    return FALSE;
  }
  filter_file_list(&file_list, MKDB_DATA_FILE, &master_file_list);
  dl_list_destroy(&master_file_list);
  
  not_done = dl_list_first(&file_list);
    
  while (not_done)
  {
    curr_file = dl_list_value(&file_list);
    if (!file_exists(curr_file->filename))
    {
      return FALSE;
    }
    found_data += xfer_file_xfer(aa, curr_file, class, 
                                curr_class, serial_no);

    not_done = dl_list_next(&file_list);
  } /* end of while (not_done_file) */

  dl_list_destroy(&file_list);
  
  return(found_data);
}  /* end of xfer_class */


/* xfer_all_classes:  This function xfers data from all classes in an
     authority area aa, depending upon the value of serial number.  It
     returns TRUE if data is transferred.  */
static int 
xfer_all_classes(aa, serial_no)
  auth_area_struct *aa;
  char             *serial_no;
{
  int          not_done;
  int          found_data = 0;
  dl_list_type *class_list;
  class_struct *class;

  if (!aa)
  {
    return FALSE;
  }

  class_list = &(aa->schema->class_list);
  
  not_done = dl_list_first(class_list);

  while (not_done)
  {
    class = dl_list_value(class_list);

    found_data += xfer_class(aa, class, NULL, serial_no);

    not_done = dl_list_next(class_list);
  } /* end of while (not_done_class) */

  return(found_data);
}  /* end of xfer_all_classes */

static int
xfer_some_classes(xs)
  xfer_arg_struct *xs;
{
  xfer_class_struct *curr_class;
  int               not_done;
  int               found_data = 0;

  not_done = dl_list_first(&(xs->xfer_class_list));

  while (not_done)
  {
    curr_class  = dl_list_value(&(xs->xfer_class_list));
    found_data += xfer_class(xs->auth_area, curr_class->class, curr_class,
                             xs->serial_no);

    not_done = dl_list_next(&(xs->xfer_class_list));
  }
  
  return(found_data);
}

/* ------------------- PUBLIC FUNCTIONS ------------------- */


/* xfer_directive:  This function xfers data depending upon the 
   parameters passed in str.  Returns TRUE on success. */

int 
xfer_directive( str)
  char *str;
{
  xfer_arg_struct   *xs;
  int               found_data;
  
  xs = xfer_parse_args(str);

  if (!(xs))
  {
    return FALSE;
  }

  log(L_LOG_DEBUG, CLIENT, "xfer directive: %s", str);
  
  if (dl_list_empty(&(xs->xfer_class_list)))
  {
    found_data = xfer_all_classes(xs->auth_area, xs->serial_no);
  }
  else
  {
    found_data = xfer_some_classes(xs);
  }
  
  destroy_xfer_arg_data(xs);
    
  if (found_data)
  {
/*     print_ok(); */
    return TRUE;
  }

  print_error(NO_TRANSFER, "");
  return FALSE;
  
}
