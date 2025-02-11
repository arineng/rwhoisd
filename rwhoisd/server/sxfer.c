#include "sxfer.h"

#include "attributes.h"
#include "auth_area.h"
#include "defines.h"
#include "fileinfo.h"
#include "fileutils.h"
#include "index.h"
#include "index_file.h"
#include "log.h"
#include "misc.h"
#include "schema.h"
#include "sresponse.h"
#include "strutil.h"

#define DATA_FILE_TEMPLATE       "%s/%s.XXXXXX"

typedef struct xfer_class_struct
{
  class_struct *class;
  dl_list_type attr_list;
} xfer_class_struct;
 
typedef struct xfer_arg_struct
{
  auth_area_struct *auth_area;
  char             *serial_no;
  dl_list_type     xfer_class_list;
} xfer_arg_struct;

static char data_dir[MAX_LINE];
static char data_file[MAX_LINE];
static FILE *data_fp             = NULL;

static int
create_data_file_record PROTO((auth_area_struct *aa,
                               dl_list_type     *response));

static void
create_data_file_line PROTO((FILE *fp,
                             char *tag,
                             char *value));

static int destroy_xfer_class_data PROTO((xfer_class_struct *xclass));

static int destroy_xfer_arg_data PROTO((xfer_arg_struct *xarg));

static void xfer_split_av PROTO((char *str,
                                 char *attr,
                                 char *value));

static xfer_arg_struct *
xfer_parse_args PROTO((char             *str,
                       auth_area_struct *aa));

static int class_in_xfer_arg PROTO((class_struct    *class,
                                    xfer_arg_struct *xs));


/* ------------------- LOCAL FUNCTIONS -------------------- */


/* create_data_file_record: This function maps an RWhois server
   response into a data file record */
static int
create_data_file_record(aa, response)
  auth_area_struct *aa;
  dl_list_type     *response;
{
  int         not_done;
  int         first_str        = TRUE;
  static int  first_record     = FALSE;
  char        class[MAX_LINE];
  char        tag[MAX_LINE];
  char        value[MAX_LINE];
  char        *str             = NULL;
  static char *old_class       = NULL;

  if (dl_list_empty(response))
  {
    return(FALSE);
  }

  not_done = dl_list_first(response);
  while (not_done)
  {
    str = dl_list_value(response);
    if (!get_tuple(class, tag, value, str))
    {
      return(FALSE);
    }

    /* Check the first line in the response */
    if (first_str)
    {
      /* Check for a new class */
      if (!old_class || !STR_EQ(class, old_class))
      {
        if (old_class)
        {
          /* Close data file for the old class */
          release_file_lock(data_file, data_fp);
          free(old_class); old_class = NULL;
          
          first_record = FALSE;
        }

        old_class = NEW_STRING(class);

        bzero((char *) data_dir, MAX_LINE);
        sprintf(data_dir, "%s/%s", aa->data_dir, class);

        bzero((char *) data_file, MAX_LINE);
        create_filename(data_file, DATA_FILE_TEMPLATE, data_dir);
        strcat(data_file, ".txt");

        if (!directory_exists(data_dir))
        {
          mkdir(data_dir, 493);
        }

        /* Open data file for the new class */
        if ((data_fp = get_file_lock(data_file, "w", 60)) == NULL)
        {
          log(L_LOG_ERR, SECONDARY,
              "create_data_file_record: could not open data file %s: %s",
              data_file, strerror(errno));
          return(FALSE);
        }
      }

      /* Except for the first record, print the record
         separator before printing the data file record */
      if (!first_record)
      {
        first_record = TRUE;
      }
      else
      {
        fprintf(data_fp, "---\n");
      }

      first_str = FALSE;
    }

    /* Print data file line */
    create_data_file_line(data_fp, tag, value);

    not_done = dl_list_next(response);
  }

  return(TRUE);
}


/* create_data_file_line: This function creates a data file line */
static void
create_data_file_line(fp, tag, value)
  FILE *fp;
  char *tag;
  char *value;
{
  if (STR_EQ(tag, "Class-Name"))
  {
    return;
  }

  fprintf(fp, "%s:%s\n", tag, value);
}


/* destroy_xfer_class_data: This function frees a
   xfer_class_struct structure */
static int
destroy_xfer_class_data(xclass)
  xfer_class_struct *xclass;
{
  if (!xclass)
  {
    return(TRUE);
  }

  dl_list_destroy(&(xclass->attr_list));
  free(xclass);

  return(TRUE);
}


/* destroy_xfer_arg_data: This function frees a xfer_arg_struct
   structure */
static int
destroy_xfer_arg_data(xarg)
  xfer_arg_struct *xarg;
{
  if (!xarg)
  {
    return(TRUE);
  }

  if (xarg->serial_no)
  {
    free(xarg->serial_no);
  }

  dl_list_destroy(&(xarg->xfer_class_list));

  free(xarg);

  return(TRUE);
}


/* xfer_split_av: This function parses an attribute=value string */
static void 
xfer_split_av(str, attr, value)
  char *str;
  char *attr;
  char *value;
{
  char *eq = NULL;

  eq = strchr(str, '=');
  
  if (!eq)
  {
    strcpy(value, str);
    attr[0] = '\0';
    return;
  }

  *eq++ = '\0';
  strcpy(attr, str);
  trim(attr);

  strcpy(value, eq);
  trim(value);
}


/* xfer_parse_args: This function parses the xfer-arg parameter for
   partial replication */
static xfer_arg_struct * 
xfer_parse_args(str, aa)
  char             *str;
  auth_area_struct *aa;
{
  xfer_arg_struct   *xs;
  xfer_class_struct *cur_xclass = NULL;
  class_struct      *class;
  attribute_struct  *a;
  int               argc;
  char              **argv;
  char              attr[MAX_LINE];
  char              value[MAX_LINE];
  int               i;

  split_arg_list(str, &argc, &argv);

  if (argc < 1)
  {
    free_arg_list(argv);
    return(NULL);
  }

  xs = xcalloc(1, sizeof(*xs));
  dl_list_default(&(xs->xfer_class_list), FALSE, (int(*)(void *))destroy_xfer_class_data);

  for (i = 0; i < argc; i++)
  {
    xfer_split_av(argv[i], attr, value);

    if (!*attr)
    {
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
          free_arg_list(argv);
          destroy_xfer_class_data(cur_xclass);
          destroy_xfer_arg_data(xs);
          return(NULL);
        }

        cur_xclass->class = class;
        dl_list_append(&(xs->xfer_class_list), cur_xclass);
      }
      else if (STR_EQ(attr, "attr"))
      {
        if (!cur_xclass)
        {
          free_arg_list(argv);
          destroy_xfer_arg_data(xs);
          return(NULL);
        }
        
        a = find_attribute_by_name(class, value);
        if (!a)
        {
          free_arg_list(argv);
          destroy_xfer_arg_data(xs);
          return(NULL);
        }
        dl_list_append(&(cur_xclass->attr_list), a);
      }
    }
  }

  free_arg_list(argv);
  
  return(xs);
}


/* class_in_xfer_arg: This function checks if a class is in
   the xfer-arg parameter for partial replication */
static int
class_in_xfer_arg(class, xs)
  class_struct    *class;
  xfer_arg_struct *xs;
{
  xfer_class_struct *xfer_class;
  class_struct      *c;
  int               not_done;
 
  not_done = dl_list_first(&(xs->xfer_class_list));
 
  while (not_done)
  {
    xfer_class = dl_list_value(&(xs->xfer_class_list));
    c = xfer_class->class;

    if (STR_EQ(c->name, class->name))
    {
      return(TRUE);
    }
 
    not_done = dl_list_next(&(xs->xfer_class_list));
  }

  return(FALSE);
}
 

/* ------------------- PUBLIC FUNCTIONS ------------------- */


/* create_data_files: This function creates data files for a
   slave authority area */
int
create_data_files(aa, server, initial)
  auth_area_struct *aa;
  server_struct    *server;
  int              initial;
{
  int             sockfd;
  int             not_done             = TRUE;
  int             rval                 = FALSE;
  char            directive[MAX_LINE];
  char            *p;
  char            *aa_dir;
  dl_list_type    response;
  xfer_arg_struct *xs;

  if (!aa || !server)
  {
    return(rval);
  }

  aa_dir = get_aa_schema_directory(aa);
  if (!aa_dir)
  {
    aa_dir = get_default_aa_directory(aa);
    if (!aa_dir)
    {
      aa_dir = xstrdup("./");
    }
  }
  
  /* Get lock */
  if (initial)
  {
    release_dot_lock(aa_dir);
  }
  else
  {
    if (dot_lock_exists(aa_dir))
    {
      free(aa_dir);
      return(rval);
    }
  }
  get_dot_lock(aa_dir, 1);

  /* Connect to the master server */
  connect_server(server->addr, server->port, &sockfd);

  bzero((char *) directive, MAX_LINE);
  if (aa->xfer_arg)
  {
    /* Send '-xfer autharea class=classname attr=attrname'
       directive for partial replication */
    p  = NEW_STRING(aa->xfer_arg);
    xs = xfer_parse_args(p, aa);
 
    if (!(xs))
    {
      free(aa_dir);
      return(rval);
    }

    sprintf(directive, "-xfer %s %s\r\n", aa->name, aa->xfer_arg);
  }
  else
  {
    /* Send '-xfer autharea' directive for complete replication */
    sprintf(directive, "-xfer %s\r\n", aa->name);
  }
  send_directive(sockfd, directive);

  if (!directory_exists(aa->data_dir))
  {
    mkdir(aa->data_dir, 493);
  }

  /* Create data files */
  do
  {
    recv_response(stdin, "%xfer", &response);

    if (dl_list_empty(&response))
    {
      not_done = FALSE;
    }
    else
    {
      if (create_data_file_record(aa, &response))
      {
        rval = TRUE;
      }
      dl_list_destroy(&response);
    }
  } while (not_done);

  release_file_lock(data_file, data_fp);

  close(sockfd);

  /* Index data files */
  if ((p = strchr(strrchr(data_file, '/'), '.')))
  {
    p++;
    index_data_files_by_suffix(aa, p);
  }

  /* Release lock */
  release_dot_lock(aa_dir);

  free(aa_dir);
  
  return(rval);
}


/* index_data_files_by_suffix: This function indexes data files
   by suffix */
int
index_data_files_by_suffix(aa, suffix)
  auth_area_struct *aa;
  char             *suffix;
{
  schema_struct   *schema;
  dl_list_type    *class_list;
  class_struct    *class;
  dl_list_type    full_file_list;
  dl_list_type    data_file_list;
  dl_list_type    index_file_list;
  char            *p;
  int             not_done;
  int             rval                       = TRUE;
  xfer_arg_struct *xs;

  if (!aa || !aa->schema || !suffix)
  {
    return(FALSE);
  }

  schema = aa->schema;
  class_list = &(schema->class_list);

  if (dl_list_empty(class_list))
  {
    return(FALSE);
  }

  if (aa->xfer_arg)
  {
    p  = NEW_STRING(aa->xfer_arg);
    xs = xfer_parse_args(p, aa);
 
    if (!(xs))
    {
      return(FALSE);
    }
  }

  /* Iterate through each class */
  not_done = dl_list_first(class_list);
  while (not_done)
  {
    class = dl_list_value(class_list);

    /* Skip if class is not in the xfer-arg parameter for
       partial replication */
    if (aa->xfer_arg)
    {
      if (!class_in_xfer_arg(class, xs))
      {
        not_done = dl_list_next(class_list);
        continue;
      }
    }

    /* Skip if the class doesn't have a directory (and therefore
       nothing was transferred */
    if (!directory_exists(class->db_dir))
    {
      not_done = dl_list_next(class_list);
      continue;
    }
    
    /* Get current data and index files list */ 
    dl_list_default(&full_file_list, FALSE, (int(*)(void *))destroy_file_struct_data);
    get_file_list(class, aa, &full_file_list);

    /* Build new data files list */
    dl_list_default(&data_file_list, FALSE, (int(*)(void *))destroy_file_struct_data);
    if (!build_file_list_by_suffix(&data_file_list, MKDB_DATA_FILE,
                                   class->db_dir, suffix))
    {
      rval = FALSE;
      break;
    }

    dl_list_default(&index_file_list, FALSE, (int(*)(void *))destroy_index_fp_data);
    if (!build_index_list(class, aa, &index_file_list, class->db_dir, NULL))
    {
      rval = FALSE;
      break;
    }

    /* Index new data files */
    if (!index_files(class, aa, &index_file_list, &data_file_list, FALSE, TRUE))
    {
      rval = FALSE;
      break;
    }

    /* Replace current data and index files list with the new list */
    modify_file_list(class, aa, NULL, &full_file_list, NULL,
                     &data_file_list, NULL);

    unlink_file_list(&full_file_list);

    dl_list_destroy(&index_file_list);
    dl_list_destroy(&full_file_list);
    dl_list_destroy(&data_file_list);

    not_done = dl_list_next(class_list);
  }

  dl_list_destroy(&index_file_list);
  dl_list_destroy(&full_file_list);
  dl_list_destroy(&data_file_list);

  return(rval);
}
