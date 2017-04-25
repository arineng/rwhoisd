#include "sschema.h"

#include "attributes.h"
#include "auth_area.h"
#include "defines.h"
#include "fileutils.h"
#include "log.h"
#include "misc.h"
#include "schema.h"
#include "sresponse.h"

static char attr_dir[MAX_LINE];
static char attr_file[MAX_LINE];
static FILE *attr_fp             = NULL;

static int
create_schema_file_record PROTO((auth_area_struct *aa,
                                 FILE             *fp,
                                 dl_list_type     *response));

static void
create_attr_file_line PROTO((FILE *fp,
                             char *tag,
                             char *value));

static int base_attr PROTO((char *tag,
                            char *value));


/* ------------------- LOCAL FUNCTIONS -------------------- */


/* create_schema_file_record: This function maps an RWhois
   server response into a schema file record */
static int
create_schema_file_record(aa, fp, response)
  auth_area_struct *aa;
  FILE             *fp;
  dl_list_type     *response;
{
  int         not_done;
  int         first_str        = TRUE;
  static int  first_attr       = FALSE;
  char        class[MAX_LINE];
  char        tag[MAX_LINE];
  char        value[MAX_LINE];
  char        *str             = NULL;
  char        *aa_dir          = NULL;
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
          /* Close attribute file for the old class */
          release_file_lock(attr_file, attr_fp);

          /* Except for the first class, print the record separator
             before printing the schema file record */
          fprintf(fp, "---\n");

          first_attr = FALSE;
        }

        old_class = NEW_STRING(class);

        aa_dir = get_aa_schema_directory(aa);
        
        /* Print schema file record for the new class */
        fprintf(fp, "%s: %s\n", O_NAME, class);

        if (aa_dir)
        {
          fprintf(fp, "%s: %s/attribute_defs/%s.tmpl\n",
                  O_ATTRIBUTEDEF, aa_dir, class);
        }
        else
        {
          fprintf(fp, "%s: attribute_defs/%s.tmpl\n",
                  O_ATTRIBUTEDEF, class);
        }
        
        fprintf(fp, "%s: %s/%s\n", O_DBDIR, aa->data_dir, class);

        bzero((char *) attr_dir, MAX_LINE);
        if (aa_dir)
        {
          sprintf(attr_dir, "%s/attribute_defs", aa_dir);
        }
        else
        {
          sprintf(attr_dir, "attribute_defs");
        }

        bzero((char *) attr_file, MAX_LINE);
        sprintf(attr_file, "%s/%s.tmpl", attr_dir, class);

        if (aa_dir && !directory_exists(aa_dir))
        {
          mkdir(aa_dir, 493);
        }

        if (aa_dir)
        {
          free(aa_dir);
        }
        
        if (!directory_exists(attr_dir))
        {
          mkdir(attr_dir, 493);
        }

        /* Open attribute file for the new class */
        if ((attr_fp = get_file_lock(attr_file, "w", 60)) == NULL)
        {
          log(L_LOG_ERR, SECONDARY,
             "create_schema_file_record: could not open attribute file %s: %s",
              attr_file, strerror(errno));
          return(FALSE);
        }
      }

      /* Check for the first attribute of the new class.  Exclude base
         attributes.  Except for the first attribute, print the record
         separator before printing the attribute file record */
      if (!first_attr)
      {
        if (base_attr(tag, value))
        {
          break;
        }
        else
        {
          first_attr = TRUE;
        }
      }
      else
      {
        fprintf(attr_fp, "---\n");
      }

      first_str = FALSE;
    }

    /* Print attribute file line */
    create_attr_file_line(attr_fp, tag, value);

    not_done = dl_list_next(response);
  }

  return(TRUE);
}


/* create_attr_file_line: This function creates an attribute file
   line */
static void
create_attr_file_line(fp, tag, value)
  FILE *fp;
  char *tag;
  char *value;
{
  if (!fp    ||
      !tag   || !*tag ||
      !value || !*value)
  {
    return;
  }

  if (STR_EQ(tag, "attribute"))
  {
    fprintf(fp, "%s: %s\n", A_ATTRIBUTE, value);
  }
  else if (STR_EQ(tag, "description"))
  {
    fprintf(fp, "%s: %s\n", A_DESCRIPTION, value);
  }
  else if (STR_EQ(tag, "primary"))
  {
    if (STR_EQ(value, "ON"))
    {
      fprintf(fp, "%s: TRUE\n", A_IS_PRIMARY_KEY);
    }
    else if (STR_EQ(value, "OFF"))
    {
      fprintf(fp, "%s: FALSE\n", A_IS_PRIMARY_KEY);
    }
  }
  else if (STR_EQ(tag, "required"))
  {
    if (STR_EQ(value, "ON"))
    {
      fprintf(fp, "%s: TRUE\n", A_IS_REQUIRED);
    }
    else if (STR_EQ(value, "OFF"))
    {
      fprintf(fp, "%s: FALSE\n", A_IS_REQUIRED);
    }
  }
  else if (STR_EQ(tag, "repeatable"))
  {
    if (STR_EQ(value, "ON"))
    {
      fprintf(fp, "%s: TRUE\n", A_IS_REPEAT);
    }
    else if (STR_EQ(value, "OFF"))
    {
      fprintf(fp, "%s: FALSE\n", A_IS_REPEAT);
    }
  }
  else if (STR_EQ(tag, "multi-line"))
  {
    if (STR_EQ(value, "ON"))
    {
      fprintf(fp, "%s: TRUE\n", A_IS_MULTI_LINE);
    }
    else if (STR_EQ(value, "OFF"))
    {
      fprintf(fp, "%s: FALSE\n", A_IS_MULTI_LINE);
    }
  }
  else if (STR_EQ(tag, "hierarchical"))
  {
    if (STR_EQ(value, "ON"))
    {
      fprintf(fp, "%s: TRUE\n", A_IS_HIERARCHICAL);
    }
    else if (STR_EQ(value, "OFF"))
    {
      fprintf(fp, "%s: FALSE\n", A_IS_HIERARCHICAL);
    }
  }
  else if (STR_EQ(tag, "indexed"))
  {
    if (STR_EQ(value, "None"))
    {
      fprintf(fp, "%s: %s\n", A_INDEX, A_INDEX_NONE);
    }
    else if (STR_EQ(value, "All Methods"))
    {
      fprintf(fp, "%s: %s\n", A_INDEX, A_INDEX_ALL);
    }
    else if (STR_EQ(value, "Entire Value"))
    {
      fprintf(fp, "%s: %s\n", A_INDEX, A_INDEX_EXACT);
    }
    else if (STR_EQ(value, "CIDR"))
    {
      fprintf(fp, "%s: %s\n", A_INDEX, A_INDEX_CIDR);
    }
    else if (STR_EQ(value, "Soundex"))
    {
      fprintf(fp, "%s: %s\n", A_INDEX, A_INDEX_SOUNDEX);
    }
  }
  else if (STR_EQ(tag, "type"))
  {
    if (STR_EQ(value, "TEXT"))
    {
      fprintf(fp, "%s: %s\n", A_TYPE, A_TYPE_TEXT);
    }
    else if (STR_EQ(value, "ID"))
    {
      fprintf(fp, "%s: %s\n", A_TYPE, A_ID);
    }
    else if (STR_EQ(value, "See-Also"))
    {
      fprintf(fp, "%s: %s\n", A_TYPE, A_SEE_ALSO);
    }
  }
}


/* base_attr: This function checks for a base schema attribute */
static int
base_attr(tag, value)
  char *tag;
  char *value;
{
  if (STR_EQ(tag, "attribute"))
  {
    if (STR_EQ(value, "Class-Name")  ||
        STR_EQ(value, "ID")          ||
        STR_EQ(value, "Auth-Area")   ||
        STR_EQ(value, "Updated")     ||
        STR_EQ(value, "Guardian")    ||
        STR_EQ(value, "TTL")         ||
        STR_EQ(value, "Private"))
    {
      return(TRUE);
    }
  }
 
  return(FALSE);
}
 

/* ------------------- PUBLIC FUNCTIONS ------------------- */


/* create_schema_file: This function creates schema file and
   attribute definitions directory for a slave authority area */
int
create_schema_file(aa, server)
  auth_area_struct *aa;
  server_struct    *server;
{
  int          sockfd;
  int          not_done             = TRUE;
  int          rval                 = FALSE;
  char         directive[MAX_LINE];
  FILE         *fp;
  dl_list_type response;

  if (!aa || !server)
  {
    return(rval);
  }

  dl_list_default(&response, FALSE, simple_destroy_data);
  
  /* Connect to the master server */
  connect_server(server->addr, server->port, &sockfd);

  /* Send '-schema autharea' directive */
  bzero((char *) directive, MAX_LINE);
  sprintf(directive, "-schema %s\r\n", aa->name);
  send_directive(sockfd, directive);

  /* Create schema file and attribute definitions directory */
  if ((fp = get_file_lock(aa->schema_file, "w", 60)) == NULL)
  {
    log(L_LOG_ERR, SECONDARY,
        "create_schema_file: could not open schema file %s: %s",
        aa->schema_file, strerror(errno));
    return(rval);
  }

  do
  {
    recv_response(stdin, "%schema", &response);

    if (dl_list_empty(&response))
    {
      not_done = FALSE;
    }
    else
    {
      if (create_schema_file_record(aa, fp, &response))
      {
        rval = TRUE;
      }
      dl_list_destroy(&response);
    }
  } while (not_done);

  release_file_lock(aa->schema_file, fp);
  release_file_lock(attr_file, attr_fp);

  close(sockfd);

  return(rval);
}
