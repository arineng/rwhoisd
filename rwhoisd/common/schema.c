/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "schema.h"

#include "attributes.h"
#include "auth_area.h"
#include "client_msgs.h"
#include "defines.h"
#include "fileutils.h"
#include "log.h"
#include "misc.h"
#include "strutil.h"
#include "main_config.h"

static int add_class_alias PROTO((char ***alias_array, int *num_aliases,
                                  char *alias));

static int verify_class PROTO((auth_area_struct *aa, class_struct *class));

static int append_class PROTO((class_struct *class, auth_area_struct *aa ));

static int count_class_entries PROTO((dl_list_type *class_list, 
                                      char *class_name));



/* -----------------LOCAL STATICS --------------------------*/

static dl_list_type *class_ref_list = NULL;


/* -------------------- LOCAL FUNCTIONS ------------------- */

static int
add_class_alias(alias_array, num_aliases, alias)
  char ***alias_array;
  int  *num_aliases;
  char *alias;
{
  int   i;
  char  **array = *alias_array;

  if (NOT_STR_EXISTS(alias))
  {
    return FALSE;
  }

  /* check the alias list */
  for (i = 0; i < *num_aliases; i++ )
  {
    if (STR_EQ(alias, array[i]) )
    {
      log(L_LOG_ERR, CONFIG,
          "attribute alias '%s' already exists for this attribute %s",
          alias, file_context_str());
      return FALSE;
    }
  }

  array = xrealloc(array, (*num_aliases + 1) * sizeof(char *));
  
  array[(*num_aliases)++] = xstrdup(alias);

  *alias_array = array;
  
  return TRUE;
}

/* verify the contents of class structure and its attributes. Check for
   any duplicate use of class names and class aliases across the authority
   area. */
static int 
verify_class(aa, class)
  auth_area_struct *aa;
  class_struct *class;
{
  int i, errnum; 
 
  if (!aa || !class) return FALSE;

  if ((errnum = examin_class_name(class->name)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid '%s' authority area class name '%s': %s", 
        aa->name, class->name, examin_error_string(errnum));
    return FALSE;
  }

  if (count_class_entries(&(aa->schema->class_list), class->name) > 1) 
  {
    log(L_LOG_ERR, CONFIG,
        "duplicate class name '%s' found in '%s' authority area", 
        class->name, aa->name);
    return FALSE;
  }

  for (i=0; i<class->num_aliases; i++)
  {
    if ((errnum = examin_class_name(class->aliases[i])))
    {
      log(L_LOG_ERR, CONFIG,
          "invalid '%s' authority area '%s' class alias '%s': %s", 
          aa->name, class->name, class->aliases[i],
          examin_error_string(errnum));
      return FALSE;
    }
    if (count_class_entries(&(aa->schema->class_list), class->aliases[i]) > 1) 
    {
      log(L_LOG_ERR, CONFIG,
          "duplicate class alias '%s' found in '%s' authority area", 
          class->aliases[i], aa->name);
      return FALSE;
    }
  }
  if ((errnum = examin_class_db_dir(class->db_dir)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid '%s' authority area class '%s' data directory '%s': %s", 
        aa->name, class->name, class->db_dir, examin_error_string(errnum));
    return FALSE;
  }
  if ((errnum = examin_class_attr_file(class->attr_file)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid '%s' authority area class '%s' attribute file '%s': %s", 
        aa->name, class->name, class->attr_file, examin_error_string(errnum));
    return FALSE;
  }
  if ((errnum = examin_schema_version(class->version)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid '%s' authority area class '%s' version '%s': %s", 
        aa->name, class->name, class->version, examin_error_string(errnum));
    return FALSE;
  }
  if ( class->parse_program && *class->parse_program &&
       (errnum = examin_class_parse_prog(class->parse_program)) )
  {
    log(L_LOG_ERR, CONFIG,
        "invalid '%s' authority area class '%s' parse program '%s': %s", 
        aa->name, class->name, class->parse_program, 
        examin_error_string(errnum));
    return FALSE;
  }
  if (class->id < 0)
  {
    log(L_LOG_ERR, CONFIG, 
        "invalid '%s' authority area '%s' class id '%d': internal error", 
        aa->name, class->name, class->id);
    return FALSE;
  }

  if (!verify_attribute_list(aa, class))
  {
    return FALSE;
  }

  return TRUE;
}

/* count the number of times a class name occurs in the authority area
   class list. Looks at the aliases as well. */
static int
count_class_entries(class_list, class_name)
  dl_list_type *class_list;
  char *class_name;
{
  int          not_done;
  int          i, count = 0;
  class_struct *class;
  dl_node_type *orig_posn;
  
  /* bad parameters */
  if (!class_list || !class_name) return( 0 );

  /* save the current position */
  orig_posn = dl_list_get_pos(class_list);
  
  not_done = dl_list_first(class_list);
  while (not_done)
  {
    class = dl_list_value(class_list);

    if (STR_EQ(class->name, class_name)) 
    {
      count++;
    }

    for (i=0; i<class->num_aliases; i++)
    {
      if (STR_EQ(class->aliases[i], class_name))
      {
        count++;
      }
    }
    not_done = dl_list_next(class_list);
  }

  /* restore the saved position */
  dl_list_put_pos(class_list, orig_posn);

  return( count );
}

/* append a valid class to the authority area class list. */
static int
append_class( class, aa )
  class_struct     *class;
  auth_area_struct *aa;
{
  dl_list_type *class_list;
  class_struct *tmp_class;
  
  if (!aa || !aa->schema || !class) return FALSE;
  
  /* set the id (and initialize the list, if necessary) */
  class_list = &(aa->schema->class_list);
  if (!dl_list_last(class_list))
  {
    class->id = 0;
    dl_list_default(class_list, FALSE, (int(*)(void *))destroy_class_data);
  }
  else
  {
    tmp_class = dl_list_value(class_list);
    class->id = tmp_class->id + 1;
  }

  /* add the object to the list */
  dl_list_append(class_list, class);

  return TRUE;
}


/* -------------------- PUBLIC FUNCTIONS ------------------ */

/* reads the main schema/object configuration file.  Returns TRUE if
     successful, FALSE otherwise.  */
int
read_schema(aa)
  auth_area_struct *aa;
{
  char                  line[MAX_LINE];
  char                  tag[MAX_TEMPLATE_DESC];
  char                  datum[MAX_TEMPLATE_DESC];
  FILE                  *fp                         = NULL;
  class_struct          *class                      = NULL;
  schema_struct         *schema;
  int                   content_flag                = FALSE;
  
  if ( !aa || !aa->schema_file || !aa->schema )
  {
    log(L_LOG_ERR, CONFIG, "read_schema: null data detected");
    return FALSE;
  }

  schema = aa->schema;
  
  if ((fp = fopen(aa->schema_file, "r")) == NULL)
  {
    log(L_LOG_ERR, CONFIG,
        "could not open schema file '%s' for auth-area '%s': %s %s",
        aa->schema_file,
        aa->name,
        strerror(errno),
        file_context_str());
    return FALSE;
  }

  /* clear out the old schema, if necessary */
  if (!dl_list_empty(&(schema->class_list)))   
  {     
    dl_list_destroy(&(schema->class_list)); 
  }  
  if (!dl_list_empty(&(schema->attribute_ref_list)))
  { 
    dl_list_destroy(&(schema->attribute_ref_list));
  }

  /* read in the schema objects */
  class = xcalloc(1, sizeof(*class));
 
  bzero(line,  sizeof(line)); 

  set_log_context(aa->schema_file, 0, -1);
  
  while ((readline(fp, line, MAX_LINE)) != NULL)
  {
    inc_log_context_line_num(1);
    
    /* store last record; prepare for reading the next record */
    if (new_record(line))
    {
      if (!add_class(schema, class, aa))
      {
        destroy_class_data(class);
      }
      
      /* allocate the next node */
      class = xcalloc(1, sizeof(*class));

      content_flag = FALSE;
      
      continue;
    }       

    if (parse_line(line, tag, datum))
    {
      content_flag = TRUE;
      
      if (STR_EQ(tag, O_SCHEMA_VERSION))
      {
        if (class->version)
        {
          log(L_LOG_WARNING, CONFIG,
              "version '%s' replaces previous value '%s' %s",
              datum, class->version, file_context_str());
          free(class->version);
        }
        class->version = xstrdup(datum);
      }
      else if (STR_EQ(tag, O_NAME))
      {
        if (class->name)
        {
          log(L_LOG_WARNING, CONFIG,
              "schema object name '%s' replaces previous value '%s' %s",
              datum, class->name, file_context_str());
          free(class->name);
        }  
        class->name = xstrdup(datum);
      }
      else if (STR_EQ(tag, O_CLASS_ALIAS) ||
               STR_EQ(tag, O_COMMAND))
      {
        add_class_alias(&(class->aliases), &(class->num_aliases), datum);   
      }
      else if (STR_EQ(tag, O_ATTRIBUTEDEF))
      {
        if (class->attr_file)
        {
          log(L_LOG_WARNING, CONFIG,
              "schema object attribute file '%s' replaces previous value '%s' %s",
              datum, class->attr_file, file_context_str());
          free(class->attr_file);
        }

        if (!file_exists(datum))
        {
          log(L_LOG_ERR, CONFIG, "attribute file '%s' is unreadable: %s %s",
              datum, strerror(errno), file_context_str());
          destroy_class_data(class);
          fclose(fp);
          return FALSE;
        }

        class->attr_file = xstrdup(datum);
      }
      else if (STR_EQ(tag, O_DBDIR))
      {
        if (class->db_dir)
        {
          log(L_LOG_WARNING, CONFIG,
              "schema object db_dir '%s' replaces previous value '%s' %s",
              datum, class->db_dir, file_context_str());
          free(class->db_dir);
        }

        if (!directory_exists(datum))
        {
          if (aa->type == AUTH_AREA_PRIMARY)
          {
            log(L_LOG_ERR, CONFIG,
                "db directory '%s' is unreadable: %s %s",
                datum, strerror(errno), file_context_str());
            destroy_class_data(class);
            fclose(fp);
            return FALSE;
          }
        }

        class->db_dir = xstrdup(datum);
      }
      else if (STR_EQ(tag, O_DESCRIPTION))
      {
        if (class->description)
        {
          log(L_LOG_WARNING, CONFIG,
              "schema object description '%s' replaces previous value '%s' %s",
              datum, class->description, file_context_str());
          free(class->description);
        }
        
        class->description = xstrdup(datum);
      }
      else if (STR_EQ(tag, O_PARSE_PROG))
      {
        if (class->parse_program)
        {
          log(L_LOG_WARNING, CONFIG,
              "schema object parse program '%s' replaces previous value '%s' %s",
              datum, class->parse_program, file_context_str());
          free(class->parse_program);
        }

        class->parse_program = xstrdup(datum);
      }
      else
      {
        log(L_LOG_WARNING, CONFIG,
            "tag '%s' in '%s:%s' is unrecognized; ignoring %s",
            tag, aa->name, SAFE_STR(class->name, "unknown"),
            file_context_str());
      }
    }
  }

  /* commit last entry */
  if (!content_flag || !add_class(schema, class, aa))
  {
    destroy_class_data(class);
  }

  fclose (fp);

  return TRUE;
}

int
add_class(schema, class, aa)
  schema_struct    *schema;
  class_struct     *class;
  auth_area_struct *aa;
{
  class_struct       *tmp_class;
  dl_list_type       *class_list = &(schema->class_list);
  log_context_struct local_context;

  /* take care of "schema_version" */
  if ( !class || !class->name )
  {
    log(L_LOG_ERR, CONFIG, "add_class: null data detected %s",
        file_context_str());
    return FALSE;
  } 

  /* set the id (and initialize the list, if necessary) */
  if (!dl_list_last(class_list))
  {
    class->id = 0;
    dl_list_default(class_list, FALSE, (int(*)(void *))destroy_class_data);
  }
  else
  {
    tmp_class = dl_list_value(class_list);
    class->id = tmp_class->id + 1;
  }

  /* add the base schema attributes */
  if (!add_base_schema(class, &(schema->attribute_ref_list)))
  {
    log(L_LOG_ERR, CONFIG, "could not load base schema for '%s'", class->name);
    return FALSE;
  }

  save_log_context(&local_context);
  
  /* read the attributes for this object */
  log(L_LOG_DEBUG, CONFIG,
      "loading attributes for class '%s' in auth-area '%s'",
      class->name, aa->name);
  
  if (!read_attributes(class, &(schema->attribute_ref_list)))
  {
    log(L_LOG_ERR, CONFIG, "could not load attributes for '%s'", class->name);
    return FALSE;
  }

  restore_log_context(&local_context);
  
  /* add the object to the list */
  dl_list_append(class_list, class);

  /* add to the class_ref_list */
  if (!add_global_class(class, aa))
  {
    log(L_LOG_ERR, CONFIG, "could not add '%s' to class_ref_list",
        class->name);
    return FALSE;
  }
  
  return TRUE;
}


/* add class to class_ref_list */
int
add_global_class(class, aa)
  class_struct      *class;
  auth_area_struct  *aa;
{
  class_ref_struct  *ref;
  class_ref_struct  *alias_ref;
  dl_list_type      *aa_list;
  int               i;
  
  if ( !class || !aa )
  {
    log(L_LOG_ERR, CONFIG, "add_global_class: null data detected");
    return FALSE;
  }

  /* first look for an class with same name */
  ref = find_global_class_by_name(class->name);
  if (ref)
  {
    aa_list = &(ref->auth_area_list);

    if (is_duplicate_aa(aa, aa_list))
    {
      log(L_LOG_WARNING, CONFIG,
          "auth_area '%s' already exists in aa_list", aa->name);
      return FALSE;
    }

    dl_list_append(aa_list, aa);
   
  }
  else
  /* no class is found, or NULL class_ref_list, add a new node */
  {
    /* take care of empty list too */
    if ( !class_ref_list )
    {
      class_ref_list = xcalloc(1, sizeof(*class_ref_list));

      dl_list_default(class_ref_list, TRUE, (int(*)(void *))destroy_class_ref_data);
    }

    /* allocate and set the new node */
    ref = xcalloc(1, sizeof(*ref));

    ref->name = xstrdup(class->name);
    
    aa_list = &(ref->auth_area_list);
    dl_list_default(aa_list, FALSE, null_destroy_data);
    
    dl_list_append(aa_list, aa);

    dl_list_append(class_ref_list, ref);
  }

  /* aliases */
  for (i = 0; i < class->num_aliases; i++)
  {
    alias_ref = find_global_class_by_name(class->aliases[i]);

    /* if we didn't find a match, we will add it to the current global
       attr ref */
    if (!alias_ref)
    {
      add_class_alias(&(ref->aliases), &(ref->num_aliases),
                      class->aliases[i]);
    }
    else
    {
      /* if we *did* find a match, check to see if it is a conflict
         (the alias may just have already been added */
      if (STR_EQ(alias_ref->name, class->name))
      {
        log(L_LOG_WARNING, CONFIG,
            "class alias '%s' conflicts with the previously defined '%s'class %s",
            class->aliases[i], alias_ref->name, file_context_str());
      }
    }
  }

  return TRUE;
}


dl_list_type *
get_class_list(schema)
  schema_struct *schema;
{
  return(&(schema->class_list));
}


dl_list_type *
get_schema_attribute_ref_list(schema)
  schema_struct *schema;
{
  return(&(schema->attribute_ref_list));
}


class_struct *
find_class_by_name(schema, name)
  schema_struct  *schema;
  char           *name;
{
  dl_list_type  *list;
  class_struct  *class;
  int           not_done;
  int           i;
  
  if (!schema) return NULL;

  list = &(schema->class_list);

  if (dl_list_empty(list) )
  {
    return NULL;
  }

  not_done = dl_list_first(list);
  while (not_done)
  {
    class = dl_list_value(list);
    if (STR_EQ(class->name, name))
    {
      return(class);
    }

    /* search the aliases */
    for (i = 0; i < class->num_aliases; i++)
    {
      if (STR_EQ(class->aliases[i], name))
      {
        return(class);
      }
    }
    
    not_done = dl_list_next(list);
  }

  return NULL;
}


class_struct *
find_class_by_id(schema, id)
  schema_struct *schema;
  int           id;
{
  dl_list_type  *list;
  class_struct  *class;
  int           not_done;
  
  if (!schema) return NULL;

  list = &(schema->class_list);

  if (dl_list_empty(list) )
  {
    return NULL;
  }

  not_done = dl_list_first(list);
  while (not_done)
  {
    class = dl_list_value(list);
    if (class->id == id)
    {
      return(class);
    }
    
    not_done = dl_list_next(list);
  }

  return NULL;
}


void
display_class(class)
  class_struct  *class;
{
  if (!class) return ;

  printf("   schema:            %s\n", SAFE_STR_NONE(class->name));
  printf("   id:                %d\n", class->id);
  printf("   description:       %s\n", SAFE_STR_NONE(class->description));
  printf("   version:           %s\n", SAFE_STR_NONE(class->version));
  printf("   db-dir:            %s\n", SAFE_STR_NONE(class->db_dir));
  printf("   attr-file:         %s\n", SAFE_STR_NONE(class->attr_file));
  printf("   parse_program:     %s\n", SAFE_STR_NONE(class->parse_program));

  display_attribute_list(&(class->attribute_list));
}


void
display_schema(schema)
  schema_struct *schema;
{
  int   not_done;

  if (!schema) return ;

  not_done = dl_list_first(&(schema->class_list));
  while (not_done)
  {
    display_class(dl_list_value(&(schema->class_list)));

    not_done = dl_list_next(&(schema->class_list));
    if (not_done)
    {
      printf("   --------------------\n");
    }
  }
  /* don't have to display attribute_ref_list */ 
}


/* search class_ref_list */
class_ref_struct *
find_global_class_by_name(name)
  char    *name;
{
  int                   not_done;
  int                   i;
  class_ref_struct      *val;

  if ( !name || !class_ref_list )
  {
    return NULL;
  }

  not_done = dl_list_first(class_ref_list);
  while (not_done)
  {
    val = dl_list_value(class_ref_list);

    if (STR_EQ(val->name, name))
    {
      return(val);
    }

    for (i = 0; i < val->num_aliases; i++)   
    {                                        
      if (STR_EQ(val->aliases[i], name))     
      {                                      
        return(val);                         
      }                                      
    }                                        

    not_done = dl_list_next(class_ref_list);
  }

  return NULL;
}


/* ---------------- Destructor Components ------------- */

int
destroy_class_data(class)
  class_struct  *class;
{
  int i;

  if (!class) return TRUE;

  if (class->name)
  {
    free(class->name);
  }

  if (class->description)
  {
    free(class->description);
  }

  if (class->db_dir)
  {
    free(class->db_dir);
  }

  if (class->attr_file)
  {
    free(class->attr_file);
  }

  if (class->parse_program)
  {
    free(class->parse_program);
  }

  if (class->version)
  {
    free(class->version);
  }

  for (i = 0; i < class->num_aliases; i++)
  {
    if (class->aliases[i])
    {
      free(class->aliases[i]);
    }
  }

  if (class->aliases)
  {
    free(class->aliases);
  }
  
  dl_list_destroy(&(class->attribute_list));

  free(class);
  
  return TRUE;
}


int
destroy_schema_data(schema)
  schema_struct *schema;
{
  if (!schema) return TRUE;

  dl_list_destroy(&(schema->class_list));
  dl_list_destroy(&(schema->attribute_ref_list));

  free(schema);
  
  return TRUE;
}


/* destroy_class_ref_data:
 */
int 
destroy_class_ref_data( class_ref )
  class_ref_struct      *class_ref;
{
  int    i;

  if (!class_ref) return TRUE;

  if (class_ref->name)
  {
    free(class_ref->name);
  }
  
  for( i = 0; i < class_ref->num_aliases; i++)
  {
    if (class_ref->aliases[i])
    {
      free(class_ref->aliases[i]);
    }
  }

  if (class_ref->aliases)
  {
    free(class_ref->aliases);
  }

  dl_list_destroy(&(class_ref->auth_area_list));
  
  free(class_ref);

  return TRUE;
}

int
destroy_class_ref_list()
{
  dl_list_destroy(class_ref_list);
  class_ref_list = NULL;
  return TRUE;
}

/* write authority area schema file, and class attributes. Add the file
   names to 'paths_list' if created on disk. */
int 
write_schema_file(file, suffix, aa, paths_list)
  char             *file;
  char             *suffix;
  auth_area_struct *aa;
  dl_list_type     *paths_list;
{
  int           i;
  int           not_done;
  FILE          *fp;
  schema_struct *schema;
  class_struct  *class;
  dl_list_type  *class_list;
  char          new_file[MAX_FILE];

  if (!aa || !file || !*file || !paths_list) return FALSE;

  /* check if secondary auth-area */
  if (aa->type == AUTH_AREA_SECONDARY)
  {
    return TRUE;
  }

  schema = aa->schema;

  class_list = &schema->class_list;

  /* write the schema file */
  bzero(new_file, sizeof(new_file));
  strncpy(new_file, file, sizeof(new_file)-1);
  strncat(new_file, suffix, sizeof(new_file)-1);
  if ((fp = open_file_to_write(new_file, 60, paths_list)) == NULL)
  {
    log(L_LOG_ERR, CONFIG, "could not create schema file '%s': %s",
        new_file, strerror(errno));
    return FALSE;
  }

  not_done = dl_list_first(class_list);
  while (not_done)
  {
    class = dl_list_value(class_list);

    /* write class info to schema file */
    fprintf(fp, "%s: %s\n", O_NAME, SAFE_STR(class->name, ""));  
    for (i = 0; i < class->num_aliases; i++)
    {
      fprintf(fp, "%s: %s\n", O_CLASS_ALIAS, 
              SAFE_STR(class->aliases[i], ""));  
    }
    if (class->description && *class->description)
    {
      fprintf(fp, "%s: %s\n", O_DESCRIPTION, 
              SAFE_STR(class->description, ""));  
    }
    fprintf(fp, "%s: %s\n", O_DBDIR, SAFE_STR(class->db_dir, ""));  
    fprintf(fp, "%s: %s\n", O_ATTRIBUTEDEF, SAFE_STR(class->attr_file, ""));  
    if (class->parse_program && *class->parse_program)
    {
      fprintf(fp, "%s: %s\n", O_PARSE_PROG, 
              SAFE_STR(class->parse_program, ""));  
    }
    if (class->version && *class->version)
    {
      fprintf(fp, "%s: %s\n", O_SCHEMA_VERSION, 
              SAFE_STR(class->version, ""));  
    }
  
    /* write class template in attribute def directory */
    if (!write_class_attributes(class->attr_file, suffix, class, paths_list))
    {
      log(L_LOG_ERR, CONFIG, 
          "error writing attribute definitions file '%s' for '%s:%s' class", 
          class->attr_file, aa->name, class->name);
      release_file_lock(new_file, fp);  
      dl_list_append(paths_list, xstrdup(new_file));
      return FALSE;
    }

    not_done = dl_list_next(class_list);
    if (not_done)
    {
      fprintf(fp, "-----\n");
    }
  }
  release_file_lock(new_file, fp);  

  dl_list_append(paths_list, xstrdup(new_file));

  return TRUE;
}

/* examine the validity of schema version string. Returns non-zero value
   on failure */
int
examin_schema_version(version)
  char *version;
{
  int ret;

  if ((ret = examin_timestamp(version))) return( ret );

  return( 0 );
}

/* examine the validity of class name string. 
   Returns non-zero value on failure */
int
examin_class_name(name)
  char *name;
{
  if (NOT_STR_EXISTS(name)) return ERW_EMTYSTR;
  if (!is_id_str(name)) return ERW_IDSTR;

  return( 0 );
}

/* examine the validity of class data directory. Returns non-zero value on
   failure */
int
examin_class_db_dir(path)
  char *path;
{
  int ret;

  if (NOT_STR_EXISTS(path)) return ERW_EMTYSTR;
  if ((ret = examin_directory_name(path))) return( ret );
  if (!path_under_root_dir(path, get_root_dir())) return ERW_UNDROOT;

  return( 0 );
}

/* examine the validity of attribute file name. Also checks if the
   file name is under the root directory. Returns non-zero value on
   failure. */
int
examin_class_attr_file(path)
  char *path;
{
  int ret;

  if (NOT_STR_EXISTS(path)) return ERW_EMTYSTR;
  if ((ret = examin_file_name(path))) return( ret );
  if (!path_under_root_dir(path, get_root_dir())) return ERW_UNDROOT;

  return( 0 );
}

/* examine the validity of class parse program. If not found at the given
   path search in the bin-path of the server. Also checks if the program
   is an executable file on disk. Returns non-zero value on failure. */
int
examin_class_parse_prog(path)
  char *path;
{
  int  ret = 0;
  char new_path[MAX_FILE];

  if (!path)  return ERW_NDEF;
  if (!*path) return ERW_EMTYSTR;

  if (is_rel_path(path))
  {
    ret = examin_executable_name(path);
    if (ret)
    {
      bzero(new_path, sizeof(new_path));
      strncpy(new_path, get_bin_path(), sizeof(new_path)-1);
      strncat(new_path, "/", sizeof(new_path)-1);
      strncat(new_path, path, sizeof(new_path)-1);
      ret = examin_executable_name(new_path);
    }
  }
  else
  {
    ret = examin_executable_name(new_path);
  }

  return( ret );
}


/* verify the authority area schema. Makes sure atleast one class is
   defined in the schema. */
int 
verify_schema(aa)
  auth_area_struct *aa;
{
  int           not_done;
  class_struct  *class;
  schema_struct *schema     = aa->schema;
  dl_list_type  *class_list = &schema->class_list;
  
  if (!aa) return FALSE;

  if (dl_list_empty(class_list))
  {
    log(L_LOG_ERR, CONFIG, 
    "'%s' authority area does not have any classes defined", aa->name);
    return FALSE;
  }

  not_done = dl_list_first(class_list);
  while (not_done)
  {
    class = dl_list_value(class_list);

    if (!verify_class(aa, class))
    {
      return FALSE;
    }
    not_done = dl_list_next(class_list);
  }

  return TRUE;
}

/* creates a new class using user-defined information or defaults,
   then appends the created class to the class list of authority
   area. */
int 
create_class(class, aa)
  class_struct     *class;
  auth_area_struct *aa;
{
  int              not_done;
  int              i;
  int              errnum;
  char             aa_dir[MAX_FILE];
  class_struct     *newclass;
  char             buffer[MAX_LINE];
  attribute_struct *attr             = NULL;

  if (!class || !class->name || !aa || !aa->schema) return FALSE;

  /* check if all required fields are initialized and valid */
  if ((errnum = examin_class_name(class->name)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid '%s' authority area class name '%s': %s", 
        aa->name, class->name, examin_error_string(errnum));
    return FALSE;
  }

  if (find_class_by_name(aa->schema, class->name))
  {
    log(L_LOG_ERR, CONFIG,
        "'%s' class already exists in '%s' authority area", 
        class->name, aa->name);
    return FALSE;
  }

  /* get the authority area directory */
  if (!check_aa_syntax(aa->name, aa_dir)) return FALSE;

  newclass = xcalloc(1, sizeof(*class));

  newclass->name = xstrdup(class->name);

  /* add class aliases */
  for (i = 0; i < class->num_aliases; i++) 
  {
    if (!add_new_class_alias(aa, newclass, class->aliases[i]))
    {
      destroy_class_data(newclass);
      return FALSE;
    }
  }

  if (class->version && *(class->version))
  {
    newclass->version = xstrdup(class->version);
  } 
  else
  {
    newclass->version = xstrdup(make_timestamp());
  }
  if (class->attr_file && *(class->attr_file))
  {
    newclass->attr_file = xstrdup(class->attr_file);
  } 
  else
  {
    bzero(buffer, sizeof(buffer));
    strncpy(buffer, aa_dir, sizeof(buffer)-1);
    strncat(buffer, "/attribute_defs/", sizeof(buffer)-1);
    strncat(buffer, class->name, sizeof(buffer)-1);
    strncat(buffer, ".tmpl", sizeof(buffer)-1);
    newclass->attr_file = xstrdup(buffer);
  }
  if (class->db_dir && *(class->db_dir))
  {
    newclass->db_dir = xstrdup(class->db_dir);
  } 
  else
  {
    bzero(buffer, sizeof(buffer));
    strncpy(buffer, aa_dir, sizeof(buffer)-1);
    strncat(buffer, "/data/", sizeof(buffer)-1);
    strncat(buffer, class->name, sizeof(buffer)-1);
    newclass->db_dir = xstrdup(buffer);
  }

  /* assign optional fields */
  if (class->description && *(class->description))
  {
    newclass->description = xstrdup(class->description);
  }
  if (class->parse_program && *(class->parse_program))
  {
    newclass->parse_program = xstrdup(class->parse_program);
  }

  /* add base schema attributes to this class */
  if (!add_base_schema(newclass, NULL))
  {
    destroy_class_data(newclass);
    return FALSE;
  }

  /* add other attribs if specified */
  if (!dl_list_empty(&class->attribute_list))
  {
    not_done = dl_list_first(&class->attribute_list);
    while (not_done)
    {
      attr = dl_list_value(&class->attribute_list);
      if (!create_attribute_def(attr, newclass, aa))
      {
        destroy_class_data(newclass);
        return FALSE;
      }
    }
  }

  /* commit class */
  if (!append_class( newclass, aa )) 
  {  
    destroy_class_data(newclass);
    return FALSE;
  }
  
  return TRUE;
}

/* sets a new class schema version */
int
update_schema_version(class)
  class_struct *class;
{
  char *tmp_ver;

  if (!class) return FALSE;

  if (class->version)
  {
    tmp_ver = xstrdup(get_updated_timestamp(class->version));
    free(class->version);
    class->version = tmp_ver;
  }

  return TRUE;
}

/* add a new class after making sure the name does not clash with any
   other class name or class alias. */
int
add_new_class_alias(aa, class, alias)
  auth_area_struct *aa;
  class_struct     *class;
  char             *alias;
{
  /* bad parameters */
  if (!aa || !class || !alias || !*alias) return FALSE;

  /* check to make sure we are not adding duplicate attribute names */
  if (find_class_by_name(aa->schema, alias))
  {
    log(L_LOG_ERR, CONFIG,
        "class alias name '%s' already used in '%s' authority area",
        alias, aa->name);
    return FALSE;
  }

  return( add_class_alias(&(class->aliases), &(class->num_aliases), alias) );
}

/* add class file names and directories to 'paths_list' if not in the list.
   Log error if path already in the list. Returns non-zero value on
   failure. */
int
verify_all_class_paths(paths_list, aa)
  dl_list_type     *paths_list;
  auth_area_struct *aa;
{
  int          ret = 0;
  int          not_done;
  dl_list_type *class_list;
  class_struct *class;
  char         buffer[MAX_LINE];

  if (!paths_list || !aa) return( 1 );

  class_list = &(aa->schema->class_list);

  not_done = dl_list_first(class_list);
  while (not_done)
  {
    class = dl_list_value(class_list);

    bzero(buffer, sizeof(buffer));
    strncpy(buffer, aa->name, sizeof(buffer)-1);
    strncat(buffer, ":", sizeof(buffer)-1);
    strncat(buffer, class->name, sizeof(buffer)-1);
    strncat(buffer, ":", sizeof(buffer)-1);
    strncat(buffer, O_DBDIR, sizeof(buffer)-1);
    ret += dup_config_path_name(paths_list, class->db_dir, 
                              buffer);
    bzero(buffer, sizeof(buffer));
    strncpy(buffer, aa->name, sizeof(buffer)-1);
    strncat(buffer, ":", sizeof(buffer)-1);
    strncat(buffer, class->name, sizeof(buffer)-1);
    strncat(buffer, ":", sizeof(buffer)-1);
    strncat(buffer, O_ATTRIBUTEDEF, sizeof(buffer)-1);
    ret += dup_config_path_name(paths_list, class->attr_file, 
                              buffer);
    not_done = dl_list_next(class_list);
  }

  return( ret );  
}

/* make sure the class parse program names are not used in the
   configuration. Don't want to overwrite something not written out
   by admin server. */
int
verify_class_parse_progs(paths_list, aa)
  dl_list_type     *paths_list;
  auth_area_struct *aa;
{
  int          ret = 0;
  int          not_done;
  dl_list_type *class_list;
  class_struct *class;
  char buffer[MAX_LINE];

  if (!paths_list || !aa) return( 1 );

  class_list = &(aa->schema->class_list);

  not_done = dl_list_first(class_list);
  while (not_done)
  {
    class = dl_list_value(class_list);

    bzero(buffer, sizeof(buffer));
    strncpy(buffer, aa->name, sizeof(buffer)-1);
    strncat(buffer, ":", sizeof(buffer)-1);
    strncat(buffer, class->name, sizeof(buffer)-1);
    strncat(buffer, ":", sizeof(buffer)-1);
    strncat(buffer, O_PARSE_PROG, sizeof(buffer)-1);
    ret += in_config_path_list(paths_list, class->parse_program, 
                               buffer);

    not_done = dl_list_next(class_list);
  }

  return( ret );
}
