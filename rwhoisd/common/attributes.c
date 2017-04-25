/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "attributes.h"

#include "client_msgs.h"
#include "defines.h"
#include "log.h"
#include "misc.h"
#include "strutil.h"
#include "types.h"
#include "fileutils.h"

/* local prototypes */
static attribute_struct *
create_attribute PROTO((char            *name,
                        char            *desc,
                        char            *format,
                        attr_index_type index,
                        attr_type       type,
                        int             is_hierarchical,
                        int             is_required,
                        int             is_repeatable,
                        int             is_primary_key,
                        int             is_multi_line,
                        int             is_private));

static int
add_attribute_alias PROTO((char ***alias_array,
                           int  *num_aliases, 
                           char *alias));

static int write_attribute_defs PROTO((FILE *fptr, attribute_struct *attr));

static int
count_attribute_entries PROTO((dl_list_type *attr_list, 
                               char         *attr_name));

static int
verify_attribute_defs PROTO((auth_area_struct *aa, 
                             class_struct     *class,
                             attribute_struct *attr));


/* -------------------- LOCAL FUNCTIONS ------------------------ */

static attribute_struct *
create_attribute(name, desc, format, index, type, is_hierarchical,
                 is_required, is_repeatable, is_primary_key, is_multi_line,
                 is_private)
  char            *name;
  char            *desc;
  char            *format;
  attr_index_type index;
  attr_type       type;
  int             is_hierarchical;
  int             is_required;
  int             is_repeatable;
  int             is_primary_key;
  int             is_multi_line;
  int             is_private;
{
  attribute_struct  *attr;

  if (!name) return NULL;
  
  attr = xcalloc(1, sizeof(*attr));

  attr->name = xstrdup(name);

  if (desc)
  {
    attr->description = xstrdup(desc);
  }

  if (format)
  {
    attr->format = xstrdup(format);
  }

  attr->index               = index;
  attr->type                = type;
  attr->is_hierarchical     = is_hierarchical;
  attr->is_required         = is_required;
  attr->is_repeatable       = is_repeatable;
  attr->is_primary_key      = is_primary_key;
  attr->is_multi_line       = is_multi_line;
  attr->is_private          = is_private;
  
  return(attr);
}

/* add_attribute_alias: Add an alias to the attribute structure.
   Check the alias list, if this alias already exits, return FALSE.
   This is spun off into its own routine to deal with the memory
   allocation. */
static int
add_attribute_alias(alias_array, num_aliases, alias)
  char ***alias_array;
  int  *num_aliases;
  char *alias;
{
  int   i;
  char  **array = *alias_array;

  if (!alias)
  {
    return FALSE;
  }

  /* check the alias list */
  for (i = 0; i < *num_aliases; i++ )
  {
    if (STR_EQ(alias, array[i]) )
    {
      log(L_LOG_ERR, CONFIG,
          "attribute alias '%s' already exists for this attribute %s", alias,
          file_context_str());
      return FALSE;
    }
  }

  array = xrealloc(array, (*num_aliases + 1) * sizeof(char *));
  
  array[(*num_aliases)++] = xstrdup(alias);

  *alias_array = array;
  
  return TRUE;
}

/* writes/append a specific attribute definition to the class attribute 
   template file. */
static int 
write_attribute_defs(fp, attr)
  FILE             *fp; 
  attribute_struct *attr;
{
  int i;

  fprintf(fp, "%s: %s\n", A_ATTRIBUTE, SAFE_STR(attr->name, ""));    
  for (i = 0; i < attr->num_aliases; i++) 
  {
    fprintf(fp, "%s: %s\n", A_ATTRIB_ALIAS, SAFE_STR(attr->aliases[i], ""));
  }
  if (attr->description && *attr->description) 
  {
    fprintf(fp, "%s: %s\n", A_DESCRIPTION, SAFE_STR(attr->description, ""));
  }
  if (attr->format && *attr->format) 
  {
    fprintf(fp, "%s: %s\n", A_FORMAT, SAFE_STR(attr->format, ""));
  }
  fprintf(fp, "%s: %s\n", A_IS_PRIMARY_KEY, 
                         true_false_str(attr->is_primary_key));
  fprintf(fp, "%s: %s\n", A_IS_REQUIRED, 
                         true_false_str(attr->is_required));
  fprintf(fp, "%s: %s\n", A_IS_REPEAT, 
                         true_false_str(attr->is_repeatable));
  fprintf(fp, "%s: %s\n", A_IS_MULTI_LINE, 
                         true_false_str(attr->is_multi_line));
  fprintf(fp, "%s: %s\n", A_IS_HIERARCHICAL, 
                         true_false_str(attr->is_hierarchical));
  fprintf(fp, "%s: %s\n", A_IS_PRIVATE, 
                         true_false_str(attr->is_private));
  fprintf(fp, "%s: %s\n", A_INDEX, show_index_type(attr->index));
  fprintf(fp, "%s: %s\n", A_TYPE, show_attribute_type(attr->type));

  return TRUE;
}

/* count the number of times a given attibute occurs in the attribute
   list */
static int
count_attribute_entries(attr_list, attr_name)
  dl_list_type *attr_list;
  char *attr_name;
{
  int               i, not_done;
  int               count = 0;
  attribute_struct  *val;
  dl_node_type      *orig_posn;
  
  if (!attr_list || !attr_name || !*attr_name) return( 0 );

  /* save the current position */
  orig_posn = dl_list_get_pos(attr_list);

  not_done = dl_list_first(attr_list);
  while (not_done)
  {
    val = dl_list_value(attr_list);

    if (STR_EQ(val->name, attr_name))
    {
      count++;
    }

    for (i = 0; i < val->num_aliases; i++)
    {
      if (STR_EQ(val->aliases[i], attr_name))
      {
        count++;
      }
    }
    not_done = dl_list_next(attr_list);
  }

  /* restore the saved position */
  dl_list_put_pos(attr_list, orig_posn);

  return( count );
}

/* verifies the correctness of a class attribute definition */
static int
verify_attribute_defs(aa, class, attr)
  auth_area_struct *aa;
  class_struct     *class;
  attribute_struct *attr;
{
  int i;
  int ret;

  /* check for bad parameters */
  if (!aa || !class || !attr) return FALSE;

  if (attr->local_id < 0)
  {
    log(L_LOG_ERR, CONFIG,
        "'%s:%s:%s' attribute local id '%d' is not valid - internal error",
        SAFE_STR(aa->name, ""), SAFE_STR(class->name, ""), 
        SAFE_STR(attr->name, ""), attr->local_id);
    return FALSE;
  }

  if (attr->is_primary_key && !attr->is_required)
  {
    log(L_LOG_ERR, CONFIG,
        "'%s:%s:%s' primary key attribute must be a required attribute",
        SAFE_STR(aa->name, ""), SAFE_STR(class->name, ""), 
        SAFE_STR(attr->name, ""));
    return FALSE;
  }

  if (attr->is_multi_line && attr->is_repeatable)
  {
    log(L_LOG_ERR, CONFIG,
        "'%s:%s:%s' repeatable attribute must not be multi-line",
        SAFE_STR(aa->name, ""), SAFE_STR(class->name, ""), 
        SAFE_STR(attr->name, ""));
    return FALSE;
  }

  if ((ret = examin_attribute_name(attr->name)))
  {
    log(L_LOG_ERR, CONFIG, 
        "invalid '%s:%s' class attribute name '%s': %s", 
        SAFE_STR(aa->name, ""), SAFE_STR(class->name, ""), 
        SAFE_STR(attr->name, ""), examin_error_string(ret));
    return FALSE;
  }

  for (i=0; i<attr->num_aliases; i++) 
  {
    if ((ret = examin_attribute_name(attr->aliases[i])))
    {
      log(L_LOG_ERR, CONFIG, 
          "invalid '%s:%s:%s' attribute alias '%s': %s", 
          SAFE_STR(aa->name, ""), SAFE_STR(class->name, ""), 
          SAFE_STR(attr->name, ""), SAFE_STR(attr->aliases[i], ""),
          examin_error_string(ret));
      return FALSE;
    }
    if (count_attribute_entries(&class->attribute_list, 
                                attr->aliases[i]) > 1) 
    {
      log(L_LOG_ERR, CONFIG, 
          "attribute alias '%s' already used in '%s:%s' authority area class", 
          SAFE_STR(attr->aliases[i], ""), SAFE_STR(aa->name, ""), 
          SAFE_STR(class->name, ""));
      return FALSE;
    }
  }
  
  return TRUE;
}


/* -------------------- PUBLIC FUNCTIONS ----------------------- */

/* returns how to index the word based on the attribute. If none
   declared, returns all words. */
attr_index_type
translate_index_type(itype)
  char *itype;
{
  if (STR_EQ(itype, A_INDEX_ALL))
  {
    return INDEX_ALL;
  }
  else if (STR_EQ(itype, A_INDEX_EXACT))
  {
    return INDEX_EXACTLY;
  }
  else if (STR_EQ(itype, A_INDEX_CIDR))
  {
    return INDEX_CIDR;
  }
  else if (STR_EQ(itype, A_INDEX_SOUNDEX))
  {
    return INDEX_SOUNDEX;
  }
  else
  {
    return INDEX_NONE;
  }
}

/* returns the description of the attribute */
attr_type
translate_attr_type(type)
  char *type;
{
  if (STR_EQ(type, A_SEE_ALSO))
  {
    return(TYPE_SEE_ALSO);
  }
  if (STR_EQ(type, A_ID))
  {
    return(TYPE_ID);
  }
  else
  {
    return(TYPE_TEXT);
  }
}

/* reads the attributes for the class; returns TRUE if ok, FALSE if
   not. */
int
read_attributes(class, attr_ref_list)
  class_struct  *class;
  dl_list_type  *attr_ref_list;
{
  FILE              *fp                 = NULL;
  attribute_struct  *attr               = NULL;
  char              line[MAX_LINE + 1];
  char              tag[MAX_TEMPLATE_NAME];
  char              datum[MAX_TEMPLATE_NAME];
  int               content_flag = FALSE;
  
  if (!class || !class->attr_file)
  {
    return TRUE;
  }

  fp = fopen(class->attr_file, "r");
  if (!fp)
  {
    log(L_LOG_ERR, CONFIG, "could not open attribute template '%s': %s",
        class->attr_file, strerror(errno));
    return FALSE;
  } 

  set_log_context(class->attr_file, 0, -1);
  
  /* allocate the first node */
  attr = xcalloc(1, sizeof(*attr));
  
  bzero(line, sizeof(line));

  while ((readline(fp, line, MAX_LINE)))
  {
    inc_log_context_line_num(1);
    
    /* add previously completed attribute item and prepare for the
       next one */
    if (new_record(line))
    {
      if (!add_attribute(attr, class, attr_ref_list))
      {
        destroy_attr_data(attr);
      }
      
      attr = xcalloc(1, sizeof(*attr));

      content_flag = FALSE;
      continue;
    }

    /* parse the individual lines */
    
    if (parse_line(line, tag, datum))
    {
      content_flag = TRUE;
      
      if (STR_EQ(tag, A_ATTRIBUTE))
      {
        if (attr->name)
        {
          log(L_LOG_WARNING, CONFIG,
              "attribute name '%s' replaces previous value '%s' %s",
              datum, attr->name, file_context_str());
          free(attr->name);
        }
        attr->name = xstrdup(datum);
      }
      else if (STR_EQ(tag, A_ATTRIB_ALIAS))
      {
        add_attribute_alias(&(attr->aliases), &(attr->num_aliases), datum);
      }
      else if (STR_EQ(tag, A_DESCRIPTION))
      {
        if (attr->description)
        {
          log(L_LOG_WARNING, CONFIG,
              "attribute description replaces previous value %s %s",
              class->name, file_context_str());
          free(attr->description);
        }
        attr->description = xstrdup(datum);
      }
      /* Move all the schema checks to add_attribute() */
      else if (STR_EQ(tag, A_IS_PRIMARY_KEY))
      {
        attr->is_primary_key = true_false(datum);
      }
      else if (STR_EQ(tag, A_IS_HIERARCHICAL))
      {
        attr->is_hierarchical = true_false(datum);
      }
      else if (STR_EQ(tag, A_IS_REPEAT))
      {
        attr->is_repeatable = true_false(datum);
      }
      else if (STR_EQ(tag, A_IS_REQUIRED) )
      {
        attr->is_required = true_false(datum);
      }
      else if (STR_EQ(tag, A_IS_MULTI_LINE))
      {
        attr->is_multi_line = true_false(datum);
      }
      else if (STR_EQ(tag, A_IS_PRIVATE))
      {
        attr->is_private = true_false(datum);
      }
      else if (STR_EQ(tag, A_FORMAT))
      {
        if (attr->format)
        {
          log(L_LOG_WARNING, CONFIG,
              "attribute format '%s' replaces previous value '%s' %s",
              datum, attr->format, file_context_str());
          free(attr->format);
        }
        attr->format = xstrdup(datum);
      }
      else if (STR_EQ(tag, A_INDEX))
      {
        attr->index = translate_index_type(datum);
      }
      else if (STR_EQ(tag, A_TYPE))
      {
        attr->type = translate_attr_type(datum);
      }
      else
      {
        log(L_LOG_WARNING, CONFIG,
            "attribute tag '%s' unrecognized; ignored %s",
            tag, file_context_str());
      }
    }
  }

  /* commit the last attribute */
  if (!content_flag || !add_attribute(attr, class, attr_ref_list))
  {
    destroy_attr_data(attr);
  }
  
  fclose(fp);

  return TRUE;
}

int
add_attribute(attr, class, attr_ref_list)
  attribute_struct      *attr;
  class_struct          *class;
  dl_list_type          *attr_ref_list;
{
  attribute_struct  *tmp_attr;
  dl_list_type      *attr_list = &(class->attribute_list);
  int               i;
  
  /* first determine if we have everything that we need */
  if (!attr->name)
  {
    log(L_LOG_ERR, CONFIG, 
        "attribute in class '%s' missing required data: name %s",
        class->name, file_context_str());
    return FALSE;
  }
  
  /* now determine if it is a duplicate */
  if (find_attribute_by_name(class, attr->name))
  {
    log(L_LOG_ERR, CONFIG,
        "attribute '%s' is a duplicate; pick another name %s",
        attr->name, file_context_str());
    return FALSE;
  }

  for (i = 0; i < attr->num_aliases; i++)
  {
    tmp_attr = find_attribute_by_name(class, attr->aliases[i]);
    if (tmp_attr)
    {
      log(L_LOG_ERR, CONFIG,
          "attribute alias '%s' conficts with name or alias '%s' %s",
          attr->aliases[i], tmp_attr->name, file_context_str());
      return FALSE;
    }
  }

  /* schema checks */

  if ( attr->is_primary_key && !attr->is_required )
  {
    /* is_primary_key => is_required */
    /* !is_required => !is_primary_key */
    log(L_LOG_ERR, CONFIG, "primary_key '%s' has to be is_required %s",
        attr->name, file_context_str());
    return FALSE;
  }
  
  if (attr->is_multi_line && attr->is_repeatable )
  {
    /* is_multi_line  => !is_repeatable */
    /* is_repeatable  => !is_multi_line */
    log(L_LOG_ERR, CONFIG,
        "attribute '%s' cannot be both multi-line and repeatable %s",
        attr->name, file_context_str());
    return FALSE;
  }
  
  /* determine local id -- if there is a last node, set it to the next value,
     otherwise, just leave it at zero */
  if( !dl_list_last(attr_list))
  {
    /* this is the first entry, so default the list */
    dl_list_default(attr_list, FALSE, destroy_attr_data);
  }
  else
  {
    tmp_attr = dl_list_value(attr_list);
    attr->local_id = tmp_attr->local_id + 1;
  }
    
  /* add to the global list */
  add_global_attribute(attr, class, attr_ref_list, &(attr->global_id));

  /* add it to the internal_list */
  dl_list_append(attr_list, attr);

  return TRUE;
}

  
int
add_global_attribute(attr, class, attr_ref_list, global_id)
  attribute_struct  *attr;
  class_struct      *class;
  dl_list_type      *attr_ref_list;
  int               *global_id;
{
  attribute_ref_struct  *ref;
  attribute_ref_struct  *alias_ref;
  dl_list_type          *class_list;
  int                   i;
  
  if (!attr || !class || !attr_ref_list)
  {
    return FALSE;
  }
  
  /* first look for an attribute with the same name */
  ref = find_global_attr_by_name(attr_ref_list, attr->name);
  if (ref)
  {
    class_list = &(ref->class_list);
    dl_list_append(class_list, class);
    *global_id = ref->global_id;
  }
  else
  {
    /* since we didn't find a matching global id, add a new one */

    /* get the next global id number (and default the list if empty) */
    if (! dl_list_last(attr_ref_list))
    {
      *global_id = 0;
      dl_list_default(attr_ref_list, FALSE, destroy_attr_ref_data);
    }
    else
    {
      ref = dl_list_value(attr_ref_list);
      *global_id = ref->global_id + 1;
    }

    /* allocate and set the new node */
    ref = xcalloc(1, sizeof(*ref));

    class_list = &(ref->class_list);
    dl_list_default(class_list, FALSE, null_destroy_data);
    dl_list_append(class_list, class);
  
    ref->name = xstrdup(attr->name);
    ref->global_id = *global_id;

    dl_list_append(attr_ref_list, ref);
  }

  /* now we need to deal with the aliases */
  for (i = 0; i < attr->num_aliases; i++)
  {
    alias_ref = find_global_attr_by_name(attr_ref_list, attr->aliases[i]);

    /* if we didn't find a match, we will add it to the current global
       attr ref */
    if (!alias_ref)
    {
      add_attribute_alias(&(ref->aliases), &(ref->num_aliases),
                          attr->aliases[i]);
    }
    else
    {
      /* if we *did* find a match, check to see if it is a conflict
         (the alias may just have already been added */
      if (alias_ref->global_id != *global_id)
      {
        log(L_LOG_WARNING, CONFIG,
            "attribute alias '%s' conflicts with the previously defined '%s' attribute %s",
            attr->aliases[i], alias_ref->name, file_context_str());
      }
    }
  }

  return TRUE;
}


int
add_base_schema(class, attr_ref_list)
  class_struct  *class;
  dl_list_type  *attr_ref_list;
{
  attribute_struct  *attr;

  /* NOTE: the properties of the base class attributes are not always
     what one would expect (for instance, some are not required when
     you might expect that they are).  This is to prevent the generic
     syntax checks from interfering with protocol specific syntax
     checks */

  /* NOTE: the register code relies heavily on the supplied base class
     names and aliases.  If the names (or aliases) change, be sure to
     update that code.  */
  
  /* class name */
  attr = create_attribute(BC_CLASS_NAME,         /* attr-name   */   
                          "Type of the object.", /* description */
                          NULL,                  /* format      */
                          INDEX_NONE,            /* index-type  */
                          TYPE_TEXT,             /* type        */
                          FALSE,                 /* is_hierarchical */
                          TRUE,                  /* is_required */
                          FALSE,                 /* is_repeatable*/
                          FALSE,                 /* is_primary_key */
                          FALSE,                 /* is_multi_line */
                          FALSE                  /* is_private    */
                          );

  add_attribute_alias(&(attr->aliases), &(attr->num_aliases),
                      BC_CLASS_NAME_A1);
  add_attribute_alias(&(attr->aliases), &(attr->num_aliases),
                      BC_CLASS_NAME_A2);
  add_attribute_alias(&(attr->aliases), &(attr->num_aliases),
                      BC_CLASS_NAME_A3);

  if (! add_attribute(attr, class, attr_ref_list))
  {
    log(L_LOG_ERR, CONFIG,
        "Base Schema attribute '%s' unable to be added to class '%s'",
        attr->name, class->name);
    destroy_attr_data(attr);
    return FALSE;
  }

  
  /* ID */
  attr = create_attribute(BC_ID,            /* attr-name */
                          "Globally unique object identifier",
                          NULL,             /* format */
                          INDEX_EXACTLY,    /* index-type */
                          TYPE_TEXT,        /* type */
                          TRUE,             /* is_hierarchical */
                          FALSE,            /* is_required */
                          FALSE,            /* is_repeatable */
                          FALSE,            /* is_primary_key */
                          FALSE,           /* is_multi_line */
                          FALSE            /* is_private */
                          );
  
  if (!add_attribute(attr, class, attr_ref_list))
  {
    log(L_LOG_ERR, CONFIG,
        "Base Schema attribute '%s' unable to be added to class '%s'",
        attr->name, class->name);
    destroy_attr_data(attr);
    return FALSE;
  }

  /* Auth-Area */
  attr = create_attribute(BC_AUTH_AREA,     /* attr-name */
                          "Authority area to which the object belongs",
                          NULL,             /* format */
                          INDEX_NONE,       /* index-type */
                          TYPE_TEXT,        /* type */
                          TRUE,             /* is_hierarchical */
                          TRUE,             /* is_required */
                          FALSE,            /* is_repeatable */
                          FALSE,            /* is_primary_key */
                          FALSE,            /* is_multi_line */
                          FALSE             /* is_private */
                          );
  add_attribute_alias(&(attr->aliases), &(attr->num_aliases), BC_AUTH_AREA_A1);
  
  if (! add_attribute(attr, class, attr_ref_list))
  {
    log(L_LOG_ERR, CONFIG,
        "Base Schema attribute '%s' unable to be added to class '%s'",
        attr->name, class->name);
    destroy_attr_data(attr);
    return FALSE;
  }

  /* Updated */
  attr = create_attribute(BC_UPDATED,       /* attr-name */
                          "Last modification time/serial number",
                          NULL,             /* format */
                          INDEX_NONE,       /* index-type  */
                          TYPE_TEXT,        /* type        */
                          FALSE,            /* is_hierarchical */
                          FALSE,            /* is_required */
                          FALSE,            /* is_repeatable*/
                          FALSE,            /* is_primary_key */
                          FALSE,            /* is_multi_line */
                          FALSE             /* is_private */
                          );

  add_attribute_alias(&(attr->aliases), &(attr->num_aliases), BC_UPDATED_A1);
  
  if (! add_attribute(attr, class, attr_ref_list))
  {
    log(L_LOG_ERR, CONFIG,
        "Base Schema attribute '%s' unable to be added to class '%s'",
        attr->name, class->name);
    destroy_attr_data(attr);
    return FALSE;
  }
  
  /* Guardian is optional */
  attr = create_attribute(BC_GUARDIAN,          /* attr-name  */
                          "Guardian object",    /* description */
                          NULL,                 /* format      */
                          INDEX_NONE,           /* index-type  */
                          TYPE_ID,              /* type        */
                          FALSE,                /* is_hierarchical */
                          FALSE,                /* is_required */
                          TRUE,                 /* is_repeatable*/
                          FALSE,                /* is_primary_key */
                          FALSE,                /* is_multi_line */
                          FALSE                 /* is_private */
                          );
  
  add_attribute_alias(&(attr->aliases), &(attr->num_aliases), BC_GUARDIAN_A1);
  
  if (! add_attribute(attr, class, attr_ref_list))
  {
    log(L_LOG_ERR, CONFIG,
        "Base Schema attribute '%s' unable to be added to class '%s'",
        attr->name, class->name);
    destroy_attr_data(attr);
    return FALSE;
  }
 
  /* Private is optional */
  attr = create_attribute(BC_PRIVATE,           /* attr-name   */
                          "object is private",  /* description */
                          NULL,                 /* format      */
                          INDEX_NONE,           /* index-type  */
                          TYPE_TEXT,            /* type        */
                          FALSE,                /* is_hierarchical */
                          FALSE,                /* is_required */
                          FALSE,                /* is_repeatable*/
                          FALSE,                /* is_multi_line */
                          FALSE,                /* is_primary_key */
                          TRUE                  /* is_private */
                          );
  
  add_attribute_alias(&(attr->aliases), &(attr->num_aliases), BC_PRIVATE_A1);
  
  if (! add_attribute(attr, class, attr_ref_list))
  {
    log(L_LOG_ERR, CONFIG,
        "Base Schema attribute '%s' unable to be added to class '%s'",
        attr->name, class->name);
    destroy_attr_data(attr);
    return FALSE;
  }

  /* TTL is optional */
  attr = create_attribute(BC_TTL,               /* attr-name   */
                          "Time to live",       /* description */
                          NULL,                 /* format      */
                          INDEX_NONE,           /* index-type  */
                          TYPE_TEXT,            /* type        */
                          FALSE,                /* is_hierarchical */
                          FALSE,                /* is_required */
                          FALSE,                /* is_repeatable*/
                          FALSE,                /* is_multi_line */
                          FALSE,                /* is_primary_key */
                          FALSE                 /* is_private */
                          );
  
  if (! add_attribute(attr, class, attr_ref_list))
  {
    log(L_LOG_ERR, CONFIG,
        "Base Schema attribute '%s' unable to be added to class '%s'",
        attr->name, class->name);
    destroy_attr_data(attr);
    return FALSE;
  }
 
  return TRUE;
}

attribute_struct *
find_attribute_by_name(class, name)
  class_struct  *class;
  char          *name;
{
  int               not_done;
  attribute_struct  *val;
  dl_list_type      *list;
  int               i;
  
  if (!class || !name)
  {
    return NULL;
  }

  list = &(class->attribute_list);
  
  not_done = dl_list_first(list);
  while (not_done)
  {
    val = dl_list_value(list);

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

    not_done = dl_list_next(list);
  }

  /* we didn't find anything */
  return NULL;
}

attribute_struct *
find_attribute_by_id(class, id)
  class_struct  *class;
  int           id;
{
  int               not_done;
  attribute_struct  *val;
  dl_list_type      *list;
  
  if (!class)
  {
    return NULL;
  }

  list = &(class->attribute_list);
  
  not_done = dl_list_first(list);
  while (not_done)
  {
    val = dl_list_value(list);

    if (val->local_id == id)
    {
      return(val);
    }

    not_done = dl_list_next(list);
  }

  /* we didn't find anything */
  return NULL;
}

attribute_struct *
find_attribute_by_global_id(class, global_id)
  class_struct  *class;
  int           global_id;
{
  int               not_done;
  attribute_struct  *val;
  dl_list_type      *list;
  
  if (!class)
  {
    return NULL;
  }

  list = &(class->attribute_list);
  
  not_done = dl_list_first(list);
  while (not_done)
  {
    val = dl_list_value(list);

    if (val->global_id == global_id)
    {
      return(val);
    }

    not_done = dl_list_next(list);
  }

  /* we didn't find anything */
  return NULL;
}

attribute_ref_struct *
find_global_attr_by_name(attr_ref_list, name)
  dl_list_type  *attr_ref_list;
  char          *name;
{
  int                   not_done;
  attribute_ref_struct  *val;
  int                   i;

  if (!attr_ref_list || !name)
  {
    return NULL;
  }

  not_done = dl_list_first(attr_ref_list);
  while (not_done)
  {
    val = dl_list_value(attr_ref_list);

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

    not_done = dl_list_next(attr_ref_list);
  }

  /* we didn't find anything */
  return NULL;
}

attribute_ref_struct *
find_global_attr_by_id(attr_ref_list, id)
  dl_list_type  *attr_ref_list;
  int           id;
{
  int                   not_done;
  attribute_ref_struct  *val;

  if (!attr_ref_list)
  {
    return NULL;
  }

  not_done = dl_list_first(attr_ref_list);
  while (not_done)
  {
    val = dl_list_value(attr_ref_list);

    if (val->global_id == id)
    {
      return(val);
    }

    not_done = dl_list_next(attr_ref_list);
  }

  /* we didn't find anything */
  return NULL;
}


/* returns the description of the attribute */
char *
show_attribute_type(type)
  attr_type type;
{
  switch (type)
  {
  case TYPE_SEE_ALSO:
    return(A_SEE_ALSO);
  case TYPE_ID:
    return(A_ID);
  case TYPE_TEXT:
    return(A_TYPE_TEXT);
  default:
    return("UNKNOWN");
  }
}

/* returns the description of index type */
char *
show_index_type(index)
  attr_index_type index;
{
  switch (index)
  {
  case INDEX_NONE:
    return (A_INDEX_NONE);
  case INDEX_ALL:
    return (A_INDEX_ALL);
  case INDEX_EXACTLY:
    return (A_INDEX_EXACT);
  case INDEX_SOUNDEX:
    return (A_INDEX_SOUNDEX);
  case INDEX_CIDR:
    return (A_INDEX_CIDR);
  default:
    return ("UNKNOWN");
  }
}


void
display_attribute(attr)
  attribute_struct  *attr;
{
  int i;
  
  printf("      attribute:      %s\n", attr->name);

  printf("      aliases:        ");
  for (i = 0; i < attr->num_aliases; i++)
  {
    printf("%s ", attr->aliases[i]);
  }
  printf("\n");
  
  
  printf("      global_id:      %d\n", attr->global_id);
  printf("      local id:       %d\n", attr->local_id);

  printf("       flags:         ");
  if (attr->is_hierarchical) printf("(hierarchical) ");
  if (attr->is_required) printf("(required) ");
  if (attr->is_repeatable) printf("(repeatable) ");
  if (attr->is_primary_key) printf("(primary_key) ");
  if (attr->is_private) printf("(private) ");
  printf("\n");
  
  printf("      description:    %s\n", SAFE_STR_NONE(attr->description));
  printf("      format:         %s\n", SAFE_STR_NONE(attr->format));
  printf("      index:          %s\n", show_index_type(attr->index));
  printf("      type:           %s\n", show_attribute_type(attr->type));
}

void
display_attribute_list(list)
  dl_list_type  *list;
{
  int   not_done;

  not_done = dl_list_first(list);
  while (not_done)
  {
    display_attribute(dl_list_value(list));

    not_done = dl_list_next(list);
    if (not_done)
    {
      printf("      --------------------\n");
    }
  }
}

/* destroy_attr_data: destroy function for the attribute_struct data
      type */
int
destroy_attr_data(attr)
  attribute_struct  *attr;
{
  int   i;
  
  if (!attr) return TRUE;

  if (attr->name)
  {
    free(attr->name);
  }

  if (attr->description)
  {
    free(attr->description);
  }

  if (attr->format)
  {
    free(attr->format);
  }
  
  for (i = 0; i < attr->num_aliases; i++)
  {
    if (attr->aliases[i])
    {
      free(attr->aliases[i]);
    }
  }

  if (attr->aliases)
  {
    free(attr->aliases);
  }
  
  free(attr);

  return TRUE;
}
  
/* destroy_attr_ref_data: the destroy function for the
      attribute_ref_struct type. */
int
destroy_attr_ref_data(attr_ref)
  attribute_ref_struct  *attr_ref;
{
  int   i;
  
  if (!attr_ref) return TRUE;

  if (attr_ref->name)
  {
    free(attr_ref->name);
  }

  for (i = 0; i < attr_ref->num_aliases; i++)
  {
    if (attr_ref->aliases[i])
    {
      free(attr_ref->aliases[i]);
    }
  }

  if (attr_ref->aliases)
  {
    free(attr_ref->aliases);
  }
  
  dl_list_destroy(&(attr_ref->class_list));

  free(attr_ref);
  
  return TRUE;
}

/* writes a class attribute template file. If given it uses the suffix 
   to create a new file name by appending this suffix. If writing this file
   was successful the file name is added to the 'paths_list'. It also
   creates the class database directory. */
int 
write_class_attributes(file, suffix, class, paths_list)
  char         *file;
  char         *suffix;
  class_struct *class;
  dl_list_type *paths_list;
{
  FILE             *fp;
  int              not_done;
  int              wrote_attr;
  dl_list_type     *attr_list;
  attribute_struct *attr;
  char             new_file[MAX_FILE];

  if (!file || !*file || !class || !paths_list) return FALSE;

  /* create the database directory for the class if it does not exist */
  if (!directory_exists(class->db_dir))
  {
    if (!make_config_dir(class->db_dir, 0755, paths_list)) 
    {
      log(L_LOG_ERR, CONFIG, "creating class data directory '%s': %s",
          SAFE_STR(class->db_dir, ""), strerror(errno));
      return FALSE;
    }
  }
  
  attr_list = &class->attribute_list;

  if (dl_list_empty(attr_list))
  {
    log(L_LOG_ERR, CONFIG, "class '%s' attribute list empty", 
        SAFE_STR(class->name, ""));
    return FALSE;
  }

  bzero(new_file, sizeof(new_file));
  strncpy(new_file, file, sizeof(new_file)-1);
  strncat(new_file, suffix, sizeof(new_file)-1);

  /* write the class template file */
  if ((fp = open_file_to_write(new_file, 60, paths_list)) == NULL)
  {
    log(L_LOG_ERR, CONFIG, "could not open class template file '%s': %s",
        new_file, strerror(errno));
    return FALSE;
  }

  not_done = dl_list_first(attr_list);
  while (not_done)
  {
    attr = dl_list_value(attr_list);

    /* write the attribute information in the template file */
    wrote_attr = FALSE;
    if (!is_base_attr(attr))
    {
      if (write_attribute_defs(fp, attr))
      {
        wrote_attr = TRUE;
      }
      else
      {
        release_file_lock(new_file, fp);
        dl_list_append(paths_list, xstrdup(new_file));
        return FALSE;
      }
    }

    not_done = dl_list_next(attr_list);
    if (not_done && wrote_attr)
    {
      fprintf(fp, "-----\n");
    }
  }  

  release_file_lock(new_file, fp);

  dl_list_append(paths_list, xstrdup(new_file));

  return TRUE;
}


/* creates a class attribute and appends it to the attribute list */
int 
create_attribute_def(attr, class, aa)
  attribute_struct *attr;
  class_struct     *class;
  auth_area_struct *aa;
{
  int              i;
  dl_list_type     *attr_ref_list;
  attribute_struct *newattr = NULL;

  if ( !attr || !attr->name || 
       !class || !aa || !aa->schema ) return FALSE;

  newattr = create_attribute(attr->name,          /* attr-name  */   
                             attr->description,      /* description */
                             attr->format,           /* format      */
                             attr->index,            /* index-type  */
                             attr->type,             /* type        */
                             attr->is_hierarchical,  /* is_hierarchical */
                             attr->is_required,      /* is_required */
                             attr->is_repeatable,    /* is_repeatable*/
                             attr->is_primary_key,   /* is_primary_key */
                             attr->is_multi_line,    /* is_multi_line */
                             attr->is_private        /* is_private */
                             );

  /* add attribute aliases */
  for (i = 0; i < attr->num_aliases; i++) 
  {
    if (!add_new_attribute_alias(aa, class, newattr, attr->aliases[i]))
    {
      destroy_attr_data(newattr);
      return FALSE;
    }
  }

  attr_ref_list = &aa->schema->attribute_ref_list;
  if ( !add_attribute(newattr, class, attr_ref_list) )
  {
    log(L_LOG_ERR, CONFIG, 
        "'%s:%s:%s' schema attribute could not be added",
        aa->name, class->name, newattr->name);
    destroy_attr_data(newattr);
    return FALSE;
  }

  return TRUE;
}

/* checks if the attribute specified is a base attribute - hard coded */
int
is_base_attr(attr)
  attribute_struct *attr;
{
  if (STR_EQ(attr->name, BC_CLASS_NAME))
    return TRUE;
  else if (STR_EQ(attr->name, BC_CLASS_NAME_A1))
    return TRUE;
  else if (STR_EQ(attr->name, BC_CLASS_NAME_A2))
    return TRUE;
  else if (STR_EQ(attr->name, BC_CLASS_NAME_A3))
    return TRUE;
  else if (STR_EQ(attr->name, BC_ID))
    return TRUE;
  else if (STR_EQ(attr->name, BC_AUTH_AREA))
    return TRUE;
  else if (STR_EQ(attr->name, BC_AUTH_AREA_A1))
    return TRUE;
  else if (STR_EQ(attr->name, BC_UPDATED))
    return TRUE;
  else if (STR_EQ(attr->name, BC_UPDATED_A1))
    return TRUE;
  else if (STR_EQ(attr->name, BC_GUARDIAN))
    return TRUE;
  else if (STR_EQ(attr->name, BC_GUARDIAN_A1))
    return TRUE;
  else if (STR_EQ(attr->name, BC_PRIVATE))
    return TRUE;
  else if (STR_EQ(attr->name, BC_PRIVATE_A1))
    return TRUE;
  else if (STR_EQ(attr->name, BC_TTL))
    return TRUE;

  return FALSE;
}


/* verify each attribute in the attribute list */
int
verify_attribute_list(aa, class)
  auth_area_struct *aa;
  class_struct     *class;
{
  int              not_done;
  int              non_base;
  attribute_struct *attr;
  dl_list_type     *attr_list = &(class->attribute_list);

  /* check for bad attributes */
  if (!aa || !class || !aa->name || !class->name) return FALSE;

  non_base = 0;
  not_done = dl_list_first(attr_list);
  while (not_done)
  {
    attr = dl_list_value(attr_list);
  
    if (!verify_attribute_defs(aa, class, attr))
    {
      return FALSE;
    }
    if (!is_base_attr(attr)) non_base++;

    not_done = dl_list_next(attr_list);
  }

  if (non_base == 0)
  {
    log(L_LOG_ERR, CONFIG,
        "'%s' authority area '%s' class has no non-base attributes", 
        SAFE_STR(aa->name, ""), SAFE_STR(class->name, ""));
    return FALSE;
  }

  return TRUE;
}

/*
   examine the validity of an attribute name or its alias. Returns a
   non-zero value if failed.
*/
int
examin_attribute_name(name)
  char *name;
{
  if (NOT_STR_EXISTS(name)) return ERW_EMTYSTR;
  if (!is_id_str(name)) return ERW_IDSTR;
  return( 0 );
}

/*
   examine the validity of attribute display format syntax. Returns a
   non-zero value if failed.
*/
int
examin_attribute_format(fmt)
  char *fmt;
{
  if (NOT_STR_EXISTS(fmt)) return ERW_EMTYSTR;
  return( 0 );
}


/* add a new attibute to the list after making sure it is not a
   duplicate. */
int
add_new_attribute_alias(aa, class, attr, alias)
  auth_area_struct *aa;
  class_struct     *class;
  attribute_struct *attr;
  char             *alias;
{
  /* bad parameters */
  if (!aa || !class || !attr || !alias || !*alias) return FALSE;

  /* check to make sure we are not adding duplicate attribute names */
  if (find_attribute_by_name(class, alias))
  {
    log(L_LOG_ERR, CONFIG,
        "attribute alias name '%s' already used in '%s:%s' class",
        alias, SAFE_STR(aa->name, ""), SAFE_STR(class->name, ""));
    return FALSE;
  }

  return( add_attribute_alias(&(attr->aliases), &(attr->num_aliases), alias) );
}
