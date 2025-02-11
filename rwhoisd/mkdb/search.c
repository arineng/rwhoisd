/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "search.h"

#include "common_regexps.h"
#include "attributes.h"
#include "auth_area.h"
#include "client_msgs.h"
#include "defines.h"
#include "fileinfo.h"
#include "index.h"
#include "index_file.h"
#include "ip_network.h"
#include "log.h"
#include "main_config.h"
#include "misc.h"
#include "records.h"
#include "schema.h"
#include "strutil.h"
#include "search_prim.h"

/* ----------------------- Local Functions --------------- */


static int
rebuild_query(auth_area, query)
  auth_area_struct *auth_area;
  query_struct *query;
{
  query_term_struct    *cur_or;
  query_term_struct    *cur_and;
  dl_list_type         *attr_ref_list;
  attribute_ref_struct *attr_ref;

  /* -2 means there is no attribute to set.
   * -1 means that the attribute id has NOT been set.
   *  0 and higher is a valid attribute id.           */

  if (!query)
  {
    log(L_LOG_ERR, MKDB, "rebuild_query: no query");
    return FALSE;
  }

  if (!auth_area || !auth_area->schema)
  {
    log(L_LOG_ERR, MKDB, "rebuild_query: no auth_area");
    return FALSE;
  }


  attr_ref_list = &(auth_area->schema->attribute_ref_list);

  if (dl_list_empty(attr_ref_list))
  {
    return FALSE;
  }

  if (!query->query_tree)
  {
    log(L_LOG_ERR, MKDB, "rebuild_query: the query doesn't have a query_tree");
    return FALSE;
  }

  cur_or = cur_and = query->query_tree;

  while (cur_or)
  {
    while (cur_and)
    {
      if (!cur_and->attribute_name)
      {
        cur_and->attribute_id = -2;
      }
      else
      {
        attr_ref = find_global_attr_by_name(attr_ref_list,
                                            cur_and->attribute_name);
        if (!attr_ref)
        {
          /* this query contains an attribute that does not exist in
             the auth_area, thus rendering the whole search
             unnecessary */
          return FALSE;
        }
        cur_and->attribute_id = attr_ref->global_id;
      }

      cur_and = cur_and->and_list;
    }

    cur_or = cur_and = cur_or->or_list;
  }

  return TRUE;
}

static ret_code_type
search_exact_index_file(class, auth_area, file, data_fi_list,
                        query_tree, record_list, max_hits)
  class_struct      *class;
  auth_area_struct  *auth_area;
  file_struct       *file;
  dl_list_type      *data_fi_list;
  query_term_struct *query_tree;
  dl_list_type      *record_list;
  int               max_hits;
{
  off_t         fposition;
  ret_code_type ret_code    = SEARCH_SUCCESSFUL;

  switch (query_tree->search_type)
  {
  case MKDB_BINARY_SEARCH:
    fposition = binary_search(file, query_tree);
    if (fposition != -1)
    {
      ret_code = full_scan(class, auth_area, file,
                           data_fi_list, query_tree, record_list, max_hits,
                           fposition, FALSE);
    }
    break;

  case MKDB_FULL_SCAN:
    ret_code = full_scan(class, auth_area, file,
                         data_fi_list, query_tree, record_list,
                         max_hits, 0, TRUE);
    break;
  default:
    log(L_LOG_ERR, MKDB, "invalid search type '%d'",
        query_tree->search_type);
    return(INVALID_SEARCH_TYPE);
    break;
  }

  return(ret_code);
}

static ret_code_type
search_soundex_index_file(class, auth_area, file, data_fi_list,
                          query_tree, record_list, max_hits)
  class_struct      *class;
  auth_area_struct  *auth_area;
  file_struct       *file;
  dl_list_type      *data_fi_list;
  query_term_struct *query_tree;
  dl_list_type      *record_list;
  int               max_hits;
{
  char          *orig_search_val;
  char          search_val_buf[MAX_LINE];
  ret_code_type ret_code;

  orig_search_val = query_tree->search_value;
  if (! is_soundexable(orig_search_val))
  {
    return(SEARCH_SUCCESSFUL);
  }
  soundex_index_to_var(search_val_buf, orig_search_val);

  if (NOT_STR_EXISTS(search_val_buf))
  {
    return(SEARCH_SUCCESSFUL);
  }

  query_tree->search_value = search_val_buf;

  ret_code = search_exact_index_file(class, auth_area, file,
                                     data_fi_list, query_tree,
                                     record_list, max_hits);

  query_tree->search_value = orig_search_val;

  return(ret_code);
}

static ret_code_type
search_cidr_index_file(class, auth_area, file, data_fi_list,
                       query_tree, record_list, max_hits)
  class_struct      *class;
  auth_area_struct  *auth_area;
  file_struct       *file;
  dl_list_type      *data_fi_list;
  query_term_struct *query_tree;
  dl_list_type      *record_list;
  int               max_hits;
{
  struct netinfo         prefix;
  off_t                  fposition;
  char                   search_val_buf[MAX_LINE];
  char                   *orig_search_val;
  ret_code_type          ret_code = SEARCH_SUCCESSFUL;
  int                    not_done = TRUE;

  orig_search_val = query_tree->search_value;

  if ( ! get_network_prefix_and_len( orig_search_val, &prefix ) )
  {
    return(SEARCH_SUCCESSFUL);
  }

  /* replace the original query string with our ever changing buffer */
  query_tree->search_value = search_val_buf;

  while (not_done)
  {
    /* mask off the bits that are now in the host part */
    mask_addr_to_len( &prefix, prefix.masklen );

    /* convert back into a string */
    write_network( search_val_buf, &prefix );

    switch (query_tree->search_type)
    {
    case MKDB_BINARY_SEARCH:
      fposition = binary_search(file, query_tree);
      if (fposition != -1)
      {
        ret_code = full_scan(class, auth_area, file,
                             data_fi_list, query_tree, record_list, max_hits,
                             fposition, FALSE);
      }
      break;

      /* this don't make sense bud! */
    case MKDB_FULL_SCAN:
      log(L_LOG_DEBUG, MKDB,
          "invalid search type '%d' for search_cidr_index_file",
          query_tree->search_type);
      return(INVALID_SEARCH_TYPE);
      break;
    default:
      log(L_LOG_ERR, MKDB, "invalid search type '%d'",
          query_tree->search_type);
      return(INVALID_SEARCH_TYPE);
      break;
    }

    /* advance the prefix either up (the network tree) */
    prefix.masklen--;
    if ( prefix.masklen < 0 ) not_done = FALSE;
  }

  /* restore the query term back its original state */
  query_tree->search_value = orig_search_val;

  return(ret_code);
}

static ret_code_type
search_index_file(class, auth_area, index_fi_list, data_fi_list, query_tree,
                  record_list, max_hits, index_type)
  class_struct      *class;
  auth_area_struct  *auth_area;
  dl_list_type      *index_fi_list;
  dl_list_type      *data_fi_list;
  query_term_struct *query_tree;
  dl_list_type      *record_list;
  int               max_hits;
  attr_index_type   index_type;
  /* for a switch-a-roo on a query's value */
{
  file_struct    *file;
  mkdb_file_type file_type_of_term;
  ret_code_type  ret_code           = SEARCH_SUCCESSFUL;
  int            not_done;

  not_done = dl_list_first(index_fi_list);
  while (not_done)
  {
    /* get the file to work on */
    file = dl_list_value(index_fi_list);
    file_type_of_term = convert_file_type(index_type);

    /* if that file's type does not match the index type then skip it */
    if (index_type != INDEX_ALL && (file->type != file_type_of_term))
    {
      not_done = dl_list_next(index_fi_list);
      continue;
    }

    /* if the index_type is INDEX_ALL then the query_term type doesn't */
    /* get passed but instead we pass the index file's type */
    if (index_type == INDEX_ALL)
    {
      file_type_of_term = file->type;
    }

    switch(file_type_of_term)
    {
    case MKDB_EXACT_INDEX_FILE:
      ret_code = search_exact_index_file(class, auth_area, file,
                                         data_fi_list, query_tree,
                                         record_list, max_hits);
      break;
    case MKDB_SOUNDEX_INDEX_FILE:
      ret_code = search_soundex_index_file(class, auth_area, file,
                                           data_fi_list, query_tree,
                                           record_list, max_hits);
      break;
    case MKDB_CIDR_INDEX_FILE:
      if (is_network_valid_for_searching(query_tree->search_value))
      {
        ret_code = search_cidr_index_file(class, auth_area, file,
                                          data_fi_list, query_tree,
                                          record_list, max_hits);
      }
      break;
    default:
      log(L_LOG_ERR, MKDB, "invalid search type '%d'",
          query_tree->search_type);
      return(INVALID_SEARCH_TYPE);
      break;
    }

    if (ret_code == HIT_LIMIT_EXCEEDED)
    {
      return(ret_code);
    }

    not_done = dl_list_next(index_fi_list);
  }

  return(ret_code);
}

static ret_code_type
search_class(query_tree, auth_area, class, record_list, max_hits)
  query_term_struct *query_tree;
  auth_area_struct  *auth_area;
  class_struct      *class;
  dl_list_type      *record_list;
  int               max_hits;
{
  dl_list_type     master_fi_list;
  dl_list_type     index_fi_list;
  dl_list_type     data_fi_list;
  char             index_file[MAX_LINE];
  attribute_struct *attr;
  attr_index_type  index_type;
  ret_code_type    ret_code             = FALSE;

  bzero((char *)index_file, sizeof(index_file));

  dl_list_default(&master_fi_list, FALSE, (int(*)(void *))destroy_file_struct_data);
  dl_list_default(&index_fi_list, FALSE, (int(*)(void *))destroy_file_struct_data);
  dl_list_default(&data_fi_list, FALSE, (int(*)(void *))destroy_file_struct_data);

  /* Ok, this needs a little bit of explaining because there is an
     implicit filtering function here handled by the indexer. What we
     want is the list of index files that are valid for the this
     class. Indexer handles that by only creating index files when
     appropriate. Thus, we can just get the whole list and skip the
     ones that are incorrect for the given step. */

  if (! get_file_list(class, auth_area, &master_fi_list))
  {
    return UNKNOWN_SEARCH_ERROR;
  }
  filter_file_list(&index_fi_list, MKDB_ALL_INDEX_FILES, &master_fi_list);
  filter_file_list(&data_fi_list, MKDB_DATA_FILE, &master_fi_list);

  /* while we have a term to look at */
  while (query_tree && ((max_hits == 0) || (get_hit_count() <= max_hits)))
  {
    if (query_tree->attribute_id > 0)
    {
      attr = find_attribute_by_global_id(class, query_tree->attribute_id);
      if (!attr)
      {
        /* this is the situation where this class doesn't have the
           particular attribute being looked for, so the search is
           successful with nothing found. */
        return SEARCH_SUCCESSFUL;
      }
      index_type = attr->index;
    }
    else
    {
      index_type = INDEX_ALL;
    }

    ret_code = search_index_file(class, auth_area, &index_fi_list,
                                 &data_fi_list, query_tree, record_list,
                                 max_hits, index_type);

    if (ret_code != 0)
    {
      break;
    }

    query_tree = query_tree->or_list;
  }

  /* done with the queries. Just return the number of hits we've accumulated */
  dl_list_destroy(&data_fi_list);
  dl_list_destroy(&index_fi_list);
  dl_list_destroy(&master_fi_list);

  return(ret_code);
}

static ret_code_type
search_auth_area(auth_area, class_name, query, record_list, max_hits)
  auth_area_struct *auth_area;
  char             *class_name;
  query_struct     *query;
  dl_list_type     *record_list;
  int              max_hits;
{
  class_struct  *class;
  dl_list_type  *class_list;
  int           not_done;
  ret_code_type ret_code = SEARCH_SUCCESSFUL;

  if (!auth_area || !auth_area->schema)
  {
    log(L_LOG_ERR, MKDB,
        "search_auth_area: could not find auth area or schema");
    return UNKNOWN_SEARCH_ERROR;
  }

  rebuild_query(auth_area, query);

  if (!class_name || !*class_name)
  {
    class_list = &(auth_area->schema->class_list);

    not_done = dl_list_first(class_list);
    while (not_done)
    {
      class = dl_list_value(class_list);

      /* when doing a classless search, skip the referral areas */
      if (STR_EQ(class->name, "referral"))
      {
        not_done = dl_list_next(class_list);
        continue;
      }

      ret_code = search_class(query->query_tree, auth_area, class,
                             record_list, max_hits);

      if (ret_code != SEARCH_SUCCESSFUL)
      {
        return(ret_code);
      }

      not_done = dl_list_next(class_list);
    }

    return SEARCH_SUCCESSFUL;
  }

  class = find_class_by_name(auth_area->schema, class_name);

  if (!class)
  {
    log(L_LOG_ERR, MKDB, "search_auth_area: could not find class '%s'",
        class_name);
    return UNKNOWN_SEARCH_ERROR;
  }

  return(search_class(query->query_tree, auth_area, class, record_list,
                     max_hits));
}


/* ------------------- Public Functions -------------------- */


/* search: for the given query find all of the appropriate index files
   and data files. Then do the query on each index file and fill out
   the record_list. Returns the number of hits, and an error code it
   'ret_code' */
int
search(query, record_list, max_hits, ret_code)
  query_struct  *query;
  dl_list_type  *record_list;
  int           max_hits;
  ret_code_type *ret_code;
{
  dl_list_type     *auth_area_list = NULL;
  auth_area_struct *auth_area      = NULL;
  class_ref_struct *class_ref      = NULL;
  char             *auth_area_name;
  char             *class_name;
  int              not_done;

  *ret_code = SEARCH_SUCCESSFUL; /* be optimistic */

  /* ummm, if this were the case, why were we called?
     Note that a value of 0 means an unlimited number of hits is allowed */
  if (max_hits < 0)
  {
    return(0);
  }

  if (record_list == NULL)
  {
    log(L_LOG_ERR, MKDB, "search: record_list = NULL");
    *ret_code = UNKNOWN_SEARCH_ERROR;
    return(-1);
  }

  if (query == NULL)
  {
    log(L_LOG_ERR, MKDB, "search: query == NULL");
    *ret_code = UNKNOWN_SEARCH_ERROR;
    return(-1);
  }

  /* reset the hit count */
  set_hit_count(0);

  auth_area_name = query->auth_area_name;
  class_name     = query->class_name;

  /* get the auth_area_list -- 3 cases:
       1. have an auth_area_name.  In this case, leave the list blank
          (not a list) and fill out 'auth_area'.
       2. have a class name only.  Get the list from the class_ref_list
       3. don't have class or  auth_area name.  Get the full auth_area
          list. */
  if (auth_area_name && *auth_area_name)
  {
    auth_area = find_auth_area_by_name(auth_area_name);
    if (!auth_area)
    {
      log(L_LOG_ERR, MKDB, "search: auth_area '%s' unknown", auth_area_name);
      *ret_code = UNKNOWN_SEARCH_ERROR;
      return(-1);
    }
  }
  else if (class_name && *class_name)
  {
    class_ref = find_global_class_by_name(class_name);
    if (!class_ref)
    {
      log(L_LOG_ERR, MKDB, "mkdb: search: class '%s' unknown", class_name);
      *ret_code = UNKNOWN_SEARCH_ERROR;
      return(-1);
    }

    auth_area_list = &(class_ref->auth_area_list);
  }
  else
  {
    auth_area_list = get_auth_area_list();
  }

  /* we had a valid auth area specified */
  if (auth_area)
  {
    *ret_code = search_auth_area(auth_area, class_name, query, record_list,
                                max_hits);

    return(get_hit_count());
  }

  /* otherwise, we need to iterate over auth areas */

  if (!auth_area_list)
  {
    /* some kind of bizarre configuration error occurred */
    log(L_LOG_ERR, MKDB, "search: no authority areas found");
    *ret_code = UNKNOWN_SEARCH_ERROR;
    return(-1);
  }

  not_done = dl_list_first(auth_area_list);

  while (not_done)
  {
    auth_area = dl_list_value(auth_area_list);

    *ret_code = search_auth_area(auth_area, class_name, query, record_list,
                                 max_hits);

    not_done = dl_list_next(auth_area_list);
  }

  return(get_hit_count());
}

int
check_query_complexity(query)
  query_struct *query;
{
  query_term_struct *current_or;
  query_term_struct *current_and;
  int               allow_wild = get_query_allow_wild();
  int               allow_substr = get_query_allow_substr();

  if (!query || !query->query_tree)
  {
    return FALSE;
  }

  current_or = current_and = query->query_tree;

  while (current_or)
  {
    while (current_and)
    {
      if (!allow_wild && (current_and->search_type != MKDB_BINARY_SEARCH ||
                          current_and->comp_type != MKDB_FULL_COMPARE))
      {
        log(L_LOG_INFO, CLIENT,
            "query was too complex -- contained disallowed wildcard");
        print_error(QUERY_TOO_COMPLEX, "");
        return FALSE;
      }
      if (!allow_substr && current_and->search_type != MKDB_BINARY_SEARCH)
      {
        log(L_LOG_INFO, CLIENT,
            "query was too complex -- contained disallowed substring search");
        print_error(QUERY_TOO_COMPLEX, "");
        return FALSE;
      }
      if (current_and->comp_type >= MKDB_NEGATION_OFFSET)
      {
        log(L_LOG_INFO, CLIENT,
            "query was too complex -- contained unsupported comparison type");
        print_error(QUERY_TOO_COMPLEX, "");
        return FALSE;
      }

      current_and = current_and->and_list;
    }

    current_or = current_and = current_or->or_list;
  }

  return TRUE;
}
