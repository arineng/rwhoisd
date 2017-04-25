/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "security_directive.h"
#include "guardian.h"

#include "attributes.h"
#include "client_msgs.h"
#include "defines.h"
#include "dl_list.h"
#include "fileutils.h"
#include "log.h"
#include "main_config.h"
#include "misc.h"
#include "mkdb_types.h"
#include "parse.h"
#include "records.h"
#include "search.h"
#include "state.h"
#include "types.h"


/*--------------------- LOCAL FUNCTIONS ---------------------------*/

static int
looks_like_id(id)
  char *id;
{
  char *p = NULL;

  if (NOT_STR_EXISTS(id))
  {
    return FALSE;
  }

  p = strchr(id, '.');

  if (! p)
  {
    return FALSE;
  }

  return TRUE;
}

static int
build_guardian_query(query, id)
  query_struct *query;
  char         *id;
{
  char         query_str[MAX_LINE];

  if (!query)
  {
    log(L_LOG_ERR, UNKNOWN, "build_guardian_query: null data detected");
    return FALSE;
  }

  if (looks_like_id(id))
  {
    sprintf(query_str, "ID=%s", id);
  }
  else
  {
    sprintf(query_str, "%s", id);
  }

  if (!parse_query(query_str, query))
  {
    log(L_LOG_ERR, UNKNOWN, "find guardian query failed to parse: %s",
        query_str);
    return FALSE;
  }

  return TRUE;
}

/* A debug function which prints the details of a query_struct */
void
print_query_details(query)
  query_struct *query;
{

  if (query->auth_area_name)
  {
    printf("Auth-Area: %s\n", query->auth_area_name);
  }
  if (query->class_name)
  {
    printf("Class-Name: %s\n", query->class_name);
  }
  if (query->query_tree->attribute_name)
  {
    printf("Attribute-Name: %s\n", query->query_tree->attribute_name);
  }
  if (query->query_tree->search_value)
  {
    printf("Search-Value: %s\n", query->query_tree->search_value);
  }
}

/* checks to see of the security request structure matches the
   guardian information.  Returns FALSE if this guardian doesn't
   match, TRUE if it does. */
static int
check_credentials(guard, request)
  record_struct *guard;
  auth_struct   *request;
{
  av_pair_struct    *av_pair;
  char              *guard_info;
  char              *guard_scheme;
  char              *guard_id;

  /* since we can't check again non-existant credentials, we
     immediately conclude that this guardian doesn't match */
  if (!request)
  {
    return FALSE;
  }

  av_pair = find_attr_in_record_by_name(guard, "ID");
  if (!av_pair)
  {
    log(L_LOG_ERR, UNKNOWN, "guardian record has no ID");
    return FALSE;
  }

  guard_id = (char *)av_pair->value;

  av_pair = find_attr_in_record_by_name(guard, "Guard-Scheme");
  if (!av_pair)
  {
    log(L_LOG_ERR, UNKNOWN, "guardian object '%s' doesn't contain a scheme",
        guard_id);
    return FALSE;
  }

  /* deal with cleartext password scheme name ambiguity */
  if (STR_EQ((char *)av_pair->value, "pw") ||
      STR_EQ((char *)av_pair->value, "passwd") ||
      STR_EQ((char *)av_pair->value, "password"))
  {
    guard_scheme = "pw";
  }
  else
  {
    guard_scheme = (char *)av_pair->value;
  }

  /* if this guardian does not match our scheme, continue to next
     guardian */
  if (!STR_EQ(request->scheme, guard_scheme))
  {
    return FALSE;
  }

  av_pair = find_attr_in_record_by_name(guard, "Guard-Info");
  if (!av_pair)
  {
    log(L_LOG_ERR, UNKNOWN, "guardian object '%s' doesn't contain info",
        guard_id);
    return FALSE;
  }

  guard_info = (char *)av_pair->value;

  /* compare the info */
  if (STR_EQ(request->scheme, "pw"))
  {
    if (strcmp(request->info, guard_info) == 0)
    {
      return TRUE;
    }
  }
  else if (STR_EQ(request->scheme, "crypt-pw"))
  {
    if (strcmp(guard_info, crypt(request->info, guard_info)) == 0)
    {
      return TRUE;
    }
  }
  else
  {
    /* don't know what to do for the unknown guard-scheme */
    log(L_LOG_ERR, UNKNOWN, "unknown guard scheme '%s'", request->scheme);
  }

  return FALSE;
}

static record_struct *
lookup_guardian_record(guard_id)
  char *guard_id;
{
  query_struct      *query;
  dl_list_type      new_rec_list;
  record_struct     *guard;
  record_struct     *result;
  ret_code_type     ret_code;
  int               num_recs;

  if (!STR_EXISTS(guard_id))
  {
    return NULL;
  }

  query = xcalloc(1, sizeof(*query));

  if (! build_guardian_query(query, guard_id))
  {
    destroy_query(query);
    return NULL;
  }

  dl_list_default(&new_rec_list, FALSE, destroy_record_data);
  num_recs = search(query, &new_rec_list, 2, &ret_code);

  destroy_query(query);

  if (ret_code != SEARCH_SUCCESSFUL)
  {
    log(L_LOG_NOTICE, UNKNOWN, "guardian lookup search failed");
    return NULL;
  }

  /* stale guardian record, basically */
  if (dl_list_empty(&new_rec_list))
  {
    return NULL;
  }

  if (num_recs > 1)
  {
    log(L_LOG_NOTICE, UNKNOWN,
        "multiple objects returned from guardian reference '%s'", guard_id);
  }

  dl_list_first(&new_rec_list);
  guard = dl_list_value(&new_rec_list);

  if (!guard)
  {
    return NULL;
  }

  result = copy_record(guard);

  dl_list_destroy(&new_rec_list);

  return(result);
}


/* this function returns TRUE if the record is guarded, FALSE if not.  */
static int
is_record_guarded(record)
  record_struct *record;
{
  av_pair_struct *av_pair;

  /* strange null data isn't guarded, I guess */
  if (!record ||
      dl_list_empty(&(record->av_pair_list)))
  {
    return FALSE;
  }

  /* if we are a guardian */
  if (is_guardian_record(record))
  {
    return TRUE;
  }

  /* if our auth-area is guarded */
  if (record->auth_area && record->auth_area->guardian_list)
  {
    return TRUE;
  }

  /* or if we have a guardian attribute; note that if the link is stale, we
     actually shouldn't be considered guarded, but we defer this check
     until later */
  av_pair = find_attr_in_record_by_name(record, "Guardian");
  if (av_pair)
  {
    return TRUE;
  }

  /* otherwise, we aren't guarded */
  return FALSE;
}

/*------------------- Public Functions ----------------------------*/

/* returns TRUE if the security attributes match a guardian of record,
   or record not guarded */
int
check_guardian(record)
  record_struct *record;
{
  av_pair_struct *av_pair;
  record_struct  *guard;
  auth_struct    *request         = get_request_auth_struct();
  char           *guard_id;
  char           *rec_id;
  char           *scheme;
  int            not_done;
  int            found_guard_attr = FALSE;
  int            status;

  if (!record ||
      dl_list_empty(&(record->av_pair_list)))
  {
    log(L_LOG_ERR, UNKNOWN, "check_guardian: null data detected");
    return FALSE;
  }

  /* detect the malformed security state */
  if ((get_rwhois_secure_mode() == TRUE) &&
      (request == NULL ||
       request->mode == NULL ||
       request->scheme == NULL ||
       request->info == NULL ||
       request->type == NULL))
  {
    log(L_LOG_ERR, UNKNOWN, "check_guardian: null security data detected");
    return FALSE;
  }

  if (! is_record_guarded(record))
  {
    return TRUE;
  }

  av_pair = find_attr_in_record_by_name(record, "ID");
  if (av_pair)
  {
    rec_id = (char *)av_pair->value;
  }
  else
  {
    rec_id = "unknown";
  }

  /* otherwise, we presume that the obj is guarded, and so we must
     check the various lists of guardians. We know for sure if we are
     guarded when we actually find a guardian. */

  /* first look for guard attrs */
  not_done = dl_list_first(&(record->av_pair_list));
  while (not_done)
  {
    av_pair  = dl_list_value(&(record->av_pair_list));
    not_done = dl_list_next(&(record->av_pair_list));

    if (!STR_EQ(av_pair->attr->name, "Guardian"))
    {
      continue;
    }
    guard_id = (char *)av_pair->value;
    guard = lookup_guardian_record(guard_id);

    if (!guard)
    {
      /* we have discovered a stale guardian link */
      log(L_LOG_WARNING, UNKNOWN, "stale guardian link '%s' in object '%s'",
          guard_id, rec_id);
      continue;
    }

    found_guard_attr = TRUE;

    /* if the object is guarded, and we aren't it secure mode, then we
       get to fail immediately */
    if (get_rwhois_secure_mode() == FALSE)
    {
      destroy_record_data(guard);
      return FALSE;
    }

    status = check_credentials(guard, request);
    destroy_record_data(guard);

    if (status > 0)
    {
      return TRUE;
    }
  }

  /* if the authority area is guarded, check it */
  if (record->auth_area  &&
      record->auth_area->guardian_list &&
      !dl_list_empty(record->auth_area->guardian_list))
  {
    not_done = dl_list_first(record->auth_area->guardian_list);
    while (not_done)
    {
      guard_id = dl_list_value(record->auth_area->guardian_list);
      guard = lookup_guardian_record(guard_id);
      not_done = dl_list_next(record->auth_area->guardian_list);

      if (!guard)
      {
        /* we have discovered a stale guardian link */
        log(L_LOG_WARNING, UNKNOWN,
            "stale guardian link '%s' for auth-area '%s'",
            guard_id, record->auth_area->name);
        continue;
      }

      if (get_rwhois_secure_mode() == FALSE)
      {
        destroy_record_data(guard);
        return FALSE;
      }

      status = check_credentials(guard, request);
      destroy_record_data(guard);

      if (status > 0)
      {
        return TRUE;
      }
    }
  }

  /* guardians without guardian attrs guard themselves */
  if (!found_guard_attr && (STR_EQ(record->class->name, "Guardian")))
  {
    /* if we are guarding ourselves and we aren't in secure mode,
       don't embarrass ourselves by trying to check the credentials
       and core dumping */
    if (get_rwhois_secure_mode() == FALSE)
    {
      return FALSE;
    }

    status = check_credentials(record, request);

    if (status > 0)
    {
      return TRUE;
    }
  }

  /* the record is guarded, but is not a guardian itself, but has no
     real guardians (i.e., all guard attributes were stale or
     missing), so we conclude that authorization *must* fail */
  if (!found_guard_attr)
  {
    return FALSE;
  }

  /* if we couldn't match any guardians credentials, we fail by default */
  if (STR_EXISTS(rec_id))
  {
    rec_id = "unknown";
  }
  if (!request || NOT_STR_EXISTS(request->scheme))
  {
    scheme = "unset";
  }
  else
  {
    scheme = request->scheme;
  }

  log(L_LOG_INFO, CLIENT,
      "failed to authenticate for object '%s' using guard scheme '%s'",
      rec_id, scheme);
  return FALSE;
}

int
is_guardian_record(record)
  record_struct *record;
{
  if (STR_EQ(record->class->name, "Guardian"))
  {
    return TRUE;
  }

  return FALSE;
}

/* given a guardian record, possibly transform (or rewrite) the
   guard-scheme and guard-info attribute values.  This allows us to
   crypt() passwords, normalize scheme names, etc. */

int
transform_guardian_record(rec)
  record_struct *rec;
{
  av_pair_struct *av;
  char           *scheme;
  char           *info;

  /* no need to modify if we are not a guardian */
  if (! is_guardian_record(rec))
  {
    return TRUE;
  }

  /* modify the guard scheme */
  av = find_attr_in_record_by_name(rec, "Guard-Scheme");
  if (!av)
  {
    return FALSE;
  }

  scheme = (char *)av->value;

  if (STR_EXISTS(scheme) &&
      (STR_EQ(scheme, "pw") || STR_EQ(scheme, "passwd") ||
       STR_EQ(scheme, "password")))
  {
    free(av->value);
    av->value = xstrdup("pw");
    scheme = (char *)av->value;
  }

  /* modify the guard info */
  av = find_attr_in_record_by_name(rec, "Guard-Info");
  if (!av)
  {
    return FALSE;
  }

  info = (char *)av->value;
  if (STR_EXISTS(info) && STR_EXISTS(scheme) && STR_EQ(scheme, "crypt-pw"))
  {
    info = crypt(info, generate_salt());
    free(av->value);
    av->value = xstrdup(info);
  }

  return TRUE;
}
