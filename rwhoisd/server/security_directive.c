/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "security_directive.h"

#include "attributes.h"
#include "client_msgs.h"
#include "defines.h"
#include "dl_list.h"
#include "fileutils.h"
#include "log.h"
#include "main_config.h"
#include "misc.h"
#include "mkdb_types.h"
#include "state.h"
#include "types.h"

typedef struct _security_arg_struct 
{
  char         *mode;
  char         *direction;
  char         *scheme;
  dl_list_type *data_list;
} security_arg_struct;


static auth_struct *request   = NULL;
static auth_struct *response  = NULL;

static security_arg_struct *security_parse_args PROTO((char *str));

static auth_struct *security_store_auth PROTO((security_arg_struct *prs));

static void free_security_args_struct PROTO((security_arg_struct *prs));

static void free_auth_struct PROTO((auth_struct *auth));

static void print_auth_struct PROTO((void));

/*------------------ LOCAL FUNCTIONS -----------------------------*/

static void 
free_auth_struct(auth)
  auth_struct *auth;
{
  if (!auth)
  {
    return;
  }
  if (auth->mode)
  {
    free(auth->mode);
  }
  if (auth->scheme)
  {
    free(auth->scheme);
  }
  if (auth->info)
  {
    free(auth->info);
  }
  if (auth->type)
  {
    free(auth->type);
  }
  free(auth);
}

static security_arg_struct *
security_parse_args(str)
  char *str;
{
  int                 i;
  int                 argc;
  char                **argv;
  security_arg_struct *prs;
  
  if (!str || !*str)
  {
    return (security_arg_struct *) NULL;
  }

  split_arg_list(str, &argc, &argv);
 
  if (argc < 1)
  {
    free_arg_list(argv);
    return (security_arg_struct *) NULL;
  }

  
  prs = (security_arg_struct *)xcalloc(1, sizeof(security_arg_struct));
  
  /* Mode */
  if (STR_EQ(argv[0], "off") || STR_EQ(argv[0], "on"))
  {
    prs->mode = NEW_STRING(argv[0]);
  }
  else
  {
    free_arg_list(argv);
    free_security_args_struct(prs);
    return (security_arg_struct *) NULL;
  }

  if (STR_EQ(prs->mode, "off"))
  {
    free_arg_list(argv);
    return (prs);
  } 

  if (argc < 3)
  {
    free_arg_list(argv);
    free_security_args_struct(prs);
    return (security_arg_struct *) NULL;
  }
    
  /* Direction */
  if (STR_EQ(argv[1], "request") ||
      STR_EQ(argv[1], "response"))
  {
    prs->direction = NEW_STRING(argv[1]);
  }
  else
  {
    free_arg_list(argv);
    free_security_args_struct(prs);
    return (security_arg_struct *) NULL;
  }

  if (STR_EQ(prs->mode, "on"))
  {
    /* Scheme */
    if (STR_EQ(argv[2], "pw") ||
        STR_EQ(argv[2], "password") ||
        STR_EQ(argv[2], "passwd"))
    {
      prs->scheme = NEW_STRING("pw");
    }
    else if (STR_EQ(argv[2], "crypt-pw"))
    {
      prs->scheme = NEW_STRING(argv[2]);
    }
    else
    {
      free_arg_list(argv);
      free_security_args_struct(prs);
      print_error(INVALID_SECURITY, "");
      return (security_arg_struct *) NULL;
    }

    /* Data */
    if (argc > 3)
    {
      prs->data_list = (dl_list_type *)xcalloc(1, sizeof(dl_list_type));
      dl_list_default(prs->data_list, TRUE, simple_destroy_data);
      
      for (i = 3; i < argc; i++)
      {
        dl_list_insert(prs->data_list, xstrdup(argv[i]));
      }
    }
  }

  free_arg_list(argv);

  return prs;
}


/* This function stores the authentication information sent by the
   client into the appropriate data structure - request for
   authentication of all requests sent by the client, and response for
   all responses from the server. */
static auth_struct * 
security_store_auth(prs)
  security_arg_struct *prs;
{
  auth_struct *auth = NULL;

  if (STR_EQ(prs->mode, "on"))
  {
    auth = xcalloc(1, sizeof(*auth));
  }

  auth->mode   = prs->mode;
  auth->scheme = NEW_STRING(prs->scheme);

  if (STR_EQ(prs->scheme, "pw"))
  {
    if (STR_EQ(prs->direction, "response"))
    {
      print_error(INVALID_DIRECTIVE_PARAM, 
                  "Scheme not supported");
      free_auth_struct(auth);
      return((auth_struct *)NULL);
    }
    auth->type = NEW_STRING("auth");
    if (!dl_list_first(prs->data_list))
    {
      print_error(INVALID_DIRECTIVE_PARAM, "Password not supplied");
      free_auth_struct(auth);
      return ((auth_struct *)NULL);
    }
    auth->info = NEW_STRING(dl_list_value(prs->data_list));
  }
  else if (STR_EQ(prs->scheme, "crypt-pw"))
  {
    if (STR_EQ(prs->direction, "response"))
    {
      print_error(INVALID_DIRECTIVE_PARAM, 
                  "Scheme not supported");
      free_auth_struct(auth);
      return((auth_struct *)NULL);
    }
    auth->type = NEW_STRING("auth");
    if (!dl_list_first(prs->data_list))
    {
      print_error(INVALID_DIRECTIVE_PARAM, "Password not supplied");
      free_auth_struct(auth);
      return NULL;
    }
    auth->info = NEW_STRING(dl_list_value(prs->data_list));
  }
  else
  {
    print_error(INVALID_DIRECTIVE_PARAM, "Invalid auth type");
    free_auth_struct(auth);
    return NULL;
  }

  return auth;
}


static void
print_auth_struct()
{
  if (request)
  {
    if (request->mode != NULL)
    {
      printf("request->mode:   <%s>\n", request->mode);
    }
    if (request->scheme != NULL)
    {
      printf("request->scheme: <%s>\n", request->scheme);
    }
    if (request->info != NULL)
    {
      printf("request->info:   <%s>\n", request->info);
    }
    if (request->type != NULL)
    {
      printf("request->type:   <%s>\n", request->type);
    }
  }
}


static void 
free_security_args_struct(prs)
    security_arg_struct *prs;
{
  if (prs->mode)
  {
    free(prs->mode);
  }
  if (prs->direction)
  {
    free(prs->direction);
  }
  if (prs->direction)
  {
    free(prs->scheme);
  }
  if (prs->data_list)
  {
    dl_list_destroy(prs->data_list);
  }
  free(prs);
}



/*------------------- PUBLIC FUNCTIONS -------------------------*/

int
security_directive(str)
  char  *str;
{
  security_arg_struct *prs;

  if ((prs = security_parse_args(str)) != NULL)
  {
    log(L_LOG_DEBUG, CLIENT,
        "security directive: %s %s %s <other data hidden>",
        prs->mode, prs->direction, prs->scheme);

    if (STR_EQ(prs->mode, "off"))
    {
      if (response != NULL)
      {
        free_auth_struct(response);
        free_security_args_struct(prs);      
        set_rwhois_secure_mode(FALSE);
        set_out_fp(stdout);
        return TRUE;
      }
      if (request != NULL)
      {
        free_auth_struct(request);
        free_security_args_struct(prs);      
        set_rwhois_secure_mode(FALSE);
        return TRUE;
      }
      else
      {
        print_error(INVALID_DIRECTIVE_PARAM, ""); 
        free_security_args_struct(prs);      
        return FALSE;
      }
    }
    if (STR_EQ(prs->direction, "request"))
    {
      if ((request = security_store_auth(prs)) == NULL)
      {
        free_security_args_struct(prs);
        return(FALSE);
      }
    }
    else if (STR_EQ(prs->direction, "response"))
    {
      if ((response = security_store_auth(prs)) == NULL)
      {
        free_security_args_struct(prs);
        return(FALSE);
      }
    }  

    set_rwhois_secure_mode(TRUE);
    free_security_args_struct(prs);
        
    return(TRUE);
  }
  else
  {
    print_error(INVALID_DIRECTIVE_PARAM, ""); 
    return(FALSE);
  }
}


auth_struct *
get_request_auth_struct()
{
  return request;
}


auth_struct *
get_response_auth_struct()
{
  return response;
}

