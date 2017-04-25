/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "referral.h"

#include "auth_area.h"
#include "schema.h"
#include "client_msgs.h"
#include "common_regexps.h"
#include "defines.h"
#include "ip_network.h"
#include "log.h"
#include "misc.h"
#include "mkdb_types.h"
#include "parse.h"
#include "records.h"
#include "search.h"
#include "strutil.h"
#include "main_config.h"

#define RWHOIS_URL_RX "^rwhois://"
#define RWHOIS_OLD_RX "^([^: \t]+):([0-9]+):rwhois"

static int is_net PROTO((char *str));

static int is_domain PROTO((char *str));

static int hierarchical_value_domain PROTO((char *value,
                                            char *hvalue));

static int hierarchical_value_network PROTO((char *value,
                                             char *hvalue));

static int within_domain PROTO((char *subdomain,
                                char *domain));

static int within_network PROTO((char *subnetwork,
                                 char *network));

static int get_up_referral PROTO((dl_list_type *referral_list));

static int get_down_referral PROTO((char         *hvalue,
                                    int          htype,
                                    char         *aa_name,
                                    dl_list_type *referral_list));

static int reduce_domain PROTO((char *domain));

static int reduce_network PROTO((char *network));

static int build_referral_query PROTO((query_struct *query,
                                       char         *search_value,
                                       char         *aa_name));

static void print_referral_list PROTO((dl_list_type *referral_list));

static void destroy_referral_list PROTO((dl_list_type *referral_list));

static int destroy_referral_data PROTO((referral_struct *referral));

static int aa_has_referrals PROTO((auth_area_struct *aa));

/* ------------------- LOCAL FUNCTIONS -------------------- */

/* roughly check network format, detailed check is done in with_network() 
 * network str has to have "prefix/prefix-length" format 
 */
static int
is_net( str )
  char *str;
{
  if ( !str || !*str) return FALSE;

  if ( strchr(str, '/'))
  {
    return TRUE;
  }
  return FALSE;
}

/* domain str has to have "XX.XXX" format */
/* what about second level domain */
static int
is_domain( str )
  char *str;
{
  if (! str || !*str) return FALSE;

  if ( strchr(str, '.') 
        || strSTR("EDU GOV COM NET ORG", str) 
    || is_country_code(str) 
     )
  { 
    return TRUE;
  }

  return FALSE;
}


/* hierarchical_value_domain: This function parses a domain
   hierarchical value */
static int
hierarchical_value_domain(value, hvalue)
  char *value;
  char *hvalue;
{
  char *p;

  if (!value || !*value ||
      !hvalue)
  {
    return(FALSE);
  }

  /* Check top level domain */
  if ((p = strrchr(value, '.')) != NULL)
  {
    p++;
  }
  else
  {
    p = value;
  }
  if (!(strlen(p) == 3 && strSTR("EDU GOV COM NET ORG MIL INT", p)) &&
      !(strlen(p) == 2))
  {
    return(FALSE);
  }

  /* Parse domain */
  if ((p = strrchr(value, '@')) != NULL)
  {
    p++;
    strcpy(hvalue, p);
  }
  else
  {
    strcpy(hvalue, value);
  }

  return(TRUE);
}


/* hierarchical_value_network: This function parses a network
   hierarchical value in prefix/prefix length format.  Note that is
   repeats some of the same logic from the ip_network routines, but
   this is trying to discover a (possibly) embedded instance. */
static int
hierarchical_value_network(value, hvalue)
  char *value;
  char *hvalue;
{
  struct netinfo value_info;

  if (NOT_STR_EXISTS(value) || !hvalue)
  {
    return FALSE;
  }

  if ( ! get_network_prefix_and_len( value, &value_info ) )
  {
    return(FALSE);
  }

  /* prefix/prefix length format */
  write_network( hvalue, &value_info );

  return(TRUE);
}


/* within_domain: This function checks if a subdomain is within
   a domain */
static int
within_domain(subdomain, domain)
  char *subdomain;
  char *domain;
{
  int    rval = FALSE;
  static regexp *prog = NULL;
  char   *subdomain_str;
  char   *domain_str;

  if (!subdomain || !*subdomain ||
      !domain    || !*domain)
  {
    return(rval);
  }
 
  /* Check domain format */
  if (!prog)
  {
    prog = regcomp(DOMAIN_REGEXP);
  }
  if (!regexec(prog, domain))
  {
    return(rval);
  }

  /* Check if a subdomain is within a domain */
  subdomain_str = NEW_STRING(subdomain);
  domain_str    = NEW_STRING(domain);

  strrev(subdomain_str);
  strrev(domain_str);

  if (STRN_EQ(subdomain_str, domain_str, strlen(domain_str)) ||
      STR_EQ(domain_str, "."))
  {
    rval = TRUE;
  }

  free(subdomain_str);
  free(domain_str);
  return(rval);
}


/* within_network: This function checks if a subnetwork is
   within a network */
static int
within_network(subnetwork, network)
  char *subnetwork;
  char *network;
{
  int           rval            = FALSE;
  static regexp *prog           = NULL;
  struct netinfo subnetwork_info;
  struct netinfo network_info;
  
  if (!subnetwork || !*subnetwork ||
      !network    || !*network)
  {
    return(rval);
  }
 
  /* Check network format */
  if (!prog)
  {
    prog = regcomp(NETWORK_REGEXP);
  }
  
  if (!regexec(prog, network))
  {
    return(rval);
  }

  /* Check if a subnetwork is within a network */

  if ( ! get_network_prefix_and_len( subnetwork, &subnetwork_info ) )
  {
    return(rval);
  }

  if ( ! get_network_prefix_and_len(network, &network_info ) )
  {
    return(rval);
  }
  
  mask_addr_to_len( &subnetwork_info, network_info.masklen );
  if ( ! compare_addr( &subnetwork_info, &network_info ) )
  {
    rval = TRUE;
  }

  return(rval);
}


/* get_up_referral: This function gets punt referrals to the
   root RWhois server */
static int
get_up_referral(referral_list)
  dl_list_type *referral_list;
{
  FILE            *fp;
  char            *punt_file;
  char            line[MAX_LINE];
  referral_struct *referral;
 
  if (!referral_list)
  {
    return(FALSE);
  }

  /* No punt referrals if root server */
  if (is_root_server())
  {
    return(FALSE);
  }

  /* Read the punt file.  There can be multiple referral entries in
     the punt file */

  punt_file = get_punt_file();
  if ((fp = fopen(punt_file, "r")) == NULL)
  {
    log(L_LOG_ERR, REFERRAL, "could not open punt file '%s'", punt_file);
    return(FALSE);
  }
 
  bzero((char *) line, MAX_LINE);
  while (readline(fp, line, MAX_LINE) != NULL)
  {
    if (line[0] != '\0' && line[0] != '#')
    {
      referral          = xcalloc(1, sizeof(*referral));
      referral->to      = NEW_STRING(line);
      referral->type    = UP_HIERARCHICAL;
      referral->aa_name = NULL;
      
      dl_list_append(referral_list, referral);
    }
    bzero((char *) line, MAX_LINE);
  }

  fclose(fp);

  if (!dl_list_empty(referral_list))
  {
    return(TRUE);
  }

  return(FALSE);
}


/* get_down_referral: This function gets link referrals to a
   referred authority area */ 
static int
get_down_referral(hvalue, htype, aa_name, referral_list)
  char         *hvalue;
  int          htype;
  char         *aa_name;
  dl_list_type *referral_list;
{
  query_struct      *query;
  dl_list_type      record_list;
  record_struct     *record;
  dl_list_type      *pair_list;
  av_pair_struct    *pair;
  referral_struct   *referral;
  int               not_done;
  ret_code_type     ret_code;
  char              *referred_aa_name = NULL;
  
  if (!hvalue  || !*hvalue  ||
      !aa_name || !*aa_name ||
      !referral_list)
  {
    return(TRUE);
  }

  while (TRUE)
  {
    /* Search referral records in the authority area for
       Referred-Auth-Area attribute equal to hierarchical
       value */
    query = xcalloc(1, sizeof(*query));
    
    if (!build_referral_query(query, hvalue, aa_name))
    {
      break;
    }

    dl_list_default(&record_list, FALSE, destroy_record_data);

    search(query, &record_list, 1, &ret_code);

    destroy_query(query);
    
    if (!dl_list_empty(&record_list))
    {
      dl_list_first(&record_list);
      record    = dl_list_value(&record_list);

      /* get the auth-area name from the "referred-auth-area" attribute */
      pair = find_attr_in_record_by_name(record, "Referred-Auth-Area");
      if (pair && STR_EXISTS((char *)pair->value))
      {
        referred_aa_name = (char *)pair->value;
      }

      /* for each "Referral" attribute, generate a referral structure */
      pair_list = &(record->av_pair_list);
      if (!dl_list_empty(pair_list))
      {
        not_done = dl_list_first(pair_list);
        while (not_done)
        {
          pair = dl_list_value(pair_list);
          if (STR_EQ(pair->attr->name, "Referral"))
          {
            referral          = xcalloc(1, sizeof(*referral));
            referral->to      = NEW_STRING(pair->value);
            referral->aa_name = NEW_STRING(referred_aa_name);
            referral->type    = DOWN_HIERARCHICAL;
            
            dl_list_append(referral_list, referral);
          }
          not_done = dl_list_next(pair_list);
        }
      }
    }

    dl_list_destroy(&record_list);

    if (!dl_list_empty(referral_list))
    {
      return(TRUE);
    }

    /* If search failed, reduce hierarchical value.  If
       hierarchical value still within the authority area,
       search again */
    if (htype == NETWORK)
    {
      /* note that for networks, if the referred-auth-area attribute
         was CIDR-indexed, reduction will undoubtedly not be necessary */
      if (!reduce_network(hvalue))
      {
        break;
      }
    }
    else if (htype == DOMAIN)
    {
      if (!reduce_domain(hvalue))
      {
        break;
      }
    }
    if (!hierarchical_value_within_aa(hvalue, htype, aa_name))
    {
       break;
    }
  } /* while */

  return(FALSE);
}


/* reduce_domain: This function reduces a domain */
static int
reduce_domain(domain)
  char *domain;
{
  int  rval = FALSE;
  char *p;

  if (!domain || !*domain)
  {
    return(rval);
  }
 
  /* Truncate leftmost label-dot */ 
  strrev(domain);
  if ((p = strrchr(domain, '.')) != NULL)
  {
    *p = '\0';
    rval = TRUE;
  }
  strrev(domain);

  return(rval);
}

/* reduce_network: This function reduces a network */
static int
reduce_network(network)
  char *network;
{
  struct netinfo ni;
 
  if (NOT_STR_EXISTS(network))
  {
    return(FALSE);
  }

  /* Get prefix, prefix length, and mask */
  if ( ! get_network_prefix_and_len( network, &ni ) )
  {
    return(FALSE);
  }

  /* reduce! */
  ni.masklen--;
  
  /* Left-shift mask by one bit to get the new prefix */
  mask_addr_to_len( &ni, ni.masklen );

  /* Quad-octet prefix/prefix length format */
  write_network( network, &ni );

  return(TRUE);
}


static int
build_referral_query(query, search_value, aa_name)
  query_struct *query;
  char *search_value;
  char *aa_name;
{
  char query_str[MAX_LINE];

  if (!query || NOT_STR_EXISTS(search_value))
  {
    log(L_LOG_ERR, REFERRAL, "build_referral_query: null data detected");
    return FALSE;
  }

  sprintf(query_str, "referral Referred-Auth-Area=%s", search_value);

  if (!parse_query(query_str, query))
  {
    log(L_LOG_ERR, REFERRAL, "referral query failed to parse: %s",
        query_str);
    return FALSE;
  }

  if (STR_EXISTS(aa_name))
  {
    query->auth_area_name = xstrdup(aa_name);
  }

  return TRUE;
}

static void
print_referral(referral_to, aa_name)
  char *referral_to;
  char *aa_name;
{

  if (NOT_STR_EXISTS(referral_to))
  {
    return;
  }
  
  trim(referral_to);
  strip_trailing(referral_to, '/');
  
  if (strSTR(referral_to, "auth-area=") ||
      NOT_STR_EXISTS(aa_name))
  {
    print_response(RESP_REFERRAL, "%s", referral_to);
  }
  else
  {
    print_response(RESP_REFERRAL, "%s/auth-area=%s", referral_to, aa_name);
  }
}

/* print_referral_list: This function prints a referral list */
static void
print_referral_list(referral_list)
  dl_list_type *referral_list;
{
  int             not_done;
  referral_struct *referral;

  if (!referral_list)
  {
    return;
  }

  if (!dl_list_empty(referral_list))
  {
    not_done = dl_list_first(referral_list);
    while (not_done)
    {
      referral = dl_list_value(referral_list);
      print_referral(referral->to, referral->aa_name);
      not_done = dl_list_next(referral_list);
    }
  }
}


/* destroy_referral_list: This function frees a referral list */
static void
destroy_referral_list(referral_list)
  dl_list_type *referral_list;
{
  if (!referral_list)
  {
    return;
  }

  dl_list_destroy(referral_list);
}


/* destroy_referral_data: This function frees a referral structure */
static int
destroy_referral_data(referral)
  referral_struct *referral;
{
  if (!referral)
  {
    return(TRUE);
  }

  if (referral->to)
  {
    free(referral->to);
  }

  if (referral->aa_name)
  {
    free(referral->aa_name);
  }
  
  free(referral);

  return(TRUE);
}


/* ------------------- PUBLIC FUNCTIONS ------------------- */


/* refer_query: This function refers a query to another RWhois
   server if this server can not resolve the query */
int
refer_query(query)
  query_struct *query;
{
  query_term_struct *ver;
  query_term_struct *hor;
  dl_list_type      referral_list;
  int               rval            = FALSE;
 
  if (!query || !(query->query_tree))
  {
    return(rval);
  }

  dl_list_default(&referral_list, FALSE, destroy_referral_data);

  /* Traverse the query tree to get referral for a particular
     query term.  Break the loop on the first hit. */
  hor = query->query_tree;
  while (hor)
  {
    ver = hor;
    while (ver)
    {
      if (refer_query_term(ver, &referral_list))
      {
        rval = TRUE;
        break;
      }
      ver = ver->and_list;
    }
    hor = hor->or_list;
  }

  /* Print referral list */
  if (rval)
  {
    print_referral_list(&referral_list);
  }

  destroy_referral_list(&referral_list);

  return(rval);
}


/* refer_query_term:  This function refers a query term */
int
refer_query_term(query_term, referral_list)
  query_term_struct *query_term;
  dl_list_type      *referral_list;
{
  dl_list_type     *auth_area_list    = NULL;
  auth_area_struct *auth_area;
  char             hvalue[MAX_LINE];
  char             *tmp_hvalue;
  int              htype;
  int              not_done;
  int              within_an_aa = FALSE;
  int              found_referral = FALSE;
  
  if (!query_term || !referral_list)
  {
    return(FALSE);
  }
 
  /* Parse hierarchical value from the search value in the query term */
  if (!parse_hierarchical_value(query_term->search_value, hvalue, &htype))
  {
    return(FALSE);
  }

  /* Get authority area list */
  auth_area_list = get_auth_area_list();
  if (!auth_area_list)
  {
    return(FALSE);
  }
 
  /* If hierarchical value within a particular authority area, get
     link referral. */
  not_done = dl_list_first(auth_area_list);
  while (not_done)
  {
    auth_area = dl_list_value(auth_area_list);
    if (hierarchical_value_within_aa(hvalue, htype, auth_area->name))
    {
      within_an_aa = TRUE;
      
      /* make sure that the authority area even has a referral class.
         otherwise, we may get a bogus "Invalid Query Syntax" from the
         generated referral query. */
      if (!aa_has_referrals(auth_area)) break;
      
      /* keep the hvalue from getting trashed */
      tmp_hvalue = xstrdup(hvalue);
      if (get_down_referral(tmp_hvalue, htype, auth_area->name, referral_list))
      {
        found_referral = TRUE;
      }
      free(tmp_hvalue);
    }
    not_done = dl_list_next(auth_area_list);
  }

  if (found_referral) { return TRUE; }
  if (!found_referral && within_an_aa) { return(FALSE); }
  
  /* Else, get punt referral */
  if (get_up_referral(referral_list))
  {
    return(TRUE);
  }

  return(FALSE);
}


/* parse_hierarchical_value: This function parses hierarchical value
   from the search value in a query term */
int
parse_hierarchical_value(value, hvalue, htype)
  char *value;
  char *hvalue;
  int  *htype;
{
  int    rval = FALSE;
  static regexp *net_prog   = NULL;
  static regexp *dom_prog   = NULL;
  static regexp *email_prog = NULL;

  if (NOT_STR_EXISTS(value) || !hvalue || !htype)
  {
    return(rval);
  }

  /* Apply network, domain, and email regular expressions to
     the search value in the given order */
  if (!net_prog)
  {
    net_prog = regcomp(NETWORK_REGEXP);
  }

  if (regexec(net_prog, value))
  {
    *htype = NETWORK;
  }
  else
  {
    if (!dom_prog)
    {
      dom_prog = regcomp(DOMAIN_REGEXP);
    }
    if (regexec(dom_prog, value))
    {
      *htype = DOMAIN; 
    }
    else
    {
      if (!email_prog)
      {
        email_prog = regcomp(EMAIL_REGEXP);
      }
      if (regexec(email_prog, value))
      {
        *htype = DOMAIN; 
      }
      else
      {
        return(rval);
      }
    }
  }

  /* Parse network or domain hierarchical value */
  if (*htype == NETWORK)
  {
    if (hierarchical_value_network(value, hvalue))
    {
      rval = TRUE;
    }
  }
  else if (*htype == DOMAIN)
  {
    if (hierarchical_value_domain(value, hvalue))
    {
      rval = TRUE;
    }
  }

  return(rval);
}


/* hierarchical_value_within_aa: This function checks if a
   hierarchical value is within an authority area */
int
hierarchical_value_within_aa(hvalue, htype, aa_name)
  char *hvalue;
  int  htype;
  char *aa_name;
{
  if (!hvalue  || !*hvalue ||
      !aa_name || !*aa_name)
  {
    return(FALSE);
  }

  /* Check if a hierarchical value is within a domain or a network
     authority area */
  if (htype == NETWORK)
  {
    if (within_network(hvalue, aa_name))
    {
      return(TRUE);
    }
  }
  else if (htype == DOMAIN)
  {
    if (within_domain(hvalue, aa_name))
    {
      return(TRUE);
    }
  }

  return(FALSE);
}


/* referral_rec_check: referral record checking routine,         */
/*   assume that the record has been passed check_record() check */
/*   here we only check the specific referral_auth_area attribute*/

int
referral_rec_check( ref_rec )
  record_struct *ref_rec; 
{
  int           not_done;
  av_pair_struct    *av;
  dl_list_type      *av_pair_list;

  if (! ref_rec ) return FALSE;
   
  av_pair_list = &(ref_rec->av_pair_list);
 
  not_done = dl_list_first(av_pair_list);
 
  while (not_done)
  {
    av = dl_list_value(av_pair_list);
 
    if (!av || !av->attr)
    {
      return FALSE;
    }
 
    /* find attribute: Referred-Auth-Area */
    if (STR_EQ(av->attr->name, "Referred-Auth-Area") )
    {
      if (! av->value )
      {
        print_error(INVALID_ATTR_SYNTAX, "attribute missing value");
        return FALSE;
      }
      /* ref_rec->auth_area->name should be the same as 
          av->attr->value (where av->attr->name: Auth-Area) ? */
      if (! ref_rec->auth_area)
      {
    return FALSE;
      }
      if ( is_net((char *) av->value))
      {
        if ( within_network( (char *) av->value, ref_rec->auth_area->name))
        {
          return TRUE;
        }
        log(L_LOG_ERR, REFERRAL, "referral '%s' out ouf auth_area '%s'", 
            (char *) av->value, ref_rec->auth_area->name );
        return FALSE;
      }
      else if ( is_domain((char *) av->value))
      {
        if (within_domain( (char *) av->value, ref_rec->auth_area->name) )
        {
           return TRUE;
        }
        log(L_LOG_ERR, REFERRAL, "referral '%s' out ouf auth_area '%s'", 
            (char *) av->value, ref_rec->auth_area->name );
        return FALSE;       
      }
      else
      {
         return FALSE;
      }
    } /* if */
  } /* while */

  log(L_LOG_ERR, REFERRAL,
      "attribute 'Referred-Auth-Area' is required in referral record"); 
  return FALSE;

}

static int
aa_has_referrals(aa)
  auth_area_struct *aa;
{
  class_ref_struct     *c_ref;

  /* for now, because of the way the referral query is generated, we
     don't care if *this* auth_area has a referral class, just that
     there is a referral class defined somewhere. */

  log(L_LOG_WARNING, REFERRAL, "looking for a referral class");
  c_ref = find_global_class_by_name("Referral");
  if (c_ref) {
    log(L_LOG_WARNING, REFERRAL, "found a referral class somewhere");
    return TRUE;
  }
  
  log(L_LOG_WARNING, REFERRAL, "no referral class found");
  return FALSE;
}
