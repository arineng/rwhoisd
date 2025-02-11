/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "auth_area.h"

#include "attributes.h"
#include "common_regexps.h"
#include "compat.h"
#include "conf.h"
#include "defines.h"
#include "dl_list.h"
#include "fileutils.h"
#include "ip_network.h"
#include "log.h"
#include "main_config.h"
#include "misc.h"
#include "schema.h"
#include "strutil.h"

/* local definations */
#define DEFAULT_ATTRIB_DIR         "attribute_defs"
#define DEFAULT_DATA_DIR           "data"
#define DEFAULT_SCHEMA_FILE        "schema"
#define DEFAULT_SOA_FILE           "soa"
#define DEFAULT_HOSTMASTER         "hostmaster"
#define DEFAULT_REFRESH_INTERVAL   3600
#define DEFAULT_INCREMENT_INTERVAL 1800
#define DEFAULT_RETRY_INTERVAL     60
#define DEFAULT_TIME_TO_LIVE       86400

static int check_soa PROTO((auth_area_struct *aa));

static int same_auth_area PROTO((auth_area_struct *aa,
                                 auth_area_struct *bb));

static int write_new_soa_file PROTO((char *file, char *suffix,
                                     auth_area_struct *aa,
                                     dl_list_type     *paths_list));

static int write_server_list PROTO((FILE         *fp,
                                    char         *type,
                                    dl_list_type *serv_list));

static int write_guardian_list PROTO((FILE *fp, dl_list_type *guard_list));

static int write_auth_area PROTO((char             *suffix,
                                  auth_area_struct *aa,
                                  dl_list_type     *paths_list));


static char *get_server_hostaddr PROTO((server_struct *serv));

static int count_server_entries PROTO((dl_list_type *servlst,
                                       server_struct *serv));

static int verify_server_data PROTO((server_struct *server, char *aa_name));

static int verify_server_list PROTO((auth_area_struct *aa, char *list_type));

static int count_guardian_entries PROTO((dl_list_type *guard_list,
                                         char         *guard_str));

static int verify_guardian_list PROTO((auth_area_struct *aa));

static int verify_auth_area PROTO((auth_area_struct *aa));

/* local statics */

static dl_list_type *auth_area_list = NULL;


/* ------------------ Local Functions ------------------ */


/* check_soa: given an auth-area record, check for null or illegal
   values.  If found, log errors and return FALSE */
static int
check_soa(aa)
  auth_area_struct *aa;
{
  char hostname[MAX_LINE];
  char port[MAX_LINE];

  if (!aa || NOT_STR_EXISTS(aa->name))
  {
    log(L_LOG_ERR, CONFIG, "SOA: null record");
    return FALSE;
  }

  if (aa->refresh_interval == 0)
  {
    log(L_LOG_ERR, CONFIG, "SOA: Refresh-Interval required for '%s'",
        aa->name);
    return FALSE;
  }
  if (aa->increment_interval == 0)
  {
    log(L_LOG_ERR, CONFIG, "SOA: Increment-Interval required for '%s'",
        aa->name);
    return FALSE;
  }
  if (aa->retry_interval == 0)
  {
    log(L_LOG_ERR, CONFIG, "SOA: Retry-Interval required for '%s'",
        aa->name);
    return FALSE;
  }
  if (aa->time_to_live == 0)
  {
    log(L_LOG_ERR, CONFIG, "SOA: Time-To-Live required for '%s'",
        aa->name);
    return FALSE;
  }
  if (NOT_STR_EXISTS(aa->primary_server))
  {
    log(L_LOG_ERR, CONFIG, "SOA: Primary-Server required for '%s'",
        aa->name);
    return FALSE;
  }

  /* primary server syntax check, format:  hostname:port */
  if (!parse_line(aa->primary_server, hostname, port))
  {
    log(L_LOG_ERR, CONFIG,
        "SOA: Primary-Server for '%s' has incorrect format: %s",
        aa->name,
        aa->primary_server);
    return FALSE;
  }
  if (!is_valid_hostname(hostname))
  {
    log(L_LOG_ERR, CONFIG,
        "SOA: Primary-Server for '%s' has incorrect hostname: %s",
        aa->name,
        hostname);
    return FALSE;
  }
  if (!is_valid_port(port))
  {
    log(L_LOG_ERR, CONFIG,
        "SOA: Primary-Server '%s' for '%s' has incorrect port: %s",
        aa->name,
        hostname,
        port);
    return FALSE;
  }

  if (NOT_STR_EXISTS(aa->hostmaster))
  {
    log(L_LOG_ERR, CONFIG, "SOA: Hostmaster required for '%s'",
        aa->name);
    return FALSE;
  }
  if (NOT_STR_EXISTS(aa->serial_no))
  {
    log(L_LOG_ERR, CONFIG, "SOA: Serial-Number required for '%s'",
        aa->name);
    return FALSE;
  }

  return TRUE;
}

/* compare the two auth-areas: just compare the name and the type */
static int
same_auth_area(aa,  bb)
  auth_area_struct *aa;
  auth_area_struct *bb;
{

  if (!aa || !bb) return FALSE;

  /* compare auth_area name and type */
  if (aa->type == bb->type && STR_EQ(aa->name, bb->name))
  {
    return TRUE;
  }

  return FALSE;
}

/* write authority area soa file. The optional suffix is used to create
   a new temporary soa file name. If file was created on disk,
   add the file name to the paths_list. */
static int
write_new_soa_file(file, suffix, aa, paths_list)
  char *file;
  char *suffix;
  auth_area_struct  *aa;
  dl_list_type *paths_list;
{
  FILE *fp = NULL;
  char new_file[MAX_FILE];

  if (!file || !*file || !aa || !paths_list) return FALSE;

  bzero(new_file, sizeof(new_file));
  strncpy(new_file, file, sizeof(new_file)-1);
  strncat(new_file, suffix, sizeof(new_file)-1);

  if ((fp = open_file_to_write(new_file, 60, paths_list)) == NULL)
  {
    log(L_LOG_ERR, CONFIG, "could not open soa file '%s': %s",
        new_file, strerror(errno));
    return FALSE;
  }

  fprintf(fp, "%s: %s\n", SOA_SERIAL_NUMBER, SAFE_STR(aa->serial_no, ""));
  fprintf(fp, "%s: %ld\n", SOA_REFRESH_INTERVAL, aa->refresh_interval);
  fprintf(fp, "%s: %ld\n", SOA_INCREMENT_INTERVAL, aa->increment_interval);
  fprintf(fp, "%s: %ld\n", SOA_RETRY_INTERVAL, aa->retry_interval);
  fprintf(fp, "%s: %ld\n", SOA_TIME_TO_LIVE, aa->time_to_live);
  fprintf(fp, "%s: %s\n", SOA_PRIMARY_SERVER,
                          SAFE_STR(aa->primary_server, ""));
  fprintf(fp, "%s: %s\n", SOA_HOSTMASTER, SAFE_STR(aa->hostmaster, ""));

  release_file_lock(new_file, fp);

  dl_list_append(paths_list, xstrdup(new_file));

  return TRUE;
}

/* writes master/slave server entries to rwhois auth-area file if the list
   is not empty. */
static int
write_server_list(fp, type, serv_list)
  FILE         *fp;
  char         *type;
  dl_list_type *serv_list;
{
  int           not_done;
  server_struct *serv;

  if (!fp || !type || !*type) return FALSE;

  if (dl_list_empty(serv_list))
  {
    /* list is empty */
    return TRUE;
  }

  not_done = dl_list_first(serv_list);
  while (not_done)
  {
    serv = dl_list_value(serv_list);

    /* print server list information */
    fprintf(fp, "%s: %s %d\n", type, get_server_hostaddr(serv), serv->port);

    not_done = dl_list_next(serv_list);
  }
  return TRUE;
}

/* write guardian entries to the rwhois auth-area file, if the
   list is not empty */
static int
write_guardian_list(fp, guard_list)
  FILE         *fp;
  dl_list_type *guard_list;
{
  int  not_done;
  char *guard_item;

  if (!fp) return FALSE;

  if (dl_list_empty(guard_list))
  {
    return TRUE;
  }

  not_done = dl_list_first(guard_list);
  while (not_done)
  {
    guard_item = dl_list_value(guard_list);

    fprintf(fp, "%s: %s\n", AA_GUARDIAN_ARG, guard_item);

    not_done = dl_list_next(guard_list);
  }
  return TRUE;
}

/* creates authority area directory, its data and attribute-defs directories,
   and calls to write the auhority area schema, and soa file. */
static int
write_auth_area(suffix, aa, paths_list)
  char             *suffix;
  auth_area_struct *aa;
  dl_list_type     *paths_list;
{
  char aa_dir[MAX_FILE];
  char attr_dir[MAX_FILE];

  if (!aa || !paths_list) return FALSE;

  if (!check_aa_syntax(aa->name, aa_dir))
  {
    log(L_LOG_ERR, CONFIG, "'%s' is not a valid authority area syntax",
        SAFE_STR(aa->name, ""));
    return FALSE;
  }

  /* create authority area directory */
  if (!directory_exists(aa_dir))
  {
    if (!make_config_dir(aa_dir, 0755, paths_list))
    {
      log(L_LOG_ERR, CONFIG,
          "could not create auth-area directory '%s': %s",
          SAFE_STR(aa_dir, ""), strerror(errno));
      return FALSE;
    }
  }

  /* Secondary server does not need anything from here on */
  if (aa->type == AUTH_AREA_PRIMARY)
  {
    /* create authority area data directory */
    if (!directory_exists(aa->data_dir))
    {
      if (!make_config_dir(aa->data_dir, 0755, paths_list))
      {
        log(L_LOG_ERR, CONFIG,
            "could not create auth-area data directory '%s': %s",
            SAFE_STR(aa->data_dir, ""), strerror(errno));
        return FALSE;
      }
    }

    /* create authority area attribute definitions directory */
    bzero(attr_dir, sizeof(attr_dir));
    strncat(attr_dir, aa_dir, sizeof(attr_dir)-1);
    strncat(attr_dir, "/", sizeof(attr_dir)-1);
    strncat(attr_dir, DEFAULT_ATTRIB_DIR, sizeof(attr_dir)-1);
    if (!directory_exists(attr_dir))
    {
      if (!make_config_dir(attr_dir, 0755, paths_list))
      {
        log(L_LOG_ERR, CONFIG,
            "could not create auth-area attribute-defs directory '%s': %s",
            SAFE_STR(attr_dir, ""), strerror(errno));
        return FALSE;
      }
    }

    /* write soa file - under authority area */
    if (!write_new_soa_file(aa->soa_file, suffix, aa, paths_list))
    {
      log(L_LOG_ERR, CONFIG, "error in writing soa file '%s'",
          SAFE_STR(aa->soa_file, ""));
      return FALSE;
    }

    /* write schema file - under authority area */
    if (!write_schema_file(aa->schema_file, suffix, aa, paths_list))
    {
      log(L_LOG_ERR, CONFIG, "error in writing schema file '%s'",
          SAFE_STR(aa->schema_file, ""));
      return FALSE;
    }
  }

  return TRUE;
}

/* server info can be defined by its host name or ip address. This
   function returns whichever(hostname/ip-addr) is defined for the
   server. */
static char *
get_server_hostaddr(serv)
  server_struct *serv;
{
  if (STR_EXISTS(serv->name)) return( serv->name );

  return( SAFE_STR(serv->addr, "") );
}

/* count the number of times a given server occurs in the server
   list. */
static int
count_server_entries(servlst, serv)
  dl_list_type  *servlst;
  server_struct *serv;
{
  int           not_done;
  int           n_serv;
  dl_node_type  *orig_posn;
  server_struct *serv_item;

  if (!serv) return( 0 );

  if (dl_list_empty(servlst))
  {
    return( 0 );
  }

  /* save the current position */
  orig_posn = dl_list_get_pos(servlst);

  n_serv   = 0;
  not_done = dl_list_first(servlst);

  while (not_done)
  {
    serv_item = dl_list_value(servlst);
    if ( STR_EQ(get_server_hostaddr(serv_item), get_server_hostaddr(serv)) &&
         (serv_item->port == serv->port) )
    {
      n_serv++;
    }
    not_done = dl_list_next(servlst);
  }

  /* restore the saved position */
  dl_list_put_pos(servlst, orig_posn);

  return( n_serv );
}

/* verifies the contents of master/slave server info structure. */
static int
verify_server_data(server, aa_name)
  server_struct *server;
  char          *aa_name;
{
  int ret;

  if (!server || !aa_name || !*aa_name) return FALSE;

  if ((ret = examin_hostname(get_server_hostaddr(server))))
  {
    log(L_LOG_ERR, CONFIG,
      "'%s' authority area master/slave server hostname not valid (%s:%d)",
      aa_name, get_server_hostaddr(server), server->port,
      examin_error_string(ret));
    return FALSE;
  }
  if (server->port < 1)
  {
    log(L_LOG_ERR, CONFIG,
      "'%s' authority area master/slave server (%s:%d) port: %s",
      aa_name, get_server_hostaddr(server), server->port,
      examin_error_string(ERW_NUMVAL));
  }

  return TRUE;
}

/* verify the master/slave server list. Make sure a secondary authority
   area does not have master list empty, and make sure a primary does
   does not have any master servers defined. */
static int
verify_server_list(aa, list_type)
  auth_area_struct *aa;
  char             *list_type;
{
  int           n;
  int           not_done;
  server_struct *serv;
  dl_list_type  *servlst;

  if (!aa || !list_type) return FALSE;

  n = 0;

  if (STR_EQ(list_type, AA_MASTER))
  {
    servlst = aa->master;
  }
  else if (STR_EQ(list_type, AA_SLAVE))
  {
    servlst = aa->slave;
  }
  else
  {
    return FALSE;
  }

  not_done = dl_list_first(servlst);
  while (not_done)
  {
    serv = dl_list_value(servlst);

    if (!verify_server_data(serv, aa->name))
    {
      return FALSE;
    }
    if (count_server_entries(servlst, serv) > 1)
    {
      log(L_LOG_ERR, CONFIG,
        "duplicate entries in '%s' server list of '%s' authority area: %s:%d",
          list_type, aa->name, get_server_hostaddr(serv), serv->port);
      return FALSE;
    }
    n++;

    not_done = dl_list_next(servlst);
  }

  if (aa->type == AUTH_AREA_PRIMARY && n > 0 && STR_EQ(list_type, AA_MASTER))
  {
    log(L_LOG_ERR, CONFIG,
        "Master server list must be empty for primary authority area: %s",
        aa->name);
    return FALSE;
  }
  if (aa->type == AUTH_AREA_SECONDARY)
  {
    if (n < 1 && STR_EQ(list_type, AA_MASTER))
    {
      log(L_LOG_ERR, CONFIG,
          "Secondary authority area '%s' must have atleast one master server",
          aa->name, n);
      return FALSE;
    }
    if (n > 0 && STR_EQ(list_type, AA_SLAVE))
    {
      log(L_LOG_ERR, CONFIG,
          "Slave server list must be empty for secondary authority area: %s",
          aa->name);
      return FALSE;
    }
  }

  return TRUE;
}

/* count the number of times a guardian string occurs in the guardian
   list of the authority area. */
static int
count_guardian_entries(guard_list, guard_str)
  dl_list_type *guard_list;
  char         *guard_str;
{
  int          not_done;
  int          n;
  char         *guard_item;
  dl_node_type *orig_posn;

  if (!guard_str) return( 0 );

  if (dl_list_empty(guard_list)) return( 0 );

  /* save the current position */
  orig_posn = dl_list_get_pos(guard_list);

  n = 0;
  not_done = dl_list_first(guard_list);
  while (not_done)
  {
    guard_item = dl_list_value(guard_list);
    if (STR_EQ(guard_item, guard_str))
    {
      n++;
    }
    not_done = dl_list_next(guard_list);
  }

  /* restore the saved position */
  dl_list_put_pos(guard_list, orig_posn);

  return( n );
}

/* verify the contents of guardian list of an authority area. Check
   for any duplicates. */
static int
verify_guardian_list(aa)
  auth_area_struct *aa;
{
  int  not_done;
  int  ret;
  char *guard_item;

  if (!aa) return FALSE;

  if (dl_list_empty(aa->guardian_list))
  {
    return TRUE;
  }

  not_done = dl_list_first(aa->guardian_list);
  while (not_done)
  {
    guard_item = dl_list_value(aa->guardian_list);

    if ((ret = examin_guardian_item(guard_item)))
    {
      log(L_LOG_ERR, CONFIG,
        "invalid '%s' authority area guardian item '%s': %s",
        aa->name, guard_item, examin_error_string(ret));
      return FALSE;
    }
    if (count_guardian_entries(aa->guardian_list, guard_item) > 1)
    {
      log(L_LOG_ERR, CONFIG,
        "duplicate entries in the guardian list of '%s' authority area: %s",
        aa->name, guard_item);
      return FALSE;
    }

    not_done = dl_list_next(aa->guardian_list);
  }

  return TRUE;
}

/* verify the complete authority area. Verify path names, value ranges,
   schema, server and guardian lists etc.. Take into consideration
   the authority area type (primary/secondary). */
static int
verify_auth_area(aa)
  auth_area_struct *aa;
{
  int  ret;
  char directory[MAX_FILE];

  /* verify schema, soa, class list, attribute lists */
  if (!aa)
  {
    log(L_LOG_ERR, CONFIG, "authority area not defined - internal error");
    return FALSE;
  }

  if (!check_aa_syntax(aa->name, directory))
  {
    log(L_LOG_ERR, CONFIG, "'%s' is not a valid authority area syntax",
        aa->name );
    return FALSE;
  }
  if (aa->type == AUTH_AREA_PRIMARY)
  {
    if ((ret = examin_aa_data_dir(aa->data_dir)))
    {
      log(L_LOG_ERR, CONFIG,
          "invalid '%s' authority area data directory '%s': %s",
          aa->name, SAFE_STR(aa->data_dir, ""), examin_error_string(ret));
      return FALSE;
    }
    if ((ret = examin_aa_schema_file(aa->schema_file)))
    {
      log(L_LOG_ERR, CONFIG,
          "invalid '%s' authority area schema file name '%s': %s",
          aa->name, SAFE_STR(aa->schema_file, ""), examin_error_string(ret));
      return FALSE;
    }
    if ((ret = examin_aa_soa_file(aa->soa_file)))
    {
      log(L_LOG_ERR, CONFIG,
          "invalid '%s' authority area soa file name '%s': %s",
          aa->name, SAFE_STR(aa->soa_file, ""), examin_error_string(ret));
      return FALSE;
    }
    if ((ret = examin_primary_server_str(aa->primary_server)))
    {
      log(L_LOG_ERR, CONFIG,
          "invalid '%s' authority area primary server '%s': %s",
          aa->name, SAFE_STR(aa->primary_server, ""),
          examin_error_string(ret));
      return FALSE;
    }
    if ((ret = examin_aa_hostmaster_str(aa->hostmaster)))
    {
      log(L_LOG_ERR, CONFIG,
          "invalid '%s' authority area hostmaster address '%s': %s",
          aa->name, SAFE_STR(aa->hostmaster, ""), examin_error_string(ret));
      return FALSE;
    }
    if ((ret = examin_serial_num(aa->serial_no)))
    {
      log(L_LOG_ERR, CONFIG,
        "invalid '%s' authority area serial number '%s': %s",
          aa->name, SAFE_STR(aa->serial_no, ""), examin_error_string(ret));
      return FALSE;
    }
    if (aa->xfer_arg && *aa->xfer_arg &&
        (ret = examin_aa_xfer_arg(aa->xfer_arg)))
    {
      log(L_LOG_ERR, CONFIG,
        "invalid '%s' authority area xfer arguments '%s': %s",
          aa->name, SAFE_STR(aa->xfer_arg, ""), examin_error_string(ret));
      return FALSE;
    }
    if (aa->refresh_interval < 1)
    {
      log(L_LOG_ERR, CONFIG,
        "invalid '%s' authority area Refresh-Interval '%d': %s",
          aa->name, aa->refresh_interval, examin_error_string(ERW_NUMVAL));
      return FALSE;
    }
    if (aa->increment_interval < 1)
    {
      log(L_LOG_ERR, CONFIG,
        "invalid '%s' authority area Increment-Interval '%d': %s",
          aa->name, aa->increment_interval, examin_error_string(ERW_NUMVAL));
      return FALSE;
    }
    if (aa->retry_interval < 1)
    {
      log(L_LOG_ERR, CONFIG,
        "invalid '%s' authority area Retry-Interval '%d': %s",
          aa->name, aa->retry_interval, examin_error_string(ERW_NUMVAL));
      return FALSE;
    }
    if (aa->time_to_live < 1)
    {
      log(L_LOG_ERR, CONFIG,
        "invalid '%s' authority area Time-To-Live '%d': %s",
          aa->name, aa->time_to_live, examin_error_string(ERW_NUMVAL));
      return FALSE;
    }
  }

  if (!verify_server_list(aa, AA_MASTER))
  {
    log(L_LOG_ERR, CONFIG,
      "'%s' authority area master server list is not valid",
        aa->name);
    return FALSE;
  }

  if (!verify_server_list(aa, AA_SLAVE))
  {
    log(L_LOG_ERR, CONFIG,
      "'%s' authority area slave server list is not valid",
      aa->name);
    return FALSE;
  }

  if (!verify_guardian_list(aa))
  {
    log(L_LOG_ERR, CONFIG,
      "'%s' authority area guardian list is not valid",
      aa->name);
    return FALSE;
  }

  /* check schema for only primary auth area */
  if (aa->type == AUTH_AREA_PRIMARY)
  {
    if (!verify_schema(aa))
    {
      return FALSE;
    }
  }

  return TRUE;
}

/* ------------------ Public Functions ----------------- */

int
add_auth_area_guardian(aa, id_str)
  auth_area_struct *aa;
  char             *id_str;
{
  if (!aa || !STR_EXISTS(id_str))
  {
    return FALSE;
  }

  if (!aa->guardian_list)
  {
    aa->guardian_list = xcalloc(1, sizeof(*(aa->guardian_list)));
    dl_list_default(aa->guardian_list, TRUE, simple_destroy_data);
  }

  dl_list_append(aa->guardian_list, xstrdup(id_str));

  return TRUE;
}

/* translate_auth_area_type: given a string, translate it into one of
   the auth_area_type values */
auth_area_type
translate_auth_area_type(val)
  char  *val;
{
  if (!val) return AUTH_AREA_PRIMARY;

  if (STR_EQ(val, AA_SECONDARY) || STR_EQ(val, AA_SLAVE))
  {
    return AUTH_AREA_SECONDARY;
  }

  return AUTH_AREA_PRIMARY;
}

char *
translate_auth_area_type_str(val)
  auth_area_type    val;
{
  if (val == AUTH_AREA_PRIMARY)
  {
    return(AA_PRIMARY);
  }

  return(AA_SECONDARY);
}

/* check to see if it is a valid hostname with format:
 *  rs.internic.net  -OR- 198.41.0.21
 * return TRUE if it is valid (don't care its reachability)
 * else return FALSE;
 */
int
is_valid_hostname ( name)
  char   *name;
{
  char           *p;
  char           *op_str;
  static regexp  *host1_prog = NULL;
  static regexp  *host2_prog = NULL;
  int            status1     = FALSE;
  int            status2     = FALSE;

  if (NOT_STR_EXISTS(name)) return FALSE;

  trim(name);

  if (!host1_prog)
  {
    host1_prog = regcomp(DOMAIN_NAME_REGEXP);
  }
  if (!host2_prog)
  {
    host2_prog = regcomp(IP_ADDR_REGEXP);
  }

  status1 = regexec(host1_prog, name);
  if (!status1)
  {
    status2 = regexec(host2_prog, name);
    if (!status2)
    {
      return FALSE;
    }
  }

  op_str = NEW_STRING(name);

  /* hostname format: e.g. rs.internic.net  */
  if (status1)
  {
    p = strrchr(op_str, '.');
    p++;
    if (strlen(p) == 2 && is_country_code(p))
    {
      free(op_str);
      return TRUE;
    }
    if (strlen(p) == 3 && strSTR("EDU GOV COM NET ORG MIL INT", p))
    {
      free(op_str);
      return TRUE;
    }
    free(op_str);
    return FALSE;
  }

  if (status2)
  {
    int octs;
    int o1=0;
    int o2=0;
    int o3=0;
    int o4=0;

    /* read in octets */
    octs = sscanf(op_str, "%d.%d.%d.%d", &o1, &o2, &o3, &o4);

    if (octs <= 0) return FALSE;

    if (o1 < 0 || o1 > 255 || o2 < 0 || o2 > 255 ||
        o3 < 0 || o3 > 255 || o4 < 0 || o4 > 255)
    {
      free(op_str);
      return FALSE;
    }

    free(op_str);
    return TRUE;
  }

  return TRUE;
}

/* is_valid_port: check the port number. Return TRUE if a valid port
   number, else return FALSE */
int
is_valid_port(port)
  char  *port;
{
  char  *p;

  trim(port);

  for (p = port; *p; p++)
  {
    if (!isdigit(*p)) return FALSE;
  }

  if (atoi(port) <= 0)
  {
    return FALSE;
  }

  return TRUE;
}


/* check to see if  aa is already in aa_list */
int
is_duplicate_aa(aa, aa_list)
  auth_area_struct *aa;
  dl_list_type     *aa_list;
{
  int not_done;

  if (!aa) return FALSE;

  if (dl_list_empty(aa_list))
  {
    return FALSE;
  }

  not_done = dl_list_first(aa_list);
  while (not_done)
  {
    if (same_auth_area(dl_list_value(aa_list), aa))
    {
      return TRUE;
    }

    not_done = dl_list_next(aa_list);
  }

  return FALSE;
}


/* read_auth_areas: given an auth-area conf file name, read the
   configuration file (and associated configuration files.  Return
   FALSE if a fatal error was detected */
int
read_auth_areas(file)
  char *file;
{
  char              line[BUFSIZ];
  char              tag[MAX_TEMPLATE_DESC];
  char              datum[MAX_TEMPLATE_DESC];
  FILE             *fp                        = NULL;
  auth_area_struct *aa                        = NULL;
  int               content_flag              = FALSE;

  if ((fp = fopen(file, "r")) == NULL)
  {
    log(L_LOG_ERR, CONFIG, "cannot open file '%s': %s", file, strerror(errno));
    return FALSE;
  }

  /* free old auth area stuff, if necessary */
  if (auth_area_list)
  {
    log(L_LOG_DEBUG, CONFIG, "destroying pre-existing schema"); /* temp */
    destroy_auth_area_list();
    destroy_class_ref_list();
  }

  set_log_context(file, 0, -1);

  aa = xcalloc(1, sizeof(*aa));

  bzero(line, sizeof(line));

  while (readline(fp, line, BUFSIZ))
  {
    inc_log_context_line_num(1);

    /* commit to the list the record we just read */
    if (new_record(line))
    {
      if (!add_auth_area(aa))
      {
        destroy_auth_area_data(aa);
      }

      aa = xcalloc(1, sizeof(*aa));

      content_flag = FALSE;

      continue;
    }

    if (parse_line(line, tag, datum))
    {
      content_flag = TRUE; /* we have read and parsed something */

      if (STR_EQ(tag, AA_TYPE))
      {
        aa->type = translate_auth_area_type(datum);
      }
      else if (STR_EQ(tag, AA_NAME))
      {
        if (aa->name)
        {
          log(L_LOG_WARNING, CONFIG,
              "auth area name '%s' replaces previous value '%s' %s",
              datum, aa->name, file_context_str());
          free(aa->name);
        }
        aa->name = xstrdup(datum);
      }
      else if (STR_EQ(tag, AA_SCHEMA_FILE))
      {
        if (aa->schema_file)
        {
          log(L_LOG_WARNING, CONFIG,
        "auth area schema file '%s' (in '%s') replaces previous value '%s' %s",
              datum, SAFE_STR(aa->name, "unknown"), aa->schema_file,
              file_context_str());
          free(aa->schema_file);
        }

        if (!file_exists(datum))
        {
          if (aa->type == AUTH_AREA_PRIMARY)
          {
            log(L_LOG_ERR, CONFIG, "schema file '%s' unreadable: %s %s",
                datum, strerror(errno), file_context_str());
            destroy_auth_area_data(aa);
            fclose(fp);
            return FALSE;
          }
        }
        aa->schema_file = xstrdup(datum);
      }
      else if (STR_EQ(tag, AA_SOA_FILE))
      {
        if (aa->soa_file)
        {
          log(L_LOG_WARNING, CONFIG,
          "auth area soa file '%s' (in '%s') replaces previous value '%s' %s",
              datum, SAFE_STR(aa->name, "unknown"), aa->soa_file,
              file_context_str());
          free(aa->soa_file);
        }

        if (! file_exists(datum))
        {
          if (aa->type == AUTH_AREA_PRIMARY)
          {
            log(L_LOG_WARNING, CONFIG,
                "auth area soa file '%s' unreadable: %s %s",
                datum, strerror(errno), file_context_str());
            destroy_auth_area_data(aa);
            fclose(fp);
            return FALSE;
          }
        }

        aa->soa_file = xstrdup(datum);
      }
      else if (STR_EQ(tag, AA_DATA_DIR))
      {
        if (aa->data_dir)
        {
          log(L_LOG_WARNING, CONFIG,
           "auth area data dir '%s' (in '%s') replaces previous value '%s' %s",
              datum, SAFE_STR(aa->name, "unknown"), aa->data_dir,
              file_context_str());
          free(aa->data_dir);
        }

        if (!directory_exists(datum))
        {
          if (aa->type == AUTH_AREA_PRIMARY)
          {
            log(L_LOG_WARNING, CONFIG,
                "auth area data dir '%s' unreadable: %s %s",
                datum, strerror(errno), file_context_str());
            destroy_auth_area_data(aa);
            fclose(fp);
            return FALSE;
          }
        }

        aa->data_dir = xstrdup(datum);
      }
      else if (STR_EQ(tag, AA_MASTER))
      {
        if (!add_server(&(aa->master), datum))
        {
          destroy_auth_area_data(aa);
          fclose(fp);
          return FALSE;
        }
      }
      else if (STR_EQ(tag, AA_SLAVE))
      {
        if (!add_server(&(aa->slave), datum))
        {
          destroy_auth_area_data(aa);
          fclose(fp);
          return FALSE;
        }
      }
      else if (STR_EQ(tag, AA_XFER_ARG))
      {
        if (aa->xfer_arg)
        {
          log(L_LOG_WARNING, CONFIG,
              "auth area xfer arg '%s' replaces previous value '%s' %s",
              datum, aa->xfer_arg, file_context_str());
          free(aa->xfer_arg);
        }
        aa->xfer_arg = xstrdup(datum);
      }
      else if (STR_EQ(tag, AA_GUARDIAN_ARG))
      {
        add_auth_area_guardian(aa, datum);
      }
      else
      {
        log(L_LOG_WARNING, CONFIG,
            "tag '%s' in '%s' is unrecognized; ignoring %s",
            tag, aa->name, file_context_str());
      }
    } /* parse_line */

  } /* readline */

  /* commit last auth area; if there is no content, or the add fails,
     just free the data. */
  if (!content_flag || !add_auth_area(aa))
  {
    destroy_auth_area_data(aa);
  }

  fclose(fp);
  return TRUE;
}

/* add_auth_area: commit the auth area structure to the global list.
     Checks for illegal variable conditions first, and refuse to add
     structures that fail.  Returns TRUE on success, otherwise FALSE */
int
add_auth_area(aa)
  auth_area_struct  *aa;
{
  char               directory[MAX_FILE];
  log_context_struct local_context;

  if (!aa) return FALSE;

  /* instantiate the auth-area-list first, if necessary */
  if (!auth_area_list)
  {
    auth_area_list = xcalloc(1, sizeof(*auth_area_list));

    dl_list_default(auth_area_list, TRUE, (int(*)(void *))destroy_auth_area_data);
  }

  /* check the aa for existance, syntax, etc .. first */

  if (!aa->name)
  {
    log(L_LOG_ERR, CONFIG, "authority area missing name %s",
        file_context_str());
    return FALSE;
  }

  /* check for a duplicate auth area */
  if (is_duplicate_aa(aa, auth_area_list))
  {
    log(L_LOG_ERR, CONFIG, "authority area '%s' already exists %s",
        aa->name, file_context_str());
    return FALSE;
  }

  if (!check_aa_syntax(aa->name, directory))
  {
    log(L_LOG_ERR, CONFIG, "'%s' is not a valid authority area syntax %s",
        aa->name, file_context_str());
    return FALSE;
  }

  if (!aa->data_dir)
  {
    if (aa->type == AUTH_AREA_PRIMARY)
    {
      log(L_LOG_ERR, CONFIG, "authority area '%s' missing data directory %s",
          aa->name, file_context_str());
      return FALSE;
    }
  }

  if (!aa->schema_file)
  {
    if (aa->type == AUTH_AREA_PRIMARY)
    {
      log(L_LOG_ERR, CONFIG, "authority area '%s' missing schema file %s",
          aa->name, file_context_str());
      return FALSE;
    }
  }

  if (!aa->soa_file)
  {
    if (aa->type == AUTH_AREA_PRIMARY)
    {
      log(L_LOG_ERR, CONFIG, "authority area '%s' missing soa file %s",
          aa->name, file_context_str());
      return FALSE;
    }
  }

  /* Non-primary auth-areas get to do this stuff later */
  if (aa->type == AUTH_AREA_PRIMARY)
  {
    save_log_context(&local_context);

    /* now actually read the SOA data */
    if (!read_soa_file(aa))
    {
      return FALSE;
    }

    aa->schema = xcalloc(1, sizeof(*(aa->schema)));

    log(L_LOG_DEBUG, CONFIG, "reading schema for auth-area '%s'", aa->name);

    if (!read_schema(aa))
    {
      return FALSE;
    }

    restore_log_context(&local_context);
  }


  dl_list_append(auth_area_list, aa);

  return TRUE;
}


/* check_aa_syntax(): check auth_area syntax, also create auth_area directory.
   Return TRUE if valid auth-area else FALSE */
int
check_aa_syntax (aa_name, directory)
  char *aa_name;
  char *directory;
{
  char      *p;
  char      *op_str;
  static    regexp *prog  = NULL;

  if (!aa_name) return FALSE;

  /* root server */
  if (!strcmp(aa_name, "."))
  {
     strcpy(directory, "root");
     return TRUE;
  }

  /* check:    domain format: a.1-b.biz
   *            -OR-
   *           network format: 1234.111/156
   */
  if (!prog)
  {
    prog = regcomp(AUTH_AREA_REGEXP);
  }

  if (!regexec(prog, aa_name))
  {
    return FALSE;
  }

  strip_leading(aa_name, '.');
  strip_trailing(aa_name, '.');

  op_str = NEW_STRING(aa_name);

  /* domain format: the second level has to be:
   *  country-code  -OR-  EDU, COM, GOV, NET, ORG
   */
  if (!(p = strrchr(op_str, '/')))
  {
    /* create directory */
    strcpy (directory, aa_name);

    /* grab second level */
    if ((p = strrchr(op_str, '.')))
    {
      p++;
    }
    else
    {
      p = op_str;
    }
    if (strlen(p) == 2 && is_country_code(p))
    {
      free(op_str);
      return TRUE;
    }
    if (strlen(p) == 3 && strSTR("EDU GOV COM NET ORG INT", p))
    {
      free(op_str);
      return TRUE;
    }

    free(op_str);
    return FALSE;
  }
  else
  /* network format:
   *    Convert the IP-network to bit stream (32-bit long integer),
   *    compare the trailing number of zeros with prefix-length.
   *        127.253.252.0/22    01111111111111011111110000000000
   *                                                  ^^^^^^^^^^
   *           len = 22                               32-len=10
   */
  {
    struct netinfo prefix;

    if ( ! get_network_prefix_and_len( op_str, &prefix ) )
    {
      free(op_str);
      return FALSE;
    }

    /* default directory name for network:  net-ipaddress-length */
    sprintf( directory, "net-%s-%d", natop( &prefix ), prefix.masklen );

    free(op_str);
    return TRUE;
  } /*   */

  free(op_str);
  return TRUE;
}


/* read_soa_file: given an auth-area structure, read the SOA file
   contained within, and fill out the record.  Returns FALSE if it
   discovered something wrong. */
int
read_soa_file(aa)
  auth_area_struct  *aa;
{
  char              line[MAX_LINE + 1];
  char              tag[MAX_TEMPLATE_DESC];
  char              value[MAX_TEMPLATE_DESC];
  FILE              *fp                        = NULL;

  fp = fopen(aa->soa_file, "r");
  if (!fp)
  {
    log(L_LOG_ERR, CONFIG,
        "cannot open soa file '%s' for auth-area '%s': %s",
        aa->soa_file, aa->name,
        strerror(errno));
    return FALSE;
  }

  /* free any possible old SOA data */
  destroy_soa_in_auth_area(aa);

  set_log_context(aa->soa_file, 1, -1);

  bzero(line, sizeof(*line));

  while (readline(fp, line, MAX_LINE))
  {
    if (parse_line(line, tag, value))
    {
      if (STR_EQ(tag, SOA_REFRESH_INTERVAL))
      {
        aa->refresh_interval = atol(value);
      }
      else if (STR_EQ(tag, SOA_INCREMENT_INTERVAL))
      {
        aa->increment_interval = atol(value);
      }
      else if (STR_EQ(tag, SOA_RETRY_INTERVAL))
      {
        aa->retry_interval = atol(value);
      }
      else if (STR_EQ(tag, SOA_TIME_TO_LIVE))
      {
        aa->time_to_live = atol(value);
      }
      else if (STR_EQ(tag, SOA_PRIMARY_SERVER))
      {
        if (aa->primary_server)
        {
          log(L_LOG_WARNING, CONFIG,
   "SOA primary server '%s' replaces previous value '%s' in auth-area '%s' %s",
              value, aa->primary_server, aa->name, file_context_str());
          free(aa->primary_server);
        }
        aa->primary_server = xstrdup(value);
      }
      else if (STR_EQ(tag, SOA_HOSTMASTER))
      {
        if (aa->hostmaster)
        {
          log(L_LOG_WARNING, CONFIG,
       "SOA hostmaster '%s' replaces previous value '%s' in auth-area '%s' %s",
              value, aa->hostmaster, aa->name, file_context_str());
          free(aa->hostmaster);
        }
        aa->hostmaster = NEW_STRING(value);
      }
      else if (STR_EQ(tag, SOA_SERIAL_NUMBER))
      {
        if (aa->serial_no)
        {
          log(L_LOG_WARNING, CONFIG,
    "SOA serial number '%s' replaces previous value '%s' in auth-area '%s' %s",
              value, aa->serial_no, aa->name, file_context_str());
          free(aa->serial_no);
        }
        aa->serial_no = NEW_STRING(value);
      }
      else
      {
        log(L_LOG_WARNING, CONFIG,
            "SOA tag '%s' unrecognized in auth-area '%s' %s",
            aa->name, file_context_str());
      }
    }   /* if parse_line */
  } /* while (readline) */

  fclose(fp);

  return( check_soa(aa) );
}

/* write_soa_file: given an auth-area structure, writes the SOA file
   contained within, and fill out the record.  Returns FALSE if it
   discovered something wrong. */
int
write_soa_file(aa)
  auth_area_struct  *aa;
{
  FILE *fp = NULL;
  int   lock_fd;

  /* first establish a file lock */
  if (!get_placeholder_lock(aa->soa_file, 5, &lock_fd))
  {
    log(L_LOG_ERR, CONFIG,
        "write_soa_file: can not establish lock for soa file %s: %s",
        aa->soa_file, strerror(errno));
    return FALSE;
  }

  /* now that we have the file locked, open the soa file, truncating it */

  if ((fp = fopen(aa->soa_file, "w")) == NULL)
  {
    log(L_LOG_ERR, CONFIG, "write_soa_file: can not open soa file %s: %s",
        aa->soa_file, strerror(errno));
    release_placeholder_lock(aa->soa_file, lock_fd);
    return FALSE;
  }

  fprintf(fp, "%s: %s\n", SOA_SERIAL_NUMBER, SAFE_STR(aa->serial_no, ""));
  fprintf(fp, "%s: %ld\n", SOA_REFRESH_INTERVAL, aa->refresh_interval);
  fprintf(fp, "%s: %ld\n", SOA_INCREMENT_INTERVAL, aa->increment_interval);
  fprintf(fp, "%s: %ld\n", SOA_RETRY_INTERVAL, aa->retry_interval);
  fprintf(fp, "%s: %ld\n", SOA_TIME_TO_LIVE, aa->time_to_live);
  fprintf(fp, "%s: %s\n", SOA_PRIMARY_SERVER,
          SAFE_STR(aa->primary_server, ""));
  fprintf(fp, "%s: %s\n", SOA_HOSTMASTER, SAFE_STR(aa->hostmaster, ""));

  fclose(fp);
  release_placeholder_lock(aa->soa_file, lock_fd);

  return TRUE;
}

/* destroy_soa_in_auth_area: destroy the soa related data in an auth_area */
int
destroy_soa_in_auth_area(aa)
  auth_area_struct *aa;
{
  if (!aa) return TRUE;

  if (aa->primary_server)
  {
    free(aa->primary_server);
    aa->primary_server = NULL;
  }

  if (aa->hostmaster)
  {
    free(aa->hostmaster);
    aa->hostmaster = NULL;
  }

  if (aa->serial_no)
  {
    free(aa->serial_no);
    aa->serial_no = NULL;
  }

  return TRUE;

}


int
add_server(srv_list_ptr, val)
  dl_list_type      **srv_list_ptr;
  char              *val;
{
  dl_list_type    *list         = *srv_list_ptr;
  char            name[BUFSIZ];
  char            port[BUFSIZ];
  char            addr[BUFSIZ];
  char           *p             = NULL;
  server_struct  *server        = NULL;
  int             ipaddr        = TRUE;
#ifdef HAVE_GETADDRINFO
  struct addrinfo hints, *res1;
  int             error;
#else
  struct hostent *hp            = NULL;
  struct in_addr *ptr           = NULL;
#endif

  bzero(name, sizeof(name));
  bzero(port, sizeof(port));

  /* actually read the server line */
  sscanf(val, "%s %s", name, port);

  trim(name);
  trim(port);

  server = xcalloc(1, sizeof(*server));

  if (NOT_STR_EXISTS(name))
  {
    log(L_LOG_ERR, CONFIG, "add_server: null data detected");
    return FALSE;
  }

  server->name = xstrdup(name);

  /* look for dotted quad style IP addresses */
  for (p = name; *p; p++)
  {
#ifdef HAVE_IPV6
    if ( !isxdigit(*p) && *p != ':' && *p != '.'  )
#else
    if (!isdigit(*p) && *p != '.')
#endif
    {
      ipaddr = FALSE;
      break;
    }
  }

  if (ipaddr)
  {
    server->addr = xstrdup(name);
    /* use ipaddr as server->name */
  }
  else
  {


#ifdef HAVE_GETADDRINFO
      memset( &hints, 0, sizeof(hints) );
      hints.ai_family = PF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;

      error = getaddrinfo( name, "0", &hints, &res1 );
      if(error) {
         log(L_LOG_ERR, CONFIG, "add_server: %s", gai_strerror(error) );
         return FALSE;
      }

      bzero(addr, sizeof(addr));
      inet_ntop( res1->ai_family, res1->ai_addr, addr, sizeof addr );
      freeaddrinfo( res1 );
#ifdef DEBUG
      fprintf( stderr, "SERVER_ADDR = %s\n", addr );
#endif /* DEBUG */

#else  /* ! HAVE_GETADDRINFO */
    if ((hp = gethostbyname(name)) == NULL)
    {
      log(L_LOG_ERR, CONFIG, "add_server: could not resolve hostname '%s': %s",
          name, strerror(errno));
      return FALSE;
    }

    ptr = (struct in_addr *) (hp->h_addr);
    bzero(addr, sizeof(addr));
    sprintf(addr, "%s", inet_ntoa(*ptr));
#endif  /* HAVE_GETADDRINFO */

    server->addr = xstrdup(addr);
  }

  server->port = atoi(port);
  /* check port */
  if (server->port <= 0)
  {
    log(L_LOG_ERR, CONFIG, "add_server: incorrect port '%s'",
        port);
    return FALSE;
  }

  if (!list)
  {
    list = xcalloc(1, sizeof(*list));
  }

  if (dl_list_empty(list))
  {
    dl_list_default(list, TRUE, (int(*)(void*))destroy_server_data);
  }

  dl_list_append(list, server);

  *srv_list_ptr = list;

  return TRUE;
}

void
display_auth_area(aa)
  auth_area_struct  *aa;
{
  if (!aa)
  {
    return;
  }

  printf("auth-area:            %s\n", SAFE_STR_NONE(aa->name));
  printf("type:                 %s\n", translate_auth_area_type_str(aa->type));
  printf("data-dir:             %s\n", SAFE_STR_NONE(aa->data_dir));
  printf("schema-file:          %s\n", SAFE_STR_NONE(aa->schema_file));
  printf("soa-file:             %s\n", SAFE_STR_NONE(aa->soa_file));
  printf("primary-server:       %s\n", SAFE_STR_NONE(aa->primary_server));
  printf("hostmaster:           %s\n", SAFE_STR_NONE(aa->hostmaster));
  printf("serial-number:        %s\n", SAFE_STR_NONE(aa->serial_no));
  printf("refresh-interval:     %ld\n", aa->refresh_interval);
  printf("increment-interval:   %ld\n", aa->increment_interval);
  printf("retry-interval:       %ld\n", aa->retry_interval);
  printf("time-to-live:         %ld\n", aa->time_to_live);
  printf("xfer-time:            %ld\n", aa->xfer_time);

  display_schema(aa->schema);
}

void
display_all_auth_areas()
{
  int   not_done;

  if ( dl_list_empty(auth_area_list) )
  {
    return ;
  }

  not_done = dl_list_first(auth_area_list);
  while (not_done)
  {
    display_auth_area(dl_list_value(auth_area_list));

    not_done = dl_list_next(auth_area_list);
    if (not_done)
    {
      printf("--------------------\n");
    }
  }
}


int
destroy_server_data(server)
  server_struct *server;
{
  if (!server) return TRUE;

  if (server->name)
  {
    free(server->name);
  }

  if (server->addr)
  {
    free(server->addr);
  }

  free(server);

  return TRUE;
}

void
destroy_auth_area_list()
{
  dl_list_destroy(auth_area_list);
  auth_area_list = NULL;
}

int
destroy_auth_area_data(aa)
  auth_area_struct  *aa;
{
  if (!aa) return TRUE;

  if (aa->name)
  {
    free(aa->name);
  }

  if (aa->data_dir)
  {
    free(aa->data_dir);
  }

  if (aa->schema_file)
  {
    free(aa->schema_file);
  }

  if (aa->soa_file)
  {
    free(aa->soa_file);
  }

  if (aa->primary_server)
  {
    free(aa->primary_server);
  }

  if (aa->hostmaster)
  {
    free(aa->hostmaster);
  }

  if (aa->serial_no)
  {
    free(aa->serial_no);
  }

  if (aa->xfer_arg)
  {
    free(aa->xfer_arg);
  }

  destroy_schema_data(aa->schema);

  dl_list_destroy(aa->master);
  dl_list_destroy(aa->slave);

  dl_list_destroy(aa->guardian_list);

  free(aa);

  return TRUE;
}



dl_list_type *
get_auth_area_list()
{
  return(auth_area_list);
}


auth_area_struct *
find_auth_area_by_name(name)
  char *name;
{
  auth_area_struct  *auth_area;
  int               not_done;

  if (!auth_area_list) return NULL;

  if (NOT_STR_EXISTS(name)) return NULL;

  not_done = dl_list_first(auth_area_list);
  while (not_done)
  {
    auth_area = dl_list_value(auth_area_list);
    if (STR_EQ(auth_area->name, name))
    {
      return(auth_area);
    }

    not_done = dl_list_next(auth_area_list);
  }

  return NULL;
}


attribute_ref_struct *
find_truly_global_attr_by_name(name)
  char *name;
{
  dl_list_type         *auth_area_list;
  dl_list_type         *attr_ref_list;
  auth_area_struct     *auth_area;
  attribute_ref_struct *ar;
  int                   not_done;

  if (NOT_STR_EXISTS(name)) return NULL;

  auth_area_list = get_auth_area_list();
  if (!auth_area_list)
  {
    return NULL;
  }

  not_done = dl_list_first(auth_area_list);
  while (not_done)
  {
    auth_area = dl_list_value(auth_area_list);

    if (!auth_area || !auth_area->schema)
    {
      not_done = dl_list_next(auth_area_list);
      continue;
    }

    attr_ref_list = &(auth_area->schema->attribute_ref_list);
    ar = find_global_attr_by_name(attr_ref_list, name);
    if (ar)
    {
      return(ar);
    }

    not_done = dl_list_next(auth_area_list);
  }

  return NULL;
}

/* check_root_referral: check the syntax of punt file(rwhois.root)
 * format: <hostname>:<port>:<protocol>
 * return TRUE if not error, else return FALSE
 */
int
check_root_referral(file)
  char *file;
{
  FILE         *fp                = NULL;
  char         *pound             = NULL;
  char         line[BUFSIZ];
  char         hostname[BUFSIZ];
  char         port[BUFSIZ];
  char         proto[BUFSIZ];
  static regexp *old_ref_exp      = NULL;
  static regexp *url_exp          = NULL;

  if ((fp = fopen(file, "r")) == NULL)
  {
    log(L_LOG_ERR, CONFIG,
        "cannot open root_referral_file '%s': %s", file, strerror(errno));
    return FALSE;
  }

  if (!old_ref_exp || !url_exp)
  {
    /* FIXME: regexps should be #defined */
    old_ref_exp = regcomp(OLD_REF_REGEXP);
    url_exp = regcomp(URL_REGEXP);
  }

  bzero(line, sizeof(line));

  while (readline(fp, line, BUFSIZ))
  {
    /* skip comment line and empty line */
    if (NOT_STR_EXISTS(line))
    {
      continue;
    }

    pound = skip_whitespace(line);
    if (*pound == '#')
    {
      continue;
    }

    trim(line);

    if (NOT_STR_EXISTS(line))
    {
      continue;
    }

    bzero(hostname, sizeof(hostname));
    bzero(port, sizeof(port));
    bzero(proto, sizeof(proto));

    if (regexec(old_ref_exp, line))
    {
      regncpy(hostname, old_ref_exp, 1, sizeof(hostname));
      regncpy(port, old_ref_exp, 2, sizeof(port));
      regncpy(proto, old_ref_exp, 3, sizeof(proto));
    }
    else if (regexec(url_exp, line))
    {
      regncpy(proto, url_exp, 1, sizeof(proto));
      regncpy(hostname, url_exp, 2, sizeof(hostname));
      regncpy(port, url_exp, 3, sizeof(port));
    }
    else
    {
      log(L_LOG_ERR, CONFIG,
          "root referral server record has invalid format: %s", line);
      fclose(fp);
      return FALSE;
    }

    if (!is_valid_hostname(hostname))
    {
      log(L_LOG_ERR, CONFIG,
          "root referral server has invalid hostname: %s",
          hostname);
      fclose(fp);
      return FALSE;
    }
    if (STR_EXISTS(port) && !is_valid_port(port))
    {
      log(L_LOG_ERR, CONFIG,
          "root referral server '%s' has invalid port: %s",
          hostname, port);
      fclose(fp);
      return FALSE;
    }

    /* check protocol, starting with "rwhois" ? */
    if (!STRN_EQ(proto, "rwhois", 6))
    {
      log(L_LOG_ERR, CONFIG, "root referral has incorrect proto: %s", proto);
      fclose(fp);
      return FALSE;
    }

  } /* while */

  fclose(fp);
  return TRUE;
}

/* check to see if it is a country-code */
int
is_country_code(p)
  char  *p;
{
  /* FIXME: need the country-code database */
  return TRUE;
}

char *
get_default_aa_directory(aa)
  auth_area_struct *aa;
{
  struct netinfo prefix;
  char           buf[MAX_LINE];

  if ( get_network_prefix_and_len( aa->name, &prefix ) ) {
    sprintf( buf, "net-%s-%d", natop( &prefix ), prefix.masklen );
    return(xstrdup(buf));
  }
  else
  {
    return(xstrdup(aa->name));
  }
}

char *
get_aa_schema_directory(aa)
  auth_area_struct *aa;
{
  char  dir[MAX_FILE];
  char  file[MAX_FILE];

  bzero(dir, sizeof(dir));
  bzero(file, sizeof(file));

  if (!aa || NOT_STR_EXISTS(aa->schema_file))
  {
    return NULL;
  }

  split_path(aa->schema_file, dir, file);

  if (STR_EXISTS(dir))
  {
    return(xstrdup(dir));
  }

  return NULL;
}

/* writes all authority areas in the list to disk. Creates the top level
   authority area file while going through the auth-area list. Saves
   any directory and file names created into paths_list structure. */
int
write_all_auth_areas(file, suffix, paths_list)
  char         *file;
  char         *suffix;
  dl_list_type *paths_list;
{
  int              not_done;
  auth_area_struct *aa;
  FILE             *fp;
  char             new_file[MAX_FILE];

  if (!file || !*file || !paths_list) return FALSE;

  bzero(new_file, sizeof(new_file));
  strncpy(new_file, file, sizeof(new_file)-1);
  strncat(new_file, suffix, sizeof(new_file)-1);

  if ((fp = open_file_to_write(new_file, 60, paths_list)) == NULL)
  {
    log(L_LOG_ERR, CONFIG,
        "could not create rwhois server auth-area file '%s': %s",
        new_file, strerror(errno));
    return FALSE;
  }

  not_done = dl_list_first(auth_area_list);

  while (not_done)
  {
    aa = dl_list_value(auth_area_list);

    /* write the top level auth_area file contents */
    /* required */
    fprintf(fp, "%s: %s\n", AA_TYPE, translate_auth_area_type_str(aa->type));
    fprintf(fp, "%s: %s\n", AA_NAME, SAFE_STR(aa->name, ""));
    /* optional */
    if (aa->data_dir)
    {
      fprintf(fp, "%s: %s\n", AA_DATA_DIR, SAFE_STR(aa->data_dir, ""));
    }
    if (aa->schema_file)
    {
      fprintf(fp, "%s: %s\n", AA_SCHEMA_FILE, SAFE_STR(aa->schema_file, ""));
    }
    if (aa->soa_file)
    {
      fprintf(fp, "%s: %s\n", AA_SOA_FILE, SAFE_STR(aa->soa_file, ""));
    }
    if (aa->xfer_arg)
    {
      fprintf(fp, "%s: %s\n", AA_XFER_ARG, SAFE_STR(aa->xfer_arg, ""));
    }

    /* optional */
    write_server_list(fp, AA_MASTER, aa->master);
    write_server_list(fp, AA_SLAVE, aa->slave);
    write_guardian_list(fp, aa->guardian_list);

    /* write inidividual authority area */
    if (!write_auth_area(suffix, aa, paths_list))
    {
      log(L_LOG_ERR, CONFIG, "error in writing auth-area '%s'",
          SAFE_STR(aa->name, ""));
      release_file_lock(new_file, fp);
      dl_list_append(paths_list, xstrdup(new_file));
      return FALSE;
    }

    /* go to the next auth-area information */
    not_done = dl_list_next(auth_area_list);
    if (not_done)
    {
      fprintf(fp, "-----\n");
    }
  }

  release_file_lock(new_file, fp);

  dl_list_append(paths_list, xstrdup(new_file));

  return TRUE;
}

/* creates a new authority area, uses defaults where somethings are not
   defined by the user. And finally appends the created authority area
   to the list. */
int
create_auth_area(aa)
  auth_area_struct *aa;
{
  char             aa_dir[MAX_FILE];
  char             buffer[MAX_FILE];
  char             portstr[BUFSIZ];
  auth_area_struct *newaa;

  /* check if all essentials are initialized */
  if ( !aa || !aa->name || !*(aa->name) ) return FALSE;

  if (!check_aa_syntax(aa->name, aa_dir))
  {
    log(L_LOG_ERR, CONFIG, "'%s' is not a valid authority area name syntax",
        aa->name);
    return FALSE;
  }
  if (is_duplicate_aa(aa, auth_area_list))
  {
    log(L_LOG_ERR, CONFIG, "authority area '%s' already exists",
        aa->name);
    return FALSE;
  }

  newaa = xcalloc(1, sizeof(*newaa));

  newaa->name = xstrdup(aa->name);

  if (aa->serial_no && *(aa->serial_no))
  {
    newaa->serial_no = xstrdup(aa->serial_no);
  }
  else
  {
    newaa->serial_no = xstrdup(make_timestamp());
  }

  if (aa->schema_file && *(aa->schema_file))
  {
    newaa->schema_file = xstrdup(aa->schema_file);
  }
  else
  {
    bzero(buffer, sizeof(buffer));
    strncpy(buffer, aa_dir, sizeof(buffer)-1);
    strncat(buffer, "/", sizeof(buffer)-1);
    strncat(buffer, DEFAULT_SCHEMA_FILE, sizeof(buffer)-1);
    newaa->schema_file = xstrdup(buffer);
  }

  if (aa->soa_file && *(aa->soa_file))
  {
    newaa->soa_file = xstrdup(aa->soa_file);
  }
  else
  {
    bzero(buffer, sizeof(buffer));
    strncpy(buffer, aa_dir, sizeof(buffer)-1);
    strncat(buffer, "/", sizeof(buffer)-1);
    strncat(buffer, DEFAULT_SOA_FILE, sizeof(buffer)-1);
    newaa->soa_file = xstrdup(buffer);
  }
  if (aa->data_dir && *(aa->data_dir))
  {
    newaa->data_dir = xstrdup(aa->data_dir);
  }
  else
  {
    bzero(buffer, sizeof(buffer));
    strncpy(buffer, aa_dir, sizeof(buffer)-1);
    strncat(buffer, "/", sizeof(buffer)-1);
    strncat(buffer, DEFAULT_DATA_DIR, sizeof(buffer)-1);
    newaa->data_dir = xstrdup(buffer);
  }
  if (aa->type == AUTH_AREA_PRIMARY)
  {
    newaa->type = AUTH_AREA_PRIMARY;
  }
  else
  {
    newaa->type = AUTH_AREA_SECONDARY;
  }

  if (aa->refresh_interval > 0)
  {
    newaa->refresh_interval = aa->refresh_interval;
  }
  else
  {
    newaa->refresh_interval = DEFAULT_REFRESH_INTERVAL;
  }
  if (aa->increment_interval > 0)
  {
    newaa->increment_interval = aa->increment_interval;
  }
  else
  {
    newaa->increment_interval = DEFAULT_INCREMENT_INTERVAL;
  }
  if (aa->retry_interval > 0)
  {
    newaa->retry_interval = aa->retry_interval;
  }
  else
  {
    newaa->retry_interval = DEFAULT_RETRY_INTERVAL;
  }
  if (aa->time_to_live > 0)
  {
    newaa->time_to_live = aa->time_to_live;
  }
  else
  {
    newaa->time_to_live = DEFAULT_TIME_TO_LIVE;
  }
  if ( aa->primary_server && *(aa->primary_server) )
  {
    newaa->primary_server = xstrdup( aa->primary_server );
  }
  else
  {
    sprintf(portstr, "%d", DEFAULT_PORT);
    bzero(buffer, sizeof(buffer));
    strncpy(buffer, sys_gethostname(), sizeof(buffer)-1);
    strncat(buffer, ":", sizeof(buffer)-1);
    strncat(buffer, portstr, sizeof(buffer)-1);
    newaa->primary_server = xstrdup( buffer );
  }
  if ( aa->hostmaster && *(aa->hostmaster) )
  {
    newaa->hostmaster = xstrdup( aa->hostmaster );
  }
  else
  {
    bzero(buffer, sizeof(buffer));
    strncpy(buffer, DEFAULT_HOSTMASTER, sizeof(buffer)-1);
    strncat(buffer, "@", sizeof(buffer)-1);
    strncat(buffer, sys_gethostname(), sizeof(buffer)-1);
    newaa->hostmaster = xstrdup( buffer );
  }

  /* Non-primary auth-areas get to do this stuff later */
  if (newaa->type == AUTH_AREA_PRIMARY)
  {
    newaa->schema = xcalloc(1, sizeof(*(aa->schema)));
  }

  /* commit authority area */
  if (!auth_area_list)
  {
    auth_area_list = xcalloc(1, sizeof(*auth_area_list));

    dl_list_default(auth_area_list, TRUE, (int(*)(void *))destroy_auth_area_data);
  }

  dl_list_append(auth_area_list, newaa);

  return TRUE;
}

/* deletes an authority area (by name) from the configuration */
int
delete_auth_area(name)
  char *name;
{
  if (!find_auth_area_by_name(name))
  {
    log(L_LOG_ERR, CONFIG,
        "'%s' authority area does not exist", name);
    return FALSE;
  }
  if (!dl_list_delete(auth_area_list))
  {
    log(L_LOG_ERR, CONFIG,
        "'%s' authority area could not be deleted", name);
    return FALSE;
  }
  return TRUE;
}

/* examine the format of email address string. Currently excuses the
   hostname to have an non-dns hostname. Returns non-zero value if
   some error was found. */
int
examin_email_address(addr)
  char *addr;
{
  static regexp  *email_exp = NULL;

  if (!addr) return ERW_NDEF;
  if (!*addr) return ERW_EMTYSTR;

  if (!email_exp)
  {
    email_exp = regcomp(EMAIL_REGEXP);
  }
  if (!regexec(email_exp, addr))
  {
    log(L_LOG_WARNING, CONFIG,
      "email address '%s': %s", addr,
      examin_error_string(ERW_FMTMAIL));
  }

  return( 0 );
}

/* examine the format of x-fer arguments. Returns non-zero value on
   failure. */
int
examin_aa_xfer_arg(path)
  char *path;
{
  return ( 0 );
}

/* examine the validity of authority area directory. Returns non-zero
   value on failure. */
int
examin_aa_data_dir(path)
  char *path;
{
  int ret;

  if (NOT_STR_EXISTS(path)) return ERW_EMTYSTR;
  if ((ret = examin_directory_name(path))) return( ret );
  if (!path_under_root_dir(path, get_root_dir())) return ERW_UNDROOT;

  return( 0 );
}

/* examine the validity of authority area schema file name. Returns
   non-zero value on failure. */
int
examin_aa_schema_file(path)
  char *path;
{
  int ret;

  if (NOT_STR_EXISTS(path)) return ERW_EMTYSTR;
  if ((ret = examin_file_name(path))) return( ret );
  if (!path_under_root_dir(path, get_root_dir())) return ERW_UNDROOT;

  return( 0 );
}

/* examine the validity of authority area soa file name. Returns non-zero
   value on failure. */
int
examin_aa_soa_file(path)
  char *path;
{
  int ret;

  if (NOT_STR_EXISTS(path)) return ERW_EMTYSTR;
  if ((ret = examin_file_name(path))) return( ret );
  if (!path_under_root_dir(path, get_root_dir())) return ERW_UNDROOT;

  return( 0 );
}

/* examine the validity of authority area hostmaster e-mail address.
   Returns non-zero value on failure. */
int
examin_aa_hostmaster_str(contact)
  char *contact;
{
  int ret;

  if (NOT_STR_EXISTS(contact)) return ERW_EMTYSTR;
  if ((ret = examin_email_address(contact))) return( ret );

  return( 0 );
}

/* examine the vailidity of authority area serial number. Makes sure
   it is a number string. Returns non-zero value on failure. */
int
examin_serial_num(num)
  char *num;
{
  int ret;

  if ((ret = examin_timestamp(num))) return( ret );

  return( 0 );
}

/* examine the validity of guardian item string. Returns non-zero value
   on failure. */
int
examin_guardian_item(guard_str)
  char *guard_str;
{
  if (NOT_STR_EXISTS(guard_str)) return ERW_EMTYSTR;

  return( 0 );
}


/* examins the validity of a host name. It logs a warning if the hostname
   is not a complete dns host name. Returns non-zero value on
   error. */
int
examin_hostname(name)
  char *name;
{
  if (NOT_STR_EXISTS(name)) return ERW_EMTYSTR;

  if (strchr(name, '.') == NULL)
  {
    log(L_LOG_WARNING, CONFIG,
        "'%s' is not a complete dns host name", name);
    return( 0 );
  }
  else if (!is_valid_hostname(name))
  {
    return ERW_DNSSTR;
  }
  return( 0 );
}

/* examins the validity of a port number string. Returns non-zero
   value on error. */
int
examin_port_str(portstr)
  char *portstr;
{
  if (NOT_STR_EXISTS(portstr)) return ERW_EMTYSTR;
  if (!is_number_str(portstr)) return ERW_NUMSTR;
  if (atoi(portstr) < 1) return ERW_NUMVAL;

  return( 0 );
}

/* examine the validity of authority area primary server string. Returns
   non-zero value if failed. */
int
examin_primary_server_str(server)
  char *server;
{
  char hostname[BUFSIZ];
  char port[BUFSIZ];
  int argc;
  char **argv;
  int ret;

  if (NOT_STR_EXISTS(server)) return ERW_EMTYSTR;

  /* extract host and port number */
  if (!split_list(server, ':', 2, &argc, &argv)) return ERW_FMTSERV;
  if (argc != 2)
  {
    free_arg_list(argv);
    return ERW_FMTSERV;
  }

  bzero(hostname, sizeof(hostname));
  strncpy(hostname, argv[0], sizeof(hostname)-1);

  bzero(port, sizeof(port));
  strncpy(port, argv[1], sizeof(port)-1);

  free_arg_list(argv);

  if ((ret = examin_hostname(hostname))) return ret;

  if ((ret = examin_port_str(port))) return ret;

  return( 0 );
}

/* examine the validity of master or slave server string. Returns
   a non-zero value if failed. Calls functions to examine hostname and
   port number string separately. */
int
examin_server_str(server)
  char *server;
{
  int             ret;
  char            name[BUFSIZ];
  char            port[BUFSIZ];

  bzero(name, sizeof(name));
  bzero(port, sizeof(port));

  /* actually read the server line */
  sscanf(server, "%s %s", name, port);

  trim(name);
  trim(port);

  if ((ret = examin_hostname(name))) return ret;

  if ((ret = examin_port_str(port))) return ret;

  return( 0 );
}


/* verify all authority area definitions in the server configuration. */
int
verify_all_auth_areas()
{
  int              not_done;
  auth_area_struct *aa;

  not_done = dl_list_first(auth_area_list);
  while (not_done)
  {
    aa = dl_list_value(auth_area_list);

    if (!verify_auth_area(aa))
    {
      return FALSE;
    }

    not_done = dl_list_next(auth_area_list);
  }

  return TRUE;
}

/* Adds path names in the authority area structure to paths_list if not
   already in the list. Logs an error if a path name is already used in
   the configuration. */
int
verify_all_auth_area_paths(paths_list)
  dl_list_type *paths_list;
{
  int              ret = 0;
  char             buffer[MAX_LINE];
  auth_area_struct *aa;
  int              not_done;

  if (!paths_list) return( 1 );

  not_done = dl_list_first(auth_area_list);
  while (not_done)
  {
    aa = dl_list_value(auth_area_list);

    bzero(buffer, sizeof(buffer));
    strncpy(buffer, aa->name, sizeof(buffer)-1);
    strncat(buffer, ":", sizeof(buffer)-1);
    strncat(buffer, AA_DATA_DIR, sizeof(buffer)-1);
    ret += dup_config_path_name(paths_list, aa->data_dir,
                                buffer);
    bzero(buffer, sizeof(buffer));
    strncpy(buffer, aa->name, sizeof(buffer)-1);
    strncat(buffer, ":", sizeof(buffer)-1);
    strncat(buffer, AA_SCHEMA_FILE, sizeof(buffer)-1);
    ret += dup_config_path_name(paths_list, aa->schema_file,
                                buffer);
    bzero(buffer, sizeof(buffer));
    strncpy(buffer, aa->name, sizeof(buffer)-1);
    strncat(buffer, ":", sizeof(buffer)-1);
    strncat(buffer, AA_SOA_FILE, sizeof(buffer)-1);
    ret += dup_config_path_name(paths_list, aa->soa_file,
                                buffer);

    ret += verify_all_class_paths(paths_list, aa);

    not_done = dl_list_next(auth_area_list);
  }

  return( ret );
}

/* verifies to make sure none of the parse programs defined for the
   classes are used as configuration path names (contents of
   paths_list). */
int
verify_aa_parse_progs(paths_list)
  dl_list_type *paths_list;
{
  int              ret = 0;
  auth_area_struct *aa;
  int              not_done;

  if (!paths_list) return( 1 );

  not_done = dl_list_first(auth_area_list);
  while (not_done)
  {
    aa = dl_list_value(auth_area_list);

    ret += verify_class_parse_progs(paths_list, aa);

    not_done = dl_list_next(auth_area_list);
  }

  return( ret );
}
