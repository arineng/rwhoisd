#include "ssoa.h"

#include "auth_area.h"
#include "defines.h"
#include "fileutils.h"
#include "log.h"
#include "misc.h"
#include "sresponse.h"

static int create_soa_file_record PROTO((FILE         *fp,
                                         dl_list_type *response));


/* ------------------- LOCAL FUNCTIONS -------------------- */


/* create_soa_file_record: This function maps an RWhois server
   response into an SOA file record */
static int
create_soa_file_record(fp, response)
  FILE         *fp;
  dl_list_type *response;
{
  int  not_done;
  char *str;
  char tag[MAX_LINE];
  char value[MAX_LINE];

  if (dl_list_empty(response))
  {
    return(FALSE);
  }

  not_done = dl_list_first(response);
  while (not_done)
  {
    str = dl_list_value(response);
    if (!parse_line(str, tag, value))
    {
      return(FALSE);
    }

    if (STR_EQ(tag, "ttl"))
    {
      fprintf(fp, "%s: %s\n", SOA_TIME_TO_LIVE, value);
    }
    else if (STR_EQ(tag, "serial"))
    {
      fprintf(fp, "%s: %s\n", SOA_SERIAL_NUMBER, value);
    }
    else if (STR_EQ(tag, "refresh"))
    {
      fprintf(fp, "%s: %s\n", SOA_REFRESH_INTERVAL, value);
    }
    else if (STR_EQ(tag, "increment"))
    {
      fprintf(fp, "%s: %s\n", SOA_INCREMENT_INTERVAL, value);
    }
    else if (STR_EQ(tag, "retry"))
    {
      fprintf(fp, "%s: %s\n", SOA_RETRY_INTERVAL, value);
    }
    else if (STR_EQ(tag, "hostmaster"))
    {
      fprintf(fp, "%s: %s\n", SOA_HOSTMASTER, value);
    }
    else if (STR_EQ(tag, "primary"))
    {
      fprintf(fp, "%s: %s\n", SOA_PRIMARY_SERVER, value);
    }

    not_done = dl_list_next(response);
  }

  return(TRUE);
}


/* ------------------- PUBLIC FUNCTIONS ------------------- */


/* create_soa_file: This function creates SOA file for a
   slave authority area */
int
create_soa_file(aa, server)
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

  /* Connect to the master server */
  connect_server(server->addr, server->port, &sockfd);

  /* Send '-soa autharea' directive */
  bzero((char *) directive, MAX_LINE);
  sprintf(directive, "-soa %s\r\n", aa->name);
  send_directive(sockfd, directive);

  /* Create SOA file */
  if ((fp = get_file_lock(aa->soa_file, "w", 60)) == NULL)
  {
    log(L_LOG_ERR, SECONDARY,
        "create_soa_file: could not open soa file %s: %s",
        aa->soa_file, strerror(errno));
    return(rval);
  }

  do
  {
    recv_response(stdin, "%soa", &response);

    if (dl_list_empty(&response))
    {
      not_done = FALSE;
    }
    else
    {
      if (create_soa_file_record(fp, &response))
      {
        rval = TRUE;
      }
      dl_list_destroy(&response);
    }
  } while (not_done);

  release_file_lock(aa->soa_file, fp);

  close(sockfd);

  return(rval);
}
