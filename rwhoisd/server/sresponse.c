#include "sresponse.h"

#include "deadman.h"
#include "defines.h"
#include "log.h"
#include "misc.h"

static int processline PROTO((char         *line,
                              char         *delimiter,
                              dl_list_type *response));


/* ------------------- LOCAL FUNCTIONS -------------------- */


/* processline: This function processes a response line */
static int
processline(line, delimiter, response)
  char         *line;
  char         *delimiter;
  dl_list_type *response;
{
  char *p;

  if (strstr(line, delimiter))
  {
    if ((p = strchr(line, ' ')))
    {
      /* Response line: delimiter text
         For example:   %xfer domain:Auth-Area:a.com
         Parse text */
      p++;
      dl_list_append(response, NEW_STRING(p));
    }
    else
    {
      /* Response line: delimiter
         For example:   %xfer
         End of response */
      return(FALSE);
    }
  }
  else if (strstr(line, "%ok") ||
           strstr(line, "%error"))
  {
    /* End of response */
    return(FALSE);
  }

  return(TRUE);
}


/* ------------------- PUBLIC FUNCTIONS ------------------- */


/* connect_server: This function sets up a TCP connection to
   an RWhois server running at addr:port */
void
connect_server(addr, port, sockfd)
  char *addr;
  int  port;
  int  *sockfd;
{
#ifdef HAVE_IPV6
  struct addrinfo hints, *gai_result, *server_aip;
  char            portstr[MAX_LINE];
  int             connect_status = -1;

  memset( &hints, '\0', sizeof hints );
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  snprintf( portstr, sizeof portstr, "%d", port );
  if ( getaddrinfo( addr, portstr, &hints, &gai_result ) )
  {
    log( L_LOG_ERR, SECONDARY, "connect_server: bad address or port: %s", 
         strerror( errno ) );
    exit( 1 );
  }

  /* Try each returned address until we get a connection. */
  for( server_aip = gai_result; server_aip != NULL;
       server_aip = server_aip->ai_next )
  {
    /* Open socket */
    if ( ( *sockfd = socket( server_aip->ai_family, 
                             server_aip->ai_socktype,
                             server_aip->ai_protocol ) ) < 0 )
      continue;
 
    /* Connect */
    if ( ( connect_status = connect( *sockfd,
                                     (struct sockaddr *) server_aip->ai_addr, 
                                     server_aip->ai_addrlen ) ) == 0 )
      break;
  }

  if ( ! connect_status )
  {
    log(L_LOG_ERR, SECONDARY,
        "connect_server: connect error: %s", strerror(errno));
    exit(1);
  }

#else

  struct sockaddr_in  server;

  bzero((char *) &server, sizeof(server));

  server.sin_family      = AF_INET;
  server.sin_addr.s_addr = inet_addr(addr);
  server.sin_port        = htons(port);

  /* Open socket */
  if ((*sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
  {
    log(L_LOG_ERR, SECONDARY,
        "connect_server: could not open socket: %s", strerror(errno));
    exit(1);
  }
 
  /* Connect */
  if (connect(*sockfd, (struct sockaddr *) &server, sizeof(server)) < 0)
  {
    log(L_LOG_ERR, SECONDARY,
        "connect_server: connect error: %s", strerror(errno));
    exit(1);
  }
  
#endif
  /* Redirect stdin and stdout to socket */
  if (dup2(*sockfd, 0) == -1)
  {
    log(L_LOG_ERR, SECONDARY,
        "connect_server: dup error: %s", strerror(errno));
    exit(1);
  }
  if (dup2(*sockfd, 1) == -1)
  {
    log(L_LOG_ERR, SECONDARY,
        "connect_server: dup error: %s", strerror(errno));
    exit(1);
  }
}


/* send_directive: This function sends directive to
   an RWhois server */
void
send_directive(sockfd, directive)
  int  sockfd;
  char *directive;
{
  /* Write directive */
  if (write(sockfd, directive, strlen(directive)) < 0)
  {
    log(L_LOG_ERR, SECONDARY,
        "send_directive: write error: %s", strerror(errno));
    exit(1);
  }
}


/* recv_response: This functions receives response from
   an RWhois server */
void
recv_response(fp, delimiter, response)
  FILE         *fp;
  char         *delimiter;
  dl_list_type *response;
{
  char line[MAX_LINE];
  int  not_done        = TRUE;

  dl_list_default(response, FALSE, (int(*)(void *))destroy_response_data);

  /* Read response line by line till delimiter */
  do
  {
    set_timer(get_deadman_time(), is_a_deadman);

    if (readline(fp, line, MAX_LINE) == NULL)
    {
      not_done = FALSE;
    }
    else
    {
      unset_timer();
      not_done = processline(line, delimiter, response);
    }
  } while (not_done);
}


/* destroy_response_data: This function frees a character string */
int
destroy_response_data(str)
  char *str;
{
  if (!str)
  {
    return(TRUE);
  }
 
  free(str);
 
  return(TRUE);
}
