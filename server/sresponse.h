#ifndef _SRESPONSE_H_
#define _SRESPONSE_H_

/* includes */

#include "common.h"
#include "types.h"

/* prototypes */

void connect_server PROTO((char *addr,
                           int  port,
                           int  *sockfd));

void send_directive PROTO((int  sockfd,
                           char *directive));

void recv_response PROTO((FILE         *fp,
                          char         *delimiter,
                          dl_list_type *response));

int destroy_response_data PROTO((char *str));

#endif /* _SRESPONSE_H_ */
