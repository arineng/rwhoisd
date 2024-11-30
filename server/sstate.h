#ifndef _SSTATE_H_
#define _SSTATE_H_

/* includes */

#include "common.h"
#include "types.h"

/* types */

typedef enum
{
  ACTION_NULL,
  ACTION_SOA,
  ACTION_SCHEMA,
  ACTION_XFER
} action_type;
 
typedef enum
{
  STATUS_NULL,
  STATUS_WAIT,
  STATUS_ERROR,
  STATUS_OK
} status_type;
 
typedef struct _slave_state_struct
{
  char        *name;
  int         pid;
  action_type action;
  status_type status;
} slave_state_struct;

/* prototypes */

int set_slave_state PROTO((char *name,
                           int  pid,
                           int  action,
                           int  status));

slave_state_struct *
get_slave_state PROTO((char *name));

void init_slave_state_list PROTO((dl_list_type *slave_aa_list));

void wait_for_child_processes PROTO((int count,
                                     int seconds,
                                     int action));

#endif /* _SSTATE_H_ */
