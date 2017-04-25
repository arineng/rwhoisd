/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _STATE_H_
#define _STATE_H_

/* includes */

#include "common.h"
#include "reg_utils.h"

/* types */

typedef enum
{
  QUERY_STATE,
  SPOOL_STATE
} rwhois_state_type;

/* prototypes */
int get_rwhois_secure_mode PROTO((void));

void set_rwhois_secure_mode PROTO((int mode));

rwhois_state_type get_rwhois_state PROTO((void));

int set_rwhois_state PROTO((rwhois_state_type s));

char *get_rwhois_spool_file_name PROTO((void));

int set_rwhois_spool_file_name PROTO((char *file));

FILE *open_spool_file PROTO((char *mode));

void close_spool_file PROTO((void));

int move_spool_file PROTO((char *new_file_name));

int remove_spool_file PROTO((void));

char *get_client_vendor_id PROTO((void));

void set_client_vendor_id PROTO((char  *id));

char *get_register_email PROTO((void));

void set_register_email PROTO((char *email));

register_action_type get_register_action PROTO((void));

void set_register_action PROTO((register_action_type action));

#endif /* _STATE_H_ */
