/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _VALIDATE_REC_H_
#define _VALIDATE_REC_H_

/* includes */

#include "common.h"
#include "types.h"

/* defines */

#define VALIDATE_ON                 0x01
#define VALIDATE_PROTOCOL_ERROR     0x02
#define VALIDATE_QUIET              0x04
#define VALIDATE_FIND_ALL           0x08


/* prototypes */

int encode_validate_flag PROTO((int quiet_mode_flag,
                                int protocol_error_flag,
                                int find_all_flag));

void decode_validate_flag PROTO((int    validate_flag,
                                 int    *quiet_mode_flag,
                                 int    *protocol_error_flag,
                                 int    *find_all_flag));
  
av_pair_struct *find_record_attr_by_id PROTO((record_struct *record,
                                              int           id));

int count_record_attr_by_id PROTO((record_struct    *record,
                                   int              id));

int check_required PROTO((record_struct *record,
                          int           validate_flag));

int check_repeated PROTO((record_struct *record,
                          int           validate_flag));

int check_formats PROTO((record_struct  *record,
                         int            validate_flag));

int check_record PROTO((record_struct   *record,
                        int             validate_flag));

#endif /* _VALIDATE_REC_H_ */
