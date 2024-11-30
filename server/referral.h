/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _REFERRAL_H_
#define _REFERRAL_H_

/* includes */

#include "common.h"
#include "types.h"
#include "mkdb_types.h"

/* defines */

#define NETWORK        1
#define DOMAIN         2

/* types */

typedef enum
{
  UP_HIERARCHICAL,
  DOWN_HIERARCHICAL,
  NON_HIERARCHICAL
} referral_type;

typedef struct _referral_struct
{
  char          *to;
  char          *aa_name;
  referral_type type;
} referral_struct;

/* prototypes */

int refer_query PROTO((query_struct *query));

int refer_query_term PROTO((query_term_struct *query_term,
                            dl_list_type      *referral_list));

int parse_hierarchical_value PROTO((char *value,
                                    char *hvalue,
                                    int  *htype));

int hierarchical_value_within_aa PROTO((char *hvalue,
                                        int  htype,
                                        char *aa_name));

int referral_rec_check PROTO( (record_struct *ref_rec) );


#endif /* _REFERRAL_H_ */
