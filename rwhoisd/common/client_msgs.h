/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _CLIENT_MSGS_H_
#define _CLIENT_MSGS_H_

/* includes */

#include "common.h"

/* types */

typedef enum {
  REGIST_DEFFERED,
  OBJECT_NOT_AUTHORITATIVE,
  NO_OBJECTS_FOUND,
  UNCOMPAT_VERSION,
  INVALID_ATTRIBUTE,
  INVALID_ATTR_SYNTAX,
  MISSING_REQ_ATTRIB,
  MISSING_OBJECT_REF,
  NON_UNIQ_KEY,
  OUTDATED_OBJ,
  EXCEEDED_MAXOBJ,
  INVALID_LIMIT,
  NO_TRANSFER,
  NOT_MASTER_AUTH_AREA,
  NO_OBJECT_FOUND,
  INVALID_DIRECTIVE_PARAM,
  INVALID_AUTH_AREA,
  INVALID_CLASS,
  INVALID_HOST_PORT,
  INVALID_QUERY_SYNTAX,
  QUERY_TOO_COMPLEX,
  INVALID_SECURITY,
  AUTHENTICATION_FAILED,
  ENCRIPTION_FAILED,
    CORRUPT_DATA,
  INVALID_DIRECTIVE,
  UNAUTH_DIRECTIVE,
  UNIDENT_ERROR,
  UNAUTH_REGIST,
  UNAUTH_DISPLAY,
  MEMORY_ALLOCATION_PROBLEM,
  SERVICE_NOT_AVAIL,
  UNRECOV_ERROR,
  DEADMAN_TIME,
  MISC_DIAG
} error_codes_type;

typedef enum {
  RESP_RWHOIS,
  RESP_REFERRAL,
  RESP_CLASS,
  RESP_SEEALSO,
  RESP_LOAD,
  RESP_SOA,
  RESP_STATUS,
  RESP_XFER,
  RESP_SCHEMA,
/*  RESP_DEFINE, */
/*  RESP_OBJECT, */
  RESP_DIRECTIVE,
  RESP_INFO,
  RESP_DISPLAY,
  RESP_X,
  RESP_REGISTER,
/*  RESP_LANGUAGE, */
  RESP_QUERY
} response_codes_type;

/* prototypes */

void set_out_fp PROTO((FILE *fp));

FILE *get_out_fp PROTO((void));

void clear_printed_error_flag PROTO((void));

void print_error PROTO((int err_no, char *str));

#ifndef HAVE_STDARG_H
void print_response PROTO(());
#else
void print_response(int, char *, ...);
#endif

void print_ok PROTO((void));

#endif /* CLIENT_MSGS */
