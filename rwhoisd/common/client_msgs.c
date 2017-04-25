/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "client_msgs.h"

#include "defines.h"

static struct err_struct
{
  error_codes_type err_no;
  char *msg;
} errs[] =  {
  { REGIST_DEFFERED, "120 Registration Deferred"},
  { OBJECT_NOT_AUTHORITATIVE, "130 Object not authoritative"},
  { NO_OBJECTS_FOUND, "230 No Objects Found"},
  { UNCOMPAT_VERSION, "300 Not Compatible With Version"},
  { INVALID_ATTRIBUTE, "320 Invalid Attribute"},
  { INVALID_ATTR_SYNTAX, "321 Invalid Attribute Syntax"},
  { MISSING_REQ_ATTRIB, "322 Required Attribute Missing"},
  { MISSING_OBJECT_REF, "323 Object Reference Not Found"},
  { NON_UNIQ_KEY, "324 Primary Key Not Unique"},
  { OUTDATED_OBJ, "325 Failed to Update Outdated Object"},
  { EXCEEDED_MAXOBJ, "330 Exceeded Max Objects Limit"},
  { INVALID_LIMIT, "331 Invalid Limit"},
  { NO_TRANSFER, "332 Nothing To Transfer"},
  { NOT_MASTER_AUTH_AREA, "333 Not Master for Authority Area"},
  { NO_OBJECT_FOUND, "336 Object Not Found"},
  { INVALID_DIRECTIVE_PARAM, "338 Invalid Directive Syntax"},
  { INVALID_AUTH_AREA, "340 Invalid Authority Area"},
  { INVALID_CLASS, "341 Invalid Class"},
  { INVALID_HOST_PORT, "342 Invalid Host/Port"},
  { INVALID_QUERY_SYNTAX, "350 Invalid Query Syntax"},
  { QUERY_TOO_COMPLEX, "351 Query Too Complex"},
  { INVALID_SECURITY, "352 Invalid Security Method"},
  { AUTHENTICATION_FAILED, "353 Authentication Failed"},
  { ENCRIPTION_FAILED, "354 Encription Failed"},
  { CORRUPT_DATA, "360 Corrupt Data. Keyadd Failed"},
  { INVALID_DIRECTIVE, "400 Directive Not Available"},
  { UNAUTH_DIRECTIVE, "401 Not Authorized for Directive"},
  { UNIDENT_ERROR, "402 Unidentified Error"},
  { UNAUTH_REGIST, "420 Registration Not Authorized"},
  { UNAUTH_DISPLAY, "436 Invalid Display Format"},
  { MEMORY_ALLOCATION_PROBLEM, "500 Memory Allocation Problem"},
  { SERVICE_NOT_AVAIL, "501 Service Not Available"},
  { UNRECOV_ERROR, "502 Unrecoverable Error"},
  { DEADMAN_TIME, "503 Idle Time Exceeded"},
  { MISC_DIAG, "560 "}
};

static struct response_struct
{
  response_codes_type resp_no;
  char *msg;
}   resp[] = {
  { RESP_RWHOIS, "%rwhois"},
  { RESP_REFERRAL, "%referral"},
  { RESP_CLASS, "%class"},
  { RESP_SEEALSO, "%see-also"},
  { RESP_LOAD, "%load"},
  { RESP_SOA, "%soa"},
  { RESP_STATUS, "%status"},
  { RESP_XFER, "%xfer"},
  { RESP_SCHEMA, "%schema"},
 /*  { RESP_DEFINE, "%define"}, */
 /*  { RESP_OBJECT, "%object"}, */
  { RESP_DIRECTIVE, "%directive"},
  { RESP_INFO, "%info"},
  { RESP_DISPLAY, "%display"},
  { RESP_X, "%X-"},
  { RESP_REGISTER, "%register"},
 /*  { RESP_LANGUAGE, "%language"}, */
  { RESP_QUERY, ""}
};

static FILE *out;

static int  printed_error_flag = FALSE;

void
set_out_fp(fp)
  FILE *fp;
{
  out = fp;
}

FILE *
get_out_fp()
{
  return out;
}

/* FIXME: this entire solution, which attempts to reliably prevent the
   printing of multiple "%error" codes in succession is a hack. */
void
clear_printed_error_flag()
{
  printed_error_flag = FALSE;
}

#define N_ERRS (sizeof(errs)/sizeof (struct err_struct))
#define N_RESP (sizeof(resp)/sizeof (struct response_struct))

/* prints to stdout the error messages. Format: %error ### message
     text, where ### follows rfc 640 */
void
print_error(err_no, str)
  int   err_no;
  char *str;
{
  int   i;
  
  if (printed_error_flag)
  {
    return;
  }

  for (i = 0; i < N_ERRS; i++)
  {
    if (errs[i].err_no == err_no)
    {
      printf("%%error %s", errs[i].msg);
      break;
    }
  }

  if (STR_EXISTS(str))
  {
    printf(": %s", str);
  }
  
  printf("\n");

  printed_error_flag = TRUE;
}

/* prints to stdout the ok message */
void print_ok ()
{
  printf ("%%ok\n");
}

#ifndef HAVE_STDARG_H
void print_response(va_alist)
    va_dcl
#else
void print_response(int resp_no, char *format, ...)
#endif
{
  va_list list;
  int i;
  FILE *fp;
#ifndef HAVE_STDARG_H
  int resp_no;
  char *format;
  va_start(list);
  resp_no = va_arg(list, int);
  format = va_arg(list, char *);
#else
  va_start(list, format);
#endif /* HAVE_STDARG_H */

  fp = get_out_fp();

  for (i = 0; i < N_RESP; i++)
  {
    if (resp[i].resp_no == resp_no)
    {
      if (STR_EXISTS(resp[i].msg))
      {
        fprintf(fp, "%s", resp[i].msg);

        if (STR_EXISTS(format))
        {
          fprintf(fp, " ");
        }
      }
      break;
    }
  }

  vfprintf(fp, format, list);

  fprintf(fp, "\n");
  va_end(list);
}

