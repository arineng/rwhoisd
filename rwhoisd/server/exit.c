/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "exit.h"

#include "client_msgs.h"
#include "holdconnect.h"
#include "defines.h"

/*************************************************************************
  exits the whois loop
**************************************************************************/
int
quit_directive(str)
  char *str;
{
   print_ok(); 

  return QUIT;
}
