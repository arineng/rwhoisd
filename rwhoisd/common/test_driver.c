#include "defines.h"
#include "../regexp/regexp.h"

#define NETWORK_REGEXP "^[0-9]+([.][0-9]+)*(/[0-9]+)?$"

int
is_network(value)
  char *value;
{
  static regexp *net_prog = NULL;

  if (!net_prog)
  {
    net_prog = regcomp(NETWORK_REGEXP);
  }
  
  if (regexec(net_prog, value))
  {
    return(TRUE);
  }
  else
  {
    return(FALSE);
  }
}

void main(argc, argv)
  int argc;
  char **argv;
{
  printf("checking: %s\n", argv[1]);
  
  if (is_network(argv[1]))
  {
    printf("looks like a valid network search\n");
  }
  else
  {
    printf("doesn't look like a valid network search\n");
  }

}
