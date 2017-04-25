/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "daemon.h"

#include "fileutils.h"
#include "log.h"
#include "main.h"  /* ugh */
#include "main_config.h"
#include "security.h"
#include "session.h"
#include "sslave.h"

/* -------------------- Local Vars ---------------------- */

static int hup_recvd    = FALSE;
static int num_children = 0;

/* -------------------- Local Functions ----------------- */

/* logpid: put the pid in a specified file */
static void
logpid ()
{
  FILE *fp;

  if ((fp = fopen(get_pid_file(), "w")) != NULL)
  {
    fprintf(fp, "%ld\n", (long) getpid());
    fclose(fp);
  }
}

static void
delpid()
{
  char  *pid_file = get_pid_file();

  if (pid_file && file_exists(pid_file))
  {
    unlink(pid_file);
  }
}

/* daemonize: turn the process into a daemon a la Stevens */
static void
daemonize()
{
  /* ignore TTY signals, if necessary */

#ifdef SIGTOU
  signal(SIGTOU, SIG_IGN);
#endif
#ifdef SIGTIN
  signal(SIGTIN, SIG_IGN);
#endif
#ifdef SIGTSTP
  signal(SIGTSTP, SIG_IGN);
#endif

  /* force the process into the background */
  switch (fork())
  {
  case -1:
    log(L_LOG_ERR, CONFIG, "run_server_in_background: fork error");
    exit(1);
  case 0:
    /* child */
    break;
  default:
    /* parent */
    exit(0);
  }

  /* disassociate from the process group if we know how */
#ifdef HAVE_SETSID
  if (setsid() < 0)
  {
    log(L_LOG_ALERT, CONFIG, "setsid failed: %s", strerror(errno));
    exit(1);
  }
#endif

  umask(0);
}

/* the sigchld signal handler */
static RETSIGTYPE
sigchld_handler(arg)
  int   arg;
{
  int       status;
  pid_t     pid;

  /* use waitpid instead of wait to avoid blocking forever.  From
     Stevens.. */
  while ( (pid = waitpid((pid_t)-1, &status, WNOHANG)) > 0)
  {
    num_children--;
  }

  /* reset the signal handler -- some older systems remove the signal
     handler upon use.  POSIX systems should not do this */
  signal(SIGCHLD, sigchld_handler);
}

static RETSIGTYPE
sighup_handler(arg)
  int   arg;
{
  hup_recvd = TRUE;
  signal(SIGHUP, sighup_handler);
}

static RETSIGTYPE
exit_handler(arg)
  int   arg;
{
  log(L_LOG_NOTICE, UNKNOWN, "Exiting");
  delpid();
  exit(0);
}

static void
set_sighup()
{
  signal(SIGHUP, sighup_handler);
}

/* this actually handles all the normal quitting signals */
static void
set_exithandler()
{
  signal(SIGINT, exit_handler);
  signal(SIGTERM, exit_handler);
}

static void
reinit()
{
  log(L_LOG_NOTICE, CONFIG, "Hangup received -- reinitializing");

  initialize();

  setup_logging();

  if (is_daemon_server())
  {
    init_slave_auth_areas();
  }

  log(L_LOG_NOTICE, CONFIG, "server re-initialized");
  if (num_children > 0)
  {
    log(L_LOG_NOTICE, CONFIG, "%d child(ren) did not reinitialize",
        num_children);
  }
}

/* -------------------- Public Functions ---------------- */

void
no_zombies()
{
  /* we need the sigchld handler to limit the number of concurrent
     processes */
  signal(SIGCHLD, sigchld_handler);
}

int
run_daemon()
{
#ifdef HAVE_IPV6
  struct sockaddr_storage client_addr;
  struct sockaddr_in6     server_addr;
#else
  struct sockaddr_in    client_addr;
  struct sockaddr_in    server_addr;
#endif
  int                   sockfd;
  int                   newsockfd;
  int                   clilen;
  int                   childpid;
  int                   one          = 1;
  int                   port         = get_port();
  int                   failure      = 0;

#ifdef HAVE_IPV6
  /* This will accept both IPv4 and IPv6 connections on any interface
     including the loopback so that a local client can send to us. */
  if ( ( sockfd = socket( AF_INET6, SOCK_STREAM, IPPROTO_TCP ) ) < 0 )
#else
  if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
#endif
  {
    log(L_LOG_ERR, CONFIG, "run_daemon: Can not open socket: %s",
        strerror(errno));
    exit (1);
  }

  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one))
      < 0)
  {
    log(L_LOG_ERR, CONFIG,
        "run_daemon: Can not set socket options SO_REUSEADDR");
    exit(1);
  }

#ifdef NEED_LINGER
  {
    struct linger li;

    li.l_onoff = 1;
    li.l_linger = 15;
    setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (char *)&li,
               sizeof(struct linger));
  }
#endif  /* NEED_LINGER */

  /* for now, we will bind to all IP interfaces (INADDR_ANY) */
  /* Bind our local address so that the client can send to us */
  bzero((char *)&server_addr, sizeof(server_addr));
#ifdef HAVE_IPV6
  server_addr.sin6_family = AF_INET6;
  server_addr.sin6_port = htons(port);
  server_addr.sin6_addr = in6addr_any;
#else
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
#endif

  if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
  {
    log(L_LOG_ERR, CONFIG, "run_daemon: Can not bind socket: %s",
        strerror(errno));
    exit(1);
  }

  listen(sockfd, get_listen_queue_length());

  no_zombies();

  if (get_background())
  {
    /* put ourselves in the background */
    daemonize();
  }

  /* now that the socket has been successfully contstructed, and we
     have daemonized (if we are going to, record the pid */
  logpid();

  init_slave_auth_areas();

  set_exithandler();
  set_sighup();

  log(L_LOG_NOTICE, CONFIG, "rwhoisd ready to answer queries");

  /* main loop: accepts a client connection and then forks off a child
     to handle it */
  for (;;)
  {
    if (hup_recvd)
    {
      reinit();
      hup_recvd = FALSE;
    }

    clilen = sizeof(client_addr);
    newsockfd = accept(sockfd, (struct sockaddr *) &client_addr, &clilen);
    if (newsockfd < 0)
    {
      if (errno == EINTR)
      {
        continue;
      }
      fprintf(stderr, "run_daemon: accept error: %s\n", strerror(errno));
      continue;
    }

    failure = 0;

    if ((childpid = fork()) <  0)
    {
      fprintf(stderr, "run_daemon: fork error: %s\n", strerror(errno));
      exit(1);
    }
    else if (childpid  ==  0)
    {
      /* reset the child signal handler (don't need it anymore) */
      signal(SIGCHLD, SIG_DFL);
      /* this is the child */

      /* reset stdin and stdout to newsockfd */
      close(0); close(1);
      if (dup2(newsockfd, 0) == -1)
      {
        log(L_LOG_ERR, CONFIG, "run_daemon: dup error: %s", strerror(errno));
        exit(1);
      }
      if (dup2(newsockfd, 1) == -1)
      {
        log(L_LOG_ERR, CONFIG, "run_daemon: dup error: %s", strerror(errno));
        exit(1);
      }

      close(sockfd);

      if (!authorized_client())
      {
        log(L_LOG_NOTICE, CLIENT, "rejected rwhoisd connection");
        exit(1);
      }

      log(L_LOG_INFO, CLIENT, "accepted rwhois connection");

      /* renice the process if we have something to do.
         Note: negative offsets will only work if we run the daemon as
         root. */
      if (get_child_priority() != 0)
      {
        nice(get_child_priority());
      }

      /* do the real work */
      if (get_max_children() > 0 && num_children >= get_max_children())
      {
        /* ...or not */
        run_session(FALSE);
      }
      else
      {
        run_session(TRUE);
      }

      close(newsockfd);

      exit(0);
    }
    else
    {
      /* else this is the parent */
      close(newsockfd);
      num_children++;
    }
  } /* for (;;) */

  /* will never actually hit this */
  return TRUE;
}


