dnl Process this file with autoconf to produce a configure script.
dnl This has been updated to use autoconf-2.52.

AC_INIT
AC_CONFIG_SRCDIR([common/attributes.c])

AC_CHECK_TOOL(AR, ar, false)

dnl Random substitution variables
if test -f VERSION; then
	RWHOIS_VERSION=`cat VERSION`
elif test -f ../VERSION; then
	RWHOIS_VERSION=`cat ../VERSION`
elif test -f `dirname $0`/VERSION; then
	vfile=`dirname $0`/VERSION
	RWHOIS_VERSION=`cat $vfile`
else
	RWHOIS_VERSION="unknown"
fi
AC_DEFINE_UNQUOTED(RWHOIS_SERVER_VERSION, "$RWHOIS_VERSION", 
  [Build/Version number of the server.])

SAMPLE_DATA_DIR=`pwd`/sample.data
AC_SUBST(SAMPLE_DATA_DIR)

AC_CONFIG_HEADER(config.h)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_GCC_TRADITIONAL
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_PROG_LEX     
if test "$LEX" != flex; then
   LEX="$SHELL $missing_dir/missing flex"
   AC_SUBST(LEX_OUTPUT_ROOT, lex.yy)
   AC_SUBST(LEXLIB, '')
fi
AC_PROG_YACC

AC_PREFIX_DEFAULT(/usr/local/rwhoisd)
# AC_PREFIX_PROGRAM(rwhoisd)

dnl Checks for libraries.
# AC_CHECK_LIB(c, strcpy)
# AC_CHECK_LIB(y, yyerror)
AC_CHECK_LIB(crypt, crypt)
AC_CHECK_LIB(nsl, gethostbyname)
AC_CHECK_LIB(resolv, res_search)
AC_CHECK_LIB(socket, connect)
AC_CHECK_LIB(inet, connect)

# check for the libwrap library: we (apparently) cannot just use the
# standard AC_CHECK_LIB() macro, because the test program may need to
# define a few variables.  Some OS versions of libwrap don't have this
# problem, but we cannot rely on that.

# check for the libwrap library the normal way.
AC_CHECK_LIB(wrap, hosts_access, build_libwrap=no, build_libwrap=yes)

# check for libwrap library the manual way.
if test "${build_libwrap}" = "yes"; then
   ac_check_lib_save_LIBS=$LIBS
   LIBS="-lwrap $LIBS"
   AC_MSG_CHECKING(for hosts_access in -lwrap (again))
   AC_LINK_IFELSE([ 
int allow_severity;
int deny_severity;
extern int hosts_access(void);

int main(void)
{
	hosts_access();
}
], 
   AC_MSG_RESULT(yes)
   build_libwrap=no,

   AC_MSG_RESULT(no)
   LIBS=$ac_check_lib_save_LIBS
)

fi

dnl Checks for header files.
AC_HEADER_STDC
# AC_HEADER_MAJOR
# AC_HEADER_SYS_WAIT
AC_HEADER_DIRENT
AC_CHECK_HEADERS(stdarg.h fcntl.h sys/file.h sys/time.h syslog.h \
                 sys/wait.h crypt.h)

# NOTE: we *will* have a strerror function (see AC_REPLACE_FUNCS below)
TCPD_EXTRA_CFLAGS="-DUSE_STRERROR"

dnl Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_C_CONST
AC_TYPE_OFF_T
AC_CHECK_SIZEOF(off_t)
AC_CHECK_TYPES([uint8_t, uint32_t])
dnl for tcpd_wrappers
AC_CHECK_TYPES(uchar_t, TCPD_EXTRA_CFLAGS="$TCPD_EXTRA_CFLAGS -DHAVE_UCHAR_T")


dnl Checks for library functions.
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_SETVBUF_REVERSED
AC_CHECK_FUNCS(getcwd gethostname socket strftime uname flock lockf \
	       setsid crypt memset memcpy usleep wait3 getaddrinfo vsnprintf)
AC_REPLACE_FUNCS(strerror)


dnl Optional software.

AC_ARG_WITH(local-libwrap, AS_HELP_STRING([--with-local-libwrap], 
                           [Use local copy of tcpd_wrapper.]), 
            build_libwrap=yes)

if test "${build_libwrap}" = "yes"; then
   AC_SUBST(TCPD_EXTRA_CFLAGS)
   LIBWRAP=libwrap
   AC_SUBST(LIBWRAP)
   wrap_dir=../tools/tcpd_wrapper
   WRAP_INCLUDE=-I'$(srcdir)'/$wrap_dir
   WRAP_LIBS="-L$wrap_dir -lwrap"
else
   WRAP_INCLUDE=
   WRAP_LIBS="-lwrap"
fi
AC_SUBST(WRAP_INCLUDE)
AC_SUBST(WRAP_LIBS)       


dnl Package options
AC_ARG_ENABLE(gcc-debug, AS_HELP_STRING([--enable-gcc-debug], 
                         [Use '-g -Wall' if using gcc.]),
[ if test -n "$GCC"; then
	AC_MSG_RESULT(Setting CFLAGS to -g -Wall)
	CFLAGS="-g -Wall"
  fi])

AC_ARG_ENABLE(warnings, AS_HELP_STRING([--enable-warnings], 
                        [Enable -Wall if using gcc.]),
[ if test -n "$GCC"; then
    AC_MSG_RESULT(Adding -Wall to CFLAGS.)
    CFLAGS="$CFLAGS -Wall"
  fi])

AC_ARG_ENABLE(gprof, AS_HELP_STRING([--enable-gprof], 
                     [Enable -pg if using gcc.]),
[ if test -n "$GCC"; then
    AC_MSG_RESULT(Adding -pg to CFLAGS/LDFLAGS.)
    CFLAGS="$CFLAGS -pg"
    LDFLAGS="$LDFLAGS -pg"
  fi])

AC_ARG_ENABLE(largefile, AS_HELP_STRING([--enable-largefile], 
                         [Enable largefile (files >2GB) support.]))

AC_MSG_CHECKING([whether to enable largefile suport])
if test "${enable_largefile}" = "yes"; then
	largefile_cflags=`getconf LFS_CFLAGS 2>/dev/null`
	largefile_ldflags=`getconf LFS_LDFLAGS 2>/dev/null`
	largefile_libs=`getconf LFS_LIBS 2>/dev/null`
	if test "x$largefile_cflags" != "x"; then
		CFLAGS="${CFLAGS} $largefile_cflags"
		LDFLAGS="${LDFLAGS} $largefile_ldflags"
		LIBS="${LIBS} $largefile_libs"
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
	fi
else
	AC_MSG_RESULT([no]);
fi

dnl Check for IPv6 function
AC_ARG_ENABLE(ipv6, AS_HELP_STRING([--disable-ipv6], [Do not use IPv6]))

AC_MSG_CHECKING([whether to enable IPv6])
if test "${enable_ipv6}" = "no"; then
        AC_MSG_RESULT([disabled])
else
   dnl KAME IPv6
   if grep WIDE /usr/include/netinet6/in6.h >/dev/null 2>&1; then
      if test -d /usr/local/v6/lib -a -f /usr/local/v6/lib/libinet6.a; then
         IPV6LIBS="-L/usr/local/v6/lib -linet6"
      fi
      AC_MSG_RESULT([KAME])

   dnl Linux IPv6
   elif test x`ls /proc/net/ipv6_route 2>/dev/null` = \
             x"/proc/net/ipv6_route"; then
      AC_MSG_RESULT([Linux IPv6])

   else
      AC_MSG_RESULT([no])
      enable_ipv6=no
   fi
fi

if test "${enable_ipv6}" != "no"; then
    AC_DEFINE(HAVE_IPV6, 1, [IPv6 Function])
    AC_SUBST(IPV6LIBS)
    AC_SUBST(IPV6INCLUDES)
    AC_CHECK_FUNC(getipnodebyname, 
        AC_SUBST(IPV6_WRAP_DEFINE, "-DHAVE_IPV6"),
        AC_SUBST(IPV6_WRAP_DEFINE, "-DHAVE_IPV6 -DUSE_GETHOSTBYNAME2"))

    AC_MSG_CHECKING([for sockaddr_storage])
    AC_EGREP_HEADER(sockaddr_storage, sys/socket.h, \
	    AC_MSG_RESULT([yes])
	    AC_DEFINE(HAVE_SOCKADDR_STORAGE, 1, struct SOCKADDR_STORAGE), \
	    AC_MSG_RESULT([no]) )
fi

AC_ARG_ENABLE(syslock, AS_HELP_STRING([--enable-syslock], 
                       [Enable system level file locks (flock/lockf).]),
[ AC_DEFINE(USE_SYS_LOCK, 1, Define to use filesystem locking instead of dot-locks.) ])



dnl the output
AC_CONFIG_FILES([Makefile common/Makefile mkdb/Makefile server/Makefile \
	  regexp/Makefile tools/Makefile tools/tcpd_wrapper/Makefile \
          tools/rwhois_indexer/Makefile tools/rwhois_deleter/Makefile \
          tools/rwhois_repack/Makefile sample.data/Makefile])
AC_OUTPUT
