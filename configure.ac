dnl Process this file with autoconf to produce a configure script.
AC_INIT(flow-tools, 0.68.4-rc5, flow-tools@googlegroups.com)

AC_PREFIX_DEFAULT(/usr/local/flow-tools)

AM_INIT_AUTOMAKE([foreign dist-bzip2])
AM_CONFIG_HEADER(lib/ftconfig.h) 

dnl CFLAGS="-g -Wall"

dnl Checks for programs.
AC_PROG_LIBTOOL
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_YACC
AM_PROG_LEX

AC_SUBST(YLIB)
AC_SUBST(MYSQLLIB)
AC_SUBST(MYSQLCFLAGS)
AC_SUBST(MYSQLLDFLAGS)
AC_SUBST(CRYPTOLIB)
AC_SUBST(OPENSSLINCLUDE)
AC_SUBST(OPENSSLLDFLAGS)

dnl extra argument: --with-mysql
WITH_MYSQL=
AC_ARG_WITH(mysql, 
  AS_HELP_STRING([[[[[--with-mysql[=PATH]]]]]], [Compile in MySQL support. (default=no)]),
[ if test -x "$withval"; then
    WHERE_MYSQL=$withval
  else
    WHERE_MYSQL="/usr"
  fi
]
)

AX_LIB_POSTGRESQL

AC_SUBST(POSTGRESQL_LIB)

if test "x$found_postgresql" = "xyes" ; then
  POSTGRESQL_LIB=-lpq
fi

dnl extra argument: --with-openssl
WITH_OPENSSL=
AC_ARG_WITH(openssl,
  AS_HELP_STRING([[[[[--with-openssl[=PATH]]]]]], [Compile in OpenSSL support. (default=no)]),
[ if test -x "$withval"; then
    WHERE_OPENSSL=$withval
  else
    WHERE_OPENSSL="/usr"
  fi
]
)

dnl Checks for libraries.

if test "x$WHERE_MYSQL" != "x"; then
  old_LIBS="$LIBS"
  old_LDFLAGS="$LDFLAGS"
  LDFLAGS="$LDFLAGS -L$WHERE_MYSQL/lib/mysql"
  AC_CHECK_LIB(mysqlclient, my_init,
    [
      MYSQLCFLAGS="-I$WHERE_MYSQL/include/mysql"
      MYSQLLDFLAGS="-L$WHERE_MYSQL/lib/mysql"
      MYSQLLIB="-lmysqlclient"
      AC_DEFINE(HAVE_MYSQL, 1, [Do we have to build MySQL support])
    ]
  )
  LIBS="$old_LIBS"
  LDFLAGS="$old_LDFLAGS"
fi

if test "x$WHERE_OPENSSL" != "x"; then
  old_LIBS="$LIBS"
  old_LDFLAGS="$LDFLAGS"
  LDFLAGS="$LDFLAGS -L$WHERE_OPENSSL/lib"
  AC_CHECK_LIB(crypto, EVP_EncryptUpdate,
    [
      OPENSSLCFLAGS="-I$WHERE_OPENSSL/include"
      OPENSSLLDFLAGS="-L$WHERE_OPENSSL/lib"
      CRYPTOLIB="-lcrypto"
      AC_DEFINE(HAVE_OPENSSL, 1, [Do we have to include OpenSSL support])
    ]
  )
  LIBS="$old_LIBS"
  LDFLAGS="$old_LDFLAGS"
fi

AC_CHECK_LIB(y, main,YLIB="$YLIB -ly",)
AC_CHECK_LIB(z, zlibVersion)
case "X$LIBS" in
*-lz*)
   ;;
*)
   AC_MSG_ERROR(Link with "-lz" (zlib >= 1.0.2) failed!)
   ;;
esac
AC_CHECK_LIB(wrap,allow_severity)

dnl Conditionally enable PIE support for GNU toolchains.
enable_pie=yes

AC_ARG_ENABLE(pie, AS_HELP_STRING([--disable-pie], [Do not build tools as a Position Independent Executables]))
if test "$enable_pie" = "yes"; then
  AC_CACHE_CHECK([whether $CC accepts PIE flags], [ap_cv_cc_pie], [
    save_CFLAGS=$CFLAGS
    save_LDFLAGS=$LDFLAGS
    CFLAGS="$CFLAGS -fPIE"
    LDFLAGS="$LDFLAGS -pie"
    AC_TRY_RUN([static int foo[30000]; int main () { return 0; }],
     [ap_cv_cc_pie=yes], [ap_cv_cc_pie=no], [ap_cv_cc_pie=yes])
    CFLAGS=$save_CFLAGS
    LDFLAGS=$save_LDFLAGS
  ])
  if test "$ap_cv_cc_pie" = "yes"; then
    PICFLAGS="-fPIE"
    PILDFLAGS="-pie"
  fi
fi

AC_SUBST(PICFLAGS)
AC_SUBST(PILDFLAGS)

dnl Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h features.h limits.h malloc.h string.h strings.h sys/time.h syslog.h unistd.h)

# from cvs
echo $ac_n "checking for sin_len in sockaddr_in ... $ac_c"
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>],
[struct sockaddr_in sock; sock.sin_len = sizeof(sock);],
echo yes;AC_DEFINE(HAVE_SOCK_SIN_LEN, 1, [Do we have sock.sin_len]), 
echo no)


AC_DEFINE(_BSD_SOURCE, 1, [We need BSD compatibility])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_STRUCT_ST_RDEV
AC_HEADER_TIME
AC_STRUCT_TM

dnl Checks for library functions.
AC_FUNC_MMAP
AC_FUNC_ALLOCA
AC_TYPE_SIGNAL
AC_CHECK_LIB(nsl,gethostbyname)
AC_CHECK_LIB(socket,socket)
AC_CHECK_FUNCS(gethostname gettimeofday select socket strdup strtoul)
AC_CHECK_FUNCS(timelocal)
AC_CHECK_FUNCS(sigaction)
AC_CONFIG_LIBOBJ_DIR([lib])
AC_REPLACE_FUNCS(strsep strerror strtoull)

AC_SYS_LARGEFILE

AC_OUTPUT([
  lib/Makefile
  src/Makefile 
  bin/Makefile
  Makefile
  docs/Makefile 
  configs/Makefile
  utils/Makefile
])

