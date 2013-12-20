# This file is part of the VMI-Honeymon project.
#
# 2012-2013 University of Connecticut (http://www.uconn.edu)
# Tamas K Lengyel (tamas.k.lengyel@gmail.com)
#
#  VMI-Honeymon is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, see <http://www.gnu.org/licenses/>.

AC_PREREQ([2.60])
AC_INIT([VMI-Honeymon], [2.1], [tamas.k.lengyel@gmail.com], [], [http://github.com/tklengyel/vmi-honeymon])
AM_INIT_AUTOMAKE([1.10 no-define foreign])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CXX

# AUTOHARDEN START
# We want to check for compiler flag support, but there is no way to make
# clang's "argument unused" warning fatal.  So we invoke the compiler through a
# wrapper script that greps for this message.
saved_CC="$CC"
saved_CXX="$CXX"
saved_LD="$LD"
flag_wrap="$srcdir/scripts/wrap-compiler-for-flag-check"
CC="$flag_wrap $CC"
CXX="$flag_wrap $CXX"
LD="$flag_wrap $LD"

# We use the same hardening flags for C and C++.  We must check that each flag
# is supported by both compilers.
AC_DEFUN([check_cc_cxx_flag],
 [AC_LANG_PUSH(C)
  AX_CHECK_COMPILE_FLAG([$1],
   [AC_LANG_PUSH(C++)
    AX_CHECK_COMPILE_FLAG([$1], [$2], [$3], [-Werror $4])
    AC_LANG_POP(C++)],
   [$3], [-Werror $4])
  AC_LANG_POP(C)])
AC_DEFUN([check_link_flag],
 [AX_CHECK_LINK_FLAG([$1], [$2], [$3], [-Werror $4])])

AC_ARG_ENABLE([hardening],
  [AS_HELP_STRING([--enable-hardening],
    [Enable compiler and linker options to frustrate memory corruption exploits @<:@yes@:>@])],
  [hardening="$enableval"],
  [hardening="yes"])
  
AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug],
    [Enable verbose debug output to be compiled @<:@no@:>@])],
  [debug="$enableval"],
  [debug="no"])   

AM_CONDITIONAL([DEBUG], [test x$debug = xyes])
AM_CONDITIONAL([HARDENING], [test x$hardening = xyes])  

HARDEN_CFLAGS=""
HARDEN_LDFLAGS=""
AS_IF([test x"$hardening" != x"no"], [
  check_cc_cxx_flag([-fno-strict-overflow], [HARDEN_CFLAGS="$HARDEN_CFLAGS -fno-strict-overflow"])

#  This one will likely succeed, even on platforms where it does nothing.
  check_cc_cxx_flag([-D_FORTIFY_SOURCE=2], [HARDEN_CFLAGS="$HARDEN_CFLAGS -D_FORTIFY_SOURCE=2"])

  check_cc_cxx_flag([-fstack-protector-all],
   [check_link_flag([-fstack-protector-all],
     [HARDEN_CFLAGS="$HARDEN_CFLAGS -fstack-protector-all"
      check_cc_cxx_flag([-Wstack-protector], [HARDEN_CFLAGS="$HARDEN_CFLAGS -Wstack-protector"],
        [], [-fstack-protector-all])
      check_cc_cxx_flag([--param ssp-buffer-size=1], [HARDEN_CFLAGS="$HARDEN_CFLAGS --param ssp-buffer-size=1"],
        [], [-fstack-protector-all])])])

  # At the link step, we might want -pie (GCC) or -Wl,-pie (Clang on OS X)
  #
  # The linker checks also compile code, so we need to include -fPIE as well.
  check_cc_cxx_flag([-fPIE],
   [check_link_flag([-fPIE -pie],
     [HARDEN_CFLAGS="$HARDEN_CFLAGS -fPIE"
      HARDEN_LDFLAGS="$HARDEN_LDFLAGS -pie"],
     [check_link_flag([-fPIE -Wl,-pie],
       [HARDEN_CFLAGS="$HARDEN_CFLAGS -fPIE"
        HARDEN_LDFLAGS="$HARDEN_LDFLAGS -Wl,-pie"])])])

  check_link_flag([-Wl,-z,relro],
   [HARDEN_LDFLAGS="$HARDEN_LDFLAGS -Wl,-z,relro"
    check_link_flag([-Wl,-z,now], [HARDEN_LDFLAGS="$HARDEN_LDFLAGS -Wl,-z,now"])])])

AC_SUBST([HARDEN_CFLAGS])
AC_SUBST([HARDEN_LDFLAGS])

# End of flag tests.
CC="$saved_CC"
CXX="$saved_CXX"
LD="$saved_LD"
# AUTOHARDEN END

AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h malloc.h stdio.h stdlib.h string.h sys/time.h sys/mman.h syslog.h unistd.h errno.h pthread.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_VPRINTF

PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.28], [], [AC_ERROR([glib-2.0 (version 2.28+) has to be installed!])])
AC_CHECK_LIB(glib-2.0, [g_malloc0, g_tree_lookup], [], [AC_ERROR([glib-2.0 library is not functional!])]) 
AC_CHECK_LIB(pthread, pthread_create, [], [AC_ERROR([Pthread library is not functional!])])

PKG_CHECK_MODULES([VMI], [libvmi], [], [AC_ERROR([LibVMI not found])])

AC_CHECK_HEADER([lvm2app.h], [], [AC_ERROR([No lvm2app.h found])], [[#include <libdevmapper.h>]])
AC_CHECK_LIB(lvm2app, lvm_lv_snapshot, [], [AC_ERROR([LibLVM (lvm2app) is unusable])])

AC_CHECK_HEADERS([libxl.h libxl_utils.h], [], [AC_ERROR([Standard Xenlight (libxl) headers not found!])])
AC_CHECK_LIB(xenlight, 
	[libxl_domain_create_new, libxl_domain_destroy, libxl_domain_suspend, 
	libxl_domain_resume, libxl_domain_pause, libxl_domain_unpause, 
	libxl_domain_create_restore,libxl_domain_config_init], 
	[], [AC_ERROR([Xenlight does not have required features!])])

AC_CHECK_HEADER([libxlutil.h], [
            AC_DEFINE(HAVE_LIBXLUTIL_H, 1, "libxlutil.h was found installed on the system")
        ],
        [
            AC_MSG_NOTICE([libxlutil.h didn't get installed with Xen, using our own copy!])
        ]
)
AC_CHECK_LIB([xlutil], [xlu_cfg_init, xlu_cfg_readfile, xlu_cfg_readdata, xlu_cfg_destroy], [], [AC_ERROR([libxlutil doesn't support required functions!])])

# Check for XL
AC_PATH_PROG(XL, xl)
if test "x$XL" != "x"; then
    AC_DEFINE_UNQUOTED(XL, "$XL", "XL path")
else
    AC_ERROR([XL was not found!])
fi

AC_CHECK_HEADER([xenstore.h])
AC_CHECK_LIB(xenstore, [xc_read, xs_transaction_start], [], [AC_ERROR([Xenstore not found!])])

# Check for Xenctrl and memory sharing

AC_CHECK_HEADERS([xenctrl.h], [], [AC_ERROR([XenCtrl missing! Did you install Xen yet?])])

AC_CHECK_LIB([xenctrl], 
	[xc_interface_open, xc_memshr_control, xc_memshr_nominate_gfn, xc_memshr_share_gfns], 
	[], [AC_ERROR([XenCtrl is unusable! Do you have Xen 4.2+ installed?])])

# Check for LibGuestFS
AC_CHECK_LIB(guestfs, 
	[guestfs_create, guestfs_add_drive_ro, guestfs_launch, guestfs_mount, 
	guestfs_copy_device_to_file, guestfs_checksum, guestfs_shutdown, guestfs_close],
	[],
	[AC_MSG_NOTICE([*** No LibGuestFS present])])

AC_CHECK_HEADER([magic.h], [
    AC_CHECK_LIB(magic, [magic_open, magic_load, magic_close, magic_file])
])

# Check for MySQL
AC_PATH_PROG(MYSQL_CONFIG, mysql_config)
if test "x$MYSQL_CONFIG" != "x"; then
	MYSQL_LIBS=$($MYSQL_CONFIG --libs_r)
	MYSQL_CFLAGS=$($MYSQL_CONFIG --cflags)

        AC_DEFINE(HAVE_MYSQL, 1, "Working MySQL library found")
        AC_MSG_NOTICE([Enabling MySQL logging])
        AC_SUBST(MYSQL_LIBS)
        AC_SUBST(MYSQL_CFLAGS)
else
        AC_MSG_NOTICE([*** No working MySQL library found, disabling MySQL logging!])
fi

AC_PATH_PROG(XMLRPC_C_CONFIG, xmlrpc-c-config)
if test "x$XMLRPC_C_CONFIG" != "x"; then

    PKG_CHECK_MODULES([CURL], [libcurl], [
    
        XMLRPC_SERVER_LIBS=$($XMLRPC_C_CONFIG abyss-server --libs)
        XMLRPC_SERVER_CFLAGS=$($XMLRPC_C_CONFIG abyss-server --cflags)
        XMLRPC_CLIENT_LIBS=$($XMLRPC_C_CONFIG client --libs)
        XMLRPC_CLIENT_CFLAGS=$($XMLRPC_C_CONFIG client --cflags)
    
        AC_DEFINE(HAVE_XMLRPC, 1, "Working XMLRPC C library found")
    
        AC_SUBST(XMLRPC_SERVER_LIBS)
        AC_SUBST(XMLRPC_SERVER_CFLAGS)
        AC_SUBST(XMLRPC_CLIENT_LIBS)
        AC_SUBST(XMLRPC_CLIENT_CFLAGS)
    
        #xmlrpc_client="tools/xmlrpc_client"
        #AC_SUBST(xmlrpc_client)
        #AC_CONFIG_FILES(tools/xmlrpc_client/Makefile)
    
    ], [AC_ERROR(No CURL installed)])

fi

# Check for SQlite3
#PKG_CHECK_MODULES([SQLITE3], [sqlite3], 
#	[AC_DEFINE(HAVE_SQLITE3, 1, "Working SQlite3 library found")], 
#	[AC_MSG_NOTICE([*** No working SQlite3 library found, disabling SQlite3 logging!])])

AC_CONFIG_FILES([Makefile src/Makefile tools/magic-test/Makefile])
AC_OUTPUT

