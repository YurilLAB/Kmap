dnl Defaults are prepended so explicit user CFLAGS/CXXFLAGS/LDFLAGS win.
dnl Link, rather than just compile: stack protection can require runtime symbols.
AC_DEFUN([KMAP_STACK_PROTECTOR], [
  AC_LANG_PUSH([$1])
  AC_MSG_CHECKING([for $1 stack protection])
  kmap_saved_flags="$$2"
  kmap_stack_protector=none
  for kmap_flag in -fstack-protector-strong -fstack-protector; do
    $2="$kmap_flag $kmap_saved_flags"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([], [[
      volatile char buffer[64]; buffer[0] = 0; return buffer[0];
    ]])], [kmap_stack_protector=$kmap_flag; break], [])
  done
  if test "$kmap_stack_protector" = none; then
    $2="$kmap_saved_flags"
  fi
  AC_MSG_RESULT([$kmap_stack_protector])
  AC_LANG_POP([$1])
])

AC_DEFUN([KMAP_CHECK_HARDENING], [
  AC_ARG_ENABLE([hardening],
    [AS_HELP_STRING([--disable-hardening], [omit automatically detected stack/RELRO flags])],
    [], [enable_hardening=yes])
  AS_CASE([$enable_hardening], [yes|no], [],
    [AC_MSG_ERROR([--enable-hardening accepts only yes or no])])
  KMAP_SSP_LDFLAGS=
  if test "$enable_hardening" = yes; then
    dnl Some drivers warn and ignore unknown options. Reject those probes too,
    dnl without imposing -Werror on the user's subsequent build or checks.
    kmap_saved_c_werror_flag=$ac_c_werror_flag
    kmap_saved_cxx_werror_flag=$ac_cxx_werror_flag
    ac_c_werror_flag=yes
    ac_cxx_werror_flag=yes
    KMAP_STACK_PROTECTOR([C], [CFLAGS])
    KMAP_STACK_PROTECTOR([C++], [CXXFLAGS])
    if test "$kmap_stack_protector" != none; then
      KMAP_SSP_LDFLAGS=$kmap_stack_protector
    fi

    dnl -z relro/now are ELF linker options. Do not offer them to Mach-O/PE
    dnl linkers, even if a driver would silently ignore the unknown flags.
    AC_LANG_PUSH([C++])
    AC_MSG_CHECKING([for ELF full RELRO linking])
    kmap_saved_ldflags="$LDFLAGS"
    kmap_relro=no
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#ifndef __ELF__
#error not an ELF target
#endif
    ]], [])], [
      LDFLAGS="-Wl,-z,relro,-z,now $kmap_saved_ldflags"
      AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])], [kmap_relro=yes], [])
      if test "$kmap_relro" = yes; then
        AC_LANG_PUSH([C])
        AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])], [], [kmap_relro=no])
        AC_LANG_POP([C])
      fi
    ], [])
    if test "$kmap_relro" != yes; then
      LDFLAGS="$kmap_saved_ldflags"
    fi
    AC_MSG_RESULT([$kmap_relro])
    AC_LANG_POP([C++])
    ac_c_werror_flag=$kmap_saved_c_werror_flag
    ac_cxx_werror_flag=$kmap_saved_cxx_werror_flag
  fi
  dnl The executable links with CXX but without CXXFLAGS. Some toolchains use
  dnl the supported stack option to select libssp at link time. It does not
  dnl instrument objects during linking: user compile-time -fno options still
  dnl take effect, while protected C objects retain their runtime support.
  AC_SUBST([KMAP_SSP_LDFLAGS])
])
