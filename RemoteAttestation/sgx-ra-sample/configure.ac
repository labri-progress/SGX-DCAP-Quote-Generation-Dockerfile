AC_INIT(sgxautosample, 1.0, john.p.mechalas@intel.com)

AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([foreign])

AC_PROG_CXX
AC_PROG_CPP
AC_PROG_INSTALL
AM_PROG_CC_C_O
AC_PROG_RANLIB

AC_CONFIG_HEADERS([config.h])

SGX_INIT()

AC_ARG_ENABLE([dcap],
[  --enable-dcap    Use DCAP mode],
[case "${enableval}" in
  yes) dcap=true ;;
  no)  dcap=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-dcap]) ;;
esac],[dcap=true])
AM_CONDITIONAL([DCAP], [test x$dcap = xtrue])

AC_ARG_WITH([openssldir],
	[AC_HELP_STRING([--with-openssl=DIR], [Specify location of OpenSSL package])],
	[openssl=$withval],[])

dnl Are we building against SGX SDK 2.5 which required the bool type?
dnl ----------------------------------------------------------------------
AC_EGREP_HEADER([bool refresh_att_key],
	[$SGXSDK/include/sgx_uae_service.h],
	[
		AC_DEFINE([UAE_SERVICE_HAS_BOOL], [1],
			[Define if sgx_uae_service.h uses the bool type])
	], []
)

dnl Need xxd
dnl ----------------------------------------------------------------------
AC_PATH_PROG([have_xxd], [xxd], [])
AS_IF([test "$have_xxd" = ""], AC_MSG_ERROR([xxd not installed]))

dnl Check for OpenSSL 1.1.0 or later
dnl ----------------------------------------------------------------------
AS_IF([test "$openssl" != ""], [
	old_LDFLAGS="$LDFLAGS"
	old_LIBS="$LIBS"
	old_CPPFLAGS="$CPPFLAGS"
	LDFLAGS="$LDFLAGS -L${openssl}/lib"
])

AC_CHECK_HEADERS([openssl/evp.h openssl/x509.h openssl/pem.h],,[
	AC_MSG_ERROR([Need OpenSSL header files])
])

AC_SEARCH_LIBS([ECDSA_SIG_set0], [crypto], [], [
	AC_MSG_ERROR([Need OpenSSL v1.1.0 or later])
])
AS_IF([test "$openssl" != ""], [
	LDFLAGS="$old_LDFLAGS"
	LIBS="$old_LIBS"
	CPPFLAGS="$old_CPPFLAGS"
	AC_SUBST([OPENSSL_CPPFLAGS], [-I$openssl/include])
	AC_SUBST([OPENSSL_LDFLAGS], [-L$openssl/lib])
	AC_SUBST([OPENSSL_LIBDIR], [$openssl/lib])
])

dnl Find default CA bundle that works with OpenSSL apps, if possible.
dnl ----------------------------------------------------------------------
ac_cv_default_ca_bundle_auto="not found"
AC_MSG_CHECKING([CA bundle file])
trydirs="/etc/ssl/certs /etc/pki/tls"
tryfiles="ca-bundle.crt ca-certificates.crt cert.pem"
for dir in $trydirs; do
	for file in $tryfiles; do
		AS_IF([test -f $dir/$file],
			[ac_cv_default_ca_bundle_auto=$dir/$file; break 2])
	done
done
AC_MSG_RESULT([$ac_cv_default_ca_bundle_auto])
AS_IF([ test "$ac_cv_default_ca_bundle_auto" = "not found" ],
	[ac_cv_default_ca_bundle_auto=""])
AC_DEFINE_UNQUOTED([DEFAULT_CA_BUNDLE_AUTO], ["$ac_cv_default_ca_bundle_auto"],
	[Default CA bundle for OpenSSL-based applications])

dnl Write our configuration
dnl ----------------------------------------------------------------------
AC_CONFIG_FILES([
	mrsigner.sh
	run-server:run.in
	run-client:run.in
	Makefile
	Enclave/Makefile
	ProvisioningEnclave/Makefile
],[chmod -f 755 run-client run-server mrsigner.sh])

AC_OUTPUT
