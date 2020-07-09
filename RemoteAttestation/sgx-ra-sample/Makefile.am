## This must come first when building an application that uses Intel
## SGX enclaves.

include $(top_srcdir)/build-aux/sgx_app.am

## It sets the following automake variables:
##
##   AM_CPPFLAGS = -I$(SGXSDK_INCDIR)
##   AM_LDFLAGS = -L$(SGXSDK_LIBDIR)
##
## And a pattern rule for building proxy functions from EDL files:
##
##   %_u.h %_u.c: %.edl
##
## And sets these Makefile variables:
##
##   SGXSDK
##   SGXSDK_BINDIR
##   SGXSDK_INCDIR
##   SGXSDK_LIBDIR
##   SGXSSL
##   SGXSSL_BINDIR
##   SGXSSL_INCDIR
##   SGXSSL_LIBDIR
##   SGX_URTS_LIB
##   SGX_UAE_SERVICE_LIB
##   SGX_EDGER8R

SUBDIRS = Enclave ProvisioningEnclave

## Supply additional flags to edger8r here.
##
## SGX_EDGER8R_FLAGS=


## Needed to make our pattern rule work

Enclave.edl: Enclave/Enclave.edl
	ln -s $?

Enclave.signed.so: Enclave/Enclave.signed.so
	ln -s $?

Enclave/Enclave.signed.so:
	make -C Enclave

## Needed to make our pattern rule work

ProvisioningEnclave.edl: ProvisioningEnclave/ProvisioningEnclave.edl
	ln -s $?

ProvisioningEnclave.signed.so: ProvisioningEnclave/ProvisioningEnclave.signed.so
	ln -s $?

ProvisioningEnclave/ProvisioningEnclave.signed.so: policy
	make -C ProvisioningEnclave

## Additional automake variables
##
## AM_CPPFLAGS +=
## AM_CFLAGS =

AM_CXXFLAGS = -std=c++11

AM_CPPFLAGS += -fno-builtin-memset @OPENSSL_CPPFLAGS@

## Additional targets to remove with 'make clean'. You must list
## any edger8r generated files here.

CLEANFILES = Enclave_u.c Enclave_u.h Enclave.edl Enclave.signed.so \
	ProvisioningEnclave_u.c ProvisioningEnclave_u.h ProvisioningEnclave.edl ProvisioningEnclave.signed.so \
	policy enclave_sigstruct_raw


## The build target

server: sp

bin_PROGRAMS = client sp mrsigner

## You can't use $(wildcard ...) with automake so all source files
## have to be explicitly listed.

common = common.cpp hexutil.c fileio.c \
	msgio.cpp logfile.c

## client

client_SOURCES = client.cpp sgx_detect_linux.c sgx_stub.c \
	$(common)
nodist_client_SOURCES = Enclave_u.c Enclave_u.h
EXTRA_client_DEPENDENCIES = Enclave.signed.so
BUILT_SOURCES = Enclave_u.c Enclave_u.h

client_LDFLAGS= $(AM_LDFLAGS) @OPENSSL_LDFLAGS@

## sp

sp_SOURCES = sp.cpp quote_verify.cpp $(common)
BUILT_SOURCES += policy ProvisioningEnclave_u.c ProvisioningEnclave_u.h
EXTRA_sp_DEPENDENCIES = ProvisioningEnclave.signed.so

## mrsigner (helper app)

mrsigner_SOURCES = mrsigner.cpp hexutil.c crypto.c

## Extract the enclave SIGSTRUCT and use it to calculate MRSIGNER
policy: mrsigner policy.in.h Enclave.signed.so
	$(SGX_SIGN) dump -cssfile enclave_sigstruct_raw -dumpfile /dev/null -enclave Enclave.signed.so
	sed -e "s^@MRSIGNER@^`./mrsigner.sh enclave_sigstruct_raw`^" policy.in.h > policy.h
	rm -f enclave_sigstruct_raw

sp_LDFLAGS= $(AM_LDFLAGS) @OPENSSL_LDFLAGS@
mrsigner_LDFLAGS= $(AM_LDFLAGS) @OPENSSL_LDFLAGS@

## Library flags. At minimum, an Intel SGX application will need:
##
##   -l$(SGX_URTS_LIB)
##
## Applications that use platform services or perform attestation
## will also need:
##
##  -l$(SGX_UAE_SERVICE_LIB)
##
## Use the variables, not the actual library names to ensure these
## targets work on simulation builds.

client_LDADD=-l$(SGX_URTS_LIB) -lsgx_ukey_exchange -l$(SGX_UAE_SERVICE_LIB) \
	-lcrypto -l:libsgx_capable.a -lpthread -ldl

mrsigner_LDADD=-lcrypto

nodist_sp_SOURCES = ProvisioningEnclave_u.c ProvisioningEnclave_u.h
sp_LDADD=-lsgx_dcap_ql -lsgx_dcap_quoteverify -l$(SGX_URTS_LIB) -lcrypto -ldl \
					-lsgx_usgxssl # SGX SSL
