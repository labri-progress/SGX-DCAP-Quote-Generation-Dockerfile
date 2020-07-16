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

# Allows to reference files in different directories
AUTOMAKE_OPTIONS = subdir-objects

SUBDIRS = src/client/Enclave src/provisioning/ProvisioningEnclave

## Supply additional flags to edger8r here.
##
# SGX_EDGER8R_FLAGS=--search-path src/


## Needed to make our pattern rule work

Enclave.edl: src/client/Enclave/Enclave.edl
	ln -s $?

Enclave.signed.so: src/client/Enclave/Enclave.signed.so
	ln -s $?

src/client/Enclave/Enclave.signed.so:
	make -C src/client/Enclave

## Needed to make our pattern rule work

ProvisioningEnclave.edl: src/provisioning/ProvisioningEnclave/ProvisioningEnclave.edl
	ln -s $?

ProvisioningEnclave.signed.so: src/provisioning/ProvisioningEnclave/ProvisioningEnclave.signed.so
	ln -s $?

src/provisioning/ProvisioningEnclave/ProvisioningEnclave.signed.so: policy
	make -C src/provisioning/ProvisioningEnclave

## Additional automake variables
##
## AM_CPPFLAGS +=
## AM_CFLAGS =

AM_CXXFLAGS = -std=c++11

AM_CPPFLAGS += -fno-builtin-memset @OPENSSL_CPPFLAGS@ -I src/

## Additional targets to remove with 'make clean'. You must list
## any edger8r generated files here.

CLEANFILES = Enclave_u.c Enclave_u.h Enclave.edl Enclave.signed.so \
	ProvisioningEnclave_u.c ProvisioningEnclave_u.h ProvisioningEnclave.edl ProvisioningEnclave.signed.so \
	policy enclave_sigstruct_raw


## The build target

server: provisioning_service

bin_PROGRAMS = client provisioning_service bootstrap_service mrsigner

## You can't use $(wildcard ...) with automake so all source files
## have to be explicitly listed.

common = src/common.cpp src/common/hexutil.c src/common/msgio.cpp

## client

client_SOURCES = src/client/client.cpp src/sgx_detect_linux.c src/sgx_stub.c src/client/httplib.cpp \
	$(common)
nodist_client_SOURCES = Enclave_u.c Enclave_u.h
EXTRA_client_DEPENDENCIES = Enclave.signed.so
BUILT_SOURCES = Enclave_u.c Enclave_u.h

client_LDFLAGS= $(AM_LDFLAGS) @OPENSSL_LDFLAGS@

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
	-lcrypto -l:libsgx_capable.a -lpthread -ldl \
	-lsgx_usgxssl # SGX SSL


## provisioning_service
provisioning_service_SOURCES = src/provisioning/provisioning_service.cpp src/provisioning/quote_verify.cpp $(common)
BUILT_SOURCES += policy ProvisioningEnclave_u.c ProvisioningEnclave_u.h
EXTRA_provisioning_service_DEPENDENCIES = ProvisioningEnclave.signed.so

provisioning_service_LDFLAGS= $(AM_LDFLAGS) @OPENSSL_LDFLAGS@

nodist_provisioning_service_SOURCES = ProvisioningEnclave_u.c ProvisioningEnclave_u.h
provisioning_service_LDADD= -l$(SGX_URTS_LIB) -lsgx_ukey_exchange -l$(SGX_UAE_SERVICE_LIB) \
					-l:libsgx_capable.a -lpthread -ldl \
					-lsgx_dcap_ql -lsgx_dcap_quoteverify -l$(SGX_URTS_LIB) -lcrypto -ldl \
					-lsgx_usgxssl # SGX SSL


## bootstrap_service

bootstrap_service_SOURCES = src/bootstrap/bootstrap_service.cpp $(common) src/common/remote_attestation.cpp src/common/crypto.c src/common/byteorder.c src/common/enclave_verify.cpp
bootstrap_service_LDFLAGS= $(AM_LDFLAGS) @OPENSSL_LDFLAGS@
bootstrap_service_LDADD=-lsgx_dcap_ql -lsgx_dcap_quoteverify -lcrypto


## mrsigner (helper app)

mrsigner_SOURCES = src/mrsigner/mrsigner.cpp src/common/hexutil.c src/common/crypto.c

## Extract the enclave SIGSTRUCT and use it to calculate MRSIGNER
policy: mrsigner src/policy.in.h Enclave.signed.so
	$(SGX_SIGN) dump -cssfile enclave_sigstruct_raw -dumpfile /dev/null -enclave Enclave.signed.so
	sed -e "s^@MRSIGNER@^`./mrsigner.sh enclave_sigstruct_raw`^" src/policy.in.h > src/policy.h
	rm -f enclave_sigstruct_raw

mrsigner_LDFLAGS= $(AM_LDFLAGS) @OPENSSL_LDFLAGS@

mrsigner_LDADD=-lcrypto
