KEYS=enclave_signing_private provisioning_private provisioning_public bootstrap_private bootstrap_public
HEADERS=$(addsuffix .h,$(KEYS))

all: $(HEADERS)

%.h: %.pem
		xxd -i $< | sed 's/\([0-9a-f]\)$$/\0, 0x00/' > $@

enclave_signing_private.pem:
		openssl genrsa -out enclave_signing_private.pem -3 3072

provisioning_private.pem:
		openssl ecparam -name prime256v1 -genkey -noout -out provisioning_private.pem

provisioning_public.pem: provisioning_private.pem
		openssl ec -in provisioning_private.pem -pubout -out provisioning_public.pem

bootstrap_private.pem:
		openssl ecparam -name prime256v1 -genkey -noout -out bootstrap_private.pem

bootstrap_public.pem: bootstrap_private.pem
		openssl ec -in bootstrap_private.pem -pubout -out bootstrap_public.pem

clean:
	$(RM) *.pem *.h
