FROM ubuntu:18.04 as sgxbase
RUN apt-get update && apt-get install -y \
    gnupg \
    wget

# Set up Intel repository
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' > /etc/apt/sources.list.d/intel-sgx.list
RUN wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN apt-get update


FROM sgxbase as sgx_sample_builder
# App build time dependencies
RUN apt-get install -y build-essential \
    # libraries needed to compile SGX SSL
    git \
    # Dependencies required by sgx-ra-sample
    autotools-dev \
    libssl-dev \
    automake \
    xxd

## Install the sdk
WORKDIR /opt/intel
RUN wget https://download.01.org/intel-sgx/sgx-dcap/1.7/linux/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.10.100.2.bin
RUN chmod 777 sgx_linux_x64_sdk_2.10.100.2.bin
RUN sh -c 'echo yes | ./sgx_linux_x64_sdk_2.10.100.2.bin'

## Install SGX SSL
# Mitigation tools
WORKDIR /var/app/
RUN wget https://download.01.org/intel-sgx/sgx-linux/2.10/as.ld.objdump.gold.r2.tar.gz
RUN tar -xf as.ld.objdump.gold.r2.tar.gz
RUN bash -c "cp external/toolset/ubuntu18.04/{as,ld,ld.gold,objdump} /usr/local/bin"
RUN which as ld ld.gold objdump

RUN git clone https://github.com/intel/intel-sgx-ssl.git
ADD https://www.openssl.org/source/openssl-1.1.1g.tar.gz ./intel-sgx-ssl/openssl_source/openssl-1.1.1g.tar.gz

WORKDIR /var/app/intel-sgx-ssl/Linux
RUN git checkout lin_2.10_1.1.1g
RUN /bin/bash -c 'make && make install'

## Compile the application
WORKDIR /var/app/sgx-ra-sample
COPY ./sgx-ra-sample .

RUN apt-get install -y libsgx-dcap-ql-dev

RUN ./bootstrap
RUN ./configure # --disable-dcap
RUN make


FROM sgxbase as sgxruntime
RUN apt-get install -y libsgx-dcap-ql-dev libsgx-dcap-default-qpl-dev libsgx-uae-service

# We're using a local server with an invalid https certificate
RUN echo 'USE_SECURE_CERT=FALSE' >> /etc/sgx_default_qcnl.conf # to access pccs https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/QuoteGeneration/pccs


## AESM services
FROM sgxruntime as aesm
RUN apt-get install -y \
    libcurl4 \
    libprotobuf10 \
    libssl1.1 \
    make \
    module-init-tools

RUN apt-get install -y sgx-aesm-service libsgx-uae-service

WORKDIR /opt/intel/sgx-aesm-service/aesm
ENV LD_LIBRARY_PATH=.
CMD ./aesm_service --no-daemon


## The app
FROM sgxruntime as sample
RUN apt-get install -y \
    libcurl4 \
    libprotobuf10 \
    libssl1.1

WORKDIR /var/app/sgx-ra-sample
COPY --from=sgx_sample_builder /var/app/sgx-ra-sample/settings .

RUN chmod 777 .

RUN adduser -q --disabled-password --gecos "" --no-create-home sgxuser


FROM sample as client
COPY --from=sgx_sample_builder /var/app/sgx-ra-sample/run-client .
COPY --from=sgx_sample_builder /var/app/sgx-ra-sample/client .
COPY --from=sgx_sample_builder /var/app/sgx-ra-sample/Enclave.signed.so .

WORKDIR /var/app/sgx-ra-sample
USER sgxuser
CMD ./run-client


FROM sample as provisioning_service
COPY --from=sgx_sample_builder /var/app/sgx-ra-sample/run-provisioning .
COPY --from=sgx_sample_builder /var/app/sgx-ra-sample/provisioning_service .
COPY --from=sgx_sample_builder /var/app/sgx-ra-sample/ProvisioningEnclave.signed.so .

WORKDIR /var/app/sgx-ra-sample
USER sgxuser
CMD ./run-provisioning


FROM sample as bootstrap_service
COPY --from=sgx_sample_builder /var/app/sgx-ra-sample/bootstrap_service .
COPY --from=sgx_sample_builder /var/app/sgx-ra-sample/run-bootstrap .

WORKDIR /var/app/sgx-ra-sample
USER sgxuser
CMD ./run-bootstrap
