FROM ubuntu:18.04 as builder
RUN apt-get update && apt-get install -y \
    g++ \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    libssl-dev \
    make \
    module-init-tools \
    # For the repository setup
    wget \
    gnupg \
    # Dependencies required by sgx-ra-sample
    autotools-dev \
    automake \
    xxd \
    git

# Install the SDK
WORKDIR /opt/intel
RUN wget https://download.01.org/intel-sgx/sgx-dcap/1.7/linux/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.10.100.2.bin
RUN chmod 777 sgx_linux_x64_sdk_2.10.100.2.bin
RUN sh -c 'echo yes | ./sgx_linux_x64_sdk_2.10.100.2.bin'

# Install DCAP packages
# DCAP repository setup
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | tee /etc/apt/sources.list.d/intel-sgx.list
RUN wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN apt-get update

RUN apt-get install -y libsgx-dcap-ql-dev libsgx-uae-service libsgx-dcap-default-qpl-dev

# We're using a local server with an invalid https certificate
RUN echo 'USE_SECURE_CERT=FALSE' >> /etc/sgx_default_qcnl.conf # to access pccs https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/QuoteGeneration/pccs

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


# AESM services
FROM builder as aesm
RUN apt-get install -y sgx-aesm-service

WORKDIR /opt/intel/sgx-aesm-service/aesm
ENV LD_LIBRARY_PATH=.
CMD ./aesm_service --no-daemon


# The app
FROM builder as sample

WORKDIR /var/app/sgx-ra-sample
COPY ./sgx-ra-sample .

RUN ./bootstrap
RUN ./configure # --disable-dcap
RUN make
RUN chmod 777 .

RUN adduser -q --disabled-password --gecos "" --no-create-home sgxuser


FROM sample as client

WORKDIR /var/app/sgx-ra-sample
USER sgxuser
CMD ./run-client


FROM sample as provisioning_service

WORKDIR /var/app/sgx-ra-sample
USER sgxuser
CMD ./run-provisioning --verbose


FROM sample as bootstrap_service

WORKDIR /var/app/sgx-ra-sample
USER sgxuser
CMD ./run-bootstrap --verbose
