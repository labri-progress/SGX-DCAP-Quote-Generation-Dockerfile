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
    xxd

# Install the SDK
WORKDIR /opt/intel
RUN wget https://download.01.org/intel-sgx/latest/dcap-latest/linux/distro/ubuntuServer18.04/sgx_linux_x64_sdk_2.9.101.2.bin
RUN chmod 777 sgx_linux_x64_sdk_2.9.101.2.bin
RUN sh -c 'echo yes | ./sgx_linux_x64_sdk_2.9.101.2.bin'

# Install DCAP packages
# DCAP repository setup
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | tee /etc/apt/sources.list.d/intel-sgx.list
RUN wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN apt-get update

RUN apt-get install -y libsgx-enclave-common-dev libsgx-urts libsgx-dcap-ql-dev libsgx-quote-ex-dev libsgx-ae-qe3 libsgx-ae-qve libsgx-ae-epid libsgx-epid-dev libsgx-aesm-epid-plugin libsgx-uae-service sgx-aesm-service libsgx-aesm-ecdsa-plugin libsgx-aesm-epid-plugin


# The app
FROM builder as sample

WORKDIR /var/app/SGXDataCenterAttestationPrimitives
COPY ./SGXDataCenterAttestationPrimitives .

# WORKDIR /var/app/RemoteAttestation
# COPY ./RemoteAttestation .

WORKDIR /var/app/sgx-ra-sample
COPY ./sgx-ra-sample .

RUN ./bootstrap
RUN ./configure
RUN SGX_MODE=HW make
RUN chmod 777 .

RUN adduser -q --disabled-password --gecos "" --no-create-home sgxuser
USER sgxuser

CMD ./run-client --stdio
