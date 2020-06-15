#!/bin/bash

source /opt/intel/sgxsdk/environment

RUN /opt/intel/sgx-aesm-service/startup.sh &
pid=$!

trap "kill ${pid}" TERM INT

sleep 2

exec "LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD/sample_libcrypto $@"
