set -e
docker build --target client --build-arg https_proxy=$https_proxy \
             --build-arg http_proxy=$http_proxy -t sgx_client -f ./Dockerfile .

docker run --net="host" --env http_proxy --env https_proxy --device=/dev/sgx/enclave -v ~/quote:/var/app/sgx-ra-sample/quote  -v /var/run/aesmd:/var/run/aesmd -it sgx_client 
