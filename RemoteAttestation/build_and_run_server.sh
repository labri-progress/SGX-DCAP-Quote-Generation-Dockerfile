set -e
docker build --target server --build-arg https_proxy=$https_proxy \
             --build-arg http_proxy=$http_proxy -t sgx_server -f ./Dockerfile .

docker run --env http_proxy --env https_proxy --device=/dev/sgx/enclave -v ~/quote:/var/app/sgx-ra-sample/quote -v /var/run/aesmd:/var/run/aesmd -p 7777:7777 -it sgx_server 
