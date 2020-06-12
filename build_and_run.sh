set -e
docker build --target sample --build-arg https_proxy=$https_proxy \
             --build-arg http_proxy=$http_proxy -t sgx_sample -f ./Dockerfile .

docker run --env http_proxy --env https_proxy -it sgx_sample
