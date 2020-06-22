set -e
docker build --target server --build-arg https_proxy=$https_proxy \
             --build-arg http_proxy=$http_proxy -t sgx_server -f ./Dockerfile .

docker run \
  --net="host" `# Binds localhost to the host ip as the client tries to connect to the port exposed by the server part` \
  --env http_proxy --env https_proxy --device=/dev/sgx/enclave -it sgx_server
