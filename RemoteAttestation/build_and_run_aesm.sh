set -e
docker build --target aesm --build-arg https_proxy=$https_proxy \
             --build-arg http_proxy=$http_proxy -t sgx_aesm -f ./Dockerfile .

docker run \
  --net="host" `# Binds localhost to the host ip as the client tries to connect to the port exposed by the server part` \
   --env http_proxy --env https_proxy --device=/dev/sgx/enclave --device=/dev/sgx/provision \
   -v /tmp/aesmd:/var/run/aesmd `# AESM services should be available to the the container` \
   -it sgx_aesm
