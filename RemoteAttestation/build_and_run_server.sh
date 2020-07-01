set -e
docker build --target server --build-arg https_proxy=$https_proxy \
             --build-arg http_proxy=$http_proxy -t sgx_server -f ./Dockerfile .

if test -d "/dev/sgx"; then
device_flags="--device=/dev/sgx/enclave"
else
device_flags="--device=/dev/isgx"
fi

docker run \
  --net="host" `# Binds localhost to the host ip as the client tries to connect to the port exposed by the server part` \
  $device_flags \
  --env http_proxy --env https_proxy -it sgx_server
