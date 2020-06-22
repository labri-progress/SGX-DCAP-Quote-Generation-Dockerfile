DCAP Remote Attestation
=======================

This sample demonstrates DCAP Remote Attestation.
It is an adaptation to DCAP of [intel/sgx-ra-sample](https://github.com/intel/sgx-ra-sample).

A Dockerfile is provided that allows to easily launch the different components of the sample:
- `./build_and_run_server.sh` launches the server that listens to Remote Attestation requests.
- `./build_and_run_aesm.sh` launches the AESM services used by the client.
- `./build_and_run_client.sh` launches the client that sends a request to the server to be remotely attested.

Installation
------------

The host's CPU must support Flexible Launch Control (FLC) and have the SGX DCAP Driver installed (refer to the root [README](../README.md) of this repository for the installation procedure).

You also need to install and configure the cache server (PCCS):
```
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
sudo apt-get update
sudo apt-get install sgx-dcap-pccs
```
(You will have to register on https://api.portal.trustedservices.intel.com/provisioning-certification for ECDSA attestation)
