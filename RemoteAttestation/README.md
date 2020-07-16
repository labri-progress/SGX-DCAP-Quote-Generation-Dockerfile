# DCAP Remote Attestation

This sample demonstrates DCAP Remote Attestation.
It is an adaptation to DCAP of [intel/sgx-ra-sample](https://github.com/intel/sgx-ra-sample).

A Dockerfile is provided that allows to easily launch the different components of the sample, in *this* order:

- `sudo ./build_and_run_aesm.sh` launches the AESM services used by the client (manage the generation of the quote)
- `sudo ./build_and_run_provisioning_service.sh` launches the server that listens to Remote Attestation requests. This enclave contains all the sensitive (and thus encrypted) data to be provisioned to client enclaves.
- `sudo ./build_and_run_bootstrap_service.sh` launches the bootstrap service that initializes the provisioning service by provisioning it with its private key.
- `sudo ./build_and_run_client.sh` launches the client that sends a request to the server to be remotely attested.

## Installation

The host's CPU must support Flexible Launch Control (FLC) and have the SGX DCAP Driver installed (refer to the root [README](../README.md) of this repository for the installation procedure).

You also need to install and configure the cache server (PCCS).

- First, register on [https://api.portal.trustedservices.intel.com/provisioning-certification](https://api.portal.trustedservices.intel.com/provisioning-certification) (ECDSA attestation service), and retrieve your API key.
- Then, install the cache server by running either `../install_dcap_pccs.sh` or the following commands:

  ```shell
  echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
  wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
  sudo apt-get update
  sudo apt-get install sgx-dcap-pccs
  ```

- during the installation, leave all value to defaults.
- Enter your API key when asked.

## Secrets Generation

You may regenerate the keys used to sign enclaves, to communicate between the services, etc. by running `make` in the `sgx-ra-sample/keys` subdirectory.

## Usage

1. First, launch the AESM services using `./build_and_run_aesm.sh`.
2. Launch the Provisioning service: `./build_and_run_provisioning_service.sh`.
3. Initialize it with the Bootstrap service: `./build_and_run_bootstrap_service`.
4. Then launch as many app services as wanted: `./build_and_run_client`.

## Some useful notes

### Dockerfile container hierarchy

- `sgxbase`: Ubuntu 18.04 with Intel SGX's repo setup
  - `sgx_sample_builder` = `sgxbase` + linux autotools, libssl, SGX DCAP (installed), mitigation tools (as, ld, objdump...), linux-SGX-SSL SDK for OpenSSL 1.1.1g, OpenSSL 1.1.1g and `sgx-ra-sample` (built)
  - `sgxruntime`= `sgxbase` + a few more packages (DCAP/UAE) + self-signed certificate parameter
    - `aesm` = `sgxruntime` + AESM service package (installed and launched)
    - `sample` = `sgxruntime` + libssl1.1 package + sgxuser creation
      - `client`= `sample` + run_client + client executables + Enclave.signed.so, the whole ran as sgxuser
      - `provisioning_service`= `sample` + run-provisioning + provisioning_service executables + ProvisioningEnclave.signed.so, the whole ran as sgxuser
      - `bootstrap_service`= `sample` + bootstrap_service executable ran as sgxuser

### Building project for no-FLC CPU

To build the whole project with no FLC (and thus no DCAP) support, change

```dockerfile
RUN ./configure # --disable-dcap
```

for

```dockerfile
RUN ./configure --disable-dcap
```