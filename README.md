SGX DCAP Samples
================

This repository provides two samples demonstrating the use of [SGX DCAP](https://github.com/intel/SGXDataCenterAttestationPrimitives) with Docker.

- The first demonstrates the generation of an ECDSA quote.
- The second sample is an adaptation of [intel/sgx-ra-sample](https://github.com/intel/sgx-ra-sample) to SGX DCAP.


Installing the SGX DCAP Driver
--------------------------

To ease the installation of the SGX DCAP Driver, you may run the following command at the root of this repository:

```
sudo ./install_dcap_driver.sh
```

It parses Intel's website in order to find the latest DCAP driver available, checks its SHA256 sum and installs it.

If using a CPU with no (or disabled) FLC, use:

```
sudo ./install_legacy_driver.sh
```

