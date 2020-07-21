*************************************
Intel Software Extensions Guard (SGX)
*************************************

.. |br| raw:: html

  <br/>

.. contents:: Table of Contents

What is SGX?
============

With the emergence of Cloud Computing, the privacy of the data manipulated appeared to be a
major topic.

| In order to bring a solution, Intel created a new Instruction Set Architecture: SGX.
| It allows creating private memory areas **called enclaves** which can't be read or modified by the system,
  these areas as encrypted, and only decrypted in the CPU to limit the attack surface to the hardware:

.. image:: graphs/1enclaves.svg
   :align: center
   :alt: Attack surface

| These memory areas can only be read/updated by the code they were associated with at their creation.

How does the encryption work?
=============================

Each Intel CPU ships two private keys:

- The *Root Sealing Key* which is used to encrypt the memory and seal data in long term memories.
- The *Root Provisioning Key* which is used to attest the SGX platform is genuine to third parties.

Actually, the *Root Sealing Key* is derivated by the CPU based on a hash of the code executed before being used to encrypt the memory.
Thus, different applications won't be able to read the other private memory area.

| You may read `this article<https://blog.quarkslab.com/overview-of-intel-sgx-part-1-sgx-internals.html>`_ as an
  introduction to SGX internals, the way it manages memory and the instructions used.
| For even further details, you may check out `this document<https://eprint.iacr.org/2016/086.pdf>`_ produced
  by two researchers.

How to provision secret data to an enclave?
===========================================

All this would be seamless if the code executed in our enclaves contained sensitive data
as they could be reversed engineered.

What we should do is provision the data from a trusted third party. This third party should
verify that the requesting app is running on a genuine SGX platform and that it executes
a trusted code before provisioning it.

This is done using an attestation mechanism. The attested enclave requests the CPU to produce a proof
of the code it is executing, and that it is running on an actual SGX platform.

.. image:: graphs/2certification.svg
   :align: center
   :alt: Attestation scheme

Intel provides two different mechanism to attest an enclave:

- When the third party runs in an enclave on the same machine, it is possible to do a local attestation, which relies on the CPU's knowledge.
- When the third party runs on a different machine, it should do a remote attestation, which relies on Intel services knowledge.

An enclave's identity
---------------------

Also called a report, it contains various elements:

- A hash of the code executed in the enclave, the *MRENCLAVE*
- A hash of the public key used to sign the enclave's binary, the *MRSIGNER*
- Various attributes, such as a *PRODID* defined at compilation, or whether the enclave was
  compiled in Debug mode.

Local attestation
-----------------

When doing a local attestation, there is an enclave that is attested, let's call it A, and one attesting let's call it B.

1. The enclave B send its identity (without any proof) to the enclave A.
2. The enclave A requests an identity targetting B to the CPU. |br|
   In practice, the CPU derivates the *Root Sealing Key* using elements of the identity of B and use this key
   to generate a HMAC of A's identity. |br|
   This derivated key is only accessible from B using the instruction *EGETKEY* ensuring only the CPU
   and B can generate such a MAC, and no one can forge a fake report.
3. B calls *EGETKEY* to fetch the key used to verify reports targetting it and verify the report of A.

Remote attestation
------------------

When doing a remote attestation, we rely on a *Quoting Enclave*. This is an enclave signed by Intel which transforms a local report into
a remotely verifiable quote.

To do so, first a local attestation is performed, and it is then signed by the Quoting Enclave using a derivative
of the *Root Provisioning Key* which is also stored at Intel.

Establishing a secure channel
-----------------------------

In practice, to exchange secret data, it is not sufficient to attest the receiver, we must also
establish a secure channel with it.

| To do so, the SGX SDK provides two protocols, one adapted to local attestation, and one adapted to remote attestation.
| It is based on `Eliptic-Curve Diffie-Hellman<https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman>`_: the two
  parties exchange their public session keys and tie them to their identities in order to ensure these public keys
  come from the same parties.
| The knowledge of the other public key and of their private key enable them to calculate a shared private key which
  is then used to exchange their secrets securely.


Local attestation
^^^^^^^^^^^^^^^^^

In case we're using two enclaves on the same platform, we do a mutual attestation before provisioning the secrets:

1. The enclave B sends its public key and its identity (with no proof) to A.
2. A sends its public key to B with an identity targeting B. This identity contains a hash of A's public key
   to ensure the sender of both data is the same.
3. B verifies the identity of A and responds with its own identity targetting A (and which includes a hash of its public key).

At the end of this routine, the two enclaves has the knowledge of the other's public key and was able to link
it to an attested identity.

They share a private key which is safe to use as it is linked to a verified identity.


Remote attestation
^^^^^^^^^^^^^^^^^^

In the case of the Remote Attestation, the trusted third party does not necessarily run in an enclave
and it is instead attested using ECDSA signature: its public key is shipped in the attested enclave which
is thus able to verify it is communicating with the correct provisioner.

1. The enclave generates a pair of session keys and sends its public key to the remote attester.
2. The remote party send its session public key and a proof of possession of the shared key. It signs the result with its permanent private key.
3. The enclave requests a quote containing the hash of its session public key to the Quoting Enclave, and then sends it to the remote party.


Using the SDK
=============

Installing the SDK
------------------

You may either compile the SDK yourself or use the installer provided by Intel.

- In case you want to compile it, you should follow the guide provided `here<https://github.com/intel/linux-sgx/tree/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15>`_. |br|
  This is useful in case you want to patch the SDK like in `this repository<https://github.com/labri-progress/linux-sgx>`_ which contains a custom quoting enclave which
  shortcuts SGX DCAP attestation (we are not using it in any of our projects however, this is here for demonstration and this Quoting Enclave is just here for testing).

  Intel provides also a `Dockerfile<https://github.com/intel/linux-sgx/blob/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/docker/build/Dockerfile>`_ which automatically compiles
  the SDK for you. However, it does not include the last CVE mitigations and thus **must only be used for testing purposes**.

- A safer way to install the SDK is to use the installers provided on `Intel's repository<https://download.01.org/intel-sgx/>`_. |br|
  In this version, you must install manually the PSW (SGX Platform SoftWare) packages in order to be able to attest enclaves.

  The installation of the SDK using the installer, see for instance this `Dockerfile <https://github.com/labri-progress/SGX-DCAP-Quote-Generation-Dockerfile/blob/f4d61738d251815f55ef53470c520a9c8666ba28/RemoteAttestation/Dockerfile#L12-L27>`_. |br|
  To install the PSW packages, a simple solution when using Ubuntu is to setup Intel's repository (see `this example <https://github.com/labri-progress/SGX-DCAP-Quote-Generation-Dockerfile/blob/f4d61738d251815f55ef53470c520a9c8666ba28/RemoteAttestation/Dockerfile#L7-L9>`_) and
  then install them using apt (see `this <https://github.com/labri-progress/SGX-DCAP-Quote-Generation-Dockerfile/blob/f4d61738d251815f55ef53470c520a9c8666ba28/RemoteAttestation/Dockerfile#L56-L59>`_).

The Runtime Environment
-----------------------

The SDK is only required when compiling your application, you don't need it in your production environment. However the PSW packages provide shared libraries which must be present at runtime (you may browse `Intel's repository <https://download.01.org/intel-sgx/sgx_repo/ubuntu>`_ to select the packages you need).

Notably, the `AESM services <https://github.com/labri-progress/SGX-DCAP-Quote-Generation-Dockerfile/blob/f4d61738d251815f55ef53470c520a9c8666ba28/RemoteAttestation/Dockerfile#L63-L75>`_ run in a separate instance in our Dockerfile and are used for the remote attestation to communicate with the Quoting Enclave.

In any case, in order to run your application using SGX, you must install an SGX driver.

There are two versions of it:

- the legacy one from 2016 which works on all platforms (check out `this installer <https://github.com/labri-progress/SGX-DCAP-Quote-Generation-Dockerfile/blob/f4d61738d251815f55ef53470c520a9c8666ba28/install_legacy_driver.sh>`_).
- the "out-of-tree" driver which only works on CPUs supporting the Flexible Launch Control feature (you may run `this code <https://github.com/ayeks/SGX-hardware/blob/master/test-sgx.c>`_ to check this, section "sgx launch control"). |br|
  You may install its latest version using `this executable <https://github.com/labri-progress/SGX-DCAP-Quote-Generation-Dockerfile/blob/f4d61738d251815f55ef53470c520a9c8666ba28/install_dcap_driver.sh>`_.

  The advantage of this new driver is the support of a new remote attestation method based called DCAP which requires less queries to Intel servers and is thus more efficient. We'll detail it later in this document.

Note: these two drivers expose different devices, the first exposes ``/dev/isgx``, while the second exposes ``/dev/sgx/provision`` and ``/dev/sgx/enclave``. |br|
This is important when using Docker, see `this example <https://github.com/labri-progress/SGX-DCAP-Quote-Generation-Dockerfile/blob/f4d61738d251815f55ef53470c520a9c8666ba28/RemoteAttestation/build_and_run_aesm.sh#L5-L9>`_.


Building an enclave
-------------------

You may have a look at the `SampleEnclave Makefile<https://github.com/intel/linux-sgx/blob/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/SampleCode/SampleEnclave/Makefile>`_.

The enclave is compiled as a separate shared library which is then configured and signed using SGX Edger8r. |br|
Both your application and your enclave must include headers from `/opt/intel/sgxsdk/include`.

There are various libraries you may want to link to your application:

- ``-lsgx_ukey_exchange`` when attesting remotely
- ``-lsgx_dcap_ql -lsgx_dcap_quoteverify -lcrypto`` in order to verify quotes in the trusted third party when using SGX DCAP
- ``-lsgx_usgxssl`` if you want to use OpenSSL in your enclave

And for your enclaves:

- ``-lsgx_tkey_exchange`` to attest it remotely
- ``-Wl,--whole-archive -lsgx_tsgxssl	-Wl,--no-whole-archive -lsgx_tsgxssl_crypto`` to run OpenSSL in your enclave
- ``-Wl,--whole-archive -lsgx_dcap_tvl`` when the DCAP remote attester runs inside an enclave, to verify the QvE result (we'll detail this later)

If you want to use OpenSSL in your enclaves, we suggest you to use the commands `listed here<https://github.com/labri-progress/SGX-DCAP-Quote-Generation-Dockerfile/blob/f4d61738d251815f55ef53470c520a9c8666ba28/RemoteAttestation/Dockerfile#L29-L42>`_, they compile SGX SSL 1.1.1 using the latest mitigations.


Loading an enclave
------------------

In order to load an enclave, you should include the header ``#include <sgx_urts.h>`` and then load it using the following code:

.. code-block:: c++

    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = { 0 };
  	int updated = 0;
    int debug = 1; // Change to 0 when using a production enclave

    sgx_status_t status = sgx_create_enclave("MyEnclave.signed.so", debug, &token, &updated, &eid, 0);
    if (status != SGX_SUCCESS) {
        printf("Enclave creation failed.\n");
        return 1;
    }
