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
    #include <sgx_urts.h>

    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = { 0 };
    int updated = 0;
    int debug = 1; // Change to 0 when using a production enclave

    sgx_status_t status = sgx_create_enclave("MyEnclave.signed.so", debug, &token, &updated, &eid, 0);
    if (status != SGX_SUCCESS) {
        printf("Enclave creation failed.\n");
        return 1;
    }

This function gives a unique enclave id (eid) which will be used to communicate with your enclave.

Communicating with an enclave
-----------------------------

The communication API between your app and your enclave is defined in your Enclave ``.edl`` file (see `this example<https://github.com/intel/linux-sgx/blob/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/SampleCode/LocalAttestation/EnclaveInitiator/EnclaveInitiator.edl>`_).

The calls from your app to your enclave are put inside the ``trusted`` section. |br|
Those from the enclaves to your app inside ``untrusted``. You must assert that ``untrusted`` calls may NOT return, return arbitrary data, or a different function from your enclave may be called instead of returning.

When using pointers you should use one these tags:

- ``[in]`` for arguments that will be copied from untrusted memory to trusted memory when making the call.
- ``[out]`` for arguments that will be copied from trusted memory to untrusted memory when the call returns.
- ``[in, out]`` when your data must be copied when making and when returning the call.
- ``[user_check]`` when you don't want the SDK to manage your pointer. /!\\ This must be used with extreme precaution. You must absolutely check the position of the data pointed to avoid any security issue. /!\\

To use your enclave trusted API from your app, include ``MyEnclave_u.h`` (it is generated by SGX Edger8r, see `this sample<https://github.com/intel/linux-sgx/blob/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/SampleCode/SampleEnclave/Makefile#L221>`_) and use your API as follow:

.. code-block:: c++

    #include "MyEnclave_u.h"

    my_function_return_type ret;
    sgx_status_t call_success = my_enclave_function(eid, &ret, ...arguments);
    if (call_success != SGX_SUCCESS) {
        printf("The call to my_enclave_function failed.\n");
        return 1;
    }

To use untrusted functions from your enclave, include ``MyEnclave_t.h`` and then call you functions normally:

.. code-block:: c++

    #include "MyEnclave_t.h"

    my_function_return_type ret = untrusted_function(...arguments);


Destroying an enclave
---------------------

When you're done using an enclave, you should destroy it using the following function:

.. code-block:: c++

    sgx_destroy_enclave(eid);


The SDK libraries
=================

You may include preconfigured ``.edl`` in your own ``.edl`` file. |br|
In particular, this is useful when doing remote attestation, adding ``from "sgx_tkey_exchange.edl" import *;`` to your ``.edl`` file exposes the functions needed by the SDK to have a working remote attestation protocol.


Local Attestation
-----------------

Intel provides `a sample showcasing local attestation <https://github.com/intel/linux-sgx/tree/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/SampleCode/LocalAttestation>`_.

The communication between the two enclaves is managed by the system. For instance, the two instances may be managed by the same process, or by different processes and require socket communication.

1. In any case, both enclaves should include the header ``#include "sgx_dh.h"`` (dh = Diffie Hellman) and begin by creating a Diffie Hellman session by using ``sgx_dh_init_session`` (like `this <https://github.com/intel/linux-sgx/blob/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/SampleCode/LocalAttestation/EnclaveInitiator/EnclaveMessageExchange.cpp#L97>`_ in the request initiator, the enclave A, and like `this<https://github.com/intel/linux-sgx/blob/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/SampleCode/LocalAttestation/EnclaveResponder/EnclaveMessageExchange.cpp#L86>`_ in the responder, the enclave B).
2. The enclave B should then generate the first message using ``sgx_dh_responder_gen_msg1`` (see `its usage<https://github.com/intel/linux-sgx/blob/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/SampleCode/LocalAttestation/EnclaveResponder/EnclaveMessageExchange.cpp>`_).
3. Enclave A should process the first message and generate the second message using ``sgx_dh_initiator_proc_msg1`` (see `its usage<https://github.com/intel/linux-sgx/blob/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/SampleCode/LocalAttestation/EnclaveInitiator/EnclaveMessageExchange.cpp#L115>`_).
4. Enclave B should process the second message using ``sgx_dh_responder_proc_msg2``, generates message 3 and verify that enclave A executes a trusted code/orginates from a trusted author (see `the sample<https://github.com/intel/linux-sgx/blob/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/SampleCode/LocalAttestation/EnclaveResponder/EnclaveMessageExchange.cpp#L163-L178>`_).
5. Finally, enclave A processes message 3 using ``sgx_dh_initiator_proc_msg3`` and verify enclave B's identity (see `the sample<https://github.com/intel/linux-sgx/blob/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/SampleCode/LocalAttestation/EnclaveInitiator/EnclaveMessageExchange.cpp#L134-L144>`_).


Remote Attestation
------------------

Intel provides `a sample showcasing remote attestation <https://github.com/intel/linux-sgx/tree/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/SampleCode/RemoteAttestation>`_. |br|
Note that it is not functional as is and is only useful to demonstrate the main functions used during Remote Attestation.

For a functional sample, check `our adaptation of sgx-ra-sample<https://github.com/labri-progress/SGX-DCAP-Quote-Generation-Dockerfile/tree/b041f21e641323aa66ea32eb392944ce876ceccb/RemoteAttestation>`_ which leverages Intel's DCAP technology to limit requests to Intel's servers, or `Intel's sgx-ra-sample<https://github.com/intel/sgx-ra-sample>`_ which uses EPID attestation which is slower and relies a lot on Intel's servers.


DCAP vs EPID
^^^^^^^^^^^^

The protocol used to create a secure channel between the enclave and the remote attester is identical, the difference is the method used to sign the enclave's quote.

When using EPID attestation, the Quoting Enclave uses an EPID key to sign the quote. This key is reprovisioned regularly from Intel's servers. |br|
During this provisioning phase, the Quoting Enclave proves to Intel that it is running on a genuine SGX platform (using the *Root Provisioning Key*) and Intel provides it an EPID key. |br|
The remote attester must then send the quotes it receives to Intel in order to verify the EPID signature is correct. It communicates with Intel using its API key (given after registering `here<https://api.portal.trustedservices.intel.com/EPID-attestation>`_).

When using DCAP attestation, Eliptic Curve cryptography is used to sign the quote. The Quoting Enclave generates an EC key, it then uses a derivative of the *Root Provisioning Key* called the *Provisioning Certification Key* to sign the public part of this EC key and include it in its quotes. |br|
Intel exposes the public part of this *Certification Key*s in a certificate for all its CPUs. Hence, to verify a quote, the remote attester fetches the *Provisioning Certification Key* certificate corresponding to the machine it is in contact with from Intel, and verifies the quote signature using this certificate. |br|
In order to limit the requests made to Intel and to speed up the attestation, these certificates are cached in a machine located in the same cluster.

An important limitation of DCAP is that it requires FLC support, and few CPUs has it at the time this was written.

The Remote Attestation from the Enclave
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This part is quite straightforward as the SDK provides almost all the API required.

* First, the enclave should initialize the Diffie-Hellman session using ``sgx_ra_init`` (see `the RemoteAttestation sample <https://github.com/intel/linux-sgx/blob/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/SampleCode/RemoteAttestation/isv_enclave/isv_enclave.cpp#L222>`_). You must hardcode the remote attester permanent public key in your enclave.

  Note that ``sgx_ra_init`` is not called by the app but is wrapped in a function instead to ensure the remote attester public key is not forged (see `the untrusted api exposed <https://github.com/intel/linux-sgx/blob/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/SampleCode/RemoteAttestation/isv_enclave/isv_enclave.edl#L39>`_)
* You should import the required API in your enclave's ``.edl`` using ``from "sgx_tkey_exchange.edl" import *;``.
* Then, the rest is managed using an untrusted API.

  You should first choose the attestation key used depending on whether you want to use `EPID<https://github.com/intel/linux-sgx/blob/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/SampleCode/RemoteAttestation/service_provider/service_provider.cpp#L125-L159>`_ or `DCAP attestation<https://github.com/intel/linux-sgx/blob/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/SampleCode/RemoteAttestation/service_provider/service_provider.cpp#L90-L124>`_.

  Use ``sgx_select_att_key_id`` to select the correct attestation key (see `this example <https://github.com/labri-progress/SGX-DCAP-Quote-Generation-Dockerfile/blob/1bfe1957b469eba000c334e530e8c238a6747380/RemoteAttestation/sgx-ra-sample/src/client/client.cpp#L323-L329>`_).

* Then, generate the first message using ``sgx_ra_get_msg1_ex`` (see `this<https://github.com/intel/linux-sgx/blob/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/SampleCode/RemoteAttestation/isv_app/isv_app.cpp>`_).

* Process the second message and generate the third message using ``sgx_ra_proc_msg2_ex`` (see `this <https://github.com/intel/linux-sgx/blob/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/SampleCode/RemoteAttestation/isv_app/isv_app.cpp#L514-L522>`_).

* At this stage, the secure channel is in place and the enclave is attested. You may send a custom fourth message from the remote attester to provision your enclave. |br|
  You may decrypt its message using `this code<https://github.com/intel/linux-sgx/blob/7c2e2f9d0bab50eefdac2a9360cae8e1dd470e15/SampleCode/RemoteAttestation/isv_enclave/isv_enclave.cpp#L326-L358>`_.


The Remote Attestation from the Remote attester
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This part is more complicated as Intel does not provide a library doing all the work for you.

You must implement the verifications described `in this article <https://software.intel.com/content/www/us/en/develop/articles/code-sample-intel-software-guard-extensions-remote-attestation-end-to-end-example.html>`_.

Fortunately, there is a `sample<https://github.com/intel/sgx-ra-sample>` which already implements this for you (see the `remote attester's code<https://github.com/intel/sgx-ra-sample/blob/96f5b5ce6e6467bc0e31d97ad807d52e62c61cfc/sp.cpp>`_). |br|
However, it does only support EPID attestation!

If you want to benefit from the new DCAP technology, you may use `our adaptation<https://github.com/labri-progress/SGX-DCAP-Quote-Generation-Dockerfile>`_ of this repository. |br|
You may actually test it on a non-FLC machine by using the ``--disable-dcap`` (in `the Dockerfile<https://github.com/labri-progress/SGX-DCAP-Quote-Generation-Dockerfile/blob/master/RemoteAttestation/Dockerfile#L51>`_) but this is ONLY for testing, it shortcuts security verifications and thus must not be used in production.

More details about DCAP attestation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Both the enclave attested and the remote attester must have an access to a server caching the *Provisioning Certification Key* certificates.

* In case you are self-hosting your applications, you should use the *Default Quote Provider Library* (install the library ``libsgx-dcap-default-qpl``) which relies on the `PCCS Caching Service<https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/QuoteGeneration/pccs>`_.

  The library ``sgx-dcap-pccs`` must be installed on your caching server and you must configure its url in ``/etc/sgx_default_qcnl.conf`` in the image executing your enclaves and your remote attester.

* In case you are using Azure, you should simply install the `Azure DCAP Client <https://github.com/microsoft/Azure-DCAP-Client>`_ (set up `Microsoft repository<https://github.com/labri-progress/SGX-DCAP-Quote-Generation-Dockerfile/blob/d41b47bb43102a29005092eb068dea306d10197d/RemoteAttestation/Dockerfile#L10-L12>`_ and then run ``apt install -y azure-dcap-client``).


The verification of the quote in the remote attester is done using another special enclave: the QVE (Quote Verification Enclave).

* First link your application with ``-lsgx_dcap_ql -lsgx_dcap_quoteverify``.
* Then call the QVE to verify your quote (check `our sample<https://github.com/labri-progress/SGX-DCAP-Quote-Generation-Dockerfile/blob/b041f21e641323aa66ea32eb392944ce876ceccb/RemoteAttestation/sgx-ra-sample/src/provisioning/quote_verify.cpp>`_).
* In case your remote attester runs in an enclave, you must attest you're communicating with a genuine QVE (check `how we are doing it <https://github.com/labri-progress/SGX-DCAP-Quote-Generation-Dockerfile/blob/master/RemoteAttestation/sgx-ra-sample/src/provisioning/ProvisioningEnclave/ProvisioningEnclave.cpp#L177-L239>`_).


In case you don't have access to a trusted time in your remote attester, you can use a `custom acceptation policy for the QVE's result<https://github.com/labri-progress/SGX-DCAP-Quote-Generation-Dockerfile/blob/b041f21e641323aa66ea32eb392944ce876ceccb/RemoteAttestation/sgx-ra-sample/src/provisioning/ProvisioningEnclave/ProvisioningEnclave.cpp#L189-L194>`_.
