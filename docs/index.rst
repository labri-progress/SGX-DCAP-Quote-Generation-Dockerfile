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
of the *Root Provisioning Key* which is stored at Intel.
