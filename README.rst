.. highlight:: sh

gramine-sgx-otk
***************

Introduction
============

Intel SGX requires RSA signature for each enclave that is to be executed,
irrespective of if the signature is actually needed by the attestation (that is,
if you attest against ``ENCLAVEHASH`` aka ``MRENCLAVE``, not against
``MRSIGNER``). Even if it's not really needed, CPU requires that the signature
is present and valid, and leakage of the RSA private key may compromise the data
protected by the enclave. Therefore the private key needs to be kept secure, in
spite of the fact that is serves no purpose for its holder.

This signing application generates random RSA keys and provably discards them
after a single operation. After the signing, there's no risk that the private
key leaks.

Quickstart
==========

On Debian 11 (``bullseye``):

::

    # add gramine repository, if you didn't already
    sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg \
        https://packages.gramineproject.io/gramine-keyring.gpg
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ bullseye main" \
    | sudo tee /etc/apt/sources.list.d/gramine.list

    sudo apt-get build-dep . -t bullseye-backports
    debuild

    sudo apt-get update
    sudo apt-get install ../gramine-sgx-otk_*.deb
    sudo gramine-sgx-otk init

    gramine-sgx-otk sign --inplace path/to/sigstruct.sig
    gramine-sgx-otk get-quote --sigstruct path/to/sigstruct.sig
