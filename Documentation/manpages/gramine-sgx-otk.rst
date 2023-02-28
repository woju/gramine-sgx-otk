.. program:: gramine-sgx-otk
.. _gramine-sgx-otk:

******************************************************
:program:`gramine-sgx-otk` -- One-Time-Key SGX signing
******************************************************

Synopsis
========

| :command:`gramine-sgx-otk sign` [*OPTIONS*] <*SIGSTRUCT-PATH*>
| :command:`gramine-sgx-otk get-quote` [*OPTIONS*] <*OUTPUT-PATH*>
| :command:`gramine-sgx-otk init` [*OPTIONS*] [*MANIFEST-ARGS* ...]
| :command:`gramine-sgx-otk update-measurement` [*OPTIONS*]

Commands
========

.. program:: gramine-sgx-otk-sign
.. _gramine-sgx-otk-sign:

:command:`gramine-sgx-otk sign` -- Standalone SIGSTRUCT signing tool
--------------------------------------------------------------------

Sign an existing SIGSTRUCT using one-time-key technology. The SIGSTRUCT needs to
be generated elsewhere (does not need to be from Gramine, any SGX enclave's
SIGSTRUCT will do).

.. option:: --appdir <path>

    Use alternative application directory. The directory needs to be
    initialised.


.. option:: --check-isvsvn

    Check if ISVSVN is set to its maximum value (65535, 0xffff) and fail if it
    isn't. There's no reason to ship production enclave with any other value
    than maximum. (Default off).

.. option:: --no-check-isvsvn

    Do not check ISVSVN. (This is the default)

.. option:: --show-quote

    Display RSA key's modulus and the quote to standard error. Mainly used for
    debugging. (Default off).

.. option:: --no-show-quote

    Do not display modulus and quote. (This is the default).

.. option:: --output <path>

    Write the signed SIGSTRUCT to this file.

.. option:: --inplace

    Overwrite the SIGSTRUCT given as input argument with a signed version.
    (Default off).

.. option:: --no-inplace

    Do not overwrite input SIGSTRUCT. (This is the default).

.. program:: gramine-sgx-otk-get-quote
.. _gramine-sgx-otk-get-quote:

:command:`gramine-sgx-otk get-quote` -- Query local quote database
------------------------------------------------------------------

This command is used to produce the proof that given RSA was really discarded.
The proof is a SGX quote that has matching MRSIGNER embedded in report's data.
Exactly one of the lookup selectors must be given.

.. option:: --sigstruct <path>

    Look for quote for a key used to sign this SIGSTRUCT, given as file path.
    The program parses the SIGSTRUCT, extracts modulus, computes MRSIGNER and
    looks it up in the database.

.. option:: --modulus-le <hex>

    Calculate MRSIGNER for given modulus (a hex string representing modulus in
    little-endian). Choose this option if you're copy-pasting from SIGSTRUCT's
    hexdump (SIGSTUCT has modulus in little-endian).

.. option:: --modulus-be <hex>

    Calculate MRSIGNER for given modulus (a hex string representing modulus in
    big-endian). Choose this option if you're pasting from PEM, bignums, or
    other crypto libraries, as cryptography tooling mostly prefers big-endian
    representations.

.. option:: --mrsigner <hex>

    Query for the MRSIGNER given directly as hex.

:command:`gramine-sgx-otk init`
-------------------------------

TBD

:command:`gramine-sgx-otk update-measurement`
---------------------------------------------

TBD
