# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2023 Wojtek Porczyk <woju@invisiblethingslab.com>

import functools
import pathlib
import shutil
import subprocess
import sys
import tempfile

import click

from . import (
    structs,
    store,
)

#: Path to default signer application directory.
DEFAULT_APPDIR = '/var/lib/gramine-sgx-otk'

#: Path to default template that will be rendered into signer application.
DEFAULT_TEMPLATE = '/usr/share/gramine-sgx-otk/gramine-sgx-otk.manifest.jinja'


def init(appdir=DEFAULT_APPDIR, template=DEFAULT_TEMPLATE, manifest_args=()):
    """
    Initialise the signing application.

    This function creates the directory for the new application (unlinking
    anything that was there previously), renders the manifest and signs it with
    a temporary key (though this temporary key can't be proved to have been
    discarded).

    Args:
        appdir (pathlib.Path): path to the application
        template (pathlib.Path): path to the template to be rendered for app
        manifest_args (iterable of strings): command line arguments to
            gramine-manifest
    """
    appdir = pathlib.Path(appdir)
    try:
        shutil.rmtree(appdir)
    except FileNotFoundError:
        pass
    appdir.mkdir(parents=True)

    manifest = appdir / 'gramine-sgx-otk.manifest'

    subprocess.run(['gramine-manifest',
        *manifest_args,
        template,
        manifest
    ], check=True)

    return update_measurement(appdir)


def update_measurement(appdir):
    """
    Update measurement of the signing application.

    Given the application directory, it re-measures the files and re-signs the
    manifest using ``gramine-sgx`` using a temporary key (though this temporary
    key can't be proved to have been discarded). The manifest is not
    re-rendered.

    Args:
        appdir (pathlib.Path): path to the application
    """
    appdir = pathlib.Path(appdir)
    manifest = appdir / 'gramine-sgx-otk.manifest'

    with tempfile.NamedTemporaryFile() as tmpkey:
        subprocess.run(['gramine-sgx-gen-private-key', '-f', tmpkey.name])
        subprocess.run(['gramine-sgx-sign',
            '--key', tmpkey.name,
            '--manifest', manifest,
            '--output', manifest.with_suffix('.manifest.sgx')
        ])

    # if we're on EPID, we need to unlink token, because the automation in
    # gramine-sgx launcher does not check validity of the token
    (appdir / 'gramine-sgx-otk.token').unlink(missing_ok=True)

    # TODO: record mrenclave, gramine version, Cargo.lock, openssl version


def show_quote_cb(modulus, quote):
    """
    Callback that shows modulus and quote during signing.

    This callback is suitable for use with *quote_cb* argument to
    :func:`sign_with_otk_cb`. *modulus* and *quote* are formatted
    and printed to standard error.
    """
    print('modulus:', file=sys.stderr)
    for line in structs.hexdump(modulus):
        print(f'    {line}', file=sys.stderr)
    print('mrsigner:', file=sys.stderr)
    for line in structs.hexdump(structs.get_mrsigner_for_modulus(modulus)):
        print(f'    {line}', file=sys.stderr)
    print('quote:', file=sys.stderr)
    for line in structs.hexdump(quote):
        print(f'    {line}', file=sys.stderr)


@click.command(add_help_option=False)
@click.help_option('--help-otk')
@click.option('--otk-appdir', 'appdir',
    type=click.Path(dir_okay=True, file_okay=False),
    default=DEFAULT_APPDIR,
    help='Path to signing application, where gramine manifest is stored.')
@click.option('--otk-check-isvsvn/--otk-no-check-isvsvn', 'check_isvsvn',
    default=False,
    help='Check if ISVSVN is at maximum value (0xFFFF).')
@click.option('--otk-show-quote/--otk-no-show-quote',
    default=False,
    help='Show the modulus and the quote to stderr (for debugging).')
def sign_with_otk(otk_show_quote, **kwds):
    return functools.partial(sign_with_otk_cb,
        quote_cb=(show_quote_cb if otk_show_quote else None),
        **kwds)


def sign_with_otk_cb(data, *,
        appdir=DEFAULT_APPDIR,
        quote_cb=None,
        check_isvsvn=False,
        _do_not_store_quote=False):
    """
    Signing function for signing SGX enclaves.

    *data* is expected to be signing data extracted from SIGSTRUCT.

    If *quote_cb* is not ``None``, it needs to be 2-argument function that will
    be called with *modulus* and *quote* (instances of ``bytes``, *modulus* is
    big endian).
    """
    if check_isvsvn:
        isvsvn = int.from_bytes(data[254:256], 'little')
        if isvsvn != structs.MAX_ISVSVN:
            raise structs.InvalidSigstruct(
                f'expected ISVSVN {structs.MAX_ISVSVN}, found {isvsvn:#06x}')

    try:
        proc = subprocess.run(['gramine-sgx', 'gramine-sgx-otk'],
            cwd=appdir, input=data, capture_output=True, check=True)

    except subprocess.CalledProcessError as e:
        sys.stderr.buffer.write(e.stderr)
        print('failed to sign', file=sys.stderr)
        sys.exit(1)

    sys.stderr.buffer.write(proc.stderr)
    sys.stderr.buffer.flush()
    modulus =   proc.stdout[0  :384]
    signature = proc.stdout[384:768]
    quote =     proc.stdout[768:]

    if quote_cb is not None:
        quote_cb(modulus, quote)

    if not _do_not_store_quote:
        store.QuoteStore().save(modulus, quote)

    return (
        3,
        int.from_bytes(modulus, byteorder='big'),
        int.from_bytes(signature, byteorder='big'),
    )


def sign(sigstruct, **kwds):
    assert len(sigstruct) == structs.SIGSTRUCT_SZ
    sigstruct = structs.Sigstruct(sigstruct)
    signing_data = sigstruct.get_signing_data()
    exponent, modulus, signature = sign_with_otk_cb(signing_data, **kwds)
    assert exponent == 3

    (sigstruct.exponent, sigstruct.modulus, sigstruct.signature
        ) = exponent, modulus, signature

    # https://eprint.iacr.org/2016/086.pdf, 6.5.2
    sigstruct.q1, w = divmod(signature ** 2, modulus)
    sigstruct.q2 = w * signature // modulus

    return sigstruct


# vim: tw=80 ts=4 sts=4 sw=4 et
