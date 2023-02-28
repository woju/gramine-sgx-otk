# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2023 Wojtek Porczyk <woju@invisiblethingslab.com>

import pathlib

import click

from . import (
    signer,
    structs,
    store,
)


@click.group()
def cli():
    pass


@cli.command()
@click.option('--appdir', metavar='PATH',
    type=click.Path(dir_okay=True, file_okay=False),
    default=signer.DEFAULT_APPDIR,
    help='Path to signing application, where gramine manifest is stored.')
@click.option('--check-isvsvn/--no-check-isvsvn',
    default=False,
    help='Check if ISVSVN is at maximum value (0xFFFF).')
@click.option('--show-quote/--no-show-quote',
    default=False,
    help='Show the modulus and the quote to stderr (for debugging).')
@click.option('--output', metavar='PATH',
    type=click.File('wb'),
    help='Where to write the signed SIGSTRUCT.')
@click.option('--inplace/--no-inplace',
    default=False,
    help='Overwrite the SIGSTRUCT in place.')
@click.argument('file', metavar='PATH',
    type=click.File('r+b'))
def sign(appdir, check_isvsvn, show_quote, output, inplace, file):
    """
    Sign an existing SIGSTRUCT.

    The SIGSTRUCT should be created elsewhere, possibly by gramine-sgx-sign.
    """

    sigstruct = signer.sign(structs.Sigstruct.from_file(file),
        appdir=pathlib.Path(appdir),
        quote_cb=(signer.show_quote_cb if show_quote else None),
        check_isvsvn=check_isvsvn)

    if output:
        output.write(sigstruct)

    if inplace:
        file.seek(0)
        file.truncate()
        file.write(sigstruct)


def cb_unhexlify(_ctx, _param, value):
    return value and bytes.fromhex(value)


@cli.command()
@click.pass_context
@click.option('--sigstruct', 'sigstruct_file', metavar='PATH',
    type=click.File('rb'),
    help='Read SIGSTRUCT from file, extract modulus and calculate MRSIGNER.')
@click.option('--modulus-be', metavar='HEX',
    callback=cb_unhexlify,
    help='Calculate MRSIGNER based on given modulus (big endian).')
@click.option('--modulus-le', metavar='HEX',
    callback=cb_unhexlify,
    help='Calculate MRSIGNER based on given modulus'
        ' (little endian, like in the SIGSTRUCT.')
@click.option('--mrsigner', metavar='HEX',
    callback=cb_unhexlify,
    help='Query for given MRSIGNER.')
@click.argument('quote_file', metavar='PATH',
    type=click.File('wb'), default='-')
def get_quote(ctx, quote_file,
        sigstruct_file, modulus_be, modulus_le, mrsigner):
    """
    Get quote for a signing key.

    The signing key can be specified using a variety of methods:
    """
    if sum(int(opt is not None) for opt in (
        sigstruct_file,
        modulus_be,
        modulus_le,
        mrsigner,
    )) != 1:
        ctx.fail('specify exactly one of:'
            ' --sigstruct'
            ' --modulus-be'
            ' --modulus-le'
            ' --mrsigner'
        )

    quote_store = store.QuoteStore()

    try:
        if sigstruct_file is not None:
            sigstruct = structs.Sigstruct.from_file(sigstruct_file)
            quote = quote_store.get_quote_for_sigstruct(sigstruct)
        elif modulus_be is not None:
            quote = quote_store.get_quote_for_modulus(modulus_be)
        elif modulus_le is not None:
            quote = quote_store.get_quote_for_modulus(bytes(reversed(modulus_be)))
        elif mrsigner is not None:
            quote = quote_store.get_quote_for_mrsigner(mrsigner)

    except store.QuoteLookupError as e:
        click.echo(str(e), err=True)
        ctx.exit(1)

    except Exception as e:
        ctx.fail(str(e))

    quote_file.write(quote)


@cli.command()
@click.option('--appdir', metavar='PATH',
    type=click.Path(dir_okay=True, file_okay=False),
    default=signer.DEFAULT_APPDIR,
    help='Path to signing application, where gramine manifest is stored.')
@click.option('--template', metavar='PATH',
    type=click.Path(exists=True, dir_okay=False),
    default=signer.DEFAULT_TEMPLATE,
    help='Path to manifest template.')
@click.argument('manifest-args', metavar='ARGS', nargs=-1)
def init(appdir, template, manifest_args):
    """
    Initialise the signing application.

    ARGS are passed directly to gramine-manifest, and this is where you
    configure your application (debug mode, EPID credentials, ...).
    """
    signer.init(appdir, template, manifest_args)


@cli.command()
@click.option('--appdir', metavar='PATH',
    type=click.Path(dir_okay=True, file_okay=False),
    default=signer.DEFAULT_APPDIR,
    help='Path to signing application, where gramine manifest is stored.')
def update_measurement(appdir):
    """
    Update measurement of the signing application.

    This is needed in case some dependencies od the application (like openssl)
    were changed.
    """
    signer.update_measurement(appdir)


if __name__ == '__main__':
    cli()

# vim: tw=80 ts=4 sts=4 sw=4 et
