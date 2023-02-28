# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2023 Wojtek Porczyk <woju@invisiblethingslab.com>

import os
import pathlib

from . import structs

_XDG_CONFIG_HOME = pathlib.Path(
    os.getenv('XDG_CONFIG_HOME', os.path.expanduser('~/.config')))

QUOTE_STORE = _XDG_CONFIG_HOME / 'gramine' / 'otk-quotes'


class QuoteLookupError(LookupError):
    pass

class InvalidQuoteError(Exception):
    pass

class QuoteStore:
    def __init__(self, path=QUOTE_STORE):
        self.path = pathlib.Path(path)

    def get_quote_for_sigstruct(self, sigstruct):
        return self.get_quote_for_mrsigner(
            structs.Sigstruct(sigstruct).get_mrsigner())

    def get_quote_for_modulus(self, modulus):
        return self.get_quote_for_mrsigner(
            structs.get_mrsigner_for_modulus(modulus))

    def get_quote_for_mrsigner(self, mrsigner):
        try:
            with open(self.path) as file:
                for line in file:
                    quote = structs.Quote.fromhex(line)
                    if quote.report_data_mrsigner == mrsigner:
                        return quote
        except FileNotFoundError:
            pass # will raise below
        raise QuoteLookupError('no matching quote found')

    def save(self, modulus, quote):
        quote = structs.Quote(quote)
        expected_mrsigner = structs.get_mrsigner_for_modulus(modulus)
        found_mrsigner = quote.report_data_mrsigner
        if found_mrsigner != expected_mrsigner:
            raise InvalidQuoteError(
                f'MRSIGNER in the quote ({found_mrsigner.hex()}) does not '
                f'match the intended modulus ({expected_mrsigner.hex()})')

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, 'a') as file:
            print(quote.hex(), file=file)


# vim: tw=80 ts=4 sts=4 sw=4 et
