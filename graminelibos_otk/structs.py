# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2023 Wojtek Porczyk <woju@invisiblethingslab.com>

import hashlib
import itertools
import struct

SIGSTRUCT_SZ = 1808
SIGSTRUCT_HEADER  = bytes.fromhex('06000000E10000000000010000000000')
SIGSTRUCT_HEADER2 = bytes.fromhex('01010000600000006000000001000000')

MAX_ISVSVN = 0xffff


def hexdump(data, width=64):
    for _, line in itertools.groupby(enumerate(data.hex()),
            key=(lambda e: e[0] // width)):
        yield ''.join(c for _, c in line)


def get_mrsigner_for_modulus(modulus):
    return get_mrsigner_for_modulus_le(bytes(reversed(modulus)))

def get_mrsigner_for_modulus_le(modulus):
    return hashlib.sha256(modulus).digest()


class _field_ro:
    class Value(bytes):
        def __int__(self):
            return int.from_bytes(self, byteorder='little')

    def __init__(self, offset, length):
        self.offset = offset
        self.length = length
        self.struct = struct.Struct(f'{length}s')

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        return self.Value(self.struct.unpack_from(instance, self.offset)[0])

    def __set__(self, instance, value):
        raise AttributeError('can\'t set attribute')

class _field(_field_ro):
    def __set__(self, instance, value):
        if isinstance(value, int):
            value = value.to_bytes(length=self.length, byteorder='little')
        self.struct.pack_into(instance, self.offset, value)


class InvalidSigstruct(Exception):
    pass

class Sigstruct(bytearray):
    # SDM vol. 3D part 4, 38.13, table 38-19
    # https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf
    header =    _field(   0,  16)
    header2 =   _field(  24,  16)
    modulus =   _field( 128, 384)
    exponent =  _field( 512,   4)
    signature = _field( 516, 384)
    mrenclave = _field( 960,  32)
    isvprodid = _field(1024,   2)
    isvsvn =    _field(1026,   2)
    q1 =        _field(1040, 384)
    q2 =        _field(1424, 384)

    def get_signing_data(self):
        return self[0:128] + self[900:1028]

    @classmethod
    def from_file(cls, file):
        self = file.read(SIGSTRUCT_SZ + 1)
        if len(self) != SIGSTRUCT_SZ:
            raise InvalidSigstruct(
                'wrong length: expected {SIGSTRUCT_SZ}, read {len(buf)}')
        self = cls(self)

        if self.header != SIGSTRUCT_HEADER:
            raise InvalidSigstruct('wrong HEADER')
        if self.header2 != SIGSTRUCT_HEADER2:
            raise InvalidSigstruct('wrong HEADER2')

        return self

    def get_mrsigner(self):
        return get_mrsigner_for_modulus_le(self.modulus)


class Quote(bytes):
    report_data_mrsigner =  _field_ro(368, 32)
    mrenclave =             _field_ro(112, 32)
