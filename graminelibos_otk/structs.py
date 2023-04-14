# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2023 Wojtek Porczyk <woju@invisiblethingslab.com>

import datetime
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

def _bcd(value, *, ib, ob):
    ret = 0
    shift = itertools.count()
    while value:
        value, digit = divmod(value, ib)
        ret += digit * (ob ** next(shift))
    return ret

def bcd_decode(value):
    return _bcd(value, ib=16, ob=10)

def bcd_encode(value):
    return _bcd(value, ib=10, ob=16)


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
            value = self.encode(value).to_bytes(length=self.length, byteorder='little')
        self.struct.pack_into(instance, self.offset, value)

    @staticmethod
    def encode(value):
        return value

class _field_ro_bcd(_field_ro):
    class Value(_field_ro.Value):
        def __int__(self):
            return bcd_decode(super().__int__())
    encode = staticmethod(bcd_encode)

class _field_bcd(_field_ro_bcd, _field):
    pass

class InvalidSigstruct(Exception):
    pass

class Sigstruct(bytearray):
    # SDM vol. 3D part 4, 38.13, table 38-19
    # https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf
    header =    _field(   0,  16)

    _date =     _field(  20,   4)
    day =       _field_bcd(20, 1)
    month =     _field_bcd(21, 1)
    year =      _field_bcd(22, 2)

    header2 =   _field(  24,  16)
    modulus =   _field( 128, 384)
    exponent =  _field( 512,   4)
    signature = _field( 516, 384)
    mrenclave = _field( 960,  32)
    isvprodid = _field(1024,   2)
    isvsvn =    _field(1026,   2)
    q1 =        _field(1040, 384)
    q2 =        _field(1424, 384)

    @property
    def date(self):
        return datetime.date(int(self.year), int(self.month), int(self.day))

    @date.setter
    def date(self, value):
        self.year = value.year
        self.month = value.month
        self.day = value.day


    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)

        if len(self) != SIGSTRUCT_SZ:
            raise InvalidSigstruct(
                f'wrong length: expected {SIGSTRUCT_SZ}, got {len(self)}')

        # Prevent bytearray from resizing by holding memoryview of ourselves.
        # As long as memoryview lives, all operations that would change the
        # length, like bytearray.append(), will instead raise BufferError.
        # see also:
        # https://docs.python.org/3/library/stdtypes.html#memoryview.release
        self._m = memoryview(self)

        if self.header != SIGSTRUCT_HEADER:
            raise InvalidSigstruct('wrong HEADER')
        if self.header2 != SIGSTRUCT_HEADER2:
            raise InvalidSigstruct('wrong HEADER2')

    @classmethod
    def from_file(cls, file):
        return cls(file.read(SIGSTRUCT_SZ + 1))

    def get_signing_data(self):
        return self[0:128] + self[900:1028]

    def get_mrsigner(self):
        return get_mrsigner_for_modulus_le(self.modulus)


class Quote(bytes):
    report_data_mrsigner =  _field_ro(368, 32)
    mrenclave =             _field_ro(112, 32)
