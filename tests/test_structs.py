# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2023 Wojtek Porczyk <woju@invisiblethingslab.com>

import datetime

import pytest

from graminelibos_otk.structs import (
    Sigstruct,
    SIGSTRUCT_SZ,
    SIGSTRUCT_HEADER,
    SIGSTRUCT_HEADER2,
)

@pytest.fixture
def sigstruct():
    yield Sigstruct(
        SIGSTRUCT_HEADER + bytes(8) + SIGSTRUCT_HEADER2 + bytes(1768))


def test_sigstruct_date_read(sigstruct):
    sigstruct[20:24] = bytes.fromhex('14042320')
    assert sigstruct.date == datetime.date(2023, 4, 14)

def test_sigstruct_date_write(sigstruct):
    sigstruct.date = datetime.date(2023, 11, 14)
    assert sigstruct[20:24] == bytes.fromhex('14112320')

def test_sigstruct_date_read_year(sigstruct):
    sigstruct[22:24] = bytes.fromhex('2320')
    assert int(sigstruct.year) == 2023

def test_sigstruct_date_write_year(sigstruct):
    sigstruct.year = 2023
    assert sigstruct[22:24] == bytes.fromhex('2320')

def test_sigstruct_date_read_month(sigstruct):
    sigstruct[21:22] = bytes.fromhex('11')
    assert int(sigstruct.month) == 11

def test_sigstruct_date_write_month(sigstruct):
    sigstruct.month = 11
    assert sigstruct[21:22] == bytes.fromhex('11')

def test_sigstruct_date_read_day(sigstruct):
    sigstruct[20:21] = bytes.fromhex('14')
    assert int(sigstruct.day) == 14

def test_sigstruct_date_write_day(sigstruct):
    sigstruct.day = 14
    assert sigstruct[20:21] == bytes.fromhex('14')
