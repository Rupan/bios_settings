#!/usr/bin/python3

##
#  A Python library and application which can inspect the HII database.
#  See the "Human Interface Infrastructure" section of the UEFI spec
#  version 2.7 errata A (August 2017), section 32.3 for details.
#    http://uefi.org/specifications
#
#  Copyright (c) 2018, Michael Mohr <akihana@gmail.com>.
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.
##

import os
import io
import sys
import enum
import struct
import click

from pathlib import Path


# Struct definitions are based upon C structures from the EDK2 in:
#   EdkCompatibilityPkg/Foundation/Efi/Include/EfiTypes.h
EFI_GUID = struct.Struct('=LHHBBBBBBBB')
UINT32 = struct.Struct('=L')


# All package types for the EFI_HII_PACKAGE_HEADER type field
class HIIPackageTypes(enum.Enum):
    TYPE_ALL = 0x00
    TYPE_GUID = 0x01
    FORMS = 0x02
    STRINGS = 0x04
    FONTS = 0x05
    IMAGES = 0x06
    SIMPLE_FONTS = 0x07
    DEVICE_PATH = 0x08
    KEYBOARD_LAYOUT = 0x09
    PACKAGE_ANIMATIONS = 0x0A
    PACKAGE_END = 0xDF
    TYPE_SYSTEM_BEGIN = 0xE0
    TYPE_SYSTEM_END = 0xFF


EFI_HII_DATABASE_PROTOCOL_GUID = 'ef9fc172-a1b2-4693-b327-6d32fc416042'
EFI_HII_EXPORT_DATABASE_GUID = '1b838190-4625-4ead-abc9-cd5e6af18fe0'
EFI_VARS_ROOT = Path('/sys/firmware/efi/efivars')


class HIIDBError(Exception):
    pass


def read_hii_data():
    if os.geteuid() != 0:
        raise HIIDBError('Reading the HII database requires root access')
    data_path = EFI_VARS_ROOT / 'HiiDB-{}'.format(EFI_HII_DATABASE_PROTOCOL_GUID)
    if not data_path.exists() or data_path.stat().st_size != 12:
        raise HIIDBError('HII DB export missing, cannot continue')
    with open(data_path, 'rb') as hii_fd:
        hii_descriptor = hii_fd.read(12)
    if len(hii_descriptor) != 12:
        raise HIIDBError('Unable to read the EFI HII descriptor variable')
    hii_flags, hii_size, hii_addr = struct.unpack('@III', hii_descriptor)
    with open('/dev/mem', 'rb') as devmem_fd:
        devmem_fd.seek(hii_addr, os.SEEK_SET)
        hii_database = devmem_fd.read(hii_size)
    if len(hii_database) != hii_size:
        raise HIIDBError('Unable to read HII database contents')
    return hii_database


def parse_hii_package_list(hii_fd: io.BytesIO):
    """
    Deserialize one package list from the HII database, consisting of:
        1 EFI_HII_PACKAGE_LIST_HEADER
        N EFI_HII_PACKAGE_HEADER
    The package list should be terminated by HIIPackageTypes.PACKAGE_END
    :param hii_fd: a file-like object which the HII data can be read from
    :return: a 2-tuple of (package list guid, N-tuple of packages)
    """
    start_offset = hii_fd.tell()
    package_list_guid = EFI_GUID.unpack(hii_fd.read(EFI_GUID.size))
    package_list_size, = UINT32.unpack(hii_fd.read(UINT32.size))
    end_offset = start_offset + package_list_size
    packages = []
    while hii_fd.tell() < end_offset:
        package_header, = UINT32.unpack(hii_fd.read(UINT32.size))
        package_size = (package_header & 0xFFFFFF) - UINT32.size
        package_type = HIIPackageTypes((package_header >> 24) & 0xFF)
        if package_size > 0:
            package_data = hii_fd.read(package_size)
        else:
            package_data = None
        packages.append((package_type, package_data))
    assert hii_fd.tell() == end_offset
    return package_list_guid, tuple(packages)


@click.command()
@click.option('--dump-db', type=click.Path(), help='Dump the HII DB to a file.')
def _main(dump_db):
    if dump_db:
        print('Writing HII database to ' + dump_db)
        try:
            hii_database = read_hii_data()
            with open(dump_db, 'wb') as hii_fd:
                hii_fd.write(hii_database)
            hii_fd = io.BytesIO(hii_database)
            while hii_fd.tell() < len(hii_database):
                parse_hii_package_list(hii_fd)
            return 0
        except HIIDBError as hii_err:
            print('ERROR: ' + str(hii_err))
            return 1
    else:
        with click.Context(_main) as ctx:
            click.echo(_main.get_help(ctx))
        return 0


if __name__ == '__main__':
    sys.exit(_main())
