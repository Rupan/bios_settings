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
import sys
import enum
import struct
import click

from pathlib import Path
from typing import Union, Tuple


# Struct definitions are based upon C structures from the EDK2 in:
#   EdkCompatibilityPkg/Foundation/Efi/Include/EfiTypes.h
EFI_GUID = struct.Struct('=LHHBBBBBBBB')
UINT32 = struct.Struct('=L')
UINT16 = struct.Struct('=H')


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


def read_hii_data() -> bytes:
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


class HIIPackage(object):

    def __init__(self, package_type: HIIPackageTypes, package_blob: bytes):
        self._package_type = package_type
        self._package_blob = package_blob

    @property
    def package_type(self) -> HIIPackageTypes:
        return self._package_type


class HIIPackageList(object):

    def __init__(self, pl_blob: bytes):
        """
        Container and decoder for one HII package list.
        :param pl_blob: The package list as a serialized data blob
        """
        self._pl_blob = pl_blob
        self._guid = None
        self._packages = None

    @property
    def guid(self) -> str:
        """
        Return a string representation of the package list GUID.
        """
        if self._guid is None:
            self._guid = '-'.join((
                self._pl_blob[0:4].hex(), self._pl_blob[4:6].hex(),
                self._pl_blob[6:8].hex(), self._pl_blob[8:16].hex()
            ))
        return self._guid

    @property
    def packages(self) -> Tuple[HIIPackage]:
        """
        Return an iterable representing all packages in the package list blob.
        """
        if self._packages is None:
            packages = []
            start_offset = 20
            while start_offset < len(self._pl_blob):
                if (start_offset+4) > len(self._pl_blob):
                    raise HIIDBError('Insufficient data for next package header')
                package_header, = UINT32.unpack(
                    self._pl_blob[start_offset:start_offset+4]
                )
                package_size = package_header & 0xFFFFFF
                end_offset = start_offset+package_size
                if end_offset > len(self._pl_blob):
                    raise HIIDBError('Insufficient data for next package')
                package_type = HIIPackageTypes((package_header >> 24) & 0xFF)
                package_blob = self._pl_blob[start_offset:end_offset]
                packages.append(HIIPackage(package_type, package_blob))
                start_offset += package_size
            if start_offset != len(self._pl_blob):
                raise HIIDBError('Package list encoding problem (corrupt data?)')
            self._packages = tuple(packages)
        return self._packages

    @classmethod
    def scan(cls, hii_blob: Union[None, bytes]=None) -> Tuple:
        """
        Deserialize all package lists from the HII database.
        :param hii_blob: The serialized HII database
        :return: An n-tuple of HIIPackageList objects
        """
        if hii_blob is None:
            hii_blob = read_hii_data()
        start_offset = 0
        packages = []
        while start_offset < len(hii_blob):
            if (start_offset+20) > len(hii_blob):
                raise HIIDBError('Insufficient data for next package list header')
            package_list_size, = UINT32.unpack(
                hii_blob[start_offset+16:start_offset+20]
            )
            end_offset = start_offset + package_list_size
            if end_offset > len(hii_blob):
                raise HIIDBError('Insufficient data for next package list')
            packages.append(cls(hii_blob[start_offset:end_offset]))
            start_offset += package_list_size
        if start_offset != len(hii_blob):
            raise HIIDBError('HII database encoding problem (corrupt data?)')
        return tuple(packages)


@click.command()
@click.option('--dump-db', type=click.Path(), help='Dump the HII DB to a file.')
def _main(dump_db):
    if dump_db:
        print('Writing HII database to ' + dump_db)
        try:
            hii_database = read_hii_data()
            with open(dump_db, 'wb') as hii_fd:
                hii_fd.write(hii_database)
            package_lists = HIIPackageList.scan(hii_database)
            for package_list in package_lists:
                print(package_list.guid)
                for package in package_list.packages:
                    print('  ' + package.package_type.name)
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
