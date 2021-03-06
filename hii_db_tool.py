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

import io
import os
import sys
import enum
import struct
import click

from pathlib import Path
from typing import Union, Tuple


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


# See section 32.3.6.2 - String Information
class StringInfoBlockTypes(enum.Enum):
    END = 0x00
    STRING_SCSU = 0x10
    STRING_SCSU_FONT = 0x11
    STRINGS_SCSU = 0x12
    STRINGS_SCSU_FONT = 0x13
    STRING_UCS2 = 0x14
    STRING_UCS2_FONT = 0x15
    STRINGS_UCS2 = 0x16
    STRINGS_UCS2_FONT = 0x17
    DUPLICATE = 0x20
    SKIP2 = 0x21
    SKIP1 = 0x22
    EXT1 = 0x30
    EXT2 = 0x31
    EXT4 = 0x32
    FONT = 0x40


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
        self._package_items = None

    @property
    def package_type(self) -> HIIPackageTypes:
        return self._package_type

    def _parse_device_paths(self):
        # See section 10.3.1 -- EFI_DEVICE_PATH_PROTOCOL
        package_items = []
        package_fd = io.BytesIO(self._package_blob)
        # type and length packed into an unsigned int
        package_fd.seek(4, os.SEEK_SET)
        while package_fd.tell() < len(self._package_blob):
            if (package_fd.tell() + 4) > len(self._package_blob):
                raise HIIDBError('Insufficient data for device path header')
            dp_header = struct.unpack('=BBH', package_fd.read(4))
            # Magic number: End of Hardware Device Path
            if dp_header[0] == 0x7F:
                break
            body_len = dp_header[2] - 4
            if (package_fd.tell() + body_len) > len(self._package_blob):
                raise HIIDBError('Insufficient data for device path body')
            dp_data = package_fd.read(body_len)
            package_items.append(dp_header[:2] + (dp_data,))
        if package_fd.tell() != len(self._package_blob):
            raise HIIDBError('Device path package could not be parsed')
        self._package_items = tuple(package_items)

    def _parse_strings(self):
        header_size, string_info_offset = struct.unpack(
            '=LL', self._package_blob[4:12]
        )
        assert header_size == string_info_offset
        package_fd = io.BytesIO(self._package_blob)
        package_fd.seek(header_size, os.SEEK_SET)
        package_items = []
        block_type = None
        while block_type != StringInfoBlockTypes.END:
            start_offset = package_fd.tell()
            block_type = StringInfoBlockTypes(
                struct.unpack('=B', package_fd.read(1))[0]
            )
            if block_type == StringInfoBlockTypes.STRING_UCS2:
                while package_fd.read(2) != b'\x00\x00':
                    pass
            elif block_type == StringInfoBlockTypes.END:
                pass
            elif block_type == StringInfoBlockTypes.SKIP1:
                package_fd.seek(1, os.SEEK_CUR)
            elif block_type == StringInfoBlockTypes.SKIP2:
                package_fd.seek(2, os.SEEK_CUR)
            elif block_type == StringInfoBlockTypes.DUPLICATE:
                package_fd.seek(2, os.SEEK_CUR)
            elif block_type == StringInfoBlockTypes.EXT1:
                package_fd.seek(1, os.SEEK_CUR)
            elif block_type == StringInfoBlockTypes.EXT2:
                package_fd.seek(2, os.SEEK_CUR)
            elif block_type == StringInfoBlockTypes.EXT4:
                package_fd.seek(4, os.SEEK_CUR)
            else:
                raise HIIDBError(
                    'Unsupported string info block type {}'.format(block_type)
                )
            package_items.append(
                self._package_blob[start_offset:package_fd.tell()]
            )
        assert package_fd.tell() == len(self._package_blob)
        self._package_items = tuple(package_items)

    def _parse_simple_fonts(self):
        # See section 32.3.2.1 -- EFI_HII_SIMPLE_FONT_PACKAGE_HDR
        package_fd = io.BytesIO(self._package_blob)
        package_fd.seek(4, os.SEEK_SET)
        ng_count, wg_count = struct.unpack('=HH', package_fd.read(4))
        narrow_glyphs = []
        while ng_count > 0:
            if (package_fd.tell() + 22) > len(self._package_blob):
                raise HIIDBError('Insufficient data for next narrow glyph')
            narrow_glyphs.append((
                package_fd.read(2).decode('UTF-16'),
                ord(package_fd.read(1)),
                package_fd.read(19)
            ))
            ng_count -= 1
        wide_glyphs = []
        while wg_count > 0:
            if (package_fd.tell() + 44) > len(self._package_blob):
                raise HIIDBError('Insufficient data for next wide glyph')
            wide_glyphs.append((
                package_fd.read(2).decode('UTF-16'),
                ord(package_fd.read(1)),
                package_fd.read(19),
                package_fd.read(19),
            ))
            package_fd.seek(3, os.SEEK_CUR)
            wg_count -= 1
        if package_fd.tell() != len(self._package_blob):
            raise HIIDBError('Simple font package could not be parsed')
        self._package_items = (tuple(narrow_glyphs), tuple(wide_glyphs))

    def _parse_forms(self):
        self._package_items = ()

    @property
    def items(self):
        if self._package_items is None:
            if self._package_type == HIIPackageTypes.STRINGS:
                self._parse_strings()
            elif self._package_type == HIIPackageTypes.DEVICE_PATH:
                self._parse_device_paths()
            elif self._package_type == HIIPackageTypes.SIMPLE_FONTS:
                self._parse_simple_fonts()
            elif self._package_type == HIIPackageTypes.FORMS:
                self._parse_forms()
            else:
                raise HIIDBError('Unsupported package type')
        return self._package_items


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
            pl_fd = io.BytesIO(self._pl_blob)
            pl_fd.seek(20, io.SEEK_SET)  # 16 bytes GUID + 4 bytes length
            while pl_fd.tell() < len(self._pl_blob):
                start_offset = pl_fd.tell()
                if (start_offset + 4) > len(self._pl_blob):
                    raise HIIDBError('Insufficient data for next package header')
                package_header, = struct.unpack('=L', pl_fd.read(4))
                package_size = package_header & 0xFFFFFF
                if (start_offset + package_size) > len(self._pl_blob):
                    raise HIIDBError('Insufficient data for next package')
                package_type = HIIPackageTypes((package_header >> 24) & 0xFF)
                if package_type == HIIPackageTypes.PACKAGE_END:
                    break
                pl_fd.seek(start_offset)
                packages.append(HIIPackage(
                    package_type, pl_fd.read(package_size)
                ))
            if pl_fd.tell() != len(self._pl_blob):
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
        package_lists = []
        hii_blob_fd = io.BytesIO(hii_blob)
        while hii_blob_fd.tell() < len(hii_blob):
            start_offset = hii_blob_fd.tell()
            if (start_offset + 20) > len(hii_blob):
                raise HIIDBError('Insufficient data for next package list header')
            hii_blob_fd.seek(16, os.SEEK_CUR)
            package_list_size, = struct.unpack('=L', hii_blob_fd.read(4))
            if (start_offset + package_list_size) > len(hii_blob):
                raise HIIDBError('Insufficient data for next package list')
            hii_blob_fd.seek(start_offset)
            package_lists.append(cls(hii_blob_fd.read(package_list_size)))
            start_offset += package_list_size
        if hii_blob_fd.tell() != len(hii_blob):
            raise HIIDBError('HII database encoding problem (corrupt data?)')
        return tuple(package_lists)


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
                    print('  {}: {}'.format(package.package_type, len(package.items)))
            with open('/tmp/PACKAGE', 'wb') as package_fd:
                package_fd.write(package_lists[0].packages[0]._package_blob)
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
