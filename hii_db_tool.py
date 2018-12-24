#!/usr/bin/python3

##
#  A Python library and application which can inspect the HII database.
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
import struct
import click

from pathlib import Path


EFI_HII_DATABASE_PROTOCOL_GUID = 'ef9fc172-a1b2-4693-b327-6d32fc416042'
EFI_HII_EXPORT_DATABASE_GUID = '1b838190-4625-4ead-abc9-cd5e6af18fe0'
EFI_VARS_ROOT = Path('/sys/firmware/efi/efivars')


class HIIDBError(Exception):
    pass


def read_hii_data():
    if os.geteuid() != 0:
        raise HIIDBError('Reading the HII database requires root access')
    data_path = EFI_VARS_ROOT / 'HiiDB-{}'.format(EFI_HII_EXPORT_DATABASE_GUID)
    if not data_path.exists() or data_path.stat().st_size != 12:
        raise HIIDBError('')
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


@click.command()
@click.option('--dump-db', type=click.Path(), help='Dump the HII DB to a file.')
def _main(dump_db):
    if dump_db:
        print('Writing HII database to ' + dump_db)
        try:
            hii_database = read_hii_data()
            with open(dump_db, 'wb') as hii_fd:
                hii_fd.write(hii_database)
            return 0
        except HIIDBError as hii_err:
            print('ERROR: ' + str(hii_err))
            return 1
    else:
        print('No operation requested.')
        return 0


if __name__ == '__main__':
    sys.exit(_main())
