/*
 * An EFI program to export the HII DB at boot.
 *
 * Copyright (c) 2018, Michael Mohr <akihana@gmail.com>.
 * Based on work by Aaron Miller targeted at GNU EFI:
 *   https://gist.github.com/apage43/bf15f62266159d8c3016e691e44f338c
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/HiiDatabase.h>

#include <sys/stdint.h>

#define HIIDB_VAR_NAME L"HiiDB"

typedef struct HiiDbExportVar {
    UINT32 length;
    UINT32 pointer;
} exportvar_t;

INTN
EFIAPI
ShellAppMain (IN UINTN Argc, IN CHAR16 **Argv) {
    EFI_GUID HiiDatabaseGuid = EFI_HII_DATABASE_PROTOCOL_GUID;
    EFI_HII_DATABASE_PROTOCOL *HiiDb = NULL;
    EFI_STATUS status = EFI_SUCCESS;
    UINTN DataSize = 0;
    EFI_HII_PACKAGE_LIST_HEADER *HiiPackageList = NULL;

    status = gRT->GetVariable(HIIDB_VAR_NAME, &HiiDatabaseGuid, NULL, &DataSize, NULL);
    if (status == EFI_NOT_FOUND) {
        status = gBS->LocateProtocol(&HiiDatabaseGuid, NULL, (VOID **) &HiiDb);
        if (EFI_ERROR(status) || HiiDb == NULL) {
            Print(L"HII protocol could not be found!\n");
            return EFI_UNSUPPORTED;
        }

        DataSize = 0;
        HiiDb->ExportPackageLists(HiiDb, NULL, &DataSize, NULL);
        if (DataSize == 0) {
            Print(L"Couldn't get size for ExportPackageLists\n");
            return EFI_UNSUPPORTED;
        }
        status = gBS->AllocatePool(EfiRuntimeServicesData, DataSize, (void **)&HiiPackageList);
        if (EFI_ERROR(status)) {
            Print(L"Couldn't allocate memory for ExportPackageLists\n");
            return EFI_UNSUPPORTED;
        }
        status = HiiDb->ExportPackageLists(HiiDb, NULL, &DataSize, HiiPackageList);
        if (EFI_ERROR(status)) {
            Print(L"ExportPackageLists failed: %r\n", status);
            return EFI_UNSUPPORTED;
        }

        exportvar_t var;
        var.length = (UINT32)(DataSize & 0xFFFFFFFF);
        var.pointer = (UINT32)((uintptr_t)HiiPackageList & 0xFFFFFFFF);

        status = gRT->SetVariable(HIIDB_VAR_NAME, &HiiDatabaseGuid,
                EFI_VARIABLE_RUNTIME_ACCESS |
                EFI_VARIABLE_BOOTSERVICE_ACCESS,
                sizeof(var), &var);
        if (EFI_ERROR(status)) {
            Print(L"Unable to set " HIIDB_VAR_NAME L" variable: %r\n", status);
            return EFI_UNSUPPORTED;
        } else {
            Print(L"Exported HII Packages (%u bytes), var " HIIDB_VAR_NAME L"-%g\n", DataSize, &HiiDatabaseGuid);
            return EFI_SUCCESS;
        }
    } else if(status == EFI_BUFFER_TOO_SMALL) {
        Print(L"HII export already exists, nothing to do.\n");
        return EFI_SUCCESS;
    } else if (EFI_ERROR(status)) {
        Print(L"Failed to retrieve HII DB: %r\n", status);
        return EFI_UNSUPPORTED;
    } else {
        Print(L"Successfully retrieved HII DB (probably something went wrong?)\n");
        return EFI_UNSUPPORTED;
    }
}
