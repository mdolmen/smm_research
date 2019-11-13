/** @file
 *
 * Read memory at a given address.
 *
**/

#include <Uefi.h>
#include <assert.h>
#include <Protocol/ShellParameters.h>
#include <Library/IoLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>

/**
  The user Entry Point for Application. The user code starts with this function
  as the real entry point for the application.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.  
  @param[in] SystemTable    A pointer to the EFI System Table.
  
  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
    EFI_STATUS status = EFI_SUCCESS;
    EFI_SHELL_PARAMETERS_PROTOCOL *shell_param = NULL;
    EFI_GUID shell_param_proto = EFI_SHELL_PARAMETERS_PROTOCOL_GUID;

    UINT64 address = 0, size = 0, index = 0;

    // Load protocol to handle cmdline arguments
    status = SystemTable->BootServices->HandleProtocol(
            ImageHandle,
            &shell_param_proto,
            (void**) &shell_param);
    
    if (status != EFI_SUCCESS || shell_param == NULL)
    {
        Print(L"[-] Failed to load EFI_SHELL_PARAMETERS_PROTOCOL..\n");
        return status;
    }

    if (shell_param->Argc != 3)
    {
        Print(L"Usage: %s <address> <size>\n", shell_param->Argv[0]);
        return status;
    }

    // Convert arguments to integers
    ASSERT( shell_param->Argv[1] != NULL );
    address = StrHexToUint64(shell_param->Argv[1]);

    ASSERT( shell_param->Argv[2] != NULL );
    size = StrHexToUint64(shell_param->Argv[2]);

    if (address == 0 || size == 0)
    {
        Print(L"[-] Wrong arguments provided..\n");
        return status;
    }

    Print(L"Will read %d bytes at 0x%016x\n", size, address);

    // Print memory content
    Print(L"[+] Memory content at %p:\n", address);
    for (index = 0; index < size; index++, address++)
        Print(L"0x%02x ", *(unsigned char*)address);
    Print(L"\n");

    return status;
}
