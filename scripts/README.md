## efi_to_disk

Utility to ease the process of testing an EFI binary. Create a disk image and
copy the EFI application into it. It can be run in QEMU with OVMF.

**Example:**

```bash
# Create the disk image (~46MB)
./efi_to_disk.sh test.img app.efi

# Boot it
qemu-system-x86_64 -cpu qemu64 -bios /path/to/OVMF_CODE.fd -drive file=test.img,if=ide
```

## search_guid

Binary search of predefined GUIDs on a folder containing firmware modules as
parsed by `UEFIExtract`. It will extract the folder of modules containing the
desired GUID (either in the code or in the header) into a new directory. Those
GUID are hardcoded into the script.

**Example:**

```bash
# Dump the flash
python chipsec_util.py spi dump rom.bin

# Parse it (produces a rom.bin.dump)
./UEFIExtract rom.bin

# Now we extract those we are looking for
python search_guid.py --output dest_folder --binary
```

## ida_extract_smi

Automate the extraction of the SMI number register by an SMM module with
`EFI_MM_SW_DISPATCH_PROTOCOL.Register()`. The results are written to a file and
the script can be used with the headless mode of IDA.

**Example:** Here we assume that `C:\path\to\modules` contains only folders of
binaries actually using the protocol mentioned above.

```bash
# Browse each file of the folder and select only those named body.bin with a
# full path containing “PE32”.
ForEach($x in (Get-ChildItem -Path 'C:\path\to\modules' -Recurse -Include *body.bin |
	% { $_.FullName } |
	Select-String -Pattern "PE32"))
{
    # Execute IDA in headless mode and execute the script specified by -S.
    ./ida64.exe -c -A -S"C:\path\ida_extract_smi.py" $x;

    # Wait for IDA to exit before launching another instance otherwise too      
    # much resources are used at once and there are synchronization problems 
    # in the logs file.
    Wait-Process -Id (Get-Process idaq64).id
}
```
