#!/usr/bin/env python3

# Binary search of predefined GUIDs on a firmware dump repository done with
# CHIPSEC.
#
# It will extract the folder of modules containing the desired GUID (either in
# the code or in the header) into a new directory.

import os
import sys
import mmap
import struct
import shutil
import argparse
from pathlib import Path

# List of GUID to search for.
#
# SMM_SW_DISPATCH_PROTOCOL_GUID as defined in (in order):
#    - the PI spec volume 4 version 0.9 (edk2 branch UDK2010)
#    - the PI spec volume 4 version 1.6 (2017, maybe earlier version too)
# EFI_MM_CPU_PROTOCOL_GUID, PI version 1.6
GUID_LIST = [
    #[0xe541b773, 0xdd11, 0x420c, 0xb0, 0x26, 0xdf, 0x99, 0x36, 0x53, 0xf8, 0xbf],
    #[0x18a3c6dc, 0x5eea, 0x48c8, 0xa1, 0xc1, 0xb5, 0x33, 0x89, 0xf9, 0x89, 0x99]
    [0xeb346b97, 0x975f, 0x4a9f, 0x8b, 0x22, 0xf8, 0xe9, 0x2b, 0xb3, 0xd5, 0x69]
]

def parser_args():
    parser = argparse.ArgumentParser(description="Binary search of predefined GUIDs on a firmware dump repository done with CHIPSEC")
    parser.add_argument("-o", "--output", action="store", dest="output", required=True, help="Name of the folder to store the results.")
    parser.add_argument("-a", "--all", action="store_true", help="Search in PE binaries and dependencies header.")
    parser.add_argument("-b", "--binary", action="store_true", help="Search only in PE binaries.")
    parser.add_argument("-d", "--dependency", action="store_true", help="Search only in dependencies header.")
    return parser

def guid_to_string(guid):
    return '-'.join(hex(x) for x in guid)

def cp_module_dir(path, output, search_in_bin, search_in_dep):
    # Copy the dir containing the module name.
    p = Path(path)
    p = p.parent

    # The subtree organization depends on the module. Get back till we get to
    # the directory which contains the name of the module. (May be subject to
    # change depending on UEFIExtract version)
    if (search_in_bin):
        while "PE32 image section" in p.name or "Compressed section" in p.name:
            p = p.parent
    elif (search_in_dep):
        while "DXE dependency section" in p.name:
            p = p.parent
    
    module_dir = p.name
    
    # TODO : test on Windows
    if os.name == "nt":
        shutil.copytree(str(p), output+'\\'+str(module_dir))
    else:
        shutil.copytree(str(p), output+'/'+str(module_dir))

if __name__ == "__main__":

    parser = parser_args()
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        exit(1)

    search_in_bin = args.binary
    search_in_dep = args.dependency
    output = args.output

    for i in range( len(GUID_LIST) ):
        # Create a byte sequence that respect the endianess of each subpart of
        # the GUID.
        guid = struct.pack('<I', GUID_LIST[i][0])
        guid += struct.pack('<H', GUID_LIST[i][1])
        guid += struct.pack('<H', GUID_LIST[i][2])
        guid += bytes( GUID_LIST[i][3:] )

        for root, dirs, files in os.walk('.'):
            for filename in files:
                if (filename == "body.bin"):

                    # Search in module's binary.
                    if ("PE32 image" in root and search_in_bin):
                        path = root + '/' + filename
                        f = open(path, "rb")

                        mem = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                        if mem.find(guid) != -1:
                            print("[+] GUID {} found in {}".format( guid_to_string(GUID_LIST[i]), path ));
                            cp_module_dir(path, output, search_in_bin, search_in_dep)

                        mem.close()
                        f.close()

                    # Search in module's dependency headers.
                    elif ("DXE dependency" in root and search_in_dep):
                        path = root + '/' + filename
                        f = open(path, "rb")

                        mem = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                        if mem.find(guid) != -1:
                            print("[+] GUID {} found in {}".format( guid_to_string(GUID_LIST[i]), path ));
                            cp_module_dir(path, output, search_in_bin, search_in_dep)

                        mem.close()
                        f.close()
