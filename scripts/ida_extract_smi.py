#!/usr/bin/env python3
#
# Extract the SMI number(s) of the all SMI handlers.
#
# Unicorn usage inspired from: https://github.com/alexhude/uEmu

import os

import idc
import idaapi
import idautils

from unicorn import *
from unicorn.x86_const import *

FILENAME = "C:\Users\user\Desktop\logs.txt"
BASE = idaapi.get_imagebase()
STACK_ADDR = 0x0
STACK_SIZE = 1024*1024
PAGE_SIZE = 0x1000
next_call = 0
# TODO : change the path
f = open(FILENAME, "ab")

regs = [
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
    UC_X86_REG_RIP, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10,
    UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
    UC_X86_REG_R15
]

if idaapi.IDA_SDK_VERSION >= 700:
    # functions
    IDA_SegStart      = idc.get_segm_start
    IDA_SegEnd        = idc.get_segm_end
    IDA_GetBytes      = idaapi.get_bytes
    IDA_GetFunc       = idaapi.get_func
    IDA_GetSegmByName = idaapi.get_segm_by_name
else:
    # functions
    IDA_SegStart      = idc.SegStart
    IDA_SegEnd        = idc.SegEnd
    IDA_GetBytes      = idaapi.get_many_bytes
    IDA_GetFunc       = idaapi.get_func
    IDA_GetSegmByName = idaapi.get_segm_by_name

def ALIGN_PAGE_DOWN(x):
    return x & ~(PAGE_SIZE - 1)

def ALIGN_PAGE_UP(x):
    return (x + PAGE_SIZE - 1) & ~(PAGE_SIZE-1)

def read_op_next_inst(inst, start, up):
    """
    Read the operand of the next 'inst' instruction starting from 'start' and
    going upward (up != 0) or downward (up == 0).
    """
    addr_tmp = start
    address = ""
    operand = ""

    if up:
        while True:
            addr_tmp = idc.PrevHead(addr_tmp)
            if GetOpnd(addr_tmp, 0) == inst:
                break
    else:
        while True:
            addr_tmp = idc.NextHead(addr_tmp)
            if GetOpnd(addr_tmp, 0) == inst:
                break

    address = addr_tmp
    operand = GetOpnd(address, 1)

    return (address, operand)

def read_data(filename):
    with open(filename, "rb") as f:
        data = f.read()
        f.close()
    return data

def set_registers(emu, regs, value):
    for r in regs:
        emu.reg_write(r, value)

def map_binary(emu, filename, size):
    """
    Map 'filename' into the memory of the emulator.
    """
    emu.mem_map(BASE, ALIGN_PAGE_UP(size))
    emu.mem_write(BASE, read_data(filename))

def hook_skip_calls(emu, addr, size, user_data):
    # Need to skip return instructions too: when we emulate an area not
    # recognized as a function, the emulation will not stop at the retn and the
    # execution will continue at someplace we don't want to exec.
    #
    # Skip 0xCC (INT3 breakpoints) to not stop the execution.
    mnem = GetMnem(addr)
    if mnem == "call" or idaapi.get_byte(addr) == 0xCC or "ret" in mnem:
        emu.reg_write(UC_X86_REG_RIP, addr+size)
    elif "j" in mnem:
        if hex(int(GetOpnd(addr, 0)[4:], 16)) > next_call:
            emu.reg_write(UC_X86_REG_RIP, addr+size)
    return

def hook_debug(emu, addr, size, user_data):
    f.write("(debug) Tracing instruction at {} (size = {})\n".format(hex(addr), size))
    #tmp = emu.mem_read(addr, size)
    #f.write("  -> {} bytes read are: ".format(size))
    #for i in tmp:
    #    f.write("%x" %(i))

def hook_mem_invalid(emu, access, addr, size, value, user_data):
    if access == UC_MEM_WRITE_UNMAPPED:
        f.write("  [-] Trying to write to unmapped memory. Allocating some at target address and resuming.\n")
        s = ALIGN_PAGE_DOWN(addr)
        e = ALIGN_PAGE_UP(addr+size)
        emu.mem_map(s, e - s)

        # Return True to indicate we want to continue emulation
        return True
    elif access == UC_MEM_READ_UNMAPPED:
        # Just skip it
        s = ALIGN_PAGE_DOWN(addr)
        e = ALIGN_PAGE_UP(addr+size)
        emu.mem_map(s, e - s)
        emu.mem_write(s, "\x00" * (s - e))

        return True


def find_prev_fn_end(addr):
    """
    Return the end address of the previous function.
    """
    f = IDA_GetFunc(addr)
    while f is None and addr > BASE:
        addr -= 0x20
        f = IDA_GetFunc(addr)

    if f is None:
        return None
    
    return f.endEA

def find_next_fn_start(addr):
    """
    Return the start address of the next function.
    """
    f = IDA_GetFunc(addr)
    while f is None and addr < IDA_GetSegmByName(".text").endEA:
        addr += 0x20
        f = IDA_GetFunc(addr)

    if f is None:
        return None
    
    return f.startEA

def get_emu_range(address):
    """
    Get the start and end address of the area we want to emulate. Either a
    function or a section of code (not recognized by IDA as part of a function)
    between 2 functions.
    """
    f = IDA_GetFunc(address)
    if f:
        emu_start_addr = f.startEA
        emu_end_addr = f.endEA
    else:
        emu_start_addr = find_prev_fn_end(address)
        emu_end_addr = find_next_fn_start(address)

    return (emu_start_addr, emu_end_addr)

def init_emu():
    f.write("  [+] Setting up emulation..\n")
    emu = Uc(UC_ARCH_X86, UC_MODE_64)

    # Map segments with info from IDA
    filename = idaapi.get_input_file_path()
    s = os.path.getsize(filename)
    map_binary(emu, filename, s)
    f.write("  [+] Binary mapped.\n")
    
    # Map the stack
    global STACK_ADDR
    STACK_ADDR = ALIGN_PAGE_UP(BASE + s)
    emu.mem_map(STACK_ADDR, STACK_SIZE)

    # Set registers
    set_registers(emu, regs, 0)
    # -1024 so a function fetching arguments will not access unmapped memory.
    emu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE-1024)
    f.write("  [+] Registers OK.\n")

    return emu

def extract_smi_number(emu, start, end, start_pseudo_taint, dispatch_proto_offset):
    """
    Find call(s) to Register(). Since we are dealing with 64-bit binaries and
    the address of Register() is the first member of a struct, a call to it
    will require a dereferencement of the struct pointer with a 'qword ptr'
    instruction.  Here we are looking for which register contains the address
    of the struct and then identify all the 'qword ptr' on that register
    (before any other modifications are made to it).
    """

    reg_called = ""
    call_to_register = ""
    nb_calls = 0
    addr_tmp = start_pseudo_taint

    while addr_tmp <= end:
        addr_tmp = idc.NextHead(addr_tmp)

        # Exit when 'reg_called' is being modified a second time (it doesn't
        # contains the address we are looking for anymore.
        if GetOpnd(addr_tmp, 0) == reg_called:
            reg_called = ""
        # A register is being set with the interface's address
        if GetOpnd(addr_tmp, 1) == dispatch_proto_offset:
            reg_called = GetOpnd(addr_tmp, 0)
        # This is what we are looking for
        elif reg_called != "" and GetMnem(addr_tmp) == "call" and GetOpnd(addr_tmp, 0) == "qword ptr [{}]".format(reg_called):
            next_call = addr_tmp
            f.write("  [+] Register() is called at : {}\n".format(hex(addr_tmp)))
            nb_calls += 1

            # Get SMI input value
            f.write("  [+] Starting emulation from {} to {}\n".format(hex(start), hex(addr_tmp)))
            #emu.hook_add(UC_HOOK_CODE, hook_debug)
            emu.hook_add(UC_HOOK_CODE, hook_skip_calls)
            emu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)
            emu.emu_start(start, addr_tmp)

            r8 = emu.reg_read(UC_X86_REG_R8)
            if r8 == 0xffffffff:
                f.write("  [-] SMI number unknown (-1).\n")
                continue
            if r8 > STACK_ADDR and r8 < STACK_ADDR + STACK_SIZE:
                smi_number = emu.mem_read(r8, 1)
            else:
                smi_number = r8
            f.write("  [+] SMI number : {}.\n".format(hex(ord(smi_number))))


            # If there is another call to Register() we will start the emulation
            # from here
            start = addr_tmp

    return nb_calls

if __name__ == "__main__":

    # Let IDA load the binary and build the DB.
    idaapi.autoWait()

    f.write("[{}]\n".format(idaapi.get_input_file_path()))

    guid_in_opnd = 0
    # To research from IDA, the GUID need to be a string of bytes, with the
    # correct endianness (by block).

    # TODO : make it more generic
    # The following = { 0xe541b773, 0xdd11, 0x420c, 0xb0, 0x26, 0xdf, 0x99, 0x36, 0x53, 0xf8, 0xbf }
    #guid = "73 b7 41 e5 11 dd 0c 42 b0 26 df 99 36 53 f8 bf"

    # The following = { 0x18a3c6dc, 0x5eea, 0x48c8, 0xa1, 0xc1, 0xb5, 0x33, 0x89, 0xf9, 0x89, 0x99 }
    guid = "dc c6 a3 18 ea 5e c8 48 a1 c1 b5 33 89 f9 89 99"

    # Search for that binary sequence in .data and .rdata. Useless on newer
    # version: GUID are in .text.
    #data = IDA_GetSegmByName(".data").startEA
    #guid_address = FindBinary(data, SEARCH_DOWN, guid)
    #if hex(guid_address) == 0xFFFFFFFFFFFFFFFF:
    #    rdata = IDA_GetSegmByName(".rdata").startEA
    #    FindBinary(rdata, SEARCH_DOWN, guid)

    guid_address = FindBinary(BASE, SEARCH_DOWN, guid)

    if hex(guid_address) == hex(0xFFFFFFFFFFFFFFFF):
        f.write("  [-] GUID was not found, aborting!\n")
        f.close()
        idc.Exit(0)
        exit(1)

    # TODO : refactor to manage multiple xrefs

    # Get cross refs to the GUID
    for addr in XrefsTo(guid_address, flags=0):
        guid_in_opnd = addr.frm

    # Find next call instruction ( LocateProtocol() )
    next_call = 0

    addr_tmp = guid_in_opnd
    while True:
        addr_tmp = idc.NextHead(addr_tmp)
        if GetMnem(addr_tmp) == "call":
            next_call = addr_tmp
            break
    f.write("  [+] LocateProtocol(SW_Dispatch_proto) at : {} \n".format(hex(next_call)))

    # Now get backwards to look for R8 as arguments. It will contains the address
    # where will be stored the interface returned by LocateProtocol().
    dispatch_proto_addr = 0
    dispatch_proto_offset = ""

    (dispatch_proto_addr, dispatch_proto_offset) = read_op_next_inst("r8", next_call, 1)
    # At this point if the content of R8 is 'qword_...' (which is part of the
    # .data section and is not executable) then the use of the interface will
    # happen through the code segment ('cs:qword_...') :
    # Ex: lea  r8, qword_1234
    #     mov  rax, cs:qword_1234
    #     call qword ptr [rax]
    #
    # Similar to far call in real-mode : https://c9x.me/x86/html/file_module_x86_id_26.html.
    if "qword_" in dispatch_proto_offset:
        dispatch_proto_offset = "cs:"+dispatch_proto_offset
    f.write("  [+] SW Dispatch proto interface offset = {} \n".format(dispatch_proto_offset))


    # Init Unicorn Engine
    emu = init_emu()

    (start, end) = get_emu_range(idaapi.toEA(0, next_call))

    nb_calls_to_register = extract_smi_number(emu, start, end, dispatch_proto_addr, dispatch_proto_offset)

    # If no call found at all, the interface is probably accessed from another
    # function. Get fcts that ref it and scan them.
    if nb_calls_to_register == 0:
        seen = []

        for addr in XrefsTo( int(dispatch_proto_offset.split('_')[1], 16), flags=0):
            a = addr.frm

            if a == dispatch_proto_addr:
                continue

            func = IDA_GetFunc(a)
            if func is None:
                continue
            if func.startEA in seen:
                continue

            seen.append(func.startEA)

            # Start emulation
            extract_smi_number(emu, func.startEA, func.endEA, func.startEA, dispatch_proto_offset)

    f.write("[*] Done!\n\n")
    f.close()
    idc.Exit(0)
