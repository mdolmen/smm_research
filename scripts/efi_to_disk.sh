#!/usr/bin/bash

# Create a disk image and copy the EFI application into it. It can be run in
# QEMU with OVMF.
# 
# Source: https://wiki.osdev.org/UEFI#UEFI_applications_in_detail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <image_name_to_create> <efi_application>"
    exit 1
fi

# Available loopback device which will be used to make the created partition
# visible by Linux. May change on your system.
loopback=/dev/loop2

# Create a disk image and format it into an EFI partition
dd if=/dev/zero of=$1 bs=512 count=93750
parted $1 -s -a minimal mklabel gpt
parted $1 -s -a minimal mkpart EFI FAT32 2048s 93716s
parted $1 -s -a minimal toggle 1 boot

# Make partition visible to linux on a loopback device
sudo losetup --offset 1048576 --sizelimit 46934528 $loopback $1
sudo mkdosfs -F 32 $loopback

# Mount and copy
sudo mkdir /mnt/efi && sudo mount $loopback /mnt/efi
sudo cp $2 /mnt/efi

# Clean up
sudo umount /mnt/efi && sudo rm -rf /mnt/efi
sudo losetup -d $loopback

sudo chown $USER:$USER $1
