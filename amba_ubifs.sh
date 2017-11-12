#!/bin/bash
# This scripts mounts a UBI disk image on a Linux host.
#
# The UBI filesystem is a bit different from all FATs, NTFSes and EXTs,
# as it is especially designed for solid state devices. It requires
# specific hardware operations to be accessible on the block device.
# This means the (usually used for mounting images) loopback block device
# will not work with UBIFS. To make it mount, a simulation of solid state
# device is required. Fortunately - there is such simulator, called NANDSim.

# Pease note that this script is for mounting whole UBI disk images,
# not a single volume files (it mounts whole disks, not partitions).

#set -x
set -e
# $IMAGE is ubifs image file
IMAGE=$1
SKIP_ADD=0

# the "-d" option can be used for dismount
if [ "${IMAGE}" == "-d" ]; then
  SKIP_ADD=1
  IMAGE="DISMOUNT"
fi

if [ ! "${SKIP_ADD}" -eq "1" ]; then
  if [ ! -e "${IMAGE}" ]; then
    echo "${IMAGE}: Image file not found"
    exit 1
  fi
fi

if [ -e /dev/ubi0_0 ]; then
  echo "${IMAGE}: UBI volume 0 already in place, removing"
  set +e
  sudo umount /dev/ubi0_0
  set -e
fi

if [ -e /dev/ubi0_1 ]; then
  echo "${IMAGE}: UBI volume 1 already in place, removing"
  set +e
  sudo umount /dev/ubi0_1
  set -e
fi

if [ -e /dev/ubi0 ]; then
  echo "${IMAGE}: UBI filesystem already attached, detaching"
  ubidetach -d 0
fi

if [ "${SKIP_ADD}" -eq "1" ]; then
  echo "${IMAGE}: Unloading modules"
  set +e
  rmmod ubifs
  rmmod nandsim
  set -e
  echo "${IMAGE}: Done, all clear"
  exit 0
fi

if [ ! -b "/dev/mtd0" ]; then
  echo "${IMAGE}: Loading module to create mtd0"
  # size of created mtd is 256.0 MiB
  #modprobe nandsim first_id_byte=0x2c second_id_byte=0xda third_id_byte=0x90 fourth_id_byte=0x95
  # size of created mtd is 128.0 MiB
  #modprobe nandsim first_id_byte=0xec second_id_byte=0xd3 third_id_byte=0x51 fourth_id_byte=0x95
  # size of created mtd is 64MiB-2048
  modprobe nandsim first_id_byte=0x20 second_id_byte=0xa2 third_id_byte=0x00 fourth_id_byte=0x15
else
  echo "${IMAGE}: Module for mtd0 already loaded"
  rmmod ubi
fi
echo "${IMAGE}: Loading image to simulated device"
flash_erase /dev/mtd0 0 0
#ubiformat /dev/mtd0 -s 2048 -O 2048
sudo dd if=${IMAGE} of=/dev/mtd0 bs=$((1024*1024))
echo "${IMAGE}: Attaching UBI filesystem"
modprobe ubi
ubiattach -m 0 -d 0 -O 2048
if [ ! -e /dev/ubi0_0 ]; then
  echo "${IMAGE}: No volumes found, loading UBI must've failed"
  exit 2
fi
echo "${IMAGE}: Mounting volumes"
mkdir -p "/mnt/ubi0_0"
mount -t ubifs /dev/ubi0_0 "/mnt/ubi0_0"
# volume 1 will not mount anyway; its alomst empty, likely swap
#mkdir -p "/mnt/ubi0_1"
#mount -t ubifs /dev/ubi0_1 "/mnt/ubi0_1"

exit 0
