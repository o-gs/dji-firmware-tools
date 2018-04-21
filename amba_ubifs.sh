#!/bin/bash
# -*- coding: utf-8 -*-

# This scripts mounts a UBI disk image on a Linux host.
#
# The UBI filesystem is a bit different from all FATs, NTFSes and EXTs,
# as it is especially designed for solid state devices. It requires
# specific hardware operations to be accessible on the block device.
# This means the (usually used for mounting images) loopback block device
# will not work with UBIFS. To make it mount, a simulation of solid state
# device is required. Fortunately - there is such simulator, called NANDSim.
#
# Please note that this script is for mounting whole UBI disk images,
# not a single volume files (it mounts whole disks, not partitions).

# Copyright (C) 2016,2017 Mefistotelis <mefistotelis@gmail.com>
# Copyright (C) 2018 Original Gangsters <https://dji-rev.slack.com/>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
# Copy the image to simulated NAND array; on real hardware this only works with ubiformat,
# but simulated NAND will have no issues accepting copy by dd.
#ubiformat /dev/mtd0 --sub-page-size=512 --vid-hdr-offset=2048 -f ${IMAGE}
sudo dd if=${IMAGE} of=/dev/mtd0 bs=$((1024*1024))
echo "${IMAGE}: Attaching UBI filesystem"
modprobe ubi
ubiattach -m 0 -d 0 --vid-hdr-offset=2048
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
