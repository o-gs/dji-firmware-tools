#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" DUPC Packet Builder.

 This script takes header fields and payload, and builds a proper DUPC
 packet from them.

"""

# Copyright (C) 2018 Mefistotelis <mefistotelis@gmail.com>
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

import os
import sys
import serial
import select
import argparse
import enum
import re
from ctypes import *

sys.path.insert(0, './')
from comm_dat2pcap import (
  calc_pkt55_hdr_checksum, calc_pkt55_checksum,
)

class ACK_TYPE(enum.Enum):
    NO_ACK_NEEDED = 0
    ACK_BEFORE_EXEC = 1
    ACK_AFTER_EXEC = 2

    @classmethod
    def from_name(cls, name):
        for itm in cls:
            if itm.name == name:
                return itm
        raise ValueError('{} is not a valid ack type'.format(name))


class COMM_DEV_TYPE(enum.Enum):
    ANY = 0
    CAMERA = 1
    MOBILE_APP = 2
    CONTROLLER = 3
    GIMBAL = 4
    CENTER_BOARD = 5
    REMOTE_RADIO = 6
    WIFI = 7
    LB_DM3XX_SKY = 8
    LB_MCU_SKY = 9
    PC = 10
    BATTERY = 11
    ESC = 12
    DM368_GROUND = 13
    OFDM_GROUND = 14
    LB_68013_SKY = 15
    SER_68013_GROUND = 16
    MVO = 17
    SVO = 18
    LB_FPGA_SKY = 19
    FPGA_GROUND = 20
    FPGA_SIM = 21
    STATION = 22
    XU = 23
    WTF = 24
    IMU = 25
    GPS = 26
    WIFI_GROUND = 27
    SIG_CVT = 28
    PMU = 29
    UNKNOWN30 = 30
    WM330_OR_WM220 = 31

    @classmethod
    def from_name(cls, name):
        for itm in cls:
            if itm.name == name:
                return itm
        raise ValueError('{} is not a valid module type'.format(name))

class DJICmdV1Header(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('sof', c_ubyte), # Start Of Field
              ('ver_length_tag', c_ushort), # Protocol version and packet length
              ('header_crc8', c_ubyte), # Checksum of preceding bytes
              ('sender_info', c_ubyte), # Sender module identificator
              ('receiver_info', c_ubyte), # Receiver module identificator
              ('seq_num', c_ushort), # Sequence number of this command id
              ('cmd_type_data', c_ubyte), # Packet type, required acknowledgement, encryption
              ('cmd_set', c_ubyte), # Command Set selection
              ('cmd_id', c_ubyte), # Specific command selection
             ]

  def __init__(self):
    self.sof = 0x55
    self.version = 1
    self.whole_length = sizeof(self) + 2

  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    return d

  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)

  def __get_whole_length(self):
        return self.ver_length_tag & 1023

  def __set_whole_length(self, value):
        self.ver_length_tag = (self.ver_length_tag & 64512) | (value & 1023)

  whole_length = property(__get_whole_length, __set_whole_length)

  def __get_version(self):
        return (self.ver_length_tag & 64512) >> 10

  def __set_version(self, value):
        self.ver_length_tag = (self.ver_length_tag & 1023) | ((value << 10) & 64512)

  version = property(__get_version, __set_version)

  def __get_sender_type(self):
        return self.sender_info & 31

  def __set_sender_type(self, value):
        self.sender_info = (self.sender_info & 224) | (value & 31)

  sender_type = property(__get_sender_type, __set_sender_type)

  def __get_sender_index(self):
        return (self.sender_info & 224) >> 5

  def __set_sender_index(self, value):
        self.sender_info = (self.sender_info & 31) | ((value & 7) << 5)

  sender_index = property(__get_sender_index, __set_sender_index)

  def __get_receiver_type(self):
        return self.receiver_info & 31

  def __set_receiver_type(self, value):
        self.receiver_info = (self.receiver_info & 224) | (value & 31)

  receiver_type = property(__get_receiver_type, __set_receiver_type)

  def __get_receiver_index(self):
        return (self.receiver_info & 224) >> 5

  def __set_receiver_index(self, value):
        self.receiver_info = (self.receiver_info & 31) | ((value & 7) << 5)

  receiver_index = property(__get_receiver_index, __set_receiver_index)

  def __get_packet_type(self):
        return (self.cmd_type_data)  >> 7

  def __set_packet_type(self, value):
        self.cmd_type_data = (self.cmd_type_data & 239) | ((value & 1) << 7)

  packet_type = property(__get_packet_type, __set_packet_type)

  def __get_ack_type(self):
        return (self.cmd_type_data >> 5) & 3

  def __set_ack_type(self, value):
        self.cmd_type_data = (self.cmd_type_data & 159) | ((value & 3) << 5)

  ack_type = property(__get_ack_type, __set_ack_type)

  def __get_encrypt_type(self):
        return (self.cmd_type_data & 7)

  def __set_encrypt_type(self, value):
        self.cmd_type_data = (self.cmd_type_data & 248) | (value & 7)

  encrypt_type = property(__get_encrypt_type, __set_encrypt_type)

class DJICmdV1Footer(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('crc16', c_ushort), # Whole packet checksum
             ]

  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    return d

  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)

def encode_command_packet(sender_type, sender_index, receiver_type, receiver_index, seq_num, pack_type, ack_type, encrypt_type, cmd_set, cmd_id, payload):
    djiCmd = DJICmdV1Header()
    djiCmd.whole_length = sizeof(djiCmd) + len(payload) + 2
    djiCmd.header_crc8 = calc_pkt55_hdr_checksum(0x77, (c_ubyte * 3).from_buffer_copy(djiCmd), 3)
    djiCmd.sender_type = sender_type
    djiCmd.sender_index = sender_index
    djiCmd.receiver_type = receiver_type
    djiCmd.receiver_index = receiver_index
    djiCmd.seq_num = seq_num
    djiCmd.packet_type = pack_type
    djiCmd.ack_type = ack_type
    djiCmd.encrypt_type = encrypt_type
    djiCmd.cmd_set = cmd_set
    djiCmd.cmd_id = cmd_id
    enc_data = (c_ubyte * djiCmd.whole_length)()
    memmove(addressof(enc_data), byref(djiCmd), sizeof(djiCmd))
    djiPayload = (c_char * len(payload)).from_buffer_copy(payload)
    memmove(addressof(enc_data) + sizeof(djiCmd), byref(djiPayload), sizeof(djiPayload))
    djiFoot = DJICmdV1Footer()
    djiFoot.crc16 = calc_pkt55_checksum(enc_data, sizeof(enc_data) - 2)
    memmove(addressof(enc_data) + sizeof(djiCmd) + sizeof(djiPayload), byref(djiFoot), sizeof(djiFoot))
    return enc_data

def do_build_packet(options):
    pkt = encode_command_packet(options.sender_type.value, options.sender_index, options.receiver_type.value, options.receiver_index,
      options.seq_num, options.pack_type, options.ack_type.value, options.encrypt_type, options.cmd_set, options.cmd_id,
      options.payload)
    print(' '.join('{:02x}'.format(x) for x in pkt))

def parse_module_ident(s):
    pat = re.compile(r"^([0-9]{1,2})([0-9]{2})$")
    out = re.match(pat, s)
    if out is None:
        raise argparse.ArgumentTypeError("No 4-byte module ident")
    return out

def parse_module_type(s):
    pat = re.compile(r"^[0-9]{1,2}$")
    if re.search(pat, s):
        return COMM_DEV_TYPE(int(s, 10))
    try:
        return COMM_DEV_TYPE.from_name(s.upper())
    except KeyError:
        raise argparse.ArgumentError("Unrecognized value")

def parse_ack_type(s):
    pat = re.compile(r"^[0-9]{1}$")
    if re.search(pat, s):
        return ACK_TYPE(int(s, 10))
    try:
        return ACK_TYPE.from_name(s.upper())
    except KeyError:
        raise argparse.ArgumentError("Unrecognized value")

def main():
    """ Main executable function.

      Its task is to parse command line options and call a function which performs a task.
    """
    parser = argparse.ArgumentParser(description='DUPC Packet Builder')

    parser.add_argument('-n', '--seq_num', default=0, type=int,
                        help='Sequence number of the packet (default is %(default)s)')

    parser.add_argument('-u', '--pack_type', default=0, type=int,
                        help='Pack Type (default is %(default)s)')

    parser.add_argument('-a', '--ack_type', default="No_ACK_Needed", type=parse_ack_type,
                        help='Acknowledgement type, either name or number (default is %(default)s)')

    parser.add_argument('-e', '--encrypt_type', default=0, type=int,
                        help='Encryption type (default is %(default)s)')

    parser.add_argument('-s', '--cmd_set', default=0, type=int,
                        help='Command Set (default is %(default)s)')

    parser.add_argument('-i', '--cmd_id', default=0, type=int,
                        help='Command ID (default is %(default)s)')

    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='Increases verbosity level; max level is set by -vvv')

    subparser = parser.add_mutually_exclusive_group()

    subparser.add_argument('-t', '--sender', type=parse_module_ident,
                        help='Sender Type and Index, in TTII form')

    subparser.add_argument('-tt', '--sender_type', default="PC", type=parse_module_type,
                        help='Sender(transmitter) Type, either name or number (default is %(default)s)')

    parser.add_argument('-ti', '--sender_index', default=1, type=int,
                        help='Sender(transmitter) Index (default is %(default)s)')

    subparser = parser.add_mutually_exclusive_group()

    subparser.add_argument('-r', '--receiver', type=parse_module_ident,
                        help='Receiver Type and Index, in TTII form (ie. 0306)')

    subparser.add_argument('-rt', '--receiver_type', default="ANY", type=parse_module_type,
                        help='Receiver Type, either name or number (default is %(default)s)')

    parser.add_argument('-ri', '--receiver_index', default=0, type=int,
                        help='Receiver index (default is %(default)s)')

    subparser = parser.add_mutually_exclusive_group()

    subparser.add_argument('-x', '--payload_hex', type=str,
                        help='Provide payload as hex string')

    subparser.add_argument('-p', '--payload_bin', default="", type=str,
                        help='Provide binary payload directly (default payload is empty)')

    options = parser.parse_args();

    if (options.payload_hex is not None):
        options.payload = bytes.fromhex(options.payload_hex)
    else:
        options.payload = bytes(options.payload_bin, 'utf-8')

    if (options.sender is not None):
        options.sender_type = COMM_DEV_TYPE(int(options.sender.group(1), 10))
        options.sender_index = int(options.sender.group(2), 10)

    if (options.receiver is not None):
        options.receiver_type = COMM_DEV_TYPE(int(options.receiver.group(1), 10))
        options.receiver_index = int(options.receiver.group(2), 10)

    do_build_packet(options)

if __name__ == '__main__':
    main()
