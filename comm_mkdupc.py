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

__version__ = "0.5.0"
__author__ = "Mefistotelis @ Original Gangsters"
__license__ = "GPL"

import os
import sys
import select
import argparse
import enum
import re
from ctypes import *
from collections import OrderedDict

sys.path.insert(0, './')
from comm_dat2pcap import (
  calc_pkt55_hdr_checksum, calc_pkt55_checksum,
  eprint,
)

class DecoratedEnum(enum.Enum):
    @classmethod
    def from_name(cls, name):
        for itm in cls:
            if itm.name == name:
                return itm
        raise ValueError('{} is not a known value'.format(name))


class ACK_TYPE(DecoratedEnum):
    NO_ACK_NEEDED = 0
    ACK_BEFORE_EXEC = 1
    ACK_AFTER_EXEC = 2


class COMM_DEV_TYPE(DecoratedEnum):
    ANY = 0
    CAMERA = 1
    MOBILE_APP = 2
    FLYCONTROLLER = 3
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


class ENCRYPT_TYPE(DecoratedEnum):
    NO_ENC = 0
    AES_128 = 1
    SELF_DEF = 2
    XOR = 3
    DES_56 = 4
    DES_112 = 5
    AES_192 = 6
    AES_256 = 7


class PACKET_TYPE(DecoratedEnum):
    REQUEST = 0
    RESPONSE = 1


class CMD_SET_TYPE(DecoratedEnum):
    GENERAL = 0
    SPECIAL = 1
    CAMERA = 2
    FLYCONTROLLER = 3
    ZENMUSE = 4
    CENTER_BOARD = 5
    RADIO = 6
    WIFI = 7
    DM368 = 8
    OFDM = 9
    VO = 10
    SIM = 11
    ESC = 12
    BATTERY = 13
    DATA_RECORDER = 14
    RTK = 15
    AUTOTEST = 16
    UNKNOWN17 = 17
    UNKNOWN18 = 18
    UNKNOWN19 = 19
    UNKNOWN20 = 20
    UNKNOWN21 = 21
    UNKNOWN22 = 22
    UNKNOWN23 = 23
    UNKNOWN24 = 24
    UNKNOWN25 = 25
    UNKNOWN26 = 26
    UNKNOWN27 = 27
    UNKNOWN28 = 28
    UNKNOWN29 = 29
    UNKNOWN30 = 30
    UNKNOWN31 = 31


class PacketProperties:
    def __init__(self):
        self.sender_type = COMM_DEV_TYPE.ANY
        self.sender_index = 0
        self.receiver_type = COMM_DEV_TYPE.ANY
        self.receiver_index = 0
        self.seq_num = 0
        self.pack_type = PACKET_TYPE.REQUEST
        self.ack_type = ACK_TYPE.NO_ACK_NEEDED
        self.encrypt_type = ENCRYPT_TYPE.NO_ENC
        self.cmd_set = CMD_SET_TYPE.GENERAL
        self.cmd_id = 0
        self.payload = bytes()


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
    d = OrderedDict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    return d

  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=0, width=160)

  def __get_whole_length(self):
        return self.ver_length_tag & 1023

  def __set_whole_length(self, value):
        self.ver_length_tag = (self.ver_length_tag & 64512) | (value & 1023)

  whole_length = property(__get_whole_length, __set_whole_length)

  def __get_version(self):
        return (self.ver_length_tag & 64512) >> 10

  def __set_version(self, value):
        self.ver_length_tag = (self.ver_length_tag & 1023) | ((value & 63)  << 10)

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
        self.cmd_type_data = (self.cmd_type_data & 127) | ((value & 1) << 7)

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


class DJIPayload_Base(LittleEndianStructure):
  _pack_ = 1

  def dict_export(self):
    d = OrderedDict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    return d

  def __repr__(self):
    d = self.dict_export()
    if d.keys():
        report = []
        for k, v in d.items():
            if isinstance(v, Array) and v._type_ == c_ubyte:
                report.append(k.rjust(16) + ': ' + repr(bytes(v)))
            else:
                report.append(k.rjust(16) + ': ' + repr(v))
    return "\n".join(report)


class DJIPayload_General_VersionInquiryRe(DJIPayload_Base):
  _fields_ = [('unknown0', c_ubyte),
              ('unknown1', c_ubyte),
              ('hw_version', c_char * 16),
              ('ldr_version', c_uint),
              ('app_version', c_uint),
              ('unknown1A', c_uint),
              ('unknown1E', c_ubyte),
             ]


class DJIPayload_General_ChipRebootRe(DJIPayload_Base):
  _fields_ = [('status', c_ubyte),
             ]

class DJIPayload_General_EncryptCmd(DecoratedEnum):
    GetChipState = 1
    GetModuleState = 2
    Config = 3
    DoEncrypt = 4

class DJIPayload_General_EncryptOperType(DecoratedEnum):
    WriteTarget = 0
    WriteSH204 = 1
    WriteAll = 2

class DJIPayload_General_EncryptGetStateRq(DJIPayload_Base):
  # Matches both GetChipState and GetModuleState
  _fields_ = [('command', c_ubyte),
             ]

class DJIPayload_General_EncryptConfigRq(DJIPayload_Base):
  # Matches only Config command
  _fields_ = [('command', c_ubyte),
              ('oper_type', c_ubyte),
              ('config_magic', c_ubyte * 8),
              ('mod_type', c_ubyte),
              ('board_sn', c_ubyte * 10),
              ('key', c_ubyte * 32),
              ('secure_num', c_ubyte * 16),
             ]

class DJIPayload_General_EncryptConfig3Rq(DJIPayload_Base):
  # Matches only Config command
  _fields_ = [('command', c_ubyte),
              ('oper_type', c_ubyte),
              ('config_magic', c_ubyte * 8),
              ('m01_mod_type', c_ubyte),
              ('m01_board_sn', c_ubyte * 10),
              ('m01_key', c_ubyte * 32),
              ('m01_secure_num', c_ubyte * 16),
              ('m04_mod_type', c_ubyte),
              ('m04_board_sn', c_ubyte * 10),
              ('m04_key', c_ubyte * 32),
              ('m04_secure_num', c_ubyte * 16),
              ('m08_mod_type', c_ubyte),
              ('m08_board_sn', c_ubyte * 10),
              ('m08_key', c_ubyte * 32),
              ('m08_secure_num', c_ubyte * 16),
             ]

class DJIPayload_General_EncryptDoEncryptRq(DJIPayload_Base):
  # Matches only DoEncrypt command
  _fields_ = [('command', c_ubyte),
              ('mod_type', c_ubyte),
              ('data', c_ubyte * 32),
             ]

class DJIPayload_General_EncryptGetChipStateRe(DJIPayload_Base):
  _fields_ = [('status', c_ubyte),
              ('state_flags', c_ubyte),
              ('m01_boardsn', c_ubyte * 10),
              ('m04_boardsn', c_ubyte * 10),
              ('m08_boardsn', c_ubyte * 10),
             ]

class DJIPayload_General_EncryptGetModuleStateRe(DJIPayload_Base):
  _fields_ = [('status', c_ubyte),
              ('state_flags', c_ubyte),
             ]

class DJIPayload_General_EncryptConfigRe(DJIPayload_Base):
  _fields_ = [('status', c_ubyte),
             ]


class DJIPayload_FlyController_AssistantUnlockRq(DJIPayload_Base):
  _fields_ = [('lock_state', c_uint),
             ]

class DJIPayload_FlyController_AssistantUnlockRe(DJIPayload_Base):
  _fields_ = [('status', c_ubyte),
             ]


class DJIPayload_FlyController_GetParamInfoByIndex2015Rq(DJIPayload_Base):
  _fields_ = [('param_index', c_ushort),
             ]

class DJIPayload_FlyController_GetParamInfoByHash2015Rq(DJIPayload_Base):
  _fields_ = [('param_hash', c_uint),
             ]

# We cannot define property name with variable size, so let's make const size one
DJIPayload_FlyController_ParamMaxLen = 160

class DJIPayload_FlyController_ParamType(DecoratedEnum):
    ubyte = 0x0
    ushort = 0x1
    ulong = 0x2
    ulonglong = 0x3
    byte = 0x4
    short = 0x5
    long = 0x6
    longlong = 0x7
    float = 0x8
    double = 0x9
    array = 0xa
    bool = 0xb

class DJIPayload_FlyController_GetParamInfoEOL2015Re(DJIPayload_Base):
  _fields_ = [('status', c_ubyte),
             ]

class DJIPayload_FlyController_GetParamInfoU2015Re(DJIPayload_Base):
  _fields_ = [('status', c_ubyte),
              ('type_id', c_ushort),
              ('size', c_ushort),
              ('attribute', c_ushort),
              ('limit_min', c_uint),
              ('limit_max', c_uint),
              ('limit_def', c_uint),
              ('name', c_char * DJIPayload_FlyController_ParamMaxLen),
             ]

class DJIPayload_FlyController_GetParamInfoI2015Re(DJIPayload_Base):
  _fields_ = [('status', c_ubyte),
              ('type_id', c_ushort),
              ('size', c_ushort),
              ('attribute', c_ushort),
              ('limit_min', c_int),
              ('limit_max', c_int),
              ('limit_def', c_int),
              ('name', c_char * DJIPayload_FlyController_ParamMaxLen),
             ]

class DJIPayload_FlyController_GetParamInfoF2015Re(DJIPayload_Base):
  _fields_ = [('status', c_ubyte),
              ('type_id', c_ushort),
              ('size', c_ushort),
              ('attribute', c_ushort),
              ('limit_min', c_float),
              ('limit_max', c_float),
              ('limit_def', c_float),
              ('name', c_char * DJIPayload_FlyController_ParamMaxLen),
             ]


class DJIPayload_FlyController_ReadParamValByHash2015Rq(DJIPayload_Base):
  _fields_ = [('param_hash', c_uint),
             ]

class DJIPayload_FlyController_ReadParamValByHash2015Re(DJIPayload_Base):
  _fields_ = [('status', c_ubyte),
              ('param_hash', c_uint),
              ('param_value', c_ubyte * DJIPayload_FlyController_ParamMaxLen),
             ]


class DJIPayload_FlyController_ReadParamValByIndex2017Rq(DJIPayload_Base):
  _fields_ = [('table_no', c_ushort),
              ('unknown1', c_ushort),
              ('param_index', c_ushort),
             ]

class DJIPayload_FlyController_ReadParamValByIndex2017Re(DJIPayload_Base):
  _fields_ = [('status', c_ushort),
              ('unknown1', c_ushort),
              ('param_index', c_ushort),
              ('param_value', c_ubyte * DJIPayload_FlyController_ParamMaxLen),
             ]


class DJIPayload_FlyController_WriteParamVal1ByIndex2017Rq(DJIPayload_Base):
  _fields_ = [('table_no', c_ushort),
              ('unknown1', c_ushort),
              ('param_index', c_ushort),
              ('param_value', c_ubyte),
             ]

class DJIPayload_FlyController_WriteParamVal2ByIndex2017Rq(DJIPayload_Base):
  _fields_ = [('table_no', c_ushort),
              ('unknown1', c_ushort),
              ('param_index', c_ushort),
              ('param_value', c_ubyte * 2),
             ]

class DJIPayload_FlyController_WriteParamVal4ByIndex2017Rq(DJIPayload_Base):
  _fields_ = [('table_no', c_ushort),
              ('unknown1', c_ushort),
              ('param_index', c_ushort),
              ('param_value', c_ubyte * 4),
             ]

class DJIPayload_FlyController_WriteParamVal8ByIndex2017Rq(DJIPayload_Base):
  _fields_ = [('table_no', c_ushort),
              ('unknown1', c_ushort),
              ('param_index', c_ushort),
              ('param_value', c_ubyte * 8),
             ]

class DJIPayload_FlyController_WriteParamVal16ByIndex2017Rq(DJIPayload_Base):
  _fields_ = [('table_no', c_ushort),
              ('unknown1', c_ushort),
              ('param_index', c_ushort),
              ('param_value', c_ubyte * 16),
             ]

class DJIPayload_FlyController_WriteParamValAnyByIndex2017Rq(DJIPayload_Base):
  _fields_ = [('table_no', c_ushort),
              ('unknown1', c_ushort),
              ('param_index', c_ushort),
              ('param_value', c_ubyte * DJIPayload_FlyController_ParamMaxLen),
             ]

class DJIPayload_FlyController_WriteParamValByIndex2017Re(DJIPayload_Base):
  _fields_ = [('status', c_ushort),
              ('table_no', c_ushort),
              ('param_index', c_ushort),
              ('param_value', c_ubyte * DJIPayload_FlyController_ParamMaxLen),
             ]


class DJIPayload_FlyController_WriteParamVal1ByHash2015Rq(DJIPayload_Base):
  _fields_ = [('param_hash', c_uint),
              ('param_value', c_ubyte * 1),
             ]

class DJIPayload_FlyController_WriteParamVal2ByHash2015Rq(DJIPayload_Base):
  _fields_ = [('param_hash', c_uint),
              ('param_value', c_ubyte * 2),
             ]

class DJIPayload_FlyController_WriteParamVal4ByHash2015Rq(DJIPayload_Base):
  _fields_ = [('param_hash', c_uint),
              ('param_value', c_ubyte * 4),
             ]

class DJIPayload_FlyController_WriteParamVal8ByHash2015Rq(DJIPayload_Base):
  _fields_ = [('param_hash', c_uint),
              ('param_value', c_ubyte * 8),
             ]

class DJIPayload_FlyController_WriteParamVal16ByHash2015Rq(DJIPayload_Base):
  _fields_ = [('param_hash', c_uint),
              ('param_value', c_ubyte * 16),
             ]

class DJIPayload_FlyController_WriteParamValAnyByHash2015Rq(DJIPayload_Base):
  _fields_ = [('param_hash', c_uint),
              ('param_value', c_ubyte * DJIPayload_FlyController_ParamMaxLen),
             ]

class DJIPayload_FlyController_WriteParamValByHash2015Re(DJIPayload_Base):
  _fields_ = [('status', c_ubyte),
              ('param_hash', c_uint),
              ('param_value', c_ubyte * DJIPayload_FlyController_ParamMaxLen),
             ]


class DJIPayload_FlyController_GetTblAttribute2017Rq(DJIPayload_Base):
  _fields_ = [('table_no', c_ushort),
             ]

class DJIPayload_FlyController_GetTblAttribute2017Re(DJIPayload_Base):
  _fields_ = [('status', c_ushort),
              ('table_no', c_ushort),
              ('entries_crc', c_uint),
              ('entries_num', c_uint),
             ]

class DJIPayload_FlyController_GetTblAttributeEOL2017Re(DJIPayload_Base):
  _fields_ = [('status', c_ushort),
             ]


class DJIPayload_FlyController_GetParamInfoByIndex2017Rq(DJIPayload_Base):
  _fields_ = [('table_no', c_ushort),
              ('param_index', c_ushort),
             ]

class DJIPayload_FlyController_GetParamInfoEOL2017Re(DJIPayload_Base):
  _fields_ = [('status', c_ushort),
             ]

class DJIPayload_FlyController_GetParamInfoU2017Re(DJIPayload_Base):
  _fields_ = [('status', c_ushort),
              ('table_no', c_ushort),
              ('param_index', c_ushort),
              ('type_id', c_ushort),
              ('size', c_ushort),
              ('limit_def', c_uint),
              ('limit_min', c_uint),
              ('limit_max', c_uint),
              ('name', c_char * DJIPayload_FlyController_ParamMaxLen),
             ]

class DJIPayload_FlyController_GetParamInfoI2017Re(DJIPayload_Base):
  _fields_ = [('status', c_ushort),
              ('table_no', c_ushort),
              ('param_index', c_ushort),
              ('type_id', c_ushort),
              ('size', c_ushort),
              ('limit_def', c_int),
              ('limit_min', c_int),
              ('limit_max', c_int),
              ('name', c_char * DJIPayload_FlyController_ParamMaxLen),
             ]

class DJIPayload_FlyController_GetParamInfoF2017Re(DJIPayload_Base):
  _fields_ = [('status', c_ushort),
              ('table_no', c_ushort),
              ('param_index', c_ushort),
              ('type_id', c_ushort),
              ('size', c_ushort),
              ('limit_def', c_float),
              ('limit_min', c_float),
              ('limit_max', c_float),
              ('name', c_char * DJIPayload_FlyController_ParamMaxLen),
             ]


class DJIPayload_Gimbal_CalibCmd(DecoratedEnum):
    JointCoarse = 1
    LinearHall = 2

class DJIPayload_Gimbal_CalibRq(DJIPayload_Base):
  _fields_ = [('command', c_ubyte),
             ]

class DJIPayload_Gimbal_CalibRe(DJIPayload_Base):
  _fields_ = [('status1', c_ubyte),
              ('status2', c_ubyte),
             ]


class DJIPayload_HDLink_WriteHardwareRegisterRq(DJIPayload_Base):
  _fields_ = [('reg_address', c_ushort),
              ('reg_value', c_ubyte),
             ]

class DJIPayload_HDLink_WriteHardwareRegisterRe(DJIPayload_Base):
  _fields_ = [('status', c_ubyte),
             ]


def flyc_parameter_compute_hash(po, parname):
  """ Computes hash from given flyc parameter name. Parameters are recognized by the FC by the hash.
  """
  parhash = 0
  parbt = parname.encode('gbk') # seriously, they should already know the world uses UTF now
  for i in range(0, len(parname)):
      ncode = parbt[i]
      tmpval = (parhash & 0xffffffff) << 8
      parhash = (tmpval + ncode) % 0xfffffffb
  return parhash

def flyc_parameter_is_signed(type_id):
  """ Returns whether flight param of given type is signed - should use "I" versions of packets.
  """
  return (type_id >= DJIPayload_FlyController_ParamType.byte.value) and (type_id <= DJIPayload_FlyController_ParamType.longlong.value)

def flyc_parameter_is_float(type_id):
  """ Returns whether flight param of given type is float - should use "F" versions of packets.
  """
  return (type_id == DJIPayload_FlyController_ParamType.float.value) or (type_id == DJIPayload_FlyController_ParamType.double.value)

def encode_command_packet(sender_type, sender_index, receiver_type, receiver_index, seq_num, pack_type, ack_type, encrypt_type, cmd_set, cmd_id, payload):
    """ Encodes command packet with given header fields and payload into c_ubyte array.

      Accepts integer values of all the fields.
    """
    pkthead = DJICmdV1Header()
    pkthead.whole_length = sizeof(pkthead) + len(payload) + 2
    pkthead.header_crc8 = calc_pkt55_hdr_checksum(0x77, (c_ubyte * 3).from_buffer_copy(pkthead), 3)
    pkthead.sender_type = sender_type
    pkthead.sender_index = sender_index
    pkthead.receiver_type = receiver_type
    pkthead.receiver_index = receiver_index
    pkthead.seq_num = seq_num
    pkthead.packet_type = pack_type
    pkthead.ack_type = ack_type
    pkthead.encrypt_type = encrypt_type
    pkthead.cmd_set = cmd_set
    pkthead.cmd_id = cmd_id
    enc_data = (c_ubyte * pkthead.whole_length)()
    memmove(addressof(enc_data), byref(pkthead), sizeof(pkthead))
    pktpayload = (c_ubyte * len(payload)).from_buffer_copy(payload)
    memmove(addressof(enc_data) + sizeof(pkthead), byref(pktpayload), sizeof(pktpayload))
    pktfoot = DJICmdV1Footer()
    pktfoot.crc16 = calc_pkt55_checksum(enc_data, sizeof(enc_data) - 2)
    memmove(addressof(enc_data) + sizeof(pkthead) + sizeof(pktpayload), byref(pktfoot), sizeof(pktfoot))
    return enc_data

def encode_command_packet_en(sender_type, sender_index, receiver_type, receiver_index, seq_num, pack_type, ack_type, encrypt_type, cmd_set, cmd_id, payload):
    """ Encodes command packet with given header fields and payload into c_ubyte array.

      A wrapper which accepts enums instead of integer fields for most values.
    """
    return encode_command_packet(sender_type.value, sender_index, receiver_type.value, receiver_index,
      seq_num, pack_type.value, ack_type.value, encrypt_type.value, cmd_set.value, cmd_id, payload)

def get_known_payload(pkthead, payload):
    if pkthead.cmd_set == CMD_SET_TYPE.GENERAL.value and pkthead.packet_type == 0:
        if (pkthead.cmd_id == 0x30):
            if len(payload) >= sizeof(DJIPayload_General_EncryptConfig3Rq):
                return DJIPayload_General_EncryptConfig3Rq.from_buffer_copy(payload)
            if len(payload) >= sizeof(DJIPayload_General_EncryptConfigRq):
                return DJIPayload_General_EncryptConfigRq.from_buffer_copy(payload)
            if len(payload) >= sizeof(DJIPayload_General_EncryptGetStateRq):
                return DJIPayload_General_EncryptGetStateRq.from_buffer_copy(payload)

    if pkthead.cmd_set == CMD_SET_TYPE.GENERAL.value and pkthead.packet_type == 1:
        if (pkthead.cmd_id == 0x01):
            if len(payload) >= sizeof(DJIPayload_General_VersionInquiryRe):
                return DJIPayload_General_VersionInquiryRe.from_buffer_copy(payload)
        if (pkthead.cmd_id == 0x0b):
            if len(payload) >= sizeof(DJIPayload_General_ChipRebootRe):
                return DJIPayload_General_ChipRebootRe.from_buffer_copy(payload)
        if (pkthead.cmd_id == 0x30):
            if len(payload) >= sizeof(DJIPayload_General_EncryptGetChipStateRe):
                return DJIPayload_General_EncryptGetChipStateRe.from_buffer_copy(payload)
            if len(payload) >= sizeof(DJIPayload_General_EncryptGetModuleStateRe):
                return DJIPayload_General_EncryptGetModuleStateRe.from_buffer_copy(payload)
            if len(payload) >= sizeof(DJIPayload_General_EncryptConfigRe):
                return DJIPayload_General_EncryptConfigRe.from_buffer_copy(payload)

    if pkthead.cmd_set == CMD_SET_TYPE.FLYCONTROLLER.value and pkthead.packet_type == 0:
        if (pkthead.cmd_id == 0xdf):
            if len(payload) >= sizeof(DJIPayload_FlyController_AssistantUnlockRq):
                return DJIPayload_FlyController_AssistantUnlockRq.from_buffer_copy(payload)
        if (pkthead.cmd_id == 0xe0):
            if len(payload) >= sizeof(DJIPayload_FlyController_GetTblAttribute2017Rq):
                return DJIPayload_FlyController_GetTblAttribute2017Rq.from_buffer_copy(payload)
        if (pkthead.cmd_id == 0xe1):
            if len(payload) >= sizeof(DJIPayload_FlyController_GetParamInfoByIndex2017Rq):
                return DJIPayload_FlyController_GetParamInfoByIndex2017Rq.from_buffer_copy(payload)
        if (pkthead.cmd_id == 0xe2):
            if len(payload) >= sizeof(DJIPayload_FlyController_ReadParamValByIndex2017Rq):
                return DJIPayload_FlyController_ReadParamValByIndex2017Rq.from_buffer_copy(payload)
        if (pkthead.cmd_id == 0xe3):
            if len(payload) > sizeof(DJIPayload_FlyController_WriteParamVal16ByIndex2017Rq):
                return DJIPayload_FlyController_WriteParamValAnyByIndex2017Rq.from_buffer_copy(payload.ljust(sizeof(DJIPayload_FlyController_WriteParamValAnyByIndex2017Rq), b'\0'))
            if len(payload) > sizeof(DJIPayload_FlyController_WriteParamVal8ByIndex2017Rq):
                return DJIPayload_FlyController_WriteParamVal16ByIndex2017Rq.from_buffer_copy(payload)
            if len(payload) > sizeof(DJIPayload_FlyController_WriteParamVal4ByIndex2017Rq):
                return DJIPayload_FlyController_WriteParamVal8ByIndex2017Rq.from_buffer_copy(payload)
            if len(payload) > sizeof(DJIPayload_FlyController_WriteParamVal2ByIndex2017Rq):
                return DJIPayload_FlyController_WriteParamVal4ByIndex2017Rq.from_buffer_copy(payload)
            if len(payload) > sizeof(DJIPayload_FlyController_WriteParamVal1ByIndex2017Rq):
                return DJIPayload_FlyController_WriteParamVal2ByIndex2017Rq.from_buffer_copy(payload)
            if len(payload) >= sizeof(DJIPayload_FlyController_WriteParamVal1ByIndex2017Rq):
                return DJIPayload_FlyController_WriteParamVal1ByIndex2017Rq.from_buffer_copy(payload)
        if (pkthead.cmd_id == 0xf0):
            if len(payload) >= sizeof(DJIPayload_FlyController_GetParamInfoByIndex2015Rq):
                return DJIPayload_FlyController_GetParamInfoByIndex2015Rq.from_buffer_copy(payload)
        if (pkthead.cmd_id == 0xf8):
            if len(payload) >= sizeof(DJIPayload_FlyController_ReadParamValByHash2015Rq):
                return DJIPayload_FlyController_ReadParamValByHash2015Rq.from_buffer_copy(payload)
        if (pkthead.cmd_id == 0xf9):
            if len(payload) > sizeof(DJIPayload_FlyController_WriteParamVal16ByHash2015Rq):
                return DJIPayload_FlyController_WriteParamValAnyByHash2015Rq.from_buffer_copy(payload.ljust(sizeof(DJIPayload_FlyController_WriteParamValAnyByHash2015Rq), b'\0'))
            if len(payload) > sizeof(DJIPayload_FlyController_WriteParamVal8ByHash2015Rq):
                return DJIPayload_FlyController_WriteParamVal16ByHash2015Rq.from_buffer_copy(payload)
            if len(payload) > sizeof(DJIPayload_FlyController_WriteParamVal4ByHash2015Rq):
                return DJIPayload_FlyController_WriteParamVal8ByHash2015Rq.from_buffer_copy(payload)
            if len(payload) > sizeof(DJIPayload_FlyController_WriteParamVal2ByHash2015Rq):
                return DJIPayload_FlyController_WriteParamVal4ByHash2015Rq.from_buffer_copy(payload)
            if len(payload) > sizeof(DJIPayload_FlyController_WriteParamVal1ByHash2015Rq):
                return DJIPayload_FlyController_WriteParamVal2ByHash2015Rq.from_buffer_copy(payload)
            if len(payload) >= sizeof(DJIPayload_FlyController_WriteParamVal1ByHash2015Rq):
                return DJIPayload_FlyController_WriteParamVal1ByHash2015Rq.from_buffer_copy(payload)

    if pkthead.cmd_set == CMD_SET_TYPE.FLYCONTROLLER.value and pkthead.packet_type == 1:
        if (pkthead.cmd_id == 0xdf):
            if len(payload) >= sizeof(DJIPayload_FlyController_AssistantUnlockRe):
                return DJIPayload_FlyController_AssistantUnlockRe.from_buffer_copy(payload)
        if (pkthead.cmd_id == 0xe0):
            if len(payload) >= sizeof(DJIPayload_FlyController_GetTblAttribute2017Re):
                return DJIPayload_FlyController_GetTblAttribute2017Re.from_buffer_copy(payload)
            if len(payload) >= sizeof(DJIPayload_FlyController_GetTblAttributeEOL2017Re):
                return DJIPayload_FlyController_GetTblAttributeEOL2017Re.from_buffer_copy(payload)
        if (pkthead.cmd_id == 0xe1):
            if len(payload) >= sizeof(DJIPayload_FlyController_GetParamInfoU2017Re)-DJIPayload_FlyController_ParamMaxLen+1:
                out_payload = DJIPayload_FlyController_GetParamInfoU2017Re.from_buffer_copy(payload.ljust(sizeof(DJIPayload_FlyController_GetParamInfoU2017Re), b'\0'))
                if flyc_parameter_is_signed(out_payload.type_id):
                    return DJIPayload_FlyController_GetParamInfoI2017Re.from_buffer_copy(payload.ljust(sizeof(DJIPayload_FlyController_GetParamInfoI2017Re), b'\0'))
                elif flyc_parameter_is_float(out_payload.type_id):
                    return DJIPayload_FlyController_GetParamInfoF2017Re.from_buffer_copy(payload.ljust(sizeof(DJIPayload_FlyController_GetParamInfoF2017Re), b'\0'))
                else:
                    return out_payload
            elif len(payload) >= sizeof(DJIPayload_FlyController_GetParamInfoEOL2017Re):
                return DJIPayload_FlyController_GetParamInfoEOL2017Re.from_buffer_copy(payload)
        if (pkthead.cmd_id == 0xe2):
            if len(payload) >= sizeof(DJIPayload_FlyController_ReadParamValByIndex2017Re)-DJIPayload_FlyController_ParamMaxLen+1:
                return DJIPayload_FlyController_ReadParamValByIndex2017Re.from_buffer_copy(payload.ljust(sizeof(DJIPayload_FlyController_ReadParamValByIndex2017Re), b'\0'))
        if (pkthead.cmd_id == 0xe3):
            if len(payload) >= sizeof(DJIPayload_FlyController_WriteParamValByIndex2017Re)-DJIPayload_FlyController_ParamMaxLen+1:
                return DJIPayload_FlyController_WriteParamValByIndex2017Re.from_buffer_copy(payload.ljust(sizeof(DJIPayload_FlyController_WriteParamValByIndex2017Re), b'\0'))
        if (pkthead.cmd_id == 0xf0) or (pkthead.cmd_id == 0xf7):
            if len(payload) >= sizeof(DJIPayload_FlyController_GetParamInfoU2015Re)-DJIPayload_FlyController_ParamMaxLen+1:
                out_payload = DJIPayload_FlyController_GetParamInfoU2015Re.from_buffer_copy(payload.ljust(sizeof(DJIPayload_FlyController_GetParamInfoU2015Re), b'\0'))
                if flyc_parameter_is_signed(out_payload.type_id):
                    return DJIPayload_FlyController_GetParamInfoI2015Re.from_buffer_copy(payload.ljust(sizeof(DJIPayload_FlyController_GetParamInfoI2015Re), b'\0'))
                elif flyc_parameter_is_float(out_payload.type_id):
                    return DJIPayload_FlyController_GetParamInfoF2015Re.from_buffer_copy(payload.ljust(sizeof(DJIPayload_FlyController_GetParamInfoF2015Re), b'\0'))
                else:
                    return out_payload
            elif len(payload) >= sizeof(DJIPayload_FlyController_GetParamInfoEOL2015Re):
                return DJIPayload_FlyController_GetParamInfoEOL2015Re.from_buffer_copy(payload)
        if (pkthead.cmd_id == 0xf8):
            if len(payload) >= sizeof(DJIPayload_FlyController_ReadParamValByHash2015Re)-DJIPayload_FlyController_ParamMaxLen+1:
                return DJIPayload_FlyController_ReadParamValByHash2015Re.from_buffer_copy(payload.ljust(sizeof(DJIPayload_FlyController_ReadParamValByHash2015Re), b'\0'))
        if (pkthead.cmd_id == 0xf9):
            if len(payload) >= sizeof(DJIPayload_FlyController_WriteParamValByHash2015Re)-DJIPayload_FlyController_ParamMaxLen+1:
                return DJIPayload_FlyController_WriteParamValByHash2015Re.from_buffer_copy(payload.ljust(sizeof(DJIPayload_FlyController_WriteParamValByHash2015Re), b'\0'))

    if pkthead.cmd_set == CMD_SET_TYPE.ZENMUSE.value and pkthead.packet_type == 0:
        if (pkthead.cmd_id == 0x08):
            # Response for this packet often lacks type flag
            if len(payload) >= sizeof(DJIPayload_Gimbal_CalibRe):
                return DJIPayload_Gimbal_CalibRe.from_buffer_copy(payload)
            elif len(payload) >= sizeof(DJIPayload_Gimbal_CalibRq):
                return DJIPayload_Gimbal_CalibRq.from_buffer_copy(payload)

    if pkthead.cmd_set == CMD_SET_TYPE.ZENMUSE.value and pkthead.packet_type == 1:
        if (pkthead.cmd_id == 0x08):
            if len(payload) >= sizeof(DJIPayload_Gimbal_CalibRe):
                return DJIPayload_Gimbal_CalibRe.from_buffer_copy(payload)

    if pkthead.cmd_set == CMD_SET_TYPE.OFDM.value and pkthead.packet_type == 0:
        if (pkthead.cmd_id == 0x06):
            if len(payload) >= sizeof(DJIPayload_HDLink_WriteHardwareRegisterRq):
                return DJIPayload_HDLink_WriteHardwareRegisterRq.from_buffer_copy(payload)

    if pkthead.cmd_set == CMD_SET_TYPE.OFDM.value and pkthead.packet_type == 1:
        if (pkthead.cmd_id == 0x06):
            if len(payload) >= sizeof(DJIPayload_HDLink_WriteHardwareRegisterRe):
                return DJIPayload_HDLink_WriteHardwareRegisterRe.from_buffer_copy(payload)

    return None

def do_build_packet(options):
    pkt = encode_command_packet_en(options.sender_type, options.sender_index, options.receiver_type, options.receiver_index,
      options.seq_num, options.pack_type, options.ack_type, options.encrypt_type, options.cmd_set, options.cmd_id, options.payload)
    print(' '.join('{:02x}'.format(x) for x in pkt))

def parse_module_ident(s):
    """ Parses module identification string in known formats.
    """
    pat = re.compile(r"^m?([0-9]{1,2})([0-9]{2})$")
    out = re.match(pat, s)
    if out is None:
        raise argparse.ArgumentTypeError("No 4-byte module ident")
    return out

def parse_module_type(s):
    """ Parses module type string in known formats.
    """
    pat = re.compile(r"^[0-9]{1,2}$")
    try:
        if re.search(pat, s):
            return COMM_DEV_TYPE(int(s, 10))
    except:
        raise argparse.ArgumentTypeError("Numeric value out of range")
    try:
        return COMM_DEV_TYPE.from_name(s.upper())
    except:
        raise argparse.ArgumentTypeError("Unrecognized name of enum item")

def parse_ack_type(s):
    """ Parses ack type string in known formats.
    """
    pat = re.compile(r"^[0-9]{1}$")
    try:
        if re.search(pat, s):
            return ACK_TYPE(int(s, 10))
    except:
        raise argparse.ArgumentTypeError("Numeric value out of range")
    try:
        return ACK_TYPE.from_name(s.upper())
    except:
        raise argparse.ArgumentTypeError("Unrecognized name of enum item")

def parse_encrypt_type(s):
    """ Parses encrypt type string in known formats.
    """
    pat = re.compile(r"^[0-9]{1}$")
    try:
        if re.search(pat, s):
            return ENCRYPT_TYPE(int(s, 10))
    except:
        raise argparse.ArgumentTypeError("Numeric value out of range")
    try:
        return ENCRYPT_TYPE.from_name(s.upper())
    except:
        raise argparse.ArgumentTypeError("Unrecognized name of enum item")

def parse_packet_type(s):
    """ Parses packet type string in known formats.
    """
    pat = re.compile(r"^[0-9]{1}$")
    try:
        if re.search(pat, s):
            return PACKET_TYPE(int(s, 10))
    except:
        raise argparse.ArgumentTypeError("Numeric value out of range")
    try:
        return PACKET_TYPE.from_name(s.upper())
    except:
        raise argparse.ArgumentTypeError("Unrecognized name of enum item")

def parse_cmd_set(s):
    """ Parses command set string in known formats.
    """
    pat = re.compile(r"^[0-9]{1}$")
    try:
        if re.search(pat, s):
            return CMD_SET_TYPE(int(s, 10))
    except:
        raise argparse.ArgumentTypeError("Numeric value out of range")
    try:
        return CMD_SET_TYPE.from_name(s.upper())
    except:
        raise argparse.ArgumentTypeError("Unrecognized name of enum item")

def main():
    """ Main executable function.

      Its task is to parse command line options and call a function which performs a task.
    """
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument('-n', '--seq_num', default=0, type=int,
            help='Sequence number of the packet (default is %(default)s)')

    parser.add_argument('-u', '--pack_type', default="Request", type=parse_packet_type,
            help='Packet Type, either name or number (default is %(default)s)')

    parser.add_argument('-a', '--ack_type', default="No_ACK_Needed", type=parse_ack_type,
            help='Acknowledgement type, either name or number (default is %(default)s)')

    parser.add_argument('-e', '--encrypt_type', default="NO_ENC", type=parse_encrypt_type,
            help='Encryption type, either name or number (default is %(default)s)')

    parser.add_argument('-s', '--cmd_set', default="GENERAL", type=parse_cmd_set,
            help='Command Set, either name or number (default is %(default)s)')

    parser.add_argument('-i', '--cmd_id', default=0, type=int,
            help='Command ID (default is %(default)s)')

    parser.add_argument('-v', '--verbose', action='count', default=0,
            help='Increases verbosity level; max level is set by -vvv')

    parser.add_argument("--version", action='version', version="%(prog)s {version} by {author}"
              .format(version=__version__,author=__author__),
            help="Display version information and exit")

    subparser = parser.add_mutually_exclusive_group()

    subparser.add_argument('-t', '--sender', type=parse_module_ident,
            help='Sender Type and Index, in TTII form')

    subparser.add_argument('-tt', '--sender_type', default="PC", type=parse_module_type,
            help='Sender(transmitter) Type, either name or number (default is %(default)s)')

    parser.add_argument('-ti', '--sender_index', default=0, type=int,
            help='Sender(transmitter) Index (default is %(default)s)')

    subparser = parser.add_mutually_exclusive_group()

    subparser.add_argument('-r', '--receiver', type=parse_module_ident,
            help='Receiver Type and Index, in TTII form (ie. 0300)')

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
    try:
        main()
    except Exception as ex:
        eprint("Error: "+str(ex))
        #raise
        sys.exit(10)
