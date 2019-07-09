#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" DJI 'xV4' Firmware Container tool.

Extract and creates the firmware package files.
"""

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

from __future__ import print_function
__version__ = "0.3.2"
__author__ = "Mefistotelis @ Original Gangsters"
__license__ = "GPL"

import sys
import re
import os
import hashlib
import binascii
import argparse
import configparser
import itertools
from ctypes import *
from time import gmtime, strftime, strptime
from calendar import timegm
from Crypto.Cipher import AES

def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

class DjiModuleTarget():
    "Stores identification info on module for specific target"
    def __init__(self, kind, model, name, desc):
        self.kind = kind
        self.model = model
        self.name = name
        self.desc = desc

dji_targets = [
    DjiModuleTarget( 1,-1, "CAM",     "camera"),
    DjiModuleTarget( 1, 0, "FC300X",  "camera 'Ambarella A9SE' App"), # P3X
    DjiModuleTarget( 1, 1, "CAMLDR",  "camera 'Ambarella A9SE' Ldr"), # P3X
    DjiModuleTarget( 1, 2, "CAMBST",  "camera BST"),
    DjiModuleTarget( 1, 4, "CAMBCPU", "camera BCPU"),
    DjiModuleTarget( 1, 5, "CAMLCPU", "camera LCPU"),
    DjiModuleTarget( 1, 6, "ZQ7020",  "camera 'Xilinx Zynq 7020'"),
    DjiModuleTarget( 2,-1, "MBAPP",   "mobile app"),
    DjiModuleTarget( 3,-1, "MC",      "main controller"),
    DjiModuleTarget( 3, 5, "MCLDR",   "main controller 'A3' ldr"), # P3X
    DjiModuleTarget( 3, 6, "MCAPP",   "main controller 'A3' app"), # P3X
    DjiModuleTarget( 4,-1, "GIMBAL",  "gimbal"),
    DjiModuleTarget( 4, 0, "GIMBAL0", "gimbal mdl 0"), # P3X
    DjiModuleTarget( 5,-1, "CENTER",  "central board"),
    DjiModuleTarget( 5, 0, "CENTER0", "central board mdl 0"),
    DjiModuleTarget( 6,-1, "RMRAD",   "remote radio"),
    DjiModuleTarget( 7,-1, "WIFI",    "Wi-Fi"),
    DjiModuleTarget( 7, 0, "WIFI0",   "Wi-Fi mdl 0"),
    DjiModuleTarget( 8,-1, "VENC",    "video encoder in air"),
    DjiModuleTarget( 8, 0, "DM368",   "video encoder 'DaVinci Dm368 Linux'"), # P3X
    DjiModuleTarget( 8, 1, "IG810LB2","video encoder 'IG810 LB2_ENC'"),
    DjiModuleTarget( 9,-1, "LBMCA",   "lightbridge MCU in air"),
    DjiModuleTarget( 9, 0, "MCA1765", "lightbridge MCU 'STM32F103'"), # P3X, OSMO_X5R
    DjiModuleTarget(10,-1, "BATTFW",  "battery firmware"),
    DjiModuleTarget(11,-1, "BATTMGR", "battery controller"),
    DjiModuleTarget(11, 0, "BATTERY", "battery controller 1 app"), # P3X
    DjiModuleTarget(11, 1, "BATTERY2","battery controller 2 app"),
    DjiModuleTarget(12,-1, "ESC",     "electronic speed control"),
    DjiModuleTarget(12, 0, "ESC0",    "electronic speed control 0"), # P3X
    DjiModuleTarget(12, 1, "ESC1",    "electronic speed control 1"), # P3X
    DjiModuleTarget(12, 2, "ESC2",    "electronic speed control 2"), # P3X
    DjiModuleTarget(12, 3, "ESC3",    "electronic speed control 3"), # P3X
    DjiModuleTarget(13, 0, "VDEC",    "video decoder"),
    DjiModuleTarget(13, 0, "DM365M0", "video decoder 'DaVinci Dm365 Linux'"),
    DjiModuleTarget(13, 1, "DM365M1", "video decoder 'DaVinci Dm385 Linux'"),
    DjiModuleTarget(14,-1, "LBMCG",   "lightbridge MCU on ground"),
    DjiModuleTarget(14, 0, "MCG1765A","lightbridge MCU 'LPC1765 GROUND LB2'"),
    DjiModuleTarget(15,-1, "TXUSBC",  "transmitter usb controller"),
    DjiModuleTarget(15, 0, "TX68013", "transmitter usb 'IG810 LB2_68013_TX'"), # P3X
    DjiModuleTarget(16,-1, "RXUSBCG", "receiver usb controller"),
    DjiModuleTarget(16, 0, "RX68013", "receiver usb 'IG810 LB2_68013_RX ground'"), # GL300a
    DjiModuleTarget(16, 1, "RXCY2014","receiver usb 'IG810 LB2_CY2014_RX ground'"), # GL300b+
    DjiModuleTarget(17,-1, "MVOM",    "visual positioning"),
    DjiModuleTarget(17, 0, "MVOMC4",  "visual positioning module 'camera'"), # P3X
    DjiModuleTarget(17, 1, "MVOMS0",  "visual positioning module 'sonar'"), # P3X
    DjiModuleTarget(19,-1, "FPGAA",   "lightbridge FPGA on air"),
    DjiModuleTarget(19, 0, "FPGAA0",  "lightbridge FPGA on air model 0"), # P3X
    DjiModuleTarget(20,-1, "FPGAG",   "lightbridge FPGA on ground"),
    DjiModuleTarget(20, 3, "FPGAG3",  "lightbridge FPGA on ground 'LB2'"),
    DjiModuleTarget(25,-1, "IMU",     "inertial measurement unit"),
    DjiModuleTarget(25, 0, "IMUA3M0", "inertial measurement unit pt0"),
    DjiModuleTarget(25, 1, "IMUA3M1", "inertial measurement unit pt1"),
    DjiModuleTarget(26,-1, "RTK",     "real time kinematic"),
    DjiModuleTarget(26, 6, "RTKAPP",  "real time kinematic App"),
    DjiModuleTarget(26, 7, "RTKLDR",  "real time kinematic Ldr"),
    DjiModuleTarget(27,-1, "WIFIGND", "Wi-Fi ground"),
    DjiModuleTarget(29,-1, "PMU",     "power management unit"),
    DjiModuleTarget(29, 0, "PMUA3LDR","power management unit App"),
    DjiModuleTarget(29, 1, "PMUA3APP","power management unit Ldr"),
    DjiModuleTarget(30,-1, "TESTA",   "test A"),
    DjiModuleTarget(31,-1, "TESTB",   "test B")
]

encrypt_aes128_key = bytes([0x96, 0x70, 0x9a, 0xD3, 0x26, 0x67, 0x4A, 0xC3, 0x82, 0xB6, 0x69, 0x27, 0xE6, 0xd8, 0x84, 0x21])
encrypt_aes128_iv = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])


class FwPkgHeader(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('magic', c_uint),
              ('magic_ver', c_ushort),
              ('hdrend_offs', c_ushort),
              ('timestamp', c_uint),
              ('manufacturer', c_char * 16),
              ('model', c_char * 16),
              ('entry_count', c_ushort),
              ('ver_latest_enc', c_int),
              ('ver_rollbk_enc', c_int),
              ('padding', c_ubyte * 10)]

  def set_ver_latest(self, ver):
    self.ver_latest_enc = 0x5127A564 ^ ver ^ self.timestamp;

  def set_ver_rollbk(self, ver):
    self.ver_rollbk_enc = 0x5127A564 ^ ver ^ self.timestamp;

  def get_format_version(self):
    if self.magic == 0x12345678 and self.magic_ver == 0x0001:
        if (self.ver_latest_enc == 0 and self.ver_rollbk_enc == 0):
            return 2015
        else:
            return 2016
    elif self.magic == 0x12345678 and self.magic_ver == 0x1130:
        return 2017
    else:
        return 0

  def set_format_version(self, ver):
    if ver == 2015:
        self.magic = 0x12345678
        self.magic_ver = 0x0001
        self.ver_latest_enc = 0
        self.ver_rollbk_enc = 0
    elif ver == 2016:
        self.magic = 0x12345678
        self.magic_ver = 0x0001
        self.set_ver_latest(0)
        self.set_ver_rollbk(0)
    elif ver == 2017:
        self.magic = 0x12345678
        self.magic_ver = 0x1130
        self.set_ver_latest(0)
        self.set_ver_rollbk(0)
    else:
        raise ValueError("Unsupported package format version.")

  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    varkey = 'ver_latest'
    d[varkey] = d['timestamp'] ^ d[varkey+"_enc"]  ^ 0x5127A564;
    varkey = 'ver_rollbk'
    d[varkey] = d['timestamp'] ^ d[varkey+"_enc"]  ^ 0x5127A564;
    varkey = 'padding'
    d[varkey] = "".join("{:02X}".format(x) for x in d[varkey])
    return d

  def ini_export(self, fp):
    d = self.dict_export()
    fp.write("# DJI Firmware Container main header file.\n")
    fp.write(strftime("# Generated on %Y-%m-%d %H:%M:%S\n", gmtime()))
    varkey = 'pkg_format'
    fp.write("{:s}={:d}\n".format(varkey,self.get_format_version()))
    varkey = 'manufacturer'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey].decode("utf-8")))
    varkey = 'model'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey].decode("utf-8")))
    varkey = 'timestamp'
    fp.write("{:s}={:s}\n".format(varkey,strftime("%Y-%m-%d %H:%M:%S",gmtime(d[varkey]))))
    varkey = 'ver_latest'
    fp.write("{:s}={:02d}.{:02d}.{:04d}\n".format(varkey, (d[varkey]>>24)&255, (d[varkey]>>16)&255, (d[varkey])&65535))
    varkey = 'ver_rollbk'
    fp.write("{:s}={:02d}.{:02d}.{:04d}\n".format(varkey, (d[varkey]>>24)&255, (d[varkey]>>16)&255, (d[varkey])&65535))
    #varkey = 'padding'
    #fp.write("{:s}={:s}\n".format(varkey,d[varkey]))

  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)

class FwPkgEntry(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('target', c_ubyte),
              ('spcoding', c_ubyte),
              ('reserved2', c_ushort),
              ('version', c_uint),
              ('dt_offs', c_uint),
              ('stored_len', c_uint),
              ('decrypted_len', c_uint),
              ('stored_md5', c_ubyte * 16),
              ('decrypted_md5', c_ubyte * 16)]
  preencrypted = 0

  def get_encrypt_type(self):
      return (self.spcoding >> 4) & 0x0F

  def set_encrypt_type(self, enctype):
      self.spcoding  = (self.spcoding & 0x0F) | ((enctype & 0x0F) << 4)

  def get_splvalue(self):
      return (self.spcoding) & 0x0F

  def set_splvalue(self, splval):
      self.spcoding  = (self.spcoding & 0xF0) | (splval & 0x0F)

  def target_name(self):
    tg_kind = getattr(self, 'target') & 31
    tg_model = (getattr(self, 'target') >> 5) & 7
    module_info = next((mi for mi in dji_targets if mi.kind == tg_kind and mi.model == tg_model), None)
    if (module_info is not None):
        return module_info.desc
    # If not found, try getting category
    module_info = next((mi for mi in dji_targets if mi.kind == tg_kind and mi.model == -1), None)
    if (module_info is not None):
        return "{:s} model {:02d}".format(module_info.desc,tg_model)
    # If category also not found, return as unknown device
    return "device kind {:02} model {:02}".format(tg_kind,tg_model)

  def hex_stored_md5(self):
    varkey = 'stored_md5'
    return "".join("{:02x}".format(x) for x in getattr(self, varkey))

  def hex_decrypted_md5(self):
    varkey = 'decrypted_md5'
    return "".join("{:02x}".format(x) for x in getattr(self, varkey))

  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    varkey = 'version'
    d[varkey] = "{:02d}.{:02d}.{:04d}".format((d[varkey]>>24)&255, (d[varkey]>>16)&255, (d[varkey])&65535)
    varkey = 'stored_md5'
    d[varkey] = "".join("{:02x}".format(x) for x in d[varkey])
    varkey = 'decrypted_md5'
    d[varkey] = "".join("{:02x}".format(x) for x in d[varkey])
    varkey = 'target'
    d[varkey] = "m{:02d}{:02d}".format(d[varkey]&31, (d[varkey]>>5)&7)
    varkey = 'encrypt_type'
    d[varkey] = self.get_encrypt_type()
    varkey = 'splvalue'
    d[varkey] = self.get_splvalue()
    varkey = 'target_name'
    d[varkey] = self.target_name()
    return d

  def ini_export(self, fp):
    d = self.dict_export()
    fp.write("# DJI Firmware Container module header file.\n")
    fp.write("# Stores firmware for {:s}\n".format(d['target_name']))
    fp.write(strftime("# Generated on %Y-%m-%d %H:%M:%S\n", gmtime()))
    varkey = 'target'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
    varkey = 'version'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
    varkey = 'encrypt_type'
    fp.write("{:s}={:d}\n".format(varkey,d[varkey]))
    if (d[varkey] != 0):
        # If we do not support encryption of given type, we may extract the file in encrypted form
        varkey = 'preencrypted'
        fp.write("{:s}={:d}\n".format(varkey,self.preencrypted))
    if (self.preencrypted):
        # We cannot compute decrypted MD5 for pre-encrypted files, so store them in INI file
        varkey = 'decrypted_md5'
        fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
    varkey = 'splvalue'
    fp.write("{:s}={:d}\n".format(varkey,d[varkey]))
    varkey = 'reserved2'
    fp.write("{:s}={:04X}\n".format(varkey,d[varkey]))

  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)


crc16_tab = [
  0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF, 0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
  0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E, 0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876,
  0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD, 0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5,
  0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C, 0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD, 0xC974,
  0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB, 0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3,
  0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A, 0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72,
  0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9, 0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3, 0x8A78, 0x9BF1,
  0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738, 0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70,
  0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7, 0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
  0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036, 0x18C1, 0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E,
  0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5, 0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD,
  0xB58B, 0xA402, 0x9699, 0x8710, 0xF3AF, 0xE226, 0xD0BD, 0xC134, 0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C,
  0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3, 0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB,
  0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232, 0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A,
  0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1, 0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
  0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330, 0x7BC7, 0x6A4E, 0x58D5, 0x495C, 0x3DE3, 0x2C6A, 0x1EF1, 0x0F78
]

def dji_calculate_crc16_part(buf, pcrc):
  """A non-standard crc16 hashing algorithm, looks like 32-bit one from Ambarella simply cut down in bits."""
  crc = pcrc
  for octet in buf:
      crc = crc16_tab[(crc ^ octet) & 0xff] ^ (crc >> 8)
  return crc & 0xffff

def dji_decrypt_block(cipher_buf, enc_key, enc_iv):
  """ Decrypts a buffer with AES in a DJI way. """
  block_sz = 256
  plain_buf = b""
  for cbpos in range(0, len(cipher_buf), block_sz):
      # Reinit the crypto for each block, this is how Dji does it
      crypto = AES.new(enc_key, AES.MODE_CBC, enc_iv)
      plain_buf += crypto.decrypt(cipher_buf[cbpos:cbpos+block_sz])
  return plain_buf, enc_iv

def dji_encrypt_block(cipher_buf, enc_key, enc_iv):
  """ Encrypts a buffer with AES in a DJI way. """
  block_sz = 256
  plain_buf = b""
  for cbpos in range(0, len(cipher_buf), block_sz):
      # Reinit the crypto for each block, this is how Dji does it
      crypto = AES.new(enc_key, AES.MODE_CBC, enc_iv)
      plain_buf += crypto.encrypt(cipher_buf[cbpos:cbpos+block_sz])
  return plain_buf, enc_iv

def dji_write_fwpkg_head(po, pkghead, minames):
  fname = "{:s}_head.ini".format(po.mdprefix)
  fwheadfile = open(fname, "w")
  pkghead.ini_export(fwheadfile)
  fwheadfile.write("{:s}={:s}\n".format("modules",' '.join(minames)))
  fwheadfile.close()

def dji_read_fwpkg_head(po):
  pkghead = FwPkgHeader()
  fname = "{:s}_head.ini".format(po.mdprefix)
  parser = configparser.ConfigParser()
  with open(fname, "r") as lines:
    lines = itertools.chain(("[asection]",), lines)  # This line adds section header to ini
    parser.read_file(lines)
  # Set magic fields properly
  pkgformat = parser.get("asection", "pkg_format").encode("utf-8")
  pkghead.set_format_version(int(pkgformat))
  # Set the rest of the fields
  pkghead.manufacturer = parser.get("asection", "manufacturer").encode("utf-8")
  pkghead.model = parser.get("asection", "model").encode("utf-8")
  pkghead.timestamp = timegm(strptime(parser.get("asection", "timestamp"),"%Y-%m-%d %H:%M:%S"))
  ver_latest_s = parser.get("asection", "ver_latest")
  ver_latest_m = re.search('(?P<major>[0-9]+)[.](?P<minor>[0-9]+)[.](?P<svn>[0-9A-Fa-f]+)', ver_latest_s)
  pkghead.set_ver_latest( ((int(ver_latest_m.group("major"),10)&0xff)<<24) + ((int(ver_latest_m.group("minor"),10)&0xff)<<16) + (int(ver_latest_m.group("svn"),10)&0xffff) )
  ver_rollbk_s = parser.get("asection", "ver_rollbk")
  ver_rollbk_m = re.search('(?P<major>[0-9]+)[.](?P<minor>[0-9]+)[.](?P<svn>[0-9A-Fa-f]+)', ver_rollbk_s)
  pkghead.set_ver_rollbk( ((int(ver_rollbk_m.group("major"),10)&0xff)<<24) + ((int(ver_rollbk_m.group("minor"),10)&0xff)<<16) + (int(ver_rollbk_m.group("svn"),10)&0xffff) )
  minames_s = parser.get("asection", "modules")
  minames = minames_s.split(' ')
  pkghead.entry_count = len(minames)
  pkghead.hdrend_offs = sizeof(pkghead) + sizeof(FwPkgEntry)*pkghead.entry_count + sizeof(c_ushort)
  del parser
  return (pkghead, minames)

def dji_write_fwentry_head(po, i, e, miname):
  fname = "{:s}_{:s}.ini".format(po.mdprefix,miname)
  fwheadfile = open(fname, "w")
  e.ini_export(fwheadfile)
  fwheadfile.close()

def dji_read_fwentry_head(po, i, miname):
  hde = FwPkgEntry()
  fname = "{:s}_{:s}.ini".format(po.mdprefix,miname)
  parser = configparser.ConfigParser()
  with open(fname, "r") as lines:
    lines = itertools.chain(("[asection]",), lines)  # This line adds section header to ini
    parser.read_file(lines)
  target_s = parser.get("asection", "target")
  target_m = re.search('m(?P<kind>[0-9]{2})(?P<model>[0-9]{2})', target_s)
  hde.target = ((int(target_m.group("kind"),10)&0x1f)) + ((int(target_m.group("model"),10)&0x07)<<5)
  version_s = parser.get("asection", "version")
  version_m = re.search('(?P<major>[0-9]+)[.](?P<minor>[0-9]+)[.](?P<svn>[0-9]+)', version_s)
  hde.version = ((int(version_m.group("major"),10)&0xff)<<24) + ((int(version_m.group("minor"),10)%0xff)<<16) + (int(version_m.group("svn"),10)%0xffff)
  if parser.has_option("asection", "preencrypted"):
    hde.preencrypted = int(parser.get("asection", "preencrypted"),10)
  if (hde.preencrypted):
    decrypted_md5_s = parser.get("asection", "decrypted_md5")
    hde.decrypted_md5 = (c_ubyte * 16).from_buffer_copy(binascii.unhexlify(decrypted_md5_s))
  hde.set_encrypt_type( int(parser.get("asection", "encrypt_type"),10) )
  hde.set_splvalue( int(parser.get("asection", "splvalue"),10) )
  hde.reserved2 = int(parser.get("asection", "reserved2"),16)
  del parser
  return (hde)

def dji_extract(po, fwpkgfile):
  pkghead = FwPkgHeader()
  if fwpkgfile.readinto(pkghead) != sizeof(pkghead):
      raise EOFError("Couldn't read firmware package file header.")
  pkgformat = pkghead.get_format_version()
  if pkgformat == 0:
      if (not po.force_continue):
          eprint("{}: Error: Unexpected magic value in main header; input file is not a firmware package.".format(po.fwpkg))
          exit(1)
      eprint("{}: Warning: Unexpected magic value in main header; will try to extract anyway.".format(po.fwpkg))
  if (po.verbose > 1):
      print("{}: Package format version {:d} detected".format(po.fwpkg,pkgformat))
  if (pkghead.ver_latest_enc == 0 and pkghead.ver_rollbk_enc == 0):
      eprint("{}: Warning: Unversioned firmware package identified; this format is not fully supported.".format(po.fwpkg))
      # In this format, versions should be set from file name, and CRC16 of the header should be equal to values hard-coded in updater
  if (po.verbose > 1):
      print("{}: Header:".format(po.fwpkg))
      print(pkghead)
  curhead_checksum = dji_calculate_crc16_part((c_ubyte * sizeof(pkghead)).from_buffer_copy(pkghead), 0x3692)

  pkgmodules = []
  for i in range(pkghead.entry_count):
      hde = FwPkgEntry()
      if fwpkgfile.readinto(hde) != sizeof(hde):
          raise EOFError("Couldn't read firmware package file entry.")
      if (po.verbose > 1):
          print("{}: Module index {:d}".format(po.fwpkg,i))
          print(hde)
      curhead_checksum = dji_calculate_crc16_part((c_ubyte * sizeof(hde)).from_buffer_copy(hde), curhead_checksum)
      if hde.stored_len != hde.decrypted_len:
          eprint("{}: Warning: decrypted size differs from stored one, {:d} instead of {:d}; this is not supported.".format(po.fwpkg,hde.decrypted_len,hde.stored_len))
      chksum_enctype = hde.get_encrypt_type()
      if (chksum_enctype != 0):
          if (po.no_crypto):
              hde.preencrypted = 1
          elif (chksum_enctype == 1):
              encrypt_key = encrypt_aes128_key
              encrypt_iv  = encrypt_aes128_iv
          else:
              # Since we cannot decode the encryption, mark the entry as pre-encrypted to extract in encrypted form
              eprint("{}: Warning: Unknown encryption {:d} in module {:d}, extracting encrypted.".format(po.fwpkg,chksum_enctype,i))
              hde.preencrypted = 1
      pkgmodules.append(hde)

  pkghead_checksum = c_ushort()
  if fwpkgfile.readinto(pkghead_checksum) != sizeof(pkghead_checksum):
      raise EOFError("Couldn't read firmware package file header checksum.")

  if curhead_checksum != pkghead_checksum.value:
      eprint("{}: Warning: Firmware package file header checksum did not match; should be {:04X}, found {:04X}.".format(po.fwpkg, pkghead_checksum.value, curhead_checksum))
  elif (po.verbose > 1):
      print("{}: Headers checksum {:04X} matches.".format(po.fwpkg,pkghead_checksum.value))

  if fwpkgfile.tell() != pkghead.hdrend_offs:
      eprint("{}: Warning: Header end offset does not match; should end at {}, ends at {}.".format(po.fwpkg,pkghead.hdrend_offs,fwpkgfile.tell()))

  # Prepare array of names; "0" will mean empty index
  minames = ["0"]*len(pkgmodules)
  # Name the modules after target component
  for i, hde in enumerate(pkgmodules):
      if hde.stored_len > 0:
          d = hde.dict_export()
          minames[i] = "{:s}".format(d['target'])
  # Rename targets in case of duplicates
  minames_seen = set()
  for i in range(len(minames)):
      miname = minames[i]
      if miname in minames_seen:
          # Add suffix a..z to multiple uses of the same module
          for miname_suffix in range(97,110):
              if miname+chr(miname_suffix) not in minames_seen:
                  break
          # Show warning the first time duplicate is found
          if (miname_suffix == 97):
              eprint("{}: Warning: Found multiple modules {:s}; invalid firmware.".format(po.fwpkg,miname))
          minames[i] = miname+chr(miname_suffix)
      minames_seen.add(minames[i])
  minames_seen = None

  dji_write_fwpkg_head(po, pkghead, minames)

  for i, hde in enumerate(pkgmodules):
      if minames[i] == "0":
          if (po.verbose > 0):
              print("{}: Skipping module index {}, {} bytes".format(po.fwpkg,i,hde.stored_len))
          continue
      if (po.verbose > 0):
          print("{}: Extracting module index {}, {} bytes".format(po.fwpkg,i,hde.stored_len))
      chksum_enctype = hde.get_encrypt_type()
      stored_chksum = hashlib.md5()
      decrypted_chksum = hashlib.md5()
      dji_write_fwentry_head(po, i, hde, minames[i])
      fwitmfile = open("{:s}_{:s}.bin".format(po.mdprefix,minames[i]), "wb")
      fwpkgfile.seek(hde.dt_offs)
      stored_n = 0
      decrypted_n = 0
      while stored_n < hde.stored_len:
          # read block limit must be a multiplication of encryption block size
          copy_buffer = fwpkgfile.read(min(1024 * 1024, hde.stored_len - stored_n))
          if not copy_buffer:
              break
          stored_n += len(copy_buffer)
          stored_chksum.update(copy_buffer)
          if (chksum_enctype != 0) and (not hde.preencrypted):
              copy_buffer, encrypt_iv = dji_decrypt_block(copy_buffer, encrypt_key, encrypt_iv)
          fwitmfile.write(copy_buffer)
          decrypted_n += len(copy_buffer)
          decrypted_chksum.update(copy_buffer)
      fwitmfile.close()
      if (stored_chksum.hexdigest() != hde.hex_stored_md5()):
          eprint("{}: Warning: Module index {:d} stored checksum mismatch; got {:s}, expected {:s}.".format(po.fwpkg,i,stored_chksum.hexdigest(),hde.hex_stored_md5()))
      if (not hde.preencrypted) and (decrypted_chksum.hexdigest() != hde.hex_decrypted_md5()):
          eprint("{}: Warning: Module index {:d} decrypted checksum mismatch; got {:s}, expected {:s}.".format(po.fwpkg,i,decrypted_chksum.hexdigest(),hde.hex_decrypted_md5()))
          eprint("{}: Module index {:d} may be damaged due to bad decryption; use no-crypto option to leave it as-is.".format(po.fwpkg,i))
      if (not hde.preencrypted) and (decrypted_n != hde.decrypted_len):
          eprint("{}: Warning: decrypted size mismatch, {:d} instead of {:d}.".format(po.fwpkg,decrypted_n,hde.decrypted_len))
      if (po.verbose > 1):
          print("{}: Module index {:d} stored checksum {:s}".format(po.fwpkg,i,stored_chksum.hexdigest()))


def dji_create(po, fwpkgfile):
  # Read headers from INI files
  (pkghead, minames) = dji_read_fwpkg_head(po)
  pkgmodules = []
  # Create module entry for each partition
  for i, miname in enumerate(minames):
      if miname == "0":
          hde = FwPkgEntry()
      else:
          hde = dji_read_fwentry_head(po, i, miname)
      pkgmodules.append(hde)
  # Write the unfinished headers
  fwpkgfile.write((c_ubyte * sizeof(pkghead)).from_buffer_copy(pkghead))
  for hde in pkgmodules:
      fwpkgfile.write((c_ubyte * sizeof(hde)).from_buffer_copy(hde))
  fwpkgfile.write((c_ubyte * sizeof(c_ushort))())
  # Write module data
  for i, miname in enumerate(minames):
      hde = pkgmodules[i]
      if miname == "0":
          if (po.verbose > 0):
              print("{}: Empty module index {:d}".format(po.fwpkg,i))
          continue
      if (po.verbose > 0):
          print("{}: Copying module index {:d}".format(po.fwpkg,i))
      fname = "{:s}_{:s}.bin".format(po.mdprefix,miname)
      # Skip unused pkgmodules
      if (os.stat(fname).st_size < 1):
          eprint("{}: Warning: module index {:d} empty".format(po.fwpkg,i))
          continue
      chksum_enctype = hde.get_encrypt_type()
      epos = fwpkgfile.tell()
      # Check for data encryption
      if (chksum_enctype != 0) and (not hde.preencrypted):
          if (po.no_crypto):
              if (not po.force_continue):
                  eprint("{}: Error: Module {:d} needs encryption {:d}, but crypto is disabled.".format(po.fwpkg,chksum_enctype,i))
                  exit(1)
              eprint("{}: Warning: Module {:d} needs encryption {:d}, but crypto is disabled; switching to unencrypted.".format(po.fwpkg,chksum_enctype,i))
              hde.set_encrypt_type(0)
              chksum_enctype = hde.get_encrypt_type()
          elif (chksum_enctype == 1):
              encrypt_key = encrypt_aes128_key
              encrypt_iv  = encrypt_aes128_iv
          else:
              if (not po.force_continue):
                  eprint("{}: Error: Unknown encryption {:d} in module {:d}; cannot encrypt.".format(po.fwpkg,chksum_enctype,i))
                  exit(1)
              eprint("{}: Warning: Unknown encryption {:d} in module {:d}; switching to unencrypted.".format(po.fwpkg,chksum_enctype,i))
              hde.set_encrypt_type(0)
              chksum_enctype = hde.get_encrypt_type()
      # Copy partition data and compute checksum
      fwitmfile = open(fname, "rb")
      stored_chksum = hashlib.md5()
      decrypted_chksum = hashlib.md5()
      decrypted_n = 0
      while True:
          # read block limit must be a multiplication of encryption block size
          copy_buffer = fwitmfile.read(1024 * 1024)
          if not copy_buffer:
              break
          decrypted_chksum.update(copy_buffer)
          decrypted_n += len(copy_buffer)
          if (chksum_enctype != 0) and (not hde.preencrypted):
              copy_buffer, encrypt_iv = dji_encrypt_block(copy_buffer, encrypt_key, encrypt_iv)
          stored_chksum.update(copy_buffer)
          fwpkgfile.write(copy_buffer)
      fwitmfile.close()
      hde.dt_offs = epos
      hde.stored_len = fwpkgfile.tell() - epos
      # We do not support pre-encryption which changes length of data
      # If we need it at some point, the only way is to store decrypted_len in INI file
      hde.decrypted_len = decrypted_n
      hde.stored_md5 = (c_ubyte * 16).from_buffer_copy(stored_chksum.digest())
      if (hde.preencrypted):
          # If the file is pre-encrypted, then it has to have encryption type and MD5 set from INI file
          if (chksum_enctype == 0):
              eprint("{}: Warning: Module {:d} marked as pre-encrypted, but with no encryption type.".format(po.fwpkg,i))
          if all([ v == 0 for v in hde.decrypted_md5 ]):
              eprint("{}: Warning: Module {:d} marked as pre-encrypted, but decrypted MD5 is zeros.".format(po.fwpkg,i))
          else:
              print("{}: Module {:d} marked as pre-encrypted; decrypted MD5 accepted w/o verification.".format(po.fwpkg,i))
      else:
          # If the file is not pre-encrypted, then we should just use the MD5 we've computed
          hde.decrypted_md5 = (c_ubyte * 16).from_buffer_copy(decrypted_chksum.digest())
      pkgmodules[i] = hde
  # Write all headers again
  fwpkgfile.seek(0,os.SEEK_SET)
  fwpkgfile.write((c_ubyte * sizeof(pkghead)).from_buffer_copy(pkghead))
  curhead_checksum = dji_calculate_crc16_part((c_ubyte * sizeof(pkghead)).from_buffer_copy(pkghead), 0x3692)
  for hde in pkgmodules:
      fwpkgfile.write((c_ubyte * sizeof(hde)).from_buffer_copy(hde))
      curhead_checksum = dji_calculate_crc16_part((c_ubyte * sizeof(hde)).from_buffer_copy(hde), curhead_checksum)
  pkghead_checksum = c_ushort(curhead_checksum)
  fwpkgfile.write((c_ubyte * sizeof(c_ushort)).from_buffer_copy(pkghead_checksum))

def main():
  """ Main executable function.

  Its task is to parse command line options and call a function which performs requested command.
  """
  # Parse command line options

  parser = argparse.ArgumentParser(description=__doc__)

  parser.add_argument("-p", "--fwpkg", default="", type=str, required=True,
          help="name of the firmware package file")

  parser.add_argument("-m", "--mdprefix", default="", type=str,
          help="file name prefix for the single decomposed firmware modules " \
           "(defaults to base name of firmware package file)")

  parser.add_argument("-f", "--force-continue", action="store_true",
          help="force continuing execution despite warning signs of issues")

  parser.add_argument("-c", "--no-crypto", action="store_true",
          help="disable cryptography - do not encrypt/decrypt modules")

  parser.add_argument("-v", "--verbose", action="count", default=0,
          help="increases verbosity level; max level is set by -vvv")

  subparser = parser.add_mutually_exclusive_group()

  subparser.add_argument("-x", "--extract", action="store_true",
          help="extract firmware package into modules")

  subparser.add_argument("-a", "--add", action="store_true",
          help="add module files to firmware package")

  subparser.add_argument("--version", action='version', version="%(prog)s {version} by {author}"
            .format(version=__version__,author=__author__),
          help="display version information and exit")

  po = parser.parse_args();

  if len(po.fwpkg) > 0 and len(po.mdprefix) == 0:
      po.mdprefix = os.path.splitext(os.path.basename(po.fwpkg))[0]

  if po.extract:

      if (po.verbose > 0):
        print("{}: Opening for extraction".format(po.fwpkg))
      fwpkgfile = open(po.fwpkg, "rb")

      dji_extract(po,fwpkgfile)

      fwpkgfile.close()

  elif po.add:

      if (po.verbose > 0):
        print("{}: Opening for creation".format(po.fwpkg))
      fwpkgfile = open(po.fwpkg, "wb")

      dji_create(po,fwpkgfile)

      fwpkgfile.close()

  else:

      raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        eprint("Error: "+str(ex))
        #raise
        sys.exit(10)
