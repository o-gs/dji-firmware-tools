#!/usr/bin/env python3

from __future__ import print_function
import sys
import getopt
import re
import os
import hashlib
import binascii
import configparser
import itertools
from ctypes import *
from time import gmtime, strftime, strptime
from calendar import timegm

def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

class ProgOptions:
  fwpkgfile = ''
  dcprefix = ''
  verbose = 0
  force_continue = 0
  command = ''

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
    DjiModuleTarget( 3,-1, "MC",      "main controller"),
    DjiModuleTarget( 3, 5, "MCLDR",   "main controller 'A3' ldr"), # P3X
    DjiModuleTarget( 3, 6, "MCAPP",   "main controller 'A3' app"), # P3X
    DjiModuleTarget( 4,-1, "GIMBAL",  "gimbal"),
    DjiModuleTarget( 4, 0, "GIMBAL0", "gimbal mdl 0"), # P3X
    DjiModuleTarget( 5,-1, "CENTER",  "central board"),
    DjiModuleTarget( 5, 0, "CENTER0", "central board mdl 0"),
    DjiModuleTarget( 7,-1, "WIFI",    "Wi-Fi"),
    DjiModuleTarget( 7, 0, "WIFI0",   "Wi-Fi mdl 0"),
    DjiModuleTarget( 8,-1, "VENC",    "video encoder"),
    DjiModuleTarget( 8, 0, "DM368",   "video encoder 'DaVinci Dm368 Linux'"), # P3X
    DjiModuleTarget( 8, 1, "IG810LB2","video encoder 'IG810 LB2_ENC'"),
    DjiModuleTarget( 9,-1, "MCA",     "MCU in air"),
    DjiModuleTarget( 9, 0, "MCA1765", "MCU 'NXP LPC1765'"), # P3X, OSMO_X5R
    DjiModuleTarget(10,-1, "BATTFW",  "battery firmware"),
    DjiModuleTarget(11,-1, "BATTCT",  "battery controller"),
    DjiModuleTarget(11, 0, "BATTERY", "battery controller 1 app"), # P3X
    DjiModuleTarget(11, 1, "BATTERY2","battery controller 2 app"),
    DjiModuleTarget(12,-1, "ESC",     "electronic speed control"),
    DjiModuleTarget(12, 0, "ESC0",    "electronic speed control 0"), # P3X
    DjiModuleTarget(12, 1, "ESC1",    "electronic speed control 1"), # P3X
    DjiModuleTarget(12, 2, "ESC2",    "electronic speed control 2"), # P3X
    DjiModuleTarget(12, 3, "ESC3",    "electronic speed control 3"), # P3X
    DjiModuleTarget(13, 0, "VDEC",    "video decoder"),
    DjiModuleTarget(13, 0, "DM365M0", "video decoder 'DaVinci Dm365 Linux' mdl 0"),
    DjiModuleTarget(13, 1, "DM365M1", "video decoder 'DaVinci Dm365 Linux' mdl 1"),
    DjiModuleTarget(14,-1, "MCG",     "MCU on ground"),
    DjiModuleTarget(14, 0, "MCG1765A","MCU 'LPC1765 GROUND LB2'"),
    DjiModuleTarget(15,-1, "TX",      "radio transmitter"),
    DjiModuleTarget(15, 0, "TX68013", "radio transmitter 'IG810 LB2_68013_TX'"), # P3X
    DjiModuleTarget(16,-1, "RXG",     "radio receiver"),
    DjiModuleTarget(16, 0, "RX68013", "radio receiver 'IG810 LB2_68013_RX ground'"),
    DjiModuleTarget(17,-1, "MVOM",    "visual positioning"),
    DjiModuleTarget(17, 0, "MVOMC4",  "visual positioning module 'camera'"), # P3X
    DjiModuleTarget(17, 1, "MVOMS0",  "visual positioning module 'sonar'"), # P3X
    DjiModuleTarget(19,-1, "FPGAA",   "FPGA air"),
    DjiModuleTarget(19, 0, "FPGAA0",  "FPGA air model 0"), # P3X
    DjiModuleTarget(20,-1, "FPGAG",   "FPGA ground"),
    DjiModuleTarget(20, 3, "FPGAG3",  "FPGA ground 'LB2'"),
    DjiModuleTarget(25,-1, "IMU",     "inertial measurement unit"),
    DjiModuleTarget(25, 0, "IMUA3M0", "inertial measurement unit 'A3' pt0"),
    DjiModuleTarget(25, 1, "IMUA3M1", "inertial measurement unit 'A3' pt1"),
    DjiModuleTarget(29,-1, "PMU",     "phasor measurement unit"),
    DjiModuleTarget(29, 0, "PMUA3LDR","phasor measurement unit 'A3 App'"),
    DjiModuleTarget(29, 1, "PMUA3APP","phasor measurement unit 'A3 Ldr'"),
    DjiModuleTarget(30,-1, "TESTA",   "test A"),
    DjiModuleTarget(31,-1, "TESTB",   "test B")
]

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
    crc = crc16_tab[(crc ^ octet) & 0xff] ^ (crc >> 8);
  return crc & 0xffff


def dji_write_fwpkg_head(po, pkghead, minames):
  fname = "{:s}_head.ini".format(po.dcprefix)
  fwheadfile = open(fname, "w")
  pkghead.ini_export(fwheadfile)
  fwheadfile.write("{:s}={:s}\n".format("modules",' '.join(minames)))
  fwheadfile.close()

def dji_read_fwpkg_head(po):
  pkghead = FwPkgHeader()
  pkghead.magic = 0x12345678
  pkghead.magic_ver = 0x0001
  fname = "{:s}_head.ini".format(po.dcprefix)
  parser = configparser.ConfigParser()
  with open(fname, "r") as lines:
    lines = itertools.chain(("[asection]",), lines)  # This line adds section header to ini
    parser.read_file(lines)
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
  fname = "{:s}_{:s}.ini".format(po.dcprefix,miname)
  fwheadfile = open(fname, "w")
  e.ini_export(fwheadfile)
  fwheadfile.close()

def dji_read_fwentry_head(po, i, miname):
  hde = FwPkgEntry()
  fname = "{:s}_{:s}.ini".format(po.dcprefix,miname)
  parser = configparser.ConfigParser()
  with open(fname, "r") as lines:
    lines = itertools.chain(("[asection]",), lines)  # This line adds section header to ini
    parser.read_file(lines)
  target_s = parser.get("asection", "target")
  target_m = re.search('m(?P<kind>[0-9]{2})(?P<model>[0-9]{2})', target_s)
  hde.target = ((int(target_m.group("kind"),10)&0x1f)) + ((int(target_m.group("model"),10)%0x07)<<5)
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
  if pkghead.magic != 0x12345678 or pkghead.magic_ver != 0x0001:
      if (po.force_continue):
          eprint("{}: Warning: Unexpected magic value in main header; will try to extract anyway.".format(po.fwpkgfile))
      else:
          eprint("{}: Error: Unexpected magic value in main header; input file is not a firmware package.".format(po.fwpkgfile))
          exit(1)
  if (pkghead.ver_latest_enc == 0 and pkghead.ver_rollbk_enc == 0):
      eprint("{}: Warning: Unversioned firmware package identified; this format is not fully supported.".format(po.fwpkgfile))
      # In this format, versions should be set from file name, and CRC16 of the header should be equal to values hard-coded in updater
  if (po.verbose > 1):
      print("{}: Header:".format(po.fwpkgfile))
      print(pkghead)
  curhead_checksum = dji_calculate_crc16_part((c_ubyte * sizeof(pkghead)).from_buffer_copy(pkghead), 0x3692)

  pkgmodules = []
  for i in range(pkghead.entry_count):
      hde = FwPkgEntry()
      if fwpkgfile.readinto(hde) != sizeof(hde):
          raise EOFError("Couldn't read firmware package file entry.")
      if (po.verbose > 1):
          print("{}: Module index {:d}".format(po.fwpkgfile,i))
          print(hde)
      curhead_checksum = dji_calculate_crc16_part((c_ubyte * sizeof(hde)).from_buffer_copy(hde), curhead_checksum)
      if hde.stored_len != hde.decrypted_len:
          eprint("{}: Warning: decrypted size differs from stored one, {:d} instead of {:d}; this is not supported.".format(po.fwpkgfile,hde.decrypted_len,hde.stored_len))
      chksum_enctype = hde.get_encrypt_type()
      if (chksum_enctype != 0):
          #TODO Find out what the encryption algorithm is, then write a decoder
          # Since we cannot decode the encryption, mark the entry as pre-encrypted to extract in encrypted form
          hde.preencrypted = 1
      pkgmodules.append(hde)

  pkghead_checksum = c_ushort()
  if fwpkgfile.readinto(pkghead_checksum) != sizeof(pkghead_checksum):
      raise EOFError("Couldn't read firmware package file header checksum.")

  if curhead_checksum != pkghead_checksum.value:
      eprint("{}: Warning: Firmware package file header checksum did not match; should be {:04X}, found {:04X}.".format(po.fwpkgfile, pkghead_checksum.value, curhead_checksum))
  elif (po.verbose > 1):
      print("{}: Headers checksum {:04X} matches.".format(po.fwpkgfile,pkghead_checksum.value))

  if fwpkgfile.tell() != pkghead.hdrend_offs:
      eprint("{}: Warning: Header end offset does not match; should end at {}, ends at {}.".format(po.fwpkgfile,pkghead.hdrend_offs,fwpkgfile.tell()))

  minames = ["0"]*len(pkgmodules)
  for i, hde in enumerate(pkgmodules):
      if hde.stored_len > 0:
          minames[i] = "mi{:02d}".format(i)

  dji_write_fwpkg_head(po, pkghead, minames)

  for i, hde in enumerate(pkgmodules):
      if minames[i] == "0":
          if (po.verbose > 0):
              print("{}: Skipping module index {}, {} bytes".format(po.fwpkgfile,i,hde.stored_len))
          continue
      if (po.verbose > 0):
          print("{}: Extracting module index {}, {} bytes".format(po.fwpkgfile,i,hde.stored_len))
      chksum_enctype = hde.get_encrypt_type()
      stored_chksum = hashlib.md5()
      decrypted_chksum = hashlib.md5()
      dji_write_fwentry_head(po, i, hde, minames[i])
      fwitmfile = open("{:s}_{:s}.bin".format(po.dcprefix,minames[i]), "wb")
      fwpkgfile.seek(hde.dt_offs)
      stored_n = 0
      decrypted_n = 0
      while stored_n < hde.stored_len:
          copy_buffer = fwpkgfile.read(min(1024 * 1024, hde.stored_len - stored_n))
          if not copy_buffer:
              break
          stored_n += len(copy_buffer)
          stored_chksum.update(copy_buffer);
          #TODO Find out what the encryption algorithm is, then write a decoder
          #if (chksum_enctype != 0) and (not hde.preencrypted):
          #    copy_buffer = some_decrypt_func(copy_buffer)
          fwitmfile.write(copy_buffer)
          decrypted_n += len(copy_buffer)
          decrypted_chksum.update(copy_buffer);
      fwitmfile.close()
      if (stored_chksum.hexdigest() != hde.hex_stored_md5()):
          eprint("{}: Warning: Module index {:d} stored checksum mismatch; got {:s}, expected {:s}.".format(po.fwpkgfile,i,stored_chksum.hexdigest(),hde.hex_stored_md5()))
      if (not hde.preencrypted) and (decrypted_chksum.hexdigest() != hde.hex_decrypted_md5()):
          eprint("{}: Warning: Module index {:d} decrypted checksum mismatch; got {:s}, expected {:s}.".format(po.fwpkgfile,i,decrypted_chksum.hexdigest(),hde.hex_decrypted_md5()))
      if (not hde.preencrypted) and (decrypted_n != hde.decrypted_len):
          eprint("{}: Warning: decrypted size mismatch, {:d} instead of {:d}.".format(po.fwpkgfile,decrypted_n,hde.decrypted_len))
      if (po.verbose > 1):
          print("{}: Module index {:d} stored checksum {:s}".format(po.fwpkgfile,i,stored_chksum.hexdigest()))


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
              print("{}: Empty module index {:d}".format(po.fwpkgfile,i))
          continue
      if (po.verbose > 0):
          print("{}: Copying module index {:d}".format(po.fwpkgfile,i))
      fname = "{:s}_{:s}.bin".format(po.dcprefix,miname)
      # Skip unused pkgmodules
      if (os.stat(fname).st_size < 1):
          eprint("{}: Warning: module index {:d} empty".format(po.fwpkgfile,i))
          continue
      chksum_enctype = hde.get_encrypt_type();
      epos = fwpkgfile.tell()
      # Check for data encryption
      if (chksum_enctype != 0) and (not hde.preencrypted):
          if (chksum_enctype == 1):
              #TODO Find out what the encryption algorithm is, then write an encoder
              eprint("{}: Warning: NOT IMPLEMENTED encryption {:d} in module {:d}; decrypted checksum bad.".format(po.fwpkgfile,chksum_enctype,i))
          else:
              eprint("{}: Warning: Unknown encryption {:d} in module {:d}; decrypted checksum skipped.".format(po.fwpkgfile,chksum_enctype,i))
      # Copy partition data and compute checksum
      fwitmfile = open(fname, "rb")
      stored_chksum = hashlib.md5()
      decrypted_chksum = hashlib.md5()
      decrypted_n = 0
      while True:
          copy_buffer = fwitmfile.read(1024 * 1024)
          if not copy_buffer:
              break
          decrypted_chksum.update(copy_buffer);
          decrypted_n += len(copy_buffer)
          #TODO Find out what the encryption algorithm is, then write an encoder
          #if (chksum_enctype != 0) and (not hde.preencrypted):
          #    copy_buffer = some_encrypt_func(copy_buffer)
          stored_chksum.update(copy_buffer);
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
              eprint("{}: Warning: Module {:d} marked as pre-encrypted, but with no encryption type.".format(po.fwpkgfile,i))
          if all([ v == 0 for v in hde.decrypted_md5 ]):
              eprint("{}: Warning: Module {:d} marked as pre-encrypted, but decrypted MD5 is zeros.".format(po.fwpkgfile,i))
          else:
              print("{}: Module {:d} marked as pre-encrypted; decrypted MD5 accepted w/o verification.".format(po.fwpkgfile,i))
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

def main(argv):
  # Parse command line options
  po = ProgOptions()
  try:
     opts, args = getopt.getopt(argv,"hxavp:m:",["help","version","extract","add","fwpkg=","mdprefix="])
  except getopt.GetoptError:
     print("Unrecognized options; check dji_fwcon.py --help")
     sys.exit(2)
  for opt, arg in opts:
     if opt in ("-h", "--help"):
        print("DJI Firmware Container tool")
        print("dji_fwcon.py <-x|-a> [-v] -p <fwpkgfile> [-d <dcprefix>]")
        print("  -p <fwpkgfile> - name of the firmware package file")
        print("  -m <mdprefix> - file name prefix for the single decomposed firmware modules")
        print("                  defaults to base name of firmware package file")
        print("  -f - force continuing execution despite warning signs of issues")
        print("  -x - extract firmware package into modules")
        print("  -a - add module files to firmware package")
        print("  -v - increases verbosity level; max level is set by -vvv")
        sys.exit()
     elif opt == "--version":
        print("dji_fwcon.py version 0.2.0")
        sys.exit()
     elif opt == '-v':
        po.verbose += 1
     elif opt in ("-p", "--fwpkg"):
        po.fwpkgfile = arg
     elif opt in ("-m", "--mdprefix"):
        po.dcprefix = arg
     elif opt in ("-f", "--force-continue"):
        po.force_continue = 1
     elif opt in ("-x", "--extract"):
        po.command = 'x'
     elif opt in ("-a", "--add"):
        po.command = 'a'
  if len(po.fwpkgfile) > 0 and len(po.dcprefix) == 0:
      po.dcprefix = os.path.splitext(os.path.basename(po.fwpkgfile))[0]

  if (po.command == 'x'):

    if (po.verbose > 0):
      print("{}: Opening for extraction".format(po.fwpkgfile))
    fwpkgfile = open(po.fwpkgfile, "rb")

    dji_extract(po,fwpkgfile)

    fwpkgfile.close();

  elif (po.command == 'a'):

    if (po.verbose > 0):
      print("{}: Opening for creation".format(po.fwpkgfile))
    fwpkgfile = open(po.fwpkgfile, "wb")

    dji_create(po,fwpkgfile)

    fwpkgfile.close();

  else:

    raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
   main(sys.argv[1:])
