#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Ambarella Firmware Packer tool
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
import sys
if sys.version_info < (3, 0):
    # All checksums would have to be computed differently on Python 2.x
    # due to differences in types
    raise NotImplementedError('Python version 3 or newer is required.')
import getopt
import re
import os
import hashlib
import mmap
import zlib
import configparser
import itertools
from ctypes import *
from time import gmtime, strftime

def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

class ProgOptions:
  fwmdlfile = ''
  ptprefix = ''
  verbose = 0
  binhead = False
  binfmt = 'auto'
  command = ''

part_entry_type_id = ["sys", "dsp_fw", "rom_fw", "lnx", "rfs"]
part_entry_type_name = ["System Software", "DSP uCode", "System ROM Data", "Linux Kernel", "Linux Root FS"]

# The Ambarella firmware file consists of 3 elements:
# 1. Main header, containing array of partitions
# 2. Partition header, before each partition
# 3. Partition data, for each partition
#
# The Main header is made of:
# - model_name - text description of the device model
# - ver_info - version info, set to 0 in DJI camera FW
# - crc32 - cummulative checksum of all modules with headers, equal to last
#   module cummulative checksum xor -1
# - fw module entries - array of FwModEntry, with amount of entries hard-coded
#   for specific component; the crc32 here is a cummulative checksum of data
#   with header, and initial value of -1
# - partition sizes - array of int, sizes of the partitions in partition table,
#   with 15 entries (amount of partitions is larger than the amount of modules)
#
# For a specific component, main header of Ambarella firmware has constant
# size. But DJI uses several camera types all developed on Ambarella - amount
# of module entries is different for each of them. To guess the amount of
# modules in a file, we're assuming the partition sizes are multiplication of
# 1024. This way we can detect beginning of the sizes array, as crc value and
# partition length are very unlikely to both divide by 1024.


class FwModA9Header(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('model_name', c_char * 32),
              ('ver_info', c_uint),
              ('crc32', c_uint)]

  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    varkey = 'ver_info'
    d[varkey] = "{:d}.{:d}-{:04X}".format((d[varkey]>>24)&255, (d[varkey]>>16)&255, (d[varkey])&65535)
    varkey = 'crc32'
    d[varkey] = "{:08X}".format(d[varkey])
    return d

  def ini_export(self, fp):
    d = self.dict_export()
    fp.write("# Ambarella Firmware Packer module header file. Loosly based on AFT format.\n")
    fp.write(strftime("# Generated on %Y-%m-%d %H:%M:%S\n", gmtime()))
    varkey = 'model_name'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey].decode("utf-8")))
    varkey = 'ver_info'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
    #varkey = 'crc32'
    #fp.write("{:s}={:s}\n".format(varkey,d[varkey]))

  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)

class FwModEntry(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('dt_len', c_uint),
              ('crc32', c_uint)]

  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    varkey = 'crc32'
    d[varkey] = "{:08X}".format(d[varkey])
    return d

  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)

class FwModA9PostHeader(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('part_size', c_uint * 15)]

  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    varkey = 'part_size'
    d[varkey] = " ".join("{:08x}".format(x) for x in d[varkey])
    return d

  def ini_export(self, fp):
    d = self.dict_export()
    # No header - this is a continuation of FwModA9Header export
    varkey = 'part_size'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey]))

  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)

class FwModPartHeader(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('crc32', c_uint),
              ('version', c_uint),
              ('build_date', c_uint),
              ('dt_len', c_uint),
              ('mem_addr', c_uint),
              ('flag1', c_uint),
              ('magic', c_uint),
              ('flag2', c_uint),
              ('padding', c_uint * 56)]

  def build_date_year(self):
    return (self.build_date>>16)&65535

  def build_date_month(self):
    return (self.build_date>>8)&255

  def build_date_day(self):
    return (self.build_date)&255

  def version_major(self):
    return (self.version>>16)&65535

  def version_minor(self):
    return (self.version)&65535

  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    varkey = 'mem_addr'
    d[varkey] = "{:08X}".format(d[varkey])
    varkey = 'version'
    d[varkey] = "{:d}.{:d}".format(self.version_major(), self.version_minor())
    varkey = 'build_date'
    d[varkey] = "{:d}-{:02d}-{:02d}".format(self.build_date_year(), self.build_date_month(), self.build_date_day())
    varkey = 'flag1'
    d[varkey] = "{:08X}".format(d[varkey])
    varkey = 'flag2'
    d[varkey] = "{:08X}".format(d[varkey])
    varkey = 'magic'
    d[varkey] = "{:08X}".format(d[varkey])
    varkey = 'crc32'
    d[varkey] = "{:08X}".format(d[varkey])
    varkey = 'padding'
    d[varkey] = " ".join("{:08x}".format(x) for x in d[varkey])
    return d

  def ini_export(self, fp, i):
    d = self.dict_export()
    if (i < len(part_entry_type_name)):
      ptyp_name = part_entry_type_name[i]
    else:
      ptyp_name = "type {:02d}".format(i)
    fp.write("# Ambarella Firmware Packer section header file. Loosly based on AFT format.\n")
    fp.write("# Stores partition with {:s}\n".format(ptyp_name))
    fp.write(strftime("# Generated on %Y-%m-%d %H:%M:%S\n", gmtime()))
    varkey = 'mem_addr'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
    varkey = 'version'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
    varkey = 'build_date'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
    varkey = 'flag1'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
    varkey = 'flag2'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
    #varkey = 'crc32'
    #fp.write("{:s}={:s}\n".format(varkey,d[varkey]))

  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)

crc32_tab = [
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
        0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
        0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
        0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
        0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
        0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
        0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
        0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
        0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
        0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
        0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
        0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
        0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
        0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
        0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
        0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
        0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
        0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
        0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
        0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
        0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
        0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
        0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
        0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
        0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
        0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
        0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
        0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
        0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
        0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
        0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
        0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
        0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
        0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
        0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
        0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
        0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
        0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
        0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
        0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
        0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
        0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
        0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
]

def amba_a9_part_entry_type_id(i):
  if (i >= len(part_entry_type_id)):
    return "{:02d}".format(i)
  return part_entry_type_id[i]

def amba_calculate_crc32h_part(buf, pcrc):
  """A twist on crc32 hashing algorithm, probably different from original CRC32 due to a programming mistake."""
  crc = pcrc
  for octet in buf:
    crc = crc32_tab[(crc ^ octet) & 0xff] ^ (crc >> 8)
  return crc & 0xffffffff

def amba_calculate_crc32b_part(buf, pcrc):
  """A standard crc32b hashing algorithm, the same as used in ZIP/PNG."""
  return zlib.crc32(buf, pcrc) & 0xffffffff

def amba_calculate_crc32(buf):
  return amba_calculate_crc32b_part(buf, 0)

def amba_detect_format(po, fwmdlfile):
  """Detects which binary format the firmware module file has."""
  #TODO make multiple formats support
  # FC220 has different format (2016 - FwModA9Header longer 4 butes, 319 ints in FwModA9PostHeader)
  return '2014'

# We really need both i and ptyp params
def amba_extract_part_head(po, e, i, ptyp):
  fwpartfile = open("{:s}_part_{:s}.a9h".format(po.ptprefix,ptyp), "w")
  e.ini_export(fwpartfile, i)
  fwpartfile.close()

def amba_read_part_head(po, i, ptyp):
  e = FwModPartHeader()
  e.magic = 0xA324EB90
  fname = "{:s}_part_{:s}.a9h".format(po.ptprefix,ptyp)
  parser = configparser.ConfigParser()
  with open(fname, "r") as lines:
    lines = itertools.chain(("[asection]",), lines)  # This line adds section header to ini
    parser.read_file(lines)
    e.mem_addr = int(parser.get("asection", "mem_addr"),16)
    e.flag1 = int(parser.get("asection", "flag1"),16)
    e.flag2 = int(parser.get("asection", "flag2"),16)
    version_s = parser.get("asection", "version")
    version_m = re.search('(?P<major>[0-9]+)[.](?P<minor>[0-9]+)', version_s)
    e.version = ((int(version_m.group("major"),10)&0xffff)<<16) + (int(version_m.group("minor"),10)%0xffff)
    build_date_s = parser.get("asection", "build_date")
    build_date_m = re.search('(?P<year>[0-9]+)[-](?P<month>[0-9]+)[-](?P<day>[0-9]+)', build_date_s)
    e.build_date = ((int(build_date_m.group("year"),10)&0xffff)<<16) + ((int(build_date_m.group("month"),10)&0xff)<<8) + (int(build_date_m.group("day"),10)&0xff)
  del parser
  return e


def amba_extract_mod_head(po, modhead, ptyp_names, modposthd):
  fwpartfile = open("{:s}_header.a9h".format(po.ptprefix), "w")
  modhead.ini_export(fwpartfile)
  fwpartfile.write("part_load={:s}\n".format(",".join("{:s}".format(x) for x in ptyp_names)))
  modposthd.ini_export(fwpartfile)
  fwpartfile.close()

def amba_read_mod_head(po):
  modhead = FwModA9Header()
  modposthd = FwModA9PostHeader()
  fname = "{:s}_header.a9h".format(po.ptprefix)
  parser = configparser.ConfigParser()
  with open(fname, "r") as lines:
    lines = itertools.chain(("[asection]",), lines)  # This line adds section header to ini
    parser.read_file(lines)
  ptyp_names = parser.get("asection", "part_load").split(",")
  part_sizes_s = parser.get("asection", "part_size").split(" ")
  part_sizes = [int(n,16) for n in part_sizes_s]
  ver_info_s = parser.get("asection", "ver_info")
  ver_info_m = re.search('(?P<major>[0-9]+)[.](?P<minor>[0-9]+)[-](?P<svn>[0-9A-Fa-f]+)', ver_info_s)
  modhead.model_name = parser.get("asection", "model_name").encode("utf-8")
  modhead.ver_info = ((int(ver_info_m.group("major"),10)&0xff)<<24) + ((int(ver_info_m.group("minor"),10)%0xff)<<16) + (int(ver_info_m.group("svn"),16)%0xffff)
  for i,n in enumerate(part_sizes):
    modposthd.part_size[i] = n
  del parser
  return (modhead, ptyp_names, modposthd)

def amba_extract(po, fwmdlfile):
  modhead = FwModA9Header()
  fwmdlfile.seek(0, os.SEEK_END)
  fwmdlfile_len = fwmdlfile.tell()
  fwmdlfile.seek(0, os.SEEK_SET)
  if fwmdlfile.readinto(modhead) != sizeof(modhead):
      raise EOFError("Couldn't read firmware package file header.")
  if (po.verbose > 1):
      print("{}: Header:".format(po.fwmdlfile))
      print(modhead)
  hdcrc = 0xffffffff
  i = 0
  modentries = []
  ptyp_names = []
  while (True):
    hde = FwModEntry()
    if fwmdlfile.readinto(hde) != sizeof(hde):
      raise EOFError("Couldn't read firmware package file header entries.")
    # If both values are multiplications of 1024, and 2nd is non-zero, then assume we're past end
    # of entries array. Beyond entries array, there's an array of memory load addresses - and
    # load addresses are always rounded to multiplication of a power of 2.
    # Since specific Ambarella firmwares always have set number of partitions, we have to do
    # such guessing if we want one tool to support all Ambarella firmwares.
    if ((hde.dt_len & 0x3ff) == 0) and ((hde.crc32 & 0x3ff) == 0) and (hde.crc32 != 0):
      fwmdlfile.seek(-sizeof(hde),os.SEEK_CUR)
      break
    if (sizeof(modhead)+i*sizeof(hde)+hde.dt_len >= fwmdlfile_len):
      if (po.verbose > 1):
          print("{}: Detection finished with entry larger than file; expecting {:d} entries".format(po.fwmdlfile,len(modentries)))
      eprint("{}: Warning: Detection finished with unusual condition, verify files".format(po.fwmdlfile))
      fwmdlfile.seek(-sizeof(hde),os.SEEK_CUR)
      break
    modentries.append(hde)
    if (hde.dt_len > 0):
      ptyp_names.append(amba_a9_part_entry_type_id(i))
    i += 1
    if (i > 128):
      raise EOFError("Couldn't find header entries end marking.")
  if (po.verbose > 1):
      print("{}: After detection, expecting {:d} entries".format(po.fwmdlfile,len(modentries)))
  if (po.verbose > 1):
      print("{}: Entries:".format(po.fwmdlfile))
      print(modentries)

  modposthd = FwModA9PostHeader()
  if fwmdlfile.readinto(modposthd) != sizeof(modposthd):
      raise EOFError("Couldn't read firmware package file header.")
  if (po.verbose > 1):
      print("{}: Post Header:".format(po.fwmdlfile))
      print(modposthd)
  amba_extract_mod_head(po, modhead, ptyp_names, modposthd)
  i = -1
  while True:
    i += 1
    # Skip unused modentries
    if (i < len(modentries)):
      hde = modentries[i]
      if (hde.dt_len < 1):
        continue
    else:
      # Do not show warning yet - maybe the file is at EOF
      hde = FwModEntry()
    epos = fwmdlfile.tell()
    e = FwModPartHeader()
    n = fwmdlfile.readinto(e)
    if (n is None) or (n == 0):
      # End Of File, correct ending
      break
    if n != sizeof(e):
      raise EOFError("Couldn't read firmware package partition header, got {:d} out of {:d}.".format(n,sizeof(e)))
    if e.magic != 0xA324EB90:
      eprint("{}: Warning: Invalid magic value in partition {:d} header; will try to extract anyway.".format(po.fwmdlfile,i))
    if (po.verbose > 1):
      print("{}: Entry {}".format(po.fwmdlfile,i))
      print(e)
    hdcrc = amba_calculate_crc32h_part((c_ubyte * sizeof(e)).from_buffer_copy(e), hdcrc)
    if (e.dt_len < 16) or (e.dt_len > 128*1024*1024):
      eprint("{}: Warning: entry at {:d} has bad size, {:d} bytes".format(po.fwmdlfile,epos,e.dt_len))
    # Warn if no more module entries were expected
    if (i >= len(modentries)):
      eprint("{}: Warning: Data continues after parsing all {:d} known partitions; header inconsistent.".format(po.fwmdlfile,i))
    print("{}: Extracting entry {:2d}, pos {:8d}, len {:8d} bytes".format(po.fwmdlfile,i,epos,e.dt_len))
    ptyp = amba_a9_part_entry_type_id(i)
    amba_extract_part_head(po, e, i, ptyp)
    fwpartfile = open("{:s}_part_{:s}.a9s".format(po.ptprefix,ptyp), "wb")
    if (po.binhead):
      #fwmdlfile.seek(-sizeof(e),os.SEEK_CUR)
      #copy_buffer = fwmdlfile.read(sizeof(e))
      #fwpartfile.write(copy_buffer)
      fwpartfile.write((c_ubyte * sizeof(e)).from_buffer_copy(e))
    ptcrc = 0
    n = 0
    while n < e.dt_len:
      copy_buffer = fwmdlfile.read(min(1024 * 1024, e.dt_len - n))
      if not copy_buffer:
          break
      n += len(copy_buffer)
      fwpartfile.write(copy_buffer)
      ptcrc = amba_calculate_crc32b_part(copy_buffer, ptcrc)
      hdcrc = amba_calculate_crc32h_part(copy_buffer, hdcrc)
    fwpartfile.close()
    if (n < e.dt_len):
        eprint("{}: Warning: partition {:d} truncated, {:d} out of {:d} bytes".format(po.fwmdlfile,i,n,e.dt_len))
    if (ptcrc != e.crc32):
        eprint("{}: Warning: Entry {:d} data checksum mismatch; got {:08X}, expected {:08X}.".format(po.fwmdlfile,i,ptcrc,e.crc32))
    elif (po.verbose > 1):
        print("{}: Entry {:2d} data checksum {:08X} matched OK".format(po.fwmdlfile,i,ptcrc))
    if (hdcrc != hde.crc32):
        eprint("{}: Warning: Entry {:d} cummulative checksum mismatch; got {:08X}, expected {:08X}.".format(po.fwmdlfile,i,hdcrc,hde.crc32))
    elif (po.verbose > 1):
        print("{}: Entry {:2d} cummulative checksum {:08X} matched OK".format(po.fwmdlfile,i,hdcrc))
    # Check if the date makes sense
    if (e.build_date_year() < 1970) or (e.build_date_month() < 1) or (e.build_date_month() > 12) or (e.build_date_day() < 1) or (e.build_date_day() > 31):
        eprint("{}: Warning: Entry {:d} date makes no sense.".format(po.fwmdlfile,i))
    elif (e.build_date_year() < 2004):
        eprint("{}: Warning: Entry {:d} date is from before Ambarella formed as company.".format(po.fwmdlfile,i))
    # verify if padding area is completely filled with 0x00000000
    if (e.padding[0] != 0x00000000) or (len(set(e.padding)) != 1):
      eprint("{}: Warning: partition {:d} header uses values from padded area in an unknown manner.".format(po.fwmdlfile,i))
  # Now verify checksum in main header
  hdcrc = hdcrc ^ 0xffffffff
  if (hdcrc != modhead.crc32):
      eprint("{}: Warning: Total cummulative checksum mismatch; got {:08X}, expected {:08X}.".format(po.fwmdlfile,hdcrc,modhead.crc32))
  elif (po.verbose > 1):
      print("{}: Total cummulative checksum {:08X} matched OK".format(po.fwmdlfile,hdcrc))

def amba_search_extract(po, fwmdlfile):
  fwmdlmm = mmap.mmap(fwmdlfile.fileno(), length=0, access=mmap.ACCESS_READ)
  epos = -sizeof(FwModPartHeader)
  prev_dtlen = 0
  prev_dtpos = 0
  i = 0
  while True:
    epos = fwmdlmm.find(b'\x90\xEB\x24\xA3', epos+sizeof(FwModPartHeader))
    if (epos < 0):
      break
    epos -= 24 # pos of 'magic' within FwModPartHeader
    if (epos < 0):
      continue
    dtpos = epos+sizeof(FwModPartHeader)
    e = FwModPartHeader.from_buffer_copy(fwmdlmm[epos:dtpos]);
    if (e.dt_len < 16) or (e.dt_len > 128*1024*1024) or (e.dt_len > fwmdlmm.size()-dtpos):
      print("{}: False positive - entry at {:d} has bad size, {:d} bytes".format(po.fwmdlfile,epos,e.dt_len))
      continue
    print("{}: Extracting entry {:2d}, pos {:8d}, len {:8d} bytes".format(po.fwmdlfile,i,epos,e.dt_len))
    if (prev_dtpos+prev_dtlen > epos):
      eprint("{}: Partition {:d} overlaps with previous by {:d} bytes".format(po.fwmdlfile,i,prev_dtpos+prev_dtlen - epos))
    ptyp = "{:02d}".format(i)
    amba_extract_part_head(po, e, i, ptyp)
    fwpartfile = open("{:s}_part_{:s}.a9s".format(po.ptprefix,ptyp), "wb")
    fwpartfile.write(fwmdlmm[epos+sizeof(FwModPartHeader):epos+sizeof(FwModPartHeader)+e.dt_len])
    fwpartfile.close()
    crc = amba_calculate_crc32(fwmdlmm[epos+sizeof(FwModPartHeader):epos+sizeof(FwModPartHeader)+e.dt_len])
    if (crc != e.crc32):
        eprint("{}: Warning: Entry {:d} checksum mismatch; got {:08X}, expected {:08X}.".format(po.fwmdlfile,i,crc,e.crc32))
    if (po.verbose > 1):
        print("{}: Entry {:2d} checksum {:08X}".format(po.fwmdlfile,i,crc))
    prev_dtlen = e.dt_len
    prev_dtpos = dtpos
    i += 1

def amba_create(po, fwmdlfile):
  # Read headers from INI files
  (modhead, ptyp_names, modposthd) = amba_read_mod_head(po)
  modentries = []
  # Get amount of partition slots to allocate
  modentry_max = 0
  for ptyp in ptyp_names:
    if ptyp not in part_entry_type_id:
      raise ValueError("Unrecognized partition name in 'part_load' option.")
    i = part_entry_type_id.index(ptyp)
    if (modentry_max < i):
      modentry_max = i
  # Create module entry for each partition
  for i in range(modentry_max+1):
    hde = FwModEntry()
    modentries.append(hde)
  # Write the unfinished headers
  fwmdlfile.write((c_ubyte * sizeof(modhead)).from_buffer_copy(modhead))
  for hde in modentries:
    fwmdlfile.write((c_ubyte * sizeof(hde)).from_buffer_copy(hde))
  fwmdlfile.write((c_ubyte * sizeof(modposthd)).from_buffer_copy(modposthd))
  # Write the partitions
  part_heads = []
  i = -1
  while True:
    i += 1
    if (i >= len(modentries)):
      break
    hde = modentries[i]
    ptyp = amba_a9_part_entry_type_id(i)
    fname = "{:s}_part_{:s}.a9s".format(po.ptprefix,ptyp)
    # Skip unused modentries
    if not ptyp in ptyp_names:
      if (po.verbose > 1):
        print("{}: Entry {:2d} empty".format(po.fwmdlfile,i))
      e = FwModPartHeader()
      part_heads.append(e)
      continue
    # Also skip nonexisting ones
    if (os.stat(fname).st_size < 1):
      eprint("{}: Warning: partition {:d} marked as existing but empty".format(po.fwmdlfile,i))
      e = FwModPartHeader()
      part_heads.append(e)
      continue
    e = amba_read_part_head(po, i, ptyp)
    epos = fwmdlfile.tell()
    # Wrie unfinished header
    fwmdlfile.write((c_ubyte * sizeof(e)).from_buffer_copy(e))
    # Copy partition data and compute CRC
    fwpartfile = open(fname, "rb")
    ptcrc = 0
    n = 0
    while True:
      copy_buffer = fwpartfile.read(1024 * 1024)
      if not copy_buffer:
          break
      n += len(copy_buffer)
      fwmdlfile.write(copy_buffer)
      ptcrc = amba_calculate_crc32b_part(copy_buffer, ptcrc)
    e.dt_len = n
    e.crc32 = ptcrc
    if (po.verbose > 1):
      print("{}: Entry {:2d} checksum {:08X}".format(po.fwmdlfile,i,ptcrc))
    part_heads.append(e)
    # Write final header
    npos = fwmdlfile.tell()
    fwmdlfile.seek(epos,os.SEEK_SET)
    fwmdlfile.write((c_ubyte * sizeof(e)).from_buffer_copy(e))
    fwmdlfile.seek(npos,os.SEEK_SET)
    hde.dt_len = sizeof(e) + e.dt_len
    modentries[i] = hde
  # Compute cummulative CRC32
  if (po.verbose > 1):
    print("{}: Recomputing checksums".format(po.fwmdlfile))
  hdcrc = 0xffffffff
  i = -1
  while True:
    i += 1
    if (i >= len(modentries)):
      break
    hde = modentries[i]
    ptyp = amba_a9_part_entry_type_id(i)
    fname = "{:s}_part_{:s}.a9s".format(po.ptprefix,ptyp)
    if (hde.dt_len < 1):
      continue
    fwpartfile = open(fname, "rb")
    e = part_heads[i]
    hdcrc = amba_calculate_crc32h_part((c_ubyte * sizeof(e)).from_buffer_copy(e), hdcrc)
    n = 0
    while n < e.dt_len:
      copy_buffer = fwpartfile.read(min(1024 * 1024, e.dt_len - n))
      if not copy_buffer:
          break
      n += len(copy_buffer)
      hdcrc = amba_calculate_crc32h_part(copy_buffer, hdcrc)
    hde.crc32 = hdcrc
    modentries[i] = hde
  hdcrc = hdcrc ^ 0xffffffff
  modhead.crc32 = hdcrc
  if (po.verbose > 1):
    print("{}: Total cummulative checksum {:08X}".format(po.fwmdlfile,hdcrc))
  # Write all headers again
  fwmdlfile.seek(0,os.SEEK_SET)
  fwmdlfile.write((c_ubyte * sizeof(modhead)).from_buffer_copy(modhead))
  for hde in modentries:
    fwmdlfile.write((c_ubyte * sizeof(hde)).from_buffer_copy(hde))
  fwmdlfile.write((c_ubyte * sizeof(modposthd)).from_buffer_copy(modposthd))

def main(argv):
  # Parse command line options
  po = ProgOptions()
  try:
     opts, args = getopt.getopt(argv,"hxsabvf:t:m:",["help","version","extract","search","add","binhead","format=","fwmdl=","ptprefix="])
  except getopt.GetoptError:
     print("Unrecognized options; check amba_fwpak.py --help")
     sys.exit(2)
  for opt, arg in opts:
     if opt in ("-h", "--help"):
        print("Ambarella Firmware Packer tool")
        print("amba_fwpak.py <-x|-s|-a> [-v] -m <fwmdfile> [-t <ptprefix>]")
        print("  -m <fwmdfile> - name of the firmware module file")
        print("  -t <ptprefix> - file name prefix for the single decomposed partitions")
        print("                  defaults to base name of firmware module file")
        print("  -x - extract firmware module file into partitions")
        print("  -s - search for partitions within firmware module and extract them")
        print("       (works similar to -x, but uses brute-force search for partitions)")
        print("  -a - add partition files to firmware module file")
        print("       (works only on data created with -x; the -s is insufficient)")
        #print("  -f - set binary format version; default is to detect it (-fauto)")
        #print("       valid formats are 2014 and 2016")
        print("  -b - leave (-x) or use (-a) binary header in front of partition")
        print("       this leaves the original binary header before each partition")
        print("       on extraction, and uses that header on module file creation;")
        print("       you normally should have no need to use it")
        print("  -v - increases verbosity level; max level is set by -vvv")
        sys.exit()
     elif opt == "--version":
        print("amba_fwpak.py version 0.1.1")
        sys.exit()
     elif opt == '-v':
        po.verbose += 1
     elif opt in ("-b", "--binhead"):
        po.binhead = True
     elif opt in ("-f", "--format"):
        po.binfmt = arg
     elif opt in ("-m", "--fwmdl"):
        po.fwmdlfile = arg
     elif opt in ("-t", "--ptprefix"):
        po.ptprefix = arg
     elif opt in ("-x", "--extract"):
        po.command = 'x'
     elif opt in ("-s", "--search"):
        po.command = 's'
     elif opt in ("-a", "--add"):
        po.command = 'a'
  if len(po.fwmdlfile) > 0 and len(po.ptprefix) == 0:
      po.ptprefix = os.path.splitext(os.path.basename(po.fwmdlfile))[0]

  if (po.command == 'x'):

    if (po.verbose > 0):
      print("{}: Opening for extraction".format(po.fwmdlfile))
    fwmdlfile = open(po.fwmdlfile, "rb")

    if po.binfmt == 'auto':
      po.binfmt = amba_detect_format(po,fwmdlfile)

    amba_extract(po,fwmdlfile)

    fwmdlfile.close();

  elif (po.command == 's'):

    if (po.verbose > 0):
      print("{}: Opening for search".format(po.fwmdlfile))
    fwmdlfile = open(po.fwmdlfile, "rb")

    amba_search_extract(po,fwmdlfile)

    fwmdlfile.close();

  elif (po.command == 'a'):

    if (po.verbose > 0):
      print("{}: Opening for creation".format(po.fwmdlfile))
    fwmdlfile = open(po.fwmdlfile, "wb")

    amba_create(po,fwmdlfile)

    fwmdlfile.close();

  else:

    raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
   main(sys.argv[1:])
