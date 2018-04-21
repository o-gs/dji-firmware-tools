#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Ambarella Firmware ROMFS tool
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
import getopt
import os
import hashlib
import mmap
import zlib
import re
import configparser
import itertools
from ctypes import *
from time import gmtime, strftime

def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

class ProgOptions:
  fwpartfile = ''
  snglfdir = ''
  verbose = 0
  command = ''

# The ROMFS file consists of 3 sections:
# 1. Main header, padded
# 2. File entries, padded at end only
# 3. File data, padded after each entry
# Note that padding is a bit unusual - if a file
# length is exact multiplication of 2048, the
# entry is still padded (with another 2048 bytes).

class ROMFSPartitionHeader(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('file_count', c_uint), # Amount of files stored
              ('magic', c_uint), # magic identifier, 66FC328A
              ('padding', c_ubyte * 2040)] # padded with 0xff

  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    varkey = 'padding'
    d[varkey] = "".join("{:02X}".format(x) for x in d[varkey])
    return d

  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)

class ROMFSFileEntry(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('filename', c_char * 116),
              ('offset', c_uint),
              ('length', c_uint),
              ('magic', c_uint)]

  def filename_str(self):
    return cast(self.filename, c_char_p).value.decode('utf-8')

  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    return d

  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)


def romfs_padded_size(content_offs):
  #if (content_offs % 2048) != 0: - no, padding is not done this way
  return content_offs + 2048 - (content_offs % 2048);
  


def romfs_extract_filesystem_head(po, fshead, fsentries):
  fname = "{:s}/{:s}".format(po.snglfdir,"_header.a9t")
  os.makedirs(os.path.dirname(fname), exist_ok=True)
  inifile = open(fname, "w")
  inifile.write("# Ambarella Firmware ROMFS header file. Loosly based on AFT format.\n")
  inifile.write(strftime("# Generated on %Y-%m-%d %H:%M:%S\n", gmtime()))
  inifile.write("filelist={:s}\n".format(",".join("{:s}".format(x.filename_str()) for x in fsentries)))
  inifile.close()


def romfs_read_filesystem_head(po):
  fshead = ROMFSPartitionHeader()
  fsentries = []
  fname = "{:s}/{:s}".format(po.snglfdir,"_header.a9t")
  parser = configparser.ConfigParser()
  with open(fname, "r") as lines:
    lines = itertools.chain(("[asection]",), lines)  # This line adds section header to ini
    parser.read_file(lines)
  singlefnames = parser.get("asection", "filelist").split(",")
  for sfname in singlefnames:
    fe = ROMFSFileEntry()
    fe.filename = sfname.encode('utf-8')
    fe.offset = sizeof(fshead)
    fe.magic = 0x2387AB76
    fsentries.append(fe)
  fshead.magic = 0x66FC328A
  fshead.file_count = len(fsentries)
  for i in range(len(fshead.padding)):
    fshead.padding[i] = 0xff
  del parser
  return fshead, fsentries


def romfs_recompute_filesystem_lengths(po, fshead, fsentries):
  for i, fe in enumerate(fsentries):
    fname = "{:s}/{:s}".format(po.snglfdir,fe.filename_str())
    fe.length = os.stat(fname).st_size
  fshead.file_count = len(fsentries)
  return fshead, fsentries


def romfs_recompute_filesystem_offsets(po, fshead, fsentries):
  content_offs = sizeof(fshead)
  # ROMFSPartitionHeader is already padded, no need for action
  content_offs = romfs_padded_size( content_offs + len(fsentries) * sizeof(ROMFSFileEntry) )
  for i, fe in enumerate(fsentries):
    fe.offset = content_offs;
    content_offs = romfs_padded_size( content_offs + fe.length )
  fshead.file_count = len(fsentries)
  return fshead, fsentries


def romfs_extract_filesystem_entry(po, fwpartfile, i, fe):
  if (po.verbose > 0):
    print("{}: Extracting entry {:d}: {:s}, {:d} bytes".format(po.fwpartfile,i,fe.filename_str(),fe.length))
  fwpartfile.seek(fe.offset,0)
  fname = "{:s}/{:s}".format(po.snglfdir,fe.filename_str())
  os.makedirs(os.path.dirname(fname), exist_ok=True)
  singlefile = open(fname, "wb")
  n = 0
  while n < fe.length:
    copy_buffer = fwpartfile.read(min(1024 * 1024, fe.length - n))
    if not copy_buffer:
        break
    n += len(copy_buffer)
    singlefile.write(copy_buffer)
  singlefile.close()
  if (n < fe.length):
    eprint("{}: Warning: file {:d} truncated, {:d} out of {:d} bytes".format(po.fwpartfile,i,n,fe.length))


def romfs_write_filesystem_entry(po, fwpartfile, i, fe):
  if (po.verbose > 0):
    print("{}: Writing entry {:d}: {:s}, {:d} bytes".format(po.fwpartfile,i,fe.filename_str(),fe.length))
  while (fwpartfile.tell() < fe.offset):
    fwpartfile.write(b'\xFF')
  fname = "{:s}/{:s}".format(po.snglfdir,fe.filename_str())
  singlefile = open(fname, "rb")
  n = 0
  while n < fe.length:
    copy_buffer = singlefile.read(min(1024 * 1024, fe.length - n))
    if not copy_buffer:
        break
    n += len(copy_buffer)
    fwpartfile.write(copy_buffer)
  singlefile.close()
  if (n < fe.length):
    eprint("{}: Warning: file {:d} truncated, {:d} out of {:d} bytes".format(po.fwpartfile,i,n,fe.length))
  content_offs = romfs_padded_size( fwpartfile.tell() )
  while (fwpartfile.tell() < content_offs):
    fwpartfile.write(b'\xFF')


def romfs_extract(po, fwpartfile):
  fshead = ROMFSPartitionHeader()
  if fwpartfile.readinto(fshead) != sizeof(fshead):
    raise EOFError("Couldn't read ROMFS partition file header.")
  if (po.verbose > 1):
    print("{}: Header:".format(po.fwpartfile))
    print(fshead)
  if (fshead.magic != 0x66FC328A):
    eprint("{}: Warning: magic value is {:08X} instead of {:08X}.".format(po.fwpartfile,fshead.magic,0x66FC328A))
    raise EOFError("Invalid magic value in main header. The file does not store a ROMFS filesystem.")
  if (fshead.file_count < 1) or (fshead.file_count > 16*1024):
    eprint("{}: Warning: filesystem stores alarming amount of files, which is {:d}".format(po.fwpartfile,fshead.file_count))
  # verify if padding area is completely filled with 0xff
  if (fshead.padding[0] != 0xff) or (len(set(fshead.padding)) != 1):
    eprint("{}: Warning: filesystem uses values from padded area in an unknown manner.".format(po.fwpartfile))

  fsentries = []
  for i in range(fshead.file_count):
    fe = ROMFSFileEntry()
    if fwpartfile.readinto(fe) != sizeof(fe):
      raise EOFError("Couldn't read filesystem file header entries.")
    if (fe.magic != 0x2387AB76):
      eprint("{}: Warning: entry {:d} has magic value {:08X} instead of {:08X}.".format(po.fwpartfile,i,fe.magic,0x2387AB76))
    if re.match(b'[0-9A-Za-z._-]', fe.filename) is None:
      eprint("{}: Warning: entry {:d} has invalid file name; skipping.".format(po.fwpartfile,i))
      continue
    if (fe.length < 0) or (fe.length > 128*1024*1024):
      eprint("{}: Warning: entry {:d} has bad size, {:d} bytes; skipping.".format(po.fwpartfile,i,fe.length))
      continue
    if (fe.offset < 0) or (fe.offset > 128*1024*1024):
      eprint("{}: Warning: entry {:d} has bad offset, {:d} bytes; skipping.".format(po.fwpartfile,i,fe.offset))
      continue
    fsentries.append(fe)

  if (po.verbose > 2):
      print("{}: Entries:".format(po.fwpartfile))
      print(fsentries)

  romfs_extract_filesystem_head(po, fshead, fsentries)

  for i, fe in enumerate(fsentries):
    romfs_extract_filesystem_entry(po, fwpartfile, i, fe)


def romfs_search_extract(po, fwpartfile):
  fshead = ROMFSPartitionHeader()
  fwpartmm = mmap.mmap(fwpartfile.fileno(), length=0, access=mmap.ACCESS_READ)
  fsentries = []
  epos = -sizeof(ROMFSFileEntry)
  prev_dtlen = 0
  prev_dtpos = 0
  i = 0
  while True:
    epos = fwpartmm.find(b'\x76\xAB\x87\x23', epos+sizeof(ROMFSFileEntry))
    if (epos < 0):
      break
    epos -= 124 # pos of 'magic' within FwModPartHeader
    if (epos < 0):
      continue
    fe = ROMFSFileEntry.from_buffer_copy(fwpartmm[epos:epos+sizeof(ROMFSFileEntry)]);
    dtpos = fe.offset
    if (fe.length < 0) or (fe.length > 128*1024*1024) or (fe.length > fwpartmm.size()-dtpos):
      print("{}: False positive - entry at {:d} has bad size, {:d} bytes".format(po.fwpartfile,epos,fe.length))
      continue
    if (prev_dtpos < dtpos+fe.length) and (prev_dtpos+prev_dtlen > dtpos):
      eprint("{}: File {:d} data overlaps with previous by {:d} bytes".format(po.fwpartfile,i,prev_dtpos+prev_dtlen - dtpos))
    fsentries.append(fe)
    prev_dtlen = fe.length
    prev_dtpos = dtpos
    i += 1

  if (po.verbose > 2):
      print("{}: Entries:".format(po.fwpartfile))
      print(fsentries)

  romfs_extract_filesystem_head(po, fshead, fsentries)

  for i, fe in enumerate(fsentries):
    romfs_extract_filesystem_entry(po, fwpartfile, i, fe)


def romfs_create(po, fwpartfile):
  fshead, fsentries = romfs_read_filesystem_head(po)
  if (po.verbose > 2):
      print("{}: Entries:".format(po.fwpartfile))
      print(fsentries)
  fshead, fsentries = romfs_recompute_filesystem_lengths(po, fshead, fsentries)
  fshead, fsentries = romfs_recompute_filesystem_offsets(po, fshead, fsentries)
  if fwpartfile.write(fshead) != sizeof(fshead):
    raise EOFError("Couldn't write ROMFS partition file main header.")
  for i, fe in enumerate(fsentries):
    if fwpartfile.write(fe) != sizeof(fe):
      raise EOFError("Couldn't write ROMFS partition file entry header.")
  for i, fe in enumerate(fsentries):
    romfs_write_filesystem_entry(po, fwpartfile, i, fe)


def main(argv):
  # Parse command line options
  po = ProgOptions()
  try:
     opts, args = getopt.getopt(argv,"hxsavd:p:",["help","version","extract","search","add","fwpart=","snglfdir="])
  except getopt.GetoptError:
     print("Unrecognized options; check amba_romfs.py --help")
     sys.exit(2)
  for opt, arg in opts:
     if opt in ("-h", "--help"):
        print("Ambarella Firmware ROMFS tool")
        print("amba_romfs.py <-x|-s|-a> [-v] -m <fwmdfile> [-t <snglfdir>]")
        print("  -p <fwpartfile> - name of the firmware partition file")
        print("  -d <snglfdir> - directory for the single extracted files")
        print("                  defaults to base name of firmware partition file")
        print("  -x - extract partition file into single files")
        print("  -s - search for files within partition and extract them")
        print("       (works similar to -x, but uses brute-force search for file entries)")
        print("  -a - add single files to partition file")
        print("  -v - increases verbosity level; max level is set by -vvv")
        sys.exit()
     elif opt == "--version":
        print("amba_romfs.py version 0.1.1")
        sys.exit()
     elif opt == '-v':
        po.verbose += 1
     elif opt in ("-p", "--fwpart"):
        po.fwpartfile = arg
     elif opt in ("-d", "--snglfdir"):
        po.snglfdir = arg
     elif opt in ("-x", "--extract"):
        po.command = 'x'
     elif opt in ("-s", "--search"):
        po.command = 's'
     elif opt in ("-a", "--add"):
        po.command = 'a'
  if len(po.fwpartfile) > 0 and len(po.snglfdir) == 0:
      po.snglfdir = os.path.splitext(os.path.basename(po.fwpartfile))[0]

  if (po.command == 'x'):

    if (po.verbose > 0):
      print("{}: Opening for extraction".format(po.fwpartfile))
    fwpartfile = open(po.fwpartfile, "rb")

    romfs_extract(po,fwpartfile)

    fwpartfile.close();

  elif (po.command == 's'):

    if (po.verbose > 0):
      print("{}: Opening for search".format(po.fwpartfile))
    fwpartfile = open(po.fwpartfile, "rb")

    romfs_search_extract(po,fwpartfile)

    fwpartfile.close();

  elif (po.command == 'a'):

    if (po.verbose > 0):
      print("{}: Opening for creation".format(po.fwpartfile))
    fwpartfile = open(po.fwpartfile, "wb")

    romfs_create(po,fwpartfile)

    fwpartfile.close();

  else:

    raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
   main(sys.argv[1:])
