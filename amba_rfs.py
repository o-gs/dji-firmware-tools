#!/usr/bin/env python

from __future__ import print_function
import sys
import getopt
import os
import hashlib
import mmap
import zlib
import re
from ctypes import *
from time import gmtime, strftime

def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

class ProgOptions:
  fwpartfile = ''
  ptprefix = ''
  verbose = 0
  command = ''

class RFSPartitionHeader(LittleEndianStructure):
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

class RFSFileEntry(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('filename', c_char * 116),
              ('offset', c_uint),
              ('length', c_uint),
              ('magic', c_uint)]

  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    return d

  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)

def rfs_extract_filesystem_head(po, fshead, fsentries):
  fwpartfile = open("{:s}_header.a9t".format(po.ptprefix), "w")
  fwpartfile.write("# Ambarella Firmware RFS header file. Loosly based on AFT format.\n")
  fwpartfile.write(strftime("# Generated on %Y-%m-%d %H:%M:%S\n", gmtime()))
  fwpartfile.write("filelist={:s}\n".format(",".join("{:s}".format(x.filename) for x in fsentries)))
  fwpartfile.close()

def rfs_extract(po, fwpartfile):
  fshead = RFSPartitionHeader()
  if fwpartfile.readinto(fshead) != sizeof(fshead):
    raise EOFError("Couldn't read RFS partition file header.")
  if (po.verbose > 1):
    print("{}: Header:".format(po.fwpartfile))
    print(fshead)
  if (fshead.magic != 0x66FC328A):
    eprint("{}: Warning: magic value is {:08X} instead of {:08X}.".format(po.fwpartfile,fshead.magic,0x66FC328A))
    raise EOFError("Invalid magic value in main header. The file does not store a RFS filesystem.")
  if (fshead.file_count < 1) or (fshead.file_count > 16*1024):
    eprint("{}: Warning: filesystem stores alarming amount of files, which is {:d}".format(po.fwpartfile,fshead.file_count))
  # verify if padding area is completely filled with 0xff
  if (fshead.padding[0] != 0xff) or (len(set(fshead.padding)) != 1):
    eprint("{}: Warning: filesystem uses values from padded area in an unknown manner.".format(po.fwpartfile))

  fsentries = []
  for i in range(fshead.file_count):
    fe = RFSFileEntry()
    if fwpartfile.readinto(fe) != sizeof(fe):
      raise EOFError("Couldn't read filesystem file header entries.")
    if (fe.magic != 0x2387AB76):
      eprint("{}: Warning: entry {:d} has magic value {:08X} instead of {:08X}.".format(po.fwpartfile,i,fe.magic,0x2387AB76))
    if re.match(b'[0-9A-Za-z._-]', fe.filename) is None:
      eprint("{}: Warning: entry {:d} has invalid file name; skipping.".format(po.fwpartfile,i))
      continue
    if (fe.length < 0) or (fe.length > 128*1024*1024):
      eprint("{}: Warning: entry {:d} has bad size, {:d} bytes; skipping.".format(po.fwmdlfile,i,fe.length))
      continue
    if (fe.offset < 0) or (fe.offset > 128*1024*1024):
      eprint("{}: Warning: entry {:d} has bad offset, {:d} bytes; skipping.".format(po.fwmdlfile,i,fe.offset))
      continue
    fsentries.append(fe)

  if (po.verbose > 1):
      print("{}: Entries:".format(po.fwpartfile))
      print(fsentries)

  rfs_extract_filesystem_head(po, fshead, fsentries)

  raise NotImplementedError('Unsupported command.')
  i = -1
  while True:
    i += 1
    # Skip unused fsentries
    if (i < len(fsentries)):
      fe = fsentries[i]
      if (fe.dt_len < 1):
        continue
    else:
      # Do not show warning yet - maybe the file is at EOF
      fe = FwModEntry()
    epos = fwpartfile.tell()
    e = FwModPartHeader()
    n = fwpartfile.readinto(e)
    if (n is None) or (n == 0):
      # End Of File, correct ending
      break
    if n != sizeof(e):
      raise EOFError("Couldn't read firmware package partition header, got {:d} out of {:d}.".format(n,sizeof(e)))
    if (po.verbose > 1):
      print("{}: Entry {}".format(po.fwpartfile,i))
      print(e)
    hdcrc = rfs_calculate_crc32_part((c_ubyte * sizeof(e)).from_buffer_copy(e), 0)
    if (e.dt_len < 16) or (e.dt_len > 128*1024*1024):
      eprint("{}: Warning: entry at {:d} has bad size, {:d} bytes".format(po.fwpartfile,epos,e.dt_len))
    # Warn if no more module entries were expected
    if (i >= len(fsentries)):
      eprint("{}: Warning: Data continues after parsing all {:d} known partitions; header inconsistent.".format(po.fwpartfile,i))
    print("{}: Extracting entry {:2d}, pos {:8d}, len {:8d} bytes".format(po.fwpartfile,i,epos,e.dt_len))
    if (i < len(part_entry_type_id)):
      ptyp = part_entry_type_id[i]
    else:
      ptyp = "{:02d}".format(i)
    rfs_extract_part_head(po, e, ptyp)
    singlefile = open("{:s}_part_{:s}.a9s".format(po.ptprefix,ptyp), "wb")
    ptcrc = 0
    n = 0
    while n < e.dt_len:
      copy_buffer = singlefile.read(min(1024 * 1024, e.dt_len - n))
      if not copy_buffer:
          break
      n += len(copy_buffer)
      singlefile.write(copy_buffer)
      ptcrc = rfs_calculate_crc32_part(copy_buffer, ptcrc)
      #hdcrc = rfs_calculate_crc32_part(copy_buffer, hdcrc)
    singlefile.close()
    if (n < e.dt_len):
      eprint("{}: Warning: partition {:d} truncated, {:d} out of {:d} bytes".format(po.fwpartfile,i,n,e.dt_len))

def rfs_search_extract(po, fwpartfile):
  raise NotImplementedError('NOT IMPLEMENTED')

def rfs_create(po, fwpartfile):
  raise NotImplementedError('NOT IMPLEMENTED')

def main(argv):
  # Parse command line options
  po = ProgOptions()
  try:
     opts, args = getopt.getopt(argv,"hxsavt:p:",["help","version","extract","search","add","fwpart=","ptprefix="])
  except getopt.GetoptError:
     print("Unrecognized options; check amba_rfs.py --help")
     sys.exit(2)
  for opt, arg in opts:
     if opt in ("-h", "--help"):
        print("Ambarella Firmware RFS tool")
        print("amba_rfs.py <-x|-s|-a> [-v] -m <fwmdfile> [-t <ptprefix>]")
        print("  -p <fwpartfile> - name of the firmware partition file")
        print("  -t <ptprefix> - file name prefix for the single decomposed partitions")
        print("                  defaults to base name of firmware module file")
        print("  -x - extract firmware module file into partitions")
        print("  -s - search for partitions within firmware module and extract them")
        print("       (works similar to -x, but uses brute-force search for partitions)")
        print("  -a - add partition files to firmware module file")
        print("       (works only on data created with -x; the -s is insufficient)")
        print("  -v - increases verbosity level; max level is set by -vvv")
        sys.exit()
     elif opt == "--version":
        print("amba_rfs.py version 0.1.0")
        sys.exit()
     elif opt == '-v':
        po.verbose += 1
     elif opt in ("-p", "--fwpart"):
        po.fwpartfile = arg
     elif opt in ("-t", "--ptprefix"):
        po.ptprefix = arg
     elif opt in ("-x", "--extract"):
        po.command = 'x'
     elif opt in ("-s", "--search"):
        po.command = 's'
     elif opt in ("-a", "--add"):
        po.command = 'a'
  if len(po.fwpartfile) > 0 and len(po.ptprefix) == 0:
      po.ptprefix = os.path.splitext(os.path.basename(po.fwpartfile))[0]

  if (po.command == 'x'):

    if (po.verbose > 0):
      print("{}: Opening for extraction".format(po.fwpartfile))
    fwpartfile = open(po.fwpartfile, "rb")

    rfs_extract(po,fwpartfile)

    fwpartfile.close();

  elif (po.command == 's'):

    if (po.verbose > 0):
      print("{}: Opening for search".format(po.fwpartfile))
    fwpartfile = open(po.fwpartfile, "rb")

    rfs_search_extract(po,fwpartfile)

    fwpartfile.close();

  elif (po.command == 'a'):

    if (po.verbose > 0):
      print("{}: Opening for creation".format(po.fwpartfile))
    fwpartfile = open(po.fwpartfile, "wb")

    rfs_create(po,fwpartfile)

    fwpartfile.close();

  else:

    raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
   main(sys.argv[1:])
