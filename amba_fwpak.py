#!/usr/bin/env python

from __future__ import print_function
import sys
import getopt
import os
import hashlib
import mmap
from ctypes import *
from time import gmtime, strftime

def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

class ProgOptions:
  fwmdlfile = ''
  ptprefix = ''
  verbose = 0
  command = ''

class FwModA9Header(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('description', c_char * 36),
              ('reserved36', c_char * 104)]
  def __repr__(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    from pprint import pformat
    return pformat(d, indent=4, width=1)

class FwModEntry(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('crc32', c_uint),
              ('version', c_uint),
              ('build_date', c_uint),
              ('dt_len', c_uint),
              ('dt_mem', c_uint),
              ('flag1', c_uint),
              ('magic', c_uint),
              ('flag2', c_uint),
              ('padding', c_ubyte * 224)]

  def __repr__(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    varkey = 'version'
    d[varkey] = "{:d}.{:d}".format((d[varkey]>>16)&65535, (d[varkey])&65535)
    varkey = 'build_date'
    d[varkey] = "{:02d}.{:02d}.{:d}".format((d[varkey]>>24)&255, (d[varkey]>>16)&255, (d[varkey])&65535)
    varkey = 'crc32'
    d[varkey] = "{:08X}".format(d[varkey])
    varkey = 'padding'
    d[varkey] = "".join("{:02x}".format(x) for x in d[varkey])
    from pprint import pformat
    return pformat(d, indent=4, width=64)

def amba_extract_part_head(po, e, i):
  fwpartfile = open("{:s}_part{:02d}.a9h".format(po.ptprefix,i), "w")
  fwpartfile.write("# Ambarella Firmware Packer section header file. Loosly based on AFT format.\n")
  fwpartfile.write(strftime("# Generated on %Y-%m-%d %H:%M:%S\n", gmtime()))
  fwpartfile.write("crc32={:08X}\n".format(e.crc32))
  fwpartfile.write("majorversion={:d}\n".format((e.version>>16)&65535))
  fwpartfile.write("minorversion={:d}\n".format((e.version)&65535))
  fwpartfile.write("build_date={:04d}.{:02d}.{:02d}\n".format((e.build_date>>16)&65535, (e.build_date>>8)&255, (e.build_date)&255))
  fwpartfile.write("len={:d}\n".format(e.dt_len))
  fwpartfile.write("loadaddress={:08X}\n".format(e.dt_mem))
  fwpartfile.write("flag={:08X}\n".format(e.flag1))
  fwpartfile.write("flag2={:08X}\n".format(e.flag2))
  fwpartfile.write("sectionmagic={:08X}\n".format(e.magic))
  #fwpartfile.write("padding={:s}\n".format("".join("{:02x}".format(x) for x in e.padding)))
  fwpartfile.close()

def amba_extract(po, fwmdlfile):
  modhead = FwModA9Header()
  if fwmdlfile.readinto(modhead) != sizeof(modhead):
      raise EOFError("Couldn't read firmware package file header.")
  if (po.verbose > 1):
      print("{}: Header:".format(po.fwmdlfile))
      print(modhead)
  fwpartfile = open("{:s}_header.a9s".format(po.ptprefix), "wb")
  fwpartfile.write(modhead)
  fwpartfile.close()
  i = 0
  while True:
    epos = fwmdlfile.tell()
    e = FwModEntry()
    n = fwmdlfile.readinto(e)
    if (n is None) or (n == 0):
      # End Of File, correct ending
      break
    if n != sizeof(e):
      raise EOFError("Couldn't read firmware package partition header, got {:d} out of {:d}.".format(n,sizeof(e)))
    if (po.verbose > 1):
      print("{}: Entry {}".format(po.fwmdlfile,i))
      print(e)
    if (e.dt_len < 16) or (e.dt_len > 128*1024*1024):
      eprint("{}: Warning: entry at {:d} has bad size, {:d} bytes".format(po.fwmdlfile,epos,e.dt_len))
    print("{}: Extracting entry {:2d}, pos {:8d}, len {:8d} bytes".format(po.fwmdlfile,i,epos,e.dt_len))
    amba_extract_part_head(po, e, i)
    fwpartfile = open("{:s}_part{:02d}.a9s".format(po.ptprefix,i), "wb")
    n = 0
    while n < e.dt_len:
      copy_buffer = fwmdlfile.read(min(1024 * 1024, e.dt_len - n))
      if not copy_buffer:
          break
      n += len(copy_buffer)
      fwpartfile.write(copy_buffer)
    fwpartfile.close()
    if (n < e.dt_len):
      eprint("{}: Warning: partition {:d} truncated, {:d} out of {:d} bytes".format(po.fwmdlfile,i,n,e.dt_len))
    i += 1
    #TODO: verify checksum
    #if (chksum.hexdigest() != e.hex_md5()):
    #    eprint("{}: Warning: Entry {:d} checksum mismatch; got {:s}, expected {:s}.".format(po.fwmdlfile,i,chksum.hexdigest(),e.hex_md5()))
    #if (po.verbose > 1):
    #    print("{}: Entry {:d} checksum {:s}".format(po.fwmdlfile,i,chksum.hexdigest()))

def amba_search_extract(po, fwmdlfile):
  fwmdlmm = mmap.mmap(fwmdlfile.fileno(), length=0, access=mmap.ACCESS_READ)
  epos = -sizeof(FwModEntry)
  prev_dtlen = 0
  prev_dtpos = 0
  i = 0
  while True:
    epos = fwmdlmm.find(b'\x90\xEB\x24\xA3', epos+sizeof(FwModEntry))
    if (epos < 0):
      break
    epos -= 24 # pos of 'magic' within FwModEntry
    if (epos < 0):
      continue
    dtpos = epos+sizeof(FwModEntry)
    e = FwModEntry.from_buffer_copy(fwmdlmm[epos:dtpos]);
    if (e.dt_len < 16) or (e.dt_len > 128*1024*1024) or (e.dt_len > fwmdlmm.size()-dtpos):
      print("{}: False positive - entry at {:d} has bad size, {:d} bytes".format(po.fwmdlfile,epos,e.dt_len))
      continue
    print("{}: Extracting entry {:2d}, pos {:8d}, len {:8d} bytes".format(po.fwmdlfile,i,epos,e.dt_len))
    if (prev_dtpos+prev_dtlen > epos):
      eprint("{}: Partition {:d} overlaps with previous by {:d} bytes".format(po.fwmdlfile,i,prev_dtpos+prev_dtlen - epos))
    amba_extract_part_head(po, e, i)
    fwpartfile = open("{:s}_part{:02d}.a9s".format(po.ptprefix,i), "wb")
    fwpartfile.write(fwmdlmm[epos+sizeof(FwModEntry):epos+sizeof(FwModEntry)+e.dt_len])
    fwpartfile.close()
    prev_dtlen = e.dt_len
    prev_dtpos = dtpos
    i += 1
  #TODO: verify checksum


def amba_create(po, fwmdlfile):
  raise NotImplementedError('NOT IMPLEMENTED')

def main(argv):
  # Parse command line options
  po = ProgOptions()
  try:
     opts, args = getopt.getopt(argv,"hxsavt:m:",["help","version","extract","search","add","fwmdl=","ptprefix="])
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
        print("  -v - increases verbosity level; max level is set by -vvv")
        sys.exit()
     elif opt == "--version":
        print("amba_fwpak.py version 0.1.0")
        sys.exit()
     elif opt == '-v':
        po.verbose += 1
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
