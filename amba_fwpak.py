#!/usr/bin/env python

from __future__ import print_function
import sys
import getopt
import os
import hashlib
import mmap
import zlib
from ctypes import *
from time import gmtime, strftime

def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

class ProgOptions:
  fwmdlfile = ''
  ptprefix = ''
  verbose = 0
  command = ''

part_entry_type_id = ["pri", "dsp", "rfs", "sec", "lnx"]
part_entry_type_name = ["System Software", "DSP uCode", "System ROM Data", "Linux Kernel", "Linux Root FS"]

# The Ambarella firmware file consists of 3 elements:
# 1. Main header, containing array of partitions
# 2. Partition header, before each partition
# 3. Partition data, for each partition
#
# The Main header is made of:
# - model_name - text description of the device model
# - ver_info - version info, set to 0 in DJI camera FW
# - crc32 - sum of checksums of all modules (?)
# - fw module entries - array of FwModEntry, with amount of entries hard-coded
#   for specific component
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
    varkey = 'crc32'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey]))

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

  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    varkey = 'mem_addr'
    d[varkey] = "{:08X}".format(d[varkey])
    varkey = 'version'
    d[varkey] = "{:d}.{:d}".format((d[varkey]>>16)&65535, (d[varkey])&65535)
    varkey = 'build_date'
    d[varkey] = "{:d}-{:02d}-{:02d}".format((d[varkey]>>16)&65535, (d[varkey]>>8)&255, (d[varkey])&255)
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

  def ini_export(self, fp):
    d = self.dict_export()
    fp.write("# Ambarella Firmware Packer section header file. Loosly based on AFT format.\n")
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
    varkey = 'crc32'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey]))

  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)

def amba_calculate_crc32_part(buf, pcrc):
  return zlib.crc32(buf, pcrc) & 0xffffffff

def amba_calculate_crc32(buf):
  return amba_calculate_crc32_part(buf, 0)

def amba_extract_part_head(po, e, ptyp):
  fwpartfile = open("{:s}_part_{:s}.a9h".format(po.ptprefix,ptyp), "w")
  e.ini_export(fwpartfile)
  fwpartfile.close()

def amba_extract_mod_head(po, modhead, modposthd):
  fwpartfile = open("{:s}_header.a9h".format(po.ptprefix), "w")
  modhead.ini_export(fwpartfile)
  modposthd.ini_export(fwpartfile)
  fwpartfile.close()

def amba_extract(po, fwmdlfile):
  modhead = FwModA9Header()
  if fwmdlfile.readinto(modhead) != sizeof(modhead):
      raise EOFError("Couldn't read firmware package file header.")
  if (po.verbose > 1):
      print("{}: Header:".format(po.fwmdlfile))
      print(modhead)
  i = 0
  modentries = []
  while (True):
    hde = FwModEntry()
    if fwmdlfile.readinto(hde) != sizeof(hde):
      raise EOFError("Couldn't read firmware package file header entries.")
    # If both values are multiplications of 1024, then assume we're past end
    if ((hde.dt_len & 0x3ff) == 0) and ((hde.crc32 & 0x3ff) == 0):
      fwmdlfile.seek(-sizeof(hde),1)
      break
    modentries.append(hde)
    i += 1
    if (i > 128):
      raise EOFError("Couldn't find header entries end marking.")
  if (po.verbose > 1):
      print("{}: Entries:".format(po.fwmdlfile))
      print(modentries)

  modposthd = FwModA9PostHeader()
  if fwmdlfile.readinto(modposthd) != sizeof(modposthd):
      raise EOFError("Couldn't read firmware package file header.")
  if (po.verbose > 1):
      print("{}: Post Header:".format(po.fwmdlfile))
      print(modposthd)
  amba_extract_mod_head(po, modhead, modposthd)
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
    if (po.verbose > 1):
      print("{}: Entry {}".format(po.fwmdlfile,i))
      print(e)
    hdcrc = amba_calculate_crc32_part((c_ubyte * sizeof(e)).from_buffer_copy(e), 0)
    if (e.dt_len < 16) or (e.dt_len > 128*1024*1024):
      eprint("{}: Warning: entry at {:d} has bad size, {:d} bytes".format(po.fwmdlfile,epos,e.dt_len))
    # Warn if no more module entries were expected
    if (i >= len(modentries)):
      eprint("{}: Warning: Data continues after parsing all {:d} known partitions; header inconsistent.".format(po.fwmdlfile,i))
    print("{}: Extracting entry {:2d}, pos {:8d}, len {:8d} bytes".format(po.fwmdlfile,i,epos,e.dt_len))
    if (i < len(part_entry_type_id)):
      ptyp = part_entry_type_id[i]
    else:
      ptyp = "{:02d}".format(i)
    amba_extract_part_head(po, e, ptyp)
    fwpartfile = open("{:s}_part_{:s}.a9s".format(po.ptprefix,ptyp), "wb")
    ptcrc = 0
    n = 0
    while n < e.dt_len:
      copy_buffer = fwmdlfile.read(min(1024 * 1024, e.dt_len - n))
      if not copy_buffer:
          break
      n += len(copy_buffer)
      fwpartfile.write(copy_buffer)
      ptcrc = amba_calculate_crc32_part(copy_buffer, ptcrc)
      #hdcrc = amba_calculate_crc32_part(copy_buffer, hdcrc)
    fwpartfile.close()
    if (n < e.dt_len):
      eprint("{}: Warning: partition {:d} truncated, {:d} out of {:d} bytes".format(po.fwmdlfile,i,n,e.dt_len))
    if (ptcrc != e.crc32):
        eprint("{}: Warning: Entry {:d} data checksum mismatch; got {:08X}, expected {:08X}.".format(po.fwmdlfile,i,ptcrc,e.crc32))
    #if (hdcrc != hde.crc32): #TODO: fix and add partition header CRC verification
    #  eprint("{}: Warning: Entry {:d} XXX???XXX checksum mismatch; got {:08X}, expected {:08X}.".format(po.fwmdlfile,i,hdcrc,hde.crc32))
    if (po.verbose > 1):
        print("{}: Entry {:2d} checksum {:08X}".format(po.fwmdlfile,i,ptcrc))

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
    amba_extract_part_head(po, e, ptyp)
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
        print("       (works only on data created with -x; the -s is insufficient)")
        print("  -v - increases verbosity level; max level is set by -vvv")
        sys.exit()
     elif opt == "--version":
        print("amba_fwpak.py version 0.1.1")
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
