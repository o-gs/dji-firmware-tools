#!/usr/bin/env python

from __future__ import print_function
import sys
import getopt
import os
import hashlib
from ctypes import *
from time import gmtime, strftime

def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

class ProgOptions:
  fwpkgfile = ''
  dcprefix = ''
  verbose = 0
  command = ''

class FwPkgHeader(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('magic', c_char * 6),
              ('hdrend_offs', c_ushort),
              ('reserved8', c_ushort),
              ('version', c_ushort),
              ('manufacturer', c_char * 16),
              ('model', c_char * 16),
              ('entry_count', c_ushort),
              ('reserved2E', c_int),
              ('reserved32', c_int),
              ('padding', c_ubyte * 10)]

  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    varkey = 'version'
    d[varkey] = "{:d}".format(d[varkey])
    varkey = 'padding'
    d[varkey] = "".join("{:02X}".format(x) for x in d[varkey])
    return d

  def ini_export(self, fp):
    d = self.dict_export()
    fp.write("# DJI Firmware Container main header file.\n")
    fp.write(strftime("# Generated on %Y-%m-%d %H:%M:%S\n", gmtime()))
    varkey = 'hdrend_offs'
    fp.write("{:s}={:04X}\n".format(varkey,d[varkey]))
    varkey = 'reserved8'
    fp.write("{:s}={:04X}\n".format(varkey,d[varkey]))
    varkey = 'version'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
    varkey = 'padding'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
    #TODO

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
              ('dt_length', c_uint),
              ('dt_alloclen', c_uint),
              ('dt_md5', c_ubyte * 16),
              ('dt_2ndhash', c_ubyte * 16)]

  def target_name(self):
    tg_kind = getattr(self, 'target') & 31
    tg_model = (getattr(self, 'target') >> 5) & 7
    if   (tg_kind == 1):
      if (tg_model == 0):
        return "camera '{:s}'".format("Ambarella A9SE mdl 00")
      elif (tg_model == 1):
        return "camera '{:s}'".format("Ambarella A9SE mdl 01")
      elif (tg_model == 6):
        return "camera '{:s}'".format("Xilinx Zynq 7020")
      else:
        return "camera model {:02d}".format(tg_model)
    elif (tg_kind == 3):
      if ((tg_model%2) > 0):
        return "main controller mdl {:02d} ldr".format(tg_model)
      else:
        return "main controller mdl {:02d} app".format(tg_model-1)
    elif (tg_kind == 4):
        return "gimbal model {:02d}".format(tg_model)
    elif (tg_kind == 5):
        return "central board model {:02d}".format(tg_model)
    elif (tg_kind == 8):
      if (tg_model == 0):
        return "video encoder '{:s}'".format("DaVinci Dm365 Linux")
      elif (tg_model == 1):
        return "video encoder '{:s}'".format("IG810 LB2_ENC")
      else:
        return "video encoder {:02d}".format(tg_model)
    elif (tg_kind == 9):
      if (tg_model == 0):
        return "MCU '{:s}'".format("NXP LPC1765")
      else:
        return "MCU model {:02d}".format(tg_model)
    elif (tg_kind == 11):
        return "battery controller {:02d} app".format(tg_model)
    elif (tg_kind == 10):
        return "battery {:02d} fw".format(tg_model)
    elif (tg_kind == 12):
        return "electronic speed control {:02d}".format(tg_model)
    elif (tg_kind == 13):
      if (tg_model == 0):
        return "video decoder '{:s}'".format("DaVinci Dm365 Linux")
      elif (tg_model == 1):
        return "video decoder '{:s}'".format("DaVinci Dm385 Linux")
      else:
        return "video decoder {:02d}".format(tg_model)
    elif (tg_kind == 14):
      if (tg_model == 0):
        return "device kind {:02d} '{:s}'".format(tg_kind,"LPC1765 GROUND LB2")
      else:
        return "device kind {:02d} model {:02d}".format(tg_kind,tg_model)
    elif (tg_kind == 15):
      if (tg_model == 1):
        return "radio transmitter '{:s}'".format("IG810 LB2_68013_TX")
      else:
        return "radio transmitter model {:02d}".format(tg_model)
    elif (tg_kind == 16):
      if (tg_model == 1):
        return "radio receiver '{:s}'".format("IG810 LB2_68013_RX ground")
      else:
        return "radio receiver model {:02d}".format(tg_model)
    elif (tg_kind == 17):
      if (tg_model == 0):
        return "vps component '{:s}'".format("camera")
      elif (tg_model == 1):
        return "vps component '{:s}'".format("sonar")
      else:
        return "vps component model {:02d}".format(tg_model)
    elif (tg_kind == 19):
      return "FPGA air model {:02d}".format(tg_model)
    elif (tg_kind == 20):
      if (tg_model == 3):
        return "FPGA ground '{:s}'".format("LB2")
      else:
        return "FPGA ground model {:02d}".format(tg_model)
    elif (tg_kind == 25):
      return "IMU model {:02d}".format(tg_model)
    elif (tg_kind == 29):
      if ((tg_model%2) > 0):
        return "PMU model {:02d} ldr".format(tg_model)
      else:
        return "PMU model {:02d} app".format(tg_model-1)
    else:
      return "device kind {:02} model {:02}".format(tg_kind,tg_model)

  def hex_md5(self):
    varkey = 'dt_md5'
    return "".join("{:02x}".format(x) for x in getattr(self, varkey))

  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    varkey = 'version'
    d[varkey] = "{:02d}.{:02d}.{:d}".format((d[varkey]>>24)&255, (d[varkey]>>16)&255, (d[varkey])&65535)
    varkey = 'dt_md5'
    d[varkey] = "".join("{:02x}".format(x) for x in d[varkey])
    varkey = 'dt_2ndhash'
    d[varkey] = "".join("{:02x}".format(x) for x in d[varkey])
    varkey = 'target'
    d[varkey] = "m{:02d}{:02d}".format(d[varkey]&31, (d[varkey]>>5)&7)
    varkey = 'target_name'
    d[varkey] = self.target_name()
    return d

  def ini_export(self, fp):
    d = self.dict_export()
    fp.write("# DJI Firmware Container entry header file.\n")
    fp.write("# Stores firmware for {:s}\n".format(d['target_name']))
    fp.write(strftime("# Generated on %Y-%m-%d %H:%M:%S\n", gmtime()))
    varkey = 'target'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
    varkey = 'version'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
    varkey = 'spcoding'
    fp.write("{:s}={:02X}\n".format(varkey,d[varkey]))
    varkey = 'reserved2'
    fp.write("{:s}={:04X}\n".format(varkey,d[varkey]))
    varkey = 'dt_length'
    fp.write("{:s}={:d}\n".format('length',d[varkey]))
    varkey = 'dt_md5'
    fp.write("{:s}={:s}\n".format('md5',d[varkey]))

  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)


def dji_write_fwpkg_head(po, pkghead):
  fwheadfile = open("{:s}_head.ini".format(po.dcprefix), "w")
  pkghead.ini_export(fwheadfile)
  fwheadfile.close()

def dji_write_fwentry_head(po, i, e):
  fwheadfile = open("{:s}_{:02d}.ini".format(po.dcprefix,i), "w")
  e.ini_export(fwheadfile)
  fwheadfile.close()


def dji_extract(po, fwpkgfile):
  pkghead = FwPkgHeader()
  if fwpkgfile.readinto(pkghead) != sizeof(pkghead):
      raise EOFError("Couldn't read firmware package file header.")
  if (po.verbose > 1):
      print("{}: Header:".format(po.fwpkgfile))
      print(pkghead)

  pkgentries = []
  for i in range(pkghead.entry_count):
      e = FwPkgEntry()
      if fwpkgfile.readinto(e) != sizeof(e):
          raise EOFError("Couldn't read firmware package file entry.")
      if (po.verbose > 1):
          print("{}: Entry {}".format(po.fwpkgfile,i))
          print(e)
      if e.dt_length != e.dt_alloclen:
          eprint("{}: Warning: Entry size mismatch, {:d} instead of {:d}.".format(po.fwpkgfile,e.dt_length,e.dt_alloclen))
      pkgentries.append(e)

  pkghead_checksum = c_ushort()
  if fwpkgfile.readinto(pkghead_checksum) != sizeof(pkghead_checksum):
      raise EOFError("Couldn't read firmware package file header checksum.")

  if (po.verbose > 1):
      print("{}: Headers checksum {:04X}".format(po.fwpkgfile,pkghead_checksum.value))

  if fwpkgfile.tell() != pkghead.hdrend_offs:
      eprint("{}: Warning: Header end offset does not match; should end at {}, ends at {}.".format(po.fwpkgfile,pkghead.hdrend_offs,fwpkgfile.tell()))

  dji_write_fwpkg_head(po, pkghead)

  for i, e in enumerate(pkgentries):
      if (po.verbose > 0):
          print("{}: Extracting entry {}, {} bytes".format(po.fwpkgfile,i,e.dt_length))
      chksum = hashlib.md5()
      dji_write_fwentry_head(po, i, e)
      fwitmfile = open("{:s}_{:02d}.bin".format(po.dcprefix,i), "wb")
      fwpkgfile.seek(e.dt_offs)
      n = 0
      while n < e.dt_length:
          copy_buffer = fwpkgfile.read(min(1024 * 1024, e.dt_length - n))
          if not copy_buffer:
              break
          n += len(copy_buffer)
          fwitmfile.write(copy_buffer)
          chksum.update(copy_buffer);
      fwitmfile.close()
      if (chksum.hexdigest() != e.hex_md5()):
          eprint("{}: Warning: Entry {:d} checksum mismatch; got {:s}, expected {:s}.".format(po.fwpkgfile,i,chksum.hexdigest(),e.hex_md5()))
      if (po.verbose > 1):
          print("{}: Entry {:d} checksum {:s}".format(po.fwpkgfile,i,chksum.hexdigest()))


def dji_create(po, fwpkgfile):
  pkghead = FwPkgHeader()
  raise NotImplementedError('NOT IMPLEMENTED')

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
        print("  -x - extract firmware package into modules")
        print("  -a - add module files to firmware package")
        print("  -v - increases verbosity level; max level is set by -vvv")
        sys.exit()
     elif opt == "--version":
        print("dji_fwcon.py version 0.1.1")
        sys.exit()
     elif opt == '-v':
        po.verbose += 1
     elif opt in ("-p", "--fwpkg"):
        po.fwpkgfile = arg
     elif opt in ("-m", "--mdprefix"):
        po.dcprefix = arg
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
