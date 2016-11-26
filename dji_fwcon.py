#!/usr/bin/env python

from __future__ import print_function
import sys
import getopt
import re
import os
import hashlib
import configparser
import itertools
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
  _fields_ = [('magic', c_uint),
              ('magic_ver', c_ushort),
              ('hdrend_offs', c_ushort),
              ('salt', c_int),
              ('manufacturer', c_char * 16),
              ('model', c_char * 16),
              ('entry_count', c_ushort),
              ('ver_latest_enc', c_int),
              ('ver_rollbk_enc', c_int),
              ('padding', c_ubyte * 10)]

  def set_ver_latest(self, ver):
    self.ver_latest_enc = 0x5127A564 ^ ver ^ self.salt;

  def set_ver_rollbk(self, ver):
    self.ver_rollbk_enc = 0x5127A564 ^ ver ^ self.salt;

  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    varkey = 'ver_latest'
    d[varkey] = d['salt'] ^ d[varkey+"_enc"]  ^ 0x5127A564;
    varkey = 'ver_rollbk'
    d[varkey] = d['salt'] ^ d[varkey+"_enc"]  ^ 0x5127A564;
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
    varkey = 'salt'
    fp.write("{:s}={:08X}\n".format(varkey,d[varkey]))
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
    d[varkey] = "{:02d}.{:02d}.{:04d}".format((d[varkey]>>24)&255, (d[varkey]>>16)&255, (d[varkey])&65535)
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
    fp.write("# DJI Firmware Container module header file.\n")
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

  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)


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
  pkghead.salt = int(parser.get("asection", "salt"),16)
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
  hde.spcoding = int(parser.get("asection", "spcoding"),16)
  hde.reserved2 = int(parser.get("asection", "reserved2"),16)
  del parser
  return (hde)

def dji_extract(po, fwpkgfile):
  pkghead = FwPkgHeader()
  if fwpkgfile.readinto(pkghead) != sizeof(pkghead):
      raise EOFError("Couldn't read firmware package file header.")
  if pkghead.magic != 0x12345678 or pkghead.magic_ver != 0x0001:
      eprint("{}: Warning: Unexpected magic value in main header; will try to extract anyway.".format(po.fwpkgfile))
  if (pkghead.ver_latest_enc == 0 and pkghead.ver_rollbk_enc == 0):
      eprint("{}: Warning: Unversioned firmware package identified; this format is not fully supported.".format(po.fwpkgfile))
      # In this format, versions should be set from file name, and CRC16 of the header should be equal to values hard-coded in updater
  if (po.verbose > 1):
      print("{}: Header:".format(po.fwpkgfile))
      print(pkghead)

  pkgmodules = []
  for i in range(pkghead.entry_count):
      hde = FwPkgEntry()
      if fwpkgfile.readinto(hde) != sizeof(hde):
          raise EOFError("Couldn't read firmware package file entry.")
      if (po.verbose > 1):
          print("{}: Module index {}".format(po.fwpkgfile,i))
          print(hde)
      if hde.dt_length != hde.dt_alloclen:
          eprint("{}: Warning: module size mismatch, {:d} instead of {:d}.".format(po.fwpkgfile,hde.dt_length,hde.dt_alloclen))
      pkgmodules.append(hde)

  pkghead_checksum = c_ushort()
  if fwpkgfile.readinto(pkghead_checksum) != sizeof(pkghead_checksum):
      raise EOFError("Couldn't read firmware package file header checksum.")

  if (po.verbose > 1):
      print("{}: Headers checksum {:04X}".format(po.fwpkgfile,pkghead_checksum.value))

  if fwpkgfile.tell() != pkghead.hdrend_offs:
      eprint("{}: Warning: Header end offset does not match; should end at {}, ends at {}.".format(po.fwpkgfile,pkghead.hdrend_offs,fwpkgfile.tell()))

  minames = ["0"]*len(pkgmodules)
  for i, hde in enumerate(pkgmodules):
      if hde.dt_length > 0:
          minames[i] = "mi{:02d}".format(i)

  dji_write_fwpkg_head(po, pkghead, minames)

  for i, hde in enumerate(pkgmodules):
      if minames[i] == "0":
          if (po.verbose > 0):
              print("{}: Skipping module index {}, {} bytes".format(po.fwpkgfile,i,hde.dt_length))
          continue
      if (po.verbose > 0):
          print("{}: Extracting module index {}, {} bytes".format(po.fwpkgfile,i,hde.dt_length))
      chksum = hashlib.md5()
      dji_write_fwentry_head(po, i, hde, minames[i])
      fwitmfile = open("{:s}_{:s}.bin".format(po.dcprefix,minames[i]), "wb")
      fwpkgfile.seek(hde.dt_offs)
      n = 0
      while n < hde.dt_length:
          copy_buffer = fwpkgfile.read(min(1024 * 1024, hde.dt_length - n))
          if not copy_buffer:
              break
          n += len(copy_buffer)
          fwitmfile.write(copy_buffer)
          chksum.update(copy_buffer);
      fwitmfile.close()
      if (chksum.hexdigest() != hde.hex_md5()):
          eprint("{}: Warning: Module index {:d} checksum mismatch; got {:s}, expected {:s}.".format(po.fwpkgfile,i,chksum.hexdigest(),hde.hex_md5()))
      if (po.verbose > 1):
          print("{}: Module index {:d} checksum {:s}".format(po.fwpkgfile,i,chksum.hexdigest()))


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
      epos = fwpkgfile.tell()
      # Copy partition data and compute CRC
      fwitmfile = open(fname, "rb")
      ptcrc = 0
      n = 0
      while True:
        copy_buffer = fwitmfile.read(1024 * 1024)
        if not copy_buffer:
            break
        n += len(copy_buffer)
        fwpkgfile.write(copy_buffer)
      fwitmfile.close()
      hde.dt_offs = epos
      hde.dt_length = fwpkgfile.tell() - epos
      hde.dt_alloclen = hde.dt_length
      # TODO
      #hde.dt_md5
      #hde.dt_2ndhash
      eprint("{}: Warning: Checksums not implemented, output file impaired.".format(po.fwpkgfile))
      pkgmodules[i] = hde
  # Write all headers again
  fwpkgfile.seek(0,os.SEEK_SET)
  fwpkgfile.write((c_ubyte * sizeof(pkghead)).from_buffer_copy(pkghead))
  for hde in pkgmodules:
    fwpkgfile.write((c_ubyte * sizeof(hde)).from_buffer_copy(hde))
  fwpkgfile.write((c_ubyte * sizeof(c_ushort))())

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
