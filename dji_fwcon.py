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

class DjiModuleTarget():
    "Stores identification info on module for specific target"
    def __init__(self, kind, model, name, desc):
        self.kind = kind
        self.model = model
        self.name = name
        self.desc = desc

dji_targets = [
    DjiModuleTarget( 1,-1, "CAM",     "camera"),
    DjiModuleTarget( 1, 0, "FC300X",  "camera 'Ambarella A9SE' App"),
    DjiModuleTarget( 1, 1, "CAMLDR",  "camera 'Ambarella A9SE' Ldr"),
    DjiModuleTarget( 1, 2, "CAMBST",  "camera BST"),
    DjiModuleTarget( 1, 4, "CAMBCPU", "camera BCPU"),
    DjiModuleTarget( 1, 5, "CAMLCPU", "camera LCPU"),
    DjiModuleTarget( 1, 6, "ZQ7020",  "camera 'Xilinx Zynq 7020'"),
    DjiModuleTarget( 3,-1, "MC",      "main controller"),
    DjiModuleTarget( 3, 5, "MCLDR",   "main controller 'A3' ldr"),
    DjiModuleTarget( 3, 6, "MCAPP",   "main controller 'A3' app"),
    DjiModuleTarget( 4,-1, "GIMBAL",  "gimbal"),
    DjiModuleTarget( 4, 0, "GIMBAL0", "gimbal mdl 0"),
    DjiModuleTarget( 5,-1, "CENTER",  "central board"),
    DjiModuleTarget( 5, 0, "CENTER0", "central board mdl 0"),
    DjiModuleTarget( 7,-1, "WIFI",    "Wi-Fi"),
    DjiModuleTarget( 7, 0, "WIFI0",   "Wi-Fi mdl 0"),
    DjiModuleTarget( 8,-1, "VENC",    "video encoder"),
    DjiModuleTarget( 8, 0, "DM368",   "video encoder 'DaVinci Dm368 Linux'"),
    DjiModuleTarget( 8, 1, "IG810LB2","video encoder 'IG810 LB2_ENC'"),
    DjiModuleTarget( 9,-1, "MCA",     "MCU in air"),
    DjiModuleTarget( 9, 0, "MCA1765", "MCU 'NXP LPC1765'"),
    DjiModuleTarget(10,-1, "BATTFW",  "battery firmware"),
    DjiModuleTarget(11,-1, "BATTCT",  "battery controller"),
    DjiModuleTarget(11, 0, "BATTERY", "battery controller 1 app"),
    DjiModuleTarget(11, 1, "BATTERY2","battery controller 2 app"),
    DjiModuleTarget(12,-1, "ESC",     "electronic speed control"),
    DjiModuleTarget(12, 0, "ESC0",    "electronic speed control 0"),
    DjiModuleTarget(12, 1, "ESC1",    "electronic speed control 1"),
    DjiModuleTarget(12, 2, "ESC2",    "electronic speed control 2"),
    DjiModuleTarget(12, 3, "ESC3",    "electronic speed control 3"),
    DjiModuleTarget(13, 0, "VDEC",    "video decoder"),
    DjiModuleTarget(13, 0, "DM365M0", "video decoder 'DaVinci Dm365 Linux' mdl 0"),
    DjiModuleTarget(13, 1, "DM365M1", "video decoder 'DaVinci Dm365 Linux' mdl 1"),
    DjiModuleTarget(14,-1, "MCG",     "MCU on ground"),
    DjiModuleTarget(14, 0, "MCG1765A","MCU 'LPC1765 GROUND LB2'"),
    DjiModuleTarget(15,-1, "TX",      "radio transmitter"),
    DjiModuleTarget(15, 0, "TX68013", "radio transmitter 'IG810 LB2_68013_TX'"),
    DjiModuleTarget(16,-1, "RXG",     "radio receiver"),
    DjiModuleTarget(16, 0, "RX68013", "radio receiver 'IG810 LB2_68013_RX ground'"),
    DjiModuleTarget(17,-1, "MVOM",    "visual positioning"),
    DjiModuleTarget(17, 0, "MVOMC4",  "visual positioning module 'camera'"),
    DjiModuleTarget(17, 1, "MVOMS0",  "visual positioning module 'sonar'"),
    DjiModuleTarget(19,-1, "FPGAA",   "FPGA air"),
    DjiModuleTarget(19, 0, "FPGAA0",  "FPGA air model 0"),
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
    module_info = next((mi for mi in dji_targets if mi.kind == tg_kind and mi.model == tg_model), None)
    if (module_info is not None):
        return module_info.desc
    # If not found, try getting category
    module_info = next((mi for mi in dji_targets if mi.kind == tg_kind and mi.model == -1), None)
    if (module_info is not None):
        return "{:s} model {:02d}".format(module_info.desc,tg_model)
    # If category also not found, return as unknown device
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
      chksum = hashlib.md5()
      n = 0
      while True:
        copy_buffer = fwitmfile.read(1024 * 1024)
        if not copy_buffer:
            break
        n += len(copy_buffer)
        fwpkgfile.write(copy_buffer)
        chksum.update(copy_buffer);
      fwitmfile.close()
      hde.dt_offs = epos
      hde.dt_length = fwpkgfile.tell() - epos
      hde.dt_alloclen = hde.dt_length
      hde.dt_md5 = (c_ubyte * 16).from_buffer_copy(chksum.digest())
      #TODO
      hde.dt_2ndhash = (c_ubyte * 16).from_buffer_copy(chksum.digest())
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
        print("dji_fwcon.py version 0.2.0")
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
