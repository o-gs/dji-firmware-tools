#!/usr/bin/env python3

from __future__ import print_function
import sys
import getopt
import re
import os
import math
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
  mdlfile = ''
  inffile="flyc_param_infos"
  address_base=0x8020000
  address_bss=0x20000000
  sizeof_bss=0x4400000
  expect_func_align = 4
  expect_data_align = 2
  verbose = 0
  command = ''
  param_pos = -1
  param_count = 0

class Limits:
  byte_min  = - (2 ** 7)
  byte_max  = (2 ** 7) - 1
  ubyte_min = 0
  ubyte_max = (2 ** 8) - 1
  short_min  = - (2 ** 15)
  short_max  = (2 ** 15) - 1
  ushort_min = 0
  ushort_max = (2 ** 16) - 1
  int_min  = - (2 ** 31)
  int_max  = (2 ** 31) - 1
  uint_min = 0
  uint_max = (2 ** 32) - 1
  longlong_min  = - (2 ** 63)
  longlong_max  = (2 ** 63) - 1
  ulonglong_min = 0
  ulonglong_max = (2 ** 64) - 1

class ParamType:
  unknown0 = 0x0
  unknown1 = 0x1
  uint = 0x2
  unknown3 = 0x3
  unknown4 = 0x4
  unknown5 = 0x5
  int = 0x6
  unknown7 = 0x7
  unknown8 = 0x8
  unknown9 = 0x9
  array = 0xa

class FlycExportLimitF(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('min', c_float),
              ('max', c_float),
              ('deflt', c_float)]

class FlycExportLimitI(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('min', c_int),
              ('max', c_int),
              ('deflt', c_int)]

class FlycExportLimitU(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('min', c_uint),
              ('max', c_uint),
              ('deflt', c_uint)]

class FlycExportParam(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('nameptr', c_uint), # Pointer to the name string of this parameter
              ('valptr', c_uint), # Pointer to where current value of the parameter is
              ('valsize', c_uint),
              ('type_id', c_uint),
              ('limit_f', FlycExportLimitF),
              ('limit_i', FlycExportLimitI),
              ('limit_u', FlycExportLimitU),
              ('attribute', c_uint),
              ('callback', c_uint)]

  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    varkey = 'limit_f'
    d[varkey] = "{0:.3f} {1:.3f} {2:.3f}".format(d[varkey].min,d[varkey].max,d[varkey].deflt)
    varkey = 'limit_i'
    d[varkey] = "{0:d} {1:d} {2:d}".format(d[varkey].min,d[varkey].max,d[varkey].deflt)
    varkey = 'limit_u'
    d[varkey] = "{0:d} {1:d} {2:d}".format(d[varkey].min,d[varkey].max,d[varkey].deflt)
    return d

  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)

def flyc_is_proper_parameter_entry(po, fwmdlfile, fwmdlfile_len, eexpar, func_align, data_align, pos, entry_pos):
  """ Checks whether given FlycExportParam object stores a proper entry of
      flight controller parameters array.
  """
  # Address to const string
  if (eexpar.nameptr < po.address_base) or (eexpar.nameptr >= po.address_base+fwmdlfile_len):
     return False
  # Address to uninitialized variable
  if (eexpar.valptr < po.address_bss) or (eexpar.valptr >= po.address_bss+po.sizeof_bss):
     if (eexpar.valptr != 0): # Value pointer can be NULL
        return False
  # Size and type
  if (eexpar.type_id == ParamType.unknown1):
     if (eexpar.valsize != 1) and (eexpar.valsize != 2) and (eexpar.valsize != 4) and (eexpar.valsize != 8):
        return False
  elif (eexpar.type_id == ParamType.uint):
     if (eexpar.valsize != 1) and (eexpar.valsize != 2) and (eexpar.valsize != 4) and (eexpar.valsize != 8):
        return False
  elif (eexpar.type_id <= ParamType.unknown9):
     if (eexpar.valsize != 1) and (eexpar.valsize != 2) and (eexpar.valsize != 4) and (eexpar.valsize != 8):
        return False
  elif (eexpar.type_id == ParamType.array): # array needs to have multiple elements
     if (eexpar.valsize < 2):
        return False
  else:
     return False
  # Limits
  if math.isnan(eexpar.limit_f.min) or math.isnan(eexpar.limit_f.max) or math.isnan(eexpar.limit_f.deflt):
     return False
  if (eexpar.type_id == ParamType.uint):
     # Min unsigned
     if (eexpar.limit_f.min < Limits.uint_min):
        limit_ftoi = Limits.uint_min
     elif (eexpar.limit_f.min > Limits.uint_max):
        limit_ftoi = Limits.uint_max
     else:
        limit_ftoi = int(eexpar.limit_f.min) # DJI does not use round() here
     if (limit_ftoi != eexpar.limit_u.min):
        #print("Rejected on min {:d} {:d} {:f}\n".format(limit_ftoi,eexpar.limit_u.min,eexpar.limit_f.min))
        return False
     # Max unsigned
     if (eexpar.limit_f.max < Limits.uint_min):
        limit_ftoi = Limits.uint_min
     elif (eexpar.limit_f.max > Limits.uint_max):
        limit_ftoi = Limits.uint_max
     else:
        limit_ftoi = int(eexpar.limit_f.max) # DJI does not use round() here
     if (limit_ftoi != eexpar.limit_u.max):
        print("Rejected type {:d} on max {:d} {:d} {:f}\n".format(eexpar.type_id,limit_ftoi,eexpar.limit_u.max,eexpar.limit_f.max))
        return False
     # Default unsigned
     if (eexpar.limit_f.deflt < Limits.uint_min):
        limit_ftoi = Limits.uint_min
     elif (eexpar.limit_f.deflt > Limits.uint_max):
        limit_ftoi = Limits.uint_max
     else:
        limit_ftoi = int(eexpar.limit_f.deflt) # DJI does not use round() here
     if (abs(limit_ftoi - eexpar.limit_u.deflt) > 127):
        print("Rejected type {:d} on max {:d} {:d} {:f}\n".format(eexpar.type_id,limit_ftoi,eexpar.limit_u.deflt,eexpar.limit_f.deflt))
        return False
  else:
     # Min signed
     if (eexpar.limit_f.min < Limits.int_min):
        limit_ftoi = Limits.int_min
     elif (eexpar.limit_f.min > Limits.int_max):
        limit_ftoi = Limits.int_max
     else:
        limit_ftoi = int(eexpar.limit_f.min) # DJI does not use round() here
     if (limit_ftoi != eexpar.limit_i.min):
        #print("Rejected on min {:d} {:d} {:f}\n".format(limit_ftoi,eexpar.limit_i.min,eexpar.limit_f.min))
        return False
     # Max signed
     if (eexpar.limit_f.max < Limits.int_min):
        limit_ftoi = Limits.int_min
     elif (eexpar.limit_f.max > Limits.int_max):
        limit_ftoi = Limits.int_max
     else:
        limit_ftoi = int(eexpar.limit_f.max) # DJI does not use round() here
     if (limit_ftoi != eexpar.limit_i.max):
        print("Rejected type {:d} on max {:d} {:d} {:f}\n".format(eexpar.type_id,limit_ftoi,eexpar.limit_i.max,eexpar.limit_f.max))
        return False
     # Default signed
     if (eexpar.limit_f.deflt < Limits.int_min):
        limit_ftoi = Limits.int_min
     elif (eexpar.limit_f.deflt > Limits.int_max):
        limit_ftoi = Limits.int_max
     else:
        limit_ftoi = int(eexpar.limit_f.deflt) # DJI does not use round() here
     if (abs(limit_ftoi - eexpar.limit_i.deflt) > 127):
        print("Rejected type {:d} on max {:d} {:d} {:f}\n".format(eexpar.type_id,limit_ftoi,eexpar.limit_i.deflt,eexpar.limit_f.deflt))
        return False

  if (1): # limit_u and limit_i are bitwise identical; cast them to compare
     if (c_uint(eexpar.limit_i.min).value != eexpar.limit_u.min):
        return False
     if (c_uint(eexpar.limit_i.max).value != eexpar.limit_u.max):
        return False
     if (c_uint(eexpar.limit_i.deflt).value != eexpar.limit_u.deflt):
        return False
  return True

def flyc_pos_search(po, fwmdlfile, start_pos, func_align, data_align):
  """ Finds position of flight controller parameters in the binary.
  """
  fwmdlfile.seek(0, os.SEEK_END)
  fwmdlfile_len = fwmdlfile.tell()
  eexpar = FlycExportParam()
  match_count = 0
  match_pos = -1
  match_entries = 0
  reached_eof = False
  pos = start_pos
  while (True):
     # Check how many correct parameter entries we have
     entry_count = 0
     entry_pos = pos
     while (True):
        fwmdlfile.seek(entry_pos, os.SEEK_SET)
        if fwmdlfile.readinto(eexpar) != sizeof(eexpar):
           reached_eof = True
           break
        if not flyc_is_proper_parameter_entry(po, fwmdlfile, fwmdlfile_len, eexpar, func_align, data_align, pos, entry_pos):
           break
        entry_count += 1
        entry_pos += sizeof(eexpar)
     # Do not allow entry at EOF
     if (reached_eof):
        break
     # If entry is ok, consider it a match
     if entry_count > 0:
        if (po.verbose > 1):
           print("{}: Matching parameters array at 0x{:08x}: {:d} entries".format(po.mdlfile,pos,entry_count))
        if (entry_count > match_entries):
           match_pos = pos
           match_entries = entry_count
        match_count += 1
     # Set position to search for next entry
     if entry_count > 0:
        pos += entry_count * sizeof(eexpar)
     else:
        pos += data_align
  if (match_count > 1):
     eprint("{}: Warning: multiple ({:d}) matches found for parameters array with alignment 0x{:02x}".format(po.mdlfile,match_count,data_align))
  if (match_count < 1):
     return -1, 0
  return match_pos, match_entries

def flyc_list(po, fwmdlfile):
  (po.param_pos, po.param_count) = flyc_pos_search(po, fwmdlfile, 0, po.expect_func_align, po.expect_data_align)
  raise NotImplementedError('Function unfininshed.')

def flyc_extract(po, fwmdlfile):
  (po.param_pos, po.param_count) = flyc_pos_search(po, fwmdlfile, 0, po.expect_func_align, po.expect_data_align)
  raise NotImplementedError('Function unfininshed.')

def flyc_update(po, fwmdlfile):
  (po.param_pos, po.param_count) = flyc_pos_search(po, fwmdlfile, 0, po.expect_func_align, po.expect_data_align)
  raise NotImplementedError('Function unfininshed.')

def main(argv):
  # Parse command line options
  po = ProgOptions()
  try:
     opts, args = getopt.getopt(argv,"hvm:lux",["help","version","mdlfile="])
  except getopt.GetoptError:
     print("Unrecognized options; check dji_flyc_param_ed.sh --help")
     sys.exit(2)
  for opt, arg in opts:
     if opt in ("-h", "--help"):
        print("DJI Flight Controller Firmware Parameters Array Editor")
        print("dji_flyc_param_ed.sh <-l|-x|-u> [-v] -m <mdlfile>")
        print("  -m <mdlfile> - Flight controller firmware binary module file")
        print("  -l - list parameters stored in the firmware")
        print("  -x - extract parameters array to infos text file")
        print("  -u - update parameters array in binary fw from infos text file")
        print("  -v - increases verbosity level; max level is set by -vvv")
        sys.exit()
     elif opt == "--version":
        print("dji_flyc_param_ed.sh version 0.0.1")
        sys.exit()
     elif opt == '-v':
        po.verbose += 1
     elif opt in ("-m", "--mdlfile"):
        po.mdlfile = arg
     elif opt in ("-l", "--list"):
        po.command = 'l'
     elif opt in ("-u", "--update"):
        po.command = 'u'
     elif opt in ("-x", "--extract"):
        po.command = 'x'

  if (po.command == 'l'):

    if (po.verbose > 0):
      print("{}: Opening for list display".format(po.mdlfile))
    fwmdlfile = open(po.mdlfile, "rb")

    flyc_list(po,fwmdlfile)

    fwmdlfile.close();

  elif (po.command == 'x'):

    if (po.verbose > 0):
      print("{}: Opening for extraction".format(po.mdlfile))
    fwmdlfile = open(po.mdlfile, "rb")

    flyc_extract(po,fwmdlfile)

    fwmdlfile.close();

  elif (po.command == 'u'):

    if (po.verbose > 0):
      print("{}: Opening for update".format(po.mdlfile))
    fwmdlfile = open(po.mdlfile, "wb")

    flyc_update(po,fwmdlfile)

    fwmdlfile.close();

  else:

    raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
   main(sys.argv[1:])
