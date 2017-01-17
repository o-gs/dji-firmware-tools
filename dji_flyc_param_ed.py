#!/usr/bin/env python3

from __future__ import print_function
import sys
import getopt
import os
import math
from ctypes import *
import json

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
  long_min  = - (2 ** 31)
  long_max  = (2 ** 31) - 1
  ulong_min = 0
  ulong_max = (2 ** 32) - 1
  longlong_min  = - (2 ** 63)
  longlong_max  = (2 ** 63) - 1
  ulonglong_min = 0
  ulonglong_max = (2 ** 64) - 1

class ParamType:
  ubyte = 0x0
  ushort = 0x1
  ulong = 0x2
  ulonglong = 0x3
  byte = 0x4
  short = 0x5
  long = 0x6
  longlong = 0x7
  float = 0x8
  double = 0x9
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

def isclose(a, b, rel_tol=1e-09, abs_tol=0.0):
  """ Equivalent to math.isclose(); use it if the script needs to work on Python < 3.5
  """
  return abs(a-b) <= max(rel_tol * max(abs(a), abs(b)), abs_tol)

def flyc_param_limit_to_type(po, type_id, fltval):
  if (type_id == ParamType.ubyte):
     if (fltval < Limits.ubyte_min):
        return Limits.ubyte_min
     elif (fltval > Limits.ubyte_max):
        return Limits.ubyte_max
     else:
        return int(fltval) # DJI does not use round() here
  if (type_id == ParamType.ushort):
     if (fltval < Limits.ushort_min):
        return Limits.ushort_min
     elif (fltval > Limits.ushort_max):
        return Limits.ushort_max
     else:
        return int(fltval) # DJI does not use round() here
  if (type_id == ParamType.ulong):
     if (fltval < Limits.ulong_min):
        return Limits.ulong_min
     elif (fltval > Limits.ulong_max):
        return Limits.ulong_max
     else:
        return int(fltval) # DJI does not use round() here
  if (type_id == ParamType.ulonglong):
     if (fltval < Limits.ulonglong_min):
        return Limits.ulonglong_min
     elif (fltval > Limits.ulonglong_max):
        return Limits.ulonglong_max
     else:
        return int(fltval) # DJI does not use round() here
  if (type_id == ParamType.byte):
     if (fltval < Limits.byte_min):
        return Limits.byte_min
     elif (fltval > Limits.byte_max):
        return Limits.byte_max
     else:
        return int(fltval) # DJI does not use round() here
  if (type_id == ParamType.short):
     if (fltval < Limits.short_min):
        return Limits.short_min
     elif (fltval > Limits.short_max):
        return Limits.short_max
     else:
        return int(fltval) # DJI does not use round() here
  if (type_id == ParamType.long):
     if (fltval < Limits.long_min):
        return Limits.long_min
     elif (fltval > Limits.long_max):
        return Limits.long_max
     else:
        return int(fltval) # DJI does not use round() here
  if (type_id == ParamType.longlong):
     if (fltval < Limits.longlong_min):
        return Limits.longlong_min
     elif (fltval > Limits.longlong_max):
        return Limits.longlong_max
     else:
        return int(fltval) # DJI does not use round() here
  return fltval

def flyc_param_limit_unsigned_int(po, eexpar):
  return (eexpar.type_id == ParamType.ubyte) or \
     (eexpar.type_id == ParamType.ushort) or \
     (eexpar.type_id == ParamType.ulong) or \
     (eexpar.type_id == ParamType.ulonglong)

def flyc_param_limit_signed_int(po, eexpar):
  return (eexpar.type_id == ParamType.byte) or \
     (eexpar.type_id == ParamType.short) or \
     (eexpar.type_id == ParamType.long) or \
     (eexpar.type_id == ParamType.longlong)

def flyc_param_get_proper_limit_min(po, eexpar):
  if flyc_param_limit_unsigned_int(po, eexpar):
     return eexpar.limit_u.min
  if flyc_param_limit_signed_int(po, eexpar):
     return eexpar.limit_i.min
  return eexpar.limit_f.min

def flyc_param_get_proper_limit_max(po, eexpar):
  if flyc_param_limit_unsigned_int(po, eexpar):
     return eexpar.limit_u.max
  if flyc_param_limit_signed_int(po, eexpar):
     return eexpar.limit_i.max
  return eexpar.limit_f.max

def flyc_param_get_proper_limit_deflt(po, eexpar):
  if flyc_param_limit_unsigned_int(po, eexpar):
     return eexpar.limit_u.deflt
  if flyc_param_limit_signed_int(po, eexpar):
     return eexpar.limit_i.deflt
  return eexpar.limit_f.deflt

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
  if (eexpar.type_id == ParamType.ushort):
     if (eexpar.valsize != 1) and (eexpar.valsize != 2) and (eexpar.valsize != 4) and (eexpar.valsize != 8):
        if (po.verbose > 2):
           print("Rejected type {:d} on size scheck ({:d})\n".format(eexpar.type_id,eexpar.valsize))
        return False
  elif (eexpar.type_id == ParamType.ulong):
     if (eexpar.valsize != 1) and (eexpar.valsize != 2) and (eexpar.valsize != 4) and (eexpar.valsize != 8):
        if (po.verbose > 2):
           print("Rejected type {:d} on size scheck ({:d})\n".format(eexpar.type_id,eexpar.valsize))
        return False
  elif (eexpar.type_id <= ParamType.double):
     if (eexpar.valsize != 1) and (eexpar.valsize != 2) and (eexpar.valsize != 4) and (eexpar.valsize != 8):
        if (po.verbose > 2):
           print("Rejected type {:d} on size scheck ({:d})\n".format(eexpar.type_id,eexpar.valsize))
        return False
  elif (eexpar.type_id == ParamType.array): # array needs to have multiple elements
     if (eexpar.valsize < 2):
        if (po.verbose > 2):
           print("Rejected type {:d} on size scheck ({:d})\n".format(eexpar.type_id,eexpar.valsize))
        return False
  else:
     if (po.verbose > 2):
        print("Rejected type {:d} - not known\n".format(eexpar.type_id))
     return False
  # Limits
  if math.isnan(eexpar.limit_f.min) or math.isnan(eexpar.limit_f.max) or math.isnan(eexpar.limit_f.deflt):
     return False
  if (flyc_param_limit_unsigned_int(po, eexpar)):
     # Min unsigned
     limit_ftoi = flyc_param_limit_to_type(po, eexpar.type_id, eexpar.limit_f.min)
     if (limit_ftoi != eexpar.limit_u.min):
        if (po.verbose > 2):
           print("Rejected type {:d} on min {:d} {:d} {:f}\n".format(eexpar.type_id,limit_ftoi,eexpar.limit_u.min,eexpar.limit_f.min))
        return False
     # Max unsigned
     limit_ftoi = flyc_param_limit_to_type(po, eexpar.type_id, eexpar.limit_f.max)
     if (limit_ftoi != eexpar.limit_u.max):
        if (po.verbose > 2):
           print("Rejected type {:d} on max {:d} {:d} {:f}\n".format(eexpar.type_id,limit_ftoi,eexpar.limit_u.max,eexpar.limit_f.max))
        return False
     # Default unsigned
     limit_ftoi = flyc_param_limit_to_type(po, eexpar.type_id, eexpar.limit_f.deflt)
     if (abs(limit_ftoi - eexpar.limit_u.deflt) > 127):
        if (po.verbose > 2):
           print("Rejected type {:d} on deflt {:d} {:d} {:f}\n".format(eexpar.type_id,limit_ftoi,eexpar.limit_u.deflt,eexpar.limit_f.deflt))
        return False
  elif (flyc_param_limit_signed_int(po, eexpar)):
     # Min signed
     limit_ftoi = flyc_param_limit_to_type(po, eexpar.type_id, eexpar.limit_f.min)
     if (limit_ftoi != eexpar.limit_i.min):
        if (po.verbose > 2):
           print("Rejected type {:d} on min {:d} {:d} {:f}\n".format(eexpar.type_id,limit_ftoi,eexpar.limit_i.min,eexpar.limit_f.min))
        return False
     # Max signed
     limit_ftoi = flyc_param_limit_to_type(po, eexpar.type_id, eexpar.limit_f.max)
     if (limit_ftoi != eexpar.limit_i.max):
        if (po.verbose > 2):
           print("Rejected type {:d} on max {:d} {:d} {:f}\n".format(eexpar.type_id,limit_ftoi,eexpar.limit_i.max,eexpar.limit_f.max))
        return False
     # Default signed
     limit_ftoi = flyc_param_limit_to_type(po, eexpar.type_id, eexpar.limit_f.deflt)
     if (abs(limit_ftoi - eexpar.limit_i.deflt) > 127):
        if (po.verbose > 2):
           print("Rejected type {:d} on deflt {:d} {:d} {:f}\n".format(eexpar.type_id,limit_ftoi,eexpar.limit_i.deflt,eexpar.limit_f.deflt))
        return False
  else: # in case of other types, int params are storing 32-bit signed value
     # Min signed
     limit_ftoi = flyc_param_limit_to_type(po, ParamType.long, eexpar.limit_f.min)
     if (limit_ftoi != eexpar.limit_i.min):
        if (po.verbose > 2):
           print("Rejected type {:d} on min {:d} {:d} {:f}\n".format(eexpar.type_id,limit_ftoi,eexpar.limit_i.min,eexpar.limit_f.min))
        return False
     # Max signed
     limit_ftoi = flyc_param_limit_to_type(po, ParamType.long, eexpar.limit_f.max)
     if (limit_ftoi != eexpar.limit_i.max):
        if (po.verbose > 2):
           print("Rejected type {:d} on max {:d} {:d} {:f}\n".format(eexpar.type_id,limit_ftoi,eexpar.limit_i.max,eexpar.limit_f.max))
        return False
     # Default signed
     limit_ftoi = flyc_param_limit_to_type(po, ParamType.long, eexpar.limit_f.deflt)
     if (abs(limit_ftoi - eexpar.limit_i.deflt) > 127):
        if (po.verbose > 2):
           print("Rejected type {:d} on deflt {:d} {:d} {:f}\n".format(eexpar.type_id,limit_ftoi,eexpar.limit_i.deflt,eexpar.limit_f.deflt))
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

def flyc_param_get(po, fwmdlfile, index):
  """ Returns array with properties of given flight parameter.
  """
  parprop = {'index': index, 'typeID' : 0, 'size' : 0, 'attribute' : 0,
    'minValue' : 0, 'maxValue' : 0, 'defaultValue' : 0, 'name' : "" , 'modify' : False}
  eexpar = FlycExportParam()
  fwmdlfile.seek(po.param_pos+sizeof(eexpar)*index, os.SEEK_SET)
  if fwmdlfile.readinto(eexpar) != sizeof(eexpar):
      raise EOFError("Cannot read parameter entry.")

  parprop['typeID'] = eexpar.type_id
  parprop['size'] = eexpar.valsize
  parprop['attribute'] = eexpar.attribute
  if flyc_param_limit_unsigned_int(po, eexpar):
     parprop['minValue'] = eexpar.limit_u.min
     parprop['maxValue'] = eexpar.limit_u.max
     parprop['defaultValue'] = eexpar.limit_u.deflt
  elif flyc_param_limit_signed_int(po, eexpar):
     parprop['minValue'] = eexpar.limit_i.min
     parprop['maxValue'] = eexpar.limit_i.max
     parprop['defaultValue'] = eexpar.limit_i.deflt
  else:
     parprop['minValue'] = eexpar.limit_f.min
     parprop['maxValue'] = eexpar.limit_f.max
     parprop['defaultValue'] = eexpar.limit_f.deflt
  # Read property name
  fwmdlfile.seek(eexpar.nameptr - po.address_base, os.SEEK_SET)
  parprop['name'] = fwmdlfile.read(256).split(b'\0',1)[0].decode('UTF-8')
  if ((eexpar.attribute & 0x0B) == 0x0B): # Just a guess
     parprop['modify'] = True
  return parprop

def flyc_param_set_type(po, fwmdlfile, index, parprop):
  """ Updates parameter of given index with type from given parprop array.
  """
  raise NotImplementedError('Changing variable type is dangerous; this is not supported.')

def flyc_param_set_attribs(po, fwmdlfile, index, parprop):
  """ Updates parameter of given index with attribs from given parprop array.
  """
  eexpar = FlycExportParam()
  fwmdlfile.seek(po.param_pos+sizeof(eexpar)*index, os.SEEK_SET)
  if fwmdlfile.readinto(eexpar) != sizeof(eexpar):
      raise EOFError("Cannot read parameter entry.")
  eexpar.attribute = parprop['attribute']
  fwmdlfile.seek(po.param_pos+sizeof(eexpar)*index, os.SEEK_SET)
  fwmdlfile.write((c_ubyte * sizeof(eexpar)).from_buffer_copy(eexpar))

def flyc_param_set_limits(po, fwmdlfile, index, parprop):
  """ Updates parameter of given index with limits from given parprop array.
  """
  eexpar = FlycExportParam()
  fwmdlfile.seek(po.param_pos+sizeof(eexpar)*index, os.SEEK_SET)
  if fwmdlfile.readinto(eexpar) != sizeof(eexpar):
      raise EOFError("Cannot read parameter entry.")
  if flyc_param_limit_unsigned_int(po, eexpar):
     eexpar.limit_u.min = flyc_param_limit_to_type(po, eexpar.type_id, parprop['minValue'])
     eexpar.limit_u.max = flyc_param_limit_to_type(po, eexpar.type_id, parprop['maxValue'])
     eexpar.limit_u.deflt = flyc_param_limit_to_type(po, eexpar.type_id, parprop['defaultValue'])
     eexpar.limit_i.min = c_int(eexpar.limit_u.min).value
     eexpar.limit_i.max = c_int(eexpar.limit_u.max).value
     eexpar.limit_i.deflt = c_int(eexpar.limit_u.deflt).value
     eexpar.limit_f.min = float(eexpar.limit_u.min)
     eexpar.limit_f.max = float(eexpar.limit_u.max)
     eexpar.limit_f.deflt = float(eexpar.limit_u.deflt)
     if (not isclose(eexpar.limit_u.min, float(parprop['minValue']), rel_tol=1e-5, abs_tol=1e-5)):
       eprint("{}: Warning: min value {:f} bound to {:d}".format(po.mdlfile,float(parprop['minValue']),eexpar.limit_u.min))
     if (not isclose(eexpar.limit_u.max, float(parprop['maxValue']), rel_tol=1e-5, abs_tol=1e-5)):
       eprint("{}: Warning: max value {:f} bound to {:d}".format(po.mdlfile,float(parprop['maxValue']),eexpar.limit_u.max))
     if (not isclose(eexpar.limit_u.deflt, float(parprop['defaultValue']), rel_tol=1e-5, abs_tol=1e-5)):
       eprint("{}: Warning: dafault value {:f} bound to {:d}".format(po.mdlfile,float(parprop['defaultValue']),eexpar.limit_u.deflt))
  elif flyc_param_limit_signed_int(po, eexpar):
     eexpar.limit_i.min = flyc_param_limit_to_type(po, eexpar.type_id, parprop['minValue'])
     eexpar.limit_i.max = flyc_param_limit_to_type(po, eexpar.type_id, parprop['maxValue'])
     eexpar.limit_i.deflt = flyc_param_limit_to_type(po, eexpar.type_id, parprop['defaultValue'])
     eexpar.limit_u.min = c_uint(eexpar.limit_i.min).value
     eexpar.limit_u.max = c_uint(eexpar.limit_i.max).value
     eexpar.limit_u.deflt = c_uint(eexpar.limit_i.deflt).value
     eexpar.limit_f.min = float(eexpar.limit_i.min)
     eexpar.limit_f.max = float(eexpar.limit_i.max)
     eexpar.limit_f.deflt = float(eexpar.limit_i.deflt)
     if (not isclose(eexpar.limit_i.min, float(parprop['minValue']), rel_tol=1e-5, abs_tol=1e-5)):
       eprint("{}: Warning: min value {:f} bound to {:d}".format(po.mdlfile,float(parprop['minValue']),eexpar.limit_i.min))
     if (not isclose(eexpar.limit_i.max, float(parprop['maxValue']), rel_tol=1e-5, abs_tol=1e-5)):
       eprint("{}: Warning: max value {:f} bound to {:d}".format(po.mdlfile,float(parprop['maxValue']),eexpar.limit_i.max))
     if (not isclose(eexpar.limit_i.deflt, float(parprop['defaultValue']), rel_tol=1e-5, abs_tol=1e-5)):
       eprint("{}: Warning: dafault value {:f} bound to {:d}".format(po.mdlfile,float(parprop['defaultValue']),eexpar.limit_i.deflt))
  else:
     eexpar.limit_f.min = flyc_param_limit_to_type(po, eexpar.type_id, parprop['minValue'])
     eexpar.limit_f.max = flyc_param_limit_to_type(po, eexpar.type_id, parprop['maxValue'])
     eexpar.limit_f.deflt = flyc_param_limit_to_type(po, eexpar.type_id, parprop['defaultValue'])
     eexpar.limit_f.min = flyc_param_limit_to_type(po, ParamType.long, parprop['minValue'])
     eexpar.limit_f.max = flyc_param_limit_to_type(po, ParamType.long, parprop['maxValue'])
     eexpar.limit_f.deflt = flyc_param_limit_to_type(po, ParamType.long, parprop['defaultValue'])
     eexpar.limit_u.min = c_uint(eexpar.limit_i.min).value
     eexpar.limit_u.max = c_uint(eexpar.limit_i.max).value
     eexpar.limit_u.deflt = c_uint(eexpar.limit_i.deflt).value
     if (not isclose(eexpar.limit_f.min, float(parprop['minValue']), rel_tol=1e-5, abs_tol=1e-5)):
       eprint("{}: Warning: min value {:f} bound to {:f}".format(po.mdlfile,float(parprop['minValue']),eexpar.limit_f.min))
     if (not isclose(eexpar.limit_f.max, float(parprop['maxValue']), rel_tol=1e-5, abs_tol=1e-5)):
       eprint("{}: Warning: max value {:f} bound to {:f}".format(po.mdlfile,float(parprop['maxValue']),eexpar.limit_f.max))
     if (not isclose(eexpar.limit_f.deflt, float(parprop['defaultValue']), rel_tol=1e-5, abs_tol=1e-5)):
       eprint("{}: Warning: dafault value {:f} bound to {:f}".format(po.mdlfile,float(parprop['defaultValue']),eexpar.limit_f.deflt))
  fwmdlfile.seek(po.param_pos+sizeof(eexpar)*index, os.SEEK_SET)
  fwmdlfile.write((c_ubyte * sizeof(eexpar)).from_buffer_copy(eexpar))

def flyc_list(po, fwmdlfile):
  (po.param_pos, po.param_count) = flyc_pos_search(po, fwmdlfile, 0, po.expect_func_align, po.expect_data_align)
  if po.param_pos < 0:
    raise ValueError("Flight controller parameters array signature not detected in input file.")
  for i in range(0,po.param_count):
    parprop = flyc_param_get(po, fwmdlfile, i)
    print("{:3d} {:40s} {:2d} {:2d} 0x{:x} {:6.1f} {:6.1f} {:6.1f}".format(parprop['index'],parprop['name'],parprop['typeID'],parprop['size'],parprop['attribute'],parprop['minValue'],parprop['maxValue'],parprop['defaultValue']))

def flyc_extract(po, fwmdlfile):
  """ Extracts all flight controller parameters from firmware to JSON format text file.
  """
  (po.param_pos, po.param_count) = flyc_pos_search(po, fwmdlfile, 0, po.expect_func_align, po.expect_data_align)
  if po.param_pos < 0:
    raise ValueError("Flight controller parameters array signature not detected in input file.")
  inffile = open(po.inffile, "w")
  inffile.write("[\n")
  for i in range(0,po.param_count):
    parprop = flyc_param_get(po, fwmdlfile, i)
    inffile.write("\t{\n")
    for ppname in ('index',):
       inffile.write("\t\t\"{:s}\" : {:d}".format(ppname,parprop[ppname]))
    for ppname in ('typeID', 'size', 'attribute'):
       inffile.write(",\n")
       inffile.write("\t\t\"{:s}\" : {:d}".format(ppname,parprop[ppname]))
    for ppname in ('minValue', 'maxValue', 'defaultValue'):
       inffile.write(",\n")
       if (isinstance(parprop[ppname], float)):
          inffile.write("\t\t\"{:s}\" : {:.06f}".format(ppname,parprop[ppname]))
       else:
          inffile.write("\t\t\"{:s}\" : {:d}".format(ppname,parprop[ppname]))
    for ppname in ('name',):
       inffile.write(",\n")
       inffile.write("\t\t\"{:s}\" : \"{:s}\"".format(ppname,parprop[ppname]))
    if parprop['modify']:
       inffile.write(",\n")
       inffile.write("\t\t\"{:s}\" : {:s}".format('modify','true'))
    inffile.write("\n")
    if (i+1 < po.param_count):
       inffile.write("\t},\n")
    else:
       inffile.write("\t}\n")
  inffile.write("]\n")
  inffile.close()

def flyc_update(po, fwmdlfile):
  """ Updates all flight controller parameters in firmware from JSON format text file.
  """
  (po.param_pos, po.param_count) = flyc_pos_search(po, fwmdlfile, 0, po.expect_func_align, po.expect_data_align)
  if po.param_pos < 0:
    raise ValueError("Flight controller parameters array signature not detected in input file.")
  with open(po.inffile) as inffile:
    nxparprops = json.load(inffile)
  update_count = 0
  for i in range(0,po.param_count):
    pvparprop = flyc_param_get(po, fwmdlfile, i)
    nxparprop = None
    for parprop in nxparprops:
      if (parprop['name'] == pvparprop['name']):
         nxparprop = parprop
         break
    if (nxparprop is None):
       eprint("{}: Warning: parameter not found in fw: \"{:s}\"".format(po.mdlfile,pvparprop['name']))
       continue
    update_type=False
    update_attrib=False
    update_limits=False
    # compare properties to check what we want to update
    for ppname in ('typeID', 'size'):
       if (pvparprop[ppname] != nxparprop[ppname]):
          update_type=True
          update_limits=True
    for ppname in ('attribute',):
       if (pvparprop[ppname] != nxparprop[ppname]):
          update_attrib=True
    for ppname in ('minValue', 'maxValue', 'defaultValue'):
       if (isinstance(pvparprop[ppname], float)):
          if (not isclose(pvparprop[ppname], nxparprop[ppname], rel_tol=1e-5, abs_tol=1e-5)):
             #print("{}: Prop \"{:s}\" {:s} test: {:s} vs {:s}".format(po.mdlfile,pvparprop['name'],ppname,str(pvparprop[ppname]),str(nxparprop[ppname])))
             update_limits=True
       else:
          if (pvparprop[ppname] != nxparprop[ppname]):
             #print("{}: Prop \"{:s}\" {:s} test: {:s} vs {:s}".format(po.mdlfile,pvparprop['name'],ppname,str(pvparprop[ppname]),str(nxparprop[ppname])))
             update_limits=True
    if (update_type or update_attrib or update_limits):
       if (po.verbose > 1):
          print("{}: Updating \"{:s}\" {:s}{:s}{:s}".format(po.mdlfile,pvparprop['name']," type," if update_type else ""," attribs," if update_attrib else ""," limits," if update_limits else ""))
       update_count += 1
    # do the update
    if (update_type):
       flyc_param_set_type(po, fwmdlfile, pvparprop['index'], nxparprop)
    if (update_attrib):
       flyc_param_set_attribs(po, fwmdlfile, pvparprop['index'], nxparprop)
    if (update_limits):
       flyc_param_set_limits(po, fwmdlfile, pvparprop['index'], nxparprop)
  if (po.verbose > 0):
     print("{}: Updated {:d} parameter entries".format(po.mdlfile,update_count))

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
        print("  -x - extract parameters array to infos json text file")
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
    fwmdlfile = open(po.mdlfile, "r+b")

    flyc_update(po,fwmdlfile)

    fwmdlfile.close();

  else:

    raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
   main(sys.argv[1:])
