#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" DJI Flight Controller Firmware Parameters Array Editor.
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
__version__ = "0.0.2"
__author__ = "Mefistotelis @ Original Gangsters"
__license__ = "GPL"

import sys
import argparse
import os
import math
from ctypes import *
import re
import json

def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

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
  bool = 0xb

class FlycExportLimitF2015(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('min', c_float),
              ('max', c_float),
              ('deflt', c_float)]

class FlycExportLimitI2015(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('min', c_int),
              ('max', c_int),
              ('deflt', c_int)]

class FlycExportLimitU2015(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('min', c_uint),
              ('max', c_uint),
              ('deflt', c_uint)]

class FlycExportLimitF2017(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('deflt', c_float),
              ('min', c_float),
              ('max', c_float)]

class FlycExportLimitI2017(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('deflt', c_int),
              ('min', c_int),
              ('max', c_int)]

class FlycExportLimitU2017(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('deflt', c_uint),
              ('min', c_uint),
              ('max', c_uint)]

class FlycExportParam2015(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('nameptr', c_uint), # Pointer to the name string of this parameter
              ('valptr', c_uint), # Pointer to where current value of the parameter is
              ('valsize', c_uint),
              ('type_id', c_uint),
              ('limit_f', FlycExportLimitF2015),
              ('limit_i', FlycExportLimitI2015),
              ('limit_u', FlycExportLimitU2015),
              ('attribute', c_uint),
              ('callback', c_uint)]

class FlycExportParam2017(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('nameptr', c_uint), # Pointer to the name string of this parameter
              ('valptr', c_uint), # Pointer to where current value of the parameter is
              ('valsize', c_ushort),
              ('type_id', c_ushort),
              ('limit_f', FlycExportLimitF2017),
              ('limit_i', FlycExportLimitI2017),
              ('limit_u', FlycExportLimitU2017),
              ('attribute', c_uint),
              ('callback', c_uint)]

class FlycExportParam2018(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('nameptr', c_uint), # Pointer to the name string of this block
              ('aliasptr', c_uint),
              ('field_8', c_ushort),
              ('valsize', c_ubyte),
              ('field_B', c_ubyte),
              ('attribute', c_ubyte),
              ('field_D', c_ubyte),
              ('type_id', c_ubyte),
              ('field_F', c_ubyte),
              ('limit_f', FlycExportLimitF2017),
              ('limit_i', FlycExportLimitI2017),
              ('limit_u', FlycExportLimitU2017)]

class FlycParamBlock2018(LittleEndianStructure):
  """ The 2018 generation of drones introduced grouping of parameters into independent Blocks.
      Each Block structure has its name, and points to an array of ExportParam entries.
  """
  _pack_ = 1
  _fields_ = [('nameptr', c_uint), # Pointer to the name string of this block
              ('blockid', c_uint),
              ('field_8', c_uint),
              ('params', c_uint), # Pointer to parameters array
              ('cmds', c_uint), # Pointer to commands array
              ('param_count', c_ushort),
              ('cmd_count', c_ushort),
              ('callback', c_uint)]

def isclose(a, b, rel_tol=1e-09, abs_tol=0.0):
  """ Equivalent to math.isclose(); use it if the script needs to work on Python < 3.5
  """
  return abs(a-b) <= max(rel_tol * max(abs(a), abs(b)), abs_tol)

def FlycExportParamFactory(ver):
  if ver == 2015:
      eexpar = FlycExportParam2015()
  elif ver == 2017:
      eexpar = FlycExportParam2017()
  elif ver == 2018:
      eexpar = FlycExportParam2018()
  else:
      raise ValueError("Unsupported flyc parameters format version.")
  return eexpar

def export_param_instance_to_ver(instn):
  if isinstance(instn, FlycExportParam2015):
      ver = 2015
  elif isinstance(instn, FlycExportParam2017):
      ver = 2017
  elif isinstance(instn, FlycExportParam2018):
      ver = 2018
  else:
      raise ValueError("Unsupported flyc parameters format version.")
  return ver

def flyc_param_limit_to_type(po, ver, type_id, fltval):
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
     if (ver == 2017):
         if (fltval < Limits.byte_min):
            return Limits.byte_min
         elif (fltval > Limits.ubyte_max): # This is alarming, but that's how it's really done
            return Limits.ubyte_max
         else:
            return int(fltval) # DJI does not use round() here
     else:
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

def address_is_pointer_to_initialized(po, fwmdlfile, fwmdlfile_len, ptraddr):
  """ Checks whether given value can be treated as a valid pointer to either code or initialized data.
  """
  if (ptraddr < po.baseaddr) or (ptraddr >= po.baseaddr+fwmdlfile_len):
     return False
  # Values near zero should be treated as invalid even if within segment - interrupt table cannot be referenced
  if (ptraddr < 128):
     return False
  return True

def address_is_pointer_to_bss(po, fwmdlfile, fwmdlfile_len, ptraddr):
  """ Checks whether given value can be treated as a valid pointer to uninitialized data.
  """
  if (ptraddr < po.bssaddr) or (ptraddr >= po.bssaddr+po.bsslen):
      return False
  # Values near zero should be treated as invalid even if within segment - interrupt table cannot be referenced
  if (ptraddr < 128):
     return False
  return True

def flyc_parameter_entry_type_matches_size(po, eexpar):
  if (eexpar.type_id == ParamType.ushort):
     if (eexpar.valsize != 1) and (eexpar.valsize != 2) and (eexpar.valsize != 4) and (eexpar.valsize != 8):
        if (po.verbose > 3):
           print("{}: Rejection on bad ushort ({:d}) size ({:d})".format(po.mdlfile,eexpar.type_id,eexpar.valsize))
        return False
  elif (eexpar.type_id == ParamType.ulong):
     if (eexpar.valsize != 1) and (eexpar.valsize != 2) and (eexpar.valsize != 4) and (eexpar.valsize != 8):
        if (po.verbose > 3):
           print("{}: Rejection on bad ulong ({:d}) size ({:d})".format(po.mdlfile,eexpar.type_id,eexpar.valsize))
        return False
  elif (eexpar.type_id == ParamType.bool):
     if (eexpar.valsize != 1) and (eexpar.valsize != 2) and (eexpar.valsize != 4):
        if (po.verbose > 3):
           print("{}: Rejection on bad bool ({:d}) size ({:d})".format(po.mdlfile,eexpar.type_id,eexpar.valsize))
        return False
  elif (eexpar.type_id <= ParamType.double):
     if (eexpar.valsize != 1) and (eexpar.valsize != 2) and (eexpar.valsize != 4) and (eexpar.valsize != 8):
        if (po.verbose > 3):
           print("{}: Rejection on bad type ({:d}) size ({:d})".format(po.mdlfile,eexpar.type_id,eexpar.valsize))
        return False
  elif (eexpar.type_id == ParamType.array):
     # array needs to have multiple elements
     if (eexpar.valsize < 2):
        if (po.verbose > 3):
           print("{}: Rejection on bad array ({:d}) size ({:d})".format(po.mdlfile,eexpar.type_id,eexpar.valsize))
        return False
  else:
     # unrecognized type
     return False
  return True

def flyc_parameter_limits_check_int_values_match_float_values(po, ver, eexpar):
  if (flyc_param_limit_unsigned_int(po, eexpar)):
     # Min unsigned vs Float
     limit_ftoi = flyc_param_limit_to_type(po, ver, eexpar.type_id, eexpar.limit_f.min)
     treshold = abs(limit_ftoi / 10000000) # ignore differences beyond 32bit float precision
     if (abs(limit_ftoi - eexpar.limit_u.min) > treshold):
        if (po.verbose > 3):
           print("{}: Rejection on min U-F {:d} {:d} {:f}".format(po.mdlfile,limit_ftoi,eexpar.limit_u.min,eexpar.limit_f.min))
        return False
     # Max unsigned vs Float
     limit_ftoi = flyc_param_limit_to_type(po, ver, eexpar.type_id, eexpar.limit_f.max)
     treshold = abs(limit_ftoi / 10000000) # ignore differences beyond 32bit float precision
     if (abs(limit_ftoi - eexpar.limit_u.max) > treshold):
        if (po.verbose > 3):
           print("{}: Rejection on max U-F {:d} {:d} {:f}".format(po.mdlfile,limit_ftoi,eexpar.limit_u.max,eexpar.limit_f.max))
        return False
     # Default unsigned vs Float
     limit_ftoi = flyc_param_limit_to_type(po, ver, eexpar.type_id, eexpar.limit_f.deflt)
     treshold = abs(limit_ftoi / 10000000) # ignore differences beyond 32bit float precision
     if (abs(limit_ftoi - eexpar.limit_u.deflt) > treshold):
        if (po.verbose > 3):
           print("{}: Rejection on deflt U-F {:d} {:d} {:f}".format(po.mdlfile,limit_ftoi,eexpar.limit_u.deflt,eexpar.limit_f.deflt))
        return False
  elif (flyc_param_limit_signed_int(po, eexpar)):
     # Min signed vs Float
     limit_ftoi = flyc_param_limit_to_type(po, ver, eexpar.type_id, eexpar.limit_f.min)
     treshold = abs(limit_ftoi / 10000000) # ignore differences beyond 32bit float precision
     if (abs(limit_ftoi - eexpar.limit_i.min) > treshold):
        if (po.verbose > 3):
           print("{}: Rejection on min I-F {:d} {:d} {:f}".format(po.mdlfile,limit_ftoi,eexpar.limit_i.min,eexpar.limit_f.min))
        return False
     # Max signed vs Float
     limit_ftoi = flyc_param_limit_to_type(po, ver, eexpar.type_id, eexpar.limit_f.max)
     treshold = abs(limit_ftoi / 10000000) # ignore differences beyond 32bit float precision
     if (abs(limit_ftoi - eexpar.limit_i.max) > treshold):
        if (po.verbose > 3):
           print("{}: Rejection on max I-F {:d} {:d} {:f}".format(po.mdlfile,limit_ftoi,eexpar.limit_i.max,eexpar.limit_f.max))
        return False
     # Default signed vs Float
     limit_ftoi = flyc_param_limit_to_type(po, ver, eexpar.type_id, eexpar.limit_f.deflt)
     treshold = abs(limit_ftoi / 10000000) # ignore differences beyond 32bit float precision
     if (abs(limit_ftoi - eexpar.limit_i.deflt) > treshold):
        if (po.verbose > 3):
           print("{}: Rejection on deflt I-F {:d} {:d} {:f}".format(po.mdlfile,limit_ftoi,eexpar.limit_i.deflt,eexpar.limit_f.deflt))
        return False
  else: # in case of other types, int params are storing 32-bit signed value
     # Min signed vs Float
     limit_ftoi = flyc_param_limit_to_type(po, ver, ParamType.long, eexpar.limit_f.min)
     if (limit_ftoi != eexpar.limit_i.min):
        if (po.verbose > 3):
           print("{}: Rejection on min O-F {:d} {:d} {:f}".format(po.mdlfile,limit_ftoi,eexpar.limit_i.min,eexpar.limit_f.min))
        return False
     # Max signed vs Float
     limit_ftoi = flyc_param_limit_to_type(po, ver, ParamType.long, eexpar.limit_f.max)
     if (limit_ftoi != eexpar.limit_i.max):
        if (po.verbose > 3):
           print("{}: Rejection on max O-F {:d} {:d} {:f}".format(po.mdlfile,limit_ftoi,eexpar.limit_i.max,eexpar.limit_f.max))
        return False
     # Default signed vs Float
     limit_ftoi = flyc_param_limit_to_type(po, ver, ParamType.long, eexpar.limit_f.deflt)
     if (abs(limit_ftoi - eexpar.limit_i.deflt) > 127):
        if (po.verbose > 3):
           print("{}: Rejection on deflt O-F {:d} {:d} {:f}".format(po.mdlfile,limit_ftoi,eexpar.limit_i.deflt,eexpar.limit_f.deflt))
        return False
  return True

def flyc_parameter_limits_check_minmax_relations(po, ver, eexpar):
  if math.isnan(eexpar.limit_f.min) or math.isnan(eexpar.limit_f.max) or math.isnan(eexpar.limit_f.deflt):
      if (po.verbose > 3):
         print("{}: Rejection on valid float check ({:f} {:f} {:f})".format(po.mdlfile,eexpar.limit_f.min,eexpar.limit_f.deflt,eexpar.limit_f.max))
      return False
  if (eexpar.limit_f.min > eexpar.limit_f.max):
      if (po.verbose > 3):
         print("{}: Rejection on float min:max relation check ({:f}:{:f})".format(po.mdlfile,eexpar.limit_f.min,eexpar.limit_f.max))
      return False
  # That would be a nice check, but the original parameters have errors and some of them would fail this test
  #if (eexpar.limit_f.min > eexpar.limit_f.deflt):
  #    if (po.verbose > 3):
  #       print("{}: Rejection on float min:default relation check ({:f}:{:f})".format(po.mdlfile,eexpar.limit_f.min,eexpar.limit_f.deflt))
  #    return False
  # That would be a nice check, but the original parameters have errors and some of them would fail this test
  #if (eexpar.limit_f.deflt > eexpar.limit_f.max):
  #    if (po.verbose > 3):
  #       print("{}: Rejection on float default:max relation check ({:f}:{:f})".format(po.mdlfile,eexpar.limit_f.deflt,eexpar.limit_f.max))
  #    return False
  return True

def flyc_parameter_limits_check_int_bitwise_identical(po, ver, eexpar):
  """ limit_u and limit_i are bitwise identical; cast them to compare
  """
  if (c_uint(eexpar.limit_i.min).value != eexpar.limit_u.min):
      if (po.verbose > 3):
         print("{}: Rejection on bitwise identical min I-U ({:d} {:d})".format(po.mdlfile,eexpar.limit_i.min,eexpar.limit_u.min))
      return False
  if (c_uint(eexpar.limit_i.max).value != eexpar.limit_u.max):
      if (po.verbose > 3):
         print("{}: Rejection on bitwise identical max I-U ({:d} {:d})".format(po.mdlfile,eexpar.limit_i.max,eexpar.limit_u.max))
      return False
  if (c_uint(eexpar.limit_i.deflt).value != eexpar.limit_u.deflt):
      if (po.verbose > 3):
         print("{}: Rejection on bitwise identical deflt I-U ({:d} {:d})".format(po.mdlfile,eexpar.limit_i.deflt,eexpar.limit_u.deflt))
      return False
  return True

def flyc_is_proper_parameter_entry(po, fwmdlfile, fwmdlfile_len, eexpar, func_align, data_align, pos, entry_pos):
  """ Checks whether given FlycExportParam object stores a proper entry of
      flight controller parameters array.
  """
  ver = export_param_instance_to_ver(eexpar)

  if (False): # DEBUG code, to be enabled when searching for missing parameters
      if (ver == 2018) and (entry_pos == 0x10F8DC): po.verbose = 4
      else: po.verbose = 2

  # Address to const string
  if not address_is_pointer_to_initialized(po, fwmdlfile, fwmdlfile_len, eexpar.nameptr):
      if (po.verbose > 2):
          print("{}: At 0x{:08x}, rejected type {:d} on name pointer check (0x{:x})".format(po.mdlfile,entry_pos,eexpar.type_id,eexpar.nameptr))
      return False

  if hasattr(eexpar, 'valptr'):
      # Address to uninitialized variable
      if not address_is_pointer_to_bss(po, fwmdlfile, fwmdlfile_len, eexpar.valptr):
          if (eexpar.valptr != 0): # Value pointer can be NULL
              if (po.verbose > 2):
                  print("{}: At 0x{:08x}, rejected type {:d} on value pointer check (0x{:x})".format(po.mdlfile,entry_pos,eexpar.type_id,eexpar.valptr))
              return False

  if hasattr(eexpar, 'aliasptr'):
      # Address to const string
      if not address_is_pointer_to_initialized(po, fwmdlfile, fwmdlfile_len, eexpar.aliasptr):
          if (eexpar.aliasptr != 0): # Alias pointer can be NULL
              if (po.verbose > 2):
                  print("{}: At 0x{:08x}, rejected type {:d} on alias pointer check (0x{:x})".format(po.mdlfile,entry_pos,eexpar.type_id,eexpar.aliasptr))
              return False

  # Size and type
  if not flyc_parameter_entry_type_matches_size(po, eexpar):
      if (po.verbose > 2):
          print("{}: At 0x{:08x}, rejected type {:d} on size check ({:d})".format(po.mdlfile,entry_pos,eexpar.type_id,eexpar.valsize))
      return False

  # Attribute used range
  if (eexpar.attribute > 255):
      if (po.verbose > 2):
          print("{}: At 0x{:08x}, rejected type {:d} on attribute check ({:d})".format(po.mdlfile,entry_pos,eexpar.type_id,eexpar.attribute))
      return False

  # Address to callback func
  if hasattr(eexpar, 'callback'):
      if not address_is_pointer_to_initialized(po, fwmdlfile, fwmdlfile_len, eexpar.callback):
          if (eexpar.callback != 0): # Callback pointer can be NULL
              if (po.verbose > 2):
                  print("{}: At 0x{:08x}, rejected type {:d} on callback address check ({:d})".format(po.mdlfile,entry_pos,eexpar.type_id,eexpar.callback))
              return False

  # Limits
  if not flyc_parameter_limits_check_minmax_relations(po, ver, eexpar):
      if (po.verbose > 2):
          print("{}: At 0x{:08x}, rejected type {:d} on min:default:max relation check".format(po.mdlfile,entry_pos,eexpar.type_id))
      return False
  if not flyc_parameter_limits_check_int_values_match_float_values(po, ver, eexpar):
      if (po.verbose > 2):
          print("{}: At 0x{:08x}, rejected type {:d} on integer-vs-float similarity check".format(po.mdlfile,entry_pos,eexpar.type_id))
      return False

  if not flyc_parameter_limits_check_int_bitwise_identical(po, ver, eexpar):
      if (po.verbose > 2):
          print("{}: At 0x{:08x}, rejected type {:d} on signed-unsigned bitwise same check".format(po.mdlfile,entry_pos,eexpar.type_id))
      return False
  return True

def flyc_is_proper_parameter_block(po, fwmdlfile, fwmdlfile_len, eparblk, func_align, data_align, pos):
  """ Checks whether given FlycParamBlock object stores a proper entry of
      flight controller parameter block.
  """
  # Address to const string
  if not address_is_pointer_to_initialized(po, fwmdlfile, fwmdlfile_len, eparblk.nameptr):
     return False

  # Address to cmds array
  if not address_is_pointer_to_initialized(po, fwmdlfile, fwmdlfile_len, eparblk.cmds):
     if (eparblk.cmds != 0): # Cmds pointer can be NULL
        return False

  # Address to callback func
  if not address_is_pointer_to_initialized(po, fwmdlfile, fwmdlfile_len, eparblk.callback):
     if (eparblk.callback != 0): # Callback pointer can be NULL
        return False

  if (eparblk.cmd_count == 0) and (eparblk.cmds != 0):
        return False
  if (eparblk.cmd_count > 0) and (eparblk.cmds == 0):
        return False

  if (eparblk.param_count == 0):
        return False

  # Address to params array
  if not address_is_pointer_to_initialized(po, fwmdlfile, fwmdlfile_len, eparblk.params):
        return False

  return True

def flyc_check_parameter_array_at(po, fwmdlfile, fwmdlfile_len, start_pos, func_align, data_align, ver):
  """ Assuming given position is a parameter array, this function will return how many
      proper entries it has.
  """
  eexpar = FlycExportParamFactory(ver)
  entry_count = 0
  entry_pos = start_pos
  while (True):
      # Read possible struct
      fwmdlfile.seek(entry_pos, os.SEEK_SET)
      if fwmdlfile.readinto(eexpar) != sizeof(eexpar):
          break
      # Check if struct is valid
      if not flyc_is_proper_parameter_entry(po, fwmdlfile, fwmdlfile_len, eexpar, func_align, data_align, start_pos, entry_pos):
          break
      # If struct seem correct, check for its name string
      fwmdlfile.seek(eexpar.nameptr - po.baseaddr, os.SEEK_SET)
      eexpar_name_btarr = fwmdlfile.read(256).split(b'\0',1)[0]
      if (len(eexpar_name_btarr) < 2):
          if (po.verbose > 3):
              print("{}: At 0x{:08x}, rejected type {:d} on name len check ({:d})".format(po.mdlfile,entry_pos,eexpar.type_id,len(eexpar_name_btarr)))
          break
      if not re.match(b'^[0-9a-zA-z\[\]\(\)\{\} .,:*#_-]+$', eexpar_name_btarr):
          if (po.verbose > 3):
              print("{}: At 0x{:08x}, rejected type {:d} on name regex check".format(po.mdlfile,entry_pos,eexpar.type_id))
          break
      if (po.verbose > 2):
          print("{}: Found entry '{:s}'".format(po.mdlfile,eexpar_name_btarr.decode('UTF-8')))
      # All correct
      entry_count += 1
      entry_pos += sizeof(eexpar)
  return entry_count

def flyc_parameter_array_pos_search(po, fwmdlfile, start_pos, func_align, data_align, ver):
  """ Finds position of flight controller parameters in the binary.
      Searches only for specific version of the parameters format.
  """
  fwmdlfile.seek(0, os.SEEK_END)
  fwmdlfile_len = fwmdlfile.tell()
  eexpar = FlycExportParamFactory(ver)
  match_count = 0
  match_pos = -1
  match_entries = 0
  pos = start_pos
  while (True):
      # Check how many correct parameter entries we have
      entry_count = flyc_check_parameter_array_at(po, fwmdlfile, fwmdlfile_len, pos, func_align, data_align, ver)
      # If entry is ok, consider it a match
      if entry_count > 0:
          if (po.verbose > 1):
              print("{}: Matching parameters array at 0x{:08x}: {:d} entries, format {:d}".format(po.mdlfile,pos,entry_count,ver))
          if (entry_count > match_entries):
              match_pos = pos
              match_entries = entry_count
          match_count += 1
      # Set position to search for next entry
      if entry_count > 0:
          pos += entry_count * sizeof(eexpar)
      else:
          pos += data_align
      # Stop if we're at EOF
      if (pos + sizeof(eexpar) > fwmdlfile_len):
          break
  if (match_count > 1):
      eprint("{}: Warning: multiple ({:d}) matches found for parameters array with alignment 0x{:02x}".format(po.mdlfile,match_count,data_align))
  if (match_count < 1):
      return {}, 0
  return {match_pos: match_entries}, match_entries

def flyc_check_parameter_block_at(po, fwmdlfile, fwmdlfile_len, start_pos, func_align, data_align, ver):
  """ Assuming given position is a parameter block, this function will read it and verify content.
  """
  eparblk = FlycParamBlock2018()
  fwmdlfile.seek(start_pos, os.SEEK_SET)
  if fwmdlfile.readinto(eparblk) != sizeof(eparblk):
      eparblk.param_count = 0
      return eparblk
  # Check if struct is valid
  if not flyc_is_proper_parameter_block(po, fwmdlfile, fwmdlfile_len, eparblk, func_align, data_align, start_pos):
      eparblk.param_count = 0
      return eparblk
  # If struct seem correct, check for its name string
  fwmdlfile.seek(eparblk.nameptr - po.baseaddr, os.SEEK_SET)
  eparblk_name_btarr = fwmdlfile.read(256).split(b'\0',1)[0]
  if (len(eparblk_name_btarr) < 2):
      eparblk.param_count = 0
      return eparblk
  if not re.match(b'^[0-9a-zA-z\[\]\(\)\{\} .,:*#_-]+$', eparblk_name_btarr):
      eparblk.param_count = 0
      return eparblk
  if (po.verbose > 2):
      print("{}: Found entry '{:s}'".format(po.mdlfile,eparblk_name_btarr.decode('UTF-8')))
  return eparblk

def flyc_parameter_blocks_pos_search(po, fwmdlfile, start_pos, func_align, data_align, ver):
  """ Finds position of flight controller parameter blocks in the binary.
      Searches only for specific version of the parameters format.
  """
  fwmdlfile.seek(0, os.SEEK_END)
  fwmdlfile_len = fwmdlfile.tell()
  matches = dict()
  match_entries = 0
  pos = start_pos
  while (True):
      entry_count = 0
      eparblk = flyc_check_parameter_block_at(po, fwmdlfile, fwmdlfile_len, pos, func_align, data_align, ver)
      if (eparblk.param_count > 0):
          # Check how many correct parameter entries we have
          match_pos = eparblk.params - po.baseaddr
          entry_count = flyc_check_parameter_array_at(po, fwmdlfile, fwmdlfile_len, match_pos, func_align, data_align, ver)
          # If entry is ok, add it to the list
          if entry_count >= eparblk.param_count:
              if (po.verbose > 1):
                  print("{}: Matching parameter block at 0x{:08x}: {:d} entries, format {:d}".format(po.mdlfile,pos,entry_count,ver))
              matches[match_pos] = entry_count
              match_entries += entry_count
          elif entry_count > 0:
              if (po.verbose > 1):
                  print("{}: Skipped parameter block at 0x{:08x} which was close to matching, format {:d}".format(po.mdlfile,pos,ver))
              entry_count = 0
      # Set position to search for next entry
      if entry_count > 0:
          pos += sizeof(eparblk)
      else:
          pos += data_align
      # Stop if we're at EOF
      if (pos + sizeof(eparblk) > fwmdlfile_len):
          break
  if (len(matches) > 1):
      eprint("{}: Found {:d} parameter blocks with alignment 0x{:02x}".format(po.mdlfile,len(matches),data_align))
  return matches, match_entries

def flyc_parameter_array_pos_search_any(po, fwmdlfile, start_pos, func_align, data_align):
  """ Finds position of flight controller parameters in the binary, in any version.
  """
  (poslist, count) = flyc_parameter_array_pos_search(po, fwmdlfile, start_pos, func_align, data_align, 2015)
  ver = 2015
  (poslist_2017, count_2017) = flyc_parameter_array_pos_search(po, fwmdlfile, start_pos, func_align, data_align, 2017)
  if count < count_2017:
      ver = 2017
      poslist = poslist_2017
      count = count_2017
  (poslist_2018, count_2018) = flyc_parameter_blocks_pos_search(po, fwmdlfile, start_pos, func_align, data_align, 2018)
  if count < count_2018:
      ver = 2018
      poslist = poslist_2018
      count = count_2018
  return poslist, ver

def flyc_param_get(po, fwmdlfile, param_pos, index, ver):
  """ Returns array with properties of given flight parameter.
  """
  parprop = {'index': index, 'typeID' : 0, 'size' : 0, 'attribute' : 0,
    'minValue' : 0, 'maxValue' : 0, 'defaultValue' : 0, 'name' : "" , 'modify' : False}
  eexpar = FlycExportParamFactory(ver)
  fwmdlfile.seek(param_pos+sizeof(eexpar)*index, os.SEEK_SET)
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
  fwmdlfile.seek(eexpar.nameptr - po.baseaddr, os.SEEK_SET)
  parprop['name'] = fwmdlfile.read(256).split(b'\0',1)[0].decode('UTF-8')
  # Read property alias name
  if hasattr(eexpar, 'aliasptr') and (eexpar.aliasptr > 0):
      fwmdlfile.seek(eexpar.aliasptr - po.baseaddr, os.SEEK_SET)
      parprop['alias'] = fwmdlfile.read(256).split(b'\0',1)[0].decode('UTF-8')
  if ((eexpar.attribute & 0x0B) == 0x0B): # Just a guess
      parprop['modify'] = True
  return parprop

def flyc_param_set_type(po, fwmdlfile, param_pos, index, parprop, ver):
  """ Updates parameter of given index with type from given parprop array.
  """
  raise NotImplementedError('Changing variable type is dangerous; this is not supported.')

def flyc_param_set_attribs(po, fwmdlfile, param_pos, index, parprop, ver):
  """ Updates parameter of given index with attribs from given parprop array.
  """
  eexpar = FlycExportParamFactory(ver)
  fwmdlfile.seek(param_pos+sizeof(eexpar)*index, os.SEEK_SET)
  if fwmdlfile.readinto(eexpar) != sizeof(eexpar):
      raise EOFError("Cannot read parameter entry.")
  eexpar.attribute = parprop['attribute']
  fwmdlfile.seek(param_pos+sizeof(eexpar)*index, os.SEEK_SET)
  fwmdlfile.write((c_ubyte * sizeof(eexpar)).from_buffer_copy(eexpar))

def flyc_param_set_limits(po, fwmdlfile, param_pos, index, parprop, ver):
  """ Updates parameter of given index with limits from given parprop array.
  """
  eexpar = FlycExportParamFactory(ver)
  fwmdlfile.seek(param_pos+sizeof(eexpar)*index, os.SEEK_SET)
  if fwmdlfile.readinto(eexpar) != sizeof(eexpar):
      raise EOFError("Cannot read parameter entry.")
  if flyc_param_limit_unsigned_int(po, eexpar):
     eexpar.limit_u.min = flyc_param_limit_to_type(po, ver, eexpar.type_id, parprop['minValue'])
     eexpar.limit_u.max = flyc_param_limit_to_type(po, ver, eexpar.type_id, parprop['maxValue'])
     eexpar.limit_u.deflt = flyc_param_limit_to_type(po, ver, eexpar.type_id, parprop['defaultValue'])
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
     eexpar.limit_i.min = flyc_param_limit_to_type(po, ver, eexpar.type_id, parprop['minValue'])
     eexpar.limit_i.max = flyc_param_limit_to_type(po, ver, eexpar.type_id, parprop['maxValue'])
     eexpar.limit_i.deflt = flyc_param_limit_to_type(po, ver, eexpar.type_id, parprop['defaultValue'])
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
     eexpar.limit_f.min = flyc_param_limit_to_type(po, ver, eexpar.type_id, parprop['minValue'])
     eexpar.limit_f.max = flyc_param_limit_to_type(po, ver, eexpar.type_id, parprop['maxValue'])
     eexpar.limit_f.deflt = flyc_param_limit_to_type(po, ver, eexpar.type_id, parprop['defaultValue'])
     eexpar.limit_i.min = flyc_param_limit_to_type(po, ver, ParamType.long, parprop['minValue'])
     eexpar.limit_i.max = flyc_param_limit_to_type(po, ver, ParamType.long, parprop['maxValue'])
     eexpar.limit_i.deflt = flyc_param_limit_to_type(po, ver, ParamType.long, parprop['defaultValue'])
     eexpar.limit_u.min = c_uint(eexpar.limit_i.min).value
     eexpar.limit_u.max = c_uint(eexpar.limit_i.max).value
     eexpar.limit_u.deflt = c_uint(eexpar.limit_i.deflt).value
     if (not isclose(eexpar.limit_f.min, float(parprop['minValue']), rel_tol=1e-5, abs_tol=1e-5)):
       eprint("{}: Warning: min value {:f} bound to {:f}".format(po.mdlfile,float(parprop['minValue']),eexpar.limit_f.min))
     if (not isclose(eexpar.limit_f.max, float(parprop['maxValue']), rel_tol=1e-5, abs_tol=1e-5)):
       eprint("{}: Warning: max value {:f} bound to {:f}".format(po.mdlfile,float(parprop['maxValue']),eexpar.limit_f.max))
     if (not isclose(eexpar.limit_f.deflt, float(parprop['defaultValue']), rel_tol=1e-5, abs_tol=1e-5)):
       eprint("{}: Warning: dafault value {:f} bound to {:f}".format(po.mdlfile,float(parprop['defaultValue']),eexpar.limit_f.deflt))
  fwmdlfile.seek(param_pos+sizeof(eexpar)*index, os.SEEK_SET)
  fwmdlfile.write((c_ubyte * sizeof(eexpar)).from_buffer_copy(eexpar))

def flyc_list(po, fwmdlfile):
  (po.param_poslist, po.param_ver) = flyc_parameter_array_pos_search_any(po, fwmdlfile, 0, po.expect_func_align, po.expect_data_align)
  if len(po.param_poslist) <= 0:
      raise ValueError("Flight controller parameters array signature not detected in input file.")
  full_index = 0
  for param_pos, param_count in po.param_poslist.items():
      if (po.verbose > 1):
        print("{}: Listing parameters array at 0x{:08x}: {:d} entries".format(po.mdlfile,param_pos,param_count))
      for i in range(0,param_count):
        parprop = flyc_param_get(po, fwmdlfile, param_pos, i, po.param_ver)
        parprop['index'] = full_index
        print("{:3d} {:40s} {:2d} {:2d} 0x{:x} {:6.1f} {:6.1f} {:6.1f}".format(parprop['index'],parprop['name'],parprop['typeID'],parprop['size'],parprop['attribute'],parprop['minValue'],parprop['maxValue'],parprop['defaultValue']))
        full_index += 1

def flyc_extract(po, fwmdlfile):
  """ Extracts all flight controller parameters from firmware to JSON format text file.
  """
  (po.param_poslist, po.param_ver) = flyc_parameter_array_pos_search_any(po, fwmdlfile, 0, po.expect_func_align, po.expect_data_align)
  if len(po.param_poslist) <= 0:
      raise ValueError("Flight controller parameters array signature not detected in input file.")
  inffile = open(po.inffile, "w")
  inffile.write("[\n")
  full_index = 0
  for param_pos, param_count in po.param_poslist.items():
      if (po.verbose > 1):
          print("{}: Extracting parameters array at 0x{:08x}: {:d} entries".format(po.mdlfile,param_pos,param_count))
      for i in range(0,param_count):
          parprop = flyc_param_get(po, fwmdlfile, param_pos, i, po.param_ver)
          parprop['index'] = full_index
          if (full_index != 0):
              inffile.write(",\n")
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
          for ppname in ('alias',):
              if not ppname in parprop: continue
              inffile.write(",\n")
              inffile.write("\t\t\"{:s}\" : \"{:s}\"".format(ppname,parprop[ppname]))
          if parprop['modify']:
              inffile.write(",\n")
              inffile.write("\t\t\"{:s}\" : {:s}".format('modify','true'))
          inffile.write("\n")
          inffile.write("\t}")
          full_index += 1
  inffile.write("\n")
  inffile.write("]\n")
  inffile.close()

def flyc_update(po, fwmdlfile):
  """ Updates all flight controller parameters in firmware from JSON format text file.
  """
  (po.param_poslist, po.param_ver) = flyc_parameter_array_pos_search_any(po, fwmdlfile, 0, po.expect_func_align, po.expect_data_align)
  if len(po.param_poslist) <= 0:
      raise ValueError("Flight controller parameters array signature not detected in input file.")
  with open(po.inffile) as inffile:
      nxparprops = json.load(inffile)
  update_count = 0
  full_index = 0
  param_pos_start_index = 0
  for param_pos, param_count in po.param_poslist.items():
      if (po.verbose > 1):
          print("{}: Updating parameters array at 0x{:08x}: {:d} entries".format(po.mdlfile,param_pos,param_count))
      # Remember full index which corresponds to param_pos
      param_pos_start_index = full_index
      for i in range(0, param_count):
          # get the param from binary file
          pvparprop = flyc_param_get(po, fwmdlfile, param_pos, i, po.param_ver)
          pvparprop['index'] = full_index
          # find it in our update list
          nxparprop = None
          for parprop in nxparprops:
              if (parprop['name'] == pvparprop['name']):
                  nxparprop = parprop
                  break
          if (nxparprop is None):
              eprint("{}: Warning: parameter not found in fw: \"{:s}\"".format(po.mdlfile,pvparprop['name']))
              continue
          # compare properties to check what we want to update
          update_type = False
          update_attrib = False
          update_limits = False # limits are: min, default, max value
          for ppname in ('typeID', 'size'):
              if (pvparprop[ppname] != nxparprop[ppname]):
                  update_type = True
                  update_limits = True
          for ppname in ('attribute',):
              if (pvparprop[ppname] != nxparprop[ppname]):
                  update_attrib = True
          for ppname in ('minValue', 'maxValue', 'defaultValue'):
              if (isinstance(pvparprop[ppname], float)):
                  if (not isclose(pvparprop[ppname], nxparprop[ppname], rel_tol=1e-5, abs_tol=1e-5)):
                      #print("{}: Prop \"{:s}\" {:s} test: {:s} vs {:s}".format(po.mdlfile,pvparprop['name'],ppname,str(pvparprop[ppname]),str(nxparprop[ppname])))
                      update_limits = True
              else:
                  if (pvparprop[ppname] != nxparprop[ppname]):
                      #print("{}: Prop \"{:s}\" {:s} test: {:s} vs {:s}".format(po.mdlfile,pvparprop['name'],ppname,str(pvparprop[ppname]),str(nxparprop[ppname])))
                      update_limits = True
          if (update_type or update_attrib or update_limits):
              if (po.verbose > 1):
                  print("{}: Updating \"{:s}\" {:s}{:s}{:s}".format(po.mdlfile,pvparprop['name']," type," if update_type else ""," attribs," if update_attrib else ""," limits," if update_limits else ""))
              update_count += 1
          # use index local to block, not the global index stored within property
          pvparprop_i = pvparprop['index'] - param_pos_start_index
          # do the update
          if (update_type):
              flyc_param_set_type(po, fwmdlfile, param_pos, pvparprop_i, nxparprop, po.param_ver)
          if (update_attrib):
              flyc_param_set_attribs(po, fwmdlfile, param_pos, pvparprop_i, nxparprop, po.param_ver)
          if (update_limits):
              flyc_param_set_limits(po, fwmdlfile, param_pos, pvparprop_i, nxparprop, po.param_ver)
          full_index += 1
  if (po.verbose > 0):
      print("{}: Updated {:d} parameter entries".format(po.mdlfile,update_count))

def main():
  """ Main executable function.

  Its task is to parse command line options and call a function which performs requested command.
  """
  # Parse command line options

  parser = argparse.ArgumentParser(description=__doc__)

  parser.add_argument("-m", "--mdlfile", type=str, required=True,
          help="Flight controller firmware binary module file")

  parser.add_argument("-i", "--inffile", type=str, default="flyc_param_infos",
          help="Flight Parameter Info JSON file name (default is \"%(default)s\")")

  parser.add_argument("-b", "--baseaddr", default=0x8020000, type=lambda x: int(x,0),
          help="Set base address; crucial for finding the array (default is 0x%(default)X)")

  parser.add_argument("--bssaddr", default=0x20000000, type=lambda x: int(x,0),
          help="Set .bss start address; set to address where RAM starts (default is 0x%(default)X)")

  parser.add_argument("--bsslen", default=0x4400000, type=lambda x: int(x,0),
          help="Set .bss length; set to size of RAM (default is 0x%(default)X)")

  parser.add_argument("-v", "--verbose", action="count", default=0,
          help="Increases verbosity level; max level is set by -vvv")

  subparser = parser.add_mutually_exclusive_group()

  subparser.add_argument("-l", "--list", action="store_true",
          help="list parameters stored in the firmware")

  subparser.add_argument("-x", "--extract", action="store_true",
          help="Extract parameters array to infos json text file")

  subparser.add_argument("-u", "--update", action="store_true",
          help="Update parameters array in binary fw from infos text file")

  subparser.add_argument("--version", action='version', version="%(prog)s {version} by {author}"
            .format(version=__version__,author=__author__),
          help="Display version information and exit")

  po = parser.parse_args()

  po.expect_func_align = 4
  po.expect_data_align = 2
  po.param_poslist = {}
  po.param_ver = 2015

  if po.list:

    if (po.verbose > 0):
      print("{}: Opening for list display".format(po.mdlfile))
    fwmdlfile = open(po.mdlfile, "rb")

    flyc_list(po,fwmdlfile)

    fwmdlfile.close();

  elif po.extract:

    if (po.verbose > 0):
      print("{}: Opening for extraction".format(po.mdlfile))
    fwmdlfile = open(po.mdlfile, "rb")

    flyc_extract(po,fwmdlfile)

    fwmdlfile.close();

  elif po.update:

    if (po.verbose > 0):
      print("{}: Opening for update".format(po.mdlfile))
    fwmdlfile = open(po.mdlfile, "r+b")

    flyc_update(po,fwmdlfile)

    fwmdlfile.close();

  else:

    raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        eprint("Error: "+str(ex))
        #raise
        sys.exit(10)
