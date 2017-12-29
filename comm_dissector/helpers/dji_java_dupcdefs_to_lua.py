#!/usr/bin/env python3

""" Java Classes with Packet Definitions parser, with Wireshark LUA out

If you don't know what this tool is, you most likely don't need it.

Input for this file is a decompiled Dji Go app, or other app with packets definitions.

"""

from __future__ import print_function
import sys
import getopt
import os
import enum
import re

def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

class ProgOptions:
  cmdsetfile = ''
  luafile = ''
  verbose = 0
  product = 'dji_mavic'
  command = ''

class RPropType(enum.IntEnum):
  none = 0
  int8_t = 1
  int16_t = 2
  int24_t = 3
  int32_t = 4
  int64_t = 5
  uint8_t = 6
  uint16_t = 7
  uint24_t = 8
  uint32_t = 9
  uint64_t = 10
  fp16 = 11
  fp32 = 12
  fp64 = 13
  expr = 14

class RecProp:
  def __init__(self):
      self.name = ''
      self.pos = 0
      self.ntype = RPropType.none
      self.base_type = RPropType.none
      self.arrlen = 0
      self.val = ''
      self.comment = ''

class RecStruct:
  def __init__(self):
      self.name = ''
      self.package = ''
      self.category = ''
      self.cmdset = 0
      self.cmdidx = 0
      self.props = []

class JavaFunc:
  def __init__(self):
      self.name = ''
      self.rettype = ''
      self.params = []
      self.body = []

def prop_type_len(ntype):
  arr =[0, 1, 2, 3, 4, 8, 1, 2, 3, 4, 8, 2, 4, 8, 0]
  return arr[ntype]

def prop_len(prop):
  if (prop.arrlen > 0):
      return prop_type_len(prop.base_type) * prop.arrlen
  else:
      return prop_type_len(prop.base_type)

def prop_typestr_to_ntype(typestr):
  sstr = typestr.strip().lower()
  # alternate names first
  arr2 =["na", "int8", "int16", "int24", "int32", "int64", "uint8", "uint16", "uint24", "uint32", "uint64", "lofloat", "float", "double", "ex"]
  if sstr in arr2:
      return arr2.index(sstr)
  # now the proper name search
  arr =["none", "int8_t", "int16_t", "int24_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint24_t", "uint32_t", "uint64_t", "fp16", "fp32", "fp64", "expr"]
  return arr.index(sstr)

def java_typestr_to_ntype(nbytes, typestr):
  sstr = typestr.strip().lower()+str(int(nbytes)*8)
  # alternate names first
  arr3 =["na0", "integer8", "integer16", "integer24", "integer32", "integer64", "uint8", "uint16", "uint24", "uint32", "uint64", "float16", "float32", "double64", "ex0"]
  if sstr in arr3:
      return arr3.index(sstr)
  arr2 =["na0", "short8", "short16", "short24", "short32", "short64", "uint8", "uint16", "uint24", "uint32", "uint64", "float16", "float32", "double64", "ex0"]
  if sstr in arr2:
      return arr2.index(sstr)
  arr1 =["na0", "long8", "long16", "long24", "long32", "long64", "ulong8", "ulong16", "ulong24", "ulong32", "ulong64", "float16", "float32", "double64", "ex0"]
  if sstr in arr1:
      return arr1.index(sstr)
  return 0

def cmdset_short_name_str(cmdset):
  arr =["general", "special", "camera", "flyc", "gimbal", "center_brd", "rc", "wifi", "dm36x", "hd_link", "mbino", "sim", "esc", "battery", "data_log", "rtk", "auto"]
  return arr[cmdset]

def cmdset_long_name_str(cmdset):
  arr =["General", "Special", "Camera", "Flight Controller", "Gimbal", "Center Board", "Remote Control", "Wi-Fi",
    "DM36x proc.", "HD Link", "Mono/Binocular", "Simulation", "El. Speed Ctrl.", "Battery", "Data Logger", "RTK", "Automation"]
  return arr[cmdset]

_underscorer1 = re.compile(r'(.)([A-Z][a-z]+)')
_underscorer2 = re.compile('([a-z0-9])([A-Z])')

def camel_to_snake(s):
    """ 
    Converts to snake case.
    Original author: Jay Taylor [@jtaylor]
    """
    subbed = _underscorer1.sub(r'\1_\2', s)
    return _underscorer2.sub(r'\1_\2', subbed).lower()

def mask_to_shift_and_base(whole_mask):
    offset = 0
    while ((whole_mask >> offset) & 1) == 0:
        offset += 1
    mask_shift = offset
    while ((whole_mask >> offset) & 1) == 1:
        offset += 1
    mask_bits = offset - mask_shift
    mask_base = 0
    i = 0
    while i < mask_base:
        mask_base = (mask_base << 1) | 1
        i += 1
    return mask_shift, mask_base

def java_cmdset_parse(po, cmdsetfile):
  """
Parses command set file and gets class names for each cmdset from an enum like:
```
public enum p {
    a(0, new d()),
    b(1, (a)new n()),
    c(2, new b()),
```
  """
  setslist = [None]*16
  i = 0;
  bad_found = -1
  for line in cmdsetfile:
      i += 1
      # Find the enum head
      if bad_found == -1:
          match = re.search("^[ \t]*public enum ([A-Za-z0-9._-]+) \{$", line)
          if match:
              bad_found = 0
          continue
      if bad_found > 5:
          break
      match = re.search("^[ \t]*([A-Za-z0-9._-]+)\(([0-9.-]+), (\([A-Za-z0-9._-]+\))?new ([A-Za-z0-9._-]+)\(\)\)[,;]$", line)
      if match:
          if (po.verbose > 2):
              print("{}: Found CmdSet {} class '{}'".format(po.cmdsetfile,match.group(2),match.group(4)))
          idx = int(match.group(2))
          setclass = match.group(4)
          setslist[idx] = setclass
          bad_found = 0
      else:
          # Check if this is a correct list entry, but empty
          match = re.search("^[ \t]*([A-Za-z0-9._-]+)\(([0-9.-]+)\)[,;]$", line)
          if match:
              if (po.verbose > 2):
                  print("{}: Found CmdSet {} with empty class".format(po.cmdsetfile,match.group(2)))
          else:
              bad_found += 1

  if (po.verbose > 1):
      if bad_found == -1:
          print("{}: Finished parsing '{}' entries, no enum header found".format(po.cmdsetfile,"CmdSet"))
      else:
          print("{}: Finished parsing '{}' entries, found {}".format(po.cmdsetfile,"CmdSet",len(setslist) - setslist.count(None)))
  if (po.verbose > 2):
      print("{}: Parsing stopped at line {}".format(po.cmdsetfile,i))

  return setslist

def java_cmdlists_parse(po, setslist):
  reclist = []
  for cmdset, setclass in enumerate(setslist):
      if setclass is None:
          continue
      cmdfile = open(os.path.dirname(po.cmdsetfile)+"/"+setclass+".java", "r")
      cmdslist = java_cmd_parse(po,cmdfile)
      cmdfile.close();
      for cmd, cmdclass in enumerate(cmdslist):
          if cmdclass is None:
              continue
          rst = RecStruct()
          rst.cmdset = cmdset
          rst.cmdidx = cmd
          rst.package = cmdclass
          # Get class name from package
          tmp1_name = cmdclass[cmdclass.rindex('.')+1:]
          # Get packet type naame from the class name
          if (True):
              tmp2_name = tmp1_name.replace("GetPush","")
          if (tmp1_name == tmp2_name):
              tmp2_name = tmp2_name.replace("SetGet","")
          if (tmp1_name == tmp2_name):
              tmp2_name = tmp2_name.replace("Get","")
          if (tmp1_name == tmp2_name):
              tmp2_name = tmp2_name.replace("Push","")
          if (tmp1_name == tmp2_name):
              tmp2_name = tmp2_name.replace("Set","")
          if (tmp2_name.startswith("Data")):
              tmp2_name = tmp2_name[4:]
          # Store in snake case
          rst.name = camel_to_snake(tmp2_name)
          rst.category = "config"
          reclist.append(rst)

  return reclist

def java_cmd_parse(po, cmdfile):
  """
Parses command file and gets class names for each cmd from an enum like:
```
    public static enum a {
        a(1, false, DataEyeGetPushLog.class),
        b(6, false, DataEyeGetPushAvoidanceParam.class),
        c(7, false, DataEyeGetPushFrontAvoidance.class),
```
  """
  cmdslist = [None]*512
  pkgslist = []
  if (po.verbose > 2):
      print("{}: Parsing started".format(cmdfile.name))
  i = 0;
  bad_found = -1
  for line in cmdfile:
      i += 1
      # Find the enum head
      if bad_found == -1:
          match = re.search("^[ \t]*public static enum ([A-Za-z0-9._-]+) \{$", line)
          if match:
              bad_found = 0
              continue
          # Find list of imported packages, to make sure we can locate each class with path
          match = re.search("^[ \t]*import[ \t]+dji[.]([A-Za-z0-9._-]+);$", line)
          if match:
              pkgslist.append(match.group(1))
          continue
      if bad_found > 5:
          break
      match = re.search("^[ \t]*([A-Za-z0-9._-]+)\(([0-9.-]+),[ \t]*(false,|true,)?[ \t]*(false,|true,)?[ \t]*([A-Za-z0-9._-]+)[.]class.*\)[,;]$", line)
      if match:
          if (po.verbose > 2):
              print("{}: Found Cmd {} class '{}'".format(cmdfile.name,match.group(2),match.group(5)))
          idx = int(match.group(2))
          setclass = match.group(5)
          setpkg = os.path.dirname(po.cmdsetfile).replace("/config/","/model/") + "/" + setclass
          # Find full package path for the class
          for pkg in pkgslist:
              if pkg.endswith("."+setclass):
                  setpkg = pkg
                  break
          cmdslist[idx] = setpkg
          bad_found = 0
      else:
          # Check if this is a correct list entry, but empty
          match = re.search("^[ \t]*([A-Za-z0-9._-]+)\(([0-9.-]+)\)[,;]$", line)
          if match:
              if (po.verbose > 3):
                  print("{}: Found Cmd {} with empty class".format(cmdfile.name,match.group(2)))
          else:
              bad_found += 1

  if (po.verbose > 1):
      if bad_found == -1:
          print("{}: Finished parsing '{}' entries, no enum header found".format(cmdfile.name,"Cmd"))
      else:
          print("{}: Finished parsing '{}' entries, found {}".format(cmdfile.name,"Cmd",len(cmdslist) - cmdslist.count(None)))
  if (po.verbose > 2):
      print("{}: Parsing stopped at line {}".format(cmdfile.name,i))

  return cmdslist


def java_dupc_classlist_parse(po, reclist):
  for rst in reclist:
      # Package name can be easily converted to file name
      clsfile = open(rst.package.replace(".","/")+".java", "r")
      java_dupc_class_parse(po, rst, clsfile)
      clsfile.close();
  return reclist

def java_dupc_class_parse(po, rst, clsfile):
  """
This function is far from being remotely comatible with Java syntax.
But as long as it gets standard decompiler output, it will work.
  """
  if (po.verbose > 2):
      print("{}: Parsing started".format(clsfile.name))
  func = JavaFunc()
  func_blocks = 0
  i = 0;
  for line in clsfile:
      i += 1
      if (func_blocks < 1):
          # Find new function start
          match = re.search("^[ \t]*(public[ \t]+|private[ \t]+|protected[ \t]+)?(static[ \t]+)?([A-Za-z0-9._-]+)[ \t]+([A-Za-z0-9._-]+)\(([A-Za-z0-9., _-]*)\)[ \t]+\{", line)
          if match:
              func = JavaFunc()
              func.name = match.group(4)
              func.rettype = match.group(3)
              func.params = match.group(5).split(",")
              map(str.strip, func.params)
              func_blocks = 1
              if (po.verbose > 2):
                  print("{}: Found function '{}'".format(clsfile.name,func.name))
              continue
          # Not a function - ignore
          continue
      # Ignore empty lines
      if len(str.strip(line)) < 1:
          continue
      func_blocks += line.count("{")
      func_blocks -= line.count("}")
      if (func_blocks < 1):
          ending_line = line[:line.rindex('}')].strip()
          if len(ending_line) > 0:
              func.body.append(ending_line)
          func_blocks = 0
          # Function ended - now it's time to analyze the body
          prop = java_func_to_property(po, clsfile.name, rst, func)
          if prop is not None:
              rst.props.append(prop)
              continue
          if (po.verbose > 3):
              for bodyline in func.body:
                  print("{}: BODY: {}".format(clsfile.name,bodyline))
          continue
      func.body.append(line.strip())
  return rst

def java_func_to_property(po, fname, rst, func):
  if len(func.body) < 1:
      return None
  func_nice_body = []
  for line in func.body:
      # Remove lines like: if (this._recData == null) return DataSingleSetPointPos.TapMode.a;
      match = re.search("^if \(this[.]_recData == null\) return .*;$", line)
      if match:
          continue
      # Remove lines like: if (this._recData.length <= 20) return DataSingleSetPointPos.TapMode.a;
      match = re.search("^if \(this[.]_recData.length <= .*\) return .*;$", line)
      if match:
          continue
      func_nice_body.append(line)

  if len(func_nice_body) == 1:
      # Check known one-liners
      line = func_nice_body[0]
      if True:
          # Example 1: return (Integer)this.get(1, 1, Integer.class) >> 4 & 15;
          match = re.search("^return [\(]?(\([A-Za-z0-9._]+\))?this[.]get\(([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+).class\)[\)]?( >>[>]? ([A-Za-z0-9._-]+))? & ([A-Za-z0-9._-]+);$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(2))
              prop_dsize = match.group(3)
              prop_dtype = match.group(4)
              tmp1_name = func.name
              if (tmp1_name.startswith("get")):
                  tmp1_name = tmp1_name[3:]
              prop.name = camel_to_snake(tmp1_name)
              bit_mask_shift = int(match.group(6) or "0")
              bit_mask_base = int(match.group(7))
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = RPropType.expr
              # Convert negative bitmasks to proper positive ones
              if bit_mask_base < 0: bit_mask_base = (~bit_mask_base) & (pow(2,prop_type_len(prop.base_type)*8)-1)
              prop.val = "bitand(shift_r({},{}),{})".format("auto_detect_name",bit_mask_shift,bit_mask_base)
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              return prop
          # Example 1: return (this.get(2, 1, Integer.class) & 240) >>> 4;
          match = re.search("^return [\(]?(\([A-Za-z0-9._]+\))?this[.]get\(([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+).class\)( & ([A-Za-z0-9._-]+))?[\)]? >>[>]? ([A-Za-z0-9._-]+);$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(2))
              prop_dsize = match.group(3)
              prop_dtype = match.group(4)
              tmp1_name = func.name
              if (tmp1_name.startswith("get")):
                  tmp1_name = tmp1_name[3:]
              prop.name = camel_to_snake(tmp1_name)
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = RPropType.expr
              bit_mask_shift = int(match.group(7))
              bit_mask_base = int(match.group(6) or (pow(2,prop_type_len(prop.base_type)*8)-1)) >> bit_mask_shift
              # Convert negative bitmasks to proper positive ones
              if bit_mask_base < 0: bit_mask_base = (~bit_mask_base) & (pow(2,prop_type_len(prop.base_type)*8)-1)
              prop.val = "bitand(shift_r({},{}),{})".format("auto_detect_name",bit_mask_shift,bit_mask_base)
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              return prop
          # Example 1: return (Integer)this.get(this.dataOffset + 1, 1, Integer.class);
          match = re.search("^return [\(]?(\([A-Za-z0-9._]+\))?this[.]get\(([A-Za-z0-9._-]+) \+ ([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+).class\)[\)]?;$", line)
          if match:
              prop = RecProp()
              prop_pos_shift = match.group(2)
              prop.pos = int(match.group(3))
              prop_dsize = match.group(4)
              prop_dtype = match.group(5)
              tmp1_name = func.name
              if (tmp1_name.startswith("get")):
                  tmp1_name = tmp1_name[3:]
              prop.name = camel_to_snake(tmp1_name)
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = prop.base_type
              prop.comment = "Offset shifted by unknown value {}".format(prop_pos_shift)
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              return prop
          # Example 1: return (Integer)this.get(4, 1, Integer.class);
          # Example 2: return ((Float)this.get(16, 4, Float.class)).floatValue();
          # Example 3: return (Integer)this.get(0, 1, Integer.class) - 256;
          match = re.search("^return [\(]?(\([A-Za-z0-9._]+\))?this[.]get\(([A-Za-z0-9._]+), ([A-Za-z0-9._]+), ([A-Za-z0-9._]+).class\)[\)]?([.][A-Za-z0-9._]+Value\(\))?( - ([A-Za-z0-9._]+))?;$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(2))
              prop_dsize = match.group(3)
              prop_dtype = match.group(4)
              prop_bias = match.group(6)
              tmp1_name = func.name
              if (tmp1_name.startswith("get")):
                  tmp1_name = tmp1_name[3:]
              prop.name = camel_to_snake(tmp1_name)
              #prop.val = 
              #prop.comment = 
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = prop.base_type
              if (prop_bias is not None): prop.comment = "value bias {}".format(prop_bias)
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              return prop
          # Example 1: return AdvanceGoHomeState.find(this.get(4, 2, Integer.class) >> 2 & 7);
          match = re.search("^return [\(]?(\([A-Za-z0-9._]+\))?([A-Za-z0-9._]+)[.]find\((\([A-Za-z0-9._]+\))?this[.]get\(([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+).class\)( >>[>]? ([A-Za-z0-9._-]+))? & ([A-Za-z0-9._-]+)\)[\)]?;$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(4))
              prop_enum_name = match.group(2)
              prop_dsize = match.group(5)
              prop_dtype = match.group(6)
              tmp1_name = func.name
              if (tmp1_name.startswith("get")):
                  tmp1_name = tmp1_name[3:]
              prop.name = camel_to_snake(tmp1_name)
              bit_mask_shift = int(match.group(8) or "0")
              bit_mask_base = int(match.group(9))
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = RPropType.expr
              prop.comment = "TODO values from enum {}".format(prop_enum_name)
              # Convert negative bitmasks to proper positive ones
              if bit_mask_base < 0: bit_mask_base = (~bit_mask_base) & (pow(2,prop_type_len(prop.base_type)*8)-1)
              prop.val = "bitand(shift_r({},{}),{})".format("auto_detect_name",bit_mask_shift,bit_mask_base)
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              return prop
          # Example 1: return PreciseLandingState.find((this.get(6, 2, Integer.class) & 6) >> 1);
          match = re.search("^return [\(]?(\([A-Za-z0-9._]+\))?([A-Za-z0-9._]+)[.]find\([\(]?(\([A-Za-z0-9._]+\))?this[.]get\(([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+).class\)( & ([A-Za-z0-9._-]+)\))? >>[>]? ([A-Za-z0-9._-]+)\)[\)]?;$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(4))
              prop_enum_name = match.group(2)
              prop_dsize = match.group(5)
              prop_dtype = match.group(6)
              tmp1_name = func.name
              if (tmp1_name.startswith("get")):
                  tmp1_name = tmp1_name[3:]
              prop.name = camel_to_snake(tmp1_name)
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = RPropType.expr
              bit_mask_shift = int(match.group(9))
              bit_mask_base = int(match.group(8) or (pow(2,prop_type_len(prop.base_type)*8)-1)) >> bit_mask_shift
              prop.comment = "TODO values from enum {}".format(prop_enum_name)
              # Convert negative bitmasks to proper positive ones
              if bit_mask_base < 0: bit_mask_base = (~bit_mask_base) & (pow(2,prop_type_len(prop.base_type)*8)-1)
              prop.val = "bitand(shift_r({},{}),{})".format("auto_detect_name",bit_mask_shift,bit_mask_base)
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              return prop
          # Example 1: return VisionSensorType.find((Integer)this.get(2, 1, Integer.class));
          match = re.search("^return [\(]?(\([A-Za-z0-9._]+\))?([A-Za-z0-9._]+)[.]find\((\([A-Za-z0-9._]+\))?this[.]get\(([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+).class\)\)[\)]?;$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(4))
              prop_enum_name = match.group(2)
              prop_dsize = match.group(5)
              prop_dtype = match.group(6)
              tmp1_name = func.name
              if (tmp1_name.startswith("get")):
                  tmp1_name = tmp1_name[3:]
              prop.name = camel_to_snake(tmp1_name)
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = prop.base_type
              prop.comment = "TODO values from enum {}".format(prop_enum_name)
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              return prop

  if len(func_nice_body) == 2:
      line = func_nice_body[1]
      # Check for a 2-liner which returns bool
      match = re.search("^return (true|false);$", line)
      if match:
          line = func_nice_body[0]
          # Example 1: if ((Integer)this.get(0, 1, Integer.class) == 0) return false;
          match = re.search("^if \((\([A-Za-z0-9._]+\))?this.get\(([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+), ([A-Za-z0-9._]+).class\) ([=!]+) ([A-Za-z0-9._-]+)\) return (true|false);$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(2))
              prop_dsize = match.group(3)
              prop_dtype = match.group(4)
              prop_op = match.group(5)
              prop_val = int(match.group(6))
              prop_bool = match.group(7)
              tmp1_name = func.name
              if (tmp1_name.startswith("is")):
                  tmp1_name = tmp1_name[2:]
              prop_neg = False
              if (prop_op == "==") and (prop_val == 0):
                  prop_neg = (prop_bool == "true")
              elif (prop_op == "!=") and (prop_val == 0):
                  prop_neg = (prop_bool == "false")
              elif (prop_op == "==") and (prop_val == 1):
                  prop_neg = (prop_bool == "false")
              elif (prop_op == "!=") and (prop_val == 1):
                  prop_neg = (prop_bool == "true")
              else:
                  prop.comment = "Unrecognized conditions in {}".format(func.name)
                  eprint("{}: Unrecognized conditions combinationin bool function {}!".format(fname,func.name))
              prop.name = camel_to_snake(tmp1_name)
              if (prop_neg): prop.name = "not_"+prop.name
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = prop.base_type
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              return prop
          # Example 1: if (((Integer)this.get(1, 1, Integer.class) & 2) != 2) return false;
          # Example 2: if ((this.get(30, 1, Short.class) & 128) != 0) return false;
          # Example 3: if ((this.get(20, 2, Integer.class) & 16) >>> 4 == 0) return false;
          match = re.search("^if \(\((\([A-Za-z0-9._]+\))?this.get\(([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+), ([A-Za-z0-9._]+).class\) & ([A-Za-z0-9._-]+)\)( >>[>]? ([A-Za-z0-9._-]+))? ([=!]+) ([A-Za-z0-9._-]+)[\)] return (true|false);$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(2))
              prop_dsize = match.group(3)
              prop_dtype = match.group(4)
              prop_mask = int(match.group(5))
              #bit_mask_shift = int(match.group(7)) # No need - we will re-create the shift from shifted mask
              prop_op = match.group(8)
              prop_val = int(match.group(9))
              prop_bool = match.group(10)
              tmp1_name = func.name
              if (tmp1_name.startswith("is")):
                  tmp1_name = tmp1_name[2:]
              bit_mask_shift, bit_mask_base = mask_to_shift_and_base(prop_mask)
              prop.val = "bitand(shift_r({},{}),{})".format("auto_detect_name",bit_mask_shift,bit_mask_base)
              prop_neg = False
              if (prop_op == "==") and (prop_val == 0):
                  prop_neg = (prop_bool == "true")
              elif (prop_op == "!=") and (prop_val == 0):
                  prop_neg = (prop_bool == "false")
              elif (prop_op == "==") and (prop_val == prop_mask):
                  prop_neg = (prop_bool == "false")
              elif (prop_op == "!=") and (prop_val == prop_mask):
                  prop_neg = (prop_bool == "true")
              else:
                  prop.comment = "Unrecognized conditions in {}".format(func.name)
                  eprint("{}: Unrecognized conditions combinationin bool function {}!".format(fname,func.name))
              prop.name = camel_to_snake(tmp1_name)
              if (prop_neg): prop.name = "not_"+prop.name
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = RPropType.expr
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              return prop

  for line in func_nice_body:
      match = re.search("this[.]get\(", line)
      if match:
          eprint("{}: Function {} contains 'get' but its structure was not recognized!".format(fname,func.name))
          break
  return None

def java_dupc_reclist_linearize(po, reclist):
  for rst in reclist:
      # Sort by pos, but if there are several entries with same pos, place other than RPropType.expr first
      sorted_props = sorted(rst.props, key=lambda prop: prop.pos * 2 + (1 if prop.ntype == RPropType.expr else 0) )
      rst.props = []
      prv_prop = RecProp()
      prv_prop.name="unknown{:02X}".format(0)
      prv_prop.base_type = RPropType.uint8_t
      prv_prop.pos = -1
      pktpos = 0
      for prop in sorted_props:

          if pktpos < prop.pos:
              nprop = RecProp()
              nprop.pos = pktpos
              nprop.name = "unknown{:02X}".format(pktpos)
              nprop.base_type = RPropType.uint8_t
              nprop.ntype = nprop.base_type
              if prop.pos - pktpos > 1:
                  nprop.arrlen = prop.pos - pktpos
              rst.props.append(nprop)
              prv_prop = nprop
              pktpos += prop_len(prv_prop)

          if pktpos > prop.pos:
              # If we have properties with overlapping offsets, convert the current to expr.
              # Unless it is already expr, which would mean this is already done in previous stge of parsing.
              if prop.ntype != RPropType.expr:
                  # Convert current to expr
                  prop.val = "bitand(shift_r({},{}),{})".format(prv_prop.name,0,pow(2,prop_type_len(prop.base_type)*8)-1)
                  prop.ntype = RPropType.expr
              pktpos = prv_prop.pos

          if pktpos == prop.pos:
              # Each pack of expr entries should start with non-expr base prop at the same offset
              # If we have no non-expr base or phony prv_prop, and expr props started - create the non-expr base
              if (prv_prop.pos < prop.pos) and (prop.ntype == RPropType.expr):
                  # Create base property, without mask
                  bprop = RecProp()
                  bprop.pos = prop.pos
                  bprop.name = "masked{:02X}".format(prop.pos)
                  bprop.base_type = prop.base_type
                  bprop.ntype = bprop.base_type
                  rst.props.append(bprop)
                  prv_prop = bprop
                  pktpos += prop_len(prv_prop)

          # Auto detect property names which were not set in previous stge of parsing.
          if prop.ntype == RPropType.expr:
              prop.val = prop.val.replace("(auto_detect_name,","("+prv_prop.name+",")

          if prop.ntype != RPropType.expr:
              prv_prop = prop
              pktpos += prop_len(prv_prop)
          rst.props.append(prop)
          
  return reclist

class EnumEntry:
  def __init__(self, v, n):
      self.val = v
      self.idx = n

class LuaProtoField:
  def __init__(self, nbase, nfltr, nview, ncmdset_str, dtype, dstyle, dlen):
      self.name_base = nbase
      self.name_fltr = nfltr
      self.name_view = nview
      self.cmdset_str = ncmdset_str
      self.descr = ""
      self.dt_type = dtype
      self.dt_mask = -1
      self.dt_len = dlen
      self.dt_style = dstyle
      self.enum_vals = []
      self.subfields = []
      self.commented = False
  def format_lua_protofield_def(self, protocol_name):
      """ Format string containing LUA ProtoField definition
      """
      add_params = ['nil','nil','nil']
      if len(self.descr) > 0:
          add_params[2] = "\"" + self.descr + "\""
      if self.dt_mask > 0:
          add_params[1] = "0x{:02x}".format(self.dt_mask)
      if set(add_params) == set(['nil']):
          add_params_str = ""
      else:
          add_params_str = ", {}, {}, {}".format(add_params[0],add_params[1],add_params[2])
      return "{}f.{}_{} = ProtoField.{} (\"{}.{}_{}\", \"{}\", base.{}{})\n".format("--" if self.commented else "",
          self.cmdset_str, self.name_fltr, self.dt_type, protocol_name, self.cmdset_str, self.name_fltr, self.name_view,
          self.dt_style, add_params_str)
  def format_lua_protofield_inst(self, protocol_name):
      """ Format string containing LUA ProtoField instantiation
      """
      return "{}subtree:add_le (f.{}_{}, payload(offset, {}))\n".format("--" if self.commented else "", self.cmdset_str, self.name_fltr, self.dt_len)


def prop_best_lua_base(prop):
  if (prop.arrlen > 0):
      return "SPACE"
  arr =["NONE", "DEC", "DEC", "DEC", "DEC", "DEC", "HEX", "HEX", "HEX", "HEX", "HEX", "HEX", "DEC", "DEC", "NONE"]
  return arr[prop.ntype]

def prop_best_lua_proto_type(prop):
  if (prop.arrlen > 0):
      return "bytes"
  arr =["none", "int8", "int16", "int24", "int32", "int64", "uint8", "uint16", "uint24", "uint32", "uint64", "uint16", "float", "double", "none"]
  return arr[prop.ntype]

def recmsg_write_enum_lua(po, luafile, enum_list, enum_name, enum_modifier=""):
  if len(enum_modifier) > 0: enum_modifier += " "
  luafile.write("\n{}{} = {{\n".format(enum_modifier,enum_name))
  for enitm in enum_list:
      luafile.write("    [0x{:02x}] = {},\n".format(enitm.idx, enitm.val))
  luafile.write("}\n")

def recmsg_write_lua(po, luafile, reclist):
  luafile.write("local f = {}_PROTO.fields\n".format(po.product.upper()))

  alltext_list = []
  for cmdset in range(0,16):
      enitm = recmsg_write_cmdset_typetexts_lua(po, luafile, cmdset, reclist)
      alltext_list.append(enitm)
  recmsg_write_enum_lua(po, luafile, alltext_list, "{}_{}_TEXT".format(po.product.upper(),"UART_CMD"))

  alldiss_list = []
  for cmdset in range(0,16):
      enitm = recmsg_write_cmdset_dissectors_lua(po, luafile, cmdset, reclist)
      alldiss_list.append(enitm)
  recmsg_write_enum_lua(po, luafile, alldiss_list, "{}_{}_DISSECT".format(po.product.upper(),"UART_CMD"))

def recmsg_write_cmdset_typetexts_lua(po, luafile, cmdset, reclist):
  cmdset_shstr = cmdset_short_name_str(cmdset)
  cmdset_enum_name = "{:s}_{:s}_TEXT".format(cmdset_shstr.upper(),"UART_CMD")
  luafile.write("\nlocal {:s} = {{\n".format(cmdset_enum_name))
  for rst in reclist[:]:
      if rst.cmdset != cmdset: continue
      if rst.category == "config" and rst.cmdidx >= 0:
          name_title = rst.name.replace("_"," ").title()
          luafile.write("    [0x{:02x}] = '{}',\n".format(rst.cmdidx, name_title))
      elif rst.category == "string" or rst.category == "config_dump":
          name_title = rst.name.replace("_"," ").title()
          luafile.write("    [0x{:02x}] = '{}',\n".format(rst.cmdidx, name_title))
  luafile.write("}\n")
  return EnumEntry(cmdset_enum_name, cmdset)

def recmsg_write_cmdset_dissectors_lua(po, luafile, cmdset, reclist):
  dissect_list = []
  cmdset_shstr = cmdset_short_name_str(cmdset)
  cmdset_enum_name = "{:s}_{:s}_DISSECT".format(cmdset_shstr.upper(),"UART_CMD")
  for rst in reclist[:]:
      if rst.cmdset != cmdset: continue
      if rst.category == "config" and rst.cmdidx >= 0:
          disitm = recmsg_write_cmd_config_dissector_lua(po, luafile, rst)
          dissect_list.append(disitm)
      elif rst.category == "string" or rst.category == "config_dump":
          disitm = recmsg_write_cmd_string_dissector_lua(po, luafile, rst)
          dissect_list.append(disitm)
      else:
          eprint("{}: Warning: Skipped record named '{}' of category '{}'.".format(po.luafile,rst.name,rst.category))
  recmsg_write_enum_lua(po, luafile, dissect_list, cmdset_enum_name, "local ")
  return EnumEntry(cmdset_enum_name, cmdset)

def recmsg_write_cmd_config_dissector_lua(po, luafile, rst):
          cmdset_shstr = cmdset_short_name_str(rst.cmdset)
          cmdset_lnstr = cmdset_long_name_str(rst.cmdset)
          name_title = rst.name.replace("_"," ").title()
          name_view = rst.name.replace("-","_").replace(".","_").lower()
          luafile.write("\n-- {:s} - {:s} - 0x{:02x}\n\n".format(cmdset_lnstr,name_title,rst.cmdidx))
          # Cgreate a list of future protofields
          proto_list = []
          for prop in rst.props[:]:
              pname_title = prop.name.replace("_"," ").title()
              pname_view = "{:s}_{:s}".format(name_view,prop.name.replace("-","_").replace(".","_").lower())
              proto = LuaProtoField(prop.name, pname_view, pname_title, cmdset_shstr, prop_best_lua_proto_type(prop),
                      prop_best_lua_base(prop), prop_len(prop))
              proto.descr = prop.comment;

              if prop.ntype == RPropType.expr:
                  # Try to match the expression to known mask formats
                  parent_field = ""
                  match = re.search("^bitand\([ \t]*shift_r[ \t]*\(([A-Za-z0-9._-]*)[ \t]*,([0-9._-]*)[ \t]*\),[ \t]*([0-9._-]*)[ \t]*\).*$", prop.val)
                  if match:
                      parent_field = match.group(1)
                      bit_mask_shift = int(match.group(2))
                      bit_mask_base = int(match.group(3))
                      proto.dt_mask = bit_mask_base << bit_mask_shift
                  match = re.search("^bitand\([ \t]*([A-Za-z0-9._-]*)[ \t]*,[ \t]*([0-9._-]*)[ \t]*\).*$", prop.val)
                  if match:
                      parent_field = match.group(1)
                      proto.dt_mask = int(match.group(2))
                  match = re.search("^shift_r\(([A-Za-z0-9._-]*)[ \t]*,([0-9._-]*)[ \t]*\)and\(([0-9._-]*)[ \t]*\).*$", prop.val)
                  if match:
                      parent_field = match.group(1)
                      bit_mask_shift = int(match.group(2))
                      bit_mask_base = int(match.group(3))
                      proto.dt_mask = bit_mask_base << bit_mask_shift
                  match = re.search("^\(([A-Za-z0-9._-]*)[ \t]*\)and\(([0-9._-]*)[ \t]*\).*$", prop.val)
                  if match:
                      parent_field = match.group(1)
                      proto.dt_mask = int(match.group(2))
                  if len(parent_field) < 1:
                      eprint("{}: Warning: Skipped expr property named '{}' in config '{}' - no bit mask format.".format(po.luafile,prop.name,rst.name))
                      if (po.verbose > 2):
                          eprint("{}: Skipped value: '{}'.".format(po.luafile,prop.val))
                      proto.commented = True
                      proto.descr = prop.val.strip()
                      proto_list.append(proto)
                      continue

                  # Find the proto struct for this field
                  parent_proto = next((x for x in proto_list if x.name_base == parent_field), None)
                  if parent_proto is None:
                      eprint("{}: Warning: Skipped expr property named '{}' in config '{}' - parent '{}' not found.".format(po.luafile,prop.name,rst.name,parent_field))
                      proto.commented = True
                      proto.descr = prop.val.strip()
                      proto_list.append(proto)
                      continue

                  proto.dt_type = parent_proto.dt_type
                  proto.dt_len = parent_proto.dt_len
                  proto.dt_style = parent_proto.dt_style
                  parent_proto.subfields.append(proto)
                  continue

              proto_list.append(proto)

          # Add phony comment field if list is empty, to make hand modification easier
          if len(proto_list) < 1:
              prop_name = "unknown0"
              pname_title = prop_name.replace("_"," ").title()
              pname_view = "{:s}_{:s}".format(name_view,prop_name.replace("-","_").replace(".","_").lower())
              proto = LuaProtoField(prop_name, pname_view, pname_title, cmdset_shstr, "none",
                      "NONE", 0)
              proto.commented = True
              proto_list.append(proto)

          for proto in proto_list[:]:
              luafile.write(proto.format_lua_protofield_def(po.product.lower()))
              for subproto in proto.subfields[:]:
                  luafile.write("  " + subproto.format_lua_protofield_def(po.product.lower()))

          dissfunc_enum_name = "{:s}_{:s}_dissector".format(cmdset_shstr,name_view)
          luafile.write("\nlocal function {:s}(payload, pinfo, subtree)\n".format(dissfunc_enum_name))
          luafile.write("    local offset = 0\n")
          tot_len = 0
          for proto in proto_list[:]:
              if (proto.commented):
                  continue
              luafile.write("\n    " + proto.format_lua_protofield_inst(po.product.lower()))
              for subproto in proto.subfields[:]:
                  luafile.write("    " + subproto.format_lua_protofield_inst(po.product.lower()))
              luafile.write("    offset = offset + {}\n".format(proto.dt_len))
              tot_len += proto.dt_len
          luafile.write("\n    if (offset ~= {}) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,\"{}: Offset does not match - internal inconsistency\") end\n".format(tot_len,name_title))
          luafile.write("    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,\"{}: Payload size different than expected\") end\n".format(name_title))
          luafile.write("end\n")
          return EnumEntry(dissfunc_enum_name, rst.cmdidx)

def recmsg_write_cmd_string_dissector_lua(po, luafile, rst):
          cmdset_shstr = cmdset_short_name_str(rst.cmdset)
          cmdset_lnstr = cmdset_long_name_str(rst.cmdset)
          name_title = rst.name.replace("_"," ").title()
          name_view = rst.name.replace("-","_").replace(".","_").lower()
          luafile.write("\n-- {:s} - {:s} - 0x{:02x}\n\n".format("Flight log",name_title,rst.cmdidx))
          if True:
              prop_name = "text"
              pname_view = "{}_{}".format(name_view,prop_name)
              luafile.write("f.{}_{} = ProtoField.{} (\"{}.{}_{}\", \"{}\", base.{})\n".format(cmdset_shstr,pname_view,
                  "string",po.product.lower(),cmdset_shstr,pname_view,name_title,"ASCII"))

          dissfunc_enum_name = "{:s}_{:s}_dissector".format(cmdset_shstr,name_view)
          luafile.write("\nlocal function {:s}(payload, pinfo, subtree)\n".format(dissfunc_enum_name))
          luafile.write("    local offset = 0\n")
          if True:
              # This can't be handled by our LuaProtoField class - variable length
              luafile.write("\n    subtree:add (f.{}_{}, payload(offset, payload:len() - offset))\n".format(cmdset_shstr,pname_view))
          luafile.write("end\n")
          return EnumEntry(dissfunc_enum_name, rst.cmdidx)


def main(argv):
  # Parse command line options
  po = ProgOptions()
  po.command = 'l'
  try:
     opts, args = getopt.getopt(argv,"hvc:l:p:",["help","version","cmdsetfile=","luafile="])
  except getopt.GetoptError:
     print("Unrecognized options; check dji_java_dupcdefs_to_lua.py --help")
     sys.exit(2)
  for opt, arg in opts:
     if opt in ("-h", "--help"):
        print("DUPC Java code parser with Wireshark LUA out")
        print("dji_java_dupcdefs_to_lua.py [-v] -r <cmdsetfile> [-l <luafile>]")
        print("  -c <cmdsetfile> - name of the java file which stores command set enum")
        print("  -l <luafile> - Wireshark LUA dissector output file")
        print("  -p <product> - Select product name, used as prefix for names")
        print("  -v - increases verbosity level; max level is set by -vvv")
        sys.exit()
     elif opt == "--version":
        print("dji_java_dupcdefs_to_lua.py version 0.1.0")
        sys.exit()
     elif opt == '-v':
        po.verbose += 1
     elif opt in ("-c", "--cmdsetfile"):
        po.cmdsetfile = arg
     elif opt in ("-l", "--luafile"):
        po.luafile = arg
     elif opt in ("-p", "--product"):
        po.product = arg
  if len(po.cmdsetfile) > 0 and len(po.luafile) == 0:
      po.luafile = os.path.splitext(os.path.basename(po.cmdsetfile))[0] + ".lua"

  if (po.command == 'l'):

    if (po.verbose > 0):
      print("{}: Opening for parsing".format(po.cmdsetfile))
    cmdsetfile = open(po.cmdsetfile, "r")
    setslist = java_cmdset_parse(po,cmdsetfile)
    cmdsetfile.close();

    reclist = java_cmdlists_parse(po, setslist)

    reclist = java_dupc_classlist_parse(po, reclist)
    reclist = java_dupc_reclist_linearize(po, reclist)
    luafile = open(po.luafile, "w")
    recmsg_write_lua(po, luafile, reclist);
    luafile.close();

  else:

    raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
   main(sys.argv[1:])
