#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Java Classes with Packet Definitions parser, with Wireshark LUA out

If you don't know what this tool is, you most likely don't need it.

Input for this file is a decompiled Dji Go app, or other app with packets definitions.

Example use:
```
$ cd dji

$ grep -r '^[a-z \t]* String [^ ]* = \"CmdSet\";$' ./
./midware/data/config/P3/p.java:    private static final String q = "CmdSet";

$ ./dji_java_dupcdefs_to_lua.py -c ./midware/data/config/P3/p.java -l _packet_dissectors.lua -v
```

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
  stat_unrecognized = 0
  stat_questionable = 0
  stat_no_mask = 0
  stat_mask_shift = 0
  stat_shift_mask = 0

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
      self.val_dict = {}
      self.val_dict_name = ""
      self.comment = ''

class RecStruct:
  def __init__(self):
      self.name = ''
      self.package = ''
      self.category = ''
      self.cmdset = 0
      self.cmdidx = 0
      self.props = []
      self.pdicts = {}
      self.imports = []

class JavaFunc:
  def __init__(self):
      self.name = ''
      self.rettype = ''
      self.params = []
      self.body = []

class JavaBlock:
  def __init__(self):
      self.name = ''
      self.package = ''
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
  """
  Returns unsigned types, even though there are no unsigned types in Java.
  This is because unsigned types are more commonly used in packets.
  """
  sstr = typestr.strip().lower()+str(int(nbytes)*8)
  # alternate names first
  arr3 =["na0", "sint8", "sint16", "sint24", "sint32", "sint64", "integer8", "integer16", "integer24", "integer32", "integer64", "float16", "float32", "double64", "ex0"]
  if sstr in arr3:
      return arr3.index(sstr)
  arr2 =["na0", "sint8", "sint16", "sint24", "sint32", "sint64", "short8", "short16", "short24", "short32", "short64", "float16", "float32", "double64", "ex0"]
  if sstr in arr2:
      return arr2.index(sstr)
  arr1 =["na0", "slong8", "slong16", "slong24", "slong32", "slong64", "long8", "long16", "long24", "long32", "long64", "float16", "float32", "double64", "ex0"]
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
    while i < mask_bits:
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


def java_dupc_classlist_getters_parse(po, reclist):
  for rst in reclist:
      # Package name can be easily converted to file name
      clsfile = open(rst.package.replace(".","/")+".java", "r")
      java_dupc_class_getters_parse(po, rst, clsfile)
      clsfile.close();
  if (po.verbose > 0):
      print("Masked properties with shift applied before mask in getters: {}".format(po.stat_shift_mask))
      print("Masked properties with mask applied before shift in getters: {}".format(po.stat_mask_shift))
      print("Unmasked properties extracted from getters: {}".format(po.stat_no_mask))
      print("In total, encoured {} unrecognized getter functions".format(po.stat_unrecognized))
      print("Also, {} functions were converted in a questionable manner".format(po.stat_questionable))
  return reclist

def java_dupc_class_enums_parse(po, rst, clsfile):
  """
This function is far from being remotely comatible with Java syntax.
But as long as it gets standard decompiler output, it will work.
  """
  if (po.verbose > 2):
      print("{}: Parsing enums started".format(clsfile.name))

  # Read all enums
  enumblk = JavaBlock()
  enum_blocks = 0
  i = 0;
  for line in clsfile:
      i += 1
      if (enum_blocks < 1):
          # Find new enum start
          match = re.search("^[ \t]*(public[ \t]+|private[ \t]+|protected[ \t]+)?(static[ \t]+)?enum[ \t]+([A-Za-z0-9._-]+) \{$", line)
          if match:
              enumblk = JavaBlock()
              enumblk.name = match.group(3)
              enumblk.package = rst.package + "." + enumblk.name
              enum_blocks = 1
              if (po.verbose > 2):
                  print("{}: Found enum '{}'".format(clsfile.name,enumblk.name))
              continue
          # Not an enum - ignore
          continue
      # Ignore empty lines
      if len(str.strip(line)) < 1:
          continue

      enum_blocks += line.count("{")
      enum_blocks -= line.count("}")

      if (enum_blocks < 1):
          ending_line = line[:line.rindex('}')].strip()
          if len(ending_line) > 0:
              enumblk.body.append(ending_line)
          enum_blocks = 0
          # Enum ended - now it's time to analyze the body
          pdict = java_enum_to_pdict(po, clsfile.name, rst, enumblk)
          if pdict is not None:
              enum_key = ".".join(enumblk.package.rsplit('.', 2)[1:])
              if (po.verbose > 0):
                  if enumblk.name in rst.pdicts:
                      print("{}: Replacing previous definition of enum '{}'".format(clsfile.name,enum_key))
              rst.pdicts[enum_key] = pdict
              continue
          if (po.verbose > 3):
              for bodyline in enumblk.body:
                  print("{}: BODY: {}".format(clsfile.name,bodyline))
          continue

      enumblk.body.append(line.strip())

  return rst

def java_dupc_class_getters_parse(po, rst, clsfile):
  """
This function is far from being remotely comatible with Java syntax.
But as long as it gets standard decompiler output, it will work.
  """
  if (po.verbose > 2):
      print("{}: Parsing getters started".format(clsfile.name))

  # Read all getter functions
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
          # Find imports, to reach enums outside of this class
          match = re.search("^[ \t]*import[ \t]+dji[.]([A-Za-z0-9._-]+);$", line)
          if match:
              rst.imports.append(match.group(1))
          # Not a function nor import - ignore
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

def java_enum_to_pdict(po, fname, rst, enumblk):
  pdict = {}
  if len(enumblk.body) < 1:
      return None
  in_block = 0
  for line in enumblk.body:
      in_block += line.count("{")
      in_block -= line.count("}")
      if (in_block > 0):
          continue;
      # Example 1: NOTCONNECTED(-1),
      match = re.search("^([A-Za-z0-9_]+)\(([0-9-]+)\)[,;]$", line)
      if match:
          enitm_name = match.group(1)
          enitm_val = int(match.group(2))
          if enitm_val in pdict:
              if (po.verbose > 2):
                  eprint("{}: Enum key {} used for two values: '{}' and '{}'".format(fname,enitm_val,pdict[enitm_val],enitm_name))
              # If having two names, select the longer one
              if (len(pdict[enitm_val]) > len(enitm_name)):
                  continue
          pdict[enitm_val] = enitm_name
  return pdict

def java_func_to_property(po, fname, rst, func):
  if len(func.body) < 1:
      return None
  func_nice_body = []
  in_block = 0
  for line in func.body:
      # Remove heading like:
      #  boolean bl = true;
      match = re.search("^[A-Za-z0-9._]+ [A-Za-z0-9_]+ = [A-Za-z0-9._]+;$", line)
      if match:
          continue
      # Remove lines like: if (this._recData == null) return DataSingleSetPointPos.TapMode.a;
      match = re.search("^if \(this[.]_recData == null\) return [A-Za-z0-9._]+;$", line)
      if match:
          continue
      # Remove lines like: if (this._recData.length <= 20) return DataSingleSetPointPos.TapMode.a;
      # Or like: if (this._recData.length <= 9) return -1;
      match = re.search("^if \(this[.]_recData[.]length <[=]? [A-Za-z0-9._]+\) return [A-Za-z0-9._-]+;$", line)
      if match:
          continue
      # Remove lines like: if (DataOsdGetPushCommon.getInstance().getFlycVersion() < 16) return false;
      # Or like: if (DataOsdGetPushCommon.getInstance().getFlycVersion() < 8) return this.get(16, 4, Float.class).floatValue();
      match = re.search("^if \([A-Za-z0-9._]+[.]getInstance\(\)[.]get[A-Za-z0-9._]+Version\(\) <[=]? [A-Za-z0-9._]+\) return [A-Za-z0-9\(\) ,._-]+;$", line)
      if match:
          continue
      # Remove conditions in lines like: if (this._recData.length != 0) return CHANNEL_STATUS.find((Integer)this.get(0, 1, Integer.class));
      match = re.search("^if \(this[.]_recData[.]length != 0\) (return .*this.get\(.*;)$", line)
      if match:
          func_nice_body.append(match.group(1))
          break
      # Remove conditions in lines like: if (this._recData.length >= 38) return this.get(37, 2, Integer.class);
      match = re.search("^if \(this[.]_recData[.]length >[=]? [A-Za-z0-9._]+\) (return .*this.get\(.*;)$", line)
      if match:
          func_nice_body.append(match.group(1))
          break
      # Remove conditions in lines like: if (this._recData != null) return GOHOME_STATUS.find(this.get(32, 4, Integer.class) >> 5 & 7);
      match = re.search("^if \(this[.]_recData != null\) (return .*this.get\(.*;)$", line)
      if match:
          func_nice_body.append(match.group(1))
          break
      # Remove block like:
      #  if (this._recData == null) {
      #      return bl;
      #  }
      match = re.search("^if \(this[.]_recData == null\) \{$", line)
      if match:
          in_block += 1
      if in_block < 1:
          func_nice_body.append(line)
      match = re.search("\}", line)
      if match:
          in_block -= 1

  # Get content of a block like:
  #  if (this._recData != null && this._recData.length > 22) {
  #      return TargetObjType.find((Integer)this.get(22, 1, Integer.class));
  #  }
  func_nice_body2 = []
  in_block = 0
  for line in func_nice_body:
      match = re.search("\}", line)
      if match:
          in_block -= 1
      if in_block > 0:
          match = re.search("^(this[.][A-Za-z0-9_]+) = (.*this.get\(.*);$", line)
          if match:
              func_nice_body2.append("return {};".format(match.group(2)))
          else:
              func_nice_body2.append(line)
      match = re.search("^if \([\(]?this[.]_recData != null[\)]? && [\(]?this[.]_recData.length > [A-Za-z0-9._]+[\)]?\) \{$", line)
      if match:
          in_block += 1
      match = re.search("^if \([\(]?this[.]_recData != null[\)]? && [\(]?this[.]_recData\[[A-Za-z0-9._]+\].* [<>=!]+ [A-Za-z0-9._]+[\)]?\) \{$", line)
      if match:
          in_block += 1
  if len(func_nice_body2) > 0:
      func_nice_body = func_nice_body2

  # Skip heading like:
  #  DataEyeGetPushFunctionList dataEyeGetPushFunctionList = DataEyeGetPushFunctionList.getInstance();
  #  if (!dataEyeGetPushFunctionList.isGetted()) return true;
  #  if (!dataEyeGetPushFunctionList.sensorStatusSource()) return true;
  # Or like:
  #  Enum enum_ = this.getDroneType();
  #  if (enum_ == DroneType.Unknown) return BatteryType.Smart;
  #  if (enum_ == DroneType.None) return BatteryType.Smart;
  func_nice_body2 = []
  in_template = False
  for line in func_nice_body:
      match = re.search("^([A-Za-z0-9._]+) ([A-Za-z0-9._]+) = ([A-Za-z0-9._]+)[.](get[A-Za-z0-9._]+)\(\);$", line)
      if match:
          in_template = True
          continue
      if (in_template):
          match = re.search("^if \([!]?([A-Za-z0-9._]+).([A-Za-z0-9._]+)\(\)\) return [A-Za-z0-9._]+;$", line)
          if match:
              continue
          match = re.search("^if \(([A-Za-z0-9._]+) [=!]+ ([A-Za-z0-9._]+)\) return [A-Za-z0-9._]+;$", line)
          if match:
              continue
          func_nice_body2.append(line)
  if len(func_nice_body2) > 0:
      func_nice_body = func_nice_body2

  if len(func_nice_body) == 1:
      # Check known one-liners
      line = func_nice_body[0]
      if True:

          # Masked entries with shift first, mask later
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
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = RPropType.expr
              bit_mask_shift = int(match.group(6) or "0")
              bit_mask_base = int(match.group(7))
              # Convert negative bitmasks to proper positive ones
              if bit_mask_base < 0: bit_mask_base = (~bit_mask_base) & (pow(2,prop_type_len(prop.base_type)*8)-1)
              prop.val = "bitand(shift_r({},{}),{})".format("auto_detect_name",bit_mask_shift,bit_mask_base)
              #prop.comment = 
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              po.stat_shift_mask += 1
              return prop

          # Masked entries with mask first, shift later
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
              #prop.comment = 
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              po.stat_mask_shift += 1
              return prop

          # Non-masked entries
          # Example 1: return (Integer)this.get(4, 1, Integer.class);
          # Example 2: return ((Float)this.get(16, 4, Float.class)).floatValue();
          # Example 3: return (Integer)this.get(0, 1, Integer.class) - 256;
          # Example 4: return this.get(8, 8, Double.class) * 180.0 / 3.141592653589793;
          # Example 5: return Math.round(((Float)this.get(0, 4, Float.class)).floatValue());
          # Example 6: return (float)((Integer)this.get(15, 2, Integer.class)).intValue() * 1.0f / 100.0f;
          match = re.search("^return (Math[.]round)?[\(]?(\([A-Za-z0-9._]+\))?[\(]?(\([A-Za-z0-9._]+\))?this[.]get\(([A-Za-z0-9._]+), ([A-Za-z0-9._]+), ([A-Za-z0-9._]+).class\)[\)]?([.][A-Za-z0-9._]+Value\(\))?[\)]?( [*] ([A-Za-z0-9._]+))?( / ([A-Za-z0-9._]+))?( - ([A-Za-z0-9._]+))?;$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(4))
              prop_dsize = match.group(5)
              prop_dtype = match.group(6)
              prop_mul = match.group(8)
              prop_div = match.group(10)
              prop_bias = match.group(12)
              tmp1_name = func.name
              if (tmp1_name.startswith("get")):
                  tmp1_name = tmp1_name[3:]
              prop.name = camel_to_snake(tmp1_name)
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = prop.base_type
              #prop.val = 
              if (prop_bias is not None): prop.comment = "value bias {}".format(prop_bias)
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              po.stat_no_mask += 1
              return prop

          # Non-masked entries with variable offset
          # Example 1: return (Integer)this.get(this.dataOffset + 1, 1, Integer.class);
          # Example 2: return (Integer)this.get((n2 - 1) * 12 + 7, 2, Integer.class);
          match = re.search("^return [\(]?(\([A-Za-z0-9._]+\))?this[.]get\(([A-Za-z0-9\(\). _\*\+-]+) \+ ([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+).class\)[\)]?;$", line)
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
              #prop.val = 
              prop.comment = "Offset shifted by unknown value {}".format(prop_pos_shift)
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              po.stat_no_mask += 1
              return prop

          # Masked enum entries with shift first, mask later
          # Example 1: return AdvanceGoHomeState.find(this.get(4, 2, Integer.class) >> 2 & 7);
          # Example 2: return DataCameraGetStateInfo.SDCardState.find((int)(this.get(0, 4, Integer.class) >> 10 & 15));
          match = re.search("^return [\(]?(\([A-Za-z0-9._]+\))?([A-Za-z0-9._]+)?[.](find|ofData)\((\([A-Za-z0-9._]+\))?[\(]?this[.]get\(([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+).class\)( >>[>]? ([A-Za-z0-9._-]+))? & ([A-Za-z0-9._-]+)\)[\)]?[\)]?;$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(5))
              prop.val_dict_name = match.group(2) or rst.package[rst.package.rindex('.')+1:] # Value of None means 'this' (or its parent) is the enum
              prop_dsize = match.group(6)
              prop_dtype = match.group(7)
              tmp1_name = func.name
              if (tmp1_name.startswith("get")):
                  tmp1_name = tmp1_name[3:]
              prop.name = camel_to_snake(tmp1_name)
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = RPropType.expr
              bit_mask_shift = int(match.group(9) or "0")
              bit_mask_base = int(match.group(10))
              # Convert negative bitmasks to proper positive ones
              if bit_mask_base < 0: bit_mask_base = (~bit_mask_base) & (pow(2,prop_type_len(prop.base_type)*8)-1)
              prop.val = "bitand(shift_r({},{}),{})".format("auto_detect_name",bit_mask_shift,bit_mask_base)
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              po.stat_shift_mask += 1
              return prop

          # Masked enum entries with mask first, shift later
          # Example 1: return PreciseLandingState.find((this.get(6, 2, Integer.class) & 6) >> 1);
          # Example 2: return RcModeChannel.find((this.get(32, 4, Integer.class) & 24576) >>> 13, this.getFlycVersion(), this.getDroneType(), false);
          # Example 3: return DataOsdGetPushCommon.TRIPOD_STATUS.ofValue((byte)((this.get(0, 1, Integer.class) & 14) >>> 1));
          match = re.search("^return [\(]?(\([A-Za-z0-9._]+\))?([A-Za-z0-9._]+)?[.](find|ofData|ofValue)\([\(]?(\([A-Za-z0-9._]+\))?[\(]?[\(]?this[.]get\(([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+).class\)( & ([A-Za-z0-9._-]+)\))? >>[>]? ([A-Za-z0-9._-]+)(, [A-Za-z0-9\(\)._-]+)?(, [A-Za-z0-9\(\)._-]+)?(, [A-Za-z0-9\(\)._-]+)?\)[\)]?;$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(5))
              prop.val_dict_name = match.group(2) or rst.package[rst.package.rindex('.')+1:] # Value of None means 'this' (or its parent) is the enum
              prop_dsize = match.group(6)
              prop_dtype = match.group(7)
              tmp1_name = func.name
              if (tmp1_name.startswith("get")):
                  tmp1_name = tmp1_name[3:]
              prop.name = camel_to_snake(tmp1_name)
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = RPropType.expr
              bit_mask_shift = int(match.group(10))
              bit_mask_base = int(match.group(9) or (pow(2,prop_type_len(prop.base_type)*8)-1)) >> bit_mask_shift
              # Convert negative bitmasks to proper positive ones
              if bit_mask_base < 0: bit_mask_base = (~bit_mask_base) & (pow(2,prop_type_len(prop.base_type)*8)-1)
              prop.val = "bitand(shift_r({},{}),{})".format("auto_detect_name",bit_mask_shift,bit_mask_base)
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              po.stat_mask_shift += 1
              return prop

          # Non-masked enum entries
          # Example 1: return VisionSensorType.find((Integer)this.get(2, 1, Integer.class));
          # Example 2: return FLIGHT_ACTION.find(this.get(37, 1, Short.class).shortValue());
          # Example 3: return DJIGimbalType.find(((Short)this.get(0, 1, Short.class)).shortValue());
          # Example 4: return DataCameraGetIso.TYPE.find((int)this.get(5, 1, Integer.class)).value();
          match = re.search("^return [\(]?(\([A-Za-z0-9._]+\))?([A-Za-z0-9._]+)?[.](find|ofData)\([\(]?(\([A-Za-z0-9._]+\))?this[.]get\(([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+).class\)[\)]?([.][A-Za-z0-9._]+Value\(\))?\)[\)]?([.]value\(\))?;$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(5))
              prop.val_dict_name = match.group(2) or rst.package[rst.package.rindex('.')+1:] # Value of None means 'this' (or its parent) is the enum
              prop_dsize = match.group(6)
              prop_dtype = match.group(7)
              tmp1_name = func.name
              if (tmp1_name.startswith("get")):
                  tmp1_name = tmp1_name[3:]
              prop.name = camel_to_snake(tmp1_name)
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = prop.base_type
              #prop.val = 
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              po.stat_no_mask += 1
              return prop

          # Non-masked hash entries
          # Example 1: return d.getNameByHash((long)((Long)this.get(1, 4, Long.class)));
          match = re.search("^return [\(]?(\([A-Za-z0-9._]+\))?([A-Za-z0-9._]+)?[.]getNameByHash\((\([A-Za-z0-9._]+\))?[\(]?(\([A-Za-z0-9._]+\))?this[.]get\(([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+).class\)[\)]?([.][A-Za-z0-9._]+Value\(\))?\)[\)]?;$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(5))
              prop_hashlist_name = match.group(2) # Value of None means 'this' is the enum
              prop_dsize = match.group(6)
              prop_dtype = match.group(7)
              tmp1_name = func.name
              if (tmp1_name.startswith("get")):
                  tmp1_name = tmp1_name[3:]
              prop.name = camel_to_snake(tmp1_name)+"_hash"
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = prop.base_type
              #prop.val = 
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              po.stat_no_mask += 1
              return prop

  if len(func_nice_body) == 2:
      # Check for a 2-liner which returns bool
      line = func_nice_body[1]
      match = re.search("^return (true|false);$", line)
      if match:
          line = func_nice_body[0]

          # Non-masked entries
          # Example 1: if ((Integer)this.get(0, 1, Integer.class) == 0) return false;
          match = re.search("^if \((\([A-Za-z0-9._]+\))?this[.]get\(([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+), ([A-Za-z0-9._]+).class\) ([=!]+) ([A-Za-z0-9._-]+)\) return (true|false);$", line)
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
                  eprint("{}: Unrecognized conditions combination in bool function1 {}; op {} val {}".format(fname,func.name,prop_op,prop_val))
              prop.name = camel_to_snake(tmp1_name)
              if (prop_neg): prop.name = "not_"+prop.name
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = prop.base_type
              #prop.val = 
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              po.stat_no_mask += 1
              return prop

          # Masked bool entries with mask first, shift later
          # Example 1: if (((Integer)this.get(1, 1, Integer.class) & 2) != 2) return false;
          # Example 2: if ((this.get(30, 1, Short.class) & 128) != 0) return false;
          # Example 3: if ((this.get(20, 2, Integer.class) & 16) >>> 4 == 0) return false;
          match = re.search("^if \(\((\([A-Za-z0-9._]+\))?this[.]get\(([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+), ([A-Za-z0-9._]+).class\) & ([A-Za-z0-9._-]+)\)( >>[>]? ([A-Za-z0-9._-]+))? ([=!]+) ([A-Za-z0-9._-]+)[\)] return (true|false);$", line)
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
                  eprint("{}: Unrecognized conditions combination in bool function2 {}; mask {} op {} val {}".format(fname,func.name,prop_mask,prop_op,prop_val))
              prop.name = camel_to_snake(tmp1_name)
              if (prop_neg): prop.name = "not_"+prop.name
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = RPropType.expr
              #prop.val = 
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              po.stat_mask_shift += 1
              return prop

          # Masked bool entries with shift first, mask later
          # Example 1: if ((this.get(20, 2, Integer.class) >> 6 & 1) == 0) return false;
          # Example 2: if (this.get(40, 2, Integer.class) >> 15 != 1) return false;
          match = re.search("^if \([\(]?(\([A-Za-z0-9._]+\))?this[.]get\(([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+), ([A-Za-z0-9._]+).class\) >>[>]? ([A-Za-z0-9._-]+)( & ([A-Za-z0-9._-]+))?[\)]? ([=!]+) ([A-Za-z0-9._-]+)\) return (true|false);$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(2))
              prop_dsize = match.group(3)
              prop_dtype = match.group(4)
              prop_op = match.group(8)
              prop_val = int(match.group(9))
              prop_bool = match.group(10)
              tmp1_name = func.name
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = RPropType.expr
              bit_mask_shift = int(match.group(5))
              bit_prop_len = prop_type_len(prop.base_type)*8
              bit_mask_base = int(match.group(7) or ((pow(2,bit_prop_len)-1) >> bit_mask_shift))
              if (tmp1_name.startswith("is")):
                  tmp1_name = tmp1_name[2:]
              prop.val = "bitand(shift_r({},{}),{})".format("auto_detect_name",bit_mask_shift,bit_mask_base)
              prop_neg = False
              if (prop_op == "==") and (prop_val == 0):
                  prop_neg = (prop_bool == "true")
              elif (prop_op == "!=") and (prop_val == 0):
                  prop_neg = (prop_bool == "false")
              elif (prop_op == "==") and (prop_val == bit_mask_base):
                  prop_neg = (prop_bool == "false")
              elif (prop_op == "!=") and (prop_val == bit_mask_base):
                  prop_neg = (prop_bool == "true")
              else:
                  prop.comment = "Unrecognized conditions in {}".format(func.name)
                  eprint("{}: Unrecognized conditions combination in bool function3 {}; mask {} op {} val {}".format(fname,func.name,bit_mask_base,prop_op,prop_val))
              prop.name = camel_to_snake(tmp1_name)
              if (prop_neg): prop.name = "not_"+prop.name
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              po.stat_shift_mask += 1
              return prop

          # Masked bool entries with shift first, mask later - a special block to support incompetent programmers
          # Example 1: if ((this.get(23, 2, Integer.class) << 6 & 1) != 1) return false;
          match = re.search("^if \([\(]?(\([A-Za-z0-9._]+\))?this[.]get\(([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+), ([A-Za-z0-9._]+).class\) <<[<]? ([A-Za-z0-9._-]+)( & ([A-Za-z0-9._-]+))?[\)]? ([=!]+) ([A-Za-z0-9._-]+)\) return (true|false);$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(2))
              prop_dsize = match.group(3)
              prop_dtype = match.group(4)
              prop_op = match.group(8)
              prop_val = int(match.group(9))
              prop_bool = match.group(10)
              tmp1_name = func.name
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = RPropType.expr
              bit_mask_shift = int(match.group(5))
              bit_prop_len = prop_type_len(prop.base_type)*8
              bit_mask_base = int(match.group(7) or ((pow(2,bit_prop_len)-1) >> bit_mask_shift))
              if (tmp1_name.startswith("is")):
                  tmp1_name = tmp1_name[2:]
              prop.val = "bitand(shift_r({},{}),{})".format("auto_detect_name",bit_mask_shift,bit_mask_base)
              prop_neg = False
              if (prop_op == "==") and (prop_val == 0):
                  prop_neg = (prop_bool == "true")
              elif (prop_op == "!=") and (prop_val == 0):
                  prop_neg = (prop_bool == "false")
              elif (prop_op == "==") and (prop_val == bit_mask_base):
                  prop_neg = (prop_bool == "false")
              elif (prop_op == "!=") and (prop_val == bit_mask_base):
                  prop_neg = (prop_bool == "true")
              else:
                  prop.comment = "Unrecognized conditions in {}".format(func.name)
                  eprint("{}: Unrecognized conditions combination in bool function3 {}; mask {} op {} val {}".format(fname,func.name,bit_mask_base,prop_op,prop_val))
              prop.name = camel_to_snake(tmp1_name)
              if (prop_neg): prop.name = "not_"+prop.name
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              po.stat_shift_mask += 1
              return prop

      # Check for a 2-liner which returns this.something, and previously sets that property
      line = func_nice_body[1]
      match = re.search("^return this[.]([A-Za-z0-9._]+);$", line)
      if match:
          ret_prop = match.group(1)
          line = func_nice_body[0]

          # Non-masked entries
          # Example 1: this.mSelectChannelCnt = (Integer)this.get(4, 4, Integer.class);
          match = re.search("^this[.]([A-Za-z0-9._]+) = (\([A-Za-z0-9._]+\))this[.]get\(([A-Za-z0-9._-]+), ([A-Za-z0-9._-]+), ([A-Za-z0-9._]+).class\);$", line)
          if match and ret_prop == match.group(1):
              prop = RecProp()
              prop.pos = int(match.group(3))
              prop_dsize = match.group(4)
              prop_dtype = match.group(5)
              tmp1_name = func.name
              prop.name = camel_to_snake(tmp1_name)
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = prop.base_type
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              po.stat_no_mask += 1
              return prop

  for line in func_nice_body:
      # Check functions of any size, without getting too much into surroundings of the `get` call
      match = re.search("this[.]get\(", line)
      if match:

          # Masked entries with shift first, mask later
          match = re.search("^.*this[.]get\(([0-9-]+), ([0-9-]+), ([A-Za-z0-9._]+).class\) >>[>]? ([0-9-]+)[\)]?( & ([0-9-]+))?.*$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(1))
              prop_dsize = int(match.group(2))
              prop_dtype = match.group(3)
              tmp1_name = func.name
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = RPropType.expr
              bit_mask_shift = int(match.group(4))
              bit_prop_len = prop_type_len(prop.base_type)*8
              bit_mask_base = int(match.group(6) or ((pow(2,bit_prop_len)-1) >> bit_mask_shift))
              if (tmp1_name.startswith("is")):
                  tmp1_name = tmp1_name[2:]
              elif (tmp1_name.startswith("get")):
                  tmp1_name = tmp1_name[3:]
              prop.val = "bitand(shift_r({},{}),{})".format("auto_detect_name",bit_mask_shift,bit_mask_base)
              prop.name = camel_to_snake(tmp1_name)
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              eprint("{}: Function {} understood without 'get' surroundings!".format(fname,func.name))
              po.stat_questionable += 1
              po.stat_shift_mask += 1
              return prop

          # Masked entries with mask first, shift later
          match = re.search("^.*this[.]get\(([0-9-]+), ([0-9-]+), ([A-Za-z0-9._]+).class\) & ([0-9-]+)[\)]?( >>[>]? ([0-9-]+))?.*$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(1))
              prop_dsize = int(match.group(2))
              prop_dtype = match.group(3)
              tmp1_name = func.name
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = RPropType.expr
              bit_mask_shift = int(match.group(6) or "0")
              bit_mask_base = int(match.group(4)) >> bit_mask_shift
              if (tmp1_name.startswith("is")):
                  tmp1_name = tmp1_name[2:]
              elif (tmp1_name.startswith("get")):
                  tmp1_name = tmp1_name[3:]
              prop.val = "bitand(shift_r({},{}),{})".format("auto_detect_name",bit_mask_shift,bit_mask_base)
              prop.name = camel_to_snake(tmp1_name)
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              eprint("{}: Function {} understood without 'get' surroundings!".format(fname,func.name))
              po.stat_questionable += 1
              po.stat_mask_shift += 1
              return prop

          # Non-masked entries
          match = re.search("^.*this[.]get\(([0-9-]+), ([0-9-]+), ([A-Za-z0-9._]+).class\).*$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(1))
              prop_dsize = match.group(2)
              prop_dtype = match.group(3)
              tmp1_name = func.name
              prop.base_type = java_typestr_to_ntype(prop_dsize,prop_dtype)
              prop.ntype = prop.base_type
              if (tmp1_name.startswith("get")):
                  tmp1_name = tmp1_name[3:]
              prop.name = camel_to_snake(tmp1_name)
              if (po.verbose > 2):
                  print("{}: Property type {} size {} at offs {}".format(fname,prop_dtype,prop_dsize,prop.pos))
              if (prop.base_type <= RPropType.none):
                  eprint("{}: Property type {} size {} not recognized in function {}!".format(fname,prop_dtype,prop_dsize,func.name))
              eprint("{}: Function {} understood without 'get' surroundings!".format(fname,func.name))
              po.stat_questionable += 1
              po.stat_no_mask += 1
              return prop

          eprint("{}: Function {} contains 'get' but its structure was not recognized!".format(fname,func.name))
          po.stat_unrecognized += 1
          break
  return None

def java_dupc_classlist_enums_parse(po, reclist):
  for rst in reclist:
      # Package name can be easily converted to file name
      fname = rst.package.replace(".","/")+".java"
      clsfile = open(fname, "r")
      java_dupc_class_enums_parse(po, rst, clsfile)
      clsfile.close();
      # Parse not only direct enums, but also those in imports
      for pkgname in rst.imports:
          clsfile = open(pkgname.replace(".","/")+".java", "r")
          java_dupc_class_enums_parse(po, rst, clsfile)
          clsfile.close();
      # Now we can assign enums to props
      for prop in rst.props:
          if len(prop.val_dict_name) < 1:
              continue
          # Assign enum to the property
          prop_enum_name = prop.val_dict_name
          if (prop_enum_name.count(".") < 1):
              tmp1_name = rst.package.rsplit(".",1)[1]
              if (tmp1_name == prop_enum_name):
                  tmp1_name = rst.package.rsplit(".",2)[1]
              prop_enum_name = tmp1_name + "." + prop_enum_name

          if True:
              tmp1_name = prop_enum_name
              if (tmp1_name in rst.pdicts):
                  prop.val_dict = rst.pdicts[tmp1_name]
          if (len(prop.val_dict) < 1):
              tmp1_name = prop_enum_name.split(".",1)[1]
              for pdname, pdict in rst.pdicts.items():
                  if pdname.endswith("."+tmp1_name):
                      # If already set, show warning
                      if len(prop.val_dict) > 0:
                          eprint("{}: Property {} has ambiguous enum '{}' reference!".format(fname,prop.name,prop_enum_name))
                      prop.val_dict = pdict

          prop.val_dict_name = camel_to_snake(prop_enum_name.split(".",1)[1]).replace(".","_")
          if (len(prop.val_dict) < 1):
              prop.comment = "TODO values from enum {}".format(prop_enum_name)
              if (po.verbose > 1):
                  print("{}: Enum {} not found".format(fname,prop_enum_name))
  return reclist

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
              # Unless it is already expr, which would mean this is already done in previous stage of parsing.
              if prop.ntype != RPropType.expr:
                  # Convert current to expr
                  prop.val = "bitand(shift_r({},{}),{})".format(prv_prop.name,0,pow(2,prop_type_len(prop.base_type)*8)-1)
                  prop.ntype = RPropType.expr
              #pktpos = prv_prop.pos # Do not update position by expr entry

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
      self.enum_name = ""
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
      if (len(self.enum_vals) > 0):
          add_params[0] = "enums.{}_ENUM".format(self.enum_name.upper())
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

def recmsg_write_quoted_enum_lua(po, luafile, enum_list, enum_name, enum_modifier=""):
  if len(enum_modifier) > 0: enum_modifier += " "
  luafile.write("\n{}{} = {{\n".format(enum_modifier,enum_name))
  for enitm in enum_list:
      luafile.write("    [0x{:02x}] = '{}',\n".format(enitm.idx, enitm.val))
  luafile.write("}\n")

def recmsg_write_lua(po, luafile, reclist):
  luafile.write("local f = {}_PROTO.fields\n".format(po.product.upper()))
  luafile.write("local enums = {}\n")

  alltext_list = []
  for cmdset in range(0,16):
      enitm = recmsg_write_cmdset_typetexts_lua(po, luafile, cmdset, reclist)
      alltext_list.append(enitm)
  recmsg_write_enum_lua(po, luafile, alltext_list, "{}_{}_{}_TEXT".format(po.product.upper(),"FLIGHT_CONTROL","UART_CMD"))

  alldiss_list = []
  for cmdset in range(0,16):
      enitm = recmsg_write_cmdset_dissectors_lua(po, luafile, cmdset, reclist)
      alldiss_list.append(enitm)
  recmsg_write_enum_lua(po, luafile, alldiss_list, "{}_{}_{}_DISSECT".format(po.product.upper(),"FLIGHT_CONTROL","UART_CMD"))

def recmsg_write_cmdset_typetexts_lua(po, luafile, cmdset, reclist):
  cmdset_shstr = cmdset_short_name_str(cmdset)
  cmdset_enum_name = "{:s}_{:s}_TEXT".format(cmdset_shstr.upper(),"UART_CMD")
  cmdtext_list = []
  for rst in reclist[:]:
      if rst.cmdset != cmdset: continue
      if rst.category == "config" and rst.cmdidx >= 0:
          name_title = rst.name.replace("_"," ").title()
          cmdtext_list.append(EnumEntry(name_title, rst.cmdidx))
      elif rst.category == "string" or rst.category == "config_dump":
          name_title = rst.name.replace("_"," ").title()
          cmdtext_list.append(EnumEntry(name_title, rst.cmdidx))
  recmsg_write_quoted_enum_lua(po, luafile, cmdtext_list, cmdset_enum_name, "local")
  # Return entry for higher level enum
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
  recmsg_write_enum_lua(po, luafile, dissect_list, cmdset_enum_name, "local")
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
              enum_name_a = proto.cmdset_str.upper()
              enum_name_b = proto.name_fltr.upper()
              enum_name_c = prop.val_dict_name.upper()
              if (enum_name_b.startswith(enum_name_a)):
                  enum_name_b = enum_name_b[len(enum_name_a):].strip("_")
              if (enum_name_b.endswith(enum_name_c)):
                  enum_name_b = enum_name_b[:-len(enum_name_c)].strip("_")
              proto.enum_name = "{}_{}_{}".format(enum_name_a,enum_name_b,enum_name_c)
              for key, val in prop.val_dict.items():
                  if (key >= 0) and (key <= (pow(2,prop_type_len(prop.base_type)*8)-1)):
                      proto.enum_vals.append(EnumEntry(val, key))
                  else:
                      if (po.verbose > 1):
                          eprint("{}: Skipped enum val [{}]:{} in property named '{}'.".format(po.luafile,key,val,prop.name))

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

          # Sort subfields by mask
          for proto in proto_list[:]:
              proto.subfields = sorted(proto.subfields, key=lambda pr: pr.dt_mask )

          # Write enumerations
          for proto in proto_list[:]:
              if len(proto.enum_vals) > 0:
                  recmsg_write_quoted_enum_lua(po, luafile, proto.enum_vals, "enums.{}_ENUM".format(proto.enum_name.upper()))
              for subproto in proto.subfields[:]:
                  if len(subproto.enum_vals) > 0:
                      recmsg_write_quoted_enum_lua(po, luafile, subproto.enum_vals, "enums.{}_ENUM".format(subproto.enum_name.upper()))

          for proto in proto_list[:]:
              luafile.write(proto.format_lua_protofield_def(po.product.lower()))
              for subproto in proto.subfields[:]:
                  luafile.write("  " + subproto.format_lua_protofield_def(po.product.lower()))

          dissfunc_enum_name = "{:s}_{:s}_dissector".format(cmdset_shstr,name_view)
          luafile.write("\nlocal function {:s}(pkt_length, buffer, pinfo, subtree)\n".format(dissfunc_enum_name))
          luafile.write("    local offset = 11\n")
          luafile.write("    local payload = buffer(offset, pkt_length - offset - 2)\n")
          luafile.write("    offset = 0\n")
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

    reclist = java_dupc_classlist_getters_parse(po, reclist)
    reclist = java_dupc_classlist_enums_parse(po, reclist)
    reclist = java_dupc_reclist_linearize(po, reclist)
    luafile = open(po.luafile, "w")
    recmsg_write_lua(po, luafile, reclist);
    luafile.close();

  else:

    raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
   main(sys.argv[1:])
