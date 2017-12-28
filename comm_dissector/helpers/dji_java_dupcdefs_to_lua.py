#!/usr/bin/env python3

""" Recorder Type Definitions parser with Wireshark LUA out

If you don't know what this tool is, you most likely don't need it.

Example input file:
---
Op.[config]
name   imu_data_status 
type   19
Op.uint8_t 	start_fan
Op.uint8_t  	led_status
Op.[string]
name	        drv_log
type			65530
---

Such file can be extracted from DAT log files, or for older generations
of hardware, from the Viewer included in Dji Assistant software.

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

class RPropType(enum.Enum):
  none = 0
  int8_t = 1
  int16_t = 2
  int32_t = 3
  uint8_t = 4
  uint16_t = 5
  uint32_t = 6
  fp32 = 7
  fp64 = 8
  expr = 9

class RecProp:
  def __init__(self):
      self.name = ''
      self.pos = 0
      self.ntype = 0
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
  arr =[0, 1, 2, 4, 1, 2, 4, 4, 8, 0]
  return arr[ntype]

def prop_len(prop):
  if (prop.arrlen > 0):
      return prop_type_len(prop.ntype) * prop.arrlen
  else:
      return prop_type_len(prop.ntype)

def prop_typestr_to_ntype(typestr):
  sstr = typestr.strip().lower()
  # alternate names first
  arr2 =["na", "int8", "int16", "int32", "uint8", "uint16", "uint32", "float", "double", "ex"]
  if sstr in arr2:
      return arr2.index(sstr)
  # now the proper name search
  arr =["none", "int8_t", "int16_t", "int32_t", "uint8_t", "uint16_t", "uint32_t", "fp32", "fp64", "expr"]
  return arr.index(sstr)

def java_typestr_to_ntype(nbytes, typestr):
  sstr = typestr.strip().lower()+str(int(nbytes)*8)
  # alternate names first
  arr2 =["na0", "integer8", "integer16", "integer32", "uint8", "uint16", "uint32", "float32", "double64", "ex0"]
  if sstr in arr2:
      return arr2.index(sstr)
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
  if len(func.body) == 1:
      # Check known one-liners
      for line in func.body:
          match = re.search("^return ([\(]?\([A-Za-z0-9._]+\))?this[.]get\(([A-Za-z0-9._]+), ([A-Za-z0-9._]+), ([A-Za-z0-9._]+).class\)[\)]?.*;$", line)
          if match:
              prop = RecProp()
              prop.pos = int(match.group(2))
              tmp1_name = func.name
              if (tmp1_name.startswith("get")):
                  tmp1_name = tmp1_name[3:]
              prop.name = camel_to_snake(tmp1_name)
              #prop.val = 
              #prop.comment = 
              prop.ntype = java_typestr_to_ntype(match.group(3),match.group(4))
              print("{}: Property type {} size {} at offs {}".format(fname,match.group(4),match.group(3),match.group(2)))
              if (prop.ntype < 1):
                  eprint("{}: Property type {} size {} not recognized!".format(fname,match.group(4),match.group(3)))
              return prop
  return None

def java_dupc_reclist_linearize(po, reclist):
  for rst in reclist:
      sorted_props = sorted(rst.props, key=lambda prop: prop.pos)
      rst.props = []
      prv_prop = None
      pktpos = 0
      for prop in sorted_props:
          if pktpos < prop.pos:
              nprop = RecProp()
              nprop.pos = pktpos
              nprop.name = "unknown{:02X}".format(pktpos)
              nprop.ntype = 4 # uint8_t
              if prop.pos - pktpos > 1:
                  nprop.arrlen = prop.pos - pktpos
              rst.props.append(nprop)
              pktpos += prop_len(nprop)
          elif pktpos > prop.pos:
              if len(prv_prop) < 1:
              else:
                  rst.props.append(prop)
              #TODO handle overlaping, ie. bitfields
              pass
          prv_prop = prop
          rst.props.append(prop)
          pktpos += prop_len(prop)
          
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
          self.cmdset_str, self.name_fltr, self.dt_type, protocol_name, self.cmdset_str, self.name_fltr, self.name_view, self.dt_style, add_params_str)
  def format_lua_protofield_inst(self, protocol_name):
      """ Format string containing LUA ProtoField instantiation
      """
      return "{}subtree:add_le (f.{}_{}, payload(offset, {}))\n".format("--" if self.commented else "", self.cmdset_str, self.name_fltr, self.dt_len)


def prop_best_lua_base(prop):
  if (prop.arrlen > 0):
      return "SPACE"
  arr =["NONE", "DEC", "DEC", "DEC", "HEX", "HEX", "HEX", "DEC", "DEC", "NONE"]
  return arr[prop.ntype]

def prop_best_lua_proto_type(prop):
  if (prop.arrlen > 0):
      return "bytes"
  arr =["none", "int8", "int16", "int32", "uint8", "uint16", "uint32", "float", "double", "none"]
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

              if prop.ntype == 9: # RPropType.expr
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
