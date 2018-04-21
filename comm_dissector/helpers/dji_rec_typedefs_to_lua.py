#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
  recmfile = ''
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
      self.ntype = 0
      self.val = ''
      self.comment = ''

class RecStruct:
  def __init__(self):
      self.name = ''
      self.category = ''
      self.numtype = 0
      self.textype = ''
      self.props = []

def prop_type_len(ntype):
  arr =[0, 1, 2, 4, 1, 2, 4, 4, 8, 0]
  return arr[ntype]

def prop_typestr_to_ntype(typestr):
  sstr = typestr.strip().lower()
  # alternate names first
  arr2 =["na", "int8", "int16", "int32", "uint8", "uint16", "uint32", "float", "double", "ex"]
  if sstr in arr2:
      return arr2.index(sstr)
  # now the proper name search
  arr =["none", "int8_t", "int16_t", "int32_t", "uint8_t", "uint16_t", "uint32_t", "fp32", "fp64", "expr"]
  return arr.index(sstr)

def recmsg_parse(po, recmfile):
  reclist = []
  rst = RecStruct()
  i = 0;
  for line in recmfile:
      i += 1
      # Find new struct head
      match = re.search("^[ \t]*Op[.]\[([A-Za-z0-9._-]*)\]", line)
      if match:
          if (len(rst.category) > 0):
              if (po.verbose > 1):
                  print("{}: Finished parsing '{}' type {} with {} fields at line {}".format(po.recmfile,rst.name,rst.numtype,len(rst.props),i))
              reclist.append(rst)
          rst = RecStruct()
          rst.category = match.group(1)
          continue
      match = re.search("^[ \t]*name[ \t]*([A-Za-z0-9._-]*)", line)
      if match:
          rst.name = match.group(1)
          if (po.verbose > 2):
              print("{}: Named '{}' at line {}".format(po.recmfile,rst.name,i))
          continue
      match = re.search("^[ \t]*type[ \t]*([A-Za-z0-9._-]*)", line)
      if match:
          if re.match("^\d+$", match.group(1)) is None:
              rst.numtype = -1
              rst.textype = match.group(1)
              eprint("{}: Warning: Non-numeric type '{}' for item in category '{}'.".format(po.luafile,rst.textype,rst.category))
          else:
              rst.numtype = int(match.group(1))
          if (po.verbose > 2):
              print("{}: Set type {} at line {}".format(po.recmfile,rst.numtype,i))
          continue
      match = re.search("^[ \t]*Op[.]([A-Za-z0-9._-]*)[ \t]*([A-Za-z0-9._-]*)[ \t]*(.*)", line)
      if match:
          prop = RecProp()
          prop.ntype = prop_typestr_to_ntype(match.group(1))
          prop.name = match.group(2)
          prop.val = match.group(3)
          submatch = re.search("^(^[ \t]*)[ \t]*\/\/[ \t]*(.*)$", prop.val)
          if submatch:
              prop.val = submatch.group(1)
              prop.comment = submatch.group(2)
          rst.props.append(prop)
          continue
      if len(line) > 0:
          eprint("{}: Warning: Skipped line {}.".format(po.recmfile,i))
  if (len(rst.category) > 0):
      reclist.append(rst)
  return reclist

class LuaDissector:
  def __init__(self, f, n):
      self.func = f
      self.numtype = n

class LuaProtoField:
  def __init__(self, nbase, nfltr, nview, dtype, dstyle, dlen):
      self.name_base = nbase
      self.name_fltr = nfltr
      self.name_view = nview
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
      return "{}f.rec_{} = ProtoField.{} (\"{}.rec_{}\", \"{}\", base.{}{})\n".format("--" if self.commented else "",
          self.name_fltr, self.dt_type, protocol_name, self.name_fltr, self.name_view, self.dt_style, add_params_str)
  def format_lua_protofield_inst(self, protocol_name):
      """ Format string containing LUA ProtoField instantiation
      """
      return "{}subtree:add_le (f.rec_{}, payload(offset, {}))\n".format("--" if self.commented else "",self.name_fltr,self.dt_len)


def prop_type_best_lua_base(ntype):
  arr =["NONE", "DEC", "DEC", "DEC", "HEX", "HEX", "HEX", "DEC", "DEC", "NONE"]
  return arr[ntype]

def prop_type_best_lua_proto_type(ntype):
  arr =["none", "int8", "int16", "int32", "uint8", "uint16", "uint32", "float", "double", "none"]
  return arr[ntype]

def recmsg_write_lua(po, luafile, reclist):
  luafile.write("local f = {}_PROTO.fields\n".format(po.product.upper()))
  dissect_list = []
  luafile.write("\n{}_FLIGHT_RECORD_ENTRY_TYPE = {{\n".format(po.product.upper()))
  for rst in reclist[:]:
      if rst.category == "config" and rst.numtype >= 0:
          name_title = rst.name.replace("_"," ").title()
          luafile.write("    [0x{:04x}] = '{}',\n".format(rst.numtype, name_title))
      elif rst.category == "string" or rst.category == "config_dump":
          name_title = rst.name.replace("_"," ").title()
          luafile.write("    [0x{:04x}] = '{}',\n".format(rst.numtype, name_title))
  luafile.write("}\n")

  for rst in reclist[:]:
      if rst.category == "config" and rst.numtype >= 0:
          name_title = rst.name.replace("_"," ").title()
          name_view = rst.name.replace("-","_").replace(".","_").lower()
          luafile.write("\n-- Flight log - {:s} - 0x{:04x}\n\n".format(name_title,rst.numtype))
          # Cgreate a list of future protofields
          proto_list = []
          for prop in rst.props[:]:
              pname_title = prop.name.replace("_"," ").title()
              pname_view = "{}_{}".format(name_view,prop.name.replace("-","_").replace(".","_").lower())
              proto = LuaProtoField(prop.name, pname_view, pname_title, prop_type_best_lua_proto_type(prop.ntype),
                      prop_type_best_lua_base(prop.ntype), prop_type_len(prop.ntype))
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

          for proto in proto_list[:]:
              luafile.write(proto.format_lua_protofield_def(po.product.lower()))
              for subproto in proto.subfields[:]:
                  luafile.write("  " + subproto.format_lua_protofield_def(po.product.lower()))

          luafile.write("\nlocal function flightrec_{}_dissector(payload, pinfo, subtree)\n".format(name_view))
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
          dissect_list.append(LuaDissector("flightrec_{}_dissector".format(name_view), rst.numtype))
      elif rst.category == "string" or rst.category == "config_dump":
          name_title = rst.name.replace("_"," ").title()
          name_view = rst.name.replace("-","_").replace(".","_").lower()
          luafile.write("\n-- Flight log - {:s} - 0x{:04x}\n\n".format(name_title,rst.numtype))
          if True:
              pname_view = "{}_{}".format(name_view,"text")
              luafile.write("f.rec_{} = ProtoField.{} (\"{}.rec_{}\", \"{}\", base.{})\n".format(pname_view,
                  "string",po.product.lower(),pname_view,name_title,"ASCII"))
          luafile.write("\nlocal function flightrec_{}_dissector(payload, pinfo, subtree)\n".format(name_view))
          luafile.write("    local offset = 0\n")
          if True:
              luafile.write("\n    subtree:add (f.rec_{}, payload(offset, payload:len() - offset))\n".format(pname_view))
          luafile.write("end\n")
          dissect_list.append(LuaDissector("flightrec_{}_dissector".format(name_view), rst.numtype))
      else:
          eprint("{}: Warning: Skipped record named '{}' of category '{}'.".format(po.luafile,rst.name,rst.category))

  luafile.write("\n{}_FLIGHT_RECORD_DISSECT = {{\n".format(po.product.upper()))
  for diss in dissect_list[:]:
      luafile.write("    [0x{:04x}] = {},\n".format(diss.numtype, diss.func))
  luafile.write("}\n")

def main(argv):
  # Parse command line options
  po = ProgOptions()
  po.command = 'l'
  try:
     opts, args = getopt.getopt(argv,"hvr:l:p:",["help","version","recmfile=","luafile="])
  except getopt.GetoptError:
     print("Unrecognized options; check dji_rec_typedefs_to_lua.py --help")
     sys.exit(2)
  for opt, arg in opts:
     if opt in ("-h", "--help"):
        print("Recorder Type Definitions parser with Wireshark LUA out")
        print("dji_rec_typedefs_to_lua.py [-v] -r <recmfile> [-l <luafile>]")
        print("  -r <recmfile> - name of the recorder messages description text file")
        print("  -l <luafile> - Wireshark LUA dissector output file")
        print("  -p <product> - Select product name, used as prefix for names")
        print("  -v - increases verbosity level; max level is set by -vvv")
        sys.exit()
     elif opt == "--version":
        print("dji_rec_typedefs_to_lua.py version 0.1.0")
        sys.exit()
     elif opt == '-v':
        po.verbose += 1
     elif opt in ("-r", "--recmfile"):
        po.recmfile = arg
     elif opt in ("-l", "--luafile"):
        po.luafile = arg
     elif opt in ("-p", "--product"):
        po.product = arg
  if len(po.recmfile) > 0 and len(po.luafile) == 0:
      po.luafile = os.path.splitext(os.path.basename(po.recmfile))[0] + ".lua"

  if (po.command == 'l'):

    if (po.verbose > 0):
      print("{}: Opening for parsing".format(po.recmfile))
    recmfile = open(po.recmfile, "r")
    reclist = recmsg_parse(po,recmfile)
    recmfile.close();

    luafile = open(po.luafile, "w")
    recmsg_write_lua(po, luafile, reclist);
    luafile.close();

  else:

    raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
   main(sys.argv[1:])
