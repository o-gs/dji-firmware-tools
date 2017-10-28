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
          for prop in rst.props[:]:
              if prop.ntype == 9: # RPropType.expr
                  eprint("{}: Warning: Skipped expr property named '{}' in config '{}'.".format(po.luafile,prop.name,rst.name))
                  continue
              pname_title = prop.name.replace("_"," ").title()
              pname_view = "{}_{}".format(name_view,prop.name.replace("-","_").replace(".","_").lower())

              add_params = None
              if len(prop.comment) > 0:
                  if add_params is None:
                      add_params = ['nil','nil','nil']
                  add_params[2] = "\"" + prop.comment + "\""
              if add_params is None:
                  add_params_str = ""
              else:
                  add_params_str = ", {}, {}, {}".format(add_params[0],add_params[1],add_params[2])

              luafile.write("f.rec_{} = ProtoField.{} (\"{}.rec_{}\", \"{}\", base.{}{})\n".format(pname_view,
                  prop_type_best_lua_proto_type(prop.ntype),po.product.lower(),pname_view,pname_title,
                  prop_type_best_lua_base(prop.ntype),add_params_str))
          luafile.write("\nlocal function flightrec_{}_dissector(payload, pinfo, subtree)\n".format(name_view))
          luafile.write("    local offset = 0\n")
          tot_len = 0
          for prop in rst.props[:]:
              if prop.ntype == 9: # RPropType.expr
                  continue
              pname_view = "{}_{}".format(name_view,prop.name.replace("-","_").replace(".","_").lower())
              luafile.write("\n    subtree:add_le (f.rec_{}, payload(offset, {}))\n".format(pname_view,prop_type_len(prop.ntype)))
              luafile.write("    offset = offset + {}\n".format(prop_type_len(prop.ntype)))
              tot_len += prop_type_len(prop.ntype)
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
