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
  inffile="flyc_forbid_areas.json"
  address_base=0x8020000
  address_bss=0x20000000
  sizeof_bss=0x4400000
  expect_func_align = 4
  expect_data_align = 2
  min_match_accepted = 5
  verbose = 0
  command = ''
  param_pos = -1
  param_count = 0

class FlycNoFlyZone(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('latitude', c_int),
              ('longitude', c_int),
              ('radius', c_ushort),
              ('country_code', c_ushort),
              ('class_id', c_ubyte),
              ('area_id', c_ushort),
              ('begin_at', c_ubyte),
              ('end_at', c_ubyte)]

  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    return d

  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)

class FlycNoFlyCoords(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('latitude', c_int),
              ('longitude', c_int)]

def flyc_nofly_is_proper_zone_entry(po, fwmdlfile, fwmdlfile_len, enfzone, func_align, data_align, pos, entry_pos):
  """ Checks whether given FlycNoFlyZone object stores a proper entry of
      flight controller no fly zones array.
  """
  if (enfzone.begin_at != 0) or (enfzone.end_at != 0):
     if (po.verbose > 2):
        print("Rejected at {:06x} on begin_at/end_at check ({:d},{:d})\n".format(entry_pos,enfzone.begin_at,enfzone.end_at))
     return False
  if (enfzone.radius < 30) or (enfzone.radius > 50000):
     if (po.verbose > 2):
        print("Rejected at {:06x} on radius check ({:d})\n".format(entry_pos,enfzone.radius))
     return False
  if (enfzone.country_code > 2000):
     if (po.verbose > 2):
        print("Rejected at {:06x} on country check ({:d})\n".format(entry_pos,enfzone.country_code))
     return False
  #if (enfzone.class_id < 30) or (enfzone.class_id > 30000):
  if (enfzone.area_id <= 0):
     if (po.verbose > 2):
        print("Rejected at {:06x} on area_id check ({:d})\n".format(entry_pos,enfzone.area_id))
     return False
  return flyc_nofly_is_proper_cord_entry(po, fwmdlfile, fwmdlfile_len, enfzone, func_align, data_align, pos, entry_pos)

def flyc_nofly_is_proper_cord_entry(po, fwmdlfile, fwmdlfile_len, enfcord, func_align, data_align, pos, entry_pos):
  """ Checks whether given FlycNoFlyCoords object stores a proper entry of
      flight controller no fly coordinates array.
  """
  # Check if we're at ocean around (0.0,0.0), that is within rectangle (-8.0,-6.7) to (4.7,5.5)
  if (enfcord.latitude >= -8000000) and (enfcord.latitude <= 4700000):
     if (enfcord.longitude >= -6700000) and (enfcord.longitude <= 5500000):
        if (po.verbose > 2):
           print("Rejected at {:06x} on low coord ocean check ({:.6f},{:.6f})\n".format(entry_pos,enfcord.latitude/1000000.0,enfcord.longitude/1000000.0))
        return False
  # Check if coords are within valid angular range
  if (enfcord.latitude < -90000000) or (enfcord.latitude > 90000000):
     if (po.verbose > 2):
        print("Rejected at {:06x} on latitude coord limit check ({:.6f},{:.6f})\n".format(entry_pos,enfcord.latitude/1000000.0,enfcord.longitude/1000000.0))
     return False
  if (enfcord.longitude < -180000000) or (enfcord.longitude > 180000000):
     if (po.verbose > 2):
        print("Rejected at {:06x} on longitude coord limit check ({:.6f},{:.6f})\n".format(entry_pos,enfcord.latitude/1000000.0,enfcord.longitude/1000000.0))
     return False
  return True

def flyc_nofly_zone_pos_search(po, fwmdlfile, start_pos, func_align, data_align, min_match_accepted):
  """ Finds position of flight controller no fly zones in the binary.
  """
  fwmdlfile.seek(0, os.SEEK_END)
  fwmdlfile_len = fwmdlfile.tell()
  enfzone = FlycNoFlyZone()
  match_count = 0
  match_pos = -1
  match_entries = 0
  reached_eof = False
  pos = start_pos
  while (True):
     # Check how many correct zone entries we have
     entry_count = 0
     entry_pos = pos
     while (True):
        fwmdlfile.seek(entry_pos, os.SEEK_SET)
        if fwmdlfile.readinto(enfzone) != sizeof(enfzone):
           reached_eof = True
           break
        if not flyc_nofly_is_proper_zone_entry(po, fwmdlfile, fwmdlfile_len, enfzone, func_align, data_align, pos, entry_pos):
           break
        entry_count += 1
        entry_pos += sizeof(enfzone)
     # Do not allow entry at EOF
     if (reached_eof):
        break
     # If entry is ok, consider it a match
     if entry_count > 4:
        if (po.verbose > 1):
           print("{}: Matching zones array at 0x{:08x}: {:d} entries".format(po.mdlfile,pos,entry_count))
        if (entry_count >= min_match_accepted):
           match_pos = pos
           match_entries = entry_count
        match_count += 1
     # Set position to search for next entry
     if entry_count >= min_match_accepted:
        pos += entry_count * sizeof(enfzone)
     else:
        pos += data_align - (pos%data_align)
  if (match_count > 1):
     eprint("{}: Warning: multiple ({:d}) matches found for fly zones array with alignment 0x{:02x}".format(po.mdlfile,match_count,data_align))
  if (match_count < 1):
     return -1, 0
  return match_pos, match_entries

def flyc_nofly_zone_get(po, fwmdlfile, index):
  """ Returns array with properties of given no fly zone.
  """
  parprop = {'area_id':60000,'type':0,'shape':0,'lat':90.0,'lng':0.0,'radius':30,
      'warning':0,'level':2,'disable':0,'updated_at':1447945800,'begin_at':0,'end_at':0,
      'name':"",'country':0,'city':"",'points':None}
  enfzone = FlycNoFlyZone()
  fwmdlfile.seek(po.param_pos+sizeof(enfzone)*index, os.SEEK_SET)
  if fwmdlfile.readinto(enfzone) != sizeof(enfzone):
      raise EOFError("Cannot read nfz entry.")
  parprop['area_id'] = enfzone.area_id
  parprop['begin_at'] = enfzone.begin_at
  parprop['end_at'] = enfzone.end_at
  parprop['lat'] = enfzone.latitude/1000000.0
  parprop['lng'] = enfzone.longitude/1000000.0
  parprop['radius'] = enfzone.radius
  parprop['country'] = enfzone.country_code
  # sel all or some of 'type','shape','warning','level','disable' based on class_id
  #parprop[''] = enfzone.class_id
  return parprop

def flyc_nofly_list(po, fwmdlfile):
  """ Lists all flight controller no fly zones from firmware on screen table.
  """
  (po.param_pos, po.param_count) = flyc_nofly_zone_pos_search(po, fwmdlfile, 0, po.expect_func_align, po.expect_data_align, po.min_match_accepted)
  if po.param_pos < 0:
    raise ValueError("Flight controller no fly zones array signature not detected in input file.")
  for i in range(0,po.param_count):
    parprop = flyc_nofly_zone_get(po, fwmdlfile, i)
    print("{:5d} {:3.6f} {:4.6f} {:4d} {:d} {:d} ".format(parprop['area_id'],parprop['lat'],parprop['lng'],parprop['radius'],parprop['begin_at'],parprop['end_at'],parprop['country']))

def flyc_nofly_extract(po, fwmdlfile):
  """ Extracts all flight controller no fly zones from firmware to JSON format text file.
  """
  (po.param_pos, po.param_count) = flyc_nofly_zone_pos_search(po, fwmdlfile, 0, po.expect_func_align, po.expect_data_align, po.min_match_accepted)
  if po.param_pos < 0:
    raise ValueError("Flight controller no fly zones array signature not detected in input file.")
  raise NotImplementedError('Not implemented.')

def flyc_nofly_update(po, fwmdlfile):
  """ Updates all flight controller no fly zones in firmware from JSON format text file.
  """
  (po.param_pos, po.param_count) = flyc_nofly_zone_pos_search(po, fwmdlfile, 0, po.expect_func_align, po.expect_data_align, po.min_match_accepted)
  if po.param_pos < 0:
    raise ValueError("Flight controller no fly zones array signature not detected in input file.")
  raise NotImplementedError('Not implemented.')

def main(argv):
  # Parse command line options
  po = ProgOptions()
  try:
     opts, args = getopt.getopt(argv,"hvm:lux",["help","version","mdlfile="])
  except getopt.GetoptError:
     print("Unrecognized options; check dji_flyc_nofly_ed.sh --help")
     sys.exit(2)
  for opt, arg in opts:
     if opt in ("-h", "--help"):
        print("DJI Flight Controller Firmware No Fly Zones Editor")
        print("dji_flyc_nofly_ed.sh <-l|-x|-u> [-v] -m <mdlfile>")
        print("  -m <mdlfile> - Flight controller firmware binary module file")
        print("  -l - list no fly zones stored in the firmware")
        print("  -x - extract no fly zones array to infos json text file")
        print("  -u - update no fly zones array in binary fw from infos text file")
        print("  -v - increases verbosity level; max level is set by -vvv")
        sys.exit()
     elif opt == "--version":
        print("dji_flyc_nofly_ed.sh version 0.0.1")
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

    flyc_nofly_list(po,fwmdlfile)

    fwmdlfile.close();

  elif (po.command == 'x'):

    if (po.verbose > 0):
      print("{}: Opening for extraction".format(po.mdlfile))
    fwmdlfile = open(po.mdlfile, "rb")

    flyc_nofly_extract(po,fwmdlfile)

    fwmdlfile.close();

  elif (po.command == 'u'):

    if (po.verbose > 0):
      print("{}: Opening for update".format(po.mdlfile))
    fwmdlfile = open(po.mdlfile, "r+b")

    flyc_nofly_update(po,fwmdlfile)

    fwmdlfile.close();

  else:

    raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
   main(sys.argv[1:])
