#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" DJI Flight Controller Firmware No Fly Zones Editor
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
  min_match_accepted = 60
  verbose = 0
  command = ''
  nfzone_pos = -1
  nfzone_count = 0
  nfcord_pos = -1
  nfcord_count = 0

class NoFlyStorage:
  none = 0x0
  zone = 0x1
  cord = 0x2

class FlycNoFlyZone(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('latitude', c_int), # angular value * 1000000
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

def isclose(a, b, rel_tol=1e-09, abs_tol=0.0):
  """ Equivalent to math.isclose(); use it if the script needs to work on Python < 3.5
  """
  return abs(a-b) <= max(rel_tol * max(abs(a), abs(b)), abs_tol)

def flyc_nofly_is_proper_zone_entry(po, fwmdlfile, fwmdlfile_len, enfzone, func_align, data_align, pos, entry_pos):
  """ Checks whether given FlycNoFlyZone object stores a proper entry of
      flight controller no fly zones array.
  """
  if (enfzone.begin_at != 0) or (enfzone.end_at != 0):
     if (po.verbose > 2):
        print("Rejected at {:06x} on begin_at/end_at check ({:d},{:d})".format(entry_pos,enfzone.begin_at,enfzone.end_at))
     return False
  if (enfzone.radius < 30) or (enfzone.radius > 50000):
     if (po.verbose > 2):
        print("Rejected at {:06x} on radius check ({:d})".format(entry_pos,enfzone.radius))
     return False
  if (enfzone.country_code > 2000):
     if (po.verbose > 2):
        print("Rejected at {:06x} on country check ({:d})".format(entry_pos,enfzone.country_code))
     return False
  #if (enfzone.class_id < 30) or (enfzone.class_id > 30000):
  if (enfzone.area_id <= 0):
     if (po.verbose > 2):
        print("Rejected at {:06x} on area_id check ({:d})".format(entry_pos,enfzone.area_id))
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
           print("Rejected at {:06x} on low coord ocean check ({:.6f},{:.6f})".format(entry_pos,enfcord.latitude/1000000.0,enfcord.longitude/1000000.0))
        return False
  # Check if coords are within valid angular range
  if (enfcord.latitude < -90000000) or (enfcord.latitude > 90000000):
     if (po.verbose > 2):
        print("Rejected at {:06x} on latitude coord limit check ({:.6f},{:.6f})".format(entry_pos,enfcord.latitude/1000000.0,enfcord.longitude/1000000.0))
     return False
  if (enfcord.longitude < -180000000) or (enfcord.longitude > 180000000):
     if (po.verbose > 2):
        print("Rejected at {:06x} on longitude coord limit check ({:.6f},{:.6f})".format(entry_pos,enfcord.latitude/1000000.0,enfcord.longitude/1000000.0))
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
     if entry_count > min_match_accepted:
        if (po.verbose > 1):
           print("{}: Matching zones array at 0x{:08x}: {:d} entries".format(po.mdlfile,pos,entry_count))
        if (entry_count >= match_entries):
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

def flyc_nofly_cord_pos_search(po, fwmdlfile, start_pos, func_align, data_align, min_match_accepted):
  """ Finds position of flight controller no fly coords in the binary.
  """
  fwmdlfile.seek(0, os.SEEK_END)
  fwmdlfile_len = fwmdlfile.tell()
  enfcord = FlycNoFlyCoords()
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
        if fwmdlfile.readinto(enfcord) != sizeof(enfcord):
           reached_eof = True
           break
        # The array ends with int value storing its size
        if (entry_count >= min_match_accepted) and (enfcord.latitude == entry_count):
           break
        if not flyc_nofly_is_proper_cord_entry(po, fwmdlfile, fwmdlfile_len, enfcord, func_align, data_align, pos, entry_pos):
           break
        entry_count += 1
        entry_pos += sizeof(enfcord)
     # Do not allow entry at EOF
     if (reached_eof):
        break
     # If entry is ok, consider it a match
     if entry_count > min_match_accepted:
        if (po.verbose > 1):
           print("{}: Matching coords array at 0x{:08x}: {:d} entries".format(po.mdlfile,pos,entry_count))
        if (entry_count >= match_entries):
           match_pos = pos
           match_entries = entry_count
        match_count += 1
     # Set position to search for next entry
     if entry_count >= min_match_accepted:
        pos += entry_count * sizeof(enfcord)
     else:
        pos += data_align - (pos%data_align)
  if (match_count > 1):
     eprint("{}: Warning: multiple ({:d}) matches found for fly coords array with alignment 0x{:02x}".format(po.mdlfile,match_count,data_align))
  if (match_count < 1):
     return -1, 0
  return match_pos, match_entries

def flyc_nofly_zone_template(po):
  # Set coords at north pole; they should never stay at default value after all
  # Set 'level' at 2; definition is: WARNING(0), CAN_UNLIMIT(1), CAN_NOT_UNLIMIT(2, 4), STRONG_WARNING(3)
  parprop = {'area_id':60000,'type':0,'shape':0,'lat':90.0,'lng':0.0,'radius':30,
      'warning':0,'level':2,'disable':0,'updated_at':1447945800,'begin_at':0,'end_at':0,
      'name':"",'country':0,'city':"",'storage':NoFlyStorage.none,'points':None}
  return parprop

def flyc_nofly_zone_get(po, fwmdlfile, index):
  """ Returns array with properties of given no fly zone.
  """
  parprop = flyc_nofly_zone_template(po)
  enfzone = FlycNoFlyZone()
  fwmdlfile.seek(po.nfzone_pos+sizeof(enfzone)*index, os.SEEK_SET)
  if fwmdlfile.readinto(enfzone) != sizeof(enfzone):
      raise EOFError("Cannot read nfzone entry.")
  parprop['area_id'] = enfzone.area_id
  parprop['begin_at'] = enfzone.begin_at
  parprop['end_at'] = enfzone.end_at
  parprop['lat'] = enfzone.latitude/1000000.0
  parprop['lng'] = enfzone.longitude/1000000.0
  parprop['radius'] = enfzone.radius
  parprop['country'] = enfzone.country_code
  parprop['type'] = enfzone.class_id
  parprop['storage'] |= NoFlyStorage.zone
  return parprop

def flyc_nofly_cord_get(po, fwmdlfile, index):
  """ Returns array with properties of given no fly coords.
  """
  parprop = {'lat':90.0,'lng':0.0}
  enfcord = FlycNoFlyCoords()
  fwmdlfile.seek(po.nfcord_pos+sizeof(enfcord)*index, os.SEEK_SET)
  if fwmdlfile.readinto(enfcord) != sizeof(enfcord):
      raise EOFError("Cannot read nfcord entry.")
  parprop['lat'] = enfcord.latitude/1000000.0
  parprop['lng'] = enfcord.longitude/1000000.0
  return parprop

def flyc_nofly_merged_zones_array(po, fwmdlfile):
  if (po.verbose > 0):
     print("{}: Merging No Fly arrays...".format(po.mdlfile))
  nfzones = []
  for i in range(0,po.nfzone_count):
    parprop = flyc_nofly_zone_get(po, fwmdlfile, i)
    nfzones.append(parprop)
    #print("{:5d} {:10.6f} {:11.6f} {:5d} {:4d} {:d} {:d} {:d}".format(parprop['area_id'],parprop['lat'],parprop['lng'],parprop['radius'],parprop['country'],parprop['type'],parprop['begin_at'],parprop['end_at']))
  for i in range(0,po.nfcord_count):
    parcord = flyc_nofly_cord_get(po, fwmdlfile, i)
    parprop = next((parprop for parprop in nfzones if isclose(parprop["lat"], parcord["lat"], rel_tol=1e-3, abs_tol=1e-2) and isclose(parprop["lng"], parcord["lng"], rel_tol=1e-3, abs_tol=1e-2)), None)
    if (parprop is None):
       parprop = flyc_nofly_zone_template(po)
       parprop['lat'] = parcord['lat']
       parprop['lng'] = parcord['lng']
       parprop['radius'] = 500
       parprop['area_id'] = 30000 + i
       nfzones.append(parprop)
    parprop['storage'] |= NoFlyStorage.cord
    #print("{:5d} {:10.6f} {:11.6f}".format(i,parcord['lat'],parcord['lng']))
  return sorted(nfzones, key=lambda k: -k['lat'])

def flyc_nofly_list(po, fwmdlfile):
  """ Lists all flight controller no fly zones from firmware on screen table.
  """
  (po.nfzone_pos, po.nfzone_count) = flyc_nofly_zone_pos_search(po, fwmdlfile, 0, po.expect_func_align, po.expect_data_align, po.min_match_accepted)
  if po.nfzone_pos < 0:
    raise ValueError("Flight controller no fly zones array signature not detected in input file.")
  (po.nfcord_pos, po.nfcord_count) = flyc_nofly_cord_pos_search(po, fwmdlfile, 0, po.expect_func_align, po.expect_data_align, po.min_match_accepted)
  if po.nfcord_pos < 0:
    raise ValueError("Flight controller no fly coords array signature not detected in input file.")
  nfzones = flyc_nofly_merged_zones_array(po, fwmdlfile)
  for parprop in nfzones:
     print("{:5d} {:10.6f} {:11.6f} {:5d} {:4d} {:s}{:s} {:d} {:d} {:d}".format(parprop['area_id'],parprop['lat'],parprop['lng'],
       parprop['radius'],parprop['country'],"z" if (parprop['storage'] & NoFlyStorage.zone) != 0 else " ",
       "c" if (parprop['storage'] & NoFlyStorage.cord) != 0 else " ",parprop['type'],parprop['begin_at'],parprop['end_at']))
  if (po.verbose > 0):
     print("{}: Done listing.".format(po.mdlfile))

def flyc_nofly_extract(po, fwmdlfile):
  """ Extracts all flight controller no fly zones from firmware to JSON format text file.
  """
  (po.nfzone_pos, po.nfzone_count) = flyc_nofly_zone_pos_search(po, fwmdlfile, 0, po.expect_func_align, po.expect_data_align, po.min_match_accepted)
  if po.nfzone_pos < 0:
    raise ValueError("Flight controller no fly zones array signature not detected in input file.")
  (po.nfcord_pos, po.nfcord_count) = flyc_nofly_cord_pos_search(po, fwmdlfile, 0, po.expect_func_align, po.expect_data_align, po.min_match_accepted)
  if po.nfcord_pos < 0:
    raise ValueError("Flight controller no fly coords array signature not detected in input file.")
  nfzones = flyc_nofly_merged_zones_array(po, fwmdlfile)
  if (po.verbose > 0):
     print("{}: Creating JSON file...".format(po.mdlfile))
  inffile = open(po.inffile, "w")
  inffile.write("{\"release_limits\":[\n")
  i = 0
  for parprop in nfzones:
    inffile.write("{")
    for ppname in ('area_id','type','shape',):
       inffile.write("\"{:s}\":{:d}".format(ppname,parprop[ppname]))
       inffile.write(",")
    for ppname in ('lat','lng',):
       inffile.write("\"{:s}\":{:06f}".format(ppname,parprop[ppname]))
       inffile.write(",")
    for ppname in ('radius','warning','level','disable','updated_at','begin_at','end_at',):
       inffile.write("\"{:s}\":{:d}".format(ppname,parprop[ppname]))
       inffile.write(",")
    for ppname in ('name',):
       inffile.write("\"{:s}\":\"{:s}\"".format(ppname,parprop[ppname]))
       inffile.write(",")
    for ppname in ('storage','country',):
       inffile.write("\"{:s}\":{:d}".format(ppname,parprop[ppname]))
       inffile.write(",")
    for ppname in ('city',):
       inffile.write("\"{:s}\":\"{:s}\"".format(ppname,parprop[ppname]))
       inffile.write(",")
    for ppname in ('points',):
       inffile.write("\"{:s}\":{:s}".format(ppname,parprop[ppname] if parprop[ppname] is not None else "null"))
    if (i+1 < len(nfzones)):
       inffile.write("},\n")
    else:
       inffile.write("}\n")
    i += 1
  inffile.write("]}\n")
  inffile.close()
  if (po.verbose > 0):
     print("{}: Done exporting.".format(po.mdlfile))

def flyc_nofly_update(po, fwmdlfile):
  """ Updates all flight controller no fly zones in firmware from JSON format text file.
  """
  (po.nfzone_pos, po.nfzone_count) = flyc_nofly_zone_pos_search(po, fwmdlfile, 0, po.expect_func_align, po.expect_data_align, po.min_match_accepted)
  if po.nfzone_pos < 0:
    raise ValueError("Flight controller no fly zones array signature not detected in input file.")
  (po.nfcord_pos, po.nfcord_count) = flyc_nofly_cord_pos_search(po, fwmdlfile, 0, po.expect_func_align, po.expect_data_align, po.min_match_accepted)
  if po.nfcord_pos < 0:
    raise ValueError("Flight controller no fly coords array signature not detected in input file.")
  #pvnfzones = flyc_nofly_merged_zones_array(po, fwmdlfile) # No need for merging, we will use separate lists
  if (po.verbose > 0):
     print("{}: Loading JSON file...".format(po.mdlfile))
  with open(po.inffile) as inffile:
    nxnfzones = json.load(inffile)
  nxnfzones = nxnfzones['release_limits']
  update_zone_count = 0
  update_cord_count = 0
  if (True):
      # Update the zones first
      if (po.verbose > 1):
          print("{}: Updating no fly zones array at 0x{:08x}: {:d} entries".format(po.mdlfile,po.nfzone_pos,po.nfzone_count))
      for i in range(0, po.nfzone_count):
          pvparprop = flyc_nofly_zone_get(po, fwmdlfile, i)
          # Match the current entry to user provided data
          nxparprop = None
          if (nxparprop is None):
              for parprop in nxnfzones:
                  if parprop['area_id'] == pvparprop['area_id']:
                      nxparprop = parprop
                      break
          if (nxparprop is None):
              eprint("{}: Warning: no fly zone not found in fw: area_id={:s}".format(po.mdlfile,pvparprop['area_id']))
              continue
          update_pos=False
          update_radius=False
          update_country=False
          update_limits=False
          update_type=False
          # compare properties to check what we want to update
          if not isclose(nxparprop['lat'], pvparprop['lat']) or not isclose(nxparprop['lng'], pvparprop['lng']):
              update_pos=True
          if nxparprop['radius'] != pvparprop['radius']:
              update_radius=True
          if nxparprop['country'] != pvparprop['country']:
              update_country=True
          if nxparprop['begin_at'] != pvparprop['begin_at'] or nxparprop['end_at'] != pvparprop['end_at']:
              update_limits=True
          if nxparprop['type'] != pvparprop['type']:
              update_type=True
          if (update_pos):
              eprint("{}: pos update not implemented.".format(po.mdlfile)) # TODO
          if (update_radius):
              eprint("{}: radius update not implemented.".format(po.mdlfile)) # TODO
          if (update_country):
              eprint("{}: country update not implemented.".format(po.mdlfile)) # TODO
          if (update_limits):
              eprint("{}: limits update not implemented.".format(po.mdlfile)) # TODO
          if (update_type):
              eprint("{}: type update not implemented.".format(po.mdlfile)) # TODO
      # Now do the same to coords
      if (po.verbose > 1):
          print("{}: Updating no fly coords array at 0x{:08x}: {:d} entries".format(po.mdlfile,po.nfcord_pos,po.nfcord_count))
      for i in range(0, po.nfcord_count):
          pvparprop = flyc_nofly_cord_get(po, fwmdlfile, i)
          # Match the current entry to user provided data
          nxparprop = None
          if (nxparprop is None):
                  if isclose(parprop['lat'], pvparprop['lat']) and isclose(parprop['lng'], pvparprop['lng']):
                      nxparprop = parprop
                      break
          # If not found, try accepting some variation
          if (nxparprop is None):
              for parprop in nxnfzones:
                  if (isclose(parprop['lat'], pvparprop['lat'], rel_tol=1e-3, abs_tol=1e-2) and isclose(parprop['lng'], pvparprop['lng'], rel_tol=1e-3, abs_tol=1e-2)):
                      nxparprop = parprop
                      break
          if (nxparprop is None):
              eprint("{}: Warning: no fly coords not found in fw: area_id={:s}".format(po.mdlfile,pvparprop['area_id']))
              continue
          update_pos=False
          # compare properties to check what we want to update
          # TODO does it really make sense for coord list to first search based on coords, then allow update it? Maybe remove/add from the list instead?
          if not isclose(nxparprop['lat'], pvparprop['lat']) or not isclose(nxparprop['lng'], pvparprop['lng']):
              update_pos=True
          if (update_pos):
              eprint("{}: Coords update not implemented.".format(po.mdlfile)) # TODO
  raise NotImplementedError('Not implemented - no data was updated.')
  if (po.verbose > 0):
      print("{}: Updated {:d} no fly zone entries and {:d} no fly coord entries".format(po.mdlfile,update_zone_count,update_cord_count))

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
