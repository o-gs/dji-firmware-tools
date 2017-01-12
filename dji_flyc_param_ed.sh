#!/usr/bin/env python3

from __future__ import print_function
import sys
import getopt
import re
import os
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
  verbose = 0
  command = ''
  param_pos = -1

def flyc_pos_search(po, fwmdlfile):
  return -1

def flyc_list(po, fwmdlfile):
  po.param_pos = flyc_pos_search(po, fwmdlfile)
  raise NotImplementedError('Function unfininshed.')

def flyc_extract(po, fwmdlfile):
  po.param_pos = flyc_pos_search(po, fwmdlfile)
  raise NotImplementedError('Function unfininshed.')

def flyc_update(po, fwmdlfile):
  po.param_pos = flyc_pos_search(po, fwmdlfile)
  raise NotImplementedError('Function unfininshed.')

def main(argv):
  # Parse command line options
  po = ProgOptions()
  try:
     opts, args = getopt.getopt(argv,"hvm:",["help","version","mdlfile="])
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
     elif opt in ("-x", "--extract"):
        po.command = 'x'
     elif opt in ("-u", "--update"):
        po.command = 'u'

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
