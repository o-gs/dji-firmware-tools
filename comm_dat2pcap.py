#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Raw DUPC packets to PCap converter

This tool parses Dji Unified Packet Container packets from input file,
and puts the results into PCap file.

PCap files can be used with WireShark and other tools for packets analysis.

"""

from __future__ import print_function
import sys
import getopt
import os
import re
import configparser
import itertools

sys.path.insert(0, './')
from comm_serial2pcap import setup_output, do_packetiser, CaptureStats

def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

class ProgOptions:
  datfile = ''
  pcapfile = ''
  basename = ''
  verbose = 0
  command = ''

def do_dat2pcap(po, datfile, pcapfile)
  pass

def main(argv):
  """ Main executable function.

      Its task is to parse command line options and call a function which performs selected command.
  """
  po = ProgOptions()
  # Parse command line options
  try:
     opts, args = getopt.getopt(argv,"hvd:p:",["help","version","datfile=","pcapfile="])
  except getopt.GetoptError:
     print("Unrecognized options; check comm_dat2pcap.py --help")
     sys.exit(2)
  for opt, arg in opts:
     if opt in ("-h", "--help"):
        print("Dji Unified Packet Container parser: Raw DUPC packets to PCap converter")
        print("comm_dat2pcap.py [-v] -d <datfile> [-p <pcapfile>]")
        print("  -d <datfile> - input from dat file (Raw DUPC) of given name")
        print("  -p <pcapfile> - output to pcap file of given name")
        print("  -v - increases verbosity level; max level is set by -vvv")
        sys.exit()
     elif opt == "--version":
        print("comm_dat2pcap.py version 0.1.0")
        sys.exit()
     elif opt == "-v":
        po.verbose += 1
     elif opt in ("-d", "--datfile"):
        po.datfile = arg
        po.command == 'd'
     elif opt in ("-p", "--pcapfile"):
        po.pcapfile = arg

  po.basename = os.path.splitext(os.path.basename(po.datfile))[0]
  if len(po.datfile) > 0 and len(po.pcapfile) == 0:
     po.pcapfile = po.basename + ".pcap"

  if (po.command == 'd'):

     if (po.verbose > 0):
        print("{}: Opening Raw DUPC for conversion to PCap".format(po.datfile))
     # read base address from INI file which should be there after AMBA extraction
     datfile = open(po.datfile, "rb")
     pcapfile = open(po.pcapfile, "wb")

     do_dat2pcap(po,datfile)

     datfile.close();
     pcapfile.close();

  else:

     raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
   main(sys.argv[1:])
