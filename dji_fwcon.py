#!/usr/bin/env python

import sys
import getopt
from ctypes import *
from os.path import basename

class ProgOptions:
  fwpkgfile = ''
  dcprefix = ''
  verbose = 0
  command = ''

class FwPkgHeader(Structure):
  _pack_ = 1
  _fields_ = [('magic', c_char * 6),
              ('hdrend_offs', c_ushort),
              ('reserved8', c_ushort),
              ('version', c_ushort),
              ('manufacturer', c_char * 16),
              ('model', c_char * 16),
              ('entry_count', c_ushort),
              ('reserved2E', c_int),
              ('reserved32', c_int),
              ('reserved36', c_char * 10)]
  def __repr__(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    from pprint import pformat
    return pformat(d, indent=4, width=1)

class FwPkgEntry(Structure):
  _pack_ = 1
  _fields_ = [('target', c_char),
              ('spcoding', c_char),
              ('reserved2', c_ushort),
              ('version', c_uint),
              ('dt_offs', c_uint),
              ('dt_length', c_uint),
              ('dt_alloclen', c_uint),
              ('dt_md5', c_char * 16),
              ('dt_2ndhash', c_char * 16)]
  def __repr__(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    from pprint import pformat
    return pformat(d, indent=4, width=1)

def dji_extract(po, fwpkgfile):
  pkghead = FwPkgHeader()
  if fwpkgfile.readinto(pkghead) != sizeof(pkghead):
      raise EOFError("Couldn't read firmware package file header.")
  if (po.verbose > 1):
      print("{}: Header:".format(po.fwpkgfile))
      print(pkghead)

  pkgentries = []
  for i in range(pkghead.entry_count):
      e = FwPkgEntry()
      if fwpkgfile.readinto(e) != sizeof(e):
          raise EOFError("Couldn't read firmware package file entry.")
      if (po.verbose > 1):
          print("{}: Entry {}".format(po.fwpkgfile,i))
          print(e)
      if e.dt_length != e.dt_alloclen:
          raise RuntimeWarning("Entry size mismatch, {} instead of {}.".format(e.dt_length,e.dt_alloclen))
      pkgentries.append(e)

  pkghead_checksum = c_ushort()
  if (po.verbose > 1):
      print("{}: Headers checksum {}".format(po.fwpkgfile,pkghead_checksum))

  if fwpkgfile.readinto(pkghead_checksum) != sizeof(pkghead_checksum):
      raise EOFError("Couldn't read firmware package file header checksum.")

  if fwpkgfile.tell() != pkghead.hdrend_offs:
      raise RuntimeWarning("Header end offset does not match; should end at {}, ends at {}.".format(pkghead.hdrend_offs,fwpkgfile.tell()))

  for i, e in enumerate(pkgentries):
      if (po.verbose > 0):
          print("{}: Extracting entry {}, {} bytes".format(po.fwpkgfile,i,e.dt_length))
      fwitmfile = open("{}_{}.bin".format(po.dcprefix,i), "wb")
      fwpkgfile.seek(e.dt_offs)
      n = 0
      while n < e.dt_length:
          copy_buffer = fwpkgfile.read(min(1024 * 1024, e.dt_length - n))
          if not copy_buffer:
              break
          n += len(copy_buffer)
          fwitmfile.write(copy_buffer)

def dji_create(po, fwpkgfile):
    raise NotImplementedError('NOT IMPLEMENTED')

def main(argv):
  # Parse command line options
  po = ProgOptions()
  try:
     opts, args = getopt.getopt(argv,"hxvp:m:",["help","version","fwpkg=","mdprefix="])
  except getopt.GetoptError:
     print("Unrecognized options; check dji_fwcon.py --help")
     sys.exit(2)
  for opt, arg in opts:
     if opt in ("-h", "--help"):
        print("dji_fwcon.py <-x|-a> [-v] -p <fwpkgfile> [-d <dcprefix>]")
        print("  -p <fwpkgfile> - name of the firmware package file")
        print("  -m <mdprefix> - file name prefix for the single decomposed firmware modules")
        print("                  defaults to base name of firmware package file")
        print("  -x - extract firmware package into modules")
        print("  -a - add module files to firmware package")
        print("  -v - increases verbosity level; max level is set by -vvv")
        sys.exit()
     elif opt == "--version":
        print("dji_fwcon.py version 0.1.0")
        sys.exit()
     elif opt == '-v':
        po.verbose += 1
     elif opt in ("-p", "--fwpkg"):
        po.fwpkgfile = arg
     elif opt in ("-m", "--mdprefix"):
        po.dcprefix = arg
     elif opt in ("-x", "--extract"):
        po.command = 'x'
     elif opt in ("-a", "--add"):
        po.command = 'a'
  if len(po.fwpkgfile) > 0 and len(po.dcprefix) == 0:
      po.dcprefix = os.path.splitext(basename(po.fwpkgfile))[0]

  if (po.command == 'x'):

    if (po.verbose > 0):
      print("{}: Opening".format(po.fwpkgfile))
    fwpkgfile = open(po.fwpkgfile, "rb")

    dji_extract(po,fwpkgfile)

    fwpkgfile.close();

  elif (po.command == 'a'):

    if (po.verbose > 0):
      print("{}: Opening".format(po.fwpkgfile))
    fwpkgfile = open(po.fwpkgfile, "wb")

    dji_create(po,fwpkgfile)

    fwpkgfile.close();

  else:

    raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
   main(sys.argv[1:])
