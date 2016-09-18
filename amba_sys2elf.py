#!/usr/bin/env python

from __future__ import print_function
import sys
import getopt
import os
import hashlib
import mmap
import zlib
import re
import subprocess
import configparser
import itertools
from ctypes import *
from time import gmtime, strftime

def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

class ProgOptions:
  fwpartfile = ''
  basename = ''
  outfile = ''
  inifile = ''
  section_pos = { '.text': 0x0, '.ARM.exidx': -2, '.dsp_buf': -3, '.data': -4, 'no_init': -5, '.bss.noinit': -6, '.bss': -7 }
  elftemplate='amba_sys2elf_template.elf'
  verbose = 0
  dry_run = False
  command = ''

# Converts "System Software" partition from Ambarella a7/a9 firmware
# from a binary image form into ELF format. The ELF format can be then
# easily disassembled, as most tools can read ELF files.
#
# The Ambarella SDK contains an example system application, on which
# most products which use Ambarella SoC base their software.
# The application is linked and prepared like this:
# ---
#  /usr/bin/arm-none-eabi-ld \
#   -EL -p --no-undefined --gc-sections --no-wchar-size-warning \
#   -nostdlib -nodefaultlibs -nostartfiles \
#   -L/usr/lib/arm-none-eabi/lib/armv7-ar/thumb/fpu \
#   -L/usr/lib/gcc/arm-none-eabi/4.9.3/armv7-ar/thumb/fpu \
#   -o out/amba_app.elf -T ../output/app/amba_app.lds \
#   --start-group --whole-archive \
#   ../output/lib/libapp.a \
#   ../output/lib/libapplib.a \
#   ../vendors/ambarella/lib/libaudio.a \
#   ../vendors/ambarella/lib/libaudio_sys.a \
#   ../output/lib/libbsp.a \
#   [...]
#   ../vendors/ambarella/lib/libthreadx.a \
#   ../vendors/ambarella/lib/libusb.a \
#   --no-whole-archive -lc -lnosys -lm -lgcc -lrdimon -lstdc++ \
#   --end-group \
#   app/AmbaVer_LinkInfo.o
#
#  /usr/bin/arm-none-eabi-nm -n -l out/amba_app.elf
#
#  /usr/bin/arm-none-eabi-objcopy -O binary out/amba_app.elf out/amba_app.bin
# ---
# Note that the last command converts a linked ELF file into a binary memory
# image. The purpose of this tool is to revert that last operation, which makes
# it a lot easier to use tols like objdump or IDA Pro.
#
# The script uses an ELF template, which was prepared from example Ambarella SDK
# application by the command (mock_sect.bin is a random file with 32 bytes size):
#  /usr/bin/arm-none-eabi-objcopy \
#   --remove-section ".comment" \
#   --update-section ".text=mock_sect.bin" --change-section-address ".text=0xa0001000" \
#   --change-section-address ".ARM.exidx=0xa0001020" \
#   --update-section ".dsp_buf=mock_sect.bin" --change-section-address ".dsp_buf=0xa0001020" \
#   --update-section ".data=mock_sect.bin" --change-section-address ".data=0xa0001040" \
#   --change-section-address "no_init=0xa0001060" \
#   --change-section-address ".bss.noinit=0xa0004000" \
#   --change-section-address ".bss=0xa03a8000" \
#   amba_app.elf amba_sys2elf_template.elf

def section_is_bss(sectname):
  return sectname.startswith('.bss')

def syssw_read_base_address(po):
  mem_addr = 0
  fname = "{:s}.a9h".format(po.basename)
  if (po.verbose > 1):
    print("{}: Opening {:s}".format(po.fwpartfile,fname))
  parser = configparser.ConfigParser()
  with open(fname, "r") as lines:
    lines = itertools.chain(("[asection]",), lines) # This line adds section header to ini
    parser.read_file(lines)
    mem_addr = int(parser.get("asection", "mem_addr"),16)
  del parser
  return mem_addr

def syssw_bin2elf(po, fwpartfile):
  # read base address from INI file which should be there after AMBA extraction
  memaddr_base = syssw_read_base_address(po)
  if (po.verbose > 0):
    print("{}: Memory base address set to 0x{:08x}".format(po.fwpartfile,memaddr_base))
  # detect position of each section in the binary file
  if (po.verbose > 1):
    print("{}: Searching for sections".format(po.fwpartfile))
  # TODO
  # set positions for bss sections too - to the place
  # where they yould be if they existed
  # TODO
  # Prepare list of sections in the order of position
  sections_order = []
  for sortpos in sorted(po.section_pos.values()):
    for sectname, pos in po.section_pos.iteritems():
      if pos == sortpos:
        sections_order.append(sectname)
  # Prepare list of section sizes
  sections_size = {}
  fwpartfile.seek(0, os.SEEK_END)
  sectpos_next = fwpartfile.tell()
  for sectname in reversed(sections_order):
    sections_size[sectname] = sectpos_next - po.section_pos[sectname]
    sectpos_next = po.section_pos[sectname]
  # Extract sections to separate files
  sections_fname = {}
  for sectname in sections_order:
    if section_is_bss(sectname):
      continue
    if (po.verbose > 0):
      print("{}: Extracting section '{:s}' from binary pos 0x{:08x}".format(po.fwpartfile,sectname,po.section_pos[sectname]))
    fname = "{:s}_sect_{:s}.bin".format(po.basename, re.sub('[\W_]+', '', sectname))
    sections_fname[sectname] = fname
    if not po.dry_run:
      sectfile = open(fname, "wb")
    fwpartfile.seek(po.section_pos[sectname], os.SEEK_SET)
    n = 0
    while (n < sections_size[sectname]):
      copy_buffer = fwpartfile.read(min(1024 * 1024, sections_size[sectname] - n))
      if not copy_buffer:
          raise EOFError("Couldn't read whole section '{:s}' from binary file.".format(sectname))
          break
      n += len(copy_buffer)
      if not po.dry_run:
        sectfile.write(copy_buffer)
    if not po.dry_run:
      sectfile.close()
    if (po.verbose > 1):
      print("{}: Section '{:s}' written to '{:s}'".format(po.fwpartfile,sectname,fname))
  # Prepare array of addresses
  sections_address = {}
  memaddr = memaddr_base
  for sectname in sections_order:
    # align the address
    if (memaddr % 0x20) != 0:
      memaddr += 0x20 - (memaddr % 0x20)
    # add section address to array
    sections_address[sectname] = memaddr
    memaddr += sections_size[sectname]
    if (po.verbose > 0):
      print("{}: Section '{:s}' memory address set to 0x{:08x}".format(po.fwpartfile,sectname,sections_address[sectname]))
  # prepare objcopy command line
  objcopy_cmd = '/usr/bin/arm-none-eabi-objcopy'
  for sectname in sections_order:
    if not section_is_bss(sectname):
      objcopy_cmd += ' --update-section "{0:s}={1:s}"'.format(sectname,sections_fname[sectname])
    objcopy_cmd += ' --change-section-address "{0:s}=0x{1:08x}"'.format(sectname,sections_address[sectname])
  objcopy_cmd += ' "{:s}" "{:s}"'.format(po.elftemplate, po.outfile)
  # execute the objcopy command
  if (po.verbose > 0):
    print("{}: Executing command:\n{:s}".format(po.fwpartfile,objcopy_cmd))
  retcode = 0
  if not po.dry_run:
    retcode = subprocess.call(objcopy_cmd, shell=True)
  if (retcode != 0):
    raise EnvironmentError("Execution of objcopy returned with error {:d}.".format(retcode))
  # update entry point in the ELF header
  elffile = open(po.outfile, "r+b")
  elffile.seek(16+2*4, os.SEEK_SET) # position of e_entry within ELF header
  elffile.write(c_uint(memaddr_base))
  elffile.close()

def main(argv):
  # Parse command line options
  po = ProgOptions()
  try:
     opts, args = getopt.getopt(argv,"hevt:p:s:o:",["help","version","mkelf","dry-run","fwpart=","template","section=","output="])
  except getopt.GetoptError:
     print("Unrecognized options; check amba_sys2elf.py --help")
     sys.exit(2)
  for opt, arg in opts:
     if opt in ("-h", "--help"):
        print("Ambarella Firmware SYS partiton to ELF converter")
        print("amba_sys2elf.py <-e> [-v] -p <fwmdfile> [-t <tmpltfile>]")
        print("  -p <fwpartfile> - name of the firmware partition file")
        print("  -e - make ELF file from a binary image within partition file")
        print("  -v - increases verbosity level; max level is set by -vvv")
        sys.exit()
     elif opt == "--version":
        print("amba_sys2elf.py version 0.1.0")
        sys.exit()
     elif opt == "-v":
        po.verbose += 1
     elif opt == "--dry-run":
        po.dry_run = True
     elif opt in ("-p", "--fwpart"):
        po.fwpartfile = arg
     elif opt in ("-o", "--output"):
        po.outfile = arg
     elif opt in ("-t", "--template"):
        po.elftemplate = arg
     elif opt in ("-s", "--section"):
        arg_m = re.search('(?P<name>[0-9A-Za-z._-]+)@(?P<pos>[Xx0-9A-Fa-f]+)', arg)
        # Convert to integer, detect base from prefix
        po.section_pos[arg_m.group("name")] = int(arg_m.group("pos"),0)
     elif opt in ("-e", "--mkelf"):
        po.command = 'e'
  po.basename = os.path.splitext(os.path.basename(po.fwpartfile))[0]
  if len(po.fwpartfile) > 0 and len(po.inifile) == 0:
      po.inifile = po.basename + ".a9h"
  if len(po.fwpartfile) > 0 and len(po.outfile) == 0:
      po.outfile = po.basename + ".elf"
  if (po.command == 'e'):

    if (po.verbose > 0):
      print("{}: Opening for conversion to ELF".format(po.fwpartfile))
    fwpartfile = open(po.fwpartfile, "rb")

    syssw_bin2elf(po,fwpartfile)

    fwpartfile.close();

  else:

    raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
   main(sys.argv[1:])
