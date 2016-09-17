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
  outfile = ''
  inifile = ''
  section_pos = { '.text': 0x0, '.ARM.exidx': -2, '.dsp_buf': -3, '.data': -4, 'no_init': -5 }
  elftemplate='amba_sys2elf_template.elf'
  verbose = 0
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


def syssw_bin2elf(po, fwpartfile):
  # TODO detect offsets
  # TODO read base address
  # TODO Prepare array of addresses
  # TODO set sizes of uninitialized sections
  # prepare objcopy command line
  objcopy_cmd = '/usr/bin/arm-none-eabi-objcopy'
  objcopy_cmd += ' --update-section "{0:s}={1:s}" --change-section-address "{0:s}=0x{2:08x}"'.format(".text","amba_app_test-sec_text.bin",0xa0001000)
  objcopy_cmd += ' --update-section ".ARM.exidx=amba_app_test-sec_ARMexidx.bin"  --change-section-address ".ARM.exidx=0xa03e7820"'
  objcopy_cmd += ' --update-section ".dsp_buf=amba_app_test-sec_dspbuf.bin" --change-section-address ".dsp_buf=0xa03e7840"'
  objcopy_cmd += ' --update-section ".data=amba_app_test-sec_data.bin" --change-section-address ".data=0xa044c920"'
  objcopy_cmd += ' --update-section "no_init=amba_app_test-sec_noinit.bin" --change-section-address "no_init=0xa04b0b60"'
  objcopy_cmd += ' --change-section-address ".bss.noinit=0xa04b4000"'
  objcopy_cmd += ' --change-section-address ".bss=0xa0858000"'
  objcopy_cmd += ' "{:s}" "{:s}"'.format(po.elftemplate, po.outfile)
  # execute the objcopy command
  objcopy_cmd = "echo "+objcopy_cmd
  retcode = subprocess.call(objcopy_cmd, shell=True)

def main(argv):
  # Parse command line options
  po = ProgOptions()
  try:
     opts, args = getopt.getopt(argv,"hevt:p:s:o:",["help","version","mkelf","fwpart=","template","section=","output="])
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
     elif opt == '-v':
        po.verbose += 1
     elif opt in ("-p", "--fwpart"):
        po.fwpartfile = arg
     elif opt in ("-o", "--output"):
        po.outfile = arg
     elif opt in ("-t", "--template"):
        po.elftemplate = arg
     elif opt in ("-s", "--section"):
        arg_m = re.search('(?P<name>[0-9A-Za-z._-]+)@(?P<pos>[Xx0-9]+)', arg)
        # Convert to integer, detect base from prefix
        po.section_pos[arg_m.group("name")] = int(arg_m.group("pos"),0)
     elif opt in ("-e", "--mkelf"):
        po.command = 'e'
  if len(po.fwpartfile) > 0 and len(po.inifile) == 0:
      po.inifile = os.path.splitext(os.path.basename(po.fwpartfile))[0] + ".a9h"
  if len(po.fwpartfile) > 0 and len(po.outfile) == 0:
      po.outfile = os.path.splitext(os.path.basename(po.fwpartfile))[0] + ".elf"
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
