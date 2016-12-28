#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Ambarella Firmware SYS partiton to ELF converter

 Converts "System Software" partition from Ambarella a7/a9 firmware
 from a binary image form into ELF format. The ELF format can be then
 easily disassembled, as most tools can read ELF files.

 The Ambarella SDK contains an example system application, on which
 most products which use Ambarella SoC base their software.
 The application is linked and prepared like this:
```
  /usr/bin/arm-none-eabi-ld \
   -EL -p --no-undefined --gc-sections --no-wchar-size-warning \
   -nostdlib -nodefaultlibs -nostartfiles \
   -L/usr/lib/arm-none-eabi/lib/armv7-ar/thumb/fpu \
   -L/usr/lib/gcc/arm-none-eabi/4.9.3/armv7-ar/thumb/fpu \
   -o out/amba_app.elf -T ../output/app/amba_app.lds \
   --start-group --whole-archive \
   ../output/lib/libapp.a \
   ../output/lib/libapplib.a \
   ../vendors/ambarella/lib/libaudio.a \
   ../vendors/ambarella/lib/libaudio_sys.a \
   ../output/lib/libbsp.a \
   [...]
   ../vendors/ambarella/lib/libthreadx.a \
   ../vendors/ambarella/lib/libusb.a \
   --no-whole-archive -lc -lnosys -lm -lgcc -lrdimon -lstdc++ \
   --end-group \
   app/AmbaVer_LinkInfo.o

  /usr/bin/arm-none-eabi-nm -n -l out/amba_app.elf

  /usr/bin/arm-none-eabi-objcopy -O binary out/amba_app.elf out/amba_app.bin
```
 Note that the last command converts a linked ELF file into a binary memory
 image. The purpose of this tool is to revert that last operation, which makes
 it a lot easier to use tols like objdump or IDA Pro.

 The script uses an ELF template, which was prepared from example Ambarella SDK
 application by the command (mock_sect.bin is a random file with 32 bytes size):
```
  echo "MockDataToUpdateUsingObjcopy" > mock_sect.bin
  /usr/bin/arm-none-eabi-objcopy \
   --remove-section ".comment" \
   --update-section ".text=mock_sect.bin" --change-section-address ".text=0xa0001000" \
   --change-section-address ".ARM.exidx=0xa0001020" \
   --update-section ".dsp_buf=mock_sect.bin" --change-section-address ".dsp_buf=0xa0001020" \
   --update-section ".data=mock_sect.bin" --change-section-address ".data=0xa0001040" \
   --change-section-address "no_init=0xa0001060" \
   --change-section-address ".bss.noinit=0xa0004000" \
   --change-section-address ".bss=0xa03a8000" \
   amba_app.elf amba_sys2elf_template.elf
```

 This tool really uses arm_bin2elf to do the work; it just sets optimal
 initial parameters for the Ambarella A9 firmware input.

"""

from __future__ import print_function
import sys
import getopt
import os
import re
import configparser
import itertools

sys.path.insert(0, './')
from arm_bin2elf import eprint, ProgOptions, armfw_bin2elf

def syssw_read_base_address(po):
  mem_addr = 0
  # Do not use basename - a9h file is in the same folder where a9s was
  fname = "{:s}.a9h".format(os.path.splitext(po.fwpartfile)[0])
  if (po.verbose > 1):
    print("{}: Opening {:s}".format(po.fwpartfile,fname))
  parser = configparser.ConfigParser()
  with open(fname, "r") as lines:
    lines = itertools.chain(("[asection]",), lines) # This line adds section header to ini
    parser.read_file(lines)
    mem_addr = int(parser.get("asection", "mem_addr"),16)
  del parser
  return mem_addr

def main(argv):
  """ Main executable function.

      Its task is to parse command line options and call a function which performs selected command.
  """
  po = ProgOptions()
  # Set optimal options for Ambarella A9 ARM firmware
  po.elftemplate='amba_sys2elf_template.elf'
  po.inifile = '' # What differs Ambarella BIN from other BINs is INI file with base address inside
  po.address_base=0x1000000
  po.address_space_len=0x2000000 # 32MB
  po.expect_func_align = 4 # Full length instructions are used in Cortex A9 binary
  po.expect_sect_align = 0x20 # This is how sections are aligned in Ambarella SDK
  # Parse command line options
  try:
     opts, args = getopt.getopt(argv,"hevt:p:l:b:s:o:",["help","version","mkelf","dry-run","fwpart=","template","addrsplen=","baseaddr=","section=","output="])
  except getopt.GetoptError:
     print("Unrecognized options; check amba_sys2elf.py --help")
     sys.exit(2)
  for opt, arg in opts:
     if opt in ("-h", "--help"):
        print("Ambarella Firmware SYS partiton to ELF converter")
        print("amba_sys2elf.py <-e> [-v] -p <fwmdfile> [-o <elffile>] [-t <tmpltfile>]")
        print("  -p <fwpartfile> - name of the firmware binary file")
        print("  -o <elffile> - output file name")
        print("  -t <tmpltfile> - template file name")
        print("  -e - make ELF file from a binary image")
        print("  -l <spacelen> - set address space length; influences size of last section")
        print("  -b <baseaddr> - set base address; first section will start at this memory location")
        print("  -v - increases verbosity level; max level is set by -vvv")
        sys.exit()
     elif opt == "--version":
        print("amba_sys2elf.py version 0.2.0")
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
     elif opt in ("-l", "--addrsplen"):
        po.address_space_len = int(arg,0)
     elif opt in ("-b", "--baseaddr"):
        po.address_base = int(arg,0)
     elif opt in ("-s", "--section"):
        arg_m = re.search('(?P<name>[0-9A-Za-z._-]+)(@(?P<pos>[Xx0-9A-Fa-f]+))?(:(?P<len>[Xx0-9A-Fa-f]+))?', arg)
        # Convert to integer, detect base from prefix
        if arg_m.group("pos") is not None:
           po.section_pos[arg_m.group("name")] = int(arg_m.group("pos"),0)
        if arg_m.group("len") is not None:
           po.section_size[arg_m.group("name")] = int(arg_m.group("len"),0)
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
     # read base address from INI file which should be there after AMBA extraction
     po.address_base = syssw_read_base_address(po)
     fwpartfile = open(po.fwpartfile, "rb")

     armfw_bin2elf(po,fwpartfile)

     fwpartfile.close();

  else:

     raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
   main(sys.argv[1:])
