#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Ambarella Firmware SYS partiton to ELF converter.

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
__version__ = "0.2.1"
__author__ = "Mefistotelis @ Original Gangsters"
__license__ = "GPL"

import sys
import argparse
import os
import re
import configparser
import itertools

sys.path.insert(0, './')
from arm_bin2elf import eprint, armfw_bin2elf, parse_section_param

def syssw_read_base_address(po, fname):
  mem_addr = 0
  # Do not use basename - a9h file is in the same folder where a9s was
  if (po.verbose > 1):
    print("{}: Opening {:s}".format(po.fwpartfile,fname))
  parser = configparser.ConfigParser()
  with open(fname, "r") as lines:
    lines = itertools.chain(("[asection]",), lines) # This line adds section header to ini
    parser.read_file(lines)
    mem_addr = int(parser.get("asection", "mem_addr"),16)
  del parser
  return mem_addr

def main():
  """ Main executable function.

  Its task is to parse command line options and call a function which performs requested command.
  """
  # Parse command line options
  # Set optimal options for Ambarella A9 ARM firmware

  parser = argparse.ArgumentParser(description=__doc__.split('.')[0])

  parser.add_argument("-p", "--fwpartfile", type=str, required=True,
          help="Executable ARM firmware binary module file")

  parser.add_argument("-o", "--elffile", type=str,
          help="Output ELF file name (default is fwpartfile with elf extension appended)")

  parser.add_argument("-t", "--tmpltfile", type=str, default="amba_sys2elf_template.elf",
          help="Template ELF file to use header fields from (default is \"%(default)s\")")

  parser.add_argument('-l', '--addrspacelen', default=0x2000000, type=lambda x: int(x,0),
          help='Set address space length; influences size of last section (defaults to 0x%(default)X)')

  parser.add_argument("-s", "--section", action='append', metavar='SECT@POS:LEN', type=parse_section_param,
          help="Set section position and/or length; can be used to override " \
           "detection of sections; setting section .ARM.exidx will influence " \
           ".text and .data, moving them and sizing to fit one before and one " \
           "after the .ARM.exidx. Parameters are: " \
           "SECT - a text name of the section, as defined in elf template; multiple sections " \
           "can be cloned from the same template section by adding index at end (ie. .bss2); " \
           "POS - is a position of the section within input file (not a memory address!); " \
           "LEN - is the length of the section (in both input file and memory, unless its " \
           "uninitialized section, in which case it is memory size as file size is 0)")

  parser.add_argument("--dry-run", action="store_true",
          help="Do not write any files or do permanent changes")

  parser.add_argument("-v", "--verbose", action="count", default=0,
          help="Increases verbosity level; max level is set by -vvv")

  subparser = parser.add_mutually_exclusive_group()

  subparser.add_argument( "--inifile", type=str,
          help="INI file name with base address (default is fwpartfile with a9h extension appended)")

  subparser.add_argument('-b', '--baseaddr', type=lambda x: int(x,0),
          help='Set base address; first section will start at this memory location (default is to get address from INI file)')

  subparser = parser.add_mutually_exclusive_group()

  subparser.add_argument("-e", "--mkelf", action="store_true",
          help="make ELF file from a binary image")

  subparser.add_argument("--version", action='version', version="%(prog)s {version} by {author}"
            .format(version=__version__,author=__author__),
          help="Display version information and exit")

  po = parser.parse_args()

  po.expect_func_align = 4 # Full length instructions are used in Cortex A9 binary
  po.expect_sect_align = 0x20 # This is how sections are aligned in Ambarella SDK
  # For some reason, if no "--section" parameters are present, argparse leaves this unset
  if po.section is None:
      po.section = []
  # Flatten the sections we got in arguments
  po.section_pos = {}
  po.section_size = {}
  for sect in po.section:
      po.section_pos.update(sect["pos"])
      po.section_size.update(sect["len"])

  po.basename = os.path.splitext(os.path.basename(po.fwpartfile))[0]
  # What differs Ambarella BIN from other BINs is INI file with base address inside
  if len(po.fwpartfile) > 0 and (po.inifile is None or len(po.inifile) == 0):
     # Assume .a9h is in the same folder as .a9s - do not strip path for it
     po.inifile = os.path.splitext(po.fwpartfile)[0] + ".a9h"
  if len(po.fwpartfile) > 0 and (po.elffile is None or len(po.elffile) == 0):
      po.elffile = po.basename + ".elf"

  if po.mkelf:

     if (po.verbose > 0):
        print("{}: Opening for conversion to ELF".format(po.fwpartfile))
     # read base address from INI file which should be there after AMBA extraction
     if po.baseaddr is None:
         po.baseaddr = syssw_read_base_address(po, po.inifile)
     fwpartfile = open(po.fwpartfile, "rb")

     armfw_bin2elf(po,fwpartfile)

     fwpartfile.close();

  else:

     raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        eprint("Error: "+str(ex))
        #raise
        sys.exit(10)
