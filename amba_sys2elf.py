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

# This tool requires version of pyelftools with elf write support.
# Get it from https://github.com/mefistotelis/pyelftools.git
# clone to upper level folder, as the path below indicates.
sys.path.insert(0, '../pyelftools')
#import elftools
import elftools.elf.elffile
import elftools.elf.sections

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
#  echo "MockDataToUpdateUsingObjcopy" > mock_sect.bin
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

class ExIdxEntry(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('tboffs', c_uint),
              ('entry', c_uint)]
  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        val = getattr(self, varkey)
        d[varkey] = "{:08X}".format(val)
    return d
  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)

class ExIdxPaddedEntry(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('tboffs', c_uint),
              ('entry', c_uint),
              ('padding', c_ubyte * 24)]
  def dict_export(self):
    d = dict()
    for (varkey, vartype) in self._fields_:
        val = getattr(self, varkey)
        d[varkey] = "{:08X}".format(val)
    return d
  def __repr__(self):
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)

def section_is_bss(sectname):
  return sectname.startswith('.bss')

def sign_extend(value, bits):
  sign_bit = 1 << (bits - 1)
  return (value & (sign_bit - 1)) - (value & sign_bit)

# Convert a prel31 symbol to an absolute address
def prel31_to_addr(ptr,refptr):
  # sign-extend to 32 bits
  offset = sign_extend(ptr, 31)
  #offset = (c_int(ptr) << 1) >> 1
  return c_uint(refptr + offset).value

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

# Finds position and size of .ARM.exidx section. That section contains entries
# described in detail in "Exception Handling ABI for the ARM Architecture"
# document. The function currently does many assumptions. It can only find
# section which uses only one entry of CANTUNWIND type. It seem to be enough
# for Phantom 3 firmware, but might not be enough for others.
def syssw_detect_sect_ARMexidx(po, fwpartfile,  memaddr_base, start_pos, loose):
  sectname = ".ARM.exidx"
  eexidx = ExIdxPaddedEntry()
  match_count = 0
  match_pos = -1
  loose = False
  pos = start_pos
  while (True):
    fwpartfile.seek(pos, os.SEEK_SET)
    if fwpartfile.readinto(eexidx) != sizeof(eexidx):
      break
    glob_offs = prel31_to_addr(eexidx.tboffs, memaddr_base+pos)
    # Check if offset falls into ".text" section
    if (glob_offs > memaddr_base) and (glob_offs < memaddr_base+pos):
      # Check if entry contains EXIDX_CANTUNWIND value (0x01)
      if (eexidx.entry == 0x01):
        # verify if padding area is completely filled with 0x00
        if (eexidx.padding[0] == 0x00) and (len(set(eexidx.padding)) == 1) or loose:
          if (po.verbose > 1):
            print("{}: Matching '{:s}' entry at 0x{:08x}: 0x{:08x} 0x{:08x}".format(po.fwpartfile,sectname,pos,glob_offs,eexidx.entry))
          match_pos = pos
          match_count += 1
    pos += 0x20
  if (match_count > 1):
    eprint("{}: Warning: multiple ({:d}) matches found for section '{:s}'".format(po.fwpartfile,match_count,sectname))
  if (match_count < 1):
    return -1, 0
  return match_pos, sizeof(ExIdxEntry)

# Finds position and size of no_init section. That section is filled with
# zeros, and most likely has 1024 bytes, as is used only by DoPrintDsp().
# But here we will just make it zero size, so that everything is take into
# .data section.
def syssw_detect_sect_no_init(po, fwpartfile,  memaddr_base, start_pos, loose):
  sectname = "no_init"
  fwpartfile.seek(0, os.SEEK_END)
  match_pos = fwpartfile.tell()
  return match_pos, 0

def syssw_bin2elf(po, fwpartfile):
  # read base address from INI file which should be there after AMBA extraction
  memaddr_base = syssw_read_base_address(po)
  if (po.verbose > 0):
    print("{}: Memory base address set to 0x{:08x}".format(po.fwpartfile,memaddr_base))
  # detect position of each section in the binary file
  sections_size = {}
  if (po.verbose > 1):
    print("{}: Searching for sections".format(po.fwpartfile))
  # ARM exceprions index section is easy to find
  sectname = ".ARM.exidx"
  if (po.section_pos[sectname] < 0):
    sect_pos, sect_len = syssw_detect_sect_ARMexidx(po, fwpartfile,  memaddr_base, 0, False)
    if (sect_pos < 0):
      sect_pos, sect_len = syssw_detect_sect_ARMexidx(po, fwpartfile,  memaddr_base, 0, True)
    if (sect_pos < 0):
      raise EOFError("No matches found for section '{:s}' in binary file.".format(sectname))
    po.section_pos[sectname] = sect_pos
    if (sect_len > 0):
      sections_size[sectname] = sect_len
  else:
    sect_pos = po.section_pos[sectname]
    sect_len = 0x20
  if (po.verbose > 1):
    print("{}: Set '{:s}' section at file pos 0x{:08x}, size 0x{:08x}".format(po.fwpartfile,sectname,po.section_pos[sectname],sections_size[sectname]))
  # Now let's assume that the .ARM.exidx section is located after .text section. Also, the .text section
  # is first because it contains interrupt table located at offset 0
  sectname = ".text"
  if (po.section_pos[sectname] < 0):
    if (sect_pos > 0x20):
      po.section_pos[sectname] = 0x0
    else:
      raise EOFError("No place for '{:s}' section before the '{:s}' section in binary file.".format(sectname,".ARM.exidx"))
  # After the .ARM.exidx section come two data sections - .dsp_buf and .data. Since they are quite similar,
  # we can safely make one of them zero-sized, and use all the size for second one.
  sectname = ".dsp_buf"
  if (po.section_pos[sectname] < 0):
    sect_pos += sect_len
    sect_len = 0
    if (sect_pos % 0x20) != 0:
      sect_pos += 0x20 - (sect_pos % 0x20)
    po.section_pos[sectname] = sect_pos
    sections_size[sectname] = 0
  else:
    sect_pos = po.section_pos[sectname]
    sect_len = 0
  # same goes to no_init section behind the data section - make it zero size
  sectname = "no_init"
  if (po.section_pos[sectname] < 0):
    last_sect_pos, last_sect_len = syssw_detect_sect_no_init(po, fwpartfile,  memaddr_base, sect_pos, False)
    po.section_pos[sectname] = last_sect_pos
    sections_size[sectname] = last_sect_len
  else:
    last_sect_pos = po.section_pos[sectname]
    last_sect_len = 0
  # Now we can make the .data section take everything .dsp_buf and no_init
  sectname = ".data"
  if (po.section_pos[sectname] < 0):
    sect_pos += sect_len
    sect_len = last_sect_pos - sect_pos
    if (sect_pos % 0x20) != 0:
      sect_pos += 0x20 - (sect_pos % 0x20)
    po.section_pos[sectname] = sect_pos
    sections_size[sectname] = sect_len
  if (po.verbose > 1):
    print("{}: Set '{:s}' section at file pos 0x{:08x}, size 0x{:08x}".format(po.fwpartfile,sectname,po.section_pos[sectname],sections_size[sectname]))
  # Set positions for bss sections too - to the place
  # where they should be if they existed
  sect_pos = last_sect_pos
  sect_len = last_sect_len
  sectname = ".bss.noinit"
  if (po.section_pos[sectname] < 0):
    sect_pos += sect_len
    if (sect_pos % 0x20) != 0:
      sect_pos += 0x20 - (sect_pos % 0x20)
    sect_len = 0x400000
    po.section_pos[sectname] = sect_pos
    sections_size[sectname] = sect_len
  else:
    sect_pos = po.section_pos[sectname]
    sect_len = 0
  if (po.verbose > 1):
    print("{}: Set '{:s}' section at file pos 0x{:08x}, size 0x{:08x}".format(po.fwpartfile,sectname,po.section_pos[sectname],sections_size[sectname]))
  sectname = ".bss"
  if (po.section_pos[sectname] < 0):
    sect_pos += sect_len
    if (sect_pos % 0x20) != 0:
      sect_pos += 0x20 - (sect_pos % 0x20)
    sect_len = 0x2000000 - sect_pos
    po.section_pos[sectname] = sect_pos
    sections_size[sectname] = sect_len
  if (po.verbose > 1):
    print("{}: Set '{:s}' section at file pos 0x{:08x}, size 0x{:08x}".format(po.fwpartfile,sectname,po.section_pos[sectname],sections_size[sectname]))

  # Prepare list of sections in the order of position
  sections_order = []
  for sortpos in sorted(set(po.section_pos.values())):
    # First add sections with size equal zero
    for sectname, pos in po.section_pos.iteritems():
      if pos == sortpos:
        if sectname in sections_size.keys():
          if (sections_size[sectname] < 1):
            sections_order.append(sectname)
    # The non-zero sized section should be last
    for sectname, pos in po.section_pos.iteritems():
      if pos == sortpos:
        if sectname not in sections_order:
          sections_order.append(sectname)
  # Prepare list of section sizes
  sectpos_next = 0x2000000 # max size is larger than bin file size due to uninitialized sections (bss)
  for sectname in reversed(sections_order):
    if sectname in sections_size.keys():
      if (sections_size[sectname] > sectpos_next - po.section_pos[sectname]):
        eprint("{}: Warning: section '{:s}' size reduced due to overlapping".format(po.fwpartfile,sectname))
        sections_size[sectname] = sectpos_next - po.section_pos[sectname]
    else:
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
  #TODO use elftools library instead of calling external executable
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
  if (po.verbose > 0):
    print("{}: Updating entry point and section headers".format(po.fwpartfile))
  if not po.dry_run:
    elf_fh = open(po.outfile, "r+b")
  else:
    elf_fh = open(po.outfile, "rb")
  elfobj = elftools.elf.elffile.ELFFile(elf_fh)
  elfobj.header['e_entry'] = memaddr_base
  # update section sizes, including the uninitialized (.bss*) sections
  for sectname in sections_order:
    sect = elfobj.get_section_by_name(sectname)
    sect.header['sh_addr'] = sections_address[sectname]
    # for non-bss sections, size will be updated automatically when replacing data sect.set_data(data_buf)
    if section_is_bss(sectname):
      sect.header['sh_size'] = sections_size[sectname]
    elfobj.set_section_by_name(sectname, sect)
  if not po.dry_run:
    elfobj.write_changes()
  elf_fh.close()

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
        print("amba_sys2elf.py version 0.1.1")
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
