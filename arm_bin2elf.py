#!/usr/bin/env python3

from __future__ import print_function
import sys
import getopt
import os
import hashlib
import mmap
import zlib
import re
import subprocess
import itertools
from ctypes import *
from time import gmtime, strftime

sys.path.insert(0, '../pyelftools')
try:
  import elftools.elf.elffile
  import elftools.elf.sections
  if not callable(getattr(elftools.elf.elffile.ELFFile, "write_changes", None)):
    raise ImportError("The pyelftools library provided has no write support")
except ImportError:
  print("Warning:")
  print("This tool requires version of pyelftools with ELF write support.")
  print("Get it from https://github.com/mefistotelis/pyelftools.git")
  print("clone to upper level folder, '../pyelftools'.")
  raise


def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

class ProgOptions:
  fwpartfile = ''
  basename = ''
  outfile = ''
  section_pos = { '.text': 0x0, '.ARM.exidx': -2, '.data': -4, '.bss': -7 }
  elftemplate='arm_bin2elf_template.elf'
  address_base=0x1000000
  address_space_len=0x2000000 # 32MB
  verbose = 0
  dry_run = False
  command = ''

# Converts BIN firmware with ARM code from a binary image form into
# ELF format. The ELF format can be then easily disassembled, as most
# tools can read ELF files.
#
# The BIN firmware is often linked and prepared like this:
# ---
#  arm-none-eabi-ld \
#   -EL -p --no-undefined --gc-sections \
#   -nostdlib -nodefaultlibs -nostartfiles \
#   -o out/firmware.elf -T custom_sections.lds \
#   --start-group --whole-archive \
#   lib/libapp.a \
#   [...]
#   lib/libmain.a \
#   --no-whole-archive -lc -lnosys -lm -lgcc -lrdimon -lstdc++ \
#   --end-group
#
#  arm-none-eabi-nm -n -l out/firmware.elf
#
#  arm-none-eabi-objcopy -O binary out/firmware.elf out/firmware.bin
# ---
# Note that the last command converts a linked ELF file into a binary
# memory image. The purpose of this tool is to revert that last operation,
# which makes it a lot easier to use tols like objdump or IDA Pro.
#
# The script uses an ELF template, which was prepared especially for BINs
# within DJI firmwares. It was made by compiling an example mock firmware,
# and then stripping all the data with use of objcopy.

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

def armfw_is_proper_ARMexidx_entry(po, eexidx, memaddr_base, pos, loose):
  """ Checks whether given ExIdxEntry object stores a proper entry of 
      .ARM.exidx section. The entries are described in detail in
      "Exception Handling ABI for the ARM Architecture" document.
  """
  if (eexidx.tboffs == 0):
    return False
  glob_offs = prel31_to_addr(eexidx.tboffs, memaddr_base+pos)
  # Check if first word offset falls into ".text" section
  if (glob_offs <= memaddr_base) or (glob_offs >= memaddr_base+pos):
    return False
  # Second word can be one of 3 things: table entry offset, exception entry itself or EXIDX_CANTUNWIND
  # Check if second word contains EXIDX_CANTUNWIND value (0x01)
  if (eexidx.entry == 0x01):
    if (po.verbose > 2):
      print("{}: Matching '{:s}' entry at 0x{:08x}: 0x{:08x} 0x{:08x} [CANTUNWIND]".format(po.fwpartfile,".ARM.exidx",pos,glob_offs,eexidx.entry))
    return True
  # Check if second word contains exception handling entry itself
  if (eexidx.entry & 0x80000000):
    if (po.verbose > 2):
      print("{}: Matching '{:s}' entry at 0x{:08x}: 0x{:08x} 0x{:08x} [handling entry]".format(po.fwpartfile,".ARM.exidx",pos,glob_offs,eexidx.entry))
    return True
  # Check if second word contains table entry start offset
  tbent_offs = prel31_to_addr(eexidx.entry & 0x7fffffff, memaddr_base+pos)
  if (tbent_offs > memaddr_base) and (tbent_offs < memaddr_base+pos):
    if (po.verbose > 2):
      print("{}: Matching '{:s}' entry at 0x{:08x}: 0x{:08x} 0x{:08x} [table entry offs]".format(po.fwpartfile,".ARM.exidx",pos,glob_offs,eexidx.entry))
    return True
  return False

def armfw_detect_sect_ARMexidx(po, fwpartfile,  memaddr_base, start_pos, secalign, loose):
  """ Finds position and size of .ARM.exidx section. That section contains entries
      used for exception handling, and have a particular structure that is quite easy
      to detect, with minimal amount of false positives.
  """
  sectname = ".ARM.exidx"
  eexidx = ExIdxEntry()
  match_count = 0
  match_pos = -1
  match_entries = 0
  reached_eof = False
  pos = start_pos
  assert secalign >= sizeof(ExIdxEntry)
  while (True):
    fwpartfile.seek(pos, os.SEEK_SET)
    # Check how many correct exception entries we have
    entry_count = 0
    entry_pos = pos
    while (True):
      if fwpartfile.readinto(eexidx) != sizeof(eexidx):
        reached_eof = True
        break
      if not armfw_is_proper_ARMexidx_entry(po, eexidx, memaddr_base, entry_pos, loose):
        break
      entry_count += 1
      entry_pos += sizeof(eexidx)
    # Do not allow entry at EOF
    if (reached_eof):
      break
    # verify if padding area is completely filled with 0x00
    if (entry_count > 0):
      if ((pos % secalign) > 0) and (not loose):
        fwpartfile.seek(pos, os.SEEK_SET)
        padding = fwpartfile.read(secalign - (pos % secalign))
        if (padding[0] != 0x00) or (len(set(padding)) > 1):
          entry_count = 0
      # If we found any entries, make sure the position won't divide by align
      # otherwise we would skip the next align unit
      if ((pos % secalign) == 0):
        pos -= sizeof(eexidx)
    # If entry is ok, consider it a match
    if entry_count > 0:
          if (po.verbose > 1):
            print("{}: Matching '{:s}' section at 0x{:08x}: {:d} exception entries".format(po.fwpartfile,sectname,pos,entry_count))
          match_pos = pos
          match_entries = entry_count
          match_count += 1
    # Set position to search for next entry
    pos += secalign
  if (match_count > 1):
    eprint("{}: Warning: multiple ({:d}) matches found for section '{:s}'".format(po.fwpartfile,match_count,sectname))
  if (match_count < 1):
    return -1, 0
  return match_pos, match_entries * sizeof(ExIdxEntry)

def armfw_bin2elf(po, fwpartfile):
  if (po.verbose > 0):
    print("{}: Memory base address set to 0x{:08x}".format(po.fwpartfile,po.address_base))
  # detect position of each section in the binary file
  sections_size = {}
  if (po.verbose > 1):
    print("{}: Searching for sections".format(po.fwpartfile))
  # ARM exceprions index section is easy to find
  sectname = ".ARM.exidx"
  if (po.section_pos[sectname] < 0):
    sect_pos, sect_len = armfw_detect_sect_ARMexidx(po, fwpartfile,  po.address_base, 0, 0x20, False)
    if (sect_pos < 0):
      sect_pos, sect_len = armfw_detect_sect_ARMexidx(po, fwpartfile,  po.address_base, 0, 0x20, True)
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
  # After the .ARM.exidx section come .data section.
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
  # Set positions for bss section too - to the place
  # where they should be if they existed
  sectname = ".bss"
  if (po.section_pos[sectname] < 0):
    sect_pos += sect_len
    if (sect_pos % 0x20) != 0:
      sect_pos += 0x20 - (sect_pos % 0x20)
    sect_len = po.address_space_len - sect_pos
    po.section_pos[sectname] = sect_pos
    sections_size[sectname] = sect_len
  if (po.verbose > 1):
    print("{}: Set '{:s}' section at file pos 0x{:08x}, size 0x{:08x}".format(po.fwpartfile,sectname,po.section_pos[sectname],sections_size[sectname]))

  # Prepare list of sections in the order of position
  sections_order = []
  for sortpos in sorted(set(po.section_pos.values())):
    # First add sections with size equal zero
    for sectname, pos in po.section_pos.items():
      if pos == sortpos:
        if sectname in sections_size.keys():
          if (sections_size[sectname] < 1):
            sections_order.append(sectname)
    # The non-zero sized section should be last
    for sectname, pos in po.section_pos.items():
      if pos == sortpos:
        if sectname not in sections_order:
          sections_order.append(sectname)
  # Prepare list of section sizes
  sectpos_next = po.address_space_len # max size is larger than bin file size due to uninitialized sections (bss)
  for sectname in reversed(sections_order):
    if sectname in sections_size.keys():
      if (sections_size[sectname] > sectpos_next - po.section_pos[sectname]):
        eprint("{}: Warning: section '{:s}' size reduced due to overlapping".format(po.fwpartfile,sectname))
        sections_size[sectname] = sectpos_next - po.section_pos[sectname]
    else:
      sections_size[sectname] = sectpos_next - po.section_pos[sectname]
    sectpos_next = po.section_pos[sectname]
  # Prepare array of addresses
  sections_address = {}
  memaddr = po.address_base
  for sectname in sections_order:
    # align the address
    if (memaddr % 0x20) != 0:
      memaddr += 0x20 - (memaddr % 0x20)
    # add section address to array
    sections_address[sectname] = memaddr
    memaddr += sections_size[sectname]
    if (po.verbose > 0):
      print("{}: Section '{:s}' memory address set to 0x{:08x}".format(po.fwpartfile,sectname,sections_address[sectname]))
  # Copy an ELF template to destination file name
  elf_templt = open(po.elftemplate, "rb")
  if not po.dry_run:
    elf_fh = open(po.outfile, "wb")
  n = 0
  while (1):
    copy_buffer = elf_templt.read(1024 * 1024)
    if not copy_buffer:
        break
    n += len(copy_buffer)
    if not po.dry_run:
      elf_fh.write(copy_buffer)
  elf_templt.close()
  if not po.dry_run:
    elf_fh.close()
  if (po.verbose > 1):
    print("{}: ELF template '{:s}' copied to '{:s}', {:d} bytes".format(po.fwpartfile,po.elftemplate,po.outfile,n))
  # Update entry point in the ELF header
  if (po.verbose > 0):
    print("{}: Updating entry point and section headers".format(po.fwpartfile))
  if not po.dry_run:
    elf_fh = open(po.outfile, "r+b")
  else:
    elf_fh = open(po.elftemplate, "rb")
  elfobj = elftools.elf.elffile.ELFFile(elf_fh)
  elfobj.header['e_entry'] = po.address_base
  # Update section sizes, including the uninitialized (.bss*) sections
  for sectname in sections_order:
    sect = elfobj.get_section_by_name(sectname)
    if (po.verbose > 0):
      print("{}: Preparing ELF section '{:s}' from binary pos 0x{:08x}".format(po.fwpartfile,sectname,po.section_pos[sectname]))
    sect.header['sh_addr'] = sections_address[sectname]
    # for non-bss sections, size will be updated automatically when replacing data
    if section_is_bss(sectname):
      sect.header['sh_size'] = sections_size[sectname]
    elif sections_size[sectname] <= 0:
      sect.set_data(b'')
    else:
      fwpartfile.seek(po.section_pos[sectname], os.SEEK_SET)
      data_buf = fwpartfile.read(sections_size[sectname])
      if not data_buf:
          raise EOFError("Couldn't read section '{:s}' from binary file.".format(sectname))
      sect.set_data(data_buf)
    if (po.verbose > 2):
      print("{}: Updating section '{:s}' and shifting subsequent sections".format(po.fwpartfile,sectname))
    elfobj.set_section_by_name(sectname, sect)
  if (po.verbose > 1):
    print("{}: Writing changes to '{:s}'".format(po.fwpartfile,po.outfile))
  if not po.dry_run:
    elfobj.write_changes()
  elf_fh.close()

def main(argv):
  # Parse command line options
  po = ProgOptions()
  try:
     opts, args = getopt.getopt(argv,"hevt:p:l:s:o:",["help","version","mkelf","dry-run","fwpart=","template","addrsplen=","section=","output="])
  except getopt.GetoptError:
     print("Unrecognized options; check arm_bin2elf.py --help")
     sys.exit(2)
  for opt, arg in opts:
     if opt in ("-h", "--help"):
        print("Binary firmware with ARM code to ELF converter")
        print("arm_bin2elf.py <-e> [-v] -p <fwmdfile> [-t <tmpltfile>]")
        print("  -p <fwpartfile> - name of the firmware binary file")
        print("  -e - make ELF file from a binary image")
        print("  -l - set address space length; influences size of last section")
        print("  -v - increases verbosity level; max level is set by -vvv")
        sys.exit()
     elif opt == "--version":
        print("arm_bin2elf.py version 0.1.1")
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
        arg_m = re.search('(?P<name>[0-9A-Za-z._-]+)@(?P<pos>[Xx0-9A-Fa-f]+)', arg)
        # Convert to integer, detect base from prefix
        po.section_pos[arg_m.group("name")] = int(arg_m.group("pos"),0)
     elif opt in ("-e", "--mkelf"):
        po.command = 'e'
  po.basename = os.path.splitext(os.path.basename(po.fwpartfile))[0]
  if len(po.fwpartfile) > 0 and len(po.outfile) == 0:
      po.outfile = po.basename + ".elf"
  if (po.command == 'e'):

    if (po.verbose > 0):
      print("{}: Opening for conversion to ELF".format(po.fwpartfile))
    fwpartfile = open(po.fwpartfile, "rb")

    armfw_bin2elf(po,fwpartfile)

    fwpartfile.close();

  else:

    raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
   main(sys.argv[1:])
