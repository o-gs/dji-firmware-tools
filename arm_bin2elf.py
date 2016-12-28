#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Binary firmware with ARM code to ELF converter

 Converts BIN firmware with ARM code from a binary image form into
 ELF format. The ELF format can be then easily disassembled, as most
 tools can read ELF files.

 The BIN firmware is often linked and prepared like this:

```
  arm-none-eabi-ld \
   -EL -p --no-undefined --gc-sections \
   -nostdlib -nodefaultlibs -nostartfiles \
   -o out/firmware.elf -T custom_sections.lds \
   --start-group --whole-archive \
   lib/libapp.a \
   [...]
   lib/libmain.a \
   --no-whole-archive -lc -lnosys -lm -lgcc -lrdimon -lstdc++ \
   --end-group

  arm-none-eabi-nm -n -l out/firmware.elf

  arm-none-eabi-objcopy -O binary out/firmware.elf out/firmware.bin
```

 Note that the last command converts a linked ELF file into a binary
 memory image. The purpose of this tool is to revert that last operation,
 which makes it a lot easier to use tols like objdump or IDA Pro.

 The script uses an ELF template, which was prepared especially for BINs
 within DJI firmwares. It was made by compiling an example mock firmware,
 and then stripping all the data with use of objcopy.
"""

from __future__ import print_function
import sys
import getopt
import os
import hashlib
import mmap
import zlib
import re
import itertools
from ctypes import *

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
  section_pos = {}
  section_size = {}
  elftemplate='arm_bin2elf_template.elf'
  address_base=0x1000000
  address_space_len=0x2000000 # 32MB
  expect_func_align = 2
  expect_sect_align = 0x10
  verbose = 0
  dry_run = False
  command = ''


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

def section_is_bss(sectname):
  return sectname.startswith('.bss')

def sign_extend(value, bits):
  """ Sign-extend an integer value from given amount of bits to full Python int
  """
  sign_bit = 1 << (bits - 1)
  return (value & (sign_bit - 1)) - (value & sign_bit)

def prel31_to_addr(ptr,refptr):
  """ Convert a prel31 symbol to an absolute address
  """
  offset = sign_extend(ptr, 31)
  return c_uint(refptr + offset).value

def armfw_is_proper_ARMexidx_entry(po, fwpartfile, eexidx, memaddr_base, func_align, arr_pos, ent_pos):
  """ Checks whether given ExIdxEntry object stores a proper entry of 
      .ARM.exidx section. The entries are described in detail in
      "Exception Handling ABI for the ARM Architecture" document.
      The function assumes that .text section with code is located before
      the .ARM.exidx section, starting at memaddr_base.
  """
  sectname = ".ARM.exidx"
  # Spec states clearly this offset is "with bit 31 clear"
  if (eexidx.tboffs == 0) or (eexidx.tboffs & 0x80000000):
     return False
  glob_offs = prel31_to_addr(eexidx.tboffs, memaddr_base+ent_pos)
  # Check if first word offset falls into ".text" section and can be a function start
  if (glob_offs <= memaddr_base) or (glob_offs >= memaddr_base+arr_pos) or ((glob_offs % func_align) != 0):
     return False
  #TODO we could also check if the handling function starts with STORE/STM instruction; it is very unlikely to start in different way
  # Second word can be one of 3 things: table entry offset, exception entry itself or EXIDX_CANTUNWIND
  # Check if second word contains EXIDX_CANTUNWIND value (0x01)
  if (eexidx.entry == 0x01):
     if (po.verbose > 2):
        print("{}: Matching '{:s}' entry at 0x{:08x}: 0x{:08x} 0x{:08x} [CANTUNWIND]".format(po.fwpartfile,sectname,ent_pos,glob_offs,eexidx.entry))
     return True
  # Check if second word contains exception handling entry itself
  if (eexidx.entry & 0x80000000):
     # According to specs, bits 30-28 should be zeros; personality routine and index are stored on lower bits
     if (eexidx.entry & 0x70000000):
        return False
     if (po.verbose > 2):
        print("{}: Matching '{:s}' entry at 0x{:08x}: 0x{:08x} 0x{:08x} [handling entry, idx 0x{:02x}]".format(po.fwpartfile,sectname,ent_pos,glob_offs,eexidx.entry,(eexidx.entry >> 24) & 7))
     return True
  # Check if second word contains table entry start offset
  # the offset is not to the .data segment, but to a separate .ARM.extab segment
  # Let's assume this segment is somewhere adjacent to our .ARM.exidx segment
  # Size of the table entry which is being pointed at is no less than 4 bytes
  tbent_offs = prel31_to_addr(eexidx.entry, memaddr_base+ent_pos)
  if ((tbent_offs >= memaddr_base+arr_pos-po.expect_sect_align*0x10) and (tbent_offs <= memaddr_base+arr_pos-4) or
      (tbent_offs < memaddr_base+ent_pos+po.expect_sect_align*0x20) and (tbent_offs >= memaddr_base+ent_pos+sizeof(eexidx))):
     # We can assume the table is aligned; we don't know the size of the entry, but it is multiplication of 4
     if ((tbent_offs % 4) != 0):
           return False
     # Try to read at that offset - it should start with function address (so-called personality routine)
     fwpartfile.seek(tbent_offs-memaddr_base, os.SEEK_SET)
     pers_routine_offs = c_uint(0)
     if fwpartfile.readinto(pers_routine_offs) != sizeof(pers_routine_offs):
        return False
     if (pers_routine_offs.value <= memaddr_base) or (pers_routine_offs.value >= memaddr_base+arr_pos) or ((pers_routine_offs.value % func_align) != 0):
        return False
     if (po.verbose > 2):
        print("{}: Matching '{:s}' entry at 0x{:08x}: 0x{:08x} 0x{:08x} [table entry offs 0x{:08x}]".format(po.fwpartfile,sectname,ent_pos,glob_offs,eexidx.entry,tbent_offs))
     return True
  return False

def armfw_detect_sect_ARMexidx(po, fwpartfile, memaddr_base, start_pos, func_align, sect_align):
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
  assert sect_align >= sizeof(ExIdxEntry)
  while (True):
     # Check how many correct exception entries we have
     entry_count = 0
     entry_pos = pos
     while (True):
        fwpartfile.seek(entry_pos, os.SEEK_SET)
        if fwpartfile.readinto(eexidx) != sizeof(eexidx):
           reached_eof = True
           break
        if not armfw_is_proper_ARMexidx_entry(po, fwpartfile, eexidx, memaddr_base, func_align, pos, entry_pos):
           break
        entry_count += 1
        entry_pos += sizeof(eexidx)
     # Do not allow entry at EOF
     if (reached_eof):
        break
     # verify if padding area is completely filled with 0x00
     if (entry_count > 0):
        if ((entry_pos % sect_align) > 0):
           fwpartfile.seek(entry_pos, os.SEEK_SET)
           padding = fwpartfile.read(sect_align - (entry_pos % sect_align))
           if (padding[0] != 0x00) or (len(set(padding)) > 1):
              entry_count = 0
     # If entry is ok, consider it a match
     if entry_count > 0:
        if (po.verbose > 1):
           print("{}: Matching '{:s}' section at 0x{:08x}: {:d} exception entries".format(po.fwpartfile,sectname,pos,entry_count))
        match_pos = pos
        match_entries = entry_count
        match_count += 1
     # Set position to search for next entry
     pos += sect_align
  if (match_count > 1):
     eprint("{}: Warning: multiple ({:d}) matches found for section '{:s}' with alignment 0x{:02x}".format(po.fwpartfile,match_count,sectname,sect_align))
  if (match_count < 1):
     return -1, 0
  return match_pos, match_entries * sizeof(ExIdxEntry)

def armfw_detect_empty_sect_ARMexidx(po, fwpartfile, memaddr_base, start_pos, func_align, sect_align):
  """ Finds position of empty .ARM.exidx section. This is a last resort solution, when the
      section appears not to exist. In that case, we will try to find a zero-filled block
      which ends at an aligned offset; it is likely that the place where .text ends and .data starts
      will look like this.
  """
  match_count = 0
  match_pos = -1
  pos = start_pos
  while (True):
     fwpartfile.seek(pos, os.SEEK_SET)
     buf = fwpartfile.read(sect_align)
     if len(buf) != sect_align:
        break
     buf_set = set(buf)
     if (0x00 in buf_set) and (len(buf_set) == 1):
        match_pos = pos + sect_align
        match_count += 1
     elif (match_count > 0):
        break
     # Set position to search for next entry
     pos += sect_align
  if (match_count < 1):
     return -1, 0
  return match_pos, 0

def armfw_bin2elf(po, fwpartfile):
  if (po.verbose > 0):
     print("{}: Memory base address set to 0x{:08x}".format(po.fwpartfile,po.address_base))
  # detect position of each section in the binary file
  if (po.verbose > 1):
     print("{}: Searching for sections".format(po.fwpartfile))
  # ARM exceprions index section is easy to find
  sectname = ".ARM.exidx"
  sect_align = po.expect_sect_align
  if (not sectname in po.section_pos):
     sect_pos, sect_len = armfw_detect_sect_ARMexidx(po, fwpartfile,  po.address_base, 0, po.expect_func_align, sect_align)
     if (sect_pos < 0):
        sect_align = (po.expect_sect_align >> 1)
        sect_pos, sect_len = armfw_detect_sect_ARMexidx(po, fwpartfile,  po.address_base, 0, po.expect_func_align, sect_align)
     if (sect_pos < 0):
        sect_align = po.expect_sect_align
        sect_pos, sect_len = armfw_detect_empty_sect_ARMexidx(po, fwpartfile,  po.address_base, 0, po.expect_func_align, sect_align)
     if (sect_pos < 0):
        raise EOFError("No matches found for section '{:s}' in binary file.".format(sectname))
     po.section_pos[sectname] = sect_pos
  else:
     sect_pos = po.section_pos[sectname]
     sect_len = po.expect_sect_align
  if (not sectname in po.section_size):
     po.section_size[sectname] = sect_len
  else:
     sect_len = po.section_size[sectname]
  if (po.verbose > 1):
     print("{}: Set '{:s}' section at file pos 0x{:08x}, size 0x{:08x}".format(po.fwpartfile,sectname,po.section_pos[sectname],po.section_size[sectname]))
  # Make sure we will not realign sections by mistake; we will update alignment in file later
  sect_align = 1
  # Now let's assume that the .ARM.exidx section is located after .text section. Also, the .text section
  # is first because it contains interrupt table located at offset 0
  sectname = ".text"
  if (not sectname in po.section_pos):
     if (sect_pos > po.expect_func_align * 8):
        po.section_pos[sectname] = 0x0
     else:
        raise EOFError("No place for '{:s}' section before the '{:s}' section in binary file.".format(sectname,".ARM.exidx"))
  if (not sectname in po.section_size):
     po.section_size[sectname] = sect_pos - po.section_pos[sectname]
  if (po.verbose > 1):
     print("{}: Set '{:s}' section at file pos 0x{:08x}, size 0x{:08x}".format(po.fwpartfile,sectname,po.section_pos[sectname],po.section_size[sectname]))
  # After the .ARM.exidx section come .data section.
  sectname = ".data"
  if (not sectname in po.section_pos):
     sect_pos += sect_len
     if (sect_pos % sect_align) != 0:
        sect_pos += sect_align - (sect_pos % sect_align)
     po.section_pos[sectname] = sect_pos
  else:
     sect_pos = po.section_pos[sectname]
  if (not sectname in po.section_size):
     fwpartfile.seek(0, os.SEEK_END)
     sect_len = fwpartfile.tell() - sect_pos
     po.section_size[sectname] = sect_len
  else:
     sect_len = po.section_size[sectname]
  if (po.verbose > 1):
     print("{}: Set '{:s}' section at file pos 0x{:08x}, size 0x{:08x}".format(po.fwpartfile,sectname,po.section_pos[sectname],po.section_size[sectname]))
  # Set position for bss section too - to the place
  # where it should be if it had the content stored
  sectname = ".bss"
  if (not sectname in po.section_pos):
     sect_pos += sect_len
     if (sect_pos % sect_align) != 0:
        sect_pos += sect_align - (sect_pos % sect_align)
     po.section_pos[sectname] = sect_pos
  else:
     sect_pos = po.section_pos[sectname]
  if (not sectname in po.section_size):
     sect_len = po.address_space_len - sect_pos
     if (sect_len < 0): sect_len = 0
     po.section_size[sectname] = sect_len
  else:
     sect_len = po.section_size[sectname]
  if (po.verbose > 1):
     print("{}: Set '{:s}' section at file pos 0x{:08x}, size 0x{:08x}".format(po.fwpartfile,sectname,po.section_pos[sectname],po.section_size[sectname]))

  # Prepare list of sections in the order of position
  sections_order = []
  for sortpos in sorted(set(po.section_pos.values())):
     # First add sections with size equal zero
     for sectname, pos in po.section_pos.items():
        if pos == sortpos:
           if sectname in po.section_size.keys():
              if (po.section_size[sectname] < 1):
                 sections_order.append(sectname)
     # The non-zero sized section should be last
     for sectname, pos in po.section_pos.items():
        if pos == sortpos:
           if sectname not in sections_order:
              sections_order.append(sectname)
  # Prepare list of section sizes
  sectpos_next = po.address_space_len # max size is larger than bin file size due to uninitialized sections (bss)
  for sectname in reversed(sections_order):
     sectpos_delta = sectpos_next - po.section_pos[sectname]
     if (sectpos_delta < 0): sectpos_delta = 0xffffffff - po.section_pos[sectname]
     if sectname in po.section_size.keys():
        if (po.section_size[sectname] > sectpos_delta):
           eprint("{}: Warning: section '{:s}' size reduced due to overlapping".format(po.fwpartfile,sectname))
           po.section_size[sectname] = sectpos_next - po.section_pos[sectname]
     else:
        po.section_size[sectname] = sectpos_delta
     sectpos_next = po.section_pos[sectname]

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

  # Prepare array of addresses
  sections_address = {}
  sections_align = {}
  for sectname in sections_order:
     # add section address to array; since BIN is a linear mem dump, addresses are the same as file offsets
     sections_address[sectname] = po.address_base + po.section_pos[sectname]
     sect_align = (po.expect_sect_align << 1)
     while (sections_address[sectname] % sect_align) != 0: sect_align = (sect_align >> 1)
     sections_align[sectname] = sect_align
     if (po.verbose > 0):
        print("{}: Section '{:s}' memory address set to 0x{:08x}, alignment 0x{:02x}".format(po.fwpartfile,sectname,sections_address[sectname],sect_align))
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
     sect.header['sh_addralign'] = sections_align[sectname]
     # for non-bss sections, size will be updated automatically when replacing data
     if section_is_bss(sectname):
        sect.header['sh_size'] = po.section_size[sectname]
     elif po.section_size[sectname] <= 0:
        sect.set_data(b'')
     else:
        fwpartfile.seek(po.section_pos[sectname], os.SEEK_SET)
        data_buf = fwpartfile.read(po.section_size[sectname])
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
  """ Main executable function.

      Its task is to parse command line options and call a function which performs selected command.
  """
  po = ProgOptions()
  # Parse command line options
  try:
     opts, args = getopt.getopt(argv,"hevt:p:l:b:s:o:",["help","version","mkelf","dry-run","fwpart=","template","addrsplen=","baseaddr=","section=","output="])
  except getopt.GetoptError:
     print("Unrecognized options; check arm_bin2elf.py --help")
     sys.exit(2)
  for opt, arg in opts:
     if opt in ("-h", "--help"):
        print("Binary firmware with ARM code to ELF converter")
        print("arm_bin2elf.py <-e> [-v] -p <fwmdfile> [-o <elffile>] [-t <tmpltfile>]")
        print("  -p <fwpartfile> - name of the firmware binary file")
        print("  -o <elffile> - output file name")
        print("  -t <tmpltfile> - template file name")
        print("  -e - make ELF file from a binary image")
        print("  -l <spacelen> - set address space length; influences size of last section")
        print("  -b <baseaddr> - set base address; first section will start at this memory location")
        print("  -v - increases verbosity level; max level is set by -vvv")
        sys.exit()
     elif opt == "--version":
        print("arm_bin2elf.py version 0.2.0")
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
