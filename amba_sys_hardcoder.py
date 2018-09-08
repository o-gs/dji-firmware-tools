#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Ambarella Firmware SYS partiton hard-coded values editor.
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
__version__ = "0.0.1"
__author__ = "Mefistotelis @ Original Gangsters"
__license__ = "GPL"

import sys
import argparse
import os
import re
import collections.abc
import itertools
import enum

from capstone import *
from keystone import *
sys.path.insert(0, '../pyelftools')
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SH_FLAGS

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

class VarType(enum.Enum):
    # Variable contains directly entered integer value
    DIRECT_INT_VALUE = enum.auto()
    # Variable contains absolute address to a code chunk or function
    ABSOLUTE_ADDR_TO_CODE = enum.auto()
    # Variable contains absolute address to a global variable
    ABSOLUTE_ADDR_TO_GLOBAL_DATA = enum.auto()
    # Variable contains address to a code chunk relative to current value of PC register
    RELATIVE_PC_ADDR_TO_CODE = enum.auto()
    # Variable contains address to a global variable relative to current value of PC register
    RELATIVE_PC_ADDR_TO_GLOBAL_DATA = enum.auto()

class DataVariety(enum.Enum):
    UNKNOWN = enum.auto()
    CHAR = enum.auto()
    UINT8_T = enum.auto()
    UINT16_T = enum.auto()
    UINT32_T = enum.auto()
    UINT64_T = enum.auto()
    INT8_T = enum.auto()
    INT16_T = enum.auto()
    INT32_T = enum.auto()
    INT64_T = enum.auto()
    FLOAT = enum.auto()
    DOUBLE = enum.auto()
    STRUCT = enum.auto()

class CodeVariety(enum.Enum):
    # Just a chunk of code, not a function start
    CHUNK = enum.auto()
    # The pointed place is a function start
    FUNCTION = enum.auto()

# List of architectures
# based on ropstone by blasty
elf_archs = [
    {
        'name'     : "arm",
        'cs_const' : CS_ARCH_ARM,
        'ks_const' : KS_ARCH_ARM,
        'boundary' : 4,
        'modes'    : [
            {
                'name'     : "thumb",
                'desc'     : "THUMB processor mode",
                'cs_const' : CS_MODE_THUMB,
                'ks_const' : KS_MODE_THUMB,
                # this overrides the boundary of the parent architecture
                'boundary' : 2,
                # this adds a shift offset to the output addr to force THUMB mode
                'retshift' : 1,
            },
            {
                'name'     : "le",
                'desc'     : "Little endian",
                'cs_const' : CS_MODE_LITTLE_ENDIAN,
                'ks_const' : KS_MODE_LITTLE_ENDIAN,
            },
            {
                'name'     : "be",
                'desc'     : "Big endian",
                'cs_const' : CS_MODE_BIG_ENDIAN,
                'ks_const' : KS_MODE_BIG_ENDIAN,
            },
        ]
    },
    {
        'name'     : "arm64",
        'cs_const' : CS_ARCH_ARM64,
        'ks_const' : KS_ARCH_ARM64,
        'boundary' : 4,
        'modes'    : [
            {
                'name'     : "le",
                'desc'     : "Little Endian",
                'cs_const' : CS_MODE_LITTLE_ENDIAN,
                'ks_const' : KS_MODE_LITTLE_ENDIAN,
            },
        ]
    },
    {
        'name'     : "mips",
        'cs_const' : CS_ARCH_MIPS,
        'ks_const' : KS_ARCH_MIPS,
        'boundary' : 4,
        'modes'    : [
            {
                'name'     : "32b",
                'desc'     : "MIPS32",
                'cs_const' : CS_MODE_MIPS32,
                'ks_const' : KS_MODE_MIPS32,
            },
            {
                'name'     : "64b",
                'desc'     : "MIPS64",
                'cs_const' : CS_MODE_MIPS64,
                'ks_const' : KS_MODE_MIPS64,
            },
            {
                'name'     : "le",
                'desc'     : "Little endian",
                'cs_const' : CS_MODE_LITTLE_ENDIAN,
                'ks_const' : KS_MODE_LITTLE_ENDIAN,
            },
            {
                'name'     : "be",
                'desc'     : "Big endian",
                'cs_const' : CS_MODE_BIG_ENDIAN,
                'ks_const' : KS_MODE_BIG_ENDIAN,
            },
        ]
    },
    {
        'name'     : "x86",
        'cs_const' : CS_ARCH_X86,
        'ks_const' : KS_ARCH_X86,
        'boundary' : 1,
        'modes'    : [
            {
                'name'     : "32b",
                'desc'     : "x86 32bit",
                'cs_const' : CS_MODE_32,
                'ks_const' : KS_MODE_32,
            },
            {
                'name'     : "64b",
                'desc'     : "x86_64 64bit",
                'cs_const' : CS_MODE_64,
                'ks_const' : KS_MODE_64,
            },
        ]
    }
]

# Function with address to _msg_author_level
re_func_DjiMsgAuthorLevelGet = {
'name': "DjiMsgAuthorLevelGet",
're': """
  ldr	r0, \[pc, #(?P<msg_author_level>[0-9a-fx]+)\]
  ldr	r0, \[r0\]
  bx	lr
""",
'vars': {
  'msg_author_level': {'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UINT32_T},
},
}

re_func_DjiMsgSettingsInit = {
'name': "DjiMsgSettingsInit",
're': """
  push	{r4, r5, lr}
  sub	sp, sp, #0x14
  mov	r4, #0
  mov	r1, #0
  strb	r1, \[sp, #0x11\]
  mov	r1, #0
  strb	r1, \[sp, #0x10\]
  mov	r5, #0
  ldr	r0, \[pc, #(?P<dji_msg_mutex>[0-9a-fx]+)\]
  bl	#(?P<AmbaKAL_MutexCreate>[0-9a-fx]+)
  movs	r4, r0
  cmp	r4, #0
  beq	#(?P<loc_label02>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<printk_log_level>[0-9a-fx]+)\]
  ldr	r0, \[r0\]
  cmp	r0, #0
  bmi	#(?P<loc_label03>[0-9a-fx]+)
  mov	r5, #0
  mov	r0, #1
  movs	r5, r0
  bl	#(?P<AmbaPrintk_Disabled>[0-9a-fx]+)
  cmp	r0, #1
  beq	#(?P<loc_label03>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<cstr_func_name>[0-9a-fx]+)\]
  str	r0, \[sp, #0xc\]
  ldr	r0, \[pc, #(?P<cstr_fmt_text1>[0-9a-fx]+)\]
  str	r0, \[sp, #8\]
  str	r5, \[sp, #4\]
  mov	r0, #0
  str	r0, \[sp\]
  mov	r3, #0
  mov	r2, #1
  mov	r1, #1
  mov	r0, #1
  bl	#(?P<AmbaPrintk>[0-9a-fx]+)
  movs	r0, r4
  b	#(?P<loc_label06>[0-9a-fx]+)
  mov	r0, #0
  bl	#(?P<DjiMsgAuthorLevelSet>[0-9a-fx]+)
  movs	r4, r0
  add	r1, sp, #0x10
  add	r0, sp, #0x11
  bl	#(?P<DjiEncryptGetA9Status>[0-9a-fx]+)
  cmp	r0, #0
  beq	#(?P<loc_label09>[0-9a-fx]+)
  mov	r0, #(?P<encrypt_query_fail_authority_level>[0-9a-fx]+)
  bl	#(?P<DjiMsgAuthorLevelSet>[0-9a-fx]+)
  ldrb	r0, \[sp, #0x11\]
  cmp	r0, #1
  bne	#(?P<loc_label10>[0-9a-fx]+)
  ldrb	r0, \[sp, #0x10\]
  cmp	r0, #1
  bne	#(?P<loc_label10>[0-9a-fx]+)
  mov	r0, #(?P<verify_state_good_authority_level>[0-9a-fx]+)
  bl	#(?P<DjiMsgAuthorLevelSet>[0-9a-fx]+)
  b	#(?P<loc_label11>[0-9a-fx]+)
  mov	r0, #(?P<verify_state_bad_authority_level>[0-9a-fx]+)
  bl	#(?P<DjiMsgAuthorLevelSet>[0-9a-fx]+)
  mov	r5, #0
  b	#(?P<loc_label12>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<unk_var01>[0-9a-fx]+)\]
  lsls	r1, r5, #2
  ldr	r2, \[pc, #(?P<unk_var02>[0-9a-fx]+)\]
  adds	r1, r1, r2
  mov	r2, #1
  str	r2, \[r0, r1\]
  adds	r5, r5, #1
  cmp	r5, #4
  blo	#(?P<loc_label13>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<unk_var03>[0-9a-fx]+)\]
  mov	r1, #0
  str	r1, \[r0\]
  ldr	r0, \[pc, #(?P<unk_var04>[0-9a-fx]+)\]
  mov	r1, #1
  str	r1, \[r0\]
  ldr	r0, \[pc, #(?P<msg_adjust_task_finished>[0-9a-fx]+)\]
  mov	r1, #0
  str	r1, \[r0\]
  ldr	r0, \[pc, #(?P<unk_var05>[0-9a-fx]+)\]
  mov	r1, #0
  str	r1, \[r0\]
  mov	r2, #0x90
  mov	r1, #0
  ldr	r0, \[pc, #(?P<unk_var06>[0-9a-fx]+)\]
  bl	#(?P<memset_0>[0-9a-fx]+)
  mov	r2, #0x38
  mov	r1, #0
  ldr	r0, \[pc, #(?P<unk_var07>[0-9a-fx]+)\]
  bl	#(?P<memset_0>[0-9a-fx]+)
  mov	r2, #0xc
  mov	r1, #0
  ldr	r0, \[pc, #(?P<unk_var08>[0-9a-fx]+)\]
  bl	#(?P<memset_0>[0-9a-fx]+)
  mov	r2, #8
  mov	r1, #0
  ldr	r0, \[pc, #(?P<unk_var09>[0-9a-fx]+)\]
  bl	#(?P<memset_0>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<dji_msg_mutex>[0-9a-fx]+)\]
  ldr	r1, \[pc, #(?P<unk_var10>[0-9a-fx]+)\]
  str	r1, \[r0, #(?P<unk_offs01>[0-9a-fx]+)\]
  movw	r2, #0x1010
  mov	r1, #0
  ldr	r0, \[pc, #(?P<unk_var11>[0-9a-fx]+)\]
  bl	#(?P<memset_0>[0-9a-fx]+)
  mov	r2, #8
  mov	r1, #0
  ldr	r0, \[pc, #(?P<unk_var12>[0-9a-fx]+)\]
  bl	#(?P<memset_0>[0-9a-fx]+)
  mov	r2, #0xc
  mov	r1, #0
  ldr	r0, \[pc, #(?P<unk_var13>[0-9a-fx]+)\]
  bl	#(?P<memset_0>[0-9a-fx]+)
  mov	r2, #8
  mov	r1, #0
  ldr	r0, \[pc, #(?P<unk_var14>[0-9a-fx]+)\]
  bl	#(?P<memset_0>[0-9a-fx]+)
  mov	r2, #0x16
  mov	r1, #0
  ldr	r0, \[pc, #(?P<unk_var15>[0-9a-fx]+)\]
  bl	#(?P<memset_0>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<unk_var16>[0-9a-fx]+)\]
  mov	r1, #0
  strb	r1, \[r0\]
  mov	r2, #0x36
  mov	r1, #0
  ldr	r0, \[pc, #(?P<unk_var17>[0-9a-fx]+)\]
  bl	#(?P<memset_0>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<unk_var18>[0-9a-fx]+)\]
  mov	r1, #1
  str	r1, \[r0\]
  mov	r2, #0xc
  mov	r1, #0
  ldr	r0, \[pc, #(?P<unk_var19>[0-9a-fx]+)\]
  bl	#(?P<memset_0>[0-9a-fx]+)
  mov	r2, #4
  mov	r1, #0
  ldr	r0, \[pc, #(?P<unk_var20>[0-9a-fx]+)\]
  bl	#(?P<memset_0>[0-9a-fx]+)
  mov	r0, #0
  add	sp, sp, #0x14
  pop	{r4, r5, pc}
""",
'vars': {
  'AmbaKAL_MutexCreate':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'AmbaPrintk_Disabled':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'AmbaPrintk':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'DjiMsgAuthorLevelSet':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'DjiEncryptGetA9Status':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'memset_0':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'cstr_fmt_text1':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_func_name':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'dji_msg_mutex':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.STRUCT},
  'msg_adjust_task_finished':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UINT32_T},
  'printk_log_level':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UINT32_T},
  'encrypt_query_fail_authority_level':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T, 'public': "og_hardcoded.p3x_ambarella"},
  'verify_state_good_authority_level':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T, 'public': "og_hardcoded.p3x_ambarella"},
  'verify_state_bad_authority_level':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T, 'public': "og_hardcoded.p3x_ambarella"},
  'loc_label02':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label03':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label06':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label09':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label10':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label11':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label12':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label13':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'unk_offs01':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T},
  'unk_var01':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var02':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var03':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var04':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var05':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var06':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var07':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var08':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var09':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var10':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var11':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var12':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var13':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var14':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var15':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var16':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var17':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var18':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var19':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_var20':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
},
}

re_general_list = [
  {'sect': ".text", 'func': re_func_DjiMsgSettingsInit,},
]

def get_asm_arch_by_name(arname):
    for arch in elf_archs:
        if arch['name'] == arname:
            return arch
    return None


def get_asm_mode_by_name(arch, mdname):
    for mode in arch['modes']:
        if mode['name'] == mdname:
            return mode
    return None


def elf_march_to_asm_config(elf):
    """ Retrieves machine architecture for given elf.

    Returns config for capstone and keystone.
    """
    march = elf.get_machine_arch()
    asm_arch = None
    asm_mode = None
    if march == "x64":
        asm_arch = get_asm_arch_by_name("x86")
        asm_mode = get_asm_mode_by_name(asm_arch, "64b")
    elif march == "x86":
        asm_arch = get_asm_arch_by_name("x86")
        asm_mode = get_asm_mode_by_name(asm_arch, "32b")
    elif march == "ARM":
        asm_arch = get_asm_arch_by_name("arm")
        if elf.little_endian:
            asm_mode = get_asm_mode_by_name(asm_arch, "le")
        else:
            asm_mode = get_asm_mode_by_name(asm_arch, "be")
    elif march == "MIPS":
        asm_arch = get_asm_arch_by_name("mips")
        asm_mode = get_asm_mode_by_name(asm_arch, "32b")
        if elf.little_endian:
            asm_mode = get_asm_mode_by_name(asm_arch, "le")
        else:
            asm_mode = get_asm_mode_by_name(asm_arch, "be")
    return (asm_arch, [asm_mode])


def get_arm_vma_relative_to_pc_register(asm_arch, section, address, size, offset_str):
    """ Gets Virtual Memory Address associated with offet given within an asm instruction.

    ARMs have a way of storing relative offsets which may be confusing at first.
    """
    vma = address + size + int(offset_str, 0)
    return vma - (vma % asm_arch['boundary'])


def armfw_elf_ambavals_objdump(po, elffh):
    """ Dump executable in similar manner to objdump disassemble function.
    """
    elf = ELFFile(elffh)

    asm_arch, asm_modes = elf_march_to_asm_config(elf)
    if len(asm_modes) < 1 or not isinstance(asm_modes[0], collections.abc.Mapping):
        raise ValueError("ELF has unsupported machine type ({:s}).".format(elf['e_machine']))

    cs_mode = 0
    retshift = 0
    for mode in asm_modes:
        cs_mode = cs_mode | mode['cs_const']
        # check for mode specific overrides (only needed for THUMB atm)
        if 'boundary' in mode:
            asm_arch['boundary'] = mode['boundary']
        if 'retshift' in mode:
            retshift = mode['retshift']

    cs = Cs(asm_arch['cs_const'], cs_mode)

    # Get sections dictionary, so that we can easily access them by name
    elf_sections = {}
    for i in range(elf.num_sections()):
        esection = elf.get_section(i)

        if esection['sh_type'] != "SHT_PROGBITS":
            continue

        if not (esection['sh_flags'] & SH_FLAGS.SHF_ALLOC):
            continue

        if (po.verbose > 2):
            print("{:s}: Found section {:s}".format(po.elffile,esection.name))

        section = {
              'name' : esection.name,
              'addr' : esection['sh_addr'],
              'data' : esection.data(),
        }

        if (esection['sh_flags'] & SH_FLAGS.SHF_EXECINSTR):
            sect_offs = 0
            while sect_offs < len(section['data']):
                for (address, size, mnemonic, op_str) in cs.disasm_lite(section['data'][sect_offs:], section['addr']+sect_offs):
                    print("0x{:x}:\t{:s}\t{:s}".format(address, mnemonic, op_str))
                    sect_offs += size
                size = len(section['data']) - sect_offs
                if size > asm_arch['boundary']:
                    size = asm_arch['boundary']
                address = section['addr']+sect_offs
                if size > 0:
                    print("0x{:x}:\tdb ".format(address), end='')
                    for bt in section['data'][sect_offs:sect_offs+size]:
                        print("{:02x} ".format(bt), end='')
                    print("")
                sect_offs += size
        else:
            sect_offs = 0
            while sect_offs < len(section['data']):
                size = len(section['data']) - sect_offs
                if size > 4:
                    size = 4
                address = section['addr']+sect_offs
                if size > 0:
                    print("0x{:x}:\tdb ".format(address), end='')
                    for bt in section['data'][sect_offs:sect_offs+size]:
                        print("{:02x} ".format(bt), end='')
                    print("")
                sect_offs += size

def armfw_elf_section_search_init(asm_arch, section, patterns):
    """ Initialize search data.
    """
    search = {}
    search['asm_arch'] = asm_arch
    search['section'] = section
    search['name'] = patterns['name']
    re_lines = patterns['re'].split(sep="\n")
    re_lines = list(map(str.strip, re_lines))
    search['re'] = list(filter(None, re_lines))
    search['var_defs'] = patterns['vars']
    search['var_vals'] = {}
    search['match_address'] = 0
    search['first_line_size'] = 0
    search['match_lines'] = 0
    search['best_match_address'] = 0
    search['best_match_lines'] = 0
    search['full_matches'] = []
    return search

def armfw_elf_section_search_reset(search):
    """ Reset search data after matching failed.
    """
    if search['best_match_lines'] < search['match_lines']:
        search['best_match_address'] = search['match_address']
        search['best_match_lines'] = search['match_lines']
    search['var_vals'] = {}
    search['match_address'] = 0
    search['first_line_size'] = 0
    search['match_lines'] = 0
    return search


def armfw_elf_section_search_progress(search, match_address, match_line_size):
    """ Update search data after matching next line suceeded.
    """
    search['match_lines'] += 1
    if search['match_lines'] == 1:
        search['match_address'] = match_address
        search['first_line_size'] = match_line_size
    if search['match_lines'] == len(search['re']):
        search['full_matches'].append({'address': search['match_address'], 'vars': search['var_vals']})
        search['match_lines'] = 0
    return search

def armfw_elf_section_search_get_pattern(search):
    """ Get regex pattern to match with next line.
    """
    re_patterns = search['re']
    match_lines = search['match_lines']
    return re_patterns[match_lines]

def armfw_elf_section_search_get_next_search_pos(search, sect_offs):
    """ Get position to start a next search before resetting current one.
    """
    # We intentionally zero first_line_size only on reset, so that it could be used here even after full msatch
    asm_arch = search['asm_arch']
    if search['first_line_size'] > 0:
        return search['match_address'] - search['section']['addr'] + search['first_line_size']
    else:
        new_offs = sect_offs + asm_arch['boundary']
        return new_offs - (new_offs % asm_arch['boundary'])


def armfw_elf_section_search_process_vars_from_code(search, elf_sections, address, size, re_code):
    """ Process variable values from a code line and add them to search results.
    """
    for var_name, var_val in re_code.groupdict().items():
        var_info = search['var_defs'][var_name]
        # Get direct int value or offset
        if (var_info['type'] == VarType.DIRECT_INT_VALUE):
            prop_val = int(var_val, 0)
        elif (var_info['type'] == VarType.ABSOLUTE_ADDR_TO_CODE):
            prop_val = int(var_val, 0)
        elif (var_info['type'] == VarType.ABSOLUTE_ADDR_TO_GLOBAL_DATA):
            prop_val = int(var_val, 0)
        elif (var_info['type'] == VarType.RELATIVE_PC_ADDR_TO_CODE):
            prop_val = get_arm_vma_relative_to_pc_register(search['asm_arch'], search['section'], address, size, var_val)
        elif (var_info['type'] == VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA):
            prop_val = get_arm_vma_relative_to_pc_register(search['asm_arch'], search['section'], address, size, var_val)
        else:
            raise NotImplementedError('Unexpected variable type found.')

        # Get expected length of the value
        if var_info['variety'] in [DataVariety.CHAR, DataVariety.UINT8_T, DataVariety.INT8_T]:
            prop_size = 1
        elif var_info['variety'] in [DataVariety.UINT16_T, DataVariety.INT16_T]:
            prop_size = 2
        elif var_info['variety'] in [DataVariety.UINT32_T, DataVariety.INT32_T, DataVariety.FLOAT]:
            prop_size = 4
        elif var_info['variety'] in [DataVariety.UINT64_T, DataVariety.INT64_T, DataVariety.DOUBLE]:
            prop_size = 8
        else:
            prop_size = 0

        if 'array' in var_info:
            if isinstance(var_info['array'], int):
                prop_count = var_info['array']
            else:
                # We have variable size array; just use static limit
                prop_count = 2048
        else:
            prop_count = 1

        # Either convert the direct value to bytes, or get bytes from offset
        if (var_info['type'] == VarType.DIRECT_INT_VALUE):
            prop_bytes = (prop_val).to_bytes(prop_size*prop_count, byteorder=search['asm_arch']['byteorder'])
        elif (var_info['type'] == VarType.ABSOLUTE_ADDR_TO_GLOBAL_DATA) or (var_info['type'] == VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA):
            prop_bytes = b"" #TODO
        else:
            prop_bytes = b""

        if var_info['variety'] in [DataVariety.CHAR]:
            if 'array' in var_info:
                prop_str = prop_bytes.rstrip(b"\0").decode("utf-8")
            else:
                prop_str = chr(prop_val)
        elif var_info['variety'] in [DataVariety.UINT8_T, DataVariety.UINT16_T, DataVariety.UINT32_T, DataVariety.UINT64_T]:
            prop_str = ""
            for i in range(len(prop_bytes) // prop_size):
                prop_str += "0x{:x} ".format(int.from_bytes(prop_bytes[i*prop_size:(i+1)*prop_size], byteorder=search['asm_arch']['byteorder'], signed=False))
            prop_str = prop_str.rstrip()
        elif var_info['variety'] in [DataVariety.INT8_T, DataVariety.INT16_T, DataVariety.INT32_T, DataVariety.INT64_T]:
            prop_str = ""
            for i in range(len(prop_bytes) // prop_size):
                prop_str += "{:d} ".format(int.from_bytes(prop_bytes[i*prop_size:(i+1)*prop_size], byteorder=search['asm_arch']['byteorder'], signed=True))
            prop_str = prop_str.rstrip()
        elif var_info['variety'] in [DataVariety.FLOAT, DataVariety.DOUBLE]:
            prop_str = ""
            for i in range(len(prop_bytes) // prop_size):
                if prop_size >= 8:
                    prop_str += "{:d} ".format(struct.unpack("<f",prop_bytes[i*prop_size:(i+1)*prop_size]))
                else:
                    prop_str += "{:f} ".format(struct.unpack("<f",prop_bytes[i*prop_size:(i+1)*prop_size]))
            prop_str = prop_str.rstrip()
        else:
            prop_str = ""

        if var_name in search['var_vals']:
            var_val = search['var_vals'][var_name]
            if var_val['value'] != prop_val:
                return False
        else:
            var_def = search['var_defs'][var_name]
            search['var_vals'][var_name] = {'str_value': prop_str, 'value': prop_val, 'address': address, 'instr_size': size, 're_line': search['match_lines']}
            search['var_vals'][var_name].update(var_def)
    return True


def armfw_elf_section_search_block(search, sect_offs, elf_sections, cs, block_len):
    """ Search for pattern in a block of ELF file section.
        The function will try to save state and stop somewhere around given block_len.
    """
    sect_limit = len(search['section']['data'])
    if (sect_limit > sect_offs + block_len):
        sect_limit = sect_offs + block_len
    re_dataline = "d([bwdq])\t(.*)"
    while sect_offs < sect_limit:
        curr_pattern = armfw_elf_section_search_get_pattern(search)
        re_isdata = re.search(re_dataline, curr_pattern)
        if re_isdata is not None:
            # now matching a data line; get its length
            raise NotImplementedError('TODO data')
        else:
            # now matching an assembly code line
            for (address, size, mnemonic, op_str) in cs.disasm_lite(search['section']['data'][sect_offs:], search['section']['addr'] + sect_offs):
                instruction_str = "{:s}\t{:s}".format(mnemonic, op_str).strip()
                re_code = re.search(curr_pattern, instruction_str)
                # If matching failed after exactly one line, get back to checking first line without resetting offset
                # This is a major perforance optimization
                if re_code is None and search['match_lines'] == 1:
                    search = armfw_elf_section_search_reset(search)
                    curr_pattern = armfw_elf_section_search_get_pattern(search)
                    re_code = re.search(curr_pattern, instruction_str)

                match_ok = (re_code is not None)
                if match_ok:
                    match_ok = armfw_elf_section_search_process_vars_from_code(search, elf_sections, address, size, re_code)

                if match_ok:
                    #print("a {:d} @ {:x}".format(search['match_lines'],address))
                    search = armfw_elf_section_search_progress(search, address, size)
                    if search['match_lines'] == 0: # This means we had a full match; we need to go back with offset to search for overlapping areas
                        sect_offs = armfw_elf_section_search_get_next_search_pos(search, sect_offs)
                        break
                    curr_pattern = armfw_elf_section_search_get_pattern(search)
                    sect_offs += size
                else:
                    # Breaking the loop is expensive; do it only if we had more than one line matched, to search for overlapping areas
                    if search['match_lines'] > 0: # this really means > 1 because the value of 1 (fast reset) was handled before
                        sect_offs = armfw_elf_section_search_get_next_search_pos(search, sect_offs)
                        search = armfw_elf_section_search_reset(search)
                        break
                    else: # search['match_lines'] == 0
                        sect_offs += size
            else: # for loop finished by inability to decode next instruction
                # Currently end of code means end of matching - data search is todo
                sect_offs = armfw_elf_section_search_get_next_search_pos(search, sect_offs)
                search = armfw_elf_section_search_reset(search)
    return (search, sect_offs)


def armfw_elf_whole_section_search(po, asm_arch, elf_sections, cs, sect_name, patterns):
    """ Search for pattern in ELF file section.
        Return list of matching data.
    """
    search = armfw_elf_section_search_init(asm_arch, elf_sections[sect_name], patterns)
    sect_offs = 0
    sect_progress_treshold = 0
    while sect_offs < len(search['section']['data']):
        search, sect_offs = armfw_elf_section_search_block(search, sect_offs, elf_sections, cs, 65536)
        # Print progress info
        if (po.verbose > 2) and (sect_offs > sect_progress_treshold):
            print("{:s}: Searching for {:s}, progress {:3d}%".format(po.elffile, search['name'], sect_offs * 100 // len(search['section']['data'])))
            sect_progress_treshold += len(search['section']['data']) / 10

    if (po.verbose > 1):
        if len(search['full_matches']) == 1:
            print("{:s}: Pattern of {:s} located at 0x{:x}".format(po.elffile, search['name'], search['full_matches'][0]['address']))
        elif len(search['full_matches']) > 1:
            print("{:s}: Pattern of {:s} found {:d} times".format(po.elffile, search['name'], len(search['full_matches'])))
        else:
            print("{:s}: Pattern of {:s} was not found; closest was {:d} lines at 0x{:x}".format(po.elffile, search['name'], search['best_match_lines'], search['best_match_address']))

    return search['full_matches']


def armfw_elf_match_to_public_values(po, match):
    params_list = {}
    for var_name, var_info in match['vars'].items():
        if 'public' in var_info:
            par_name = var_info['public']+"."+var_name
            params_list[par_name] = var_info.copy()
    return params_list


def armfw_elf_ambavals_list(po, elffh):

    elf = ELFFile(elffh)

    asm_arch, asm_modes = elf_march_to_asm_config(elf)
    if len(asm_modes) < 1 or not isinstance(asm_modes[0], collections.abc.Mapping):
        raise ValueError("ELF has unsupported machine type ({:s}).".format(elf['e_machine']))

    cs_mode = 0
    retshift = 0
    for mode in asm_modes:
        cs_mode = cs_mode | mode['cs_const']
        # check for mode specific overrides (only needed for THUMB atm)
        if 'boundary' in mode:
            asm_arch['boundary'] = mode['boundary']
        if 'retshift' in mode:
            retshift = mode['retshift']
    asm_arch['byteorder']='big' #TODO get byte order based on real params

    cs = Cs(asm_arch['cs_const'], cs_mode)

    # Get sections dictionary, so that we can easily access them by name
    elf_sections = {}
    for i in range(elf.num_sections()):
        section = elf.get_section(i)

        if section['sh_type'] != "SHT_PROGBITS":
            continue

        if (po.verbose > 2):
            print("{:s}: Found section {:s} at 0x{:06x}".format(po.elffile,section.name,section['sh_addr']))

        elf_sections[section.name] = {
              'name' : section.name,
              'addr' : section['sh_addr'],
              'data' : section.data(),
        }

    # Check if expected sections are there
    for sect_name in ('.text', '.data'):
        if not sect_name in elf_sections:
            raise ValueError("ELF does not contain expected section '{:s}'.".format(sect_name))

    # prepare list of parameter values
    params_list = {}
    for re_item in re_general_list:
        matches = armfw_elf_whole_section_search(po, asm_arch, elf_sections, cs, re_item['sect'], re_item['func'])
        if len(matches) == 1:
            params_list.update(armfw_elf_match_to_public_values(po, matches[0]))

    # print list of parameter values
    for par_name, par_info in params_list.items():
        print("{:s}\t{:s}".format(par_name,par_info['str_value']))

def main():
    """ Main executable function.

    Its task is to parse command line options and call a function which performs requested command.
    """

    parser = argparse.ArgumentParser(description=__doc__.split('.')[0])

    parser.add_argument("-e", "--elffile", type=str, required=True,
          help="Input ELF firmware file name")

    parser.add_argument("-o", "--valfile", type=str,
          help="Values list JSON file name")

    parser.add_argument("--dry-run", action="store_true",
          help="Do not write any files or do permanent changes")

    parser.add_argument("-v", "--verbose", action="count", default=0,
          help="Increases verbosity level; max level is set by -vvv")

    subparser = parser.add_mutually_exclusive_group(required=True)

    subparser.add_argument("-l", "--list", action="store_true",
          help="list values stored in the firmware")

    subparser.add_argument("-x", "--extract", action="store_true",
          help="Extract values to infos json text file")

    subparser.add_argument("-u", "--update", action="store_true",
          help="Update values in binary fw from infos text file")

    subparser.add_argument("-d", "--objdump", action="store_true",
          help="display asm like slightly primitive objdump")

    subparser.add_argument("--version", action='version', version="%(prog)s {version} by {author}"
            .format(version=__version__,author=__author__),
          help="Display version information and exit")

    po = parser.parse_args()

    po.basename = os.path.splitext(os.path.basename(po.elffile))[0]

    if len(po.elffile) > 0 and (po.valfile is None or len(po.valfile) == 0):
        po.valfile = po.basename + ".json"

    if po.objdump:

        if (po.verbose > 0):
            print("{}: Opening for objdump".format(po.elffile))

        elffh = open(po.elffile, "rb")

        armfw_elf_ambavals_objdump(po, elffh)

        elffh.close();

    elif po.list:

        if (po.verbose > 0):
            print("{}: Opening for list".format(po.elffile))

        elffh = open(po.elffile, "rb")

        armfw_elf_ambavals_list(po, elffh)

        elffh.close();

    else:

        raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
    main()
