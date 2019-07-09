#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Ambarella Firmware SYS partiton hard-coded values editor.

The tool can parse Ambarella firmware SYS partition converted to ELF.
It finds certain hard-coded values in the binary data, and allows
exporting or importing them.

Only 'setValue' element in the exported file is really changeable,
all the other data is just informational. This includes `maxValue` and
`minValue` - they don't do anything and changing them in the JSON file
will not influence update operation.

Exported values:

og_hardcoded.p3x_ambarella.*_authority_level -

  Authority Level controls whether the module should respond to external
  commands. Normally it is set to `1`, but if encryption keys verification
  failed at startup, it is set to `0`. These parameters allow to change the
  value, so that the camera continues to operate normally even if keys are
  different or SHA204 chip is missing. There is no reason to keep the values
  unchanged even if encryption pairing currently works fine - the changes might
  become helpful in case of hardware malfunction in that area.

  Here's an example AmbaShell log when there's an issue with encryption which
  results in lowest Authority Level:
  ```
  [DJI_ENCRYPT] [DjiEncryptCheckA9]check a9 mac failed
  [DJI_ENCRYPT] [DjiEncryptReGetA9Status]a9's encrypt status[1] verify state[0]
  ```

og_hardcoded.p3x_ambarella.vid_setting_bitrates_* -

  These are bitrates used when encoding videos to SD-card. There are 27 sets,
  and which one is used depends on options selected in mobile app and on
  model of the drone. Specifics are not known at this point.

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
__version__ = "0.0.3"
__author__ = "Mefistotelis @ Original Gangsters"
__license__ = "GPL"

import sys
import argparse
import os
import re
import io
import collections
import itertools
import struct
import enum
import json

from ctypes import *
from capstone import *
from keystone import *
from keystone.keystone_const import *

sys.path.insert(0, '../pyelftools')
try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.constants import SH_FLAGS
    if not callable(getattr(ELFFile, "write_changes", None)):
        raise ImportError("The pyelftools library provided has no write support")
except ImportError:
    print("Warning:")
    print("This tool requires version of pyelftools with ELF write support.")
    print("Try `arm_bin2elf.py` for details.")
    raise


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

class VarType(enum.Enum):
    # Variable points to code line from asm regular expression
    DIRECT_LINE_OF_CODE = enum.auto()
    # Variable contains directly entered integer value
    DIRECT_INT_VALUE = enum.auto()
    # Variable represents assembler operand
    DIRECT_OPERAND = enum.auto()
    # Variable contains absolute address to a code chunk or function
    ABSOLUTE_ADDR_TO_CODE = enum.auto()
    # Variable contains absolute address to a global variable
    ABSOLUTE_ADDR_TO_GLOBAL_DATA = enum.auto()
    # Variable contains address to a code chunk relative to some base address
    RELATIVE_ADDR_TO_CODE = enum.auto()
    # Variable contains relative address to a global variable which contains absolute address to the code chunk
    RELATIVE_ADDR_TO_PTR_TO_CODE = enum.auto()
    # Variable contains address to a global variable relative to some base address
    RELATIVE_ADDR_TO_GLOBAL_DATA = enum.auto()
    # Variable contains relative address to a global variable which contains absolute address to the real value
    RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA = enum.auto()
    # Variable contains offset in unknown relation to some address, ie field position within a struct; obsolete - use the above instead
    RELATIVE_OFFSET = enum.auto()
    # Variable contains data not directly bound to any input offset
    DETACHED_DATA = enum.auto()
    # Variable which value is unused in current variant of the code
    UNUSED_DATA = enum.auto()
    # Internal variable of the tool, not to be used in pattern definitions
    INTERNAL_DATA = enum.auto()

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

class DummyStruct(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('unk', c_uint8)]

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
                'byteorder': "little",
                'cs_const' : CS_MODE_LITTLE_ENDIAN,
                'ks_const' : KS_MODE_LITTLE_ENDIAN,
            },
            {
                'name'     : "be",
                'desc'     : "Big endian",
                'byteorder': "big",
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
                'byteorder': "little",
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
                'byteorder': "little",
                'cs_const' : CS_MODE_LITTLE_ENDIAN,
                'ks_const' : KS_MODE_LITTLE_ENDIAN,
            },
            {
                'name'     : "be",
                'desc'     : "Big endian",
                'byteorder': "big",
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
                'byteorder': "little",
                'cs_const' : CS_MODE_32,
                'ks_const' : KS_MODE_32,
            },
            {
                'name'     : "64b",
                'desc'     : "x86_64 64bit",
                'byteorder': "little",
                'cs_const' : CS_MODE_64,
                'ks_const' : KS_MODE_64,
            },
        ]
    }
]

# Function with address to _msg_author_level
re_func_DjiMsgAuthorLevelGet = {
'name': "DjiMsgAuthorLevelGet",
'version': "P3X_FW_V01.01",
're': """
DjiMsgAuthorLevelGet:
  ldr	r0, \[pc, #(?P<msg_author_level>[0-9a-fx]+)\]
  ldr	r0, \[r0\]
  bx	lr
""",
'vars': {
  'DjiMsgAuthorLevelGet':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'msg_author_level': {'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T},
},
}

re_func_DjiMsgSettingsInit = {
'name': "DjiMsgSettingsInit",
'version': "P3X_FW_V01.01",
're': """
DjiMsgSettingsInit:
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
loc_label03:
  movs	r0, r4
  b	#(?P<loc_label06>[0-9a-fx]+)
loc_label02:
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
loc_label09:
  ldrb	r0, \[sp, #0x11\]
  cmp	r0, #1
  bne	#(?P<loc_label10>[0-9a-fx]+)
  ldrb	r0, \[sp, #0x10\]
  cmp	r0, #1
  bne	#(?P<loc_label10>[0-9a-fx]+)
  mov	r0, #(?P<verify_state_good_authority_level>[0-9a-fx]+)
  bl	#(?P<DjiMsgAuthorLevelSet>[0-9a-fx]+)
  b	#(?P<loc_label11>[0-9a-fx]+)
loc_label10:
  mov	r0, #(?P<verify_state_bad_authority_level>[0-9a-fx]+)
  bl	#(?P<DjiMsgAuthorLevelSet>[0-9a-fx]+)
loc_label11:
  mov	r5, #0
  b	#(?P<loc_label12>[0-9a-fx]+)
loc_label13:
  ldr	r0, \[pc, #(?P<unk_var01>[0-9a-fx]+)\]
  lsls	r1, r5, #2
  ldr	r2, \[pc, #(?P<unk_var02>[0-9a-fx]+)\]
  adds	r1, r1, r2
  mov	r2, #1
  str	r2, \[r0, r1\]
  adds	r5, r5, #1
loc_label12:
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
loc_label06:
  add	sp, sp, #0x14
  pop	{r4, r5, pc}
""",
'vars': {
  'DjiMsgSettingsInit':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'AmbaKAL_MutexCreate':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'AmbaPrintk_Disabled':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'AmbaPrintk':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'DjiMsgAuthorLevelSet':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'DjiEncryptGetA9Status':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'memset_0':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'cstr_fmt_text1':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_func_name':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'dji_msg_mutex':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.STRUCT, 'struct': DummyStruct,},
  'msg_adjust_task_finished':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T},
  'printk_log_level':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T},
  'encrypt_query_fail_authority_level':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT32_T,
    'public': "og_hardcoded.p3x_ambarella", 'minValue': "0", 'maxValue': "2", 'defaultValue': "0",
    'description': "AuthorityLevel established when SHA204 communication fail; 0-restricted,1-normal,2-superuser"},
  'verify_state_good_authority_level':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT32_T,
    'public': "og_hardcoded.p3x_ambarella", 'minValue': "0", 'maxValue': "2", 'defaultValue': "1",
    'description': "AuthorityLevel established when encryption keys match; 0-restricted,1-normal,2-superuser"},
  'verify_state_bad_authority_level':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT32_T,
    'public': "og_hardcoded.p3x_ambarella", 'minValue': "0", 'maxValue': "2", 'defaultValue': "0",
    'description': "AuthorityLevel established on encryption mismatch; 0-restricted,1-normal,2-superuser"},
  'loc_label02':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label03':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label06':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label09':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label10':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label11':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label12':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label13':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'unk_offs01':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T},
  'unk_var01':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var02':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var03':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var04':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var05':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var06':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var07':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var08':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var09':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var10':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var11':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var12':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var13':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var14':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var15':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var16':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var17':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var18':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var19':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var20':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
},
}

class AmbaP3XBitrateTableEntry(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('min', c_int),
              ('avg', c_int),
              ('max', c_int)]

re_func_DjiUstVideoQualitySetInner = {
'name': "DjiUstVideoQualitySetInner",
'version': "P3X_FW_V01.01",
're': """
DjiUstVideoQualitySetInner:
  push	{r4, r5, lr}
  sub	sp, sp, #0x14
  movs	r4, r0
  ldr	r0, \[r4\]
  cmp	r0, #0
  beq	#(?P<loc_label01>[0-9a-fx]+)
  cmp	r0, #2
  beq	#(?P<loc_label02>[0-9a-fx]+)
  blo	#(?P<loc_label03>[0-9a-fx]+)
  b	#(?P<loc_label04>[0-9a-fx]+)
loc_label01:
  add	r0, r2, r2, lsl #1
  ldr	r1, \[pc, #(?P<vid_setting_bitrates>[0-9a-fx]+)\]
  ldr	r0, \[r1, r0, lsl #2\]
loc_label06:
  cmp	r0, #0
  beq	#(?P<loc_label05>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<unk_var01>[0-9a-fx]+)\]
  ldrsb	r1, \[r1, #0x12\]
  mov	r2, #0x54
  ldr	r3, \[pc, #(?P<vid_settings_ust>[0-9a-fx]+)\]
  smlabb	r1, r1, r2, r3
  str	r0, \[r1, #8\]
loc_label05:
  mov	r0, #0
loc_label08:
  add	sp, sp, #0x14
  pop	{r4, r5, pc}
loc_label03:
  add	r0, r2, r2, lsl #1
  ldr	r1, \[pc, #(?P<vid_setting_bitrates>[0-9a-fx]+)\]
  adds	r0, r1, r0, lsl #2
  ldr	r0, \[r0, #4\]
  b	#(?P<loc_label06>[0-9a-fx]+)
loc_label02:
  add	r0, r2, r2, lsl #1
  ldr	r1, \[pc, #(?P<vid_setting_bitrates>[0-9a-fx]+)\]
  adds	r0, r1, r0, lsl #2
  ldr	r0, \[r0, #8\]
  b	#(?P<loc_label06>[0-9a-fx]+)
loc_label04:
  ldr	r0, \[pc, #(?P<printk_log_level>[0-9a-fx]+)\]
  ldr	r0, \[r0\]
  cmp	r0, #0
  bmi	#(?P<loc_label07>[0-9a-fx]+)
  mov	r5, #0
  mov	r0, #1
  movs	r5, r0
  bl	#(?P<AmbaPrintk_Disabled>[0-9a-fx]+)
  cmp	r0, #1
  beq	#(?P<loc_label07>[0-9a-fx]+)
  ldr	r0, \[r4\]
  str	r0, \[sp, #0x10\]
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
loc_label07:
  mvn	r0, #0
  b	#(?P<loc_label08>[0-9a-fx]+)
""",
'vars': {
  'DjiUstVideoQualitySetInner':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'cstr_fmt_text1':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_func_name':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'AmbaPrintk_Disabled':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'AmbaPrintk':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'loc_label01':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label02':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label03':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label04':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label05':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label06':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label07':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label08':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'unk_var01':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'vid_settings_ust':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.STRUCT, 'struct': DummyStruct,},
  'vid_setting_bitrates':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.STRUCT, 'array': 27,
    'struct': AmbaP3XBitrateTableEntry,
    'public': "og_hardcoded.p3x_ambarella", 'minValue': "1000000 1000000 1000000", 'maxValue': "64000000 64000000 64000000",
    'description': "Bitrates used for h.264 video compression; 3 values: min, avg, max"},
  'printk_log_level':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T},
},
}

re_general_list = [
  {'sect': ".text", 'func': re_func_DjiMsgSettingsInit,},
  {'sect': ".text", 'func': re_func_DjiUstVideoQualitySetInner,},
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


def elf_march_to_asm_config(elfobj, submode=None):
    """ Retrieves machine architecture for given elf.

    Returns config for capstone and keystone.
    """
    march = elfobj.get_machine_arch()
    asm_arch = None
    asm_modes = []
    if march == "x64":
        asm_arch = get_asm_arch_by_name("x86")
        asm_modes.append( get_asm_mode_by_name(asm_arch, "64b") )
    elif march == "x86":
        asm_arch = get_asm_arch_by_name("x86")
        asm_modes.append( get_asm_mode_by_name(asm_arch, "32b") )
    elif march == "ARM":
        asm_arch = get_asm_arch_by_name("arm")
        if elfobj.little_endian:
            asm_modes.append( get_asm_mode_by_name(asm_arch, "le") )
        else:
            asm_modes.append( get_asm_mode_by_name(asm_arch, "be") )
    elif march == "MIPS":
        asm_arch = get_asm_arch_by_name("mips")
        asm_modes.append( get_asm_mode_by_name(asm_arch, "32b") )
        if elfobj.little_endian:
            asm_modes.append( get_asm_mode_by_name(asm_arch, "le") )
        else:
            asm_modes.append( get_asm_mode_by_name(asm_arch, "be") )
    if submode != None:
        asm_modes.append( get_asm_mode_by_name(asm_arch, submode) )
    return (asm_arch, asm_modes)


def get_arm_vma_relative_to_pc_register(asm_arch, section, address, size, offset_str):
    """ Gets Virtual Memory Address associated with offet given within an asm instruction.

    ARMs have a way of storing relative offsets which may be confusing at first.
    """
    alignment = asm_arch['boundary']
    # In ARM THUMB mode, alignment is 4
    if (asm_arch['name'] == "arm") and (alignment == 2):
        alignment = 4
    if isinstance(offset_str, int):
        offset_int = offset_str
    else:
        offset_int = int(offset_str, 0)
    address = address - (address % alignment)
    vma = address + size + asm_arch['boundary'] + offset_int
    return vma - (vma % alignment)

def get_arm_vma_subtracted_from_pc_register(asm_arch, section, address, size, offset_str):
    """ Gets Virtual Memory Address associated to offet subtracted from PC reg within an asm instruction.
    """
    alignment = asm_arch['boundary']
    # In ARM THUMB mode, alignment is 4
    if (asm_arch['name'] == "arm") and (alignment == 2):
        alignment = 4
    if isinstance(offset_str, int):
        offset_int = offset_str
    else:
        offset_int = int(offset_str, 0)
    address = address - (address % alignment)
    vma = address + size - offset_int
    return vma - (vma % asm_arch['boundary'])


def get_arm_offset_val_relative_to_pc_register(asm_arch, address, size, vma):
    """ Gets offset associated with Virtual Memory Address given to place into asm instruction.
    """
    offset_val = vma - address - size - asm_arch['boundary']
    return offset_val


def get_section_and_offset_from_address(asm_arch, elf_sections, address):
    """ Gets Virtual Memory Address associated with offet given within an asm instruction.
    """
    for sect_name, sect in elf_sections.items():
        offset = address - sect['addr']
        if (offset >= 0) and (offset < len(sect['data'])):
            return sect_name, offset
    return None, None


def armfw_elf_generic_objdump(po, elffh, asm_submode=None):
    """ Dump executable in similar manner to objdump disassemble function.
    """
    elfobj = ELFFile(elffh)

    asm_arch, asm_modes = elf_march_to_asm_config(elfobj, asm_submode)
    if len(asm_modes) < 1 or not isinstance(asm_modes[0], collections.abc.Mapping):
        raise ValueError("ELF has unsupported machine type ({:s}).".format(elfobj['e_machine']))

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
    for i in range(elfobj.num_sections()):
        esection = elfobj.get_section(i)

        if esection['sh_type'] != "SHT_PROGBITS":
            continue

        if not (esection['sh_flags'] & SH_FLAGS.SHF_ALLOC):
            continue

        if (po.verbose > 2):
            print("{:s}: Found section {:s}".format(po.elffile,esection.name))

        section = {
              'index' : i,
              'name' : esection.name,
              'addr' : esection['sh_addr'],
              'data' : esection.data(),
        }

        if (esection['sh_flags'] & SH_FLAGS.SHF_EXECINSTR):
            sect_offs = 0
            while sect_offs < len(section['data']):
                for (address, size, mnemonic, op_str) in cs.disasm_lite(section['data'][sect_offs:], section['addr']+sect_offs):
                    print("0x{:05x}:\t{:s}\t{:s}".format(address, mnemonic, op_str))
                    sect_offs += size
                size = len(section['data']) - sect_offs
                if size > asm_arch['boundary']:
                    size = asm_arch['boundary']
                address = section['addr']+sect_offs
                if size > 0:
                    print("0x{:05x}:\tdcb\t".format(address), end='')
                    for bt in section['data'][sect_offs:sect_offs+size]:
                        print("0x{:02x} ".format(bt), end='')
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
                    print("0x{:05x}:\tdcb\t".format(address), end='')
                    for bt in section['data'][sect_offs:sect_offs+size]:
                        print("0x{:02x} ".format(bt), end='')
                    print("")
                sect_offs += size


def armfw_asm_search_strings_to_re_list(re_patterns):
    """ Converts multiline regex string to a list of patterns.
    """
    # Divide to lines
    re_lines = re_patterns.split(sep="\n")
    re_labels = {}
    # Remove comments
    re_lines = [s.split(";",1)[0]  if ";" in s else s for s in re_lines]
    # Remove labels
    for i, s in enumerate(re_lines):
        re_label = re.search(r'^([a-zA-Z0-9_]+):(.*)$', s)
        if re_label is not None:
            re_lines[i] = re_label.group(2)
            re_labels[re_label.group(1)] = i
    # Strip whitespaces
    re_lines = list(map(str.strip, re_lines))
    # Later empty lines will be removed; update re_labels accordingly
    reduced_line = 0
    for s in re_lines:
        if s is "":
            for lab_name, lab_line in re_labels.items():
                if (lab_line > reduced_line):
                    re_labels[lab_name] = lab_line - 1
        else:
            reduced_line += 1
    # Remove empty lines
    return list(filter(None, re_lines)), re_labels

def armfw_elf_section_search_init(asm_arch, section, patterns):
    """ Initialize search data.
    """
    search = {}
    search['asm_arch'] = asm_arch
    search['section'] = section
    search['name'] = patterns['name']
    search['version'] = patterns['version']
    re_lines, re_labels = armfw_asm_search_strings_to_re_list(patterns['re'])
    search['re'] = re_lines
    search['var_defs'] = patterns['vars'].copy()
    for lab_name, lab_line in re_labels.items():
        if lab_name in search['var_defs']:
            var_def = search['var_defs'][lab_name]
            var_def['line'] = lab_line
    search['var_vals'] = {}
    # Starting address of the current match
    search['match_address'] = 0
    # Binary size of each matched regex line
    search['re_size'] = []
    # Amount of lines already matched (aka current line)
    search['match_lines'] = 0
    search['best_match_address'] = 0
    search['best_match_lines'] = 0
    # List of datasets for full matches
    search['full_matches'] = []
    # Variant of the current variable length statement
    search['varlen_inc'] = 0
    # List of points where variable length lines were found
    search['varlen_points'] = []
    return search

def armfw_elf_section_search_reset(search):
    """ Reset search data after matching failed.
    """
    if search['best_match_lines'] < search['match_lines']:
        search['best_match_address'] = search['match_address']
        search['best_match_lines'] = search['match_lines']
    search['var_vals'] = {}
    search['match_address'] = 0
    search['re_size'] = []
    search['match_lines'] = 0
    search['varlen_inc'] = 0
    search['varlen_points'] = []
    return search


def armfw_elf_section_search_varlen_point_mark(search, address, varlen_delta):
    """ Add or update variable length point in given search results.
    """
    # the search['match_address'], might be unset if we are matching first line;
    # in that case, use address from func parameter
    if search['match_lines'] < 1:
        search['match_address'] = address
    # do not change search['varlen_inc'], only the one which will be used
    # if matching current one will fail
    for varlen in search['varlen_points']:
        if varlen['match_address'] != search['match_address']:
            continue
        if varlen['match_lines'] != search['match_lines']:
            continue
        if sum(varlen['re_size']) != sum(search['re_size']):
            continue
        # found pre-existing varlen point
        varlen['varlen_delta'] = varlen_delta
        if varlen_delta > 0:
            varlen['varlen_inc'] += 1
        return search
    varlen = {}
    varlen['var_vals'] = search['var_vals'].copy()
    varlen['match_address'] = search['match_address'] # int value
    varlen['re_size'] = search['re_size'].copy()
    varlen['match_lines'] = search['match_lines'] # int value
    varlen['varlen_inc'] = 1 # 0 is already being tested when this is added
    varlen['varlen_delta'] = varlen_delta
    search['varlen_points'].append(varlen)
    return search

def armfw_elf_section_search_varlen_point_rewind(search):
    """ Rewinds the search to last varlen entry which may be increased.
    """
    if search['best_match_lines'] < search['match_lines']:
        search['best_match_address'] = search['match_address']
        search['best_match_lines'] = search['match_lines']
    for varlen in reversed(search['varlen_points']):
        if varlen['varlen_delta'] <= 0:
            search['varlen_points'].pop()
            continue
        search['var_vals'] = varlen['var_vals'].copy()
        search['match_address'] = varlen['match_address'] # int value
        search['re_size'] = varlen['re_size'].copy()
        search['match_lines'] = varlen['match_lines'] # int value
        search['varlen_inc'] = varlen['varlen_inc']
        return True
    return False

def armfw_elf_section_search_progress(search, match_address, match_line_size):
    """ Update search data after matching next line suceeded.
    """
    search['match_lines'] += 1
    if search['match_lines'] == 1:
        search['match_address'] = match_address
        search['re_size'] = []
    search['varlen_inc'] = 0
    search['re_size'].append(match_line_size)
    if search['match_lines'] == len(search['re']):
        search['full_matches'].append({'address': search['match_address'], 're': search['re'], 're_size': search['re_size'], 'vars': search['var_vals']})
        search['match_lines'] = 0
    return search

def armfw_elf_section_search_print_unused_vars(search):
    """ Show messages about unused variables defined in the regex.
    To be used after a match is found.
    """
    for var_name in search['var_defs']:
        if var_name in search['var_vals']:
            continue
        var_val_found = False
        # Handle vars with suffixes
        for var_val_name in search['var_vals']:
            if var_val_name.startswith(var_name+"_"):
                var_val_found = True
                break
        if var_val_found:
            continue
        print("Variable '{:s}' defined but not used within matched regex".format(var_name))

def armfw_elf_section_search_get_pattern(search):
    """ Get regex pattern to match with next line.
    """
    re_patterns = search['re']
    match_lines = search['match_lines']
    return re_patterns[match_lines]

def armfw_elf_section_search_get_next_search_pos(search, sect_offs):
    """ Get position to start a next search before resetting current one.
    """
    # We intentionally clean 're_size' only on reset, so that it could be used here even after full match
    asm_arch = search['asm_arch']
    if len(search['re_size']) > 0:
        new_offs = search['match_address'] - search['section']['addr'] + min(asm_arch['boundary'],search['re_size'][0])
        return new_offs
    else:
        new_offs = sect_offs + asm_arch['boundary']
        return new_offs - (new_offs % asm_arch['boundary'])


def variety_is_signed_int(var_variety):
    return  var_variety in (DataVariety.INT8_T, DataVariety.INT16_T, DataVariety.INT32_T, DataVariety.INT64_T,)

def variety_is_unsigned_int(var_variety):
    return  var_variety in (DataVariety.UINT8_T, DataVariety.UINT16_T, DataVariety.UINT32_T, DataVariety.UINT64_T,)

def variety_is_string(var_variety):
    return  var_variety in (DataVariety.CHAR,)

def variety_is_float(var_variety):
    return  var_variety in (DataVariety.FLOAT, DataVariety.DOUBLE,)


def armfw_elf_section_search_get_value_variety_size(var_variety):
    """ Get expected size of the value
    """
    if var_variety in (DataVariety.CHAR, DataVariety.UINT8_T, DataVariety.INT8_T,):
        var_size = 1
    elif var_variety in (DataVariety.UINT16_T, DataVariety.INT16_T,):
        var_size = 2
    elif var_variety in (DataVariety.UINT32_T, DataVariety.INT32_T, DataVariety.FLOAT,):
        var_size = 4
    elif var_variety in (DataVariety.UINT64_T, DataVariety.INT64_T, DataVariety.DOUBLE,):
        var_size = 8
    else:
        var_size = 0
    return var_size


def value_type_is_known_address(var_def):
    """ Returns whether given type represents an address which can be referenced.

    Only some addresses can be converted to global addresses by this tool; an address is known
    if it either is global to begin with, or can be converted to global.
    If the address is known, property 'value' field will hold the absolute address.
    """
    if var_def['type'] in (VarType.RELATIVE_ADDR_TO_CODE, VarType.RELATIVE_ADDR_TO_PTR_TO_CODE,
            VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA,):
        if not 'baseaddr' in var_def: return False
        return var_def['baseaddr'] in ("PC+","PC-",)
    return var_def['type'] in (VarType.ABSOLUTE_ADDR_TO_CODE, VarType.ABSOLUTE_ADDR_TO_GLOBAL_DATA,
        VarType.DIRECT_LINE_OF_CODE,)

def value_type_is_unknown_address(var_def):
    """ Returns whether given type represents a relative address which cannot be referenced.

    Only some addresses can be converted to global addresses by this tool; an address is known
    if it either is global to begin with, or can be converted to global.
    If the address is unknown, property 'value' field will hold offset relative to unknown base.
    """
    if var_def['type'] in (VarType.ABSOLUTE_ADDR_TO_CODE, VarType.ABSOLUTE_ADDR_TO_GLOBAL_DATA,
            VarType.DIRECT_LINE_OF_CODE, VarType.RELATIVE_OFFSET,
            VarType.RELATIVE_ADDR_TO_CODE, VarType.RELATIVE_ADDR_TO_PTR_TO_CODE,
            VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA,):
        return (not value_type_is_known_address(var_def))
    return False

def armfw_elf_section_search_get_value_size(asm_arch, var_info):
    """ Get expected item size and count of the value
    """
    if var_info['variety'] in (DataVariety.STRUCT,):
        var_size = sizeof(var_info['struct'])
    else:
        var_size = armfw_elf_section_search_get_value_variety_size(var_info['variety'])

    if 'array' in var_info:
        if isinstance(var_info['array'], int):
            var_count = var_info['array']
        elif isinstance(var_info['array'], tuple):
            var_count = var_info['array'][1]
        else:
            # We have variable size array; just use static limit
            var_count = 2048
    else:
        var_count = 1
    return var_size, var_count


def prepare_simplified_asm_lines_from_pattern_list(asm_arch, glob_params_list, patterns_addr, pattern_lines, variab_size_select):
    """ Given a list of patterns and variables to put inside, produces assembly code.

    Removes regex-specific clauses and replaces named groups with values of variables.
    """
    asm_lines = []
    asm_addr_curr = patterns_addr
    for pat_line in pattern_lines:
        asm_line, code_size = prepare_asm_line_from_pattern(asm_arch, glob_params_list, asm_addr_curr, '', pat_line, variab_size_select=variab_size_select)
        asm_addr_curr += code_size
        asm_lines.append(asm_line)
    return asm_lines, (asm_addr_curr-patterns_addr)


def armfw_elf_create_dummy_params_list_for_patterns_with_best_match(asm_arch, patterns_list, pattern_vars):
    dummy_patt_base = 0x10000
    dummy_params_list = {}
    for var_name, var_info_orig in pattern_vars.items():
        var_info = var_info_orig.copy()
        if value_type_is_known_address(var_info):
            var_count = 1
        elif value_type_is_unknown_address(var_info):
            var_count = 1
        else:
            var_count = 1
            if 'array' in var_info:
                if isinstance(var_info['array'], int):
                    var_count = var_info['array']
                elif isinstance(var_info['array'], tuple):
                    var_count = var_info['array'][0] + (var_info['array'][1] - var_info['array'][0]) // 4
                else:
                    # We have variable size array; just use minimum length
                    var_count = 1
        var_limit_best = 0x20
        # Predict value of each variable which leads to best size match
        if 'setValue' in var_info:
            var_info['value'] = armfw_elf_search_value_string_to_native_type(var_info, var_info['setValue'])
        elif ('maxValue' in var_info) and ('minValue' in var_info) and (variety_is_float(var_info['variety']) or
          variety_is_unsigned_int(var_info['variety']) or variety_is_signed_int(var_info['variety'])):
            var_info['value'] = (armfw_elf_search_value_string_to_native_type(var_info, var_info['maxValue'])
                               + armfw_elf_search_value_string_to_native_type(var_info, var_info['minValue'])) // 2
        elif 'defaultValue' in var_info:
            var_info['value'] = armfw_elf_search_value_string_to_native_type(var_info, var_info['defaultValue'])
        elif 'maxValue' in var_info:
            var_info['value'] = armfw_elf_search_value_string_to_native_type(var_info, var_info['maxValue'])
        elif value_type_is_known_address(var_info):
            if 'line' in var_info:
                var_info['value'] = dummy_patt_base + asm_arch['boundary'] * var_info['line']
            else:
                var_info['value'] = dummy_patt_base + var_limit_best
        elif value_type_is_unknown_address(var_info):
            # Relative address must be relatively small or it might not compile
            var_info['value'] = var_limit_best
        elif var_info['type'] in (VarType.DIRECT_INT_VALUE,):
            if variety_is_string(var_info['variety']):
                # Direct string value - always treat as array
                prop_ofs_val = "a" * var_count
            else:
                # Direct int value - either single value or array
                if var_count < 2:
                    prop_ofs_val = var_limit_best
                else:
                    prop_ofs_val = [var_limit_best] * var_count
            var_info['value'] = prop_ofs_val
        else:
            # Anything else - either single value or array
            if var_count < 2:
                prop_ofs_val = var_limit_best
            else:
                prop_ofs_val = [var_limit_best] * var_count
            var_info['value'] = prop_ofs_val
        dummy_params_list[var_name] = var_info

    return dummy_params_list, dummy_patt_base


def armfw_elf_create_dummy_params_list_for_patterns_with_short_values(asm_arch, patterns_list, pattern_vars):
    dummy_patt_base = 0x10000
    dummy_params_list = {}
    for var_name, var_info_orig in pattern_vars.items():
        var_info = var_info_orig.copy()
        if value_type_is_known_address(var_info):
            var_count = 1
        elif value_type_is_unknown_address(var_info):
            var_count = 1
        else:
            var_count = 1
            if 'array' in var_info:
                if isinstance(var_info['array'], int):
                    var_count = var_info['array']
                elif isinstance(var_info['array'], tuple):
                    var_count = var_info['array'][0]
                else:
                    # We have variable size array; just use minimum length
                    var_count = 1
        var_limit_min = 0x10
        # Predict value of each variable which leads to shortest code
        if 'minValue' in var_info:
            var_info['value'] = armfw_elf_search_value_string_to_native_type(var_info, var_info['minValue'])
        elif 'setValue' in var_info:
            var_info['value'] = armfw_elf_search_value_string_to_native_type(var_info, var_info['setValue'])
        elif 'defaultValue' in var_info:
            var_info['value'] = armfw_elf_search_value_string_to_native_type(var_info, var_info['defaultValue'])
        elif 'maxValue' in var_info:
            var_info['value'] = armfw_elf_search_value_string_to_native_type(var_info, var_info['maxValue'])
        elif value_type_is_known_address(var_info):
            if 'line' in var_info:
                var_info['value'] = dummy_patt_base + asm_arch['boundary'] * var_info['line']
            else:
                var_info['value'] = dummy_patt_base + var_limit_min
        elif value_type_is_unknown_address(var_info):
            # Relative address must be relatively small ot it might not compile
            var_info['value'] = var_limit_min
        elif var_info['type'] in (VarType.DIRECT_INT_VALUE,):
            if variety_is_string(var_info['variety']):
                # Direct string value - always treat as array
                prop_ofs_val = "a" * var_count
            else:
                # Direct int value - either single value or array
                if var_count < 2:
                    prop_ofs_val = var_limit_min
                else:
                    prop_ofs_val = [var_limit_min] * var_count
            var_info['value'] = prop_ofs_val
        else:
            # Anything else - either single value or array
            if var_count < 2:
                prop_ofs_val = var_limit_min
            else:
                prop_ofs_val = [var_limit_min] * var_count
            var_info['value'] = prop_ofs_val
        dummy_params_list[var_name] = var_info
    return dummy_params_list, dummy_patt_base


def armfw_elf_create_dummy_params_list_for_patterns_with_long_values(asm_arch, patterns_list, pattern_vars):
    dummy_patt_base = 0x10000
    dummy_params_list = {}
    for var_name, var_info_orig in pattern_vars.items():
        var_info = var_info_orig.copy()
        if value_type_is_known_address(var_info):
            var_size = 3
            var_count = 1
        elif value_type_is_unknown_address(var_info):
            var_size = 1
            var_count = 1
        else:
            if var_info['variety'] in (DataVariety.STRUCT,):
                var_size = sizeof(var_info['struct'])
            else:
                var_size = armfw_elf_section_search_get_value_variety_size(var_info['variety'])
            var_count = 1
            if 'array' in var_info:
                if isinstance(var_info['array'], int):
                    var_count = var_info['array']
                elif isinstance(var_info['array'], tuple):
                    var_count = var_info['array'][1]
                else:
                    # We have variable size array; just use static limit
                    var_count = 2048
        if var_size > 0:
            var_limit_max = (2 << (var_size*8-1)) - 1
        else:
            var_limit_max = 0x7F
        # Predict value of each variable which leads to longest code
        if 'maxValue' in var_info:
            var_info['value'] = armfw_elf_search_value_string_to_native_type(var_info, var_info['maxValue'])
        elif 'setValue' in var_info:
            var_info['value'] = armfw_elf_search_value_string_to_native_type(var_info, var_info['setValue'])
        elif 'defaultValue' in var_info:
            var_info['value'] = armfw_elf_search_value_string_to_native_type(var_info, var_info['defaultValue'])
        elif 'minValue' in var_info:
            var_info['value'] = armfw_elf_search_value_string_to_native_type(var_info, var_info['minValue'])
        elif value_type_is_known_address(var_info):
            if 'line' in var_info:
                var_info['value'] = dummy_patt_base + asm_arch['boundary'] * var_info['line']
            else:
                var_info['value'] = dummy_patt_base + var_limit_max
        elif value_type_is_unknown_address(var_info):
            # Relative address must be relatively small ot it might not compile
            var_info['value'] = var_limit_max
        elif var_info['type'] in (VarType.DIRECT_INT_VALUE,):
            if variety_is_string(var_info['variety']):
                # Direct string value - always treat as array
                prop_ofs_val = "a" * var_count
            else:
                # Direct int value - either single value or array
                if var_count < 2:
                    prop_ofs_val = var_limit_max
                else:
                    prop_ofs_val = [var_limit_max] * var_count
            var_info['value'] = prop_ofs_val
        else:
            # Anything else - either single value or array
            if var_count < 2:
                prop_ofs_val = var_limit_max
            else:
                prop_ofs_val = [var_limit_max] * var_count
            var_info['value'] = prop_ofs_val

        dummy_params_list[var_name] = var_info
    return dummy_params_list, dummy_patt_base


def armfw_elf_compute_pattern_code_length(asm_arch, patterns_list, pattern_vars, variab_size_select):
    """ Returns estimated length in bytes of given asm patterns list.

    Using this function should be avoided whenever possible. It tries hard to provide correct length,
    but it is simply impossible - not only because of parameter values influencing the length, but also
    because there are many binary equivalents to an instruction, and they have different lengths. Every
    compiler prepares different code for some instructions.
    """
    if variab_size_select == 'best':
        dummy_params_list, dummy_patt_base = armfw_elf_create_dummy_params_list_for_patterns_with_best_match(asm_arch, patterns_list, pattern_vars)
    elif variab_size_select == 'long':
        dummy_params_list, dummy_patt_base = armfw_elf_create_dummy_params_list_for_patterns_with_long_values(asm_arch, patterns_list, pattern_vars)
    elif variab_size_select == 'short':
        dummy_params_list, dummy_patt_base = armfw_elf_create_dummy_params_list_for_patterns_with_short_values(asm_arch, patterns_list, pattern_vars)
    else:
        raise ValueError("Unknown variable size param '{:s}' - internal error".format(variab_size_select))

    #print("Making code from re for len:","; ".join(patterns_list))
    asm_lines, _ = prepare_simplified_asm_lines_from_pattern_list(asm_arch, dummy_params_list, dummy_patt_base, patterns_list, variab_size_select)
    # Now compile our new code line to get proper length
    #print("Compiling code for",variab_size_select,"len:","; ".join(asm_lines))
    bt_enc_data = armfw_asm_compile_lines(asm_arch, dummy_patt_base, asm_lines)
    return len(bt_enc_data)


def armfw_elf_search_value_bytes_to_native_type(asm_arch, var_info, var_bytes):
    """ Converts bytes to a variable described in info struct and architecture.
    """
    # Get expected length of the value
    var_size, var_count = armfw_elf_section_search_get_value_size(asm_arch, var_info)
    if var_info['variety'] in (DataVariety.CHAR,):
        # Native type is str
        if 'array' in var_info:
            var_nativ = [ var_bytes.rstrip(b"\0").decode("ISO-8859-1") ]
        else:
            var_nativ = [ var_bytes.decode("ISO-8859-1") ]
    elif variety_is_unsigned_int(var_info['variety']):
        var_nativ = []
        for i in range(len(var_bytes) // var_size):
            var_nativ.append(int.from_bytes(var_bytes[i*var_size:(i+1)*var_size], byteorder=asm_arch['byteorder'], signed=False))
    elif variety_is_signed_int(var_info['variety']):
        var_nativ = []
        for i in range(len(var_bytes) // var_size):
            var_nativ.append(int.from_bytes(var_bytes[i*var_size:(i+1)*var_size], byteorder=asm_arch['byteorder'], signed=True))
    elif variety_is_float(var_info['variety']):
        var_nativ = []
        for i in range(len(var_bytes) // var_size):
            # struct.unpack() returns a typle, even if with only one item; so we add it to list via extend().
            if var_size >= 8:
                var_nativ.extend(struct.unpack("<d",var_bytes[i*var_size:(i+1)*var_size]))
            else:
                var_nativ.extend(struct.unpack("<f",var_bytes[i*var_size:(i+1)*var_size]))
    elif var_info['variety'] in (DataVariety.STRUCT,):
        var_nativ = []
        prop_array_len = len(var_bytes) // var_size
        for i in range(prop_array_len):
            var_struct = var_info['struct'].from_buffer_copy(var_bytes[i*var_size:(i+1)*var_size])
            var_nativ.append(var_struct)
    else:
        var_nativ = []

    if len(var_nativ) == 1:
        var_nativ = var_nativ[0]
    elif len(var_nativ) < 1:
        var_nativ = None

    return var_nativ

def armfw_elf_search_value_native_type_to_bytes(asm_arch, var_info, var_nativ):
    """ Converts native variable to bytes as described in info struct and architecture.
    """
    # Get expected length of the value
    var_size, var_count = armfw_elf_section_search_get_value_size(asm_arch, var_info)
    if isinstance(var_nativ, str):
        var_bytes = var_nativ.encode("ISO-8859-1")
    elif isinstance(var_nativ, int):
        var_bytes = var_nativ.to_bytes(var_size, asm_arch['byteorder'])
    elif isinstance(var_nativ, float):
        if var_size >= 8:
            var_bytes = struct.pack("<d", var_nativ)
        else:
            var_bytes = struct.pack("<f", var_nativ)
    elif hasattr(var_nativ, "_fields_"): # check if we have a ctypes struct
        var_bytes = (c_ubyte * sizeof(var_nativ)).from_buffer_copy(var_nativ)
    elif hasattr(var_nativ, "__len__"): # check if we have an array
        var_bytes = b''
        for itm in var_nativ:
            var_bytes.append(armfw_elf_search_value_native_type_to_bytes(asm_arch, var_info, itm))
    else:
        var_bytes = b''
    return var_bytes


def armfw_elf_search_value_native_type_to_string(var_nativ):
    """ Converts given native type to string or array of strings.
    """
    if isinstance(var_nativ, str):
        val_str = var_nativ
    elif isinstance(var_nativ, int):
        val_str = "{:d}".format(var_nativ)
    elif isinstance(var_nativ, float):
        val_str = "{:f}".format(var_nativ)
    elif hasattr(var_nativ, "_fields_"): # check if we have a ctypes struct
        val_str = ""
        for field in var_nativ._fields_:
            val_str += "{:d} ".format(getattr(var_nativ, field[0]))
        val_str = val_str.rstrip()
    elif hasattr(var_nativ, "__len__"): # check if we have an array
        val_str = []
        for itm in var_nativ:
            val_str.append(armfw_elf_search_value_native_type_to_string(itm))
    else:
        val_str = ""
    return val_str


def armfw_elf_search_value_string_to_native_type(var_info, var_str):
    """ Converts string value to native type.

    Native type can be str, int, float, struct or array of int or float.
    """
    if var_info['variety'] in (DataVariety.CHAR,):
        var_nativ = str(var_str)
    elif var_info['variety'] in (DataVariety.UINT8_T, DataVariety.UINT16_T,
            DataVariety.UINT32_T, DataVariety.UINT64_T, DataVariety.INT8_T,
            DataVariety.INT16_T, DataVariety.INT32_T, DataVariety.INT64_T,):
        if isinstance(var_str, int):
            # If we already got an int - no processing required (this happens if JSON value is not in quotes)
            var_nativ = var_str
        else:
            var_nativ = []
            for val_itm in var_str.split():
                var_nativ.append(int(val_itm,0))
            if len(var_nativ) == 1:
                var_nativ = var_nativ[0]
    elif var_info['variety'] in (DataVariety.FLOAT, DataVariety.DOUBLE,):
        if isinstance(var_str, float):
            # If we already got a float - no processing required
            var_nativ = var_str
        else:
            var_nativ = []
            for val_itm in var_str.split():
                var_nativ.append(float(val_itm))
            if len(var_nativ) == 1:
                var_nativ = var_nativ[0]
    elif var_info['variety'] in (DataVariety.STRUCT,):
        var_nativ = var_info['struct']()
        for field, valstr in zip(var_nativ._fields_,var_str.split()):
            # currently we only accept int values within struct
            setattr(var_nativ, field[0], int(valstr,0))
    else:
        var_nativ = None
    return var_nativ


def get_matching_variable_from_patterns(patterns, var_type=None, var_variety=None, var_name=None, var_size=None, var_setValue=None, var_depend=None):
    for v_name, var_info in patterns['vars'].items():
        if var_type is not None and var_info['type'] != var_type:
            continue
        if var_variety is not None and var_info['variety'] != var_variety:
            continue
        if var_name is not None and v_name != var_name:
            continue
        if var_size is not None and var_info['size'] != var_size:
            continue
        if var_depend is not None:
            if 'depend' in var_info:
                # True means - any value, but must be set
                if var_depend == True:
                    pass
                elif var_info['depend'] != var_depend:
                    continue
            else:
                # False means - must not be set
                if var_depend == False:
                    pass
                else:
                    continue
        if var_setValue is not None:
            if 'setValue' not in var_info:
                # if we cannot check setValue, consider this loose match
                # That allows values merged together from definitions with
                # different types, as long as only one has no setValue.
                if var_setValue >= var_info['minValue']:
                    if var_setValue <= var_info['maxValue']:
                        loose_matched_patts = patterns
                continue
            if var_setValue != var_info['setValue']:
                continue
        return v_name
    return None


def find_patterns_containing_variable(re_list, cfunc_ver=None, var_type=None, var_variety=None, var_sect=None, var_name=None, var_size=None, var_setValue=None, var_depend=None):
    loose_matched_patts = None
    for re_item in re_list:
        if var_sect is not None and re_item['sect'] != var_sect:
            continue
        patterns = re_item['func']
        if cfunc_ver is not None and patterns['version'] != cfunc_ver:
            continue
        v_name = get_matching_variable_from_patterns(patterns, var_type, var_variety, var_name, var_size, var_setValue, var_depend)
        if v_name is not None:
            return patterns
    return loose_matched_patts


def find_patterns_diff(patterns_prev, patterns_next):
    """ Given two patterns, returns a part which is different between them.

    Assumes that patterns correspond to code of the same langth.
    """
    #TODO we should get and compare labels as well
    re_lines_prev, _ = armfw_asm_search_strings_to_re_list(patterns_prev['re'])
    re_lines_next, _ = armfw_asm_search_strings_to_re_list(patterns_next['re'])
    sp = 0
    sn = 0
    while sp < len(re_lines_prev) and sn < len(re_lines_next):
        line_p = re_lines_prev[sp]
        line_n = re_lines_next[sn]
        if line_p != line_n:
            break
        sp += 1
        sn += 1
    ep = len(re_lines_prev) - 1
    en = len(re_lines_next) - 1
    while ep > sp and en > sn:
        line_p = re_lines_prev[ep]
        line_n = re_lines_next[en]
        if line_p != line_n:
            break
        ep -= 1
        en -= 1
    patterns_diff = []
    patterns_diff_prev = []
    for i in range(sn, en+1):
        line_n = re_lines_next[i]
        patterns_diff.append(line_n)
        line_p = re_lines_prev[i]
        patterns_diff_prev.append(line_p)
    return patterns_diff, re_lines_prev[0:sp], patterns_diff_prev


def armfw_asm_is_data_definition(asm_arch, asm_line):
    """ Recognizes data definition assembly line, without fully interpreting data.

    The fact that it doesn't interpret data means it will work for regex too
    (though it might get signedness incorrectly).
    """
    re_isdata = re.search(r'^(dc[bwdq])\t(.*)$', asm_line)
    if re_isdata is None:
        return None, None, None
    elif re_isdata.group(1) == 'dcb':
        if re.match(r'".+"', re_isdata.group(2)):
            dt_variety = DataVariety.CHAR
        else:
            dt_variety = DataVariety.UINT8_T
        single_len = 1
    elif re_isdata.group(1) == 'dcw':
        if re.match(r'-[0-9]+"', re_isdata.group(2)):
            dt_variety = DataVariety.INT16_T
        else:
            dt_variety = DataVariety.UINT16_T
        single_len = 2
    elif re_isdata.group(1) == 'dcd':
        if re.match(r'[0-9]+[.][0-9]+"', re_isdata.group(2)):
            dt_variety = DataVariety.FLOAT
        if re.match(r'-[0-9]+"', re_isdata.group(2)):
            dt_variety = DataVariety.INT32_T
        else:
            dt_variety = DataVariety.UINT32_T
        single_len = 4
    elif re_isdata.group(1) == 'dcq':
        if re.match(r'[0-9]+[.][0-9]+"', re_isdata.group(2)):
            dt_variety = DataVariety.DOUBLE
        if re.match(r'-[0-9]+"', re_isdata.group(2)):
            dt_variety = DataVariety.INT64_T
        else:
            dt_variety = DataVariety.UINT64_T
        single_len = 8

    return single_len, dt_variety, re_isdata.group(2)

def armfw_asm_parse_data_definition(asm_arch, asm_line):
    """ Recognizes data definition assembly line, returns data as bytes.
    """
    single_len, dt_variety, data_part = armfw_asm_is_data_definition(asm_arch, asm_line)
    if single_len is None:
        return None
    dt_bytes = b''
    for dt_item in data_part.split(","):
        dt_sitem = dt_item.strip()
        dt_btitem = None
        try:
            dt_btitem = int(dt_sitem, 0).to_bytes(single_len, byteorder=asm_arch['byteorder'])
        except ValueError:
            pass
        if dt_btitem is None:
            if dt_sitem.startswith('"') and dt_sitem.endswith('"'):
                dt_btitem = dt_sitem[1:-1].encode()
        if dt_btitem is None:
            raise ValueError("Cannot convert data def part to bytes: \"{:s}\".".format(dt_item))
        dt_bytes += dt_btitem
    return {'variety': dt_variety, 'item_size': single_len, 'value': dt_bytes }


def armfw_elf_data_definition_from_bytes(asm_arch, bt_data, bt_addr, pat_line, var_defs, var_size_inc=0):
    """ Converts bytes into data definition, keeping format given in pattern line.

    @asm_arch - Assembly architecture definition list.
    @bt_data - bytes stroring data for the definition; its length may exceed the definiton
    @bt_addr - address of the definition in memory
    @pat_line - regex pattern line containing the definition
    @var_defs - definitions of variables which may be used in the pattern
    @var_size_inc - variable length increase when the variable is an array of varying size
    """
    whole_size_min = armfw_elf_compute_pattern_code_length(asm_arch, [pat_line,], var_defs, 'short')
    whole_size_max = armfw_elf_compute_pattern_code_length(asm_arch, [pat_line,], var_defs, 'long')
    itm_size, itm_variety, _ = armfw_asm_is_data_definition(asm_arch, pat_line)

    if whole_size_max > whole_size_min:
        whole_size = whole_size_min + itm_size * var_size_inc
    else:
        whole_size = whole_size_min
    if whole_size > whole_size_max:
        whole_size = whole_size_max

    if itm_size == 1:
        mnemonic = 'dcb'
    elif itm_size == 2:
        mnemonic = 'dcw'
    elif itm_size == 4:
        mnemonic = 'dcd'
    elif itm_size == 8:
        mnemonic = 'dcq'
    itm_count = whole_size // itm_size
    op_list = []
    if itm_variety == DataVariety.CHAR:
        itm_merge = b""
        for i in range(itm_count):
            curr_bt = bt_data[i*itm_size:(i+1)*itm_size]
            curr_int = int.from_bytes(curr_bt, byteorder=asm_arch['byteorder'], signed=False)
            if curr_int >= 32 and curr_int <= 127:
                itm_merge += curr_bt
            else:
                if len(itm_merge) > 0:
                    op_list.append(itm_merge)
                    itm_merge = b""
                op_list.append(curr_int)
        if len(itm_merge) > 0:
            op_list.append(itm_merge)
    else:
        for i in range(itm_count):
            op_list.append(int.from_bytes(bt_data[i*itm_size:(i+1)*itm_size], byteorder=asm_arch['byteorder'], signed=False))
    op_list_str = []
    for itm in op_list:
        if isinstance(itm, int):
            op_list_str.append("0x{:x}".format(itm))
        elif isinstance(itm, (bytes, bytearray)):
            op_list_str.append("\"{:s}\"".format(itm.decode()))
        else:
            raise ValueError("Unexpected type - internal error.")
    return bt_addr, whole_size, whole_size_max, mnemonic, ", ".join(op_list_str)


def armfw_elf_section_search_add_var(po, search, var_name, var_suffix, var_info, prop_ofs_val, prop_str, address, size):
    """ Adds variable to current search results.

       @search - the target search results
       @var_name, @var_suffix - variable name and its suffix
       @var_info - static info about the variable
       @prop_ofs_val - offset or value to compare while validating the variable
       @prop_str - real value of the variable, converted to string
       @address - address to the initial finding place (not dereferenced if the place contained pointer to pointer)
       @size - instruction size, if the variable is a value within code
    """
    if var_name in search['var_vals']:
        var_val = search['var_vals'][var_name+var_suffix]
        if var_val['value'] != prop_ofs_val:
            if (po.verbose > 3):
                if isinstance(var_val['value'], int):
                    old_val = "0x{:0x}".format(var_val['value'])
                else:
                    old_val = str(var_val['value'])
                if isinstance(prop_ofs_val, int):
                    new_val = "0x{:0x}".format(prop_ofs_val)
                else:
                    new_val = str(prop_ofs_val)
                print("Mismatch on var '{:s}' value - is {:s}, now got {:s}".format(var_name+var_suffix,old_val,new_val))
            return False
        if var_info['type'] in (VarType.DIRECT_INT_VALUE,):
            raise ValueError("Mismatch on var '{:s}' occurences - direct int value can only occur once".format(var_name+var_suffix))
    else:
        var_def = search['var_defs'][var_name]
        var_val = {'str_value': prop_str, 'value': prop_ofs_val, 'address': address, 'line': search['match_lines'], 'cfunc_name': search['name'], 'cfunc_ver': search['version']}
        var_val.update(var_def)
        # For direct values, also store the regex matched to the line
        if (var_info['type'] == VarType.DIRECT_INT_VALUE):
            var_val['line'] = search['match_lines']
        search['var_vals'][var_name+var_suffix] = var_val
    return True


def armfw_elf_offset_or_value_to_value_bytes(asm_arch, elf_sections, var_info, prop_ofs_val):
    """ Either convert the direct value to bytes, or get bytes from offset.
    """
    # Get expected length of the value
    prop_size, prop_count = armfw_elf_section_search_get_value_size(asm_arch, var_info)
    if (var_info['type'] == VarType.DIRECT_INT_VALUE):
        # Convert the direct value to bytes
        if not isinstance(prop_ofs_val, list):
            prop_ofs_val = [prop_ofs_val]
        prop_bytes = b""
        for prop_var in prop_ofs_val:
            prop_bytes += (prop_var).to_bytes(prop_size, byteorder=asm_arch['byteorder'])
    elif (var_info['type'] in (VarType.ABSOLUTE_ADDR_TO_GLOBAL_DATA, VarType.RELATIVE_ADDR_TO_GLOBAL_DATA,
      VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA,)):
        # Get bytes from offset
        var_sect, var_offs = get_section_and_offset_from_address(asm_arch, elf_sections, prop_ofs_val)
        if var_sect is not None:
            var_data = elf_sections[var_sect]['data']
            prop_bytes = var_data[var_offs:var_offs+prop_size*prop_count]
        else:
            prop_bytes = b""
    else:
        prop_bytes = b""
    return prop_bytes


def armfw_elf_section_search_process_vars_from_code(po, search, elf_sections, address, size, re_code):
    """ Process variable values from a code line and add them to search results.
    """
    for var_name, var_val in re_code.groupdict().items():
        var_info = search['var_defs'][var_name]
        # Get expected length of the value
        prop_size, prop_count = armfw_elf_section_search_get_value_size(search['asm_arch'], var_info)

        # Get direct int value or offset to value
        if var_info['type'] in (VarType.DIRECT_INT_VALUE,):
            # for direct values, count is used
            # we may alco encounter a string
            if var_info['variety'] in (DataVariety.CHAR,):
                prop_ofs_val = [ord(sing_var) for sing_var in var_val]
                #prop_ofs_val = var_val
            else:
                if prop_count <= 1:
                    prop_ofs_val = int(var_val, 0)
                else:
                    prop_ofs_val = [int(sing_var.strip(),0) for sing_var in var_val.split(',')]
        elif var_info['type'] in (VarType.ABSOLUTE_ADDR_TO_CODE, VarType.ABSOLUTE_ADDR_TO_GLOBAL_DATA, VarType.RELATIVE_OFFSET,):
            prop_ofs_val = int(var_val, 0)
        elif var_info['type'] in (VarType.RELATIVE_ADDR_TO_CODE, VarType.RELATIVE_ADDR_TO_GLOBAL_DATA,) and var_info['baseaddr'] in ("PC+","PC-",):
            if var_info['baseaddr'].endswith('-'):
                prop_ofs_val = get_arm_vma_subtracted_from_pc_register(search['asm_arch'], search['section'], address, size, var_val)
            else:
                prop_ofs_val = get_arm_vma_relative_to_pc_register(search['asm_arch'], search['section'], address, size, var_val)
        elif var_info['type'] in (VarType.RELATIVE_ADDR_TO_PTR_TO_CODE,VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA,) and var_info['baseaddr'] in ("PC+","PC-",):
            if var_info['baseaddr'].endswith('-'):
                prop_ofs_val = get_arm_vma_subtracted_from_pc_register(search['asm_arch'], search['section'], address, size, var_val)
            else:
                prop_ofs_val = get_arm_vma_relative_to_pc_register(search['asm_arch'], search['section'], address, size, var_val)
            var_sect, var_offs = get_section_and_offset_from_address(search['asm_arch'], elf_sections, prop_ofs_val)
            if var_sect is not None:
                var_data = elf_sections[var_sect]['data']
                prop_ofs_val = int.from_bytes(var_data[var_offs:var_offs+4], byteorder=search['asm_arch']['byteorder'], signed=False)
            else:
                raise ValueError("Address to uninitialized data found (0x{:06x}).".format(prop_ofs_val))
        elif var_info['type'] in (VarType.DIRECT_OPERAND,):
            prop_ofs_val = var_val
        else:
            raise NotImplementedError("Unexpected variable type found while processing vars, '{:s}'.".format(var_info['type'].name))

        # Either convert the direct value to bytes, or get bytes from offset
        prop_bytes = armfw_elf_offset_or_value_to_value_bytes(search['asm_arch'], elf_sections, var_info, prop_ofs_val)
        # And convert further, to native type value
        var_nativ = armfw_elf_search_value_bytes_to_native_type(search['asm_arch'], var_info, prop_bytes)
        prop_str = armfw_elf_search_value_native_type_to_string(var_nativ)
        if isinstance(prop_str, str):
            if not armfw_elf_section_search_add_var(po, search, var_name, "", var_info, prop_ofs_val, prop_str, address, size):
                return False
        else: # array of strings
            if var_info['type'] in (VarType.DIRECT_INT_VALUE,):
                for i in range(len(prop_str)):
                    prop_sstr = prop_str[i]
                    if not armfw_elf_section_search_add_var(po, search, var_name, "_{:02d}".format(i), var_info, prop_ofs_val[i], prop_sstr, address, size):
                        return False
            else:
                for i in range(len(prop_str)):
                    prop_sstr = prop_str[i]
                    if not armfw_elf_section_search_add_var(po, search, var_name, "_{:02d}".format(i), var_info, prop_ofs_val + i*prop_size, prop_sstr, address, size):
                        return False

    # Now get variables associated to line of code, not anything within the code
    for var_name, var_info in search['var_defs'].items():
        # Add variables attached to code line (usually function name)
        if var_info['type'] in (VarType.DIRECT_LINE_OF_CODE,) and 'line' in var_info and search['match_lines'] == var_info['line']:
            # Get expected length of the value
            prop_size, prop_count = armfw_elf_section_search_get_value_size(search['asm_arch'], var_info)
            prop_ofs_val = address
            prop_str = ""
            if not armfw_elf_section_search_add_var(po, search, var_name, "", var_info, prop_ofs_val, prop_str, address, size):
                return False
        # Add variables detached from data (per-regex constants) or unused (used in different variant of the regex code)
        if var_info['type'] in (VarType.DETACHED_DATA, VarType.UNUSED_DATA,):
            # DETACHED_DATA with 'setValue' can be added on first line
            if 'depend' not in var_info and search['match_lines'] == 0:
                # Get expected length of the value
                prop_size, prop_count = armfw_elf_section_search_get_value_size(search['asm_arch'], var_info)
                prop_ofs_val = 0
                prop_str = var_info['setValue']
                if not armfw_elf_section_search_add_var(po, search, var_name, "", var_info, prop_ofs_val, prop_str, address, size):
                    return False
            # DETACHED_DATA which 'depend' on others must wait until all others are known - to last line
            if 'depend' in var_info and search['match_lines']+1 == len(search['re']):
                # Get expected length of the value
                prop_size, prop_count = armfw_elf_section_search_get_value_size(search['asm_arch'], var_info)
                prop_ofs_val = 0
                prop_str = armfw_elf_paramvals_get_depend_value(search['var_vals'], var_info)
                if not armfw_elf_section_search_add_var(po, search, var_name, "", var_info, prop_ofs_val, prop_str, address, size):
                    return False

    return True


def armfw_elf_section_search_block(po, search, sect_offs, elf_sections, cs, block_len):
    """ Search for pattern in a block of ELF file section.
        The function will try to save state and stop somewhere around given block_len.
    """
    sect_limit = len(search['section']['data'])
    if (sect_limit > sect_offs + block_len):
        sect_limit = sect_offs + block_len
    while sect_offs < sect_limit:
        curr_pattern = armfw_elf_section_search_get_pattern(search)
        curr_is_data, _, _ = armfw_asm_is_data_definition(search['asm_arch'], curr_pattern)
        if curr_is_data is not None:
            # now matching a data line; get its length
            line_iter = [armfw_elf_data_definition_from_bytes(search['asm_arch'],search['section']['data'][sect_offs:], search['section']['addr'] + sect_offs, curr_pattern, search['var_defs'], search['varlen_inc']),]
            for (address, size, max_size, mnemonic, op_str) in line_iter:
                if size < max_size or search['varlen_inc'] > 0:
                    search = armfw_elf_section_search_varlen_point_mark(search, address, max_size - size)
                instruction_str = "{:s}\t{:s}".format(mnemonic, op_str).strip()
                if (po.verbose > 3) and (search['match_lines'] > 1):
                    print("Current vs pattern {:3d} `{:s}` `{:s}`".format(search['match_lines'],instruction_str,curr_pattern))
                re_code = re.search(curr_pattern, instruction_str)
                # The block below is exactly the same as for normal instruction
                match_ok = (re_code is not None)
                if match_ok:
                    match_ok = armfw_elf_section_search_process_vars_from_code(po, search, elf_sections, address, size, re_code)

                if match_ok:
                    #print("Match lines: {:d} @ {:x}".format(search['match_lines'],address))
                    search = armfw_elf_section_search_progress(search, address, size)
                    if search['match_lines'] == 0: # This means we had a full match; we need to go back with offset to search for overlapping areas
                        if (po.verbose > 2):
                            armfw_elf_section_search_print_unused_vars(search)
                        sect_offs = armfw_elf_section_search_get_next_search_pos(search, sect_offs)
                        search = armfw_elf_section_search_reset(search)
                        break
                    curr_pattern = armfw_elf_section_search_get_pattern(search)
                    sect_offs += size
                    curr_is_data, _, _ = armfw_asm_is_data_definition(search['asm_arch'], curr_pattern)
                    if curr_is_data is not None: break
                else:
                    # Breaking the loop is only expensive for ASM code; for data, we don't really care that much
                    if armfw_elf_section_search_varlen_point_rewind(search):
                        sect_offs = search['match_address'] - search['section']['addr'] + sum(search['re_size'])
                    else:
                        sect_offs = armfw_elf_section_search_get_next_search_pos(search, sect_offs)
                        search = armfw_elf_section_search_reset(search)
                    break
        else:
            # now matching an assembly code line
            for (address, size, mnemonic, op_str) in cs.disasm_lite(search['section']['data'][sect_offs:], search['section']['addr'] + sect_offs):
                instruction_str = "{:s}\t{:s}".format(mnemonic, op_str).strip()
                if (po.verbose > 3) and (search['match_lines'] > 1):
                    print("Current vs pattern {:3d} `{:s}` `{:s}`".format(search['match_lines'],instruction_str,curr_pattern))
                re_code = re.search(curr_pattern, instruction_str)

                match_ok = (re_code is not None)
                if match_ok:
                    match_ok = armfw_elf_section_search_process_vars_from_code(po, search, elf_sections, address, size, re_code)

                if match_ok:
                    #print("Match lines: {:d} @ {:x}".format(search['match_lines'],address))
                    search = armfw_elf_section_search_progress(search, address, size)
                    if search['match_lines'] == 0: # This means we had a full match; we need to go back with offset to search for overlapping areas
                        if (po.verbose > 2):
                            armfw_elf_section_search_print_unused_vars(search)
                        sect_offs = armfw_elf_section_search_get_next_search_pos(search, sect_offs)
                        search = armfw_elf_section_search_reset(search)
                        break
                    curr_pattern = armfw_elf_section_search_get_pattern(search)
                    sect_offs += size
                    curr_is_data, _, _ = armfw_asm_is_data_definition(search['asm_arch'], curr_pattern)
                    if curr_is_data is not None: break
                else:
                    # Breaking the loop is expensive; do it only if we had more than one line matched, to search for overlapping areas
                    if search['match_lines'] > 0:
                        if armfw_elf_section_search_varlen_point_rewind(search):
                            sect_offs = search['match_address'] - search['section']['addr'] + sum(search['re_size'])
                            break
                        else:
                            pev_sect_offs = sect_offs
                            sect_offs = armfw_elf_section_search_get_next_search_pos(search, sect_offs)
                            search = armfw_elf_section_search_reset(search)
                            # Now try optimization - maybe we do not need to break the for() loop
                            # but this is only possible if the next offset to search matches the offset of next instruction in for()
                            if sect_offs != pev_sect_offs + size: break
                            # And if the first line pattern happens to be code, not data
                            curr_pattern = armfw_elf_section_search_get_pattern(search)
                            curr_is_data, _, _ = armfw_asm_is_data_definition(search['asm_arch'], curr_pattern)
                            if curr_is_data is not None: break
                            # ok, it should be safe not to break here and start matching next assembly line
                    else: # search['match_lines'] == 0
                        sect_offs += size
            else: # for loop finished by inability to decode next instruction
                # We know that curr_is_data is None - otherwise we'd break the loop; so since we encoured
                # invalid instruction, we are sure that the current matching failed and we should reset.
                if armfw_elf_section_search_varlen_point_rewind(search):
                    sect_offs = search['match_address'] - search['section']['addr'] + sum(search['re_size'])
                else:
                    sect_offs = armfw_elf_section_search_get_next_search_pos(search, sect_offs)
                    search = armfw_elf_section_search_reset(search)
    return (search, sect_offs)


def armfw_elf_whole_section_search(po, asm_arch, elf_sections, cs, sect_name, patterns, glob_params_list):
    """ Search for pattern in ELF file section.
        Return list of matching data.
    """
    search = armfw_elf_section_search_init(asm_arch, elf_sections[sect_name], patterns)
    # Prepare start offset
    start_sect_offs = 0
    for var_name, var_def in search['var_defs'].items():
        # Find variable representing offset of first line in the pattern
        if var_def['type'] not in (VarType.DIRECT_LINE_OF_CODE,):
            continue
        if 'line' not in var_def:
            continue
        if var_def['line'] != 0:
            continue
        # Check if that variable is in global vars
        var_info = variable_info_from_value_name(glob_params_list, search['name'], var_name)
        if var_info is None:
            continue
        if not value_type_is_known_address(var_info):
            continue
        # Use offset of the found variable
        next_sect_addr = get_final_address_from_var_info(asm_arch, elf_sections, var_info)
        if next_sect_addr is None:
            continue
        next_sect_name, next_sect_offs = get_section_and_offset_from_address(asm_arch, elf_sections, next_sect_addr)
        if next_sect_name is None:
            eprint("Pre-determined address of {:s} is outside of initialized sections (0x{:06x}); ignoring".format(var_name,next_sect_addr))
            continue
        if next_sect_name != sect_name:
            eprint("Pre-determined address of {:s} is in section '{:s}' instead of '{:s}'; ignoring".format(var_name,next_sect_name,sect_name))
            continue
        if (po.verbose > 1):
            print("Found pre-determined address of {:s} at 0x{:06x}".format(var_name,var_info['value']))
        start_sect_offs = next_sect_offs

    if 'no_search' in patterns:
        if patterns['no_search'] and start_sect_offs == 0:
            eprint("The {:s} requires pre-determined address from previously found functions; no such address exists".format(search['name']))
            return []

    sect_offs = start_sect_offs
    sect_progress_treshold = 0
    while sect_offs < len(search['section']['data']):
        search, sect_offs = armfw_elf_section_search_block(po, search, sect_offs, elf_sections, cs, 65536)
        # Print progress info
        if (po.verbose > 1) and (sect_offs > sect_progress_treshold):
            print("{:s}: Search for {:s} ver {:s}, progress {:3d}%".format(po.elffile, search['name'], search['version'], sect_offs * 100 // len(search['section']['data'])))
            sect_progress_treshold += len(search['section']['data']) / 10

    # If had offset before search, and found at that exact offset - ignore further matches
    if len(search['full_matches']) > 1 and start_sect_offs > 0:
        first_match = search['full_matches'][0]
        if first_match['address'] == search['section']['addr'] + start_sect_offs:
            search['full_matches'] = [ first_match ]

    if (po.verbose > 0):
        if len(search['full_matches']) == 1:
            print("{:s}: Pattern of {:s} ver {:s} located at 0x{:x}".format(po.elffile, search['name'], search['version'], search['full_matches'][0]['address']))
        elif len(search['full_matches']) > 1:
            print("{:s}: Pattern of {:s} ver {:s} found {:d} times".format(po.elffile, search['name'], search['version'], len(search['full_matches'])))
        else:
            print("{:s}: Pattern of {:s} ver {:s} was not found; closest was {:d} lines at 0x{:x}".format(po.elffile, search['name'], search['version'], search['best_match_lines'], search['best_match_address']))

    # If we have multiple matches, treat them based on a value set within the patterns definition; default is "reject"
    if len(search['full_matches']) > 1:
        if 'multiple' not in patterns or patterns['multiple'] == "reject":
            # do not accept multiple matches
            return []
        elif patterns['multiple'] == "depend":
            # convert public vars from subsequent matches to depend
            for match in search['full_matches'][1:]:
                for var_name, var_info in match['vars'].items():
                    if value_needs_global_name(var_name, var_info):
                        del match['vars'][var_name]
                        if 'public' in var_info and 'depend' not in var_info:
                            var_info['depend'] = var_name
                        var_name = "{:s}_match{:02d}".format(var_name,i)
                        match['vars'][var_name] = var_info

    return search['full_matches']


def armfw_elf_match_to_public_values(po, match):
    params_list = {}
    for var_name, var_info in match['vars'].items():
        if 'public' in var_info:
            if 'depend' in var_info:
                if 'forceVisible' not in var_info or not var_info['forceVisible']:
                    continue
            par_name = var_info['public']+'.'+var_name
            par_info = var_info.copy()
            par_info['name'] = var_name
            params_list[par_name] = par_info
    return params_list


def value_needs_global_name(var_name, var_info):
    if var_info['variety'] in (DataVariety.UNKNOWN,):
        return False
    if var_info['type'] in (VarType.ABSOLUTE_ADDR_TO_GLOBAL_DATA, VarType.RELATIVE_ADDR_TO_GLOBAL_DATA,):
        return True
    if var_info['type'] in (VarType.DETACHED_DATA,):
        return True
    if var_info['variety'] in (CodeVariety.FUNCTION,):
        return True
    return False


def armfw_elf_match_to_global_values(po, match, cfunc_name):
    params_list = {}
    for var_name, var_info in match['vars'].items():
        if value_needs_global_name(var_name, var_info):
            par_info = var_info.copy()
            var_full_name = var_name
        else:
            par_info = var_info.copy()
            var_full_name = cfunc_name+'.'+var_name
        par_info['name'] = var_full_name
        params_list[var_full_name] = par_info
    # Internal variables
    if True:
        var_name = '.re_size'
        par_info = {'type': VarType.INTERNAL_DATA, 'variety': DataVariety.UNKNOWN}
        var_full_name = cfunc_name+'.'+var_name
        par_info['name'] = var_full_name
        par_info['value'] = match['re_size']
        par_info['cfunc_name'] = cfunc_name
        params_list[var_full_name] = par_info
    if True:
        var_name = '.re'
        par_info = {'type': VarType.INTERNAL_DATA, 'variety': DataVariety.UNKNOWN}
        var_full_name = cfunc_name+'.'+var_name
        par_info['name'] = var_full_name
        par_info['value'] = match['re']
        par_info['cfunc_name'] = cfunc_name
        params_list[var_full_name] = par_info
    return params_list


def armfw_asm_compile_lines(asm_arch, asm_addr, asm_lines):
    ks = Ks(asm_arch['ks_const'], asm_arch['ks_mode'])
    asm_ln_start = 0
    bt_enc_data = b''
    for asm_ln_curr in range(len(asm_lines)+1):
        if asm_ln_curr < len(asm_lines):
            curr_data = armfw_asm_parse_data_definition(asm_arch, asm_lines[asm_ln_curr])
        else:
            curr_data = {'value': b''}
        if curr_data is not None:
            # Compile any pending asm lines
            if asm_ln_start < asm_ln_curr:
                asm_addr_curr = asm_addr + len(bt_enc_data)
                try:
                    encoding, encoded_num = ks.asm("\n".join(asm_lines[asm_ln_start:asm_ln_curr]), addr=asm_addr_curr)
                except KsError as e:
                    encoded_num = e.get_asm_count()
                    raise ValueError("Cannot compile all assembly lines: {:s}; compiled circa {:d} out of {:d}.".format(e.message, asm_ln_start+encoded_num, len(asm_lines)))
                if encoded_num != asm_ln_curr-asm_ln_start:
                    raise ValueError("Cannot compile all assembly lines; compiled circa {:d} out of {:d}.".format(asm_ln_start+encoded_num, len(asm_lines)))
                bt_enc_data += bytes(encoding)
            # Add data from the line at end
            bt_enc_data += curr_data['value']
            asm_ln_start = asm_ln_curr + 1
    return bt_enc_data


def variable_info_from_value_name(glob_params_list, cfunc_name, var_name):
    var_info = None
    if var_name in glob_params_list:
        var_info = glob_params_list[var_name]
    elif cfunc_name+'.'+var_name in glob_params_list:
        var_info = glob_params_list[cfunc_name+'.'+var_name]
    else:
        for var_name_iter, var_info_iter in glob_params_list.items():
            if var_name_iter.endswith('.'+var_name):
                var_info = var_info_iter
                break
    return var_info

def prepare_asm_line_from_pattern(asm_arch, glob_params_list, address, cfunc_name, pat_line, variab_size_select=None):
    # List regex parameters used in that line
    vars_used = re.findall(r'[(][?]P<([^>]+)>([^()]*([(][^()]+[)][^()]*)*)[)]', pat_line)
    inaccurate_size = (variab_size_select is not None)
    if not inaccurate_size:
        instr_size = armfw_elf_compute_pattern_code_length(asm_arch, [pat_line,], glob_params_list, 'best')
    else:
        instr_size = asm_arch['boundary'] # not true, but good enough if we don't care about the code being properly executable
    # Replace parameters with their values
    asm_line = pat_line
    for var_regex in vars_used:
        var_name = var_regex[0]
        var_info = variable_info_from_value_name(glob_params_list, cfunc_name, var_name)
        if var_info is None:
            raise ValueError("Parameter '{:s}' is required to compose assembly patch but was not found.".format(var_name))
        if (not inaccurate_size) and (var_info['cfunc_name'] != cfunc_name):
            eprint("Warning: Parameter '{:s}' for function '{:s}' matched from other function '{:s}'.".format(var_name,cfunc_name,var_info['cfunc_name']))

        if (var_info['type'] in (VarType.DIRECT_INT_VALUE, VarType.ABSOLUTE_ADDR_TO_CODE, VarType.ABSOLUTE_ADDR_TO_GLOBAL_DATA, VarType.RELATIVE_OFFSET,)):
            prop_ofs_val = var_info['value']
        elif (var_info['type'] in (VarType.RELATIVE_ADDR_TO_CODE, VarType.RELATIVE_ADDR_TO_PTR_TO_CODE,
                VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA,) and
                var_info['baseaddr'] in ("PC+","PC-",)):
            prop_ofs_val = get_arm_offset_val_relative_to_pc_register(asm_arch, address, instr_size, var_info['value'])
            if var_info['baseaddr'].endswith('-'): prop_ofs_val = -prop_ofs_val
        elif (var_info['type'] in (VarType.DIRECT_OPERAND,)):
            prop_ofs_val = var_info['value']
        else:
            raise NotImplementedError("Unexpected variable type found while preparimg ASM from pattern, '{:s}'.".format(var_info['type'].name))
        if isinstance(prop_ofs_val, int):
            prop_ofs_val = [ prop_ofs_val ]
        elif isinstance(prop_ofs_val, str):
            prop_ofs_val = [ prop_ofs_val ]
        var_value = None
        if isinstance(prop_ofs_val, list):
            var_value_list = []
            for val in prop_ofs_val:
                if isinstance(val, int):
                    if (val >= 0):
                        var_value_list.append("0x{:x}".format(val))
                    else:
                        var_value_list.append("-0x{:x}".format(-val))
                elif isinstance(val, str):
                    var_value_list.append("{:s}".format(val))
            var_value = ', '.join(var_value_list)
        asm_line = re.sub(r'[(][?]P<'+var_name+r'>[^()]*([(][^()]+[)][^()]*)*[)]', var_value, asm_line)
    if variab_size_select == 'long':
        # Make optional square bracket clauses (with '?' after) to no longer be optional
        # They will be matched again later and replaced by first char from inside
        asm_line = re.sub(r'([^\\]\[[^\]]*?[^\\]\])[?]', r'\1', asm_line)
        # Make optional curly bracket clauses (with '?' after) to no longer be optional
        asm_line = re.sub(r'([^\\]\([^\)]*?[^\\]\))[?]', r'\1', asm_line)
        # Make optional single bytes (with '?' after) to no longer be optional
        asm_line = re.sub(r'([^\\\[])[?]', r'\1', asm_line)
    elif variab_size_select == 'short':
        # Remove optional regex square bracket clauses (with '?' after)
        asm_line = re.sub(r'([^\\])\[[^\]]*?[^\\]\][?]', r'\1', asm_line)
        # Remove optional regex curly bracket clauses (with '?' after)
        asm_line = re.sub(r'([^\\])\([^\)]*?[^\\]\)[?]', r'\1', asm_line)
        # Remove optional regex single bytes (with '?' after)
        asm_line = re.sub(r'([^\\\[])[?]', r'', asm_line)
    else:
        # Make optional square bracket clauses (with '?' after) to no longer be optional
        asm_line = re.sub(r'([^\\]\[[^\]]*?[^\\]\])[?]', r'\1', asm_line)
        # Make optional curly bracket clauses (with '?' after) to no longer be optional
        asm_line = re.sub(r'([^\\]\([^\)]*?[^\\]\))[?]', r'\1', asm_line)
        # Make optional single bytes (with '?' after) to no longer be optional
        asm_line = re.sub(r'([^\\\[])[?]', r'\1', asm_line)
    # Remove regex square bracket clauses with single char within brackets
    asm_line = re.sub(r'([^\\])\[([^\\])\]', r'\1\2', asm_line)
    # Replace regex square bracket clauses with multiple chars within brackets with first char
    asm_line = re.sub(r'([^\\])\[(.)[^\]]*?[^\\]\]', r'\1\2', asm_line)
    # Remove escaping from remaining square brackets
    asm_line = re.sub(r'\\([\[\]])', r'\1', asm_line)
    # Replace unnamed curly bracket clauses with alternatives ('|' within brackets) with first choice
    asm_line = re.sub(r'([^\\])\(([^\|\)\?]*)[^\)]*?[^\\]\)', r'\1\2', asm_line)
    return asm_line, instr_size


def prepare_asm_lines_from_pattern_list(asm_arch, glob_params_list, patterns_addr, cfunc_name, pattern_lines):
    """ Given a list of patterns and variables to put inside, produces assembly code.

    Removes regex-specific clauses and replaces named groups with values of variables.
    """
    asm_lines = []
    asm_addr_curr = patterns_addr
    for pat_line in pattern_lines:
        asm_line, code_size = prepare_asm_line_from_pattern(asm_arch, glob_params_list, asm_addr_curr, cfunc_name, pat_line)
        asm_addr_curr += code_size
        asm_lines.append(asm_line)
    return asm_lines, (asm_addr_curr-patterns_addr)


def armfw_elf_value_pre_update_call(po, asm_arch, elf_sections, re_list, glob_params_list, var_info, new_value_str):
    """ Calls update callback of a variable.
    """
    new_var_nativ = armfw_elf_search_value_string_to_native_type(var_info, new_value_str)

    if 'custom_params_callback' in var_info:
        custom_params_update = var_info['custom_params_callback']
        custom_params_update(asm_arch, elf_sections, re_list, glob_params_list, var_info, new_var_nativ)

    # The global variable is named either exactly like property, or is preceded by function name
    glob_var_info = variable_info_from_value_name(glob_params_list, var_info['cfunc_name'], var_info['name'])
    if glob_var_info is None:
        raise ValueError("Lost the variable to set, '{:s}' - internal error.".format(var_info['name']))

    if glob_var_info['type'] in (VarType.DIRECT_INT_VALUE,):
        # The value was taken directly from code - must be converted to int form
        prop_bytes = armfw_elf_search_value_native_type_to_bytes(asm_arch, glob_var_info, new_var_nativ)
        if len(prop_bytes) > 0:
            if glob_var_info['variety'] in (DataVariety.CHAR,):
                new_value = prop_bytes.decode("ISO-8859-1")
            else:
                prop_pad = len(prop_bytes) % 4
                if prop_pad != 0:
                    prop_bytes = prop_bytes + (b"\0" * (4 - prop_pad))
                new_value = int.from_bytes(prop_bytes, byteorder=asm_arch['byteorder'], signed=False)
        else:
            new_value = None
        if new_value is None:
            raise ValueError("Unable to prepare direct int value from provided string value.")
        # Set new value of the global variable and generate the code with it
        glob_var_info['value'] = new_value
    elif glob_var_info['type'] in (VarType.DETACHED_DATA,):
        if 'depend' in glob_var_info:
            # there is no action to take here
            pass
        else:
            # DETACHED_DATA with no dependency should store constant setValue, and that alue is used to select variant of cfunc
            glob_re_var = glob_params_list[glob_var_info['cfunc_name']+'..re']
            # For detached data, we need to find an assembly pattern with matching value, and then patch the asm code to look like it
            patterns_next = find_patterns_containing_variable(re_list, cfunc_ver=glob_var_info['cfunc_ver'], var_name=glob_var_info['name'], var_setValue=str(new_var_nativ))
            if patterns_next is None:
                raise ValueError("Cannot find function modification which would allow to set the value of {:s}={:s}.".format(glob_var_info['name'],str(new_var_nativ)))
            re_lines, re_labels = armfw_asm_search_strings_to_re_list(patterns_next['re'])
            glob_re_var['value'] = re_lines
            #for lab_name, lab_line in re_labels.items(): #TODO - update line numbers in label variables if this will be needed
    else:
        # No pre-update glob_var_info modifications needed for other types
        pass
    # We might have glob_params_list updated now, but pub_params_list has an outdated copy
    if True:
        for fld_name, fld_value in glob_var_info.items():
            if fld_name in ('name',):
                continue
            var_info[fld_name] = fld_value


def get_final_address_from_var_info(asm_arch, elf_sections, var_info):
    if var_info['type'] in (VarType.DIRECT_INT_VALUE, VarType.DIRECT_LINE_OF_CODE, VarType.DIRECT_OPERAND,):
        return var_info['address']
    elif var_info['type'] in (VarType.ABSOLUTE_ADDR_TO_CODE, VarType.RELATIVE_ADDR_TO_CODE,
      VarType.ABSOLUTE_ADDR_TO_GLOBAL_DATA, VarType.RELATIVE_ADDR_TO_GLOBAL_DATA,):
        return var_info['value']
    elif var_info['type'] in (VarType.RELATIVE_ADDR_TO_PTR_TO_CODE, VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA,):
        return var_info['value']
    return None


def armfw_elf_get_value_switching_patterns_update_bytes(po, asm_arch, elf_sections, re_list, glob_params_list, var_info, new_var_nativ):
    """ Finds an assembly pattern with matching value, and then returns a binary patching which makes the asm code to look like it
    """
    patterns_next = find_patterns_containing_variable(re_list, cfunc_ver=var_info['cfunc_ver'], var_name=var_info['name'], var_setValue=str(new_var_nativ))
    patterns_prev = find_patterns_containing_variable(re_list, cfunc_ver=var_info['cfunc_ver'], var_type=var_info['type'], var_name=var_info['name'], var_setValue=var_info['setValue'])
    # Get part of the pattern which is different between the current one and the one we want
    patterns_diff = []
    if patterns_prev != patterns_next:
        patterns_diff, patterns_preced, patterns_diff_prev = find_patterns_diff(patterns_prev, patterns_next)
    valbts = []
    if len(patterns_diff) < 1:
        return valbts
    # From patterns preceding the diff, compute offset where the diff starts
    glob_re_size = glob_params_list[var_info['cfunc_name']+'..re_size']['value']
    # for DETACHED_DATA, 'address' identifies beginning of the whole matched block; add proper amount of instruction sizes to it
    patterns_addr = var_info['address'] + sum(glob_re_size[0:len(patterns_preced)])
    if (po.verbose > 2):
        print("Making code re:","; ".join(patterns_diff))
    var_sect, var_offs = get_section_and_offset_from_address(asm_arch, elf_sections, patterns_addr)
    if var_sect is None:
        raise ValueError("Address to uninitialized data found (0x{:06x}) while updating '{:s}'.".format(patterns_addr, var_info['name']))
    asm_lines, bt_size_predict = prepare_asm_lines_from_pattern_list(asm_arch, glob_params_list, patterns_addr, var_info['cfunc_name'], patterns_diff)
    if len(asm_lines) < 1:
        raise ValueError("No assembly lines prepared - internal error.")
    # Now compile our new code line
    if (po.verbose > 2):
        print("Compiling code:","; ".join(asm_lines))
    bt_enc_data = armfw_asm_compile_lines(asm_arch, patterns_addr, asm_lines)
    if len(bt_enc_data) != bt_size_predict:
        raise ValueError("Compiled code size different than expected (got {:d} instead of {:d} bytes) - internal error.".format(len(bt_enc_data),bt_size_predict))
    bt_size_previous = sum(glob_re_size[len(patterns_preced):len(patterns_preced)+len(patterns_diff_prev)])
    if len(bt_enc_data) != bt_size_previous:
        raise ValueError("Compiled code size different than previous (got {:d} instead of {:d} bytes) - internal error.".format(len(bt_enc_data),bt_size_previous))
    valbt = {}
    valbt['sect'] = var_sect
    section = elf_sections[valbt['sect']]
    valbt['offs'] = var_offs
    valbt['data'] = bt_enc_data
    valbts.append(valbt)
    return valbts


def armfw_elf_get_value_update_bytes(po, asm_arch, elf_sections, re_list, glob_params_list, var_info, par_strvalue_nx):
    valbts = []
    # Get expected length of the value
    prop_size, prop_count = armfw_elf_section_search_get_value_size(asm_arch, var_info)
    new_var_nativ = armfw_elf_search_value_string_to_native_type(var_info, par_strvalue_nx)

    # not calling 'custom_params_callback' here - it should have been called before

    if var_info['type'] in (VarType.DIRECT_INT_VALUE,):
        # We are only changing one line, but use the whole multiline algorithm just for unification
        #TODO make the possibility of multiple lines with one variable
        glob_re = glob_params_list[var_info['cfunc_name']+'..re']['value']
        patterns_list = [glob_re[var_info['line']],]
        if len(patterns_list) > 0:
            glob_re_size = glob_params_list[var_info['cfunc_name']+'..re_size']['value']
            patterns_addr = var_info['address']
            if (po.verbose > 2):
                print("Making code re:","; ".join(patterns_list))
            var_sect, var_offs = get_section_and_offset_from_address(asm_arch, elf_sections, patterns_addr)
            if var_sect is None:
                raise ValueError("Address to uninitialized data found (0x{:06x}) while updating '{:s}'.".format(patterns_addr, var_info['name']))
            asm_lines, bt_size_predict = prepare_asm_lines_from_pattern_list(asm_arch, glob_params_list, patterns_addr, var_info['cfunc_name'], patterns_list)
            # Now compile our new code line
            if (po.verbose > 2):
                print("Compiling code:","; ".join(asm_lines))
            bt_enc_data = armfw_asm_compile_lines(asm_arch, patterns_addr, asm_lines)
            if len(bt_enc_data) != bt_size_predict:
                raise ValueError("Compiled code size different than expected (got {:d} instead of {:d} bytes) - internal error.".format(len(bt_enc_data),bt_size_predict))
            bt_size_previous = glob_re_size[var_info['line']]
            if len(bt_enc_data) != bt_size_previous:
                raise ValueError("Compiled code size different than previous (got {:d} instead of {:d} bytes) - internal error.".format(len(bt_enc_data),bt_size_previous))
            valbt = {}
            valbt['sect'] = var_sect
            section = elf_sections[valbt['sect']]
            valbt['offs'] = var_offs
            valbt['data'] = bt_enc_data
            valbts.append(valbt)
            if (po.verbose > 3):
                print("Offset 0x{:06x} data {:s}".format(valbt['offs'], valbt['data'].hex()))
    elif var_info['type'] in (VarType.ABSOLUTE_ADDR_TO_GLOBAL_DATA, VarType.RELATIVE_ADDR_TO_GLOBAL_DATA,
      VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA,):
        # The value was referenced in code, but stored outside
        bt_enc_data = armfw_elf_search_value_native_type_to_bytes(asm_arch, var_info, new_var_nativ)
        if len(bt_enc_data) < 1:
            raise ValueError("Unable to prepare bytes from provided string value.")

        var_sect, var_offs = get_section_and_offset_from_address(asm_arch, elf_sections, var_info['value']) # for "*_ADDR_*" types, value stores address
        if var_sect is None:
            raise ValueError("Address to uninitialized data found (0x{:06x}) while updating '{:s}'.".format(var_info['value'], var_info['name']))
        valbt = {}
        valbt['sect'] = var_sect
        section = elf_sections[valbt['sect']]
        valbt['offs'] = var_offs
        valbt['data'] = bytes(bt_enc_data)
        valbts.append(valbt)
    elif var_info['type'] in (VarType.DETACHED_DATA,):
        if 'depend' in var_info:
            # DETACHED_DATA which depends on other variables only has relation to code
            # by other variables depending on it; this function should never be called for such veriable
            raise ValueError("Unable to prepare bytes for '{:s}' because it represents detached data with dependants.".format(var_info['name']))
        else:
            # For detached data, we need to find an assembly pattern with matching value, and then patch the asm code to look like it
            valbts += armfw_elf_get_value_switching_patterns_update_bytes(po, asm_arch, elf_sections, re_list, glob_params_list, var_info, new_var_nativ)
    elif var_info['type'] in (VarType.UNUSED_DATA,):
        # No binary change needed in regard to that variable
        pass
    else:
        raise NotImplementedError("Unexpected variable type found while getting update bytes from it, '{:s}'.".format(var_info['type'].name))

    for valbt in valbts:
        section = elf_sections[valbt['sect']]
        if (valbt['offs'] < 0) or (valbt['offs'] + len (valbt['data']) > len(section['data'])):
            raise ValueError("Got past section '{:s}' border - internal error.".format(valbt['sect']))
    return valbts


def armfw_elf_paramvals_extract_list(po, elffh, re_list, asm_submode=None):

    elfobj = ELFFile(elffh)

    asm_arch, asm_modes = elf_march_to_asm_config(elfobj, asm_submode)
    if len(asm_modes) < 1 or not isinstance(asm_modes[0], collections.abc.Mapping):
        raise ValueError("ELF has unsupported machine type ({:s}).".format(elfobj['e_machine']))

    cs_mode = 0
    ks_mode = 0
    retshift = 0
    for mode in asm_modes:
        cs_mode = cs_mode | mode['cs_const']
        ks_mode = ks_mode | mode['ks_const']
        # check for mode specific overrides
        if 'byteorder' in mode:
            asm_arch['byteorder'] = mode['byteorder']
        if 'boundary' in mode:
            asm_arch['boundary'] = mode['boundary']
        if 'retshift' in mode:
            retshift = mode['retshift']
    asm_arch['cs_mode'] = cs_mode
    asm_arch['ks_mode'] = ks_mode

    cs = Cs(asm_arch['cs_const'], asm_arch['cs_mode'])

    # Get sections dictionary, so that we can easily access them by name
    elf_sections = {}
    for i in range(elfobj.num_sections()):
        section = elfobj.get_section(i)

        if section['sh_type'] != "SHT_PROGBITS":
            continue

        if (po.verbose > 2):
            print("{:s}: Found section {:s} at 0x{:06x}".format(po.elffile,section.name,section['sh_addr']))

        elf_sections[section.name] = {
              'index' : i,
              'name' : section.name,
              'addr' : section['sh_addr'],
              'data' : section.data(),
        }

    # Check if expected sections are there
    expect_sections = ['.text', '.data']
    for re_item in re_list:
        if not re_item['sect'] in expect_sections:
            expect_sections.append(re_item['sect'])
    for sect_name in expect_sections:
        if not sect_name in elf_sections:
            raise ValueError("ELF does not contain expected section '{:s}'.".format(sect_name))

    # prepare list of parameter values
    pub_params_list = {}
    glob_params_list = {}
    found_func_list = []
    for re_item in re_list:
        matches = armfw_elf_whole_section_search(po, asm_arch, elf_sections, cs, re_item['sect'], re_item['func'], glob_params_list)
        for i, match in enumerate(matches):
            if i == 0:
                found_func_list.append(re_item['func'])
                func_name = re_item['func']['name']
            else:
                func_name = "{:s}_{:02d}".format(re_item['func']['name'],i)
            pub_params_list.update(armfw_elf_match_to_public_values(po, match))
            glob_params_list.update(armfw_elf_match_to_global_values(po, match, func_name))

    # verify if we've found all the functions we should have founded
    missed_func_list = []
    for re_item in re_list:
        # skip items with name identical to one of these we've found
        if re_item['func']['name'] in [re_func['name'] for re_func in found_func_list]:
            continue
        # skip function variants identified by DETACHED_DATA variable
        detached_var_found = False
        detached_var_name = get_matching_variable_from_patterns(re_item['func'], var_type=VarType.DETACHED_DATA, var_depend=False)
        if detached_var_name is not None:
            for re_func in found_func_list:
                detached_match_name = get_matching_variable_from_patterns(re_func, var_type=VarType.DETACHED_DATA, var_name=detached_var_name)
                if detached_match_name is not None:
                    detached_var_found = True
                    break
        if detached_var_found:
            continue
        # skip items which have 'alt_name' pointing to a function we've found
        alt_name_found = False
        if 'alt_name' in re_item['func']:
            for re_alt_name in re_item['func']['alt_name'].split(','):
                for re_func in found_func_list:
                    if re.fullmatch(re_alt_name, re_func['name']):
                        alt_name_found = True
                        break
                if alt_name_found:
                    break
        if alt_name_found:
            continue
        # add only one variant of each function
        if re_item['func']['name'] in [re_func['name'] for re_func in missed_func_list]:
            continue
        missed_func_list.append(re_item['func'])
    for re_func in missed_func_list:
        print("{:s}: Warning: No variant of function '{:s}' was found".format(po.elffile,re_func['name']))
    if len(missed_func_list) > 0:
        print("{:s}: Warning: From expacted functions, {:d} were not found".format(po.elffile,len(missed_func_list)))
    else:
        print("{:s}: All expected functions were found".format(po.elffile))

    return pub_params_list, glob_params_list, elf_sections, cs, elfobj, asm_arch


def armfw_elf_paramvals_export_simple_list(po, params_list, valfile):
    valfile.write("{:s}\t{:s}\n".format("Name","Value"))
    for par_name, par_info in params_list.items():
        valfile.write("{:s}\t{:s}\n".format(par_name,par_info['str_value']))
    if (po.verbose > 0):
        print("{:s}: Listed {:d} hardcoded values".format(po.elffile,len(params_list)))

def armfw_elf_ambavals_list(po, elffh):
    params_list, _, _, _, _, _ = armfw_elf_paramvals_extract_list(po, elffh, re_general_list)
    # print list of parameter values
    armfw_elf_paramvals_export_simple_list(po, params_list, sys.stdout)


def armfw_elf_paramvals_export_mapfile(po, params_list, elf_sections, asm_arch, valfile):
    valfile.write("  {:s}         {:s}\n".format("Address","Publics by Value"))
    symbols_num = 0
    for par_name, par_info in params_list.items():
        if not value_type_is_known_address(par_info):
            continue
        if par_info['variety'] in (CodeVariety.CHUNK,):
            continue
        var_sect, var_offs = get_section_and_offset_from_address(asm_arch, elf_sections, par_info['value'])
        if var_sect is None:
            eprint("{:s}: Cannot retrieve offset for symbol '{:s}' at 0x{:08x}".format(po.elffile,par_name,par_info['value']))
            continue
        var_sect_index = elf_sections[var_sect]['index']
        valfile.write(" {:04X}:{:08X}       {:s}\n".format(var_sect_index,var_offs,par_info['name']))
        symbols_num += 1
    if (po.verbose > 0):
        print("{:s}: Map contains {:d} symbols".format(po.elffile,symbols_num))

def armfw_elf_ambavals_mapfile(po, elffh):
    _, params_list, elf_sections, _, _, asm_arch = armfw_elf_paramvals_extract_list(po, elffh, re_general_list)
    armfw_elf_paramvals_export_mapfile(po, params_list, elf_sections, asm_arch, sys.stdout)


def armfw_elf_paramvals_export_json(po, params_list, valfile):
    valfile.write("[\n")
    full_index = 0
    for par_name, par_info in params_list.items():
        if (full_index != 0):
            valfile.write(",\n")
        valfile.write("\t{\n")
        for ppname in ('index',):
            valfile.write("\t\t\"{:s}\" : {:d}".format(ppname,full_index))
        for ppname in ('description',):
            valfile.write(",\n")
            valfile.write("\t\t\"{:s}\" : \"{:s}\"".format(ppname,par_info[ppname]))
        for ppname in ('hint1','hint2','hint3','hint4','hint5'):
            if not ppname in par_info: continue
            valfile.write(",\n")
            valfile.write("\t\t\"{:s}\" : \"{:s}\"".format(ppname,par_info[ppname]))
        for ppname in ('minValue', 'maxValue', 'defaultValue'):
            if not ppname in par_info: continue
            valfile.write(",\n")
            if re.fullmatch(r"^(0[Xx][0-9a-fA-F]+|[0-9-]+|[0-9-]*[.][0-9]+)$", par_info['str_value']):
                valfile.write("\t\t\"{:s}\" : {:s}".format(ppname,par_info[ppname]))
            else:
                valfile.write("\t\t\"{:s}\" : \"{:s}\"".format(ppname,par_info[ppname]))
        for ppname in ('setValue',):
            valfile.write(",\n")
            if re.fullmatch(r"^(0[Xx][0-9a-fA-F]+|[0-9-]+|[0-9-]*[.][0-9]+)$", par_info['str_value']):
                valfile.write("\t\t\"{:s}\" : {:s}".format(ppname,par_info['str_value']))
            else:
                valfile.write("\t\t\"{:s}\" : \"{:s}\"".format(ppname,par_info['str_value']))
        for ppname in ('name',):
            valfile.write(",\n")
            valfile.write("\t\t\"{:s}\" : \"{:s}\"".format(ppname,par_name))
        valfile.write("\n")
        valfile.write("\t}")
        full_index += 1
    valfile.write("\n")
    valfile.write("]\n")
    if (po.verbose > 0):
        print("{:s}: Extracted {:d} hardcoded values".format(po.elffile,len(params_list)))

def armfw_elf_ambavals_extract(po, elffh):
    """ Extracts all values from firmware to JSON format text file.
    """
    params_list, _, _, _, _, _ = armfw_elf_paramvals_extract_list(po, elffh, re_general_list)
    if len(params_list) <= 0:
        raise ValueError("No known values found in ELF file.")
    if not po.dry_run:
        valfile = open(po.valfile, "w")
    else:
        valfile = io.StringIO()
    armfw_elf_paramvals_export_json(po, params_list, valfile)
    valfile.close()


def armfw_elf_paramvals_get_depend_value(glob_params_list, deppar_info):
    par_strvalue_nx = None
    for var_name_iter, var_info_iter in glob_params_list.items():
        if deppar_info['depend'] != var_name_iter:
            continue
        if deppar_info['public'] != var_info_iter['public']:
            continue
        par_strvalue_nx = var_info_iter['str_value']
        break
    if par_strvalue_nx is None:
        return None
    if 'getter' not in deppar_info:
        return None
    get_value_from_depend_value = deppar_info['getter']
    return get_value_from_depend_value(par_strvalue_nx)


def armfw_elf_paramvals_get_depend_list(glob_params_list, par_info, par_strvalue_nx):
    """ Gets a list of depending values which should be updated if specific public param changed value.

    Emulates the list format we get from JSON, so that the same update functions can be used as for
    the parent public parameter.
    """
    depend_list = []
    for var_name_iter, var_info_iter in glob_params_list.items():
        if 'depend' not in var_info_iter:
            continue
        if var_info_iter['depend'] != par_info['name']:
            continue
        if var_info_iter['public'] != par_info['public']:
            continue
        #deppar_name = var_info_iter['public']+'.'+var_name_iter
        deppar_info = var_info_iter.copy()
        #deppar_info['name'] = deppar_name
        if 'getter' in deppar_info:
            get_value_from_depend_value = deppar_info['getter']
            deppar_info['setValue'] = get_value_from_depend_value(par_strvalue_nx)
        if 'setValue' not in deppar_info:
            raise ValueError("No 'setValue' and no 'getter' in '{:s}'.".format(deppar_info['name']))
        depend_list.append(deppar_info)
    return depend_list


def armfw_elf_publicval_update(po, asm_arch, elf_sections, re_list, glob_params_list, par_info, par_strvalue_nx):
    """ Updates given hardcoded value in ELF section data.
    """
    if par_info['type'] in (VarType.DETACHED_DATA,) and 'depend' in par_info:
        # Special case - a variable which has no directly associated data, only updates binary data by dependants
        return True
    valbts = armfw_elf_get_value_update_bytes(po, asm_arch, elf_sections, re_list, glob_params_list, par_info, par_strvalue_nx)
    update_performed = False
    for valbt in valbts:
        section = elf_sections[valbt['sect']]
        old_beg = valbt['offs']
        old_end = valbt['offs']+len(valbt['data'])
        old_data = section['data'][old_beg:old_end]
        if valbt['data'] != old_data:
            update_performed = True
            if (po.verbose > 1):
                print("At 0x{:06x}, replacing {:s} -> {:s} to set {:s}".format(section['addr']+old_beg,old_data.hex(),valbt['data'].hex(),par_info['name']))
            sect_data = section['data']
            sect_data[old_beg:old_end] = valbt['data']
    return update_performed


def armfw_elf_paramvals_update_list(po, asm_arch, re_list, pub_params_list, glob_params_list, elf_sections, nxparams_list):
    update_list_a = [] # Params which others use ag 'getters' should be updated first
    update_list_b = [] # Most parameters are updated as part of this list
    update_list_c = [] # Some parameters have multiline changes and should be updated at end

    # Get names of all variables which other depend on
    depend_names_list = []
    for par_info in glob_params_list:
        if 'depend' in par_info:
            if 'public' in par_info:
                depend_names_list.append(par_info['public']+'.'+par_info['depend'])
            else:
                depend_names_list.append(par_info['depend'])

    for nxpar in nxparams_list:
        if not nxpar['name'] in pub_params_list:
            eprint("{:s}: Value '{:s}' not found in ELF file.".format(po.elffile,nxpar['name']))
            continue
        par_info = pub_params_list[nxpar['name']]
        if par_info['name'] in depend_names_list:
            update_list_a.append(nxpar)
        elif par_info['type'] in (VarType.DETACHED_DATA,):
            update_list_c.append(nxpar)
        else:
            update_list_b.append(nxpar)

    for nxpar in update_list_a + update_list_b + update_list_c:
        par_info = pub_params_list[nxpar['name']]
        armfw_elf_value_pre_update_call(po, asm_arch, elf_sections, re_list, glob_params_list, par_info, nxpar['setValue'])
        if True:
            depparams_list = armfw_elf_paramvals_get_depend_list(glob_params_list, par_info, nxpar['setValue'])
            for deppar in depparams_list:
                armfw_elf_value_pre_update_call(po, asm_arch, elf_sections, re_list, glob_params_list, deppar, deppar['setValue'])

    update_count = 0
    # Update the params from priority lists
    for nxpar in update_list_a + update_list_b + update_list_c:
        par_info = pub_params_list[nxpar['name']]
        update_performed = armfw_elf_publicval_update(po, asm_arch, elf_sections, re_list, glob_params_list, par_info, nxpar['setValue'])
        if update_performed:
            depparams_list = armfw_elf_paramvals_get_depend_list(glob_params_list, par_info, nxpar['setValue'])
            for deppar in depparams_list:
                update_performed = armfw_elf_publicval_update(po, asm_arch, elf_sections, re_list, glob_params_list, deppar, deppar['setValue'])
            update_count += 1

    return update_count


def armfw_elf_ambavals_update(po, elffh):
    """ Updates all hardcoded values in firmware from JSON format text file.
    """
    pub_params_list, glob_params_list, elf_sections, cs, elfobj, asm_arch = armfw_elf_paramvals_extract_list(po, elffh, re_general_list)
    if len(pub_params_list) <= 0:
        raise ValueError("No known values found in ELF file.")
    with open(po.valfile) as valfile:
        nxparams_list = json.load(valfile)
    # Change section data buffers to bytearrays, so we can change them easily
    for section_name, section in elf_sections.items():
        section['data'] = bytearray(section['data'])
    update_count = armfw_elf_paramvals_update_list(po, asm_arch, re_general_list, pub_params_list, glob_params_list, elf_sections, nxparams_list)
    if (po.verbose > 0):
        print("{:s}: Updated {:d} out of {:d} hardcoded values".format(po.elffile,update_count,len(pub_params_list)))
    # Now update the ELF file
    for section_name, section in elf_sections.items():
        elfsect = elfobj.get_section_by_name(section_name)
        elfsect.set_data(section['data'])
        elfobj.set_section_by_name(section_name, elfsect)
    if not po.dry_run:
        elfobj.write_changes()


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

    subparser.add_argument("--mapfile", action="store_true",
          help="export known symbols to map file")

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

        armfw_elf_generic_objdump(po, elffh)

        elffh.close();

    elif po.list:

        if (po.verbose > 0):
            print("{}: Opening for list".format(po.elffile))

        elffh = open(po.elffile, "rb")

        armfw_elf_ambavals_list(po, elffh)

        elffh.close();

    elif po.mapfile:

        if (po.verbose > 0):
            print("{}: Opening for mapfile generation".format(po.elffile))

        elffh = open(po.elffile, "rb")

        armfw_elf_ambavals_mapfile(po, elffh)

        elffh.close();

    elif po.extract:

        if (po.verbose > 0):
            print("{}: Opening for extract".format(po.elffile))

        elffh = open(po.elffile, "rb")

        armfw_elf_ambavals_extract(po, elffh)

        elffh.close();

    elif po.update:

        if (po.verbose > 0):
            print("{}: Opening for update".format(po.elffile))

        elffh = open(po.elffile, "r+b")

        armfw_elf_ambavals_update(po, elffh)

        elffh.close();

    else:

        raise NotImplementedError("Unsupported command.")

if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        eprint("Error: "+str(ex))
        #raise
        sys.exit(10)
