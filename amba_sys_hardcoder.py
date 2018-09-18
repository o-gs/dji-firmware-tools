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
__version__ = "0.0.1"
__author__ = "Mefistotelis @ Original Gangsters"
__license__ = "GPL"

import sys
import argparse
import os
import re
import io
import collections.abc
import itertools
import enum
import json

from ctypes import *
from capstone import *
from keystone import *
sys.path.insert(0, '../pyelftools')
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SH_FLAGS

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

class VarType(enum.Enum):
    # Variable points to code line from asm regular expression
    DIRECT_LINE_OF_CODE = enum.auto()
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
    # Variable contains relative address to a global variable which contains absolute address to the real value
    RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA = enum.auto()
    # Variable contains data not directly bound to any input offset
    DETACHED_DATA = enum.auto()

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
're': """
  ldr	r0, \[pc, #(?P<msg_author_level>[0-9a-fx]+)\]
  ldr	r0, \[r0\]
  bx	lr
""",
'vars': {
  'DjiMsgAuthorLevelGet':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION, 'line': 0},
  'msg_author_level': {'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.UINT32_T},
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
  'DjiMsgSettingsInit':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION, 'line': 0},
  'AmbaKAL_MutexCreate':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'AmbaPrintk_Disabled':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'AmbaPrintk':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'DjiMsgAuthorLevelSet':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'DjiEncryptGetA9Status':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'memset_0':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'cstr_fmt_text1':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_func_name':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'dji_msg_mutex':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.STRUCT, 'struct': DummyStruct,},
  'msg_adjust_task_finished':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.UINT32_T},
  'printk_log_level':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.UINT32_T},
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

class AmbaP3XBitrateTableEntry(LittleEndianStructure):
  _pack_ = 1
  _fields_ = [('min', c_int),
              ('avg', c_int),
              ('max', c_int)]

re_func_DjiUstVideoQualitySetInner = {
'name': "DjiUstVideoQualitySetInner",
're': """
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
  add	r0, r2, r2, lsl #1
  ldr	r1, \[pc, #(?P<vid_setting_bitrates>[0-9a-fx]+)\]
  ldr	r0, \[r1, r0, lsl #2\]
  cmp	r0, #0
  beq	#(?P<loc_label05>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<unk_var01>[0-9a-fx]+)\]
  ldrsb	r1, \[r1, #0x12\]
  mov	r2, #0x54
  ldr	r3, \[pc, #(?P<vid_settings_ust>[0-9a-fx]+)\]
  smlabb	r1, r1, r2, r3
  str	r0, \[r1, #8\]
  mov	r0, #0
  add	sp, sp, #0x14
  pop	{r4, r5, pc}
  add	r0, r2, r2, lsl #1
  ldr	r1, \[pc, #(?P<vid_setting_bitrates>[0-9a-fx]+)\]
  adds	r0, r1, r0, lsl #2
  ldr	r0, \[r0, #4\]
  b	#(?P<loc_label06>[0-9a-fx]+)
  add	r0, r2, r2, lsl #1
  ldr	r1, \[pc, #(?P<vid_setting_bitrates>[0-9a-fx]+)\]
  adds	r0, r1, r0, lsl #2
  ldr	r0, \[r0, #8\]
  b	#(?P<loc_label06>[0-9a-fx]+)
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
  mvn	r0, #0
  b	#(?P<loc_label08>[0-9a-fx]+)
""",
'vars': {
  'DjiUstVideoQualitySetInner':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION, 'line': 0},
  'cstr_fmt_text1':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_func_name':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
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
  'unk_var01':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'vid_settings_ust':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.STRUCT, 'struct': DummyStruct,},
  'vid_setting_bitrates':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.STRUCT, 'array': 27,
    'struct': AmbaP3XBitrateTableEntry,
    'public': "og_hardcoded.p3x_ambarella", 'minValue': "1000000 1000000 1000000", 'maxValue': "64000000 64000000 64000000",
    'description': "Bitrates used for h.264 video compression; 3 values: min, avg, max"},
  'printk_log_level':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.UINT32_T},
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


def elf_march_to_asm_config(elfobj):
    """ Retrieves machine architecture for given elf.

    Returns config for capstone and keystone.
    """
    march = elfobj.get_machine_arch()
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
        if elfobj.little_endian:
            asm_mode = get_asm_mode_by_name(asm_arch, "le")
        else:
            asm_mode = get_asm_mode_by_name(asm_arch, "be")
    elif march == "MIPS":
        asm_arch = get_asm_arch_by_name("mips")
        asm_mode = get_asm_mode_by_name(asm_arch, "32b")
        if elfobj.little_endian:
            asm_mode = get_asm_mode_by_name(asm_arch, "le")
        else:
            asm_mode = get_asm_mode_by_name(asm_arch, "be")
    return (asm_arch, [asm_mode])


def get_arm_vma_relative_to_pc_register(asm_arch, section, address, size, offset_str):
    """ Gets Virtual Memory Address associated with offet given within an asm instruction.

    ARMs have a way of storing relative offsets which may be confusing at first.
    """
    vma = address + size + asm_arch['boundary'] + int(offset_str, 0)
    return vma - (vma % asm_arch['boundary'])


def get_arm_offset_val_relative_to_pc_register(asm_arch, elf_sections, address, size, vma):
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


def armfw_elf_ambavals_objdump(po, elffh):
    """ Dump executable in similar manner to objdump disassemble function.
    """
    elfobj = ELFFile(elffh)

    asm_arch, asm_modes = elf_march_to_asm_config(elfobj)
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

def armfw_asm_search_string_to_re(re_patterns):
    # Divide to lines
    re_lines = re_patterns.split(sep="\n")
    # Remove comments
    re_lines = [s.split(";",1)[0]  if ";" in s else s for s in re_lines]
    # Remove labels
    for i, s in enumerate(re_lines):
        re_label = re.search(r'^([a-zA-Z0-9_]*):(.*)$', s)
        if re_label is not None:
            re_lines[i] = re_label.group(2)
    # Strip whitespaces
    re_lines = list(map(str.strip, re_lines))
    # Remove empty lines
    return list(filter(None, re_lines))

def armfw_elf_section_search_init(asm_arch, section, patterns):
    """ Initialize search data.
    """
    search = {}
    search['asm_arch'] = asm_arch
    search['section'] = section
    search['name'] = patterns['name']
    search['re'] = armfw_asm_search_string_to_re(patterns['re'])
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


def armfw_elf_section_search_get_value_variety_size(var_variety):
    """ Get expected size of the value
    """
    if var_variety in [DataVariety.CHAR, DataVariety.UINT8_T, DataVariety.INT8_T]:
        var_size = 1
    elif var_variety in [DataVariety.UINT16_T, DataVariety.INT16_T]:
        var_size = 2
    elif var_variety in [DataVariety.UINT32_T, DataVariety.INT32_T, DataVariety.FLOAT]:
        var_size = 4
    elif var_variety in [DataVariety.UINT64_T, DataVariety.INT64_T, DataVariety.DOUBLE]:
        var_size = 8
    else:
        var_size = 0
    return var_size


def armfw_elf_section_search_get_value_size(asm_arch, var_info):
    """ Get expected item size size and count of the value
    """
    if var_info['variety'] in [DataVariety.STRUCT]:
        var_size = sizeof(var_info['struct'])
    else:
        var_size = armfw_elf_section_search_get_value_variety_size(var_info['variety'])

    if 'array' in var_info:
        if isinstance(var_info['array'], int):
            var_count = var_info['array']
        else:
            # We have variable size array; just use static limit
            var_count = 2048
    else:
        var_count = 1
    return var_size, var_count


def armfw_elf_compute_code_length(asm_arch, patterns):
    # TODO - make support of variable instruction size architactures
    return len(patterns)*asm_arch['boundary']

def armfw_elf_search_value_bytes_to_native_type(asm_arch, var_info, var_bytes):
    """ Converts bytes to a variable described in info struct and architecture.
    """
    # Get expected length of the value
    var_size, var_count = armfw_elf_section_search_get_value_size(asm_arch, var_info)
    if var_info['variety'] in [DataVariety.CHAR]:
        # Native type is str
        if 'array' in var_info:
            var_nativ = [ var_bytes.rstrip(b"\0").decode("ISO-8859-1") ]
        else:
            var_nativ = [ var_bytes.decode("ISO-8859-1") ]
    elif var_info['variety'] in [DataVariety.UINT8_T, DataVariety.UINT16_T, DataVariety.UINT32_T, DataVariety.UINT64_T]:
        var_nativ = []
        for i in range(len(var_bytes) // var_size):
            var_nativ.append(int.from_bytes(var_bytes[i*var_size:(i+1)*var_size], byteorder=asm_arch['byteorder'], signed=False))
    elif var_info['variety'] in [DataVariety.INT8_T, DataVariety.INT16_T, DataVariety.INT32_T, DataVariety.INT64_T]:
        var_nativ = []
        for i in range(len(var_bytes) // var_size):
            var_nativ.append(int.from_bytes(var_bytes[i*var_size:(i+1)*var_size], byteorder=asm_arch['byteorder'], signed=True))
    elif var_info['variety'] in [DataVariety.FLOAT, DataVariety.DOUBLE]:
        var_nativ = []
        for i in range(len(var_bytes) // var_size):
            if var_size >= 8:
                var_nativ.append(struct.unpack("<d",var_bytes[i*var_size:(i+1)*var_size]))
            else:
                var_nativ.append(struct.unpack("<f",var_bytes[i*var_size:(i+1)*var_size]))
    elif var_info['variety'] in [DataVariety.STRUCT]:
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
    """
    Converts string value to native type.
    Native type can be str, int, float, struct or array of int or float.
    """
    if var_info['variety'] in [DataVariety.CHAR]:
        var_nativ = str(var_str)
    elif var_info['variety'] in [DataVariety.UINT8_T, DataVariety.UINT16_T, DataVariety.UINT32_T, DataVariety.UINT64_T, DataVariety.INT8_T, DataVariety.INT16_T, DataVariety.INT32_T, DataVariety.INT64_T]:
        if isinstance(var_str, int):
            # If we already got an int - no processing required (this happens if JSON value is not in quotes)
            var_nativ = var_str
        else:
            var_nativ = []
            for val_itm in var_str.split():
                var_nativ.append(int(val_itm,0))
            if len(var_nativ) == 1:
                var_nativ = var_nativ[0]
    elif var_info['variety'] in [DataVariety.FLOAT, DataVariety.DOUBLE]:
        if isinstance(var_str, float):
            # If we already got a float - no processing required
            var_nativ = var_str
        else:
            var_nativ = []
            for val_itm in var_str.split():
                var_nativ.append(float(val_itm,0))
            if len(var_nativ) == 1:
                var_nativ = var_nativ[0]
    elif var_info['variety'] in [DataVariety.STRUCT]:
        var_nativ = var_info['struct']()
        for field, valstr in zip(var_nativ._fields_,var_str.split()):
            # currently we only accept int values within struct
            setattr(var_nativ, field[0], int(valstr,0))
    else:
        var_nativ = None
    return var_nativ


def find_patterns_containing_variable(re_list, var_type=None, var_variety=None, var_sect=None, var_name=None, var_size=None, var_setValue=None):
    for re_item in re_list:
        if var_sect is not None and re_item['sect'] != var_sect:
            continue
        patterns = re_item['func']
        for v_name, var_info in patterns['vars'].items():
            if var_type is not None and var_info['type'] != var_type:
                continue
            if var_variety is not None and var_info['variety'] != var_variety:
                continue
            if var_name is not None and v_name != var_name:
                continue
            if var_size is not None and var_info['size'] != var_size:
                continue
            if var_setValue is not None and var_info['setValue'] != var_setValue:
                continue
            return patterns
    return None


def find_patterns_diff(patterns_prev, patterns_next):
    re_lines_prev = armfw_asm_search_string_to_re(patterns_prev['re'])
    re_lines_next = armfw_asm_search_string_to_re(patterns_next['re'])
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
    for i in range(sn, en+1):
        line_n = re_lines_next[i]
        patterns_diff.append(line_n)
    return patterns_diff, re_lines_prev[0:sp]


def armfw_asm_is_data_definition(asm_arch, asm_line):
    """ Recognizes data definition assembly line, without touching data.

    The fat that it doesn 't interpret data means it will work for regex too.
    """
    re_isdata = re.search(r'^dc([bwdq])\t(.*)$', asm_line)
    if re_isdata is None:
        return None
    elif re_isdata.group(1) == 'b':
        single_len = 1
    elif re_isdata.group(1) == 'w':
        single_len = 2
    elif re_isdata.group(1) == 'd':
        single_len = 4
    elif re_isdata.group(1) == 'q':
        single_len = 8
    return single_len

def armfw_asm_parse_data_definition(asm_arch, asm_line):
    """ Recognizes data definition assembly line, returns data as bytes.
    """
    re_isdata = re.search(r'^dc([bwdq])\t(.*)$', asm_line)
    dt_bytes = b''
    if re_isdata is None:
        return None
    elif re_isdata.group(1) == 'b':
        dt_variety = DataVariety.UINT8_T
        single_len = 1
    elif re_isdata.group(1) == 'w':
        dt_variety = DataVariety.UINT16_T
        single_len = 2
    elif re_isdata.group(1) == 'd':
        dt_variety = DataVariety.UINT32_T
        single_len = 4
    elif re_isdata.group(1) == 'q':
        dt_variety = DataVariety.UINT64_T
        single_len = 8

    for dt_item in re_isdata.group(2).split(","):
        dt_bytes += int(dt_item.strip(), 0).to_bytes(single_len, byteorder=asm_arch['byteorder'])
    return {'variety': dt_variety, 'value': dt_bytes }


def armfw_elf_section_search_add_var(search, var_name, var_suffix, var_info, prop_ofs_val, prop_str, address, size):
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
            return False
    else:
        var_def = search['var_defs'][var_name]
        var_val = {'str_value': prop_str, 'value': prop_ofs_val, 'address': address, 'instr_size': size, 're_line': search['match_lines'], 'cfunc_name': search['name']}
        var_val.update(var_def)
        # For direct values, also store the regex matched to the line
        if (var_info['type'] == VarType.DIRECT_INT_VALUE):
            var_val['re_line_str'] = armfw_elf_section_search_get_pattern(search)
        search['var_vals'][var_name+var_suffix] = var_val
    return True


def armfw_elf_section_search_process_vars_from_code(search, elf_sections, address, size, re_code):
    """ Process variable values from a code line and add them to search results.
    """
    for var_name, var_val in re_code.groupdict().items():
        var_info = search['var_defs'][var_name]
        # Get direct int value or offset to value
        if (var_info['type'] == VarType.DIRECT_INT_VALUE):
            prop_ofs_val = int(var_val, 0)
        elif (var_info['type'] == VarType.ABSOLUTE_ADDR_TO_CODE):
            prop_ofs_val = int(var_val, 0)
        elif (var_info['type'] == VarType.ABSOLUTE_ADDR_TO_GLOBAL_DATA):
            prop_ofs_val = int(var_val, 0)
        elif (var_info['type'] == VarType.RELATIVE_PC_ADDR_TO_CODE):
            prop_ofs_val = get_arm_vma_relative_to_pc_register(search['asm_arch'], search['section'], address, size, var_val)
        elif (var_info['type'] == VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA):
            prop_ofs_val = get_arm_vma_relative_to_pc_register(search['asm_arch'], search['section'], address, size, var_val)
        elif (var_info['type'] == VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA):
            prop_ofs_val = get_arm_vma_relative_to_pc_register(search['asm_arch'], search['section'], address, size, var_val)
            var_sect, var_offs = get_section_and_offset_from_address(search['asm_arch'], elf_sections, prop_ofs_val)
            if var_sect is not None:
                var_data = elf_sections[var_sect]['data']
                prop_ofs_val = int.from_bytes(var_data[var_offs:var_offs+4], byteorder=search['asm_arch']['byteorder'], signed=False)
            else:
                raise ValueError("Address to uninitialized data found.")
        else:
            raise NotImplementedError("Unexpected variable type found.")

        # Get expected length of the value
        prop_size, prop_count = armfw_elf_section_search_get_value_size(search['asm_arch'], var_info)

        # Either convert the direct value to bytes, or get bytes from offset
        if (var_info['type'] == VarType.DIRECT_INT_VALUE):
            prop_bytes = (prop_ofs_val).to_bytes(prop_size*prop_count, byteorder=search['asm_arch']['byteorder'])
        elif ((var_info['type'] == VarType.ABSOLUTE_ADDR_TO_GLOBAL_DATA) or (var_info['type'] == VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA)
          or (var_info['type'] == VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA)):
            var_sect, var_offs = get_section_and_offset_from_address(search['asm_arch'], elf_sections, prop_ofs_val)
            if var_sect is not None:
                var_data = elf_sections[var_sect]['data']
                prop_bytes = var_data[var_offs:var_offs+prop_size*prop_count]
            else:
                prop_bytes = b""
        else:
            prop_bytes = b""

        var_nativ = armfw_elf_search_value_bytes_to_native_type(search['asm_arch'], var_info, prop_bytes)
        prop_str = armfw_elf_search_value_native_type_to_string(var_nativ)
        if isinstance(prop_str, str):
            if not armfw_elf_section_search_add_var(search, var_name, "", var_info, prop_ofs_val, prop_str, address, size):
                return False
        else: # array of strings
            for i in range(len(prop_str)):
                prop_sstr = prop_str[i]
                if not armfw_elf_section_search_add_var(search, var_name, "_{:02d}".format(i), var_info, prop_ofs_val + i*prop_size, prop_sstr, address, size):
                    return False

    # Now get variables associated to line of code, not anything within the code
    for var_name, var_info in search['var_defs'].items():
        # Add variables attached to code line (usually function name)
        if var_info['type'] in [VarType.DIRECT_LINE_OF_CODE] and search['match_lines'] == var_info['line']:
            # Get expected length of the value
            prop_size, prop_count = armfw_elf_section_search_get_value_size(search['asm_arch'], var_info)
            prop_ofs_val = address
            prop_str = ""
            if not armfw_elf_section_search_add_var(search, var_name, "", var_info, prop_ofs_val, prop_str, address, size):
                return False
        # Add variables detached from data (per-regex constants)
        if var_info['type'] in [VarType.DETACHED_DATA] and search['match_lines'] == 0:
            # Get expected length of the value
            prop_size, prop_count = armfw_elf_section_search_get_value_size(search['asm_arch'], var_info)
            prop_ofs_val = 0
            prop_str = var_info['setValue']
            if not armfw_elf_section_search_add_var(search, var_name, "", var_info, prop_ofs_val, prop_str, address, size):
                return False

    return True


def armfw_elf_section_search_block(search, sect_offs, elf_sections, cs, block_len):
    """ Search for pattern in a block of ELF file section.
        The function will try to save state and stop somewhere around given block_len.
    """
    sect_limit = len(search['section']['data'])
    if (sect_limit > sect_offs + block_len):
        sect_limit = sect_offs + block_len
    while sect_offs < sect_limit:
        curr_pattern = armfw_elf_section_search_get_pattern(search)
        curr_is_data = armfw_asm_is_data_definition(search['asm_arch'], curr_pattern)
        if curr_is_data is not None:
            # now matching a data line; get its length
            raise NotImplementedError("TODO data '{:s}'".format(curr_pattern))
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
                    curr_is_data = armfw_asm_is_data_definition(search['asm_arch'], curr_pattern)
                    if curr_is_data is not None: break
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
                    curr_is_data = armfw_asm_is_data_definition(search['asm_arch'], curr_pattern)
                    if curr_is_data is not None: break
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
            par_info = var_info.copy()
            par_info['name'] = var_name
            params_list[par_name] = par_info
    return params_list


def armfw_elf_match_to_global_values(po, match, cfunc_name):
    params_list = {}
    for var_name, var_info in match['vars'].items():
        if (var_info['type'] in [VarType.ABSOLUTE_ADDR_TO_GLOBAL_DATA, VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, VarType.DETACHED_DATA] or
          var_info['variety'] in [CodeVariety.FUNCTION]) and var_info['variety'] not in [DataVariety.UNKNOWN]:
            par_info = var_info.copy()
            var_full_name = var_name
        else:
            par_info = var_info.copy()
            var_full_name = cfunc_name+"."+var_name
        par_info['name'] = var_full_name
        params_list[var_full_name] = par_info
    return params_list


def prepare_asm_line_from_pattern(asm_arch, elf_sections, glob_params_list, address, cfunc_name, pat_line):
    # List regex parameters used in that line
    vars_used = re.findall(r'[(][?]P<([^>]+)>[^)]+[)]', pat_line)
    #TODO would be better to have instruction size from the assembly, ie. by replacing all vars in regex by arbitrary value
    instr_size = asm_arch['boundary']
    # Replace parameters with their values
    asm_line = pat_line
    for var_name in vars_used:
        var_info = None
        if var_name in glob_params_list:
            var_info = glob_params_list[var_name]
        elif cfunc_name+"."+var_name in glob_params_list:
            var_info = glob_params_list[cfunc_name+"."+var_name]
        else:
            for var_name_iter, var_info_iter in glob_params_list.items():
                if var_name_iter.endswith("."+var_name):
                    var_info = var_info_iter
                    eprint("Warning: Parameter '{:s}' for function '{:s}' matched from other function '{:s}'.".format(var_name,cfunc_name,var_info['cfunc_name']))
                    break
        if var_info is None:
            raise ValueError("Parameter '{:s}' is required to compose assembly patch but was not found.".format(var_name))
        if (var_info['type'] in [VarType.DIRECT_INT_VALUE, VarType.ABSOLUTE_ADDR_TO_CODE, VarType.ABSOLUTE_ADDR_TO_GLOBAL_DATA]):
            prop_ofs_val = var_info['value']
        elif (var_info['type'] in [VarType.RELATIVE_PC_ADDR_TO_CODE, VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA]):
            prop_ofs_val = get_arm_offset_val_relative_to_pc_register(asm_arch, elf_sections, address, instr_size, var_info['value'])
        else:
            raise NotImplementedError("Unexpected variable type found.")

        var_value = "0x{:x}".format(prop_ofs_val)
        asm_line = re.sub(r'[(][?]P<'+var_name+r'>[^)]+[)]', var_value, asm_line)
    # Remove regex square bracket clauses
    asm_line = re.sub(r'[^\\]\[(.*)[^\\]\]', r'\1', asm_line)
    # Remove escaping from remaining square brackets
    asm_line = re.sub(r'\\([\[\]])', r'\1', asm_line)
    return asm_line, instr_size

def armfw_elf_get_value_update_bytes(po, asm_arch, elf_sections, re_list, glob_params_list, var_info, new_value_str):
    valbts = []
    # Get expected length of the value
    prop_size, prop_count = armfw_elf_section_search_get_value_size(asm_arch, var_info)
    new_var_nativ = armfw_elf_search_value_string_to_native_type(var_info, new_value_str)

    if 'custom_params_callback' in var_info:
        custom_params_update = var_info['custom_params_callback']
        custom_params_update(asm_arch, elf_sections, re_list, glob_params_list, var_info, new_var_nativ)

    if (var_info['type'] in [VarType.DIRECT_INT_VALUE]):
        # The value was taken directly from code - must be converted to int form
        prop_bytes = armfw_elf_search_value_native_type_to_bytes(asm_arch, var_info, new_var_nativ)
        if len(prop_bytes) > 0:
            prop_pad = len(prop_bytes) % 4
            if prop_pad != 0:
                prop_bytes = prop_bytes + (b"\0" * (4 - prop_pad))
            new_value = int.from_bytes(prop_bytes, byteorder=asm_arch['byteorder'], signed=False)
        else:
            new_value = None
        if new_value is None:
            raise ValueError("Unable to prepare direct int value from provided string value.")
        #TODO replace with the more complex patching used below for DETACHED_DATA
        new_value_for_asm = "0x{:x}".format(new_value)
        asm_line = re.sub(r'[(][?]P<'+var_info['name']+r'>[^)]+[)]', new_value_for_asm, var_info['re_line_str'])
        # Now compile our new code line
        ks = Ks(asm_arch['ks_const'], asm_arch['ks_mode'])
        encoding, _ = ks.asm(asm_line)
        valbt = {}
        valbt['sect'] = '.text'
        section = elf_sections[valbt['sect']]
        valbt['offs'] = var_info['address'] - section['addr']
        valbt['data'] = bytes(encoding)
        valbts.append(valbt)
        #print("{:s} = {:s}".format(asm_line, encoding))
    elif (var_info['type'] in [VarType.ABSOLUTE_ADDR_TO_GLOBAL_DATA, VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA,
      VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA]):
        # The value was referenced in code, but stored outside
        prop_bytes = armfw_elf_search_value_native_type_to_bytes(asm_arch, var_info, new_var_nativ)
        if len(prop_bytes) < 1:
            raise ValueError("Unable to prepare bytes from provided string value.")

        var_sect, var_offs = get_section_and_offset_from_address(asm_arch, elf_sections, var_info['value']) # for "*_ADDR_*" types, value stores address
        valbt = {}
        valbt['sect'] = var_sect
        section = elf_sections[valbt['sect']]
        valbt['offs'] = var_offs
        valbt['data'] = bytes(prop_bytes)
        valbts.append(valbt)
    elif (var_info['type'] in [VarType.DETACHED_DATA]):
        # For detached data, we need to find an assembly pattern with matching value, and then patch the asm code to look like it
        patterns_next = find_patterns_containing_variable(re_list, var_type=var_info['type'], var_name=var_info['name'], var_setValue=str(new_var_nativ))
        patterns_prev = find_patterns_containing_variable(re_list, var_type=var_info['type'], var_name=var_info['name'], var_setValue=var_info['setValue'])
        # Get part of the pattern which is different between the current one and the one we want
        patterns_diff = []
        if patterns_prev != patterns_next:
            patterns_diff, patterns_preced = find_patterns_diff(patterns_prev, patterns_next)
        if len(patterns_diff) > 0:
            # From patterns preceding the diff, compute offset where the diff starts
            patterns_addr = var_info['address'] + armfw_elf_compute_code_length(asm_arch, patterns_preced)
            var_sect, var_offs = get_section_and_offset_from_address(asm_arch, elf_sections, patterns_addr)
            asm_lines = []
            asm_addr_curr = patterns_addr
            for pat_line in patterns_diff:
                asm_line, code_size = prepare_asm_line_from_pattern(asm_arch, elf_sections, glob_params_list, asm_addr_curr, var_info['cfunc_name'], pat_line)
                asm_addr_curr += code_size
                asm_lines.append(asm_line)
            if len(asm_lines) < 1:
                raise ValueError("No assembly lines prepared - internal error.")
            if (po.verbose > 2):
                print("Compiling code:",asm_lines)
            # Now compile our new code line
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
                        asm_addr_curr = patterns_addr + len(bt_enc_data)
                        encoding, encoded_num = ks.asm("\n".join(asm_lines[asm_ln_start:asm_ln_curr]), addr=asm_addr_curr)
                        if encoded_num != asm_ln_curr-asm_ln_start:
                            raise ValueError("Cannot compile all assembly lines; compiled circa {:d} out of {:d}.".format(asm_ln_start+encoded_num, len(asm_lines)))
                        bt_enc_data += bytes(encoding)
                    # Add data from the line at end
                    bt_enc_data += curr_data['value']
                    asm_ln_start = asm_ln_curr + 1

            valbt = {}
            valbt['sect'] = var_sect
            section = elf_sections[valbt['sect']]
            valbt['offs'] = var_offs
            valbt['data'] = bt_enc_data
            valbts.append(valbt)
    else:
        raise NotImplementedError("Unexpected variable type found.")

    for valbt in valbts:
        section = elf_sections[valbt['sect']]
        if (valbt['offs'] < 0) or (valbt['offs'] + len (valbt['data']) > len(section['data'])):
            raise ValueError("Got past section '{:s}' border - internal error.".format(valbt['sect']))
    return valbts


def armfw_elf_paramvals_extract_list(po, elffh, re_list):

    elfobj = ELFFile(elffh)

    asm_arch, asm_modes = elf_march_to_asm_config(elfobj)
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
    for re_item in re_list:
        matches = armfw_elf_whole_section_search(po, asm_arch, elf_sections, cs, re_item['sect'], re_item['func'])
        if len(matches) == 1:
            pub_params_list.update(armfw_elf_match_to_public_values(po, matches[0]))
            glob_params_list.update(armfw_elf_match_to_global_values(po, matches[0], re_item['func']['name']))

    return pub_params_list, glob_params_list, elf_sections, cs, elfobj, asm_arch


def armfw_elf_ambavals_list(po, elffh):
    params_list, _, _, _, _, _ = armfw_elf_paramvals_extract_list(po, elffh, re_general_list)
    # print list of parameter values
    for par_name, par_info in params_list.items():
        print("{:s}\t{:s}".format(par_name,par_info['str_value']))
    if (po.verbose > 0):
        print("{:s}: Listed {:d} hardcoded values".format(po.elffile,len(params_list)))


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
        for ppname in ('minValue', 'maxValue', 'defaultValue'):
            if not ppname in par_info: continue
            valfile.write(",\n")
            if re.match(r"^(0[Xx][0-9a-fA-F]+|[0-9]+)$", par_info['str_value']):
                valfile.write("\t\t\"{:s}\" : {:s}".format(ppname,par_info[ppname]))
            else:
                valfile.write("\t\t\"{:s}\" : \"{:s}\"".format(ppname,par_info[ppname]))
        for ppname in ('setValue',):
            valfile.write(",\n")
            if re.fullmatch(r"^(0[Xx][0-9a-fA-F]+|[0-9]+)$", par_info['str_value']):
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
    valfile.close()


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
    update_count = 0
    for nxpar in nxparams_list:
        if not nxpar['name'] in pub_params_list:
            eprint("{:s}: Value '{:s}' not found in ELF file.".format(po.elffile,nxpar['name']))
            continue
        par_info = pub_params_list[nxpar['name']]
        valbts = armfw_elf_get_value_update_bytes(po, asm_arch, elf_sections, re_general_list, glob_params_list, par_info, nxpar['setValue'])
        update_performed = False
        for valbt in valbts:
            section = elf_sections[valbt['sect']]
            old_beg = valbt['offs']
            old_end = valbt['offs']+len(valbt['data'])
            old_data = section['data'][old_beg:old_end]
            if valbt['data'] != old_data:
                update_performed = True
                if (po.verbose > 1):
                    print("Replacing {:s} -> {:s} to set {:s}".format(old_data.hex(),valbt['data'].hex(),par_info['name']))
                sect_data = section['data']
                sect_data[old_beg:old_end] = valbt['data']
        if update_performed:
            update_count += 1
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
    main()
