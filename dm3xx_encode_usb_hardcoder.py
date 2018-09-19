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

sys.path.insert(0, './')
from amba_sys_hardcoder import eprint, elf_march_to_asm_config, \
  armfw_elf_whole_section_search, armfw_elf_match_to_public_values, \
  armfw_elf_paramvals_extract_list, armfw_elf_get_value_update_bytes, \
  VarType, DataVariety, CodeVariety


def startup_encrypt_check_always_pass_params_update(asm_arch, elf_sections, re_list, glob_params_list, var_info, new_var_nativ):
    """ Callback function to prepare 'startup_encrypt_check_always_pass' value change.
    Sets global params required for the switch.3
    """
    if new_var_nativ == 1:
        # Set variables requires to change original into encpass
        var_bPassedEnc = glob_params_list['Encrypt_Request.s_bPassedEnc'].copy()
        var_bPassedEnc['re_line'] = None
        var_bPassedEnc['cfunc_name'] = var_info['cfunc_name']
        var_bPassedEnc['address'] = None
        var_bPassedEnc['value'] = glob_params_list['encryptThrFxn']['value'] + 13*4 #var_bPassedEnc['address']
        glob_params_list['encryptThrFxn-original.s_bPassedEnc'] = var_bPassedEnc
        var_bPassedEnc_p = {'str_value': "", 'value': 0x0, 'address': None, 'instr_size': None, 're_line': None, 'cfunc_name': var_info['cfunc_name']}
        var_bPassedEnc_p['value'] = glob_params_list['Encrypt_Request.s_bPassedEnc']['value']
        var_bPassedEnc_p.update(re_func_encryptThrFxn_encpass['vars']['s_bPassedEnc_p'])
        glob_params_list['encryptThrFxn-original.s_bPassedEnc_p'] = var_bPassedEnc_p
    else:
        # Set variables requires to change encpass back to original
        pass

re_func_encryptThrFxn_original = {
'name': "encryptThrFxn-original",
're': """
  push	{fp, lr}
  add	fp, sp, #4
  sub	sp, sp, #0x10
  str	r0, \[fp, #-0x10\]
  ldr	r0, \[pc, #(?P<cstr_ent_query_md>[0-9a-fx]+)\]
  bl	#(?P<puts>[0-9a-fx]+)
loc_label1:
  mov	r0, #1
  bl	#(?P<Encrypt_Request>[0-9a-fx]+)
  mov	r3, r0
  str	r3, \[fp, #-8\]
  ldr	r3, \[fp, #-8\]
  cmp	r3, #0
  bne	#(?P<loc_label2>[0-9a-fx]+)
  mov	r0, #1
  bl	#(?P<sleep>[0-9a-fx]+)
  b	#(?P<loc_label1>[0-9a-fx]+)
loc_label2:
  ldr	r0, \[pc, #(?P<cstr_enc_pass>[0-9a-fx]+)\]
  bl	#(?P<puts>[0-9a-fx]+)
  sub	sp, fp, #4
  pop	{fp, pc}
""",
'vars': {
  'encryptThrFxn':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION, 'line': 0},
  'startup_encrypt_check_always_pass':	{'type': VarType.DETACHED_DATA, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.p3x_dm3xx", 'minValue': "0", 'maxValue': "1", 'defaultValue': "0", 'setValue': "0",
    'custom_params_callback': startup_encrypt_check_always_pass_params_update,
    'description': "Set startup encryption test as passed even if it did not; 0-repeat forever on fail,1-force pass"},
  'cstr_ent_query_md':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_enc_pass':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'loc_label1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'puts':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sleep':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'Encrypt_Request':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
},
}

re_func_encryptThrFxn_encpass = {
'name': "encryptThrFxn-encpass",
're': """
  push	{fp, lr}
  add	fp, sp, #4
  sub	sp, sp, #0x10
  str	r0, \[fp, #-0x10\]
  ldr	r0, \[pc, #(?P<cstr_ent_query_md>[0-9a-fx]+)\]
  bl	#(?P<puts>[0-9a-fx]+)
loc_label1:
  mov	r0, #1
  bl	#(?P<Encrypt_Request>[0-9a-fx]+)
  mov	r3, #1
  ldr	r0, \[pc, #(?P<s_bPassedEnc>[0-9a-fx]+)\]
  strb	r3, \[r0\]
  cmp	r3, #0
  b	#(?P<loc_label2>[0-9a-fx]+)
  dcd	(?P<s_bPassedEnc_p>[0-9a-fx]+)
  bl	#(?P<sleep>[0-9a-fx]+)
  b	#(?P<loc_label1>[0-9a-fx]+)
loc_label2:
  ldr	r0, \[pc, #(?P<cstr_enc_pass>[0-9a-fx]+)\]
  bl	#(?P<puts>[0-9a-fx]+)
  sub	sp, fp, #4
  pop	{fp, pc}
""",
'vars': {
  'encryptThrFxn':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION, 'line': 0},
  'startup_encrypt_check_always_pass':	{'type': VarType.DETACHED_DATA, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.p3x_dm3xx", 'minValue': "0", 'maxValue': "1", 'defaultValue': "0", 'setValue': "1",
    'description': "Set startup encryption test as passed even if it did not; 0-repeat forever on fail,1-force pass"},
  'cstr_ent_query_md':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_enc_pass':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'loc_label1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'puts':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sleep':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'Encrypt_Request':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  's_bPassedEnc':		{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.UINT32_T},
  's_bPassedEnc_p':	{'type': VarType.ABSOLUTE_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UINT32_T},
},
}

re_func_Encrypt_Request = {
'name': "Encrypt_Request",
're': """
  push	{fp, lr}
  add	fp, sp, #4
  sub	sp, sp, #0x360
  str	r0, \[fp, #-0x350\]
  sub	r3, fp, #0x300
  mov	r0, r3
  mov	r1, #0x20
  bl	#(?P<GetRandomData>[0-9a-fx]+)
  sub	r3, fp, #0x34c
  mov	r0, r3
  mov	r1, #0
  mov	r2, #8
  bl	#(?P<memset>[0-9a-fx]+)
  mov	r3, #8
  strb	r3, \[fp, #-0x34c\]
  mov	r3, #1
  strb	r3, \[fp, #-0x34b\]
  mov	r3, #2
  strb	r3, \[fp, #-0x34a\]
  mov	r3, #0
  strb	r3, \[fp, #-0x349\]
  mov	r3, #0x30
  strb	r3, \[fp, #-0x348\]
  mov	r3, #0
  strb	r3, \[fp, #-0x347\]
  bl	#(?P<Enc_Serial_Get_CurSeq>[0-9a-fx]+)
  mov	r3, r0
  mov	r2, r3
  ldr	r3, \[pc, #0x284\]
  sub	r1, fp, #4
  strh	r2, \[r1, r3\]
  sub	r3, fp, #0x140
  str	r3, \[fp, #-0x10\]
  ldr	r2, \[fp, #-0x10\]
  mov	r3, #4
  strb	r3, \[r2\]
  ldr	r3, \[fp, #-0x10\]
  add	r3, r3, #1
  str	r3, \[fp, #-0x10\]
  ldr	r2, \[fp, #-0x10\]
  mov	r3, #8
  strb	r3, \[r2\]
  ldr	r3, \[fp, #-0x10\]
  add	r3, r3, #1
  str	r3, \[fp, #-0x10\]
  sub	r3, fp, #0x300
  ldr	r0, \[fp, #-0x10\]
  mov	r1, r3
  mov	r2, #0x20
  bl	#(?P<memcpy>[0-9a-fx]+)
  ldr	r3, \[fp, #-0x10\]
  add	r3, r3, #0x20
  str	r3, \[fp, #-0x10\]
  ldr	r2, \[fp, #-0x10\]
  sub	r3, fp, #0x140
  rsb	r3, r3, r2
  str	r3, \[fp, #-0x14\]
  mov	r3, #0
  str	r3, \[fp, #-8\]
  b	#(?P<loc_label02>[0-9a-fx]+)
  sub	r2, fp, #0x34c
  sub	r1, fp, #0x140
  sub	r3, fp, #0x26c
  str	r3, \[sp\]
  sub	r3, fp, #0x344
  str	r3, \[sp, #4\]
  mov	r3, #0x12c
  str	r3, \[sp, #8\]
  mov	r0, r2
  ldr	r2, \[fp, #-0x14\]
  mov	r3, #0x3e8
  bl	#(?P<Enc_Serial_SendWaitAck>[0-9a-fx]+)
  mov	r3, r0
  cmp	r3, #0
  beq	#(?P<loc_label03>[0-9a-fx]+)
  ldr	r3, \[fp, #-8\]
  add	r3, r3, #1
  str	r3, \[fp, #-8\]
  ldr	r2, \[fp, #-8\]
  ldr	r3, \[fp, #-0x350\]
  cmp	r2, r3
  blo	#(?P<loc_label01>[0-9a-fx]+)
  ldr	r2, \[fp, #-8\]
  ldr	r3, \[fp, #-0x350\]
  cmp	r2, r3
  blo	#(?P<loc_label04>[0-9a-fx]+)
  mov	r3, #0
  str	r3, \[fp, #-0x354\]
  b	#(?P<loc_label10>[0-9a-fx]+)
  ldr	r3, \[fp, #-0x344\]
  cmp	r3, #0x3a
  bhi	#(?P<loc_label05>[0-9a-fx]+)
  mov	r1, #0
  str	r1, \[fp, #-0x354\]
  b	#(?P<loc_label10>[0-9a-fx]+)
  sub	r3, fp, #0x26c
  str	r3, \[fp, #-0x10\]
  ldr	r3, \[fp, #-0x10\]
  ldrb	r3, \[r3\]
  cmp	r3, #0
  moveq	r3, #0
  movne	r3, #1
  and	r2, r3, #0xff
  ldr	r3, \[fp, #-0x10\]
  add	r3, r3, #1
  str	r3, \[fp, #-0x10\]
  cmp	r2, #0
  beq	#(?P<loc_label06>[0-9a-fx]+)
  mov	r3, #0
  str	r3, \[fp, #-0x354\]
  b	#(?P<loc_label10>[0-9a-fx]+)
  sub	r3, fp, #0x320
  mov	r0, r3
  mov	r1, #0x20
  ldr	r2, \[pc, #(?P<cstr_fname_key>[0-9a-fx]+)\]
  bl	#(?P<AesDecryptFromFile>[0-9a-fx]+)
  mov	r3, r0
  cmp	r3, #0
  beq	#(?P<loc_label07>[0-9a-fx]+)
  mov	r1, #0
  str	r1, \[fp, #-0x354\]
  b	#(?P<loc_label10>[0-9a-fx]+)
  sub	r3, fp, #0x340
  sub	r2, fp, #0x320
  sub	ip, fp, #0x300
  mov	r0, r3
  mov	r1, #2
  mov	r3, ip
  bl	#(?P<CalMac>[0-9a-fx]+)
  sub	r3, fp, #0x340
  mov	r0, r3
  ldr	r1, \[fp, #-0x10\]
  mov	r2, #0x20
  bl	#(?P<memcmp>[0-9a-fx]+)
  mov	r3, r0
  cmp	r3, #0
  beq	#(?P<loc_label08>[0-9a-fx]+)
  mov	r3, #0
  str	r3, \[fp, #-0x354\]
  b	#(?P<loc_label10>[0-9a-fx]+)
  ldr	r3, \[fp, #-0x10\]
  add	r3, r3, #0x20
  str	r3, \[fp, #-0x10\]
  sub	r3, fp, #0x2d0
  str	r3, \[fp, #-0xc\]
  ldr	r0, \[fp, #-0xc\]
  ldr	r1, \[fp, #-0x10\]
  mov	r2, #0xa
  bl	#(?P<memcpy>[0-9a-fx]+)
  ldr	r3, \[fp, #-0xc\]
  add	r3, r3, #0xa
  str	r3, \[fp, #-0xc\]
  ldr	r3, \[fp, #-0x10\]
  add	r3, r3, #0xa
  str	r3, \[fp, #-0x10\]
  sub	r3, fp, #0x320
  ldr	r0, \[fp, #-0xc\]
  mov	r1, r3
  mov	r2, #0x20
  bl	#(?P<memcpy>[0-9a-fx]+)
  ldr	r3, \[fp, #-0xc\]
  add	r3, r3, #0x20
  str	r3, \[fp, #-0xc\]
  ldr	r2, \[fp, #-0xc\]
  sub	r3, fp, #0x2d0
  rsb	r3, r3, r2
  mov	r1, r3
  sub	r3, fp, #0x2d0
  sub	r2, fp, #0x2e0
  mov	r0, r3
  bl	#(?P<CalMD5>[0-9a-fx]+)
  sub	r3, fp, #0x2e0
  mov	r0, r3
  ldr	r1, \[fp, #-0x10\]
  mov	r2, #0x10
  bl	#(?P<memcmp>[0-9a-fx]+)
  mov	r3, r0
  cmp	r3, #0
  beq	#(?P<loc_label09>[0-9a-fx]+)
  mov	r1, #0
  str	r1, \[fp, #-0x354\]
  b	#(?P<loc_label10>[0-9a-fx]+)
  ldr	r3, \[pc, #(?P<s_bPassedEnc>[0-9a-fx]+)\]
  mov	r2, #1
  strb	r2, \[r3\]
  mov	r3, #1
  str	r3, \[fp, #-0x354\]
  ldr	r3, \[fp, #-0x354\]
  mov	r0, r3
  sub	sp, fp, #4
  pop	{fp, pc}
""",
'vars': {
  'Encrypt_Request':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION, 'line': 0},
  'cstr_fname_key':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'loc_label01':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label02':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label03':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label04':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label05':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label06':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label07':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label08':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label09':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label10':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'puts':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'memset':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'memcpy':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'memcmp':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sleep':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'GetRandomData':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'Enc_Serial_Get_CurSeq':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'Enc_Serial_SendWaitAck':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'AesDecryptFromFile':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'CalMac':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'CalMD5':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  's_bPassedEnc':		{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.UINT32_T},
  'Encrypt_Request':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
},
}

def armfw_elf_dm3xxvals_func_encryptThrFxn_prep(po, xxx):
    pass

re_general_list = [
  {'sect': ".text", 'func': re_func_encryptThrFxn_original,},
  {'sect': ".text", 'func': re_func_encryptThrFxn_encpass,},
  {'sect': ".text", 'func': re_func_Encrypt_Request,},
]


def armfw_elf_dm3xxvals_list(po, elffh):
    params_list, _, _, _, _, _ = armfw_elf_paramvals_extract_list(po, elffh, re_general_list)
    # print list of parameter values
    for par_name, par_info in params_list.items():
        print("{:s}\t{:s}".format(par_name,par_info['str_value']))
    if (po.verbose > 0):
        print("{:s}: Listed {:d} hardcoded values".format(po.elffile,len(params_list)))


def armfw_elf_dm3xxvals_extract(po, elffh):
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


def armfw_elf_dm3xxvals_update(po, elffh):
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

        armfw_elf_dm3xxvals_objdump(po, elffh)

        elffh.close();

    elif po.list:

        if (po.verbose > 0):
            print("{}: Opening for list".format(po.elffile))

        elffh = open(po.elffile, "rb")

        armfw_elf_dm3xxvals_list(po, elffh)

        elffh.close();

    elif po.extract:

        if (po.verbose > 0):
            print("{}: Opening for extract".format(po.elffile))

        elffh = open(po.elffile, "rb")

        armfw_elf_dm3xxvals_extract(po, elffh)

        elffh.close();

    elif po.update:

        if (po.verbose > 0):
            print("{}: Opening for update".format(po.elffile))

        elffh = open(po.elffile, "r+b")

        armfw_elf_dm3xxvals_update(po, elffh)

        elffh.close();

    else:

        raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
    main()
