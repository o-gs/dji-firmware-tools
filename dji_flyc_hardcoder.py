#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Dji Flight Controller firmware binary hard-coded values editor.

The tool can parse Flight Controller firmware converted to ELF.
It finds certain hard-coded values in the binary data, and allows
exporting or importing them.

Only 'setValue' element in the exported file is really changeable,
all the other data is just informational. This includes `maxValue` and
`minValue` - they don't do anything and changing them in the JSON file
will not influence update operation.

Exported values:

og_hardcoded.TODO -

  TODO.

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
  armfw_elf_paramvals_get_depend_list, armfw_elf_publicval_update, \
  armfw_elf_paramvals_update_list, armfw_elf_generic_objdump, \
  armfw_asm_search_strings_to_re_list, armfw_elf_paramvals_export_json, \
  VarType, DataVariety, CodeVariety


re_func_wp_check_input_mission_validity_WM100_V03_02_43_20 = {
'name': "wp_check_input_mission_validity",
'version': "wm100_0306_v03.02.43.20",
're': """
wp_check_input_mission_validity:
  push.w	{r2, r3, r4, r5, r6, r7, r8, lr}
  ldr	r0, \[pc, #(?P<unk_2042AD08>[0-9a-fx]+)\]
  movs	r5, #0
  ldr	r6, \[pc, #(?P<byte_20428D08>[0-9a-fx]+)\]
  ldrb.w	r1, \[r0, #(?P<rel_byte_2042B3B0>[0-9a-fx]+)\]
  ldrb	r0, \[r6\]
  cmp	r1, r0
  bne	#(?P<loc_4ADCD0>[0-9a-fx]+)
  add.w	r0, r0, r0, lsl #1
  movs	r2, #0x60
  add.w	r0, r6, r0, lsl #5
  adds	r0, #0x40
  add.w	r1, r6, #0x40
  bl	#(?P<sub_4BEB10>[0-9a-fx]+)
  b	#(?P<loc_4ADECE>[0-9a-fx]+)
loc_4ADBE8:
  add.w	r0, r5, r5, lsl #1
  add.w	r7, r6, r0, lsl #5
  add.w	r4, r7, #0x40
  vldr	d0, \[r7, #0x40\]
  vldr	d1, \[pc, #(?P<dbl_minus_pi_half>[0-9a-fx]+)\]
  vcmpe.f64	d0, d1
  vmrs	apsr_nzcv, fpscr
  blo	#(?P<loc_val_fail>[0-9a-fx]+)
  vldr	d1, \[pc, #(?P<dbl_pi_half>[0-9a-fx]+)\]
  vcmpe.f64	d0, d1
  vmrs	apsr_nzcv, fpscr
  bgt	#(?P<loc_val_fail>[0-9a-fx]+)
  vldr	d0, \[r4, #8\]
  vldr	d1, \[pc, #(?P<dbl_minus_pi>[0-9a-fx]+)\]
  vcmpe.f64	d0, d1
  vmrs	apsr_nzcv, fpscr
  blo	#(?P<loc_val_fail>[0-9a-fx]+)
  vldr	d1, \[pc, #(?P<dbl_just_pi>[0-9a-fx]+)\]
  vcmpe.f64	d0, d1
  vmrs	apsr_nzcv, fpscr
  bgt	#(?P<loc_val_fail>[0-9a-fx]+)
  ldr	r2, \[pc, #(?P<min_alt_below_home>[0-9a-fx]+)\]
  ldr	r0, \[r4, #0x10\]
  cmp	r0, r2
  bhi	#(?P<loc_val_fail>[0-9a-fx]+)
  ldr	r2, \[pc, #(?P<min_alt_above_home>[0-9a-fx]+)\]
  cmp	r0, r2
  bgt	#(?P<loc_val_fail>[0-9a-fx]+)
  ldrsh.w	r0, \[r4, #0x18\]
  cmn.w	r0, #0xb4
  blt	#(?P<loc_val_fail>[0-9a-fx]+)
  cmp	r0, #0xb4
  bgt	#(?P<loc_val_fail>[0-9a-fx]+)
  ldrsh.w	r0, \[r4, #0x1a\]
  cmn.w	r0, #0x384 ; 900
  blt	#(?P<loc_val_fail>[0-9a-fx]+)
  cmp	r0, #0
  bgt	#(?P<loc_val_fail>[0-9a-fx]+)
  ldrsh.w	r0, \[r4, #0x1e\]
  movw	r2, #0x5dc ; 1500
  cmn	r0, r2
  blt	#(?P<loc_val_fail>[0-9a-fx]+)
  cmp	r0, r2
  bgt	#(?P<loc_val_fail>[0-9a-fx]+)
  ldrb.w	r0, \[r4, #0x20\]
  cmp	r0, #3
  bhs	#(?P<loc_val_fail>[0-9a-fx]+)
  ldrb	r0, \[r4, #0x1c\]
  cmp	r0, #2
  blo	#(?P<loc_chk_contn1>[0-9a-fx]+)
loc_val_fail:
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr	r3, \[r0, #0xc\]
  movs	r0, #0x28
  adr	r1, #(?P<cstr_wp_data_val_fail>[0-9a-fx]+)
  mov	r2, r5
  blx	r3
  b	#(?P<loc_4ADF68>[0-9a-fx]+)
loc_chk_contn1:
  cmp	r1, r5
  bls	#(?P<loc_4ADD36>[0-9a-fx]+)
  adds	r7, #0xa0
  mov	r1, r4
  mov	r0, r7
  bl	#(?P<sub_4A894E>[0-9a-fx]+)
  vldr	s1, \[r7, #0x10\]
  vldr	s2, \[r4, #0x10\]
  vmul.f32	s0, s0, s0
  vsub.f32	s1, s1, s2
  vmla.f32	s0, s1, s1
  bl	#(?P<sub_4AC860>[0-9a-fx]+)
  ldrb	r0, \[r6, #(?P<rel_byte_20428D15>[0-9a-fx]+)\]
  cmp	r0, #1
  bne	#(?P<loc_4ADCC0>[0-9a-fx]+)
  ldrb	r1, \[r6\]
  subs	r1, r1, #1
  cmp	r1, r5
  beq	#(?P<loc_chk_contn3>[0-9a-fx]+)
loc_4ADCC0:
  vmov	r1, s0
  cmp.w	r1, #0x3f000000 ; 0.5f
  bge	#(?P<loc_chk_contn2>[0-9a-fx]+)
  bl	#(?P<get_logger>[0-9a-fx]+)
  b	#(?P<loc_dist_small>[0-9a-fx]+)
loc_4ADCD0:
  b	#(?P<loc_4ADFE2>[0-9a-fx]+)
loc_dist_small:
  ldr	r3, \[r0, #0xc\]
  movs	r0, #0x28
  adr	r1, #(?P<cstr_wp_dist_too_small>[0-9a-fx]+)
  mov	r2, r5
  blx	r3
  movs	r0, #0xe5
loc_ret1:
  pop.w	{r2, r3, r4, r5, r6, r7, r8, pc}
loc_chk_contn2:
  cmp	r0, #1
  bne	#(?P<loc_4ADCEE>[0-9a-fx]+)
loc_chk_contn3:
  ldrb	r1, \[r6\]
  subs	r1, r1, #1
  cmp	r1, r5
  beq	#(?P<loc_4ADD0E>[0-9a-fx]+)
loc_4ADCEE:
  vmov	r1, s0
  ldr	r2, \[pc, #(?P<max_wp_dist_to_home>[0-9a-fx]+)\]
  cmp	r1, r2
  ble	#(?P<loc_4ADD0A>[0-9a-fx]+)
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr	r3, \[r0, #0xc\]
  movs	r0, #0x28
  adr	r1, #(?P<cstr_wp_dist_too_large>[0-9a-fx]+)
  mov	r2, r5
  blx	r3
  movs	r0, #0xe6
  b	#(?P<loc_ret1>[0-9a-fx]+)
loc_4ADD0A:
  cmp	r0, #1
  bne	#(?P<loc_4ADD16>[0-9a-fx]+)
loc_4ADD0E:
  ldrb	r0, \[r6\]
  subs	r0, r0, #1
  cmp	r0, r5
  beq	#(?P<loc_4ADD36>[0-9a-fx]+)
loc_4ADD16:
  ldrb	r0, \[r6, #(?P<rel_byte_20428D17>[0-9a-fx]+)\]
  cmp	r0, #1
  bne	#(?P<loc_4ADD36>[0-9a-fx]+)
  vldr	s1, \[r4, #0x14\]
  ldr	r1, \[pc, #(?P<flt_minus_twentytwo_dot_four>[0-9a-fx]+)\]
  vmov	r0, s1
  add	r0, r1
  ldr	r1, \[pc, #(?P<flt_positive_epsylon>[0-9a-fx]+)\]
  cmp	r0, r1
  blo	#(?P<loc_4ADD38>[0-9a-fx]+)
  bl	#(?P<get_logger>[0-9a-fx]+)
  mov	r2, r5
  b	#(?P<loc_4ADE94>[0-9a-fx]+)
; The function continues, but nothing interesting happens after this place
""",
'vars': {
  'wp_check_input_mission_validity':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'get_logger':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_4A894E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_4AC860':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_4BEB10':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'loc_val_fail':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_chk_contn1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADCC0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADCD0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_dist_small':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_chk_contn2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_chk_contn3':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADCEE':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADD0A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADD0E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADD16':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADD36':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADD38':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADE94':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADECE':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADF68':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADFE2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'byte_20428D08':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_2042AD08':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'cstr_wp_data_val_fail':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_wp_dist_too_large':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_wp_dist_too_small':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'dbl_just_pi':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'dbl_minus_pi':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'dbl_minus_pi_half':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'dbl_pi_half':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'flt_minus_twentytwo_dot_four':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT},
  'flt_positive_epsylon':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT},
  'max_wp_dist_to_home':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT},
  'min_alt_above_home':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT},
  'min_alt_below_home':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT},
  'rel_byte_20428D15':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_byte_20428D17':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_byte_2042B3B0':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
},
}

re_general_list = [
  {'sect': ".text", 'func': re_func_wp_check_input_mission_validity_WM100_V03_02_43_20,},
]


def armfw_elf_lbstm32_list(po, elffh):
    params_list, _, _, _, _, _ = armfw_elf_paramvals_extract_list(po, elffh, re_general_list, 'thumb')
    # print list of parameter values
    for par_name, par_info in params_list.items():
        print("{:s}\t{:s}".format(par_name,par_info['str_value']))
    if (po.verbose > 0):
        print("{:s}: Listed {:d} hardcoded values".format(po.elffile,len(params_list)))


def armfw_elf_lbstm32_extract(po, elffh):
    """ Extracts all values from firmware to JSON format text file.
    """
    params_list, _, _, _, _, _ = armfw_elf_paramvals_extract_list(po, elffh, re_general_list, 'thumb')
    if len(params_list) <= 0:
        raise ValueError("No known values found in ELF file.")
    if not po.dry_run:
        valfile = open(po.valfile, "w")
    else:
        valfile = io.StringIO()
    armfw_elf_paramvals_export_json(po, params_list, valfile)
    valfile.close()


def armfw_elf_lbstm32_update(po, elffh):
    """ Updates all hardcoded values in firmware from JSON format text file.
    """
    pub_params_list, glob_params_list, elf_sections, cs, elfobj, asm_arch = armfw_elf_paramvals_extract_list(po, elffh, re_general_list, 'thumb')
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

        armfw_elf_generic_objdump(po, elffh, 'thumb')

        elffh.close();

    elif po.list:

        if (po.verbose > 0):
            print("{}: Opening for list".format(po.elffile))

        elffh = open(po.elffile, "rb")

        armfw_elf_lbstm32_list(po, elffh)

        elffh.close();

    elif po.extract:

        if (po.verbose > 0):
            print("{}: Opening for extract".format(po.elffile))

        elffh = open(po.elffile, "rb")

        armfw_elf_lbstm32_extract(po, elffh)

        elffh.close();

    elif po.update:

        if (po.verbose > 0):
            print("{}: Opening for update".format(po.elffile))

        elffh = open(po.elffile, "r+b")

        armfw_elf_lbstm32_update(po, elffh)

        elffh.close();

    else:

        raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
    main()
