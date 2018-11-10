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

og_hardcoded.flyc.max_wp_dist_to_home -

  Max distance from one waypoint to home point, in meters.
  This value is also app limited and need Android App side patch.

og_hardcoded.flyc.max_alt_above_home -

  Max altitude relative to home point, in meters.
  This value is also app limited and need Android App side patch.

og_hardcoded.flyc.min_alt_below_home -

  Min altitude relative to home point, in meters.
  This value is also app limited and need Android App side patch.

og_hardcoded.flyc.max_mission_path_len -

  Maximum total length of mission trace, in meters.

og_hardcoded.flyc.max_speed_pos -

  Maximum speed used when doing autonomous flights; in meters per second [m/s]".
  This value should be positive - in represents the limit when calculated speed
  vector is in positive direction.

og_hardcoded.flyc.max_speed_neg -

  Maximum negative speed used when doing autonomous flights; in meters
  per second [m/s]". This value should be lower than zero, and equal to
  max_speed_pos in its absolute value.

"""

# Copyright (C) 2017,2018 Mefistotelis <mefistotelis@gmail.com>
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
__author__ = "Mefistotelis, Matioupi @ Original Gangsters"
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
  armfw_elf_paramvals_export_simple_list, armfw_elf_paramvals_export_mapfile, \
  VarType, DataVariety, CodeVariety


re_func_wp_check_input_mission_validity_P3X_V01_05_0030 = {
'name': "wp_check_input_mission_validity",
'version': "P3X_FW_V01.05.0030",
're': """
wp_check_input_mission_validity:
  push	{r4, r5, r6, r7, lr}
  ldr	r0, \[pc, #(?P<byte_200084A4>[0-9a-fx]+)\]
  ldr	r7, \[pc, #(?P<byte_20005DF8>[0-9a-fx]+)\]
  movs	r4, #0
  vpush	{d8}
  sub	sp, #0x1c
  ldrb	r0, \[r0\]
  ldrb	r1, \[r7\]
  cmp	r0, r1
  beq	#(?P<loc_8064122>[0-9a-fx]+)
  b	#(?P<loc_806438A>[0-9a-fx]+)
loc_80640E2:
  add.w	r0, r4, r4, lsl #1
  add.w	r5, r7, r0, lsl #5
  ldr	r0, \[r5, #0x54\]
  bl	#(?P<calculate_cali_matrix>[0-9a-fx]+)
  vmov	d8, r0, r1
  ldr	r0, \[r5, #0x50\]
  bl	#(?P<calculate_cali_matrix>[0-9a-fx]+)
  vmov	d0, r0, r1
  vstr	d8, \[sp, #(?P<loc_var_28>[0-9a-fx]+)\]
  vstr	d0, \[sp, #(?P<loc_var_30>[0-9a-fx]+)\]
  vldr	d0, \[r5, #0x48\]
  mov	r1, r4
  vstr	d0, \[sp\]
  vldr	d0, \[r5, #0x40\]
  adr	r0, #(?P<cstr_debug_log_l1h>[0-9a-fx]+)
  vmov	r2, r3, d0
  bl	#(?P<flight_rec_printf_send_c0E>[0-9a-fx]+)
  adds	r4, r4, #1
  uxtb	r4, r4
loc_8064122:
  ldrb	r0, \[r7\]
  cmp	r0, r4
  bhi	#(?P<loc_80640E2>[0-9a-fx]+)
  uxtb	r0, r0
  add.w	r0, r0, r0, lsl #1
  ldr	r1, \[pc, #(?P<byte_20005DF8>[0-9a-fx]+)\]
  add.w	r0, r7, r0, lsl #5
  adds	r0, #0x40
  movs	r2, #0x60
  adds	r1, #0x40
  bl	#(?P<memcpy_0>[0-9a-fx]+)
  movs	r5, #0
  b	#(?P<loc_806429C>[0-9a-fx]+)
loc_8064142:
  add.w	r0, r5, r5, lsl #1
  add.w	r6, r7, r0, lsl #5
  add.w	r4, r6, #0x40
  vldr	d0, \[r6, #0x40\]
  vldr	d1, \[pc, #(?P<dbl_minus_pi_half>[0-9a-fx]+)\]
  vmov	r0, r1, d0
  vmov	r2, r3, d1
  bl	#(?P<sub_808B480>[0-9a-fx]+)
loc_80641D6:
  blo	#(?P<loc_80641D6>[0-9a-fx]+)
  vldr	d0, \[r4\]
  vldr	d1, \[pc, #(?P<dbl_pi_half>[0-9a-fx]+)\]
  vmov	r0, r1, d0
  vmov	r2, r3, d1
  bl	#(?P<sub_8086F86>[0-9a-fx]+)
  blo	#(?P<loc_80641D6>[0-9a-fx]+)
  vldr	d0, \[r4, #8\]
  vldr	d1, \[pc, #(?P<dbl_minus_pi>[0-9a-fx]+)\]
  vmov	r0, r1, d0
  vmov	r2, r3, d1
  bl	#(?P<sub_808B480>[0-9a-fx]+)
  blo	#(?P<loc_80641D6>[0-9a-fx]+)
  vldr	d0, \[r4, #8\]
  vldr	d1, \[pc, #(?P<dbl_just_pi>[0-9a-fx]+)\]
  vmov	r0, r1, d0
  vmov	r2, r3, d1
  bl	#(?P<sub_8086F86>[0-9a-fx]+)
  blo	#(?P<loc_80641D6>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<min_alt_below_home>[0-9a-fx]+)\]
  ldr	r0, \[r4, #0x10\]
  cmp	r0, r1
  bhi	#(?P<loc_80641D6>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<max_alt_above_home>[0-9a-fx]+)\]
  cmp	r0, r1
  bgt	#(?P<loc_80641D6>[0-9a-fx]+)
  ldrsh.w	r0, \[r4, #0x18\]
  cmn.w	r0, #0xb4
  blt	#(?P<loc_80641D6>[0-9a-fx]+)
  cmp	r0, #0xb4
  bgt	#(?P<loc_80641D6>[0-9a-fx]+)
  ldrsh.w	r0, \[r4, #0x1a\]
  cmn.w	r0, #0x384 ; 900
  blt	#(?P<loc_80641D6>[0-9a-fx]+)
  cmp	r0, #0
  bgt	#(?P<loc_80641D6>[0-9a-fx]+)
  ldrb	r0, \[r4, #0x1c\]
  cmp	r0, #2
  blo	#(?P<loc_80641E0>[0-9a-fx]+)
loc_80641D6:
  mov	r1, r5
  adr	r0, #(?P<cstr_wp_data_val_fail>[0-9a-fx]+)
  bl	#(?P<flight_rec_printf_send_c0E>[0-9a-fx]+)
  b	#(?P<loc_806432E>[0-9a-fx]+)
  ; block of code here, 35 words in P3X_FW_V01.07.0060
  dcw	(?P<undefined_varlen_2>([0-9a-fx]+[, ]*){32,48})
  vmov	r0, s0
  ldr	r1, \[pc, #(?P<max_wp_dist_to_home>[0-9a-fx]+)\]
  cmp	r0, r1
  ble	#(?P<loc_806423A>[0-9a-fx]+)
  mov	r1, r5
  adr	r0, #(?P<cstr_wp_dist_too_large>[0-9a-fx]+)
  bl	#(?P<flight_rec_printf_send_c0E>[0-9a-fx]+)
  movs	r0, #0xe6
  b	#(?P<loc_806421C>[0-9a-fx]+)
loc_806423A:
  ldrb	r0, \[r7, #0xd\]
  cmp	r0, #1
  bne	#(?P<loc_8064248>[0-9a-fx]+)
  ldrb	r0, \[r7\]
  subs	r0, r0, #1
  cmp	r0, r5
  beq	#(?P<loc_8064298>[0-9a-fx]+)
loc_8064248:
  ldrb	r0, \[r7, #0xf\]
  cmp	r0, #1
  bne	#(?P<loc_8064298>[0-9a-fx]+)
  vldr	s1, \[r4, #0x14\]
  ldr	r1, \[pc, #(?P<flt_minus_twentytwo_dot_four>[0-9a-fx]+)\]
  vmov	r0, s1
  add	r0, r1
  ldr	r1, \[pc, #(?P<flt_positive_epsylon>[0-9a-fx]+)\]
  cmp	r0, r1
  blo	#(?P<loc_806426A>[0-9a-fx]+)
  ; block of code here, 29 words in P3X_FW_V01.07.0060
  dcw	(?P<undefined_varlen_3>([0-9a-fx]+[, ]*){24,40})
  adds	r5, r5, #1
  uxtb	r5, r5
loc_806429C:
  ldrb	r0, \[r7\]
  cmp	r0, r5
  bhi.w	#(?P<loc_8064142>[0-9a-fx]+)
  bl	#(?P<sub_8064078>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<byte_200081F8>[0-9a-fx]+)\]
  ldr	r1, \[pc, #(?P<max_mission_path_len>[0-9a-fx]+)\]
  vstr	s0, \[r0, #0x2bc\]
  vmov	r0, s0
  cmp	r0, r1
  ble	#(?P<loc_80642D2>[0-9a-fx]+)
  vmov	r0, s0
  bl	#(?P<calculate_cali_matrix>[0-9a-fx]+)
  vmov	d0, r0, r1
  ldr	r0, \[pc, #(?P<cstr_total_dis_too_long>[0-9a-fx]+)\]
  vmov	r2, r3, d0
  bl	#(?P<flight_rec_printf_send_c0E>[0-9a-fx]+)
  movs	r0, #0xe2
  b	#(?P<loc_806421C>[0-9a-fx]+)
; The function continues

""",
'vars': {
  'wp_check_input_mission_validity':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'calculate_cali_matrix':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'flight_rec_printf_send_c0E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'memcpy_0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_8064078':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_808B480':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_8086F86':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'loc_80640E2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_8064122':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_80641D6':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_80641E0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_806423A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_806421C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_8064248':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_806426A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_8064298':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_806429C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_806432E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_806438A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_8064142':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_80642D2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_806421C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'undefined_varlen_2':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (32,48)},
  'undefined_varlen_3':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (24,40)},
  'byte_200084A4':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'byte_20005DF8':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'cstr_debug_log_l1h':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_wp_data_val_fail':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'dbl_just_pi':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'dbl_minus_pi':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'dbl_minus_pi_half':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'dbl_pi_half':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'cstr_wp_dist_too_large':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'flt_minus_twentytwo_dot_four':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT},
  'flt_positive_epsylon':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT},
  'cstr_total_dis_too_long':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'byte_200081F8':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'max_alt_above_home':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "1.0", 'maxValue': "1000000.0", 'defaultValue': "1000.0",
    'description': "Max altitude relative to home point"},
  'min_alt_below_home':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "-1.0", 'maxValue': "-1000000.0", 'defaultValue': "-200.0",
    'description': "Min altitude relative to home point"},
  'max_wp_dist_to_home':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "10.0", 'maxValue': "1000000.0", 'defaultValue': "2000.0",
    'description': "Max distance from one waypoint to home point"},
  'max_mission_path_len':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "10.0", 'maxValue': "1000000.0", 'defaultValue': "30000.0",
    'description': "Max total length of mission"},
  'loc_var_28':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'loc_var_30':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
},
}

re_func_wp_check_input_mission_validity_WM330_V03_01_10_93 = {
'name': "wp_check_input_mission_validity",
'version': "wm330_0306_v03.01.10.93",
're': """
wp_check_input_mission_validity:
  (push[.]w|push)	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){2,8}), lr}
  ldr	(r0|r6), \[pc, #(?P<unk_2042AD08>[0-9a-fx]+)\]
  movs	(r5|r4), #0
  ; this beginning comes from WM100 and WM220; it is different in WM330
  ;movs	r5, #0
  ;ldr	r6, \[pc, #(?P<byte_20428D08>[0-9a-fx]+)\]
  ;ldrb.w	r1, \[r0, #(?P<rel_byte_2042B3B0>[0-9a-fx]+)\]
  ;ldrb	r0, \[r6\]
  ;cmp	r1, r0
  ;bne	#(?P<loc_4ADCD0>[0-9a-fx]+)
  ;add.w	r0, r0, r0, lsl #1
  ;movs	r2, #0x60
  ;add.w	r0, r6, r0, lsl #5
  ;adds	r0, #0x40
  ;add.w	r1, r6, #0x40
  ;bl	#(?P<sub_4BEB10>[0-9a-fx]+)
  ;b	#(?P<loc_4ADECE>[0-9a-fx]+)
  ; this beginning comes from wm220_0306_v03.02.13.12:
  ;movs	r4, #0
  ;ldr	r0, \[pc, #0x180\]
  ;sub	sp, #0x24
  ;adds	r6, #0x10
  ;ldrb.w	r0, \[r0, #0x6ac\]
  ;ldrb	r1, \[r6\]
  ;cmp	r0, r1
  ;beq	#0x4852b4
  ;b	#0x485688
  ;add.w	r0, r4, r4, lsl #1
  ;add.w	r0, r6, r0, lsl #5
  ;vldr	s0, \[r0, #0x54\]
  ;vcvt.f64.f32	d0, s0
  ;vstr	d0, \[sp, #0x18\]
  ;vldr	s0, \[r0, #0x50\]
  ;vcvt.f64.f32	d0, s0
  ;vstr	d0, \[sp, #0x10\]
  ;vldr	d0, \[r0, #0x48\]
  ;vstr	d0, \[sp, #8\]
  ;vldr	d0, \[r0, #0x40\]
  ;vstr	d0, \[sp\]
  ;bl	#0x4c3c4a
  ;ldr	r3, \[r0, #0xc\]
  ;movs	r0, #0x28
  ;adr	r1, #0x13c
  ;mov	r2, r4
  ;blx	r3
  ;adds	r4, r4, #1
  ;uxtb	r4, r4
  ;ldrb	r0, \[r6\]
  ;cmp	r0, r4
  ;bhi	#0x485272
  ;uxtb	r0, r0
  ;ldr	r1, \[pc, #0x74\]
  ;movs	r2, #0x60
  ;add.w	r0, r0, r0, lsl #1
  ;adds	r1, #0x50
  ;add.w	r0, r6, r0, lsl #5
  ;adds	r0, #0x40
  ;bl	#0x4c4076
  ;movs	r5, #0
  ;b	#0x485574
  ; the beginning from WM330 looks like the longer one; not pasted here
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){12,64})
loc_4ADBE8:
  add.w	r0, r5, r5, lsl #1
  add.w	r7, r6, r0, lsl #5
  add.w	r4, r7, #0x40
  vldr	d0, \[r7, #0x40\]
  vldr	d1, \[pc, #(?P<dbl_minus_pi_half>[0-9a-fx]+)\]
  vcmpe.f64	d0, d1
  vmrs	apsr_nzcv, fpscr
  blo	#(?P<loc_val_fail2>[0-9a-fx]+)
  vldr	d1, \[pc, #(?P<dbl_pi_half>[0-9a-fx]+)\]
  vcmpe.f64	d0, d1
  vmrs	apsr_nzcv, fpscr
  ; this comes from WM100 and newer WM220:
  ;bgt	#(?P<loc_val_fail2>[0-9a-fx]+)
  ; in from wm220_0306_v03.02.13.12, there is a long block of data+code, not listed here
  dcw	(?P<undefined_varlen_5>([0-9a-fx]+[, ]*){1,196})
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
  ldr	r2, \[pc, #(?P<max_alt_above_home>[0-9a-fx]+)\]
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
  ; this comes from WM100 and WM220; it is different in WM330
  ;ldrsh.w	r0, \[r4, #0x1e\]
  ;movw	r2, #0x5dc ; 1500
  ;cmn	r0, r2
  ;blt	#(?P<loc_val_fail>[0-9a-fx]+)
  ;cmp	r0, r2
  ;bgt	#(?P<loc_val_fail>[0-9a-fx]+)
  ;ldrb.w	r0, \[r4, #0x20\]
  ;cmp	r0, #3
  ;bhs	#(?P<loc_val_fail>[0-9a-fx]+)
  ;ldrb	r0, \[r4, #0x1c\]
  ;cmp	r0, #2
  ;blo	#(?P<loc_chk_contn1>[0-9a-fx]+)
  ; the block from WM330 is shorter; not pasted here
  dcw	(?P<undefined_varlen_2>([0-9a-fx]+[, ]*){3,20})
loc_val_fail:
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr	r3, \[r0, #0xc\]
  movs	r0, #(?P<log_tag1>[0-9a-fx]+)
  adr	r1, #(?P<cstr_wp_data_val_fail>[0-9a-fx]+)
  mov	r2, r5
  blx	r3
  ; this comes from WM100 and WM220; it is different in WM330
loc_ret1:
  ;pop[.]w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){2,8}), pc}
  dcw	(?P<undefined_varlen_3>([0-9a-fx]+[, ]*){1,48})
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
  movs	r0, #(?P<log_tag2>[0-9a-fx]+)
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
  ; some code and a large data block comes here
  ; in wm220_0306_v03.02.13.12, it is 30 words long; in newer version, much longer
  dcw	(?P<undefined_varlen_4>([0-9a-fx]+[, ]*){28,240})
  adds	r5, r5, #1
  uxtb	r5, r5
loc_4ADECE:
  ldrb	r1, \[r6\]
  cmp	r1, r5
  bhi.w	#(?P<loc_4ADBE8>[0-9a-fx]+)
  bl	#(?P<sub_4AD984>[0-9a-fx]+)
  ldr	r4, \[pc, #(?P<unk_2042B108>[0-9a-fx]+)\]
  vmov	r0, s0
  ldr	r1, \[pc, #(?P<max_mission_path_len>[0-9a-fx]+)\]
  vstr	s0, \[r4, #(?P<rel_unk_var01>[0-9a-fx]+)\]
  cmp	r0, r1
  ble	#(?P<loc_4ADF06>[0-9a-fx]+)
  bl	#(?P<get_logger>[0-9a-fx]+)
  vldr	s0, \[r4, #(?P<rel_unk_var01>[0-9a-fx]+)\]
  ldr	r5, \[r0, #0xc\]
  movs	r0, #(?P<log_tag3>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<cstr_total_dis_too_long>[0-9a-fx]+)\]
  vcvt.f64.f32	d0, s0
  vmov	r2, r3, d0
  blx	r5
  movs	r0, #0xe2
  b	#(?P<loc_ret1>[0-9a-fx]+)
loc_4ADF06:
  movs	r4, #0
  b	#(?P<loc_4ADF30>[0-9a-fx]+)
; The function continues
""",
'vars': {
  'wp_check_input_mission_validity':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'get_logger':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  #'sub_4BEB10':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_4AD984':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'loc_val_fail2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_val_fail':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  #'loc_chk_contn1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  #'loc_4ADCD0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADCEE':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADD0A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADD0E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADD16':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADD36':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADD38':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADE94':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  #'loc_4ADECE':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADBE8':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADF06':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4ADF30':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (12,64)},
  'undefined_varlen_2':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (3,20)},
  'undefined_varlen_3':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,48)},
  'undefined_varlen_4':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (28,240)},
  'undefined_varlen_5':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,196)},
  'log_tag1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T},
  'log_tag2':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T},
  'log_tag3':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T},
  #'byte_20428D08':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'unk_2042AD08':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'cstr_wp_data_val_fail':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'dbl_just_pi':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'dbl_minus_pi':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'dbl_minus_pi_half':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'dbl_pi_half':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'cstr_wp_dist_too_large':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'flt_minus_twentytwo_dot_four':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT},
  'flt_positive_epsylon':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT},
  'cstr_total_dis_too_long':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'unk_2042B108':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'max_alt_above_home':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "1.0", 'maxValue': "1000000.0", 'defaultValue': "1000.0",
    'description': "Max altitude relative to home point"},
  'min_alt_below_home':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "-1.0", 'maxValue': "-1000000.0", 'defaultValue': "-200.0",
    'description': "Min altitude relative to home point"},
  'max_wp_dist_to_home':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "10.0", 'maxValue': "1000000.0", 'defaultValue': "2000.0",
    'description': "Max distance from one waypoint to home point"},
  'max_mission_path_len':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "10.0", 'maxValue': "1000000.0", 'defaultValue': "30000.0",
    'description': "Max total length of mission"},
  #'rel_byte_2042B3B0':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_byte_20428D17':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_unk_var01':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
},
}

re_func_wp_mission_data_verify_P3X_V01_05_0030 = {
'name': "wp_mission_data_verify",
'version': "P3X_FW_V01.05.0030",
're': """
wp_mission_data_verify:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){2,4}), lr}
  ldr	r4, \[pc, #(?P<byte_20005DF8>[0-9a-fx]+)\]
  movs	r1, #0
  vpush	{d8}
  sub	sp, #0xc
  ldrb	r2, \[r0\], #7
  strb	r2, \[r4\]
  ldr	r2, \[r0, #-0x6\]
  str	r2, \[r4, #(?P<rel_dword_20005DFC>[0-9a-fx]+)\]
  ldr	r2, \[r0, #-0x2\]
  str	r2, \[r4, #(?P<rel_dword_20005E00>[0-9a-fx]+)\]
  ldrb	r2, \[r0, #2\]
  strb	r2, \[r4, #(?P<rel_byte_20005E04>[0-9a-fx]+)\]
  ldrb	r2, \[r0, #3\]
  strb	r2, \[r4, #(?P<rel_byte_20005E05>[0-9a-fx]+)\]
  ldrb	r2, \[r0, #4\]
  strb	r2, \[r4, #(?P<rel_byte_20005E06>[0-9a-fx]+)\]
  ldrb	r2, \[r0, #5\]
  strb	r2, \[r4, #(?P<rel_byte_20005E07>[0-9a-fx]+)\]
  ldrb	r2, \[r0, #6\]
  strb	r2, \[r4, #(?P<rel_byte_20005E08>[0-9a-fx]+)\]
  ldrb	r2, \[r0, #7\]
  strb	r2, \[r4, #(?P<rel_byte_20005E09>[0-9a-fx]+)\]
  ldr	r2, \[r0, #8\]
  str	r2, \[sp\]
  ldr	r2, \[r0, #0xc\]
  str	r2, \[sp, #4\]
  vldr	d0, \[sp\]
  vstr	d0, \[r4, #0x18\]
  ldr	r2, \[r0, #0x10\]
  str	r2, \[sp\]
  ldr	r2, \[r0, #0x14\]
  str	r2, \[sp, #4\]
  vldr	d0, \[sp\]
  vstr	d0, \[r4, #0x20\]
  ldr	r2, \[r0, #0x18\]
  str	r2, \[r4, #(?P<rel_dword_20005E20>[0-9a-fx]+)\]
  ldrb	r2, \[r0, #0x1c\]
  subs	r0, r0, #7
  strb.w	r2, \[r4, #(?P<rel_byte_20005E24>[0-9a-fx]+)\]
loc_80643F0:
  adds	r2, r0, r1
  adds	r3, r4, r1
  adds	r1, r1, #1
  ldrb.w	r2, \[r2, #0x24\]
  uxtb	r1, r1
  strb.w	r2, \[r3, #(?P<rel_byte_20005E25>[0-9a-fx]+)\]
  cmp	r1, #0xf
  blo	#(?P<loc_80643F0>[0-9a-fx]+)
  ldrb	r0, \[r4, #(?P<rel_byte_20005E05>[0-9a-fx]+)\]
  movs	r5, #1
  cbnz	r0, #(?P<loc_806440C>[0-9a-fx]+)
  strb	r5, \[r4, #(?P<rel_byte_20005E05>[0-9a-fx]+)\]
  ; the code above isn't really important and can be replaced by variable size data when needed
loc_806440C:
  ldrb	r0, \[r4\]
  subs	r0, r0, #2
  cmp	r0, #0x63
  bhs	#(?P<loc_8064478>[0-9a-fx]+)
  ldr	r0, \[r4, #(?P<rel_dword_20005DFC>[0-9a-fx]+)\]
  cmp.w	r0, #0x40000000 ; 2.0
  blt	#(?P<loc_8064478>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<max_speed_pos>[0-9a-fx]+)\]
  cmp	r0, r1
  bgt	#(?P<loc_8064478>[0-9a-fx]+)
  ldr	r2, \[pc, #(?P<max_speed_neg>[0-9a-fx]+)\]
  ldr	r0, \[r4, #(?P<rel_dword_20005E00>[0-9a-fx]+)\]
  cmp	r0, r2
  bhi	#(?P<loc_8064478>[0-9a-fx]+)
  cmp	r0, r1
  bgt	#(?P<loc_8064478>[0-9a-fx]+)
  ldrb	r0, \[r4, #(?P<rel_byte_20005E04>[0-9a-fx]+)\]
  cmp	r0, #5
  bhs	#(?P<loc_8064478>[0-9a-fx]+)
  ldrb	r0, \[r4, #(?P<rel_byte_20005E06>[0-9a-fx]+)\]
  cmp	r0, #5
  bhs	#(?P<loc_8064478>[0-9a-fx]+)
  ldrb	r0, \[r4, #(?P<rel_byte_20005E07>[0-9a-fx]+)\]
  cmp	r0, #2
  bhs	#(?P<loc_8064478>[0-9a-fx]+)
  ldrb	r0, \[r4, #(?P<rel_byte_20005E08>[0-9a-fx]+)\]
  cmp	r0, #2
  bhs	#(?P<loc_8064478>[0-9a-fx]+)
  ldrb	r0, \[r4, #(?P<rel_byte_20005E09>[0-9a-fx]+)\]
  cmp	r0, #2
  bhs	#(?P<loc_8064478>[0-9a-fx]+)
  vldr	d0, \[r4, #0x18\]
  vldr	d1, \[pc, #(?P<dbl_minus_pi_half>[0-9a-fx-]+)\]
  vmov	r0, r1, d0
  vmov	r2, r3, d1
  bl	#(?P<sub_808B480>[0-9a-fx]+)
  blo	#(?P<loc_8064478>[0-9a-fx]+)
  vldr	d0, \[r4, #0x18\]
  vldr	d1, \[pc, #(?P<dbl_pi_half>[0-9a-fx-]+)\]
  vmov	r0, r1, d0
  vmov	r2, r3, d1
  ; block of code, 187 words in P3X_FW_V01.07.0060 starting with:
  ;bl	#(?P<sub_8086F86>[0-9a-fx]+)
  ; block of code, 189 words in P3X_FW_V01.10.0090 starting with:
  ;b	#0x8064a10
  ;b	#0x8064a6e
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){176,200})
  vldr	d0, \[r4, #0x20\]
  vldr	d1, \[pc, #(?P<dbl_minus_pi>[0-9a-fx-]+)\]
  vmov	r0, r1, d0
  vmov	r2, r3, d1
  bl	#(?P<sub_808B480>[0-9a-fx]+)
  blo	#(?P<loc_8064642>[0-9a-fx]+)
  vldr	d0, \[r4, #0x20\]
  vldr	d1, \[pc, #(?P<dbl_just_pi>[0-9a-fx-]+)\]
  vmov	r0, r1, d0
  vmov	r2, r3, d1
  bl	#(?P<sub_8086F86>[0-9a-fx]+)
  blo	#(?P<loc_8064642>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<min_alt_below_home_inst2>[0-9a-fx]+)\]
  ldr	r0, \[r4, #(?P<rel_dword_20005E20>[0-9a-fx]+)\]
  cmp	r0, r1
  bhi	#(?P<loc_8064642>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<max_alt_above_home_inst2>[0-9a-fx]+)\]
  cmp	r0, r1
  bgt	#(?P<loc_8064642>[0-9a-fx]+)
  ldrb.w	r0, \[r4, #(?P<rel_byte_20005E24>[0-9a-fx]+)\]
  cmp	r0, #2
  bhs	#(?P<loc_8064642>[0-9a-fx]+)
  vldr	s0, \[r4, #8\]
  vldr	s1, \[r4, #4\]
  vabs.f32	s0, s0
  vcmpe.f32	s0, s1
  vmrs	apsr_nzcv, fpscr
  ble	#(?P<loc_8064652>[0-9a-fx]+)
loc_8064642:
  adr	r0, #(?P<cstr_mission_info_data_invalid>[0-9a-fx]+)
  bl	#(?P<flight_rec_printf_send_c0E>[0-9a-fx]+)
  movs	r0, #0xe0
; The function continues
""",
'vars': {
  'wp_mission_data_verify':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'loc_8064478':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_80643F0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_806440C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_8064642':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_8064652':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'sub_808B480':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_8086F86':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_808B480':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_8086F86':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'flight_rec_printf_send_c0E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (176,200)},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'rel_dword_20005DFC':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_dword_20005E00':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_byte_20005E04':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_byte_20005E05':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_byte_20005E06':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_byte_20005E07':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_byte_20005E08':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_byte_20005E09':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_dword_20005E20':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_byte_20005E24':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_byte_20005E25':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'byte_20005DF8':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'dbl_minus_pi_half':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'dbl_pi_half':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'cstr_mission_info_data_invalid':	{'type': VarType.RELATIVE_PC_ADDR_TO_PTR_TO_GLOBAL_DATA, 'variety': DataVariety.CHAR, 'array': "null_term"},
  'dbl_just_pi':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'dbl_minus_pi':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'rel_dword_20005E20':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_byte_20005E24':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'max_speed_pos':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "1.0", 'maxValue': "1000000.0", 'defaultValue': "15.0",
    'description': "Max speed (positive value); in meters per second [m/s]"},
  'max_speed_neg':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "-1.0", 'maxValue': "-1000000.0", 'defaultValue': "-15.0",
    'description': "Max speed (negative value); in meters per second [m/s]"},
  'max_alt_above_home_inst2':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'depend': "max_alt_above_home", 'getter': (lambda val: val)},
  'min_alt_below_home_inst2':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'depend': "min_alt_below_home", 'getter': (lambda val: val)},
},
}

re_func_wp_mission_data_verify_WM330_V03_01_10_93 = {
'name': "wp_mission_data_verify",
'version': "wm330_0306_v03.01.10.93",
're': """
wp_mission_data_verify:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){2,4}), lr}
  ldr	r4, \[pc, #(?P<byte_20428D08>[0-9a-fx]+)\]
  ; block of code, 51 words in wm220_0306_v03.02.35.05
  ; block of code, 42 words in wm330_0306_v03.01.10.93
  ; below code example is from WM100
  ;sub	sp, #0x1c
  ;ldrb	r1, \[r0\]
  ;movs	r3, #0
  ;strb	r1, \[r4\]
  ;ldr.w	r1, \[r0, #1\]
  ;str	r1, \[r4, #4\]
  ;ldr.w	r1, \[r0, #5\]
  ;str	r1, \[r4, #8\]
  ;ldrb	r1, \[r0, #9\]
  ;strb	r1, \[r4, #0xc\]
  ;ldrb	r1, \[r0, #0xa\]
  ;strb	r1, \[r4, #0xd\]
  ;ldrb	r1, \[r0, #0xb\]
  ;strb	r1, \[r4, #0xe\]
  ;ldrb	r1, \[r0, #0xc\]
  ;strb	r1, \[r4, #0xf\]
  ;ldrb	r1, \[r0, #0xd\]
  ;strb	r1, \[r4, #0x10\]
  ;ldrb	r1, \[r0, #0xe\]
  ;strb	r1, \[r4, #0x11\]
  ;ldr.w	r2, \[r0, #0x13\]
  ;ldr.w	r1, \[r0, #0xf\]
  ;strd	r1, r2, \[r4, #0x18\]
  ;ldr.w	r2, \[r0, #0x1b\]
  ;ldr.w	r1, \[r0, #0x17\]
  ;strd	r1, r2, \[r4, #0x20\]
  ;ldr.w	r1, \[r0, #0x1f\]
  ;str	r1, \[r4, #0x28\]
  ;ldrb.w	r1, \[r0, #0x23\]
  ;strb.w	r1, \[r4, #0x2c\]
  ;ldrb.w	r1, \[r0, #0x24\]
  ;strb.w	r1, \[r4, #0x2d\]
  ;ldrh.w	r1, \[r0, #0x25\]
  ;strh	r1, \[r4, #0x2e\]
  ;ldrh.w	r1, \[r0, #0x27\]
  ;strh	r1, \[r4, #0x30\]
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){40,64})
loc_4AE050:
  adds	r1, r0, r3
  adds	r2, r4, r3
  adds	r3, r3, #1
  ldrb.w	r1, \[r1, #(?P<rel_unkn_val1>[0-9a-fx]+)\]
  uxtb	r3, r3
  cmp	r3, #(?P<var_loop_limit1>[0-9a-fx]+) ; 0xa or 0xf
  strb.w	r1, \[r2, #(?P<rel_unkn_val2>[0-9a-fx]+)\]
  blo	#(?P<loc_4AE050>[0-9a-fx]+)
  ldrb	r0, \[r4, #0xd\]
  movs	(r2|r1), #1
  cbnz	r0, #(?P<loc_4AE06C>[0-9a-fx]+)
  strb	(r2|r1), \[r4, #0xd\]
loc_4AE06C:
  ldrb	r0, \[r4\]
  subs	r0, r0, #2
  cmp	r0, #0x63
  bhs	#(?P<loc_4AE12C>[0-9a-fx]+)
  vldr	s5, \[r4, #4\]
  vmov	r0, s5
  cmp.w	r0, #0x40000000 ; 2.0
  blt	#(?P<loc_4AE12C>[0-9a-fx]+)
  vmov	r0, s5
  ldr	r[12], \[pc, #(?P<max_speed_pos>[0-9a-fx]+)\]
  cmp	r0, r[12]
  bgt	#(?P<loc_4AE12C>[0-9a-fx]+)
  vldr	s4, \[r4, #8\]
  ldr	r3, \[pc, #(?P<max_speed_neg>[0-9a-fx]+)\]
  vmov	r0, s4
  cmp	r0, r3
  bhi	#(?P<loc_4AE12C>[0-9a-fx]+)
  vmov	r0, s4
  cmp	r0, r[12] ; either r1 or r2 is used
  bgt	#(?P<loc_4AE12C>[0-9a-fx]+)
  ldrb	r0, \[r4, #0xc\]
  cmp	r0, #(?P<max_unkn1_val>[0-9a-fx]+)
  bhs	#(?P<loc_4AE12C>[0-9a-fx]+)
  ldrb	r0, \[r4, #0xe\]
  cmp	r0, #(?P<max_unkn2_val>[0-9a-fx]+)
  bhs	#(?P<loc_4AE12C>[0-9a-fx]+)
  ldrb	r0, \[r4, #0xf\]
  cmp	r0, #2
  bhs	#(?P<loc_4AE12C>[0-9a-fx]+)
  ldrb	r0, \[r4, #0x10\]
  cmp	r0, #2
  bhs	#(?P<loc_4AE12C>[0-9a-fx]+)
  ldrb	r0, \[r4, #0x11\]
  cmp	r0, #[32]
  bhs	#(?P<loc_4AE12C>[0-9a-fx]+)
  vldr	d0, \[r4, #0x18\]
  vldr	d1, \[pc, #(?P<dbl_minus_pi_half>[0-9a-fx-]+)\]
  vcmpe.f64	d0, d1
  vmrs	apsr_nzcv, fpscr
  blo	#(?P<loc_4AE12C>[0-9a-fx]+)
  vldr	d1, \[pc, #(?P<dbl_pi_half>[0-9a-fx-]+)\]
  vcmpe.f64	d0, d1
  vmrs	apsr_nzcv, fpscr
  bgt	#(?P<loc_4AE12C>[0-9a-fx]+)
  vldr	d0, \[r4, #0x20\]
  vldr	d1, \[pc, #(?P<dbl_minus_pi>[0-9a-fx-]+)\]
  vcmpe.f64	d0, d1
  vmrs	apsr_nzcv, fpscr
  blo	#(?P<loc_4AE12C>[0-9a-fx]+)
  vldr	d1, \[pc, #(?P<dbl_just_pi>[0-9a-fx-]+)\]
  vcmpe.f64	d0, d1
  vmrs	apsr_nzcv, fpscr
  bgt	#(?P<loc_4AE12C>[0-9a-fx]+)
  ldr	r[12], \[pc, #(?P<min_alt_below_home_inst2>[0-9a-fx]+)\]
  ldr	r0, \[r4, #0x28\]
  cmp	r0, r[12]
  bhi	#(?P<loc_4AE12C>[0-9a-fx]+)
  ldr	r[12], \[pc, #(?P<max_alt_above_home_inst2>[0-9a-fx]+)\]
  cmp	r0, r[12]
  bgt	#(?P<loc_4AE12C>[0-9a-fx]+)
  ldrb.w	r0, \[r4, #0x2c\]
  cmp	r0, #2
  bhs	#(?P<loc_4AE12C>[0-9a-fx]+)
""",
're_after': """ ; this code matches WM100 and WM220, but not WM330
  ldrb.w	r0, \[r4, #0x2d\]
  cmp	r0, #3
  bhs	#(?P<loc_4AE12C>[0-9a-fx]+)
  vabs.f32	s0, s4
  vcmpe.f32	s0, s5
  vmrs	apsr_nzcv, fpscr
  ble	#(?P<loc_4AE13E>[0-9a-fx]+)
loc_4AE12C:
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr	r2, \[r0, #0xc\]
  movs	r0, #0x28
; The function continues
""",
'vars': {
  'wp_mission_data_verify':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'loc_4AE050':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4AE06C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4AE12C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  #'loc_4AE13E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  #'get_logger':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (40,64)},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'byte_20428D08':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.UNKNOWN},
  'rel_unkn_val1':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_unkn_val2':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  #'rel_byte_2042B3B0':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'var_loop_limit1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T},
  'max_unkn1_val':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T},
  'max_unkn2_val':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T},
  'dbl_just_pi':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'dbl_minus_pi':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'dbl_minus_pi_half':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'dbl_pi_half':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.DOUBLE},
  'max_speed_pos':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "1.0", 'maxValue': "1000000.0", 'defaultValue': "15.0",
    'description': "Max speed (positive value); in meters per second [m/s]"},
  'max_speed_neg':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "-1.0", 'maxValue': "-1000000.0", 'defaultValue': "-15.0",
    'description': "Max speed (negative value); in meters per second [m/s]"},
  'max_alt_above_home_inst2':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'depend': "max_alt_above_home", 'getter': (lambda val: val)},
  'min_alt_below_home_inst2':	{'type': VarType.RELATIVE_PC_ADDR_TO_GLOBAL_DATA, 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'depend': "min_alt_below_home", 'getter': (lambda val: val)},
},
}

re_func_firmware_release_marking_WM330_V03_01_10_93 = {
'name': "firmware_release_marking",
'version': "wm330_0306_v03.01.10.93",
're': """
  dcb	"(?P<sdk_version>([ ]?SDK-v[1-2][.][0-9]) BETA"
  dcb	" (?P<product_code>(WM[0-9][0-9][0-9])-"
  dcb	"(?P<firmware_version>([0-9][0-9][.][0-9][0-9][.][0-9][0-9][.][0-9][0-9])"
""",
'vars': {
  'sdk_version':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.CHAR, 'array': (8,9)},
  'product_code':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.CHAR, 'array': 5},
  'firmware_version':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.CHAR, 'array': 11,
    'public': "og_hardcoded.flyc", 'minValue': "00.00.00.00", 'maxValue': "99.99.99.99",
    'description': "Firmware version number"},
},
}

re_general_list = [
  {'sect': ".text", 'func': re_func_wp_check_input_mission_validity_P3X_V01_05_0030,},
  {'sect': ".text", 'func': re_func_wp_check_input_mission_validity_WM330_V03_01_10_93,},
  {'sect': ".text", 'func': re_func_wp_mission_data_verify_P3X_V01_05_0030,},
  {'sect': ".text", 'func': re_func_wp_mission_data_verify_WM330_V03_01_10_93,},
  #{'sect': ".data", 'func': re_func_firmware_release_marking_WM330_V03_01_10_93,},
]


def armfw_elf_flyc_list(po, elffh):
    params_list, _, _, _, _, _ = armfw_elf_paramvals_extract_list(po, elffh, re_general_list, 'thumb')
    # print list of parameter values
    armfw_elf_paramvals_export_simple_list(po, params_list, sys.stdout)


def armfw_elf_flyc_mapfile(po, elffh):
    _, params_list, elf_sections, _, _, asm_arch = armfw_elf_paramvals_extract_list(po, elffh, re_general_list, 'thumb')
    armfw_elf_paramvals_export_mapfile(po, params_list, elf_sections, asm_arch, sys.stdout)


def armfw_elf_flyc_extract(po, elffh):
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


def armfw_elf_flyc_update(po, elffh):
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

        armfw_elf_generic_objdump(po, elffh, 'thumb')

        elffh.close();

    elif po.list:

        if (po.verbose > 0):
            print("{}: Opening for list".format(po.elffile))

        elffh = open(po.elffile, "rb")

        armfw_elf_flyc_list(po, elffh)

        elffh.close();

    elif po.mapfile:

        if (po.verbose > 0):
            print("{}: Opening for mapfile generation".format(po.elffile))

        elffh = open(po.elffile, "rb")

        armfw_elf_flyc_mapfile(po, elffh)

        elffh.close();

    elif po.extract:

        if (po.verbose > 0):
            print("{}: Opening for extract".format(po.elffile))

        elffh = open(po.elffile, "rb")

        armfw_elf_flyc_extract(po, elffh)

        elffh.close();

    elif po.update:

        if (po.verbose > 0):
            print("{}: Opening for update".format(po.elffile))

        elffh = open(po.elffile, "r+b")

        armfw_elf_flyc_update(po, elffh)

        elffh.close();

    else:

        raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
    main()
