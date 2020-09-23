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

sys.path.insert(0, './')
from amba_sys_hardcoder import eprint, elf_march_to_asm_config, \
  armfw_elf_whole_section_search, armfw_elf_match_to_public_values, \
  armfw_elf_paramvals_extract_list, armfw_elf_get_value_update_bytes, \
  armfw_elf_paramvals_get_depend_list, armfw_elf_publicval_update, \
  armfw_elf_paramvals_update_list, armfw_elf_generic_objdump, \
  armfw_asm_search_strings_to_re_list, armfw_elf_paramvals_export_json, \
  armfw_elf_paramvals_export_simple_list, armfw_elf_paramvals_export_mapfile, \
  VarType, DataVariety, CodeVariety, DummyStruct


def version_string_to_int_getter(val):
  ver = re.search(r'^([0-9]+)[.]([0-9]+)[.]([0-9]+)[.]([0-9]+)$', val)
  ver_major = int(ver.group(1),10)
  ver_minor = int(ver.group(2),10)
  ver_mmtnc = int(ver.group(3),10)
  ver_revsn = int(ver.group(4),10)
  return (ver_major << 24) + (ver_minor << 16) + (ver_mmtnc << 8) + (ver_revsn)

def version_string_to_parts_getter(val,grp):
  ver = re.search(r'^([0-9]+)[.]([0-9]+)[.]([0-9]+)[.]([0-9]+)$', val)
  return int(ver.group(grp),10)


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
  'byte_200084A4':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'byte_20005DF8':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'cstr_debug_log_l1h':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_wp_data_val_fail':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'dbl_just_pi':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.DOUBLE},
  'dbl_minus_pi':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.DOUBLE},
  'dbl_minus_pi_half':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.DOUBLE},
  'dbl_pi_half':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.DOUBLE},
  'cstr_wp_dist_too_large':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'flt_minus_twentytwo_dot_four':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT},
  'flt_positive_epsylon':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT},
  'cstr_total_dis_too_long':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'byte_200081F8':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'max_alt_above_home':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "1.0", 'maxValue': "1000000.0", 'defaultValue': "1000.0",
    'description': "Max altitude relative to home point"},
  'min_alt_below_home':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "-1.0", 'maxValue': "-1000000.0", 'defaultValue': "-200.0",
    'description': "Min altitude relative to home point"},
  'max_wp_dist_to_home':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "10.0", 'maxValue': "1000000.0", 'defaultValue': "2000.0",
    'description': "Max distance from one waypoint to home point"},
  'max_mission_path_len':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT,
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
  #'byte_20428D08':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_2042AD08':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'cstr_wp_data_val_fail':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'dbl_just_pi':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.DOUBLE},
  'dbl_minus_pi':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.DOUBLE},
  'dbl_minus_pi_half':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.DOUBLE},
  'dbl_pi_half':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.DOUBLE},
  'cstr_wp_dist_too_large':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'flt_minus_twentytwo_dot_four':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT},
  'flt_positive_epsylon':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT},
  'cstr_total_dis_too_long':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'unk_2042B108':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'max_alt_above_home':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "1.0", 'maxValue': "1000000.0", 'defaultValue': "1000.0",
    'description': "Max altitude relative to home point"},
  'min_alt_below_home':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "-1.0", 'maxValue': "-1000000.0", 'defaultValue': "-200.0",
    'description': "Min altitude relative to home point"},
  'max_wp_dist_to_home':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "10.0", 'maxValue': "1000000.0", 'defaultValue': "2000.0",
    'description': "Max distance from one waypoint to home point"},
  'max_mission_path_len':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT,
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
  'wp_mission_data_verify':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
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
  'byte_20005DF8':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'dbl_minus_pi_half':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.DOUBLE},
  'dbl_pi_half':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.DOUBLE},
  'cstr_mission_info_data_invalid':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'dbl_just_pi':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.DOUBLE},
  'dbl_minus_pi':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.DOUBLE},
  'rel_dword_20005E20':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_byte_20005E24':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'max_speed_pos':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "1.0", 'maxValue': "1000000.0", 'defaultValue': "15.0",
    'description': "Max speed (positive value); in meters per second [m/s]"},
  'max_speed_neg':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "-1.0", 'maxValue': "-1000000.0", 'defaultValue': "-15.0",
    'description': "Max speed (negative value); in meters per second [m/s]"},
  'max_alt_above_home_inst2':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'depend': "max_alt_above_home", 'getter': (lambda val: val)},
  'min_alt_below_home_inst2':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT,
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
  'wp_mission_data_verify':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'loc_4AE050':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4AE06C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4AE12C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  #'loc_4AE13E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  #'get_logger':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (40,64)},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'byte_20428D08':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_unkn_val1':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_unkn_val2':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  #'rel_byte_2042B3B0':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'var_loop_limit1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T},
  'max_unkn1_val':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T},
  'max_unkn2_val':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T},
  'dbl_just_pi':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.DOUBLE},
  'dbl_minus_pi':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.DOUBLE},
  'dbl_minus_pi_half':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.DOUBLE},
  'dbl_pi_half':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.DOUBLE},
  'max_speed_pos':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "1.0", 'maxValue': "1000000.0", 'defaultValue': "15.0",
    'description': "Max speed (positive value); in meters per second [m/s]"},
  'max_speed_neg':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'minValue': "-1.0", 'maxValue': "-1000000.0", 'defaultValue': "-15.0",
    'description': "Max speed (negative value); in meters per second [m/s]"},
  'max_alt_above_home_inst2':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'depend': "max_alt_above_home", 'getter': (lambda val: val)},
  'min_alt_below_home_inst2':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.FLOAT,
    'public': "og_hardcoded.flyc", 'depend': "min_alt_below_home", 'getter': (lambda val: val)},
},
}


re_func_firmware_release_marking_WM330_V03_01_10_93 = {
'name': "firmware_release_marking",
'version': "wm330_0306_v03.01.10.93",
# if multiple copies of the pattern are found, make public vars from subsequent ones depend on first
'multiple': "depend",
're': """
  dcb	(?P<starter_odd_even>([0-9a-fx]+[, ]*){2,3})
  dcb	"SDK-v(?P<sdk_version>[1-2][.][0-9]) BETA"
  dcb	" (?P<product_code>[A-Z][A-Z]?[0-9][0-9][0-9])-"
  dcb	"(?P<firmware_version>[0-9][0-9][.][0-9][0-9][.][0-9][0-9][.][0-9][0-9])"
""",
'vars': {
  'starter_odd_even':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T, 'array': (2,3)},
  'sdk_version':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.CHAR, 'array': 3},
  'product_code':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.CHAR, 'array': (4,5)},
  'firmware_version':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.CHAR, 'array': 11,
    'public': "og_hardcoded.flyc", 'minValue': "00.00.00.00", 'maxValue': "99.99.99.99",
    'description': "Firmware version number"},
},
}


re_func_check_activation_authority_WM220_V03_02_13_12 = {
'name': "check_activation_authority",
# No public properties - only here to avoid 'not found' warnings
'version': "wm220_0306_v03.02.13.12",
're': """
check_activation_authority:
  push.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){5,8}), lr}
  movs	r4, r0
  beq	#(?P<loc_510806>[0-9a-fx]+)
  ldr	r0, \[pc, #0x1b4\]
  ldrb.w	r0, \[r0, #0x90f\]
  cmp	r0, #1
  beq	#(?P<loc_51080C>[0-9a-fx]+)
  b	#(?P<loc_510828>[0-9a-fx]+)
loc_510806:
  movs	r0, #1
locret_510808:
  pop.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){5,8}), pc}
loc_51080C:
  ldr	r0, \[r4\]
  sub.w	r1, r0, #0x2700
  subs	r1, #0x66
  beq	#(?P<loc_5108A2>[0-9a-fx]+)
loc_510844:
  ldr	r0, \[r4\]
  bl	#(?P<sub_51078E>[0-9a-fx]+)
  ldr.w	r8, \[pc, #(?P<unkval_4350>[0-9a-fx]+)\]
  movs	r6, #0
  cmp	r0, #2
  mov	r5, r0
  bhs	#(?P<loc_5108B4>[0-9a-fx]+)
  str	r5, \[sp\]
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr	r7, \[r0, #0xc\]
  add.w	r1, r5, r5, lsl #2
  ldr	r0, \[pc, #(?P<dword_20430DD0>[0-9a-fx]+)\]
  ldr	r2, \[r4, #4\]
  add.w	r5, r0, r1, lsl #3
  movs	r0, #8
  adr	r1, #(?P<cstr_req_real>[0-9a-fx]+)
  ldr	r3, \[r5, #4\]
  blx	r7
  strh.w	r6, \[r8\]
  str.w	r6, \[r8, #(?P<rel_dword_20404370>[0-9a-fx]+)\]
  str.w	r6, \[r8, #(?P<rel_dword_2040436C>[0-9a-fx]+)\]
  ldr	r0, \[r4, #4\]
  ldr	r1, \[r5, #4\]
  cmp	r0, r1
  bhi	#(?P<loc_5108B0>[0-9a-fx]+)
  add.w	r0, r5, #8
  mov	r4, r0
  bl	#(?P<dji_sdk_set_key>[0-9a-fx]+)
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr	r3, \[r0, #0xc\]
  movs	r0, #8
  adr	r1, #(?P<cstr_dji_sdk_set_key_val>[0-9a-fx]+)
  mov	r2, r4
  blx	r3
loc_51089E:
  movs	r0, #0
  b	#(?P<locret_510808>[0-9a-fx]+)
loc_5108A2:
  ldr	r0, \[r4, #4\]
  cmp	r0, #2
  bhi	#(?P<loc_5108B0>[0-9a-fx]+)
  adr	r0, #(?P<cstr_dji_demo_lala_haha>[0-9a-fx]+)
  bl	#(?P<dji_sdk_set_key>[0-9a-fx]+)
  b	#(?P<loc_51089E>[0-9a-fx]+)
loc_5108B0:
  movs	r0, #7
  b	#(?P<locret_510808>[0-9a-fx]+)
loc_5108B4:
  ldr	r0, \[r4\]
  mov	r5, r8
  ldr.w	r1, \[r8, #(?P<rel_dword_2040436C>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_5108C8>[0-9a-fx]+)
  str	r0, \[r5, #(?P<rel_dword_2040436C>[0-9a-fx]+)\]
  ldr	r0, \[r4, #4\]
  str	r0, \[r5, #(?P<rel_dword_20404374>[0-9a-fx]+)\]
  strh	r6, \[r5\]
loc_5108C8:
  ldrh	r0, \[r5\]
  adds	r0, r0, #1
  strh	r0, \[r5\]
  mov	r0, r4
  bl	#(?P<sub_4DFB70>[0-9a-fx]+)
  ldrh	r1, \[r5\]
  ldr	r0, \[pc, #(?P<unkval_9DE8>[0-9a-fx]+)\]
  cmp	r1, #0xa
  bhs	#(?P<loc_5108E2>[0-9a-fx]+)
loc_5108DC:
  mov.w	r0, #3
  b	#(?P<locret_510808>[0-9a-fx]+)
loc_5108E2:
  ldr.w	r0, \[r0, #(?P<rel_ctrl_tick>[0-9a-fx]+)\]
  bne	#(?P<loc_5108EC>[0-9a-fx]+)
  str	r0, \[r5, #(?P<rel_dword_20404378>[0-9a-fx]+)\]
  b	#(?P<loc_5108FC>[0-9a-fx]+)
loc_5108EC:
  ldr	r1, \[r5, #(?P<rel_dword_20404378>[0-9a-fx]+)\]
  sub.w	r0, r0, r1
  cmp.w	r0, #0x1f4 ; #500
  bls	#(?P<loc_5108FC>[0-9a-fx]+)
  strh	r6, \[r5\]
  b	#(?P<loc_5108DC>[0-9a-fx]+)
loc_5108FC:
  ldr	r0, \[r5, #(?P<rel_dword_20404370>[0-9a-fx]+)\]
  cmp	r0, #1
  beq	#(?P<loc_510908>[0-9a-fx]+)
  cbz	r0, #(?P<loc_51090C>[0-9a-fx]+)
  movs	r0, #6
  b	#(?P<locret_510808>[0-9a-fx]+)
loc_510908:
  movs	r0, #5
  b	#(?P<locret_510808>[0-9a-fx]+)
loc_51090C:
  movs	r0, #4
  b	#(?P<locret_510808>[0-9a-fx]+)
""",
'vars': {
  'check_activation_authority':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'dji_sdk_set_key':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'get_logger':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_4DFB70':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_51078E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'loc_510806':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_51080C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_510828':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_51089E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108A2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108B0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108B4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108C8':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108DC':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108E2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108EC':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108FC':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_510908':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_51090C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'locret_510808':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'cstr_dji_demo_lala_haha':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_dji_sdk_set_key_val':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_req_real':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'dword_20430DD0':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T},
  'rel_ctrl_tick':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_dword_2040436C':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_dword_20404370':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_dword_20404374':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_dword_20404378':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_word_20404352':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'unkval_4350':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unkval_9DE8':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
},
}

re_func_check_activation_authority_WM220_V03_01_10_93 = {
'name': "check_activation_authority",
'version': "wm220_0306_v03.01.10.93",
're': """
check_activation_authority:
  push.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){6,8}), lr}
  movs	r4, r0
  beq	#(?P<loc_510806>[0-9a-fx]+)
  bl	#(?P<get_config>[0-9a-fx]+)
  ldr	r1, \[r0, #0xc\]
  movs	r0, #(?P<CONFIG_VAR_37a>[0-9a-fx]+)
  blx	r1
  ldrb.w	r0, \[r0, #0x26\]
  cmp	r0, #1
  beq	#(?P<loc_51080C>[0-9a-fx]+)
  b	#(?P<loc_510828>[0-9a-fx]+)
loc_510806:
  movs	r0, #1
locret_510808:
  pop.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){6,8}), pc}
loc_51080C:
  ldr	r6, \[pc, #(?P<mc_version_1>[0-9a-fx]+)\]
  ldr	r0, \[r4, #8\]
  cmp	r0, r6
  ; block of code, in wm330_0306_v03.01.10.93:
  ;beq	#(?P<loc_510828>[0-9a-fx]+)
  ; block of code, in wm100_0306_v03.02.43.20:
  ;beq	#(?P<loc_510828>[0-9a-fx]+)
  ;cmp.w   r0, #0x50505050
  ;beq	#(?P<loc_510828>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){1,8})
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr	r5, \[r0, #4\]
  movs	r0, #8
  adr	r1, #(?P<cstr_sdk_version_error>[0-9a-fx]+)
  ldr	r2, \[r4, #8\]
  mov	r3, r6
  blx	r5
  movs	r0, #8
  b	#(?P<locret_510808>[0-9a-fx]+)
loc_510828:
  bl	#(?P<get_config>[0-9a-fx]+)
  ldr	r1, \[r0, #0xc\]
  movs	r0, #(?P<CONFIG_VAR_37b>[0-9a-fx]+)
  blx	r1
  ldrb.w	r0, \[r0, #0x23\]
  cmp	r0, #1
  bne	#(?P<loc_510844>[0-9a-fx]+)
  ldr	r0, \[r4\]
  sub.w	r1, r0, #0x2700
  subs	r1, #0x66
  beq	#(?P<loc_5108A2>[0-9a-fx]+)
loc_510844:
  ldr	r0, \[r4\]
  bl	#(?P<sub_51078E>[0-9a-fx]+)
  ldr.w	r8, \[pc, #(?P<unkval_4350>[0-9a-fx]+)\]
  movs	r6, #0
  cmp	r0, #2
  mov	r5, r0
  bhs	#(?P<loc_5108B4>[0-9a-fx]+)
  str	r5, \[sp\]
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr	r7, \[r0, #0xc\]
  add.w	r1, r5, r5, lsl #2
  ldr	r0, \[pc, #(?P<dword_20430DD0>[0-9a-fx]+)\]
  ldr	r2, \[r4, #4\]
  add.w	r5, r0, r1, lsl #3
  movs	r0, #8
  adr	r1, #(?P<cstr_req_real>[0-9a-fx]+)
  ldr	r3, \[r5, #4\]
  blx	r7
  strh.w	r6, \[r8, #(?P<rel_word_20404352>[0-9a-fx]+)\]
  str.w	r6, \[r8, #(?P<rel_dword_20404370>[0-9a-fx]+)\]
  str.w	r6, \[r8, #(?P<rel_dword_2040436C>[0-9a-fx]+)\]
  ldr	r0, \[r4, #4\]
  ldr	r1, \[r5, #4\]
  cmp	r0, r1
  bhi	#(?P<loc_5108B0>[0-9a-fx]+)
  add.w	r0, r5, #8
  mov	r4, r0
  bl	#(?P<dji_sdk_set_key>[0-9a-fx]+)
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr	r3, \[r0, #0xc\]
  movs	r0, #8
  adr	r1, #(?P<cstr_dji_sdk_set_key_val>[0-9a-fx]+)
  mov	r2, r4
  blx	r3
loc_51089E:
  movs	r0, #0
  b	#(?P<locret_510808>[0-9a-fx]+)
loc_5108A2:
  ldr	r0, \[r4, #4\]
  cmp	r0, #2
  bhi	#(?P<loc_5108B0>[0-9a-fx]+)
  adr	r0, #(?P<cstr_dji_demo_lala_haha>[0-9a-fx]+)
  bl	#(?P<dji_sdk_set_key>[0-9a-fx]+)
  b	#(?P<loc_51089E>[0-9a-fx]+)
loc_5108B0:
  movs	r0, #7
  b	#(?P<locret_510808>[0-9a-fx]+)
loc_5108B4:
  ldr	r0, \[r4\]
  mov	r5, r8
  ldr.w	r1, \[r8, #(?P<rel_dword_2040436C>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_5108C8>[0-9a-fx]+)
  str	r0, \[r5, #(?P<rel_dword_2040436C>[0-9a-fx]+)\]
  ldr	r0, \[r4, #4\]
  str	r0, \[r5, #(?P<rel_dword_20404374>[0-9a-fx]+)\]
  strh	r6, \[r5, #(?P<rel_word_20404352>[0-9a-fx]+)\]
loc_5108C8:
  ldrh	r0, \[r5, #(?P<rel_word_20404352>[0-9a-fx]+)\]
  adds	r0, r0, #1
  strh	r0, \[r5, #(?P<rel_word_20404352>[0-9a-fx]+)\]
  mov	r0, r4
  bl	#(?P<sub_4DFB70>[0-9a-fx]+)
  ldrh	r1, \[r5, #(?P<rel_word_20404352>[0-9a-fx]+)\]
  ldr	r0, \[pc, #(?P<unkval_9DE8>[0-9a-fx]+)\]
  cmp	r1, #0xa
  bhs	#(?P<loc_5108E2>[0-9a-fx]+)
loc_5108DC:
  mov.w	r0, #3
  b	#(?P<locret_510808>[0-9a-fx]+)
loc_5108E2:
  ; block of code, in wm330_0306_v03.01.10.93:
  ;ldr.w	r0, \[r0, #(?P<rel_ctrl_tick>[0-9a-fx]+)\]
  ; block of code and data, in wm100_0306_v03.02.43.20:
  ;b	#(?P<loc_5108E8>[0-9a-fx]+)
  ;[...] - block of data here
  ;loc_5108E8:
  ;ldr.w	r0, \[r0, #(?P<rel_ctrl_tick>[0-9a-fx]+)\]
  dcw	(?P<undefined_varlen_2>([0-9a-fx]+[, ]*){1,204})
  bne	#(?P<loc_5108EC>[0-9a-fx]+)
  str	r0, \[r5, #(?P<rel_dword_20404378>[0-9a-fx]+)\]
  b	#(?P<loc_5108FC>[0-9a-fx]+)
loc_5108EC:
  ldr	r1, \[r5, #(?P<rel_dword_20404378>[0-9a-fx]+)\]
  sub.w	r0, r0, r1
  cmp.w	r0, #0x1f4 ; #500
  bls	#(?P<loc_5108FC>[0-9a-fx]+)
  strh	r6, \[r5, #2\]
  b	#(?P<loc_5108DC>[0-9a-fx]+)
loc_5108FC:
  ldr	r0, \[r5, #(?P<rel_dword_20404370>[0-9a-fx]+)\]
  cmp	r0, #1
  beq	#(?P<loc_510908>[0-9a-fx]+)
  cbz	r0, #(?P<loc_51090C>[0-9a-fx]+)
  movs	r0, #6
  b	#(?P<locret_510808>[0-9a-fx]+)
loc_510908:
  movs	r0, #5
  b	#(?P<locret_510808>[0-9a-fx]+)
loc_51090C:
  movs	r0, #4
  b	#(?P<locret_510808>[0-9a-fx]+)
""",
'vars': {
  'check_activation_authority':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'dji_sdk_set_key':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'get_config':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'get_logger':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_4DFB70':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_51078E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'loc_510806':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_51080C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_510828':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_510844':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_51089E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108A2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108B0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108B4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108C8':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108DC':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108E2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108EC':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108FC':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_510908':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_51090C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'locret_510808':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,8)},
  'undefined_varlen_2':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,204)},
  'CONFIG_VAR_37a':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T},
  'CONFIG_VAR_37b':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T},
  'cstr_dji_demo_lala_haha':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_dji_sdk_set_key_val':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_req_real':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_sdk_version_error':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'dword_20430DD0':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T},
  'rel_ctrl_tick':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_dword_2040436C':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_dword_20404370':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_dword_20404374':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_dword_20404378':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_word_20404352':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'unkval_4350':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unkval_9DE8':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'mc_version_1':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': version_string_to_int_getter},
},
}

re_func_check_activation_authority_WM330_V03_01_10_93 = {
'name': "check_activation_authority",
'version': "wm330_0306_v03.01.10.93",
're': """
check_activation_authority:
  push.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){5,8}), lr}
  movs	r4, r0
  beq	#(?P<loc_510806>[0-9a-fx]+)
  ldr	(?P<regB>r[0-9]), \[pc, #(?P<mc_version_1>[0-9a-fx]+)\]
  ldr	(?P<regC>r[0-9]), \[r4, #8\]
  cmp	(?P<regC>r[0-9]), (?P<regB>r[0-9])
  beq	#(?P<loc_510828>[0-9a-fx]+)
  ; block of code, in P3X_FW_V01.07.0060_m0306:
  ;movs	r0, #8
  ; block of code, in wm330_0306_v03.01.10.93:
  ;movs	r0, #0x70
  ;adr	r1, #(?P<cstr_sdk_version_error>[0-9a-fx]+)
  ;bl	#(?P<log_printf_debug>[0-9a-fx]+)
  ;movs	r0, #8
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){1,8})
locret_510808:
  pop.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){5,8}), pc}
loc_510806:
  movs	r0, #1
  b	#(?P<locret_510808>[0-9a-fx]+)
loc_510828:
  ldr	r0, \[pc, #(?P<g_real__aircraft_status>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_g_real__config__api_entry_cfg__cheat_backdoor>[0-9a-fx]+)\]
  cmp	r0, #1
  bne	#(?P<loc_510844>[0-9a-fx]+)
  ldr	r0, \[r4\]
  sub.w	r1, r0, #0x2700
  subs	r1, #0x66
  ; block of code, in P3X_FW_V01.07.0060_m0306:
  ;bne	#(?P<loc_510844>[0-9a-fx]+)
  ;ldr	r0, \[r4, #4\]
  ;cmp	r0, #2
  ;bhi	#(?P<loc_5108B0>[0-9a-fx]+)
  ;adr	r0, #(?P<cstr_dji_demo_lala_haha>[0-9a-fx]+)
  ;bl	#(?P<dji_sdk_set_key>[0-9a-fx]+)
  ;b	#(?P<loc_51089E>[0-9a-fx]+)
  ; block of code, in wm330_0306_v03.01.10.93:
  ;beq	#(?P<loc_5108A2>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_2>([0-9a-fx]+[, ]*){1,12})
loc_510844:
  ldr	r0, \[r4\]
  bl	#(?P<sub_51078E>[0-9a-fx]+)
  ; block of code, in P3X_FW_V01.07.0060_m0306:
  ;movs	r5, #0
  ;ldr	r7, \[pc, #(?P<unkval_4350>[0-9a-fx]+)\]
  ;mov	r3, r0
  ;cmp	r0, #2
  ; block of code, in wm330_0306_v03.01.10.93:
  ;ldr	r7, \[pc, #(?P<unkval_4350>[0-9a-fx]+)\]
  ;movs	r5, #0
  ;cmp	r0, #2
  ;mov	r3, r0
  dcw	(?P<undefined_varlen_3>([0-9a-fx]+[, ]*){1,6})
  bhs	#(?P<loc_5108B4>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<dword_20430DD0>[0-9a-fx]+)\]
  add.w	r1, r3, r3, lsl #2
  add.w	r6, r0, r1, lsl #3
  ; block of code, in P3X_FW_V01.07.0060_m0306:
  ;adr	r0, #(?P<cstr_req_real>[0-9a-fx]+)
  ;ldr	r2, \[r6, #4\]
  ;ldr	r1, \[r4, #4\]
  ; block of code, in wm330_0306_v03.01.10.93:
  ;ldr	r1, \[r4, #4\]
  ;adr	r0, #(?P<cstr_req_real>[0-9a-fx]+)
  ;ldr	r2, \[r6, #4\]
  dcw	(?P<undefined_varlen_4>([0-9a-fx]+[, ]*){3,4})
  bl	#(?P<log_printf>[0-9a-fx]+)
  strh	r5, \[r7\]
  str	r5, \[r7, #(?P<rel_dword_20404370>[0-9a-fx]+)\]
  str	r5, \[r7, #(?P<rel_dword_2040436C>[0-9a-fx]+)\]
  ldr	r0, \[r4, #4\]
  ldr	r1, \[r6, #4\]
  cmp	r0, r1
  bhi	#(?P<loc_5108B0>[0-9a-fx]+)
  add.w	r0, r6, #8
  mov	r4, r0
  bl	#(?P<dji_sdk_set_key>[0-9a-fx]+)
  ; block of code, in P3X_FW_V01.07.0060_m0306:
  ;mov	r1, r4
  ;adr	r0, #(?P<cstr_dji_sdk_set_key_val>[0-9a-fx]+)
  ; block of code, in wm330_0306_v03.01.10.93:
  ;adr	r0, #(?P<cstr_dji_sdk_set_key_val>[0-9a-fx]+)
  ;mov	r1, r4
  dcw	(?P<undefined_varlen_5>([0-9a-fx]+[, ]*){2,4})
  bl	#(?P<log_printf>[0-9a-fx]+)
loc_51089E:
  movs	r0, #0
  ; block of code, in P3X_FW_V01.07.0060_m0306:
  ;b	#(?P<locret_510808>[0-9a-fx]+)
  ; block of code, in wm330_0306_v03.01.10.93:
  ;b	#(?P<locret_510808>[0-9a-fx]+)
  ;loc_5108A2:
  ;ldr	r0, \[r4, #4\]
  ;cmp	r0, #2
  ;bhi	#(?P<loc_5108B0>[0-9a-fx]+)
  ;adr	r0, #(?P<cstr_dji_demo_lala_haha>[0-9a-fx]+)
  ;bl	#(?P<dji_sdk_set_key>[0-9a-fx]+)
  ;b	#(?P<loc_51089E>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_6>([0-9a-fx]+[, ]*){1,16})
loc_5108B0:
  movs	r0, #7
  b	#(?P<locret_510808>[0-9a-fx]+)
loc_5108B4:
  ldr	r0, \[r4\]
  ldr	r1, \[r7, #(?P<rel_dword_2040436C>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_5108C8>[0-9a-fx]+)
  str	r0, \[r7, #(?P<rel_dword_2040436C>[0-9a-fx]+)\]
  ldr	r0, \[r4, #4\]
  str	r0, \[r7, #(?P<rel_dword_20404374>[0-9a-fx]+)\]
  strh	r5, \[r7\]
loc_5108C8:
  ldrh	r0, \[r7\]
  adds	r0, r0, #1
  strh	r0, \[r7\]
  mov	r0, r4
  bl	#(?P<sub_4DFB70>[0-9a-fx]+)
  ldrh	r1, \[r7\]
  ldr	r0, \[pc, #(?P<unkval_9DE8>[0-9a-fx]+)\]
  cmp	r1, #0xa
  bhs	#(?P<loc_5108E2>[0-9a-fx]+)
loc_5108DC:
  mov.w	r0, #3
  b	#(?P<locret_510808>[0-9a-fx]+)
loc_5108E2:
  ; block of code, in P3X_FW_V01.07.0060_m0306:
  ;ldr	r0, \[r0\]
  ; block of code, in wm330_0306_v03.01.10.93:
  ;ldr.w	r0, \[r0, #(?P<rel_ctrl_tick>[0-9a-fx]+)\]
  dcw	(?P<undefined_varlen_7>([0-9a-fx]+[, ]*){1,204})
  bne	#(?P<loc_5108EC>[0-9a-fx]+)
  str	r0, \[r7, #(?P<rel_dword_20404378>[0-9a-fx]+)\]
  b	#(?P<loc_5108FC>[0-9a-fx]+)
loc_5108EC:
  ldr	r1, \[r7, #(?P<rel_dword_20404378>[0-9a-fx]+)\]
  sub.w	r0, r0, r1
  cmp.w	r0, #0x1f4 ; #500
  bls	#(?P<loc_5108FC>[0-9a-fx]+)
  strh	r5, \[r7\]
  b	#(?P<loc_5108DC>[0-9a-fx]+)
loc_5108FC:
  ldr	r0, \[r7, #(?P<rel_dword_20404370>[0-9a-fx]+)\]
  cmp	r0, #1
  beq	#(?P<loc_510908>[0-9a-fx]+)
  cbz	r0, #(?P<loc_51090C>[0-9a-fx]+)
  movs	r0, #6
  b	#(?P<locret_510808>[0-9a-fx]+)
loc_510908:
  movs	r0, #5
  b	#(?P<locret_510808>[0-9a-fx]+)
loc_51090C:
  movs	r0, #4
  b	#(?P<locret_510808>[0-9a-fx]+)
""",
'vars': {
  'check_activation_authority':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'dji_sdk_set_key':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'log_printf_debug':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'log_printf':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_4DFB70':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_51078E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'loc_510806':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_510828':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_510844':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_51089E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108A2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108B0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108B4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108C8':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108DC':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108E2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108EC':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5108FC':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_510908':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_51090C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'locret_510808':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regB':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regC':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,8)},
  'undefined_varlen_2':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,12)},
  'undefined_varlen_3':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,6)},
  'undefined_varlen_4':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (3,4)},
  'undefined_varlen_5':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (2,4)},
  'undefined_varlen_6':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,16)},
  'undefined_varlen_7':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,204)},
  #'CONFIG_VAR_37a':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T},
  #'CONFIG_VAR_37b':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T},
  'cstr_dji_demo_lala_haha':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_dji_sdk_set_key_val':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_req_real':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_sdk_version_error':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'dword_20430DD0':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T},
  'g_real__aircraft_status':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.STRUCT, 'struct': DummyStruct,},
  'rel_g_real__config__api_entry_cfg__cheat_backdoor':	{'type': VarType.RELATIVE_OFFSET, 'baseaddr': "g_real__aircraft_status+", 'variety': DataVariety.UNKNOWN},
  #'rel_ctrl_tick':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_dword_2040436C':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_dword_20404370':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_dword_20404374':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_dword_20404378':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'unkval_4350':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unkval_9DE8':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'mc_version_1':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': version_string_to_int_getter},
},
}


re_func_system_init_P3X_FW_V01_07_0060 = {
'name': "system_init",
'alt_name': "imu_init",
'version': "P3X_FW_V01.07.0060",
're': """
system_init:
  push	{r4, lr}
  bl	#(?P<hal_push_mc_version>[0-9a-fx]+)
  bl	#(?P<init_sub_7E88>[0-9a-fx]+)
  bl	#(?P<init_sub_CB9A>[0-9a-fx]+)
  bl	#(?P<init_sub_185C>[0-9a-fx]+)
  bl	#(?P<init_sub_61CA>[0-9a-fx]+)
  bl	#(?P<init_led>[0-9a-fx]+)
  bl	#(?P<init_fitler>[0-9a-fx]+)
  bl	#(?P<init_sub_CC58>[0-9a-fx]+)
  bl	#(?P<init_sub_17C4>[0-9a-fx]+)
  bl	#(?P<init_sub_142A>[0-9a-fx]+)
  bl	#(?P<init_sub_2E3E>[0-9a-fx]+)
  bl	#(?P<init_sub_9580>[0-9a-fx]+)
  bl	#(?P<request_esc_real_states>[0-9a-fx]+)
  bl	#(?P<init_temp_cali>[0-9a-fx]+)
  bl	#(?P<init_sub_FE48>[0-9a-fx]+)
  pop.w	{r4, lr}
  b.w	#(?P<init_sub_2052>[0-9a-fx]+)
""",
'vars': {
  'system_init':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'hal_push_mc_version':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'init_sub_7E88':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'init_sub_CB9A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'init_sub_185C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'init_sub_61CA':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'init_led':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'init_fitler':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'init_sub_CC58':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'init_sub_17C4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'init_sub_142A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'init_sub_2E3E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'init_sub_9580':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'request_esc_real_states':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'init_temp_cali':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'init_sub_FE48':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'init_sub_2052':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
},
}

re_func_imu_init_WM220_V03_01_10_93 = {
'name': "imu_init",
'alt_name': "system_init",
'version': "wm220_0306_v03.01.10.93",
're': """
imu_init:
  push.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){7,10}), lr}
  sub	sp, #0x64
  ; block of code, in wm220_0306_v03.02.13.12, 12 words:
  ;bl	#0x5130f2
  ;bl	#(?P<nullsub_53>[0-9a-fx]+)
  ;ldr.w	fp, \[pc, #0x374\]
  ;movs	r6, #0
  ;ldr	r5, \[pc, #0x370\]
  ;mov.w	sb, #1
  ;mov	r8, r6
  ;loc_527BC4:
  ;movs	r0, #0xbb
  ;muls	r0, r6, r0
  ;add.w	r4, fp, r0, lsl #3
  ;ldr.w	r0, \[r4, #(?P<unkstru_r4_field_46C>[0-9a-fx]+)\]
  ; block of code and data, in wm220_0306_v03.02.35.05, 290 words:
  ;movs	r1, #0x58
  ;add	r0, sp, #8
  ;bl	#(?P<memset_zero>[0-9a-fx]+)
  ;movs	r7, #0
  ;bl	#(?P<nullsub_53>[0-9a-fx]+)
  ;bl	#(?P<sub_50BF40>[0-9a-fx]+)
  ;ldr.w	sl, \[pc, #(?P<imu_groups_p4>[0-9a-fx]+)\]
  ;sub.w	sl, sl, #0xc
  ;str.w	r0, \[sl, #(?P<rel_dword_20404528>[0-9a-fx]+)\]
  ;bl	#(?P<getSystemTimerTickRate>[0-9a-fx]+)
  ;movs	r3, #0
  ;str	r0, \[r4\]
  ;mov	r2, r3
  ;mov	r1, r3
  ;subw	r0, pc, #(?P<sub_526EFA>[0-9a-fx]+) ; or adr.w	r0, (sub_526EFA+1)
  ;bl	#(?P<timer_event_enable>[0-9a-fx]+)
  ;ldr.w	r8, \[pc, #(?P<printf_s>[0-9a-fx]+)\]
  ;movs	r6, #1
  ;ldr.w	fp, \[pc, #(?P<unkvar_01>[0-9a-fx]+)\]
  ;movs	r5, #0
  ;loc_527BC4:
  ;rsb	r0, r7, r7, lsl #3
  ;add.w	r1, r0, r7, lsl #6
  ;ldr	r0, \[pc, #(?P<imu_groups>[0-9a-fx]+)\]
  ;add.w	r4, r0, r1, lsl #4
  ;ldr.w	r0, \[r4, #(?P<unkstru_r4_field_46C>[0-9a-fx]+)\]
  ;b	#(?P<loc_527DDC>[0-9a-fx]+)
  ;dcd	(?P<ptr_unk_5848FC>[0-9a-fx]+)
  ;dcb	"miscali_%d ", 0
  ;dcb	"miscali_init_cfg miscali_%d",0
  ;[...]
  ;dcd	(?P<ptr_printf_s>[0-9a-fx]+)
  ;dcd	(?P<ptr_unkvar_01>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_01>([0-9a-fx]+[, ]*){10,580})
  cbnz	r0, #(?P<loc_527DEA>[0-9a-fx]+)
  ; block of code, in wm220_0306_v03.02.13.12, same as:
  ; block of code, in wm220_0306_v03.02.35.05, 1 word:
  ;subw	r0, pc, #(?P<cstr_link_manual_cali_neg>[0-9a-fx]+)
  ; block of code, in wm220_0306_v03.02.44.07, 1 word:
  ;adr	r0, #(?P<cstr_link_manual_cali>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_18>([0-9a-fx]+[, ]*){1,2})
  bl	#(?P<get_link_by_name>[0-9a-fx]+)
  str.w	r0, \[r4, #(?P<unkstru_r4_field_46C>[0-9a-fx]+)\]
loc_527DEA:
  ; block of code, in wm220_0306_v03.02.13.12, 37 words:
  ;movs	r7, #0
  ;loc_513EDC:
  ;movs	r3, #1
  ;rsb	r1, r7, r7, lsl #3
  ;movs	r2, #0x10
  ;add.w	r0, r4, r1, lsl #4
  ;add.w	r1, r0, #0x6c
  ;adds	r0, #0xac
  ;bl	#0x426702
  ;adds	r7, r7, #1
  ;cmp	r7, #8
  ;blo	#(?P<loc_513EDC>[0-9a-fx]+)
  ;movs	r0, #0
  ;loc_513EFA:
  ;rsb	r2, r0, r0, lsl #3
  ;add.w	r1, r4, r2, lsl #4
  ;ldr	r1, \[r1, #0x68\]
  ;cbnz	r1, #(?P<loc_513F0A>[0-9a-fx]+)
  ;cmp	r0, #7
  ;bne	#(?P<loc_514008>[0-9a-fx]+)
  ;loc_513F0A:
  ;adds	r0, r0, #1
  ;cmp	r0, #8
  ;blo	#0x513efa
  ;ldr.w	r0, \[r4, #0x3e8\]
  ;subs	r0, r0, #1
  ;cmp.w	r0, #0x1f40
  ;bhs	#(?P<loc_514008>[0-9a-fx]+)
  ;ldr.w	ip, \[r5\]
  ; block of code and data, in wm220_0306_v03.02.35.05:
  ;mov	r0, r7
  ;bl	#(?P<sub_526D10>[0-9a-fx]+)
  ;cmp	r0, #0
  ;bge	#(?P<loc_527E08>[0-9a-fx]+)
  ;ldrb	r0, \[r4, #0x1c\]
  ;movs	r1, #3
  ;orr	r0, r0, #0x900000
  ;bl	#(?P<open_device>[0-9a-fx]+)
  ;str	r0, \[r4, #0x64\]
  ;strb.w	r5, \[r4, #0x6c\]
  ;b	#(?P<loc_527E0E>[0-9a-fx]+)
  ;loc_527E08:
  ;str	r5, \[r4, #0x64\]
  ;strb.w	r6, \[r4, #0x6c\]
  ;loc_527E0E:
  ;mov	r0, r7
  ;bl	#(?P<sub_526D52>[0-9a-fx]+)
  ;cmp	r0, #0
  ;bge	#(?P<loc_527E2C>[0-9a-fx]+)
  ;ldrb	r0, \[r4, #0x1d\]
  ;movs	r1, #3
  ;orr	r0, r0, #0x910000
  ;bl	#(?P<open_device>[0-9a-fx]+)
  ;str	r0, \[r4, #0x68\]
  ;strb.w	r5, \[r4, #0x6d\]
  ;b	#(?P<loc_527E32>[0-9a-fx]+)
  ;loc_527E2C:
  ;str	r5, \[r4, #0x68\]
  ;strb.w	r6, \[r4, #0x6d\]
  ;loc_527E32:
  ;ldr	r0, \[r4, #0x64\]
  ;cbnz	r0, #(?P<loc_527E3E>[0-9a-fx]+)
  ;ldrb.w	r0, \[r4, #0x6c\]
  ;cmp	r0, #0
  ;beq	#(?P<loc_527ED8>[0-9a-fx]+)
  ;loc_527E3E:
  ;ldr	r0, \[r4, #0x68\]
  ;cbnz	r0, #(?P<loc_527E4A>[0-9a-fx]+)
  ;ldrb.w	r0, \[r4, #0x6d\]
  ;cmp	r0, #0
  ;beq	#(?P<loc_527ED8>[0-9a-fx]+)
  ;loc_527E4A:
  ;ldr.w	r3, \[r8\]
  dcw	(?P<undefined_varlen_02>([0-9a-fx]+[, ]*){32,64})
  movs	r0, #7
  adr	r1, #(?P<cstr_imu_group_ok1>[0-9a-fx]+)
  ; block of code, in wm220_0306_v03.02.13.12:
  ;ldr.w	r3, \[r4, #0x3e8\]
  ;mov	r7, r8
  ;mov	r2, r6
  ; block of code and data, in wm220_0306_v03.02.35.05:
  ;mov	r2, r7
  dcw	(?P<undefined_varlen_03>([0-9a-fx]+[, ]*){1,6})
  blx	(r3|ip)
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr(.w)?	(r3|ip), \[r0, #0xc\]
  movs	r0, #0x39
  adr	r1, #(?P<cstr_imu_group_ok2>[0-9a-fx]+)
  ; block of code, in wm220_0306_v03.02.13.12:
  ;ldr.w	r3, \[r4, #0x3e8\]
  ;mov	r2, (r7|r6)
  ; block of code and data, in wm220_0306_v03.02.35.05:
  ;mov	r2, (r7|r6)
  dcw	(?P<undefined_varlen_04>([0-9a-fx]+[, ]*){1,4})
  blx	(r3|ip)
  movs	r1, #0xe0
  add.w	r0, r4, #(?P<unkstru_r4_field_350>[0-9a-fx]+)
  bl	#(?P<memset_zero>[0-9a-fx]+)
  add[.]?w	r0, r4, #(?P<unkstru_r4_field_70>[0-9a-fx]+)
  movs	r1, #0x38
  mov	(sb|sl), r0
  bl	#(?P<memset_zero>[0-9a-fx]+)
  add.w	r1, r4, #(?P<unkstru_r4_field_20>[0-9a-fx]+)
  ldr.w	r0, \[(sl|r4), #(?P<rel_dword_20404528>[0-9a-fx]+)\]
  movs	r3, #0
  mov	r2, (r7|r6)
  strd	r0, r1, \[sp\]
  adds	r1, r4, #4
  add	r0, sp, #8
  bl	#(?P<sub_5273E2>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<dword_20404358>[0-9a-fx]+)\]
  ldrb	r1, \[r4\]
  ldr	r0, \[r0\]
  bic	r0, r0, #0xff000000
  orr.w	r0, r0, r1, lsl #29
  str.w	r0, \[r4, #(?P<unkstru_r4_field_34Ca>[0-9a-fx]+)\]
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr.w	ip, \[r0, #0xc\]
  movs	r0, #0xe
  adr	r1, #(?P<cstr_imu_group_sensor_id>[0-9a-fx]+)
  ldr.w	r3, \[r4, #(?P<unkstru_r4_field_34Cb>[0-9a-fx]+)\]
  mov	r2, (r7|r6)
  blx	ip
  uxth	r2, (r7|r6)
  mov	r0, (sb|sl)
  adr	r1, #(?P<cstr_gyro_acc>[0-9a-fx]+)
  bl	#(?P<snprintf_sd_16>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<sub_527570>[0-9a-fx]+)\]
  add	r2, sp, #8
  mov	r1, (sb|sl)
  str.w	r0, \[r4, #(?P<unkstru_r4_field_80>[0-9a-fx]+)\]
  movs	r0, #8
  bl	#(?P<hal_add_device_with_param>[0-9a-fx]+)
  ; block of code, in wm330_0306_v03.02.13.12:
  ;cmp	r0, #0
  ;beq	#(?P<loc_527F00>[0-9a-fx]+)
  ; block of code and data, in wm220_0306_v03.02.35.05:
  ;cbz	r0, #(?P<loc_527F00>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_05>([0-9a-fx]+[, ]*){1,4})
  strb.w	(r5|r7), \[r4, #(?P<unkstru_r4_field_A8>[0-9a-fx]+)\]
loc_527ED8:
  ; block of code, in wm330_0306_v03.02.13.12:
  ;adds	r6, r6, #1
  ;cmp	r6, #2
  ;blo	#(?P<loc_527BC4>[0-9a-fx]+)
  ; block of code, in wm330_0306_v03.01.10.93:
  ;adds	r7, r7, #1
  ; block of code and data, in wm100_0306_v03.02.43.20:
  ;adds	r7, r7, #1
  ;beq.w	#(?P<loc_527BC4>[0-9a-fx]+)
  ;cmp	r7, #2
  ;blo.w	#(?P<loc_527BC4>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_06>([0-9a-fx]+[, ]*){1,8})
  ldr.w	sl, \[pc, #(?P<byte_20404E10>[0-9a-fx]+)\]
  movs	r7, #0
  ; block of code, in wm330_0306_v03.02.13.12, 35 words:
  ;loc_527F76:
  ;movs	r6, #0
  ;add.w	r0, r7, r7, lsl #4
  ;add.w	r1, r0, r7, lsl #5
  ;add.w	r4, sl, r1, lsl #3
  ;loc_513FD2:
  ;rsb	r1, r6, r6, lsl #3
  ;movs	r3, #1
  ;add.w	r0, r4, r1, lsl #4
  ;add.w	r1, r0, #0x10
  ;movs	r2, #0x10
  ;adds	r0, #0x50
  ;bl	#0x426702
  ;adds	r6, r6, #1
  ;cmp	r6, #2
  ;blo	#(?P<loc_513FD2>[0-9a-fx]+)
  ;ldr	r0, \[r4, #0xc\]
  ;cmp	r0, #0
  ;beq	#(?P<loc_5140D6>[0-9a-fx]+)
  ;ldr	r0, \[r4, #0x7c\]
  ;cmp	r0, #0
  ;beq	#(?P<loc_5140D6>[0-9a-fx]+)
  ;ldr.w	r3, \[r4, #0xec\]
  ;subs	r0, r3, #1
  ;cmp.w	r0, #0x320
  ;bhs	#(?P<loc_5140D6>[0-9a-fx]+)
  ;b	#(?P<loc_527F2A>[0-9a-fx]+)
  ;loc_514008:
  ;b	#(?P<loc_5140A4>[0-9a-fx]+)
  ; block of code, in wm100_0306_v03.02.43.20:
  ;loc_527EE6:
  ;add.w	r1, r7, r7, lsl #2
  ;add.w	r4, sl, r1, lsl #4
  ;movs	r1, #3
  ;ldrb	r0, \[r4, #1\]
  ;orr	r0, r0, #0x920000
  ;bl	#(?P<open_device>[0-9a-fx]+)
  ;str	r0, \[r4, #0x10\]
  ;cbnz	r0, #(?P<loc_527F2A>[0-9a-fx]+)
  ;b	#(?P<loc_527F24>[0-9a-fx]+)
  ;loc_527F00:
  ;movs	r1, #0x32
  ;mov	r0, sb
  ;bl	#(?P<sub_524FE2>[0-9a-fx]+)
  ;strb.w	r6, \[r4, #0xa8\]
  ;movs	r2, #1
  ;ldr	r0, \[r4, #0x64\]
  ;mov	sb, fp
  ;mov	r1, fp
  ;bl	#(?P<enable_device>[0-9a-fx]+)
  ;ldr	r0, \[r4, #0x68\]
  ;movs	r2, #1
  ;mov	r1, sb
  ;bl	#(?P<enable_device>[0-9a-fx]+)
  ;b	#(?P<loc_527ED8>[0-9a-fx]+)
  ;loc_527F24:
  ;ldrb	r0, \[r4, #1\]
  ;cmp	r0, #0x80
  ;blo	#(?P<loc_527F68>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_07>([0-9a-fx]+[, ]*){32,48})
loc_527F2A:
  ldr(.w)?	(r3|r6), \[(r8|r5)\]
  movs	r0, #7
  adr	r1, #(?P<cstr_baro_group_ok1>[0-9a-fx]+)
  mov	r2, r7
  blx	(r3|r6)
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr	(r3|r6), \[r0, #0xc\]
  movs	r0, #0x39
  adr	r1, #(?P<cstr_baro_group_ok2>[0-9a-fx]+)
  ; block of code, in wm330_0306_v03.02.13.12:
  ;ldr.w	r3, \[r4, #0xec\]
  ;mov	r2, r7
  ; block of code, in wm100_0306_v03.02.43.20:
  ;mov	r2, r7
  dcw	(?P<undefined_varlen_08>([0-9a-fx]+[, ]*){1,4})
  blx	(r3|r6)
  add.w	r0, r4, #(?P<unkstru_r4_field_14>[0-9a-fx]+)
  movs	r1, #0x38
  mov	(sb|r6), r0
  bl	#(?P<memset_zero>[0-9a-fx]+)
  movs	r2, #0
  mov	r0, (sb|r6)
  adr	r1, #(?P<cstr_baro>[0-9a-fx]+)
  bl	#(?P<snprintf_sd_16>[0-9a-fx]+)
  movs	r0, #9
  mov	r1, (sb|r6)
  bl	#(?P<hal_add_device>[0-9a-fx]+)
  ; block of code, in wm330_0306_v03.02.13.12:
  ;cmp	r0, #0
  ; block of code, in wm100_0306_v03.02.43.20:
  ;cbz	r0, #(?P<loc_527F90>[0-9a-fx]+)
  ;strb.w	r5, \[r4, #0x4d\]
  ;loc_527F68:
  ;adds	r7, r7, #1
  ;beq	#(?P<loc_527EE6>[0-9a-fx]+)
  ;ldr.w	sl, \[pc, #(?P<byte_20404E10>[0-9a-fx]+)\]
  ;movs	r7, #0
  ;add.w	sl, sl, #0x50
  ;loc_527F76:
  ;add.w	r1, r7, r7, lsl #2
  ;add.w	r4, sl, r1, lsl #4
  ;movs	r1, #3
  ;ldrb	r0, \[r4, #1\]
  ;orr	r0, r0, #0x930000
  ;bl	#(?P<open_device>[0-9a-fx]+)
  ;str	r0, \[r4, #0x10\]
  ;cbnz	r0, #(?P<loc_527FAE>[0-9a-fx]+)
  ;b	#(?P<loc_527FA8>[0-9a-fx]+)
  ;loc_527F90:
  ;movs	r1, #0x32
  ;mov	r0, sb
  ;bl	#(?P<sub_524FE2>[0-9a-fx]+)
  ;strb.w	r6, \[r4, #0x4d\]
  ;movs	r2, #1
  ;ldr	r0, \[r4, #0x10\]
  ;mov	r1, fp
  ;bl	#(?P<enable_device>[0-9a-fx]+)
  ;b	#(?P<loc_527F68>[0-9a-fx]+)
  ;loc_527FA8:
  ;ldrb	r0, \[r4, #1\]
  ;cmp	r0, #0x80
  ;blo	#(?P<loc_527FEE>[0-9a-fx]+)
  ;loc_527FAE:
  ;ldr.w	r3, \[r8\]
  ;movs	r0, #7
  ;adr	r1, #(?P<cstr_compass_group_ok1>[0-9a-fx]+)
  ;mov	r2, r7
  ;blx	r3
  ;bl	#(?P<get_logger>[0-9a-fx]+)
  ;ldr	r3, \[r0, #0xc\]
  ;movs	r0, #0x39
  ;adr	r1, #(?P<cstr_compass_group_ok2>[0-9a-fx]+)
  ;mov	r2, r7
  ;blx	r3
  ;add.w	r0, r4, #0x14
  ;movs	r1, #0x38
  ;mov	sb, r0
  ;bl	#(?P<memset_zero>[0-9a-fx]+)
  ;movs	r2, #0
  ;mov	r0, sb
  ;adr	r1, #(?P<cstr_compass>[0-9a-fx]+)
  ;bl	#(?P<snprintf_sd_16>[0-9a-fx]+)
  ;movs	r0, #0xa
  ;mov	r1, sb
  ;bl	#(?P<hal_add_device>[0-9a-fx]+)
  ;cmp	r0, #0
  dcw	(?P<undefined_varlen_10>([0-9a-fx]+[, ]*){1,72})
  beq	#(?P<loc_528066>[0-9a-fx]+)
  strb.w	(r5|r8), \[r4, #(?P<unkstru_r4_field_4C>[0-9a-fx]+)\]
loc_527FEE:
  adds	r7, r7, #1
  ; block of code, in wm330_0306_v03.01.10.93:
  ;cmp	r7, #3
  ;blo	#(?P<loc_527F76>[0-9a-fx]+)
  ; block of code and data, in wm100_0306_v03.02.43.20:
  ;beq	#(?P<loc_527F76>[0-9a-fx]+)
  ; block of code, in wm220_0306_v03.02.13.12:
  ;beq	#(?P<loc_527F76>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_11>([0-9a-fx]+[, ]*){1,4})
  ldr	r0, \[pc, #(?P<hal_stru_164C>[0-9a-fx]+)\]
  movs	r2, #0
  adr	r1, #(?P<cstr_local>[0-9a-fx]+)
  bl	#(?P<hal_add_imu>[0-9a-fx]+)
  subw	r0, pc, #(?P<hal_push_mc_version>[0-9a-fx]+)
  ldr	r4, \[pc, #(?P<hal_stru_164C>[0-9a-fx]+)\]
  movs	r1, #0
  str	r0, \[r4, #0x1c\] ; hal_stru_164C.push_version_cb
  mov	r0, r4
  bl	#(?P<sub_525DB0>[0-9a-fx]+)
  mov	r0, r4
  bl	#(?P<sub_525CF0>[0-9a-fx]+)
  cbz	r0, #(?P<loc_528032>[0-9a-fx]+)
  ; block of code, in wm330_0306_v03.02.13.12, same as:
  ; block of code, in wm100_0306_v03.02.43.20, 5 words:
  ;ldr(.w)?	r3, \[(r8|r5)\]
  ;movs	r0, #7
  ;ldrb	r2, \[r4, #0x40\]! ; hal_stru_164C.local_imu_id_errno
  ; block of code and data, in wm220_0306_v03.02.44.07:
  dcw	(?P<undefined_varlen_19>([0-9a-fx]+[, ]*){4,224})
  adr	r1, #(?P<cstr_warn_local_imu_id_error1>[0-9a-fx]+)
  blx	r3
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr	r3, \[r0, #0xc\]
  movs	r0, #0x39
  adr	r1, #(?P<cstr_warn_local_imu_id_error2>[0-9a-fx]+)
  ldrb	r2, \[r4\]
  blx	r3
loc_528032:
  ; block of code, in wm330_0306_v03.02.13.12:
  ;bl	#0x514408
  ;bl	#0x514610
  ;ldr	r1, \[pc, #(?P<constval_2FA0000>[0-9a-fx]+)\]
  ;ldr	r0, \[pc, #(?P<unk_20404F50>[0-9a-fx]+)\]
  ; block of code, in wm330_0306_v03.01.10.93:
  ;ldr	r2, \[pc, #(?P<hal_stru_164C>[0-9a-fx]+)\]
  ;adr	r0, #(?P<cstr_link_auto_cali>[0-9a-fx]+)
  ;ldr	r1, \[pc, #(?P<link_cali_msg_callback>[0-9a-fx]+)\]
  ;adds	r2, #0x44
  ;bl	#(?P<link_set_msg_callback>[0-9a-fx]+)
  ;ldr	r2, \[pc, #(?P<hal_stru_164C>[0-9a-fx]+)\]
  ;adr	r0, #(?P<cstr_link_manual_cali>[0-9a-fx]+)
  ;ldr	r1, \[pc, #(?P<link_cali_msg_callback>[0-9a-fx]+)\]
  ;adds	r2, #0x44
  ;bl	#(?P<link_set_msg_callback>[0-9a-fx]+)
  ;ldr	r1, \[pc, #(?P<hal_stru_164C>[0-9a-fx]+)\]
  ;movs	r2, #0xc8
  ;adds	r1, #0x5c
  ;sub.w	r0, r1, #0x14
  ;bl	#(?P<sub_50B8C4>[0-9a-fx]+)
  ;ldr	r1, \[pc, #(?P<constval_2FA0000>[0-9a-fx]+)\]
  ;ldr	r0, \[pc, #(?P<unk_20404F50>[0-9a-fx]+)\]
  ; block of code and data, in wm100_0306_v03.02.43.20:
  ;ldr	r2, \[pc, #(?P<hal_stru_164C>[0-9a-fx]+)\]
  ;adr	r0, #(?P<cstr_link_auto_cali>[0-9a-fx]+)
  ;ldr	r1, \[pc, #(?P<link_cali_msg_callback>[0-9a-fx]+)\]
  ;adds	r2, #0x44
  ;bl	#(?P<link_set_msg_callback>[0-9a-fx]+)
  ;ldr	r2, \[pc, #(?P<hal_stru_164C>[0-9a-fx]+)\]
  ;adr	r0, #(?P<cstr_link_manual_cali>[0-9a-fx]+)
  ;ldr	r1, \[pc, #(?P<link_cali_msg_callback>[0-9a-fx]+)\]
  ;adds	r2, #0x44
  ;bl	#(?P<link_set_msg_callback>[0-9a-fx]+)
  ;ldr	r1, \[pc, #(?P<hal_stru_164C>[0-9a-fx]+)\]
  ;movs	r2, #0xc8
  ;adds	r1, #0x5c
  ;sub.w	r0, r1, #0x14
  ;bl	#(?P<sub_50B8C4>[0-9a-fx]+)
  ;ldr	r0, \[pc, #(?P<unk_20404F50>[0-9a-fx]+)\]
  ;ldr	r1, \[pc, #(?P<constval_2FA0000>[0-9a-fx]+)\]
  ;adds	r0, #0xa0
  dcw	(?P<undefined_varlen_12>([0-9a-fx]+[, ]*){6,24})
  bl	#(?P<sub_526C66>[0-9a-fx]+)
  add	sp, #0x64
  pop.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){7,10}), pc}
  ; the function continues - there are a few blocks after the pop
  ; real end is with:
  ;b	#(?P<loc_527FEE>[0-9a-fx]+)
""",
'vars': {
  'imu_init':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'enable_device':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'getSystemTimerTickRate':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'get_link_by_name':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'get_logger':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'hal_add_device':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'hal_add_device_with_param':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'hal_add_imu':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'hal_push_mc_version':	{'type': VarType.RELATIVE_ADDR_TO_CODE, 'baseaddr': "PC-", 'variety': CodeVariety.FUNCTION},
  'snprintf_sd_16':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'memset_zero':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'nullsub_53':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'open_device':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'link_cali_msg_callback':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_CODE, 'baseaddr': "PC+", 'variety': CodeVariety.FUNCTION},
  'link_set_msg_callback':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'printf_s':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_50B8C4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_50BF40':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_524FE2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_525CF0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_525DB0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_526C66':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_526D10':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_526D52':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_526EFA':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_5273E2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_527570':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'timer_event_enable':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'loc_513FD2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5140A4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_5140D6':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527BC4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527DDC':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527DEA':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527E08':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527E0E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527E2C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527E32':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527E3E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527E4A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527ED8':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527EE6':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527F00':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527F24':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527F2A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527F68':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527F76':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527F90':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527FA8':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527FAE':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_527FEE':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_528032':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_528066':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'undefined_varlen_01':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (10,580)},
  'undefined_varlen_02':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (32,64)},
  'undefined_varlen_03':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,6)},
  'undefined_varlen_04':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,4)},
  'undefined_varlen_05':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,4)},
  'undefined_varlen_06':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,8)},
  'undefined_varlen_07':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (32,48)},
  'undefined_varlen_08':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,4)},
  'undefined_varlen_10':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,72)},
  'undefined_varlen_11':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,4)},
  'undefined_varlen_12':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (6,24)},
  'undefined_varlen_18':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,2)},
  'undefined_varlen_19':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (4,224)},
  'cstr_baro':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_baro_group_ok1':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_baro_group_ok2':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  #'cstr_compass':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  #'cstr_compass_group_ok1':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  #'cstr_compass_group_ok2':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_gyro_acc':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_imu_group_ok1':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_imu_group_ok2':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_imu_group_sensor_id':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_link_auto_cali':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_link_manual_cali':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # this is offset to `cstr_link_manual_cali` but computed by 'sub' function - so offset provided needs to be negated to get address
  'cstr_link_manual_cali_neg':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC-", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_local':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_warn_local_imu_id_error1':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_warn_local_imu_id_error2':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'byte_20404E10':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT8_T},
  #'constval_2FA0000':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T},
  'hal_stru_164C':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.STRUCT, 'struct': DummyStruct,},
  'imu_groups':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.STRUCT, 'struct': DummyStruct,},
  # this is the pointer to `imu_groups`, same as above; but it gets misinterpreted by 4 bytes, so we define separate var as workaround:
  'imu_groups_p4':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T},
  'unkstru_r4_field_14':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT16_T},
  'unkstru_r4_field_20':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT16_T},
  'unkstru_r4_field_4C':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT16_T},
  'unkstru_r4_field_70':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT16_T},
  'unkstru_r4_field_80':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT16_T},
  'unkstru_r4_field_A8':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT16_T},
  'unkstru_r4_field_34Ca':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT16_T},
  'unkstru_r4_field_34Cb':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT16_T},
  'unkstru_r4_field_350':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT16_T},
  'unkstru_r4_field_46C':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT16_T},
  #'ptr_printf_s':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UNKNOWN},
  #'ptr_unk_5848FC':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UNKNOWN},
  #'ptr_unkvar_01':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UNKNOWN},
  'dword_20404358':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T},
  'rel_dword_20404528':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  #'unk_20404F50':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unkvar_01':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
},
}

re_func_imu_init_WM330_V03_01_10_93 = {
'name': "imu_init",
'alt_name': "system_init",
'version': "wm330_0306_v03.01.10.93",
're': """
imu_init:
  push.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){7,10}), lr}
  sub	sp, #0x64
  bl	#(?P<sub_4E7D9E>[0-9a-fx]+)
  ldr.w	r8, \[pc, #(?P<dword_20404E48>[0-9a-fx]+)\]
  movs	r6, #0
  ldr	r7, \[pc, #(?P<dword_514C70>[0-9a-fx]+)\]
  mov.w	sl, #1
  mov	sb, r6
loc_4E79F0:
  rsb	r0, r6, r6, lsl #3
  movs	r5, #0
  add.w	r1, r0, r0, lsl #2
  ldr	r0, \[pc, #(?P<byte_204053B4>[0-9a-fx]+)\]
  add.w	r4, r0, r1, lsl #5
loc_4E7A00:
  rsb	r1, r5, r5, lsl #4
  movs	r3, #4
  add.w	r0, r4, r1, lsl #2
  mov	r2, r3
  add.w	r1, r0, #0x44
  adds	r0, #0x54
  bl	#(?P<sub_46EF10>[0-9a-fx]+)
  adds	r5, r5, #1
  cmp	r5, #0xa
  blo	#(?P<loc_4E7A00>[0-9a-fx]+)
  movs	r0, #0
  mov	r2, r4
loc_4E7A20:
  rsb	r1, r0, r0, lsl #4
  add.w	r1, r2, r1, lsl #2
  ldr	r1, \[r1, #0x6c\]
  b	#(?P<loc_4E7B74>[0-9a-fx]+)
  ;dcd	(?P<unk_204397A0>[0-9a-fx]+)
  ;dcb	"temp cali",0
  ;[...]
  ;dcd	(?P<dword_20404E48>[0-9a-fx]+)
  ;dcd	(?P<dword_514C70>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_01>([0-9a-fx]+[, ]*){10,580})
loc_4E7B74:
  cbnz	r1, #(?P<loc_4E7BB4>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_4E7BB4>[0-9a-fx]+)
  cmp	r0, #8
  beq	#(?P<loc_4E7BB4>[0-9a-fx]+)
  cmp	r0, #9
  beq	#(?P<loc_4E7BB4>[0-9a-fx]+)
  ldr.w	r0, \[r8\]
  mov	r3, r6
  ldr	r1, \[r7\]
  udiv	r2, r0, r1
  mls	r1, r1, r2, r0
  mov.w	r2, #0x3e8
  muls	r1, r2, r1
  ldr	r2, \[r7\]
  udiv	r2, r1, r2
  ldr	r1, \[r7\]
  udiv	r1, r0, r1
  adr	r0, #(?P<cstr_fmt_imu_group_err1>[0-9a-fx]+)
  bl	#(?P<log_printf>[0-9a-fx]+)
  adr	r0, #(?P<cstr_fmt_imu_group_err2>[0-9a-fx]+)
  mov	r1, r6
  bl	#(?P<sub_4472FC>[0-9a-fx]+)
  b	#(?P<loc_4E7C46>[0-9a-fx]+)
loc_4E7BB4:
  adds	r0, r0, #1
  cmp	r0, #0xa
  blo.w	#(?P<loc_4E7A20>[0-9a-fx]+)
  ldr.w	r0, \[r8\]
  mov	r5, sb
  ldr	r1, \[r7\]
  mov	r3, r6
  udiv	r2, r0, r1
  mls	r1, r1, r2, r0
  mov.w	r2, #0x3e8
  muls	r1, r2, r1
  ldr	r2, \[r7\]
  udiv	r2, r1, r2
  ldr	r1, \[r7\]
  udiv	r1, r0, r1
  adr	r0, #(?P<cstr_fmt_imu_group_ok1>[0-9a-fx]+)
  bl	#(?P<log_printf>[0-9a-fx]+)
  adr	r0, #(?P<cstr_fmt_imu_group_ok2>[0-9a-fx]+)
  mov	r1, r6
  bl	#(?P<sub_4472FC>[0-9a-fx]+)
  movs	r1, #0xe0
  add.w	r0, r4, #(?P<unkstru_r4_field_350>[0-9a-fx]+)
  bl	#(?P<memset_zero>[0-9a-fx]+)
  add[.]?w	r0, r4, #(?P<unkstru_r4_field_70>[0-9a-fx]+)
  movs	r1, #0x38
  mov	fp, r0
  bl	#(?P<memset_zero>[0-9a-fx]+)
  movs	r3, #0
  mov	r2, r6
  adds	r1, r4, #4
  mov	r0, sp
  bl	#(?P<sub_5273E2>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<dword_20404358>[0-9a-fx]+)\]
  mov.w	r1, #-1
  str.w	r1, \[r4, #0x380\]
  uxth	r2, r6
  adr	r1, #(?P<cstr_gyro_acc>[0-9a-fx]+) ; "gyro_acc"
  ldr	r0, \[r0\]
  bfi	r0, r6, #0x18, #8
  str.w	r0, \[r4, #(?P<unkstru_r4_field_34Ca>[0-9a-fx]+)\]
  mov	r0, fp
  bl	#(?P<snprintf_sd_16>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<sub_4E7792_p1>[0-9a-fx]+)\]
  movs	r0, #0xa
  mov	r2, sp
  str.w	r1, \[r4, #0x314\]
  mov	r1, fp
  bl	#(?P<sub_4E591C>[0-9a-fx]+)
  cmp	r0, #0
  beq	#(?P<loc_4E7D40>[0-9a-fx]+)
  strb.w	r5, \[r4, #0x374\]
loc_4E7C46:
  ldr.w	r0, \[r4, #0x1d4\]
  cmp	r0, #0
loc_4E7C4C:
  beq	#(?P<loc_4E7D42>[0-9a-fx]+)
  ldr.w	r0, \[r4, #0x288\]
  cmp	r0, #0
  beq	#(?P<loc_4E7C4C>[0-9a-fx]+)
  ldr.w	r0, \[r8\]
  mov	r3, r6
  ldr	r1, \[r7\]
  udiv	r2, r0, r1
  mls	r1, r1, r2, r0
  mov.w	r2, #0x3e8
  muls	r1, r2, r1
  ldr	r2, \[r7\]
  udiv	r2, r1, r2
  ldr	r1, \[r7\]
  udiv	r1, r0, r1
  adr	r0, #(?P<cstr_fmt_imu_grp_baro_ok1>[0-9a-fx]+)
  bl	#(?P<log_printf>[0-9a-fx]+)
  adr	r0, #(?P<cstr_fmt_imu_grp_baro_ok2>[0-9a-fx]+)
  mov	r1, r6
  bl	#(?P<sub_4472FC>[0-9a-fx]+)
  add.w	r0, r4, #0x33c
  movs	r2, #0
  mov	r5, r0
  adr	r1, #(?P<cstr_baro>[0-9a-fx]+)
  bl	#(?P<snprintf_sd_16>[0-9a-fx]+)
  movs	r0, #0xb
  mov	r1, r5
  bl	#(?P<hal_add_device>[0-9a-fx]+)
  cmp	r0, #0
  beq	#(?P<loc_4E7D8E>[0-9a-fx]+)
  strb.w	sb, \[r4, #0x375\]
loc_4E7CA4:
  adds	r6, r6, #1
  cmp	r6, #2
  blo.w	#(?P<loc_4E79F0>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<hal_stru_164C>[0-9a-fx]+)\]
  movs	r2, #0
  adr	r1, #(?P<cstr_local>[0-9a-fx]+) ; "_local"
  bl	#(?P<hal_add_imu>[0-9a-fx]+)
  subw	r0, pc, #(?P<hal_push_mc_version>[0-9a-fx]+)
  ldr	r4, \[pc, #(?P<hal_stru_164C>[0-9a-fx]+)\]
  movs	r1, #0
  str	r0, \[r4, #0x1c\] ; hal_stru_164C.push_version_cb
  mov	r0, r4
  bl	#(?P<sub_525DB0>[0-9a-fx]+)
  mov	r0, r4
  bl	#(?P<sub_525CF0>[0-9a-fx]+)
  cbz	r0, #(?P<loc_528032>[0-9a-fx]+)
  ; block of code, in wm330_0306_v03.01.10.93:
  ldr.w	r0, \[r8\]
  ldr	r1, \[r7\]
  ldrb	r3, \[r4, #(?P<rel_byte_204397E0>[0-9a-fx]+)\]!
  udiv	r2, r0, r1
  mls	r1, r1, r2, r0
  mov.w	r2, #0x3e8
  muls	r1, r2, r1
  ldr	r2, \[r7\]
  udiv	r2, r1, r2
  ldr	r1, \[r7\]
  udiv	r1, r0, r1
  adr	r0, #(?P<cstr_fmt_warn_local_imu_id_errno1>[0-9a-fx]+)
  bl	#(?P<log_printf>[0-9a-fx]+)
  ldrb	r1, \[r4\]
  adr	r0, #(?P<cstr_fmt_warn_local_imu_id_errno2>[0-9a-fx]+)
  bl	#(?P<sub_4472FC>[0-9a-fx]+)
loc_4E7D00:
  bl	#(?P<sub_4E7E14>[0-9a-fx]+)
  ldr	r4, \[pc, #(?P<unk_554B84>[0-9a-fx]+)\]
  ldrd	r0, r1, \[r4, #0x18\]
  strd	r0, r1, \[sp, #0x58\]
  movs	r1, #0
  add	r0, sp, #0x58
  bl	#(?P<sub_48E00A>[0-9a-fx]+)
  ldr	r5, \[pc, #(?P<unk_204397A0>[0-9a-fx]+)\]
  adds	r5, #0x44
  mov	r2, r5
  str	r0, \[r5\]
  ldrd	r0, r1, \[r4, #0x20\]
  strd	r0, r1, \[sp, #0x58\]
  ldr	r1, \[pc, #(?P<sub_4E79A8>[0-9a-fx]+)\]
  add	r0, sp, #0x58
  bl	#(?P<sub_48E034>[0-9a-fx]+)
  movs	r2, #0xc8
  adds	r0, r5, #4
  add.w	r1, r5, #0x18
  bl	#(?P<sub_48C064>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<unk_20405C9C>[0-9a-fx]+)\]
  movs	r1, #2
  b	#(?P<loc_4E7D44>[0-9a-fx]+)
loc_4E7D40:
  b	#(?P<loc_4E7D4C>[0-9a-fx]+)
loc_4E7D42:
  b	#(?P<loc_4E7D5A>[0-9a-fx]+)
loc_4E7D44:
  bl	#(?P<sub_4E8656>[0-9a-fx]+)
  add	sp, #0x64
  b	#(?P<locret_4E762E>[0-9a-fx]+)
loc_4E7D4C:
  movs	r1, #0x32
  mov	r0, fp
  bl	#(?P<sub_4E56BA>[0-9a-fx]+)
  strb.w	sl, \[r4, #0x374\]
  b	#(?P<loc_4E7C46>[0-9a-fx]+)
loc_4E7D5A:
  ldr.w	r0, \[r8\]
  mov	r3, r6
  ldr	r1, \[r7\]
  udiv	r2, r0, r1
  mls	r1, r1, r2, r0
  mov.w	r2, #0x3e8
  muls	r1, r2, r1
  ldr	r2, \[r7\]
  udiv	r2, r1, r2
  ldr	r1, \[r7\]
  udiv	r1, r0, r1
  adr	r0, #(?P<cstr_fmt_imu_grp_baro_err1>[0-9a-fx]+)
  bl	#(?P<log_printf>[0-9a-fx]+)
  adr	r0, #(?P<cstr_fmt_imu_grp_baro_err2>[0-9a-fx]+)
  mov	r1, r6
  bl	#(?P<sub_4472FC>[0-9a-fx]+)
  b	#(?P<loc_4E7CA4>[0-9a-fx]+)
  b	#(?P<loc_4E7D8E>[0-9a-fx]+)
loc_4E7D8E:
  movs	r1, #0x32
  add.w	r0, r4, #0x33c
  bl	#(?P<sub_4E56BA>[0-9a-fx]+)
  strb.w	sl, \[r4, #0x375\]
  b	#(?P<loc_4E7CA4>[0-9a-fx]+)
""",
'vars': {
  'imu_init':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'snprintf_sd_16':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_4472FC':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_46EF10':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_48C064':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_48E00A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_48E034':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'log_printf':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_4E56BA':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_4E591C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_4E7792_p1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_4E79A8':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_4E7D9E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_4E7E14':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_4E8656':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_525CF0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_525DB0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_5273E2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'memset_zero':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'hal_add_device':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'hal_add_imu':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'hal_push_mc_version':	{'type': VarType.RELATIVE_ADDR_TO_CODE, 'baseaddr': "PC-", 'variety': CodeVariety.FUNCTION},
  'loc_4E79F0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4E7A00':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4E7A20':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4E7B74':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4E7BB4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4E7C46':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4E7C4C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4E7CA4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4E7D40':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4E7D42':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4E7D44':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4E7D4C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4E7D5A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4E7D8E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_528032':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'locret_4E762E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'undefined_varlen_01':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (10,580)},
  'cstr_baro':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "<%d.%03d>imu group%d error**.\r\n"
  'cstr_fmt_imu_group_err1':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "imu group%d error**."
  'cstr_fmt_imu_group_err2':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "<%d.%03d>imu group%d ok**.\r\n"
  'cstr_fmt_imu_group_ok1':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "imu group%d ok**."
  'cstr_fmt_imu_group_ok2':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "<%d.%03d>imu group%d baro error**.\r\n"
  'cstr_fmt_imu_grp_baro_err1':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "imu group%d baro error**."
  'cstr_fmt_imu_grp_baro_err2':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "<%d.%03d>imu group%d baro ok**.\r\n"
  'cstr_fmt_imu_grp_baro_ok1':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "imu group%d baro ok**."
  'cstr_fmt_imu_grp_baro_ok2':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "<%d.%03d>Waring: Local imu ID erro %d!!"...
  'cstr_fmt_warn_local_imu_id_errno1':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "Waring: Local imu ID erro %d!!! \r\n"
  'cstr_fmt_warn_local_imu_id_errno2':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_gyro_acc':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_local':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'byte_204053B4':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT8_T},
  'dword_20404358':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T},
  'dword_20404E48':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T},
  'dword_514C70':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T},
  'hal_stru_164C':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.STRUCT, 'struct': DummyStruct,},
  'rel_byte_204397E0':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UINT8_T},
  'unk_20405C9C':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T},
  'unk_204397A0':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T},
  'unk_554B84':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T},
  'unkstru_r4_field_34Ca':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT16_T},
  'unkstru_r4_field_350':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT16_T},
  'unkstru_r4_field_70':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT16_T},
},
}


re_func_hal_push_mc_version_P3X_FW_V01_07_0060 = {
'name': "hal_push_mc_version",
'version': "P3X_FW_V01.07.0060",
'no_search': True,
're': """
hal_push_mc_version:
  ldr	r1, \[pc, #(?P<dword_2001C99C>[0-9a-fx]+)\]
  ldr	r0, \[pc, #(?P<mc_version_2>[0-9a-fx]+)\]
  str	r0, \[r1, #(?P<rel_mc_version>[0-9a-fx]+)\]
  bx	lr
""",
'vars': {
  'dword_2001C99C':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.STRUCT, 'struct': DummyStruct,},
  'hal_push_mc_version':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'hal_push_version':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'rel_mc_version':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UINT32_T},
  'mc_version_2':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': version_string_to_int_getter},
},
}

re_func_hal_push_mc_version_WM330_V03_01_10_93 = {
'name': "hal_push_mc_version",
'version': "wm330_0306_v03.01.10.93",
'no_search': True,
're': """
hal_push_mc_version:
  ldr	r1, \[pc, #(?P<mc_version_2>[0-9a-fx]+)\]
  b.w	#(?P<hal_push_version>[0-9a-fx]+)
""",
'vars': {
  'hal_push_mc_version':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'hal_push_version':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'mc_version_2':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': version_string_to_int_getter},
},
}


re_func_navi_init_WM330_V03_01_10_93 = {
'name': "navi_init",
'version': "wm330_0306_v03.01.10.93",
're': """
navi_init:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){6,8}), lr}
  adr	r0, #(?P<cstr_build_datetime>[0-9a-fx]+)
  ldr	r4, \[pc, #(?P<unkn_20418DE8>[0-9a-fx]+)\]
  ldm	r0, {r0, r1, r2, r3}
  stm.w	sp, {r0, r1, r2, r3}
  ldr	r0, \[pc, #(?P<mc_version_3a>[0-9a-fx]+)\]
  movs	r1, #3
  str.w	r0, \[r4, #(?P<rel_navi_version>[0-9a-fx]+)\]
  mov.w	r0, #0x620000
  bl	#(?P<open_device>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<unkn_10620005>[0-9a-fx]+)\]
  add.w	r2, r4, #(?P<rel_serial_nb_0>[0-9a-fx]+)
  bl	#(?P<enable_device>[0-9a-fx]+)
  movs	r0, #1
  strb.w	r0, \[r4, #(?P<byte_20419720>[0-9a-fx]+)\]
  movs	r0, #0
  strb.w	r0, \[r4, #(?P<byte_20419721>[0-9a-fx]+)\]
  add.w	r0, r4, #(?P<rel_serial_nb_1>[0-9a-fx]+)
  adr	r1, #(?P<cstr_navi>[0-9a-fx]+)
  mov	r5, r0
  bl	#(?P<strcpy_1>[0-9a-fx]+)
  adr	r1, #(?P<cstr_space1>[0-9a-fx]+)
  mov	r0, r5
  bl	#(?P<strcat>[0-9a-fx]+)
  adr	r1, #(?P<cstr_product_model>[0-9a-fx]+)
  mov	r0, r5
  bl	#(?P<strcat>[0-9a-fx]+)
  adr	r1, #(?P<cstr_space1>[0-9a-fx]+)
  mov	r0, r5
  bl	#(?P<strcat>[0-9a-fx]+)
  mov	r1, sp
  mov	r0, r5
  bl	#(?P<strcat>[0-9a-fx]+)
  addw	r0, r4, #(?P<rel_serial_nb_2>[0-9a-fx]+)
  movs	r1, #0x21
  mov	r5, r0
  bl	#(?P<sub_4EB780>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<unk_20413254>[0-9a-fx]+)\]
  movs	r2, #0x21
  mov	r1, r5
  bl	#(?P<sub_4EC598>[0-9a-fx]+)
  bl	#(?P<sub_44F07E>[0-9a-fx]+)
  cbnz	r0, #(?P<loc_4B9060>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<word_20437EB4>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_byte_20437EDA>[0-9a-fx]+)\]
  cmp	r0, #1
  bne	#(?P<loc_4B9060>[0-9a-fx]+)
  ldr.w	r0, \[r4, #(?P<rel_dword_20436038>[0-9a-fx]+)\]
  orr	r0, r0, #2
  str.w	r0, \[r4, #(?P<rel_dword_20436038>[0-9a-fx]+)\]
loc_4B9060:
  movs	r0, #(?P<const_val_1>[0-9a-fx]+)
  strb.w	r0, \[r4, #(?P<rel_byte_2041971F>[0-9a-fx]+)\]
  pop	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){6,8}), pc}
""",
'vars': {
  'navi_init':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'enable_device':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'memcpy_0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'open_device':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'strcat':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'strcpy_1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_4EB780':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_4EC598':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_44F07E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'loc_4B9060':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  # "20160707|163948",0
  'cstr_build_datetime':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "NAVI"
  'cstr_navi':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # ie. "wm330v2"
  'cstr_product_model':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # " "
  'cstr_space1':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'unk_20413254':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'word_20437EB4':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT16_T},
  'byte_20419720':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'byte_20419721':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_serial_nb_0':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_serial_nb_1':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_serial_nb_2':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'unkn_20418DE8':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unkn_10620005':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_byte_2041971F':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_navi_version':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_unkn_1':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_byte_20437EDA':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_dword_20436038':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'const_val_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T},
  'mc_version_3a':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': version_string_to_int_getter},
},
}

re_func_navi_init_WM220_V03_01_10_93 = {
'name': "navi_init",
'version': "wm220_0306_v03.01.10.93",
're': """
navi_init:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){6,8}), lr}
  adr	r0, #(?P<cstr_build_datetime>[0-9a-fx]+)
  ldr	r4, \[pc, #(?P<unkn_20418DE8>[0-9a-fx]+)\]
  ldm	r0, {r0, r1, r2, r3}
  stm.w	sp, {r0, r1, r2, r3}
  ldr	r0, \[pc, #(?P<mc_version_3a>[0-9a-fx]+)\]
  movs	r1, #3
  str.w	r0, \[r4, #(?P<rel_navi_version>[0-9a-fx]+)\]
  mov.w	r0, #0x620000
  addw	r4, r4, #(?P<rel_unkn_1>[0-9a-fx]+)
  bl	#(?P<open_device>[0-9a-fx]+)
  ldr	r2, \[pc, #(?P<serial_nb_0>[0-9a-fx]+)\]
  ldr	r1, \[pc, #(?P<unkn_10620005>[0-9a-fx]+)\]
  subs	r2, #0x3a
  bl	#(?P<enable_device>[0-9a-fx]+)
  movs	r0, #1
  strb	r0, \[r4, #(?P<byte_20419720>[0-9a-fx]+)\]
  movs	r0, #0
  strb	r0, \[r4, #(?P<byte_20419721>[0-9a-fx]+)\]
  ldr	r0, \[pc, #(?P<serial_nb_0>[0-9a-fx]+)\]
  adr	r1, #(?P<cstr_navi>[0-9a-fx]+)
  subs	r0, #0x32
  mov	r5, r0
  bl	#(?P<strcpy_1>[0-9a-fx]+)
  adr	r1, #(?P<cstr_space1>[0-9a-fx]+)
  mov	r0, r5
  bl	#(?P<strcat>[0-9a-fx]+)
  adr	r1, #(?P<cstr_product_model>[0-9a-fx]+)
  mov	r0, r5
  bl	#(?P<strcat>[0-9a-fx]+)
  adr	r1, #(?P<cstr_space1>[0-9a-fx]+)
  mov	r0, r5
  bl	#(?P<strcat>[0-9a-fx]+)
  mov	r1, sp
  mov	r0, r5
  bl	#(?P<strcat>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<serial_nb_0>[0-9a-fx]+)\]
  movs	r2, #0x10
  mov	r1, sp
  adds	r0, #0x54
  bl	#(?P<memcpy_0>[0-9a-fx]+)
  movs	r0, #(?P<const_val_1>[0-9a-fx]+)
  strb	r0, \[r4, #(?P<rel_byte_2041971F>[0-9a-fx]+)\]
  pop	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){6,8}), pc}
""",
'vars': {
  'navi_init':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'enable_device':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'memcpy_0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'open_device':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'strcat':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'strcpy_1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'cstr_build_datetime':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_navi':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_product_model':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_space1':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'byte_20419720':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'byte_20419721':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'serial_nb_0':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unkn_20418DE8':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unkn_10620005':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_byte_2041971F':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_navi_version':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_unkn_1':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'const_val_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T},
  'mc_version_3a':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': version_string_to_int_getter},
},
}


re_func_init_config_table_version_WM330_V03_01_10_93 = {
'name': "init_config_table_version",
'version': "wm330_0306_v03.01.10.93",
're': """
init_config_table_version:
  push	{r4, lr}
  ldr	r4, \[pc, #(?P<mc_version_3b>[0-9a-fx]+)\]
  bl	#(?P<get_version_4384>[0-9a-fx]+)
  cmp	r0, r4
  beq	#(?P<loc_541300>[0-9a-fx]+)
  mov	r0, r4
  bl	#(?P<set_version_4384>[0-9a-fx]+)
  movs	r0, #1
  pop	{r4, pc}
loc_541300:
  movs	r0, #0
  pop	{r4, pc}
""",
'vars': {
  'init_config_table_version':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'get_version_4384':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_version_4384':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'loc_541300':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'mc_version_3b':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': version_string_to_int_getter},
},
}

re_func_init_config_table_version_WM220_V03_01_10_93 = {
'name': "init_config_table_version",
'version': "wm220_0306_v03.01.10.93",
're': """
init_config_table_version:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){2,4}), lr}
  mov	r0, sp
  ; block of code, in wm220_0306_v03.02.35.05 is 4 words long:
  ;bl	#(?P<get_version_4384>[0-9a-fx]+)
  ;bl	#(?P<set_hw_version>[0-9a-fx]+)
  ; block of code, in wm220_0306_v03.02.13.12 is 2 words long:
  ;bl	#(?P<get_version_4384>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){2,8})
  ldr	r0, \[pc, #(?P<mc_version_3b>[0-9a-fx]+)\]
  ldr	r1, \[sp\]
  cmp	r1, r0
  bne	#(?P<loc_5412EE>[0-9a-fx]+)
  ldrb.w	r1, \[sp, #4\]
  cmp	r1, #(?P<const_val_1a>[0-9a-fx]+)
  beq	#(?P<loc_541300>[0-9a-fx]+)
loc_5412EE:
  str	r0, \[sp\]
  movs	r0, #(?P<const_val_1b>[0-9a-fx]+)
  strb.w	r0, \[sp, #4\]
  mov	r0, sp
  bl	#(?P<set_version_4384>[0-9a-fx]+)
  movs	r0, #1
  pop	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){2,4}), pc}
loc_541300:
  movs	r0, #0
  pop	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){2,4}), pc}
""",
'vars': {
  'init_config_table_version':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'get_version_4384':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_hw_version':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_version_4384':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'loc_5412EE':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_541300':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (2,8)},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'const_val_1a':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T},
  'const_val_1b':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T},
  'mc_version_3b':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': version_string_to_int_getter},
},
}


re_func_log_version_info_P3X_FW_V01_07_0060 = {
'name': "log_version_info",
'version': "P3X_FW_V01.07.0060",
're': """
log_version_info:
  push	{lr}
  sub	sp, #0x14
  add	r0, sp, #8
  bl	#(?P<get_mc_ident>[0-9a-fx]+)
  add	r2, sp, #8
  adr	r1, #(?P<cstr_fmt_mc_id>[0-9a-fx]+)
  movs	r0, #0xfe
  bl	#(?P<log_printf_info>[0-9a-fx]+)
  movs	r1, #(?P<mc_ver_revsn>[0-9a-fx]+)
  movs	r0, #(?P<mc_ver_mmtnc>[0-9a-fx]+)
  strd	r0, r1, \[sp\]
  movs	r3, #(?P<mc_ver_minor>[0-9a-fx]+)
  movs	r2, #(?P<mc_ver_major>[0-9a-fx]+)
  adr	r1, #(?P<cstr_fmt_mc_ver>[0-9a-fx]+)
  movs	r0, #0xfe
  bl	#(?P<log_printf_info>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<dword_20404E98>[0-9a-fx]+)\]
  ldr	r0, \[r0, #(?P<rel_battery_version>[0-9a-fx]+)\]
  uxtb	r2, r0
  ubfx	r1, r0, #8, #8
  strd	r1, r2, \[sp\]
  lsrs	r2, r0, #0x18
  ubfx	r3, r0, #0x10, #8
  adr	r1, #(?P<cstr_fmt_bat_ver>[0-9a-fx]+)
  movs	r0, #0xfe
  bl	#(?P<log_printf_info>[0-9a-fx]+)
  adr	r2, #(?P<cstr_repo_revision>[0-9a-fx]+)
  adr	r1, #(?P<cstr_fmt_svn_ver>[0-9a-fx]+)
  movs	r0, #0xfe
  bl	#(?P<log_printf_info>[0-9a-fx]+)
  adr	r2, #(?P<cstr_repo_build_date>[0-9a-fx]+)
  adr	r1, #(?P<cstr_fmt_time>[0-9a-fx]+)
  movs	r0, #0xfe
  bl	#(?P<log_printf_info>[0-9a-fx]+)
  add	sp, #0x14
  pop	{pc}
""",
'vars': {
  'log_version_info':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'log_printf_info':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'get_mc_ident':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  # "Mc  ID  :%s"
  'cstr_fmt_mc_id':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "Mc  Ver :v%d.%d.%d.%d"
  'cstr_fmt_mc_ver':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "Bat Ver :v%d.%d.%d.%d"
  'cstr_fmt_bat_ver':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "svn Ver :%s"
  'cstr_fmt_svn_ver':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "Time    :%s"
  'cstr_fmt_time':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # ie. "commit:2016-07-07 16:39:58 /build:2016-07-07 16:41:31 ",0
  'cstr_repo_build_date':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # ie. "f824fd4656cb8e42128d3450985004f754a3f2f3",0
  'cstr_repo_revision':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'byte_20435FE2':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'dword_20404E98':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_battery_version':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'mc_ver_major':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': (lambda val: version_string_to_parts_getter(val,1))},
  'mc_ver_minor':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': (lambda val: version_string_to_parts_getter(val,2))},
  'mc_ver_mmtnc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': (lambda val: version_string_to_parts_getter(val,3))},
  'mc_ver_revsn':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': (lambda val: version_string_to_parts_getter(val,4))},
},
}

re_func_log_version_info_WM330_V03_01_10_93 = {
'name': "log_version_info",
'version': "wm330_0306_v03.01.10.93",
're': """
log_version_info:
  push	{r0, r1, r2, r3, r4, lr}
  ldr	r0, \[pc, #(?P<byte_20435FE2>[0-9a-fx]+)\]
  movs	r1, #0
  ldr	r2, \[pc, #(?P<cstr_func_name>[0-9a-fx]+)\]
  adr	r3, #(?P<cstr_fmt_mc_id>[0-9a-fx]+)
  str	r0, \[sp\]
  movs	r0, #3
  bl	#(?P<log_printf_info>[0-9a-fx]+)
  movs	r3, #(?P<mc_ver_revsn>[0-9a-fx]+)
  movs	r2, #(?P<mc_ver_mmtnc>[0-9a-fx]+)
  movs	r1, #(?P<mc_ver_minor>[0-9a-fx]+)
  movs	r0, #(?P<mc_ver_major>[0-9a-fx]+)
  stm.w	sp, {r0, r1, r2, r3}
  ldr	r2, \[pc, #(?P<cstr_func_name>[0-9a-fx]+)\]
  movs	r1, #0
  adr	r3, #(?P<cstr_fmt_mc_ver>[0-9a-fx]+)
  bl	#(?P<log_printf_info>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<dword_20404E98>[0-9a-fx]+)\]
  ldr	r0, \[r0, #(?P<rel_battery_version>[0-9a-fx]+)\]
  uxtb	r2, r0
  ubfx	r1, r0, #8, #8
  ubfx	r3, r0, #0x10, #8
  lsrs	r0, r0, #0x18
  strd	r1, r2, \[sp, #8\]
  strd	r0, r3, \[sp\]
  ldr	r2, \[pc, #(?P<cstr_func_name>[0-9a-fx]+)\]
  movs	r1, #0
  movs	r0, #3
  adr	r3, #(?P<cstr_fmt_bat_ver>[0-9a-fx]+)
  bl	#(?P<log_printf_info>[0-9a-fx]+)
  adr	r0, #(?P<cstr_repo_revision>[0-9a-fx]+)
  ldr	r2, \[pc, #(?P<cstr_func_name>[0-9a-fx]+)\]
  movs	r1, #0
  str	r0, \[sp\]
  movs	r0, #3
  adr	r3, #(?P<cstr_fmt_svn_ver>[0-9a-fx]+)
  bl	#(?P<log_printf_info>[0-9a-fx]+)
  adr	r0, #(?P<cstr_repo_build_date>[0-9a-fx]+)
  ldr	r2, \[pc, #(?P<cstr_func_name>[0-9a-fx]+)\]
  movs	r1, #0
  str	r0, \[sp\]
  movs	r0, #3
  adr	r3, #(?P<cstr_fmt_time>[0-9a-fx]+)
  bl	#(?P<log_printf_info>[0-9a-fx]+)
  pop	{r0, r1, r2, r3, r4, pc}
""",
'vars': {
  'log_version_info':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'log_printf_info':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  # "log_system_info"
  'cstr_func_name':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "Mc  ID  :%s"
  'cstr_fmt_mc_id':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "Mc  Ver :v%d.%d.%d.%d"
  'cstr_fmt_mc_ver':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "Bat Ver :v%d.%d.%d.%d"
  'cstr_fmt_bat_ver':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "svn Ver :%s"
  'cstr_fmt_svn_ver':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # "Time    :%s"
  'cstr_fmt_time':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # ie. "commit:2016-07-07 16:39:58 /build:2016-07-07 16:41:31 ",0
  'cstr_repo_build_date':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  # ie. "f824fd4656cb8e42128d3450985004f754a3f2f3",0
  'cstr_repo_revision':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'byte_20435FE2':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'dword_20404E98':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_battery_version':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'mc_ver_major':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': (lambda val: version_string_to_parts_getter(val,1))},
  'mc_ver_minor':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': (lambda val: version_string_to_parts_getter(val,2))},
  'mc_ver_mmtnc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': (lambda val: version_string_to_parts_getter(val,3))},
  'mc_ver_revsn':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': (lambda val: version_string_to_parts_getter(val,4))},
},
}

re_func_log_version_info_WM220_V03_01_10_93 = {
'name': "log_version_info",
'version': "wm220_0306_v03.01.10.93",
're': """
log_version_info:
  push	{r2, r3, r4, r5, r6, lr}
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr	r3, \[r0, #0xc\]
  movs	r0, #5
  adr	r1, #(?P<cstr_fmt_mc_id>[0-9a-fx]+)
  ldr	r2, \[pc, #(?P<serial_nb_0>[0-9a-fx]+)\]
  blx	r3
  movs	r1, #(?P<mc_ver_revsn>[0-9a-fx]+)
  movs	r0, #(?P<mc_ver_mmtnc>[0-9a-fx]+)
  strd	r0, r1, \[sp\]
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr	r4, \[r0, #0xc\]
  movs	r3, #(?P<mc_ver_minor>[0-9a-fx]+)
  movs	r2, #(?P<mc_ver_major>[0-9a-fx]+)
  movs	r0, #5
  adr	r1, #(?P<cstr_fmt_mc_ver>[0-9a-fx]+)
  blx	r4
  ldr	r5, \[pc, #(?P<dword_20405E40>[0-9a-fx]+)\]
  ldrh	r0, \[r5, #(?P<rel_battery_version>[0-9a-fx]+)\]
  uxtb	r1, r0
  ubfx	r0, r0, #8, #8
  strd	r0, r1, \[sp\]
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr	r4, \[r0, #0xc\]
  adr	r1, #(?P<cstr_fmt_bat_ver>[0-9a-fx]+)
  ldr	r0, \[r5, #(?P<rel_battery_version>[0-9a-fx]+)\]
  lsrs	r2, r0, #0x18
  ubfx	r3, r0, #0x10, #8
  movs	r0, #5
  blx	r4
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr	r3, \[r0, #0xc\]
  movs	r0, #5
  adr	r2, #(?P<cstr_repo_revision>[0-9a-fx]+)
  adr	r1, #(?P<cstr_fmt_svn_ver>[0-9a-fx]+)
  blx	r3
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr	r3, \[r0, #0xc\]
  add	sp, #8
  movs	r0, #5
  adr	r2, #(?P<cstr_repo_build_date>[0-9a-fx]+)
  pop.w	{r4, r5, r6, lr}
  adr	r1, #(?P<cstr_fmt_time>[0-9a-fx]+)
  bx	r3
""",
'vars': {
  'log_version_info':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'get_logger':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'cstr_fmt_bat_ver':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_fmt_mc_id':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_fmt_mc_ver':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_fmt_svn_ver':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_fmt_time':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_repo_build_date':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_repo_revision':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'dword_20405E40':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_battery_version':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'serial_nb_0':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'mc_ver_major':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': (lambda val: version_string_to_parts_getter(val,1))},
  'mc_ver_minor':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': (lambda val: version_string_to_parts_getter(val,2))},
  'mc_ver_mmtnc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': (lambda val: version_string_to_parts_getter(val,3))},
  'mc_ver_revsn':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': (lambda val: version_string_to_parts_getter(val,4))},
},
}


re_func_version_check_sub1_WM330_V03_01_10_93 = {
'name': "version_check_sub1",
'version': "wm330_0306_v03.01.10.93",
're': """
version_check_sub1:
  push.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){10,16}), lr}
  ldr	r5, \[pc, #(?P<byte_20402ECE>[0-9a-fx]+)\]
  movs	r0, #0
  mov	r4, r0
  str	r0, \[sp\]
  str	r0, \[sp, #4\]
  str	r0, \[sp, #8\]
  strh.w	r0, \[sp, #0xc\]
  ldrb	r1, \[r5, #(?P<rel_byte_20402ECF>[0-9a-fx]+)\]
  cmp	r1, #0
  bne	#(?P<locret_45FEE6>[0-9a-fx]+)
  movs	r6, #1
  mov	sb, r0
  mov	sl, sp
  strb	r6, \[r5, #(?P<rel_byte_20402ECF>[0-9a-fx]+)\]
loc_45FE24:
  bl	#(?P<get_fmu_dm>[0-9a-fx]+)
  ldr.w	r3, \[r0, #(?P<field_dm_callback_B4a>[0-9a-fx]+)\]
  add	r2, sp, #0xc
  mov	r1, sp
  mov	r0, r4
  blx	r3
  cbnz	r0, #(?P<loc_45FE52>[0-9a-fx]+)
  movs	r1, #0
  mov	r0, sb
  mov	r2, sl
  b	#(?P<loc_45FE4A>[0-9a-fx]+)
loc_45FE3E:
  ldr.w	r3, \[r2, r1, lsl #2\]
  adds	r1, r1, #1
  uxtb	r1, r1
  strb.w	r0, \[r3, #(?P<field_var48_ofs38a>[0-9a-fx]+)\]
loc_45FE4A:
  ldrh.w	r3, \[sp, #0xc\]
  cmp	r1, r3
  blo	#(?P<loc_45FE3E>[0-9a-fx]+)
loc_45FE52:
  adds	r4, r4, #1
  uxtb	r4, r4
  cmp	r4, #(?P<const_loop_limit_1>[0-9a-fx]+)
  blo	#(?P<loc_45FE24>[0-9a-fx]+)
  movs	r4, #0
  mov	fp, r5
  b	#(?P<loc_45FEDE>[0-9a-fx]+)
loc_45FE60:
  ldr	r7, \[pc, #(?P<pvstru_D61C>[0-9a-fx]+)\]
  add.w	r5, r4, r4, lsl #1
  add.w	r8, r7, r5, lsl #2
  ldr.w	r0, \[r8, #8\]
  cmp	r0, #1
  bne	#(?P<loc_45FEDA>[0-9a-fx]+)
  bl	#(?P<get_fmu_dm>[0-9a-fx]+)
  ldr.w	r3, \[r0, #(?P<field_dm_callback_B4b>[0-9a-fx]+)\]
  add	r2, sp, #0xc
  ldrb.w	r0, \[r7, r5, lsl #2\]
  mov	r1, sp
  blx	r3
  movs	r0, #0
  mov	r7, sb
  mov	r5, sl
  b	#(?P<loc_45FEA0>[0-9a-fx]+)
loc_45FE8C:
  ldr.w	r1, \[r5, r0, lsl #2\]
  strb.w	r6, \[r1, #(?P<field_var48_ofs38b>[0-9a-fx]+)\]
  ldr.w	r1, \[r5, r0, lsl #2\]
  adds	r0, r0, #1
  uxtb	r0, r0
  strb.w	r7, \[r1, #(?P<field_var48_ofs3Aa>[0-9a-fx]+)\]
loc_45FEA0:
  ldrh.w	r1, \[sp, #0xc\]
  cmp	r0, r1
  blo	#(?P<loc_45FE8C>[0-9a-fx]+)
  bl	#(?P<get_fmu_dm>[0-9a-fx]+)
  ldr.w	r3, \[r0, #(?P<field_dm_callback_B4c>[0-9a-fx]+)\]
  add	r2, sp, #0xc
  ldrb.w	r0, \[r8, #1\]
  mov	r1, sp
  blx	r3
  movs	r0, #0
  b	#(?P<loc_45FED2>[0-9a-fx]+)
loc_45FEBE:
  ldr.w	r1, \[r5, r0, lsl #2\]
  strb.w	r6, \[r1, #(?P<field_var48_ofs38c>[0-9a-fx]+)\]
  ldr.w	r1, \[r5, r0, lsl #2\]
  adds	r0, r0, #1
  uxtb	r0, r0
  strb.w	r7, \[r1, #(?P<field_var48_ofs3Ab>[0-9a-fx]+)\]
loc_45FED2:
  ldrh.w	r1, \[sp, #0xc\]
  cmp	r0, r1
  blo	#(?P<loc_45FEBE>[0-9a-fx]+)
loc_45FEDA:
  adds	r4, r4, #1
  uxtb	r4, r4
loc_45FEDE:
  ldrb.w	r0, \[fp\]
  cmp	r4, r0
  blo	#(?P<loc_45FE60>[0-9a-fx]+)
locret_45FEE6:
  pop.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){10,16}), pc}
""",
'vars': {
  'version_check_sub1':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'get_fmu_dm':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'loc_45FE24':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_45FE3E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_45FE4A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_45FE52':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_45FE60':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_45FE8C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_45FEA0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_45FEBE':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_45FED2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_45FEDA':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_45FEDE':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'locret_45FEE6':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'field_dm_callback_B4a':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_dm_callback_B4b':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_dm_callback_B4c':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs38a':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs38b':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs38c':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs3Aa':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs3Ab':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'const_loop_limit_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T},
  'byte_20402ECE':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'pvstru_D61C':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+",
    'variety': DataVariety.STRUCT, 'struct': DummyStruct,},
  'rel_byte_20402ECF':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
},
}

re_func_version_check_WM330_V03_01_10_93 = {
'name': "version_check",
'version': "wm330_0306_v03.01.10.93",
're': """
version_check:
  push.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){6,10}), lr}
  mov	r5, r0
  ldr	r0, \[pc, #(?P<unkval_9DE8>[0-9a-fx]+)\]
  mov.w	sb, #0
  sub	sp, #0x24
  mov	r4, sb
  ldrb.w	r0, \[r0, #(?P<rel_simulator_running>[0-9a-fx]+)\]
  cmp	r0, #1
  beq	#(?P<loc_45FF4E>[0-9a-fx]+)
  bl	#(?P<version_check_sub1>[0-9a-fx]+)
  movs	r0, #0
  mov	sl, sp
  add.w	r8, sp, #0x10
  mov.w	fp, #1
  strb	r0, \[r5, #2\]
  b	#(?P<loc_4600B2>[0-9a-fx]+)
loc_45FF4E:
  movs	r0, #(?P<const_val_sim_a>[0-9a-fx]+)
  strb	r0, \[r5\]
  strb	r0, \[r5, #1\]
  strb	r4, \[r5, #2\]
  b	#(?P<loc_4601B0>[0-9a-fx]+)
loc_45FF58:
  ldr	r6, \[pc, #(?P<pvstru_D61C>[0-9a-fx]+)\]
  add.w	r4, sb, sb, lsl #1
  add.w	r7, r6, r4, lsl #2
  ldr	r0, \[r7, #8\]
  cmp	r0, #1
  bne	#(?P<loc_45FFF4>[0-9a-fx]+)
  movs	r0, #0
  str	r0, \[sp\]
  str	r0, \[sp, #4\]
  str	r0, \[sp, #8\]
  strh.w	r0, \[sp, #0xc\]
  str	r0, \[sp, #0x10\]
  str	r0, \[sp, #0x14\]
  str	r0, \[sp, #0x18\]
  strh.w	r0, \[sp, #0x1c\]
  bl	#(?P<get_fmu_dm>[0-9a-fx]+)
  ldr.w	r3, \[r0, #(?P<field_dm_callback_B4a>[0-9a-fx]+)\] ; known values: 0xb4 0xb8
  add	r2, sp, #0xc
  ldrb.w	r0, \[r6, r4, lsl #2\]
  mov	r1, sp
  blx	r3
  bl	#(?P<get_fmu_dm>[0-9a-fx]+)
  ldr.w	r3, \[r0, #(?P<field_dm_callback_B4b>[0-9a-fx]+)\]
  add	r2, sp, #0x1c
  add	r1, sp, #0x10
  ldrb	r0, \[r7, #1\]
  blx	r3
  ldrb.w	r0, \[r6, r4, lsl #2\]
  ldrb	r1, \[r7, #1\]
  cmp	r0, r1
  bne	#(?P<loc_46003A>[0-9a-fx]+)
  ldr	r0, \[r7, #4\]
  movs	r4, #0
  cbnz	r0, #(?P<loc_46002C>[0-9a-fx]+)
  movs	r4, #1
  mov	r6, sl
  b	#(?P<loc_45FFEC>[0-9a-fx]+)
loc_45FFB6:
  ldr	r0, \[sp\]
  movs	r2, #2
  ldr	r1, \[r0, #(?P<field_var48_ofs34a>[0-9a-fx]+)\]
  ldr.w	r0, \[r6, r4, lsl #2\]
  ldr	r0, \[r0, #(?P<field_var48_ofs34b>[0-9a-fx]+)\]
  bl	#(?P<sub_45FEEA>[0-9a-fx]+)
  cbnz	r0, #(?P<loc_45FFE8>[0-9a-fx]+)
  ldr.w	r0, \[r6, r4, lsl #2\]
  ldrb(.w)?	r0, \[r0, #(?P<field_var48_ofs0Ba>[0-9a-fx]+)\]
  lsls	r0, r0, #0x1e
  bne	#(?P<loc_45FFD6>[0-9a-fx]+)
  strb.w	fp, \[r5, #2\]
loc_45FFD6:
  ldr.w	r1, \[r6, r4, lsl #2\]
  ldrb.w	r0, \[r1, #(?P<field_var48_ofs3Aa>[0-9a-fx]+)\]
  cmp	r0, #0xc8
  bhs	#(?P<loc_45FFE8>[0-9a-fx]+)
  adds	r0, r0, #1
  strb.w	r0, \[r1, #(?P<field_var48_ofs3Ab>[0-9a-fx]+)\]
loc_45FFE8:
  adds	r4, r4, #1
  uxth	r4, r4
loc_45FFEC:
  ldrh.w	r0, \[sp, #0xc\]
  cmp	r4, r0
  blo	#(?P<loc_45FFB6>[0-9a-fx]+)
loc_45FFF4:
  b	#(?P<loc_4600AA>[0-9a-fx]+)
loc_45FFF6:
  ldr.w	r0, \[sl, r4, lsl #2\]
  mov	r6, sl
  ldrb	r2, \[r7, #2\]
  ldr	r1, \[r7, #4\]
  ldr	r0, \[r0, #(?P<field_var48_ofs34c>[0-9a-fx]+)\]
  bl	#(?P<sub_45FEEA>[0-9a-fx]+)
  cbnz	r0, #(?P<loc_460028>[0-9a-fx]+)
  ldr.w	r0, \[r6, r4, lsl #2\]
  ldrb(.w)?	r0, \[r0, #(?P<field_var48_ofs0Bb>[0-9a-fx]+)\]
  lsls	r0, r0, #0x1e
  bne	#(?P<loc_460016>[0-9a-fx]+)
  strb.w	fp, \[r5, #2\]
loc_460016:
  ldr.w	r1, \[r6, r4, lsl #2\]
  ldrb.w	r0, \[r1, #(?P<field_var48_ofs3Ac>[0-9a-fx]+)\]
  cmp	r0, #0xc8 ; 200
  bhs	#(?P<loc_460028>[0-9a-fx]+)
  adds	r0, r0, #1
  ; block of code in wm220_0306_v03.01.10.93:
  ;strb.w	r0, \[r1, #(?P<field_var48_ofs3Ad>[0-9a-fx]+)\]
  ;loc_460028:
  ;adds	r4, r4, #1
  ;b	#(?P<loc_46002E>[0-9a-fx]+)
  ;loc_46002C:
  ;b	#(?P<loc_460030>[0-9a-fx]+)
  ; block of code in wm330_0306_v03.01.10.93:
  ;b	#loc_4D8E18
  ;b	#0x4d8e20
  ;loc_4D8E18:
  ;strb.w	r0, \[r1, #(?P<field_var48_ofs3Ad>[0-9a-fx]+)\]
  ;loc_460028:
  ;adds	r4, r4, #1
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){5,8})
loc_46002E:
  uxth	r4, r4
loc_460030:
  ldrh.w	r0, \[sp, #0xc\]
  cmp	r4, r0
  blo	#(?P<loc_45FFF6>[0-9a-fx]+)
  b	#(?P<loc_4600AA>[0-9a-fx]+)
loc_46003A:
  movs	r6, #0
  b	#(?P<loc_4600A2>[0-9a-fx]+)
loc_46003E:
  movs	r4, #0
  b	#(?P<loc_460096>[0-9a-fx]+)
loc_460042:
  ldr.w	r0, \[r8, r4, lsl #2\]
  ldrb	r2, \[r7, #2\]
  ldr	r1, \[r0, #(?P<field_var48_ofs34d>[0-9a-fx]+)\]
  ldr.w	r0, \[sl, r6, lsl #2\]
  ldr	r0, \[r0, #(?P<field_var48_ofs34e>[0-9a-fx]+)\]
  bl	#(?P<sub_45FEEA>[0-9a-fx]+)
  cbnz	r0, #(?P<loc_460092>[0-9a-fx]+)
  ldr.w	r0, \[sl, r6, lsl #2\]
  ldrb(.w)?	r0, \[r0, #(?P<field_var48_ofs0Bc>[0-9a-fx]+)\]
  lsls	r0, r0, #0x1e
  bne	#(?P<loc_46006E>[0-9a-fx]+)
  ldr.w	r0, \[r8, r4, lsl #2\]
  ldrb(.w)?	r0, \[r0, #(?P<field_var48_ofs0Bd>[0-9a-fx]+)\]
  lsls	r0, r0, #0x1e
  bne	#(?P<loc_46006E>[0-9a-fx]+)
  strb.w	fp, \[r5, #2\]
loc_46006E:
  ldr.w	r1, \[sl, r6, lsl #2\]
  ldrb.w	r0, \[r1, #(?P<field_var48_ofs3Ae>[0-9a-fx]+)\]
  cmp	r0, #0xc8
  bhs	#(?P<loc_460080>[0-9a-fx]+)
  adds	r0, r0, #1
  strb.w	r0, \[r1, #(?P<field_var48_ofs3Af>[0-9a-fx]+)\]
loc_460080:
  ldr.w	r1, \[r8, r4, lsl #2\]
  ldrb.w	r0, \[r1, #(?P<field_var48_ofs3Ag>[0-9a-fx]+)\]
  cmp	r0, #0xc8 ; 200
  bhs	#(?P<loc_460092>[0-9a-fx]+)
  adds	r0, r0, #1
  strb.w	r0, \[r1, #(?P<field_var48_ofs3Ah>[0-9a-fx]+)\]
loc_460092:
  adds	r4, r4, #1
  uxth	r4, r4
loc_460096:
  ldrh.w	r0, \[sp, #0x1c\]
  cmp	r4, r0
  blo	#(?P<loc_460042>[0-9a-fx]+)
  adds	r6, r6, #1
  uxth	r6, r6
loc_4600A2:
  ldrh.w	r0, \[sp, #0xc\]
  cmp	r6, r0
  blo	#(?P<loc_46003E>[0-9a-fx]+)
loc_4600AA:
  add.w	r0, sb, #1
  uxth.w	sb, r0
loc_4600B2:
  ldr	r1, \[pc, #(?P<byte_20402ECE>[0-9a-fx]+)\]
  ldrb	r1, \[r1\]
  cmp	sb, r1
  blo.w	#(?P<loc_45FF58>[0-9a-fx]+)
  movs	r6, #0
  add	r7, sp, #0x10
  mov	r8, r6
loc_4600C2:
  str.w	r8, \[sp, #0x10\]
  str.w	r8, \[sp, #0x14\]
  str.w	r8, \[sp, #0x18\]
  strh.w	r8, \[sp, #0xc\]
  bl	#(?P<get_fmu_dm>[0-9a-fx]+)
  ldr.w	r3, \[r0, #(?P<field_dm_callback_B4c>[0-9a-fx]+)\]
  add	r2, sp, #0xc
  add	r1, sp, #0x10
  uxtb	r0, r6
  blx	r3
  cbnz	r0, #(?P<loc_460152>[0-9a-fx]+)
  movs	r4, #0
  b	#(?P<loc_460170>[0-9a-fx]+)
loc_4600E8:
  ldr.w	r0, \[r7, r4, lsl #2\]
  ldrb.w	r1, \[r0, #(?P<field_var48_ofs38a>[0-9a-fx]+)\]
  cbz	r1, #(?P<loc_460154>[0-9a-fx]+)
  cmp	r6, #(3|5)
  beq	#(?P<loc_46016C>[0-9a-fx]+)
  ldrb.w	r1, \[r0, #(?P<field_var48_ofs3Ai>[0-9a-fx]+)\]
  cbz	r1, #(?P<loc_460132>[0-9a-fx]+)
  ldr	r1, \[r0, #(?P<field_var48_ofs34f>[0-9a-fx]+)\]
  cbnz	r1, #(?P<loc_460108>[0-9a-fx]+)
  ldrb.w	r2, \[r0, #(?P<field_var48_ofs39a>[0-9a-fx]+)\]
  cmp	r2, #2
  beq	#(?P<loc_460164>[0-9a-fx]+)
loc_460108:
  ldrb.w	r0, \[r0, #(?P<field_var48_ofs39b>[0-9a-fx]+)\]
  cbz	r0, #(?P<loc_460128>[0-9a-fx]+)
  str	r1, \[sp\]
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr.w	ip, \[r0, #0xc\]
  ; block of code in wm220_0306_v03.01.10.93:
  ;adr	r1, #(?P<cstr_fmt_ver_check_fail>[0-9a-fx]+)
  ;ldr.w	r0, \[r7, r4, lsl #2\]
  ;ldrb	r3, \[r0, #0xa\]
  ;ldr.w	r2, \[r0, #2\]
  ;movs	r0, #5
  ; block of code in wm330_0306_v03.01.10.93:
  ;ldr.w	r0, \[r7, r4, lsl #2\]
  ;ldrb.w	r1, [r0, #0x2a]
  ;ldr.w	r2, [r0, #2]
  ;movs	r0, #4
  ;and	r3, r1, #0x7f
  ;adr	r1, #(?P<cstr_fmt_ver_check_fail>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_2>([0-9a-fx]+[, ]*){7,12})
  blx	ip
loc_460128:
  ldr.w	r1, \[r7, r4, lsl #2\]
  strb.w	r8, \[r1, #(?P<field_var48_ofs39c>[0-9a-fx]+)\]
  b	#(?P<loc_460164>[0-9a-fx]+)
loc_460132:
  ldrb.w	r1, \[r0, #(?P<field_var48_ofs39d>[0-9a-fx]+)\]
  cmp	r1, #1
  beq	#(?P<loc_46015C>[0-9a-fx]+)
  ldr	r0, \[r0, #(?P<field_var48_ofs34g>[0-9a-fx]+)\]
  str	r0, \[sp\]
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr.w	ip, \[r0, #0xc\]
  ldr.w	r0, \[r7, r4, lsl #2\]
  ldrb(.w)?	(r3|r1), \[r0, #(?P<field_var48_ofs0Aa>[0-9a-fx]+)\]
  ; block of code in wm220_0306_v03.01.10.93:
  ;ldr.w	r2, \[r0, #2\]
  ; block of code in wm330_0306_v03.01.10.93:
  ;ldr.w	r2, \[r0, #2\]
  ;and	r3, r1, #0x7f
  dcw	(?P<undefined_varlen_3>([0-9a-fx]+[, ]*){2,4})
  b	#(?P<loc_460156>[0-9a-fx]+)
loc_460152:
  b	#(?P<loc_460178>[0-9a-fx]+)
loc_460154:
  b	#(?P<loc_46016C>[0-9a-fx]+)
loc_460156:
  movs	r0, #(5|4)
  adr	r1, #(?P<cstr_fmt_ver_check_pass>[0-9a-fx]+)
  blx	ip
loc_46015C:
  ldr.w	r1, \[r7, r4, lsl #2\]
  strb.w	fp, \[r1, #(?P<field_var48_ofs39e>[0-9a-fx]+)\]
loc_460164:
  ldr.w	r1, \[r7, r4, lsl #2\]
  strb.w	r8, \[r1, #(?P<field_var48_ofs3Aj>[0-9a-fx]+)\]
loc_46016C:
  adds	r4, r4, #1
  uxth	r4, r4
loc_460170:
  ldrh.w	r0, \[sp, #0xc\]
  cmp	r4, r0
  blo	#(?P<loc_4600E8>[0-9a-fx]+)
loc_460178:
  adds	r6, r6, #1
  uxth	r6, r6
  cmp	r6, #(?P<const_loop_limit_1>[0-9a-fx]+) ; known values 0x23 0x24
  blo	#(?P<loc_4600C2>[0-9a-fx]+)
  ldrb	r0, \[r5, #2\]
  cmp	r0, #1
  beq	#(?P<loc_460192>[0-9a-fx]+)
  movs	r0, #(?P<const_val_sim_b>[0-9a-fx]+) ; known values 0x24 0x25
  strb	r0, \[r5\]
  strb	r0, \[r5, #1\]
  strb.w	r8, \[r5, #2\]
  b	#(?P<loc_4601B0>[0-9a-fx]+)
loc_460192:
  ldr	r1, \[pc, #(?P<byte_20402ECE>[0-9a-fx]+)\]
  ldrb	r0, \[r1, #(?P<rel_byte_20402ED0>[0-9a-fx]+)\]
  cmp	r0, #0x32
  bhs	#(?P<loc_4601A0>[0-9a-fx]+)
  adds	r0, r0, #1
  strb	r0, \[r1, #(?P<rel_byte_20402ED0>[0-9a-fx]+)\]
  b	#(?P<loc_4601B0>[0-9a-fx]+)
loc_4601A0:
  strb.w	r8, \[r1, #(?P<rel_byte_20402ED0>[0-9a-fx]+)\]
  bl	#(?P<get_logger>[0-9a-fx]+)
  ldr	r2, \[r0, #4\]
  movs	r0, #(5|4)
  adr	r1, #(?P<cstr_invalid_version>[0-9a-fx]+)
  blx	r2
loc_4601B0:
  add	sp, #0x24
  movs	r0, #1
  pop.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){6,10}), pc}
""",
'vars': {
  'version_check':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'get_fmu_dm':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'get_logger':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_45FEEA':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'version_check_sub1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'loc_45FF4E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_45FF58':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_45FFB6':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_45FFD6':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_45FFE8':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_45FFEC':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_45FFF4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_45FFF6':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_460016':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_460028':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_46002C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  #'loc_46002E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  #'loc_460030':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_46003A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_46003E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_460042':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_46006E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_460080':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_460092':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_460096':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4600A2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4600AA':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4600B2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4600C2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4600E8':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_460108':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_460128':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_460132':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_460152':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_460154':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_460156':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_46015C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_460164':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_46016C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_460170':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_460178':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_460192':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4601A0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_4601B0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (5,8)},
  'undefined_varlen_2':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (7,12)},
  'undefined_varlen_3':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (2,4)},
  #'cstr_fmt_ver_check_fail':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_fmt_ver_check_pass':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_invalid_version':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'const_val_sim_a':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT16_T},
  'const_val_sim_b':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT16_T},
  'field_dm_callback_B4a':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_dm_callback_B4b':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_dm_callback_B4c':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs34a':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs34b':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs34c':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs34d':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs34e':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs34f':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs34g':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs38a':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs39a':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs39b':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs39c':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs39d':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs39e':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs0Aa':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs0Ba':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs0Bb':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs0Bc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs0Bd':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs3Aa':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs3Ab':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs3Ac':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs3Ae':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs3Af':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs3Ag':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs3Ah':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs3Ai':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'field_var48_ofs3Aj':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'const_loop_limit_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T},
  'byte_20402ECE':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'pvstru_D61C':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+",
    'variety': DataVariety.STRUCT, 'struct': DummyStruct,},
  'rel_byte_20402ED0':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'rel_simulator_running':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'unkval_9DE8':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
},
}

re_func_pvstru_D61C_WM330_V03_01_10_93 = {
'name': "pvstru_D61C",
'version': "wm330_0306_v03.01.10.93",
'no_search': True,
're': """
pvstru_D61C:
  ; array entry 0
  dcb	(0x5|0x3), (0x5|0x3), 0x2, 0x0
  dcd	(?P<pvstru_D61C_0_mc_version>[0-9a-fx]+)
  dcd	0x1
""",
'vars': {
  'pvstru_D61C':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'pvstru_D61C_0_mc_version':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT32_T,
    'public': "og_hardcoded.flyc", 'depend': "firmware_version", 'getter': version_string_to_int_getter},
},
}


re_general_list = [
  {'sect': ".text", 'func': re_func_wp_check_input_mission_validity_P3X_V01_05_0030,},
  {'sect': ".text", 'func': re_func_wp_check_input_mission_validity_WM330_V03_01_10_93,},
  {'sect': ".text", 'func': re_func_wp_mission_data_verify_P3X_V01_05_0030,},
  {'sect': ".text", 'func': re_func_wp_mission_data_verify_WM330_V03_01_10_93,},
  {'sect': ".data", 'func': re_func_firmware_release_marking_WM330_V03_01_10_93,},
  {'sect': ".text", 'func': re_func_check_activation_authority_WM330_V03_01_10_93,},
  {'sect': ".text", 'func': re_func_check_activation_authority_WM220_V03_01_10_93,},
  {'sect': ".text", 'func': re_func_check_activation_authority_WM220_V03_02_13_12,},
  {'sect': ".text", 'func': re_func_system_init_P3X_FW_V01_07_0060,},
  {'sect': ".text", 'func': re_func_imu_init_WM330_V03_01_10_93,},
  {'sect': ".text", 'func': re_func_imu_init_WM220_V03_01_10_93,},
  {'sect': ".text", 'func': re_func_hal_push_mc_version_P3X_FW_V01_07_0060,},
  {'sect': ".text", 'func': re_func_hal_push_mc_version_WM330_V03_01_10_93,},
  {'sect': ".text", 'func': re_func_navi_init_WM330_V03_01_10_93,},
  {'sect': ".text", 'func': re_func_navi_init_WM220_V03_01_10_93,},
  {'sect': ".text", 'func': re_func_init_config_table_version_WM330_V03_01_10_93,},
  {'sect': ".text", 'func': re_func_init_config_table_version_WM220_V03_01_10_93,},
  {'sect': ".text", 'func': re_func_log_version_info_P3X_FW_V01_07_0060,},
  {'sect': ".text", 'func': re_func_log_version_info_WM330_V03_01_10_93,},
  {'sect': ".text", 'func': re_func_log_version_info_WM220_V03_01_10_93,},
  {'sect': ".text", 'func': re_func_version_check_sub1_WM330_V03_01_10_93,},
  {'sect': ".text", 'func': re_func_version_check_WM330_V03_01_10_93,},
  {'sect': ".data", 'func': re_func_pvstru_D61C_WM330_V03_01_10_93,},
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
    try:
        main()
    except Exception as ex:
        eprint("Error: "+str(ex))
        #raise
        sys.exit(10)
