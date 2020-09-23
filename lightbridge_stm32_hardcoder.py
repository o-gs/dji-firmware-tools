#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Dji Lightbridge STM32 micro-controller binary hard-coded values editor.

The tool can parse Lightbridge MCU firmware converted to ELF.
It finds certain hard-coded values in the binary data, and allows
exporting or importing them.

Only 'setValue' element in the exported file is really changeable,
all the other data is just informational. This includes `maxValue` and
`minValue` - they don't do anything and changing them in the JSON file
will not influence update operation.

Exported values:

og_hardcoded.lightbridge_stm32.packet_received_attenuation_override -

  Allows to override attenuation value in an incomming packet command.
  The firmware allows to set attenuation via DUML packet received from
  another module of the drone, or RC. This parameter allows to replace
  the value set by that packet with a constant number. Value of `0` means
  the attenuation setting from packet should work as it originally does,
  value of `1` will set the attenuation to `packet_received_attenuation_value`
  and the value received in packet will be ignored.

og_hardcoded.lightbridge_stm32.packet_received_attenuation_value -

  Used as attenuation value when `packet_received_attenuation_override` is
  set to `1`. The value is not scaled to board variant - which means specific
  attenuation can mean different values of output power, depending on OFDM
  board used. Increasing attenuation by 1 changes the output signal strength
  by either -1 dBm or -0.25 dBm, depending on board variant. If override
  function is disabled, this value has no effect.

og_hardcoded.lightbridge_stm32.board_ad4_attenuation_tx?_* -

  Sets attenuation value for `tx1` or `tx2` for either `fcc` or `ce` region.
  Used on `ad4` OFDM board variant only.

  There are several variants of OFDM boards supported by the firmware.
  Each of these boards has different power output, so different attenuation
  values are set to keep the power level in bound of CE or FCC regulations.
  The values with `ad4` in name means board variant 4 with Analog Devices
  transciever.

  That chip is a double transciever, hence attenuation can be set for both
  channels - `tx1` and `tx2`. Each of the channels is used to send and receive
  data through one antenna within the drone. There are four antennas, and only
  two are used at a specific time. The drone switches used antennas
  automatically when a need arises. There are minor differences in default
  attenuation values between channels; these are due to specifics of high
  frequency signal progagation through the circuit board.

og_hardcoded.lightbridge_stm32.board_ad5_attenuation_tx?_* -

  Sets attenuation value for `tx1` or `tx2` for either `fcc` or `ce` region.
  Used on `ad5` OFDM board variant only.

  Look at previous values descriptions for detailed explanation.
  The values with `ad5` in name means board variant 5 with Analog Devices
  transciever.

og_hardcoded.lightbridge_stm32.board_ar6_attenuation_tx?_* -

  Sets attenuation value for `tx1` or `tx2` for either `fcc` or `ce` region.
  Used on `ar6` OFDM board variant only.

  Look at previous values descriptions for detailed explanation.
  The values with `ar6` in name means board variant 6 with Artosyn AR8003
  transciever.

og_hardcoded.lightbridge_stm32.board_ar7_attenuation_tx?_* -

  Sets attenuation value for `tx1` or `tx2` for either `fcc` or `ce` region.
  Used on `ar7` OFDM board variant only.

  Look at previous values descriptions for detailed explanation.
  The values with `ar7` in name means board variant 7 with Artosyn AR8003
  transciever.

og_hardcoded.lightbridge_stm32.board_ad2_attenuation_tx?_* -

  Sets attenuation value for `tx1` or `tx2` for either `fcc` or `ce` region.
  Used on `ad2` OFDM board variant only.

  Look at previous values descriptions for detailed explanation.
  The values with `ad2` in name means board variant 2 with Analog Devices
  transciever.

og_hardcoded.lightbridge_stm32.power_zone_selection_override -

  The C1 firmware within Remote Controller is responsinble for selecting
  either FCC or CE power zone for both the RC and the drone. Selection is
  made when the GPS coordinates are stable - then they are compared to
  list of areas where FCC compliant power levels can be used. This causes
  a flag to be set within a block of config data shared between RC and the
  drone.

  This value allows changing the behavior when power zone is about to be
  selected from geo coordinates. Value of `0` means the value based on
  GPS location will be stored in shared config block. Value of `1` will
  cause the stored flag to be overriden and always set to a value which
  corresponds to FCC power zone.

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
__version__ = "0.0.2"
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

sys.path.insert(0, './')
from amba_sys_hardcoder import eprint, elf_march_to_asm_config, \
  armfw_elf_whole_section_search, armfw_elf_match_to_public_values, \
  armfw_elf_paramvals_extract_list, armfw_elf_get_value_update_bytes, \
  armfw_elf_paramvals_get_depend_list, armfw_elf_publicval_update, \
  armfw_elf_paramvals_update_list, armfw_elf_generic_objdump, \
  armfw_asm_search_strings_to_re_list, armfw_elf_paramvals_export_json, \
  armfw_elf_paramvals_export_simple_list, armfw_elf_paramvals_export_mapfile, \
  VarType, DataVariety, CodeVariety


def packet_received_attenuation_override_update(asm_arch, elf_sections, re_list, glob_params_list, var_info, new_var_nativ):
    """ Callback function to prepare 'packet_received_attenuation_override_update' value change.
    Changes variable type as required for the switch.
    """
    glob_re = glob_params_list[var_info['cfunc_name']+'..re']['value']
    glob_re_size = glob_params_list[var_info['cfunc_name']+'..re_size']['value']
    # Multi-version support - get patterns for current version
    if var_info['cfunc_ver'] == re_func_cmd_exec_set09_cmd12_P3X_V01_07_original['version']:
        re_func_cmd_exec_set09_cmd12_CURR_original = re_func_cmd_exec_set09_cmd12_P3X_V01_07_original
        re_func_cmd_exec_set09_cmd12_CURR_constatt = re_func_cmd_exec_set09_cmd12_P3X_V01_07_constatt
    elif var_info['cfunc_ver'] == re_func_cmd_exec_set09_cmd12_C1_V01_04_m1400_original['version']:
        re_func_cmd_exec_set09_cmd12_CURR_original = re_func_cmd_exec_set09_cmd12_C1_V01_04_m1400_original
        re_func_cmd_exec_set09_cmd12_CURR_constatt = re_func_cmd_exec_set09_cmd12_C1_V01_04_m1400_constatt
    else:
        raise ValueError("Unrecognized version of 'cmd_exec_set09_cmd12' - internal error.")
    # Note that the value we're modifying is not the one we got in var_info
    var_name = 'packet_received_attenuation_value'
    for cfunc_name in (re_func_cmd_exec_set09_cmd12_CURR_original['name'], re_func_cmd_exec_set09_cmd12_CURR_constatt['name'], ):
        var_full_name = cfunc_name+'.'+var_name
        if var_full_name in glob_params_list:
            glob_var_info = glob_params_list[var_full_name]
            break
    if new_var_nativ == 0:
        # Set variables requires to change constatt back to original
        patterns = re_func_cmd_exec_set09_cmd12_CURR_original
        re_var_info = patterns['vars'][var_name]
        if glob_var_info['type'] != re_var_info['type']:
            glob_var_info['type'] = re_var_info['type']
            del glob_var_info['line']
    else:
        # Set variables requires to change original into constatt
        patterns = re_func_cmd_exec_set09_cmd12_CURR_constatt
        re_lines, re_labels = armfw_asm_search_strings_to_re_list(patterns['re'])
        re_var_info = patterns['vars'][var_name]
        if glob_var_info['type'] != re_var_info['type']:
            for ln_num, ln_regex in enumerate(re_lines):
                re_line = re.search(r'^.+P<'+var_name+'>.+$', ln_regex)
                if re_line:
                    glob_var_info['line'] = ln_num
                    glob_var_info['address'] = var_info['address'] + sum(glob_re_size[0:ln_num])
                    break
            glob_var_info['type'] = re_var_info['type']


def version_string_to_int_getter(val):
  ver = re.search(r'^([0-9]+)[.]([0-9]+)[.]([0-9]+)[.]([0-9]+)$', val)
  ver_major = int(ver.group(1),10)
  ver_minor = int(ver.group(2),10)
  ver_mmtnc = int(ver.group(3),10)
  ver_revsn = int(ver.group(4),10)
  return (ver_major << 24) + (ver_minor << 16) + (ver_mmtnc << 8) + (ver_revsn)


def version_int_to_string_getter(val):
  if isinstance(val, str):
      ver = int(val,10)
  else:
      ver = int(val)
  ver_major = (ver >> 24) & 0xff
  ver_minor = (ver >> 16) & 0xff
  ver_mmtnc = (ver >>  8) & 0xff
  ver_revsn = (ver      ) & 0xff
  return "{:02d}.{:02d}.{:02d}.{:02d}".format(ver_major, ver_minor, ver_mmtnc, ver_revsn)


re_func_cmd_exec_set09_cmd12_P3X_V01_07_original = {
'name': "cmd_exec_set09_cmd12-original",
'version': "P3X_FW_V01.07",
're': """
cmd_exec_set09_cmd12:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){2,8}), lr}
  mov	r5, r0
  ; in P3X_FW_V01.07, the wildcard matches lines:
  ;mov	r6, r1
  ;movs	r0, #0
  ; in P3X_FW_V01.08, the wildcard matches lines:
  ;movs	r0, #0
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){1,4})
  (str|strb.w)	r0, \[sp\]
  add.w	r4, r5, #0xb
  bl	#(?P<tcx_config_80105FA>[0-9a-fx]+)
  ldrb	r0, \[r4\]
  ; in P3X_FW_V01.07, the wildcard matches lines:
  ;lsrs	r0, r0, #7
  ;bne	#(?P<loc_label01>[0-9a-fx]+)
  ; in P3X_FW_V01.08, the wildcard matches lines:
  ;lsls	r0, r0, #0x18
  ;bmi	#(?P<loc_label01>[0-9a-fx]+)
  ;movs	r0, #0
  dcw	(?P<undefined_varlen_2>([0-9a-fx]+[, ]*){2,4})
  bl	#(?P<set_transciever_flag_20001A28_E>[0-9a-fx]+)
  b	#(?P<loc_label02>[0-9a-fx]+)
loc_label01:
  movs	r0, #1
  bl	#(?P<set_transciever_flag_20001A28_E>[0-9a-fx]+)
  ldrb	(?P<regB>r[0-9]), \[r4\]
  and	r0, (?P<regB>r[0-9]), #0x7f
  bl	#(?P<set_transciever_flag_20001A28_D>[0-9a-fx]+)
loc_label02:
  ldrb	(?P<regC>r[0-9]), \[r4, #1\]
  lsrs	r0, (?P<regC>r[0-9]), #6
  bl	#(?P<set_transciever_flag_20001A28_A>[0-9a-fx]+)
  ldrb	(?P<regD>r[0-9]), \[r4, #1\]
  and	r0, (?P<regD>r[0-9]), #0x3f
  bl	#(?P<set_transciever_flag_20001A28_B>[0-9a-fx]+)
  ldrb	r0, \[r4, #2\]
  bl	#(?P<set_transciever_attenuation>[0-9a-fx]+)
  ldrb	r0, \[r4, #3\]
  bl	#(?P<set_transciever_flag_20001A28_C>[0-9a-fx]+)
  movs	r3, #1
  mov	r2, sp
  mov	r1, r5
  ldr	r0, \[pc, #(?P<rel_func_packet_send>[0-9a-fx]+)\] ; relative address to func packet_send
  bl	#(?P<packet_make_response>[0-9a-fx]+)
  pop	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){2,8}), pc}
""",
'vars': {
  'cmd_exec_set09_cmd12':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_received_attenuation_override':	{'type': VarType.DETACHED_DATA, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "1", 'defaultValue': "0", 'setValue': "0",
    'custom_params_callback': packet_received_attenuation_override_update,
    'description': "What to do when received a packet with transceiver power set request; 0 - use the received attenuation value, 1 - override the value with constant one"},
  'packet_received_attenuation_value':	{'type': VarType.UNUSED_DATA, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'setValue': "40",
    'description': "Constant attenuation value used when packet_received_attenuation_override is enabled; unit depends on OFDM board type"},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,4)},
  'undefined_varlen_2':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (2,4)},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regB':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regC':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regD':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  #'loc_label01':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label02':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'tcx_config_80105FA':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_B':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_D':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_attenuation':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'rel_func_packet_send':		{'type': VarType.RELATIVE_ADDR_TO_CODE, 'baseaddr': "PC+", 'variety': CodeVariety.FUNCTION},
  'packet_make_response':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
},
}

re_func_cmd_exec_set09_cmd12_P3X_V01_07_constatt = {
'name': "cmd_exec_set09_cmd12-constatt",
'version': "P3X_FW_V01.07",
're': """
cmd_exec_set09_cmd12:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){2,8}), lr}
  mov	r5, r0
  ; in P3X_FW_V01.07, the wildcard matches lines:
  ;mov	r6, r1
  ;movs	r0, #0
  ; in P3X_FW_V01.08, the wildcard matches lines:
  ;movs	r0, #0
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){1,4})
  (str|strb.w)	r0, \[sp\]
  add.w	r4, r5, #0xb
  bl	#(?P<tcx_config_80105FA>[0-9a-fx]+)
  ldrb	r0, \[r4\]
  ; in P3X_FW_V01.07, the wildcard matches lines:
  ;lsrs	r0, r0, #7
  ;bne	#(?P<loc_label01>[0-9a-fx]+)
  ; in P3X_FW_V01.08, the wildcard matches lines:
  ;lsls	r0, r0, #0x18
  ;bmi	#(?P<loc_label01>[0-9a-fx]+)
  ;movs	r0, #0
  dcw	(?P<undefined_varlen_2>([0-9a-fx]+[, ]*){2,4})
  bl	#(?P<set_transciever_flag_20001A28_E>[0-9a-fx]+)
  b	#(?P<loc_label02>[0-9a-fx]+)
loc_label01:
  movs	r0, #1
  bl	#(?P<set_transciever_flag_20001A28_E>[0-9a-fx]+)
  ldrb	(?P<regB>r[0-9]), \[r4\]
  and	r0, (?P<regB>r[0-9]), #0x7f
  bl	#(?P<set_transciever_flag_20001A28_D>[0-9a-fx]+)
loc_label02:
  ldrb	(?P<regC>r[0-9]), \[r4, #1\]
  lsrs	r0, (?P<regC>r[0-9]), #6
  bl	#(?P<set_transciever_flag_20001A28_A>[0-9a-fx]+)
  ldrb	(?P<regD>r[0-9]), \[r4, #1\]
  and	r0, (?P<regD>r[0-9]), #0x3f
  bl	#(?P<set_transciever_flag_20001A28_B>[0-9a-fx]+)
  movs	r0, #(?P<packet_received_attenuation_value>[0-9a-fx]+)
  bl	#(?P<set_transciever_attenuation>[0-9a-fx]+)
  ldrb	r0, \[r4, #3\]
  bl	#(?P<set_transciever_flag_20001A28_C>[0-9a-fx]+)
  movs	r3, #1
  mov	r2, sp
  mov	r1, r5
  ldr	r0, \[pc, #(?P<rel_func_packet_send>[0-9a-fx]+)\] ; relative address to func packet_send
  bl	#(?P<packet_make_response>[0-9a-fx]+)
  pop	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){2,8}), pc}
""",
'vars': {
  'cmd_exec_set09_cmd12':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_received_attenuation_override':	{'type': VarType.DETACHED_DATA, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "1", 'defaultValue': "0", 'setValue': "1",
    'custom_params_callback': packet_received_attenuation_override_update,
    'description': "What to do when received a packet with transceiver power set request; 0 - use the received attenuation value, 1 - override the value with constant one"},
  'packet_received_attenuation_value':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255",
    'description': "Constant attenuation value used when packet_received_attenuation_override is enabled; unit depends on OFDM board type"},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,4)},
  'undefined_varlen_2':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (2,4)},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regB':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regC':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regD':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  #'loc_label01':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label02':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'tcx_config_80105FA':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_B':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_D':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_attenuation':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'rel_func_packet_send':		{'type': VarType.RELATIVE_ADDR_TO_CODE, 'baseaddr': "PC+", 'variety': CodeVariety.FUNCTION},
  'packet_make_response':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
},
}

re_func_cmd_exec_set09_cmd12_C1_V01_04_m1400_original = {
'name': "cmd_exec_set09_cmd12-original",
'version': "C1_FW_V01.04-m1400",
're': """
cmd_exec_set09_cmd12:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){2,8}), lr}
  ; in C1_FW_V01.04-m1400, the wildcard are lines:
  ;sub	sp, #(?P<loc_frame_len>[0-9a-fx]+)
  ;mov	(?P<regH>r[0-9]), r0
  ;add.w	(?P<regE>r[0-9]), r0, #0xb
  ; in C1_FW_V01.06-m1400, the wildcard are lines:
  ;mov	(?P<regH>r[0-9]), r0
  ;add.w	(?P<regE>r[0-9]), r0, #0xb
  ;sub	sp, #(?P<loc_frame_len>[0-9a-fx]+)
  ;movs	r0, #0
  ; in C1_FW_V01.06-m1401, the wildcard are lines:
  ;sub	sp, #(?P<loc_frame_len>[0-9a-fx]+)
  ;mov	r6, r0
  ;mov	(?P<regH>r[0-9]), r6
  ;add.w	(?P<regE>r[0-9]), (?P<regH>r[0-9]), #0xb
  ;movs	r0, #0
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){2,8})
  bl	#(?P<tcx_config_80105FA>[0-9a-fx]+)
  ldrb	(?P<regB>r[0-9]), \[(?P<regE>r[0-9])\]
  (lsls|lsrs)	r0, (?P<regB>r[0-9]), #(?P<bitshift1>[0-9a-fx]+)
  ; in C1_FW_V01.04-m1400, the wildcard are lines:
  ;bmi	#(?P<loc_label01>[0-9a-fx]+)
  ; in C1_FW_V01.06-m1401, the wildcard are lines:
  ;cbnz	r0, #(?P<loc_label01>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_2>([0-9a-fx]+[, ]*){1,2})
  movs	r0, #0
  bl	#(?P<set_transciever_flag_20001A28_E>[0-9a-fx]+)
  ; in C1_FW_V01.03-m1400, the wildcard are lines:
  ;b	#(?P<loc_label02>[0-9a-fx]+)
  ;dcw	0x0
  ;dcd	(?P<byte_100000A8>[0-9a-fx]+)
  ;[...]
  ;dcd	(?P<word_1000000C>[0-9a-fx]+)
  ; in C1_FW_V01.04-m1400, the wildcard are lines:
  ;b	#(?P<loc_label02>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_6>([0-9a-fx]+[, ]*){1,32})
loc_label01:
  movs	r0, #1
  bl	#(?P<set_transciever_flag_20001A28_E>[0-9a-fx]+)
  ldrb	(?P<regC>r[0-9]), \[(?P<regE>r[0-9])\]
  and	r0, (?P<regC>r[0-9]), #0x7f
  bl	#(?P<set_transciever_flag_20001A28_D>[0-9a-fx]+)
loc_label02:
  ldrb	(?P<regD>r[0-9]), \[(?P<regE>r[0-9]), #1\]
  and	r0, (?P<regD>r[0-9]), #0x3f
  bl	#(?P<set_transciever_flag_20001A28_B>[0-9a-fx]+)
  ldrb	r0, \[(?P<regE>r[0-9]), #2\]
  bl	#(?P<set_transciever_attenuation>[0-9a-fx]+)
  ldrb	r0, \[(?P<regE>r[0-9]), #3\]
  bl	#(?P<set_transciever_flag_20001A28_C>[0-9a-fx]+)
  ldrb	(?P<regF>r[0-9]), \[(?P<regH>r[0-9]), #8\]
  ubfx	(?P<regI>r[0-9]), (?P<regF>r[0-9]), #5, #2
  cmp	(?P<regI>r[0-9]), #2
  bne	#(?P<loc_retlabel01>[0-9a-fx]+)
  movs	(?P<regG>r[0-9]), #0
  ; in C1_FW_V01.04-m1400, the wildcard are lines:
  ;strb.w	(?P<regG>r[0-9]), \[sp, #(?P<locvar_ptr_01>[0-9a-fx]+)\]
  ;orr	r0, r0, #0x80
  ; in C1_FW_V01.06-m1401, the wildcard are lines:
  ;str	(?P<regG>r[0-9]), \[sp, #(?P<locvar_ptr_01>[0-9a-fx]+)\]
  ;ldrb	r0, \[(?P<regH>r[0-9]), #8\]
  ;bic	r0, r0, #0x80
  ;adds	r0, #0x80
  dcw	(?P<undefined_varlen_3>([0-9a-fx]+[, ]*){2,8})
  strb	r0, \[(?P<regH>r[0-9]), #8\]
  ; in C1_FW_V01.04-m1400, the wildcard are lines:
  ;mov	r3, sp
  ; in C1_FW_V01.06-m1401, the wildcard are lines:
  ;add	r3, sp, #4
  dcw	(?P<undefined_varlen_4>([0-9a-fx]+[, ]*){1,2})
  movs	r2, #1
  add	r1, sp, #(?P<locvar_ptr_01>[0-9a-fx]+)
  mov	r0, (?P<regH>r[0-9])
  bl	#(?P<packet_prepare_response>[0-9a-fx]+)
  ; in C1_FW_V01.04-m1400, the wildcard are lines:
  ;mov	r0, sp
  ; in C1_FW_V01.06-m1401, the wildcard are lines:
  ;add	r0, sp, #4
  dcw	(?P<undefined_varlen_5>([0-9a-fx]+[, ]*){1,2})
  bl	#(?P<packet_send>[0-9a-fx]+)
loc_retlabel01:
  add	sp, #(?P<loc_frame_len>[0-9a-fx]+)
  pop	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){2,8}), pc}
""",
'vars': {
  'cmd_exec_set09_cmd12':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_received_attenuation_override':	{'type': VarType.DETACHED_DATA, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "1", 'defaultValue': "0", 'setValue': "0",
    'custom_params_callback': packet_received_attenuation_override_update,
    'description': "What to do when received a packet with transceiver power set request; 0 - use the received attenuation value, 1 - override the value with constant one"},
  'packet_received_attenuation_value':	{'type': VarType.UNUSED_DATA, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'setValue': "40",
    'description': "Constant attenuation value used when packet_received_attenuation_override is enabled; unit depends on OFDM board type"},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (2,8)},
  'undefined_varlen_2':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,2)},
  'undefined_varlen_3':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (2,8)},
  'undefined_varlen_4':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,2)},
  'undefined_varlen_5':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,2)},
  'undefined_varlen_6':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,32)},
  'loc_frame_len':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'locvar_ptr_01':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'bitshift1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regB':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regC':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regD':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regE':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regF':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regG':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regH':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regI':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  #'loc_label01':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label02':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_retlabel01':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'tcx_config_80105FA':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_B':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_D':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_attenuation':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_send':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_prepare_response':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
},
}

re_func_cmd_exec_set09_cmd12_C1_V01_04_m1400_constatt = {
'name': "cmd_exec_set09_cmd12-constatt",
'version': "C1_FW_V01.04-m1400",
're': """
cmd_exec_set09_cmd12:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){2,8}), lr}
  ; in C1_FW_V01.04-m1400, the wildcard are lines:
  ;sub	sp, #(?P<loc_frame_len>[0-9a-fx]+)
  ;mov	(?P<regH>r[0-9]), r0
  ;add.w	(?P<regE>r[0-9]), r0, #0xb
  ; in C1_FW_V01.06-m1400, the wildcard are lines:
  ;mov	(?P<regH>r[0-9]), r0
  ;add.w	(?P<regE>r[0-9]), r0, #0xb
  ;sub	sp, #(?P<loc_frame_len>[0-9a-fx]+)
  ;movs	r0, #0
  ; in C1_FW_V01.06-m1401, the wildcard are lines:
  ;sub	sp, #(?P<loc_frame_len>[0-9a-fx]+)
  ;mov	r6, r0
  ;mov	(?P<regH>r[0-9]), r6
  ;add.w	(?P<regE>r[0-9]), (?P<regH>r[0-9]), #0xb
  ;movs	r0, #0
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){2,8})
  bl	#(?P<tcx_config_80105FA>[0-9a-fx]+)
  ldrb	(?P<regB>r[0-9]), \[(?P<regE>r[0-9])\]
  (lsls|lsrs)	r0, (?P<regB>r[0-9]), #(?P<bitshift1>[0-9a-fx]+)
  ; in C1_FW_V01.04-m1400, the wildcard are lines:
  ;bmi	#(?P<loc_label01>[0-9a-fx]+)
  ; in C1_FW_V01.06-m1401, the wildcard are lines:
  ;cbnz	r0, #(?P<loc_label01>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_2>([0-9a-fx]+[, ]*){1,2})
  movs	r0, #0
  bl	#(?P<set_transciever_flag_20001A28_E>[0-9a-fx]+)
  ; in C1_FW_V01.03-m1400, the wildcard are lines:
  ;b	#(?P<loc_label02>[0-9a-fx]+)
  ;dcw	0x0
  ;dcd	(?P<byte_100000A8>[0-9a-fx]+)
  ;[...]
  ;dcd	(?P<word_1000000C>[0-9a-fx]+)
  ; in C1_FW_V01.04-m1400, the wildcard are lines:
  ;b	#(?P<loc_label02>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_6>([0-9a-fx]+[, ]*){1,32})
loc_label01:
  movs	r0, #1
  bl	#(?P<set_transciever_flag_20001A28_E>[0-9a-fx]+)
  ldrb	(?P<regC>r[0-9]), \[(?P<regE>r[0-9])\]
  and	r0, (?P<regC>r[0-9]), #0x7f
  bl	#(?P<set_transciever_flag_20001A28_D>[0-9a-fx]+)
loc_label02:
  ldrb	(?P<regD>r[0-9]), \[(?P<regE>r[0-9]), #1\]
  and	r0, (?P<regD>r[0-9]), #0x3f
  bl	#(?P<set_transciever_flag_20001A28_B>[0-9a-fx]+)
  movs	r0, #(?P<packet_received_attenuation_value>[0-9a-fx]+)
  bl	#(?P<set_transciever_attenuation>[0-9a-fx]+)
  ldrb	r0, \[(?P<regE>r[0-9]), #3\]
  bl	#(?P<set_transciever_flag_20001A28_C>[0-9a-fx]+)
  ldrb	(?P<regF>r[0-9]), \[(?P<regH>r[0-9]), #8\]
  ubfx	(?P<regI>r[0-9]), (?P<regF>r[0-9]), #5, #2
  cmp	(?P<regI>r[0-9]), #2
  bne	#(?P<loc_retlabel01>[0-9a-fx]+)
  movs	(?P<regG>r[0-9]), #0
  ; in C1_FW_V01.04-m1400, the wildcard are lines:
  ;strb.w	(?P<regG>r[0-9]), \[sp, #(?P<locvar_ptr_01>[0-9a-fx]+)\]
  ;orr	r0, r0, #0x80
  ; in C1_FW_V01.06-m1401, the wildcard are lines:
  ;str	(?P<regG>r[0-9]), \[sp, #(?P<locvar_ptr_01>[0-9a-fx]+)\]
  ;ldrb	r0, \[(?P<regH>r[0-9]), #8\]
  ;bic	r0, r0, #0x80
  ;adds	r0, #0x80
  dcw	(?P<undefined_varlen_3>([0-9a-fx]+[, ]*){2,8})
  strb	r0, \[(?P<regH>r[0-9]), #8\]
  ; in C1_FW_V01.04-m1400, the wildcard are lines:
  ;mov	r3, sp
  ; in C1_FW_V01.06-m1401, the wildcard are lines:
  ;add	r3, sp, #4
  dcw	(?P<undefined_varlen_4>([0-9a-fx]+[, ]*){1,2})
  movs	r2, #1
  add	r1, sp, #(?P<locvar_ptr_01>[0-9a-fx]+)
  mov	r0, (?P<regH>r[0-9])
  bl	#(?P<packet_prepare_response>[0-9a-fx]+)
  ; in C1_FW_V01.04-m1400, the wildcard are lines:
  ;mov	r0, sp
  ; in C1_FW_V01.06-m1401, the wildcard are lines:
  ;add	r0, sp, #4
  dcw	(?P<undefined_varlen_5>([0-9a-fx]+[, ]*){1,2})
  bl	#(?P<packet_send>[0-9a-fx]+)
loc_retlabel01:
  add	sp, #(?P<loc_frame_len>[0-9a-fx]+)
  pop	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){2,8}), pc}
""",
'vars': {
  'cmd_exec_set09_cmd12':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_received_attenuation_override':	{'type': VarType.DETACHED_DATA, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "1", 'defaultValue': "0", 'setValue': "1",
    'custom_params_callback': packet_received_attenuation_override_update,
    'description': "What to do when received a packet with transceiver power set request; 0 - use the received attenuation value, 1 - override the value with constant one"},
  'packet_received_attenuation_value':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255",
    'description': "Constant attenuation value used when packet_received_attenuation_override is enabled; unit depends on OFDM board type"},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (2,8)},
  'undefined_varlen_2':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,2)},
  'undefined_varlen_3':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (2,8)},
  'undefined_varlen_4':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,2)},
  'undefined_varlen_5':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,2)},
  'undefined_varlen_6':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,32)},
  'loc_frame_len':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T},
  'locvar_ptr_01':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.UNKNOWN},
  'bitshift1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regB':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regC':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regD':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regE':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regF':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regG':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regH':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regI':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  #'loc_label01':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label02':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_retlabel01':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'tcx_config_80105FA':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_B':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_D':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_attenuation':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_send':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_prepare_response':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
},
}

re_func_tcx_config_power_zone_P3X_V01_08 = {
'name': "tcx_config_power_zone",
'version': "P3X_FW_V01.08",
# This function exists only in P3X_FW_V01.08.0080_m0900 and greater.
# It is also not present in C1_FW. To hide warnings there, we will mark it
# as alternative of a function which isn't really related, but it's present
# in all C1 firmwares.
'alt_name': "update_tcx_power_zone_flag-.*",
're': """
tcx_config_power_zone:
  ldr	r1, \[pc, #(?P<unk_var01>[0-9a-fx]+)\]
  push	{r4, lr}
  ldrb	r2, \[r1, #(?P<unk_var02>[0-9a-fx]+)\]
  cmp	r0, r2
  beq	#(?P<loc_label_ret2>[0-9a-fx]+)
  strb	r0, \[r1, #(?P<unk_var02>[0-9a-fx]+)\]
  cbz	r0, #(?P<loc_label01>[0-9a-fx]+)
  cmp	r0, #1
  bne	#(?P<loc_label_ret2>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_label09>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  beq	#(?P<loc_label17>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_label11>[0-9a-fx]+)
  b	#(?P<loc_label13>[0-9a-fx]+)
loc_label01:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_board_ad4_ce>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  beq	#(?P<loc_label03>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_board_ar6_ce>[0-9a-fx]+)
  b	#(?P<loc_label07>[0-9a-fx]+)
loc_board_ad4_ce:
  movs	r2, #0
  movs	r1, #(?P<board_ad4_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad4_attenuation_tx2_ce>[0-9a-fx]+)
  b	#(?P<loc_board_ad_set_tx2a>[0-9a-fx]+)
loc_label03:
  movs	r2, #0
  movs	r1, #(?P<board_ad5_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad5_attenuation_tx2_ce>[0-9a-fx]+)
loc_board_ad_set_tx2a:
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  b	#(?P<loc_label06>[0-9a-fx]+)
loc_board_ar6_ce:
  movs	r2, #0
  movs	r1, #(?P<board_ar6_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar6_attenuation_tx2_ce>[0-9a-fx]+)
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
loc_label06:
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_label07:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  beq	#(?P<loc_board_ar7>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  ; in P3X_FW_V01.08, wildcard data replaces one line:
  ;bne	#(?P<loc_label_ret1>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){1,64})
; Set attenuation values for board AD2 in CE zone
  movs	r2, #0
  movs	r1, #(?P<board_ad2_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad2_attenuation_tx2_ce>[0-9a-fx]+)
  b	#(?P<loc_board_ad_set_tx2b>[0-9a-fx]+)
loc_board_ar7:
; Set attenuation values for board AR7 in CE zone
  movs	r2, #0
  movs	r1, #(?P<board_ar7_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar7_attenuation_tx2_ce>[0-9a-fx]+)
  b	#(?P<loc_board_ar_set_tx2>[0-9a-fx]+)
loc_label09:
  movs	r2, #0
  movs	r1, #(?P<board_ad4_attenuation_tx1_fcc>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad4_attenuation_tx2_fcc>[0-9a-fx]+)
  b	#(?P<loc_label10>[0-9a-fx]+)
loc_label17:
  movs	r2, #0
  movs	r1, #(?P<board_ad5_attenuation_tx1_fcc>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad5_attenuation_tx2_fcc>[0-9a-fx]+)
loc_label10:
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  b	#(?P<loc_label12>[0-9a-fx]+)
loc_label11:
  movs	r2, #0
  movs	r1, #(?P<board_ar6_attenuation_tx1_fcc>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar6_attenuation_tx2_fcc>[0-9a-fx]+)
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
loc_label12:
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_label13:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  beq	#(?P<loc_label18>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  bne	#(?P<loc_label_ret1>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #(?P<board_ad2_attenuation_tx1_fcc>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad2_attenuation_tx2_fcc>[0-9a-fx]+)
loc_board_ad_set_tx2b:
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
loc_label15:
  ; in wm330_0900_v03.01.00.01_20160422.fw_0900, the below wildcard is one line:
  ;pop.w	{r4, lr}
  dcw	(?P<undefined_varlen_2>([0-9a-fx]+[, ]*){1,64})
loc_j_ad936x_reg_sync_write:
  b.w	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_label18:
  movs	r2, #0
  movs	r1, #(?P<board_ar7_attenuation_tx1_fcc>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar7_attenuation_tx2_fcc>[0-9a-fx]+)
loc_board_ar_set_tx2:
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  b	#(?P<loc_label15>[0-9a-fx]+)
loc_label_ret1:
  pop	{r4, pc}
""",
'vars': {
  'tcx_config_power_zone':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'loc_label01':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_ad4_ce':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label03':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_ad_set_tx2a':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_ar6_ce':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label06':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label07':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_ar7':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label09':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label11':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label13':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label_ret2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label17':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label10':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label12':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_ad_set_tx2b':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label18':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_ar_set_tx2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label15':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'get_board_version':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'unk_var01':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var02':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,64)},
  'undefined_varlen_2':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,64)},
  'board_ad4_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "50",
    'description': "Transceiver attenuation value for board type 4 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad4_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "44",
    'description': "Transceiver attenuation value for board type 4 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad5_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "44",
    'description': "Transceiver attenuation value for board type 5 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad5_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "45",
    'description': "Transceiver attenuation value for board type 5 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ar6_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "20",
    'description': "Transceiver attenuation value for board type 6 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar6_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "20",
    'description': "Transceiver attenuation value for board type 6 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar7_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "12",
    'description': "Transceiver attenuation value for board type 7 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar7_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "12",
    'description': "Transceiver attenuation value for board type 7 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ad2_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "44",
    'description': "Transceiver attenuation value for board type 2 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad2_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "45",
    'description': "Transceiver attenuation value for board type 2 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad4_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "10",
    'description': "Transceiver attenuation value for board type 4 with Analog Devices chip, change by 1 means 0.25 dBm",
    'hint1': "value of 0 means minimal attenuation and therefore max output power of the transceiver"},
  'board_ad4_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "4",
    'description': "Transceiver attenuation value for board type 4 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad5_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "4",
    'description': "Transceiver attenuation value for board type 5 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad5_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "5",
    'description': "Transceiver attenuation value for board type 5 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ar6_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "10",
    'description': "Transceiver attenuation value for board type 6 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar6_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "10",
    'description': "Transceiver attenuation value for board type 6 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ad2_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "4",
    'description': "Transceiver attenuation value for board type 2 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad2_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "5",
    'description': "Transceiver attenuation value for board type 2 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ar7_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "2",
    'description': "Transceiver attenuation value for board type 7 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar7_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "2",
    'description': "Transceiver attenuation value for board type 7 with Artosyn chip, change by 1 means 1 dBm"},
},
}


re_func_tcx_config_update1_P3X_V01_04 = {
'name': "tcx_config_update1",
'version': "P3X_FW_V01.04",
're': """
tcx_config_update1:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), lr}
  ldr	r0, \[pc, #(?P<ptr_ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_tcx_control_attenuation_by_packet>[0-9a-fx]+)\]
  cmp	r0, #0
loc_start:
  beq	#(?P<loc_phase2_s5>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ptr_ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  ldr	r1, \[pc, #(?P<ptr_active_transciever_attenuation>[0-9a-fx]+)\]
  ldrb	r1, \[r1\]
  cmp	r0, r1
  beq	#(?P<loc_start>[0-9a-fx]+)
  movs	r0, #0xe9 ; FPGA_REG_UNKN_E9
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  ; in P3X_FW_V01.04, the wildcard matches lines:
  ;and	r0, r0, #3
  ;b	#(?P<loc_800E78C>[0-9a-fx]+)
  ;dcd	... (x13)
  ;loc_800E78C:
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){1,32})
  cmp	r0, #3
  bne	#(?P<loc_800FC36>[0-9a-fx]+)
  movs	r0, #0
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  orr	r0, r0, #8
  ldr	r1, \[pc, #(?P<rel_fpga_reg_unkn00_value>[0-9a-fx]+)\]
  strb	r0, \[r1\]
  mov	r0, r1
  ldrb	r0, \[r0\]
  orr	r1, r0, #1
  movs	r0, #0 ; FPGA_REG_UNKN_00
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r1, #1
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r1, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_ad_from_pkt_s1>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_ad_from_pkt_s1:
  movs	r1, #1
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r1, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_phase2_s4>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<rel_fpga_reg_unkn00_value>[0-9a-fx]+)\]
  ldrb	r1, \[r0\]
  movs	r0, #0 ; FPGA_REG_UNKN_00
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  ldr	r1, \[pc, #(?P<active_transciever_attenuation>[0-9a-fx]+)\]
  strb	r0, \[r1\]
loc_800FC36:
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_tcx_control_attenuation_by_packet>[0-9a-fx]+)\]
  cbnz	r0, #(?P<loc_800FD20>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldr	r0, \[r0, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  ldr	r1, \[pc, #(?P<transceiver_pwr_mode_unk016C>[0-9a-fx]+)\]
  ldrb	r1, \[r1\]
  cmp.w	r1, r0, lsr #31
  beq	#(?P<loc_800FD20>[0-9a-fx]+)
  movs	r0, #0xe9 ; FPGA_REG_UNKN_E9
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  and	r0, r0, #3
  cmp	r0, #3
  bne	#(?P<loc_800FD20>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldr	r0, \[r0, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  lsrs	r0, r0, #0x1f
  beq	#(?P<loc_init_fcc>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad4_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad4_attenuation_tx2_ce>[0-9a-fx]+)
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  b	#(?P<loc_800FCD0>[0-9a-fx]+)
loc_init_fcc:
  movs	r2, #1
  movs	r1, #(?P<board_ad4_attenuation_tx1_fcc>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad4_attenuation_tx2_fcc>[0-9a-fx]+)
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_800FCD0:
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldr	r0, \[r0, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  lsrs	r0, r0, #0x1f
  ldr	r1, \[pc, #(?P<transceiver_pwr_mode_unk016C>[0-9a-fx]+)\]
  strb	r0, \[r1\]
loc_800FD20:
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #0x4c\]
  cmp	r0, #1
  bne	#(?P<loc_label_ret1>[0-9a-fx]+)
  movs	r0, #0 ; FPGA_REG_UNKN_00
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  orr	r4, r0, #1
  mov	r1, r4
  movs	r0, #0 ; FPGA_REG_UNKN_00
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r1, #1
  movs	r0, #0x17 ; AD9363_REG_STATE
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  cmp	r0, #0x1a
  beq	#(?P<loc_state_ok>[0-9a-fx]+)
  movs	r0, #0x40 ; OFDM_TCX_REGISTER_ERR
  bl	#(?P<ofdm_tx_state_set_flag>[0-9a-fx]+)
  bl	#(?P<sub_800CCC8>[0-9a-fx]+)
loc_state_ok:
  movs	r0, #0 ; FPGA_REG_UNKN_00
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  and	r4, r0, #0xfe
  mov	r1, r4
  movs	r0, #0
loc_last_fpga_wr:
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
loc_label_ret1:
  pop	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), pc}
""",
'vars': {
  'tcx_config_update1':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_fpga_raw_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_fpga_raw_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ofdm_tx_state_set_flag':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_800CCC8':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,32)},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'ptr_ofdm_receiver_id':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'ofdm_receiver_id':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'ptr_active_transciever_attenuation':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'active_transciever_attenuation':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_tcx_control_attenuation_by_packet':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_fpga_reg_unkn00_value':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T},
  'rel_transceiver_flags_1A28':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'transceiver_pwr_mode_unk016C':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_transciever_attenuation':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'loc_800FC36':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_800FCD0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_800FD20':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_init_fcc':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_start':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ad_from_pkt':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ad_from_pkt_s1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s5':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_state_ok':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'board_ad4_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "10",
    'description': "Transceiver attenuation value for board type 4 with Analog Devices chip, change by 1 means 0.25 dBm",
    'hint1': "value of 0 means minimal attenuation and therefore max output power of the transceiver",
    'hint2': "in P3X_FW_V01.04, only one board type is suported"},
  'board_ad4_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "10",
    'description': "Transceiver attenuation value for board type 4 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad4_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "0",
    'description': "Transceiver attenuation value for board type 4 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad4_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "0",
    'description': "Transceiver attenuation value for board type 4 with Analog Devices chip, change by 1 means 0.25 dBm"},
},
}

re_func_tcx_config_update1_P3X_V01_05 = {
'name': "tcx_config_update1",
'version': "P3X_FW_V01.05",
're': """
tcx_config_update1:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), lr}
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_tcx_control_attenuation_by_packet>[0-9a-fx]+)\]
  cmp	r0, #0
loc_start:
  beq	#(?P<loc_phase2_s5>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  ldr	r1, \[pc, #(?P<active_transciever_attenuation>[0-9a-fx]+)\]
  ldrb	r1, \[r1\]
  cmp	r0, r1
  beq	#(?P<loc_start>[0-9a-fx]+)
  movs	r0, #0xe9 ; FPGA_REG_UNKN_E9
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  and	r0, r0, #3
  cmp	r0, #3
  bne	#(?P<loc_800FC36>[0-9a-fx]+)
  movs	r0, #0
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  orr	r0, r0, #8
  ldr	r1, \[pc, #(?P<rel_fpga_reg_unkn00_value>[0-9a-fx]+)\]
  strb	r0, \[r1\]
  mov	r0, r1
  ldrb	r0, \[r0\]
  orr	r1, r0, #1
  movs	r0, #0 ; FPGA_REG_UNKN_00
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_ad_from_pkt>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  beq	#(?P<loc_ad_from_pkt>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  bne	#(?P<loc_not_ad_from_pkt>[0-9a-fx]+)
loc_ad_from_pkt:
  movs	r1, #1
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r1, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_ad_from_pkt_s1>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_ad_from_pkt_s1:
  movs	r1, #1
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r1, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_phase2_s4>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  b	#(?P<loc_phase2_s4>[0-9a-fx]+)
loc_not_ad_from_pkt:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_ar_from_pkt>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  bne	#(?P<loc_phase2_s4>[0-9a-fx]+)
loc_ar_from_pkt:
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r0, #0xce ; FPGA_REG_UNKN_CE
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #1
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r1, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_ar_from_pkt_s1>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_ar_from_pkt_s1:
  movs	r1, #1
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r1, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_ar_from_pkt_s2>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_ar_from_pkt_s2:
  b	#(?P<loc_skip01>[0-9a-fx]+)
loc_phase2_s5:
  b	#(?P<loc_800FC36>[0-9a-fx]+)
loc_skip01:
  ldr	r0, \[pc, #(?P<rel_fpga_reg_unkn00_value>[0-9a-fx]+)\]
  ldrb	r1, \[r0\]
  movs	r0, #0 ; FPGA_REG_UNKN_00
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  ldr	r1, \[pc, #(?P<active_transciever_attenuation>[0-9a-fx]+)\]
  strb	r0, \[r1\]
loc_800FC36:
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_tcx_control_attenuation_by_packet>[0-9a-fx]+)\]
  cmp	r0, #0
loc_800FC3E:
  bne	#(?P<loc_800FD20>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldr	r0, \[r0, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  ldr	r1, \[pc, #(?P<transceiver_pwr_mode_unk016C>[0-9a-fx]+)\]
  ldrb	r1, \[r1\]
  cmp.w	r1, r0, lsr #31
  beq	#(?P<loc_800FD20>[0-9a-fx]+)
  movs	r0, #0xe9 ; FPGA_REG_UNKN_E9
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  and	r0, r0, #3
  cmp	r0, #3
  bne	#(?P<loc_800FC3E>[0-9a-fx]+)

  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldr	r0, \[r0, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  lsrs	r0, r0, #0x1f
  beq	#(?P<loc_init_fcc>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  bne	#(?P<loc_800FC82>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad4_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad4_attenuation_tx2_ce>[0-9a-fx]+)
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  b	#(?P<loc_800FCD0>[0-9a-fx]+)
loc_800FC82:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  bne	#(?P<loc_800FCA0>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad5_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad5_attenuation_tx2_ce>[0-9a-fx]+)
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  b	#(?P<loc_800FCD0>[0-9a-fx]+)
loc_800FCA0:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  bne	#(?P<loc_800FCD0>[0-9a-fx]+)
  movs	r0, #1
  bl	#(?P<sub_800DD72>[0-9a-fx]+)
  movs	r1, #(?P<board_ar6_attenuation_fpga_ce>[0-9a-fx]+)
  movs	r0, #0xce ; FPGA_REG_UNKN_CE
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<sub_800DD72>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar6_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar6_attenuation_tx2_ce>[0-9a-fx]+)
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_800FCD0:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  bne	#(?P<loc_800FD02>[0-9a-fx]+)
  movs	r0, #1
  bl	#(?P<sub_800DD72>[0-9a-fx]+)
  movs	r1, #(?P<board_ar7_attenuation_fpga_ce>[0-9a-fx]+)
  movs	r0, #0xce ; FPGA_REG_UNKN_CE
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<sub_800DD72>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar7_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar7_attenuation_tx2_ce>[0-9a-fx]+)
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  b	#(?P<loc_800FDDC>[0-9a-fx]+)
loc_800FD02:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  bne	#(?P<loc_800FDDC>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad2_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad2_attenuation_tx2_ce>[0-9a-fx]+)
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  b	#(?P<loc_800FDDC>[0-9a-fx]+)
loc_800FD20:
  b	#(?P<loc_800FDE6>[0-9a-fx]+)
loc_init_fcc:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  bne	#(?P<loc_800FD40>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad4_attenuation_tx1_fcc>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad4_attenuation_tx2_fcc>[0-9a-fx]+)
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  b	#(?P<loc_800FD8E>[0-9a-fx]+)
loc_800FD40:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  bne	#(?P<loc_800FD5E>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad5_attenuation_tx1_fcc>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad5_attenuation_tx2_fcc>[0-9a-fx]+)
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  b	#(?P<loc_800FD8E>[0-9a-fx]+)
loc_800FD5E:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  bne	#(?P<loc_800FD8E>[0-9a-fx]+)
  movs	r0, #1
  bl	#(?P<sub_800DD72>[0-9a-fx]+)
  movs	r1, #(?P<board_ar6_attenuation_fpga_fcc>[0-9a-fx]+)
  movs	r0, #0xce ; FPGA_REG_UNKN_CE
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<sub_800DD72>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar6_attenuation_tx1_fcc>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar6_attenuation_tx2_fcc>[0-9a-fx]+)
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_800FD8E:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  bne	#(?P<loc_800FDC0>[0-9a-fx]+)
  movs	r0, #1
  bl	#(?P<sub_800DD72>[0-9a-fx]+)
  movs	r1, #(?P<board_ar7_attenuation_fpga_fcc>[0-9a-fx]+)
  movs	r0, #0xce ; FPGA_REG_UNKN_CE
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<sub_800DD72>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar7_attenuation_tx1_fcc>[0-9a-fx]+) ; default was 0xa?
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar7_attenuation_tx2_fcc>[0-9a-fx]+) ; default was 0xa?
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  b	#(?P<loc_800FDDC>[0-9a-fx]+)
loc_800FDC0:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  bne	#(?P<loc_800FDDC>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad2_attenuation_tx1_fcc>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad2_attenuation_tx2_fcc>[0-9a-fx]+)
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_800FDDC:
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldr	r0, \[r0, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  lsrs	r0, r0, #0x1f
  ldr	r1, \[pc, #(?P<transceiver_pwr_mode_unk016C>[0-9a-fx]+)\]
  strb	r0, \[r1\]
loc_800FDE6:
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_byte_20001DAF>[0-9a-fx]+)\]
  cmp	r0, #0xff
  beq	#(?P<loc_800FE4C>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_800FE08>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  beq	#(?P<loc_800FE08>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  bne	#(?P<loc_800FE4C>[0-9a-fx]+)
loc_800FE08:
  movs	r0, #1
  bl	#(?P<sub_800DD72>[0-9a-fx]+)
  movs	r0, #9 ; FPGA_REG_UNKN_09
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  and	r0, r0, #0xf
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r1, #(?P<rel_byte_20001DAF>[0-9a-fx]+)\]
  and	r1, r1, #0xf
  cmp	r0, r1
  beq	#(?P<loc_800FE46>[0-9a-fx]+)
  movs	r0, #9 ; FPGA_REG_UNKN_09
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  and	r0, r0, #0xf0
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r1, #(?P<rel_byte_20001DAF>[0-9a-fx]+)\]
  and	r1, r1, #0xf
  orr.w	r4, r0, r1
  mov	r1, r4
  movs	r0, #9 ; FPGA_REG_UNKN_09
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
loc_800FE46:
  movs	r0, #2
  bl	#(?P<sub_800DD72>[0-9a-fx]+)
loc_800FE4C:
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #0x4c\]
  cmp	r0, #1
  bne	#(?P<loc_label_ret1>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<dword_20000190>[0-9a-fx]+)\]
  ldr	r0, \[r0\]
  adds	r0, r0, #1
  ldr	r1, \[pc, #(?P<dword_20000190>[0-9a-fx]+)\]
  str	r0, \[r1\]
  movs	r1, #0xa
  udiv	r2, r0, r1
  mls	r0, r1, r2, r0
  cbnz	r0, #(?P<loc_label_ret2>[0-9a-fx]+)
  movs	r0, #0 ; FPGA_REG_UNKN_00
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  orr	r4, r0, #1
  mov	r1, r4
  movs	r0, #0 ; FPGA_REG_UNKN_00
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_st3_board_ad>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  beq	#(?P<loc_st3_board_ad>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  bne	#(?P<loc_st3_not_ad>[0-9a-fx]+)
loc_st3_board_ad:
  movs	r1, #1
  movs	r0, #0x17 ; AD9363_REG_STATE
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  cmp	r0, #0x1a
  beq	#(?P<loc_state_ok>[0-9a-fx]+)
  movs	r0, #0x40 ; OFDM_TCX_REGISTER_ERR
  bl	#(?P<ofdm_tx_state_set_flag>[0-9a-fx]+)
  bl	#(?P<sub_800CCC8>[0-9a-fx]+)
  b	#(?P<loc_state_ok>[0-9a-fx]+)
loc_st3_not_ad:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_st3_board_ar>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  bne	#(?P<loc_state_ok>[0-9a-fx]+)
loc_st3_board_ar:
  movs	r1, #1
  movs	r0, #0x7c ; AR8003_REG_STATE_FLAGS
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  tst.w	r0, #0x40
  bne	#(?P<loc_state_ok>[0-9a-fx]+)
  movs	r0, #0x40 ; OFDM_TCX_REGISTER_ERR
  bl	#(?P<ofdm_tx_state_set_flag>[0-9a-fx]+)
  bl	#(?P<sub_800CCC8>[0-9a-fx]+)
loc_state_ok:
  movs	r0, #0 ; FPGA_REG_UNKN_00
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  and	r4, r0, #0xfe
  mov	r1, r4
  movs	r0, #0
  b	#(?P<loc_last_fpga_wr>[0-9a-fx]+)
loc_label_ret2:
  b	#(?P<loc_label_ret1>[0-9a-fx]+)
loc_last_fpga_wr:
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
loc_label_ret1:
  pop	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), pc}
""",
'vars': {
  'tcx_config_update1':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'get_board_version':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_fpga_raw_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_fpga_raw_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ofdm_tx_state_set_flag':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'tx_sub_800D3E4':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_800DD72':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_800CCC8':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'ofdm_receiver_id':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'active_transciever_attenuation':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_tcx_control_attenuation_by_packet':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_byte_20001DAF':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_fpga_reg_unkn00_value':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T},
  'rel_transceiver_flags_1A28':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'transceiver_pwr_mode_unk016C':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'dword_20000190':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_transciever_attenuation':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'loc_not_ad_from_pkt':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_skip01':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_800FC36':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_800FC3E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_800FC82':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_800FCA0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_800FCD0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_800FD02':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_800FD20':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_800FD40':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_init_fcc':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_800FD5E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_800FD8E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_800FDC0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_800FDDC':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_800FDE6':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_800FE08':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_800FE46':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_800FE4C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_start':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ad_from_pkt':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ad_from_pkt_s1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ar_from_pkt':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ar_from_pkt_s1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ar_from_pkt_s2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s5':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_last_fpga_wr':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_st3_board_ad':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_st3_not_ad':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_st3_board_ar':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_state_ok':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label_ret2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'board_ad4_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "10",
    'description': "Transceiver attenuation value for board type 4 with Analog Devices chip, change by 1 means 0.25 dBm",
    'hint1': "value of 0 means minimal attenuation and therefore max output power of the transceiver",
    'hint2': "in P3X_FW_V01.05-V01.07, CE and FCC attenuation values are initially equal"},
  'board_ad4_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "4",
    'description': "Transceiver attenuation value for board type 4 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad5_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "4",
    'description': "Transceiver attenuation value for board type 5 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad5_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "5",
    'description': "Transceiver attenuation value for board type 5 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ar6_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "10",
    'description': "Transceiver attenuation value for board type 6 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar6_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "10",
    'description': "Transceiver attenuation value for board type 6 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar7_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "10",
    'description': "Transceiver attenuation value for board type 7 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar7_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "10",
    'description': "Transceiver attenuation value for board type 7 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ad2_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "4",
    'description': "Transceiver attenuation value for board type 2 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad2_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "5",
    'description': "Transceiver attenuation value for board type 2 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ar6_attenuation_fpga_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar6_attenuation_tx1_ce", 'getter': (lambda val: val)},
  'board_ar7_attenuation_fpga_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar7_attenuation_tx1_ce", 'getter': (lambda val: val)},
  'board_ad4_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "10",
    'description': "Transceiver attenuation value for board type 4 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad4_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "4",
    'description': "Transceiver attenuation value for board type 4 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad5_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "4",
    'description': "Transceiver attenuation value for board type 5 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad5_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "5",
    'description': "Transceiver attenuation value for board type 5 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ar6_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "10",
    'description': "Transceiver attenuation value for board type 6 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar6_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "10",
    'description': "Transceiver attenuation value for board type 6 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar7_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "10",
    'description': "Transceiver attenuation value for board type 7 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar7_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "10",
    'description': "Transceiver attenuation value for board type 7 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ad2_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "4",
    'description': "Transceiver attenuation value for board type 2 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad2_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "5",
    'description': "Transceiver attenuation value for board type 2 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ar6_attenuation_fpga_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar6_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ar7_attenuation_fpga_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar7_attenuation_tx1_fcc", 'getter': (lambda val: val)},
},
}


re_func_tcx_config_update1_P3X_V01_08 = {
'name': "tcx_config_update1",
'version': "P3X_FW_V01.08",
're': """
tcx_config_update1:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), lr}
  ; in P3X_FW_V01.08, the wildcard matches lines:
  ;ldr	r4, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ; in P3X_FW_V01.11, the wildcard matches lines:
  ;ldr	r4, \[pc, #(?P<unk_200019B8>[0-9a-fx]+)\]
  ;adds	r4, #(?P<rel_unk_200019B8_shift>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){1,4})
  ldrb.w	r0, \[r4, #(?P<rel_tcx_control_attenuation_by_packet>[0-9a-fx]+)\]
  ldr	r5, \[pc, #(?P<tcx_byte_2000015C>[0-9a-fx]+)\]
  cmp	r0, #0
  beq	#(?P<loc_phase2_s5>[0-9a-fx]+)
  ldrb.w	r0, \[r4, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  ldrb	r1, \[r5, #(?P<rel_active_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_phase2_s5>[0-9a-fx]+)
  movs	r0, #0xe9 ; FPGA_REG_UNKN_E9
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  mvns	r0, r0
  lsls	r0, r0, #0x1e
  bne	#(?P<loc_phase2_s5>[0-9a-fx]+)
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  orr	r0, r0, #8
  strb	r0, \[r5, #(?P<rel_fpga_reg_unkn00_value>[0-9a-fx]+)\]
  orr	r1, r0, #1
  movs	r0, #0 ; FPGA_REG_UNKN_00
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_ad_from_pkt>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  beq	#(?P<loc_ad_from_pkt>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  beq	#(?P<loc_ad_from_pkt>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_ar_from_pkt>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  beq	#(?P<loc_ar_from_pkt>[0-9a-fx]+)
  b	#(?P<loc_phase2_s4>[0-9a-fx]+)
loc_ad_from_pkt:
  movs	r1, #1
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldrb.w	r1, \[r4, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_ad_from_pkt_s1>[0-9a-fx]+)
  ldrb.w	r1, \[r4, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_ad_from_pkt_s1:
  movs	r1, #1
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldrb.w	r1, \[r4, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_phase2_s4>[0-9a-fx]+)
  ldrb.w	r1, \[r4, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  b	#(?P<loc_last4_dirct>[0-9a-fx]+)
loc_ar_from_pkt:
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r0, #0xce ; FPGA_REG_UNKN_CE
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  ldrb.w	r1, \[r4, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_ar_from_pkt_s1>[0-9a-fx]+)
  ldrb.w	r1, \[r4, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r0, #0xce ; FPGA_REG_UNKN_CE
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
loc_ar_from_pkt_s1:
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #1
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldrb.w	r1, \[r4, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_ar_from_pkt_s2>[0-9a-fx]+)
  ldrb.w	r1, \[r4, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_ar_from_pkt_s2:
  movs	r1, #1
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldrb.w	r1, \[r4, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_phase2_s4>[0-9a-fx]+)
  ldrb.w	r1, \[r4, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
loc_last4_dirct:
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_phase2_s4:
  ldrb	r1, \[r5, #(?P<rel_fpga_reg_unkn00_value>[0-9a-fx]+)\]
  movs	r0, #0 ; FPGA_REG_UNKN_00
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  ldrb.w	r0, \[r4, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  strb	r0, \[r5, #(?P<rel_active_transciever_attenuation>[0-9a-fx]+)\]
loc_phase2_s5:
  ldrb.w	r0, \[r4, #(?P<rel_tcx_control_attenuation_by_packet>[0-9a-fx]+)\]
  cbnz	r0, #(?P<loc_phase2_j_s2>[0-9a-fx]+)
  ldrb.w	r0, \[r4, #(?P<rel_tcx_control_attenuation_by_unkn1>[0-9a-fx]+)\]
  cbnz	r0, #(?P<loc_phase2_j_s2>[0-9a-fx]+)
  ldr	r0, \[r4, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  ldrb	r1, \[r5, #(?P<rel_transceiver_pwr_mode_unk016C>[0-9a-fx]+)\]
  cmp.w	r1, r0, lsr #31
  beq	#(?P<loc_phase2_s2>[0-9a-fx]+)
  movs	r0, #0xe9 ; FPGA_REG_UNKN_E9
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  mvns	r0, r0
  lsls	r0, r0, #0x1e
  bne	#(?P<loc_phase2_s2>[0-9a-fx]+)
  ldr	r0, \[r4, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_ad4_dirct>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  beq	#(?P<loc_ad5_dirct>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_ar6_dirct>[0-9a-fx]+)
  b	#(?P<loc_phase3_s1>[0-9a-fx]+)
loc_ad4_dirct:
  movs	r2, #0
  movs	r1, #(?P<board_ad4_attenuation_tx1_cnup>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad4_attenuation_tx2_cnup>[0-9a-fx]+)
  b	#(?P<loc_last_dirct>[0-9a-fx]+)
loc_ad5_dirct:
  movs	r2, #0
  movs	r1, #(?P<board_ad5_attenuation_tx1_cnup>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad5_attenuation_tx2_cnup>[0-9a-fx]+)
loc_last_dirct:
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
loc_last2_dirct:
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_phase3_s1:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  beq	#(?P<loc_phase3_s3>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  beq	#(?P<loc_ad2_dirct>[0-9a-fx]+)
  b	#(?P<loc_phase2_s1>[0-9a-fx]+)
loc_phase2_j_s2:
  b	#(?P<loc_phase2_s2>[0-9a-fx]+)
loc_phase3_s3:
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #(?P<board_ar7_attenuation_fpga_cnup>[0-9a-fx]+)
  movs	r0, #0xce ; FPGA_REG_UNKN_CE
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #(?P<board_ar7_attenuation_tx1_cnup>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar7_attenuation_tx2_cnup>[0-9a-fx]+)
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  b	#(?P<loc_last3_dirct>[0-9a-fx]+)
loc_ad2_dirct:
  movs	r2, #0
  movs	r1, #(?P<board_ad2_attenuation_tx1_cnup>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad2_attenuation_tx2_cnup>[0-9a-fx]+)
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
loc_last3_dirct:
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_phase2_s1:
  ldr	r0, \[r4, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  lsrs	r0, r0, #0x1f
  strb	r0, \[r5, #(?P<rel_transceiver_pwr_mode_unk016C>[0-9a-fx]+)\]
loc_phase2_s2:
  ldrb.w	r0, \[r4, #(?P<rel_byte_20001B23>[0-9a-fx]+)\]
  cmp	r0, #0xff
  beq	#(?P<loc_phase4_s2>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_phase2_s3>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  beq	#(?P<loc_phase2_s3>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  beq	#(?P<loc_phase2_s3>[0-9a-fx]+)
  b	#(?P<loc_phase4_s2>[0-9a-fx]+)
loc_ar6_dirct:
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #(?P<board_ar6_attenuation_fpga_cnup>[0-9a-fx]+)
  movs	r0, #0xce ; FPGA_REG_UNKN_CE
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #(?P<board_ar6_attenuation_tx1_cnup>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar6_attenuation_tx2_cnup>[0-9a-fx]+)
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  b	#(?P<loc_last2_dirct>[0-9a-fx]+)
loc_phase2_s3:
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r0, #9 ; FPGA_REG_UNKN_09
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  ldrb.w	r1, \[r4, #(?P<rel_byte_20001B23>[0-9a-fx]+)\]
  and	r0, r0, #0xf
  and	r1, r1, #0xf
  cmp	r0, r1
  beq	#(?P<loc_phase4_s1>[0-9a-fx]+)
  movs	r0, #9 ; FPGA_REG_UNKN_09
  ; in P3X_FW_V01.08, the wildcard matches lines:
  ;bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  ; in P3X_FW_V01.11, the wildcard matches lines:
  ;b	#(?P<loc_skip_datablk1>[0-9a-fx]+)
  ;dcw	0
  ;dcd	(?P<data_ptr_unkn1>[0-9a-fx]+)
  ;dcd	(?P<data_val_unkn1>[0-9a-fx]+)
  ;dcd	(?P<data_val_unkn2>[0-9a-fx]+)
  ;dcd	(?P<data_ptr_unkn2>[0-9a-fx]+)
  ;dcd	(?P<data_ptr_unkn3>[0-9a-fx]+)
  ;loc_skip_datablk1:
  ;bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_2>([0-9a-fx]+[, ]*){1,16})
  and	r1, r0, #0xf0
  ldrb.w	r0, \[r4, #(?P<rel_byte_20001B23>[0-9a-fx]+)\]
  and	r0, r0, #0xf
  orrs	r1, r0
  movs	r0, #9 ; FPGA_REG_UNKN_09
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
loc_phase4_s1:
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
loc_phase4_s2:
  ldrb.w	r0, \[r4, #0x6c\]
  cmp	r0, #1
  bne	#(?P<loc_label_ret1>[0-9a-fx]+)
  ; in P3X_FW_V01.08, the wildcard matches lines:
  ;ldr	r0, \[r5, #(?P<rel_byte_r5p024>[0-9a-fx]+)\]
  ; in P3X_FW_V01.11, the wildcard matches lines:
  ;ldrb.w	r0, \[r4, #(?P<rel_byte_r4p11a>[0-9a-fx]+)\]
  ;cmp	r0, #0
  ;bne	#(?P<loc_label_ret1>[0-9a-fx]+)
  ;ldr	r0, \[r5, #(?P<rel_byte_r5p024>[0-9a-fx]+)\]
  dcw	(?P<undefined_varlen_3>([0-9a-fx]+[, ]*){1,16})
  movs	r1, #0xa
  adds	r0, r0, #1
  udiv	r2, r0, r1
  str	r0, \[r5, #(?P<rel_byte_r5p024>[0-9a-fx]+)\]
  mls	r0, r1, r2, r0
  cmp	r0, #0
  bne	#(?P<loc_label_ret1>[0-9a-fx]+)
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  orr	r1, r0, #1
  movs	r0, #0
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_state_ad_check>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  beq	#(?P<loc_state_ad_check>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  beq	#(?P<loc_state_ad_check>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_state_ar_check>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  beq	#(?P<loc_state_ar_check>[0-9a-fx]+)
  b	#(?P<loc_state_ok>[0-9a-fx]+)
loc_state_ad_check:
  movs	r1, #1
  movs	r0, #0x17 ; AD9363_REG_STATE
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  cmp	r0, #0x1a
  beq	#(?P<loc_state_ok>[0-9a-fx]+)
  movs	r0, #0x40 ; OFDM_TCX_REGISTER_ERR
  bl	#(?P<ofdm_tx_state_set_flag>[0-9a-fx]+)
  movs	r1, #1
  movs	r0, #0x17 ; AD9363_REG_STATE
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  mov	r2, r0
  adr	r1, #(?P<cstr_err_ad9363_reg17>[0-9a-fx]+)
  b	#(?P<loc_state_err>[0-9a-fx]+)
loc_state_ar_check:
  movs	r1, #1
  movs	r0, #0x7c ; AR8003_REG_STATE_FLAGS
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  lsls	r0, r0, #0x19
  bmi	#(?P<loc_state_ok>[0-9a-fx]+)
  movs	r1, #1
  movs	r0, #0x7c ; AR8003_REG_STATE_FLAGS
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  lsls	r0, r0, #0x19
  bmi	#(?P<loc_state_ok>[0-9a-fx]+)
  movs	r0, #0x40 ; OFDM_TCX_REGISTER_ERR
  bl	#(?P<ofdm_tx_state_set_flag>[0-9a-fx]+)
  movs	r1, #1
  movs	r0, #0x7c ; AR8003_REG_STATE_FLAGS
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  mov	r2, r0
  adr	r1, #(?P<cstr_err_ar8003_reg7c>[0-9a-fx]+)
loc_state_err:
  movs	r0, #3
  bl	#(?P<log_printf>[0-9a-fx]+)
  bl	#(?P<sub_800BD8A>[0-9a-fx]+)
loc_state_ok:
  movs	r0, #0 ; FPGA_REG_UNKN_00
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  pop.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), lr}
  and	r1, r0, #0xfe
  movs	r0, #0
  b.w	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
loc_label_ret1:
  pop	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), pc}
""",
'vars': {
  'tcx_config_update1':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'get_board_version':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_fpga_raw_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_fpga_raw_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ofdm_tx_state_set_flag':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'log_printf':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_800BD8A':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'tx_sub_800D3E4':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,4)},
  'undefined_varlen_2':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,16)},
  'undefined_varlen_3':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,16)},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'ofdm_receiver_id':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_tcx_control_attenuation_by_packet':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_tcx_control_attenuation_by_unkn1':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_transceiver_flags_1A28':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_byte_20001B23':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_fpga_reg_unkn00_value':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_transceiver_pwr_mode_unk016C':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_byte_r5p024':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'tcx_byte_2000015C':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_transciever_attenuation':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_active_transciever_attenuation':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'cstr_err_ad9363_reg17':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'cstr_err_ar8003_reg7c':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.CHAR, 'array': "null_term"},
  'loc_ad_from_pkt':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ad_from_pkt_s1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ar_from_pkt':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ar_from_pkt_s1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ar_from_pkt_s2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_last4_dirct':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s5':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ad4_dirct':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ad5_dirct':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_last_dirct':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_last2_dirct':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase3_s1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_j_s2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase3_s3':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ad2_dirct':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_last3_dirct':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ar6_dirct':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s3':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase4_s1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase4_s2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_state_ad_check':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_state_ar_check':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_state_err':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_state_ok':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'board_ad4_attenuation_tx1_cnup':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad4_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ad4_attenuation_tx2_cnup':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad4_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ad5_attenuation_tx1_cnup':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad5_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ad5_attenuation_tx2_cnup':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad5_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ar6_attenuation_tx1_cnup':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar6_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ar6_attenuation_tx2_cnup':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar6_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ar7_attenuation_tx1_cnup':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar7_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ar7_attenuation_tx2_cnup':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar7_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ad2_attenuation_tx1_cnup':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad2_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ad2_attenuation_tx2_cnup':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad2_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ar6_attenuation_fpga_cnup':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar6_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ar7_attenuation_fpga_cnup':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar7_attenuation_tx1_fcc", 'getter': (lambda val: val)},
},
}

re_func_tcx_config_update1_C1_V01_03_m1400 = {
'name': "tcx_config_update1",
'version': "C1_FW_V01.03-m1400",
're': """
tcx_config_update1:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), lr}
  ldr	r4, \[pc, #(?P<unknown_anchor_point_01>[0-9a-fx]+)\]
  subs	r4, #(?P<rel_ofdm_receiver_id>[0-9a-fx]+)
  ldrb.w	r0, \[r4, #(?P<rel_tcx_control_attenuation_by_packet>[0-9a-fx]+)\]
  ldr	r5, \[pc, #(?P<tcx_byte_2000015C>[0-9a-fx]+)\]
  cbz	r0, #(?P<loc_phase2_s5>[0-9a-fx]+)
  ldrb.w	(?P<regB>r[0-9]), \[r4, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  ldrb	(?P<regC>r[0-9]), \[r5, #(?P<rel_active_transciever_attenuation>[0-9a-fx]+)\]
  cmp	(?P<regB>r[0-9]), (?P<regC>r[0-9])
  beq	#(?P<loc_phase2_s5>[0-9a-fx]+)
  movs	r1, #0
  movs	r0, #0xf
  bl	#(?P<spi_raw_ct16_dt8_read>[0-9a-fx]+)
  strb	r0, \[r5, #(?P<rel_fpga_reg_unkn15_value>[0-9a-fx]+)\]
  orr	r2, r0, #1
  movs	r1, #0
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
  movs	r1, #1
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldrb.w	r1, \[r4, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_ad_from_pkt_s1>[0-9a-fx]+)
  ldrb.w	r1, \[r4, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_ad_from_pkt_s1:
  movs	r1, #1
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldrb.w	r1, \[r4, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_phase2_s4>[0-9a-fx]+)
  ldrb.w	r1, \[r4, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_phase2_s4:
  ldrb	r2, \[r5, #(?P<rel_fpga_reg_unkn15_value>[0-9a-fx]+)\]
  movs	r1, #0
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
  ldrb.w	r0, \[r4, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  strb	r0, \[r5, #(?P<rel_active_transciever_attenuation>[0-9a-fx]+)\]
loc_phase2_s5:
  ldrb.w	r0, \[r4, #(?P<rel_tcx_control_attenuation_by_packet>[0-9a-fx]+)\]
  cbnz	r0, #(?P<loc_167B0>[0-9a-fx]+)
  ldr	r0, \[r4, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  ldrb	r1, \[r5, #(?P<rel_transceiver_pwr_mode_unk016C>[0-9a-fx]+)\]
  cmp.w	r1, r0, lsr #31
  beq	#(?P<loc_167B0>[0-9a-fx]+)
  ldr	r0, \[r4, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  mov.w	r2, #1
  cmp	r0, #0
  bge	#(?P<loc_16EBC>[0-9a-fx]+)
  movs	r1, #(?P<board_ad3_attenuation_tx1_fcc>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad3_attenuation_tx2_fcc>[0-9a-fx]+)
  b	#(?P<loc_last_dirct>[0-9a-fx]+)
loc_16EBC:
  movs	r1, #(?P<board_ad3_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad3_attenuation_tx2_ce>[0-9a-fx]+)
loc_last_dirct:
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  ldr	r0, \[r4, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  lsrs	r0, r0, #0x1f
  strb	r0, \[r5, #(?P<rel_transceiver_pwr_mode_unk016C>[0-9a-fx]+)\]
loc_167B0:
  ldrb.w	r0, \[r4, #0x64\]
  cmp	r0, #0xff
  beq	#(?P<loc_label_ret1>[0-9a-fx]+)
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #9
  movs	r0, #0xf
  bl	#(?P<spi_raw_ct16_dt8_read>[0-9a-fx]+)
  ldrb.w	r1, \[r4, #0x64\]
  cmp	r0, r1
  beq	#(?P<loc_167E2>[0-9a-fx]+)
  ldrb.w	r2, \[r4, #0x64\]
  movs	r1, #9
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
loc_167E2:
  pop.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), lr}
  movs	r0, #2
  b.w	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
loc_label_ret1:
  pop	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), pc}
""",
'vars': {
  'tcx_config_update1':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'unknown_anchor_point_01':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_ofdm_receiver_id':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'ad936x_reg_sync_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_raw_ct16_dt8_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_raw_ct16_dt8_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'tx_sub_800D3E4':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regB':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regC':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'rel_tcx_control_attenuation_by_packet':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_transceiver_flags_1A28':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_fpga_reg_unkn15_value':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_transceiver_pwr_mode_unk016C':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'tcx_byte_2000015C':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_transciever_attenuation':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_active_transciever_attenuation':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'loc_ad_from_pkt':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ad_from_pkt_s1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s5':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_last_dirct':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_167B0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_167E2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16EBC':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'board_ad3_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "8",
    'description': "Transceiver attenuation value for board type 3 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad3_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "8",
    'description': "Transceiver attenuation value for board type 3 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad3_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "36",
    'description': "Transceiver attenuation value for board type 3 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad3_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "36",
    'description': "Transceiver attenuation value for board type 3 with Analog Devices chip, change by 1 means 0.25 dBm"},
},
}

re_func_tcx_config_update1_C1_V01_04_m1400 = {
'name': "tcx_config_update1",
'version': "C1_FW_V01.05-m1400",
're': """
tcx_config_update1:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), lr}
  ldr	r6, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r6, #(?P<rel_tcx_control_attenuation_by_packet>[0-9a-fx]+)\]
  ldr	r5, \[pc, #(?P<tcx_byte_2000015C>[0-9a-fx]+)\]
  cmp	r0, #0
  beq	#(?P<loc_phase2_s5>[0-9a-fx]+)
  ldrb.w	(?P<regB>r[0-9]), \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  ldrb	(?P<regC>r[0-9]), \[r5, #(?P<rel_active_transciever_attenuation>[0-9a-fx]+)\]
  cmp	(?P<regB>r[0-9]), (?P<regC>r[0-9])
  beq	#(?P<loc_phase2_s5>[0-9a-fx]+)
  movs	r1, #0
  movs	r0, #0xf
  bl	#(?P<spi_raw_ct16_dt8_read>[0-9a-fx]+)
  strb	r0, \[r5, #(?P<rel_fpga_reg_unkn15_value>[0-9a-fx]+)\]
  orr	r2, r0, #1
  movs	r1, #0
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #3
  beq	#(?P<loc_ad_from_pkt>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cbz	r0, #(?P<loc_ar_from_pkt>[0-9a-fx]+)
  b	#(?P<loc_phase2_s4>[0-9a-fx]+)
loc_ad_from_pkt:
  movs	r1, #1
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldrb.w	r1, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_ad_from_pkt_s1>[0-9a-fx]+)
  ldrb.w	r1, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_ad_from_pkt_s1:
  movs	r1, #1
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldrb.w	r1, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_phase2_s4>[0-9a-fx]+)
  ldrb.w	r1, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  b	#(?P<loc_last4_dirct>[0-9a-fx]+)
loc_ar_from_pkt:
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  ldrb.w	r2, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r1, #0xce ; FPGA_REG_UNKN_CE
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #1
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldrb.w	r1, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_ar_from_pkt_s2>[0-9a-fx]+)
  ldrb.w	r1, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_ar_from_pkt_s2:
  movs	r1, #1
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldrb.w	r1, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_phase2_s4>[0-9a-fx]+)
  ldrb.w	r1, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
loc_last4_dirct:
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_phase2_s4:
  ldrb	r2, \[r5, #(?P<rel_fpga_reg_unkn15_value>[0-9a-fx]+)\]
  movs	r1, #0
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
  ldrb.w	r0, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  strb	r0, \[r5, #(?P<rel_active_transciever_attenuation>[0-9a-fx]+)\]
loc_phase2_s5:
  ldrb.w	r0, \[r6, #(?P<rel_tcx_control_attenuation_by_packet>[0-9a-fx]+)\]
  cbnz	r0, #(?P<loc_j_167B0>[0-9a-fx]+)
  ldr	r0, \[r6, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  ldrb	r1, \[r5, #(?P<rel_transceiver_pwr_mode_unk016C>[0-9a-fx]+)\]
  cmp.w	r1, r0, lsr #31
  beq	#(?P<loc_167B0>[0-9a-fx]+)
  ldr	r4, \[r6, #(?P<rel_dword_10004258>[0-9a-fx]+)\]
  cbnz	r4, #(?P<loc_16E76>[0-9a-fx]+)
  movs	r1, #0
  movs	r0, #0xf
  bl	#(?P<spi_raw_ct16_dt8_read>[0-9a-fx]+)
  strb	r0, \[r5, #(?P<rel_fpga_reg_unkn15_value>[0-9a-fx]+)\]
  orr	r2, r0, #1
  movs	r1, #0
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
loc_16E76:
  ldr	r0, \[r6, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  cmp	r0, #0
  bge	#(?P<loc_16EBC>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #3
  bne	#(?P<loc_16EC4>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad3_attenuation_tx1_fcc>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad3_attenuation_tx2_fcc>[0-9a-fx]+)
  b	#(?P<loc_last_dirct>[0-9a-fx]+)
loc_16E94:
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r2, #(?P<board_ar0_attenuation_fpga_ce>[0-9a-fx]+)
  movs	r1, #0xce ; FPGA_REG_UNKN_CE
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar0_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar0_attenuation_tx2_ce>[0-9a-fx]+)
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  b	#(?P<loc_last2_dirct>[0-9a-fx]+)
loc_j_167B0:
  b	#(?P<loc_167B0>[0-9a-fx]+)
loc_16EBC:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #3
  beq	#(?P<loc_16ECE>[0-9a-fx]+)
loc_16EC4:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #0
  beq	#(?P<loc_16E94>[0-9a-fx]+)
  b	#(?P<loc_16EE2>[0-9a-fx]+)
loc_16ECE:
  movs	r2, #1
  movs	r1, #(?P<board_ad3_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad3_attenuation_tx2_ce>[0-9a-fx]+)
loc_last_dirct:
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
loc_last2_dirct:
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_16EE2:
  cbnz	r4, #(?P<loc_phase2_s1>[0-9a-fx]+)
  ldrb	r2, \[r5, #(?P<rel_fpga_reg_unkn15_value>[0-9a-fx]+)\]
  movs	r1, #0
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
loc_phase2_s1:
  ldr	r0, \[r6, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  lsrs	r0, r0, #0x1f
  strb	r0, \[r5, #(?P<rel_transceiver_pwr_mode_unk016C>[0-9a-fx]+)\]
loc_167B0:
  ldrb.w	r0, \[r6, #0x64\]
  cmp	r0, #0xff
  beq	#(?P<loc_label_ret1>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #3
  bne	#(?P<loc_label_ret1>[0-9a-fx]+)
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #9
  movs	r0, #0xf
  bl	#(?P<spi_raw_ct16_dt8_read>[0-9a-fx]+)
  ldrb.w	r1, \[r6, #0x64\]
  cmp	r0, r1
  beq	#(?P<loc_167E2>[0-9a-fx]+)
  ldrb.w	r2, \[r6, #0x64\]
  movs	r1, #9
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
loc_167E2:
  pop.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), lr}
  movs	r0, #2
  b.w	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
loc_label_ret1:
  pop	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), pc}
""",
'vars': {
  'tcx_config_update1':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'ofdm_receiver_id':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'get_board_version':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_raw_ct16_dt8_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_raw_ct16_dt8_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'tx_sub_800D3E4':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regB':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regC':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'rel_dword_10004258':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_tcx_control_attenuation_by_packet':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_transceiver_flags_1A28':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_fpga_reg_unkn15_value':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_transceiver_pwr_mode_unk016C':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'tcx_byte_2000015C':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_transciever_attenuation':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_active_transciever_attenuation':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'loc_ad_from_pkt':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ad_from_pkt_s1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ar_from_pkt':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ar_from_pkt_s2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_last4_dirct':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s5':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_last_dirct':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_last2_dirct':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_j_167B0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_167B0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_167E2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16E76':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16E94':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16EBC':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16EC4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16ECE':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16EE2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'board_ad3_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "8",
    'description': "Transceiver attenuation value for board type 3 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad3_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "8",
    'description': "Transceiver attenuation value for board type 3 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad3_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "36",
    'description': "Transceiver attenuation value for board type 3 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad3_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "36",
    'description': "Transceiver attenuation value for board type 3 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ar0_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "17",
    'description': "Transceiver attenuation value for board type 0 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar0_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "17",
    'description': "Transceiver attenuation value for board type 0 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar0_attenuation_fpga_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar0_attenuation_tx1_ce", 'getter': (lambda val: val)},
},
}


re_func_tcx_config_update1_C1_V01_06_m1400 = {
'name': "tcx_config_update1",
'version': "C1_FW_V01.06-m1400",
're': """
tcx_config_update1:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), lr}
  ldr	r6, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r6, #(?P<rel_tcx_control_attenuation_by_packet>[0-9a-fx]+)\]
  ldr	r5, \[pc, #(?P<tcx_byte_2000015C>[0-9a-fx]+)\]
  cmp	r0, #0
  beq	#(?P<loc_phase2_s5>[0-9a-fx]+)
  ldrb.w	(?P<regB>r[0-9]), \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  ldrb	(?P<regC>r[0-9]), \[r5, #(?P<rel_active_transciever_attenuation>[0-9a-fx]+)\]
  cmp	(?P<regB>r[0-9]), (?P<regC>r[0-9])
  beq	#(?P<loc_phase2_s5>[0-9a-fx]+)
  movs	r1, #0
  movs	r0, #0xf
  bl	#(?P<spi_raw_ct16_dt8_read>[0-9a-fx]+)
  strb	r0, \[r5, #(?P<rel_fpga_reg_unkn15_value>[0-9a-fx]+)\]
  orr	r2, r0, #1
  movs	r1, #0
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #1
  beq	#(?P<loc_ad_from_pkt>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #3
  beq	#(?P<loc_ad_from_pkt>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cbz	r0, #(?P<loc_ar_from_pkt>[0-9a-fx]+)
  b	#(?P<loc_phase2_s4>[0-9a-fx]+)
loc_ad_from_pkt:
  movs	r1, #1
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldrb.w	r1, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_ad_from_pkt_s1>[0-9a-fx]+)
  ldrb.w	r1, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_ad_from_pkt_s1:
  movs	r1, #1
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldrb.w	r1, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_phase2_s4>[0-9a-fx]+)
  ldrb.w	r1, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  b	#(?P<loc_last4_dirct>[0-9a-fx]+)
loc_ar_from_pkt:
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #0xce ; FPGA_REG_UNKN_CE
  movs	r0, #0xf
  bl	#(?P<spi_raw_ct16_dt8_read>[0-9a-fx]+)
  ldrb.w	r1, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_ar_from_pkt_s1>[0-9a-fx]+)
  ldrb.w	r2, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r1, #0xce ; FPGA_REG_UNKN_CE
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
loc_ar_from_pkt_s1:
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #1
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldrb.w	r1, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_ar_from_pkt_s2>[0-9a-fx]+)
  ldrb.w	r1, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_ar_from_pkt_s2:
  movs	r1, #1
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldrb.w	r1, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_phase2_s4>[0-9a-fx]+)
  ldrb.w	r1, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
loc_last4_dirct:
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_phase2_s4:
  ldrb	r2, \[r5, #(?P<rel_fpga_reg_unkn15_value>[0-9a-fx]+)\]
  movs	r1, #0
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
  ldrb.w	r0, \[r6, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  strb	r0, \[r5, #(?P<rel_active_transciever_attenuation>[0-9a-fx]+)\]
loc_phase2_s5:
  ldrb.w	r0, \[r6, #(?P<rel_tcx_control_attenuation_by_packet>[0-9a-fx]+)\]
  cmp	r0, #0
  bne	#(?P<loc_label_ret1>[0-9a-fx]+)
  ldrb.w	r0, \[r6, #(?P<rel_tcx_control_attenuation_by_unkn1>[0-9a-fx]+)\]
  cmp	r0, #0
  bne	#(?P<loc_label_ret1>[0-9a-fx]+)
  ldr	r0, \[r6, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  ldrb	r1, \[r5, #(?P<rel_transceiver_pwr_mode_unk016C>[0-9a-fx]+)\]
  cmp.w	r1, r0, lsr #31
  beq	#(?P<loc_label_ret1>[0-9a-fx]+)
  ldr.w	r4, \[r6, #(?P<rel_dword_10004258>[0-9a-fx]+)\]
  cbnz	r4, #(?P<loc_16E76>[0-9a-fx]+)
  movs	r1, #0
  movs	r0, #0xf
  bl	#(?P<spi_raw_ct16_dt8_read>[0-9a-fx]+)
  strb	r0, \[r5, #(?P<rel_fpga_reg_unkn15_value>[0-9a-fx]+)\]
  orr	r2, r0, #1
  movs	r1, #0
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
loc_16E76:
  ldr	r0, \[r6, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  cmp	r0, #0
  bge	#(?P<loc_16EBC>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #3
  bne	#(?P<loc_16EC4>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad3_attenuation_tx1_fcc>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad3_attenuation_tx2_fcc>[0-9a-fx]+)
  b	#(?P<loc_last_dirct>[0-9a-fx]+)
loc_16E94:
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r2, #(?P<board_ar0_attenuation_fpga_ce>[0-9a-fx]+)
  movs	r1, #0xce ; FPGA_REG_UNKN_CE
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar0_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar0_attenuation_tx2_ce>[0-9a-fx]+)
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  b	#(?P<loc_last2_dirct>[0-9a-fx]+)
loc_16EBC:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #3
  beq	#(?P<loc_16ECE>[0-9a-fx]+)
loc_16EC4:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #0
  beq	#(?P<loc_16E94>[0-9a-fx]+)
  b	#(?P<loc_16EE2>[0-9a-fx]+)
loc_16ECE:
  movs	r2, #1
  movs	r1, #(?P<board_ad3_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad3_attenuation_tx2_ce>[0-9a-fx]+)
loc_last_dirct:
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
loc_last2_dirct:
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_16EE2:
  cbnz	r4, #(?P<loc_phase2_s1>[0-9a-fx]+)
  ldrb	r2, \[r5, #(?P<rel_fpga_reg_unkn15_value>[0-9a-fx]+)\]
  movs	r1, #0
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
loc_phase2_s1:
  ldr	r0, \[r6, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  lsrs	r0, r0, #0x1f
  strb	r0, \[r5, #(?P<rel_transceiver_pwr_mode_unk016C>[0-9a-fx]+)\]
loc_label_ret1:
  pop	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), pc}
""",
'vars': {
  'tcx_config_update1':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'ofdm_receiver_id':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'get_board_version':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_raw_ct16_dt8_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_raw_ct16_dt8_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'tx_sub_800D3E4':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regB':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regC':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'rel_dword_10004258':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_tcx_control_attenuation_by_packet':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_tcx_control_attenuation_by_unkn1':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_transceiver_flags_1A28':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_fpga_reg_unkn15_value':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_transceiver_pwr_mode_unk016C':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'tcx_byte_2000015C':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_transciever_attenuation':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_active_transciever_attenuation':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'loc_ad_from_pkt':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ad_from_pkt_s1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ar_from_pkt':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ar_from_pkt_s1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ar_from_pkt_s2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_last4_dirct':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s5':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_last_dirct':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_last2_dirct':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16E76':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16E94':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16EBC':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16EC4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16ECE':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16EE2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'board_ad3_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "8",
    'description': "Transceiver attenuation value for board type 3 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad3_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "8",
    'description': "Transceiver attenuation value for board type 3 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad3_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "36",
    'description': "Transceiver attenuation value for board type 3 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad3_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "36",
    'description': "Transceiver attenuation value for board type 3 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ar0_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "17",
    'description': "Transceiver attenuation value for board type 0 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar0_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "17",
    'description': "Transceiver attenuation value for board type 0 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar0_attenuation_fpga_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar0_attenuation_tx1_ce", 'getter': (lambda val: val)},
},
}

re_func_tcx_config_update1_C1_V01_05_m1401 = {
'name': "tcx_config_update1",
'version': "C1_FW_V01.05-m1401",
're': """
tcx_config_update1:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), lr}
  movs	r4, #0
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_tcx_control_attenuation_by_packet>[0-9a-fx]+)\]
  cmp	r0, #0
  beq	#(?P<loc_16DA2>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  ldr	r1, \[pc, #(?P<active_transciever_attenuation>[0-9a-fx]+)\]
  ldrb	r1, \[r1\]
  cmp	r0, r1
  beq	#(?P<loc_16DA2>[0-9a-fx]+)
  movs	r1, #0
  movs	r0, #0xf
  bl	#(?P<spi_raw_ct16_dt8_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<fpga_reg_unkn15_value>[0-9a-fx]+)\]
  strb	r0, \[r1\]
  mov	r0, r1
  ldrb	r0, \[r0\]
  orr	r2, r0, #1
  movs	r1, #0
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #1
  beq	#(?P<loc_ad_from_pkt>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #3
  bne	#(?P<loc_16D16>[0-9a-fx]+)
loc_ad_from_pkt:
  movs	r1, #1
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r1, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_16CF4>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_16CF4:
  movs	r1, #1
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r1, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_phase2_s4>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  b	#(?P<loc_phase2_s4>[0-9a-fx]+)
loc_16D16:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cbnz	r0, #(?P<loc_phase2_s4>[0-9a-fx]+)
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r2, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r1, #0xce ; FPGA_REG_UNKN_CE
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #1
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r1, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_16D68>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_16D68:
  movs	r1, #1
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r1, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_phase2_s4>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_phase2_s4:
  ldr	r0, \[pc, #(?P<fpga_reg_unkn15_value>[0-9a-fx]+)\]
  ldrb	r2, \[r0\]
  movs	r1, #0
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  ldr	r1, \[pc, #(?P<active_transciever_attenuation>[0-9a-fx]+)\]
  strb	r0, \[r1\]
loc_16DA2:
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_tcx_control_attenuation_by_packet>[0-9a-fx]+)\]
  cmp	r0, #0
  bne	#(?P<loc_14D58>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldr	r0, \[r0, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  ldr	r1, \[pc, #(?P<transceiver_pwr_mode_unk016C>[0-9a-fx]+)\]
  ldrb	r1, \[r1\]
  cmp.w	r1, r0, lsr #31
  beq	#(?P<loc_14D5E>[0-9a-fx]+)
  bl	#(?P<tx_sub_16A5C>[0-9a-fx]+)
  mov	r4, r0
  cbnz	r4, #(?P<loc_16DE8>[0-9a-fx]+)
  movs	r1, #0
  movs	r0, #0xf
  bl	#(?P<spi_raw_ct16_dt8_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<fpga_reg_unkn15_value>[0-9a-fx]+)\]
  strb	r0, \[r1\]
  mov	r0, r1
  ldrb	r0, \[r0\]
  orr	r2, r0, #1
  movs	r1, #0
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
loc_16DE8:
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldr	r0, \[r0, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  lsrs	r0, r0, #0x1f
  cbz	r0, #(?P<loc_16E0E>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #1
  beq	#(?P<loc_board_ad1_fcc>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #3
  bne	#(?P<loc_board_ar0_fcc>[0-9a-fx]+)
loc_board_ad1_fcc:
  movs	r2, #1
  movs	r1, #(?P<board_ad1_attenuation_tx1_fcc>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad1_attenuation_tx2_fcc>[0-9a-fx]+)
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  b	#(?P<loc_14D42>[0-9a-fx]+)
loc_board_ar0_fcc:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cbnz	r0, #(?P<loc_14D10>[0-9a-fx]+)
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r2, #(?P<board_ar0_attenuation_fpga_fcc>[0-9a-fx]+)
  movs	r1, #0xce ; FPGA_REG_UNKN_CE
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar0_attenuation_tx1_fcc>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar0_attenuation_tx2_fcc>[0-9a-fx]+)
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  b	#(?P<loc_14D42>[0-9a-fx]+)
loc_16E0E:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #1
  beq	#(?P<loc_board_ad1_ce>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #3
  bne	#(?P<loc_board_ar0_ce>[0-9a-fx]+)
loc_board_ad1_ce:
  movs	r2, #1
  movs	r1, #(?P<board_ad1_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad1_attenuation_tx2_ce>[0-9a-fx]+)
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_14D10:
  b	#(?P<loc_14D42>[0-9a-fx]+)
loc_board_ar0_ce:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cbnz	r0, #(?P<loc_14D42>[0-9a-fx]+)
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r2, #(?P<board_ar0_attenuation_fpga_ce>[0-9a-fx]+)
  movs	r1, #0xce ; FPGA_REG_UNKN_CE
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar0_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar0_attenuation_tx2_ce>[0-9a-fx]+)
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_14D42:
  cbnz	r4, #(?P<loc_phase2_s1>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<fpga_reg_unkn15_value>[0-9a-fx]+)\]
  ldrb	r2, \[r0\]
  movs	r1, #0
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
loc_phase2_s1:
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldr	r0, \[r0, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  lsrs	r0, r0, #0x1f
  b	#(?P<loc_14D5A>[0-9a-fx]+)
loc_14D58:
  b	#(?P<loc_14D5E>[0-9a-fx]+)
loc_14D5A:
  ldr	r1, \[pc, #(?P<transceiver_pwr_mode_unk016C>[0-9a-fx]+)\]
  strb	r0, \[r1\]
loc_14D5E:
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_tx_byte_20033B4>[0-9a-fx]+)\]
  cmp	r0, #0xff
  beq	#(?P<loc_label_ret1>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #1
  beq	#(?P<loc_14D78>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #3
  bne	#(?P<loc_label_ret1>[0-9a-fx]+)
loc_14D78:
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #9
  movs	r0, #0xf
  bl	#(?P<spi_raw_ct16_dt8_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r1, #(?P<rel_tx_byte_20033B4>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_14D9E>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r2, \[r0, #(?P<rel_tx_byte_20033B4>[0-9a-fx]+)\]
  movs	r1, #9
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
loc_14D9E:
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
loc_label_ret1:
  pop	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), pc}
""",
'vars': {
  'tcx_config_update1':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'ofdm_receiver_id':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'get_board_version':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_raw_ct16_dt8_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_raw_ct16_dt8_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'tx_sub_800D3E4':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'tx_sub_16A5C':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'rel_tcx_control_attenuation_by_packet':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_transceiver_flags_1A28':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_tx_byte_20033B4':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'fpga_reg_unkn15_value':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T},
  'transceiver_pwr_mode_unk016C':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T},
  'rel_transciever_attenuation':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'active_transciever_attenuation':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T},
  'loc_ad_from_pkt':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_ad1_fcc':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_ar0_fcc':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_ad1_ce':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_14D10':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_ar0_ce':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_14D42':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_14D58':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_14D5A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_14D5E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_14D78':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_14D9E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16CF4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16DA2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16D16':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16D68':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16DE8':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16E0E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'board_ad1_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "8",
    'description': "Transceiver attenuation value for board type 1 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad1_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "8",
    'description': "Transceiver attenuation value for board type 1 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad1_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "36",
    'description': "Transceiver attenuation value for board type 1 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad1_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "36",
    'description': "Transceiver attenuation value for board type 1 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ar0_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "6",
    'description': "Transceiver attenuation value for board type 0 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar0_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "6",
    'description': "Transceiver attenuation value for board type 0 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar0_attenuation_fpga_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar0_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ar0_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "17",
    'description': "Transceiver attenuation value for board type 0 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar0_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "17",
    'description': "Transceiver attenuation value for board type 0 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar0_attenuation_fpga_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar0_attenuation_tx1_ce", 'getter': (lambda val: val)},
},
}

re_func_tcx_config_update1_C1_V01_06_m1401 = {
'name': "tcx_config_update1",
'version': "C1_FW_V01.06-m1401",
're': """
tcx_config_update1:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), lr}
  movs	r4, #0
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_tcx_control_attenuation_by_packet>[0-9a-fx]+)\]
  cmp	r0, #0
  beq	#(?P<loc_16D98>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  ldr	r1, \[pc, #(?P<active_transciever_attenuation>[0-9a-fx]+)\]
  ldrb	r1, \[r1\]
  cmp	r0, r1
  beq	#(?P<loc_16DA2>[0-9a-fx]+)
  movs	r1, #0
  movs	r0, #0xf
  bl	#(?P<spi_raw_ct16_dt8_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<fpga_reg_unkn15_value>[0-9a-fx]+)\]
  strb	r0, \[r1\]
  mov	r0, r1
  ldrb	r0, \[r0\]
  orr	r2, r0, #1
  movs	r1, #0
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #1
  beq	#(?P<loc_ad_from_pkt>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #3
  bne	#(?P<loc_16D16>[0-9a-fx]+)
loc_ad_from_pkt:
  movs	r1, #1
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r1, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_16CF4>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_16CF4:
  movs	r1, #1
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r1, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_phase2_s4>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  b	#(?P<loc_phase2_s4>[0-9a-fx]+)
loc_16D16:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cbnz	r0, #(?P<loc_phase2_s4>[0-9a-fx]+)
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #0xce ; FPGA_REG_UNKN_CE
  movs	r0, #0xf
  bl	#(?P<spi_raw_ct16_dt8_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r1, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_ar_from_pkt_s1>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r2, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r1, #0xce ; FPGA_REG_UNKN_CE
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
loc_ar_from_pkt_s1:
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #1
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r1, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_16D68>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_16D68:
  movs	r1, #1
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r1, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  cmp	r0, r1
  beq	#(?P<loc_phase2_s4>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r1, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  movs	r2, #1
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_phase2_s4:
  ldr	r0, \[pc, #(?P<fpga_reg_unkn15_value>[0-9a-fx]+)\]
  ldrb	r2, \[r0\]
  movs	r1, #0
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  b	#(?P<loc_16D9A>[0-9a-fx]+)
loc_16D98:
  b	#(?P<loc_16DA2>[0-9a-fx]+)
loc_16D9A:
  ldrb.w	r0, \[r0, #(?P<rel_transciever_attenuation>[0-9a-fx]+)\]
  ldr	r1, \[pc, #(?P<active_transciever_attenuation>[0-9a-fx]+)\]
  strb	r0, \[r1\]
loc_16DA2:
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_tcx_control_attenuation_by_packet>[0-9a-fx]+)\]
  cmp	r0, #0
  bne	#(?P<loc_label_ret1>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldrb.w	r0, \[r0, #(?P<rel_tcx_control_attenuation_by_unkn1>[0-9a-fx]+)\]
  cmp	r0, #0
  bne	#(?P<loc_label_ret1>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldr	r0, \[r0, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  ldr	r1, \[pc, #(?P<transceiver_pwr_mode_unk016C>[0-9a-fx]+)\]
  ldrb	r1, \[r1\]
  cmp.w	r1, r0, lsr #31
  beq	#(?P<loc_label_ret1>[0-9a-fx]+)
  bl	#(?P<tx_sub_16A5C>[0-9a-fx]+)
  mov	r4, r0
  cbnz	r4, #(?P<loc_16DE8>[0-9a-fx]+)
  movs	r1, #0
  movs	r0, #0xf
  bl	#(?P<spi_raw_ct16_dt8_read>[0-9a-fx]+)
  ldr	r1, \[pc, #(?P<fpga_reg_unkn15_value>[0-9a-fx]+)\]
  strb	r0, \[r1\]
  mov	r0, r1
  ldrb	r0, \[r0\]
  orr	r2, r0, #1
  movs	r1, #0
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
loc_16DE8:
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldr	r0, \[r0, #0xc\]
  lsrs	r0, r0, #0x1f
  cbz	r0, #(?P<loc_16E0E>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #1
  bne	#(?P<loc_16E2A>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad1_attenuation_tx1_fcc>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad1_attenuation_tx2_fcc>[0-9a-fx]+)
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  b	#(?P<loc_16E2A>[0-9a-fx]+)
loc_16E0E:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #1
  bne	#(?P<loc_16E2A>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad1_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad1_attenuation_tx2_ce>[0-9a-fx]+)
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_16E2A:
  cbnz	r4, #(?P<loc_phase2_s1>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<fpga_reg_unkn15_value>[0-9a-fx]+)\]
  ldrb	r2, \[r0\]
  movs	r1, #0
  movs	r0, #0xe
  bl	#(?P<spi_raw_ct16_dt8_write>[0-9a-fx]+)
loc_phase2_s1:
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldr	r0, \[r0, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  lsrs	r0, r0, #0x1f
  ldr	r1, \[pc, #(?P<transceiver_pwr_mode_unk016C>[0-9a-fx]+)\]
  strb	r0, \[r1\]
loc_label_ret1:
  pop	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){1,8}), pc}
""",
'vars': {
  'tcx_config_update1':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'ofdm_receiver_id':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'get_board_version':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_raw_ct16_dt8_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_raw_ct16_dt8_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'tx_sub_800D3E4':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'tx_sub_16A5C':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'rel_tcx_control_attenuation_by_packet':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_tcx_control_attenuation_by_unkn1':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_transceiver_flags_1A28':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'fpga_reg_unkn15_value':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T},
  'transceiver_pwr_mode_unk016C':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T},
  'rel_transciever_attenuation':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'active_transciever_attenuation':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T},
  'loc_ad_from_pkt':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ar_from_pkt':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_ar_from_pkt_s1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_phase2_s1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16CF4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16D98':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16DA2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16D16':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16D68':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16D9A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16DE8':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16E0E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_16E2A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'board_ad1_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "8",
    'description': "Transceiver attenuation value for board type 3 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad1_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "8",
    'description': "Transceiver attenuation value for board type 3 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad1_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "36",
    'description': "Transceiver attenuation value for board type 1 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad1_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "36",
    'description': "Transceiver attenuation value for board type 1 with Analog Devices chip, change by 1 means 0.25 dBm"},
},
}

re_func_update_tcx_power_zone_flag_C1_V01_05_m1400_original = {
'name': "update_tcx_power_zone_flag-original",
'version': "C1_FW_V01.05-m1400",
# This function is only present in C1_FW, as the air part receives
# the value set by RC and does not detect the zone by itself.
# Bit 31 (0x1f) of transceiver_flags_1A28 variable is POWER_ZONE_FCC.
're': """
update_tcx_power_zone_flag:
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldr([.]w)?	r2, \[r1, #(?P<rel_tcx_dword_33C0>[0-9a-fx]+)\]
  lsls	r2, r2, #0x1f
  bne	#(?P<loc_label_ret1>[0-9a-fx]+)
  ldr	r2, \[r1, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  bfi	r2, r0, #0x1f, #1
  str	r2, \[r1, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
loc_label_ret1:
  bx	lr
""",
'vars': {
  'power_zone_selection_override':	{'type': VarType.DETACHED_DATA, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "1", 'defaultValue': "0", 'setValue': "0",
    'description': "What to do when power zone is about to be selected from geo coordinates; 0 - set the value based on geolocation, 1 - override the value and set to FCC"},
  'update_tcx_power_zone_flag':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'ofdm_receiver_id':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_tcx_dword_33C0':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_transceiver_flags_1A28':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'loc_label_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
},
}

re_func_update_tcx_power_zone_flag_C1_V01_05_m1400_setfcc = {
'name': "update_tcx_power_zone_flag-setfcc",
'version': "C1_FW_V01.05-m1400",
're': """
update_tcx_power_zone_flag:
  ldr	r1, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldr([.]w)?	r2, \[r1, #(?P<rel_tcx_dword_33C0>[0-9a-fx]+)\]
  lsls	r2, r2, #0x1f
  bne	#(?P<loc_label_ret1>[0-9a-fx]+)
  ldr	r2, \[r1, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  orr	r2, r2, #0x80000000
  str	r2, \[r1, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
loc_label_ret1:
  bx	lr
""",
'vars': {
  'power_zone_selection_override':	{'type': VarType.DETACHED_DATA, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "1", 'defaultValue': "0", 'setValue': "1",
    'description': "What to do when power zone is about to be selected from geo coordinates; 0 - set the value based on geolocation, 1 - override the value and set to FCC"},
  'update_tcx_power_zone_flag':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'ofdm_receiver_id':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'rel_tcx_dword_33C0':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'rel_transceiver_flags_1A28':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'loc_label_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
},
}

re_func_update_tcx_power_zone_flag_C1_V01_05_m1401_original = {
'name': "update_tcx_power_zone_flag-original",
'version': "C1_FW_V01.05-m1401",
# This function is only present in C1_FW, as the air part receives
# the value set by RC and does not detect the zone by itself.
# Bit 31 (0x1f) of transceiver_flags_1A28 variable is POWER_ZONE_FCC.
're': """
update_tcx_power_zone_flag:
  push	{lr}
  mov	r1, r0
  bl	#(?P<get_dword_33C0>[0-9a-fx]+)
  and	r0, r0, #1
  cbnz	r0, #(?P<loc_label_ret1>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldr	r0, \[r0, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  bfi	r0, r1, #0x1f, #1
  ldr	r2, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  str	r0, \[r2, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
loc_label_ret1:
  pop	{pc}
""",
'vars': {
  'power_zone_selection_override':	{'type': VarType.DETACHED_DATA, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "1", 'defaultValue': "0", 'setValue': "0",
    'description': "What to do when power zone is about to be selected from geo coordinates; 0 - set the value based on geolocation, 1 - override the value and set to FCC"},
  'update_tcx_power_zone_flag':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'ofdm_receiver_id':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'get_dword_33C0':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'rel_transceiver_flags_1A28':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'loc_label_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
},
}

re_func_update_tcx_power_zone_flag_C1_V01_05_m1401_setfcc = {
'name': "update_tcx_power_zone_flag-setfcc",
'version': "C1_FW_V01.05-m1401",
're': """
update_tcx_power_zone_flag:
  push	{lr}
  movs	r1, #1
  bl	#(?P<get_dword_33C0>[0-9a-fx]+)
  and	r0, r0, #1
  cbnz	r0, #(?P<loc_label_ret1>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  ldr	r0, \[r0, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
  bfi	r0, r1, #0x1f, #1
  ldr	r2, \[pc, #(?P<ofdm_receiver_id>[0-9a-fx]+)\]
  str	r0, \[r2, #(?P<rel_transceiver_flags_1A28>[0-9a-fx]+)\]
loc_label_ret1:
  pop	{pc}
""",
'vars': {
  'power_zone_selection_override':	{'type': VarType.DETACHED_DATA, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "1", 'defaultValue': "0", 'setValue': "1",
    'description': "What to do when power zone is about to be selected from geo coordinates; 0 - set the value based on geolocation, 1 - override the value and set to FCC"},
  'update_tcx_power_zone_flag':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'ofdm_receiver_id':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'get_dword_33C0':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'rel_transceiver_flags_1A28':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'loc_label_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
},
}


re_func_init_fpga_config_C1_V01_03_m1400 = {
'name': "init_fpga_config",
'version': "P3X_FW_V01.03-m1400", # Before V01.04, C1 firmware was part of P3X firmware
# This pattern does not define anything meaningful.
# It is here only to keep init_fpga_config defined for C1_FW versions.
're': """
init_fpga_config:
  push.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){3,12}), lr}
  movs	r5, #0
  movw	r6, #0x313c
  movs	r4, #0
  ldr	r7, \[pc, #(?P<ofdm_init_list_1>[0-9a-fx]+)\]
loc_145A0:
  bl	#(?P<WDT_Feed_cond>[0-9a-fx]+)
  cmp	r4, r6
  bhs	#(?P<loc_145B2>[0-9a-fx]+)
  adds	r0, r7, r4
  adds	r4, r4, #4
  bl	#(?P<sub_14B18>[0-9a-fx]+)
  b	#(?P<loc_145A0>[0-9a-fx]+)
loc_145B2:
  movs	r2, #0
  movs	r1, #0x29
  movs	r0, #0x14
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r1, #0
  movs	r0, #0x17
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  cmp	r0, #0x1a
  beq	#(?P<loc_1460A>[0-9a-fx]+)
  movs	r4, #0
  movs	r1, #0
  movs	r0, #0x5e
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  and.w	r4, r4, r0, lsr #7
  movs	r1, #0
  movw	r0, #0x247
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ubfx	r0, r0, #1, #1
  ands	r4, r0
  movs	r1, #0
  movw	r0, #0x287
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ubfx	r0, r0, #1, #1
  tst	r4, r0
  beq	#(?P<loc_1460E>[0-9a-fx]+)
  movs	r2, #2
  movs	r1, #1
  movs	r0, #0xe
; The function continues
""",
'vars': {
  'init_fpga_config':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_14B18':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'WDT_Feed_cond':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ofdm_init_list_1':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'loc_145A0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_145B2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_1460A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_1460E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
},
}

re_func_init_fpga_config_C1_V01_05_m1400 = {
'name': "init_fpga_config",
'version': "C1_FW_V01.05-m1400",
# This pattern does not define anything meaningful.
# It is here only to keep init_fpga_config defined for C1_FW versions.
're': """
init_fpga_config:
  push.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){3,12}), lr}
  movs	r6, #0
  ;mov	r5, r6
  dcw	(?P<undefined_varlen_3>([0-9a-fx]+[, ]*){1,8})
  bl	#(?P<get_board_version>[0-9a-fx]+)
  ; in C1_FW_V01.06 the wildcard is for 4 lines
  ;cbz	r0, #(?P<loc_15836>[0-9a-fx]+)
  ;bl	#(?P<get_board_version>[0-9a-fx]+)
  ;cmp	r0, #1
  ;bne	#(?P<loc_15BBA>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){1,8})
loc_15836:
  movs	r0, #0xa
  bl	#(?P<sub_15D96>[0-9a-fx]+)
  ldr	(r4|r0), \[pc, #(?P<unk_var01>[0-9a-fx]+)\]
  ldr	r0, \[(r4|r0), #(?P<unk_var02>[0-9a-fx]+)\]
  orr	r0, r0, #0x800000
  str	r0, \[r4, #(?P<unk_var02>[0-9a-fx]+)\]
  movs	r0, #1
  bl	#(?P<sub_15D96>[0-9a-fx]+)
  ldr	r0, \[r4, #(?P<unk_var03>[0-9a-fx]+)\]
  orr	r0, r0, #0x800000
  str	r0, \[r4, #(?P<unk_var03>[0-9a-fx]+)\]
loc_15BBA:
  ldr.w	(sl|r8), \[pc, #(?P<ofdm_init_list_2>[0-9a-fx]+)\]
  ; in C1_FW_V01.06 the wildcard is for 4 lines
  ;movs	r4, #0
  ;ldr.w	r8, \[pc, #(?P<ofdm_init_list_1>[0-9a-fx]+)\]
  ;movw	sb, #0x91c
  dcw	(?P<undefined_varlen_2>([0-9a-fx]+[, ]*){2,8})
  ; in earlier versions, they tend to switch order
  movw	(r7|sb), #(0x313c|0x91c)
  (addw|add.w)	(fp|sl), (sl|r8), (r7|#0x91c)
loc_15BD0:
  bl	#(?P<WDT_Feed_cond>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #3
  beq	#(?P<loc_15BEC>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cbz	r0, #(?P<loc_15BF6>[0-9a-fx]+)
; The function continues
""",
'vars': {
  'init_fpga_config':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'get_board_version':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_15D96':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'WDT_Feed_cond':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  #'ofdm_init_list_1':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'ofdm_init_list_2':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,8)},
  'undefined_varlen_2':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (2,8)},
  'undefined_varlen_3':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,8)},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'unk_var01':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var02':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'unk_var03':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'loc_15BF6':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  #'loc_15BBA':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_15BEC':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
},
}

re_func_init_fpga_config_C1_V01_05_m1401 = {
'name': "init_fpga_config",
'version': "C1_FW_V01.05-m1401",
# This pattern does not define anything meaningful.
# It is here only to keep init_fpga_config defined for C1_FW versions.
're': """
init_fpga_config:
  push.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){3,12}), lr}
  mov[.]w	r8, #0
  movs	r7, #0
  movs	r5, #0
  movs	r6, #0
  movs	r4, #0
  bl	#(?P<get_board_version>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){2,8})
loc_15836:
  movs	r0, #0xa
  bl	#(?P<sub_15D96>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<unk_var01>[0-9a-fx]+)\]
  ldr	r0, \[r0, #(?P<unk_var02>[0-9a-fx]+)\]
  orr	r1, r0, #0x400000
  ldr	r0, \[pc, #(?P<unk_var01>[0-9a-fx]+)\]
  str	r1, \[r0, #(?P<unk_var02>[0-9a-fx]+)\]
  movs	r0, #1
  bl	#(?P<sub_15D96>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<unk_var01>[0-9a-fx]+)\]
  subs	r0, #0x80
  ldr	r0, \[r0, #(?P<unk_var03>[0-9a-fx]+)\]
  orr	r1, r0, #0x4000000
  ldr	r0, \[pc, #(?P<unk_var01>[0-9a-fx]+)\]
  subs	r0, #0x80
  str	r1, \[r0, #(?P<unk_var03>[0-9a-fx]+)\]
  movs	r7, #0
  b	#(?P<loc_CF74>[0-9a-fx]+)
  movs	r4, #0
  b	#(?P<loc_CE72>[0-9a-fx]+)
  bl	#(?P<WDT_Feed_cond>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  ; Comparison to 1 is there only for older firmwares
  ;cmp	r0, #1
  ;beq	#(?P<loc_CE3E>[0-9a-fx]+)
  ;bl	#(?P<get_board_version>[0-9a-fx]+)
  ;cmp	r0, #3
  dcw	(?P<undefined_varlen_2>([0-9a-fx]+[, ]*){1,8})
  bne	#(?P<loc_CE50>[0-9a-fx]+)
  movw	r0, #0x313c
  cmp	r4, r0
; The function continues
""",
'vars': {
  'init_fpga_config':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'get_board_version':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_15D96':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'WDT_Feed_cond':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (2,8)},
  'undefined_varlen_2':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,8)},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'unk_var01':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_var02':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'unk_var03':	{'type': VarType.RELATIVE_OFFSET, 'variety': DataVariety.INT32_T},
  'loc_CF74':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_CE72':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  #'loc_CE3E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_CE50':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
},
}

re_func_init_fpga_config_P3X_V01_01 = {
'name': "init_fpga_config",
'version': "P3X_FW_V01.01",
# Attenuation values were added to this function in P3X_FW_V01.05; this variant is useless, just to remove warnings
're': """
init_fpga_config:
  push.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){3,12}), lr}
  mov.w	r8, #0
  movs	r7, #0
  movs	(r4|r5), #0
  movs	(r5|r6), #0
  movs	(r6|r4), #0
  nop	
  b	#(?P<loc_label35>[0-9a-fx]+)
loc_label01:
  movs	r6, #0
  b	#(?P<loc_label08>[0-9a-fx]+)
loc_label03:
  movw	r0, #0x314c ; sizeof ofdm_init_list_2
  cmp	r6, r0
  blo	#(?P<loc_label06>[0-9a-fx]+)
  b	#(?P<loc_label09>[0-9a-fx]+) ; end for ofdm_init_list_2
loc_label06:
  ldr	r0, \[pc, #(?P<ofdm_init_list_2>[0-9a-fx]+)\]
  add.w	r8, r0, r6
  adds	r6, r6, #4
  mov	r0, r8
  bl	#(?P<ofdm_init_instruction>[0-9a-fx]+)
loc_label08:
  b	#(?P<loc_label03>[0-9a-fx]+)
loc_label09:
  nop	
  movs	r2, #0
  movs	r1, #0x29
  movs	r0, #0x14 ; AD9363_REG_ENSM_CONFIG_1
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r1, #0
  movs	r0, #0x17 ; AD9363_REG_STATE
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  mov	r4, r0
  cmp	r4, #0x1a
  bne	#(?P<loc_label18>[0-9a-fx]+)
  movs	r0, #1
  b	#(?P<loc_label17>[0-9a-fx]+)
loc_label18:
  movs	r0, #0
loc_label17:
  mov	r5, r0
  movs	r1, #0
  movs	r0, #0x5e
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  mov	r4, r0
  and.w	r5, r5, r4, lsr #7
  movs	r1, #0
  movw	r0, #0x247
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  mov	(r4|r5), r0
  ubfx	r0, (r4|r5), #1, #1
  ands	r5, r0
  movs	r1, #0
  movw	r0, #0x287
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  mov	r4, r0
  ubfx	r0, r4, #1, #1
  ands	r5, r0
  cbz	r5, #(?P<loc_label34>[0-9a-fx]+)
  movs	r0, #0xc8
  bl	#(?P<sub_800C1E4>[0-9a-fx]+)
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r0, #0x20 ; FPGA_REG_UNKN_20
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  orr	sb, r0, #0xc
  mov	r1, sb
  movs	r0, #0x20 ; FPGA_REG_UNKN_20
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #2
  movs	r0, #1 ; FPGA_REG_UNKN_01
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  bl	#(?P<sub_800D7B8>[0-9a-fx]+)
  nop	
  nop	
  movs	r0, #1
loc_label_ret1:
  pop.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){3,12}), pc}
loc_label34:
  nop	
  nop	
  adds	r0, r7, #1
  uxtb	r7, r0
loc_label35:
  cmp	r7, #3 ; num of retries
  blt	#(?P<loc_label01>[0-9a-fx]+)
  movs	r0, #0
  b	#(?P<loc_label_ret1>[0-9a-fx]+)
""",
'vars': {
  'init_fpga_config':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_fpga_raw_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_fpga_raw_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ofdm_init_instruction':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'tx_sub_800D3E4':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_800D7B8':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_800C1E4':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'ofdm_init_list_2':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'loc_label01':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label03':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label06':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label08':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label09':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label17':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label18':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label34':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label35':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
},
}

re_func_init_fpga_config_P3X_V01_05 = {
'name': "init_fpga_config",
'version': "P3X_FW_V01.05",
're': """
init_fpga_config:
  push.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){3,12}), lr}
  mov.w	r8, #0
  movs	r7, #0
  movs	(r5|r4), #0
  movs	(r6|r5), #0
  movs	(r4|r6), #0
  nop	
  b	#(?P<loc_label35>[0-9a-fx]+)
loc_label01:
  movs	r4, #0
  b	#(?P<loc_label08>[0-9a-fx]+)
loc_label03:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_board_ad>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  beq	#(?P<loc_board_ad>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  bne	#(?P<loc_board_check_3>[0-9a-fx]+)
loc_board_ad:
  movw	r0, #0x314c ; sizeof ofdm_init_list_2
  cmp	r4, r0
  blo	#(?P<loc_label06>[0-9a-fx]+)
  b	#(?P<loc_label09>[0-9a-fx]+) ; end for ofdm_init_list_2
loc_label06:
  ldr	r0, \[pc, #(?P<ofdm_init_list_2>[0-9a-fx]+)\]
  add.w	r8, r0, r4
  b	#(?P<loc_label07>[0-9a-fx]+)
loc_board_check_3:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_label05>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  bne	#(?P<loc_label11>[0-9a-fx]+)
loc_label05:
  movw	r0, #0x91c ; sizeof ofdm_init_list_3
  cmp	r4, r0
  blo	#(?P<loc_label12>[0-9a-fx]+)
  b	#(?P<loc_label09>[0-9a-fx]+)
loc_label12:
  ldr	r0, \[pc, #0x280\]
  add.w	r8, r0, r4
  b	#(?P<loc_label07>[0-9a-fx]+)
loc_label11:
  b	#(?P<loc_label09>[0-9a-fx]+)
loc_label07:
  adds	r4, r4, #4
  mov	r0, r8
  bl	#(?P<ofdm_init_instruction>[0-9a-fx]+)
loc_label08:
  b	#(?P<loc_label03>[0-9a-fx]+)
loc_label09:
  nop	
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_label10>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  bne	#(?P<loc_board_check_9>[0-9a-fx]+)
loc_label10:
  ldr	r0, \[pc, #0x260\]
  ldr	r0, \[r0\]
  ldr	r1, \[pc, #0x260\]
  cmp	r0, r1
  bne	#(?P<loc_board_check_9>[0-9a-fx]+)
  movs	r4, #0
  b	#(?P<loc_label31>[0-9a-fx]+)
loc_label32:
  cmp	r4, #0x38 ; sizeof ofdm_init_list_1
  blo	#(?P<loc_label14>[0-9a-fx]+)
  b	#(?P<loc_label33>[0-9a-fx]+)
loc_label14:
  ldr	r0, \[pc, #(?P<ofdm_init_list_1>[0-9a-fx]+)\]
  add.w	r8, r0, r4
  adds	r4, r4, #4
  mov	r0, r8
  bl	#(?P<ofdm_init_instruction>[0-9a-fx]+)
loc_label31:
  b	#(?P<loc_label32>[0-9a-fx]+)
loc_label33:
  nop	
loc_board_check_9:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  bne	#(?P<loc_board_check_8>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #(?P<board_ad4_attenuation_tx1_init>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #(?P<board_ad4_attenuation_tx2_init>[0-9a-fx]+)
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  b	#(?P<loc_board_check_6>[0-9a-fx]+)
loc_board_check_8:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  bne	#(?P<loc_board_check_7>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #(?P<board_ad5_attenuation_tx1_init>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #(?P<board_ad5_attenuation_tx2_init>[0-9a-fx]+)
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  b	#(?P<loc_board_check_6>[0-9a-fx]+)
loc_board_check_7:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  bne	#(?P<loc_board_check_6>[0-9a-fx]+)
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #(?P<board_ar6_attenuation_fpga_init>[0-9a-fx]+)
  movs	r0, #0xce ; FPGA_REG_UNKN_CE
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #(?P<board_ar6_attenuation_tx1_init>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #(?P<board_ar6_attenuation_tx2_init>[0-9a-fx]+)
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_board_check_6:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  bne	#(?P<loc_board_check_5>[0-9a-fx]+)
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #(?P<board_ar7_attenuation_fpga_init>[0-9a-fx]+)
  movs	r0, #0xce ; FPGA_REG_UNKN_CE
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #(?P<board_ar7_attenuation_tx1_init>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #(?P<board_ar7_attenuation_tx2_init>[0-9a-fx]+)
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  b	#(?P<loc_board_check_4>[0-9a-fx]+)
loc_board_check_5:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  bne	#(?P<loc_board_check_4>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #(?P<board_ad2_attenuation_tx1_init>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #(?P<board_ad2_attenuation_tx2_init>[0-9a-fx]+)
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_board_check_4:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_label16>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  beq	#(?P<loc_label16>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  bne	#(?P<loc_board_check_2>[0-9a-fx]+)
loc_label16:
  movs	r2, #0
  movs	r1, #0x29
  movs	r0, #0x14 ; AD9363_REG_ENSM_CONFIG_1
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r1, #0
  movs	r0, #0x17 ; AD9363_REG_STATE
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  mov	r5, r0
  cmp	r5, #0x1a
  bne	#(?P<loc_label18>[0-9a-fx]+)
  movs	r0, #1
  b	#(?P<loc_label17>[0-9a-fx]+)
loc_label18:
  movs	r0, #0
loc_label17:
  mov	r6, r0
  movs	r1, #0
  movs	r0, #0x5e
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  mov	r5, r0
  and.w	r6, r6, r5, lsr #7
  movs	r1, #0
  movw	r0, #0x247
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  mov	r5, r0
  ubfx	r0, r5, #1, #1
  ands	r6, r0
  movs	r1, #0
  movw	r0, #0x287
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  mov	r5, r0
  ubfx	r0, r5, #1, #1
  ands	r6, r0
  b	#(?P<loc_label20>[0-9a-fx]+)
loc_board_check_2:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_label19>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  bne	#(?P<loc_label20>[0-9a-fx]+)
loc_label19:
  movs	r2, #0
  movs	r1, #0xc0
  movs	r0, #0x42 ; AR8003_REG_UNKN_42
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #0x40
  movs	r0, #0x42 ; AR8003_REG_UNKN_42
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #1
  movs	r0, #0x2a ; AR8003_REG_UNKN_2A
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r0, #1
  bl	#(?P<sub_800C1E4>[0-9a-fx]+)
  movs	r2, #0
  mov	r1, r2
  movs	r0, #0x2a ; AR8003_REG_UNKN_2A
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r0, #0xa
  bl	#(?P<sub_800C1E4>[0-9a-fx]+)
  movs	r1, #0
  movs	r0, #0x7c
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  mov	r5, r0
  ubfx	r6, r5, #6, #1
loc_label20:
  cbz	r6, #(?P<loc_label34>[0-9a-fx]+)
  movs	r0, #0xc8
  bl	#(?P<sub_800C1E4>[0-9a-fx]+)
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r0, #0x20 ; FPGA_REG_UNKN_20
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  orr	sb, r0, #0xc
  mov	r1, sb
  movs	r0, #0x20 ; FPGA_REG_UNKN_20
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #2
  movs	r0, #1 ; FPGA_REG_UNKN_01
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  bl	#(?P<sub_800D7B8>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_label21>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  bne	#(?P<loc_label22>[0-9a-fx]+)
loc_label21:
  bl	#(?P<sub_800D414>[0-9a-fx]+)
  bl	#(?P<sub_800D7B8>[0-9a-fx]+)
loc_label22:
  nop	
  nop	
  movs	r0, #1
loc_label_ret1:
  pop.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){3,12}), pc}
loc_label34:
  nop	
  nop	
  adds	r0, r7, #1
  uxtb	r7, r0
loc_label35:
  cmp	r7, #3 ; num of retries
  blt.w	#(?P<loc_label01>[0-9a-fx]+)
  movs	r0, #0
  b	#(?P<loc_label_ret1>[0-9a-fx]+)
""",
'vars': {
  'init_fpga_config':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'get_board_version':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_fpga_raw_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_fpga_raw_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ofdm_init_instruction':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'tx_sub_800D3E4':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_800D414':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_800D7B8':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_800C1E4':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'ofdm_init_list_1':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'ofdm_init_list_2':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'loc_board_check_2':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_check_3':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_check_4':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_check_5':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_check_6':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_check_7':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_check_8':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_check_9':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label01':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label03':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_ad':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label05':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label06':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label07':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label08':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label09':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label10':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label11':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label12':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label14':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label16':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label17':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label18':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label19':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label20':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label21':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label22':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label31':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label32':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label33':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label34':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label35':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'board_ad4_attenuation_tx1_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad4_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ad4_attenuation_tx2_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad4_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ad5_attenuation_tx1_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad5_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ad5_attenuation_tx2_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad5_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ar6_attenuation_tx1_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar6_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ar6_attenuation_tx2_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar6_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ar7_attenuation_tx1_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar7_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ar7_attenuation_tx2_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar7_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ad2_attenuation_tx1_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad2_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ad2_attenuation_tx2_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad2_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ar6_attenuation_fpga_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar6_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ar7_attenuation_fpga_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar7_attenuation_tx1_fcc", 'getter': (lambda val: val)},
},
}

re_func_init_fpga_config_P3X_V01_08 = {
'name': "init_fpga_config",
'version': "P3X_FW_V01.08",
're': """
init_fpga_config:
  push.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){3,12}), lr}
  mov.w	r8, #0
  mov	r7, r8
loc_label01:
  movs	r5, #0
  mov	r6, r5
loc_label02:
  movs	r4, #0
loc_label03:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_board_ad>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  beq	#(?P<loc_board_ad>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  beq	#(?P<loc_board_ad>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_label05>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  beq	#(?P<loc_label05>[0-9a-fx]+)
  b	#(?P<loc_label07>[0-9a-fx]+)
loc_board_ad:
  ldr	r0, \[pc, #(?P<byte_8016118>[0-9a-fx]+)\]
  b	#(?P<loc_label06>[0-9a-fx]+)
loc_label05:
  ldr	r0, \[pc, #(?P<byte_8016318>[0-9a-fx]+)\]
loc_label06:
  add.w	r0, r0, r6, lsl #8
  ldrb	r1, \[r0, r4\]
  uxtb	r0, r4
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
loc_label07:
  adds	r4, r4, #1
  cmp	r4, #0xff
  bls	#(?P<loc_label03>[0-9a-fx]+)
  adds	r6, r6, #1
  cmp	r6, #2
  blo	#(?P<loc_label02>[0-9a-fx]+)
  ldr	r6, \[pc, #0x2d0\]
  movw	r4, #0x293c
  mov.w	sl, #0x10c
  add.w	sb, r6, r4
loc_label08:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_label09>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  beq	#(?P<loc_label09>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  beq	#(?P<loc_label09>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_label10>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  beq	#(?P<loc_label10>[0-9a-fx]+)
  b	#(?P<loc_label12>[0-9a-fx]+)
loc_label09:
  cmp	r5, r4
  bhs	#(?P<loc_label12>[0-9a-fx]+)
  adds	r0, r6, r5
  b	#(?P<loc_label11>[0-9a-fx]+)
loc_label10:
  cmp	r5, sl
  bhs	#(?P<loc_label12>[0-9a-fx]+)
  add.w	r0, sb, r5
loc_label11:
  adds	r5, r5, #4
  bl	#(?P<ofdm_init_instruction>[0-9a-fx]+)
  b	#(?P<loc_label08>[0-9a-fx]+)
loc_label12:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_label13>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  bne	#(?P<loc_label15>[0-9a-fx]+)
loc_label13:
  ldr	r0, \[pc, #(?P<dword_200000FC>[0-9a-fx]+)\]
  ldr	r1, \[pc, #(?P<unk_1000910>[0-9a-fx]+)\]
  ldr	r0, \[r0\]
  cmp	r0, r1
  bne	#(?P<loc_label15>[0-9a-fx]+)
  ldr	r5, \[pc, #(?P<ofdm_init_list_1>[0-9a-fx]+)\]
  movs	r4, #0
loc_label14:
  adds	r0, r5, r4
  adds	r4, r4, #4
  bl	#(?P<ofdm_init_instruction>[0-9a-fx]+)
  cmp	r4, #0x38
  blo	#(?P<loc_label14>[0-9a-fx]+)
loc_label15:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_label16>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  beq	#(?P<loc_label16>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  beq	#(?P<loc_label16>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_label19>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  beq	#(?P<loc_label19>[0-9a-fx]+)
  b	#(?P<loc_label20>[0-9a-fx]+)
loc_label16:
  movs	r2, #0
  movs	r1, #0x29
  movs	r0, #0x14 ; AD9363_REG_ENSM_CONFIG_1
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r1, #0
  movs	r0, #0x17 ; AD9363_REG_STATE
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  cmp	r0, #0x1a
  beq	#(?P<loc_label18>[0-9a-fx]+)
  movs	r4, #0
loc_label17:
  movs	r1, #0
  movs	r0, #0x5e
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  and.w	r7, r4, r0, lsr #7
  movs	r1, #0
  movw	r0, #0x247
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ubfx	r0, r0, #1, #1
  ands	r7, r0
  movs	r1, #0
  movw	r0, #0x287
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ubfx	r0, r0, #1, #1
  ands	r7, r0
  b	#(?P<loc_label20>[0-9a-fx]+)
loc_label18:
  movs	r4, #1
  b	#(?P<loc_label17>[0-9a-fx]+)
loc_label19:
  movs	r2, #0
  movs	r1, #0xc0
  movs	r0, #0x42 ; AR8003_REG_UNKN_42
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #0x40
  movs	r0, #0x42 ; AR8003_REG_UNKN_42
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #1
  movs	r0, #0x2a ; AR8003_REG_UNKN_2A
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r0, #1
  bl	#(?P<sub_800C1E4>[0-9a-fx]+)
  movs	r2, #0
  mov	r1, r2
  movs	r0, #0x2a ; AR8003_REG_UNKN_2A
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r0, #0xa
  bl	#(?P<sub_800C1E4>[0-9a-fx]+)
  movs	r1, #0
  movs	r0, #0x7c
  bl	#(?P<ad936x_reg_sync_read>[0-9a-fx]+)
  ubfx	r7, r0, #6, #1
loc_label20:
  cmp	r7, #0
  beq	#(?P<loc_label29>[0-9a-fx]+)
  movs	r0, #0xc8
  bl	#(?P<sub_800C1E4>[0-9a-fx]+)
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r0, #0x20 ; FPGA_REG_UNKN_20
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  orr	r1, r0, #0xc
  movs	r0, #0x20 ; FPGA_REG_UNKN_20
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #2
  movs	r0, #1 ; FPGA_REG_UNKN_01
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  bl	#(?P<sub_800D7B8>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_label21>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  bne	#(?P<loc_label22>[0-9a-fx]+)
loc_label21:
  bl	#(?P<sub_800D414>[0-9a-fx]+)
  bl	#(?P<sub_800D7B8>[0-9a-fx]+)
loc_label22:
  mov.w	r0, #0x7d0
  bl	#(?P<sub_800C1E4>[0-9a-fx]+)
  movs	r0, #0
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  orr	r1, r0, #1
  movs	r0, #0 ; FPGA_REG_UNKN_00
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_label23>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  beq	#(?P<loc_label24>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_label26>[0-9a-fx]+)
  b	#(?P<loc_label28>[0-9a-fx]+)
loc_label23:
  movs	r2, #0
  movs	r1, #(?P<board_ad4_attenuation_tx1_init>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad4_attenuation_tx2_init>[0-9a-fx]+)
  b	#(?P<loc_label25>[0-9a-fx]+)
loc_label24:
  movs	r2, #0
  movs	r1, #(?P<board_ad5_attenuation_tx1_init>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad5_attenuation_tx2_init>[0-9a-fx]+)
loc_label25:
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  b	#(?P<loc_label27>[0-9a-fx]+)
loc_label26:
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #(?P<board_ar6_attenuation_fpga_init>[0-9a-fx]+)
  movs	r0, #0xce ; FPGA_REG_UNKN_CE
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #(?P<board_ar6_attenuation_tx1_init>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #(?P<board_ar6_attenuation_tx2_init>[0-9a-fx]+)
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #0xf0
  movs	r0, #0x6a ; AR8003_REG_UNKN_6A
loc_label27:
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_label28:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  beq	#(?P<loc_label30>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  beq	#(?P<loc_label31>[0-9a-fx]+)
  ; in P3X_FW_V01.08, the wildcard matches lines:
  ;b	#(?P<loc_label33>[0-9a-fx]+)
  ;loc_label29:
  ;b	#(?P<loc_label34>[0-9a-fx]+)
  ; in wm330_0900_v04.03.00.00, the wildcard matches lines:
  ;b	#(?P<loc_label33>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){1,4})
loc_label30:
  movs	r0, #1
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r1, #(?P<board_ar7_attenuation_fpga_init>[0-9a-fx]+)
  movs	r0, #0xce ; FPGA_REG_UNKN_CE
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<tx_sub_800D3E4>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #(?P<board_ar7_attenuation_tx1_init>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  ;movs	r2, #0
  ; in P3X_FW_V01.08, the wildcard matches lines:
  ;movs	r2, #0
  ; in wm330_0900_v04.03.00.00, the wildcard matches lines:
  ;loc_label29:
  ;b	#(?P<loc_label34>[0-9a-fx]+)
  ;movs	r2, #0
  dcw	(?P<undefined_varlen_2>([0-9a-fx]+[, ]*){1,4})
  movs	r1, #(?P<board_ar7_attenuation_tx2_init>[0-9a-fx]+)
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #0xf0
  movs	r0, #0x6a ; AR8003_REG_UNKN_6A
  b	#(?P<loc_label32>[0-9a-fx]+)
loc_label31:
  movs	r2, #0
  movs	r1, #(?P<board_ad2_attenuation_tx1_init>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad2_attenuation_tx2_init>[0-9a-fx]+)
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
loc_label32:
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_label33:
  movs	r0, #0
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  and	r1, r0, #0xfe
  movs	r0, #0 ; FPGA_REG_UNKN_00
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r0, #1
loc_label_ret1:
  pop.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){3,12}), pc}
loc_label34:
  add.w	r0, r8, #1
  and	r8, r0, #0xff
  cmp.w	r8, #3
  blo.w	#(?P<loc_label01>[0-9a-fx]+)
  movs	r0, #0
  b	#(?P<loc_label_ret1>[0-9a-fx]+)
""",
'vars': {
  'init_fpga_config':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'get_board_version':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_fpga_raw_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'spi_fpga_raw_read':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ofdm_init_instruction':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'tx_sub_800D3E4':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_800D414':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_800D7B8':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_800C1E4':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,4)},
  'undefined_varlen_2':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,4)},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'byte_8016118':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'byte_8016318':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'dword_200000FC':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'unk_1000910':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'ofdm_init_list_1':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UNKNOWN},
  'loc_label01':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label02':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label03':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_board_ad':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label05':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label06':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label07':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label08':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label09':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label10':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label11':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label12':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label13':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label14':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label15':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label16':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label17':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label18':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label19':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label20':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label21':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label22':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label23':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label24':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label25':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label26':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label27':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label28':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label29':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label30':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label31':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label32':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  #'loc_label33':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  #'loc_label34':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'board_ad4_attenuation_tx1_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad4_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ad4_attenuation_tx2_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad4_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ad5_attenuation_tx1_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad5_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ad5_attenuation_tx2_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad5_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ar6_attenuation_tx1_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar6_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ar6_attenuation_tx2_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar6_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ar7_attenuation_tx1_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar7_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ar7_attenuation_tx2_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar7_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ad2_attenuation_tx1_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad2_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ad2_attenuation_tx2_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad2_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ar6_attenuation_fpga_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar6_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ar7_attenuation_fpga_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar7_attenuation_tx1_fcc", 'getter': (lambda val: val)},
},
}


re_func_cmd_exec_set00_cmd01b_P3X_V01_04 = {
'name': "cmd_exec_set00_cmd01b",
'version': "P3X_FW_V01.04",
'alt_name': "cmd_exec_set00_cmd01",
're': """
cmd_exec_set00_cmd01b:
  (push|push.w)	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){3,5}), lr}
  mov	r5, r0
  ; in P3X_FW_V01.07, the wildcard matches lines:
  ;mov	r8, r1
  ;movs	r7, #0
  ;mov	r6, r5
  ; in P3X_FW_V01.08, the wildcard matches lines:
  ;movs	r6, #0
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){1,8})
  add.w	r4, (?P<regB>r[0-9]), #0xb
  ; in P3X_FW_V01.07, the wildcard matches lines:
  ;ldrb	r0, [r4, #1]
  ;bic	r0, r0, #0xf0
  ;strb	r0, [r4, #1]
  ;ldrb	r0, [r4, #1]
  ;bic	r0, r0, #0xf
  ; in P3X_FW_V01.08, the wildcard matches lines:
  ;movs	(?P<regC>r[0-9]), #0 ; regC is r6
  dcw	(?P<undefined_varlen_2>([0-9a-fx]+[, ]*){1,10})
  adds	r0, (?P<regC>r[0-9]), #1
  strb	r0, \[r4, #1\]
  movs	r1, #0x10
  adds	r0, r4, #2
  bl	#(?P<sub_8012360>[0-9a-fx]+)
  ldrb	r0, \[(?P<regD>r[0-9]), #5\] ; regD is r5 or r6
  and	r0, r0, #0x1f
  cmp	r0, #9
  bne	#(?P<loc_8012D84>[0-9a-fx]+)
  bl	#(?P<sub_8012372>[0-9a-fx]+)
  str.w	r0, \[r4, #0x12\]
  ldr	r0, \[pc, #(?P<lb_mcu_version_1>[0-9a-fx]+)\]
  str.w	r0, \[r4, #0x16\]
  ; in P3X_FW_V01.04, the wildcard matches 1 line only:
  ;b	#(?P<loc_8011F72>[0-9a-fx]+)
  ; in P3X_FW_V01.07, the wildcard matches 1 line plus data block:
  ;b	#(?P<loc_8011F72>[0-9a-fx]+)
  ;dcd ... (x7)
  dcw	(?P<undefined_varlen_3>([0-9a-fx]+[, ]*){1,16})
loc_8012D84:
  ldrb	r0, \[r6, #5\]
  and	r0, r0, #0x1f
  cmp	r0, #0x13
  ; in P3X_FW_V01.04, the wildcard matches lines:
  ;bne	#(?P<loc_8011F72>[0-9a-fx]+)
  ; in P3X_FW_V01.07, the wildcard matches lines:
  ;bne	#(?P<loc_8011F72>[0-9a-fx]+)
  ;bl	#(?P<get_board_version>[0-9a-fx]+)
  ;cmp	r0, #4
  ;beq	#(?P<loc_8011F5C>[0-9a-fx]+)
  ;bl	#(?P<get_board_version>[0-9a-fx]+)
  ;cmp	r0, #5
  ;bne	#(?P<loc_8012DB0>[0-9a-fx]+)
  dcw	(?P<undefined_varlen_4>([0-9a-fx]+[, ]*){1,16})
loc_8011F5C:
  ldr	r0, \[pc, #(?P<dword_200000F8>[0-9a-fx]+)\]
  ldr	r0, \[r0\]
  str.w	r0, \[r4, #0x12\]
  ldr	r0, \[pc, #(?P<dword_200000FC>[0-9a-fx]+)\]
  ldr	r0, \[r0\]
  ; in P3X_FW_V01.04, the wildcard matches lines:
  ;str.w	r0, \[r4, #0x16\]
  ; in P3X_FW_V01.07, the wildcard matches lines:
  ;str.w	r0, \[r4, #0x16\]
  ;b	#(?P<loc_8011F72>[0-9a-fx]+)
  ;loc_8012DB0:
  ;bl	#(?P<get_board_version>[0-9a-fx]+)
  ;cmp	r0, #6
  ;beq	#(?P<loc_8012DC8>[0-9a-fx]+)
  ;bl	#(?P<get_board_version>[0-9a-fx]+)
  ;cmp	r0, #7
  ;beq	#(?P<loc_8012DC8>[0-9a-fx]+)
  ;bl	#(?P<get_board_version>[0-9a-fx]+)
  ;cmp	r0, #2
  ;bne	#(?P<loc_8011F72>[0-9a-fx]+)
  ;loc_8012DC8:
  ;mvn	r0, #1
  ;str.w	r0, \[r4, #0x12\]
  ;str.w	r0, \[r4, #0x16\]
  dcw	(?P<undefined_varlen_5>([0-9a-fx]+[, ]*){1,24})
loc_8011F72:
  movs	r0, #1
  str.w	r0, \[r4, #0x1a\]
  strb	r7, \[r4\]
  movs	r3, #0x1e
  mov	r2, r4
  mov	r1, r5
  ldr	r0, \[pc, #(?P<packet_send>[0-9a-fx]+)\]
  bl	#(?P<packet_make_response>[0-9a-fx]+)
  pop.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){3,5}), pc}
""",
'vars': {
  'cmd_exec_set00_cmd01b':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_8012360':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_8012372':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'get_board_version':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_make_response':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_send':	{'type': VarType.RELATIVE_ADDR_TO_CODE, 'baseaddr': "PC+", 'variety': CodeVariety.FUNCTION},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regB':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regC':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regD':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,4)},
  'undefined_varlen_2':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,10)},
  'undefined_varlen_3':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,16)},
  'undefined_varlen_4':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,16)},
  'undefined_varlen_5':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,24)},
  'loc_8011F5C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_8011F72':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_8012D84':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_8012DC8':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_8012DB0':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'dword_200000F8':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T},
  'dword_200000FC':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T},
  'lb_mcu_version_1':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "mcu_firmware_version", 'getter': version_string_to_int_getter},
  'mcu_firmware_version':	{'type': VarType.DETACHED_DATA, 'variety': DataVariety.CHAR, 'array': 11,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "00.00.00.00", 'maxValue': "99.99.99.99",
    'depend': "lb_mcu_version_1", 'getter': version_int_to_string_getter, 'forceVisible': True,
    'description': "Firmware version number"},
},
}

re_func_cmd_exec_set00_cmd01b_P3X_V01_08 = {
'name': "cmd_exec_set00_cmd01b",
'version': "P3X_FW_V01.08",
'alt_name': "cmd_exec_set00_cmd01",
're': """
cmd_exec_set00_cmd01b:
  (push|push.w)	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){3,5}), lr}
  mov	r5, r0
  ; in P3X_FW_V01.07, the wildcard matches lines:
  ;mov	r8, r1
  ;movs	r7, #0
  ;mov	r6, r5
  ;add.w	r4, (?P<regB>r[0-9]), #0xb
  ;ldrb	r0, [r4, #1]
  ;bic	r0, r0, #0xf0
  ;strb	r0, [r4, #1]
  ;ldrb	r0, [r4, #1]
  ;bic	r0, r0, #0xf
  ; in P3X_FW_V01.08, the wildcard matches lines:
  ;movs	(?P<regC>r[0-9]), #0 ; regC is r6
  ;add.w	r4, (?P<regB>r[0-9]), #0xb
  dcw	(?P<undefined_varlen_1>([0-9a-fx]+[, ]*){3,20})
  adds	r0, (?P<regC>r[0-9]), #1
  strb	r0, \[r4, #1\] ; struct offset PktPayload_VersionInquiry.field_0
  ; in P3X_FW_V01.07, the wildcard matches lines:
  ;movs	r1, #0x10
  ; in P3X_FW_V01.11, the wildcard matches lines:
  ;movs r7, #1
  ;str.w r7, \[r4, #0x1e\] ; struct offset PktPayload_VersionInquiry.field_1E
  ;movs	r1, #0x10
  dcw	(?P<undefined_varlen_2>([0-9a-fx]+[, ]*){1,6})
  adds	r0, r4, #2
  bl	#(?P<sub_8012360>[0-9a-fx]+)
  ldrb	r0, \[(?P<regD>r[0-9]), #5\] ; regD is r5 or r6
  and	r0, r0, #0x1f
  cmp	r0, #9
  beq	#(?P<loc_8011F26>[0-9a-fx]+)
  cmp	r0, #0x13
  beq	#(?P<loc_8011F32>[0-9a-fx]+)
  b	#(?P<loc_8011F76>[0-9a-fx]+)
loc_8011F26:
  bl	#(?P<sub_8012372>[0-9a-fx]+)
  str.w	r0, \[r4, #0x12\] ; struct offset PktPayload_VersionInquiry.ldr_version
  ldr	r0, \[pc, #(?P<lb_mcu_version_1>[0-9a-fx]+)\]
  b	#(?P<loc_8011F72>[0-9a-fx]+)
loc_8011F32:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_8011F5C>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  beq	#(?P<loc_8011F5C>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_8011F6A>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  beq	#(?P<loc_8011F6A>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  beq	#(?P<loc_8011F6A>[0-9a-fx]+)
  b	#(?P<loc_8011F76>[0-9a-fx]+)
loc_8011F5C:
  ldr	r0, \[pc, #(?P<dword_200000F8>[0-9a-fx]+)\]
  ldr	r0, \[r0\]
  str.w	r0, \[r4, #0x12\] ; struct offset PktPayload_VersionInquiry.ldr_version
  ldr	r0, \[pc, #(?P<dword_200000FC>[0-9a-fx]+)\]
  ldr	r0, \[r0\]
  b	#(?P<loc_8011F72>[0-9a-fx]+)
loc_8011F6A:
  mvn	r0, #1
  str.w	r0, \[r4, #0x12\] ; struct offset PktPayload_VersionInquiry.ldr_version
loc_8011F72:
  str.w	r0, \[r4, #0x16\] ; struct offset PktPayload_VersionInquiry.app_version
loc_8011F76:
  ; in P3X_FW_V01.07, the wildcard matches lines:
  ;movs	r0, #1
  ;str.w	r0, \[r4, #0x1a\]
  ; in P3X_FW_V01.11, the wildcard matches lines:
  ;str.w	r0, \[r4, #0x1a\] ; struct offset PktPayload_VersionInquiry.field_1A
  dcw	(?P<undefined_varlen_3>([0-9a-fx]+[, ]*){1,4})
  strb	r6, \[r4\] ; struct offset PktPayload_VersionInquiry.field_0
  mov	r2, r4
  mov	r1, r5
  pop.w	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){3,5}), lr}
  movs	r3, #(?P<packet_payload_len>[0-9a-fx]+) ; payload_len is 0x1e in v01.07 and 0x22 in v01.11
  ldr	r0, \[pc, #(?P<packet_send>[0-9a-fx]+)\]
  b.w	#(?P<packet_make_response>[0-9a-fx]+)
""",
'vars': {
  'cmd_exec_set00_cmd01b':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_8012360':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_8012372':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'get_board_version':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_make_response':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_send':	{'type': VarType.RELATIVE_ADDR_TO_CODE, 'baseaddr': "PC+", 'variety': CodeVariety.FUNCTION},
  'packet_payload_len':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT16_T,},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regB':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regC':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'regD':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'undefined_varlen_1':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (3,20)},
  'undefined_varlen_2':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,6)},
  'undefined_varlen_3':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT16_T, 'array': (1,4)},
  'loc_8011F26':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_8011F32':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_8011F5C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_8011F6A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_8011F72':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_8011F76':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'dword_200000F8':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T},
  'dword_200000FC':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T},
  'lb_mcu_version_1':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "mcu_firmware_version", 'getter': version_string_to_int_getter},
  'mcu_firmware_version':	{'type': VarType.DETACHED_DATA, 'variety': DataVariety.CHAR, 'array': 11,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "00.00.00.00", 'maxValue': "99.99.99.99",
    'depend': "lb_mcu_version_1", 'getter': version_int_to_string_getter, 'forceVisible': True,
    'description': "Firmware version number"},
},
}

re_func_cmd_exec_set00_cmd01_C1_V01_04_m1400 = {
'name': "cmd_exec_set00_cmd01",
'version': "C1_FW_V01.04-m1400",
'alt_name': "cmd_exec_set00_cmd01b",
're': """
cmd_exec_set00_cmd01:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){3,5}), lr}
  ldr	r1, \[pc, #(?P<dword_10007F74>[0-9a-fx]+)\]
  mov	r4, r0
  ldrb	r0, \[r0, #8\]
  ldr	r5, \[r1\]
  ubfx	r1, r0, #5, #2
  sub	sp, #0x50
  cmp	r1, #2
  bne	#(?P<loc_F3B6>[0-9a-fx]+)
  orr	r0, r0, #0x80
  strb	r0, \[r4, #8\]
  movs	r6, #0
  strb.w	r6, \[sp\] ; payload_buf + struct offset PktPayload_VersionInquiry.field_0
  ldrb.w	r0, \[sp, #1\] ; payload_buf + struct offset PktPayload_VersionInquiry.field_1
  movs	r1, #0x10
  bic	r0, r0, #0xf0
  adds	r0, #0x10
  bic	r0, r0, #0xf
  strb.w	r0, \[sp, #1\] ; payload_buf + struct offset PktPayload_VersionInquiry.field_1
  add.w	r0, sp, #2 ; payload_buf + struct offset PktPayload_VersionInquiry.hw_version
  bl	#(?P<sub_1F904>[0-9a-fx]+)
  ldrb	r0, \[r4, #5\]
  and	r0, r0, #0x1f
  cmp	r0, #0x14
  beq	#(?P<loc_F346>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<dword_10007F74>[0-9a-fx]+)\]
  mvns	r1, r5
  subs	r0, r0, #4
  ldr	r0, \[r0\]
  str.w	r0, \[sp, #0x12\] ; payload_buf + struct offset PktPayload_VersionInquiry.ldr_version
  cmp	r0, r1
  beq	#(?P<loc_F368>[0-9a-fx]+)
  str.w	r6, \[sp, #0x12\] ; payload_buf + struct offset PktPayload_VersionInquiry.ldr_version
  b	#(?P<loc_F390>[0-9a-fx]+)
loc_F346:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cbz	r0, #(?P<loc_F35E>[0-9a-fx]+)
  ldr	r0, \[pc, #(?P<dword_10000344>[0-9a-fx]+)\]
  ldr	r0, \[r0\]
  str.w	r0, \[sp, #0x12\] ; payload_buf + struct offset PktPayload_VersionInquiry.ldr_version
  ldr	r0, \[pc, #(?P<dword_10000348>[0-9a-fx]+)\]
  ldr	r0, \[r0\]
loc_F358:
  str.w	r0, \[sp, #0x16\] ; payload_buf + struct offset PktPayload_VersionInquiry.app_version
  b	#(?P<loc_F39C>[0-9a-fx]+)
loc_F35E:
  mvn	r0, #1
  str.w	r0, \[sp, #0x12\] ; payload_buf + struct offset PktPayload_VersionInquiry.ldr_version
  b	#(?P<loc_F358>[0-9a-fx]+)
loc_F368:
  ldr	r0, \[pc, #(?P<byte_10000000>[0-9a-fx]+)\]
  ldrb	r1, \[r0\]
  ldr	r0, \[pc, #(?P<byte_10000006>[0-9a-fx]+)\]
  cbz	r1, #(?P<loc_F376>[0-9a-fx]+)
  ldrb	r1, \[r0\]
  cmp	r1, #3
  beq	#(?P<loc_F3BA>[0-9a-fx]+)
loc_F376:
  ldr	r2, \[pc, #(?P<byte_10000008>[0-9a-fx]+)\]
  ldr.w	r1, \[sp, #0x12\] ; payload_buf + struct offset PktPayload_VersionInquiry.ldr_version
  ldrb	r0, \[r0\]
  ldrb	r2, \[r2\]
  and	r1, r1, #0xff00ff
  orr.w	r1, r1, r2, lsl #24
  orr.w	r0, r1, r0, lsl #8
loc_F38C:
  str.w	r0, \[sp, #0x12\] ; payload_buf + struct offset PktPayload_VersionInquiry.ldr_version
loc_F390:
  ldr	r0, \[pc, #(?P<lb_mcu_version_1>[0-9a-fx]+)\]
  str.w	r0, \[sp, #0x16\] ; payload_buf + struct offset PktPayload_VersionInquiry.app_version
  movs	r0, #1
  strb.w	r0, \[sp, #0x1e\] ; payload_buf + struct offset PktPayload_VersionInquiry.field_1E
loc_F39C:
  movw	r0, #0x243
  str.w	r0, \[sp, #0x1a\] ; payload_buf + struct offset PktPayload_VersionInquiry.field_1A
  add	r3, sp, #0x20
  movs	r2, #(?P<packet_payload_len>[0-9a-fx]+) ; sizeof(PktPayload_VersionInquiry)
  mov	r1, sp
  mov	r0, r4
  bl	#(?P<packet_prepare_response>[0-9a-fx]+)
  add	r0, sp, #0x20
  bl	#(?P<packet_send>[0-9a-fx]+)
loc_F3B6:
  add	sp, #0x50
  pop	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){3,5}), pc}
loc_F3BA:
  ldr.w	r0, \[sp, #0x12\] ; payload_buf + struct offset PktPayload_VersionInquiry.ldr_version
  and	r0, r0, #0xff00ff
  orr	r0, r0, #0x3000300
  b	#(?P<loc_F38C>[0-9a-fx]+)
""",
'vars': {
  'cmd_exec_set00_cmd01':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_1F904':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'get_board_version':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_prepare_response':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_send':	{'type': VarType.RELATIVE_ADDR_TO_CODE, 'baseaddr': "PC+", 'variety': CodeVariety.FUNCTION},
  'packet_payload_len':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT16_T,},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'loc_F346':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_F358':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_F35E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_F368':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_F376':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_F38C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_F390':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_F39C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_F3B6':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_F3BA':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'dword_10007F74':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T},
  'dword_10000344':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T},
  'dword_10000348':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T},
  'byte_10000000':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT8_T},
  'byte_10000006':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT8_T},
  'byte_10000008':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.UINT8_T},
  'lb_mcu_version_1':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "mcu_firmware_version", 'getter': version_string_to_int_getter},
  'mcu_firmware_version':	{'type': VarType.DETACHED_DATA, 'variety': DataVariety.CHAR, 'array': 11,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "00.00.00.00", 'maxValue': "99.99.99.99",
    'depend': "lb_mcu_version_1", 'getter': version_int_to_string_getter, 'forceVisible': True,
    'description': "Firmware version number"},
},
}

re_func_cmd_exec_set00_cmd01_C1_V01_04_m1401 = {
'name': "cmd_exec_set00_cmd01",
'version': "C1_FW_V01.04-m1401",
'alt_name': "cmd_exec_set00_cmd01b",
're': """
cmd_exec_set00_cmd01:
  push	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){3,5}), lr}
  sub	sp, #0x50
  mov	r5, r0
  ldr	r0, \[pc, #(?P<dword_10007F74>[0-9a-fx]+)\]
  ldr	r6, \[r0\]
  mov	r4, r5
  ldrb	r0, \[r4, #8\]
  ubfx	r0, r0, #5, #2
  cmp	r0, #2
  bne	#(?P<loc_F3B6>[0-9a-fx]+)
  ldrb	r0, \[r4, #8\]
  bic	r0, r0, #0x80
  adds	r0, #0x80
  strb	r0, \[r4, #8\]
  movs	r0, #0
  strb.w	r0, \[sp, #0x30\] ; payload_buf + struct offset PktPayload_VersionInquiry.field_0
  ldrb.w	r0, \[sp, #0x31\] ; payload_buf + struct offset PktPayload_VersionInquiry.field_1
  bic	r0, r0, #0xf0
  adds	r0, #0x10
  strb.w	r0, \[sp, #0x31\] ; payload_buf + struct offset PktPayload_VersionInquiry.field_1
  ldrb.w	r0, \[sp, #0x31\] ; payload_buf + struct offset PktPayload_VersionInquiry.field_1
  bic	r0, r0, #0xf
  strb.w	r0, \[sp, #0x31\] ; payload_buf + struct offset PktPayload_VersionInquiry.field_1
  movs	r1, #0x10
  add.w	r0, sp, #0x32 ; payload_buf + struct offset PktPayload_VersionInquiry.hw_version
  bl	#(?P<sub_1F904>[0-9a-fx]+)
  ldrb	r0, \[r4, #5\]
  and	r0, r0, #0x1f
  cmp	r0, #0x14
  bne	#(?P<loc_F376>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cbnz	r0, #(?P<loc_F346>[0-9a-fx]+)
  mvn	r0, #1
  str.w	r0, \[sp, #0x42\] ; payload_buf + struct offset PktPayload_VersionInquiry.ldr_version
  str.w	r0, \[sp, #0x46\] ; payload_buf + struct offset PktPayload_VersionInquiry.app_version
  b	#(?P<loc_F39C>[0-9a-fx]+)
loc_F346:
  ldr	r0, \[pc, #(?P<dword_10000344>[0-9a-fx]+)\]
  ldr	r0, \[r0\]
  str.w	r0, \[sp, #0x42\] ; payload_buf + struct offset PktPayload_VersionInquiry.ldr_version
  ldr	r0, \[pc, #(?P<dword_10000348>[0-9a-fx]+)\]
  ldr	r0, \[r0\]
  str.w	r0, \[sp, #0x46\] ; payload_buf + struct offset PktPayload_VersionInquiry.app_version
  b	#(?P<loc_F39C>[0-9a-fx]+)
loc_F376:
  ldr	r0, \[pc, #(?P<dword_10007F74>[0-9a-fx]+)\]
  subs	r0, r0, #4
  ldr	r0, \[r0\]
  str.w	r0, \[sp, #0x42\] ; payload_buf + struct offset PktPayload_VersionInquiry.ldr_version
  ldr.w	r0, \[sp, #0x42\] ; payload_buf + struct offset PktPayload_VersionInquiry.ldr_version
  mvns	r1, r6
  cmp	r0, r1
  beq	#(?P<loc_F390>[0-9a-fx]+)
  movs	r0, #0
  str.w	r0, \[sp, #0x42\] ; payload_buf + struct offset PktPayload_VersionInquiry.ldr_version
loc_F390:
  ldr	r0, \[pc, #(?P<lb_mcu_version_1>[0-9a-fx]+)\]
  str.w	r0, \[sp, #0x46\] ; payload_buf + struct offset PktPayload_VersionInquiry.app_version
  movs	r0, #1
  strb.w	r0, \[sp, #0x4e\] ; payload_buf + struct offset PktPayload_VersionInquiry.field_1E
loc_F39C:
  movw	r0, #0x243
  str.w	r0, \[sp, #0x4a\] ; payload_buf + struct offset PktPayload_VersionInquiry.field_1A
  add	r3, sp, #4 ; local resp_pkt
  movs	r2, #(?P<packet_payload_len>[0-9a-fx]+) ; sizeof(PktPayload_VersionInquiry)
  add	r1, sp, #0x30 ; payload_buf
  mov	r0, r4
  bl	#(?P<packet_prepare_response>[0-9a-fx]+)
  add	r0, sp, #4 ; local resp_pkt
  bl	#(?P<packet_send>[0-9a-fx]+)
loc_F3B6:
  add	sp, #0x50
  pop	{(?P<regsA>(r[0-9]+[, ]*|[a-z][a-z][, ]*){3,5}), pc}
""",
'vars': {
  'cmd_exec_set00_cmd01':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_1F904':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'get_board_version':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_prepare_response':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_send':	{'type': VarType.RELATIVE_ADDR_TO_CODE, 'baseaddr': "PC+", 'variety': CodeVariety.FUNCTION},
  'packet_payload_len':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.UINT16_T,},
  'regsA':	{'type': VarType.DIRECT_OPERAND, 'variety': DataVariety.UNKNOWN},
  'loc_F346':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_F376':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_F390':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_F39C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_F3B6':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'dword_10007F74':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T},
  'dword_10000344':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T},
  'dword_10000348':	{'type': VarType.RELATIVE_ADDR_TO_PTR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T},
  'lb_mcu_version_1':	{'type': VarType.RELATIVE_ADDR_TO_GLOBAL_DATA, 'baseaddr': "PC+", 'variety': DataVariety.INT32_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "mcu_firmware_version", 'getter': version_string_to_int_getter},
  'mcu_firmware_version':	{'type': VarType.DETACHED_DATA, 'variety': DataVariety.CHAR, 'array': 11,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "00.00.00.00", 'maxValue': "99.99.99.99",
    'depend': "lb_mcu_version_1", 'getter': version_int_to_string_getter, 'forceVisible': True,
    'description': "Firmware version number"},
},
}


re_general_list = [
  {'sect': ".text", 'func': re_func_cmd_exec_set09_cmd12_P3X_V01_07_original,},
  {'sect': ".text", 'func': re_func_cmd_exec_set09_cmd12_P3X_V01_07_constatt,},
  {'sect': ".text", 'func': re_func_cmd_exec_set09_cmd12_C1_V01_04_m1400_original,},
  {'sect': ".text", 'func': re_func_cmd_exec_set09_cmd12_C1_V01_04_m1400_constatt,},
  {'sect': ".text", 'func': re_func_init_fpga_config_P3X_V01_01,},
  {'sect': ".text", 'func': re_func_init_fpga_config_P3X_V01_05,},
  {'sect': ".text", 'func': re_func_init_fpga_config_P3X_V01_08,},
  {'sect': ".text", 'func': re_func_init_fpga_config_C1_V01_03_m1400,},
  {'sect': ".text", 'func': re_func_init_fpga_config_C1_V01_05_m1400,},
  {'sect': ".text", 'func': re_func_init_fpga_config_C1_V01_05_m1401,},
  {'sect': ".text", 'func': re_func_tcx_config_update1_P3X_V01_04,},
  {'sect': ".text", 'func': re_func_tcx_config_update1_P3X_V01_05,},
  {'sect': ".text", 'func': re_func_tcx_config_update1_P3X_V01_08,},
  {'sect': ".text", 'func': re_func_tcx_config_update1_C1_V01_03_m1400,},
  {'sect': ".text", 'func': re_func_tcx_config_update1_C1_V01_04_m1400,},
  {'sect': ".text", 'func': re_func_tcx_config_update1_C1_V01_06_m1400,},
  {'sect': ".text", 'func': re_func_tcx_config_update1_C1_V01_05_m1401,},
  {'sect': ".text", 'func': re_func_tcx_config_update1_C1_V01_06_m1401,},
  {'sect': ".text", 'func': re_func_tcx_config_power_zone_P3X_V01_08,},
  {'sect': ".text", 'func': re_func_update_tcx_power_zone_flag_C1_V01_05_m1400_original,},
  {'sect': ".text", 'func': re_func_update_tcx_power_zone_flag_C1_V01_05_m1400_setfcc,},
  {'sect': ".text", 'func': re_func_update_tcx_power_zone_flag_C1_V01_05_m1401_original,},
  {'sect': ".text", 'func': re_func_update_tcx_power_zone_flag_C1_V01_05_m1401_setfcc,},
  {'sect': ".text", 'func': re_func_cmd_exec_set00_cmd01b_P3X_V01_04,},
  {'sect': ".text", 'func': re_func_cmd_exec_set00_cmd01b_P3X_V01_08,},
  {'sect': ".text", 'func': re_func_cmd_exec_set00_cmd01_C1_V01_04_m1400,},
  {'sect': ".text", 'func': re_func_cmd_exec_set00_cmd01_C1_V01_04_m1401,},
]

def armfw_elf_lbstm32_list(po, elffh):
    params_list, _, _, _, _, _ = armfw_elf_paramvals_extract_list(po, elffh, re_general_list, 'thumb')
    # print list of parameter values
    armfw_elf_paramvals_export_simple_list(po, params_list, sys.stdout)


def armfw_elf_lbstm32_mapfile(po, elffh):
    _, params_list, elf_sections, _, _, asm_arch = armfw_elf_paramvals_extract_list(po, elffh, re_general_list, 'thumb')
    armfw_elf_paramvals_export_mapfile(po, params_list, elf_sections, asm_arch, sys.stdout)


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

        armfw_elf_lbstm32_list(po, elffh)

        elffh.close();

    elif po.mapfile:

        if (po.verbose > 0):
            print("{}: Opening for mapfile generation".format(po.elffile))

        elffh = open(po.elffile, "rb")

        armfw_elf_lbstm32_mapfile(po, elffh)

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
    try:
        main()
    except Exception as ex:
        eprint("Error: "+str(ex))
        #raise
        sys.exit(10)
