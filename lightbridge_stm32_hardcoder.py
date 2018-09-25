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
  armfw_elf_generic_objdump, VarType, DataVariety, CodeVariety


re_func_cmd_exec_set09_cmd12_original = {
'name': "cmd_exec_set09_cmd12-original",
're': """
cmd_exec_set09_cmd12:
  push	{r3, r4, r5, lr}
  mov	r5, r0
  movs	r0, #0
  strb.w	r0, \[sp\]
  add.w	r4, r5, #0xb
  bl	#(?P<tcx_config_80105FA>[0-9a-fx]+)
  ldrb	r0, \[r4\]
  lsls	r0, r0, #0x18
  bmi	#(?P<loc_label01>[0-9a-fx]+)
  movs	r0, #0
  bl	#(?P<set_transciever_flag_20001A28_E>[0-9a-fx]+)
  b	#(?P<loc_label02>[0-9a-fx]+)
loc_label01:
  movs	r0, #1
  bl	#(?P<set_transciever_flag_20001A28_E>[0-9a-fx]+)
  ldrb	r0, \[r4\]
  and	r0, r0, #0x7f
  bl	#(?P<set_transciever_flag_20001A28_D>[0-9a-fx]+)
loc_label02:
  ldrb	r0, \[r4, #1\]
  lsrs	r0, r0, #6
  bl	#(?P<set_transciever_flag_20001A28_A>[0-9a-fx]+)
  ldrb	r0, \[r4, #1\]
  and	r0, r0, #0x3f
  bl	#(?P<set_transciever_flag_20001A28_B>[0-9a-fx]+)
  ldrb	r0, \[r4, #2\]
  bl	#(?P<set_transciever_attenuation>[0-9a-fx]+)
  ldrb	r0, \[r4, #3\]
  bl	#(?P<set_transciever_flag_20001A28_C>[0-9a-fx]+)
  movs	r3, #1
  mov	r2, sp
  mov	r1, r5
  ldr	r0, \[pc, #0x124\] ; func packet_send
  bl	#(?P<packet_make_response>[0-9a-fx]+)
  pop	{r3, r4, r5, pc}
""",
'vars': {
  'cmd_exec_set09_cmd12':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_received_attenuation_override':	{'type': VarType.DETACHED_DATA, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "-1", 'maxValue': "255", 'defaultValue': "-1", 'setValue': "-1",
    'description': "When received a packet with power set request, override the received value with constant one; -1 - use value from packet, >=0 - override with given value"},
  'loc_label01':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label02':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'tcx_config_80105FA':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_B':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_D':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_attenuation':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_make_response':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
},
}

re_func_cmd_exec_set09_cmd12_constatt = {
'name': "cmd_exec_set09_cmd12-constatt",
're': """
cmd_exec_set09_cmd12:
  push	{r3, r4, r5, lr}
  mov	r5, r0
  movs	r0, #0
  strb.w	r0, \[sp\]
  add.w	r4, r5, #0xb
  bl	#(?P<tcx_config_80105FA>[0-9a-fx]+)
  ldrb	r0, \[r4\]
  lsls	r0, r0, #0x18
  bmi	#(?P<loc_label01>[0-9a-fx]+)
  movs	r0, #0
  bl	#(?P<set_transciever_flag_20001A28_E>[0-9a-fx]+)
  b	#(?P<loc_label02>[0-9a-fx]+)
loc_label01:
  movs	r0, #1
  bl	#(?P<set_transciever_flag_20001A28_E>[0-9a-fx]+)
  ldrb	r0, \[r4\]
  and	r0, r0, #0x7f
  bl	#(?P<set_transciever_flag_20001A28_D>[0-9a-fx]+)
loc_label02:
  ldrb	r0, \[r4, #1\]
  lsrs	r0, r0, #6
  bl	#(?P<set_transciever_flag_20001A28_A>[0-9a-fx]+)
  ldrb	r0, \[r4, #1\]
  and	r0, r0, #0x3f
  bl	#(?P<set_transciever_flag_20001A28_B>[0-9a-fx]+)
  ldrb	r0, #(?P<packet_received_attenuation_override>[0-9a-fx]+)
  bl	#(?P<set_transciever_attenuation>[0-9a-fx]+)
  ldrb	r0, \[r4, #3\]
  bl	#(?P<set_transciever_flag_20001A28_C>[0-9a-fx]+)
  movs	r3, #1
  mov	r2, sp
  mov	r1, r5
  ldr	r0, \[pc, #0x124\] ; func packet_send
  bl	#(?P<packet_make_response>[0-9a-fx]+)
  pop	{r3, r4, r5, pc}
""",
'vars': {
  'cmd_exec_set09_cmd12':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_received_attenuation_override':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "-1", 'maxValue': "255", 'defaultValue': "-1",
    'description': "When received a packet with power set request, override the received value with constant one; -1 - use value from packet, >=0 - override with given value"},
  'loc_label01':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label02':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'tcx_config_80105FA':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_A':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_B':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_C':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_D':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_flag_20001A28_E':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'set_transciever_attenuation':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'packet_make_response':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
},
}

re_func_tcx_config_power_zone = {
'name': "tcx_config_power_zone",
're': """
tcx_config_power_zone:
  ldr	r1, \[pc, #0x170\]
  push	{r4, lr}
  ldrb	r2, \[r1, #0x12\]
  cmp	r0, r2
  beq	#(?P<loc_label16>[0-9a-fx]+)
  strb	r0, \[r1, #0x12\]
  cbz	r0, #(?P<loc_label01>[0-9a-fx]+)
  cmp	r0, #1
  bne	#(?P<loc_label16>[0-9a-fx]+)
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
  beq	#(?P<loc_label02>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  beq	#(?P<loc_label03>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_label05>[0-9a-fx]+)
  b	#(?P<loc_label07>[0-9a-fx]+)
loc_label02:
  movs	r2, #0
  movs	r1, #(?P<board_ad4_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad4_attenuation_tx2_ce>[0-9a-fx]+)
  b	#(?P<loc_label04>[0-9a-fx]+)
loc_label03:
  movs	r2, #0
  movs	r1, #(?P<board_ad5_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad5_attenuation_tx2_ce>[0-9a-fx]+)
loc_label04:
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
  b	#(?P<loc_label06>[0-9a-fx]+)
loc_label05:
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
  beq	#(?P<loc_label08>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  bne	#(?P<loc_label_ret1>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #(?P<board_ad2_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x73 ; AD9363_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ad2_attenuation_tx2_ce>[0-9a-fx]+)
  b	#(?P<loc_label14>[0-9a-fx]+)
loc_label08:
  movs	r2, #0
  movs	r1, #(?P<board_ar7_attenuation_tx1_ce>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar7_attenuation_tx2_ce>[0-9a-fx]+)
  b	#(?P<loc_label19>[0-9a-fx]+)
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
loc_label14:
  movs	r0, #0x75 ; AD9363_REG_TX2_ATTEN_0
loc_label15:
  pop.w	{r4, lr}
  b	#(?P<loc_j_ad936x_reg_sync_write>[0-9a-fx]+)
loc_label16:
  b	#(?P<loc_label_ret1>[0-9a-fx]+)
loc_j_ad936x_reg_sync_write:
  b.w	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
loc_label18:
  movs	r2, #0
  movs	r1, #(?P<board_ar7_attenuation_tx1_fcc>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #1
  movs	r1, #(?P<board_ar7_attenuation_tx2_fcc>[0-9a-fx]+)
loc_label19:
  movs	r0, #0x5c ; AR8003_REG_TX2_ATTEN_0
  b	#(?P<loc_label15>[0-9a-fx]+)
loc_label_ret1:
  pop	{r4, pc}
""",
'vars': {
  'tcx_config_power_zone':	{'type': VarType.DIRECT_LINE_OF_CODE, 'variety': CodeVariety.FUNCTION},
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
  'loc_label11':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label12':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label13':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label14':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label15':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label16':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label17':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_j_ad936x_reg_sync_write':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label18':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label19':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'get_board_version':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'ad936x_reg_sync_write':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'board_ad4_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "50",
    'description': "Transceiver attenuation value for board type 4 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad4_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "44",
    'description': "Transceiver attenuation value for board type 4 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad5_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "44",
    'description': "Transceiver attenuation value for board type 5 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad5_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "45",
    'description': "Transceiver attenuation value for board type 5 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ar6_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "20",
    'description': "Transceiver attenuation value for board type 6 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar6_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "20",
    'description': "Transceiver attenuation value for board type 6 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar7_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "12",
    'description': "Transceiver attenuation value for board type 7 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar7_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "12",
    'description': "Transceiver attenuation value for board type 7 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ad2_attenuation_tx1_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "44",
    'description': "Transceiver attenuation value for board type 2 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad2_attenuation_tx2_ce':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "45",
    'description': "Transceiver attenuation value for board type 2 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad4_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "10",
    'description': "Transceiver attenuation value for board type 4 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad4_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "4",
    'description': "Transceiver attenuation value for board type 4 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad5_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "4",
    'description': "Transceiver attenuation value for board type 5 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad5_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "5",
    'description': "Transceiver attenuation value for board type 5 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ar6_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "10",
    'description': "Transceiver attenuation value for board type 6 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar6_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "10",
    'description': "Transceiver attenuation value for board type 6 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar7_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "2",
    'description': "Transceiver attenuation value for board type 7 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ar7_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "63", 'defaultValue': "2",
    'description': "Transceiver attenuation value for board type 7 with Artosyn chip, change by 1 means 1 dBm"},
  'board_ad2_attenuation_tx1_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "4",
    'description': "Transceiver attenuation value for board type 2 with Analog Devices chip, change by 1 means 0.25 dBm"},
  'board_ad2_attenuation_tx2_fcc':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'minValue': "0", 'maxValue': "255", 'defaultValue': "5",
    'description': "Transceiver attenuation value for board type 2 with Analog Devices chip, change by 1 means 0.25 dBm"},
},
}


re_func_init_fpga_config = {
'name': "init_fpga_config",
're': """
init_fpga_config:
  push.w	{r4, r5, r6, r7, r8, sb, sl, lr}
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
  beq	#(?P<loc_label04>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  beq	#(?P<loc_label04>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #2
  beq	#(?P<loc_label04>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #6
  beq	#(?P<loc_label05>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #7
  beq	#(?P<loc_label05>[0-9a-fx]+)
  b	#(?P<loc_label07>[0-9a-fx]+)
loc_label04:
  ldr	r0, \[pc, #0x2e4\]
  b	#(?P<loc_label06>[0-9a-fx]+)
loc_label05:
  ldr	r0, \[pc, #0x2e4\]
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
  bl	#(?P<sub_800D32C>[0-9a-fx]+)
  b	#(?P<loc_label08>[0-9a-fx]+)
loc_label12:
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #4
  beq	#(?P<loc_label13>[0-9a-fx]+)
  bl	#(?P<get_board_version>[0-9a-fx]+)
  cmp	r0, #5
  bne	#(?P<loc_label15>[0-9a-fx]+)
loc_label13:
  ldr	r0, \[pc, #0x274\]
  ldr	r1, \[pc, #0x274\]
  ldr	r0, \[r0\]
  cmp	r0, r1
  bne	#(?P<loc_label15>[0-9a-fx]+)
  ldr	r5, \[pc, #0x270\]
  movs	r4, #0
loc_label14:
  adds	r0, r5, r4
  adds	r4, r4, #4
  bl	#(?P<sub_800D32C>[0-9a-fx]+)
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
  movs	r0, #0x17
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
  bl	#(?P<sub_800D3E4>[0-9a-fx]+)
  movs	r0, #0x20
  bl	#(?P<spi_fpga_raw_read>[0-9a-fx]+)
  orr	r1, r0, #0xc
  movs	r0, #0x20 ; FPGA_REG_UNKN_20
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<sub_800D3E4>[0-9a-fx]+)
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
  bl	#(?P<sub_800D3E4>[0-9a-fx]+)
  movs	r1, #0xa
  movs	r0, #0xce ; FPGA_REG_UNKN_CE
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<sub_800D3E4>[0-9a-fx]+)
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
  b	#(?P<loc_label33>[0-9a-fx]+)
loc_label29:
  b	#(?P<loc_label34>[0-9a-fx]+)
loc_label30:
  movs	r0, #1
  bl	#(?P<sub_800D3E4>[0-9a-fx]+)
  movs	r1, #2
  movs	r0, #0xce ; FPGA_REG_UNKN_CE
  bl	#(?P<spi_fpga_raw_write>[0-9a-fx]+)
  movs	r0, #2
  bl	#(?P<sub_800D3E4>[0-9a-fx]+)
  movs	r2, #0
  movs	r1, #(?P<board_ar7_attenuation_tx1_init>[0-9a-fx]+)
  movs	r0, #0x54 ; AR8003_REG_TX1_ATTEN_0
  bl	#(?P<ad936x_reg_sync_write>[0-9a-fx]+)
  movs	r2, #0
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
  pop.w	{r4, r5, r6, r7, r8, sb, sl, pc}
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
  'sub_800D32C':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_800D3E4':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_800D414':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_800D7B8':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
  'sub_800C1E4':		{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.FUNCTION},
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
  'loc_label33':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label34':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'loc_label_ret1':	{'type': VarType.ABSOLUTE_ADDR_TO_CODE, 'variety': CodeVariety.CHUNK},
  'board_ad4_attenuation_tx1_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad4_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ad4_attenuation_tx2_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad4_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ad5_attenuation_tx1_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad5_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ad5_attenuation_tx2_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad5_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ar6_attenuation_tx1_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar6_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ar6_attenuation_tx2_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar6_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ar7_attenuation_tx1_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar7_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ar7_attenuation_tx2_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ar7_attenuation_tx2_fcc", 'getter': (lambda val: val)},
  'board_ad2_attenuation_tx1_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad2_attenuation_tx1_fcc", 'getter': (lambda val: val)},
  'board_ad2_attenuation_tx2_init':	{'type': VarType.DIRECT_INT_VALUE, 'variety': DataVariety.INT8_T,
    'public': "og_hardcoded.lightbridge_stm32", 'depend': "board_ad2_attenuation_tx2_fcc", 'getter': (lambda val: val)},
},
}

re_general_list = [
  {'sect': ".text", 'func': re_func_cmd_exec_set09_cmd12_original,},
  {'sect': ".text", 'func': re_func_cmd_exec_set09_cmd12_constatt,},
  {'sect': ".text", 'func': re_func_tcx_config_power_zone,},
  {'sect': ".text", 'func': re_func_init_fpga_config,},
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
    update_count = 0
    for nxpar in nxparams_list:
        if not nxpar['name'] in pub_params_list:
            eprint("{:s}: Value '{:s}' not found in ELF file.".format(po.elffile,nxpar['name']))
            continue
        par_info = pub_params_list[nxpar['name']]
        update_performed = armfw_elf_publicval_update(po, asm_arch, elf_sections, re_general_list, glob_params_list, par_info, nxpar['setValue'])
        if update_performed:
            depparams_list = armfw_elf_paramvals_get_depend_list(glob_params_list, par_info, nxpar['setValue'])
            for deppar in depparams_list:
                update_performed = armfw_elf_publicval_update(po, asm_arch, elf_sections, re_general_list, glob_params_list, deppar, deppar['setValue'])
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
