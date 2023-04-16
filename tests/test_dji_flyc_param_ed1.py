# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, dji_flyc_param_ed script.

    This test verifies functions of the script by extracting the
    array of parameters from BIN module, applying modifications, and
    re-applying them, finally checking if the resulting files have
    expected amount of changes.

    This test requires modules to already be extracted from their
    packages.
"""

# Copyright (C) 2023 Mefistotelis <mefistotelis@gmail.com>
# Copyright (C) 2023 Original Gangsters <https://dji-rev.slack.com/>
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

import filecmp
import glob
import itertools
import json
import logging
import mmap
import os
import re
import shlex
import shutil
import sys
import pathlib
import pytest
from unittest.mock import patch

# Import the functions to be tested
sys.path.insert(0, './')
import filediff
from dji_flyc_param_ed import main as dji_flyc_param_ed_main


LOGGER = logging.getLogger(__name__)


def is_module_unsigned_encrypted(modl_inp_fn):
    """ Identify if the module was extracted without full decryption.
        If the module data is encrypted, invoking further tests on it makes no sense.
    """
    match = re.search(r'^(.*)_m?([0-9A-Z]{4})[.]bin$', modl_inp_fn, flags=re.IGNORECASE)
    if not match:
        return False
    modl_part_fn = match.group(1)
    modl_ini_fn = "{:s}_head.ini".format(modl_part_fn)
    try:
        with open(modl_ini_fn, 'rb') as fh:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            return mm.find(b"scramble_key_encrypted") != -1
    except Exception as e:
        LOGGER.info("Could not check INI for: {:s}".format(modl_inp_fn))
        return False


def get_params_for_dji_flyc_param_ed(modl_inp_fn):
    """ From given module file name, figure out required dji_flyc_param_ed cmd options.
    """
    module_cmdopts = ""
    expect_json_changes = 99
    if (modl_inp_fn.endswith("_m0306.bin")):
        if (m := re.match(r'^.*(A3)_FW_V01[.]00[.]00[.]32[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            # AI900 FW masquerading as A3
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 25
        elif (m := re.match(r'^.*(A3)_FW_[A-Z0-9]+_V01[.]00[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            # version incompletely labelled, the FUCHONG9 files seem to be circa V01.07
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 28
        elif (m := re.match(r'^.*(A3)_FW_V01[.]00[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            # ie. A3_FW_V01.00.00.99
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 28
        elif (m := re.match(r'^.*(A3)_FW_V01[.]0[2-3][0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 37
        elif (m := re.match(r'^.*(A3)_FW_V01[.]06[.]00[.]10[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            # AI900 FW masquerading as A3
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 25
        elif (m := re.match(r'^.*(A3)_FW_V01[.]0[4-6][0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 26
        elif (m := re.match(r'^.*(A3)_FW_V01[.]07[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            # ie. A3_FW_V01.07.00.03tx
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 25
        elif (m := re.match(r'^.*(A3)_OFFICAL_1_7_5[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 28
        elif (m := re.match(r'^.*(A3)_OFFICAL_1_7_6[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 21
        elif (m := re.match(r'^.*(A3)_FW_V[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 36
        elif (m := re.match(r'^.*(AI900|AI900_AGR|A3[_]?AGR)_FW_V[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            # ie. A3AGR_FW_V01.00.01.05
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 25
        elif (m := re.match(r'^.*(AM603|N3_AGR)_FW_V[()0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            # ie. AM603_FW_V01.00.00.43
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 26
        elif (m := re.match(r'^.*(MATRICE100)_FW_V[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x8020000"
            expect_json_changes = 37
        elif (m := re.match(r'^.*(MATRICE600)_FW_V01[.]00[.]00[.]([0-3][0-9]|[4][0-3])[()0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 37
        elif (m := re.match(r'^.*(MATRICE600|MATRICE600PRO)_FW_V01[.]00[.]00[.]([4][4-9]|[5-7][0-9])[()0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            # ie. MATRICE600_FW_V01.00.00.44
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 25
        elif (m := re.match(r'^.*(MATRICE600|MATRICE600PRO)_FW_V01[.]00[()0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            # ie. MATRICE600_FW_V01.00.00.80
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 24
        elif (m := re.match(r'^.*(MATRICE600|MATRICE600PRO)_FW_V02[.]00[.]00[.]9[0-9][()0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            # ie. MATRICE600_FW_V02.00.00.95
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 25
        elif (m := re.match(r'^.*(MATRICE600|MATRICE600PRO)_FW_V[()0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 37
        elif (m := re.match(r'^.*(MG1S)_FW_V01[.]01[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            # ie. MG1S_FW_V01.01.00.00
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 25
        elif (m := re.match(r'^.*(MG1S)_FW_V[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            # ie. MG1S_FW_V01.00.00.02
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 27
        elif (m := re.match(r'^.*(MG1S)_V[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 20
        elif (m := re.match(r'^.*(N3)_FW_V01[.](00[.]01[.]01|01[.]01[.]00)[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 25
        elif (m := re.match(r'^.*(N3)_FW_V01[.]07[.]00[.]0[0-5][0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            # ie. N3_FW_V01.07.00.00
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 25
        elif (m := re.match(r'^.*(N3)_FW_V01[.]00[.]00[.][0-1][0-9][0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            # ie. N3_FW_V01.00.00.01
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 28
        elif (m := re.match(r'^.*(N3)_FW_V[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            # ie. N3_FW_V01.00.00.22
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 27
        elif (m := re.match(r'^.*(P3X|P3S)_FW_V01[.]0[0-1].0[0-9][0-9][0-9][0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x8020000"
            expect_json_changes = 16
        elif (m := re.match(r'^.*(P3X|P3S)_FW_V01[.]01.[1-9][0-9][0-9][0-9][0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x8020000"
            expect_json_changes = 33
        elif (m := re.match(r'^.*(P3X|P3S)_FW_V[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x8020000"
            expect_json_changes = 36
        elif (m := re.match(r'^.*(P3C|P3SE|P3XW)_FW_V[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x8020000"
            expect_json_changes = 42
        elif (m := re.match(r'^.*(WM610|WM610_FC550|WM610_FC350Z)_FW_V01[.]02[.]01[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x8020000"
            expect_json_changes = 14
        elif (m := re.match(r'^.*(WM610|WM610_FC550|WM610_FC350Z)_FW_V01[.]03[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x8020000"
            expect_json_changes = 42
        elif (m := re.match(r'^.*(WM610|WM610_FC550|WM610_FC350Z)_FW_V[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x8020000"
            expect_json_changes = 43
        else:
            platform = "unknown-xv4"
            module_cmdopts = ""
            expect_json_changes = 16

    elif (modl_inp_fn.endswith("_0306.decrypted.bin")):
        if (m := re.match(r'^.*(ag407)_0306_v[0-9a-z_.-]*_head[.][0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420180"
            expect_json_changes = 20
        elif (m := re.match(r'^.*(ag407)_0306_v[0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 20

        elif (m := re.match(r'^.*(ag408)_0306_v[0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420180"
            expect_json_changes = 21

        elif (m := re.match(r'^.*(ag410)_0306_v[0-9a-z_.-]*_fc00[.][0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 20
        elif (m := re.match(r'^.*(ag410)_0306_v[0-9a-z_.-]*_head[.][0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420180"
            expect_json_changes = 20 # from ag410_0306_v03.04.05.35_20191220_head
        elif (m := re.match(r'^.*(ag410)_0306_v[0-9a-z_.-]*_nk00[.][0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 4

        elif (m := re.match(r'^.*(pm410)_0306_v03[.]02[0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 31
        elif (m := re.match(r'^.*(pm410)_0306_v[0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 24 # from pm410_0306_v03.03.10.04

        elif (m := re.match(r'^.*(wm100)_0306_v[0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 29

        elif (m := re.match(r'^.*(wm220)_0306_v03[.]02[.][0-1][0-9][.][0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 28
        elif (m := re.match(r'^.*(wm220)_0306_v03[.]02[.][2-3][0-9][.][0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 30
        elif (m := re.match(r'^.*(wm220)_0306_v[0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 31

        elif (m := re.match(r'^.*(wm222)_0306_v[0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 29

        elif (m := re.match(r'^.*(wm330)_0306_v03[.]0[0-1][.][0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 39
        elif (m := re.match(r'^.*(wm330)_0306_v[0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 26

        elif (m := re.match(r'^.*(wm331)_0306_v03[.]02[.]1[2-5][0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 21
        elif (m := re.match(r'^.*(wm331)_0306_v[0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 24

        elif (m := re.match(r'^.*(wm332)_0306_v[0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 24

        elif (m := re.match(r'^.*(wm334)_0306_v[0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 17 # from wm334_0306_v03.03.06.57

        elif (m := re.match(r'^.*(wm335)_0306_v[0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 18 # from wm335_0306_v03.03.04.10

        elif (m := re.match(r'^.*(wm620)_0306_v03[.]02[0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 26 # from wm620_0306_v03.02.10.83
        elif (m := re.match(r'^.*(wm620)_0306_v03[.]03[.]09[0-9a-z_.-]*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 23 # from wm620_0306_v03.03.09.09

        else:
            platform = "unknown-imah"
            module_cmdopts = ""
            expect_json_changes = 16

    elif (modl_inp_fn.endswith("_FCFW.bin")):
        if (m := re.match(r'^.*(ag500|ag501|ag600|ag601)_0802_v[0-9a-z_.-]*_FCFW[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x00"
            expect_json_changes = 28

        elif (m := re.match(r'^.*(pm320)_0802_v[0-9a-z_.-]*_FCFW[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x00"
            expect_json_changes = 29

        elif (m := re.match(r'^.*(pm430)_0801_v[0-9a-z_.-]*_FCFW[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x00"
            expect_json_changes = 33

        elif (m := re.match(r'^.*(wm170)_0802_v[0-9a-z_.-]*_FCFW[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x00"
            expect_json_changes = 27

        elif (m := re.match(r'^.*(wm230)_0801_v[0-9a-z_.-]*_FCFW[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x00"
            expect_json_changes = 24

        elif (m := re.match(r'^.*(wm231|wm232|wm240|wm245|wm246|wm247)_0801_v[0-9a-z_.-]*_FCFW[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x00"
            expect_json_changes = 33

        else:
            platform = "unknown-fcfw"
            module_cmdopts = ""
            expect_json_changes = 16

    return module_cmdopts, expect_json_changes, platform


def modify_flyc_params(params_list):
    props_changed = []
    for par in params_list:
        if re.match(r'^g_config[.](advanced_function|flying_limit)[.]height_limit_enabled[_0]*$', par['name']):
            par['defaultValue'] = 2
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^(g_config[.]flying_limit[.]max_height|fly_limit_height)[_0]*$', par['name']):
            par['maxValue'] = 5000
            par['defaultValue'] = 5000
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]control[.]horiz_vel_atti_range[_0]*$', par['name']):
            par['defaultValue'] = 55
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]control[.](horiz_emergency_brake_tilt_max|horiz_tilt_emergency_brake_limit)[_0]*$', par['name']):
            par['defaultValue'] = 58
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]control[.]atti_limit[_0]*$', par['name']):
            par['maxValue'] = 9000
            par['defaultValue'] = 9000
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]control[.]atti_range[_0]*$', par['name']):
            par['defaultValue'] = 55
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]control[.]avoid_atti_range[_0]*$', par['name']):
            par['maxValue'] = 6000
            par['defaultValue'] = 3000
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.](control[.]vert_up_vel|mode_sport_cfg[.]vert_vel_up)[_0]*$', par['name']):
            par['maxValue'] = 20
            par['defaultValue'] = 20
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]mode_tripod_cfg[.]vert_vel_up[_0]*$', par['name']):
            par['defaultValue'] = 1.5
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]control[.]vert_down_vel[_0]*$', par['name']):
            par['defaultValue'] = 10
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]mode_sport_cfg[.]vert_vel_down[_0]*$', par['name']):
            par['minValue'] = -10.0
            par['defaultValue'] = -10.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]mode_tripod_cfg[.]vert_vel_down[_0]*$', par['name']):
            par['defaultValue'] = -1.5
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]control[.]vert_vel_down_bat_limit[_0]*$', par['name']):
            par['maxValue'] = 10
            par['defaultValue'] = 10
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]serial_api_cfg[.]advance_function_enable[_0]*$', par['name']):
            par['defaultValue'] = 0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]api_entry_cfg[.]value_sign[_0]*$', par['name']):
            par['defaultValue'] = 1
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]api_entry_cfg[.]enable_api[_0]*$', par['name']):
            par['defaultValue'] = 1
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]api_entry_cfg[.]enable_time_stamp[_0]*$', par['name']):
            par['defaultValue'] = 1
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]api_entry_cfg[.](acc|gyro|alti|height|pos)_data_type[_0]*$', par['name']):
            par['defaultValue'] = 5
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]api_entry_cfg[.]std_msg_frq\[[0-9]+\][_0]*$', par['name']):
            par['defaultValue'] = 5
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]api_entry_cfg[.]authority_level[_0]*$', par['name']):
            par['defaultValue'] = 10
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]api_entry_cfg[.]api_authority_group[0][_0]*$', par['name']):
            par['defaultValue'] = 0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]airport_limit_cfg[.]cfg_search_radius[_0]*$', par['name']):
            par['maxValue'] = 10
            par['defaultValue'] = 1
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^(g_config[.]airport_limit_cfg[.]|)cfg_disable_airport_fly_limit[_0]*$', par['name']):
            par['defaultValue'] = 255
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]airport_limit_cfg[.]cfg_debug_airport_enable[_0]*$', par['name']):
            par['defaultValue'] = 255
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]airport_limit_cfg[.]cfg_limit_data[_0]*$', par['name']):
            par['defaultValue'] = 20250910
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]misc_cfg[.]auto_landing_vel_L1[_0]*$', par['name']):
            par['defaultValue'] = -2.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]misc_cfg[.]auto_landing_vel_L2[_0]*$', par['name']):
            par['defaultValue'] = -8.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]followme_cfg[.]horiz_vel_limit[_0]*$', par['name']):
            par['maxValue'] = 30.0
            par['defaultValue'] = 30.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]waypoint_cfg[.]max_horiz_vel[_0]*$', par['name']):
            par['maxValue'] = 30.0
            par['defaultValue'] = 30.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]fdi[.]gps_max_horizontal_vel_mod[_0]*$', par['name']):
            par['defaultValue'] = 50.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^limit_height[_0]*$', par['name']):
            par['defaultValue'] = 0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^limit_height_abs[_0]*$', par['name']):
            par['defaultValue'] = 10000.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^limit_height_abs_without_gps[_0]*$', par['name']):
            par['defaultValue'] = 10000.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^limit_height_rel[_0]*$', par['name']):
            par['defaultValue'] = 10000.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^(g_config[.]go_home[.]|)avoid_ascending_height_limit_disable[_0]*$', par['name']):
            par['defaultValue'] = 1
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]flying_limit[.](viechle|driver)_license_limit_enable[_0]*$', par['name']):
            par['defaultValue'] = 0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^motor_no_start_motor_check[_0]*$', par['name']):
            par['defaultValue'] = 1
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]fdi_open[.]close_auto_stop_motor_check[_0]*$', par['name']):
            par['defaultValue'] = 1
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^(g_config[.]avoid_cfg[.]avoid|avoid_cfg)_tors_rate_range[_0]*$', par['name']):
            par['defaultValue'] = 70.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]mode_normal_cfg[.]tors_gyro_range[_0]*$', par['name']):
            par['defaultValue'] = 150.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]mode_sport_cfg[.]tors_gyro_range[_0]*$', par['name']):
            par['defaultValue'] = 250.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^CM_tors_range[_0]*$', par['name']):
            par['defaultValue'] = 52.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]mode_tripod_cfg[.]tors_gyro_range[_0]*$', par['name']):
            par['defaultValue'] = 60.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^(dji_bat_level_1|g_config[.]voltage2[.]level_1_voltage)[_0]*$', par['name']):
            par['minValue'] = 0
            par['maxValue'] = 100
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^(dji_bat_level_2|g_config[.]voltage2[.]level_2_voltage)[_0]*$', par['name']):
            par['minValue'] = 0
            par['maxValue'] = 100
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^(tilt_sensitive_gain|g_config[.]control[.]rc_tilt_sensitivity)[_0]*$', par['name']):
            par['minValue'] = 1
            par['maxValue'] = 100
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^yaw_sensitive_gain[_0]*$', par['name']):
            par['minValue'] = 1
            par['maxValue'] = 100
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^rc_throttle_sensitivity[_0]*$', par['name']):
            par['minValue'] = 1
            par['maxValue'] = 100
            props_changed.append(str(par['name']))
            continue
    return props_changed


def case_dji_flyc_param_ed_ckmod(modl_inp_fn):
    """ Test case for extraction and re-applying of hard-coded properties within FC BIN module.
    """
    LOGGER.info("Testcase file: {:s}".format(modl_inp_fn))

    # Get parameters for specific platforms
    extra_cmdopts, expect_json_changes, platform = get_params_for_dji_flyc_param_ed(modl_inp_fn)
    if expect_json_changes > 4:
        expect_file_changes = [expect_json_changes*2, expect_json_changes*2*4]
    else:
        expect_file_changes = [expect_json_changes*1, expect_json_changes*2*4 + 4]

    inp_path, inp_filename = os.path.split(modl_inp_fn)
    inp_path = pathlib.Path(inp_path)
    inp_basename, modl_fileext = os.path.splitext(inp_filename)
    if len(inp_path.parts) > 1:
        out_path = os.sep.join(["out"] + list(inp_path.parts[1:]))
    else:
        out_path = "out"
    modl_out_fn = os.sep.join([out_path, "{:s}.mod.bin".format(inp_basename)])
    json_ori_fn = os.sep.join([out_path, "{:s}.flyc_param_infos.json".format(inp_basename)])
    json_mod_fn = os.sep.join([out_path, "{:s}.flyc_param_infos.mod.json".format(inp_basename)])

    # Create json file with recognized hard-coded values
    command = [os.path.join(".", "dji_flyc_param_ed.py"), "-vv"] + shlex.split(extra_cmdopts) + ["-x", "-m", modl_inp_fn, "-i", json_ori_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        dji_flyc_param_ed_main()
    # Modify the JSON
    with open(json_ori_fn) as valfile:
        params_list = json.load(valfile)

    props_changed = modify_flyc_params(params_list)

    with open(json_mod_fn, "w") as valfile:
        valfile.write(json.dumps(params_list, indent=4))
    assert len(props_changed) >= expect_json_changes, "Performed too few JSON modifications ({:d}<{:d}): {:s}".format(len(props_changed), expect_json_changes, json_mod_fn)
    # Make copy of the BIN file
    shutil.copyfile(modl_inp_fn, modl_out_fn)
    # Import json file back to bin
    command = [os.path.join(".", "dji_flyc_param_ed.py"), "-vv"] + shlex.split(extra_cmdopts) + ["-u", "-i", json_mod_fn, "-m", modl_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        dji_flyc_param_ed_main()

    if True:
        # Count byte differences between repackaged file and the original
        nchanges =  filediff.diffcount(modl_inp_fn, modl_out_fn)
        assert nchanges >= expect_file_changes[0], "Updated file differences below bounds ({:d}<{:d}): {:s}".format(nchanges, expect_file_changes[0], modl_inp_fn)
        assert nchanges <= expect_file_changes[1], "Updated file differences above bounds ({:d}>{:d}): {:s}".format(nchanges, expect_file_changes[1], modl_inp_fn)
    pass


@pytest.mark.order(3) # must be run after test_dji_xv4_fwcon_rebin
@pytest.mark.fw_xv4
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/a3-flight_controller',0,),
    ('out/ag405-agras_mg_1s_octocopter',0,),
    ('out/ai900_agr-a3_based_multicopter_platform',0,),
    ('out/am603-n3_based_multicopter_platform',0,),
    ('out/m100-matrice_100_quadcopter',0,),
    ('out/m600-matrice_600_hexacopter',0,),
    ('out/m600pro-matrice_600_pro_hexacopter',0,),
    ('out/n3-flight_controller',0,),
    ('out/p3c-phantom_3_std_quadcopter',3,),
    ('out/p3se-phantom_3_se_quadcopter',0,),
    ('out/p3s-phantom_3_adv_quadcopter',3,),
    ('out/p3x-phantom_3_pro_quadcopter',3,),
    ('out/p3xw-phantom_3_4k_quadcopter',0,),
    ('out/wind-a3_based_multicopter_platform',0,),
    ('out/wm610_fc350z-t600_inspire_1_z3_quadcopter',0,),
    ('out/wm610_fc550-t600_inspire_1_pro_x5_quadcopter',0,),
    ('out/wm610-t600_inspire_1_x3_quadcopter',0,),
  ] )
def test_dji_flyc_param_ed_xv4_ckmod(capsys, modl_inp_dir, test_nth):
    """ Test extraction and re-applying of hard-coded properties within FC BIN module.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*-split1/*_m0306.bin".format(modl_inp_dir),
    ) ]) if (os.path.isfile(fn) and os.stat(fn).st_size > 0)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for modl_inp_fn in modl_inp_filenames[::test_nth]:
        case_dji_flyc_param_ed_ckmod(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(3) # must be run after test_dji_mvfc_fwpak_imah_v1_rebin
@pytest.mark.fw_imah_v1
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/ag407-agras_mg-1p-rtk',0,),
    ('out/ag408-agras_mg-unk',0,),
    ('out/ag410-agras_t16',0,),
    ('out/pm410-matrice200',0,),
    ('out/pm420-matrice200_v2',0,),
    ('out/wm100-spark',3,),
    ('out/wm220-mavic',3,),
    ('out/wm222-mavic_sp',0,),
    ('out/wm330-phantom_4_std',0,),
    ('out/wm331-phantom_4_pro',0,),
    ('out/wm332-phantom_4_adv',0,),
    ('out/wm334-phantom_4_rtk',0,),
    ('out/wm335-phantom_4_pro_v2',0,),
    ('out/wm336-phantom_4_mulspectral',0,),
    ('out/wm620-inspire_2',0,),
    ('out/xw607-robomaster_s1',0,),
  ] )
def test_dji_flyc_param_ed_imah_v1_ckmod(capsys, modl_inp_dir, test_nth):
    """ Test extraction and re-applying of hard-coded properties within FC BIN module.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*/*_0306.decrypted.bin".format(modl_inp_dir),
    ) ]) if (os.path.isfile(fn) and os.stat(fn).st_size > 0)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for modl_inp_fn in modl_inp_filenames[::test_nth]:
        case_dji_flyc_param_ed_ckmod(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(6) # must be run after test_dji_mvfc_fwpak_imah_v2_rebin and test_dji_imah_fwsig_v2_nested_rebin
@pytest.mark.fw_imah_v2
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/ag500-agras_t10',1,),
    ('out/ag501-agras_t30',1,),
    ('out/ag600-agras_t40_gimbal',1,),
    ('out/ag601-agras_t40',1,),
    ('out/pm320-matrice30',1,),
    ('out/pm430-matrice300',1,),
    ('out/wm1605-mini_se',1,),
    ('out/wm160-mavic_mini',1,),
    ('out/wm161-mini_2',1,),
    ('out/wm170-fpv_racer',1,),
    ('out/wm230-mavic_air',1,),
    ('out/wm231-mavic_air_2',1,),
    ('out/wm232-mavic_air_2s',1,),
    ('out/wm240-mavic_2',1,),
    ('out/wm245-mavic_2_enterpr',1,),
    ('out/wm246-mavic_2_enterpr_dual',1,),
    ('out/wm247-mavic_2_enterpr_rtk',1,),
  ] )
def test_dji_flyc_param_ed_imah_v2_ckmod(capsys, modl_inp_dir, test_nth):
    """ Test extraction and re-applying of hard-coded properties within FC BIN module.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*/*_0306.decrypted.bin".format(modl_inp_dir),
        "{}/*/*_FCFW.bin".format(modl_inp_dir),
    ) ]) if (os.path.isfile(fn) and os.stat(fn).st_size > 0)]

    # Skip the packages which were extracted in encrypted form (need non-public key)
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not is_module_unsigned_encrypted(fn)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for modl_inp_fn in modl_inp_filenames[::test_nth]:
        case_dji_flyc_param_ed_ckmod(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass
