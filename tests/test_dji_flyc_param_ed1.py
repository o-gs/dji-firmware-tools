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


def get_params_for_dji_flyc_param_ed(modl_inp_fn):
    """ From given module file name, figure out required dji_flyc_param_ed cmd options.
    """
    module_cmdopts = ""
    expect_json_changes = 99
    if (modl_inp_fn.endswith("_m0306.bin")):
        if (m := re.match(r'^.*(A3)_FW_[A-Z0-9_]*V(01[.]00|01[.]0[2-6])[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 17
        elif (m := re.match(r'^.*(A3)_FW_[A-Z0-9_]*V(01[.]0[7])[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 15
        elif (m := re.match(r'^.*(A3)_OFFICAL_1_7_5[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 17
        elif (m := re.match(r'^.*(A3)_OFFICAL_1_7_6[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 2
        elif (m := re.match(r'^.*(A3)_FW_V[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 36
        elif (m := re.match(r'^.*(MATRICE100)_FW_V[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 37
        elif (m := re.match(r'^.*(MATRICE600)_FW_V01[.]00[.]00[.]([0-3][0-9]|[4][0-3])[\(\)0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 37
        elif (m := re.match(r'^.*(MATRICE600|MATRICE600PRO)_FW_V01[.]00[.]00[.]([4][4-9]|[5-7][0-9])[\(\)0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 17
        elif (m := re.match(r'^.*(MATRICE600|MATRICE600PRO)_FW_V01[.]00[\(\)0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 15
        elif (m := re.match(r'^.*(MATRICE600|MATRICE600PRO)_FW_V02[.]00[.]00[.]9[0-9][\(\)0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 17
        elif (m := re.match(r'^.*(MATRICE600|MATRICE600PRO)_FW_V[\(\)0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 37
        elif (m := re.match(r'^.*(N3)_FW_V01[.](00[.]01[.]01|01[.]01[.]00)[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 15
        elif (m := re.match(r'^.*(N3)_FW_V01[.]07[.]00[.]0[0-5][0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 15
        elif (m := re.match(r'^.*(N3)_FW_V[0-9A-Z_.-]*_m0306[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x0420000"
            expect_json_changes = 17
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
            #expect_json_changes = 16
    elif (modl_inp_fn.endswith("_0306.decrypted.bin")):
        if (m := re.match(r'^.*(XXX)TODO_0306_v.*[.]bin$', modl_inp_fn, re.IGNORECASE)):
            platform = m.group(1)
            module_cmdopts = "-b 0x420000"
            expect_json_changes = 6
        else:
            platform = "unknown-imah"
            module_cmdopts = ""
            expect_json_changes = 16

    return module_cmdopts, expect_json_changes, platform


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
    command = [os.path.join(".", "dji_flyc_param_ed.py"), "-vv", *shlex.split(extra_cmdopts), "-x", "-m", modl_inp_fn, "-i", json_ori_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        dji_flyc_param_ed_main()
    # Modify the JSON
    with open(json_ori_fn) as valfile:
        params_list = json.load(valfile)
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
        if re.match(r'^g_config[.]control[.]vert_down_vel[_0]*$', par['name']):
            par['defaultValue'] = 10
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]mode_sport_cfg[.]vert_vel_down[_0]*$', par['name']):
            par['minValue'] = -10.0
            par['defaultValue'] = -10.0
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
        if re.match(r'^g_config[.]airport_limit_cfg[.]cfg_disable_airport_fly_limit[_0]*$', par['name']):
            par['defaultValue'] = 255
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]airport_limit_cfg[.]cfg_debug_airport_enable[_0]*$', par['name']):
            par['defaultValue'] = 255
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]airport_limit_cfg[.]cfg_limit_data[_0]*$', par['name']):
            par['defaultValue'] = 20200910
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
    with open(json_mod_fn, "w") as valfile:
        valfile.write(json.dumps(params_list, indent=4))
    assert len(props_changed) >= expect_json_changes, "Performed too few JSON modifications ({:d}<{:d}): {:s}".format(len(props_changed), expect_json_changes, json_mod_fn)
    # Make copy of the BIN file
    shutil.copyfile(modl_inp_fn, modl_out_fn)
    # Import json file back to bin
    command = [os.path.join(".", "dji_flyc_param_ed.py"), "-vv", *shlex.split(extra_cmdopts), "-u", "-i", json_mod_fn, "-m", modl_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        dji_flyc_param_ed_main()

    if True:
        # Count byte differences between repackaged file and the original
        nchanges =  filediff.diffcount(modl_inp_fn, modl_out_fn)
        assert nchanges >= expect_file_changes[0], "Updated file differences below bounds ({:d}<{:d}): {:s}".format(nchanges, expect_file_changes[0], modl_inp_fn)
        assert nchanges <= expect_file_changes[1], "Updated file differences above bounds ({:d}>{:d}): {:s}".format(nchanges, expect_file_changes[1], modl_inp_fn)
    pass


@pytest.mark.order(4) # must be run after test_arm_bin2elf_xv4_rebin
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/a3-flight_controller',0,),
    ('out/ag405-agras_mg_1s_octocopter',0,),
    #('out/ai900_agr-a3_based_multicopter_platform',0,),
    #('out/am603-n3_based_multicopter_platform',0,),
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

