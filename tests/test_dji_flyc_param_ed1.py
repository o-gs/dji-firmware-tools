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


def case_dji_flyc_param_ed_ckmod(modl_inp_fn):
    """ Test case for extraction and re-applying of hard-coded properties within FC BIN module.
    """
    LOGGER.info("Testcase file: {:s}".format(modl_inp_fn))
    # Most files we are able to recreate with full accuracy
    expect_json_changes = 99
    expect_file_changes = [0,0]

    # Special cases - setting certain params and error tolerance for specific files
    if (modl_inp_fn.endswith("_m0306.bin")):
        if (re.match(r'^.*P3X_FW_V01[.]0[0-1].0[0-9][0-9][0-9][0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE)):
            expect_json_changes = 16
            expect_file_changes = [16*2, 16*2*4]
        elif (re.match(r'^.*P3X_FW_V01[.]01.[1-9][0-9][0-9][0-9][0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE)):
            expect_json_changes = 33
            expect_file_changes = [33*2, 33*2*4]
        elif (re.match(r'^.*P3X_FW_V[0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE)):
            expect_json_changes = 36
            expect_file_changes = [36*2, 36*2*4]
        else:
            expect_json_changes = 6
            expect_file_changes = [6*2, 6*2*4]
    elif (modl_inp_fn.endswith("_0306.decrypted.bin")):
        if (re.match(r'^.*XXXTODO_0306_v.*[.]bin', modl_inp_fn, re.IGNORECASE)):
            expect_json_changes = 6
            expect_file_changes = [10, 12*4]
        else:
            expect_json_changes = 7
            expect_file_changes = [14, 14*4]

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
    command = [os.path.join(".", "dji_flyc_param_ed.py"), "-vv", "-x", "-m", modl_inp_fn, "-i", json_ori_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        dji_flyc_param_ed_main()
    # Modify the JSON
    with open(json_ori_fn) as valfile:
        params_list = json.load(valfile)
    props_changed = []
    for par in params_list:
        if re.match(r'^g_config[.]advanced_function[.]height_limit_enabled_0$', par['name']):
            par['defaultValue'] = 2
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]flying_limit[.]max_height_0$', par['name']):
            par['maxValue'] = 5000
            par['defaultValue'] = 5000
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]control[.]horiz_vel_atti_range_0$', par['name']):
            par['defaultValue'] = 55
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]control[.]horiz_emergency_brake_tilt_max_0$', par['name']):
            par['defaultValue'] = 58
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]control[.]atti_limit_0$', par['name']):
            par['maxValue'] = 9000
            par['defaultValue'] = 9000
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]control[.]atti_range_0$', par['name']):
            par['defaultValue'] = 55
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]control[.]avoid_atti_range_0$', par['name']):
            par['maxValue'] = 6000
            par['defaultValue'] = 3000
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]control[.]vert_up_vel_0$', par['name']):
            par['maxValue'] = 20
            par['defaultValue'] = 20
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]control[.]vert_down_vel_0$', par['name']):
            par['defaultValue'] = 10
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]control[.]vert_vel_down_bat_limit_0$', par['name']):
            par['maxValue'] = 10
            par['defaultValue'] = 10
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]serial_api_cfg[.]advance_function_enable_0$', par['name']):
            par['defaultValue'] = 0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]api_entry_cfg[.]value_sign_0$', par['name']):
            par['defaultValue'] = 1
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]api_entry_cfg[.]enable_api_0$', par['name']):
            par['defaultValue'] = 1
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]api_entry_cfg[.]enable_time_stamp_0$', par['name']):
            par['defaultValue'] = 1
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]api_entry_cfg[.](acc|gyro|alti|height)_data_type_0$', par['name']):
            par['defaultValue'] = 5
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]api_entry_cfg[.]std_msg_frq\[[0-9]+\]_0$', par['name']):
            par['defaultValue'] = 5
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]api_entry_cfg[.]authority_level_0$', par['name']):
            par['defaultValue'] = 10
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]api_entry_cfg[.]api_authority_group[0]_0$', par['name']):
            par['defaultValue'] = 0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]airport_limit_cfg[.]cfg_search_radius_0$', par['name']):
            par['maxValue'] = 10
            par['defaultValue'] = 1
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]airport_limit_cfg[.]cfg_disable_airport_fly_limit_0$', par['name']):
            par['defaultValue'] = 255
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]airport_limit_cfg[.]cfg_debug_airport_enable_0$', par['name']):
            par['defaultValue'] = 255
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]airport_limit_cfg[.]cfg_limit_data_0$', par['name']):
            par['defaultValue'] = 20200910
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]misc_cfg[.]auto_landing_vel_L1_0$', par['name']):
            par['defaultValue'] = -2.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]misc_cfg[.]auto_landing_vel_L2_0$', par['name']):
            par['defaultValue'] = -8.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]followme_cfg[.]horiz_vel_limit_0$', par['name']):
            par['maxValue'] = 30.0
            par['defaultValue'] = 30.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]waypoint_cfg[.]max_horiz_vel_0$', par['name']):
            par['maxValue'] = 30.0
            par['defaultValue'] = 30.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^g_config[.]fdi[.]gps_max_horizontal_vel_mod_0$', par['name']):
            par['defaultValue'] = 50.0
            props_changed.append(str(par['name']))
            continue
    with open(json_mod_fn, "w") as valfile:
        valfile.write(json.dumps(params_list, indent=4))
    assert len(props_changed) >= expect_json_changes, "Performed too few JSON modifications ({:d}<{:d}): {:s}".format(len(props_changed), expect_json_changes, json_mod_fn)
    # Make copy of the BIN file
    shutil.copyfile(modl_inp_fn, modl_out_fn)
    # Import json file back to bin
    command = [os.path.join(".", "dji_flyc_param_ed.py"), "-vv", "-u", "-i", json_mod_fn, "-m", modl_out_fn]
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
    #('out/a3-flight_controller',0,),
    #('out/ag405-agras_mg_1s_octocopter',0,),
    #('out/ai900_agr-a3_based_multicopter_platform',0,),
    #('out/am603-n3_based_multicopter_platform',0,),
    #('out/m100-matrice_100_quadcopter',0,),
    #('out/m600-matrice_600_hexacopter',0,),
    #('out/m600pro-matrice_600_pro_hexacopter',0,),
    #('out/n3-flight_controller',0,),
    #('out/p3c-phantom_3_std_quadcopter',3,),
    #('out/p3se-phantom_3_se_quadcopter',0,),
    #('out/p3s-phantom_3_adv_quadcopter',3,),
    ('out/p3x-phantom_3_pro_quadcopter',3,),
    #('out/p3xw-phantom_3_4k_quadcopter',0,),
    #('out/wind-a3_based_multicopter_platform',0,),
    #('out/wm610_fc350z-t600_inspire_1_z3_quadcopter',0,),
    #('out/wm610_fc550-t600_inspire_1_pro_x5_quadcopter',0,),
    #('out/wm610-t600_inspire_1_x3_quadcopter',0,),
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

