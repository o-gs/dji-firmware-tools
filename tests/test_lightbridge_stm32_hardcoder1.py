# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, lightbridge_stm32_hardcoder script.

    This test verifies functions of the script by extracting the
    hard-coded values from ELF, applying modifications, and re-applying
    them, finally checking if the resulting files have expected
    amount of changes.

    This test requires modules to already be extracted from their
    packages, and specific modules used here to be converted to ELF.
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
from lightbridge_stm32_hardcoder import main as lightbridge_stm32_hardcoder_main


LOGGER = logging.getLogger(__name__)


def case_lightbridge_stm32_hardcoder_ckmod(elf_inp_fn):
    """ Test case for extraction and re-applying of hard-coded properties within ELFs.
    """
    LOGGER.info("Testcase file: {:s}".format(elf_inp_fn))
    # Most files we are able to recreate with full accuracy
    expect_json_changes = 99
    expect_file_changes = [0,0]

    # Special cases - setting certain params and error tolerance for specific files
    if (elf_inp_fn.endswith("_m0900.elf")):
        if (re.match(r'^.*P3S_FW_V01[.]0[0-4][.][0-9A-Z_.-]*_m0900[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*P3S_FW_V01[.]05[.]00[0-1][0-9][0-9A-Z_.-]*_m0900[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*P3X_FW_V01[.]0[0-4][.][0-9A-Z_.-]*_m0900[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*P3X_FW_V01[.]05[.]00[0-1][0-9][0-9A-Z_.-]*_m0900[.]elf', elf_inp_fn, re.IGNORECASE)):
            # P3S and P3X firmwares m0900 with package version number below V01.05
            expect_json_changes = 2
            expect_file_changes = [2, 2*4]
        elif (re.match(r'^.*P3S_FW_V[0-9A-Z_.-]*_m0900[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*P3X_FW_V[0-9A-Z_.-]*_m0900[.]elf', elf_inp_fn, re.IGNORECASE)):
            # The rest of P3S and P3X firmwares m0900
            expect_json_changes = 6 # 3 x authority_level + 3 x vid_setting_bitrates
            expect_file_changes = [12, 12*4]
    elif (elf_inp_fn.endswith("_m1400.elf")):
        if (re.match(r'^.*C1_FW_V01[.]0[0-3][.][0-9A-Z_.-]*_m1400[.]elf', elf_inp_fn, re.IGNORECASE)):
            # C1 RC firmwares m1400 with package version number below V01.04
            expect_json_changes = 6
            expect_file_changes = [6, 2*3 + 3*4]
        elif (re.match(r'^.*C1_FW_V01[.]05[.]0072_m1400[.]elf', elf_inp_fn, re.IGNORECASE)):
            # C1 RC firmwares m1400 with package version number V01.05.0072
            expect_json_changes = 3
            expect_file_changes = [3, 3*4]
        elif (re.match(r'^.*C1_FW_V[0-9A-Z_.-]*_m1400[.]elf', elf_inp_fn, re.IGNORECASE)):
            # The rest of C1 RC firmwares m1400
            expect_json_changes = 8 # 1 x attenuation_override + 1 x attenuation_value + 6 x board_attenuation
            expect_file_changes = [2+6, 2*3 + 3*4]
        elif (re.match(r'^.*P3S_FW_V01[.]0[0-2][.][0-9A-Z_.-]*_m1400[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*P3X_FW_V01[.]0[0-2][.][0-9A-Z_.-]*_m1400[.]elf', elf_inp_fn, re.IGNORECASE)):
            # P3S and P3X firmwares m1400 with package version number below V01.03
            expect_json_changes = 2
            expect_file_changes = [2, 2*4]
        elif (re.match(r'^.*P3S_FW_V[0-9A-Z_.-]*_m1400[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*P3X_FW_V[0-9A-Z_.-]*_m1400[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 6 # 3 x authority_level + 3 x vid_setting_bitrates
            expect_file_changes = [6, 6*4]
        elif (re.match(r'^.*WM610_FW_V[0-9A-Z_.-]*_m1400[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 2
            expect_file_changes = [2, 2*4]
    elif (elf_inp_fn.endswith("_m1401.elf")):
        if (re.match(r'^.*C1_FW_V01[.]05[.]0072_m1401[.]elf', elf_inp_fn, re.IGNORECASE)):
            # C1 RC firmwares m1401 with package version number V01.05.0072
            expect_json_changes = 3
            expect_file_changes = [3, 3*4]
        elif (re.match(r'^.*C1_FW_V[0-9A-Z_.-]*_m1401[.]elf', elf_inp_fn, re.IGNORECASE)):
            # The rest of C1 RC firmwares m1401
            expect_json_changes = 6
            expect_file_changes = [6, 2*3 + 3*4]
        elif (re.match(r'^.*P34_v[0-9A-Z_.-]*_m1401[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 7
            expect_file_changes = [7, 2*3 + 4*4]
    elif (elf_inp_fn.endswith("_0900.elf")):
        if (re.match(r'^.*wm330_0900_v[0-9a-z_.-]*[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 22
            expect_file_changes = [22, 22*4]

    inp_path, inp_filename = os.path.split(elf_inp_fn)
    inp_path = pathlib.Path(inp_path)
    inp_basename, elf_fileext = os.path.splitext(inp_filename)
    if len(inp_path.parts) > 1:
        out_path = os.sep.join(["out"] + list(inp_path.parts[1:]))
    else:
        out_path = "out"
    elf_out_fn = os.sep.join([out_path, "{:s}.mod.elf".format(inp_basename)])
    json_ori_fn = os.sep.join([out_path, "{:s}.json".format(inp_basename)])
    json_mod_fn = os.sep.join([out_path, "{:s}.mod.json".format(inp_basename)])

    # Create json file with recognized hard-coded values
    command = [os.path.join(".", "lightbridge_stm32_hardcoder.py"), "-vvv", "-x", "-e", elf_inp_fn, "-o", json_ori_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        lightbridge_stm32_hardcoder_main()
    # Modify the JSON
    with open(json_ori_fn) as valfile:
        params_list = json.load(valfile)
    props_changed = []
    for par in params_list:
        if re.match(r'^og_hardcoded[.]lightbridge_stm32[.]packet_received_attenuation_override$', par['name']):
            par['setValue'] = 1
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^og_hardcoded[.]lightbridge_stm32[.]packet_received_attenuation_value$', par['name']):
            par['setValue'] = 0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^og_hardcoded[.]lightbridge_stm32[.]board_[a-z0-9]*_attenuation_[a-z0-9]*_[a-z0-9]*$', par['name']):
            par['setValue'] = 0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^og_hardcoded[.]lightbridge_stm32[.]power_zone_selection_override$', par['name']):
            par['setValue'] = 1
            props_changed.append(str(par['name']))
            continue
    with open(json_mod_fn, "w") as valfile:
        valfile.write(json.dumps(params_list, indent=4))
    assert len(props_changed) >= expect_json_changes, "Performed too few JSON modifications ({:d}<{:d}): {:s}".format(len(props_changed), expect_json_changes, json_mod_fn)
    # Make copy of the ELF file
    shutil.copyfile(elf_inp_fn, elf_out_fn)
    # Import json file back to elf
    command = [os.path.join(".", "lightbridge_stm32_hardcoder.py"), "-vvv", "-u", "-o", json_mod_fn, "-e", elf_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        lightbridge_stm32_hardcoder_main()

    if True:
        # Count byte differences between repackaged file and the original
        nchanges =  filediff.diffcount(elf_inp_fn, elf_out_fn)
        assert nchanges >= expect_file_changes[0], "Updated file differences below bounds ({:d}<{:d}): {:s}".format(nchanges, expect_file_changes[0], elf_inp_fn)
        assert nchanges <= expect_file_changes[1], "Updated file differences above bounds ({:d}>{:d}): {:s}".format(nchanges, expect_file_changes[1], elf_inp_fn)
    pass


@pytest.mark.order(4) # must be run after test_arm_bin2elf_xv4_rebin
@pytest.mark.fw_xv4
@pytest.mark.parametrize("elf_inp_dir,test_nth", [
    #('out/ag405-agras_mg_1s_octocopter',1,), # no matching modules
    ('out/gl300abc-radio_control',3,),
    ('out/gl300e-radio_control',1,),
    ('out/hg910-ronin2_gimbal',1,),
    ('out/p3c-phantom_3_std_quadcopter',1,),
    ('out/p3s-phantom_3_adv_quadcopter',3,),
    #('out/p3se-phantom_3_se_quadcopter',1,), # no patterns recognized by the hardcoder
    ('out/p3x-phantom_3_pro_quadcopter',3,),
    #('out/p3xw-phantom_3_4k_quadcopter',1,), # no patterns recognized by the hardcoder
    ('out/wm610-t600_inspire_1_x3_quadcopter',3,),
  ] )
def test_lightbridge_stm32_hardcoder_xv4_ckmod(capsys, elf_inp_dir, test_nth):
    """ Test extraction and re-applying of hard-coded properties within ELFs.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    elf_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*-split1/*_m0900.elf".format(elf_inp_dir),
        "{}/*-split1/*_m1400.elf".format(elf_inp_dir),
        "{}/*-split1/*_m1401.elf".format(elf_inp_dir),
    ) ]) if os.path.isfile(fn)]

    # Remove unsupported m0900 files
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*MG1S_[0-9A-Z_.-]*_m0900[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*P3XW_FW_V[0-9A-Z_.-]*_m0900[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*P3SE_FW_V[0-9A-Z_.-]*_m0900[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*P3C_FW_V[0-9A-Z_.-]*_m0900[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*WM610_FW_V[0-9A-Z_.-]*_m0900[.]elf', fn, re.IGNORECASE)]
    # Remove unsupported m1400 files
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*C1_FW_v00[.]00[.][0-9A-Z_.-]*_m1400[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*C1_FW_v01[.]01[.]003[5-9][0-9A-Z_.-]*_m1400[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*C1_FW_v01[.]01[.]00[4-9][0-9][0-9A-Z_.-]*_m1400[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*C1_FW_v01[.]07[.]000[2-9][0-9A-Z_.-]*_m1400[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*C1_FW_v01[.]07[.]00[1-6][0-9][0-9A-Z_.-]*_m1400[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*C1_FW_v01[.]09[.][0-9A-Z_.-]*_m1400[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*IN1_v1780_[0-9A-Z_.-]*_m1400[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*P34_v19[0-9][0-9]_[0-9A-Z_.-]*_m1400[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*MG1SRC_FW_V[0-9A-Z_.-]*_m1400[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*LB2_GND_V[0-9A-Z_.-]*_m1400[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*RC_[0-9A-Z_.-]*_m1400[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*300E_MCU_[0-9A-Z_.-]*_m1400[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*GL300E_V[0-9A-Z_.-]*_m1400[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*GL300E_RC_V[0-9A-Z_.-]*_m1400[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*P3C_FW_V[0-9A-Z_.-]*_m1400[.]elf', fn, re.IGNORECASE)]
    # Remove unsupported m1401 files
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*HG910_RC_FW_V[0-9A-Z_.-]*_m1401[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*C1_33[0-3]_[0-9A-Z_.-]*_m1401[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*C1_RC_v1[0-4]00_[0-9A-Z_.-]*_m1401[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*C1_v1400_[0-9A-Z_.-]*_m1401[.]elf', fn, re.IGNORECASE)] # renamed - to be removed after xV4 zip update
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*C1_FW_v00[.]00[.][0-9A-Z_.-]*m1401[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*C1_V00[.]01[.][0-9A-Z_.-]*_m1401[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*p4pRC_v1[.]0[.][0-9A-Z_.-]*_m1401[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*P34_v1930_[0-9A-Z_.-]*_m1401[.]elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*WM332_V2100_[0-9A-Z_.-]*_m1401[.]elf', fn, re.IGNORECASE)]

    if len(elf_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for elf_inp_fn in elf_inp_filenames[::test_nth]:
        case_lightbridge_stm32_hardcoder_ckmod(elf_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(4) # must be run after test_arm_bin2elf_imah_v1_rebin
@pytest.mark.fw_imah_v1
@pytest.mark.parametrize("elf_inp_dir,test_nth", [
    #('out/pm410-matrice200',3,), # no patterns recognized by the hardcoder
    ('out/wm330-phantom_4_std',3,),
    #('out/wm331-phantom_4_pro',3,), # no patterns recognized by the hardcoder
    #('out/wm332-phantom_4_adv',3,), # no patterns recognized by the hardcoder
    #('out/wm620-inspire_2',3,), # no patterns recognized by the hardcoder
  ] )
def test_lightbridge_stm32_hardcoder_imah_v1_ckmod(capsys, elf_inp_dir, test_nth):
    """ Test extraction and re-applying of hard-coded properties within ELFs.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    elf_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*/*_0900.elf".format(elf_inp_dir),
    ) ]) if os.path.isfile(fn)]

    if len(elf_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for elf_inp_fn in elf_inp_filenames[::test_nth]:
        case_lightbridge_stm32_hardcoder_ckmod(elf_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass
