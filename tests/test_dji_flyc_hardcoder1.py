# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, dji_flyc_hardcoder script.

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
from dji_flyc_hardcoder import main as dji_flyc_hardcoder_main


LOGGER = logging.getLogger(__name__)


def case_dji_flyc_hardcoder_ckmod(elf_inp_fn):
    """ Test case for extraction and re-applying of hard-coded properties within ELFs.
    """
    LOGGER.info("Testcase file: {:s}".format(elf_inp_fn))
    # Most files we are able to recreate with full accuracy
    expect_json_changes = 99
    expect_file_changes = [0,0]

    # Special cases - setting certain params and error tolerance for specific files
    # Most of these are firmwares which are not intentionally supported - they accidentally match
    # a small amount of patterns searched by the tool, allowing export of some parameters
    # For file changes - most parameters modify 1..4 bytes, but there are exceptions, ie.
    # firmware_version can modify 2..16
    if (elf_inp_fn.endswith("_m0306.elf")):
        if (re.match(r'^.*A3_FW_V01[.]0[1-6][.][0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*A3_FW_V01[.]07[.]00[.]0[0-9][0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*A3_OFFICAL_1_7_6_[0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 2
            expect_file_changes = [2, 2*4]
        elif (re.match(r'^.*AI900_AGR_FW_V01[.]00[.]00[.][0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*AI900_FW_V01[.]05[.][0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*A3[_]?AGR_FW_V[0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*A3_FW_V01[.]00[.]00[.]32[0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 2
            expect_file_changes = [2, 2*4]
        elif (re.match(r'^.*A3_OFFICAL_1_7_5_[0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 6
            expect_file_changes = [12, 12*4]
        elif (re.match(r'^.*AM603_FW_V0[0-2][.][()0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*N3_AGR_FW_V01[.]00[.]0[0-2][.][0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*N3_FW_V01[.]00[.]00[.][1-9][0-9][0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*N3_FW_V01[.]00[.]01[.][0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*N3_FW_V01[.]0[1-6][.][0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*N3_FW_V01[.]07[.]00[.]0[0-9][0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*N3_FW_V02[.]00[.]00[.][0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 2
            expect_file_changes = [2, 2*4]
        elif (re.match(r'^.*N3_FW_V01[.]00[.]00[.]01[0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*N3_FW_V01[.]07[.]00[.]10[0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 6
            expect_file_changes = [10, 12*4]
        elif (re.match(r'^.*MATRICE600_FW_V01[.]00[.]00[.]56[0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*MATRICE600PRO_FW_V01[.]00[.]01[.]2[1-9][0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*MATRICE600PRO_FW_V01[.]00[.]01[.][3-9][0-9][0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 6
            expect_file_changes = [10, 12*4]
        elif (re.match(r'^.*MATRICE600_FW_V01[.]00[.]00[.][0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*MATRICE600_FW_V01[.]00[.]01[.][0-1][0-9][0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*MATRICE600_FW_V01[.]00[.]01[.]2[0-1][0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*MATRICE600PRO_FW_V01[.][0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 2
            expect_file_changes = [2, 2*4]
        elif (re.match(r'^.*MATRICE600_FW_V02[.]00[.]00[.][()0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 4
            expect_file_changes = [4, 4*4]
        elif (re.match(r'^.*MG1S_FW_V01[.]00[.]00[.]0[3-5][0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*MG1S_FW_V01[.]01[.]00[.]00[0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE) or
          re.match(r'^.*MG1S_V3210_[0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 2
            expect_file_changes = [2, 2*4]
        elif (re.match(r'^.*MG1S_FW_V01[.]00[.]00[.]02[0-9A-Z_.-]*_m0306[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 6
            expect_file_changes = [10, 12*4]
        else:
            expect_json_changes = 6
            expect_file_changes = [12, 12*4]
    elif (elf_inp_fn.endswith("_0306.decrypted.elf")):
        if (re.match(r'^.*ag407_0306_v[0-9a-z_.-]*[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 2
            expect_file_changes = [2, 2*4]
        elif (re.match(r'^.*ag408_0306_v03[.]03[.]12[0-9a-z_.-]*[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 2
            expect_file_changes = [2, 2*4]
        elif (re.match(r'^.*ag410_0306_v03[.]04[0-9a-z_.-]*[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 1
            expect_file_changes = [0 + 2, 0*4 + 16]
        elif (re.match(r'^.*pm410_0306_v03[.]02[0-9a-z_.-]*[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 7
            expect_file_changes = [14, 14*4]
        elif (re.match(r'^.*pm410_0306_v03[.]03[0-9a-z_.-]*[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 2
            expect_file_changes = [2, 2*4]
        elif (re.match(r'^.*wm100_0306_v03[.]02[.]34[.]0[0-9][0-9a-z_.-]*[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 6
            expect_file_changes = [10, 12*4]
        elif (re.match(r'^.*wm100_0306_v[0-9a-z_.-]*[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 7
            expect_file_changes = [14, 14*4]
        elif (re.match(r'^.*wm331_0306_v03[.]02[.]15[.]14[0-9a-z_.-]*[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 3
            expect_file_changes = [2 + 2, 2*4 + 16]
        elif (re.match(r'^.*wm335_0306_v[0-9a-z_.-]*[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 2
            expect_file_changes = [2, 2*4]
        elif (re.match(r'^.*wm620_0306_v03[.]02[.][0-2][0-9][0-9a-z_.-]*[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 2
            expect_file_changes = [2, 2*4]
        elif (re.match(r'^.*wm620_0306_v03[.]03[.]09[0-9a-z_.-]*[.]elf', elf_inp_fn, re.IGNORECASE)):
            expect_json_changes = 2
            expect_file_changes = [2, 2*4]
        else:
            expect_json_changes = 7
            expect_file_changes = [14, 14*4]

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
    command = [os.path.join(".", "dji_flyc_hardcoder.py"), "-vvv", "-x", "-e", elf_inp_fn, "-o", json_ori_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        dji_flyc_hardcoder_main()
    # Modify the JSON
    with open(json_ori_fn) as valfile:
        params_list = json.load(valfile)
    props_changed = []
    for par in params_list:
        if re.match(r'^og_hardcoded[.]flyc[.]min_alt_below_home$', par['name']):
            par['setValue'] = -800.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^og_hardcoded[.]flyc[.]max_alt_above_home$', par['name']):
            par['setValue'] = 4000.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^og_hardcoded[.]flyc[.]max_wp_dist_to_home$', par['name']):
            par['setValue'] = 6000.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^og_hardcoded[.]flyc[.]max_mission_path_len$', par['name']):
            par['setValue'] = 40000.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^og_hardcoded[.]flyc[.]max_speed_pos$', par['name']):
            par['setValue'] = 25.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^og_hardcoded[.]flyc[.]max_speed_neg$', par['name']):
            par['setValue'] = -25.0
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^og_hardcoded[.]flyc[.]firmware_version$', par['name']):
            par['setValue'] = "12.34.56.78"
            props_changed.append(str(par['name']))
            continue
    with open(json_mod_fn, "w") as valfile:
        valfile.write(json.dumps(params_list, indent=4))
    assert len(props_changed) >= expect_json_changes, "Performed too few JSON modifications ({:d}<{:d}): {:s}".format(len(props_changed), expect_json_changes, json_mod_fn)
    # Make copy of the ELF file
    shutil.copyfile(elf_inp_fn, elf_out_fn)
    # Import json file back to elf
    command = [os.path.join(".", "dji_flyc_hardcoder.py"), "-vvv", "-u", "-o", json_mod_fn, "-e", elf_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        dji_flyc_hardcoder_main()

    if True:
        # Count byte differences between repackaged file and the original
        nchanges =  filediff.diffcount(elf_inp_fn, elf_out_fn)
        assert nchanges >= expect_file_changes[0], "Updated file differences below bounds ({:d}<{:d}): {:s}".format(nchanges, expect_file_changes[0], elf_inp_fn)
        assert nchanges <= expect_file_changes[1], "Updated file differences above bounds ({:d}>{:d}): {:s}".format(nchanges, expect_file_changes[1], elf_inp_fn)
    pass


@pytest.mark.order(4) # must be run after test_arm_bin2elf_xv4_rebin
@pytest.mark.fw_xv4
@pytest.mark.parametrize("elf_inp_dir,test_nth", [
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
def test_dji_flyc_hardcoder_xv4_ckmod(capsys, elf_inp_dir, test_nth):
    """ Test extraction and re-applying of hard-coded properties within ELFs.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    elf_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*-split1/*_m0306.elf".format(elf_inp_dir),
    ) ]) if (os.path.isfile(fn) and os.stat(fn).st_size > 0)]

    # Remove unsupported m0306 files
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*A3_FW_V02[.][0-9A-Z_.-]*_m0306.elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*MATRICE100_FW_V01[.]0[1-3][.][0-9A-Z_.-]*_m0306.elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*MATRICE600_FW_V01[.]00[.]00[.]28[0-9A-Z_.-]*_m0306.elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*MATRICE600_FW_V02[.]00[.]00[.]95[(]polar[)][0-9A-Z_.-]*_m0306.elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*MG1S_FW_V01[.]00[.]00[.]03[0-9A-Z_.-]*_m0306.elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*P3X_FW_V01[.]0[0-4][.][0-9A-Z_.-]*_m0306.elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*P3X_FW_V01[.]05[.]00[0-2][0-9][0-9A-Z_.-]*_m0306.elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*P3S_FW_V01[.]0[0-4][.][0-9A-Z_.-]*_m0306.elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*P3S_FW_V01[.]05[.]00[0-2][0-9][0-9A-Z_.-]*_m0306.elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*P3C_FW_V01[.]0[0-4][.][0-9A-Z_.-]*_m0306.elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*P3C_FW_V01[.]05[.]00[0-2][0-9][0-9A-Z_.-]*_m0306.elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*WM610_FC550_FW_V01[.]00[.]00[.]3[0-9][0-9A-Z_.-]*_m0306.elf', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*WM610_FW_V01[.]0[0-4][.][0-9A-Z_.-]*_m0306.elf', fn, re.IGNORECASE)]

    if len(elf_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for elf_inp_fn in elf_inp_filenames[::test_nth]:
        case_dji_flyc_hardcoder_ckmod(elf_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(4) # must be run after test_arm_bin2elf_imah_v1_rebin
@pytest.mark.fw_imah_v1
@pytest.mark.parametrize("elf_inp_dir,test_nth", [
    ('out/ag407-agras_mg-1p-rtk',0,),
    ('out/ag408-agras_mg-unk',0,),
    ('out/ag410-agras_t16',0,),
    ('out/pm410-matrice200',0,),
    ('out/pm420-matrice200_v2',0,),
    ('out/wm100-spark',0,),
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
def test_dji_flyc_hardcoder_imah_v1_ckmod(capsys, elf_inp_dir, test_nth):
    """ Test extraction and re-applying of hard-coded properties within ELFs.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    elf_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*/*_0306.decrypted.elf".format(elf_inp_dir),
    ) ]) if (os.path.isfile(fn) and os.stat(fn).st_size > 0)]

    # Remove unsupported m0306 files
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*ag407_0306_v03[.]03[.]03[.]8[0-9][0-9a-z_.-]*[.]elf$', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*wm334_0306_v03[.]03[.]06[.]57[0-9a-z_.-]*[.]elf$', fn, re.IGNORECASE)]

    if len(elf_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for elf_inp_fn in elf_inp_filenames[::test_nth]:
        case_dji_flyc_hardcoder_ckmod(elf_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass
