# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, amba_sys_hardcoder script.

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
from amba_sys_hardcoder import main as amba_sys_hardcoder_main


LOGGER = logging.getLogger(__name__)


def case_amba_sys_hardcoder_ckmod(elf_inp_fn):
    """ Test case for extraction and re-applying of hard-coded properties within ELFs.
    """
    LOGGER.info("Testcase file: {:s}".format(elf_inp_fn))
    # Most files we are able to recreate with full accuracy
    expect_json_changes = 99
    expect_file_changes = [0,0]

    # Special cases - setting certain params and error tolerance for specific files
    if (re.match(r'^.*P3C_FW_V01[.]00[.]0014[0-9A-Z_.-]*_m0100_part_sys[.]elf', elf_inp_fn, re.IGNORECASE) or
      re.match(r'^.*P3S_FW_V01[.]01[.]0008[0-9A-Z_.-]*_m0100_part_sys[.]elf', elf_inp_fn, re.IGNORECASE) or
      re.match(r'^.*P3X_FW_V01[.]01[.]0006[0-9A-Z_.-]*_m0100_part_sys[.]elf', elf_inp_fn, re.IGNORECASE) or
      re.match(r'^.*P3XW_FW_V01[.]00[.]0010[0-9A-Z_.-]*_m0100_part_sys[.]elf', elf_inp_fn, re.IGNORECASE)):
        expect_json_changes = 3 # 3 x authority_level
        expect_file_changes = [2, 3*4] # one authority_level may be changed to same value
    elif (re.match(r'^.*P3C_FW_V[0-9A-Z_.-]*_m0100_part_sys[.]elf', elf_inp_fn, re.IGNORECASE) or
      re.match(r'^.*P3S_FW_V[0-9A-Z_.-]*_m0100_part_sys[.]elf', elf_inp_fn, re.IGNORECASE) or
      re.match(r'^.*P3X_FW_V[0-9A-Z_.-]*_m0100_part_sys[.]elf', elf_inp_fn, re.IGNORECASE) or
      re.match(r'^.*P3XW_FW_V[0-9A-Z_.-]*_m0100_part_sys[.]elf', elf_inp_fn, re.IGNORECASE)):
        expect_json_changes = 6 # 3 x authority_level + 3 x vid_setting_bitrates
        expect_file_changes = [2+6, 2*3 + 3*4] # one authority_level change is to default which decreases min
    elif (re.match(r'^.*WM610_FW_V[0-9A-Z_.-]*_m0100_part_sys[.]elf', elf_inp_fn, re.IGNORECASE) or
      re.match(r'^.*WM610_FC550_FW_V[0-9A-Z_.-]*_m0100_part_sys[.]elf', elf_inp_fn, re.IGNORECASE)):
        expect_json_changes = 3 # 3 x vid_setting_bitrates
        expect_file_changes = [3*2, 3*4]

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
    command = [os.path.join(".", "amba_sys_hardcoder.py"), "-vvv", "-x", "-e", elf_inp_fn, "-o", json_ori_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        amba_sys_hardcoder_main()
    # Modify the JSON
    with open(json_ori_fn) as valfile:
        params_list = json.load(valfile)
    props_changed = []
    for par in params_list:
        if re.match(r'^og_hardcoded[.]p3x_ambarella[.][a-z_]*_authority_level$', par['name']):
            # There are 3 such params
            par['setValue'] = 1
            props_changed.append(str(par['name']))
            continue
        if re.match(r'^og_hardcoded[.]p3x_ambarella[.]vid_setting_bitrates_00$', par['name']):
            # There is one 00 param, but it contains 3 property values
            par['setValue'] = "29500000 47500000 62500000"
            for n in [0, 1, 2]:
                props_changed.append("{:s}[{:d}]".format(par['name'], n))
            continue
    with open(json_mod_fn, "w") as valfile:
        valfile.write(json.dumps(params_list, indent=4))
    assert len(props_changed) >= expect_json_changes, "Performed too few JSON modifications ({:d}<{:d}): {:s}".format(len(props_changed), expect_json_changes, json_mod_fn)
    # Make copy of the ELF file
    shutil.copyfile(elf_inp_fn, elf_out_fn)
    # Import json file back to elf
    command = [os.path.join(".", "amba_sys_hardcoder.py"), "-vvv", "-u", "-o", json_mod_fn, "-e", elf_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        amba_sys_hardcoder_main()

    if True:
        # Count byte differences between repackaged file and the original
        nchanges =  filediff.diffcount(elf_inp_fn, elf_out_fn)
        assert nchanges >= expect_file_changes[0], "Updated file differences below bounds ({:d}<{:d}): {:s}".format(nchanges, expect_file_changes[0], elf_inp_fn)
        assert nchanges <= expect_file_changes[1], "Updated file differences above bounds ({:d}>{:d}): {:s}".format(nchanges, expect_file_changes[1], elf_inp_fn)
    pass

@pytest.mark.order(5) # must be run after test_amba_sys2elf_rebin
@pytest.mark.fw_xv4
@pytest.mark.parametrize("elf_inp_dir,test_nth", [
    #('out/m600-matrice_600_hexacopter',3,), # no patterns recognized by the hardcoder
    #('out/osmo_fc350z-osmo_zoom_z3_gimbal',3,), # no patterns recognized by the hardcoder
    #('out/osmo_fc550-osmo_x5_gimbal',3,), # no matching modules
    #('out/osmo_fc550r-osmo_x5raw_gimbal',3,), # no patterns recognized by the hardcoder
    #('out/osmo-osmo_x3_gimbal',3,), # no patterns recognized by the hardcoder
    ('out/p3c-phantom_3_std_quadcopter',0,),
    #('out/p3se-phantom_3_se_quadcopter',3,), # no matching modules (amba extract disabled)
    ('out/p3s-phantom_3_adv_quadcopter',0,),
    ('out/p3x-phantom_3_pro_quadcopter',3,),
    ('out/p3xw-phantom_3_4k_quadcopter',0,),
    #('out/wm610_fc350z-t600_inspire_1_z3_quadcopter',3,), # no patterns recognized by the hardcoder
    ('out/wm610_fc550-t600_inspire_1_pro_x5_quadcopter',0,),
    ('out/wm610-t600_inspire_1_x3_quadcopter',3,),
  ] )
def test_amba_sys_hardcoder_ckmod(capsys, elf_inp_dir, test_nth):
    """ Test extraction and re-applying of hard-coded properties within ELFs.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    elf_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*-split1/*-split1/*_m0100_part_sys.elf".format(elf_inp_dir),
    ) ]) if os.path.isfile(fn)]

    # Remove unsupported files
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*WM610_FW_V01[.]02[.]01[.]0[3-6][0-9a-z_.-]*_m0100_part_sys[.]elf$', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*WM610_FW_V01[.]0[5-9][.][0-9][0-9][.][0-9a-z_.-]*_m0100_part_sys[.]elf$', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*WM610_FW_V01[.]1[0-1][.][0-9][0-9][.][0-9a-z_.-]*_m0100_part_sys[.]elf$', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*WM610_FC550_FW_V01[.]0[1-2][.][0-9a-z_.-]*_m0100_part_sys[.]elf$', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*WM610_FC550_FW_V01[.]08[.]01[.]00_m0100_part_sys[.]elf$', fn, re.IGNORECASE)]

    if len(elf_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for elf_inp_fn in elf_inp_filenames[::test_nth]:
        case_amba_sys_hardcoder_ckmod(elf_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass
