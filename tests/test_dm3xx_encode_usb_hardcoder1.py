# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, dm3xx_encode_usb_hardcoder script.

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
import subprocess
import sys
import pathlib
import pytest
from unittest.mock import patch

# Import the functions to be tested
sys.path.insert(0, './')
import filediff
from dm3xx_encode_usb_hardcoder import main as dm3xx_encode_usb_hardcoder_main


LOGGER = logging.getLogger(__name__)


def case_dm3xx_encode_usb_hardcoder_ckmod(elf_inp_fn):
    """ Test case for extraction and re-applying of hard-coded properties within ELFs.
    """
    LOGGER.info("Testcase file: {:s}".format(elf_inp_fn))
    # Most files we are able to recreate with full accuracy
    expect_json_changes = 99
    expect_file_changes = [0,0]

    # We expect the input file to be in a folder which identifies the module
    inp_path, elf_base_name = os.path.split(elf_inp_fn)
    match = re.search(r'^(.*_m([0-9]{4}))[.-].*$', inp_path, flags=re.IGNORECASE)
    assert match, "File path does not identify module: {:s}".format(elf_inp_fn)
    inp_path = match.group(1)
    inp_path, modl_base_name = os.path.split(inp_path)
    inp_module = match.group(2)

    # Special cases - setting certain params and error tolerance for specific files
    if inp_module == '0800' and elf_base_name == 'encode_usb':
        expect_json_changes = 1 # only startup_encrypt_check_always_pass
        expect_file_changes = [1, 16]
    elif inp_module == '1300' and elf_base_name == 'usbclient':
        # There are currently no supported cases for m1300
        expect_json_changes = 99
        expect_file_changes = [0, 0]

    inp_path = pathlib.Path(inp_path)
    if len(inp_path.parts) > 1:
        out_path = os.sep.join(["out"] + list(inp_path.parts[1:]))
    else:
        out_path = "out"
    elf_cpy_fn = os.sep.join([out_path, "{:s}-{:s}.elf".format(modl_base_name, elf_base_name)])
    elf_out_fn = os.sep.join([out_path, "{:s}-{:s}.mod.elf".format(modl_base_name, elf_base_name)])
    json_ori_fn = os.sep.join([out_path, "{:s}-{:s}.json".format(modl_base_name, elf_base_name)])
    json_mod_fn = os.sep.join([out_path, "{:s}-{:s}.mod.json".format(modl_base_name, elf_base_name)])

    # Copy the ELF file into better place, and rename
    shutil.copy(elf_inp_fn, elf_cpy_fn)

    # Create json file with recognized hard-coded values
    command = [os.path.join(".", "dm3xx_encode_usb_hardcoder.py"), "-vvv", "-x", "-e", elf_cpy_fn, "-o", json_ori_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        dm3xx_encode_usb_hardcoder_main()

    # Modify the JSON
    with open(json_ori_fn) as valfile:
        params_list = json.load(valfile)
    props_changed = []
    for par in params_list:
        if re.match(r'^og_hardcoded[.]p3x_dm3xx[.]startup_encrypt_check_always_pass$', par['name']):
            par['setValue'] = 1
            props_changed.append(str(par['name']))
            continue
    with open(json_mod_fn, "w") as valfile:
        valfile.write(json.dumps(params_list, indent=4))
    assert len(props_changed) >= expect_json_changes, "Performed too few JSON modifications ({:d}<{:d}): {:s}".format(len(props_changed), expect_json_changes, json_mod_fn)

    # Make copy of the ELF file
    shutil.copyfile(elf_cpy_fn, elf_out_fn)
    # Import json file back to elf
    command = [os.path.join(".", "dm3xx_encode_usb_hardcoder.py"), "-vvv", "-u", "-o", json_mod_fn, "-e", elf_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        dm3xx_encode_usb_hardcoder_main()

    if True:
        # Count byte differences between repackaged file and the original
        nchanges =  filediff.diffcount(elf_cpy_fn, elf_out_fn)
        assert nchanges >= expect_file_changes[0], "Updated file differences below bounds ({:d}<{:d}): {:s}".format(nchanges, expect_file_changes[0], elf_inp_fn)
        assert nchanges <= expect_file_changes[1], "Updated file differences above bounds ({:d}>{:d}): {:s}".format(nchanges, expect_file_changes[1], elf_inp_fn)
    pass


@pytest.mark.order(3) # must be run after test_bin_archives_xv4_extract
@pytest.mark.fw_xv4
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    #('out/gl300abc-radio_control',3,), # Currently we do not have anything to extract from the m1300 modules in this directory
    #('out/gl300e-radio_control',1,), # There is m1300 in one of these firmwares, but it is not SSL'ed TGZ, but OTA ZIP file
    ('out/m600-matrice_600_hexacopter',3,),
    ('out/osmo_fc550-osmo_x5_gimbal',3,),
    ('out/osmo_fc550r-osmo_x5raw_gimbal',3,),
    ('out/osmo-osmo_x3_gimbal',3,),
    ('out/p3s-phantom_3_adv_quadcopter',3,),
    ('out/p3x-phantom_3_pro_quadcopter',3,),
    ('out/wm610_fc550-t600_inspire_1_pro_x5_quadcopter',3,),
    ('out/wm610-t600_inspire_1_x3_quadcopter',3,),
  ] )
def test_dm3xx_encode_usb_hardcoder_ckmod(capsys, modl_inp_dir, test_nth):
    """ Test extraction and re-applying of hard-coded properties within ELFs.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    elf_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*-split1/*_m0800-extr1/**/bin/encode_usb".format(modl_inp_dir),
        "{}/*-split1/*_m1300-extr1/**/bin/usbclient".format(modl_inp_dir),
    ) ]) if os.path.isfile(fn)]

    # Remove unsupported m1300 files
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*WM610_FW_V01[.]02[.]01[.][0-9A-Z_.-]*_m1300-extr1.*$', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*WM610_FW_V01[.]03[.]00[.]00_m1300-extr1.*$', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*P3X_FW_V01[.]0[1-4][.][0-9A-Z_.-]*_m1300-extr1.*$', fn, re.IGNORECASE)]
    elf_inp_filenames = [fn for fn in elf_inp_filenames if not re.match(r'^.*P3S_FW_V01[.]0[1-4][.][0-9A-Z_.-]*_m1300-extr1.*$', fn, re.IGNORECASE)]

    if len(elf_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for elf_inp_fn in elf_inp_filenames[::test_nth]:
        case_dm3xx_encode_usb_hardcoder_ckmod(elf_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass
