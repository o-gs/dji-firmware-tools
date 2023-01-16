# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, dm3xx_encode_usb_hardcoder script.

    This test verifies functions of the script by extracting the
    hard-coded values from ELF, applying modifications, and re-applying
    them, finally checking if the resulting files have expected
    amount of changes.

    This test requires modules to already be extracted from their
    packagges, and specific modules used here to be converted to ELF.
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


def case_dm3xx_encode_usb_hardcoder_ckmod(modl_inp_fn):
    """ Test case for extraction and re-applying of hard-coded properties within ELFs.
    """
    LOGGER.info("Testcase file: {:s}".format(modl_inp_fn))
    # Most files we are able to recreate with full accuracy
    expect_json_changes = 99
    expect_file_changes = [0,0]

    # Special cases - setting certain params and error tolerance for specific files
    if (modl_inp_fn.endswith("_m0800.bin")):
        elf_base_name = "encode_usb"
        expect_json_changes = 1 # only startup_encrypt_check_always_pass
        expect_file_changes = [1, 16]
    if (modl_inp_fn.endswith("_m1300.bin")):
        # There are currently no supported cases for m1300
        elf_base_name = "usbclient"
        expect_json_changes = 99
        expect_file_changes = [0, 0]

    inp_path, inp_filename = os.path.split(modl_inp_fn)
    inp_path = pathlib.Path(inp_path)
    inp_basename, modl_fileext = os.path.splitext(inp_filename)
    if len(inp_path.parts) > 1:
        out_path = os.sep.join(["out"] + list(inp_path.parts[1:]))
    else:
        out_path = "out"
    tgz_inp_fn = os.sep.join([out_path, "{:s}.decrypted.tar.gz".format(inp_basename)])
    elf_inp_fn = os.sep.join([out_path, "{:s}-{:s}.elf".format(inp_basename, elf_base_name)])
    elf_out_fn = os.sep.join([out_path, "{:s}-{:s}.mod.elf".format(inp_basename, elf_base_name)])
    json_ori_fn = os.sep.join([out_path, "{:s}-{:s}.json".format(inp_basename, elf_base_name)])
    json_mod_fn = os.sep.join([out_path, "{:s}-{:s}.mod.json".format(inp_basename, elf_base_name)])

    # Decrypt the TGZ file
    command = ["openssl", "des3", "-md", "md5", "-d", "-k", "Dji123456", "-in", modl_inp_fn, "-out", tgz_inp_fn]
    LOGGER.info(' '.join(command))
    subprocess.run(command)

    # Now we need to extract our ELF from that TGZ
    # First, find the path and name of our encode_usb
    command = ["tar", "-ztf", tgz_inp_fn]
    LOGGER.info(' '.join(command))
    procret = subprocess.run(command, capture_output=True, text=True)
    match = re.search(r'^.*\/{:s}$'.format(elf_base_name), procret.stdout, flags=re.MULTILINE)
    assert match, "File `{:s}` not found within TGZ content: {:s}".format(elf_base_name, tgz_inp_fn)
    elf_raw_inp_fn = match.group(0)
    # Extract the TGZ file
    command = ["tar", "-zxf", tgz_inp_fn, "-C", out_path, elf_raw_inp_fn]
    LOGGER.info(' '.join(command))
    subprocess.run(command)
    # Move the ELF file into proper place, and rename
    shutil.move(os.sep.join([out_path, elf_raw_inp_fn]), elf_inp_fn)

    # Create json file with recognized hard-coded values
    command = [os.path.join(".", "dm3xx_encode_usb_hardcoder.py"), "-vvv", "-x", "-e", elf_inp_fn, "-o", json_ori_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        dm3xx_encode_usb_hardcoder_main()

    # Modify the JSON
    with open(json_ori_fn) as valfile:
        params_list = json.load(valfile)
    nchanges = 0
    for par in params_list:
        if re.match(r'^og_hardcoded[.]p3x_dm3xx[.]startup_encrypt_check_always_pass$', par['name']):
            par['setValue'] = 1
            nchanges += 1
            continue
    with open(json_mod_fn, "w") as valfile:
        valfile.write(json.dumps(params_list, indent=4))
    assert nchanges >= expect_json_changes, "Performed too few JSON modifications ({:d}<{:d}): {:s}".format(nchanges, expect_json_changes, json_mod_fn)

    # Make copy of the ELF file
    shutil.copyfile(elf_inp_fn, elf_out_fn)
    # Import json file back to elf
    command = [os.path.join(".", "dm3xx_encode_usb_hardcoder.py"), "-vvv", "-u", "-o", json_mod_fn, "-e", elf_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        dm3xx_encode_usb_hardcoder_main()

    if True:
        # Count byte differences between repackaged file and the original
        nchanges =  filediff.diffcount(elf_inp_fn, elf_out_fn)
        assert nchanges >= expect_file_changes[0], "Updated file differences below bounds ({:d}<{:d}): {:s}".format(nchanges, expect_file_changes[0], elf_inp_fn)
        assert nchanges <= expect_file_changes[1], "Updated file differences above bounds ({:d}>{:d}): {:s}".format(nchanges, expect_file_changes[1], elf_inp_fn)
    pass

@pytest.mark.order(2) # must be run after test_dji_xv4_fwcon_rebin
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

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*-split1/*_m0800.bin".format(modl_inp_dir),
        "{}/*-split1/*_m1300.bin".format(modl_inp_dir),
    ) ]) if os.path.isfile(fn)]

    # Remove unsupported m1300 files
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*WM610_FW_V01[.]02[.]01[.][0-9A-Z_.-]*_m1300[.]bin', fn, re.IGNORECASE)]
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*WM610_FW_V01[.]03[.]00[.]00_m1300[.]bin', fn, re.IGNORECASE)]
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*P3X_FW_V01[.]0[1-4][.][0-9A-Z_.-]*_m1300[.]bin', fn, re.IGNORECASE)]
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*P3S_FW_V01[.]0[1-4][.][0-9A-Z_.-]*_m1300[.]bin', fn, re.IGNORECASE)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for modl_inp_fn in modl_inp_filenames[::test_nth]:
        case_dm3xx_encode_usb_hardcoder_ckmod(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass
