# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, amba_fwpak script.

    This test verifies functions of the script by extracting the
    amba modules, re-packing them and checking if the resulting
    files are identical.

    This test requires modules to already be extracted from their
    packagges.
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
import logging
import os
import re
import sys
import pathlib
import pytest
from unittest.mock import patch

# Import the functions to be tested
sys.path.insert(0, './')
from amba_fwpak import main as amba_fwpak_main


LOGGER = logging.getLogger(__name__)


def case_amba_fwpak_rebin(modl_inp_fn):
    """ Test case for extraction and re-creation of BIN package files.
    """
    LOGGER.info("Testcase file: {:s}".format(modl_inp_fn))
    # Most files we are able to recreate with full accuracy
    expect_file_identical = True

    # Special cases - ignoring differences for some specific files
    # Only application format is fully supported, the loader binaries will re-create with a few (8?) different bytes
    if (modl_inp_fn.endswith("_m0101.bin")):
        LOGGER.warning("Expected non-identical binary due to loader format differences: {:s}".format(modl_inp_fn))
        expect_file_identical = False
    # The padding in re-created file is different than in original
    if (modl_inp_fn.endswith("WM610_FW_V01.02.01.03_m0100.bin")):
        LOGGER.warning("Expected non-identical binary due to padding length differences: {:s}".format(modl_inp_fn))
        expect_file_identical = False

    inp_path, inp_filename = os.path.split(modl_inp_fn)
    inp_path = pathlib.Path(inp_path)
    inp_basename, modl_fileext = os.path.splitext(inp_filename)
    if len(inp_path.parts) > 1:
        out_path = os.sep.join(["out"] + list(inp_path.parts[1:]))
    else:
        out_path = "out"
    modules_path1 = os.sep.join([out_path, "{:s}-split1".format(inp_basename)])
    if not os.path.exists(modules_path1):
        os.makedirs(modules_path1)
    pfx_out_fn = os.sep.join([modules_path1, "{:s}".format(inp_basename)]) # prefix for output files
    modl_out_fn = os.sep.join([out_path, "{:s}.repack.bin".format(inp_basename)])
    # Extract the package
    command = [os.path.join(".", "amba_fwpak.py"), "-vv", "-x", "-m", modl_inp_fn, "-t", pfx_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        amba_fwpak_main()
    # Re-pack the package
    command = [os.path.join(".", "amba_fwpak.py"), "-vv", "-a", "-t", pfx_out_fn, "-m", modl_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        amba_fwpak_main()
    if expect_file_identical:
        # Compare repackaged file and the original byte-to-byte
        match =  filecmp.cmp(modl_inp_fn, modl_out_fn, shallow=False)
        assert match, "Re-created file different: {:s}".format(modl_inp_fn)
    else:
        # Check if repackaged file size roughly matches the original
        modl_inp_fsize = os.path.getsize(modl_inp_fn)
        modl_out_fsize = os.path.getsize(modl_out_fn)
        assert modl_out_fsize >= int(modl_inp_fsize * 0.95), "Re-created file too small: {:s}".format(modl_inp_fn)
        assert modl_out_fsize <= int(modl_inp_fsize * 1.05), "Re-created file too large: {:s}".format(modl_inp_fn)
    pass

# the extractor currently does not support the new LZ4-compressed files (ie. out/osmo_action-sport_cam, out/hg211-osmo_pocket_2)
@pytest.mark.order(2) # must be run after test_dji_xv4_fwcon_rebin
@pytest.mark.parametrize("modl_inp_dir", [
    'out/m600-matrice_600_hexacopter',
    'out/osmo_fc350z-osmo_zoom_z3_gimbal',
    'out/osmo_fc550-osmo_x5_gimbal',
    'out/osmo_fc550r-osmo_x5raw_gimbal',
    'out/osmo-osmo_x3_gimbal',
    'out/p3c-phantom_3_std_quadcopter',
    #'out/p3se-phantom_3_se_quadcopter', # the format here is clearly very similar, but still different - not supported ATM
    'out/p3s-phantom_3_adv_quadcopter',
    'out/p3x-phantom_3_pro_quadcopter',
    'out/p3xw-phantom_3_4k_quadcopter',
    'out/wm610_fc350z-t600_inspire_1_z3_quadcopter',
    'out/wm610_fc550-t600_inspire_1_pro_x5_quadcopter',
    'out/wm610-t600_inspire_1_x3_quadcopter',
  ] )
def test_amba_fwpak_rebin(modl_inp_dir):
    """ Test extraction and re-creation of BIN package files.
    """
    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*-split1/*_m0100.bin".format(modl_inp_dir),
        "{}/*-split1/*_m0101.bin".format(modl_inp_dir),
    ) ]) if os.path.isfile(fn)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for modl_inp_fn in modl_inp_filenames:
        case_amba_fwpak_rebin(modl_inp_fn)
    pass
