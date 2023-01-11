# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, amba_sys2elf script.

    This test verifies functions of the script by generating elf
    from the system binary, then stripping it back to plain binary,
    and checking in the bin files are identical.

    This test requires sys partitions to already be extracted from their
    modules.
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
import subprocess
import sys
import pathlib
import pytest
from unittest.mock import patch

# Import the functions to be tested
sys.path.insert(0, './')
from amba_sys2elf import main as amba_sys2elf_main


LOGGER = logging.getLogger(__name__)


def case_amba_sys2elf_rebin(modl_inp_fn):
    """ Test case for ELF creation and stripping back to BIN files.
    """
    LOGGER.info("Testcase file: {:s}".format(modl_inp_fn))
    # Most files we are able to recreate with full accuracy
    expect_file_identical = True

    # Special cases - ignoring differences for some specific files
    # Unused - no special cases required, as of now
    if (modl_inp_fn.endswith("XXX_m0100_part_sys.bin")):
        LOGGER.warning("Expected non-identical binary due to XXX differences: {:s}".format(modl_inp_fn))
        expect_file_identical = False

    inp_path, inp_filename = os.path.split(modl_inp_fn)
    inp_path = pathlib.Path(inp_path)
    inp_basename, modl_fileext = os.path.splitext(inp_filename)
    if len(inp_path.parts) > 1:
        out_path = os.sep.join(["out"] + list(inp_path.parts[1:]))
    else:
        out_path = "out"
    elf_out_fn = os.sep.join([out_path, "{:s}.elf".format(inp_basename)]) # prefix for output files
    modl_out_fn = os.sep.join([out_path, "{:s}.rebin.bin".format(inp_basename)])
    # Extract the package
    command = [os.path.join(".", "amba_sys2elf.py"), "-vv", "-e", "-p", modl_inp_fn, "-o", elf_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        amba_sys2elf_main()
    # Re-pack the package
    command = ["arm-none-eabi-objcopy", "-O", "binary", elf_out_fn, modl_out_fn]
    LOGGER.info(' '.join(command))
    subprocess.run(command)
    if expect_file_identical:
        # Compare repackaged file and the original byte-to-byte
        match =  filecmp.cmp(modl_inp_fn, modl_out_fn, shallow=False)
        assert match, "Re-stripped file different: {:s}".format(modl_inp_fn)
    else:
        # Check if repackaged file size roughly matches the original
        modl_inp_fsize = os.path.getsize(modl_inp_fn)
        modl_out_fsize = os.path.getsize(modl_out_fn)
        assert modl_out_fsize >= int(modl_inp_fsize * 0.95), "Re-stripped file too small: {:s}".format(modl_inp_fn)
        assert modl_out_fsize <= int(modl_inp_fsize * 1.05), "Re-stripped file too large: {:s}".format(modl_inp_fn)
    pass

#@pytest.mark.skip(reason="our pyelftools is outdated, requires rebase")
@pytest.mark.order(3) # must be run after test_amba_fwpak_rebin
@pytest.mark.parametrize("modl_inp_dir", [
    'out/m600-matrice_600_hexacopter',
    'out/osmo_fc350z-osmo_zoom_z3_gimbal',
    'out/osmo_fc550-osmo_x5_gimbal',
    'out/osmo_fc550r-osmo_x5raw_gimbal',
    'out/osmo-osmo_x3_gimbal',
    'out/p3c-phantom_3_std_quadcopter',
    'out/p3se-phantom_3_se_quadcopter',
    'out/p3s-phantom_3_adv_quadcopter',
    'out/p3x-phantom_3_pro_quadcopter',
    'out/p3xw-phantom_3_4k_quadcopter',
    'out/wm610_fc350z-t600_inspire_1_z3_quadcopter',
    'out/wm610_fc550-t600_inspire_1_pro_x5_quadcopter',
    'out/wm610-t600_inspire_1_x3_quadcopter',
  ] )
def test_amba_sys2elf_rebin(modl_inp_dir):
    """ Test for ELF creation and stripping back to BIN files.
    """
    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*-split1/*-split1/*_m0100_part_sys.a9s".format(modl_inp_dir),
    ) ]) if os.path.isfile(fn)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for modl_inp_fn in modl_inp_filenames:
        case_amba_sys2elf_rebin(modl_inp_fn)
    pass
