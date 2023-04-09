# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, amba_romfs script.

    This test verifies functions of the script by extracting the
    amba partition, re-packing it and checking if the resulting
    files are identical.

    This test requires partitions to already be extracted from the
    amba module.
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
import shlex
import sys
import pathlib
import pytest
from unittest.mock import patch

# Import the functions to be tested
sys.path.insert(0, './')
import filediff
from amba_romfs import main as amba_romfs_main


LOGGER = logging.getLogger(__name__)


def case_amba_romfs_rebin(part_inp_fn):
    """ Test case for extraction and re-creation of BIN partition files.
    """
    LOGGER.info("Testcase file: {:s}".format(part_inp_fn))
    # Most files we are able to recreate with full accuracy
    expect_file_changes = 0
    extra_cmdopts = ""

    # Special cases - ignoring differences for some specific files
    # no special cases currently needed

    inp_path, inp_filename = os.path.split(part_inp_fn)
    inp_path = pathlib.Path(inp_path)
    inp_basename, part_fileext = os.path.splitext(inp_filename)
    if len(inp_path.parts) > 1:
        out_path = os.sep.join(["out"] + list(inp_path.parts[1:]))
    else:
        out_path = "out"
    snglfiles_path1 = os.sep.join([out_path, "{:s}-split1".format(inp_basename)])
    if not os.path.exists(snglfiles_path1):
        os.makedirs(snglfiles_path1)
    part_out_fn = os.sep.join([out_path, "{:s}.repack.bin".format(inp_basename)])
    # Extract the package
    command = [os.path.join(".", "amba_romfs.py"), "-vv"] + shlex.split(extra_cmdopts) + ["-x", "-p", part_inp_fn, "-d", snglfiles_path1]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        amba_romfs_main()
    # Re-pack the package
    command = [os.path.join(".", "amba_romfs.py"), "-vv"] + shlex.split(extra_cmdopts) + ["-a", "-d", snglfiles_path1, "-p", part_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        amba_romfs_main()
    if expect_file_changes == 0:
        # Compare repackaged file and the original byte-to-byte, do not count differences
        match =  filecmp.cmp(part_inp_fn, part_out_fn, shallow=False)
        assert match, "Re-created file different: {:s}".format(part_inp_fn)
    elif expect_file_changes == 999999:
        # Check only if repackaged file size roughly matches the original
        part_inp_fsize = os.path.getsize(part_inp_fn)
        part_out_fsize = os.path.getsize(part_out_fn)
        assert part_out_fsize >= int(part_inp_fsize * 0.95), "Re-created file too small: {:s}".format(part_inp_fn)
        assert part_out_fsize <= int(part_inp_fsize * 1.05), "Re-created file too large: {:s}".format(part_inp_fn)
    else:
        # Count byte differences between repackaged file and the original
        nchanges =  filediff.diffcount(part_inp_fn, part_out_fn)
        assert nchanges <= expect_file_changes, "Re-created file exceeded differences ({:d}>{:d}): {:s}".format(nchanges, expect_file_changes, part_inp_fn)
    pass


@pytest.mark.order(3) # must be run after test_amba_fwpak_xv4_rebin
@pytest.mark.fw_xv4
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/m600-matrice_600_hexacopter',2,),
    ('out/osmo_fc350z-osmo_zoom_z3_gimbal',2,),
    ('out/osmo_fc550-osmo_x5_gimbal',2,),
    ('out/osmo_fc550r-osmo_x5raw_gimbal',2,),
    ('out/osmo-osmo_x3_gimbal',2,),
    ('out/p3c-phantom_3_std_quadcopter',2,),
    ('out/p3se-phantom_3_se_quadcopter',2,),
    ('out/p3s-phantom_3_adv_quadcopter',2,),
    ('out/p3x-phantom_3_pro_quadcopter',2,),
    ('out/p3xw-phantom_3_4k_quadcopter',2,),
    ('out/wm610_fc350z-t600_inspire_1_z3_quadcopter',2,),
    ('out/wm610_fc550-t600_inspire_1_pro_x5_quadcopter',2,),
    ('out/wm610-t600_inspire_1_x3_quadcopter',2,),
  ] )
def test_amba_romfs_xv4_rebin(capsys, modl_inp_dir, test_nth):
    """ Test extraction and re-creation of BIN package files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    part_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*-split1/*_m0100-split1/*part_rom_fw.a9s".format(modl_inp_dir),
    ) ]) if os.path.isfile(fn)]

    if len(part_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for part_inp_fn in part_inp_filenames[::test_nth]:
        case_amba_romfs_rebin(part_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass
