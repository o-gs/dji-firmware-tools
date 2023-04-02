# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, amba_fwpak script.

    This test verifies functions of the script by extracting the
    amba modules, re-packing them and checking if the resulting
    files are identical.

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
from amba_fwpak import main as amba_fwpak_main


LOGGER = logging.getLogger(__name__)


def case_amba_fwpak_rebin(modl_inp_fn):
    """ Test case for extraction and re-creation of BIN package files.
    """
    LOGGER.info("Testcase file: {:s}".format(modl_inp_fn))
    # Most files we are able to recreate with full accuracy
    expect_file_changes = 0
    extra_cmdopts = ""

    # Special cases - ignoring differences for some specific files
    if (re.match(r'^.*_m0101[.]bin', modl_inp_fn, re.IGNORECASE)):
        # Only application format is fully supported, the loader binaries will re-create with a few (8?) different bytes
        LOGGER.warning("Expected non-identical binary due to loader format differences: {:s}".format(modl_inp_fn))
        expect_file_changes = 12
        extra_cmdopts = "-f" # Some checksums do not match
    elif (re.match(r'^.*WM610_FW_V01[.]02[.]01[.]0[3-6][0-9a-z_.-]*_m0100[.]bin', modl_inp_fn, re.IGNORECASE)):
        # The padding in re-created file is different than in original
        LOGGER.warning("Expected non-identical binary due to padding length differences: {:s}".format(modl_inp_fn))
        expect_file_changes = 999999
        extra_cmdopts = "-f" # Some checksums do not match

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
    command = [os.path.join(".", "amba_fwpak.py"), "-vv"] + shlex.split(extra_cmdopts) + ["-x", "-m", modl_inp_fn, "-t", pfx_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        amba_fwpak_main()
    # Re-pack the package
    command = [os.path.join(".", "amba_fwpak.py"), "-vv"] + shlex.split(extra_cmdopts) + ["-a", "-t", pfx_out_fn, "-m", modl_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        amba_fwpak_main()
    if expect_file_changes == 0:
        # Compare repackaged file and the original byte-to-byte, do not count differences
        match =  filecmp.cmp(modl_inp_fn, modl_out_fn, shallow=False)
        assert match, "Re-created file different: {:s}".format(modl_inp_fn)
    elif expect_file_changes == 999999:
        # Check only if repackaged file size roughly matches the original
        modl_inp_fsize = os.path.getsize(modl_inp_fn)
        modl_out_fsize = os.path.getsize(modl_out_fn)
        assert modl_out_fsize >= int(modl_inp_fsize * 0.95), "Re-created file too small: {:s}".format(modl_inp_fn)
        assert modl_out_fsize <= int(modl_inp_fsize * 1.05), "Re-created file too large: {:s}".format(modl_inp_fn)
    else:
        # Count byte differences between repackaged file and the original
        nchanges =  filediff.diffcount(modl_inp_fn, modl_out_fn)
        assert nchanges <= expect_file_changes, "Re-created file exceeded differences ({:d}>{:d}): {:s}".format(nchanges, expect_file_changes, modl_inp_fn)
    pass


def case_amba_fwpak_search_extract(modl_inp_fn):
    """ Test case for searching partitions in not fully supported Ambarella BIN package files.
    """
    LOGGER.info("Testcase file: {:s}".format(modl_inp_fn))
    # Most files we are able to recreate with full accuracy
    expect_file_changes = 0
    extra_cmdopts = ""

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
    # Extract the package
    command = [os.path.join(".", "amba_fwpak.py"), "-vv"] + shlex.split(extra_cmdopts) + ["-s", "-m", modl_inp_fn, "-t", pfx_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        amba_fwpak_main()
    pass


# the extractor currently does not support the new LZ4-compressed files (ie. out/osmo_action-sport_cam, out/hg211-osmo_pocket_2)
@pytest.mark.order(2) # must be run after test_dji_xv4_fwcon_rebin
@pytest.mark.fw_xv4
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/m600-matrice_600_hexacopter',2,),
    ('out/osmo_fc350z-osmo_zoom_z3_gimbal',2,),
    ('out/osmo_fc550-osmo_x5_gimbal',2,),
    ('out/osmo_fc550r-osmo_x5raw_gimbal',2,),
    ('out/osmo-osmo_x3_gimbal',2,),
    ('out/p3c-phantom_3_std_quadcopter',2,),
    #('out/p3se-phantom_3_se_quadcopter',2,), # the format here is clearly very similar, but still different - not supported ATM
    ('out/p3s-phantom_3_adv_quadcopter',2,),
    ('out/p3x-phantom_3_pro_quadcopter',2,),
    ('out/p3xw-phantom_3_4k_quadcopter',2,),
    ('out/wm610_fc350z-t600_inspire_1_z3_quadcopter',2,),
    ('out/wm610_fc550-t600_inspire_1_pro_x5_quadcopter',2,),
    ('out/wm610-t600_inspire_1_x3_quadcopter',2,),
  ] )
def test_amba_fwpak_xv4_rebin(capsys, modl_inp_dir, test_nth):
    """ Test extraction and re-creation of BIN package files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*-split1/*_m0100.bin".format(modl_inp_dir),
        "{}/*-split1/*_m0101.bin".format(modl_inp_dir),
    ) ]) if os.path.isfile(fn)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for modl_inp_fn in modl_inp_filenames[::test_nth]:
        case_amba_fwpak_rebin(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(3) # must be run after test_bin_single_compressed_xv4_extract
@pytest.mark.fw_xv4
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/hg211-osmo_pocket_2',2,),
    ('out/osmo_action-sport_cam',2,),
    ('out/ot110-osmo_pocket_gimbal',2,),
  ] )
def test_amba_fwpak_xv4_unpacked_search_extract(capsys, modl_inp_dir, test_nth):
    """ Test search-based extraction of BIN package files with not fully supported Ambarella format.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*-split1/*_m0100.unpack.bin".format(modl_inp_dir),
        "{}/*-split1/*_m0101.unpack.bin".format(modl_inp_dir),
    ) ]) if os.path.isfile(fn)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for modl_inp_fn in modl_inp_filenames[::test_nth]:
        case_amba_fwpak_search_extract(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(2) # must be run after test_dji_xv4_fwcon_rebin
@pytest.mark.fw_xv4
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/p3se-phantom_3_se_quadcopter',2,),
  ] )
def test_amba_fwpak_xv4_search_extract(capsys, modl_inp_dir, test_nth):
    """ Test search-based extraction of BIN package files with not fully supported Ambarella format.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*-split1/*_m0100.bin".format(modl_inp_dir),
        "{}/*-split1/*_m0101.bin".format(modl_inp_dir),
    ) ]) if os.path.isfile(fn)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for modl_inp_fn in modl_inp_filenames[::test_nth]:
        case_amba_fwpak_search_extract(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass
