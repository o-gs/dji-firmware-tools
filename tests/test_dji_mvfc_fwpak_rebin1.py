# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, dji_mvfc_fwpak script.

    This test verifies functions of the script by decrypting
    and then re-encrypting the already extracted FC firmware
    binaries, then checking if the resulting files are
    identical.
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

import configparser
import filecmp
import glob
import itertools
import logging
import os
import re
import shlex
import sys
import tarfile
import pathlib
import pytest
from unittest.mock import patch

# Import the functions to be tested
sys.path.insert(0, './')
import filediff
from dji_mvfc_fwpak import main as dji_mvfc_fwpak_main


LOGGER = logging.getLogger(__name__)


def case_dji_mvfc_fwpak_rebin(capsys, modl_inp_fn):
    """ Test case for decryption and re-encryption of FC BIN module files.
    """
    LOGGER.info("Testcase file: {:s}".format(modl_inp_fn))
    # Most files we are able to recreate with full accuracy
    expect_file_changes = 0

    inp_path, inp_filename = os.path.split(modl_inp_fn)
    inp_path = pathlib.Path(inp_path)
    inp_basename, modl_fileext = os.path.splitext(inp_filename)
    if len(inp_path.parts) > 1:
        out_path = os.sep.join(["out"] + list(inp_path.parts[1:]))
    else:
        out_path = "out"
    modules_path1 = out_path # no need for a sub-folder
    if not os.path.exists(modules_path1):
        os.makedirs(modules_path1)
    modl_dec_fn = os.sep.join([out_path, "{:s}.decrypted.bin".format(inp_basename)])
    modl_out_fn = os.sep.join([out_path, "{:s}.reencrypt.bin".format(inp_basename)])
    # Unsign/decrypt the module
    command = [os.path.join(".", "dji_mvfc_fwpak.py"), "-vv", "dec", "-i", modl_inp_fn, "-o", modl_dec_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        dji_mvfc_fwpak_main()
    capstdout, _ = capsys.readouterr()

    match = re.search(r'^.*_(030[5-6])$', inp_basename, flags=re.MULTILINE)
    assert match, "Base name `{:s}` does not identify FC module: {:s}".format(inp_basename, modl_inp_fn)
    mod_ident = match.group(1)

    match = re.search(r'^Version:[ \t]*([0-9A-Za-z. :_-]*)$', capstdout, flags=re.MULTILINE)
    assert match, "Decryptor output for file does not contain version: {:s}".format(modl_inp_fn)
    mod_fwver = match.group(1)

    match = re.search(r'^Time:[ \t]*([0-9A-Za-z. :_-]*)$', capstdout, flags=re.MULTILINE)
    assert match, "Decryptor output for file does not contain timestamp: {:s}".format(modl_inp_fn)
    mod_tmstamp = match.group(1)

    # Re-sign the module
    command = [os.path.join(".", "dji_mvfc_fwpak.py"), "-vv", "enc", "-V", mod_fwver, "-T", mod_tmstamp, "-t", mod_ident, "-i", modl_dec_fn, "-o", modl_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        dji_mvfc_fwpak_main()
    capstdout, _ = capsys.readouterr()

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


@pytest.mark.order(2) # must be run after test_dji_imah_fwsig_rebin
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/wm100-spark',1,),
    ('out/wm220-mavic',1,),
    ('out/wm330-phantom_4_std',1,),
    ('out/wm331-phantom_4_pro',1,),
    #('out/wm335-phantom_4_pro_v2',1,), # decrypting this is not currently supported
    #('out/wm620-inspire_2',1,), # decrypting this is not currently supported
  ] )
def test_dji_mvfc_fwpak_rebin(capsys, modl_inp_dir, test_nth):
    """ Test decryption and re-encryption of FC BIN module files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e, recursive=True) for e in (
        "{}/*/*_0305.bin".format(modl_inp_dir),
        "{}/*/*_0306.bin".format(modl_inp_dir),
      ) ]) if (os.path.isfile(fn) and os.stat(fn).st_size > 0)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no fc module files to test in this directory")

    for modl_inp_fn in modl_inp_filenames:
        case_dji_mvfc_fwpak_rebin(capsys, modl_inp_fn)
    pass
