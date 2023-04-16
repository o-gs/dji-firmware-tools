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

import filecmp
import glob
import itertools
import logging
import mmap
import os
import re
import sys
import pathlib
import pytest
from unittest.mock import patch

# Import the functions to be tested
sys.path.insert(0, './')
import filediff
from dji_mvfc_fwpak import main as dji_mvfc_fwpak_main


LOGGER = logging.getLogger(__name__)


def is_module_unsigned_encrypted(modl_inp_fn):
    """ Identify if the module was extracted without full decryption.
        If the module data is encrypted, invoking further tests on it makes no sense.
    """
    match = re.search(r'^(.*)_m?([0-9A-Z]{4})[.]bin$', modl_inp_fn, flags=re.IGNORECASE)
    if not match:
        return False
    modl_part_fn = match.group(1)
    modl_ini_fn = "{:s}_head.ini".format(modl_part_fn)
    try:
        with open(modl_ini_fn, 'rb') as fh:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            return mm.find(b"scramble_key_encrypted") != -1
    except Exception:
        LOGGER.info("Could not check INI for: {:s}".format(modl_inp_fn))
        return False


def case_dji_mvfc_fwpak_rebin(capsys, cmdargs, modl_inp_fn):
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
    if cmdargs.rm_repacks:
        os.remove(modl_out_fn)
    pass


@pytest.mark.order(2) # must be run after test_dji_imah_fwsig_v1_rebin
@pytest.mark.fw_imah_v1
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/ag407-agras_mg-1p-rtk',1,),
    ('out/ag408-agras_mg-unk',1,),
    ('out/ag410-agras_t16',1,),
    ('out/pm410-matrice200',1,),
    #('out/pm420-matrice200_v2',1,), # not currently supported - '12345678' format
    ('out/wm100-spark',1,),
    ('out/wm220-mavic',1,),
    ('out/wm222-mavic_sp',1,),
    ('out/wm330-phantom_4_std',1,),
    ('out/wm331-phantom_4_pro',1,),
    ('out/wm332-phantom_4_adv',1,),
    ('out/wm334-phantom_4_rtk',1,),
    ('out/wm335-phantom_4_pro_v2',1,),
    #('out/wm336-phantom_4_mulspectral',1,), # not currently supported - '12345678' format
    ('out/wm620-inspire_2',1,),
    #('out/xw607-robomaster_s1',1,), # not currently supported - '12345678' format
  ] )
def test_dji_mvfc_fwpak_imah_v1_rebin(capsys, cmdargs, modl_inp_dir, test_nth):
    """ Test decryption and re-encryption of FC BIN module files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e, recursive=True) for e in (
        "{}/*/*_0305.bin".format(modl_inp_dir),
        "{}/*/*_0306.bin".format(modl_inp_dir),
      ) ]) if (os.path.isfile(fn) and os.stat(fn).st_size > 0)]

    # Remove files not encrypted to start with
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*ag407_0306_v03[.]03[.]99[.]54.*[.]bin$', fn, re.IGNORECASE)]
    # Some packages have multiple versions of specific modules, with only part of them not supported - '12345678' format
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*ag410_0306_v.*_nk00.*[.]bin$', fn, re.IGNORECASE)]
    # Skip the packages which were extracted in encrypted form (need non-public key)
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not is_module_unsigned_encrypted(fn)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no fc module files to test in this directory")

    for modl_inp_fn in modl_inp_filenames:
        case_dji_mvfc_fwpak_rebin(capsys, cmdargs, modl_inp_fn)
    pass


@pytest.mark.order(2) # must be run after test_dji_imah_fwsig_v2_rebin
@pytest.mark.fw_imah_v2
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    #('out/ag500-agras_t10',1,), # not supported - the m120[0-3] here requires a different key
    #('out/ag501-agras_t30',1,), # not supported - the m120[0-5] here requires a different key
    #('out/ag700-agras_t25',1,), # not supported - the m120[0-3] has 1st level decryption not public
    #('out/ag701-agras_t50',1,), # not supported - the m120[0-7] has 1st level decryption not public
    #('out/pm320-matrice30',1,), # not supported - the m120[0-3] here requires a different key
    #('out/pm430-matrice300',1,), # not supported - the m120[0-3] here requires a different key
    #('out/wm1605-mini_se',1,), # not currently supported - the m0306 in '12345678' format
    #('out/wm160-mavic_mini',1,), # not currently supported - the m0306 in '12345678' format
    #('out/wm161-mini_2',1,), # not currently supported - the m0306 in '12345678' format
    #('out/wm162-mini_3',1,), # not supported - the m120[0-3] has 1st level decryption not public
    #('out/wm169-avata',1,), # not supported - the m120[0-3] has 1st level decryption not public
    #('out/wm231-mavic_air_2',1,), # not supported - the m120[0-3] here requires a different key
    #('out/wm232-mavic_air_2s',1,), # not supported - the m1200/m1202 here requires a different key
    #('out/wm240-mavic_2',1,), # not supported - the m120[0-3] here requires a different key
    #('out/wm245-mavic_2_enterpr',1,), # not supported - the m120[0-3] here requires a different key
    #('out/wm246-mavic_2_enterpr_dual',1,), # not supported - the m120[0-3] here requires a different key
    #('out/wm2605-mavic_3_classic',1,), # not supported - the m1200/m1202 here requires a different key
    #('out/wm260-mavic_pro_3',1,), # not supported - the m1200/m1202 here requires a different key
    #('out/wm265e-mavic_pro_3_enterpr',1,), # not supported - the m120[0-3] has 1st level decryption not public
    #('out/wm265m-mavic_pro_3_mulspectr',1,), # not supported - the m120[0-3] has 1st level decryption not public
    #('out/wm265t-mavic_pro_3_thermal',1,), # not supported - the m120[0-3] has 1st level decryption not public
  ] )
def test_dji_mvfc_fwpak_imah_v2_rebin(capsys, cmdargs, modl_inp_dir, test_nth):
    """ Test decryption and re-encryption of FC BIN module files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e, recursive=True) for e in (
        "{}/*/*_0305.bin".format(modl_inp_dir),
        "{}/*/*_0306.bin".format(modl_inp_dir),
        "{}/*/*_1200.bin".format(modl_inp_dir),
        "{}/*/*_1201.bin".format(modl_inp_dir),
        "{}/*/*_1202.bin".format(modl_inp_dir),
        "{}/*/*_1203.bin".format(modl_inp_dir),
      ) ]) if (os.path.isfile(fn) and os.stat(fn).st_size > 0)]

    # Remove files not encrypted to start with
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*pm430_120[0-3]_v[0-9a-z_.-]*_mc02[.]pro[.]fw_120[0-3][.]bin$', fn, re.IGNORECASE)]
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*wm231_120[0-3]_v[0-9a-z_.-]*_mc03[.]pro[.]fw_120[0-3][.]bin$', fn, re.IGNORECASE)]
    # Skip the packages which were extracted in encrypted form (need non-public key)
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not is_module_unsigned_encrypted(fn)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no fc module files to test in this directory")

    for modl_inp_fn in modl_inp_filenames:
        case_dji_mvfc_fwpak_rebin(capsys, cmdargs, modl_inp_fn)
    pass
