# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, dji_imah_fwsig script.

    This test verifies functions of the script by extracting some
    packages, then unsigning some modules from the inside,
    re-signing them and checking if the resulting files
    are identical.
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
from dji_imah_fwsig import main as dji_imah_fwsig_main


LOGGER = logging.getLogger(__name__)

def case_extract_tarfile(pkg_inp_fn):
    """ Extract TAR package file with firmware modules.

    Returns a list of file names (relative to the extraction path), and the extraction path.
    """
    inp_path, inp_filename = os.path.split(pkg_inp_fn)
    inp_path = pathlib.Path(inp_path)
    inp_basename, pkg_fileext = os.path.splitext(inp_filename)
    if len(inp_path.parts) > 1:
        out_path = os.sep.join(["out"] + list(inp_path.parts[1:]))
    else:
        out_path = "out"
    modules_path1 = os.sep.join([out_path, "{:s}".format(inp_basename)])
    if not os.path.exists(modules_path1):
        os.makedirs(modules_path1)

    modl_fnames = []
    with tarfile.open(pkg_inp_fn) as tarfh:
        # get file names
        modl_fnames = tarfh.getnames()
        # extracting file
        tarfh.extractall(modules_path1)

    return modl_fnames, modules_path1

def get_params_for_dji_imah_fwsig(modl_inp_fn):
    """ From given module file name, figure out required dji_imah_fwsig cmd options.
    """
    module_cmdopts = ""
    module_changes_limit = 0
    nested = {}
    if (re.match(r'^.*(wm220)[._].*[.]sig$', modl_inp_fn, re.IGNORECASE)):
        module_cmdopts = "-k PRAK-2017-01 -k PUEK-2017-07"
        # allow change of 2 bytes from auth key name, 256 from signature
        module_changes_limit = 2 + 256
    elif (re.match(r'^.*(wm330)[._].*[.]sig$', modl_inp_fn, re.IGNORECASE)):
        module_cmdopts = "-k PRAK-2017-01 -k PUEK-2017-07"
        # allow change of 2 bytes from auth key name, 256 from signature
        module_changes_limit = 2 + 256
    elif (re.match(r'^.*(wm331|wm332|wm333|wm334|wm335|wm336)[._].*[.]sig$', modl_inp_fn, re.IGNORECASE)):
        module_cmdopts = "-k PRAK-2017-01 -k PUEK-2017-11 -f" # PUEK not published, forcing extract encrypted
        # allow change of 2 bytes from auth key name, 256 from signature, up to 16 chunk padding, 32 payload digest
        module_changes_limit = 2 + 256 + 16+32
    elif (re.match(r'^.*(wm100|rc002)[._a].*[.]sig$', modl_inp_fn, re.IGNORECASE)):
        module_cmdopts = "-k PRAK-2017-01 -k PUEK-2017-09 -f" # PUEK not published, forcing extract encrypted
        # allow change of 2 bytes from auth key name, 256 from signature
        module_changes_limit = 2 + 256
    elif (re.match(r'^.*(wm620|rc001)[._].*[.]sig$', modl_inp_fn, re.IGNORECASE)):
        module_cmdopts = "-k PRAK-2017-01 -k PUEK-2017-09 -f" # PUEK not published, forcing extract encrypted
        # allow change of 2 bytes from auth key name, 4 from enc checksum, 256 from signature
        module_changes_limit = 2 + 4 + 256
    elif (re.match(r'^.*(wm230)[._].*[.]sig$', modl_inp_fn, re.IGNORECASE)):
        module_cmdopts = "-k PRAK-2017-08 -k UFIE-2018-01 -k TBIE-2018-01"
        # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
        module_changes_limit = 2 + 4 + 4 + 256 + 32+16
    elif (re.match(r'^.*(rc230)[._].*[.]sig$', modl_inp_fn, re.IGNORECASE)):
        module_cmdopts = "-k PRAK-2017-12 -k UFIE-2018-01"
        # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
        module_changes_limit = 2 + 4 + 4 + 256 + 32+16
    elif (re.match(r'^.*(wm170|wm231|wm232|gl170|pm430|ag500)[._].*[.]sig$', modl_inp_fn, re.IGNORECASE)):
        module_cmdopts = "-k PRAK-2020-01 -k UFIE-2020-04 -k TBIE-2020-02" # TBIE not published, boot images decryption (m080?/280?) will fail
        # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
        module_changes_limit = 2 + 4 + 4 + 256 + 32+16
    elif (re.match(r'^.*(rcss170|rcjs170|rcs231|rc-n1-wm161b)[._].*[.]sig$', modl_inp_fn, re.IGNORECASE)):
        module_cmdopts = "-k PRAK-2018-02 -k TBIE-2020-04 -f" # PRAK not published, forcing ignore signature fail; modules not encrypted, boot images encrypted
        # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
        module_changes_limit = 2 + 4 + 4 + 256 + 32+16
    elif (re.match(r'^.*(wm240|wm245|wm246)[._].*[.]sig$', modl_inp_fn, re.IGNORECASE)):
        module_cmdopts = "-k PRAK-2017-08 -k UFIE-2018-07 -k TBIE-2018-07"
        # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
        module_changes_limit = 2 + 4 + 4 + 256 + 32+16
    elif (re.match(r'^.*(gl150|wm150|lt150)[._].*[.]sig$', modl_inp_fn, re.IGNORECASE)):
        module_cmdopts = "-k PRAK-2017-08 -k UFIE-2018-07 -k TBIE-2018-07"
        # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
        module_changes_limit = 2 + 4 + 4 + 256 + 32+16
    elif (re.match(r'^.*(rc240)[._].*[.]sig$', modl_inp_fn, re.IGNORECASE)):
        module_cmdopts = "-k PRAK-2017-12 -k UFIE-2018-07"
        # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
        module_changes_limit = 2 + 4 + 4 + 256 + 32+16
    elif (re.match(r'^.*(wm160)[._].*[.]sig$', modl_inp_fn, re.IGNORECASE)):
        module_cmdopts = "-k PRAK-2019-09 -k UFIE-2019-11"
        # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
        module_changes_limit = 2 + 4 + 4 + 256 + 32+16
    elif (re.match(r'^.*(wm1605)[._].*[.]sig$', modl_inp_fn, re.IGNORECASE)):
        module_cmdopts = "-k PRAK-2019-09 -k UFIE-2021-06"
        # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
        module_changes_limit = 2 + 4 + 4 + 256 + 32+16
    elif (re.match(r'^.*(wm161)[._].*[.]sig$', modl_inp_fn, re.IGNORECASE)):
        module_cmdopts = "-k PRAK-2019-09 -k UFIE-2019-11"
        # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
        module_changes_limit = 2 + 4 + 4 + 256 + 32+16
    else:
        module_cmdopts = ""
        module_changes_limit = 2 + 4 + 4 + 256
    return module_cmdopts, module_changes_limit, nested


def modify_head_ini_option(ini_fname, ini_options):
    parser = configparser.ConfigParser()
    with open(ini_fname) as ini_fh:
        parser.read_string("[top]\n" + ini_fh.read())
    for key, val in ini_options:
        parser['top'][key] = val
    with open(ini_fname, 'w') as ini_fh:
       ini_fh.write('\n'.join(['='.join(item) for item in parser.items('top')]))
    del parser


def case_dji_imah_fwsig_rebin(modl_inp_fn):
    """ Test case for extraction and re-creation of SIG module files.
    """
    LOGGER.info("Testcase file: {:s}".format(modl_inp_fn))

    # Get parameters for specific platforms
    extra_cmdopts, expect_file_changes, nested = get_params_for_dji_imah_fwsig(modl_inp_fn)

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
    pfx_out_fn = os.sep.join([modules_path1, "{:s}".format(inp_basename)]) # prefix for output file names
    modl_out_fn = os.sep.join([out_path, "{:s}.rebin.sig".format(inp_basename)])
    # Unsign/decrypt the module
    command = [os.path.join(".", "dji_imah_fwsig.py"), "-vv", *shlex.split(extra_cmdopts), "-u", "-i", modl_inp_fn, "-m", pfx_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        dji_imah_fwsig_main()
    # We do not have private parts of auth keys used for signing - use OG community key instead
    # Different signature means we will get up to 256 different bytes in the resulting file
    # Additional 2 bytes of difference is the FourCC - two first bytes of it were changed
    modify_head_ini_option("{:s}_head.ini".format(pfx_out_fn), [('auth_key','SLAK',)])
    # Re-sign the module
    command = [os.path.join(".", "dji_imah_fwsig.py"), "-vv", *shlex.split(extra_cmdopts), "-s", "-m", pfx_out_fn, "-i", modl_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        dji_imah_fwsig_main()

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


@pytest.mark.order(1)
@pytest.mark.parametrize("pkg_inp_dir,test_nth", [
    ('fw_packages/wm100-spark',1,),
    ('fw_packages/wm220-mavic',1,),
    ('fw_packages/wm330-phantom_4_std',1,),
    ('fw_packages/wm331-phantom_4_pro',1,),
    ('fw_packages/wm335-phantom_4_pro_v2',1,),
    ('fw_packages/wm620-inspire_2',1,),

  ] )
def test_dji_imah_fwsig_rebin(capsys, pkg_inp_dir, test_nth):
    """ Test extraction and re-creation of signed modules from within BIN package files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    pkg_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e, recursive=True) for e in (
        "{}/*.bin".format(pkg_inp_dir),
      ) ]) if os.path.isfile(fn)]

    if len(pkg_inp_filenames) < 1:
        pytest.skip("no package files to test in this directory")

    for pkg_inp_fn in pkg_inp_filenames:
        modl_filenames, modl_path = case_extract_tarfile(pkg_inp_fn[::test_nth])
        assert len(modl_filenames) >= 2, "The package file contained {:d} files, expeted at least {:d}: {:s}".format(len(modl_filenames), 2, pkg_inp_fn)
        for modl_inp_fn in modl_filenames:
            case_dji_imah_fwsig_rebin(os.sep.join([modl_path, modl_inp_fn]))
            capstdout, _ = capsys.readouterr()
    pass
