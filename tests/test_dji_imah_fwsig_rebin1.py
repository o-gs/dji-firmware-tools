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
    if (m := re.match(r'^.*/(ac103)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if False:
            pass # no quirks
        else: # if first level module
            module_cmdopts = "-k PRAK-2020-01 -k UFIE-9999-99 -f" # unsupported signature_size=384 - forcing extract
            module_changes_limit = 999999 # we can not re-create signature
    elif (m := re.match(r'^.*/(ag406|ag407|ag408|ag410|ag411)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0801_[^/]*[.]fw_0801.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-01 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding
            module_changes_limit = 2 + 256 + 3*16
        elif (re.match(r'^.*{:s}_1301_[^/]*[.]fw_1301.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-01 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding, 3x16 unknown additional
            module_changes_limit = 2 + 256 + 3*16 + 3*16
        elif (re.match(r'^.*{:s}_2601_[^/]*[.]fw_2601.*$'.format("ag410"), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-01 -k PUEK-2017-11 -f" # PUEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding, 3x16 unknown additional
            module_changes_limit = 2 + 256 + 3*16 + 3*16
        elif (re.match(r'^.*{:s}_2602_[^/]*[.]fw_2602.*$'.format("ag410"), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-01 -k PUEK-2017-11 -f" # PUEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding, 3x16 unknown additional
            module_changes_limit = 2 + 256 + 3*16 + 3*16
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-01 -k PUEK-2017-11 -f" # PUEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature
            module_changes_limit = 2 + 256
    elif (m := re.match(r'^.*/(ag501|ag600|ag601)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0802_[^/]*[.]fw_0802.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2020-01 -k TBIE-2020-02 -f" # TBIE not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 6x16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 6*16 + 32
        # specific first level modules with encrypted data checksum verification issues
        elif (re.match(r'^.*ag600_1202_v01[.]51[.]02[.]19_20220118_mc01[.]pro[.]fw[.]sig$', modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*ag600_2403_v06[.]00[.]01[.]10_20220107_ro02[.]pro[.]fw[.]sig$', modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*ag600_2404_v06[.]01[.]00[.]13_20220107_bd02[.]pro[.]fw[.]sig$', modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*ag600_2607_v00[.]00[.]56[.]06_20220124_0982[.]pro[.]fw[.]sig$', modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*ag600_3002_v01[.]13[.]04[.]05_20220105_mc11[.]pro[.]fw[.]sig$', modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2020-01 -k UFIE-2020-04 -f" # ignore data checksum issue - flaw in our checksum algorithm?
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 2x16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 2*16 + 32
        else: # if first level module
            module_cmdopts = "-k PRAK-2020-01 -k UFIE-2020-04"
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding
            module_changes_limit = 2 + 256 + 3*16
    elif (m := re.match(r'^.*/(ag603)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if False:
            pass # no quirks
        else: # if first level module
            module_cmdopts = "-k PRAK-9999-99 -k UFIE-9999-99 -f" # PRAK not published, UFIE not published
            module_changes_limit = 2 + 256
    elif (m := re.match(r'^.*/(ag700|ag701)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if False:
            pass # no quirks
        else: # if first level module
            module_cmdopts = "-k PRAK-9999-99 -k UFIE-9999-99 -f" # PRAK not published, UFIE not published
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 2*16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 2*16 + 32
    elif (m := re.match(r'^.*/(asvl01)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_1502_[^/]*[.]fw_1502.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2020-01 -k TBIE-2020-02 -f" # TBIE not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 9x16 chunk padding, 32 payload digest, 6x16 unknown additional
            module_changes_limit = 2 + 4 + 4 + 256 + 9*16 + 32 + 6*16
        else: # if first level module
            module_cmdopts = "-k PRAK-2020-01 -k UFIE-2020-04"
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding
            module_changes_limit = 2 + 256 + 3*16
    elif (m := re.match(r'^.*/(ch320)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if False:
            pass # no quirks
        else: # if first level module
            module_cmdopts = "-k PRAK-2020-01 -k UFIE-2020-04"
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding
            module_changes_limit = 2 + 256 + 3*16
    elif (m := re.match(r'^.*/(ec174)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if False:
            pass # no quirks
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-08 -k UFIE-2018-07"
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding
            module_changes_limit = 2 + 256 + 3*16
    elif (m := re.match(r'^.*/(hg330)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if False:
            pass # no quirks
        else: # if first level module
            module_cmdopts = "-k PRAK-2020-01 -k UFIE-9999-99 -f" # unsupported signature_size=384 - forcing extract
            module_changes_limit = 999999 # we can not re-create signature
    elif (m := re.match(r'^.*/(pm320)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0702_[^/]*[.]fw_0702.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2020-01 -k TBIE-2020-02 -f" # TBIE not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 9x16 chunk padding, 32 payload digest, 6x16 unknown additional
            module_changes_limit = 2 + 4 + 4 + 256 + 9*16 + 32 + 6*16
        elif (re.match(r'^.*{:s}_0802_[^/]*[.]fw_0802.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2020-01 -k TBIE-2020-02 -f" # TBIE not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding
            module_changes_limit = 2 + 256 + 3*16
        # specific first level modules with unsupported signature_size=384
        elif (re.match(r'^.*pm320_2805_v[0-9a-z_.-]*[.]pro[.]fw[.]sig$', modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2020-01 -k UFIE-2020-04 -f"
            module_changes_limit = 999999 # we can not re-create signature
        else: # if first level module
            module_cmdopts = "-k PRAK-2020-01 -k UFIE-2020-04"
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 2*16 chunk padding
            module_changes_limit = 2 + 4 + 4 + 256 + 2*16
    elif (m := re.match(r'^.*/(rc230)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if False:
            pass # no quirks
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-12 -k PUEK-2017-07" # PUEK is not used
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 32+16
    elif (m := re.match(r'^.*/(rc240)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_1301_[^/]*[.]fw_1301.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-12 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding, 3x16 unknown additional
            module_changes_limit = 2 + 256 + 3*16 + 3*16
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-12 -k UFIE-2018-07"
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 32+16
    elif (m := re.match(r'^.*/(rc430|rm330)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_1301_[^/]*[.]fw_1301.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2020-01 -k TBIE-2020-02 -f" # TBIE not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 6x16 chunk padding
            module_changes_limit = 2 + 4 + 4 + 256 + 6*16
        else: # if first level module
            module_cmdopts = "-k PRAK-2020-01 -k UFIE-2020-04"
            # allow change of 2 bytes from auth key name, 256 from signature, up to 16 chunk padding
            module_changes_limit = 2 + 256 + 16
    elif (m := re.match(r'^.*/(tp703)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_1301_[^/]*[.]fw_1301.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-12 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding, 3x16 unknown additional
            module_changes_limit = 2 + 256 + 3*16 + 3*16
        elif (re.match(r'^.*{:s}_1407_[^/]*[.]fw_1407.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-12 -k PUEK-2017-01"
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding
            module_changes_limit = 2 + 256 + 3*16
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-12 -k PUEK-2017-11" # PUEK is not used
            # allow change of 2 bytes from auth key name, 256 from signature
            module_changes_limit = 2 + 256
    elif (m := re.match(r'^.*/(xw607)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0801_[^/]*[.]fw_0801.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-12 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding
            module_changes_limit = 2 + 256 + 3*16
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-12 -k PUEK-2017-11 -f" # PUEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature
            module_changes_limit = 2 + 256
    elif (m := re.match(r'^.*/(gl811|glass_re|zv811_gl|zv811)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0801_[^/]*[.]fw_0801.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-12 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding, 3x16 unknown additional
            module_changes_limit = 2 + 256 + 3*16 + 3*16
        elif (re.match(r'^.*{:s}_2801_[^/]*[.]fw_2801.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-12 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding, 3x16 unknown additional
            module_changes_limit = 2 + 256 + 3*16 + 3*16
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-12 -k PUEK-2017-11 -f" # PUEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature
            module_changes_limit = 2 + 256
    elif (m := re.match(r'^.*/(pm410)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0801_[^/]*[.]fw_0801.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-12 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding, 3x16 unknown additional
            module_changes_limit = 2 + 256 + 3*16 + 3*16
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-12 -k PUEK-2017-11 -f" # PUEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature
            module_changes_limit = 2 + 256
    elif (m := re.match(r'^.*/(pm420)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0801_[^/]*[.]fw_0801.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-12 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding, 3x16 unknown additional
            module_changes_limit = 2 + 256 + 3*16 + 3*16
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-12 -k PUEK-2017-07"
            # allow change of 2 bytes from auth key name, 256 from signature
            module_changes_limit = 2 + 256
    elif (m := re.match(r'^.*/(rc-n1-wm260)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if False:
            pass # no quirks
        else: # if first level module or nested within m1301
            module_cmdopts = "-k PRAK-2018-01 -k TBIE-2020-04"
            # allow change of 2 bytes from auth key name, 256 from signature, up to 16 chunk padding
            module_changes_limit = 2 + 256 + 16
    elif (m := re.match(r'^.*/(wm330)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0801_[^/]*[.]fw_0801.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-01 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding
            module_changes_limit = 2 + 256 + 3*16
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-01 -k PUEK-2017-07"
            # allow change of 2 bytes from auth key name, 256 from signature
            module_changes_limit = 2 + 256
    elif (m := re.match(r'^.*/(wm331|wm332|wm333|wm334|wm336)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0801_[^/]*[.]fw_0801.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-01 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding
            module_changes_limit = 2 + 256 + 3*16
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-01 -k PUEK-2017-11 -f" # PUEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 256 + 16+32
    elif (m := re.match(r'^.*/(wm335)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0100_[^/]*[.]fw_0100.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k RRAK -k RAEK-9999-99 -f" # RAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature
            module_changes_limit = 2 + 256
        elif (re.match(r'^.*{:s}_0801_[^/]*[.]fw_0801.*$'.format(platform), modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*{:s}_1301_[^/]*[.]fw_1301.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-01 -k IAEK-9999-99 -f" # TODO verify
            # allow change of 2 bytes from auth key name, 256 from signature
            module_changes_limit = 2 + 256
        else: # if first level module or nested within m1301
            module_cmdopts = "-k PRAK-2017-01 -k PUEK-2017-07"
            # allow change of 2 bytes from auth key name, 256 from signature
            module_changes_limit = 2 + 256
    elif (m := re.match(r'^.*/(wm100|rc002)[a]?([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0801_[^/]*[.]fw_0801.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-01 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding
            module_changes_limit = 2 + 256 + 3*16
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-01 -k PUEK-2017-09 -f" # PUEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature
            module_changes_limit = 2 + 256
    elif (m := re.match(r'^.*[/-](wm620|rc001)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0801_[^/]*[.]fw_0801.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-01 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding
            module_changes_limit = 2 + 256 + 3*16
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-01 -k PUEK-2017-09 -f" # PUEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 4 from enc checksum, 256 from signature
            module_changes_limit = 2 + 4 + 256
    elif (m := re.match(r'^.*/(wm170|wm231|wm232|gl170|pm430|ag500)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0701_[^/]*[.]fw_0701.*$'.format(platform), modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*{:s}_0801_[^/]*[.]fw_0801.*$'.format(platform), modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*{:s}_0802_[^/]*[.]fw_0802.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2020-01 -k TBIE-2020-02 -f" # TBIE not published, for boot images (m080?/280?) forcing extract encrypted
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 11x16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 11*16 + 32
        else: # if first level module
            module_cmdopts = "-k PRAK-2020-01 -k UFIE-2020-04"
            # allow change of 2 bytes from auth key name, 4 from enc checksum, 256 from signature
            module_changes_limit = 2 + 4 + 256
    elif (m := re.match(r'^.*/(rcss170|rcjs170|rcs231|rc-n1-wm161b)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if False:
            pass # no quirks
        else: # if first level module
            module_cmdopts = "-k PRAK-2018-02 -k TBIE-2020-04 -f" # PRAK not published, forcing ignore signature fail; modules not encrypted, boot images encrypted
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 32+16
    elif (m := re.match(r'^.*/(gl150|wm150|lt150)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if False:
            pass # no quirks
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-08 -k UFIE-2018-07 -k TBIE-2018-07"
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 32+16
    elif (m := re.match(r'^.*/(rc160)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if False:
            pass # no quirks
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-12 -k PUEK-2017-11 -f" # PUEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature
            module_changes_limit = 2 + 256
    elif (m := re.match(r'^.*/(wm160)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0100_[^/]*[.]fw_0100.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2019-09 -k TBIE-2019-11 -k TKIE-2019-11"
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 9x16 chunk padding, 32 payload digest, 6x16 unknown additional
            module_changes_limit = 2 + 4 + 4 + 256 + 9*16 + 32 + 6*16
        else: # if first level module
            module_cmdopts = "-k PRAK-2019-09 -k UFIE-2019-11"
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 1x16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 1*16 + 32
    elif (m := re.match(r'^.*/(wm1605)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0100_[^/]*[.]fw_0100.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2019-09 -k TBIE-2021-06 -k TKIE-2021-06"
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding
            module_changes_limit = 2 + 256 + 3*16
        else:
            module_cmdopts = "-k PRAK-2019-09 -k UFIE-2021-06"
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 32+16
    elif (m := re.match(r'^.*/(wm161)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0100_[^/]*[.]fw_0100.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2019-09 -k TBIE-2019-11 -k TKIE-2019-11"
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 9x16 chunk padding, 32 payload digest, 6x16 unknown additional
            module_changes_limit = 2 + 4 + 4 + 256 + 9*16 + 32 + 6*16
        else: # if first level module
            module_cmdopts = "-k PRAK-2019-09 -k UFIE-2019-11"
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 32+16
    elif (m := re.match(r'^.*/(wm162)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if False:
            pass # no quirks
        else: # if first level module
            module_cmdopts = "-k PRAK-9999-99 -k UFIE-9999-99 -f" # PRAK not published, UFIE not published
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 2x16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 2*16 + 32
    elif (m := re.match(r'^.*/(wm169)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if False:
            pass # no quirks
        else: # if first level module
            module_cmdopts = "-k PRAK-2019-09 -k UFIE-9999-99 -f" # unsupported signature_size=384 - forcing extract
            module_changes_limit = 999999 # we can not re-create signature
    elif (m := re.match(r'^.*/(wm1695)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if False:
            pass # no quirks
        else: # if first level module
            module_cmdopts = "-k PRAK-2019-09 -k UFIE-9999-99 -f" # unsupported signature_size=384 - forcing extract
            module_changes_limit = 999999 # we can not re-create signature
    elif (m := re.match(r'^.*/(wm220)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0801_[^/]*[.]fw_0801.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-01 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding
            module_changes_limit = 2 + 256 + 3*16
        elif (re.match(r'^.*{:s}_0907_v4[0-6][^/]*[.]fw_0907.*$'.format(platform), modl_inp_fn, re.IGNORECASE) or # FW packages up to v01.03.0400
          re.match(r'^.*{:s}_0907_v47[.]26[.]02[.][1][0-7][^/]*[.]fw_0907.*$'.format(platform), modl_inp_fn, re.IGNORECASE)): # FW package v01.03.0700+
            module_cmdopts = "-k PRAK-2017-01 -k PUEK-2017-01"
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding, 3x16 unknown additional
            module_changes_limit = 2 + 256 + 3*16 + 3*16
        elif (re.match(r'^.*{:s}_0907_v47[^/]*[.]fw_0907.*$'.format(platform), modl_inp_fn, re.IGNORECASE)): # FW package v01.04.0000+
            module_cmdopts = "-k PRAK-2017-01 -k PUEK-2017-07"
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding, 3x16 unknown additional
            module_changes_limit = 2 + 256 + 3*16 + 3*16
        elif (re.match(r'^.*{:s}_1407_v4[0-6][^/]*[.]fw_1407.*$'.format(platform), modl_inp_fn, re.IGNORECASE) or # RC FW packages up to v01.03.0400
          re.match(r'^.*{:s}_1407_v47[.]26[.]02[.][1][0-7][^/]*[.]fw_1407.*$'.format(platform), modl_inp_fn, re.IGNORECASE)): # RC FW package v01.03.0700+
            module_cmdopts = "-k PRAK-2017-01 -k PUEK-2017-01"
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding, 3x16 unknown additional
            module_changes_limit = 2 + 256 + 3*16 + 3*16
        elif (re.match(r'^.*{:s}_1407_v47[^/]*[.]fw_1407.*$'.format(platform), modl_inp_fn, re.IGNORECASE)): # RC FW package v01.04.0000+
            module_cmdopts = "-k PRAK-2017-01 -k PUEK-2017-07"
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding, 3x16 unknown additional
            module_changes_limit = 2 + 256 + 3*16 + 3*16
        elif (re.match(r'^.*{:s}_1301_[^/]*[.]fw_1301.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-01 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding, 3x16 unknown additional
            module_changes_limit = 2 + 256 + 3*16 + 3*16
        elif (re.match(r'^.*{:s}_2801_[^/]*[.]fw_2801.*$'.format(platform), modl_inp_fn, re.IGNORECASE)): # goggles
            module_cmdopts = "-k PRAK-2017-01 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding, 3x16 unknown additional
            module_changes_limit = 2 + 256 + 3*16 + 3*16
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-01 -k PUEK-2017-07"
            # allow change of 2 bytes from auth key name, 256 from signature
            module_changes_limit = 2 + 256
    elif (m := re.match(r'^.*/(wm222)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0801_[^/]*[.]fw_0801.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-01 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding
            module_changes_limit = 2 + 256 + 3*16
        elif (re.match(r'^.*{:s}_0907_[^/]*[.]fw_0907.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-12 -k PUEK-2017-04 -f" # PUEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding
            module_changes_limit = 2 + 256 + 3*16
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-12 -k PUEK-2017-07" # PUEK is not used
            # allow change of 2 bytes from auth key name, 256 from signature
            module_changes_limit = 2 + 256
    elif (m := re.match(r'^.*/(wm230)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0801_[^/]*[.]fw_0801.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-08 -k TBIE-2018-01 -k FCIE-2018-04 -k TKIE-2018-04 -f" # TBIE, FCIE, TKIE not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 6x16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 6*16 + 32
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-08 -k UFIE-2018-01 -k TBIE-2018-01"
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 32+16
    elif (m := re.match(r'^.*/(wm265e|wm265m|wm265t)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if False:
            pass # no quirks
        else: # if first level module
            module_cmdopts = "-k PRAK-2019-09 -k UFIE-9999-99 -f" # unsupported signature_size=384 - forcing extract
            module_changes_limit = 999999 # we can not re-create signature
    elif (m := re.match(r'^.*/(wm240|wm245|wm246)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0901_[^/]*[.]fw_0901.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-12 -f" # m0901 uses different PRAK; IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding
            module_changes_limit = 2 + 4 + 4 + 256 + 1*16 + 32
        elif (re.match(r'^.*{:s}_0907_[^/]*[.]fw_0907.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-12 -k PUEK-9999-99 -k IAEK-9999-99 -f" # m0907 uses different PRAK; IAEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 1*16 + 32
        elif (re.match(r'^.*V00.01.0852_Mavic2_dji_system/{:s}_[^/]*[.]sig$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k rrak-2018-03 -k ufie-2018-03 -f" # rrak and ufie (which are dev keys) not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 3x16 chunk padding, 3x16 unknown additional
            module_changes_limit = 2 + 256 + 3*16 + 3*16
        else: # if first level module
            module_cmdopts = "-k PRAK-2017-08 -k UFIE-2018-07 -k TBIE-2018-07"
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 1*16 + 32
    elif (m := re.match(r'^.*/(wm247)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if (re.match(r'^.*{:s}_0801_[^/]*[.]fw_0801.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2020-01 -k TBIE-2020-02 -f" # TBIE not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 6x16 chunk padding, 32 payload digest, 3x16 unknown additional
            module_changes_limit = 2 + 256 + 6*16 + 32 + 4*16
        elif (re.match(r'^.*{:s}_0901_[^/]*[.]fw_0901.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-12 -k PUEK-2017-11 -f" # m0901 uses different PRAK; PUEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 1*16 + 32
        elif (re.match(r'^.*{:s}_0907_[^/]*[.]fw_0907.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2017-12 -k PUEK-2017-11 -f" # m0907 uses different PRAK; PUEK not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 256 from signature, up to 16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 1*16 + 32
        else: # if first level module
            module_cmdopts = "-k PRAK-2020-01 -k UFIE-2020-04"
            # allow change of 2 bytes from auth key name, 256 from signature, up to 16 chunk padding
            module_changes_limit = 2 + 256 + 16
    elif (m := re.match(r'^.*/(wm260|wm2605)([.][a-z]*|[_][0-9]{4}.*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        # specific nested modules
        if (re.match(r'^.*{:s}_1502_[^/]*[.]fw_1502.*$'.format(platform), modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2020-01 -k TBIE-2020-02 -f" # TBIE not published, forcing extract encrypted
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 9x16 chunk padding, 32 payload digest, 6x16 unknown additional
            module_changes_limit = 2 + 4 + 4 + 256 + 9*16 + 32 + 6*16
        # specific first level modules with unsupported signature_size=384
        elif (re.match(r'^.*/(wm260|wm2605)_0802_v[0-9a-z_.-]*[.]pro[.]fw[.]sig$', modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2020-01 -k UFIE-2020-04 -f"
            module_changes_limit = 999999 # we can not re-create signature
        # specific first level modules with encrypted data checksum verification issues
        elif (re.match(r'^.*V00[.]20[.]0101_wm260_dji_system/wm260([._].*)?[.]cfg[.]sig$', modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*V01[.]00[.]0100_wm260_dji_system/wm260([._].*)?[.]cfg[.]sig$', modl_inp_fn, re.IGNORECASE)):
            module_cmdopts = "-k PRAK-2020-01 -k UFIE-2020-04 -f" # ignore data checksum issue - flaw in our checksum algorithm?
            # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 2x16 chunk padding, 32 payload digest
            module_changes_limit = 2 + 4 + 4 + 256 + 2*16 + 32
        else: # if first level module
            module_cmdopts = "-k PRAK-2020-01 -k UFIE-2020-04"
            # allow change of 2 bytes from auth key name, 256 from signature, up to 16 chunk padding
            module_changes_limit = 2 + 256 + 16
    elif (m := re.match(r'^.*/(zv900)([._].*)?[.](bin|cfg|enc|fw|img|sig|ta|txt)$', modl_inp_fn, re.IGNORECASE)):
        platform = m.group(1)
        if False:
            pass # no quirks
        else: # if first level module
            module_cmdopts = "-k PRAK-2019-09 -k UFIE-9999-99 -f" # unsupported signature_size=384 - forcing extract
            module_changes_limit = 999999 # we can not re-create signature
    else:
        platform = "unknown"
        module_cmdopts = ""
        module_changes_limit = 2 + 4 + 4 + 256
    return module_cmdopts, module_changes_limit, platform


def modify_head_ini_option(ini_fname, ini_options):
    parser = configparser.ConfigParser()
    with open(ini_fname) as ini_fh:
        parser.read_string("[top]\n" + ini_fh.read())
    for key, val in ini_options:
        parser['top'][key] = val
    with open(ini_fname, 'w') as ini_fh:
       ini_fh.write('\n'.join(['='.join(item) for item in parser.items('top')]))
    del parser


def case_dji_imah_fwsig_rebin(capsys, cmdargs, modl_inp_fn):
    """ Test case for extraction and re-creation of SIG module files.
    """
    LOGGER.info("Testcase file: {:s}".format(modl_inp_fn))

    # Get parameters for specific platforms
    extra_cmdopts, expect_file_changes, platform = get_params_for_dji_imah_fwsig(modl_inp_fn)
    # Ignore padding in images which we have divided into parts
    ignore_inp_end_padding = False
    if (re.match(r'^.*-bootarea_p[0-9]+.*[.]img[.]sig$', modl_inp_fn, re.IGNORECASE) or
     re.match(r'^.*-loader_p[0-9]+.*[.]img[.]sig$', modl_inp_fn, re.IGNORECASE) or
     re.match(r'^.*-normal_p[0-9]+.*[.]img[.]sig$', modl_inp_fn, re.IGNORECASE) or
     re.match(r'^.*-unpack_p[0-9]+.*[.]img[.]sig$', modl_inp_fn, re.IGNORECASE) or
     re.match(r'^.*-part_p[0-9]+.*[.]img[.]sig$', modl_inp_fn, re.IGNORECASE)):
        ignore_inp_end_padding = True

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
    command = [os.path.join(".", "dji_imah_fwsig.py"), "-vv"] + shlex.split(extra_cmdopts) + ["-u", "-i", modl_inp_fn, "-m", pfx_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        dji_imah_fwsig_main()
    # We do not have private parts of auth keys used for signing - use OG community key instead
    # Different signature means we will get up to 256 different bytes in the resulting file
    # Additional 2 bytes of difference is the FourCC - two first bytes of it were changed
    modify_head_ini_option("{:s}_head.ini".format(pfx_out_fn), [('auth_key','SLAK',)])
    # Re-sign the module
    command = [os.path.join(".", "dji_imah_fwsig.py"), "-vv"] + shlex.split(extra_cmdopts) + ["-s", "-m", pfx_out_fn, "-i", modl_out_fn]
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
        assert modl_out_fsize >= int(modl_inp_fsize * 0.95) - 32, "Re-created file too small: {:s}".format(modl_inp_fn)
        if not ignore_inp_end_padding:
            assert modl_out_fsize <= int(modl_inp_fsize * 1.05) + 32, "Re-created file too large: {:s}".format(modl_inp_fn)
    else:
        # Count byte differences between repackaged file and the original
        nchanges = filediff.diffcount(modl_inp_fn, modl_out_fn)
        if ignore_inp_end_padding:
            # Our diffcount counted file size difference as changes; if source was padded, do not count this as changes
            modl_inp_fsize = os.path.getsize(modl_inp_fn)
            modl_out_fsize = os.path.getsize(modl_out_fn)
            if modl_inp_fsize > modl_out_fsize:
                nchanges -= (modl_inp_fsize - modl_out_fsize)
        assert nchanges <= expect_file_changes, "Re-created file exceeded differences ({:d}>{:d}): {:s}".format(nchanges, expect_file_changes, modl_inp_fn)
    if cmdargs.rm_repacks:
        os.remove(modl_out_fn)
    pass


@pytest.mark.order(1)
@pytest.mark.fw_imah_v1
@pytest.mark.parametrize("pkg_inp_dir,test_nth", [
    ('fw_packages/ag406-agras_mg-1a',1,),
    ('fw_packages/ag407-agras_mg-1p-rtk',1,),
    ('fw_packages/ag408-agras_mg-unk',1,),
    ('fw_packages/ag410-agras_t16',1,),
    ('fw_packages/ag411-agras_t20',1,),
    #('fw_packages/ag603-agras_unk_rtk',1,), # had no time to look into
    ('fw_packages/gl811-goggles_racing_ed',1,),
    ('fw_packages/pm410-matrice200',1,),
    ('fw_packages/pm420-matrice200_v2',1,),
    ('fw_packages/rc001-inspire_2_rc',1,),
    ('fw_packages/rc002-spark_rc',1,),
    ('fw_packages/rc160-mavic_mini_rc',1,),
    ('fw_packages/rc220-mavic_rc',1,),
    ('fw_packages/rc230-mavic_air_rc',1,),
    ('fw_packages/rc240-mavic_2_rc',1,),
    ('fw_packages/tp703-aeroscope',1,),
    ('fw_packages/wm100-spark',1,),
    ('fw_packages/wm220-goggles_std',1,),
    ('fw_packages/wm220-mavic',1,),
    ('fw_packages/wm222-mavic_sp',1,),
    ('fw_packages/wm330-phantom_4_std',1,),
    ('fw_packages/wm331-phantom_4_pro',1,),
    ('fw_packages/wm332-phantom_4_adv',1,),
    ('fw_packages/wm334-phantom_4_rtk',1,),
    ('fw_packages/wm335-phantom_4_pro_v2',1,),
    ('fw_packages/wm336-phantom_4_mulspectral',1,),
    ('fw_packages/wm620-inspire_2',1,),
    ('fw_packages/xw607-robomaster_s1',1,),
    ('fw_packages/zv811-occusync_air_sys',1,),
  ] )
def test_dji_imah_fwsig_v1_rebin(capsys, cmdargs, pkg_inp_dir, test_nth):
    """ Test extraction and re-creation of signed IMaH v1 modules from within BIN package files.
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
            case_dji_imah_fwsig_rebin(capsys, cmdargs, os.sep.join([modl_path, modl_inp_fn]))
            capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(4) # must be run after test_bin_archives_imah_v1_extract and test_bin_bootimg_imah_v1_extract
@pytest.mark.fw_imah_v1
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/ag407-agras_mg-1p-rtk',1,),
    ('out/ag408-agras_mg-unk',1,),
    ('out/ag410-agras_t16',1,),
    ('out/ag411-agras_t20',1,),
    ('out/gl811-goggles_racing_ed',1,),
    ('out/pm410-matrice200',1,),
    ('out/pm420-matrice200_v2',1,),
    ('out/rc220-mavic_rc',1,),
    ('out/rc240-mavic_2_rc',1,),
    ('out/tp703-aeroscope',1,),
    ('out/wm100-spark',1,),
    ('out/wm220-goggles_std',1,),
    ('out/wm220-mavic',1,),
    ('out/wm222-mavic_sp',1,),
    ('out/wm330-phantom_4_std',1,),
    ('out/wm331-phantom_4_pro',1,),
    ('out/wm332-phantom_4_adv',1,),
    ('out/wm334-phantom_4_rtk',1,),
    ('out/wm335-phantom_4_pro_v2',1,),
    ('out/wm336-phantom_4_mulspectral',1,),
    ('out/wm620-inspire_2',1,),
    ('out/xw607-robomaster_s1',1,),
    ('out/zv811-occusync_air_sys',1,),
  ] )
def test_dji_imah_fwsig_v1_nested_rebin(capsys, cmdargs, modl_inp_dir, test_nth):
    """ Test extraction and re-creation of signed IMaH v1 images nested within other modules.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e, recursive=True) for e in (
        # output from test_bin_archives_imah_v1_extract
        "{}/*/**/normal.img".format(modl_inp_dir),
        "{}/*/**/recovery.img".format(modl_inp_dir),
        "{}/*/**/modemarm.pro.fw".format(modl_inp_dir),
        "{}/*/**/modemdsp_gnd.pro.fw".format(modl_inp_dir),
        "{}/*/**/modemdsp_uav.pro.fw".format(modl_inp_dir),
        # output from test_bin_bootimg_imah_v1_extract
        "{}/*/*-bootarea_p*.img.sig".format(modl_inp_dir),
        "{}/*/*-normal_p*.img.sig".format(modl_inp_dir),
        "{}/*/*-unpack_p*.img.sig".format(modl_inp_dir),
        "{}/*/*-part_p*.img.sig".format(modl_inp_dir),
      ) ]) if os.path.isfile(fn)]

    # Some nested 'recovery.img' files are standard `ANDROID!` images
    modl_filenames = [fn for fn in modl_filenames if not re.match(r'^.*ag408_1401_v[0-9a-z_.-]*_1401-extr1/recovery[.]img$', fn, re.IGNORECASE)]
    modl_filenames = [fn for fn in modl_filenames if not re.match(r'^.*ag410_1401_v[0-9a-z_.-]*_1401-extr1/recovery[.]img$', fn, re.IGNORECASE)]
    modl_filenames = [fn for fn in modl_filenames if not re.match(r'^.*ag411_0205_v[0-9a-z_.-]*_0205-extr1/recovery[.]img$', fn, re.IGNORECASE)]
    # Some 'normal.img' files consist of several IMaH parts, so only the divided form needs to be tested
    modl_filenames = [fn for fn in modl_filenames if not re.match(r'^.*_2601_v[0-9a-z_.-]*_2601-extr1/normal[.]img$', fn, re.IGNORECASE)]

    if len(modl_filenames) < 1:
        pytest.skip("no package files to test in this directory")

    for modl_inp_fn in modl_filenames:
        case_dji_imah_fwsig_rebin(capsys, cmdargs, modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(1)
@pytest.mark.fw_imah_v2
@pytest.mark.parametrize("pkg_inp_dir,test_nth", [
    ('fw_packages/ac103-osmo_action_2',1,),
    ('fw_packages/ag500-agras_t10',1,),
    ('fw_packages/ag501-agras_t30',1,),
    ('fw_packages/ag600-agras_t40_gimbal',1,),
    ('fw_packages/ag601-agras_t40',1,),
    ('fw_packages/ag700-agras_t25',1,),
    ('fw_packages/ag701-agras_t50',1,),
    ('fw_packages/asvl001-vid_transmission',1,),
    ('fw_packages/ch320-battery_station',1,),
    ('fw_packages/ec174-hassel_x1d_ii_50c_cam',1,),
    ('fw_packages/gl150-goggles_fpv_v1',1,),
    ('fw_packages/gl170-goggles_fpv_v2',1,),
    ('fw_packages/hg330-ronin_4d',1,),
    ('fw_packages/lt150-caddx_vis_air_unit_lt',1,),
    ('fw_packages/pm320-matrice30',1,),
    ('fw_packages/pm430-matrice300',1,),
    ('fw_packages/rc-n1-wm161b-mini_2n3_rc',1,),
    ('fw_packages/rc-n1-wm260-mavic_pro_3',1,),
    ('fw_packages/rc430-matrice300_rc',1,),
    ('fw_packages/rcjs170-racer_rc',1,),
    ('fw_packages/rcs231-mavic_air_2_rc',1,),
    ('fw_packages/rcss170-racer_rc_motion',1,),
    ('fw_packages/rm330-mini_rc_wth_monitor',1,),
    ('fw_packages/wm150-fpv_system',1,),
    ('fw_packages/wm160-mavic_mini',1,),
    ('fw_packages/wm1605-mini_se',1,),
    ('fw_packages/wm161-mini_2',1,),
    ('fw_packages/wm162-mini_3',1,),
    ('fw_packages/wm169-avata',1,),
    ('fw_packages/wm1695-o3_air_unit',1,),
    ('fw_packages/wm170-fpv_racer',1,),
    ('fw_packages/wm230-mavic_air',1,),
    ('fw_packages/wm231-mavic_air_2',1,),
    ('fw_packages/wm232-mavic_air_2s',1,),
    ('fw_packages/wm240-mavic_2',1,),
    ('fw_packages/wm245-mavic_2_enterpr',1,),
    ('fw_packages/wm246-mavic_2_enterpr_dual',1,),
    ('fw_packages/wm247-mavic_2_enterpr_rtk',1,),
    ('fw_packages/wm260-mavic_pro_3',1,),
    ('fw_packages/wm2605-mavic_3_classic',1,),
    ('fw_packages/wm265e-mavic_pro_3_enterpr',1,),
    ('fw_packages/wm265m-mavic_pro_3_mulspectr',1,),
    ('fw_packages/wm265t-mavic_pro_3_thermal',1,),
    ('fw_packages/zv900-goggles_2',1,),
  ] )
def test_dji_imah_fwsig_v2_rebin(capsys, cmdargs, pkg_inp_dir, test_nth):
    """ Test extraction and re-creation of signed IMaH v2 modules from within BIN package files.
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
        # Remove files not really in IMaH format
        if re.match(r'^.*V00[.]05[.]1505_FPV_Racer_RC_Motion_dji_system$', modl_path, re.IGNORECASE):
            modl_filenames = [fn for fn in modl_filenames if not re.match(r'^.*rcss170[0-9a-z_.-]*[.]cfg[.]sig$', fn, re.IGNORECASE)]
        for modl_inp_fn in modl_filenames:
            case_dji_imah_fwsig_rebin(capsys, cmdargs, os.sep.join([modl_path, modl_inp_fn]))
            capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(5) # must be run after test_bin_archives_imah_v2_extract, test_bin_bootimg_imah_v2_extract, test_bin_archives_imah_v2_nested_extract
@pytest.mark.fw_imah_v2
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/ac103-osmo_action_2',1,),
    ('out/ag500-agras_t10',1,),
    ('out/ag501-agras_t30',1,),
    ('out/ag600-agras_t40_gimbal',1,),
    ('out/ag601-agras_t40',1,),
    ('out/ag700-agras_t25',1,),
    ('out/ag701-agras_t50',1,),
    ('out/asvl001-vid_transmission',1,),
    ('out/ch320-battery_station',1,),
    ('out/ec174-hassel_x1d_ii_50c_cam',1,),
    ('out/gl150-goggles_fpv_v1',1,),
    ('out/gl170-goggles_fpv_v2',1,),
    ('out/hg330-ronin_4d',1,),
    ('out/lt150-caddx_vis_air_unit_lt',1,),
    ('out/pm320-matrice30',1,),
    ('out/pm430-matrice300',1,),
    ('out/rc-n1-wm161b-mini_2n3_rc',1,),
    ('out/rc-n1-wm260-mavic_pro_3',1,),
    ('out/rc430-matrice300_rc',1,),
    ('out/rcjs170-racer_rc',1,),
    ('out/rcs231-mavic_air_2_rc',1,),
    ('out/rcss170-racer_rc_motion',1,),
    ('out/rm330-mini_rc_wth_monitor',1,),
    ('out/wm150-fpv_system',1,),
    ('out/wm160-mavic_mini',1,),
    ('out/wm1605-mini_se',1,),
    ('out/wm161-mini_2',1,),
    ('out/wm162-mini_3',1,),
    ('out/wm169-avata',1,),
    ('out/wm1695-o3_air_unit',1,),
    ('out/wm170-fpv_racer',1,),
    ('out/wm230-mavic_air',1,),
    ('out/wm231-mavic_air_2',1,),
    ('out/wm232-mavic_air_2s',1,),
    ('out/wm240-mavic_2',1,),
    ('out/wm245-mavic_2_enterpr',1,),
    ('out/wm246-mavic_2_enterpr_dual',1,),
    ('out/wm247-mavic_2_enterpr_rtk',1,),
    ('out/wm260-mavic_pro_3',1,),
    ('out/wm2605-mavic_3_classic',1,),
    ('out/wm265e-mavic_pro_3_enterpr',1,),
    ('out/wm265m-mavic_pro_3_mulspectr',1,),
    ('out/wm265t-mavic_pro_3_thermal',1,),
    ('out/zv900-goggles_2',1,),
  ] )
def test_dji_imah_fwsig_v2_nested_rebin(capsys, cmdargs, modl_inp_dir, test_nth):
    """ Test extraction and re-creation of signed IMaH v2 images nested within other modules.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e, recursive=True) for e in (
        # output from test_bin_archives_imah_v2_extract
        "{}/*/**/ap.img".format(modl_inp_dir),
        "{}/*/**/cp.img".format(modl_inp_dir),
        "{}/*/**/normal.img".format(modl_inp_dir),
        "{}/*/**/recovery.img".format(modl_inp_dir),
        "{}/*/**/rtos.img".format(modl_inp_dir),
        "{}/*/**/modemarm.pro.fw".format(modl_inp_dir),
        "{}/*/**/modemdsp_gnd.pro.fw".format(modl_inp_dir),
        "{}/*/**/modemdsp_uav.pro.fw".format(modl_inp_dir),
        # output from test_bin_bootimg_imah_v2_extract
        "{}/*/*-bootarea_p*.img.sig".format(modl_inp_dir),
        "{}/*/*-loader_p*.img.sig".format(modl_inp_dir),
        "{}/*/*-unpack_p*.img.sig".format(modl_inp_dir),
        "{}/*/*-part_p*.img.sig".format(modl_inp_dir),
        # output from test_bin_archives_imah_v2_nested_extract
        "{}/*/*-extr1/vendor-extr1/ta/*-*-*0.ta".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/ta/*-*-*1.ta".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/ta/*-*-*2.ta".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/ta/*-*-*3.ta".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/ta/*-*-*4.ta".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/ta/*-*-*5.ta".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/ta/*-*-*6.ta".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/ta/*-*-*7.ta".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/ta/*-*-*8.ta".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/ta/*-*-*9.ta".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/ta/*-*-*a.ta".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/ta/*-*-*b.ta".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/ta/*-*-*c.ta".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/ta/*-*-*d.ta".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/ta/*-*-*e.ta".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/ta/*-*-*f.ta".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/nfz/nfz.fw".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/nfz/nfz.fw.bin".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/modem_firmware/**/ap.img".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/modem_firmware/**/cp.img".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/modem_firmware/**/info.img".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/modem_firmware/**/normal.img".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/firmware/camera/**/*.fw.bin".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/firmware/navigation/**/*.fw.bin".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/firmware/perception/**/*.fw.bin".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/ml/**/*.eng.enc".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/navigation/**/*.eng.enc".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*_0.bin".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*_1.bin".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*_2.bin".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*_3.bin".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*_4.bin".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*_5.bin".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*_6.bin".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*_7.bin".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*_8.bin".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*_9.bin".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*_0.txt".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*bits.txt".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*cfg.txt".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*info.txt".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*len.txt".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*mapping.txt".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*offset.txt".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*pairs.txt".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*pair.txt".format(modl_inp_dir),
        "{}/*/*-extr1/vendor-extr1/model/perception/**/*tag.txt".format(modl_inp_dir),
      ) ]) if os.path.isfile(fn) and os.path.getsize(fn) > 0]

    # Some nested 'recovery.img' files are standard `ANDROID!` images
    modl_filenames = [fn for fn in modl_filenames if not re.match(r'^.*rc430_0205_v[0-9a-z_.-]*_0205-extr1/recovery[.]img$', fn, re.IGNORECASE)]

    # Some vendor files are generally not encrypted
    modl_filenames = [fn for fn in modl_filenames if not re.match(r'^.*-extr1/model/perception/.*/test_img[.]bin$', fn, re.IGNORECASE)]
    # Some vendor files in specific folders are not encrypted
    modl_filenames = [fn for fn in modl_filenames if not re.match(r'^.*pm320_.*-extr1/vendor-extr1/model/perception/pm320_rear_left_propeller_parsing.*$', fn, re.IGNORECASE)]
    modl_filenames = [fn for fn in modl_filenames if not re.match(r'^.*pm430_0[78]01_v10[.]01[.]03[.]18.*_0[78]01-extr1/vendor-extr1/model/.*$', fn, re.IGNORECASE)]

    if len(modl_filenames) < 1:
        pytest.skip("no package files to test in this directory")

    for modl_inp_fn in modl_filenames:
        case_dji_imah_fwsig_rebin(capsys, cmdargs, modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass
