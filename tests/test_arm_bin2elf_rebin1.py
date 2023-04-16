# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, arm_bin2elf script.

    This test verifies functions of the script by generating elf
    from the system binary, then stripping it back to plain binary,
    and checking in the bin files are identical.

    This test requires the plain binaries to already be extracted from their
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
import subprocess
import sys
import pathlib
import pytest
from unittest.mock import patch

# Import the functions to be tested
sys.path.insert(0, './')
from arm_bin2elf import main as arm_bin2elf_main


LOGGER = logging.getLogger(__name__)


def get_params_for_arm_bin2elf(modl_inp_fn):
    """ From given module file name, figure out required arm_bin2elf cmd options.
    """
    file_specific_cmdargs = []
    platform = "unknown"
    # Most files we are able to recreate with full accuracy
    expect_file_changes = 0

    if (modl_inp_fn.endswith("_m0306.bin")): # FC modules from xV4 firmwares
        if (re.match(r'^.*A3_FW_V02[.][0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `A3_FW_V02.00.00.01_m0306.bin`
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x512F74:0",
              "--section", ".bss@0x20400000:0x46000", "--section", ".bss2@0x40000000:0x30000"]
        elif (re.match(r'^.*A3_FW_[0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*A3_OFFICIAL_[0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets for `A3_FW_V??.??.??.??_m0306.bin`, auto-detection of .ARM.exidx works good enough for this
            file_specific_cmdargs = ["-b", "0x00420000",
              "--section", ".bss@0x20400000:0x46000", "--section", ".bss2@0x40000000:0x30000"]
        elif (re.match(r'^.*AI900_AGR_FW_V[0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*AI900_FW_V[0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*A3[_]?AGR_[0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets for `AI900_AGR_FW_V??.??.??.??_m0306.bin`, auto-detection of .ARM.exidx works good enough
            file_specific_cmdargs = ["-b", "0x00420000",
              "--section", ".bss@0x20400000:0x46000", "--section", ".bss2@0x40000000:0x30000"]

        elif (re.match(r'^.*MATRICE100_FW_V01[.]02[()0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `MATRICE100_FW_V01.02.00.60_m0306.bin`
            file_specific_cmdargs = ["-b", "0x8020000", "--section", ".ARM.exidx@0x80E4338:0",
              "--section", ".bss@0x10000000:0x100", "--section", ".bss2@0x20000000:0x30000",
              "--section", ".bss3@0x40000000:0x30000"]
        elif (re.match(r'^.*MATRICE100_FW_V[()0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets for `MATRICE100_FW_V??.??.??.??_m0306.bin`, auto-detection of .ARM.exidx works good enough
            file_specific_cmdargs = ["-b", "0x8020000",
              "--section", ".bss@0x10000000:0xA000", "--section", ".bss2@0x20000000:0x30000",
              "--section", ".bss3@0x40000000:0x30000"]

        elif (re.match(r'^.*MATRICE600_FW_V[()0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*MATRICE600PRO_FW_V[()0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets for `MATRICE600_FW_V??.??.??.??_m0306.bin`, auto-detection of .ARM.exidx works good enough
            file_specific_cmdargs = ["-b", "0x00420000",
              "--section", ".bss@0x20400000:0x5D000", "--section", ".bss2@0x40000000:0x30000"]
        elif (re.match(r'^.*MG1S_FW_[0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*MG1S_V[0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets for `MG1S_FW_V??.??.??.??_m0306.bin`, auto-detection of .ARM.exidx works good enough
            file_specific_cmdargs = ["-b", "0x00420000",
              "--section", ".bss@0x20400000:0x5D000", "--section", ".bss2@0x40000000:0x30000"]
        elif (re.match(r'^.*P3X_FW_V01[.]01[.][0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*P3S_FW_V01[.]01[.][0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `P3X_FW_V01.01.0006_m0306.bin`
            file_specific_cmdargs = ["-b", "0x8020000", "--section", ".ARM.exidx@0x8092D48:0",
              "--section", ".bss@0x10000000:0xA000", "--section", ".bss2@0x20000000:0x30000",
              "--section", ".bss3@0x40000000:0x30000"]
        elif (re.match(r'^.*P3X_FW_V01[.]0[23][.][0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*P3S_FW_V01[.]0[23][.][0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `P3X_FW_V01.02.0006_m0306.bin`
            file_specific_cmdargs = ["-b", "0x8020000", "--section", ".ARM.exidx@0x80971A8:0",
              "--section", ".bss@0x10000000:0xA000", "--section", ".bss2@0x20000000:0x30000",
              "--section", ".bss3@0x40000000:0x30000"]
        elif (re.match(r'^.*P3X_FW_V01[.]0[45][.][0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*P3S_FW_V01[.]0[45][.][0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `P3X_FW_V01.05.0011_m0306.bin`
            file_specific_cmdargs = ["-b", "0x8020000", "--section", ".ARM.exidx@0x80A2BD8:0",
              "--section", ".bss@0x10000000:0xA000", "--section", ".bss2@0x20000000:0x30000",
              "--section", ".bss3@0x40000000:0x30000"]
        elif (re.match(r'^.*P3X_FW_V[0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*P3S_FW_V[0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `P3X_FW_V01.07.0060_m0306.bin`
            file_specific_cmdargs = ["-b", "0x8020000", "--section", ".ARM.exidx@0x80A5D34:0",
              "--section", ".bss@0x10000000:0xA000", "--section", ".bss2@0x20000000:0x30000",
              "--section", ".bss3@0x40000000:0x30000"]
        elif (re.match(r'^.*WM610_FW_V[0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*WM610_FC350Z_FW_V[0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*WM610_FC550_FW_V[0-9A-Z_.-]*_m0306[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets, taken from similar module
            file_specific_cmdargs = ["-b", "0x8020000", "--section", ".ARM.exidx@0x80A5D34:0",
              "--section", ".bss@0x10000000:0xA000", "--section", ".bss2@0x20000000:0x30000",
              "--section", ".bss3@0x40000000:0x30000"]
        else:
            # Generic m0306 solution - detect the location of .ARM.exidx
            file_specific_cmdargs = ["-b", "0x8020000",
              "--section", ".bss@0x10000000:0xA000", "--section", ".bss2@0x20000000:0x30000",
              "--section", ".bss3@0x40000000:0x30000"]
    elif (modl_inp_fn.endswith("_m0900.bin")): # LB air MCU modules from xV4 firmwares
        if (re.match(r'^.*P3X_FW_V[0-9A-Z_.-]*_m0900[.]bin', modl_inp_fn, re.IGNORECASE) or
          re.match(r'^.*P3S_FW_V[0-9A-Z_.-]*_m0900[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `P3X_FW_V01.08.0080_m0900.bin`
            file_specific_cmdargs = ["-b", "0x8008000", "--section", ".ARM.exidx@0x8015510:0",
              "--section", ".bss@0x1FFFF700:0x5A00", "--section", ".bss2@0x40000000:0x6700",
              "--section", ".bss3@0x40010000:0x5500", "--section", ".bss4@0x40020000:0x2200",
              "--section", ".bss5@0x42200000:0x100", "--section", ".bss6@0x42420000:0x500"]
        else:
            # Generic m0900 solution - detect the location of .ARM.exidx
            file_specific_cmdargs = ["-b", "0x8008000",
              "--section", ".bss@0x1FFFF700:0x5A00", "--section", ".bss2@0x40000000:0x23000",
              "--section", ".bss3@0x42200000:0x500", "--section", ".bss4@0x42420000:0x500"]
    elif (modl_inp_fn.endswith("_m1400.bin")): # LB ground MCU model 0 modules from xV4 firmwares
        if (re.match(r'^.*C1_FW_V00[][0-9A-Z_.-]*_m1400[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `C1_FW_v00.00.00.01_m1400.bin`
            file_specific_cmdargs = ["-b", "0x0A000", "--section", ".ARM.exidx@0x023600:0",
              "--section", ".bss@0x10000000:0x8000", "--section", ".bss2@0x40000000:0x50000",
              "--section", ".bss3@0xE0000000:0x10000"]
        elif (re.match(r'^.*C1_FW_V01[][0-9A-Z_.-]*_m1400[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `C1_FW_V01.06.0000_m1400.bin`
            file_specific_cmdargs = ["-b", "0x0A000", "--section", ".ARM.exidx@0x01CE50:0",
              "--section", ".bss@0x10000000:0x8000", "--section", ".bss2@0x40000000:0x50000",
              "--section", ".bss3@0xE0000000:0x10000"]
        elif (re.match(r'^.*MG1SRC_FW_V[0-9A-Z_.-]*_m1400[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `MG1SRC_FW_V01.01.00.00_m1400.bin`
            file_specific_cmdargs = ["-b", "0x0A000", "--section", ".ARM.exidx@0x0173A0:0",
              "--section", ".bss@0x10000000:0x8000", "--section", ".bss2@0x40000000:0x50000",
              "--section", ".bss3@0xE0000000:0x10000"]
        else:
            # Generic m1400 solution - detect the location of .ARM.exidx
            file_specific_cmdargs = ["-b", "0x0A000",
              "--section", ".bss@0x10000000:0x8000", "--section", ".bss2@0x40000000:0x50000",
              "--section", ".bss3@0xE0000000:0x10000"]
    elif (modl_inp_fn.endswith("_m1401.bin")): # LB ground MCU model 1 modules from xV4 firmwares
        if (re.match(r'^.*C1_FW_V[0-9A-Z_.-]*_m1401[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `C1_FW_V01.06.0000_m1401.bin`
            file_specific_cmdargs = ["-b", "0x0A000", "--section", ".ARM.exidx@0x01CE50:0",
              "--section", ".bss@0x20000000:0x9000", "--section", ".bss2@0x2C000000:0x20000",
              "--section", ".bss3@0x40022000:0x50000", "--section", ".bss4@0x400EE000:0x200",
              "--section", ".bss5@0xE0000000:0x8000"]
        else:
            # Generic m1401 solution - detect the location of .ARM.exidx
            file_specific_cmdargs = ["-b", "0x0A000",
              "--section", ".bss@0x10000000:0x8000", "--section", ".bss2@0x20000000:0x9000",
              "--section", ".bss3@0x2C000000:0x20000", "--section", ".bss4@0x40000000:0xF0000",
              "--section", ".bss5@0xE0000000:0x8000"]
    elif (modl_inp_fn.endswith("_0306.decrypted.bin")): # FC modules from IMaH firmwares
        if (re.match(r'^.*ag407_0306_v03[.]03[.]03[.][0-5][0-9][0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `ag407_0306_v03.03.03.38_20180511.pro.fw_0306.decrypted.bin`
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x0532950:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*ag407_0306_v03[.]03[.]03[.][6][0-9][0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `ag407_0306_v03.03.03.64_20181023.pro.fw_0306.decrypted.bin`
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x053A638:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*ag407_0306_v[0-9a-z_.-]*_fc00[.][0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `ag407_0306_v03.03.03.70_20181108_fc00.pro.fw_0306.decrypted.bin`
            # Since FW package v01.05.0002, the FC firmware comes in two versions, with slightly different base
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x053ABA8:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*ag407_0306_v[0-9a-z_.-]*_head[.][0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `ag407_0306_v03.03.03.80_20190808_head.pro.fw_0306.decrypted.bin`
            # Since FW package v01.05.0002, 'head' variant was added to FC firmwares
            file_specific_cmdargs = ["-b", "0x00420180", "--section", ".ARM.exidx@0x053C578:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*ag408_0306_v[0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets, taken from similar module
            file_specific_cmdargs = ["-b", "0x00420180", "--section", ".ARM.exidx@0x0529F00:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*ag410_0306_v[0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets, taken from similar module
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x0529F00:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*pm410_0306_v[0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets, taken from similar module
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x0529F00:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*pm420_0306_v[0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets, taken from similar module
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x0529F00:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*wm100_0306_v03[.]02[.]3[0-4][0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `wm100_0306_v03.02.34.02_20170505.pro.fw_0306.decrypted.bin`
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x0547E90:0",
              "--section", ".bss@0x20400000:0x60000", "--section", ".bss2@0x400E0000:0x1000",
              "--section", ".bss3@0xE0000000:0x10000"]
        elif (re.match(r'^.*wm100_0306_v[0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `wm100_0306_v03.02.37.55_20170722.pro.fw_0306.decrypted.bin`
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x0525A10:0",
              "--section", ".bss@0x20400000:0x60000", "--section", ".bss2@0x400E0000:0x1000",
              "--section", ".bss3@0xE0000000:0x10000"]
        elif (re.match(r'^.*wm220_0306_v03[.]02[.][0-2][0-9][0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `wm220_0306_v03.02.13.12_20161209.pro.fw_0306.decrypted.bin`
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x0536000:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*wm220_0306_v03[.]02[.]3[0-9][0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `wm220_0306_v03.02.35.05_20170525.pro.fw_0306.decrypted.bin`
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x05465D8:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*wm220_0306_v03[.]02[.]4[0-3][0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `wm220_0306_v03.02.43.20_2017????.pro.fw_0306.decrypted.bin`
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x05277D0:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*wm220_0306_v[0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `wm220_0306_v03.02.44.07_20171116.pro.fw_0306.decrypted.bin`
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x0525300:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*wm222_0306_v[0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets, taken from similar module
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x0525300:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*wm330_0306_v[0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets, taken from similar module
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x0529F00:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*wm331_0306_v[0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets, taken from similar module
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x0529F00:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*wm332_0306_v[0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets, taken from similar module
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x0529F00:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*wm334_0306_v[0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets, taken from similar module
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x0529F00:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*wm335_0306_v[0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets, taken from similar module
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x0529F00:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*wm336_0306_v[0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets, taken from similar module
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x0529F00:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        elif (re.match(r'^.*wm620_0306_v[0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `wm620_0306_v03.03.09.18_20180921.pro.fw_0306.bin`
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x536F60:0",
              "--section", ".bss@0x20400000:0x46000", "--section", ".bss2@0x40000000:0x30000"]
        elif (re.match(r'^.*xw607_0306_v[0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets, taken from similar module
            file_specific_cmdargs = ["-b", "0x00420000", "--section", ".ARM.exidx@0x0529F00:0",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
        else:
            # Generic m0306 solution - detect the location of .ARM.exidx
            file_specific_cmdargs = ["-b", "0x00420000",
              "--section", ".bss@0x20400000:0x60100", "--section", ".bss2@0x400E0000:0x2000"]
    elif (modl_inp_fn.endswith("_0900.bin")): # LB air MCU modules from IMaH v1 firmwares
        if (re.match(r'^.*wm330_0900_v[0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Generic offsets, taken from similar module
            file_specific_cmdargs = ["-b", "0x8008000", "--section", ".ARM.exidx@0x8015500:0",
              "--section", ".bss@0x1FFFF700:0x5A00", "--section", ".bss2@0x40000000:0x6700",
              "--section", ".bss3@0x40010000:0x5500", "--section", ".bss4@0x40020000:0x2200",
              "--section", ".bss5@0x42200000:0x100", "--section", ".bss6@0x42420000:0x500"]
        elif (re.match(r'^.*wm620_0900_v[0-9a-z_.-]*[.]bin', modl_inp_fn, re.IGNORECASE)):
            # Specific offsets for `wm620_0900_v01.07.00.00_20171101.pro.fw_0900.bin`
            file_specific_cmdargs = ["-b", "0x8008000", "--section", ".ARM.exidx@0x80164C8:0",
              "--section", ".bss@0x1FFFF700:0x5A00", "--section", ".bss2@0x40000000:0x6700",
              "--section", ".bss3@0x40010000:0x5500", "--section", ".bss4@0x40020000:0x2200",
              "--section", ".bss5@0x42200000:0x100", "--section", ".bss6@0x42420000:0x500"]
        else:
            # Generic m0900 solution - detect the location of .ARM.exidx
            file_specific_cmdargs = ["-b", "0x8008000",
              "--section", ".bss@0x1FFFF700:0x5A00", "--section", ".bss2@0x40000000:0x23000",
              "--section", ".bss3@0x42200000:0x500", "--section", ".bss4@0x42420000:0x500"]

    return file_specific_cmdargs, expect_file_changes, platform


def case_arm_bin2elf_rebin(capsys, cmdargs, modl_inp_fn):
    """ Test case for ELF creation and stripping back to BIN files.
    """
    LOGGER.info("Testcase file: {:s}".format(modl_inp_fn))
    # Most files we are able to recreate with full accuracy
    file_specific_cmdargs = []
    expect_file_changes = 0

    # Get certain params and error tolerance for specific files
    file_specific_cmdargs, expect_file_changes, platform = get_params_for_arm_bin2elf(modl_inp_fn)

    inp_path, inp_filename = os.path.split(modl_inp_fn)
    inp_path = pathlib.Path(inp_path)
    inp_basename, modl_fileext = os.path.splitext(inp_filename)
    if len(inp_path.parts) > 1:
        out_path = os.sep.join(["out"] + list(inp_path.parts[1:]))
    else:
        out_path = "out"
    elf_out_fn = os.sep.join([out_path, "{:s}.elf".format(inp_basename)]) # prefix for output files
    modl_out_fn = os.sep.join([out_path, "{:s}.rebin{:s}".format(inp_basename, modl_fileext)])
    # Extract the package
    command = [os.path.join(".", "arm_bin2elf.py"), "-vv", "-e"] + file_specific_cmdargs + ["-p", modl_inp_fn, "-o", elf_out_fn]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        arm_bin2elf_main()
    # Re-pack the package
    command = ["arm-none-eabi-objcopy", "-O", "binary", elf_out_fn, modl_out_fn]
    LOGGER.info(' '.join(command))
    subprocess.run(command)
    if expect_file_changes == 0:
        # Compare repackaged file and the original byte-to-byte, do not count differences
        match =  filecmp.cmp(modl_inp_fn, modl_out_fn, shallow=False)
        assert match, "Re-stripped file different: {:s}".format(modl_inp_fn)
    elif expect_file_changes == 999999:
        # Check only if repackaged file size roughly matches the original
        modl_inp_fsize = os.path.getsize(modl_inp_fn)
        modl_out_fsize = os.path.getsize(modl_out_fn)
        assert modl_out_fsize >= int(modl_inp_fsize * 0.95), "Re-stripped file too small: {:s}".format(modl_inp_fn)
        assert modl_out_fsize <= int(modl_inp_fsize * 1.05), "Re-stripped file too large: {:s}".format(modl_inp_fn)
    else:
        assert 0, "Not implemented"
    if cmdargs.rm_repacks:
        os.remove(modl_out_fn)
    pass


@pytest.mark.order(3) # must be run after test_dji_xv4_fwcon_rebin
@pytest.mark.fw_xv4
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/a3-flight_controller',1,),
    ('out/ag405-agras_mg_1s_octocopter',1,),
    ('out/ai900_agr-a3_based_multicopter_platform',1,),
    ('out/am603-n3_based_multicopter_platform',1,),
    ('out/d_rtk-mobile_station',1,),
    ('out/ennn-esc',1,),
    ('out/gl300abc-radio_control',1,),
    ('out/gl300e-radio_control',1,),
    ('out/hg211-osmo_pocket_2',1,),
    ('out/hg300-osmo_mobile',1,),
    ('out/hg301-osmo_mobile_2',1,),
    ('out/hg910-ronin2_gimbal',1,),
    ('out/lbtx-lightbridge_2_video_tx',1,),
    ('out/m100-matrice_100_quadcopter',1,),
    ('out/m600-matrice_600_hexacopter',1,),
    ('out/m600pro-matrice_600_pro_hexacopter',1,),
    ('out/n3-flight_controller',1,),
    ('out/osmo-osmo_x3_gimbal',1,),
    ('out/osmo_action-sport_cam',1,),
    ('out/osmo_fc350z-osmo_zoom_z3_gimbal',1,),
    ('out/osmo_fc550-osmo_x5_gimbal',1,),
    ('out/osmo_fc550r-osmo_x5raw_gimbal',1,),
    ('out/ot110-osmo_pocket_gimbal',1,),
    ('out/p3c-phantom_3_std_quadcopter',1,),
    ('out/p3s-phantom_3_adv_quadcopter',1,),
    ('out/p3se-phantom_3_se_quadcopter',1,),
    ('out/p3x-phantom_3_pro_quadcopter',1,),
    ('out/p3xw-phantom_3_4k_quadcopter',1,),
    ('out/swr60g-matrice_600_swr_60g',1,),
    ('out/wind-a3_based_multicopter_platform',1,),
    ('out/wm610-t600_inspire_1_x3_quadcopter',1,),
    ('out/wm610_fc350z-t600_inspire_1_z3_quadcopter',1,),
    ('out/wm610_fc550-t600_inspire_1_pro_x5_quadcopter',1,),
    ('out/zt300-datalink_pro',1,),
  ] )
def test_arm_bin2elf_xv4_rebin(capsys, cmdargs, modl_inp_dir, test_nth):
    """ Test for ELF creation and stripping back to BIN files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*-split1/*_m0306.bin".format(modl_inp_dir),
        "{}/*-split1/*_m0900.bin".format(modl_inp_dir),
        "{}/*-split1/*_m1400.bin".format(modl_inp_dir),
        "{}/*-split1/*_m1401.bin".format(modl_inp_dir),
    ) ]) if (os.path.isfile(fn) and os.stat(fn).st_size > 0)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for modl_inp_fn in modl_inp_filenames[::test_nth]:
        case_arm_bin2elf_rebin(capsys, cmdargs, modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(3) # must be run after test_dji_mvfc_fwpak_imah_v1_rebin
@pytest.mark.fw_imah_v1
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/ag406-agras_mg-1a',1,),
    ('out/ag407-agras_mg-1p-rtk',1,),
    ('out/ag408-agras_mg-unk',1,),
    ('out/ag410-agras_t16',1,),
    ('out/pm410-matrice200',1,),
    ('out/rc220-mavic_rc',1,),
    ('out/tp703-aeroscope',1,),
    ('out/wm100-spark',1,),
    ('out/wm220-mavic',1,),
    ('out/wm222-mavic_sp',1,),
    ('out/wm330-phantom_4_std',1,),
    ('out/wm331-phantom_4_pro',1,),
    ('out/wm332-phantom_4_adv',1,),
    ('out/wm334-phantom_4_rtk',1,),
    ('out/wm335-phantom_4_pro_v2',1,),
    ('out/wm336-phantom_4_mulspectral',1,),
    ('out/wm620-inspire_2',1,),
  ] )
def test_arm_bin2elf_imah_v1_rebin(capsys, cmdargs, modl_inp_dir, test_nth):
    """ Test for ELF creation and stripping back to BIN files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*/*_0306.decrypted.bin".format(modl_inp_dir),
        "{}/*/*_0900.bin".format(modl_inp_dir),
        "{}/*/*_1400.bin".format(modl_inp_dir),
        "{}/*/*_1401.bin".format(modl_inp_dir),
    ) ]) if (os.path.isfile(fn) and os.stat(fn).st_size > 0)]

    # Remove unsupported files - modules which are not a simple uC firmware
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*ag410_1401_v[0-9a-z_.-]*[.]bin$', fn, re.IGNORECASE)]
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*ag408_1401_v[0-9a-z_.-]*[.]bin$', fn, re.IGNORECASE)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for modl_inp_fn in modl_inp_filenames[::test_nth]:
        case_arm_bin2elf_rebin(capsys, cmdargs, modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(3) # must be run after test_dji_mvfc_fwpak_imah_v2_rebin
@pytest.mark.fw_imah_v2
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/wm1605-mini_se',1,),
    ('out/wm160-mavic_mini',1,),
    ('out/wm161-mini_2',1,),
  ] )
def test_arm_bin2elf_imah_v2_rebin(capsys, cmdargs, modl_inp_dir, test_nth):
    """ Test for ELF creation and stripping back to BIN files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*/*_0306.decrypted.bin".format(modl_inp_dir),
    ) ]) if (os.path.isfile(fn) and os.stat(fn).st_size > 0)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for modl_inp_fn in modl_inp_filenames[::test_nth]:
        case_arm_bin2elf_rebin(capsys, cmdargs, modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass
