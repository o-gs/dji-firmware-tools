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


def case_arm_bin2elf_rebin(modl_inp_fn):
    """ Test case for ELF creation and stripping back to BIN files.
    """
    LOGGER.info("Testcase file: {:s}".format(modl_inp_fn))
    # Most files we are able to recreate with full accuracy
    file_specific_cmdargs = []
    expect_file_changes = 0

    # Special cases - setting certain params and error tolerance for specific files
    if (modl_inp_fn.endswith("_m0306.bin")):
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
        else:
            # Generic m0306 solution - detect the location of .ARM.exidx
            file_specific_cmdargs = ["-b", "0x8020000",
              "--section", ".bss@0x10000000:0xA000", "--section", ".bss2@0x20000000:0x30000",
              "--section", ".bss3@0x40000000:0x30000"]
    elif (modl_inp_fn.endswith("_m0900.bin")):
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
    elif (modl_inp_fn.endswith("_m1400.bin")):
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
    elif (modl_inp_fn.endswith("_m1401.bin")):
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
    pass

@pytest.mark.order(2) # must be run after test_dji_xv4_fwcon_rebin
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
def test_arm_bin2elf_rebin(capsys, modl_inp_dir, test_nth):
    """ Test for ELF creation and stripping back to BIN files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e) for e in (
        "{}/*-split1/*_m0306.bin".format(modl_inp_dir),
        "{}/*-split1/*_m0900.bin".format(modl_inp_dir),
        "{}/*-split1/*_m1400.bin".format(modl_inp_dir),
        "{}/*-split1/*_m1401.bin".format(modl_inp_dir),
    ) ]) if os.path.isfile(fn)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no files to test in this directory")

    for modl_inp_fn in modl_inp_filenames[::test_nth]:
        case_arm_bin2elf_rebin(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass
