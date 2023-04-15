# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, known archives extraction check.

    This test prepares files for deeper verification by extracting
    any archives included within previously extracted modules.
    It also decrypts any generic encryption applied to the files.
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

import glob
import itertools
import logging
import mmap
import os
import re
import shutil
import subprocess
import sys
import pathlib
import pytest
from datetime import datetime
from unittest.mock import patch

# Import the functions to be tested
sys.path.insert(0, './')
sys.path.insert(0, './ext4')


BUFSIZE = 8*1024

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
    except Exception as e:
        LOGGER.info("Could not check INI for: {:s}".format(modl_inp_fn))
        return False


def is_openssl_file(inp_fn):
    with open(inp_fn, 'rb') as encfh:
        return encfh.read(8) == b'Salted__'


def is_android_bootimg_file(inp_fn):
    with open(inp_fn, 'rb') as encfh:
        return encfh.read(8) == b'ANDROID!'


def is_rockchip_rkfw_file(inp_fn):
    with open(inp_fn, 'rb') as encfh:
        return encfh.read(4) == b'RKFW'


def is_rockchip_rkaf_file(inp_fn):
    with open(inp_fn, 'rb') as encfh:
        return encfh.read(4) == b'RKAF'


def is_lzmafile(inp_fn):
    with open(inp_fn, 'rb') as encfh:
        head = encfh.read(5)
        compress_mode = int.from_bytes(head[3:5], byteorder='little')
        return (head[0:3] == b'\x5D\x00\x00') and (bin(compress_mode).count("1") == 1)


def is_lz4file(inp_fn):
    with open(inp_fn, 'rb') as encfh:
        head = encfh.read(5)
        frame_flg = int.from_bytes(head[4:5], byteorder='little')
        return (head[0:4] == b'\x04\x22\x4D\x18') and ((frame_flg & 0xC0) == 0x40)


def is_gzipfile(inp_fn):
    with open(inp_fn, 'rb') as encfh:
        head = encfh.read(10)
        compr_method = head[2]
        modif_time = datetime.utcfromtimestamp(int.from_bytes(head[4:8], byteorder='little'))
        return (head[0:2] == b'\x1F\x8B') and (compr_method == 8) and (modif_time.year == 1970 or modif_time.year >= 1996)


def is_ext4file(inp_fn):
    with open(inp_fn, 'rb') as encfh:
        encfh.seek(0x400)
        superblock = encfh.read(0x40)
        s_magic = int.from_bytes(superblock[0x38:0x3A], byteorder='little')
        return (s_magic == 0xEF53)


def is_ubifsfile(inp_fn):
    with open(inp_fn, 'rb') as encfh:
        echead = encfh.read(0x40)
        vihead_offs = int.from_bytes(echead[0x10:0x14], byteorder='big')
        if (echead[0:4] != b'UBI#') or (vihead_offs < 0x40) or (vihead_offs > 0x8000):
            return False;
        encfh.seek(vihead_offs)
        vihead = encfh.read(0x40)
        return (vihead[0:4] == b'UBI!')


def remove_files_only_recursive(path):
    for d in os.listdir(path):
        nxpath = os.path.join(path, d)
        try:
            os.remove(nxpath)
        except OSError:
            remove_files_only_recursive(nxpath)


def tar_extractall_overwrite(tarfh, path='.'):
    for f in tarfh:
        try:
            tarfh.extract(f, path, set_attrs=False, numeric_owner=False)
        except IOError as e:
            os.remove(os.sep.join([path, f.name]))
            tarfh.extract(f, path, set_attrs=False, numeric_owner=False)
    pass


def case_bin_archive_extract(modl_inp_fn):
    """ Test case for extraction check, and prepare data for tests which use the extracted files.
    """
    LOGGER.info("Testcase file: {:s}".format(modl_inp_fn))

    import tarfile
    import zipfile

    ignore_unknown_format = False

    inp_path, inp_filename = os.path.split(modl_inp_fn)
    inp_path = pathlib.Path(inp_path)
    inp_basename, modl_fileext = os.path.splitext(inp_filename)

    # For some files, we may want to ignore unrecognized format because the files can be incorrectly decrypted (due to no key)
    if (re.match(r'^(wm100)[a]?_(0801|0905).*$', inp_basename, re.IGNORECASE)):
        ignore_unknown_format = True # PUEK-2017-09 not published
    if (re.match(r'^(wm620)_(0801|0802|0905).*$', inp_basename, re.IGNORECASE)):
        ignore_unknown_format = True # PUEK-2017-09 not published
    if (re.match(r'^(wm335)_(0801|0802|0805|1301).*$', inp_basename, re.IGNORECASE)):
        ignore_unknown_format = True # PUEK-2017-11 not published
    if (re.match(r'^(wm260|wm2605)_(0802).*$', inp_basename, re.IGNORECASE)):
        ignore_unknown_format = True # unsupported signature size - data not decrypted correctly
    # There are also damaged files, where we expect the extraction to fail
    if (re.match(r'^(ag600)_(2403)_v06[.]00[.]01[.]10_.*', inp_basename, re.IGNORECASE)):
        ignore_unknown_format = True # truncated file

    if len(inp_path.parts) > 1:
        out_path = os.sep.join(["out"] + list(inp_path.parts[1:]))
    else:
        out_path = "out"

    if is_openssl_file(modl_inp_fn):
        real_inp_fn = os.sep.join([out_path, "{:s}.decrypted{:s}".format(inp_basename, modl_fileext)])
        # Decrypt the file
        command = ["openssl", "des3", "-md", "md5", "-d", "-k", "Dji123456", "-in", modl_inp_fn, "-out", real_inp_fn]
        LOGGER.info(' '.join(command))
        subprocess.run(command)
    else:
        real_inp_fn = modl_inp_fn

    modules_path1 = os.sep.join([out_path, "{:s}-extr1".format(inp_basename)])
    if not os.path.exists(modules_path1):
        os.makedirs(modules_path1)

    if zipfile.is_zipfile(real_inp_fn):
        with zipfile.ZipFile(real_inp_fn) as zipfh:
            command = ["unzip", "-q", "-o", "-d", modules_path1,  real_inp_fn]
            LOGGER.info(' '.join(command))
            # extracting file
            zipfh.extractall(modules_path1)
    elif is_android_bootimg_file(real_inp_fn):
        if True:
            command = ["./mkbootimg/unpackbootimg", "-i",  real_inp_fn, "-o", modules_path1]
            LOGGER.info(' '.join(command))
            # extracting file
            subprocess.run(command)
    elif is_rockchip_rkfw_file(real_inp_fn):
        if True:
            command = [os.path.join(os.getcwd(), "rkflashtool", "rkunpack"),  os.path.join(os.getcwd(), real_inp_fn)]
            LOGGER.info(' '.join(command))
            # extracting file level 1
            subprocess.run(command, cwd=modules_path1)
            assert is_rockchip_rkaf_file(os.path.join(modules_path1, "embedded-update.img"))
            command = [os.path.join(os.getcwd(), "rkflashtool", "rkunpack"),  "embedded-update.img"]
            LOGGER.info(' '.join(command))
            # extracting file level 2
            subprocess.run(command, cwd=modules_path1)
            assert is_android_bootimg_file(os.path.join(modules_path1, "Image-out", "boot.img"))
    elif is_ubifsfile(real_inp_fn):
        if True:
            pass # extraction not supported atm
    elif is_ext4file(real_inp_fn):
        from ext4_cp import main as ext4_cp_main
        if True:
            # The extractor we use makes a numbered copy instead of overwrite; we need to clear the old files
            command = ["rm -Rf", "{}/*".format(modules_path1)]
            LOGGER.info(' '.join(command))
            remove_files_only_recursive(modules_path1)
            command = ["./ext4/ext4_cp.py", "-R", "-n", "--wa-fnames", "-v", "{:s}:.".format(real_inp_fn), modules_path1]
            LOGGER.info(' '.join(command))
            # extracting file
            with patch.object(sys, 'argv', command):
                ext4_cp_main()
    elif tarfile.is_tarfile(real_inp_fn): # testing for tar at the bottom, as it may give false positives
        with tarfile.open(real_inp_fn) as tarfh:
            if type(tarfh.fileobj).__name__ == "GzipFile":
                command = ["tar", "-zxf", real_inp_fn, "--directory={}".format(modules_path1)]
            else:
                command = ["tar", "-xf", real_inp_fn, "--directory={}".format(modules_path1)]
            LOGGER.info(' '.join(command))
            # extracting file
            tar_extractall_overwrite(tarfh, modules_path1)
    else:
        if not ignore_unknown_format:
            assert False, "Unrecognized archive format of the module file: {:s}".format(modl_inp_fn)
        LOGGER.warning("Unrecognized archive format of the module file: {:s}".format(modl_inp_fn))
    pass


def case_bin_single_decompress(modl_inp_fn):
    """ Test case for extraction check, and prepare data for tests which use the extracted file.
    """
    LOGGER.info("Testcase file: {:s}".format(modl_inp_fn))

    import gzip
    import lzma
    import lz4.frame
    import zlib

    bufsize = BUFSIZE
    ignore_unknown_format = False

    inp_path, inp_filename = os.path.split(modl_inp_fn)
    inp_path = pathlib.Path(inp_path)
    inp_basename, inp_fileext = os.path.splitext(inp_filename)
    # do not remove extension if it explains the type
    if inp_fileext.endswith("ramdisk"):
        inp_basename += inp_fileext
    if len(inp_path.parts) > 1:
        out_path = os.sep.join(["out"] + list(inp_path.parts[1:]))
    else:
        out_path = "out"
    modl_out_fn = os.sep.join([out_path, "{:s}.unpack.bin".format(inp_basename)])

    if is_lzmafile(modl_inp_fn):
        with lzma.open(modl_inp_fn) as lzmafh:
            command = ["lzma", "-d ", "-c", modl_inp_fn, ">", modl_out_fn]
            LOGGER.info(' '.join(command))
            with open(modl_out_fn, "wb") as unpfh:
                shutil.copyfileobj(lzmafh, unpfh)
    elif is_lz4file(modl_inp_fn):
        with lz4.frame.open(modl_inp_fn) as lz4fh:
            command = ["lz4", "-d",  modl_inp_fn, modl_out_fn]
            LOGGER.info(' '.join(command))
            with open(modl_out_fn, "wb") as unpfh:
                shutil.copyfileobj(lz4fh, unpfh)
    elif is_gzipfile(modl_inp_fn):
        truncated_file = (
            re.match(r'^.*ag408_0801_v[0-9a-z_.-]*_0801-extr1/(normal|recovery)_LRFS[.]bin$', modl_inp_fn, re.IGNORECASE) or
            re.match(r'^.*ag408_1301_v[0-9a-z_.-]*_1301-extr1/(normal|recovery)_LRFS[.]bin$', modl_inp_fn, re.IGNORECASE) or
            re.match(r'^.*ag410_0801_v[0-9a-z_.-]*_0801-extr1/(normal|recovery)_LRFS[.]bin$', modl_inp_fn, re.IGNORECASE) or
            re.match(r'^.*ag410_1301_v[0-9a-z_.-]*_1301-extr1/(normal|recovery)_LRFS[.]bin$', modl_inp_fn, re.IGNORECASE) or
            re.match(r'^.*ag410_2601_v[0-9a-z_.-]*_2601-extr1/(normal|recovery)_LRFS[.]bin$', modl_inp_fn, re.IGNORECASE) or
            re.match(r'^.*ag411_1301_v[0-9a-z_.-]*_1301-extr1/(normal|recovery)_LRFS[.]bin$', modl_inp_fn, re.IGNORECASE)
        )
        if True:
            command = ["gzip", "-d", "-k", "-f", "-c",  modl_inp_fn, ">", modl_out_fn]
            LOGGER.info(' '.join(command))
        if (truncated_file): # Extract truncated files with zlib to avoid exceptions
            with open(modl_inp_fn, 'rb') as gzfh:
                d = zlib.decompressobj(16+zlib.MAX_WBITS)
                with open(modl_out_fn, "wb") as unpfh:
                    while file_content := gzfh.read(bufsize):
                        unpfh.write(d.decompress(file_content))
        else:
            with gzip.open(modl_inp_fn, 'rb') as gzfh:
                with open(modl_out_fn, "wb") as unpfh:
                    shutil.copyfileobj(gzfh, unpfh)
    else:
        if not ignore_unknown_format:
            assert False, "Unrecognized compression format of the module file: {:s}".format(modl_inp_fn)
        LOGGER.warning("Unrecognized compression format of the module file: {:s}".format(modl_inp_fn))
    pass


@pytest.mark.order(2) # must be run after test_dji_xv4_fwcon_rebin
@pytest.mark.fw_xv4
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/gl300abc-radio_control',1,),
    ('out/gl300e-radio_control',1,),
    ('out/m600-matrice_600_hexacopter',1,),
    ('out/osmo_fc550-osmo_x5_gimbal',1,),
    ('out/osmo_fc550r-osmo_x5raw_gimbal',1,),
    ('out/osmo-osmo_x3_gimbal',1,),
    ('out/p3s-phantom_3_adv_quadcopter',1,),
    ('out/p3x-phantom_3_pro_quadcopter',1,),
    ('out/wm610-t600_inspire_1_x3_quadcopter',1,),
    ('out/wm610_fc550-t600_inspire_1_pro_x5_quadcopter',1,),
    ('out/zs600a-crystalsky_5_5inch',1,),
    ('out/zs600b-crystalsky_7_85in',1,),
  ] )
def test_bin_archives_xv4_extract(capsys, modl_inp_dir, test_nth):
    """ Test if known archives are extracting correctly, and prepare data for tests which use the extracted files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e, recursive=True) for e in (
        # Some Android OTA/TGZ/TAR modules contain ELFs for hardcoders
        "{}/*/*_m0800.bin".format(modl_inp_dir),
        "{}/*/*_m1300.bin".format(modl_inp_dir),
      ) ]) if os.path.isfile(fn)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no package files to test in this directory")

    for modl_inp_fn in modl_inp_filenames:
        case_bin_archive_extract(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(3) # must be run after test_bin_archives_xv4_extract
@pytest.mark.fw_xv4
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/gl300e-radio_control',1,),
    ('out/osmo_fc350z-osmo_zoom_z3_gimbal',1,),
    ('out/osmo_action-sport_cam',1,),
    ('out/ot110-osmo_pocket_gimbal',1,),
    ('out/zs600a-crystalsky_5_5inch',1,),
    ('out/zs600b-crystalsky_7_85in',1,),
  ] )
def test_bin_archives_xv4_nested_extract(capsys, modl_inp_dir, test_nth):
    """ Test if known archives are extracting correctly, and prepare data for tests which use the extracted files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e, recursive=True) for e in (
        # The mkbootimg `ANDROID!` images extracted from OTA archives
        "{}/*/*-extr1/boot.img".format(modl_inp_dir),
        "{}/*/*-extr1/recovery.img".format(modl_inp_dir),
        # The mkbootimg `ANDROID!` images extracted by `rkunpack`
        "{}/*/*-extr1/Image-out/boot.img".format(modl_inp_dir),
        "{}/*/*-extr1/Image-out/recovery.img".format(modl_inp_dir),
        # The partition images extracted by `rkunpack`
        "{}/*/*-extr1/Image-out/system.img".format(modl_inp_dir),
        # The partition images extracted by `amba_fwpak`
        "{}/*/*_m0100-split1/*_part_rfs.a9s".format(modl_inp_dir),
        "{}/*/*_m0100-split1/*.unpack_part_04.a9s".format(modl_inp_dir),
      ) ]) if os.path.isfile(fn)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no package files to test in this directory")

    for modl_inp_fn in modl_inp_filenames:
        case_bin_archive_extract(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(2) # must be run after test_dji_xv4_fwcon_rebin
@pytest.mark.fw_xv4
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/hg211-osmo_pocket_2',1,),
    ('out/osmo_action-sport_cam',1,),
    ('out/ot110-osmo_pocket_gimbal',1,),
  ] )
def test_bin_single_compressed_xv4_extract(capsys, modl_inp_dir, test_nth):
    """ Test if known single compressed files are extracting correctly, and prepare data for tests which use the extracted files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e, recursive=True) for e in (
        "{}/*/*_m0100.bin".format(modl_inp_dir),
        "{}/*/*_m0107.bin".format(modl_inp_dir),
      ) ]) if os.path.isfile(fn)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no package files to test in this directory")

    for modl_inp_fn in modl_inp_filenames:
        case_bin_single_decompress(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(3) # must be run after test_bin_archives_xv4_extract
@pytest.mark.fw_xv4
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/ag406-agras_mg-1a',1,),
    ('out/ag408-agras_mg-unk',1,),
    ('out/ag410-agras_t16',1,),
    ('out/ag411-agras_t20',1,),
    ('out/gl300e-radio_control',1,),
    ('out/zs600a-crystalsky_5_5inch',1,),
    ('out/zs600b-crystalsky_7_85in',1,),
  ] )
def test_bin_single_compressed_xv4_nested_extract(capsys, modl_inp_dir, test_nth):
    """ Test if known single compressed files are extracting correctly.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e, recursive=True) for e in (
        # the .cpio.gz archives; we extract only gz part
        "{}/*/*-extr1/*-extr1/*.img-ramdisk".format(modl_inp_dir),
        "{}/*/*-extr1/Image-out/*-extr1/*.img-ramdisk".format(modl_inp_dir),
      ) ]) if os.path.isfile(fn)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no package files to test in this directory")

    for modl_inp_fn in modl_inp_filenames:
        case_bin_single_decompress(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(2) # must be run after test_dji_imah_fwsig_v1_rebin
@pytest.mark.fw_imah_v1
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/ag406-agras_mg-1a',1,),
    ('out/ag407-agras_mg-1p-rtk',1,),
    ('out/ag408-agras_mg-unk',1,),
    ('out/ag410-agras_t16',1,),
    ('out/ag411-agras_t20',1,),
    ('out/ag603-agras_unk_rtk',1,),
    ('out/gl811-goggles_racing_ed',1,),
    ('out/pm410-matrice200',1,),
    ('out/pm420-matrice200_v2',1,),
    ('out/rc001-inspire_2_rc',1,),
    ('out/rc002-spark_rc',1,),
    ('out/rc160-mavic_mini_rc',1,),
    ('out/rc220-mavic_rc',1,),
    ('out/rc230-mavic_air_rc',1,),
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
def test_bin_archives_imah_v1_extract(capsys, modl_inp_dir, test_nth):
    """ Test if known archives are extracting correctly, and prepare data for tests which use the extracted files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e, recursive=True) for e in (
        # Some Android OTA/TGZ/TAR modules contain boot images with another stage of IMaH encryption
        "{}/*/*_0205.bin".format(modl_inp_dir),
        "{}/*/*_0801.bin".format(modl_inp_dir),
        "{}/*/*_0802.bin".format(modl_inp_dir),
        "{}/*/*_0805.bin".format(modl_inp_dir),
        "{}/*/*_0905.bin".format(modl_inp_dir),
        "{}/*/*_0907.bin".format(modl_inp_dir),
        "{}/*/*_1300.bin".format(modl_inp_dir),
        "{}/*/*_1301.bin".format(modl_inp_dir),
        "{}/*/*_1401.bin".format(modl_inp_dir),
        "{}/*/*_1407.bin".format(modl_inp_dir),
        "{}/*/*_2403.bin".format(modl_inp_dir),
        "{}/*/*_2601.bin".format(modl_inp_dir),
        "{}/*/*_2602.bin".format(modl_inp_dir),
        "{}/*/*_2801.bin".format(modl_inp_dir),
      ) ]) if os.path.isfile(fn)]

    # Direct `MA2x` Myriad firmware (but v02 has the `MA2x` within .tgz)
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*wm330_0802_v01[.][0-9a-z_.-]*_0802[.]bin$', fn, re.IGNORECASE)]
    # Simple linear uC binary, not an archive
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*ag406_1401_v[0-9a-z_.-]*[.]bin$', fn, re.IGNORECASE)]
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*rc001_1401_v[0-9a-z_.-]*[.]bin$', fn, re.IGNORECASE)]
    # Double-encrypted FW module
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*xw607_2403_v[0-9a-z_.-]*[.]bin$', fn, re.IGNORECASE)]

    # Skip the packages which were extracted in encrypted form (need non-public key)
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not is_module_unsigned_encrypted(fn)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no package files to test in this directory")

    for modl_inp_fn in modl_inp_filenames:
        case_bin_archive_extract(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(3) # must be run after test_bin_archives_imah_v1_extract
@pytest.mark.fw_imah_v1
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/ag406-agras_mg-1a',1,),
    ('out/ag408-agras_mg-unk',1,),
    ('out/ag410-agras_t16',1,),
    ('out/ag411-agras_t20',1,),
  ] )
def test_bin_archives_imah_v1_nested_extract(capsys, modl_inp_dir, test_nth):
    """ Test if known archives are extracting correctly, and prepare data for tests which use the extracted files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e, recursive=True) for e in (
        # The mkbootimg `ANDROID!` images extracted from OTA archives
        "{}/*/*-extr1/boot.img".format(modl_inp_dir),
        "{}/*/*-extr1/recovery.img".format(modl_inp_dir),
      ) ]) if os.path.isfile(fn)]

    # Remove modules which are in IMaH format
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*ag408_0801_v[0-9a-z_.-]*/[0-9a-z_.-]*[.]img$', fn, re.IGNORECASE)]
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*ag408_1301_v[0-9a-z_.-]*/[0-9a-z_.-]*[.]img$', fn, re.IGNORECASE)]
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*ag410_0801_v[0-9a-z_.-]*/[0-9a-z_.-]*[.]img$', fn, re.IGNORECASE)]
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*ag410_1301_v[0-9a-z_.-]*/[0-9a-z_.-]*[.]img$', fn, re.IGNORECASE)]
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*ag411_1301_v[0-9a-z_.-]*/[0-9a-z_.-]*[.]img$', fn, re.IGNORECASE)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no package files to test in this directory")

    for modl_inp_fn in modl_inp_filenames:
        case_bin_archive_extract(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(2) # must be run after test_dji_imah_fwsig_v1_rebin
@pytest.mark.fw_imah_v1
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/pm410-matrice200',1,),
    ('out/wm220-mavic',1,),
    ('out/wm330-phantom_4_std',1,),
    ('out/wm331-phantom_4_pro',1,),
    ('out/wm332-phantom_4_adv',1,),
    ('out/wm334-phantom_4_rtk',1,),
    ('out/wm335-phantom_4_pro_v2',1,),
    ('out/wm336-phantom_4_mulspectral',1,),
    ('out/wm620-inspire_2',1,),
  ] )
def test_bin_single_compressed_imah_v1_extract(capsys, modl_inp_dir, test_nth):
    """ Test if known single compressed files are extracting correctly, and prepare data for tests which use the extracted files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e, recursive=True) for e in (
        "{}/*/*_0100.bin".format(modl_inp_dir),
        "{}/*/*_0101.bin".format(modl_inp_dir),
      ) ]) if os.path.isfile(fn)]

    # Skip images in Ambarella format which are not compressed
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*wm220_0100_v[0-9a-z_.-]*_ca02[.]pro[.]fw_0100[.]bin$', fn, re.IGNORECASE)]
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*wm220_0101_v[0-9a-z_.-]*_ca02[.]pro[.]fw_0101[.]bin$', fn, re.IGNORECASE)]

    # Skip the packages which were extracted in encrypted form (need non-public key)
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not is_module_unsigned_encrypted(fn)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no package files to test in this directory")

    for modl_inp_fn in modl_inp_filenames:
        case_bin_single_decompress(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(3) # must be run after test_bin_archives_imah_v1_extract
@pytest.mark.fw_imah_v1
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/ag406-agras_mg-1a',1,),
    ('out/ag408-agras_mg-unk',1,),
    ('out/ag410-agras_t16',1,),
    ('out/ag411-agras_t20',1,),
  ] )
def test_bin_single_compressed_imah_v1_nested_extract(capsys, modl_inp_dir, test_nth):
    """ Test if known single compressed files are extracting correctly, and prepare data for tests which use the extracted files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e, recursive=True) for e in (
        # the .cpio.gz archives; we extract only gz part
        "{}/*/*-extr1/*-extr1/*.img-ramdisk".format(modl_inp_dir),
        "{}/*/*-extr1/*_LRFS.bin".format(modl_inp_dir),
      ) ]) if os.path.isfile(fn)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no package files to test in this directory")

    for modl_inp_fn in modl_inp_filenames:
        case_bin_single_decompress(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(2) # must be run after test_dji_imah_fwsig_v2_rebin
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
def test_bin_archives_imah_v2_extract(capsys, modl_inp_dir, test_nth):
    """ Test if known archives are extracting correctly, and prepare data for tests which use the extracted files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e, recursive=True) for e in (
        # Some Android OTA/TGZ/TAR modules contain boot images with another stage of IMaH encryption
        "{}/*/wm230_0001_v*_0001.bin".format(modl_inp_dir), # probably just incorrectly marked, only in one FW of wm230
        "{}/*/*_0104.bin".format(modl_inp_dir),
        "{}/*/*_0205.bin".format(modl_inp_dir),
        "{}/*/*_0701.bin".format(modl_inp_dir),
        "{}/*/*_0702.bin".format(modl_inp_dir),
        "{}/*/*_0801.bin".format(modl_inp_dir),
        "{}/*/*_0802.bin".format(modl_inp_dir),
        "{}/*/*_0805.bin".format(modl_inp_dir),
        "{}/*/*_0901.bin".format(modl_inp_dir),
        "{}/*/*_0905.bin".format(modl_inp_dir),
        "{}/*/*_0907.bin".format(modl_inp_dir),
        "{}/*/*_1300.bin".format(modl_inp_dir),
        "{}/*/*_1301.bin".format(modl_inp_dir),
        "{}/*/*_1407.bin".format(modl_inp_dir),
        "{}/*/*_1502.bin".format(modl_inp_dir),
        "{}/*/*_2403.bin".format(modl_inp_dir),
        "{}/*/*_2801.bin".format(modl_inp_dir),
      ) ]) if os.path.isfile(fn)]

    # Firmware in `VHABCIM` format, not an archive
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*ec174_0801_v[0-9a-z_.-]*_0801[.]bin$', fn, re.IGNORECASE)]
    # Firmware in linear uC memory dump, not an archive
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*(ag500|ag501)_0104_v[0-9a-z_.-]*_0104[.]bin$', fn, re.IGNORECASE)]
    # NFZ data format, with index array at start, then the data; not an archive format
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*(pm430|wm160|wm1605|wm161)_0905_v[0-9a-z_.-]*_0905[.]bin$', fn, re.IGNORECASE)]

    # Skip the packages which were extracted in encrypted form (need non-public key)
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not is_module_unsigned_encrypted(fn)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no package files to test in this directory")

    for modl_inp_fn in modl_inp_filenames:
        case_bin_archive_extract(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(4) # must be run after test_bin_sparseimg_imah_v2_solidify
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
def test_bin_archives_imah_v2_nested_extract(capsys, modl_inp_dir, test_nth):
    """ Test if known archives are extracting correctly, and prepare data for tests which use the extracted files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e, recursive=True) for e in (
        # The Android ext4 filesystem partitions
        "{}/*/*-extr1/system.img".format(modl_inp_dir),
        "{}/*/*-extr1/vendor.img".format(modl_inp_dir),
      ) ]) if os.path.isfile(fn)]

    # Remove modules which are in archive format
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not re.match(r'^.*TODOX_1301_v[0-9a-z_.-]*/[0-9a-z_.-]*[.]img$', fn, re.IGNORECASE)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no package files to test in this directory")

    for modl_inp_fn in modl_inp_filenames:
        case_bin_archive_extract(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.order(2) # must be run after test_dji_imah_fwsig_v2_rebin
@pytest.mark.fw_imah_v2
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/wm160-mavic_mini',1,),
    ('out/wm1605-mini_se',1,),
    ('out/wm161-mini_2',1,),
  ] )
def test_bin_single_compressed_imah_v2_extract(capsys, modl_inp_dir, test_nth):
    """ Test if known single compressed files are extracting correctly, and prepare data for tests which use the extracted files.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    modl_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e, recursive=True) for e in (
        "{}/*/*_0100.bin".format(modl_inp_dir),
      ) ]) if os.path.isfile(fn)]

    # Skip the packages which were extracted in encrypted form (need non-public key)
    modl_inp_filenames = [fn for fn in modl_inp_filenames if not is_module_unsigned_encrypted(fn)]

    if len(modl_inp_filenames) < 1:
        pytest.skip("no package files to test in this directory")

    for modl_inp_fn in modl_inp_filenames:
        case_bin_single_decompress(modl_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass
