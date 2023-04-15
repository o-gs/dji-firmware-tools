# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, re-create solid image from sparse image.

    This test prepares files for deeper verification by extracting
    single files from partition images.
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
import os
import re
import sys
import pathlib
import pytest
from unittest.mock import patch

# Import the functions to be tested
# Use 'git clone https://github.com/xpirt/sdat2img.git' to get the sparse images tool
sys.path.insert(0, './')


LOGGER = logging.getLogger(__name__)


def case_bin_sparseimg_solidify(img_inp_fn):
    """ Test case for solidification of sparse images so that they can be later extracted.
    """
    LOGGER.info("Testcase file: {:s}".format(img_inp_fn))
    from sdat2img.sdat2img import main as sdat2img_main

    inp_path, inp_filename = os.path.split(img_inp_fn)
    inp_path = pathlib.Path(inp_path)
    # Remove ".new.dat"
    inp_basename, _ = os.path.splitext(inp_filename)
    inp_basename, _ = os.path.splitext(inp_basename)

    if len(inp_path.parts) > 1:
        out_path = os.sep.join(["out"] + list(inp_path.parts[1:]))
    else:
        out_path = "out"

    img_newdat_fn = os.path.join(inp_path, "{}.new.dat".format(inp_basename))
    img_trlist_fn = os.path.join(inp_path, "{}.transfer.list".format(inp_basename))
    img_out_fn = os.path.join(inp_path, "{}.img".format(inp_basename))

    assert os.path.exists(img_trlist_fn)
    assert os.path.getsize(img_newdat_fn) > 0

    if os.path.exists(img_out_fn):
        os.remove(img_out_fn)

    command = ["./sdat2img/sdat2img.py", img_trlist_fn, img_newdat_fn, img_out_fn]
    LOGGER.info(' '.join(command))
    # solidify the sparse image
    sdat2img_main(img_trlist_fn, img_newdat_fn, img_out_fn)
    assert os.path.getsize(img_out_fn) > 0
    pass


@pytest.mark.order(3) # must be run after test_bin_archives_imah_v2_extract
@pytest.mark.fw_imah_v2
@pytest.mark.parametrize("modl_inp_dir,test_nth", [
    ('out/ag500-agras_t10',1,),
    ('out/ag501-agras_t30',1,),
    ('out/ag600-agras_t40_gimbal',1,),
    ('out/ag601-agras_t40',1,),
    ('out/asvl001-vid_transmission',1,),
    ('out/gl150-goggles_fpv_v1',1,),
    ('out/gl170-goggles_fpv_v2',1,),
    ('out/lt150-caddx_vis_air_unit_lt',1,),
    ('out/pm320-matrice30',1,),
    ('out/pm430-matrice300',1,),
    ('out/rc430-matrice300_rc',1,),
    ('out/rcjs170-racer_rc',1,),
    ('out/rc-n1-wm161b-mini_2n3_rc',1,),
    ('out/rc-n1-wm260-mavic_pro_3',1,),
    ('out/rcs231-mavic_air_2_rc',1,),
    ('out/rcss170-racer_rc_motion',1,),
    ('out/wm150-fpv_system',1,),
    ('out/wm160-mavic_mini',1,),
    ('out/wm1605-mini_se',1,),
    ('out/wm161-mini_2',1,),
    ('out/wm170-fpv_racer',1,),
    ('out/wm230-mavic_air',1,),
    ('out/wm231-mavic_air_2',1,),
    ('out/wm232-mavic_air_2s',1,),
    ('out/wm240-mavic_2',1,),
    ('out/wm245-mavic_2_enterpr',1,),
    ('out/wm246-mavic_2_enterpr_dual',1,),
    ('out/wm247-mavic_2_enterpr_rtk',1,),
    ('out/wm2605-mavic_3_classic',1,),
    ('out/wm260-mavic_pro_3',1,),
  ] )
def test_bin_sparseimg_imah_v2_solidify(capsys, modl_inp_dir, test_nth):
    """ Solidify sparse images so that they can be later extracted.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    img_inp_filenames = [fn for fn in itertools.chain.from_iterable([ glob.glob(e, recursive=True) for e in (
        "{}/*/*-extr1/*.new.dat".format(modl_inp_dir),
      ) ]) if os.path.isfile(fn)]

    if len(img_inp_filenames) < 1:
        pytest.skip("no package files to test in this directory")

    for img_inp_fn in img_inp_filenames:
        case_bin_sparseimg_solidify(img_inp_fn)
        capstdout, _ = capsys.readouterr()
    pass
