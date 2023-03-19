# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, comm_og_service_tool script.

    This test verifies functions of the script by using its
    "dry test" functionality. This provides static, typical responses
    to all requests.
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

import logging
import os
import re
import sys
import pytest
from unittest.mock import patch

# Import the functions to be tested
sys.path.insert(0, './')
from comm_og_service_tool import main as comm_og_service_tool_main


LOGGER = logging.getLogger(__name__)

@pytest.mark.comm
def test_comm_og_service_tool_flyc_param_list():
    """ Test list function using typical answers.
    """
    command = [os.path.join(".", "comm_og_service_tool.py"), "-vvv", "--dry-test", "--port", "/dev/ttyUSB1", "p3x", "FlycParam", "list", "--start=100", "--fmt=2line"]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        comm_og_service_tool_main()
    pass

@pytest.mark.comm
def test_comm_og_service_tool_flyc_param_get(capsys):
    """ Test get function using typical answers.
    """
    command = [os.path.join(".", "comm_og_service_tool.py"), "-vvv", "--dry-test", "--port", "/dev/ttyUSB1", "p3x", "FlycParam", "get", "g_config.flying_limit.max_height_0"]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        comm_og_service_tool_main()
    capstdout, _ = capsys.readouterr()
    assert "g_config.flying_limit.max_height_0 = 500" in capstdout
    pass

@pytest.mark.comm
def test_comm_og_service_tool_flyc_param_set(capsys):
    """ Test set function using typical answers.
    """
    command = [os.path.join(".", "comm_og_service_tool.py"), "-vvv", "--dry-test", "--port", "/dev/ttyUSB1", "p3x", "FlycParam", "set", "g_config.flying_limit.max_height_0", "499"]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        comm_og_service_tool_main()
    capstdout, _ = capsys.readouterr()
    assert "g_config.flying_limit.max_height_0 = 499" in capstdout

    command = [os.path.join(".", "comm_og_service_tool.py"), "-vvv", "--dry-test", "--port", "/dev/ttyUSB1", "SPARK", "FlycParam", "set", "g_config.flying_limit.max_height_0", "500"]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        comm_og_service_tool_main()
    capstdout, _ = capsys.readouterr()
    assert "g_config.flying_limit.max_height_0 = " in capstdout
    pass

@pytest.mark.comm
def test_comm_og_service_tool_gimbal_calib(capsys):
    """ Test gimbal calibration function using typical answers.
    """
    command = [os.path.join(".", "comm_og_service_tool.py"), "-vvv", "--dry-test", "--port", "/dev/ttyUSB1", "SPARK", "GimbalCalib", "JointCoarse"]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        comm_og_service_tool_main()
    capstdout, _ = capsys.readouterr()
    assert "; result: PASS" in capstdout

    command = [os.path.join(".", "comm_og_service_tool.py"), "-vvv", "--dry-test", "--port", "/dev/ttyUSB1", "SPARK", "GimbalCalib", "LinearHall"]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        comm_og_service_tool_main()
    capstdout, _ = capsys.readouterr()
    assert "; result: PASS" in capstdout
    pass
