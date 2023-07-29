# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, comm_sbs_bqctrl script.

    This test verifies functions of the script by using its
    "dry run" functionality. This simulates the battery,
    returning typical responses to all requests.
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
from comm_sbs_bqctrl import main as comm_sbs_bqctrl_main


LOGGER = logging.getLogger(__name__)

@pytest.mark.comm
def test_comm_sbs_bqctrl_chip_detect(capsys):
    """ Test detection on a mock chip.
    """
    # Provide chip - should know not to contact the chip even w/o "--dry-run"
    command = [os.path.join(".", "comm_sbs_bqctrl.py"), "-v", "--chip", "BQ30z55", "read-list"]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        comm_sbs_bqctrl_main(command[1:])
    capstdout, _ = capsys.readouterr()

    # Do not provide chip - test auto-detect
    command = [os.path.join(".", "comm_sbs_bqctrl.py"), "-v", "--dry-run", "info-list"]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        comm_sbs_bqctrl_main(command[1:])
    capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.comm
@pytest.mark.parametrize("chip_name,test_nth", [
  ("BQ30z55",3,),
  ("BQ40z50",3,),
  ("BQ40z307",3,),
])
def test_comm_sbs_bqctrl_chip_info_commands(capsys, chip_name, test_nth):
    """ Test info commands on a mock chip.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    # Capture a list of commands
    command = [os.path.join(".", "comm_sbs_bqctrl.py"), "--dry-run", "--chip", chip_name, "info-list"]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        comm_sbs_bqctrl_main(command[1:])
    capstdout, _ = capsys.readouterr()
    info_commands = list(capstdout.splitlines())
    LOGGER.info("List of info commands: {}".format(', '.join(info_commands)))
    for cmd in info_commands:
        assert " " not in cmd, "Listed command has a space: {:s}".format(cmd)

    # Run some of the commands
    for info_cmd in info_commands[::test_nth]:
        command = [os.path.join(".", "comm_sbs_bqctrl.py"), "-v", "--dry-run", "--chip", chip_name, "info", info_cmd]
        LOGGER.info(' '.join(command))
        with patch.object(sys, 'argv', command):
            comm_sbs_bqctrl_main(command[1:])
        capstdout, _ = capsys.readouterr()
        assert "Type:" in capstdout
        assert "Description:" in capstdout
    pass


@pytest.mark.comm
@pytest.mark.parametrize("chip_name,test_nth", [
  ("BQ30z55",1,),
  ("BQ40z50",1,),
  ("BQ40z307",1,),
])
def test_comm_sbs_bqctrl_chip_read_commands(capsys, chip_name, test_nth):
    """ Test read commands on a mock chip.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    # Capture a list of commands
    command = [os.path.join(".", "comm_sbs_bqctrl.py"), "--dry-run", "--chip", chip_name, "read-list"]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        comm_sbs_bqctrl_main(command[1:])
    capstdout, _ = capsys.readouterr()
    read_commands = list(capstdout.splitlines())
    LOGGER.info("List of read commands: {}".format(', '.join(read_commands)))
    for cmd in read_commands:
        assert " " not in cmd, "Listed command has a space: {:s}".format(cmd)
    # Skip combinations not simulated properly ATM
    if chip_name == "BQ30z55":
        read_commands = [ cmd for cmd in read_commands if not (cmd.endswith("ManufacturerData") or cmd.endswith("ManufacturerInput")) ]
    elif chip_name in ("BQ40z50", "BQ40z307",):
        read_commands = [ cmd for cmd in read_commands if not (cmd in ("Authenticate",) or cmd.endswith("ManufacturerData")) ]

    # Run some of the commands
    for read_cmd in read_commands[::test_nth]:
        command = [os.path.join(".", "comm_sbs_bqctrl.py"), "-vv", "--dry-run", "--chip", chip_name, "read", read_cmd]
        LOGGER.info(' '.join(command))
        with patch.object(sys, 'argv', command):
            comm_sbs_bqctrl_main(command[1:])
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.comm
@pytest.mark.parametrize("chip_name,test_nth", [
  ("BQ30z55",3,),
  ("BQ40z50",3,),
  ("BQ40z307",3,),
])
def test_comm_sbs_bqctrl_chip_write_commands(capsys, chip_name, test_nth):
    """ Test write commands on a mock chip.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    # Capture a list of commands
    command = [os.path.join(".", "comm_sbs_bqctrl.py"), "--dry-run", "--chip", chip_name, "write-list"]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        comm_sbs_bqctrl_main(command[1:])
    capstdout, _ = capsys.readouterr()
    write_commands = list(capstdout.splitlines())
    pytest.skip("no tests for write command as the command is unfinished")


@pytest.mark.comm
@pytest.mark.parametrize("chip_name,test_nth", [
  ("BQ30z55",1,),
  ("BQ40z50",1,),
  ("BQ40z307",1,),
])
def test_comm_sbs_bqctrl_chip_monitor_commands(capsys, chip_name, test_nth):
    """ Test monitor commands on a mock chip.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    # Prepare a list of commands
    monitor_commands = [
      "DeviceInfo", "UsageInfo", "ComputedInfo", "StatusBits", "AtRates", "BQCellVoltages", "BQStatusBits",
      "BQStatusBitsMA", "BQLifetimeData", "BQLifetimeDataMA", "ImpedanceTrack", "ImpedanceTrackMA",
    ]
    LOGGER.info("List of monitor commands: {}".format(', '.join(monitor_commands)))

    # Run some of the commands
    for monitor_cmd in monitor_commands[::test_nth]:
        command = [os.path.join(".", "comm_sbs_bqctrl.py"), "-vvv", "--dry-run", "--chip", chip_name, "--short", "monitor", monitor_cmd]
        LOGGER.info(' '.join(command))
        with patch.object(sys, 'argv', command):
            comm_sbs_bqctrl_main(command[1:])
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.comm
@pytest.mark.parametrize("chip_name,test_nth", [
  ("BQ30z55",1,),
  ("BQ40z50",1,),
  ("BQ40z307",1,),
])
def test_comm_sbs_bqctrl_chip_sealing_commands(capsys, chip_name, test_nth):
    """ Test sealing commands on a mock chip.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    # Prepare a list of commands
    sealing_commands = [
      "Unseal", "Seal", "FullAccess",
    ]
    LOGGER.info("List of sealing commands: {}".format(', '.join(sealing_commands)))
    # Skip combinations not simulated properly ATM
    if chip_name == "BQ30z55":
        sealing_commands = [ cmd for cmd in sealing_commands if cmd not in ("FullAccess",) ]

    # Run some of the commands
    for sealing_cmd in sealing_commands[::test_nth]:
        command = [os.path.join(".", "comm_sbs_bqctrl.py"), "-vvv", "--dry-run", "--chip", chip_name, "--short", "sealing", sealing_cmd]
        LOGGER.info(' '.join(command))
        with patch.object(sys, 'argv', command):
            comm_sbs_bqctrl_main(command[1:])
        capstdout, _ = capsys.readouterr()
        assert ".OperationStatus:" in capstdout
        # TODO maybe check status value, ie assert " SEC=1" in capstdout
    pass


@pytest.mark.comm
@pytest.mark.parametrize("chip_name,flash_start,flash_end,flash_step,test_nth", [
  ("BQ40z307", 0x0000, 0x0500, 0x20, 2),
])
def test_comm_sbs_bqctrl_data_flash(capsys, chip_name, flash_start, flash_end, flash_step, test_nth):
    """ Test reading data flash on a mock chip.
    """
    if test_nth < 1:
        pytest.skip("limited scope")

    for flash_offset in range(flash_start, flash_end, flash_step)[::test_nth]:
        command = [os.path.join(".", "comm_sbs_bqctrl.py"), "-v", "--dry-run", "--chip", chip_name, "raw-read", "DataFlash", "0x{:X}".format(flash_offset), "string[32]"]
        LOGGER.info(' '.join(command))
        with patch.object(sys, 'argv', command):
            comm_sbs_bqctrl_main(command[1:])
        capstdout, _ = capsys.readouterr()
    pass
