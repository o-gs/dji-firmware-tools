# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, comm_sbs_bqctrl script.

    This test verifies functions of the script by using its
    "dry run" functionality. This simulates the battery,
    returning typical responses to all requests.
"""

# Copyright (C) 2023 Mefistotelis <mefistotelis@gmail.com>
#
# This work is licensed under the terms of the MIT license.
# For a copy, see <https://opensource.org/licenses/MIT>.

import logging
import os
import re
import sys
import pytest
from unittest.mock import patch

# Import the functions to be tested
from comm_sbs_bqctrl import main as comm_sbs_bqctrl_main


LOGGER = logging.getLogger(__name__)

def test_comm_sbs_bqctrl_chip_detect():
    """ Test detection on a mock chip.
    """
    # Provide chip - should know not to contact the chip even w/o "--dry-run"
    command = [os.path.join(".", "comm_sbs_bqctrl.py"), "-v", "--chip", "BQ30z55", "read-list"]
    with patch.object(sys, 'argv', command):
        comm_sbs_bqctrl_main()

    # Do not provide chip - test auto-detect
    command = [os.path.join(".", "comm_sbs_bqctrl.py"), "-v", "--dry-run", "info-list"]
    with patch.object(sys, 'argv', command):
        comm_sbs_bqctrl_main()
    pass


@pytest.mark.parametrize("chip_name,test_nth", [
  ("BQ30z55",3,),
  ("BQ40z50",3,),
  ("BQ40z307",3,),
])
def test_comm_sbs_bqctrl_chip_info_commands(capsys, chip_name, test_nth):
    """ Test info commands on a mock chip.
    """
    # Capture a list of commands
    command = [os.path.join(".", "comm_sbs_bqctrl.py"), "--dry-run", "--chip", chip_name, "info-list"]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        comm_sbs_bqctrl_main()
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
            comm_sbs_bqctrl_main()
        capstdout, _ = capsys.readouterr()
        assert "Type:" in capstdout
        assert "Description:" in capstdout
    pass


@pytest.mark.parametrize("chip_name,test_nth", [
  ("BQ30z55",3,),
  ("BQ40z50",3,),
  ("BQ40z307",3,),
])
def test_comm_sbs_bqctrl_chip_read_commands(capsys, chip_name, test_nth):
    """ Test read commands on a mock chip.
    """
    # Capture a list of commands
    command = [os.path.join(".", "comm_sbs_bqctrl.py"), "--dry-run", "--chip", chip_name, "read-list"]
    LOGGER.info(' '.join(command))
    with patch.object(sys, 'argv', command):
        comm_sbs_bqctrl_main()
    capstdout, _ = capsys.readouterr()
    read_commands = list(capstdout.splitlines())
    LOGGER.info("List of read commands: {}".format(', '.join(read_commands)))
    for cmd in read_commands:
        assert " " not in cmd, "Listed command has a space: {:s}".format(cmd)
    # Skip combinations not simulated properly ATM
    if chip_name == "BQ40z50":
        read_commands = [ cmd for cmd in read_commands if "Authenticate" not in cmd ]

    # Run some of the commands
    for read_cmd in read_commands[::test_nth]:
        command = [os.path.join(".", "comm_sbs_bqctrl.py"), "-vv", "--dry-run", "--chip", chip_name, "read", read_cmd]
        LOGGER.info(' '.join(command))
        with patch.object(sys, 'argv', command):
            comm_sbs_bqctrl_main()
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.parametrize("chip_name,test_nth", [
  ("BQ30z55",1,),
  ("BQ40z50",1,),
  ("BQ40z307",1,),
])
def test_comm_sbs_bqctrl_chip_monitor_commands(capsys, chip_name, test_nth):
    """ Test monitor commands on a mock chip.
    """
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
            comm_sbs_bqctrl_main()
        capstdout, _ = capsys.readouterr()
    pass


@pytest.mark.parametrize("chip_name,test_nth", [
  ("BQ30z55",1,),
  ("BQ40z50",1,),
  ("BQ40z307",1,),
])
def test_comm_sbs_bqctrl_chip_sealing_commands(capsys, chip_name, test_nth):
    """ Test sealing commands on a mock chip.
    """
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
            comm_sbs_bqctrl_main()
        capstdout, _ = capsys.readouterr()
        assert ".OperationStatus:" in capstdout
        # TODO maybe check status value, ie assert " SEC=1" in capstdout
    pass


@pytest.mark.parametrize("chip_name,flash_start,flash_end,flash_step", [
  ("BQ40z307", 0x0000, 0x0500, 0x20),
])
def test_comm_sbs_bqctrl_data_flash(chip_name, flash_start, flash_end, flash_step):
    """ Test reading data flash on a mock chip.
    """
    for flash_offset in range(flash_start, flash_end, flash_step):
        command = [os.path.join(".", "comm_sbs_bqctrl.py"), "-v", "--dry-run", "--chip", chip_name, "raw-read", "DataFlash", "0x{:X}".format(flash_offset), "string[32]"]
        LOGGER.info(' '.join(command))
        with patch.object(sys, 'argv', command):
            comm_sbs_bqctrl_main()
    pass
