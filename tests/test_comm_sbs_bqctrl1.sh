#!/bin/bash
# -*- coding: utf-8 -*-

# Copyright (C) 2021 Mefistotelis <mefistotelis@gmail.com>
# Copyright (C) 2021 Original Gangsters <https://dji-rev.slack.com/>
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

TMPFILE=_tmp_test_comm_sbs_bqctrl1.log

# Prepare command lists

./comm_sbs_bqctrl.py --chip BQ30z55 info-list | tee "${TMPFILE}"
INFO_LIST=$(cat "${TMPFILE}" | tr "\r" " " | tr "\n" " ")

./comm_sbs_bqctrl.py --chip BQ30z55 read-list | tee "${TMPFILE}"
READ_LIST=$(cat "${TMPFILE}" | tr "\r" " " | tr "\n" " ")

./comm_sbs_bqctrl.py --chip BQ30z55 trigger-list | tee "${TMPFILE}"
TRIGGER_LIST=$(cat "${TMPFILE}" | tr "\r" " " | tr "\n" " ")

./comm_sbs_bqctrl.py --chip BQ30z55 write-list | tee "${TMPFILE}"
WRITE_LIST=$(cat "${TMPFILE}" | tr "\r" " " | tr "\n" " ")


for SBSCMD in ${INFO_LIST}; do
    set -x # print the command before executing
    ./comm_sbs_bqctrl.py -vvv --chip BQ30z55 info "${SBSCMD}"
    TEST_RESULT=$?
    set +x

    if [ ${TEST_RESULT} == 0 ]; then
        echo '### SUCCESS: info '${SBSCMD}' - No error returned. ###'
    else
        echo '### FAIL: info '${SBSCMD}' - Script run failed! ###'
        exit 1
    fi
done

# Remove commands which do not support dry-run
READ_LIST=$(echo -n "${READ_LIST}" | sed -e 's/\(ManufacturerAccess[.]\)\?\(ManufacturerData\|ManufacturerInput\) / /g')

for SBSCMD in ${READ_LIST}; do
    set -x # print the command before executing
    ./comm_sbs_bqctrl.py -vvv --chip BQ30z55 --dry-run read ${SBSCMD}
    TEST_RESULT=$?
    set +x

    if [ ${TEST_RESULT} == 0 ]; then
        echo '### SUCCESS: read '${SBSCMD}' - No error returned. ###'
    else
        echo '### FAIL: read '${SBSCMD}' - Script run failed! ###'
        exit 1
    fi
done

for SBSCMD in ${TRIGGER_LIST}; do
    set -x # print the command before executing
    ./comm_sbs_bqctrl.py -vvv --chip BQ30z55 --dry-run trigger ${SBSCMD}
    TEST_RESULT=$?
    set +x

    if [ ${TEST_RESULT} == 0 ]; then
        echo '### SUCCESS: trigger '${SBSCMD}' - No error returned. ###'
    else
        echo '### FAIL: trigger '${SBSCMD}' - Script run failed! ###'
        exit 1
    fi
done

# No WRITE validation - the command isn't finished yet

MONITOR_LIST="DeviceInfo UsageInfo ComputedInfo StatusBits AtRates
  BQCellVoltages BQStatusBits BQStatusBitsMA BQLifetimeData BQLifetimeDataMA
  ImpedanceTrack ImpedanceTrackMA"

for SBSGROUP in ${MONITOR_LIST}; do
    set -x # print the command before executing
    ./comm_sbs_bqctrl.py -vvv --dry-run --short monitor ${SBSGROUP}
    TEST_RESULT=$?
    set +x

    if [ ${TEST_RESULT} == 0 ]; then
        echo '### SUCCESS: monitor '${SBSGROUP}' - No error returned. ###'
    else
        echo '### FAIL: monitor '${SBSGROUP}' - Script run failed! ###'
        exit 1
    fi
done

SEALING_LIST="Unseal Seal"

for SBSGROUP in ${SEALING_LIST}; do
    set -x # print the command before executing
    ./comm_sbs_bqctrl.py -vvv --dry-run --short sealing ${SBSGROUP}
    TEST_RESULT=$?
    set +x

    if [ ${TEST_RESULT} == 0 ]; then
        echo '### SUCCESS: sealing '${SBSGROUP}' - No error returned. ###'
    else
        echo '### FAIL: sealing '${SBSGROUP}' - Script run failed! ###'
        exit 1
    fi
done

exit 0
