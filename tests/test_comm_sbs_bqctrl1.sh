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


function test_chip_detect {

    # Provide chip - should know not to contact the chip even w/o "--dry-run"
    if true; then
        set -x # print the command before executing
        ./comm_sbs_bqctrl.py --chip BQ30z55 read-list
        TEST_RESULT=$?
        set +x

        if [ ${TEST_RESULT} == 0 ]; then
            echo '### SUCCESS: read-list - No error returned. ###'
        else
            echo '### FAIL: read-list - Script run failed! ###'
            exit 1
        fi
    fi

    # Do not provide chip - test auto-detect
    if true; then
        set -x # print the command before executing
        ./comm_sbs_bqctrl.py --dry-run info-list
        TEST_RESULT=$?
        set +x

        if [ ${TEST_RESULT} == 0 ]; then
            echo '### SUCCESS: info-list - No error returned. ###'
        else
            echo '### FAIL: info-list - Script run failed! ###'
            exit 1
        fi
    fi
}


function test_chip_commands {
    TEST_PARAMS=$1
    # Prepare command lists

    ./comm_sbs_bqctrl.py ${TEST_PARAMS} info-list | tee "${TMPFILE}"
    INFO_LIST=$(cat "${TMPFILE}" | tr "\r" " " | tr "\n" " ")

    ./comm_sbs_bqctrl.py ${TEST_PARAMS} read-list | tee "${TMPFILE}"
    READ_LIST=$(cat "${TMPFILE}" | tr "\r" " " | tr "\n" " ")

    ./comm_sbs_bqctrl.py ${TEST_PARAMS} trigger-list | tee "${TMPFILE}"
    TRIGGER_LIST=$(cat "${TMPFILE}" | tr "\r" " " | tr "\n" " ")

    ./comm_sbs_bqctrl.py ${TEST_PARAMS} write-list | tee "${TMPFILE}"
    WRITE_LIST=$(cat "${TMPFILE}" | tr "\r" " " | tr "\n" " ")


    for SBSCMD in ${INFO_LIST}; do
        set -x # print the command before executing
        ./comm_sbs_bqctrl.py -vvv ${TEST_PARAMS} info "${SBSCMD}"
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
    READ_LIST=$(echo -n "${READ_LIST}" | sed -e 's/\([A-Za-z]\+[.]\)\?\(ManufacturerData\|ManufacturerInput\|Authenticate\) / /g')

    for SBSCMD in ${READ_LIST}; do
        set -x # print the command before executing
        ./comm_sbs_bqctrl.py -vvv ${TEST_PARAMS} read ${SBSCMD}
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
        ./comm_sbs_bqctrl.py -vvv ${TEST_PARAMS} trigger ${SBSCMD}
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
        ./comm_sbs_bqctrl.py -vvv ${TEST_PARAMS} --short monitor ${SBSGROUP}
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
        ./comm_sbs_bqctrl.py -vvv ${TEST_PARAMS} --short sealing ${SBSGROUP}
        TEST_RESULT=$?
        set +x

        if [ ${TEST_RESULT} == 0 ]; then
            echo '### SUCCESS: sealing '${SBSGROUP}' - No error returned. ###'
        else
            echo '### FAIL: sealing '${SBSGROUP}' - Script run failed! ###'
            exit 1
        fi
    done

}

function test_data_flash {
    TEST_PARAMS=$1
    DATAFLASH_LIST=$(seq 0x0000 0x0020 0x0500)

    for DFOFFS in ${DATAFLASH_LIST}; do
        set -x # print the command before executing
        ./comm_sbs_bqctrl.py -vvv ${TEST_PARAMS} raw-read DataFlash ${DFOFFS} 'string[32]'
        TEST_RESULT=$?
        set +x

        if [ ${TEST_RESULT} == 0 ]; then
            echo '### SUCCESS: raw-read DataFlash '${DFOFFS}' - No error returned. ###'
        else
            echo '### FAIL: raw-read DataFlash '${DFOFFS}' - Script run failed! ###'
            exit 1
        fi
    done

}


test_chip_detect

test_chip_commands "--chip BQ30z55 --dry-run"

test_chip_commands "--chip BQ40z50 --dry-run"

test_chip_commands "--chip BQ40z307 --dry-run"

test_data_flash "--chip BQ40z307 --dry-run"

exit 0
