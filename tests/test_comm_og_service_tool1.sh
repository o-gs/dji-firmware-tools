#!/bin/bash
# -*- coding: utf-8 -*-

# Copyright (C) 2016,2017 Mefistotelis <mefistotelis@gmail.com>
# Copyright (C) 2018 Original Gangsters <https://dji-rev.slack.com/>
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

./comm_og_service_tool.py --dry-test -vvv /dev/ttyUSB1 p3x FlycParam list --start=100 --fmt=2line
TEST_RESULT=$?

if [ ${TEST_RESULT} == 0 ]; then
    echo '### SUCCESS: FlycParam list 1 - No error returned. ###'
else
    echo '### FAIL: FlycParam list 1 - Script run failed! ###'
    exit 1
fi

./comm_og_service_tool.py --dry-test -vvv /dev/ttyUSB1 p3x FlycParam get g_config.flying_limit.max_height_0
TEST_RESULT=$?

if [ ${TEST_RESULT} == 0 ]; then
    echo '### SUCCESS: FlycParam get 1 - No error returned. ###'
else
    echo '### FAIL: FlycParam get 1 - Script run failed! ###'
    exit 1
fi

./comm_og_service_tool.py --dry-test -vvv /dev/ttyUSB1 p3x FlycParam set g_config.flying_limit.max_height_0 499
TEST_RESULT=$?

if [ ${TEST_RESULT} == 0 ]; then
    echo '### SUCCESS: FlycParam set 1 - No error returned. ###'
else
    echo '### FAIL: FlycParam set 1 - Script run failed! ###'
    exit 1
fi

./comm_og_service_tool.py --dry-test -vvv /dev/ttyUSB1 SPARK FlycParam set g_config.flying_limit.max_height_0 500
TEST_RESULT=$?

if [ ${TEST_RESULT} == 0 ]; then
    echo '### SUCCESS: FlycParam set 2 - No error returned. ###'
else
    echo '### FAIL: FlycParam set 2 - Script run failed! ###'
    exit 1
fi

./comm_og_service_tool.py --dry-test -vvv /dev/ttyUSB1 SPARK GimbalCalib JointCoarse
TEST_RESULT=$?

if [ ${TEST_RESULT} == 0 ]; then
    echo '### SUCCESS: GimbalCalib JointCoarse 1 - No error returned. ###'
else
    echo '### FAIL: GimbalCalib JointCoarse 1 - Script run failed! ###'
    exit 1
fi

./comm_og_service_tool.py --dry-test -vvv /dev/ttyUSB1 SPARK GimbalCalib LinearHall
TEST_RESULT=$?

if [ ${TEST_RESULT} == 0 ]; then
    echo '### SUCCESS: GimbalCalib LinearHall 1 - No error returned. ###'
else
    echo '### FAIL: GimbalCalib LinearHall 1 - Script run failed! ###'
    exit 1
fi

exit 0
