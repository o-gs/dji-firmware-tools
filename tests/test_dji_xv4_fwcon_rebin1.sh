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

SKIP_EXTRACT=0
SKIP_REPACK=0
SKIP_CLEANUP=0
SKIP_COMPARE=0

if [ "$#" -lt "1" ]; then
    echo '### FAIL: No bin file name provided! ###'
    exit 4
fi

while [ "$#" -gt "0" ]
do
key="$1"

case $key in
  -se|--skip-extract)
    SKIP_EXTRACT=1
    ;;
  -sp|--skip-repack)
    SKIP_REPACK=1
    ;;
  -sn|--skip-cleanup)
    SKIP_CLEANUP=1
    ;;
  -sc|--skip-compare)
    SKIP_COMPARE=1
    ;;
  -on|--only-cleanup)
    SKIP_EXTRACT=1
    SKIP_REPACK=1
    SKIP_COMPARE=1
    ;;
  *)
    BINFILE="$key"
    ;;
esac
shift # past argument or value
done

if [ ! -f "${BINFILE}" ]; then
    echo '### FAIL: Input file not foumd! ###'
    echo "### INFO: Expexted file \"${BINFILE}\" ###"
    exit 3
fi

TESTFILE="${BINFILE%.*}-test.bin"
TESTFILE="${TESTFILE##*/}"

if [ "${SKIP_COMPARE}" -le "0" ]; then
  echo '### TEST for dji_xv4_fwcon.py re-creation of binary file ###'
  # The test extracts firmware modules from DJI firmware package, abd then repacks them.
  # The test ends with success if the resulting BIN file is
  # exactly the same as input BIN file.
fi

if [ "${SKIP_EXTRACT}" -le "0" ]; then
  echo "### INFO: Input file \"${BINFILE}\" ###"
  # Remove files which will be created
  rm ${TESTFILE%.*}_*.bin ${TESTFILE%.*}_*.ini 2>/dev/null
  # Extract firmwares for modules
  ./dji_xv4_fwcon.py -vvv -x -p "${BINFILE}" -m ${TESTFILE%.*}
fi

if [ "${SKIP_REPACK}" -le "0" ]; then
  # Remove file which will be created
  rm "${TESTFILE}" 2>/dev/null
  # Repack back to final format
  ./dji_xv4_fwcon.py -vvv -a -p "${TESTFILE}"
fi

if [ "${SKIP_COMPARE}" -le "0" ]; then
  # Compare converted with original
  cmp --silent "${BINFILE}" "${TESTFILE}"
  TEST_RESULT=$?
fi

if [ "${SKIP_CLEANUP}" -le "0" ]; then
  # Cleanup
  rm "${TESTFILE}" ${TESTFILE%.*}_*.bin ${TESTFILE%.*}_*.ini
fi

if [ "${SKIP_COMPARE}" -le "0" ]; then
  if [ ${TEST_RESULT} == 0 ]; then
    echo '### SUCCESS: File identical after conversion. ###'
  elif [ ! -s "${TESTFILE}" ]; then
    echo '### FAIL: File empty or missing; creation faled! ###'
    exit 2
  else
    echo '### FAIL: File changed during conversion! ###'
    exit 1
  fi
fi

exit 0
