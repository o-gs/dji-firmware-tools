#!/bin/bash
# -*- coding: utf-8 -*-

# Execute this from upper level directory

# Copyright (C) 2016-2021 Mefistotelis <mefistotelis@gmail.com>
# Copyright (C) 2018-2021 Original Gangsters <https://dji-rev.slack.com/>
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

set +x

if [ ! -f "tests/test_dji_imah_fwsig_rebin1.sh" ]; then
  echo '### SUITE sub-script not found; executed from wrong directory? ###'
  exit 4
fi

declare -a FWPKG_LIST=(
V01.03.0200_Mavic_dji_system.bin
V01.03.0900_Mavic_dji_system.bin
V01.04.0000_Mavic_dji_system.bin
V01.04.0500_Mavic_dji_system.bin
)

# In case we want to use Python from non-standard location
#PATH="/mingw64/bin:$PATH"

echo "Using Python: $(which python3)"

set -e

NUMFAILS=0
NUMSKIPS=0

for FWPKG in "${FWPKG_LIST[@]}"; do
  FWDLURL=
  FWDLNAME=
  FWTSTFLG=0x00

  # Download firmwares

  if [ ! -f "fw_imah1/${FWPKG}" ]; then

    if [ ! -f "fw_imah1/${FWDLNAME}" ] && [ $((FWTSTFLG & 0x01)) -ne 0 ]; then
      curl "${FWDLURL}" -o "fw_imah1/${FWDLNAME}"
    fi

    if [ ! -f "fw_imah1/${FWDLNAME}" ]; then
      echo '### SKIP could not download firmware to test ###'
      ((NUMSKIPS++))
      continue
    fi

    if [[ ${FWDLNAME} =~ [.]zip$ ]]; then
      (unzip -j -o -d fw "fw_imah1/${FWDLNAME}")
    elif [[ ${FWDLNAME} =~ [.]rar$ ]]; then
      (cd fw && unrar e "${FWDLNAME}")
    fi
  fi

  if [ ! -f "fw_imah1/${FWPKG}" ]; then
    echo '### SKIP could not extract firmware to test ###'
    ((NUMSKIPS++))
    continue
  fi

  SIGDIR=
  if [ ! -z "${FWPKG}" ]; then
    SIGDIR=${FWPKG%.*}
    # Extract the package TAR file
    mkdir "${SIGDIR}"
    tar -xf "fw_imah1/${FWPKG}" -C "${SIGDIR}"
    if [ $? -ne 0 ]; then
      ((NUMFAILS++))
    fi
  fi

  SIGLIST=$(find "${SIGDIR}/" -type f -name "*.sig")

  if [ ! -z "${SIGLIST}" ]; then
    for SIGFILE in ${SIGLIST}; do
      # Execute test - DJI firmware extractor
      tests/test_dji_imah_fwsig_rebin1.sh -sn "${SIGFILE}"
      if [ $? -ne 0 ]; then
        ((NUMFAILS++))
      fi
      # per-SIG Cleanup
      if [ ! -z "${SIGDIR}" ]; then
        tests/test_dji_imah_fwsig_rebin1.sh -on "${SIGFILE}"
      fi
    done
  fi

  # Package Cleanup
  if [ ! -z "${SIGLIST}" ]; then
    rm ${SIGLIST}
  fi
  if [ ! -z "${SIGDIR}" ]; then
    rm -d "${SIGDIR}"
  fi

done

if [ ${NUMSKIPS} -gt 0 ]; then
    echo "### SKIP count during tests is ${NUMSKIPS} ###"
fi

if [ ${NUMFAILS} -eq 0 ]; then
    echo "### PASS all tests ###"
else
    echo "### FAIL count during tests is ${NUMFAILS} ###"
fi


exit 0

