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

declare -a FWPKG1_LIST=(
V01.03.0200_Mavic_dji_system.bin
V01.04.0500_Mavic_dji_system.bin
V01.03.0400_RC_Mavic_dji_system.bin
V02.00.0700_P4_dji_system.bin
V01.01.0203_P4P_dji_system.bin
V01.00.1000_P4PV2_dji_system.bin
V01.02.0500_I2_dji_system.bin
V01.00.0900_Spark_dji_system.bin
V01.00.0002_RC_Spark_fw.tar
)

declare -a FWPKG2_LIST=(
V00.02.0026_Mavic_Air_dji_system.tar
V01.00.0100_Mavic_Air_dji_system.tar
V01.00.0500_Mavic_Air_dji_system.bin
V01.00.0000_Mavic_Air_RC_dji_system.tar
V01.00.0200_Mavic_Air_RC_dji_system.bin
V01.00.0113_Mavic_Air_2_dji_system.bin
V01.01.0610_Mavic_Air_2_dji_system.bin
V09.09.0902_Mavic_Air_2_dji_system.bin
V01.00.0108_Mavic_Air_2_RC_dji_system.bin
V02.00.1200_Mavic_Air_2_RC_dji_system.bin
V02.04.1640_wm232_dji_system.bin
V04.11.0016_RC-N1-WM161b_dji_system.bin
V01.00.0600_lt150_dji_system.bin
V01.00.0500_Mavic_Mini_dji_system.tar
V01.00.0200_Mavic_Mini_dji_system.tar
V01.00.0000_Mavic_Mini_2_dji_system.bin
V01.02.0300_Mavic_Mini_2_dji_system.bin
V01.01.0000_Mavic_Mini_2_SE_dji_system.bin
V01.00.0600_FPV_Goggles_dji_system.bin
V00.04.1009_FPV_Racer_dji_system.bin
V01.01.0000_FPV_Racer_dji_system.bin
V01.01.0000_FPV_Racer_RC_dji_system.bin
V01.01.0000_FPV_Racer_RC_Motion_dji_system.bin
V01.01.0000_gl170_dji_system.bin
V00.06.0000_Mavic2_dji_system.bin
V01.00.0510_Mavic2_dji_system.bin
V01.00.0640_RC_Mavic2_dji_system.bin
V01.00.0100_RC_Mavic2_dji_system.bin
V01.00.0670_wm240_dji_system.bin
V01.01.0000_Mavic2_Enterprise_dji_system.bin
V01.01.0800_Mavic2_Enterprise_dji_system.bin
V01.00.0000_Mavic2_Enterprise_Dual_dji_system.bin
V01.01.0800_Mavic2_Enterprise_Dual_dji_system.bin
)

# In case we want to use Python from non-standard location
#PATH="/mingw64/bin:$PATH"

echo "Using Python: $(which python3)"

NUMFAILS=0
NUMSKIPS=0

function test_dji_imah_package {
  FWPKG="$1"
  FWDIR="$2"
  FWDLURL="$3"
  FWDLNAME="$4"
  FWTSTFLG="$5"
  LAST_NUMFAILS=${NUMFAILS}

  # Download firmwares

  if [ ! -f "${FWDIR}/${FWPKG}" ]; then

    if [ ! -f "${FWDIR}/${FWDLNAME}" ] && [ $((FWTSTFLG & 0x01)) -ne 0 ]; then
      curl "${FWDLURL}" -o "${FWDIR}/${FWDLNAME}"
    fi

    if [ ! -f "${FWDIR}/${FWDLNAME}" ]; then
      echo '### SKIP could not download firmware to test ###'
      ((NUMSKIPS++))
      return 1
    fi

    if [[ ${FWDLNAME} =~ [.]zip$ ]]; then
      (unzip -j -o -d fw "${FWDIR}/${FWDLNAME}")
    elif [[ ${FWDLNAME} =~ [.]rar$ ]]; then
      (cd fw && unrar e "${FWDLNAME}")
    fi
  fi

  if [ ! -f "${FWDIR}/${FWPKG}" ]; then
    echo '### SKIP could not extract firmware to test ###'
    ((NUMSKIPS++))
    return 1
  fi

  SIGDIR=
  if [ ! -z "${FWPKG}" ]; then
    SIGDIR=${FWPKG%.*}
    # Extract the package TAR file
    mkdir "${SIGDIR}"
    tar -xf "${FWDIR}/${FWPKG}" -C "${SIGDIR}"
    if [ $? -ne 0 ]; then
      ((NUMFAILS++))
    fi
  fi

  SIGLIST=$(find "${SIGDIR}/" -type f -name "*.sig")

  if [ ! -z "${SIGLIST}" ]; then
    for SIGFILE in ${SIGLIST}; do
      # Execute test - DJI firmware extractor
      tests/test_dji_imah_fwsig_rebin1.sh -sn "${SIGFILE}"
      RESULT=$?
      if [ $RESULT -ne 0 ]; then
        echo '### FAIL: Error code '$RESULT' returned from test ###'
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

  # Mention which file caused fails, for easier debug
  NEW_NUMFAILS=$(( NUMFAILS - LAST_NUMFAILS ))
  if (( ${NEW_NUMFAILS} > 0 )); then
    echo "### FAIL count while processing ${FWPKG} is ${NEW_NUMFAILS} ###"
  fi

  return 0
}

for FWPKG in "${FWPKG1_LIST[@]}"; do
  FWDIR="fw_imah1"
  FWDLURL=
  FWDLNAME=
  FWTSTFLG=0x00

  test_dji_imah_package "${FWPKG}" "${FWDIR}" "${FWDLURL}" "${FWDLNAME}" "${FWTSTFLG}"
done

for FWPKG in "${FWPKG2_LIST[@]}"; do
  FWDIR="fw_imah2"
  FWDLURL=
  FWDLNAME=
  FWTSTFLG=0x00

  test_dji_imah_package "${FWPKG}" "${FWDIR}" "${FWDLURL}" "${FWDLNAME}" "${FWTSTFLG}"
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

