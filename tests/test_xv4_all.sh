#!/bin/bash
# -*- coding: utf-8 -*-

# Execute this from upper level directory

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

set +x

if [ ! -f "tests/test_dji_xv4_fwcon_rebin1.sh" ]; then
  echo '### SUITE sub-script not found; executed from wrong directory? ###'
  exit 4
fi

if [ ! -f "supported_firmwares_xv4.csv" ]; then
  echo '### SUITE fw list not found; executed from wrong directory? ###'
  exit 4
fi

EXEC_FLAG=0x04
#EXEC_FLAG=0x02 # use to download and test all firmwares instead of selected few

mkdir -p fw

declare -a all_firmwares=()

i=0
while IFS=, read product binname dlpage dlurl dlname testflg alltherest
do
  printf -v itm "itm_fw%05d" $i
  # Remove prefix/suffix quotes
  binname="${binname%\"}"
  binname="${binname#\"}"
  dlurl="${dlurl%\"}"
  dlurl="${dlurl#\"}"
  dlname="${dlname%\"}"
  dlname="${dlname#\"}"
  #echo "$itm:$product|$binname|$dlpage|$dlurl|$dlname|$testflg"
  # Verify flags
  if [ $i -eq 0 ]; then
    testflg=0
  fi
  re='^[0-9]+$'
  if ! [[ ${testflg} =~ $re ]]; then
      echo '### SKIP fw list entry '$i' has non-numeric test flags ###'
      testflg=0
  fi
  declare -A ${itm}
  eval ${itm}[binname]=\"${binname}\"
  eval ${itm}[dlurl]=\"${dlurl}\"
  eval ${itm}[dlname]=\"${dlname}\"
  eval ${itm}[testflg]=\"${testflg}\"
  # Verify entry
  if [ ${testflg} -ne 0 ]; then
    if [ -z "${binname}" ]; then
      echo '### SKIP fw list entry '$i' has no binary file name set ###'
      testflg=0
    fi
  fi
  # Select firmwares for testing
  if [ $((testflg & EXEC_FLAG)) -ne 0 ]; then
    all_firmwares+=("$itm")
  fi

  i=$((i+1))
done < supported_firmwares_xv4.csv

NUMFAILS=0
NUMSKIPS=0

for itm in "${all_firmwares[@]}"; do
  tmp=${itm}[dlurl]
  FWDLURL=${!tmp}
  tmp=${itm}[dlname]
  FWDLNAME=${!tmp}
  tmp=${itm}[binname]
  FWPKG=${!tmp}
  tmp=${itm}[testflg]
  FWTSTFLG=${!tmp}

  # Download firmwares

  if [ ! -f "fw/${FWPKG}" ]; then

    if [ ! -f "fw/${FWDLNAME}" ] && [ $((FWTSTFLG & 0x01)) -ne 0 ]; then
      curl "${FWDLURL}" -o "fw/${FWDLNAME}"
    fi

    if [ ! -f "fw/${FWDLNAME}" ]; then
      echo '### SKIP could not download firmware to test ###'
      ((NUMSKIPS++))
      continue
    fi

    if [[ ${FWDLNAME} =~ [.]zip$ ]]; then
      (unzip -j -o -d fw "fw/${FWDLNAME}")
    elif [[ ${FWDLNAME} =~ [.]rar$ ]]; then
      (cd fw && unrar e "${FWDLNAME}")
    fi
  fi

  if [ ! -f "fw/${FWPKG}" ]; then
    echo '### SKIP could not extract firmware to test ###'
    ((NUMSKIPS++))
    continue
  fi

  if [ ! -z "${FWPKG}" ]; then
    # Execute test - DJI firmware extractor
    tests/test_dji_xv4_fwcon_rebin1.sh -sn "fw/${FWPKG}"
    if [ $? -ne 0 ]; then
      ((NUMFAILS++))
    fi
  fi

  # Find Ambarella App firmware file name
  AMBAPKG1=$(grep '^target=m0100' "${FWPKG%.*}-test_"*".ini" | head -n 1 | cut -d : -f 1)
  if [ -z "${AMBAPKG1}" ]; then
    echo '### SKIP no ambarella app firmware found in extracted files ###'
    AMBAPKG1=
    ((NUMSKIPS++))
  fi
  if [ ! -z "${AMBAPKG1}" ]; then
    AMBAPKG1="${AMBAPKG1%.*}.bin"
  fi

  if [ ! -z "${AMBAPKG1}" ]; then
    # Execute test - Ambarella firmware extractor
    tests/test_amba_fwpak_repack1.sh -sn "${AMBAPKG1}"
    if [ $? -ne 0 ]; then
      ((NUMFAILS++))
    fi
  fi

  # Get Ambarella system partition file name
  AMBAPKG1SYS="${AMBAPKG1%.*}_part_sys.a9s"
  if [ ! -f "${AMBAPKG1SYS}" ]; then
    echo '### SKIP no ambarella app system partition found in extracted files ###'
    AMBAPKG1SYS=
    ((NUMSKIPS++))
  fi

  if [ ! -z "${AMBAPKG1SYS}" ]; then
    # Execute test - Ambarella system partition to ELF wrapper
    tests/test_amba_sys2elf_rebin1.sh -sn "${AMBAPKG1SYS}"
    if [ $? -ne 0 ]; then
      ((NUMFAILS++))
    fi
  fi

  # Find Ambarella Ldr firmware file name
  AMBAPKG2=$(grep '^target=m0101' "${FWPKG%.*}-test_"*".ini" | head -n 1 | cut -d : -f 1)
  if [ -z "${AMBAPKG2}" ]; then
    echo '### SKIP no ambarella ldr firmware found in extracted files ###'
    ((NUMSKIPS++))
  fi
  if [ ! -z "${AMBAPKG2}" ]; then
    AMBAPKG2="${AMBAPKG2%.*}.bin"
  fi

  if [ ! -z "${AMBAPKG2}" ]; then
    # Execute test - Ambarella firmware extractor
    tests/test_amba_fwpak_repack1.sh -sn "${AMBAPKG2}"
    if [ $? -ne 0 ]; then
      ((NUMFAILS++))
    fi
  fi

  # Cleanup

  if [ ! -z "${AMBAPKG1SYS}" ]; then
    tests/test_amba_sys2elf_rebin1.sh -on "${AMBAPKG1SYS}"
  fi

  if [ ! -z "${AMBAPKG2}" ]; then
    tests/test_amba_fwpak_repack1.sh -on "${AMBAPKG2}"
  fi

  if [ ! -z "${AMBAPKG1}" ]; then
    tests/test_amba_fwpak_repack1.sh -on "${AMBAPKG1}"
  fi

  if [ ! -z "${FWPKG}" ]; then
    tests/test_dji_xv4_fwcon_rebin1.sh -on "fw/${FWPKG}"
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

