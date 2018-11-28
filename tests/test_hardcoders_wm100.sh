#!/bin/bash
# -*- coding: utf-8 -*-

# Tests modding scripts by preparing a set of modded firmwares

# Copyright (C) 2017,2018 Mefistotelis <mefistotelis@gmail.com>
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

declare -a FWPKG_LIST=(
V01.00.0006_Spark_dji_system.bin
V01.00.0500_Spark_dji_system.bin
V01.00.0600_Spark_dji_system.bin
V01.00.0701_Spark_dji_system.bin
#V01.00.0900_Spark_dji_system.bin # same m0306 version as 01.00.0701, no need to test
)

# In case we want to use Python from non-standard location
#PATH="/mingw64/bin:$PATH"

echo "Using Python: $(which python3)"

set -e

function modify_json_value_inplace {
  JSONFILE="$1"
  VALNAME="$2"
  VALSET="$3"
  sed -i '/^[ \t]*"setValue"[ \t]*:[ \t]*\([0-9.-]\+\|"[0-9a-zA-Z. #:;_\+-]\+"\),$/{
       $!{ N        # append the next line when not on the last line
         s/^\([ \t]*"setValue"[ \t]*:[ \t]*\)\([0-9a-zA-Z. #:;_\+"-]\+\)\(,\n[ \t]*"name"[ \t]*:[ \t]*"'"${VALNAME}"'"\)$/\1'"${VALSET}"'\3/
                    # now test for a successful substitution, otherwise
                    #+  unpaired "a test" lines would be mis-handled
         t sub-yes  # branch_on_substitute (goto label :sub-yes)
         :sub-not   # a label (not essential; here to self document)
                    # if no substituion, print only the first line
         P          # pattern_first_line_print
         D          # pattern_ltrunc(line+nl)_top/cycle
         :sub-yes   # a label (the goto target of the 't' branch)
                    # fall through to final auto-pattern_print (2 lines)
       }    
     }' "${JSONFILE}"
}

function verify_changed_bytes_between_files {
  MIN_CHANGED="$1"
  MAX_CHANGED="$2"
  FILE1="$3"
  FILE2="$4"

  local FWDIFF_COUNT=$(cmp -l "${FILE1}" "${FILE2}" | wc -l)

  if [ "${FWDIFF_COUNT}" -lt "${MIN_CHANGED}" ] || [ "${FWDIFF_COUNT}" -gt "${MAX_CHANGED}" ]; then
    echo "### FAIL: found ${FWDIFF_COUNT} binary changes which is outside expected range (${MIN_CHANGED}..${MAX_CHANGED}). ###"
    exit 2
  fi
  echo "### OK: Amount of changes in bin file, ${FWDIFF_COUNT}, is reasonable. ###"
}

function exec_mod_for_m0306 {
  local FWMODL=$1
  set -x
  cp "${FWMODL}.bin" "${FWMODL}.orig.bin"
  if [[ "${FWMODL}" < "wm100_0306_v03.02.34.99" ]]; then
    # command optimized for  wm100_0306_v03.02.34.02
    ./arm_bin2elf.py -vv -e -b 0x00420000 --section .ARM.exidx@0x0127e90:0 --section .bss@0x1ffe0000:0x60000 \
     --section .bss2@0x3fcc0000:0x1000 --section .bss3@0xdfbe0000:0x10000 \
     -p "${FWMODL}.bin"
  else
    # command optimized for  wm100_0306_v03.02.37.55
    ./arm_bin2elf.py -vv -e -b 0x00420000 --section .ARM.exidx@0x0105a10:0 --section .bss@0x1ffe0000:0x60000 \
     --section .bss2@0x3fcc0000:0x1000 --section .bss3@0xdfbe0000:0x10000 \
     -p "${FWMODL}.bin"
  fi

  ./dji_flyc_hardcoder.py -vvv -x -e "${FWMODL}.elf"

  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]flyc[.]min_alt_below_home" "-800.0"
  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]flyc[.]max_alt_above_home" "4000.0"
  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]flyc[.]max_wp_dist_to_home" "6000.0"
  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]flyc[.]max_mission_path_len" "40000.0"
  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]flyc[.]max_speed_pos" "25.0"
  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]flyc[.]max_speed_neg" "-25.0"
  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]flyc[.]firmware_version" "\"12.34.56.78\""

  ./dji_flyc_hardcoder.py -vvv -u -e "${FWMODL}.elf"
  arm-none-eabi-objcopy -O binary "${FWMODL}.elf" "${FWMODL}.bin"

  # Verify by checking amount of changes within the file
  set +x
  if [[ "${FWMODL}" < "wm100_0306_v03.02.34.99" ]]; then
    # TODO - partial support only
    verify_changed_bytes_between_files 12 48 "${FWMODL}.orig.bin" "${FWMODL}.bin"
  else
    verify_changed_bytes_between_files 32 48 "${FWMODL}.orig.bin" "${FWMODL}.bin"
  fi
  echo "### SUCCESS: Binary file changes are within acceptable limits. ###"
}

for FWPKG in "${FWPKG_LIST[@]}"; do
  echo "### TEST of modding tools with ${FWPKG} ###"
  FWIMAH_LIST=$(tar -xvf "fw_imah/${FWPKG}")
  FWIMAH_0306=$(echo "${FWIMAH_LIST}" | sed -n 's/^\([a-z0-9]\+_0306_v.*\)[.]fw[.]sig$/\1/p')
  ./dji_imah_fwsig.py -vv -u -i "${FWIMAH_0306}.fw.sig"
  ./dji_mvfc_fwpak.py dec -i "${FWIMAH_0306}.fw_0306.bin"

  exec_mod_for_m0306 "${FWIMAH_0306}.fw_0306.decrypted"
done

echo "### PASS all tests ###"

exit 0
