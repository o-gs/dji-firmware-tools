#!/bin/bash
# -*- coding: utf-8 -*-

# Tests hardcoder scripts by preparing a set of modded firmwares for FCC zone

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

# Note that very old P3X and WM610 firmwares contain both RC and AC modules;
# these were separated in later firmwares.
declare -a FWPKG_LIST=(
P3X_FW_V01.03.0020
WM610_FW_V01.02.01.03
WM610_FW_V01.02.01.06
WM610_FW_V01.03.00.00
C1_FW_V01.04.0030
C1_FW_V01.05.0070
C1_FW_V01.05.0080
C1_FW_V01.06.0000
C1_FW_v01.05.0071
C1_FW_v01.06.0001
C1_FW_v01.07.0000
C1_FW_v01.08.0000
C1_FW_v01.09.0000
)

# In case we want to use Python from non-standard location
#PATH="/mingw64/bin:$PATH"

echo "Using Python: $(which python3)"

set -e

if [ -f ./dji ]; then
  echo "Found existing ./dji folder, please remove"
  exit 1
fi

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

function exec_mod_for_m1300 {
  local FWMODL=$1
  set -x
  openssl des3 -md md5 -d -k Dji123456 -in "${FWMODL}.bin"  -out "${FWMODL}_decrypted.tar.gz"
  # Symlinks creation will fail on Windows
  set +e
  tar -zxf "${FWMODL}_decrypted.tar.gz"
  set -e
  cp ./dji/bin/usbclient "./${FWMODL}-usbclient.elf"
  cp "./${FWMODL}-usbclient.elf" "./${FWMODL}-usbclient.orig.elf"
  #./dm3xx_encode_usb_hardcoder.py -vv -x -e "${FWMODL}-usbclient.elf"

  # now modify the generated JSON file

  #modify_json_value_inplace "${FWMODL}-usbclient.json" "og_hardcoded[.]p3x_dm3xx[.]startup_encrypt_check_always_pass" "1"

  #./dm3xx_encode_usb_hardcoder.py -vv -u -e "${FWMODL}-usbclient.elf"
  #cp -f "./${FWMODL}-usbclient.elf" ./dji/bin/usbclient
  #tar -zcf "${FWMODL}_decrypted.tar.gz" ./dji
  rm -rf ./dji
  openssl des3 -md md5 -e -k Dji123456 -in "${FWMODL}_decrypted.tar.gz"  -out "${FWMODL}.bin"

  # Verify by checking amount of changes within the file
  set +x
  #verify_changed_bytes_between_files 10 32 "./${FWMODL}-encode_usb.orig.elf" "./${FWMODL}-encode_usb.elf"
  echo "### SUCCESS: Binary file changes are within acceptable limits. ###"
}

function exec_mod_for_m1400 {
  local FWMODL=$1
  set -x
  cp "${FWMODL}.bin" "${FWMODL}.orig.bin"
  ./arm_bin2elf.py -vvv -e -b 0x000a000 --section .ARM.exidx@0x01ce00:0 --section .bss@0xfff6000:0x8000 \
   --section .bss2@0x3fff6000:0x50000 --section .bss3@0xdfff6000:0x10000 -p "${FWMODL}.bin"
  ./lightbridge_stm32_hardcoder.py -vvv -x -e "${FWMODL}.elf"

  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]lightbridge_stm32[.]packet_received_attenuation_override" "1"
  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]lightbridge_stm32[.]packet_received_attenuation_value" "0"
  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]lightbridge_stm32[.]board_[a-z0-9]*_attenuation_[a-z0-9]*_[a-z0-9]*" "0"

  ./lightbridge_stm32_hardcoder.py -vvv -u -e "${FWMODL}.elf"
  arm-none-eabi-objcopy -O binary "${FWMODL}.elf" "${FWMODL}.bin"

  # Verify by checking amount of changes within the file
  set +x
  if [[ "${FWPKG}" == "WM610_FW_V"* ]]; then
    # Old Inspire firmware, not fully suported
    verify_changed_bytes_between_files 2 32 "${FWMODL}.orig.bin" "${FWMODL}.bin"
  elif [[ "${FWMODL}" == "P3X_FW_V"* ]]; then
    # Old firmware, less attenuation values to modify
    verify_changed_bytes_between_files 6 32 "${FWMODL}.orig.bin" "${FWMODL}.bin"
  else
    verify_changed_bytes_between_files 9 32 "${FWMODL}.orig.bin" "${FWMODL}.bin"
  fi
  echo "### SUCCESS: Binary file changes are within acceptable limits. ###"
}

function exec_mod_for_m1401 {
  local FWMODL=$1
  set -x
  cp "${FWMODL}.bin" "${FWMODL}.orig.bin"
  ./arm_bin2elf.py -vv -e -b 0x000a000 --section .ARM.exidx@0x019300:0 --section .bss@0x1ff6000:0x4000 \
   --section .bss2@0x1ffe000:0x1000 --section .bss3@0x1bff6000:0x2400 --section .bss4@0x1c01a000:0x2400 \
   --section .bss5@0x40022000:0x50000 --section .bss6@0x400ee000:0x200 --section .bss7@0xe0004000:0x1200 \
   -p "${FWMODL}.bin"
  ./lightbridge_stm32_hardcoder.py -vvv -x -e "${FWMODL}.elf"

  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]lightbridge_stm32[.]packet_received_attenuation_override" "1"
  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]lightbridge_stm32[.]packet_received_attenuation_value" "0"
  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]lightbridge_stm32[.]board_[a-z0-9]*_attenuation_[a-z0-9]*_[a-z0-9]*" "0"

  ./lightbridge_stm32_hardcoder.py -vvv -u -e "${FWMODL}.elf"
  arm-none-eabi-objcopy -O binary "${FWMODL}.elf" "${FWMODL}.bin"

  # Verify by checking amount of changes within the file
  set +x
  verify_changed_bytes_between_files 6 32 "${FWMODL}.orig.bin" "${FWMODL}.bin"
  echo "### SUCCESS: Binary file changes are within acceptable limits. ###"
}

for FWPKG in "${FWPKG_LIST[@]}"; do
  echo "### TEST of hardcoders with ${FWPKG} ###"
  ./dji_xv4_fwcon.py -vvv -x -p "fw/${FWPKG}.bin"

  exec_mod_for_m1300 "${FWPKG}_m1300"
  exec_mod_for_m1400 "${FWPKG}_m1400"
  if [[ "${FWPKG}" > "C1_FW_V01.04.9999" ]] && [[ "${FWPKG}" != "P3X_FW_V"* ]] && [[ "${FWPKG}" != "WM610_FW_V"* ]]; then
    exec_mod_for_m1401 "${FWPKG}_m1401"
  fi
done

echo "### PASS all tests ###"

exit 0
