#!/bin/bash
# -*- coding: utf-8 -*-

# Tests hardcoder scripts by preparing a set of modded firmwares for 8fps encryption issue

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

declare -a FWPKG_LIST=(
P3X_FW_V01.01.0006
P3X_FW_V01.03.0020
P3X_FW_V01.04.0005
P3X_FW_V01.05.0030
P3X_FW_V01.06.0040
P3X_FW_V01.07.0060
P3X_FW_V01.08.0080
P3X_FW_V01.09.0060
P3X_FW_V01.10.0090
P3X_FW_V01.11.0030
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

function exec_mod_for_m0100 {
  local FWMODL=$1
  set -x
  cp "${FWMODL}.bin" "${FWMODL}.orig.bin"
  ./amba_fwpak.py -vvv -x -m "${FWMODL}.bin"
  ./amba_sys2elf.py -vv -e -l 0x6000000 --section .ARM.exidx@0x464800:0 -p "${FWMODL}_part_sys.a9s"
  ./amba_sys_hardcoder.py -vvv -x -e "${FWMODL}_part_sys.elf"

  modify_json_value_inplace "${FWMODL}_part_sys.json" "og_hardcoded[.]p3x_ambarella[.][a-z_]*_authority_level" "1"

  ./amba_sys_hardcoder.py -vvv -u -e "${FWMODL}_part_sys.elf"
  arm-none-eabi-objcopy -O binary "${FWMODL}_part_sys.elf" "${FWMODL}_part_sys.a9s"
  ./amba_fwpak.py -vvv -a -m "${FWMODL}.bin"

  # Verify by checking amount of changes within the file
  set +x
  verify_changed_bytes_between_files 28 48 "${FWMODL}.orig.bin" "${FWMODL}.bin"
  echo "### SUCCESS: Binary file changes are within acceptable limits. ###"
}

function exec_mod_for_m0800 {
  local FWMODL=$1
  set -x
  openssl des3 -md md5 -d -k Dji123456 -in "${FWMODL}.bin"  -out "${FWMODL}_decrypted.tar.gz"
  tar -zxf "${FWMODL}_decrypted.tar.gz"
  cp ./dji/bin/encode_usb "./${FWMODL}-encode_usb.elf"
  cp "./${FWMODL}-encode_usb.elf" "./${FWMODL}-encode_usb.orig.elf"
  ./dm3xx_encode_usb_hardcoder.py -vv -x -e "${FWMODL}-encode_usb.elf"

  # now modify the generated JSON file

  modify_json_value_inplace "${FWMODL}-encode_usb.json" "og_hardcoded[.]p3x_dm3xx[.]startup_encrypt_check_always_pass" "1"

  ./dm3xx_encode_usb_hardcoder.py -vv -u -e "${FWMODL}-encode_usb.elf"
  cp -f "./${FWMODL}-encode_usb.elf" ./dji/bin/encode_usb
  tar -zcf "${FWMODL}_decrypted.tar.gz" ./dji
  rm -rf ./dji
  openssl des3 -md md5 -e -k Dji123456 -in "${FWMODL}_decrypted.tar.gz"  -out "${FWMODL}.bin"

  # Verify by checking amount of changes within the file
  set +x
  verify_changed_bytes_between_files 10 32 "./${FWMODL}-encode_usb.orig.elf" "./${FWMODL}-encode_usb.elf"
  echo "### SUCCESS: Binary file changes are within acceptable limits. ###"
}

function exec_mod_for_m0306 {
  local FWMODL=$1
  set -x
  cp "${FWMODL}.bin" "${FWMODL}.orig.bin"
  ./arm_bin2elf.py -vvv -e -b 0x8020000 --section .ARM.exidx@0x085d34:0 --section .bss@0x07fe0000:0xA000 \
   --section .bss2@0x17fe0000:0x30000 --section .bss3@0x37fe0000:0x30000 -p "${FWMODL}.bin"
  ./dji_flyc_hardcoder.py -vvv -x -e "${FWMODL}.elf"

  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]flyc[.]min_alt_below_home" "-800.0"
  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]flyc[.]max_alt_above_home" "4000.0"
  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]flyc[.]max_wp_dist_to_home" "6000.0"
  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]flyc[.]max_mission_path_len" "40000.0"
  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]flyc[.]max_speed_pos" "25.0"
  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]flyc[.]max_speed_neg" "-25.0"

  ./dji_flyc_hardcoder.py -vvv -u -e "${FWMODL}.elf"
  arm-none-eabi-objcopy -O binary "${FWMODL}.elf" "${FWMODL}.bin"

  # Verify by checking amount of changes within the file
  set +x
  verify_changed_bytes_between_files 12 48 "${FWMODL}.orig.bin" "${FWMODL}.bin"
  echo "### SUCCESS: Binary file changes are within acceptable limits. ###"
}

function exec_mod_for_m0900 {
  local FWMODL=$1
  set -x
  cp "${FWMODL}.bin" "${FWMODL}.orig.bin"
  ./arm_bin2elf.py -vvv -e -b 0x8008000 --section .ARM.exidx@0x0D500:0 --section .bss@0x17FF7700:0x5A00 \
   --section .bss2@0x37ff8000:0x6700 --section .bss3@0x38008000:0x5500 --section .bss4@0x38018000:0x2200 \
   --section .bss5@0x3a1f8000:0x100 --section .bss6@0x3a418000:0x500 -p "${FWMODL}.bin"
  ./lightbridge_stm32_hardcoder.py -vvv -x -e "${FWMODL}.elf"

  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]lightbridge_stm32[.]packet_received_attenuation_override" "1"
  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]lightbridge_stm32[.]packet_received_attenuation_value" "0"
  modify_json_value_inplace "${FWMODL}.json" "og_hardcoded[.]lightbridge_stm32[.]board_[a-z0-9]*_attenuation_[a-z0-9]*_[a-z0-9]*" "0"

  ./lightbridge_stm32_hardcoder.py -vvv -u -e "${FWMODL}.elf"
  arm-none-eabi-objcopy -O binary "${FWMODL}.elf" "${FWMODL}.bin"

  # Verify by checking amount of changes within the file
  set +x
  if [[ "${FWMODL}" < "P3X_FW_V01.04.9999_m0900" ]]; then
    # TODO - partial support only
    verify_changed_bytes_between_files 2 32 "${FWMODL}.orig.bin" "${FWMODL}.bin"
  else
    verify_changed_bytes_between_files 32 48 "${FWMODL}.orig.bin" "${FWMODL}.bin"
  fi
  echo "### SUCCESS: Binary file changes are within acceptable limits. ###"
}

for FWPKG in "${FWPKG_LIST[@]}"; do
  echo "### TEST of hardcoders with ${FWPKG} ###"
  ./dji_xv4_fwcon.py -vvv -x -p "fw/${FWPKG}.bin"

  exec_mod_for_m0100 "${FWPKG}_m0100"
  exec_mod_for_m0800 "${FWPKG}_m0800"
  if [[ "${FWPKG}" > "P3X_FW_V01.04.9999" ]]; then
    exec_mod_for_m0306 "${FWPKG}_m0306"
  fi
  exec_mod_for_m0900 "${FWPKG}_m0900"
done

echo "### PASS all tests ###"

exit 0
