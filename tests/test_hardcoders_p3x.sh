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

function exec_mod_for_m0100 {
  local FWPKG=$1
  set -x
  cp "${FWPKG}_m0100.bin" "${FWPKG}_m0100.orig.bin"
  ./amba_fwpak.py -vvv -x -m "${FWPKG}_m0100.bin"
  ./amba_sys2elf.py -vv -e -l 0x6000000 --section .ARM.exidx@0x464800:0 -p "${FWPKG}_m0100_part_sys.a9s"
  ./amba_sys_hardcoder.py -vvv -x -e "${FWPKG}_m0100_part_sys.elf"

  sed -i '/^[ \t]*"setValue"[ \t]*:[ \t]*[0-9]\+,$/{
       $!{ N        # append the next line when not on the last line
         s/^\([ \t]*"setValue"[ \t]*:[ \t]*\)\([0-9]\+\)\(,\n[ \t]*"name"[ \t]*:[ \t]*"og_hardcoded[.]p3x_ambarella[.][a-z_]*_authority_level"\)$/\11\3/
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
     }' "${FWPKG}_m0100_part_sys.json"

  ./amba_sys_hardcoder.py -vvv -u -e "${FWPKG}_m0100_part_sys.elf"
  arm-none-eabi-objcopy -O binary "${FWPKG}_m0100_part_sys.elf" "${FWPKG}_m0100_part_sys.a9s"
  ./amba_fwpak.py -vvv -a -m "${FWPKG}_m0100.bin"

  # Verify by checking amount of changes within the file
  local FWDIFF_COUNT=$(cmp -l "${FWPKG}_m0100.orig.bin" "${FWPKG}_m0100.bin" | wc -l)
  set +x

  if [ "${FWDIFF_COUNT}" -le "4" ] || [ "${FWDIFF_COUNT}" -ge "48" ]; then
    echo "### FAIL: found ${FWDIFF_COUNT} binary changes which is outside expected range. ###"
    exit 2
  fi
  echo "### SUCCESS: Amount of changes in bin file is reasonable. ###"
}

function exec_mod_for_m0800 {
  local FWPKG=$1
  set -x
  openssl des3 -d -k Dji123456 -in "${FWPKG}_m0800.bin"  -out "${FWPKG}_m0800_decrypted.tar.gz"
  tar -zxf "${FWPKG}_m0800_decrypted.tar.gz"
  cp ./dji/bin/encode_usb "./${FWPKG}_m0800-encode_usb.elf"
  cp "./${FWPKG}_m0800-encode_usb.elf" "./${FWPKG}_m0800-encode_usb.orig.elf"
  ./dm3xx_encode_usb_hardcoder.py -vv -x -e "${FWPKG}_m0800-encode_usb.elf"

  # now modify *_m0800-encode_usb.json - we will use sed

  sed -i '/^[ \t]*"setValue"[ \t]*:[ \t]*[0-9]\+,$/{
       $!{ N        # append the next line when not on the last line
         s/^\([ \t]*"setValue"[ \t]*:[ \t]*\)\([0-9]\+\)\(,\n[ \t]*"name"[ \t]*:[ \t]*"og_hardcoded[.]p3x_dm3xx[.]startup_encrypt_check_always_pass"\)$/\11\3/
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
     }' "${FWPKG}_m0800-encode_usb.json"


  ./dm3xx_encode_usb_hardcoder.py -vv -u -e "${FWPKG}_m0800-encode_usb.elf"
  cp -f "./${FWPKG}_m0800-encode_usb.elf" ./dji/bin/encode_usb
  tar -zcf "${FWPKG}_m0800_decrypted.tar.gz" ./dji
  rm -rf ./dji
  openssl des3 -e -k Dji123456 -in "${FWPKG}_m0800_decrypted.tar.gz"  -out "${FWPKG}_m0800.bin"

  # Verify by checking amount of changes within the file
  local FWDIFF_COUNT=$(cmp -l "./${FWPKG}_m0800-encode_usb.orig.elf" "./${FWPKG}_m0800-encode_usb.elf" | wc -l)
  set +x

  if [ "${FWDIFF_COUNT}" -le "4" ] || [ "${FWDIFF_COUNT}" -ge "32" ]; then
    echo "### FAIL: found ${FWDIFF_COUNT} binary changes which is outside expected range. ###"
    exit 2
  fi
  echo "### SUCCESS: Amount of changes in bin file is reasonable. ###"
}

for FWPKG in "${FWPKG_LIST[@]}"; do
  echo "### TEST of hardcoders with ${FWPKG} ###"
  ./dji_xv4_fwcon.py -vvv -x -p "fw/${FWPKG}.bin"

  exec_mod_for_m0100 "${FWPKG}"
  exec_mod_for_m0800 "${FWPKG}"
done

echo "### PASS all tests ###"

exit 0
