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

declare -a FWPKG_LIST=(
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

function exec_mod_for_m1400 {
  local FWPKG=$1
  set -x
  cp "${FWPKG}_m1400.bin" "${FWPKG}_m1400.orig.bin"
  ./arm_bin2elf.py -vvv -e -b 0x000a000 --section .ARM.exidx@0x01ce00:0 --section .bss@0xfff6000:0x8000 \
   --section .bss2@0x3fff6000:0x50000 --section .bss3@0xdfff6000:0x10000 -p "${FWPKG}_m1400.bin"
  ./lightbridge_stm32_hardcoder.py -vvv -x -e "${FWPKG}_m1400.elf"

  sed -i '/^[ \t]*"setValue"[ \t]*:[ \t]*[0-9]\+,$/{
       $!{ N        # append the next line when not on the last line
         s/^\([ \t]*"setValue"[ \t]*:[ \t]*\)\([0-9]\+\)\(,\n[ \t]*"name"[ \t]*:[ \t]*"og_hardcoded[.]lightbridge_stm32[.]packet_received_attenuation_override"\)$/\11\3/
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
     }' "${FWPKG}_m1400.json"

  sed -i '/^[ \t]*"setValue"[ \t]*:[ \t]*[0-9]\+,$/{
       $!{ N        # append the next line when not on the last line
         s/^\([ \t]*"setValue"[ \t]*:[ \t]*\)\([0-9]\+\)\(,\n[ \t]*"name"[ \t]*:[ \t]*"og_hardcoded[.]lightbridge_stm32[.]packet_received_attenuation_value"\)$/\10\3/
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
     }' "${FWPKG}_m1400.json"

  sed -i '/^[ \t]*"setValue"[ \t]*:[ \t]*[0-9]\+,$/{
       $!{ N        # append the next line when not on the last line
         s/^\([ \t]*"setValue"[ \t]*:[ \t]*\)\([0-9]\+\)\(,\n[ \t]*"name"[ \t]*:[ \t]*"og_hardcoded[.]lightbridge_stm32[.]board_[a-z0-9]*_attenuation_[a-z0-9]*_[a-z0-9]*"\)$/\10\3/
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
     }' "${FWPKG}_m1400.json"

  ./lightbridge_stm32_hardcoder.py -vvv -u -e "${FWPKG}_m1400.elf"
  arm-none-eabi-objcopy -O binary "${FWPKG}_m1400.elf" "${FWPKG}_m1400.bin"

  # Verify by checking amount of changes within the file
  local FWDIFF_COUNT=$(cmp -l "${FWPKG}_m1400.orig.bin" "${FWPKG}_m1400.bin" | wc -l)
  set +x

  if [ "${FWDIFF_COUNT}" -le "1" ] || [ "${FWDIFF_COUNT}" -ge "32" ]; then
    echo "### FAIL: found ${FWDIFF_COUNT} binary changes which is outside expected range. ###"
    exit 2
  fi
  echo "### SUCCESS: Amount of changes in bin file is reasonable. ###"
}

function exec_mod_for_m1401 {
  local FWPKG=$1
  set -x
  cp "${FWPKG}_m1401.bin" "${FWPKG}_m1401.orig.bin"
  ./arm_bin2elf.py -vv -e -b 0x000a000 --section .ARM.exidx@0x019300:0 --section .bss@0x1ff6000:0x4000 \
   --section .bss2@0x1ffe000:0x1000 --section .bss3@0x1bff6000:0x2400 --section .bss4@0x1c01a000:0x2400 \
   --section .bss5@0x40022000:0x50000 --section .bss6@0x400ee000:0x200 --section .bss7@0xe0004000:0x1200 \
   -p "${FWPKG}_m1401.bin"
  ./lightbridge_stm32_hardcoder.py -vvv -x -e "${FWPKG}_m1401.elf"

  sed -i '/^[ \t]*"setValue"[ \t]*:[ \t]*[0-9]\+,$/{
       $!{ N        # append the next line when not on the last line
         s/^\([ \t]*"setValue"[ \t]*:[ \t]*\)\([0-9]\+\)\(,\n[ \t]*"name"[ \t]*:[ \t]*"og_hardcoded[.]lightbridge_stm32[.]packet_received_attenuation_override"\)$/\11\3/
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
     }' "${FWPKG}_m1401.json"

  sed -i '/^[ \t]*"setValue"[ \t]*:[ \t]*[0-9]\+,$/{
       $!{ N        # append the next line when not on the last line
         s/^\([ \t]*"setValue"[ \t]*:[ \t]*\)\([0-9]\+\)\(,\n[ \t]*"name"[ \t]*:[ \t]*"og_hardcoded[.]lightbridge_stm32[.]packet_received_attenuation_value"\)$/\10\3/
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
     }' "${FWPKG}_m1401.json"

  sed -i '/^[ \t]*"setValue"[ \t]*:[ \t]*[0-9]\+,$/{
       $!{ N        # append the next line when not on the last line
         s/^\([ \t]*"setValue"[ \t]*:[ \t]*\)\([0-9]\+\)\(,\n[ \t]*"name"[ \t]*:[ \t]*"og_hardcoded[.]lightbridge_stm32[.]board_[a-z0-9]*_attenuation_[a-z0-9]*_[a-z0-9]*"\)$/\10\3/
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
     }' "${FWPKG}_m1401.json"

  ./lightbridge_stm32_hardcoder.py -vvv -u -e "${FWPKG}_m1401.elf"
  arm-none-eabi-objcopy -O binary "${FWPKG}_m1401.elf" "${FWPKG}_m1401.bin"

  # Verify by checking amount of changes within the file
  local FWDIFF_COUNT=$(cmp -l "${FWPKG}_m1401.orig.bin" "${FWPKG}_m1401.bin" | wc -l)
  set +x

  if [ "${FWDIFF_COUNT}" -le "1" ] || [ "${FWDIFF_COUNT}" -ge "32" ]; then
    echo "### FAIL: found ${FWDIFF_COUNT} binary changes which is outside expected range. ###"
    exit 2
  fi
  echo "### SUCCESS: Amount of changes in bin file is reasonable. ###"
}

for FWPKG in "${FWPKG_LIST[@]}"; do
  echo "### TEST of hardcoders with ${FWPKG} ###"
  ./dji_xv4_fwcon.py -vvv -x -p "fw/${FWPKG}.bin"

  exec_mod_for_m1400 "${FWPKG}"
  if [[ "${FWPKG}" > "C1_FW_V01.04.9999" ]]; then
    exec_mod_for_m1401 "${FWPKG}"
  fi
done

echo "### PASS all tests ###"

exit 0
