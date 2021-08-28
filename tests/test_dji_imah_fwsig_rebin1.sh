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

set -eo pipefail
set -x

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
    echo "### INFO: Expected file \"${BINFILE}\" ###"
    exit 3
fi

TESTFILE="${BINFILE%.*}-test.sig"
SUPPORTS_MVFC_ENC=1
SUPPORTS_ANDR_OTA_BOOTIMG_ENC=1
SUPPORTS_ANDR_TGZ_BOOTIMG_ENC=1
SUPPORTS_ANDR_TAR_BOOTIMG_ENC=1
SUPPORTS_ANDR_LZA_BOOTIMG_ENC=1
SUPPORTS_ANDR_LZ4_BOOTIMG_ENC=1
HAS_MVFC_ENC=
HAS_ANDR_OTA_BOOTIMG_ENC=
HAS_ANDR_TGZ_BOOTIMG_ENC=
HAS_ANDR_TAR_BOOTIMG_ENC=
HAS_ANDR_LZA_BOOTIMG_ENC=
HAS_ANDR_LZ4_BOOTIMG_ENC=
EXTRAPAR_NESTED_m0100=
EXTRAPAR_NESTED_m0801=
EXTRAPAR_NESTED_m0901=
EXTRAPAR_NESTED_m0907=
NESTED_CHANGES_LIMIT=

if [ "${SKIP_COMPARE}" -le "0" ]; then
  echo '### TEST for dji_imah_fwsig.py and dji_mvfc_fwpak.py re-creation of binary file ###'
  # The test extracts firmware module from signed (and often encrypted)
  # DJI IMaH format, and then repacks it.
  # The test ends with success if the resulting BIN file is
  # exactly the same as input BIN file.
fi

BINFNAME=$(basename "${BINFILE}" | tr '[:upper:]' '[:lower:]')
if   [[ ${BINFNAME} =~ ^wm220[._].*[.]sig$ ]]; then
  EXTRAPAR="-k PRAK-2017-01 -k PUEK-2017-07"
  # allow change of 2 bytes from auth key name, 256 from signature
  HEAD_CHANGES_LIMIT=$((2 + 256))
  NESTED_CHANGES_LIMIT=$(( HEAD_CHANGES_LIMIT + 3*16 ))
  EXTRAPAR_NESTED_m0801="-k PRAK-2017-01 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
  EXTRAPAR_NESTED_m1301="-k PRAK-2017-01 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
elif [[ ${BINFNAME} =~ ^wm330[._].*[.]sig$ ]]; then
  EXTRAPAR="-k PRAK-2017-01 -k PUEK-2017-07"
  # allow change of 2 bytes from auth key name, 256 from signature
  HEAD_CHANGES_LIMIT=$((2 + 256))
  NESTED_CHANGES_LIMIT=$(( HEAD_CHANGES_LIMIT + 3*16 ))
  EXTRAPAR_NESTED_m0801="-k PRAK-2017-01 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
elif [[ ${BINFNAME} =~ ^wm33[1-6][._].*[.]sig$ ]]; then
  EXTRAPAR="-k PRAK-2017-01 -k PUEK-2017-11 -f" # PUEK not published, forcing extract encrypted
  # allow change of 2 bytes from auth key name, 256 from signature, up to 16 chunk padding, 32 payload digest
  HEAD_CHANGES_LIMIT=$((2 + 256 + 16+32))
  SUPPORTS_MVFC_ENC=0 # Decryption of 2nd lv FC enc won't work without 1st stage
  SUPPORTS_ANDR_OTA_BOOTIMG_ENC=0 # IAEK not published
elif [[ ${BINFNAME} =~ ^wm100[._a].*[.]sig$ ]]; then
  EXTRAPAR="-k PRAK-2017-01 -k PUEK-2017-09 -f" # PUEK not published, forcing extract encrypted
  # allow change of 2 bytes from auth key name, 256 from signature
  HEAD_CHANGES_LIMIT=$((2 + 256))
  NESTED_CHANGES_LIMIT=$(( HEAD_CHANGES_LIMIT + 3*16 ))
  EXTRAPAR_NESTED_m0801="-k PRAK-2017-01 -k RREK-2017-01 -k IAEK-2017-01 -f" # IAEK not published, forcing extract encrypted
  SUPPORTS_MVFC_ENC=0 # Decryption of 2nd lv FC enc won't work without 1st stage
elif [[ ${BINFNAME} =~ ^(wm620|rc001)[._].*[.]sig$ ]]; then
  EXTRAPAR="-k PRAK-2017-01 -k PUEK-2017-09 -f" # PUEK not published, forcing extract encrypted
  # allow change of 2 bytes from auth key name, 4 from enc checksum, 256 from signature
  HEAD_CHANGES_LIMIT=$((2 + 4 + 256))
  NESTED_CHANGES_LIMIT=$(( HEAD_CHANGES_LIMIT + 3*16 ))
  SUPPORTS_MVFC_ENC=0 # Decryption of 2nd lv FC enc won't work without 1st stage
elif [[ ${BINFNAME} =~ ^(wm230)[._].*[.]sig$ ]]; then
  EXTRAPAR="-k PRAK-2018-01 -k UFIE-2018-01 -k TBIE-2018-01"
  EXTRAPAR_NESTED_m0801="-k PRAK-2018-01 -k TBIE-2018-01 -k FCIE-2018-04 -k TKIE-2018-04 -f" # TBIE, FCIE, TKIE not published, forcing extract encrypted
  # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
  HEAD_CHANGES_LIMIT=$((2 + 4 + 4 + 256 + 32+16))
  # nested files have more chunks, so allow more discrepencies for chunk padding
  NESTED_CHANGES_LIMIT=$(( HEAD_CHANGES_LIMIT + 6*16 ))
  SUPPORTS_MVFC_ENC=0 # Decryption of 2nd lv FC enc not currently supported for this platform
elif [[ ${BINFNAME} =~ ^(rc230)[._].*[.]sig$ ]]; then
  EXTRAPAR="-k PRAK-2018-02 -k UFIE-2018-01 -f" # PRAK not published, forcing ignore signature fail
  # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
  HEAD_CHANGES_LIMIT=$((2 + 4 + 4 + 256 + 32+16))
  SUPPORTS_MVFC_ENC=0 # Decryption of 2nd lv FC enc not currently supported for this platform
elif [[ ${BINFNAME} =~ ^(wm170|wm231|wm232|gl170|pm430|ag500)[._].*[.]sig$ ]]; then
  EXTRAPAR="-k PRAK-2018-02 -k UFIE-2020-04 -f" # PRAK not published, forcing ignore signature fail
  # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
  HEAD_CHANGES_LIMIT=$((2 + 4 + 4 + 256 + 32+16))
  # nested files have more chunks, so allow more discrepencies for chunk padding
  NESTED_CHANGES_LIMIT=$(( HEAD_CHANGES_LIMIT + 15*16 ))
  SUPPORTS_MVFC_ENC=0 # Decryption of 2nd lv FC enc not currently supported for this platform
elif [[ ${BINFNAME} =~ ^(rcss170|rcjs170|rcs231|rc-n1-wm161b)[._].*[.]sig$ ]]; then
  EXTRAPAR="-k PRAK-2018-02 -k TBIE-2020-04 -f" # PRAK not published, forcing ignore signature fail; modules not encrypted, boot images encrypted
  # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
  HEAD_CHANGES_LIMIT=$((2 + 4 + 4 + 256 + 32+16))
  SUPPORTS_MVFC_ENC=0 # Decryption of 2nd lv FC enc not currently supported for this platform
  SUPPORTS_ANDR_TAR_BOOTIMG_ENC=1
elif [[ ${BINFNAME} =~ ^(wm24[0-6])[._].*[.]sig$ ]]; then
  EXTRAPAR="-k PRAK-2018-01 -k UFIE-2018-07 -k TBIE-2018-07"
  EXTRAPAR_NESTED_m0901="-k PRAK-2018-01 -f" # PRAK not published, forcing ignore signature fail; IAEK not published, forcing extract encrypted
  EXTRAPAR_NESTED_m0907="${EXTRAPAR_NESTED_m0901}"
  # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
  HEAD_CHANGES_LIMIT=$((2 + 4 + 4 + 256 + 32+16))
  SUPPORTS_MVFC_ENC=0 # Decryption of 2nd lv FC enc not currently supported for this platform
elif [[ ${BINFNAME} =~ ^(gl150|wm150|lt150)[._].*[.]sig$ ]]; then
  EXTRAPAR="-k PRAK-2018-01 -k UFIE-2018-07 -k TBIE-2018-07"
  # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
  HEAD_CHANGES_LIMIT=$((2 + 4 + 4 + 256 + 32+16))
  SUPPORTS_MVFC_ENC=0 # Decryption of 2nd lv FC enc not currently supported for this platform
elif [[ ${BINFNAME} =~ ^(rc240)[._].*[.]sig$ ]]; then
  EXTRAPAR="-k PRAK-2018-02 -k UFIE-2018-07 -f" # PRAK not published, forcing ignore signature fail
  # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
  HEAD_CHANGES_LIMIT=$((2 + 4 + 4 + 256 + 32+16))
  SUPPORTS_MVFC_ENC=0 # Decryption of 2nd lv FC enc not currently supported for this platform
elif [[ ${BINFNAME} =~ ^wm160[._].*[.]sig$ ]]; then
  EXTRAPAR="-k PRAK-2019-09 -k UFIE-2019-11"
  EXTRAPAR_NESTED_m0100="-k PRAK-2019-09 -k TBIE-2019-11 -k TKIE-2019-11"
  # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
  HEAD_CHANGES_LIMIT=$((2 + 4 + 4 + 256 + 32+16))
  # nested files have more chunks, so allow more discrepencies for chunk padding
  NESTED_CHANGES_LIMIT=$(( HEAD_CHANGES_LIMIT + 16 ))
  SUPPORTS_MVFC_ENC=0 # Decryption of 2nd lv FC enc not currently supported for this platform
elif [[ ${BINFNAME} =~ ^wm1605[._].*[.]sig$ ]]; then
  EXTRAPAR="-k PRAK-2019-09 -k UFIE-2021-06"
  EXTRAPAR_NESTED_m0100="-k PRAK-2019-09 -k TBIE-2021-06 -k TKIE-2021-06"
  # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
  HEAD_CHANGES_LIMIT=$((2 + 4 + 4 + 256 + 32+16))
  # nested files have more chunks, so allow more discrepencies for chunk padding
  NESTED_CHANGES_LIMIT=$(( HEAD_CHANGES_LIMIT + 16 ))
  SUPPORTS_MVFC_ENC=0 # Decryption of 2nd lv FC enc not currently supported for this platform
elif [[ ${BINFNAME} =~ ^wm161[._].*[.]sig$ ]]; then
  EXTRAPAR="-k PRAK-2019-09 -k UFIE-2019-11"
  EXTRAPAR_NESTED_m0100="-k PRAK-2019-09 -k TBIE-2019-11 -k TKIE-2019-11"
  # allow change of 2 bytes from auth key name, 4+4 from enc+dec checksum, 256 from signature, up to 16 chunk padding, 32 payload digest
  HEAD_CHANGES_LIMIT=$((2 + 4 + 4 + 256 + 32+16))
  # nested files have more chunks, so allow more discrepencies for chunk padding
  NESTED_CHANGES_LIMIT=$(( HEAD_CHANGES_LIMIT + 16 ))
  SUPPORTS_MVFC_ENC=0 # Decryption of 2nd lv FC enc not currently supported for this platform
else
  EXTRAPAR=""
  HEAD_CHANGES_LIMIT=$((2 + 4 + 4 + 256))
fi

if [ -z "${NESTED_CHANGES_LIMIT}" ]; then
  NESTED_CHANGES_LIMIT=${HEAD_CHANGES_LIMIT}
fi

if [ "${SKIP_EXTRACT}" -le "0" ]; then
  echo "### INFO: Input file \"${BINFILE}\" ###"
  # Remove files which will be created
  set +e
  rm ${TESTFILE%.*}_*.bin ${TESTFILE%.*}_*.ini 2>/dev/null
  set -e
  # Unsign/decrypt the module
  ./dji_imah_fwsig.py -vv ${EXTRAPAR} -u -i "${BINFILE}" -m "${TESTFILE%.*}" 2>&1 | tee "${TESTFILE%.*}_unsig.log"

  # FC modules have another stage of encryption which can be handled by MVFC script
  HAS_MVFC_ENC=$(sed -n 's/^modules=\([0-9]\{4\}[ ]\)*\(0305\|0306\).*$/\2/p' "${TESTFILE%.*}_head.ini" | head -n 1)
  if [ "${SUPPORTS_MVFC_ENC}" -le "0" ] && [ ! -z "${HAS_MVFC_ENC}" ]; then
    MODULE="${HAS_MVFC_ENC}"
    echo "### INFO: Found m${MODULE} inside, but 2nd stage MVFC decrypt disabled for this platform ###"
    HAS_MVFC_ENC=
  fi
  if [ ! -z "${HAS_MVFC_ENC}" ]; then
    MODULE="${HAS_MVFC_ENC}"
    echo "### INFO: Found m${MODULE} inside, doing 2nd stage MVFC decrypt ###"
    ./dji_mvfc_fwpak.py -vv dec -i "${TESTFILE%.*}_${MODULE}.bin" \
      -o "${TESTFILE%.*}_${MODULE}.decrypted.bin" 2>&1 | tee "${TESTFILE%.*}_${MODULE}.log"
  fi
fi

if true; then
  # Some Android OTA modules contain boot images which have another stage of IMaH encryption
  HAS_ANDR_OTA_BOOTIMG_ENC=$(sed -n 's/^modules=\([0-9]\{4\}[ ]\)*\(0801\|0802\|0901\|1301\|2801\|2805\).*$/\2/p' "${TESTFILE%.*}_head.ini" | head -n 1)
  MODULE="${HAS_ANDR_OTA_BOOTIMG_ENC}"
  if [ "${SUPPORTS_ANDR_OTA_BOOTIMG_ENC}" -le 0 ] && [ ! -z "${HAS_ANDR_OTA_BOOTIMG_ENC}" ]; then
    echo "### INFO: Found m${MODULE} inside, but 2nd stage Android OTA bootimg decrypt disabled for this platform ###"
    HAS_ANDR_OTA_BOOTIMG_ENC=
  fi
  if [ ! -z "${HAS_ANDR_OTA_BOOTIMG_ENC}" ] && [[ $(file "${TESTFILE%.*}_${MODULE}.bin") != *"Java archive"* ]]; then
    echo "### INFO: Found m${MODULE} inside, but 2nd stage Android OTA bootimg decrypt disabled because it is not Java archive ###"
    HAS_ANDR_OTA_BOOTIMG_ENC=
  fi
fi

if [ "${SKIP_EXTRACT}" -le "0" ]; then
  if [ ! -z "${HAS_ANDR_OTA_BOOTIMG_ENC}" ]; then
    echo "### INFO: Found m${MODULE} inside, doing 2nd stage Android OTA bootimg decrypt ###"
    unzip -q -o -d "${TESTFILE%.*}_${MODULE}" "${TESTFILE%.*}_${MODULE}.bin"
  fi
fi

if true; then
  # Some Android TGZ modules also contain boot images with another stage of IMaH encryption
  HAS_ANDR_TGZ_BOOTIMG_ENC=$(sed -n 's/^modules=\([0-9]\{4\}[ ]\)*\(0801\|0802\|0905\|0907\|1407\|2801\).*$/\2/p' "${TESTFILE%.*}_head.ini" | head -n 1)
  MODULE="${HAS_ANDR_TGZ_BOOTIMG_ENC}"
  if [ "${SUPPORTS_ANDR_TGZ_BOOTIMG_ENC}" -le 0 ] && [ ! -z "${HAS_ANDR_TGZ_BOOTIMG_ENC}" ]; then
    echo "### INFO: Found m${MODULE} inside, but 2nd stage Android TGZ bootimg decrypt disabled for this platform ###"
    HAS_ANDR_TGZ_BOOTIMG_ENC=
  fi
  if [ ! -z "${HAS_ANDR_TGZ_BOOTIMG_ENC}" ] && [[ $(file "${TESTFILE%.*}_${MODULE}.bin") != *"gzip compressed"* ]]; then
    echo "### INFO: Found m${MODULE} inside, but 2nd stage Android TGZ bootimg decrypt disabled because it is not TGZ archive ###"
    HAS_ANDR_TGZ_BOOTIMG_ENC=
  fi
fi

if [ "${SKIP_EXTRACT}" -le "0" ]; then
  if [ ! -z "${HAS_ANDR_TGZ_BOOTIMG_ENC}" ]; then
    echo "### INFO: Found m${MODULE} inside, doing 2nd stage Android TGZ bootimg decrypt ###"
    mkdir -p "${TESTFILE%.*}_${MODULE}"
    tar -zxf "${TESTFILE%.*}_${MODULE}.bin" --directory="${TESTFILE%.*}_${MODULE}"
  fi
fi

if true; then
  # Some Android TAR modules also contain boot images with another stage of IMaH encryption
  HAS_ANDR_TAR_BOOTIMG_ENC=$(sed -n 's/^modules=\([0-9]\{4\}[ ]\)*\(0905\|0907\|1301\).*$/\2/p' "${TESTFILE%.*}_head.ini" | head -n 1)
  MODULE="${HAS_ANDR_TAR_BOOTIMG_ENC}"
  if [ "${SUPPORTS_ANDR_TAR_BOOTIMG_ENC}" -le 0 ] && [ ! -z "${HAS_ANDR_TAR_BOOTIMG_ENC}" ]; then
    echo "### INFO: Found m${MODULE} inside, but 2nd stage Android TAR bootimg decrypt disabled for this platform ###"
    HAS_ANDR_TAR_BOOTIMG_ENC=
  fi
  if [ ! -z "${HAS_ANDR_TAR_BOOTIMG_ENC}" ] && [[ $(file "${TESTFILE%.*}_${MODULE}.bin") != *"tar archive"* ]]; then
    echo "### INFO: Found m${MODULE} inside, but 2nd stage Android TAR bootimg decrypt disabled because it is not TAR archive ###"
    HAS_ANDR_TAR_BOOTIMG_ENC=
  fi
fi

if [ "${SKIP_EXTRACT}" -le "0" ]; then
  if [ ! -z "${HAS_ANDR_TAR_BOOTIMG_ENC}" ]; then
    echo "### INFO: Found m${MODULE} inside, doing 2nd stage Android TAR bootimg decrypt ###"
    mkdir -p "${TESTFILE%.*}_${MODULE}"
    tar -xf "${TESTFILE%.*}_${MODULE}.bin" --directory="${TESTFILE%.*}_${MODULE}"
  fi
fi

if true; then
  # Some Android LZA modules also contain boot images with another stage of IMaH encryption
  HAS_ANDR_LZA_BOOTIMG_ENC=$(sed -n 's/^modules=\([0-9]\{4\}[ ]\)*\(0100\|0101\).*$/\2/p' "${TESTFILE%.*}_head.ini" | head -n 1)
  MODULE="${HAS_ANDR_LZA_BOOTIMG_ENC}"
  if [ "${SUPPORTS_ANDR_LZA_BOOTIMG_ENC}" -le 0 ] && [ ! -z "${HAS_ANDR_LZA_BOOTIMG_ENC}" ]; then
    echo "### INFO: Found m${MODULE} inside, but 2nd stage Android LZMA bootimg decrypt disabled for this platform ###"
    HAS_ANDR_LZA_BOOTIMG_ENC=
  fi
  if [ ! -z "${HAS_ANDR_LZA_BOOTIMG_ENC}" ] && [[ $(file "${TESTFILE%.*}_${MODULE}.bin") != *"LZMA compressed"* ]]; then
    echo "### INFO: Found m${MODULE} inside, but 2nd stage Android LZA bootimg decrypt disabled because it is not LZMA archive ###"
    HAS_ANDR_LZA_BOOTIMG_ENC=
  fi
fi

if [ "${SKIP_EXTRACT}" -le "0" ]; then
  if [ ! -z "${HAS_ANDR_LZA_BOOTIMG_ENC}" ]; then
    echo "### INFO: Found m${MODULE} inside, doing 2nd stage Android LZMA bootimg decrypt ###"
    mkdir -p "${TESTFILE%.*}_${MODULE}"
    lzma -d -c "${TESTFILE%.*}_${MODULE}.bin" > "${TESTFILE%.*}_${MODULE}/whole.img"
  fi
fi

if true; then
  # Some Android LZ4 modules also contain boot images with another stage of IMaH encryption
  HAS_ANDR_LZ4_BOOTIMG_ENC=$(sed -n 's/^modules=\([0-9]\{4\}[ ]\)*\(0100\|0101\).*$/\2/p' "${TESTFILE%.*}_head.ini" | head -n 1)
  MODULE="${HAS_ANDR_LZ4_BOOTIMG_ENC}"
  if [ "${SUPPORTS_ANDR_LZ4_BOOTIMG_ENC}" -le 0 ] && [ ! -z "${HAS_ANDR_LZ4_BOOTIMG_ENC}" ]; then
    echo "### INFO: Found m${MODULE} inside, but 2nd stage Android LZ4 bootimg decrypt disabled for this platform ###"
    HAS_ANDR_LZ4_BOOTIMG_ENC=
  fi
  if [ ! -z "${HAS_ANDR_LZ4_BOOTIMG_ENC}" ] && [[ $(file "${TESTFILE%.*}_${MODULE}.bin") != *"LZ4 compressed"* ]]; then
    echo "### INFO: Found m${MODULE} inside, but 2nd stage Android LZ4 bootimg decrypt disabled because it is not LZ4 archive ###"
    HAS_ANDR_LZ4_BOOTIMG_ENC=
  fi
fi

if [ "${SKIP_EXTRACT}" -le "0" ]; then
  if [ ! -z "${HAS_ANDR_LZ4_BOOTIMG_ENC}" ]; then
    echo "### INFO: Found m${MODULE} inside, doing 2nd stage Android LZ4 bootimg decrypt ###"
    mkdir -p "${TESTFILE%.*}_${MODULE}"
    lz4 -d "${TESTFILE%.*}_${MODULE}.bin" "${TESTFILE%.*}_${MODULE}/whole.img"
  fi
fi

NESTED_IMAH_LIST=
MODULE=
if [ ! -z "${HAS_ANDR_OTA_BOOTIMG_ENC}" ]; then
  MODULE="${HAS_ANDR_OTA_BOOTIMG_ENC}"
elif [ ! -z "${HAS_ANDR_TGZ_BOOTIMG_ENC}" ]; then
  MODULE="${HAS_ANDR_TGZ_BOOTIMG_ENC}"
elif [ ! -z "${HAS_ANDR_TAR_BOOTIMG_ENC}" ]; then
  MODULE="${HAS_ANDR_TAR_BOOTIMG_ENC}"
elif [ ! -z "${HAS_ANDR_LZ4_BOOTIMG_ENC}" ]; then
  MODULE="${HAS_ANDR_LZ4_BOOTIMG_ENC}"
fi
if [ ! -z "${MODULE}" ]; then
  # Some nested images are just single IMaH files
  for IMAH_NAME in "ap" "cp" "normal" "recovery" "rtos"; do
    if [ -f "${TESTFILE%.*}_${MODULE}/${IMAH_NAME}.img" ]; then
      NESTED_IMAH_LIST+=" ${TESTFILE%.*}_${MODULE}/${IMAH_NAME}.img"
    fi
  done
  for IMAH_NAME in "modemarm" "modemdsp_gnd" "modemdsp_uav"; do
    if [ -f "${TESTFILE%.*}_${MODULE}/${IMAH_NAME}.pro.fw" ]; then
      NESTED_IMAH_LIST+=" ${TESTFILE%.*}_${MODULE}/${IMAH_NAME}.pro.fw"
    fi
  done
  # Some nested images may consist of several files; we need to separate them
  for IMAH_NAME in "bootarea" "loader" "whole"; do
    if [ -f "${TESTFILE%.*}_${MODULE}/${IMAH_NAME}.img" ]; then
      # Use binwalk to find, but not to extract the files; we want to control size of each file
      PART_SEARCH_RES=$(binwalk --signature --raw='IM\x2aH\x01' --raw='IM\x2aH\x02' -y filesystem -y raw "${TESTFILE%.*}_${MODULE}/${IMAH_NAME}.img")
      PART_OFFSETS=( 0 )
      for PART_POS in $(echo "${PART_SEARCH_RES}" | sed -n 's/^\([0-9]\+\)[ ]\+\(0x[0-9A-F]\+\)[ ]\+\(.*\)$/\1/p'); do
        PART_OFFSETS+=( ${PART_POS} )
      done
      FILESIZE=$(stat -c%s "${TESTFILE%.*}_${MODULE}/${IMAH_NAME}.img")
      PART_OFFSETS+=( ${FILESIZE} )
      for N in $(seq 0 $(( ${#PART_OFFSETS[@]} - 2 )) ); do
        PART_OFFSET=${PART_OFFSETS[$N]}
        PART_ENDOFF=${PART_OFFSETS[$((N + 1))]}
        PART_TYPE=$(echo "${PART_SEARCH_RES}" | sed -n 's/^\('${PART_OFFSET}'\)[ ]\+\(0x[0-9A-F]\+\)[ ]\+\(.*\)$/\3/p')
        if [[ ${PART_TYPE} =~ 'Raw signature (IM\x2aH' ]]; then
          PART_EXT="img.sig"
        elif [[ ${PART_TYPE} =~ 'Squashfs filesystem' ]]; then
          PART_EXT="squashfs"
        else
          PART_EXT="bin"
        fi
        dd bs=4 skip=$((PART_OFFSET / 4)) count=$(( ( PART_ENDOFF - PART_OFFSET ) / 4)) \
          if="${TESTFILE%.*}_${MODULE}/${IMAH_NAME}.img" \
          of="${TESTFILE%.*}_${MODULE}/${IMAH_NAME}_p${N}.${PART_EXT}"
      done
    fi
  done
  # Some nested IMaH files can be found on Andoid `system` and `vendor` partitions
  for IMAH_NAME in "system" "vendor"; do
    if [ -f "${TESTFILE%.*}_${MODULE}/${IMAH_NAME}.new.dat" ]; then
      # TODO unpack ext4 fs in `system.new.dat` and `vendor.new.dat` partitions, find IMaHs inside
      echo "No support made for ${IMAH_NAME}.new.dat"
    fi
  done
  # Some nested IMaH files can be recognized by name mask
  for IMAH_FNAME in $(find "${TESTFILE%.*}_${MODULE}" -name '*.sig'); do
    NESTED_IMAH_LIST+=" ${IMAH_FNAME}"
  done
  if [ "${MODULE}" == "0100" ] && [ ! -z "${EXTRAPAR_NESTED_m0100}" ]; then
    EXTRAPAR_NESTED=${EXTRAPAR_NESTED_m0100}
  elif [ "${MODULE}" == "0801" ] && [ ! -z "${EXTRAPAR_NESTED_m0801}" ]; then
    EXTRAPAR_NESTED=${EXTRAPAR_NESTED_m0801}
  elif [ "${MODULE}" == "0901" ] && [ ! -z "${EXTRAPAR_NESTED_m0901}" ]; then
    EXTRAPAR_NESTED=${EXTRAPAR_NESTED_m0901}
  elif [ "${MODULE}" == "0907" ] && [ ! -z "${EXTRAPAR_NESTED_m0907}" ]; then
    EXTRAPAR_NESTED=${EXTRAPAR_NESTED_m0907}
  elif [ "${MODULE}" == "1301" ] && [ ! -z "${EXTRAPAR_NESTED_m1301}" ]; then
    EXTRAPAR_NESTED=${EXTRAPAR_NESTED_m1301}
  else
    EXTRAPAR_NESTED=${EXTRAPAR}
  fi
fi

if [ "${SKIP_EXTRACT}" -le "0" ]; then
  for IMAH_FNAME in ${NESTED_IMAH_LIST}; do
    FNAME_ARR=( ${IMAH_FNAME//\//" " } )
    IMAH_BDIR="${FNAME_ARR[0]}/${FNAME_ARR[1]}" # get first two folders in relative path
    IMAH_NAME=${IMAH_FNAME##*/} # get file name with extension
    IMAH_NAME=${IMAH_NAME%.*} # remove extension
    set +e
    ./dji_imah_fwsig.py -vv ${EXTRAPAR_NESTED} -u -i "${IMAH_FNAME}" \
      -m "${IMAH_BDIR}.${IMAH_NAME}" 2>&1 | tee "${IMAH_BDIR}.${IMAH_NAME}_unsig.log"
    set -e
  done
fi

if [ "${SKIP_REPACK}" -le "0" ]; then
  # Remove file which will be created
  set +e
  if [ ! -z "${HAS_MVFC_ENC}" ]; then
    rm "${TESTFILE%.*}_${HAS_MVFC_ENC}.bin" 2>/dev/null
  fi
  rm "${TESTFILE}" 2>/dev/null
  set -e
  # We do not have private parts of auth keys used for signing - use OG community key instead
  # Different signature means we will get up to 256 different bytes in the resulting file
  # Additional 2 bytes of difference is the FourCC - two first bytes of it were changed
  sed -i "s/^auth_key=[0-9A-Za-z]\{4\}$/auth_key=SLAK/" "${TESTFILE%.*}_head.ini"
  # Encrypt and sign back to final format
  if [ ! -z "${HAS_MVFC_ENC}" ]; then
    MODULE="${HAS_MVFC_ENC}"
    MOD_FWVER=$(sed    -n "s/^Version:[ \t]*\([0-9A-Za-z. :_-]*\)$/\1/p" "${TESTFILE%.*}_${MODULE}.log" | head -n 1)
    MOD_TMSTAMP=$(sed  -n "s/^Time:[ \t]*\([0-9A-Za-z. :_-]*\)$/\1/p"    "${TESTFILE%.*}_${MODULE}.log" | head -n 1)
    ./dji_mvfc_fwpak.py enc -V "${MOD_FWVER}" -T "${MOD_TMSTAMP}" -t "${MODULE}" \
      -i "${TESTFILE%.*}_${MODULE}.decrypted.bin" -o "${TESTFILE%.*}_${MODULE}.bin"
  fi

  for IMAH_FNAME in ${NESTED_IMAH_LIST}; do
    FNAME_ARR=( ${IMAH_FNAME//\//" " } )
    IMAH_BDIR="${FNAME_ARR[0]}/${FNAME_ARR[1]}" # get first two folders in relative path
    IMAH_NAME=${IMAH_FNAME##*/} # get file name with extension
    IMAH_NAME=${IMAH_NAME%.*} # remove extension
    sed -i "s/^auth_key=[0-9A-Za-z]\{4\}$/auth_key=SLAK/" "${IMAH_BDIR}.${IMAH_NAME}_head.ini"
    ./dji_imah_fwsig.py -vv ${EXTRAPAR_NESTED} -s -i "${IMAH_BDIR}.${IMAH_NAME}.img" \
      -m "${IMAH_BDIR}.${IMAH_NAME}" 2>&1 | tee "${IMAH_BDIR}.${IMAH_NAME}_resig.log"
  done

  ./dji_imah_fwsig.py -vv ${EXTRAPAR} -s -i "${TESTFILE}" -m "${TESTFILE%.*}" 2>&1 | tee "${TESTFILE%.*}_resig.log"
fi

set +eo pipefail

if [ "${SKIP_COMPARE}" -le "0" ]; then
  # Compare converted with original, nested images
  for IMAH_FNAME in ${NESTED_IMAH_LIST}; do
    FNAME_ARR=( ${IMAH_FNAME//\//" " } )
    IMAH_BDIR="${FNAME_ARR[0]}/${FNAME_ARR[1]}" # get first two folders in relative path
    IMAH_NAME=${IMAH_FNAME##*/} # get file name with extension
    IMAH_NAME=${IMAH_NAME%.*} # remove extension
    TEST_RESULT=$(cmp -l "${IMAH_FNAME}" "${IMAH_BDIR}.${IMAH_NAME}.img" | wc -l)
    echo '### INFO: Counted '${TEST_RESULT}' differences in '${IMAH_NAME}'.img. ###'
    if [ ${TEST_RESULT} -gt ${NESTED_CHANGES_LIMIT} ]; then
      echo '### FAIL: Nested image '${IMAH_NAME}'.img changed during conversion! ###'
      exit 1
    fi
  done
  # Compare converted with original, main image
  TEST_RESULT=$(cmp -l "${BINFILE}" "${TESTFILE}" | wc -l)
  echo '### INFO: Counted '${TEST_RESULT}' differences. ###'
fi

if [ "${SKIP_CLEANUP}" -le "0" ]; then
  # Cleanup
  MODULES=$(sed -n 's/^modules=\(.*\)$/\1/p' "${TESTFILE%.*}_head.ini" | head -n 1)
  for MODULE in $MODULES; do
    if [ -d "${TESTFILE%.*}_${MODULE}" ]; then
      rm -rf "${TESTFILE%.*}_${MODULE}"
      rm ${TESTFILE%.*}_${MODULE}.*.img
    fi
  done
  rm "${TESTFILE}" ${TESTFILE%.*}_*.bin ${TESTFILE%.*}_*.ini
fi

if [ "${SKIP_COMPARE}" -le "0" ]; then
  if [ ${TEST_RESULT} == 0 ]; then
    echo '### SUCCESS: File identical after conversion. ###'
  elif [ ${TEST_RESULT} -le ${HEAD_CHANGES_LIMIT} ]; then
    echo '### SUCCESS: File matches, except signature. ###'
  elif [ ! -s "${TESTFILE}" ]; then
    echo '### FAIL: File empty or missing; creation faled! ###'
    exit 2
  else
    echo '### FAIL: File changed during conversion! ###'
    exit 1
  fi
fi

exit 0
