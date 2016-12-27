#!/bin/bash
# Execute this from upper level directory

set +x

if [ ! -f "tests/test_dji_fwcon_rebin1.sh" ]; then
  echo '### SUITE executed from wrong directory ###'
  exit 4
fi

mkdir -p fw

declare -A itm_p3x_fw01=([binname]="P3X_FW_V01.01.0006.bin" [dlurl]="http://download.dji-innovations.com/downloads/phantom_3/en/Phantom_3_Professional_Firmware_v1.1.6_en.zip" [dlname]="Phantom_3_Professional_Firmware_v1.1.6_en.zip" )
declare -A itm_p3x_fw02=([binname]="P3X_FW_V01.01.0008.bin" [dlurl]="http://download.dji-innovations.com/downloads/phantom_3/en/Phantom_3_Professional_Firmware_v1.1.8_en.zip" [dlname]="Phantom_3_Professional_Firmware_v1.1.8_en.zip" )
declare -A itm_p3x_fw03=([binname]="P3X_FW_V01.01.0009.bin" [dlurl]="http://download.dji-innovations.com/downloads/phantom_3/en/Phantom_3_Professional_Firmware_v1.1.9_en.zip" [dlname]="Phantom_3_Professional_Firmware_v1.1.9_en.zip" )
declare -A itm_p3x_fw04=([binname]="P3X_FW_V01.01.1003.bin" [dlurl]="none" [dlname]="none" )
declare -A itm_p3x_fw05=([binname]="P3X_FW_V01.01.1007.bin" [dlurl]="none" [dlname]="none" )
declare -A itm_p3x_fw06=([binname]="P3X_FW_V01.02.0006.bin" [dlurl]="http://download.dji-innovations.com/downloads/phantom_3/en/Phantom_3_Professional_Firmware_v1.2.6_en.zip" [dlname]="Phantom_3_Professional_Firmware_v1.2.6_en.zip" )
declare -A itm_p3x_fw07=([binname]="P3X_FW_V01.03.0020.bin" [dlurl]="http://download.dji-innovations.com/downloads/phantom_3/en/Phantom_3_Professional_Firmware_v1.3.20_en.zip" [dlname]="Phantom_3_Professional_Firmware_v1.3.20_en.zip" )
declare -A itm_p3x_fw08=([binname]="P3X_FW_V01.04.0005.bin" [dlurl]="none" [dlname]="none" )
declare -A itm_p3x_fw09=([binname]="P3X_FW_V01.04.0010.bin" [dlurl]="http://download.dji-innovations.com/downloads/phantom_3/en/Phantom_3_Professional_Firmware_v1.4.0010_en.zip" [dlname]="Phantom_3_Professional_Firmware_v1.4.0010_en.zip" )
declare -A itm_p3x_fw10=([binname]="P3X_FW_V01.05.0030.bin" [dlurl]="http://dl.djicdn.com/downloads/phantom_3/P3X_FW_V01.05.0030.zip" [dlname]="P3X_FW_V01.05.0030.zip" )
declare -A itm_p3x_fw11=([binname]="P3X_FW_V01.06.0040.bin" [dlurl]="http://dl.djicdn.com/downloads/phantom_3/P3X_FW_V01.06.0040.zip" [dlname]="P3X_FW_V01.06.0040.zip" )
declare -A itm_p3x_fw12=([binname]="P3X_FW_V01.07.0043_beta.bin" [dlurl]="none" [dlname]="none" )
declare -A itm_p3x_fw13=([binname]="P3X_FW_V01.07.0060.bin" [dlurl]="http://dl.djicdn.com/downloads/phantom_3/P3X_FW_V01.07.0060.zip" [dlname]="P3X_FW_V01.07.0060.zip" )
declare -A itm_p3x_fw14=([binname]="P3X_FW_V01.08.0080.bin" [dlurl]="http://dl.djicdn.com/downloads/phantom_3/P3X_FW_V01.08.0080.zip" [dlname]="P3X_FW_V01.08.0080.zip" ) # interesting - mi02 encrypted
declare -A itm_p3x_fw15=([binname]="P3X_FW_V01.09.0021.bin" [dlurl]="http://dl.djicdn.com/downloads/phantom_3/P3X_FW_V01.09.0021.zip" [dlname]="P3X_FW_V01.09.0021.zip" )
declare -A itm_p3x_fw16=([binname]="P3X_FW_V01.09.0060.bin" [dlurl]="http://dl.djicdn.com/downloads/phantom_3/P3X_FW_V01.09.0060.zip" [dlname]="P3X_FW_V01.09.0060.zip" )
declare -A itm_p3x_fw17=([binname]="P3X_FW_V01.10.0090.bin" [dlurl]="http://dl.djicdn.com/downloads/phantom_3/P3X_FW_V01.10.0090.zip" [dlname]="P3X_FW_V01.10.0090.zip" ) # latest available

declare -A itm_osmo_fw01=([binname]="OSMO_FC550_FW_V01.03.00.40.bin" [dlurl]="https://dl.djicdn.com/downloads/osmo/OSMO_FC550_FW_V01.03.00.40.zip" [dlname]="OSMO_FC550_FW_V01.03.00.40.zip" )
declare -A itm_osmo_fw02=([binname]="OSMO_FC550R_FW_V01.03.00.40.bin" [dlurl]="https://dl.djicdn.com/downloads/osmo/OSMO_FC550R_FW_V01.03.00.40.zip" [dlname]="OSMO_FC550R_FW_V01.03.00.40.zip" ) # larger than others
declare -A itm_osmo_fw03=([binname]="OSMO_FW_V01.04.01.80.bin" [dlurl]="http://dl.djicdn.com/downloads/osmo/OSMO_FW_BUGFIX_V01.04.01.80.bin.zip" [dlname]="OSMO_FW_BUGFIX_V01.04.01.80.bin.zip" )
declare -A itm_osmo_fw04=([binname]="OSMO_FW_V01.06.02.10.bin" [dlurl]="http://dl.djicdn.com/downloads/osmo/OSMO_FW_V01.06.02.10.zip" [dlname]="OSMO_FW_V01.06.02.10.zip" )
declare -A itm_osmo_fw05=([binname]="OSMO_FW_V01.08.02.40.bin" [dlurl]="https://dl.djicdn.com/downloads/osmo/OSMO_FW_V01.08.02.40.zip" [dlname]="OSMO_FW_V01.08.02.40.zip" )

# Select firmwares for testing

declare -a all_firmwares=( \
itm_p3x_fw01 \
itm_p3x_fw02 \
#itm_p3x_fw03 \
#itm_p3x_fw04 \
#itm_p3x_fw05 \
itm_p3x_fw06 \
#itm_p3x_fw07 \
#itm_p3x_fw08 \
#itm_p3x_fw09 \
#itm_p3x_fw10 \
#itm_p3x_fw11 \
#itm_p3x_fw12 \
#itm_p3x_fw13 \
itm_p3x_fw14 \
#itm_p3x_fw15 \
#itm_p3x_fw16 \
itm_p3x_fw17 \
#itm_osmo_fw01 \
itm_osmo_fw02 \
#itm_osmo_fw03 \
#itm_osmo_fw04 \
itm_osmo_fw05 \
)

NUMFAILS=0
NUMSKIPS=0

for itm in "${all_firmwares[@]}"; do
  tmp=${itm}[dlurl]
  FWDLURL=${!tmp}
  tmp=${itm}[dlname]
  FWDLNAME=${!tmp}
  tmp=${itm}[binname]
  FWPKG=${!tmp}

  # Download firmwares

  if [ ! -f "fw/${FWPKG}" ]; then

    if [ ! -f "fw/${FWDLNAME}" ]; then
      curl "${FWDLURL}" -o "fw/${FWDLNAME}"
    fi

    if [ ! -f "fw/${FWDLNAME}" ]; then
      echo '### SKIP could not download firmware to test ###'
      ((NUMSKIPS++))
      continue
    fi

    unzip -j -o -d fw "fw/${FWDLNAME}"
  fi

  if [ ! -f "fw/${FWPKG}" ]; then
    echo '### SKIP could not extract firmware to test ###'
    ((NUMSKIPS++))
    continue
  fi

  # Execute test - DJI firmware extractor
  tests/test_dji_fwcon_rebin1.sh -sn "fw/${FWPKG}"
  if [ $? -ne 0 ]; then
    ((NUMFAILS++))
  fi

  # Find Ambarella firmware file name
  AMBAPKG=$(grep '^target=m0100' "${FWPKG%.*}-test_"*".ini" | head -n 1 | cut -d : -f 1)
  if [ -z "${AMBAPKG}" ]; then
    echo '### SKIP no ambarella firmware found in extracted files ###'
    ((NUMSKIPS++))
    continue
  fi
  AMBAPKG="${AMBAPKG%.*}.bin"

  # Execute test - Ambarella firmware extractor
  tests/test_amba_fwpak_repack1.sh -sn "${AMBAPKG}"
  if [ $? -ne 0 ]; then
    ((NUMFAILS++))
  fi

  # Get Ambarella system partition file name
  AMBASYSPKG="${AMBAPKG%.*}_part_sys.a9s"
  if [ ! -f "${AMBASYSPKG}" ]; then
    echo '### SKIP no ambarella system partition found in extracted files ###'
    ((NUMSKIPS++))
  else

    # Execute test - Ambarella system partition to ELF wrapper
    tests/test_amba_sys2elf_rebin1.sh -sn "${AMBASYSPKG}"
    if [ $? -ne 0 ]; then
      ((NUMFAILS++))
    fi

  fi

  # Cleanup

  tests/test_amba_sys2elf_rebin1.sh -on "${AMBASYSPKG}"

  tests/test_amba_fwpak_repack1.sh -on "${AMBAPKG}"

  tests/test_dji_fwcon_rebin1.sh -on "fw/${FWPKG}"
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

