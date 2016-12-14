#!/bin/bash
# Execute this from upper level directory

set +x

if [ ! -f "tests/test_dji_fwcon_rebin1.sh" ]; then
  echo '### SUITE executed from wrong directory ###'
  exit 4
fi

mkdir -p fw

declare -A itm_p3x_fw1=([binname]="P3X_FW_V01.01.0008.bin" [dlurl]="http://download.dji-innovations.com/downloads/phantom_3/en/Phantom_3_Professional_Firmware_v1.1.8_en.zip" [dlname]="Phantom_3_Professional_Firmware_v1.1.8_en.zip" )
declare -A itm_p3x_fw2=([binname]="P3X_FW_V01.01.1003.bin" [dlurl]="none" [dlname]="none" )
declare -A itm_p3x_fw3=([binname]="P3X_FW_V01.08.0080.bin" [dlurl]="http://dl.djicdn.com/downloads/phantom_3/P3X_FW_V01.08.0080.zip" [dlname]="P3X_FW_V01.08.0080.zip" )
declare -A itm_p3x_fw4=([binname]="P3X_FW_V01.10.0090.bin" [dlurl]="http://dl.djicdn.com/downloads/phantom_3/P3X_FW_V01.10.0090.zip" [dlname]="P3X_FW_V01.10.0090.zip" )

declare -a all_firmwares=( itm_p3x_fw1 itm_p3x_fw2 itm_p3x_fw3 itm_p3x_fw4 )

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
      echo '### SUITE could not download firmware to test ###'
      exit 5
    fi

    unzip -j -d fw "fw/${FWDLNAME}"
  fi

  if [ ! -f "fw/${FWPKG}" ]; then
    echo '### SUITE could not extract firmware to test ###'
    exit 5
  fi

  # Execute test - DJI firmware extractor

  tests/test_dji_fwcon_rebin1.sh -sn "fw/${FWPKG}"

  # Find Ambarella firmware
  AMBAPKG=$(grep '^target=m0100' "${FWPKG%.*}-test_"*".ini" | cut -d : -f 1)
  AMBAPKG="${AMBAPKG%.*}.bin"

  # Execute test - Ambarella firmware extractor

  tests/test_amba_fwpak_repack1.sh -sn "${AMBAPKG}"

  # Cleanup

  tests/test_amba_fwpak_repack1.sh -on "${AMBAPKG}"

  tests/test_dji_fwcon_rebin1.sh -on "fw/${FWPKG}"
done

exit 0
