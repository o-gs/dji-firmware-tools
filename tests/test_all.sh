#!/bin/bash
# Execute this from upper level directory

if [ ! -f "tests/test_dji_fwcon_rebin1.sh" ]; then
  echo '### SUITE executed from wrong directory ###'
  exit 4
fi

mkdir -p fw

FWPKG="P3X_FW_V01.08.0080.bin"
AMBAPKG="${FWPKG%.*}-test_mi12.bin"

# Download firmwares

if [ ! -f "fw/${FWPKG}" ]; then
  curl https://dl.djicdn.com/downloads/phantom_3/P3X_FW_V01.09.0060.zip -o fw/P3X_FW_V01.09.0060.zip
  unzip -j -d fw fw/P3X_FW_V01.09.0060.zip
fi

# Execute tests

tests/test_dji_fwcon_rebin1.sh -sn "fw/${FWPKG}"

tests/test_amba_fwpak_repack1.sh -sn "${AMBAPKG}"

# Cleanup

tests/test_amba_fwpak_repack1.sh -on "${AMBAPKG}"

tests/test_dji_fwcon_rebin1.sh -on "fw/${FWPKG}"

exit 0

