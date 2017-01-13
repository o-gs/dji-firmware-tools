#!/bin/bash

SKIP_MKELF=0
SKIP_REBIN=0
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
  -se|--skip-mkelf)
    SKIP_MKELF=1
    ;;
  -sb|--skip-rebin)
    SKIP_REBIN=1
    ;;
  -sn|--skip-cleanup)
    SKIP_CLEANUP=1
    ;;
  -sc|--skip-compare)
    SKIP_COMPARE=1
    ;;
  -on|--only-cleanup)
    SKIP_MKELF=1
    SKIP_REBIN=1
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
    echo "### INFO: Expexted file \"${BINFILE}\" ###"
    exit 3
fi

ELFFILE="${BINFILE%.*}.elf"
ELFFILE="${ELFFILE##*/}"
TESTFILE="${BINFILE%.*}-test.bin"
TESTFILE="${TESTFILE##*/}"

if [ "${SKIP_COMPARE}" -le "0" ]; then
  echo '### TEST for amba_sys2elf.py re-creation of binary file ###'
  # The test creates ELF file from Ambarella system partiton, and then re-creates BIN.
  # The test ends with success if the resulting BIN file is
  # exactly the same as input BIN file.
fi

if [ "${SKIP_MKELF}" -le "0" ]; then
  # Remove files which will be created
  rm "${ELFFILE}" 2>/dev/null
  # Convert to ELF
  ./amba_sys2elf.py -vvv -e -p "${BINFILE}" -o "${ELFFILE}"
fi

if [ "${SKIP_REBIN}" -le "0" ]; then
  # Remove file which will be created
  rm "${TESTFILE}" 2>/dev/null
  # Convert back to final format
  arm-none-eabi-objcopy -O binary "${ELFFILE}" "${TESTFILE}"
fi

if [ "${SKIP_COMPARE}" -le "0" ]; then
  # Compare converted with original
  cmp --silent "${BINFILE}" "${TESTFILE}"
  TEST_RESULT=$?
fi

if [ "${SKIP_CLEANUP}" -le "0" ]; then
  # Cleanup
  rm "${TESTFILE}" "${ELFFILE}"
fi

if [ "${SKIP_COMPARE}" -le "0" ]; then
  if [ ${TEST_RESULT} == 0 ]; then
    echo '### SUCCESS: File identical after conversion. ###'
  elif [ ! -s "${TESTFILE}" ]; then
    echo '### FAIL: File empty or missing; creation faled! ###'
    exit 2
  else
    echo '### FAIL: File changed during conversion! ###'
    exit 1
  fi
fi

exit 0
