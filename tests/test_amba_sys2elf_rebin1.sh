#!/bin/bash

BINFILE="P3X_FW_V01.08.0080_mi12_part_sys.a9s"
ELFFILE="${BINFILE%.*}.elf"
TESTFILE="${BINFILE%.*}-test.bin"

echo '### TEST for amba_sys2elf.py re-creation of binary file ###'
# The test converts BIN to ELF, and the converts the result back to BIN.
# The test ends with success if the resulting BIN file is
# exactly the same as input BIN file.

# Remove files which will be created
rm "${ELFFILE}" "${TESTFILE}"

# Convert to ELF
./amba_sys2elf.py -vvv -e -p "${BINFILE}" -o "${ELFFILE}"

# write info about file
#readelf -a amba_app_test.elf > amba_app_test.elf.txt

# Convert back to final format
/usr/bin/arm-none-eabi-objcopy -O binary "${ELFFILE}" "${TESTFILE}"

# Compare converted with original
cmp --silent "${BINFILE}" "${TESTFILE}"
TEST_RESULT=$?

# Cleanup
rm "${ELFFILE}" "${TESTFILE}"

if [ ${TEST_RESULT} == 0 ]; then
  echo '### SUCCESS: File identical after conversion. ###'
else
  echo '### FAIL: File changed during conversion! ###'
  exit 2
fi

exit 0

