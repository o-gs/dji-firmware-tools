#!/bin/bash

BINFILE="P3X_FW_V01.08.0080.bin"
TESTFILE="${BINFILE%.*}-test.bin"

echo '### TEST for dji_fwcon.py re-creation of binary file ###'
# The test extracts firmware modules from DJI firmware package, abd then repacks them.
# The test ends with success if the resulting BIN file is
# exactly the same as input BIN file.

# Remove files which will be created
rm "${TESTFILE}" ${TESTFILE%.*}*.bin ${TESTFILE%.*}*.ini

# Extract firmwares for modules
./dji_fwcon.py -vvv -x -p "${BINFILE}" -m ${TESTFILE%.*}

# Repack back to final format
./dji_fwcon.py -vvv -a -p "${TESTFILE}"

# Compare converted with original
cmp --silent "${BINFILE}" "${TESTFILE}"
TEST_RESULT=$?

# Cleanup
rm "${TESTFILE}" ${TESTFILE%.*}*.bin ${TESTFILE%.*}*.ini

if [ ${TEST_RESULT} == 0 ]; then
  echo '### SUCCESS: File identical after conversion. ###'
else
  echo '### FAIL: File changed during conversion! ###'
  exit 2
fi

exit 0

