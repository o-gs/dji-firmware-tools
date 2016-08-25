# phantom-firmware-tools

Tools for extracting, modding and re-packaging [DJI Phantom 3](http://www.dji.com/product/phantom-3/download) firmware.

# Motivation

This is an alternative implementation to parser from [phantom-licensecheck](https://github.com/probonopd/phantom-licensecheck), more focused on hacking.

# Firmware structure

Documentation of the formware format is held within [phantom-licensecheck](https://github.com/probonopd/phantom-licensecheck) project.

# Tools

dji_fwcon.py - DJI Firmware Container tool; allows extracting modules from package file, or creating container by merging firmware modules.

amba_fwpak.py - Ambarella A7/A9 firmware pack tool; allows extracting partitions from the firmware, or merging them back.

amba_rfs.py - Ambarella A7/A9 firmware RFS filesystem tool; allows extracting single files from RFS filesystem file, or rebuilding filesystem from the single files.
