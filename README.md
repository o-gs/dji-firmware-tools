# phantom-firmware-tools

Tools for extracting, modding and re-packaging [DJI Phantom 3](http://www.dji.com/product/phantom-3/download) firmware.

# Motivation

This is an alternative implementation to parser from [phantom-licensecheck](https://github.com/probonopd/phantom-licensecheck), more focused on hacking.

# Step by step instruction

Such instruction will not be provided. These tools are for engineers with vast
hardware and software knowledge. You need to know what you're doing to achieve
anything with these tools.

This is to make sure the tools won't be used by script kiddies to disable
security mechanisms and to allow breaking the law.

If you can't understand how the tools work, you should not use them. If any
warnings are shown, you must investigate the cause to make sure final firmware
will not be damaged. You are using the tools on your own risk.

# Firmware structure

Documentation of the firmware format is held within [phantom-licensecheck](https://github.com/probonopd/phantom-licensecheck) project.
Some details can be checked by looking inside the scripts in this repository.

# Tools

Below the specific tools are described in short. Running them without parameters
will give you details on supported commands in each of them.

### dji_fwcon.py

DJI Firmware Container tool; allows extracting modules from package file, or
creating container by merging firmware modules. Use this tool first, to extract
the BIN file downloaded from DJI.

Example: ```./dji_fwcon.py -vv -x -p P3X_FW_V01.08.0080.bin```

### amba_fwpak.py

Ambarella A7/A9 firmware pack tool; allows extracting partitions from the
firmware, or merging them back. Use this to extract Ambarella firmware from
files created after DJI firmware is extracted. You can recognize the Ambarella
firmware by a lot of "Amba" strings within, or in case of Phantom 3 by "FC300X"
string at the beginning of the file.

Example: ```./amba_fwpak.py -vv -x -m P3X_FW_V01.08.0080_12.bin```

### amba_romfs.py

Ambarella A7/A9 firmware ROMFS filesystem tool; allows extracting single files
from ROMFS filesystem file, or rebuilding filesystem from the single files.
Use this after the Ambarella firmware is extracted. You can recognize ROMFS
partitions by file names near beginning of the file, surrounded by blocks of
0xff filled bytes.

Example: ```./amba_romfs.py -vv -x -p P3X_FW_V01.08.0080_12_part_rom_fw.a9s```

### amba_ubifs.sh

Linux script for mounting UBIFS partition from the Ambarella firmware. After
mounting, the files can be copied or modified. Use this after the Ambarella
firmware is extracted.

Example: ```sudo ./amba_ubifs.sh P3X_FW_V01.08.0080_12_part_rfs.a9s```
