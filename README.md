# phantom-firmware-tools

Tools for extracting, modding and re-packaging [DJI Phantom 3](http://www.dji.com/product/phantom-3/download) firmware.

# Motivation

This is an alternative implementation to parser from [phantom-licensecheck](https://github.com/probonopd/phantom-licensecheck), more focused on hacking.
It allows to merge the previously extracted modules back into single file,
and includes tools for handling some of the modules after they're extracted.

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
firmware by a lot of "Amba" strings within, or by a 32-char zero-padded string
at the beginning of the file.

Example: ```./amba_fwpak.py -vv -x -m P3X_FW_V01.08.0080_mi12.bin```

### amba_romfs.py

Ambarella A7/A9 firmware ROMFS filesystem tool; allows extracting single files
from ROMFS filesystem file, or rebuilding filesystem from the single files.
Use this after the Ambarella firmware is extracted. You can recognize ROMFS
partitions by file names near beginning of the file, surrounded by blocks of
0xff filled bytes.

Example: ```./amba_romfs.py -vv -x -p P3X_FW_V01.08.0080_mi12_part_rom_fw.a9s```

### amba_ubifs.sh

Linux script for mounting UBIFS partition from the Ambarella firmware. After
mounting, the files can be copied or modified. Use this after the Ambarella
firmware is extracted. The file containing UBIFS can be easily recognized
by "UBI#" at the beginning of the file.

Example: ```sudo ./amba_ubifs.sh P3X_FW_V01.08.0080_mi12_part_rfs.a9s```


### arm_bin2elf.py

Tool which wrapps binary execytable ARM images with ELF header. If a firmware
contains binary image of executable file, this tool can rebuild ELF header for it.
The ELF format can be then easily disassembled, as most debuggers can read ELF files.
Note that using this tool on encrypted firmwares will not result in useable ELF.

Example: ```./arm_bin2elf.py -vv -e -b 0x8020000 -l 0x6000000 -p P3X_FW_V01.07.0060_mi01.bin```

After first look at the disassembly, it is good to find where the correct border
between '.text' and '.data' sections is located. File offset of this location can
be used to generate better ELF file in case '.ARM.exidx' section was not detected.
This section is treated as a separator between '.text' and '.data'. This means that
position of the '.ARM.exidx' influences length of the '.text' section, and starting
offset of the '.data' section. If there is no '.ARM.exidx' section in the file, it
will still be used as separator, just with zero size.

Optimized examples for specific firmwares:

```./arm_bin2elf.py -vv -e -b 0x8020000 --section .ARM.exidx@0x085d34:0 --section .bss@0x17fe0000:0x4400000 -p P3X_FW_V01.07.0060_mi01.bin```

### amba_sys2elf.py

Ambarella A7/A9 firmware "System Software" partition converter. The partition
contains a binary image of executable file, and this tool wraps it with ELF
header. The ELF format can be then easily disassembled, as most debuggers can
read ELF files. This tool is very similar to arm_bin2elf.py, it is just
pre-configured to specific firmware.

Example: ```./amba_sys2elf.py -vv -e -l 0x6000000 -p P3X_FW_V01.08.0080_mi12_part_sys.a9s```

All border adjusting rules explained for arm_bin2elf.py apply for this tool as well.

Optimized examples for specific firmwares:

```./amba_sys2elf.py -vv -e -l 0x6000000 --section .ARM.exidx@0x483E4C:0 -p P3X_FW_V01.08.0080_mi12_part_sys.a9s```

```./amba_sys2elf.py -vv -e -l 0x6000000 --section .ARM.exidx@0x482EC0:0 -p P3X_FW_V01.07.0060_mi12_part_sys.a9s```

# Symbols

For some specific firmware modules in specific versions, there are partial symbols
available in 'symbols' directory. Only functions and variables which were given a
meaningful names are included in the symbol files. The symbols are in MAP format,
which can be loaded into most disassemblers with minimal effort. For Ida Pro,
there is a plugin which can read MAP files and rename functions and variables
accordingly.

Symbols are matched with ELF files generated with the tools described above,
not directly with the BINs. Use example commands provided in previous section
to generate ELF files with content matching to the symbols.

When working on a firmware version for which no symbols are available, you may
want to use a version with symbols for reference in naming.
