# dji-firmware-tools

Tools for extracting, modding and re-packaging firmwares of [DJI](http://www.dji.com) multirotor drones.

# Motivation

The project started as an alternative implementation of the parser from [phantom-licensecheck](https://github.com/probonopd/phantom-licensecheck).
Over time it has grown to support many generations of DJI products.
It consists of tools which allow not only extraction, but also re-packing of
the previously extracted modules back into single file. There are also tools
which are supposed to be used on specific modules to extract and allow modification
of their content.

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

Since all the tools are available in source code form, it is easy to check details
on the structure and protocols processed by these tools by looking at their source.
The source code is intended to also act as a format documentation.

# Tools

Below the specific tools are described in short. Running them without parameters
will give you details on supported commands in each of them.

### dji_xv4_fwcon.py

DJI Firmware xV4 Container tool; allows extracting modules from package file which
starts with `xV4`, or creating container by merging firmware modules. Use this tool
first, to extract the BIN file downloaded from DJI, as long as the file starts with
`xV4`.

Example: ```./dji_xv4_fwcon.py -vv -x -p P3X_FW_V01.08.0080.bin```

### dji_imah_fwsig.py

DJI Firmware IMaH Un-signer and Decryptor tool; allows to decrypt and un-sign module
from `.sig` file which starts with `IM*H`. Use this tool after untarring single
modules from a firmware package, to decrypt its content.

Example: ```./dji_imah_fwsig.py -vv -u -s wm335_0306_v03.03.04.10_20180429.pro.fw.sig```

### dji_mvfc_fwpak.py

DJI Mavic Flight Controller Firmware Decryptor tool; removes second layer encryption
in Flight Controller firmware modules from several DJI products released around the
same period: Mavic Pro, Spark, Inspire 2 and Phantom 4. Does not accept `IM*H`
format - requires input files with first level encryption already removed.

Example: ```./dji_mvfc_fwpak.py dec -i wm220_0306_v03.02.40.11_20170918.pro.fw```

### amba_fwpak.py

Ambarella A7/A9 firmware pack tool; allows extracting partitions from the
firmware, or merging them back. Use this to extract Ambarella firmware from
files created after DJI Container is extracted. You can recognize the Ambarella
firmware by a lot of "Amba" strings within, or by a 32-char zero-padded string
at the beginning of the file.

Example: ```./amba_fwpak.py -vv -x -m P3X_FW_V01.08.0080_m0100.bin```

### amba_romfs.py

Ambarella A7/A9 firmware ROMFS filesystem tool; allows extracting single files
from ROMFS filesystem file, or rebuilding filesystem from the single files.
Use this after the Ambarella firmware is extracted. You can recognize ROMFS
partitions by file names near beginning of the file, surrounded by blocks of
0xff filled bytes.

Example: ```./amba_romfs.py -vv -x -p P3X_FW_V01.08.0080_m0100_part_rom_fw.a9s```

### amba_ubifs.sh

Linux script for mounting UBIFS partition from the Ambarella firmware. After
mounting, the files can be copied or modified. Use this after the Ambarella
firmware is extracted. The file containing UBIFS can be easily recognized
by "UBI#" at the beginning of the file.

Example: ```sudo ./amba_ubifs.sh P3X_FW_V01.08.0080_m0100_part_rfs.a9s```


### arm_bin2elf.py

Tool which wrapps binary execytable ARM images with ELF header. If a firmware
contains binary image of executable file, this tool can rebuild ELF header for it.
The ELF format can be then easily disassembled, as most debuggers can read ELF files.
Note that using this tool on encrypted firmwares will not result in useable ELF.

Example: ```./arm_bin2elf.py -vv -e -b 0x8020000 -l 0x6000000 -p P3X_FW_V01.07.0060_m0306.bin```

After first look at the disassembly, it is good to find where the correct border
between '.text' and '.data' sections is located. File offset of this location can
be used to generate better ELF file in case '.ARM.exidx' section was not detected.
This section is treated as a separator between '.text' and '.data'. This means that
position of the '.ARM.exidx' influences length of the '.text' section, and starting
offset of the '.data' section. If there is no '.ARM.exidx' section in the file, it
will still be used as separator, just with zero size.

Optimized examples for specific firmwares:

```./arm_bin2elf.py -vv -e -b 0x8020000 --section .ARM.exidx@0x085d34:0  --section .bss@0x07fe0000:0xA000 --section .bss2@0x17fe0000:0x30000 --section .bss3@0x37fe0000:0x30000 -p P3X_FW_V01.07.0060_m0306.bin```

```./arm_bin2elf.py -vv -e -b 0x000a000 --section .ARM.exidx@0x01ce50:0 --section .bss@0xfff6000:0x8000 --section .bss2@0x3fff6000:0x50000 --section .bss3@0xdfff6000:0x10000 -p C1_FW_V01.06.0000_m1400.bin```

```./arm_bin2elf.py -vv -e -b 0x8008000 --section .ARM.exidx@0x0D510:0 --section .bss@0x17FF7700:0x5A00 --section .bss2@0x37ff8000:0x6700 --section .bss3@0x38008000:0x5500 --section .bss4@0x38018000:0x2200 --section .bss5@0x3a1f8000:0x100 --section .bss6@0x3a418000:0x500 -p P3X_FW_V01.08.0080_m0900.bin```

```./arm_bin2elf.py -vv -e -b 0x8008000 --section .ARM.exidx@0x0136D0:0 --section .bss@0x17FF7700:0xC900 --section .bss2@0x37ff8000:0x6700 --section .bss3@0x38008000:0x5500 --section .bss4@0x38018000:0x7000 --section .bss5@0x48058800:0x100 -p P3X_FW_V01.11.0030_m0400.bin```

### amba_sys2elf.py

Ambarella A7/A9 firmware "System Software" partition converter. The partition
contains a binary image of executable file, and this tool wraps it with ELF
header. The ELF format can be then easily disassembled, as most debuggers can
read ELF files. This tool is very similar to arm_bin2elf.py, it is just
pre-configured to specific firmware.

Example: ```./amba_sys2elf.py -vv -e -l 0x6000000 -p P3X_FW_V01.08.0080_m0100_part_sys.a9s```

All border adjusting rules explained for arm_bin2elf.py apply for this tool as well.

Optimized examples for specific firmwares:

```./amba_sys2elf.py -vv -e -l 0x6000000 --section .ARM.exidx@0x483E4C:0 -p P3X_FW_V01.08.0080_m0100_part_sys.a9s```

```./amba_sys2elf.py -vv -e -l 0x6000000 --section .ARM.exidx@0x482EC0:0 -p P3X_FW_V01.07.0060_m0100_part_sys.a9s```

### dji_flyc_param_ed.py

Flight Controller Firmware Parameters Array Editor finds an array of flight
parameters within formware binary, and allows to extract the parameters to a JSON
format text file. This file can then easily be modified, and used to update
binary firmware, changing attributes and limits of each parameter.

Example of extracting and then updating the flight controller parameters:

```./dji_flyc_param_ed.py -vv -x -m P3X_FW_V01.07.0060_m0306.bin```

```./dji_flyc_param_ed.py -vv -u -m P3X_FW_V01.07.0060_m0306.bin```

More examples, for other products:

```./dji_flyc_param_ed.py -vv -x -b 0x420000 -m A3_FW_V01.02.00.00_m0306.bin```

```./dji_flyc_param_ed.py -vv -x -b 0x420000 -m wm220_0306_v03.02.35.05_20170525.pro.bin```

```./dji_flyc_param_ed.py -vv -x -b 0x0000 -m wm230_0306_v01.00.02.255_20170213.bin```

### comm_dat2pcap.py

DJI Universal Packet Container stream pareser with pcap output format.

The script parses Raw DUPC stream (ie. flight log files ```FLY???.DAT```) and wraps
single packets with PCap headers. Packets CRC is checked before the data is passed.
Any tool with PCap format support can then be used to analyse the data (ie. Wireshark).

Example of converting flight log file:

```./comm_dat2pcap.py -vv -d FLY002.DAT```

### comm_serial2pcap.py

DJI serial bus sniffer with DUPC packetizer and PCap output format.

The script captures data from two UARTs and wraps single DUPC packets with PCap headers.
Packets CRC is checked before the data is passed to the PCap file or FIFO pipe.
Any tool with pcap format support can then be used to analyse the data (ie. Wireshark).

The utility requires two serial interfaces with RX lines connected to RX and TX lines
within the drone.

Example of starting the capture from two UART-to-TTL (aka FTDI) converters:

```./comm_serial2pcap.py -b 115200 -F /tmp/wsf /dev/ttyUSB0 /dev/ttyUSB1```

### comm_mkdupc.py

DUPC Packet Builder with hex string output.

This tool can build a proper DUPC packet containing given header fields and payload.
The packet will be outputed in hexadecimal form. List of known commands and the look
of expected payloads can be found in Wireshark dissectors described below.

Example of generating a packet to ask Spark camera module for its Sensor ID:

```./comm_mkdupc.py --receiver_type=Camera --seq_num=65280 --ack_type=ACK_After_Exec --cmd_set=Camera --cmd_id=181```

### comm_serialtalk.py

DUPC Builder which sends packet to DJI product and receives a response.

This tool builds a proper DUPC packet containing given header fields and payload.
Then it sends it via given serial port and waits for response. It shows the
returning packet upon receiving it.

Example of asking Flight Controller for hardware and firmware version data (tested on Ph3):

```./comm_serialtalk.py /dev/ttyUSB0 -vv --timeout=5000 --receiver_type=FlyController --seq_num=65280 --ack_type=No_ACK_Needed --cmd_set=General --cmd_id=1```

### comm_og_service_tool.py

OGs Service Tool for Dji products.

The script allows to trigger a few service functions of Dji drones. It talks to the drone
like `comm_serialtalk.py`, but provides easier interface for some important functions.

Example of listing Flight Controller Parameters 200-300 on Ph3 Pro to CSV format:

```./comm_og_service_tool.py /dev/ttyUSB0 P3X FlycParam list --start=200 --count=100 --fmt=csv```

Example of getting value of Flight Controller Parameters on Spark:

```./comm_og_service_tool.py /dev/ttyUSB0 -vv SPARK FlycParam get g_config.flying_limit.max_height_0 --fmt=2line```

Example of setting value of Flight Controller Parameters on Spark:

```./comm_og_service_tool.py /dev/ttyUSB0 -vv SPARK FlycParam set g_config.flying_limit.max_height_0 500```

Example of performing service "joint coarse" calibration of Spark gimbal:

```./comm_og_service_tool.py /dev/ttyUSB0 -vv SPARK GimbalCalib JointCoarse```

Example of performing service "linear hall" calibration of Spark gimbal, using Windows host:

```python3 comm_og_service_tool.py COM23 -vv SPARK GimbalCalib LinearHall```

### comm_dissector

The folder contains [Wireshark](https://www.wireshark.org/) dissector for for analyzing communication in DJI drone interfaces.

Documentation of the tool is [included in its folder](comm_dissector/README.md).

# Symbols

For some specific firmware modules in specific versions, there are partial symbols
available in 'symbols' directory. The symbols are in two formats:

- MAP files - Can be loaded into most disassemblers with minimal effort. For IDA Pro,
there is a plugin which can read MAP files and rename functions and variables
accordingly. Only functions and global variables which were given a meaningful names
are included in these files.
- IDC script - Format specific to IDA Pro. Stores not only functions and globals,
but also type information - enums and structs. Allows storing function parameters
and local variables with their names and types, too. Can be easily applied to an
opened ELF file via IDA Pro, no other tool will understand it.

Symbols are matched with ELF files generated with the tools described above,
not directly with the BINs. Use example commands provided in previous section
to generate ELF files with content matching to the symbols.

When working on a firmware version for which no symbols are available, you may
want to use a version with symbols for reference in naming.
