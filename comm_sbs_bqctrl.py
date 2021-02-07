#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Smart Battery System communication tool.

This tool allows to interact with chips designed based on Smart Battery Data
Specification. It also supports some extensions to that specification
implemented by Texas Instruments in their BQ series gas gauge chips.

Usage of this tool requires connection to SMBus lines (SDA,SCL,GND) of the
SBS-compatible chip. SMBus communication uses I2C as a base, so most devices
with I2C bus can be used to establish the communication.

This tool was written with intent to be used on Raspberry Pi and its I2C bus.
Using a different device will require slight modifications to the code.

You do not need the TI EV2300 programmer to use this script.

To get address of the device, you may use `i2cdetect`. Don't be scared about
the interactive messages, SBS is a well defined protocol which isn't easy to
break, sepecially when the chip is sealed. Probing will not accidently result
in a packet which disables the battery forever.

If the battery already has I2C master device on the bus (like uC on battery
board), do NOT turn the battery on for use with this program. The SBS chip
should wake from sleep to answer on requests from this program, and if the
battery is turned on, the constant communication from internal master will
interfere with packets sent by this tool. It can also cause the battery
to enter temporary SMBus error mode. To avoid that, don't even press the
battery button while it is connected to I2C interface.

If the script shows "OSError: [Errno 74] Bad message", the very likely
cause is invalid I2C speed. Check how to change baud rate of your
I2C bus device. Baud rate of 100kbps should work. The EV2300 usually
uses baud rate of 66kbps.

If the script shows "OSError: [Errno 121] Remote I/O error", that means
the device did not respond to a command. It's hard to say if there was no
response at all, or only to a specific part. This one may also happen when
trying to access priviliged command in sealed state. Make sure you can see
the device with 'i2cdetect'. If not, check physical connections. Make sure
that no other device interferes with the communication - it is known that
even unpowered EV2300 programmer connected to the bus can interfere with
signals on lines.

On Raspberry Pi, the "Remote I/O error" can sometimes disappear after
starting GPIO deamon with high sampling rate, ie. `sudo pigpiod -s 1`.

There is also "OSError: [Errno 5] Input/output error" which tend to happen
interchangeably with "Remote I/O error", but only if the other side responds
to part of the message.

"""
__version__ = "0.1.0"
__author__ = "Mefistotelis @ Original Gangsters"
__license__ = "GPL"

import re
import sys
import time
import enum
import struct
import hashlib
import argparse

def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

class DecoratedEnum(enum.Enum):
    @classmethod
    def from_name(cls, name):
        for itm in cls:
            if itm.name == name:
                return itm
        raise ValueError("{} is not a known value".format(name))


class CHIP_TYPE(DecoratedEnum):
    """ Smart Battery System chip type
    """
    AUTO		= 0
    SBS			= 1
    # Texas Instruments BQ chips; lower 16 bits are DeviceType
    BQGENERIC	= 0x010000
    BQ30z55		= 0x010550
    BQ20z65		= 0x010650
    BQ3050		= 0x013050
    BQ3060		= 0x013060
    BQ40z307	= 0x014307
    # supported by BatteryManagementStudio-1.3
    BQ35100		= 0x010100
    BQ34110		= 0x010110
    BQ34210		= 0x010210
    BQ27220		= 0x010220
    BQ27320		= 0x010320
    BQ27421		= 0x010421
    BQ27425		= 0x010425
    BQ27426		= 0x010426
    BQ27510		= 0x010510
    BQ27520		= 0x010520
    BQ27530		= 0x010530
    BQ27531		= 0x010531
    BQ27532		= 0x010532
    BQ27541		= 0x010541
    BQ27542		= 0x010542
    BQ27545		= 0x010545
    BQ27546		= 0x010546
    BQ27621		= 0x010621
    BQ27742		= 0x010742
    BQ78z100	= 0x011100
    BQ27z561	= 0x011561
    BQ78350		= 0x011e9b
    BQ28z610	= 0x012610
    BQ40z50		= 0x014500
    BQ40z60		= 0x014600
    BQ40z70		= 0x014800
    BQ4050		= 0x019e34
    BQ769x2		= 0x017692

CHIP_TYPE.AUTO.__doc__	= "Automatic detection of the chip"
CHIP_TYPE.SBS.__doc__	= "Generic chip with SBS support"
CHIP_TYPE.BQGENERIC.__doc__= "Unidentified chip from TI BQ family"
CHIP_TYPE.BQ30z55.__doc__ = "Texas Instruments BQ30z55 chip"

class SBS_COMMAND(DecoratedEnum):
    """ Smart Battery Data Specification 1.1 commands list

    This is a list taken directly from specification.
    """
    ManufacturerAccess		= 0x00
    RemainingCapacityAlarm	= 0x01
    RemainingTimeAlarm		= 0x02
    BatteryMode				= 0x03
    AtRate					= 0x04
    AtRateToFull			= 0x05
    AtRateToEmpty			= 0x06
    AtRateOK				= 0x07
    Temperature				= 0x08
    Voltage					= 0x09
    Current					= 0x0a
    AverageCurrent			= 0x0b
    MaxError				= 0x0c
    RelativeStateOfCharge	= 0x0d
    AbsoluteStateOfCharge	= 0x0e
    RemainingCapacity		= 0x0f
    FullChargeCapacity		= 0x10
    RunTimeToEmpty			= 0x11
    AverageTimeToEmpty		= 0x12
    AverageTimeToFull		= 0x13
    ChargingCurrent			= 0x14
    ChargingVoltage			= 0x15
    BatteryStatus			= 0x16
    CycleCount				= 0x17
    DesignCapacity			= 0x18
    DesignVoltage			= 0x19
    SpecificationInfo		= 0x1a
    ManufactureDate			= 0x1b
    SerialNumber			= 0x1c
    ManufacturerName		= 0x20
    DeviceName				= 0x21
    DeviceChemistry			= 0x22
    ManufacturerData		= 0x23
    OptionalMfgFunction5	= 0x2f
    OptionalMfgFunction4	= 0x3c
    OptionalMfgFunction3	= 0x3d
    OptionalMfgFunction2	= 0x3e
    OptionalMfgFunction1	= 0x3f


class SBS_COMMAND_BQ30(DecoratedEnum):
    """ Commands used in BQ30 family SBS chips
    """
    ManufacturerInput		= SBS_COMMAND.OptionalMfgFunction5.value
    Cell3Voltage			= SBS_COMMAND.OptionalMfgFunction4.value
    Cell2Voltage			= SBS_COMMAND.OptionalMfgFunction3.value
    Cell1Voltage			= SBS_COMMAND.OptionalMfgFunction2.value
    Cell0Voltage			= SBS_COMMAND.OptionalMfgFunction1.value
    SafetyAlert				= 0x50
    SafetyStatus			= 0x51
    PFAlert					= 0x52
    PFStatus				= 0x53
    OperationStatus			= 0x54
    ChargingStatus			= 0x55
    GaugingStatus			= 0x56
    ManufacturingStatus		= 0x57
    AFERegisters			= 0x58
    LifetimeDataBlock1		= 0x60
    LifetimeDataBlock2		= 0x61
    LifetimeDataBlock3		= 0x62
    ManufacturerInfo		= 0x70
    Voltages				= 0x71
    Temperatures			= 0x72
    ITStatus1				= 0x73
    ITStatus2				= 0x74


class SBS_COMMAND_BQ_TURBO(DecoratedEnum):
    """ Commands used in BQ family SBS chips which support TURBO mode
    """
    TURBO_POWER				= 0x59
    TURBO_FINAL				= 0x5a
    TURBO_PACK_R			= 0x5b
    TURBO_SYS_R				= 0x5c
    MIN_SYS_V				= 0x5d
    TURBO_CURRENT			= 0x5e


class MANUFACTURER_ACCESS_CMD_BQ30(DecoratedEnum):
    """ ManufacturerAccess sub-commands used in BQ30 family SBS chips
    """
    ManufacturerData		= 0x00
    DeviceType				= 0x01
    FirmwareVersion			= 0x02
    HardwareVersion			= 0x03
    InstructionFlashChecksum= 0x04
    DataFlashChecksum		= 0x05
    ChemicalID				= 0x06
    ShutdownMode			= 0x10
    SleepMode				= 0x11
    DeviceReset				= 0x12
    FuseToggle				= 0x1d
    PreChargeFET			= 0x1e
    ChargeFET				= 0x1f
    DischargeFET			= 0x20
    Gauging					= 0x21
    FETControl				= 0x22
    LifetimeDataCollection	= 0x23
    PermanentFailure		= 0x24
    BlackBoxRecorder		= 0x25
    Fuse					= 0x26
    LEDEnable				= 0x27
    LifetimeDataReset		= 0x28
    PermanentFailDataReset	= 0x29
    BlackBoxRecorderReset	= 0x2a
    LEDToggle				= 0x2b
    LEDDisplayOn			= 0x2c
    CALMode					= 0x2d
    SealDevice				= 0x30
    UnSealDevice			= 0x31
    FullAccessDevice		= 0x32
    ROMMode					= 0x33
    SHIPMode				= 0x34
    UnsealKey				= 0x35
    FullAccessKey			= 0x36
    AuthenticationKey		= 0x37
    SafetyAlert				= 0x50
    SafetyStatus			= 0x51
    PFAlert					= 0x52
    PFStatus				= 0x53
    OperationStatus			= 0x54
    ChargingStatus			= 0x55
    GaugingStatus			= 0x56
    ManufacturingStatus		= 0x57
    AFERegister				= 0x58
    LifetimeDataBlock1		= 0x60
    LifetimeDataBlock2		= 0x61
    LifetimeDataBlock3		= 0x62
    ManufacturerInfo		= 0x70
    Voltages				= 0x71
    Temperatures			= 0x72
    ITStatus1				= 0x73
    ITStatus2				= 0x74
    DFAccessRowAddress		= 0x0100
    ExitCalibOutputMode		= 0xf080
    OutputCCnADC			= 0xf081
    OutputShortCCnADCOffset	= 0xf082


class MANUFACTURER_ACCESS_CMD_BQ_FIRMWARE_VERSION(DecoratedEnum):
    """ FirmwareVersion sub-command fields used in BQ30 family SBS chips
    """
    DeviceNumber			= 0x00
    FirmwareVersion			= 0x10
    FwBuildNumber			= 0x20
    FirmwareType			= 0x30
    ImpedanceTrackVersion	= 0x38
    ReservedRR				= 0x48
    ReservedEE				= 0x58

MANUFACTURER_ACCESS_CMD_BQ_FIRMWARE_VERSION_INFO = {
    MANUFACTURER_ACCESS_CMD_BQ_FIRMWARE_VERSION.DeviceNumber : {
        'type'	: "uint16",
        'endian': "be",
        'unit'	: {'scale':1,'name':"hex"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DevN",
        'desc'	: ("Type of this IC device. The same as returned by DeviceType."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_FIRMWARE_VERSION.FirmwareVersion : {
        'type'	: "byte[2]",
        'unit'	: {'scale':1,'name':"hexver"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "FwVer",
        'desc'	: ("Version number of the firmware."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_FIRMWARE_VERSION.FwBuildNumber : {
        'type'	: "uint16",
        'endian': "be",
        'unit'	: {'scale':1,'name':"dec04"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "FwBld",
        'desc'	: ("Build number of the firmware."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_FIRMWARE_VERSION.FirmwareType : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"hex"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "FwTyp",
        'desc'	: ("Type of the firmware. Usually used to differentiate "
            "pre-release firmwares from production ones."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_FIRMWARE_VERSION.ImpedanceTrackVersion : {
        'type'	: "byte[2]",
        'unit'	: {'scale':1,'name':"hexver"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "ITVer",
        'desc'	: ("Impedance Track sw implementation version. Impedance "
            "Track Algorithm with Cell Balancing During Rest is Texas "
            "Instuments trademarked functionality."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_FIRMWARE_VERSION.ReservedRR : {
        'type'	: "byte[2]",
        'unit'	: {'scale':1,'name':"hex"},
        'nbits'	: 16,
        'access'	: "-",
        'tiny_name'	: "ResR",
        'desc'	: ("Field RR reserved by manufacturer. Either unused or used for internal purposes."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_FIRMWARE_VERSION.ReservedEE : {
        'type'	: "byte[2]",
        'unit'	: {'scale':1,'name':"hex"},
        'nbits'	: 16,
        'access'	: "-",
        'tiny_name'	: "ResE",
        'desc'	: ("Field EE reserved by manufacturer. Either unused or used for internal purposes."),
    },
}


class MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1(DecoratedEnum):
    """ LifetimeDataBlock1 sub-command fields used in BQ30 family SBS chips
    """
    MaxCellVoltage1			= 0x000
    MaxCellVoltage2			= 0x008
    MaxCellVoltage3			= 0x010
    MaxCellVoltage4			= 0x018
    MinCellVoltage1			= 0x020
    MinCellVoltage2			= 0x028
    MinCellVoltage3			= 0x030
    MinCellVoltage4			= 0x038
    MaxDeltaCellVoltage		= 0x040
    MaxChargeCurrent		= 0x048
    MaxDischargeCurrent		= 0x050
    MaxAvgDischrCurrent		= 0x058
    MaxAvgDischrPower		= 0x060
    NoOfCOVEvents			= 0x068
    LastCOVEvent			= 0x070
    NoOfCUVEvents			= 0x078
    LastCUVEvent			= 0x080
    NoOfOCD1Events			= 0x088
    LastOCD1Event			= 0x090
    NoOfOCD2Events			= 0x098
    LastOCD2Event			= 0x0a0
    NoOfOCC1Events			= 0x0a8
    LastOCC1Event			= 0x0b0
    NoOfOCC2Events			= 0x0b8
    LastOCC2Event			= 0x0c0
    NoOfOLDEvents			= 0x0c8
    LastOLDEvent			= 0x0d0
    NoOfSCDEvents			= 0x0d8
    LastSCDEvent			= 0x0e0
    NoOfSCCEvents			= 0x0e8
    LastSCCEvent			= 0x0f0
    NoOfOTCEvents			= 0x0f8

MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1_INFO = {
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxCellVoltage1 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxV1",
        'desc'	: ("Max Cell 1 Voltage."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxCellVoltage2 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxV2",
        'desc'	: ("Max Cell 2 Voltage."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxCellVoltage3 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxV3",
        'desc'	: ("Max Cell 3 Voltage."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxCellVoltage4 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxV4",
        'desc'	: ("Max Cell 4 Voltage."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.MinCellVoltage1 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MinV1",
        'desc'	: ("Min Cell 1 Voltage."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.MinCellVoltage2 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MinV2",
        'desc'	: ("Min Cell 2 Voltage."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.MinCellVoltage3 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MinV3",
        'desc'	: ("Min Cell 3 Voltage."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.MinCellVoltage4 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MinV4",
        'desc'	: ("Min Cell 4 Voltage."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxDeltaCellVoltage : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxDV",
        'desc'	: ("Max Delta Cell Voltage."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxChargeCurrent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MChgI",
        'desc'	: ("Max Charge Current."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxDischargeCurrent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MDisI",
        'desc'	: ("Max Discharge Current."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxAvgDischrCurrent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MADisI",
        'desc'	: ("Max Average Discharge Current."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxAvgDischrPower : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MADisP",
        'desc'	: ("Max Average Discharge Power."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfCOVEvents : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nCOVEv",
        'desc'	: ("Number of Cell Overvoltage Events."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.LastCOVEvent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LCOVEv",
        'desc'	: ("Last Cell Overvoltage Event."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfCUVEvents : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nCUVEv",
        'desc'	: ("Number of Cell Undervoltage Events."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.LastCUVEvent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LCUVEv",
        'desc'	: ("Last Cell Undervoltage Event."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfOCD1Events : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nOCD1E",
        'desc'	: ("Number of Overcurrent in Discharge 1 Events."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.LastOCD1Event : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LOCD1E",
        'desc'	: ("Last Overcurrent in Discharge 1 Event."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfOCD2Events : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nOCD2E",
        'desc'	: ("Number of Overcurrent in Discharge 2 Events."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.LastOCD2Event : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LOCD2E",
        'desc'	: ("Last Overcurrent in Discharge 2 Event."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfOCC1Events : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nOCC1E",
        'desc'	: ("Number of Overcurrent in Charge 1 Events."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.LastOCC1Event : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LOCC1E",
        'desc'	: ("Last Overcurrent in Charge 1 Event."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfOCC2Events : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nOCC2E",
        'desc'	: ("Number of Overcurrent in Charge 2 Events."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.LastOCC2Event : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LOCC2E",
        'desc'	: ("Last Overcurrent in Charge 2 Event."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfOLDEvents : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nOLDEv",
        'desc'	: ("Number of Overload in Discharge Events."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.LastOLDEvent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LOLDEv",
        'desc'	: ("Last Overload in Discharge Event."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfSCDEvents : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nSCDEv",
        'desc'	: ("Number of Short Circuit in Discharge Events."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.LastSCDEvent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LSCDEv",
        'desc'	: ("Last Short Circuit in Discharge Event."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfSCCEvents : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nSCCEv",
        'desc'	: ("Number of Short Circuit in Charge Events."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.LastSCCEvent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LSCCEv",
        'desc'	: ("Last Short Circuit in Charge Event."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfOTCEvents : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "-", # Inaccessible - message limit to 32 bytes
        'tiny_name'	: "nOTCEv",
        'desc'	: ("Number of Overtemperature in Charge Events. Inaccessible due to I2C constrains."),
    },
}


class MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2(DecoratedEnum):
    """ LifetimeDataBlock2 sub-command fields used in BQ30 family SBS chips
    """
    LastOTCEvent			= 0x000
    NoOfOTDEvents			= 0x008
    LastOTDEvent			= 0x010
    NoOfOTFEvents			= 0x018
    LastOTFEvent			= 0x020
    NoValidChrgTerm			= 0x028
    LastValidChrgTerm		= 0x030
    NoOfQMaxUpdates			= 0x038
    LastQMaxUpdate			= 0x040
    NoOfRAUpdates			= 0x048
    LastRAUpdate			= 0x050
    NoOfRADisables			= 0x058
    LastRADisable			= 0x060
    NoOfShutdowns			= 0x068
    NoOfPartialResets		= 0x070
    NoOfFullResets			= 0x078
    NoOfWDTResets			= 0x080
    CBTimeCell1				= 0x088
    CBTimeCell2				= 0x090
    CBTimeCell3				= 0x098
    CBTimeCell4				= 0x0a0
    MaxTempCell				= 0x0a8
    MinTempCell				= 0x0b0
    MaxDeltaCellTemp		= 0x0b8
    MaxTempIntSensor		= 0x0c0
    MinTempIntSensor		= 0x0c8
    MaxTempFET				= 0x0d0

MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2_INFO = {
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.LastOTCEvent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LOTCEv",
        'desc'	: ("Last Overtemperature in Charge Event."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoOfOTDEvents : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nOTDEv",
        'desc'	: ("Number of Overtemperature in Discharge Events."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.LastOTDEvent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LOTDEv",
        'desc'	: ("Last Overtemperature in Discharge Event."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoOfOTFEvents : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nOTFEv",
        'desc'	: ("Number of Overtemperature FET Events."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.LastOTFEvent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LOTFEv",
        'desc'	: ("Last Overtemperature FET Event."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoValidChrgTerm : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nVChrT",
        'desc'	: ("Number of Valid Charge Terminations."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.LastValidChrgTerm : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LVChrT",
        'desc'	: ("Last Valid Charge Termination."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoOfQMaxUpdates : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nQMaxU",
        'desc'	: ("Number of QMax Updates."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.LastQMaxUpdate : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LQMaxU",
        'desc'	: ("Last QMax Update."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoOfRAUpdates : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nRAUpd",
        'desc'	: ("Number of RA resistance Updates."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.LastRAUpdate : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LRAUp2",
        'desc'	: ("Last RA resistance Update."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoOfRADisables : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nRADis",
        'desc'	: ("Number of RA resistance Disables."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.LastRADisable : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LRADis",
        'desc'	: ("Last RA resistance Disable."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoOfShutdowns : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nShtdn",
        'desc'	: ("Number of Shutdowns."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoOfPartialResets : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nPaRst",
        'desc'	: ("Number of Partial Resets."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoOfFullResets : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nFuRst",
        'desc'	: ("Number of Full Resets."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoOfWDTResets : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nWDRst",
        'desc'	: ("Number of Resets by Watchdog Timer."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.CBTimeCell1 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CBTim1",
        'desc'	: ("Total performed balancing bypass time cell 1."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.CBTimeCell2 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CBTim2",
        'desc'	: ("Total performed balancing bypass time cell 2."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.CBTimeCell3 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CBTim3",
        'desc'	: ("Total performed balancing bypass time cell 3."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.CBTimeCell4 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CBTim4",
        'desc'	: ("Total performed balancing bypass time cell 4."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.MaxTempCell : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxTem",
        'desc'	: ("Max cell temperatute."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.MinTempCell : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MinTem",
        'desc'	: ("Min cell temperatute."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.MaxDeltaCellTemp : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxDTe",
        'desc'	: ("Max delta of cell temperatute."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.MaxTempIntSensor : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxTeS",
        'desc'	: ("Max temperatute on internal sensor."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.MinTempIntSensor : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MinTeS",
        'desc'	: ("Min temperatute on internal sensor."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2.MaxTempFET : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MxTFET",
        'desc'	: ("Max temperature of FET."),
    },
}


class MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK3(DecoratedEnum):
    """ LifetimeDataBlock3 sub-command fields used in BQ30 family SBS chips
    """
    TotalFwRunTime			= 0x000
    TimeSpentInUT			= 0x010
    TimeSpentInLT			= 0x020
    TimeSpentInSTL			= 0x030
    TimeSpentInRT			= 0x040
    TimeSpentInSTH			= 0x050
    TimeSpentInHT			= 0x060
    TimeSpentInOT			= 0x070

MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK3_INFO = {
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK3.TotalFwRunTime : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TotFRT",
        'desc'	: ("Total firmware Run Time."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK3.TimeSpentInUT : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TimeUT",
        'desc'	: ("Time Spent in Under Temperature."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK3.TimeSpentInLT : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TimeLT",
        'desc'	: ("Time Spent in Low Temperature."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK3.TimeSpentInSTL : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TimSTL",
        'desc'	: ("Time Spent in Standard Temp Low."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK3.TimeSpentInRT : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TimeRT",
        'desc'	: ("Time Spent in Recommended Temperature."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK3.TimeSpentInSTH : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TimSTH",
        'desc'	: ("Time Spent in Standard Temp High."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK3.TimeSpentInHT : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TimeHT",
        'desc'	: ("Time Spent in High Temperature."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK3.TimeSpentInOT : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TimeOT",
        'desc'	: ("Time Spent in Over Temperature."),
    },
}


class MANUFACTURER_ACCESS_CMD_BQ_VOLTAGES(DecoratedEnum):
    """ Voltages sub-command fields used in BQ30 family SBS chips
    """
    CellVoltage0			= 0x000
    CellVoltage1			= 0x010
    CellVoltage2			= 0x020
    CellVoltage3			= 0x030
    BATVoltage				= 0x040
    PACKVoltage				= 0x050

MANUFACTURER_ACCESS_CMD_BQ_VOLTAGES_INFO = {
    MANUFACTURER_ACCESS_CMD_BQ_VOLTAGES.CellVoltage0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Volt0",
        'desc'	: ("Cell Voltage 0."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_VOLTAGES.CellVoltage1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Volt1",
        'desc'	: ("Cell Voltage 1."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_VOLTAGES.CellVoltage2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Volt2",
        'desc'	: ("Cell Voltage 2."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_VOLTAGES.CellVoltage3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Volt3",
        'desc'	: ("Cell Voltage 3."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_VOLTAGES.BATVoltage : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "BatV",
        'desc'	: ("BAT Voltage."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_VOLTAGES.PACKVoltage : {
        'type'	: "uint16",
        'unit'	: {'scale':100,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "PackV",
        'desc'	: ("PACK Voltage."),
    },
}


class MANUFACTURER_ACCESS_CMD_BQ_TEMPERATURES(DecoratedEnum):
    """ Temperatures sub-command fields used in BQ30 family SBS chips
    """
    IntTemperature			= 0x000
    TS1Temperature			= 0x010
    TS2Temperature			= 0x020
    TS3Temperature			= 0x030
    TS4Temperature			= 0x040
    CellTemperature			= 0x050
    FETTemperature			= 0x060

MANUFACTURER_ACCESS_CMD_BQ_TEMPERATURES_INFO = {
    MANUFACTURER_ACCESS_CMD_BQ_TEMPERATURES.IntTemperature : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "IntTm",
        'desc'	: ("Int Temperature."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_TEMPERATURES.TS1Temperature : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TS1Tm",
        'desc'	: ("Temp Sensor 1 Temperature."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_TEMPERATURES.TS2Temperature : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TS2Tm",
        'desc'	: ("Temp Sensor 2 Temperature."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_TEMPERATURES.TS3Temperature : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TS3Tm",
        'desc'	: ("Temp Sensor 3 Temperature."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_TEMPERATURES.TS4Temperature : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TS4Tm",
        'desc'	: ("Temp Sensor 4 Temperature."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_TEMPERATURES.CellTemperature : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'optional'	: True,
        'access'	: "r",
        'tiny_name'	: "CelTm",
        'desc'	: ("Cell Temperature."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_TEMPERATURES.FETTemperature : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'optional'	: True,
        'access'	: "r",
        'tiny_name'	: "FETTm",
        'desc'	: ("FET Temperature."),
    },
}


class MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS1(DecoratedEnum):
    """ ITStatus1 sub-command fields used in BQ30 family SBS chips
    """
    DepthOfDischg0Cell0		= 0x000
    DepthOfDischg0Cell1		= 0x010
    DepthOfDischg0Cell2		= 0x020
    DepthOfDischg0Cell3		= 0x030
    ChargeLastDOD0Upd		= 0x040
    QMaxCell0				= 0x050
    QMaxCell1				= 0x060
    QMaxCell2				= 0x070
    QMaxCell3				= 0x080
    TimeSinceStateChg		= 0x090
    DepOfDischEOCCell0		= 0x0b0
    DepOfDischEOCCell1		= 0x0c0
    DepOfDischEOCCell2		= 0x0d0
    DepOfDischEOCCell3		= 0x0e0

MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS1_INFO = {
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS1.DepthOfDischg0Cell0 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DOD0_0",
        'desc'	: ("Depth of discharge cell 0."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS1.DepthOfDischg0Cell1 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DOD0_1",
        'desc'	: ("Depth of discharge cell 1."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS1.DepthOfDischg0Cell2 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DOD0_2",
        'desc'	: ("Depth of discharge cell 2."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS1.DepthOfDischg0Cell3 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DOD0_3",
        'desc'	: ("Depth of discharge cell 3."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS1.ChargeLastDOD0Upd : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "ChDOD0Up",
        'desc'	: ("Passed charge since last DOD0 update."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS1.QMaxCell0 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "QMAX0",
        'desc'	: ("Qmax of cell 0."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS1.QMaxCell1 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "QMAX1",
        'desc'	: ("Qmax of cell 1."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS1.QMaxCell2 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "QMAX2",
        'desc'	: ("Qmax of cell 2."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS1.QMaxCell3 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "QMAX3",
        'desc'	: ("Qmax of cell 3."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS1.TimeSinceStateChg : {
        'type'	: "uint32",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 32,
        'access'	: "r",
        'tiny_name'	: "StateTime",
        'desc'	: ("Time passed since last state change. The changes "
            "accounted are DSG, CHG, RST."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS1.DepOfDischEOCCell0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DODEOC0",
        'desc'	: ("Depth of discharge cell0 at End of Charge."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS1.DepOfDischEOCCell1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DODEOC1",
        'desc'	: ("Depth of discharge cell1 at End of Charge."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS1.DepOfDischEOCCell2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DODEOC2",
        'desc'	: ("Depth of discharge cell2 at End of Charge."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS1.DepOfDischEOCCell3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DODEOC3",
        'desc'	: ("Depth of discharge cell3 at End of Charge."),
    },
}


class MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2(DecoratedEnum):
    """ ITStatus2 sub-command fields used in BQ30 family SBS chips
    """
    PackGridPoint			= 0x000
    LearnedStatus			= 0x008
    GridCell0				= 0x010
    GridCell1				= 0x018
    GridCell2				= 0x020
    GridCell3				= 0x028
    CompResCell0			= 0x030
    CompResCell1			= 0x040
    CompResCell2			= 0x050
    CompResCell3			= 0x060
    CBTimeCell0				= 0x070
    CBTimeCell1				= 0x080
    CBTimeCell2				= 0x090
    CBTimeCell3				= 0x0a0
    RaScale0				= 0x0b0
    RaScale1				= 0x0c0
    RaScale2				= 0x0d0
    RaScale3				= 0x0e0

MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2_INFO = {
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2.PackGridPoint : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "PackGrid",
        'desc'	: ("Active pack grid point. Minimum of CellGrid0 to CellGrid3."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2.LearnedStatus : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LStatus",
        'desc'	: ("Learned status of resistance table."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2.GridCell0 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CellGrid0",
        'desc'	: ("Active grid point cell 0."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2.GridCell1 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CellGrid1",
        'desc'	: ("Active grid point cell 1."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2.GridCell2 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CellGrid2",
        'desc'	: ("Active grid point cell 2."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2.GridCell3 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CellGrid3",
        'desc'	: ("Active grid point cell 3."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2.CompResCell0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CompRes0",
        'desc'	: ("Last calc temp compensated resistance cell 0."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2.CompResCell1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CompRes1",
        'desc'	: ("Last calc temp compensated resistance cell 1."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2.CompResCell2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CompRes2",
        'desc'	: ("Last calc temp compensated resistance cell 2."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2.CompResCell3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CompRes3",
        'desc'	: ("Last calc temp compensated resistance cell 3."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2.CBTimeCell0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CBTime0",
        'desc'	: ("Calculated cell balancing time cell 0."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2.CBTimeCell1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CBTime1",
        'desc'	: ("Calculated cell balancing time cell 1."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2.CBTimeCell2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CBTime2",
        'desc'	: ("Calculated cell balancing time cell 2."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2.CBTimeCell3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CBTime3",
        'desc'	: ("Calculated cell balancing time cell 3."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2.RaScale0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "RaScale0",
        'desc'	: ("Ra Table scaling factor cell 0."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2.RaScale1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "RaScale1",
        'desc'	: ("Ra Table scaling factor cell 1."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2.RaScale2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "RaScale2",
        'desc'	: ("Ra Table scaling factor cell 2."),
    },
    MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2.RaScale3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "RaScale3",
        'desc'	: ("Ra Table scaling factor cell 3."),
    },
}


class SBS_FLAG_SAFETY_ALERT(DecoratedEnum):
    """ Flags used in SafetyAlert command
    """
    CELL_UNDERVOLTAGE			= 0
    CELL_OVERVOLTAGE			= 1
    OVERCURRENT_CHG_TIER1		= 2
    OVERCURRENT_CHG_TIER2		= 3
    OVERCURRENT_DIS_TIER1		= 4
    OVERCURRENT_DIS_TIER2		= 5
    OVERLOAD_DIS				= 6
    RESERVED7					= 7
    SHORT_CIRCUIT_CHG			= 8
    RESERVED9					= 9
    SHORT_CIRCUIT_DIS			= 10
    RESERVED11					= 11
    OVERTEMPERATURE_CHG			= 12
    OVERTEMPERATURE_DIS			= 13
    IR_COMPENSATED_CUV			= 14
    RESERVED15					= 15
    FET_OVERTEMPERATURE			= 16
    HOST_WATCHDOG_TIMEOUT		= 17
    PRECHARGING_TIMEOUT			= 18
    PRECHG_TIMEOUT_SUSPEND		= 19
    CHARGING_TIMEOUT			= 20
    CHG_TIMEOUT_SUSPEND			= 21
    OVERCHARGE					= 22
    CHG_CURRENT_ABOVE_REQ		= 23
    CHG_VOLTAGE_ABOVE_REQ		= 24
    RESERVED25					= 25
    RESERVED26					= 26
    RESERVED27					= 27
    RESERVED28					= 28
    RESERVED29					= 29
    RESERVED30					= 30
    RESERVED31					= 31

SBS_SAFETY_ALERT_INFO = {
    SBS_FLAG_SAFETY_ALERT.CELL_UNDERVOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CUV",
        'desc'	: ("Cell Undervoltage."),
    },
    SBS_FLAG_SAFETY_ALERT.CELL_OVERVOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "COV",
        'desc'	: ("Cell Overvoltage."),
    },
    SBS_FLAG_SAFETY_ALERT.OVERCURRENT_CHG_TIER1 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OCC1",
        'desc'	: ("Overcurrent in Charge 1st Tier."),
    },
    SBS_FLAG_SAFETY_ALERT.OVERCURRENT_CHG_TIER2 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OCC2",
        'desc'	: ("Overcurrent in Charge 2nd Tier."),
    },
    SBS_FLAG_SAFETY_ALERT.OVERCURRENT_DIS_TIER1 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OCD1",
        'desc'	: ("Overcurrent in Discharge 1st Tier."),
    },
    SBS_FLAG_SAFETY_ALERT.OVERCURRENT_DIS_TIER2 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OCD2",
        'desc'	: ("Overcurrent in Discharge 2nd Tier."),
    },
    SBS_FLAG_SAFETY_ALERT.OVERLOAD_DIS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OLD",
        'desc'	: ("Overload in discharge."),
    },
    SBS_FLAG_SAFETY_ALERT.RESERVED7 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "Res7",
        'desc'	: ("Reserved (Overload in discharge)."),
    },
    SBS_FLAG_SAFETY_ALERT.SHORT_CIRCUIT_CHG : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "SCC",
        'desc'	: ("Short circuit in charge."),
    },
    SBS_FLAG_SAFETY_ALERT.RESERVED9 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "Res9",
        'desc'	: ("Reserved (Short circ. in charge latch)."),
    },
    SBS_FLAG_SAFETY_ALERT.SHORT_CIRCUIT_DIS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "SCD",
        'desc'	: ("Short circuit in discharge."),
    },
    SBS_FLAG_SAFETY_ALERT.RESERVED11 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResB",
        'desc'	: ("Reserved (Short circ. in disch. latch)."),
    },
    SBS_FLAG_SAFETY_ALERT.OVERTEMPERATURE_CHG : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OTC",
        'desc'	: ("Overtemperature in charge."),
    },
    SBS_FLAG_SAFETY_ALERT.OVERTEMPERATURE_DIS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OTD",
        'desc'	: ("Overtemperature in discharge."),
    },
    SBS_FLAG_SAFETY_ALERT.IR_COMPENSATED_CUV : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CUVC",
        'desc'	: ("I*R compensated CUV."),
    },
    SBS_FLAG_SAFETY_ALERT.RESERVED15 : {
        'type'	: "int_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'access'	: "-",
        'tiny_name'	: "ResF",
        'desc'	: ("Reserved bit 15."),
    },
    SBS_FLAG_SAFETY_ALERT.FET_OVERTEMPERATURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OTF",
        'desc'	: ("FET overtemperature."),
    },
    SBS_FLAG_SAFETY_ALERT.HOST_WATCHDOG_TIMEOUT : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "HWD",
        'desc'	: ("SBS Host watchdog timeout."),
    },
    SBS_FLAG_SAFETY_ALERT.PRECHARGING_TIMEOUT : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "PTO",
        'desc'	: ("Pre-charging timeout."),
    },
    SBS_FLAG_SAFETY_ALERT.PRECHG_TIMEOUT_SUSPEND : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "PTOS",
        'desc'	: ("Pre-charging timeout suspend."),
    },
    SBS_FLAG_SAFETY_ALERT.CHARGING_TIMEOUT : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CTO",
        'desc'	: ("Charging timeout."),
    },
    SBS_FLAG_SAFETY_ALERT.CHG_TIMEOUT_SUSPEND : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CTOS",
        'desc'	: ("Charging timeout suspend."),
    },
    SBS_FLAG_SAFETY_ALERT.OVERCHARGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OC",
        'desc'	: ("Overcharge."),
    },
    SBS_FLAG_SAFETY_ALERT.CHG_CURRENT_ABOVE_REQ : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CHGC",
        'desc'	: ("Charging Current higher than requested."),
    },
    SBS_FLAG_SAFETY_ALERT.CHG_VOLTAGE_ABOVE_REQ : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CHGV",
        'desc'	: ("Charging Voltage higher than requested."),
    },
    SBS_FLAG_SAFETY_ALERT.RESERVED25 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResO",
        'desc'	: ("Reserved bit 25."),
    },
    SBS_FLAG_SAFETY_ALERT.RESERVED26 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResP",
        'desc'	: ("Reserved bit 26."),
    },
    SBS_FLAG_SAFETY_ALERT.RESERVED27 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResQ",
        'desc'	: ("Reserved bit 27."),
    },
    SBS_FLAG_SAFETY_ALERT.RESERVED28 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResR",
        'desc'	: ("Reserved bit 28."),
    },
    SBS_FLAG_SAFETY_ALERT.RESERVED29 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResS",
        'desc'	: ("Reserved bit 29."),
    },
    SBS_FLAG_SAFETY_ALERT.RESERVED30 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResT",
        'desc'	: ("Reserved bit 30."),
    },
    SBS_FLAG_SAFETY_ALERT.RESERVED31 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResU",
        'desc'	: ("Reserved bit 31."),
    },
}


class SBS_FLAG_SAFETY_STATUS(DecoratedEnum):
    """ Flags used in SafetyStatus command
    """
    CELL_UNDERVOLTAGE			= 0
    CELL_OVERVOLTAGE			= 1
    OVERCURRENT_CHG_TIER1		= 2
    OVERCURRENT_CHG_TIER2		= 3
    OVERCURRENT_DIS_TIER1		= 4
    OVERCURRENT_DIS_TIER2		= 5
    OVERLOAD_DIS				= 6
    OVERLOAD_DIS_LATCH			= 7
    SHORT_CIRCUIT_CHG			= 8
    SHORT_CIRC_CHG_LATCH		= 9
    SHORT_CIRCUIT_DIS			= 10
    SHORT_CIRC_DIS_LATCH		= 11
    OVERTEMPERATURE_CHG			= 12
    OVERTEMPERATURE_DIS			= 13
    IR_COMPENSATED_CUV			= 14
    RESERVED15					= 15
    FET_OVERTEMPERATURE			= 16
    HOST_WATCHDOG_TIMEOUT		= 17
    PRECHARGING_TIMEOUT			= 18
    RESERVED19					= 19
    CHARGING_TIMEOUT			= 20
    RESERVED21					= 21
    OVERCHARGE					= 22
    CHG_CURRENT_ABOVE_REQ		= 23
    CHG_VOLTAGE_ABOVE_REQ		= 24
    RESERVED25					= 25
    RESERVED26					= 26
    RESERVED27					= 27
    RESERVED28					= 28
    RESERVED29					= 29
    RESERVED30					= 30
    RESERVED31					= 31

SBS_SAFETY_STATUS_INFO = {
    SBS_FLAG_SAFETY_STATUS.CELL_UNDERVOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CUV",
        'desc'	: ("Cell Undervoltage."),
    },
    SBS_FLAG_SAFETY_STATUS.CELL_OVERVOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "COV",
        'desc'	: ("Cell Overvoltage."),
    },
    SBS_FLAG_SAFETY_STATUS.OVERCURRENT_CHG_TIER1 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OCC1",
        'desc'	: ("Overcurrent in Charge 1st Tier."),
    },
    SBS_FLAG_SAFETY_STATUS.OVERCURRENT_CHG_TIER2 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OCC2",
        'desc'	: ("Overcurrent in Charge 2nd Tier."),
    },
    SBS_FLAG_SAFETY_STATUS.OVERCURRENT_DIS_TIER1 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OCD1",
        'desc'	: ("Overcurrent in Discharge 1st Tier."),
    },
    SBS_FLAG_SAFETY_STATUS.OVERCURRENT_DIS_TIER2 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OCD2",
        'desc'	: ("Overcurrent in Discharge 2nd Tier."),
    },
    SBS_FLAG_SAFETY_STATUS.OVERLOAD_DIS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OLD",
        'desc'	: ("Overload in discharge."),
    },
    SBS_FLAG_SAFETY_STATUS.OVERLOAD_DIS_LATCH : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OLDL",
        'desc'	: ("Overload in discharge latch."),
    },
    SBS_FLAG_SAFETY_STATUS.SHORT_CIRCUIT_CHG : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "SCC",
        'desc'	: ("Short circuit in charge."),
    },
    SBS_FLAG_SAFETY_STATUS.SHORT_CIRC_CHG_LATCH : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "SCCL",
        'desc'	: ("Short circuit in charge latch."),
    },
    SBS_FLAG_SAFETY_STATUS.SHORT_CIRCUIT_DIS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "SCD",
        'desc'	: ("Short circuit in discharge."),
    },
    SBS_FLAG_SAFETY_STATUS.SHORT_CIRC_DIS_LATCH : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "SCDL",
        'desc'	: ("Short circuit in discharge latch."),
    },
    SBS_FLAG_SAFETY_STATUS.OVERTEMPERATURE_CHG : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OTC",
        'desc'	: ("Overtemperature in charge."),
    },
    SBS_FLAG_SAFETY_STATUS.OVERTEMPERATURE_DIS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OTD",
        'desc'	: ("Overtemperature in discharge."),
    },
    SBS_FLAG_SAFETY_STATUS.IR_COMPENSATED_CUV : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CUVC",
        'desc'	: ("I*R compensated CUV."),
    },
    SBS_FLAG_SAFETY_STATUS.RESERVED15 : {
        'type'	: "int_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'access'	: "-",
        'tiny_name'	: "ResF",
        'desc'	: ("Reserved bit 15."),
    },
    SBS_FLAG_SAFETY_STATUS.FET_OVERTEMPERATURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OTF",
        'desc'	: ("FET overtemperature."),
    },
    SBS_FLAG_SAFETY_STATUS.HOST_WATCHDOG_TIMEOUT : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "HWD",
        'desc'	: ("SBS Host watchdog timeout."),
    },
    SBS_FLAG_SAFETY_STATUS.PRECHARGING_TIMEOUT : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "PTO",
        'desc'	: ("Pre-charging timeout."),
    },
    SBS_FLAG_SAFETY_STATUS.RESERVED19 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResI",
        'desc'	: ("Reserved (Pre-charging timeout suspend)."),
    },
    SBS_FLAG_SAFETY_STATUS.CHARGING_TIMEOUT : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CTO",
        'desc'	: ("Charging timeout."),
    },
    SBS_FLAG_SAFETY_STATUS.RESERVED21 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResK",
        'desc'	: ("Reserved (Charging timeout suspend)."),
    },
    SBS_FLAG_SAFETY_STATUS.OVERCHARGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OC",
        'desc'	: ("Overcharge."),
    },
    SBS_FLAG_SAFETY_STATUS.CHG_CURRENT_ABOVE_REQ : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CHGC",
        'desc'	: ("Charging Current higher than requested."),
    },
    SBS_FLAG_SAFETY_STATUS.CHG_VOLTAGE_ABOVE_REQ : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CHGV",
        'desc'	: ("Charging Voltage higher than requested."),
    },
    SBS_FLAG_SAFETY_STATUS.RESERVED25 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResO",
        'desc'	: ("Reserved bit 25."),
    },
    SBS_FLAG_SAFETY_STATUS.RESERVED26 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResP",
        'desc'	: ("Reserved bit 26."),
    },
    SBS_FLAG_SAFETY_STATUS.RESERVED27 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResQ",
        'desc'	: ("Reserved bit 27."),
    },
    SBS_FLAG_SAFETY_STATUS.RESERVED28 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResR",
        'desc'	: ("Reserved bit 28."),
    },
    SBS_FLAG_SAFETY_STATUS.RESERVED29 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResS",
        'desc'	: ("Reserved bit 29."),
    },
    SBS_FLAG_SAFETY_STATUS.RESERVED30 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResT",
        'desc'	: ("Reserved bit 30."),
    },
    SBS_FLAG_SAFETY_STATUS.RESERVED31 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResU",
        'desc'	: ("Reserved bit 31."),
    },
}


class SBS_FLAG_PF_ALERT(DecoratedEnum):
    """ Flags used in PFAlert command
    """
    CELL_UNDERVOLTAGE			= 0
    CELL_OVERVOLTAGE			= 1
    COPPER_DEPOSITION			= 2
    RESERVED3					= 3
    OVERTEMPERATURE				= 4
    RESERVED5					= 5
    OVERTEMPERATURE_FET			= 6
    QMAX_IMBALANCE				= 7
    CELL_BALANCING				= 8
    CELL_IMPEDANCE				= 9
    CAPACITY_DETERIORATION		= 10
    VOLTAGE_IMBALANCE_REST		= 11
    VOLTAGE_IMBALANCE_ACTV		= 12
    RESERVED13					= 13
    RESERVED14					= 14
    RESERVED15					= 15
    CHARGE_FET					= 16
    DISCHARGE_FET				= 17
    THERMISTOR					= 18
    FUSE						= 19
    AFE_REGISTER				= 20
    AFE_COMMUNICATION			= 21
    FUSE_TRIGGER_2ND_LEVEL		= 22
    RESERVED23					= 23
    RESERVED24					= 24
    OPEN_VCX					= 25
    RESERVED26					= 26
    RESERVED27					= 27
    RESERVED28					= 28
    RESERVED29					= 29
    RESERVED30					= 30
    RESERVED31					= 31

SBS_PF_ALERT_INFO = {
    SBS_FLAG_PF_ALERT.CELL_UNDERVOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CUV",
        'desc'	: ("Cell Undervoltage."),
    },
    SBS_FLAG_PF_ALERT.CELL_OVERVOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "COV",
        'desc'	: ("Cell Overvoltage."),
    },
    SBS_FLAG_PF_ALERT.COPPER_DEPOSITION : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CUDEP",
        'desc'	: ("Copper deposition."),
    },
    SBS_FLAG_PF_ALERT.RESERVED3 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "Res3",
        'desc'	: ("Reserved bit 3."),
    },
    SBS_FLAG_PF_ALERT.OVERTEMPERATURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OTCE",
        'desc'	: ("Overtemperature in charge."),
    },
    SBS_FLAG_PF_ALERT.RESERVED5 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "Res5",
        'desc'	: ("Reserved bit 5."),
    },
    SBS_FLAG_PF_ALERT.OVERTEMPERATURE_FET : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OTF",
        'desc'	: ("Overtemperature of FET."),
    },
    SBS_FLAG_PF_ALERT.QMAX_IMBALANCE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "QIM",
        'desc'	: ("QMAX Imbalance."),
    },
    SBS_FLAG_PF_ALERT.CELL_BALANCING : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CB",
        'desc'	: ("Cell balancing."),
    },
    SBS_FLAG_PF_ALERT.CELL_IMPEDANCE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "IMP",
        'desc'	: ("Cell impedance."),
    },
    SBS_FLAG_PF_ALERT.CAPACITY_DETERIORATION : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CD",
        'desc'	: ("Capacity Deterioration."),
    },
    SBS_FLAG_PF_ALERT.VOLTAGE_IMBALANCE_REST : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "VIMR",
        'desc'	: ("Voltage imbalance at Rest."),
    },
    SBS_FLAG_PF_ALERT.VOLTAGE_IMBALANCE_ACTV : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "VIMA",
        'desc'	: ("Voltage imbalance at Active."),
    },
    SBS_FLAG_PF_ALERT.RESERVED13 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResD",
        'desc'	: ("Reserved bit 13."),
    },
    SBS_FLAG_PF_ALERT.RESERVED14 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResE",
        'desc'	: ("Reserved bit 14."),
    },
    SBS_FLAG_PF_ALERT.RESERVED15 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResF",
        'desc'	: ("Reserved bit 15."),
    },
    SBS_FLAG_PF_ALERT.CHARGE_FET : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CFETF",
        'desc'	: ("Charge FET."),
    },
    SBS_FLAG_PF_ALERT.DISCHARGE_FET : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "DFET",
        'desc'	: ("Discharge FET."),
    },
    SBS_FLAG_PF_ALERT.THERMISTOR : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "THERM",
        'desc'	: ("Thermistor."),
    },
    SBS_FLAG_PF_ALERT.FUSE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "FUSE",
        'desc'	: ("Fuse."),
    },
    SBS_FLAG_PF_ALERT.AFE_REGISTER : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Not avail.","Detected"],
        'access'	: "r",
        'tiny_name'	: "AFER",
        'desc'	: ("AFE Register."),
    },
    SBS_FLAG_PF_ALERT.AFE_COMMUNICATION : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "AFEC",
        'desc'	: ("AFE Communication."),
    },
    SBS_FLAG_PF_ALERT.FUSE_TRIGGER_2ND_LEVEL : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "2LVL",
        'desc'	: ("FUSE input trigger by external protection. Whether FUSE "
            "input indicates fuse trigger by external 2nd level protection."),
    },
    SBS_FLAG_PF_ALERT.RESERVED23 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResM",
        'desc'	: ("Reserved (PTC by AFE)."),
    },
    SBS_FLAG_PF_ALERT.RESERVED24 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResN",
        'desc'	: ("Reserved (Instruction Flash Checksum)."),
    },
    SBS_FLAG_PF_ALERT.OPEN_VCX : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Not avail.","Detected"],
        'access'	: "r",
        'tiny_name'	: "OCECO",
        'desc'	: ("Open VCx."),
    },
    SBS_FLAG_PF_ALERT.RESERVED26 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResP",
        'desc'	: ("Reserved bit 26."),
    },
    SBS_FLAG_PF_ALERT.RESERVED27 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResQ",
        'desc'	: ("Reserved bit 27."),
    },
    SBS_FLAG_PF_ALERT.RESERVED28 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResR",
        'desc'	: ("Reserved bit 28."),
    },
    SBS_FLAG_PF_ALERT.RESERVED29 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResS",
        'desc'	: ("Reserved bit 29."),
    },
    SBS_FLAG_PF_ALERT.RESERVED30 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResT",
        'desc'	: ("Reserved bit 30."),
    },
    SBS_FLAG_PF_ALERT.RESERVED31 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResU",
        'desc'	: ("Reserved bit 31."),
    },
}


class SBS_FLAG_PF_STATUS(DecoratedEnum):
    """ Flags used in PFStatus command
    """
    CELL_UNDERVOLTAGE			= 0
    CELL_OVERVOLTAGE			= 1
    COPPER_DEPOSITION			= 2
    RESERVED3					= 3
    OVERTEMPERATURE				= 4
    RESERVED5					= 5
    OVERTEMPERATURE_FET			= 6
    QMAX_IMBALANCE				= 7
    CELL_BALANCING				= 8
    CELL_IMPEDANCE				= 9
    CAPACITY_DETERIORATION		= 10
    VOLTAGE_IMBALANCE_REST		= 11
    VOLTAGE_IMBALANCE_ACTV		= 12
    RESERVED13					= 13
    RESERVED14					= 14
    RESERVED15					= 15
    CHARGE_FET					= 16
    DISCHARGE_FET				= 17
    THERMISTOR					= 18
    FUSE						= 19
    AFE_REGISTER				= 20
    AFE_COMMUNICATION			= 21
    FUSE_TRIGGER_2ND_LEVEL		= 22
    PTC_BY_AFE					= 23
    INSTR_FLASH_CHECKSUM		= 24
    OPEN_VCX					= 25
    DF_WRITE_FAILURE			= 26
    RESERVED27					= 27
    RESERVED28					= 28
    RESERVED29					= 29
    RESERVED30					= 30
    RESERVED31					= 31

SBS_PF_STATUS_INFO = {
    SBS_FLAG_PF_STATUS.CELL_UNDERVOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CUV",
        'desc'	: ("Cell Undervoltage."),
    },
    SBS_FLAG_PF_STATUS.CELL_OVERVOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "COV",
        'desc'	: ("Cell Overvoltage."),
    },
    SBS_FLAG_PF_STATUS.COPPER_DEPOSITION : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CUDEP",
        'desc'	: ("Copper deposition."),
    },
    SBS_FLAG_PF_STATUS.RESERVED3 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "Res3",
        'desc'	: ("Reserved bit 3."),
    },
    SBS_FLAG_PF_STATUS.OVERTEMPERATURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "OTCE",
        'desc'	: ("Overtemperature in charge."),
    },
    SBS_FLAG_PF_STATUS.RESERVED5 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "Res5",
        'desc'	: ("Reserved bit 5."),
    },
    SBS_FLAG_PF_STATUS.OVERTEMPERATURE_FET : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "OTF",
        'desc'	: ("Overtemperature of FET."),
    },
    SBS_FLAG_PF_STATUS.QMAX_IMBALANCE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "QIM",
        'desc'	: ("QMAX Imbalance."),
    },
    SBS_FLAG_PF_STATUS.CELL_BALANCING : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CB",
        'desc'	: ("Cell balancing."),
    },
    SBS_FLAG_PF_STATUS.CELL_IMPEDANCE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "IMP",
        'desc'	: ("Cell impedance."),
    },
    SBS_FLAG_PF_STATUS.CAPACITY_DETERIORATION : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CD",
        'desc'	: ("Capacity Deterioration."),
    },
    SBS_FLAG_PF_STATUS.VOLTAGE_IMBALANCE_REST : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "VIMR",
        'desc'	: ("Voltage imbalance at Rest."),
    },
    SBS_FLAG_PF_STATUS.VOLTAGE_IMBALANCE_ACTV : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "VIMA",
        'desc'	: ("Voltage imbalance at Active."),
    },
    SBS_FLAG_PF_STATUS.RESERVED13 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResD",
        'desc'	: ("Reserved bit 13."),
    },
    SBS_FLAG_PF_STATUS.RESERVED14 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResE",
        'desc'	: ("Reserved bit 14."),
    },
    SBS_FLAG_PF_STATUS.RESERVED15 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResF",
        'desc'	: ("Reserved bit 15."),
    },
    SBS_FLAG_PF_STATUS.CHARGE_FET : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CFETF",
        'desc'	: ("Charge FET."),
    },
    SBS_FLAG_PF_STATUS.DISCHARGE_FET : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "DFET",
        'desc'	: ("Discharge FET."),
    },
    SBS_FLAG_PF_STATUS.THERMISTOR : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "THERM",
        'desc'	: ("Thermistor."),
    },
    SBS_FLAG_PF_STATUS.FUSE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "FUSE",
        'desc'	: ("Fuse."),
    },
    SBS_FLAG_PF_STATUS.AFE_REGISTER : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Not avail.","Active"],
        'access'	: "r",
        'tiny_name'	: "AFER",
        'desc'	: ("AFE Register."),
    },
    SBS_FLAG_PF_STATUS.AFE_COMMUNICATION : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "AFEC",
        'desc'	: ("AFE Communication."),
    },
    SBS_FLAG_PF_STATUS.FUSE_TRIGGER_2ND_LEVEL : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "2LVL",
        'desc'	: ("FUSE input trigger by external protection. Whether FUSE "
            "input indicates fuse trigger by external 2nd level protection."),
    },
    SBS_FLAG_PF_STATUS.PTC_BY_AFE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "PTC",
        'desc'	: ("Positive Temperature Coefficient by AFE."),
    },
    SBS_FLAG_PF_STATUS.INSTR_FLASH_CHECKSUM : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Normal","Chksum fail"],
        'access'	: "-",
        'tiny_name'	: "IFC",
        'desc'	: ("Instruction Flash Checksum."),
    },
    SBS_FLAG_PF_STATUS.OPEN_VCX : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Not avail.","Active"],
        'access'	: "r",
        'tiny_name'	: "OCECO",
        'desc'	: ("Open VCx."),
    },
    SBS_FLAG_PF_STATUS.DF_WRITE_FAILURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "DFW",
        'desc'	: ("Data Flash write failure."),
    },
    SBS_FLAG_PF_STATUS.RESERVED27 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResQ",
        'desc'	: ("Reserved bit 27."),
    },
    SBS_FLAG_PF_STATUS.RESERVED28 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResR",
        'desc'	: ("Reserved bit 28."),
    },
    SBS_FLAG_PF_STATUS.RESERVED29 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResS",
        'desc'	: ("Reserved bit 29."),
    },
    SBS_FLAG_PF_STATUS.RESERVED30 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResT",
        'desc'	: ("Reserved bit 30."),
    },
    SBS_FLAG_PF_STATUS.RESERVED31 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResU",
        'desc'	: ("Reserved bit 31."),
    },
}


class SBS_FLAG_OPERATION_STATUS(DecoratedEnum):
    """ Flags used in OperationStatus command
    """
    SYS_PRESENT_LOW				= 0
    DSG_FET_STATUS				= 1
    CHG_FET_STATUS				= 2
    PCHG_FET_STATUS				= 3
    GPOD_FET_STATUS				= 4
    FUSE_STATUS					= 5
    CELL_BALANCING				= 6
    LED_ENABLE					= 7
    SECURITY_MODE				= 8
    CAL_RAW_ADC_CC				= 10
    SAFETY_STATUS				= 11
    PERMANENT_FAILURE			= 12
    DISCHARGING_DISABLED		= 13
    CHARGING_DISABLED			= 14
    SLEEP_MODE					= 15
    SHUTDOWN_BY_MA				= 16
    SHIP_MODE_BY_MA				= 17
    AUTH_ONGOING				= 18
    AFE_WATCHDOG_FAIL			= 19
    FAST_VOLTAGE_SAMP			= 20
    RAW_ADC_CC_OUTPUT			= 21
    SHUTDOWN_BY_VOLTAGE			= 22
    SLEEP_BY_MA					= 23
    INIT_AFTER_RESET			= 24
    SMB_CAL_ON_LOW			= 25
    QMAX_UPDATE_IN_SLEEP		= 26
    CURRENT_CHK_IN_SLEEP		= 27
    XLOW_SPEED_STATE			= 28
    RESERVED29					= 29
    RESERVED30					= 30
    RESERVED31					= 31

SBS_OPERATION_STATUS_INFO = {
    SBS_FLAG_OPERATION_STATUS.SYS_PRESENT_LOW : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "PRES",
        'desc'	: ("System present input state low."),
    },
    SBS_FLAG_OPERATION_STATUS.DSG_FET_STATUS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "DSG",
        'desc'	: ("DSG FET status."),
    },
    SBS_FLAG_OPERATION_STATUS.CHG_FET_STATUS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CHG",
        'desc'	: ("CHG FET Status."),
    },
    SBS_FLAG_OPERATION_STATUS.PCHG_FET_STATUS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "PCHG",
        'desc'	: ("PCHG FET Status."),
    },
    SBS_FLAG_OPERATION_STATUS.GPOD_FET_STATUS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "GPOD",
        'desc'	: ("GPOD FET Status."),
    },
    SBS_FLAG_OPERATION_STATUS.FUSE_STATUS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "FUSE",
        'desc'	: ("FUSE input status."),
    },
    SBS_FLAG_OPERATION_STATUS.CELL_BALANCING : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CB",
        'desc'	: ("Cell Balancing."),
    },
    SBS_FLAG_OPERATION_STATUS.LED_ENABLE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "LED",
        'desc'	: ("LED Enable."),
    },
    SBS_FLAG_OPERATION_STATUS.SECURITY_MODE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 2,
        'value_names'	: ["Reserved","Full Access","Unsealed","Sealed"],
        'access'	: "r",
        'tiny_name'	: "SEC",
        'desc'	: ("Security Mode."),
    },
    SBS_FLAG_OPERATION_STATUS.CAL_RAW_ADC_CC : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CAL",
        'desc'	: ("Calibration Raw ADC/CC output active."),
    },
    SBS_FLAG_OPERATION_STATUS.SAFETY_STATUS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SS",
        'desc'	: ("Safety Status."),
    },
    SBS_FLAG_OPERATION_STATUS.PERMANENT_FAILURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "PF",
        'desc'	: ("Permanent Failure."),
    },
    SBS_FLAG_OPERATION_STATUS.DISCHARGING_DISABLED : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "XDSG",
        'desc'	: ("Discharging Disabled."),
    },
    SBS_FLAG_OPERATION_STATUS.CHARGING_DISABLED : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "XCHG",
        'desc'	: ("Charging Disabled."),
    },
    SBS_FLAG_OPERATION_STATUS.SLEEP_MODE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SLEEP",
        'desc'	: ("Sleep mode condition met."),
    },
    SBS_FLAG_OPERATION_STATUS.SHUTDOWN_BY_MA : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SDM",
        'desc'	: ("Shutdown activated by ManufacturerAccess()."),
    },
    SBS_FLAG_OPERATION_STATUS.SHIP_MODE_BY_MA : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SHPM",
        'desc'	: ("SHIP mode activated with ManufacturerAccess()."),
    },
    SBS_FLAG_OPERATION_STATUS.AUTH_ONGOING : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "AUTH",
        'desc'	: ("Authentication ongoing."),
    },
    SBS_FLAG_OPERATION_STATUS.AFE_WATCHDOG_FAIL : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "AWD",
        'desc'	: ("AFE Watchdog failure."),
    },
    SBS_FLAG_OPERATION_STATUS.FAST_VOLTAGE_SAMP : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "FVS",
        'desc'	: ("Fast Voltage Sampling."),
    },
    SBS_FLAG_OPERATION_STATUS.RAW_ADC_CC_OUTPUT : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CALO",
        'desc'	: ("Raw ADC/CC offset calibration output."),
    },
    SBS_FLAG_OPERATION_STATUS.SHUTDOWN_BY_VOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SDV",
        'desc'	: ("SHUTDOWN activated by voltage."),
    },
    SBS_FLAG_OPERATION_STATUS.SLEEP_BY_MA : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SLEPM",
        'desc'	: ("SLEEP mode activated by ManufacturerAccess()."),
    },
    SBS_FLAG_OPERATION_STATUS.INIT_AFTER_RESET : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "INIT",
        'desc'	: ("Initialization after full reset. Cleared when SBS data "
            "calculated and available."),
    },
    SBS_FLAG_OPERATION_STATUS.SMB_CAL_ON_LOW : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Cal starts","Not in Cal"],
        'access'	: "r",
        'tiny_name'	: "SLCAL",
        'desc'	: ("Auto CC offset calibration on low. The calibration "
            "ongoing after this SBS line goes low. This bit may not be "
            "read by the host because the FW will clear it when a "
            "communication is detected."),
    },
    SBS_FLAG_OPERATION_STATUS.QMAX_UPDATE_IN_SLEEP : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SLEPQM",
        'desc'	: ("QMax update in SLEEP mode."),
    },
    SBS_FLAG_OPERATION_STATUS.CURRENT_CHK_IN_SLEEP : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SLEPC",
        'desc'	: ("Checking current in SLEEP mode."),
    },
    SBS_FLAG_OPERATION_STATUS.XLOW_SPEED_STATE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "XLSBS",
        'desc'	: ("Fast Mode."),
    },
    SBS_FLAG_OPERATION_STATUS.RESERVED29 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResS",
        'desc'	: ("Reserved bit 29."),
    },
    SBS_FLAG_OPERATION_STATUS.RESERVED30 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResT",
        'desc'	: ("Reserved bit 30."),
    },
    SBS_FLAG_OPERATION_STATUS.RESERVED31 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResU",
        'desc'	: ("Reserved bit 31."),
    },
}


class SBS_FLAG_CHARGING_STATUS(DecoratedEnum):
    """ Flags used in ChargingStatus command
    """
    UNDER_TEMPERATURE			= 0
    LOW_TEMPERATURE				= 1
    STD_TEMPERATURE_LOW			= 2
    RECOMMENDED_TEMPERATURE		= 3
    STD_TEMPERATURE_HIGH		= 4
    HIGH_TEMPERATURE			= 5
    OVER_TEMPERATURE			= 6
    PRECHARGE_VOLTAGE			= 7
    LOW_VOLTAGE					= 8
    MID_VOLTAGE					= 9
    HIGH_VOLTAGE				= 10
    CHARGE_INHIBIT				= 11
    CHARGE_SUSPEND				= 12
    CHARGING_CURRENT_RATE		= 13
    CHARGING_VOLTAGE_RATE		= 14
    CHARGING_CURRENT_COMPNS		= 15
    VALID_CHARGE_TERMINATN		= 16
    RESERVED17					= 17
    MAINTENANCE_CHARGE			= 18
    RESERVED19					= 19
    RESERVED20					= 20
    RESERVED21					= 21
    RESERVED22					= 22
    RESERVED23					= 23

SBS_CHARGING_STATUS_INFO = {
    SBS_FLAG_CHARGING_STATUS.UNDER_TEMPERATURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "UT",
        'desc'	: ("Under Temperature Range."),
    },
    SBS_FLAG_CHARGING_STATUS.LOW_TEMPERATURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "LT",
        'desc'	: ("Low Temperature Range."),
    },
    SBS_FLAG_CHARGING_STATUS.STD_TEMPERATURE_LOW : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "STL",
        'desc'	: ("Standard Temperature Low Range."),
    },
    SBS_FLAG_CHARGING_STATUS.RECOMMENDED_TEMPERATURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "RT",
        'desc'	: ("Recommended Temperature Range."),
    },
    SBS_FLAG_CHARGING_STATUS.STD_TEMPERATURE_HIGH : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "ST",
        'desc'	: ("Standard Temperature High Range."),
    },
    SBS_FLAG_CHARGING_STATUS.HIGH_TEMPERATURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "HT",
        'desc'	: ("High Temperature Range."),
    },
    SBS_FLAG_CHARGING_STATUS.OVER_TEMPERATURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "OT",
        'desc'	: ("Over Temperature Range."),
    },
    SBS_FLAG_CHARGING_STATUS.PRECHARGE_VOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "PV",
        'desc'	: ("Precharge Voltage Range."),
    },
    SBS_FLAG_CHARGING_STATUS.LOW_VOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "LV",
        'desc'	: ("Low Voltage Range."),
    },
    SBS_FLAG_CHARGING_STATUS.MID_VOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "MV",
        'desc'	: ("Mid Voltage Range."),
    },
    SBS_FLAG_CHARGING_STATUS.HIGH_VOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "HV",
        'desc'	: ("High Voltage Range."),
    },
    SBS_FLAG_CHARGING_STATUS.CHARGE_INHIBIT : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "IN",
        'desc'	: ("Charge Inhibit."),
    },
    SBS_FLAG_CHARGING_STATUS.CHARGE_SUSPEND : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SU",
        'desc'	: ("Charge Suspend."),
    },
    SBS_FLAG_CHARGING_STATUS.CHARGING_CURRENT_RATE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CCR",
        'desc'	: ("ChargingCurrent() Rate."),
    },
    SBS_FLAG_CHARGING_STATUS.CHARGING_VOLTAGE_RATE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CVR",
        'desc'	: ("ChargingVoltage() Rate."),
    },
    SBS_FLAG_CHARGING_STATUS.CHARGING_CURRENT_COMPNS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CCC",
        'desc'	: ("ChargingCurrent() Compensation."),
    },
    SBS_FLAG_CHARGING_STATUS.VALID_CHARGE_TERMINATN : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "VCT",
        'desc'	: ("Valid Charge Termination."),
    },
    SBS_FLAG_CHARGING_STATUS.RESERVED17 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResH",
        'desc'	: ("Reserved bit 17."),
    },
    SBS_FLAG_CHARGING_STATUS.MAINTENANCE_CHARGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "MCHG",
        'desc'	: ("Maintenance charge."),
    },
    SBS_FLAG_CHARGING_STATUS.RESERVED19 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResJ",
        'desc'	: ("Reserved bit 19."),
    },
    SBS_FLAG_CHARGING_STATUS.RESERVED20 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResK",
        'desc'	: ("Reserved bit 20."),
    },
    SBS_FLAG_CHARGING_STATUS.RESERVED21 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResL",
        'desc'	: ("Reserved bit 21."),
    },
    SBS_FLAG_CHARGING_STATUS.RESERVED22 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResM",
        'desc'	: ("Reserved bit 22."),
    },
    SBS_FLAG_CHARGING_STATUS.RESERVED23 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResN",
        'desc'	: ("Reserved bit 23."),
    },
}


class SBS_FLAG_GAUGING_STATUS(DecoratedEnum):
    """ Flags used in GaugingStatus command
    """
    OCV_QMAX_UPDATED			= 0
    DISCHARGE_DETECTED			= 1
    RESISTANCE_UPDATE			= 2
    VOLTAGE_OK_FOR_QMAX			= 3
    QMAX_UPDATES				= 4
    FULLY_DISCHARGED			= 5
    FULLY_CHARGED				= 6
    NEG_SCALE_FACTOR			= 7
    DISCHARGE_QUALIFIED			= 8
    QMAX_UPDATED_T				= 9
    RESISTANCE_UPDATE_T			= 10
    LOAD_MODE					= 11
    OCV_FLAT_REGION				= 12
    TERMNT_DISCHG_ALARM			= 13
    TERMNT_CHARGE_ALARM			= 14
    LIPH_RELAX_MODE				= 15

SBS_GAUGING_STATUS_INFO = {
    SBS_FLAG_GAUGING_STATUS.OCV_QMAX_UPDATED : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Not upd.","Updated"],
        'access'	: "r",
        'tiny_name'	: "RESTD0",
        'desc'	: ("OCV and QMax Updated."),
    },
    SBS_FLAG_GAUGING_STATUS.DISCHARGE_DETECTED : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Charging","Discharging"],
        'access'	: "r",
        'tiny_name'	: "DSG",
        'desc'	: ("Discharge Detected."),
    },
    SBS_FLAG_GAUGING_STATUS.RESISTANCE_UPDATE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "RU",
        'desc'	: ("Resistance update."),
    },
    SBS_FLAG_GAUGING_STATUS.VOLTAGE_OK_FOR_QMAX : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "VOK",
        'desc'	: ("Cell Voltage OK for QMax."),
    },
    SBS_FLAG_GAUGING_STATUS.QMAX_UPDATES : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "QEN",
        'desc'	: ("QMax updates."),
    },
    SBS_FLAG_GAUGING_STATUS.FULLY_DISCHARGED : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "FD",
        'desc'	: ("Fully Discharged Detected by gauge algorithm."),
    },
    SBS_FLAG_GAUGING_STATUS.FULLY_CHARGED : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "FC",
        'desc'	: ("Fully Charged Detected by gauge algorithm."),
    },
    SBS_FLAG_GAUGING_STATUS.NEG_SCALE_FACTOR : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "NSFM",
        'desc'	: ("Negative scale factor mode."),
    },
    SBS_FLAG_GAUGING_STATUS.DISCHARGE_QUALIFIED : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "VDQ",
        'desc'	: ("Discharge qualified for learning."),
    },
    SBS_FLAG_GAUGING_STATUS.QMAX_UPDATED_T : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Toggle0","Toggle1"],
        'access'	: "r",
        'tiny_name'	: "QMax",
        'desc'	: ("QMax updated toggle. This flag toggles "
            "every time QMax is updated."),
    },
    SBS_FLAG_GAUGING_STATUS.RESISTANCE_UPDATE_T : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "RX",
        'desc'	: ("Resistance update toggle. This flag toggles "
            "every time Resistance is updated."),
    },
    SBS_FLAG_GAUGING_STATUS.LOAD_MODE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["C.Current","C.Power"],
        'access'	: "r",
        'tiny_name'	: "LDMD",
        'desc'	: ("Load Mode, constant current or power."),
    },
    SBS_FLAG_GAUGING_STATUS.OCV_FLAT_REGION : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Outside","In f.r."],
        'access'	: "r",
        'tiny_name'	: "OCVFR",
        'desc'	: ("OCV in flat region."),
    },
    SBS_FLAG_GAUGING_STATUS.TERMNT_DISCHG_ALARM : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "TDA",
        'desc'	: ("Terminate Discharge Alarm. Used when alarm is set by gauging algorithm."),
    },
    SBS_FLAG_GAUGING_STATUS.TERMNT_CHARGE_ALARM : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "TCA",
        'desc'	: ("Terminate Charge Alarm. Used when alarm is set by gauging algorithm."),
    },
    SBS_FLAG_GAUGING_STATUS.LIPH_RELAX_MODE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "LPFRlx",
        'desc'	: ("LiPh Relax Mode. Only active with Chem ID 0x400."),
    },
}


class SBS_FLAG_MANUFACTURING_STATUS(DecoratedEnum):
    """ Flags used in ManufacturingStatus command
    """
    PCHG_FUNCTION				= 0
    CHG_FET						= 1
    DSG_FET						= 2
    GAUGING						= 3
    FET_ACTION					= 4
    LIFETIME_DT_COLL			= 5
    PERMANENT_FAIL				= 6
    BLACK_BOX_REC				= 7
    FUSE_ACTION					= 8
    LED_DISPLAY					= 9
    RESERVED10					= 10
    RESERVED11					= 11
    RESERVED12					= 12
    RESERVED13					= 13
    RESERVED14					= 14
    CAL_ADC_CC_ON_MD			= 15

SBS_MANUFACTURING_STATUS_INFO = {
    SBS_FLAG_MANUFACTURING_STATUS.PCHG_FUNCTION : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "PCHG",
        'desc'	: ("PCHG Function, only available with FET=0."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.CHG_FET : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "CHG",
        'desc'	: ("CHG FET, only available with FET=0."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.DSG_FET : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "DSG",
        'desc'	: ("DSG FET, only available with FET=0."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.GAUGING : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "GAUGE",
        'desc'	: ("Gauging."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.FET_ACTION : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "FET",
        'desc'	: ("FET action."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.LIFETIME_DT_COLL : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "LF",
        'desc'	: ("Lifetime data collection."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.PERMANENT_FAIL : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "PF",
        'desc'	: ("Permanent Fail."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.BLACK_BOX_REC : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "BBR",
        'desc'	: ("Black box recorder."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.FUSE_ACTION : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "FUSE",
        'desc'	: ("FUSE action."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.LED_DISPLAY : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "LED",
        'desc'	: ("LED Display."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.RESERVED10 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "-",
        'tiny_name'	: "ResA",
        'desc'	: ("Reserved bit 10."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.RESERVED11 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "-",
        'tiny_name'	: "ResB",
        'desc'	: ("Reserved bit 11."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.RESERVED12 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "-",
        'tiny_name'	: "ResC",
        'desc'	: ("Reserved bit 12."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.RESERVED13 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "-",
        'tiny_name'	: "ResD",
        'desc'	: ("Reserved bit 13."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.RESERVED14 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "-",
        'tiny_name'	: "ResE",
        'desc'	: ("Reserved bit 14."),
    },

    SBS_FLAG_MANUFACTURING_STATUS.CAL_ADC_CC_ON_MD : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "CAL",
        'desc'	: ("CAL ADC or CC output on ManufacturerData()."),
    },
}


MANUFACTURER_ACCESS_CMD_BQ_INFO = {
    MANUFACTURER_ACCESS_CMD_BQ30.ManufacturerData : {
        # Data type associated with the sub-command
        'type'	: "uint16",
        # Measurement unit in which data type is stored
        'unit'	: {'scale':1,'name':"bitfields"},
        # Response field definition
        'bitfields_info'	: SBS_OPERATION_STATUS_INFO,
        # Access to the function in BQ seal modes: sealed, unsealed, full access;
        # write - means the command does a change within SBS chip other that
        # preparing output; read - means the command prepares output accessible by
        # reading value from 'resp_location'
        'access_per_seal'	: ("r","r","r",),
        # Command/offsets which stores response on this sub-command
        #'resp_location'	: SBS_COMMAND.ManufacturerData,
        # Description, with first sentence making a short description,
        'desc'	: ("Output ManufacturerData()."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.DeviceType : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"hex"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("IC device part number."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.FirmwareVersion : {
        'type'	: "byte[13]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: MANUFACTURER_ACCESS_CMD_BQ_FIRMWARE_VERSION_INFO,
        'access_per_seal'	: ("r","r","r",), # Tested working on BQ30z55 in sealed mode
        'desc'	: ("Version of the firmware within the device. Major and "
            "minor version numbers."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.HardwareVersion : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"dec"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("The IC hardware revision."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.InstructionFlashChecksum : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"hex"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'resp_wait'	: 0.35, # 250 turned out to be too little sometimes
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Checksum of the Instruction Flash. Read on "
            "ManufacturerData() after a wait time of 250 ms"),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.DataFlashChecksum : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"hex"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'resp_wait'	: 0.35,
        # doesn't seem to work on sealed BQ30z55
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Checksum of the Data Flash. Read on "
            "ManufacturerData() after a wait time of 250 ms"),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.ChemicalID : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"hex"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Chemical ID of the OCV tables. Returns ID used in the "
            "gauging algorithm."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.ShutdownMode : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        # when sealed, the command needs to be sent twice to BQ30z55
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("SHUTDOWN mode with reduced power consumption. The device "
            "can be sent to this mode before shipping. The device will wake "
            "up when a voltage is applied to PACK."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.SleepMode : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Send device to sleep if conditions are met. Some of "
            "wake conditions are: Current exceeds Sleep Current, Wake"
            "Comparator trips, SafetyAlert() or PFAlert() flags are set."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.DeviceReset : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Resets the device."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.FuseToggle : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Activate/deactivate FUSE pin. Toggle switch which allows "
            "to control the FUSE for ease of testing during manufacturing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.PreChargeFET : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Turns on/off Pre-CHG FET drive function. Toggle switch "
            "which allows to control the FUSE for ease of testing during "
            "manufacturing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.ChargeFET : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Turns on/off CHG FET drive function. Toggle switch "
            "which allows to control the Charge FET for ease of testing "
            "during manufacturing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.DischargeFET : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Turns on/off DSG FET drive function. Toggle switch "
            "which allows to control the Discharge FET for ease of testing "
            "during manufacturing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.Gauging : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Enable/disable the gauging function. Toggle switch "
            "which allows to control the Gauge for ease of testing "
            "during manufacturing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.FETControl : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Control of the CHG, DSG, and PCHG FET. Toggle switch "
            "which allows to either control the 3 FETs by the firmware, "
            "or disable them."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.LifetimeDataCollection : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Enables/disables Lifetime data collection. Toggle switch "
            "which allows to control whether Lifetime Data collection feature "
            "is working."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.PermanentFailure : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Enables/disables Permanent Failure. Toggle switch which "
            "allows to control when PF can be triggered for ease of "
            "manufacturing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.BlackBoxRecorder : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Enables/disables Black box recorder function. Toggle "
            "switch which allows to control the recorder for ease of "
            "manufacturing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.Fuse : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Enables/disables firmware fuse toggle function. Toggle "
            "switch which allows to control the fuse for ease of "
            "manufacturing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.LEDEnable : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Enables/disables LED Display function. Toggle "
            "switch which allows to control the LEDs for ease of "
            "manufacturing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.LifetimeDataReset : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Resets Lifetime data data in data flash. Clears the "
            "flags for ease of manufacturing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.PermanentFailDataReset : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Resets PF data in data flash. Clears permanent fail "
            "flags for ease of manufacturing. If the condition which caused "
            "the flag to appear is still tripped, the flag will get set again."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.BlackBoxRecorderReset : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Resets the black box recorder data in data flash. "
            "Toggle switch which allows to control the Black Box Recorder "
            "data in DF for ease of manufacturing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.LEDToggle : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Activate/deactivate configured LEDs. Toggle "
            "switch which allows to control the LEDs for ease of "
            "testing during manufacturing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.LEDDisplayOn : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Simulates low-high-low detection on the /DISP pin. "
            "Toggle switch which allows to control the /DISP pin "
            "for ease of manufacturing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.CALMode : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Outputs the raw ADC and CC data. Output of the raw data "
            "on ManufacturingData(), is controllable with 0xF081 and 0xF082 "
            "on ManufacturerAccess(). Toggle switch - write the value again "
            "to disable the output."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.SealDevice : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Seals the device, disabling some commands. Certain SBS "
            "commands and access to DF are disabled in sealed device."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.UnSealDevice : {
        'type'	: "byte[20]",
        'unit'	: {'scale':None,'name':"hex"},
        'resp_location'	: SBS_COMMAND_BQ30.ManufacturerInput,
        # special routine is required for this function, not just read/write
        'access_per_seal'	: ("-","-","-",),
        'desc'	: ("Unseals the device after valid SHA-1 authentication."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.FullAccessDevice : {
        'type'	: "byte[20]",
        'unit'	: {'scale':None,'name':"hex"},
        'resp_location'	: SBS_COMMAND_BQ30.ManufacturerInput,
        # special routine is required for this function, not just read/write
        'access_per_seal'	: ("-","-","-",),
        'desc'	: ("Enable Full Access to the device after SHA-1 auth."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.ROMMode : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","-","w",),
        'desc'	: ("Enables the ROM mode for IF update. On this command, "
            "device goes to ROM mode ready for update. Use 0x08 to "
            "ManufacturerAccess() to return."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.SHIPMode : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Low power SHIP Mode with no physical measurements. "
            "Enters a low power mode with no voltage, current, and "
            "temperature measurements, FETs are turned off, and the MCU "
            "is in a halt state. The device will return to NORMAL mode "
            "on SBS communication detection."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.UnsealKey : {
        'type'	: "byte[20]",
        'unit'	: {'scale':None,'name':"hex"},
        'resp_location'	: SBS_COMMAND_BQ30.ManufacturerInput,
        # special routine is required for this function, not just read/write
        'access_per_seal'	: ("-","-","-",),
        'desc'	: ("Enter a new Unseal key into the device."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.FullAccessKey : {
        'type'	: "byte[20]",
        'unit'	: {'scale':None,'name':"hex"},
        'resp_location'	: SBS_COMMAND_BQ30.ManufacturerInput,
        # special routine is required for this function, not just read/write
        'access_per_seal'	: ("-","-","-",),
        'desc'	: ("Enter a new Full Access key into the device."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.AuthenticationKey : {
        'type'	: "byte[20]",
        'unit'	: {'scale':None,'name':"hex"},
        'resp_location'	: SBS_COMMAND_BQ30.ManufacturerInput,
        # special routine is required for this function, not just read/write
        'access_per_seal'	: ("-","-","-",),
        'desc'	: ("Enter a new Authentication key into the device."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.SafetyAlert : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'bitfields_info'	: SBS_SAFETY_ALERT_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Safety Alert bits. Works in sealed mode."),
        'getter'	: "simple",
    },
    MANUFACTURER_ACCESS_CMD_BQ30.SafetyStatus : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'bitfields_info'	: SBS_SAFETY_STATUS_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Safety Status bits. Works in sealed mode."),
        'getter'	: "simple",
    },
    MANUFACTURER_ACCESS_CMD_BQ30.PFAlert : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'bitfields_info'	: SBS_PF_ALERT_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Permanent Fail Alert bits. Works in sealed mode."),
        'getter'	: "simple",
    },
    MANUFACTURER_ACCESS_CMD_BQ30.PFStatus : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'bitfields_info'	: SBS_PF_STATUS_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Permanent Fail Status bits. Works in sealed mode."),
        'getter'	: "simple",
    },
    MANUFACTURER_ACCESS_CMD_BQ30.OperationStatus : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'bitfields_info'	: SBS_OPERATION_STATUS_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Operational Status bits. Works in sealed mode."),
        'getter'	: "simple",
    },
    MANUFACTURER_ACCESS_CMD_BQ30.ChargingStatus : {
        'type'	: "uint24_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'bitfields_info'	: SBS_CHARGING_STATUS_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Charging Status bits. Works in sealed mode."),
        'getter'	: "simple",
    },
    MANUFACTURER_ACCESS_CMD_BQ30.GaugingStatus : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'bitfields_info'	: SBS_GAUGING_STATUS_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Gauging Status bits. Works in sealed mode."),
        'getter'	: "simple",
    },
    MANUFACTURER_ACCESS_CMD_BQ30.ManufacturingStatus : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'bitfields_info'	: SBS_MANUFACTURING_STATUS_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Manufacturing Status bits. Works in sealed mode."),
        'getter'	: "simple",
    },
    MANUFACTURER_ACCESS_CMD_BQ30.AFERegister : {
        'type'	: "byte[]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: None,
        # doesn't seem to work on sealed BQ30z55
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Output AFE register values on ManufacturerData()."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.LifetimeDataBlock1 : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK1_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Output lifetimes values on ManufacturerData()."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.LifetimeDataBlock2 : {
        'type'	: "byte[27]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK2_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Output lifetimes values on ManufacturerData()."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.LifetimeDataBlock3 : {
        'type'	: "byte[16]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: MANUFACTURER_ACCESS_CMD_BQ_LIFETIME_DATA_BLOCK3_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Output lifetimes values on ManufacturerData()."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.ManufacturerInfo : {
        'type'	: "string[32]",
        'unit'	: {'scale':None,'name':None},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Output 32 bytes of ManufacturerInfo."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.Voltages : {
        'type'	: "byte[12]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: MANUFACTURER_ACCESS_CMD_BQ_VOLTAGES_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Outputs voltage data values."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.Temperatures : {
        'type'	: "byte[14]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: MANUFACTURER_ACCESS_CMD_BQ_TEMPERATURES_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Outputs temperature data values. Block size "
            "is either 10 or 14 bytes, depending on chip and firmware."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.ITStatus1 : {
        'type'	: "byte[30]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS1_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Impedance Track Status parameters 1. Gauging algorithm "
            "related params. Outputs 30 bytes of IT data values."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.ITStatus2 : {
        'type'	: "byte[10]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: MANUFACTURER_ACCESS_CMD_BQ_IT_STATUS2_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Impedance Track Status parameters 2. Gauging algorithm "
            "related params. Outputs 30 bytes of IT data values."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.DFAccessRowAddress : {
        'type'	: "byte[]",
        'unit'	: {'scale':None,'name':"hex"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        # Requires special processing, not just r/w, as row needs to be added to the command
        'access_per_seal'	: ("-","-","-",),
        'desc'	: ("Read/write DF row with given address. Sets the DF row "
            "with address yy on ManufacturerInfo() for immediate read/write "
            "on ManufacturingInfo()."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.ExitCalibOutputMode : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Exit Calibration Output Mode. Stop output of ADC or CC "
            "data on ManufacturerData() and return to NORMAL data acquisition "
            "mode."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.OutputCCnADC : {
        'type'	: "byte[]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: None,
        # Requires special processing, not just r/w, as it changes the battery mode
        'access_per_seal'	: ("-","-","-",),
        'desc'	: ("Output CC and ADC for Calibration. Lets the device output "
            "the raw values of Coulomb counter, CellVoltagen, TSn, Tint, PACK, "
            "and BAT as block on ManufacturerData() with updates every 250 ms."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.OutputShortCCnADCOffset : {
        'type'	: "byte[]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: None,
        # Requires special processing, not just r/w, as it changes the battery mode
        'access_per_seal'	: ("-","-","-",),
        'desc'	: ("Output Shorted CC AND ADC Offset for Calibration. Lets the "
            "device output the raw CC value on ManufacturerData()."),
    },
}


class SBS_FLAG_BATTERY_MODE(DecoratedEnum):
    """ Flags used in BatteryMode command
    """
    INTERNAL_CHARGE_CONTROLLER	= 0
    PRIMARY_BATTERY_SUPPORT		= 1
    RESERVED2					= 2
    RESERVED3					= 3
    RESERVED4					= 4
    RESERVED5					= 5
    RESERVED6					= 6
    CONDITION_FLAG				= 7
    CHARGE_CONTROLLER_ENABLED	= 8
    PRIMARY_BATTERY				= 9
    RESERVED10					= 10
    RESERVED11					= 11
    RESERVED12					= 12
    ALARM_MODE					= 13
    CHARGER_MODE				= 14
    CAPACITY_MODE				= 15

SBS_BATTERY_MODE_INFO = {
    SBS_FLAG_BATTERY_MODE.INTERNAL_CHARGE_CONTROLLER : {
        # Data type associated with the field
        # For strings, it also contains expected length (which can be exceeeded,
        # as all strings are up to 32 bytes, but this causes a second read)
        'type'	: "named_bitfield",
        # Measurement unit in which data type is stored
        'unit'	: {'scale':1,'name':"boolean"},
        # Amount of bits in this field
        'nbits'	: 1,
        # Names for possible values
        'value_names'	: ["No support","Supported"],
        # Access to the field
        'access'	: "r",
        # Very short name of this field,
        'tiny_name'	: "ICC",
        # Description, with first sentence making a short description,
        'desc'	: ("Internal Charge Controller circuit available. The ICC "
            "accepts power from the battery terminals but may regulate or "
            "otherwise control the current and voltage that actually reaches "
            "the battery’s cells. "
            "When the bit is set, the CHARGE_CONTROLLER_ENABLED bit will be "
            "available for activation and control of the actual internal "
            "charger."),
    },
    SBS_FLAG_BATTERY_MODE.PRIMARY_BATTERY_SUPPORT: {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["No support","Supported"],
        'access'	: "r",
        'tiny_name'	: "PBS",
        'desc'	: ("Ability to act as primary or secondary battery. The "
            "Primary/Secondary battery feature is used with batteries "
            "containing internal discharge control mechanisms to allow "
            "multiple batteries to be connected in parallel. This bit "
            "indicates the presence of this internal control, while the "
            "PRIMARY_BATTERY bit actually controls the on/off state of "
            "this internal control."),
    },
    SBS_FLAG_BATTERY_MODE.RESERVED2: {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'access'	: "-",
        'tiny_name'	: "Rsvd",
        'desc'	: ("Reserved by SBS spec. This field cannot be used unless "
            "future version of SBS specification defines its meaning."),
    },
    SBS_FLAG_BATTERY_MODE.RESERVED3: {
        'type'	: "int_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'access'	: "-",
        'tiny_name'	: "Rsvd",
        'desc'	: ("Reserved by SBS spec. This field cannot be used unless "
            "future version of SBS specification defines its meaning."),
    },
    SBS_FLAG_BATTERY_MODE.RESERVED4: {
        'type'	: "int_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'access'	: "-",
        'tiny_name'	: "Rsvd",
        'desc'	: ("Reserved by SBS spec. This field cannot be used unless "
            "future version of SBS specification defines its meaning."),
    },
    SBS_FLAG_BATTERY_MODE.RESERVED5: {
        'type'	: "int_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'access'	: "-",
        'tiny_name'	: "Rsvd",
        'desc'	: ("Reserved by SBS spec. This field cannot be used unless "
            "future version of SBS specification defines its meaning."),
    },
    SBS_FLAG_BATTERY_MODE.RESERVED6: {
        'type'	: "int_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'access'	: "-",
        'tiny_name'	: "Rsvd",
        'desc'	: ("Reserved by SBS spec. This field cannot be used unless "
            "future version of SBS specification defines its meaning."),
    },
    SBS_FLAG_BATTERY_MODE.CONDITION_FLAG: {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["No need","Requested"],
        'access'	: "r",
        'tiny_name'	: "CF",
        'desc'	: ("Battery requests a conditioning cycle. A conditioning "
            "cycle may be requested because of the characteristics of the "
            "battery chemistry and/or the electronics in combination with "
            "the usage pattern. "
            "This flag is the first signal from the Smart Battery that it "
            "has limited ability to determine the present state-of-charge."),
    },
    SBS_FLAG_BATTERY_MODE.CHARGE_CONTROLLER_ENABLED: {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "rw",
        'tiny_name'	: "CC",
        'desc'	: ("Battery pack's internal charge controller state. When "
            "this bit is cleared, the internal charge controller is disabled. "
            "This bit is active only when the INTERNAL_CHARGE_CONTROLLER bit "
            "is set, indicating that this function is supported."),
    },
    SBS_FLAG_BATTERY_MODE.PRIMARY_BATTERY: {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Secondary","Primary"],
        'access'	: "rw",
        'tiny_name'	: "PB",
        'desc'	: ("Operate as the pri/sec battery in a system. When this bit "
            "is cleared, the battery operates in a secondary role. This bit "
            "is active only when the PRIMARY_BATTERY_SUPPORT bit is set. The "
            "optional Primary/Secondary battery feature is used with batteries "
            "containing internal discharge control mechanisms to allow multiple "
            "batteries to be connected in parallel."),
    },
    SBS_FLAG_BATTERY_MODE.RESERVED10: {
        'type'	: "int_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'access'	: "-",
        'tiny_name'	: "Rsvd",
        'desc'	: ("Reserved by SBS spec. This field cannot be used unless "
            "future version of SBS specification defines its meaning."),
    },
    SBS_FLAG_BATTERY_MODE.RESERVED11: {
        'type'	: "int_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'access'	: "-",
        'tiny_name'	: "Rsvd",
        'desc'	: ("Reserved by SBS spec. This field cannot be used unless "
            "future version of SBS specification defines its meaning."),
    },
    SBS_FLAG_BATTERY_MODE.RESERVED12: {
        'type'	: "int_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'access'	: "-",
        'tiny_name'	: "Rsvd",
        'desc'	: ("Reserved by SBS spec. This field cannot be used unless "
            "future version of SBS specification defines its meaning."),
    },
    SBS_FLAG_BATTERY_MODE.ALARM_MODE: {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Tx enabled","Tx disabled"],
        'access'	: "rw",
        'tiny_name'	: "AM",
        'desc'	: ("Don't master the SMBus and send AlarmWarning(). "
            "When set, the Smart Battery will NOT master the SMBus and "
            "messages will NOT be sent to the SMBus Host and the Smart Battery "
            "Charger. Automatically cleared by the Smart Battery electronics "
            "every 60 seconds."),
    },
    SBS_FLAG_BATTERY_MODE.CHARGER_MODE: {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Tx enabled","Tx disabled"],
        'access'	: "rw",
        'tiny_name'	: "ChgM",
        'desc'	: ("Don't send ChargingCurrent() and ChargingVoltage(). "
            "When set, the Smart Battery will NOT transmit charging values to "
            "the Smart Battery Charger. When cleared, the Battery will transmit "
            "the ChargingCurrent() and ChargingVoltage() values to the Smart "
            "Battery Charger when charging is desired."),
    },
    SBS_FLAG_BATTERY_MODE.CAPACITY_MODE: {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Report in mAh","Report in 10mWh"],
        'access'	: "rw",
        'tiny_name'	: "CapM",
        'desc'	: ("Capacity reporting unit, mA/mAh or 10mW/10mWh. After "
            "changing this bit, all related values (such as AtRate()) should "
            "be re-written while the new mode is active. This bit allows "
            "power management systems to best match their electrical "
            "characteristics with those reported by the battery. For example,"
            " a switching power supply represents a constant power load, "
            "whereas a linear supply is better represented by a constant "
            "current model."),
    },
}


class SBS_FLAG_BATTERY_STATUS(DecoratedEnum):
    """ Flags used in BatteryStatus command
    """
    ERROR_CODE					= 0
    FULLY_DISCHARGED			= 4
    FULLY_CHARGED				= 5
    DISCHARGING					= 6
    INITIALIZED					= 7
    REMAINING_TIME_ALARM		= 8
    REMAINING_CAPACITY_ALARM	= 9
    RESERVED10					= 10
    TERMINATE_DISCHARGE_ALARM	= 11
    OVERTEMPERATURE_ALARM		= 12
    RESERVED13					= 13
    TERMINATE_CHARGE_ALARM		= 14
    OVER_CHARGED_ALARM			= 15

SBS_BATTERY_STATUS_INFO = {
    SBS_FLAG_BATTERY_STATUS.ERROR_CODE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 4,
        'value_names'	: ["OK", "Busy", "Reserved Cmd", "Unsupported Cmd", 
            "Access Denied", "Over/Underflow", "Bad Size", "Unknown Error"],
        'access'	: "r",
        'tiny_name'	: "EC",
        'desc'	: ("Function error code. Error code generated by function "
            "of the last command."),
    },
    SBS_FLAG_BATTERY_STATUS.FULLY_DISCHARGED : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Not fully","Fully"],
        'access'	: "r",
        'tiny_name'	: "FD",
        'desc'	: ("Battery capacity is depleted. Cleared when "
            "RelativeStateOfCharge() value rises above 20% again."),
    },
    SBS_FLAG_BATTERY_STATUS.FULLY_CHARGED : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Not fully","Fully"],
        'access'	: "r",
        'tiny_name'	: "FC",
        'desc'	: ("Battery is full. Set when further charge is not required."),
    },
    SBS_FLAG_BATTERY_STATUS.DISCHARGING : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["No","Yes"],
        'access'	: "r",
        'tiny_name'	: "DSG",
        'desc'	: ("Battery is discharging. This is set by both external "
            "load and self-discharge, so it does not always indicate that "
            "a discharge current is present."),
    },
    SBS_FLAG_BATTERY_STATUS.INITIALIZED : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Correct","Recalibrate"],
        'access'	: "r",
        'tiny_name'	: "INIT",
        'desc'	: ("State of calibration/configuration. Battery electronics "
            "are first calibrated and configured at time of manufacture. This "
            "flag is set when calibration or configuration information has "
            "been lost, and accuracy is significantly impaired."),
    },
    SBS_FLAG_BATTERY_STATUS.REMAINING_TIME_ALARM : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "RTA",
        'desc'	: ("Remaining time to depletion alarm tripped. Set when "
            "value of AverageTimeToEmpty() is less than the value "
            "of RemainingTimeAlarm()."),
    },
    SBS_FLAG_BATTERY_STATUS.REMAINING_CAPACITY_ALARM : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "RCA",
        'desc'	: ("Remaining capacity alarm tripped. Set when "
            "value of RemainingCapacity() is less than the value "
            "of RemainingCapacityAlarm()."),
    },
    SBS_FLAG_BATTERY_STATUS.RESERVED10 : {
        'type'	: "int_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'access'	: "-",
        'tiny_name'	: "ResA",
        'desc'	: ("Purpose undefined."),
    },
    SBS_FLAG_BATTERY_STATUS.TERMINATE_DISCHARGE_ALARM : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "TDA",
        'desc'	: ("Battery capacity is depleted. Stop Discharge As Soon As "
            "Possible."),
    },
    SBS_FLAG_BATTERY_STATUS.OVERTEMPERATURE_ALARM : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "OTA",
        'desc'	: ("Temperature is above pre-set limit."),
    },
    SBS_FLAG_BATTERY_STATUS.RESERVED13 : {
        'type'	: "int_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'access'	: "-",
        'tiny_name'	: "ResD",
        'desc'	: ("Purpose undefined."),
    },
    SBS_FLAG_BATTERY_STATUS.TERMINATE_CHARGE_ALARM : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "TCA",
        'desc'	: ("Charging should be suspended. Stop Charging temporarily. "
            "Charging may be re-started when conditions permit."),
    },
    SBS_FLAG_BATTERY_STATUS.OVER_CHARGED_ALARM : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "OCA",
        'desc'	: ("Battery is fully charged. Stop charging."),
    },
}

class SBS_FLAG_SPECIFICATION_INFO(DecoratedEnum):
    """ Flags used in SpecificationInfo command
    """
    Revision					= 0
    Version						= 4
    VScale						= 8
    IPScale						= 12

SBS_SPECIFICATION_INFO = {
    SBS_FLAG_SPECIFICATION_INFO.Revision : {
        'type'	: "int_bitfield",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 4,
        'access'	: "r",
        'tiny_name'	: "Rev",
        'desc'	: ("Supported SBS revision. Identifies revision of the "
            "Smart Battery Specification document used to design this chip."),
    },
    SBS_FLAG_SPECIFICATION_INFO.Version : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 4,
        'value_names'	: ["v0-none","v1.0","v1.1","v1.1+PEC","vFuture4","vFuture5","vFuture6","vFuture7"],
        'access'	: "r",
        'tiny_name'	: "Ver",
        'desc'	: ("Supported SBS version. Identifies Smart Battery "
            "Specification version used to design this chip."),
    },
    SBS_FLAG_SPECIFICATION_INFO.VScale : {
        'type'	: "int_bitfield",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 4,
        'access'	: "r",
        'tiny_name'	: "VSc",
        'desc'	: ("Voltage scaling exponent. Multiplies voltages "
            "by 10 ^ VScale."),
    },
    SBS_FLAG_SPECIFICATION_INFO.IPScale : {
        'type'	: "int_bitfield",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 4,
        'access'	: "r",
        'tiny_name'	: "IPSc",
        'desc'	: ("Current/capacity scaling exp. Multiplies currents "
            "and capacities by 10 ^ IPScale."),
    },
}


SBS_CMD_INFO = {
    SBS_COMMAND.ManufacturerAccess : {
        # Data type associated with the function
        'type'	: "uint16",
        # Measurement unit in which data type is stored
        'unit'	: {'scale':1,'name':"variable"},
        # Tuple which contains all possible lists of sub-commands
        # The getter algorithm should know which of these lists to use
        # depending on chip model, and possibly other variables
        'subcmd_infos'	: (MANUFACTURER_ACCESS_CMD_BQ_INFO,),
        # Access to the function in BQ seal modes: sealed, unsealed, full access;
        # Access modes are defined this way in TI BQ chips, they're not part of SBS.
        'access_per_seal'	: ("rw","rw","rw",),
        # Description, with first sentence making a short description,
        'desc'	: ("Optional command, is implementation specific. "
            "It may be used by a battery manufacturer or silicon supplier to "
            "return specific version information, internal calibration "
            "information, or some other manufacturer specific function."),
        # Selection of an algorithm to read/write the value of this function
        'getter'	: "manufacturer_access_subcommand",
    },
    SBS_COMMAND.RemainingCapacityAlarm : {
        'type'	: "uint16",
        'unit0'	: {'scale':1,'name':"mAh"},
        'unit1'	: {'scale':10,'name':"mWh"},
        'access_per_seal'	: ("rw","rw","rw",),
        'desc'	: ("Low Capacity alarm threshold value. Whenever the "
            "RemainingCapacity() falls below the Low Capacity value, the "
            "Smart Battery sends AlarmWarning() messages to the SMBus Host "
            "with the REMAINING_CAPACITY_ALARM bit set. A Low Capacity value "
            "of 0 disables this alarm. Unit depends on BatteryMode()'s "
            "CAPACITY_MODE bit."),
        'getter'	: "unit_select_on_capacity_mode",
    },
    SBS_COMMAND.RemainingTimeAlarm : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"minutes"},
        'access_per_seal'	: ("rw","rw","rw",),
        'desc'	: ("Remaining Time alarm value. Whenever the AverageTimeToEmpty() "
            "falls below the Remaining Time value, the Smart Battery sends "
            "AlarmWarning() messages to the SMBus Host with the "
            "REMAINING_TIME_ALARM bit set. A Remaining Time value of 0 "
            "effectively disables this alarm."),
        'getter'	: "simple",
    },
    SBS_COMMAND.BatteryMode : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_BATTERY_MODE_INFO,
        'access_per_seal'	: ("rw","rw","rw",),
        'desc'	: ("Battery modes and capabilities. Selects the various battery "
            "operational modes and reports the battery’s capabilities, modes, "
            "and flags minor conditions requiring attention."),
        'getter'	: "simple",
    },
    SBS_COMMAND.AtRate : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"mA"},
        'access_per_seal'	: ("rw","rw","rw",),
        'desc'	: ("The AtRate value used in calculations. First half of "
            "a two-function call-set used to set the AtRate value used in "
            "calculations made by the AtRateTimeToFull(), AtRateTimeToEmpty(), "
            "and AtRateOK() functions. The AtRate value may be expressed in "
            "either current (mA) or power (10mW) depending on the setting of "
            "the BatteryMode()'s CAPACITY_MODE bit."),
        'getter'	: "simple",
    },
    SBS_COMMAND.AtRateToFull : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"minutes"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Predicted remaining time to fully charge the battery. "
            "Uses the previously written AtRate value."),
        'getter'	: "simple",
    },
    SBS_COMMAND.AtRateToEmpty : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"minutes"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Predicted remaining operating time if the battery is discharged. "
            "Uses the previously written AtRate value."),
        'getter'	: "simple",
    },
    SBS_COMMAND.AtRateOK : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"boolean"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Whether the battery can deliver an additional energy for 10 seconds."
            "Uses the previously written AtRate value for additional energy amount."),
        'getter'	: "simple",
    },
    SBS_COMMAND.Temperature : {
        'type'	: "uint16",
        'unit'	: {'scale':0.1,'name':"K"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Cell-pack's internal temperature. The actual operational "
            "temperature range will be defined at a pack level by a particular "
            "manufacturer. Typically it will be in the range of -20°C to +75°C."),
        'getter'	: "simple",
    },
    SBS_COMMAND.Voltage : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Cell-pack voltage. Provides power management systems with "
            "an accurate battery terminal voltage. Power management systems can "
            "use this voltage, along with battery current information, to "
            "characterize devices they control."),
        'getter'	: "simple",
    },
    SBS_COMMAND.Current : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"mA"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("The current being supplied (or accepted) through terminals. "
            "Provides a snapshot for the power management system of the current "
            "flowing into or out of the battery. This information will be of "
            "particular use in power management systems because they can "
            "characterize individual devices and \"tune\" their operation."),
        'getter'	: "simple",
    },
    SBS_COMMAND.AverageCurrent : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"mA"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("One-minute rolling average on the current flow. "
            "Returns the rolling average based on the current being supplied "
            "(or accepted) through the battery's terminals. This function "
            "is expected to return meaningful values during the battery's "
            "first minute of operation."),
        'getter'	: "simple",
    },
    SBS_COMMAND.MaxError : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"%"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Expected margin of error in charge calculation. "
            "For example, when MaxError() returns 10% and RelativeStateOfCharge() "
            "returns 50%, the Relative StateOfCharge() is actually between 50 "
            "and 60%. The MaxError() of a battery is expected to increase until "
            "the Smart Battery identifies a condition that will give it higher "
            "confidence in its own accuracy, like being fully charged. The Battery "
            "can signal when MaxError() has become too high by setting the "
            "CONDITION_FLAG bit in BatteryMode()."),
        'getter'	: "simple",
    },
    SBS_COMMAND.RelativeStateOfCharge : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"%"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Predicted remaining capacity, percentage of FullChargeCapacity()."
            "Returns the predicted remaining battery capacity expressed as a "
            "percentage of FullChargeCapacity(). This is is used to estimate "
            "the amount of charge remaining in the battery. The problem with "
            "this paradigm is that the tank size is variable."),
        'getter'	: "simple",
    },
    SBS_COMMAND.AbsoluteStateOfCharge : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"%"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Predicted remaining capacity, percentage of DesignCapacity(). "
            "Returns the predicted remaining battery capacity expressed as a "
            "percentage of DesignCapacity(). This can return values greater "
            "than 100%."),
        'getter'	: "simple",
    },
    SBS_COMMAND.RemainingCapacity : {
        'type'	: "uint16",
        'unit0'	: {'scale':1,'name':"mAh"},
        'unit1'	: {'scale':10,'name':"mWh"},
        'access_per_seal'	: ("r","r","rw",),
        'desc'	: ("Predicted remaining battery capacity. The capacity value "
            "is expressed in either current (mAh at a C/5 discharge rate) or "
            "power (10mWh at a P/5 discharge rate) depending on the setting "
            "of the BatteryMode()'s CAPACITY_MODE bit."),
        'getter'	: "unit_select_on_capacity_mode",
    },
    SBS_COMMAND.FullChargeCapacity : {
        'type'	: "uint16",
        'unit0'	: {'scale':1,'name':"mAh"},
        'unit1'	: {'scale':10,'name':"mWh"},
        'access_per_seal'	: ("r","r","rw",),
        'desc'	: ("Predicted pack capacity when it is fully charged. "
            "The value is expressed in either current (mAh at a C/5 discharge "
            "rate) or power (10mWh at a P/5 discharge rate) depending on the "
            "setting of the BatteryMode()'s CAPACITY_MODE bit."),
        'getter'	: "unit_select_on_capacity_mode",
    },
    SBS_COMMAND.RunTimeToEmpty : {
        'type'	: "uint16",
        'unit0'	: {'scale':1,'name':"mAh"},
        'unit1'	: {'scale':10,'name':"mWh"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Remaining battery life at the present rate of discharge. "
            "The value is calculated based on either current or power, "
            "depending on the setting of the BatteryMode()'s CAPACITY_MODE bit. "
            "This is an important distinction because use of the wrong calculation "
            "mode may result in inaccurate return values."),
        'getter'	: "unit_select_on_capacity_mode",
    },
    SBS_COMMAND.AverageTimeToEmpty : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"minutes"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("One-minute rolling average of the remaining battery life. "
            "The AverageTimeToEmpty() value is calculated based on either current "
            "or power depending on the setting of the BatteryMode()'s "
            "CAPACITY_MODE bit."),
        'getter'	: "simple",
    },
    SBS_COMMAND.AverageTimeToFull : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"minutes"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("One minute average of the remaining time until full charge. "
            "This function can be used by the SMBus Host's power management "
            "system to aid in its policy. It may also be used to find out how "
            "long the system must be left on to achieve full charge."),
        'getter'	: "simple",
    },
    SBS_COMMAND.ChargingCurrent : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mA"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("The desired charging rate to the Battery Charger. "
            "This represents the maximum current which may be provided by "
            "the Smart Battery Charger to permit the Battery to reach a "
            "Fully Charged state."),
        'getter'	: "simple",
    },
    SBS_COMMAND.ChargingVoltage : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("The desired charging voltage to the Battery Charger. "
            "This represents the maximum voltage which may be provided by "
            "the Smart Battery Charger to permit the Smart Battery to reach "
            "a Fully Charged state."),
        'getter'	: "simple",
    },
    SBS_COMMAND.BatteryStatus : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_BATTERY_STATUS_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Battery's Alarm and Status bit flags. Some of the "
            "BatteryStatus() flags (REMAINING_CAPACITY_ALARM and "
            "REMAINING_TIME_ALARM) are calculated based on either current "
            "or power depending on the setting of the BatteryMode()'s "
            "CAPACITY_MODE bit."),
        'getter'	: "simple",
    },
    SBS_COMMAND.CycleCount : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"cycles"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Number of cycles the battery has experienced. A cycle "
            "is defined as: An amount of discharge approximately equal "
            "to the value of DesignCapacity."),
        'getter'	: "simple",
    },
    SBS_COMMAND.DesignCapacity : {
        'type'	: "uint16",
        'unit0'	: {'scale':1,'name':"mAh"},
        'unit1'	: {'scale':10,'name':"mWh"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Theoretical capacity of a new pack. The value is expressed "
            "in either current (mAh at a C/5 discharge rate) or power (10mWh "
            "at a P/5 discharge rate) depending on the setting of the "
            "BatteryMode()'s CAPACITY_MODE bit."),
        'getter'	: "unit_select_on_capacity_mode",
    },
    SBS_COMMAND.DesignVoltage : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Theoretical voltage of a new pack. This can be used to "
            "give additional information about a particular Smart Battery's "
            "expected terminal voltage."),
        'getter'	: "simple",
    },
    SBS_COMMAND.SpecificationInfo : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_SPECIFICATION_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("SBS spec version, plus scaling for measures. "
            "Returns the version number of the Smart Battery specification "
            "the battery pack supports, as well as voltage and current and "
            "capacity scaling information in a packed unsigned integer. "
            "Power scaling is the product of the voltage scaling times the "
            "current scaling."),
        'getter'	: "simple",
    },
    SBS_COMMAND.ManufactureDate : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"date547"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("The date the cell pack was manufactured. This provides "
            "the system with information that can be used to uniquely "
            "identify a particular battery."),
        'getter'	: "simple",
    },
    SBS_COMMAND.SerialNumber : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':""},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Serial number of the battery. This function is used to "
            "identify a particular battery."),
        'getter'	: "simple",
    },
    SBS_COMMAND.ManufacturerName : {
        'type'	: "string[8]", # expected length, max is 32
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("The battery's manufacturer's name. "
            "The name can be displayed by the SMBus Host's power "
            "management system display as both an identifier and as an "
            "advertisement for the manufacturer."),
        'getter'	: "simple",
    },
    SBS_COMMAND.DeviceName : {
        'type'	: "string[12]",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Character string that contains the battery's name. This "
            "returns the battery's name for display by the SMBus Host's power "
            "management system as well as for identification purposes."),
        'getter'	: "simple",
    },
    SBS_COMMAND.DeviceChemistry : {
        'type'	: "string[4]",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Character string that contains the battery's chemistry. "
            "This function gives cell chemistry information for use by "
            "charging systems."),
        'getter'	: "simple",
    },
    SBS_COMMAND.ManufacturerData : {
        'type'	: "byte[]",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Manufacturer data contained in the battery. This may "
            "be used to access the manufacturer's data area. The information "
            "and its format are proprietary, but might include items such as: "
            "lot codes, number of deep cycles, discharge patterns, deepest "
            "discharge, etc."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.ManufacturerInput : {
        'type'	: "byte[]",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("rw","rw","rw",),
        'desc'	: ("Either Authentication or ManufacturerInfo, depending on use."),
        'getter'	: "TODO",
    },
    SBS_COMMAND_BQ30.Cell3Voltage : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"mV"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Voltage on the fourth (#3) cell of the battery."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.Cell2Voltage : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"mV"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Voltage on third cell (#2) of the battery."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.Cell1Voltage : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"mV"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Voltage on second cell (#1) of the battery."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.Cell0Voltage : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"mV"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Voltage on first cell (#0) of the battery."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.SafetyAlert : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_SAFETY_ALERT_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Safety Alert bits. In sealed mode, use "
            "ManufacturerAccess() instead."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.SafetyStatus : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_SAFETY_STATUS_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Safety Status bits. In sealed mode, use "
            "ManufacturerAccess() instead."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.PFAlert : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_PF_ALERT_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Permanent Failure Alert bits. In sealed mode, use "
            "ManufacturerAccess() instead."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.PFStatus : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_PF_STATUS_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Permanent Failure Status bits. In sealed mode, use "
            "ManufacturerAccess() instead."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.OperationStatus : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_OPERATION_STATUS_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Operational Status bits. In sealed mode, use "
            "ManufacturerAccess() instead."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.ChargingStatus : {
        'type'	: "uint24_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_CHARGING_STATUS_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Charging Status bits. In sealed mode, use "
            "ManufacturerAccess() instead."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.GaugingStatus : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_GAUGING_STATUS_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Gauging Status bits. In sealed mode, use "
            "ManufacturerAccess() instead."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.ManufacturingStatus : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_MANUFACTURING_STATUS_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Manufacturing Status bits. In sealed mode, use "
            "ManufacturerAccess() instead."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.AFERegisters : {
        'type'	: "byte[]",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: {},
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("AFE register values from ManufacturerData(). "
            "In sealed mode, use ManufacturerAccess() instead."),
        'getter'	: "TODO",
    },
    SBS_COMMAND_BQ_TURBO.TURBO_POWER : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"cW"},
        'access_per_seal'	: ("r","r","rw",),
        'desc'	: ("Max Peak Power for the battery pack config. Computes "
            "and provides Max Power information based on the battery pack "
            "configuration. The device predicts the maximum power pulse "
            "the system can deliver for approximately 10 ms. Value is "
            "negative."),
        'getter'	: "TODO",
    },
    SBS_COMMAND_BQ_TURBO.TURBO_FINAL : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"cW"},
        'access_per_seal'	: ("r","rw","rw",),
        'desc'	: ("Minimal TURBO-mode power level during active operation. "
            "DF.Min Turbo Power represents minimal TURBO-mode power level "
            "during active operation (e.g., non-SLEEP) after all higher "
            "TURBO-mode levels are disabled (expected at the end of discharge). "
            "Negative value is expected."),
        'getter'	: "TODO",
    },
    SBS_COMMAND_BQ_TURBO.TURBO_PACK_R : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mOhm"},
        'access_per_seal'	: ("r","rw","rw",),
        'desc'	: ("Battery pack serial resistance. The serial resistance "
            "includes FETs, traces, sense resistors, etc. This is the "
            "actual data flash value DF.Pack Resistance."),
        'getter'	: "TODO",
    },
    SBS_COMMAND_BQ_TURBO.TURBO_SYS_R : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mOhm"},
        'access_per_seal'	: ("r","rw","rw",),
        'desc'	: ("System serial resistance. Resistance along the path from "
            "battery to system power converter input that includes FETs, "
            "traces, sense resistors, etc. This is the actual data flash "
            "value DF.Pack Resistance."),
        'getter'	: "TODO",
    },
    SBS_COMMAND_BQ_TURBO.MIN_SYS_V : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'access_per_seal'	: ("r","rw","rw",),
        'desc'	: ("Minimal system power converter operational voltage. "
            "Minimal Voltage at system power converter input at which the "
            "system will still operate. This is initialized to the data "
            "flash value of DF.Terminate Voltage."),
        'getter'	: "TODO",
    },
    SBS_COMMAND_BQ_TURBO.TURBO_CURRENT : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mA"},
        'access_per_seal'	: ("r","r","rw",),
        'desc'	: ("Max supported pulse current. The gauge computes "
            "a maximal discharge current supported by the cell "
            "for a 10 ms pulse. Value is updated every 1 sec."),
        'getter'	: "TODO",
    },
    SBS_COMMAND_BQ30.LifetimeDataBlock1 : {
        'type'	: "byte[]",
        'unit'	: {'scale':1,'name':"variable"},
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Lifetime data values, block 1. The values from "
            "ManufacturerData()."),
        'getter'	: "TODO",
    },
    SBS_COMMAND_BQ30.LifetimeDataBlock2 : {
        'type'	: "byte[]",
        'unit'	: {'scale':1,'name':"variable"},
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Lifetime data values, block 2. The values from "
            "ManufacturerData()."),
        'getter'	: "TODO",
    },
    SBS_COMMAND_BQ30.LifetimeDataBlock3 : {
        'type'	: "byte[]",
        'unit'	: {'scale':1,'name':"variable"},
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Lifetime data values, block 3. The values from "
            "ManufacturerData()."),
        'getter'	: "TODO",
    },
    SBS_COMMAND_BQ30.ManufacturerInfo : {
        'type'	: "byte[]",
        'unit'	: {'scale':1,'name':"variable"},
        'access_per_seal'	: ("r","rw","rw",),
        'desc'	: ("Manufacturer Info values. The values from "
            "ManufacturerData()."),
        'getter'	: "TODO",
    },
    SBS_COMMAND_BQ30.Voltages : {
        'type'	: "byte[]",
        'unit'	: {'scale':1,'name':"mV"},
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Voltage data values. The values from ManufacturerData()."),
        'getter'	: "TODO",
    },
    SBS_COMMAND_BQ30.Temperatures : {
        'type'	: "byte[]",
        'unit'	: {'scale':0.1,'name':"K"},
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("IT data values. The values from ManufacturerData()."),
        'getter'	: "TODO",
    },
    SBS_COMMAND_BQ30.ITStatus1 : {
        'type'	: "byte[30]",
        'unit'	: {'scale':1,'name':"variable"},
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("IT data values, block 1. The values from ManufacturerData()."),
        'getter'	: "TODO",
    },
    SBS_COMMAND_BQ30.ITStatus2 : {
        'type'	: "byte[30]",
        'unit'	: {'scale':1,'name':"variable"},
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("IT data values, block 2. The values from ManufacturerData()."),
        'getter'	: "TODO",
    },

}


class MONITOR_GROUP(DecoratedEnum):
    """ List of groups of commands/offsets.
    """
    DeviceInfo	= 0x00
    UsageInfo	= 0x01
    ComputedInfo= 0x02
    StatusBits	= 0x03
    AtRates		= 0x04
    Group1		= 0x05
    BQStatusBits	= 0x06
    BQStatusBitsMA	= 0x07
    BQCellVoltages	= 0x08
    BQTurboMode	= 0x0f


SBS_CMD_GROUPS = {
    MONITOR_GROUP.DeviceInfo : (
        SBS_COMMAND.ManufactureDate,
        SBS_COMMAND.SerialNumber,
        SBS_COMMAND.ManufacturerName,
        SBS_COMMAND.DeviceName,
        SBS_COMMAND.DeviceChemistry,
        SBS_COMMAND.DesignCapacity,
        SBS_COMMAND.DesignVoltage,
        SBS_COMMAND.RemainingCapacityAlarm,
        SBS_COMMAND.RemainingTimeAlarm,
        SBS_COMMAND.SpecificationInfo,
    ),
    MONITOR_GROUP.UsageInfo : (
        SBS_COMMAND.Temperature,
        SBS_COMMAND.Voltage,
        SBS_COMMAND.Current,
        SBS_COMMAND.AverageCurrent,
        SBS_COMMAND.RemainingCapacity,
        SBS_COMMAND.FullChargeCapacity,
        SBS_COMMAND.MaxError,
        SBS_COMMAND.CycleCount,
    ),
    MONITOR_GROUP.ComputedInfo : (
        SBS_COMMAND.RelativeStateOfCharge,
        SBS_COMMAND.AbsoluteStateOfCharge,
        SBS_COMMAND.RunTimeToEmpty,
        SBS_COMMAND.AverageTimeToEmpty,
        SBS_COMMAND.AverageTimeToFull,
        SBS_COMMAND.ChargingCurrent,
        SBS_COMMAND.ChargingVoltage,
    ),
    MONITOR_GROUP.StatusBits : (
        SBS_COMMAND.BatteryMode,
        SBS_COMMAND.BatteryStatus,
    ),
    MONITOR_GROUP.BQStatusBits : (
        SBS_COMMAND_BQ30.SafetyAlert,
        SBS_COMMAND_BQ30.SafetyStatus,
        SBS_COMMAND_BQ30.PFAlert,
        SBS_COMMAND_BQ30.PFStatus,
        SBS_COMMAND_BQ30.OperationStatus,
        SBS_COMMAND_BQ30.ChargingStatus,
        SBS_COMMAND_BQ30.GaugingStatus,
        SBS_COMMAND_BQ30.ManufacturingStatus,
    ),
    MONITOR_GROUP.BQStatusBitsMA : (
        MANUFACTURER_ACCESS_CMD_BQ30.SafetyAlert,
        MANUFACTURER_ACCESS_CMD_BQ30.SafetyStatus,
        MANUFACTURER_ACCESS_CMD_BQ30.PFAlert,
        MANUFACTURER_ACCESS_CMD_BQ30.PFStatus,
        MANUFACTURER_ACCESS_CMD_BQ30.OperationStatus,
        MANUFACTURER_ACCESS_CMD_BQ30.ChargingStatus,
        MANUFACTURER_ACCESS_CMD_BQ30.GaugingStatus,
        MANUFACTURER_ACCESS_CMD_BQ30.ManufacturingStatus,
    ),
    MONITOR_GROUP.Group1 : (
        SBS_COMMAND_BQ30.AFERegisters,
        SBS_COMMAND_BQ30.LifetimeDataBlock1,
        SBS_COMMAND_BQ30.LifetimeDataBlock2,
        SBS_COMMAND_BQ30.LifetimeDataBlock3,
        SBS_COMMAND_BQ30.ManufacturerInfo,
        SBS_COMMAND_BQ30.Voltages,
        SBS_COMMAND_BQ30.Temperatures,
        SBS_COMMAND_BQ30.ITStatus1,
        SBS_COMMAND_BQ30.ITStatus2,
    ),
    MONITOR_GROUP.BQCellVoltages : (
        SBS_COMMAND_BQ30.Cell0Voltage,
        SBS_COMMAND_BQ30.Cell1Voltage,
        SBS_COMMAND_BQ30.Cell2Voltage,
        SBS_COMMAND_BQ30.Cell3Voltage,
    ),
    MONITOR_GROUP.BQTurboMode : (
        SBS_COMMAND_BQ_TURBO.TURBO_POWER,
        SBS_COMMAND_BQ_TURBO.TURBO_FINAL,
        SBS_COMMAND_BQ_TURBO.TURBO_PACK_R,
        SBS_COMMAND_BQ_TURBO.TURBO_SYS_R,
        SBS_COMMAND_BQ_TURBO.MIN_SYS_V,
        SBS_COMMAND_BQ_TURBO.TURBO_CURRENT,
    ),
    MONITOR_GROUP.AtRates : (
        SBS_COMMAND.AtRate,
        SBS_COMMAND.AtRateToFull,
        SBS_COMMAND.AtRateToEmpty,
        SBS_COMMAND.AtRateOK,
    ),
}


class SMBusMock(object):
    def __init__(self, bus=None, force=False):
        self.address = None
        self.bus = bus
        self.force = force

    def open(self, bus):
        self.bus = bus

    def close(self):
        pass

    def write_quick(self, i2c_addr, force=None):
        pass

    def read_byte(self, i2c_addr, force=None):
        return 1

    def write_byte(self, i2c_addr, value, force=None):
        pass

    def read_byte_data(self, i2c_addr, register, force=None):
        return 1

    def write_byte_data(self, i2c_addr, register, value, force=None):
        pass

    def read_word_data(self, i2c_addr, register, force=None):
        return 0x101

    def write_word_data(self, i2c_addr, register, value, force=None):
        pass

    def process_call(self, i2c_addr, register, value, force=None):
        pass

    def read_block_data(self, i2c_addr, register, force=None):
        return [1] * 32

    def write_block_data(self, i2c_addr, register, data, force=None):
        pass

    def read_i2c_block_data(self, i2c_addr, register, length, force=None):
        return [1] * length

    def write_i2c_block_data(self, i2c_addr, register, data, force=None):
        pass


def crc8_ccitt_byte(crc, dt):
    """ Add one byte to smbus PEC crc-8 calculation
    """
    ncrc = crc ^ dt;
    for i in range(8):
        if ( ncrc & 0x80 ) != 0:
            ncrc <<= 1
            ncrc ^= 0x07
        else:
            ncrc <<= 1
    return ncrc & 0xff

def crc8_ccitt_compute(data):
    crc = 0
    for dt in data:
        crc = crc8_ccitt_byte(crc, dt)
    return crc


def is_ti_bq_chip(chip):
    return chip.name.startswith("BQ")


def type_str_value_length(type_str):
    m = re.match(r'[a-z]+\[([0-9]+)\]', type_str)
    if m:
        return int(m.group(1))
    elif type_str in ("int8","uint8",):
        return 1
    elif type_str in ("int16","uint16","int16_blk","uint16_blk",):
        return 2
    elif type_str in ("uint24","uint24_blk",):
        return 3
    elif type_str in ("int32","uint32","int32_blk","uint32_blk",):
        return 4
    elif type_str in ("float","float_blk",):
        return 4
    return 32


def bytes_to_type_str(b, type_str, endian="le"):
    if endian == "be":
        endian = '>'
    else:
        endian = '<'
    if type_str in ("int8",):
        (v,) = struct.unpack(endian+'b', bytearray(b)[0:1])
    elif type_str in ("uint8",):
        (v,) = struct.unpack(endian+'B', bytearray(b)[0:1])
    elif type_str in ("int16","int16_blk",):
        (v,) = struct.unpack(endian+'h', bytearray(b)[0:2])
    elif type_str in ("uint16","uint16_blk",):
        (v,) = struct.unpack(endian+'H', bytearray(b)[0:2])
    elif type_str in ("uint24","uint24_blk",):
        (v,) = struct.unpack(endian+'L', bytearray(b)[0:3]+bytes([0]))
    elif type_str in ("int32","int32_blk",):
        (v,) = struct.unpack(endian+'l', bytearray(b)[0:4])
    elif type_str in ("uint32","uint32_blk",):
        (v,) = struct.unpack(endian+'L', bytearray(b)[0:4])
    elif type_str in ("float","float_blk",):
        (v,) = struct.unpack(endian+'f', bytearray(b)[0:4])
    else:
        v = b
    return v


def type_str_to_bytes(v, type_str, endian="le"):
    if endian == "be":
        endian = '>'
    else:
        endian = '<'
    if type_str in ("int8",):
        b = struct.pack(endian+'b', v)
    elif type_str in ("uint8",):
        b = struct.pack(endian+'B', v)
    elif type_str in ("int16","int16_blk",):
        b = struct.pack(endian+'h', v)
    elif type_str in ("uint16","uint16_blk",):
        b = struct.pack(endian+'H', v)
    elif type_str in ("uint24","uint24_blk",):
        b = struct.pack(endian+'L', v)
    elif type_str in ("int32","int32_blk",):
        b = struct.pack(endian+'l', v)
    elif type_str in ("uint32","uint32_blk",):
        b = struct.pack(endian+'L', v)
    elif type_str in ("float","float_blk",):
        b = struct.pack(endian+'f', v)
    else:
        b = bytes(v)
    return b


def smbus_recreate_read_packet_data(dev_addr, cmd, resp_data):
  """ Re-creates read command packet with response

  The data is useful for PEC calculation.
  """
  data = bytes([(dev_addr << 1) + 0, cmd.value, (dev_addr << 1) + 1]) + bytes(resp_data)
  return data


def smbus_recreate_write_packet_data(dev_addr, cmd, req_data):
  """ Re-creates read command packet with response

  The data is useful for PEC calculation.
  """
  data = bytes([(dev_addr << 1) + 0, cmd.value]) + bytes(req_data)
  return data


def smbus_open(bus_str, po):
    """ Opens the System Managememnt Bus over I2C interface

    The current implementation is for Rapsberry Pi.
    """
    global bus
    m = re.match(r'smbus:([0-9]+)', bus_str)
    if m:
        bus_index = int(m.group(1),0)
        if po.dry_run:
            bus = SMBusMock(bus_index)
            return
        import smbus2
        bus = smbus2.SMBus(bus_index)
        bus.pec = True
        return
    raise ValueError("Unrecognized bus definition")


def smbus_close():
    """ Closes the System Managememnt Bus over I2C interface
    """
    global bus
    bus.close()
    bus = None


def smbus_read_word(bus, dev_addr, cmd, resp_type, po):
    """ Read 16-bit integer from SMBus command, using READ_WORD protocol.
    """
    v = bus.read_word_data(dev_addr, cmd.value)
    if (po.verbose > 2):
        print("Raw {} response: 0x{:x}".format(cmd.name, v))
    if v < 0 or v > 65535:
        raise ValueError("Received value of command {} is beyond type {} bounds".format(cmd.name,resp_type))
    if resp_type in ("int16",): # signed type support
        if v > 32767:
            v -= 65536
    return v


def smbus_read_long(bus, dev_addr, cmd, resp_type, po):
    """ Read 32-bit integer from SMBus command, reading just 4 bytes.
    """
    b = bus.read_i2c_block_data(dev_addr, cmd.value, 4)
    if (po.verbose > 2):
        print("Raw {} response: {}".format(cmd.name, " ".join('{:02x}'.format(x) for x in b)))
    return bytes_to_type_str(b, resp_type)


def smbus_read_block_for_basecmd(bus, dev_addr, cmd, basecmd_name, resp_type, po):
    """ Read block from cmd, use basecmd_name for logging

    Needed because request cmd isn't always clearly identifying what we're reading.
    """
    expect_len = min(type_str_value_length(resp_type) + 2, 32) # +1 length, +1 PEC
    # Try reading expected length first
    b = bus.read_i2c_block_data(dev_addr, cmd.value, expect_len)
    # block starts with 1-byte lenght
    # check if we meet the expected length restriction
    if (len(b) < 1):
        raise ValueError("Received {} from command {} is too short to even have length".format(resp_type,basecmd_name))
    if (b[0] < 32) and (len(b) < b[0]+2):
        # expected lngth exceeded - read the whole thing
        b = bus.read_i2c_block_data(dev_addr, cmd.value, 32)
    if (po.verbose > 2):
        print("Raw {} response: {}".format(basecmd_name, " ".join('{:02x}'.format(x) for x in b)))
    if b[0] == 32 and len(b) == 32:
        # We've lost last byte; but there is no other way - accept the truncated message
        # Otherwise communicating 32-bit messages would just not work
        if (po.verbose > 2):
            print("Response last byte was truncated because of I2C constrains; adding zero")
        b += b'\0'
    if len(b) < b[0] + 1:
        raise ValueError("Received {} from command {} has invalid length".format(resp_type,basecmd_name))
    # check PEC crc-8 byte (unless the packet was so long that we didn't receive it)
    if b[0] < 31:
        whole_packet = smbus_recreate_read_packet_data(dev_addr, cmd, b[0:b[0]+1])
        pec = crc8_ccitt_compute(whole_packet)
        if b[b[0]+1] != pec:
            raise ValueError("Received {} from command {} with wrong PEC checksum".format(resp_type,basecmd_name))
    # prepare data part of the string
    v = bytes(b[1:b[0]+1])
    return v


def smbus_read_block(bus, dev_addr, cmd, resp_type, po):
    """ Read block from cmd
    """
    return smbus_read_block_for_basecmd(bus, dev_addr, cmd, cmd.name, resp_type, po)


def smbus_read_word_blk(bus, dev_addr, cmd, resp_type, po):
    """ Read 16-bit integer from SMBus command, using READ_BLOCK protocol.
    """
    b = smbus_read_block_for_basecmd(bus, dev_addr, cmd, cmd.name, resp_type, po)
    return bytes_to_type_str(b, resp_type)


def smbus_read_long_blk(bus, dev_addr, cmd, resp_type, po):
    """ Read 32-bit integer from SMBus command, using READ_BLOCK protocol.
    """
    b = smbus_read_block_for_basecmd(bus, dev_addr, cmd, cmd.name, resp_type, po)
    return bytes_to_type_str(b, resp_type)


def smbus_write_word(bus, dev_addr, cmd, v, val_type, po):
    if val_type in ("int16",): # signed type support
        if v < 0:
            v += 65536
    if v < 0 or v > 65535:
        raise ValueError("Value to write for command {} is beyond type {} bounds".format(cmd.name,val_type))
    if (po.verbose > 2):
        print("Write {}: {:02x} WORD=0x{:x}".format(cmd.name, cmd.value, v))
    bus.write_word_data(dev_addr, cmd.value, v)


def smbus_write_block_for_basecmd(bus, dev_addr, cmd, v, basecmd_name, val_type, po):
    """ Write block to cmd, use basecmd_name for logging
    """
    b = v
    if (po.verbose > 2):
        print("Write {}: {:02x} BLOCK={}".format(basecmd_name, cmd.value, " ".join('{:02x}'.format(x) for x in b)))
    bus.write_block_data(dev_addr, cmd.value, b)


def smbus_write_block(bus, dev_addr, cmd, v, val_type, po):
    """ Write block to cmd
    """
    smbus_write_block_for_basecmd(bus, dev_addr, cmd, v, cmd.name, val_type, po)


def smbus_write_word_blk(bus, dev_addr, cmd, v, val_type, po):
    b = type_str_to_bytes(v, val_type)
    smbus_write_block_for_basecmd(bus, dev_addr, cmd, b, cmd.name, val_type, po)


def smbus_write_long_blk(bus, dev_addr, cmd, v, val_type, po):
    b = type_str_to_bytes(v, val_type)
    smbus_write_block_for_basecmd(bus, dev_addr, cmd, b, cmd.name, val_type, po)


def smbus_read_manufacturer_access_block_bq(bus, dev_addr, cmd, subcmd, resp_type, resp_cmd, resp_wait, po):
    """ Reads value from ManufacturerAccess sub-command of the battery.

    Returns bytes array received in response, without converting the type.
    """
    # write sub-command to ManufacturerAccess
    bus.write_word_data(dev_addr, cmd.value, subcmd.value)
    # Check if sleep needed inbetween requests
    if resp_wait > 0:
        time.sleep(resp_wait)
    # This function should never be called for void type; if it was, error out
    if resp_type == "void":
        raise TypeError("Reading should not be called for a void response type")
    basecmd_name = "{}.{}".format(cmd.name,subcmd.name)
    v = smbus_read_block_for_basecmd(bus, dev_addr, resp_cmd, basecmd_name, resp_type, po)
    return v


def smbus_write_manufacturer_access_block_bq(bus, dev_addr, cmd, subcmd, v, resp_type, resp_cmd, resp_wait, po):
    """ Write value to ManufacturerAccess sub-command of the battery.

    Expects value to already be bytes array ready for sending.
    """
    # write sub-command to ManufacturerAccess
    bus.write_word_data(dev_addr, cmd.value, subcmd.value)
    # Check if sleep needed inbetween requests
    if resp_wait > 0:
        time.sleep(resp_wait)
    # If the type to store is void, meaning we're writing to trigger switch - that's all
    if resp_type == "void":
        return
    basecmd_name = "{}.{}".format(cmd.name,subcmd.name)
    smbus_write_block_for_basecmd(bus, dev_addr, resp_cmd, v, basecmd_name, resp_type, po)


def smbus_perform_unseal_bq30(bus, dev_addr, cmd, subcmd, resp_type, resp_cmd, resp_wait, sec_key_hex, po):
    """ Execute Unseal or Full Access operation on BQ30 chip.
    """
    basecmd_name = "{}.{}".format(cmd.name,subcmd.name)
    if resp_type == "void":
        # Command with no params - which is sealing
        smbus_write_manufacturer_access_block_bq(bus, dev_addr, cmd, subcmd, b'', resp_type, resp_cmd, resp_wait, po)
        return
    if False: # TODO use for dry run
        KD = bytes.fromhex("00000000 00000000 00000000 00000000")
    KD = bytes.fromhex(sec_key_hex)
    if len(KD) != 16:
        raise ValueError("Algorithm broken, length of unseal key KD is {} instead of {} bytes".format(len(KD),16))
    # write UnSealDevice/FullAccessDevice sub-command to ManufacturerAccess, then read 160-bit message M
    if False: # TODO use for dry run
        M = bytes.fromhex("C82CA3CA 10DEC726 8E070A7C F0D1FE82 20AAD3B8") # on zeroed key
        # For above case, HMAC2=fb8a342458e0b136988cb5203bb23f94dfd4440e
        M = bytes.fromhex("12b59558 b6d20605 121149b1 16af564a ae19a256") # on default key
        # For above case, HMAC2=fca9642f6846e01f219c6ed7160b2f15cddeb1bc
    M = smbus_read_manufacturer_access_block_bq(bus, dev_addr, cmd, subcmd, resp_type, resp_cmd, resp_wait, po)
    M = bytes(reversed(M))
    if len(M) != 20:
        raise ValueError("Algorithm broken, length of challenge message M is {} instead of {} bytes".format(len(M),20))
    # Generate SHA-1 input block B1 of 512 bytes (total input =128-bit unseal/full access key KD
    # + 160 bit message M + 1 + 159 0s + 100100000)
    B1 = KD + M # the rest will be added automatically to the message, as hashlib honors FIPS 180-2
    if (po.verbose > 2):
        print("Prepared {} B1={}".format(basecmd_name, B1.hex()))
    if len(B1) != 288//8:
        raise ValueError("Algorithm broken, length of input block B1 is {} instead of {} bits".format(len(B1)*8,288))
    # Generate SHA-1 hash HMAC1 using B1
    HMAC1 = hashlib.sha1(B1).digest()
    if (po.verbose > 2):
        print("Computed {} HMAC1={}".format(basecmd_name,HMAC1.hex()))
    # Generate SHA-1 input block B2 of 512 bytes (total input =128-bit unseal/full access key KD
    # + 160 bit hash HMAC1 + 1 + 159 0s + 100100000)
    B2 = KD + HMAC1 # the rest is added automatically in accordance to FIPS 180-2
    # Generate SHA-1 hash HMAC2 using B2
    HMAC2 = hashlib.sha1(B2).digest()
    if (po.verbose > 2):
        print("Computed {} HMAC2={}".format(basecmd_name,HMAC2.hex()))
    # Write 160-bit hash HMAC2 to ManufacturerInput() in the format
    # 0xAABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTT, where AA is LSB
    HMAC2 = bytes(reversed(HMAC2))
    if False: # re-creation of the whole packet, for debug
        whole_packet = smbus_recreate_write_packet_data(dev_addr, resp_cmd, bytes([len(HMAC2)]) + HMAC2)
        pec = crc8_ccitt_compute(whole_packet)
        print("WHOLE:", " ".join('{:02x}'.format(x) for x in whole_packet), '{:02x}'.format(pec))
    smbus_write_block_for_basecmd(bus, dev_addr, resp_cmd, HMAC2, basecmd_name, resp_type, po)
    # Device compares hash HMAC2 with internal calculated hash HMAC3. If it matches, device
    # allows UNSEALED/FULL ACCESS mode indicated with the OperationStatus()[SEC1],[SEC0] flags.
    return

def smbus_read_manufacturer_access_block_value_bq(bus, dev_addr, cmd, subcmd, resp_type, resp_cmd, resp_wait, po):
    """ Reads value of ManufacturerAccess sub-command from the battery.

    Converts the received bytes to properly typed value, based on resp_type.
    Handles retries, if neccessary.
    """
    basecmd_name = "{}.{}".format(cmd.name,subcmd.name)
    if (po.verbose > 2):
        print("Query {}: {:02x} WORD=0x{:x}".format(basecmd_name, cmd.value, subcmd.value))

    b = None
    for nretry in reversed(range(3)):
        try:
            b = smbus_read_manufacturer_access_block_bq(bus, dev_addr, cmd, subcmd, resp_type, resp_cmd, resp_wait, po)
        except Exception as ex:
            if (nretry > 0) and (
              (isinstance(ex, OSError) and ex.errno in (5,121,))
              # 5 = Input/output error, sometimes just happens
              # 121 = I/O error, usually means no ACK
              ):
                if (po.verbose > 2):
                    print("Retrying due to error: "+str(ex))
                pass
            else:
                raise
        if b is None:
            time.sleep(0.25)
            continue
        break

    v = bytes_to_type_str(b, resp_type, "le")

    return v


def smbus_write_manufacturer_access_block_value_bq(bus, dev_addr, cmd, subcmd, v, stor_type, stor_cmd, stor_wait, po):
    """ Writes value to ManufacturerAccess sub-command of the battery.

    Converts the value v to proper bytes array for write, based on stor_type.
    Handles retries, if neccessary.
    """
    basecmd_name = "{}.{}".format(cmd.name,subcmd.name)
    if (po.verbose > 2):
        print("Store {}: {:02x} WORD=0x{:x}".format(basecmd_name, cmd.value, subcmd.value))

    b = type_str_to_bytes(v, stor_type, "le")

    for nretry in reversed(range(1)):
        try:
            smbus_write_manufacturer_access_block_bq(bus, dev_addr, cmd, subcmd, b, stor_type, stor_cmd, stor_wait, po)
        except Exception as ex:
            if (nretry > 0) and (
              (isinstance(ex, OSError) and ex.errno in (5,121,))
              # 5 = Input/output error, sometimes just happens
              # 121 = I/O error, usually means no ACK
              ):
                if (po.verbose > 2):
                    print("Retrying due to error: "+str(ex))
                pass
            else:
                raise
        if b is None:
            time.sleep(0.25)
            continue
        break

    return


def smbus_read_simple(bus, dev_addr, cmd, resp_type, resp_unit, retry_count, po):
    """ Reads value of simple command from the battery.
    """
    v = None
    for nretry in reversed(range(retry_count)):
        try:
            if resp_type in ("int16","uint16",):
                v = smbus_read_word(bus, dev_addr, cmd, resp_type, po)

            elif resp_type in ("int16_blk","uint16_blk",):
                v = smbus_read_word_blk(bus, dev_addr, cmd, resp_type, po)

            elif resp_type in ("int32","uint32",):
                v = smbus_read_long(bus, dev_addr, cmd, resp_type, po)

            elif resp_type in ("int24_blk","uint24_blk","int32_blk","uint32_blk",):
                v = smbus_read_long_blk(bus, dev_addr, cmd, resp_type, po)

            elif resp_type.startswith("string["):
                v = smbus_read_block(bus, dev_addr, cmd, resp_type, po)

            elif resp_type.startswith("byte["):
                v = smbus_read_block(bus, dev_addr, cmd, resp_type, po)

            else:
                raise ValueError("Command {} type {} not supported".format(cmd.name,resp_type))
        except Exception as ex:
            if (nretry > 0) and (
              (isinstance(ex, OSError) and ex.errno in (5,121,)) or
              # 5 = Input/output error, sometimes just happens
              # 121 = I/O error, usually means no ACK
              (isinstance(ex, ValueError)) # invalid length or checksum
              ):
                if (po.verbose > 2):
                    print("Retrying due to error: "+str(ex))
                pass
            else:
                raise
        if v is None:
            time.sleep(0.25)
            continue
        break

    if resp_unit['scale'] is not None:
        v *= resp_unit['scale']
    return v, resp_unit['name']


def smbus_write_simple(bus, dev_addr, cmd, v, val_type, val_unit, retry_count, po):
    """ Writes value of simple command to the battery.
    """
    if val_unit['scale'] is not None:
        if val_type in ("float","float_blk",):
            v = v / val_unit['scale']
        else:
            v = v // val_unit['scale']

    if val_type in ("int16","uint16",):
        smbus_write_word(bus, dev_addr, cmd, v, val_type, po)

    elif val_type in ("int16_blk","uint16_blk",):
        smbus_write_word_blk(bus, dev_addr, cmd, v, val_type, po)

    elif val_type in ("int32","uint32",):
        smbus_write_long(bus, dev_addr, cmd, v, val_type, po)

    elif val_type in ("int32_blk","uint32_blk",):
        smbus_write_long_blk(bus, dev_addr, cmd, v, val_type, po)

    elif val_type.startswith("string["):
        smbus_write_block(bus, dev_addr, cmd, v, val_type, po)

    elif val_type.startswith("byte["):
        smbus_write_block(bus, dev_addr, cmd, v, val_type, po)

    else:
        raise ValueError("Command {} type {} not supported".format(cmd.name,val_type))

    return


def parse_sbs_command_value(cmd, subcmdinf, v, u, po):
    """ Parse compound values to get list of sub-values
    """
    cmdinf = SBS_CMD_INFO[cmd]
    if (u == "bitfields"):
        vlist = {}
        for fld in sorted(subcmdinf.keys(), key=lambda x:x.value):
            fldinf = subcmdinf[fld]
            # Prepare bit mask
            bit_start = fld.value
            bit_count = fldinf['nbits']
            bit_mask = 0
            for i in range(bit_count):
                bit_mask = (bit_mask << 1) | 1
            bit_mask = bit_mask << bit_start
            fld_val = ((v & bit_mask) >> bit_start)
            fld_unit = fldinf['unit']

            if fld_unit['scale'] is not None:
                fld_val *= fld_unit['scale']
            vlist[fld] = {'val':fld_val,'uname':fld_unit['name'],}
    elif u == "struct":
        fld_start = 0
        vlist = {}
        for fld in sorted(subcmdinf.keys(), key=lambda x:x.value):
            fldinf = subcmdinf[fld]
            fld_buf = []
            try:
                for i in range((fldinf['nbits']+7) // 8):
                    m = (fld_start // 8) + i
                    r = (fld_start % 8)
                    if r == 0:
                        c = v[m]
                    else:
                        c = (v[m] >> r) + (v[m+1] << (8-r)) & 0xff
                    fld_buf.append(c)
            except IndexError as ex:
                # Some structs can have fields at end which exist only in some versions
                if ('optional' in fldinf) and fldinf['optional']:
                    if (po.verbose > 2):
                        print("Optional field {} does not exist".format(fld.name))
                    break
                raise IndexError("Received block too short to contain '{}' field".format(fld.name))
            fld_type = fldinf['type']
            fld_unit = fldinf['unit']

            if fld_type in ("int16","uint16",) and len(fld_buf) < 2:
                if (po.verbose > 2):
                    print("Zero-extending {} field {}".format(fld_type,fld.name))
                fld_buf.extend([0,0])
            elif fld_type in ("int32","uint32",) and len(fld_buf) < 4:
                if (po.verbose > 2):
                    print("Zero-extending {} field {}".format(fld_type,fld.name))
                fld_buf.extend([0,0,0,0])

            if 'endian' in fldinf:
                fld_val = bytes_to_type_str(fld_buf, fld_type, fldinf['endian'])
            else:
                fld_val = bytes_to_type_str(fld_buf, fld_type, "le")

            if fld_unit['scale'] is not None:
                fld_val *= fld_unit['scale']
            vlist[fld] = {'val':fld_val,'uname':fld_unit['name'],}
            fld_start += fldinf['nbits']
    else:
        vlist = None
    return vlist


def is_printable_value_unit(uname):
    return uname not in ("boolean","hex","hexver","dec","dec02","dec04","date547",)


def command_value_to_string(cmdinf, subcmdinf, u, v, po):
    if u in ("bitfields","struct","hex",):
        if isinstance(v, list) or isinstance(v, bytes):
            return "hex:" + "".join('{:02x}'.format(x) for x in v)
        else:
            if 'nbits' in subcmdinf:
                val_len = (subcmdinf['nbits']+3) // 4
            elif 'type' in subcmdinf:
                val_len = 2*type_str_value_length(subcmdinf['type'])
            else:
                val_len = 2*type_str_value_length(cmdinf['type'])
            return "0x{:0{}x}".format(v,val_len)
    if u == "hexver":
        if isinstance(v, list) or isinstance(v, bytes):
            return ".".join('{:02x}'.format(x) for x in v)
        else:
            if 'nbits' in subcmdinf:
                val_len = (subcmdinf['nbits']+3) // 4
            elif 'type' in subcmdinf:
                val_len = 2*type_str_value_length(subcmdinf['type'])
            else:
                val_len = 2*type_str_value_length(cmdinf['type'])
            fmt_val = ""
            while val_len > 0:
                fmt_val += "{:02x}.".format(v & 0xff)
                v <<= 8
                val_len -= 2
            return fmt_val[0:len(fmt_val)-1]
    if u in ("dec02","dec04",):
        return "{:{}d}".format(v,u[u.index('0'):])
    if u == "date547":
        return "{:d}-{:02d}-{:02d}".format(1980 + ((v>>9)&0x7f), (v>>5)&0x0f, (v)&0x1f)
    return "{}".format(v)


def print_sbs_command_subfield_value(fld, lstfld, fields_info, name_width, po):
    fldinf = fields_info[fld]
    fld_short_desc = fldinf['desc'].split('.')[0]
    val = lstfld['val']
    # Do not show fields which have no read access, unless somehow they're non-zero
    if ('r' not in fldinf['access']) and (val == 0):
        return
    # Prepare the unit (or replace it with short name for flags)
    if (not is_printable_value_unit(lstfld['uname'])) and ('tiny_name' in fldinf):
        fld_uname = "[{}]".format(fldinf['tiny_name'])
    else:
        fld_uname = lstfld['uname']
    # Prepare the value for formatting
    fmt_val = command_value_to_string({'type':"byte[1]"}, fldinf, lstfld['uname'], val, po)
    if fldinf['type'] == "named_bitfield":
        fmt_val = "{}={}".format(fmt_val, fldinf['value_names'][val])

    print(" {:>{}s}:\t{}\t{}\t{}".format(fld.name, name_width, fmt_val, fld_uname, fld_short_desc))
    if (po.explain):
        print("Description: {}".format(fldinf['desc']))
    return


def group_fields_by_bits(enum_list, bits_group, bits_limit, po):
    field_groups = []
    all_bits = [x.value for x in enum_list]
    for nbyte in range((bits_limit+bits_group-1)//bits_group):
        fields_in_byte = []
        for nbit in range(bits_group):
            if bits_group*nbyte+nbit in all_bits:
                for fld in (x for x in enum_list if x.value == bits_group*nbyte+nbit):
                    fields_in_byte.append(fld)
        if len(fields_in_byte) > 0:
            field_groups.append(fields_in_byte)
    return field_groups


def print_sbs_command_short_subfields(field_groups, l, fields_info, cell_width, bit_per_cell, display_mode, po):
    field_lines = []
    for fields_in_byte in reversed(field_groups):
        field_strings = []
        for fld in reversed(fields_in_byte):
            fldinf = fields_info[fld]
            lstfld = l[fld]
            val = lstfld['val']
            fldt = {}
            if display_mode == 1:
                fldt['str'] = "{}={}".format(fldinf['tiny_name'],val)
                fldt['color'] = 34 if ('r' not in fldinf['access']) else 31 if val!=0 else 32
            else:
                if isinstance(val, list) or isinstance(val, bytes):
                    fldt['str'] = "{}={}".format(fldinf['tiny_name'],"".join('{:02x}'.format(x) for x in val))
                else:
                    fldt['str'] = "{}={:x}".format(fldinf['tiny_name'],val)
                fldt['color'] = 30 if ('r' not in fldinf['access']) else 37
            fldt['nbits'] = fldinf['nbits']
            field_strings.append(fldt)
        field_lines.append(field_strings)
    for field_strings in field_lines:
        line_str = []
        for i, fldt in enumerate(field_strings):
            use_width = cell_width * (fldt['nbits']//bit_per_cell) - 2
            line_str.append("\x1b[1;{}m[{:>{}s}]".format(fldt['color'], fldt['str'], use_width))
        print("".join(line_str),'\x1b[0m')


def print_sbs_command_value(cmd, subcmd, response, name_width, po):
    v = response['val']
    l = response['list']
    s = response['sinf']
    u = response['uname']
    cmdinf = SBS_CMD_INFO[cmd]
    subcmdinf = {}
    if subcmd is not None:
        for subgrp in cmdinf['subcmd_infos']:
            if subcmd in subgrp.keys():
                subcmdinf = subgrp[subcmd]
                break
        basecmd_name = re.sub('[^A-Z]', '', cmd.name) + '.' + subcmd.name
    else:
        basecmd_name = cmd.name
    if 'desc' in subcmdinf:
        short_desc = subcmdinf['desc'].split('.')[0]
    else:
        short_desc = cmdinf['desc'].split('.')[0]

    if name_width < 1:
        name_width = 1
    if u in ("bitfields","struct",):
        fmt_val = command_value_to_string(cmdinf, subcmdinf, u, v, po)
        print("{:{}s}\t{}\t{}\t{}".format(basecmd_name+":", name_width, fmt_val, u, short_desc))
        if (po.explain):
            print("Description: {}".format(subcmdinf['desc'] if 'desc' in subcmdinf else cmdinf['desc']))

        fields_info = s
        if (po.short):
            if u in ("bitfields",):
                field_groups = group_fields_by_bits(l.keys(), 8, 64, po)
                print_sbs_command_short_subfields(field_groups, l, fields_info, 9, 1, 1, po)
            else:
                field_groups = group_fields_by_bits(l.keys(), 64, 256, po)
                print_sbs_command_short_subfields(field_groups, l, fields_info, 9, 8, 2, po)
        else:
            max_name_len = max([len(fld.name) for fld in l.keys()])
            for fld in sorted(l.keys(), key=lambda x:x.value):
                print_sbs_command_subfield_value(fld, l[fld], fields_info, max_name_len, po)

    elif u == "date547":
        fld_uname = "date"
        fmt_val = "{:d}-{:02d}-{:02d}".format(1980 + ((v>>9)&0x7f), (v>>5)&0x0f, (v)&0x1f)
        print("{:{}s}\t{}\t{}\t{}".format(basecmd_name+":", name_width, fmt_val, fld_uname, short_desc))
        if (po.explain):
            print("Description: {}".format(subcmdinf['desc'] if 'desc' in subcmdinf else cmdinf['desc']))

    else:
        fmt_val = command_value_to_string(cmdinf, subcmdinf, u, v, po)
        print("{:{}s}\t{}\t{}\t{}".format(basecmd_name+":", name_width, fmt_val, u, short_desc))
        if (po.explain):
            print("Description: {}".format(subcmdinf['desc'] if 'desc' in subcmdinf else cmdinf['desc']))


def smbus_read_manufacturer_access_bq(bus, dev_addr, cmd, subcmd, subcmdinf, po):
    """ Reads value of ManufacturerAccess sub-command from the battery.
    """
    resp_type = subcmdinf['type']
    resp_cmd = subcmdinf['resp_location']
    if 'resp_wait' in subcmdinf:
        resp_wait = subcmdinf['resp_wait']
    else:
        resp_wait = 0

    if (resp_type.startswith("byte[") or resp_type.startswith("string") or resp_type.endswith("_blk")):
        v = smbus_read_manufacturer_access_block_value_bq(bus, dev_addr, cmd, subcmd, resp_type, resp_cmd, resp_wait, po)
    else:
        raise ValueError("Command {}.{} type {} not supported".format(cmd.name,subcmd.name,resp_type))

    resp_unit = subcmdinf['unit']
    if resp_unit['scale'] is not None:
        v *= resp_unit['scale']

    return v, resp_unit['name']


def smbus_write_manufacturer_access_bq(bus, dev_addr, cmd, subcmd, subcmdinf, v, po):
    """ Write value to ManufacturerAccess sub-command of the battery.

    Handles value scaling and its conversion to bytes. Handles retries as well.
    """
    stor_type = subcmdinf['type']
    stor_cmd = subcmdinf['resp_location']
    if 'resp_wait' in subcmdinf:
        stor_wait = subcmdinf['resp_wait']
    else:
        stor_wait = 0

    stor_unit = subcmdinf['unit']
    if stor_unit['scale'] is not None:
        if stor_type in ("float","float_blk",):
            v = v / stor_unit['scale']
        else:
            v = v // stor_unit['scale']

    if (stor_type.startswith("byte[") or stor_type.startswith("string") or stor_type.endswith("_blk")):
        smbus_write_manufacturer_access_block_value_bq(bus, dev_addr, cmd, subcmd, stor_type, stor_cmd, stor_wait, po)
    else:
        raise ValueError("Command {}.{} type {} not supported".format(cmd.name,subcmd.name,stor_type))

    return


def smbus_read(bus, dev_addr, cmd, opts, vals, po):
    """ Reads value of given command from the battery.

    Selects proper getter function for the command given.
    """
    cmdinf = SBS_CMD_INFO[cmd]
    subinfgrp = None
    if 'retry_count' in opts:
        retry_count = opts['retry_count']
    else:
        retry_count = 3
    if (po.verbose > 1):
        print("Reading {} command at addr=0x{:x}, cmd=0x{:x}, type={}, opts={}".format(cmdinf['getter'], dev_addr, cmd.value, cmdinf['type'], opts))

    if cmdinf['getter'] == "simple":
        resp_unit = cmdinf['unit']
        v, u = smbus_read_simple(bus, dev_addr, cmd, cmdinf['type'], resp_unit, retry_count, po)

    elif cmdinf['getter'] == "unit_select_on_capacity_mode":
        capacity_mode = None
        if SBS_COMMAND.BatteryMode in vals.keys():
            batt_mode = vals[SBS_COMMAND.BatteryMode]
            capacity_mode_mask = 1 << SBS_FLAG_BATTERY_MODE.CAPACITY_MODE.value
            capacity_mode = (batt_mode['val'] & capacity_mode_mask) != 0
        if capacity_mode is None:
            resp_unit = {'scale':1,'name':"{:d}{:s}/{:d}{:s}".format(
                cmdinf['unit0']['scale'],cmdinf['unit0']['name'],
                cmdinf['unit1']['scale'],cmdinf['unit1']['name'])}
        elif capacity_mode:
            resp_unit = cmdinf['unit1']
        else:
            resp_unit = cmdinf['unit0']
        v, u = smbus_read_simple(bus, dev_addr, cmd, cmdinf['type'], resp_unit, retry_count, po)

    elif cmdinf['getter'] == "manufacturer_access_subcommand":
        if "subcmd" not in opts.keys():
            raise ValueError("Command {} requires to provide sub-command".format(cmd.name))
        subcmd = opts["subcmd"]
        for subgrp in cmdinf['subcmd_infos']:
            if subcmd in subgrp.keys():
                subcmdinf = subgrp[subcmd]
                break
        if not subgrp:
            raise ValueError("Command {}.{} missing definition".format(cmd.name,subcmd.name))

        if 'resp_location' in subcmdinf:
            # do write request, then expect response at specific location
            v, u = smbus_read_manufacturer_access_bq(bus, dev_addr, cmd, subcmd, subcmdinf, po)
        else:
            # Do normal read, this is not a sub-command with different response location
            v, u = smbus_read_simple(bus, dev_addr, cmd, subcmdinf['type'], subcmdinf['unit'], retry_count, po)
        if (u == "struct"):
            subinfgrp = subcmdinf['struct_info']
        elif (u == "bitfields"):
            subinfgrp = subcmdinf['bitfields_info']

    else:
        raise ValueError("Command {} getter {} not supported".format(cmd.name,cmdinf['getter']))

    if (not subinfgrp) and (u == "bitfields"):
        # The 'bitfields' type has only one list of sub-fields, so use it
        subinfgrp = cmdinf['bitfields_info']

    l = parse_sbs_command_value(cmd, subinfgrp, v, u, po)
    return v, l, u, subinfgrp


def smbus_write(bus, dev_addr, cmd, v, opts, vals, po):
    """ Write value to given command of the battery.

    Selects proper getter function for the command given.
    """
    cmdinf = SBS_CMD_INFO[cmd]
    subinfgrp = None
    if 'retry_count' in opts:
        retry_count = opts['retry_count']
    else:
        retry_count = 1
    if (po.verbose > 1):
        print("Writing {} command at addr=0x{:x}, cmd=0x{:x}, type={}, v={}, opts={}".format(
          cmdinf['getter'], dev_addr, cmd.value, cmdinf['type'], v, opts))

    if cmdinf['getter'] == "simple":
        stor_unit = cmdinf['unit']
        smbus_write_simple(bus, dev_addr, cmd, v, cmdinf['type'], stor_unit, retry_count, po)

    elif cmdinf['getter'] == "unit_select_on_capacity_mode":
        capacity_mode = None
        if SBS_COMMAND.BatteryMode in vals.keys():
            batt_mode = vals[SBS_COMMAND.BatteryMode]
            capacity_mode_mask = 1 << SBS_FLAG_BATTERY_MODE.CAPACITY_MODE.value
            capacity_mode = (batt_mode['val'] & capacity_mode_mask) != 0
        if capacity_mode is None:
            stor_unit = {'scale':1,'name':"{:d}{:s}/{:d}{:s}".format(
                cmdinf['unit0']['scale'],cmdinf['unit0']['name'],
                cmdinf['unit1']['scale'],cmdinf['unit1']['name'])}
        elif capacity_mode:
            stor_unit = cmdinf['unit1']
        else:
            stor_unit = cmdinf['unit0']
        smbus_write_simple(bus, dev_addr, cmd, v, cmdinf['type'], stor_unit, retry_count, po)

    elif cmdinf['getter'] == "manufacturer_access_subcommand":
        if "subcmd" not in opts.keys():
            raise ValueError("Command {} requires to provide sub-command".format(cmd.name))
        subcmd = opts["subcmd"]
        for subgrp in cmdinf['subcmd_infos']:
            if subcmd in subgrp.keys():
                subcmdinf = subgrp[subcmd]
                break
        if not subgrp:
            raise ValueError("Command {}.{} missing definition".format(cmd.name,subcmd.name))

        if 'resp_location' in subcmdinf:
            # do write request, then expect response at specific location
            smbus_write_manufacturer_access_bq(bus, dev_addr, cmd, subcmd, subcmdinf, v, po)
        else:
            smbus_write_simple(bus, dev_addr, cmd, v, subcmdinf['type'], subcmdinf['unit'], retry_count, po)
        if (u == "struct"):
            subinfgrp = subcmdinf['struct_info']
        elif (u == "bitfields"):
            subinfgrp = subcmdinf['bitfields_info']

    else:
        raise ValueError("Command {} getter {} not supported".format(cmd.name,cmdinf['getter']))

    if (not subinfgrp) and (u == "bitfields"):
        # The 'bitfields' type has only one list of sub-fields, so use it
        subinfgrp = cmdinf['bitfields_info']

    return u, subinfgrp


def bq_read_firmware_version_sealed(bus, dev_addr, po):
    """ Reads firmware version from BQ series chips

    Uses the sequence which allows to read the FW version even in sealed mode.
    The sequence used to do this read requires low-level access to the bus via
    `write()` command which allows sending raw data. Not all smbus wrappers
    available in various platforms have that support.
    """
    # Do 3 commands which pretend to write oversized buffer; this needs to be done within 4 seconds
    for cmd in (SBS_COMMAND.DeviceChemistry, SBS_COMMAND.ManufacturerName, SBS_COMMAND.DeviceChemistry):
        # We are sending messages which are not correct commands - we expect to receive no ACK
        # This is normal part of this routine; each of these commands should fail
        try:
            bus.write(dev_addr, [cmd.value, 62])
            # If somehow we got no exception, raise one
            raise ConnectionError("FW version acquire tripped as it expected NACK on a command")
        except OSError as ex:
            if ex.errno in (121,): # I/O error - usually means no ACK
                pass

    # Now ManufacturerData() will contain FW version data which we can read; wait to make sure it's ready
    time.sleep(0.35) # EV2300 software waits 350 ms; but documentation doesn't explicitly say to wait here

    cmd  = SBS_COMMAND_BQ30.ManufacturerInput
    # Data length is 11 or 13 bytes
    v = smbus_read_block_for_basecmd(bus, dev_addr, cmd, "FirmwareVersion", "byte[13]", po)

    return v


def smart_battery_bq_detect(vals, po):
    global bus
    if not callable(getattr(bus, "write", None)):
        raise ImportError("The smbus library provided has no raw write support")

    v = None
    for nretry in reversed(range(3)):
        try:
            v = bq_read_firmware_version_sealed(bus, po.dev_address, po)
        except Exception as ex:
            if (nretry > 0) and (
              (isinstance(ex, OSError) and ex.errno in (5,121,)) or
              # 5 = Input/output error, sometimes just happens
              # 121 = I/O error, usually means no ACK
              (isinstance(ex, ValueError)) or # invalid length or checksum
              (isinstance(ex, ConnectionError)) # invalid response on initial writes
              ):
                if (po.verbose > 2):
                    print("Retrying due to error: "+str(ex))
                pass
            else:
                raise
        if v is None:
            time.sleep(0.35)
            continue
        break
    chip = CHIP_TYPE.BQGENERIC
    for chchip in CHIP_TYPE:
        # Go through all TI chips
        if (chchip.value & 0xff0000) != 0x010000:
            continue
        # Lower 16 bits of each enum are the DeviceNumber
        if (v[0]<<8)+(v[1]) == chchip.value & 0xffff:
            chip = chchip
            break

    return chip


def smart_battery_detect(vals, po):
    chip = CHIP_TYPE.SBS
    try:
        chip = smart_battery_bq_detect(vals, po)
    except Exception as ex:
        print("Chip detection failded: "+str(ex))
    if (po.verbose > 0):
        print("Auto-selected chip: {}, {}".format(chip.name,chip.__doc__))
    return chip


def smart_battery_system_command_from_text(cmd_str, po):
    """ Converts SBS command from text to enum

    Requires chip to be identified to properly map commands
    which are not in base SBS specification.
    """
    cmd_str_parts = cmd_str.split('.')
    major_cmd_str = cmd_str_parts[0]
    subcmd_str = None
    if len(cmd_str_parts) > 1:
        subcmd_str = cmd_str_parts[1]
    cmd = None
    if is_ti_bq_chip(po.chip):
        if major_cmd_str in [i.name for i in SBS_COMMAND_BQ30]:
            cmd = SBS_COMMAND_BQ30.from_name(major_cmd_str)
        elif major_cmd_str in [i.name for i in SBS_COMMAND_BQ_TURBO]:
            cmd = SBS_COMMAND_BQ_TURBO.from_name(major_cmd_str)
    if cmd is None: # Standard SBS command can be used on any chip
        if major_cmd_str in [i.name for i in SBS_COMMAND]:
            cmd = SBS_COMMAND.from_name(major_cmd_str)
    if cmd is None:
        raise ValueError("The command '{}' is either invalid or not supported by chip".format(major_cmd_str))

    subcmd = None
    if (cmd == SBS_COMMAND.ManufacturerAccess) and is_ti_bq_chip(po.chip):
        if subcmd_str in [i.name for i in MANUFACTURER_ACCESS_CMD_BQ30]:
            subcmd = MANUFACTURER_ACCESS_CMD_BQ30.from_name(subcmd_str)

    return cmd, subcmd


def smart_battery_system_last_error(bus, dev_addr, vals, po):
    """ Reads and prints value of last ERROR_CODE from the battery.
    """
    cmd = SBS_COMMAND.BatteryStatus
    fld = SBS_FLAG_BATTERY_STATUS.ERROR_CODE
    fldinf = SBS_BATTERY_STATUS_INFO[fld]
    val = None
    try:
        v, l, u, s = smbus_read(bus, dev_addr, cmd, {"subcmd": None,"retry_count":1}, vals, po)
        response = {'val':v,'list':l,'sinf':s,'uname':u,}
        vals[cmd if subcmd is None else subcmd] = response
        val = l[fld]['val']
        fmt_val = "{}={}".format(val, fldinf['value_names'][val])
        print("Reported {}: {}".format(fld.name,fmt_val))
    except Exception as ex:
        print("Could not read {} from the battery".format(fld.name))
        pass
    if (po.explain):
        if val == 0:
            print(("Explanation: If battery reports no error, but command did failed, "
              "then the blame goes to the receiver side."))
        elif is_ti_bq_chip(po.chip) and val == 3:
            print(("Explanation: The 'Unsupported command' error often means "
              "that the command is unavailable in sealed mode. "
              "But it may also be unsupported by the specific chip."))
    return


def smart_battery_system_read(cmd_str, vals, po):
    """ Reads and prints value of the command from the battery.
    """
    global bus
    cmd, subcmd = smart_battery_system_command_from_text(cmd_str, po)
    cmdinf = SBS_CMD_INFO[cmd]
    opts = {"subcmd": subcmd}
    v, l, u, s = smbus_read(bus, po.dev_address, cmd, opts, vals, po)
    response = {'val':v,'list':l,'sinf':s,'uname':u,}
    vals[cmd if subcmd is None else subcmd] = response
    print_sbs_command_value(cmd, subcmd, response, 0, po)


def smart_battery_system_trigger(cmd_str, vals, po):
    """ Trigger a switch command within the battery.
    """
    global bus
    cmd, subcmd = smart_battery_system_command_from_text(cmd_str, po)
    cmdinf = SBS_CMD_INFO[cmd]
    opts = {"subcmd": subcmd}
    v = None
    try:
        u, s = smbus_write(bus, po.dev_address, cmd, v, opts, vals, po)
    except Exception as ex:
        print("{:{}s}\t{}\t{}\t{}".format(cmd.name+":", 1, "trigger", "FAIL", str(ex)))
        if (isinstance(ex, OSError)):
            smart_battery_system_last_error(bus, po.dev_address, vals, po)
        if (po.explain):
            print("Description: {}".format(cmdinf['desc']))
        return
    print("{:{}s}\t{}\t{}\t{}".format(cmd.name+":", 1, "trigger", "SUCCESS", "Trigger switch write accepted"))


def smart_battery_system_monitor(mgroup_str, vals, po):
    """ Reads and prints multiple values from the battery.
    """
    global bus
    mgroup = MONITOR_GROUP.from_name(mgroup_str)
    names_width = 0
    for cmd in SBS_CMD_GROUPS[mgroup]:
        names_width = max(names_width, len(cmd.name))
    for anycmd in SBS_CMD_GROUPS[mgroup]:
        if anycmd in MANUFACTURER_ACCESS_CMD_BQ_INFO.keys():
            cmd = SBS_COMMAND.ManufacturerAccess
            subcmd = anycmd
        else:
            cmd = anycmd
            subcmd = None
        cmdinf = SBS_CMD_INFO[cmd]
        opts = {"subcmd": subcmd}
        try:
            v, l, u, s = smbus_read(bus, po.dev_address, cmd, opts, vals, po)
        except Exception as ex:
            print("{:{}s}\t{}\t{}\t{}".format(cmd.name+":", names_width, "n/a", "FAIL", str(ex)))
            if (isinstance(ex, OSError)):
                smart_battery_system_last_error(bus, po.dev_address, vals, po)
            if (po.explain):
                print("Description: {}".format(cmdinf['desc']))
            continue
        response = {'val':v,'list':l,'sinf':s,'uname':u,}
        vals[cmd if subcmd is None else subcmd] = response
        print_sbs_command_value(cmd, subcmd, response, names_width, po)
    return


def smart_battery_system_sealing(seal_str, vals, po):
    """ Change sealing state of the battery.
    """
    global bus

    cmd = SBS_COMMAND.ManufacturerAccess
    if seal_str == "Unseal":
        subcmd = MANUFACTURER_ACCESS_CMD_BQ30.UnSealDevice
    elif seal_str == "Seal":
        subcmd = MANUFACTURER_ACCESS_CMD_BQ30.SealDevice
    elif seal_str == "FullAccess":
        subcmd = MANUFACTURER_ACCESS_CMD_BQ30.FullAccessDevice
    else:
        raise ValueError("Unrecognized target seal state")

    if True:
        cmdinf = SBS_CMD_INFO[cmd]
        for subgrp in cmdinf['subcmd_infos']:
            if subcmd in subgrp.keys():
                subcmdinf = subgrp[subcmd]
                break
        if not subgrp:
            raise ValueError("Command {}.{} missing definition".format(cmd.name,subcmd.name))

    checkcmd_name = "{}.{}".format(SBS_COMMAND.ManufacturerAccess.name,SBS_COMMAND_BQ30.OperationStatus.name)
    resp_type = subcmdinf['type']
    resp_cmd = subcmdinf['resp_location']
    if 'resp_wait' in subcmdinf:
        resp_wait = subcmdinf['resp_wait']
    else:
        resp_wait = 0

    time.sleep(0.35)
    smbus_perform_unseal_bq30(bus, po.dev_address, cmd, subcmd, resp_type, resp_cmd, resp_wait, po.sha1key, po)
    time.sleep(0.35)
    smart_battery_system_read(checkcmd_name, vals, po)


def parse_chip_type(s):
    """ Parses chip type string in known formats.
    """
    return s


def parse_command(s):
    """ Parses command/offset string in known formats.
    """
    try: 
        if int(s) in SBS_COMMAND.values:
            s = SBS_COMMAND(int(s)).name
    except ValueError:
        pass
    return s


def parse_monitor_group(s):
    """ Parses monitor group string in known formats.
    """
    return s


def main():
    """ Main executable function.

      Its task is to parse command line options and call a function which performs sniffing.
    """
    # Create a list of valid commands/offsets: for read, write and trigger
    all_r_commands = []
    for cmd, cmdinf in SBS_CMD_INFO.items():
        can_access = sum(('r' in accstr) for accstr in cmdinf['access_per_seal'])
        if 'subcmd_infos' in cmdinf:
            for subgrp in cmdinf['subcmd_infos']:
                for subcmd, subcmdinf in subgrp.items():
                    sub_can_access = sum(('r' in accstr) for accstr in subcmdinf['access_per_seal'])
                    if sub_can_access > 0:
                        all_r_commands.append("{}.{}".format(cmd.name,subcmd.name))
        elif can_access > 0:
            all_r_commands.append(cmd.name)
    all_w_commands = []
    all_t_commands = []
    for cmd, cmdinf in SBS_CMD_INFO.items():
        can_access = sum(('w' in accstr) for accstr in cmdinf['access_per_seal'])
        if 'subcmd_infos' in cmdinf:
            for subgrp in cmdinf['subcmd_infos']:
                for subcmd, subcmdinf in subgrp.items():
                    sub_can_access = sum(('w' in accstr) for accstr in subcmdinf['access_per_seal'])
                    if sub_can_access > 0:
                        if subcmdinf['type'] == "void":
                            all_t_commands.append("{}.{}".format(cmd.name,subcmd.name))
                        else:
                            all_w_commands.append("{}.{}".format(cmd.name,subcmd.name))
        elif can_access > 0:
            if cmdinf['type'] == "void":
                all_t_commands.append(cmd.name)
            else:
                all_w_commands.append(cmd.name)
                
    parser = argparse.ArgumentParser(description=__doc__.split('.')[0])

    parser.add_argument('-b', '--bus', default="smbus:1", type=str,
            help="I2C bus device selection (defaults to '%(default)s')")

    parser.add_argument('-a', '--dev_address', default=0x0b, type=lambda x: int(x,0),
            help="Target SBS device address (defaults to 0x%(default)x)")

    parser.add_argument('-c', '--chip', metavar='model', choices=[i.name for i in CHIP_TYPE],
            type=parse_chip_type,  default=CHIP_TYPE.AUTO.name,
            help="target chip model; one of: {:s}".format(', '.join(i.name for i in CHIP_TYPE)))

    parser.add_argument("--dry-run", action="store_true",
            help="Do not use real smbus device or do permanent changes")

    parser.add_argument('-v', '--verbose', action='count', default=0,
            help="Increases verbosity level; max level is set by -vvv")

    subparser = parser.add_mutually_exclusive_group()

    subparser.add_argument('-s', '--short', action="store_true",
            help="Display only minimal description of values; to be used by "
              "experienced users, who have no need for additional info")

    subparser.add_argument('-e', '--explain', action="store_true",
            help="Explain each value by providing description from spec")

    parser.add_argument("--version", action='version', version="%(prog)s {version} by {author}"
              .format(version=__version__,author=__author__),
            help="Display version information and exit")


    subparsers = parser.add_subparsers(dest='action', metavar='action',
            help="action to take")


    subpar_read = subparsers.add_parser('read',
            help="Read value from a single command/offset of the battery")

    subpar_read.add_argument('command', metavar='command', choices=all_r_commands, type=parse_command,
            help="The command/offset name to read from; one of: {:s}".format(', '.join(all_r_commands)))


    subpar_trigger = subparsers.add_parser('trigger',
            help="Write to a trigger, command/offset of the battery which acts as a switch")

    subpar_trigger.add_argument('command', metavar='command', choices=all_t_commands, type=parse_command,
            help="The command/offset name to trigger; one of: {:s}".format(', '.join(all_t_commands)))


    subpar_write = subparsers.add_parser('write',
            help="Write value to a single command/offset of the battery")

    subpar_write.add_argument('command', metavar='command', choices=all_w_commands, type=parse_command,
            help="The command/offset name to write to; one of: {:s}".format(', '.join(all_w_commands)))

    subpar_write.add_argument('newvalue', metavar='value', type=str,
            help="New value to write to the command/offset")


    subpar_monitor = subparsers.add_parser('monitor',
            help="Monitor value of a group of commands/offsets")

    subpar_monitor.add_argument('cmdgroup', metavar='group', choices=[i.name for i in MONITOR_GROUP], type=parse_monitor_group,
            help="Group of commands/offsets; one of: {:s}".format(', '.join(i.name for i in MONITOR_GROUP)))


    subpar_sealing = subparsers.add_parser('sealing',
            help="Change sealing state of BQ chip")

    sealing_choices = ("Unseal", "Seal", "FullAccess",)
    subpar_sealing.add_argument('sealstate', metavar='state', choices=sealing_choices, type=str,
            help="New sealing state; one of: {:s}".format(', '.join(sealing_choices)))

    subpar_sealing.add_argument('--sha1key', default='0123456789abcdeffedcba9876543210', type=str,
            help="Device key for SHA-1/HMAC Authentication (defaults to '%(default)s')")

    po = parser.parse_args();

    po.chip = CHIP_TYPE.from_name(po.chip)

    if (po.verbose > 0):
        print("Opening {}".format(po.bus))
    smbus_open(po.bus, po)

    vals = {}

    if po.chip == CHIP_TYPE.AUTO:
        po.chip = smart_battery_detect(vals, po)

    if po.action == 'read':
        smart_battery_system_read(po.command, vals, po)
    elif po.action == 'trigger':
        smart_battery_system_trigger(po.command, vals, po)
    elif po.action == 'write':
        smart_battery_system_write(po.command, po.newvalue, vals, po)
    elif po.action == 'monitor':
        smart_battery_system_monitor(po.cmdgroup, vals, po)
    elif po.action == 'sealing':
        smart_battery_system_sealing(po.sealstate, vals, po)
    else:
        raise NotImplementedError('Unsupported command.')

    smbus_close()


if __name__ == '__main__':
    try:
        main()
    except Exception as ex:
        eprint("Error: "+str(ex))
        raise
        sys.exit(10)
