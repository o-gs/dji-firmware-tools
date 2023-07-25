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
break, especially when the chip is sealed. Probing will not accidently result
in a packet which disables the battery forever.

If the battery already has I2C master device on the bus (like uC on battery
board), try not to turn on the battery for use with this program. The SBS chip
should wake from sleep to answer on requests from this program, and if the
battery is turned on, the constant communication from internal master will
interfere with packets sent by this tool. It can also cause the battery
to enter temporary SMBus error mode. To avoid that, don't even press the
battery button while it is connected to I2C interface.

Though in case of connection issues, you may try re-running the script when
battery is on. The uC of some batteries keeps the line shorted to high state
when turned off.

Another thing to try on issues is using your bus through both SMBus API and
I2C API, using "--bus" parameter.

If the script shows "OSError: [Errno 74] Bad message", the very likely
cause is invalid I2C speed. Check how to change baud rate of your
I2C bus device. Baud rate of 100kbps should work. The EV2300 usually
uses baud rate of 66kbps, though for some chips it switches to 30kbps.

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
Constant probing of the line affects its impedance, which may sometimes
lead to such unusual effects.

There is also "OSError: [Errno 5] Input/output error" which tend to happen
interchangeably with "Remote I/O error", but only if the other side responds
to part of the message.

Finally, remember that cheap I2C devices can sometimes get into unuseable
state - make sure you reboot the Raspberry Pi, or re-connect the USB stick,
if logic signal changes are visible but I2C still refuses to detect anything.

Tested devices:
(these devices are confirmed)
BQ30z55 fw 0.36, Mavic Pro battery, 2021-02-15, mefistotelis

Devices verified with spec:
(should work, but not actually tested)
BQ30z50, BQ30z554

For other devices, only basic SBS functions are expected to work.
Using chip-specific commands on them may have undesired effects.
To make sure a command is safe, check Reference Manual of the chip
and make sure the command is defined in the same way as in spec of
one of tested devices.

"""
__version__ = "0.2.1"
__author__ = "Mefistotelis @ Original Gangsters"
__license__ = "GPL"

import re
import sys
import time
import enum
import types
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


class ImprovisedCommand(types.SimpleNamespace):
    def __hash__(self):
        return hash(self.value)


class CHIP_TYPE(DecoratedEnum):
    """ Smart Battery System chip type
    """
    AUTO		= 0
    SBS			= 1
    # Texas Instruments BQ chips; lower 16 bits are DeviceType
    BQGENERIC	= 0x010000
    BQ20z45		= 0x010450
    BQ30z50		= 0x010500
    BQ30z55		= 0x010550
    BQ30z554	= 0x010554
    BQ20z65		= 0x010650
    BQ3050		= 0x013050
    BQ3060		= 0x013060
    BQ40z307	= 0x014307 # hw marking bq9003; custom chip for DJI
    BQ40370		= 0x019db2
    # supported by BatteryManagementStudio-1.3
    BQ35100		= 0x010100 # hw marking bq8035;
    BQ34110		= 0x010110 # hw marking bq8035;
    BQ34210		= 0x010210 # hw marking bq8101;
    BQ27220		= 0x010220 # hw marking bq8101;
    BQ27320		= 0x010320 # hw marking bq8035;
    BQ27421		= 0x010421 # hw marking bq8101; seem to also be BQ27411 ?
    BQ27425		= 0x010425 # hw marking bq8036;
    BQ27426		= 0x010426 # hw marking bq8101;
    BQ27510		= 0x010510 # hw marking bq8035;
    BQ27520		= 0x010520 # hw marking bq8035;
    BQ27530		= 0x010530 # hw marking bq8035;
    BQ27531		= 0x010531 # hw marking bq8035;
    BQ27532		= 0x010532 # hw marking bq8035;
    BQ27541		= 0x010541 # hw marking bq8034;
    BQ27542		= 0x010542 # hw marking bq8034;
    BQ27545		= 0x010545 # hw marking bq8035;
    BQ27546		= 0x010546 # hw marking bq8034;
    BQ27621		= 0x010621 # hw marking bq8101;
    BQ27742		= 0x010742 # hw marking bq8037;
    BQ78z100	= 0x011100 # hw marking bq9002;
    BQ27z561	= 0x011561 # hw marking bq9035;
    BQ78350		= 0x011e9b # hw marking bq8030;
    BQ28z610	= 0x012610 # hw marking bq9002;
    BQ40z50		= 0x014500 # hw marking bq9000;
    BQ40z60		= 0x014600 # hw marking bq9000;
    BQ40z80		= 0x014800 # hw marking bq9006; seem to also be BQ40z70 ?
    BQ4050		= 0x019e34 # hw marking bq9000;
    BQ769x2		= 0x017692 # hw marking bq7692; BQ76942/BQ76952


CHIP_TYPE.AUTO.__doc__		= "Automatic detection of the chip"
CHIP_TYPE.SBS.__doc__		= "Generic chip with SBS support"
CHIP_TYPE.BQGENERIC.__doc__	= "Unidentified chip from TI BQ family"
CHIP_TYPE.BQ30z55.__doc__	= "Texas Instruments BQ30z55 chip"
CHIP_TYPE.BQ20z65.__doc__	= "Texas Instruments BQ20z65 chip"
CHIP_TYPE.BQ3050.__doc__	= "Texas Instruments BQ3050 chip"
CHIP_TYPE.BQ3060.__doc__	= "Texas Instruments BQ3060 chip"
CHIP_TYPE.BQ40z307.__doc__	= "Texas Instruments BQ40z307 chip for DJI"
CHIP_TYPE.BQ40370.__doc__	= "Texas Instruments BQ40370 chip"
CHIP_TYPE.BQ35100.__doc__	= "Texas Instruments BQ35100 chip"
CHIP_TYPE.BQ34110.__doc__	= "Texas Instruments BQ34110 chip"
CHIP_TYPE.BQ34210.__doc__	= "Texas Instruments BQ34210 chip"
CHIP_TYPE.BQ27220.__doc__	= "Texas Instruments BQ27220 chip"
CHIP_TYPE.BQ27320.__doc__	= "Texas Instruments BQ27320 chip"
CHIP_TYPE.BQ27421.__doc__	= "Texas Instruments BQ27411/BQ27421 chip"
CHIP_TYPE.BQ27425.__doc__	= "Texas Instruments BQ27425 chip"
CHIP_TYPE.BQ27426.__doc__	= "Texas Instruments BQ27426 chip"
CHIP_TYPE.BQ27510.__doc__	= "Texas Instruments BQ27510 chip"
CHIP_TYPE.BQ27520.__doc__	= "Texas Instruments BQ27520 chip"
CHIP_TYPE.BQ27530.__doc__	= "Texas Instruments BQ27530 chip"
CHIP_TYPE.BQ27531.__doc__	= "Texas Instruments BQ27531 chip"
CHIP_TYPE.BQ27532.__doc__	= "Texas Instruments BQ27532 chip"
CHIP_TYPE.BQ27541.__doc__	= "Texas Instruments BQ27541 chip"
CHIP_TYPE.BQ27542.__doc__	= "Texas Instruments BQ27542 chip"
CHIP_TYPE.BQ27545.__doc__	= "Texas Instruments BQ27545 chip"
CHIP_TYPE.BQ27546.__doc__	= "Texas Instruments BQ27546 chip"
CHIP_TYPE.BQ27621.__doc__	= "Texas Instruments BQ27621 chip"
CHIP_TYPE.BQ27742.__doc__	= "Texas Instruments BQ27742 chip"
CHIP_TYPE.BQ78z100.__doc__	= "Texas Instruments BQ78z100 chip"
CHIP_TYPE.BQ27z561.__doc__	= "Texas Instruments BQ27z561 chip"
CHIP_TYPE.BQ78350.__doc__	= "Texas Instruments BQ78350 chip"
CHIP_TYPE.BQ28z610.__doc__	= "Texas Instruments BQ28z610 chip"
CHIP_TYPE.BQ40z50.__doc__	= "Texas Instruments BQ40z50 chip"
CHIP_TYPE.BQ40z60.__doc__	= "Texas Instruments BQ40z60 chip"
CHIP_TYPE.BQ40z80.__doc__	= "Texas Instruments BQ40z70/BQ40z80 chip"
CHIP_TYPE.BQ4050.__doc__	= "Texas Instruments BQ4050 chip"
CHIP_TYPE.BQ769x2.__doc__	= "Texas Instruments BQ76942/BQ76952 chip"


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


class RAW_ADDRESS_SPACE_KIND_BQGENERIC(DecoratedEnum):
    """ Address spaces used in BQ family SBS chips
    """
    DataFlash				= 0x00
    InstructionFlash		= 0x01


class MANUFACTURER_ACCESS_CMD_BQGENERIC(DecoratedEnum):
    """ ManufacturerAccess sub-commands used in all BQ family SBS chips
    """
    ManufacturerData		= 0x00
    DeviceType				= 0x01
    FirmwareVersion			= 0x02
    HardwareVersion			= 0x03


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


class SBS_FLAG_SPECIFICATION_INFO(DecoratedEnum):
    """ Flags used in SpecificationInfo command
    """
    Revision					= 0
    Version						= 4
    VScale						= 8
    IPScale						= 12


class MONITOR_GROUP(DecoratedEnum):
    """ List of groups of commands/offsets.
    """
    DeviceInfo       = 0x00
    UsageInfo        = 0x01
    ComputedInfo     = 0x02
    StatusBits       = 0x03
    AtRates          = 0x04
    BQStatusBits     = 0x06
    BQStatusBitsMA   = 0x07
    BQCellVoltages   = 0x08
    BQLifetimeData   = 0x09
    BQLifetimeDataMA = 0x0a
    ImpedanceTrack   = 0x0b
    ImpedanceTrackMA = 0x0c
    BQTurboMode      = 0x0f


# Global variables, modified by chip drivers
MANUFACTURER_ACCESS_CMD_BQ_INFO = {}
MANUFACTURER_BLOCK_ACCESS_CMD_BQ_INFO = {}
SBS_BATTERY_MODE_INFO = {}
SBS_BATTERY_STATUS_INFO = {}
SBS_SPECIFICATION_INFO = {}
SBS_CMD_INFO = {}
RAW_ADDRESS_SPACE_KIND_INFO = {}
SBS_CMD_GROUPS = {}
SBS_SEALING = {}


def reset_default_driver(po):
  """ Sets global variables to no chip-specific driver loaded state.
  """
  global MANUFACTURER_ACCESS_CMD_BQ_INFO
  MANUFACTURER_ACCESS_CMD_BQ_INFO = {
    MANUFACTURER_ACCESS_CMD_BQGENERIC.ManufacturerData : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"hex"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Output ManufacturerData()."),
    },
    MANUFACTURER_ACCESS_CMD_BQGENERIC.DeviceType : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"hex"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("IC device part number."),
    },
    MANUFACTURER_ACCESS_CMD_BQGENERIC.FirmwareVersion : {
        'type'	: "byte[13]",
        'unit'	: {'scale':None,'name':"hex"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Version of the firmware within the device. Major and "
            "minor version numbers."),
    },
    MANUFACTURER_ACCESS_CMD_BQGENERIC.HardwareVersion : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"dec"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("The IC hardware revision."),
    },
  }

  global MANUFACTURER_BLOCK_ACCESS_CMD_BQ_INFO
  MANUFACTURER_BLOCK_ACCESS_CMD_BQ_INFO = {
  }

  global SBS_BATTERY_MODE_INFO
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

  global SBS_BATTERY_STATUS_INFO
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

  global SBS_SPECIFICATION_INFO
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
        'value_names'	: ["v0-none","v1.0","v1.1","v1.1+PEC","vFuture4",
          "vFuture5","vFuture6","vFuture7"],
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

  global SBS_CMD_INFO
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
        'getter'	: "write_word_subcommand",
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
        'desc'	: ("Predicted remaining operating time when discharging. "
            "Uses the previously written AtRate value."),
        'getter'	: "simple",
    },
    SBS_COMMAND.AtRateOK : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"boolean"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Whether can deliver an additional energy for 10 sec."
            "Uses the previously written AtRate value for additional energy "
            "amount."),
        'getter'	: "simple",
    },
    SBS_COMMAND.Temperature : {
        'type'	: "uint16",
        'unit'	: {'scale':0.1,'name':"K"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Cell-pack's internal temperature. The actual operational "
            "temperature range will be defined at a pack level by a "
            "particular manufacturer. Typically it will be in the range "
            "of -20 degC to +75 degC."),
        'getter'	: "simple",
    },
    SBS_COMMAND.Voltage : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Cell-pack voltage. Provides power management systems "
            "with an accurate battery terminal voltage. Power management "
            "systems can use this voltage, along with battery current "
            "information, to characterize devices they control."),
        'getter'	: "simple",
    },
    SBS_COMMAND.Current : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"mA"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("The current being supplied/accepted through terminals. "
            "Provides a snapshot for the power management system of the "
            "current flowing into or out of the battery. This information "
            "will be of particular use in power management systems because "
            "they can characterize individual devices and \"tune\" their "
            "operation."),
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
            "returns 50%, the Relative StateOfCharge() is actually between "
            "50 and 60%. The MaxError() of a battery is expected to increase "
            "until the Smart Battery identifies a condition that will give it "
            "higher confidence in its own accuracy, like being fully charged. "
            "The Battery can signal when MaxError() has become too high by "
            "setting the CONDITION_FLAG bit in BatteryMode()."),
        'getter'	: "simple",
    },
    SBS_COMMAND.RelativeStateOfCharge : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"%"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Predicted remaining capacity, % of FullChargeCap()."
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
        'desc'	: ("Predicted remaining capacity, % of DesignCap(). "
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
            "depending on the setting of the BatteryMode()'s CAPACITY_MODE "
            "bit. This is an important distinction because use of the wrong "
            "calculation mode may result in inaccurate return values."),
        'getter'	: "unit_select_on_capacity_mode",
    },
    SBS_COMMAND.AverageTimeToEmpty : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"minutes"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("One-minute rolling average of the remaining bat life. "
            "The AverageTimeToEmpty() value is calculated based on either "
            "current or power depending on the setting of the BatteryMode()'s "
            "CAPACITY_MODE bit."),
        'getter'	: "simple",
    },
    SBS_COMMAND.AverageTimeToFull : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"minutes"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("One minute average of the remaining time until full. "
            "This function can be used by the SMBus Host's power management "
            "system to aid in its policy. It may also be used to find out "
            "how long the system must be left on to achieve full charge."),
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
        'unit'	: {'scale':None,'name':"str"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("The battery's manufacturer's name. "
            "The name can be displayed by the SMBus Host's power "
            "management system display as both an identifier and as an "
            "advertisement for the manufacturer."),
        'getter'	: "simple",
    },
    SBS_COMMAND.DeviceName : {
        'type'	: "string[12]",
        'unit'	: {'scale':None,'name':"str"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Character string that contains the battery's name. "
            "This returns the battery's name for display by the SMBus "
            "Host's power management system as well as for identification "
            "purposes."),
        'getter'	: "simple",
    },
    SBS_COMMAND.DeviceChemistry : {
        'type'	: "string[4]",
        'unit'	: {'scale':None,'name':"str"},
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
  }

  global RAW_ADDRESS_SPACE_KIND_INFO
  RAW_ADDRESS_SPACE_KIND_INFO = {}

  global SBS_CMD_GROUPS
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
    MONITOR_GROUP.AtRates : (
        SBS_COMMAND.AtRate,
        SBS_COMMAND.AtRateToFull,
        SBS_COMMAND.AtRateToEmpty,
        SBS_COMMAND.AtRateOK,
    ),
  }

  global SBS_SEALING
  SBS_SEALING = {}

  pass # reset_default_driver() ends

class ChipMock(object):
    def __init__(self, bus, chip=None):
        self.bus = bus
        self.reads = {}
        self.reads_sub = {}
        self.prep_static()

    def prep_static(self):
        # Only commands required to chip detection;
        # After detection, imported chip file will replace this
        self.add_read_sub(0x00, 0x02, bytes.fromhex(
          "0550 0036 0034 00 0380 0001 0083")) # FirmwareVersion

    def add_read(self, register, data):
        self.reads[register] = data

    def add_read_sub(self, register, subreg, data):
        if register not in self.reads_sub.keys():
            self.reads_sub[register] = {}
        self.reads_sub[register][subreg] = data

    def prep_read(self, cmd, cmdinf):
        pass

    def prep_read_sub(self, cmd, cmdinf, subcmd, subcmdinf):
        if subcmd == MANUFACTURER_ACCESS_CMD_BQGENERIC.FirmwareVersion:
            register = 0x2f
            self.reads[register] = self.reads_sub[cmd.value][subcmd.value]

    def do_read(self, i2c_addr, register):
        data = bytes(self.reads[register])
        return data

    def prep_write(self, cmd, cmdinf):
        pass

    def prep_write_sub(self, cmd, cmdinf, subcmd, subcmdinf):
        pass

    def do_write(self, i2c_addr, register, value):
        pass


class i2c_msg_mock(object):
    def __init__(self, **kwargs):
        vars(self).update(kwargs)

    def __bytes__(self):
        return bytes(self.buf[0:self.len])

    @staticmethod
    def read(address, length):
        return i2c_msg_mock(addr=address, flags=0, len=length, buf=None)

    @staticmethod
    def write(address, buf):
        return i2c_msg_mock(addr=address, flags=1, len=len(buf), buf=bytes(buf))


class SMBusMock(object):
    """ Mock SMBus module, used for dry-run testing.

    Implements PEC and block sizes, but for actual data requires mock chip.
    """
    def __init__(self, busid=None, force=False):
        self.address = None
        self.busid = busid
        self.force = force
        self.pec = False
        self.expect_block = False
        self.mock = ChipMock(self)
        self.mock_exception = None

    def open(self, busid):
        self.busid = busid

    def close(self):
        self.busid = None

    def write_quick(self, i2c_addr, force=None):
        pass

    def read_byte(self, i2c_addr, force=None):
        return 1

    def write_byte(self, i2c_addr, value, force=None):
        pass

    def read_byte_data(self, i2c_addr, register, force=None):
        data = self.do_mock_read(i2c_addr, register)
        return data[0]

    def write_byte_data(self, i2c_addr, register, value, force=None):
        self.do_mock_write(i2c_addr, register, struct.pack('<B', value))

    def read_word_data(self, i2c_addr, register, force=None):
        data = self.do_mock_read(i2c_addr, register)
        return struct.unpack('<H', data[0:2])[0]

    def write_word_data(self, i2c_addr, register, value, force=None):
        self.do_mock_write(i2c_addr, register, struct.pack('<H', value))

    def write_dword_data(self, i2c_addr, register, value, force=None):
        self.do_mock_write(i2c_addr, register, struct.pack('<L', value))

    def process_call(self, i2c_addr, register, value, force=None):
        pass

    def read_block_data(self, i2c_addr, register, force=None):
        data = self.do_mock_read(i2c_addr, register, is_block=True)
        return data[1:data[0]+1]

    def write_block_data(self, i2c_addr, register, data, force=None):
        self.do_mock_write(i2c_addr, register, bytes(data), is_block=True)

    def read_i2c_block_data(self, i2c_addr, register, length, force=None):
        data = self.do_mock_read(i2c_addr, register, is_block=True)
        data = data + bytes([data[-1]] * 32)
        return data[0:length] # For some reason this doesn't start at 1

    def write_i2c_block_data(self, i2c_addr, register, data, force=None):
        self.do_mock_write(i2c_addr, register, bytes(data), is_block=True)

    def i2c_rdwr(self, *i2c_msgs):
        data = None
        register = None
        is_read = False
        for msg in i2c_msgs:
            if msg.flags == 1:
                register = msg.buf[0]
            else:
                is_read = True
        # msg stays assigned from last iteration
        if is_read:
            data = self.do_mock_read(msg.addr, register,
              is_block=self.expect_block)
            msg.buf = data
        else:
            self.do_mock_write(msg.addr, register, msg.buf[1:],
              is_block=self.expect_block)

    def add_mock_read(self, register, data):
        self.mock.add_read(register, data)

    def add_mock_read_sub(self, register, subreg, data):
        self.mock.add_read_sub(register, subreg, data)

    def add_mock_except(self, ex):
        self.mock_exception = ex

    def prep_expect_block(self, cmdinf):
        if cmdinf is None or 'type' not in cmdinf:
            resp_type = 'byte[]'
        elif 'resp_location' in cmdinf:
            resp_type = 'byte[]'
        else:
            resp_type = cmdinf['type']
        self.expect_block = (resp_type.startswith("byte[") or
          resp_type.startswith("string") or resp_type.endswith("_blk"))

    def prep_mock_read(self, cmd, subcmd=None):
        cmdinf = SBS_CMD_INFO[cmd]
        if 'subcmd_infos' in cmdinf:
            subcmdinf = sbs_subcommand_get_info(cmd, subcmd)
            self.prep_expect_block(subcmdinf)
            self.mock.prep_read_sub(cmd, cmdinf, subcmd, subcmdinf)
        else:
            self.prep_expect_block(cmdinf)
            self.mock.prep_read(cmd, cmdinf)

    def do_mock_read(self, i2c_addr, register, is_block=False):
        data = self.mock.do_read(i2c_addr, register)
        if is_block: data = bytes([len(data)]) + data
        if is_block and self.pec:
            whole_packet = smbus_recreate_read_packet_data(i2c_addr,
              register, data)
            pec = crc8_ccitt_compute(whole_packet)
            data = data + bytes([pec])
        return data

    def prep_mock_write(self, cmd, subcmd=None):
        cmdinf = SBS_CMD_INFO[cmd]
        if 'subcmd_infos' in cmdinf:
            subcmdinf = sbs_subcommand_get_info(cmd, subcmd)
            self.mock.prep_write_sub(cmd, cmdinf, subcmd, subcmdinf)
        else:
            self.mock.prep_write(cmd, cmdinf)

    def do_mock_write(self, i2c_addr, register, value, is_block=False):
        if self.mock_exception is not None:
            ex = self.mock_exception
            self.mock_exception = None
            raise ex
        self.mock.do_write(i2c_addr, register, value)


def crc8_ccitt_byte(crc, dt):
    """ Add one byte to smbus PEC crc-8 calculation
    """
    ncrc = crc ^ dt
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


def str_exception_with_type(ex):
    if type(ex).__name__ not in str(ex):
        return "{}: {}".format(type(ex).__name__,str(ex))
    return str(ex)


def is_ti_bq_chip(chip):
    """ Returns whether the chip is Texas Instruments BQ chip

    Also gives True if the chip awaits auto-detection.
    """
    return chip.name.startswith("BQ") or chip == CHIP_TYPE.AUTO


def type_str_value_length(type_str):
    m = re.match(r'(byte|string)\[([0-9]+|0x[0-9a-fA-F]+)\]', type_str)
    if m:
        return int(m.group(2),0)
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
  if isinstance(cmd, enum.Enum):
      register = cmd.value
  else:
      register = int(cmd)
  data = bytes([(dev_addr << 1) + 0, register, (dev_addr << 1) + 1]) + \
    bytes(resp_data)
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
    global i2c_msg
    m = re.match(r'(smbus|i2c):([0-9]+)', bus_str)
    if m:
        po.api_type = str(m.group(1))
        bus_index = int(m.group(2),0)
        if po.dry_run:
            bus = SMBusMock(bus_index)
            bus.pec = True
            if po.api_type == "i2c":
                class i2c_msg(i2c_msg_mock):
                    pass
            return
        import smbus2
        bus = smbus2.SMBus(bus_index)
        bus.pec = True
        if po.api_type == "i2c":
            from smbus2 import i2c_msg
        return
    raise ValueError("Unrecognized bus definition")


def smbus_close():
    """ Closes the System Managememnt Bus over I2C interface
    """
    global bus
    bus.close()
    bus = None


def smbus_write_raw(bus, dev_addr, b, po):
    if (po.verbose > 2):
        print("Raw write: DATA={}".format(
          " ".join('{:02x}'.format(x) for x in b)))

    if po.api_type == "i2c":
        if callable(getattr(bus, "i2c_rdwr", None)):
            use_api_type = "i2c"
        else:
            print("No real raw write supported; using smbus write")
            use_api_type = "smbus"
    else:
        use_api_type = po.api_type

    if use_api_type == "smbus":
        # Try to send the raw data using normal smbus API
        orig_pec = bus.pec
        try:
            bus.pec = False
            if len(b) in (2,3):
                (v,) = struct.unpack('<H', bytearray(bytes(b[1:]) + b'\0')[0:2])
                bus.write_word_data(dev_addr, b[0], v)
            else:
                raise NotImplementedError(
                  "No way of sending such raw data via smbus api")
        finally:
            bus.pec = orig_pec
    elif use_api_type == "i2c":
        part_write = i2c_msg.write(dev_addr, b)
        bus.i2c_rdwr(part_write)
    else:
        raise NotImplementedError("Unsupported bus API type '{}'".format(po.api_type))


def smbus_read_word(bus, dev_addr, cmd, resp_type, po):
    """ Read 16-bit integer from SMBus command, using READ_WORD protocol.
    """
    if po.api_type == "smbus":
        v = bus.read_word_data(dev_addr, cmd.value)
        if (po.verbose > 2):
            print("Raw {} response: 0x{:x}".format(cmd.name, v))
        if v < 0 or v > 65535:
            raise ValueError((
              "Received value of command {} is beyond type {} bounds"
              ).format(cmd.name,resp_type))
        if resp_type in ("int16",): # signed type support
            if v > 32767:
                v -= 65536
    elif po.api_type == "i2c":
        part_write = i2c_msg.write(dev_addr, [cmd.value])
        part_read = i2c_msg.read(dev_addr, 2 + (1 if bus.pec else 0))
        bus.i2c_rdwr(part_write, part_read)
        b = bytes(part_read)
        if (po.verbose > 2):
            print("Raw {} response: {}".format(cmd.name,
              " ".join('{:02x}'.format(x) for x in b)))
        if len(b) > 2:
            whole_packet = smbus_recreate_read_packet_data(dev_addr, cmd, b[0:2])
            pec = crc8_ccitt_compute(whole_packet)
            if b[2] != pec:
                raise ValueError((
                  "Received {} from command {} with wrong PEC checksum"
                  ).format(resp_type,cmd.name))
        v = bytes_to_type_str(b[0:2], resp_type)
    else:
        raise NotImplementedError("Unsupported bus API type '{}'"
          .format(po.api_type))
    return v


def smbus_read_long(bus, dev_addr, cmd, resp_type, po):
    """ Read 32-bit integer from SMBus command, reading just 4 bytes.
    """
    if po.api_type == "smbus":
        b = bus.read_i2c_block_data(dev_addr, cmd.value, 4)
    elif po.api_type == "i2c":
        part_write = i2c_msg.write(dev_addr, [cmd.value])
        part_read = i2c_msg.read(dev_addr, 4 + (1 if bus.pec else 0))
        bus.i2c_rdwr(part_write, part_read)
        b = bytes(part_read)
    else:
        raise NotImplementedError("Unsupported bus API type '{}'"
          .format(po.api_type))

    if (po.verbose > 2):
        print("Raw {} response: {}".format(cmd.name,
          " ".join('{:02x}'.format(x) for x in b)))

    if len(b) > 4:
        whole_packet = smbus_recreate_read_packet_data(dev_addr, cmd, b[0:4])
        pec = crc8_ccitt_compute(whole_packet)
        if b[4] != pec:
            raise ValueError((
              "Received {} from command {} with wrong PEC checksum"
              ).format(resp_type,cmd.name))
    return bytes_to_type_str(b, resp_type)


def smbus_read_block_for_basecmd(bus, dev_addr, cmd, basecmd_name, resp_type, po):
    """ Read block from cmd, use basecmd_name for logging

    Needed because request cmd isn't always clearly identifying what we're reading.
    """
    expect_len = type_str_value_length(resp_type)
    # Try reading expected length first
    if po.api_type == "smbus":
        # 32 is SMBus 2.0 limit, it is enforced by Linux kernel I2C module
        expect_len = min(expect_len + 1 + (1 if bus.pec else 0), 32)
        b = bus.read_i2c_block_data(dev_addr, cmd.value, expect_len)
    elif po.api_type == "i2c":
        # 36 = 32 sbs max len +2 subcmd +1 length, +1 PEC
        expect_len = min(expect_len + 1 + (1 if bus.pec else 0), 36)
        part_write = i2c_msg.write(dev_addr, [cmd.value])
        part_read = i2c_msg.read(dev_addr, expect_len)
        bus.i2c_rdwr(part_write, part_read)
        b = bytes(part_read)
    else:
        raise NotImplementedError("Unsupported bus API type '{}'".format(po.api_type))

    # block starts with 1-byte lenght
    if (len(b) < 1):
        raise ValueError((
          "Received {} from command {} is too short to even have length"
          ).format(resp_type,basecmd_name))

    # check if we meet the expected length restriction
    if len(b) >= b[0] + 1:
        pass # length expectations met
    elif po.api_type == "smbus":
        # 32 is SMBus 2.0 limit, it is enforced by Linux kernel I2C module
        expect_len = 32
        b = bus.read_i2c_block_data(dev_addr, cmd.value, expect_len)
        if len(b) == 32 and b[0] in (32,33,34,):
            # We've lost last bytes; but there is no other way - accept
            # the truncated message. Otherwise communicating messages
            # >  31-byte would just not work
            if (po.verbose > 0):
                print("Warning: Response truncated because of Smbus 2.0 constrains; adding zeros")
            b += b'\0' * (b[0]-31)
    elif po.api_type == "i2c":
        # 36 = 32 sbs max len +2 subcmd +1 length, +1 PEC
        expect_len = 32 + 2 + 1 + (1 if bus.pec else 0)
        part_write = i2c_msg.write(dev_addr, [cmd.value])
        part_read = i2c_msg.read(dev_addr, expect_len)
        bus.i2c_rdwr(part_write, part_read)
        b = bytes(part_read)
    else:
        raise NotImplementedError("Unsupported bus API type '{}'"
          .format(po.api_type))

    if (po.verbose > 2):
        print("Raw {} response: {}".format(basecmd_name,
          " ".join('{:02x}'.format(x) for x in b)))

    if len(b) < b[0] + 1:
        raise ValueError("Received {} from command {} has invalid length"
          .format(resp_type,basecmd_name))

    # check PEC crc-8 byte (unless the packet was so long that we didn't receive it)
    if len(b) >= b[0] + 2:
        whole_packet = smbus_recreate_read_packet_data(dev_addr, cmd, b[0:b[0]+1])
        pec = crc8_ccitt_compute(whole_packet)
        if b[b[0]+1] != pec:
            raise ValueError("Received {} from command {} with wrong PEC checksum"
              .format(resp_type,basecmd_name))

    # prepare data part of the message
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
    if po.api_type == "smbus":
        if val_type in ("int16",): # signed type support
            if v < 0:
                v += 65536
        if v < 0 or v > 65535:
            raise ValueError((
              "Value to write for command {} is beyond type {} bounds"
              ).format(cmd.name,val_type))
        if (po.verbose > 2):
            print("Write {}: {:02x} WORD=0x{:x}".format(cmd.name, cmd.value, v))
        bus.write_word_data(dev_addr, cmd.value, v)
    elif po.api_type == "i2c":
        b = type_str_to_bytes(v, val_type, endian="le")
        if (po.verbose > 2):
            print("Write {}: CMD={:02x} WORD={}".format(cmd.name,
              cmd.value, " ".join('{:02x}'.format(x) for x in b)))
        if bus.pec:
            whole_packet = smbus_recreate_write_packet_data(dev_addr, cmd, b)
            pec = crc8_ccitt_compute(whole_packet)
            b = bytes([cmd.value]) + b + bytes([pec])
        else:
            b = bytes([cmd.value]) + b
        part_write = i2c_msg.write(dev_addr, b)
        bus.i2c_rdwr(part_write)
    else:
        raise NotImplementedError("Unsupported bus API type '{}'".format(po.api_type))


def smbus_write_long(bus, dev_addr, cmd, v, val_type, po):
    if po.api_type == "smbus":
        if val_type in ("int32",): # signed type support
            if v < 0:
                v += 0x100000000
        if v < 0 or v > 0xFFFFFFFF:
            raise ValueError((
              "Value to write for command {} is beyond type {} bounds"
              ).format(cmd.name,val_type))
        if (po.verbose > 2):
            print("Write {}: {:02x} LONG=0x{:x}".format(cmd.name, cmd.value, v))
        bus.write_dword_data(dev_addr, cmd.value, v)
    elif po.api_type == "i2c":
        b = type_str_to_bytes(v, val_type, endian="le")
        if (po.verbose > 2):
            print("Write {}: CMD={:02x} LONG={}".format(cmd.name,
              cmd.value, " ".join('{:02x}'.format(x) for x in b)))
        if bus.pec:
            whole_packet = smbus_recreate_write_packet_data(dev_addr, cmd, b)
            pec = crc8_ccitt_compute(whole_packet)
            b = bytes([cmd.value]) + b + bytes([pec])
        else:
            b = bytes([cmd.value]) + b
        part_write = i2c_msg.write(dev_addr, b)
        bus.i2c_rdwr(part_write)
    else:
        raise NotImplementedError("Unsupported bus API type '{}'".format(po.api_type))


def smbus_write_block_for_basecmd(bus, dev_addr, cmd, v, basecmd_name, val_type, po):
    """ Write block to cmd, use basecmd_name for logging
    """
    b = v
    if po.api_type == "smbus":
        if (po.verbose > 2):
            print("Write {}: {:02x} BLOCK={}".format(basecmd_name,
              cmd.value, " ".join('{:02x}'.format(x) for x in b)))
        bus.write_block_data(dev_addr, cmd.value, b)
    elif po.api_type == "i2c":
        if (po.verbose > 2):
            print("Write {}: CMD={:02x} BLOCK={}".format(basecmd_name,
              cmd.value, " ".join('{:02x}'.format(x) for x in b)))
        if bus.pec:
            whole_packet = smbus_recreate_write_packet_data(dev_addr, cmd, bytes([len(b)]) + b)
            pec = crc8_ccitt_compute(whole_packet)
            b = bytes([cmd.value,len(b)]) + b + bytes([pec])
        else:
            b = bytes([cmd.value,len(b)]) + b
        part_write = i2c_msg.write(dev_addr, b)
        bus.i2c_rdwr(part_write)
    else:
        raise NotImplementedError("Unsupported bus API type '{}'".format(po.api_type))


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


def smbus_read_raw_block_by_writing_word_subcmd(bus, dev_addr, cmd, subcmd, resp_type, resp_cmd, resp_wait, po):
    """ Read raw value of a sub-command, performing subcmd selection write first.

    Used to access ManufacturerAccess sub-commands of the battery.
    Returns bytes array received in response, without converting the type.
    """
    # write sub-command to ManufacturerAccess
    smbus_write_word(bus, dev_addr, cmd, subcmd.value, "uint16", po)
    # Check if sleep needed inbetween requests
    if resp_wait > 0:
        time.sleep(resp_wait)
    # This function should never be called for void type; if it was, error out
    if resp_type == "void":
        raise TypeError("Reading should not be called for a void response type")
    basecmd_name = "{}.{}".format(cmd.name,subcmd.name)
    v = smbus_read_block_for_basecmd(bus, dev_addr, resp_cmd, basecmd_name, resp_type, po)
    return v


def smbus_write_raw_block_by_writing_word_subcmd(bus, dev_addr, cmd, subcmd, v, resp_type, resp_cmd, resp_wait, po):
    """ Write raw value of a sub-command, performing subcmd selection word write first.

    Used to access ManufacturerAccess sub-commands of the battery.
    Expects value to already be bytes array ready for sending.
    """
    # write sub-command to ManufacturerAccess
    smbus_write_word(bus, dev_addr, cmd, subcmd.value, "uint16", po)
    # Check if sleep needed inbetween requests
    if resp_wait > 0:
        time.sleep(resp_wait)
    # If the type to store is void, meaning we're writing to trigger switch - that's all
    if resp_type == "void":
        return
    basecmd_name = "{}.{}".format(cmd.name,subcmd.name)
    smbus_write_block_for_basecmd(bus, dev_addr, resp_cmd, v, basecmd_name, resp_type, po)


def smbus_read_raw_block_by_writing_block_subcmd(bus, dev_addr, cmd, subcmd, resp_type, resp_cmd, resp_wait, po):
    """ Read raw value of a sub-command, performing subcmd selection block write first.

    Used to access ManufacturerBlockAccess sub-commands of the battery.
    Returns bytes array received in response, without converting the type.
    """
    # write sub-command to ManufacturerBlockAccess
    smbus_write_word_blk(bus, dev_addr, cmd, subcmd.value, "uint16_blk", po)
    # Check if sleep needed inbetween requests
    if resp_wait > 0:
        time.sleep(resp_wait)
    # This function should never be called for void type; if it was, error out
    if resp_type == "void":
        raise TypeError("Reading should not be called for a void response type")
    basecmd_name = "{}.{}".format(cmd.name,subcmd.name)
    v = smbus_read_block_for_basecmd(bus, dev_addr, resp_cmd, basecmd_name, resp_type, po)
    return v


def smbus_perform_unseal_bq_sha1_hmac(bus, dev_addr, cmd, subcmd, resp_type, resp_cmd, resp_wait, sec_key_hex, po):
    """ Execute Unseal or Full Access operation using SHA-1/HMAC algorithm, for BQ30 chips.
    """
    basecmd_name = "{}.{}".format(cmd.name,subcmd.name)
    if not resp_type.startswith("byte["):
        # Command with unexpected params - cannot perform the auth
        raise ValueError("Cannot perform SHA-1/HMAC auth with response type '{}'".format(resp_type))
    KD = bytes.fromhex(sec_key_hex)
    if len(KD) != 16:
        raise ValueError("Algorithm broken, length of unseal key KD is {} instead of {} bytes".format(len(KD),16))
    # write UnSealDevice/FullAccessDevice sub-command to ManufacturerAccess, then read 160-bit message M
    if po.dry_run:
        bus.prep_mock_read(cmd, subcmd)
    M = smbus_read_raw_block_by_writing_word_subcmd(bus, dev_addr, cmd, subcmd, resp_type, resp_cmd, resp_wait, po)
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
    # Write 160-bit hash HMAC2 to ManufacturerInput()/Authenticate() in the format
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

def smbus_perform_unseal_bq_2word_sckey(bus, dev_addr, cmd, resp_wait, sec_key_w0, sec_key_w1, vals, po):
    """ Execute Unseal or Full Access operation using 2 Word MA commands, for BQ40 chips.
    """
    subcmd0 = ImprovisedCommand(value=sec_key_w0, name="SecKeyWord{:x}".format(0))
    subcmd1 = ImprovisedCommand(value=sec_key_w1, name="SecKeyWord{:x}".format(1))
    basecmd_name = "{}.{}".format(cmd.name,subcmd0.name)
    # Unsealing is a two-step command, performed by writing the first word
    # of the unseal key to ManufacturerAccess() (MAC), followed by the second
    # word of the unseal key to ManufacturerAccess(). The two words must be
    # sent within 4 sec.
    subcmdinf = {
        'type'	: "void",
        'unit'	: {'scale':None, 'name':"hex"},
        'tiny_name'	: "SKeyUD",
        'desc'	: "Word of Security key.",
    }
    # Make sure the command isn't just one of known commands; would be bad to start triggering random things
    for ckcmd, ckcmdinfo in MANUFACTURER_BLOCK_ACCESS_CMD_BQ_INFO.items():
        ckcmd_range = 1
        if 'cmd_array' in ckcmdinfo:
            ckcmd_range = ckcmdinfo['cmd_array']
        if (subcmd0.value >= ckcmd.value) and (subcmd0.value < ckcmd.value + ckcmd_range):
            raise ValueError("First word of security key (0x{:04x}) cannot be valid MAC command".format(subcmd0.value))
    v = b''
    if True:
        if po.dry_run:
            bus.prep_mock_write(cmd, subcmd0)
        u = smbus_write_by_writing_word_subcmd_first(bus, dev_addr, cmd, subcmd0, subcmdinf, v, po)
    if True:
        if po.dry_run:
            bus.prep_mock_write(cmd, subcmd1)
        u = smbus_write_by_writing_word_subcmd_first(bus, dev_addr, cmd, subcmd1, subcmdinf, v, po)
    return

def smbus_read_block_val_by_writing_word_subcmd_first(bus, dev_addr, cmd, subcmd, resp_type, resp_cmd, resp_wait, po):
    """ Reads value of a sub-command which requires the subcmd selection write first.

    Converts the received bytes to properly typed value, based on resp_type.
    Handles retries, if neccessary.
    """
    basecmd_name = "{}.{}".format(cmd.name,subcmd.name)
    if (po.verbose > 2):
        print("Query {}: {:02x} WORD=0x{:x}".format(basecmd_name, cmd.value, subcmd.value))

    b = None
    for nretry in reversed(range(3)):
        try:
            b = smbus_read_raw_block_by_writing_word_subcmd(bus, dev_addr, cmd, subcmd, resp_type, resp_cmd, resp_wait, po)
        except Exception as ex:
            if (nretry > 0) and (
              (isinstance(ex, OSError) and ex.errno in (5,121,))
              # 5 = Input/output error, sometimes just happens
              # 121 = I/O error, usually means no ACK
              ):
                if (po.verbose > 2):
                    print("Retrying due to error: "+str_exception_with_type(ex))
                pass
            else:
                raise
        if b is None:
            time.sleep(0.25)
            continue
        break

    v = bytes_to_type_str(b, resp_type, "le")

    return v


def smbus_write_block_val_by_writing_word_subcmd_first(bus, dev_addr, cmd, subcmd, v, stor_type, stor_cmd, stor_wait, po):
    """ Writes value to a sub-command which requires the subcmd selection write first.

    Converts the value v to proper bytes array for write, based on stor_type.
    Handles retries, if neccessary.
    """
    basecmd_name = "{}.{}".format(cmd.name,subcmd.name)
    if (po.verbose > 2):
        print("Store {}: {:02x} WORD=0x{:x}".format(basecmd_name, cmd.value, subcmd.value))

    b = type_str_to_bytes(v, stor_type, "le")

    for nretry in reversed(range(1)):
        try:
            smbus_write_raw_block_by_writing_word_subcmd(bus, dev_addr, cmd, subcmd, b, stor_type, stor_cmd, stor_wait, po)
        except Exception as ex:
            if (nretry > 0) and (
              (isinstance(ex, OSError) and ex.errno in (5,121,))
              # 5 = Input/output error, sometimes just happens
              # 121 = I/O error, usually means no ACK
              ):
                if (po.verbose > 2):
                    print("Retrying due to error: "+str_exception_with_type(ex))
                pass
            else:
                raise
        if b is None:
            time.sleep(0.25)
            continue
        break

    return


def smbus_read_macblock_val_by_writing_block_subcmd_first(bus, dev_addr, cmd, subcmd, resp_type, resp_cmd, resp_wait, po):
    """ Reads value of a sub-command which requires the subcmd selection write first, and expects sub-cmd at start of output.

    Converts the received bytes to properly typed value, based on resp_type.
    Handles retries, if neccessary.
    """
    basecmd_name = "{}.{}".format(cmd.name,subcmd.name)
    if (po.verbose > 2):
        print("Query {}: {:02x} WORD=0x{:x}".format(basecmd_name, cmd.value, subcmd.value))

    b = None
    expect_len = type_str_value_length(resp_type)
    full_resp_type = "byte[{}]".format(expect_len+2)
    for nretry in reversed(range(3)):
        try:
            full_b = smbus_read_raw_block_by_writing_block_subcmd(bus, dev_addr, cmd, subcmd, full_resp_type, resp_cmd, resp_wait, po)
            subcmd_num = bytes_to_type_str(full_b[:2], "uint16", "le")
            if subcmd_num != subcmd.value:
                raise ValueError("Read claims the subcmd was 0x{:x} instead of 0x{:x}".format(subcmd_num,subcmd.value))
            b = full_b[2:]
        except Exception as ex:
            if (nretry > 0) and (
              (isinstance(ex, OSError) and ex.errno in (5,121,)) or
              # 5 = Input/output error, sometimes just happens
              # 121 = I/O error, usually means no ACK
              isinstance(ex, ValueError)
              ):
                if (po.verbose > 2):
                    print("Retrying due to error: "+str_exception_with_type(ex))
                pass
            else:
                raise
        if b is None:
            time.sleep(0.25)
            continue
        break


    v = bytes_to_type_str(b, resp_type, "le")

    return v


def smbus_write_macblock_val_adding_block_subcmd_first(bus, dev_addr, cmd, subcmd, v, stor_type, stor_wait, po):
    """ Writes value to a sub-command which requires the subcmd written at start of the data.

    Converts the value v to proper bytes array for write, based on stor_type.
    Handles retries, if neccessary.
    """
    basecmd_name = "{}.{}".format(cmd.name,subcmd.name)
    if (po.verbose > 2):
        print("Store {}: {:02x} WORD=0x{:x}".format(basecmd_name, cmd.value, subcmd.value))

    b = type_str_to_bytes(v, stor_type, "le")
    v = type_str_to_bytes(subcmd.value, "uint16", "le") + b[1:]
    full_stor_type = "byte[{}]".format(len(v))

    for nretry in reversed(range(1)):
        try:
            smbus_write_block_for_basecmd(bus, dev_addr, cmd, v, basecmd_name, full_stor_type, po)
        except Exception as ex:
            if (nretry > 0) and (
              (isinstance(ex, OSError) and ex.errno in (5,121,))
              # 5 = Input/output error, sometimes just happens
              # 121 = I/O error, usually means no ACK
              ):
                if (po.verbose > 2):
                    print("Retrying due to error: "+str_exception_with_type(ex))
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

    Returns the value as either a number or byte array, depending on type.
    """
    if po.dry_run:
        bus.prep_mock_read(cmd)

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
                raise ValueError("Command {} type {} not supported in simple read".format(cmd.name,resp_type))
        except Exception as ex:
            if (nretry > 0) and (
              (isinstance(ex, OSError) and ex.errno in (5,121,)) or
              # 5 = Input/output error, sometimes just happens
              # 121 = I/O error, usually means no ACK
              (isinstance(ex, ValueError)) # invalid length or checksum
              ):
                if (po.verbose > 2):
                    print("Retrying due to error: "+str_exception_with_type(ex))
                pass
            else:
                raise
        if v is None:
            time.sleep(0.25)
            continue
        break

    if (resp_unit['scale'] is not None) and (resp_unit['scale'] != 1):
        if isinstance(v, int) or isinstance(v, float):
            v *= resp_unit['scale']
        else:
            print("Warning: Cannot apply scaling to non-numeric value of {} command".format(cmd.name))
    return v, resp_unit['name']


def smbus_write_simple(bus, dev_addr, cmd, v, val_type, val_unit, retry_count, po):
    """ Writes value of simple command to the battery.
    """
    if (val_unit['scale'] is not None) and (val_unit['scale'] != 1):
        if isinstance(v, int) or isinstance(v, float):
            if val_type in ("float","float_blk",):
                v = v / val_unit['scale']
            else:
                v = v // val_unit['scale']
        else:
            raise ValueError("Cannot apply scaling to non-numeric value of {} command".format(cmd.name))

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
        raise ValueError("Command {} type {} not supported in simple write".format(cmd.name,val_type))

    return val_unit['name']


def parse_sbs_command_value(cmd, subcmdinf, v, u, po):
    """ Parse compound values to get list of sub-values
    """
    cmdinf = SBS_CMD_INFO[cmd]
    if (u == "bitfields"):
        # We only support bitfields on integer value
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
        # We only support struct on byte array value
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
    return uname not in ("boolean", "hex", "hexver", "dec", "dec02", "dec04", "date547", "str", "bitfields", "struct",)


def command_value_to_string(cmdinf, subcmdinf, u, v, po):
    if u in ("bitfields","struct","hex",):
        if isinstance(v, list) or isinstance(v, bytes):
            return "hex:" + "".join('{:02x}'.format(x) for x in v), u
        else:
            if 'nbits' in subcmdinf:
                val_len = (subcmdinf['nbits']+3) // 4
            elif 'type' in subcmdinf:
                val_len = 2*type_str_value_length(subcmdinf['type'])
            else:
                val_len = 2*type_str_value_length(cmdinf['type'])
            return "0x{:0{}x}".format(v,val_len), u
    if u == "hexver":
        if isinstance(v, list) or isinstance(v, bytes):
            return ".".join('{:02x}'.format(x) for x in v), u
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
            return fmt_val[0:len(fmt_val)-1], u
    if u in ("dec02","dec04",):
        return "{:{}d}".format(v,u[u.index('0'):]), u
    if u == "K": # Temperature in Kelvin - convert to degC
        return "{:.2f}".format(v - 273.15), "degC"
    if u == "date547":
        return "{:d}-{:02d}-{:02d}".format(1980 + ((v>>9)&0x7f), (v>>5)&0x0f, (v)&0x1f), "date"
    if u in ("str",):
        return "{}".format(bytes(v)), u
    return "{}".format(v), u


def print_sbs_command_subfield_value(fld, lstfld, fields_info, name_width, po):
    fldinf = fields_info[fld]
    fld_short_desc = fldinf['desc'].split('.')[0]
    val = lstfld['val']
    # Do not show fields which have no read access, unless somehow they're non-zero
    if ("r" not in fldinf['access']) and (val == 0):
        return
    # Prepare the value for formatting
    fmt_val, fld_uname = command_value_to_string({'type':"byte[1]"}, fldinf, lstfld['uname'], val, po)
    # Prepare the unit (or replace it with short name for flags)
    if (not is_printable_value_unit(fld_uname)) and ('tiny_name' in fldinf):
        fld_uname = "[{}]".format(fldinf['tiny_name'])
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
                fldt['color'] = 34 if ("r" not in fldinf['access']) else 31 if val != 0 else 32
            else:
                if isinstance(val, list) or isinstance(val, bytes):
                    fldt['str'] = "{}={}".format(fldinf['tiny_name'],"".join('{:02x}'.format(x) for x in val))
                elif isinstance(val, float):
                    fldt['str'] = "{}={:g}".format(fldinf['tiny_name'],val)
                else:
                    fldt['str'] = "{}={:x}".format(fldinf['tiny_name'],val)
                fldt['color'] = 30 if ("r" not in fldinf['access']) else 37
            fldt['nbits'] = fldinf['nbits']
            field_strings.append(fldt)
        field_lines.append(field_strings)
    for field_strings in field_lines:
        line_str = []
        for i, fldt in enumerate(field_strings):
            use_width = cell_width * (fldt['nbits']//bit_per_cell) - 2
            line_str.append("\x1b[1;{}m[{:>{}s}]".format(fldt['color'], fldt['str'], use_width))
        print("".join(line_str),'\x1b[0m')


def print_sbs_command_value_cust_inf_basecmd(cmd, cmdinf, subcmd, subcmdinf, v, l, s, u, basecmd_name, name_width, po):
    if 'desc' in subcmdinf:
        short_desc = subcmdinf['desc'].split('.')[0]
    else:
        short_desc = cmdinf['desc'].split('.')[0]

    if name_width < 1:
        name_width = 1
    if True:
        fmt_val, fld_uname = command_value_to_string(cmdinf, subcmdinf, u, v, po)
        if (not is_printable_value_unit(fld_uname)) and ('tiny_name' in subcmdinf):
            fld_uname = "[{}]".format(subcmdinf['tiny_name'])
        print("{:{}s}\t{}\t{}\t{}".format(basecmd_name+":", name_width, fmt_val, fld_uname, short_desc))
        if (po.explain):
            print("Description: {}".format(subcmdinf['desc'] if 'desc' in subcmdinf else cmdinf['desc']))

    if u in ("bitfields","struct",):
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
    pass


def print_sbs_command_value_cust_inf(cmd, cmdinf, subcmd, subcmdinf, response, opts, name_width, po):
    v = response['val']
    l = response['list']
    s = response['sinf']
    u = response['uname']

    # If reading from array-like command, hand-craft our own which includes the shift
    if 'cmd_shift' in opts:
        cmd = sbs_command_add_shift(cmd, cmdinf, opts['cmd_shift'], po)

    if subcmd is not None:
        # If reading from array-like command, hand-craft our own which includes the shift
        if 'subcmd_shift' in opts:
            subcmd = sbs_command_add_shift(subcmd, subcmdinf, opts['subcmd_shift'], po)

    if subcmd is not None:
        basecmd_name = re.sub('[^A-Z0-9]', '', cmd.name) + '.' + subcmd.name
    else:
        basecmd_name = cmd.name

    print_sbs_command_value_cust_inf_basecmd(cmd, cmdinf, subcmd, subcmdinf, v, l, s, u, basecmd_name, name_width, po)


def print_sbs_command_value(cmd, subcmd, response, opts, name_width, po):
    cmdinf = SBS_CMD_INFO[cmd]
    subcmdinf = {}
    if subcmd is not None:
        subcmdinf = sbs_subcommand_get_info(cmd, subcmd)

    print_sbs_command_value_cust_inf(cmd, cmdinf, subcmd, subcmdinf, response, opts, name_width, po)


def sbs_command_add_shift(cmd, cmdinf, cmd_shift, po):
    """ Adds shift to array-like command

    When reading from array-like command, we need to hand-craft our own 'cmd' which includes the shift.
    """
    if 'cmd_array' not in cmdinf:
        raise ValueError("Tried to add shift to non-array command '{}'".format(cmd.name))
    cmd_array_len = cmdinf['cmd_array']
    if (cmd_shift < 0) or (cmd_shift >= cmd_array_len):
        raise ValueError("Command {} array shift {} out of bounds".format(cmd.name, cmd_shift))
    return ImprovisedCommand(value=cmd.value+cmd_shift, name="{}{}".format(cmd.name, cmd_shift))


def sbs_subcommand_get_info(cmd, subcmd):
    cmdinf = SBS_CMD_INFO[cmd]
    subcmdinf = {}
    if 'subcmd_infos' in cmdinf:
        for subgrp in cmdinf['subcmd_infos']:
            if subcmd in subgrp.keys():
                subcmdinf = subgrp[subcmd]
                break
    return subcmdinf


def sbs_command_check_access(cmd, cmdinf, opts, acc_type, po):
    """ Checks if given command allows given access type
    """
    if cmdinf['getter'] in ("write_word_subcommand","write_word_subcmd_mac_block",):
        can_access = sum(("w" in accstr) for accstr in cmdinf['access_per_seal'])
        if can_access == 0:
            return False
        subcmd = opts['subcmd']
        subcmdinf = sbs_subcommand_get_info(cmd, subcmd)
        if 'access_per_seal' in subcmdinf:
            can_access = sum((acc_type in accstr) for accstr in subcmdinf['access_per_seal'])
    else:
        can_access = sum((acc_type in accstr) for accstr in cmdinf['access_per_seal'])
    return (can_access > 0)


def smbus_read_by_writing_word_subcmd_first(bus, dev_addr, cmd, subcmd, subcmdinf, po):
    """ Reads value of a sub-command by writing the subcmd index, then reading response location.

    This is used to access ManufacturerAccess sub-commands of the battery.
    Handles value scaling and its conversion to bytes. Handles retries as well.
    """
    resp_type = subcmdinf['type']
    if 'resp_location' in subcmdinf:
        resp_cmd = subcmdinf['resp_location']
    else:
        resp_cmd = None
    if 'resp_wait' in subcmdinf:
        resp_wait = subcmdinf['resp_wait']
    else:
        resp_wait = 0

    if po.dry_run:
        bus.prep_mock_read(cmd, subcmd)

    if (resp_type.startswith("byte[") or resp_type.startswith("string") or resp_type.endswith("_blk")):
        v = smbus_read_block_val_by_writing_word_subcmd_first(bus, dev_addr, cmd, subcmd, resp_type, resp_cmd, resp_wait, po)
    else:
        raise ValueError("Command {}.{} type {} not supported in sub-command read".format(cmd.name,subcmd.name,resp_type))

    resp_unit = subcmdinf['unit']
    if (resp_unit['scale'] is not None) and (resp_unit['scale'] != 1):
        if isinstance(v, int) or isinstance(v, float):
            v *= resp_unit['scale']
        else:
            print("Warning: Cannot apply scaling to non-numeric value of {} command".format(cmd.name))

    return v, resp_unit['name']


def smbus_write_by_writing_word_subcmd_first(bus, dev_addr, cmd, subcmd, subcmdinf, v, po):
    """ Write value of a sub-command by writing the subcmd index, then writing to resp_location.

    This is used to access ManufacturerAccess sub-commands of the battery.
    Handles value scaling and its conversion to bytes. Handles retries as well.
    """
    stor_type = subcmdinf['type']
    if 'resp_location' in subcmdinf:
        stor_cmd = subcmdinf['resp_location']
    else:
        stor_cmd = None
    if 'resp_wait' in subcmdinf:
        stor_wait = subcmdinf['resp_wait']
    else:
        stor_wait = 0

    stor_unit = subcmdinf['unit']
    if (stor_unit['scale'] is not None) and (stor_unit['scale'] != 1):
        if isinstance(v, int) or isinstance(v, float):
            if stor_type in ("float","float_blk",):
                v = v / stor_unit['scale']
            else:
                v = v // stor_unit['scale']
        else:
            raise ValueError("Cannot apply scaling to non-numeric value of {}.{} command"
              .format(cmd.name,subcmd.name))

    if (stor_type.startswith("byte[") or stor_type.startswith("string") or
      stor_type.endswith("_blk") or stor_type in ("void",)):
        smbus_write_block_val_by_writing_word_subcmd_first(bus, dev_addr,
          cmd, subcmd, v, stor_type, stor_cmd, stor_wait, po)
    else:
        raise ValueError("Command {}.{} type {} not supported in sub-command write"
          .format(cmd.name, subcmd.name, stor_type))

    return stor_unit['name']


def smbus_read_macblk_by_writing_block_subcmd_first(bus, dev_addr, cmd, subcmd, subcmdinf, po):
    """ Reads value of a sub-command by writing the subcmd index,
    then reading response which starts with the sub-command.

    This is used to access ManufacturerBlockAccess sub-commands of the battery.
    Handles value scaling and its conversion to bytes. Handles retries as well.
    """
    resp_type = subcmdinf['type']
    if 'resp_location' in subcmdinf:
        resp_cmd = subcmdinf['resp_location']
    else:
        resp_cmd = cmd
    if 'resp_wait' in subcmdinf:
        resp_wait = subcmdinf['resp_wait']
    else:
        resp_wait = 0

    if po.dry_run:
        bus.prep_mock_read(cmd, subcmd)

    if (resp_type.startswith("byte[") or resp_type.startswith("string") or resp_type.endswith("_blk")):
        v = smbus_read_macblock_val_by_writing_block_subcmd_first(bus, dev_addr,
          cmd, subcmd, resp_type, resp_cmd, resp_wait, po)
    else:
        raise ValueError("Command {}.{} type {} not supported in block sub-command read"
          .format(cmd.name,subcmd.name,resp_type))

    resp_unit = subcmdinf['unit']
    if (resp_unit['scale'] is not None) and (resp_unit['scale'] != 1):
        if isinstance(v, int) or isinstance(v, float):
            v *= resp_unit['scale']
        else:
            print("Warning: Cannot apply scaling to non-numeric value of {} command".format(cmd.name))

    return v, resp_unit['name']


def smbus_write_macblk_with_block_subcmd_first(bus, dev_addr, cmd, subcmd, subcmdinf, v, po):
    """ Write value of a sub-command by writing block data with the subcmd index before actual content.

    This is used to access ManufacturerBlockAccess sub-commands of the battery.
    Handles value scaling and its conversion to bytes. Handles retries as well.
    """
    stor_type = subcmdinf['type']
    # Separate response command is only in use when reading MAC Block values
    if 'resp_wait' in subcmdinf:
        stor_wait = subcmdinf['resp_wait']
    else:
        stor_wait = 0

    stor_unit = subcmdinf['unit']
    if (stor_unit['scale'] is not None) and (stor_unit['scale'] != 1):
        if isinstance(v, int) or isinstance(v, float):
            if stor_type in ("float","float_blk",):
                v = v / stor_unit['scale']
            else:
                v = v // stor_unit['scale']
        else:
            raise ValueError("Cannot apply scaling to non-numeric value of {}.{} command"
              .format(cmd.name,subcmd.name))

    if (stor_type.startswith("byte[") or stor_type.startswith("string") or
      stor_type.endswith("_blk") or stor_type in ("void",)):
        smbus_write_macblock_val_adding_block_subcmd_first(bus, dev_addr,
          cmd, subcmd, v, stor_type, stor_wait, po)
    else:
        raise ValueError("Command {}.{} type {} not supported in block sub-command write"
          .format(cmd.name,subcmd.name,stor_type))

    return stor_unit['name']


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
        print("Reading {} command at addr=0x{:x}, cmd=0x{:x}, type={}, opts={}"
          .format(cmdinf['getter'], dev_addr, cmd.value, cmdinf['type'], opts))

    # If reading from array-like command, hand-craft our own which includes the shift
    if 'cmd_shift' in opts:
        cmd = sbs_command_add_shift(cmd, cmdinf, opts['cmd_shift'], po)

    if not sbs_command_check_access(cmd, cmdinf, opts, "r", po):
        print("Warning: Requested command does not provide read access; continuing anyway")

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

    elif cmdinf['getter'] in ("write_word_subcommand", "write_word_subcmd_mac_block",):
        if 'subcmd' not in opts.keys():
            raise ValueError("Command {} requires to provide sub-command".format(cmd.name))
        subcmd = opts['subcmd']
        subcmdinf = sbs_subcommand_get_info(cmd, subcmd)
        if len(subcmdinf) <= 0:
            raise ValueError("Command {}.{} missing definition".format(cmd.name,subcmd.name))

        # If reading from array-like sub-command, hand-craft our own which includes the shift
        if 'subcmd_shift' in opts:
            subcmd = sbs_command_add_shift(subcmd, subcmdinf, opts['subcmd_shift'], po)

        if cmdinf['getter'] == "write_word_subcommand":
            if ('resp_location' in subcmdinf) or (subcmdinf['type'] == "void"):
                # do write request with subcmd, then expect response at specific location
                v, u = smbus_read_by_writing_word_subcmd_first(bus, dev_addr, cmd, subcmd, subcmdinf, po)
            else:
                # do normal read, this is not a sub-command with different response location
                v, u = smbus_read_simple(bus, dev_addr, cmd, subcmdinf['type'], subcmdinf['unit'], retry_count, po)
        else: # cmdinf['getter'] == "write_word_subcmd_mac_block"
            # do write request with subcmd, then expect block response at specific location starting with subcmd
            v, u = smbus_read_macblk_by_writing_block_subcmd_first(bus, dev_addr, cmd, subcmd, subcmdinf, po)
        if (u == "struct"):
            subinfgrp = subcmdinf['struct_info']
        elif (u == "bitfields"):
            subinfgrp = subcmdinf['bitfields_info']

    else:
        raise ValueError("Command {} getter {} not supported".format(cmd.name,cmdinf['getter']))

    if not subinfgrp:
        # Structs and bitfields types have only one list of sub-fields, so use it
        if (u == "struct"):
            subinfgrp = cmdinf['struct_info']
        elif u == "bitfields":
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

    if not sbs_command_check_access(cmd, cmdinf, opts, "w", po):
        print("Warning: Requested command does not provide write access; continuing anyway")

    if cmdinf['getter'] == "simple":
        stor_unit = cmdinf['unit']
        u = smbus_write_simple(bus, dev_addr, cmd, v, cmdinf['type'], stor_unit, retry_count, po)

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
        u = smbus_write_simple(bus, dev_addr, cmd, v, cmdinf['type'], stor_unit, retry_count, po)

    elif cmdinf['getter'] in ("write_word_subcommand", "write_word_subcmd_mac_block",):
        if 'subcmd' not in opts.keys():
            raise ValueError("Command {} requires to provide sub-command".format(cmd.name))
        subcmd = opts['subcmd']
        subcmdinf = sbs_subcommand_get_info(cmd, subcmd)
        if len(subcmdinf) <= 0:
            raise ValueError("Command {}.{} missing definition".format(cmd.name,subcmd.name))

        if cmdinf['getter'] == "write_word_subcommand":
            if ('resp_location' in subcmdinf) or (subcmdinf['type'] == "void"):
                # do write request with subcmd, then do actual data write at specific location
                # trigger (type == "void") is supported by this function as well
                u = smbus_write_by_writing_word_subcmd_first(bus, dev_addr, cmd, subcmd, subcmdinf, v, po)
            else:
                # do normal write, this is not a sub-command with different value location
                u = smbus_write_simple(bus, dev_addr, cmd, v, subcmdinf['type'], subcmdinf['unit'], retry_count, po)

        else: # cmdinf['getter'] == "write_word_subcmd_mac_block"
            # write block with actual data preceded by subcmd
            u = smbus_write_macblk_with_block_subcmd_first(bus, dev_addr, cmd, subcmd, subcmdinf, v, po)

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


def sbs_read_firmware_version_bq_sealed(bus, dev_addr, po):
    """ Reads firmware version from BQ series chips

    Uses the sequence which allows to read the FW version even in sealed mode.
    The sequence used to do this read requires low-level access to the bus via
    i2c commands which allows sending raw data. Not all smbus wrappers
    available in various platforms have that support.

    This function is designed to work even if command list for specific BQ chip was not loaded.
    """
    cmd, subcmd = (SBS_COMMAND.ManufacturerAccess,MANUFACTURER_ACCESS_CMD_BQGENERIC.FirmwareVersion,)
    cmdinf = SBS_CMD_INFO[cmd]
    subcmdinf = sbs_subcommand_get_info(cmd, subcmd)

    # Do 3 commands which pretend to write oversized buffer; this needs to be done within 4 seconds
    for pre_cmd in (SBS_COMMAND.DeviceChemistry, SBS_COMMAND.ManufacturerName, SBS_COMMAND.DeviceChemistry):
        # We are sending messages which are not correct commands - we expect to receive no ACK
        # This is normal part of this routine; each of these commands should fail
        if po.dry_run:
            bus.add_mock_except(OSError(121,"Simulated error"))
        try:
            smbus_write_raw(bus, dev_addr, [pre_cmd.value, 62], po)
            # If somehow we got no exception, raise one
            raise ConnectionError("FW version acquire tripped as it expected NACK on a command")
        except OSError as ex:
            if ex.errno not in (121,): # I/O error - usually means no ACK - this is what we expect
                raise

    # Now ManufacturerData() will contain FW version data which we can read; wait to make sure it's ready
    time.sleep(0.35) # EV2300 software waits 350 ms; but documentation doesn't explicitly say to wait here
    if po.dry_run:
        bus.prep_mock_read(cmd, subcmd)

    resp_cmd  = SBS_COMMAND.OptionalMfgFunction5 # ManufacturerInput/Authenticate
    # Data length is 11 or 13 bytes
    v = smbus_read_block_for_basecmd(bus, dev_addr, resp_cmd, subcmd.name, subcmdinf['type'], po)

    return v


def smart_battery_bq_detect(vals, po):
    global bus

    v = None
    for nretry in reversed(range(3)):
        try:
            v = sbs_read_firmware_version_bq_sealed(bus, po.dev_address, po)
        except Exception as ex:
            if (nretry > 0) and (
              (isinstance(ex, OSError) and ex.errno in (5,121,)) or
              # 5 = Input/output error, sometimes just happens
              # 121 = I/O error, usually means no ACK
              (isinstance(ex, ValueError)) or # invalid length or checksum
              (isinstance(ex, ConnectionError)) # invalid response on initial writes
              ):
                if (po.verbose > 2):
                    print("Retrying due to error: "+str_exception_with_type(ex))
                pass
            else:
                raise
        # If we still have retries, accept only packets of certain length
        if (nretry > 0) and (v is not None) and (len(v) not in (11,13,)):
            if (po.verbose > 2):
                print("Retrying because received data looks suspicious")
            v = None
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
        print("Chip detection failded: {}".format(str_exception_with_type(ex)))
    if (po.verbose > 0):
        print("Auto-selected chip: {}, {}".format(chip.name,chip.__doc__))
    return chip


def smart_battery_system_subcmd_define(subcmd_val, cmdinf, data_len):
    if ('subcmd_infos' not in cmdinf) or (len(cmdinf['subcmd_infos']) < 1):
        raise ValueError("The sub-cmd 0x{:02x} cannot be user-defined within requested command".format(subcmd_val))
    subcmd = ImprovisedCommand(value=subcmd_val, name="UserSubCmd{:02x}".format(subcmd_val))
    subgrp = cmdinf['subcmd_infos'][0]
    subcmdinf = {
        'type'	: "byte[{}]".format(data_len),
        'unit'	: {'scale':None,'name':"hex"},
        'access_per_seal'	: ("rw","rw","rw",),
        'tiny_name'	: "UsrSC",
        'desc'	: "User defined sub-command {:02x}.".format(subcmd_val),
    }
    # Figure out response location
    resp_location = None
    for nxsubcmd, nxsubcmdinf in subgrp.items():
        if 'resp_location' not in nxsubcmdinf:
            continue
        resp_location = nxsubcmdinf['resp_location']
        break
    if resp_location is not None:
        subcmdinf['resp_location'] = resp_location
    # Add info dict on the new sub-command
    subgrp[subcmd] = subcmdinf
    return subcmd


def smart_battery_system_command_from_text(cmd_str, po, define_new=False):
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
    if cmd is None: # Recognize major SBS command by name
        if True:
            for curr_cmd in SBS_CMD_INFO.keys():
                if major_cmd_str == curr_cmd.name:
                    cmd = curr_cmd
                    break
    if cmd is None: # Recognize major SBS command by number
        try:
            major_cmd_int = int(major_cmd_str,0)
            for curr_cmd in SBS_CMD_INFO.keys():
                if major_cmd_int == curr_cmd.value:
                    cmd = curr_cmd
                    break
        except ValueError:
            pass
    if cmd is None:
        raise ValueError("The command '{}' is either invalid or not supported by chip".format(major_cmd_str))

    subcmd = None
    if subcmd_str is not None:
        cmdinf = SBS_CMD_INFO[cmd]
        if 'subcmd_infos' in cmdinf:
            if subcmd is None: # Recognize SBS sub-command by name
                if True:
                    for subgrp in cmdinf['subcmd_infos']:
                        for cur_subcmd in subgrp.keys():
                            if subcmd_str == cur_subcmd.name:
                                subcmd = cur_subcmd
                                break
                        if subcmd is not None:
                            break
            if subcmd is None: # Recognize SBS sub-command by number
                try:
                    subcmd_int = int(subcmd_str,0)
                    for subgrp in cmdinf['subcmd_infos']:
                        for cur_subcmd in subgrp.keys():
                            if subcmd_int == cur_subcmd.value:
                                subcmd = cur_subcmd
                                break
                        if subcmd is not None:
                            break
                except ValueError:
                    pass
            if subcmd is None and define_new: # Define new SBS sub-command
                try:
                    subcmd_int = int(subcmd_str,0)
                    if (po.verbose > 0):
                        print("Warning: Sub-command 0x{:02x} not recognized, creating user-definwd one".format(subcmd_int))
                    subcmd = smart_battery_system_subcmd_define(subcmd_int, cmdinf, 32)
                except ValueError:
                    pass

    if subcmd_str is not None and subcmd is None:
        raise ValueError("The sub-command '{}' is either invalid or not supported by chip".format(subcmd_str))

    return cmd, subcmd


def smart_battery_system_cmd_value_from_text(cmd, subcmd, nval_str, po):
    raise NotImplementedError('Converting the string value to cmd/subcmd type is not implemented.')


def smart_battery_system_address_space_from_text(knd_str, addr, po):
    """ Converts SBS address space name text to enum

    Requires chip to be identified to properly map commands
    which are not in base SBS specification.
    """
    knd = None
    if knd is None: # Recognize address space by name
        if True:
            for curr_knd in RAW_ADDRESS_SPACE_KIND_INFO.keys():
                if knd_str == curr_knd.name:
                    knd = curr_knd
                    break
    if knd is None:
        raise ValueError("The address space '{}' is either invalid or not supported by chip".format(knd_str))
    return knd


def smart_battery_system_last_error(bus, dev_addr, vals, po):
    """ Reads and prints value of last ERROR_CODE from the battery.
    """
    cmd = SBS_COMMAND.BatteryStatus
    subcmd = None
    fld = SBS_FLAG_BATTERY_STATUS.ERROR_CODE
    fldinf = SBS_BATTERY_STATUS_INFO[fld]
    val = None
    try:
        v, l, u, s = smbus_read(bus, dev_addr, cmd, {'subcmd': subcmd,'retry_count':1}, vals, po)
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


def smart_battery_system_info(cmd_str, vals, po):
    """ Prints info on the command/offces based on fields from its info dict.
    """
    cmd, subcmd = smart_battery_system_command_from_text(cmd_str, po)
    cmdinf = SBS_CMD_INFO[cmd]
    subcmdinf = sbs_subcommand_get_info(cmd, subcmd)

    if True:
        print("Command/offset:")
        if subcmd is None:
            print("  {} = 0x{:02x}".format(cmd.name,cmd.value))
        else:
            print("  {}.{} = 0x{:02x}.0x{:04x}".format(cmd.name,subcmd.name,cmd.value,subcmd.value))

        print("Access:")
        aps = subcmdinf['access_per_seal'] if 'access_per_seal' in subcmdinf else cmdinf['access_per_seal']
        if len(set(aps)) <= 1:
            print("  Always '{}'".format(aps[0].upper()))
        else:
            print("  Sealed '{}'; Unsealed  '{}'; Full Access  '{}'"
              .format(aps[0].upper(), aps[1].upper(), aps[2].upper()))
        gtr = subcmdinf['getter'] if 'getter' in subcmdinf else cmdinf['getter']

        if gtr == "simple":
            print("  Read/Write by simple SMBus operations")
        elif gtr == "unit_select_on_capacity_mode":
            print("  Read/Write by simple SMBus operations, but unit of the value depends on flags config")
        elif gtr == "write_word_subcommand":
            print("  Access by first writing sub-command word to {}".format(cmd.name))
        elif gtr == "write_word_subcmd_mac_block":
            print("  Access by writing sub-command; read in 2nd command, or append data to write (MAC block algorithm)")
        else:
            print("  Access by special method '{}'".format(gtr))

        print("Type:")
        vtype = subcmdinf['type'] if 'type' in subcmdinf else cmdinf['type']
        if vtype == "void":
            print("  There is no value field in read/Write operations, it works as trigger")
        else:
            print("  Read/Write value is of type '{}'".format(vtype))
        if gtr == "unit_select_on_capacity_mode":
            vunits = []
            if 'getter' in subcmdinf:
                for n in range(16):
                    if ('unit'+str(n)) not in subcmdinf:
                        break
                    vunits.append(subcmdinf['unit'+str(n)])
            else:
                for n in range(16):
                    if ('unit'+str(n)) not in cmdinf:
                        break
                    vunits.append(cmdinf['unit'+str(n)])
            vunit = {'scale': " / ".join(str(vu['scale']) for vu in vunits), 'name': " / ".join(vu['name'] for vu in vunits)}
        else:
            vunit = subcmdinf['unit'] if 'unit' in subcmdinf else cmdinf['unit']
        if vunit['name'] is None and vunit['scale'] is None:
            print("  The value has no unit or printing format preference")
        elif is_printable_value_unit(vunit):
            print("  Physical unit of the value is '{}' with value scaler {}".format(vunit['name'],vunit['scale']))
        else:
            print("  The value has no unit, but uses printing format '{}' with multiplier {}".format(vunit['name'],vunit['scale']))

        print("Description:")
        print(" ", subcmdinf['desc'] if 'desc' in subcmdinf else cmdinf['desc'])

    return


def smart_battery_system_read(cmd_str, vals, po):
    """ Reads and prints value of the command from the battery.
    """
    global bus
    cmd, subcmd = smart_battery_system_command_from_text(cmd_str, po, define_new=True)
    cmdinf = SBS_CMD_INFO[cmd]
    opts = {'subcmd': subcmd}
    v, l, u, s = smbus_read(bus, po.dev_address, cmd, opts, vals, po)
    response = {'val':v,'list':l,'sinf':s,'uname':u,}
    vals[cmd if subcmd is None else subcmd] = response
    print_sbs_command_value(cmd, subcmd, response, opts, 0, po)


def smart_battery_system_trigger(cmd_str, vals, po):
    """ Trigger a switch command within the battery.
    """
    global bus
    cmd, subcmd = smart_battery_system_command_from_text(cmd_str, po, define_new=True)
    if subcmd is not None:
        basecmd_name = re.sub('[^A-Z0-9]', '', cmd.name) + '.' + subcmd.name
    else:
        basecmd_name = cmd.name
    cmdinf = SBS_CMD_INFO[cmd]
    opts = {'subcmd': subcmd}
    v = b''
    try:
        u, s = smbus_write(bus, po.dev_address, cmd, v, opts, vals, po)
    except Exception as ex:
        print("{:{}s}\t{}\t{}\t{}".format(basecmd_name+":", 1, "trigger", "FAIL", str_exception_with_type(ex)))
        if (isinstance(ex, OSError)):
            smart_battery_system_last_error(bus, po.dev_address, vals, po)
        if (po.explain):
            print("Description: {}".format(cmdinf['desc']))
        raise RuntimeError("Trigger failed on command {}".format(basecmd_name))
    print("{:{}s}\t{}\t{}\t{}".format(basecmd_name+":", 1, "trigger", "SUCCESS", "Trigger switch write accepted"))


def smart_battery_system_write(cmd_str, nval_str, vals, po):
    """ Write value to a command within the battery.
    """
    global bus
    cmd, subcmd = smart_battery_system_command_from_text(cmd_str, po, define_new=True)
    if subcmd is not None:
        basecmd_name = re.sub('[^A-Z0-9]', '', cmd.name) + '.' + subcmd.name
    else:
        basecmd_name = cmd.name
    cmdinf = SBS_CMD_INFO[cmd]
    opts = {'subcmd': subcmd}
    v = smart_battery_system_cmd_value_from_text(cmd, subcmd, nval_str, po)
    try:
        u, s = smbus_write(bus, po.dev_address, cmd, v, opts, vals, po)
    except Exception as ex:
        print("{:{}s}\t{}\t{}\t{}".format(basecmd_name+":", 1, "write", "FAIL", str_exception_with_type(ex)))
        if (isinstance(ex, OSError)):
            smart_battery_system_last_error(bus, po.dev_address, vals, po)
        if (po.explain):
            print("Description: {}".format(cmdinf['desc']))
        raise RuntimeError("Write failed to command {}".format(basecmd_name))
    print("{:{}s}\t{}\t{}\t{}".format(cmd.name+":", 1, "write", "SUCCESS", "Value write accepted"))


def smart_battery_system_raw_read(knd_str, addr, val_type, vals, po):
    """ Reads and prints raw value from address space of the battery.
    """
    global bus
    knd = smart_battery_system_address_space_from_text(knd_str, addr, po)
    kndinf = RAW_ADDRESS_SPACE_KIND_INFO[knd]

    cmd, subcmd = (kndinf['read_cmd'],kndinf['read_subcmd'],)
    cmdinf = SBS_CMD_INFO[cmd]
    subcmd_shift = addr // kndinf['granularity']
    opts = {'subcmd': subcmd, 'subcmd_shift': subcmd_shift}
    v, l, u, s = smbus_read(bus, po.dev_address, cmd, opts, vals, po)
    response = {'val':v,'list':l,'sinf':s,'uname':u,}
    #vals[cmd if subcmd is None else subcmd] = response #TODO we need to store sub-index
    response_tot_len = len(v)

    # Create improvised data type if the user demanded
    if val_type not in ("byte[32]",):
        subcmd_pos = addr - subcmd_shift * kndinf['granularity']
        s = {}
        fld_nbytes = type_str_value_length(val_type)
        if subcmd_pos > 0:
            fld0 = ImprovisedCommand(value=0, name="UserVal{:02x}".format(0))
            s[fld0] = {
                'type'	: "byte[{}]".format(subcmd_pos),
                'unit'	: {'scale':None,'name':"hex"},
                'nbits'	: subcmd_pos * 8,
                'access'	: "-",
                'tiny_name'	: "BefUD",
                'desc'	: "Data before user field.",
            }
        if fld_nbytes > 0:
            fld = ImprovisedCommand(value=subcmd_pos*8, name="UserVal{:02x}".format(subcmd_pos))
            s[fld] = {
                'type'	: val_type,
                'unit'	: {'scale':None,'name':None},
                'nbits'	: fld_nbytes * 8,
                'access'	: "r",
                'tiny_name'	: "UsrDf",
                'desc'	: "User defined field.",
            }
            if val_type in ("uint8","uint16","uint32",):
                s[fld]['unit'] = {'scale':1,'name':"hex"}
            elif val_type in ("int8","int16","int32",):
                s[fld]['unit'] = {'scale':1,'name':"dec"}
            elif val_type.startswith("string["):
                s[fld]['unit'] = {'scale':None,'name':"str"}
        if subcmd_pos+fld_nbytes < response_tot_len:
            fld2 = ImprovisedCommand(value=(subcmd_pos+fld_nbytes)*8, name="UserVal{:02x}".format(subcmd_pos+fld_nbytes))
            s[fld2] = {
                'type'	: "byte[{}]".format(response_tot_len-subcmd_pos-fld_nbytes),
                'unit'	: {'scale':None,'name':"hex"},
                'nbits'	: (response_tot_len-subcmd_pos-fld_nbytes) * 8,
                'access'	: "-",
                'tiny_name'	: "AftUD",
                'desc'	: "Data after user field.",
            }
        u = "struct"
        l = parse_sbs_command_value(cmd, s, v, u, po)
        response = {'val':v,'list':l,'sinf':s,'uname':u,}

    print_sbs_command_value(cmd, subcmd, response, opts, 0, po)


def smart_battery_system_raw_write(knd_str, addr, val_type, nval_str, vals, po):
    """ Writes raw value to address space of the battery.
    """
    raise NotImplementedError('Writing raw data is not implemented.')


def smart_battery_system_raw_backup(knd_str, fname, vals, po):
    """ Reads raw data from address space of the battery, and stores in a file.
    """
    global bus
    addr = 0x0
    knd = smart_battery_system_address_space_from_text(knd_str, addr, po)
    kndinf = RAW_ADDRESS_SPACE_KIND_INFO[knd]

    cmd, subcmd = (kndinf['read_cmd'],kndinf['read_subcmd'],)
    subcmdinf = sbs_subcommand_get_info(cmd, subcmd)
    addrspace_tot_len = subcmdinf['cmd_array'] * kndinf['granularity']
    last_pct = -100

    with open(fname, "wb") as addrsp_file:
        while (addr < addrspace_tot_len):
            if (po.verbose > 0) and (addr * 100 // addrspace_tot_len - last_pct >= 5):
                last_pct = addr * 100 // addrspace_tot_len
                print("Raw read {}: address=0x{:04X} progress={:d}%".format(knd.name, addr, last_pct,))
            subcmd_shift = addr // kndinf['granularity']
            opts = {'subcmd': subcmd, 'subcmd_shift': subcmd_shift}
            v, l, u, s = smbus_read(bus, po.dev_address, cmd, opts, vals, po)
            response = {'val':v,'list':l,'sinf':s,'uname':u,}
            #vals[cmd if subcmd is None else subcmd] = response #TODO we need to store sub-index
            addrsp_file.write(v)
            addr += len(v)

    print("Raw read {}: done".format(knd.name,))


def smart_battery_system_raw_restore(knd_str, fname, vals, po):
    """ Writes raw data to address space of the battery, from a file.
    """
    from functools import partial
    global bus
    addr = 0x0
    knd = smart_battery_system_address_space_from_text(knd_str, addr, po)
    kndinf = RAW_ADDRESS_SPACE_KIND_INFO[knd]

    cmd, subcmd = (kndinf['read_cmd'],kndinf['read_subcmd'],)
    subcmdinf = sbs_subcommand_get_info(cmd, subcmd)
    addrspace_tot_len = subcmdinf['cmd_array'] * kndinf['granularity']
    last_pct = -100

    with open(fname, "rb") as addrsp_file:
        for v in iter(partial(addrsp_file.read, 32), b''):
            if (po.verbose > 0) and (addr * 100 // addrspace_tot_len - last_pct >= 5):
                last_pct = addr * 100 // addrspace_tot_len
                print("Raw write {}: address=0x{:04X} progress={:d}%".format(knd.name, addr, last_pct,))
            if (addr >= addrspace_tot_len):
                print("Warning: File size exceeds address space size; excessive data ignored")
                break
            subcmd_shift = addr // kndinf['granularity']
            opts = {'subcmd': subcmd, 'subcmd_shift': subcmd_shift}
            u, s = smbus_write(bus, po.dev_address, cmd, v, opts, vals, po)
            addr += len(v)

    print("Raw write {}: done".format(knd.name,))


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
        opts = {'subcmd': subcmd}
        try:
            v, l, u, s = smbus_read(bus, po.dev_address, cmd, opts, vals, po)
        except Exception as ex:
            print("{:{}s}\t{}\t{}\t{}".format(cmd.name+":", names_width, "n/a", "FAIL", str_exception_with_type(ex)))
            if (isinstance(ex, OSError)):
                smart_battery_system_last_error(bus, po.dev_address, vals, po)
            if (po.explain):
                print("Description: {}".format(cmdinf['desc']))
            continue
        response = {'val':v,'list':l,'sinf':s,'uname':u,}
        vals[cmd if subcmd is None else subcmd] = response
        print_sbs_command_value(cmd, subcmd, response, opts, names_width, po)
    return


def smart_battery_system_sealing(seal_str, vals, po):
    """ Change sealing state of the battery.
    """
    global bus

    if seal_str in SBS_SEALING:
        auth = SBS_SEALING[seal_str]['auth']
        cmd = SBS_SEALING[seal_str]['cmd']
        subcmd = SBS_SEALING[seal_str]['subcmd']
    else:
        raise ValueError("Unrecognized target seal state")

    if True:
        cmdinf = SBS_CMD_INFO[cmd]
    if subcmd is not None:
        subcmdinf = sbs_subcommand_get_info(cmd, subcmd)
        if len(subcmdinf) <= 0:
            raise ValueError("Command {}.{} missing definition".format(cmd.name,subcmd.name))
        resp_type = subcmdinf['type']
    else:
        subcmdinf = {}
        resp_type = "void"

    if 'resp_location' in subcmdinf:
        resp_cmd = subcmdinf['resp_location']
    else:
        resp_cmd = None
    if 'resp_wait' in subcmdinf:
        resp_wait = subcmdinf['resp_wait']
    else:
        resp_wait = 0

    checkcmd = SBS_SEALING["Check"]
    checkcmd_name = "{}.{}".format(checkcmd['cmd'].name,checkcmd['subcmd'].name)

    if auth == "SHA-1/HMAC":
        time.sleep(0.35)
        smbus_perform_unseal_bq_sha1_hmac(bus, po.dev_address,
          cmd, subcmd, resp_type, resp_cmd, resp_wait, po.sha1key, po)
        time.sleep(0.35)
    elif auth == "2-Word SCKey": # Two word key, where first word is written as MAC sub-command
        time.sleep(0.35)
        smbus_perform_unseal_bq_2word_sckey(bus, po.dev_address,
          cmd, resp_wait, (po.i32key) & 0xffff, (po.i32key>>16) & 0xffff, vals, po)
        time.sleep(0.35)
    else: # No auth required - sealing or checking status
        if resp_type == "void":
            smbus_write_raw_block_by_writing_word_subcmd(bus, po.dev_address,
              cmd, subcmd, b'', resp_type, resp_cmd, resp_wait, po)
        else:
            raise ValueError("No auth, but not void command; not sure what to do")

    smart_battery_system_read(checkcmd_name, vals, po)


def extract_r_commands_list():
    """ Create lists of commands: for read, and everything else (not read).
    """
    all_r_commands = []
    all_nr_commands = []
    for cmd, cmdinf in SBS_CMD_INFO.items():
        can_access = sum(("r" in accstr) for accstr in cmdinf['access_per_seal'])
        if 'subcmd_infos' in cmdinf:
            for subgrp in cmdinf['subcmd_infos']:
                for subcmd, subcmdinf in subgrp.items():
                    if 'cmd_array' in subcmdinf:
                        all_nr_commands.append("{}.{}".format(cmd.name,subcmd.name))
                        continue
                    sub_can_access = sum(("r" in accstr) for accstr in subcmdinf['access_per_seal'])
                    if sub_can_access > 0:
                        all_r_commands.append("{}.{}".format(cmd.name,subcmd.name))
                    else:
                        all_nr_commands.append("{}.{}".format(cmd.name,subcmd.name))
        elif 'cmd_array' in cmdinf:
            all_nr_commands.append(cmd.name)
        else:
            if can_access > 0:
                all_r_commands.append(cmd.name)
            else:
                all_nr_commands.append(cmd.name)
    return all_r_commands, all_nr_commands


def extract_w_commands_list():
    """ Create lists of commands: for write, and for trigger.
    """
    all_w_commands = []
    all_t_commands = []
    for cmd, cmdinf in SBS_CMD_INFO.items():
        can_access = sum(("w" in accstr) for accstr in cmdinf['access_per_seal'])
        if 'subcmd_infos' in cmdinf:
            for subgrp in cmdinf['subcmd_infos']:
                for subcmd, subcmdinf in subgrp.items():
                    if 'cmd_array' in subcmdinf:
                        continue
                    sub_can_access = sum(("w" in accstr) for accstr in subcmdinf['access_per_seal'])
                    if sub_can_access > 0:
                        if subcmdinf['type'] == "void":
                            all_t_commands.append("{}.{}".format(cmd.name,subcmd.name))
                        else:
                            all_w_commands.append("{}.{}".format(cmd.name,subcmd.name))
        elif 'cmd_array' in cmdinf:
            pass
        else:
            if can_access > 0:
                if cmdinf['type'] == "void":
                    all_t_commands.append(cmd.name)
                else:
                    all_w_commands.append(cmd.name)
    return all_w_commands, all_t_commands


def extract_raw_commands_list():
    """ Create lists of raw commands: for read and write.
    """
    raw_r_commands = []
    for knd, kndinf in RAW_ADDRESS_SPACE_KIND_INFO.items():
        can_access = sum(("r" in accstr) for accstr in kndinf['access_per_seal'])
        if True:
            if can_access > 0:
                raw_r_commands.append(knd.name)

    raw_w_commands = []
    for knd, kndinf in RAW_ADDRESS_SPACE_KIND_INFO.items():
        can_access = sum(("w" in accstr) for accstr in kndinf['access_per_seal'])
        if True:
            if can_access > 0:
                raw_w_commands.append(knd.name)
    return raw_r_commands, raw_w_commands


def parse_chip_type(s):
    """ Parses chip type string in known formats.
    """
    return s


def parse_addrspace_datatype(s):
    """ Parses command/offset string in known formats.
    """
    if s in ("int8", "uint8", "int16", "uint16", "int32", "uint32", "float",):
        return s

    if re.match(r'(byte|string)\[([0-9]+|0x[0-9a-fA-F]+)\]', s):
        return s

    raise argparse.ArgumentTypeError(" invalid choice: '{}' (see '--help' for a list)".format(s))


def parse_monitor_group(s):
    """ Parses monitor group string in known formats.
    """
    return s

driver_cache = dict()

def main(argv=sys.argv[1:]):
    """ Main executable function.

      Its task is to parse command line options and call a function which performs sniffing.
    """

    global driver_cache

    addrspace_datatypes = [ "int8", "uint8", "int16", "uint16", "int32", "uint32", "float", 'string[n]', 'byte[n]']

    parser = argparse.ArgumentParser(description=__doc__.split('.')[0])

    parser.add_argument('-b', '--bus', default="i2c:1", type=str,
            help=("I2C/SMBus bus device selection; 'smbus' will use OS API "
              "prepared for that protocol, while 'i2c' will use I2C messages, "
              "constructing SMBus frames manually; after a colon, bus number "
              "from your OS has to be provided (defaults to '%(default)s')"))

    parser.add_argument('-a', '--dev_address', default=0x0b, type=lambda x: int(x,0),
            help="target SBS device address (defaults to 0x%(default)x)")

    parser.add_argument('-c', '--chip', metavar='model', choices=[i.name for i in CHIP_TYPE],
            type=parse_chip_type,  default=CHIP_TYPE.AUTO.name,
            help="target chip model; one of: {:s} (defaults to '%(default)s')"
              .format(', '.join(i.name for i in CHIP_TYPE)))

    parser.add_argument("--dry-run", action='store_true',
            help="do not use real smbus device or do permanent changes")

    parser.add_argument('-v', '--verbose', action='count', default=0,
            help="increases verbosity level; max level is set by -vvv")

    subparser = parser.add_mutually_exclusive_group()

    subparser.add_argument('-s', '--short', action='store_true',
            help="display only minimal description of values; to be used by "
              "experienced users, who have no need for additional info")

    subparser.add_argument('-e', '--explain', action='store_true',
            help="explain each value by providing description from spec")

    parser.add_argument('--version', action='version', version="%(prog)s {version} by {author}"
              .format(version=__version__, author=__author__),
            help="display version information and exit")

    subparsers = parser.add_subparsers(dest='action', metavar='action',
            help="action to take", required=True)

    subpar_info = subparsers.add_parser('info',
            help=("displays information about specific command; when chip "
              "auto-detect is disabled, this action does not require SMBus "
              "connection; it just shows the shortened version of description "
              "from manual, which is included in the tool"))

    subpar_info.add_argument('command', metavar='command', type=str,
            help=("the command/offset name to show info about; "
              "use 'info-list' action to see supported commands"))

    subpar_info_list = subparsers.add_parser('info-list',
            help=("lists all commands on which 'info' action can be used; "
              "the list changes with selected chip type; when chip auto-detect "
              "is disabled, this action can be performed without connection"))

    subpar_read = subparsers.add_parser('read',
            help="read value from a single command/offset of the battery")

    subpar_read.add_argument('command', metavar='command', type=str,
            help=("the command/offset name to read from; "
              "use 'read-list' action to see supported commands"))

    subpar_read_list = subparsers.add_parser('read-list',
            help=("lists all commands on which 'read' action can be used; "
              "the list changes with selected chip type; when chip auto-detect "
              "is disabled, this action can be performed without connection"))

    subpar_trigger = subparsers.add_parser('trigger',
            help="write to a trigger, command/offset of the battery which acts as a switch")

    subpar_trigger.add_argument('command', metavar='command', type=str,
            help=("the command/offset name to trigger; "
              "use 'trigger-list' action to see supported commands"))

    subpar_trigger_list = subparsers.add_parser('trigger-list',
            help=("lists all commands on which 'trigger' action can be used; "
              "the list changes with selected chip type; when chip auto-detect "
              "is disabled, this action can be performed without connection"))

    subpar_write = subparsers.add_parser('write',
            help="write value to a single command/offset of the battery")

    subpar_write.add_argument('command', metavar='command', type=str,
            help=("the command/offset name to write to; "
              "use 'write-list' action to see supported commands"))

    subpar_write.add_argument('newvalue', metavar='value', type=str,
            help="new value to write to the command/offset")

    subpar_write_list = subparsers.add_parser('write-list',
            help=("lists all commands on which 'write' action can be used; "
              "the list changes with selected chip type; when chip auto-detect "
              "is disabled, this action can be performed without connection"))

    subpar_raw_read = subparsers.add_parser('raw-read',
            help="read raw value from an address space of the battery")

    subpar_raw_read.add_argument('addrspace', metavar='addrspace', type=str,
            help=("the address space name to read from; use 'raw-read-list' "
              "action to see supported addrspaces"))

    subpar_raw_read.add_argument('address', metavar='address', type=lambda x: int(x,0),
            help="address within the space to read from")

    subpar_raw_read.add_argument('dttype', metavar='datatype', type=parse_addrspace_datatype,
            help="data type at target offset; one of: {:s}".format(', '.join(addrspace_datatypes)))


    subpar_raw_read_list = subparsers.add_parser('raw-read-list',
            help=("lists all address spaces on which 'raw-read' action can be used; "
              "the list changes with selected chip type; when chip auto-detect "
              "is disabled, this action can be performed without connection"))

    subpar_raw_write = subparsers.add_parser('raw-write',
            help="write raw value into an address space of the battery")

    subpar_raw_write.add_argument('addrspace', metavar='addrspace', type=str,
            help=("the address space name to write into; use 'raw-write-list' "
              "action to see supported addrspaces"))

    subpar_raw_write.add_argument('address', metavar='address', type=lambda x: int(x,0),
            help="address within the space to write to")

    subpar_raw_write.add_argument('dttype', metavar='datatype', type=parse_addrspace_datatype,
            help="data type at target offset; one of: {:s}".format(', '.join(addrspace_datatypes)))

    subpar_raw_write.add_argument('newvalue', metavar='value', type=str,
            help="new value to write at the address")

    subpar_raw_write_list = subparsers.add_parser('raw-write-list',
            help=("lists all address spaces on which 'raw-write' action can be used; "
              "the list changes with selected chip type; when chip auto-detect "
              "is disabled, this action can be performed without connection"))

    subpar_raw_backup = subparsers.add_parser('raw-backup',
            help="read whole raw address space and store it in a file")

    subpar_raw_backup.add_argument('addrspace', metavar='addrspace', type=str,
            help=("the address space name to backup; use 'raw-read-list' "
              "action to see supported addrspaces"))

    subpar_raw_backup.add_argument('fname', metavar='filename', type=str,
            help="name of the file to write to")

    subpar_raw_restore = subparsers.add_parser('raw-restore',
            help="write whole raw address space using values from a file")

    subpar_raw_restore.add_argument('addrspace', metavar='addrspace', type=str,
            help=("the address space name to restore; use 'raw-write-list' "
              "action to see supported addrspaces"))

    subpar_raw_restore.add_argument('fname', metavar='filename', type=str,
            help="name of the file to read from")

    subpar_monitor = subparsers.add_parser('monitor',
            help=("monitor value of a group of commands/offsets; "
              "just reads all of the values from a group"))

    subpar_monitor.add_argument('cmdgroup', metavar='group',
            choices=[i.name for i in MONITOR_GROUP], type=parse_monitor_group,
            help="group of commands/offsets; one of: {:s}".format(', '.join(i.name for i in MONITOR_GROUP)))

    subpar_sealing = subparsers.add_parser('sealing',
            help="change sealing state of BQ chip")

    sealing_choices = ("Unseal", "Seal", "FullAccess",)
    subpar_sealing.add_argument('sealstate', metavar='state', choices=sealing_choices, type=str,
            help="new sealing state; one of: {:s}".format(', '.join(sealing_choices)))

    subpar_sealing.add_argument('--sha1key', default='0123456789abcdeffedcba9876543210', type=str,
            help="device key for SHA-1/HMAC Authentication (defaults to '%(default)s')")

    subpar_sealing.add_argument('--i32key', default=None, type=lambda x: int(x,0),
            help=("device key for 32-bit integer (two word) Authentication "
              "(defaults to 0x{:08x} for FullAccess, otherwise to 0x{:08x})"
              ).format(0xffffffff,0x36720414))

    po = parser.parse_args(argv)

    vals = {}

    po.chip = CHIP_TYPE.from_name(po.chip)

    po.offline_mode = False

    # If specific chip type was provided, then some actions do not require SMBus connection
    if po.action in ('info','info-list','read-list','trigger-list','write-list',) and (po.chip != CHIP_TYPE.AUTO):
        if (po.verbose > 0):
            print("Using offline mode")
        po.offline_mode = True
    else:
        if (po.verbose > 0):
            print("Opening {}".format(po.bus))
        smbus_open(po.bus, po)

    # Re-init global variables; then they are modified by specific chip driver, do it before detection
    reset_default_driver(po)
    if po.chip == CHIP_TYPE.AUTO:
        po.chip = smart_battery_detect(vals, po)

    if po.chip in driver_cache:
        chip_file_code = driver_cache[po.chip]
        exec(chip_file_code)
    else:
        if po.chip in (CHIP_TYPE.BQ30z50, CHIP_TYPE.BQ30z55, CHIP_TYPE.BQ30z554,):
            fnames = ["comm_sbs_chips/{}.py".format("BQ30z554")]
        elif po.chip in (CHIP_TYPE.BQ40z50,):
            fnames = ["comm_sbs_chips/{}.py".format("BQ40z50")]
        elif po.chip in ("SBS",):    # default
            pass # do nothing, already loaded with reset_default_driver(po)
        else:
            fnames = ["comm_sbs_chips/{}.py".format(po.chip.name)]
        driver_cache[po.chip] = list()
        for fname in fnames:
            try:
                with open(fname, "rb") as source_file:
                    chip_file_code = compile(source_file.read(), fname, "exec")
                if (po.verbose > 0):
                    print("Importing {}".format(fname))
                exec(chip_file_code)
                driver_cache[po.chip] = chip_file_code
            except IOError:
                print("Warning: Could not open chip definition file '{}'".format(fname))

    if po.action == 'info':
        smart_battery_system_info(po.command, vals, po)
    elif po.action == 'info-list':
        if (po.explain > 0):
            print("Display info can be used on any of the following commands:")
        all_r_commands, all_nr_commands = extract_r_commands_list()
        print("\n".join(sorted(all_r_commands+all_nr_commands)))
    elif po.action == 'read-list':
        if (po.explain > 0):
            print("Read value can be used on any of the following commands:")
        all_r_commands, all_nr_commands = extract_r_commands_list()
        print("\n".join(sorted(all_r_commands)))
    elif po.action == 'trigger-list':
        if (po.explain > 0):
            print("Trigger can be sent to any of the following commands:")
        all_w_commands, all_t_commands = extract_w_commands_list()
        print("\n".join(sorted(all_t_commands)))
    elif po.action == 'write-list':
        if (po.explain > 0):
            print("Write value can be used on any of the following commands:")
        all_w_commands, all_t_commands = extract_w_commands_list()
        print("\n".join(sorted(all_w_commands)))
    elif po.action == 'raw-read-list':
        if (po.explain > 0):
            print("Raw Read can be used on any of the following address spaces:")
        raw_r_commands, raw_w_commands = extract_raw_commands_list()
        print("\n".join(sorted(raw_r_commands)))
    elif po.action == 'raw-write-list':
        if (po.explain > 0):
            print("Raw Write can be used on any of the following address spaces:")
        raw_r_commands, raw_w_commands = extract_raw_commands_list()
        print("\n".join(sorted(raw_w_commands)))
    elif po.action == 'read':
        smart_battery_system_read(po.command, vals, po)
    elif po.action == 'trigger':
        smart_battery_system_trigger(po.command, vals, po)
    elif po.action == 'write':
        smart_battery_system_write(po.command, po.newvalue, vals, po)
    elif po.action == 'raw-read':
        smart_battery_system_raw_read(po.addrspace, po.address,
          po.dttype, vals, po)
    elif po.action == 'raw-write':
        smart_battery_system_raw_write(po.addrspace, po.address,
          po.dttype, po.newvalue, vals, po)
    elif po.action == 'raw-backup':
        smart_battery_system_raw_backup(po.addrspace, po.fname, vals, po)
    elif po.action == 'raw-restore':
        smart_battery_system_raw_restore(po.addrspace, po.fname, vals, po)
    elif po.action == 'monitor':
        smart_battery_system_monitor(po.cmdgroup, vals, po)
    elif po.action == 'sealing':
        if po.i32key is None:
            if po.sealstate == "FullAccess":
                po.i32key = 0xffffffff
            else:
                po.i32key = 0x36720414
        smart_battery_system_sealing(po.sealstate, vals, po)
    else:
        raise NotImplementedError("Unsupported or missing command.")

    if not po.offline_mode:
        smbus_close()


if __name__ == '__main__':
    try:
        main()
    except Exception as ex:
        eprint("Error: "+str_exception_with_type(ex))
        if 0: raise
        sys.exit(10)
