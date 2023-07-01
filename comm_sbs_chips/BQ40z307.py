#!/usr/bin/env false
# -*- coding: utf-8 -*-

""" Smart Battery System chip definition.

Implemented based on:
* Empirical testing of the chip
* Used BQ40z50 as a documented base

Compatible chips:
BQ40z307

For list of devices on which these definitons were tested,
see comments within `comm_sbs_bqctrl.py`.
"""

class SBS_COMMAND_BQ40(DecoratedEnum):
    """ Commands used in BQ40 family SBS chips
    """
    Authenticate			= SBS_COMMAND.OptionalMfgFunction5.value # 0x2f
    Cell3Voltage			= SBS_COMMAND.OptionalMfgFunction4.value # 0x3c
    Cell2Voltage			= SBS_COMMAND.OptionalMfgFunction3.value
    Cell1Voltage			= SBS_COMMAND.OptionalMfgFunction2.value
    Cell0Voltage			= SBS_COMMAND.OptionalMfgFunction1.value
    ManufacturerBlockAccess	= 0x44
    SafetyAlert				= 0x50
    SafetyStatus			= 0x51
    PFAlert					= 0x52
    PFStatus				= 0x53
    OperationStatus			= 0x54
    ChargingStatus			= 0x55
    GaugingStatus			= 0x56
    ManufacturingStatus		= 0x57
    TURBO_FINAL				= 0x5a
    LifetimeDataBlock1		= 0x60
    LifetimeDataBlock2		= 0x61
    LifetimeDataBlock3		= 0x62
    ManufacturerInfo		= 0x70
    DAStatus1				= 0x71
    DAStatus2				= 0x72
    GaugeStatus1			= 0x73
    GaugeStatus2			= 0x74
    GaugeStatus3			= 0x75
    CBStatus				= 0x76
    FilteredCapacity		= 0x78
    ManufacturerInfo2		= 0x7a


class MANUFACTURER_ACCESS_CMD_BQ40(DecoratedEnum):
    """ ManufacturerAccess sub-commands used in BQ40 family SBS chips
    """
    InstrFlashChecksum		= 0x04
    StaticDataFlashChecksum	= 0x05
    ChemicalID				= 0x06
    StaticChemDFSignature	= 0x08
    AllDFSignature			= 0x09
    ShutdownMode			= 0x10
    SleepMode				= 0x11
    DeviceResetOld			= 0x12
    AutoCCOfset				= 0x13
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
    LEDDisplayEnable		= 0x27
    LifetimeDataReset		= 0x28
    PermanentFailDataReset	= 0x29
    BlackBoxRecorderReset	= 0x2a
    LEDToggle				= 0x2b
    LEDDisplayPress			= 0x2c
    CalibrationMode			= 0x2d
    LifetimeDataFlush		= 0x2e
    LifetimeDataSpeedUpMode	= 0x2f
    SealDevice				= 0x30
    ROMModeLegacy			= 0x33
    SecurityKeys			= 0x35
    AuthenticationKey		= 0x37
    DeviceReset				= 0x41
    SafetyAlert				= 0x50
    SafetyStatus			= 0x51
    PFAlert					= 0x52
    PFStatus				= 0x53
    OperationStatus			= 0x54
    ChargingStatus			= 0x55
    GaugingStatus			= 0x56
    ManufacturingStatus		= 0x57
    LifetimeDataBlock1		= 0x60
    LifetimeDataBlock2		= 0x61
    LifetimeDataBlock3		= 0x62
    ManufacturerInfo		= 0x70
    DAStatus1				= 0x71
    DAStatus2				= 0x72
    GaugeStatus1			= 0x73
    GaugeStatus2			= 0x74
    GaugeStatus3			= 0x75
    CBStatus				= 0x76
    FilteredCapacity		= 0x78
    ManufacturerInfo2		= 0x7a
    ROMMode					= 0x0f00
    DataFlashAccess			= 0x4000
    ExitCalibOutputMode		= 0xf080
    OutputCCnADC			= 0xf081
    OutputShortCCnADCOffset	= 0xf082


class SBS_CMD_BQ_FIRMWARE_VERSION(DecoratedEnum):
    """ FirmwareVersion sub-command fields used in BQ40 family SBS chips
    """
    DeviceNumber			= 0x00
    FirmwareVersion			= 0x10
    FwBuildNumber			= 0x20
    FirmwareType			= 0x30
    ImpedanceTrackVersion	= 0x38
    ReservedRR				= 0x48
    ReservedEE				= 0x58

SBS_CMD_BQ_FIRMWARE_VERSION_INFO = {
    SBS_CMD_BQ_FIRMWARE_VERSION.DeviceNumber : {
        'type'	: "uint16",
        'endian': "be",
        'unit'	: {'scale':1,'name':"hex"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DevN",
        'desc'	: ("Type of this IC device. The same as returned by DeviceType."),
    },
    SBS_CMD_BQ_FIRMWARE_VERSION.FirmwareVersion : {
        'type'	: "byte[2]",
        'unit'	: {'scale':1,'name':"hexver"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "FwVer",
        'desc'	: ("Version number of the firmware."),
    },
    SBS_CMD_BQ_FIRMWARE_VERSION.FwBuildNumber : {
        'type'	: "uint16",
        'endian': "be",
        'unit'	: {'scale':1,'name':"dec04"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "FwBld",
        'desc'	: ("Build number of the firmware."),
    },
    SBS_CMD_BQ_FIRMWARE_VERSION.FirmwareType : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"hex"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "FwTyp",
        'desc'	: ("Type of the firmware. Usually used to differentiate "
          "pre-release firmwares from production ones."),
    },
    SBS_CMD_BQ_FIRMWARE_VERSION.ImpedanceTrackVersion : {
        'type'	: "byte[2]",
        'unit'	: {'scale':1,'name':"hexver"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "ITVer",
        'desc'	: ("Impedance Track sw implementation version. Impedance "
          "Track Algorithm with Cell Balancing During Rest is Texas "
          "Instuments trademarked functionality."),
    },
    SBS_CMD_BQ_FIRMWARE_VERSION.ReservedRR : {
        'type'	: "byte[2]",
        'unit'	: {'scale':1,'name':"hex"},
        'nbits'	: 16,
        'access'	: "-",
        'tiny_name'	: "ResR",
        'desc'	: ("Field RR reserved by manufacturer. Either unused "
          "or used for internal purposes."),
    },
    SBS_CMD_BQ_FIRMWARE_VERSION.ReservedEE : {
        'type'	: "byte[2]",
        'unit'	: {'scale':1,'name':"hex"},
        'nbits'	: 16,
        'optional'	: True,
        'access'	: "-",
        'tiny_name'	: "ResE",
        'desc'	: ("Field EE reserved by manufacturer. Either unused "
          "or used for internal purposes."),
    },
}


class SBS_CMD_BQ_LIFETIME_DATA_BLOCK1(DecoratedEnum):
    """ LifetimeDataBlock1 sub-command fields used in BQ40 family SBS chips
    """
    MaxCellVoltage1			= 0x000
    MaxCellVoltage2			= 0x010
    MaxCellVoltage3			= 0x020
    MaxCellVoltage4			= 0x030
    MinCellVoltage1			= 0x040
    MinCellVoltage2			= 0x050
    MinCellVoltage3			= 0x060
    MinCellVoltage4			= 0x070
    MaxDeltaCellVoltage		= 0x080

SBS_CMD_BQ_LIFETIME_DATA_BLOCK1_INFO = {
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxCellVoltage1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MaxV1",
        'desc'	: ("Max Cell 1 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxCellVoltage2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MaxV2",
        'desc'	: ("Max Cell 2 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxCellVoltage3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MaxV3",
        'desc'	: ("Max Cell 3 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxCellVoltage4 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MaxV4",
        'desc'	: ("Max Cell 4 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MinCellVoltage1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MinV1",
        'desc'	: ("Min Cell 1 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MinCellVoltage2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MinV2",
        'desc'	: ("Min Cell 2 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MinCellVoltage3 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MinV3",
        'desc'	: ("Min Cell 3 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MinCellVoltage4 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MinV4",
        'desc'	: ("Min Cell 4 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxDeltaCellVoltage : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MaxDV",
        'desc'	: ("Max Delta Cell Voltage. That is, the max cell "
          "imbalance voltage."),
    },
}


class SBS_CMD_BQ_LIFETIME_DATA_BLOCK2(DecoratedEnum):
    """ LifetimeDataBlock2 sub-command fields used in BQ40 family SBS chips
    """
    NoOfShutdowns			= 0x000
    NoOfPartialResets		= 0x008
    NoOfFullResets			= 0x010
    NoOfWDTResets			= 0x018

SBS_CMD_BQ_LIFETIME_DATA_BLOCK2_INFO = {
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoOfShutdowns : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nShtdn",
        'desc'	: ("Number of Shutdowns."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoOfPartialResets : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nPaRst",
        'desc'	: ("Number of Partial Resets."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoOfFullResets : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nFuRst",
        'desc'	: ("Number of Full Resets."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoOfWDTResets : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nWDRst",
        'desc'	: ("Number of Resets by Watchdog Timer."),
    },
}


class SBS_CMD_BQ_LIFETIME_DATA_BLOCK3(DecoratedEnum):
    """ LifetimeDataBlock3 sub-command fields used in BQ40 family SBS chips
    """
    TotalFwRunTime			= 0x000
    TimeSpentInUT			= 0x010
    TimeSpentInLT			= 0x020
    TimeSpentInSTL			= 0x030
    TimeSpentInRT			= 0x040
    TimeSpentInSTH			= 0x050
    TimeSpentInHT			= 0x060
    TimeSpentInOT			= 0x070

SBS_CMD_BQ_LIFETIME_DATA_BLOCK3_INFO = {
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK3.TotalFwRunTime : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TotFRT",
        'desc'	: ("Total firmware Run Time."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK3.TimeSpentInUT : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TimeUT",
        'desc'	: ("Time Spent in Under Temperature."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK3.TimeSpentInLT : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TimeLT",
        'desc'	: ("Time Spent in Low Temperature."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK3.TimeSpentInSTL : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TimSTL",
        'desc'	: ("Time Spent in Standard Temp Low."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK3.TimeSpentInRT : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TimeRT",
        'desc'	: ("Time Spent in Recommended Temperature."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK3.TimeSpentInSTH : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TimSTH",
        'desc'	: ("Time Spent in Standard Temp High."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK3.TimeSpentInHT : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TimeHT",
        'desc'	: ("Time Spent in High Temperature."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK3.TimeSpentInOT : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TimeOT",
        'desc'	: ("Time Spent in Over Temperature."),
    },
}


class SBS_CMD_BQ_DA_STATUS1(DecoratedEnum):
    """ DAStatus1 sub-command fields used in BQ40 family SBS chips
    """
    CellVoltage0			= 0x000
    CellVoltage1			= 0x010
    CellVoltage2			= 0x020
    CellVoltage3			= 0x030
    BATVoltage				= 0x040
    PACKVoltage				= 0x050
    CellCurrent0			= 0x060
    CellCurrent1			= 0x070
    CellCurrent2			= 0x080
    CellCurrent3			= 0x090
    CellPower0				= 0x0a0
    CellPower1				= 0x0b0
    CellPower2				= 0x0c0
    CellPower3				= 0x0d0
    AllCellPower			= 0x0e0
    AveragePower			= 0x0f0

SBS_CMD_BQ_DA_STATUS1_INFO = {
    SBS_CMD_BQ_DA_STATUS1.CellVoltage0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Volt0",
        'desc'	: ("Cell Voltage 0."),
    },
    SBS_CMD_BQ_DA_STATUS1.CellVoltage1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Volt1",
        'desc'	: ("Cell Voltage 1."),
    },
    SBS_CMD_BQ_DA_STATUS1.CellVoltage2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Volt2",
        'desc'	: ("Cell Voltage 2."),
    },
    SBS_CMD_BQ_DA_STATUS1.CellVoltage3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Volt3",
        'desc'	: ("Cell Voltage 3."),
    },
    SBS_CMD_BQ_DA_STATUS1.BATVoltage : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "BatV",
        'desc'	: ("Voltage at the BAT pin. This is different than Voltage(), "
          "which is the sum of all the cell voltages."),
    },
    SBS_CMD_BQ_DA_STATUS1.PACKVoltage : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "PackV",
        'desc'	: ("PACK Voltage."),
    },
    SBS_CMD_BQ_DA_STATUS1.CellCurrent0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mA"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Curr0",
        'desc'	: ("Cell Current 0. Simultaneous current measured during "
          "Cell Voltage 0 measurement"),
    },
    SBS_CMD_BQ_DA_STATUS1.CellCurrent1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mA"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Curr1",
        'desc'	: ("Cell Current 1. Simultaneous current measured during "
          "Cell Voltage 1 measurement"),
    },
    SBS_CMD_BQ_DA_STATUS1.CellCurrent2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mA"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Curr2",
        'desc'	: ("Cell Current 2. Simultaneous current measured during "
          "Cell Voltage 2 measurement"),
    },
    SBS_CMD_BQ_DA_STATUS1.CellCurrent3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mA"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Curr3",
        'desc'	: ("Cell Current 3. Simultaneous current measured during "
          "Cell Voltage 3 measurement"),
    },
    SBS_CMD_BQ_DA_STATUS1.CellPower0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"cW"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Pwr0",
        'desc'	: ("Cell Power 0. Calculated using Cell Voltage 0 and "
          "Cell Current 0 data."),
    },
    SBS_CMD_BQ_DA_STATUS1.CellPower1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"cW"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Pwr1",
        'desc'	: ("Cell Power 1. Calculated using Cell Voltage 1 and "
          "Cell Current 1 data."),
    },
    SBS_CMD_BQ_DA_STATUS1.CellPower2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"cW"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Pwr2",
        'desc'	: ("Cell Power 2. Calculated using Cell Voltage 2 and "
          "Cell Current 2 data."),
    },
    SBS_CMD_BQ_DA_STATUS1.CellPower3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"cW"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Pwr3",
        'desc'	: ("Cell Power 3. Calculated using Cell Voltage 3 and "
          "Cell Current 3 data."),
    },
    SBS_CMD_BQ_DA_STATUS1.AllCellPower : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"cW"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "AllPwr",
        'desc'	: ("Power calculated by Voltage() x Current()."),
    },
    SBS_CMD_BQ_DA_STATUS1.AveragePower : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"cW"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "AvgPwr",
        'desc'	: ("Average Power."),
    },
}


class SBS_CMD_BQ_DA_STATUS2(DecoratedEnum):
    """ DAStatus2 sub-command fields used in BQ40 family SBS chips
    """
    IntTemperature			= 0x000
    TS1Temperature			= 0x010
    TS2Temperature			= 0x020
    TS3Temperature			= 0x030
    TS4Temperature			= 0x040
    CellTemperature			= 0x050
    FETTemperature			= 0x060

SBS_CMD_BQ_DA_STATUS2_INFO = {
    SBS_CMD_BQ_DA_STATUS2.IntTemperature : {
        'type'	: "uint16",
        'unit'	: {'scale':0.1,'name':"K"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "IntTm",
        'desc'	: ("Int Temperature."),
    },
    SBS_CMD_BQ_DA_STATUS2.TS1Temperature : {
        'type'	: "uint16",
        'unit'	: {'scale':0.1,'name':"K"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TS1Tm",
        'desc'	: ("Temp Sensor 1 Temperature."),
    },
    SBS_CMD_BQ_DA_STATUS2.TS2Temperature : {
        'type'	: "uint16",
        'unit'	: {'scale':0.1,'name':"K"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TS2Tm",
        'desc'	: ("Temp Sensor 2 Temperature."),
    },
    SBS_CMD_BQ_DA_STATUS2.TS3Temperature : {
        'type'	: "uint16",
        'unit'	: {'scale':0.1,'name':"K"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TS3Tm",
        'desc'	: ("Temp Sensor 3 Temperature."),
    },
    SBS_CMD_BQ_DA_STATUS2.TS4Temperature : {
        'type'	: "uint16",
        'unit'	: {'scale':0.1,'name':"K"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TS4Tm",
        'desc'	: ("Temp Sensor 4 Temperature."),
    },
    SBS_CMD_BQ_DA_STATUS2.CellTemperature : {
        'type'	: "uint16",
        'unit'	: {'scale':0.1,'name':"K"},
        'nbits'	: 16,
        'optional'	: True,
        'access'	: "r",
        'tiny_name'	: "CelTm",
        'desc'	: ("Cell Temperature."),
    },
    SBS_CMD_BQ_DA_STATUS2.FETTemperature : {
        'type'	: "uint16",
        'unit'	: {'scale':0.1,'name':"K"},
        'nbits'	: 16,
        'optional'	: True,
        'access'	: "r",
        'tiny_name'	: "FETTm",
        'desc'	: ("FET Temperature."),
    },
}


class SBS_CMD_BQ_GAUGE_STATUS1(DecoratedEnum):
    """ GaugeStatus1 sub-command fields used in BQ40 family SBS chips
    """
    TrueRemQ				= 0x000
    TrueRemE				= 0x010
    InitialQ				= 0x020
    InitialE				= 0x030
    TrueFCCQ				= 0x040
    TrueFCCE				= 0x050
    TempSim					= 0x060
    TempAmbient				= 0x070
    RaScale0				= 0x080
    RaScale1				= 0x090
    RaScale2				= 0x0a0
    RaScale3				= 0x0b0
    CompRes0				= 0x0c0
    CompRes1				= 0x0d0
    CompRes2				= 0x0e0
    CompRes3				= 0x0f0

SBS_CMD_BQ_GAUGE_STATUS1_INFO = {
    SBS_CMD_BQ_GAUGE_STATUS1.TrueRemQ : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mAh"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TruRemQ",
        'desc'	: ("True remaining capacity from sim. The value in mAh "
          "computed by IT simulation before any filtering or smoothing "
          "function. This value can be negative or higher than FCC."),
    },
    SBS_CMD_BQ_GAUGE_STATUS1.TrueRemE : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"cWh"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TruRemE",
        'desc'	: ("True remaining energy from sim. The value in cWh "
          "computed by IT simulation before any filtering or smoothing "
          "function. This value can be negative or higher than FCC."),
    },
    SBS_CMD_BQ_GAUGE_STATUS1.InitialQ : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mAh"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "InitQ",
        'desc'	: ("Initial capacity calculated from IT simulation."),
    },
    SBS_CMD_BQ_GAUGE_STATUS1.InitialE : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"cWh"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "InitE",
        'desc'	: ("Initial energy calculated from IT simulation."),
    },
    SBS_CMD_BQ_GAUGE_STATUS1.TrueFCCQ : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mAh"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TruFCCQ",
        'desc'	: ("True full charge capacity from sim. The value computed "
          "by IT simulation without the effects of any smoothing function."),
    },
    SBS_CMD_BQ_GAUGE_STATUS1.TrueFCCE : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"cWh"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TruFCCE",
        'desc'	: ("True full charge energy from sim.  The value computed "
          "by IT simulation without the effects of any smoothing function."),
    },
    SBS_CMD_BQ_GAUGE_STATUS1.TempSim : {
        'type'	: "uint16",
        'unit'	: {'scale':0.1,'name':"K"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TempSim",
        'desc'	: ("Temperature during the last simulation run."),
    },
    SBS_CMD_BQ_GAUGE_STATUS1.TempAmbient : {
        'type'	: "uint16",
        'unit'	: {'scale':0.1,'name':"K"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TempAmb",
        'desc'	: ("Assumed ambient temperature used by sim. The current "
          "assumed ambient temperature used by the Impedance Track "
          "algorithm for thermal modeling."),
    },
    SBS_CMD_BQ_GAUGE_STATUS1.RaScale0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "RaScale0",
        'desc'	: ("Ra Table scaling factor of Cell 0."),
    },
    SBS_CMD_BQ_GAUGE_STATUS1.RaScale1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "RaScale1",
        'desc'	: ("Ra Table scaling factor of Cell 1."),
    },
    SBS_CMD_BQ_GAUGE_STATUS1.RaScale2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "RaScale2",
        'desc'	: ("Ra Table scaling factor of Cell 2."),
    },
    SBS_CMD_BQ_GAUGE_STATUS1.RaScale3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "RaScale3",
        'desc'	: ("Ra Table scaling factor of Cell 3."),
    },
    SBS_CMD_BQ_GAUGE_STATUS1.CompRes0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1000.0/1024,'name':"mOhm"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CompRes0",
        'desc'	: ("Last temperature compensated Resistance of Cell 0."),
    },
    SBS_CMD_BQ_GAUGE_STATUS1.CompRes1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1000.0/1024,'name':"mOhm"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CompRes1",
        'desc'	: ("Last temperature compensated Resistance of Cell 1."),
    },
    SBS_CMD_BQ_GAUGE_STATUS1.CompRes2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1000.0/1024,'name':"mOhm"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CompRes2",
        'desc'	: ("Last temperature compensated Resistance of Cell 2."),
    },
    SBS_CMD_BQ_GAUGE_STATUS1.CompRes3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1000.0/1024,'name':"mOhm"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CompRes3",
        'desc'	: ("Last temperature compensated Resistance of Cell 3."),
    },
}


class SBS_LEARNED_STATUS(DecoratedEnum):
    """ GaugeStatus2 LearnedStatus fields used in BQ40 family SBS chips
    """
    CF						= 0x000
    ITEn					= 0x002
    ITEnQax					= 0x003
    RESRV4					= 0x004

SBS_LEARNED_STATUS_INFO = {
    SBS_LEARNED_STATUS.CF : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 2,
        'value_names'	: ["Bat.OK","Qm first","Qm&RT Upd","Unkn3",],
        'access'	: "r",
        'tiny_name'	: "CF",
        'desc'	: ("QMax Status."),
    },
    SBS_LEARNED_STATUS.ITEn : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "ITEn",
        'desc'	: ("Impedance Track enable."),
    },
    SBS_LEARNED_STATUS.ITEnQax : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 1,
        'value_names'	: ["Not upd.","Updated"],
        'access'	: "r",
        'tiny_name'	: "ITEnQ",
        'desc'	: ("QMax field updates."),
    },
    SBS_LEARNED_STATUS.RESRV4 : {
        'type'	: "int8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 4,
        'access'	: "r",
        'tiny_name'	: "Rsrv4",
        'desc'	: ("Reserved bits."),
    },
}


class SBS_CMD_BQ_GAUGE_STATUS2(DecoratedEnum):
    """ GaugeStatus2 sub-command fields used in BQ40 family SBS chips
    """
    PackGridPoint			= 0x000
    LearnedStatus			= 0x008
    GridCell0				= 0x010
    GridCell1				= 0x018
    GridCell2				= 0x020
    GridCell3				= 0x028
    StateTime				= 0x030
    DOD0_Cell0				= 0x050
    DOD0_Cell1				= 0x060
    DOD0_Cell2				= 0x070
    DOD0_Cell3				= 0x080
    DOD0_PassedQ			= 0x090
    DOD0_PassedE			= 0x0a0
    DOD0_UpdTime			= 0x0b0
    DOD_EOC_Cell0			= 0x0c0
    DOD_EOC_Cell1			= 0x0d0
    DOD_EOC_Cell2			= 0x0e0
    DOD_EOC_Cell3			= 0x0f0

SBS_CMD_BQ_GAUGE_STATUS2_INFO = {
    SBS_CMD_BQ_GAUGE_STATUS2.PackGridPoint : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "PackGrid",
        'desc'	: ("Active pack grid point. Minimum of GridCell0 to GridCell3. "
          "This data is only valid during DISCHARGE mode when [R_DIS] = 0."),
    },
    SBS_CMD_BQ_GAUGE_STATUS2.LearnedStatus : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_LEARNED_STATUS_INFO,
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LStatus",
        'desc'	: ("Learned status of resistance table."),
    },
    SBS_CMD_BQ_GAUGE_STATUS2.GridCell0 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CellGrd0",
        'desc'	: ("Active grid point cell 0. This data is only valid during "
          "DISCHARGE mode when [R_DIS] = 0."),
    },
    SBS_CMD_BQ_GAUGE_STATUS2.GridCell1 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CellGrd1",
        'desc'	: ("Active grid point cell 1. This data is only valid during "
          "DISCHARGE mode when [R_DIS] = 0."),
    },
    SBS_CMD_BQ_GAUGE_STATUS2.GridCell2 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CellGrd2",
        'desc'	: ("Active grid point cell 2. This data is only valid during "
          "DISCHARGE mode when [R_DIS] = 0."),
    },
    SBS_CMD_BQ_GAUGE_STATUS2.GridCell3 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CellGrd3",
        'desc'	: ("Active grid point cell 3. This data is only valid during "
          "DISCHARGE mode when [R_DIS] = 0."),
    },
    SBS_CMD_BQ_GAUGE_STATUS2.StateTime : {
        'type'	: "uint32",
        'unit'	: {'scale':1,'name':"sec"},
        'nbits'	: 32,
        'access'	: "r",
        'tiny_name'	: "StateTm",
        'desc'	: ("Time past since last state change. Tracks time within "
          "DISCHARGE, CHARGE, REST."),
    },
    SBS_CMD_BQ_GAUGE_STATUS2.DOD0_Cell0 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DOD0_0",
        'desc'	: ("Depth of discharge cell 0."),
    },
    SBS_CMD_BQ_GAUGE_STATUS2.DOD0_Cell1 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DOD0_1",
        'desc'	: ("Depth of discharge cell 1."),
    },
    SBS_CMD_BQ_GAUGE_STATUS2.DOD0_Cell2 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DOD0_2",
        'desc'	: ("Depth of discharge cell 2."),
    },
    SBS_CMD_BQ_GAUGE_STATUS2.DOD0_Cell3 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DOD0_3",
        'desc'	: ("Depth of discharge cell 3."),
    },
    SBS_CMD_BQ_GAUGE_STATUS2.DOD0_PassedQ : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"mAh"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "PassQ",
        'desc'	: ("Passed capacity since the last DOD0 update."),
    },
    SBS_CMD_BQ_GAUGE_STATUS2.DOD0_PassedE : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"cWh"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "PassE",
        'desc'	: ("Passed energy since last DOD0 update."),
    },
    SBS_CMD_BQ_GAUGE_STATUS2.DOD0_UpdTime : {
        'type'	: "uint16",
        'unit'	: {'scale':60.0/16,'name':"min"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "UpdTime",
        'desc'	: ("Time passed since the last DOD0 update."),
    },
    SBS_CMD_BQ_GAUGE_STATUS2.DOD_EOC_Cell0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DODEOC0",
        'desc'	: ("Depth of discharge cell0 at End of Charge."),
    },
    SBS_CMD_BQ_GAUGE_STATUS2.DOD_EOC_Cell1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DODEOC1",
        'desc'	: ("Depth of discharge cell1 at End of Charge."),
    },
    SBS_CMD_BQ_GAUGE_STATUS2.DOD_EOC_Cell2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DODEOC2",
        'desc'	: ("Depth of discharge cell2 at End of Charge."),
    },
    SBS_CMD_BQ_GAUGE_STATUS2.DOD_EOC_Cell3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DODEOC3",
        'desc'	: ("Depth of discharge cell3 at End of Charge."),
    },
}


class SBS_CMD_BQ_GAUGE_STATUS3(DecoratedEnum):
    """ GaugeStatus3 sub-command fields used in BQ40 family SBS chips
    """
    QMaxCell0				= 0x000
    QMaxCell1				= 0x010
    QMaxCell2				= 0x020
    QMaxCell3				= 0x030
    DOD0_Cell0_4QMax		= 0x040
    DOD0_Cell1_4QMax		= 0x050
    DOD0_Cell2_4QMax		= 0x060
    DOD0_Cell3_4QMax		= 0x070
    PassedQ_4QMax			= 0x080
    DOD0_UpdTime_4QMax		= 0x090
    TemperatureFactorK		= 0x0a0
    TemperatureA			= 0x0b0

SBS_CMD_BQ_GAUGE_STATUS3_INFO = {
    SBS_CMD_BQ_GAUGE_STATUS3.QMaxCell0 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "QMax0",
        'desc'	: ("Qmax of cell 0."),
    },
    SBS_CMD_BQ_GAUGE_STATUS3.QMaxCell1 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "QMax1",
        'desc'	: ("Qmax of cell 1."),
    },
    SBS_CMD_BQ_GAUGE_STATUS3.QMaxCell2 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "QMax2",
        'desc'	: ("Qmax of cell 2."),
    },
    SBS_CMD_BQ_GAUGE_STATUS3.QMaxCell3 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "QMax3",
        'desc'	: ("Qmax of cell 3."),
    },
    SBS_CMD_BQ_GAUGE_STATUS3.DOD0_Cell0_4QMax : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DOD0_0_Q",
        'desc'	: ("DOD0 saved for next QMax update of Cell 0. Value stored "
          "as a component required for future QMax calculations. The value "
          "is only valid when [VOK] = 1."),
    },
    SBS_CMD_BQ_GAUGE_STATUS3.DOD0_Cell1_4QMax : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DOD0_1_Q",
        'desc'	: ("DOD0 saved for next QMax update of Cell 1. Value stored "
          "as a component required for future QMax calculations. The value "
          "is only valid when [VOK] = 1."),
    },
    SBS_CMD_BQ_GAUGE_STATUS3.DOD0_Cell2_4QMax : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DOD0_2_Q",
        'desc'	: ("DOD0 saved for next QMax update of Cell 2. Value stored "
          "as a component required for future QMax calculations. The value "
          "is only valid when [VOK] = 1."),
    },
    SBS_CMD_BQ_GAUGE_STATUS3.DOD0_Cell3_4QMax : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DOD0_3_Q",
        'desc'	: ("DOD0 saved for next QMax update of Cell 3. Value stored "
          "as a component required for future QMax calculations. The value "
          "is only valid when [VOK] = 1."),
    },
    SBS_CMD_BQ_GAUGE_STATUS3.PassedQ_4QMax : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"mAh"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "PassQ_Q",
        'desc'	: ("Pass capacity since last QMax DOD value is saved."),
    },
    SBS_CMD_BQ_GAUGE_STATUS3.DOD0_UpdTime_4QMax : {
        'type'	: "uint16",
        'unit'	: {'scale':60.0/16,'name':"min"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "UpdTm_Q",
        'desc'	: ("Time passed since last QMax DOD value is saved."),
    },

    SBS_CMD_BQ_GAUGE_STATUS3.TemperatureFactorK : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TempK",
        'desc'	: ("Thermal Model temperature K factor."),
    },
    SBS_CMD_BQ_GAUGE_STATUS3.TemperatureA : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TempA",
        'desc'	: ("Thermal Model temperature A."),
    },
}


class SBS_CMD_BQ_CB_STATUS(DecoratedEnum):
    """ CBStatus sub-command fields used in BQ40 family SBS chips
    """
    CBTimeCell0				= 0x000
    CBTimeCell1				= 0x010
    CBTimeCell2				= 0x020
    CBTimeCell3				= 0x030

SBS_CMD_BQ_CB_STATUS_INFO = {
    SBS_CMD_BQ_CB_STATUS.CBTimeCell0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"s"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CBTime0",
        'desc'	: ("Calculated cell balancing time cell 0."),
    },
    SBS_CMD_BQ_CB_STATUS.CBTimeCell1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"s"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CBTime1",
        'desc'	: ("Calculated cell balancing time cell 1."),
    },
    SBS_CMD_BQ_CB_STATUS.CBTimeCell2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"s"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CBTime2",
        'desc'	: ("Calculated cell balancing time cell 2."),
    },
    SBS_CMD_BQ_CB_STATUS.CBTimeCell3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"s"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CBTime3",
        'desc'	: ("Calculated cell balancing time cell 3."),
    },
}


class SBS_CMD_BQ_FILTERED_CAPACITY(DecoratedEnum):
    """ FilteredCapacity sub-command fields used in BQ40 family SBS chips
    """
    RemainingCapacity		= 0x000
    RemainingEnergy			= 0x010
    FullChgCapacity			= 0x020
    FullChgEnergy			= 0x030

SBS_CMD_BQ_FILTERED_CAPACITY_INFO = {
    SBS_CMD_BQ_FILTERED_CAPACITY.RemainingCapacity : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mAh"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "RmnCap",
        'desc'	: ("Filtered remaining capacity."),
    },
    SBS_CMD_BQ_FILTERED_CAPACITY.RemainingEnergy : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mWh"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "RmnEnrg",
        'desc'	: ("Filtered remaining energy."),
    },
    SBS_CMD_BQ_FILTERED_CAPACITY.FullChgCapacity : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mAh"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "FCCap",
        'desc'	: ("Filtered full charge capacity."),
    },
    SBS_CMD_BQ_FILTERED_CAPACITY.FullChgEnergy : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mWh"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "FCEnrg",
        'desc'	: ("Filtered full charge energy."),
    },
}


class SBS_CMD_BQ_CC_AND_ADC(DecoratedEnum):
    """ OutputCCnADC sub-command fields used in BQ40 family SBS chips
    """
    RefreshCounter			= 0x000
    Status					= 0x008
    CurrentCC				= 0x010
    CellVoltage0			= 0x020
    CellVoltage1			= 0x030
    CellVoltage2			= 0x040
    CellVoltage3			= 0x050
    PACKVoltage				= 0x060
    BATVoltage				= 0x070
    CellCurrent0			= 0x080
    CellCurrent1			= 0x090
    CellCurrent2			= 0x0a0
    CellCurrent3			= 0x0b0

SBS_CMD_BQ_CC_AND_ADC_INFO = {
    SBS_CMD_BQ_CC_AND_ADC.RefreshCounter : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "RfrVCntr",
        'desc'	: ("Rolling 8-bit counter, increments when values are refreshed."),
    },
    SBS_CMD_BQ_CC_AND_ADC.Status : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "Status",
        'desc'	: ("Status, informs which calib mode is active. Is 1 when "
          "ManufacturerAccess() = 0xF081, 2 when ManufacturerAccess() = 0xF082."),
    },
    SBS_CMD_BQ_CC_AND_ADC.CurrentCC : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "X",
        'desc'	: ("X."),
    },
    SBS_CMD_BQ_CC_AND_ADC.CellVoltage0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "X",
        'desc'	: ("X."),
    },
    SBS_CMD_BQ_CC_AND_ADC.CellVoltage1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "X",
        'desc'	: ("X."),
    },
    SBS_CMD_BQ_CC_AND_ADC.CellVoltage2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "X",
        'desc'	: ("X."),
    },
    SBS_CMD_BQ_CC_AND_ADC.CellVoltage3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "X",
        'desc'	: ("X."),
    },
    SBS_CMD_BQ_CC_AND_ADC.PACKVoltage : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "X",
        'desc'	: ("X."),
    },
    SBS_CMD_BQ_CC_AND_ADC.BATVoltage : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "X",
        'desc'	: ("X."),
    },
    SBS_CMD_BQ_CC_AND_ADC.CellCurrent0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "X",
        'desc'	: ("X."),
    },
    SBS_CMD_BQ_CC_AND_ADC.CellCurrent1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "X",
        'desc'	: ("X."),
    },
    SBS_CMD_BQ_CC_AND_ADC.CellCurrent2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "X",
        'desc'	: ("X."),
    },
    SBS_CMD_BQ_CC_AND_ADC.CellCurrent3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "X",
        'desc'	: ("X."),
    },
}

SBS_COMMAND_BQ_CC_AND_ADC_CALIB_MODE = {
    0 : { # no support of special modes ATM
        'type'	: "byte[]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_CC_AND_ADC_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Output CC and ADC for Calibration. All values "
          "are updated every 250 ms and the format of each value is 2's "
          "complement, MSB first."),
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
    RESERVED6					= 6
    OVERLOAD_DIS_LATCH			= 7
    RESERVED8					= 8
    SHORT_CIRCUIT_CHG_L			= 9
    RESERVED10					= 10
    SHORT_CIRCUIT_DIS_L			= 11
    OVERTEMPERATURE_CHG			= 12
    OVERTEMPERATURE_DIS			= 13
    COMPENSATED_CUV				= 14
    RESERVED15					= 15
    FET_OVERTEMPERATURE			= 16
    RESERVED17					= 17
    PRECHARGING_TIMEOUT			= 18
    PRECHG_TIMEOUT_SUSPEND		= 19
    CHARGING_TIMEOUT			= 20
    CHG_TIMEOUT_SUSPEND			= 21
    OVERCHARGE					= 22
    OVERCHARGE_CURRENT			= 23
    OVERCHARGE_VOLTAGE			= 24
    OVER_PRECHARGE_CURRENT		= 25
    UNDERTEMP_DURING_CHG		= 26
    UNDERTEMP_DURING_DIS		= 27
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
    SBS_FLAG_SAFETY_ALERT.RESERVED6 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "Res6",
        'desc'	: ("Reserved (Overload during discharge)."),
    },
    SBS_FLAG_SAFETY_ALERT.OVERLOAD_DIS_LATCH : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "AOLDL",
        'desc'	: ("Overload during discharge, latch."),
    },
    SBS_FLAG_SAFETY_ALERT.RESERVED8 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "Res8",
        'desc'	: ("Reserved (Short circuit in charge)."),
    },
    SBS_FLAG_SAFETY_ALERT.SHORT_CIRCUIT_CHG_L : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "ASCCL",
        'desc'	: ("Short circuit during charge, latch."),
    },
    SBS_FLAG_SAFETY_ALERT.RESERVED10 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResA",
        'desc'	: ("Reserved (Short circuit in disch)."),
    },
    SBS_FLAG_SAFETY_ALERT.SHORT_CIRCUIT_DIS_L : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "ASCDL",
        'desc'	: ("Short circuit during discharge, latch."),
    },
    SBS_FLAG_SAFETY_ALERT.OVERTEMPERATURE_CHG : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OTC",
        'desc'	: ("Overtemperature during charge."),
    },
    SBS_FLAG_SAFETY_ALERT.OVERTEMPERATURE_DIS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OTD",
        'desc'	: ("Overtemperature during discharge."),
    },
    SBS_FLAG_SAFETY_ALERT.COMPENSATED_CUV : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CUVC",
        'desc'	: ("Compensated Cell Undervoltage."),
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
    SBS_FLAG_SAFETY_ALERT.RESERVED17 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "-",
        'tiny_name'	: "ResH",
        'desc'	: ("Reserved (SBS Host watchdog timeout)."),
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
    SBS_FLAG_SAFETY_ALERT.OVERCHARGE_CURRENT : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CHGC",
        'desc'	: ("Overcharge caused by current. Charging Current "
          "higher than requested."),
    },
    SBS_FLAG_SAFETY_ALERT.OVERCHARGE_VOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CHGV",
        'desc'	: ("Overcharge caused by voltage. Charging Voltage "
          "higher than requested."),
    },
    SBS_FLAG_SAFETY_ALERT.OVER_PRECHARGE_CURRENT : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "PCHGC",
        'desc'	: ("Over-Precharge Current. Precharging Current "
          "higher than requested."),
    },
    SBS_FLAG_SAFETY_ALERT.UNDERTEMP_DURING_CHG : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "UTC",
        'desc'	: ("Undertemperature During Charge."),
    },
    SBS_FLAG_SAFETY_ALERT.UNDERTEMP_DURING_DIS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "UTD",
        'desc'	: ("Undertemperature During Discharge."),
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
    COMPENSATED_CUV				= 14
    RESERVED15					= 15
    FET_OVERTEMPERATURE			= 16
    RESERVED17					= 17
    PRECHARGING_TIMEOUT			= 18
    RESERVED19					= 19
    CHARGING_TIMEOUT			= 20
    RESERVED21					= 21
    OVERCHARGE					= 22
    OVERCHARGE_CURRENT			= 23
    OVERCHARGE_VOLTAGE			= 24
    OVER_PRECHARGE_CURRENT		= 25
    UNDERTEMP_DURING_CHG		= 26
    UNDERTEMP_DURING_DIS		= 27
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
        'desc'	: ("Overload during discharge."),
    },
    SBS_FLAG_SAFETY_STATUS.OVERLOAD_DIS_LATCH : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OLDL",
        'desc'	: ("Overload during discharge, latch."),
    },
    SBS_FLAG_SAFETY_STATUS.SHORT_CIRCUIT_CHG : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "SCC",
        'desc'	: ("Short circuit during charge."),
    },
    SBS_FLAG_SAFETY_STATUS.SHORT_CIRC_CHG_LATCH : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "SCCL",
        'desc'	: ("Short circuit during charge, latch."),
    },
    SBS_FLAG_SAFETY_STATUS.SHORT_CIRCUIT_DIS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "SCD",
        'desc'	: ("Short circuit during discharge."),
    },
    SBS_FLAG_SAFETY_STATUS.SHORT_CIRC_DIS_LATCH : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "SCDL",
        'desc'	: ("Short circuit during discharge, latch."),
    },
    SBS_FLAG_SAFETY_STATUS.OVERTEMPERATURE_CHG : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OTC",
        'desc'	: ("Overtemperature during charge."),
    },
    SBS_FLAG_SAFETY_STATUS.OVERTEMPERATURE_DIS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OTD",
        'desc'	: ("Overtemperature during discharge."),
    },
    SBS_FLAG_SAFETY_STATUS.COMPENSATED_CUV : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CUVC",
        'desc'	: ("Compensated Cell Undervoltage."),
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
    SBS_FLAG_SAFETY_STATUS.RESERVED17 : {
        'type'	: "int_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'access'	: "-",
        'tiny_name'	: "Res11",
        'desc'	: ("Reserved bit 17."),
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
    SBS_FLAG_SAFETY_STATUS.OVERCHARGE_CURRENT : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CHGC",
        'desc'	: ("Overcharge caused by current. Charging Current "
          "higher than requested."),
    },
    SBS_FLAG_SAFETY_STATUS.OVERCHARGE_VOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CHGV",
        'desc'	: ("Overcharge caused by voltage. Charging Voltage "
          "higher than requested."),
    },
    SBS_FLAG_SAFETY_STATUS.OVER_PRECHARGE_CURRENT : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "PCHGC",
        'desc'	: ("Over-Precharge Current. Precharging Current "
          "higher than requested."),
    },
    SBS_FLAG_SAFETY_STATUS.UNDERTEMP_DURING_CHG : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "UTC",
        'desc'	: ("Undertemperature During Charge."),
    },
    SBS_FLAG_SAFETY_STATUS.UNDERTEMP_DURING_DIS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "UTD",
        'desc'	: ("Undertemperature During Discharge."),
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
    OVERCURRENT_CHARGE			= 2
    OVERCURRENT_DISCHG			= 3
    OVERTEMPERATURE_CELL		= 4
    RESERVED5					= 5
    OVERTEMPERATURE_FET			= 6
    QMAX_IMBALANCE				= 7
    CELL_BALANCING				= 8
    CELL_IMPEDANCE				= 9
    CAPACITY_DEGRADATION		= 10
    VOLTAGE_IMBALANCE_REST		= 11
    VOLTAGE_IMBALANCE_ACTV		= 12
    RESERVED13					= 13
    RESERVED14					= 14
    RESERVED15					= 15
    CHARGE_FET					= 16
    DISCHARGE_FET				= 17
    RESERVED18					= 18
    CHEMICAL_FUSE				= 19
    AFE_REGISTER				= 20
    AFE_COMMUNICATION			= 21
    FUSE_PROTECT_2ND_LEVEL		= 22
    RESERVED23					= 23
    RESERVED24					= 24
    OPEN_CELL_TAB_CONNECT		= 25
    RESERVED26					= 26
    RESERVED27					= 27
    OPEN_THERMISTOR_1			= 28
    OPEN_THERMISTOR_2			= 29
    OPEN_THERMISTOR_3			= 30
    OPEN_THERMISTOR_4			= 31

SBS_PF_ALERT_INFO = {
    SBS_FLAG_PF_ALERT.CELL_UNDERVOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "SUV",
        'desc'	: ("Cell Undervoltage below Safety."),
    },
    SBS_FLAG_PF_ALERT.CELL_OVERVOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "SOV",
        'desc'	: ("Cell Overvoltage above Safety."),
    },
    SBS_FLAG_PF_ALERT.OVERCURRENT_CHARGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "SOCC",
        'desc'	: ("Overcurrent in Charge above Safety."),
    },
    SBS_FLAG_PF_ALERT.OVERCURRENT_DISCHG : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "SOCD",
        'desc'	: ("Overcurrent in Dischg above Safety."),
    },
    SBS_FLAG_PF_ALERT.OVERTEMPERATURE_CELL : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "SOT",
        'desc'	: ("Safety Overtemperature Cell Failure."),
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
        'tiny_name'	: "SOTF",
        'desc'	: ("Safety Overtemperature FET Failure. Field Effect "
          "Transistors used for gauging exceed temperature limit."),
    },
    SBS_FLAG_PF_ALERT.QMAX_IMBALANCE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "QIM",
        'desc'	: ("QMAX Imbalance Failure."),
    },
    SBS_FLAG_PF_ALERT.CELL_BALANCING : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CB",
        'desc'	: ("Cell Balancing Failure."),
    },
    SBS_FLAG_PF_ALERT.CELL_IMPEDANCE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "IMP",
        'desc'	: ("Cell impedance failure."),
    },
    SBS_FLAG_PF_ALERT.CAPACITY_DEGRADATION : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "CD",
        'desc'	: ("Capacity Degradation Failure. Cell capacity "
          "deteriorated below useablility."),
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
        'desc'	: ("Voltage imbalance while Pack is Active."),
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
        'desc'	: ("Charge FET Failure."),
    },
    SBS_FLAG_PF_ALERT.DISCHARGE_FET : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "DFETF",
        'desc'	: ("Discharge FET Failure."),
    },
    SBS_FLAG_PF_ALERT.RESERVED18 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResI",
        'desc'	: ("Reserved (Thermistor)."),
    },
    SBS_FLAG_PF_ALERT.CHEMICAL_FUSE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "FUSE",
        'desc'	: ("Chemical Fuse Failure."),
    },
    SBS_FLAG_PF_ALERT.AFE_REGISTER : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "AFER",
        'desc'	: ("AFE Register Failure."),
    },
    SBS_FLAG_PF_ALERT.AFE_COMMUNICATION : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "AFEC",
        'desc'	: ("AFE Communication Failure."),
    },
    SBS_FLAG_PF_ALERT.FUSE_PROTECT_2ND_LEVEL : {
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
    SBS_FLAG_PF_ALERT.OPEN_CELL_TAB_CONNECT : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "OCECO",
        'desc'	: ("Open Cell Tab Connection Failure. Set if VCx "
          "connection indicates open line."),
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
    SBS_FLAG_PF_ALERT.OPEN_THERMISTOR_1 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "TS1",
        'desc'	: ("Open Thermistor TS1 Failure."),
    },
    SBS_FLAG_PF_ALERT.OPEN_THERMISTOR_2 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "TS2",
        'desc'	: ("Open Thermistor TS2 Failure."),
    },
    SBS_FLAG_PF_ALERT.OPEN_THERMISTOR_3 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "TS3",
        'desc'	: ("Open Thermistor TS3 Failure."),
    },
    SBS_FLAG_PF_ALERT.OPEN_THERMISTOR_4 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "TS4",
        'desc'	: ("Open Thermistor TS4 Failure."),
    },
}


class SBS_FLAG_PF_STATUS(DecoratedEnum):
    """ Flags used in PFStatus command
    """
    CELL_UNDERVOLTAGE			= 0
    CELL_OVERVOLTAGE			= 1
    OVERCURRENT_CHARGE			= 2
    OVERCURRENT_DISCHG			= 3
    OVERTEMPERATURE_CELL		= 4
    RESERVED5					= 5
    OVERTEMPERATURE_FET			= 6
    QMAX_IMBALANCE				= 7
    CELL_BALANCING				= 8
    CELL_IMPEDANCE				= 9
    CAPACITY_DEGRADATION		= 10
    VOLTAGE_IMBALANCE_REST		= 11
    VOLTAGE_IMBALANCE_ACTV		= 12
    RESERVED13					= 13
    RESERVED14					= 14
    RESERVED15					= 15
    CHARGE_FET					= 16
    DISCHARGE_FET				= 17
    RESERVED18					= 18
    CHEMICAL_FUSE				= 19
    AFE_REGISTER				= 20
    AFE_COMMUNICATION			= 21
    FUSE_PROTECT_2ND_LEVEL		= 22
    PTC_FAILURE					= 23
    INSTR_FLASH_CHECKSUM		= 24
    OPEN_CELL_TAB_CONNECT		= 25
    DF_WEAR_FAILURE				= 26
    RESERVED27					= 27
    OPEN_THERMISTOR_1			= 28
    OPEN_THERMISTOR_2			= 29
    OPEN_THERMISTOR_3			= 30
    OPEN_THERMISTOR_4			= 31

SBS_PF_STATUS_INFO = {
    SBS_FLAG_PF_STATUS.CELL_UNDERVOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SUV",
        'desc'	: ("Cell Undervoltage below Safety."),
    },
    SBS_FLAG_PF_STATUS.CELL_OVERVOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SOV",
        'desc'	: ("Cell Overvoltage above Safety."),
    },
    SBS_FLAG_PF_STATUS.OVERCURRENT_CHARGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "SOCC",
        'desc'	: ("Overcurrent in Charge above Safety."),
    },
    SBS_FLAG_PF_STATUS.OVERCURRENT_DISCHG : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SOCD",
        'desc'	: ("Overcurrent in Dischg above Safety."),
    },
    SBS_FLAG_PF_STATUS.OVERTEMPERATURE_CELL : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SOT",
        'desc'	: ("Safety Overtemperature Cell Failure."),
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
        'tiny_name'	: "SOTF",
        'desc'	: ("Safety Overtemperature FET Failure. Field Effect "
          "Transistors used for gauging exceed temperature limit."),
    },
    SBS_FLAG_PF_STATUS.QMAX_IMBALANCE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "QIM",
        'desc'	: ("QMAX Imbalance Failure."),
    },
    SBS_FLAG_PF_STATUS.CELL_BALANCING : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CB",
        'desc'	: ("Cell Balancing Failure."),
    },
    SBS_FLAG_PF_STATUS.CELL_IMPEDANCE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "IMP",
        'desc'	: ("Cell impedance failure."),
    },
    SBS_FLAG_PF_STATUS.CAPACITY_DEGRADATION : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CD",
        'desc'	: ("Capacity Degradation Failure. Cell capacity "
          "deteriorated below useablility."),
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
        'desc'	: ("Voltage imbalance while Pack is Active."),
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
        'desc'	: ("Charge FET Failure."),
    },
    SBS_FLAG_PF_STATUS.DISCHARGE_FET : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "DFETF",
        'desc'	: ("Discharge FET Failure."),
    },
    SBS_FLAG_PF_STATUS.RESERVED18 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResI",
        'desc'	: ("Reserved (Thermistor)."),
    },
    SBS_FLAG_PF_STATUS.CHEMICAL_FUSE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "FUSE",
        'desc'	: ("Chemical Fuse Failure. The FUSE pin is designed to "
          "ignite the chemical fuse if one of the various safety criteria "
          "is violated. Can also be triggered via SBS for manufacturing "
          "test. If not used, it should be pulled down."),
    },
    SBS_FLAG_PF_STATUS.AFE_REGISTER : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Not avail.","Active"],
        'access'	: "r",
        'tiny_name'	: "AFER",
        'desc'	: ("Analog-Front-End Register Failure."),
    },
    SBS_FLAG_PF_STATUS.AFE_COMMUNICATION : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "AFEC",
        'desc'	: ("Analog-Front-End Communication Failure."),
    },
    SBS_FLAG_PF_STATUS.FUSE_PROTECT_2ND_LEVEL : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "2LVL",
        'desc'	: ("FUSE input trigger by external protection. Whether FUSE "
          "input indicates fuse trigger by external 2nd level protection."),
    },
    SBS_FLAG_PF_STATUS.PTC_FAILURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "PTC",
        'desc'	: ("Positive Temperature Coefficient failure. The PTC is "
          "linked to Analog-Front-End."),
    },
    SBS_FLAG_PF_STATUS.INSTR_FLASH_CHECKSUM : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Normal","Chksum fail"],
        'access'	: "-",
        'tiny_name'	: "IFC",
        'desc'	: ("Instruction Flash Checksum Failure."),
    },
    SBS_FLAG_PF_STATUS.OPEN_CELL_TAB_CONNECT : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Not avail.","Active"],
        'access'	: "r",
        'tiny_name'	: "OCECO",
        'desc'	: ("Open Cell Tab Connection Failure. Set if VCx "
          "connection indicates open line."),
    },
    SBS_FLAG_PF_STATUS.DF_WEAR_FAILURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "DFW",
        'desc'	: ("Data Flash wearout failure. Set if Data Flash writes "
          "are not always ending with success."),
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
    SBS_FLAG_PF_STATUS.OPEN_THERMISTOR_1 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "TS1",
        'desc'	: ("Open Thermistor TS1 Failure."),
    },
    SBS_FLAG_PF_STATUS.OPEN_THERMISTOR_2 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "TS2",
        'desc'	: ("Open Thermistor TS2 Failure."),
    },
    SBS_FLAG_PF_STATUS.OPEN_THERMISTOR_3 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "TS3",
        'desc'	: ("Open Thermistor TS3 Failure."),
    },
    SBS_FLAG_PF_STATUS.OPEN_THERMISTOR_4 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "TS4",
        'desc'	: ("Open Thermistor TS4 Failure."),
    },
}


class SBS_FLAG_OPERATION_STATUS(DecoratedEnum):
    """ Flags used in OperationStatus command
    """
    SYS_PRESENT_LOW				= 0
    DSG_FET_STATUS				= 1
    CHG_FET_STATUS				= 2
    PCHG_FET_STATUS				= 3
    RESERVED4					= 4
    FUSE_STATUS					= 5
    SMOOTHING					= 6
    TRIP_POINT_INTR				= 7
    SECURITY_MODE				= 8
    SHUTDOWN_LOW_VOLT			= 10
    SAFETY_STATUS				= 11
    PERMANENT_FAILURE			= 12
    DISCHARGING_DISABLED		= 13
    CHARGING_DISABLED			= 14
    SLEEP_MODE					= 15
    SHUTDOWN_BY_MA				= 16
    LED_DISPLAY					= 17
    AUTH_ONGOING				= 18
    AUTO_CC_OFFS_CALIB			= 19
    RAW_ADC_CC_OUTPUT			= 20
    RAW_CCOFFS_OUTPUT			= 21
    XLOW_SPEED_STATE			= 22
    SLEEP_BY_MA					= 23
    INIT_AFTER_RESET			= 24
    SMB_CAL_ON_LOW				= 25
    ADC_MEAS_IN_SLEEP			= 26
    CC_MEAS_IN_SLEEP			= 27
    CELL_BALANCING				= 28
    EMERGENCY_SHUTDOWN			= 29
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
        'desc'	: ("Discharge FET status."),
    },
    SBS_FLAG_OPERATION_STATUS.CHG_FET_STATUS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CHG",
        'desc'	: ("Charge FET Status."),
    },
    SBS_FLAG_OPERATION_STATUS.PCHG_FET_STATUS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "PCHG",
        'desc'	: ("Precharge FET Status."),
    },
    SBS_FLAG_OPERATION_STATUS.RESERVED4 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "Res4",
        'desc'	: ("Reserved (GPOD FET Status)."),
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
    SBS_FLAG_OPERATION_STATUS.SMOOTHING : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SMOTH",
        'desc'	: ("CEDV Smoothing status. The ability to smooth the "
          "RemainingCapacity() during discharge in order to avoid a drop in "
          "RelativeStateOfCharge() when the EDV thresholds are reached."),
    },
    SBS_FLAG_OPERATION_STATUS.TRIP_POINT_INTR : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "BTPI",
        'desc'	: ("Battery Trip Point Interrupt. Setting and clearing "
          "this bit depends on various conditions."),
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
    SBS_FLAG_OPERATION_STATUS.SHUTDOWN_LOW_VOLT : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SDV",
        'desc'	: ("Shutdown triggered via low pack voltage."),
    },
    SBS_FLAG_OPERATION_STATUS.SAFETY_STATUS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SS",
        'desc'	: ("Safety mode status."),
    },
    SBS_FLAG_OPERATION_STATUS.PERMANENT_FAILURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "PF",
        'desc'	: ("Permanent Failure mode status."),
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
        'desc'	: ("Shutdown activated by SMBus command."),
    },
    SBS_FLAG_OPERATION_STATUS.LED_DISPLAY : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Off","On"],
        'access'	: "r",
        'tiny_name'	: "LED",
        'desc'	: ("LED Display state."),
    },
    SBS_FLAG_OPERATION_STATUS.AUTH_ONGOING : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "AUTH",
        'desc'	: ("Authentication ongoing. Set when Authentication function "
          "is in progress."),
    },
    SBS_FLAG_OPERATION_STATUS.AUTO_CC_OFFS_CALIB : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Cal Done","Start Cal"],
        'access'	: "r",
        'tiny_name'	: "ACALM",
        'desc'	: ("Auto CC offset calibration by SMBus cmd. When the gauge "
          "receives the MAC AutoCCOffset(), it sets the bit and starts the "
          "auto CC offset calibration. The bit gets cleared when the "
          "calibration is completed."),
    },
    SBS_FLAG_OPERATION_STATUS.RAW_ADC_CC_OUTPUT : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CALOC",
        'desc'	: ("Raw ADC/CC data calibration output. Active when either "
          "the MAC OutputCCADCCal() or OutputShortedCCADCCal() is sent and "
          "the raw CC and ADC data for calibration is available."),
    },
    SBS_FLAG_OPERATION_STATUS.RAW_CCOFFS_OUTPUT : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CALOO",
        'desc'	: ("Raw CC offset data calibration output. Active when MAC "
          "OutputShortedCCADCCal() is sent and the raw shorted Current Check "
          "data for calibration is available."),
    },
    SBS_FLAG_OPERATION_STATUS.XLOW_SPEED_STATE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "XL",
        'desc'	: ("400 kHz transmission SMBus mode."),
    },
    SBS_FLAG_OPERATION_STATUS.SLEEP_BY_MA : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SLEPM",
        'desc'	: ("SLEEP mode activated by SMBus command."),
    },
    SBS_FLAG_OPERATION_STATUS.INIT_AFTER_RESET : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "INIT",
        'desc'	: ("Initialization after full reset. Cleared when SBS data "
          "is calculated and available."),
    },
    SBS_FLAG_OPERATION_STATUS.SMB_CAL_ON_LOW : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Not in Cal","Cal starts"],
        'access'	: "r",
        'tiny_name'	: "SLCAL",
        'desc'	: ("Auto CC calibration when the bus is low. The Current Check "
          "calibration is ongoing after this SBS line goes low. This bit may "
          "not be read by the host because the FW will clear it when a "
          "communication is detected."),
    },
    SBS_FLAG_OPERATION_STATUS.ADC_MEAS_IN_SLEEP : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SLPAD",
        'desc'	: ("ADC Measurement in SLEEP mode. The measurement is "
          "performed for QMax update."),
    },
    SBS_FLAG_OPERATION_STATUS.CC_MEAS_IN_SLEEP : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SLPCC",
        'desc'	: ("Current Check measurement in SLEEP mode."),
    },
    SBS_FLAG_OPERATION_STATUS.CELL_BALANCING : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CB",
        'desc'	: ("Cell balancing status."),
    },
    SBS_FLAG_OPERATION_STATUS.EMERGENCY_SHUTDOWN : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "EMSHT",
        'desc'	: ("Emergency Shutdown. This SHUTDOWN can be activated ie "
          "by outranged voltage."),
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
    RESERVED7					= 7
    PRECHARGE_VOLTAGE			= 8
    LOW_VOLTAGE					= 9
    MID_VOLTAGE					= 10
    HIGH_VOLTAGE				= 11
    CHARGE_INHIBIT				= 12
    CHARGE_SUSPEND				= 13
    MAINTENANCE_CHARGE			= 14
    CHARGE_TERMINATION			= 15

SBS_CHARGING_STATUS_INFO = {
    SBS_FLAG_CHARGING_STATUS.UNDER_TEMPERATURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "UT",
        'desc'	: ("Under Temperature Region."),
    },
    SBS_FLAG_CHARGING_STATUS.LOW_TEMPERATURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "LT",
        'desc'	: ("Low Temperature Region."),
    },
    SBS_FLAG_CHARGING_STATUS.STD_TEMPERATURE_LOW : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "STL",
        'desc'	: ("Standard Temperature Low Region."),
    },
    SBS_FLAG_CHARGING_STATUS.RECOMMENDED_TEMPERATURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "RT",
        'desc'	: ("Recommended Temperature Region."),
    },
    SBS_FLAG_CHARGING_STATUS.STD_TEMPERATURE_HIGH : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "STH",
        'desc'	: ("Standard Temperature High Region."),
    },
    SBS_FLAG_CHARGING_STATUS.HIGH_TEMPERATURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "HT",
        'desc'	: ("High Temperature Region."),
    },
    SBS_FLAG_CHARGING_STATUS.OVER_TEMPERATURE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "OT",
        'desc'	: ("Over Temperature Region."),
    },
    SBS_FLAG_CHARGING_STATUS.RESERVED7 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "Res7",
        'desc'	: ("Reserved bit 7."),
    },
    SBS_FLAG_CHARGING_STATUS.PRECHARGE_VOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "PV",
        'desc'	: ("Precharge Voltage Region."),
    },
    SBS_FLAG_CHARGING_STATUS.LOW_VOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "LV",
        'desc'	: ("Low Voltage Region."),
    },
    SBS_FLAG_CHARGING_STATUS.MID_VOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "MV",
        'desc'	: ("Mid Voltage Region."),
    },
    SBS_FLAG_CHARGING_STATUS.HIGH_VOLTAGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "HV",
        'desc'	: ("High Voltage Region."),
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
    SBS_FLAG_CHARGING_STATUS.MAINTENANCE_CHARGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "MCHG",
        'desc'	: ("Maintenance charge."),
    },
    SBS_FLAG_CHARGING_STATUS.CHARGE_TERMINATION : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "VCT",
        'desc'	: ("Valid Charge Termination."),
    },
}


class SBS_FLAG_GAUGING_STATUS(DecoratedEnum):
    """ Flags used in GaugingStatus command
    """
    FULLY_DISCHARGED			= 0
    FULLY_CHARGED				= 1
    TERMNATE_DISCHARGE			= 2
    TERMNATE_CHARGE				= 3
    CELL_BALANCING				= 4
    END_OF_DISCHG_V_REACH		= 5
    DISCHARGE_RELAX				= 6
    CONDITION_FLAG				= 7
    REST_OCV_READINGS			= 8
    RESERVED9					= 9
    RESISTANCE_UPDATES			= 10
    VOLTAGE_OK_FOR_QMAX			= 11
    QMAX_GAUGING				= 12
    OCV_UPDATE_IN_SLEEP			= 13
    RESERVED14					= 14
    NEG_SCALE_FACTOR			= 15
    DISCHARGE_QUALIFIED			= 16
    QMAX_UPDATED_T				= 17
    RESISTANCE_UPDATE_T			= 18
    LOAD_MODE					= 19
    OCV_FLAT_REGION				= 20
    RESERVED21					= 21
    RESERVED22					= 22
    RESERVED23					= 23

SBS_GAUGING_STATUS_INFO = {
    SBS_FLAG_GAUGING_STATUS.FULLY_DISCHARGED : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "FD",
        'desc'	: ("Fully Discharged Detected by gauge algorithm."),
    },
    SBS_FLAG_GAUGING_STATUS.FULLY_CHARGED : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "FC",
        'desc'	: ("Fully Charged Detected by gauge algorithm."),
    },
    SBS_FLAG_GAUGING_STATUS.TERMNATE_DISCHARGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "TD",
        'desc'	: ("Terminate Discharge."),
    },
    SBS_FLAG_GAUGING_STATUS.TERMNATE_CHARGE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Detected"],
        'access'	: "r",
        'tiny_name'	: "TCA",
        'desc'	: ("Terminate Charge."),
    },
    SBS_FLAG_GAUGING_STATUS.CELL_BALANCING : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disallow","Possible"],
        'access'	: "r",
        'tiny_name'	: "BAL_EN",
        'desc'	: ("Cell Balancing availability. If set, cell balancing "
          "is possible if enabled."),
    },
    SBS_FLAG_GAUGING_STATUS.END_OF_DISCHG_V_REACH : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["No reach","Reached"],
        'access'	: "r",
        'tiny_name'	: "EDV",
        'desc'	: ("End-of-Discharge Termination Voltage. Set when "
          "termination voltage is reached during discharge."),
    },
    SBS_FLAG_GAUGING_STATUS.DISCHARGE_RELAX : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Charging","Not chg."],
        'access'	: "r",
        'tiny_name'	: "DSG",
        'desc'	: ("Discharge/Relax."),
    },
    SBS_FLAG_GAUGING_STATUS.CONDITION_FLAG : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CF",
        'desc'	: ("Condition Cycle Flag. Set when Condition Cycle is "
          "needed due to MaxError() exceeding Max Error Limit."),
    },
    SBS_FLAG_GAUGING_STATUS.REST_OCV_READINGS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Not taken","Taken"],
        'access'	: "r",
        'tiny_name'	: "REST",
        'desc'	: ("Open Circuit Voltage reading taken. If not set, the "
          "OCV Reading was Not Taken, or battery is not in RELAX mode."),
    },
    SBS_FLAG_GAUGING_STATUS.RESERVED9 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "Res9",
        'desc'	: ("Reserved bit 9."),
    },
    SBS_FLAG_GAUGING_STATUS.RESISTANCE_UPDATES : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "R_DIS",
        'desc'	: ("Resistance Updates."),
    },
    SBS_FLAG_GAUGING_STATUS.VOLTAGE_OK_FOR_QMAX : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["No DOD","DOD saved"],
        'access'	: "r",
        'tiny_name'	: "VOK",
        'desc'	: ("Voltages are OK for QMax update. This flag is updated "
          "at exit of the RELAX mode. If set, a DOD is saved for next "
          "QMax update."),
    },
    SBS_FLAG_GAUGING_STATUS.QMAX_GAUGING : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "QEN",
        'desc'	: ("Impedance Track Gauging. If set, Ra and QMax updates "
          "are enabled."),
    },
    SBS_FLAG_GAUGING_STATUS.OCV_UPDATE_IN_SLEEP : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "SLPQMx",
        'desc'	: ("OCV update in SLEEP mode. Active when OCV reading is "
          "in progress."),
    },
    SBS_FLAG_GAUGING_STATUS.RESERVED14 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResE",
        'desc'	: ("Reserved bit 14."),
    },
    SBS_FLAG_GAUGING_STATUS.NEG_SCALE_FACTOR : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Not det.","Detected"],
        'access'	: "r",
        'tiny_name'	: "NSFM",
        'desc'	: ("Negative scale factor mode. Set if Negative Ra Scaling "
          "Factor is Detected."),
    },
    SBS_FLAG_GAUGING_STATUS.DISCHARGE_QUALIFIED : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "VDQ",
        'desc'	: ("Discharge qualified for learning. This is opposite "
          "of the R_DIS flag."),
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
        'value_names'	: ["Toggle0","Toggle1"],
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
        'desc'	: ("Open Circuit Voltage in flat region."),
    },
    SBS_FLAG_GAUGING_STATUS.RESERVED21 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "-",
        'tiny_name'	: "ResL",
        'desc'	: ("Reserved bit 21."),
    },
    SBS_FLAG_GAUGING_STATUS.RESERVED22 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "-",
        'tiny_name'	: "ResM",
        'desc'	: ("Reserved bit 22."),
    },
    SBS_FLAG_GAUGING_STATUS.RESERVED23 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "-",
        'tiny_name'	: "ResN",
        'desc'	: ("Reserved bit 23."),
    },
}


class SBS_FLAG_MANUFACTURING_STATUS(DecoratedEnum):
    """ Flags used in ManufacturingStatus command
    """
    PCHG_FET_TEST				= 0
    CHG_FET_TEST				= 1
    DSG_FET_TEST				= 2
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
    LIFETIME_SU_MODE			= 14
    CALIBRATION_MODE			= 15

SBS_MANUFACTURING_STATUS_INFO = {
    SBS_FLAG_MANUFACTURING_STATUS.PCHG_FET_TEST : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Active"],
        'access'	: "r",
        'tiny_name'	: "PCHG",
        'desc'	: ("Precharge FET Test."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.CHG_FET_TEST : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Active"],
        'access'	: "r",
        'tiny_name'	: "CHG",
        'desc'	: ("Charge FET Test."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.DSG_FET_TEST : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Active"],
        'access'	: "r",
        'tiny_name'	: "DSG",
        'desc'	: ("Discharge FET Test."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.GAUGING : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "GAUGE",
        'desc'	: ("Gas Gauging."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.FET_ACTION : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "FET",
        'desc'	: ("All FET Action."),
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
        'desc'	: ("Permanent Failure functionality. When enabled, the chip "
          "will trigger PF mode if alarm conditions are tripped."),
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
        'value_names'	: ["Off","On"],
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
    SBS_FLAG_MANUFACTURING_STATUS.LIFETIME_SU_MODE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "LT_TS",
        'desc'	: ("Lifetime Speed Up mode."),
    },
    SBS_FLAG_MANUFACTURING_STATUS.CALIBRATION_MODE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Disabled","Enabled"],
        'access'	: "r",
        'tiny_name'	: "CALTS",
        'desc'	: ("CAL ADC or CC output on ManufacturerData()."),
    },
}


class SBS_STATE_OF_HEALTH_PERCENT(DecoratedEnum):
    """ Flags used in StateOfHealthPercent command
    """
    SOH_REMAIN_CAPACITY_PCT				= 0
    SOH_REMAIN_ENERGY_PCT				= 8

SBS_STATE_OF_HEALTH_PERCENT_INFO = {
    SBS_STATE_OF_HEALTH_PERCENT.SOH_REMAIN_CAPACITY_PCT : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "HlCap",
        'desc'	: ("Percentage of design capacity still useable."),
    },
    SBS_STATE_OF_HEALTH_PERCENT.SOH_REMAIN_ENERGY_PCT : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "HlEnr",
        'desc'	: ("Percentage of design energy still useable."),
    },
}


class SBS_CMD_BQ_SECURITY_KEYS(DecoratedEnum):
    """ Flags used in StateOfHealthPercent command
    """
    KEY_UNSEAL_W0						= 0
    KEY_UNSEAL_W1						= 16
    KEY_FULL_ACCESS_W0					= 32
    KEY_FULL_ACCESS_W1					= 48

SBS_CMD_BQ_SECURITY_KEYS_INFO = {
    SBS_CMD_BQ_SECURITY_KEYS.KEY_UNSEAL_W0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"hex"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "UnslW0",
        'desc'	: ("Unseal key, word 0."),
    },
    SBS_CMD_BQ_SECURITY_KEYS.KEY_UNSEAL_W1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"hex"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "UnslW1",
        'desc'	: ("Unseal key, word 1."),
    },
    SBS_CMD_BQ_SECURITY_KEYS.KEY_FULL_ACCESS_W0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"hex"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "FAccW0",
        'desc'	: ("Full Access key, word 0."),
    },
    SBS_CMD_BQ_SECURITY_KEYS.KEY_FULL_ACCESS_W1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"hex"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "FAccW1",
        'desc'	: ("Full Access key, word 1."),
    },
}


MANUFACTURER_ACCESS_CMD_BQ40_INFO = {
    MANUFACTURER_ACCESS_CMD_BQGENERIC.ManufacturerData : {
        # Data type associated with the sub-command
        'type'	: "byte[]",
        # Measurement unit in which data type is stored
        'unit'	: {'scale':None,'name':"hex"},
        # Access to the function in BQ seal modes: sealed, unsealed, full access;
        # write - means the command does a change within SBS chip other that
        # preparing output; read - means the command prepares output accessible by
        # reading value from 'resp_location'
        'access_per_seal'	: ("r","r","r",),
        # Command/offsets which stores response on this sub-command
        #'resp_location'	: SBS_COMMAND.ManufacturerData,
        # Description, with first sentence making a short description,
        'desc'	: ("Output selected ManufacturerData(). The selection is made"
          "by invoking other sub-commands."),
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
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_FIRMWARE_VERSION_INFO,
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
    MANUFACTURER_ACCESS_CMD_BQ40.InstrFlashChecksum : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"hex"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'resp_wait'	: 0.35,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Checksum/signature of the Instruction Flash. Read on "
          "ManufacturerBlockAccess() or ManufacturerData() after a wait time "
          "of 250 ms."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.StaticDataFlashChecksum : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"hex"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'resp_wait'	: 0.35,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Checksum/signature of the Data Flash. MSB is set to 1 "
          "if the calculated signature does not match the signature stored "
          "in DF. Read on ManufacturerBlockAccess() or ManufacturerData() "
          "after a wait time of 250 ms."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.ChemicalID : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"hex"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Chemical ID of the OCV tables. Returns ID used in the "
          "gauging algorithm."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.StaticChemDFSignature : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"hex"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'resp_wait'	: 0.35,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Checksum of the Chemical OCV tables Data Flash. MSB is set "
          "to 1 if the calculated signature does not match the signature stored "
          "in DF. Read on ManufacturerBlockAccess() or ManufacturerData() "
          "after a wait time of 250 ms."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.AllDFSignature : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"hex"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'resp_wait'	: 0.35,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Checksum of the all Data Flash parameters. MSB is set "
          "to 1 if the calculated signature does not match the signature "
          "stored in DF. It is normally expected that this signature will "
          "change due to updates of lifetime, gauging, and other info. "
          "Read on ManufacturerBlockAccess() or ManufacturerData() after a "
          "wait time of 250 ms"),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.ShutdownMode : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        # when sealed, the command needs to be sent twice to BQ40z55
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("SHUTDOWN mode with reduced power consumption. The device "
          "can be sent to this mode before shipping. It shuts down respecting "
          "ShipFETOffTime ShipDelayTime delays. The device will wake up when "
          "voltage exceeding ChargerPresentThreshold is applied to PACK pin."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.SleepMode : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Send device to sleep if conditions are met. Some of "
          "wake conditions are: Current exceeds Sleep Current, Wake"
          "Comparator trips, SafetyAlert() or PFAlert() flags are set."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.DeviceResetOld : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Resets the device. Backwards compatibility with the BQ30zxy."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.AutoCCOfset : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Starts an Auto CC Offset calibration. The calibration "
          "takes about 16 sec. This value is used for cell current measurement "
          "when the device is in CHARGING or DISCHARGING state."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.FuseToggle : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Activate/deactivate FUSE output pin. Toggle switch which "
          "allows to control the FUSE for ease of testing during manufacturing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.PreChargeFET : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Turns on/off Pre-CHG FET drive function. Toggle switch "
          "which allows to control the PCHG FET for ease of testing during "
          "manufacturing. This command is only enabled if FW FET control is "
          "not active and manual control is allowed."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.ChargeFET : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Turns on/off CHG FET drive function. Toggle switch "
          "which allows to control the Charge FET for ease of testing "
          "during manufacturing. This command is only enabled if FW FET "
          "control is not active and manual control is allowed."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.DischargeFET : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Turns on/off DSG FET drive function. Toggle switch "
          "which allows to control the Discharge FET for ease of testing "
          "during manufacturing. This command is only enabled if FW FET "
          "control is not active and manual control is allowed."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.Gauging : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Enable/disable the gauging function. Toggle switch "
          "which allows to control the Gauge for ease of testing during "
          "manufacturing. If triggered in UNSEALED mode, the switch remains "
          "on latest status after reset."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.FETControl : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Control of the CHG, DSG, and PCHG FET. Toggle switch "
          "which allows to either control the 3 FETs by the firmware, "
          "or disable automation and allow manual control."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.LifetimeDataCollection : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Enables/disables Lifetime data collection. Toggle switch "
          "which allows to control whether Lifetime Data collection feature "
          "is working. If triggered in UNSEALED mode, the switch remains "
          "on latest status after reset."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.PermanentFailure : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Enables/disables Permanent Failure. Toggle switch which "
          "allows to control when PF mode can be triggered, for ease of "
          "manufacturing. If triggered in UNSEALED mode, the switch remains "
          "on latest status after reset."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.BlackBoxRecorder : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Enables/disables Black box recorder function. Toggle "
          "switch which allows to control the recorder for ease of "
          "manufacturing. If triggered in UNSEALED mode, the switch remains "
          "on latest status after reset."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.Fuse : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Enables/disables firmware fuse tripping function. Toggle "
          "switch which allows to switch beetween automatic control the fuse "
          "by FW and manual control for ease of manufacturing. If triggered "
          "in UNSEALED mode, the switch remains on latest status after reset."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.LEDDisplayEnable : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Enables/disables LED Display function. Toggle switch "
          "which allows to control the LEDs for ease of manufacturing. "
          "If triggered in UNSEALED mode, the switch remains on latest "
          "status after reset."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.LifetimeDataReset : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Resets Lifetime data data in data flash. Clears the "
          "flags for ease of manufacturing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.PermanentFailDataReset : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Resets PF data in data flash. Clears permanent fail "
          "flags for ease of manufacturing. If the condition which caused "
          "the flag to appear is still tripped, the flag will get set again."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.LifetimeDataFlush : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Flushes the RAM Lifetime Data to Data Flash. Toggle switch "
          "intended to help streamline evaluation testing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.LifetimeDataSpeedUpMode : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Lifetime SPEED UP mode, multiplies time by 7200. "
          "When SPEED UP is active LT_TEST bit is set, and every 1 sec in "
          "real time counts as 2 hours in FW time. Toggle switch "
          "intended to help streamline evaluation testing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.BlackBoxRecorderReset : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Resets the black box recorder data in Data Flash. "
          "Toggle switch which allows to control the Black Box Recorder "
          "data in DF for ease of manufacturing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.LEDToggle : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Activate/deactivate configured LED display. Toggle "
          "switch which allows to control the LED display for ease of "
          "testing during manufacturing."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.LEDDisplayPress : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Simulates low-high-low detection on the /DISP pin. "
          "Toggle switch which allows to activate the LED display, while "
          "forcing RSOC to 100% in order to demonstrate all LEDs in use, "
          "the full speed, and the brightness."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.CalibrationMode : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Disables/enables entry into CALIBRATION mode. Status is "
          "indicated by the CAL_EN flag. In this mode, the chip outputs the "
          " raw ADC and CC data. Output is controllable with 0xF081 and 0xF082 "
          "on ManufacturerAccess(). Toggle switch - write the value again "
          "to disable the output. It is also disabled upon a reset."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.SealDevice : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","w","w",),
        'desc'	: ("Seals the device, disabling some commands. Certain SBS "
          "commands and access to Data Flash are disabled in sealed device."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.ROMModeLegacy : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","-","w",),
        'desc'	: ("Legacy way of enabling the ROM mode for IF update. "
          "This comand was left for compatibility with BQ30 chips. "
          "It works in the same way as the new ROMMode cmd. On this command, "
          "device goes to ROM mode ready for re-programming firmware in "
          "Instruction Flash. Use 0x08 to ManufacturerAccess() to return."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.SecurityKeys : {
        'type'	: "byte[8]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_SECURITY_KEYS_INFO,
        # different routine is required to write this function, so allow only read
        'access_per_seal'	: ("-","-","r",),
        'desc'	: ("Read/write Unseal key and Full Access key."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.AuthenticationKey : {
        'type'	: "byte[20]",
        'unit'	: {'scale':None,'name':"hex"},
        'resp_location'	: SBS_COMMAND_BQ40.Authenticate,
        # special routine is required for this function, not just read/write
        'access_per_seal'	: ("-","-","-",),
        'desc'	: ("Enter a new Authentication key into the device."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.DeviceReset : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Resets the device. This counts as Full Device Reset as "
          "well as AFE Reset, the terms used in chip reference doc."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.SafetyAlert : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'bitfields_info'	: SBS_SAFETY_ALERT_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Safety Alert bits. Works in sealed mode."),
        'getter'	: "simple",
    },
    MANUFACTURER_ACCESS_CMD_BQ40.SafetyStatus : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'bitfields_info'	: SBS_SAFETY_STATUS_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Safety Status bits. Works in sealed mode."),
        'getter'	: "simple",
    },
    MANUFACTURER_ACCESS_CMD_BQ40.PFAlert : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'bitfields_info'	: SBS_PF_ALERT_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Permanent Fail Alert bits. Works in sealed mode."),
        'getter'	: "simple",
    },
    MANUFACTURER_ACCESS_CMD_BQ40.PFStatus : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'bitfields_info'	: SBS_PF_STATUS_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Permanent Fail Status bits. Works in sealed mode."),
        'getter'	: "simple",
    },
    MANUFACTURER_ACCESS_CMD_BQ40.OperationStatus : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'bitfields_info'	: SBS_OPERATION_STATUS_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Operational Status bits. Works in sealed mode."),
        'getter'	: "simple",
    },
    MANUFACTURER_ACCESS_CMD_BQ40.ChargingStatus : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'bitfields_info'	: SBS_CHARGING_STATUS_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Charging Status bits. Works in sealed mode."),
        'getter'	: "simple",
    },
    MANUFACTURER_ACCESS_CMD_BQ40.GaugingStatus : {
        'type'	: "uint24_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'bitfields_info'	: SBS_GAUGING_STATUS_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Gauging Status bits. Works in sealed mode."),
        'getter'	: "simple",
    },
    MANUFACTURER_ACCESS_CMD_BQ40.ManufacturingStatus : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'bitfields_info'	: SBS_MANUFACTURING_STATUS_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Manufacturing Status bits. Works in sealed mode."),
        'getter'	: "simple",
    },
    MANUFACTURER_ACCESS_CMD_BQ40.LifetimeDataBlock1 : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_LIFETIME_DATA_BLOCK1_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Output lifetimes values on ManufacturerData()."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.LifetimeDataBlock2 : {
        'type'	: "byte[8]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_LIFETIME_DATA_BLOCK2_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Output lifetimes values on ManufacturerData()."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.LifetimeDataBlock3 : {
        'type'	: "byte[16]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_LIFETIME_DATA_BLOCK3_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Output lifetimes values on ManufacturerData()."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.ManufacturerInfo : {
        'type'	: "string[32]",
        'unit'	: {'scale':None,'name':"str"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Output 32 bytes of ManufacturerInfo."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.DAStatus1 : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_DA_STATUS1_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Outputs voltage data values."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.DAStatus2 : {
        'type'	: "byte[14]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_DA_STATUS2_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Outputs temperature data values. Block size "
          "is either 10 or 14 bytes, depending on chip and firmware."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.GaugeStatus1 : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_GAUGE_STATUS1_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Impedance Track Status parameters 1. Gauging algorithm "
          "related params. Outputs 32 bytes of IT data values."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.GaugeStatus2 : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_GAUGE_STATUS2_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Impedance Track Status parameters 2. Gauging algorithm "
          "related params. Outputs 32 bytes of IT data values."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.GaugeStatus3 : {
        'type'	: "byte[24]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_GAUGE_STATUS3_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Impedance Track Status parameters 3. Gauging algorithm "
          "related params. Outputs 24 bytes of IT data values."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.CBStatus : {
        'type'	: "byte[8]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_CB_STATUS_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Cell balance time information."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.FilteredCapacity : {
        'type'	: "byte[8]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_FILTERED_CAPACITY_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Returns the filtered capacity and energy. "
          "Works even if [SMOOTH]=0."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.ManufacturerInfo2 : {
        'type'	: "string[32]",
        'unit'	: {'scale':None,'name':"str"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Unknown value."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.ROMMode : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("-","-","w",),
        'desc'	: ("Enables the ROM mode for IF update. On this command, "
          "device goes to ROM mode ready for re-programming firmware in "
          "Instruction Flash. Thit is often called BootROM mode. Use "
          "0x08 to ManufacturerAccess() to return."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.ExitCalibOutputMode : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Exit Calibration Output Mode. Stop output of ADC or CC "
          "data on ManufacturerData() and return to NORMAL data acquisition "
          "mode. Any other MAC command sent to the gauge will also stop the "
          "output of the calibration data."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.OutputCCnADC : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        # Requires special processing, as it changes the battery mode
        'mode_commands'	: SBS_COMMAND_BQ_CC_AND_ADC_CALIB_MODE,
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Output CC and ADC for Calibration, mode trigger. Lets the "
          "device output several raw values for calibration purposes, as "
          "block on ManufacturerBlockAccess() or ManufacturerData(). "
          "All values are updated every 250 ms and the format of each value "
          "is 2's complement, MSB first."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.OutputShortCCnADCOffset : {
        'type'	: "void",
        'unit'	: {'scale':None,'name':None},
        # Requires special processing, as it changes the battery mode
        'mode_commands'	: SBS_COMMAND_BQ_CC_AND_ADC_CALIB_MODE,
        # Requires special processing, not just r/w, as it changes the battery mode
        'access_per_seal'	: ("w","w","w",),
        'desc'	: ("Output Shorted CC AND ADC Offset for Calib, mode trigger. "
          "Lets the device output several raw values for calibration purposes, "
          "as block on ManufacturerBlockAccess() or ManufacturerData(). "
          "All values are updated every 250 ms and the format of each value "
          "is 2's complement, MSB first. This mode includes an internal "
          "short on the coulomb counter inputs for measuring offset."),
    },
}

global MANUFACTURER_ACCESS_CMD_BQ_INFO
MANUFACTURER_ACCESS_CMD_BQ_INFO.update(MANUFACTURER_ACCESS_CMD_BQ40_INFO)


MANUFACTURER_BLOCK_ACCESS_CMD_BQ40_INFO = {
    MANUFACTURER_ACCESS_CMD_BQ40.DataFlashAccess : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"hex"},
        # Special command - is really an array of commands, shift needs to be added to cmd.value
        'cmd_array'	: 0x2000,
        'access_per_seal'	: ("-","rw","rw",),
        'desc'	: ("Read/write DF content with given address. Sets the DF address "
          "for immediate read/write on ManufacturerBlockAccess(). Not available "
          "on ManufacturerAccess()."),
    },
}

# Add ManufacturerAccess commands to ManufacturerBlockAccess, with small fixes
for subcmd, subcmdinf in MANUFACTURER_ACCESS_CMD_BQ40_INFO.items():
    maccmdinf = subcmdinf.copy()
    if 'resp_location' not in maccmdinf:
        pass
    elif maccmdinf['resp_location'] == SBS_COMMAND.ManufacturerData:
        # The response location is same as command - SBS_COMMAND_BQ40.ManufacturerBlockAccess
        del maccmdinf['resp_location']
    MANUFACTURER_BLOCK_ACCESS_CMD_BQ40_INFO[subcmd] = maccmdinf


global MANUFACTURER_BLOCK_ACCESS_CMD_BQ_INFO
MANUFACTURER_BLOCK_ACCESS_CMD_BQ_INFO.update(MANUFACTURER_BLOCK_ACCESS_CMD_BQ40_INFO)


SBS_CMD_BQ40_INFO = {
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
    SBS_COMMAND_BQ40.Authenticate : {
        'type'	: "byte[]",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("rw","rw","rw",),
        'desc'	: ("Authentication challenge / response / new key. "
          "Provides SHA-1 authentication to send the challenge and read the "
          "response in the default mode. It is also used to input a new "
          "authentication key when the MAC AuthenticationKey() is used."),
        # We need special algorithm to authenticate or change key; but simple r/w is possible
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.Cell3Voltage : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Voltage on the fourth (#3) cell of the battery."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.Cell2Voltage : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Voltage on third cell (#2) of the battery."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.Cell1Voltage : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Voltage on second cell (#1) of the battery."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.Cell0Voltage : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Voltage on first cell (#0) of the battery."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.ManufacturerBlockAccess : {
        'type'	: "byte[]",
        'unit'	: {'scale':None,'name':None},
        'subcmd_infos'	: (MANUFACTURER_BLOCK_ACCESS_CMD_BQ_INFO,),
        # We need special algorithm to use this; but simple r/w is possible
        'access_per_seal'	: ("rw","rw","rw",),
        'desc'	: ("Method of data R/W in the Manufacturer Access System (MAC). "
          "The MAC command is sent via ManufacturerBlockAccess() by the SMBus "
          "block protocol. The result is returned on ManufacturerBlockAccess() "
          "via an SMBus block read."),
        'getter'	: "write_word_subcmd_mac_block",
    },
    SBS_COMMAND_BQ40.SafetyAlert : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_SAFETY_ALERT_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Safety Alert bits. In sealed mode, use "
          "ManufacturerAccess() instead."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.SafetyStatus : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_SAFETY_STATUS_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Safety Status bits. In sealed mode, use "
          "ManufacturerAccess() instead."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.PFAlert : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_PF_ALERT_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Permanent Failure Alert bits. In sealed mode, use "
          "ManufacturerAccess() instead."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.PFStatus : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_PF_STATUS_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Permanent Failure Status bits. In sealed mode, use "
          "ManufacturerAccess() instead."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.OperationStatus : {
        'type'	: "uint32_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_OPERATION_STATUS_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Operational Status bits. In sealed mode, use "
          "ManufacturerAccess() instead."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.ChargingStatus : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_CHARGING_STATUS_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Charging Status bits. In sealed mode, use "
          "ManufacturerAccess() instead."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.GaugingStatus : {
        'type'	: "uint24_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_GAUGING_STATUS_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Gauging Status bits. In sealed mode, use "
          "ManufacturerAccess() instead."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.ManufacturingStatus : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_MANUFACTURING_STATUS_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Manufacturing Status bits. In sealed mode, use "
          "ManufacturerAccess() instead."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.TURBO_FINAL : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"cW"},
        'access_per_seal'	: ("r","r","rw",),
        'desc'	: ("Turbo final, or something else."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.LifetimeDataBlock1 : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_LIFETIME_DATA_BLOCK1_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Lifetime data values, block 1. The same values "
          "as in corresponding ManufacturerData() command."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.LifetimeDataBlock2 : {
        'type'	: "byte[8]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_LIFETIME_DATA_BLOCK2_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Lifetime data values, block 2. The same values "
          "as in corresponding ManufacturerData() command."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.LifetimeDataBlock3 : {
        'type'	: "byte[16]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_LIFETIME_DATA_BLOCK3_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Lifetime data values, block 3. The same values "
          "as in corresponding ManufacturerData() command."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.ManufacturerInfo : {
        'type'	: "string[32]",
        'unit'	: {'scale':1,'name':"str"},
        'access_per_seal'	: ("r","rw","rw",),
        'desc'	: ("Manufacturer Info values. The same values "
          "as in corresponding ManufacturerData() command."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.DAStatus1 : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_DA_STATUS1_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("DA status values, block 1. The same values "
          "as in corresponding ManufacturerData() command."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.DAStatus2 : {
        'type'	: "byte[14]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_DA_STATUS2_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("DA status values, block 2. The same values "
          "as in corresponding ManufacturerData() command."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.GaugeStatus1 : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_GAUGE_STATUS1_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Gauging Status for Impedance Track, block 1. "
          "Gauging algorithm related parameters. The same values "
          "as in corresponding ManufacturerData() command."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.GaugeStatus2 : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_GAUGE_STATUS2_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Gauging Status for Impedance Track, block 2. "
          "Gauging algorithm related parameters. The same values "
          "as in corresponding ManufacturerData() command."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.GaugeStatus3 : {
        'type'	: "byte[24]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_GAUGE_STATUS3_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Gauging Status for Impedance Track, block 3. "
          "Gauging algorithm related parameters. The same values "
          "as in corresponding ManufacturerData() command."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.CBStatus : {
        'type'	: "byte[8]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_CB_STATUS_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Cell balance time information. The same values "
          "as in corresponding ManufacturerData() command."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.FilteredCapacity : {
        'type'	: "byte[8]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_FILTERED_CAPACITY_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Returns the filtered capacity and energy. "
          "Works even if [SMOOTH]=0. The same values "
          "as in corresponding ManufacturerData() command."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.ManufacturerInfo2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'access_per_seal'	: ("r","rw","rw",),
        'desc'	: ("Unknown value."),
        'getter'	: "simple",
    },
}

global SBS_CMD_INFO
SBS_CMD_INFO.update(SBS_CMD_BQ40_INFO)


RAW_ADDRESS_SPACE_KIND_BQ_INFO = {
    RAW_ADDRESS_SPACE_KIND_BQGENERIC.DataFlash : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"hex"},
        'access_per_seal'	: ("-","rw","rw",),
        'desc'	: ("Data Flash raw access. Allows to read/write values within "
          "data flash, which stores all parameters which drive smart battery "
          "algorithms. Positions of values depend not only on chip model, "
          "but also of battery firmware version - so be careful when writing "
          "to this space."),
        'read_cmd':	SBS_COMMAND_BQ40.ManufacturerBlockAccess,
        'read_subcmd':	MANUFACTURER_ACCESS_CMD_BQ40.DataFlashAccess,
        # How much data each cmd_array step represents
        'granularity'	: 1,
        'getter'	: "data_flash_access",
    },
    RAW_ADDRESS_SPACE_KIND_BQGENERIC.InstructionFlash : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"hex"},
        'access_per_seal'	: ("-","rw","rw",),
        'desc'	: ("Instruction Flash raw access. The easiest way to brick "
          "your chip."),
        'read_cmd':	None,
        'read_subcmd':	None,
        'granularity'	: 1,
        'getter'	: "instruction_flash_access",
    },

}

global RAW_ADDRESS_SPACE_KIND_INFO
RAW_ADDRESS_SPACE_KIND_INFO.update(RAW_ADDRESS_SPACE_KIND_BQ_INFO)

SBS_CMD_GROUPS_BQ40 = {
    MONITOR_GROUP.BQStatusBits : (
        SBS_COMMAND_BQ40.SafetyAlert,
        SBS_COMMAND_BQ40.SafetyStatus,
        SBS_COMMAND_BQ40.PFAlert,
        SBS_COMMAND_BQ40.PFStatus,
        SBS_COMMAND_BQ40.OperationStatus,
        SBS_COMMAND_BQ40.ChargingStatus,
        SBS_COMMAND_BQ40.GaugingStatus,
        SBS_COMMAND_BQ40.ManufacturingStatus,
    ),
    MONITOR_GROUP.BQStatusBitsMA : (
        MANUFACTURER_ACCESS_CMD_BQ40.SafetyAlert,
        MANUFACTURER_ACCESS_CMD_BQ40.SafetyStatus,
        MANUFACTURER_ACCESS_CMD_BQ40.PFAlert,
        MANUFACTURER_ACCESS_CMD_BQ40.PFStatus,
        MANUFACTURER_ACCESS_CMD_BQ40.OperationStatus,
        MANUFACTURER_ACCESS_CMD_BQ40.ChargingStatus,
        MANUFACTURER_ACCESS_CMD_BQ40.GaugingStatus,
        MANUFACTURER_ACCESS_CMD_BQ40.ManufacturingStatus,
    ),
    MONITOR_GROUP.BQLifetimeData : (
        SBS_COMMAND_BQ40.ManufacturerInfo,
        SBS_COMMAND_BQ40.TURBO_FINAL,
        SBS_COMMAND_BQ40.LifetimeDataBlock1,
        SBS_COMMAND_BQ40.LifetimeDataBlock2,
        SBS_COMMAND_BQ40.LifetimeDataBlock3,
    ),
    MONITOR_GROUP.BQLifetimeDataMA : (
        MANUFACTURER_ACCESS_CMD_BQ40.ManufacturerInfo,
        MANUFACTURER_ACCESS_CMD_BQ40.LifetimeDataBlock1,
        MANUFACTURER_ACCESS_CMD_BQ40.LifetimeDataBlock2,
        MANUFACTURER_ACCESS_CMD_BQ40.LifetimeDataBlock3,
    ),
    MONITOR_GROUP.ImpedanceTrack : (
        SBS_COMMAND_BQ40.DAStatus1,
        SBS_COMMAND_BQ40.DAStatus2,
        SBS_COMMAND_BQ40.GaugeStatus1,
        SBS_COMMAND_BQ40.GaugeStatus2,
        SBS_COMMAND_BQ40.GaugeStatus3,
        SBS_COMMAND_BQ40.CBStatus,
        SBS_COMMAND_BQ40.FilteredCapacity,
    ),
    MONITOR_GROUP.ImpedanceTrackMA : (
        MANUFACTURER_ACCESS_CMD_BQ40.DAStatus1,
        MANUFACTURER_ACCESS_CMD_BQ40.DAStatus2,
        MANUFACTURER_ACCESS_CMD_BQ40.GaugeStatus1,
        MANUFACTURER_ACCESS_CMD_BQ40.GaugeStatus2,
        MANUFACTURER_ACCESS_CMD_BQ40.GaugeStatus3,
        MANUFACTURER_ACCESS_CMD_BQ40.CBStatus,
        MANUFACTURER_ACCESS_CMD_BQ40.FilteredCapacity,
    ),
    MONITOR_GROUP.BQCellVoltages : (
        SBS_COMMAND_BQ40.Cell0Voltage,
        SBS_COMMAND_BQ40.Cell1Voltage,
        SBS_COMMAND_BQ40.Cell2Voltage,
        SBS_COMMAND_BQ40.Cell3Voltage,
    ),
}

global SBS_CMD_GROUPS
SBS_CMD_GROUPS.update(SBS_CMD_GROUPS_BQ40)

global SBS_SEALING
SBS_SEALING = {
    "Unseal": {
        'auth' : "2-Word SCKey",
        'cmd' : SBS_COMMAND.ManufacturerAccess,
        'subcmd' : None, # first word of key is the sub-command
    },
    "Seal": {
        'auth' : None,
        'cmd' : SBS_COMMAND.ManufacturerAccess,
        'subcmd' : MANUFACTURER_ACCESS_CMD_BQ40.SealDevice,
    },
    "FullAccess": {
        'auth' : "2-Word SCKey",
        'cmd' : SBS_COMMAND.ManufacturerAccess,
        'subcmd' : None, # first word of key is the sub-command
    },
    "Check": {
        'auth' : None,
        'cmd' : SBS_COMMAND.ManufacturerAccess,
        'subcmd' : MANUFACTURER_ACCESS_CMD_BQ40.OperationStatus,
    },
}

class ChipMockBQ40(ChipMock):
    def __init__(self, bus, chip=None):
        self.bus = bus
        self.reads = {}
        self.reads_sub = {}
        # Battery status, used for returned packets
        self.v = (3831, 3832, 0, 0, ) # curreny voltage
        self.dv = (3600, 3600, 0, 0, ) # design voltage
        self.dc = (1200, 1200, 0, 0, ) # design capacity
        self.cyc = 13
        self.t = 23.45 + 273.15 # temperature, in Kelvin
        self.atrate = 0
        self.prep_dataflash()
        # Prepare static packets
        self.prep_static()

    def prep_dataflash(self):
        """ Prepare data flash, or at least a chunk of it
        """
        df = bytearray(0x2000)
        df[0x000:0x010] = struct.pack('<hHHffh', 12146, 49158, 48942, 3.53481793, 1054300.5, 0) # Cell Gain, Pack Gain, BAT Gain, CC Gain, Capacity Gain, CC Offset
        df[0x010:0x019] = struct.pack('<Hhbbbbb', 64, 0, 0, 0, 0, 0, 0) # Coulomb Counter Offset Samples, Board Offset, Internal Temp Offset, External 0..3 Temp Offset
        df[0x019:0x020] = bytes.fromhex("ff 00 ff 00 00 01 00")
        df[0x020:0x024] = bytes.fromhex("00 00 00 00 00")
        df[0x024:0x040] = b'\xff' * 0x1c
        df[0x040:0x060] = struct.pack('<B31s', 32, b'\x20\x32\x1e\x14\x0afghijklmnopqrstuvwzxy01234') # ManufacturerInfo; size exceeds actual length by 1, so it's kind of broken
        df[0x060:0x062] = bytes.fromhex("02 04")
        df[0x062:0x068] = bytes.fromhex("00 00 00 67 00 00") # ManufacturerInfo2
        df[0x068:0x070] = struct.pack('<HHHH', 0x3a6b, 0, 0x4f5a, 0x0057) # StaticChemDFSignature, ?, ManufactureDate, SerialNumber
        df[0x070:0x085] = struct.pack('<21p', b'SDI') # ManufacturerName
        df[0x085:0x09A] = struct.pack('<21p', b'BA01WM160') # DeviceName
        df[0x09A:0x09F] = struct.pack('<5p', b'2044') # DeviceChemistry
        df[0x0C0:0x0C2] = bytes.fromhex("07 4a")

        df[0x100:0x104] = struct.pack('<hh', 0, 131)
        df[0x104:0x110] = struct.pack('<HHHHHH', 0x2b, 0x2b, 0x2c, 0x29, 0x2b, 0x30)
        df[0x110:0x120] = struct.pack('<HHHHHHHH', 0x2e, 0x31, 0x37, 0x3c, 0x42, 0x58, 0x0db, 0x742)
        df[0x140:0x144] = struct.pack('<hh', 0, 131)
        df[0x180:0x184] = struct.pack('<hh', -171, 308)
        df[0x1c0:0x1c4] = struct.pack('<hh', -171, 308)
        df[0x200:0x204] = struct.pack('<hh', 85, 150)
        df[0x204:0x210] = struct.pack('<HHHHHH', 0x31, 0x31, 0x32, 0x2f, 0x31, 0x37)
        df[0x210:0x220] = struct.pack('<HHHHHHHH', 0x35, 0x38, 0x3f, 0x45, 0x4c, 0x65, 0x0fb, 0x852)
        df[0x220:0x240] = b'\xff' * 0x20
        df[0x240:0x244] = struct.pack('<hh', 85, 153)
        df[0x244:0x250] = struct.pack('<HHHHHH', 0x32, 0x32, 0x34, 0x30, 0x32, 0x38)
        df[0x250:0x260] = struct.pack('<HHHHHHHH', 0x36, 0x39, 0x40, 0x46, 0x4d, 0x67, 0x100, 0x87f)
        df[0x260:0x280] = b'\xff' * 0x20
        df[0x280:0x284] = struct.pack('<hh', -1, 308)
        df[0x2c0:0x2c4] = struct.pack('<hh', -1, 308)
        df[0x144:0x150] = df[0x184:0x190] = df[0x1C4:0x1D0] = df[0x284:0x290] = df[0x2c4:0x2d0] = df[0x104:0x110]
        df[0x150:0x160] = df[0x190:0x1A0] = df[0x1D0:0x1E0] = df[0x290:0x2A0] = df[0x2D0:0x2E0] = df[0x110:0x120]

        df[0x300:0x306] = bytes.fromhex("39 00 1e 00 00 00")
        df[0x306:0x310] = struct.pack('<HHHHH', 2634, 2650, 2500, 2500, 2634)
        df[0x310:0x320] = bytes.fromhex("00 00 0e 6b 10 6e 10 65  10 00 00 70 00 b4 fd 48")
        df[0x320:0x330] = bytes.fromhex("fe 03 00 57 01 82 02 87  fd 29 fe 00 00 00 00 00")
        df[0x380:0x388] = struct.pack('<HHHH', 3894, 3894, 0, 0) # LifetimeDataBlock1 - MaxCellVoltage
        df[0x388:0x390] = struct.pack('<HHHH', 3046, 3053, 32767, 32767) # LifetimeDataBlock1 - MinCellVoltage
        df[0x390:0x392] = struct.pack('<H', 28) # LifetimeDataBlock1 - MaxDeltaCellVoltage
        df[0x392:0x396] = struct.pack('<BBBB', 3, 0, 7, 0) # LifetimeDataBlock2
        df[0x396:0x3a6] = struct.pack('<HHHHHHHH', 0x98f, 0, 0, 0, 0x98d, 0, 0, 0) # LifetimeDataBlock3
        df[0x3a6:0x3a8] = struct.pack('<H', 500)

        df[0x440:0x500] = b'\xff' * 0xc0
        df[0x4c0:0x4c2] = struct.pack('<H', 0x38)
        # Simulating 'proper' values of Data Flash up to offset 0x500
        self.dataflash = df

    def prep_static(self):
        """ Commands for simulated BQ40z307

        Values taken from a real Mavic Mini battery
        """
        df = self.dataflash
        minv = [3500, 3500, 3500, 3500, ] # min (zero charge) voltage
        maxv = [4200, 4200, 4200, 4200, ] # max (full charge) voltage
        maxc = [(self.dc[i] * (1.015 + i/1000)) for i in range(4)] # manufacture time capacity
        wear = max(1.0-self.cyc/800,0.01)
        c = [(self.dc[i] * wear * max(self.v[i]-minv[i],0)/(maxv[i]-minv[i])) for i in range(4)]
        mamp = [0, 0, 0, 0, ] # Current, mAmp
        self.add_read(0x01, struct.pack('<H', 712)) # RemainingCapacityAlarm
        self.add_read(0x02, struct.pack('<H', 10)) # RemainingTimeAlarm
        self.add_read(0x03, struct.pack('<H', 0x6001)) # BatteryMode
        self.add_read(0x04, struct.pack('<H', int(self.atrate))) # AtRate
        self.add_read(0x05, struct.pack('<H', int(min(60*(sum(maxc)-sum(c))/max(self.atrate,0.00001),0xffff)))) # AtRateToFull
        self.add_read(0x06, struct.pack('<H', int(min(60*sum(c)/max(self.atrate,0.00001),0xffff)))) # AtRateToEmpty
        self.add_read(0x07, struct.pack('<H', 1)) # AtRateOK
        self.add_read(0x08, struct.pack('<H', int(self.t*10))) # Temperature
        self.add_read(0x09, struct.pack('<H', int(sum(self.v)))) # Voltage
        self.add_read(0x0a, struct.pack('<H', int(sum(mamp)))) # Current
        self.add_read(0x0b, struct.pack('<H', int(sum(mamp)*0.77))) # AverageCurrent
        self.add_read(0x0c, struct.pack('<H', 2)) # MaxError
        self.add_read(0x0d, struct.pack('<H', int(100*sum(c)//(sum(maxc)*wear)))) # RelativeStateOfCharge
        self.add_read(0x0e, struct.pack('<H', int(100*sum(c)//sum(self.dc)))) # AbsoluteStateOfCharge
        self.add_read(0x0f, struct.pack('<H', int(sum(c)))) # RemainingCapacity
        self.add_read(0x10, struct.pack('<H', int(sum(maxc)*wear))) # FullChargeCapacity
        self.add_read(0x11, struct.pack('<H', 0xffff)) # RunTimeToEmpty
        self.add_read(0x12, struct.pack('<H', 0xffff)) # AverageTimeToEmpty
        self.add_read(0x13, struct.pack('<H', 0xffff)) # AverageTimeToFull
        self.add_read(0x14, struct.pack('<H', 4750)) # ChargingCurrent
        self.add_read(0x15, struct.pack('<H', 0)) # ChargingVoltage
        self.add_read(0x16, struct.pack('<H', 0x00c0)) # BatteryStatus
        self.add_read(0x17, struct.pack('<H', int(self.cyc))) # CycleCount
        self.add_read(0x18, struct.pack('<H', sum(self.dc))) # DesignCapacity
        self.add_read(0x19, struct.pack('<H', sum(self.dv))) # DesignVoltage
        self.add_read(0x1a, struct.pack('<H', 0x0031)) # SpecificationInfo
        self.add_read(0x3c, struct.pack('<H', self.v[3])) # Cell3Voltage
        self.add_read(0x3d, struct.pack('<H', self.v[2])) # Cell2Voltage
        self.add_read(0x3e, struct.pack('<H', self.v[1])) # Cell1Voltage
        self.add_read(0x3f, struct.pack('<H', self.v[0])) # Cell0Voltage
        self.add_read(0x50, struct.pack('<L', 0x0000)) # SafetyAlert
        self.add_read(0x51, struct.pack('<L', 0x0000)) # SafetyStatus
        self.add_read(0x52, struct.pack('<L', 0x0000)) # PFAlert
        self.add_read(0x53, struct.pack('<L', 0x0000)) # PFStatus
        self.add_read(0x54, struct.pack('<L', 0x0c048106)) # OperationStatus
        self.add_read(0x55, struct.pack('<H', 0x0408)) # ChargingStatus
        self.add_read(0x56, struct.pack('<L', 0x091950)[:3]) # GaugingStatus
        self.add_read(0x57, struct.pack('<H', 0x0038)) # ManufacturingStatus
        self.add_read(0x5a, struct.pack('<H', 1261)) # TURBO_FINAL, read as 2-byte block for BQ40z307
        self.add_read(0x71, struct.pack('<HHHHHHHHHHHHHHHH', self.v[0], self.v[1],
          self.v[2], self.v[3], sum(self.v), int(sum(self.v)*1.04),
          mamp[0], mamp[1], mamp[2], mamp[3], self.v[0]*mamp[0],
          self.v[1]*mamp[1], self.v[2]*mamp[2], self.v[3]*mamp[3],
          int(sum(self.v)*sum(mamp)), int(sum(self.v)*sum(mamp)*0.88))) # DAStatus1
        self.add_read(0x72, struct.pack('<HHHHHHH', int(self.t*10-21), int(self.t*10), int(self.t*10-772), int(0*10), int(0*10), int(self.t*10), int(0*10))) # DAStatus2
        self.add_read(0x73, bytes.fromhex("24 04 aa 02 5d 05 2d 04 81 09 d7 06 9c 0b 9c 0b e8 03 e8 03 00 00 00 00 2f 00 30 00 00 00 00 00")) # GaugeStatus1
        self.add_read(0x74, bytes.fromhex("05 0e 00 00 00 00 b0 cd 13 00 5e 21 3e 21 00 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00 00 00")) # GaugeStatus2
        self.add_read(0x75, bytes.fromhex("4a 0a 5a 0a c4 09 c4 09 6f 17 4f 17 00 00 00 00 32 01 99 16 57 01 82 02 60 21 40 21 00 00 00 00")) # GaugeStatus3
        self.add_read(0x76, bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")) # CBStatus
        self.add_read(0x78, struct.pack('<HHHH', int(1059), int(681), int(2432), int(1750))) # FilteredCapacity
        self.add_read(0x7a, bytes.fromhex("72 05")) # ManufacturerInfo2
        # ManufacturerAccess commands
        self.add_read_sub(0x00, 0x01, struct.pack('<H', 0x4307)) # DeviceType
        self.add_read_sub(0x00, 0x02, bytes.fromhex("4307 0101 0027 00 0385 0200")) # FirmwareVersion
        self.add_read_sub(0x00, 0x03, struct.pack('<H', 0x00a1)) # HardwareVersion
        self.add_read_sub(0x00, 0x04, struct.pack('<H', 0x67b2)) # InstrFlashChecksum
        self.add_read_sub(0x00, 0x05, struct.pack('<H', 0x9a31)) # StaticDataFlashChecksum
        self.add_read_sub(0x00, 0x06, struct.pack('<H', 0x2044)) # ChemicalID
        self.add_read_sub(0x00, 0x09, struct.pack('<H', 0xd5fa)) # AllDFSignature
        self.add_read_sub(0x00, 0x35, struct.pack('<LL', int(0x36720414), int(0xffffffff))) # SecurityKeys
        self.add_read_sub(0x00, 0x7a, bytes.fromhex("00 00 45 67")) # ManufacturerInfo2 - somehow through MA it returns different value
        # The chip returns the same invalid data for unsupported ManufacturerBlockAccess commands
        bad_manufc_block_data = bytes.fromhex( ("00 00 13 7f 16 be 94 98 d8 15 "
          "bd a3 f0 fa c5 d9 98 5b 67 78 dc d6 00 f8 53 9f "
          "9c 79 3c c2 21 ce f4 33 a6 50 38 84 37 6f 72 7b 59 00") )
        #TODO should we get values from data space in more dynamic manner?
        self.add_read(0x1b, df[0x06C:0x06E]) # ManufactureDate
        self.add_read(0x1c, df[0x06E:0x070]) # SerialNumber
        # Allow Pascal strings to behave as they do in original dataspace - if first byte is corrupted, they can return too much
        self.add_read(0x20, struct.unpack('<256p', df[0x070:0x170])[0]) # ManufacturerName
        self.add_read(0x21, struct.unpack('<256p', df[0x085:0x185])[0]) # DeviceName
        self.add_read(0x22, struct.unpack('<256p', df[0x09A:0x19A])[0]) # DeviceChemistry
        self.add_read(0x60, df[0x380:0x392]) # LifetimeDataBlock1, 18 bytes for BQ40z307
        self.add_read(0x61, df[0x392:0x396]) # LifetimeDataBlock2, 4 bytes for BQ40z307
        self.add_read(0x62, df[0x396:0x3A6]) # LifetimeDataBlock3
        self.add_read(0x70, struct.unpack('<256p', df[0x040:0x140])[0]) # ManufacturerInfo
        self.add_read_sub(0x00, 0x08, df[0x068:0x06A]) # StaticChemDFSignature
        # For ManufacturerBlockAccess commands, remember to add subcmd word at start

    def add_read(self, register, data):
        self.reads[register] = data

    def add_read_sub(self, register, subreg, data):
        if register not in self.reads_sub.keys():
            self.reads_sub[register] = {}
        self.reads_sub[register][subreg] = data

    def prep_read(self, cmd, cmdinf):
        pass

    def prep_read_sub(self, cmd, cmdinf, subcmd, subcmdinf):
        if 'resp_location' in subcmdinf:
            register = subcmdinf['resp_location'].value
        else:
            register = cmd.value
        if subcmd is None: # No sub-command, just clear the data
            self.mock_reads[register] = b''
        elif cmd.value == 0x44: # ManufacturerBlockAccess clones ManufacturerAccess but adds subcmd word
            if (subcmd.value >= 0x4000) and (subcmd.value < 0x6000): # DataFlashAccess
                offs = subcmd.value - 0x4000
                self.reads[register] = struct.pack('<H', 0x4000+offs) + self.dataflash[offs:offs+0x020]
            elif cmd.value in self.reads_sub and subcmd.value in self.reads_sub[cmd.value]:
                self.reads[register] = self.reads_sub[cmd.value][subcmd.value]
            elif 0x00 in self.reads_sub and subcmd.value in self.reads_sub[0x00]:
                self.reads[register] = struct.pack('<H', subcmd.value) + self.reads_sub[0x00][subcmd.value]
            else: # some MA commands are just mirrors of standard SBS commands
                self.reads[register] = struct.pack('<H', subcmd.value) + self.reads[subcmd.value]
        elif cmd.value in self.reads_sub and subcmd.value in self.reads_sub[cmd.value]:
            self.reads[register] = self.reads_sub[cmd.value][subcmd.value]
        else: # some MA commands are just mirrors of standard SBS commands
            self.reads[register] = self.reads[subcmd.value]

    def do_read(self, i2c_addr, register):
        data = bytes(self.reads[register])
        return data

    def prep_write(self, cmd, cmdinf):
        pass

    def prep_write_sub(self, cmd, cmdinf, subcmd, subcmdinf):
        pass

    def do_write(self, i2c_addr, register, value):
        pass

if (not po.offline_mode) and (po.dry_run):
    global bus
    bus.mock = ChipMockBQ40(bus)
