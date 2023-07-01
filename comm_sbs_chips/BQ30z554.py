#!/usr/bin/env false
# -*- coding: utf-8 -*-

""" Smart Battery System chip definition.

Implemented based on:
* sluu852a.pdf BQ30z50-R1 and BQ30z55-R1 Technical Reference
* sluua79.pdf BQ30z554-R1 Technical Reference

Compatible chips:
BQ30z50, BQ30z55, BQ30z554

For list of devices on which these definitons were tested,
see comments within `comm_sbs_bqctrl.py`.
"""

class SBS_COMMAND_BQ30(DecoratedEnum):
    """ Commands used in BQ30 family SBS chips
    """
    ManufacturerInput		= SBS_COMMAND.OptionalMfgFunction5.value # 0x2f
    Cell3Voltage			= SBS_COMMAND.OptionalMfgFunction4.value # 0x3c
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
    AFERegisters			= 0x58
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


class SBS_CMD_BQ_FIRMWARE_VERSION(DecoratedEnum):
    """ FirmwareVersion sub-command fields used in BQ30 family SBS chips
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
        'desc'	: ("Field RR reserved by manufacturer. Either unused or used for internal purposes."),
    },
    SBS_CMD_BQ_FIRMWARE_VERSION.ReservedEE : {
        'type'	: "byte[2]",
        'unit'	: {'scale':1,'name':"hex"},
        'nbits'	: 16,
        'optional'	: True,
        'access'	: "-",
        'tiny_name'	: "ResE",
        'desc'	: ("Field EE reserved by manufacturer. Either unused or used for internal purposes."),
    },
}


class SBS_CMD_BQ_AFE_REGISTERS(DecoratedEnum):
    """ AFERegisters sub-command fields used in BQ family SBS chips
    """
    STATUS					= 0x000
    STATE_CONTROL			= 0x008
    OUTPUT_CONTROL			= 0x010
    OUTPUT_STATUS			= 0x018
    FUNCTION_CONTROL		= 0x020
    CELL_SEL				= 0x028
    OCDV					= 0x030
    OCDD					= 0x038
    SCC						= 0x040
    SCD1					= 0x048
    SCD2					= 0x050

SBS_CMD_BQ_AFE_REGISTERS_INFO = {
    SBS_CMD_BQ_AFE_REGISTERS.STATUS : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "Statu",
        'desc'	: ("STATUS register."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.STATE_CONTROL : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "StCtl",
        'desc'	: ("STATE_CONTROL register."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.OUTPUT_CONTROL : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "OuCtl",
        'desc'	: ("OUTPUT_CONTROL register."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.OUTPUT_STATUS : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "OuSta",
        'desc'	: ("OUTPUT_STATUS register."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.FUNCTION_CONTROL : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "FuCtl",
        'desc'	: ("FUNCTION_CONTROL register."),
    },
}


class SBS_CMD_BQ_LIFETIME_DATA_BLOCK1(DecoratedEnum):
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

SBS_CMD_BQ_LIFETIME_DATA_BLOCK1_INFO = {
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxCellVoltage1 : {
        'type'	: "uint8",
        'unit'	: {'scale':20,'name':"mV"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxV1",
        'desc'	: ("Max Cell 1 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxCellVoltage2 : {
        'type'	: "uint8",
        'unit'	: {'scale':20,'name':"mV"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxV2",
        'desc'	: ("Max Cell 2 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxCellVoltage3 : {
        'type'	: "uint8",
        'unit'	: {'scale':20,'name':"mV"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxV3",
        'desc'	: ("Max Cell 3 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxCellVoltage4 : {
        'type'	: "uint8",
        'unit'	: {'scale':20,'name':"mV"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxV4",
        'desc'	: ("Max Cell 4 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MinCellVoltage1 : {
        'type'	: "uint8",
        'unit'	: {'scale':20,'name':"mV"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MinV1",
        'desc'	: ("Min Cell 1 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MinCellVoltage2 : {
        'type'	: "uint8",
        'unit'	: {'scale':20,'name':"mV"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MinV2",
        'desc'	: ("Min Cell 2 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MinCellVoltage3 : {
        'type'	: "uint8",
        'unit'	: {'scale':20,'name':"mV"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MinV3",
        'desc'	: ("Min Cell 3 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MinCellVoltage4 : {
        'type'	: "uint8",
        'unit'	: {'scale':20,'name':"mV"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MinV4",
        'desc'	: ("Min Cell 4 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxDeltaCellVoltage : {
        'type'	: "uint8",
        'unit'	: {'scale':20,'name':"mV"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxDV",
        'desc'	: ("Max Delta Cell Voltage. That is, the max cell imbalance voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxChargeCurrent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MChgI",
        'desc'	: ("Max Charge Current."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxDischargeCurrent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MDisI",
        'desc'	: ("Max Discharge Current."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxAvgDischrCurrent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MADisI",
        'desc'	: ("Max Average Discharge Current."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxAvgDischrPower : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MADisP",
        'desc'	: ("Max Average Discharge Power."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfCOVEvents : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nCOVEv",
        'desc'	: ("Number of Cell Overvoltage Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.LastCOVEvent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LCOVEv",
        'desc'	: ("Last Cell Overvoltage Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfCUVEvents : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nCUVEv",
        'desc'	: ("Number of Cell Undervoltage Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.LastCUVEvent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LCUVEv",
        'desc'	: ("Last Cell Undervoltage Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfOCD1Events : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nOCD1E",
        'desc'	: ("Number of Overcurrent in Discharge 1 Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.LastOCD1Event : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LOCD1E",
        'desc'	: ("Last Overcurrent in Discharge 1 Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfOCD2Events : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nOCD2E",
        'desc'	: ("Number of Overcurrent in Discharge 2 Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.LastOCD2Event : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LOCD2E",
        'desc'	: ("Last Overcurrent in Discharge 2 Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfOCC1Events : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nOCC1E",
        'desc'	: ("Number of Overcurrent in Charge 1 Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.LastOCC1Event : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LOCC1E",
        'desc'	: ("Last Overcurrent in Charge 1 Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfOCC2Events : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nOCC2E",
        'desc'	: ("Number of Overcurrent in Charge 2 Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.LastOCC2Event : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LOCC2E",
        'desc'	: ("Last Overcurrent in Charge 2 Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfOLDEvents : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nOLDEv",
        'desc'	: ("Number of Overload in Discharge Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.LastOLDEvent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LOLDEv",
        'desc'	: ("Last Overload in Discharge Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfSCDEvents : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nSCDEv",
        'desc'	: ("Number of Short Circuit in Discharge Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.LastSCDEvent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LSCDEv",
        'desc'	: ("Last Short Circuit in Discharge Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfSCCEvents : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nSCCEv",
        'desc'	: ("Number of Short Circuit in Charge Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.LastSCCEvent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LSCCEv",
        'desc'	: ("Last Short Circuit in Charge Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.NoOfOTCEvents : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nOTCEv",
        'desc'	: ("Number of Overtemperature in Charge Events. Inaccessible due to I2C constrains."),
    },
}


class SBS_CMD_BQ_LIFETIME_DATA_BLOCK2(DecoratedEnum):
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

SBS_CMD_BQ_LIFETIME_DATA_BLOCK2_INFO = {
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.LastOTCEvent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LOTCEv",
        'desc'	: ("Last Overtemperature in Charge Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoOfOTDEvents : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nOTDEv",
        'desc'	: ("Number of Overtemperature in Discharge Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.LastOTDEvent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LOTDEv",
        'desc'	: ("Last Overtemperature in Discharge Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoOfOTFEvents : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nOTFEv",
        'desc'	: ("Number of Overtemperature FET Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.LastOTFEvent : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LOTFEv",
        'desc'	: ("Last Overtemperature FET Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoValidChrgTerm : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nVChrT",
        'desc'	: ("Number of Valid Charge Terminations."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.LastValidChrgTerm : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LVChrT",
        'desc'	: ("Last Valid Charge Termination."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoOfQMaxUpdates : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nQMaxU",
        'desc'	: ("Number of QMax Updates."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.LastQMaxUpdate : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LQMaxU",
        'desc'	: ("Last QMax Update."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoOfRAUpdates : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nRAUpd",
        'desc'	: ("Number of RA resistance Updates."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.LastRAUpdate : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LRAUp2",
        'desc'	: ("Last RA resistance Update."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.NoOfRADisables : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "nRADis",
        'desc'	: ("Number of RA resistance Disables."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.LastRADisable : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LRADis",
        'desc'	: ("Last RA resistance Disable."),
    },
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
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.CBTimeCell1 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CBTim1",
        'desc'	: ("Total performed balancing bypass time cell 1."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.CBTimeCell2 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CBTim2",
        'desc'	: ("Total performed balancing bypass time cell 2."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.CBTimeCell3 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CBTim3",
        'desc'	: ("Total performed balancing bypass time cell 3."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.CBTimeCell4 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CBTim4",
        'desc'	: ("Total performed balancing bypass time cell 4."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.MaxTempCell : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxTem",
        'desc'	: ("Max cell temperatute."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.MinTempCell : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MinTem",
        'desc'	: ("Min cell temperatute."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.MaxDeltaCellTemp : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxDTe",
        'desc'	: ("Max delta of cell temperatute."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.MaxTempIntSensor : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxTeS",
        'desc'	: ("Max temperatute on internal sensor."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.MinTempIntSensor : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MinTeS",
        'desc'	: ("Min temperatute on internal sensor."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK2.MaxTempFET : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MxTFET",
        'desc'	: ("Max temperature of FET."),
    },
}


class SBS_CMD_BQ_LIFETIME_DATA_BLOCK3(DecoratedEnum):
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


class SBS_CMD_BQ_VOLTAGES(DecoratedEnum):
    """ Voltages sub-command fields used in BQ30 family SBS chips
    """
    CellVoltage0			= 0x000
    CellVoltage1			= 0x010
    CellVoltage2			= 0x020
    CellVoltage3			= 0x030
    BATVoltage				= 0x040
    PACKVoltage				= 0x050

SBS_CMD_BQ_VOLTAGES_INFO = {
    SBS_CMD_BQ_VOLTAGES.CellVoltage0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Volt0",
        'desc'	: ("Cell Voltage 0."),
    },
    SBS_CMD_BQ_VOLTAGES.CellVoltage1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Volt1",
        'desc'	: ("Cell Voltage 1."),
    },
    SBS_CMD_BQ_VOLTAGES.CellVoltage2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Volt2",
        'desc'	: ("Cell Voltage 2."),
    },
    SBS_CMD_BQ_VOLTAGES.CellVoltage3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Volt3",
        'desc'	: ("Cell Voltage 3."),
    },
    SBS_CMD_BQ_VOLTAGES.BATVoltage : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "BatV",
        'desc'	: ("BAT Voltage."),
    },
    SBS_CMD_BQ_VOLTAGES.PACKVoltage : {
        'type'	: "uint16",
        'unit'	: {'scale':100,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "PackV",
        'desc'	: ("PACK Voltage."),
    },
}


class SBS_CMD_BQ_TEMPERATURES(DecoratedEnum):
    """ Temperatures sub-command fields used in BQ30 family SBS chips
    """
    IntTemperature			= 0x000
    TS1Temperature			= 0x010
    TS2Temperature			= 0x020
    TS3Temperature			= 0x030
    TS4Temperature			= 0x040
    CellTemperature			= 0x050
    FETTemperature			= 0x060

SBS_CMD_BQ_TEMPERATURES_INFO = {
    SBS_CMD_BQ_TEMPERATURES.IntTemperature : {
        'type'	: "uint16",
        'unit'	: {'scale':0.1,'name':"K"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "IntTm",
        'desc'	: ("Int Temperature."),
    },
    SBS_CMD_BQ_TEMPERATURES.TS1Temperature : {
        'type'	: "uint16",
        'unit'	: {'scale':0.1,'name':"K"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TS1Tm",
        'desc'	: ("Temp Sensor 1 Temperature."),
    },
    SBS_CMD_BQ_TEMPERATURES.TS2Temperature : {
        'type'	: "uint16",
        'unit'	: {'scale':0.1,'name':"K"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TS2Tm",
        'desc'	: ("Temp Sensor 2 Temperature."),
    },
    SBS_CMD_BQ_TEMPERATURES.TS3Temperature : {
        'type'	: "uint16",
        'unit'	: {'scale':0.1,'name':"K"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TS3Tm",
        'desc'	: ("Temp Sensor 3 Temperature."),
    },
    SBS_CMD_BQ_TEMPERATURES.TS4Temperature : {
        'type'	: "uint16",
        'unit'	: {'scale':0.1,'name':"K"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "TS4Tm",
        'desc'	: ("Temp Sensor 4 Temperature."),
    },
    SBS_CMD_BQ_TEMPERATURES.CellTemperature : {
        'type'	: "uint16",
        'unit'	: {'scale':0.1,'name':"K"},
        'nbits'	: 16,
        'optional'	: True,
        'access'	: "r",
        'tiny_name'	: "CelTm",
        'desc'	: ("Cell Temperature."),
    },
    SBS_CMD_BQ_TEMPERATURES.FETTemperature : {
        'type'	: "uint16",
        'unit'	: {'scale':0.1,'name':"K"},
        'nbits'	: 16,
        'optional'	: True,
        'access'	: "r",
        'tiny_name'	: "FETTm",
        'desc'	: ("FET Temperature."),
    },
}


class SBS_CMD_BQ_IT_STATUS1(DecoratedEnum):
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

SBS_CMD_BQ_IT_STATUS1_INFO = {
    SBS_CMD_BQ_IT_STATUS1.DepthOfDischg0Cell0 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DOD0_0",
        'desc'	: ("Depth of discharge cell 0."),
    },
    SBS_CMD_BQ_IT_STATUS1.DepthOfDischg0Cell1 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DOD0_1",
        'desc'	: ("Depth of discharge cell 1."),
    },
    SBS_CMD_BQ_IT_STATUS1.DepthOfDischg0Cell2 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DOD0_2",
        'desc'	: ("Depth of discharge cell 2."),
    },
    SBS_CMD_BQ_IT_STATUS1.DepthOfDischg0Cell3 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DOD0_3",
        'desc'	: ("Depth of discharge cell 3."),
    },
    SBS_CMD_BQ_IT_STATUS1.ChargeLastDOD0Upd : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "ChDOD0Up",
        'desc'	: ("Passed charge since last DOD0 update."),
    },
    SBS_CMD_BQ_IT_STATUS1.QMaxCell0 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "QMAX0",
        'desc'	: ("Qmax of cell 0."),
    },
    SBS_CMD_BQ_IT_STATUS1.QMaxCell1 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "QMAX1",
        'desc'	: ("Qmax of cell 1."),
    },
    SBS_CMD_BQ_IT_STATUS1.QMaxCell2 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "QMAX2",
        'desc'	: ("Qmax of cell 2."),
    },
    SBS_CMD_BQ_IT_STATUS1.QMaxCell3 : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "QMAX3",
        'desc'	: ("Qmax of cell 3."),
    },
    SBS_CMD_BQ_IT_STATUS1.TimeSinceStateChg : {
        'type'	: "uint32",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 32,
        'access'	: "r",
        'tiny_name'	: "StateTime",
        'desc'	: ("Time passed since last state change. The changes "
          "accounted are DSG, CHG, RST."),
    },
    SBS_CMD_BQ_IT_STATUS1.DepOfDischEOCCell0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DODEOC0",
        'desc'	: ("Depth of discharge cell0 at End of Charge."),
    },
    SBS_CMD_BQ_IT_STATUS1.DepOfDischEOCCell1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DODEOC1",
        'desc'	: ("Depth of discharge cell1 at End of Charge."),
    },
    SBS_CMD_BQ_IT_STATUS1.DepOfDischEOCCell2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DODEOC2",
        'desc'	: ("Depth of discharge cell2 at End of Charge."),
    },
    SBS_CMD_BQ_IT_STATUS1.DepOfDischEOCCell3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "DODEOC3",
        'desc'	: ("Depth of discharge cell3 at End of Charge."),
    },
}


class SBS_LEARNED_STATUS(DecoratedEnum):
    """ ITStatus2 LearnedStatus fields used in BQ30 family SBS chips
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


class SBS_CMD_BQ_IT_STATUS2(DecoratedEnum):
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

SBS_CMD_BQ_IT_STATUS2_INFO = {
    SBS_CMD_BQ_IT_STATUS2.PackGridPoint : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "PackGrid",
        'desc'	: ("Active pack grid point. Minimum of CellGrid0 to CellGrid3."),
    },
    SBS_CMD_BQ_IT_STATUS2.LearnedStatus : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_LEARNED_STATUS_INFO,
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "LStatus",
        'desc'	: ("Learned status of resistance table."),
    },
    SBS_CMD_BQ_IT_STATUS2.GridCell0 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CellGrid0",
        'desc'	: ("Active grid point cell 0."),
    },
    SBS_CMD_BQ_IT_STATUS2.GridCell1 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CellGrid1",
        'desc'	: ("Active grid point cell 1."),
    },
    SBS_CMD_BQ_IT_STATUS2.GridCell2 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CellGrid2",
        'desc'	: ("Active grid point cell 2."),
    },
    SBS_CMD_BQ_IT_STATUS2.GridCell3 : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CellGrid3",
        'desc'	: ("Active grid point cell 3."),
    },
    SBS_CMD_BQ_IT_STATUS2.CompResCell0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CompRes0",
        'desc'	: ("Last calc temp compensated resistance cell 0."),
    },
    SBS_CMD_BQ_IT_STATUS2.CompResCell1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CompRes1",
        'desc'	: ("Last calc temp compensated resistance cell 1."),
    },
    SBS_CMD_BQ_IT_STATUS2.CompResCell2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CompRes2",
        'desc'	: ("Last calc temp compensated resistance cell 2."),
    },
    SBS_CMD_BQ_IT_STATUS2.CompResCell3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CompRes3",
        'desc'	: ("Last calc temp compensated resistance cell 3."),
    },
    SBS_CMD_BQ_IT_STATUS2.CBTimeCell0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CBTime0",
        'desc'	: ("Calculated cell balancing time cell 0."),
    },
    SBS_CMD_BQ_IT_STATUS2.CBTimeCell1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CBTime1",
        'desc'	: ("Calculated cell balancing time cell 1."),
    },
    SBS_CMD_BQ_IT_STATUS2.CBTimeCell2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CBTime2",
        'desc'	: ("Calculated cell balancing time cell 2."),
    },
    SBS_CMD_BQ_IT_STATUS2.CBTimeCell3 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "CBTime3",
        'desc'	: ("Calculated cell balancing time cell 3."),
    },
    SBS_CMD_BQ_IT_STATUS2.RaScale0 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "RaScale0",
        'desc'	: ("Ra Table scaling factor cell 0."),
    },
    SBS_CMD_BQ_IT_STATUS2.RaScale1 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "RaScale1",
        'desc'	: ("Ra Table scaling factor cell 1."),
    },
    SBS_CMD_BQ_IT_STATUS2.RaScale2 : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "RaScale2",
        'desc'	: ("Ra Table scaling factor cell 2."),
    },
    SBS_CMD_BQ_IT_STATUS2.RaScale3 : {
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
        'desc'	: ("Reserved (Short circt in charge latch)."),
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
        'desc'	: ("Reserved (Short circt in dischg latch)."),
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
        'desc'	: ("Value of the FUSE pin, designed to ignite the chemical "
          "fuse if one of the various safety criteria is violated. Can also "
          "be triggered via SBS for manufacturing test. If not used, it "
          "should be pulled down."),
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
        'desc'	: ("Detected overtemperature using Positive Temperature "
           "Coefficient resistor connected to AFE PTC pin."),
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
    SMB_CAL_ON_LOW				= 25
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
        'tiny_name'	: "STH",
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


MANUFACTURER_ACCESS_CMD_BQ30_INFO = {
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
        'access_per_seal'	: ("r","r","r",), # Tested working on BQ30z55 in sealed mode
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
    MANUFACTURER_ACCESS_CMD_BQ30.InstructionFlashChecksum : {
        'type'	: "uint16_blk",
        'unit'	: {'scale':1,'name':"hex"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'resp_wait'	: 0.35, # 250 turned out to be too little sometimes
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Checksum of the Instruction Flash. Read on "
          "ManufacturerData() after a wait time of 250 ms"),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.DataFlashChecksum : {
        'type'	: "uint16_blk",
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
        'desc'	: ("Resets the device. This counts as Full Device Reset as "
          "well as AFE Reset, the terms used in chip reference doc."),
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
          "or disable automation and allow manual control."),
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
          "device goes to ROM mode ready for re-programming firmware in "
          "Instruction Flash. Thit is often called BootROM mode. Use "
          "0x08 to ManufacturerAccess() to return."),
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
    MANUFACTURER_ACCESS_CMD_BQ30.AFERegisters : {
        'type'	: "byte[]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_AFE_REGISTERS_INFO,
        # doesn't seem to work on sealed BQ30z55
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Output Analog-Front-End register values."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.LifetimeDataBlock1 : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_LIFETIME_DATA_BLOCK1_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Output lifetimes values on ManufacturerData()."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.LifetimeDataBlock2 : {
        'type'	: "byte[27]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_LIFETIME_DATA_BLOCK2_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Output lifetimes values on ManufacturerData()."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.LifetimeDataBlock3 : {
        'type'	: "byte[16]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_LIFETIME_DATA_BLOCK3_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Output lifetimes values on ManufacturerData()."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.ManufacturerInfo : {
        'type'	: "string[32]",
        'unit'	: {'scale':None,'name':"str"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Output 32 bytes of ManufacturerInfo."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.Voltages : {
        'type'	: "byte[12]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_VOLTAGES_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Outputs voltage data values."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.Temperatures : {
        'type'	: "byte[14]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_TEMPERATURES_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Outputs temperature data values. Block size "
          "is either 10 or 14 bytes, depending on chip and firmware."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.ITStatus1 : {
        'type'	: "byte[30]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_IT_STATUS1_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Impedance Track Status parameters 1. Gauging algorithm "
          "related params. Outputs 30 bytes of IT data values."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.ITStatus2 : {
        'type'	: "byte[10]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_IT_STATUS2_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Impedance Track Status parameters 2. Gauging algorithm "
          "related params. Outputs 30 bytes of IT data values."),
    },
    MANUFACTURER_ACCESS_CMD_BQ30.DFAccessRowAddress : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"hex"},
        # Special command - is really an array of commands, shift needs to be added to cmd.value
        'cmd_array'	: 0x1000,
        'resp_location'	: SBS_COMMAND_BQ30.ManufacturerInput,
        'access_per_seal'	: ("-","rw","rw",),
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

global MANUFACTURER_ACCESS_CMD_BQ_INFO
MANUFACTURER_ACCESS_CMD_BQ_INFO.update(MANUFACTURER_ACCESS_CMD_BQ30_INFO)


SBS_CMD_BQ30_INFO = {
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
    SBS_COMMAND_BQ30.ManufacturerInput : {
        'type'	: "byte[]",
        'unit'	: {'scale':None,'name':None},
        'access_per_seal'	: ("rw","rw","rw",),
        'desc'	: ("Either Authentication or ManufacturerInfo, depending on use. "
          "Direct R/W of this command isn't very useful, it is to be used in "
          "compound commands."),
        # We need special algorithm to use this; but simple r/w is possible
        'getter'	: "simple",
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
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_AFE_REGISTERS_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Analog-Front-End reg values from ManufacturerData(). "
          "In sealed mode, use ManufacturerAccess() instead."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.LifetimeDataBlock1 : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_LIFETIME_DATA_BLOCK1_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Lifetime data values, block 1. The values from "
          "ManufacturerData()."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.LifetimeDataBlock2 : {
        'type'	: "byte[27]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_LIFETIME_DATA_BLOCK2_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Lifetime data values, block 2. The values from "
          "ManufacturerData()."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.LifetimeDataBlock3 : {
        'type'	: "byte[16]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_LIFETIME_DATA_BLOCK3_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Lifetime data values, block 3. The values from "
          "ManufacturerData()."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.ManufacturerInfo : {
        'type'	: "string[32]",
        'unit'	: {'scale':1,'name':"str"},
        'access_per_seal'	: ("r","rw","rw",),
        'desc'	: ("Manufacturer Info values. The values from "
          "ManufacturerData()."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.Voltages : {
        'type'	: "byte[12]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_VOLTAGES_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Voltage data values. The values from ManufacturerData()."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.Temperatures : {
        'type'	: "byte[14]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_TEMPERATURES_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("IT data values. The values from ManufacturerData()."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.ITStatus1 : {
        'type'	: "byte[30]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_IT_STATUS1_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Impedance Track Status parameters 1. Gauging algorithm "
          "related params. The values from ManufacturerData()."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ30.ITStatus2 : {
        'type'	: "byte[30]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_IT_STATUS2_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Impedance Track Status parameters 2. Gauging algorithm "
          "related params. The values from ManufacturerData()."),
        'getter'	: "simple",
    },

}

SBS_CMD_BQ30_TURBO_INFO = {
    SBS_COMMAND_BQ_TURBO.TURBO_POWER : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"cW"},
        'access_per_seal'	: ("r","r","rw",),
        'desc'	: ("Max Peak Power for the battery pack config. Computes "
          "and provides Max Power information based on the battery pack "
          "configuration. The device predicts the maximum power pulse "
          "the system can deliver for approximately 10 ms. Value is "
          "negative."),
        'getter'	: "simple",
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
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ_TURBO.TURBO_PACK_R : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mOhm"},
        'access_per_seal'	: ("r","rw","rw",),
        'desc'	: ("Battery pack serial resistance. The serial resistance "
          "includes FETs, traces, sense resistors, etc. This is the "
          "actual data flash value DF.Pack Resistance."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ_TURBO.TURBO_SYS_R : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mOhm"},
        'access_per_seal'	: ("r","rw","rw",),
        'desc'	: ("System serial resistance. Resistance along the path from "
          "battery to system power converter input that includes FETs, "
          "traces, sense resistors, etc. This is the actual data flash "
          "value DF.System Resistance."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ_TURBO.MIN_SYS_V : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'access_per_seal'	: ("r","rw","rw",),
        'desc'	: ("Minimal system power converter operational voltage. "
          "Minimal Voltage at system power converter input at which the "
          "system will still operate. This is initialized to the data "
          "flash value of DF.Terminate Voltage."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ_TURBO.TURBO_CURRENT : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mA"},
        'access_per_seal'	: ("r","r","rw",),
        'desc'	: ("Max supported pulse current. The gauge computes "
          "a maximal discharge current supported by the cell "
          "for a 10 ms pulse. Value is updated every 1 sec."),
        'getter'	: "simple",
    },
}

global SBS_CMD_INFO
SBS_CMD_INFO.update(SBS_CMD_BQ30_INFO)
if po.chip == CHIP_TYPE.BQ30z554: # Support of TURBO
    SBS_CMD_INFO.update(SBS_CMD_BQ30_TURBO_INFO)


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
        'read_cmd':	SBS_COMMAND.ManufacturerAccess,
        'read_subcmd':	MANUFACTURER_ACCESS_CMD_BQ30.DFAccessRowAddress,
        # How much data each cmd_array step represents
        'granularity'	: 32,
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

SBS_CMD_GROUPS_BQ30 = {
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
    MONITOR_GROUP.BQLifetimeData : (
        SBS_COMMAND_BQ30.ManufacturerInfo,
        SBS_COMMAND_BQ30.LifetimeDataBlock1,
        SBS_COMMAND_BQ30.LifetimeDataBlock2,
        SBS_COMMAND_BQ30.LifetimeDataBlock3,
    ),
    MONITOR_GROUP.BQLifetimeDataMA : (
        MANUFACTURER_ACCESS_CMD_BQ30.ManufacturerInfo,
        MANUFACTURER_ACCESS_CMD_BQ30.LifetimeDataBlock1,
        MANUFACTURER_ACCESS_CMD_BQ30.LifetimeDataBlock2,
        MANUFACTURER_ACCESS_CMD_BQ30.LifetimeDataBlock3,
    ),
    MONITOR_GROUP.ImpedanceTrack : (
        SBS_COMMAND_BQ30.Voltages,
        SBS_COMMAND_BQ30.Temperatures,
        SBS_COMMAND_BQ30.ITStatus1,
        SBS_COMMAND_BQ30.ITStatus2,
    ),
    MONITOR_GROUP.ImpedanceTrackMA : (
        MANUFACTURER_ACCESS_CMD_BQ30.Voltages,
        MANUFACTURER_ACCESS_CMD_BQ30.Temperatures,
        MANUFACTURER_ACCESS_CMD_BQ30.ITStatus1,
        MANUFACTURER_ACCESS_CMD_BQ30.ITStatus2,
    ),
    MONITOR_GROUP.BQCellVoltages : (
        SBS_COMMAND_BQ30.Cell0Voltage,
        SBS_COMMAND_BQ30.Cell1Voltage,
        SBS_COMMAND_BQ30.Cell2Voltage,
        SBS_COMMAND_BQ30.Cell3Voltage,
    ),
}

SBS_CMD_GROUPS_BQ30_TURBO = {
    MONITOR_GROUP.BQTurboMode : (
        SBS_COMMAND_BQ_TURBO.TURBO_POWER,
        SBS_COMMAND_BQ_TURBO.TURBO_FINAL,
        SBS_COMMAND_BQ_TURBO.TURBO_PACK_R,
        SBS_COMMAND_BQ_TURBO.TURBO_SYS_R,
        SBS_COMMAND_BQ_TURBO.MIN_SYS_V,
        SBS_COMMAND_BQ_TURBO.TURBO_CURRENT,
    ),
}

global SBS_CMD_GROUPS
SBS_CMD_GROUPS.update(SBS_CMD_GROUPS_BQ30)
if po.chip == CHIP_TYPE.BQ30z554: # Support of TURBO
    SBS_CMD_GROUPS.update(SBS_CMD_GROUPS_BQ30_TURBO)

global SBS_SEALING
SBS_SEALING = {
    "Unseal": {
        'auth' : "SHA-1/HMAC",
        'cmd' : SBS_COMMAND.ManufacturerAccess,
        'subcmd' : MANUFACTURER_ACCESS_CMD_BQ30.UnSealDevice,
    },
    "Seal": {
        'auth' : None,
        'cmd' : SBS_COMMAND.ManufacturerAccess,
        'subcmd' : MANUFACTURER_ACCESS_CMD_BQ30.SealDevice,
    },
    "FullAccess": {
        'auth' : "SHA-1/HMAC",
        'cmd' : SBS_COMMAND.ManufacturerAccess,
        'subcmd' : MANUFACTURER_ACCESS_CMD_BQ30.FullAccessDevice,
    },
    "Check": {
        'auth' : None,
        'cmd' : SBS_COMMAND.ManufacturerAccess,
        'subcmd' : MANUFACTURER_ACCESS_CMD_BQ30.OperationStatus,
    },
}

class ChipMockBQ30(ChipMock):
    def __init__(self, bus, chip=None):
        self.bus = bus
        self.reads = {}
        self.reads_sub = {}
        # Battery status, used for returned packets
        self.v = (3711, 3712, 3713, 0, )
        self.dv = (3800, 3800, 3800, 0, )
        self.dc = (639, 639, 639, 0, )
        self.cyc = 99
        self.t = 29.92
        self.atrate = 0
        self.prep_dataflash()
        # Prepare static packets
        self.prep_static()

    def prep_dataflash(self):
        """ Prepare data flash, or at least a chunk of it
        """
        df = bytearray(0x2000)
        # TODO: Simulate 'proper' values of Data Flash
        self.dataflash = df

    def prep_static(self):
        """ Commands for simulated BQ30z55

        Values taken from a real Mavic Pro battery
        """
        wear = max(1.0-self.cyc/400,0.01)
        c = [(self.dc[i] * wear * max(self.v[i]-3500,0)/700) for i in range(4)]
        self.add_read(0x01, struct.pack('<H', 150)) # RemainingCapacityAlarm
        self.add_read(0x02, struct.pack('<H', 10)) # RemainingTimeAlarm
        self.add_read(0x03, struct.pack('<H', 0x6001)) # BatteryMode
        self.add_read(0x04, struct.pack('<H', int(self.atrate))) # AtRate
        self.add_read(0x05, struct.pack('<H', int(min(60*(sum(self.dc)-sum(c))/max(self.atrate,0.00001),0xffff)))) # AtRateToFull
        self.add_read(0x06, struct.pack('<H', int(min(60*sum(c)/max(self.atrate,0.00001),0xffff)))) # AtRateToEmpty
        self.add_read(0x07, struct.pack('<H', 1)) # AtRateOK
        self.add_read(0x08, struct.pack('<H', int(self.t*100))) # Temperature
        self.add_read(0x09, struct.pack('<H', int(sum(self.v)))) # Voltage
        self.add_read(0x0a, struct.pack('<H', 0)) # Current
        self.add_read(0x0b, struct.pack('<H', 0)) # AverageCurrent
        self.add_read(0x0c, struct.pack('<H', 4)) # MaxError
        self.add_read(0x0d, struct.pack('<H', int(100*sum(c)//(sum(self.dc)*wear)))) # RelativeStateOfCharge
        self.add_read(0x0e, struct.pack('<H', int(100*sum(c)//sum(self.dc)))) # AbsoluteStateOfCharge
        self.add_read(0x0f, struct.pack('<H', int(sum(c)))) # RemainingCapacity
        self.add_read(0x10, struct.pack('<H', int(sum(self.dc)*wear))) # FullChargeCapacity
        self.add_read(0x11, struct.pack('<H', 0xffff)) # RunTimeToEmpty
        self.add_read(0x12, struct.pack('<H', 0xffff)) # AverageTimeToEmpty
        self.add_read(0x13, struct.pack('<H', 0xffff)) # AverageTimeToFull
        self.add_read(0x14, struct.pack('<H', 0)) # ChargingCurrent
        self.add_read(0x15, struct.pack('<H', 0)) # ChargingVoltage
        self.add_read(0x16, struct.pack('<H', 0x48d0)) # BatteryStatus
        self.add_read(0x17, struct.pack('<H', int(self.cyc))) # CycleCount
        self.add_read(0x18, struct.pack('<H', sum(self.dc))) # DesignCapacity
        self.add_read(0x19, struct.pack('<H', sum(self.dv))) # DesignVoltage
        self.add_read(0x1a, struct.pack('<H', 0x0031)) # SpecificationInfo
        self.add_read(0x1b, struct.pack('<H', 0x4661)) # ManufactureDate
        self.add_read(0x1c, struct.pack('<H', 0x0dd3)) # SerialNumber
        self.add_read(0x20, b'ATL NVT') # ManufacturerName
        self.add_read(0x21, b'DJI008') # DeviceName
        self.add_read(0x22, b'LION') # DeviceChemistry
        self.add_read(0x3c, struct.pack('<H', self.v[3])) # Cell3Voltage
        self.add_read(0x3d, struct.pack('<H', self.v[2])) # Cell2Voltage
        self.add_read(0x3e, struct.pack('<H', self.v[1])) # Cell1Voltage
        self.add_read(0x3f, struct.pack('<H', self.v[0])) # Cell0Voltage
        self.add_read(0x50, struct.pack('<L', 0x0000)) # SafetyAlert
        self.add_read(0x51, struct.pack('<L', 0x0000)) # SafetyStatus
        self.add_read(0x52, struct.pack('<L', 0x0000)) # PFAlert
        self.add_read(0x53, struct.pack('<L', 0x0005)) # PFStatus
        self.add_read(0x54, struct.pack('<L', 0x107200)) # OperationStatus
        self.add_read(0x55, struct.pack('<L', 0x000000)[:3]) # ChargingStatus
        self.add_read(0x56, struct.pack('<H', 0x0817)) # GaugingStatus
        self.add_read(0x57, struct.pack('<H', 0x0058)) # ManufacturingStatus
        self.add_read(0x58, bytes.fromhex("00 20 00 00 00 04 0f 0f 20 44 46 0d")) # AFERegisters
        self.add_read(0x60, bytes.fromhex("ec e5 ec 00 7b 83 a9 00 44 16 45 2a 70 2a 0b 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")) # LifetimeDataBlock1
        self.add_read(0x61, bytes.fromhex("00 00 00 00 00 07 0b 01 09 22 0b 03 0b 01 00 0a 00 22 00 18 00 3b ff 75 30 f9 80")) # LifetimeDataBlock2
        self.add_read(0x62, bytes.fromhex("12 4a 18 00 f8 04 8b 19 58 2a 0e 01 0d 00 01 00")) # LifetimeDataBlock3
        self.add_read(0x70, b'abcdefghijklmnopqrstuvwzxy012345') # ManufacturerInfo
        self.add_read(0x71, struct.pack('<HHHHHH', self.v[0], self.v[1], self.v[2], self.v[3], sum(self.v), int(sum(self.v)*1.04//100))) # Voltages
        self.add_read(0x72, struct.pack('<HHHHHHH', int(self.t*100-9), int(self.t*100-20), int(self.t*100), int(self.t*100), int(self.t*100), int(self.t*100), int(self.t*100-100))) # Temperatures
        self.add_read(0x73, bytes.fromhex("c0 03 e0 03 a0 05 00 00 00 00 ad 07 7e 07 bd 07 7b 07 00 00 34 04 00 00 30 00 18 01 00 00")) # ITStatus1
        self.add_read(0x74, bytes.fromhex("01 0e 01 01 01 00 7d 00 5a 00 8a 00 00 00 d9 39 00 00 00 00 00 00 e8 03 e8 03 e8 03 00 00")) # ITStatus2
        self.add_read_sub(0x00, 0x02, bytes.fromhex("0550 0036 0034 00 0380 0001 0083")) # FirmwareVersion
        if False: # UnSealDevice M zero-filled key
            self.add_read_sub(0x00, 0x31, reversed(bytes.fromhex("C82CA3CA 10DEC726 8E070A7C F0D1FE82 20AAD3B8")))
            # For above case, HMAC2=fb8a342458e0b136988cb5203bb23f94dfd4440e
        if True: # UnSealDevice M default key
            self.add_read_sub(0x00, 0x31, reversed(bytes.fromhex("12b59558 b6d20605 121149b1 16af564a ae19a256")))
            # For above case, HMAC2=fca9642f6846e01f219c6ed7160b2f15cddeb1bc

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
        if subcmd is None:
            self.mock_reads[register] = b''
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
    bus.mock = ChipMockBQ30(bus)
