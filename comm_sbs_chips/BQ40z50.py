#!/usr/bin/env false
# -*- coding: utf-8 -*-

""" Smart Battery System chip definition.

Implemented based on:
* sluua43a.pdf BQ40z50 Technical Reference

Compatible chips:
BQ40z50

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
    BTPDischargeSet			= 0x4a
    BTPChargeSet			= 0x4b
    StateOfHealthPercent	= 0x4f
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
    LifetimeDataBlock4		= 0x63
    LifetimeDataBlock5		= 0x64
    ManufacturerInfo		= 0x70
    DAStatus1				= 0x71
    DAStatus2				= 0x72
    GaugeStatus1			= 0x73
    GaugeStatus2			= 0x74
    GaugeStatus3			= 0x75
    CBStatus				= 0x76
    StateOfHealthPhys		= 0x77
    FilteredCapacity		= 0x78


class SBS_COMMAND_BQ_TURBO(DecoratedEnum):
    """ Commands used in BQ family SBS chips which support TURBO mode
    """
    TURBO_POWER				= 0x59
    TURBO_FINAL				= 0x5a
    TURBO_PACK_R			= 0x5b
    TURBO_SYS_R				= 0x5c
    TURBO_EDV				= 0x5d
    TURBO_CURRENT			= 0x5e


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
    AFERegisters			= 0x58
    LifetimeDataBlock1		= 0x60
    LifetimeDataBlock2		= 0x61
    LifetimeDataBlock3		= 0x62
    LifetimeDataBlock4		= 0x63
    LifetimeDataBlock5		= 0x64
    ManufacturerInfo		= 0x70
    DAStatus1				= 0x71
    DAStatus2				= 0x72
    GaugeStatus1			= 0x73
    GaugeStatus2			= 0x74
    GaugeStatus3			= 0x75
    CBStatus				= 0x76
    StateOfHealthPhys		= 0x77
    FilteredCapacity		= 0x78
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
    INTERRUPT_STATUS		= 0x000
    FET_STATUS				= 0x008
    RX_IN_STATUS			= 0x010
    LATCH_STATUS			= 0x018
    IRQ_ENABLED				= 0x020
    FET_CONTROL				= 0x028
    RX_IN_ENABLE			= 0x030
    RH_OUT_STATUS			= 0x038
    RH_INT_STATUS			= 0x040
    CELL_BALANCE			= 0x048
    ADC_CC_CONTROL			= 0x050
    ADC_MUX_CONTROL			= 0x058
    LED_CONTROL				= 0x060
    FEATURES_CONTROL		= 0x068
    COMP_TIMER_CONTROL		= 0x070
    PROT_DELAY_CONTROL		= 0x078
    OCD_CONTROL				= 0x080
    SCC_CONTROL				= 0x088
    SCD1_CONTROL			= 0x090
    SCD2_CONTROL			= 0x098

SBS_CMD_BQ_AFE_REGISTERS_INFO = {
    SBS_CMD_BQ_AFE_REGISTERS.INTERRUPT_STATUS : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "StIRQ",
        'desc'	: ("AFE Interrupt Status. AFE Hardware interrupt status (for "
          "example, wake time, push-button, and so on)."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.FET_STATUS : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "StFET",
        'desc'	: ("AFE FET Status. AFE FET status (for example, CHG FET, "
          "DSG FET, PCHG FET, FUSE input, and so on)."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.RX_IN_STATUS : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "RXIN",
        'desc'	: ("AFE RXIN. AFE I/O port input status."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.LATCH_STATUS : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "Latch",
        'desc'	: ("AFE Latch Status. AFE protection latch status."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.IRQ_ENABLED : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "EnIRQ",
        'desc'	: ("AFE Interrupt Enable. AFE interrupt control settings."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.FET_CONTROL : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CtFET",
        'desc'	: ("AFE Control. AFE FET control enable setting."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.RX_IN_ENABLE : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "RXIEN",
        'desc'	: ("AFE RXIEN. AFE I/O input enable settings."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.RH_OUT_STATUS : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "RHOUT",
        'desc'	: ("AFE RHOUT. AFE I/O pins output status."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.RH_INT_STATUS : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "RHINT",
        'desc'	: ("AFE RHINT. AFE I/O pins interrupt status."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.CELL_BALANCE : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "StCB",
        'desc'	: ("AFE Cell Balance. AFE cell balancing enable settings and "
          "status."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.ADC_CC_CONTROL : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "ADCCC",
        'desc'	: ("AFE ADC/CC Control. AFE ADC/CC Control settings."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.ADC_MUX_CONTROL : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "ADCMx",
        'desc'	: ("AFE ADC Mux Control. AFE ADC channel selections."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.LED_CONTROL : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CtLED",
        'desc'	: ("AFE LED Control."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.FEATURES_CONTROL : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "FtCtl",
        'desc'	: ("AFE Features Control. AFE control on various HW based "
          "features."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.COMP_TIMER_CONTROL : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "CtCmTm",
        'desc'	: ("AFE Timer Control. AFE comparator and timer control."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.PROT_DELAY_CONTROL : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "PrtTm",
        'desc'	: ("AFE Protection. AFE protection delay time control."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.OCD_CONTROL : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "OCD",
        'desc'	: ("AFE OCD. AFE OCD settings."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.SCC_CONTROL : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "SCC",
        'desc'	: ("AFE SCC. AFE SCC settings."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.SCD1_CONTROL : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "SCD1",
        'desc'	: ("AFE SCD1. AFE SCD1 settings."),
    },
    SBS_CMD_BQ_AFE_REGISTERS.SCD2_CONTROL : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "SCD2",
        'desc'	: ("AFE SCD2. AFE SCD2 settings."),
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
    MaxChargeCurrent		= 0x090
    MaxDischargeCurrent		= 0x0a0
    MaxAvgDischrCurrent		= 0x0b0
    MaxAvgDischrPower		= 0x0c0
    MaxTempCell				= 0x0d0
    MinTempCell				= 0x0d8
    MaxDeltaCellTemp		= 0x0e0
    MaxTempIntSensor		= 0x0e8
    MinTempIntSensor		= 0x0f0
    MaxTempFET				= 0x0f8

SBS_CMD_BQ_LIFETIME_DATA_BLOCK1_INFO = {
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxCellVoltage1 : {
        'type'	: "uint16",
        'unit'	: {'scale':20,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MaxV1",
        'desc'	: ("Max Cell 1 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxCellVoltage2 : {
        'type'	: "uint16",
        'unit'	: {'scale':20,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MaxV2",
        'desc'	: ("Max Cell 2 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxCellVoltage3 : {
        'type'	: "uint16",
        'unit'	: {'scale':20,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MaxV3",
        'desc'	: ("Max Cell 3 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxCellVoltage4 : {
        'type'	: "uint16",
        'unit'	: {'scale':20,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MaxV4",
        'desc'	: ("Max Cell 4 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MinCellVoltage1 : {
        'type'	: "uint16",
        'unit'	: {'scale':20,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MinV1",
        'desc'	: ("Min Cell 1 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MinCellVoltage2 : {
        'type'	: "uint16",
        'unit'	: {'scale':20,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MinV2",
        'desc'	: ("Min Cell 2 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MinCellVoltage3 : {
        'type'	: "uint16",
        'unit'	: {'scale':20,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MinV3",
        'desc'	: ("Min Cell 3 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MinCellVoltage4 : {
        'type'	: "uint16",
        'unit'	: {'scale':20,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MinV4",
        'desc'	: ("Min Cell 4 Voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxDeltaCellVoltage : {
        'type'	: "uint16",
        'unit'	: {'scale':20,'name':"mV"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MaxDV",
        'desc'	: ("Max Delta Cell Voltage. That is, the max cell imbalance voltage."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxChargeCurrent : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MChgI",
        'desc'	: ("Max Charge Current."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxDischargeCurrent : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MDisI",
        'desc'	: ("Max Discharge Current."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxAvgDischrCurrent : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MADisI",
        'desc'	: ("Max Average Discharge Current."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxAvgDischrPower : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "MADisP",
        'desc'	: ("Max Average Discharge Power."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxTempCell : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxTem",
        'desc'	: ("Max Temp Cell."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MinTempCell : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MinTem",
        'desc'	: ("Min Temp Cell."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxDeltaCellTemp : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxDTe",
        'desc'	: ("Max delta of cell temperatute."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxTempIntSensor : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MaxTeS",
        'desc'	: ("Max temperatute on internal sensor."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MinTempIntSensor : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MinTeS",
        'desc'	: ("Min temperatute on internal sensor."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK1.MaxTempFET : {
        'type'	: "uint8",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 8,
        'access'	: "r",
        'tiny_name'	: "MxTFET",
        'desc'	: ("Max temperature of FET."),
    },
}


class SBS_CMD_BQ_LIFETIME_DATA_BLOCK2(DecoratedEnum):
    """ LifetimeDataBlock2 sub-command fields used in BQ40 family SBS chips
    """
    NoOfShutdowns			= 0x000
    NoOfPartialResets		= 0x008
    NoOfFullResets			= 0x010
    NoOfWDTResets			= 0x018
    CBTimeCell1				= 0x020
    CBTimeCell2				= 0x028
    CBTimeCell3				= 0x030
    CBTimeCell4				= 0x038

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


class SBS_CMD_BQ_LIFETIME_DATA_BLOCK4(DecoratedEnum):
    """ LifetimeDataBlock4 sub-command fields used in BQ40 family SBS chips
    """
    NoOfCOVEvents			= 0x000
    LastCOVEvent			= 0x010
    NoOfCUVEvents			= 0x020
    LastCUVEvent			= 0x030
    NoOfOCD1Events			= 0x040
    LastOCD1Event			= 0x050
    NoOfOCD2Events			= 0x060
    LastOCD2Event			= 0x070
    NoOfOCC1Events			= 0x080
    LastOCC1Event			= 0x090
    NoOfOCC2Events			= 0x0a0
    LastOCC2Event			= 0x0b0
    NoOfAOLDEvents			= 0x0c0
    LastAOLDEvent			= 0x0d0
    NoOfASCDEvents			= 0x0e0
    LastASCDEvent			= 0x0f0

SBS_CMD_BQ_LIFETIME_DATA_BLOCK4_INFO = {
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK4.NoOfCOVEvents : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "nCOVEv",
        'desc'	: ("Number of Cell Overvoltage Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK4.LastCOVEvent : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "LCOVEv",
        'desc'	: ("Last Cell Overvoltage Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK4.NoOfCUVEvents : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "nCUVEv",
        'desc'	: ("Number of Cell Undervoltage Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK4.LastCUVEvent : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "LCUVEv",
        'desc'	: ("Last Cell Undervoltage Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK4.NoOfOCD1Events : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "nOCD1E",
        'desc'	: ("Number of Overcurrent in Discharge 1 Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK4.LastOCD1Event : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "LOCD1E",
        'desc'	: ("Last Overcurrent in Discharge 1 Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK4.NoOfOCD2Events : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "nOCD2E",
        'desc'	: ("Number of Overcurrent in Discharge 2 Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK4.LastOCD2Event : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "LOCD2E",
        'desc'	: ("Last Overcurrent in Discharge 2 Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK4.NoOfOCC1Events : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "nOCC1E",
        'desc'	: ("Number of Overcurrent in Charge 1 Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK4.LastOCC1Event : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "LOCC1E",
        'desc'	: ("Last Overcurrent in Charge 1 Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK4.NoOfOCC2Events : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "nOCC2E",
        'desc'	: ("Number of Overcurrent in Charge 2 Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK4.LastOCC2Event : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "LOCC2E",
        'desc'	: ("Last Overcurrent in Charge 2 Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK4.NoOfAOLDEvents : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "nOLDEv",
        'desc'	: ("Number of Overload in Discharge Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK4.LastAOLDEvent : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "LOLDEv",
        'desc'	: ("Last Overload in Discharge Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK4.NoOfASCDEvents : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "nSCDEv",
        'desc'	: ("Number of Short Circuit in Discharge Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK4.LastASCDEvent : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "LSCDEv",
        'desc'	: ("Last Short Circuit in Discharge Event."),
    },
}

class SBS_CMD_BQ_LIFETIME_DATA_BLOCK5(DecoratedEnum):
    """ LifetimeDataBlock5 sub-command fields used in BQ40 family SBS chips
    """
    NoOfASCCEvents			= 0x000
    LastASCCEvent			= 0x010
    NoOfOTCEvents			= 0x020
    LastOTCEvent			= 0x030
    NoOfOTDEvents			= 0x040
    LastOTDEvent			= 0x050
    NoOfOTFEvents			= 0x060
    LastOTFEvent			= 0x070
    NoValidChrgTerm			= 0x080
    LastValidChrgTerm		= 0x090
    NoOfQMaxUpdates			= 0x0a0
    LastQMaxUpdate			= 0x0b0
    NoOfRAUpdates			= 0x0c0
    LastRAUpdate			= 0x0d0
    NoOfRADisables			= 0x0e0
    LastRADisable			= 0x0f0

SBS_CMD_BQ_LIFETIME_DATA_BLOCK5_INFO = {
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK5.NoOfASCCEvents : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "nSCCEv",
        'desc'	: ("Number of Short Circuit in Charge Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK5.LastASCCEvent : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "LSCCEv",
        'desc'	: ("Last Short Circuit in Charge Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK5.NoOfOTCEvents : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "nOTCEv",
        'desc'	: ("Number of Overtemperature in Charge Events. Inaccessible due to I2C constrains."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK5.LastOTCEvent : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "LOTCEv",
        'desc'	: ("Last Overtemperature in Charge Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK5.NoOfOTDEvents : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "nOTDEv",
        'desc'	: ("Number of Overtemperature in Discharge Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK5.LastOTDEvent : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "LOTDEv",
        'desc'	: ("Last Overtemperature in Discharge Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK5.NoOfOTFEvents : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "nOTFEv",
        'desc'	: ("Number of Overtemperature FET Events."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK5.LastOTFEvent : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "LOTFEv",
        'desc'	: ("Last Overtemperature FET Event."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK5.NoValidChrgTerm : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "nVChrT",
        'desc'	: ("Number of Valid Charge Terminations."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK5.LastValidChrgTerm : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "LVChrT",
        'desc'	: ("Last Valid Charge Termination."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK5.NoOfQMaxUpdates : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "nQMaxU",
        'desc'	: ("Number of QMax Updates."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK5.LastQMaxUpdate : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "LQMaxU",
        'desc'	: ("Last QMax Update."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK5.NoOfRAUpdates : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "nRAUpd",
        'desc'	: ("Number of RA resistance Updates."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK5.LastRAUpdate : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "LRAUp2",
        'desc'	: ("Last RA resistance Update."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK5.NoOfRADisables : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "nRADis",
        'desc'	: ("Number of RA resistance Disables."),
    },
    SBS_CMD_BQ_LIFETIME_DATA_BLOCK5.LastRADisable : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"dec"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "LRADis",
        'desc'	: ("Last RA resistance Disable."),
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
          "assumed ambient temperature used by the Impedance Track algorithm "
          "for thermal modeling."),
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


class SBS_CMD_BQ_STATE_OF_HEALTH_PHYS(DecoratedEnum):
    """ StateOfHealthPhys sub-command fields used in BQ40 family SBS chips
    """
    SOH_FCC				= 0x000
    SOH_Energy			= 0x010

SBS_CMD_BQ_STATE_OF_HEALTH_PHYS_INFO = {
    SBS_CMD_BQ_STATE_OF_HEALTH_PHYS.SOH_FCC : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mAh"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "FCC",
        'desc'	: ("State-of-Health FCC."),
    },
    SBS_CMD_BQ_STATE_OF_HEALTH_PHYS.SOH_Energy : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"cWh"},
        'nbits'	: 16,
        'access'	: "r",
        'tiny_name'	: "Enrgy",
        'desc'	: ("State-of-Health energy."),
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
    RESERVED6					= 6
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
    SBS_FLAG_OPERATION_STATUS.RESERVED6 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "Res6",
        'desc'	: ("Reserved (Cell Balancing)."),
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
    MAINTENANCE_CHARGE			= 13
    CHARGE_TERMINATION			= 14
    CHARGING_CURRENT_RATE		= 15
    CHARGING_VOLTAGE_RATE		= 16
    CHARGING_CURRENT_COMPNS		= 17
    RESERVED18					= 18
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
    SBS_FLAG_CHARGING_STATUS.CHARGING_CURRENT_RATE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CCR",
        'desc'	: ("Charging Current Rate of Change."),
    },
    SBS_FLAG_CHARGING_STATUS.CHARGING_VOLTAGE_RATE : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CVR",
        'desc'	: ("Charging Voltage Rate of Change."),
    },
    SBS_FLAG_CHARGING_STATUS.CHARGING_CURRENT_COMPNS : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "r",
        'tiny_name'	: "CCC",
        'desc'	: ("Charging Current Loss Compensation."),
    },
    SBS_FLAG_CHARGING_STATUS.RESERVED18 : {
        'type'	: "named_bitfield",
        'unit'	: {'scale':1,'name':"boolean"},
        'nbits'	: 1,
        'value_names'	: ["Inactive","Active"],
        'access'	: "-",
        'tiny_name'	: "ResI",
        'desc'	: ("Reserved bit 18."),
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
        'type'	: "uint24_blk",
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
    MANUFACTURER_ACCESS_CMD_BQ40.AFERegisters : {
        'type'	: "byte[20]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_AFE_REGISTERS_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Output Analog-Front-End register values."),
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
    MANUFACTURER_ACCESS_CMD_BQ40.LifetimeDataBlock4 : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_LIFETIME_DATA_BLOCK4_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Output lifetimes values on ManufacturerData()."),
    },
    MANUFACTURER_ACCESS_CMD_BQ40.LifetimeDataBlock5 : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_LIFETIME_DATA_BLOCK5_INFO,
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
    MANUFACTURER_ACCESS_CMD_BQ40.StateOfHealthPhys : {
        'type'	: "byte[4]",
        'unit'	: {'scale':None,'name':"struct"},
        'resp_location'	: SBS_COMMAND.ManufacturerData,
        'struct_info'	: SBS_CMD_BQ_STATE_OF_HEALTH_PHYS_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("State-of-health full charge capacity and energy."),
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
    SBS_COMMAND_BQ40.BTPDischargeSet : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"mAh"},
        'access_per_seal'	: ("rw","rw","rw",),
        'desc'	: ("The BTP set threshold for discharge mode. Allows updating "
          "threshold for the next Battery Trip Point interrupt, while also "
          "de-asserts the present BTP interrupt, and clears the  "
          "OperationStatus[BTP_INT] bit."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.BTPChargeSet : {
        'type'	: "int16",
        'unit'	: {'scale':1,'name':"mV"},
        'access_per_seal'	: ("rw","rw","rw",),
        'desc'	: ("The BTP set threshold for charge mode. Allows updating "
          "threshold for the next Battery Trip Point interrupt, while also "
          "de-asserts the present BTP interrupt, and clears the  "
          "OperationStatus[BTP_INT] bit."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.StateOfHealthPercent : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"bitfields"},
        'bitfields_info'	: SBS_STATE_OF_HEALTH_PERCENT_INFO,
        'access_per_seal'	: ("r","r","r",),
        'desc'	: ("Battery SoH information, in % of design params. Returns "
          "percentage of design capacity and design energy."),
        'getter'	: "simple",
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
        'type'	: "uint24_blk",
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
    SBS_COMMAND_BQ40.AFERegisters : {
        'type'	: "byte[20]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_AFE_REGISTERS_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Analog-Front-End reg values from ManufacturerData(). "
          "In sealed mode, use ManufacturerAccess() instead."),
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
    SBS_COMMAND_BQ40.LifetimeDataBlock4 : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_LIFETIME_DATA_BLOCK4_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Lifetime data values, block 4. The same values "
          "as in corresponding ManufacturerData() command."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ40.LifetimeDataBlock5 : {
        'type'	: "byte[32]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_LIFETIME_DATA_BLOCK5_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("Lifetime data values, block 5. The same values "
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
    SBS_COMMAND_BQ40.StateOfHealthPhys : {
        'type'	: "byte[4]",
        'unit'	: {'scale':None,'name':"struct"},
        'struct_info'	: SBS_CMD_BQ_STATE_OF_HEALTH_PHYS_INFO,
        'access_per_seal'	: ("-","r","r",),
        'desc'	: ("State-of-health full charge capacity and energy. "
          "The same values "
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
}

SBS_CMD_BQ40_TURBO_INFO = {
    SBS_COMMAND_BQ_TURBO.TURBO_POWER : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"cW"},
        'access_per_seal'	: ("r","r","rw",),
        'desc'	: ("Max Peak Power for the battery pack config. Computes "
          "and provides Max Power information based on the battery pack "
          "configuration. The gauge computes a new RAM value every second."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ_TURBO.TURBO_FINAL : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"cW"},
        'access_per_seal'	: ("rw","rw","rw",),
        'desc'	: ("Minimal TURBO-mode power level during active operation. "
          "Min Turbo Power represents minimal TURBO BOOST mode power level "
          "during active operation (e.g., non-SLEEP)."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ_TURBO.TURBO_PACK_R : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mOhm"},
        'access_per_seal'	: ("rw","rw","rw",),
        'desc'	: ("Battery pack serial resistance. The serial resistance "
          "includes FETs, traces, sense resistors, etc. This accesses the "
          "actual data flash value PackResistance."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ_TURBO.TURBO_SYS_R : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mOhm"},
        'access_per_seal'	: ("rw","rw","rw",),
        'desc'	: ("System serial resistance. Resistance along the path from "
          "battery to system power converter input that includes FETs, "
          "traces, sense resistors, etc. This accesses the actual data flash "
          "value SystemResistance."),
        'getter'	: "simple",
    },
    SBS_COMMAND_BQ_TURBO.TURBO_EDV : {
        'type'	: "uint16",
        'unit'	: {'scale':1,'name':"mV"},
        'access_per_seal'	: ("rw","rw","rw",),
        'desc'	: ("Minimal system power converter operational voltage. "
          "Minimal Voltage at system power converter input at which the "
          "system will still operate. This accesses the actual data "
          "flash value of TerminateVoltage. Older name was MIN_SYS_V."),
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
SBS_CMD_INFO.update(SBS_CMD_BQ40_INFO)
# Support of TURBO
SBS_CMD_INFO.update(SBS_CMD_BQ40_TURBO_INFO)


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
        SBS_COMMAND_BQ40.LifetimeDataBlock1,
        SBS_COMMAND_BQ40.LifetimeDataBlock2,
        SBS_COMMAND_BQ40.LifetimeDataBlock3,
        SBS_COMMAND_BQ40.LifetimeDataBlock4,
        SBS_COMMAND_BQ40.LifetimeDataBlock5,
    ),
    MONITOR_GROUP.BQLifetimeDataMA : (
        MANUFACTURER_ACCESS_CMD_BQ40.ManufacturerInfo,
        MANUFACTURER_ACCESS_CMD_BQ40.LifetimeDataBlock1,
        MANUFACTURER_ACCESS_CMD_BQ40.LifetimeDataBlock2,
        MANUFACTURER_ACCESS_CMD_BQ40.LifetimeDataBlock3,
        MANUFACTURER_ACCESS_CMD_BQ40.LifetimeDataBlock4,
        MANUFACTURER_ACCESS_CMD_BQ40.LifetimeDataBlock5,
    ),
    MONITOR_GROUP.ImpedanceTrack : (
        SBS_COMMAND_BQ40.DAStatus1,
        SBS_COMMAND_BQ40.DAStatus2,
        SBS_COMMAND_BQ40.GaugeStatus1,
        SBS_COMMAND_BQ40.GaugeStatus2,
        SBS_COMMAND_BQ40.GaugeStatus3,
        SBS_COMMAND_BQ40.CBStatus,
        SBS_COMMAND_BQ40.StateOfHealthPhys,
        SBS_COMMAND_BQ40.FilteredCapacity,
    ),
    MONITOR_GROUP.ImpedanceTrackMA : (
        MANUFACTURER_ACCESS_CMD_BQ40.DAStatus1,
        MANUFACTURER_ACCESS_CMD_BQ40.DAStatus2,
        MANUFACTURER_ACCESS_CMD_BQ40.GaugeStatus1,
        MANUFACTURER_ACCESS_CMD_BQ40.GaugeStatus2,
        MANUFACTURER_ACCESS_CMD_BQ40.GaugeStatus3,
        MANUFACTURER_ACCESS_CMD_BQ40.CBStatus,
        MANUFACTURER_ACCESS_CMD_BQ40.StateOfHealthPhys,
        MANUFACTURER_ACCESS_CMD_BQ40.FilteredCapacity,
    ),
    MONITOR_GROUP.BQCellVoltages : (
        SBS_COMMAND_BQ40.Cell0Voltage,
        SBS_COMMAND_BQ40.Cell1Voltage,
        SBS_COMMAND_BQ40.Cell2Voltage,
        SBS_COMMAND_BQ40.Cell3Voltage,
        SBS_COMMAND_BQ40.BTPDischargeSet,
        SBS_COMMAND_BQ40.BTPChargeSet,
        SBS_COMMAND_BQ40.StateOfHealthPercent,
    ),
}

SBS_CMD_GROUPS_BQ40_TURBO = {
    MONITOR_GROUP.BQTurboMode : (
        SBS_COMMAND_BQ_TURBO.TURBO_POWER,
        SBS_COMMAND_BQ_TURBO.TURBO_FINAL,
        SBS_COMMAND_BQ_TURBO.TURBO_PACK_R,
        SBS_COMMAND_BQ_TURBO.TURBO_SYS_R,
        SBS_COMMAND_BQ_TURBO.TURBO_EDV,
        SBS_COMMAND_BQ_TURBO.TURBO_CURRENT,
    ),
}

global SBS_CMD_GROUPS
SBS_CMD_GROUPS.update(SBS_CMD_GROUPS_BQ40)
# Support of TURBO
SBS_CMD_GROUPS.update(SBS_CMD_GROUPS_BQ40_TURBO)

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
        # Prepare static packets
        self.prep_static()

    def prep_static(self):
        """ Commands for simulated BQ40z50

        Not real values - just made up data which meets spec requirements
        """
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
        self.add_read(0x1b, struct.pack('<H', 0x4f5a)) # ManufactureDate
        self.add_read(0x1c, struct.pack('<H', 0x0057)) # SerialNumber
        self.add_read(0x20, b'SDI') # ManufacturerName
        self.add_read(0x21, b'BA01WM160') # DeviceName
        self.add_read(0x22, b'2044') # DeviceChemistry
        self.add_read(0x3c, struct.pack('<H', self.v[3])) # Cell3Voltage
        self.add_read(0x3d, struct.pack('<H', self.v[2])) # Cell2Voltage
        self.add_read(0x3e, struct.pack('<H', self.v[1])) # Cell1Voltage
        self.add_read(0x3f, struct.pack('<H', self.v[0])) # Cell0Voltage
        self.add_read(0x4a, struct.pack('<H', 0x0000)) # BTPDischargeSet
        self.add_read(0x4b, struct.pack('<H', 0x0000)) # BTPChargeSet
        self.add_read(0x4f, struct.pack('<BB', 0, 0)) # StateOfHealthPercent
        self.add_read(0x50, struct.pack('<L', 0x0000)) # SafetyAlert
        self.add_read(0x51, struct.pack('<L', 0x0000)) # SafetyStatus
        self.add_read(0x52, struct.pack('<L', 0x0000)) # PFAlert
        self.add_read(0x53, struct.pack('<L', 0x0000)) # PFStatus
        self.add_read(0x54, struct.pack('<L', 0x0c048106)) # OperationStatus
        self.add_read(0x55, struct.pack('<L', 0x000408)[:3]) # ChargingStatus
        self.add_read(0x56, struct.pack('<L', 0x091950)[:3]) # GaugingStatus
        self.add_read(0x57, struct.pack('<H', 0x0038)) # ManufacturingStatus
        self.add_read(0x58, bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")) # AFERegisters
        self.add_read(0x59, struct.pack('<H', 0)) # TURBO_POWER
        self.add_read(0x5a, struct.pack('<H', 1261)) # TURBO_FINAL
        self.add_read(0x5b, struct.pack('<H', 1)) # TURBO_PACK_R
        self.add_read(0x5c, struct.pack('<H', 1)) # TURBO_SYS_R
        self.add_read(0x5d, struct.pack('<H', 6)) # TURBO_EDV
        self.add_read(0x5e, struct.pack('<H', 21)) # TURBO_CURRENT
        self.add_read(0x60, bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")) # LifetimeDataBlock1
        self.add_read(0x61, bytes.fromhex("00 00 00 00 00 00 00 00")) # LifetimeDataBlock2
        self.add_read(0x62, bytes.fromhex("5c 09 00 00 00 00 00 00 5b 09 00 00 00 00 00 00")) # LifetimeDataBlock3
        self.add_read(0x63, bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")) # LifetimeDataBlock4
        self.add_read(0x64, bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")) # LifetimeDataBlock5
        self.add_read(0x70, b'abcdefghijklmnopqrstuvwzxy012345') # ManufacturerInfo
        self.add_read(0x71, struct.pack('<HHHHHHHHHHHHHHHH', self.v[0], self.v[1],
          self.v[2], self.v[3], sum(self.v), int(sum(self.v)*1.04),
          mamp[0], mamp[1], mamp[2], mamp[3], self.v[0]*mamp[0],
          self.v[1]*mamp[1], self.v[2]*mamp[2], self.v[3]*mamp[3],
          int(sum(self.v)*sum(mamp)), int(sum(self.v)*sum(mamp)*0.88))) # DAStatus1
        self.add_read(0x72, struct.pack('<HHHHHHH', int(self.t*10-21), int(self.t*10), int(self.t*10-772), int(0*10), int(0*10), int(self.t*10), int(0*10))) # DAStatus2
        self.add_read(0x73, bytes.fromhex("24 04 aa 02 5d 05 2d 04 81 09 d7 06 9c 0b 9c 0b e8 03 e8 03 00 00 00 00 2f 00 30 00 00 00 00 00")) # GaugeStatus1
        self.add_read(0x74, bytes.fromhex("05 0e 00 00 00 00 b0 cd 13 00 5e 21 3e 21 00 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00 00 00")) # GaugeStatus2
        self.add_read(0x75, bytes.fromhex("4a 0a 5a 0a c4 09 c4 09 6f 17 4f 17 00 00 00 00 32 01 99 16 57 01 82 02")) # GaugeStatus3
        self.add_read(0x76, bytes.fromhex("00 00 00 00 00 00 00 00")) # CBStatus
        self.add_read(0x77, struct.pack('<HH', 900, 901)) # StateOfHealthPhys
        self.add_read(0x78, struct.pack('<HHHH', int(1059), int(681), int(2432), int(1750))) # FilteredCapacity

        self.add_read_sub(0x00, 0x01, struct.pack('<H', 0x4500)) # DeviceType
        self.add_read_sub(0x00, 0x02, bytes.fromhex("4500 0061 0027 00 0385 0200")) # FirmwareVersion
        self.add_read_sub(0x00, 0x03, struct.pack('<H', 0x00a1)) # HardwareVersion
        self.add_read_sub(0x00, 0x04, struct.pack('<H', 0x67b2)) # InstrFlashChecksum
        self.add_read_sub(0x00, 0x05, struct.pack('<H', 0x9a31)) # StaticDataFlashChecksum
        self.add_read_sub(0x00, 0x06, struct.pack('<H', 0x2044)) # ChemicalID
        self.add_read_sub(0x00, 0x08, struct.pack('<H', 0x3a6b)) # StaticChemDFSignature
        self.add_read_sub(0x00, 0x09, struct.pack('<H', 0xd5fa)) # AllDFSignature
        self.add_read_sub(0x00, 0x35, struct.pack('<LL', int(0x36720414), int(0xffffffff))) # SecurityKeys
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
            if cmd.value in self.reads_sub and subcmd.value in self.reads_sub[cmd.value]:
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
