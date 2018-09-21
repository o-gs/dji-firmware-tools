local f = DJI_SPARK_PROTO.fields

DJI_SPARK_FLIGHT_CONTROL_UART_SRC_DEST = {
    [0] = 'Invalid',
    [1] = 'Camera',
    [2] = 'App',
    [3] = 'Flight Controller',
    [4] = 'Gimbal',
    [5] = 'Center Board',
    [6] = 'Remote Control',
    [7] = 'Wi-Fi air side',
    [8] = 'DM36x transcoder air side',
    [9] = 'HD transmission MCU air side',
    [10] = 'PC',
    [11] = 'Battery',
    [12] = 'ESC',
    [13] = 'DM36x transcoder gnd side',
    [14] = 'HD transmission MCU gnd side',
    [15] = 'Serial-to-parallel (USB ctrl.) air side',
    [16] = 'Serial-to-parallel (USB ctrl.) gnd side',
    [17] = 'Monocular',
    [18] = 'Binocular',
    [19] = 'HD transmission FPGA air side',
    [20] = 'HD transmission FPGA gnd side',
    [21] = 'Simulator',
    [22] = 'Base Station',
    [23] = 'Airborne computing platform',
    [24] = 'RC battery',
    [25] = 'IMU',
    [26] = 'GPS/RTK',
    [27] = 'Wi-Fi gnd side',
    [28] = 'Sig_cvt',
    [29] = 'PMU',
    [30] = 'Unknown',
    [31] = 'Last',
}

DJI_SPARK_FLIGHT_CONTROL_UART_ENCRYPT_TYPE = {
    [0]='None',
    [2]='SeqHash2',
}

DJI_SPARK_FLIGHT_CONTROL_UART_ACK_POLL = {
    [0]="RSP",[1]="CMD",[2]="CMD",[3]="????",
}

DJI_SPARK_FLIGHT_CONTROL_UART_CMD_SET = {
    [0] = 'General',
    [1] = 'Special',
    [2] = 'Camera',
    [3] = 'Flight Control',
    [4] = 'Gimbal',
    [5] = 'Center Board',
    [6] = 'Remote Control',
    [7] = 'Wi-Fi',
    [8] = 'DM36x',
    [9] = 'HD Link',
    [10] = 'Mono/Binocular',
    [11] = 'Simulator',
    [12] = 'ESC',
    [13] = 'Battery',
    [14] = 'Data Logger',
    [15] = 'RTK',
    [16] = 'Automation',
}

-- CMD name decode tables

local GENERAL_CMDS = {
}

local SPECIAL_CMDS = {
}

-- source: dji.go.4_4.1.14, dji.midware.data.config.P3.c
local CAMERA_CMDS = {
    [1] = 'SetPhoto',
    [2] = 'SetRecord',
    [3] = 'SetHeart',
    [5] = 'VirtualKey',
    [4] = 'SwitchUSB',
    [6] = 'GetUSB',
    [16] = 'SetMode',
    [17] = 'GetMode',
    [18] = 'SetImageSize',
    [19] = 'GetImageSize',
    [20] = 'SetImageQuality',
    [21] = 'GetImageQuality',
    [22] = 'SetImageFormat',
    [23] = 'GetImageFormat',
    [24] = 'SetVideoFormat',
    [25] = 'GetVideoFormat',
    [26] = 'SetVideoQuality',
    [27] = 'GetVideoQuality',
    [28] = 'SetVideoStoreFormat',
    [29] = 'GetVideoStoreFormat',
    [30] = 'SetExposureMode',
    [0x1F] = 'GetExposureMode',
    [0x20] = 'SetSceneMode',
    [33] = 'GetSceneMode',
    [34] = 'SetMetering',
    [35] = 'GetMetering',
    [36] = 'SetFocusMode',
    [37] = 'GetFocusMode',
    [38] = 'SetAperture',
    [39] = 'GetAperture',
    [40] = 'SetShutterSpeed',
    [41] = 'GetShutterSpeed',
    [42] = 'SetIso',
    [43] = 'GetIso',
    [44] = 'SetWhiteBalance',
    [45] = 'GetWhiteBalance',
    [46] = 'SetExposureCompensation',
    [0x2F] = 'GetExposureCompensation',
    [0x30] = 'SetFocusArea',
    [50] = 'SetMeteringArea',
    [51] = 'GetMeteringArea',
    [52] = 'SetFocusParam',
    [52] = 'SetZoomParams',
    [56] = 'SetSharpe',
    [57] = 'GetSharpe',
    [58] = 'SetContrast',
    [59] = 'GetContrast',
    [60] = 'SetSaturation',
    [61] = 'GetSaturation',
    [62] = 'SetTonal',
    [0x3F] = 'GetTonal',
    [66] = 'SetDigitalFilter',
    [67] = 'GetDigitalFilter',
    [70] = 'SetAntiFlicker',
    [71] = 'GetAntiFlicker',
    [72] = 'SetContinuous',
    [73] = 'GetContinuous',
    [74] = 'SetTimeParams',
    [75] = 'GetTimeParams',
    [76] = 'SetVOutParams',
    [77] = 'GetVOutParams',
    [78] = 'SetQuickPlayBack',
    [0x4F] = 'GetQuickPlayBack',
    [84] = 'SetDate',
    [94] = 'SetAEBParms',
    [0x5F] = 'GetAEBParams',
    [92] = 'SetFileIndexMode',
    [93] = 'GetFileIndexMode',
    [0x60] = 'SetPushChart',
    [97] = 'GetPushChart',
    [98] = 'SetVideoCaption',
    [99] = 'GetVideoCaption',
    [102] = 'SetStandard',
    [103] = 'GetStandard',
    [108] = 'SetVideoRecordMode',
    [109] = 'GetVideoRecordMode',
    [110] = 'SetPanoMode',
    [104] = 'SetAELock',
    [105] = 'GetAELock',
    [106] = 'SetPhotoMode',
    [107] = 'GetPhotoMode',
    [0x70] = 'GetStateInfo',
    [0x71] = 'GetSDCardParams',
    [0x72] = 'FormatSDCard',
    [0x77] = 'SaveParams',
    [120] = 'LoadParams',
    [0x79] = 'DeletePhoto',
    [0x7A] = 'VideoControl',
    [0x7B] = 'SingleChoice',
    [0x7C] = 'ResponseRc',
    [0x7D] = 'ScaleGesture',
    [0x7E] = 'DragGesture',
    [0x80] = 'GetPushStateInfo',
    [0x81] = 'GetPushShotParams',
    [130] = 'GetPushPlayBackParams',
    [0x83] = 'GetPushChartParams',
    [0x84] = 'GetPushRecordingName',
    [0x86] = 'GetPushCurPanoFileName',
    [0x88] = 'GetPushTimelapseParms',
    [0x85] = 'GetPushRawParams',
    [0x87] = 'GetPushShotInfo',
    [0x89] = 'GetPushTrackingStatus',
    [0x8A] = 'GetPushFovParam',
    [0x92] = 'GetVideoParams',
    [0x93] = 'ControlTransCode',
    [0x95] = 'SetFocusStroke',
    [0x98] = 'GetFileParams',
    [0x9B] = 'SetVideoContrastEnhance',
    [0x9C] = 'GetVideoContrastEnhance',
    [0x9F] = 'SetAudioParma',
    [0xA0] = 'GetAudioParam',
    [0xA1] = 'FormatSSD',
    [0xA3] = 'SetCalibrationControl',
    [0xA5] = 'GetTrackingParms',
    [0xA6] = 'SetTrackingParms',
    [0xA8] = 'SetAEUnlockMode',
    [0xA9] = 'GetAEUnlockMode',
    [170] = 'GetPanoFileParams',
    [0xAB] = 'SetVideoEncode',
    [0xAC] = 'GetVideoEncode',
    [0xAF] = 'SetSSDVideoFormat',
    [0xB0] = 'GetSSDVideoFormat',
    [0x99] = 'GetShotInfo',
    [0x9A] = 'SetFocusAid',
    [0x9D] = 'SetWhiteBalanceArea',
    [0x9E] = 'GetWhiteBalanceArea',
    [0xA1] = 'FormatRawSSD',
    [0xA2] = 'SetFocusDistance',
    [0xA4] = 'SetFocusWindow',
    [0xA7] = 'SetIris',
    [0xAD] = 'SetMCTF',
    [0xAE] = 'GetMCTF',
    [0xB1] = 'SetRecordFan',
    [0xB2] = 'GetRecordFan',
    [0xB3] = 'RequestIFrame',
    [180] = 'GetPushPrepareOpenFan',
    [0xB6] = 'SetForeArmLed',
    [0xB7] = 'GetForeArmLed',
    [0xB8] = 'SetOpticsZoom',
    [0xB9] = 'SetCameraRotationMode',
    [0xBA] = 'GetCameraRotationMode',
    [0xBB] = 'SetLockGimbalWhenShot',
    [0xBD] = 'SetRawVideoFormat',
    [190] = 'GetRawVideoFormat',
    [0xBF] = 'SetFileStar',
    [0xC0] = 'MFDemarcate',
    [0xC1] = 'SetLogMode',
    [0xC2] = 'SetParamName',
    [0xC3] = 'GetParamName',
    [0xC4] = 'SetTapZoom',
    [0xC5] = 'GetTapZoom',
    [0xC6] = 'SetTapZoomTarget',
    [0xC7] = 'GetPushTapZoom',
    [200] = 'SetDefogEnabled',
    [201] = 'GetDefogEnabled',
    [202] = 'SetRawEquipInfo',
    [204] = 'SetSSDRawVideoDigitalFilter',
    [206] = 'GetCalibrationControl',
    [0xCF] = 'SetMechanicalShutter',
    [0xD0] = 'GetMechanicalShutter',
    [209] = 'GetPushDFCInfo',
    [210] = 'SetDustReductionState',
    [0xDD] = 'SetNDFilter',
    [0xDE] = 'SetRawNewParam',
    [0xDF] = 'GetPushRawNewParam',
    [0xE0] = 'GetCapabilityRange',
    [0xF1] = 'TauParam',
    [0xF2] = 'GetPushTauParam',
    [0xF9] = 'GetFocusInfinite',
    [0xFA] = 'SetFocusInfinite',
}

-- source: dji.go.4_4.1.14, dji.midware.data.config.P3.h
local FLIGHT_CTRL_CMDS = {
    [0] = 'SimScan',
    [1] = 'SimGetParams',
    [2] = 'SimParams',
    [5] = 'SimCommand',
    [8] = 'SetFlyForbidArea',
    [9] = 'GetPushFlyForbidStatus',
    [13] = 'SetHaveCheckedStruct',
    [16] = 'A2PushCommom',
    [17] = 'SimRc',
    [28] = 'SetDate',
    [22] = 'SimStatus',
    [39] = 'ExecFly',
    [42] = 'FunctionControl',
    [43] = 'SetIoc',
    [44] = 'GetIoc',
    [45] = 'SetLimits',
    [46] = 'GetLimits',
    [0x2F] = 'SetVoltageWarnning',
    [0x30] = 'GetVoltageWarnning',
    [49] = 'SetHomePoint',
    [50] = 'GetPushDeformStatus',
    [52] = 'GetPlaneName',
    [51] = 'SetPlaneName',
    [57] = 'SetReadFlyDataMode',
    [58] = 'FormatDataRecorder',
    [59] = 'SetFsAction',
    [60] = 'GetFsAction',
    [61] = 'SetTimeZone',
    [62] = 'GetPushRequestLimitUpdate',
    [0x3F] = 'SetFlyForbidAreaData',
    [65] = 'UploadUnlimitAreas',
    [71] = 'EnableUnlimitAreas',
    [66] = 'GetPushUnlimitAreas',
    [67] = 'GetPushCommon',
    [68] = 'GetPushHome',
    [69] = 'GetPushGpsSnr',
    [70] = 'SetPushGpsSnr',
    [81] = 'GetPushSmartBattery',
    [82] = 'SmartLowBatteryAck',
    [83] = 'GetPushAvoidParam',
    [85] = 'GetPushLimitState',
    [86] = 'GetPushLedStatus',
    [97] = 'GetPushActiveRequest',
    [98] = 'SetActiveResult',
    [99] = 'GetPushOnBoardRecv',
    [100] = 'SetSendOnBoard',
    [105] = 'RTKSwitch',
    [103] = 'GetPowerParam',
    [105] = 'SetRTKState',
    [106] = 'GetPushAvoid',
    [108] = 'GetPushRTKLocationData',
    [106] = 'SetBatteryValidStste',
    [0x80] = 'NavigationSwitch',
    [130] = 'UploadWayPointMissionMsg',
    [0x83] = 'DownloadWayPointMissionMsg',
    [0x84] = 'UploadWayPointMsgByIndex',
    [0x85] = 'DownloadWayPointMsgByIndex',
    [0x86] = 'WayPointMissionSwitch',
    [0x8F] = 'NoeMissionPauseOrResume',
    [0x87] = 'WayPointMissionPauseOrResume',
    [0x94] = 'StartNoeMission',
    [0x95] = 'StopNoeMission',
    [0x9C] = 'WayPointMissionSetIdleSpeed',
    [0x88] = 'GetPushWayPointMissionInfo',
    [0x89] = 'GetPushWayPointMissionCurrentEvent',
    [0x8A] = 'StartHotPointMissionWithInfo',
    [0x8B] = 'CancelHotPointMission',
    [140] = 'HotPointMissionSwitch',
    [150] = 'HotPointMissionDownload',
    [0x99] = 'HotPointResetParams',
    [0x9A] = 'HotPointResetRadius',
    [0x9B] = 'HotPointResetCamera',
    [0x8E] = 'JoyStick',
    [0x90] = 'StartFollowMeWithInfo',
    [0x91] = 'CancelFollowMeMission',
    [0x92] = 'FollowMeMissionSwitch',
    [0x93] = 'SendGpsInfo',
    [0x97] = 'StartIoc',
    [0x98] = 'StopIoc',
    [0xA0] = 'SendAgpsData',
    [0xA1] = 'GetPushAgpsState',
    [0xAD] = 'GetPushFlycInstallError',
    [0x9C] = 'SetFlightIdleSpeed',
    [0xB0] = 'GetBatteryGroupsSingleInfo',
    [0xB5] = 'FaultInject',
    [0xB6] = 'GetPushFaultInject',
    [0xB7] = 'SetAndGetRedundancyIMUIndex',
    [0xB8] = 'RedundancyStatus',
    [0xB9] = 'PushRedundancyStatus',
    [204] = 'GetSetWarningAreaEnable',
    [205] = 'UpdateFlyforbidArea',
    [206] = 'PushForbidDataInfos',
    [0xCF] = 'GetNewFlyforbidArea',
    [0xD7] = 'GetPushFlightRecord',
    [0xDA] = 'Detection',
    [0xE9] = 'SetFlyforbidData',
    [0xED] = 'SetEscEcho',
    [0xEE] = 'GetPushGoHomeCountDown',
    [0xF0] = 'GetParamInfoByIndex',
    [0xF1] = 'GetParamsByIndex',
    [0xF2] = 'SetParamsByIndex',
    [0xF3] = 'ResetParamsByIndex',
    [0xF4] = 'GetPushParamsByIndex',
    [0xF5] = 'GetSetVerPhone',
    [0xF7] = 'GetParamInfoByHash',
    [0xF8] = 'GetParamsByHash',
    [0xF9] = 'SetParamsByHash',
    [0xFA] = 'ResetParamsByHash',
    [0xFB] = 'GetPushParamsByHash',
    [0xFC] = 'SetPushParams',
    [0xFE] = 'SetMotorForceDisable',
}

-- source: dji.go.4_4.1.14, dji.midware.data.config.P3.i
local GIMBAL_CMDS = {
    [1] = 'Control',
    [5] = 'GetPushParams',
    [7] = 'RollFinetune',
    [8] = 'AutoCalibration',
    [10] = 'SetAngle',
    [13] = 'SetOnOrOff',
    [12] = 'SpeedControl',
    [10] = 'AngleControl',
    [15] = 'SetUserParams',
    [16] = 'GetUserParams',
    [17] = 'SaveUserParams',
    [19] = 'ResetUserParams',
    [20] = 'AbsAngleControl',
    [28] = 'GetPushType',
    [36] = 'GetPushUserParams',
    [39] = 'GetPushAbnormalStatus',
    [43] = 'GetPushTutorialStatus',
    [44] = 'SetTutorialStep',
    [0x30] = 'GetPushAutoCalibrationStatus',
    [49] = 'RobinSetParams',
    [50] = 'RobinGetParams',
    [51] = 'RobinPushBattery',
    [53] = 'SetHandleParams',
    [54] = 'GetHandleParams',
    [55] = 'SetTimelapseParams',
    [56] = 'GetPushTimelapseStatus',
    [86] = 'NotiFyCameraId',
    [87] = 'GetPushHandheldStickState',
    [88] = 'SetHandheldStickControlEnabled',
    [76] = 'ResetAndSetMode',
}

local CENTER_BRD_CMDS = {
}

-- source: dji.go.4_4.1.14, dji.midware.data.config.P3.o
local RC_CMDS = {
    [1] = 'GetChannelParams',
    [2] = 'SetChannelParams',
    [3] = 'SetCalibration',
    [4] = 'GetHardwareParams',
    [5] = 'GetPushParams',
    [6] = 'SetMaster',
    [7] = 'GetMaster',
    [8] = 'SetName',
    [9] = 'GetName',
    [10] = 'SetPassword',
    [11] = 'GetPassword',
    [12] = 'SetConnectMaster',
    [13] = 'GetConnectMaster',
    [14] = 'GetSearchMasters',
    [15] = 'SetSearchMode',
    [16] = 'GetSearchMode',
    [17] = 'SetToggle',
    [18] = 'GetToggle',
    [19] = 'RequestSlaveJoin',
    [20] = 'GetSlaveList',
    [21] = 'DeleteSlave',
    [22] = 'DeleteMaster',
    [23] = 'SetSlavePermission',
    [24] = 'GetSlavePermission',
    [25] = 'SetControlMode',
    [26] = 'GetControlMode',
    [27] = 'GetPushGpsInfo',
    [30] = 'GetPushBatteryInfo',
    [0x1F] = 'GetPushConnectStatus',
    [0x20] = 'SetPowerMode',
    [34] = 'RequestGimbalCtrPermission',
    [35] = 'AckGimbalCtrPermission',
    [36] = 'SetSimulation',
    [37] = 'GetSimFlyStatus',
    [38] = 'GetSimPushParams',
    [41] = 'SetSlaveMode',
    [42] = 'GetSlaveMode',
    [43] = 'SetGimbalSpeed',
    [44] = 'GetGimbalSpeed',
    [45] = 'SetCustomFuction',
    [46] = 'GetCustomFuction',
    [0x2F] = 'SetFrequency',
    [49] = 'SetRTC',
    [51] = 'SetWheelGain',
    [52] = 'GetWheelGain',
    [53] = 'SetGimbalControlMode',
    [54] = 'GetGimbalControlMode',
    [60] = 'CoachMode',
    [0x3F] = 'MaterSlaveId',
    [66] = 'GetPushFollowFocus',
    [71] = 'AppSpecailControl',
    [72] = 'GetFreqModeInfo',
    [76] = 'GetPushRcProCustomButtonsStatus',
-- Double index 72 .. unclear, what to take.
--    [72] = 'GetRCParam',
	[0x98] = 'GetPushFollowFocus2',
    [0x99] = 'SetFollowFocusInfo',
	[80] = 'SetMCU407',
    [81] = 'GetPushRcCustomButtonsStatus',
    [83] = 'GetRcUnitNLang',
    [84] = 'SetRcUnitNLang',
    [86] = 'GetRcRole',
    [87] = 'GetFDPushConnectStatus',
    [88] = 'SetNewControlFunction',
    [89] = 'GetNewControlFunction',
    [0xF8] = 'GetFDRcCalibrationStatue',
}

-- source: dji.go.4_4.1.14, dji.midware.data.config.P3.s
local WIFI_CMDS = {
    [7] = 'GetSSID',
    [8] = 'SetSSID',
    [9] = 'GetSignalPush',
    [16] = 'SetWifiFrequency',
    [14] = 'GetPassword',
    [13] = 'SetPassword',
    [17] = 'GetPushFirstAppMac',
    [18] = 'GetPushElectricSignal',
    [19] = 'SetPowerMode',
    [21] = 'RestartWifi',
    [22] = 'SetSelectionMode',
    [23] = 'GetSelectionMode',
    [0x20] = 'GetWifiFrequency',
    [38] = 'SetNoiseCheckAdapt',
    [39] = 'SwitchSDR',
    [40] = 'GetChannelList',
    [41] = 'SetSweepFrequency',
    [42] = 'GetPushSweepFrequency',
    [43] = 'SetWifiModeChannel',
    [44] = 'SetWifiCodeRate',
    [45] = 'GetWifiCurCodeRate',
    [46] = 'SetWifiFreq5GMode',
    [0x2F] = 'GetWifiFreqMode',
    [0x30] = 'SetWiFiCountryCode',
--  [0x30] = 'Set Region',
    [51] = 'IsSupportCountryCode',
    [41] = 'RequestSnrPush',
    [0x80] = 'GetPushLog',
    [130] = 'GetPushMasterSlaveStatus',
    [0x83] = 'SetMasterSlaveAuthCode',
    [0x84] = 'ScanMasterList',
    [0x85] = 'ConnectMasterWithIdAuthCode',
    [0x89] = 'GetAuthCode',
    [0x8B] = 'GetPushMSErrorInfo',
}

-- source: dji.go.4_4.1.14, dji.midware.data.config.P3.f
local DM36X_CMDS = {
    [1] = 'SetGParams',
    [2] = 'GetGParams',
    [3] = 'SetParams',
    [4] = 'GetParams',
    [6] = 'GetPushStatus',
    [0x20] = 'SetWifiCodeRate',
    [33] = 'GetWifiCurCodeRate',
    [0x30] = 'SetForesightShowed',
    [49] = 'GetForesightShowed',
    [0x60] = 'SetActiveTrackCamera',
}

-- source: dji.go.4_4.1.14, dji.midware.data.config.P3.m
local HD_LINK_CMDS = {
    [1] = 'GetPushCommon',
    [2] = 'GetPushHome',
    [3] = 'GetPushBasebandState',
    [4] = 'SetFPGA',
    [5] = 'GetFPGA',
    [6] = 'Set9363',
    [7] = 'Get9363',
    [8] = 'GetPushSignalQuality',
    [9] = 'SetSweepFrequency',
    [10] = 'GetPushSweepFrequency',
    [11] = 'GetPushDevicesState',
    [12] = 'GetPushConfig',
    [13] = 'SetConfig',
    [14] = 'SetUsbTransform',
    [16] = 'SetUpgradeTip',
    [17] = 'GetPushChannelStatus',
    [20] = 'SetMaxMcs',
    [21] = 'GetPushMaxMcs',
    [80] = 'SetLED',
    [22] = 'GetPushDebugInfo',
    [0x20] = 'GetPushSdrSweepFrequency',
    [33] = 'GetSdrConfig',
    [34] = 'GetPushSdrConfigInfo',
    [35] = 'SetSdrStatus',
    [36] = 'GetPushSdrStatusInfo',
    [37] = 'GetPushSdrStatusGroundInfo',
    [38] = 'SetSdrAssitantRead',
    [39] = 'SetSdrAssitantWrite',
    [40] = 'SetSdrStartLog',
    [41] = 'GetPushSdrUpwardSweepFrequency',
    [42] = 'GetPushSdrUpwardSelectChannel',
    [45] = 'GetSdrLBT',
    [46] = 'SetSdrLBT',
    [0x30] = 'GetPushWirelessState',
    [52] = 'SetSDRImageTransmissionMode',
    [53] = 'GetSDRImageTransmissionMode',
    [54] = 'GetSDRPushCustomCodeRate',
    [55] = 'GetHdtvPushException',
    [57] = 'SetSDRConfigInfo',
    [58] = 'GetPushSDRNfParams',
    [59] = 'GetPushSDRBarDisturb',
    [60] = 'SetSDRForceBoost',
    [81] = 'SetPower',
    [82] = 'GetPushPowerStatus',
    [83] = 'OsmoCalibration',
    [84] = 'OsmoPushCalibration',
    [87] = 'SetMicGain',
    [88] = 'GetMicGain',
    [89] = 'GetPushMicInfo',
    [98] = 'GetMicEnable',
    [99] = 'SetMicEnable',
    [0x71] = 'SetMainCameraBandwidthPercent',
    [0x72] = 'GetMainCameraBandwidthPercent',
}

local MBINO_CMDS = {
}

-- source: dji.go.4_4.1.14, dji.midware.data.config.P3.p
local SIM_CMDS = {
    [1] = 'GetPushConnectHeartPacket',
    [1] = 'ConnectHeartPacket',
    [2] = 'RequestMainControllerParams',
    [3] = 'GetPushMainControllerReturnParams',
    [4] = 'SimulateFlightCommend',
    [6] = 'GetPushFlightStatusParams',
    [7] = 'SetGetWind',
    [8] = 'SetGetArea',
    [9] = 'SetGetAirParams',
    [10] = 'ForceMoment',
    [11] = 'SetGetTemperature',
    [12] = 'SetGetGravity',
    [13] = 'CrashShutDown',
    [14] = 'CtrlMotor',
    [15] = 'Momentum',
    [16] = 'SetGetArmLength',
    [17] = 'SetGetMassInertia',
    [18] = 'SetGetMotorSetting',
    [19] = 'SetGetBatterySetting',
    [20] = 'GetFrequency',
    [0xFF] = 'ResetAll',
}

local ESC_CMDS = {
}

-- source: dji.go.4_4.1.14, dji.midware.data.config.P3.q
local BATTERY_CMDS = {
    [1] = 'GetStaticData',
    [2] = 'GetPushDynamicData',
    [3] = 'GetPushCellVoltage',
    [4] = 'GetBarCode',
    [5] = 'GetHistory',
    [17] = 'GetSetSelfDischargeDays',
    [18] = 'ShutDown',
    [19] = 'ForceShutDown',
    [20] = 'StartUp',
    [21] = 'GetPair',
    [22] = 'SetPair',
    [34] = 'DataRecordControl',
    [35] = 'Authentication',
    [49] = 'GetPushReArrangement',
    [50] = 'GetMultBatteryInfo',
}

local DATA_LOG_CMDS = {
}

local RTK_CMDS = {
}

local AUTO_CMDS = {
}

DJI_SPARK_FLIGHT_CONTROL_UART_CMD_TYPE = {
    [0] = GENERAL_CMDS,
    [1] = SPECIAL_CMDS,
    [2] = CAMERA_CMDS,
    [3] = FLIGHT_CTRL_CMDS,
    [4] = GIMBAL_CMDS,
    [5] = CENTER_BRD_CMDS,
    [6] = RC_CMDS,
    [7] = WIFI_CMDS,
    [8] = DM36X_CMDS,
    [9] = HD_LINK_CMDS,
    [10] = MBINO_CMDS,
    [11] = SIM_CMDS,
    [12] = ESC_CMDS,
    [13] = BATTERY_CMDS,
    [14] = DATA_LOG_CMDS,
    [15] = RTK_CMDS,
    [16] = AUTO_CMDS,
}

local GENERAL_DISSECT = {
}

local SPECIAL_DISSECT = {
}

local CAMERA_DISSECT = {
}

local FLIGHT_CTRL_DISSECT = {
}

local GIMBAL_DISSECT = {
}

local CENTER_BRD_DISSECT = {
}

local RC_DISSECT = {
}

-- Wi-Fi - Set Region - 0x30

f.flyc_wifi_set_region_str1 = ProtoField.string ("dji_spark.flyc_wifi_set_region_str1", "Region Str1", base.NONE)
f.flyc_wifi_set_region_str2 = ProtoField.string ("dji_spark.flyc_wifi_set_region_str2", "Region Str2", base.NONE)
f.flyc_wifi_set_region_unkn8 = ProtoField.uint16 ("dji_spark.flyc_wifi_set_region_unkn8", "Unknown8", base.HEX)

local function flyc_wifi_set_region_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_wifi_set_region_str1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_wifi_set_region_str2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_wifi_set_region_unkn8, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 10) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Set Region: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Set Region: Payload size different than expected") end
end

local WIFI_DISSECT = {
    [0x30] = flyc_wifi_set_region_dissector,
}

local DM36X_DISSECT = {
}

local HD_LINK_DISSECT = {
}

local MBINO_DISSECT = {
}

local SIM_DISSECT = {
}

local ESC_DISSECT = {
}

local BATTERY_DISSECT = {
}

local DATA_LOG_DISSECT = {
}

local RTK_DISSECT = {
}

local AUTO_DISSECT = {
}


DJI_SPARK_FLIGHT_CONTROL_UART_DISSECT = {
    [0x00] = GENERAL_DISSECT,
    [0x01] = SPECIAL_DISSECT,
    [0x02] = CAMERA_DISSECT,
    [0x03] = FLIGHT_CTRL_DISSECT,
    [0x04] = GIMBAL_DISSECT,
    [0x05] = CENTER_BRD_DISSECT,
    [0x06] = RC_DISSECT,
    [0x07] = WIFI_DISSECT,
    [0x08] = DM36X_DISSECT,
    [0x09] = HD_LINK_DISSECT,
    [0x0A] = MBINO_DISSECT,
    [0x0B] = SIM_DISSECT,
    [0x0c] = ESC_DISSECT,
    [0x0D] = BATTERY_DISSECT,
    [0x0E] = DATA_LOG_DISSECT,
    [0x0F] = RTK_DISSECT,
    [0x10] = AUTO_DISSECT,
}
