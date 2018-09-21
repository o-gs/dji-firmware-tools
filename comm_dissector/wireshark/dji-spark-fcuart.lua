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

local FLIGHT_CTRL_CMDS = {
}

local GIMBAL_CMDS = {
}

local CENTER_BRD_CMDS = {
}

local RC_CMDS = {
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

local DM36X_CMDS = {
}

local HD_LINK_CMDS = {
}

local MBINO_CMDS = {
}

local SIM_CMDS = {
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
