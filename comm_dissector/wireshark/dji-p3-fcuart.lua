local f = DJI_P3_PROTO.fields

DJI_P3_FLIGHT_CONTROL_UART_SRC_DEST = {
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

DJI_P3_FLIGHT_CONTROL_UART_ENCRYPT_TYPE = {
    [0]='None',
    [2]='SeqHash2',
}

DJI_P3_FLIGHT_CONTROL_UART_ACK_POLL = {
    [0]="RSP",[1]="CMD",[2]="CMD",[3]="????"
}

DJI_P3_FLIGHT_CONTROL_UART_CMD_SET = {
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

local GENERAL_UART_CMD_TEXT = {
    [0x01] = 'Inquiry',
    [0x07] = 'TBD',
    [0x0b] = 'REBOOT',
    [0x0c] = 'TBD',
    [0x0e] = 'Message', -- It looks like it was supposed to transmit text messages, but is always empty
    [0x0f] = 'Upgrade Self Request',
    [0x24] = 'Camera Files',
    [0x27] = 'Camera File',
    [0x32] = 'TBD',
    [0x42] = 'Common Upgrade Status',
    [0x47] = 'Notify Disconnect',
    [0x52] = 'Common App Gps Config',
    [0xf1] = 'Component State', -- The component is identified by sender field
}

local SPECIAL_UART_CMD_TEXT = {
    [0x01] = 'Old Special Control',
    [0x03] = 'New Special Control',
}

local CAMERA_UART_CMD_TEXT = {
    [0x7c] = 'Camera Shutter Cmd',
    [0x80] = 'Camera State Info',
    [0x81] = 'Camera Shot Params',
    [0x82] = 'Camera Play Back Params',
    [0x83] = 'Camera Chart Info',
    [0x84] = 'Camera Recording Name',
    [0x85] = 'Camera Raw Params',
    [0x86] = 'Camera Cur Pano File Name',
    [0x87] = 'Camera Shot Info',
    [0x88] = 'Camera Timelapse Parms',
    [0x89] = 'Camera Tracking Status',
    [0x8a] = 'Camera Fov Param',
    [0xb4] = 'Camera Prepare Open Fan',
    [0xb8] = 'Camera Optics Zoom Mode',
    [0xc7] = 'Camera Tap Zoom State Info',
    [0xf2] = 'Camera Tau Param',
}

local FLYC_UART_CMD_TEXT = {
    [0x09] = 'Flyc Forbid Status',
    [0x10] = 'A2 Commom',
    [0x1c] = 'TBD',
    [0x2a] = 'App Cmd',
    [0x2f] = 'Set Alarm',
    [0x30] = 'Get Alarm',
    [0x31] = 'Set Home Point',   --AC/RC/APP
    [0x32] = 'Flyc Deform Status',
    [0x33] = 'Set User String',
    [0x34] = 'Get User String',
    [0x39] = 'TBD',
    [0x3a] = 'TBD',
    [0x3b] = 'Set RC Lost Action',
    [0x3c] = 'Get RC Lost Action',
    [0x3d] = 'Set Timezone',
    [0x3e] = 'Flyc Request Limit Update',
    [0x3f] = 'TBD',     --Data transfer
    [0x41] = 'TBD',
    [0x42] = 'Flyc Unlimit State',
    [0x43] = 'Osd General',
    [0x44] = 'Osd Home',
    [0x45] = 'Flyc Gps Snr',
    [0x46] = 'TBD',
    [0x47] = 'Toggle Whitelist',
    [0x50] = 'Imu Data Status',
    [0x51] = 'Flyc Smart Battery',
    [0x52] = 'TBD',
    [0x53] = 'Flyc Avoid Param',
    [0x55] = 'Flyc Limit State',
    [0x56] = 'Flyc Led Status',
    [0x57] = 'Gps Glns',
    [0x60] = 'SVO API Transfer',
    [0x61] = 'Flyc Active Request',
    [0x62] = 'TBD',
    [0x63] = 'Flyc Board Recv',
    [0x64] = 'TBD',
    [0x67] = 'Flyc Power Param',
    [0x6a] = 'Flyc Avoid',
    [0x6c] = 'Flyc Rtk Location Data',
    [0x70] = 'TBD',     --Some licensing string check
    [0x71] = 'TBD',     --Some licensing string check
    [0x74] = 'Get Serial Number',
    [0x75] = 'Write EEPROM FC0',
    [0x76] = 'Read EEPROM FC0',
    [0x80] = 'TBD',
    [0x82] = 'Set Mission Length',
    [0x83] = 'TBD',
    [0x84] = 'TBD',
    [0x85] = 'TBD',
    [0x86] = 'WP Mission go/stop',
    [0x87] = 'WP Mission pasue/resume',
    [0x88] = 'Flyc Way Point Mission Info',
    [0x89] = 'Flyc Way Point Mission Current Event',
    [0x8a] = 'TBD',
    [0x8b] = 'TBD',
    [0x8c] = 'HP Mission pasue/resume',
    [0x8d] = 'TBD',
    [0x8e] = 'TBD',
    [0x90] = 'TBD',
    [0x91] = 'App Request Follow Mission',
    [0x92] = 'Follow Mission pasue/resume',
    [0x93] = 'TBD',
    [0x96] = 'TBD',
    [0x97] = 'TBD',
    [0x98] = 'TBD',
    [0x99] = 'TBD',
    [0x9a] = 'TBD',
    [0x9b] = 'TBD',
    [0x9c] = 'Set WP Mission Idle V',
    [0x9d] = 'Get WP Mission Idle V',
    [0xa1] = 'Flyc Agps Status',
    [0xaa] = 'TBD',
    [0xab] = 'Set Attitude',
    [0xac] = 'Set Tail Lock',
    [0xad] = 'Flyc Flyc Install Error',
    [0xb6] = 'Flyc Fault Inject',
    [0xb9] = 'Flyc Redundancy Status',
    [0xf0] = 'TBD',
    [0xf1] = 'TBD',
    [0xf2] = 'TBD',
    [0xf3] = 'TBD',
    [0xf4] = 'TBD',
    [0xf7] = 'TBD',
    [0xf8] = 'TBD',
    [0xf9] = 'TBD',
    [0xfa] = 'Reset Flyc Params',
    [0xfb] = 'Flyc Params By Hash',
    [0xfc] = 'TBD',
    [0xfd] = 'TBD',
}

local GIMBAL_UART_CMD_TEXT = {
    [0x05] = 'Gimbal Params',
    [0x1c] = 'Gimbal Type',
    [0x24] = 'Gimbal User Params',
    [0x27] = 'Gimbal Abnormal Status',
    [0x2b] = 'Gimbal Tutorial Status',
    [0x30] = 'Gimbal Auto Calibration Status',
    [0x33] = 'Gimbal Battery Info',
    [0x38] = 'Gimbal Timelapse Status',
}

local CENTER_BRD_UART_CMD_TEXT = {
    [0x06] = 'Center Battery Common',
}

local RC_UART_CMD_TEXT = {
    [0x05] = 'Rc Params',
    [0x1c] = 'TBD',
    [0xf0] = 'Set Transciever Pwr Mode',
}

local WIFI_UART_CMD_TEXT = {
    [0x09] = 'Wifi Signal',
    [0x0e] = 'Get PSK',
    [0x11] = 'Wifi First App Mac',
    [0x12] = 'Wifi Elec Signal',
    [0x1e] = 'Get SSID',
    [0x2a] = 'Wifi Sweep Frequency',
}

local DM36X_UART_CMD_TEXT = {
    [0x06] = 'Dm368 Status',
}

local HD_LINK_UART_CMD_TEXT = {
    [0x01] = 'Osd Common',
    [0x02] = 'Osd Home',
    [0x06] = 'Set Transciever Reg',
    [0x08] = 'Osd Signal Quality',
    [0x0a] = 'Osd Sweep Frequency',
    [0x0b] = 'Osd Devices State',
    [0x0c] = 'Osd Config',
    [0x11] = 'Osd Channal Status',
    [0x15] = 'Osd Max Mcs',
    [0x16] = 'Osd Debug Info',
    [0x20] = 'Osd Sdr Sweep Frequency',
    [0x22] = 'Osd Sdr Config Info',
    [0x24] = 'Osd Sdr Status Info',
    [0x25] = 'Osd Sdr Status Ground Info',
    [0x29] = 'Osd Sdr Upward Sweep Frequency',
    [0x2a] = 'Osd Sdr Upward Select Channel',
    [0x30] = 'Osd Wireless State',
    [0x36] = 'Osd Sdr Push Custom Code Rate',
    [0x37] = 'Osd Hdvt Push Exception',
    [0x3a] = 'Osd Sdr Nf Params',
    [0x3b] = 'Osd Sdr Bar Interference',
    [0x52] = 'Osd Power Status',
    [0x54] = 'Osd Osmo Calibration',
    [0x59] = 'Osd Mic Info',
}

local MBINO_UART_CMD_TEXT = {
    [0x01] = 'Eye Log',
    [0x06] = 'Eye Avoidance Param',
    [0x07] = 'Eye Front Avoidance',
    [0x08] = 'Eye Point Avoidance',
    [0x0d] = 'Eye Track Log',
    [0x0e] = 'Eye Point Log',
    [0x19] = 'Eye Flat Check',
    [0x23] = 'Eye Track Status',
    [0x26] = 'Eye Point State',
    [0x2a] = 'Eye Exception',
    [0x2e] = 'Eye Function List',
    [0x2f] = 'Eye Sensor Exception',
    [0x32] = 'Eye Easy Self Calibration',
    [0x39] = 'Eye Vision Tip',
    [0x3a] = 'Eye Precise Landing Energy',
}

local SIM_UART_CMD_TEXT = {
    [0x01] = 'Simulator Connect Heart Packet',
    [0x03] = 'Simulator Main Controller Return Params',
    [0x06] = 'Simulator Flight Status Params',
    [0x07] = 'Simulator Wind',
}

local ESC_UART_CMD_TEXT = {
}

local BATTERY_UART_CMD_TEXT = {
    [0x02] = 'Smart Battery Dynamic Data',
    [0x03] = 'Smart Battery Cell Voltage',
    [0x31] = 'Smart Battery Re Arrangement',
}

local DATA_LOG_UART_CMD_TEXT = {
}

local RTK_UART_CMD_TEXT = {
    [0x09] = 'Rtk Status',
}

local AUTO_UART_CMD_TEXT = {
}

DJI_P3_FLIGHT_CONTROL_UART_CMD_TEXT = {
    [0x00] = GENERAL_UART_CMD_TEXT,
    [0x01] = SPECIAL_UART_CMD_TEXT,
    [0x02] = CAMERA_UART_CMD_TEXT,
    [0x03] = FLYC_UART_CMD_TEXT,
    [0x04] = GIMBAL_UART_CMD_TEXT,
    [0x05] = CENTER_BRD_UART_CMD_TEXT,
    [0x06] = RC_UART_CMD_TEXT,
    [0x07] = WIFI_UART_CMD_TEXT,
    [0x08] = DM36X_UART_CMD_TEXT,
    [0x09] = HD_LINK_UART_CMD_TEXT,
    [0x0a] = MBINO_UART_CMD_TEXT,
    [0x0b] = SIM_UART_CMD_TEXT,
    [0x0c] = ESC_UART_CMD_TEXT,
    [0x0d] = BATTERY_UART_CMD_TEXT,
    [0x0e] = DATA_LOG_UART_CMD_TEXT,
    [0x0f] = RTK_UART_CMD_TEXT,
    [0x10] = AUTO_UART_CMD_TEXT,
}

-- Component state packet
f.general_compn_state_current_state = ProtoField.uint32 ("dji_p3.general_compn_state_current_state", "Current state", base.HEX)
  -- Component state packet flags for OFDM
  f.general_compn_state_ofdm_curr_state_fpga_boot = ProtoField.uint32 ("dji_p3.general_compn_state_ofdm_curr_state_fpga_boot", "E FPGA Boot error", base.HEX, nil, 0x01, "Error in FPGA boot state, final state not reached")
  f.general_compn_state_ofdm_curr_state_fpga_conf = ProtoField.uint32 ("dji_p3.general_compn_state_ofdm_curr_state_fpga_conf", "E FPGA Config error", base.HEX, nil, 0x02, nil)
  f.general_compn_state_ofdm_curr_state_exec_fail1 = ProtoField.uint32 ("dji_p3.general_compn_state_ofdm_curr_state_exec_fail1", "E Exec fail 1", base.HEX, nil, 0x04, "Meaning uncertain")
  f.general_compn_state_ofdm_curr_state_exec_fail2 = ProtoField.uint32 ("dji_p3.general_compn_state_ofdm_curr_state_exec_fail2", "E Exec fail 2", base.HEX, nil, 0x08, "Meaning uncertain")
  f.general_compn_state_ofdm_curr_state_ver_match = ProtoField.uint32 ("dji_p3.general_compn_state_ofdm_curr_state_ver_match", "E RC vs OFDM version mismatch?", base.HEX, nil, 0x20, "Meaning uncertain")
  f.general_compn_state_ofdm_curr_state_tcx_reg = ProtoField.uint32 ("dji_p3.general_compn_state_ofdm_curr_state_tcx_reg", "E Transciever Register error", base.HEX, nil, 0x40, "Error in either ad9363 reg 0x17 or ar8003 reg 0x7C")
  f.general_compn_state_ofdm_curr_state_rx_bad_crc = ProtoField.uint32 ("dji_p3.general_compn_state_ofdm_curr_state_rx_bad_crc", "E Received data CRC fail", base.HEX, nil, 0x400, "Meaning uncertain")
  f.general_compn_state_ofdm_curr_state_rx_bad_seq = ProtoField.uint32 ("dji_p3.general_compn_state_ofdm_curr_state_rx_bad_seq", "E Received data sequence fail", base.HEX, nil, 0x800, "Meaning uncertain")

local function main_general_compn_state_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 4
    local sender = buffer(offset,1):uint()
    offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.general_compn_state_current_state, payload(offset, 4))
    if sender == 0x09 then
        subtree:add_le (f.general_compn_state_ofdm_curr_state_fpga_boot, payload(offset, 4))
        subtree:add_le (f.general_compn_state_ofdm_curr_state_fpga_conf, payload(offset, 4))
        subtree:add_le (f.general_compn_state_ofdm_curr_state_exec_fail1, payload(offset, 4))
        subtree:add_le (f.general_compn_state_ofdm_curr_state_exec_fail2, payload(offset, 4))
        subtree:add_le (f.general_compn_state_ofdm_curr_state_ver_match, payload(offset, 4))
        subtree:add_le (f.general_compn_state_ofdm_curr_state_tcx_reg, payload(offset, 4))
        subtree:add_le (f.general_compn_state_ofdm_curr_state_rx_bad_crc, payload(offset, 4))
        subtree:add_le (f.general_compn_state_ofdm_curr_state_rx_bad_seq, payload(offset, 4))
    else
    end
    offset = offset + 4

end

local GENERAL_UART_CMD_DISSECT = {
    [0xf1] = main_general_compn_state_dissector,
}

local SPECIAL_UART_CMD_DISSECT = {
}

-- Camera - FW Update State - 0x80
f.camera_fw_update_state_unkn0 = ProtoField.uint8 ("dji_p3.camera_fw_update_state_unkn0", "Unknown 0", base.HEX)
f.camera_fw_update_state_flags = ProtoField.uint8 ("dji_p3.camera_fw_update_state_flags", "Flags", base.HEX)
  f.camera_fw_update_state_flags_in_progress = ProtoField.uint8 ("dji_p3.camera_fw_update_state_flags_in_progress", "FW Update In Progress", base.HEX, nil, 0x40)

local function main_camera_fw_update_state_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_fw_update_state_unkn0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_fw_update_state_flags, payload(offset, 1))
    subtree:add_le (f.camera_fw_update_state_flags_in_progress, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FW Update State: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FW Update State: Payload size different than expected") end
end

local CAMERA_UART_CMD_DISSECT = {
    [0x80] = main_camera_fw_update_state_dissector,
}

-- Flight Controller - Osd General - 0x43, identical to flight recorder packet 0x000c

local FLYC_OSD_GENERAL_MODE1_ENUM = {
    [0]="Manual",
    [1]="Atti",
    [2]="Atti_CL",
    [3]="Atti_Hover",
    [4]="Hover",
    [5]="GPS_Blake",
    [6]="GPS_Atti",
    [7]="GPS_CL",
    [8]="GPS_HomeLock",
    [9]="GPS_HotPoint",
    [10]="AssitedTakeoff",
    [11]="AutoTakeoff",
    [12]="AutoLanding",
    [13]="AttiLangding",
    [14]="NaviGo",
    [15]="GoHome",
    [16]="ClickGo",
    [17]="Joystick",
    [23]="Atti_Limited",
    [24]="GPS_Atti_Limited",
    [25]="NaviMissionFollow",
    [26]="NaviSubMode_Tracking",
    [27]="NaviSubMode_Pointing",
    [28]="PANO",
    [29]="Farming",
    [30]="FPV",
    [31]="SPORT",
    [32]="NOVICE",
    [33]="FORCE_LANDING",
    [35]="TERRAIN_TRACKING",
    [36]="NAVI_ADV_GOHOME",
    [37]="NAVI_ADV_LANDING",
    [38]="TRIPOD_GPS",
    [39]="TRACK_HEADLOCK",
    [43]="GENTLE_GPS",
    [100]="OTHER",
}

local FLYC_OSD_GENERAL_COMMAND_ENUM = {
    [1]="AUTO_FLY",
    [2]="AUTO_LANDING",
    [3]="HOMEPOINT_NOW",
    [4]="HOMEPOINT_HOT",
    [5]="HOMEPOINT_LOC",
    [6]="GOHOME",
    [7]="START_MOTOR",
    [8]="STOP_MOTOR",
    [9]="Calibration",
    [10]="DeformProtecClose",
    [11]="DeformProtecOpen",
    [12]="DropGohome",
    [13]="DropTakeOff",
    [14]="DropLanding",
    [15]="DynamicHomePointOpen",
    [16]="DynamicHomePointClose",
    [17]="FollowFunctioonOpen",
    [18]="FollowFunctionClose",
    [19]="IOCOpen",
    [20]="IOCClose",
    [21]="DropCalibration",
    [22]="PackMode",
    [23]="UnPackMode",
    [24]="EnterManaualMode",
    [25]="StopDeform",
    [28]="DownDeform",
    [29]="UpDeform",
    [30]="ForceLanding",
    [31]="ForceLanding2",
    [100]="OTHER",
}

local FLYC_OSD_GENERAL_BATT_TYPE_ENUM = {
    [0]="Unknown",
    [1]="NonSmart",
    [2]="Smart",
}

local FLYC_OSD_GENERAL_GOHOME_STATE_ENUM = {
    [0]="STANDBY",
    [1]="PREASCENDING",
    [2]="ALIGN",
    [3]="ASCENDING",
    [4]="CRUISE",
    [5]="BRAKING",
    [6]="BYPASSING",
    [7]="OTHER",
}

local FLYC_OSD_GENERAL_GOHOME_REASON_ENUM = {
    [0]="NONE",
    [1]="WARNING_POWER_GOHOME",
    [2]="WARNING_POWER_LANDING",
    [3]="SMART_POWER_GOHOME",
    [4]="SMART_POWER_LANDING",
    [5]="LOW_VOLTAGE_LANDING",
    [6]="LOW_VOLTAGE_GOHOME",
    [7]="SERIOUS_LOW_VOLTAGE_LANDING",
    [8]="RC_ONEKEY_GOHOME",
    [9]="RC_ASSISTANT_TAKEOFF",
    [10]="RC_AUTO_TAKEOFF",
    [11]="RC_AUTO_LANDING",
    [12]="APP_AUTO_GOHOME",
    [13]="APP_AUTO_LANDING",
    [14]="APP_AUTO_TAKEOFF",
    [15]="OUTOF_CONTROL_GOHOME",
    [16]="API_AUTO_TAKEOFF",
    [17]="API_AUTO_LANDING",
    [18]="API_AUTO_GOHOME",
    [19]="AVOID_GROUND_LANDING",
    [20]="AIRPORT_AVOID_LANDING",
    [21]="TOO_CLOSE_GOHOME_LANDING",
    [22]="TOO_FAR_GOHOME_LANDING",
    [23]="APP_WP_MISSION",
    [24]="WP_AUTO_TAKEOFF",
    [25]="GOHOME_AVOID",
    [26]="GOHOME_FINISH",
    [27]="VERT_LOW_LIMIT_LANDING",
    [28]="BATTERY_FORCE_LANDING",
    [29]="MC_PROTECT_GOHOME",
}

local FLYC_OSD_GENERAL_START_FAIL_REASON_ENUM = {
    [0x00] = 'Allow start',
    [0x01] = 'Compass error',
    [0x02] = 'Assistant protected',
    [0x03] = 'Device lock protect',
    [0x04] = 'Off radius limit landed',
    [0x05] = 'IMU need adv-calib',
    [0x06] = 'IMU SN error',
    [0x07] = 'Temperature cal not ready',
    [0x08] = 'Compass calibration in progress',
    [0x09] = 'Attitude error',
    [0x0a] = 'Novice mode without gps',
    [0x0b] = 'Battery cell error stop motor',
    [0x0c] = 'Battery communite error stop motor',
    [0x0d] = 'Battery voltage very low stop motor',
    [0x0e] = 'Battery below user low land level stop motor',
    [0x0f] = 'Battery main vol low stop motor',
    [0x10] = 'Battery temp and vol low stop motor',
    [0x11] = 'Battery smart low land stop motor',
    [0x12] = 'Battery not ready stop motor',
    [0x13] = 'May run simulator',
    [0x14] = 'Gear pack mode',
    [0x15] = 'Atti limit',
    [0x16] = 'Product not activation, stop motor',
    [0x17] = 'In fly limit area, need stop motor',
    [0x18] = 'Bias limit',
    [0x19] = 'ESC error',
    [0x1a] = 'IMU is initing',
    [0x1b] = 'System upgrade, stop motor',
    [0x1c] = 'Have run simulator, please restart',
    [0x1d] = 'IMU cali in progress',
    [0x1e] = 'Too large tilt angle when auto take off, stop motor',
    [0x1f] = 'Gyroscope is stuck',
    [0x20] = 'Accel is stuck',
    [0x21] = 'Compass is stuck',
    [0x22] = 'Pressure sensor is stuck',
    [0x23] = 'Pressure read is negative',
    [0x24] = 'Compass mod is huge',
    [0x25] = 'Gyro bias is large',
    [0x26] = 'Accel bias is large',
    [0x27] = 'Compass noise is large',
    [0x28] = 'Pressure noise is large',
    [0x29] = 'SN invalid',
    [0x2a] = 'Pressure slope is large',
    [0x2b] = 'Ahrs error is large',
    [0x2c] = 'Flash operating',
    [0x2d] = 'GPS disconnect',
    [0x2e] = 'Out of whitelist area',
    [0x2f] = 'SD Card Exception',
    [0x3d] = 'IMU No connection',
    [0x3e] = 'RC Calibration',
    [0x3f] = 'RC Calibration Exception',
    [0x40] = 'RC Calibration Unfinished',
    [0x41] = 'RC Calibration Exception2',
    [0x42] = 'RC Calibration Exception3',
    [0x43] = 'Aircraft Type Mismatch',
    [0x44] = 'Found Unfinished Module',
    [0x46] = 'Cyro Abnormal',
    [0x47] = 'Baro Abnormal',
    [0x48] = 'Compass Abnormal',
    [0x49] = 'GPS Abnormal',
    [0x4a] = 'NS Abnormal',
    [0x4b] = 'Topology Abnormal',
    [0x4c] = 'RC Need Cali',
    [0x4d] = 'Invalid Float',
    [0x4e] = 'M600 Bat Too Little',
    [0x4f] = 'M600 Bat Auth Err',
    [0x50] = 'M600 Bat Comm Err',
    [0x51] = 'M600 Bat Dif Volt Large 1',
    [0x52] = 'M600 Bat Dif Volt Large 2',
    [0x53] = 'Invalid Version',
    [0x54] = 'Gimbal Gyro Abnormal',
    [0x55] = 'Gimbal ESC Pitch Non Data',
    [0x56] = 'Gimbal ESC Roll No Data',
    [0x57] = 'Gimbal ESC Yaw No Data',
    [0x58] = 'Gimbal Firm Is Updating',
    [0x59] = 'Gimbal Disorder',
    [0x5a] = 'Gimbal Pitch Shock',
    [0x5b] = 'Gimbal Roll Shock',
    [0x5c] = 'Gimbal Yaw Shock',
    [0x5d] = 'IMU Calibration Finished',
    [0x66] = 'RTK Bad Signal',
    [0x67] = 'RTK Deviation Error',
    [0x65] = 'Bat Version Error',
    [0x72] = 'Gimbal Is Calibrating',
    [0x100]= 'Other',
}

local FLYC_OSD_GENERAL_GPS_STATE_ENUM = {
    [0]="ALREADY",
    [1]="FORBIN",
    [2]="GPSNUM_NONENOUGH",
    [3]="GPS_HDOP_LARGE",
    [4]="GPS_POSITION_NONMATCH",
    [5]="SPEED_ERROR_LARGE",
    [6]="YAW_ERROR_LARGE",
    [7]="COMPASS_ERROR_LARGE",
    [8]="UNKNOWN",
}

local FLYC_OSD_GENERAL_PRODUCT_TYPE_ENUM = {
    [0]="Unknown",
    [1]="Inspire",
    [2]="P3S/P3X",
    [3]="P3X",
    [4]="P3C",
    [5]="OpenFrame",
    [6]="ACEONE",
    [7]="WKM",
    [8]="NAZA",
    [9]="A2",
    [10]="A3",
    [11]="P4",
    [14]="PM820",
    [15]="P34K",
    [16]="wm220",
    [17]="Orange2",
    [18]="Pomato",
    [20]="N3",
    [255]="NoFlyc",
    [100]="None",
}

local FLYC_OSD_GENERAL_IMU_INIT_FAIL_RESON_ENUM = {
    [0]="None/MonitorError",
    [1]="ColletingData",
    [2]="GyroDead",
    [3]="AcceDead",
    [4]="CompassDead",
    [5]="BarometerDead",
    [6]="BarometerNegative",
    [7]="CompassModTooLarge",
    [8]="GyroBiasTooLarge",
    [9]="AcceBiasTooLarge",
    [10]="CompassNoiseTooLarge",
    [11]="BarometerNoiseTooLarge",
    [12]="WaitingMcStationary",
    [13]="AcceMoveTooLarge",
    [14]="McHeaderMoved",
    [15]="McVirbrated",
    [100]="None",
}

f.flyc_osd_general_longtitude = ProtoField.double ("dji_p3.flyc_osd_general_longtitude", "Longtitude", base.DEC)
f.flyc_osd_general_latitude = ProtoField.double ("dji_p3.flyc_osd_general_latitude", "Latitude", base.DEC)
f.flyc_osd_general_relative_height = ProtoField.int16 ("dji_p3.flyc_osd_general_relative_height", "Relative Height", base.DEC, nil, nil, "0.1m, altitude to ground")
f.flyc_osd_general_vgx = ProtoField.int16 ("dji_p3.flyc_osd_general_vgx", "Vgx", base.DEC, nil, nil, "0.1m/s, to ground")
f.flyc_osd_general_vgy = ProtoField.int16 ("dji_p3.flyc_osd_general_vgy", "Vgy", base.DEC, nil, nil, "0.1m/s, to ground")
f.flyc_osd_general_vgz = ProtoField.int16 ("dji_p3.flyc_osd_general_vgz", "Vgz", base.DEC, nil, nil, "0.1m/s, to ground")
f.flyc_osd_general_pitch = ProtoField.int16 ("dji_p3.flyc_osd_general_pitch", "Pitch", base.DEC, nil, nil, "0.1")
f.flyc_osd_general_roll = ProtoField.int16 ("dji_p3.flyc_osd_general_roll", "Roll", base.DEC)
f.flyc_osd_general_yaw = ProtoField.int16 ("dji_p3.flyc_osd_general_yaw", "Yaw", base.DEC)
f.flyc_osd_general_mode1 = ProtoField.uint8 ("dji_p3.flyc_osd_general_mode1", "Mode1", base.HEX, FLYC_OSD_GENERAL_MODE1_ENUM, 0x7F, "Flight Controller state1")
f.flyc_osd_general_rc_state = ProtoField.uint8 ("dji_p3.flyc_osd_general_rc_state", "RC State", base.HEX, nil, 0x80, nil)
f.flyc_osd_general_latest_cmd = ProtoField.uint8 ("dji_p3.flyc_osd_general_latest_cmd", "Latest Cmd", base.HEX, FLYC_OSD_GENERAL_COMMAND_ENUM, nil, "controller exccute lastest cmd")
f.flyc_osd_general_controller_state = ProtoField.uint32 ("dji_p3.flyc_osd_general_controller_state", "Controller State", base.HEX, nil, nil, "Flight Controller state flags")
  f.flyc_osd_general_e_can_ioc_work = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_can_ioc_work", "E Can IOC Work", base.HEX, nil, 0x01, nil)
  f.flyc_osd_general_e_on_ground = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_on_ground", "E On Ground", base.HEX, nil, 0x02, nil)
  f.flyc_osd_general_e_in_air = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_in_air", "E In Air", base.HEX, nil, 0x04, nil)
  f.flyc_osd_general_e_motor_on = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_motor_on", "E Motor On", base.HEX, nil, 0x08, "Force allow start motors ignoring errors")
  f.flyc_osd_general_e_usonic_on = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_usonic_on", "E Usonic On", base.HEX, nil, 0x10, nil)
  f.flyc_osd_general_e_gohome_state = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_gohome_state", "E Gohome State", base.HEX, FLYC_OSD_GENERAL_GOHOME_STATE_ENUM, 0xe0, nil)
  f.flyc_osd_general_e_mvo_used = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_mvo_used", "E MVO Used", base.HEX, nil, 0x100, "Monocular Visual Odometry is used as horizonal velocity sensor")
  f.flyc_osd_general_e_battery_req_gohome = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_battery_req_gohome", "E Battery Req Gohome", base.HEX, nil, 0x200, nil)
  f.flyc_osd_general_e_battery_req_land = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_battery_req_land", "E Battery Req Land", base.HEX, nil, 0x400, "Landing required due to battery voltage low")
  f.flyc_osd_general_e_still_heating = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_still_heating", "E Still Heating", base.HEX, nil, 0x1000, nil)
  f.flyc_osd_general_e_rc_state = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_rc_state", "E RC State", base.HEX, nil, 0x6000, nil)
  f.flyc_osd_general_e_gps_used = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_gps_used", "E GPS Used", base.HEX, nil, 0x8000, "Satellite Positioning System is used as horizonal velocity sensor")
  f.flyc_osd_general_e_compass_over_range = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_compass_over_range", "E Compass Over Range", base.HEX, nil, 0x10000, nil)
  f.flyc_osd_general_e_wave_err = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_wave_err", "E Wave Error", base.HEX, nil, 0x20000, nil)
  f.flyc_osd_general_e_gps_level = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_gps_level", "E GPS Level", base.HEX, nil, 0x3C0000, "Satellite Positioning System signal level")
  f.flyc_osd_general_e_battery_type = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_battery_type", "E Battery Type", base.HEX, FLYC_OSD_GENERAL_BATT_TYPE_ENUM, 0xC00000, nil)
  f.flyc_osd_general_e_accel_over_range = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_accel_over_range", "E Acceletor Over Range", base.HEX, nil, 0x1000000, nil)
  f.flyc_osd_general_e_is_vibrating = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_is_vibrating", "E Is Vibrating", base.HEX, nil, 0x2000000, nil)
  f.flyc_osd_general_e_press_err = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_press_err", "E Press Err", base.HEX, nil, 0x4000000, "Barometer error")
  f.flyc_osd_general_e_esc_stall = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_esc_stall", "E ESC is stall", base.HEX, nil, 0x8000000, "ESC reports motor blocked")
  f.flyc_osd_general_e_esc_empty = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_esc_empty", "E ESC is empty", base.HEX, nil, 0x10000000, "ESC reports not enough force")
  f.flyc_osd_general_e_propeller_catapult = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_propeller_catapult", "E Is Propeller Catapult", base.HEX, nil, 0x20000000, nil)
  f.flyc_osd_general_e_gohome_height_mod = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_gohome_height_mod", "E GoHome Height Mod", base.HEX, nil, 0x40000000, "Go Home Height is Modified")
  f.flyc_osd_general_e_out_of_limit = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_out_of_limit", "E Is Out Of Limit", base.HEX, nil, 0x80000000, nil)
f.flyc_osd_general_gps_nums = ProtoField.uint8 ("dji_p3.flyc_osd_general_gps_nums", "Gps Nums", base.DEC, nil, nil, "Number of Global Nav System positioning satellites")
f.flyc_osd_general_gohome_landing_reason = ProtoField.uint8 ("dji_p3.flyc_osd_general_gohome_landing_reason", "Gohome or Landing Reason", base.HEX, FLYC_OSD_GENERAL_GOHOME_REASON_ENUM, nil, "Reason for automatic GoHome or Landing")
f.flyc_osd_general_start_fail_reason = ProtoField.uint8 ("dji_p3.flyc_osd_general_start_fail_reason", "Start Fail Reason", base.HEX, FLYC_OSD_GENERAL_START_FAIL_REASON_ENUM, nil, "Reason for failure to start motors")
f.flyc_osd_general_controller_state_ext = ProtoField.uint8 ("dji_p3.flyc_osd_general_controller_state_ext", "Controller State Ext", base.HEX)
  f.flyc_osd_general_e_gps_state = ProtoField.uint8 ("dji_p3.flyc_osd_general_e_gps_state", "E Gps State", base.HEX, FLYC_OSD_GENERAL_GPS_STATE_ENUM, 0x0f, nil)
  f.flyc_osd_general_e_wp_limit_md = ProtoField.uint8 ("dji_p3.flyc_osd_general_e_wp_limit_md", "E Wp Limit Mode", base.HEX, nil, 0x10, "Waypoint Limit Mode")
f.flyc_osd_general_batt_remain = ProtoField.uint8 ("dji_p3.flyc_osd_general_batt_remain", "Battery Remain", base.DEC, nil, nil, "Battery Remaining Capacity")
f.flyc_osd_general_ultrasonic_height = ProtoField.uint8 ("dji_p3.flyc_osd_general_ultrasonic_height", "Ultrasonic Height", base.DEC)
f.flyc_osd_general_motor_startup_time = ProtoField.uint16 ("dji_p3.flyc_osd_general_motor_startup_time", "Motor Startup Time", base.DEC)
f.flyc_osd_general_motor_startup_times = ProtoField.uint8 ("dji_p3.flyc_osd_general_motor_startup_times", "Motor Startup Times", base.DEC, nil, nil, "aka Motor Revolution")
f.flyc_osd_general_bat_alarm1 = ProtoField.uint8 ("dji_p3.flyc_osd_general_bat_alarm1", "Bat Alarm1", base.HEX)
  f.flyc_osd_general_bat_alarm1_ve = ProtoField.uint8 ("dji_p3.flyc_osd_general_bat_alarm1_ve", "Alarm Level 1 Voltage", base.DEC, nil, 0x7F)
  f.flyc_osd_general_bat_alarm1_fn = ProtoField.uint8 ("dji_p3.flyc_osd_general_bat_alarm1_fn", "Alarm Level 1 Function", base.DEC, nil, 0x80)
f.flyc_osd_general_bat_alarm2 = ProtoField.uint8 ("dji_p3.flyc_osd_general_bat_alarm2", "Bat Alarm2", base.HEX)
  f.flyc_osd_general_bat_alarm2_ve = ProtoField.uint8 ("dji_p3.flyc_osd_general_bat_alarm2_ve", "Alarm Level 2 Voltage", base.DEC, nil, 0x7F)
  f.flyc_osd_general_bat_alarm2_fn = ProtoField.uint8 ("dji_p3.flyc_osd_general_bat_alarm2_fn", "Alarm Level 2 Function", base.DEC, nil, 0x80)
f.flyc_osd_general_version_match = ProtoField.uint8 ("dji_p3.flyc_osd_general_version_match", "Version Match", base.HEX, nil, nil, "Flight Controller version")
f.flyc_osd_general_product_type = ProtoField.uint8 ("dji_p3.flyc_osd_general_product_type", "Product Type", base.HEX, FLYC_OSD_GENERAL_PRODUCT_TYPE_ENUM)
f.flyc_osd_general_imu_init_fail_reson = ProtoField.int8 ("dji_p3.flyc_osd_general_imu_init_fail_reson", "IMU init Fail Reason", base.DEC, FLYC_OSD_GENERAL_IMU_INIT_FAIL_RESON_ENUM)

local function main_flight_ctrl_osd_general_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_osd_general_longtitude, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.flyc_osd_general_latitude, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.flyc_osd_general_relative_height, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_general_vgx, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_general_vgy, payload(offset, 2)) -- offset = 20
    offset = offset + 2

    subtree:add_le (f.flyc_osd_general_vgz, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_general_pitch, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_general_roll, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_general_yaw, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_general_mode1, payload(offset, 1))
    subtree:add_le (f.flyc_osd_general_rc_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_general_latest_cmd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_general_controller_state, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_can_ioc_work, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_on_ground, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_in_air, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_motor_on, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_usonic_on, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_gohome_state, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_mvo_used, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_battery_req_gohome, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_battery_req_land, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_still_heating, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_rc_state, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_gps_used, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_compass_over_range, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_wave_err, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_gps_level, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_battery_type, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_accel_over_range, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_is_vibrating, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_press_err, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_esc_stall, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_esc_empty, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_propeller_catapult, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_gohome_height_mod, payload(offset, 4))
    subtree:add_le (f.flyc_osd_general_e_out_of_limit, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_osd_general_gps_nums, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_general_gohome_landing_reason, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_general_start_fail_reason, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_general_controller_state_ext, payload(offset, 1))
    subtree:add_le (f.flyc_osd_general_e_gps_state, payload(offset, 1))
    subtree:add_le (f.flyc_osd_general_e_wp_limit_md, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_general_batt_remain, payload(offset, 1)) -- offset = 40
    offset = offset + 1

    subtree:add_le (f.flyc_osd_general_ultrasonic_height, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_general_motor_startup_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_general_motor_startup_times, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_general_bat_alarm1, payload(offset, 1))
    subtree:add_le (f.flyc_osd_general_bat_alarm1_ve, payload(offset, 1))
    subtree:add_le (f.flyc_osd_general_bat_alarm1_fn, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_general_bat_alarm2, payload(offset, 1))
    subtree:add_le (f.flyc_osd_general_bat_alarm2_ve, payload(offset, 1))
    subtree:add_le (f.flyc_osd_general_bat_alarm2_fn, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_general_version_match, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_general_product_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_general_imu_init_fail_reson, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 50) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd General: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd General: Payload size different than expected") end
end

-- Flight Controller - OSD Home - 0x44, identical to flight recorder packet 0x000d

f.flyc_osd_home_osd_lon = ProtoField.double ("dji_p3.flyc_osd_home_osd_lon", "OSD Longitude", base.DEC) -- home point coords?
f.flyc_osd_home_osd_lat = ProtoField.double ("dji_p3.flyc_osd_home_osd_lat", "OSD Latitude", base.DEC) -- home point coords?
f.flyc_osd_home_osd_alt = ProtoField.float ("dji_p3.flyc_osd_home_osd_alt", "OSD Altitude", base.DEC, nil, nil, "0.1m, altitude")
f.flyc_osd_home_osd_home_state = ProtoField.uint16 ("dji_p3.flyc_osd_home_osd_home_state", "OSD Home State", base.HEX)
  f.flyc_osd_home_e_homepoint_set = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_homepoint_set", "E Homepoint Set", base.HEX, nil, 0x01, nil)
  f.flyc_osd_home_e_method = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_method", "E Method", base.HEX, nil, 0x02, nil)
  f.flyc_osd_home_e_heading = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_heading", "E Heading", base.HEX, nil, 0x04, nil)
  f.flyc_osd_home_e_is_dyn_homepoint = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_is_dyn_homepoint", "E Is Dyn Homepoint", base.HEX, nil, 0x08, nil)
  f.flyc_osd_home_e_multiple = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_multiple", "E Multiple", base.HEX, nil, 0x40, nil)
  f.flyc_osd_home_e_ioc_enable = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_ioc_enable", "E Ioc Enable", base.HEX, nil, 0x1000, nil)
f.flyc_osd_home_fixed_altitedue = ProtoField.uint16 ("dji_p3.flyc_osd_home_fixed_altitedue", "Fixed Altitedue", base.HEX)
f.flyc_osd_home_course_lock_torsion = ProtoField.int16 ("dji_p3.flyc_osd_home_course_lock_torsion", "Course Lock Torsion", base.DEC)
f.flyc_osd_home_fld1a = ProtoField.int8 ("dji_p3.flyc_osd_home_fld1a", "field1A", base.DEC)
f.flyc_osd_home_fld1b = ProtoField.int8 ("dji_p3.flyc_osd_home_fld1b", "field1B", base.DEC)
f.flyc_osd_home_fld1c = ProtoField.int16 ("dji_p3.flyc_osd_home_fld1c", "field1C", base.DEC)
f.flyc_osd_home_fld1e = ProtoField.int16 ("dji_p3.flyc_osd_home_fld1e", "field1E", base.DEC)
f.flyc_osd_home_fld20 = ProtoField.int8 ("dji_p3.flyc_osd_home_fld20", "field20", base.DEC)
f.flyc_osd_home_fld21 = ProtoField.int8 ("dji_p3.flyc_osd_home_fld21", "field21", base.DEC) -- seem to not be filled

local function main_flight_ctrl_osd_home_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_osd_home_osd_lon, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.flyc_osd_home_osd_lat, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.flyc_osd_home_osd_alt, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_osd_home_osd_home_state, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_e_homepoint_set, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_e_method, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_e_heading, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_e_is_dyn_homepoint, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_e_multiple, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_e_ioc_enable, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_home_fixed_altitedue, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_home_course_lock_torsion, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_home_fld1a, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_home_fld1b, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_home_fld1c, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_home_fld1e, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_home_fld20, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_home_fld21, payload(offset, 1))
    offset = offset + 1

    -- Before firmware P3X_FW_V01.07.0060, the packet was 68 bytes long
    if (payload:len() == offset + 34) then
        offset = offset + 34
    end

    if (offset ~= 34) and (offset ~= 68) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Home: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Home: Payload size different than expected") end
end

-- Flight Controller - Imu Data Status - 0x50, identical to flight recorder packet 0x0013

f.flyc_imu_data_status_start_fan = ProtoField.uint8 ("dji_p3.flyc_imu_data_status_start_fan", "Start Fan", base.HEX, nil, nil, "On Ph3, always 1")
f.flyc_imu_data_status_led_status = ProtoField.uint8 ("dji_p3.flyc_imu_data_status_led_status", "Led Status", base.HEX, nil, nil, "On Ph3, always 0")

local function main_flight_ctrl_imu_data_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_imu_data_status_start_fan, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_imu_data_status_led_status, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Data Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Data Status: Payload size different than expected") end
end

-- Flight Controller - Gps Glns - 0x57, similar to flight recorder packet 0x0005

f.flyc_gps_glns_gps_lon = ProtoField.int32 ("dji_p3.flyc_gps_glns_gps_lon", "Gps Lon", base.DEC)
f.flyc_gps_glns_gps_lat = ProtoField.int32 ("dji_p3.flyc_gps_glns_gps_lat", "Gps Lat", base.DEC)
f.flyc_gps_glns_hmsl = ProtoField.int32 ("dji_p3.flyc_gps_glns_hmsl", "Hmsl", base.DEC)
f.flyc_gps_glns_vel_n = ProtoField.float ("dji_p3.flyc_gps_glns_vel_n", "Vel N", base.DEC)
f.flyc_gps_glns_vel_e = ProtoField.float ("dji_p3.flyc_gps_glns_vel_e", "Vel E", base.DEC)
f.flyc_gps_glns_vel_d = ProtoField.float ("dji_p3.flyc_gps_glns_vel_d", "Vel D", base.DEC)
f.flyc_gps_glns_hdop = ProtoField.float ("dji_p3.flyc_gps_glns_hdop", "Hdop", base.DEC)
f.flyc_gps_glns_numsv = ProtoField.uint16 ("dji_p3.flyc_gps_glns_numsv", "NumSV", base.DEC, nil, nil, "Number of Global Nav System positioning satellites")
f.flyc_gps_glns_gpsglns_cnt = ProtoField.uint16 ("dji_p3.flyc_gps_glns_gpsglns_cnt", "Gps Glns Count", base.DEC, nil, nil, "Sequence counter increased each time the packet of this type is prepared")
f.flyc_gps_glns_unkn20 = ProtoField.uint8 ("dji_p3.flyc_gps_glns_unkn20", "Unknown 20", base.DEC)
f.flyc_gps_glns_homepoint_set = ProtoField.uint8 ("dji_p3.flyc_gps_glns_homepoint_set", "Homepoint Set", base.DEC)

local function main_flight_ctrl_gps_glns_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_gps_glns_gps_lon, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_gps_glns_gps_lat, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_gps_glns_hmsl, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_gps_glns_vel_n, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_gps_glns_vel_e, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_gps_glns_vel_d, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_gps_glns_hdop, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_gps_glns_numsv, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_gps_glns_gpsglns_cnt, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_gps_glns_unkn20, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_gps_glns_homepoint_set, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 22) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gps Glns: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gps Glns: Payload size different than expected") end
end

local FLYC_UART_CMD_DISSECT = {
    [0x43] = main_flight_ctrl_osd_general_dissector,
    [0x44] = main_flight_ctrl_osd_home_dissector,
    [0x50] = main_flight_ctrl_imu_data_status_dissector,
    [0x57] = main_flight_ctrl_gps_glns_dissector,
}

-- Gimbal - Gimbal Type - 0x1C

f.gimbal_gimbal_type_id = ProtoField.uint8 ("dji_p3.gimbal_gimbal_type_id", "Type ID", base.HEX)

local function main_gimbal_gimbal_type_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_gimbal_type_id, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Type: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Type: Payload size different than expected") end
end

-- Gimbal - Gimbal Position - 0x05

f.gimbal_gimbal_position_pitch = ProtoField.int16 ("dji_p3.gimbal_gimbal_position_pitch", "Gimbal Pitch", base.DEC, nil, nil, "0.1, gimbal angular position, zero is forward, max down..up is about -900..470")
f.gimbal_gimbal_position_roll = ProtoField.int16 ("dji_p3.gimbal_gimbal_position_roll", "Gimbal Roll", base.DEC, nil, nil, "0.1, gimbal angular position, zero is parallel to earth, max right..left is about -410..410")
f.gimbal_gimbal_position_yaw = ProtoField.int16 ("dji_p3.gimbal_gimbal_position_yaw", "Gimbal Yaw", base.DEC, nil, nil, "0.1, gimbal angular position, -1000 is forward, max right..left is about -1460..-540") -- TODO verify
f.gimbal_gimbal_position_unkn6 = ProtoField.uint16 ("dji_p3.gimbal_gimbal_position_unkn6", "Unknown 06", base.HEX)
f.gimbal_gimbal_position_unkn8 = ProtoField.uint16 ("dji_p3.gimbal_gimbal_position_unkn8", "Unknown 08", base.HEX)
f.gimbal_gimbal_position_unknA = ProtoField.uint16 ("dji_p3.gimbal_gimbal_position_unknA", "Unknown 0A", base.HEX)

local function main_gimbal_gimbal_position_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_gimbal_position_pitch, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_position_roll, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_position_yaw, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_position_unkn6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_position_unkn8, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_position_unknA, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 12) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Position: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Position: Payload size different than expected") end
end


local GIMBAL_UART_CMD_DISSECT = {
    [0x05] = main_gimbal_gimbal_position_dissector,
    [0x1C] = main_gimbal_gimbal_type_dissector,
}

local CENTER_BRD_UART_CMD_DISSECT = {
}

local RC_UART_CMD_DISSECT = {
}

local WIFI_UART_CMD_DISSECT = {
}

local DM36X_UART_CMD_DISSECT = {
}

-- Set transciever register packet
f.transciever_reg_addr = ProtoField.uint16 ("dji_p3.transciever_reg_set", "Register addr", base.HEX)
f.transciever_reg_val = ProtoField.uint8 ("dji_p3.transciever_reg_val", "Register value", base.HEX)

local function main_hd_link_set_transciever_reg_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --TODO verify
    offset = offset + 2

    subtree:add_le (f.transciever_reg_addr, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.transciever_reg_val, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Set Transciever Reg: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Set Transciever Reg: Payload size different than expected") end
end

local HD_LINK_UART_CMD_DISSECT = {
    [0x06] = main_hd_link_set_transciever_reg_dissector,
}

local MBINO_UART_CMD_DISSECT = {
}

local SIM_UART_CMD_DISSECT = {
}

local ESC_UART_CMD_DISSECT = {
}

local BATTERY_UART_CMD_DISSECT = {
}

local DATA_LOG_UART_CMD_DISSECT = {
}

local RTK_UART_CMD_DISSECT = {
}

local AUTO_UART_CMD_DISSECT = {
}


DJI_P3_FLIGHT_CONTROL_UART_CMD_DISSECT = {
    [0x00] = GENERAL_UART_CMD_DISSECT,
    [0x01] = SPECIAL_UART_CMD_DISSECT,
    [0x02] = CAMERA_UART_CMD_DISSECT,
    [0x03] = FLYC_UART_CMD_DISSECT,
    [0x04] = GIMBAL_UART_CMD_DISSECT,
    [0x05] = CENTER_BRD_UART_CMD_DISSECT,
    [0x06] = RC_UART_CMD_DISSECT,
    [0x07] = WIFI_UART_CMD_DISSECT,
    [0x08] = DM36X_UART_CMD_DISSECT,
    [0x09] = HD_LINK_UART_CMD_DISSECT,
    [0x0a] = MBINO_UART_CMD_DISSECT,
    [0x0b] = SIM_UART_CMD_DISSECT,
    [0x0c] = ESC_UART_CMD_DISSECT,
    [0x0d] = BATTERY_UART_CMD_DISSECT,
    [0x0e] = DATA_LOG_UART_CMD_DISSECT,
    [0x0f] = RTK_UART_CMD_DISSECT,
    [0x10] = AUTO_UART_CMD_DISSECT,
}
