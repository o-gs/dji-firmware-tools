local f = DJI_P3_PROTO.fields
local enums = {}

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
    [0x01] = 'Osd General',
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

-- General - Message - 0x0e

--f.general_message_unknown0 = ProtoField.none ("dji_p3.general_message_unknown0", "Unknown0", base.NONE)

local function general_message_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Message: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Message: Payload size different than expected") end
end

-- General - Upgrade Self Request - 0x0f

f.general_upgrade_self_request_unknown0 = ProtoField.uint8 ("dji_p3.general_upgrade_self_request_unknown0", "Unknown0", base.HEX)
f.general_upgrade_self_request_unknown1 = ProtoField.uint8 ("dji_p3.general_upgrade_self_request_unknown1", "Unknown1", base.HEX)

local function general_upgrade_self_request_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.general_upgrade_self_request_unknown0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.general_upgrade_self_request_unknown1, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Upgrade Self Request: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Upgrade Self Request: Payload size different than expected") end
end

-- General - Camera Files - 0x24

f.general_camera_files_index = ProtoField.int32 ("dji_p3.general_camera_files_index", "Index", base.DEC)
f.general_camera_files_data = ProtoField.bytes ("dji_p3.general_camera_files_data", "Data", base.SPACE)

local function general_camera_files_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.general_camera_files_index, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.general_camera_files_data, payload(offset, 495))
    offset = offset + 495


    if (offset ~= 499) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Files: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Files: Payload size different than expected") end
end

-- General - Camera File - 0x27

--f.general_camera_file_unknown0 = ProtoField.none ("dji_p3.general_camera_file_unknown0", "Unknown0", base.NONE)

local function general_camera_file_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera File: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera File: Payload size different than expected") end
end

-- General - Common Upgrade Status - 0x42

enums.COMMON_UPGRADE_STATUS_UPGRADE_STATE_ENUM = {
    [1]="Verify",
    [2]="UserConfirm",
    [3]="Upgrading",
    [4]="Complete",
}

enums.COMMON_UPGRADE_STATUS_UPGRADE_COMPLETE_REASON_ENUM = {
    [1]="Success",
    [2]="Failure",
    [3]="FirmwareError",
    [4]="SameVersion",
    [5]="UserCancel",
    [6]="TimeOut",
    [7]="MotorWorking",
    [8]="FirmNotMatch",
    [9]="IllegalDegrade",
    [10]="NoConnectRC",
}

f.general_common_upgrade_status_upgrade_state = ProtoField.uint8 ("dji_p3.general_common_upgrade_status_upgrade_state", "Upgrade State", base.DEC, enums.COMMON_UPGRADE_STATUS_UPGRADE_STATE_ENUM, nil, nil)
f.general_common_upgrade_status_user_time = ProtoField.uint8 ("dji_p3.general_common_upgrade_status_user_time", "User Time", base.DEC, nil, nil, "For upgrade_state==2")
f.general_common_upgrade_status_user_reserve = ProtoField.uint8 ("dji_p3.general_common_upgrade_status_user_reserve", "User Reserve", base.HEX, nil, nil, "For upgrade_state==2")
f.general_common_upgrade_status_upgrade_process = ProtoField.uint8 ("dji_p3.general_common_upgrade_status_upgrade_process", "Upgrade Process", base.DEC, nil, nil, "For upgrade_state==3")
f.general_common_upgrade_status_cur_upgrade_index = ProtoField.uint8 ("dji_p3.general_common_upgrade_status_cur_upgrade_index", "Cur Upgrade Index", base.DEC, nil, 0xe0, "For upgrade_state==3")
f.general_common_upgrade_status_upgrade_times_3 = ProtoField.uint8 ("dji_p3.general_common_upgrade_status_upgrade_times", "Upgrade Times", base.DEC, nil, 0x1f, "For upgrade_state==3")
f.general_common_upgrade_status_upgrade_result = ProtoField.uint8 ("dji_p3.general_common_upgrade_status_upgrade_result", "Upgrade Result", base.HEX, enums.COMMON_UPGRADE_STATUS_UPGRADE_COMPLETE_REASON_ENUM, nil, "For upgrade_state==4")
f.general_common_upgrade_status_upgrade_times_4 = ProtoField.uint8 ("dji_p3.general_common_upgrade_status_upgrade_times", "Upgrade Times", base.HEX, nil, nil, "For upgrade_state==4")

local function general_common_upgrade_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    local upgrade_state = buffer(offset,1):le_uint()
    subtree:add_le (f.general_common_upgrade_status_upgrade_state, payload(offset, 1))
    offset = offset + 1

    if upgrade_state == 2 then

        subtree:add_le (f.general_common_upgrade_status_user_time, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.general_common_upgrade_status_user_reserve, payload(offset, 1))
        offset = offset + 1

        if (offset ~= 3) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Common Upgrade Status: Offset does not match - internal inconsistency") end

    elseif upgrade_state == 3 then

        subtree:add_le (f.general_common_upgrade_status_upgrade_process, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.general_common_upgrade_status_cur_upgrade_index, payload(offset, 1))
        subtree:add_le (f.general_common_upgrade_status_upgrade_times_3, payload(offset, 1))
        offset = offset + 1

        if (offset ~= 3) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Common Upgrade Status: Offset does not match - internal inconsistency") end

    elseif upgrade_state == 4 then

        subtree:add_le (f.general_common_upgrade_status_upgrade_result, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.general_common_upgrade_status_upgrade_times_4, payload(offset, 1))
        offset = offset + 1

        if (offset ~= 3) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Common Upgrade Status: Offset does not match - internal inconsistency") end

    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Common Upgrade Status: Payload size different than expected") end
end

-- General - Notify Disconnect - 0x47

f.general_notify_disconnect_a = ProtoField.uint8 ("dji_p3.general_notify_disconnect_a", "A", base.DEC, nil, nil, "TODO values from enum P3.DataNotifyDisconnect")
f.general_notify_disconnect_b = ProtoField.uint16 ("dji_p3.general_notify_disconnect_b", "B", base.DEC)

local function general_notify_disconnect_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.general_notify_disconnect_a, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.general_notify_disconnect_b, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 3) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Notify Disconnect: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Notify Disconnect: Payload size different than expected") end
end

-- General - Common App Gps Config - 0x52

f.general_common_app_gps_config_is_start = ProtoField.uint8 ("dji_p3.general_common_app_gps_config_is_start", "Is Start", base.DEC)
f.general_common_app_gps_config_get_push_interval = ProtoField.uint32 ("dji_p3.general_common_app_gps_config_get_push_interval", "Get Push Interval", base.DEC)

local function general_common_app_gps_config_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.general_common_app_gps_config_is_start, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.general_common_app_gps_config_get_push_interval, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Common App Gps Config: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Common App Gps Config: Payload size different than expected") end
end

-- General - Component state packet - 0xf1

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

local function general_compn_state_dissector(pkt_length, buffer, pinfo, subtree)
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
    [0x0e] = general_message_dissector,
    [0x0f] = general_upgrade_self_request_dissector,
    [0x24] = general_camera_files_dissector,
    [0x27] = general_camera_file_dissector,
    [0x42] = general_common_upgrade_status_dissector,
    [0x47] = general_notify_disconnect_dissector,
    [0x52] = general_common_app_gps_config_dissector,
    [0xf1] = general_compn_state_dissector,
}

-- Special - Old Special Control - 0x01

f.special_old_special_control_unknown0 = ProtoField.uint8 ("dji_p3.special_old_special_control_unknown0", "Unknown0", base.HEX)
f.special_old_special_control_unknown1 = ProtoField.uint8 ("dji_p3.special_old_special_control_unknown1", "Unknown1", base.HEX)
f.special_old_special_control_unknown2 = ProtoField.uint8 ("dji_p3.special_old_special_control_unknown2", "Unknown2", base.HEX)
f.special_old_special_control_unknown4 = ProtoField.uint8 ("dji_p3.special_old_special_control_unknown4", "Unknown4", base.HEX)
f.special_old_special_control_unknown5 = ProtoField.uint8 ("dji_p3.special_old_special_control_unknown5", "Unknown5", base.HEX)
f.special_old_special_control_unknown6 = ProtoField.uint8 ("dji_p3.special_old_special_control_unknown6", "Unknown6", base.HEX)
f.special_old_special_control_unknown7 = ProtoField.uint8 ("dji_p3.special_old_special_control_unknown7", "Unknown7", base.HEX)
f.special_old_special_control_checksum = ProtoField.uint8 ("dji_p3.special_old_special_control_checksum", "Checksum", base.HEX, nil, nil, "Previous payload bytes xor'ed together with initial seed 0.")

local function special_old_special_control_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.special_old_special_control_unknown0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.special_old_special_control_unknown1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.special_old_special_control_unknown2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.special_old_special_control_unknown4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.special_old_special_control_unknown5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.special_old_special_control_unknown6, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.special_old_special_control_unknown7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.special_old_special_control_checksum, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 10) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Old Special Control: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Old Special Control: Payload size different than expected") end
end

-- Special - New Special Control - 0x03

f.special_new_special_control_unknown0 = ProtoField.bytes ("dji_p3.special_new_special_control_unknown0", "Unknown0", base.SPACE)

local function special_new_special_control_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.special_new_special_control_unknown0, payload(offset, 24))
    offset = offset + 24

    if (offset ~= 24) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"New Special Control: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"New Special Control: Payload size different than expected") end
end

local SPECIAL_UART_CMD_DISSECT = {
    [0x01] = special_old_special_control_dissector,
    [0x03] = special_new_special_control_dissector,
}

-- Camera - Camera Shutter Cmd - 0x7c

f.camera_camera_shutter_cmd_shutter_type = ProtoField.uint8 ("dji_p3.camera_camera_shutter_cmd_shutter_type", "Shutter Type", base.DEC)

local function camera_camera_shutter_cmd_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_shutter_cmd_shutter_type, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Shutter Cmd: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Shutter Cmd: Payload size different than expected") end
end

-- Camera - Camera State Info - 0x80

enums.CAMERA_STATE_INFO_FIRM_UPGRADE_ERROR_STATE_FIRM_ERROR_TYPE_ENUM = {
    [0x00] = 'NO',
    [0x01] = 'Nomatch',
    [0x02] = 'UpgradeError',
    [0x06] = 'OTHER',
}

enums.CAMERA_STATE_INFO_PHOTO_STATE_ENUM = {
    [0x00] = 'NO',
    [0x01] = 'Single',
    [0x02] = 'Multiple',
    [0x03] = 'Hdr',
    [0x04] = 'FullView',
    [0x06] = 'OTHER',
}

enums.CAMERA_STATE_INFO_SD_CARD_STATE_ENUM = {
    [0x00] = 'Normal',
    [0x01] = 'None',
    [0x02] = 'Invalid',
    [0x03] = 'WriteProtection',
    [0x04] = 'Unformat',
    [0x05] = 'Formating',
    [0x06] = 'Illegal',
    [0x07] = 'Busy',
    [0x08] = 'Full',
    [0x09] = 'Slow',
    [0x0a] = 'Unknow',
    [0x0b] = 'IndexMax',
    [0x0c] = 'Initialzing',
    [0x0d] = 'ToFormat',
    [0x0e] = 'TryToRecoverFile',
    [0x0f] = 'BecomeSlow',
    [0x63] = 'USBConnected',
    [0x64] = 'OTHER',
}

enums.CAMERA_STATE_INFO_MODE_ENUM = {
    [0x00] = 'TAKEPHOTO',
    [0x01] = 'RECORD',
    [0x02] = 'PLAYBACK',
    [0x03] = 'TRANSCODE',
    [0x04] = 'TUNING',
    [0x05] = 'SAVEPOWER',
    [0x06] = 'DOWNLOAD',
    [0x07] = 'NEW_PLAYBACK',
    [0x64] = 'OTHER',
}

enums.CAMERA_STATE_INFO_FILE_INDEX_MODE_ENUM = {
    [0x00] = 'Reset',
    [0x01] = 'Sequence',
}

enums.CAMERA_STATE_INFO_CAMERA_TYPE_ENUM = {
    [0x00] = 'DJICameraTypeFC350',
    [0x01] = 'DJICameraTypeFC550',
    [0x02] = 'DJICameraTypeFC260',
    [0x03] = 'DJICameraTypeFC300S',
    [0x04] = 'DJICameraTypeFC300X',
    [0x05] = 'DJICameraTypeFC550Raw',
    [0x06] = 'DJICameraTypeFC330X',
    [0x07] = 'DJICameraTypeTau640',
    [0x08] = 'DJICameraTypeTau336',
    [0x09] = 'DJICameraTypeFC220',
    [0x0a] = 'DJICameraTypeFC300XW',
    [0x0b] = 'DJICameraTypeCV600',
    [0x0d] = 'DJICameraTypeFC6310',
    [0x0e] = 'DJICameraTypeFC6510',
    [0x0f] = 'DJICameraTypeFC6520',
    [0x12] = 'DJICameraTypeFC220S',
    [0x14] = 'DJICameraTypeGD600',
    [0xff] = 'OTHER',
}

f.camera_camera_state_info_masked00 = ProtoField.uint32 ("dji_p3.camera_camera_state_info_masked00", "Masked00", base.HEX)
  f.camera_camera_state_info_connect_state = ProtoField.uint32 ("dji_p3.camera_camera_state_info_connect_state", "Connect State", base.HEX, nil, 0x0001, nil)
  f.camera_camera_state_info_usb_state = ProtoField.uint32 ("dji_p3.camera_camera_state_info_usb_state", "Usb State", base.HEX, nil, 0x0002, nil)
  f.camera_camera_state_info_time_sync_state = ProtoField.uint32 ("dji_p3.camera_camera_state_info_time_sync_state", "Time Sync State", base.HEX, nil, 0x0004, nil)
  f.camera_camera_state_info_photo_state = ProtoField.uint32 ("dji_p3.camera_camera_state_info_photo_state", "Photo State", base.HEX, enums.CAMERA_STATE_INFO_PHOTO_STATE_ENUM, 0x0038, nil)
  f.camera_camera_state_info_record_state = ProtoField.uint32 ("dji_p3.camera_camera_state_info_record_state", "Record State", base.HEX, nil, 0x00c0, "TODO values from enum P3.DataCameraGetPushStateInfo")
  f.camera_camera_state_info_sensor_state = ProtoField.uint32 ("dji_p3.camera_camera_state_info_sensor_state", "Sensor State", base.HEX, nil, 0x0100, nil)
  f.camera_camera_state_info_sd_card_insert_state = ProtoField.uint32 ("dji_p3.camera_camera_state_info_sd_card_insert_state", "Sd Card Insert State", base.HEX, nil, 0x0200, nil)
  f.camera_camera_state_info_sd_card_state = ProtoField.uint32 ("dji_p3.camera_camera_state_info_sd_card_state", "Sd Card State", base.HEX, enums.CAMERA_STATE_INFO_SD_CARD_STATE_ENUM, 0x3c00, nil)
  f.camera_camera_state_info_firm_upgrade_state = ProtoField.uint32 ("dji_p3.camera_camera_state_info_firm_upgrade_state", "Firm Upgrade State", base.HEX, nil, 0x4000, nil)
  f.camera_camera_state_info_firm_upgrade_error_state = ProtoField.uint32 ("dji_p3.camera_camera_state_info_firm_upgrade_error_state", "Firm Upgrade Error State", base.HEX, enums.CAMERA_STATE_INFO_FIRM_UPGRADE_ERROR_STATE_FIRM_ERROR_TYPE_ENUM, 0x18000, nil)
  f.camera_camera_state_info_hot_state = ProtoField.uint32 ("dji_p3.camera_camera_state_info_hot_state", "Hot State", base.HEX, nil, 0x020000, nil)
  f.camera_camera_state_info_not_enabled_photo = ProtoField.uint32 ("dji_p3.camera_camera_state_info_not_enabled_photo", "Not Enabled Photo", base.HEX, nil, 0x040000, nil)
  f.camera_camera_state_info_is_storing = ProtoField.uint32 ("dji_p3.camera_camera_state_info_is_storing", "Is Storing", base.HEX, nil, 0x080000, nil)
  f.camera_camera_state_info_is_time_photoing = ProtoField.uint32 ("dji_p3.camera_camera_state_info_is_time_photoing", "Is Time Photoing", base.HEX, nil, 0x100000, nil)
  f.camera_camera_state_info_encrypt_status = ProtoField.uint32 ("dji_p3.camera_camera_state_info_encrypt_status", "Encrypt Status", base.HEX, nil, 0xc00000, "TODO values from enum P3.DataCameraGetPushStateInfo")
  f.camera_camera_state_info_is_gimbal_busy = ProtoField.uint32 ("dji_p3.camera_camera_state_info_is_gimbal_busy", "Is Gimbal Busy", base.HEX, nil, 0x08000000, nil)
  f.camera_camera_state_info_in_tracking_mode = ProtoField.uint32 ("dji_p3.camera_camera_state_info_in_tracking_mode", "In Tracking Mode", base.HEX, nil, 0x10000000, nil)
f.camera_camera_state_info_mode = ProtoField.uint8 ("dji_p3.camera_camera_state_info_mode", "Camera Mode", base.HEX, enums.CAMERA_STATE_INFO_MODE_ENUM, nil, nil)
f.camera_camera_state_info_sd_card_total_size = ProtoField.uint32 ("dji_p3.camera_camera_state_info_sd_card_total_size", "Sd Card Total Size", base.DEC)
f.camera_camera_state_info_sd_card_free_size = ProtoField.uint32 ("dji_p3.camera_camera_state_info_sd_card_free_size", "Sd Card Free Size", base.DEC)
f.camera_camera_state_info_remained_shots = ProtoField.uint32 ("dji_p3.camera_camera_state_info_remained_shots", "Remained Shots", base.DEC)
f.camera_camera_state_info_remained_time = ProtoField.uint32 ("dji_p3.camera_camera_state_info_remained_time", "Remained Time", base.DEC)
f.camera_camera_state_info_file_index_mode = ProtoField.uint8 ("dji_p3.camera_camera_state_info_file_index_mode", "File Index Mode", base.DEC, enums.CAMERA_STATE_INFO_FILE_INDEX_MODE_ENUM, nil, nil)
f.camera_camera_state_info_fast_play_back_info = ProtoField.uint8 ("dji_p3.camera_camera_state_info_fast_play_back_info", "Fast Play Back Info", base.HEX)
  f.camera_camera_state_info_fast_play_back_enabled = ProtoField.uint8 ("dji_p3.camera_camera_state_info_fast_play_back_enabled", "Fast Play Back Enabled", base.HEX, nil, 0x80, nil)
  f.camera_camera_state_info_fast_play_back_time = ProtoField.uint8 ("dji_p3.camera_camera_state_info_fast_play_back_time", "Fast Play Back Time", base.DEC, nil, 0x7f, nil)
f.camera_camera_state_info_photo_osd_info = ProtoField.uint16 ("dji_p3.camera_camera_state_info_photo_osd_info", "Photo Osd Info", base.HEX)
  f.camera_camera_state_info_photo_osd_time_is_show = ProtoField.uint16 ("dji_p3.camera_camera_state_info_photo_osd_time_is_show", "Photo Osd Time Is Show", base.HEX, nil, 0x01, nil)
  f.camera_camera_state_info_photo_osd_aperture_is_show = ProtoField.uint16 ("dji_p3.camera_camera_state_info_photo_osd_aperture_is_show", "Photo Osd Aperture Is Show", base.HEX, nil, 0x02, nil)
  f.camera_camera_state_info_photo_osd_shutter_is_show = ProtoField.uint16 ("dji_p3.camera_camera_state_info_photo_osd_shutter_is_show", "Photo Osd Shutter Is Show", base.HEX, nil, 0x04, nil)
  f.camera_camera_state_info_photo_osd_iso_is_show = ProtoField.uint16 ("dji_p3.camera_camera_state_info_photo_osd_iso_is_show", "Photo Osd Iso Is Show", base.HEX, nil, 0x08, nil)
  f.camera_camera_state_info_photo_osd_exposure_is_show = ProtoField.uint16 ("dji_p3.camera_camera_state_info_photo_osd_exposure_is_show", "Photo Osd Exposure Is Show", base.HEX, nil, 0x10, nil)
  f.camera_camera_state_info_photo_osd_sharpe_is_show = ProtoField.uint16 ("dji_p3.camera_camera_state_info_photo_osd_sharpe_is_show", "Photo Osd Sharpe Is Show", base.HEX, nil, 0x20, nil)
  f.camera_camera_state_info_photo_osd_contrast_is_show = ProtoField.uint16 ("dji_p3.camera_camera_state_info_photo_osd_contrast_is_show", "Photo Osd Contrast Is Show", base.HEX, nil, 0x40, nil)
  f.camera_camera_state_info_photo_osd_saturation_is_show = ProtoField.uint16 ("dji_p3.camera_camera_state_info_photo_osd_saturation_is_show", "Photo Osd Saturation Is Show", base.HEX, nil, 0x80, nil)
f.camera_camera_state_info_unknown19 = ProtoField.bytes ("dji_p3.camera_camera_state_info_unknown19", "Unknown19", base.SPACE)
f.camera_camera_state_info_in_debug_mode = ProtoField.uint8 ("dji_p3.camera_camera_state_info_in_debug_mode", "In Debug Mode", base.HEX)
f.camera_camera_state_info_unknown1c = ProtoField.uint8 ("dji_p3.camera_camera_state_info_unknown1c", "Unknown1C", base.HEX)
f.camera_camera_state_info_video_record_time = ProtoField.uint16 ("dji_p3.camera_camera_state_info_video_record_time", "Video Record Time", base.DEC)
f.camera_camera_state_info_max_photo_num = ProtoField.uint8 ("dji_p3.camera_camera_state_info_max_photo_num", "Max Photo Num", base.DEC)
f.camera_camera_state_info_masked20 = ProtoField.uint8 ("dji_p3.camera_camera_state_info_masked20", "Masked20", base.HEX)
  f.camera_camera_state_info_histogram_enable = ProtoField.uint8 ("dji_p3.camera_camera_state_info_histogram_enable", "Histogram Enable", base.HEX, nil, 0x01, nil)
f.camera_camera_state_info_camera_type = ProtoField.uint8 ("dji_p3.camera_camera_state_info_camera_type", "Camera Type", base.HEX, enums.CAMERA_STATE_INFO_CAMERA_TYPE_ENUM, nil, nil)
f.camera_camera_state_info_unknown22 = ProtoField.bytes ("dji_p3.camera_camera_state_info_unknown22", "Unknown22", base.SPACE)
f.camera_camera_state_info_version = ProtoField.uint8 ("dji_p3.camera_camera_state_info_version", "Version", base.DEC)

local function camera_camera_state_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_state_info_masked00, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_connect_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_usb_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_time_sync_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_photo_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_record_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_sensor_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_sd_card_insert_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_sd_card_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_firm_upgrade_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_firm_upgrade_error_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_hot_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_not_enabled_photo, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_is_storing, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_is_time_photoing, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_encrypt_status, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_is_gimbal_busy, payload(offset, 4))

    subtree:add_le (f.camera_camera_state_info_in_tracking_mode, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_state_info_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_state_info_sd_card_total_size, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_state_info_sd_card_free_size, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_state_info_remained_shots, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_state_info_remained_time, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_state_info_file_index_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_state_info_fast_play_back_info, payload(offset, 1))
    subtree:add_le (f.camera_camera_state_info_fast_play_back_enabled, payload(offset, 1))
    subtree:add_le (f.camera_camera_state_info_fast_play_back_time, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_state_info_photo_osd_info, payload(offset, 2))
    subtree:add_le (f.camera_camera_state_info_photo_osd_aperture_is_show, payload(offset, 2))
    subtree:add_le (f.camera_camera_state_info_photo_osd_shutter_is_show, payload(offset, 2))
    subtree:add_le (f.camera_camera_state_info_photo_osd_iso_is_show, payload(offset, 2))
    subtree:add_le (f.camera_camera_state_info_photo_osd_exposure_is_show, payload(offset, 2))
    subtree:add_le (f.camera_camera_state_info_photo_osd_sharpe_is_show, payload(offset, 2))
    subtree:add_le (f.camera_camera_state_info_photo_osd_contrast_is_show, payload(offset, 2))
    subtree:add_le (f.camera_camera_state_info_photo_osd_saturation_is_show, payload(offset, 2))
    subtree:add_le (f.camera_camera_state_info_photo_osd_time_is_show, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_state_info_unknown19, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_state_info_in_debug_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_state_info_unknown1c, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_state_info_video_record_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_state_info_max_photo_num, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_state_info_masked20, payload(offset, 1))
    subtree:add_le (f.camera_camera_state_info_histogram_enable, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_state_info_camera_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_state_info_unknown22, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_state_info_version, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 37) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera State Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera State Info: Payload size different than expected") end
end

-- Camera - Camera Shot Params - 0x81

enums.CAMERA_SHOT_PARAMS_ISO_TYPE_ENUM = {
    [0x00] = 'AUTO',
    [0x01] = 'AUTOHIGH',
    [0x02] = 'ISO50',
    [0x03] = 'ISO100',
    [0x04] = 'ISO200',
    [0x05] = 'ISO400',
    [0x06] = 'ISO800',
    [0x07] = 'ISO1600',
    [0x08] = 'ISO3200',
    [0x09] = 'ISO6400',
    [0x0a] = 'ISO12800',
    [0x0b] = 'ISO25600',
}

enums.CAMERA_SHOT_PARAMS_IMAGE_SIZE_SIZE_TYPE_ENUM = {
    [0x00] = 'DEFAULT',
    [0x01] = 'SMALLEST',
    [0x02] = 'SMALL',
    [0x03] = 'MIDDLE',
    [0x04] = 'LARGE',
    [0x05] = 'LARGEST',
    [0x06] = 'OTHER',
}

enums.CAMERA_SHOT_PARAMS_IMAGE_RATIO_TYPE_ENUM = {
    [0x00] = 'R 4:3',
    [0x01] = 'R 16:9',
    [0x02] = 'R 3:2',
    [0x06] = 'R OTHER',
}

enums.CAMERA_SHOT_PARAMS_EXPOSURE_MODE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'Program',
    [0x02] = 'ShutterPriority',
    [0x03] = 'AperturePriority',
    [0x04] = 'Manual',
    [0x05] = 'f',
    [0x06] = 'g',
    [0x07] = 'Cine',
    [0x64] = 'i',
}

enums.CAMERA_SHOT_PARAMS_PHOTO_TYPE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x02] = 'c',
    [0x03] = 'd',
    [0x04] = 'e',
    [0x05] = 'f',
    [0x06] = 'g',
    [0x07] = 'h',
    [0x0a] = 'i',
}

enums.CAMERA_SHOT_PARAMS_VIDEO_ENCODE_TYPE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x64] = 'c',
}

f.camera_camera_shot_params_aperture_size = ProtoField.uint16 ("dji_p3.camera_camera_shot_params_aperture_size", "Aperture Size", base.HEX)
f.camera_camera_shot_params_user_shutter = ProtoField.uint16 ("dji_p3.camera_camera_shot_params_user_shutter", "User Shutter", base.HEX)
  f.camera_camera_shot_params_reciprocal = ProtoField.uint16 ("dji_p3.camera_camera_shot_params_reciprocal", "Reciprocal", base.HEX, nil, 0x8000, nil)
f.camera_camera_shot_params_shutter_speed_decimal = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_shutter_speed_decimal", "Shutter Speed Decimal", base.DEC)
f.camera_camera_shot_params_iso = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_iso", "Iso", base.HEX, enums.CAMERA_SHOT_PARAMS_ISO_TYPE_ENUM, nil, nil)
f.camera_camera_shot_params_exposure_compensation = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_exposure_compensation", "Exposure Compensation", base.HEX)
f.camera_camera_shot_params_ctr_object_for_one = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_ctr_object_for_one", "Ctr Object For One", base.HEX)
f.camera_camera_shot_params_ctr_object_for_two = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_ctr_object_for_two", "Ctr Object For Two", base.HEX)
f.camera_camera_shot_params_image_size = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_image_size", "Image Size", base.HEX, enums.CAMERA_SHOT_PARAMS_IMAGE_SIZE_SIZE_TYPE_ENUM, nil, nil)
f.camera_camera_shot_params_image_ratio = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_image_ratio", "Image Ratio", base.HEX, enums.CAMERA_SHOT_PARAMS_IMAGE_RATIO_TYPE_ENUM, nil, nil)
f.camera_camera_shot_params_image_quality = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_image_quality", "Image Quality", base.HEX)
f.camera_camera_shot_params_image_format = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_image_format", "Image Format", base.HEX)
f.camera_camera_shot_params_video_format = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_video_format", "Video Format", base.HEX)
f.camera_camera_shot_params_video_fps = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_video_fps", "Video Fps", base.HEX)
f.camera_camera_shot_params_video_fov = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_video_fov", "Video Fov", base.HEX)
f.camera_camera_shot_params_video_second_open = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_video_second_open", "Video Second Open", base.HEX)
f.camera_camera_shot_params_video_second_ratio = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_video_second_ratio", "Video Second Ratio", base.HEX)
f.camera_camera_shot_params_video_quality = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_video_quality", "Video Quality", base.HEX)
f.camera_camera_shot_params_video_store_format = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_video_store_format", "Video Store Format", base.HEX)
f.camera_camera_shot_params_exposure_mode = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_exposure_mode", "Exposure Mode", base.HEX, enums.CAMERA_SHOT_PARAMS_EXPOSURE_MODE_ENUM, nil, nil)
f.camera_camera_shot_params_scene_mode = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_scene_mode", "Scene Mode", base.HEX)
f.camera_camera_shot_params_metering = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_metering", "Metering", base.HEX)
f.camera_camera_shot_params_white_balance = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_white_balance", "White Balance", base.HEX)
f.camera_camera_shot_params_color_temp = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_color_temp", "Color Temp", base.HEX)
f.camera_camera_shot_params_mctf_enable = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_mctf_enable", "Mctf Enable", base.HEX)
f.camera_camera_shot_params_mctf_strength = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_mctf_strength", "Mctf Strength", base.HEX)
f.camera_camera_shot_params_sharpe = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_sharpe", "Sharpe", base.HEX)
f.camera_camera_shot_params_contrast = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_contrast", "Contrast", base.HEX)
f.camera_camera_shot_params_saturation = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_saturation", "Saturation", base.HEX)
f.camera_camera_shot_params_tonal = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_tonal", "Tonal", base.HEX)
f.camera_camera_shot_params_digital_filter = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_digital_filter", "Digital Filter", base.HEX)
f.camera_camera_shot_params_anti_flicker = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_anti_flicker", "Anti Flicker", base.HEX)
f.camera_camera_shot_params_continuous = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_continuous", "Continuous", base.HEX)
f.camera_camera_shot_params_time_params_type = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_time_params_type", "Time Params Type", base.HEX)
f.camera_camera_shot_params_time_params_num = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_time_params_num", "Time Params Num", base.HEX)
f.camera_camera_shot_params_time_params_period = ProtoField.uint16 ("dji_p3.camera_camera_shot_params_time_params_period", "Time Params Period", base.HEX)
f.camera_camera_shot_params_real_aperture_size = ProtoField.uint16 ("dji_p3.camera_camera_shot_params_real_aperture_size", "Real Aperture Size", base.HEX)
f.camera_camera_shot_params_real_shutter = ProtoField.uint16 ("dji_p3.camera_camera_shot_params_real_shutter", "Real Shutter", base.HEX)
  f.camera_camera_shot_params_rel_reciprocal = ProtoField.uint16 ("dji_p3.camera_camera_shot_params_rel_reciprocal", "Rel Reciprocal", base.HEX, nil, 0x8000, nil)
f.camera_camera_shot_params_rel_shutter_speed_decimal = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_rel_shutter_speed_decimal", "Real Shutter Speed Decimal", base.DEC)
f.camera_camera_shot_params_rel_iso = ProtoField.uint32 ("dji_p3.camera_camera_shot_params_rel_iso", "Real Iso", base.HEX)
f.camera_camera_shot_params_rel_exposure_compensation = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_rel_exposure_compensation", "Real Exposure Compensation", base.HEX)
f.camera_camera_shot_params_time_countdown = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_time_countdown", "Time Countdown", base.HEX)
f.camera_camera_shot_params_cap_min_shutter = ProtoField.uint16 ("dji_p3.camera_camera_shot_params_cap_min_shutter", "Cap Min Shutter", base.HEX)
  f.camera_camera_shot_params_cap_min_shutter_reciprocal = ProtoField.uint16 ("dji_p3.camera_camera_shot_params_cap_min_shutter_reciprocal", "Cap Min Shutter Reciprocal", base.HEX, nil, 0x8000, nil)
f.camera_camera_shot_params_cap_min_shutter_decimal = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_cap_min_shutter_decimal", "Cap Min Shutter Decimal", base.DEC)
f.camera_camera_shot_params_cap_max_shutter = ProtoField.uint16 ("dji_p3.camera_camera_shot_params_cap_max_shutter", "Cap Max Shutter", base.HEX)
  f.camera_camera_shot_params_cap_max_shutter_reciprocal = ProtoField.uint16 ("dji_p3.camera_camera_shot_params_cap_max_shutter_reciprocal", "Cap Max Shutter Reciprocal", base.HEX, nil, 0x8000, nil)
f.camera_camera_shot_params_cap_max_shutter_decimal = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_cap_max_shutter_decimal", "Cap Max Shutter Decimal", base.DEC)
f.camera_camera_shot_params_video_standard = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_video_standard", "Video Standard", base.HEX)
f.camera_camera_shot_params_ae_lock = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_ae_lock", "Ae Lock", base.HEX)
f.camera_camera_shot_params_photo_type = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_photo_type", "Photo Type", base.HEX, enums.CAMERA_SHOT_PARAMS_PHOTO_TYPE_ENUM, nil, nil)
f.camera_camera_shot_params_spot_area_bottom_right_pos = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_spot_area_bottom_right_pos", "Spot Area Bottom Right Pos", base.HEX)
f.camera_camera_shot_params_unknown3b = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_unknown3b", "Unknown3B", base.HEX)
f.camera_camera_shot_params_aeb_number = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_aeb_number", "Aeb Number", base.HEX)
f.camera_camera_shot_params_pano_mode = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_pano_mode", "Pano Mode", base.HEX, nil, nil, "TODO values from enum P3.DataCameraGetPushShotParams")
f.camera_camera_shot_params_cap_min_aperture = ProtoField.uint16 ("dji_p3.camera_camera_shot_params_cap_min_aperture", "Cap Min Aperture", base.HEX)
f.camera_camera_shot_params_cap_max_aperture = ProtoField.uint16 ("dji_p3.camera_camera_shot_params_cap_max_aperture", "Cap Max Aperture", base.HEX)
f.camera_camera_shot_params_masked42 = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_masked42", "Masked42", base.HEX)
  f.camera_camera_shot_params_auto_turn_off_fore_led = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_auto_turn_off_fore_led", "Auto Turn Off Fore Led", base.HEX, nil, 0x01, nil)
f.camera_camera_shot_params_exposure_status = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_exposure_status", "Exposure Status", base.HEX)
f.camera_camera_shot_params_locked_gimbal_when_shot = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_locked_gimbal_when_shot", "Locked Gimbal When Shot", base.HEX)
f.camera_camera_shot_params_encode_types = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_encode_types", "Video Encode Types", base.HEX)
  f.camera_camera_shot_params_primary_video_encode_type = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_primary_video_encode_type", "Primary Video Encode Type", base.HEX, enums.CAMERA_SHOT_PARAMS_VIDEO_ENCODE_TYPE_ENUM, 0x0f, nil)
  f.camera_camera_shot_params_secondary_video_encode_type = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_secondary_video_encode_type", "Secondary Video Encode Type", base.HEX, enums.CAMERA_SHOT_PARAMS_VIDEO_ENCODE_TYPE_ENUM, 0xf0, nil)
f.camera_camera_shot_params_not_auto_ae_unlock = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_not_auto_ae_unlock", "Not Auto Ae Unlock", base.HEX)
f.camera_camera_shot_params_unknown47 = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_unknown47", "Unknown47", base.HEX)
f.camera_camera_shot_params_constrast_ehance = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_constrast_ehance", "Constrast Ehance", base.HEX)
f.camera_camera_shot_params_video_record_mode = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_video_record_mode", "Video Record Mode", base.HEX)
f.camera_camera_shot_params_timelapse_save_type = ProtoField.uint8 ("dji_p3.camera_camera_shot_params_timelapse_save_type", "Timelapse Save Type", base.HEX)
f.camera_camera_shot_params_video_record_interval_time = ProtoField.uint16 ("dji_p3.camera_camera_shot_params_video_record_interval_time", "Video Record Interval Time", base.HEX)
f.camera_camera_shot_params_timelapse_duration = ProtoField.uint32 ("dji_p3.camera_camera_shot_params_timelapse_duration", "Timelapse Duration", base.HEX)
f.camera_camera_shot_params_timelapse_time_count_down = ProtoField.uint16 ("dji_p3.camera_camera_shot_params_timelapse_time_count_down", "Timelapse Time Count Down", base.HEX)
f.camera_camera_shot_params_timelapse_recorded_frame = ProtoField.uint32 ("dji_p3.camera_camera_shot_params_timelapse_recorded_frame", "Timelapse Recorded Frame", base.HEX)
f.camera_camera_shot_params_optics_scale = ProtoField.uint16 ("dji_p3.camera_camera_shot_params_optics_scale", "Optics Scale", base.HEX)
f.camera_camera_shot_params_digital_zoom_scale = ProtoField.uint16 ("dji_p3.camera_camera_shot_params_digital_zoom_scale", "Digital Zoom Scale", base.HEX)

local function camera_camera_shot_params_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_shot_params_aperture_size, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_user_shutter, payload(offset, 2))
    subtree:add_le (f.camera_camera_shot_params_reciprocal, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_shutter_speed_decimal, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_iso, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_exposure_compensation, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_ctr_object_for_one, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_ctr_object_for_two, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_image_size, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_image_ratio, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_image_quality, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_image_format, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_format, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_fps, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_fov, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_second_open, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_second_ratio, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_quality, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_store_format, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_exposure_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_scene_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_metering, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_white_balance, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_color_temp, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_mctf_enable, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_mctf_strength, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_sharpe, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_contrast, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_saturation, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_tonal, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_digital_filter, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_anti_flicker, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_continuous, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_time_params_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_time_params_num, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_time_params_period, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_real_aperture_size, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_real_shutter, payload(offset, 2))
    subtree:add_le (f.camera_camera_shot_params_rel_reciprocal, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_rel_shutter_speed_decimal, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_rel_iso, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_shot_params_rel_exposure_compensation, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_time_countdown, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_cap_min_shutter, payload(offset, 2))
    subtree:add_le (f.camera_camera_shot_params_cap_min_shutter_reciprocal, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_cap_min_shutter_decimal, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_cap_max_shutter, payload(offset, 2))
    subtree:add_le (f.camera_camera_shot_params_cap_max_shutter_reciprocal, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_cap_max_shutter_decimal, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_standard, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_ae_lock, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_photo_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_spot_area_bottom_right_pos, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_unknown3b, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_aeb_number, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_pano_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_cap_min_aperture, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_cap_max_aperture, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_masked42, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_params_auto_turn_off_fore_led, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_exposure_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_locked_gimbal_when_shot, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_encode_types, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_params_primary_video_encode_type, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_params_secondary_video_encode_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_not_auto_ae_unlock, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_unknown47, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_constrast_ehance, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_record_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_timelapse_save_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_record_interval_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_timelapse_duration, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_shot_params_timelapse_time_count_down, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_timelapse_recorded_frame, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_shot_params_optics_scale, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_digital_zoom_scale, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 91) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Shot Params: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Shot Params: Payload size different than expected") end
end

-- Camera - Camera Play Back Params - 0x82

enums.CAMERA_PLAY_BACK_PARAMS_MODE_ENUM = {
    [0x00] = 'Single',
    [0x01] = 'SingleLarge',
    [0x02] = 'SinglePlay',
    [0x03] = 'SinglePause',
    [0x04] = 'MultipleDel',
    [0x05] = 'Multiple',
    [0x06] = 'Download',
    [0x07] = 'SingleOver',
    [0x64] = 'OTHER',
}

enums.CAMERA_PLAY_BACK_PARAMS_FILE_TYPE_ENUM = {
    [0x00] = 'JPEG',
    [0x01] = 'DNG',
    [0x02] = 'VIDEO',
    [0x64] = 'OTHER',
}

enums.CAMERA_PLAY_BACK_PARAMS_DEL_FILE_STATUS_ENUM = {
    [0x00] = 'NORMAL',
    [0x02] = 'DELETING',
    [0x03] = 'COMPLETED',
}

f.camera_camera_play_back_params_mode = ProtoField.uint8 ("dji_p3.camera_camera_play_back_params_mode", "Mode", base.HEX, enums.CAMERA_PLAY_BACK_PARAMS_MODE_ENUM, nil, nil)
f.camera_camera_play_back_params_file_type = ProtoField.uint16 ("dji_p3.camera_camera_play_back_params_file_type", "File Type", base.HEX, enums.CAMERA_PLAY_BACK_PARAMS_FILE_TYPE_ENUM, nil, nil)
f.camera_camera_play_back_params_file_num = ProtoField.uint8 ("dji_p3.camera_camera_play_back_params_file_num", "File Num", base.DEC)
f.camera_camera_play_back_params_total_num = ProtoField.uint16 ("dji_p3.camera_camera_play_back_params_total_num", "Total Num", base.DEC)
f.camera_camera_play_back_params_index = ProtoField.uint16 ("dji_p3.camera_camera_play_back_params_index", "Index", base.DEC)
f.camera_camera_play_back_params_progress = ProtoField.uint8 ("dji_p3.camera_camera_play_back_params_progress", "Progress", base.HEX)
f.camera_camera_play_back_params_total_time = ProtoField.uint16 ("dji_p3.camera_camera_play_back_params_total_time", "Total Time", base.HEX)
f.camera_camera_play_back_params_current = ProtoField.uint16 ("dji_p3.camera_camera_play_back_params_current", "Current", base.HEX)
f.camera_camera_play_back_params_delete_chioce_num = ProtoField.uint16 ("dji_p3.camera_camera_play_back_params_delete_chioce_num", "Delete Chioce Num", base.HEX)
f.camera_camera_play_back_params_zoom_size = ProtoField.uint16 ("dji_p3.camera_camera_play_back_params_zoom_size", "Zoom Size", base.HEX)
f.camera_camera_play_back_params_total_photo_num = ProtoField.uint16 ("dji_p3.camera_camera_play_back_params_total_photo_num", "Total Photo Num", base.HEX)
f.camera_camera_play_back_params_total_video_num = ProtoField.uint16 ("dji_p3.camera_camera_play_back_params_total_video_num", "Total Video Num", base.HEX)
f.camera_camera_play_back_params_photo_width = ProtoField.uint32 ("dji_p3.camera_camera_play_back_params_photo_width", "Photo Width", base.HEX)
f.camera_camera_play_back_params_photo_height = ProtoField.uint32 ("dji_p3.camera_camera_play_back_params_photo_height", "Photo Height", base.HEX)
f.camera_camera_play_back_params_center_x = ProtoField.uint32 ("dji_p3.camera_camera_play_back_params_center_x", "Center X", base.HEX)
f.camera_camera_play_back_params_center_y = ProtoField.uint32 ("dji_p3.camera_camera_play_back_params_center_y", "Center Y", base.HEX)
f.camera_camera_play_back_params_cur_page_selected = ProtoField.uint8 ("dji_p3.camera_camera_play_back_params_cur_page_selected", "Cur Page Selected", base.HEX)
f.camera_camera_play_back_params_del_file_status = ProtoField.uint8 ("dji_p3.camera_camera_play_back_params_del_file_status", "Del File Status", base.HEX, enums.CAMERA_PLAY_BACK_PARAMS_DEL_FILE_STATUS_ENUM, nil, nil)
f.camera_camera_play_back_params_not_select_file_valid = ProtoField.uint8 ("dji_p3.camera_camera_play_back_params_not_select_file_valid", "Not Select File Valid", base.HEX)
f.camera_camera_play_back_params_single_downloaded = ProtoField.uint8 ("dji_p3.camera_camera_play_back_params_single_downloaded", "Single Downloaded", base.HEX)

local function camera_camera_play_back_params_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_play_back_params_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_play_back_params_file_type, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_play_back_params_file_num, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_play_back_params_total_num, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_play_back_params_index, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_play_back_params_progress, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_play_back_params_total_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_play_back_params_current, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_play_back_params_delete_chioce_num, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_play_back_params_zoom_size, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_play_back_params_total_photo_num, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_play_back_params_total_video_num, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_play_back_params_photo_width, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_play_back_params_photo_height, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_play_back_params_center_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_play_back_params_center_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_play_back_params_cur_page_selected, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_play_back_params_del_file_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_play_back_params_not_select_file_valid, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_play_back_params_single_downloaded, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 41) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Play Back Params: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Play Back Params: Payload size different than expected") end
end

-- Camera - Camera Chart Info - 0x83

f.camera_camera_chart_info_light_values = ProtoField.bytes ("dji_p3.camera_camera_chart_info_light_values", "Light Values", base.NONE)

local function camera_camera_chart_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_chart_info_light_values, payload(offset, 4)) -- size not known
    offset = offset + 4

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Chart Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Chart Info: Payload size different than expected") end
end

-- Camera - Camera Recording Name - 0x84

enums.CAMERA_RECORDING_FILE_TYPE_ENUM = {
    [0x00] = 'JPEG',
    [0x01] = 'DNG',
    [0x02] = 'VIDEO',
    [0x64] = 'OTHER',
}

f.camera_camera_recording_name_file_type = ProtoField.uint8 ("dji_p3.camera_camera_recording_name_file_type", "File Type", base.HEX, enums.CAMERA_RECORDING_FILE_TYPE_ENUM, nil, nil)
f.camera_camera_recording_name_index = ProtoField.uint32 ("dji_p3.camera_camera_recording_name_index", "Index", base.HEX)
f.camera_camera_recording_name_size = ProtoField.uint64 ("dji_p3.camera_camera_recording_name_size", "Size", base.HEX)
f.camera_camera_recording_name_time = ProtoField.uint32 ("dji_p3.camera_camera_recording_name_time", "Time", base.HEX)

local function camera_camera_recording_name_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_recording_name_file_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_recording_name_index, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_recording_name_size, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.camera_camera_recording_name_time, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 17) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Recording Name: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Recording Name: Payload size different than expected") end
end

-- Camera - Camera Raw Params - 0x85

enums.CAMERA_RAW_PARAMS_DISK_STATUS_ENUM = {
    [0x00] = 'NA',
    [0x01] = 'WAITING',
    [0x02] = 'STORING',
    [0x03] = 'LOW_FORMATING',
    [0x04] = 'FAST_FORMATING',
    [0x05] = 'INITIALIZING',
    [0x06] = 'DEVICE_ERROR',
    [0x07] = 'VERIFY_ERROR',
    [0x08] = 'FULL',
    [0x09] = 'OTHER',
}

f.camera_camera_raw_params_masked00 = ProtoField.uint8 ("dji_p3.camera_camera_raw_params_masked00", "Masked00", base.HEX)
  f.camera_camera_raw_params_disk_status = ProtoField.uint8 ("dji_p3.camera_camera_raw_params_disk_status", "Disk Status", base.HEX, enums.CAMERA_RAW_PARAMS_DISK_STATUS_ENUM, 0x0f, nil)
  f.camera_camera_raw_params_disk_connected = ProtoField.uint8 ("dji_p3.camera_camera_raw_params_disk_connected", "Disk Connected", base.HEX, nil, 0x10, nil)
  f.camera_camera_raw_params_disk_capacity = ProtoField.uint8 ("dji_p3.camera_camera_raw_params_disk_capacity", "Disk Capacity", base.HEX, nil, 0x60, nil)
f.camera_camera_raw_params_disk_available_time = ProtoField.uint16 ("dji_p3.camera_camera_raw_params_disk_available_time", "Disk Available Time", base.HEX)
f.camera_camera_raw_params_available_capacity = ProtoField.uint32 ("dji_p3.camera_camera_raw_params_available_capacity", "Available Capacity", base.HEX)
f.camera_camera_raw_params_resolution = ProtoField.uint8 ("dji_p3.camera_camera_raw_params_resolution", "Resolution", base.HEX)
f.camera_camera_raw_params_fps = ProtoField.uint8 ("dji_p3.camera_camera_raw_params_fps", "Fps", base.HEX)
f.camera_camera_raw_params_ahci_status = ProtoField.uint8 ("dji_p3.camera_camera_raw_params_ahci_status", "Ahci Status", base.HEX)

local function camera_camera_raw_params_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_raw_params_masked00, payload(offset, 1))
    subtree:add_le (f.camera_camera_raw_params_disk_status, payload(offset, 1))
    subtree:add_le (f.camera_camera_raw_params_disk_connected, payload(offset, 1))
    subtree:add_le (f.camera_camera_raw_params_disk_capacity, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_raw_params_disk_available_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_raw_params_available_capacity, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_raw_params_resolution, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_raw_params_fps, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_raw_params_ahci_status, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 10) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Raw Params: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Raw Params: Payload size different than expected") end
end

-- Camera - Camera Cur Pano File Name - 0x86

f.camera_camera_cur_pano_file_name_index = ProtoField.uint32 ("dji_p3.camera_camera_cur_pano_file_name_index", "Index", base.HEX)
f.camera_camera_cur_pano_file_name_unknown04 = ProtoField.bytes ("dji_p3.camera_camera_cur_pano_file_name_unknown04", "Unknown04", base.SPACE)
f.camera_camera_cur_pano_file_name_pano_create_time = ProtoField.uint32 ("dji_p3.camera_camera_cur_pano_file_name_pano_create_time", "Pano Create Time", base.HEX)
f.camera_camera_cur_pano_file_name_cur_saved_number = ProtoField.uint8 ("dji_p3.camera_camera_cur_pano_file_name_cur_saved_number", "Cur Saved Number", base.HEX)
f.camera_camera_cur_pano_file_name_cur_taken_number = ProtoField.uint8 ("dji_p3.camera_camera_cur_pano_file_name_cur_taken_number", "Cur Taken Number", base.HEX)
f.camera_camera_cur_pano_file_name_total_number = ProtoField.uint8 ("dji_p3.camera_camera_cur_pano_file_name_total_number", "Total Number", base.HEX)
f.camera_camera_cur_pano_file_name_unknown13 = ProtoField.uint8 ("dji_p3.camera_camera_cur_pano_file_name_unknown13", "Unknown13", base.HEX)
f.camera_camera_cur_pano_file_name_file_size = ProtoField.uint64 ("dji_p3.camera_camera_cur_pano_file_name_file_size", "File Size", base.HEX)
f.camera_camera_cur_pano_file_name_create_time = ProtoField.uint32 ("dji_p3.camera_camera_cur_pano_file_name_create_time", "Create Time", base.HEX)

local function camera_camera_cur_pano_file_name_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_cur_pano_file_name_index, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_cur_pano_file_name_unknown04, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.camera_camera_cur_pano_file_name_pano_create_time, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_cur_pano_file_name_cur_saved_number, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_cur_pano_file_name_cur_taken_number, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_cur_pano_file_name_total_number, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_cur_pano_file_name_unknown13, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_cur_pano_file_name_file_size, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.camera_camera_cur_pano_file_name_create_time, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 32) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Cur Pano File Name: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Cur Pano File Name: Payload size different than expected") end
end

-- Camera - Camera Shot Info - 0x87


enums.CAMERA_SHOT_INFO_FUSELAGE_FOCUS_MODE_ENUM = {
    [0x00] = 'Manual',
    [0x01] = 'OneAuto',
    [0x02] = 'ContinuousAuto',
    [0x03] = 'ManualFine',
    [0x06] = 'OTHER',
}

f.camera_camera_shot_info_masked00 = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_masked00", "Masked00", base.HEX)
  f.camera_camera_shot_info_fuselage_focus_mode = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_fuselage_focus_mode", "Fuselage Focus Mode", base.HEX, enums.CAMERA_SHOT_INFO_FUSELAGE_FOCUS_MODE_ENUM, 0x03, nil)
  f.camera_camera_shot_info_shot_focus_mode = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_shot_focus_mode", "Shot Focus Mode", base.HEX, nil, 0x0c, "TODO values from enum P3.DataCameraGetPushShotInfo")
  f.camera_camera_shot_info_zoom_focus_type = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_zoom_focus_type", "Zoom Focus Type", base.HEX, nil, 0x10, nil)
  f.camera_camera_shot_info_shot_type = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_shot_type", "Shot Type", base.HEX, nil, 0x20, "TODO values from enum P3.DataCameraGetPushShotInfo")
  f.camera_camera_shot_info_shot_fd_type = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_shot_fd_type", "Shot Fd Type", base.HEX, nil, 0x40, "TODO values from enum P3.DataCameraGetPushShotInfo")
  f.camera_camera_shot_info_shot_connected = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_shot_connected", "Shot Connected", base.HEX, nil, 0x80, nil)
f.camera_camera_shot_info_shot_focus_max_stroke = ProtoField.uint16 ("dji_p3.camera_camera_shot_info_shot_focus_max_stroke", "Shot Focus Max Stroke", base.HEX)
f.camera_camera_shot_info_shot_focus_cur_stroke = ProtoField.uint16 ("dji_p3.camera_camera_shot_info_shot_focus_cur_stroke", "Shot Focus Cur Stroke", base.HEX)
f.camera_camera_shot_info_obj_distance = ProtoField.float ("dji_p3.camera_camera_shot_info_obj_distance", "Obj Distance", base.DEC)
f.camera_camera_shot_info_min_aperture = ProtoField.uint16 ("dji_p3.camera_camera_shot_info_min_aperture", "Min Aperture", base.HEX)
f.camera_camera_shot_info_max_aperture = ProtoField.uint16 ("dji_p3.camera_camera_shot_info_max_aperture", "Max Aperture", base.HEX)
f.camera_camera_shot_info_spot_af_axis_x = ProtoField.float ("dji_p3.camera_camera_shot_info_spot_af_axis_x", "Spot Af Axis X", base.DEC)
f.camera_camera_shot_info_spot_af_axis_y = ProtoField.float ("dji_p3.camera_camera_shot_info_spot_af_axis_y", "Spot Af Axis Y", base.DEC)
f.camera_camera_shot_info_masked15 = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_masked15", "Masked15", base.HEX)
  f.camera_camera_shot_info_focus_status = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_focus_status", "Focus Status", base.HEX, nil, 0x03, nil)
f.camera_camera_shot_info_mf_focus_probability = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_mf_focus_probability", "Mf Focus Probability", base.HEX)
f.camera_camera_shot_info_min_focus_distance = ProtoField.uint16 ("dji_p3.camera_camera_shot_info_min_focus_distance", "Min Focus Distance", base.HEX)
f.camera_camera_shot_info_max_focus_distance = ProtoField.uint16 ("dji_p3.camera_camera_shot_info_max_focus_distance", "Max Focus Distance", base.HEX)
f.camera_camera_shot_info_cur_focus_distance = ProtoField.uint16 ("dji_p3.camera_camera_shot_info_cur_focus_distance", "Cur Focus Distance", base.HEX)
f.camera_camera_shot_info_min_focus_distance_step = ProtoField.uint16 ("dji_p3.camera_camera_shot_info_min_focus_distance_step", "Min Focus Distance Step", base.HEX)
f.camera_camera_shot_info_masked1f = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_masked1f", "Masked1F", base.HEX)
  f.camera_camera_shot_info_digital_focus_m_enable = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_digital_focus_m_enable", "Digital Focus M Enable", base.HEX, nil, 0x01, nil)
  f.camera_camera_shot_info_digital_focus_a_enable = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_digital_focus_a_enable", "Digital Focus A Enable", base.HEX, nil, 0x02, nil)
f.camera_camera_shot_info_x_axis_focus_window_num = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_x_axis_focus_window_num", "X Axis Focus Window Num", base.HEX)
f.camera_camera_shot_info_y_axis_focus_window_num = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_y_axis_focus_window_num", "Y Axis Focus Window Num", base.HEX)
f.camera_camera_shot_info_mf_focus_status = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_mf_focus_status", "Mf Focus Status", base.HEX)
f.camera_camera_shot_info_focus_window_start_x = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_focus_window_start_x", "Focus Window Start X", base.HEX)
f.camera_camera_shot_info_focus_window_real_num_x = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_focus_window_real_num_x", "Focus Window Real Num X", base.HEX)
f.camera_camera_shot_info_focus_window_start_y = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_focus_window_start_y", "Focus Window Start Y", base.HEX)
f.camera_camera_shot_info_focus_window_real_num_y = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_focus_window_real_num_y", "Focus Window Real Num Y", base.HEX)
f.camera_camera_shot_info_support_type = ProtoField.uint8 ("dji_p3.camera_camera_shot_info_support_type", "Support Type", base.HEX)

local function camera_camera_shot_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_shot_info_masked00, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_info_fuselage_focus_mode, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_info_shot_focus_mode, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_info_zoom_focus_type, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_info_shot_type, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_info_shot_fd_type, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_info_shot_connected, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_shot_focus_max_stroke, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_info_shot_focus_cur_stroke, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_info_obj_distance, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_shot_info_min_aperture, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_info_max_aperture, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_info_spot_af_axis_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_shot_info_spot_af_axis_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_shot_info_masked15, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_info_focus_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_mf_focus_probability, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_min_focus_distance, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_info_max_focus_distance, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_info_cur_focus_distance, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_info_min_focus_distance_step, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_info_masked1f, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_info_digital_focus_m_enable, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_info_digital_focus_a_enable, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_x_axis_focus_window_num, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_y_axis_focus_window_num, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_mf_focus_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_focus_window_start_x, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_focus_window_real_num_x, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_focus_window_start_y, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_focus_window_real_num_y, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_support_type, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 40) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Shot Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Shot Info: Payload size different than expected") end
end

-- Camera - Camera Timelapse Parms - 0x88

f.camera_camera_timelapse_parms_masked00 = ProtoField.uint8 ("dji_p3.camera_camera_timelapse_parms_masked00", "Masked00", base.HEX)
  f.camera_camera_timelapse_parms_control_mode = ProtoField.uint8 ("dji_p3.camera_camera_timelapse_parms_control_mode", "Control Mode", base.HEX, nil, 0x03, nil)
  f.camera_camera_timelapse_parms_gimbal_point_count = ProtoField.uint8 ("dji_p3.camera_camera_timelapse_parms_gimbal_point_count", "Gimbal Point Count", base.HEX, nil, 0xfc, nil)
-- for i=0..point_count, each entry 12 bytes
f.camera_camera_timelapse_parms_interval = ProtoField.uint16 ("dji_p3.camera_camera_timelapse_parms_interval", "Point Interval", base.HEX)
f.camera_camera_timelapse_parms_duration = ProtoField.uint32 ("dji_p3.camera_camera_timelapse_parms_duration", "Point Duration", base.HEX)
f.camera_camera_timelapse_parms_yaw = ProtoField.uint16 ("dji_p3.camera_camera_timelapse_parms_yaw", "Point Yaw", base.HEX, nil, nil)
f.camera_camera_timelapse_parms_roll = ProtoField.uint16 ("dji_p3.camera_camera_timelapse_parms_roll", "Point Roll", base.HEX, nil, nil)
f.camera_camera_timelapse_parms_pitch = ProtoField.uint16 ("dji_p3.camera_camera_timelapse_parms_pitch", "Point Pitch", base.HEX, nil, nil)

local function camera_camera_timelapse_parms_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_timelapse_parms_masked00, payload(offset, 1))
    subtree:add_le (f.camera_camera_timelapse_parms_control_mode, payload(offset, 1))
    local point_count = bit.band(buffer(offset,1):le_uint(), 0xfc)
    subtree:add_le (f.camera_camera_timelapse_parms_gimbal_point_count, payload(offset, 1))
    offset = offset + 1

    local i = 0
    repeat

        subtree:add_le (f.camera_camera_timelapse_parms_interval, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.camera_camera_timelapse_parms_duration, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.camera_camera_timelapse_parms_yaw, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.camera_camera_timelapse_parms_roll, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.camera_camera_timelapse_parms_pitch, payload(offset, 2))
        offset = offset + 2

        i = i + 1

    until i >= point_count

    if (offset ~= 12 * point_count + 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Timelapse Parms: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Timelapse Parms: Payload size different than expected") end
end

-- Camera - Camera Tracking Status - 0x89

f.camera_camera_tracking_status_masked00 = ProtoField.uint8 ("dji_p3.camera_camera_tracking_status_masked00", "Masked00", base.HEX)
  f.camera_camera_tracking_status_get_status = ProtoField.uint8 ("dji_p3.camera_camera_tracking_status_status", "Status", base.HEX, nil, 0x01, nil)
f.camera_camera_tracking_status_x_coord = ProtoField.uint16 ("dji_p3.camera_camera_tracking_status_x_coord", "X Coord", base.DEC)
f.camera_camera_tracking_status_y_coord = ProtoField.uint16 ("dji_p3.camera_camera_tracking_status_y_coord", "Y Coord", base.DEC)

local function camera_camera_tracking_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_tracking_status_masked00, payload(offset, 1))
    subtree:add_le (f.camera_camera_tracking_status_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tracking_status_x_coord, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tracking_status_y_coord, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Tracking Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Tracking Status: Payload size different than expected") end
end

-- Camera - Camera Fov Param - 0x8a

f.camera_camera_fov_param_image_width = ProtoField.uint32 ("dji_p3.camera_camera_fov_param_image_width", "Image Width", base.DEC)
f.camera_camera_fov_param_image_height = ProtoField.uint32 ("dji_p3.camera_camera_fov_param_image_height", "Image Height", base.DEC)
f.camera_camera_fov_param_image_ratio = ProtoField.uint32 ("dji_p3.camera_camera_fov_param_image_ratio", "Image Ratio", base.HEX)
f.camera_camera_fov_param_lens_focal_length = ProtoField.uint32 ("dji_p3.camera_camera_fov_param_lens_focal_length", "Lens Focal Length", base.DEC)

local function camera_camera_fov_param_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_fov_param_image_width, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_fov_param_image_height, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_fov_param_image_ratio, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_fov_param_lens_focal_length, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 16) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Fov Param: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Fov Param: Payload size different than expected") end
end

-- Camera - Camera Prepare Open Fan - 0xb4

f.camera_camera_prepare_open_fan_left_seconds = ProtoField.uint8 ("dji_p3.camera_camera_prepare_open_fan_left_seconds", "Left Seconds", base.DEC)

local function camera_camera_prepare_open_fan_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_prepare_open_fan_left_seconds, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Prepare Open Fan: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Prepare Open Fan: Payload size different than expected") end
end

-- Camera - Camera Optics Zoom Mode - 0xb8

enums.CAMERA_OPTICS_ZOOM_MODE_ZOOM_MODE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
}

enums.CAMERA_OPTICS_ZOOM_MODE_ZOOM_SPEED_ENUM = {
    [0x78] = 'a',
    [0x79] = 'b',
    [0x7a] = 'c',
    [0x7b] = 'd',
    [0x7c] = 'e',
    [0x7d] = 'f',
    [0x7e] = 'g',
}

f.camera_camera_optics_zoom_mode_optics_zomm_mode = ProtoField.uint8 ("dji_p3.camera_camera_optics_zoom_mode_optics_zomm_mode", "Optics Zomm Mode", base.HEX, enums.CAMERA_OPTICS_ZOOM_MODE_ZOOM_MODE_ENUM, nil, nil)
f.camera_camera_optics_zoom_mode_zoom_speed = ProtoField.uint8 ("dji_p3.camera_camera_optics_zoom_mode_zoom_speed", "Zoom Speed", base.HEX, enums.CAMERA_OPTICS_ZOOM_MODE_ZOOM_SPEED_ENUM, nil, nil)
f.camera_camera_optics_zoom_mode_c = ProtoField.uint8 ("dji_p3.camera_camera_optics_zoom_mode_c", "C", base.HEX)
f.camera_camera_optics_zoom_mode_d = ProtoField.uint8 ("dji_p3.camera_camera_optics_zoom_mode_d", "D", base.HEX)

local function camera_camera_optics_zoom_mode_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_optics_zoom_mode_optics_zomm_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_optics_zoom_mode_zoom_speed, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_optics_zoom_mode_c, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_optics_zoom_mode_d, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Optics Zoom Mode: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Optics Zoom Mode: Payload size different than expected") end
end

-- Camera - Camera Tap Zoom State Info - 0xc7

enums.CAMERA_TAP_ZOOM_STATE_INFO_WORKING_STATE_ENUM = {
    [0x00] = 'IDLE',
    [0x01] = 'ZOOM_IN',
    [0x02] = 'ZOOM_OUT',
    [0xff] = 'Unknown',
}

f.camera_camera_tap_zoom_state_info_working_state = ProtoField.uint8 ("dji_p3.camera_camera_tap_zoom_state_info_working_state", "Working State", base.HEX, enums.CAMERA_TAP_ZOOM_STATE_INFO_WORKING_STATE_ENUM, nil, nil)
f.camera_camera_tap_zoom_state_info_gimbal_state = ProtoField.uint8 ("dji_p3.camera_camera_tap_zoom_state_info_gimbal_state", "Gimbal State", base.HEX)
f.camera_camera_tap_zoom_state_info_multiplier = ProtoField.uint8 ("dji_p3.camera_camera_tap_zoom_state_info_multiplier", "Multiplier", base.HEX)

local function camera_camera_tap_zoom_state_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_tap_zoom_state_info_working_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tap_zoom_state_info_gimbal_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tap_zoom_state_info_multiplier, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 3) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Tap Zoom State Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Tap Zoom State Info: Payload size different than expected") end
end

-- Camera - Camera Tau Param - 0xf2

enums.CAMERA_TAU_PARAM_ZOOM_MODE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x02] = 'c',
}

enums.CAMERA_TAU_PARAM_AGC_AGC_TYPE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x02] = 'c',
    [0x03] = 'd',
    [0x04] = 'e',
    [0x05] = 'f',
    [0x06] = 'g',
    [0x07] = 'h',
    [0x08] = 'i',
    [0x64] = 'j',
}

enums.CAMERA_TAU_PARAM_ROI_TYPE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x02] = 'c',
    [0x64] = 'd',
}

enums.CAMERA_TAU_PARAM_THERMOMETRIC_TYPE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x02] = 'c',
    [0x63] = 'd',
}

enums.CAMERA_TAU_PARAM_GAIN_MODE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x02] = 'c',
    [0x64] = 'd',
}

enums.CAMERA_TAU_PARAM_VIDEO_RESOLUTION_ENUM = {
    [0x00] = 'VR_640',
    [0x01] = 'VR_336',
    [0xff] = 'UNKNOWN',
}

enums.CAMERA_TAU_PARAM_LEN_FOCUS_LENGTH_ENUM = {
    [0x00] = 'LFL_68',
    [0x01] = 'LFL_75',
    [0x02] = 'LFL_90',
    [0x03] = 'LFL_130',
    [0x04] = 'LFL_190',
    [0xff] = 'UNKNOWN',
}

enums.CAMERA_TAU_PARAM_LEN_FPS_ENUM = {
    [0x00] = 'FPS_LESS_9',
    [0x04] = 'FPS_30',
    [0xff] = 'UNKNOWN',
}

enums.CAMERA_TAU_PARAM_FFC_MODE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x64] = 'c',
}

enums.CAMERA_TAU_PARAM_EXTER_PARAM_TYPE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x02] = 'c',
    [0x63] = 'd',
}

f.camera_camera_tau_param_image_format = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_image_format", "Image Format", base.HEX)
f.camera_camera_tau_param_video_format = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_video_format", "Video Format", base.HEX)
f.camera_camera_tau_param_video_fps = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_video_fps", "Video Fps", base.HEX)
f.camera_camera_tau_param_zoom_mode = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_zoom_mode", "Zoom Mode", base.HEX, enums.CAMERA_TAU_PARAM_ZOOM_MODE_ENUM, nil, nil)
f.camera_camera_tau_param_zoom_scale = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_zoom_scale", "Zoom Scale", base.HEX)
f.camera_camera_tau_param_digital_filter = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_digital_filter", "Digital Filter", base.HEX)
f.camera_camera_tau_param_agc = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_agc", "Agc", base.HEX, enums.CAMERA_TAU_PARAM_AGC_AGC_TYPE_ENUM, nil, nil)
f.camera_camera_tau_param_dde = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_dde", "Dde", base.HEX)
f.camera_camera_tau_param_ace = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_ace", "Ace", base.HEX)
f.camera_camera_tau_param_sso = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_sso", "Sso", base.HEX)
f.camera_camera_tau_param_contrast = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_contrast", "Contrast", base.HEX)
f.camera_camera_tau_param_brightness = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_brightness", "Brightness", base.HEX)
f.camera_camera_tau_param_thermometric_x_axis = ProtoField.float ("dji_p3.camera_camera_tau_param_thermometric_x_axis", "Thermometric X Axis", base.DEC)
f.camera_camera_tau_param_thermometric_y_axis = ProtoField.float ("dji_p3.camera_camera_tau_param_thermometric_y_axis", "Thermometric Y Axis", base.DEC)
f.camera_camera_tau_param_thermometric_temp = ProtoField.float ("dji_p3.camera_camera_tau_param_thermometric_temp", "Thermometric Temp", base.DEC)
f.camera_camera_tau_param_shot_count_down = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_shot_count_down", "Shot Count Down", base.HEX)
f.camera_camera_tau_param_roi_type = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_roi_type", "Roi Type", base.HEX, enums.CAMERA_TAU_PARAM_ROI_TYPE_ENUM, nil, nil)
f.camera_camera_tau_param_masked1f = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_masked1f", "Masked1F", base.HEX)
  f.camera_camera_tau_param_isotherm_enable = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_isotherm_enable", "Isotherm Enable", base.HEX, nil, 0x01, nil)
f.camera_camera_tau_param_isotherm_unit = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_isotherm_unit", "Isotherm Unit", base.HEX)
f.camera_camera_tau_param_isotherm_lower = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_isotherm_lower", "Isotherm Lower", base.HEX)
f.camera_camera_tau_param_isotherm_middle = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_isotherm_middle", "Isotherm Middle", base.HEX)
f.camera_camera_tau_param_isotherm_upper = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_isotherm_upper", "Isotherm Upper", base.HEX)
f.camera_camera_tau_param_thermometric_type = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_thermometric_type", "Thermometric Type", base.HEX, enums.CAMERA_TAU_PARAM_THERMOMETRIC_TYPE_ENUM, nil, nil)
f.camera_camera_tau_param_object_control = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_object_control", "Object Control", base.HEX)
f.camera_camera_tau_param_gain_mode = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_gain_mode", "Gain Mode", base.HEX, enums.CAMERA_TAU_PARAM_GAIN_MODE_ENUM, nil, nil)
f.camera_camera_tau_param_video_resolution = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_video_resolution", "Video Resolution", base.HEX, enums.CAMERA_TAU_PARAM_VIDEO_RESOLUTION_ENUM, nil, nil)
f.camera_camera_tau_param_len_focus_length = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_len_focus_length", "Len Focus Length", base.HEX, enums.CAMERA_TAU_PARAM_LEN_FOCUS_LENGTH_ENUM, nil, nil)
f.camera_camera_tau_param_len_fps = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_len_fps", "Len Fps", base.HEX, enums.CAMERA_TAU_PARAM_LEN_FPS_ENUM, nil, nil)
f.camera_camera_tau_param_photo_interval = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_photo_interval", "Photo Interval", base.HEX)
f.camera_camera_tau_param_unknown2e = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_unknown2e", "Unknown2E", base.HEX)
f.camera_camera_tau_param_ffc_mode = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_ffc_mode", "Ffc Mode", base.HEX, enums.CAMERA_TAU_PARAM_FFC_MODE_ENUM, nil, nil)
f.camera_camera_tau_param_masked30 = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_masked30", "Masked30", base.HEX)
  f.camera_camera_tau_param_support_spot_thermometric = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_support_spot_thermometric", "Support Spot Thermometric", base.HEX, nil, 0x01, nil)
  f.camera_camera_tau_param_thermometric_valid = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_thermometric_valid", "Thermometric Valid", base.HEX, nil, 0x80, nil)
f.camera_camera_tau_param_exter_param_type = ProtoField.uint8 ("dji_p3.camera_camera_tau_param_exter_param_type", "Exter Param Type", base.HEX, enums.CAMERA_TAU_PARAM_EXTER_PARAM_TYPE_ENUM, nil, nil)
f.camera_camera_tau_param_target_emissivity = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_target_emissivity", "Target Emissivity", base.HEX)
f.camera_camera_tau_param_atmosphere_transmission = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_atmosphere_transmission", "Atmosphere Transmission", base.HEX)
f.camera_camera_tau_param_atmosphere_temperature = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_atmosphere_temperature", "Atmosphere Temperature", base.HEX)
f.camera_camera_tau_param_background_temperature = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_background_temperature", "Background Temperature", base.HEX)
f.camera_camera_tau_param_window_transmission = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_window_transmission", "Window Transmission", base.HEX)
f.camera_camera_tau_param_window_temperature = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_window_temperature", "Window Temperature", base.HEX)
f.camera_camera_tau_param_window_reflection = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_window_reflection", "Window Reflection", base.HEX)
f.camera_camera_tau_param_window_reflected_temperature = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_window_reflected_temperature", "Window Reflected Temperature", base.HEX)
f.camera_camera_tau_param_area_thermometric_left = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_area_thermometric_left", "Area Thermometric Left", base.HEX)
f.camera_camera_tau_param_area_thermometric_top = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_area_thermometric_top", "Area Thermometric Top", base.HEX)
f.camera_camera_tau_param_area_thermometric_right = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_area_thermometric_right", "Area Thermometric Right", base.HEX)
f.camera_camera_tau_param_area_thermometric_bottom = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_area_thermometric_bottom", "Area Thermometric Bottom", base.HEX)
f.camera_camera_tau_param_area_thermometric_average = ProtoField.float ("dji_p3.camera_camera_tau_param_area_thermometric_average", "Area Thermometric Average", base.DEC)
f.camera_camera_tau_param_area_thermometric_min = ProtoField.float ("dji_p3.camera_camera_tau_param_area_thermometric_min", "Area Thermometric Min", base.DEC)
f.camera_camera_tau_param_area_thermometric_max = ProtoField.float ("dji_p3.camera_camera_tau_param_area_thermometric_max", "Area Thermometric Max", base.DEC)
f.camera_camera_tau_param_area_thermometric_min_x = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_area_thermometric_min_x", "Area Thermometric Min X", base.HEX)
f.camera_camera_tau_param_area_thermometric_min_y = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_area_thermometric_min_y", "Area Thermometric Min Y", base.HEX)
f.camera_camera_tau_param_area_thermometric_max_x = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_area_thermometric_max_x", "Area Thermometric Max X", base.HEX)
f.camera_camera_tau_param_area_thermometric_max_y = ProtoField.uint16 ("dji_p3.camera_camera_tau_param_area_thermometric_max_y", "Area Thermometric Max Y", base.HEX)

local function camera_camera_tau_param_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_tau_param_image_format, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_video_format, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_video_fps, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_zoom_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_zoom_scale, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_digital_filter, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_agc, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_dde, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_ace, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_sso, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_contrast, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_brightness, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_thermometric_x_axis, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_tau_param_thermometric_y_axis, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_tau_param_thermometric_temp, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_tau_param_shot_count_down, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_roi_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_masked1f, payload(offset, 1))
    subtree:add_le (f.camera_camera_tau_param_isotherm_enable, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_isotherm_unit, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_isotherm_lower, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_isotherm_middle, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_isotherm_upper, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_thermometric_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_object_control, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_gain_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_video_resolution, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_len_focus_length, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_len_fps, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_photo_interval, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_unknown2e, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_ffc_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_masked30, payload(offset, 1))
    subtree:add_le (f.camera_camera_tau_param_support_spot_thermometric, payload(offset, 1))
    subtree:add_le (f.camera_camera_tau_param_thermometric_valid, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_exter_param_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_target_emissivity, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_atmosphere_transmission, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_atmosphere_temperature, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_background_temperature, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_window_transmission, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_window_temperature, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_window_reflection, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_window_reflected_temperature, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_left, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_top, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_right, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_bottom, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_average, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_min, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_max, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_min_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_min_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_max_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_max_y, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 94) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Tau Param: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Tau Param: Payload size different than expected") end
end

local CAMERA_UART_CMD_DISSECT = {
    [0x7c] = camera_camera_shutter_cmd_dissector,
    [0x80] = camera_camera_state_info_dissector,
    [0x81] = camera_camera_shot_params_dissector,
    [0x82] = camera_camera_play_back_params_dissector,
    [0x83] = camera_camera_chart_info_dissector,
    [0x84] = camera_camera_recording_name_dissector,
    [0x85] = camera_camera_raw_params_dissector,
    [0x86] = camera_camera_cur_pano_file_name_dissector,
    [0x87] = camera_camera_shot_info_dissector,
    [0x88] = camera_camera_timelapse_parms_dissector,
    [0x89] = camera_camera_tracking_status_dissector,
    [0x8a] = camera_camera_fov_param_dissector,
    [0xb4] = camera_camera_prepare_open_fan_dissector,
    [0xb8] = camera_camera_optics_zoom_mode_dissector,
    [0xc7] = camera_camera_tap_zoom_state_info_dissector,
    [0xf2] = camera_camera_tau_param_dissector,
}

-- Flight Controller - Flyc Forbid Status - 0x09

enums.FLYC_FORBID_STATUS_FLIGHT_LIMIT_AREA_STATE_DJI_FLIGHT_LIMIT_AREA_STATE_ENUM = {
    [0x00] = 'None',
    [0x01] = 'NearLimit',
    [0x02] = 'InHalfLimit',
    [0x03] = 'InSlowDownArea',
    [0x04] = 'InnerLimit',
    [0x05] = 'InnerUnLimit',
    [0x64] = 'OTHER',
}

enums.FLYC_FORBID_STATUS_DJI_FLIGHT_LIMIT_ACTION_EVENT_ENUM = {
    [0x00] = 'None',
    [0x01] = 'ExitLanding',
    [0x02] = 'Collision',
    [0x03] = 'StartLanding',
    [0x04] = 'StopMotor',
    [0x64] = 'OTHER',
}

f.flyc_flyc_forbid_status_flight_limit_area_state = ProtoField.uint8 ("dji_p3.flyc_flyc_forbid_status_flight_limit_area_state", "Flight Limit Area State", base.HEX, enums.FLYC_FORBID_STATUS_FLIGHT_LIMIT_AREA_STATE_DJI_FLIGHT_LIMIT_AREA_STATE_ENUM, nil, nil)
f.flyc_flyc_forbid_status_dji_flight_limit_action_event = ProtoField.uint8 ("dji_p3.flyc_flyc_forbid_status_dji_flight_limit_action_event", "Dji Flight Limit Action Event", base.HEX, enums.FLYC_FORBID_STATUS_DJI_FLIGHT_LIMIT_ACTION_EVENT_ENUM, nil, nil)
f.flyc_flyc_forbid_status_limit_space_num = ProtoField.uint8 ("dji_p3.flyc_flyc_forbid_status_limit_space_num", "Limit Space Num", base.HEX)
f.flyc_flyc_forbid_status_unknown3 = ProtoField.bytes ("dji_p3.flyc_flyc_forbid_status_unknown3", "Unknown3", base.SPACE)

local function flyc_flyc_forbid_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_forbid_status_flight_limit_area_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_forbid_status_dji_flight_limit_action_event, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_forbid_status_limit_space_num, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_forbid_status_unknown3, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 7) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Forbid Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Forbid Status: Payload size different than expected") end
end

-- Flight Controller - A2 Commom - 0x10

enums.FLYC_A2_COMMOM_E_DJIA2_CTRL_MODE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x02] = 'c',
    [0x06] = 'd',
    [0x07] = 'e',
    [0x08] = 'f',
    [0x12] = 'g',
}

f.flyc_a2_commom_a = ProtoField.uint8 ("dji_p3.flyc_a2_commom_a", "A", base.HEX)
f.flyc_a2_commom_b = ProtoField.uint8 ("dji_p3.flyc_a2_commom_b", "B", base.HEX)
f.flyc_a2_commom_c = ProtoField.uint32 ("dji_p3.flyc_a2_commom_c", "C", base.HEX)
f.flyc_a2_commom_d = ProtoField.uint32 ("dji_p3.flyc_a2_commom_d", "D", base.HEX)
f.flyc_a2_commom_control_mode = ProtoField.uint8 ("dji_p3.flyc_a2_commom_control_mode", "Control Mode", base.HEX, enums.FLYC_A2_COMMOM_E_DJIA2_CTRL_MODE_ENUM, nil, nil)
f.flyc_a2_commom_f = ProtoField.uint8 ("dji_p3.flyc_a2_commom_f", "F", base.HEX)

local function flyc_a2_commom_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_a2_commom_a, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_a2_commom_b, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_a2_commom_c, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_a2_commom_d, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_a2_commom_control_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_a2_commom_f, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 12) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"A2 Commom: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"A2 Commom: Payload size different than expected") end
end

-- Flight Controller - Flyc Deform Status - 0x32

enums.FLYC_DEFORM_STATUS_DEFORM_STATUS_TRIPOD_STATUS_ENUM = {
    [0x00] = 'UNKNOWN',
    [0x01] = 'FOLD_COMPELTE',
    [0x02] = 'FOLOING',
    [0x03] = 'STRETCH_COMPLETE',
    [0x04] = 'STRETCHING',
    [0x05] = 'STOP_DEFORMATION',
}

enums.FLYC_DEFORM_STATUS_DEFORM_MODE_ENUM = {
    [0x00] = 'Pack',
    [0x01] = 'Protect',
    [0x02] = 'Normal',
    [0x03] = 'OTHER',
}

f.flyc_flyc_deform_status_masked00 = ProtoField.uint8 ("dji_p3.flyc_flyc_deform_status_masked00", "Masked00", base.HEX)
  f.flyc_flyc_deform_status_deform_protected = ProtoField.uint8 ("dji_p3.flyc_flyc_deform_status_deform_protected", "Deform Protected", base.HEX, nil, 0x01, nil)
  f.flyc_flyc_deform_status_deform_status = ProtoField.uint8 ("dji_p3.flyc_flyc_deform_status_deform_status", "Deform Status", base.HEX, enums.FLYC_DEFORM_STATUS_DEFORM_STATUS_TRIPOD_STATUS_ENUM, 0x0e, nil)
  f.flyc_flyc_deform_status_deform_mode = ProtoField.uint8 ("dji_p3.flyc_flyc_deform_status_deform_mode", "Deform Mode", base.HEX, enums.FLYC_DEFORM_STATUS_DEFORM_MODE_ENUM, 0x30, nil)

local function flyc_flyc_deform_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_deform_status_masked00, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_deform_status_deform_protected, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_deform_status_deform_status, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_deform_status_deform_mode, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Deform Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Deform Status: Payload size different than expected") end
end

-- Flight Controller - Flyc Request Limit Update - 0x3e

--f.flyc_flyc_request_limit_update_unknown0 = ProtoField.none ("dji_p3.flyc_flyc_request_limit_update_unknown0", "Unknown0", base.NONE)

local function flyc_flyc_request_limit_update_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Request Limit Update: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Request Limit Update: Payload size different than expected") end
end

-- Flight Controller - Flyc Unlimit State - 0x42

f.flyc_flyc_unlimit_state_is_in_unlimit_area = ProtoField.uint8 ("dji_p3.flyc_flyc_unlimit_state_is_in_unlimit_area", "Is In Unlimit Area", base.HEX)
f.flyc_flyc_unlimit_state_unlimit_areas_action = ProtoField.uint8 ("dji_p3.flyc_flyc_unlimit_state_unlimit_areas_action", "Unlimit Areas Action", base.HEX)
f.flyc_flyc_unlimit_state_unlimit_areas_size = ProtoField.uint8 ("dji_p3.flyc_flyc_unlimit_state_unlimit_areas_size", "Unlimit Areas Size", base.HEX)
f.flyc_flyc_unlimit_state_unlimit_areas_enabled = ProtoField.uint8 ("dji_p3.flyc_flyc_unlimit_state_unlimit_areas_enabled", "Unlimit Areas Enabled", base.HEX)

local function flyc_flyc_unlimit_state_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_unlimit_state_is_in_unlimit_area, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_unlimit_state_unlimit_areas_action, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_unlimit_state_unlimit_areas_size, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_unlimit_state_unlimit_areas_enabled, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Unlimit State: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Unlimit State: Payload size different than expected") end
end

-- Flight Controller - Osd General - 0x43, identical to flight recorder packet 0x000c
-- HD Link - Osd General - 0x01 is a second use of the same packet

enums.FLYC_OSD_GENERAL_FLYC_STATE_ENUM = {
    [0x00] = 'Manual',
    [0x01] = 'Atti',
    [0x02] = 'Atti_CL',
    [0x03] = 'Atti_Hover',
    [0x04] = 'Hover',
    [0x05] = 'GPS_Blake',
    [0x06] = 'GPS_Atti',
    [0x07] = 'GPS_CL',
    [0x08] = 'GPS_HomeLock',
    [0x09] = 'GPS_HotPoint',
    [0x0a] = 'AssitedTakeoff',
    [0x0b] = 'AutoTakeoff',
    [0x0c] = 'AutoLanding',
    [0x0d] = 'AttiLangding',
    [0x0e] = 'NaviGo',
    [0x0f] = 'GoHome',
    [0x10] = 'ClickGo',
    [0x11] = 'Joystick',
    [0x17] = 'Atti_Limited',
    [0x18] = 'GPS_Atti_Limited',
    [0x19] = 'NaviMissionFollow',
    [0x1a] = 'NaviSubMode_Tracking',
    [0x1b] = 'NaviSubMode_Pointing',
    [0x1c] = 'PANO',
    [0x1d] = 'Farming',
    [0x1e] = 'FPV',
    [0x1f] = 'SPORT',
    [0x20] = 'NOVICE',
    [0x21] = 'FORCE_LANDING',
    [0x23] = 'TERRAIN_TRACKING',
    [0x24] = 'NAVI_ADV_GOHOME',
    [0x25] = 'NAVI_ADV_LANDING',
    [0x26] = 'TRIPOD_GPS',
    [0x27] = 'TRACK_HEADLOCK',
    [0x29] = 'ENGINE_START',
    [0x2b] = 'GENTLE_GPS',
    [0x64] = 'OTHER',
}

enums.FLYC_OSD_GENERAL_COMMAND_ENUM = {
    [0x01] = 'AUTO_FLY',
    [0x02] = 'AUTO_LANDING',
    [0x03] = 'HOMEPOINT_NOW',
    [0x04] = 'HOMEPOINT_HOT',
    [0x05] = 'HOMEPOINT_LOC',
    [0x06] = 'GOHOME',
    [0x07] = 'START_MOTOR',
    [0x08] = 'STOP_MOTOR',
    [0x09] = 'Calibration',
    [0x0a] = 'DeformProtecClose',
    [0x0b] = 'DeformProtecOpen',
    [0x0c] = 'DropGohome',
    [0x0d] = 'DropTakeOff',
    [0x0e] = 'DropLanding',
    [0x0f] = 'DynamicHomePointOpen',
    [0x10] = 'DynamicHomePointClose',
    [0x11] = 'FollowFunctioonOpen',
    [0x12] = 'FollowFunctionClose',
    [0x13] = 'IOCOpen',
    [0x14] = 'IOCClose',
    [0x15] = 'DropCalibration',
    [0x16] = 'PackMode',
    [0x17] = 'UnPackMode',
    [0x18] = 'EnterManaualMode',
    [0x19] = 'StopDeform',
    [0x1c] = 'DownDeform',
    [0x1d] = 'UpDeform',
    [0x1e] = 'ForceLanding',
    [0x1f] = 'ForceLanding2',
    [0x64] = 'OTHER',
}

enums.FLYC_OSD_GENERAL_GOHOME_STATE_ENUM = {
    [0x00] = 'STANDBY',
    [0x01] = 'PREASCENDING',
    [0x02] = 'ALIGN',
    [0x03] = 'ASCENDING',
    [0x04] = 'CRUISE',
    [0x05] = 'BRAKING',
    [0x06] = 'BYPASSING',
    [0x07] = 'OTHER',
}

enums.FLYC_OSD_GENERAL_MODE_CHANNEL_RC_MODE_CHANNEL_ENUM = {
    [0x00] = 'CHANNEL_MANUAL',
    [0x01] = 'CHANNEL_A',
    [0x02] = 'CHANNEL_P',
    [0x03] = 'CHANNEL_NAV',
    [0x04] = 'CHANNEL_FPV',
    [0x05] = 'CHANNEL_FARM',
    [0x06] = 'CHANNEL_S',
    [0x07] = 'CHANNEL_F',
    [0xff] = 'CHANNEL_UNKNOWN',
}

enums.FLYC_OSD_GENERAL_BATT_TYPE_ENUM = {
    [0x00] = 'Unknown',
    [0x01] = 'NonSmart',
    [0x02] = 'Smart',
}

enums.FLYC_OSD_GENERAL_GOHOME_REASON_ENUM = {
    [0x00] = 'NONE',
    [0x01] = 'WARNING_POWER_GOHOME',
    [0x02] = 'WARNING_POWER_LANDING',
    [0x03] = 'SMART_POWER_GOHOME',
    [0x04] = 'SMART_POWER_LANDING',
    [0x05] = 'LOW_VOLTAGE_LANDING',
    [0x06] = 'LOW_VOLTAGE_GOHOME',
    [0x07] = 'SERIOUS_LOW_VOLTAGE_LANDING',
    [0x08] = 'RC_ONEKEY_GOHOME',
    [0x09] = 'RC_ASSISTANT_TAKEOFF',
    [0x0a] = 'RC_AUTO_TAKEOFF',
    [0x0b] = 'RC_AUTO_LANDING',
    [0x0c] = 'APP_AUTO_GOHOME',
    [0x0d] = 'APP_AUTO_LANDING',
    [0x0e] = 'APP_AUTO_TAKEOFF',
    [0x0f] = 'OUTOF_CONTROL_GOHOME',
    [0x10] = 'API_AUTO_TAKEOFF',
    [0x11] = 'API_AUTO_LANDING',
    [0x12] = 'API_AUTO_GOHOME',
    [0x13] = 'AVOID_GROUND_LANDING',
    [0x14] = 'AIRPORT_AVOID_LANDING',
    [0x15] = 'TOO_CLOSE_GOHOME_LANDING',
    [0x16] = 'TOO_FAR_GOHOME_LANDING',
    [0x17] = 'APP_WP_MISSION',
    [0x18] = 'WP_AUTO_TAKEOFF',
    [0x19] = 'GOHOME_AVOID',
    [0x1a] = 'GOHOME_FINISH',
    [0x1b] = 'VERT_LOW_LIMIT_LANDING',
    [0x1c] = 'BATTERY_FORCE_LANDING',
    [0x1d] = 'MC_PROTECT_GOHOME',
}

enums.FLYC_OSD_GENERAL_GPS_STATE_ENUM = {
    [0x00] = 'ALREADY',
    [0x01] = 'FORBIN',
    [0x02] = 'GPSNUM_NONENOUGH',
    [0x03] = 'GPS_HDOP_LARGE',
    [0x04] = 'GPS_POSITION_NONMATCH',
    [0x05] = 'SPEED_ERROR_LARGE',
    [0x06] = 'YAW_ERROR_LARGE',
    [0x07] = 'COMPASS_ERROR_LARGE',
    [0x08] = 'UNKNOWN',
}

enums.FLYC_OSD_GENERAL_PRODUCT_TYPE_ENUM = {
    [0x00] = 'Unknown',
    [0x01] = 'Inspire',
    [0x02] = 'P3S/P3X',
    [0x03] = 'P3X',
    [0x04] = 'P3C',
    [0x05] = 'OpenFrame',
    [0x06] = 'ACEONE',
    [0x07] = 'WKM',
    [0x08] = 'NAZA',
    [0x09] = 'A2',
    [0x0a] = 'A3',
    [0x0b] = 'P4',
    [0x0e] = 'PM820',
    [0x0f] = 'P34K',
    [0x10] = 'wm220',
    [0x11] = 'Orange2',
    [0x12] = 'Pomato',
    [0x14] = 'N3',
    [0x17] = 'PM820PRO',
    [0xff] = 'NoFlyc',
    [0x64] = 'None',
}

enums.FLYC_OSD_GENERAL_IMU_INIT_FAIL_RESON_ENUM = {
    [0x00] = 'None/MonitorError',
    [0x01] = 'ColletingData',
    [0x02] = 'GyroDead',
    [0x03] = 'AcceDead',
    [0x04] = 'CompassDead',
    [0x05] = 'BarometerDead',
    [0x06] = 'BarometerNegative',
    [0x07] = 'CompassModTooLarge',
    [0x08] = 'GyroBiasTooLarge',
    [0x09] = 'AcceBiasTooLarge',
    [0x0a] = 'CompassNoiseTooLarge',
    [0x0b] = 'BarometerNoiseTooLarge',
    [0x0c] = 'WaitingMcStationary',
    [0x0d] = 'AcceMoveTooLarge',
    [0x0e] = 'McHeaderMoved',
    [0x0f] = 'McVirbrated',
    [0x64] = 'None',
}

enums.FLYC_OSD_GENERAL_START_FAIL_REASON_ENUM = {
    [0x00] = 'None/Allow start',
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
    [0x5e] = 'Takeoff Exception',
    [0x5f] = 'Esc Stall Near Ground',
    [0x60] = 'Esc Unbalance On Grd',
    [0x61] = 'Esc Part Empty On Grd',
    [0x62] = 'Engine Start Failed',
    [0x63] = 'Auto Takeoff Lanch Failed',
    [0x64] = 'Roll Over On Grd',
    [0x65] = 'Bat Version Error',
    [0x66] = 'RTK Bad Signal',
    [0x67] = 'RTK Deviation Error',
    [0x70] = 'Esc Calibrating',
    [0x71] = 'Gps Sign_invalid',
    [0x72] = 'Gimbal Is Calibrating',
    [0x73] = 'Lock By App',
    [0x74] = 'Start Fly Height Error',
    [0x75] = 'Esc Version Not Match',
    [0x76] = 'Imu Ori Not Match',
    [0x77] = 'Stop By App',
    [0x78] = 'Compass Imu Ori Not Match',
    [0x100]= 'Other',
}

enums.FLYC_OSD_GENERAL_SDK_CTRL_DEVICE_ENUM = {
    [0x00] = 'RC',
    [0x01] = 'APP',
    [0x02] = 'ONBOARD_DEVICE',
    [0x03] = 'CAMERA',
    [0x80] = 'OTHER',
}

f.flyc_osd_general_longtitude = ProtoField.double ("dji_p3.flyc_osd_general_longtitude", "Longtitude", base.DEC)
f.flyc_osd_general_latitude = ProtoField.double ("dji_p3.flyc_osd_general_latitude", "Latitude", base.DEC)
f.flyc_osd_general_relative_height = ProtoField.int16 ("dji_p3.flyc_osd_general_relative_height", "Relative Height", base.DEC, nil, nil, "0.1m, altitude to ground")
f.flyc_osd_general_vgx = ProtoField.int16 ("dji_p3.flyc_osd_general_vgx", "Vgx speed", base.DEC, nil, nil, "0.1m/s, to ground")
f.flyc_osd_general_vgy = ProtoField.int16 ("dji_p3.flyc_osd_general_vgy", "Vgy speed", base.DEC, nil, nil, "0.1m/s, to ground")
f.flyc_osd_general_vgz = ProtoField.int16 ("dji_p3.flyc_osd_general_vgz", "Vgz speed", base.DEC, nil, nil, "0.1m/s, to ground")
f.flyc_osd_general_pitch = ProtoField.int16 ("dji_p3.flyc_osd_general_pitch", "Pitch", base.DEC, nil, nil, "0.1")
f.flyc_osd_general_roll = ProtoField.int16 ("dji_p3.flyc_osd_general_roll", "Roll", base.DEC)
f.flyc_osd_general_yaw = ProtoField.int16 ("dji_p3.flyc_osd_general_yaw", "Yaw", base.DEC)
f.flyc_osd_general_ctrl_info = ProtoField.uint8 ("dji_p3.flyc_osd_general_ctrl_info", "Control Info", base.HEX)
  f.flyc_osd_general_flyc_state = ProtoField.uint8 ("dji_p3.flyc_osd_general_flyc_state", "FC State", base.HEX, enums.FLYC_OSD_GENERAL_FLYC_STATE_ENUM, 0x7F, "Flight Controller state1")
  f.flyc_osd_general_no_rc_state = ProtoField.uint8 ("dji_p3.flyc_osd_general_no_rc_state", "No RC State Received", base.HEX, nil, 0x80, nil)
f.flyc_osd_general_latest_cmd = ProtoField.uint8 ("dji_p3.flyc_osd_general_latest_cmd", "Latest App Cmd", base.HEX, enums.FLYC_OSD_GENERAL_COMMAND_ENUM, nil, "controller exccute lastest cmd")
f.flyc_osd_general_controller_state = ProtoField.uint32 ("dji_p3.flyc_osd_general_controller_state", "Controller State", base.HEX, nil, nil, "Flight Controller state flags")
  f.flyc_osd_general_e_can_ioc_work = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_can_ioc_work", "E Can IOC Work", base.HEX, nil, 0x01, nil)
  f.flyc_osd_general_e_on_ground = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_on_ground", "E On Ground", base.HEX, nil, 0x02, nil)
  f.flyc_osd_general_e_in_air = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_in_air", "E In Air", base.HEX, nil, 0x04, nil)
  f.flyc_osd_general_e_motor_on = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_motor_on", "E Motor On", base.HEX, nil, 0x08, "Force allow start motors ignoring errors")
  f.flyc_osd_general_e_usonic_on = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_usonic_on", "E Usonic On", base.HEX, nil, 0x10, "Ultrasonic wave sonar in use")
  f.flyc_osd_general_e_gohome_state = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_gohome_state", "E Gohome State", base.HEX, enums.FLYC_OSD_GENERAL_GOHOME_STATE_ENUM, 0xe0, nil)
  f.flyc_osd_general_e_mvo_used = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_mvo_used", "E MVO Used", base.HEX, nil, 0x100, "Monocular Visual Odometry is used as horizonal velocity sensor")
  f.flyc_osd_general_e_battery_req_gohome = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_battery_req_gohome", "E Battery Req Gohome", base.HEX, nil, 0x200, nil)
  f.flyc_osd_general_e_battery_req_land = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_battery_req_land", "E Battery Req Land", base.HEX, nil, 0x400, "Landing required due to battery voltage low")
  f.flyc_osd_general_e_still_heating = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_still_heating", "E Still Heating", base.HEX, nil, 0x1000, "IMU Preheating")
  f.flyc_osd_general_e_rc_state = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_rc_state", "E RC Mode Channel", base.HEX, enums.FLYC_OSD_GENERAL_MODE_CHANNEL_RC_MODE_CHANNEL_ENUM, 0x6000, nil)
  f.flyc_osd_general_e_gps_used = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_gps_used", "E GPS Used", base.HEX, nil, 0x8000, "Satellite Positioning System is used as horizonal velocity sensor")
  f.flyc_osd_general_e_compass_over_range = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_compass_over_range", "E Compass Over Range", base.HEX, nil, 0x10000, nil)
  f.flyc_osd_general_e_wave_err = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_wave_err", "E Wave Error", base.HEX, nil, 0x20000, "Ultrasonic sensor error")
  f.flyc_osd_general_e_gps_level = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_gps_level", "E GPS Level", base.HEX, nil, 0x3C0000, "Satellite Positioning System signal level")
  f.flyc_osd_general_e_battery_type = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_battery_type", "E Battery Type", base.HEX, enums.FLYC_OSD_GENERAL_BATT_TYPE_ENUM, 0xC00000, nil)
  f.flyc_osd_general_e_accel_over_range = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_accel_over_range", "E Acceletor Over Range", base.HEX, nil, 0x1000000, nil)
  f.flyc_osd_general_e_is_vibrating = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_is_vibrating", "E Is Vibrating", base.HEX, nil, 0x2000000, nil)
  f.flyc_osd_general_e_press_err = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_press_err", "E Press Err", base.HEX, nil, 0x4000000, "Barometer error")
  f.flyc_osd_general_e_esc_stall = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_esc_stall", "E ESC is stall", base.HEX, nil, 0x8000000, "ESC reports motor blocked")
  f.flyc_osd_general_e_esc_empty = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_esc_empty", "E ESC is empty", base.HEX, nil, 0x10000000, "ESC reports not enough force")
  f.flyc_osd_general_e_propeller_catapult = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_propeller_catapult", "E Propeller Catapult", base.HEX, nil, 0x20000000, nil)
  f.flyc_osd_general_e_gohome_height_mod = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_gohome_height_mod", "E GoHome Height Mod", base.HEX, nil, 0x40000000, "Go Home Height is Modified")
  f.flyc_osd_general_e_out_of_limit = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_out_of_limit", "E Is Out Of Limit", base.HEX, nil, 0x80000000, nil)
f.flyc_osd_general_gps_nums = ProtoField.uint8 ("dji_p3.flyc_osd_general_gps_nums", "Gps Nums", base.DEC, nil, nil, "Number of Global Nav System positioning satellites")
f.flyc_osd_general_gohome_landing_reason = ProtoField.uint8 ("dji_p3.flyc_osd_general_gohome_landing_reason", "Gohome or Landing Reason", base.HEX, enums.FLYC_OSD_GENERAL_GOHOME_REASON_ENUM, nil, "Reason for automatic GoHome or Landing")
f.flyc_osd_general_start_fail_state = ProtoField.uint8 ("dji_p3.flyc_osd_general_start_fail_state", "Motor Start Failure State", base.HEX)
  f.flyc_osd_general_start_fail_reason = ProtoField.uint8 ("dji_p3.flyc_osd_general_start_fail_reason", "Motor Start Fail Reason", base.HEX, enums.FLYC_OSD_GENERAL_START_FAIL_REASON_ENUM, 0x7f, "Reason for failure to start motors")
  f.flyc_osd_common_start_fail_happened = ProtoField.uint8 ("dji_p3.flyc_osd_common_start_fail_happened", "Motor Start Fail Happened", base.HEX, nil, 0x80, nil)
f.flyc_osd_general_controller_state_ext = ProtoField.uint8 ("dji_p3.flyc_osd_general_controller_state_ext", "Controller State Ext", base.HEX)
  f.flyc_osd_general_e_gps_state = ProtoField.uint8 ("dji_p3.flyc_osd_general_e_gps_state", "E Gps State", base.HEX, enums.FLYC_OSD_GENERAL_GPS_STATE_ENUM, 0x0f, "Cause of not being able to switch to GPS mode")
  f.flyc_osd_general_e_wp_limit_md = ProtoField.uint8 ("dji_p3.flyc_osd_general_e_wp_limit_md", "E Wp Limit Mode", base.HEX, nil, 0x10, "Waypoint Limit Mode")
f.flyc_osd_general_batt_remain = ProtoField.uint8 ("dji_p3.flyc_osd_general_batt_remain", "Battery Remain", base.DEC, nil, nil, "Battery Remaining Capacity")
f.flyc_osd_general_ultrasonic_height = ProtoField.uint8 ("dji_p3.flyc_osd_general_ultrasonic_height", "Ultrasonic Height", base.DEC, nil, nil, "Height as reported by ultrasonic wave sensor")
f.flyc_osd_general_motor_startup_time = ProtoField.uint16 ("dji_p3.flyc_osd_general_motor_startup_time", "Motor Started Time", base.DEC, nil, nil, "aka Fly Time")
f.flyc_osd_general_motor_startup_times = ProtoField.uint8 ("dji_p3.flyc_osd_general_motor_startup_times", "Motor Starts Count", base.DEC, nil, nil, "aka Motor Revolution")
f.flyc_osd_general_bat_alarm1 = ProtoField.uint8 ("dji_p3.flyc_osd_general_bat_alarm1", "Bat Alarm1", base.HEX)
  f.flyc_osd_general_bat_alarm1_ve = ProtoField.uint8 ("dji_p3.flyc_osd_general_bat_alarm1_ve", "Alarm Level 1 Voltage", base.DEC, nil, 0x7F)
  f.flyc_osd_general_bat_alarm1_fn = ProtoField.uint8 ("dji_p3.flyc_osd_general_bat_alarm1_fn", "Alarm Level 1 Function", base.DEC, nil, 0x80)
f.flyc_osd_general_bat_alarm2 = ProtoField.uint8 ("dji_p3.flyc_osd_general_bat_alarm2", "Bat Alarm2", base.HEX)
  f.flyc_osd_general_bat_alarm2_ve = ProtoField.uint8 ("dji_p3.flyc_osd_general_bat_alarm2_ve", "Alarm Level 2 Voltage", base.DEC, nil, 0x7F)
  f.flyc_osd_general_bat_alarm2_fn = ProtoField.uint8 ("dji_p3.flyc_osd_general_bat_alarm2_fn", "Alarm Level 2 Function", base.DEC, nil, 0x80)
f.flyc_osd_general_version_match = ProtoField.uint8 ("dji_p3.flyc_osd_general_version_match", "Version Match", base.HEX, nil, nil, "Flight Controller version")
f.flyc_osd_general_product_type = ProtoField.uint8 ("dji_p3.flyc_osd_general_product_type", "Product Type", base.HEX, enums.FLYC_OSD_GENERAL_PRODUCT_TYPE_ENUM)
f.flyc_osd_general_imu_init_fail_reson = ProtoField.int8 ("dji_p3.flyc_osd_general_imu_init_fail_reson", "IMU init Fail Reason", base.DEC, enums.FLYC_OSD_GENERAL_IMU_INIT_FAIL_RESON_ENUM)
-- Non existing in P3 packets - next gen only?
--f.flyc_osd_common_motor_fail_reason = ProtoField.uint8 ("dji_p3.flyc_osd_common_motor_fail_reason", "Motor Fail Reason", base.HEX, enums.FLYC_OSD_GENERAL_START_FAIL_REASON_ENUM, nil, nil)
--f.flyc_osd_common_motor_start_cause_no_start_action = ProtoField.uint8 ("dji_p3.flyc_osd_common_motor_start_cause_no_start_action", "Motor Start Cause No Start Action", base.HEX, enums.FLYC_OSD_GENERAL_START_FAIL_REASON_ENUM)
--f.flyc_osd_common_sdk_ctrl_device = ProtoField.uint8 ("dji_p3.flyc_osd_common_sdk_ctrl_device", "Sdk Ctrl Device", base.HEX, enums.FLYC_OSD_GENERAL_SDK_CTRL_DEVICE_ENUM, nil, nil)

local function flyc_osd_general_dissector(pkt_length, buffer, pinfo, subtree)
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

    subtree:add_le (f.flyc_osd_general_ctrl_info, payload(offset, 1))
    subtree:add_le (f.flyc_osd_general_flyc_state, payload(offset, 1))
    subtree:add_le (f.flyc_osd_general_no_rc_state, payload(offset, 1))
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

    subtree:add_le (f.flyc_osd_general_start_fail_state, payload(offset, 1))
    subtree:add_le (f.flyc_osd_general_start_fail_reason, payload(offset, 1))
    subtree:add_le (f.flyc_osd_common_start_fail_happened, payload(offset, 1))
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
-- HD Link - Osd Home - 0x02  is a second use of the same packet

enums.FLYC_OSD_HOME_IOC_MODE_ENUM = {
    [0x01] = 'CourseLock',
    [0x02] = 'HomeLock',
    [0x03] = 'HotspotSurround',
    [0x64] = 'OTHER',
}

enums.FLYC_OSD_HOME_HEIGHT_LIMIT_STATUS_ENUM = {
    [0x00] = 'NON_LIMIT',
    [0x01] = 'NON_GPS',
    [0x02] = 'ORIENTATION_NEED_CALI',
    [0x03] = 'ORIENTATION_GO',
    [0x04] = 'AVOID_GROUND',
    [0x05] = 'NORMAL_LIMIT',
}

f.flyc_osd_home_osd_lon = ProtoField.double ("dji_p3.flyc_osd_home_osd_lon", "OSD Longitude", base.DEC) -- home point coords?
f.flyc_osd_home_osd_lat = ProtoField.double ("dji_p3.flyc_osd_home_osd_lat", "OSD Latitude", base.DEC) -- home point coords?
f.flyc_osd_home_osd_alt = ProtoField.float ("dji_p3.flyc_osd_home_osd_alt", "OSD Altitude", base.DEC, nil, nil, "0.1m, altitude")
f.flyc_osd_home_osd_home_state = ProtoField.uint16 ("dji_p3.flyc_osd_home_osd_home_state", "OSD Home State", base.HEX)
  f.flyc_osd_home_e_homepoint_set = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_homepoint_set", "E Homepoint Set", base.HEX, nil, 0x01, "Is Home Point Recorded")
  f.flyc_osd_home_e_go_home_mode = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_go_home_mode", "E Go Home Mode", base.HEX, nil, 0x02, nil)
  f.flyc_osd_home_e_heading = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_heading", "E Heading", base.HEX, nil, 0x04, "Aircraft Head Direction")
  f.flyc_osd_home_e_is_dyn_homepoint = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_is_dyn_homepoint", "E Is Dyn Homepoint", base.HEX, nil, 0x08, "Dynamic Home Piont Enable")
  f.flyc_osd_home_e_reach_limit_distance = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_reach_limit_distance", "E Reach Limit Distance", base.HEX, nil, 0x10, nil)
  f.flyc_osd_home_e_reach_limit_height = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_reach_limit_height", "E Reach Limit Height", base.HEX, nil, 0x20, nil)
  f.flyc_osd_home_e_multiple_mode_open = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_multiple_mode_open", "E Multiple Mode Open", base.HEX, nil, 0x40, nil)
  f.flyc_osd_home_e_has_go_home = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_has_go_home", "E Has Go Home", base.HEX, nil, 0x80, nil)
  f.flyc_osd_home_e_compass_cele_status = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_compass_cele_status", "E Compass Cele Status", base.HEX, nil, 0x300, nil)
  f.flyc_osd_home_e_compass_celeing = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_compass_celeing", "E Compass Celeing", base.HEX, nil, 0x400, nil)
  f.flyc_osd_home_e_beginner_mode = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_beginner_mode", "E Beginner Mode", base.HEX, nil, 0x800, nil)
  f.flyc_osd_home_e_ioc_enable = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_ioc_enable", "E Ioc Enable", base.HEX, nil, 0x1000, nil)
  f.flyc_osd_home_e_ioc_mode = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_ioc_mode", "E Ioc Mode", base.HEX, enums.FLYC_OSD_HOME_IOC_MODE_ENUM, 0xe000, nil)
f.flyc_osd_home_go_home_height = ProtoField.uint16 ("dji_p3.flyc_osd_home_go_home_height", "Go Home Height", base.DEC, nil, nil, "aka Fixed Altitude")
f.flyc_osd_home_course_lock_angle = ProtoField.uint16 ("dji_p3.flyc_osd_home_course_lock_angle", "Course Lock Angle", base.DEC, nil, nil, "Course Lock Torsion")
f.flyc_osd_home_data_recorder_status = ProtoField.uint8 ("dji_p3.flyc_osd_home_data_recorder_status", "Data Recorder Status", base.HEX)
f.flyc_osd_home_data_recorder_remain_capacity = ProtoField.uint8 ("dji_p3.flyc_osd_home_data_recorder_remain_capacity", "Data Recorder Remain Capacity", base.HEX)
f.flyc_osd_home_data_recorder_remain_time = ProtoField.uint16 ("dji_p3.flyc_osd_home_data_recorder_remain_time", "Data Recorder Remain Time", base.HEX)
f.flyc_osd_home_cur_data_recorder_file_index = ProtoField.uint16 ("dji_p3.flyc_osd_home_cur_data_recorder_file_index", "Cur Data Recorder File Index", base.HEX)
-- Version of the packet from newer firmwares, 34 bytes long
f.flyc_osd_home_ver1_masked20 = ProtoField.uint16 ("dji_p3.flyc_osd_home_ver1_masked20", "Masked20", base.HEX)
  f.flyc_osd_home_ver1_flyc_in_simulation_mode = ProtoField.uint16 ("dji_p3.flyc_osd_home_ver1_flyc_in_simulation_mode", "Flyc In Simulation Mode", base.HEX, nil, 0x01, nil)
  f.flyc_osd_home_ver1_flyc_in_navigation_mode = ProtoField.uint16 ("dji_p3.flyc_osd_home_ver1_flyc_in_navigation_mode", "Flyc In Navigation Mode", base.HEX, nil, 0x02, nil)
-- Version of the packet from older firmwares, 68 bytes long
f.flyc_osd_home_masked20 = ProtoField.uint32 ("dji_p3.flyc_osd_home_masked20", "Masked20", base.HEX)
  f.flyc_osd_home_flyc_in_simulation_mode = ProtoField.uint32 ("dji_p3.flyc_osd_home_flyc_in_simulation_mode", "Flyc In Simulation Mode", base.HEX, nil, 0x01, nil)
  f.flyc_osd_home_flyc_in_navigation_mode = ProtoField.uint32 ("dji_p3.flyc_osd_home_flyc_in_navigation_mode", "Flyc In Navigation Mode", base.HEX, nil, 0x02, nil)
  f.flyc_osd_home_wing_broken = ProtoField.uint32 ("dji_p3.flyc_osd_home_wing_broken", "Wing Broken", base.HEX, nil, 0x1000, nil)
  f.flyc_osd_home_big_gale = ProtoField.uint32 ("dji_p3.flyc_osd_home_big_gale", "Big Gale", base.HEX, nil, 0x4000, nil)
  f.flyc_osd_home_big_gale_warning = ProtoField.uint32 ("dji_p3.flyc_osd_home_big_gale_warning", "Big Gale Warning", base.HEX, nil, 0x100000, nil)
  f.flyc_osd_home_compass_install_err = ProtoField.uint32 ("dji_p3.flyc_osd_home_compass_install_err", "Compass Install Err", base.HEX, nil, 0x800000, nil)
  f.flyc_osd_home_height_limit_status = ProtoField.uint32 ("dji_p3.flyc_osd_home_height_limit_status", "Height Limit Status", base.HEX, enums.FLYC_OSD_HOME_HEIGHT_LIMIT_STATUS_ENUM, 0x1f000000, nil)
  f.flyc_osd_home_use_absolute_height = ProtoField.uint32 ("dji_p3.flyc_osd_home_use_absolute_height", "Use Absolute Height", base.HEX, nil, 0x20000000, nil)
f.flyc_osd_home_height_limit_value = ProtoField.float ("dji_p3.flyc_osd_home_height_limit_value", "Height Limit Value", base.DEC)
f.flyc_osd_home_unknown28 = ProtoField.bytes ("dji_p3.flyc_osd_home_unknown28", "Unknown28", base.SPACE)
f.flyc_osd_home_force_landing_height = ProtoField.uint8 ("dji_p3.flyc_osd_home_force_landing_height", "Force Landing Height", base.DEC)
f.flyc_osd_home_unknown2E = ProtoField.bytes ("dji_p3.flyc_osd_home_unknown2E", "Unknown2E", base.SPACE)

local function flyc_osd_home_dissector(pkt_length, buffer, pinfo, subtree)
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
    subtree:add_le (f.flyc_osd_home_e_go_home_mode, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_e_heading, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_e_is_dyn_homepoint, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_e_reach_limit_distance, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_e_reach_limit_height, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_e_multiple_mode_open, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_e_has_go_home, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_e_compass_cele_status, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_e_compass_celeing, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_e_beginner_mode, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_e_ioc_enable, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_e_ioc_mode, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_home_go_home_height, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_home_course_lock_angle, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_home_data_recorder_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_home_data_recorder_remain_capacity, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_home_data_recorder_remain_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_home_cur_data_recorder_file_index, payload(offset, 2))
    offset = offset + 2

    -- Before firmware P3X_FW_V01.07.0060, the packet was 68 bytes long
    if (payload:len() < 68) then

        subtree:add_le (f.flyc_osd_home_ver1_masked20, payload(offset, 2))
        subtree:add_le (f.flyc_osd_home_ver1_flyc_in_simulation_mode, payload(offset, 2))
        subtree:add_le (f.flyc_osd_home_ver1_flyc_in_navigation_mode, payload(offset, 2))
        offset = offset + 2

        if (offset ~= 34) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Home: Offset does not match - internal inconsistency") end

    else

        subtree:add_le (f.flyc_osd_home_masked20, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_flyc_in_simulation_mode, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_flyc_in_navigation_mode, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_wing_broken, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_big_gale, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_big_gale_warning, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_compass_install_err, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_height_limit_status, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_use_absolute_height, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.flyc_osd_home_height_limit_value, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.flyc_osd_home_unknown28, payload(offset, 5))
        offset = offset + 5

        subtree:add_le (f.flyc_osd_home_force_landing_height, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_osd_home_unknown2E, payload(offset, 22))
        offset = offset + 22

        if (offset ~= 68) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Home: Offset does not match - internal inconsistency") end

    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Home: Payload size different than expected") end
end

-- Flight Controller - Flyc Gps Snr - 0x45

--f.flyc_flyc_gps_snr_unknown0 = ProtoField.none ("dji_p3.flyc_flyc_gps_snr_unknown0", "Unknown0", base.NONE)

local function flyc_flyc_gps_snr_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Gps Snr: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Gps Snr: Payload size different than expected") end
end

-- Flight Controller - Imu Data Status - 0x50, identical to flight recorder packet 0x0013

f.flyc_imu_data_status_start_fan = ProtoField.uint8 ("dji_p3.flyc_imu_data_status_start_fan", "Start Fan", base.HEX, nil, nil, "On P3, always 1")
f.flyc_imu_data_status_led_status = ProtoField.uint8 ("dji_p3.flyc_imu_data_status_led_status", "Led Status", base.HEX, nil, nil, "On P3, always 0")

local function flyc_imu_data_status_dissector(pkt_length, buffer, pinfo, subtree)
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

-- Flight Controller - Flyc Smart Battery - 0x51

enums.FLYC_SMART_BATTERY_GO_HOME_STATUS_SMART_GO_HOME_STATUS_ENUM = {
    [0x00] = 'NON_GOHOME',
    [0x01] = 'GOHOME',
    [0x02] = 'GOHOME_ALREADY',
}

f.flyc_flyc_smart_battery_useful_time = ProtoField.uint16 ("dji_p3.flyc_flyc_smart_battery_useful_time", "Useful Time", base.DEC)
f.flyc_flyc_smart_battery_go_home_time = ProtoField.uint16 ("dji_p3.flyc_flyc_smart_battery_go_home_time", "Go Home Time", base.DEC)
f.flyc_flyc_smart_battery_land_time = ProtoField.uint16 ("dji_p3.flyc_flyc_smart_battery_land_time", "Land Time", base.DEC)
f.flyc_flyc_smart_battery_go_home_battery = ProtoField.uint16 ("dji_p3.flyc_flyc_smart_battery_go_home_battery", "Go Home Battery", base.DEC)
f.flyc_flyc_smart_battery_land_battery = ProtoField.uint16 ("dji_p3.flyc_flyc_smart_battery_land_battery", "Land Battery", base.DEC)
f.flyc_flyc_smart_battery_safe_fly_radius = ProtoField.float ("dji_p3.flyc_flyc_smart_battery_safe_fly_radius", "Safe Fly Radius", base.DEC)
f.flyc_flyc_smart_battery_volume_comsume = ProtoField.float ("dji_p3.flyc_flyc_smart_battery_volume_comsume", "Volume Comsume", base.DEC)
f.flyc_flyc_smart_battery_status = ProtoField.uint32 ("dji_p3.flyc_flyc_smart_battery_status", "Status", base.HEX)
f.flyc_flyc_smart_battery_go_home_status = ProtoField.uint8 ("dji_p3.flyc_flyc_smart_battery_go_home_status", "Go Home Status", base.HEX, enums.FLYC_SMART_BATTERY_GO_HOME_STATUS_SMART_GO_HOME_STATUS_ENUM, nil, nil)
f.flyc_flyc_smart_battery_go_home_count_down = ProtoField.uint8 ("dji_p3.flyc_flyc_smart_battery_go_home_count_down", "Go Home Count Down", base.HEX)
f.flyc_flyc_smart_battery_voltage = ProtoField.uint16 ("dji_p3.flyc_flyc_smart_battery_voltage", "Voltage", base.DEC)
f.flyc_flyc_smart_battery_battery_percent = ProtoField.uint8 ("dji_p3.flyc_flyc_smart_battery_battery_percent", "Battery Percent", base.DEC)
f.flyc_flyc_smart_battery_masked1b = ProtoField.uint8 ("dji_p3.flyc_flyc_smart_battery_masked1b", "Masked1B", base.HEX)
  f.flyc_flyc_smart_battery_low_warning = ProtoField.uint8 ("dji_p3.flyc_flyc_smart_battery_low_warning", "Low Warning", base.HEX, nil, 0x7f, nil)
  f.flyc_flyc_smart_battery_low_warning_go_home = ProtoField.uint8 ("dji_p3.flyc_flyc_smart_battery_low_warning_go_home", "Low Warning Go Home", base.HEX, nil, 0x80, nil)
f.flyc_flyc_smart_battery_masked1c = ProtoField.uint8 ("dji_p3.flyc_flyc_smart_battery_masked1c", "Masked1C", base.HEX)
  f.flyc_flyc_smart_battery_serious_low_warning = ProtoField.uint8 ("dji_p3.flyc_flyc_smart_battery_serious_low_warning", "Serious Low Warning", base.HEX, nil, 0x7f, nil)
  f.flyc_flyc_smart_battery_serious_low_warning_landing = ProtoField.uint8 ("dji_p3.flyc_flyc_smart_battery_serious_low_warning_landing", "Serious Low Warning Landing", base.HEX, nil, 0x80, nil)
f.flyc_flyc_smart_battery_voltage_percent = ProtoField.uint8 ("dji_p3.flyc_flyc_smart_battery_voltage_percent", "Voltage Percent", base.DEC)

local function flyc_flyc_smart_battery_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_smart_battery_useful_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_flyc_smart_battery_go_home_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_flyc_smart_battery_land_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_flyc_smart_battery_go_home_battery, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_flyc_smart_battery_land_battery, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_flyc_smart_battery_safe_fly_radius, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_flyc_smart_battery_volume_comsume, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_flyc_smart_battery_status, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_flyc_smart_battery_go_home_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_smart_battery_go_home_count_down, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_smart_battery_voltage, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_flyc_smart_battery_battery_percent, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_smart_battery_masked1b, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_smart_battery_low_warning, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_smart_battery_low_warning_go_home, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_smart_battery_masked1c, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_smart_battery_serious_low_warning, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_smart_battery_serious_low_warning_landing, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_smart_battery_voltage_percent, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 30) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Smart Battery: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Smart Battery: Payload size different than expected") end
end

-- Flight Controller - Flyc Avoid Param - 0x53

f.flyc_flyc_avoid_param_masked00 = ProtoField.uint16 ("dji_p3.flyc_flyc_avoid_param_masked00", "Masked00", base.HEX)
  f.flyc_flyc_avoid_param_avoid_obstacle_enable = ProtoField.uint16 ("dji_p3.flyc_flyc_avoid_param_avoid_obstacle_enable", "Avoid Obstacle Enable", base.HEX, nil, 0x01, nil)
  f.flyc_flyc_avoid_param_user_avoid_enable = ProtoField.uint16 ("dji_p3.flyc_flyc_avoid_param_user_avoid_enable", "User Avoid Enable", base.HEX, nil, 0x02, nil)
  f.flyc_flyc_avoid_param_get_avoid_obstacle_work_flag = ProtoField.uint16 ("dji_p3.flyc_flyc_avoid_param_get_avoid_obstacle_work_flag", "Get Avoid Obstacle Work Flag", base.HEX, nil, 0x04, nil)
  f.flyc_flyc_avoid_param_get_emergency_brake_work_flag = ProtoField.uint16 ("dji_p3.flyc_flyc_avoid_param_get_emergency_brake_work_flag", "Get Emergency Brake Work Flag", base.HEX, nil, 0x08, nil)
  f.flyc_flyc_avoid_param_gohome_avoid_enable = ProtoField.uint16 ("dji_p3.flyc_flyc_avoid_param_gohome_avoid_enable", "Gohome Avoid Enable", base.HEX, nil, 0x10, nil)
  f.flyc_flyc_avoid_param_avoid_ground_force_landing = ProtoField.uint16 ("dji_p3.flyc_flyc_avoid_param_avoid_ground_force_landing", "Avoid Ground Force Landing", base.HEX, nil, 0x20, nil)
  f.flyc_flyc_avoid_param_radius_limit_working = ProtoField.uint16 ("dji_p3.flyc_flyc_avoid_param_radius_limit_working", "Radius Limit Working", base.HEX, nil, 0x40, nil)
  f.flyc_flyc_avoid_param_airport_limit_working = ProtoField.uint16 ("dji_p3.flyc_flyc_avoid_param_airport_limit_working", "Airport Limit Working", base.HEX, nil, 0x80, nil)
  f.flyc_flyc_avoid_param_avoid_obstacle_working = ProtoField.uint16 ("dji_p3.flyc_flyc_avoid_param_avoid_obstacle_working", "Avoid Obstacle Working", base.HEX, nil, 0x100, nil)
  f.flyc_flyc_avoid_param_horiz_near_boundary = ProtoField.uint16 ("dji_p3.flyc_flyc_avoid_param_horiz_near_boundary", "Horiz Near Boundary", base.HEX, nil, 0x200, nil)
  f.flyc_flyc_avoid_param_avoid_overshot_act = ProtoField.uint16 ("dji_p3.flyc_flyc_avoid_param_avoid_overshot_act", "Avoid Overshot Act", base.HEX, nil, 0x400, nil)
  f.flyc_flyc_avoid_param_vert_low_limit_work_flag = ProtoField.uint16 ("dji_p3.flyc_flyc_avoid_param_vert_low_limit_work_flag", "Vert Low Limit Work Flag", base.HEX, nil, 0x800, nil)

local function flyc_flyc_avoid_param_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_avoid_param_masked00, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_avoid_param_avoid_obstacle_enable, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_avoid_param_user_avoid_enable, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_avoid_param_get_avoid_obstacle_work_flag, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_avoid_param_get_emergency_brake_work_flag, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_avoid_param_gohome_avoid_enable, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_avoid_param_avoid_ground_force_landing, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_avoid_param_radius_limit_working, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_avoid_param_airport_limit_working, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_avoid_param_avoid_obstacle_working, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_avoid_param_horiz_near_boundary, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_avoid_param_avoid_overshot_act, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_avoid_param_vert_low_limit_work_flag, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Avoid Param: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Avoid Param: Payload size different than expected") end
end

-- Flight Controller - Flyc Limit State - 0x55

f.flyc_flyc_limit_state_latitude = ProtoField.double ("dji_p3.flyc_flyc_limit_state_latitude", "Latitude", base.DEC)
f.flyc_flyc_limit_state_longitude = ProtoField.double ("dji_p3.flyc_flyc_limit_state_longitude", "Longitude", base.DEC)
f.flyc_flyc_limit_state_inner_radius = ProtoField.uint16 ("dji_p3.flyc_flyc_limit_state_inner_radius", "Inner Radius", base.HEX)
f.flyc_flyc_limit_state_outer_radius = ProtoField.uint16 ("dji_p3.flyc_flyc_limit_state_outer_radius", "Outer Radius", base.HEX)
f.flyc_flyc_limit_state_type = ProtoField.uint8 ("dji_p3.flyc_flyc_limit_state_type", "Type", base.HEX)
f.flyc_flyc_limit_state_area_state = ProtoField.uint8 ("dji_p3.flyc_flyc_limit_state_area_state", "Area State", base.HEX)
f.flyc_flyc_limit_state_action_state = ProtoField.uint8 ("dji_p3.flyc_flyc_limit_state_action_state", "Action State", base.HEX)
f.flyc_flyc_limit_state_enable = ProtoField.uint8 ("dji_p3.flyc_flyc_limit_state_enable", "Enable", base.HEX)

local function flyc_flyc_limit_state_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_limit_state_latitude, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.flyc_flyc_limit_state_longitude, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.flyc_flyc_limit_state_inner_radius, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_flyc_limit_state_outer_radius, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_flyc_limit_state_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_limit_state_area_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_limit_state_action_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_limit_state_enable, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 24) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Limit State: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Limit State: Payload size different than expected") end
end

-- Flight Controller - Flyc Led Status - 0x56

enums.FLYC_LED_STATUS_LED_REASON_ENUM = {
    [0x00] = 'SET_HOME',
    [0x01] = 'SET_HOT_POINT',
    [0x02] = 'SET_COURSE_LOCK',
    [0x03] = 'TEST_LED',
    [0x04] = 'USB_IS_VALID',
    [0x05] = 'PACKING_FAIL',
    [0x06] = 'PACKING_NORMAL',
    [0x07] = 'NO_ATTI',
    [0x08] = 'COMPASS_CALI_STEP0',
    [0x09] = 'COMPASS_CALI_STEP1',
    [0x0a] = 'COMPASS_CALI_ERROR',
    [0x0b] = 'SENSOR_TEMP_NOT_READY',
    [0x0c] = 'IMU_OR_GYRO_LOST',
    [0x0d] = 'IMU_BAD_ATTI',
    [0x0e] = 'SYSTEM_ERROR',
    [0x0f] = 'IMU_ERROR',
    [0x10] = 'IMU_NEED_CALI',
    [0x11] = 'COMPASS_OUT_RANGE',
    [0x12] = 'RC_COMPLETELY_LOST',
    [0x13] = 'BATTERY_WARNING',
    [0x14] = 'BATTERY_ERROR',
    [0x15] = 'IMU_WARNING',
    [0x16] = 'SET_FLY_LIMIT',
    [0x17] = 'NORMAL_LED',
    [0x18] = 'FDI_VIBRATE',
    [0x19] = 'CODE_ERROR',
    [0x1a] = 'SYSTEM_RECONSTRUCTION',
    [0x1b] = 'RECORDER_ERROR',
}

f.flyc_flyc_led_status_led_reason = ProtoField.uint32 ("dji_p3.flyc_flyc_led_status_led_reason", "Led Reason", base.HEX, enums.FLYC_LED_STATUS_LED_REASON_ENUM, nil, nil)

local function flyc_flyc_led_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_led_status_led_reason, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Led Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Led Status: Payload size different than expected") end
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

local function flyc_gps_glns_dissector(pkt_length, buffer, pinfo, subtree)
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

-- Flight Controller - Flyc Active Request - 0x61

f.flyc_flyc_active_request_app_id = ProtoField.uint32 ("dji_p3.flyc_flyc_active_request_app_id", "App Id", base.HEX)
f.flyc_flyc_active_request_app_level = ProtoField.uint32 ("dji_p3.flyc_flyc_active_request_app_level", "App Level", base.HEX)
f.flyc_flyc_active_request_app_version = ProtoField.uint32 ("dji_p3.flyc_flyc_active_request_app_version", "App Version", base.HEX)

local function flyc_flyc_active_request_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_active_request_app_id, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_flyc_active_request_app_level, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_flyc_active_request_app_version, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 12) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Active Request: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Active Request: Payload size different than expected") end
end

-- Flight Controller - Flyc Board Recv - 0x63

--f.flyc_flyc_board_recv_unknown0 = ProtoField.none ("dji_p3.flyc_flyc_board_recv_unknown0", "Unknown0", base.NONE)

local function flyc_flyc_board_recv_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Board Recv: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Board Recv: Payload size different than expected") end
end

-- Flight Controller - Flyc Power Param - 0x67

f.flyc_flyc_power_param_esc_average_speed = ProtoField.float ("dji_p3.flyc_flyc_power_param_esc_average_speed", "Esc Average Speed", base.DEC)
f.flyc_flyc_power_param_lift = ProtoField.float ("dji_p3.flyc_flyc_power_param_lift", "Lift", base.DEC)

local function flyc_flyc_power_param_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_power_param_esc_average_speed, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_flyc_power_param_lift, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Power Param: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Power Param: Payload size different than expected") end
end

-- Flight Controller - Flyc Avoid - 0x6a

f.flyc_flyc_avoid_masked00 = ProtoField.uint8 ("dji_p3.flyc_flyc_avoid_masked00", "Masked00", base.HEX)
  f.flyc_flyc_avoid_visual_sensor_enable = ProtoField.uint8 ("dji_p3.flyc_flyc_avoid_visual_sensor_enable", "Visual Sensor Enable", base.HEX, nil, 0x01, nil)
  f.flyc_flyc_avoid_visual_sensor_work = ProtoField.uint8 ("dji_p3.flyc_flyc_avoid_visual_sensor_work", "Visual Sensor Work", base.HEX, nil, 0x02, nil)
  f.flyc_flyc_avoid_in_stop = ProtoField.uint8 ("dji_p3.flyc_flyc_avoid_in_stop", "In Stop", base.HEX, nil, 0x04, nil)

local function flyc_flyc_avoid_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_avoid_masked00, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_avoid_visual_sensor_enable, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_avoid_visual_sensor_work, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_avoid_in_stop, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Avoid: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Avoid: Payload size different than expected") end
end

-- Flight Controller - Flyc Rtk Location Data - 0x6c

f.flyc_flyc_rtk_location_data_longitude = ProtoField.double ("dji_p3.flyc_flyc_rtk_location_data_longitude", "Longitude", base.DEC)
f.flyc_flyc_rtk_location_data_latitude = ProtoField.double ("dji_p3.flyc_flyc_rtk_location_data_latitude", "Latitude", base.DEC)
f.flyc_flyc_rtk_location_data_height = ProtoField.float ("dji_p3.flyc_flyc_rtk_location_data_height", "Height", base.DEC)
f.flyc_flyc_rtk_location_data_heading = ProtoField.uint16 ("dji_p3.flyc_flyc_rtk_location_data_heading", "Heading", base.HEX)
f.flyc_flyc_rtk_location_data_rtk_connected = ProtoField.uint8 ("dji_p3.flyc_flyc_rtk_location_data_rtk_connected", "Rtk Connected", base.HEX)
f.flyc_flyc_rtk_location_data_rtk_canbe_used = ProtoField.uint8 ("dji_p3.flyc_flyc_rtk_location_data_rtk_canbe_used", "Rtk Canbe Used", base.HEX)

local function flyc_flyc_rtk_location_data_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_rtk_location_data_longitude, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.flyc_flyc_rtk_location_data_latitude, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.flyc_flyc_rtk_location_data_height, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_flyc_rtk_location_data_heading, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_flyc_rtk_location_data_rtk_connected, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_rtk_location_data_rtk_canbe_used, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 24) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Rtk Location Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Rtk Location Data: Payload size different than expected") end
end

-- Flight Controller - Flyc Way Point Mission Info - 0x88

enums.FLYC_WAY_POINT_MISSION_INFO_MISSION_TYPE_ENUM = {
    [0x01] = 'Way Point',
    [0x02] = 'Hot Point',
    [0x03] = 'Follow Me',
    [0x04] = 'Course Lock/Home Lock',
    [0x05] = 'TBD',
}

enums.FLYC_WAY_POINT_MISSION_INFO_RUNNING_STATUS_ENUM = {
    [0x00] = 'NotRunning',
    [0x01] = 'Running',
    [0x02] = 'Paused',
}

f.flyc_flyc_way_point_mission_info_mission_type = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_info_mission_type", "Mission Type", base.HEX, enums.FLYC_WAY_POINT_MISSION_INFO_MISSION_TYPE_ENUM)
-- Way Point mission (unverified)
f.flyc_flyc_way_point_mission_info_target_way_point = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_info_target_way_point", "Target Way Point", base.DEC)
f.flyc_flyc_way_point_mission_info_limited_height = ProtoField.uint16 ("dji_p3.flyc_flyc_way_point_mission_info_limited_height", "Limited Height", base.HEX)
f.flyc_flyc_way_point_mission_info_running_status = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_info_running_status", "Way Point Running Status", base.HEX, enums.FLYC_WAY_POINT_MISSION_INFO_RUNNING_STATUS_ENUM)
f.flyc_flyc_way_point_mission_info_wp_unknown5 = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_info_wp_unknown5", "Way Point Unknown5", base.HEX)
-- Hot Point mission
f.flyc_flyc_way_point_mission_info_hot_point_mission_status = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_info_hot_point_mission_status", "Hot Point Mission Status", base.HEX)
f.flyc_flyc_way_point_mission_info_hot_point_radius = ProtoField.uint16 ("dji_p3.flyc_flyc_way_point_mission_info_hot_point_radius", "Hot Point Radius", base.DEC)
f.flyc_flyc_way_point_mission_info_hot_point_reason = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_info_hot_point_reason", "Hot Point Reason", base.HEX)
f.flyc_flyc_way_point_mission_info_hot_point_speed = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_info_hot_point_speed", "Hot Point Speed", base.DEC)
-- Follow Me mission
f.flyc_flyc_way_point_mission_info_follow_me_flags = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_info_follow_me_flags", "Follow Me Flags", base.HEX)
  f.flyc_flyc_way_point_mission_info_follow_me_status = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_info_follow_me_status", "Follow Me Status", base.HEX, nil, 0x0f, nil)
  f.flyc_flyc_way_point_mission_info_follow_me_gps_level = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_info_follow_me_gps_level", "Follow Me Gps Level", base.HEX, nil, 0xf0, nil)
f.flyc_flyc_way_point_mission_info_follow_me_distance = ProtoField.uint16 ("dji_p3.flyc_flyc_way_point_mission_info_follow_me_distance", "Follow Me Distance", base.Dec)
f.flyc_flyc_way_point_mission_info_follow_me_reason = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_info_follow_me_reason", "Follow Me Reason", base.HEX)
f.flyc_flyc_way_point_mission_info_follow_me_unknown6 = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_info_follow_me_unknown6", "Follow Me Unknown6", base.HEX)
-- Any other mission (unverified)
f.flyc_flyc_way_point_mission_info_mission_flags = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_info_mission_flags", "Mission Flags", base.HEX)
  f.flyc_flyc_way_point_mission_info_mission_status = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_info_mission_status", "Mission Status", base.HEX, nil, 0x03, nil)
  f.flyc_flyc_way_point_mission_info_position_valid = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_info_position_valid", "Position Valid", base.HEX, nil, 0x04, nil)
f.flyc_flyc_way_point_mission_info_current_status = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_info_current_status", "Current Status", base.HEX)
f.flyc_flyc_way_point_mission_info_error_notification = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_info_error_notification", "Error Notification", base.HEX)
f.flyc_flyc_way_point_mission_info_current_height = ProtoField.uint16 ("dji_p3.flyc_flyc_way_point_mission_info_current_height", "Current Height", base.HEX)
-- All types
f.flyc_flyc_way_point_mission_info_is_tracking_enabled = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_info_is_tracking_enabled", "Is Tracking Enabled", base.HEX)

local function flyc_flyc_way_point_mission_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    local mission_type = buffer(offset,1):le_uint()
    subtree:add_le (f.flyc_flyc_way_point_mission_info_mission_type, payload(offset, 1))
    offset = offset + 1

    if (mission_type == 0x01) then

        subtree:add_le (f.flyc_flyc_way_point_mission_info_target_way_point, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_flyc_way_point_mission_info_limited_height, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.flyc_flyc_way_point_mission_info_running_status, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_flyc_way_point_mission_info_wp_unknown5, payload(offset, 1))
        offset = offset + 1

    elseif (mission_type == 0x02) then

        subtree:add_le (f.flyc_flyc_way_point_mission_info_hot_point_mission_status, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_flyc_way_point_mission_info_hot_point_radius, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.flyc_flyc_way_point_mission_info_hot_point_reason, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_flyc_way_point_mission_info_hot_point_speed, payload(offset, 1))
        offset = offset + 1

    elseif (mission_type == 0x03) then

        subtree:add_le (f.flyc_flyc_way_point_mission_info_follow_me_flags, payload(offset, 1))
        subtree:add_le (f.flyc_flyc_way_point_mission_info_follow_me_status, payload(offset, 1))
        subtree:add_le (f.flyc_flyc_way_point_mission_info_follow_me_gps_level, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_flyc_way_point_mission_info_follow_me_distance, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.flyc_flyc_way_point_mission_info_follow_me_reason, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_flyc_way_point_mission_info_follow_me_unknown6, payload(offset, 1))
        offset = offset + 1

    else

        subtree:add_le (f.flyc_flyc_way_point_mission_info_mission_flags, payload(offset, 1))
        subtree:add_le (f.flyc_flyc_way_point_mission_info_mission_status, payload(offset, 1))
        subtree:add_le (f.flyc_flyc_way_point_mission_info_position_valid, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_flyc_way_point_mission_info_current_status, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_flyc_way_point_mission_info_error_notification, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_flyc_way_point_mission_info_current_height, payload(offset, 2))
        offset = offset + 2

    end

    subtree:add_le (f.flyc_flyc_way_point_mission_info_is_tracking_enabled, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 7) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Way Point Mission Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Way Point Mission Info: Payload size different than expected") end
end

-- Flight Controller - Flyc Way Point Mission Current Event - 0x89

enums.FLYC_WAY_POINT_MISSION_CURRENT_EVENT_EVENT_TYPE_ENUM = {
    [0x01] = 'Finish Incident',
    [0x02] = 'Reach Incident',
    [0x03] = 'Upload Incident',
}

f.flyc_flyc_way_point_mission_current_event_event_type = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_current_event_event_type", "Event Type", base.HEX, enums.FLYC_WAY_POINT_MISSION_CURRENT_EVENT_EVENT_TYPE_ENUM)
-- Finish Incident
f.flyc_flyc_way_point_mission_current_event_finish_incident_is_repeat = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_current_event_finish_incident_is_repeat", "Finish Incident Is Repeat", base.HEX)
f.flyc_flyc_way_point_mission_current_event_finish_incident_resrved = ProtoField.uint16 ("dji_p3.flyc_flyc_way_point_mission_current_event_finish_incident_resrved", "Finish Incident Resrved", base.HEX)
-- Reach Incident
f.flyc_flyc_way_point_mission_current_event_reach_incident_way_point_index = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_current_event_reach_incident_way_point_index", "Reach Incident Way Point Index", base.HEX, nil, 0xff, nil)
f.flyc_flyc_way_point_mission_current_event_reach_incident_current_status = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_current_event_reach_incident_current_status", "Reach Incident Current Status", base.HEX, nil, 0xff, nil)
f.flyc_flyc_way_point_mission_current_event_reach_incident_reserved = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_current_event_reach_incident_reserved", "Reach Incident Reserved", base.HEX, nil, 0xff, nil)
-- Upload Incident
f.flyc_flyc_way_point_mission_current_event_upload_incident_is_valid = ProtoField.uint8 ("dji_p3.flyc_flyc_way_point_mission_current_event_upload_incident_is_valid", "Upload Incident Is Valid", base.HEX, nil, 0xff, nil)
f.flyc_flyc_way_point_mission_current_event_upload_incident_estimated_time = ProtoField.uint16 ("dji_p3.flyc_flyc_way_point_mission_current_event_upload_incident_estimated_time", "Upload Incident Estimated Time", base.HEX, nil, 0xffff, nil)
--f.flyc_flyc_way_point_mission_current_event_upload_incident_reserved = ProtoField.uint16 ("dji_p3.flyc_flyc_way_point_mission_current_event_upload_incident_reserved", "Upload Incident Reserved", base.HEX)

local function flyc_flyc_way_point_mission_current_event_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    local event_type = buffer(offset,1):le_uint()
    subtree:add_le (f.flyc_flyc_way_point_mission_current_event_event_type, payload(offset, 1))
    offset = offset + 1

    if (event_type == 0x02) then

        subtree:add_le (f.flyc_flyc_way_point_mission_current_event_reach_incident_way_point_index, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_flyc_way_point_mission_current_event_reach_incident_current_status, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_flyc_way_point_mission_current_event_reach_incident_reserved, payload(offset, 1))
        offset = offset + 1

    elseif (event_type == 0x03) then

        subtree:add_le (f.flyc_flyc_way_point_mission_current_event_upload_incident_is_valid, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_flyc_way_point_mission_current_event_upload_incident_estimated_time, payload(offset, 2))
        offset = offset + 2

        --subtree:add_le (f.flyc_flyc_way_point_mission_current_event_upload_incident_reserved, payload(offset, 2))
        --offset = offset + 2

    else

        subtree:add_le (f.flyc_flyc_way_point_mission_current_event_finish_incident_is_repeat, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_flyc_way_point_mission_current_event_finish_incident_resrved, payload(offset, 2))
        offset = offset + 2

    end

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Way Point Mission Current Event: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Way Point Mission Current Event: Payload size different than expected") end
end

-- Flight Controller - Flyc Agps Status - 0xa1

f.flyc_flyc_agps_status_time_stamp = ProtoField.uint32 ("dji_p3.flyc_flyc_agps_status_time_stamp", "Time Stamp", base.HEX)
f.flyc_flyc_agps_status_data_length = ProtoField.uint32 ("dji_p3.flyc_flyc_agps_status_data_length", "Data Length", base.HEX)
f.flyc_flyc_agps_status_crc16_hash = ProtoField.uint16 ("dji_p3.flyc_flyc_agps_status_crc16_hash", "Crc16 Hash", base.HEX)

local function flyc_flyc_agps_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_agps_status_time_stamp, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_flyc_agps_status_data_length, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_flyc_agps_status_crc16_hash, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 10) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Agps Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Agps Status: Payload size different than expected") end
end

-- Flight Controller - Flyc Flyc Install Error - 0xad

f.flyc_flyc_flyc_install_error_masked00 = ProtoField.uint32 ("dji_p3.flyc_flyc_flyc_install_error_masked00", "Masked00", base.HEX)
  f.flyc_flyc_flyc_install_error_yaw_install_error_level = ProtoField.uint32 ("dji_p3.flyc_flyc_flyc_install_error_yaw_install_error_level", "Yaw Install Error Level", base.HEX, nil, 0x03, nil)
  f.flyc_flyc_flyc_install_error_roll_install_error_level = ProtoField.uint32 ("dji_p3.flyc_flyc_flyc_install_error_roll_install_error_level", "Roll Install Error Level", base.HEX, nil, 0x0c, nil)
  f.flyc_flyc_flyc_install_error_pitch_install_error_level = ProtoField.uint32 ("dji_p3.flyc_flyc_flyc_install_error_pitch_install_error_level", "Pitch Install Error Level", base.HEX, nil, 0x30, nil)
  f.flyc_flyc_flyc_install_error_gyro_x_install_error_level = ProtoField.uint32 ("dji_p3.flyc_flyc_flyc_install_error_gyro_x_install_error_level", "Gyro X Install Error Level", base.HEX, nil, 0xc0, nil)
  f.flyc_flyc_flyc_install_error_gyro_y_install_error_level = ProtoField.uint32 ("dji_p3.flyc_flyc_flyc_install_error_gyro_y_install_error_level", "Gyro Y Install Error Level", base.HEX, nil, 0x300, nil)
  f.flyc_flyc_flyc_install_error_gyro_z_install_error_level = ProtoField.uint32 ("dji_p3.flyc_flyc_flyc_install_error_gyro_z_install_error_level", "Gyro Z Install Error Level", base.HEX, nil, 0xc00, nil)
  f.flyc_flyc_flyc_install_error_acc_x_install_error_level = ProtoField.uint32 ("dji_p3.flyc_flyc_flyc_install_error_acc_x_install_error_level", "Acc X Install Error Level", base.HEX, nil, 0x3000, nil)
  f.flyc_flyc_flyc_install_error_acc_y_install_error_level = ProtoField.uint32 ("dji_p3.flyc_flyc_flyc_install_error_acc_y_install_error_level", "Acc Y Install Error Level", base.HEX, nil, 0xc000, nil)
  f.flyc_flyc_flyc_install_error_acc_z_install_error_level = ProtoField.uint32 ("dji_p3.flyc_flyc_flyc_install_error_acc_z_install_error_level", "Acc Z Install Error Level", base.HEX, nil, 0x30000, nil)
  f.flyc_flyc_flyc_install_error_thrust_install_error_level = ProtoField.uint32 ("dji_p3.flyc_flyc_flyc_install_error_thrust_install_error_level", "Thrust Install Error Level", base.HEX, nil, 0xc0000, nil)

local function flyc_flyc_flyc_install_error_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_flyc_install_error_masked00, payload(offset, 4))
    subtree:add_le (f.flyc_flyc_flyc_install_error_yaw_install_error_level, payload(offset, 4))
    subtree:add_le (f.flyc_flyc_flyc_install_error_roll_install_error_level, payload(offset, 4))
    subtree:add_le (f.flyc_flyc_flyc_install_error_pitch_install_error_level, payload(offset, 4))
    subtree:add_le (f.flyc_flyc_flyc_install_error_gyro_x_install_error_level, payload(offset, 4))
    subtree:add_le (f.flyc_flyc_flyc_install_error_gyro_y_install_error_level, payload(offset, 4))
    subtree:add_le (f.flyc_flyc_flyc_install_error_gyro_z_install_error_level, payload(offset, 4))
    subtree:add_le (f.flyc_flyc_flyc_install_error_acc_x_install_error_level, payload(offset, 4))
    subtree:add_le (f.flyc_flyc_flyc_install_error_acc_y_install_error_level, payload(offset, 4))
    subtree:add_le (f.flyc_flyc_flyc_install_error_acc_z_install_error_level, payload(offset, 4))
    subtree:add_le (f.flyc_flyc_flyc_install_error_thrust_install_error_level, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Flyc Install Error: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Flyc Install Error: Payload size different than expected") end
end

-- Flight Controller - Flyc Fault Inject - 0xb6

enums.FLYC_FAULT_INJECT_STATUS_ENUM = {
    [0x01] = 'FIT_VERSION_UNMATCH',
    [0x02] = 'FIT_OPEN_FAILED',
    [0x03] = 'FIT_OPEN_SUCCESS',
    [0x04] = 'FIT_CLOSE_SUCCESS',
    [0x05] = 'FIT_INJECT_SUCCESS',
    [0x06] = 'FIT_INJECT_FAILED',
    [0x07] = 'FIT_FDI_DETECT_SUCCESS',
    [0x08] = 'FIT_FDI_DETECT_FAILED',
    [0x09] = 'FIT_AUTO_STOP_FOR_SAFE',
    [0x0a] = 'FIT_TIME_PARA_INVALID',
    [0x0b] = 'FIT_DENY_FOR_UNSAFE',
    [0x0c] = 'FIT_DENY_FOR_FAULT',
    [0x0d] = 'FIT_DENY_FOR_DISCONNECT',
    [0x0e] = 'FIT_UNKNOWN_FAULT_TYPE',
    [0x0f] = 'FIT_INVALID_SYSTEM_ID',
    [0x10] = 'FIT_UNKNOWN_MODULE_TYPE',
    [0x11] = 'FIT_MODULE_CANNOT_FOUND',
    [0x12] = 'FIT_UNKNOWN_CMD_ID',
    [0x13] = 'FIT_UNSUPPORT_NOW',
    [0x14] = 'FIT_DENY_FOR_UNOPEN',
    [0x15] = 'FIT_DENY_FOR_FUNC_CLOSED',
    [0x16] = 'FIT_MSG_LEN_ERR',
    [0x17] = 'FIT_ROUTE_FAILED',
}

f.flyc_flyc_fault_inject_status = ProtoField.uint8 ("dji_p3.flyc_flyc_fault_inject_status", "Status", base.HEX, enums.FLYC_FAULT_INJECT_STATUS_ENUM, nil, nil)

local function flyc_flyc_fault_inject_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_fault_inject_status, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Fault Inject: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Fault Inject: Payload size different than expected") end
end

-- Flight Controller - Flyc Redundancy Status - 0xb9

enums.FLYC_REDUNDANCY_STATUS_CMD_TYPE_ENUM = {
    [0x01] = 'a',
    [0x02] = 'b',
    [0x03] = 'c',
    [0x04] = 'd',
}

f.flyc_flyc_redundancy_status_cmd_type = ProtoField.uint8 ("dji_p3.flyc_flyc_redundancy_status_cmd_type", "Command Type", base.HEX, enums.FLYC_REDUNDANCY_STATUS_CMD_TYPE_ENUM)
f.flyc_flyc_redundancy_status_unknown1 = ProtoField.uint8 ("dji_p3.flyc_flyc_redundancy_status_unknown1", "Unknown1", base.HEX)
f.flyc_flyc_redundancy_status_unknown2 = ProtoField.uint8 ("dji_p3.flyc_flyc_redundancy_status_unknown2", "Unknown2", base.HEX)
f.flyc_flyc_redundancy_status_unknown3 = ProtoField.uint8 ("dji_p3.flyc_flyc_redundancy_status_unknown3", "Unknown3", base.HEX)
f.flyc_flyc_redundancy_status_unknown4 = ProtoField.uint8 ("dji_p3.flyc_flyc_redundancy_status_unknown4", "Unknown4", base.HEX)
f.flyc_flyc_redundancy_status_unknown5 = ProtoField.uint8 ("dji_p3.flyc_flyc_redundancy_status_unknown5", "Unknown5", base.HEX)
f.flyc_flyc_redundancy_status_unknown6 = ProtoField.uint8 ("dji_p3.flyc_flyc_redundancy_status_unknown6", "Unknown6", base.HEX)
f.flyc_flyc_redundancy_status_unknown7 = ProtoField.uint8 ("dji_p3.flyc_flyc_redundancy_status_unknown7", "Unknown7", base.HEX)
f.flyc_flyc_redundancy_status_unknown8 = ProtoField.uint8 ("dji_p3.flyc_flyc_redundancy_status_unknown8", "Unknown8", base.HEX)
f.flyc_flyc_redundancy_status_unknown9 = ProtoField.uint8 ("dji_p3.flyc_flyc_redundancy_status_unknown9", "Unknown9", base.HEX)
f.flyc_flyc_redundancy_status_unknownA = ProtoField.uint8 ("dji_p3.flyc_flyc_redundancy_status_unknownA", "UnknownA", base.HEX)
f.flyc_flyc_redundancy_status_unknownB = ProtoField.uint8 ("dji_p3.flyc_flyc_redundancy_status_unknownB", "UnknownB", base.HEX)

local function flyc_flyc_redundancy_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_redundancy_status_cmd_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_redundancy_status_unknown1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_redundancy_status_unknown2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_redundancy_status_unknown3, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_redundancy_status_unknown4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_redundancy_status_unknown5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_redundancy_status_unknown6, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_redundancy_status_unknown7, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_redundancy_status_unknown8, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_redundancy_status_unknown9, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_redundancy_status_unknownA, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_redundancy_status_unknownB, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 12) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Redundancy Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Redundancy Status: Payload size different than expected") end
end

-- Flight Controller - Flyc Params By Hash - 0xfb

f.flyc_flyc_params_by_hash_unknown00 = ProtoField.uint8 ("dji_p3.flyc_flyc_params_by_hash_unknown00", "Unknown00", base.HEX)
f.flyc_flyc_params_by_hash_first_index_hash = ProtoField.uint32 ("dji_p3.flyc_flyc_params_by_hash_first_index_hash", "First Index Hash", base.HEX)

local function flyc_flyc_params_by_hash_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_params_by_hash_unknown00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_params_by_hash_first_index_hash, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Params By Hash: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Flyc Params By Hash: Payload size different than expected") end
end

local FLYC_UART_CMD_DISSECT = {
    [0x09] = flyc_flyc_forbid_status_dissector,
    [0x10] = flyc_a2_commom_dissector,
    [0x32] = flyc_flyc_deform_status_dissector,
    [0x3e] = flyc_flyc_request_limit_update_dissector,
    [0x42] = flyc_flyc_unlimit_state_dissector,
    [0x43] = flyc_osd_general_dissector,
    [0x44] = flyc_osd_home_dissector,
    [0x45] = flyc_flyc_gps_snr_dissector,
    [0x51] = flyc_flyc_smart_battery_dissector,
    [0x53] = flyc_flyc_avoid_param_dissector,
    [0x55] = flyc_flyc_limit_state_dissector,
    [0x56] = flyc_flyc_led_status_dissector,
    [0x50] = flyc_imu_data_status_dissector,
    [0x57] = flyc_gps_glns_dissector,
    [0x61] = flyc_flyc_active_request_dissector,
    [0x63] = flyc_flyc_board_recv_dissector,
    [0x67] = flyc_flyc_power_param_dissector,
    [0x6a] = flyc_flyc_avoid_dissector,
    [0x6c] = flyc_flyc_rtk_location_data_dissector,
    [0x88] = flyc_flyc_way_point_mission_info_dissector,
    [0x89] = flyc_flyc_way_point_mission_current_event_dissector,
    [0xa1] = flyc_flyc_agps_status_dissector,
    [0xad] = flyc_flyc_flyc_install_error_dissector,
    [0xb6] = flyc_flyc_fault_inject_dissector,
    [0xb9] = flyc_flyc_redundancy_status_dissector,
    [0xfb] = flyc_flyc_params_by_hash_dissector,
}

-- Gimbal - Gimbal Params - 0x05

enums.GIMBAL_PARAMS_MODE_ENUM = {
    [0x00] = 'YawNoFollow',
    [0x01] = 'FPV',
    [0x02] = 'YawFollow',
    [0x64] = 'OTHER',
}

f.gimbal_gimbal_params_pitch = ProtoField.uint16 ("dji_p3.gimbal_gimbal_params_pitch", "Gimbal Pitch", base.DEC, nil, nil, "0.1, gimbal angular position, zero is forward, max down..up is about -900..470")
f.gimbal_gimbal_params_roll = ProtoField.uint16 ("dji_p3.gimbal_gimbal_params_roll", "Gimbal Roll", base.DEC, nil, nil, "0.1, gimbal angular position, zero is parallel to earth, max right..left is about -410..410")
f.gimbal_gimbal_params_yaw = ProtoField.uint16 ("dji_p3.gimbal_gimbal_params_yaw", "Gimbal Yaw", base.DEC, nil, nil, "0.1, gimbal angular position, -1000 is forward, max right..left is about -1460..-540") -- TODO verify
f.gimbal_gimbal_params_masked06 = ProtoField.uint8 ("dji_p3.gimbal_gimbal_params_masked06", "Masked06", base.HEX)
  f.gimbal_gimbal_params_sub_mode = ProtoField.uint8 ("dji_p3.gimbal_gimbal_params_sub_mode", "Sub Mode", base.HEX, nil, 0x20, nil)
  f.gimbal_gimbal_params_mode = ProtoField.uint8 ("dji_p3.gimbal_gimbal_params_mode", "Mode", base.HEX, enums.GIMBAL_PARAMS_MODE_ENUM, 0xc0, nil)
f.gimbal_gimbal_params_roll_adjust = ProtoField.uint8 ("dji_p3.gimbal_gimbal_params_roll_adjust", "Roll Adjust", base.HEX)
f.gimbal_gimbal_params_yaw_angle = ProtoField.uint16 ("dji_p3.gimbal_gimbal_params_yaw_angle", "Yaw Angle", base.HEX, nil, nil, "Not sure whether Yaw angle or Joytick Direction")
  f.gimbal_gimbal_params_joystick_ver_direction = ProtoField.uint16 ("dji_p3.gimbal_gimbal_params_joystick_ver_direction", "Joystick Ver Direction", base.HEX, nil, 0x03, nil)
  f.gimbal_gimbal_params_joystick_hor_direction = ProtoField.uint16 ("dji_p3.gimbal_gimbal_params_joystick_hor_direction", "Joystick Hor Direction", base.HEX, nil, 0x0c, nil)
f.gimbal_gimbal_params_masked0a = ProtoField.uint8 ("dji_p3.gimbal_gimbal_params_masked0a", "Masked0A", base.HEX)
  f.gimbal_gimbal_params_pitch_in_limit = ProtoField.uint8 ("dji_p3.gimbal_gimbal_params_pitch_in_limit", "Pitch In Limit", base.HEX, nil, 0x01, nil)
  f.gimbal_gimbal_params_roll_in_limit = ProtoField.uint8 ("dji_p3.gimbal_gimbal_params_roll_in_limit", "Roll In Limit", base.HEX, nil, 0x02, nil)
  f.gimbal_gimbal_params_yaw_in_limit = ProtoField.uint8 ("dji_p3.gimbal_gimbal_params_yaw_in_limit", "Yaw In Limit", base.HEX, nil, 0x04, nil)
  f.gimbal_gimbal_params_auto_calibration = ProtoField.uint8 ("dji_p3.gimbal_gimbal_params_auto_calibration", "Auto Calibration", base.HEX, nil, 0x08, nil)
  f.gimbal_gimbal_params_auto_calibration_result = ProtoField.uint8 ("dji_p3.gimbal_gimbal_params_auto_calibration_result", "Auto Calibration Result", base.HEX, nil, 0x10, nil)
  f.gimbal_gimbal_params_stuck = ProtoField.uint8 ("dji_p3.gimbal_gimbal_params_stuck", "Stuck", base.HEX, nil, 0x40, nil)
f.gimbal_gimbal_params_masked0b = ProtoField.uint8 ("dji_p3.gimbal_gimbal_params_masked0b", "Masked0B", base.HEX)
  f.gimbal_gimbal_params_version = ProtoField.uint8 ("dji_p3.gimbal_gimbal_params_version", "Version", base.HEX, nil, 0x0f, nil)
  f.gimbal_gimbal_params_double_click = ProtoField.uint8 ("dji_p3.gimbal_gimbal_params_double_click", "Double Click", base.HEX, nil, 0x20, nil)
  f.gimbal_gimbal_params_triple_click = ProtoField.uint8 ("dji_p3.gimbal_gimbal_params_triple_click", "Triple Click", base.HEX, nil, 0x40, nil)
  f.gimbal_gimbal_params_single_click = ProtoField.uint8 ("dji_p3.gimbal_gimbal_params_single_click", "Single Click", base.HEX, nil, 0x80, nil)

local function gimbal_gimbal_params_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_gimbal_params_pitch, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_params_roll, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_params_yaw, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_params_masked06, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_params_sub_mode, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_params_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_gimbal_params_roll_adjust, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_gimbal_params_yaw_angle, payload(offset, 2))
    subtree:add_le (f.gimbal_gimbal_params_joystick_ver_direction, payload(offset, 2))
    subtree:add_le (f.gimbal_gimbal_params_joystick_hor_direction, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_params_masked0a, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_params_pitch_in_limit, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_params_roll_in_limit, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_params_yaw_in_limit, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_params_auto_calibration, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_params_auto_calibration_result, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_params_stuck, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_gimbal_params_masked0b, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_params_version, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_params_double_click, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_params_triple_click, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_params_single_click, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 12) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Params: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Params: Payload size different than expected") end
end

-- Gimbal - Gimbal Type - 0x1c

enums.GIMBAL_TYPE_TYPE_DJI_GIMBAL_TYPE_ENUM = {
    [0x00] = 'TIMEOUT',
    [0x01] = 'FAULT',
    [0x02] = 'FC550',
    [0x03] = 'FC300SX',
    [0x04] = 'FC260',
    [0x05] = 'FC350',
    [0x06] = 'FC350Z',
    [0x07] = 'Z15',
    [0x08] = 'P4',
    [0x0b] = 'D5',
    [0x0c] = 'GH4',
    [0x0d] = 'A7',
    [0x0e] = 'BMPCC',
    [0x14] = 'WM220',
    [0x0a] = 'Ronin',
    [0x64] = 'OTHER',
}

f.gimbal_gimbal_type_type = ProtoField.uint8 ("dji_p3.gimbal_gimbal_type_type", "Type", base.HEX, enums.GIMBAL_TYPE_TYPE_DJI_GIMBAL_TYPE_ENUM, nil, nil)

local function gimbal_gimbal_type_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_gimbal_type_type, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Type: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Type: Payload size different than expected") end
end

-- Gimbal - Gimbal User Params - 0x24

f.gimbal_gimbal_user_params_unknown00 = ProtoField.bytes ("dji_p3.gimbal_gimbal_user_params_unknown00", "Unknown00", base.SPACE)
f.gimbal_gimbal_user_params_preset_id = ProtoField.uint8 ("dji_p3.gimbal_gimbal_user_params_preset_id", "Preset Id", base.HEX)
f.gimbal_gimbal_user_params_unknown03 = ProtoField.bytes ("dji_p3.gimbal_gimbal_user_params_unknown03", "Unknown03", base.SPACE)
f.gimbal_gimbal_user_params_yaw_speed = ProtoField.uint16 ("dji_p3.gimbal_gimbal_user_params_yaw_speed", "Yaw Speed", base.HEX)
f.gimbal_gimbal_user_params_unknown0b = ProtoField.bytes ("dji_p3.gimbal_gimbal_user_params_unknown0b", "Unknown0B", base.SPACE)
f.gimbal_gimbal_user_params_pitch_speed = ProtoField.uint16 ("dji_p3.gimbal_gimbal_user_params_pitch_speed", "Pitch Speed", base.HEX)
f.gimbal_gimbal_user_params_unknown0f = ProtoField.bytes ("dji_p3.gimbal_gimbal_user_params_unknown0f", "Unknown0F", base.SPACE)
f.gimbal_gimbal_user_params_yaw_deadband = ProtoField.uint16 ("dji_p3.gimbal_gimbal_user_params_yaw_deadband", "Yaw Deadband", base.HEX)
f.gimbal_gimbal_user_params_unknown13 = ProtoField.bytes ("dji_p3.gimbal_gimbal_user_params_unknown13", "Unknown13", base.SPACE)
f.gimbal_gimbal_user_params_pitch_deadband = ProtoField.uint16 ("dji_p3.gimbal_gimbal_user_params_pitch_deadband", "Pitch Deadband", base.HEX)
f.gimbal_gimbal_user_params_unknown17 = ProtoField.bytes ("dji_p3.gimbal_gimbal_user_params_unknown17", "Unknown17", base.SPACE)
f.gimbal_gimbal_user_params_stick_yaw_speed = ProtoField.uint16 ("dji_p3.gimbal_gimbal_user_params_stick_yaw_speed", "Stick Yaw Speed", base.HEX)
f.gimbal_gimbal_user_params_unknown1b = ProtoField.bytes ("dji_p3.gimbal_gimbal_user_params_unknown1b", "Unknown1B", base.SPACE)
f.gimbal_gimbal_user_params_stick_pitch_speed = ProtoField.uint16 ("dji_p3.gimbal_gimbal_user_params_stick_pitch_speed", "Stick Pitch Speed", base.HEX)
f.gimbal_gimbal_user_params_unknown1f = ProtoField.bytes ("dji_p3.gimbal_gimbal_user_params_unknown1f", "Unknown1F", base.SPACE)
f.gimbal_gimbal_user_params_stick_yaw_smooth = ProtoField.uint16 ("dji_p3.gimbal_gimbal_user_params_stick_yaw_smooth", "Stick Yaw Smooth", base.HEX)
f.gimbal_gimbal_user_params_unknown23 = ProtoField.bytes ("dji_p3.gimbal_gimbal_user_params_unknown23", "Unknown23", base.SPACE)
f.gimbal_gimbal_user_params_stick_pitch_smooth = ProtoField.uint16 ("dji_p3.gimbal_gimbal_user_params_stick_pitch_smooth", "Stick Pitch Smooth", base.HEX)
f.gimbal_gimbal_user_params_unknown27 = ProtoField.bytes ("dji_p3.gimbal_gimbal_user_params_unknown27", "Unknown27", base.SPACE)
f.gimbal_gimbal_user_params_roll_speed = ProtoField.uint16 ("dji_p3.gimbal_gimbal_user_params_roll_speed", "Roll Speed", base.HEX)
f.gimbal_gimbal_user_params_unknown31 = ProtoField.bytes ("dji_p3.gimbal_gimbal_user_params_unknown31", "Unknown31", base.SPACE)
f.gimbal_gimbal_user_params_roll_deadband = ProtoField.uint16 ("dji_p3.gimbal_gimbal_user_params_roll_deadband", "Roll Deadband", base.HEX)
f.gimbal_gimbal_user_params_unknown35 = ProtoField.bytes ("dji_p3.gimbal_gimbal_user_params_unknown35", "Unknown35", base.SPACE)
f.gimbal_gimbal_user_params_yaw_accel = ProtoField.uint16 ("dji_p3.gimbal_gimbal_user_params_yaw_accel", "Yaw Accel", base.HEX)
f.gimbal_gimbal_user_params_unknown39 = ProtoField.bytes ("dji_p3.gimbal_gimbal_user_params_unknown39", "Unknown39", base.SPACE)
f.gimbal_gimbal_user_params_pitch_accel = ProtoField.uint16 ("dji_p3.gimbal_gimbal_user_params_pitch_accel", "Pitch Accel", base.HEX)
f.gimbal_gimbal_user_params_unknown3d = ProtoField.bytes ("dji_p3.gimbal_gimbal_user_params_unknown3d", "Unknown3D", base.SPACE)
f.gimbal_gimbal_user_params_roll_accel = ProtoField.uint16 ("dji_p3.gimbal_gimbal_user_params_roll_accel", "Roll Accel", base.HEX)
f.gimbal_gimbal_user_params_unknown41 = ProtoField.bytes ("dji_p3.gimbal_gimbal_user_params_unknown41", "Unknown41", base.SPACE)
f.gimbal_gimbal_user_params_yaw_smooth_track = ProtoField.uint8 ("dji_p3.gimbal_gimbal_user_params_yaw_smooth_track", "Yaw Smooth Track", base.HEX)
f.gimbal_gimbal_user_params_unknown44 = ProtoField.bytes ("dji_p3.gimbal_gimbal_user_params_unknown44", "Unknown44", base.SPACE)
f.gimbal_gimbal_user_params_pitch_smooth_track = ProtoField.uint8 ("dji_p3.gimbal_gimbal_user_params_pitch_smooth_track", "Pitch Smooth Track", base.HEX)
f.gimbal_gimbal_user_params_unknown47 = ProtoField.bytes ("dji_p3.gimbal_gimbal_user_params_unknown47", "Unknown47", base.SPACE)
f.gimbal_gimbal_user_params_roll_smooth_track = ProtoField.uint8 ("dji_p3.gimbal_gimbal_user_params_roll_smooth_track", "Roll Smooth Track", base.HEX)

local function gimbal_gimbal_user_params_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_gimbal_user_params_unknown00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_preset_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_gimbal_user_params_unknown03, payload(offset, 6))
    offset = offset + 6

    subtree:add_le (f.gimbal_gimbal_user_params_yaw_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_unknown0b, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_pitch_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_unknown0f, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_yaw_deadband, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_unknown13, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_pitch_deadband, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_unknown17, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_stick_yaw_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_unknown1b, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_stick_pitch_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_unknown1f, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_stick_yaw_smooth, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_unknown23, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_stick_pitch_smooth, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_unknown27, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.gimbal_gimbal_user_params_roll_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_unknown31, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_roll_deadband, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_unknown35, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_yaw_accel, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_unknown39, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_pitch_accel, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_unknown3d, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_roll_accel, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_unknown41, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_yaw_smooth_track, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_gimbal_user_params_unknown44, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_pitch_smooth_track, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_gimbal_user_params_unknown47, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_gimbal_user_params_roll_smooth_track, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 74) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal User Params: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal User Params: Payload size different than expected") end
end

-- Gimbal - Gimbal Abnormal Status - 0x27

f.gimbal_gimbal_abnormal_status_masked00 = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_masked00", "Masked00", base.HEX)
  f.gimbal_gimbal_abnormal_status_roll_locked = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_roll_locked", "Roll Locked", base.HEX, nil, 0x01, nil)
  f.gimbal_gimbal_abnormal_status_pitch_locked = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_pitch_locked", "Pitch Locked", base.HEX, nil, 0x02, nil)
  f.gimbal_gimbal_abnormal_status_yaw_locked = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_yaw_locked", "Yaw Locked", base.HEX, nil, 0x04, nil)
f.gimbal_gimbal_abnormal_status_masked01 = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_masked01", "Masked01", base.HEX)
  f.gimbal_gimbal_abnormal_status_joint_lock_after_startup = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_joint_lock_after_startup", "Joint Lock After Startup", base.HEX, nil, 0x01, nil)
  f.gimbal_gimbal_abnormal_status_joint_lock_when_startup = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_joint_lock_when_startup", "Joint Lock When Startup", base.HEX, nil, 0x02, nil)
  f.gimbal_gimbal_abnormal_status_motor_protected = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_motor_protected", "Motor Protected", base.HEX, nil, 0x04, nil)
  f.gimbal_gimbal_abnormal_status_error_recent_when_start_up = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_error_recent_when_start_up", "Error Recent When Start Up", base.HEX, nil, 0x08, nil)
  f.gimbal_gimbal_abnormal_status_upgrading = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_upgrading", "Upgrading", base.HEX, nil, 0x10, nil)
  f.gimbal_gimbal_abnormal_status_yaw_limit = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_yaw_limit", "Yaw Limit", base.HEX, nil, 0x20, nil)
  f.gimbal_gimbal_abnormal_status_error_recent_or_selfie = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_error_recent_or_selfie", "Error Recent Or Selfie", base.HEX, nil, 0x40, nil)
  f.gimbal_gimbal_abnormal_status_pano_ready = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_pano_ready", "Pano Ready", base.HEX, nil, 0x80, nil)
f.gimbal_gimbal_abnormal_status_masked02 = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_masked02", "Masked02", base.HEX)
  f.gimbal_gimbal_abnormal_status_fan_direction = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_fan_direction", "Fan Direction", base.HEX, nil, 0x02, nil)
  f.gimbal_gimbal_abnormal_status_vertical_direction = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_vertical_direction", "Vertical Direction", base.HEX, nil, 0x04, nil)
  f.gimbal_gimbal_abnormal_status_in_flashlight = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_in_flashlight", "In Flashlight", base.HEX, nil, 0x08, nil)
  f.gimbal_gimbal_abnormal_status_portrait = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_portrait", "Portrait", base.HEX, nil, 0x10, nil)
  f.gimbal_gimbal_abnormal_status_gimbal_direction_when_vertical = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_gimbal_direction_when_vertical", "Gimbal Direction When Vertical", base.HEX, nil, 0x20, nil)
f.gimbal_gimbal_abnormal_status_masked03 = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_masked03", "Masked03", base.HEX)
  f.gimbal_gimbal_abnormal_status_phone_out_gimbal = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_phone_out_gimbal", "Phone Out Gimbal", base.HEX, nil, 0x01, nil)
  f.gimbal_gimbal_abnormal_status_gimbal_gravity = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_gimbal_gravity", "Gimbal Gravity", base.HEX, nil, 0x06, nil)
  f.gimbal_gimbal_abnormal_status_yaw_limited_in_tracking = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_yaw_limited_in_tracking", "Yaw Limited In Tracking", base.HEX, nil, 0x20, nil)
  f.gimbal_gimbal_abnormal_status_pitch_limited_in_tracking = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_pitch_limited_in_tracking", "Pitch Limited In Tracking", base.HEX, nil, 0x40, nil)
f.gimbal_gimbal_abnormal_status_masked04 = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_masked04", "Masked04", base.HEX)
  f.gimbal_gimbal_abnormal_status_sleep_mode = ProtoField.uint8 ("dji_p3.gimbal_gimbal_abnormal_status_sleep_mode", "Sleep Mode", base.HEX, nil, 0x01, nil)

local function gimbal_gimbal_abnormal_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_gimbal_abnormal_status_masked00, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_roll_locked, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_pitch_locked, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_yaw_locked, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_gimbal_abnormal_status_masked01, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_joint_lock_after_startup, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_joint_lock_when_startup, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_motor_protected, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_error_recent_when_start_up, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_upgrading, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_yaw_limit, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_error_recent_or_selfie, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_pano_ready, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_gimbal_abnormal_status_masked02, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_fan_direction, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_vertical_direction, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_in_flashlight, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_portrait, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_gimbal_direction_when_vertical, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_gimbal_abnormal_status_masked03, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_phone_out_gimbal, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_gimbal_gravity, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_yaw_limited_in_tracking, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_pitch_limited_in_tracking, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_gimbal_abnormal_status_masked04, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_abnormal_status_sleep_mode, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Abnormal Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Abnormal Status: Payload size different than expected") end
end

-- Gimbal - Gimbal Tutorial Status - 0x2b

enums.GIMBAL_TUTORIAL_STATUS_CUR_STEP_TUTORIAL_STATUS_ENUM = {
    [0x00] = 'STEP_FINISH',
    [0x01] = 'STEP_START',
    [0x02] = 'STEP_UNLOCK_GIMBAL',
    [0x03] = 'STEP_HOLD_GIMBAL_UPRIGHT',
    [0x04] = 'STEP_FOLLOW',
    [0x05] = 'STEP_STICK',
    [0x06] = 'STEP_LOCK_DIRECTION',
    [0x07] = 'STEP_RECENTER',
    [0x08] = 'STEP_SELFIE',
    [0x09] = 'STEP_PUSH',
    [0x0a] = 'STEP_APP_CONTROL',
}

f.gimbal_gimbal_tutorial_status_cur_step = ProtoField.uint8 ("dji_p3.gimbal_gimbal_tutorial_status_cur_step", "Cur Step", base.HEX, enums.GIMBAL_TUTORIAL_STATUS_CUR_STEP_TUTORIAL_STATUS_ENUM, nil, nil)
f.gimbal_gimbal_tutorial_status_step_status = ProtoField.uint32 ("dji_p3.gimbal_gimbal_tutorial_status_step_status", "Step Status", base.HEX)
  f.gimbal_gimbal_tutorial_status_is_unlock = ProtoField.uint32 ("dji_p3.gimbal_gimbal_tutorial_status_is_unlock", "Is Unlock", base.HEX, nil, 0x01, nil)
  f.gimbal_gimbal_tutorial_status_is_upright = ProtoField.uint32 ("dji_p3.gimbal_gimbal_tutorial_status_is_upright", "Is Upright", base.HEX, nil, 0x02, nil)
  f.gimbal_gimbal_tutorial_status_is_follow_finish = ProtoField.uint32 ("dji_p3.gimbal_gimbal_tutorial_status_is_follow_finish", "Is Follow Finish", base.HEX, nil, 0x04, nil)
  f.gimbal_gimbal_tutorial_status_is_stick_finish = ProtoField.uint32 ("dji_p3.gimbal_gimbal_tutorial_status_is_stick_finish", "Is Stick Finish", base.HEX, nil, 0x08, nil)
  f.gimbal_gimbal_tutorial_status_is_lock_direction_finish = ProtoField.uint32 ("dji_p3.gimbal_gimbal_tutorial_status_is_lock_direction_finish", "Is Lock Direction Finish", base.HEX, nil, 0x10, nil)
  f.gimbal_gimbal_tutorial_status_is_recent_finish = ProtoField.uint32 ("dji_p3.gimbal_gimbal_tutorial_status_is_recent_finish", "Is Recent Finish", base.HEX, nil, 0x20, nil)
  f.gimbal_gimbal_tutorial_status_is_selfie_finish = ProtoField.uint32 ("dji_p3.gimbal_gimbal_tutorial_status_is_selfie_finish", "Is Selfie Finish", base.HEX, nil, 0x40, nil)
  f.gimbal_gimbal_tutorial_status_is_handle_push_finish = ProtoField.uint32 ("dji_p3.gimbal_gimbal_tutorial_status_is_handle_push_finish", "Is Handle Push Finish", base.HEX, nil, 0x80, nil)
  f.gimbal_gimbal_tutorial_status_is_app_control_finish = ProtoField.uint32 ("dji_p3.gimbal_gimbal_tutorial_status_is_app_control_finish", "Is App Control Finish", base.HEX, nil, 0x100, nil)

local function gimbal_gimbal_tutorial_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_gimbal_tutorial_status_cur_step, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_gimbal_tutorial_status_step_status, payload(offset, 4))
    subtree:add_le (f.gimbal_gimbal_tutorial_status_is_unlock, payload(offset, 4))
    subtree:add_le (f.gimbal_gimbal_tutorial_status_is_upright, payload(offset, 4))
    subtree:add_le (f.gimbal_gimbal_tutorial_status_is_follow_finish, payload(offset, 4))
    subtree:add_le (f.gimbal_gimbal_tutorial_status_is_stick_finish, payload(offset, 4))
    subtree:add_le (f.gimbal_gimbal_tutorial_status_is_lock_direction_finish, payload(offset, 4))
    subtree:add_le (f.gimbal_gimbal_tutorial_status_is_recent_finish, payload(offset, 4))
    subtree:add_le (f.gimbal_gimbal_tutorial_status_is_selfie_finish, payload(offset, 4))
    subtree:add_le (f.gimbal_gimbal_tutorial_status_is_handle_push_finish, payload(offset, 4))
    subtree:add_le (f.gimbal_gimbal_tutorial_status_is_app_control_finish, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Tutorial Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Tutorial Status: Payload size different than expected") end
end

-- Gimbal - Gimbal Auto Calibration Status - 0x30

f.gimbal_gimbal_auto_calibration_status_progress = ProtoField.uint8 ("dji_p3.gimbal_gimbal_auto_calibration_status_progress", "Progress", base.HEX)
f.gimbal_gimbal_auto_calibration_status_status = ProtoField.uint8 ("dji_p3.gimbal_gimbal_auto_calibration_status_status", "Status", base.HEX)

local function gimbal_gimbal_auto_calibration_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_gimbal_auto_calibration_status_progress, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_gimbal_auto_calibration_status_status, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Auto Calibration Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Auto Calibration Status: Payload size different than expected") end
end

-- Gimbal - Gimbal Battery Info - 0x33

f.gimbal_gimbal_battery_info_a = ProtoField.uint8 ("dji_p3.gimbal_gimbal_battery_info_a", "A", base.HEX)

local function gimbal_gimbal_battery_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_gimbal_battery_info_a, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Battery Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Battery Info: Payload size different than expected") end
end

-- Gimbal - Gimbal Timelapse Status - 0x38

f.gimbal_gimbal_timelapse_status_masked00 = ProtoField.uint8 ("dji_p3.gimbal_gimbal_timelapse_status_masked00", "Masked00", base.HEX)
  f.gimbal_gimbal_timelapse_status_timelapse_status = ProtoField.uint8 ("dji_p3.gimbal_gimbal_timelapse_status_timelapse_status", "Timelapse Status", base.HEX, nil, 0x03, nil)

local function gimbal_gimbal_timelapse_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_gimbal_timelapse_status_masked00, payload(offset, 1))
    subtree:add_le (f.gimbal_gimbal_timelapse_status_timelapse_status, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Timelapse Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Timelapse Status: Payload size different than expected") end
end

local GIMBAL_UART_CMD_DISSECT = {
    [0x05] = gimbal_gimbal_params_dissector,
    [0x1c] = gimbal_gimbal_type_dissector,
    [0x24] = gimbal_gimbal_user_params_dissector,
    [0x27] = gimbal_gimbal_abnormal_status_dissector,
    [0x2b] = gimbal_gimbal_tutorial_status_dissector,
    [0x30] = gimbal_gimbal_auto_calibration_status_dissector,
    [0x33] = gimbal_gimbal_battery_info_dissector,
    [0x38] = gimbal_gimbal_timelapse_status_dissector,
}

-- Center Board - Center Battery Common - 0x06

enums.CENTER_BRD_CENTER_BATTERY_COMMON_CONN_STATUS_ENUM = {
    [0x00] = 'NORMAL',
    [0x01] = 'INVALID',
    [0x02] = 'EXCEPTION',
    [0x64] = 'OTHER',
}

f.center_brd_center_battery_common_relative_capacity = ProtoField.uint8 ("dji_p3.center_brd_center_battery_common_relative_capacity", "Relative Capacity", base.DEC)
f.center_brd_center_battery_common_current_pv = ProtoField.uint16 ("dji_p3.center_brd_center_battery_common_current_pv", "Current Pv", base.DEC)
f.center_brd_center_battery_common_current_capacity = ProtoField.uint16 ("dji_p3.center_brd_center_battery_common_current_capacity", "Current Capacity", base.DEC)
f.center_brd_center_battery_common_full_capacity = ProtoField.uint16 ("dji_p3.center_brd_center_battery_common_full_capacity", "Full Capacity", base.DEC)
f.center_brd_center_battery_common_life = ProtoField.uint8 ("dji_p3.center_brd_center_battery_common_life", "Life", base.DEC)
f.center_brd_center_battery_common_loop_num = ProtoField.uint16 ("dji_p3.center_brd_center_battery_common_loop_num", "Loop Num", base.DEC)
f.center_brd_center_battery_common_error_type = ProtoField.uint32 ("dji_p3.center_brd_center_battery_common_error_type", "Error Type", base.HEX)
f.center_brd_center_battery_common_current = ProtoField.uint16 ("dji_p3.center_brd_center_battery_common_current", "Current", base.DEC)
f.center_brd_center_battery_common_unknown10 = ProtoField.bytes ("dji_p3.center_brd_center_battery_common_unknown10", "Unknown10", base.SPACE)
f.center_brd_center_battery_common_serial_no = ProtoField.uint16 ("dji_p3.center_brd_center_battery_common_serial_no", "Serial No", base.HEX)
f.center_brd_center_battery_common_unknown1e = ProtoField.bytes ("dji_p3.center_brd_center_battery_common_unknown1e", "Unknown1E", base.SPACE)
f.center_brd_center_battery_common_temperature = ProtoField.uint16 ("dji_p3.center_brd_center_battery_common_temperature", "Temperature", base.DEC)
f.center_brd_center_battery_common_conn_status = ProtoField.uint8 ("dji_p3.center_brd_center_battery_common_conn_status", "Conn Status", base.HEX, enums.CENTER_BRD_CENTER_BATTERY_COMMON_CONN_STATUS_ENUM, nil, nil)
f.center_brd_center_battery_common_total_study_cycle = ProtoField.uint16 ("dji_p3.center_brd_center_battery_common_total_study_cycle", "Total Study Cycle", base.HEX)
f.center_brd_center_battery_common_last_study_cycle = ProtoField.uint16 ("dji_p3.center_brd_center_battery_common_last_study_cycle", "Last Study Cycle", base.HEX)
f.center_brd_center_battery_common_battery_on_charge = ProtoField.uint16 ("dji_p3.center_brd_center_battery_common_battery_on_charge", "Battery On Charge", base.HEX)

local function center_brd_center_battery_common_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.center_brd_center_battery_common_relative_capacity, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.center_brd_center_battery_common_current_pv, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.center_brd_center_battery_common_current_capacity, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.center_brd_center_battery_common_full_capacity, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.center_brd_center_battery_common_life, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.center_brd_center_battery_common_loop_num, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.center_brd_center_battery_common_error_type, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.center_brd_center_battery_common_current, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.center_brd_center_battery_common_unknown10, payload(offset, 12))
    offset = offset + 12

    subtree:add_le (f.center_brd_center_battery_common_serial_no, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.center_brd_center_battery_common_unknown1e, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.center_brd_center_battery_common_temperature, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.center_brd_center_battery_common_conn_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.center_brd_center_battery_common_total_study_cycle, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.center_brd_center_battery_common_last_study_cycle, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.center_brd_center_battery_common_battery_on_charge, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 41) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Center Battery Common: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Center Battery Common: Payload size different than expected") end
end

local CENTER_BRD_UART_CMD_DISSECT = {
    [0x06] = center_brd_center_battery_common_dissector,
}

-- Remote Control - Rc Params - 0x05

f.rc_rc_params_aileron = ProtoField.uint16 ("dji_p3.rc_rc_params_aileron", "Aileron", base.HEX)
f.rc_rc_params_elevator = ProtoField.uint16 ("dji_p3.rc_rc_params_elevator", "Elevator", base.HEX)
f.rc_rc_params_throttle = ProtoField.uint16 ("dji_p3.rc_rc_params_throttle", "Throttle", base.HEX)
f.rc_rc_params_rudder = ProtoField.uint16 ("dji_p3.rc_rc_params_rudder", "Rudder", base.HEX)
f.rc_rc_params_gyro_value = ProtoField.uint16 ("dji_p3.rc_rc_params_gyro_value", "Gyro Value", base.HEX)
f.rc_rc_params_wheel_info = ProtoField.uint8 ("dji_p3.rc_rc_params_wheel_info", "Wheel Info", base.HEX)
  f.rc_rc_params_wheel_click_status = ProtoField.uint8 ("dji_p3.rc_rc_params_wheel_click_status", "Wheel Click Status", base.HEX, nil, 0x01, nil)
  f.rc_rc_params_wheel_offset = ProtoField.uint8 ("dji_p3.rc_rc_params_wheel_offset", "Wheel Offset", base.HEX, nil, 0x3e, nil)
  f.rc_rc_params_not_wheel_positive = ProtoField.uint8 ("dji_p3.rc_rc_params_not_wheel_positive", "Not Wheel Positive", base.HEX, nil, 0x40, nil)
  f.rc_rc_params_wheel_changed = ProtoField.uint8 ("dji_p3.rc_rc_params_wheel_changed", "Wheel Changed", base.HEX, nil, 0x80, nil)
f.rc_rc_params_masked0b = ProtoField.uint8 ("dji_p3.rc_rc_params_masked0b", "Masked0B", base.HEX)
  f.rc_rc_params_go_home_button_pressed = ProtoField.uint8 ("dji_p3.rc_rc_params_go_home_button_pressed", "Go Home Button Pressed", base.HEX, nil, 0x08, nil)
  f.rc_rc_params_mode = ProtoField.uint8 ("dji_p3.rc_rc_params_mode", "Mode", base.HEX, nil, 0x30, nil)
  f.rc_rc_params_get_foot_stool = ProtoField.uint8 ("dji_p3.rc_rc_params_get_foot_stool", "Get Foot Stool", base.HEX, nil, 0xc0, nil)
f.rc_rc_params_masked0c = ProtoField.uint8 ("dji_p3.rc_rc_params_masked0c", "Masked0C", base.HEX)
  f.rc_rc_params_custom2 = ProtoField.uint8 ("dji_p3.rc_rc_params_custom2", "Custom2", base.HEX, nil, 0x08, nil)
  f.rc_rc_params_custom1 = ProtoField.uint8 ("dji_p3.rc_rc_params_custom1", "Custom1", base.HEX, nil, 0x10, nil)
  f.rc_rc_params_playback_status = ProtoField.uint8 ("dji_p3.rc_rc_params_playback_status", "PlayBack Status", base.HEX, nil, 0x20, nil)
  f.rc_rc_params_shutter_status = ProtoField.uint8 ("dji_p3.rc_rc_params_shutter_status", "Shutter Status", base.HEX, nil, 0x40, nil)
  f.rc_rc_params_record_status = ProtoField.uint8 ("dji_p3.rc_rc_params_record_status", "Record Status", base.HEX, nil, 0x80, nil)
f.rc_rc_params_band_width = ProtoField.uint8 ("dji_p3.rc_rc_params_band_width", "Band Width", base.HEX)

local function rc_rc_params_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.rc_rc_params_aileron, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_rc_params_elevator, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_rc_params_throttle, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_rc_params_rudder, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_rc_params_gyro_value, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_rc_params_wheel_info, payload(offset, 1))
    subtree:add_le (f.rc_rc_params_wheel_click_status, payload(offset, 1))
    subtree:add_le (f.rc_rc_params_wheel_offset, payload(offset, 1))
    subtree:add_le (f.rc_rc_params_not_wheel_positive, payload(offset, 1))
    subtree:add_le (f.rc_rc_params_wheel_changed, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_rc_params_masked0b, payload(offset, 1))
    subtree:add_le (f.rc_rc_params_go_home_button_pressed, payload(offset, 1))
    subtree:add_le (f.rc_rc_params_mode, payload(offset, 1))
    subtree:add_le (f.rc_rc_params_get_foot_stool, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_rc_params_masked0c, payload(offset, 1))
    subtree:add_le (f.rc_rc_params_custom2, payload(offset, 1))
    subtree:add_le (f.rc_rc_params_custom1, payload(offset, 1))
    subtree:add_le (f.rc_rc_params_playback_status, payload(offset, 1))
    subtree:add_le (f.rc_rc_params_shutter_status, payload(offset, 1))
    subtree:add_le (f.rc_rc_params_record_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_rc_params_band_width, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 14) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Rc Params: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Rc Params: Payload size different than expected") end
end

local RC_UART_CMD_DISSECT = {
    [0x05] = rc_rc_params_dissector,
}

-- Wi-Fi - Wifi Signal - 0x09

f.wifi_wifi_signal_signal = ProtoField.uint8 ("dji_p3.wifi_wifi_signal_signal", "Signal", base.HEX)

local function wifi_wifi_signal_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.wifi_wifi_signal_signal, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Wifi Signal: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Wifi Signal: Payload size different than expected") end
end

-- Wi-Fi - Wifi First App Mac - 0x11

f.wifi_wifi_first_app_mac_mac = ProtoField.ether ("dji_p3.wifi_wifi_first_app_mac_mac", "Mac")

local function wifi_wifi_first_app_mac_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.wifi_wifi_first_app_mac_mac, payload(offset, 6))
    offset = offset + 6

    if (offset ~= 6) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Wifi First App Mac: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Wifi First App Mac: Payload size different than expected") end
end

-- Wi-Fi - Wifi Elec Signal - 0x12

enums.WIFI_ELEC_SIGNAL_SIGNAL_STATUS_ENUM = {
    [0x00] = 'Good',
    [0x01] = 'Medium',
    [0x02] = 'Poor',
    [0x64] = 'OTHER',
}

f.wifi_wifi_elec_signal_signal_status = ProtoField.uint8 ("dji_p3.wifi_wifi_elec_signal_signal_status", "Signal Status", base.HEX, enums.WIFI_ELEC_SIGNAL_SIGNAL_STATUS_ENUM, nil, nil)

local function wifi_wifi_elec_signal_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.wifi_wifi_elec_signal_signal_status, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Wifi Elec Signal: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Wifi Elec Signal: Payload size different than expected") end
end

-- Wi-Fi - Wifi Sweep Frequency - 0x2a

f.wifi_wifi_sweep_frequency_total = ProtoField.uint32 ("dji_p3.wifi_wifi_sweep_frequency_total", "Total", base.HEX)

local function wifi_wifi_sweep_frequency_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.wifi_wifi_sweep_frequency_total, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Wifi Sweep Frequency: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Wifi Sweep Frequency: Payload size different than expected") end
end

local WIFI_UART_CMD_DISSECT = {
    [0x09] = wifi_wifi_signal_dissector,
    [0x11] = wifi_wifi_first_app_mac_dissector,
    [0x12] = wifi_wifi_elec_signal_dissector,
    [0x2a] = wifi_wifi_sweep_frequency_dissector,
}

-- DM36x proc. - Dm368 Status - 0x06

f.dm36x_dm368_status_unknown00 = ProtoField.bytes ("dji_p3.dm36x_dm368_status_unknown00", "Unknown00", base.SPACE)
f.dm36x_dm368_status_disable_liveview = ProtoField.uint8 ("dji_p3.dm36x_dm368_status_disable_liveview", "Disable Liveview", base.HEX)
f.dm36x_dm368_status_encode_mode = ProtoField.uint8 ("dji_p3.dm36x_dm368_status_encode_mode", "Encode Mode", base.HEX)
f.dm36x_dm368_status_dual_encode_mode_percentage = ProtoField.uint8 ("dji_p3.dm36x_dm368_status_dual_encode_mode_percentage", "Dual Encode Mode Percentage", base.HEX)

local function dm36x_dm368_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.dm36x_dm368_status_unknown00, payload(offset, 3))
    offset = offset + 3

    subtree:add_le (f.dm36x_dm368_status_disable_liveview, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.dm36x_dm368_status_encode_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.dm36x_dm368_status_dual_encode_mode_percentage, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 6) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Dm368 Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Dm368 Status: Payload size different than expected") end
end

local DM36X_UART_CMD_DISSECT = {
    [0x06] = dm36x_dm368_status_dissector,
}

-- HD Link - Set transciever register packet - 0x06

f.hd_link_transciever_reg_addr = ProtoField.uint16 ("dji_p3.hd_link_transciever_reg_set", "Register addr", base.HEX, nil, nil, "AD9363 register address")
f.hd_link_transciever_reg_val = ProtoField.uint8 ("dji_p3.hd_link_transciever_reg_val", "Register value", base.HEX, nil, nil, "AD9363 register value")

local function hd_link_set_transciever_reg_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --TODO verify
    offset = offset + 2

    subtree:add_le (f.hd_link_transciever_reg_addr, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.hd_link_transciever_reg_val, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Set Transciever Reg: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Set Transciever Reg: Payload size different than expected") end
end

-- HD Link - Osd Signal Quality - 0x08

f.hd_link_osd_signal_quality_masked00 = ProtoField.uint8 ("dji_p3.hd_link_osd_signal_quality_masked00", "Masked00", base.HEX)
  f.hd_link_osd_signal_quality_up_signal_quality = ProtoField.uint8 ("dji_p3.hd_link_osd_signal_quality_up_signal_quality", "Up Signal Quality", base.HEX, nil, 0x7f, nil)

local function hd_link_osd_signal_quality_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_osd_signal_quality_masked00, payload(offset, 1))
    subtree:add_le (f.hd_link_osd_signal_quality_up_signal_quality, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Signal Quality: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Signal Quality: Payload size different than expected") end
end

-- HD Link - Osd Sweep Frequency - 0x0a

--f.hd_link_osd_sweep_frequency_unknown0 = ProtoField.none ("dji_p3.hd_link_osd_sweep_frequency_unknown0", "Unknown0", base.NONE)

local function hd_link_osd_sweep_frequency_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Sweep Frequency: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Sweep Frequency: Payload size different than expected") end
end

-- HD Link - Osd Devices State - 0x0b

f.hd_link_osd_devices_state_unknown0 = ProtoField.uint8 ("dji_p3.hd_link_osd_devices_state_unknown0", "Unknown0", base.HEX)
f.hd_link_osd_devices_state_unknown1 = ProtoField.uint32 ("dji_p3.hd_link_osd_devices_state_unknown1", "Unknown1", base.DEC)

local function hd_link_osd_devices_state_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    local num_entries = math.floor(payload:len() / 5)

    local i = 0
    repeat

        subtree:add_le (f.hd_link_osd_devices_state_unknown0, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.hd_link_osd_devices_state_unknown1, payload(offset, 4))
        offset = offset + 4

        i = i + 1

    until i >= num_entries

    if (offset ~= num_entries * 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Devices State: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Devices State: Payload size different than expected") end
end

-- HD Link - Osd Config - 0x0c

f.hd_link_osd_config_channel = ProtoField.uint8 ("dji_p3.hd_link_osd_config_channel", "Channel", base.HEX)
f.hd_link_osd_config_unknown01 = ProtoField.uint8 ("dji_p3.hd_link_osd_config_unknown01", "Unknown01", base.HEX)
f.hd_link_osd_config_get_is_auto = ProtoField.uint8 ("dji_p3.hd_link_osd_config_get_is_auto", "Get Is Auto", base.HEX)
f.hd_link_osd_config_get_is_master = ProtoField.uint8 ("dji_p3.hd_link_osd_config_get_is_master", "Get Is Master", base.HEX)
f.hd_link_osd_config_unknown04 = ProtoField.bytes ("dji_p3.hd_link_osd_config_unknown04", "Unknown04", base.SPACE)
f.hd_link_osd_config_mcs = ProtoField.uint8 ("dji_p3.hd_link_osd_config_mcs", "Mcs", base.HEX)
f.hd_link_osd_config_single_or_double = ProtoField.uint8 ("dji_p3.hd_link_osd_config_single_or_double", "Single Or Double", base.HEX, nil, nil)
f.hd_link_osd_config_band_width_percent = ProtoField.uint8 ("dji_p3.hd_link_osd_config_band_width_percent", "Band Width Percent", base.DEC)
f.hd_link_osd_config_unknown0c = ProtoField.bytes ("dji_p3.hd_link_osd_config_unknown0c", "Unknown0C", base.SPACE)
f.hd_link_osd_config_working_freq = ProtoField.uint8 ("dji_p3.hd_link_osd_config_working_freq", "Working Freq", base.HEX)

local function hd_link_osd_config_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_osd_config_channel, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osd_config_unknown01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osd_config_get_is_auto, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osd_config_get_is_master, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osd_config_unknown04, payload(offset, 5))
    offset = offset + 5

    subtree:add_le (f.hd_link_osd_config_mcs, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osd_config_single_or_double, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osd_config_band_width_percent, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osd_config_unknown0c, payload(offset, 3))
    offset = offset + 3

    subtree:add_le (f.hd_link_osd_config_working_freq, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 16) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Config: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Config: Payload size different than expected") end
end

-- HD Link - Osd Channal Status - 0x11

enums.HD_LINK_OSD_CHANNAL_STATUS_CHANNEL_STATUS_ENUM = {
    [0x00] = 'Excellent',
    [0x01] = 'Good',
    [0x02] = 'Medium',
    [0x03] = 'Poor',
    [0x64] = 'OTHER',
}

f.hd_link_osd_channal_status_channel_status = ProtoField.uint8 ("dji_p3.hd_link_osd_channal_status_channel_status", "Channel Status", base.HEX, enums.HD_LINK_OSD_CHANNAL_STATUS_CHANNEL_STATUS_ENUM, nil, nil)

local function hd_link_osd_channal_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_osd_channal_status_channel_status, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Channal Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Channal Status: Payload size different than expected") end
end

-- HD Link - Osd Max Mcs - 0x15

f.hd_link_osd_max_mcs_max_mcs = ProtoField.uint8 ("dji_p3.hd_link_osd_max_mcs_max_mcs", "Max Mcs", base.HEX)

local function hd_link_osd_max_mcs_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_osd_max_mcs_max_mcs, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Max Mcs: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Max Mcs: Payload size different than expected") end
end

-- HD Link - Osd Debug Info - 0x16

f.hd_link_osd_debug_info_type = ProtoField.uint8 ("dji_p3.hd_link_osd_debug_info_type", "Type", base.HEX, nil, nil, "TODO values from enum P3.DataOsdGetPushDebugInfo")

local function hd_link_osd_debug_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_osd_debug_info_type, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Debug Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Debug Info: Payload size different than expected") end
end

-- HD Link - Osd Sdr Sweep Frequency - 0x20

--f.hd_link_osd_sdr_sweep_frequency_unknown0 = ProtoField.none ("dji_p3.hd_link_osd_sdr_sweep_frequency_unknown0", "Unknown0", base.NONE)

local function hd_link_osd_sdr_sweep_frequency_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Sdr Sweep Frequency: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Sdr Sweep Frequency: Payload size different than expected") end
end

-- HD Link - Osd Sdr Config Info - 0x22

f.hd_link_osd_sdr_config_info_nf = ProtoField.uint16 ("dji_p3.hd_link_osd_sdr_config_info_nf", "NF", base.DEC)
f.hd_link_osd_sdr_config_info_band = ProtoField.uint8 ("dji_p3.hd_link_osd_sdr_config_info_band", "Band", base.DEC)
f.hd_link_osd_sdr_config_info_unknown3 = ProtoField.uint8 ("dji_p3.hd_link_osd_sdr_config_info_unknown3", "Unknown3", base.HEX)
f.hd_link_osd_sdr_config_info_auto_mcs = ProtoField.float ("dji_p3.hd_link_osd_sdr_config_info_auto_mcs", "Auto Mcs", base.DEC)
f.hd_link_osd_sdr_config_info_mcs_type = ProtoField.uint8 ("dji_p3.hd_link_osd_sdr_config_info_mcs_type", "Mcs Type", base.HEX)

local function hd_link_osd_sdr_config_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_osd_sdr_config_info_nf, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.hd_link_osd_sdr_config_info_band, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osd_sdr_config_info_unknown3, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osd_sdr_config_info_auto_mcs, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hd_link_osd_sdr_config_info_mcs_type, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 9) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Sdr Config Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Sdr Config Info: Payload size different than expected") end
end

-- HD Link - Osd Sdr Status Info - 0x24
-- HD Link - Osd Sdr Status Ground Info - 0x25

f.hd_link_osd_sdr_status_info_name = ProtoField.string ("dji_p3.hd_link_osd_sdr_status_info_name", "Name", base.NONE)
f.hd_link_osd_sdr_status_info_value = ProtoField.float ("dji_p3.hd_link_osd_sdr_status_info_value", "Value", base.DEC)

local function hd_link_osd_sdr_status_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    local num_entries = math.floor(payload:len() / 12)

    local i = 0
    repeat

        subtree:add_le (f.hd_link_osd_sdr_status_info_name, payload(offset, 8))
        offset = offset + 8

        subtree:add_le (f.hd_link_osd_sdr_status_info_value, payload(offset, 4))
        offset = offset + 4

        i = i + 1

    until i >= num_entries

    if (offset ~= num_entries * 12) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Sdr Status Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Sdr Status Info: Payload size different than expected") end
end

-- HD Link - Osd Sdr Upward Sweep Frequency - 0x29

--f.hd_link_osd_sdr_upward_sweep_frequency_unknown0 = ProtoField.none ("dji_p3.hd_link_osd_sdr_upward_sweep_frequency_unknown0", "Unknown0", base.NONE)

local function hd_link_osd_sdr_upward_sweep_frequency_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Sdr Upward Sweep Frequency: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Sdr Upward Sweep Frequency: Payload size different than expected") end
end

-- HD Link - Osd Sdr Upward Select Channel - 0x2a

f.hd_link_osd_sdr_upward_select_channel_select_channel_type = ProtoField.float ("dji_p3.hd_link_osd_sdr_upward_select_channel_select_channel_type", "Select Channel Type", base.DEC)
f.hd_link_osd_sdr_upward_select_channel_get_select_channel_count = ProtoField.uint32 ("dji_p3.hd_link_osd_sdr_upward_select_channel_get_select_channel_count", "Get Select Channel Count", base.HEX)

local function hd_link_osd_sdr_upward_select_channel_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_osd_sdr_upward_select_channel_select_channel_type, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hd_link_osd_sdr_upward_select_channel_get_select_channel_count, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Sdr Upward Select Channel: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Sdr Upward Select Channel: Payload size different than expected") end
end

-- HD Link - Osd Wireless State - 0x30

enums.HD_LINK_OSD_WIRELESS_STATE_EVENT_CODE_SDR_WIRELESS_STATE_ENUM = {
    [0x00] = 'STRONG_DISTURBANCE',
    [0x01] = 'VIDEO_DISTURBANCE',
    [0x02] = 'RC_DISTURBANCE',
    [0x03] = 'LOW_SIGNAL_POWER',
    [0x04] = 'CUSTOM_SIGNAL_DISTURBANCE',
    [0x05] = 'RC_TO_GLASS_DIST',
    [0x06] = 'UAV_HAL_RESTART',
    [0x07] = 'GLASS_DIST_RC_ANTENNA',
    [0x08] = 'DISCONNECT_RC_DISTURB',
    [0x09] = 'DISCONNECT_UAV_DISTURB',
    [0x0a] = 'DISCONNECT_WEEK_SIGNAL',
    [0xff] = 'INTERNAL_EVENT',
    [0x100] = 'NONE',
}

f.hd_link_osd_wireless_state_event_code = ProtoField.uint16 ("dji_p3.hd_link_osd_wireless_state_event_code", "Event Code", base.HEX, enums.HD_LINK_OSD_WIRELESS_STATE_EVENT_CODE_SDR_WIRELESS_STATE_ENUM, nil, nil)

local function hd_link_osd_wireless_state_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_osd_wireless_state_event_code, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Wireless State: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Wireless State: Payload size different than expected") end
end

-- HD Link - Osd Sdr Push Custom Code Rate - 0x36

f.hd_link_osd_sdr_push_custom_code_rate_code_rate = ProtoField.float ("dji_p3.hd_link_osd_sdr_push_custom_code_rate_code_rate", "Code Rate", base.DEC)

local function hd_link_osd_sdr_push_custom_code_rate_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_osd_sdr_push_custom_code_rate_code_rate, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Sdr Push Custom Code Rate: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Sdr Push Custom Code Rate: Payload size different than expected") end
end

-- HD Link - Osd Hdvt Push Exception - 0x37

f.hd_link_osd_hdvt_push_exception_masked00 = ProtoField.uint8 ("dji_p3.hd_link_osd_hdvt_push_exception_masked00", "Masked00", base.HEX)
  f.hd_link_osd_hdvt_push_exception_post = ProtoField.uint8 ("dji_p3.hd_link_osd_hdvt_push_exception_post", "Post", base.HEX, nil, 0x01, nil)

local function hd_link_osd_hdvt_push_exception_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_osd_hdvt_push_exception_masked00, payload(offset, 1))
    subtree:add_le (f.hd_link_osd_hdvt_push_exception_post, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Hdvt Push Exception: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Hdvt Push Exception: Payload size different than expected") end
end

-- HD Link - Osd Sdr Nf Params - 0x3a

enums.HD_LINK_OSD_SDR_NF_PARAMS_DIS_LOSS_IND_DIS_LOSS_EVENT_ENUM = {
    [0x00] = 'NONE',
    [0x01] = 'GROUND_INTERFERED',
    [0x02] = 'UAV_INTERFERED',
    [0x03] = 'SIGNAL_BLOCK',
}

f.hd_link_osd_sdr_nf_params_1_km_offset = ProtoField.uint8 ("dji_p3.hd_link_osd_sdr_nf_params_1_km_offset", "1 Km Offset", base.HEX, nil, nil, "value bias  - 256")
f.hd_link_osd_sdr_nf_params_path_loss_offset = ProtoField.uint8 ("dji_p3.hd_link_osd_sdr_nf_params_path_loss_offset", "Path Loss Offset", base.HEX)
f.hd_link_osd_sdr_nf_params_rc_link_offset = ProtoField.uint8 ("dji_p3.hd_link_osd_sdr_nf_params_rc_link_offset", "Rc Link Offset", base.HEX)
f.hd_link_osd_sdr_nf_params_tx_power_offset = ProtoField.uint8 ("dji_p3.hd_link_osd_sdr_nf_params_tx_power_offset", "Tx Power Offset", base.HEX)
f.hd_link_osd_sdr_nf_params_dis_loss_ind = ProtoField.uint8 ("dji_p3.hd_link_osd_sdr_nf_params_dis_loss_ind", "Dis Loss Ind", base.HEX, enums.HD_LINK_OSD_SDR_NF_PARAMS_DIS_LOSS_IND_DIS_LOSS_EVENT_ENUM, nil, nil)
f.hd_link_osd_sdr_nf_params_sig_bar_ind = ProtoField.uint8 ("dji_p3.hd_link_osd_sdr_nf_params_sig_bar_ind", "Sig Bar Ind", base.HEX)
f.hd_link_osd_sdr_nf_params_dl_pwr_accu = ProtoField.uint8 ("dji_p3.hd_link_osd_sdr_nf_params_dl_pwr_accu", "Dl Pwr Accu", base.HEX)
f.hd_link_osd_sdr_nf_params_max_nf20_m = ProtoField.uint16 ("dji_p3.hd_link_osd_sdr_nf_params_max_nf20_m", "Max Nf20 M", base.HEX)
f.hd_link_osd_sdr_nf_params_min_nf20_m = ProtoField.uint16 ("dji_p3.hd_link_osd_sdr_nf_params_min_nf20_m", "Min Nf20 M", base.HEX)
f.hd_link_osd_sdr_nf_params_max_nf10_m = ProtoField.uint16 ("dji_p3.hd_link_osd_sdr_nf_params_max_nf10_m", "Max Nf10 M", base.HEX)
f.hd_link_osd_sdr_nf_params_min_nf10_m = ProtoField.uint16 ("dji_p3.hd_link_osd_sdr_nf_params_min_nf10_m", "Min Nf10 M", base.HEX)

local function hd_link_osd_sdr_nf_params_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_osd_sdr_nf_params_1_km_offset, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osd_sdr_nf_params_path_loss_offset, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osd_sdr_nf_params_rc_link_offset, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osd_sdr_nf_params_tx_power_offset, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osd_sdr_nf_params_dis_loss_ind, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osd_sdr_nf_params_sig_bar_ind, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osd_sdr_nf_params_dl_pwr_accu, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osd_sdr_nf_params_max_nf20_m, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.hd_link_osd_sdr_nf_params_min_nf20_m, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.hd_link_osd_sdr_nf_params_max_nf10_m, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.hd_link_osd_sdr_nf_params_min_nf10_m, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 15) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Sdr Nf Params: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Sdr Nf Params: Payload size different than expected") end
end

-- HD Link - Osd Sdr Bar Interference - 0x3b

f.hd_link_osd_sdr_bar_interference_be_interfered = ProtoField.uint8 ("dji_p3.hd_link_osd_sdr_bar_interference_be_interfered", "Be Interfered", base.HEX)

local function hd_link_osd_sdr_bar_interference_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_osd_sdr_bar_interference_be_interfered, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Sdr Bar Interference: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Sdr Bar Interference: Payload size different than expected") end
end

-- HD Link - Osd Power Status - 0x52

f.hd_link_osd_power_status_power_status = ProtoField.uint8 ("dji_p3.hd_link_osd_power_status_power_status", "Power Status", base.HEX)
f.hd_link_osd_power_status_get_is_power_off = ProtoField.uint8 ("dji_p3.hd_link_osd_power_status_get_is_power_off", "Get Is Power Off", base.HEX)

local function hd_link_osd_power_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_osd_power_status_power_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osd_power_status_get_is_power_off, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Power Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Power Status: Payload size different than expected") end
end

-- HD Link - Osd Osmo Calibration - 0x54

f.hd_link_osd_osmo_calibration_a = ProtoField.uint8 ("dji_p3.hd_link_osd_osmo_calibration_a", "A", base.HEX)
f.hd_link_osd_osmo_calibration_b = ProtoField.uint8 ("dji_p3.hd_link_osd_osmo_calibration_b", "B", base.HEX)

local function hd_link_osd_osmo_calibration_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_osd_osmo_calibration_a, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osd_osmo_calibration_b, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Osmo Calibration: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Osmo Calibration: Payload size different than expected") end
end

-- HD Link - Osd Mic Info - 0x59

enums.HD_LINK_OSD_MIC_INFO_MIC_TYPE_ENUM = {
    [0x00] = 'IN',
    [0x01] = 'OUT',
    [0x02] = 'OTHER',
}

f.hd_link_osd_mic_info_masked00 = ProtoField.uint8 ("dji_p3.hd_link_osd_mic_info_masked00", "Masked00", base.HEX)
  f.hd_link_osd_mic_info_mic_type = ProtoField.uint8 ("dji_p3.hd_link_osd_mic_info_mic_type", "Mic Type", base.HEX, enums.HD_LINK_OSD_MIC_INFO_MIC_TYPE_ENUM, 0x01, nil)
  f.hd_link_osd_mic_info_mic_volume = ProtoField.uint8 ("dji_p3.hd_link_osd_mic_info_mic_volume", "Mic Volume", base.HEX, nil, 0xfe, nil)

local function hd_link_osd_mic_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_osd_mic_info_masked00, payload(offset, 1))
    subtree:add_le (f.hd_link_osd_mic_info_mic_type, payload(offset, 1))
    subtree:add_le (f.hd_link_osd_mic_info_mic_volume, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Mic Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Mic Info: Payload size different than expected") end
end

local HD_LINK_UART_CMD_DISSECT = {
    [0x01] = flyc_osd_general_dissector,
    [0x02] = flyc_osd_home_dissector,
    [0x06] = hd_link_set_transciever_reg_dissector,
    [0x08] = hd_link_osd_signal_quality_dissector,
    [0x0a] = hd_link_osd_sweep_frequency_dissector,
    [0x0b] = hd_link_osd_devices_state_dissector,
    [0x0c] = hd_link_osd_config_dissector,
    [0x11] = hd_link_osd_channal_status_dissector,
    [0x15] = hd_link_osd_max_mcs_dissector,
    [0x16] = hd_link_osd_debug_info_dissector,
    [0x20] = hd_link_osd_sdr_sweep_frequency_dissector,
    [0x22] = hd_link_osd_sdr_config_info_dissector,
    [0x24] = hd_link_osd_sdr_status_info_dissector,
    [0x25] = hd_link_osd_sdr_status_info_dissector, -- Ground version is the same as air version
    [0x29] = hd_link_osd_sdr_upward_sweep_frequency_dissector,
    [0x2a] = hd_link_osd_sdr_upward_select_channel_dissector,
    [0x30] = hd_link_osd_wireless_state_dissector,
    [0x36] = hd_link_osd_sdr_push_custom_code_rate_dissector,
    [0x37] = hd_link_osd_hdvt_push_exception_dissector,
    [0x3a] = hd_link_osd_sdr_nf_params_dissector,
    [0x3b] = hd_link_osd_sdr_bar_interference_dissector,
    [0x52] = hd_link_osd_power_status_dissector,
    [0x54] = hd_link_osd_osmo_calibration_dissector,
    [0x59] = hd_link_osd_mic_info_dissector,
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
