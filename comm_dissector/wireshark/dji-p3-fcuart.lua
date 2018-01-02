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

    if (offset ~= 3) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Flyc Forbid Status: Offset does not match - internal inconsistency") end
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

enums.FLYC_OSD_COMMON_FLYC_STATE_ENUM = {
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
    [0x5e] = 'Takeoff Exception',
    [0x5f] = 'Esc Stall Near Ground',
    [0x60] = 'Esc Unbalance On Grd',
    [0x61] = 'Esc Part Empty On Grd',
    [0x62] = 'Engine Start Failed',
    [0x63] = 'Auto Takeoff Lanch Failed',
    [0x64] = 'Roll Over On Grd',
    [0x66] = 'RTK Bad Signal',
    [0x67] = 'RTK Deviation Error',
    [0x65] = 'Bat Version Error',
    [0x72] = 'Gimbal Is Calibrating',
    [0x100]= 'Other',
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
  f.flyc_osd_general_fc_state = ProtoField.uint8 ("dji_p3.flyc_osd_general_fc_state", "FC State", base.HEX, enums.FLYC_OSD_COMMON_FLYC_STATE_ENUM, 0x7F, "Flight Controller state1")
  f.flyc_osd_general_rc_state = ProtoField.uint8 ("dji_p3.flyc_osd_general_rc_state", "RC State", base.HEX, nil, 0x80, nil)
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
  f.flyc_osd_general_e_still_heating = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_still_heating", "E Still Heating", base.HEX, nil, 0x1000, nil)
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
  f.flyc_osd_general_e_propeller_catapult = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_propeller_catapult", "E Is Propeller Catapult", base.HEX, nil, 0x20000000, nil)
  f.flyc_osd_general_e_gohome_height_mod = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_gohome_height_mod", "E GoHome Height Mod", base.HEX, nil, 0x40000000, "Go Home Height is Modified")
  f.flyc_osd_general_e_out_of_limit = ProtoField.uint32 ("dji_p3.flyc_osd_general_e_out_of_limit", "E Is Out Of Limit", base.HEX, nil, 0x80000000, nil)
f.flyc_osd_general_gps_nums = ProtoField.uint8 ("dji_p3.flyc_osd_general_gps_nums", "Gps Nums", base.DEC, nil, nil, "Number of Global Nav System positioning satellites")
f.flyc_osd_general_gohome_landing_reason = ProtoField.uint8 ("dji_p3.flyc_osd_general_gohome_landing_reason", "Gohome or Landing Reason", base.HEX, enums.FLYC_OSD_GENERAL_GOHOME_REASON_ENUM, nil, "Reason for automatic GoHome or Landing")
f.flyc_osd_general_start_fail_state = ProtoField.uint8 ("dji_p3.flyc_osd_general_start_fail_state", "Motor Start Failure State", base.HEX)
  f.flyc_osd_general_start_fail_reason = ProtoField.uint8 ("dji_p3.flyc_osd_general_start_fail_reason", "Motor Start Fail Reason", base.HEX, enums.FLYC_OSD_GENERAL_START_FAIL_REASON_ENUM, 0x7f, "Reason for failure to start motors")
  f.flyc_osd_common_start_fail_happened = ProtoField.uint8 ("dji_p3.flyc_osd_common_start_fail_happened", "Motor Start Fail Happened", base.HEX, nil, 0x80, nil)
f.flyc_osd_general_controller_state_ext = ProtoField.uint8 ("dji_p3.flyc_osd_general_controller_state_ext", "Controller State Ext", base.HEX)
  f.flyc_osd_general_e_gps_state = ProtoField.uint8 ("dji_p3.flyc_osd_general_e_gps_state", "E Gps State", base.HEX, enums.FLYC_OSD_GENERAL_GPS_STATE_ENUM, 0x0f, nil)
  f.flyc_osd_general_e_wp_limit_md = ProtoField.uint8 ("dji_p3.flyc_osd_general_e_wp_limit_md", "E Wp Limit Mode", base.HEX, nil, 0x10, "Waypoint Limit Mode")
f.flyc_osd_general_batt_remain = ProtoField.uint8 ("dji_p3.flyc_osd_general_batt_remain", "Battery Remain", base.DEC, nil, nil, "Battery Remaining Capacity")
f.flyc_osd_general_ultrasonic_height = ProtoField.uint8 ("dji_p3.flyc_osd_general_ultrasonic_height", "Ultrasonic Height", base.DEC, nil, nil, "Height as reported by ultrasonic sensor")
f.flyc_osd_general_motor_startup_time = ProtoField.uint16 ("dji_p3.flyc_osd_general_motor_startup_time", "Motor Started Time", base.DEC)
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
--f.flyc_osd_common_motor_fail_reason = ProtoField.uint8 ("dji_p3.flyc_osd_common_motor_fail_reason", "Motor Fail Reason", base.HEX, enums.FLYC_OSD_COMMON_MOTOR_FAIL_REASON_ENUM, nil, nil)
--f.flyc_osd_common_masked33 = ProtoField.uint8 ("dji_p3.flyc_osd_common_masked33", "Masked33", base.HEX)
--  f.flyc_osd_common_motor_start_cause_no_start_action = ProtoField.uint8 ("dji_p3.flyc_osd_common_motor_start_cause_no_start_action", "Motor Start Cause No Start Action", base.HEX, enums.FLYC_OSD_COMMON_MOTOR_START_CAUSE_NO_START_ACTION_MOTOR_START_FAILED_CAUSE_ENUM, 0xff, nil)
--f.flyc_osd_common_sdk_ctrl_device = ProtoField.uint8 ("dji_p3.flyc_osd_common_sdk_ctrl_device", "Sdk Ctrl Device", base.HEX, enums.FLYC_OSD_COMMON_SDK_CTRL_DEVICE_ENUM, nil, nil)

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
    subtree:add_le (f.flyc_osd_general_fc_state, payload(offset, 1))
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
  f.flyc_osd_home_e_homepoint_set = ProtoField.uint16 ("dji_p3.flyc_osd_home_e_homepoint_set", "E Homepoint Set", base.HEX, nil, 0x01, nil)
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
  f.flyc_osd_home_ver1_height_limit_status = ProtoField.uint16 ("dji_p3.flyc_osd_home_ver1_height_limit_status", "Height Limit Status", base.HEX, enums.FLYC_OSD_HOME_HEIGHT_LIMIT_STATUS_ENUM, 0x1f, nil)
  f.flyc_osd_home_ver1_use_absolute_height = ProtoField.uint16 ("dji_p3.flyc_osd_home_ver1_use_absolute_height", "Use Absolute Height", base.HEX, nil, 0x20, nil)
-- Version of the packet from older firmwares, 68 bytes long
f.flyc_osd_home_masked20 = ProtoField.uint32 ("dji_p3.flyc_osd_home_masked20", "Masked20", base.HEX)
  f.flyc_osd_home_flyc_in_simulation_mode = ProtoField.uint32 ("dji_p3.flyc_osd_home_flyc_in_simulation_mode", "Flyc In Simulation Mode", base.HEX, nil, 0x01, nil)
  f.flyc_osd_home_flyc_in_navigation_mode = ProtoField.uint32 ("dji_p3.flyc_osd_home_flyc_in_navigation_mode", "Flyc In Navigation Mode", base.HEX, nil, 0x02, nil)
  f.flyc_osd_home_height_limit_status = ProtoField.uint32 ("dji_p3.flyc_osd_home_height_limit_status", "Height Limit Status", base.HEX, enums.FLYC_OSD_HOME_HEIGHT_LIMIT_STATUS_ENUM, 0x1f, nil)
  f.flyc_osd_home_use_absolute_height = ProtoField.uint32 ("dji_p3.flyc_osd_home_use_absolute_height", "Use Absolute Height", base.HEX, nil, 0x20, nil)
  f.flyc_osd_home_wing_broken = ProtoField.uint32 ("dji_p3.flyc_osd_home_wing_broken", "Wing Broken", base.HEX, nil, 0x1000, nil)
  f.flyc_osd_home_big_gale = ProtoField.uint32 ("dji_p3.flyc_osd_home_big_gale", "Big Gale", base.HEX, nil, 0x4000, nil)
  f.flyc_osd_home_big_gale_warning = ProtoField.uint32 ("dji_p3.flyc_osd_home_big_gale_warning", "Big Gale Warning", base.HEX, nil, 0x100000, nil)
  f.flyc_osd_home_compass_install_err = ProtoField.uint32 ("dji_p3.flyc_osd_home_compass_install_err", "Compass Install Err", base.HEX, nil, 0x800000, nil)
f.flyc_osd_home_height_limit_value = ProtoField.float ("dji_p3.flyc_osd_home_height_limit_value", "Height Limit Value", base.DEC)
f.flyc_osd_home_unknown28 = ProtoField.bytes ("dji_p3.flyc_osd_home_unknown28", "Unknown28", base.SPACE)
f.flyc_osd_home_force_landing_height = ProtoField.uint8 ("dji_p3.flyc_osd_home_force_landing_height", "Force Landing Height", base.HEX)
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
        subtree:add_le (f.flyc_osd_home_ver1_height_limit_status, payload(offset, 2))
        subtree:add_le (f.flyc_osd_home_ver1_use_absolute_height, payload(offset, 2))
        offset = offset + 2

        if (offset ~= 34) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Home: Offset does not match - internal inconsistency") end

    else

        subtree:add_le (f.flyc_osd_home_masked20, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_flyc_in_simulation_mode, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_flyc_in_navigation_mode, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_height_limit_status, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_use_absolute_height, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_wing_broken, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_big_gale, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_big_gale_warning, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_compass_install_err, payload(offset, 4))
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

-- Flight Controller - Imu Data Status - 0x50, identical to flight recorder packet 0x0013

f.flyc_imu_data_status_start_fan = ProtoField.uint8 ("dji_p3.flyc_imu_data_status_start_fan", "Start Fan", base.HEX, nil, nil, "On Ph3, always 1")
f.flyc_imu_data_status_led_status = ProtoField.uint8 ("dji_p3.flyc_imu_data_status_led_status", "Led Status", base.HEX, nil, nil, "On Ph3, always 0")

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

local FLYC_UART_CMD_DISSECT = {
    [0x09] = flyc_flyc_forbid_status_dissector,
    [0x10] = flyc_a2_commom_dissector,
    [0x32] = flyc_flyc_deform_status_dissector,
    [0x3e] = flyc_flyc_request_limit_update_dissector,
    [0x42] = flyc_flyc_unlimit_state_dissector,
    [0x43] = flyc_osd_general_dissector,
    [0x44] = flyc_osd_home_dissector,
    [0x50] = flyc_imu_data_status_dissector,
    [0x57] = flyc_gps_glns_dissector,
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
