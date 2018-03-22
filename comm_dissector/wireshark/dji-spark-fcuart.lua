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

local CAMERA_CMDS = {
}

local FLIGHT_CTRL_CMDS = {
}

local GIMBAL_CMDS = {
}

local CENTER_BRD_CMDS = {
}

local RC_CMDS = {
}

local WIFI_CMDS = {
    [0x30] = 'Set Region',
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

local BATTERY_CMDS = {
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
