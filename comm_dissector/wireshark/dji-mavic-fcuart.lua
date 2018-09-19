local f = DJI_MAVIC_PROTO.fields
local enums = {}

DJI_MAVIC_FLIGHT_CONTROL_UART_SRC_DEST = {
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

DJI_MAVIC_FLIGHT_CONTROL_UART_ENCRYPT_TYPE = {
    [0]='None',
    [2]='SeqHash2',
}

DJI_MAVIC_FLIGHT_CONTROL_UART_ACK_TYPE = {
    [0] = 'No ACK',
    [1] = 'Push',
    [2] = 'ACK',
}

DJI_MAVIC_FLIGHT_CONTROL_UART_PACKET_TYPE = {
    [0] = 'Request',
    [1] = 'Response',
}

DJI_MAVIC_FLIGHT_CONTROL_UART_CMD_SET = {
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
    [0x0E] = 'Text Message',
    [0x32] = 'Activation Action',
    [0x4a] = 'Set Date/Time',
}

local SPECIAL_CMDS = {
}

local CAMERA_CMDS = {
}

local FLIGHT_CTRL_CMDS = {
    [0xf9] = 'Write Old Flyc Param By Hash',
}

local GIMBAL_CMDS = {
}

local CENTER_BRD_CMDS = {
}

local RC_CMDS = {
}

local WIFI_CMDS = {
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
    [0x02] = 'Battery State',
    [0x03] = 'Battery Cell State',
}

local DATA_LOG_CMDS = {
    [0x22] = 'Battery State',
    [0x23] = 'Battery Message',
}

local RTK_CMDS = {
}

local AUTO_CMDS = {
}

DJI_MAVIC_FLIGHT_CONTROL_UART_CMD_TYPE = {
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

-- Text Message packet
f.general_text_msg_unk1 = ProtoField.bytes ("dji_mavic.general_text_msg_unknown1", "Unknown", base.SPACE)
f.general_text_msg_message = ProtoField.string ("dji_mavic.general_text_msg_message", "Message", base.ASCII)

local function main_general_text_msg_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add (f.general_text_msg_unk1, payload(offset, 1))
    offset = offset + 1

    local message_len = payload:len() - offset
    subtree:add_le (f.general_text_msg_message, payload(offset, message_len))
end

-- Activation Action packet
f.general_activation_actn_action = ProtoField.uint8 ("dji_mavic.general_activation_actn_action", "Action", base.HEX)
f.general_activation_actn_state = ProtoField.uint8 ("dji_mavic.general_activation_actn_state", "State", base.HEX)
f.general_activation_actn_year = ProtoField.uint16 ("dji_mavic.general_activation_actn_year", "Year", base.DEC)
f.general_activation_actn_month = ProtoField.uint8 ("dji_mavic.general_activation_actn_month", "Month", base.DEC)
f.general_activation_actn_day = ProtoField.uint8 ("dji_mavic.general_activation_actn_day", "Day", base.DEC)
f.general_activation_actn_hour = ProtoField.uint8 ("dji_mavic.general_activation_actn_hour", "Hour", base.DEC)
f.general_activation_actn_min = ProtoField.uint8 ("dji_mavic.general_activation_actn_min", "Minute", base.DEC)
f.general_activation_actn_sec = ProtoField.uint8 ("dji_mavic.general_activation_actn_sec", "Second", base.DEC)
f.general_activation_actn_ts = ProtoField.bytes ("dji_mavic.general_activation_actn_ts", "Timestamp", base.NONE)
f.general_activation_actn_mc_serial_len = ProtoField.uint8 ("dji_mavic.general_activation_actn_mc_serial_len", "MC Serial length", base.DEC)
f.general_activation_actn_mc_serial = ProtoField.string ("dji_mavic.general_activation_actn_mc_serial", "MC Serial", base.ASCII)

local function main_general_activation_actn_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.general_activation_actn_action, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.general_activation_actn_state, payload(offset, 1))
    offset = offset + 1

    -- Instead of a series of ints, let's use a single timestamp field

    local ts_year = payload(offset, 2):le_uint()
    --subtree:add_le (f.general_activation_actn_year, payload(offset, 2))
    offset = offset + 2

    local ts_month = payload(offset, 1):le_uint()
    --subtree:add_le (f.general_activation_actn_month, payload(offset, 1))
    offset = offset + 1

    local ts_day = payload(offset, 1):le_uint()
    --subtree:add_le (f.general_activation_actn_day, payload(offset, 1))
    offset = offset + 1

    local ts_hour = payload(offset, 1):le_uint()
    --subtree:add_le (f.general_activation_actn_hour, payload(offset, 1))
    offset = offset + 1

    local ts_min = payload(offset, 1):le_uint()
    --subtree:add_le (f.general_activation_actn_min, payload(offset, 1))
    offset = offset + 1

    local ts_sec = payload(offset, 1):le_uint()
    --subtree:add_le (f.general_activation_actn_sec, payload(offset, 1))
    offset = offset + 1

    local timestamp_str = string.format("Timestamp: %d-%02d-%02d %02d:%02d:%02d", ts_year, ts_month, ts_day, ts_hour, ts_min, ts_sec)
    subtree:add (f.general_activation_actn_ts, payload(offset-7, 7), 0, timestamp_str)

    local mc_serial_len = payload(offset,1):uint()
    subtree:add_le (f.general_activation_actn_mc_serial_len, payload(offset, 1))
    offset = offset + 1

    subtree:add (f.general_activation_actn_mc_serial, payload(offset, mc_serial_len))
    offset = offset + mc_serial_len

    if (offset ~= 10 + mc_serial_len) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Activation Action: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Activation Action: Payload size different than expected") end
end

local GENERAL_DISSECT = {
    [0x0E] = main_general_text_msg_dissector,
    [0x32] = main_general_activation_actn_dissector,
}

local SPECIAL_DISSECT = {
}

local CAMERA_DISSECT = {
}

-- Flight Controller - Write Flyc Param By Hash - 0xf9

enums.FLYC_PARAMETER_BY_HASH_ENUM = {
    [0x4d5c7a3d] = 'cfg_var_table_size_0',
}

f.flyc_write_flyc_param_by_hash_name_hash = ProtoField.uint32 ("dji_mavic.flyc_write_flyc_param_by_hash_name_hash", "Param Name Hash", base.HEX, enums.FLYC_PARAMETER_BY_HASH_ENUM, nil, "Hash of a flight controller parameter name string")
f.flyc_write_flyc_param_by_hash_value = ProtoField.bytes ("dji_mavic.flyc_write_flyc_param_by_hash_value", "Param Value", base.SPACE, nil, nil, "Flight controller parameter value to set; size and type depends on parameter")

local function flyc_write_flyc_param_by_hash_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_write_flyc_param_by_hash_name_hash, payload(offset, 4))
    offset = offset + 4

    local varsize_val = payload(offset, payload:len() - offset)
    subtree:add (f.flyc_write_flyc_param_by_hash_value, varsize_val)
    offset = payload:len()

    --if (offset ~= 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Write Flyc Param By Hash: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Write Flyc Param By Hash: Payload size different than expected") end
end

local FLIGHT_CTRL_DISSECT = {
    [0xf9] = flyc_write_flyc_param_by_hash_dissector,
}

local GIMBAL_DISSECT = {
}

local CENTER_BRD_DISSECT = {
}

local RC_DISSECT = {
}

local WIFI_DISSECT = {
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

-- Battery Data packet
f.bat_battery_data_unk1 = ProtoField.bytes ("dji_mavic.bat_battery_data_unknown1", "Unknown", base.SPACE)
f.bat_battery_data_voltage = ProtoField.uint32 ("dji_mavic.bet_battery_data_voltage", "Pack Voltage [mV]", base.DEC)
f.bat_battery_data_current = ProtoField.int32 ("dji_mavic.bat_battery_data_current", "Current [mA]", base.DEC)
f.bat_battery_data_full_charge_capacity = ProtoField.uint32 ("dji_mavic.bat_battery_data_full_charge_capacity", "Full Charge Capacity [mAh]", base.DEC)
f.bat_battery_data_current_capacity = ProtoField.uint32 ("dji_mavic.bat_battery_data_current_capacity", "Current Capacity [mAh]", base.DEC)
f.bat_battery_data_unk2 = ProtoField.bytes ("dji_mavic.bat_battery_data_unknown2", "Unknown", base.SPACE)
f.bat_battery_data_state_of_charge = ProtoField.uint8 ("dji_mavic.datlog_battery_data_state_of_charge", "State of Charge [%]", base.DEC)
f.bat_battery_data_unk3 = ProtoField.bytes ("dji_mavic.bat_battery_data_unknown3", "Unknown", base.SPACE)

local function bat_battery_data_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if ((payload:len() == 31) or (payload:len() == 32)) then
        if (payload:len() == 31) then
            subtree:add (f.bat_battery_data_unk1, payload(offset, 1))
            offset = offset + 1
        else
            subtree:add (f.bat_battery_data_unk1, payload(offset, 2))
            offset = offset + 2
        end

        subtree:add_le (f.bat_battery_data_voltage, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.bat_battery_data_current, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.bat_battery_data_full_charge_capacity, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.bat_battery_data_current_capacity, payload(offset, 4))
        offset = offset + 4

        subtree:add (f.bat_battery_data_unk2, payload(offset, 3))
        offset = offset + 3

        subtree:add_le (f.bat_battery_data_state_of_charge, payload(offset, 1))
        offset = offset + 1

        subtree:add (f.bat_battery_data_unk3, payload(offset, 10))
        offset = offset + 10
    end
end

-- Cell Data packet
f.bat_cell_data_unk1 = ProtoField.bytes ("dji_mavic.bat_battery_data_unknown1", "Unknown", base.SPACE)
f.bat_cell_data_cell_count = ProtoField.uint8 ("dji_mavic.bat_cell_data_cell_count", "Number of Cells", base.DEC)
f.bat_cell_data_cell1_voltage = ProtoField.uint16 ("dji_mavic.bat_cell_data_cell1_voltage", "Cell 1 Voltage [mV]", base.DEC)
f.bat_cell_data_cell2_voltage = ProtoField.uint16 ("dji_mavic.bat_cell_data_cell2_voltage", "Cell 2 Voltage [mV]", base.DEC)
f.bat_cell_data_cell3_voltage = ProtoField.uint16 ("dji_mavic.bat_cell_data_cell3_voltage", "Cell 3 Voltage [mV]", base.DEC)

local function bat_cell_data_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if ((payload:len() == 8) or (payload:len() == 9)) then
        if (payload:len() == 8) then
            subtree:add (f.bat_cell_data_unk1, payload(offset, 1))
            offset = offset + 1
        else
            subtree:add (f.bat_cell_data_unk1, payload(offset, 2))
            offset = offset + 2
        end

        subtree:add_le (f.bat_cell_data_cell_count, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.bat_cell_data_cell1_voltage, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.bat_cell_data_cell2_voltage, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.bat_cell_data_cell3_voltage, payload(offset, 2))
        offset = offset + 2
    end
end

local BATTERY_DISSECT = {
    [0x02] = bat_battery_data_dissector,
    [0x03] = bat_cell_data_dissector,
}

-- Battery Data packet
f.datlog_battery_data_unk1 = ProtoField.bytes ("dji_mavic.datlog_battery_data_unknown1", "Unknown", base.SPACE)
f.datlog_battery_data_voltage = ProtoField.uint16 ("dji_mavic.datlog_battery_data_voltage", "Pack Voltage [mV]", base.DEC)
f.datlog_battery_data_current = ProtoField.int32 ("dji_mavic.datlog_battery_data_current", "Current [mA]", base.DEC)
f.datlog_battery_data_full_charge_capacity = ProtoField.uint16 ("dji_mavic.datlog_battery_data_full_charge_capacity", "Full Charge Capacity [mAh]", base.DEC)
f.datlog_battery_data_current_capacity = ProtoField.uint16 ("dji_mavic.datlog_battery_data_current_capacity", "Current Capacity [mAh]", base.DEC)
f.datlog_battery_data_temperature = ProtoField.uint16 ("dji_mavic.datlog_battery_data_temperature", "Temperature [deg C]", base.DEC)
f.datlog_battery_data_state_of_charge = ProtoField.uint16 ("dji_mavic.datlog_battery_data_state_of_charge", "State of Charge [%]", base.DEC)
f.datlog_battery_data_status1 = ProtoField.uint8 ("dji_mavic.datlog_battery_data_status1", "Status 1", base.HEX)
f.datlog_battery_data_status2 = ProtoField.uint8 ("dji_mavic.datlog_battery_data_status1", "Status 2", base.HEX)
f.datlog_battery_data_status3 = ProtoField.uint8 ("dji_mavic.datlog_battery_data_status1", "Status 3", base.HEX)
f.datlog_battery_data_status4 = ProtoField.uint8 ("dji_mavic.datlog_battery_data_status1", "Status 4", base.HEX)
f.datlog_battery_data_cell1_voltage = ProtoField.uint16 ("dji_mavic.datlog_battery_data_cell1_voltage", "Cell 1 Voltage [mV]", base.DEC)
f.datlog_battery_data_cell2_voltage = ProtoField.uint16 ("dji_mavic.datlog_battery_data_cell2_voltage", "Cell 2 Voltage [mV]", base.DEC)
f.datlog_battery_data_cell3_voltage = ProtoField.uint16 ("dji_mavic.datlog_battery_data_cell3_voltage", "Cell 2 Voltage [mV]", base.DEC)

local function datlog_battery_data_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (payload:len() == 29) then
        subtree:add (f.datlog_battery_data_unk1, payload(offset, 3))
        offset = offset + 3

        subtree:add_le (f.datlog_battery_data_voltage, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.datlog_battery_data_current, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.datlog_battery_data_full_charge_capacity, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.datlog_battery_data_current_capacity, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.datlog_battery_data_temperature, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.datlog_battery_data_state_of_charge, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.datlog_battery_data_status1, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.datlog_battery_data_status2, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.datlog_battery_data_status3, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.datlog_battery_data_status4, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.datlog_battery_data_cell1_voltage, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.datlog_battery_data_cell2_voltage, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.datlog_battery_data_cell2_voltage, payload(offset, 2))
        offset = offset + 2
    end
end

-- Battery Message packet
f.datlog_battery_msg_message = ProtoField.string ("dji_mavic.datlog_battery_msg_message", "Message", base.ASCII)

local function datlog_battery_msg_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (payload:len() > 2) then
        local message_len = payload:len() - offset
        subtree:add_le (f.datlog_battery_msg_message, payload(offset, message_len))
    end
end

local DATA_LOG_DISSECT = {
    [0x22] = datlog_battery_data_dissector,
    [0x23] = datlog_battery_msg_dissector,
}

local RTK_DISSECT = {
}

local AUTO_DISSECT = {
}


DJI_MAVIC_FLIGHT_CONTROL_UART_DISSECT = {
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
