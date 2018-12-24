-- Create a new dissector
DJI_P3_FLYREC_PROTO = Proto ("dji_p3_flyrec", "DJI_P3_FLYREC", "Dji Ph3 Flight Record file format")

local f = DJI_P3_FLYREC_PROTO.fields
local enums = {}

DJI_P3_FLIGHT_RECORD_ENTRY_TYPE = {
    [0x0000] = 'Controller',
    [0x07cf] = 'Ofdm Cnt',
    [0x07d0] = 'Uart Cnt',
    [0x0002] = 'Imu Tail',
    [0xfffa] = 'Drv Log',
    [0x0073] = 'Asr',
    [0x0001] = 'Imu Atti',
    [0x0003] = 'Imu Ex',
    [0x0820] = 'Imu Tail 00',
    [0x0800] = 'Imu Atti 00',
    [0x0810] = 'Imu Ex 00',
    [0x0821] = 'Imu Tail 01',
    [0x0801] = 'Imu Atti 01',
    [0x0811] = 'Imu Ex 01',
    [0x0822] = 'Imu Tail 02',
    [0x0802] = 'Imu Atti 02',
    [0x0812] = 'Imu Ex 02',
    [0x0004] = 'Compass',
    [0x0005] = 'Gps Glns',
    [0x000b] = 'Gps Snr',
    [0x0061] = 'Pt3 Gps Snr',
    [0x005b] = 'Imu 21100',
    [0x005c] = 'Imu Raw',
    [0x0062] = 'Imu Raw 01',
    [0x0006] = 'Imu Init',
    [0x000c] = 'Osd General',
    [0x000d] = 'Osd Home',
    [0x001a] = 'Fdi',
    [0x8003] = 'Vincent Debug',
    [0x8000] = 'Fly Log',
    [0xff00] = 'Sd Logs',
    [0xfffe] = 'Svn Info',
    [0x0007] = 'Imu Data',
    [0x0870] = 'Imu Data 00',
    [0x0871] = 'Imu Data 01',
    [0x0872] = 'Imu Data 02',
    [0x0008] = 'Imu Cali Data',
    [0x0009] = 'Sensor Cfg Temp',
    [0x000a] = 'Temp Ctl Data',
    [0x0880] = 'Temp Ctl Data 00',
    [0x0881] = 'Temp Ctl Data 01',
    [0x0882] = 'Temp Ctl Data 02',
    [0x0014] = 'Pwm Output',
    [0x0015] = 'Temp Bias Data',
    [0x0016] = 'Temp Cali Data',
    [0x0018] = 'App Temp Bias Data',
    [0x0019] = 'App Temp Cali Data',
    [0x0893] = 'Temp Cali Data 00',
    [0x0896] = 'App Temp Cali Data 00',
    [0x0894] = 'Temp Cali Data 01',
    [0x0897] = 'App Temp Cali Data 01',
    [0x0895] = 'Temp Cali Data 02',
    [0x0898] = 'App Temp Cali Data 02',
    [0x0023] = 'Mpu6500 Raw Data',
    [0x0024] = 'Adxl278 Raw Data',
    [0x0065] = 'Svo Debug',
    [0xcdf0] = 'Uc Monitor',
    [0xcdff] = 'Rc Delay',
    [0xce02] = 'Taskb Info',
    [0xce06] = 'Taska Info',
    [0xce08] = 'Taskc Info',
    [0xce09] = 'Taskd Info',
    [0xcdf6] = 'Rc Replay',
    [0xcdf1] = 'Escm',
    [0xcdf2] = 'Sweep',
    [0x000e] = 'Mvo',
    [0x0010] = 'Usonic',
    [0xcdef] = 'Console',
    [0xffff] = 'Syscfg',
    [0x0011] = 'Battery Info',
    [0x0017] = 'Special Cmd',
    [0x003c] = 'Serial Api Inputs',
    [0x0032] = 'Ctrl Vert',
    [0x0033] = 'Ctrl Horiz',
    [0x0034] = 'Ctrl Atti',
    [0x0035] = 'Ctrl Ccpm',
    [0x0036] = 'Ctrl Motor',
    [0x0096] = 'Wp Curve',
    [0x0012] = 'Smart Battery Info',
    [0x0028] = 'Airport Limit Data',
    [0x0029] = 'Fmu Device Run Time',
    [0x002a] = 'Hp Data',
    [0x002b] = 'Follow Me Data',
    [0x002c] = 'Home Lock',
    [0x0013] = 'Imu Data Status',
    [0x0046] = 'Aircraft Condition Monitor',
    [0x0050] = 'Aircraft Model',
    [0x005a] = 'Go Home Info',
    [0x001d] = 'New Mvo Feedback',
    [0x0064] = 'Svo Avoid Obstacle',
    [0xcff1] = 'Rtkdata',
    [0x006e] = 'Gear Debug Info',
    [0x0066] = 'Svo Ctrl Debug',
    [0x00a0] = 'Waypoint Debug',
    [0xa000] = 'Battery Unknown',
}

local function bytearray_to_hexstr(bytes)
  s = {}
  for i = 0, bytes:len() - 1 do
    s[i+1] = string.format("%02X",bytes:get_index(i))
  end
  return table.concat(s," ")
end

-- Flight log - Controller - 0x0000

f.controller_g_real_clock = ProtoField.uint32 ("dji_p3_flyrec.controller_g_real_clock", "G Real Clock", base.HEX)
f.controller_g_real_input_channel_command_aileron = ProtoField.int16 ("dji_p3_flyrec.controller_g_real_input_channel_command_aileron", "G Real Input Channel Command Aileron", base.DEC, nil, nil, "Aileron stick value, -10000..10000")
f.controller_g_real_input_channel_command_elevator = ProtoField.int16 ("dji_p3_flyrec.controller_g_real_input_channel_command_elevator", "G Real Input Channel Command Elevator", base.DEC, nil, nil, "Elevator stick value, -10000..10000")
f.controller_g_real_input_channel_command_throttle = ProtoField.int16 ("dji_p3_flyrec.controller_g_real_input_channel_command_throttle", "G Real Input Channel Command Throttle", base.DEC, nil, nil, "Throttle stick value, -10000..10000")
f.controller_g_real_input_channel_command_rudder = ProtoField.int16 ("dji_p3_flyrec.controller_g_real_input_channel_command_rudder", "G Real Input Channel Command Rudder", base.DEC, nil, nil, "Rudder stick value, -10000..10000")
f.controller_g_real_input_channel_command_mode = ProtoField.int16 ("dji_p3_flyrec.controller_g_real_input_channel_command_mode", "G Real Input Channel Command Mode", base.DEC)
f.controller_g_real_input_channel_command_ioc = ProtoField.int16 ("dji_p3_flyrec.controller_g_real_input_channel_command_ioc", "G Real Input Channel Command Ioc", base.DEC)
f.controller_g_real_input_channel_command_go_home = ProtoField.int16 ("dji_p3_flyrec.controller_g_real_input_channel_command_go_home", "G Real Input Channel Command Go Home", base.DEC)
f.controller_g_real_input_channel_command_d4 = ProtoField.int16 ("dji_p3_flyrec.controller_g_real_input_channel_command_d4", "G Real Input Channel Command D4", base.DEC)
f.controller_g_real_input_control_core_pitch = ProtoField.int16 ("dji_p3_flyrec.controller_g_real_input_control_core_pitch", "G Real Input Control Core Pitch", base.DEC, nil, nil, "Pitch stick value, -10000..10000")
f.controller_g_real_input_control_core_roll = ProtoField.int16 ("dji_p3_flyrec.controller_g_real_input_control_core_roll", "G Real Input Control Core Roll", base.DEC, nil, nil, "Roll stick value, -10000..10000")
f.controller_g_real_input_control_core_alti = ProtoField.int16 ("dji_p3_flyrec.controller_g_real_input_control_core_alti", "G Real Input Control Core Alti", base.DEC, nil, nil, "Altitude stick value, -10000..10000")
f.controller_g_real_input_control_core_tail = ProtoField.int16 ("dji_p3_flyrec.controller_g_real_input_control_core_tail", "G Real Input Control Core Tail", base.DEC, nil, nil, "Tail/Yaw stick value, -10000..10000")
f.controller_g_real_status_cotrol_command_mode = ProtoField.uint8 ("dji_p3_flyrec.controller_g_real_status_cotrol_command_mode", "G Real Status Cotrol Command Mode", base.HEX)
f.controller_g_real_status_control_real_mode = ProtoField.uint8 ("dji_p3_flyrec.controller_g_real_status_control_real_mode", "G Real Status Control Real Mode", base.HEX)
f.controller_g_real_status_ioc_control_command_mode = ProtoField.uint8 ("dji_p3_flyrec.controller_g_real_status_ioc_control_command_mode", "G Real Status Ioc Control Command Mode", base.HEX)
f.controller_g_real_status_rc_state = ProtoField.uint8 ("dji_p3_flyrec.controller_g_real_status_rc_state", "G Real Status Rc State", base.HEX)
f.controller_g_real_status_motor_status = ProtoField.uint8 ("dji_p3_flyrec.controller_g_real_status_motor_status", "G Real Status Motor Status", base.HEX, nil, nil, "Zero if motors off, 1 if motors running")
f.controller_imu_package_lost_count = ProtoField.uint32 ("dji_p3_flyrec.controller_imu_package_lost_count", "Imu Package Lost Count", base.HEX)
f.controller_g_real_status_main_batery_voltage = ProtoField.uint16 ("dji_p3_flyrec.controller_g_real_status_main_batery_voltage", "G Real Status Main Batery Voltage", base.HEX)
f.controller_imu_temp_real_ctl_out_per = ProtoField.uint8 ("dji_p3_flyrec.controller_imu_temp_real_ctl_out_per", "Imu Temp Real Ctl Out Per", base.HEX)
f.controller_us_fail_flag = ProtoField.uint8 ("dji_p3_flyrec.controller_us_fail_flag", "Us Fail Flag", base.HEX)
f.controller_gps_signal_levels = ProtoField.uint8 ("dji_p3_flyrec.controller_gps_signal_levels", "Gps Signal Levels", base.HEX)
f.controller_gps_ctrl_levels = ProtoField.uint8 ("dji_p3_flyrec.controller_gps_ctrl_levels", "Gps Ctrl Levels", base.HEX)

local function flightrec_controller_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.controller_g_real_clock, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.controller_g_real_input_channel_command_aileron, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_g_real_input_channel_command_elevator, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_g_real_input_channel_command_throttle, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_g_real_input_channel_command_rudder, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_g_real_input_channel_command_mode, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_g_real_input_channel_command_ioc, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_g_real_input_channel_command_go_home, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_g_real_input_channel_command_d4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_g_real_input_control_core_pitch, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_g_real_input_control_core_roll, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_g_real_input_control_core_alti, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_g_real_input_control_core_tail, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_g_real_status_cotrol_command_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_g_real_status_control_real_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_g_real_status_ioc_control_command_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_g_real_status_rc_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_g_real_status_motor_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_imu_package_lost_count, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.controller_g_real_status_main_batery_voltage, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_imu_temp_real_ctl_out_per, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_us_fail_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_gps_signal_levels, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_gps_ctrl_levels, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 43) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Controller: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Controller: Payload size different than expected") end
end

-- Flight log - Ofdm Cnt - 0x07cf

f.ofdm_cnt_recv_total = ProtoField.uint16 ("dji_p3_flyrec.ofdm_cnt_recv_total", "Recv Total", base.HEX)
f.ofdm_cnt_header_error = ProtoField.uint16 ("dji_p3_flyrec.ofdm_cnt_header_error", "Header Error", base.HEX)
f.ofdm_cnt_v1_error = ProtoField.uint16 ("dji_p3_flyrec.ofdm_cnt_v1_error", "V1 Error", base.HEX)
f.ofdm_cnt_v0_error = ProtoField.uint16 ("dji_p3_flyrec.ofdm_cnt_v0_error", "V0 Error", base.HEX)
f.ofdm_cnt_seccuss = ProtoField.uint16 ("dji_p3_flyrec.ofdm_cnt_seccuss", "Seccuss", base.HEX)

local function flightrec_ofdm_cnt_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ofdm_cnt_recv_total, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ofdm_cnt_header_error, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ofdm_cnt_v1_error, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ofdm_cnt_v0_error, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ofdm_cnt_seccuss, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 10) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ofdm Cnt: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ofdm Cnt: Payload size different than expected") end
end

-- Flight log - Uart Cnt - 0x07d0

f.uart_cnt_uart_tx1 = ProtoField.uint16 ("dji_p3_flyrec.uart_cnt_uart_tx1", "Uart Tx1", base.HEX)
f.uart_cnt_uart_rx1 = ProtoField.uint16 ("dji_p3_flyrec.uart_cnt_uart_rx1", "Uart Rx1", base.HEX)
f.uart_cnt_uart_tx2 = ProtoField.uint16 ("dji_p3_flyrec.uart_cnt_uart_tx2", "Uart Tx2", base.HEX)
f.uart_cnt_uart_rx2 = ProtoField.uint16 ("dji_p3_flyrec.uart_cnt_uart_rx2", "Uart Rx2", base.HEX)
f.uart_cnt_uart_tx3 = ProtoField.uint16 ("dji_p3_flyrec.uart_cnt_uart_tx3", "Uart Tx3", base.HEX)
f.uart_cnt_uart_rx3 = ProtoField.uint16 ("dji_p3_flyrec.uart_cnt_uart_rx3", "Uart Rx3", base.HEX)
f.uart_cnt_uart_tx4 = ProtoField.uint16 ("dji_p3_flyrec.uart_cnt_uart_tx4", "Uart Tx4", base.HEX)
f.uart_cnt_uart_rx4 = ProtoField.uint16 ("dji_p3_flyrec.uart_cnt_uart_rx4", "Uart Rx4", base.HEX)
f.uart_cnt_uart_tx5 = ProtoField.uint16 ("dji_p3_flyrec.uart_cnt_uart_tx5", "Uart Tx5", base.HEX)
f.uart_cnt_uart_rx5 = ProtoField.uint16 ("dji_p3_flyrec.uart_cnt_uart_rx5", "Uart Rx5", base.HEX)
f.uart_cnt_uart_tx6 = ProtoField.uint16 ("dji_p3_flyrec.uart_cnt_uart_tx6", "Uart Tx6", base.HEX)
f.uart_cnt_uart_rx6 = ProtoField.uint16 ("dji_p3_flyrec.uart_cnt_uart_rx6", "Uart Rx6", base.HEX)
f.uart_cnt_uart_tx7 = ProtoField.uint16 ("dji_p3_flyrec.uart_cnt_uart_tx7", "Uart Tx7", base.HEX)
f.uart_cnt_uart_rx7 = ProtoField.uint16 ("dji_p3_flyrec.uart_cnt_uart_rx7", "Uart Rx7", base.HEX)
f.uart_cnt_uart_tx8 = ProtoField.uint16 ("dji_p3_flyrec.uart_cnt_uart_tx8", "Uart Tx8", base.HEX)
f.uart_cnt_uart_rx8 = ProtoField.uint16 ("dji_p3_flyrec.uart_cnt_uart_rx8", "Uart Rx8", base.HEX)

local function flightrec_uart_cnt_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.uart_cnt_uart_tx1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_cnt_uart_rx1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_cnt_uart_tx2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_cnt_uart_rx2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_cnt_uart_tx3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_cnt_uart_rx3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_cnt_uart_tx4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_cnt_uart_rx4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_cnt_uart_tx5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_cnt_uart_rx5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_cnt_uart_tx6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_cnt_uart_rx6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_cnt_uart_tx7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_cnt_uart_rx7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_cnt_uart_tx8, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_cnt_uart_rx8, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 32) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Uart Cnt: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Uart Cnt: Payload size different than expected") end
end

-- Flight log - Imu Tail - 0x0002

f.imu_tail_raw_w_x = ProtoField.int16 ("dji_p3_flyrec.imu_tail_raw_w_x", "Raw W X", base.DEC)
f.imu_tail_raw_w_y = ProtoField.int16 ("dji_p3_flyrec.imu_tail_raw_w_y", "Raw W Y", base.DEC)
f.imu_tail_raw_w_z = ProtoField.int16 ("dji_p3_flyrec.imu_tail_raw_w_z", "Raw W Z", base.DEC)
f.imu_tail_raw_a_x = ProtoField.int16 ("dji_p3_flyrec.imu_tail_raw_a_x", "Raw A X", base.DEC)
f.imu_tail_raw_a_y = ProtoField.int16 ("dji_p3_flyrec.imu_tail_raw_a_y", "Raw A Y", base.DEC)
f.imu_tail_raw_a_z = ProtoField.int16 ("dji_p3_flyrec.imu_tail_raw_a_z", "Raw A Z", base.DEC)
f.imu_tail_raw_wa_x = ProtoField.int16 ("dji_p3_flyrec.imu_tail_raw_wa_x", "Raw Wa X", base.DEC)
f.imu_tail_raw_wa_y = ProtoField.int16 ("dji_p3_flyrec.imu_tail_raw_wa_y", "Raw Wa Y", base.DEC)
f.imu_tail_raw_wa_z = ProtoField.int16 ("dji_p3_flyrec.imu_tail_raw_wa_z", "Raw Wa Z", base.DEC)
f.imu_tail_iir_w_x = ProtoField.int16 ("dji_p3_flyrec.imu_tail_iir_w_x", "Iir W X", base.DEC)
f.imu_tail_iir_w_y = ProtoField.int16 ("dji_p3_flyrec.imu_tail_iir_w_y", "Iir W Y", base.DEC)
f.imu_tail_iir_w_z = ProtoField.int16 ("dji_p3_flyrec.imu_tail_iir_w_z", "Iir W Z", base.DEC)
f.imu_tail_iir_a_x = ProtoField.int16 ("dji_p3_flyrec.imu_tail_iir_a_x", "Iir A X", base.DEC)
f.imu_tail_iir_a_y = ProtoField.int16 ("dji_p3_flyrec.imu_tail_iir_a_y", "Iir A Y", base.DEC)
f.imu_tail_iir_a_z = ProtoField.int16 ("dji_p3_flyrec.imu_tail_iir_a_z", "Iir A Z", base.DEC)
f.imu_tail_iir_wa_x = ProtoField.int16 ("dji_p3_flyrec.imu_tail_iir_wa_x", "Iir Wa X", base.DEC)
f.imu_tail_iir_wa_y = ProtoField.int16 ("dji_p3_flyrec.imu_tail_iir_wa_y", "Iir Wa Y", base.DEC)
f.imu_tail_iir_wa_z = ProtoField.int16 ("dji_p3_flyrec.imu_tail_iir_wa_z", "Iir Wa Z", base.DEC)
f.imu_tail_gyro_hf_cnt = ProtoField.uint32 ("dji_p3_flyrec.imu_tail_gyro_hf_cnt", "Gyro Hf Cnt", base.DEC, nil, nil, "Sequence counter increased each time the packet of this type is prepared")
--f.imu_tail_e_raw_w_x = ProtoField.none ("dji_p3_flyrec.imu_tail_e_raw_w_x", "E Raw W X", base.NONE, nil, nil, "raw_w_x/1000")
--f.imu_tail_e_raw_w_y = ProtoField.none ("dji_p3_flyrec.imu_tail_e_raw_w_y", "E Raw W Y", base.NONE, nil, nil, "raw_w_y/1000")
--f.imu_tail_e_raw_w_z = ProtoField.none ("dji_p3_flyrec.imu_tail_e_raw_w_z", "E Raw W Z", base.NONE, nil, nil, "raw_w_z/1000")
--f.imu_tail_e_raw_a_x = ProtoField.none ("dji_p3_flyrec.imu_tail_e_raw_a_x", "E Raw A X", base.NONE, nil, nil, "raw_a_x/500")
--f.imu_tail_e_raw_a_y = ProtoField.none ("dji_p3_flyrec.imu_tail_e_raw_a_y", "E Raw A Y", base.NONE, nil, nil, "raw_a_y/500")
--f.imu_tail_e_raw_a_z = ProtoField.none ("dji_p3_flyrec.imu_tail_e_raw_a_z", "E Raw A Z", base.NONE, nil, nil, "raw_a_z/500")
--f.imu_tail_e_raw_wa_x = ProtoField.none ("dji_p3_flyrec.imu_tail_e_raw_wa_x", "E Raw Wa X", base.NONE, nil, nil, "raw_wa_x/100")
--f.imu_tail_e_raw_wa_y = ProtoField.none ("dji_p3_flyrec.imu_tail_e_raw_wa_y", "E Raw Wa Y", base.NONE, nil, nil, "raw_wa_y/100")
--f.imu_tail_e_raw_wa_z = ProtoField.none ("dji_p3_flyrec.imu_tail_e_raw_wa_z", "E Raw Wa Z", base.NONE, nil, nil, "raw_wa_z/100")
--f.imu_tail_e_iir_w_x = ProtoField.none ("dji_p3_flyrec.imu_tail_e_iir_w_x", "E Iir W X", base.NONE, nil, nil, "iir_w_x/1000")
--f.imu_tail_e_iir_w_y = ProtoField.none ("dji_p3_flyrec.imu_tail_e_iir_w_y", "E Iir W Y", base.NONE, nil, nil, "iir_w_y/1000")
--f.imu_tail_e_iir_w_z = ProtoField.none ("dji_p3_flyrec.imu_tail_e_iir_w_z", "E Iir W Z", base.NONE, nil, nil, "iir_w_z/1000")
--f.imu_tail_e_iir_a_x = ProtoField.none ("dji_p3_flyrec.imu_tail_e_iir_a_x", "E Iir A X", base.NONE, nil, nil, "iir_a_x/500")
--f.imu_tail_e_iir_a_y = ProtoField.none ("dji_p3_flyrec.imu_tail_e_iir_a_y", "E Iir A Y", base.NONE, nil, nil, "iir_a_y/500")
--f.imu_tail_e_iir_a_z = ProtoField.none ("dji_p3_flyrec.imu_tail_e_iir_a_z", "E Iir A Z", base.NONE, nil, nil, "iir_a_z/500")
--f.imu_tail_e_iir_wa_x = ProtoField.none ("dji_p3_flyrec.imu_tail_e_iir_wa_x", "E Iir Wa X", base.NONE, nil, nil, "iir_wa_x/100")
--f.imu_tail_e_iir_wa_y = ProtoField.none ("dji_p3_flyrec.imu_tail_e_iir_wa_y", "E Iir Wa Y", base.NONE, nil, nil, "iir_wa_y/100")
--f.imu_tail_e_iir_wa_z = ProtoField.none ("dji_p3_flyrec.imu_tail_e_iir_wa_z", "E Iir Wa Z", base.NONE, nil, nil, "iir_wa_z/100")

local function flightrec_imu_tail_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_tail_raw_w_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_tail_raw_w_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_tail_raw_w_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_tail_raw_a_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_tail_raw_a_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_tail_raw_a_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_tail_raw_wa_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_tail_raw_wa_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_tail_raw_wa_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_tail_iir_w_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_tail_iir_w_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_tail_iir_w_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_tail_iir_a_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_tail_iir_a_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_tail_iir_a_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_tail_iir_wa_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_tail_iir_wa_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_tail_iir_wa_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_tail_gyro_hf_cnt, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 40) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Tail: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Tail: Payload size different than expected") end
end

-- Flight log - Drv Log - 0xfffa

f.drv_log_text = ProtoField.string ("dji_p3_flyrec.drv_log_text", "Drv Log", base.ASCII)

local function flightrec_drv_log_dissector(payload, pinfo, subtree)
    local offset = 0

    local rec_drv_log_text = payload(offset, payload:len() - offset)
    subtree:add (f.drv_log_text, rec_drv_log_text)

    pinfo.cols.info = rec_drv_log_text:string():gsub('[^a-zA-Z0-9_:,.[[]]/\\ \t-]','')

end

-- Flight log - Asr - 0x0073

f.asr_lead = ProtoField.uint32 ("dji_p3_flyrec.asr_lead", "Lead", base.HEX)

local function flightrec_asr_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.asr_lead, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Asr: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Asr: Payload size different than expected") end
end

-- Flight log - Imu Atti - 0x0001

f.imu_atti_longti = ProtoField.double ("dji_p3_flyrec.imu_atti_longti", "Longti", base.DEC)
f.imu_atti_lati = ProtoField.double ("dji_p3_flyrec.imu_atti_lati", "Lati", base.DEC)
f.imu_atti_alti = ProtoField.float ("dji_p3_flyrec.imu_atti_alti", "Alti", base.DEC)
f.imu_atti_acc_x = ProtoField.float ("dji_p3_flyrec.imu_atti_acc_x", "Acc X", base.DEC)
f.imu_atti_acc_y = ProtoField.float ("dji_p3_flyrec.imu_atti_acc_y", "Acc Y", base.DEC)
f.imu_atti_acc_z = ProtoField.float ("dji_p3_flyrec.imu_atti_acc_z", "Acc Z", base.DEC)
f.imu_atti_gyro_x = ProtoField.float ("dji_p3_flyrec.imu_atti_gyro_x", "Gyro X", base.DEC)
f.imu_atti_gyro_y = ProtoField.float ("dji_p3_flyrec.imu_atti_gyro_y", "Gyro Y", base.DEC)
f.imu_atti_gyro_z = ProtoField.float ("dji_p3_flyrec.imu_atti_gyro_z", "Gyro Z", base.DEC)
f.imu_atti_press = ProtoField.float ("dji_p3_flyrec.imu_atti_press", "Press", base.DEC)
f.imu_atti_q0 = ProtoField.float ("dji_p3_flyrec.imu_atti_q0", "Q0", base.DEC)
f.imu_atti_q1 = ProtoField.float ("dji_p3_flyrec.imu_atti_q1", "Q1", base.DEC)
f.imu_atti_q2 = ProtoField.float ("dji_p3_flyrec.imu_atti_q2", "Q2", base.DEC)
f.imu_atti_q3 = ProtoField.float ("dji_p3_flyrec.imu_atti_q3", "Q3", base.DEC)
f.imu_atti_ag_x = ProtoField.float ("dji_p3_flyrec.imu_atti_ag_x", "Ag X", base.DEC)
f.imu_atti_ag_y = ProtoField.float ("dji_p3_flyrec.imu_atti_ag_y", "Ag Y", base.DEC)
f.imu_atti_ag_z = ProtoField.float ("dji_p3_flyrec.imu_atti_ag_z", "Ag Z", base.DEC)
f.imu_atti_vg_x = ProtoField.float ("dji_p3_flyrec.imu_atti_vg_x", "Vg X", base.DEC)
f.imu_atti_vg_y = ProtoField.float ("dji_p3_flyrec.imu_atti_vg_y", "Vg Y", base.DEC)
f.imu_atti_vg_z = ProtoField.float ("dji_p3_flyrec.imu_atti_vg_z", "Vg Z", base.DEC)
f.imu_atti_gb_x = ProtoField.float ("dji_p3_flyrec.imu_atti_gb_x", "Gb X", base.DEC)
f.imu_atti_gb_y = ProtoField.float ("dji_p3_flyrec.imu_atti_gb_y", "Gb Y", base.DEC)
f.imu_atti_gb_z = ProtoField.float ("dji_p3_flyrec.imu_atti_gb_z", "Gb Z", base.DEC)
f.imu_atti_m_x = ProtoField.int16 ("dji_p3_flyrec.imu_atti_m_x", "M X", base.DEC)
f.imu_atti_m_y = ProtoField.int16 ("dji_p3_flyrec.imu_atti_m_y", "M Y", base.DEC)
f.imu_atti_m_z = ProtoField.int16 ("dji_p3_flyrec.imu_atti_m_z", "M Z", base.DEC)
f.imu_atti_temp_x = ProtoField.int16 ("dji_p3_flyrec.imu_atti_temp_x", "Temp X", base.DEC)
f.imu_atti_temp_y = ProtoField.int16 ("dji_p3_flyrec.imu_atti_temp_y", "Temp Y", base.DEC)
f.imu_atti_temp_z = ProtoField.int16 ("dji_p3_flyrec.imu_atti_temp_z", "Temp Z", base.DEC)
f.imu_atti_sensor_monitor = ProtoField.uint16 ("dji_p3_flyrec.imu_atti_sensor_monitor", "Sensor Monitor", base.HEX)
f.imu_atti_filter_status = ProtoField.uint16 ("dji_p3_flyrec.imu_atti_filter_status", "Filter Status", base.HEX)
f.imu_atti_svn = ProtoField.uint16 ("dji_p3_flyrec.imu_atti_svn", "Svn", base.DEC, nil, nil, "Number of Global Nav System positioning satellites")
f.imu_atti_cnt_atti = ProtoField.uint16 ("dji_p3_flyrec.imu_atti_cnt_atti", "Cnt Atti", base.DEC, nil, nil, "Sequence counter increased each time the packet of this type is prepared")

local function flightrec_imu_atti_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_atti_longti, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_atti_lati, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_atti_alti, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_acc_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_acc_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_acc_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_gyro_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_gyro_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_gyro_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_press, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_q0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_q1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_q2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_q3, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_ag_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_ag_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_ag_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_vg_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_vg_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_vg_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_gb_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_gb_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_gb_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_m_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_m_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_m_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_temp_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_temp_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_temp_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_sensor_monitor, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_filter_status, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_svn, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_cnt_atti, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 120) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Atti: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Atti: Payload size different than expected") end
end

-- Flight log - Imu Ex - 0x0003

f.imu_ex_vo_vx = ProtoField.float ("dji_p3_flyrec.imu_ex_vo_vx", "Vo Vx", base.DEC)
f.imu_ex_vo_vy = ProtoField.float ("dji_p3_flyrec.imu_ex_vo_vy", "Vo Vy", base.DEC)
f.imu_ex_vo_vz = ProtoField.float ("dji_p3_flyrec.imu_ex_vo_vz", "Vo Vz", base.DEC)
f.imu_ex_vo_px = ProtoField.float ("dji_p3_flyrec.imu_ex_vo_px", "Vo Px", base.DEC)
f.imu_ex_vo_py = ProtoField.float ("dji_p3_flyrec.imu_ex_vo_py", "Vo Py", base.DEC)
f.imu_ex_vo_pz = ProtoField.float ("dji_p3_flyrec.imu_ex_vo_pz", "Vo Pz", base.DEC)
f.imu_ex_us_v = ProtoField.float ("dji_p3_flyrec.imu_ex_us_v", "Us V", base.DEC)
f.imu_ex_us_p = ProtoField.float ("dji_p3_flyrec.imu_ex_us_p", "Us P", base.DEC)
--f.imu_ex_rtk_longti = ProtoField.double ("dji_p3_flyrec.imu_ex_rtk_longti", "Rtk Longti", base.DEC)
--f.imu_ex_rtk_lati = ProtoField.double ("dji_p3_flyrec.imu_ex_rtk_lati", "Rtk Lati", base.DEC)
--f.imu_ex_rtk_alti = ProtoField.float ("dji_p3_flyrec.imu_ex_rtk_alti", "Rtk Alti", base.DEC)
f.imu_ex_vo_flag_navi = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_vo_flag_navi", "Vo Flag Navi", base.HEX)
  f.imu_ex_e_vo_flag_navi_vo_vx = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_e_vo_flag_navi_vo_vx", "E Vo Flag Navi Vo Vx", base.HEX, nil, 0x01, nil)
  f.imu_ex_e_vo_flag_navi_vo_vy = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_e_vo_flag_navi_vo_vy", "E Vo Flag Navi Vo Vy", base.HEX, nil, 0x02, nil)
  f.imu_ex_e_vo_flag_navi_vo_vz = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_e_vo_flag_navi_vo_vz", "E Vo Flag Navi Vo Vz", base.HEX, nil, 0x04, nil)
  f.imu_ex_e_vo_flag_navi_vo_px = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_e_vo_flag_navi_vo_px", "E Vo Flag Navi Vo Px", base.HEX, nil, 0x08, nil)
  f.imu_ex_e_vo_flag_navi_vo_py = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_e_vo_flag_navi_vo_py", "E Vo Flag Navi Vo Py", base.HEX, nil, 0x10, nil)
  f.imu_ex_e_vo_flag_navi_vo_pz = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_e_vo_flag_navi_vo_pz", "E Vo Flag Navi Vo Pz", base.HEX, nil, 0x20, nil)
  f.imu_ex_e_vo_flag_navi_us_vz = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_e_vo_flag_navi_us_vz", "E Vo Flag Navi Us Vz", base.HEX, nil, 0x40, nil)
  f.imu_ex_e_vo_flag_navi_us_pz = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_e_vo_flag_navi_us_pz", "E Vo Flag Navi Us Pz", base.HEX, nil, 0x80, "Relative height flag; 0=Unavailable, 1=Available")
f.imu_ex_imu_err_flag = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_imu_err_flag", "Imu Err Flag", base.HEX)
  f.imu_ex_e_imu_err_vg_large = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_e_imu_err_vg_large", "E Imu Err Vg Large", base.HEX, nil, 0x01, nil)
  f.imu_ex_e_imu_err_gps_yaw = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_e_imu_err_gps_yaw", "E Imu Err Gps Yaw", base.HEX, nil, 0x02, nil)
  f.imu_ex_e_imu_err_mag_yaw = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_e_imu_err_mag_yaw", "E Imu Err Mag Yaw", base.HEX, nil, 0x04, nil)
  f.imu_ex_e_imu_err_gps_consist = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_e_imu_err_gps_consist", "E Imu Err Gps Consist", base.HEX, nil, 0x08, nil)
  f.imu_ex_e_imu_err_us_fail = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_e_imu_err_us_fail", "E Imu Err Us Fail", base.HEX, nil, 0x10, nil)
  f.imu_ex_e_imu_init_ok_flag = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_e_imu_init_ok_flag", "E Imu Init Ok Flag", base.HEX, nil, 0x20, nil)
f.imu_ex_vo_flag_rsv = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_vo_flag_rsv", "Vo Flag Rsv", base.HEX)
f.imu_ex_imu_ex_cnt = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_imu_ex_cnt", "Imu Ex Cnt", base.DEC, nil, nil, "Sequence counter increased each time the packet of this type is prepared")
f.imu_ex_imu_ex_fld28 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_imu_ex_fld28", "Field28", base.HEX)

local function flightrec_imu_ex_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_ex_vo_vx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_vo_vy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_vo_vz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_vo_px, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_vo_py, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_vo_pz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_us_v, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_us_p, payload(offset, 4))
    offset = offset + 4

    --subtree:add_le (f.imu_ex_rtk_longti, payload(offset, 8))
    --offset = offset + 8

    --subtree:add_le (f.imu_ex_rtk_lati, payload(offset, 8))
    --offset = offset + 8

    --subtree:add_le (f.imu_ex_rtk_alti, payload(offset, 4))
    --offset = offset + 4

    subtree:add_le (f.imu_ex_vo_flag_navi, payload(offset, 2))
    subtree:add_le (f.imu_ex_e_vo_flag_navi_vo_vx, payload(offset, 2))
    subtree:add_le (f.imu_ex_e_vo_flag_navi_vo_vy, payload(offset, 2))
    subtree:add_le (f.imu_ex_e_vo_flag_navi_vo_vz, payload(offset, 2))
    subtree:add_le (f.imu_ex_e_vo_flag_navi_vo_px, payload(offset, 2))
    subtree:add_le (f.imu_ex_e_vo_flag_navi_vo_py, payload(offset, 2))
    subtree:add_le (f.imu_ex_e_vo_flag_navi_vo_pz, payload(offset, 2))
    subtree:add_le (f.imu_ex_e_vo_flag_navi_us_vz, payload(offset, 2))
    subtree:add_le (f.imu_ex_e_vo_flag_navi_us_pz, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_imu_err_flag, payload(offset, 2))
    subtree:add_le (f.imu_ex_e_imu_err_vg_large, payload(offset, 2))
    subtree:add_le (f.imu_ex_e_imu_err_gps_yaw, payload(offset, 2))
    subtree:add_le (f.imu_ex_e_imu_err_mag_yaw, payload(offset, 2))
    subtree:add_le (f.imu_ex_e_imu_err_gps_consist, payload(offset, 2))
    subtree:add_le (f.imu_ex_e_imu_err_us_fail, payload(offset, 2))
    subtree:add_le (f.imu_ex_e_imu_init_ok_flag, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_vo_flag_rsv, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_imu_ex_cnt, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_imu_ex_fld28, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 42) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Ex: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Ex: Payload size different than expected") end
end

-- Flight log - Imu Tail 00 - 0x0820

f.imu_tail_00_wa_x_00 = ProtoField.float ("dji_p3_flyrec.imu_tail_00_wa_x_00", "Wa X 00", base.DEC)
f.imu_tail_00_wa_y_00 = ProtoField.float ("dji_p3_flyrec.imu_tail_00_wa_y_00", "Wa Y 00", base.DEC)
f.imu_tail_00_wa_z_00 = ProtoField.float ("dji_p3_flyrec.imu_tail_00_wa_z_00", "Wa Z 00", base.DEC)
f.imu_tail_00_w_x_00 = ProtoField.float ("dji_p3_flyrec.imu_tail_00_w_x_00", "W X 00", base.DEC)
f.imu_tail_00_w_y_00 = ProtoField.float ("dji_p3_flyrec.imu_tail_00_w_y_00", "W Y 00", base.DEC)
f.imu_tail_00_w_z_00 = ProtoField.float ("dji_p3_flyrec.imu_tail_00_w_z_00", "W Z 00", base.DEC)

local function flightrec_imu_tail_00_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_tail_00_wa_x_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_tail_00_wa_y_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_tail_00_wa_z_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_tail_00_w_x_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_tail_00_w_y_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_tail_00_w_z_00, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 24) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Tail 00: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Tail 00: Payload size different than expected") end
end

-- Flight log - Imu Atti 00 - 0x0800

f.imu_atti_00_longti_00 = ProtoField.double ("dji_p3_flyrec.imu_atti_00_longti_00", "Longti 00", base.DEC)
f.imu_atti_00_lati_00 = ProtoField.double ("dji_p3_flyrec.imu_atti_00_lati_00", "Lati 00", base.DEC)
f.imu_atti_00_alti_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_alti_00", "Alti 00", base.DEC)
f.imu_atti_00_acc_x_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_acc_x_00", "Acc X 00", base.DEC)
f.imu_atti_00_acc_y_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_acc_y_00", "Acc Y 00", base.DEC)
f.imu_atti_00_acc_z_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_acc_z_00", "Acc Z 00", base.DEC)
f.imu_atti_00_gyro_x_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_gyro_x_00", "Gyro X 00", base.DEC)
f.imu_atti_00_gyro_y_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_gyro_y_00", "Gyro Y 00", base.DEC)
f.imu_atti_00_gyro_z_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_gyro_z_00", "Gyro Z 00", base.DEC)
f.imu_atti_00_press_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_press_00", "Press 00", base.DEC)
f.imu_atti_00_q0_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_q0_00", "Q0 00", base.DEC)
f.imu_atti_00_q1_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_q1_00", "Q1 00", base.DEC)
f.imu_atti_00_q2_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_q2_00", "Q2 00", base.DEC)
f.imu_atti_00_q3_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_q3_00", "Q3 00", base.DEC)
f.imu_atti_00_ag_x_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_ag_x_00", "Ag X 00", base.DEC)
f.imu_atti_00_ag_y_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_ag_y_00", "Ag Y 00", base.DEC)
f.imu_atti_00_ag_z_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_ag_z_00", "Ag Z 00", base.DEC)
f.imu_atti_00_vg_x_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_vg_x_00", "Vg X 00", base.DEC)
f.imu_atti_00_vg_y_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_vg_y_00", "Vg Y 00", base.DEC)
f.imu_atti_00_vg_z_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_vg_z_00", "Vg Z 00", base.DEC)
f.imu_atti_00_gb_x_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_gb_x_00", "Gb X 00", base.DEC)
f.imu_atti_00_gb_y_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_gb_y_00", "Gb Y 00", base.DEC)
f.imu_atti_00_gb_z_00 = ProtoField.float ("dji_p3_flyrec.imu_atti_00_gb_z_00", "Gb Z 00", base.DEC)
f.imu_atti_00_m_x_00 = ProtoField.int16 ("dji_p3_flyrec.imu_atti_00_m_x_00", "M X 00", base.DEC)
f.imu_atti_00_m_y_00 = ProtoField.int16 ("dji_p3_flyrec.imu_atti_00_m_y_00", "M Y 00", base.DEC)
f.imu_atti_00_m_z_00 = ProtoField.int16 ("dji_p3_flyrec.imu_atti_00_m_z_00", "M Z 00", base.DEC)
f.imu_atti_00_temp_x_00 = ProtoField.int16 ("dji_p3_flyrec.imu_atti_00_temp_x_00", "Temp X 00", base.DEC)
f.imu_atti_00_temp_y_00 = ProtoField.int16 ("dji_p3_flyrec.imu_atti_00_temp_y_00", "Temp Y 00", base.DEC)
f.imu_atti_00_temp_z_00 = ProtoField.int16 ("dji_p3_flyrec.imu_atti_00_temp_z_00", "Temp Z 00", base.DEC)
f.imu_atti_00_sensor_monitor_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_atti_00_sensor_monitor_00", "Sensor Monitor 00", base.HEX)
f.imu_atti_00_filter_status_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_atti_00_filter_status_00", "Filter Status 00", base.HEX)
f.imu_atti_00_svn_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_atti_00_svn_00", "Svn 00", base.DEC, nil, nil, "Number of Global Nav System positioning satellites")
f.imu_atti_00_cnt_atti_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_atti_00_cnt_atti_00", "Cnt Atti 00", base.HEX)
--f.imu_atti_00_e_mod_m_00 = ProtoField.none ("dji_p3_flyrec.imu_atti_00_e_mod_m_00", "E Mod M 00", base.NONE, nil, nil, "sqrt(m_x_00*m_x_00+m_y_00*m_y_00+m_z_00*m_z_00)")
--f.imu_atti_00_e_pitch_00 = ProtoField.none ("dji_p3_flyrec.imu_atti_00_e_pitch_00", "E Pitch 00", base.NONE, nil, nil, "-asin_x(2*(q1_00*q3_00-q0_00*q2_00))/3.1415926*180")
--f.imu_atti_00_e_roll_00 = ProtoField.none ("dji_p3_flyrec.imu_atti_00_e_roll_00", "E Roll 00", base.NONE, nil, nil, "atan2(2*(q2_00*q3_00+q0_00*q1_00),1-2*(q1_00*q1_00+q2_00*q2_00))/3.1415926*180")
--f.imu_atti_00_e_yaw_00 = ProtoField.none ("dji_p3_flyrec.imu_atti_00_e_yaw_00", "E Yaw 00", base.NONE, nil, nil, "atan2(2*(q1_00*q2_00+q0_00*q3_00),1-2*(q2_00*q2_00+q3_00*q3_00))/3.1415926*180")
--f.imu_atti_00_e_yaw_from_m_00 = ProtoField.none ("dji_p3_flyrec.imu_atti_00_e_yaw_from_m_00", "E Yaw From M 00", base.NONE, nil, nil, "atan2(-(m_y_00*cos(E_roll_00/57.29578)-m_z_00*sin(E_roll_00/57.29578)),m_x_00*cos(E_pitch_00/57.29578)+m_y_00*sin(E_pitch_00/57.29578)*sin(E_roll_00/57.29578)+m_z_00*sin(E_pitch_00/57.29578)*cos(E_roll_00/57.29578))*180/3.14159265")

local function flightrec_imu_atti_00_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_atti_00_longti_00, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_atti_00_lati_00, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_atti_00_alti_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_acc_x_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_acc_y_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_acc_z_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_gyro_x_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_gyro_y_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_gyro_z_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_press_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_q0_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_q1_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_q2_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_q3_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_ag_x_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_ag_y_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_ag_z_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_vg_x_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_vg_y_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_vg_z_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_gb_x_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_gb_y_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_gb_z_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_00_m_x_00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_00_m_y_00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_00_m_z_00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_00_temp_x_00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_00_temp_y_00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_00_temp_z_00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_00_sensor_monitor_00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_00_filter_status_00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_00_svn_00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_00_cnt_atti_00, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 120) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Atti 00: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Atti 00: Payload size different than expected") end
end

-- Flight log - Imu Ex 00 - 0x0810

f.imu_ex_00_vo_vx_00 = ProtoField.float ("dji_p3_flyrec.imu_ex_00_vo_vx_00", "Vo Vx 00", base.DEC)
f.imu_ex_00_vo_vy_00 = ProtoField.float ("dji_p3_flyrec.imu_ex_00_vo_vy_00", "Vo Vy 00", base.DEC)
f.imu_ex_00_vo_vz_00 = ProtoField.float ("dji_p3_flyrec.imu_ex_00_vo_vz_00", "Vo Vz 00", base.DEC)
f.imu_ex_00_vo_px_00 = ProtoField.float ("dji_p3_flyrec.imu_ex_00_vo_px_00", "Vo Px 00", base.DEC)
f.imu_ex_00_vo_py_00 = ProtoField.float ("dji_p3_flyrec.imu_ex_00_vo_py_00", "Vo Py 00", base.DEC)
f.imu_ex_00_vo_pz_00 = ProtoField.float ("dji_p3_flyrec.imu_ex_00_vo_pz_00", "Vo Pz 00", base.DEC)
f.imu_ex_00_us_v_00 = ProtoField.float ("dji_p3_flyrec.imu_ex_00_us_v_00", "Us V 00", base.DEC)
f.imu_ex_00_us_p_00 = ProtoField.float ("dji_p3_flyrec.imu_ex_00_us_p_00", "Us P 00", base.DEC, nil, nil, "Relative height; unit:m")
f.imu_ex_00_vo_flag_navi_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_00_vo_flag_navi_00", "Vo Flag Navi 00", base.HEX)
  f.imu_ex_00_e_vo_flag_navi_vo_vx_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_00_e_vo_flag_navi_vo_vx_00", "E Vo Flag Navi Vo Vx 00", base.HEX, nil, 0x01, nil)
  f.imu_ex_00_e_vo_flag_navi_vo_vy_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_00_e_vo_flag_navi_vo_vy_00", "E Vo Flag Navi Vo Vy 00", base.HEX, nil, 0x02, nil)
  f.imu_ex_00_e_vo_flag_navi_vo_vz_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_00_e_vo_flag_navi_vo_vz_00", "E Vo Flag Navi Vo Vz 00", base.HEX, nil, 0x04, nil)
  f.imu_ex_00_e_vo_flag_navi_vo_px_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_00_e_vo_flag_navi_vo_px_00", "E Vo Flag Navi Vo Px 00", base.HEX, nil, 0x08, nil)
  f.imu_ex_00_e_vo_flag_navi_vo_py_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_00_e_vo_flag_navi_vo_py_00", "E Vo Flag Navi Vo Py 00", base.HEX, nil, 0x10, nil)
  f.imu_ex_00_e_vo_flag_navi_vo_pz_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_00_e_vo_flag_navi_vo_pz_00", "E Vo Flag Navi Vo Pz 00", base.HEX, nil, 0x20, nil)
  f.imu_ex_00_e_vo_flag_navi_us_vz_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_00_e_vo_flag_navi_us_vz_00", "E Vo Flag Navi Us Vz 00", base.HEX, nil, 0x40, nil)
  f.imu_ex_00_e_vo_flag_navi_us_pz_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_00_e_vo_flag_navi_us_pz_00", "E Vo Flag Navi Us Pz 00", base.HEX, nil, 0x80, "Relative height flag; 0=Unavailable, 1=Available")
f.imu_ex_00_imu_err_flag_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_00_imu_err_flag_00", "Imu Err Flag 00", base.HEX)
  f.imu_ex_00_e_imu_err_vg_large_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_00_e_imu_err_vg_large_00", "E Imu Err Vg Large 00", base.HEX, nil, 0x01, nil)
  f.imu_ex_00_e_imu_err_gps_yaw_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_00_e_imu_err_gps_yaw_00", "E Imu Err Gps Yaw 00", base.HEX, nil, 0x02, nil)
  f.imu_ex_00_e_imu_err_mag_yaw_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_00_e_imu_err_mag_yaw_00", "E Imu Err Mag Yaw 00", base.HEX, nil, 0x04, nil)
  f.imu_ex_00_e_imu_err_gps_consist_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_00_e_imu_err_gps_consist_00", "E Imu Err Gps Consist 00", base.HEX, nil, 0x08, nil)
  f.imu_ex_00_e_imu_err_us_fail_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_00_e_imu_err_us_fail_00", "E Imu Err Us Fail 00", base.HEX, nil, 0x10, nil)
  f.imu_ex_00_e_imu_err_init_ok_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_00_e_imu_err_init_ok_00", "E Imu Err Init Ok 00", base.HEX, nil, 0x20, nil)
f.imu_ex_00_vo_flag_rsv_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_00_vo_flag_rsv_00", "Vo Flag Rsv 00", base.HEX)
f.imu_ex_00_imu_ex_cnt_00 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_00_imu_ex_cnt_00", "Imu Ex Cnt 00", base.HEX)

local function flightrec_imu_ex_00_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_ex_00_vo_vx_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_00_vo_vy_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_00_vo_vz_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_00_vo_px_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_00_vo_py_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_00_vo_pz_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_00_us_v_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_00_us_p_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_00_vo_flag_navi_00, payload(offset, 2))
    subtree:add_le (f.imu_ex_00_e_vo_flag_navi_vo_vx_00, payload(offset, 2))
    subtree:add_le (f.imu_ex_00_e_vo_flag_navi_vo_vy_00, payload(offset, 2))
    subtree:add_le (f.imu_ex_00_e_vo_flag_navi_vo_vz_00, payload(offset, 2))
    subtree:add_le (f.imu_ex_00_e_vo_flag_navi_vo_px_00, payload(offset, 2))
    subtree:add_le (f.imu_ex_00_e_vo_flag_navi_vo_py_00, payload(offset, 2))
    subtree:add_le (f.imu_ex_00_e_vo_flag_navi_vo_pz_00, payload(offset, 2))
    subtree:add_le (f.imu_ex_00_e_vo_flag_navi_us_vz_00, payload(offset, 2))
    subtree:add_le (f.imu_ex_00_e_vo_flag_navi_us_pz_00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_00_imu_err_flag_00, payload(offset, 2))
    subtree:add_le (f.imu_ex_00_e_imu_err_vg_large_00, payload(offset, 2))
    subtree:add_le (f.imu_ex_00_e_imu_err_gps_yaw_00, payload(offset, 2))
    subtree:add_le (f.imu_ex_00_e_imu_err_mag_yaw_00, payload(offset, 2))
    subtree:add_le (f.imu_ex_00_e_imu_err_gps_consist_00, payload(offset, 2))
    subtree:add_le (f.imu_ex_00_e_imu_err_us_fail_00, payload(offset, 2))
    subtree:add_le (f.imu_ex_00_e_imu_err_init_ok_00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_00_vo_flag_rsv_00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_00_imu_ex_cnt_00, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 40) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Ex 00: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Ex 00: Payload size different than expected") end
end

-- Flight log - Imu Tail 01 - 0x0821

f.imu_tail_01_wa_x_01 = ProtoField.float ("dji_p3_flyrec.imu_tail_01_wa_x_01", "Wa X 01", base.DEC)
f.imu_tail_01_wa_y_01 = ProtoField.float ("dji_p3_flyrec.imu_tail_01_wa_y_01", "Wa Y 01", base.DEC)
f.imu_tail_01_wa_z_01 = ProtoField.float ("dji_p3_flyrec.imu_tail_01_wa_z_01", "Wa Z 01", base.DEC)
f.imu_tail_01_w_x_01 = ProtoField.float ("dji_p3_flyrec.imu_tail_01_w_x_01", "W X 01", base.DEC)
f.imu_tail_01_w_y_01 = ProtoField.float ("dji_p3_flyrec.imu_tail_01_w_y_01", "W Y 01", base.DEC)
f.imu_tail_01_w_z_01 = ProtoField.float ("dji_p3_flyrec.imu_tail_01_w_z_01", "W Z 01", base.DEC)

local function flightrec_imu_tail_01_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_tail_01_wa_x_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_tail_01_wa_y_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_tail_01_wa_z_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_tail_01_w_x_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_tail_01_w_y_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_tail_01_w_z_01, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 24) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Tail 01: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Tail 01: Payload size different than expected") end
end

-- Flight log - Imu Atti 01 - 0x0801

f.imu_atti_01_longti_01 = ProtoField.double ("dji_p3_flyrec.imu_atti_01_longti_01", "Longti 01", base.DEC)
f.imu_atti_01_lati_01 = ProtoField.double ("dji_p3_flyrec.imu_atti_01_lati_01", "Lati 01", base.DEC)
f.imu_atti_01_alti_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_alti_01", "Alti 01", base.DEC)
f.imu_atti_01_acc_x_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_acc_x_01", "Acc X 01", base.DEC)
f.imu_atti_01_acc_y_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_acc_y_01", "Acc Y 01", base.DEC)
f.imu_atti_01_acc_z_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_acc_z_01", "Acc Z 01", base.DEC)
f.imu_atti_01_gyro_x_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_gyro_x_01", "Gyro X 01", base.DEC)
f.imu_atti_01_gyro_y_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_gyro_y_01", "Gyro Y 01", base.DEC)
f.imu_atti_01_gyro_z_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_gyro_z_01", "Gyro Z 01", base.DEC)
f.imu_atti_01_press_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_press_01", "Press 01", base.DEC)
f.imu_atti_01_q0_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_q0_01", "Q0 01", base.DEC)
f.imu_atti_01_q1_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_q1_01", "Q1 01", base.DEC)
f.imu_atti_01_q2_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_q2_01", "Q2 01", base.DEC)
f.imu_atti_01_q3_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_q3_01", "Q3 01", base.DEC)
f.imu_atti_01_ag_x_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_ag_x_01", "Ag X 01", base.DEC)
f.imu_atti_01_ag_y_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_ag_y_01", "Ag Y 01", base.DEC)
f.imu_atti_01_ag_z_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_ag_z_01", "Ag Z 01", base.DEC)
f.imu_atti_01_vg_x_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_vg_x_01", "Vg X 01", base.DEC)
f.imu_atti_01_vg_y_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_vg_y_01", "Vg Y 01", base.DEC)
f.imu_atti_01_vg_z_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_vg_z_01", "Vg Z 01", base.DEC)
f.imu_atti_01_gb_x_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_gb_x_01", "Gb X 01", base.DEC)
f.imu_atti_01_gb_y_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_gb_y_01", "Gb Y 01", base.DEC)
f.imu_atti_01_gb_z_01 = ProtoField.float ("dji_p3_flyrec.imu_atti_01_gb_z_01", "Gb Z 01", base.DEC)
f.imu_atti_01_m_x_01 = ProtoField.int16 ("dji_p3_flyrec.imu_atti_01_m_x_01", "M X 01", base.DEC)
f.imu_atti_01_m_y_01 = ProtoField.int16 ("dji_p3_flyrec.imu_atti_01_m_y_01", "M Y 01", base.DEC)
f.imu_atti_01_m_z_01 = ProtoField.int16 ("dji_p3_flyrec.imu_atti_01_m_z_01", "M Z 01", base.DEC)
f.imu_atti_01_temp_x_01 = ProtoField.int16 ("dji_p3_flyrec.imu_atti_01_temp_x_01", "Temp X 01", base.DEC)
f.imu_atti_01_temp_y_01 = ProtoField.int16 ("dji_p3_flyrec.imu_atti_01_temp_y_01", "Temp Y 01", base.DEC)
f.imu_atti_01_temp_z_01 = ProtoField.int16 ("dji_p3_flyrec.imu_atti_01_temp_z_01", "Temp Z 01", base.DEC)
f.imu_atti_01_sensor_monitor_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_atti_01_sensor_monitor_01", "Sensor Monitor 01", base.HEX)
f.imu_atti_01_filter_status_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_atti_01_filter_status_01", "Filter Status 01", base.HEX)
f.imu_atti_01_svn_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_atti_01_svn_01", "Svn 01", base.DEC, nil, nil, "Number of Global Nav System positioning satellites")
f.imu_atti_01_cnt_atti_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_atti_01_cnt_atti_01", "Cnt Atti 01", base.HEX)
--f.imu_atti_01_e_pitch_01 = ProtoField.none ("dji_p3_flyrec.imu_atti_01_e_pitch_01", "E Pitch 01", base.NONE, nil, nil, "-asin_x(2*(q1_01*q3_01-q0_01*q2_01))/3.1415926*180")
--f.imu_atti_01_e_roll_01 = ProtoField.none ("dji_p3_flyrec.imu_atti_01_e_roll_01", "E Roll 01", base.NONE, nil, nil, "atan2(2*(q2_01*q3_01+q0_01*q1_01),1-2*(q1_01*q1_01+q2_01*q2_01))/3.1415926*180")
--f.imu_atti_01_e_yaw_01 = ProtoField.none ("dji_p3_flyrec.imu_atti_01_e_yaw_01", "E Yaw 01", base.NONE, nil, nil, "atan2(2*(q1_01*q2_01+q0_01*q3_01),1-2*(q2_01*q2_01+q3_01*q3_01))/3.1415926*180")
--f.imu_atti_01_e_yaw_from_m_01 = ProtoField.none ("dji_p3_flyrec.imu_atti_01_e_yaw_from_m_01", "E Yaw From M 01", base.NONE, nil, nil, "atan2(-(m_y_01*cos(E_roll_01/57.29578)-m_z_01*sin(E_roll_01/57.29578)),m_x_01*cos(E_pitch_01/57.29578)+m_y_01*sin(E_pitch_01/57.29578)*sin(E_roll_01/57.29578)+m_z_01*sin(E_pitch_01/57.29578)*cos(E_roll_01/57.29578))*180/3.14159265")

local function flightrec_imu_atti_01_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_atti_01_longti_01, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_atti_01_lati_01, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_atti_01_alti_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_acc_x_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_acc_y_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_acc_z_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_gyro_x_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_gyro_y_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_gyro_z_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_press_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_q0_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_q1_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_q2_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_q3_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_ag_x_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_ag_y_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_ag_z_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_vg_x_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_vg_y_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_vg_z_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_gb_x_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_gb_y_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_gb_z_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_01_m_x_01, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_01_m_y_01, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_01_m_z_01, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_01_temp_x_01, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_01_temp_y_01, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_01_temp_z_01, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_01_sensor_monitor_01, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_01_filter_status_01, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_01_svn_01, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_01_cnt_atti_01, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 120) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Atti 01: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Atti 01: Payload size different than expected") end
end

-- Flight log - Imu Ex 01 - 0x0811

f.imu_ex_01_vo_vx_01 = ProtoField.float ("dji_p3_flyrec.imu_ex_01_vo_vx_01", "Vo Vx 01", base.DEC)
f.imu_ex_01_vo_vy_01 = ProtoField.float ("dji_p3_flyrec.imu_ex_01_vo_vy_01", "Vo Vy 01", base.DEC)
f.imu_ex_01_vo_vz_01 = ProtoField.float ("dji_p3_flyrec.imu_ex_01_vo_vz_01", "Vo Vz 01", base.DEC)
f.imu_ex_01_vo_px_01 = ProtoField.float ("dji_p3_flyrec.imu_ex_01_vo_px_01", "Vo Px 01", base.DEC)
f.imu_ex_01_vo_py_01 = ProtoField.float ("dji_p3_flyrec.imu_ex_01_vo_py_01", "Vo Py 01", base.DEC)
f.imu_ex_01_vo_pz_01 = ProtoField.float ("dji_p3_flyrec.imu_ex_01_vo_pz_01", "Vo Pz 01", base.DEC)
f.imu_ex_01_us_v_01 = ProtoField.float ("dji_p3_flyrec.imu_ex_01_us_v_01", "Us V 01", base.DEC)
f.imu_ex_01_us_p_01 = ProtoField.float ("dji_p3_flyrec.imu_ex_01_us_p_01", "Us P 01", base.DEC)
f.imu_ex_01_vo_flag_navi_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_01_vo_flag_navi_01", "Vo Flag Navi 01", base.HEX)
  f.imu_ex_01_e_vo_flag_navi_vo_vx_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_01_e_vo_flag_navi_vo_vx_01", "E Vo Flag Navi Vo Vx 01", base.HEX, nil, 0x01, nil)
  f.imu_ex_01_e_vo_flag_navi_vo_vy_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_01_e_vo_flag_navi_vo_vy_01", "E Vo Flag Navi Vo Vy 01", base.HEX, nil, 0x02, nil)
  f.imu_ex_01_e_vo_flag_navi_vo_vz_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_01_e_vo_flag_navi_vo_vz_01", "E Vo Flag Navi Vo Vz 01", base.HEX, nil, 0x04, nil)
  f.imu_ex_01_e_vo_flag_navi_vo_px_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_01_e_vo_flag_navi_vo_px_01", "E Vo Flag Navi Vo Px 01", base.HEX, nil, 0x08, nil)
  f.imu_ex_01_e_vo_flag_navi_vo_py_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_01_e_vo_flag_navi_vo_py_01", "E Vo Flag Navi Vo Py 01", base.HEX, nil, 0x10, nil)
  f.imu_ex_01_e_vo_flag_navi_vo_pz_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_01_e_vo_flag_navi_vo_pz_01", "E Vo Flag Navi Vo Pz 01", base.HEX, nil, 0x20, nil)
  f.imu_ex_01_e_vo_flag_navi_us_vz_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_01_e_vo_flag_navi_us_vz_01", "E Vo Flag Navi Us Vz 01", base.HEX, nil, 0x40, nil)
  f.imu_ex_01_e_vo_flag_navi_us_pz_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_01_e_vo_flag_navi_us_pz_01", "E Vo Flag Navi Us Pz 01", base.HEX, nil, 0x80, nil)
f.imu_ex_01_imu_err_flag_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_01_imu_err_flag_01", "Imu Err Flag 01", base.HEX)
  f.imu_ex_01_e_imu_err_vg_large_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_01_e_imu_err_vg_large_01", "E Imu Err Vg Large 01", base.HEX, nil, 0x01, nil)
  f.imu_ex_01_e_imu_err_gps_yaw_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_01_e_imu_err_gps_yaw_01", "E Imu Err Gps Yaw 01", base.HEX, nil, 0x02, nil)
  f.imu_ex_01_e_imu_err_mag_yaw_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_01_e_imu_err_mag_yaw_01", "E Imu Err Mag Yaw 01", base.HEX, nil, 0x04, nil)
  f.imu_ex_01_e_imu_err_gps_consist_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_01_e_imu_err_gps_consist_01", "E Imu Err Gps Consist 01", base.HEX, nil, 0x08, nil)
  f.imu_ex_01_e_imu_err_us_fail_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_01_e_imu_err_us_fail_01", "E Imu Err Us Fail 01", base.HEX, nil, 0x10, nil)
  f.imu_ex_01_e_imu_err_init_ok_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_01_e_imu_err_init_ok_01", "E Imu Err Init Ok 01", base.HEX, nil, 0x20, nil)
f.imu_ex_01_vo_flag_rsv_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_01_vo_flag_rsv_01", "Vo Flag Rsv 01", base.HEX)
f.imu_ex_01_imu_ex_cnt_01 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_01_imu_ex_cnt_01", "Imu Ex Cnt 01", base.HEX)

local function flightrec_imu_ex_01_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_ex_01_vo_vx_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_01_vo_vy_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_01_vo_vz_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_01_vo_px_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_01_vo_py_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_01_vo_pz_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_01_us_v_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_01_us_p_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_01_vo_flag_navi_01, payload(offset, 2))
    subtree:add_le (f.imu_ex_01_e_vo_flag_navi_vo_vx_01, payload(offset, 2))
    subtree:add_le (f.imu_ex_01_e_vo_flag_navi_vo_vy_01, payload(offset, 2))
    subtree:add_le (f.imu_ex_01_e_vo_flag_navi_vo_vz_01, payload(offset, 2))
    subtree:add_le (f.imu_ex_01_e_vo_flag_navi_vo_px_01, payload(offset, 2))
    subtree:add_le (f.imu_ex_01_e_vo_flag_navi_vo_py_01, payload(offset, 2))
    subtree:add_le (f.imu_ex_01_e_vo_flag_navi_vo_pz_01, payload(offset, 2))
    subtree:add_le (f.imu_ex_01_e_vo_flag_navi_us_vz_01, payload(offset, 2))
    subtree:add_le (f.imu_ex_01_e_vo_flag_navi_us_pz_01, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_01_imu_err_flag_01, payload(offset, 2))
    subtree:add_le (f.imu_ex_01_e_imu_err_vg_large_01, payload(offset, 2))
    subtree:add_le (f.imu_ex_01_e_imu_err_gps_yaw_01, payload(offset, 2))
    subtree:add_le (f.imu_ex_01_e_imu_err_mag_yaw_01, payload(offset, 2))
    subtree:add_le (f.imu_ex_01_e_imu_err_gps_consist_01, payload(offset, 2))
    subtree:add_le (f.imu_ex_01_e_imu_err_us_fail_01, payload(offset, 2))
    subtree:add_le (f.imu_ex_01_e_imu_err_init_ok_01, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_01_vo_flag_rsv_01, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_01_imu_ex_cnt_01, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 40) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Ex 01: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Ex 01: Payload size different than expected") end
end

-- Flight log - Imu Tail 02 - 0x0822

f.imu_tail_02_wa_x_02 = ProtoField.float ("dji_p3_flyrec.imu_tail_02_wa_x_02", "Wa X 02", base.DEC)
f.imu_tail_02_wa_y_02 = ProtoField.float ("dji_p3_flyrec.imu_tail_02_wa_y_02", "Wa Y 02", base.DEC)
f.imu_tail_02_wa_z_02 = ProtoField.float ("dji_p3_flyrec.imu_tail_02_wa_z_02", "Wa Z 02", base.DEC)
f.imu_tail_02_w_x_02 = ProtoField.float ("dji_p3_flyrec.imu_tail_02_w_x_02", "W X 02", base.DEC)
f.imu_tail_02_w_y_02 = ProtoField.float ("dji_p3_flyrec.imu_tail_02_w_y_02", "W Y 02", base.DEC)
f.imu_tail_02_w_z_02 = ProtoField.float ("dji_p3_flyrec.imu_tail_02_w_z_02", "W Z 02", base.DEC)

local function flightrec_imu_tail_02_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_tail_02_wa_x_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_tail_02_wa_y_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_tail_02_wa_z_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_tail_02_w_x_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_tail_02_w_y_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_tail_02_w_z_02, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 24) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Tail 02: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Tail 02: Payload size different than expected") end
end

-- Flight log - Imu Atti 02 - 0x0802

f.imu_atti_02_longtii_02 = ProtoField.double ("dji_p3_flyrec.imu_atti_02_longtii_02", "Longtii 02", base.DEC)
f.imu_atti_02_latii_02 = ProtoField.double ("dji_p3_flyrec.imu_atti_02_latii_02", "Latii 02", base.DEC)
f.imu_atti_02_altii_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_altii_02", "Altii 02", base.DEC)
f.imu_atti_02_acc_x_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_acc_x_02", "Acc X 02", base.DEC)
f.imu_atti_02_acc_y_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_acc_y_02", "Acc Y 02", base.DEC)
f.imu_atti_02_acc_z_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_acc_z_02", "Acc Z 02", base.DEC)
f.imu_atti_02_gyro_x_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_gyro_x_02", "Gyro X 02", base.DEC)
f.imu_atti_02_gyro_y_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_gyro_y_02", "Gyro Y 02", base.DEC)
f.imu_atti_02_gyro_z_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_gyro_z_02", "Gyro Z 02", base.DEC)
f.imu_atti_02_press_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_press_02", "Press 02", base.DEC)
f.imu_atti_02_q0_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_q0_02", "Q0 02", base.DEC)
f.imu_atti_02_q1_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_q1_02", "Q1 02", base.DEC)
f.imu_atti_02_q2_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_q2_02", "Q2 02", base.DEC)
f.imu_atti_02_q3_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_q3_02", "Q3 02", base.DEC)
f.imu_atti_02_ag_x_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_ag_x_02", "Ag X 02", base.DEC)
f.imu_atti_02_ag_y_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_ag_y_02", "Ag Y 02", base.DEC)
f.imu_atti_02_ag_z_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_ag_z_02", "Ag Z 02", base.DEC)
f.imu_atti_02_vg_x_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_vg_x_02", "Vg X 02", base.DEC)
f.imu_atti_02_vg_y_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_vg_y_02", "Vg Y 02", base.DEC)
f.imu_atti_02_vg_z_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_vg_z_02", "Vg Z 02", base.DEC)
f.imu_atti_02_gb_x_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_gb_x_02", "Gb X 02", base.DEC)
f.imu_atti_02_gb_y_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_gb_y_02", "Gb Y 02", base.DEC)
f.imu_atti_02_gb_z_02 = ProtoField.float ("dji_p3_flyrec.imu_atti_02_gb_z_02", "Gb Z 02", base.DEC)
f.imu_atti_02_m_x_02 = ProtoField.int16 ("dji_p3_flyrec.imu_atti_02_m_x_02", "M X 02", base.DEC)
f.imu_atti_02_m_y_02 = ProtoField.int16 ("dji_p3_flyrec.imu_atti_02_m_y_02", "M Y 02", base.DEC)
f.imu_atti_02_m_z_02 = ProtoField.int16 ("dji_p3_flyrec.imu_atti_02_m_z_02", "M Z 02", base.DEC)
f.imu_atti_02_temp_x_02 = ProtoField.int16 ("dji_p3_flyrec.imu_atti_02_temp_x_02", "Temp X 02", base.DEC)
f.imu_atti_02_temp_y_02 = ProtoField.int16 ("dji_p3_flyrec.imu_atti_02_temp_y_02", "Temp Y 02", base.DEC)
f.imu_atti_02_temp_z_02 = ProtoField.int16 ("dji_p3_flyrec.imu_atti_02_temp_z_02", "Temp Z 02", base.DEC)
f.imu_atti_02_sensor_monitor_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_atti_02_sensor_monitor_02", "Sensor Monitor 02", base.HEX)
f.imu_atti_02_filter_status_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_atti_02_filter_status_02", "Filter Status 02", base.HEX)
f.imu_atti_02_svn_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_atti_02_svn_02", "Svn 02", base.DEC, nil, nil, "Number of Global Nav System positioning satellites")
f.imu_atti_02_cnt_atti_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_atti_02_cnt_atti_02", "Cnt Atti 02", base.HEX)
--f.imu_atti_02_e_pitch_02 = ProtoField.none ("dji_p3_flyrec.imu_atti_02_e_pitch_02", "E Pitch 02", base.NONE, nil, nil, "-asin_x(2*(q1_02*q3_02-q0_02*q2_02))/3.1415926*180")
--f.imu_atti_02_e_roll_02 = ProtoField.none ("dji_p3_flyrec.imu_atti_02_e_roll_02", "E Roll 02", base.NONE, nil, nil, "atan2(2*(q2_02*q3_02+q0_02*q1_02),1-2*(q1_02*q1_02+q2_02*q2_02))/3.1415926*180")
--f.imu_atti_02_e_yaw_02 = ProtoField.none ("dji_p3_flyrec.imu_atti_02_e_yaw_02", "E Yaw 02", base.NONE, nil, nil, "atan2(2*(q1_02*q2_02+q0_02*q3_02),1-2*(q2_02*q2_02+q3_02*q3_02))/3.1415926*180")
--f.imu_atti_02_e_yaw_from_m_02 = ProtoField.none ("dji_p3_flyrec.imu_atti_02_e_yaw_from_m_02", "E Yaw From M 02", base.NONE, nil, nil, "atan2(-(m_y_02*cos(E_roll_02/57.29578)-m_z_02*sin(E_roll_02/57.29578)),m_x_02*cos(E_pitch_02/57.29578)+m_y_02*sin(E_pitch_02/57.29578)*sin(E_roll_02/57.29578)+m_z_02*sin(E_pitch_02/57.29578)*cos(E_roll_02/57.29578))*180/3.14159265")

local function flightrec_imu_atti_02_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_atti_02_longtii_02, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_atti_02_latii_02, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_atti_02_altii_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_acc_x_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_acc_y_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_acc_z_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_gyro_x_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_gyro_y_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_gyro_z_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_press_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_q0_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_q1_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_q2_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_q3_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_ag_x_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_ag_y_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_ag_z_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_vg_x_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_vg_y_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_vg_z_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_gb_x_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_gb_y_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_gb_z_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_02_m_x_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_02_m_y_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_02_m_z_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_02_temp_x_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_02_temp_y_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_02_temp_z_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_02_sensor_monitor_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_02_filter_status_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_02_svn_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_02_cnt_atti_02, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 120) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Atti 02: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Atti 02: Payload size different than expected") end
end

-- Flight log - Imu Ex 02 - 0x0812

f.imu_ex_02_vo_vx_02 = ProtoField.float ("dji_p3_flyrec.imu_ex_02_vo_vx_02", "Vo Vx 02", base.DEC)
f.imu_ex_02_vo_vy_02 = ProtoField.float ("dji_p3_flyrec.imu_ex_02_vo_vy_02", "Vo Vy 02", base.DEC)
f.imu_ex_02_vo_vz_02 = ProtoField.float ("dji_p3_flyrec.imu_ex_02_vo_vz_02", "Vo Vz 02", base.DEC)
f.imu_ex_02_vo_px_02 = ProtoField.float ("dji_p3_flyrec.imu_ex_02_vo_px_02", "Vo Px 02", base.DEC)
f.imu_ex_02_vo_py_02 = ProtoField.float ("dji_p3_flyrec.imu_ex_02_vo_py_02", "Vo Py 02", base.DEC)
f.imu_ex_02_vo_pz_02 = ProtoField.float ("dji_p3_flyrec.imu_ex_02_vo_pz_02", "Vo Pz 02", base.DEC)
f.imu_ex_02_us_v_02 = ProtoField.float ("dji_p3_flyrec.imu_ex_02_us_v_02", "Us V 02", base.DEC)
f.imu_ex_02_us_p_02 = ProtoField.float ("dji_p3_flyrec.imu_ex_02_us_p_02", "Us P 02", base.DEC)
f.imu_ex_02_vo_flag_navi_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_vo_flag_navi_02", "Vo Flag Navi 02", base.HEX)
  f.imu_ex_02_e_vo_flag_navi_vo_vx_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_e_vo_flag_navi_vo_vx_02", "E Vo Flag Navi Vo Vx 02", base.HEX, nil, 0x01, nil)
  f.imu_ex_02_e_vo_flag_navi_vo_vy_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_e_vo_flag_navi_vo_vy_02", "E Vo Flag Navi Vo Vy 02", base.HEX, nil, 0x02, nil)
  f.imu_ex_02_e_vo_flag_navi_vo_vz_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_e_vo_flag_navi_vo_vz_02", "E Vo Flag Navi Vo Vz 02", base.HEX, nil, 0x04, nil)
  f.imu_ex_02_e_vo_flag_navi_vo_px_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_e_vo_flag_navi_vo_px_02", "E Vo Flag Navi Vo Px 02", base.HEX, nil, 0x08, nil)
  f.imu_ex_02_e_vo_flag_navi_vo_py_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_e_vo_flag_navi_vo_py_02", "E Vo Flag Navi Vo Py 02", base.HEX, nil, 0x10, nil)
  f.imu_ex_02_e_vo_flag_navi_vo_pz_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_e_vo_flag_navi_vo_pz_02", "E Vo Flag Navi Vo Pz 02", base.HEX, nil, 0x20, nil)
  f.imu_ex_02_e_vo_flag_navi_us_vz_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_e_vo_flag_navi_us_vz_02", "E Vo Flag Navi Us Vz 02", base.HEX, nil, 0x40, nil)
  f.imu_ex_02_e_vo_flag_navi_us_pz_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_e_vo_flag_navi_us_pz_02", "E Vo Flag Navi Us Pz 02", base.HEX, nil, 0x80, nil)
f.imu_ex_02_imu_err_flag_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_imu_err_flag_02", "Imu Err Flag 02", base.HEX)
  f.imu_ex_02_e_imu_err_vg_large_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_e_imu_err_vg_large_02", "E Imu Err Vg Large 02", base.HEX, nil, 0x01, nil)
  f.imu_ex_02_e_imu_err_gps_yaw_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_e_imu_err_gps_yaw_02", "E Imu Err Gps Yaw 02", base.HEX, nil, 0x02, nil)
  f.imu_ex_02_e_imu_err_mag_yaw_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_e_imu_err_mag_yaw_02", "E Imu Err Mag Yaw 02", base.HEX, nil, 0x04, nil)
  f.imu_ex_02_e_imu_err_gps_consist_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_e_imu_err_gps_consist_02", "E Imu Err Gps Consist 02", base.HEX, nil, 0x08, nil)
  f.imu_ex_02_e_imu_err_us_fail_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_e_imu_err_us_fail_02", "E Imu Err Us Fail 02", base.HEX, nil, 0x10, nil)
  f.imu_ex_02_e_imu_err_init_ok_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_e_imu_err_init_ok_02", "E Imu Err Init Ok 02", base.HEX, nil, 0x20, nil)
f.imu_ex_02_vo_flag_rsv_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_vo_flag_rsv_02", "Vo Flag Rsv 02", base.HEX)
f.imu_ex_02_imu_ex_cnt_02 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_imu_ex_cnt_02", "Imu Ex Cnt 02", base.DEC, nil, nil, "Sequence counter increased each time the packet of this type is prepared")
f.imu_ex_02_imu_ex_fld28 = ProtoField.uint16 ("dji_p3_flyrec.imu_ex_02_imu_ex_fld28", "Field28", base.HEX)


local function flightrec_imu_ex_02_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_ex_02_vo_vx_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_02_vo_vy_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_02_vo_vz_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_02_vo_px_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_02_vo_py_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_02_vo_pz_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_02_us_v_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_02_us_p_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_02_vo_flag_navi_02, payload(offset, 2))
    subtree:add_le (f.imu_ex_02_e_vo_flag_navi_vo_vx_02, payload(offset, 2))
    subtree:add_le (f.imu_ex_02_e_vo_flag_navi_vo_vy_02, payload(offset, 2))
    subtree:add_le (f.imu_ex_02_e_vo_flag_navi_vo_vz_02, payload(offset, 2))
    subtree:add_le (f.imu_ex_02_e_vo_flag_navi_vo_px_02, payload(offset, 2))
    subtree:add_le (f.imu_ex_02_e_vo_flag_navi_vo_py_02, payload(offset, 2))
    subtree:add_le (f.imu_ex_02_e_vo_flag_navi_vo_pz_02, payload(offset, 2))
    subtree:add_le (f.imu_ex_02_e_vo_flag_navi_us_vz_02, payload(offset, 2))
    subtree:add_le (f.imu_ex_02_e_vo_flag_navi_us_pz_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_02_imu_err_flag_02, payload(offset, 2))
    subtree:add_le (f.imu_ex_02_e_imu_err_vg_large_02, payload(offset, 2))
    subtree:add_le (f.imu_ex_02_e_imu_err_gps_yaw_02, payload(offset, 2))
    subtree:add_le (f.imu_ex_02_e_imu_err_mag_yaw_02, payload(offset, 2))
    subtree:add_le (f.imu_ex_02_e_imu_err_gps_consist_02, payload(offset, 2))
    subtree:add_le (f.imu_ex_02_e_imu_err_us_fail_02, payload(offset, 2))
    subtree:add_le (f.imu_ex_02_e_imu_err_init_ok_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_02_vo_flag_rsv_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_02_imu_ex_cnt_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_02_imu_ex_fld28, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 42) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Ex 02: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Ex 02: Payload size different than expected") end
end

-- Flight log - Compass - 0x0004

f.compass_magx = ProtoField.int16 ("dji_p3_flyrec.compass_magx", "Mag X", base.DEC)
f.compass_magy = ProtoField.int16 ("dji_p3_flyrec.compass_magy", "Mag Y", base.DEC)
f.compass_magz = ProtoField.int16 ("dji_p3_flyrec.compass_magz", "Mag Z", base.DEC)
f.compass_mag_cnt = ProtoField.uint16 ("dji_p3_flyrec.compass_mag_cnt", "Mag Cnt", base.DEC, nil, nil, "Sequence counter increased each time the packet of this type is prepared")

local function flightrec_compass_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.compass_magx, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.compass_magy, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.compass_magz, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.compass_mag_cnt, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Compass: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Compass: Payload size different than expected") end
end

-- Flight log - Gps Glns - 0x0005

f.gps_glns_gps_date = ProtoField.uint32 ("dji_p3_flyrec.gps_glns_gps_date", "Gps Date", base.DEC)
f.gps_glns_gps_time = ProtoField.uint32 ("dji_p3_flyrec.gps_glns_gps_time", "Gps Time", base.DEC)
f.gps_glns_gps_lon = ProtoField.int32 ("dji_p3_flyrec.gps_glns_gps_lon", "Gps Lon", base.DEC, nil, nil, "degrees; coordinate with 7 digits accuracy after decimal point")
f.gps_glns_gps_lat = ProtoField.int32 ("dji_p3_flyrec.gps_glns_gps_lat", "Gps Lat", base.DEC, nil, nil, "degrees; coordinate with 7 digits accuracy after decimal point")
f.gps_glns_hmsl = ProtoField.int32 ("dji_p3_flyrec.gps_glns_hmsl", "hMSL", base.DEC, nil, nil, "mm; height above mean sea level (height above geoid)")
f.gps_glns_vel_n = ProtoField.float ("dji_p3_flyrec.gps_glns_vel_n", "Vel N", base.DEC)
f.gps_glns_vel_e = ProtoField.float ("dji_p3_flyrec.gps_glns_vel_e", "Vel E", base.DEC)
f.gps_glns_vel_d = ProtoField.float ("dji_p3_flyrec.gps_glns_vel_d", "Vel D", base.DEC)
f.gps_glns_hdop = ProtoField.float ("dji_p3_flyrec.gps_glns_hdop", "HDoP", base.DEC, nil, nil, "horizontal dilution of precision")
f.gps_glns_pdop = ProtoField.float ("dji_p3_flyrec.gps_glns_pdop", "PDoP", base.DEC, nil, nil, "position dilution of precision")
f.gps_glns_gps_fix = ProtoField.float ("dji_p3_flyrec.gps_glns_gps_fix", "GPS Fix", base.DEC)
f.gps_glns_gnss_flag = ProtoField.float ("dji_p3_flyrec.gps_glns_gnss_flag", "GNSS Flag", base.DEC)
f.gps_glns_hacc = ProtoField.float ("dji_p3_flyrec.gps_glns_hacc", "Hacc", base.DEC)
f.gps_glns_sacc = ProtoField.float ("dji_p3_flyrec.gps_glns_sacc", "Sacc", base.DEC)
f.gps_glns_gps_used = ProtoField.uint32 ("dji_p3_flyrec.gps_glns_gps_used", "GPS Used", base.DEC, nil, nil, "Number of GPS satellites")
f.gps_glns_gln_used = ProtoField.uint32 ("dji_p3_flyrec.gps_glns_gln_used", "GLN Used", base.DEC, nil, nil, "Number of GLNS satellites")
f.gps_glns_numsv = ProtoField.uint16 ("dji_p3_flyrec.gps_glns_numsv", "NumSV", base.DEC, nil, nil, "Total number of Global Nav System positioning satellites")
--f.gps_glns_gpsstate = ProtoField.uint16 ("dji_p3_flyrec.gps_glns_gpsstate", "GPS State", base.HEX)
f.gps_glns_gpsglns_cnt = ProtoField.uint16 ("dji_p3_flyrec.gps_glns_gpsglns_cnt", "Gps Glns Count", base.DEC, nil, nil, "Sequence counter increased each time the packet of this type is prepared")


local function flightrec_gps_glns_dissector(payload, pinfo, subtree)
    local offset = 0


    local gps_date = payload(offset, 4):le_uint()
    local ts_year = (gps_date / 10000)
    local ts_month = (gps_date / 100) % 100
    local ts_day = (gps_date) % 100
    local gps_date_str = string.format("GPS Date: %d-%02d-%02d", ts_year, ts_month, ts_day)
    subtree:add_le (f.gps_glns_gps_date, payload(offset, 4), gps_date, gps_date_str)
    offset = offset + 4

    local gps_time = payload(offset, 4):le_uint()
    local ts_hour = (gps_time / 10000)
    local ts_min = (gps_time / 100) % 100
    local ts_sec = (gps_time) % 100
    local gps_time_str = string.format("GPS Time: %02d:%02d:%02d", ts_hour, ts_min, ts_sec)
    subtree:add_le (f.gps_glns_gps_time, payload(offset, 4), gps_time, gps_time_str)
    offset = offset + 4

    local gps_lon = payload(offset, 4):le_uint()
    local gps_lon_str = string.format("GPS Longitude: %.7f", gps_lon / 10000000)
    subtree:add_le (f.gps_glns_gps_lon, payload(offset, 4), gps_lon, gps_lon_str)
    offset = offset + 4

    local gps_lat = payload(offset, 4):le_uint()
    local gps_lat_str = string.format("GPS Latitude: %.7f", gps_lat / 10000000)
    subtree:add_le (f.gps_glns_gps_lat, payload(offset, 4), gps_lat, gps_lat_str)
    offset = offset + 4

    subtree:add_le (f.gps_glns_hmsl, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_glns_vel_n, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_glns_vel_e, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_glns_vel_d, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_glns_hdop, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_glns_pdop, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_glns_gps_fix, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_glns_gnss_flag, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_glns_hacc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_glns_sacc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_glns_gps_used, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_glns_gln_used, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_glns_numsv, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gps_glns_gpsglns_cnt, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 68) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gps Glns: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gps Glns: Payload size different than expected") end
end

-- Flight log - Gps Snr - 0x000b

f.gps_snr_gps_snr1 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr1", "Gps Snr1", base.HEX)
f.gps_snr_gps_snr2 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr2", "Gps Snr2", base.HEX)
f.gps_snr_gps_snr3 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr3", "Gps Snr3", base.HEX)
f.gps_snr_gps_snr4 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr4", "Gps Snr4", base.HEX)
f.gps_snr_gps_snr5 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr5", "Gps Snr5", base.HEX)
f.gps_snr_gps_snr6 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr6", "Gps Snr6", base.HEX)
f.gps_snr_gps_snr7 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr7", "Gps Snr7", base.HEX)
f.gps_snr_gps_snr8 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr8", "Gps Snr8", base.HEX)
f.gps_snr_gps_snr9 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr9", "Gps Snr9", base.HEX)
f.gps_snr_gps_snr10 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr10", "Gps Snr10", base.HEX)
f.gps_snr_gps_snr11 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr11", "Gps Snr11", base.HEX)
f.gps_snr_gps_snr12 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr12", "Gps Snr12", base.HEX)
f.gps_snr_gps_snr13 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr13", "Gps Snr13", base.HEX)
f.gps_snr_gps_snr14 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr14", "Gps Snr14", base.HEX)
f.gps_snr_gps_snr15 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr15", "Gps Snr15", base.HEX)
f.gps_snr_gps_snr16 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr16", "Gps Snr16", base.HEX)
f.gps_snr_gps_snr17 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr17", "Gps Snr17", base.HEX)
f.gps_snr_gps_snr18 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr18", "Gps Snr18", base.HEX)
f.gps_snr_gps_snr19 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr19", "Gps Snr19", base.HEX)
f.gps_snr_gps_snr20 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr20", "Gps Snr20", base.HEX)
f.gps_snr_gps_snr21 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr21", "Gps Snr21", base.HEX)
f.gps_snr_gps_snr22 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr22", "Gps Snr22", base.HEX)
f.gps_snr_gps_snr23 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr23", "Gps Snr23", base.HEX)
f.gps_snr_gps_snr24 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr24", "Gps Snr24", base.HEX)
f.gps_snr_gps_snr25 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr25", "Gps Snr25", base.HEX)
f.gps_snr_gps_snr26 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr26", "Gps Snr26", base.HEX)
f.gps_snr_gps_snr27 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr27", "Gps Snr27", base.HEX)
f.gps_snr_gps_snr28 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr28", "Gps Snr28", base.HEX)
f.gps_snr_gps_snr29 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr29", "Gps Snr29", base.HEX)
f.gps_snr_gps_snr30 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr30", "Gps Snr30", base.HEX)
f.gps_snr_gps_snr31 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr31", "Gps Snr31", base.HEX)
f.gps_snr_gps_snr32 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gps_snr32", "Gps Snr32", base.HEX)
f.gps_snr_gln_snr1 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr1", "Gln Snr1", base.HEX)
f.gps_snr_gln_snr2 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr2", "Gln Snr2", base.HEX)
f.gps_snr_gln_snr3 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr3", "Gln Snr3", base.HEX)
f.gps_snr_gln_snr4 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr4", "Gln Snr4", base.HEX)
f.gps_snr_gln_snr5 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr5", "Gln Snr5", base.HEX)
f.gps_snr_gln_snr6 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr6", "Gln Snr6", base.HEX)
f.gps_snr_gln_snr7 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr7", "Gln Snr7", base.HEX)
f.gps_snr_gln_snr8 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr8", "Gln Snr8", base.HEX)
f.gps_snr_gln_snr9 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr9", "Gln Snr9", base.HEX)
f.gps_snr_gln_snr10 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr10", "Gln Snr10", base.HEX)
f.gps_snr_gln_snr11 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr11", "Gln Snr11", base.HEX)
f.gps_snr_gln_snr12 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr12", "Gln Snr12", base.HEX)
f.gps_snr_gln_snr13 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr13", "Gln Snr13", base.HEX)
f.gps_snr_gln_snr14 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr14", "Gln Snr14", base.HEX)
f.gps_snr_gln_snr15 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr15", "Gln Snr15", base.HEX)
f.gps_snr_gln_snr16 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr16", "Gln Snr16", base.HEX)
f.gps_snr_gln_snr17 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr17", "Gln Snr17", base.HEX)
f.gps_snr_gln_snr18 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr18", "Gln Snr18", base.HEX)
f.gps_snr_gln_snr19 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr19", "Gln Snr19", base.HEX)
f.gps_snr_gln_snr20 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr20", "Gln Snr20", base.HEX)
f.gps_snr_gln_snr21 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr21", "Gln Snr21", base.HEX)
f.gps_snr_gln_snr22 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr22", "Gln Snr22", base.HEX)
f.gps_snr_gln_snr23 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr23", "Gln Snr23", base.HEX)
f.gps_snr_gln_snr24 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr24", "Gln Snr24", base.HEX)
f.gps_snr_gln_snr25 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr25", "Gln Snr25", base.HEX)
f.gps_snr_gln_snr26 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr26", "Gln Snr26", base.HEX)
f.gps_snr_gln_snr27 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr27", "Gln Snr27", base.HEX)
f.gps_snr_gln_snr28 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr28", "Gln Snr28", base.HEX)
f.gps_snr_gln_snr29 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr29", "Gln Snr29", base.HEX)
f.gps_snr_gln_snr30 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr30", "Gln Snr30", base.HEX)
f.gps_snr_gln_snr31 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr31", "Gln Snr31", base.HEX)
f.gps_snr_gln_snr32 = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_snr32", "Gln Snr32", base.HEX)
f.gps_snr_gln_cnt = ProtoField.uint8 ("dji_p3_flyrec.gps_snr_gln_cnt", "Gln Cnt", base.HEX)

local function flightrec_gps_snr_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.gps_snr_gps_snr1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr3, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr6, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr7, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr8, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr9, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr10, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr11, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr12, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr13, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr14, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr15, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr16, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr17, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr18, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr19, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr20, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr21, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr22, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr23, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr24, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr25, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr26, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr27, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr28, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr29, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr30, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr31, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gps_snr32, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr3, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr6, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr7, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr8, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr9, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr10, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr11, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr12, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr13, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr14, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr15, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr16, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr17, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr18, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr19, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr20, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr21, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr22, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr23, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr24, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr25, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr26, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr27, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr28, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr29, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr30, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr31, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_snr32, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gps_snr_gln_cnt, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 65) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gps Snr: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gps Snr: Payload size different than expected") end
end

-- Flight log - Pt3 Gps Snr - 0x0061

f.pt3_gps_snr_pt3_gps_snr1 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr1", "Pt3 Gps Snr1", base.HEX)
f.pt3_gps_snr_pt3_gps_snr2 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr2", "Pt3 Gps Snr2", base.HEX)
f.pt3_gps_snr_pt3_gps_snr3 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr3", "Pt3 Gps Snr3", base.HEX)
f.pt3_gps_snr_pt3_gps_snr4 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr4", "Pt3 Gps Snr4", base.HEX)
f.pt3_gps_snr_pt3_gps_snr5 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr5", "Pt3 Gps Snr5", base.HEX)
f.pt3_gps_snr_pt3_gps_snr6 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr6", "Pt3 Gps Snr6", base.HEX)
f.pt3_gps_snr_pt3_gps_snr7 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr7", "Pt3 Gps Snr7", base.HEX)
f.pt3_gps_snr_pt3_gps_snr8 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr8", "Pt3 Gps Snr8", base.HEX)
f.pt3_gps_snr_pt3_gps_snr9 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr9", "Pt3 Gps Snr9", base.HEX)
f.pt3_gps_snr_pt3_gps_snr10 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr10", "Pt3 Gps Snr10", base.HEX)
f.pt3_gps_snr_pt3_gps_snr11 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr11", "Pt3 Gps Snr11", base.HEX)
f.pt3_gps_snr_pt3_gps_snr12 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr12", "Pt3 Gps Snr12", base.HEX)
f.pt3_gps_snr_pt3_gps_snr13 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr13", "Pt3 Gps Snr13", base.HEX)
f.pt3_gps_snr_pt3_gps_snr14 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr14", "Pt3 Gps Snr14", base.HEX)
f.pt3_gps_snr_pt3_gps_snr15 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr15", "Pt3 Gps Snr15", base.HEX)
f.pt3_gps_snr_pt3_gps_snr16 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr16", "Pt3 Gps Snr16", base.HEX)
f.pt3_gps_snr_pt3_gps_snr17 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr17", "Pt3 Gps Snr17", base.HEX)
f.pt3_gps_snr_pt3_gps_snr18 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr18", "Pt3 Gps Snr18", base.HEX)
f.pt3_gps_snr_pt3_gps_snr19 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr19", "Pt3 Gps Snr19", base.HEX)
f.pt3_gps_snr_pt3_gps_snr20 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr20", "Pt3 Gps Snr20", base.HEX)
f.pt3_gps_snr_pt3_gps_snr21 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr21", "Pt3 Gps Snr21", base.HEX)
f.pt3_gps_snr_pt3_gps_snr22 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr22", "Pt3 Gps Snr22", base.HEX)
f.pt3_gps_snr_pt3_gps_snr23 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr23", "Pt3 Gps Snr23", base.HEX)
f.pt3_gps_snr_pt3_gps_snr24 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr24", "Pt3 Gps Snr24", base.HEX)
f.pt3_gps_snr_pt3_gps_snr25 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr25", "Pt3 Gps Snr25", base.HEX)
f.pt3_gps_snr_pt3_gps_snr26 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr26", "Pt3 Gps Snr26", base.HEX)
f.pt3_gps_snr_pt3_gps_snr27 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr27", "Pt3 Gps Snr27", base.HEX)
f.pt3_gps_snr_pt3_gps_snr28 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr28", "Pt3 Gps Snr28", base.HEX)
f.pt3_gps_snr_pt3_gps_snr29 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr29", "Pt3 Gps Snr29", base.HEX)
f.pt3_gps_snr_pt3_gps_snr30 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr30", "Pt3 Gps Snr30", base.HEX)
f.pt3_gps_snr_pt3_gps_snr31 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr31", "Pt3 Gps Snr31", base.HEX)
f.pt3_gps_snr_pt3_gps_snr32 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gps_snr32", "Pt3 Gps Snr32", base.HEX)
f.pt3_gps_snr_pt3_gln_snr1 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr1", "Pt3 Gln Snr1", base.HEX)
f.pt3_gps_snr_pt3_gln_snr2 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr2", "Pt3 Gln Snr2", base.HEX)
f.pt3_gps_snr_pt3_gln_snr3 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr3", "Pt3 Gln Snr3", base.HEX)
f.pt3_gps_snr_pt3_gln_snr4 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr4", "Pt3 Gln Snr4", base.HEX)
f.pt3_gps_snr_pt3_gln_snr5 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr5", "Pt3 Gln Snr5", base.HEX)
f.pt3_gps_snr_pt3_gln_snr6 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr6", "Pt3 Gln Snr6", base.HEX)
f.pt3_gps_snr_pt3_gln_snr7 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr7", "Pt3 Gln Snr7", base.HEX)
f.pt3_gps_snr_pt3_gln_snr8 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr8", "Pt3 Gln Snr8", base.HEX)
f.pt3_gps_snr_pt3_gln_snr9 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr9", "Pt3 Gln Snr9", base.HEX)
f.pt3_gps_snr_pt3_gln_snr10 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr10", "Pt3 Gln Snr10", base.HEX)
f.pt3_gps_snr_pt3_gln_snr11 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr11", "Pt3 Gln Snr11", base.HEX)
f.pt3_gps_snr_pt3_gln_snr12 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr12", "Pt3 Gln Snr12", base.HEX)
f.pt3_gps_snr_pt3_gln_snr13 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr13", "Pt3 Gln Snr13", base.HEX)
f.pt3_gps_snr_pt3_gln_snr14 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr14", "Pt3 Gln Snr14", base.HEX)
f.pt3_gps_snr_pt3_gln_snr15 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr15", "Pt3 Gln Snr15", base.HEX)
f.pt3_gps_snr_pt3_gln_snr16 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr16", "Pt3 Gln Snr16", base.HEX)
f.pt3_gps_snr_pt3_gln_snr17 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr17", "Pt3 Gln Snr17", base.HEX)
f.pt3_gps_snr_pt3_gln_snr18 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr18", "Pt3 Gln Snr18", base.HEX)
f.pt3_gps_snr_pt3_gln_snr19 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr19", "Pt3 Gln Snr19", base.HEX)
f.pt3_gps_snr_pt3_gln_snr20 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr20", "Pt3 Gln Snr20", base.HEX)
f.pt3_gps_snr_pt3_gln_snr21 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr21", "Pt3 Gln Snr21", base.HEX)
f.pt3_gps_snr_pt3_gln_snr22 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr22", "Pt3 Gln Snr22", base.HEX)
f.pt3_gps_snr_pt3_gln_snr23 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr23", "Pt3 Gln Snr23", base.HEX)
f.pt3_gps_snr_pt3_gln_snr24 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr24", "Pt3 Gln Snr24", base.HEX)
f.pt3_gps_snr_pt3_gln_snr25 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr25", "Pt3 Gln Snr25", base.HEX)
f.pt3_gps_snr_pt3_gln_snr26 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr26", "Pt3 Gln Snr26", base.HEX)
f.pt3_gps_snr_pt3_gln_snr27 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr27", "Pt3 Gln Snr27", base.HEX)
f.pt3_gps_snr_pt3_gln_snr28 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr28", "Pt3 Gln Snr28", base.HEX)
f.pt3_gps_snr_pt3_gln_snr29 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr29", "Pt3 Gln Snr29", base.HEX)
f.pt3_gps_snr_pt3_gln_snr30 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr30", "Pt3 Gln Snr30", base.HEX)
f.pt3_gps_snr_pt3_gln_snr31 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr31", "Pt3 Gln Snr31", base.HEX)
f.pt3_gps_snr_pt3_gln_snr32 = ProtoField.uint8 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_snr32", "Pt3 Gln Snr32", base.HEX)
f.pt3_gps_snr_pt3_gln_cnt = ProtoField.uint16 ("dji_p3_flyrec.pt3_gps_snr_pt3_gln_cnt", "Pt3 Gln Cnt", base.HEX, nil, nil, "Sequence counter increased each time the packet of this type is prepared")

local function flightrec_pt3_gps_snr_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr3, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr6, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr7, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr8, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr9, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr10, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr11, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr12, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr13, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr14, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr15, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr16, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr17, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr18, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr19, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr20, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr21, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr22, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr23, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr24, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr25, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr26, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr27, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr28, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr29, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr30, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr31, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gps_snr32, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr3, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr6, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr7, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr8, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr9, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr10, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr11, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr12, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr13, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr14, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr15, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr16, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr17, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr18, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr19, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr20, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr21, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr22, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr23, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr24, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr25, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr26, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr27, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr28, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr29, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr30, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr31, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_snr32, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.pt3_gps_snr_pt3_gln_cnt, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 66) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Pt3 Gps Snr: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Pt3 Gps Snr: Payload size different than expected") end
end

-- Flight log - Imu 21100 - 0x005b

f.imu_21100_gyro_x_21100 = ProtoField.int16 ("dji_p3_flyrec.imu_21100_gyro_x_21100", "Gyro X 21100", base.DEC)
f.imu_21100_gyro_y_21100 = ProtoField.int16 ("dji_p3_flyrec.imu_21100_gyro_y_21100", "Gyro Y 21100", base.DEC)
f.imu_21100_gyro_z_21100 = ProtoField.int16 ("dji_p3_flyrec.imu_21100_gyro_z_21100", "Gyro Z 21100", base.DEC)
f.imu_21100_acc_x_21100 = ProtoField.int16 ("dji_p3_flyrec.imu_21100_acc_x_21100", "Acc X 21100", base.DEC)
f.imu_21100_acc_y_21100 = ProtoField.int16 ("dji_p3_flyrec.imu_21100_acc_y_21100", "Acc Y 21100", base.DEC)
f.imu_21100_acc_z_21100 = ProtoField.int16 ("dji_p3_flyrec.imu_21100_acc_z_21100", "Acc Z 21100", base.DEC)
f.imu_21100_cnt_21100 = ProtoField.uint32 ("dji_p3_flyrec.imu_21100_cnt_21100", "Cnt 21100", base.DEC, nil, nil, "Sequence counter increased each time the packet of this type is prepared")

local function flightrec_imu_21100_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_21100_gyro_x_21100, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_21100_gyro_y_21100, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_21100_gyro_z_21100, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_21100_acc_x_21100, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_21100_acc_y_21100, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_21100_acc_z_21100, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_21100_cnt_21100, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 16) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu 21100: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu 21100: Payload size different than expected") end
end

-- Flight log - Imu Raw - 0x005c

f.imu_raw_gyro_x_used = ProtoField.int16 ("dji_p3_flyrec.imu_raw_gyro_x_used", "Gyro X Used", base.DEC)
f.imu_raw_gyro_y_used = ProtoField.int16 ("dji_p3_flyrec.imu_raw_gyro_y_used", "Gyro Y Used", base.DEC)
f.imu_raw_gyro_z_used = ProtoField.int16 ("dji_p3_flyrec.imu_raw_gyro_z_used", "Gyro Z Used", base.DEC)
f.imu_raw_acc_x_used = ProtoField.int16 ("dji_p3_flyrec.imu_raw_acc_x_used", "Acc X Used", base.DEC)
f.imu_raw_acc_y_used = ProtoField.int16 ("dji_p3_flyrec.imu_raw_acc_y_used", "Acc Y Used", base.DEC)
f.imu_raw_acc_z_used = ProtoField.int16 ("dji_p3_flyrec.imu_raw_acc_z_used", "Acc Z Used", base.DEC)
f.imu_raw_gyro_x_unused = ProtoField.int16 ("dji_p3_flyrec.imu_raw_gyro_x_unused", "Gyro X Unused", base.DEC)
f.imu_raw_gyro_y_unused = ProtoField.int16 ("dji_p3_flyrec.imu_raw_gyro_y_unused", "Gyro Y Unused", base.DEC)
f.imu_raw_gyro_z_unused = ProtoField.int16 ("dji_p3_flyrec.imu_raw_gyro_z_unused", "Gyro Z Unused", base.DEC)
f.imu_raw_acc_x_unused = ProtoField.int16 ("dji_p3_flyrec.imu_raw_acc_x_unused", "Acc X Unused", base.DEC)
f.imu_raw_acc_y_unused = ProtoField.int16 ("dji_p3_flyrec.imu_raw_acc_y_unused", "Acc Y Unused", base.DEC)
f.imu_raw_acc_z_unused = ProtoField.int16 ("dji_p3_flyrec.imu_raw_acc_z_unused", "Acc Z Unused", base.DEC)
f.imu_raw_xxxxcnt = ProtoField.int32 ("dji_p3_flyrec.imu_raw_xxxxcnt", "Xxxxcnt", base.DEC, nil, nil, "Sequence counter increased each time the packet of this type is prepared")
--f.imu_raw_xxxxcnt = ProtoField.int16 ("dji_p3_flyrec.imu_raw_xxxxcnt", "Xxxxcnt", base.DEC, nil, nil, "Sequence counter increased each time the packet of this type is prepared")
--f.imu_raw_xxbaro = ProtoField.int16 ("dji_p3_flyrec.imu_raw_xxbaro", "Xxbaro", base.DEC)
--f.imu_raw_xxbaro_temp = ProtoField.int16 ("dji_p3_flyrec.imu_raw_xxbaro_temp", "Xxbaro Temp", base.DEC)

local function flightrec_imu_raw_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_raw_gyro_x_used, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_raw_gyro_y_used, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_raw_gyro_z_used, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_raw_acc_x_used, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_raw_acc_y_used, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_raw_acc_z_used, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_raw_gyro_x_unused, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_raw_gyro_y_unused, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_raw_gyro_z_unused, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_raw_acc_x_unused, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_raw_acc_y_unused, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_raw_acc_z_unused, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_raw_xxxxcnt, payload(offset, 4))
    offset = offset + 4

    --subtree:add_le (f.imu_raw_xxbaro, payload(offset, 2))
    --offset = offset + 2

    --subtree:add_le (f.imu_raw_xxbaro_temp, payload(offset, 2))
    --offset = offset + 2

    if (offset ~= 28) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Raw: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Raw: Payload size different than expected") end
end

-- Flight log - Imu Init - 0x0006

f.imu_init_imu_offset_x = ProtoField.float ("dji_p3_flyrec.imu_init_imu_offset_x", "Imu Offset X", base.DEC)
f.imu_init_imu_offset_y = ProtoField.float ("dji_p3_flyrec.imu_init_imu_offset_y", "Imu Offset Y", base.DEC)
f.imu_init_imu_offset_z = ProtoField.float ("dji_p3_flyrec.imu_init_imu_offset_z", "Imu Offset Z", base.DEC)
f.imu_init_gps_offset_x = ProtoField.float ("dji_p3_flyrec.imu_init_gps_offset_x", "Gps Offset X", base.DEC)
f.imu_init_gps_offset_y = ProtoField.float ("dji_p3_flyrec.imu_init_gps_offset_y", "Gps Offset Y", base.DEC)
f.imu_init_gps_offset_z = ProtoField.float ("dji_p3_flyrec.imu_init_gps_offset_z", "Gps Offset Z", base.DEC)
f.imu_init_imu_dir = ProtoField.uint16 ("dji_p3_flyrec.imu_init_imu_dir", "Imu Dir", base.HEX, nil, nil, "equal to flyc param g_real.config.imu_gps.imu_dir")
f.imu_init_imu_key = ProtoField.uint8 ("dji_p3_flyrec.imu_init_imu_key", "Imu Key", base.HEX, nil, nil, "on P3, always zero; key for encrypted Imu packets")
f.imu_init_o_sw = ProtoField.uint8 ("dji_p3_flyrec.imu_init_o_sw", "O Sw", base.HEX, nil, nil, "on P3, always zero")
f.imu_init_mag_bias_x = ProtoField.float ("dji_p3_flyrec.imu_init_mag_bias_x", "Mag Bias X", base.DEC)
f.imu_init_mag_bias_y = ProtoField.float ("dji_p3_flyrec.imu_init_mag_bias_y", "Mag Bias Y", base.DEC)
f.imu_init_mag_bias_z = ProtoField.float ("dji_p3_flyrec.imu_init_mag_bias_z", "Mag Bias Z", base.DEC)
f.imu_init_mag_scale_x = ProtoField.float ("dji_p3_flyrec.imu_init_mag_scale_x", "Mag Scale X", base.DEC)
f.imu_init_mag_scale_y = ProtoField.float ("dji_p3_flyrec.imu_init_mag_scale_y", "Mag Scale Y", base.DEC)
f.imu_init_mag_scale_z = ProtoField.float ("dji_p3_flyrec.imu_init_mag_scale_z", "Mag Scale Z", base.DEC)
f.imu_init_init_counter = ProtoField.uint16 ("dji_p3_flyrec.imu_init_init_counter", "Init Counter", base.HEX)

local function flightrec_imu_init_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_init_imu_offset_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_init_imu_offset_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_init_imu_offset_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_init_gps_offset_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_init_gps_offset_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_init_gps_offset_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_init_imu_dir, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_init_imu_key, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.imu_init_o_sw, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.imu_init_mag_bias_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_init_mag_bias_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_init_mag_bias_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_init_mag_scale_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_init_mag_scale_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_init_mag_scale_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_init_init_counter, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 54) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Init: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Init: Payload size different than expected") end
end

-- Flight log - Osd General - 0x000c, identical to UART packet set=0x03 cmd=0x43

local REC_OSD_GENERAL_MODE1_ENUM = {
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

local REC_OSD_GENERAL_COMMAND_ENUM = {
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

local REC_OSD_GENERAL_BATT_TYPE_ENUM = {
    [0]="Unknown",
    [1]="NonSmart",
    [2]="Smart",
}

local REC_OSD_GENERAL_GOHOME_STATE_ENUM = {
    [0]="STANDBY",
    [1]="PREASCENDING",
    [2]="ALIGN",
    [3]="ASCENDING",
    [4]="CRUISE",
    [5]="BRAKING",
    [6]="BYPASSING",
    [7]="OTHER",
}

local REC_OSD_GENERAL_GOHOME_REASON_ENUM = {
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

local REC_OSD_GENERAL_START_FAIL_REASON_ENUM = {
    [0x00] = 'Allow start',
    [0x01] = 'Compass error',
    [0x02] = 'Assistant protected',
    [0x03] = 'Device lock protect',
    [0x04] = 'Off radius limit landed', -- aka Distance Limit
    [0x05] = 'IMU need adv-calib',
    [0x06] = 'IMU SN error',
    [0x07] = 'Temperature cal not ready', -- aka IMU Warning
    [0x08] = 'Compass calibration in progress',
    [0x09] = 'Attitude error',
    [0x0a] = 'Novice mode without gps', -- aka Novice Protected
    [0x0b] = 'Battery cell error stop motor',
    [0x0c] = 'Battery communite error stop motor',
    [0x0d] = 'Battery voltage very low stop motor',
    [0x0e] = 'Battery below user low land level stop motor', -- aka Serious Low Power
    [0x0f] = 'Battery main vol low stop motor',
    [0x10] = 'Battery temp and vol low stop motor',
    [0x11] = 'Battery smart low land stop motor',
    [0x12] = 'Battery not ready stop motor',
    [0x13] = 'May run simulator', -- aka Simulator Mode
    [0x14] = 'Gear pack mode',
    [0x15] = 'Atti limit', -- aka Attitude Abnormal
    [0x16] = 'Product not activation, stop motor',
    [0x17] = 'In fly limit area, need stop motor', -- aka Fly Forbidden Error
    [0x18] = 'Bias limit',
    [0x19] = 'ESC error',
    [0x1a] = 'IMU is initing',
    [0x1b] = 'System upgrade, stop motor',
    [0x1c] = 'Have run simulator, please restart', -- aka Simulator Started
    [0x1d] = 'IMU cali in progress',
    [0x1e] = 'Too large tilt angle when auto take off, stop motor', -- aka Atti Angle Over
    [0x1f] = 'Gyroscope is stuck',
    [0x20] = 'Accel is stuck',
    [0x21] = 'Compass is stuck',
    [0x22] = 'Pressure sensor is stuck',
    [0x23] = 'Pressure read is negative',
    [0x24] = 'Compass mod is huge',
    [0x25] = 'Gyro bias is large',
    [0x26] = 'Accel bias is large',
    [0x27] = 'Compass noise is large',
    [0x28] = 'Pressure noise is large', -- aka Barometer Noise Big
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
    [0x5e] = 'Takeoff Rollover',
    [0x5f] = 'Motor Stuck',
    [0x60] = 'Motor Unbalanced',
    [0x61] = 'Motor Less Paddle',
    [0x62] = 'Motor Start Error',
    [0x63] = 'Motor Auto Takeoff Fail',
    [0x65] = 'Bat Version Error',
    [0x66] = 'RTK Bad Signal',
    [0x67] = 'RTK Deviation Error',
    [0x70] = 'ESC Calibrating',
    [0x71] = 'GPS Sign Invalid',
    [0x72] = 'Gimbal Is Calibrating',
    [0x73] = 'Lock By App',
    [0x74] = 'Start Fly Height Error',
    [0x75] = 'Esc Version Not Match',
    [0x76] = 'Imu Ori Not Match',
    [0x77] = 'Stop By App',
    [0x78] = 'Compass Imu Ori Not Match',
    [0x7a] = 'Esc Echoing',
    [0x7b] = 'Battery Over Temperature',
    [0x7c] = 'Battery Install Error',
    [0x7d] = 'Be Impact',
    [0x7f] = 'Crash',
    [0x81] = 'Low Version Of Battery',
    [0x82] = 'Voltage Of Battery Is Too High',
    [0x83] = 'Battery Embed Error',
    [0x84] = 'Cooling Fan Exception',
    [0x88] = 'RC Throttle Is Not In Middle',
    [0xff] = 'Remote Usb Connected', -- Would be bad to take off when a cable is plugged into AC
    [0x100]= 'Other',
}

local REC_OSD_GENERAL_GPS_STATE_ENUM = {
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

local REC_OSD_GENERAL_PRODUCT_TYPE_ENUM = {
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

local REC_OSD_GENERAL_IMU_INIT_FAIL_RESON_ENUM = {
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

f.osd_general_longtitude = ProtoField.double ("dji_p3_flyrec.osd_general_longtitude", "Longtitude", base.DEC)
f.osd_general_latitude = ProtoField.double ("dji_p3_flyrec.osd_general_latitude", "Latitude", base.DEC)
f.osd_general_relative_height = ProtoField.int16 ("dji_p3_flyrec.osd_general_relative_height", "Relative Height", base.DEC, nil, nil, "0.1m, altitude to ground")
f.osd_general_vgx = ProtoField.int16 ("dji_p3_flyrec.osd_general_vgx", "Vgx", base.DEC, nil, nil, "0.1m/s, to ground")
f.osd_general_vgy = ProtoField.int16 ("dji_p3_flyrec.osd_general_vgy", "Vgy", base.DEC, nil, nil, "0.1m/s, to ground")
f.osd_general_vgz = ProtoField.int16 ("dji_p3_flyrec.osd_general_vgz", "Vgz", base.DEC, nil, nil, "0.1m/s, to ground")
f.osd_general_pitch = ProtoField.int16 ("dji_p3_flyrec.osd_general_pitch", "Pitch", base.DEC, nil, nil, "0.1")
f.osd_general_roll = ProtoField.int16 ("dji_p3_flyrec.osd_general_roll", "Roll", base.DEC)
f.osd_general_yaw = ProtoField.int16 ("dji_p3_flyrec.osd_general_yaw", "Yaw", base.DEC)
f.osd_general_mode1 = ProtoField.uint8 ("dji_p3_flyrec.osd_general_mode1", "Mode1", base.HEX, REC_OSD_GENERAL_MODE1_ENUM, 0x7F, "Flight Controller state1")
f.osd_general_rc_state = ProtoField.uint8 ("dji_p3_flyrec.osd_general_rc_state", "RC State", base.HEX, nil, 0x80, nil)
f.osd_general_latest_cmd = ProtoField.uint8 ("dji_p3_flyrec.osd_general_latest_cmd", "Latest Cmd", base.HEX, REC_OSD_GENERAL_COMMAND_ENUM, nil, "controller exccute lastest cmd")
f.osd_general_controller_state = ProtoField.uint32 ("dji_p3_flyrec.osd_general_controller_state", "Controller State", base.HEX, nil, nil, "Flight Controller state flags")
  f.osd_general_e_can_ioc_work = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_can_ioc_work", "E Can IOC Work", base.HEX, nil, 0x01, nil)
  f.osd_general_e_on_ground = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_on_ground", "E On Ground", base.HEX, nil, 0x02, nil)
  f.osd_general_e_in_air = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_in_air", "E In Air", base.HEX, nil, 0x04, nil)
  f.osd_general_e_motor_on = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_motor_on", "E Motor On", base.HEX, nil, 0x08, "Force allow start motors ignoring errors")
  f.osd_general_e_usonic_on = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_usonic_on", "E Usonic On", base.HEX, nil, 0x10, nil)
  f.osd_general_e_gohome_state = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_gohome_state", "E Gohome State", base.HEX, REC_OSD_GENERAL_GOHOME_STATE_ENUM, 0xe0, nil)
  f.osd_general_e_mvo_used = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_mvo_used", "E MVO Used", base.HEX, nil, 0x100, "Monocular Visual Odometry is used as horizonal velocity sensor")
  f.osd_general_e_battery_req_gohome = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_battery_req_gohome", "E Battery Req Gohome", base.HEX, nil, 0x200, nil)
  f.osd_general_e_battery_req_land = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_battery_req_land", "E Battery Req Land", base.HEX, nil, 0x400, "Landing required due to battery voltage low")
  f.osd_general_e_still_heating = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_still_heating", "E Still Heating", base.HEX, nil, 0x1000, nil)
  f.osd_general_e_rc_state = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_rc_state", "E RC State", base.HEX, nil, 0x6000, nil)
  f.osd_general_e_gps_used = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_gps_used", "E GPS Used", base.HEX, nil, 0x8000, "Satellite Positioning System is used as horizonal velocity sensor")
  f.osd_general_e_compass_over_range = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_compass_over_range", "E Compass Over Range", base.HEX, nil, 0x10000, nil)
  f.osd_general_e_wave_err = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_wave_err", "E Wave Error", base.HEX, nil, 0x20000, nil)
  f.osd_general_e_gps_level = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_gps_level", "E GPS Level", base.HEX, nil, 0x3C0000, "Satellite Positioning System signal level")
  f.osd_general_e_battery_type = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_battery_type", "E Battery Type", base.HEX, REC_OSD_GENERAL_BATT_TYPE_ENUM, 0xC00000, nil)
  f.osd_general_e_accel_over_range = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_accel_over_range", "E Acceletor Over Range", base.HEX, nil, 0x1000000, nil)
  f.osd_general_e_is_vibrating = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_is_vibrating", "E Is Vibrating", base.HEX, nil, 0x2000000, nil)
  f.osd_general_e_press_err = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_press_err", "E Press Err", base.HEX, nil, 0x4000000, "Barometer error")
  f.osd_general_e_esc_stall = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_esc_stall", "E ESC is stall", base.HEX, nil, 0x8000000, "ESC reports motor blocked")
  f.osd_general_e_esc_empty = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_esc_empty", "E ESC is empty", base.HEX, nil, 0x10000000, "ESC reports not enough force")
  f.osd_general_e_propeller_catapult = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_propeller_catapult", "E Is Propeller Catapult", base.HEX, nil, 0x20000000, nil)
  f.osd_general_e_gohome_height_mod = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_gohome_height_mod", "E GoHome Height Mod", base.HEX, nil, 0x40000000, "Go Home Height is Modified")
  f.osd_general_e_out_of_limit = ProtoField.uint32 ("dji_p3_flyrec.osd_general_e_out_of_limit", "E Is Out Of Limit", base.HEX, nil, 0x80000000, nil)
f.osd_general_gps_nums = ProtoField.uint8 ("dji_p3_flyrec.osd_general_gps_nums", "Gps Nums", base.DEC, nil, nil, "Number of Global Nav System positioning satellites")
f.osd_general_gohome_landing_reason = ProtoField.uint8 ("dji_p3_flyrec.osd_general_gohome_landing_reason", "Gohome or Landing Reason", base.HEX, REC_OSD_GENERAL_GOHOME_REASON_ENUM, nil, "Reason for automatic GoHome or Landing")
f.osd_general_start_fail_reason = ProtoField.uint8 ("dji_p3_flyrec.osd_general_start_fail_reason", "Start Fail Reason", base.HEX, REC_OSD_GENERAL_START_FAIL_REASON_ENUM, nil, "Reason for failure to start motors")
f.osd_general_controller_state_ext = ProtoField.uint8 ("dji_p3_flyrec.osd_general_controller_state_ext", "Controller State Ext", base.HEX)
  f.osd_general_e_gps_state = ProtoField.uint8 ("dji_p3_flyrec.osd_general_e_gps_state", "E Gps State", base.HEX, REC_OSD_GENERAL_GPS_STATE_ENUM, 0x0f, nil)
  f.osd_general_e_wp_limit_md = ProtoField.uint8 ("dji_p3_flyrec.osd_general_e_wp_limit_md", "E Wp Limit Mode", base.HEX, nil, 0x10, "Waypoint Limit Mode")
f.osd_general_batt_remain = ProtoField.uint8 ("dji_p3_flyrec.osd_general_batt_remain", "Battery Remain", base.DEC, nil, nil, "Battery Remaining Capacity")
f.osd_general_ultrasonic_height = ProtoField.uint8 ("dji_p3_flyrec.osd_general_ultrasonic_height", "Ultrasonic Height", base.DEC)
f.osd_general_motor_startup_time = ProtoField.uint16 ("dji_p3_flyrec.osd_general_motor_startup_time", "Motor Startup Time", base.DEC)
f.osd_general_motor_startup_times = ProtoField.uint8 ("dji_p3_flyrec.osd_general_motor_startup_times", "Motor Startup Times", base.DEC, nil, nil, "aka Motor Revolution")
f.osd_general_bat_alarm1 = ProtoField.uint8 ("dji_p3_flyrec.osd_general_bat_alarm1", "Bat Alarm1", base.HEX)
  f.osd_general_bat_alarm1_ve = ProtoField.uint8 ("dji_p3_flyrec.osd_general_bat_alarm1_ve", "Alarm Level 1 Voltage", base.DEC, nil, 0x7F)
  f.osd_general_bat_alarm1_fn = ProtoField.uint8 ("dji_p3_flyrec.osd_general_bat_alarm1_fn", "Alarm Level 1 Function", base.DEC, nil, 0x80)
f.osd_general_bat_alarm2 = ProtoField.uint8 ("dji_p3_flyrec.osd_general_bat_alarm2", "Bat Alarm2", base.HEX)
  f.osd_general_bat_alarm2_ve = ProtoField.uint8 ("dji_p3_flyrec.osd_general_bat_alarm2_ve", "Alarm Level 2 Voltage", base.DEC, nil, 0x7F)
  f.osd_general_bat_alarm2_fn = ProtoField.uint8 ("dji_p3_flyrec.osd_general_bat_alarm2_fn", "Alarm Level 2 Function", base.DEC, nil, 0x80)
f.osd_general_version_match = ProtoField.uint8 ("dji_p3_flyrec.osd_general_version_match", "Version Match", base.HEX, nil, nil, "Flight Controller version")
f.osd_general_product_type = ProtoField.uint8 ("dji_p3_flyrec.osd_general_product_type", "Product Type", base.HEX, REC_OSD_GENERAL_PRODUCT_TYPE_ENUM)
f.osd_general_imu_init_fail_reson = ProtoField.int8 ("dji_p3_flyrec.osd_general_imu_init_fail_reson", "IMU init Fail Reason", base.DEC, REC_OSD_GENERAL_IMU_INIT_FAIL_RESON_ENUM)

local function flightrec_osd_general_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.osd_general_longtitude, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.osd_general_latitude, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.osd_general_relative_height, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.osd_general_vgx, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.osd_general_vgy, payload(offset, 2)) -- offset = 20
    offset = offset + 2

    subtree:add_le (f.osd_general_vgz, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.osd_general_pitch, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.osd_general_roll, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.osd_general_yaw, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.osd_general_mode1, payload(offset, 1))
    subtree:add_le (f.osd_general_rc_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.osd_general_latest_cmd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.osd_general_controller_state, payload(offset, 4))
    subtree:add_le (f.osd_general_e_can_ioc_work, payload(offset, 4))
    subtree:add_le (f.osd_general_e_on_ground, payload(offset, 4))
    subtree:add_le (f.osd_general_e_in_air, payload(offset, 4))
    subtree:add_le (f.osd_general_e_motor_on, payload(offset, 4))
    subtree:add_le (f.osd_general_e_usonic_on, payload(offset, 4))
    subtree:add_le (f.osd_general_e_gohome_state, payload(offset, 4))
    subtree:add_le (f.osd_general_e_mvo_used, payload(offset, 4))
    subtree:add_le (f.osd_general_e_battery_req_gohome, payload(offset, 4))
    subtree:add_le (f.osd_general_e_battery_req_land, payload(offset, 4))
    subtree:add_le (f.osd_general_e_still_heating, payload(offset, 4))
    subtree:add_le (f.osd_general_e_rc_state, payload(offset, 4))
    subtree:add_le (f.osd_general_e_gps_used, payload(offset, 4))
    subtree:add_le (f.osd_general_e_compass_over_range, payload(offset, 4))
    subtree:add_le (f.osd_general_e_wave_err, payload(offset, 4))
    subtree:add_le (f.osd_general_e_gps_level, payload(offset, 4))
    subtree:add_le (f.osd_general_e_battery_type, payload(offset, 4))
    subtree:add_le (f.osd_general_e_accel_over_range, payload(offset, 4))
    subtree:add_le (f.osd_general_e_is_vibrating, payload(offset, 4))
    subtree:add_le (f.osd_general_e_press_err, payload(offset, 4))
    subtree:add_le (f.osd_general_e_esc_stall, payload(offset, 4))
    subtree:add_le (f.osd_general_e_esc_empty, payload(offset, 4))
    subtree:add_le (f.osd_general_e_propeller_catapult, payload(offset, 4))
    subtree:add_le (f.osd_general_e_gohome_height_mod, payload(offset, 4))
    subtree:add_le (f.osd_general_e_out_of_limit, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.osd_general_gps_nums, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.osd_general_gohome_landing_reason, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.osd_general_start_fail_reason, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.osd_general_controller_state_ext, payload(offset, 1))
    subtree:add_le (f.osd_general_e_gps_state, payload(offset, 1))
    subtree:add_le (f.osd_general_e_wp_limit_md, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.osd_general_batt_remain, payload(offset, 1)) -- offset = 40
    offset = offset + 1

    subtree:add_le (f.osd_general_ultrasonic_height, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.osd_general_motor_startup_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.osd_general_motor_startup_times, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.osd_general_bat_alarm1, payload(offset, 1))
    subtree:add_le (f.osd_general_bat_alarm1_ve, payload(offset, 1))
    subtree:add_le (f.osd_general_bat_alarm1_fn, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.osd_general_bat_alarm2, payload(offset, 1))
    subtree:add_le (f.osd_general_bat_alarm2_ve, payload(offset, 1))
    subtree:add_le (f.osd_general_bat_alarm2_fn, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.osd_general_version_match, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.osd_general_product_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.osd_general_imu_init_fail_reson, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 50) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd General: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd General: Payload size different than expected") end
end

-- Flight log - Osd Home - 0x000d

f.osd_home_osd_lon = ProtoField.double ("dji_p3_flyrec.osd_home_osd_lon", "Osd Longitude", base.DEC) -- home point coords?
f.osd_home_osd_lat = ProtoField.double ("dji_p3_flyrec.osd_home_osd_lat", "Osd Latitude", base.DEC) -- home point coords?
f.osd_home_osd_alt = ProtoField.float ("dji_p3_flyrec.osd_home_osd_alt", "Osd Altitude", base.DEC, nil, nil, "0.1m, altitude")
f.osd_home_osd_home_state = ProtoField.uint16 ("dji_p3_flyrec.osd_home_osd_home_state", "Osd Home State", base.HEX)
  f.osd_home_e_homepoint_set = ProtoField.uint16 ("dji_p3_flyrec.osd_home_e_homepoint_set", "E Homepoint Set", base.HEX, nil, 0x01, nil)
  f.osd_home_e_method = ProtoField.uint16 ("dji_p3_flyrec.osd_home_e_method", "E Method", base.HEX, nil, 0x02, nil)
  f.osd_home_e_heading = ProtoField.uint16 ("dji_p3_flyrec.osd_home_e_heading", "E Heading", base.HEX, nil, 0x04, nil)
  f.osd_home_e_is_dyn_homepoint = ProtoField.uint16 ("dji_p3_flyrec.osd_home_e_is_dyn_homepoint", "E Is Dyn Homepoint", base.HEX, nil, 0x08, nil)
  f.osd_home_e_multiple = ProtoField.uint16 ("dji_p3_flyrec.osd_home_e_multiple", "E Multiple", base.HEX, nil, 0x40, nil)
  f.osd_home_e_ioc_enable = ProtoField.uint16 ("dji_p3_flyrec.osd_home_e_ioc_enable", "E Ioc Enable", base.HEX, nil, 0x1000, nil)
f.osd_home_fixed_altitude = ProtoField.uint16 ("dji_p3_flyrec.osd_home_fixed_altitude", "Fixed Altitude", base.HEX)
f.osd_home_course_lock_torsion = ProtoField.int16 ("dji_p3_flyrec.osd_home_course_lock_torsion", "Course Lock Torsion", base.DEC)
f.osd_home_fld1a = ProtoField.int8 ("dji_p3_flyrec.osd_home_fld1a", "field1A", base.DEC)
f.osd_home_fld1b = ProtoField.int8 ("dji_p3_flyrec.osd_home_fld1b", "field1B", base.DEC)
f.osd_home_fld1c = ProtoField.int16 ("dji_p3_flyrec.osd_home_fld1c", "field1C", base.DEC)
f.osd_home_fld1e = ProtoField.int16 ("dji_p3_flyrec.osd_home_fld1e", "field1E", base.DEC)
f.osd_home_fld20 = ProtoField.int8 ("dji_p3_flyrec.osd_home_fld20", "field20", base.DEC)
f.osd_home_fld21 = ProtoField.int8 ("dji_p3_flyrec.osd_home_fld21", "field21", base.DEC) -- seem to not be filled
f.osd_home_fld22 = ProtoField.bytes ("dji_p3_flyrec.osd_home_fld22", "field22", base.SPACE)
f.osd_home_fld33 = ProtoField.bytes ("dji_p3_flyrec.osd_home_fld33", "field33", base.SPACE)

local function flightrec_osd_home_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.osd_home_osd_lon, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.osd_home_osd_lat, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.osd_home_osd_alt, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.osd_home_osd_home_state, payload(offset, 2))
    subtree:add_le (f.osd_home_e_homepoint_set, payload(offset, 2))
    subtree:add_le (f.osd_home_e_method, payload(offset, 2))
    subtree:add_le (f.osd_home_e_heading, payload(offset, 2))
    subtree:add_le (f.osd_home_e_is_dyn_homepoint, payload(offset, 2))
    subtree:add_le (f.osd_home_e_multiple, payload(offset, 2))
    subtree:add_le (f.osd_home_e_ioc_enable, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.osd_home_fixed_altitude, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.osd_home_course_lock_torsion, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.osd_home_fld1a, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.osd_home_fld1b, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.osd_home_fld1c, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.osd_home_fld1e, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.osd_home_fld20, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.osd_home_fld21, payload(offset, 1))
    offset = offset + 1

    if (payload:len() >= 68) then
        subtree:add_le (f.osd_home_fld22, payload(offset, 18))
        offset = offset + 18
        subtree:add_le (f.osd_home_fld33, payload(offset, 16))
        offset = offset + 16
    end

    if (offset ~= 34) and (offset ~= 68) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Osd Home: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Osd Home: Payload size different than expected") end
end

-- Flight log - Fdi - 0x001a
-- fault detection isolation

f.fdi_ns_abnormal_all = ProtoField.uint32 ("dji_p3_flyrec.fdi_ns_abnormal_all", "Ns Abnormal All", base.HEX)
f.fdi_history_ns_abnormal_all = ProtoField.uint32 ("dji_p3_flyrec.fdi_history_ns_abnormal_all", "History Ns Abnormal All", base.HEX)
f.fdi_gyro_bias_raw_flag = ProtoField.uint8 ("dji_p3_flyrec.fdi_gyro_bias_raw_flag", "Gyro Bias Raw Flag", base.HEX)
f.fdi_gyrox_bias_raw = ProtoField.float ("dji_p3_flyrec.fdi_gyrox_bias_raw", "Gyrox Bias Raw", base.DEC)
f.fdi_gyroy_bias_raw = ProtoField.float ("dji_p3_flyrec.fdi_gyroy_bias_raw", "Gyroy Bias Raw", base.DEC)
f.fdi_gyroz_bias_raw = ProtoField.float ("dji_p3_flyrec.fdi_gyroz_bias_raw", "Gyroz Bias Raw", base.DEC)

local function flightrec_fdi_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.fdi_ns_abnormal_all, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fdi_history_ns_abnormal_all, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fdi_gyro_bias_raw_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.fdi_gyrox_bias_raw, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fdi_gyroy_bias_raw, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fdi_gyroz_bias_raw, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 21) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Fdi: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Fdi: Payload size different than expected") end
end

-- Flight log - Vincent Debug - 0x8003

f.vincent_debug_data0 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data0", "Data0", base.DEC)
f.vincent_debug_data1 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data1", "Data1", base.DEC)
f.vincent_debug_data2 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data2", "Data2", base.DEC)
f.vincent_debug_data3 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data3", "Data3", base.DEC)
f.vincent_debug_data4 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data4", "Data4", base.DEC)
f.vincent_debug_data5 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data5", "Data5", base.DEC)
f.vincent_debug_data6 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data6", "Data6", base.DEC)
f.vincent_debug_data7 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data7", "Data7", base.DEC)
f.vincent_debug_data8 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data8", "Data8", base.DEC)
f.vincent_debug_data9 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data9", "Data9", base.DEC)
f.vincent_debug_data10 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data10", "Data10", base.DEC)
f.vincent_debug_data11 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data11", "Data11", base.DEC)
f.vincent_debug_data12 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data12", "Data12", base.DEC)
f.vincent_debug_data13 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data13", "Data13", base.DEC)
f.vincent_debug_data14 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data14", "Data14", base.DEC)
f.vincent_debug_data15 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data15", "Data15", base.DEC)
f.vincent_debug_data16 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data16", "Data16", base.DEC)
f.vincent_debug_data17 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data17", "Data17", base.DEC)
f.vincent_debug_data18 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data18", "Data18", base.DEC)
f.vincent_debug_data19 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data19", "Data19", base.DEC)
f.vincent_debug_data20 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data20", "Data20", base.DEC)
f.vincent_debug_data21 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data21", "Data21", base.DEC)
f.vincent_debug_data22 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data22", "Data22", base.DEC)
f.vincent_debug_data23 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data23", "Data23", base.DEC)
f.vincent_debug_data24 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data24", "Data24", base.DEC)
f.vincent_debug_data25 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data25", "Data25", base.DEC)
f.vincent_debug_data26 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data26", "Data26", base.DEC)
f.vincent_debug_data27 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data27", "Data27", base.DEC)
f.vincent_debug_data28 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data28", "Data28", base.DEC)
f.vincent_debug_data29 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data29", "Data29", base.DEC)
f.vincent_debug_data30 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data30", "Data30", base.DEC)
f.vincent_debug_data31 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data31", "Data31", base.DEC)
f.vincent_debug_data32 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data32", "Data32", base.DEC)
f.vincent_debug_data33 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data33", "Data33", base.DEC)
f.vincent_debug_data34 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data34", "Data34", base.DEC)
f.vincent_debug_data35 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data35", "Data35", base.DEC)
f.vincent_debug_data36 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data36", "Data36", base.DEC)
f.vincent_debug_data37 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data37", "Data37", base.DEC)
f.vincent_debug_data38 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data38", "Data38", base.DEC)
f.vincent_debug_data39 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data39", "Data39", base.DEC)
f.vincent_debug_data40 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data40", "Data40", base.DEC)
f.vincent_debug_data41 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data41", "Data41", base.DEC)
f.vincent_debug_data42 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data42", "Data42", base.DEC)
f.vincent_debug_data43 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data43", "Data43", base.DEC)
f.vincent_debug_data44 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data44", "Data44", base.DEC)
f.vincent_debug_data45 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data45", "Data45", base.DEC)
f.vincent_debug_data46 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data46", "Data46", base.DEC)
f.vincent_debug_data47 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data47", "Data47", base.DEC)
f.vincent_debug_data48 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data48", "Data48", base.DEC)
f.vincent_debug_data49 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data49", "Data49", base.DEC)
f.vincent_debug_data50 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data50", "Data50", base.DEC)
f.vincent_debug_data51 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data51", "Data51", base.DEC)
f.vincent_debug_data52 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data52", "Data52", base.DEC)
f.vincent_debug_data53 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data53", "Data53", base.DEC)
f.vincent_debug_data54 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data54", "Data54", base.DEC)
f.vincent_debug_data55 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data55", "Data55", base.DEC)
f.vincent_debug_data56 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data56", "Data56", base.DEC)
f.vincent_debug_data57 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data57", "Data57", base.DEC)
f.vincent_debug_data58 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data58", "Data58", base.DEC)
f.vincent_debug_data59 = ProtoField.float ("dji_p3_flyrec.vincent_debug_data59", "Data59", base.DEC)

local function flightrec_vincent_debug_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.vincent_debug_data0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data3, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data4, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data5, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data6, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data7, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data8, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data9, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data10, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data11, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data12, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data13, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data14, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data15, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data16, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data17, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data18, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data19, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data20, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data21, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data22, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data23, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data24, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data25, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data26, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data27, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data28, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data29, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data30, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data31, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data32, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data33, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data34, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data35, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data36, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data37, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data38, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data39, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data40, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data41, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data42, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data43, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data44, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data45, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data46, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data47, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data48, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data49, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data50, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data51, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data52, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data53, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data54, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data55, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data56, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data57, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data58, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vincent_debug_data59, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 240) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Vincent Debug: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Vincent Debug: Payload size different than expected") end
end

-- Flight log - Fly Log - 0x8000

f.fly_log_text = ProtoField.string ("dji_p3_flyrec.fly_log_text", "Fly Log", base.ASCII)

local function flightrec_fly_log_dissector(payload, pinfo, subtree)
    local offset = 0

    local rec_fly_log_text = payload(offset, payload:len() - offset)
    subtree:add (f.fly_log_text, rec_fly_log_text)

    pinfo.cols.info = rec_fly_log_text:string():gsub('[^a-zA-Z0-9_:,.[[]]/\\ \t-]','')
end

-- Flight log - Sd Logs - 0xff00

f.sd_logs_text = ProtoField.string ("dji_p3_flyrec.sd_logs_text", "Sd Logs", base.ASCII)

local function flightrec_sd_logs_dissector(payload, pinfo, subtree)
    local offset = 0

    local rec_sd_logs_text = payload(offset, payload:len() - offset)
    subtree:add (f.sd_logs_text, rec_sd_logs_text)

    pinfo.cols.info = rec_sd_logs_text:string():gsub('[^a-zA-Z0-9_:,.[[]]/\\ \t-]','')
end

-- Flight log - Svn Info - 0xfffe

f.svn_info_text = ProtoField.string ("dji_p3_flyrec.svn_info_text", "Svn Info", base.ASCII)

local function flightrec_svn_info_dissector(payload, pinfo, subtree)
    local offset = 0

    local rec_svn_info_text = payload(offset, payload:len() - offset)
    subtree:add (f.svn_info_text, rec_svn_info_text)

    pinfo.cols.info = rec_svn_info_text:string():gsub('[^a-zA-Z0-9_:,.[[]]/\\ \t-]','')
end

-- Flight log - Imu Data - 0x0007

f.imu_data_imu_gyro_tempx = ProtoField.float ("dji_p3_flyrec.imu_data_imu_gyro_tempx", "Imu Gyro TempX", base.DEC)
f.imu_data_imu_gyro_tempy = ProtoField.float ("dji_p3_flyrec.imu_data_imu_gyro_tempy", "Imu Gyro TempY", base.DEC)
f.imu_data_imu_gyro_tempz = ProtoField.float ("dji_p3_flyrec.imu_data_imu_gyro_tempz", "Imu Gyro TempZ", base.DEC)
f.imu_data_imu_gyro_x = ProtoField.float ("dji_p3_flyrec.imu_data_imu_gyro_x", "Imu Gyro X", base.DEC)
f.imu_data_imu_gyro_y = ProtoField.float ("dji_p3_flyrec.imu_data_imu_gyro_y", "Imu Gyro Y", base.DEC)
f.imu_data_imu_gyro_z = ProtoField.float ("dji_p3_flyrec.imu_data_imu_gyro_z", "Imu Gyro Z", base.DEC)
f.imu_data_imu_acc_x = ProtoField.float ("dji_p3_flyrec.imu_data_imu_acc_x", "Imu Acc X", base.DEC)
f.imu_data_imu_acc_y = ProtoField.float ("dji_p3_flyrec.imu_data_imu_acc_y", "Imu Acc Y", base.DEC)
f.imu_data_imu_acc_z = ProtoField.float ("dji_p3_flyrec.imu_data_imu_acc_z", "Imu Acc Z", base.DEC)
f.imu_data_imu_airpress = ProtoField.float ("dji_p3_flyrec.imu_data_imu_airpress", "Imu Airpress", base.DEC)
f.imu_data_imu_vin = ProtoField.float ("dji_p3_flyrec.imu_data_imu_vin", "Imu Vin", base.DEC)
f.imu_data_imu_ref = ProtoField.float ("dji_p3_flyrec.imu_data_imu_ref", "Imu Ref", base.DEC)

local function flightrec_imu_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_data_imu_gyro_tempx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_imu_gyro_tempy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_imu_gyro_tempz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_imu_gyro_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_imu_gyro_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_imu_gyro_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_imu_acc_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_imu_acc_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_imu_acc_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_imu_airpress, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_imu_vin, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_imu_ref, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 48) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Data: Payload size different than expected") end
end

-- Flight log - Imu Data 00 - 0x0870

f.imu_data_00_imu_gyro_tempx_00 = ProtoField.float ("dji_p3_flyrec.imu_data_00_imu_gyro_tempx_00", "Imu Gyro Tempx 00", base.DEC)
f.imu_data_00_imu_gyro_tempy_00 = ProtoField.float ("dji_p3_flyrec.imu_data_00_imu_gyro_tempy_00", "Imu Gyro Tempy 00", base.DEC)
f.imu_data_00_imu_gyro_tempz_00 = ProtoField.float ("dji_p3_flyrec.imu_data_00_imu_gyro_tempz_00", "Imu Gyro Tempz 00", base.DEC)
f.imu_data_00_imu_gyro_x_00 = ProtoField.float ("dji_p3_flyrec.imu_data_00_imu_gyro_x_00", "Imu Gyro X 00", base.DEC)
f.imu_data_00_imu_gyro_y_00 = ProtoField.float ("dji_p3_flyrec.imu_data_00_imu_gyro_y_00", "Imu Gyro Y 00", base.DEC)
f.imu_data_00_imu_gyro_z_00 = ProtoField.float ("dji_p3_flyrec.imu_data_00_imu_gyro_z_00", "Imu Gyro Z 00", base.DEC)
f.imu_data_00_imu_acc_x_00 = ProtoField.float ("dji_p3_flyrec.imu_data_00_imu_acc_x_00", "Imu Acc X 00", base.DEC)
f.imu_data_00_imu_acc_y_00 = ProtoField.float ("dji_p3_flyrec.imu_data_00_imu_acc_y_00", "Imu Acc Y 00", base.DEC)
f.imu_data_00_imu_acc_z_00 = ProtoField.float ("dji_p3_flyrec.imu_data_00_imu_acc_z_00", "Imu Acc Z 00", base.DEC)
f.imu_data_00_imu_airpress_00 = ProtoField.float ("dji_p3_flyrec.imu_data_00_imu_airpress_00", "Imu Airpress 00", base.DEC)
f.imu_data_00_imu_vin_00 = ProtoField.float ("dji_p3_flyrec.imu_data_00_imu_vin_00", "Imu Vin 00", base.DEC)
f.imu_data_00_imu_ref_00 = ProtoField.float ("dji_p3_flyrec.imu_data_00_imu_ref_00", "Imu Ref 00", base.DEC)

local function flightrec_imu_data_00_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_data_00_imu_gyro_tempx_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_00_imu_gyro_tempy_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_00_imu_gyro_tempz_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_00_imu_gyro_x_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_00_imu_gyro_y_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_00_imu_gyro_z_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_00_imu_acc_x_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_00_imu_acc_y_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_00_imu_acc_z_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_00_imu_airpress_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_00_imu_vin_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_00_imu_ref_00, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 48) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Data 00: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Data 00: Payload size different than expected") end
end

-- Flight log - Imu Data 01 - 0x0871

f.imu_data_01_imu_gyro_tempx_01 = ProtoField.float ("dji_p3_flyrec.imu_data_01_imu_gyro_tempx_01", "Imu Gyro Tempx 01", base.DEC)
f.imu_data_01_imu_gyro_tempy_01 = ProtoField.float ("dji_p3_flyrec.imu_data_01_imu_gyro_tempy_01", "Imu Gyro Tempy 01", base.DEC)
f.imu_data_01_imu_gyro_tempz_01 = ProtoField.float ("dji_p3_flyrec.imu_data_01_imu_gyro_tempz_01", "Imu Gyro Tempz 01", base.DEC)
f.imu_data_01_imu_gyro_x_01 = ProtoField.float ("dji_p3_flyrec.imu_data_01_imu_gyro_x_01", "Imu Gyro X 01", base.DEC)
f.imu_data_01_imu_gyro_y_01 = ProtoField.float ("dji_p3_flyrec.imu_data_01_imu_gyro_y_01", "Imu Gyro Y 01", base.DEC)
f.imu_data_01_imu_gyro_z_01 = ProtoField.float ("dji_p3_flyrec.imu_data_01_imu_gyro_z_01", "Imu Gyro Z 01", base.DEC)
f.imu_data_01_imu_acc_x_01 = ProtoField.float ("dji_p3_flyrec.imu_data_01_imu_acc_x_01", "Imu Acc X 01", base.DEC)
f.imu_data_01_imu_acc_y_01 = ProtoField.float ("dji_p3_flyrec.imu_data_01_imu_acc_y_01", "Imu Acc Y 01", base.DEC)
f.imu_data_01_imu_acc_z_01 = ProtoField.float ("dji_p3_flyrec.imu_data_01_imu_acc_z_01", "Imu Acc Z 01", base.DEC)
f.imu_data_01_imu_airpress_01 = ProtoField.float ("dji_p3_flyrec.imu_data_01_imu_airpress_01", "Imu Airpress 01", base.DEC)
f.imu_data_01_imu_vin_01 = ProtoField.float ("dji_p3_flyrec.imu_data_01_imu_vin_01", "Imu Vin 01", base.DEC)
f.imu_data_01_imu_ref_01 = ProtoField.float ("dji_p3_flyrec.imu_data_01_imu_ref_01", "Imu Ref 01", base.DEC)

local function flightrec_imu_data_01_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_data_01_imu_gyro_tempx_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_01_imu_gyro_tempy_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_01_imu_gyro_tempz_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_01_imu_gyro_x_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_01_imu_gyro_y_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_01_imu_gyro_z_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_01_imu_acc_x_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_01_imu_acc_y_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_01_imu_acc_z_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_01_imu_airpress_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_01_imu_vin_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_01_imu_ref_01, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 48) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Data 01: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Data 01: Payload size different than expected") end
end

-- Flight log - Imu Data 02 - 0x0872

f.imu_data_02_imu_gyro_tempx_02 = ProtoField.float ("dji_p3_flyrec.imu_data_02_imu_gyro_tempx_02", "Imu Gyro Tempx 02", base.DEC)
f.imu_data_02_imu_gyro_tempy_02 = ProtoField.float ("dji_p3_flyrec.imu_data_02_imu_gyro_tempy_02", "Imu Gyro Tempy 02", base.DEC)
f.imu_data_02_imu_gyro_tempz_02 = ProtoField.float ("dji_p3_flyrec.imu_data_02_imu_gyro_tempz_02", "Imu Gyro Tempz 02", base.DEC)
f.imu_data_02_imu_gyro_x_02 = ProtoField.float ("dji_p3_flyrec.imu_data_02_imu_gyro_x_02", "Imu Gyro X 02", base.DEC)
f.imu_data_02_imu_gyro_y_02 = ProtoField.float ("dji_p3_flyrec.imu_data_02_imu_gyro_y_02", "Imu Gyro Y 02", base.DEC)
f.imu_data_02_imu_gyro_z_02 = ProtoField.float ("dji_p3_flyrec.imu_data_02_imu_gyro_z_02", "Imu Gyro Z 02", base.DEC)
f.imu_data_02_imu_acc_x_02 = ProtoField.float ("dji_p3_flyrec.imu_data_02_imu_acc_x_02", "Imu Acc X 02", base.DEC)
f.imu_data_02_imu_acc_y_02 = ProtoField.float ("dji_p3_flyrec.imu_data_02_imu_acc_y_02", "Imu Acc Y 02", base.DEC)
f.imu_data_02_imu_acc_z_02 = ProtoField.float ("dji_p3_flyrec.imu_data_02_imu_acc_z_02", "Imu Acc Z 02", base.DEC)
f.imu_data_02_imu_airpress_02 = ProtoField.float ("dji_p3_flyrec.imu_data_02_imu_airpress_02", "Imu Airpress 02", base.DEC)
f.imu_data_02_imu_vin_02 = ProtoField.float ("dji_p3_flyrec.imu_data_02_imu_vin_02", "Imu Vin 02", base.DEC)
f.imu_data_02_imu_ref_02 = ProtoField.float ("dji_p3_flyrec.imu_data_02_imu_ref_02", "Imu Ref 02", base.DEC)

local function flightrec_imu_data_02_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_data_02_imu_gyro_tempx_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_02_imu_gyro_tempy_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_02_imu_gyro_tempz_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_02_imu_gyro_x_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_02_imu_gyro_y_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_02_imu_gyro_z_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_02_imu_acc_x_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_02_imu_acc_y_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_02_imu_acc_z_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_02_imu_airpress_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_02_imu_vin_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_data_02_imu_ref_02, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 48) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Data 02: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Data 02: Payload size different than expected") end
end

-- Flight log - Imu Cali Data - 0x0008

f.imu_cali_data_gyrox_temp = ProtoField.float ("dji_p3_flyrec.imu_cali_data_gyrox_temp", "Gyrox Temp", base.DEC)
f.imu_cali_data_g_cfg_temper_bias_bias_bw = ProtoField.float ("dji_p3_flyrec.imu_cali_data_g_cfg_temper_bias_bias_bw", "G Cfg Temper Bias.Bias.Bw", base.DEC)
f.imu_cali_data_g_cfg_temper_bias_bias_bw = ProtoField.float ("dji_p3_flyrec.imu_cali_data_g_cfg_temper_bias_bias_bw", "G Cfg Temper Bias.Bias.Bw", base.DEC)
f.imu_cali_data_g_cfg_temper_bias_bias_bw = ProtoField.float ("dji_p3_flyrec.imu_cali_data_g_cfg_temper_bias_bias_bw", "G Cfg Temper Bias.Bias.Bw", base.DEC)
f.imu_cali_data_g_cfg_temper_bias_bias_ba = ProtoField.float ("dji_p3_flyrec.imu_cali_data_g_cfg_temper_bias_bias_ba", "G Cfg Temper Bias.Bias.Ba", base.DEC)
f.imu_cali_data_g_cfg_temper_bias_bias_ba = ProtoField.float ("dji_p3_flyrec.imu_cali_data_g_cfg_temper_bias_bias_ba", "G Cfg Temper Bias.Bias.Ba", base.DEC)
f.imu_cali_data_g_cfg_temper_bias_bias_ba = ProtoField.float ("dji_p3_flyrec.imu_cali_data_g_cfg_temper_bias_bias_ba", "G Cfg Temper Bias.Bias.Ba", base.DEC)
f.imu_cali_data_g_cfg_temper_bias_flag = ProtoField.uint16 ("dji_p3_flyrec.imu_cali_data_g_cfg_temper_bias_flag", "G Cfg Temper Bias Flag", base.HEX)
f.imu_cali_data_g_cfg_temper_bias_cali = ProtoField.uint16 ("dji_p3_flyrec.imu_cali_data_g_cfg_temper_bias_cali", "G Cfg Temper Bias Cali", base.HEX)
f.imu_cali_data_g_cfg_gyro_bias_flag = ProtoField.uint16 ("dji_p3_flyrec.imu_cali_data_g_cfg_gyro_bias_flag", "G Cfg Gyro Bias Flag", base.HEX)
f.imu_cali_data_g_cfg_gyro_bias_cali = ProtoField.uint16 ("dji_p3_flyrec.imu_cali_data_g_cfg_gyro_bias_cali", "G Cfg Gyro Bias Cali", base.HEX)
f.imu_cali_data_imu_cali_bias_sta_flag = ProtoField.uint8 ("dji_p3_flyrec.imu_cali_data_imu_cali_bias_sta_flag", "Imu Cali Bias Sta Flag", base.HEX)
f.imu_cali_data_imu_cali_bias_sta_cnt = ProtoField.uint8 ("dji_p3_flyrec.imu_cali_data_imu_cali_bias_sta_cnt", "Imu Cali Bias Sta Cnt", base.HEX)
f.imu_cali_data_g_cali_state = ProtoField.uint8 ("dji_p3_flyrec.imu_cali_data_g_cali_state", "G Cali State", base.HEX)
f.imu_cali_data_clock = ProtoField.uint16 ("dji_p3_flyrec.imu_cali_data_clock", "Clock", base.HEX)
f.imu_cali_data_time = ProtoField.int16 ("dji_p3_flyrec.imu_cali_data_time", "Time", base.DEC)

local function flightrec_imu_cali_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_cali_data_gyrox_temp, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_cali_data_g_cfg_temper_bias_bias_bw, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_cali_data_g_cfg_temper_bias_bias_bw, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_cali_data_g_cfg_temper_bias_bias_bw, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_cali_data_g_cfg_temper_bias_bias_ba, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_cali_data_g_cfg_temper_bias_bias_ba, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_cali_data_g_cfg_temper_bias_bias_ba, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_cali_data_g_cfg_temper_bias_flag, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_cali_data_g_cfg_temper_bias_cali, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_cali_data_g_cfg_gyro_bias_flag, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_cali_data_g_cfg_gyro_bias_cali, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_cali_data_imu_cali_bias_sta_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.imu_cali_data_imu_cali_bias_sta_cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.imu_cali_data_g_cali_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.imu_cali_data_clock, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_cali_data_time, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 43) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Cali Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Cali Data: Payload size different than expected") end
end

-- Flight log - Sensor Cfg Temp - 0x0009

f.sensor_cfg_temp_bias_gyrox = ProtoField.float ("dji_p3_flyrec.sensor_cfg_temp_bias_gyrox", "Bias Gyro X", base.DEC)
f.sensor_cfg_temp_bias_gyroy = ProtoField.float ("dji_p3_flyrec.sensor_cfg_temp_bias_gyroy", "Bias Gyro Y", base.DEC)
f.sensor_cfg_temp_bias_gyroz = ProtoField.float ("dji_p3_flyrec.sensor_cfg_temp_bias_gyroz", "Bias Gyro Z", base.DEC)
f.sensor_cfg_temp_bias_accx = ProtoField.float ("dji_p3_flyrec.sensor_cfg_temp_bias_accx", "Bias Acc X", base.DEC)
f.sensor_cfg_temp_bias_accy = ProtoField.float ("dji_p3_flyrec.sensor_cfg_temp_bias_accy", "Bias Acc Y", base.DEC)
f.sensor_cfg_temp_bias_accz = ProtoField.float ("dji_p3_flyrec.sensor_cfg_temp_bias_accz", "Bias Acc Z", base.DEC)
f.sensor_cfg_temp_tw = ProtoField.float ("dji_p3_flyrec.sensor_cfg_temp_tw", "Tw", base.DEC)
f.sensor_cfg_temp_ta = ProtoField.float ("dji_p3_flyrec.sensor_cfg_temp_ta", "Ta", base.DEC)
f.sensor_cfg_temp_fw = ProtoField.uint16 ("dji_p3_flyrec.sensor_cfg_temp_fw", "Fw", base.HEX)
f.sensor_cfg_temp_fa = ProtoField.uint16 ("dji_p3_flyrec.sensor_cfg_temp_fa", "Fa", base.HEX)

local function flightrec_sensor_cfg_temp_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.sensor_cfg_temp_bias_gyrox, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.sensor_cfg_temp_bias_gyroy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.sensor_cfg_temp_bias_gyroz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.sensor_cfg_temp_bias_accx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.sensor_cfg_temp_bias_accy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.sensor_cfg_temp_bias_accz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.sensor_cfg_temp_tw, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.sensor_cfg_temp_ta, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.sensor_cfg_temp_fw, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.sensor_cfg_temp_fa, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 36) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Sensor Cfg Temp: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Sensor Cfg Temp: Payload size different than expected") end
end

-- Flight log - Temp Ctl Data - 0x000a

f.temp_ctl_data_p = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_p", "P", base.DEC)
f.temp_ctl_data_i = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_i", "I", base.DEC)
f.temp_ctl_data_i_small = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_i_small", "I Small", base.DEC)
f.temp_ctl_data_d = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_d", "D", base.DEC)
f.temp_ctl_data_dl_err = ProtoField.int16 ("dji_p3_flyrec.temp_ctl_data_dl_err", "Dl Err", base.DEC, nil, nil, "difference in cur_dst_temp")
f.temp_ctl_data_err_last = ProtoField.int16 ("dji_p3_flyrec.temp_ctl_data_err_last", "Err Last", base.DEC)
f.temp_ctl_data_out = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_out", "Out", base.DEC)
f.temp_ctl_data_kp = ProtoField.float ("dji_p3_flyrec.temp_ctl_data_kp", "Kp", base.DEC)
f.temp_ctl_data_ki = ProtoField.float ("dji_p3_flyrec.temp_ctl_data_ki", "Ki", base.DEC)
f.temp_ctl_data_kd = ProtoField.float ("dji_p3_flyrec.temp_ctl_data_kd", "Kd", base.DEC)
f.temp_ctl_data_ctl_out_value = ProtoField.uint32 ("dji_p3_flyrec.temp_ctl_data_ctl_out_value", "Ctl Out Value", base.DEC, nil, nil, "2000000 means 100%")
f.temp_ctl_data_real_ctl_out_value = ProtoField.uint32 ("dji_p3_flyrec.temp_ctl_data_real_ctl_out_value", "Real Ctl Out Value", base.DEC)
f.temp_ctl_data_dst_value = ProtoField.int16 ("dji_p3_flyrec.temp_ctl_data_dst_value", "Dst Value", base.DEC)
f.temp_ctl_data_cur_dst_temp = ProtoField.int16 ("dji_p3_flyrec.temp_ctl_data_cur_dst_temp", "Cur Dst Temp", base.DEC)
-- The fields below do not match the implementation in m0306 firmware
--f.temp_ctl_data_cnt = ProtoField.uint32 ("dji_p3_flyrec.temp_ctl_data_cnt", "Cnt", base.DEC)
--f.temp_ctl_data_real_ctl_out_per = ProtoField.uint8 ("dji_p3_flyrec.temp_ctl_data_real_ctl_out_per", "Real Ctl Out Per", base.DEC, nil, nil, "real_ctl_out_value in percent")
--f.temp_ctl_data_slope_type = ProtoField.uint8 ("dji_p3_flyrec.temp_ctl_data_slope_type", "Slope Type", base.HEX)
--f.temp_ctl_data_temp_ctl_slope = ProtoField.uint8 ("dji_p3_flyrec.temp_ctl_data_temp_ctl_slope", "Temp Ctl Slope", base.HEX)
--f.temp_ctl_data_t_finish = ProtoField.uint8 ("dji_p3_flyrec.temp_ctl_data_t_finish", "T Finish", base.HEX)
-- This is what flyc_param suggests here
f.temp_ctl_data_imu_fldc = ProtoField.uint32 ("dji_p3_flyrec.temp_ctl_data_imu_fldc", "imu_temp fldC", base.DEC, nil, nil, "Looks like this supposed to be a counter but never increases beyond 0")
f.temp_ctl_data_temp_ctl_slope = ProtoField.uint32 ("dji_p3_flyrec.temp_ctl_data_temp_ctl_slope", "Temp Ctl Slope", base.DEC, nil, nil, "Cummulative value of real_ctl_out_per over time")
f.temp_ctl_data_imu_fld14 = ProtoField.uint32 ("dji_p3_flyrec.temp_ctl_data_imu_fld14", "imu_temp fld14", base.DEC, nil, nil, "Cummulative change in value of fld1c over time")
f.temp_ctl_data_imu_fld18 = ProtoField.float ("dji_p3_flyrec.temp_ctl_data_imu_fld18", "imu_temp fld18", base.DEC, nil, nil, "equal to temp_ctl_slope / fld14")
f.temp_ctl_data_imu_fld1c = ProtoField.uint16 ("dji_p3_flyrec.temp_ctl_data_imu_fld1c", "imu_temp fld1C", base.DEC, nil, nil, "unknown param * 100")
f.temp_ctl_data_real_ctl_out_per = ProtoField.uint8 ("dji_p3_flyrec.temp_ctl_data_real_ctl_out_per", "Real Ctl Out Per", base.DEC, nil, nil, "real_ctl_out_value in percent")
f.temp_ctl_data_imu_fld1f = ProtoField.uint8 ("dji_p3_flyrec.temp_ctl_data_imu_fld1f", "imu_temp fld1F", base.HEX)

local function flightrec_temp_ctl_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.temp_ctl_data_p, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_i, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_i_small, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_d, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_dl_err, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_data_err_last, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_data_out, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_kp, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_ki, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_kd, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_ctl_out_value, payload(offset, 4)) -- offset 36
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_real_ctl_out_value, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_dst_value, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_data_cur_dst_temp, payload(offset, 2))
    offset = offset + 2

    --subtree:add_le (f.temp_ctl_data_cnt, payload(offset, 4))
    subtree:add_le (f.temp_ctl_data_imu_fldc, payload(offset, 4)) -- offset 48
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_temp_ctl_slope, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_imu_fld14, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_imu_fld18, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_imu_fld1c, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_data_real_ctl_out_per, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_data_imu_fld1f, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 68) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Temp Ctl Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Temp Ctl Data: Payload size different than expected") end
end

-- Flight log - Temp Ctl Data 00 - 0x0880

f.temp_ctl_data_00_dst_value_00 = ProtoField.int16 ("dji_p3_flyrec.temp_ctl_data_00_dst_value_00", "Dst Value 00", base.DEC)
f.temp_ctl_data_00_cur_dst_temp_00 = ProtoField.int16 ("dji_p3_flyrec.temp_ctl_data_00_cur_dst_temp_00", "Cur Dst Temp 00", base.DEC)
f.temp_ctl_data_00_p_00 = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_00_p_00", "P 00", base.DEC)
f.temp_ctl_data_00_i_00 = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_00_i_00", "I 00", base.DEC)
f.temp_ctl_data_00_d_00 = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_00_d_00", "D 00", base.DEC)
f.temp_ctl_data_00_dl_err_00 = ProtoField.int16 ("dji_p3_flyrec.temp_ctl_data_00_dl_err_00", "Dl Err 00", base.DEC)
f.temp_ctl_data_00_real_ctl_out_per_00 = ProtoField.uint8 ("dji_p3_flyrec.temp_ctl_data_00_real_ctl_out_per_00", "Real Ctl Out Per 00", base.HEX)
f.temp_ctl_data_00_slope_type_00 = ProtoField.uint8 ("dji_p3_flyrec.temp_ctl_data_00_slope_type_00", "Slope Type 00", base.HEX)
f.temp_ctl_data_00_temp_ctl_slope_00 = ProtoField.uint8 ("dji_p3_flyrec.temp_ctl_data_00_temp_ctl_slope_00", "Temp Ctl Slope 00", base.HEX)
f.temp_ctl_data_00_t_finish_00 = ProtoField.uint8 ("dji_p3_flyrec.temp_ctl_data_00_t_finish_00", "T Finish 00", base.HEX)
f.temp_ctl_data_00_err_last_00 = ProtoField.int16 ("dji_p3_flyrec.temp_ctl_data_00_err_last_00", "Err Last 00", base.DEC)
f.temp_ctl_data_00_ctl_out_value_00 = ProtoField.uint32 ("dji_p3_flyrec.temp_ctl_data_00_ctl_out_value_00", "Ctl Out Value 00", base.HEX)
f.temp_ctl_data_00_real_ctl_out_value_00 = ProtoField.uint32 ("dji_p3_flyrec.temp_ctl_data_00_real_ctl_out_value_00", "Real Ctl Out Value 00", base.HEX)
f.temp_ctl_data_00_i_small_00 = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_00_i_small_00", "I Small 00", base.DEC)
f.temp_ctl_data_00_out_00 = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_00_out_00", "Out 00", base.DEC)
f.temp_ctl_data_00_cnt_00 = ProtoField.uint32 ("dji_p3_flyrec.temp_ctl_data_00_cnt_00", "Cnt 00", base.DEC, nil, nil, "Sequence counter increased each time the packet of this type is prepared")

local function flightrec_temp_ctl_data_00_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.temp_ctl_data_00_dst_value_00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_data_00_cur_dst_temp_00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_data_00_p_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_00_i_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_00_d_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_00_dl_err_00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_data_00_real_ctl_out_per_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_data_00_slope_type_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_data_00_temp_ctl_slope_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_data_00_t_finish_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_data_00_err_last_00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_data_00_ctl_out_value_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_00_real_ctl_out_value_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_00_i_small_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_00_out_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_00_cnt_00, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 44) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Temp Ctl Data 00: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Temp Ctl Data 00: Payload size different than expected") end
end

-- Flight log - Temp Ctl Data 01 - 0x0881

f.temp_ctl_data_01_dst_value_01 = ProtoField.int16 ("dji_p3_flyrec.temp_ctl_data_01_dst_value_01", "Dst Value 01", base.DEC)
f.temp_ctl_data_01_cur_dst_temp_01 = ProtoField.int16 ("dji_p3_flyrec.temp_ctl_data_01_cur_dst_temp_01", "Cur Dst Temp 01", base.DEC)
f.temp_ctl_data_01_p_01 = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_01_p_01", "P 01", base.DEC)
f.temp_ctl_data_01_i_01 = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_01_i_01", "I 01", base.DEC)
f.temp_ctl_data_01_d_01 = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_01_d_01", "D 01", base.DEC)
f.temp_ctl_data_01_dl_err_01 = ProtoField.int16 ("dji_p3_flyrec.temp_ctl_data_01_dl_err_01", "Dl Err 01", base.DEC)
f.temp_ctl_data_01_real_ctl_out_per_01 = ProtoField.uint8 ("dji_p3_flyrec.temp_ctl_data_01_real_ctl_out_per_01", "Real Ctl Out Per 01", base.HEX)
f.temp_ctl_data_01_slope_type_01 = ProtoField.uint8 ("dji_p3_flyrec.temp_ctl_data_01_slope_type_01", "Slope Type 01", base.HEX)
f.temp_ctl_data_01_temp_ctl_slope_01 = ProtoField.uint8 ("dji_p3_flyrec.temp_ctl_data_01_temp_ctl_slope_01", "Temp Ctl Slope 01", base.HEX)
f.temp_ctl_data_01_t_finish_01 = ProtoField.uint8 ("dji_p3_flyrec.temp_ctl_data_01_t_finish_01", "T Finish 01", base.HEX)
f.temp_ctl_data_01_err_last_01 = ProtoField.int16 ("dji_p3_flyrec.temp_ctl_data_01_err_last_01", "Err Last 01", base.DEC)
f.temp_ctl_data_01_ctl_out_value_01 = ProtoField.uint32 ("dji_p3_flyrec.temp_ctl_data_01_ctl_out_value_01", "Ctl Out Value 01", base.HEX)
f.temp_ctl_data_01_real_ctl_out_value_01 = ProtoField.uint32 ("dji_p3_flyrec.temp_ctl_data_01_real_ctl_out_value_01", "Real Ctl Out Value 01", base.HEX)
f.temp_ctl_data_01_i_small_01 = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_01_i_small_01", "I Small 01", base.DEC)
f.temp_ctl_data_01_out_01 = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_01_out_01", "Out 01", base.DEC)
f.temp_ctl_data_01_cnt_01 = ProtoField.uint32 ("dji_p3_flyrec.temp_ctl_data_01_cnt_01", "Cnt 01", base.DEC, nil, nil, "Sequence counter increased each time the packet of this type is prepared")

local function flightrec_temp_ctl_data_01_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.temp_ctl_data_01_dst_value_01, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_data_01_cur_dst_temp_01, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_data_01_p_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_01_i_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_01_d_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_01_dl_err_01, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_data_01_real_ctl_out_per_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_data_01_slope_type_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_data_01_temp_ctl_slope_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_data_01_t_finish_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_data_01_err_last_01, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_data_01_ctl_out_value_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_01_real_ctl_out_value_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_01_i_small_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_01_out_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_01_cnt_01, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 44) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Temp Ctl Data 01: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Temp Ctl Data 01: Payload size different than expected") end
end

-- Flight log - Temp Ctl Data 02 - 0x0882

f.temp_ctl_data_02_dst_value_02 = ProtoField.int16 ("dji_p3_flyrec.temp_ctl_data_02_dst_value_02", "Dst Value 02", base.DEC)
f.temp_ctl_data_02_cur_dst_temp_02 = ProtoField.int16 ("dji_p3_flyrec.temp_ctl_data_02_cur_dst_temp_02", "Cur Dst Temp 02", base.DEC)
f.temp_ctl_data_02_p_02 = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_02_p_02", "P 02", base.DEC)
f.temp_ctl_data_02_i_02 = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_02_i_02", "I 02", base.DEC)
f.temp_ctl_data_02_d_02 = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_02_d_02", "D 02", base.DEC)
f.temp_ctl_data_02_dl_err_02 = ProtoField.int16 ("dji_p3_flyrec.temp_ctl_data_02_dl_err_02", "Dl Err 02", base.DEC)
f.temp_ctl_data_02_real_ctl_out_per_02 = ProtoField.uint8 ("dji_p3_flyrec.temp_ctl_data_02_real_ctl_out_per_02", "Real Ctl Out Per 02", base.HEX)
f.temp_ctl_data_02_slope_type_02 = ProtoField.uint8 ("dji_p3_flyrec.temp_ctl_data_02_slope_type_02", "Slope Type 02", base.HEX)
f.temp_ctl_data_02_temp_ctl_slope_02 = ProtoField.uint8 ("dji_p3_flyrec.temp_ctl_data_02_temp_ctl_slope_02", "Temp Ctl Slope 02", base.HEX)
f.temp_ctl_data_02_t_finish_02 = ProtoField.uint8 ("dji_p3_flyrec.temp_ctl_data_02_t_finish_02", "T Finish 02", base.HEX)
f.temp_ctl_data_02_err_last_02 = ProtoField.int16 ("dji_p3_flyrec.temp_ctl_data_02_err_last_02", "Err Last 02", base.DEC)
f.temp_ctl_data_02_ctl_out_value_02 = ProtoField.uint32 ("dji_p3_flyrec.temp_ctl_data_02_ctl_out_value_02", "Ctl Out Value 02", base.HEX)
f.temp_ctl_data_02_real_ctl_out_value_02 = ProtoField.uint32 ("dji_p3_flyrec.temp_ctl_data_02_real_ctl_out_value_02", "Real Ctl Out Value 02", base.HEX)
f.temp_ctl_data_02_i_small_02 = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_02_i_small_02", "I Small 02", base.DEC)
f.temp_ctl_data_02_out_02 = ProtoField.int32 ("dji_p3_flyrec.temp_ctl_data_02_out_02", "Out 02", base.DEC)
f.temp_ctl_data_02_cnt_02 = ProtoField.uint32 ("dji_p3_flyrec.temp_ctl_data_02_cnt_02", "Cnt 02", base.DEC, nil, nil, "Sequence counter increased each time the packet of this type is prepared")

local function flightrec_temp_ctl_data_02_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.temp_ctl_data_02_dst_value_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_data_02_cur_dst_temp_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_data_02_p_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_02_i_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_02_d_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_02_dl_err_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_data_02_real_ctl_out_per_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_data_02_slope_type_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_data_02_temp_ctl_slope_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_data_02_t_finish_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_data_02_err_last_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_data_02_ctl_out_value_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_02_real_ctl_out_value_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_02_i_small_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_02_out_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_data_02_cnt_02, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 44) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Temp Ctl Data 02: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Temp Ctl Data 02: Payload size different than expected") end
end

-- Flight log - Pwm Output - 0x0014

f.pwm_output_m1 = ProtoField.uint16 ("dji_p3_flyrec.pwm_output_m1", "Motor 1", base.HEX)
f.pwm_output_m2 = ProtoField.uint16 ("dji_p3_flyrec.pwm_output_m2", "Motor 2", base.HEX)
f.pwm_output_m3 = ProtoField.uint16 ("dji_p3_flyrec.pwm_output_m3", "Motor 3", base.HEX)
f.pwm_output_m4 = ProtoField.uint16 ("dji_p3_flyrec.pwm_output_m4", "Motor 4", base.HEX)
f.pwm_output_m5 = ProtoField.uint16 ("dji_p3_flyrec.pwm_output_m5", "Motor 5", base.HEX)
f.pwm_output_m6 = ProtoField.uint16 ("dji_p3_flyrec.pwm_output_m6", "Motor 6", base.HEX)
f.pwm_output_m7 = ProtoField.uint16 ("dji_p3_flyrec.pwm_output_m7", "Motor 7", base.HEX)
f.pwm_output_m8 = ProtoField.uint16 ("dji_p3_flyrec.pwm_output_m8", "Motor 8", base.HEX)

local function flightrec_pwm_output_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.pwm_output_m1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.pwm_output_m2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.pwm_output_m3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.pwm_output_m4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.pwm_output_m5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.pwm_output_m6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.pwm_output_m7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.pwm_output_m8, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 16) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Pwm Output: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Pwm Output: Payload size different than expected") end
end

-- Flight log - Temp Bias Data - 0x0015

f.temp_bias_data__bw_x = ProtoField.float ("dji_p3_flyrec.temp_bias_data__bw_x", " Bw X", base.DEC)
f.temp_bias_data__bw_y = ProtoField.float ("dji_p3_flyrec.temp_bias_data__bw_y", " Bw Y", base.DEC)
f.temp_bias_data__bw_z = ProtoField.float ("dji_p3_flyrec.temp_bias_data__bw_z", " Bw Z", base.DEC)
f.temp_bias_data__ba_x = ProtoField.float ("dji_p3_flyrec.temp_bias_data__ba_x", " Ba X", base.DEC)
f.temp_bias_data__ba_y = ProtoField.float ("dji_p3_flyrec.temp_bias_data__ba_y", " Ba Y", base.DEC)
f.temp_bias_data__ba_z = ProtoField.float ("dji_p3_flyrec.temp_bias_data__ba_z", " Ba Z", base.DEC)
f.temp_bias_data__temp = ProtoField.float ("dji_p3_flyrec.temp_bias_data__temp", " Temp", base.DEC)
f.temp_bias_data__flag = ProtoField.uint8 ("dji_p3_flyrec.temp_bias_data__flag", " Flag", base.HEX)

local function flightrec_temp_bias_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.temp_bias_data__bw_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_bias_data__bw_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_bias_data__bw_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_bias_data__ba_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_bias_data__ba_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_bias_data__ba_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_bias_data__temp, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_bias_data__flag, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 29) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Temp Bias Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Temp Bias Data: Payload size different than expected") end
end

-- Flight log - Temp Cali Data - 0x0016

f.temp_cali_data__start_flag = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data__start_flag", " Start Flag", base.HEX)
f.temp_cali_data__state = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data__state", " State", base.DEC)
f.temp_cali_data__cali_cnt = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data__cali_cnt", " Cali Cnt", base.HEX)
f.temp_cali_data__temp_ready = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data__temp_ready", " Temp Ready", base.HEX)
f.temp_cali_data__step = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data__step", " Step", base.HEX)
f.temp_cali_data__cali_type = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data__cali_type", " Cali Type", base.HEX)
f.temp_cali_data__tick = ProtoField.uint16 ("dji_p3_flyrec.temp_cali_data__tick", " Tick", base.HEX)
f.temp_cali_data__grav_acc_x = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data__grav_acc_x", " Grav Acc X", base.DEC)
f.temp_cali_data__grav_acc_y = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data__grav_acc_y", " Grav Acc Y", base.DEC)
f.temp_cali_data__grav_acc_z = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data__grav_acc_z", " Grav Acc Z", base.DEC)
f.temp_cali_data__dst_cali_temp = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data__dst_cali_temp", " Dst Cali Temp", base.DEC)
f.temp_cali_data__temp_min = ProtoField.float ("dji_p3_flyrec.temp_cali_data__temp_min", " Temp Min", base.DEC)
f.temp_cali_data__temp_max = ProtoField.float ("dji_p3_flyrec.temp_cali_data__temp_max", " Temp Max", base.DEC)
f.temp_cali_data__temp_cali_status = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data__temp_cali_status", " Temp Cali Status", base.HEX)
f.temp_cali_data__base_cali_status = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data__base_cali_status", " Base Cali Status", base.HEX)
f.temp_cali_data__cfg_temp_cali_fw_version = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data__cfg_temp_cali_fw_version", " Cfg Temp Cali Fw Version", base.HEX)
f.temp_cali_data__cur_temp_cali_fw_version = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data__cur_temp_cali_fw_version", " Cur Temp Cali Fw Version", base.HEX)
f.temp_cali_data__temp_bw_x = ProtoField.float ("dji_p3_flyrec.temp_cali_data__temp_bw_x", " Temp Bw X", base.DEC)
f.temp_cali_data__temp_bw_y = ProtoField.float ("dji_p3_flyrec.temp_cali_data__temp_bw_y", " Temp Bw Y", base.DEC)
f.temp_cali_data__temp_bw_z = ProtoField.float ("dji_p3_flyrec.temp_cali_data__temp_bw_z", " Temp Bw Z", base.DEC)
f.temp_cali_data__temp_ba_x = ProtoField.float ("dji_p3_flyrec.temp_cali_data__temp_ba_x", " Temp Ba X", base.DEC)
f.temp_cali_data__temp_ba_y = ProtoField.float ("dji_p3_flyrec.temp_cali_data__temp_ba_y", " Temp Ba Y", base.DEC)
f.temp_cali_data__temp_ba_z = ProtoField.float ("dji_p3_flyrec.temp_cali_data__temp_ba_z", " Temp Ba Z", base.DEC)
f.temp_cali_data__temp_temp = ProtoField.float ("dji_p3_flyrec.temp_cali_data__temp_temp", " Temp Temp", base.DEC)
f.temp_cali_data__base_bw_x = ProtoField.float ("dji_p3_flyrec.temp_cali_data__base_bw_x", " Base Bw X", base.DEC)
f.temp_cali_data__base_bw_y = ProtoField.float ("dji_p3_flyrec.temp_cali_data__base_bw_y", " Base Bw Y", base.DEC)
f.temp_cali_data__base_bw_z = ProtoField.float ("dji_p3_flyrec.temp_cali_data__base_bw_z", " Base Bw Z", base.DEC)
f.temp_cali_data__base_ba_x = ProtoField.float ("dji_p3_flyrec.temp_cali_data__base_ba_x", " Base Ba X", base.DEC)
f.temp_cali_data__base_ba_y = ProtoField.float ("dji_p3_flyrec.temp_cali_data__base_ba_y", " Base Ba Y", base.DEC)
f.temp_cali_data__base_ba_z = ProtoField.float ("dji_p3_flyrec.temp_cali_data__base_ba_z", " Base Ba Z", base.DEC)
f.temp_cali_data__base_temp = ProtoField.float ("dji_p3_flyrec.temp_cali_data__base_temp", " Base Temp", base.DEC)

local function flightrec_temp_cali_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.temp_cali_data__start_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data__state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data__cali_cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data__temp_ready, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data__step, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data__cali_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data__tick, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_cali_data__grav_acc_x, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data__grav_acc_y, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data__grav_acc_z, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data__dst_cali_temp, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data__temp_min, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data__temp_max, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data__temp_cali_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data__base_cali_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data__cfg_temp_cali_fw_version, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data__cur_temp_cali_fw_version, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data__temp_bw_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data__temp_bw_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data__temp_bw_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data__temp_ba_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data__temp_ba_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data__temp_ba_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data__temp_temp, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data__base_bw_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data__base_bw_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data__base_bw_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data__base_ba_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data__base_ba_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data__base_ba_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data__base_temp, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 80) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Temp Cali Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Temp Cali Data: Payload size different than expected") end
end

-- Flight log - App Temp Bias Data - 0x0018

f.app_temp_bias_data_bw_x = ProtoField.float ("dji_p3_flyrec.app_temp_bias_data_bw_x", "Bw X", base.DEC)
f.app_temp_bias_data_bw_y = ProtoField.float ("dji_p3_flyrec.app_temp_bias_data_bw_y", "Bw Y", base.DEC)
f.app_temp_bias_data_bw_z = ProtoField.float ("dji_p3_flyrec.app_temp_bias_data_bw_z", "Bw Z", base.DEC)
f.app_temp_bias_data_ba_x = ProtoField.float ("dji_p3_flyrec.app_temp_bias_data_ba_x", "Ba X", base.DEC)
f.app_temp_bias_data_ba_y = ProtoField.float ("dji_p3_flyrec.app_temp_bias_data_ba_y", "Ba Y", base.DEC)
f.app_temp_bias_data_ba_z = ProtoField.float ("dji_p3_flyrec.app_temp_bias_data_ba_z", "Ba Z", base.DEC)
f.app_temp_bias_data_temp = ProtoField.float ("dji_p3_flyrec.app_temp_bias_data_temp", "Temp", base.DEC)
f.app_temp_bias_data_flag = ProtoField.uint8 ("dji_p3_flyrec.app_temp_bias_data_flag", "Flag", base.HEX)

local function flightrec_app_temp_bias_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.app_temp_bias_data_bw_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias_data_bw_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias_data_bw_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias_data_ba_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias_data_ba_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias_data_ba_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias_data_temp, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias_data_flag, payload(offset, 1))
    offset = offset + 1

    -- The size might be padded to multiplication of 4 bytes
    if (offset ~= 29) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"App Temp Bias Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) and (payload:len() ~= offset+4-(offset%4)) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"App Temp Bias Data: Payload size different than expected") end
end

-- Flight log - App Temp Cali Data - 0x0019

f.app_temp_cali_data_start_flag = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_start_flag", "Start Flag", base.HEX)
f.app_temp_cali_data_state = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_state", "State", base.DEC)
f.app_temp_cali_data_cali_cnt = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_cali_cnt", "Cali Cnt", base.HEX)
f.app_temp_cali_data_temp_ready = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_temp_ready", "Temp Ready", base.HEX)
f.app_temp_cali_data_step = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_step", "Step", base.HEX)
f.app_temp_cali_data_cali_type = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_cali_type", "Cali Type", base.HEX)
f.app_temp_cali_data_tick = ProtoField.uint16 ("dji_p3_flyrec.app_temp_cali_data_tick", "Tick", base.HEX)
f.app_temp_cali_data_grav_acc_x = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_grav_acc_x", "Grav Acc X", base.DEC)
f.app_temp_cali_data_grav_acc_y = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_grav_acc_y", "Grav Acc Y", base.DEC)
f.app_temp_cali_data_grav_acc_z = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_grav_acc_z", "Grav Acc Z", base.DEC)
f.app_temp_cali_data_dst_cali_temp = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_dst_cali_temp", "Dst Cali Temp", base.DEC)
f.app_temp_cali_data_temp_min = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_temp_min", "Temp Min", base.DEC)
f.app_temp_cali_data_temp_max = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_temp_max", "Temp Max", base.DEC)
f.app_temp_cali_data_temp_cali_status = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_temp_cali_status", "Temp Cali Status", base.HEX)
f.app_temp_cali_data_base_cali_status = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_base_cali_status", "Base Cali Status", base.HEX)
f.app_temp_cali_data_cfg_temp_cali_fw_version = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_cfg_temp_cali_fw_version", "Cfg Temp Cali Fw Version", base.HEX)
f.app_temp_cali_data_cur_temp_cali_fw_version = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_cur_temp_cali_fw_version", "Cur Temp Cali Fw Version", base.HEX)
f.app_temp_cali_data_temp_bw_x = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_temp_bw_x", "Temp Bw X", base.DEC)
f.app_temp_cali_data_temp_bw_y = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_temp_bw_y", "Temp Bw Y", base.DEC)
f.app_temp_cali_data_temp_bw_z = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_temp_bw_z", "Temp Bw Z", base.DEC)
f.app_temp_cali_data_temp_ba_x = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_temp_ba_x", "Temp Ba X", base.DEC)
f.app_temp_cali_data_temp_ba_y = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_temp_ba_y", "Temp Ba Y", base.DEC)
f.app_temp_cali_data_temp_ba_z = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_temp_ba_z", "Temp Ba Z", base.DEC)
f.app_temp_cali_data_temp_temp = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_temp_temp", "Temp Temp", base.DEC)
f.app_temp_cali_data_base_bw_x = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_base_bw_x", "Base Bw X", base.DEC)
f.app_temp_cali_data_base_bw_y = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_base_bw_y", "Base Bw Y", base.DEC)
f.app_temp_cali_data_base_bw_z = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_base_bw_z", "Base Bw Z", base.DEC)
f.app_temp_cali_data_base_ba_x = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_base_ba_x", "Base Ba X", base.DEC)
f.app_temp_cali_data_base_ba_y = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_base_ba_y", "Base Ba Y", base.DEC)
f.app_temp_cali_data_base_ba_z = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_base_ba_z", "Base Ba Z", base.DEC)
f.app_temp_cali_data_base_temp = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_base_temp", "Base Temp", base.DEC)

local function flightrec_app_temp_cali_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.app_temp_cali_data_start_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_cali_cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_temp_ready, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_step, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_cali_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_tick, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.app_temp_cali_data_grav_acc_x, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_grav_acc_y, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_grav_acc_z, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_dst_cali_temp, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_temp_min, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_temp_max, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_temp_cali_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_base_cali_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_cfg_temp_cali_fw_version, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_cur_temp_cali_fw_version, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_temp_bw_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_temp_bw_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_temp_bw_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_temp_ba_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_temp_ba_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_temp_ba_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_temp_temp, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_base_bw_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_base_bw_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_base_bw_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_base_ba_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_base_ba_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_base_ba_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_base_temp, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 80) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"App Temp Cali Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"App Temp Cali Data: Payload size different than expected") end
end

-- Flight log - Temp Cali Data 00 - 0x0893

f.temp_cali_data_00__start_flag_00 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_00__start_flag_00", " Start Flag 00", base.HEX)
f.temp_cali_data_00__state_00 = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data_00__state_00", " State 00", base.DEC)
f.temp_cali_data_00__cali_cnt_00 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_00__cali_cnt_00", " Cali Cnt 00", base.HEX)
f.temp_cali_data_00__temp_ready_00 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_00__temp_ready_00", " Temp Ready 00", base.HEX)
f.temp_cali_data_00__step_00 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_00__step_00", " Step 00", base.HEX)
f.temp_cali_data_00__cali_type_00 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_00__cali_type_00", " Cali Type 00", base.HEX)
f.temp_cali_data_00__tick_00 = ProtoField.uint16 ("dji_p3_flyrec.temp_cali_data_00__tick_00", " Tick 00", base.HEX)
f.temp_cali_data_00__grav_acc_x_00 = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data_00__grav_acc_x_00", " Grav Acc X 00", base.DEC)
f.temp_cali_data_00__grav_acc_y_00 = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data_00__grav_acc_y_00", " Grav Acc Y 00", base.DEC)
f.temp_cali_data_00__grav_acc_z_00 = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data_00__grav_acc_z_00", " Grav Acc Z 00", base.DEC)
f.temp_cali_data_00__dst_cali_temp_00 = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data_00__dst_cali_temp_00", " Dst Cali Temp 00", base.DEC)
f.temp_cali_data_00__temp_min_00 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_00__temp_min_00", " Temp Min 00", base.DEC)
f.temp_cali_data_00__temp_max_00 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_00__temp_max_00", " Temp Max 00", base.DEC)
f.temp_cali_data_00__temp_cali_status_00 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_00__temp_cali_status_00", " Temp Cali Status 00", base.HEX)
f.temp_cali_data_00__base_cali_status_00 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_00__base_cali_status_00", " Base Cali Status 00", base.HEX)
f.temp_cali_data_00__cfg_temp_cali_fw_version_00 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_00__cfg_temp_cali_fw_version_00", " Cfg Temp Cali Fw Version 00", base.HEX)
f.temp_cali_data_00__cur_temp_cali_fw_version_00 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_00__cur_temp_cali_fw_version_00", " Cur Temp Cali Fw Version 00", base.HEX)
f.temp_cali_data_00__temp_bw_x_00 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_00__temp_bw_x_00", " Temp Bw X 00", base.DEC)
f.temp_cali_data_00__temp_bw_y_00 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_00__temp_bw_y_00", " Temp Bw Y 00", base.DEC)
f.temp_cali_data_00__temp_bw_z_00 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_00__temp_bw_z_00", " Temp Bw Z 00", base.DEC)
f.temp_cali_data_00__temp_ba_x_00 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_00__temp_ba_x_00", " Temp Ba X 00", base.DEC)
f.temp_cali_data_00__temp_ba_y_00 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_00__temp_ba_y_00", " Temp Ba Y 00", base.DEC)
f.temp_cali_data_00__temp_ba_z_00 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_00__temp_ba_z_00", " Temp Ba Z 00", base.DEC)
f.temp_cali_data_00__temp_temp_00 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_00__temp_temp_00", " Temp Temp 00", base.DEC)
f.temp_cali_data_00__base_bw_x_00 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_00__base_bw_x_00", " Base Bw X 00", base.DEC)
f.temp_cali_data_00__base_bw_y_00 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_00__base_bw_y_00", " Base Bw Y 00", base.DEC)
f.temp_cali_data_00__base_bw_z_00 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_00__base_bw_z_00", " Base Bw Z 00", base.DEC)
f.temp_cali_data_00__base_ba_x_00 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_00__base_ba_x_00", " Base Ba X 00", base.DEC)
f.temp_cali_data_00__base_ba_y_00 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_00__base_ba_y_00", " Base Ba Y 00", base.DEC)
f.temp_cali_data_00__base_ba_z_00 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_00__base_ba_z_00", " Base Ba Z 00", base.DEC)
f.temp_cali_data_00__base_temp_00 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_00__base_temp_00", " Base Temp 00", base.DEC)

local function flightrec_temp_cali_data_00_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.temp_cali_data_00__start_flag_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_00__state_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_00__cali_cnt_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_00__temp_ready_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_00__step_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_00__cali_type_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_00__tick_00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_cali_data_00__grav_acc_x_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_00__grav_acc_y_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_00__grav_acc_z_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_00__dst_cali_temp_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_00__temp_min_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_00__temp_max_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_00__temp_cali_status_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_00__base_cali_status_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_00__cfg_temp_cali_fw_version_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_00__cur_temp_cali_fw_version_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_00__temp_bw_x_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_00__temp_bw_y_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_00__temp_bw_z_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_00__temp_ba_x_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_00__temp_ba_y_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_00__temp_ba_z_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_00__temp_temp_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_00__base_bw_x_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_00__base_bw_y_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_00__base_bw_z_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_00__base_ba_x_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_00__base_ba_y_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_00__base_ba_z_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_00__base_temp_00, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 80) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Temp Cali Data 00: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Temp Cali Data 00: Payload size different than expected") end
end

-- Flight log - App Temp Cali Data 00 - 0x0896

f.app_temp_cali_data_00_start_flag_00 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_00_start_flag_00", "Start Flag 00", base.HEX)
f.app_temp_cali_data_00_state_00 = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_00_state_00", "State 00", base.DEC)
f.app_temp_cali_data_00_cali_cnt_00 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_00_cali_cnt_00", "Cali Cnt 00", base.HEX)
f.app_temp_cali_data_00_temp_ready_00 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_00_temp_ready_00", "Temp Ready 00", base.HEX)
f.app_temp_cali_data_00_step_00 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_00_step_00", "Step 00", base.HEX)
f.app_temp_cali_data_00_cali_type_00 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_00_cali_type_00", "Cali Type 00", base.HEX)
f.app_temp_cali_data_00_tick_00 = ProtoField.uint16 ("dji_p3_flyrec.app_temp_cali_data_00_tick_00", "Tick 00", base.HEX)
f.app_temp_cali_data_00_grav_acc_x_00 = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_00_grav_acc_x_00", "Grav Acc X 00", base.DEC)
f.app_temp_cali_data_00_grav_acc_y_00 = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_00_grav_acc_y_00", "Grav Acc Y 00", base.DEC)
f.app_temp_cali_data_00_grav_acc_z_00 = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_00_grav_acc_z_00", "Grav Acc Z 00", base.DEC)
f.app_temp_cali_data_00_dst_cali_temp_00 = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_00_dst_cali_temp_00", "Dst Cali Temp 00", base.DEC)
f.app_temp_cali_data_00_temp_min_00 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_00_temp_min_00", "Temp Min 00", base.DEC)
f.app_temp_cali_data_00_temp_max_00 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_00_temp_max_00", "Temp Max 00", base.DEC)
f.app_temp_cali_data_00_temp_cali_status_00 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_00_temp_cali_status_00", "Temp Cali Status 00", base.HEX)
f.app_temp_cali_data_00_base_cali_status_00 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_00_base_cali_status_00", "Base Cali Status 00", base.HEX)
f.app_temp_cali_data_00_cfg_temp_cali_fw_version_00 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_00_cfg_temp_cali_fw_version_00", "Cfg Temp Cali Fw Version 00", base.HEX)
f.app_temp_cali_data_00_cur_temp_cali_fw_version_00 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_00_cur_temp_cali_fw_version_00", "Cur Temp Cali Fw Version 00", base.HEX)
f.app_temp_cali_data_00_temp_bw_x_00 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_00_temp_bw_x_00", "Temp Bw X 00", base.DEC)
f.app_temp_cali_data_00_temp_bw_y_00 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_00_temp_bw_y_00", "Temp Bw Y 00", base.DEC)
f.app_temp_cali_data_00_temp_bw_z_00 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_00_temp_bw_z_00", "Temp Bw Z 00", base.DEC)
f.app_temp_cali_data_00_temp_ba_x_00 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_00_temp_ba_x_00", "Temp Ba X 00", base.DEC)
f.app_temp_cali_data_00_temp_ba_y_00 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_00_temp_ba_y_00", "Temp Ba Y 00", base.DEC)
f.app_temp_cali_data_00_temp_ba_z_00 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_00_temp_ba_z_00", "Temp Ba Z 00", base.DEC)
f.app_temp_cali_data_00_temp_temp_00 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_00_temp_temp_00", "Temp Temp 00", base.DEC)
f.app_temp_cali_data_00_base_bw_x_00 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_00_base_bw_x_00", "Base Bw X 00", base.DEC)
f.app_temp_cali_data_00_base_bw_y_00 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_00_base_bw_y_00", "Base Bw Y 00", base.DEC)
f.app_temp_cali_data_00_base_bw_z_00 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_00_base_bw_z_00", "Base Bw Z 00", base.DEC)
f.app_temp_cali_data_00_base_ba_x_00 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_00_base_ba_x_00", "Base Ba X 00", base.DEC)
f.app_temp_cali_data_00_base_ba_y_00 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_00_base_ba_y_00", "Base Ba Y 00", base.DEC)
f.app_temp_cali_data_00_base_ba_z_00 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_00_base_ba_z_00", "Base Ba Z 00", base.DEC)
f.app_temp_cali_data_00_base_temp_00 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_00_base_temp_00", "Base Temp 00", base.DEC)

local function flightrec_app_temp_cali_data_00_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.app_temp_cali_data_00_start_flag_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_00_state_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_00_cali_cnt_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_00_temp_ready_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_00_step_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_00_cali_type_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_00_tick_00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.app_temp_cali_data_00_grav_acc_x_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_00_grav_acc_y_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_00_grav_acc_z_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_00_dst_cali_temp_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_00_temp_min_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_00_temp_max_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_00_temp_cali_status_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_00_base_cali_status_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_00_cfg_temp_cali_fw_version_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_00_cur_temp_cali_fw_version_00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_00_temp_bw_x_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_00_temp_bw_y_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_00_temp_bw_z_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_00_temp_ba_x_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_00_temp_ba_y_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_00_temp_ba_z_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_00_temp_temp_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_00_base_bw_x_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_00_base_bw_y_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_00_base_bw_z_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_00_base_ba_x_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_00_base_ba_y_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_00_base_ba_z_00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_00_base_temp_00, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 80) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"App Temp Cali Data 00: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"App Temp Cali Data 00: Payload size different than expected") end
end

-- Flight log - Temp Cali Data 01 - 0x0894

f.temp_cali_data_01__start_flag_01 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_01__start_flag_01", " Start Flag 01", base.HEX)
f.temp_cali_data_01__state_01 = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data_01__state_01", " State 01", base.DEC)
f.temp_cali_data_01__cali_cnt_01 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_01__cali_cnt_01", " Cali Cnt 01", base.HEX)
f.temp_cali_data_01__temp_ready_01 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_01__temp_ready_01", " Temp Ready 01", base.HEX)
f.temp_cali_data_01__step_01 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_01__step_01", " Step 01", base.HEX)
f.temp_cali_data_01__cali_type_01 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_01__cali_type_01", " Cali Type 01", base.HEX)
f.temp_cali_data_01__tick_01 = ProtoField.uint16 ("dji_p3_flyrec.temp_cali_data_01__tick_01", " Tick 01", base.HEX)
f.temp_cali_data_01__grav_acc_x_01 = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data_01__grav_acc_x_01", " Grav Acc X 01", base.DEC)
f.temp_cali_data_01__grav_acc_y_01 = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data_01__grav_acc_y_01", " Grav Acc Y 01", base.DEC)
f.temp_cali_data_01__grav_acc_z_01 = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data_01__grav_acc_z_01", " Grav Acc Z 01", base.DEC)
f.temp_cali_data_01__dst_cali_temp_01 = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data_01__dst_cali_temp_01", " Dst Cali Temp 01", base.DEC)
f.temp_cali_data_01__temp_min_01 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_01__temp_min_01", " Temp Min 01", base.DEC)
f.temp_cali_data_01__temp_max_01 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_01__temp_max_01", " Temp Max 01", base.DEC)
f.temp_cali_data_01__temp_cali_status_01 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_01__temp_cali_status_01", " Temp Cali Status 01", base.HEX)
f.temp_cali_data_01__base_cali_status_01 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_01__base_cali_status_01", " Base Cali Status 01", base.HEX)
f.temp_cali_data_01__cfg_temp_cali_fw_version_01 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_01__cfg_temp_cali_fw_version_01", " Cfg Temp Cali Fw Version 01", base.HEX)
f.temp_cali_data_01__cur_temp_cali_fw_version_01 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_01__cur_temp_cali_fw_version_01", " Cur Temp Cali Fw Version 01", base.HEX)
f.temp_cali_data_01__temp_bw_x_01 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_01__temp_bw_x_01", " Temp Bw X 01", base.DEC)
f.temp_cali_data_01__temp_bw_y_01 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_01__temp_bw_y_01", " Temp Bw Y 01", base.DEC)
f.temp_cali_data_01__temp_bw_z_01 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_01__temp_bw_z_01", " Temp Bw Z 01", base.DEC)
f.temp_cali_data_01__temp_ba_x_01 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_01__temp_ba_x_01", " Temp Ba X 01", base.DEC)
f.temp_cali_data_01__temp_ba_y_01 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_01__temp_ba_y_01", " Temp Ba Y 01", base.DEC)
f.temp_cali_data_01__temp_ba_z_01 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_01__temp_ba_z_01", " Temp Ba Z 01", base.DEC)
f.temp_cali_data_01__temp_temp_01 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_01__temp_temp_01", " Temp Temp 01", base.DEC)
f.temp_cali_data_01__base_bw_x_01 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_01__base_bw_x_01", " Base Bw X 01", base.DEC)
f.temp_cali_data_01__base_bw_y_01 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_01__base_bw_y_01", " Base Bw Y 01", base.DEC)
f.temp_cali_data_01__base_bw_z_01 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_01__base_bw_z_01", " Base Bw Z 01", base.DEC)
f.temp_cali_data_01__base_ba_x_01 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_01__base_ba_x_01", " Base Ba X 01", base.DEC)
f.temp_cali_data_01__base_ba_y_01 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_01__base_ba_y_01", " Base Ba Y 01", base.DEC)
f.temp_cali_data_01__base_ba_z_01 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_01__base_ba_z_01", " Base Ba Z 01", base.DEC)
f.temp_cali_data_01__base_temp_01 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_01__base_temp_01", " Base Temp 01", base.DEC)

local function flightrec_temp_cali_data_01_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.temp_cali_data_01__start_flag_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_01__state_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_01__cali_cnt_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_01__temp_ready_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_01__step_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_01__cali_type_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_01__tick_01, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_cali_data_01__grav_acc_x_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_01__grav_acc_y_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_01__grav_acc_z_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_01__dst_cali_temp_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_01__temp_min_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_01__temp_max_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_01__temp_cali_status_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_01__base_cali_status_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_01__cfg_temp_cali_fw_version_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_01__cur_temp_cali_fw_version_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_01__temp_bw_x_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_01__temp_bw_y_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_01__temp_bw_z_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_01__temp_ba_x_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_01__temp_ba_y_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_01__temp_ba_z_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_01__temp_temp_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_01__base_bw_x_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_01__base_bw_y_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_01__base_bw_z_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_01__base_ba_x_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_01__base_ba_y_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_01__base_ba_z_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_01__base_temp_01, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 80) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Temp Cali Data 01: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Temp Cali Data 01: Payload size different than expected") end
end

-- Flight log - App Temp Cali Data 01 - 0x0897

f.app_temp_cali_data_01_start_flag_01 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_01_start_flag_01", "Start Flag 01", base.HEX)
f.app_temp_cali_data_01_state_01 = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_01_state_01", "State 01", base.DEC)
f.app_temp_cali_data_01_cali_cnt_01 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_01_cali_cnt_01", "Cali Cnt 01", base.HEX)
f.app_temp_cali_data_01_temp_ready_01 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_01_temp_ready_01", "Temp Ready 01", base.HEX)
f.app_temp_cali_data_01_step_01 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_01_step_01", "Step 01", base.HEX)
f.app_temp_cali_data_01_cali_type_01 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_01_cali_type_01", "Cali Type 01", base.HEX)
f.app_temp_cali_data_01_tick_01 = ProtoField.uint16 ("dji_p3_flyrec.app_temp_cali_data_01_tick_01", "Tick 01", base.HEX)
f.app_temp_cali_data_01_grav_acc_x_01 = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_01_grav_acc_x_01", "Grav Acc X 01", base.DEC)
f.app_temp_cali_data_01_grav_acc_y_01 = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_01_grav_acc_y_01", "Grav Acc Y 01", base.DEC)
f.app_temp_cali_data_01_grav_acc_z_01 = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_01_grav_acc_z_01", "Grav Acc Z 01", base.DEC)
f.app_temp_cali_data_01_dst_cali_temp_01 = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_01_dst_cali_temp_01", "Dst Cali Temp 01", base.DEC)
f.app_temp_cali_data_01_temp_min_01 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_01_temp_min_01", "Temp Min 01", base.DEC)
f.app_temp_cali_data_01_temp_max_01 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_01_temp_max_01", "Temp Max 01", base.DEC)
f.app_temp_cali_data_01_temp_cali_status_01 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_01_temp_cali_status_01", "Temp Cali Status 01", base.HEX)
f.app_temp_cali_data_01_base_cali_status_01 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_01_base_cali_status_01", "Base Cali Status 01", base.HEX)
f.app_temp_cali_data_01_cfg_temp_cali_fw_version_01 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_01_cfg_temp_cali_fw_version_01", "Cfg Temp Cali Fw Version 01", base.HEX)
f.app_temp_cali_data_01_cur_temp_cali_fw_version_01 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_01_cur_temp_cali_fw_version_01", "Cur Temp Cali Fw Version 01", base.HEX)
f.app_temp_cali_data_01_temp_bw_x_01 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_01_temp_bw_x_01", "Temp Bw X 01", base.DEC)
f.app_temp_cali_data_01_temp_bw_y_01 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_01_temp_bw_y_01", "Temp Bw Y 01", base.DEC)
f.app_temp_cali_data_01_temp_bw_z_01 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_01_temp_bw_z_01", "Temp Bw Z 01", base.DEC)
f.app_temp_cali_data_01_temp_ba_x_01 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_01_temp_ba_x_01", "Temp Ba X 01", base.DEC)
f.app_temp_cali_data_01_temp_ba_y_01 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_01_temp_ba_y_01", "Temp Ba Y 01", base.DEC)
f.app_temp_cali_data_01_temp_ba_z_01 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_01_temp_ba_z_01", "Temp Ba Z 01", base.DEC)
f.app_temp_cali_data_01_temp_temp_01 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_01_temp_temp_01", "Temp Temp 01", base.DEC)
f.app_temp_cali_data_01_base_bw_x_01 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_01_base_bw_x_01", "Base Bw X 01", base.DEC)
f.app_temp_cali_data_01_base_bw_y_01 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_01_base_bw_y_01", "Base Bw Y 01", base.DEC)
f.app_temp_cali_data_01_base_bw_z_01 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_01_base_bw_z_01", "Base Bw Z 01", base.DEC)
f.app_temp_cali_data_01_base_ba_x_01 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_01_base_ba_x_01", "Base Ba X 01", base.DEC)
f.app_temp_cali_data_01_base_ba_y_01 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_01_base_ba_y_01", "Base Ba Y 01", base.DEC)
f.app_temp_cali_data_01_base_ba_z_01 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_01_base_ba_z_01", "Base Ba Z 01", base.DEC)
f.app_temp_cali_data_01_base_temp_01 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_01_base_temp_01", "Base Temp 01", base.DEC)

local function flightrec_app_temp_cali_data_01_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.app_temp_cali_data_01_start_flag_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_01_state_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_01_cali_cnt_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_01_temp_ready_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_01_step_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_01_cali_type_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_01_tick_01, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.app_temp_cali_data_01_grav_acc_x_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_01_grav_acc_y_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_01_grav_acc_z_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_01_dst_cali_temp_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_01_temp_min_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_01_temp_max_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_01_temp_cali_status_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_01_base_cali_status_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_01_cfg_temp_cali_fw_version_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_01_cur_temp_cali_fw_version_01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_01_temp_bw_x_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_01_temp_bw_y_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_01_temp_bw_z_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_01_temp_ba_x_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_01_temp_ba_y_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_01_temp_ba_z_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_01_temp_temp_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_01_base_bw_x_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_01_base_bw_y_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_01_base_bw_z_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_01_base_ba_x_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_01_base_ba_y_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_01_base_ba_z_01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_01_base_temp_01, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 80) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"App Temp Cali Data 01: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"App Temp Cali Data 01: Payload size different than expected") end
end

-- Flight log - Temp Cali Data 02 - 0x0895

f.temp_cali_data_02__start_flag_02 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_02__start_flag_02", " Start Flag 02", base.HEX)
f.temp_cali_data_02__state_02 = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data_02__state_02", " State 02", base.DEC)
f.temp_cali_data_02__cali_cnt_02 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_02__cali_cnt_02", " Cali Cnt 02", base.HEX)
f.temp_cali_data_02__temp_ready_02 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_02__temp_ready_02", " Temp Ready 02", base.HEX)
f.temp_cali_data_02__step_02 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_02__step_02", " Step 02", base.HEX)
f.temp_cali_data_02__cali_type_02 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_02__cali_type_02", " Cali Type 02", base.HEX)
f.temp_cali_data_02__tick_02 = ProtoField.uint16 ("dji_p3_flyrec.temp_cali_data_02__tick_02", " Tick 02", base.HEX)
f.temp_cali_data_02__grav_acc_x_02 = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data_02__grav_acc_x_02", " Grav Acc X 02", base.DEC)
f.temp_cali_data_02__grav_acc_y_02 = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data_02__grav_acc_y_02", " Grav Acc Y 02", base.DEC)
f.temp_cali_data_02__grav_acc_z_02 = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data_02__grav_acc_z_02", " Grav Acc Z 02", base.DEC)
f.temp_cali_data_02__dst_cali_temp_02 = ProtoField.int8 ("dji_p3_flyrec.temp_cali_data_02__dst_cali_temp_02", " Dst Cali Temp 02", base.DEC)
f.temp_cali_data_02__temp_min_02 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_02__temp_min_02", " Temp Min 02", base.DEC)
f.temp_cali_data_02__temp_max_02 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_02__temp_max_02", " Temp Max 02", base.DEC)
f.temp_cali_data_02__temp_cali_status_02 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_02__temp_cali_status_02", " Temp Cali Status 02", base.HEX)
f.temp_cali_data_02__base_cali_status_02 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_02__base_cali_status_02", " Base Cali Status 02", base.HEX)
f.temp_cali_data_02__cfg_temp_cali_fw_version_02 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_02__cfg_temp_cali_fw_version_02", " Cfg Temp Cali Fw Version 02", base.HEX)
f.temp_cali_data_02__cur_temp_cali_fw_version_02 = ProtoField.uint8 ("dji_p3_flyrec.temp_cali_data_02__cur_temp_cali_fw_version_02", " Cur Temp Cali Fw Version 02", base.HEX)
f.temp_cali_data_02__temp_bw_x_02 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_02__temp_bw_x_02", " Temp Bw X 02", base.DEC)
f.temp_cali_data_02__temp_bw_y_02 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_02__temp_bw_y_02", " Temp Bw Y 02", base.DEC)
f.temp_cali_data_02__temp_bw_z_02 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_02__temp_bw_z_02", " Temp Bw Z 02", base.DEC)
f.temp_cali_data_02__temp_ba_x_02 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_02__temp_ba_x_02", " Temp Ba X 02", base.DEC)
f.temp_cali_data_02__temp_ba_y_02 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_02__temp_ba_y_02", " Temp Ba Y 02", base.DEC)
f.temp_cali_data_02__temp_ba_z_02 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_02__temp_ba_z_02", " Temp Ba Z 02", base.DEC)
f.temp_cali_data_02__temp_temp_02 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_02__temp_temp_02", " Temp Temp 02", base.DEC)
f.temp_cali_data_02__base_bw_x_02 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_02__base_bw_x_02", " Base Bw X 02", base.DEC)
f.temp_cali_data_02__base_bw_y_02 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_02__base_bw_y_02", " Base Bw Y 02", base.DEC)
f.temp_cali_data_02__base_bw_z_02 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_02__base_bw_z_02", " Base Bw Z 02", base.DEC)
f.temp_cali_data_02__base_ba_x_02 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_02__base_ba_x_02", " Base Ba X 02", base.DEC)
f.temp_cali_data_02__base_ba_y_02 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_02__base_ba_y_02", " Base Ba Y 02", base.DEC)
f.temp_cali_data_02__base_ba_z_02 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_02__base_ba_z_02", " Base Ba Z 02", base.DEC)
f.temp_cali_data_02__base_temp_02 = ProtoField.float ("dji_p3_flyrec.temp_cali_data_02__base_temp_02", " Base Temp 02", base.DEC)

local function flightrec_temp_cali_data_02_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.temp_cali_data_02__start_flag_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_02__state_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_02__cali_cnt_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_02__temp_ready_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_02__step_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_02__cali_type_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_02__tick_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_cali_data_02__grav_acc_x_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_02__grav_acc_y_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_02__grav_acc_z_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_02__dst_cali_temp_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_02__temp_min_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_02__temp_max_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_02__temp_cali_status_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_02__base_cali_status_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_02__cfg_temp_cali_fw_version_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_02__cur_temp_cali_fw_version_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_cali_data_02__temp_bw_x_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_02__temp_bw_y_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_02__temp_bw_z_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_02__temp_ba_x_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_02__temp_ba_y_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_02__temp_ba_z_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_02__temp_temp_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_02__base_bw_x_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_02__base_bw_y_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_02__base_bw_z_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_02__base_ba_x_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_02__base_ba_y_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_02__base_ba_z_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_cali_data_02__base_temp_02, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 80) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Temp Cali Data 02: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Temp Cali Data 02: Payload size different than expected") end
end

-- Flight log - App Temp Cali Data 02 - 0x0898

f.app_temp_cali_data_02_start_flag_02 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_02_start_flag_02", "Start Flag 02", base.HEX)
f.app_temp_cali_data_02_state_02 = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_02_state_02", "State 02", base.DEC)
f.app_temp_cali_data_02_cali_cnt_02 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_02_cali_cnt_02", "Cali Cnt 02", base.HEX)
f.app_temp_cali_data_02_temp_ready_02 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_02_temp_ready_02", "Temp Ready 02", base.HEX)
f.app_temp_cali_data_02_step_02 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_02_step_02", "Step 02", base.HEX)
f.app_temp_cali_data_02_cali_type_02 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_02_cali_type_02", "Cali Type 02", base.HEX)
f.app_temp_cali_data_02_tick_02 = ProtoField.uint16 ("dji_p3_flyrec.app_temp_cali_data_02_tick_02", "Tick 02", base.HEX)
f.app_temp_cali_data_02_grav_acc_x_02 = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_02_grav_acc_x_02", "Grav Acc X 02", base.DEC)
f.app_temp_cali_data_02_grav_acc_y_02 = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_02_grav_acc_y_02", "Grav Acc Y 02", base.DEC)
f.app_temp_cali_data_02_grav_acc_z_02 = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_02_grav_acc_z_02", "Grav Acc Z 02", base.DEC)
f.app_temp_cali_data_02_dst_cali_temp_02 = ProtoField.int8 ("dji_p3_flyrec.app_temp_cali_data_02_dst_cali_temp_02", "Dst Cali Temp 02", base.DEC)
f.app_temp_cali_data_02_temp_min_02 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_02_temp_min_02", "Temp Min 02", base.DEC)
f.app_temp_cali_data_02_temp_max_02 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_02_temp_max_02", "Temp Max 02", base.DEC)
f.app_temp_cali_data_02_temp_cali_status_02 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_02_temp_cali_status_02", "Temp Cali Status 02", base.HEX)
f.app_temp_cali_data_02_base_cali_status_02 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_02_base_cali_status_02", "Base Cali Status 02", base.HEX)
f.app_temp_cali_data_02_cfg_temp_cali_fw_version_02 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_02_cfg_temp_cali_fw_version_02", "Cfg Temp Cali Fw Version 02", base.HEX)
f.app_temp_cali_data_02_cur_temp_cali_fw_version_02 = ProtoField.uint8 ("dji_p3_flyrec.app_temp_cali_data_02_cur_temp_cali_fw_version_02", "Cur Temp Cali Fw Version 02", base.HEX)
f.app_temp_cali_data_02_temp_bw_x_02 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_02_temp_bw_x_02", "Temp Bw X 02", base.DEC)
f.app_temp_cali_data_02_temp_bw_y_02 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_02_temp_bw_y_02", "Temp Bw Y 02", base.DEC)
f.app_temp_cali_data_02_temp_bw_z_02 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_02_temp_bw_z_02", "Temp Bw Z 02", base.DEC)
f.app_temp_cali_data_02_temp_ba_x_02 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_02_temp_ba_x_02", "Temp Ba X 02", base.DEC)
f.app_temp_cali_data_02_temp_ba_y_02 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_02_temp_ba_y_02", "Temp Ba Y 02", base.DEC)
f.app_temp_cali_data_02_temp_ba_z_02 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_02_temp_ba_z_02", "Temp Ba Z 02", base.DEC)
f.app_temp_cali_data_02_temp_temp_02 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_02_temp_temp_02", "Temp Temp 02", base.DEC)
f.app_temp_cali_data_02_base_bw_x_02 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_02_base_bw_x_02", "Base Bw X 02", base.DEC)
f.app_temp_cali_data_02_base_bw_y_02 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_02_base_bw_y_02", "Base Bw Y 02", base.DEC)
f.app_temp_cali_data_02_base_bw_z_02 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_02_base_bw_z_02", "Base Bw Z 02", base.DEC)
f.app_temp_cali_data_02_base_ba_x_02 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_02_base_ba_x_02", "Base Ba X 02", base.DEC)
f.app_temp_cali_data_02_base_ba_y_02 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_02_base_ba_y_02", "Base Ba Y 02", base.DEC)
f.app_temp_cali_data_02_base_ba_z_02 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_02_base_ba_z_02", "Base Ba Z 02", base.DEC)
f.app_temp_cali_data_02_base_temp_02 = ProtoField.float ("dji_p3_flyrec.app_temp_cali_data_02_base_temp_02", "Base Temp 02", base.DEC)

local function flightrec_app_temp_cali_data_02_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.app_temp_cali_data_02_start_flag_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_02_state_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_02_cali_cnt_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_02_temp_ready_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_02_step_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_02_cali_type_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_02_tick_02, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.app_temp_cali_data_02_grav_acc_x_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_02_grav_acc_y_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_02_grav_acc_z_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_02_dst_cali_temp_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_02_temp_min_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_02_temp_max_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_02_temp_cali_status_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_02_base_cali_status_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_02_cfg_temp_cali_fw_version_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_02_cur_temp_cali_fw_version_02, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.app_temp_cali_data_02_temp_bw_x_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_02_temp_bw_y_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_02_temp_bw_z_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_02_temp_ba_x_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_02_temp_ba_y_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_02_temp_ba_z_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_02_temp_temp_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_02_base_bw_x_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_02_base_bw_y_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_02_base_bw_z_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_02_base_ba_x_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_02_base_ba_y_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_02_base_ba_z_02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_cali_data_02_base_temp_02, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 80) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"App Temp Cali Data 02: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"App Temp Cali Data 02: Payload size different than expected") end
end

-- Flight log - Mpu6500 Raw Data - 0x0023

f.mpu6500_raw_data_mpu6500_ax = ProtoField.float ("dji_p3_flyrec.mpu6500_raw_data_mpu6500_ax", "Mpu6500 Ax", base.DEC)
f.mpu6500_raw_data_mpu6500_ay = ProtoField.float ("dji_p3_flyrec.mpu6500_raw_data_mpu6500_ay", "Mpu6500 Ay", base.DEC)
f.mpu6500_raw_data_mpu6500_az = ProtoField.float ("dji_p3_flyrec.mpu6500_raw_data_mpu6500_az", "Mpu6500 Az", base.DEC)
f.mpu6500_raw_data_mpu6500_wx = ProtoField.float ("dji_p3_flyrec.mpu6500_raw_data_mpu6500_wx", "Mpu6500 Wx", base.DEC)
f.mpu6500_raw_data_mpu6500_wy = ProtoField.float ("dji_p3_flyrec.mpu6500_raw_data_mpu6500_wy", "Mpu6500 Wy", base.DEC)
f.mpu6500_raw_data_mpu6500_wz = ProtoField.float ("dji_p3_flyrec.mpu6500_raw_data_mpu6500_wz", "Mpu6500 Wz", base.DEC)

local function flightrec_mpu6500_raw_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.mpu6500_raw_data_mpu6500_ax, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.mpu6500_raw_data_mpu6500_ay, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.mpu6500_raw_data_mpu6500_az, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.mpu6500_raw_data_mpu6500_wx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.mpu6500_raw_data_mpu6500_wy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.mpu6500_raw_data_mpu6500_wz, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 24) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Mpu6500 Raw Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Mpu6500 Raw Data: Payload size different than expected") end
end

-- Flight log - Adxl278 Raw Data - 0x0024

f.adxl278_raw_data_adxl278_ax = ProtoField.float ("dji_p3_flyrec.adxl278_raw_data_adxl278_ax", "Adxl278 Ax", base.DEC)
f.adxl278_raw_data_adxl278_ay = ProtoField.float ("dji_p3_flyrec.adxl278_raw_data_adxl278_ay", "Adxl278 Ay", base.DEC)
f.adxl278_raw_data_adxl278_az = ProtoField.float ("dji_p3_flyrec.adxl278_raw_data_adxl278_az", "Adxl278 Az", base.DEC)

local function flightrec_adxl278_raw_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.adxl278_raw_data_adxl278_ax, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adxl278_raw_data_adxl278_ay, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adxl278_raw_data_adxl278_az, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 12) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Adxl278 Raw Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Adxl278 Raw Data: Payload size different than expected") end
end

-- Flight log - Svo Debug - 0x0065

f.svo_debug_visiondebug1 = ProtoField.float ("dji_p3_flyrec.svo_debug_visiondebug1", "Vision Debug 1", base.DEC)
f.svo_debug_visiondebug2 = ProtoField.float ("dji_p3_flyrec.svo_debug_visiondebug2", "Vision Debug 2", base.DEC)
f.svo_debug_visiondebug3 = ProtoField.float ("dji_p3_flyrec.svo_debug_visiondebug3", "Vision Debug 3", base.DEC)
f.svo_debug_visiondebug4 = ProtoField.float ("dji_p3_flyrec.svo_debug_visiondebug4", "Vision Debug 4", base.DEC)
f.svo_debug_visiondebug5 = ProtoField.float ("dji_p3_flyrec.svo_debug_visiondebug5", "Vision Debug 5", base.DEC)
f.svo_debug_visiondebug6 = ProtoField.float ("dji_p3_flyrec.svo_debug_visiondebug6", "Vision Debug 6", base.DEC)
f.svo_debug_visiondebug7 = ProtoField.float ("dji_p3_flyrec.svo_debug_visiondebug7", "Vision Debug 7", base.DEC)
f.svo_debug_visiondebug8 = ProtoField.float ("dji_p3_flyrec.svo_debug_visiondebug8", "Vision Debug 8", base.DEC)
--f.svo_debug_e_led_atti = ProtoField.none ("dji_p3_flyrec.svo_debug_e_led_atti", "E Led Atti", base.NONE, nil, 0x03, "bitand(filter_status,3)")
--f.svo_debug_e_led_hori = ProtoField.none ("dji_p3_flyrec.svo_debug_e_led_hori", "E Led Hori", base.NONE, nil, 0x0c, "bitand(shift_r(filter_status,2),3)")
--f.svo_debug_e_led_vert = ProtoField.none ("dji_p3_flyrec.svo_debug_e_led_vert", "E Led Vert", base.NONE, nil, 0x30, "bitand(shift_r(filter_status,4),3)")
--f.svo_debug_e_led_gps_new = ProtoField.none ("dji_p3_flyrec.svo_debug_e_led_gps_new", "E Led Gps New", base.NONE, nil, 0xc0, "bitand(shift_r(filter_status,6),3)")
--f.svo_debug_e_long_gps = ProtoField.none ("dji_p3_flyrec.svo_debug_e_long_gps", "E Long Gps", base.NONE, nil, nil, "if(long_gps/10000000<113.93,113.93,long_gps/10000000)")
--f.svo_debug_e_lat_gps = ProtoField.none ("dji_p3_flyrec.svo_debug_e_lat_gps", "E Lat Gps", base.NONE, nil, nil, "if(lat_gps/10000000<22.53,22.53,lat_gps/10000000)")
--f.svo_debug_e_longti = ProtoField.none ("dji_p3_flyrec.svo_debug_e_longti", "E Longti", base.NONE, nil, nil, "if(longti/3.14159265*180<113.93,113.93,longti/3.14159265*180)")
--f.svo_debug_e_lati = ProtoField.none ("dji_p3_flyrec.svo_debug_e_lati", "E Lati", base.NONE, nil, nil, "if(lati/3.14159265*180<22.53,22.53,lati/3.14159265*180)")
--f.svo_debug_e_longti_sim = ProtoField.none ("dji_p3_flyrec.svo_debug_e_longti_sim", "E Longti Sim", base.NONE, nil, nil, "if(longti_sim/3.14159265*180<113.93,113.93,longti_sim/3.14159265*180)")
--f.svo_debug_e_lati_sim = ProtoField.none ("dji_p3_flyrec.svo_debug_e_lati_sim", "E Lati Sim", base.NONE, nil, nil, "if(lati_sim/3.14159265*180<22.53,22.53,lati_sim/3.14159265*180)")
--f.svo_debug_e_x = ProtoField.none ("dji_p3_flyrec.svo_debug_e_x", "E X", base.NONE, nil, nil, "if(absf(x)>50,50,x)")
--f.svo_debug_e_x_m = ProtoField.none ("dji_p3_flyrec.svo_debug_e_x_m", "E X M", base.NONE, nil, nil, "if(absf(x_m)>50,50,x_m)")
--f.svo_debug_e_y = ProtoField.none ("dji_p3_flyrec.svo_debug_e_y", "E Y", base.NONE, nil, nil, "if(absf(y)>50,50,y)")
--f.svo_debug_e_y_m = ProtoField.none ("dji_p3_flyrec.svo_debug_e_y_m", "E Y M", base.NONE, nil, nil, "if(absf(y_m)<50,50,y_m)")
--f.svo_debug_e_pitch = ProtoField.none ("dji_p3_flyrec.svo_debug_e_pitch", "E Pitch", base.NONE, nil, nil, "-asin_x(2*(q1*q3-q0*q2))/3.1415926*180")
--f.svo_debug_e_roll = ProtoField.none ("dji_p3_flyrec.svo_debug_e_roll", "E Roll", base.NONE, nil, nil, "atan2(2*(q2*q3+q0*q1),1-2*(q1*q1+q2*q2))/3.1415926*180")
--f.svo_debug_e_yaw = ProtoField.none ("dji_p3_flyrec.svo_debug_e_yaw", "E Yaw", base.NONE, nil, nil, "atan2(2*(q1*q2+q0*q3),1-2*(q2*q2+q3*q3))/3.1415926*180")
--f.svo_debug_e_yaw_from_m = ProtoField.none ("dji_p3_flyrec.svo_debug_e_yaw_from_m", "E Yaw From M", base.NONE, nil, nil, "atan2(-(m_y*cos(E_roll/57.29578)-m_z*sin(E_roll/57.29578)),m_x*cos(E_pitch/57.29578)+m_y*sin(E_pitch/57.29578)*sin(E_roll/57.29578)+m_z*sin(E_pitch/57.29578)*cos(E_roll/57.29578))*180/3.14159265")
--f.svo_debug_lon = ProtoField.none ("dji_p3_flyrec.svo_debug_lon", "Lon", base.NONE, nil, nil, "if(longti<1.9886,1.9886,longti)")
--f.svo_debug_lat = ProtoField.none ("dji_p3_flyrec.svo_debug_lat", "Lat", base.NONE, nil, nil, "if(lati<0.3933,0.3933,lati)")
--f.svo_debug_nedx = ProtoField.none ("dji_p3_flyrec.svo_debug_nedx", "Nedx", base.NONE, nil, nil, "(lat-0.3933)*6378137.0")
--f.svo_debug_nedy = ProtoField.none ("dji_p3_flyrec.svo_debug_nedy", "Nedy", base.NONE, nil, nil, "(lon-1.9886)*6378137.0*cos(lat)")
--f.svo_debug_e_mod_m = ProtoField.none ("dji_p3_flyrec.svo_debug_e_mod_m", "E Mod M", base.NONE, nil, nil, "sqrt(m_x^2+m_y^2+m_z^2)")
--f.svo_debug_e_mod_acc = ProtoField.none ("dji_p3_flyrec.svo_debug_e_mod_acc", "E Mod Acc", base.NONE, nil, nil, "sqrt(acc_x^2+acc_y^2+acc_z^2)")
--f.svo_debug_e_mod_acc_xy = ProtoField.none ("dji_p3_flyrec.svo_debug_e_mod_acc_xy", "E Mod Acc Xy", base.NONE, nil, nil, "sqrt(acc_x^2+acc_y^2)")
--f.svo_debug_e_vel_n = ProtoField.none ("dji_p3_flyrec.svo_debug_e_vel_n", "E Vel N", base.NONE, nil, nil, "vel_n/100.0")
--f.svo_debug_e_vel_e = ProtoField.none ("dji_p3_flyrec.svo_debug_e_vel_e", "E Vel E", base.NONE, nil, nil, "vel_e/100.0")
--f.svo_debug_e_vel_d = ProtoField.none ("dji_p3_flyrec.svo_debug_e_vel_d", "E Vel D", base.NONE, nil, nil, "vel_d/100.0")
--f.svo_debug_e_gps_err = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_err", "E Gps Err", base.NONE, nil, 0xff000000, "bitand(shift_r(gpstime,24),255)")
--f.svo_debug_e_svn_gln = ProtoField.none ("dji_p3_flyrec.svo_debug_e_svn_gln", "E Svn Gln", base.NONE, nil, 0x0f, "bitand(shift_r(gpsalt,0),15)")
--f.svo_debug_e_svn_gps = ProtoField.none ("dji_p3_flyrec.svo_debug_e_svn_gps", "E Svn Gps", base.NONE, nil, 0xf0, "bitand(shift_r(gpsalt,4),15)")
--f.svo_debug_e_svn_check = ProtoField.none ("dji_p3_flyrec.svo_debug_e_svn_check", "E Svn Check", base.NONE, nil, nil, "E_svn_gln+E_svn_gps-numsv")
--f.svo_debug_e_pitch_sim = ProtoField.none ("dji_p3_flyrec.svo_debug_e_pitch_sim", "E Pitch Sim", base.NONE, nil, nil, "-asin_x(2*(q1_sim*q3_sim-q0_sim*q2_sim))/3.1415926*180")
--f.svo_debug_e_roll_sim = ProtoField.none ("dji_p3_flyrec.svo_debug_e_roll_sim", "E Roll Sim", base.NONE, nil, nil, "atan2(2*(q2_sim*q3_sim+q0_sim*q1_sim),1-2*(q1_sim*q1_sim+q2_sim*q2_sim))/3.1415926*180")
--f.svo_debug_e_yaw_sim = ProtoField.none ("dji_p3_flyrec.svo_debug_e_yaw_sim", "E Yaw Sim", base.NONE, nil, nil, "atan2(2*(q1_sim*q2_sim+q0_sim*q3_sim),1-2*(q2_sim*q2_sim+q3_sim*q3_sim))/3.1415926*180")
--f.svo_debug_e_pitch_rad_sim = ProtoField.none ("dji_p3_flyrec.svo_debug_e_pitch_rad_sim", "E Pitch Rad Sim", base.NONE, nil, nil, "-asin_x(2*(q1_sim*q3_sim-q0_sim*q2_sim))")
--f.svo_debug_e_roll_rad_sim = ProtoField.none ("dji_p3_flyrec.svo_debug_e_roll_rad_sim", "E Roll Rad Sim", base.NONE, nil, nil, "atan2(2*(q2_sim*q3_sim+q0_sim*q1_sim),1-2*(q1_sim*q1_sim+q2_sim*q2_sim))")
--f.svo_debug_e_yaw_rad_sim = ProtoField.none ("dji_p3_flyrec.svo_debug_e_yaw_rad_sim", "E Yaw Rad Sim", base.NONE, nil, nil, "atan2(2*(q1_sim*q2_sim+q0_sim*q3_sim),1-2*(q2_sim*q2_sim+q3_sim*q3_sim))")
--f.svo_debug_e_vb_x = ProtoField.none ("dji_p3_flyrec.svo_debug_e_vb_x", "E Vb X", base.NONE, nil, nil, "(1-2*q2*q2-2*q3*q3)*vg_x+(2*q1*q2+2*q3*q0)*vg_y+(2*q1*q3-2*q2*q0)*vg_z")
--f.svo_debug_e_vb_y = ProtoField.none ("dji_p3_flyrec.svo_debug_e_vb_y", "E Vb Y", base.NONE, nil, nil, "(2*q1*q2-2*q3*q0)*vg_x+(1-2*q1*q1-2*q3*q3)*vg_y+(2*q2*q3+2*q1*q0)*vg_z")
--f.svo_debug_e_vb_z = ProtoField.none ("dji_p3_flyrec.svo_debug_e_vb_z", "E Vb Z", base.NONE, nil, nil, "(2*q1*q3+2*q2*q0)*vg_x+(2*q2*q3-2*q1*q0)*vg_y+(1-2*q1*q1-2*q2*q2)*vg_z")
--f.svo_debug_e_vb_norm_acc = ProtoField.none ("dji_p3_flyrec.svo_debug_e_vb_norm_acc", "E Vb Norm Acc", base.NONE, nil, nil, "sqrt(acc_x*acc_x*9.8*9.8+acc_y*acc_y*9.8*9.8)")
--f.svo_debug_e_vb_norm_vb = ProtoField.none ("dji_p3_flyrec.svo_debug_e_vb_norm_vb", "E Vb Norm Vb", base.NONE, nil, nil, "sqrt(E_vb_x^2+E_vb_y^2)")
--f.svo_debug_e_vb_x_sim = ProtoField.none ("dji_p3_flyrec.svo_debug_e_vb_x_sim", "E Vb X Sim", base.NONE, nil, nil, "(1-2*q2*q2-2*q3*q3)*vg_x_sim+(2*q1*q2+2*q3*q0)*vg_y_sim+(2*q1*q3-2*q2*q0)*vg_z_sim")
--f.svo_debug_e_vb_y_sim = ProtoField.none ("dji_p3_flyrec.svo_debug_e_vb_y_sim", "E Vb Y Sim", base.NONE, nil, nil, "(2*q1*q2-2*q3*q0)*vg_x_sim+(1-2*q1*q1-2*q3*q3)*vg_y_sim+(2*q2*q3+2*q1*q0)*vg_z_sim")
--f.svo_debug_e_vb_z_sim = ProtoField.none ("dji_p3_flyrec.svo_debug_e_vb_z_sim", "E Vb Z Sim", base.NONE, nil, nil, "(2*q1*q3+2*q2*q0)*vg_x_sim+(2*q2*q3-2*q1*q0)*vg_y_sim+(1-2*q1*q1-2*q2*q2)*vg_z_sim")
--f.svo_debug_e_vb_x_yaw_sim = ProtoField.none ("dji_p3_flyrec.svo_debug_e_vb_x_yaw_sim", "E Vb X Yaw Sim", base.NONE, nil, nil, "cos(E_yaw_rad_sim)*vg_x_sim+sin(E_yaw_rad_sim)*vg_y_sim")
--f.svo_debug_e_vb_y_yaw_sim = ProtoField.none ("dji_p3_flyrec.svo_debug_e_vb_y_yaw_sim", "E Vb Y Yaw Sim", base.NONE, nil, nil, "-sin(E_yaw_rad_sim)*vg_x_sim+cos(E_yaw_rad_sim)*vg_y_sim")
--f.svo_debug_e_ab_x = ProtoField.none ("dji_p3_flyrec.svo_debug_e_ab_x", "E Ab X", base.NONE, nil, nil, "(1-2*q2*q2-2*q3*q3)*ag_x+(2*q1*q2+2*q3*q0)*ag_y+(2*q1*q3-2*q2*q0)*ag_z")
--f.svo_debug_e_ab_y = ProtoField.none ("dji_p3_flyrec.svo_debug_e_ab_y", "E Ab Y", base.NONE, nil, nil, "(2*q1*q2-2*q3*q0)*ag_x+(1-2*q1*q1-2*q3*q3)*ag_y+(2*q2*q3+2*q1*q0)*ag_z")
--f.svo_debug_e_ab_z = ProtoField.none ("dji_p3_flyrec.svo_debug_e_ab_z", "E Ab Z", base.NONE, nil, nil, "(2*q1*q3+2*q2*q0)*ag_x+(2*q2*q3-2*q1*q0)*ag_y+(1-2*q1*q1-2*q2*q2)*ag_z")
--f.svo_debug_e_mvo_vx = ProtoField.none ("dji_p3_flyrec.svo_debug_e_mvo_vx", "E Mvo Vx", base.NONE, nil, nil, "-mvo_vx/1000")
--f.svo_debug_e_mvo_vy = ProtoField.none ("dji_p3_flyrec.svo_debug_e_mvo_vy", "E Mvo Vy", base.NONE, nil, nil, "-mvo_vy/1000")
--f.svo_debug_e_us_h_grnd = ProtoField.none ("dji_p3_flyrec.svo_debug_e_us_h_grnd", "E Us H Grnd", base.NONE, nil, nil, "us_h_grnd/1000")
--f.svo_debug_e_us_h_flag = ProtoField.none ("dji_p3_flyrec.svo_debug_e_us_h_flag", "E Us H Flag", base.NONE, nil, 0x01, "bitand(vo_flag,1)")
--f.svo_debug_e_us_v_flag = ProtoField.none ("dji_p3_flyrec.svo_debug_e_us_v_flag", "E Us V Flag", base.NONE, nil, 0x02, "bitand(shift_r(vo_flag,1),1)")
--f.svo_debug_e_vo_pos_flag = ProtoField.none ("dji_p3_flyrec.svo_debug_e_vo_pos_flag", "E Vo Pos Flag", base.NONE, nil, 0x04, "bitand(shift_r(vo_flag,2),1)")
--f.svo_debug_e_vo_vel_flag = ProtoField.none ("dji_p3_flyrec.svo_debug_e_vo_vel_flag", "E Vo Vel Flag", base.NONE, nil, 0x08, "bitand(shift_r(vo_flag,3),1)")
--f.svo_debug_e_gln_snr1 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr1", "E Gln Snr1", base.NONE, nil, 0x7f, "bitand(gln_snr1,127)")
--f.svo_debug_e_gln_snr2 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr2", "E Gln Snr2", base.NONE, nil, 0x7f, "bitand(gln_snr2,127)")
--f.svo_debug_e_gln_snr3 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr3", "E Gln Snr3", base.NONE, nil, 0x7f, "bitand(gln_snr3,127)")
--f.svo_debug_e_gln_snr4 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr4", "E Gln Snr4", base.NONE, nil, 0x7f, "bitand(gln_snr4,127)")
--f.svo_debug_e_gln_snr5 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr5", "E Gln Snr5", base.NONE, nil, 0x7f, "bitand(gln_snr5,127)")
--f.svo_debug_e_gln_snr6 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr6", "E Gln Snr6", base.NONE, nil, 0x7f, "bitand(gln_snr6,127)")
--f.svo_debug_e_gln_snr7 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr7", "E Gln Snr7", base.NONE, nil, 0x7f, "bitand(gln_snr7,127)")
--f.svo_debug_e_gln_snr8 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr8", "E Gln Snr8", base.NONE, nil, 0x7f, "bitand(gln_snr8,127)")
--f.svo_debug_e_gln_snr9 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr9", "E Gln Snr9", base.NONE, nil, 0x7f, "bitand(gln_snr9,127)")
--f.svo_debug_e_gln_snr10 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr10", "E Gln Snr10", base.NONE, nil, 0x7f, "bitand(gln_snr10,127)")
--f.svo_debug_e_gln_snr11 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr11", "E Gln Snr11", base.NONE, nil, 0x7f, "bitand(gln_snr11,127)")
--f.svo_debug_e_gln_snr12 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr12", "E Gln Snr12", base.NONE, nil, 0x7f, "bitand(gln_snr12,127)")
--f.svo_debug_e_gln_snr13 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr13", "E Gln Snr13", base.NONE, nil, 0x7f, "bitand(gln_snr13,127)")
--f.svo_debug_e_gln_snr14 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr14", "E Gln Snr14", base.NONE, nil, 0x7f, "bitand(gln_snr14,127)")
--f.svo_debug_e_gln_snr15 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr15", "E Gln Snr15", base.NONE, nil, 0x7f, "bitand(gln_snr15,127)")
--f.svo_debug_e_gln_snr16 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr16", "E Gln Snr16", base.NONE, nil, 0x7f, "bitand(gln_snr16,127)")
--f.svo_debug_e_gln_snr17 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr17", "E Gln Snr17", base.NONE, nil, 0x7f, "bitand(gln_snr17,127)")
--f.svo_debug_e_gln_snr18 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr18", "E Gln Snr18", base.NONE, nil, 0x7f, "bitand(gln_snr18,127)")
--f.svo_debug_e_gln_snr19 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr19", "E Gln Snr19", base.NONE, nil, 0x7f, "bitand(gln_snr19,127)")
--f.svo_debug_e_gln_snr20 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr20", "E Gln Snr20", base.NONE, nil, 0x7f, "bitand(gln_snr20,127)")
--f.svo_debug_e_gln_snr21 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr21", "E Gln Snr21", base.NONE, nil, 0x7f, "bitand(gln_snr21,127)")
--f.svo_debug_e_gln_snr22 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr22", "E Gln Snr22", base.NONE, nil, 0x7f, "bitand(gln_snr22,127)")
--f.svo_debug_e_gln_snr23 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr23", "E Gln Snr23", base.NONE, nil, 0x7f, "bitand(gln_snr23,127)")
--f.svo_debug_e_gln_snr24 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr24", "E Gln Snr24", base.NONE, nil, 0x7f, "bitand(gln_snr24,127)")
--f.svo_debug_e_gln_snr25 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr25", "E Gln Snr25", base.NONE, nil, 0x7f, "bitand(gln_snr25,127)")
--f.svo_debug_e_gln_snr26 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr26", "E Gln Snr26", base.NONE, nil, 0x7f, "bitand(gln_snr26,127)")
--f.svo_debug_e_gln_snr27 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr27", "E Gln Snr27", base.NONE, nil, 0x7f, "bitand(gln_snr27,127)")
--f.svo_debug_e_gln_snr28 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr28", "E Gln Snr28", base.NONE, nil, 0x7f, "bitand(gln_snr28,127)")
--f.svo_debug_e_gln_snr29 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr29", "E Gln Snr29", base.NONE, nil, 0x7f, "bitand(gln_snr29,127)")
--f.svo_debug_e_gln_snr30 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr30", "E Gln Snr30", base.NONE, nil, 0x7f, "bitand(gln_snr30,127)")
--f.svo_debug_e_gln_snr31 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr31", "E Gln Snr31", base.NONE, nil, 0x7f, "bitand(gln_snr31,127)")
--f.svo_debug_e_gln_snr32 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gln_snr32", "E Gln Snr32", base.NONE, nil, 0x7f, "bitand(gln_snr32,127)")
--f.svo_debug_e_gps_snr1 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr1", "E Gps Snr1", base.NONE, nil, 0x7f, "bitand(gps_snr1,127)")
--f.svo_debug_e_gps_snr2 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr2", "E Gps Snr2", base.NONE, nil, 0x7f, "bitand(gps_snr2,127)")
--f.svo_debug_e_gps_snr3 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr3", "E Gps Snr3", base.NONE, nil, 0x7f, "bitand(gps_snr3,127)")
--f.svo_debug_e_gps_snr4 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr4", "E Gps Snr4", base.NONE, nil, 0x7f, "bitand(gps_snr4,127)")
--f.svo_debug_e_gps_snr5 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr5", "E Gps Snr5", base.NONE, nil, 0x7f, "bitand(gps_snr5,127)")
--f.svo_debug_e_gps_snr6 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr6", "E Gps Snr6", base.NONE, nil, 0x7f, "bitand(gps_snr6,127)")
--f.svo_debug_e_gps_snr7 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr7", "E Gps Snr7", base.NONE, nil, 0x7f, "bitand(gps_snr7,127)")
--f.svo_debug_e_gps_snr8 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr8", "E Gps Snr8", base.NONE, nil, 0x7f, "bitand(gps_snr8,127)")
--f.svo_debug_e_gps_snr9 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr9", "E Gps Snr9", base.NONE, nil, 0x7f, "bitand(gps_snr9,127)")
--f.svo_debug_e_gps_snr10 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr10", "E Gps Snr10", base.NONE, nil, 0x7f, "bitand(gps_snr10,127)")
--f.svo_debug_e_gps_snr11 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr11", "E Gps Snr11", base.NONE, nil, 0x7f, "bitand(gps_snr11,127)")
--f.svo_debug_e_gps_snr12 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr12", "E Gps Snr12", base.NONE, nil, 0x7f, "bitand(gps_snr12,127)")
--f.svo_debug_e_gps_snr13 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr13", "E Gps Snr13", base.NONE, nil, 0x7f, "bitand(gps_snr13,127)")
--f.svo_debug_e_gps_snr14 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr14", "E Gps Snr14", base.NONE, nil, 0x7f, "bitand(gps_snr14,127)")
--f.svo_debug_e_gps_snr15 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr15", "E Gps Snr15", base.NONE, nil, 0x7f, "bitand(gps_snr15,127)")
--f.svo_debug_e_gps_snr16 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr16", "E Gps Snr16", base.NONE, nil, 0x7f, "bitand(gps_snr16,127)")
--f.svo_debug_e_gps_snr17 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr17", "E Gps Snr17", base.NONE, nil, 0x7f, "bitand(gps_snr17,127)")
--f.svo_debug_e_gps_snr18 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr18", "E Gps Snr18", base.NONE, nil, 0x7f, "bitand(gps_snr18,127)")
--f.svo_debug_e_gps_snr19 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr19", "E Gps Snr19", base.NONE, nil, 0x7f, "bitand(gps_snr19,127)")
--f.svo_debug_e_gps_snr20 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr20", "E Gps Snr20", base.NONE, nil, 0x7f, "bitand(gps_snr20,127)")
--f.svo_debug_e_gps_snr21 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr21", "E Gps Snr21", base.NONE, nil, 0x7f, "bitand(gps_snr21,127)")
--f.svo_debug_e_gps_snr22 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr22", "E Gps Snr22", base.NONE, nil, 0x7f, "bitand(gps_snr22,127)")
--f.svo_debug_e_gps_snr23 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr23", "E Gps Snr23", base.NONE, nil, 0x7f, "bitand(gps_snr23,127)")
--f.svo_debug_e_gps_snr24 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr24", "E Gps Snr24", base.NONE, nil, 0x7f, "bitand(gps_snr24,127)")
--f.svo_debug_e_gps_snr25 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr25", "E Gps Snr25", base.NONE, nil, 0x7f, "bitand(gps_snr25,127)")
--f.svo_debug_e_gps_snr26 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr26", "E Gps Snr26", base.NONE, nil, 0x7f, "bitand(gps_snr26,127)")
--f.svo_debug_e_gps_snr27 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr27", "E Gps Snr27", base.NONE, nil, 0x7f, "bitand(gps_snr27,127)")
--f.svo_debug_e_gps_snr28 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr28", "E Gps Snr28", base.NONE, nil, 0x7f, "bitand(gps_snr28,127)")
--f.svo_debug_e_gps_snr29 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr29", "E Gps Snr29", base.NONE, nil, 0x7f, "bitand(gps_snr29,127)")
--f.svo_debug_e_gps_snr30 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr30", "E Gps Snr30", base.NONE, nil, 0x7f, "bitand(gps_snr30,127)")
--f.svo_debug_e_gps_snr31 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr31", "E Gps Snr31", base.NONE, nil, 0x7f, "bitand(gps_snr31,127)")
--f.svo_debug_e_gps_snr32 = ProtoField.none ("dji_p3_flyrec.svo_debug_e_gps_snr32", "E Gps Snr32", base.NONE, nil, 0x7f, "bitand(gps_snr32,127)")

local function flightrec_svo_debug_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.svo_debug_visiondebug1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_debug_visiondebug2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_debug_visiondebug3, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_debug_visiondebug4, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_debug_visiondebug5, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_debug_visiondebug6, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_debug_visiondebug7, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_debug_visiondebug8, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 32) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Svo Debug: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Svo Debug: Payload size different than expected") end
end

-- Flight log - Uc Monitor - 0xcdf0

f.uc_monitor_cpu_usage = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_cpu_usage", "Cpu Usage", base.HEX)
f.uc_monitor_cpu_usage_task_b = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_cpu_usage_task_b", "Cpu Usage Task B", base.HEX)
f.uc_monitor_cpu_usage_task_a = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_cpu_usage_task_a", "Cpu Usage Task A", base.HEX)
f.uc_monitor_uc_resv0 = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_uc_resv0", "Uc Resv0", base.HEX)
f.uc_monitor_max_time_workqueue = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_max_time_workqueue", "Max Time Workqueue", base.HEX)
f.uc_monitor_max_time_task_b = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_max_time_task_b", "Max Time Task B", base.HEX)
f.uc_monitor_max_time_task_a = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_max_time_task_a", "Max Time Task A", base.HEX)
f.uc_monitor_max_time_task_c = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_max_time_task_c", "Max Time Task C", base.HEX)
f.uc_monitor_max_time_task_d = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_max_time_task_d", "Max Time Task D", base.HEX)
f.uc_monitor_uc_resv1 = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_uc_resv1", "Uc Resv1", base.HEX)
f.uc_monitor_stack_usage_irq = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_stack_usage_irq", "Stack Usage Irq", base.HEX)
f.uc_monitor_stack_usage_workqueue = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_stack_usage_workqueue", "Stack Usage Workqueue", base.HEX)
f.uc_monitor_stack_usage_b = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_stack_usage_b", "Stack Usage B", base.HEX)
f.uc_monitor_stack_usage_a = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_stack_usage_a", "Stack Usage A", base.HEX)
f.uc_monitor_stack_usage_c = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_stack_usage_c", "Stack Usage C", base.HEX)
f.uc_monitor_stack_usage_d = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_stack_usage_d", "Stack Usage D", base.HEX)
f.uc_monitor_uc_resv2 = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_uc_resv2", "Uc Resv2", base.HEX)
f.uc_monitor_pend_cnt_a = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_pend_cnt_a", "Pend Cnt A", base.HEX)
f.uc_monitor_pend_cnt_b = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_pend_cnt_b", "Pend Cnt B", base.HEX)
f.uc_monitor_pend_cnt_c = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_pend_cnt_c", "Pend Cnt C", base.HEX)
f.uc_monitor_pend_cnt_d = ProtoField.uint16 ("dji_p3_flyrec.uc_monitor_pend_cnt_d", "Pend Cnt D", base.HEX)

local function flightrec_uc_monitor_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.uc_monitor_cpu_usage, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_cpu_usage_task_b, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_cpu_usage_task_a, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_uc_resv0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_max_time_workqueue, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_max_time_task_b, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_max_time_task_a, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_max_time_task_c, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_max_time_task_d, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_uc_resv1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_stack_usage_irq, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_stack_usage_workqueue, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_stack_usage_b, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_stack_usage_a, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_stack_usage_c, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_stack_usage_d, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_uc_resv2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_pend_cnt_a, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_pend_cnt_b, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_pend_cnt_c, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uc_monitor_pend_cnt_d, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 42) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Uc Monitor: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Uc Monitor: Payload size different than expected") end
end

-- Flight log - Rc Delay - 0xcdff

f.rc_delay_dly_ns = ProtoField.uint32 ("dji_p3_flyrec.rc_delay_dly_ns", "Dly Ns", base.HEX)

local function flightrec_rc_delay_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.rc_delay_dly_ns, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Rc Delay: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Rc Delay: Payload size different than expected") end
end

-- Flight log - Taskb Info - 0xce02

f.taskb_info_period_jitter0 = ProtoField.int32 ("dji_p3_flyrec.taskb_info_period_jitter0", "Period Jitter0", base.DEC)
f.taskb_info_exec_time0 = ProtoField.uint16 ("dji_p3_flyrec.taskb_info_exec_time0", "Exec Time0", base.HEX)
f.taskb_info_pending0 = ProtoField.uint16 ("dji_p3_flyrec.taskb_info_pending0", "Pending0", base.HEX)

local function flightrec_taskb_info_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.taskb_info_period_jitter0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.taskb_info_exec_time0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.taskb_info_pending0, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Taskb Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Taskb Info: Payload size different than expected") end
end

-- Flight log - Taska Info - 0xce06

f.taska_info_period_jitter1 = ProtoField.int32 ("dji_p3_flyrec.taska_info_period_jitter1", "Period Jitter1", base.DEC)
f.taska_info_exec_time1 = ProtoField.uint16 ("dji_p3_flyrec.taska_info_exec_time1", "Exec Time1", base.HEX)
f.taska_info_pending1 = ProtoField.uint16 ("dji_p3_flyrec.taska_info_pending1", "Pending1", base.HEX)

local function flightrec_taska_info_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.taska_info_period_jitter1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.taska_info_exec_time1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.taska_info_pending1, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Taska Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Taska Info: Payload size different than expected") end
end

-- Flight log - Taskc Info - 0xce08

f.taskc_info_period_jitter2 = ProtoField.int32 ("dji_p3_flyrec.taskc_info_period_jitter2", "Period Jitter2", base.DEC)
f.taskc_info_exec_time2 = ProtoField.uint16 ("dji_p3_flyrec.taskc_info_exec_time2", "Exec Time2", base.HEX)
f.taskc_info_pending2 = ProtoField.uint16 ("dji_p3_flyrec.taskc_info_pending2", "Pending2", base.HEX)

local function flightrec_taskc_info_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.taskc_info_period_jitter2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.taskc_info_exec_time2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.taskc_info_pending2, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Taskc Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Taskc Info: Payload size different than expected") end
end

-- Flight log - Taskd Info - 0xce09

f.taskd_info_period_jitter3 = ProtoField.int32 ("dji_p3_flyrec.taskd_info_period_jitter3", "Period Jitter3", base.DEC)
f.taskd_info_exec_time3 = ProtoField.uint16 ("dji_p3_flyrec.taskd_info_exec_time3", "Exec Time3", base.HEX)
f.taskd_info_pending3 = ProtoField.uint16 ("dji_p3_flyrec.taskd_info_pending3", "Pending3", base.HEX)

local function flightrec_taskd_info_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.taskd_info_period_jitter3, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.taskd_info_exec_time3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.taskd_info_pending3, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Taskd Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Taskd Info: Payload size different than expected") end
end

-- Flight log - Rc Replay - 0xcdf6

f.rc_replay_cmd_alieron = ProtoField.int16 ("dji_p3_flyrec.rc_replay_cmd_alieron", "Cmd Alieron", base.DEC)
f.rc_replay_cmd_elevator = ProtoField.int16 ("dji_p3_flyrec.rc_replay_cmd_elevator", "Cmd Elevator", base.DEC)
f.rc_replay_cmd_throttle = ProtoField.int16 ("dji_p3_flyrec.rc_replay_cmd_throttle", "Cmd Throttle", base.DEC)
f.rc_replay_cmd_rudder = ProtoField.int16 ("dji_p3_flyrec.rc_replay_cmd_rudder", "Cmd Rudder", base.DEC)
f.rc_replay_cmd_mode = ProtoField.int16 ("dji_p3_flyrec.rc_replay_cmd_mode", "Cmd Mode", base.DEC)
f.rc_replay_cmd_ioc = ProtoField.int16 ("dji_p3_flyrec.rc_replay_cmd_ioc", "Cmd Ioc", base.DEC)
f.rc_replay_cmd_go_home = ProtoField.int16 ("dji_p3_flyrec.rc_replay_cmd_go_home", "Cmd Go Home", base.DEC)
f.rc_replay_cmd_d4 = ProtoField.int16 ("dji_p3_flyrec.rc_replay_cmd_d4", "Cmd D4", base.DEC)

local function flightrec_rc_replay_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.rc_replay_cmd_alieron, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_replay_cmd_elevator, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_replay_cmd_throttle, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_replay_cmd_rudder, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_replay_cmd_mode, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_replay_cmd_ioc, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_replay_cmd_go_home, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_replay_cmd_d4, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 16) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Rc Replay: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Rc Replay: Payload size different than expected") end
end

-- Flight log - Escm - 0xcdf1

f.escm_esc1_status = ProtoField.uint8 ("dji_p3_flyrec.escm_esc1_status", "Esc1 Status", base.HEX)
f.escm_esc1_current = ProtoField.int16 ("dji_p3_flyrec.escm_esc1_current", "Esc1 Current", base.DEC)
f.escm_esc1_speed = ProtoField.int16 ("dji_p3_flyrec.escm_esc1_speed", "Esc1 Speed", base.DEC)
f.escm_esc1_voltage = ProtoField.int16 ("dji_p3_flyrec.escm_esc1_voltage", "Esc1 Voltage", base.DEC)
f.escm_esc1_temperature = ProtoField.int16 ("dji_p3_flyrec.escm_esc1_temperature", "Esc1 Temperature", base.DEC)
f.escm_esc1_ppm_recv = ProtoField.int16 ("dji_p3_flyrec.escm_esc1_ppm_recv", "Esc1 Ppm Recv", base.DEC)
f.escm_esc1_v_out = ProtoField.int16 ("dji_p3_flyrec.escm_esc1_v_out", "Esc1 V Out", base.DEC)
f.escm_esc1_debug0 = ProtoField.int16 ("dji_p3_flyrec.escm_esc1_debug0", "Esc1 Debug0", base.DEC)
f.escm_esc1_debug1 = ProtoField.int16 ("dji_p3_flyrec.escm_esc1_debug1", "Esc1 Debug1", base.DEC)
f.escm_esc1_debug2 = ProtoField.int16 ("dji_p3_flyrec.escm_esc1_debug2", "Esc1 Debug2", base.DEC)
f.escm_esc2_status = ProtoField.uint8 ("dji_p3_flyrec.escm_esc2_status", "Esc2 Status", base.HEX)
f.escm_esc2_current = ProtoField.int16 ("dji_p3_flyrec.escm_esc2_current", "Esc2 Current", base.DEC)
f.escm_esc2_speed = ProtoField.int16 ("dji_p3_flyrec.escm_esc2_speed", "Esc2 Speed", base.DEC)
f.escm_esc2_voltage = ProtoField.int16 ("dji_p3_flyrec.escm_esc2_voltage", "Esc2 Voltage", base.DEC)
f.escm_esc2_temperature = ProtoField.int16 ("dji_p3_flyrec.escm_esc2_temperature", "Esc2 Temperature", base.DEC)
f.escm_esc2_ppm_recv = ProtoField.int16 ("dji_p3_flyrec.escm_esc2_ppm_recv", "Esc2 Ppm Recv", base.DEC)
f.escm_esc2_v_out = ProtoField.int16 ("dji_p3_flyrec.escm_esc2_v_out", "Esc2 V Out", base.DEC)
f.escm_esc2_debug0 = ProtoField.int16 ("dji_p3_flyrec.escm_esc2_debug0", "Esc2 Debug0", base.DEC)
f.escm_esc2_debug1 = ProtoField.int16 ("dji_p3_flyrec.escm_esc2_debug1", "Esc2 Debug1", base.DEC)
f.escm_esc2_debug2 = ProtoField.int16 ("dji_p3_flyrec.escm_esc2_debug2", "Esc2 Debug2", base.DEC)
f.escm_esc3_status = ProtoField.uint8 ("dji_p3_flyrec.escm_esc3_status", "Esc3 Status", base.HEX)
f.escm_esc3_current = ProtoField.int16 ("dji_p3_flyrec.escm_esc3_current", "Esc3 Current", base.DEC)
f.escm_esc3_speed = ProtoField.int16 ("dji_p3_flyrec.escm_esc3_speed", "Esc3 Speed", base.DEC)
f.escm_esc3_voltage = ProtoField.int16 ("dji_p3_flyrec.escm_esc3_voltage", "Esc3 Voltage", base.DEC)
f.escm_esc3_temperature = ProtoField.int16 ("dji_p3_flyrec.escm_esc3_temperature", "Esc3 Temperature", base.DEC)
f.escm_esc3_ppm_recv = ProtoField.int16 ("dji_p3_flyrec.escm_esc3_ppm_recv", "Esc3 Ppm Recv", base.DEC)
f.escm_esc3_v_out = ProtoField.int16 ("dji_p3_flyrec.escm_esc3_v_out", "Esc3 V Out", base.DEC)
f.escm_esc3_debug0 = ProtoField.int16 ("dji_p3_flyrec.escm_esc3_debug0", "Esc3 Debug0", base.DEC)
f.escm_esc3_debug1 = ProtoField.int16 ("dji_p3_flyrec.escm_esc3_debug1", "Esc3 Debug1", base.DEC)
f.escm_esc3_debug2 = ProtoField.int16 ("dji_p3_flyrec.escm_esc3_debug2", "Esc3 Debug2", base.DEC)
f.escm_esc4_status = ProtoField.uint8 ("dji_p3_flyrec.escm_esc4_status", "Esc4 Status", base.HEX)
f.escm_esc4_current = ProtoField.int16 ("dji_p3_flyrec.escm_esc4_current", "Esc4 Current", base.DEC)
f.escm_esc4_speed = ProtoField.int16 ("dji_p3_flyrec.escm_esc4_speed", "Esc4 Speed", base.DEC)
f.escm_esc4_voltage = ProtoField.int16 ("dji_p3_flyrec.escm_esc4_voltage", "Esc4 Voltage", base.DEC)
f.escm_esc4_temperature = ProtoField.int16 ("dji_p3_flyrec.escm_esc4_temperature", "Esc4 Temperature", base.DEC)
f.escm_esc4_ppm_recv = ProtoField.int16 ("dji_p3_flyrec.escm_esc4_ppm_recv", "Esc4 Ppm Recv", base.DEC)
f.escm_esc4_v_out = ProtoField.int16 ("dji_p3_flyrec.escm_esc4_v_out", "Esc4 V Out", base.DEC)
f.escm_esc4_debug0 = ProtoField.int16 ("dji_p3_flyrec.escm_esc4_debug0", "Esc4 Debug0", base.DEC)
f.escm_esc4_debug1 = ProtoField.int16 ("dji_p3_flyrec.escm_esc4_debug1", "Esc4 Debug1", base.DEC)
f.escm_esc4_debug2 = ProtoField.int16 ("dji_p3_flyrec.escm_esc4_debug2", "Esc4 Debug2", base.DEC)

local function flightrec_escm_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.escm_esc1_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.escm_esc1_current, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc1_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc1_voltage, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc1_temperature, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc1_ppm_recv, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc1_v_out, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc1_debug0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc1_debug1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc1_debug2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc2_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.escm_esc2_current, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc2_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc2_voltage, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc2_temperature, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc2_ppm_recv, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc2_v_out, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc2_debug0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc2_debug1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc2_debug2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc3_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.escm_esc3_current, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc3_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc3_voltage, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc3_temperature, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc3_ppm_recv, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc3_v_out, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc3_debug0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc3_debug1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc3_debug2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc4_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.escm_esc4_current, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc4_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc4_voltage, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc4_temperature, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc4_ppm_recv, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc4_v_out, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc4_debug0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc4_debug1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.escm_esc4_debug2, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 76) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Escm: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Escm: Payload size different than expected") end
end

-- Flight log - Sweep - 0xcdf2

f.sweep_ppm = ProtoField.uint16 ("dji_p3_flyrec.sweep_ppm", "Ppm", base.HEX)

local function flightrec_sweep_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.sweep_ppm, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Sweep: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Sweep: Payload size different than expected") end
end

-- Flight log - Mvo - 0x000e

f.mvo_mvo_px = ProtoField.float ("dji_p3_flyrec.mvo_mvo_px", "Mvo Px", base.DEC)
f.mvo_mvo_py = ProtoField.float ("dji_p3_flyrec.mvo_mvo_py", "Mvo Py", base.DEC)
f.mvo_mvo_pz = ProtoField.float ("dji_p3_flyrec.mvo_mvo_pz", "Mvo Pz", base.DEC)
f.mvo_mvo_vx = ProtoField.int16 ("dji_p3_flyrec.mvo_mvo_vx", "Mvo Vx", base.DEC)
f.mvo_mvo_vy = ProtoField.int16 ("dji_p3_flyrec.mvo_mvo_vy", "Mvo Vy", base.DEC)
f.mvo_mvo_vz = ProtoField.int16 ("dji_p3_flyrec.mvo_mvo_vz", "Mvo Vz", base.DEC)
f.mvo_mvo_cnt = ProtoField.uint8 ("dji_p3_flyrec.mvo_mvo_cnt", "Mvo Cnt", base.HEX)
f.mvo_mvo_flag = ProtoField.uint8 ("dji_p3_flyrec.mvo_mvo_flag", "Mvo Flag", base.HEX)
  f.mvo_e_mvo_px_flag = ProtoField.uint8 ("dji_p3_flyrec.mvo_e_mvo_px_flag", "E Mvo Px Flag", base.HEX, nil, 0x10, nil)
  f.mvo_e_mvo_py_flag = ProtoField.uint8 ("dji_p3_flyrec.mvo_e_mvo_py_flag", "E Mvo Py Flag", base.HEX, nil, 0x20, nil)
  f.mvo_e_mvo_pz_flag = ProtoField.uint8 ("dji_p3_flyrec.mvo_e_mvo_pz_flag", "E Mvo Pz Flag", base.HEX, nil, 0x40, "Vision height valid flag; 0=not valid, 1=valid")
  f.mvo_e_mvo_vx_flag = ProtoField.uint8 ("dji_p3_flyrec.mvo_e_mvo_vx_flag", "E Mvo Vx Flag", base.HEX, nil, 0x01, nil)
  f.mvo_e_mvo_vy_flag = ProtoField.uint8 ("dji_p3_flyrec.mvo_e_mvo_vy_flag", "E Mvo Vy Flag", base.HEX, nil, 0x02, nil)
  f.mvo_e_mvo_vz_flag = ProtoField.uint8 ("dji_p3_flyrec.mvo_e_mvo_vz_flag", "E Mvo Vz Flag", base.HEX, nil, 0x04, nil)

local function flightrec_mvo_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.mvo_mvo_px, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.mvo_mvo_py, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.mvo_mvo_pz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.mvo_mvo_vx, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.mvo_mvo_vy, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.mvo_mvo_vz, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.mvo_mvo_cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mvo_mvo_flag, payload(offset, 1))
    subtree:add_le (f.mvo_e_mvo_px_flag, payload(offset, 1))
    subtree:add_le (f.mvo_e_mvo_py_flag, payload(offset, 1))
    subtree:add_le (f.mvo_e_mvo_pz_flag, payload(offset, 1))
    subtree:add_le (f.mvo_e_mvo_vx_flag, payload(offset, 1))
    subtree:add_le (f.mvo_e_mvo_vy_flag, payload(offset, 1))
    subtree:add_le (f.mvo_e_mvo_vz_flag, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Mvo: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Mvo: Payload size different than expected") end
end

-- Flight log - Usonic - 0x0010

f.usonic_usonic_h = ProtoField.int16 ("dji_p3_flyrec.usonic_usonic_h", "Usonic H", base.DEC, nil, nil, "Ultrasonic sensor measurement; unit:mm")
f.usonic_usonic_flag = ProtoField.uint8 ("dji_p3_flyrec.usonic_usonic_flag", "Usonic Flag", base.HEX)
  f.usonic_e_us_flag_old = ProtoField.uint8 ("dji_p3_flyrec.usonic_e_us_flag_old", "E Us Flag Old", base.HEX, nil, 0x01, "Ultrasonic sensor valid flag; 0=not valid, 1=valid")
f.usonic_usonic_cnt = ProtoField.uint8 ("dji_p3_flyrec.usonic_usonic_cnt", "Usonic Cnt", base.HEX)

local function flightrec_usonic_dissector(payload, pinfo, subtree)
    local offset = 0
    local info_str = ""

    subtree:add_le (f.usonic_usonic_h, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.usonic_usonic_flag, payload(offset, 1))
    subtree:add_le (f.usonic_e_us_flag_old, payload(offset, 1))
    offset = offset + 1

    local rec_usonic_usonic_cnt = payload(offset, 1)
    subtree:add_le (f.usonic_usonic_cnt, rec_usonic_usonic_cnt)
    offset = offset + 1

    --pinfo.cols.info = info_str

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Usonic: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Usonic: Payload size different than expected") end
end

-- Flight log - Console - 0xcdef

f.console_text = ProtoField.string ("dji_p3_flyrec.console_text", "Console", base.ASCII)

local function flightrec_console_dissector(payload, pinfo, subtree)
    local offset = 0

    local rec_console_text = payload(offset, payload:len() - offset)
    subtree:add (f.console_text, rec_console_text)

    pinfo.cols.info = rec_console_text:string():gsub('[^a-zA-Z0-9_:,.[[]]/\\ \t-]','')
end

-- Flight log - Syscfg - 0xffff

f.syscfg_text = ProtoField.string ("dji_p3_flyrec.syscfg_text", "Syscfg", base.ASCII)

local function flightrec_syscfg_dissector(payload, pinfo, subtree)
    local offset = 0

    local rec_syscfg_text = payload(offset, payload:len() - offset)
    subtree:add (f.syscfg_text, rec_syscfg_text)

    pinfo.cols.info = rec_syscfg_text:string():gsub('[^a-zA-Z0-9_:,.[[]]/\\ \t-]','')
end

-- Flight log - Battery Info - 0x0011

f.battery_info_design_capacity = ProtoField.uint16 ("dji_p3_flyrec.battery_info_design_capacity", "Design Capacity", base.DEC)
f.battery_info_full_charge_capacity = ProtoField.uint16 ("dji_p3_flyrec.battery_info_full_charge_capacity", "Full Charge Capacity", base.DEC)
f.battery_info_remaining_capacity = ProtoField.uint16 ("dji_p3_flyrec.battery_info_remaining_capacity", "Remaining Capacity", base.DEC)
f.battery_info_pack_voltage = ProtoField.uint16 ("dji_p3_flyrec.battery_info_pack_voltage", "Pack Voltage", base.DEC)
f.battery_info_current = ProtoField.int16 ("dji_p3_flyrec.battery_info_current", "Current", base.DEC)
f.battery_info_life_percentage = ProtoField.uint8 ("dji_p3_flyrec.battery_info_life_percentage", "Life Percentage", base.DEC)
f.battery_info_capacity_percentage = ProtoField.uint8 ("dji_p3_flyrec.battery_info_capacity_percentage", "Capacity Percentage", base.DEC)
f.battery_info_temperature = ProtoField.int16 ("dji_p3_flyrec.battery_info_temperature", "Temperature", base.DEC)
f.battery_info_cycle_count = ProtoField.uint16 ("dji_p3_flyrec.battery_info_cycle_count", "Cycle Count", base.DEC)
f.battery_info_serial_number = ProtoField.uint16 ("dji_p3_flyrec.battery_info_serial_number", "Serial Number", base.HEX)
f.battery_info_cell1 = ProtoField.uint16 ("dji_p3_flyrec.battery_info_cell1", "Cell1 Voltage", base.DEC)
f.battery_info_cell2 = ProtoField.uint16 ("dji_p3_flyrec.battery_info_cell2", "Cell2 Voltage", base.DEC)
f.battery_info_cell3 = ProtoField.uint16 ("dji_p3_flyrec.battery_info_cell3", "Cell3 Voltage", base.DEC)
f.battery_info_cell4 = ProtoField.uint16 ("dji_p3_flyrec.battery_info_cell4", "Cell4 Voltage", base.DEC)
f.battery_info_cell5 = ProtoField.uint16 ("dji_p3_flyrec.battery_info_cell5", "Cell5 Voltage", base.DEC)
f.battery_info_cell6 = ProtoField.uint16 ("dji_p3_flyrec.battery_info_cell6", "Cell6 Voltage", base.DEC)
f.battery_info_average_current = ProtoField.int16 ("dji_p3_flyrec.battery_info_average_current", "Average Current", base.DEC)
f.battery_info_right = ProtoField.uint8 ("dji_p3_flyrec.battery_info_right", "Right", base.HEX)
f.battery_info_error_count = ProtoField.uint32 ("dji_p3_flyrec.battery_info_error_count", "Error Count", base.DEC) -- possible that only lower 8 bits store error count
f.battery_info_n_discharge_times = ProtoField.uint32 ("dji_p3_flyrec.battery_info_n_discharge_times", "N Discharge Times", base.DEC)
f.battery_info_current_status = ProtoField.uint32 ("dji_p3_flyrec.battery_info_current_status", "Current Status", base.HEX)
--f.battery_info_vol_main = ProtoField.uint16 ("dji_p3_flyrec.battery_info_vol_main", "Vol Main", base.HEX)

local function flightrec_battery_info_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.battery_info_design_capacity, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_full_charge_capacity, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_remaining_capacity, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_pack_voltage, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_current, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_life_percentage, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_info_capacity_percentage, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_info_temperature, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_cycle_count, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_serial_number, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_cell1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_cell2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_cell3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_cell4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_cell5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_cell6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_average_current, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_right, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_info_error_count, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_n_discharge_times, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_current_status, payload(offset, 4))
    offset = offset + 4

    --subtree:add_le (f.battery_info_vol_main, payload(offset, 2))
    --offset = offset + 2

    if (offset ~= 45) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Battery Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Battery Info: Payload size different than expected") end
end

-- Flight log - Special Cmd - 0x0017

f.special_cmd_byte1 = ProtoField.uint8 ("dji_p3_flyrec.special_cmd_byte1", "Byte1", base.HEX)
f.special_cmd_byte2 = ProtoField.uint8 ("dji_p3_flyrec.special_cmd_byte2", "Byte2", base.HEX)
f.special_cmd_word1 = ProtoField.uint16 ("dji_p3_flyrec.special_cmd_word1", "Word1", base.HEX)
f.special_cmd_byte3 = ProtoField.uint8 ("dji_p3_flyrec.special_cmd_byte3", "Byte3", base.HEX)
f.special_cmd_ctrl_action = ProtoField.uint8 ("dji_p3_flyrec.special_cmd_ctrl_action", "Ctrl Action", base.HEX)
f.special_cmd_byte4 = ProtoField.uint8 ("dji_p3_flyrec.special_cmd_byte4", "Byte4", base.HEX)
f.special_cmd_byte5 = ProtoField.uint8 ("dji_p3_flyrec.special_cmd_byte5", "Byte5", base.HEX)
f.special_cmd_byte6 = ProtoField.uint8 ("dji_p3_flyrec.special_cmd_byte6", "Byte6", base.HEX)
f.special_cmd_byte7 = ProtoField.uint8 ("dji_p3_flyrec.special_cmd_byte7", "Byte7", base.HEX)

local function flightrec_special_cmd_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.special_cmd_byte1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.special_cmd_byte2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.special_cmd_word1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.special_cmd_byte3, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.special_cmd_ctrl_action, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.special_cmd_byte4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.special_cmd_byte5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.special_cmd_byte6, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.special_cmd_byte7, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 10) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Special Cmd: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Special Cmd: Payload size different than expected") end
end

-- Flight log - Serial Api Inputs - 0x003c

f.serial_api_inputs_user_req_ctrl_flag = ProtoField.uint8 ("dji_p3_flyrec.serial_api_inputs_user_req_ctrl_flag", "User Req Ctrl Flag", base.HEX)
f.serial_api_inputs_user_req_roll_or_x = ProtoField.float ("dji_p3_flyrec.serial_api_inputs_user_req_roll_or_x", "User Req Roll Or X", base.DEC)
f.serial_api_inputs_user_req_pitch_or_y = ProtoField.float ("dji_p3_flyrec.serial_api_inputs_user_req_pitch_or_y", "User Req Pitch Or Y", base.DEC)
f.serial_api_inputs_user_req_thr_z = ProtoField.float ("dji_p3_flyrec.serial_api_inputs_user_req_thr_z", "User Req Thr Z", base.DEC)
f.serial_api_inputs_user_req_yaw = ProtoField.float ("dji_p3_flyrec.serial_api_inputs_user_req_yaw", "User Req Yaw", base.DEC)
f.serial_api_inputs_nav_cur_dev = ProtoField.uint8 ("dji_p3_flyrec.serial_api_inputs_nav_cur_dev", "Nav Cur Dev", base.HEX)
f.serial_api_inputs_api_cur_sub_mode = ProtoField.uint8 ("dji_p3_flyrec.serial_api_inputs_api_cur_sub_mode", "Api Cur Sub Mode", base.HEX)
f.serial_api_inputs_api_user_ctrl_data_health = ProtoField.uint8 ("dji_p3_flyrec.serial_api_inputs_api_user_ctrl_data_health", "Api User Ctrl Data Health", base.HEX)
f.serial_api_inputs_api_app_ctrl_data_health = ProtoField.uint8 ("dji_p3_flyrec.serial_api_inputs_api_app_ctrl_data_health", "Api App Ctrl Data Health", base.HEX)
f.serial_api_inputs_user_open_close_req = ProtoField.uint8 ("dji_p3_flyrec.serial_api_inputs_user_open_close_req", "User Open Close Req", base.HEX)
f.serial_api_inputs_user_open_close_ack = ProtoField.uint8 ("dji_p3_flyrec.serial_api_inputs_user_open_close_ack", "User Open Close Ack", base.HEX)
f.serial_api_inputs_user_flight_cmd_req = ProtoField.uint8 ("dji_p3_flyrec.serial_api_inputs_user_flight_cmd_req", "User Flight Cmd Req", base.HEX)
f.serial_api_inputs_user_flight_cmd_ack = ProtoField.uint8 ("dji_p3_flyrec.serial_api_inputs_user_flight_cmd_ack", "User Flight Cmd Ack", base.HEX)

local function flightrec_serial_api_inputs_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.serial_api_inputs_user_req_ctrl_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_user_req_roll_or_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.serial_api_inputs_user_req_pitch_or_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.serial_api_inputs_user_req_thr_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.serial_api_inputs_user_req_yaw, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.serial_api_inputs_nav_cur_dev, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_api_cur_sub_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_api_user_ctrl_data_health, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_api_app_ctrl_data_health, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_user_open_close_req, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_user_open_close_ack, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_user_flight_cmd_req, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_user_flight_cmd_ack, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 25) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Serial Api Inputs: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Serial Api Inputs: Payload size different than expected") end
end

-- Flight log - Ctrl Vert - 0x0032

f.ctrl_vert_vert_module_module_mode = ProtoField.uint8 ("dji_p3_flyrec.ctrl_vert_vert_module_module_mode", "Vert Module Module Mode", base.HEX)
f.ctrl_vert_vert_module_vert_hover_state = ProtoField.uint8 ("dji_p3_flyrec.ctrl_vert_vert_module_vert_hover_state", "Vert Module Vert Hover State", base.HEX)
f.ctrl_vert_vert_module_vert_hover_enable = ProtoField.uint8 ("dji_p3_flyrec.ctrl_vert_vert_module_vert_hover_enable", "Vert Module Vert Hover Enable", base.HEX)
f.ctrl_vert_vert_module_vert_hover_pos = ProtoField.float ("dji_p3_flyrec.ctrl_vert_vert_module_vert_hover_pos", "Vert Module Vert Hover Pos", base.DEC)
f.ctrl_vert_vert_module_vert_hover_brake_timer = ProtoField.float ("dji_p3_flyrec.ctrl_vert_vert_module_vert_hover_brake_timer", "Vert Module Vert Hover Brake Timer", base.DEC)
f.ctrl_vert_vert_module_take_off_thrust = ProtoField.float ("dji_p3_flyrec.ctrl_vert_vert_module_take_off_thrust", "Vert Module Take Off Thrust", base.DEC)
f.ctrl_vert_vert_module_auto_take_off_state = ProtoField.uint8 ("dji_p3_flyrec.ctrl_vert_vert_module_auto_take_off_state", "Vert Module Auto Take Off State", base.HEX)
f.ctrl_vert_vert_module_auto_take_off_height = ProtoField.float ("dji_p3_flyrec.ctrl_vert_vert_module_auto_take_off_height", "Vert Module Auto Take Off Height", base.DEC)
f.ctrl_vert_api_vert_ctrl_mode = ProtoField.uint8 ("dji_p3_flyrec.ctrl_vert_api_vert_ctrl_mode", "Api Vert Ctrl Mode", base.HEX)
f.ctrl_vert_api_vert_ctrl_cmd_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_vert_api_vert_ctrl_cmd_id", "Api Vert Ctrl Cmd Id", base.HEX)
f.ctrl_vert_vert_pos_status = ProtoField.uint8 ("dji_p3_flyrec.ctrl_vert_vert_pos_status", "Vert Pos Status", base.HEX)
f.ctrl_vert_vert_pos_cmd_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_vert_vert_pos_cmd_id", "Vert Pos Cmd Id", base.HEX)
f.ctrl_vert_vert_pos_feedback_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_vert_vert_pos_feedback_id", "Vert Pos Feedback Id", base.HEX)
f.ctrl_vert_vert_pos_cmd = ProtoField.int16 ("dji_p3_flyrec.ctrl_vert_vert_pos_cmd", "Vert Pos Cmd", base.DEC)
f.ctrl_vert_vert_pos_feedback = ProtoField.int16 ("dji_p3_flyrec.ctrl_vert_vert_pos_feedback", "Vert Pos Feedback", base.DEC)
f.ctrl_vert_vert_pos_p_ctrl = ProtoField.int16 ("dji_p3_flyrec.ctrl_vert_vert_pos_p_ctrl", "Vert Pos P Ctrl", base.DEC)
f.ctrl_vert_vert_pos_output = ProtoField.int16 ("dji_p3_flyrec.ctrl_vert_vert_pos_output", "Vert Pos Output", base.DEC)
f.ctrl_vert_vert_vel_status = ProtoField.uint8 ("dji_p3_flyrec.ctrl_vert_vert_vel_status", "Vert Vel Status", base.HEX)
f.ctrl_vert_vert_vel_cmd_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_vert_vert_vel_cmd_id", "Vert Vel Cmd Id", base.HEX)
f.ctrl_vert_vert_vel_feedback_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_vert_vert_vel_feedback_id", "Vert Vel Feedback Id", base.HEX)
f.ctrl_vert_vert_vel_cmd = ProtoField.int16 ("dji_p3_flyrec.ctrl_vert_vert_vel_cmd", "Vert Vel Cmd", base.DEC)
f.ctrl_vert_vert_vel_cmd_before_limit = ProtoField.int16 ("dji_p3_flyrec.ctrl_vert_vert_vel_cmd_before_limit", "Vert Vel Cmd Before Limit", base.DEC)
f.ctrl_vert_vert_vel_cmd_after_limit = ProtoField.int16 ("dji_p3_flyrec.ctrl_vert_vert_vel_cmd_after_limit", "Vert Vel Cmd After Limit", base.DEC)
f.ctrl_vert_vert_vel_feedback = ProtoField.int16 ("dji_p3_flyrec.ctrl_vert_vert_vel_feedback", "Vert Vel Feedback", base.DEC)
f.ctrl_vert_vert_vel_p_ctrl = ProtoField.int16 ("dji_p3_flyrec.ctrl_vert_vert_vel_p_ctrl", "Vert Vel P Ctrl", base.DEC)
f.ctrl_vert_vert_vel_output = ProtoField.int16 ("dji_p3_flyrec.ctrl_vert_vert_vel_output", "Vert Vel Output", base.DEC)
f.ctrl_vert_vert_acc_status = ProtoField.uint8 ("dji_p3_flyrec.ctrl_vert_vert_acc_status", "Vert Acc Status", base.HEX)
f.ctrl_vert_vert_acc_cmd_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_vert_vert_acc_cmd_id", "Vert Acc Cmd Id", base.HEX)
f.ctrl_vert_vert_acc_feedback_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_vert_vert_acc_feedback_id", "Vert Acc Feedback Id", base.HEX)
f.ctrl_vert_vert_acc_cmd = ProtoField.int16 ("dji_p3_flyrec.ctrl_vert_vert_acc_cmd", "Vert Acc Cmd", base.DEC)
f.ctrl_vert_vert_acc_feedback = ProtoField.int16 ("dji_p3_flyrec.ctrl_vert_vert_acc_feedback", "Vert Acc Feedback", base.DEC)
f.ctrl_vert_vert_acc_p_ctrl = ProtoField.int16 ("dji_p3_flyrec.ctrl_vert_vert_acc_p_ctrl", "Vert Acc P Ctrl", base.DEC)
f.ctrl_vert_vert_acc_i_ctrl = ProtoField.int16 ("dji_p3_flyrec.ctrl_vert_vert_acc_i_ctrl", "Vert Acc I Ctrl", base.DEC)
f.ctrl_vert_vert_acc_feedforward = ProtoField.int16 ("dji_p3_flyrec.ctrl_vert_vert_acc_feedforward", "Vert Acc Feedforward", base.DEC)
f.ctrl_vert_vert_acc_output = ProtoField.int16 ("dji_p3_flyrec.ctrl_vert_vert_acc_output", "Vert Acc Output", base.DEC)
f.ctrl_vert_vert_thrust_status = ProtoField.uint8 ("dji_p3_flyrec.ctrl_vert_vert_thrust_status", "Vert Thrust Status", base.HEX)
f.ctrl_vert_vert_thrust_cmd_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_vert_vert_thrust_cmd_id", "Vert Thrust Cmd Id", base.HEX)
f.ctrl_vert_vert_thrust_feedback_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_vert_vert_thrust_feedback_id", "Vert Thrust Feedback Id", base.HEX)
f.ctrl_vert_vert_thrust_cmd_data = ProtoField.int16 ("dji_p3_flyrec.ctrl_vert_vert_thrust_cmd_data", "Vert Thrust Cmd Data", base.DEC)

local function flightrec_ctrl_vert_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ctrl_vert_vert_module_module_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_vert_module_vert_hover_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_vert_module_vert_hover_enable, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_vert_module_vert_hover_pos, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_vert_vert_module_vert_hover_brake_timer, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_vert_vert_module_take_off_thrust, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_vert_vert_module_auto_take_off_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_vert_module_auto_take_off_height, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_vert_api_vert_ctrl_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_api_vert_ctrl_cmd_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_vert_pos_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_vert_pos_cmd_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_vert_pos_feedback_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_vert_pos_cmd, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vert_vert_pos_feedback, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vert_vert_pos_p_ctrl, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vert_vert_pos_output, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vert_vert_vel_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_vert_vel_cmd_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_vert_vel_feedback_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_vert_vel_cmd, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vert_vert_vel_cmd_before_limit, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vert_vert_vel_cmd_after_limit, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vert_vert_vel_feedback, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vert_vert_vel_p_ctrl, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vert_vert_vel_output, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vert_vert_acc_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_vert_acc_cmd_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_vert_acc_feedback_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_vert_acc_cmd, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vert_vert_acc_feedback, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vert_vert_acc_p_ctrl, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vert_vert_acc_i_ctrl, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vert_vert_acc_feedforward, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vert_vert_acc_output, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vert_vert_thrust_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_vert_thrust_cmd_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_vert_thrust_feedback_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_vert_thrust_cmd_data, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 68) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ctrl Vert: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ctrl Vert: Payload size different than expected") end
end

-- Flight log - Ctrl Horiz - 0x0033

f.ctrl_horiz_horiz_module_module_mode = ProtoField.uint8 ("dji_p3_flyrec.ctrl_horiz_horiz_module_module_mode", "Horiz Module Module Mode", base.HEX)
f.ctrl_horiz_horiz_module_horiz_hover_state = ProtoField.uint8 ("dji_p3_flyrec.ctrl_horiz_horiz_module_horiz_hover_state", "Horiz Module Horiz Hover State", base.HEX)
f.ctrl_horiz_horiz_module_horiz_hover_enable = ProtoField.uint8 ("dji_p3_flyrec.ctrl_horiz_horiz_module_horiz_hover_enable", "Horiz Module Horiz Hover Enable", base.HEX)
f.ctrl_horiz_horiz_module_horiz_hover_abs_pos_0 = ProtoField.double ("dji_p3_flyrec.ctrl_horiz_horiz_module_horiz_hover_abs_pos_0", "Horiz Module Horiz Hover Abs Pos 0", base.DEC)
f.ctrl_horiz_horiz_module_horiz_hover_abs_pos_1 = ProtoField.double ("dji_p3_flyrec.ctrl_horiz_horiz_module_horiz_hover_abs_pos_1", "Horiz Module Horiz Hover Abs Pos 1", base.DEC)
f.ctrl_horiz_horiz_module_horiz_hover_rel_pos_0 = ProtoField.float ("dji_p3_flyrec.ctrl_horiz_horiz_module_horiz_hover_rel_pos_0", "Horiz Module Horiz Hover Rel Pos 0", base.DEC)
f.ctrl_horiz_horiz_module_horiz_hover_rel_pos_1 = ProtoField.float ("dji_p3_flyrec.ctrl_horiz_horiz_module_horiz_hover_rel_pos_1", "Horiz Module Horiz Hover Rel Pos 1", base.DEC)
f.ctrl_horiz_horiz_module_horiz_hover_brake_timer = ProtoField.float ("dji_p3_flyrec.ctrl_horiz_horiz_module_horiz_hover_brake_timer", "Horiz Module Horiz Hover Brake Timer", base.DEC)
f.ctrl_horiz_horiz_module_horiz_pos_offset_0 = ProtoField.float ("dji_p3_flyrec.ctrl_horiz_horiz_module_horiz_pos_offset_0", "Horiz Module Horiz Pos Offset 0", base.DEC)
f.ctrl_horiz_horiz_module_horiz_pos_offset_1 = ProtoField.float ("dji_p3_flyrec.ctrl_horiz_horiz_module_horiz_pos_offset_1", "Horiz Module Horiz Pos Offset 1", base.DEC)
f.ctrl_horiz_api_horiz_ctrl_mode = ProtoField.uint8 ("dji_p3_flyrec.ctrl_horiz_api_horiz_ctrl_mode", "Api Horiz Ctrl Mode", base.HEX)
f.ctrl_horiz_api_horiz_ctrl_cmd_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_horiz_api_horiz_ctrl_cmd_id", "Api Horiz Ctrl Cmd Id", base.HEX)
f.ctrl_horiz_api_torsion_ctrl_mode = ProtoField.uint8 ("dji_p3_flyrec.ctrl_horiz_api_torsion_ctrl_mode", "Api Torsion Ctrl Mode", base.HEX)
f.ctrl_horiz_api_torsion_ctrl_cmd_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_horiz_api_torsion_ctrl_cmd_id", "Api Torsion Ctrl Cmd Id", base.HEX)
f.ctrl_horiz_api_atti_cmd_type = ProtoField.uint8 ("dji_p3_flyrec.ctrl_horiz_api_atti_cmd_type", "Api Atti Cmd Type", base.HEX)
f.ctrl_horiz_api_atti_unkn2C = ProtoField.uint8 ("dji_p3_flyrec.ctrl_horiz_api_atti_unkn2C", "Api Atti Unknown 2C", base.HEX)
f.ctrl_horiz_horiz_pos_tag_status = ProtoField.uint8 ("dji_p3_flyrec.ctrl_horiz_horiz_pos_tag_status", "Horiz Pos Tag Status", base.HEX)
f.ctrl_horiz_horiz_pos_tag_cmd_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_horiz_horiz_pos_tag_cmd_id", "Horiz Pos Tag Cmd Id", base.HEX)
f.ctrl_horiz_horiz_pos_tag_feedback_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_horiz_horiz_pos_tag_feedback_id", "Horiz Pos Tag Feedback Id", base.HEX)
f.ctrl_horiz_horiz_pos_cmd_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_pos_cmd_x", "Horiz Pos Cmd X", base.DEC)
f.ctrl_horiz_horiz_pos_cmd_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_pos_cmd_y", "Horiz Pos Cmd Y", base.DEC)
f.ctrl_horiz_horiz_pos_feedback_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_pos_feedback_x", "Horiz Pos Feedback X", base.DEC)
f.ctrl_horiz_horiz_pos_feedback_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_pos_feedback_y", "Horiz Pos Feedback Y", base.DEC)
f.ctrl_horiz_horiz_pos_p_ctrl_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_pos_p_ctrl_x", "Horiz Pos P Ctrl X", base.DEC)
f.ctrl_horiz_horiz_pos_p_ctrl_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_pos_p_ctrl_y", "Horiz Pos P Ctrl Y", base.DEC)
f.ctrl_horiz_horiz_pos_d_ctrl_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_pos_d_ctrl_x", "Horiz Pos D Ctrl X", base.DEC)
f.ctrl_horiz_horiz_pos_d_ctrl_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_pos_d_ctrl_y", "Horiz Pos D Ctrl Y", base.DEC)
f.ctrl_horiz_horiz_pos_output_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_pos_output_x", "Horiz Pos Output X", base.DEC)
f.ctrl_horiz_horiz_pos_output_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_pos_output_y", "Horiz Pos Output Y", base.DEC)
f.ctrl_horiz_horiz_vel_tag_status = ProtoField.uint8 ("dji_p3_flyrec.ctrl_horiz_horiz_vel_tag_status", "Horiz Vel Tag Status", base.HEX)
f.ctrl_horiz_horiz_vel_tag_cmd_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_horiz_horiz_vel_tag_cmd_id", "Horiz Vel Tag Cmd Id", base.HEX)
f.ctrl_horiz_horiz_vel_tag_feedback_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_horiz_horiz_vel_tag_feedback_id", "Horiz Vel Tag Feedback Id", base.HEX)
f.ctrl_horiz_horiz_vel_cmd_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_vel_cmd_x", "Horiz Vel Cmd X", base.DEC)
f.ctrl_horiz_horiz_vel_cmd_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_vel_cmd_y", "Horiz Vel Cmd Y", base.DEC)
f.ctrl_horiz_horiz_vel_feedback_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_vel_feedback_x", "Horiz Vel Feedback X", base.DEC)
f.ctrl_horiz_horiz_vel_feedback_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_vel_feedback_y", "Horiz Vel Feedback Y", base.DEC)
f.ctrl_horiz_horiz_vel_p_ctrl_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_vel_p_ctrl_x", "Horiz Vel P Ctrl X", base.DEC)
f.ctrl_horiz_horiz_vel_p_ctrl_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_vel_p_ctrl_y", "Horiz Vel P Ctrl Y", base.DEC)
f.ctrl_horiz_horiz_vel_d_ctrl_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_vel_d_ctrl_x", "Horiz Vel D Ctrl X", base.DEC)
f.ctrl_horiz_horiz_vel_d_ctrl_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_vel_d_ctrl_y", "Horiz Vel D Ctrl Y", base.DEC)
f.ctrl_horiz_horiz_vel_i_ctrl_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_vel_i_ctrl_x", "Horiz Vel I Ctrl X", base.DEC)
f.ctrl_horiz_horiz_vel_i_ctrl_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_vel_i_ctrl_y", "Horiz Vel I Ctrl Y", base.DEC)
f.ctrl_horiz_horiz_vel_feedforward_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_vel_feedforward_x", "Horiz Vel Feedforward X", base.DEC)
f.ctrl_horiz_horiz_vel_feedforward_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_vel_feedforward_y", "Horiz Vel Feedforward Y", base.DEC)
f.ctrl_horiz_horiz_vel_output_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_vel_output_x", "Horiz Vel Output X", base.DEC)
f.ctrl_horiz_horiz_vel_output_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_vel_output_y", "Horiz Vel Output Y", base.DEC)
f.ctrl_horiz_horiz_acc_tag_status = ProtoField.uint8 ("dji_p3_flyrec.ctrl_horiz_horiz_acc_tag_status", "Horiz Acc Tag Status", base.HEX)
f.ctrl_horiz_horiz_acc_tag_cmd_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_horiz_horiz_acc_tag_cmd_id", "Horiz Acc Tag Cmd Id", base.HEX)
f.ctrl_horiz_horiz_acc_tag_feedback_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_horiz_horiz_acc_tag_feedback_id", "Horiz Acc Tag Feedback Id", base.HEX)
f.ctrl_horiz_horiz_acc_cmd_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_acc_cmd_x", "Horiz Acc Cmd X", base.DEC)
f.ctrl_horiz_horiz_acc_cmd_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_acc_cmd_y", "Horiz Acc Cmd Y", base.DEC)
f.ctrl_horiz_horiz_acc_feedback_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_acc_feedback_x", "Horiz Acc Feedback X", base.DEC)
f.ctrl_horiz_horiz_acc_feedback_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_acc_feedback_y", "Horiz Acc Feedback Y", base.DEC)
f.ctrl_horiz_horiz_acc_feedback_i_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_acc_feedback_i_x", "Horiz Acc Feedback I X", base.DEC)
f.ctrl_horiz_horiz_acc_feedback_i_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_acc_feedback_i_y", "Horiz Acc Feedback I Y", base.DEC)
f.ctrl_horiz_horiz_acc_feedforward_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_acc_feedforward_x", "Horiz Acc Feedforward X", base.DEC)
f.ctrl_horiz_horiz_acc_feedforward_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_acc_feedforward_y", "Horiz Acc Feedforward Y", base.DEC)
f.ctrl_horiz_horiz_acc_output_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_acc_output_x", "Horiz Acc Output X", base.DEC)
f.ctrl_horiz_horiz_acc_output_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_horiz_horiz_acc_output_y", "Horiz Acc Output Y", base.DEC)

local function flightrec_ctrl_horiz_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ctrl_horiz_horiz_module_module_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_horiz_module_horiz_hover_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_horiz_module_horiz_hover_enable, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_horiz_module_horiz_hover_abs_pos_0, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.ctrl_horiz_horiz_module_horiz_hover_abs_pos_1, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.ctrl_horiz_horiz_module_horiz_hover_rel_pos_0, payload(offset, 4)) -- offset = 19
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_horiz_module_horiz_hover_rel_pos_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_horiz_module_horiz_hover_brake_timer, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_horiz_module_horiz_pos_offset_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_horiz_module_horiz_pos_offset_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_api_horiz_ctrl_mode, payload(offset, 1)) -- offset = 39
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_api_horiz_ctrl_cmd_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_api_torsion_ctrl_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_api_torsion_ctrl_cmd_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_api_atti_cmd_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_api_atti_unkn2C, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_horiz_pos_tag_status, payload(offset, 1)) -- offset = 45
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_horiz_pos_tag_cmd_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_horiz_pos_tag_feedback_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_horiz_pos_cmd_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_pos_cmd_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_pos_feedback_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_pos_feedback_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_pos_p_ctrl_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_pos_p_ctrl_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_pos_d_ctrl_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_pos_d_ctrl_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_pos_output_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_pos_output_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_vel_tag_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_horiz_vel_tag_cmd_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_horiz_vel_tag_feedback_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_horiz_vel_cmd_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_vel_cmd_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_vel_feedback_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_vel_feedback_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_vel_p_ctrl_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_vel_p_ctrl_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_vel_d_ctrl_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_vel_d_ctrl_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_vel_i_ctrl_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_vel_i_ctrl_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_vel_feedforward_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_vel_feedforward_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_vel_output_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_vel_output_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_acc_tag_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_horiz_acc_tag_cmd_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_horiz_acc_tag_feedback_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_horiz_acc_cmd_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_acc_cmd_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_acc_feedback_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_acc_feedback_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_acc_feedback_i_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_acc_feedback_i_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_acc_feedforward_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_acc_feedforward_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_acc_output_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_horiz_acc_output_y, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 122) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ctrl Horiz: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ctrl Horiz: Payload size different than expected") end
end

-- Flight log - Ctrl Motor - 0x0036

f.ctrl_motor_horiz_motor_status = ProtoField.uint8 ("dji_p3_flyrec.ctrl_motor_horiz_motor_status", "Horiz Motor Status", base.HEX)
f.ctrl_motor_horiz_motor_cmd_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_motor_horiz_motor_cmd_id", "Horiz Motor Cmd Id", base.HEX)
f.ctrl_motor_horiz_motor_feedback_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_motor_horiz_motor_feedback_id", "Horiz Motor Feedback Id", base.HEX)
f.ctrl_motor_thrust_1 = ProtoField.uint16 ("dji_p3_flyrec.ctrl_motor_thrust_1", "Thrust 1", base.DEC, nil, nil, "0.01; thrust value for motor 1 (r.f. in quads)")
f.ctrl_motor_thrust_2 = ProtoField.uint16 ("dji_p3_flyrec.ctrl_motor_thrust_2", "Thrust 2", base.DEC, nil, nil, "0.01; thrust value for motor 2 (l.f. in quads)")
f.ctrl_motor_thrust_3 = ProtoField.uint16 ("dji_p3_flyrec.ctrl_motor_thrust_3", "Thrust 3", base.DEC, nil, nil, "0.01; thrust value for motor 3 (l.b. in quads)")
f.ctrl_motor_thrust_4 = ProtoField.uint16 ("dji_p3_flyrec.ctrl_motor_thrust_4", "Thrust 4", base.DEC, nil, nil, "0.01; thrust value for motor 4 (r.b. in quads)")
f.ctrl_motor_thrust_5 = ProtoField.uint16 ("dji_p3_flyrec.ctrl_motor_thrust_5", "Thrust 5", base.DEC, nil, nil, "0.01; thrust value for motor 5 (if exists)")
f.ctrl_motor_thrust_6 = ProtoField.uint16 ("dji_p3_flyrec.ctrl_motor_thrust_6", "Thrust 6", base.DEC, nil, nil, "0.01; thrust value for motor 6 (if exists)")
f.ctrl_motor_thrust_7 = ProtoField.uint16 ("dji_p3_flyrec.ctrl_motor_thrust_7", "Thrust 7", base.DEC, nil, nil, "0.01; thrust value for motor 7 (if exists)")
f.ctrl_motor_thrust_8 = ProtoField.uint16 ("dji_p3_flyrec.ctrl_motor_thrust_8", "Thrust 8", base.DEC, nil, nil, "0.01; thrust value for motor 8 (if exists)")
f.ctrl_motor_pwm_1 = ProtoField.uint16 ("dji_p3_flyrec.ctrl_motor_pwm_1", "Pwm 1", base.DEC, nil, nil, "0.01; PWM value for motor 1 (r.f. in quads)")
f.ctrl_motor_pwm_2 = ProtoField.uint16 ("dji_p3_flyrec.ctrl_motor_pwm_2", "Pwm 2", base.DEC, nil, nil, "0.01; PWM value for motor 2 (l.f. in quads)")
f.ctrl_motor_pwm_3 = ProtoField.uint16 ("dji_p3_flyrec.ctrl_motor_pwm_3", "Pwm 3", base.DEC, nil, nil, "0.01; PWM value for motor 3 (l.b. in quads)")
f.ctrl_motor_pwm_4 = ProtoField.uint16 ("dji_p3_flyrec.ctrl_motor_pwm_4", "Pwm 4", base.DEC, nil, nil, "0.01; PWM value for motor 4 (r.b. in quads)")
f.ctrl_motor_pwm_5 = ProtoField.uint16 ("dji_p3_flyrec.ctrl_motor_pwm_5", "Pwm 5", base.DEC, nil, nil, "0.01; PWM value for motor 5 (if exists)")
f.ctrl_motor_pwm_6 = ProtoField.uint16 ("dji_p3_flyrec.ctrl_motor_pwm_6", "Pwm 6", base.DEC, nil, nil, "0.01; PWM value for motor 6 (if exists)")
f.ctrl_motor_pwm_7 = ProtoField.uint16 ("dji_p3_flyrec.ctrl_motor_pwm_7", "Pwm 7", base.DEC, nil, nil, "0.01; PWM value for motor 7 (if exists)")
f.ctrl_motor_pwm_8 = ProtoField.uint16 ("dji_p3_flyrec.ctrl_motor_pwm_8", "Pwm 8", base.DEC, nil, nil, "0.01; PWM value for motor 8 (if exists)")

local function flightrec_ctrl_motor_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ctrl_motor_horiz_motor_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_motor_horiz_motor_cmd_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_motor_horiz_motor_feedback_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_motor_thrust_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_thrust_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_thrust_3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_thrust_4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_thrust_5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_thrust_6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_thrust_7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_thrust_8, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_pwm_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_pwm_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_pwm_3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_pwm_4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_pwm_5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_pwm_6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_pwm_7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_pwm_8, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 35) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ctrl Motor: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ctrl Motor: Payload size different than expected") end
end

-- Flight log - Ctrl Atti - 0x0034

f.ctrl_atti_horiz_atti_tilt_tag_status = ProtoField.uint8 ("dji_p3_flyrec.ctrl_atti_horiz_atti_tilt_tag_status", "Horiz Atti Tilt Tag Status", base.HEX)
f.ctrl_atti_horiz_atti_tilt_tag_cmd_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_atti_horiz_atti_tilt_tag_cmd_id", "Horiz Atti Tilt Tag Cmd Id", base.HEX)
f.ctrl_atti_horiz_atti_tilt_tag_feedback_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_atti_horiz_atti_tilt_tag_feedback_id", "Horiz Atti Tilt Tag Feedback Id", base.HEX)
f.ctrl_atti_horiz_atti_torsion_tag_status = ProtoField.uint8 ("dji_p3_flyrec.ctrl_atti_horiz_atti_torsion_tag_status", "Horiz Atti Torsion Tag Status", base.HEX)
f.ctrl_atti_horiz_atti_torsion_tag_cmd_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_atti_horiz_atti_torsion_tag_cmd_id", "Horiz Atti Torsion Tag Cmd Id", base.HEX)
f.ctrl_atti_horiz_atti_torsion_tag_feedback_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_atti_horiz_atti_torsion_tag_feedback_id", "Horiz Atti Torsion Tag Feedback Id", base.HEX)
f.ctrl_atti_horiz_atti_tgt_acc_x = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_tgt_acc_x", "Horiz Atti Tgt Acc X", base.DEC)
f.ctrl_atti_horiz_atti_tgt_acc_y = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_tgt_acc_y", "Horiz Atti Tgt Acc Y", base.DEC)
f.ctrl_atti_horiz_atti_tgt_tilt_x = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_tgt_tilt_x", "Horiz Atti Tgt Tilt X", base.DEC)
f.ctrl_atti_horiz_atti_tgt_tilt_y = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_tgt_tilt_y", "Horiz Atti Tgt Tilt Y", base.DEC)
f.ctrl_atti_horiz_atti_tgt_body_tilt_x = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_tgt_body_tilt_x", "Horiz Atti Tgt Body Tilt X", base.DEC)
f.ctrl_atti_horiz_atti_tgt_body_tilt_y = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_tgt_body_tilt_y", "Horiz Atti Tgt Body Tilt Y", base.DEC)
f.ctrl_atti_horiz_atti_tgt_ground_tilt_x = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_tgt_ground_tilt_x", "Horiz Atti Tgt Ground Tilt X", base.DEC)
f.ctrl_atti_horiz_atti_tgt_ground_tilt_y = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_tgt_ground_tilt_y", "Horiz Atti Tgt Ground Tilt Y", base.DEC)
f.ctrl_atti_horiz_atti_tgt_tilt_before_limit_x = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_tgt_tilt_before_limit_x", "Horiz Atti Tgt Tilt Before Limit X", base.DEC)
f.ctrl_atti_horiz_atti_tgt_tilt_before_limit_y = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_tgt_tilt_before_limit_y", "Horiz Atti Tgt Tilt Before Limit Y", base.DEC)
f.ctrl_atti_horiz_atti_tgt_tilt_after_limit_x = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_tgt_tilt_after_limit_x", "Horiz Atti Tgt Tilt After Limit X", base.DEC)
f.ctrl_atti_horiz_atti_tgt_tilt_after_limit_y = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_tgt_tilt_after_limit_y", "Horiz Atti Tgt Tilt After Limit Y", base.DEC)
f.ctrl_atti_horiz_atti_tgt_quat_0 = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_tgt_quat_0", "Horiz Atti Tgt Quaternion 0", base.DEC)
f.ctrl_atti_horiz_atti_tgt_quat_1 = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_tgt_quat_1", "Horiz Atti Tgt Quaternion 1", base.DEC)
f.ctrl_atti_horiz_atti_tgt_quat_2 = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_tgt_quat_2", "Horiz Atti Tgt Quaternion 2", base.DEC)
f.ctrl_atti_horiz_atti_tgt_quat_3 = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_tgt_quat_3", "Horiz Atti Tgt Quaternion 3", base.DEC)
f.ctrl_atti_horiz_atti_tgt_torsion = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_tgt_torsion", "Horiz Atti Tgt Torsion", base.DEC)
f.ctrl_atti_horiz_atti_tgt_torsion_rate = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_tgt_torsion_rate", "Horiz Atti Tgt Torsion Rate", base.DEC)
f.ctrl_atti_horiz_atti_feedback_quat_0 = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_feedback_quat_0", "Horiz Atti Feedback Quaternion 0", base.DEC)
f.ctrl_atti_horiz_atti_feedback_quat_1 = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_feedback_quat_1", "Horiz Atti Feedback Quaternion 1", base.DEC)
f.ctrl_atti_horiz_atti_feedback_quat_2 = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_feedback_quat_2", "Horiz Atti Feedback Quaternion 2", base.DEC)
f.ctrl_atti_horiz_atti_feedback_quat_3 = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_feedback_quat_3", "Horiz Atti Feedback Quaternion 3", base.DEC)
f.ctrl_atti_horiz_atti_locked_torsion = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_locked_torsion", "Horiz Atti Locked Torsion", base.DEC)
f.ctrl_atti_horiz_atti_err_tilt_x = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_err_tilt_x", "Horiz Atti Err Tilt X", base.DEC)
f.ctrl_atti_horiz_atti_err_tilt_y = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_err_tilt_y", "Horiz Atti Err Tilt Y", base.DEC)
f.ctrl_atti_horiz_atti_err_torsion = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_err_torsion", "Horiz Atti Err Torsion", base.DEC)
f.ctrl_atti_horiz_atti_output_x = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_output_x", "Horiz Atti Output X", base.DEC)
f.ctrl_atti_horiz_atti_output_y = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_output_y", "Horiz Atti Output Y", base.DEC)
f.ctrl_atti_horiz_atti_output_z = ProtoField.float ("dji_p3_flyrec.ctrl_atti_horiz_atti_output_z", "Horiz Atti Output Z", base.DEC)
f.ctrl_atti_horiz_ang_vel_status = ProtoField.uint8 ("dji_p3_flyrec.ctrl_atti_horiz_ang_vel_status", "Horiz Ang Vel Status", base.HEX)
f.ctrl_atti_horiz_ang_vel_cmd_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_atti_horiz_ang_vel_cmd_id", "Horiz Ang Vel Cmd Id", base.HEX)
f.ctrl_atti_horiz_ang_vel_feedback_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_atti_horiz_ang_vel_feedback_id", "Horiz Ang Vel Feedback Id", base.HEX)
f.ctrl_atti_horiz_ang_vel_cmd_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_vel_cmd_x", "Horiz Ang Vel Cmd X", base.DEC)
f.ctrl_atti_horiz_ang_vel_cmd_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_vel_cmd_y", "Horiz Ang Vel Cmd Y", base.DEC)
f.ctrl_atti_horiz_ang_vel_cmd_z = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_vel_cmd_z", "Horiz Ang Vel Cmd Z", base.DEC)
f.ctrl_atti_horiz_ang_vel_feedback_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_vel_feedback_x", "Horiz Ang Vel Feedback X", base.DEC)
f.ctrl_atti_horiz_ang_vel_feedback_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_vel_feedback_y", "Horiz Ang Vel Feedback Y", base.DEC)
f.ctrl_atti_horiz_ang_vel_feedback_z = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_vel_feedback_z", "Horiz Ang Vel Feedback Z", base.DEC)
f.ctrl_atti_horiz_ang_vel_feedback_p_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_vel_feedback_p_x", "Horiz Ang Vel Feedback P X", base.DEC)
f.ctrl_atti_horiz_ang_vel_feedback_p_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_vel_feedback_p_y", "Horiz Ang Vel Feedback P Y", base.DEC)
f.ctrl_atti_horiz_ang_vel_feedback_p_z = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_vel_feedback_p_z", "Horiz Ang Vel Feedback P Z", base.DEC)
f.ctrl_atti_horiz_ang_vel_feedback_d_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_vel_feedback_d_x", "Horiz Ang Vel Feedback D X", base.DEC)
f.ctrl_atti_horiz_ang_vel_feedback_d_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_vel_feedback_d_y", "Horiz Ang Vel Feedback D Y", base.DEC)
f.ctrl_atti_horiz_ang_vel_feedback_d_z = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_vel_feedback_d_z", "Horiz Ang Vel Feedback D Z", base.DEC)
f.ctrl_atti_horiz_ang_vel_output_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_vel_output_x", "Horiz Ang Vel Output X", base.DEC)
f.ctrl_atti_horiz_ang_vel_output_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_vel_output_y", "Horiz Ang Vel Output Y", base.DEC)
f.ctrl_atti_horiz_ang_vel_output_z = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_vel_output_z", "Horiz Ang Vel Output Z", base.DEC)
f.ctrl_atti_horiz_ang_acc_status = ProtoField.uint8 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_status", "Horiz Ang Acc Status", base.HEX)
f.ctrl_atti_horiz_ang_acc_cmd_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_cmd_id", "Horiz Ang Acc Cmd Id", base.HEX)
f.ctrl_atti_horiz_ang_acc_feedback_id = ProtoField.uint8 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_feedback_id", "Horiz Ang Acc Feedback Id", base.HEX)
f.ctrl_atti_horiz_ang_acc_cmd_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_cmd_x", "Horiz Ang Acc Cmd X", base.DEC)
f.ctrl_atti_horiz_ang_acc_cmd_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_cmd_y", "Horiz Ang Acc Cmd Y", base.DEC)
f.ctrl_atti_horiz_ang_acc_cmd_z = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_cmd_z", "Horiz Ang Acc Cmd Z", base.DEC)
f.ctrl_atti_horiz_ang_acc_feedback_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_feedback_x", "Horiz Ang Acc Feedback X", base.DEC)
f.ctrl_atti_horiz_ang_acc_feedback_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_feedback_y", "Horiz Ang Acc Feedback Y", base.DEC)
f.ctrl_atti_horiz_ang_acc_feedback_z = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_feedback_z", "Horiz Ang Acc Feedback Z", base.DEC)
f.ctrl_atti_horiz_ang_acc_p_ctrl_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_p_ctrl_x", "Horiz Ang Acc P Ctrl X", base.DEC)
f.ctrl_atti_horiz_ang_acc_p_ctrl_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_p_ctrl_y", "Horiz Ang Acc P Ctrl Y", base.DEC)
f.ctrl_atti_horiz_ang_acc_p_ctrl_z = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_p_ctrl_z", "Horiz Ang Acc P Ctrl Z", base.DEC)
f.ctrl_atti_horiz_ang_acc_i_ctrl_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_i_ctrl_x", "Horiz Ang Acc I Ctrl X", base.DEC)
f.ctrl_atti_horiz_ang_acc_i_ctrl_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_i_ctrl_y", "Horiz Ang Acc I Ctrl Y", base.DEC)
f.ctrl_atti_horiz_ang_acc_i_ctrl_z = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_i_ctrl_z", "Horiz Ang Acc I Ctrl Z", base.DEC)
f.ctrl_atti_horiz_ang_acc_feedforward_direct_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_feedforward_direct_x", "Horiz Ang Acc Feedforward Direct X", base.DEC)
f.ctrl_atti_horiz_ang_acc_feedforward_direct_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_feedforward_direct_y", "Horiz Ang Acc Feedforward Direct Y", base.DEC)
f.ctrl_atti_horiz_ang_acc_feedforward_direct_z = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_feedforward_direct_z", "Horiz Ang Acc Feedforward Direct Z", base.DEC)
f.ctrl_atti_horiz_ang_acc_feedforward_compen_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_feedforward_compen_x", "Horiz Ang Acc Feedforward Compen X", base.DEC)
f.ctrl_atti_horiz_ang_acc_feedforward_compen_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_feedforward_compen_y", "Horiz Ang Acc Feedforward Compen Y", base.DEC)
f.ctrl_atti_horiz_ang_acc_feedforward_compen_z = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_feedforward_compen_z", "Horiz Ang Acc Feedforward Compen Z", base.DEC)
f.ctrl_atti_horiz_ang_acc_output_x = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_output_x", "Horiz Ang Acc Output X", base.DEC)
f.ctrl_atti_horiz_ang_acc_output_y = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_output_y", "Horiz Ang Acc Output Y", base.DEC)
f.ctrl_atti_horiz_ang_acc_output_z = ProtoField.int16 ("dji_p3_flyrec.ctrl_atti_horiz_ang_acc_output_z", "Horiz Ang Acc Output Z", base.DEC)
--f.ctrl_atti_e_cmd_pitch = ProtoField.none ("dji_p3_flyrec.ctrl_atti_e_cmd_pitch", "E Cmd Pitch", base.NONE, nil, nil, "-asin_x(2*(horiz_atti_tgt_quat_1*horiz_atti_tgt_quat_3-horiz_atti_tgt_quat_0*horiz_atti_tgt_quat_2))/3.1415926*180")
--f.ctrl_atti_e_cmd_roll = ProtoField.none ("dji_p3_flyrec.ctrl_atti_e_cmd_roll", "E Cmd Roll", base.NONE, nil, nil, "atan2(2*(horiz_atti_tgt_quat_2*horiz_atti_tgt_quat_3+horiz_atti_tgt_quat_0*horiz_atti_tgt_quat_1),1-2*(horiz_atti_tgt_quat_1*horiz_atti_tgt_quat_1+horiz_atti_tgt_quat_2*horiz_atti_tgt_quat_2))/3.1415926*180")
--f.ctrl_atti_e_cmd_yaw = ProtoField.none ("dji_p3_flyrec.ctrl_atti_e_cmd_yaw", "E Cmd Yaw", base.NONE, nil, nil, "atan2(2*(horiz_atti_tgt_quat_1*horiz_atti_tgt_quat_2+horiz_atti_tgt_quat_0*horiz_atti_tgt_quat_3),1-2*(horiz_atti_tgt_quat_2*horiz_atti_tgt_quat_2+horiz_atti_tgt_quat_3*horiz_atti_tgt_quat_3))/3.1415926*180")
--f.ctrl_atti_e_feedback_pitch = ProtoField.none ("dji_p3_flyrec.ctrl_atti_e_feedback_pitch", "E Feedback Pitch", base.NONE, nil, nil, "-asin_x(2*(horiz_atti_feedback_quat_1*horiz_atti_feedback_quat_3-horiz_atti_feedback_quat_0*horiz_atti_feedback_quat_2))/3.1415926*180")
--f.ctrl_atti_e_feedback_roll = ProtoField.none ("dji_p3_flyrec.ctrl_atti_e_feedback_roll", "E Feedback Roll", base.NONE, nil, nil, "atan2(2*(horiz_atti_feedback_quat_2*horiz_atti_feedback_quat_3+horiz_atti_feedback_quat_0*horiz_atti_feedback_quat_1),1-2*(horiz_atti_feedback_quat_1*horiz_atti_feedback_quat_1+horiz_atti_feedback_quat_2*horiz_atti_feedback_quat_2))/3.1415926*180")
--f.ctrl_atti_e_feedback_yaw = ProtoField.none ("dji_p3_flyrec.ctrl_atti_e_feedback_yaw", "E Feedback Yaw", base.NONE, nil, nil, "atan2(2*(horiz_atti_feedback_quat_1*horiz_atti_feedback_quat_2+horiz_atti_feedback_quat_0*horiz_atti_feedback_quat_3),1-2*(horiz_atti_feedback_quat_2*horiz_atti_feedback_quat_2+horiz_atti_feedback_quat_3*horiz_atti_feedback_quat_3))/3.1415926*180")

local function flightrec_ctrl_atti_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ctrl_atti_horiz_atti_tilt_tag_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_atti_horiz_atti_tilt_tag_cmd_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_atti_horiz_atti_tilt_tag_feedback_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_atti_horiz_atti_torsion_tag_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_atti_horiz_atti_torsion_tag_cmd_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_atti_horiz_atti_torsion_tag_feedback_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_atti_horiz_atti_tgt_acc_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_tgt_acc_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_tgt_tilt_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_tgt_tilt_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_tgt_body_tilt_x, payload(offset, 4)) -- offset = 22
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_tgt_body_tilt_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_tgt_ground_tilt_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_tgt_ground_tilt_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_tgt_tilt_before_limit_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_tgt_tilt_before_limit_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_tgt_tilt_after_limit_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_tgt_tilt_after_limit_y, payload(offset, 4)) -- offset = 50
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_tgt_quat_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_tgt_quat_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_tgt_quat_2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_tgt_quat_3, payload(offset, 4)) -- offset = 66
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_tgt_torsion, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_tgt_torsion_rate, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_feedback_quat_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_feedback_quat_1, payload(offset, 4)) -- offset = 82
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_feedback_quat_2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_feedback_quat_3, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_locked_torsion, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_err_tilt_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_err_tilt_y, payload(offset, 4)) -- offset = 102
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_err_torsion, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_output_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_output_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_atti_output_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_atti_horiz_ang_vel_status, payload(offset, 1)) -- offset = 122
    offset = offset + 1

    subtree:add_le (f.ctrl_atti_horiz_ang_vel_cmd_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_atti_horiz_ang_vel_feedback_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_atti_horiz_ang_vel_cmd_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_vel_cmd_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_vel_cmd_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_vel_feedback_x, payload(offset, 2)) -- offset = 131
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_vel_feedback_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_vel_feedback_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_vel_feedback_p_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_vel_feedback_p_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_vel_feedback_p_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_vel_feedback_d_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_vel_feedback_d_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_vel_feedback_d_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_vel_output_x, payload(offset, 2)) -- offset = 149
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_vel_output_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_vel_output_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_status, payload(offset, 1)) -- offset = 155
    offset = offset + 1

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_cmd_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_feedback_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_cmd_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_cmd_y, payload(offset, 2)) -- offset = 160
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_cmd_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_feedback_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_feedback_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_feedback_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_p_ctrl_x, payload(offset, 2)) -- offset = 170
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_p_ctrl_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_p_ctrl_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_i_ctrl_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_i_ctrl_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_i_ctrl_z, payload(offset, 2)) -- offset = 180
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_feedforward_direct_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_feedforward_direct_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_feedforward_direct_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_feedforward_compen_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_feedforward_compen_y, payload(offset, 2)) -- offset = 190
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_feedforward_compen_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_output_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_output_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_atti_horiz_ang_acc_output_z, payload(offset, 2))
    offset = offset + 2

    -- The "Ctrl Atti" record contains "Ctrl Motor" record appended at offset = 200

    subtree:add_le (f.ctrl_motor_horiz_motor_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_motor_horiz_motor_cmd_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_motor_horiz_motor_feedback_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_motor_thrust_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_thrust_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_thrust_3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_thrust_4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_thrust_5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_thrust_6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_thrust_7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_thrust_8, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_pwm_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_pwm_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_pwm_3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_pwm_4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_pwm_5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_pwm_6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_pwm_7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_motor_pwm_8, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 235) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ctrl Atti: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ctrl Atti: Payload size different than expected") end
end

-- Flight log - Ctrl Ccpm - 0x0035
-- Cyclic Collective Pitch Mixing Control

f.ctrl_ccpm_dyn_ccpm_raw_lift = ProtoField.float ("dji_p3_flyrec.ctrl_ccpm_dyn_ccpm_raw_lift", "Dyn Ccpm Raw Lift", base.DEC)
f.ctrl_ccpm_dyn_ccpm_raw_tilt_x = ProtoField.float ("dji_p3_flyrec.ctrl_ccpm_dyn_ccpm_raw_tilt_x", "Dyn Ccpm Raw Tilt X", base.DEC)
f.ctrl_ccpm_dyn_ccpm_raw_tilt_y = ProtoField.float ("dji_p3_flyrec.ctrl_ccpm_dyn_ccpm_raw_tilt_y", "Dyn Ccpm Raw Tilt Y", base.DEC)
f.ctrl_ccpm_dyn_ccpm_raw_torsion = ProtoField.float ("dji_p3_flyrec.ctrl_ccpm_dyn_ccpm_raw_torsion", "Dyn Ccpm Raw Torsion", base.DEC)
f.ctrl_ccpm_dyn_ccpm_fix_lift = ProtoField.float ("dji_p3_flyrec.ctrl_ccpm_dyn_ccpm_fix_lift", "Dyn Ccpm Fix Lift", base.DEC)
f.ctrl_ccpm_dyn_ccpm_fix_tilt_x = ProtoField.float ("dji_p3_flyrec.ctrl_ccpm_dyn_ccpm_fix_tilt_x", "Dyn Ccpm Fix Tilt X", base.DEC)
f.ctrl_ccpm_dyn_ccpm_fix_tilt_y = ProtoField.float ("dji_p3_flyrec.ctrl_ccpm_dyn_ccpm_fix_tilt_y", "Dyn Ccpm Fix Tilt Y", base.DEC)
f.ctrl_ccpm_dyn_ccpm_fix_torsion = ProtoField.float ("dji_p3_flyrec.ctrl_ccpm_dyn_ccpm_fix_torsion", "Dyn Ccpm Fix Torsion", base.DEC)
f.ctrl_ccpm_dyn_ccpm_fix_lift_scale = ProtoField.float ("dji_p3_flyrec.ctrl_ccpm_dyn_ccpm_fix_lift_scale", "Dyn Ccpm Fix Lift Scale", base.DEC)
f.ctrl_ccpm_dyn_ccpm_fix_tilt_scale = ProtoField.float ("dji_p3_flyrec.ctrl_ccpm_dyn_ccpm_fix_tilt_scale", "Dyn Ccpm Fix Tilt Scale", base.DEC)
f.ctrl_ccpm_dyn_ccpm_fix_torsion_scale = ProtoField.float ("dji_p3_flyrec.ctrl_ccpm_dyn_ccpm_fix_torsion_scale", "Dyn Ccpm Fix Torsion Scale", base.DEC)
f.ctrl_ccpm_dyn_ccpm_saturation_value = ProtoField.float ("dji_p3_flyrec.ctrl_ccpm_dyn_ccpm_saturation_value", "Dyn Ccpm Saturation Value", base.DEC)
f.ctrl_ccpm_dyn_ccpm_saturation_flag = ProtoField.uint8 ("dji_p3_flyrec.ctrl_ccpm_dyn_ccpm_saturation_flag", "Dyn Ccpm Saturation Flag", base.HEX)

local function flightrec_ctrl_ccpm_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ctrl_ccpm_dyn_ccpm_raw_lift, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_ccpm_dyn_ccpm_raw_tilt_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_ccpm_dyn_ccpm_raw_tilt_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_ccpm_dyn_ccpm_raw_torsion, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_ccpm_dyn_ccpm_fix_lift, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_ccpm_dyn_ccpm_fix_tilt_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_ccpm_dyn_ccpm_fix_tilt_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_ccpm_dyn_ccpm_fix_torsion, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_ccpm_dyn_ccpm_fix_lift_scale, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_ccpm_dyn_ccpm_fix_tilt_scale, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_ccpm_dyn_ccpm_fix_torsion_scale, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_ccpm_dyn_ccpm_saturation_value, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_ccpm_dyn_ccpm_saturation_flag, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 49) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ctrl Ccpm: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ctrl Ccpm: Payload size different than expected") end
end

-- Flight log - Wp Curve - 0x0096

f.wp_curve_px = ProtoField.float ("dji_p3_flyrec.wp_curve_px", "Px", base.DEC)
f.wp_curve_py = ProtoField.float ("dji_p3_flyrec.wp_curve_py", "Py", base.DEC)
f.wp_curve_pz = ProtoField.float ("dji_p3_flyrec.wp_curve_pz", "Pz", base.DEC)
f.wp_curve_vx = ProtoField.float ("dji_p3_flyrec.wp_curve_vx", "Vx", base.DEC)
f.wp_curve_vy = ProtoField.float ("dji_p3_flyrec.wp_curve_vy", "Vy", base.DEC)
f.wp_curve_vz = ProtoField.float ("dji_p3_flyrec.wp_curve_vz", "Vz", base.DEC)
f.wp_curve_v_norm = ProtoField.float ("dji_p3_flyrec.wp_curve_v_norm", "V Norm", base.DEC)
f.wp_curve_t = ProtoField.float ("dji_p3_flyrec.wp_curve_t", "T", base.DEC)
f.wp_curve_wp_state = ProtoField.uint8 ("dji_p3_flyrec.wp_curve_wp_state", "Wp State", base.HEX)

local function flightrec_wp_curve_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.wp_curve_px, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.wp_curve_py, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.wp_curve_pz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.wp_curve_vx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.wp_curve_vy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.wp_curve_vz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.wp_curve_v_norm, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.wp_curve_t, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.wp_curve_wp_state, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 33) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Wp Curve: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Wp Curve: Payload size different than expected") end
end

-- Flight log - Smart Battery Info - 0x0012

f.smart_battery_info_rest_time = ProtoField.uint16 ("dji_p3_flyrec.smart_battery_info_rest_time", "Rest Time", base.DEC)
f.smart_battery_info_need_time_for_gohome = ProtoField.uint16 ("dji_p3_flyrec.smart_battery_info_need_time_for_gohome", "Need Time For Gohome", base.DEC)
f.smart_battery_info_need_time_for_land = ProtoField.uint16 ("dji_p3_flyrec.smart_battery_info_need_time_for_land", "Need Time For Land", base.DEC)
f.smart_battery_info_gohome_battery_level = ProtoField.uint16 ("dji_p3_flyrec.smart_battery_info_gohome_battery_level", "Gohome Battery Level", base.DEC)
f.smart_battery_info_land_battery_level = ProtoField.uint16 ("dji_p3_flyrec.smart_battery_info_land_battery_level", "Land Battery Level", base.DEC)
f.smart_battery_info_radius_for_gohome = ProtoField.float ("dji_p3_flyrec.smart_battery_info_radius_for_gohome", "Radius For Gohome", base.DEC)
f.smart_battery_info_request_gohome = ProtoField.uint16 ("dji_p3_flyrec.smart_battery_info_request_gohome", "Request Gohome", base.HEX)
f.smart_battery_info_bat_dec_speed = ProtoField.float ("dji_p3_flyrec.smart_battery_info_bat_dec_speed", "Bat Dec Speed", base.DEC)
f.smart_battery_info_smart_battery_state = ProtoField.uint32 ("dji_p3_flyrec.smart_battery_info_smart_battery_state", "Smart Battery State", base.HEX)
f.smart_battery_info_level1_over_current = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_level1_over_current", "Level1 Over Current", base.DEC)
f.smart_battery_info_level2_over_current = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_level2_over_current", "Level2 Over Current", base.DEC)
f.smart_battery_info_level1_over_temp = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_level1_over_temp", "Level1 Over Temp", base.DEC)
f.smart_battery_info_level2_under_temp = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_level2_under_temp", "Level2 Under Temp", base.DEC)
f.smart_battery_info_level1_low_temp = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_level1_low_temp", "Level1 Low Temp", base.DEC)
f.smart_battery_info_level2_low_temp = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_level2_low_temp", "Level2 Low Temp", base.DEC)
f.smart_battery_info_short_cir = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_short_cir", "Short Cir", base.HEX)
f.smart_battery_info_low_vol_cells = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_low_vol_cells", "Low Vol Cells", base.HEX)
f.smart_battery_info_damage_cells = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_damage_cells", "Damage Cells", base.HEX)
f.smart_battery_info_exchange_cells = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_exchange_cells", "Exchange Cells", base.HEX)
f.smart_battery_info_user_gohome_level = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_user_gohome_level", "User Gohome Level", base.DEC)
f.smart_battery_info_user_land_level = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_user_land_level", "User Land Level", base.DEC)
f.smart_battery_info_user_action_for_gohome = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_user_action_for_gohome", "User Action For Gohome", base.HEX)
f.smart_battery_info_user_action_for_land = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_user_action_for_land", "User Action For Land", base.HEX)
f.smart_battery_info_user_use_smart_bat = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_user_use_smart_bat", "User Use Smart Bat", base.HEX)
f.smart_battery_info_flag_main_vol_low_gohome = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_flag_main_vol_low_gohome", "Flag Main Vol Low Gohome", base.HEX)
f.smart_battery_info_flag_main_vol_low_land = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_flag_main_vol_low_land", "Flag Main Vol Low Land", base.HEX)
f.smart_battery_info_flag_user_gohome = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_flag_user_gohome", "Flag User Gohome", base.HEX)
f.smart_battery_info_flag_user_land = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_flag_user_land", "Flag User Land", base.HEX)
f.smart_battery_info_flag_smart_bat_gohome = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_flag_smart_bat_gohome", "Flag Smart Bat Gohome", base.HEX)
f.smart_battery_info_flag_smart_bat_land = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_flag_smart_bat_land", "Flag Smart Bat Land", base.HEX)
f.smart_battery_info_flag_cell_err = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_flag_cell_err", "Flag Cell Err", base.HEX)
f.smart_battery_info_flag_communite_err = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_flag_communite_err", "Flag Communite Err", base.HEX)
f.smart_battery_info_real_desc_speed = ProtoField.float ("dji_p3_flyrec.smart_battery_info_real_desc_speed", "Real Desc Speed", base.DEC)
f.smart_battery_info_flag_vol_very_low = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_flag_vol_very_low", "Flag Vol Very Low", base.HEX)
f.smart_battery_info_flag_temp_and_vol_low = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_flag_temp_and_vol_low", "Flag Temp And Vol Low", base.HEX)
f.smart_battery_info_flag_first_charge_not_full = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_flag_first_charge_not_full", "Flag First Charge Not Full", base.HEX)
f.smart_battery_info_g_filter_vol = ProtoField.float ("dji_p3_flyrec.smart_battery_info_g_filter_vol", "G Filter Vol", base.DEC)
f.smart_battery_info_g_filter_i = ProtoField.float ("dji_p3_flyrec.smart_battery_info_g_filter_i", "G Filter I", base.DEC)
f.smart_battery_info_g_evl_vol = ProtoField.float ("dji_p3_flyrec.smart_battery_info_g_evl_vol", "G Evl Vol", base.DEC)
f.smart_battery_info_g_delt_i = ProtoField.float ("dji_p3_flyrec.smart_battery_info_g_delt_i", "G Delt I", base.DEC)
f.smart_battery_info_fld70 = ProtoField.uint16 ("dji_p3_flyrec.smart_battery_info_fld70", "Field70", base.HEX)
f.smart_battery_info_fld72 = ProtoField.uint8 ("dji_p3_flyrec.smart_battery_info_fld72", "Field72", base.HEX)
f.smart_battery_info_vol_lv1_prot = ProtoField.uint16 ("dji_p3_flyrec.smart_battery_info_vol_lv1_prot", "Voltage Level 1 Protect, flyc param g_real.config.voltage.level_1_protect", base.DEC)
f.smart_battery_info_vol_lv2_prot = ProtoField.uint16 ("dji_p3_flyrec.smart_battery_info_vol_lv2_prot", "Voltage Level 2 Protect, flyc param g_real.config.voltage.level_2_protect", base.DEC)

local function flightrec_smart_battery_info_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.smart_battery_info_rest_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.smart_battery_info_need_time_for_gohome, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.smart_battery_info_need_time_for_land, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.smart_battery_info_gohome_battery_level, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.smart_battery_info_land_battery_level, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.smart_battery_info_radius_for_gohome, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.smart_battery_info_request_gohome, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.smart_battery_info_bat_dec_speed, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.smart_battery_info_smart_battery_state, payload(offset, 4)) -- offset 20
    offset = offset + 4

    subtree:add_le (f.smart_battery_info_level1_over_current, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_level2_over_current, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_level1_over_temp, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_level2_under_temp, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_level1_low_temp, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_level2_low_temp, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_short_cir, payload(offset, 1)) -- offset 30
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_low_vol_cells, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_damage_cells, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_exchange_cells, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_user_gohome_level, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_user_land_level, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_user_action_for_gohome, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_user_action_for_land, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_user_use_smart_bat, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_flag_main_vol_low_gohome, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_flag_main_vol_low_land, payload(offset, 1)) -- offset 40
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_flag_user_gohome, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_flag_user_land, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_flag_smart_bat_gohome, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_flag_smart_bat_land, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_flag_cell_err, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_flag_communite_err, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_real_desc_speed, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.smart_battery_info_flag_vol_very_low, payload(offset, 1)) -- offset 51
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_flag_temp_and_vol_low, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_flag_first_charge_not_full, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_g_filter_vol, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.smart_battery_info_g_filter_i, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.smart_battery_info_g_evl_vol, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.smart_battery_info_g_delt_i, payload(offset, 4)) -- offset 66
    offset = offset + 4

    subtree:add_le (f.smart_battery_info_fld70, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.smart_battery_info_fld72, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_vol_lv1_prot, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.smart_battery_info_vol_lv2_prot, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 77) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Smart Battery Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Smart Battery Info: Payload size different than expected") end
end

-- Flight log - Airport Limit Data - 0x0028

f.airport_limit_data_area_state = ProtoField.uint8 ("dji_p3_flyrec.airport_limit_data_area_state", "Area State", base.HEX)
f.airport_limit_data_action_state = ProtoField.uint8 ("dji_p3_flyrec.airport_limit_data_action_state", "Action State", base.HEX)
f.airport_limit_data_work_point_num = ProtoField.uint8 ("dji_p3_flyrec.airport_limit_data_work_point_num", "Work Point Num", base.HEX)
f.airport_limit_data_lat_int_0 = ProtoField.int32 ("dji_p3_flyrec.airport_limit_data_lat_int_0", "Lat Int 0", base.DEC)
f.airport_limit_data_lon_int_0 = ProtoField.int32 ("dji_p3_flyrec.airport_limit_data_lon_int_0", "Lon Int 0", base.DEC)
f.airport_limit_data_point_from_where_0 = ProtoField.uint8 ("dji_p3_flyrec.airport_limit_data_point_from_where_0", "Point From Where 0", base.HEX)
f.airport_limit_data_flag_limit_radius_0 = ProtoField.uint8 ("dji_p3_flyrec.airport_limit_data_flag_limit_radius_0", "Flag Limit Radius 0", base.HEX)
f.airport_limit_data_flag_limit_hi_0 = ProtoField.uint8 ("dji_p3_flyrec.airport_limit_data_flag_limit_hi_0", "Flag Limit Hi 0", base.HEX)
f.airport_limit_data_d2limit_edge_0 = ProtoField.float ("dji_p3_flyrec.airport_limit_data_d2limit_edge_0", "D2Limit Edge 0", base.DEC)
f.airport_limit_data_d2limit_hi_0 = ProtoField.float ("dji_p3_flyrec.airport_limit_data_d2limit_hi_0", "D2Limit Hi 0", base.DEC)
f.airport_limit_data_directx_0 = ProtoField.float ("dji_p3_flyrec.airport_limit_data_directx_0", "Directx 0", base.DEC)
f.airport_limit_data_directy_0 = ProtoField.float ("dji_p3_flyrec.airport_limit_data_directy_0", "Directy 0", base.DEC)
f.airport_limit_data_lat_int_1 = ProtoField.int32 ("dji_p3_flyrec.airport_limit_data_lat_int_1", "Lat Int 1", base.DEC)
f.airport_limit_data_lon_int_1 = ProtoField.int32 ("dji_p3_flyrec.airport_limit_data_lon_int_1", "Lon Int 1", base.DEC)
f.airport_limit_data_point_from_where_1 = ProtoField.uint8 ("dji_p3_flyrec.airport_limit_data_point_from_where_1", "Point From Where 1", base.HEX)
f.airport_limit_data_flag_limit_radius_1 = ProtoField.uint8 ("dji_p3_flyrec.airport_limit_data_flag_limit_radius_1", "Flag Limit Radius 1", base.HEX)
f.airport_limit_data_flag_limit_hi_1 = ProtoField.uint8 ("dji_p3_flyrec.airport_limit_data_flag_limit_hi_1", "Flag Limit Hi 1", base.HEX)
f.airport_limit_data_d2limit_edge_1 = ProtoField.float ("dji_p3_flyrec.airport_limit_data_d2limit_edge_1", "D2Limit Edge 1", base.DEC)
f.airport_limit_data_d2limit_hi_1 = ProtoField.float ("dji_p3_flyrec.airport_limit_data_d2limit_hi_1", "D2Limit Hi 1", base.DEC)
f.airport_limit_data_directx_1 = ProtoField.float ("dji_p3_flyrec.airport_limit_data_directx_1", "Directx 1", base.DEC)
f.airport_limit_data_directy_1 = ProtoField.float ("dji_p3_flyrec.airport_limit_data_directy_1", "Directy 1", base.DEC)
f.airport_limit_data_lat_int_2 = ProtoField.int32 ("dji_p3_flyrec.airport_limit_data_lat_int_2", "Lat Int 2", base.DEC)
f.airport_limit_data_lon_int_2 = ProtoField.int32 ("dji_p3_flyrec.airport_limit_data_lon_int_2", "Lon Int 2", base.DEC)
f.airport_limit_data_point_from_where_2 = ProtoField.uint8 ("dji_p3_flyrec.airport_limit_data_point_from_where_2", "Point From Where 2", base.HEX)
f.airport_limit_data_flag_limit_radius_2 = ProtoField.uint8 ("dji_p3_flyrec.airport_limit_data_flag_limit_radius_2", "Flag Limit Radius 2", base.HEX)
f.airport_limit_data_flag_limit_hi_2 = ProtoField.uint8 ("dji_p3_flyrec.airport_limit_data_flag_limit_hi_2", "Flag Limit Hi 2", base.HEX)
f.airport_limit_data_d2limit_edge_2 = ProtoField.float ("dji_p3_flyrec.airport_limit_data_d2limit_edge_2", "D2Limit Edge 2", base.DEC)
f.airport_limit_data_d2limit_hi_2 = ProtoField.float ("dji_p3_flyrec.airport_limit_data_d2limit_hi_2", "D2Limit Hi 2", base.DEC)
f.airport_limit_data_directx_2 = ProtoField.float ("dji_p3_flyrec.airport_limit_data_directx_2", "Directx 2", base.DEC)
f.airport_limit_data_directy_2 = ProtoField.float ("dji_p3_flyrec.airport_limit_data_directy_2", "Directy 2", base.DEC)

local function flightrec_airport_limit_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.airport_limit_data_area_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airport_limit_data_action_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airport_limit_data_work_point_num, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airport_limit_data_lat_int_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airport_limit_data_lon_int_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airport_limit_data_point_from_where_0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airport_limit_data_flag_limit_radius_0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airport_limit_data_flag_limit_hi_0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airport_limit_data_d2limit_edge_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airport_limit_data_d2limit_hi_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airport_limit_data_directx_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airport_limit_data_directy_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airport_limit_data_lat_int_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airport_limit_data_lon_int_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airport_limit_data_point_from_where_1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airport_limit_data_flag_limit_radius_1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airport_limit_data_flag_limit_hi_1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airport_limit_data_d2limit_edge_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airport_limit_data_d2limit_hi_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airport_limit_data_directx_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airport_limit_data_directy_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airport_limit_data_lat_int_2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airport_limit_data_lon_int_2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airport_limit_data_point_from_where_2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airport_limit_data_flag_limit_radius_2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airport_limit_data_flag_limit_hi_2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airport_limit_data_d2limit_edge_2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airport_limit_data_d2limit_hi_2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airport_limit_data_directx_2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airport_limit_data_directy_2, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 84) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Airport Limit Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Airport Limit Data: Payload size different than expected") end
end

-- Flight log - Fmu Device Run Time - 0x0029

f.fmu_device_run_time_battery = ProtoField.uint32 ("dji_p3_flyrec.fmu_device_run_time_battery", "Battery", base.HEX)
f.fmu_device_run_time_led = ProtoField.uint32 ("dji_p3_flyrec.fmu_device_run_time_led", "Led", base.HEX)
f.fmu_device_run_time_baromter = ProtoField.uint32 ("dji_p3_flyrec.fmu_device_run_time_baromter", "Baromter", base.HEX)
f.fmu_device_run_time_gyro_acc = ProtoField.uint32 ("dji_p3_flyrec.fmu_device_run_time_gyro_acc", "Gyro Acc", base.HEX)
f.fmu_device_run_time_imu = ProtoField.uint32 ("dji_p3_flyrec.fmu_device_run_time_imu", "Imu", base.HEX)
f.fmu_device_run_time_vo = ProtoField.uint32 ("dji_p3_flyrec.fmu_device_run_time_vo", "Vo", base.HEX)
f.fmu_device_run_time_ultrasonic = ProtoField.uint32 ("dji_p3_flyrec.fmu_device_run_time_ultrasonic", "Ultrasonic", base.HEX)
f.fmu_device_run_time_pmu = ProtoField.uint32 ("dji_p3_flyrec.fmu_device_run_time_pmu", "Pmu", base.HEX)
f.fmu_device_run_time_esc = ProtoField.uint32 ("dji_p3_flyrec.fmu_device_run_time_esc", "Esc", base.HEX)
f.fmu_device_run_time_mc = ProtoField.uint32 ("dji_p3_flyrec.fmu_device_run_time_mc", "Mc", base.HEX)
f.fmu_device_run_time_camera = ProtoField.uint32 ("dji_p3_flyrec.fmu_device_run_time_camera", "Camera", base.HEX)
f.fmu_device_run_time_gps = ProtoField.uint32 ("dji_p3_flyrec.fmu_device_run_time_gps", "Gps", base.HEX)
f.fmu_device_run_time_compass = ProtoField.uint32 ("dji_p3_flyrec.fmu_device_run_time_compass", "Compass", base.HEX)
f.fmu_device_run_time_gimbal = ProtoField.uint32 ("dji_p3_flyrec.fmu_device_run_time_gimbal", "Gimbal", base.HEX)
f.fmu_device_run_time_rc = ProtoField.uint32 ("dji_p3_flyrec.fmu_device_run_time_rc", "Rc", base.HEX)
f.fmu_device_run_time_gear = ProtoField.uint32 ("dji_p3_flyrec.fmu_device_run_time_gear", "Gear", base.HEX)

local function flightrec_fmu_device_run_time_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.fmu_device_run_time_battery, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_device_run_time_led, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_device_run_time_baromter, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_device_run_time_gyro_acc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_device_run_time_imu, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_device_run_time_vo, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_device_run_time_ultrasonic, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_device_run_time_pmu, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_device_run_time_esc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_device_run_time_mc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_device_run_time_camera, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_device_run_time_gps, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_device_run_time_compass, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_device_run_time_gimbal, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_device_run_time_rc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_device_run_time_gear, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 64) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Fmu Device Run Time: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Fmu Device Run Time: Payload size different than expected") end
end

-- Flight log - Hp Data - 0x002a

f.hp_data_tgt_hp_alti = ProtoField.float ("dji_p3_flyrec.hp_data_tgt_hp_alti", "Tgt Hp Alti", base.DEC)
f.hp_data_tgt_ang_rate = ProtoField.float ("dji_p3_flyrec.hp_data_tgt_ang_rate", "Tgt Ang Rate", base.DEC, nil, nil, "in degrees")
f.hp_data_tgt_radius = ProtoField.float ("dji_p3_flyrec.hp_data_tgt_radius", "Tgt Radius", base.DEC)
f.hp_data_distance_to_hp = ProtoField.float ("dji_p3_flyrec.hp_data_distance_to_hp", "Distance To Hp", base.DEC)
f.hp_data_cosine_angle = ProtoField.float ("dji_p3_flyrec.hp_data_cosine_angle", "Cosine Angle", base.DEC)
f.hp_data_angle_rate = ProtoField.float ("dji_p3_flyrec.hp_data_angle_rate", "Angle Rate", base.DEC, nil, nil, "in degrees")
f.hp_data_radius = ProtoField.float ("dji_p3_flyrec.hp_data_radius", "Radius", base.DEC)
f.hp_data_pos_error_x = ProtoField.float ("dji_p3_flyrec.hp_data_pos_error_x", "Pos Error X", base.DEC)
f.hp_data_pos_error_y = ProtoField.float ("dji_p3_flyrec.hp_data_pos_error_y", "Pos Error Y", base.DEC)
f.hp_data_pos_error_z = ProtoField.float ("dji_p3_flyrec.hp_data_pos_error_z", "Pos Error Z", base.DEC)
f.hp_data_vel_error_x = ProtoField.float ("dji_p3_flyrec.hp_data_vel_error_x", "Vel Error X", base.DEC)
f.hp_data_vel_error_y = ProtoField.float ("dji_p3_flyrec.hp_data_vel_error_y", "Vel Error Y", base.DEC)
f.hp_data_vel_error_z = ProtoField.float ("dji_p3_flyrec.hp_data_vel_error_z", "Vel Error Z", base.DEC)
f.hp_data_head_error = ProtoField.float ("dji_p3_flyrec.hp_data_head_error", "Head Error", base.DEC, nil, nil, "in degrees")

local function flightrec_hp_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.hp_data_tgt_hp_alti, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hp_data_tgt_ang_rate, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hp_data_tgt_radius, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hp_data_distance_to_hp, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hp_data_cosine_angle, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hp_data_angle_rate, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hp_data_radius, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hp_data_pos_error_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hp_data_pos_error_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hp_data_pos_error_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hp_data_vel_error_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hp_data_vel_error_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hp_data_vel_error_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hp_data_head_error, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 56) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Hp Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Hp Data: Payload size different than expected") end
end

-- Flight log - Follow Me Data - 0x002b

f.follow_me_data_heading_ref = ProtoField.float ("dji_p3_flyrec.follow_me_data_heading_ref", "Heading Ref", base.DEC)
f.follow_me_data_heading_error = ProtoField.float ("dji_p3_flyrec.follow_me_data_heading_error", "Heading Error", base.DEC)
f.follow_me_data_heading_rate = ProtoField.float ("dji_p3_flyrec.follow_me_data_heading_rate", "Heading Rate", base.DEC)
f.follow_me_data_ascending_tgt_height = ProtoField.float ("dji_p3_flyrec.follow_me_data_ascending_tgt_height", "Ascending Tgt Height", base.DEC)
f.follow_me_data_ascending_error = ProtoField.float ("dji_p3_flyrec.follow_me_data_ascending_error", "Ascending Error", base.DEC)
f.follow_me_data_ascending_vel = ProtoField.float ("dji_p3_flyrec.follow_me_data_ascending_vel", "Ascending Vel", base.DEC)
f.follow_me_data_phone_tagt_x = ProtoField.double ("dji_p3_flyrec.follow_me_data_phone_tagt_x", "Phone Tagt X", base.DEC)
f.follow_me_data_phone_tagt_y = ProtoField.double ("dji_p3_flyrec.follow_me_data_phone_tagt_y", "Phone Tagt Y", base.DEC)
f.follow_me_data_quadrotor_cur_x = ProtoField.double ("dji_p3_flyrec.follow_me_data_quadrotor_cur_x", "Quadrotor Cur X", base.DEC)
f.follow_me_data_quadrotor_cur_y = ProtoField.double ("dji_p3_flyrec.follow_me_data_quadrotor_cur_y", "Quadrotor Cur Y", base.DEC)
f.follow_me_data_quadrotor2phone_offset_x = ProtoField.float ("dji_p3_flyrec.follow_me_data_quadrotor2phone_offset_x", "Quadrotor2Phone Offset X", base.DEC)
f.follow_me_data_quadrotor2phone_offset_y = ProtoField.float ("dji_p3_flyrec.follow_me_data_quadrotor2phone_offset_y", "Quadrotor2Phone Offset Y", base.DEC)
f.follow_me_data_quadrotor2phone_distance = ProtoField.float ("dji_p3_flyrec.follow_me_data_quadrotor2phone_distance", "Quadrotor2Phone Distance", base.DEC)
f.follow_me_data_quadrotor2targetpoint_offset_x = ProtoField.float ("dji_p3_flyrec.follow_me_data_quadrotor2targetpoint_offset_x", "Quadrotor2Targetpoint Offset X", base.DEC)
f.follow_me_data_quadrotor2targetpoint_offset_y = ProtoField.float ("dji_p3_flyrec.follow_me_data_quadrotor2targetpoint_offset_y", "Quadrotor2Targetpoint Offset Y", base.DEC)
f.follow_me_data_quadrotor2targetpoint_distance = ProtoField.float ("dji_p3_flyrec.follow_me_data_quadrotor2targetpoint_distance", "Quadrotor2Targetpoint Distance", base.DEC)
f.follow_me_data_tagt_vel_x = ProtoField.float ("dji_p3_flyrec.follow_me_data_tagt_vel_x", "Tagt Vel X", base.DEC)
f.follow_me_data_tagt_vel_y = ProtoField.float ("dji_p3_flyrec.follow_me_data_tagt_vel_y", "Tagt Vel Y", base.DEC)
f.follow_me_data_cur_vel_x = ProtoField.float ("dji_p3_flyrec.follow_me_data_cur_vel_x", "Cur Vel X", base.DEC)
f.follow_me_data_cur_vel_y = ProtoField.float ("dji_p3_flyrec.follow_me_data_cur_vel_y", "Cur Vel Y", base.DEC)
f.follow_me_data_cruise_vel_x = ProtoField.float ("dji_p3_flyrec.follow_me_data_cruise_vel_x", "Cruise Vel X", base.DEC)
f.follow_me_data_cruise_vel_y = ProtoField.float ("dji_p3_flyrec.follow_me_data_cruise_vel_y", "Cruise Vel Y", base.DEC)
f.follow_me_data_fixed_offset_x = ProtoField.float ("dji_p3_flyrec.follow_me_data_fixed_offset_x", "Fixed Offset X", base.DEC)
f.follow_me_data_fixed_offset_y = ProtoField.float ("dji_p3_flyrec.follow_me_data_fixed_offset_y", "Fixed Offset Y", base.DEC)
f.follow_me_data_fixed_distance_offset = ProtoField.float ("dji_p3_flyrec.follow_me_data_fixed_distance_offset", "Fixed Distance Offset", base.DEC)
f.follow_me_data_dist_drone2drone = ProtoField.float ("dji_p3_flyrec.follow_me_data_dist_drone2drone", "Dist Drone2Drone", base.DEC)
f.follow_me_data_dist_phone2phone = ProtoField.float ("dji_p3_flyrec.follow_me_data_dist_phone2phone", "Dist Phone2Phone", base.DEC)
f.follow_me_data_gimbal_ptich_tgt = ProtoField.float ("dji_p3_flyrec.follow_me_data_gimbal_ptich_tgt", "Gimbal Ptich Tgt", base.DEC)
f.follow_me_data_gimbal_pitch_error = ProtoField.float ("dji_p3_flyrec.follow_me_data_gimbal_pitch_error", "Gimbal Pitch Error", base.DEC)
f.follow_me_data_gimbal_pitch_rate = ProtoField.float ("dji_p3_flyrec.follow_me_data_gimbal_pitch_rate", "Gimbal Pitch Rate", base.DEC)
f.follow_me_data_in_height_limit = ProtoField.uint8 ("dji_p3_flyrec.follow_me_data_in_height_limit", "In Height Limit", base.HEX)
f.follow_me_data_target_loss_count = ProtoField.uint8 ("dji_p3_flyrec.follow_me_data_target_loss_count", "Target Loss Count", base.HEX)
f.follow_me_data_mission_status = ProtoField.uint8 ("dji_p3_flyrec.follow_me_data_mission_status", "Mission Status", base.HEX)

f.follow_me_data_fld8B = ProtoField.uint32 ("dji_p3_flyrec.follow_me_data_fld8B", "Unknown 8B", base.HEX)
f.follow_me_data_fld8F = ProtoField.uint32 ("dji_p3_flyrec.follow_me_data_fld8F", "Unknown 8F", base.HEX)
f.follow_me_data_fld93 = ProtoField.uint32 ("dji_p3_flyrec.follow_me_data_fld93", "Unknown 93", base.HEX)
f.follow_me_data_fld97 = ProtoField.uint32 ("dji_p3_flyrec.follow_me_data_fld97", "Unknown 97", base.HEX)
f.follow_me_data_fld9B = ProtoField.double ("dji_p3_flyrec.follow_me_data_fld9B", "Unknown 9B", base.DEC)
f.follow_me_data_fldA3 = ProtoField.double ("dji_p3_flyrec.follow_me_data_fldA3", "Unknown A3", base.DEC)
f.follow_me_data_fldAB = ProtoField.uint32 ("dji_p3_flyrec.follow_me_data_fldAB", "Unknown AB", base.HEX)
f.follow_me_data_fldAf = ProtoField.uint32 ("dji_p3_flyrec.follow_me_data_fldAF", "Unknown AF", base.HEX)

local function flightrec_follow_me_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.follow_me_data_heading_ref, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_heading_error, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_heading_rate, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_ascending_tgt_height, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_ascending_error, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_ascending_vel, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_phone_tagt_x, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.follow_me_data_phone_tagt_y, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.follow_me_data_quadrotor_cur_x, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.follow_me_data_quadrotor_cur_y, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.follow_me_data_quadrotor2phone_offset_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_quadrotor2phone_offset_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_quadrotor2phone_distance, payload(offset, 4)) -- offset = 64
    offset = offset + 4

    subtree:add_le (f.follow_me_data_quadrotor2targetpoint_offset_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_quadrotor2targetpoint_offset_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_quadrotor2targetpoint_distance, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_tagt_vel_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_tagt_vel_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_cur_vel_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_cur_vel_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_cruise_vel_x, payload(offset, 4)) -- offset = 96
    offset = offset + 4

    subtree:add_le (f.follow_me_data_cruise_vel_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_fixed_offset_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_fixed_offset_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_fixed_distance_offset, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_dist_drone2drone, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_dist_phone2phone, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_gimbal_ptich_tgt, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_gimbal_pitch_error, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_gimbal_pitch_rate, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.follow_me_data_in_height_limit, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.follow_me_data_target_loss_count, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.follow_me_data_mission_status, payload(offset, 1))
    offset = offset + 1

    -- Some old packets may stop at offset = 139

    if (payload:len() >= 179) then

        subtree:add_le (f.follow_me_data_fld8B, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.follow_me_data_fld8F, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.follow_me_data_fld93, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.follow_me_data_fld97, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.follow_me_data_fld9B, payload(offset, 8))
        offset = offset + 8

        subtree:add_le (f.follow_me_data_fldA3, payload(offset, 8))
        offset = offset + 8

        subtree:add_le (f.follow_me_data_fldAB, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.follow_me_data_fldAF, payload(offset, 4))
        offset = offset + 4

    end

    if (offset ~= 139) and (offset ~= 179) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Follow Me Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Follow Me Data: Payload size different than expected") end
end

-- Flight log - Home Lock - 0x002c

f.home_lock_unkn0 = ProtoField.float ("dji_p3_flyrec.home_lock_unkn0", "Unknown 0", base.DEC)
f.home_lock_unkn4 = ProtoField.float ("dji_p3_flyrec.home_lock_unkn4", "Unknown 4", base.DEC)
f.home_lock_unkn8 = ProtoField.float ("dji_p3_flyrec.home_lock_unkn8", "Unknown 8", base.DEC)
f.home_lock_unknC = ProtoField.float ("dji_p3_flyrec.home_lock_unknC", "Unknown C", base.DEC)

local function flightrec_home_lock_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.home_lock_unkn0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.home_lock_unkn4, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.home_lock_unkn8, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.home_lock_unknC, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 16) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Home Lock: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Home Lock: Payload size different than expected") end
end

-- Flight log - Imu Data Status - 0x0013

f.imu_data_status_start_fan = ProtoField.uint8 ("dji_p3_flyrec.imu_data_status_start_fan", "Start Fan", base.HEX, nil, nil, "On Ph3, always 1")
f.imu_data_status_led_status = ProtoField.uint8 ("dji_p3_flyrec.imu_data_status_led_status", "Led Status", base.HEX, nil, nil, "On Ph3, always 0")

local function flightrec_imu_data_status_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_data_status_start_fan, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.imu_data_status_led_status, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Data Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Data Status: Payload size different than expected") end
end

-- Flight log - Aircraft Condition Monitor - 0x0046

f.aircraft_condition_monitor_craft_flight_mode = ProtoField.uint8 ("dji_p3_flyrec.aircraft_condition_monitor_craft_flight_mode", "Craft Flight Mode", base.HEX)
f.aircraft_condition_monitor_near_gnd_state = ProtoField.uint8 ("dji_p3_flyrec.aircraft_condition_monitor_near_gnd_state", "Near Gnd State", base.HEX)
f.aircraft_condition_monitor_launch_acc_duration = ProtoField.float ("dji_p3_flyrec.aircraft_condition_monitor_launch_acc_duration", "Launch Acc Duration", base.DEC)
f.aircraft_condition_monitor_launch_delta_v = ProtoField.float ("dji_p3_flyrec.aircraft_condition_monitor_launch_delta_v", "Launch Delta V", base.DEC)
f.aircraft_condition_monitor_launch_state = ProtoField.uint8 ("dji_p3_flyrec.aircraft_condition_monitor_launch_state", "Launch State", base.HEX)
f.aircraft_condition_monitor_thrust_proj_gnd = ProtoField.float ("dji_p3_flyrec.aircraft_condition_monitor_thrust_proj_gnd", "Thrust Proj Gnd", base.DEC)
f.aircraft_condition_monitor_thrust_proj_gnd_compen = ProtoField.float ("dji_p3_flyrec.aircraft_condition_monitor_thrust_proj_gnd_compen", "Thrust Proj Gnd Compen", base.DEC)
f.aircraft_condition_monitor_thrust_compensator = ProtoField.float ("dji_p3_flyrec.aircraft_condition_monitor_thrust_compensator", "Thrust Compensator", base.DEC)
f.aircraft_condition_monitor_hover_thrust = ProtoField.float ("dji_p3_flyrec.aircraft_condition_monitor_hover_thrust", "Hover Thrust", base.DEC)
f.aircraft_condition_monitor_dynamic_thrust = ProtoField.float ("dji_p3_flyrec.aircraft_condition_monitor_dynamic_thrust", "Dynamic Thrust", base.DEC)
f.aircraft_condition_monitor_cos_safe_tilt = ProtoField.float ("dji_p3_flyrec.aircraft_condition_monitor_cos_safe_tilt", "Cos Safe Tilt", base.DEC)
f.aircraft_condition_monitor_safe_tilt = ProtoField.float ("dji_p3_flyrec.aircraft_condition_monitor_safe_tilt", "Safe Tilt", base.DEC)

local function flightrec_aircraft_condition_monitor_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.aircraft_condition_monitor_craft_flight_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.aircraft_condition_monitor_near_gnd_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.aircraft_condition_monitor_launch_acc_duration, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_condition_monitor_launch_delta_v, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_condition_monitor_launch_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.aircraft_condition_monitor_thrust_proj_gnd, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_condition_monitor_thrust_proj_gnd_compen, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_condition_monitor_thrust_compensator, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_condition_monitor_hover_thrust, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_condition_monitor_dynamic_thrust, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_condition_monitor_cos_safe_tilt, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_condition_monitor_safe_tilt, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 39) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Aircraft Condition Monitor: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Aircraft Condition Monitor: Payload size different than expected") end
end

-- Flight log - Aircraft Model - 0x0050

f.aircraft_model_m1_current = ProtoField.float ("dji_p3_flyrec.aircraft_model_m1_current", "M1 Current", base.DEC)
f.aircraft_model_m1_w = ProtoField.float ("dji_p3_flyrec.aircraft_model_m1_w", "M1 W", base.DEC)
f.aircraft_model_m1_lift = ProtoField.float ("dji_p3_flyrec.aircraft_model_m1_lift", "M1 Lift", base.DEC)
f.aircraft_model_m1_torque = ProtoField.float ("dji_p3_flyrec.aircraft_model_m1_torque", "M1 Torque", base.DEC)
f.aircraft_model_m2_current = ProtoField.float ("dji_p3_flyrec.aircraft_model_m2_current", "M2 Current", base.DEC)
f.aircraft_model_m2_w = ProtoField.float ("dji_p3_flyrec.aircraft_model_m2_w", "M2 W", base.DEC)
f.aircraft_model_m2_lift = ProtoField.float ("dji_p3_flyrec.aircraft_model_m2_lift", "M2 Lift", base.DEC)
f.aircraft_model_m2_torque = ProtoField.float ("dji_p3_flyrec.aircraft_model_m2_torque", "M2 Torque", base.DEC)
f.aircraft_model_m3_current = ProtoField.float ("dji_p3_flyrec.aircraft_model_m3_current", "M3 Current", base.DEC)
f.aircraft_model_m3_w = ProtoField.float ("dji_p3_flyrec.aircraft_model_m3_w", "M3 W", base.DEC)
f.aircraft_model_m3_lift = ProtoField.float ("dji_p3_flyrec.aircraft_model_m3_lift", "M3 Lift", base.DEC)
f.aircraft_model_m3_torque = ProtoField.float ("dji_p3_flyrec.aircraft_model_m3_torque", "M3 Torque", base.DEC)
f.aircraft_model_m4_current = ProtoField.float ("dji_p3_flyrec.aircraft_model_m4_current", "M4 Current", base.DEC)
f.aircraft_model_m4_w = ProtoField.float ("dji_p3_flyrec.aircraft_model_m4_w", "M4 W", base.DEC)
f.aircraft_model_m4_lift = ProtoField.float ("dji_p3_flyrec.aircraft_model_m4_lift", "M4 Lift", base.DEC)
f.aircraft_model_m4_torque = ProtoField.float ("dji_p3_flyrec.aircraft_model_m4_torque", "M4 Torque", base.DEC)
f.aircraft_model_m5_current = ProtoField.float ("dji_p3_flyrec.aircraft_model_m5_current", "M5 Current", base.DEC)
f.aircraft_model_m5_w = ProtoField.float ("dji_p3_flyrec.aircraft_model_m5_w", "M5 W", base.DEC)
f.aircraft_model_m5_lift = ProtoField.float ("dji_p3_flyrec.aircraft_model_m5_lift", "M5 Lift", base.DEC)
f.aircraft_model_m5_torque = ProtoField.float ("dji_p3_flyrec.aircraft_model_m5_torque", "M5 Torque", base.DEC)
f.aircraft_model_m6_current = ProtoField.float ("dji_p3_flyrec.aircraft_model_m6_current", "M6 Current", base.DEC)
f.aircraft_model_m6_w = ProtoField.float ("dji_p3_flyrec.aircraft_model_m6_w", "M6 W", base.DEC)
f.aircraft_model_m6_lift = ProtoField.float ("dji_p3_flyrec.aircraft_model_m6_lift", "M6 Lift", base.DEC)
f.aircraft_model_m6_torque = ProtoField.float ("dji_p3_flyrec.aircraft_model_m6_torque", "M6 Torque", base.DEC)
f.aircraft_model_m7_current = ProtoField.float ("dji_p3_flyrec.aircraft_model_m7_current", "M7 Current", base.DEC)
f.aircraft_model_m7_w = ProtoField.float ("dji_p3_flyrec.aircraft_model_m7_w", "M7 W", base.DEC)
f.aircraft_model_m7_lift = ProtoField.float ("dji_p3_flyrec.aircraft_model_m7_lift", "M7 Lift", base.DEC)
f.aircraft_model_m7_torque = ProtoField.float ("dji_p3_flyrec.aircraft_model_m7_torque", "M7 Torque", base.DEC)
f.aircraft_model_m8_current = ProtoField.float ("dji_p3_flyrec.aircraft_model_m8_current", "M8 Current", base.DEC)
f.aircraft_model_m8_w = ProtoField.float ("dji_p3_flyrec.aircraft_model_m8_w", "M8 W", base.DEC)
f.aircraft_model_m8_lift = ProtoField.float ("dji_p3_flyrec.aircraft_model_m8_lift", "M8 Lift", base.DEC)
f.aircraft_model_m8_torque = ProtoField.float ("dji_p3_flyrec.aircraft_model_m8_torque", "M8 Torque", base.DEC)

local function flightrec_aircraft_model_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.aircraft_model_m1_current, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m1_w, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m1_lift, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m1_torque, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m2_current, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m2_w, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m2_lift, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m2_torque, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m3_current, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m3_w, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m3_lift, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m3_torque, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m4_current, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m4_w, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m4_lift, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m4_torque, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m5_current, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m5_w, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m5_lift, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m5_torque, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m6_current, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m6_w, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m6_lift, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m6_torque, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m7_current, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m7_w, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m7_lift, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m7_torque, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m8_current, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m8_w, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m8_lift, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.aircraft_model_m8_torque, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 128) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Aircraft Model: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Aircraft Model: Payload size different than expected") end
end

-- Flight log - Go Home Info - 0x005a

f.go_home_info_go_home_stage = ProtoField.uint8 ("dji_p3_flyrec.go_home_info_go_home_stage", "Go Home Stage", base.HEX)
f.go_home_info_go_home_timer = ProtoField.float ("dji_p3_flyrec.go_home_info_go_home_timer", "Go Home Timer", base.DEC)
f.go_home_info_dis_to_home_x = ProtoField.float ("dji_p3_flyrec.go_home_info_dis_to_home_x", "Dis To Home X", base.DEC)
f.go_home_info_dis_to_home_y = ProtoField.float ("dji_p3_flyrec.go_home_info_dis_to_home_y", "Dis To Home Y", base.DEC)
--f.go_home_info_e_dis_to_home = ProtoField.none ("dji_p3_flyrec.go_home_info_e_dis_to_home", "E Dis To Home", base.NONE, nil, nil, "sqrt(dis_to_home_x*dis_to_home_x+dis_to_home_y*dis_to_home_y)")

local function flightrec_go_home_info_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.go_home_info_go_home_stage, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.go_home_info_go_home_timer, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.go_home_info_dis_to_home_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.go_home_info_dis_to_home_y, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 13) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Go Home Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Go Home Info: Payload size different than expected") end
end

-- Flight log - New Mvo Feedback - 0x001d

f.new_mvo_feedback_visionobservationcount = ProtoField.uint16 ("dji_p3_flyrec.new_mvo_feedback_visionobservationcount", "Vision Observation Count", base.HEX)
f.new_mvo_feedback_vel_x = ProtoField.int16 ("dji_p3_flyrec.new_mvo_feedback_vel_x", "Vel X", base.DEC)
f.new_mvo_feedback_vel_y = ProtoField.int16 ("dji_p3_flyrec.new_mvo_feedback_vel_y", "Vel Y", base.DEC)
f.new_mvo_feedback_vel_z = ProtoField.int16 ("dji_p3_flyrec.new_mvo_feedback_vel_z", "Vel Z", base.DEC)
f.new_mvo_feedback_pos_x = ProtoField.float ("dji_p3_flyrec.new_mvo_feedback_pos_x", "Pos X", base.DEC)
f.new_mvo_feedback_pos_y = ProtoField.float ("dji_p3_flyrec.new_mvo_feedback_pos_y", "Pos Y", base.DEC)
f.new_mvo_feedback_pos_z = ProtoField.float ("dji_p3_flyrec.new_mvo_feedback_pos_z", "Pos Z", base.DEC)
f.new_mvo_feedback_hoverpointuncertainty1 = ProtoField.float ("dji_p3_flyrec.new_mvo_feedback_hoverpointuncertainty1", "Hover Point Uncertainty 1", base.DEC)
f.new_mvo_feedback_hoverpointuncertainty2 = ProtoField.float ("dji_p3_flyrec.new_mvo_feedback_hoverpointuncertainty2", "Hover Point Uncertainty 2", base.DEC)
f.new_mvo_feedback_hoverpointuncertainty3 = ProtoField.float ("dji_p3_flyrec.new_mvo_feedback_hoverpointuncertainty3", "Hover Point Uncertainty 3", base.DEC)
f.new_mvo_feedback_hoverpointuncertainty4 = ProtoField.float ("dji_p3_flyrec.new_mvo_feedback_hoverpointuncertainty4", "Hover Point Uncertainty 4", base.DEC)
f.new_mvo_feedback_hoverpointuncertainty5 = ProtoField.float ("dji_p3_flyrec.new_mvo_feedback_hoverpointuncertainty5", "Hover Point Uncertainty 5", base.DEC)
f.new_mvo_feedback_hoverpointuncertainty6 = ProtoField.float ("dji_p3_flyrec.new_mvo_feedback_hoverpointuncertainty6", "Hover Point Uncertainty 6", base.DEC)
f.new_mvo_feedback_velocityuncertainty1 = ProtoField.float ("dji_p3_flyrec.new_mvo_feedback_velocityuncertainty1", "Velocity Uncertainty 1", base.DEC)
f.new_mvo_feedback_velocityuncertainty2 = ProtoField.float ("dji_p3_flyrec.new_mvo_feedback_velocityuncertainty2", "Velocity Uncertainty 2", base.DEC)
f.new_mvo_feedback_velocityuncertainty3 = ProtoField.float ("dji_p3_flyrec.new_mvo_feedback_velocityuncertainty3", "Velocity Uncertainty 3", base.DEC)
f.new_mvo_feedback_velocityuncertainty4 = ProtoField.float ("dji_p3_flyrec.new_mvo_feedback_velocityuncertainty4", "Velocity Uncertainty 4", base.DEC)
f.new_mvo_feedback_velocityuncertainty5 = ProtoField.float ("dji_p3_flyrec.new_mvo_feedback_velocityuncertainty5", "Velocity Uncertainty 5", base.DEC)
f.new_mvo_feedback_velocityuncertainty6 = ProtoField.float ("dji_p3_flyrec.new_mvo_feedback_velocityuncertainty6", "Velocity Uncertainty 6", base.DEC)
f.new_mvo_feedback_height = ProtoField.float ("dji_p3_flyrec.new_mvo_feedback_height", "Height", base.DEC)
f.new_mvo_feedback_heightuncertainty = ProtoField.float ("dji_p3_flyrec.new_mvo_feedback_heightuncertainty", "Height Uncertainty", base.DEC)
f.new_mvo_feedback_reserved1 = ProtoField.uint8 ("dji_p3_flyrec.new_mvo_feedback_reserved1", "Reserved1", base.HEX)
  f.new_mvo_feedback_e_new_mvo_px_flag = ProtoField.uint8 ("dji_p3_flyrec.new_mvo_feedback_e_new_mvo_px_flag", "E New Mvo Px Flag", base.HEX, nil, 0x10, nil)
  f.new_mvo_feedback_e_new_mvo_py_flag = ProtoField.uint8 ("dji_p3_flyrec.new_mvo_feedback_e_new_mvo_py_flag", "E New Mvo Py Flag", base.HEX, nil, 0x20, nil)
  f.new_mvo_feedback_e_new_mvo_pz_flag = ProtoField.uint8 ("dji_p3_flyrec.new_mvo_feedback_e_new_mvo_pz_flag", "E New Mvo Pz Flag", base.HEX, nil, 0x40, nil)
  f.new_mvo_feedback_e_new_mvo_vx_flag = ProtoField.uint8 ("dji_p3_flyrec.new_mvo_feedback_e_new_mvo_vx_flag", "E New Mvo Vx Flag", base.HEX, nil, 0x01, nil)
  f.new_mvo_feedback_e_new_mvo_vy_flag = ProtoField.uint8 ("dji_p3_flyrec.new_mvo_feedback_e_new_mvo_vy_flag", "E New Mvo Vy Flag", base.HEX, nil, 0x02, nil)
  f.new_mvo_feedback_e_new_mvo_vz_flag = ProtoField.uint8 ("dji_p3_flyrec.new_mvo_feedback_e_new_mvo_vz_flag", "E New Mvo Vz Flag", base.HEX, nil, 0x04, nil)
f.new_mvo_feedback_reserved2 = ProtoField.uint8 ("dji_p3_flyrec.new_mvo_feedback_reserved2", "Reserved2", base.HEX)
f.new_mvo_feedback_reserved3 = ProtoField.uint8 ("dji_p3_flyrec.new_mvo_feedback_reserved3", "Reserved3", base.HEX)
f.new_mvo_feedback_reserved4 = ProtoField.uint8 ("dji_p3_flyrec.new_mvo_feedback_reserved4", "Reserved4", base.HEX)

local function flightrec_new_mvo_feedback_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.new_mvo_feedback_visionobservationcount, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.new_mvo_feedback_vel_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.new_mvo_feedback_vel_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.new_mvo_feedback_vel_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.new_mvo_feedback_pos_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.new_mvo_feedback_pos_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.new_mvo_feedback_pos_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.new_mvo_feedback_hoverpointuncertainty1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.new_mvo_feedback_hoverpointuncertainty2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.new_mvo_feedback_hoverpointuncertainty3, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.new_mvo_feedback_hoverpointuncertainty4, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.new_mvo_feedback_hoverpointuncertainty5, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.new_mvo_feedback_hoverpointuncertainty6, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.new_mvo_feedback_velocityuncertainty1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.new_mvo_feedback_velocityuncertainty2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.new_mvo_feedback_velocityuncertainty3, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.new_mvo_feedback_velocityuncertainty4, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.new_mvo_feedback_velocityuncertainty5, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.new_mvo_feedback_velocityuncertainty6, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.new_mvo_feedback_height, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.new_mvo_feedback_heightuncertainty, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.new_mvo_feedback_reserved1, payload(offset, 1))
    subtree:add_le (f.new_mvo_feedback_e_new_mvo_px_flag, payload(offset, 1))
    subtree:add_le (f.new_mvo_feedback_e_new_mvo_py_flag, payload(offset, 1))
    subtree:add_le (f.new_mvo_feedback_e_new_mvo_pz_flag, payload(offset, 1))
    subtree:add_le (f.new_mvo_feedback_e_new_mvo_vx_flag, payload(offset, 1))
    subtree:add_le (f.new_mvo_feedback_e_new_mvo_vy_flag, payload(offset, 1))
    subtree:add_le (f.new_mvo_feedback_e_new_mvo_vz_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.new_mvo_feedback_reserved2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.new_mvo_feedback_reserved3, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.new_mvo_feedback_reserved4, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 80) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"New Mvo Feedback: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"New Mvo Feedback: Payload size different than expected") end
end

-- Flight log - Svo Avoid Obstacle - 0x0064

f.svo_avoid_obstacle_svo_stop_flag = ProtoField.uint8 ("dji_p3_flyrec.svo_avoid_obstacle_svo_stop_flag", "Svo Stop Flag", base.HEX)
  f.svo_avoid_obstacle_svo_stop_flag = ProtoField.uint8 ("dji_p3_flyrec.svo_avoid_obstacle_svo_stop_flag", "Svo Stop Flag", base.HEX, nil, 0x01, nil)
  f.svo_avoid_obstacle_svo_work_flag = ProtoField.uint8 ("dji_p3_flyrec.svo_avoid_obstacle_svo_work_flag", "Svo Work Flag", base.HEX, nil, 0x02, nil)
  f.svo_avoid_obstacle_svo_en_flag = ProtoField.uint8 ("dji_p3_flyrec.svo_avoid_obstacle_svo_en_flag", "Svo En Flag", base.HEX, nil, 0x04, nil)
f.svo_avoid_obstacle_svo_p_front = ProtoField.uint16 ("dji_p3_flyrec.svo_avoid_obstacle_svo_p_front", "Svo P Front", base.HEX, nil, nil, "Obstacle distance detected by front camera; unit:cm")
f.svo_avoid_obstacle_svo_p_right = ProtoField.uint16 ("dji_p3_flyrec.svo_avoid_obstacle_svo_p_right", "Svo P Right", base.HEX, nil, nil, "Obstacle distance detected by right camera; unit:cm")
f.svo_avoid_obstacle_svo_p_back = ProtoField.uint16 ("dji_p3_flyrec.svo_avoid_obstacle_svo_p_back", "Svo P Back", base.HEX, nil, nil, "Obstacle distance detected by back camera; unit:cm")
f.svo_avoid_obstacle_svo_p_left = ProtoField.uint16 ("dji_p3_flyrec.svo_avoid_obstacle_svo_p_left", "Svo P Left", base.HEX, nil, nil, "Obstacle distance detected by left camera; unit:cm")
f.svo_avoid_obstacle_svo_v_limit = ProtoField.uint8 ("dji_p3_flyrec.svo_avoid_obstacle_svo_v_limit", "Svo V Limit", base.HEX)
f.svo_avoid_obstacle_svo_cnt = ProtoField.uint8 ("dji_p3_flyrec.svo_avoid_obstacle_svo_cnt", "Svo Cnt", base.HEX)

local function flightrec_svo_avoid_obstacle_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.svo_avoid_obstacle_svo_stop_flag, payload(offset, 1))
    subtree:add_le (f.svo_avoid_obstacle_svo_stop_flag, payload(offset, 1))
    subtree:add_le (f.svo_avoid_obstacle_svo_work_flag, payload(offset, 1))
    subtree:add_le (f.svo_avoid_obstacle_svo_en_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_avoid_obstacle_svo_p_front, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.svo_avoid_obstacle_svo_p_right, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.svo_avoid_obstacle_svo_p_back, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.svo_avoid_obstacle_svo_p_left, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.svo_avoid_obstacle_svo_v_limit, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_avoid_obstacle_svo_cnt, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 11) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Svo Avoid Obstacle: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Svo Avoid Obstacle: Payload size different than expected") end
end

-- Flight log - Rtkdata - 0xcff1

f.rtkdata_lat = ProtoField.int32 ("dji_p3_flyrec.rtkdata_lat", "Lat", base.DEC)
f.rtkdata_lon = ProtoField.int32 ("dji_p3_flyrec.rtkdata_lon", "Lon", base.DEC)
f.rtkdata_height = ProtoField.int32 ("dji_p3_flyrec.rtkdata_height", "Height", base.DEC)
f.rtkdata_satnum = ProtoField.uint16 ("dji_p3_flyrec.rtkdata_satnum", "Satnum", base.HEX)
f.rtkdata_postype = ProtoField.uint16 ("dji_p3_flyrec.rtkdata_postype", "Postype", base.HEX)
f.rtkdata_reserve1 = ProtoField.int32 ("dji_p3_flyrec.rtkdata_reserve1", "Reserve1", base.DEC)
f.rtkdata_reserve2 = ProtoField.int32 ("dji_p3_flyrec.rtkdata_reserve2", "Reserve2", base.DEC)
f.rtkdata_reserve3 = ProtoField.int32 ("dji_p3_flyrec.rtkdata_reserve3", "Reserve3", base.DEC)
f.rtkdata_reserve4 = ProtoField.int32 ("dji_p3_flyrec.rtkdata_reserve4", "Reserve4", base.DEC)
f.rtkdata_reserve5 = ProtoField.int32 ("dji_p3_flyrec.rtkdata_reserve5", "Reserve5", base.DEC)
f.rtkdata_reserve6 = ProtoField.int32 ("dji_p3_flyrec.rtkdata_reserve6", "Reserve6", base.DEC)
f.rtkdata_reserve7 = ProtoField.int32 ("dji_p3_flyrec.rtkdata_reserve7", "Reserve7", base.DEC)
f.rtkdata_reserve8 = ProtoField.int32 ("dji_p3_flyrec.rtkdata_reserve8", "Reserve8", base.DEC)
f.rtkdata_reserve9 = ProtoField.int32 ("dji_p3_flyrec.rtkdata_reserve9", "Reserve9", base.DEC)
f.rtkdata_reserve10 = ProtoField.int32 ("dji_p3_flyrec.rtkdata_reserve10", "Reserve10", base.DEC)
f.rtkdata_cntrtk = ProtoField.uint32 ("dji_p3_flyrec.rtkdata_cntrtk", "Cntrtk", base.HEX)

local function flightrec_rtkdata_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.rtkdata_lat, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_lon, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_height, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_satnum, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rtkdata_postype, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rtkdata_reserve1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_reserve2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_reserve3, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_reserve4, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_reserve5, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_reserve6, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_reserve7, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_reserve8, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_reserve9, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_reserve10, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_cntrtk, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 60) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Rtkdata: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Rtkdata: Payload size different than expected") end
end

-- Flight log - Gear Debug Info - 0x006e

f.gear_debug_info_gear_mode = ProtoField.uint8 ("dji_p3_flyrec.gear_debug_info_gear_mode", "Gear Mode", base.HEX)
f.gear_debug_info_gear_state = ProtoField.uint8 ("dji_p3_flyrec.gear_debug_info_gear_state", "Gear State", base.HEX)
f.gear_debug_info_gear_cmd = ProtoField.uint8 ("dji_p3_flyrec.gear_debug_info_gear_cmd", "Gear Cmd", base.HEX)
f.gear_debug_info_gear_speed = ProtoField.uint8 ("dji_p3_flyrec.gear_debug_info_gear_speed", "Gear Speed", base.HEX)
f.gear_debug_info_gear_counter = ProtoField.uint32 ("dji_p3_flyrec.gear_debug_info_gear_counter", "Gear Counter", base.HEX)
f.gear_debug_info_gear_pack_flag = ProtoField.uint8 ("dji_p3_flyrec.gear_debug_info_gear_pack_flag", "Gear Pack Flag", base.HEX)
f.gear_debug_info_gear_pack_req = ProtoField.uint8 ("dji_p3_flyrec.gear_debug_info_gear_pack_req", "Gear Pack Req", base.HEX)
f.gear_debug_info_gear_pack_type = ProtoField.uint8 ("dji_p3_flyrec.gear_debug_info_gear_pack_type", "Gear Pack Type", base.HEX)
f.gear_debug_info_gear_pack_state = ProtoField.uint8 ("dji_p3_flyrec.gear_debug_info_gear_pack_state", "Gear Pack State", base.HEX)
f.gear_debug_info_gear_pack_manual_cmd = ProtoField.uint8 ("dji_p3_flyrec.gear_debug_info_gear_pack_manual_cmd", "Gear Pack Manual Cmd", base.HEX)
f.gear_debug_info_gear_rc_cmd = ProtoField.uint8 ("dji_p3_flyrec.gear_debug_info_gear_rc_cmd", "Gear Rc Cmd", base.HEX)
f.gear_debug_info_gear_app_req = ProtoField.uint8 ("dji_p3_flyrec.gear_debug_info_gear_app_req", "Gear App Req", base.HEX)
f.gear_debug_info_gear_app_cmd = ProtoField.uint8 ("dji_p3_flyrec.gear_debug_info_gear_app_cmd", "Gear App Cmd", base.HEX)
f.gear_debug_info_gear_rc_raw_input = ProtoField.int16 ("dji_p3_flyrec.gear_debug_info_gear_rc_raw_input", "Gear Rc Raw Input", base.DEC)

local function flightrec_gear_debug_info_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.gear_debug_info_gear_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gear_debug_info_gear_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gear_debug_info_gear_cmd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gear_debug_info_gear_speed, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gear_debug_info_gear_counter, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gear_debug_info_gear_pack_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gear_debug_info_gear_pack_req, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gear_debug_info_gear_pack_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gear_debug_info_gear_pack_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gear_debug_info_gear_pack_manual_cmd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gear_debug_info_gear_rc_cmd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gear_debug_info_gear_app_req, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gear_debug_info_gear_app_cmd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gear_debug_info_gear_rc_raw_input, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 18) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gear Debug Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gear Debug Info: Payload size different than expected") end
end

-- Flight log - Svo Ctrl Debug - 0x0066

f.svo_ctrl_debug_svo_avoid_debug0_limit_en = ProtoField.uint8 ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug0_limit_en", "Svo Avoid Debug0 Limit En", base.HEX)
f.svo_ctrl_debug_svo_avoid_debug0_d_craft2edge = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug0_d_craft2edge", "Svo Avoid Debug0 D Craft2Edge", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug0_limit_direct_0 = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug0_limit_direct_0", "Svo Avoid Debug0 Limit Direct 0", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug0_limit_direct_1 = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug0_limit_direct_1", "Svo Avoid Debug0 Limit Direct 1", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug0_limit_norm = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug0_limit_norm", "Svo Avoid Debug0 Limit Norm", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug0_damping_scale = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug0_damping_scale", "Svo Avoid Debug0 Damping Scale", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug1_limit_en = ProtoField.uint8 ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug1_limit_en", "Svo Avoid Debug1 Limit En", base.HEX)
f.svo_ctrl_debug_svo_avoid_debug1_d_craft2edge = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug1_d_craft2edge", "Svo Avoid Debug1 D Craft2Edge", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug1_limit_direct_0 = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug1_limit_direct_0", "Svo Avoid Debug1 Limit Direct 0", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug1_limit_direct_1 = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug1_limit_direct_1", "Svo Avoid Debug1 Limit Direct 1", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug1_limit_norm = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug1_limit_norm", "Svo Avoid Debug1 Limit Norm", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug1_damping_scale = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug1_damping_scale", "Svo Avoid Debug1 Damping Scale", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug2_limit_en = ProtoField.uint8 ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug2_limit_en", "Svo Avoid Debug2 Limit En", base.HEX)
f.svo_ctrl_debug_svo_avoid_debug2_d_craft2edge = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug2_d_craft2edge", "Svo Avoid Debug2 D Craft2Edge", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug2_limit_direct_0 = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug2_limit_direct_0", "Svo Avoid Debug2 Limit Direct 0", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug2_limit_direct_1 = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug2_limit_direct_1", "Svo Avoid Debug2 Limit Direct 1", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug2_limit_norm = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug2_limit_norm", "Svo Avoid Debug2 Limit Norm", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug2_damping_scale = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug2_damping_scale", "Svo Avoid Debug2 Damping Scale", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug3_limit_en = ProtoField.uint8 ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug3_limit_en", "Svo Avoid Debug3 Limit En", base.HEX)
f.svo_ctrl_debug_svo_avoid_debug3_d_craft2edge = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug3_d_craft2edge", "Svo Avoid Debug3 D Craft2Edge", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug3_limit_direct_0 = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug3_limit_direct_0", "Svo Avoid Debug3 Limit Direct 0", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug3_limit_direct_1 = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug3_limit_direct_1", "Svo Avoid Debug3 Limit Direct 1", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug3_limit_norm = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug3_limit_norm", "Svo Avoid Debug3 Limit Norm", base.DEC)
f.svo_ctrl_debug_svo_avoid_debug3_damping_scale = ProtoField.float ("dji_p3_flyrec.svo_ctrl_debug_svo_avoid_debug3_damping_scale", "Svo Avoid Debug3 Damping Scale", base.DEC)

local function flightrec_svo_ctrl_debug_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug0_limit_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug0_d_craft2edge, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug0_limit_direct_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug0_limit_direct_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug0_limit_norm, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug0_damping_scale, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug1_limit_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug1_d_craft2edge, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug1_limit_direct_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug1_limit_direct_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug1_limit_norm, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug1_damping_scale, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug2_limit_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug2_d_craft2edge, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug2_limit_direct_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug2_limit_direct_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug2_limit_norm, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug2_damping_scale, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug3_limit_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug3_d_craft2edge, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug3_limit_direct_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug3_limit_direct_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug3_limit_norm, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.svo_ctrl_debug_svo_avoid_debug3_damping_scale, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 84) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Svo Ctrl Debug: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Svo Ctrl Debug: Payload size different than expected") end
end

-- Flight log - Waypoint Debug - 0x00a0

f.waypoint_debug_wp_mission_status = ProtoField.uint8 ("dji_p3_flyrec.waypoint_debug_wp_mission_status", "Wp Mission Status", base.HEX)
f.waypoint_debug_wp_cur_num = ProtoField.uint8 ("dji_p3_flyrec.waypoint_debug_wp_cur_num", "Wp Cur Num", base.HEX)
f.waypoint_debug_wp_tgt_vel = ProtoField.uint16 ("dji_p3_flyrec.waypoint_debug_wp_tgt_vel", "Wp Tgt Vel", base.HEX)
f.waypoint_debug_wp_fld04 = ProtoField.uint16 ("dji_p3_flyrec.waypoint_debug_wp_fld04", "Wp Field 04", base.HEX)
f.waypoint_debug_wp_fld06 = ProtoField.uint8 ("dji_p3_flyrec.waypoint_debug_wp_fld06", "Wp Field 06", base.HEX)
f.waypoint_debug_wp_fld08 = ProtoField.uint16 ("dji_p3_flyrec.waypoint_debug_wp_fld08", "Wp Field 08", base.HEX)
f.waypoint_debug_wp_fld0A = ProtoField.uint32 ("dji_p3_flyrec.waypoint_debug_wp_fld0A", "Wp Field 0A", base.HEX)
f.waypoint_debug_wp_fld0E = ProtoField.uint32 ("dji_p3_flyrec.waypoint_debug_wp_fld0E", "Wp Field 0E", base.HEX)
f.waypoint_debug_wp_fld14 = ProtoField.uint32 ("dji_p3_flyrec.waypoint_debug_wp_fld14", "Wp Field 14", base.HEX)
f.waypoint_debug_wp_fld18 = ProtoField.uint32 ("dji_p3_flyrec.waypoint_debug_wp_fld18", "Wp Field 18", base.HEX)
f.waypoint_debug_wp_fld1C = ProtoField.uint32 ("dji_p3_flyrec.waypoint_debug_wp_fld1C", "Wp Field 1C", base.HEX)
f.waypoint_debug_wp_fld20 = ProtoField.uint32 ("dji_p3_flyrec.waypoint_debug_wp_fld20", "Wp Field 20", base.HEX)
f.waypoint_debug_wp_fld24 = ProtoField.uint32 ("dji_p3_flyrec.waypoint_debug_wp_fld24", "Wp Field 24", base.HEX)
f.waypoint_debug_wp_fld28 = ProtoField.uint32 ("dji_p3_flyrec.waypoint_debug_wp_fld28", "Wp Field 28", base.HEX)
f.waypoint_debug_wp_fld2C = ProtoField.uint32 ("dji_p3_flyrec.waypoint_debug_wp_fld2C", "Wp Field 2C", base.HEX)
f.waypoint_debug_wp_fld30 = ProtoField.uint8 ("dji_p3_flyrec.waypoint_debug_wp_fld30", "Wp Field 30", base.HEX)
--f.waypoint_debug_e_gps_lat = ProtoField.none ("dji_p3_flyrec.waypoint_debug_e_gps_lat", "E Gps Lat", base.NONE, nil, nil, "(gps_lat-225400000)/10000000*3.1415926/180*6370000")
--f.waypoint_debug_e_gps_lon = ProtoField.none ("dji_p3_flyrec.waypoint_debug_e_gps_lon", "E Gps Lon", base.NONE, nil, nil, "(gps_lon-1139468000)/10000000*3.1415926/180*6370000*cos(0.3933972)")
--f.waypoint_debug_e_atti_lat = ProtoField.none ("dji_p3_flyrec.waypoint_debug_e_atti_lat", "E Atti Lat", base.NONE, nil, nil, "(lati-0.3933972)*6370000")
--f.waypoint_debug_e_atti_lon = ProtoField.none ("dji_p3_flyrec.waypoint_debug_e_atti_lon", "E Atti Lon", base.NONE, nil, nil, "(longti-1.9887468)*6370000*cos(0.3933972)")
--f.waypoint_debug_neg_mvo_vx = ProtoField.none ("dji_p3_flyrec.waypoint_debug_neg_mvo_vx", "Neg Mvo Vx", base.NONE, nil, nil, "(Vel_X/1000*cos(E_yaw*3.1415926/180)+Vel_Y/1000*sin(-E_yaw*3.1415926/180))")
--f.waypoint_debug_neg_mvo_vy = ProtoField.none ("dji_p3_flyrec.waypoint_debug_neg_mvo_vy", "Neg Mvo Vy", base.NONE, nil, nil, "(Vel_X/1000*sin(E_yaw*3.1415926/180)+Vel_Y/1000*cos(E_yaw*3.1415926/180))")
--f.waypoint_debug_neg_mvo_vz = ProtoField.none ("dji_p3_flyrec.waypoint_debug_neg_mvo_vz", "Neg Mvo Vz", base.NONE, nil, nil, "Vel_Z/1000")
--f.waypoint_debug_e_acc_norm = ProtoField.none ("dji_p3_flyrec.waypoint_debug_e_acc_norm", "E Acc Norm", base.NONE, nil, nil, "sqrt(acc_x^2+acc_y^2+acc_z^2)")
--f.waypoint_debug_e_horizon_speed = ProtoField.none ("dji_p3_flyrec.waypoint_debug_e_horizon_speed", "E Horizon Speed", base.NONE, nil, nil, "sqrt(vg_x^2+vg_y^2)")

local function flightrec_waypoint_debug_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.waypoint_debug_wp_mission_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.waypoint_debug_wp_cur_num, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.waypoint_debug_wp_tgt_vel, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.waypoint_debug_wp_fld04, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.waypoint_debug_wp_fld06, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.waypoint_debug_wp_fld08, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.waypoint_debug_wp_fld0A, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.waypoint_debug_wp_fld0E, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.waypoint_debug_wp_fld14, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.waypoint_debug_wp_fld18, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.waypoint_debug_wp_fld1C, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.waypoint_debug_wp_fld20, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.waypoint_debug_wp_fld24, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.waypoint_debug_wp_fld28, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.waypoint_debug_wp_fld2C, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.waypoint_debug_wp_fld30, payload(offset, 1))
    offset = offset + 1

    -- This struct is sometimes seen as size=44; needs checking what is that version
    if (offset ~= 46) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Waypoint Debug: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Waypoint Debug: Payload size different than expected") end
end

-- Flight log - Unknown - 0xa000

f.unkn_a000_field0 = ProtoField.float ("dji_p3_flyrec.unkn_a000_field0", "Field 0", base.HEX)
f.unkn_a000_field4 = ProtoField.float ("dji_p3_flyrec.unkn_a000_field4", "Field 4", base.HEX)
f.unkn_a000_field8 = ProtoField.float ("dji_p3_flyrec.unkn_a000_field8", "Field 8", base.HEX)
f.unkn_a000_fieldC = ProtoField.float ("dji_p3_flyrec.unkn_a000_fieldC", "Field C", base.HEX)
f.unkn_a000_field10 = ProtoField.float ("dji_p3_flyrec.unkn_a000_field10", "Field 10", base.HEX)
f.unkn_a000_field14 = ProtoField.float ("dji_p3_flyrec.unkn_a000_field14", "Field 14", base.HEX)
f.unkn_a000_field18 = ProtoField.float ("dji_p3_flyrec.unkn_a000_field18", "Field 18", base.HEX)
f.unkn_a000_field1C = ProtoField.float ("dji_p3_flyrec.unkn_a000_field1C", "Field 1C", base.HEX)
f.unkn_a000_field20 = ProtoField.float ("dji_p3_flyrec.unkn_a000_field20", "Field 20", base.HEX)
f.unkn_a000_field24 = ProtoField.float ("dji_p3_flyrec.unkn_a000_field24", "Field 24", base.HEX)
f.unkn_a000_field28 = ProtoField.float ("dji_p3_flyrec.unkn_a000_field28", "Field 28", base.HEX)
f.unkn_a000_field2C = ProtoField.float ("dji_p3_flyrec.unkn_a000_field2C", "Field 2C", base.HEX)
f.unkn_a000_field30 = ProtoField.uint8 ("dji_p3_flyrec.unkn_a000_field30", "Field 30", base.HEX)

local function flightrec_unkn_a000_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.unkn_a000_field0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.unkn_a000_field4, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.unkn_a000_field8, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.unkn_a000_fieldC, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.unkn_a000_field10, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.unkn_a000_field14, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.unkn_a000_field18, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.unkn_a000_field1C, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.unkn_a000_field20, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.unkn_a000_field24, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.unkn_a000_field28, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.unkn_a000_field2C, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.unkn_a000_field30, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 49) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Unknown a000: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Unknown a000: Payload size different than expected") end
end

DJI_P3_FLIGHT_RECORD_DISSECT = {
    [0x0000] = flightrec_controller_dissector,
    [0x07cf] = flightrec_ofdm_cnt_dissector,
    [0x07d0] = flightrec_uart_cnt_dissector,
    [0x0002] = flightrec_imu_tail_dissector,
    [0xfffa] = flightrec_drv_log_dissector,
    [0x0073] = flightrec_asr_dissector,
    [0x0001] = flightrec_imu_atti_dissector,
    [0x0003] = flightrec_imu_ex_dissector,
    [0x0820] = flightrec_imu_tail_00_dissector,
    [0x0800] = flightrec_imu_atti_00_dissector,
    [0x0810] = flightrec_imu_ex_00_dissector,
    [0x0821] = flightrec_imu_tail_01_dissector,
    [0x0801] = flightrec_imu_atti_01_dissector,
    [0x0811] = flightrec_imu_ex_01_dissector,
    [0x0822] = flightrec_imu_tail_02_dissector,
    [0x0802] = flightrec_imu_atti_02_dissector,
    [0x0812] = flightrec_imu_ex_02_dissector,
    [0x0004] = flightrec_compass_dissector,
    [0x0005] = flightrec_gps_glns_dissector,
    [0x000b] = flightrec_gps_snr_dissector,
    [0x0061] = flightrec_pt3_gps_snr_dissector,
    [0x005b] = flightrec_imu_21100_dissector,
    [0x005c] = flightrec_imu_raw_dissector,
    [0x0062] = flightrec_imu_raw_dissector, -- second type containing the same data
    [0x0006] = flightrec_imu_init_dissector,
    [0x000c] = flightrec_osd_general_dissector,
    [0x000d] = flightrec_osd_home_dissector,
    [0x001a] = flightrec_fdi_dissector,
    [0x8003] = flightrec_vincent_debug_dissector,
    [0x8000] = flightrec_fly_log_dissector,
    [0xff00] = flightrec_sd_logs_dissector,
    [0xfffe] = flightrec_svn_info_dissector,
    [0x0007] = flightrec_imu_data_dissector,
    [0x0870] = flightrec_imu_data_00_dissector,
    [0x0871] = flightrec_imu_data_01_dissector,
    [0x0872] = flightrec_imu_data_02_dissector,
    [0x0008] = flightrec_imu_cali_data_dissector,
    [0x0009] = flightrec_sensor_cfg_temp_dissector,
    [0x000a] = flightrec_temp_ctl_data_dissector,
    [0x0880] = flightrec_temp_ctl_data_00_dissector,
    [0x0881] = flightrec_temp_ctl_data_01_dissector,
    [0x0882] = flightrec_temp_ctl_data_02_dissector,
    [0x0014] = flightrec_pwm_output_dissector,
    [0x0015] = flightrec_temp_bias_data_dissector,
    [0x0016] = flightrec_temp_cali_data_dissector,
    [0x0018] = flightrec_app_temp_bias_data_dissector,
    [0x0019] = flightrec_app_temp_cali_data_dissector,
    [0x0893] = flightrec_temp_cali_data_00_dissector,
    [0x0896] = flightrec_app_temp_cali_data_00_dissector,
    [0x0894] = flightrec_temp_cali_data_01_dissector,
    [0x0897] = flightrec_app_temp_cali_data_01_dissector,
    [0x0895] = flightrec_temp_cali_data_02_dissector,
    [0x0898] = flightrec_app_temp_cali_data_02_dissector,
    [0x0023] = flightrec_mpu6500_raw_data_dissector,
    [0x0024] = flightrec_adxl278_raw_data_dissector,
    [0x0065] = flightrec_svo_debug_dissector,
    [0xcdf0] = flightrec_uc_monitor_dissector,
    [0xcdff] = flightrec_rc_delay_dissector,
    [0xce02] = flightrec_taskb_info_dissector,
    [0xce06] = flightrec_taska_info_dissector,
    [0xce08] = flightrec_taskc_info_dissector,
    [0xce09] = flightrec_taskd_info_dissector,
    [0xcdf6] = flightrec_rc_replay_dissector,
    [0xcdf1] = flightrec_escm_dissector,
    [0xcdf2] = flightrec_sweep_dissector,
    [0x000e] = flightrec_mvo_dissector,
    [0x0010] = flightrec_usonic_dissector,
    [0xcdef] = flightrec_console_dissector,
    [0xffff] = flightrec_syscfg_dissector,
    [0x0011] = flightrec_battery_info_dissector,
    [0x0017] = flightrec_special_cmd_dissector,
    [0x003c] = flightrec_serial_api_inputs_dissector,
    [0x0032] = flightrec_ctrl_vert_dissector,
    [0x0033] = flightrec_ctrl_horiz_dissector,
    [0x0034] = flightrec_ctrl_atti_dissector,
    [0x0035] = flightrec_ctrl_ccpm_dissector,
    [0x0036] = flightrec_ctrl_motor_dissector,
    [0x0096] = flightrec_wp_curve_dissector,
    [0x0012] = flightrec_smart_battery_info_dissector,
    [0x0028] = flightrec_airport_limit_data_dissector,
    [0x0029] = flightrec_fmu_device_run_time_dissector,
    [0x002a] = flightrec_hp_data_dissector,
    [0x002b] = flightrec_follow_me_data_dissector,
    [0x002c] = flightrec_home_lock_dissector,
    [0x0013] = flightrec_imu_data_status_dissector,
    [0x0046] = flightrec_aircraft_condition_monitor_dissector,
    [0x0050] = flightrec_aircraft_model_dissector,
    [0x005a] = flightrec_go_home_info_dissector,
    [0x001d] = flightrec_new_mvo_feedback_dissector,
    [0x0064] = flightrec_svo_avoid_obstacle_dissector,
    [0xcff1] = flightrec_rtkdata_dissector,
    [0x006e] = flightrec_gear_debug_info_dissector,
    [0x0066] = flightrec_svo_ctrl_debug_dissector,
    [0x00a0] = flightrec_waypoint_debug_dissector,
    [0xa000] = flightrec_unkn_a000_dissector,
}

-- [0]  Start of Pkt, always 0x55
f.delimiter = ProtoField.uint8 ("dji_p3_flyrec.delimiter", "Delimiter", base.HEX)
-- [1]  Length of Pkt 
f.length = ProtoField.uint16 ("dji_p3_flyrec.length", "Length", base.HEX, nil, 0x3FF)
-- [2]  Protocol version
f.protocol_version = ProtoField.uint16 ("dji_p3_flyrec.protover", "Protocol Version", base.HEX, nil, 0xFC00)
-- [3]  Data Type
f.datatype = ProtoField.uint8 ("dji_p3_flyrec.hdr_crc", "Header CRC", base.HEX)

-- Fields for ProtoVer = 0 (Flight Record)

-- [4-5]  Log Entry Type
f.etype = ProtoField.uint16 ("dji_p3_flyrec.etype", "Log Entry Type", base.HEX, DJI_P3_FLIGHT_RECORD_ENTRY_TYPE)
-- [6-9]  Sequence Ctr
f.seqctr = ProtoField.uint16 ("dji_p3_flyrec.seqctr", "Seq Counter", base.DEC)
-- [B] Payload (optional)
f.payload = ProtoField.bytes ("dji_p3_flyrec.payload", "Payload", base.SPACE)

-- [B+Payload] CRC
f.crc = ProtoField.uint16 ("dji_p3_flyrec.crc", "CRC", base.HEX)

local function flightrec_decrypt_payload(pkt_length, buffer)
    local offset = 6
    local seqctr = buffer(offset,4):le_uint()

    offset = 10
    local payload = buffer(offset, pkt_length - offset - 2):bytes()

    for i = 0, (payload:len() - 1) do
      payload:set_index( i, bit.bxor(payload:get_index(i), bit32.band(seqctr, 0xFF) ) )
    end

    return payload
end

-- Dissector top level function; is called within this dissector, but can also be called from outsude
function dji_p3_flyrec_main_dissector(buffer, pinfo, subtree)
    local offset = 1

    -- [1-2] The Pkt length | protocol version
    local pkt_length = buffer(offset,2):le_uint()
    local pkt_protover = pkt_length
    -- bit32 lib requires LUA 5.2
    pkt_length = bit32.band(pkt_length, 0x03FF)
    pkt_protover = bit32.rshift(bit32.band(pkt_protover, 0xFC00), 10)

    subtree:add_le (f.length, buffer(offset, 2))
    subtree:add_le (f.protocol_version, buffer(offset, 2))
    offset = offset + 2

    -- [3] Header Checksum
    subtree:add (f.datatype, buffer(offset, 1))
    offset = offset + 1

    if pkt_protover == 0 then

        -- [4] Log entry type
        local etype = buffer(offset,2):le_uint()
        subtree:add_le (f.etype, buffer(offset, 2))
        offset = offset + 2

        -- [6] Sequence Counter
        subtree:add_le (f.seqctr, buffer(offset, 4))
        offset = offset + 4

        assert(offset == 10, "Offset shifted - dissector internal inconsistency")

        -- [A] Payload    
        if pkt_length > offset+2 then
            local payload_buf = flightrec_decrypt_payload(pkt_length, buffer)
            local payload_tree = subtree:add(f.payload, buffer(offset, pkt_length - offset - 2))
            payload_tree:set_text("Payload: " .. bytearray_to_hexstr(payload_buf));
            local payload_tvb = ByteArray.tvb(payload_buf, "Payload")

            -- If we have a dissector for this kind of command, run it
            local dissector = DJI_P3_FLIGHT_RECORD_DISSECT[etype]

            if dissector ~= nil then
                dissector(payload_tvb, pinfo, payload_tree)
            end

        end

    end

    -- CRC
    subtree:add_le(f.crc, buffer(pkt_length - 2, 2))
    offset = offset + 2
end

-- The protocol dissector itself
function DJI_P3_FLYREC_PROTO.dissector (buffer, pinfo, tree)

    local subtree = tree:add (DJI_P3_FLYREC_PROTO, buffer())

    -- The Pkt start byte
    local offset = 0

    local pkt_type = buffer(offset,1):uint()
    subtree:add (f.delimiter, buffer(offset, 1))
    offset = offset + 1

    if pkt_type == 0x55 then
        dji_p3_flyrec_main_dissector(buffer, pinfo, subtree)
    end

end

-- A initialization routine
function DJI_P3_FLYREC_PROTO.init ()
end
