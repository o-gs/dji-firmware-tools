-- Create a new dissector
DJI_MAVIC_FLYREC_PROTO = Proto ("dji_mavic_flyrec", "DJI_MAVIC_FLYREC", "Dji Mavic Pro Flight Record file format")

local f = DJI_MAVIC_FLYREC_PROTO.fields
local enums = {}

DJI_MAVIC_FLIGHT_RECORD_ENTRY_TYPE = {
    [0x03e8] = 'Controller',
    [0x03e9] = 'Aircraft Condition',
    [0x03ea] = 'Serial Api Inputs',
    [0x03ec] = 'Go Home Info',
    [0x03ed] = 'Fmu Devices Run Time',
    [0x03f0] = 'Fmu Sa Run Time',
    [0x03f1] = 'Fmu Write Run Time',
    [0x03f3] = 'Fmu Api Run Time',
    [0x03f4] = 'Cfg Errs',
    [0x03f5] = 'New Api Err Time',
    [0x03ee] = 'Poi Debug Data',
    [0x03f6] = 'Adv Gh Debug Data',
    [0x03f7] = 'Ahrs Data',
    [0x0070] = 'Err Code',
    [0x0800] = 'Imu Atti 0',
    [0x0801] = 'Imu Atti 1',
    [0x0802] = 'Imu Atti 2',
    [0x0810] = 'Imu Ex 0',
    [0x0811] = 'Imu Ex 1',
    [0x0812] = 'Imu Ex 2',
    [0x08a0] = 'Atti Mini0',
    [0x08a1] = 'Atti Mini1',
    [0x08a2] = 'Atti Mini2',
    [0x0860] = 'Imu Fdi 0',
    [0x0861] = 'Imu Fdi 1',
    [0x0862] = 'Imu Fdi 2',
    [0x03ef] = 'Hl Debug Data',
    [0x03f2] = 'Farm Db Data',
    [0x4ef7] = 'Spray Sys Ctrl Cmd',
    [0x4ef8] = 'Spray Sys State',
    [0x04b0] = 'Ctrl Vert Debug',
    [0x04b1] = 'Ctrl Pos Vert Debug',
    [0x04b2] = 'Ctrl Vel Vert Debug',
    [0x04b3] = 'Ctrl Acc Vert Debug',
    [0x0514] = 'Ctrl Horiz Debug',
    [0x0515] = 'Ctrl Horiz Pos Debug',
    [0x0516] = 'Ctrl Horiz Vel Debug',
    [0x0518] = 'Ctrl Horiz Atti Debug',
    [0x0519] = 'Ctrl Horiz Ang Vel Debug',
    [0x051a] = 'Ctrl Horiz Ccpm Debug',
    [0x051b] = 'Ctrl Horiz Motor Debug',
    [0x051c] = 'Ctrl Sweep Test',
    [0x0460] = 'Way Debug Info',
    [0x0461] = 'Svo Avoid',
    [0x0578] = 'Simulator Debug Data',
    [0x0579] = 'Simulator Gyro Acc Data 400Hz',
    [0x057c] = 'Simulator Press Data 200Hz',
    [0x057a] = 'Simulator Mag Data 50Hz',
    [0x057b] = 'Simulator Gps Data 5Hz',
    [0x057e] = 'Simulator Motor Data',
    [0x057d] = 'Device Change Times',
    [0x0582] = 'Simulator Config Aircraft Param',
    [0x0583] = 'Simulator Config Battery Param',
    [0x0584] = 'Simulator Config Environment Param',
    [0x0585] = 'Simulator Config Motor Param 1',
    [0x0587] = 'Simulator Config Sensor Param',
    [0xcff2] = 'Rtkdata',
    [0x0640] = 'Genral Debug Data',
    [0x06a4] = 'Rc Debug Info',
    [0x08d0] = 'Cali Mag 00',
    [0x08d1] = 'Cali Mag 01',
    [0x08d2] = 'Cali Mag 02',
    [0x0828] = 'Lpf Gyr Acc0',
    [0x0829] = 'Lpf Gyr Acc1',
    [0x082a] = 'Lpf Gyr Acc2',
    [0x08e6] = 'App Temp Bias0',
    [0x08e7] = 'App Temp Bias1',
    [0x08e8] = 'App Temp Bias2',
    [0x08e4] = 'Inner Temp Bias0',
    [0x08e5] = 'Inner Temp Bias1',
    [0x08e6] = 'Inner Temp Bias2',
    [0x06ae] = 'Battery Info',
    [0x06af] = 'Battery Status',
    [0x06b0] = 'Smart Battery Info',
    [0x0708] = 'Statistical Info',
    [0x2764] = 'Ns Sensor Quality',
    [0x2765] = 'Ns Data Debug',
    [0x2766] = 'Ns Data Component',
    [0x2767] = 'Ns Data Residuals',
    [0x2768] = 'Ns Data Posi Ofst',
    [0x2769] = 'Ns Sensor Connect',
    [0x276a] = 'Esc Data',
    [0x276b] = 'High Freq Gyro Data 0',
    [0x276c] = 'High Freq Gyro Data 1',
    [0x276d] = 'High Freq Gyro Data 2',
    [0x276e] = 'Rc Gps Data',
    [0x2770] = 'Cb Gps',
    [0x2771] = 'Cb Temp',
    [0x2772] = 'Cb Press',
    [0x2774] = 'Air Compensate Data',
    [0x2775] = 'Vision Tof',
    [0x2776] = 'Gs Rtk Data',
    [0x2777] = 'Ex Raw Baro1',
    [0x2778] = 'Ex Raw Baro2',
    [0x2779] = 'Ex Raw Compass',
    [0x27d8] = 'Gear Status',
    [0x4ef2] = 'Radar Bottom',
    [0x4ef3] = 'Radar Avoid Front',
    [0x4ef4] = 'Radar Avoid Back',
    [0x4ef5] = 'Radar Predict Front',
    [0x4ef6] = 'Radar Predict Back',
    [0x4f4c] = 'Gyro Raw0 0',
    [0x4f4d] = 'Gyro Raw0 1',
    [0x4f4e] = 'Gyro Raw0 2',
    [0x4f50] = 'Gyro Raw1 0',
    [0x4f51] = 'Gyro Raw1 1',
    [0x4f54] = 'Gyro Raw2 0',
    [0x4f55] = 'Gyro Raw2 1',
    [0x4f58] = 'Acc Raw0 0',
    [0x4f59] = 'Acc Raw0 1',
    [0x4f5a] = 'Acc Raw0 2',
    [0x4f5c] = 'Acc Raw1 0',
    [0x4f5d] = 'Acc Raw1 1',
    [0x4f60] = 'Acc Raw2 0',
    [0x4f61] = 'Acc Raw2 1',
    [0x4f64] = 'Sensor Push0 0',
    [0x4f65] = 'Sensor Push0 1',
    [0x4f6a] = 'Baro Raw0',
    [0x4f6b] = 'Baro Raw1',
    [0x4f6c] = 'Baro Raw2',
    [0x4f6d] = 'Baro Raw3',
    [0x4f74] = 'Compass Raw0',
    [0x4f75] = 'Compass Raw1',
    [0x4f76] = 'Compass Raw2',
    [0x4f7e] = 'Compass Filter0',
    [0x4f7f] = 'Compass Filter1',
    [0x4f80] = 'Compass Filter2',
    [0x4f88] = 'Imu Rotated Data',
    [0x5014] = 'Raw Wristband Data',
    [0x5015] = 'Wristband',
    [0x501e] = 'Ctrl Device',
    [0x4e20] = 'Battery Info 2',
    [0x4e21] = 'Pwm Output',
    [0x0880] = 'Temp Ctl Recorde0',
    [0x0881] = 'Temp Ctl Recorde1',
    [0x0882] = 'Temp Ctl Recorde2',
    [0x4e22] = 'Airport Limit Debug Info',
    [0x4e23] = 'Battery Raw Data 1',
    [0x4e24] = 'Battery Raw Data 2',
    [0x4e25] = 'Sys Err',
    [0x4e27] = 'Quick Circle Debug',
    [0x4e28] = 'Battery Info 3',
    [0x4e29] = 'Rc Func Data',
    [0x4e2a] = 'Rc Func State',
    [0x4e2b] = 'Gps Monitor 1',
    [0x4e2c] = 'Gps Monitor 2',
    [0x4e2d] = 'Gps Monitor 3',
    [0x0883] = 'Adaptive Roll',
    [0x0884] = 'Adaptive Pitch',
    [0x0885] = 'Fw G Api',
    [0x0887] = 'Fw Param Ekf',
    [0x27e2] = 'Ex Raw Airspeed',
    [0x5000] = 'Vibrate Detect Gyro',
    [0x500a] = 'Airprot Limit Data',
    [0x500b] = 'Adv Fl Limit Data',
    [0x0888] = 'Db Subscription',
    [0x504b] = 'Lost Sats Go Home Send Package',
    [0x504c] = 'Lost Sats Go Home Recv Package',
    [0x504d] = 'Adsb Osd Info',
    [0x092a] = 'Link Host',
    [0x092b] = 'Link Pc',
    [0x092c] = 'Link Vo',
    [0x092d] = 'Link Sdk',
    [0x092e] = 'Link Ofdm',
    [0x092f] = 'Link Bat',
    [0x0930] = 'Link Auto Cali',
    [0x0931] = 'Link Cali Led',
    [0x0932] = 'Link Manual Cali',
    [0x0933] = 'Ipc0',
    [0xcde0] = 'System Monitor',
    [0xcddf] = 'Uart Monitor',
    [0xcdde] = 'Can Monitor',
    [0x8000] = 'Fly Log',
    [0xff00] = 'Sd Logs',
    [0xffff] = 'Sys Cfg',
    [0xfffe] = 'Uno Log',
    [0xfffd] = 'Cfg Log',
    [0xfffc] = 'Module Name',
}

local function bytearray_to_hexstr(bytes)
  s = {}
  for i = 0, bytes:len() - 1 do
    s[i+1] = string.format("%02X",bytes:get_index(i))
  end
  return table.concat(s," ")
end

-- Flight log - Controller - 0x03e8

f.controller_ctrl_tick = ProtoField.uint32 ("dji_mavic_flyrec.controller_ctrl_tick", "Ctrl Tick", base.HEX)
f.controller_ctrl_pitch = ProtoField.int16 ("dji_mavic_flyrec.controller_ctrl_pitch", "Ctrl Pitch", base.DEC)
f.controller_ctrl_roll = ProtoField.int16 ("dji_mavic_flyrec.controller_ctrl_roll", "Ctrl Roll", base.DEC)
f.controller_ctrl_yaw = ProtoField.int16 ("dji_mavic_flyrec.controller_ctrl_yaw", "Ctrl Yaw", base.DEC)
f.controller_ctrl_thr = ProtoField.int16 ("dji_mavic_flyrec.controller_ctrl_thr", "Ctrl Thr", base.DEC)
f.controller_ctrl_mode = ProtoField.uint8 ("dji_mavic_flyrec.controller_ctrl_mode", "Ctrl Mode", base.HEX)
f.controller_mode_switch = ProtoField.uint8 ("dji_mavic_flyrec.controller_mode_switch", "Mode Switch", base.HEX)
f.controller_motor_state = ProtoField.uint8 ("dji_mavic_flyrec.controller_motor_state", "Motor State", base.HEX)
f.controller_sig_level = ProtoField.uint8 ("dji_mavic_flyrec.controller_sig_level", "Sig Level", base.HEX)
f.controller_ctrl_level = ProtoField.uint8 ("dji_mavic_flyrec.controller_ctrl_level", "Ctrl Level", base.HEX)
f.controller_sim_model = ProtoField.uint8 ("dji_mavic_flyrec.controller_sim_model", "Sim Model", base.HEX)
f.controller_max_height = ProtoField.uint16 ("dji_mavic_flyrec.controller_max_height", "Max Height", base.HEX)
f.controller_max_radius = ProtoField.uint16 ("dji_mavic_flyrec.controller_max_radius", "Max Radius", base.HEX)
f.controller_d2h_x = ProtoField.float ("dji_mavic_flyrec.controller_d2h_x", "D2H X", base.DEC)
f.controller_d2h_y = ProtoField.float ("dji_mavic_flyrec.controller_d2h_y", "D2H Y", base.DEC)
f.controller_act_req_id = ProtoField.uint8 ("dji_mavic_flyrec.controller_act_req_id", "Act Req Id", base.HEX)
f.controller_act_act_id = ProtoField.uint8 ("dji_mavic_flyrec.controller_act_act_id", "Act Act Id", base.HEX)
f.controller_cmd_mod = ProtoField.uint8 ("dji_mavic_flyrec.controller_cmd_mod", "Cmd Mod", base.HEX)
f.controller_mod_req_id = ProtoField.uint8 ("dji_mavic_flyrec.controller_mod_req_id", "Mod Req Id", base.HEX)
f.controller_fw_flag = ProtoField.uint8 ("dji_mavic_flyrec.controller_fw_flag", "Fw Flag", base.HEX)
f.controller_mot_sta = ProtoField.uint8 ("dji_mavic_flyrec.controller_mot_sta", "Mot Sta", base.HEX)
f.controller_oh_take = ProtoField.uint8 ("dji_mavic_flyrec.controller_oh_take", "Oh Take", base.HEX)

local function flightrec_controller_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.controller_ctrl_tick, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.controller_ctrl_pitch, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_ctrl_roll, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_ctrl_yaw, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_ctrl_thr, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_ctrl_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_mode_switch, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_motor_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_sig_level, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_ctrl_level, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_sim_model, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_max_height, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_max_radius, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.controller_d2h_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.controller_d2h_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.controller_act_req_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_act_act_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_cmd_mod, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_mod_req_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_fw_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_mot_sta, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.controller_oh_take, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 37) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Controller: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Controller: Payload size different than expected") end
end

-- Flight log - Aircraft Condition - 0x03e9

f.aircraft_condition_int_fsm = ProtoField.uint8 ("dji_mavic_flyrec.aircraft_condition_int_fsm", "Int Fsm", base.HEX)
f.aircraft_condition_fsm_state = ProtoField.uint8 ("dji_mavic_flyrec.aircraft_condition_fsm_state", "Fsm State", base.HEX)
f.aircraft_condition_last_fsm = ProtoField.uint8 ("dji_mavic_flyrec.aircraft_condition_last_fsm", "Last Fsm", base.HEX)
f.aircraft_condition_near_gnd = ProtoField.uint8 ("dji_mavic_flyrec.aircraft_condition_near_gnd", "Near Gnd", base.HEX)
f.aircraft_condition_up_state = ProtoField.uint8 ("dji_mavic_flyrec.aircraft_condition_up_state", "Up State", base.HEX)
f.aircraft_condition_land_state = ProtoField.uint8 ("dji_mavic_flyrec.aircraft_condition_land_state", "Land State", base.HEX)
f.aircraft_condition_safe_fltr = ProtoField.int16 ("dji_mavic_flyrec.aircraft_condition_safe_fltr", "Safe Fltr", base.DEC)

local function flightrec_aircraft_condition_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.aircraft_condition_int_fsm, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.aircraft_condition_fsm_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.aircraft_condition_last_fsm, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.aircraft_condition_near_gnd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.aircraft_condition_up_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.aircraft_condition_land_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.aircraft_condition_safe_fltr, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Aircraft Condition: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Aircraft Condition: Payload size different than expected") end
end

-- Flight log - Serial Api Inputs - 0x03ea

f.serial_api_inputs_sdk_ctrl_f = ProtoField.uint8 ("dji_mavic_flyrec.serial_api_inputs_sdk_ctrl_f", "Sdk Ctrl F", base.HEX)
f.serial_api_inputs_sdk_roll_x = ProtoField.int16 ("dji_mavic_flyrec.serial_api_inputs_sdk_roll_x", "Sdk Roll X", base.DEC)
f.serial_api_inputs_sdk_pitch_y = ProtoField.int16 ("dji_mavic_flyrec.serial_api_inputs_sdk_pitch_y", "Sdk Pitch Y", base.DEC)
f.serial_api_inputs_sdk_thr_z = ProtoField.int16 ("dji_mavic_flyrec.serial_api_inputs_sdk_thr_z", "Sdk Thr Z", base.DEC)
f.serial_api_inputs_sdk_yaw = ProtoField.int16 ("dji_mavic_flyrec.serial_api_inputs_sdk_yaw", "Sdk Yaw", base.DEC)
f.serial_api_inputs_sdk_fdfd_x = ProtoField.int16 ("dji_mavic_flyrec.serial_api_inputs_sdk_fdfd_x", "Sdk Fdfd X", base.DEC)
f.serial_api_inputs_sdk_fdfd_y = ProtoField.int16 ("dji_mavic_flyrec.serial_api_inputs_sdk_fdfd_y", "Sdk Fdfd Y", base.DEC)
f.serial_api_inputs_ctrl_dev = ProtoField.uint8 ("dji_mavic_flyrec.serial_api_inputs_ctrl_dev", "Ctrl Dev", base.HEX)
f.serial_api_inputs_sub_mode = ProtoField.uint8 ("dji_mavic_flyrec.serial_api_inputs_sub_mode", "Sub Mode", base.HEX)
f.serial_api_inputs_open_req = ProtoField.uint8 ("dji_mavic_flyrec.serial_api_inputs_open_req", "Open Req", base.HEX)
f.serial_api_inputs_open_ack = ProtoField.uint8 ("dji_mavic_flyrec.serial_api_inputs_open_ack", "Open Ack", base.HEX)
f.serial_api_inputs_cmd_req = ProtoField.uint8 ("dji_mavic_flyrec.serial_api_inputs_cmd_req", "Cmd Req", base.HEX)
f.serial_api_inputs_cmd_ack = ProtoField.uint8 ("dji_mavic_flyrec.serial_api_inputs_cmd_ack", "Cmd Ack", base.HEX)
f.serial_api_inputs_avoid_e = ProtoField.uint8 ("dji_mavic_flyrec.serial_api_inputs_avoid_e", "Avoid E", base.HEX)
f.serial_api_inputs_bit_s = ProtoField.uint8 ("dji_mavic_flyrec.serial_api_inputs_bit_s", "Bit S", base.HEX)
f.serial_api_inputs_rc_cnt = ProtoField.uint8 ("dji_mavic_flyrec.serial_api_inputs_rc_cnt", "Rc Cnt", base.HEX)
f.serial_api_inputs_sup_rc = ProtoField.uint8 ("dji_mavic_flyrec.serial_api_inputs_sup_rc", "Sup Rc", base.HEX)
f.serial_api_inputs_fact_cnt = ProtoField.uint8 ("dji_mavic_flyrec.serial_api_inputs_fact_cnt", "Fact Cnt", base.HEX)
f.serial_api_inputs_f_test = ProtoField.uint8 ("dji_mavic_flyrec.serial_api_inputs_f_test", "F Test", base.HEX)

local function flightrec_serial_api_inputs_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.serial_api_inputs_sdk_ctrl_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_sdk_roll_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.serial_api_inputs_sdk_pitch_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.serial_api_inputs_sdk_thr_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.serial_api_inputs_sdk_yaw, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.serial_api_inputs_sdk_fdfd_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.serial_api_inputs_sdk_fdfd_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.serial_api_inputs_ctrl_dev, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_sub_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_open_req, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_open_ack, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_cmd_req, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_cmd_ack, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_avoid_e, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_bit_s, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_rc_cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_sup_rc, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_fact_cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.serial_api_inputs_f_test, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 25) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Serial Api Inputs: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Serial Api Inputs: Payload size different than expected") end
end

-- Flight log - Go Home Info - 0x03ec

f.go_home_info_gh_sta = ProtoField.uint8 ("dji_mavic_flyrec.go_home_info_gh_sta", "Gh Sta", base.HEX)
f.go_home_info_gh_t = ProtoField.uint16 ("dji_mavic_flyrec.go_home_info_gh_t", "Gh T", base.HEX)
f.go_home_info_gh_line_t = ProtoField.uint16 ("dji_mavic_flyrec.go_home_info_gh_line_t", "Gh Line T", base.HEX)
f.go_home_info_gh_tgt_p0 = ProtoField.int16 ("dji_mavic_flyrec.go_home_info_gh_tgt_p0", "Gh Tgt P0", base.DEC)
f.go_home_info_gh_tgt_p1 = ProtoField.int16 ("dji_mavic_flyrec.go_home_info_gh_tgt_p1", "Gh Tgt P1", base.DEC)
f.go_home_info_gh_tgt_v0 = ProtoField.int16 ("dji_mavic_flyrec.go_home_info_gh_tgt_v0", "Gh Tgt V0", base.DEC)
f.go_home_info_gh_tgt_v1 = ProtoField.int16 ("dji_mavic_flyrec.go_home_info_gh_tgt_v1", "Gh Tgt V1", base.DEC)
f.go_home_info_gh_fdk_p0 = ProtoField.int16 ("dji_mavic_flyrec.go_home_info_gh_fdk_p0", "Gh Fdk P0", base.DEC)
f.go_home_info_gh_fdk_p1 = ProtoField.int16 ("dji_mavic_flyrec.go_home_info_gh_fdk_p1", "Gh Fdk P1", base.DEC)
f.go_home_info_gh_pud = ProtoField.uint8 ("dji_mavic_flyrec.go_home_info_gh_pud", "Gh Pud", base.HEX)
f.go_home_info_gh_idl_vel = ProtoField.uint16 ("dji_mavic_flyrec.go_home_info_gh_idl_vel", "Gh Idl Vel", base.HEX)
f.go_home_info_asd_tgt_h = ProtoField.uint16 ("dji_mavic_flyrec.go_home_info_asd_tgt_h", "Asd Tgt H", base.HEX)
f.go_home_info_fasd_tgt_h = ProtoField.uint16 ("dji_mavic_flyrec.go_home_info_fasd_tgt_h", "Fasd Tgt H", base.HEX)
f.go_home_info_asd_to = ProtoField.uint16 ("dji_mavic_flyrec.go_home_info_asd_to", "Asd To", base.HEX)
f.go_home_info_fasd_to = ProtoField.uint16 ("dji_mavic_flyrec.go_home_info_fasd_to", "Fasd To", base.HEX)
f.go_home_info_fasd_err = ProtoField.int16 ("dji_mavic_flyrec.go_home_info_fasd_err", "Fasd Err", base.DEC)
f.go_home_info_asd_err = ProtoField.int16 ("dji_mavic_flyrec.go_home_info_asd_err", "Asd Err", base.DEC)
f.go_home_info_220clogh_f = ProtoField.uint8 ("dji_mavic_flyrec.go_home_info_220clogh_f", "220Clogh F", base.HEX)
f.go_home_info_advghsw2fc = ProtoField.uint8 ("dji_mavic_flyrec.go_home_info_advghsw2fc", "Advghsw2Fc", base.HEX)
f.go_home_info_dyh_chd = ProtoField.uint8 ("dji_mavic_flyrec.go_home_info_dyh_chd", "Dyh Chd", base.HEX)
f.go_home_info_head_ref = ProtoField.float ("dji_mavic_flyrec.go_home_info_head_ref", "Head Ref", base.DEC)
f.go_home_info_head_err = ProtoField.float ("dji_mavic_flyrec.go_home_info_head_err", "Head Err", base.DEC)
f.go_home_info_head_rate = ProtoField.float ("dji_mavic_flyrec.go_home_info_head_rate", "Head Rate", base.DEC)

local function flightrec_go_home_info_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.go_home_info_gh_sta, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.go_home_info_gh_t, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.go_home_info_gh_line_t, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.go_home_info_gh_tgt_p0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.go_home_info_gh_tgt_p1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.go_home_info_gh_tgt_v0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.go_home_info_gh_tgt_v1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.go_home_info_gh_fdk_p0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.go_home_info_gh_fdk_p1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.go_home_info_gh_pud, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.go_home_info_gh_idl_vel, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.go_home_info_asd_tgt_h, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.go_home_info_fasd_tgt_h, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.go_home_info_asd_to, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.go_home_info_fasd_to, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.go_home_info_fasd_err, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.go_home_info_asd_err, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.go_home_info_220clogh_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.go_home_info_advghsw2fc, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.go_home_info_dyh_chd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.go_home_info_head_ref, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.go_home_info_head_err, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.go_home_info_head_rate, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 47) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Go Home Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Go Home Info: Payload size different than expected") end
end

-- Flight log - Fmu Devices Run Time - 0x03ed

f.fmu_devices_run_time_all = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_all", "All", base.DEC)
f.fmu_devices_run_time_battery = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_battery", "Battery", base.DEC)
f.fmu_devices_run_time_led = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_led", "Led", base.DEC)
f.fmu_devices_run_time_baromter = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_baromter", "Baromter", base.DEC)
f.fmu_devices_run_time_gyro_acc = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_gyro_acc", "Gyro Acc", base.DEC)
f.fmu_devices_run_time_imu = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_imu", "Imu", base.DEC)
f.fmu_devices_run_time_vo = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_vo", "Vo", base.DEC)
f.fmu_devices_run_time_ultrasonic = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_ultrasonic", "Ultrasonic", base.DEC)
f.fmu_devices_run_time_esc = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_esc", "Esc", base.DEC)
f.fmu_devices_run_time_mc = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_mc", "Mc", base.DEC)
f.fmu_devices_run_time_camera = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_camera", "Camera", base.DEC)
f.fmu_devices_run_time_gps = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_gps", "Gps", base.DEC)
f.fmu_devices_run_time_compass = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_compass", "Compass", base.DEC)
f.fmu_devices_run_time_gimbal = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_gimbal", "Gimbal", base.DEC)
f.fmu_devices_run_time_rc = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_rc", "Rc", base.DEC)
f.fmu_devices_run_time_gear = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_gear", "Gear", base.DEC)
f.fmu_devices_run_time_sdk = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_sdk", "Sdk", base.DEC)
f.fmu_devices_run_time_rtk = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_rtk", "Rtk", base.DEC)
f.fmu_devices_run_time_dropsafe = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_dropsafe", "Dropsafe", base.DEC)
f.fmu_devices_run_time_radar = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_radar", "Radar", base.DEC)
f.fmu_devices_run_time_spray_sys = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_spray_sys", "Spray Sys", base.DEC)
f.fmu_devices_run_time_tof = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_tof", "Tof", base.DEC)
f.fmu_devices_run_time_wristband = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_wristband", "Wristband", base.DEC)
f.fmu_devices_run_time_headset = ProtoField.float ("dji_mavic_flyrec.fmu_devices_run_time_headset", "Headset", base.DEC)

local function flightrec_fmu_devices_run_time_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.fmu_devices_run_time_all, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_battery, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_led, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_baromter, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_gyro_acc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_imu, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_vo, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_ultrasonic, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_esc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_mc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_camera, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_gps, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_compass, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_gimbal, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_rc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_gear, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_sdk, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_rtk, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_dropsafe, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_radar, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_spray_sys, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_tof, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_wristband, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_devices_run_time_headset, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 96) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Fmu Devices Run Time: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Fmu Devices Run Time: Payload size different than expected") end
end

-- Flight log - Fmu Sa Run Time - 0x03f0

f.fmu_sa_run_time_all = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_all", "All", base.DEC)
f.fmu_sa_run_time_assistant = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_assistant", "Assistant", base.DEC)
f.fmu_sa_run_time_data = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_data", "Data", base.DEC)
f.fmu_sa_run_time_simulator = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_simulator", "Simulator", base.DEC)
f.fmu_sa_run_time_fsm = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_fsm", "Fsm", base.DEC)
f.fmu_sa_run_time_home = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_home", "Home", base.DEC)
f.fmu_sa_run_time_battery = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_battery", "Battery", base.DEC)
f.fmu_sa_run_time_motor = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_motor", "Motor", base.DEC)
f.fmu_sa_run_time_led = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_led", "Led", base.DEC)
f.fmu_sa_run_time_gear = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_gear", "Gear", base.DEC)
f.fmu_sa_run_time_airlimit = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_airlimit", "Airlimit", base.DEC)
f.fmu_sa_run_time_power_satu = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_power_satu", "Power Satu", base.DEC)
f.fmu_sa_run_time_user_info = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_user_info", "User Info", base.DEC)
f.fmu_sa_run_time_code_check = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_code_check", "Code Check", base.DEC)
f.fmu_sa_run_time_topo_check = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_topo_check", "Topo Check", base.DEC)
f.fmu_sa_run_time_vers_check = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_vers_check", "Vers Check", base.DEC)
f.fmu_sa_run_time_gps_level = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_gps_level", "Gps Level", base.DEC)
f.fmu_sa_run_time_link = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_link", "Link", base.DEC)
f.fmu_sa_run_time_navi_data = ProtoField.float ("dji_mavic_flyrec.fmu_sa_run_time_navi_data", "Navi Data", base.DEC)

local function flightrec_fmu_sa_run_time_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.fmu_sa_run_time_all, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_sa_run_time_assistant, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_sa_run_time_data, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_sa_run_time_simulator, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_sa_run_time_fsm, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_sa_run_time_home, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_sa_run_time_battery, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_sa_run_time_motor, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_sa_run_time_led, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_sa_run_time_gear, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_sa_run_time_airlimit, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_sa_run_time_power_satu, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_sa_run_time_user_info, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_sa_run_time_code_check, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_sa_run_time_topo_check, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_sa_run_time_vers_check, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_sa_run_time_gps_level, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_sa_run_time_link, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_sa_run_time_navi_data, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 76) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Fmu Sa Run Time: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Fmu Sa Run Time: Payload size different than expected") end
end

-- Flight log - Fmu Write Run Time - 0x03f1

f.fmu_write_run_time_all = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_all", "All", base.DEC)
f.fmu_write_run_time_battery = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_battery", "Battery", base.DEC)
f.fmu_write_run_time_led = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_led", "Led", base.DEC)
f.fmu_write_run_time_baromter = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_baromter", "Baromter", base.DEC)
f.fmu_write_run_time_gyro_acc = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_gyro_acc", "Gyro Acc", base.DEC)
f.fmu_write_run_time_imu = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_imu", "Imu", base.DEC)
f.fmu_write_run_time_vo = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_vo", "Vo", base.DEC)
f.fmu_write_run_time_ultrasonic = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_ultrasonic", "Ultrasonic", base.DEC)
f.fmu_write_run_time_esc = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_esc", "Esc", base.DEC)
f.fmu_write_run_time_mc = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_mc", "Mc", base.DEC)
f.fmu_write_run_time_camera = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_camera", "Camera", base.DEC)
f.fmu_write_run_time_gps = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_gps", "Gps", base.DEC)
f.fmu_write_run_time_compass = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_compass", "Compass", base.DEC)
f.fmu_write_run_time_gimbal = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_gimbal", "Gimbal", base.DEC)
f.fmu_write_run_time_rc = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_rc", "Rc", base.DEC)
f.fmu_write_run_time_gear = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_gear", "Gear", base.DEC)
f.fmu_write_run_time_sdk = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_sdk", "Sdk", base.DEC)
f.fmu_write_run_time_rtk = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_rtk", "Rtk", base.DEC)
f.fmu_write_run_time_dropsafe = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_dropsafe", "Dropsafe", base.DEC)
f.fmu_write_run_time_radar = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_radar", "Radar", base.DEC)
f.fmu_write_run_time_spray = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_spray", "Spray", base.DEC)
f.fmu_write_run_time_tof = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_tof", "Tof", base.DEC)
f.fmu_write_run_time_wristband = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_wristband", "Wristband", base.DEC)
f.fmu_write_run_time_headset = ProtoField.float ("dji_mavic_flyrec.fmu_write_run_time_headset", "Headset", base.DEC)

local function flightrec_fmu_write_run_time_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.fmu_write_run_time_all, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_battery, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_led, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_baromter, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_gyro_acc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_imu, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_vo, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_ultrasonic, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_esc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_mc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_camera, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_gps, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_compass, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_gimbal, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_rc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_gear, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_sdk, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_rtk, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_dropsafe, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_radar, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_spray, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_tof, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_wristband, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fmu_write_run_time_headset, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 96) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Fmu Write Run Time: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Fmu Write Run Time: Payload size different than expected") end
end

-- Flight log - Fmu Api Run Time - 0x03f3

f.fmu_api_run_time_all = ProtoField.float ("dji_mavic_flyrec.fmu_api_run_time_all", "All", base.DEC)

local function flightrec_fmu_api_run_time_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.fmu_api_run_time_all, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Fmu Api Run Time: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Fmu Api Run Time: Payload size different than expected") end
end

-- Flight log - Cfg Errs - 0x03f4

f.cfg_errs_errs = ProtoField.uint32 ("dji_mavic_flyrec.cfg_errs_errs", "Errs", base.HEX)

local function flightrec_cfg_errs_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.cfg_errs_errs, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Cfg Errs: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Cfg Errs: Payload size different than expected") end
end

-- Flight log - New Api Err Time - 0x03f5

f.new_api_err_time_errs = ProtoField.uint32 ("dji_mavic_flyrec.new_api_err_time_errs", "Errs", base.HEX)

local function flightrec_new_api_err_time_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.new_api_err_time_errs, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"New Api Err Time: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"New Api Err Time: Payload size different than expected") end
end

-- Flight log - Poi Debug Data - 0x03ee

f.poi_debug_data_t_alti = ProtoField.float ("dji_mavic_flyrec.poi_debug_data_t_alti", "T Alti", base.DEC)
f.poi_debug_data_t_ang_rate = ProtoField.float ("dji_mavic_flyrec.poi_debug_data_t_ang_rate", "T Ang Rate", base.DEC)
f.poi_debug_data_t_radius = ProtoField.float ("dji_mavic_flyrec.poi_debug_data_t_radius", "T Radius", base.DEC)
f.poi_debug_data_r_dis_hp = ProtoField.float ("dji_mavic_flyrec.poi_debug_data_r_dis_hp", "R Dis Hp", base.DEC)
f.poi_debug_data_r_ang = ProtoField.float ("dji_mavic_flyrec.poi_debug_data_r_ang", "R Ang", base.DEC)
f.poi_debug_data_r_ang_rate = ProtoField.float ("dji_mavic_flyrec.poi_debug_data_r_ang_rate", "R Ang Rate", base.DEC)
f.poi_debug_data_r_radius = ProtoField.float ("dji_mavic_flyrec.poi_debug_data_r_radius", "R Radius", base.DEC)
f.poi_debug_data_p_err_x = ProtoField.float ("dji_mavic_flyrec.poi_debug_data_p_err_x", "P Err X", base.DEC)
f.poi_debug_data_p_err_y = ProtoField.float ("dji_mavic_flyrec.poi_debug_data_p_err_y", "P Err Y", base.DEC)
f.poi_debug_data_p_err_z = ProtoField.float ("dji_mavic_flyrec.poi_debug_data_p_err_z", "P Err Z", base.DEC)
f.poi_debug_data_v_err_x = ProtoField.float ("dji_mavic_flyrec.poi_debug_data_v_err_x", "V Err X", base.DEC)
f.poi_debug_data_v_err_y = ProtoField.float ("dji_mavic_flyrec.poi_debug_data_v_err_y", "V Err Y", base.DEC)
f.poi_debug_data_v_err_z = ProtoField.float ("dji_mavic_flyrec.poi_debug_data_v_err_z", "V Err Z", base.DEC)
f.poi_debug_data_head_err = ProtoField.float ("dji_mavic_flyrec.poi_debug_data_head_err", "Head Err", base.DEC)
f.poi_debug_data_c_head_err = ProtoField.float ("dji_mavic_flyrec.poi_debug_data_c_head_err", "C Head Err", base.DEC)
f.poi_debug_data_cmd_vel_x = ProtoField.float ("dji_mavic_flyrec.poi_debug_data_cmd_vel_x", "Cmd Vel X", base.DEC)
f.poi_debug_data_cmd_vel_y = ProtoField.float ("dji_mavic_flyrec.poi_debug_data_cmd_vel_y", "Cmd Vel Y", base.DEC)
f.poi_debug_data_cmd_vel_z = ProtoField.float ("dji_mavic_flyrec.poi_debug_data_cmd_vel_z", "Cmd Vel Z", base.DEC)
f.poi_debug_data_is_pud = ProtoField.uint8 ("dji_mavic_flyrec.poi_debug_data_is_pud", "Is Pud", base.HEX)

local function flightrec_poi_debug_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.poi_debug_data_t_alti, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.poi_debug_data_t_ang_rate, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.poi_debug_data_t_radius, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.poi_debug_data_r_dis_hp, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.poi_debug_data_r_ang, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.poi_debug_data_r_ang_rate, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.poi_debug_data_r_radius, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.poi_debug_data_p_err_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.poi_debug_data_p_err_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.poi_debug_data_p_err_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.poi_debug_data_v_err_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.poi_debug_data_v_err_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.poi_debug_data_v_err_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.poi_debug_data_head_err, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.poi_debug_data_c_head_err, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.poi_debug_data_cmd_vel_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.poi_debug_data_cmd_vel_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.poi_debug_data_cmd_vel_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.poi_debug_data_is_pud, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 73) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Poi Debug Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Poi Debug Data: Payload size different than expected") end
end

-- Flight log - Adv Gh Debug Data - 0x03f6

f.adv_gh_debug_data_sl_req = ProtoField.int8 ("dji_mavic_flyrec.adv_gh_debug_data_sl_req", "Sl Req", base.DEC)
f.adv_gh_debug_data_sl_f = ProtoField.int8 ("dji_mavic_flyrec.adv_gh_debug_data_sl_f", "Sl F", base.DEC)
f.adv_gh_debug_data_sl_last_f = ProtoField.int8 ("dji_mavic_flyrec.adv_gh_debug_data_sl_last_f", "Sl Last F", base.DEC)
f.adv_gh_debug_data_home_type = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_home_type", "Home Type", base.HEX)
f.adv_gh_debug_data_home_cnt = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_home_cnt", "Home Cnt", base.HEX)
f.adv_gh_debug_data_start_set = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_start_set", "Start Set", base.HEX)
f.adv_gh_debug_data_in_al = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_in_al", "In Al", base.HEX)
f.adv_gh_debug_data_gh_req = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_gh_req", "Gh Req", base.HEX)
f.adv_gh_debug_data_gh_s = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_gh_s", "Gh S", base.HEX)
f.adv_gh_debug_data_gh_t = ProtoField.int16 ("dji_mavic_flyrec.adv_gh_debug_data_gh_t", "Gh T", base.DEC)
f.adv_gh_debug_data_gh_cnt = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_gh_cnt", "Gh Cnt", base.HEX)
f.adv_gh_debug_data_gh_ok = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_gh_ok", "Gh Ok", base.HEX)
f.adv_gh_debug_data_al_need = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_al_need", "Al Need", base.HEX)
f.adv_gh_debug_data_al_in = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_al_in", "Al In", base.HEX)
f.adv_gh_debug_data_al_req = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_al_req", "Al Req", base.HEX)
f.adv_gh_debug_data_al_status = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_al_status", "Al Status", base.HEX)
f.adv_gh_debug_data_al_need_t = ProtoField.int16 ("dji_mavic_flyrec.adv_gh_debug_data_al_need_t", "Al Need T", base.DEC)
f.adv_gh_debug_data_al_is_ok = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_al_is_ok", "Al Is Ok", base.HEX)
f.adv_gh_debug_data_al__cnt = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_al__cnt", "Al  Cnt", base.HEX)
f.adv_gh_debug_data_al_gnd = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_al_gnd", "Al Gnd", base.HEX)
f.adv_gh_debug_data_al_ok = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_al_ok", "Al Ok", base.HEX)
f.adv_gh_debug_data_chg_ht_f = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_chg_ht_f", "Chg Ht F", base.HEX)
f.adv_gh_debug_data_adv_ctrl_f = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_adv_ctrl_f", "Adv Ctrl F", base.HEX)
f.adv_gh_debug_data_adv_brake_f = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_adv_brake_f", "Adv Brake F", base.HEX)
f.adv_gh_debug_data_adv_roll_x = ProtoField.int16 ("dji_mavic_flyrec.adv_gh_debug_data_adv_roll_x", "Adv Roll X", base.DEC)
f.adv_gh_debug_data_adv_pitch_y = ProtoField.int16 ("dji_mavic_flyrec.adv_gh_debug_data_adv_pitch_y", "Adv Pitch Y", base.DEC)
f.adv_gh_debug_data_adv_thr_z = ProtoField.int16 ("dji_mavic_flyrec.adv_gh_debug_data_adv_thr_z", "Adv Thr Z", base.DEC)
f.adv_gh_debug_data_adv_yaw = ProtoField.int16 ("dji_mavic_flyrec.adv_gh_debug_data_adv_yaw", "Adv Yaw", base.DEC)
f.adv_gh_debug_data_adv_fdfd_x = ProtoField.int16 ("dji_mavic_flyrec.adv_gh_debug_data_adv_fdfd_x", "Adv Fdfd X", base.DEC)
f.adv_gh_debug_data_adv_fdfd_y = ProtoField.int16 ("dji_mavic_flyrec.adv_gh_debug_data_adv_fdfd_y", "Adv Fdfd Y", base.DEC)
f.adv_gh_debug_data_ctrl_cnt = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_ctrl_cnt", "Ctrl Cnt", base.HEX)
f.adv_gh_debug_data_ctrl_ok = ProtoField.uint8 ("dji_mavic_flyrec.adv_gh_debug_data_ctrl_ok", "Ctrl Ok", base.HEX)

local function flightrec_adv_gh_debug_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.adv_gh_debug_data_sl_req, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_sl_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_sl_last_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_home_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_home_cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_start_set, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_in_al, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_gh_req, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_gh_s, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_gh_t, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.adv_gh_debug_data_gh_cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_gh_ok, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_al_need, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_al_in, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_al_req, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_al_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_al_need_t, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.adv_gh_debug_data_al_is_ok, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_al__cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_al_gnd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_al_ok, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_chg_ht_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_adv_ctrl_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_adv_brake_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_adv_roll_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.adv_gh_debug_data_adv_pitch_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.adv_gh_debug_data_adv_thr_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.adv_gh_debug_data_adv_yaw, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.adv_gh_debug_data_adv_fdfd_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.adv_gh_debug_data_adv_fdfd_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.adv_gh_debug_data_ctrl_cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_gh_debug_data_ctrl_ok, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 40) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Adv Gh Debug Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Adv Gh Debug Data: Payload size different than expected") end
end

-- Flight log - Ahrs Data - 0x03f7

f.ahrs_data_ns_longti = ProtoField.double ("dji_mavic_flyrec.ahrs_data_ns_longti", "Ns Longti", base.DEC)
f.ahrs_data_ns_lati = ProtoField.double ("dji_mavic_flyrec.ahrs_data_ns_lati", "Ns Lati", base.DEC)
f.ahrs_data_ns_height = ProtoField.float ("dji_mavic_flyrec.ahrs_data_ns_height", "Ns Height", base.DEC)
f.ahrs_data_ns_q0 = ProtoField.float ("dji_mavic_flyrec.ahrs_data_ns_q0", "Ns Q0", base.DEC)
f.ahrs_data_ns_q1 = ProtoField.float ("dji_mavic_flyrec.ahrs_data_ns_q1", "Ns Q1", base.DEC)
f.ahrs_data_ns_q2 = ProtoField.float ("dji_mavic_flyrec.ahrs_data_ns_q2", "Ns Q2", base.DEC)
f.ahrs_data_ns_q3 = ProtoField.float ("dji_mavic_flyrec.ahrs_data_ns_q3", "Ns Q3", base.DEC)
f.ahrs_data_ns_agx = ProtoField.float ("dji_mavic_flyrec.ahrs_data_ns_agx", "Ns Agx", base.DEC)
f.ahrs_data_ns_agy = ProtoField.float ("dji_mavic_flyrec.ahrs_data_ns_agy", "Ns Agy", base.DEC)
f.ahrs_data_ns_agz = ProtoField.float ("dji_mavic_flyrec.ahrs_data_ns_agz", "Ns Agz", base.DEC)
f.ahrs_data_ns_vgx = ProtoField.float ("dji_mavic_flyrec.ahrs_data_ns_vgx", "Ns Vgx", base.DEC)
f.ahrs_data_ns_vgy = ProtoField.float ("dji_mavic_flyrec.ahrs_data_ns_vgy", "Ns Vgy", base.DEC)
f.ahrs_data_ns_vgz = ProtoField.float ("dji_mavic_flyrec.ahrs_data_ns_vgz", "Ns Vgz", base.DEC)

local function flightrec_ahrs_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ahrs_data_ns_longti, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.ahrs_data_ns_lati, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.ahrs_data_ns_height, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ahrs_data_ns_q0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ahrs_data_ns_q1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ahrs_data_ns_q2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ahrs_data_ns_q3, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ahrs_data_ns_agx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ahrs_data_ns_agy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ahrs_data_ns_agz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ahrs_data_ns_vgx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ahrs_data_ns_vgy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ahrs_data_ns_vgz, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 60) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ahrs Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ahrs Data: Payload size different than expected") end
end

-- Flight log - Err Code - 0x0070

f.err_code_imu1_break = ProtoField.uint8 ("dji_mavic_flyrec.err_code_imu1_break", "Imu1 Break", base.HEX)
f.err_code_imu2_break = ProtoField.uint8 ("dji_mavic_flyrec.err_code_imu2_break", "Imu2 Break", base.HEX)
f.err_code_gcm0_break = ProtoField.uint8 ("dji_mavic_flyrec.err_code_gcm0_break", "Gcm0 Break", base.HEX)
f.err_code_gcm1_break = ProtoField.uint8 ("dji_mavic_flyrec.err_code_gcm1_break", "Gcm1 Break", base.HEX)
f.err_code_gcm2_break = ProtoField.uint8 ("dji_mavic_flyrec.err_code_gcm2_break", "Gcm2 Break", base.HEX)
f.err_code_imu0_fault = ProtoField.uint8 ("dji_mavic_flyrec.err_code_imu0_fault", "Imu0 Fault", base.HEX)
f.err_code_imu1_fault = ProtoField.uint8 ("dji_mavic_flyrec.err_code_imu1_fault", "Imu1 Fault", base.HEX)
f.err_code_imu2_fault = ProtoField.uint8 ("dji_mavic_flyrec.err_code_imu2_fault", "Imu2 Fault", base.HEX)
f.err_code_gcm0_fault = ProtoField.uint8 ("dji_mavic_flyrec.err_code_gcm0_fault", "Gcm0 Fault", base.HEX)
f.err_code_gcm1_fault = ProtoField.uint8 ("dji_mavic_flyrec.err_code_gcm1_fault", "Gcm1 Fault", base.HEX)
f.err_code_gcm2_fault = ProtoField.uint8 ("dji_mavic_flyrec.err_code_gcm2_fault", "Gcm2 Fault", base.HEX)
f.err_code_mc_fault = ProtoField.uint8 ("dji_mavic_flyrec.err_code_mc_fault", "Mc Fault", base.HEX)
f.err_code_mc_dev = ProtoField.uint8 ("dji_mavic_flyrec.err_code_mc_dev", "Mc Dev", base.HEX)
f.err_code_mc_err = ProtoField.uint8 ("dji_mavic_flyrec.err_code_mc_err", "Mc Err", base.HEX)
f.err_code_mc_act = ProtoField.uint8 ("dji_mavic_flyrec.err_code_mc_act", "Mc Act", base.HEX)
f.err_code_imu_stat = ProtoField.uint8 ("dji_mavic_flyrec.err_code_imu_stat", "Imu Stat", base.HEX)
f.err_code_mag_stat = ProtoField.uint8 ("dji_mavic_flyrec.err_code_mag_stat", "Mag Stat", base.HEX)
f.err_code_imu0_dev = ProtoField.uint8 ("dji_mavic_flyrec.err_code_imu0_dev", "Imu0 Dev", base.HEX)
f.err_code_imu0_err = ProtoField.uint8 ("dji_mavic_flyrec.err_code_imu0_err", "Imu0 Err", base.HEX)
f.err_code_imu0_act = ProtoField.uint8 ("dji_mavic_flyrec.err_code_imu0_act", "Imu0 Act", base.HEX)
f.err_code_imu1_dev = ProtoField.uint8 ("dji_mavic_flyrec.err_code_imu1_dev", "Imu1 Dev", base.HEX)
f.err_code_imu1_err = ProtoField.uint8 ("dji_mavic_flyrec.err_code_imu1_err", "Imu1 Err", base.HEX)
f.err_code_imu1_act = ProtoField.uint8 ("dji_mavic_flyrec.err_code_imu1_act", "Imu1 Act", base.HEX)
f.err_code_imu2_dev = ProtoField.uint8 ("dji_mavic_flyrec.err_code_imu2_dev", "Imu2 Dev", base.HEX)
f.err_code_imu2_err = ProtoField.uint8 ("dji_mavic_flyrec.err_code_imu2_err", "Imu2 Err", base.HEX)
f.err_code_imu2_act = ProtoField.uint8 ("dji_mavic_flyrec.err_code_imu2_act", "Imu2 Act", base.HEX)
f.err_code_gcm0_dev = ProtoField.uint8 ("dji_mavic_flyrec.err_code_gcm0_dev", "Gcm0 Dev", base.HEX)
f.err_code_gcm0_err = ProtoField.uint8 ("dji_mavic_flyrec.err_code_gcm0_err", "Gcm0 Err", base.HEX)
f.err_code_gcm0_act = ProtoField.uint8 ("dji_mavic_flyrec.err_code_gcm0_act", "Gcm0 Act", base.HEX)
f.err_code_gcm1_dev = ProtoField.uint8 ("dji_mavic_flyrec.err_code_gcm1_dev", "Gcm1 Dev", base.HEX)
f.err_code_gcm1_err = ProtoField.uint8 ("dji_mavic_flyrec.err_code_gcm1_err", "Gcm1 Err", base.HEX)
f.err_code_gcm1_act = ProtoField.uint8 ("dji_mavic_flyrec.err_code_gcm1_act", "Gcm1 Act", base.HEX)
f.err_code_gcm2_dev = ProtoField.uint8 ("dji_mavic_flyrec.err_code_gcm2_dev", "Gcm2 Dev", base.HEX)
f.err_code_gcm2_err = ProtoField.uint8 ("dji_mavic_flyrec.err_code_gcm2_err", "Gcm2 Err", base.HEX)
f.err_code_gcm2_act = ProtoField.uint8 ("dji_mavic_flyrec.err_code_gcm2_act", "Gcm2 Act", base.HEX)

local function flightrec_err_code_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.err_code_imu1_break, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_imu2_break, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_gcm0_break, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_gcm1_break, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_gcm2_break, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_imu0_fault, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_imu1_fault, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_imu2_fault, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_gcm0_fault, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_gcm1_fault, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_gcm2_fault, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_mc_fault, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_mc_dev, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_mc_err, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_mc_act, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_imu_stat, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_mag_stat, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_imu0_dev, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_imu0_err, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_imu0_act, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_imu1_dev, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_imu1_err, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_imu1_act, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_imu2_dev, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_imu2_err, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_imu2_act, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_gcm0_dev, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_gcm0_err, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_gcm0_act, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_gcm1_dev, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_gcm1_err, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_gcm1_act, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_gcm2_dev, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_gcm2_err, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.err_code_gcm2_act, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 35) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Err Code: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Err Code: Payload size different than expected") end
end

-- Flight log - Imu Atti 0 - 0x0800

f.imu_atti_0_long0 = ProtoField.double ("dji_mavic_flyrec.imu_atti_0_long0", "Long0", base.DEC)
f.imu_atti_0_lati0 = ProtoField.double ("dji_mavic_flyrec.imu_atti_0_lati0", "Lati0", base.DEC)
f.imu_atti_0_press0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_press0", "Press0", base.DEC)
f.imu_atti_0_ax0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_ax0", "Ax0", base.DEC)
f.imu_atti_0_ay0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_ay0", "Ay0", base.DEC)
f.imu_atti_0_az0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_az0", "Az0", base.DEC)
f.imu_atti_0_wx0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_wx0", "Wx0", base.DEC)
f.imu_atti_0_wy0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_wy0", "Wy0", base.DEC)
f.imu_atti_0_wz0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_wz0", "Wz0", base.DEC)
f.imu_atti_0_alti0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_alti0", "Alti0", base.DEC)
f.imu_atti_0_qw0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_qw0", "Qw0", base.DEC)
f.imu_atti_0_qx0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_qx0", "Qx0", base.DEC)
f.imu_atti_0_qy0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_qy0", "Qy0", base.DEC)
f.imu_atti_0_qz0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_qz0", "Qz0", base.DEC)
f.imu_atti_0_agx0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_agx0", "Agx0", base.DEC)
f.imu_atti_0_agy0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_agy0", "Agy0", base.DEC)
f.imu_atti_0_agz0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_agz0", "Agz0", base.DEC)
f.imu_atti_0_vgx0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_vgx0", "Vgx0", base.DEC)
f.imu_atti_0_vgy0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_vgy0", "Vgy0", base.DEC)
f.imu_atti_0_vgz0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_vgz0", "Vgz0", base.DEC)
f.imu_atti_0_gbx0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_gbx0", "Gbx0", base.DEC)
f.imu_atti_0_gby0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_gby0", "Gby0", base.DEC)
f.imu_atti_0_gbz0 = ProtoField.float ("dji_mavic_flyrec.imu_atti_0_gbz0", "Gbz0", base.DEC)
f.imu_atti_0_mx0 = ProtoField.int16 ("dji_mavic_flyrec.imu_atti_0_mx0", "Mx0", base.DEC)
f.imu_atti_0_my0 = ProtoField.int16 ("dji_mavic_flyrec.imu_atti_0_my0", "My0", base.DEC)
f.imu_atti_0_mz0 = ProtoField.int16 ("dji_mavic_flyrec.imu_atti_0_mz0", "Mz0", base.DEC)
f.imu_atti_0_tx0 = ProtoField.int16 ("dji_mavic_flyrec.imu_atti_0_tx0", "Tx0", base.DEC)
f.imu_atti_0_ty0 = ProtoField.int16 ("dji_mavic_flyrec.imu_atti_0_ty0", "Ty0", base.DEC)
f.imu_atti_0_tz0 = ProtoField.int16 ("dji_mavic_flyrec.imu_atti_0_tz0", "Tz0", base.DEC)
f.imu_atti_0_sensor_stat0 = ProtoField.uint16 ("dji_mavic_flyrec.imu_atti_0_sensor_stat0", "Sensor Stat0", base.HEX)
f.imu_atti_0_filter_stat0 = ProtoField.uint16 ("dji_mavic_flyrec.imu_atti_0_filter_stat0", "Filter Stat0", base.HEX)
f.imu_atti_0_svn0 = ProtoField.uint16 ("dji_mavic_flyrec.imu_atti_0_svn0", "Svn0", base.HEX)
f.imu_atti_0_atti_cnt0 = ProtoField.uint16 ("dji_mavic_flyrec.imu_atti_0_atti_cnt0", "Atti Cnt0", base.HEX)

local function flightrec_imu_atti_0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_atti_0_long0, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_atti_0_lati0, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_atti_0_press0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_ax0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_ay0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_az0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_wx0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_wy0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_wz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_alti0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_qw0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_qx0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_qy0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_qz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_agx0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_agy0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_agz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_vgx0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_vgy0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_vgz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_gbx0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_gby0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_gbz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_0_mx0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_0_my0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_0_mz0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_0_tx0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_0_ty0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_0_tz0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_0_sensor_stat0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_0_filter_stat0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_0_svn0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_0_atti_cnt0, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 120) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Atti 0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Atti 0: Payload size different than expected") end
end

-- Flight log - Imu Atti 1 - 0x0801

f.imu_atti_1_long1 = ProtoField.double ("dji_mavic_flyrec.imu_atti_1_long1", "Long1", base.DEC)
f.imu_atti_1_lati1 = ProtoField.double ("dji_mavic_flyrec.imu_atti_1_lati1", "Lati1", base.DEC)
f.imu_atti_1_press1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_press1", "Press1", base.DEC)
f.imu_atti_1_ax1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_ax1", "Ax1", base.DEC)
f.imu_atti_1_ay1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_ay1", "Ay1", base.DEC)
f.imu_atti_1_az1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_az1", "Az1", base.DEC)
f.imu_atti_1_wx1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_wx1", "Wx1", base.DEC)
f.imu_atti_1_wy1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_wy1", "Wy1", base.DEC)
f.imu_atti_1_wz1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_wz1", "Wz1", base.DEC)
f.imu_atti_1_alti1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_alti1", "Alti1", base.DEC)
f.imu_atti_1_qw1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_qw1", "Qw1", base.DEC)
f.imu_atti_1_qx1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_qx1", "Qx1", base.DEC)
f.imu_atti_1_qy1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_qy1", "Qy1", base.DEC)
f.imu_atti_1_qz1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_qz1", "Qz1", base.DEC)
f.imu_atti_1_agx1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_agx1", "Agx1", base.DEC)
f.imu_atti_1_agy1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_agy1", "Agy1", base.DEC)
f.imu_atti_1_agz1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_agz1", "Agz1", base.DEC)
f.imu_atti_1_vgx1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_vgx1", "Vgx1", base.DEC)
f.imu_atti_1_vgy1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_vgy1", "Vgy1", base.DEC)
f.imu_atti_1_vgz1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_vgz1", "Vgz1", base.DEC)
f.imu_atti_1_gbx1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_gbx1", "Gbx1", base.DEC)
f.imu_atti_1_gby1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_gby1", "Gby1", base.DEC)
f.imu_atti_1_gbz1 = ProtoField.float ("dji_mavic_flyrec.imu_atti_1_gbz1", "Gbz1", base.DEC)
f.imu_atti_1_mx1 = ProtoField.int16 ("dji_mavic_flyrec.imu_atti_1_mx1", "Mx1", base.DEC)
f.imu_atti_1_my1 = ProtoField.int16 ("dji_mavic_flyrec.imu_atti_1_my1", "My1", base.DEC)
f.imu_atti_1_mz1 = ProtoField.int16 ("dji_mavic_flyrec.imu_atti_1_mz1", "Mz1", base.DEC)
f.imu_atti_1_tx1 = ProtoField.int16 ("dji_mavic_flyrec.imu_atti_1_tx1", "Tx1", base.DEC)
f.imu_atti_1_ty1 = ProtoField.int16 ("dji_mavic_flyrec.imu_atti_1_ty1", "Ty1", base.DEC)
f.imu_atti_1_tz1 = ProtoField.int16 ("dji_mavic_flyrec.imu_atti_1_tz1", "Tz1", base.DEC)
f.imu_atti_1_sensor_stat1 = ProtoField.uint16 ("dji_mavic_flyrec.imu_atti_1_sensor_stat1", "Sensor Stat1", base.HEX)
f.imu_atti_1_filter_stat1 = ProtoField.uint16 ("dji_mavic_flyrec.imu_atti_1_filter_stat1", "Filter Stat1", base.HEX)
f.imu_atti_1_svn1 = ProtoField.uint16 ("dji_mavic_flyrec.imu_atti_1_svn1", "Svn1", base.HEX)
f.imu_atti_1_atti_cnt1 = ProtoField.uint16 ("dji_mavic_flyrec.imu_atti_1_atti_cnt1", "Atti Cnt1", base.HEX)

local function flightrec_imu_atti_1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_atti_1_long1, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_atti_1_lati1, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_atti_1_press1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_ax1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_ay1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_az1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_wx1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_wy1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_wz1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_alti1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_qw1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_qx1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_qy1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_qz1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_agx1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_agy1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_agz1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_vgx1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_vgy1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_vgz1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_gbx1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_gby1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_gbz1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_1_mx1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_1_my1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_1_mz1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_1_tx1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_1_ty1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_1_tz1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_1_sensor_stat1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_1_filter_stat1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_1_svn1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_1_atti_cnt1, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 120) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Atti 1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Atti 1: Payload size different than expected") end
end

-- Flight log - Imu Atti 2 - 0x0802

f.imu_atti_2_long2 = ProtoField.double ("dji_mavic_flyrec.imu_atti_2_long2", "Long2", base.DEC)
f.imu_atti_2_lati2 = ProtoField.double ("dji_mavic_flyrec.imu_atti_2_lati2", "Lati2", base.DEC)
f.imu_atti_2_press2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_press2", "Press2", base.DEC)
f.imu_atti_2_ax2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_ax2", "Ax2", base.DEC)
f.imu_atti_2_ay2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_ay2", "Ay2", base.DEC)
f.imu_atti_2_az2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_az2", "Az2", base.DEC)
f.imu_atti_2_wx2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_wx2", "Wx2", base.DEC)
f.imu_atti_2_wy2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_wy2", "Wy2", base.DEC)
f.imu_atti_2_wz2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_wz2", "Wz2", base.DEC)
f.imu_atti_2_alti2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_alti2", "Alti2", base.DEC)
f.imu_atti_2_qw2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_qw2", "Qw2", base.DEC)
f.imu_atti_2_qx2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_qx2", "Qx2", base.DEC)
f.imu_atti_2_qy2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_qy2", "Qy2", base.DEC)
f.imu_atti_2_qz2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_qz2", "Qz2", base.DEC)
f.imu_atti_2_agx2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_agx2", "Agx2", base.DEC)
f.imu_atti_2_agy2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_agy2", "Agy2", base.DEC)
f.imu_atti_2_agz2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_agz2", "Agz2", base.DEC)
f.imu_atti_2_vgx2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_vgx2", "Vgx2", base.DEC)
f.imu_atti_2_vgy2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_vgy2", "Vgy2", base.DEC)
f.imu_atti_2_vgz2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_vgz2", "Vgz2", base.DEC)
f.imu_atti_2_gbx2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_gbx2", "Gbx2", base.DEC)
f.imu_atti_2_gby2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_gby2", "Gby2", base.DEC)
f.imu_atti_2_gbz2 = ProtoField.float ("dji_mavic_flyrec.imu_atti_2_gbz2", "Gbz2", base.DEC)
f.imu_atti_2_mx2 = ProtoField.int16 ("dji_mavic_flyrec.imu_atti_2_mx2", "Mx2", base.DEC)
f.imu_atti_2_my2 = ProtoField.int16 ("dji_mavic_flyrec.imu_atti_2_my2", "My2", base.DEC)
f.imu_atti_2_mz2 = ProtoField.int16 ("dji_mavic_flyrec.imu_atti_2_mz2", "Mz2", base.DEC)
f.imu_atti_2_tx2 = ProtoField.int16 ("dji_mavic_flyrec.imu_atti_2_tx2", "Tx2", base.DEC)
f.imu_atti_2_ty2 = ProtoField.int16 ("dji_mavic_flyrec.imu_atti_2_ty2", "Ty2", base.DEC)
f.imu_atti_2_tz2 = ProtoField.int16 ("dji_mavic_flyrec.imu_atti_2_tz2", "Tz2", base.DEC)
f.imu_atti_2_sensor_stat2 = ProtoField.uint16 ("dji_mavic_flyrec.imu_atti_2_sensor_stat2", "Sensor Stat2", base.HEX)
f.imu_atti_2_filter_stat2 = ProtoField.uint16 ("dji_mavic_flyrec.imu_atti_2_filter_stat2", "Filter Stat2", base.HEX)
f.imu_atti_2_svn2 = ProtoField.uint16 ("dji_mavic_flyrec.imu_atti_2_svn2", "Svn2", base.HEX)
f.imu_atti_2_atti_cnt2 = ProtoField.uint16 ("dji_mavic_flyrec.imu_atti_2_atti_cnt2", "Atti Cnt2", base.HEX)

local function flightrec_imu_atti_2_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_atti_2_long2, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_atti_2_lati2, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_atti_2_press2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_ax2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_ay2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_az2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_wx2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_wy2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_wz2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_alti2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_qw2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_qx2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_qy2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_qz2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_agx2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_agy2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_agz2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_vgx2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_vgy2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_vgz2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_gbx2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_gby2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_gbz2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_atti_2_mx2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_2_my2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_2_mz2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_2_tx2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_2_ty2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_2_tz2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_2_sensor_stat2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_2_filter_stat2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_2_svn2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_atti_2_atti_cnt2, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 120) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Atti 2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Atti 2: Payload size different than expected") end
end

-- Flight log - Imu Ex 0 - 0x0810

f.imu_ex_0_vo_vx0 = ProtoField.float ("dji_mavic_flyrec.imu_ex_0_vo_vx0", "Vo Vx0", base.DEC)
f.imu_ex_0_vo_vy0 = ProtoField.float ("dji_mavic_flyrec.imu_ex_0_vo_vy0", "Vo Vy0", base.DEC)
f.imu_ex_0_vo_vz0 = ProtoField.float ("dji_mavic_flyrec.imu_ex_0_vo_vz0", "Vo Vz0", base.DEC)
f.imu_ex_0_vo_px0 = ProtoField.float ("dji_mavic_flyrec.imu_ex_0_vo_px0", "Vo Px0", base.DEC)
f.imu_ex_0_vo_py0 = ProtoField.float ("dji_mavic_flyrec.imu_ex_0_vo_py0", "Vo Py0", base.DEC)
f.imu_ex_0_vo_pz0 = ProtoField.float ("dji_mavic_flyrec.imu_ex_0_vo_pz0", "Vo Pz0", base.DEC)
f.imu_ex_0_us_v0 = ProtoField.float ("dji_mavic_flyrec.imu_ex_0_us_v0", "Us V0", base.DEC)
f.imu_ex_0_us_p0 = ProtoField.float ("dji_mavic_flyrec.imu_ex_0_us_p0", "Us P0", base.DEC)
f.imu_ex_0_rtk_long0 = ProtoField.double ("dji_mavic_flyrec.imu_ex_0_rtk_long0", "Rtk Long0", base.DEC)
f.imu_ex_0_rtk_lati0 = ProtoField.double ("dji_mavic_flyrec.imu_ex_0_rtk_lati0", "Rtk Lati0", base.DEC)
f.imu_ex_0_rtk_alti0 = ProtoField.float ("dji_mavic_flyrec.imu_ex_0_rtk_alti0", "Rtk Alti0", base.DEC)
f.imu_ex_0_flag_navi0 = ProtoField.uint16 ("dji_mavic_flyrec.imu_ex_0_flag_navi0", "Flag Navi0", base.HEX)
f.imu_ex_0_flag_err0 = ProtoField.uint16 ("dji_mavic_flyrec.imu_ex_0_flag_err0", "Flag Err0", base.HEX)
f.imu_ex_0_flag_rsv0 = ProtoField.uint16 ("dji_mavic_flyrec.imu_ex_0_flag_rsv0", "Flag Rsv0", base.HEX)
f.imu_ex_0_ex_cnt0 = ProtoField.uint16 ("dji_mavic_flyrec.imu_ex_0_ex_cnt0", "Ex Cnt0", base.HEX)

local function flightrec_imu_ex_0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_ex_0_vo_vx0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_0_vo_vy0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_0_vo_vz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_0_vo_px0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_0_vo_py0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_0_vo_pz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_0_us_v0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_0_us_p0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_0_rtk_long0, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_ex_0_rtk_lati0, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_ex_0_rtk_alti0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_0_flag_navi0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_0_flag_err0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_0_flag_rsv0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_0_ex_cnt0, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 60) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Ex 0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Ex 0: Payload size different than expected") end
end

-- Flight log - Imu Ex 1 - 0x0811

f.imu_ex_1_vo_vx1 = ProtoField.float ("dji_mavic_flyrec.imu_ex_1_vo_vx1", "Vo Vx1", base.DEC)
f.imu_ex_1_vo_vy1 = ProtoField.float ("dji_mavic_flyrec.imu_ex_1_vo_vy1", "Vo Vy1", base.DEC)
f.imu_ex_1_vo_vz1 = ProtoField.float ("dji_mavic_flyrec.imu_ex_1_vo_vz1", "Vo Vz1", base.DEC)
f.imu_ex_1_vo_px1 = ProtoField.float ("dji_mavic_flyrec.imu_ex_1_vo_px1", "Vo Px1", base.DEC)
f.imu_ex_1_vo_py1 = ProtoField.float ("dji_mavic_flyrec.imu_ex_1_vo_py1", "Vo Py1", base.DEC)
f.imu_ex_1_vo_pz1 = ProtoField.float ("dji_mavic_flyrec.imu_ex_1_vo_pz1", "Vo Pz1", base.DEC)
f.imu_ex_1_us_v1 = ProtoField.float ("dji_mavic_flyrec.imu_ex_1_us_v1", "Us V1", base.DEC)
f.imu_ex_1_us_p1 = ProtoField.float ("dji_mavic_flyrec.imu_ex_1_us_p1", "Us P1", base.DEC)
f.imu_ex_1_rtk_long1 = ProtoField.double ("dji_mavic_flyrec.imu_ex_1_rtk_long1", "Rtk Long1", base.DEC)
f.imu_ex_1_rtk_lati1 = ProtoField.double ("dji_mavic_flyrec.imu_ex_1_rtk_lati1", "Rtk Lati1", base.DEC)
f.imu_ex_1_rtk_alti1 = ProtoField.float ("dji_mavic_flyrec.imu_ex_1_rtk_alti1", "Rtk Alti1", base.DEC)
f.imu_ex_1_flag_navi1 = ProtoField.uint16 ("dji_mavic_flyrec.imu_ex_1_flag_navi1", "Flag Navi1", base.HEX)
f.imu_ex_1_flag_err1 = ProtoField.uint16 ("dji_mavic_flyrec.imu_ex_1_flag_err1", "Flag Err1", base.HEX)
f.imu_ex_1_flag_rsv1 = ProtoField.uint16 ("dji_mavic_flyrec.imu_ex_1_flag_rsv1", "Flag Rsv1", base.HEX)
f.imu_ex_1_ex_cnt1 = ProtoField.uint16 ("dji_mavic_flyrec.imu_ex_1_ex_cnt1", "Ex Cnt1", base.HEX)

local function flightrec_imu_ex_1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_ex_1_vo_vx1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_1_vo_vy1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_1_vo_vz1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_1_vo_px1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_1_vo_py1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_1_vo_pz1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_1_us_v1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_1_us_p1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_1_rtk_long1, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_ex_1_rtk_lati1, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_ex_1_rtk_alti1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_1_flag_navi1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_1_flag_err1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_1_flag_rsv1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_1_ex_cnt1, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 60) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Ex 1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Ex 1: Payload size different than expected") end
end

-- Flight log - Imu Ex 2 - 0x0812

f.imu_ex_2_vo_vx2 = ProtoField.float ("dji_mavic_flyrec.imu_ex_2_vo_vx2", "Vo Vx2", base.DEC)
f.imu_ex_2_vo_vy2 = ProtoField.float ("dji_mavic_flyrec.imu_ex_2_vo_vy2", "Vo Vy2", base.DEC)
f.imu_ex_2_vo_vz2 = ProtoField.float ("dji_mavic_flyrec.imu_ex_2_vo_vz2", "Vo Vz2", base.DEC)
f.imu_ex_2_vo_px2 = ProtoField.float ("dji_mavic_flyrec.imu_ex_2_vo_px2", "Vo Px2", base.DEC)
f.imu_ex_2_vo_py2 = ProtoField.float ("dji_mavic_flyrec.imu_ex_2_vo_py2", "Vo Py2", base.DEC)
f.imu_ex_2_vo_pz2 = ProtoField.float ("dji_mavic_flyrec.imu_ex_2_vo_pz2", "Vo Pz2", base.DEC)
f.imu_ex_2_us_v2 = ProtoField.float ("dji_mavic_flyrec.imu_ex_2_us_v2", "Us V2", base.DEC)
f.imu_ex_2_us_p2 = ProtoField.float ("dji_mavic_flyrec.imu_ex_2_us_p2", "Us P2", base.DEC)
f.imu_ex_2_rtk_long2 = ProtoField.double ("dji_mavic_flyrec.imu_ex_2_rtk_long2", "Rtk Long2", base.DEC)
f.imu_ex_2_rtk_lati2 = ProtoField.double ("dji_mavic_flyrec.imu_ex_2_rtk_lati2", "Rtk Lati2", base.DEC)
f.imu_ex_2_rtk_alti2 = ProtoField.float ("dji_mavic_flyrec.imu_ex_2_rtk_alti2", "Rtk Alti2", base.DEC)
f.imu_ex_2_flag_navi2 = ProtoField.uint16 ("dji_mavic_flyrec.imu_ex_2_flag_navi2", "Flag Navi2", base.HEX)
f.imu_ex_2_flag_err2 = ProtoField.uint16 ("dji_mavic_flyrec.imu_ex_2_flag_err2", "Flag Err2", base.HEX)
f.imu_ex_2_flag_rsv2 = ProtoField.uint16 ("dji_mavic_flyrec.imu_ex_2_flag_rsv2", "Flag Rsv2", base.HEX)
f.imu_ex_2_ex_cnt2 = ProtoField.uint16 ("dji_mavic_flyrec.imu_ex_2_ex_cnt2", "Ex Cnt2", base.HEX)

local function flightrec_imu_ex_2_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_ex_2_vo_vx2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_2_vo_vy2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_2_vo_vz2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_2_vo_px2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_2_vo_py2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_2_vo_pz2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_2_us_v2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_2_us_p2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_2_rtk_long2, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_ex_2_rtk_lati2, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.imu_ex_2_rtk_alti2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_ex_2_flag_navi2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_2_flag_err2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_2_flag_rsv2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_ex_2_ex_cnt2, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 60) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Ex 2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Ex 2: Payload size different than expected") end
end

-- Flight log - Atti Mini0 - 0x08a0

f.atti_mini0_s_qw0 = ProtoField.float ("dji_mavic_flyrec.atti_mini0_s_qw0", "S Qw0", base.DEC)
f.atti_mini0_s_qx0 = ProtoField.float ("dji_mavic_flyrec.atti_mini0_s_qx0", "S Qx0", base.DEC)
f.atti_mini0_s_qy0 = ProtoField.float ("dji_mavic_flyrec.atti_mini0_s_qy0", "S Qy0", base.DEC)
f.atti_mini0_s_qz0 = ProtoField.float ("dji_mavic_flyrec.atti_mini0_s_qz0", "S Qz0", base.DEC)
f.atti_mini0_s_pgz0 = ProtoField.float ("dji_mavic_flyrec.atti_mini0_s_pgz0", "S Pgz0", base.DEC)
f.atti_mini0_s_vgz0 = ProtoField.float ("dji_mavic_flyrec.atti_mini0_s_vgz0", "S Vgz0", base.DEC)
f.atti_mini0_s_agz0 = ProtoField.float ("dji_mavic_flyrec.atti_mini0_s_agz0", "S Agz0", base.DEC)
f.atti_mini0_s_rsv00 = ProtoField.uint32 ("dji_mavic_flyrec.atti_mini0_s_rsv00", "S Rsv00", base.HEX)
f.atti_mini0_s_rsv10 = ProtoField.uint32 ("dji_mavic_flyrec.atti_mini0_s_rsv10", "S Rsv10", base.HEX)
f.atti_mini0_s_cnt0 = ProtoField.uint32 ("dji_mavic_flyrec.atti_mini0_s_cnt0", "S Cnt0", base.HEX)

local function flightrec_atti_mini0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.atti_mini0_s_qw0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini0_s_qx0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini0_s_qy0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini0_s_qz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini0_s_pgz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini0_s_vgz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini0_s_agz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini0_s_rsv00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini0_s_rsv10, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini0_s_cnt0, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 40) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Atti Mini0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Atti Mini0: Payload size different than expected") end
end

-- Flight log - Atti Mini1 - 0x08a1

f.atti_mini1_s_qw1 = ProtoField.float ("dji_mavic_flyrec.atti_mini1_s_qw1", "S Qw1", base.DEC)
f.atti_mini1_s_qx1 = ProtoField.float ("dji_mavic_flyrec.atti_mini1_s_qx1", "S Qx1", base.DEC)
f.atti_mini1_s_qy1 = ProtoField.float ("dji_mavic_flyrec.atti_mini1_s_qy1", "S Qy1", base.DEC)
f.atti_mini1_s_qz1 = ProtoField.float ("dji_mavic_flyrec.atti_mini1_s_qz1", "S Qz1", base.DEC)
f.atti_mini1_s_pgz1 = ProtoField.float ("dji_mavic_flyrec.atti_mini1_s_pgz1", "S Pgz1", base.DEC)
f.atti_mini1_s_vgz1 = ProtoField.float ("dji_mavic_flyrec.atti_mini1_s_vgz1", "S Vgz1", base.DEC)
f.atti_mini1_s_agz1 = ProtoField.float ("dji_mavic_flyrec.atti_mini1_s_agz1", "S Agz1", base.DEC)
f.atti_mini1_s_rsv01 = ProtoField.uint32 ("dji_mavic_flyrec.atti_mini1_s_rsv01", "S Rsv01", base.HEX)
f.atti_mini1_s_rsv11 = ProtoField.uint32 ("dji_mavic_flyrec.atti_mini1_s_rsv11", "S Rsv11", base.HEX)
f.atti_mini1_s_cnt1 = ProtoField.uint32 ("dji_mavic_flyrec.atti_mini1_s_cnt1", "S Cnt1", base.HEX)

local function flightrec_atti_mini1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.atti_mini1_s_qw1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini1_s_qx1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini1_s_qy1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini1_s_qz1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini1_s_pgz1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini1_s_vgz1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini1_s_agz1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini1_s_rsv01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini1_s_rsv11, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini1_s_cnt1, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 40) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Atti Mini1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Atti Mini1: Payload size different than expected") end
end

-- Flight log - Atti Mini2 - 0x08a2

f.atti_mini2_s_qw2 = ProtoField.float ("dji_mavic_flyrec.atti_mini2_s_qw2", "S Qw2", base.DEC)
f.atti_mini2_s_qx2 = ProtoField.float ("dji_mavic_flyrec.atti_mini2_s_qx2", "S Qx2", base.DEC)
f.atti_mini2_s_qy2 = ProtoField.float ("dji_mavic_flyrec.atti_mini2_s_qy2", "S Qy2", base.DEC)
f.atti_mini2_s_qz2 = ProtoField.float ("dji_mavic_flyrec.atti_mini2_s_qz2", "S Qz2", base.DEC)
f.atti_mini2_s_pgz2 = ProtoField.float ("dji_mavic_flyrec.atti_mini2_s_pgz2", "S Pgz2", base.DEC)
f.atti_mini2_s_vgz2 = ProtoField.float ("dji_mavic_flyrec.atti_mini2_s_vgz2", "S Vgz2", base.DEC)
f.atti_mini2_s_agz2 = ProtoField.float ("dji_mavic_flyrec.atti_mini2_s_agz2", "S Agz2", base.DEC)
f.atti_mini2_s_rsv02 = ProtoField.uint32 ("dji_mavic_flyrec.atti_mini2_s_rsv02", "S Rsv02", base.HEX)
f.atti_mini2_s_rsv12 = ProtoField.uint32 ("dji_mavic_flyrec.atti_mini2_s_rsv12", "S Rsv12", base.HEX)
f.atti_mini2_s_cnt2 = ProtoField.uint32 ("dji_mavic_flyrec.atti_mini2_s_cnt2", "S Cnt2", base.HEX)

local function flightrec_atti_mini2_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.atti_mini2_s_qw2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini2_s_qx2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini2_s_qy2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini2_s_qz2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini2_s_pgz2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini2_s_vgz2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini2_s_agz2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini2_s_rsv02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini2_s_rsv12, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.atti_mini2_s_cnt2, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 40) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Atti Mini2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Atti Mini2: Payload size different than expected") end
end

-- Flight log - Imu Fdi 0 - 0x0860

f.imu_fdi_0_fdi_gyr0 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_0_fdi_gyr0", "Fdi Gyr0", base.HEX)
f.imu_fdi_0_fdi_acc0 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_0_fdi_acc0", "Fdi Acc0", base.HEX)
f.imu_fdi_0_fdi_bar0 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_0_fdi_bar0", "Fdi Bar0", base.HEX)
f.imu_fdi_0_fdi_mag0 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_0_fdi_mag0", "Fdi Mag0", base.HEX)
f.imu_fdi_0_fdi_gps0 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_0_fdi_gps0", "Fdi Gps0", base.HEX)
f.imu_fdi_0_fdi_ns0 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_0_fdi_ns0", "Fdi Ns0", base.HEX)
f.imu_fdi_0_fdi_multi0 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_0_fdi_multi0", "Fdi Multi0", base.HEX)
f.imu_fdi_0_fdi_cnt0 = ProtoField.uint32 ("dji_mavic_flyrec.imu_fdi_0_fdi_cnt0", "Fdi Cnt0", base.HEX)

local function flightrec_imu_fdi_0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_fdi_0_fdi_gyr0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_0_fdi_acc0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_0_fdi_bar0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_0_fdi_mag0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_0_fdi_gps0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_0_fdi_ns0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_0_fdi_multi0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_0_fdi_cnt0, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 18) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Fdi 0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Fdi 0: Payload size different than expected") end
end

-- Flight log - Imu Fdi 1 - 0x0861

f.imu_fdi_1_fdi_gyr1 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_1_fdi_gyr1", "Fdi Gyr1", base.HEX)
f.imu_fdi_1_fdi_acc1 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_1_fdi_acc1", "Fdi Acc1", base.HEX)
f.imu_fdi_1_fdi_bar1 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_1_fdi_bar1", "Fdi Bar1", base.HEX)
f.imu_fdi_1_fdi_mag1 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_1_fdi_mag1", "Fdi Mag1", base.HEX)
f.imu_fdi_1_fdi_gps1 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_1_fdi_gps1", "Fdi Gps1", base.HEX)
f.imu_fdi_1_fdi_ns1 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_1_fdi_ns1", "Fdi Ns1", base.HEX)
f.imu_fdi_1_fdi_multi1 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_1_fdi_multi1", "Fdi Multi1", base.HEX)
f.imu_fdi_1_fdi_cnt1 = ProtoField.uint32 ("dji_mavic_flyrec.imu_fdi_1_fdi_cnt1", "Fdi Cnt1", base.HEX)

local function flightrec_imu_fdi_1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_fdi_1_fdi_gyr1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_1_fdi_acc1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_1_fdi_bar1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_1_fdi_mag1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_1_fdi_gps1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_1_fdi_ns1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_1_fdi_multi1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_1_fdi_cnt1, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 18) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Fdi 1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Fdi 1: Payload size different than expected") end
end

-- Flight log - Imu Fdi 2 - 0x0862

f.imu_fdi_2_fdi_gyr2 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_2_fdi_gyr2", "Fdi Gyr2", base.HEX)
f.imu_fdi_2_fdi_acc2 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_2_fdi_acc2", "Fdi Acc2", base.HEX)
f.imu_fdi_2_fdi_bar2 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_2_fdi_bar2", "Fdi Bar2", base.HEX)
f.imu_fdi_2_fdi_mag2 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_2_fdi_mag2", "Fdi Mag2", base.HEX)
f.imu_fdi_2_fdi_gps2 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_2_fdi_gps2", "Fdi Gps2", base.HEX)
f.imu_fdi_2_fdi_ns2 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_2_fdi_ns2", "Fdi Ns2", base.HEX)
f.imu_fdi_2_fdi_multi2 = ProtoField.uint16 ("dji_mavic_flyrec.imu_fdi_2_fdi_multi2", "Fdi Multi2", base.HEX)
f.imu_fdi_2_fdi_cnt2 = ProtoField.uint32 ("dji_mavic_flyrec.imu_fdi_2_fdi_cnt2", "Fdi Cnt2", base.HEX)

local function flightrec_imu_fdi_2_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_fdi_2_fdi_gyr2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_2_fdi_acc2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_2_fdi_bar2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_2_fdi_mag2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_2_fdi_gps2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_2_fdi_ns2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_2_fdi_multi2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.imu_fdi_2_fdi_cnt2, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 18) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Fdi 2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Fdi 2: Payload size different than expected") end
end

-- Flight log - Hl Debug Data - 0x03ef

f.hl_debug_data_t_rad_v = ProtoField.float ("dji_mavic_flyrec.hl_debug_data_t_rad_v", "T Rad V", base.DEC)
f.hl_debug_data_t_tan_v = ProtoField.float ("dji_mavic_flyrec.hl_debug_data_t_tan_v", "T Tan V", base.DEC)
f.hl_debug_data_r_rad_v = ProtoField.float ("dji_mavic_flyrec.hl_debug_data_r_rad_v", "R Rad V", base.DEC)
f.hl_debug_data_r_tan_v = ProtoField.float ("dji_mavic_flyrec.hl_debug_data_r_tan_v", "R Tan V", base.DEC)

local function flightrec_hl_debug_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.hl_debug_data_t_rad_v, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hl_debug_data_t_tan_v, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hl_debug_data_r_rad_v, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hl_debug_data_r_tan_v, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 16) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Hl Debug Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Hl Debug Data: Payload size different than expected") end
end

-- Flight log - Farm Db Data - 0x03f2

f.farm_db_data_farm_mode = ProtoField.uint8 ("dji_mavic_flyrec.farm_db_data_farm_mode", "Farm Mode", base.HEX)
f.farm_db_data_dir_req = ProtoField.uint8 ("dji_mavic_flyrec.farm_db_data_dir_req", "Dir Req", base.HEX)
f.farm_db_data_cur_dir = ProtoField.uint8 ("dji_mavic_flyrec.farm_db_data_cur_dir", "Cur Dir", base.HEX)
f.farm_db_data_has_cap = ProtoField.uint8 ("dji_mavic_flyrec.farm_db_data_has_cap", "Has Cap", base.HEX)
f.farm_db_data_set_pt_a = ProtoField.uint8 ("dji_mavic_flyrec.farm_db_data_set_pt_a", "Set Pt A", base.HEX)
f.farm_db_data_set_pt_b = ProtoField.uint8 ("dji_mavic_flyrec.farm_db_data_set_pt_b", "Set Pt B", base.HEX)
f.farm_db_data_next_step = ProtoField.uint8 ("dji_mavic_flyrec.farm_db_data_next_step", "Next Step", base.HEX)
f.farm_db_data_continue = ProtoField.uint8 ("dji_mavic_flyrec.farm_db_data_continue", "Continue", base.HEX)
f.farm_db_data_resume = ProtoField.uint8 ("dji_mavic_flyrec.farm_db_data_resume", "Resume", base.HEX)
f.farm_db_data_r_dir = ProtoField.uint8 ("dji_mavic_flyrec.farm_db_data_r_dir", "R Dir", base.HEX)
f.farm_db_data_l_dir = ProtoField.uint8 ("dji_mavic_flyrec.farm_db_data_l_dir", "L Dir", base.HEX)
f.farm_db_data_rc_velx = ProtoField.float ("dji_mavic_flyrec.farm_db_data_rc_velx", "Rc Velx", base.DEC)
f.farm_db_data_rc_vely = ProtoField.float ("dji_mavic_flyrec.farm_db_data_rc_vely", "Rc Vely", base.DEC)
f.farm_db_data_rc_velz = ProtoField.float ("dji_mavic_flyrec.farm_db_data_rc_velz", "Rc Velz", base.DEC)
f.farm_db_data_rc_yaw = ProtoField.float ("dji_mavic_flyrec.farm_db_data_rc_yaw", "Rc Yaw", base.DEC)
f.farm_db_data_vel_limit = ProtoField.float ("dji_mavic_flyrec.farm_db_data_vel_limit", "Vel Limit", base.DEC)
f.farm_db_data_ref_yaw = ProtoField.float ("dji_mavic_flyrec.farm_db_data_ref_yaw", "Ref Yaw", base.DEC)
f.farm_db_data_idx_x = ProtoField.float ("dji_mavic_flyrec.farm_db_data_idx_x", "Idx X", base.DEC)
f.farm_db_data_idx_y = ProtoField.float ("dji_mavic_flyrec.farm_db_data_idx_y", "Idx Y", base.DEC)
f.farm_db_data_d_dis_x = ProtoField.float ("dji_mavic_flyrec.farm_db_data_d_dis_x", "D Dis X", base.DEC)
f.farm_db_data_d_dis_y = ProtoField.float ("dji_mavic_flyrec.farm_db_data_d_dis_y", "D Dis Y", base.DEC)
f.farm_db_data_tgt_ref_h = ProtoField.float ("dji_mavic_flyrec.farm_db_data_tgt_ref_h", "Tgt Ref H", base.DEC)
f.farm_db_data_tgt_ref_h_f = ProtoField.uint8 ("dji_mavic_flyrec.farm_db_data_tgt_ref_h_f", "Tgt Ref H F", base.HEX)
f.farm_db_data_vel_x_out = ProtoField.float ("dji_mavic_flyrec.farm_db_data_vel_x_out", "Vel X Out", base.DEC)
f.farm_db_data_vel_y_out = ProtoField.float ("dji_mavic_flyrec.farm_db_data_vel_y_out", "Vel Y Out", base.DEC)
f.farm_db_data_vel_z_out = ProtoField.float ("dji_mavic_flyrec.farm_db_data_vel_z_out", "Vel Z Out", base.DEC)
f.farm_db_data_ref_h_work = ProtoField.uint8 ("dji_mavic_flyrec.farm_db_data_ref_h_work", "Ref H Work", base.HEX)
f.farm_db_data_radar_type = ProtoField.uint8 ("dji_mavic_flyrec.farm_db_data_radar_type", "Radar Type", base.HEX)
f.farm_db_data_cur_ref_h = ProtoField.float ("dji_mavic_flyrec.farm_db_data_cur_ref_h", "Cur Ref H", base.DEC)
f.farm_db_data_ref_vz_cmd = ProtoField.float ("dji_mavic_flyrec.farm_db_data_ref_vz_cmd", "Ref Vz Cmd", base.DEC)
f.farm_db_data_ref_pz = ProtoField.float ("dji_mavic_flyrec.farm_db_data_ref_pz", "Ref Pz", base.DEC)
f.farm_db_data_app_resume_mode = ProtoField.uint8 ("dji_mavic_flyrec.farm_db_data_app_resume_mode", "App Resume Mode", base.HEX)
f.farm_db_data_resume_interaction = ProtoField.uint8 ("dji_mavic_flyrec.farm_db_data_resume_interaction", "Resume Interaction", base.HEX)
f.farm_db_data_auto_line_init_ready = ProtoField.uint8 ("dji_mavic_flyrec.farm_db_data_auto_line_init_ready", "Auto Line Init Ready", base.HEX)

local function flightrec_farm_db_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.farm_db_data_farm_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.farm_db_data_dir_req, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.farm_db_data_cur_dir, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.farm_db_data_has_cap, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.farm_db_data_set_pt_a, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.farm_db_data_set_pt_b, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.farm_db_data_next_step, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.farm_db_data_continue, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.farm_db_data_resume, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.farm_db_data_r_dir, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.farm_db_data_l_dir, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.farm_db_data_rc_velx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.farm_db_data_rc_vely, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.farm_db_data_rc_velz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.farm_db_data_rc_yaw, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.farm_db_data_vel_limit, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.farm_db_data_ref_yaw, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.farm_db_data_idx_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.farm_db_data_idx_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.farm_db_data_d_dis_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.farm_db_data_d_dis_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.farm_db_data_tgt_ref_h, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.farm_db_data_tgt_ref_h_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.farm_db_data_vel_x_out, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.farm_db_data_vel_y_out, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.farm_db_data_vel_z_out, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.farm_db_data_ref_h_work, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.farm_db_data_radar_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.farm_db_data_cur_ref_h, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.farm_db_data_ref_vz_cmd, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.farm_db_data_ref_pz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.farm_db_data_app_resume_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.farm_db_data_resume_interaction, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.farm_db_data_auto_line_init_ready, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 85) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Farm Db Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Farm Db Data: Payload size different than expected") end
end

-- Flight log - Spray Sys Ctrl Cmd - 0x4ef7

f.spray_sys_ctrl_cmd_enable_flag_0 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_ctrl_cmd_enable_flag_0", "Enable Flag 0", base.HEX)
f.spray_sys_ctrl_cmd_flow_speed_0 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_ctrl_cmd_flow_speed_0", "Flow Speed 0", base.HEX)
f.spray_sys_ctrl_cmd_enable_flag_1 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_ctrl_cmd_enable_flag_1", "Enable Flag 1", base.HEX)
f.spray_sys_ctrl_cmd_flow_speed_1 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_ctrl_cmd_flow_speed_1", "Flow Speed 1", base.HEX)
f.spray_sys_ctrl_cmd_enable_flag_2 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_ctrl_cmd_enable_flag_2", "Enable Flag 2", base.HEX)
f.spray_sys_ctrl_cmd_flow_speed_2 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_ctrl_cmd_flow_speed_2", "Flow Speed 2", base.HEX)
f.spray_sys_ctrl_cmd_enable_flag_3 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_ctrl_cmd_enable_flag_3", "Enable Flag 3", base.HEX)
f.spray_sys_ctrl_cmd_flow_speed_3 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_ctrl_cmd_flow_speed_3", "Flow Speed 3", base.HEX)
f.spray_sys_ctrl_cmd_enable_flag_4 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_ctrl_cmd_enable_flag_4", "Enable Flag 4", base.HEX)
f.spray_sys_ctrl_cmd_flow_speed_4 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_ctrl_cmd_flow_speed_4", "Flow Speed 4", base.HEX)
f.spray_sys_ctrl_cmd_enable_flag_5 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_ctrl_cmd_enable_flag_5", "Enable Flag 5", base.HEX)
f.spray_sys_ctrl_cmd_flow_speed_5 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_ctrl_cmd_flow_speed_5", "Flow Speed 5", base.HEX)
f.spray_sys_ctrl_cmd_valid_spray = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_ctrl_cmd_valid_spray", "Valid Spray", base.HEX)

local function flightrec_spray_sys_ctrl_cmd_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.spray_sys_ctrl_cmd_enable_flag_0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_ctrl_cmd_flow_speed_0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_ctrl_cmd_enable_flag_1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_ctrl_cmd_flow_speed_1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_ctrl_cmd_enable_flag_2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_ctrl_cmd_flow_speed_2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_ctrl_cmd_enable_flag_3, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_ctrl_cmd_flow_speed_3, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_ctrl_cmd_enable_flag_4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_ctrl_cmd_flow_speed_4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_ctrl_cmd_enable_flag_5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_ctrl_cmd_flow_speed_5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_ctrl_cmd_valid_spray, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 13) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Spray Sys Ctrl Cmd: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Spray Sys Ctrl Cmd: Payload size different than expected") end
end

-- Flight log - Spray Sys State - 0x4ef8

f.spray_sys_state_cap_percentage = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_cap_percentage", "Cap Percentage", base.HEX)
f.spray_sys_state_flow_speed_0 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_flow_speed_0", "Flow Speed 0", base.HEX)
f.spray_sys_state_flow_speed_1 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_flow_speed_1", "Flow Speed 1", base.HEX)
f.spray_sys_state_pump_press_1 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_pump_press_1", "Pump Press 1", base.HEX)
f.spray_sys_state_pump_press_2 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_pump_press_2", "Pump Press 2", base.HEX)
f.spray_sys_state_plug_xt90 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_plug_xt90", "Plug Xt90", base.HEX)
f.spray_sys_state_plug_xt100 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_plug_xt100", "Plug Xt100", base.HEX)
f.spray_sys_state_esc_flag_0 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_esc_flag_0", "Esc Flag 0", base.HEX)
f.spray_sys_state_reserved_0 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_reserved_0", "Reserved 0", base.HEX)
f.spray_sys_state_esc_flag_1 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_esc_flag_1", "Esc Flag 1", base.HEX)
f.spray_sys_state_reserved_1 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_reserved_1", "Reserved 1", base.HEX)
f.spray_sys_state_esc_flag_2 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_esc_flag_2", "Esc Flag 2", base.HEX)
f.spray_sys_state_reserved_2 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_reserved_2", "Reserved 2", base.HEX)
f.spray_sys_state_esc_flag_3 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_esc_flag_3", "Esc Flag 3", base.HEX)
f.spray_sys_state_reserved_3 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_reserved_3", "Reserved 3", base.HEX)
f.spray_sys_state_esc_flag_4 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_esc_flag_4", "Esc Flag 4", base.HEX)
f.spray_sys_state_reserved_4 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_reserved_4", "Reserved 4", base.HEX)
f.spray_sys_state_esc_flag_5 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_esc_flag_5", "Esc Flag 5", base.HEX)
f.spray_sys_state_reserved_5 = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_reserved_5", "Reserved 5", base.HEX)
f.spray_sys_state_cnt = ProtoField.uint8 ("dji_mavic_flyrec.spray_sys_state_cnt", "Cnt", base.HEX)

local function flightrec_spray_sys_state_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.spray_sys_state_cap_percentage, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_flow_speed_0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_flow_speed_1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_pump_press_1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_pump_press_2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_plug_xt90, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_plug_xt100, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_esc_flag_0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_reserved_0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_esc_flag_1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_reserved_1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_esc_flag_2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_reserved_2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_esc_flag_3, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_reserved_3, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_esc_flag_4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_reserved_4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_esc_flag_5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_reserved_5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.spray_sys_state_cnt, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Spray Sys State: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Spray Sys State: Payload size different than expected") end
end

-- Flight log - Ctrl Vert Debug - 0x04b0

f.ctrl_vert_debug_vert_mode = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vert_debug_vert_mode", "Vert Mode", base.HEX)
f.ctrl_vert_debug_vert_state = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vert_debug_vert_state", "Vert State", base.HEX)
f.ctrl_vert_debug_vert_flag = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vert_debug_vert_flag", "Vert Flag", base.HEX)
f.ctrl_vert_debug_vert_pos = ProtoField.float ("dji_mavic_flyrec.ctrl_vert_debug_vert_pos", "Vert Pos", base.DEC)
f.ctrl_vert_debug_vert_brk_t = ProtoField.float ("dji_mavic_flyrec.ctrl_vert_debug_vert_brk_t", "Vert Brk T", base.DEC)
f.ctrl_vert_debug_near_bound = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vert_debug_near_bound", "Near Bound", base.HEX)
f.ctrl_vert_debug_true_h_lmt = ProtoField.float ("dji_mavic_flyrec.ctrl_vert_debug_true_h_lmt", "True H Lmt", base.DEC)
f.ctrl_vert_debug_takeoff_t = ProtoField.float ("dji_mavic_flyrec.ctrl_vert_debug_takeoff_t", "Takeoff T", base.DEC)
f.ctrl_vert_debug_hit_gnd = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vert_debug_hit_gnd", "Hit Gnd", base.HEX)
f.ctrl_vert_debug_high_os_f = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vert_debug_high_os_f", "High Os F", base.HEX)
f.ctrl_vert_debug_low_os_f = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vert_debug_low_os_f", "Low Os F", base.HEX)
f.ctrl_vert_debug_ap_high_os_f = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vert_debug_ap_high_os_f", "Ap High Os F", base.HEX)
f.ctrl_vert_debug_gnd_os_f = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vert_debug_gnd_os_f", "Gnd Os F", base.HEX)
f.ctrl_vert_debug_rf_os_f = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vert_debug_rf_os_f", "Rf Os F", base.HEX)
f.ctrl_vert_debug_v_lmt_os_f = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vert_debug_v_lmt_os_f", "V Lmt Os F", base.HEX)
f.ctrl_vert_debug_landing_tyoe = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vert_debug_landing_tyoe", "Landing Tyoe", base.HEX)

local function flightrec_ctrl_vert_debug_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ctrl_vert_debug_vert_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_debug_vert_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_debug_vert_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_debug_vert_pos, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_vert_debug_vert_brk_t, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_vert_debug_near_bound, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_debug_true_h_lmt, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_vert_debug_takeoff_t, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_vert_debug_hit_gnd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_debug_high_os_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_debug_low_os_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_debug_ap_high_os_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_debug_gnd_os_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_debug_rf_os_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_debug_v_lmt_os_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vert_debug_landing_tyoe, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 28) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ctrl Vert Debug: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ctrl Vert Debug: Payload size different than expected") end
end

-- Flight log - Ctrl Pos Vert Debug - 0x04b1

f.ctrl_pos_vert_debug_pos_tag = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_pos_vert_debug_pos_tag", "Pos Tag", base.HEX)
f.ctrl_pos_vert_debug_pos_cmd = ProtoField.int16 ("dji_mavic_flyrec.ctrl_pos_vert_debug_pos_cmd", "Pos Cmd", base.DEC)
f.ctrl_pos_vert_debug_pos_fdbk = ProtoField.int16 ("dji_mavic_flyrec.ctrl_pos_vert_debug_pos_fdbk", "Pos Fdbk", base.DEC)

local function flightrec_ctrl_pos_vert_debug_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ctrl_pos_vert_debug_pos_tag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_pos_vert_debug_pos_cmd, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_pos_vert_debug_pos_fdbk, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ctrl Pos Vert Debug: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ctrl Pos Vert Debug: Payload size different than expected") end
end

-- Flight log - Ctrl Vel Vert Debug - 0x04b2

f.ctrl_vel_vert_debug_vel_tag = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vel_vert_debug_vel_tag", "Vel Tag", base.HEX)
f.ctrl_vel_vert_debug_vel_cmd = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_vel_cmd", "Vel Cmd", base.DEC)
f.ctrl_vel_vert_debug_vel_before = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_vel_before", "Vel Before", base.DEC)
f.ctrl_vel_vert_debug_vel_after = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_vel_after", "Vel After", base.DEC)
f.ctrl_vel_vert_debug_vel_fdbk = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_vel_fdbk", "Vel Fdbk", base.DEC)
f.ctrl_vel_vert_debug_gnd_en = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vel_vert_debug_gnd_en", "Gnd En", base.HEX)
f.ctrl_vel_vert_debug_gnd_work = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vel_vert_debug_gnd_work", "Gnd Work", base.HEX)
f.ctrl_vel_vert_debug_gnd_norm = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_gnd_norm", "Gnd Norm", base.DEC)
f.ctrl_vel_vert_debug_gnd_damp = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_gnd_damp", "Gnd Damp", base.DEC)
f.ctrl_vel_vert_debug_roof_en = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vel_vert_debug_roof_en", "Roof En", base.HEX)
f.ctrl_vel_vert_debug_roof_work = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vel_vert_debug_roof_work", "Roof Work", base.HEX)
f.ctrl_vel_vert_debug_roof_norm = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_roof_norm", "Roof Norm", base.DEC)
f.ctrl_vel_vert_debug_roof_damp = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_roof_damp", "Roof Damp", base.DEC)
f.ctrl_vel_vert_debug_low_en = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vel_vert_debug_low_en", "Low En", base.HEX)
f.ctrl_vel_vert_debug_low_work = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vel_vert_debug_low_work", "Low Work", base.HEX)
f.ctrl_vel_vert_debug_low_norm = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_low_norm", "Low Norm", base.DEC)
f.ctrl_vel_vert_debug_low_damp = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_low_damp", "Low Damp", base.DEC)
f.ctrl_vel_vert_debug_high_en = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vel_vert_debug_high_en", "High En", base.HEX)
f.ctrl_vel_vert_debug_high_work = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vel_vert_debug_high_work", "High Work", base.HEX)
f.ctrl_vel_vert_debug_high_norm = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_high_norm", "High Norm", base.DEC)
f.ctrl_vel_vert_debug_high_damp = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_high_damp", "High Damp", base.DEC)
f.ctrl_vel_vert_debug_ap_work = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vel_vert_debug_ap_work", "Ap Work", base.HEX)
f.ctrl_vel_vert_debug_ap_en0 = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vel_vert_debug_ap_en0", "Ap En0", base.HEX)
f.ctrl_vel_vert_debug_ap_norm0 = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_ap_norm0", "Ap Norm0", base.DEC)
f.ctrl_vel_vert_debug_ap_damp0 = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_ap_damp0", "Ap Damp0", base.DEC)
f.ctrl_vel_vert_debug_ap_en1 = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vel_vert_debug_ap_en1", "Ap En1", base.HEX)
f.ctrl_vel_vert_debug_ap_norm1 = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_ap_norm1", "Ap Norm1", base.DEC)
f.ctrl_vel_vert_debug_ap_damp1 = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_ap_damp1", "Ap Damp1", base.DEC)
f.ctrl_vel_vert_debug_ap_en2 = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vel_vert_debug_ap_en2", "Ap En2", base.HEX)
f.ctrl_vel_vert_debug_ap_norm2 = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_ap_norm2", "Ap Norm2", base.DEC)
f.ctrl_vel_vert_debug_ap_damp2 = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_ap_damp2", "Ap Damp2", base.DEC)
f.ctrl_vel_vert_debug_hit_en = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vel_vert_debug_hit_en", "Hit En", base.HEX)
f.ctrl_vel_vert_debug_hit_work = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_vel_vert_debug_hit_work", "Hit Work", base.HEX)
f.ctrl_vel_vert_debug_hit_norm = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_hit_norm", "Hit Norm", base.DEC)
f.ctrl_vel_vert_debug_hit_damp = ProtoField.int16 ("dji_mavic_flyrec.ctrl_vel_vert_debug_hit_damp", "Hit Damp", base.DEC)

local function flightrec_ctrl_vel_vert_debug_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ctrl_vel_vert_debug_vel_tag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vel_vert_debug_vel_cmd, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_vel_before, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_vel_after, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_vel_fdbk, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_gnd_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vel_vert_debug_gnd_work, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vel_vert_debug_gnd_norm, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_gnd_damp, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_roof_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vel_vert_debug_roof_work, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vel_vert_debug_roof_norm, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_roof_damp, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_low_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vel_vert_debug_low_work, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vel_vert_debug_low_norm, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_low_damp, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_high_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vel_vert_debug_high_work, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vel_vert_debug_high_norm, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_high_damp, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_ap_work, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vel_vert_debug_ap_en0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vel_vert_debug_ap_norm0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_ap_damp0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_ap_en1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vel_vert_debug_ap_norm1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_ap_damp1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_ap_en2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vel_vert_debug_ap_norm2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_ap_damp2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_hit_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vel_vert_debug_hit_work, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_vel_vert_debug_hit_norm, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_vel_vert_debug_hit_damp, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 55) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ctrl Vel Vert Debug: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ctrl Vel Vert Debug: Payload size different than expected") end
end

-- Flight log - Ctrl Acc Vert Debug - 0x04b3

f.ctrl_acc_vert_debug_acc_tag = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_acc_vert_debug_acc_tag", "Acc Tag", base.HEX)
f.ctrl_acc_vert_debug_acc_cmd = ProtoField.int16 ("dji_mavic_flyrec.ctrl_acc_vert_debug_acc_cmd", "Acc Cmd", base.DEC)
f.ctrl_acc_vert_debug_acc_fdbk = ProtoField.int16 ("dji_mavic_flyrec.ctrl_acc_vert_debug_acc_fdbk", "Acc Fdbk", base.DEC)
f.ctrl_acc_vert_debug_thr_cmd = ProtoField.int16 ("dji_mavic_flyrec.ctrl_acc_vert_debug_thr_cmd", "Thr Cmd", base.DEC)

local function flightrec_ctrl_acc_vert_debug_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ctrl_acc_vert_debug_acc_tag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_acc_vert_debug_acc_cmd, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_acc_vert_debug_acc_fdbk, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_acc_vert_debug_thr_cmd, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 7) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ctrl Acc Vert Debug: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ctrl Acc Vert Debug: Payload size different than expected") end
end

-- Flight log - Ctrl Horiz Debug - 0x0514

f.ctrl_horiz_debug_horiz_mode = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_horiz_mode", "Horiz Mode", base.HEX)
f.ctrl_horiz_debug_hov_state = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_hov_state", "Hov State", base.HEX)
f.ctrl_horiz_debug_hov_flag = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_hov_flag", "Hov Flag", base.HEX)
f.ctrl_horiz_debug_hov_px = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_debug_hov_px", "Hov Px", base.DEC)
f.ctrl_horiz_debug_hov_py = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_debug_hov_py", "Hov Py", base.DEC)
f.ctrl_horiz_debug_hov_brk_t = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_debug_hov_brk_t", "Hov Brk T", base.DEC)
f.ctrl_horiz_debug_hov_cfrm_t = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_debug_hov_cfrm_t", "Hov Cfrm T", base.DEC)
f.ctrl_horiz_debug_pos_cmdx = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_debug_pos_cmdx", "Pos Cmdx", base.DEC)
f.ctrl_horiz_debug_pos_cmdy = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_debug_pos_cmdy", "Pos Cmdy", base.DEC)
f.ctrl_horiz_debug_vel_cmdx = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_debug_vel_cmdx", "Vel Cmdx", base.DEC)
f.ctrl_horiz_debug_vel_cmdy = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_debug_vel_cmdy", "Vel Cmdy", base.DEC)
f.ctrl_horiz_debug_h_api_mode = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_h_api_mode", "H Api Mode", base.HEX)
f.ctrl_horiz_debug_h_api_frm = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_h_api_frm", "H Api Frm", base.HEX)
f.ctrl_horiz_debug_tilt_cmd_x = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_debug_tilt_cmd_x", "Tilt Cmd X", base.DEC)
f.ctrl_horiz_debug_tilt_cmd_y = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_debug_tilt_cmd_y", "Tilt Cmd Y", base.DEC)
f.ctrl_horiz_debug_v_ctrl_mod = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_v_ctrl_mod", "V Ctrl Mod", base.HEX)
f.ctrl_horiz_debug_trs_f_req = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_trs_f_req", "Trs F Req", base.HEX)
f.ctrl_horiz_debug_trs_f_flg = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_trs_f_flg", "Trs F Flg", base.HEX)
f.ctrl_horiz_debug_trs_mod = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_trs_mod", "Trs Mod", base.HEX)
f.ctrl_horiz_debug_trs_lck_st = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_trs_lck_st", "Trs Lck St", base.HEX)
f.ctrl_horiz_debug_trs_p_cmd = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_debug_trs_p_cmd", "Trs P Cmd", base.DEC)
f.ctrl_horiz_debug_trs_v_cmd = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_debug_trs_v_cmd", "Trs V Cmd", base.DEC)
f.ctrl_horiz_debug_trs_p_lck = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_debug_trs_p_lck", "Trs P Lck", base.DEC)
f.ctrl_horiz_debug_trs_lck_t = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_debug_trs_lck_t", "Trs Lck T", base.DEC)
f.ctrl_horiz_debug_emg_brk_f = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_emg_brk_f", "Emg Brk F", base.HEX)
f.ctrl_horiz_debug_near_bnd = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_near_bnd", "Near Bnd", base.HEX)
f.ctrl_horiz_debug_al_avoid = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_debug_al_avoid", "Al Avoid", base.DEC)
f.ctrl_horiz_debug_al_gmb_typ = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_debug_al_gmb_typ", "Al Gmb Typ", base.DEC)
f.ctrl_horiz_debug_al_bat = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_debug_al_bat", "Al Bat", base.DEC)
f.ctrl_horiz_debug_al_gmb_pri = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_debug_al_gmb_pri", "Al Gmb Pri", base.DEC)
f.ctrl_horiz_debug_al_final = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_debug_al_final", "Al Final", base.DEC)
f.ctrl_horiz_debug_avoid_en = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_avoid_en", "Avoid En", base.HEX)
f.ctrl_horiz_debug_flw_gmb_f = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_flw_gmb_f", "Flw Gmb F", base.HEX)
f.ctrl_horiz_debug_in_flw_gmb = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_in_flw_gmb", "In Flw Gmb", base.HEX)
f.ctrl_horiz_debug_gf_tgt_yaw = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_debug_gf_tgt_yaw", "Gf Tgt Yaw", base.DEC)
f.ctrl_horiz_debug_gf_cur_yaw = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_debug_gf_cur_yaw", "Gf Cur Yaw", base.DEC)
f.ctrl_horiz_debug_g_tgt_gyro = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_debug_g_tgt_gyro", "G Tgt Gyro", base.DEC)
f.ctrl_horiz_debug_track_en = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_track_en", "Track En", base.HEX)
f.ctrl_horiz_debug_watch_mode = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_watch_mode", "Watch Mode", base.HEX)
f.ctrl_horiz_debug_trck_yaw_v = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_debug_trck_yaw_v", "Trck Yaw V", base.DEC)
f.ctrl_horiz_debug_cl_tors = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_debug_cl_tors", "Cl Tors", base.DEC)
f.ctrl_horiz_debug_ap_os_f = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_ap_os_f", "Ap Os F", base.HEX)
f.ctrl_horiz_debug_avd_ob_os_f = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_avd_ob_os_f", "Avd Ob Os F", base.HEX)
f.ctrl_horiz_debug_h_fence_os_f = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_h_fence_os_f", "H Fence Os F", base.HEX)
f.ctrl_horiz_debug_r_os_f = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_r_os_f", "R Os F", base.HEX)
f.ctrl_horiz_debug_h_lmt_os_f = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_debug_h_lmt_os_f", "H Lmt Os F", base.HEX)
f.ctrl_horiz_debug_true_rad_lmt = ProtoField.uint16 ("dji_mavic_flyrec.ctrl_horiz_debug_true_rad_lmt", "True Rad Lmt", base.HEX)

local function flightrec_ctrl_horiz_debug_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ctrl_horiz_debug_horiz_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_hov_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_hov_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_hov_px, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_debug_hov_py, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_debug_hov_brk_t, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_debug_hov_cfrm_t, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_debug_pos_cmdx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_debug_pos_cmdy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_debug_vel_cmdx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_debug_vel_cmdy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_debug_h_api_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_h_api_frm, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_tilt_cmd_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_debug_tilt_cmd_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_debug_v_ctrl_mod, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_trs_f_req, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_trs_f_flg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_trs_mod, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_trs_lck_st, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_trs_p_cmd, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_debug_trs_v_cmd, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_debug_trs_p_lck, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_debug_trs_lck_t, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_debug_emg_brk_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_near_bnd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_al_avoid, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_debug_al_gmb_typ, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_debug_al_bat, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_debug_al_gmb_pri, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_debug_al_final, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_debug_avoid_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_flw_gmb_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_in_flw_gmb, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_gf_tgt_yaw, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_debug_gf_cur_yaw, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_debug_g_tgt_gyro, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_debug_track_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_watch_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_trck_yaw_v, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_debug_cl_tors, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_debug_ap_os_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_avd_ob_os_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_h_fence_os_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_r_os_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_h_lmt_os_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_debug_true_rad_lmt, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 102) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ctrl Horiz Debug: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ctrl Horiz Debug: Payload size different than expected") end
end

-- Flight log - Ctrl Horiz Pos Debug - 0x0515

f.ctrl_horiz_pos_debug_pos_tag = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_pos_debug_pos_tag", "Pos Tag", base.HEX)
f.ctrl_horiz_pos_debug_pos_cmdx = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_pos_debug_pos_cmdx", "Pos Cmdx", base.DEC)
f.ctrl_horiz_pos_debug_pos_cmdy = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_pos_debug_pos_cmdy", "Pos Cmdy", base.DEC)

local function flightrec_ctrl_horiz_pos_debug_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ctrl_horiz_pos_debug_pos_tag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_pos_debug_pos_cmdx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_pos_debug_pos_cmdy, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 9) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ctrl Horiz Pos Debug: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ctrl Horiz Pos Debug: Payload size different than expected") end
end

-- Flight log - Ctrl Horiz Vel Debug - 0x0516

f.ctrl_horiz_vel_debug_vel_tag = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_vel_tag", "Vel Tag", base.HEX)
f.ctrl_horiz_vel_debug_vel_cmdx = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_vel_debug_vel_cmdx", "Vel Cmdx", base.DEC)
f.ctrl_horiz_vel_debug_vel_cmdy = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_vel_debug_vel_cmdy", "Vel Cmdy", base.DEC)
f.ctrl_horiz_vel_debug_befor_cmdx = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_vel_debug_befor_cmdx", "Befor Cmdx", base.DEC)
f.ctrl_horiz_vel_debug_befor_cmdy = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_vel_debug_befor_cmdy", "Befor Cmdy", base.DEC)
f.ctrl_horiz_vel_debug_fltr_cmdx = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_vel_debug_fltr_cmdx", "Fltr Cmdx", base.DEC)
f.ctrl_horiz_vel_debug_fltr_cmdy = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_vel_debug_fltr_cmdy", "Fltr Cmdy", base.DEC)
f.ctrl_horiz_vel_debug_dyn_gain = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_vel_debug_dyn_gain", "Dyn Gain", base.DEC)
f.ctrl_horiz_vel_debug_dyn_p_gain = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_vel_debug_dyn_p_gain", "Dyn P Gain", base.DEC)
f.ctrl_horiz_vel_debug_vel_fdbkx = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_vel_debug_vel_fdbkx", "Vel Fdbkx", base.DEC)
f.ctrl_horiz_vel_debug_vel_fdbky = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_vel_debug_vel_fdbky", "Vel Fdbky", base.DEC)
f.ctrl_horiz_vel_debug_rad_en = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_rad_en", "Rad En", base.HEX)
f.ctrl_horiz_vel_debug_rad_work = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_rad_work", "Rad Work", base.HEX)
f.ctrl_horiz_vel_debug_rad_dir_x = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_rad_dir_x", "Rad Dir X", base.DEC)
f.ctrl_horiz_vel_debug_rad_dir_y = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_rad_dir_y", "Rad Dir Y", base.DEC)
f.ctrl_horiz_vel_debug_rad_norm = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_rad_norm", "Rad Norm", base.DEC)
f.ctrl_horiz_vel_debug_rad_direct = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_rad_direct", "Rad Direct", base.DEC)
f.ctrl_horiz_vel_debug_rad_damp = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_rad_damp", "Rad Damp", base.DEC)
f.ctrl_horiz_vel_debug_ap0_en = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap0_en", "Ap0 En", base.HEX)
f.ctrl_horiz_vel_debug_ap0_work = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap0_work", "Ap0 Work", base.HEX)
f.ctrl_horiz_vel_debug_ap0_dir_x = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap0_dir_x", "Ap0 Dir X", base.DEC)
f.ctrl_horiz_vel_debug_ap0_dir_y = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap0_dir_y", "Ap0 Dir Y", base.DEC)
f.ctrl_horiz_vel_debug_ap0_norm = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap0_norm", "Ap0 Norm", base.DEC)
f.ctrl_horiz_vel_debug_ap0_direct = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap0_direct", "Ap0 Direct", base.DEC)
f.ctrl_horiz_vel_debug_ap0_damp = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap0_damp", "Ap0 Damp", base.DEC)
f.ctrl_horiz_vel_debug_ap0_dis = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap0_dis", "Ap0 Dis", base.DEC)
f.ctrl_horiz_vel_debug_ap1_en = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap1_en", "Ap1 En", base.HEX)
f.ctrl_horiz_vel_debug_ap1_work = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap1_work", "Ap1 Work", base.HEX)
f.ctrl_horiz_vel_debug_ap1_dir_x = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap1_dir_x", "Ap1 Dir X", base.DEC)
f.ctrl_horiz_vel_debug_ap1_dir_y = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap1_dir_y", "Ap1 Dir Y", base.DEC)
f.ctrl_horiz_vel_debug_ap1_norm = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap1_norm", "Ap1 Norm", base.DEC)
f.ctrl_horiz_vel_debug_ap1_direct = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap1_direct", "Ap1 Direct", base.DEC)
f.ctrl_horiz_vel_debug_ap1_damp = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap1_damp", "Ap1 Damp", base.DEC)
f.ctrl_horiz_vel_debug_ap1_dis = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap1_dis", "Ap1 Dis", base.DEC)
f.ctrl_horiz_vel_debug_ap2_en = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap2_en", "Ap2 En", base.HEX)
f.ctrl_horiz_vel_debug_ap2_work = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap2_work", "Ap2 Work", base.HEX)
f.ctrl_horiz_vel_debug_ap2_dir_x = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap2_dir_x", "Ap2 Dir X", base.DEC)
f.ctrl_horiz_vel_debug_ap2_dir_y = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap2_dir_y", "Ap2 Dir Y", base.DEC)
f.ctrl_horiz_vel_debug_ap2_norm = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap2_norm", "Ap2 Norm", base.DEC)
f.ctrl_horiz_vel_debug_ap2_direct = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap2_direct", "Ap2 Direct", base.DEC)
f.ctrl_horiz_vel_debug_ap2_damp = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap2_damp", "Ap2 Damp", base.DEC)
f.ctrl_horiz_vel_debug_ap2_dis = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ap2_dis", "Ap2 Dis", base.DEC)
f.ctrl_horiz_vel_debug_ao0_en = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao0_en", "Ao0 En", base.HEX)
f.ctrl_horiz_vel_debug_ao0_work = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao0_work", "Ao0 Work", base.HEX)
f.ctrl_horiz_vel_debug_ao0_dir_x = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao0_dir_x", "Ao0 Dir X", base.DEC)
f.ctrl_horiz_vel_debug_ao0_dir_y = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao0_dir_y", "Ao0 Dir Y", base.DEC)
f.ctrl_horiz_vel_debug_ao0_norm = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao0_norm", "Ao0 Norm", base.DEC)
f.ctrl_horiz_vel_debug_ao0_direct = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao0_direct", "Ao0 Direct", base.DEC)
f.ctrl_horiz_vel_debug_ao0_damp = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao0_damp", "Ao0 Damp", base.DEC)
f.ctrl_horiz_vel_debug_ao1_en = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao1_en", "Ao1 En", base.HEX)
f.ctrl_horiz_vel_debug_ao1_work = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao1_work", "Ao1 Work", base.HEX)
f.ctrl_horiz_vel_debug_ao1_dir_x = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao1_dir_x", "Ao1 Dir X", base.DEC)
f.ctrl_horiz_vel_debug_ao1_dir_y = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao1_dir_y", "Ao1 Dir Y", base.DEC)
f.ctrl_horiz_vel_debug_ao1_norm = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao1_norm", "Ao1 Norm", base.DEC)
f.ctrl_horiz_vel_debug_ao1_direct = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao1_direct", "Ao1 Direct", base.DEC)
f.ctrl_horiz_vel_debug_ao1_damp = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao1_damp", "Ao1 Damp", base.DEC)
f.ctrl_horiz_vel_debug_ao2_en = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao2_en", "Ao2 En", base.HEX)
f.ctrl_horiz_vel_debug_ao2_work = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao2_work", "Ao2 Work", base.HEX)
f.ctrl_horiz_vel_debug_ao2_dir_x = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao2_dir_x", "Ao2 Dir X", base.DEC)
f.ctrl_horiz_vel_debug_ao2_dir_y = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao2_dir_y", "Ao2 Dir Y", base.DEC)
f.ctrl_horiz_vel_debug_ao2_norm = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao2_norm", "Ao2 Norm", base.DEC)
f.ctrl_horiz_vel_debug_ao2_direct = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao2_direct", "Ao2 Direct", base.DEC)
f.ctrl_horiz_vel_debug_ao2_damp = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao2_damp", "Ao2 Damp", base.DEC)
f.ctrl_horiz_vel_debug_ao3_en = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao3_en", "Ao3 En", base.HEX)
f.ctrl_horiz_vel_debug_ao3_work = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao3_work", "Ao3 Work", base.HEX)
f.ctrl_horiz_vel_debug_ao3_dir_x = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao3_dir_x", "Ao3 Dir X", base.DEC)
f.ctrl_horiz_vel_debug_ao3_dir_y = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao3_dir_y", "Ao3 Dir Y", base.DEC)
f.ctrl_horiz_vel_debug_ao3_norm = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao3_norm", "Ao3 Norm", base.DEC)
f.ctrl_horiz_vel_debug_ao3_direct = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao3_direct", "Ao3 Direct", base.DEC)
f.ctrl_horiz_vel_debug_ao3_damp = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_vel_debug_ao3_damp", "Ao3 Damp", base.DEC)

local function flightrec_ctrl_horiz_vel_debug_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ctrl_horiz_vel_debug_vel_tag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_vel_debug_vel_cmdx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_vel_debug_vel_cmdy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_vel_debug_befor_cmdx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_vel_debug_befor_cmdy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_vel_debug_fltr_cmdx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_vel_debug_fltr_cmdy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_vel_debug_dyn_gain, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_vel_debug_dyn_p_gain, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_vel_debug_vel_fdbkx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_vel_debug_vel_fdbky, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_vel_debug_rad_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_vel_debug_rad_work, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_vel_debug_rad_dir_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_rad_dir_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_rad_norm, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_rad_direct, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_rad_damp, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ap0_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_vel_debug_ap0_work, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_vel_debug_ap0_dir_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ap0_dir_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ap0_norm, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ap0_direct, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ap0_damp, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ap0_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ap1_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_vel_debug_ap1_work, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_vel_debug_ap1_dir_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ap1_dir_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ap1_norm, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ap1_direct, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ap1_damp, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ap1_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ap2_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_vel_debug_ap2_work, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_vel_debug_ap2_dir_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ap2_dir_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ap2_norm, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ap2_direct, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ap2_damp, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ap2_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao0_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_vel_debug_ao0_work, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_vel_debug_ao0_dir_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao0_dir_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao0_norm, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao0_direct, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao0_damp, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao1_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_vel_debug_ao1_work, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_vel_debug_ao1_dir_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao1_dir_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao1_norm, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao1_direct, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao1_damp, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao2_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_vel_debug_ao2_work, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_vel_debug_ao2_dir_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao2_dir_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao2_norm, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao2_direct, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao2_damp, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao3_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_vel_debug_ao3_work, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_vel_debug_ao3_dir_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao3_dir_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao3_norm, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao3_direct, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_vel_debug_ao3_damp, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 143) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ctrl Horiz Vel Debug: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ctrl Horiz Vel Debug: Payload size different than expected") end
end

-- Flight log - Ctrl Horiz Atti Debug - 0x0518

f.ctrl_horiz_atti_debug_atti_tag = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_atti_debug_atti_tag", "Atti Tag", base.HEX)
f.ctrl_horiz_atti_debug_tors_type = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_horiz_atti_debug_tors_type", "Tors Type", base.HEX)
f.ctrl_horiz_atti_debug_tgt_tors = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_atti_debug_tgt_tors", "Tgt Tors", base.DEC)
f.ctrl_horiz_atti_debug_tgt_tilt_x = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_atti_debug_tgt_tilt_x", "Tgt Tilt X", base.DEC)
f.ctrl_horiz_atti_debug_tgt_tilt_y = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_atti_debug_tgt_tilt_y", "Tgt Tilt Y", base.DEC)
f.ctrl_horiz_atti_debug_tgt_body_x = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_atti_debug_tgt_body_x", "Tgt Body X", base.DEC)
f.ctrl_horiz_atti_debug_tgt_body_y = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_atti_debug_tgt_body_y", "Tgt Body Y", base.DEC)
f.ctrl_horiz_atti_debug_cur_tors = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_atti_debug_cur_tors", "Cur Tors", base.DEC)
f.ctrl_horiz_atti_debug_cur_tilt_x = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_atti_debug_cur_tilt_x", "Cur Tilt X", base.DEC)
f.ctrl_horiz_atti_debug_cur_tilt_y = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_atti_debug_cur_tilt_y", "Cur Tilt Y", base.DEC)

local function flightrec_ctrl_horiz_atti_debug_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ctrl_horiz_atti_debug_atti_tag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_atti_debug_tors_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_horiz_atti_debug_tgt_tors, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_atti_debug_tgt_tilt_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_atti_debug_tgt_tilt_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_atti_debug_tgt_body_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_atti_debug_tgt_body_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_atti_debug_cur_tors, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_atti_debug_cur_tilt_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_atti_debug_cur_tilt_y, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 34) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ctrl Horiz Atti Debug: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ctrl Horiz Atti Debug: Payload size different than expected") end
end

-- Flight log - Ctrl Horiz Ang Vel Debug - 0x0519

f.ctrl_horiz_ang_vel_debug_gyro_cmdx = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_ang_vel_debug_gyro_cmdx", "Gyro Cmdx", base.DEC)
f.ctrl_horiz_ang_vel_debug_gyro_cmdy = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_ang_vel_debug_gyro_cmdy", "Gyro Cmdy", base.DEC)
f.ctrl_horiz_ang_vel_debug_gyro_cmdz = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_ang_vel_debug_gyro_cmdz", "Gyro Cmdz", base.DEC)
f.ctrl_horiz_ang_vel_debug_gyro_fbkx = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_ang_vel_debug_gyro_fbkx", "Gyro Fbkx", base.DEC)
f.ctrl_horiz_ang_vel_debug_gyro_fbky = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_ang_vel_debug_gyro_fbky", "Gyro Fbky", base.DEC)
f.ctrl_horiz_ang_vel_debug_gyro_fbkz = ProtoField.float ("dji_mavic_flyrec.ctrl_horiz_ang_vel_debug_gyro_fbkz", "Gyro Fbkz", base.DEC)

local function flightrec_ctrl_horiz_ang_vel_debug_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ctrl_horiz_ang_vel_debug_gyro_cmdx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_ang_vel_debug_gyro_cmdy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_ang_vel_debug_gyro_cmdz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_ang_vel_debug_gyro_fbkx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_ang_vel_debug_gyro_fbky, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_horiz_ang_vel_debug_gyro_fbkz, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 24) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ctrl Horiz Ang Vel Debug: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ctrl Horiz Ang Vel Debug: Payload size different than expected") end
end

-- Flight log - Ctrl Horiz Ccpm Debug - 0x051a

f.ctrl_horiz_ccpm_debug_raw_tilt_x = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_ccpm_debug_raw_tilt_x", "Raw Tilt X", base.DEC)
f.ctrl_horiz_ccpm_debug_raw_tilt_y = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_ccpm_debug_raw_tilt_y", "Raw Tilt Y", base.DEC)
f.ctrl_horiz_ccpm_debug_raw_tors = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_ccpm_debug_raw_tors", "Raw Tors", base.DEC)
f.ctrl_horiz_ccpm_debug_raw_lift = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_ccpm_debug_raw_lift", "Raw Lift", base.DEC)
f.ctrl_horiz_ccpm_debug_fix_tilt_x = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_ccpm_debug_fix_tilt_x", "Fix Tilt X", base.DEC)
f.ctrl_horiz_ccpm_debug_fix_tilt_y = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_ccpm_debug_fix_tilt_y", "Fix Tilt Y", base.DEC)
f.ctrl_horiz_ccpm_debug_fix_tor = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_ccpm_debug_fix_tor", "Fix Tor", base.DEC)
f.ctrl_horiz_ccpm_debug_fix_lift = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_ccpm_debug_fix_lift", "Fix Lift", base.DEC)
f.ctrl_horiz_ccpm_debug_thr_max = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_ccpm_debug_thr_max", "Thr Max", base.DEC)
f.ctrl_horiz_ccpm_debug_thr_min = ProtoField.int16 ("dji_mavic_flyrec.ctrl_horiz_ccpm_debug_thr_min", "Thr Min", base.DEC)

local function flightrec_ctrl_horiz_ccpm_debug_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ctrl_horiz_ccpm_debug_raw_tilt_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_ccpm_debug_raw_tilt_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_ccpm_debug_raw_tors, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_ccpm_debug_raw_lift, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_ccpm_debug_fix_tilt_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_ccpm_debug_fix_tilt_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_ccpm_debug_fix_tor, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_ccpm_debug_fix_lift, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_ccpm_debug_thr_max, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_ccpm_debug_thr_min, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ctrl Horiz Ccpm Debug: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ctrl Horiz Ccpm Debug: Payload size different than expected") end
end

-- Flight log - Ctrl Horiz Motor Debug - 0x051b

f.ctrl_horiz_motor_debug_pwm1 = ProtoField.uint16 ("dji_mavic_flyrec.ctrl_horiz_motor_debug_pwm1", "Pwm1", base.HEX)
f.ctrl_horiz_motor_debug_pwm2 = ProtoField.uint16 ("dji_mavic_flyrec.ctrl_horiz_motor_debug_pwm2", "Pwm2", base.HEX)
f.ctrl_horiz_motor_debug_pwm3 = ProtoField.uint16 ("dji_mavic_flyrec.ctrl_horiz_motor_debug_pwm3", "Pwm3", base.HEX)
f.ctrl_horiz_motor_debug_pwm4 = ProtoField.uint16 ("dji_mavic_flyrec.ctrl_horiz_motor_debug_pwm4", "Pwm4", base.HEX)
f.ctrl_horiz_motor_debug_pwm5 = ProtoField.uint16 ("dji_mavic_flyrec.ctrl_horiz_motor_debug_pwm5", "Pwm5", base.HEX)
f.ctrl_horiz_motor_debug_pwm6 = ProtoField.uint16 ("dji_mavic_flyrec.ctrl_horiz_motor_debug_pwm6", "Pwm6", base.HEX)
f.ctrl_horiz_motor_debug_pwm7 = ProtoField.uint16 ("dji_mavic_flyrec.ctrl_horiz_motor_debug_pwm7", "Pwm7", base.HEX)
f.ctrl_horiz_motor_debug_pwm8 = ProtoField.uint16 ("dji_mavic_flyrec.ctrl_horiz_motor_debug_pwm8", "Pwm8", base.HEX)

local function flightrec_ctrl_horiz_motor_debug_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ctrl_horiz_motor_debug_pwm1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_motor_debug_pwm2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_motor_debug_pwm3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_motor_debug_pwm4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_motor_debug_pwm5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_motor_debug_pwm6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_motor_debug_pwm7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ctrl_horiz_motor_debug_pwm8, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 16) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ctrl Horiz Motor Debug: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ctrl Horiz Motor Debug: Payload size different than expected") end
end

-- Flight log - Ctrl Sweep Test - 0x051c

f.ctrl_sweep_test_inj_a = ProtoField.float ("dji_mavic_flyrec.ctrl_sweep_test_inj_a", "Inj A", base.DEC)
f.ctrl_sweep_test_inj_b = ProtoField.float ("dji_mavic_flyrec.ctrl_sweep_test_inj_b", "Inj B", base.DEC)
f.ctrl_sweep_test_r = ProtoField.float ("dji_mavic_flyrec.ctrl_sweep_test_r", "R", base.DEC)
f.ctrl_sweep_test_e = ProtoField.float ("dji_mavic_flyrec.ctrl_sweep_test_e", "E", base.DEC)
f.ctrl_sweep_test_u = ProtoField.float ("dji_mavic_flyrec.ctrl_sweep_test_u", "U", base.DEC)
f.ctrl_sweep_test_y = ProtoField.float ("dji_mavic_flyrec.ctrl_sweep_test_y", "Y", base.DEC)

local function flightrec_ctrl_sweep_test_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ctrl_sweep_test_inj_a, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_sweep_test_inj_b, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_sweep_test_r, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_sweep_test_e, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_sweep_test_u, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_sweep_test_y, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 24) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ctrl Sweep Test: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ctrl Sweep Test: Payload size different than expected") end
end

-- Flight log - Way Debug Info - 0x0460

f.way_debug_info_mis_stus = ProtoField.uint8 ("dji_mavic_flyrec.way_debug_info_mis_stus", "Mis Stus", base.HEX)
f.way_debug_info_wp_num = ProtoField.uint8 ("dji_mavic_flyrec.way_debug_info_wp_num", "Wp Num", base.HEX)
f.way_debug_info_t_vel = ProtoField.int16 ("dji_mavic_flyrec.way_debug_info_t_vel", "T Vel", base.DEC)
f.way_debug_info_traj_type = ProtoField.uint8 ("dji_mavic_flyrec.way_debug_info_traj_type", "Traj Type", base.HEX)
f.way_debug_info_wp_t = ProtoField.uint16 ("dji_mavic_flyrec.way_debug_info_wp_t", "Wp T", base.HEX)
f.way_debug_info_t_p_x = ProtoField.float ("dji_mavic_flyrec.way_debug_info_t_p_x", "T P X", base.DEC)
f.way_debug_info_t_p_y = ProtoField.float ("dji_mavic_flyrec.way_debug_info_t_p_y", "T P Y", base.DEC)
f.way_debug_info_t_p_z = ProtoField.float ("dji_mavic_flyrec.way_debug_info_t_p_z", "T P Z", base.DEC)
f.way_debug_info_t_v_x = ProtoField.float ("dji_mavic_flyrec.way_debug_info_t_v_x", "T V X", base.DEC)
f.way_debug_info_t_v_y = ProtoField.float ("dji_mavic_flyrec.way_debug_info_t_v_y", "T V Y", base.DEC)
f.way_debug_info_t_v_z = ProtoField.float ("dji_mavic_flyrec.way_debug_info_t_v_z", "T V Z", base.DEC)
f.way_debug_info_f_p_x = ProtoField.float ("dji_mavic_flyrec.way_debug_info_f_p_x", "F P X", base.DEC)
f.way_debug_info_f_p_y = ProtoField.float ("dji_mavic_flyrec.way_debug_info_f_p_y", "F P Y", base.DEC)
f.way_debug_info_f_p_z = ProtoField.float ("dji_mavic_flyrec.way_debug_info_f_p_z", "F P Z", base.DEC)
f.way_debug_info_v_x = ProtoField.float ("dji_mavic_flyrec.way_debug_info_v_x", "V X", base.DEC)
f.way_debug_info_v_y = ProtoField.float ("dji_mavic_flyrec.way_debug_info_v_y", "V Y", base.DEC)
f.way_debug_info_v_z = ProtoField.float ("dji_mavic_flyrec.way_debug_info_v_z", "V Z", base.DEC)
f.way_debug_info_dv_x = ProtoField.float ("dji_mavic_flyrec.way_debug_info_dv_x", "Dv X", base.DEC)
f.way_debug_info_dv_y = ProtoField.float ("dji_mavic_flyrec.way_debug_info_dv_y", "Dv Y", base.DEC)
f.way_debug_info_ddv_z = ProtoField.float ("dji_mavic_flyrec.way_debug_info_ddv_z", "Ddv Z", base.DEC)
f.way_debug_info_dmp_scl = ProtoField.uint8 ("dji_mavic_flyrec.way_debug_info_dmp_scl", "Dmp Scl", base.HEX)
f.way_debug_info_v_dyn_g = ProtoField.float ("dji_mavic_flyrec.way_debug_info_v_dyn_g", "V Dyn G", base.DEC)
f.way_debug_info_p_dyn_g = ProtoField.float ("dji_mavic_flyrec.way_debug_info_p_dyn_g", "P Dyn G", base.DEC)
f.way_debug_info_is_pud = ProtoField.uint8 ("dji_mavic_flyrec.way_debug_info_is_pud", "Is Pud", base.HEX)
f.way_debug_info_debug_ref_flag = ProtoField.uint8 ("dji_mavic_flyrec.way_debug_info_debug_ref_flag", "Debug Ref Flag", base.HEX)
f.way_debug_info_debug_ref_h = ProtoField.float ("dji_mavic_flyrec.way_debug_info_debug_ref_h", "Debug Ref H", base.DEC)
f.way_debug_info_debug_ref_cmd = ProtoField.uint8 ("dji_mavic_flyrec.way_debug_info_debug_ref_cmd", "Debug Ref Cmd", base.HEX)
f.way_debug_info_debug_resume_mode = ProtoField.uint8 ("dji_mavic_flyrec.way_debug_info_debug_resume_mode", "Debug Resume Mode", base.HEX)

local function flightrec_way_debug_info_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.way_debug_info_mis_stus, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.way_debug_info_wp_num, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.way_debug_info_t_vel, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.way_debug_info_traj_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.way_debug_info_wp_t, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.way_debug_info_t_p_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.way_debug_info_t_p_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.way_debug_info_t_p_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.way_debug_info_t_v_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.way_debug_info_t_v_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.way_debug_info_t_v_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.way_debug_info_f_p_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.way_debug_info_f_p_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.way_debug_info_f_p_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.way_debug_info_v_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.way_debug_info_v_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.way_debug_info_v_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.way_debug_info_dv_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.way_debug_info_dv_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.way_debug_info_ddv_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.way_debug_info_dmp_scl, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.way_debug_info_v_dyn_g, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.way_debug_info_p_dyn_g, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.way_debug_info_is_pud, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.way_debug_info_debug_ref_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.way_debug_info_debug_ref_h, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.way_debug_info_debug_ref_cmd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.way_debug_info_debug_resume_mode, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 84) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Way Debug Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Way Debug Info: Payload size different than expected") end
end

-- Flight log - Svo Avoid - 0x0461

f.svo_avoid_ao_en = ProtoField.uint8 ("dji_mavic_flyrec.svo_avoid_ao_en", "Ao En", base.HEX)
f.svo_avoid_ua_en = ProtoField.uint8 ("dji_mavic_flyrec.svo_avoid_ua_en", "Ua En", base.HEX)
f.svo_avoid_ao_wf = ProtoField.uint8 ("dji_mavic_flyrec.svo_avoid_ao_wf", "Ao Wf", base.HEX)
f.svo_avoid_brake_wf = ProtoField.uint8 ("dji_mavic_flyrec.svo_avoid_brake_wf", "Brake Wf", base.HEX)
f.svo_avoid_gha_en = ProtoField.uint8 ("dji_mavic_flyrec.svo_avoid_gha_en", "Gha En", base.HEX)
f.svo_avoid_fl_f = ProtoField.uint8 ("dji_mavic_flyrec.svo_avoid_fl_f", "Fl F", base.HEX)
f.svo_avoid_rl_wf = ProtoField.uint8 ("dji_mavic_flyrec.svo_avoid_rl_wf", "Rl Wf", base.HEX)
f.svo_avoid_al_wf = ProtoField.uint8 ("dji_mavic_flyrec.svo_avoid_al_wf", "Al Wf", base.HEX)
f.svo_avoid_ao_wf = ProtoField.uint8 ("dji_mavic_flyrec.svo_avoid_ao_wf", "Ao Wf", base.HEX)
f.svo_avoid_boundary_f = ProtoField.uint8 ("dji_mavic_flyrec.svo_avoid_boundary_f", "Boundary F", base.HEX)
f.svo_avoid_overshoot_f = ProtoField.uint8 ("dji_mavic_flyrec.svo_avoid_overshoot_f", "Overshoot F", base.HEX)
f.svo_avoid_v_ll_wf = ProtoField.uint8 ("dji_mavic_flyrec.svo_avoid_v_ll_wf", "V Ll Wf", base.HEX)
f.svo_avoid_v_al_wf = ProtoField.uint8 ("dji_mavic_flyrec.svo_avoid_v_al_wf", "V Al Wf", base.HEX)
f.svo_avoid_rl_f = ProtoField.uint8 ("dji_mavic_flyrec.svo_avoid_rl_f", "Rl F", base.HEX)
f.svo_avoid_hgl_wf = ProtoField.uint8 ("dji_mavic_flyrec.svo_avoid_hgl_wf", "Hgl Wf", base.HEX)

local function flightrec_svo_avoid_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.svo_avoid_ao_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_avoid_ua_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_avoid_ao_wf, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_avoid_brake_wf, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_avoid_gha_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_avoid_fl_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_avoid_rl_wf, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_avoid_al_wf, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_avoid_ao_wf, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_avoid_boundary_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_avoid_overshoot_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_avoid_v_ll_wf, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_avoid_v_al_wf, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_avoid_rl_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.svo_avoid_hgl_wf, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 15) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Svo Avoid: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Svo Avoid: Payload size different than expected") end
end

-- Flight log - Simulator Debug Data - 0x0578

f.simulator_debug_data_thrust = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_thrust", "Thrust", base.DEC)
f.simulator_debug_data_r_moment = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_r_moment", "R Moment", base.DEC)
f.simulator_debug_data_p_moment = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_p_moment", "P Moment", base.DEC)
f.simulator_debug_data_y_moment = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_y_moment", "Y Moment", base.DEC)
f.simulator_debug_data_drag_x = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_drag_x", "Drag X", base.DEC)
f.simulator_debug_data_drag_y = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_drag_y", "Drag Y", base.DEC)
f.simulator_debug_data_drag_z = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_drag_z", "Drag Z", base.DEC)
f.simulator_debug_data_e_force_x = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_e_force_x", "E Force X", base.DEC)
f.simulator_debug_data_e_force_y = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_e_force_y", "E Force Y", base.DEC)
f.simulator_debug_data_e_force_z = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_e_force_z", "E Force Z", base.DEC)
f.simulator_debug_data_e_moment_x = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_e_moment_x", "E Moment X", base.DEC)
f.simulator_debug_data_e_moment_y = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_e_moment_y", "E Moment Y", base.DEC)
f.simulator_debug_data_e_moment_z = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_e_moment_z", "E Moment Z", base.DEC)
f.simulator_debug_data_e_mome_f_x = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_e_mome_f_x", "E Mome F X", base.DEC)
f.simulator_debug_data_e_mome_f_y = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_e_mome_f_y", "E Mome F Y", base.DEC)
f.simulator_debug_data_e_mome_f_z = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_e_mome_f_z", "E Mome F Z", base.DEC)
f.simulator_debug_data_dura_time = ProtoField.uint32 ("dji_mavic_flyrec.simulator_debug_data_dura_time", "Dura Time", base.HEX)
f.simulator_debug_data_longti = ProtoField.double ("dji_mavic_flyrec.simulator_debug_data_longti", "Longti", base.DEC)
f.simulator_debug_data_lati = ProtoField.double ("dji_mavic_flyrec.simulator_debug_data_lati", "Lati", base.DEC)
f.simulator_debug_data_pos_x_w = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_pos_x_w", "Pos X W", base.DEC)
f.simulator_debug_data_pos_y_w = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_pos_y_w", "Pos Y W", base.DEC)
f.simulator_debug_data_pos_z_w = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_pos_z_w", "Pos Z W", base.DEC)
f.simulator_debug_data_height_ = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_height_", "Height ", base.DEC)
f.simulator_debug_data_vel_x_w = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_vel_x_w", "Vel X W", base.DEC)
f.simulator_debug_data_vel_y_w = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_vel_y_w", "Vel Y W", base.DEC)
f.simulator_debug_data_vel_z_w = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_vel_z_w", "Vel Z W", base.DEC)
f.simulator_debug_data_acc_x_w = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_acc_x_w", "Acc X W", base.DEC)
f.simulator_debug_data_acc_y_w = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_acc_y_w", "Acc Y W", base.DEC)
f.simulator_debug_data_acc_z_w = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_acc_z_w", "Acc Z W", base.DEC)
f.simulator_debug_data_roll = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_roll", "Roll", base.DEC)
f.simulator_debug_data_pitch = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_pitch", "Pitch", base.DEC)
f.simulator_debug_data_yaw = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_yaw", "Yaw", base.DEC)
f.simulator_debug_data_q0 = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_q0", "Q0", base.DEC)
f.simulator_debug_data_q1 = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_q1", "Q1", base.DEC)
f.simulator_debug_data_q2 = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_q2", "Q2", base.DEC)
f.simulator_debug_data_q3 = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_q3", "Q3", base.DEC)
f.simulator_debug_data_p = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_p", "P", base.DEC)
f.simulator_debug_data_q = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_q", "Q", base.DEC)
f.simulator_debug_data_r = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_r", "R", base.DEC)
f.simulator_debug_data_p_dot = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_p_dot", "P Dot", base.DEC)
f.simulator_debug_data_q_dot = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_q_dot", "Q Dot", base.DEC)
f.simulator_debug_data_r_dot = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_r_dot", "R Dot", base.DEC)
f.simulator_debug_data_comp_mx = ProtoField.int16 ("dji_mavic_flyrec.simulator_debug_data_comp_mx", "Comp.Mx", base.DEC)
f.simulator_debug_data_comp_my = ProtoField.int16 ("dji_mavic_flyrec.simulator_debug_data_comp_my", "Comp.My", base.DEC)
f.simulator_debug_data_comp_mz = ProtoField.int16 ("dji_mavic_flyrec.simulator_debug_data_comp_mz", "Comp.Mz", base.DEC)
f.simulator_debug_data_acc_x_b = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_acc_x_b", "Acc X B", base.DEC)
f.simulator_debug_data_acc_y_b = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_acc_y_b", "Acc Y B", base.DEC)
f.simulator_debug_data_acc_z_b = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_acc_z_b", "Acc Z B", base.DEC)
f.simulator_debug_data_flag = ProtoField.uint8 ("dji_mavic_flyrec.simulator_debug_data_flag", "Flag", base.HEX)
f.simulator_debug_data_sys_time = ProtoField.float ("dji_mavic_flyrec.simulator_debug_data_sys_time", "Sys Time", base.DEC)
f.simulator_debug_data_crash_flag = ProtoField.uint8 ("dji_mavic_flyrec.simulator_debug_data_crash_flag", "Crash Flag", base.HEX)

local function flightrec_simulator_debug_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.simulator_debug_data_thrust, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_r_moment, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_p_moment, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_y_moment, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_drag_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_drag_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_drag_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_e_force_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_e_force_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_e_force_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_e_moment_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_e_moment_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_e_moment_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_e_mome_f_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_e_mome_f_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_e_mome_f_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_dura_time, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_longti, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.simulator_debug_data_lati, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.simulator_debug_data_pos_x_w, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_pos_y_w, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_pos_z_w, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_height_, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_vel_x_w, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_vel_y_w, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_vel_z_w, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_acc_x_w, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_acc_y_w, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_acc_z_w, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_roll, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_pitch, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_yaw, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_q0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_q1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_q2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_q3, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_p, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_q, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_r, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_p_dot, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_q_dot, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_r_dot, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_comp_mx, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_debug_data_comp_my, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_debug_data_comp_mz, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_debug_data_acc_x_b, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_acc_y_b, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_acc_z_b, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.simulator_debug_data_sys_time, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_debug_data_crash_flag, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 200) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Simulator Debug Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Simulator Debug Data: Payload size different than expected") end
end

-- Flight log - Simulator Gyro Acc Data 400Hz - 0x0579

f.simulator_gyro_acc_data_400hz_acc_temp = ProtoField.float ("dji_mavic_flyrec.simulator_gyro_acc_data_400hz_acc_temp", "Acc Temp", base.DEC)
f.simulator_gyro_acc_data_400hz_acc_x = ProtoField.float ("dji_mavic_flyrec.simulator_gyro_acc_data_400hz_acc_x", "Acc X", base.DEC)
f.simulator_gyro_acc_data_400hz_acc_y = ProtoField.float ("dji_mavic_flyrec.simulator_gyro_acc_data_400hz_acc_y", "Acc Y", base.DEC)
f.simulator_gyro_acc_data_400hz_acc_z = ProtoField.float ("dji_mavic_flyrec.simulator_gyro_acc_data_400hz_acc_z", "Acc Z", base.DEC)
f.simulator_gyro_acc_data_400hz_gyro_temp = ProtoField.float ("dji_mavic_flyrec.simulator_gyro_acc_data_400hz_gyro_temp", "Gyro Temp", base.DEC)
f.simulator_gyro_acc_data_400hz_gyro_x = ProtoField.float ("dji_mavic_flyrec.simulator_gyro_acc_data_400hz_gyro_x", "Gyro X", base.DEC)
f.simulator_gyro_acc_data_400hz_gyro_y = ProtoField.float ("dji_mavic_flyrec.simulator_gyro_acc_data_400hz_gyro_y", "Gyro Y", base.DEC)
f.simulator_gyro_acc_data_400hz_gyro_z = ProtoField.float ("dji_mavic_flyrec.simulator_gyro_acc_data_400hz_gyro_z", "Gyro Z", base.DEC)

local function flightrec_simulator_gyro_acc_data_400hz_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.simulator_gyro_acc_data_400hz_acc_temp, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gyro_acc_data_400hz_acc_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gyro_acc_data_400hz_acc_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gyro_acc_data_400hz_acc_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gyro_acc_data_400hz_gyro_temp, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gyro_acc_data_400hz_gyro_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gyro_acc_data_400hz_gyro_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gyro_acc_data_400hz_gyro_z, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 32) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Simulator Gyro Acc Data 400Hz: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Simulator Gyro Acc Data 400Hz: Payload size different than expected") end
end

-- Flight log - Simulator Press Data 200Hz - 0x057c

f.simulator_press_data_200hz_press = ProtoField.float ("dji_mavic_flyrec.simulator_press_data_200hz_press", "Press", base.DEC)
f.simulator_press_data_200hz_temp = ProtoField.float ("dji_mavic_flyrec.simulator_press_data_200hz_temp", "Temp", base.DEC)

local function flightrec_simulator_press_data_200hz_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.simulator_press_data_200hz_press, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_press_data_200hz_temp, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Simulator Press Data 200Hz: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Simulator Press Data 200Hz: Payload size different than expected") end
end

-- Flight log - Simulator Mag Data 50Hz - 0x057a

f.simulator_mag_data_50hz_data = ProtoField.int16 ("dji_mavic_flyrec.simulator_mag_data_50hz_data", "Data", base.DEC)
f.simulator_mag_data_50hz_data = ProtoField.int16 ("dji_mavic_flyrec.simulator_mag_data_50hz_data", "Data", base.DEC)
f.simulator_mag_data_50hz_data = ProtoField.int16 ("dji_mavic_flyrec.simulator_mag_data_50hz_data", "Data", base.DEC)
f.simulator_mag_data_50hz_cnt = ProtoField.uint16 ("dji_mavic_flyrec.simulator_mag_data_50hz_cnt", "Cnt", base.HEX)

local function flightrec_simulator_mag_data_50hz_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.simulator_mag_data_50hz_data, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_mag_data_50hz_data, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_mag_data_50hz_data, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_mag_data_50hz_cnt, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Simulator Mag Data 50Hz: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Simulator Mag Data 50Hz: Payload size different than expected") end
end

-- Flight log - Simulator Gps Data 5Hz - 0x057b

f.simulator_gps_data_5hz_date = ProtoField.uint32 ("dji_mavic_flyrec.simulator_gps_data_5hz_date", "Date", base.HEX)
f.simulator_gps_data_5hz_time = ProtoField.uint32 ("dji_mavic_flyrec.simulator_gps_data_5hz_time", "Time", base.HEX)
f.simulator_gps_data_5hz_lon = ProtoField.int32 ("dji_mavic_flyrec.simulator_gps_data_5hz_lon", "Lon", base.DEC)
f.simulator_gps_data_5hz_lat = ProtoField.int32 ("dji_mavic_flyrec.simulator_gps_data_5hz_lat", "Lat", base.DEC)
f.simulator_gps_data_5hz_hmsl = ProtoField.int32 ("dji_mavic_flyrec.simulator_gps_data_5hz_hmsl", "Hmsl", base.DEC)
f.simulator_gps_data_5hz_vel_n = ProtoField.float ("dji_mavic_flyrec.simulator_gps_data_5hz_vel_n", "Vel N", base.DEC)
f.simulator_gps_data_5hz_vel_e = ProtoField.float ("dji_mavic_flyrec.simulator_gps_data_5hz_vel_e", "Vel E", base.DEC)
f.simulator_gps_data_5hz_vel_d = ProtoField.float ("dji_mavic_flyrec.simulator_gps_data_5hz_vel_d", "Vel D", base.DEC)
f.simulator_gps_data_5hz_hdop = ProtoField.float ("dji_mavic_flyrec.simulator_gps_data_5hz_hdop", "Hdop", base.DEC)
f.simulator_gps_data_5hz_pdop = ProtoField.float ("dji_mavic_flyrec.simulator_gps_data_5hz_pdop", "Pdop", base.DEC)
f.simulator_gps_data_5hz_gnss_flag = ProtoField.float ("dji_mavic_flyrec.simulator_gps_data_5hz_gnss_flag", "Gnss Flag", base.DEC)
f.simulator_gps_data_5hz_hacc = ProtoField.float ("dji_mavic_flyrec.simulator_gps_data_5hz_hacc", "Hacc", base.DEC)
f.simulator_gps_data_5hz_sacc = ProtoField.float ("dji_mavic_flyrec.simulator_gps_data_5hz_sacc", "Sacc", base.DEC)
f.simulator_gps_data_5hz_gps_fix = ProtoField.float ("dji_mavic_flyrec.simulator_gps_data_5hz_gps_fix", "Gps Fix", base.DEC)
f.simulator_gps_data_5hz_gps_used = ProtoField.uint32 ("dji_mavic_flyrec.simulator_gps_data_5hz_gps_used", "Gps Used", base.HEX)
f.simulator_gps_data_5hz_gln_used = ProtoField.uint32 ("dji_mavic_flyrec.simulator_gps_data_5hz_gln_used", "Gln Used", base.HEX)
f.simulator_gps_data_5hz_numsv = ProtoField.uint16 ("dji_mavic_flyrec.simulator_gps_data_5hz_numsv", "Numsv", base.HEX)
f.simulator_gps_data_5hz_gpsstate = ProtoField.uint16 ("dji_mavic_flyrec.simulator_gps_data_5hz_gpsstate", "Gpsstate", base.HEX)

local function flightrec_simulator_gps_data_5hz_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.simulator_gps_data_5hz_date, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gps_data_5hz_time, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gps_data_5hz_lon, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gps_data_5hz_lat, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gps_data_5hz_hmsl, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gps_data_5hz_vel_n, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gps_data_5hz_vel_e, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gps_data_5hz_vel_d, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gps_data_5hz_hdop, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gps_data_5hz_pdop, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gps_data_5hz_gnss_flag, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gps_data_5hz_hacc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gps_data_5hz_sacc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gps_data_5hz_gps_fix, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gps_data_5hz_gps_used, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gps_data_5hz_gln_used, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_gps_data_5hz_numsv, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_gps_data_5hz_gpsstate, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 68) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Simulator Gps Data 5Hz: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Simulator Gps Data 5Hz: Payload size different than expected") end
end

-- Flight log - Simulator Motor Data - 0x057e

f.simulator_motor_data_m1_current = ProtoField.int16 ("dji_mavic_flyrec.simulator_motor_data_m1_current", "M1 Current", base.DEC)
f.simulator_motor_data_m1_speed = ProtoField.uint16 ("dji_mavic_flyrec.simulator_motor_data_m1_speed", "M1 Speed", base.HEX)
f.simulator_motor_data_m2_current = ProtoField.int16 ("dji_mavic_flyrec.simulator_motor_data_m2_current", "M2 Current", base.DEC)
f.simulator_motor_data_m2_speed = ProtoField.uint16 ("dji_mavic_flyrec.simulator_motor_data_m2_speed", "M2 Speed", base.HEX)
f.simulator_motor_data_m3_current = ProtoField.int16 ("dji_mavic_flyrec.simulator_motor_data_m3_current", "M3 Current", base.DEC)
f.simulator_motor_data_m3_speed = ProtoField.uint16 ("dji_mavic_flyrec.simulator_motor_data_m3_speed", "M3 Speed", base.HEX)
f.simulator_motor_data_m4_current = ProtoField.int16 ("dji_mavic_flyrec.simulator_motor_data_m4_current", "M4 Current", base.DEC)
f.simulator_motor_data_m4_speed = ProtoField.uint16 ("dji_mavic_flyrec.simulator_motor_data_m4_speed", "M4 Speed", base.HEX)
f.simulator_motor_data_m5_current = ProtoField.int16 ("dji_mavic_flyrec.simulator_motor_data_m5_current", "M5 Current", base.DEC)
f.simulator_motor_data_m5_speed = ProtoField.uint16 ("dji_mavic_flyrec.simulator_motor_data_m5_speed", "M5 Speed", base.HEX)
f.simulator_motor_data_m6_current = ProtoField.int16 ("dji_mavic_flyrec.simulator_motor_data_m6_current", "M6 Current", base.DEC)
f.simulator_motor_data_m6_speed = ProtoField.uint16 ("dji_mavic_flyrec.simulator_motor_data_m6_speed", "M6 Speed", base.HEX)
f.simulator_motor_data_m7_current = ProtoField.int16 ("dji_mavic_flyrec.simulator_motor_data_m7_current", "M7 Current", base.DEC)
f.simulator_motor_data_m7_speed = ProtoField.uint16 ("dji_mavic_flyrec.simulator_motor_data_m7_speed", "M7 Speed", base.HEX)
f.simulator_motor_data_m8_current = ProtoField.int16 ("dji_mavic_flyrec.simulator_motor_data_m8_current", "M8 Current", base.DEC)
f.simulator_motor_data_m8_speed = ProtoField.uint16 ("dji_mavic_flyrec.simulator_motor_data_m8_speed", "M8 Speed", base.HEX)

local function flightrec_simulator_motor_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.simulator_motor_data_m1_current, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_motor_data_m1_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_motor_data_m2_current, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_motor_data_m2_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_motor_data_m3_current, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_motor_data_m3_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_motor_data_m4_current, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_motor_data_m4_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_motor_data_m5_current, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_motor_data_m5_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_motor_data_m6_current, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_motor_data_m6_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_motor_data_m7_current, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_motor_data_m7_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_motor_data_m8_current, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_motor_data_m8_speed, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 32) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Simulator Motor Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Simulator Motor Data: Payload size different than expected") end
end

-- Flight log - Device Change Times - 0x057d

f.device_change_times_bat = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_bat", "Bat", base.HEX)
f.device_change_times_esc = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_esc", "Esc", base.HEX)
f.device_change_times_sys = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_sys", "Sys", base.HEX)
f.device_change_times_fmu = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_fmu", "Fmu", base.HEX)
f.device_change_times_mc = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_mc", "Mc", base.HEX)
f.device_change_times_imu = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_imu", "Imu", base.HEX)
f.device_change_times_gps = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_gps", "Gps", base.HEX)
f.device_change_times_gyro = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_gyro", "Gyro", base.HEX)
f.device_change_times_acc = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_acc", "Acc", base.HEX)
f.device_change_times_gyro_acc = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_gyro_acc", "Gyro Acc", base.HEX)
f.device_change_times_baro = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_baro", "Baro", base.HEX)
f.device_change_times_compass = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_compass", "Compass", base.HEX)
f.device_change_times_ultr = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_ultr", "Ultr", base.HEX)
f.device_change_times_vo = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_vo", "Vo", base.HEX)
f.device_change_times_radar = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_radar", "Radar", base.HEX)
f.device_change_times_camera = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_camera", "Camera", base.HEX)
f.device_change_times_gimbal = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_gimbal", "Gimbal", base.HEX)
f.device_change_times_trans = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_trans", "Trans", base.HEX)
f.device_change_times_led = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_led", "Led", base.HEX)
f.device_change_times_pc = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_pc", "Pc", base.HEX)
f.device_change_times_rc = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_rc", "Rc", base.HEX)
f.device_change_times_bs = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_bs", "Bs", base.HEX)
f.device_change_times_sdk = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_sdk", "Sdk", base.HEX)
f.device_change_times_spray = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_spray", "Spray", base.HEX)
f.device_change_times_tof = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_tof", "Tof", base.HEX)
f.device_change_times_wristband = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_wristband", "Wristband", base.HEX)
f.device_change_times_headset = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_headset", "Headset", base.HEX)
f.device_change_times_all = ProtoField.uint16 ("dji_mavic_flyrec.device_change_times_all", "All", base.HEX)

local function flightrec_device_change_times_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.device_change_times_bat, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_esc, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_sys, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_fmu, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_mc, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_imu, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_gps, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_gyro, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_acc, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_gyro_acc, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_baro, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_compass, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_ultr, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_vo, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_radar, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_camera, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_gimbal, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_trans, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_led, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_pc, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_rc, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_bs, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_sdk, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_spray, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_tof, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_wristband, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_headset, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.device_change_times_all, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 56) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Device Change Times: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Device Change Times: Payload size different than expected") end
end

-- Flight log - Simulator Config Aircraft Param - 0x0582

f.simulator_config_aircraft_param_arm_len = ProtoField.float ("dji_mavic_flyrec.simulator_config_aircraft_param_arm_len", "Arm Len", base.DEC)
f.simulator_config_aircraft_param_b_area = ProtoField.float ("dji_mavic_flyrec.simulator_config_aircraft_param_b_area", "B Area", base.DEC)
f.simulator_config_aircraft_param_b_area = ProtoField.float ("dji_mavic_flyrec.simulator_config_aircraft_param_b_area", "B Area", base.DEC)
f.simulator_config_aircraft_param_b_area = ProtoField.float ("dji_mavic_flyrec.simulator_config_aircraft_param_b_area", "B Area", base.DEC)
f.simulator_config_aircraft_param_inertia = ProtoField.float ("dji_mavic_flyrec.simulator_config_aircraft_param_inertia", "Inertia", base.DEC)
f.simulator_config_aircraft_param_inertia = ProtoField.float ("dji_mavic_flyrec.simulator_config_aircraft_param_inertia", "Inertia", base.DEC)
f.simulator_config_aircraft_param_inertia = ProtoField.float ("dji_mavic_flyrec.simulator_config_aircraft_param_inertia", "Inertia", base.DEC)
f.simulator_config_aircraft_param_mass = ProtoField.float ("dji_mavic_flyrec.simulator_config_aircraft_param_mass", "Mass", base.DEC)

local function flightrec_simulator_config_aircraft_param_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.simulator_config_aircraft_param_arm_len, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_aircraft_param_b_area, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_aircraft_param_b_area, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_aircraft_param_b_area, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_aircraft_param_inertia, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_aircraft_param_inertia, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_aircraft_param_inertia, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_aircraft_param_mass, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 32) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Simulator Config Aircraft Param: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Simulator Config Aircraft Param: Payload size different than expected") end
end

-- Flight log - Simulator Config Battery Param - 0x0583

f.simulator_config_battery_param_cell_num = ProtoField.uint8 ("dji_mavic_flyrec.simulator_config_battery_param_cell_num", "Cell Num", base.HEX)
f.simulator_config_battery_param_cell_v = ProtoField.uint16 ("dji_mavic_flyrec.simulator_config_battery_param_cell_v", "Cell V", base.HEX)
f.simulator_config_battery_param_cycle_cnt = ProtoField.uint8 ("dji_mavic_flyrec.simulator_config_battery_param_cycle_cnt", "Cycle Cnt", base.HEX)
f.simulator_config_battery_param_design_cap = ProtoField.uint16 ("dji_mavic_flyrec.simulator_config_battery_param_design_cap", "Design Cap", base.HEX)
f.simulator_config_battery_param_error_cnt = ProtoField.uint16 ("dji_mavic_flyrec.simulator_config_battery_param_error_cnt", "Error Cnt", base.HEX)
f.simulator_config_battery_param_i_cap_per = ProtoField.uint8 ("dji_mavic_flyrec.simulator_config_battery_param_i_cap_per", "I Cap Per", base.HEX)
f.simulator_config_battery_param_i_temp = ProtoField.float ("dji_mavic_flyrec.simulator_config_battery_param_i_temp", "I Temp", base.DEC)
f.simulator_config_battery_param_internal_r = ProtoField.float ("dji_mavic_flyrec.simulator_config_battery_param_internal_r", "Internal R", base.DEC)
f.simulator_config_battery_param_mdate = ProtoField.uint16 ("dji_mavic_flyrec.simulator_config_battery_param_mdate", "Mdate", base.HEX)
f.simulator_config_battery_param_seq_num = ProtoField.uint16 ("dji_mavic_flyrec.simulator_config_battery_param_seq_num", "Seq Num", base.HEX)
f.simulator_config_battery_param_standby_i = ProtoField.float ("dji_mavic_flyrec.simulator_config_battery_param_standby_i", "Standby I", base.DEC)

local function flightrec_simulator_config_battery_param_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.simulator_config_battery_param_cell_num, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.simulator_config_battery_param_cell_v, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_config_battery_param_cycle_cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.simulator_config_battery_param_design_cap, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_config_battery_param_error_cnt, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_config_battery_param_i_cap_per, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.simulator_config_battery_param_i_temp, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_battery_param_internal_r, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_battery_param_mdate, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_config_battery_param_seq_num, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_config_battery_param_standby_i, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 25) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Simulator Config Battery Param: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Simulator Config Battery Param: Payload size different than expected") end
end

-- Flight log - Simulator Config Environment Param - 0x0584

f.simulator_config_environment_param_density = ProtoField.float ("dji_mavic_flyrec.simulator_config_environment_param_density", "Density", base.DEC)
f.simulator_config_environment_param_drag_coef = ProtoField.float ("dji_mavic_flyrec.simulator_config_environment_param_drag_coef", "Drag Coef", base.DEC)
f.simulator_config_environment_param_wind_s = ProtoField.float ("dji_mavic_flyrec.simulator_config_environment_param_wind_s", "Wind S", base.DEC)
f.simulator_config_environment_param_wind_s = ProtoField.float ("dji_mavic_flyrec.simulator_config_environment_param_wind_s", "Wind S", base.DEC)
f.simulator_config_environment_param_wind_s = ProtoField.float ("dji_mavic_flyrec.simulator_config_environment_param_wind_s", "Wind S", base.DEC)
f.simulator_config_environment_param_gra_acc = ProtoField.float ("dji_mavic_flyrec.simulator_config_environment_param_gra_acc", "Gra Acc", base.DEC)
f.simulator_config_environment_param_temp = ProtoField.float ("dji_mavic_flyrec.simulator_config_environment_param_temp", "Temp", base.DEC)

local function flightrec_simulator_config_environment_param_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.simulator_config_environment_param_density, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_environment_param_drag_coef, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_environment_param_wind_s, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_environment_param_wind_s, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_environment_param_wind_s, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_environment_param_gra_acc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_environment_param_temp, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 28) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Simulator Config Environment Param: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Simulator Config Environment Param: Payload size different than expected") end
end

-- Flight log - Simulator Config Motor Param 1 - 0x0585

f.simulator_config_motor_param_1_cl = ProtoField.float ("dji_mavic_flyrec.simulator_config_motor_param_1_cl", "Cl", base.DEC)
f.simulator_config_motor_param_1_cq = ProtoField.float ("dji_mavic_flyrec.simulator_config_motor_param_1_cq", "Cq", base.DEC)
f.simulator_config_motor_param_1_i_max = ProtoField.int16 ("dji_mavic_flyrec.simulator_config_motor_param_1_i_max", "I Max", base.DEC)
f.simulator_config_motor_param_1_i_min = ProtoField.int16 ("dji_mavic_flyrec.simulator_config_motor_param_1_i_min", "I Min", base.DEC)
f.simulator_config_motor_param_1_in_motor = ProtoField.float ("dji_mavic_flyrec.simulator_config_motor_param_1_in_motor", "In Motor", base.DEC)
f.simulator_config_motor_param_1_in_prop = ProtoField.float ("dji_mavic_flyrec.simulator_config_motor_param_1_in_prop", "In Prop", base.DEC)
f.simulator_config_motor_param_1_rm = ProtoField.uint16 ("dji_mavic_flyrec.simulator_config_motor_param_1_rm", "Rm", base.HEX)
f.simulator_config_motor_param_1_kv = ProtoField.uint16 ("dji_mavic_flyrec.simulator_config_motor_param_1_kv", "Kv", base.HEX)
f.simulator_config_motor_param_1_mta = ProtoField.int16 ("dji_mavic_flyrec.simulator_config_motor_param_1_mta", "Mta", base.DEC)
f.simulator_config_motor_param_1_volt_max = ProtoField.uint16 ("dji_mavic_flyrec.simulator_config_motor_param_1_volt_max", "Volt Max", base.HEX)

local function flightrec_simulator_config_motor_param_1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.simulator_config_motor_param_1_cl, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_motor_param_1_cq, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_motor_param_1_i_max, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_config_motor_param_1_i_min, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_config_motor_param_1_in_motor, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_motor_param_1_in_prop, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.simulator_config_motor_param_1_rm, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_config_motor_param_1_kv, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_config_motor_param_1_mta, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.simulator_config_motor_param_1_volt_max, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 28) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Simulator Config Motor Param 1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Simulator Config Motor Param 1: Payload size different than expected") end
end

-- Flight log - Simulator Config Sensor Param - 0x0587

f.simulator_config_sensor_param_gyro_delay = ProtoField.uint8 ("dji_mavic_flyrec.simulator_config_sensor_param_gyro_delay", "Gyro Delay", base.HEX)
f.simulator_config_sensor_param_imu_delay = ProtoField.uint8 ("dji_mavic_flyrec.simulator_config_sensor_param_imu_delay", "Imu Delay", base.HEX)

local function flightrec_simulator_config_sensor_param_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.simulator_config_sensor_param_gyro_delay, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.simulator_config_sensor_param_imu_delay, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Simulator Config Sensor Param: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Simulator Config Sensor Param: Payload size different than expected") end
end

-- Flight log - Rtkdata - 0xcff2

f.rtkdata_date = ProtoField.uint32 ("dji_mavic_flyrec.rtkdata_date", "Date", base.HEX)
f.rtkdata_time = ProtoField.uint32 ("dji_mavic_flyrec.rtkdata_time", "Time", base.HEX)
f.rtkdata_lon_p = ProtoField.double ("dji_mavic_flyrec.rtkdata_lon_p", "Lon P", base.DEC)
f.rtkdata_lat_p = ProtoField.double ("dji_mavic_flyrec.rtkdata_lat_p", "Lat P", base.DEC)
f.rtkdata_hmsl_p = ProtoField.float ("dji_mavic_flyrec.rtkdata_hmsl_p", "Hmsl P", base.DEC)
f.rtkdata_lon_s = ProtoField.int32 ("dji_mavic_flyrec.rtkdata_lon_s", "Lon S", base.DEC)
f.rtkdata_lat_s = ProtoField.int32 ("dji_mavic_flyrec.rtkdata_lat_s", "Lat S", base.DEC)
f.rtkdata_hmsl_s = ProtoField.int32 ("dji_mavic_flyrec.rtkdata_hmsl_s", "Hmsl S", base.DEC)
f.rtkdata_vel_n = ProtoField.float ("dji_mavic_flyrec.rtkdata_vel_n", "Vel N", base.DEC)
f.rtkdata_vel_e = ProtoField.float ("dji_mavic_flyrec.rtkdata_vel_e", "Vel E", base.DEC)
f.rtkdata_vel_d = ProtoField.float ("dji_mavic_flyrec.rtkdata_vel_d", "Vel D", base.DEC)
f.rtkdata_yaw = ProtoField.int16 ("dji_mavic_flyrec.rtkdata_yaw", "Yaw", base.DEC)
f.rtkdata_svn_s = ProtoField.uint8 ("dji_mavic_flyrec.rtkdata_svn_s", "Svn S", base.HEX)
f.rtkdata_svn_p = ProtoField.uint8 ("dji_mavic_flyrec.rtkdata_svn_p", "Svn P", base.HEX)
f.rtkdata_hdop = ProtoField.float ("dji_mavic_flyrec.rtkdata_hdop", "Hdop", base.DEC)
f.rtkdata_pitch = ProtoField.float ("dji_mavic_flyrec.rtkdata_pitch", "Pitch", base.DEC)
f.rtkdata_posflg = ProtoField.uint8 ("dji_mavic_flyrec.rtkdata_posflg", "Posflg", base.HEX)
f.rtkdata_posflg = ProtoField.uint8 ("dji_mavic_flyrec.rtkdata_posflg", "Posflg", base.HEX)
f.rtkdata_posflg = ProtoField.uint8 ("dji_mavic_flyrec.rtkdata_posflg", "Posflg", base.HEX)
f.rtkdata_posflg = ProtoField.uint8 ("dji_mavic_flyrec.rtkdata_posflg", "Posflg", base.HEX)
f.rtkdata_posflg = ProtoField.uint8 ("dji_mavic_flyrec.rtkdata_posflg", "Posflg", base.HEX)
f.rtkdata_posflg = ProtoField.uint8 ("dji_mavic_flyrec.rtkdata_posflg", "Posflg", base.HEX)
f.rtkdata_gpsstate = ProtoField.uint16 ("dji_mavic_flyrec.rtkdata_gpsstate", "Gpsstate", base.HEX)

local function flightrec_rtkdata_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.rtkdata_date, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_time, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_lon_p, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.rtkdata_lat_p, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.rtkdata_hmsl_p, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_lon_s, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_lat_s, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_hmsl_s, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_vel_n, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_vel_e, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_vel_d, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_yaw, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rtkdata_svn_s, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtkdata_svn_p, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtkdata_hdop, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_pitch, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtkdata_posflg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtkdata_posflg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtkdata_posflg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtkdata_posflg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtkdata_posflg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtkdata_posflg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtkdata_gpsstate, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 72) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Rtkdata: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Rtkdata: Payload size different than expected") end
end

-- Flight log - Genral Debug Data - 0x0640

f.genral_debug_data_db00 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db00", "Db00", base.DEC)
f.genral_debug_data_db01 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db01", "Db01", base.DEC)
f.genral_debug_data_db02 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db02", "Db02", base.DEC)
f.genral_debug_data_db03 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db03", "Db03", base.DEC)
f.genral_debug_data_db04 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db04", "Db04", base.DEC)
f.genral_debug_data_db05 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db05", "Db05", base.DEC)
f.genral_debug_data_db06 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db06", "Db06", base.DEC)
f.genral_debug_data_db07 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db07", "Db07", base.DEC)
f.genral_debug_data_db08 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db08", "Db08", base.DEC)
f.genral_debug_data_db09 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db09", "Db09", base.DEC)
f.genral_debug_data_db10 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db10", "Db10", base.DEC)
f.genral_debug_data_db11 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db11", "Db11", base.DEC)
f.genral_debug_data_db12 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db12", "Db12", base.DEC)
f.genral_debug_data_db13 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db13", "Db13", base.DEC)
f.genral_debug_data_db14 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db14", "Db14", base.DEC)
f.genral_debug_data_db15 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db15", "Db15", base.DEC)
f.genral_debug_data_db16 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db16", "Db16", base.DEC)
f.genral_debug_data_db17 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db17", "Db17", base.DEC)
f.genral_debug_data_db18 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db18", "Db18", base.DEC)
f.genral_debug_data_db19 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db19", "Db19", base.DEC)
f.genral_debug_data_db20 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db20", "Db20", base.DEC)
f.genral_debug_data_db21 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db21", "Db21", base.DEC)
f.genral_debug_data_db22 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db22", "Db22", base.DEC)
f.genral_debug_data_db23 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db23", "Db23", base.DEC)
f.genral_debug_data_db24 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db24", "Db24", base.DEC)
f.genral_debug_data_db25 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db25", "Db25", base.DEC)
f.genral_debug_data_db26 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db26", "Db26", base.DEC)
f.genral_debug_data_db27 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db27", "Db27", base.DEC)
f.genral_debug_data_db28 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db28", "Db28", base.DEC)
f.genral_debug_data_db29 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db29", "Db29", base.DEC)
f.genral_debug_data_db30 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db30", "Db30", base.DEC)
f.genral_debug_data_db31 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db31", "Db31", base.DEC)
f.genral_debug_data_db32 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db32", "Db32", base.DEC)
f.genral_debug_data_db33 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db33", "Db33", base.DEC)
f.genral_debug_data_db34 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db34", "Db34", base.DEC)
f.genral_debug_data_db35 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db35", "Db35", base.DEC)
f.genral_debug_data_db36 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db36", "Db36", base.DEC)
f.genral_debug_data_db37 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db37", "Db37", base.DEC)
f.genral_debug_data_db38 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db38", "Db38", base.DEC)
f.genral_debug_data_db39 = ProtoField.float ("dji_mavic_flyrec.genral_debug_data_db39", "Db39", base.DEC)

local function flightrec_genral_debug_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.genral_debug_data_db00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db03, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db04, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db05, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db06, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db07, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db08, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db09, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db10, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db11, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db12, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db13, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db14, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db15, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db16, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db17, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db18, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db19, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db20, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db21, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db22, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db23, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db24, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db25, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db26, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db27, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db28, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db29, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db30, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db31, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db32, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db33, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db34, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db35, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db36, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db37, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db38, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.genral_debug_data_db39, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 160) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Genral Debug Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Genral Debug Data: Payload size different than expected") end
end

-- Flight log - Rc Debug Info - 0x06a4

f.rc_debug_info_cur_cmd = ProtoField.uint16 ("dji_mavic_flyrec.rc_debug_info_cur_cmd", "Cur Cmd", base.HEX)
f.rc_debug_info_fail_safe = ProtoField.uint8 ("dji_mavic_flyrec.rc_debug_info_fail_safe", "Fail Safe", base.HEX)
f.rc_debug_info_vedio_lost = ProtoField.uint8 ("dji_mavic_flyrec.rc_debug_info_vedio_lost", "Vedio Lost", base.HEX)
f.rc_debug_info_data_lost = ProtoField.uint8 ("dji_mavic_flyrec.rc_debug_info_data_lost", "Data Lost", base.HEX)
f.rc_debug_info_app_lost = ProtoField.uint8 ("dji_mavic_flyrec.rc_debug_info_app_lost", "App Lost", base.HEX)
f.rc_debug_info_frame_lost = ProtoField.uint8 ("dji_mavic_flyrec.rc_debug_info_frame_lost", "Frame Lost", base.HEX)
f.rc_debug_info_rec_cnt = ProtoField.uint32 ("dji_mavic_flyrec.rc_debug_info_rec_cnt", "Rec Cnt", base.HEX)
f.rc_debug_info_sky_con = ProtoField.uint8 ("dji_mavic_flyrec.rc_debug_info_sky_con", "Sky Con", base.HEX)
f.rc_debug_info_gnd_con = ProtoField.uint8 ("dji_mavic_flyrec.rc_debug_info_gnd_con", "Gnd Con", base.HEX)
f.rc_debug_info_connected = ProtoField.uint8 ("dji_mavic_flyrec.rc_debug_info_connected", "Connected", base.HEX)
f.rc_debug_info_m_changed = ProtoField.uint8 ("dji_mavic_flyrec.rc_debug_info_m_changed", "M Changed", base.HEX)
f.rc_debug_info_arm_status = ProtoField.uint8 ("dji_mavic_flyrec.rc_debug_info_arm_status", "Arm Status", base.HEX)
f.rc_debug_info_wifi_en = ProtoField.uint8 ("dji_mavic_flyrec.rc_debug_info_wifi_en", "Wifi En", base.HEX)
f.rc_debug_info_in_wifi = ProtoField.uint8 ("dji_mavic_flyrec.rc_debug_info_in_wifi", "In Wifi", base.HEX)

local function flightrec_rc_debug_info_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.rc_debug_info_cur_cmd, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_debug_info_fail_safe, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_debug_info_vedio_lost, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_debug_info_data_lost, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_debug_info_app_lost, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_debug_info_frame_lost, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_debug_info_rec_cnt, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rc_debug_info_sky_con, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_debug_info_gnd_con, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_debug_info_connected, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_debug_info_m_changed, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_debug_info_arm_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_debug_info_wifi_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_debug_info_in_wifi, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 18) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Rc Debug Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Rc Debug Info: Payload size different than expected") end
end

-- Flight log - Cali Mag 00 - 0x08d0

f.cali_mag_00_c_mx_0 = ProtoField.int16 ("dji_mavic_flyrec.cali_mag_00_c_mx_0", "C Mx 0", base.DEC)
f.cali_mag_00_c_my_0 = ProtoField.int16 ("dji_mavic_flyrec.cali_mag_00_c_my_0", "C My 0", base.DEC)
f.cali_mag_00_c_mz_0 = ProtoField.int16 ("dji_mavic_flyrec.cali_mag_00_c_mz_0", "C Mz 0", base.DEC)
f.cali_mag_00_c_m_cnt_0 = ProtoField.uint16 ("dji_mavic_flyrec.cali_mag_00_c_m_cnt_0", "C M Cnt 0", base.HEX)

local function flightrec_cali_mag_00_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.cali_mag_00_c_mx_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.cali_mag_00_c_my_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.cali_mag_00_c_mz_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.cali_mag_00_c_m_cnt_0, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Cali Mag 00: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Cali Mag 00: Payload size different than expected") end
end

-- Flight log - Cali Mag 01 - 0x08d1

f.cali_mag_01_c_mx_1 = ProtoField.int16 ("dji_mavic_flyrec.cali_mag_01_c_mx_1", "C Mx 1", base.DEC)
f.cali_mag_01_c_my_1 = ProtoField.int16 ("dji_mavic_flyrec.cali_mag_01_c_my_1", "C My 1", base.DEC)
f.cali_mag_01_c_mz_1 = ProtoField.int16 ("dji_mavic_flyrec.cali_mag_01_c_mz_1", "C Mz 1", base.DEC)
f.cali_mag_01_c_m_cnt_1 = ProtoField.uint16 ("dji_mavic_flyrec.cali_mag_01_c_m_cnt_1", "C M Cnt 1", base.HEX)

local function flightrec_cali_mag_01_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.cali_mag_01_c_mx_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.cali_mag_01_c_my_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.cali_mag_01_c_mz_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.cali_mag_01_c_m_cnt_1, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Cali Mag 01: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Cali Mag 01: Payload size different than expected") end
end

-- Flight log - Cali Mag 02 - 0x08d2

f.cali_mag_02_c_mx_2 = ProtoField.int16 ("dji_mavic_flyrec.cali_mag_02_c_mx_2", "C Mx 2", base.DEC)
f.cali_mag_02_c_my_2 = ProtoField.int16 ("dji_mavic_flyrec.cali_mag_02_c_my_2", "C My 2", base.DEC)
f.cali_mag_02_c_mz_2 = ProtoField.int16 ("dji_mavic_flyrec.cali_mag_02_c_mz_2", "C Mz 2", base.DEC)
f.cali_mag_02_c_m_cnt_2 = ProtoField.uint16 ("dji_mavic_flyrec.cali_mag_02_c_m_cnt_2", "C M Cnt 2", base.HEX)

local function flightrec_cali_mag_02_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.cali_mag_02_c_mx_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.cali_mag_02_c_my_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.cali_mag_02_c_mz_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.cali_mag_02_c_m_cnt_2, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Cali Mag 02: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Cali Mag 02: Payload size different than expected") end
end

-- Flight log - Lpf Gyr Acc0 - 0x0828

f.lpf_gyr_acc0_lpf_wx_0 = ProtoField.float ("dji_mavic_flyrec.lpf_gyr_acc0_lpf_wx_0", "Lpf Wx 0", base.DEC)
f.lpf_gyr_acc0_lpf_wy_0 = ProtoField.float ("dji_mavic_flyrec.lpf_gyr_acc0_lpf_wy_0", "Lpf Wy 0", base.DEC)
f.lpf_gyr_acc0_lpf_wz_0 = ProtoField.float ("dji_mavic_flyrec.lpf_gyr_acc0_lpf_wz_0", "Lpf Wz 0", base.DEC)
f.lpf_gyr_acc0_lpf_ax_0 = ProtoField.float ("dji_mavic_flyrec.lpf_gyr_acc0_lpf_ax_0", "Lpf Ax 0", base.DEC)
f.lpf_gyr_acc0_lpf_ay_0 = ProtoField.float ("dji_mavic_flyrec.lpf_gyr_acc0_lpf_ay_0", "Lpf Ay 0", base.DEC)
f.lpf_gyr_acc0_lpf_az_0 = ProtoField.float ("dji_mavic_flyrec.lpf_gyr_acc0_lpf_az_0", "Lpf Az 0", base.DEC)

local function flightrec_lpf_gyr_acc0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.lpf_gyr_acc0_lpf_wx_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.lpf_gyr_acc0_lpf_wy_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.lpf_gyr_acc0_lpf_wz_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.lpf_gyr_acc0_lpf_ax_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.lpf_gyr_acc0_lpf_ay_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.lpf_gyr_acc0_lpf_az_0, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 24) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Lpf Gyr Acc0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Lpf Gyr Acc0: Payload size different than expected") end
end

-- Flight log - Lpf Gyr Acc1 - 0x0829

f.lpf_gyr_acc1_lpf_wx_1 = ProtoField.float ("dji_mavic_flyrec.lpf_gyr_acc1_lpf_wx_1", "Lpf Wx 1", base.DEC)
f.lpf_gyr_acc1_lpf_wy_1 = ProtoField.float ("dji_mavic_flyrec.lpf_gyr_acc1_lpf_wy_1", "Lpf Wy 1", base.DEC)
f.lpf_gyr_acc1_lpf_wz_1 = ProtoField.float ("dji_mavic_flyrec.lpf_gyr_acc1_lpf_wz_1", "Lpf Wz 1", base.DEC)
f.lpf_gyr_acc1_lpf_ax_1 = ProtoField.float ("dji_mavic_flyrec.lpf_gyr_acc1_lpf_ax_1", "Lpf Ax 1", base.DEC)
f.lpf_gyr_acc1_lpf_ay_1 = ProtoField.float ("dji_mavic_flyrec.lpf_gyr_acc1_lpf_ay_1", "Lpf Ay 1", base.DEC)
f.lpf_gyr_acc1_lpf_az_1 = ProtoField.float ("dji_mavic_flyrec.lpf_gyr_acc1_lpf_az_1", "Lpf Az 1", base.DEC)

local function flightrec_lpf_gyr_acc1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.lpf_gyr_acc1_lpf_wx_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.lpf_gyr_acc1_lpf_wy_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.lpf_gyr_acc1_lpf_wz_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.lpf_gyr_acc1_lpf_ax_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.lpf_gyr_acc1_lpf_ay_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.lpf_gyr_acc1_lpf_az_1, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 24) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Lpf Gyr Acc1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Lpf Gyr Acc1: Payload size different than expected") end
end

-- Flight log - Lpf Gyr Acc2 - 0x082a

f.lpf_gyr_acc2_lpf_wx_2 = ProtoField.float ("dji_mavic_flyrec.lpf_gyr_acc2_lpf_wx_2", "Lpf Wx 2", base.DEC)
f.lpf_gyr_acc2_lpf_wy_2 = ProtoField.float ("dji_mavic_flyrec.lpf_gyr_acc2_lpf_wy_2", "Lpf Wy 2", base.DEC)
f.lpf_gyr_acc2_lpf_wz_2 = ProtoField.float ("dji_mavic_flyrec.lpf_gyr_acc2_lpf_wz_2", "Lpf Wz 2", base.DEC)
f.lpf_gyr_acc2_lpf_ax_2 = ProtoField.float ("dji_mavic_flyrec.lpf_gyr_acc2_lpf_ax_2", "Lpf Ax 2", base.DEC)
f.lpf_gyr_acc2_lpf_ay_2 = ProtoField.float ("dji_mavic_flyrec.lpf_gyr_acc2_lpf_ay_2", "Lpf Ay 2", base.DEC)
f.lpf_gyr_acc2_lpf_az_2 = ProtoField.float ("dji_mavic_flyrec.lpf_gyr_acc2_lpf_az_2", "Lpf Az 2", base.DEC)

local function flightrec_lpf_gyr_acc2_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.lpf_gyr_acc2_lpf_wx_2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.lpf_gyr_acc2_lpf_wy_2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.lpf_gyr_acc2_lpf_wz_2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.lpf_gyr_acc2_lpf_ax_2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.lpf_gyr_acc2_lpf_ay_2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.lpf_gyr_acc2_lpf_az_2, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 24) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Lpf Gyr Acc2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Lpf Gyr Acc2: Payload size different than expected") end
end

-- Flight log - App Temp Bias0 - 0x08e6

f.app_temp_bias0_bwx0 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias0_bwx0", "Bwx0", base.DEC)
f.app_temp_bias0_bwy0 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias0_bwy0", "Bwy0", base.DEC)
f.app_temp_bias0_bwz0 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias0_bwz0", "Bwz0", base.DEC)
f.app_temp_bias0_bax0 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias0_bax0", "Bax0", base.DEC)
f.app_temp_bias0_bay0 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias0_bay0", "Bay0", base.DEC)
f.app_temp_bias0_baz0 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias0_baz0", "Baz0", base.DEC)
f.app_temp_bias0_temp0 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias0_temp0", "Temp0", base.DEC)
f.app_temp_bias0_level2_flag0 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias0_level2_flag0", "Level2 Flag0", base.DEC)

local function flightrec_app_temp_bias0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.app_temp_bias0_bwx0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias0_bwy0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias0_bwz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias0_bax0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias0_bay0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias0_baz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias0_temp0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias0_level2_flag0, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 32) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"App Temp Bias0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"App Temp Bias0: Payload size different than expected") end
end

-- Flight log - App Temp Bias1 - 0x08e7

f.app_temp_bias1_bwx1 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias1_bwx1", "Bwx1", base.DEC)
f.app_temp_bias1_bwy1 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias1_bwy1", "Bwy1", base.DEC)
f.app_temp_bias1_bwz1 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias1_bwz1", "Bwz1", base.DEC)
f.app_temp_bias1_bax1 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias1_bax1", "Bax1", base.DEC)
f.app_temp_bias1_bay1 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias1_bay1", "Bay1", base.DEC)
f.app_temp_bias1_baz1 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias1_baz1", "Baz1", base.DEC)
f.app_temp_bias1_temp1 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias1_temp1", "Temp1", base.DEC)
f.app_temp_bias1_level2_flag1 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias1_level2_flag1", "Level2 Flag1", base.DEC)

local function flightrec_app_temp_bias1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.app_temp_bias1_bwx1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias1_bwy1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias1_bwz1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias1_bax1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias1_bay1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias1_baz1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias1_temp1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias1_level2_flag1, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 32) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"App Temp Bias1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"App Temp Bias1: Payload size different than expected") end
end

-- Flight log - App Temp Bias2 - 0x08e8

f.app_temp_bias2_bwx2 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias2_bwx2", "Bwx2", base.DEC)
f.app_temp_bias2_bwy2 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias2_bwy2", "Bwy2", base.DEC)
f.app_temp_bias2_bwz2 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias2_bwz2", "Bwz2", base.DEC)
f.app_temp_bias2_bax2 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias2_bax2", "Bax2", base.DEC)
f.app_temp_bias2_bay2 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias2_bay2", "Bay2", base.DEC)
f.app_temp_bias2_baz2 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias2_baz2", "Baz2", base.DEC)
f.app_temp_bias2_temp2 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias2_temp2", "Temp2", base.DEC)
f.app_temp_bias2_level2_flag2 = ProtoField.float ("dji_mavic_flyrec.app_temp_bias2_level2_flag2", "Level2 Flag2", base.DEC)

local function flightrec_app_temp_bias2_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.app_temp_bias2_bwx2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias2_bwy2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias2_bwz2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias2_bax2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias2_bay2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias2_baz2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias2_temp2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.app_temp_bias2_level2_flag2, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 32) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"App Temp Bias2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"App Temp Bias2: Payload size different than expected") end
end

-- Flight log - Inner Temp Bias0 - 0x08e4

f.inner_temp_bias0__bwx0 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias0__bwx0", " Bwx0", base.DEC)
f.inner_temp_bias0__bwy0 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias0__bwy0", " Bwy0", base.DEC)
f.inner_temp_bias0__bwz0 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias0__bwz0", " Bwz0", base.DEC)
f.inner_temp_bias0__bax0 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias0__bax0", " Bax0", base.DEC)
f.inner_temp_bias0__bay0 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias0__bay0", " Bay0", base.DEC)
f.inner_temp_bias0__baz0 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias0__baz0", " Baz0", base.DEC)
f.inner_temp_bias0__temp0 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias0__temp0", " Temp0", base.DEC)
f.inner_temp_bias0_level1_flag0 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias0_level1_flag0", "Level1 Flag0", base.DEC)

local function flightrec_inner_temp_bias0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.inner_temp_bias0__bwx0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias0__bwy0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias0__bwz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias0__bax0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias0__bay0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias0__baz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias0__temp0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias0_level1_flag0, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 32) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Inner Temp Bias0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Inner Temp Bias0: Payload size different than expected") end
end

-- Flight log - Inner Temp Bias1 - 0x08e5

f.inner_temp_bias1__bwx1 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias1__bwx1", " Bwx1", base.DEC)
f.inner_temp_bias1__bwy1 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias1__bwy1", " Bwy1", base.DEC)
f.inner_temp_bias1__bwz1 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias1__bwz1", " Bwz1", base.DEC)
f.inner_temp_bias1__bax1 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias1__bax1", " Bax1", base.DEC)
f.inner_temp_bias1__bay1 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias1__bay1", " Bay1", base.DEC)
f.inner_temp_bias1__baz1 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias1__baz1", " Baz1", base.DEC)
f.inner_temp_bias1__temp1 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias1__temp1", " Temp1", base.DEC)
f.inner_temp_bias1_level1_flag1 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias1_level1_flag1", "Level1 Flag1", base.DEC)

local function flightrec_inner_temp_bias1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.inner_temp_bias1__bwx1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias1__bwy1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias1__bwz1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias1__bax1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias1__bay1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias1__baz1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias1__temp1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias1_level1_flag1, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 32) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Inner Temp Bias1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Inner Temp Bias1: Payload size different than expected") end
end

-- Flight log - Inner Temp Bias2 - 0x08e6

f.inner_temp_bias2__bwx2 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias2__bwx2", " Bwx2", base.DEC)
f.inner_temp_bias2__bwy2 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias2__bwy2", " Bwy2", base.DEC)
f.inner_temp_bias2__bwz2 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias2__bwz2", " Bwz2", base.DEC)
f.inner_temp_bias2__bax2 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias2__bax2", " Bax2", base.DEC)
f.inner_temp_bias2__bay2 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias2__bay2", " Bay2", base.DEC)
f.inner_temp_bias2__baz2 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias2__baz2", " Baz2", base.DEC)
f.inner_temp_bias2__temp2 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias2__temp2", " Temp2", base.DEC)
f.inner_temp_bias2_level1_flag2 = ProtoField.float ("dji_mavic_flyrec.inner_temp_bias2_level1_flag2", "Level1 Flag2", base.DEC)

local function flightrec_inner_temp_bias2_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.inner_temp_bias2__bwx2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias2__bwy2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias2__bwz2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias2__bax2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias2__bay2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias2__baz2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias2__temp2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.inner_temp_bias2_level1_flag2, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 32) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Inner Temp Bias2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Inner Temp Bias2: Payload size different than expected") end
end

-- Flight log - Battery Info - 0x06ae

f.battery_info_ad_v = ProtoField.uint16 ("dji_mavic_flyrec.battery_info_ad_v", "Ad V", base.HEX)
f.battery_info_r_time = ProtoField.uint16 ("dji_mavic_flyrec.battery_info_r_time", "R Time", base.HEX)
f.battery_info_ave_i = ProtoField.float ("dji_mavic_flyrec.battery_info_ave_i", "Ave I", base.DEC)
f.battery_info_vol_t = ProtoField.float ("dji_mavic_flyrec.battery_info_vol_t", "Vol T", base.DEC)
f.battery_info_pack_ve = ProtoField.int32 ("dji_mavic_flyrec.battery_info_pack_ve", "Pack Ve", base.DEC)
f.battery_info_i = ProtoField.int32 ("dji_mavic_flyrec.battery_info_i", "I", base.DEC)
f.battery_info_r_cap = ProtoField.uint16 ("dji_mavic_flyrec.battery_info_r_cap", "R Cap", base.HEX)
f.battery_info_cap_per = ProtoField.uint8 ("dji_mavic_flyrec.battery_info_cap_per", "Cap Per", base.HEX)
f.battery_info_temp = ProtoField.int16 ("dji_mavic_flyrec.battery_info_temp", "Temp", base.DEC)
f.battery_info_right = ProtoField.uint8 ("dji_mavic_flyrec.battery_info_right", "Right", base.HEX)
f.battery_info_l_cell = ProtoField.uint16 ("dji_mavic_flyrec.battery_info_l_cell", "L Cell", base.HEX)
f.battery_info_dyna_cnt = ProtoField.uint32 ("dji_mavic_flyrec.battery_info_dyna_cnt", "Dyna Cnt", base.HEX)
f.battery_info_f_cap = ProtoField.uint32 ("dji_mavic_flyrec.battery_info_f_cap", "F Cap", base.HEX)
f.battery_info_out_ctl = ProtoField.float ("dji_mavic_flyrec.battery_info_out_ctl", "Out Ctl", base.DEC)
f.battery_info_out_ctl_f = ProtoField.float ("dji_mavic_flyrec.battery_info_out_ctl_f", "Out Ctl F", base.DEC)

local function flightrec_battery_info_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.battery_info_ad_v, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_r_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_ave_i, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_vol_t, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_pack_ve, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_i, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_r_cap, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_cap_per, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_info_temp, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_right, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_info_l_cell, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_dyna_cnt, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_f_cap, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_out_ctl, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_out_ctl_f, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 44) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Battery Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Battery Info: Payload size different than expected") end
end

-- Flight log - Battery Status - 0x06af

f.battery_status_not_ready = ProtoField.uint8 ("dji_mavic_flyrec.battery_status_not_ready", "Not Ready", base.HEX)
f.battery_status_comm_err = ProtoField.uint8 ("dji_mavic_flyrec.battery_status_comm_err", "Comm Err", base.HEX)
f.battery_status_first_auth = ProtoField.uint8 ("dji_mavic_flyrec.battery_status_first_auth", "First Auth", base.HEX)
f.battery_status_auth_fail = ProtoField.uint8 ("dji_mavic_flyrec.battery_status_auth_fail", "Auth Fail", base.HEX)
f.battery_status_need_re = ProtoField.uint8 ("dji_mavic_flyrec.battery_status_need_re", "Need Re", base.HEX)
f.battery_status_volverylow = ProtoField.uint8 ("dji_mavic_flyrec.battery_status_volverylow", "Volverylow", base.HEX)
f.battery_status_volnotsafe = ProtoField.uint8 ("dji_mavic_flyrec.battery_status_volnotsafe", "Volnotsafe", base.HEX)
f.battery_status_vollevel1 = ProtoField.uint8 ("dji_mavic_flyrec.battery_status_vollevel1", "Vollevel1", base.HEX)
f.battery_status_vollevel2 = ProtoField.uint8 ("dji_mavic_flyrec.battery_status_vollevel2", "Vollevel2", base.HEX)
f.battery_status_caplevel1 = ProtoField.uint8 ("dji_mavic_flyrec.battery_status_caplevel1", "Caplevel1", base.HEX)
f.battery_status_caplevel2 = ProtoField.uint8 ("dji_mavic_flyrec.battery_status_caplevel2", "Caplevel2", base.HEX)
f.battery_status_smartcap1 = ProtoField.uint8 ("dji_mavic_flyrec.battery_status_smartcap1", "Smartcap1", base.HEX)
f.battery_status_smartcap2 = ProtoField.uint8 ("dji_mavic_flyrec.battery_status_smartcap2", "Smartcap2", base.HEX)
f.battery_status_d_flg = ProtoField.uint8 ("dji_mavic_flyrec.battery_status_d_flg", "D Flg", base.HEX)
f.battery_status_ccsc = ProtoField.uint8 ("dji_mavic_flyrec.battery_status_ccsc", "Ccsc", base.HEX)
f.battery_status_all = ProtoField.uint32 ("dji_mavic_flyrec.battery_status_all", "All", base.HEX)

local function flightrec_battery_status_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.battery_status_not_ready, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_status_comm_err, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_status_first_auth, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_status_auth_fail, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_status_need_re, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_status_volverylow, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_status_volnotsafe, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_status_vollevel1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_status_vollevel2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_status_caplevel1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_status_caplevel2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_status_smartcap1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_status_smartcap2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_status_d_flg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_status_ccsc, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_status_all, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 19) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Battery Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Battery Status: Payload size different than expected") end
end

-- Flight log - Smart Battery Info - 0x06b0

f.smart_battery_info_go_home_cnt = ProtoField.uint8 ("dji_mavic_flyrec.smart_battery_info_go_home_cnt", "Go Home Cnt", base.HEX)
f.smart_battery_info_go_home_cmd = ProtoField.uint8 ("dji_mavic_flyrec.smart_battery_info_go_home_cmd", "Go Home Cmd", base.HEX)
f.smart_battery_info_gh_level = ProtoField.uint16 ("dji_mavic_flyrec.smart_battery_info_gh_level", "Gh Level", base.HEX)
f.smart_battery_info_land_level = ProtoField.uint16 ("dji_mavic_flyrec.smart_battery_info_land_level", "Land Level", base.HEX)
f.smart_battery_info_fly_t_for_gh = ProtoField.uint16 ("dji_mavic_flyrec.smart_battery_info_fly_t_for_gh", "Fly T For Gh", base.HEX)
f.smart_battery_info_fly_t_for_land = ProtoField.uint16 ("dji_mavic_flyrec.smart_battery_info_fly_t_for_land", "Fly T For Land", base.HEX)

local function flightrec_smart_battery_info_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.smart_battery_info_go_home_cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_go_home_cmd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.smart_battery_info_gh_level, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.smart_battery_info_land_level, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.smart_battery_info_fly_t_for_gh, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.smart_battery_info_fly_t_for_land, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 10) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Smart Battery Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Smart Battery Info: Payload size different than expected") end
end

-- Flight log - Statistical Info - 0x0708

f.statistical_info_distance = ProtoField.float ("dji_mavic_flyrec.statistical_info_distance", "Distance", base.DEC)
f.statistical_info_m_starts = ProtoField.float ("dji_mavic_flyrec.statistical_info_m_starts", "M Starts", base.DEC)

local function flightrec_statistical_info_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.statistical_info_distance, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.statistical_info_m_starts, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Statistical Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Statistical Info: Payload size different than expected") end
end

-- Flight log - Ns Sensor Quality - 0x2764

f.ns_sensor_quality_ns_mag_gain = ProtoField.uint16 ("dji_mavic_flyrec.ns_sensor_quality_ns_mag_gain", "Ns Mag Gain", base.HEX)

local function flightrec_ns_sensor_quality_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ns_sensor_quality_ns_mag_gain, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ns Sensor Quality: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ns Sensor Quality: Payload size different than expected") end
end

-- Flight log - Ns Data Debug - 0x2765

f.ns_data_debug_d00 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d00", "D00", base.DEC)
f.ns_data_debug_d01 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d01", "D01", base.DEC)
f.ns_data_debug_d02 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d02", "D02", base.DEC)
f.ns_data_debug_d03 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d03", "D03", base.DEC)
f.ns_data_debug_d04 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d04", "D04", base.DEC)
f.ns_data_debug_d05 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d05", "D05", base.DEC)
f.ns_data_debug_d06 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d06", "D06", base.DEC)
f.ns_data_debug_d07 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d07", "D07", base.DEC)
f.ns_data_debug_d08 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d08", "D08", base.DEC)
f.ns_data_debug_d09 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d09", "D09", base.DEC)
f.ns_data_debug_d10 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d10", "D10", base.DEC)
f.ns_data_debug_d11 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d11", "D11", base.DEC)
f.ns_data_debug_d12 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d12", "D12", base.DEC)
f.ns_data_debug_d13 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d13", "D13", base.DEC)
f.ns_data_debug_d14 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d14", "D14", base.DEC)
f.ns_data_debug_d15 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d15", "D15", base.DEC)
f.ns_data_debug_d16 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d16", "D16", base.DEC)
f.ns_data_debug_d17 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d17", "D17", base.DEC)
f.ns_data_debug_d18 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d18", "D18", base.DEC)
f.ns_data_debug_d19 = ProtoField.float ("dji_mavic_flyrec.ns_data_debug_d19", "D19", base.DEC)

local function flightrec_ns_data_debug_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ns_data_debug_d00, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d01, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d02, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d03, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d04, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d05, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d06, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d07, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d08, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d09, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d10, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d11, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d12, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d13, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d14, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d15, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d16, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d17, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d18, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_debug_d19, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 80) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ns Data Debug: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ns Data Debug: Payload size different than expected") end
end

-- Flight log - Ns Data Component - 0x2766

f.ns_data_component_ns_cmpnt = ProtoField.uint32 ("dji_mavic_flyrec.ns_data_component_ns_cmpnt", "Ns Cmpnt", base.HEX)

local function flightrec_ns_data_component_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ns_data_component_ns_cmpnt, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ns Data Component: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ns Data Component: Payload size different than expected") end
end

-- Flight log - Ns Data Residuals - 0x2767

f.ns_data_residuals_gns_px = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_gns_px", "Gns Px", base.DEC)
f.ns_data_residuals_gns_py = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_gns_py", "Gns Py", base.DEC)
f.ns_data_residuals_gns_vx = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_gns_vx", "Gns Vx", base.DEC)
f.ns_data_residuals_gns_vy = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_gns_vy", "Gns Vy", base.DEC)
f.ns_data_residuals_gns_pz = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_gns_pz", "Gns Pz", base.DEC)
f.ns_data_residuals_gns_vz = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_gns_vz", "Gns Vz", base.DEC)
f.ns_data_residuals_vod_px = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_vod_px", "Vod Px", base.DEC)
f.ns_data_residuals_vod_py = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_vod_py", "Vod Py", base.DEC)
f.ns_data_residuals_vod_vx = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_vod_vx", "Vod Vx", base.DEC)
f.ns_data_residuals_vod_vy = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_vod_vy", "Vod Vy", base.DEC)
f.ns_data_residuals_vod_pz = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_vod_pz", "Vod Pz", base.DEC)
f.ns_data_residuals_vod_vz = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_vod_vz", "Vod Vz", base.DEC)
f.ns_data_residuals_rtk_px_p = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_rtk_px_p", "Rtk Px P", base.DEC)
f.ns_data_residuals_rtk_py_p = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_rtk_py_p", "Rtk Py P", base.DEC)
f.ns_data_residuals_rtk_px_s = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_rtk_px_s", "Rtk Px S", base.DEC)
f.ns_data_residuals_rtk_py_s = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_rtk_py_s", "Rtk Py S", base.DEC)
f.ns_data_residuals_rtk_vx = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_rtk_vx", "Rtk Vx", base.DEC)
f.ns_data_residuals_rtk_vy = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_rtk_vy", "Rtk Vy", base.DEC)
f.ns_data_residuals_rtk_pz_p = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_rtk_pz_p", "Rtk Pz P", base.DEC)
f.ns_data_residuals_rtk_pz_s = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_rtk_pz_s", "Rtk Pz S", base.DEC)
f.ns_data_residuals_rtk_vz = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_rtk_vz", "Rtk Vz", base.DEC)
f.ns_data_residuals_rtk_yaw = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_rtk_yaw", "Rtk Yaw", base.DEC)
f.ns_data_residuals_usn_pz = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_usn_pz", "Usn Pz", base.DEC)
f.ns_data_residuals_bar_pz = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_bar_pz", "Bar Pz", base.DEC)
f.ns_data_residuals_mag_yaw = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_mag_yaw", "Mag Yaw", base.DEC)
f.ns_data_residuals_vod_h = ProtoField.float ("dji_mavic_flyrec.ns_data_residuals_vod_h", "Vod H", base.DEC)

local function flightrec_ns_data_residuals_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ns_data_residuals_gns_px, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_gns_py, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_gns_vx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_gns_vy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_gns_pz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_gns_vz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_vod_px, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_vod_py, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_vod_vx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_vod_vy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_vod_pz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_vod_vz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_rtk_px_p, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_rtk_py_p, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_rtk_px_s, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_rtk_py_s, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_rtk_vx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_rtk_vy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_rtk_pz_p, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_rtk_pz_s, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_rtk_vz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_rtk_yaw, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_usn_pz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_bar_pz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_mag_yaw, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_residuals_vod_h, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 104) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ns Data Residuals: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ns Data Residuals: Payload size different than expected") end
end

-- Flight log - Ns Data Posi Ofst - 0x2768

f.ns_data_posi_ofst_gns_px = ProtoField.float ("dji_mavic_flyrec.ns_data_posi_ofst_gns_px", "Gns Px", base.DEC)
f.ns_data_posi_ofst_gns_py = ProtoField.float ("dji_mavic_flyrec.ns_data_posi_ofst_gns_py", "Gns Py", base.DEC)
f.ns_data_posi_ofst_gns_pz = ProtoField.float ("dji_mavic_flyrec.ns_data_posi_ofst_gns_pz", "Gns Pz", base.DEC)
f.ns_data_posi_ofst_vod_px = ProtoField.float ("dji_mavic_flyrec.ns_data_posi_ofst_vod_px", "Vod Px", base.DEC)
f.ns_data_posi_ofst_vod_py = ProtoField.float ("dji_mavic_flyrec.ns_data_posi_ofst_vod_py", "Vod Py", base.DEC)
f.ns_data_posi_ofst_vod_pz = ProtoField.float ("dji_mavic_flyrec.ns_data_posi_ofst_vod_pz", "Vod Pz", base.DEC)
f.ns_data_posi_ofst_rtk_px_p = ProtoField.float ("dji_mavic_flyrec.ns_data_posi_ofst_rtk_px_p", "Rtk Px P", base.DEC)
f.ns_data_posi_ofst_rtk_py_p = ProtoField.float ("dji_mavic_flyrec.ns_data_posi_ofst_rtk_py_p", "Rtk Py P", base.DEC)
f.ns_data_posi_ofst_rtk_px = ProtoField.float ("dji_mavic_flyrec.ns_data_posi_ofst_rtk_px", "Rtk Px", base.DEC)
f.ns_data_posi_ofst_rtk_py = ProtoField.float ("dji_mavic_flyrec.ns_data_posi_ofst_rtk_py", "Rtk Py", base.DEC)
f.ns_data_posi_ofst_rtk_pz_p = ProtoField.float ("dji_mavic_flyrec.ns_data_posi_ofst_rtk_pz_p", "Rtk Pz P", base.DEC)
f.ns_data_posi_ofst_rtk_pz = ProtoField.float ("dji_mavic_flyrec.ns_data_posi_ofst_rtk_pz", "Rtk Pz", base.DEC)
f.ns_data_posi_ofst_rtk_y = ProtoField.float ("dji_mavic_flyrec.ns_data_posi_ofst_rtk_y", "Rtk Y", base.DEC)
f.ns_data_posi_ofst_usn_pz = ProtoField.float ("dji_mavic_flyrec.ns_data_posi_ofst_usn_pz", "Usn Pz", base.DEC)
f.ns_data_posi_ofst_bar_pz = ProtoField.float ("dji_mavic_flyrec.ns_data_posi_ofst_bar_pz", "Bar Pz", base.DEC)
f.ns_data_posi_ofst_mag_y = ProtoField.float ("dji_mavic_flyrec.ns_data_posi_ofst_mag_y", "Mag Y", base.DEC)
f.ns_data_posi_ofst_vod_h = ProtoField.float ("dji_mavic_flyrec.ns_data_posi_ofst_vod_h", "Vod H", base.DEC)

local function flightrec_ns_data_posi_ofst_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ns_data_posi_ofst_gns_px, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_posi_ofst_gns_py, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_posi_ofst_gns_pz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_posi_ofst_vod_px, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_posi_ofst_vod_py, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_posi_ofst_vod_pz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_posi_ofst_rtk_px_p, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_posi_ofst_rtk_py_p, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_posi_ofst_rtk_px, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_posi_ofst_rtk_py, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_posi_ofst_rtk_pz_p, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_posi_ofst_rtk_pz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_posi_ofst_rtk_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_posi_ofst_usn_pz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_posi_ofst_bar_pz, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_posi_ofst_mag_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ns_data_posi_ofst_vod_h, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 68) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ns Data Posi Ofst: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ns Data Posi Ofst: Payload size different than expected") end
end

-- Flight log - Ns Sensor Connect - 0x2769

f.ns_sensor_connect_ns_ss_cnnct = ProtoField.uint32 ("dji_mavic_flyrec.ns_sensor_connect_ns_ss_cnnct", "Ns Ss Cnnct", base.HEX)

local function flightrec_ns_sensor_connect_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ns_sensor_connect_ns_ss_cnnct, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ns Sensor Connect: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ns Sensor Connect: Payload size different than expected") end
end

-- Flight log - Esc Data - 0x276a

f.esc_data_status1 = ProtoField.uint8 ("dji_mavic_flyrec.esc_data_status1", "Status1", base.HEX)
f.esc_data_i_1 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_i_1", "I 1", base.DEC)
f.esc_data_speed_1 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_speed_1", "Speed 1", base.DEC)
f.esc_data_v_1 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_v_1", "V 1", base.HEX)
f.esc_data_temp_1 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_temp_1", "Temp 1", base.DEC)
f.esc_data_ppm_recv_1 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_ppm_recv_1", "Ppm Recv 1", base.HEX)
f.esc_data_v_out_1 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_v_out_1", "V Out 1", base.HEX)
f.esc_data_debug0_1 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_debug0_1", "Debug0 1", base.HEX)
f.esc_data_debug1_1 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_debug1_1", "Debug1 1", base.DEC)
f.esc_data_debug2_1 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_debug2_1", "Debug2 1", base.DEC)
f.esc_data_ppm_send_1 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_ppm_send_1", "Ppm Send 1", base.HEX)
f.esc_data_cnt_1 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_cnt_1", "Cnt 1", base.DEC)
f.esc_data_status_2 = ProtoField.uint8 ("dji_mavic_flyrec.esc_data_status_2", "Status 2", base.HEX)
f.esc_data_i_2 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_i_2", "I 2", base.DEC)
f.esc_data_speed_2 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_speed_2", "Speed 2", base.DEC)
f.esc_data_v_2 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_v_2", "V 2", base.HEX)
f.esc_data_temp_2 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_temp_2", "Temp 2", base.DEC)
f.esc_data_ppm_recv_2 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_ppm_recv_2", "Ppm Recv 2", base.HEX)
f.esc_data_v_out_2 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_v_out_2", "V Out 2", base.HEX)
f.esc_data_debug0_2 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_debug0_2", "Debug0 2", base.HEX)
f.esc_data_debug1_2 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_debug1_2", "Debug1 2", base.DEC)
f.esc_data_debug2_2 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_debug2_2", "Debug2 2", base.DEC)
f.esc_data_ppm_send_2 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_ppm_send_2", "Ppm Send 2", base.HEX)
f.esc_data_cnt_2 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_cnt_2", "Cnt 2", base.DEC)
f.esc_data_status_3 = ProtoField.uint8 ("dji_mavic_flyrec.esc_data_status_3", "Status 3", base.HEX)
f.esc_data_i_3 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_i_3", "I 3", base.DEC)
f.esc_data_speed_3 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_speed_3", "Speed 3", base.DEC)
f.esc_data_v_3 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_v_3", "V 3", base.HEX)
f.esc_data_temp_3 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_temp_3", "Temp 3", base.DEC)
f.esc_data_ppm_recv_3 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_ppm_recv_3", "Ppm Recv 3", base.HEX)
f.esc_data_v_out_3 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_v_out_3", "V Out 3", base.HEX)
f.esc_data_debug0_3 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_debug0_3", "Debug0 3", base.HEX)
f.esc_data_debug1_3 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_debug1_3", "Debug1 3", base.DEC)
f.esc_data_debug2_3 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_debug2_3", "Debug2 3", base.DEC)
f.esc_data_ppm_send_3 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_ppm_send_3", "Ppm Send 3", base.HEX)
f.esc_data_cnt_3 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_cnt_3", "Cnt 3", base.DEC)
f.esc_data_status_4 = ProtoField.uint8 ("dji_mavic_flyrec.esc_data_status_4", "Status 4", base.HEX)
f.esc_data_i_4 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_i_4", "I 4", base.DEC)
f.esc_data_speed_4 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_speed_4", "Speed 4", base.DEC)
f.esc_data_v_4 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_v_4", "V 4", base.HEX)
f.esc_data_temp_4 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_temp_4", "Temp 4", base.DEC)
f.esc_data_ppm_recv_4 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_ppm_recv_4", "Ppm Recv 4", base.HEX)
f.esc_data_v_out_4 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_v_out_4", "V Out 4", base.HEX)
f.esc_data_debug0_4 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_debug0_4", "Debug0 4", base.HEX)
f.esc_data_debug1_4 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_debug1_4", "Debug1 4", base.DEC)
f.esc_data_debug2_4 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_debug2_4", "Debug2 4", base.DEC)
f.esc_data_ppm_send_4 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_ppm_send_4", "Ppm Send 4", base.HEX)
f.esc_data_cnt_4 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_cnt_4", "Cnt 4", base.DEC)
f.esc_data_status_5 = ProtoField.uint8 ("dji_mavic_flyrec.esc_data_status_5", "Status 5", base.HEX)
f.esc_data_i_5 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_i_5", "I 5", base.DEC)
f.esc_data_speed_5 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_speed_5", "Speed 5", base.DEC)
f.esc_data_v_5 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_v_5", "V 5", base.HEX)
f.esc_data_temp_5 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_temp_5", "Temp 5", base.DEC)
f.esc_data_ppm_recv_5 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_ppm_recv_5", "Ppm Recv 5", base.HEX)
f.esc_data_v_out_5 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_v_out_5", "V Out 5", base.HEX)
f.esc_data_debug0_5 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_debug0_5", "Debug0 5", base.HEX)
f.esc_data_debug1_5 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_debug1_5", "Debug1 5", base.DEC)
f.esc_data_debug2_5 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_debug2_5", "Debug2 5", base.DEC)
f.esc_data_ppm_send = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_ppm_send", "Ppm Send", base.HEX)
f.esc_data_cnt_5 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_cnt_5", "Cnt 5", base.DEC)
f.esc_data_status_6 = ProtoField.uint8 ("dji_mavic_flyrec.esc_data_status_6", "Status 6", base.HEX)
f.esc_data_i_6 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_i_6", "I 6", base.DEC)
f.esc_data_speed_6 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_speed_6", "Speed 6", base.DEC)
f.esc_data_v_6 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_v_6", "V 6", base.HEX)
f.esc_data_temp_6 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_temp_6", "Temp 6", base.DEC)
f.esc_data_ppm_recv_6 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_ppm_recv_6", "Ppm Recv 6", base.HEX)
f.esc_data_v_out_6 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_v_out_6", "V Out 6", base.HEX)
f.esc_data_debug0_6 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_debug0_6", "Debug0 6", base.HEX)
f.esc_data_debug1_6 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_debug1_6", "Debug1 6", base.DEC)
f.esc_data_debug2_6 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_debug2_6", "Debug2 6", base.DEC)
f.esc_data_ppm_send_6 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_ppm_send_6", "Ppm Send 6", base.HEX)
f.esc_data_cnt_6 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_cnt_6", "Cnt 6", base.DEC)
f.esc_data_status_7 = ProtoField.uint8 ("dji_mavic_flyrec.esc_data_status_7", "Status 7", base.HEX)
f.esc_data_i_7 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_i_7", "I 7", base.DEC)
f.esc_data_speed_7 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_speed_7", "Speed 7", base.DEC)
f.esc_data_v_7 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_v_7", "V 7", base.HEX)
f.esc_data_temp_7 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_temp_7", "Temp 7", base.DEC)
f.esc_data_ppm_recv_7 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_ppm_recv_7", "Ppm Recv 7", base.HEX)
f.esc_data_v_out_7 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_v_out_7", "V Out 7", base.HEX)
f.esc_data_debug0_7 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_debug0_7", "Debug0 7", base.HEX)
f.esc_data_debug1_7 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_debug1_7", "Debug1 7", base.DEC)
f.esc_data_debug2_7 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_debug2_7", "Debug2 7", base.DEC)
f.esc_data_ppm_send_7 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_ppm_send_7", "Ppm Send 7", base.HEX)
f.esc_data_cnt_7 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_cnt_7", "Cnt 7", base.DEC)
f.esc_data_status_8 = ProtoField.uint8 ("dji_mavic_flyrec.esc_data_status_8", "Status 8", base.HEX)
f.esc_data_i_8 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_i_8", "I 8", base.DEC)
f.esc_data_speed_8 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_speed_8", "Speed 8", base.DEC)
f.esc_data_v_8 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_v_8", "V 8", base.HEX)
f.esc_data_temp_8 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_temp_8", "Temp 8", base.DEC)
f.esc_data_ppm_recv_8 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_ppm_recv_8", "Ppm Recv 8", base.HEX)
f.esc_data_v_out_8 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_v_out_8", "V Out 8", base.HEX)
f.esc_data_debug0_8 = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_debug0_8", "Debug0 8", base.HEX)
f.esc_data_debug1_8 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_debug1_8", "Debug1 8", base.DEC)
f.esc_data_debug2_8 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_debug2_8", "Debug2 8", base.DEC)
f.esc_data_ppm_send = ProtoField.uint16 ("dji_mavic_flyrec.esc_data_ppm_send", "Ppm Send", base.HEX)
f.esc_data_cnt_8 = ProtoField.int16 ("dji_mavic_flyrec.esc_data_cnt_8", "Cnt 8", base.DEC)
f.esc_data_ppm_mode = ProtoField.uint8 ("dji_mavic_flyrec.esc_data_ppm_mode", "Ppm Mode", base.HEX)

local function flightrec_esc_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.esc_data_status1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.esc_data_i_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_speed_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_v_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_temp_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_ppm_recv_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_v_out_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug0_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug1_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug2_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_ppm_send_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_cnt_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_status_2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.esc_data_i_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_speed_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_v_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_temp_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_ppm_recv_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_v_out_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug0_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug1_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug2_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_ppm_send_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_cnt_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_status_3, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.esc_data_i_3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_speed_3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_v_3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_temp_3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_ppm_recv_3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_v_out_3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug0_3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug1_3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug2_3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_ppm_send_3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_cnt_3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_status_4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.esc_data_i_4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_speed_4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_v_4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_temp_4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_ppm_recv_4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_v_out_4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug0_4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug1_4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug2_4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_ppm_send_4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_cnt_4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_status_5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.esc_data_i_5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_speed_5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_v_5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_temp_5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_ppm_recv_5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_v_out_5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug0_5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug1_5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug2_5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_ppm_send, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_cnt_5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_status_6, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.esc_data_i_6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_speed_6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_v_6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_temp_6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_ppm_recv_6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_v_out_6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug0_6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug1_6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug2_6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_ppm_send_6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_cnt_6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_status_7, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.esc_data_i_7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_speed_7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_v_7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_temp_7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_ppm_recv_7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_v_out_7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug0_7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug1_7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug2_7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_ppm_send_7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_cnt_7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_status_8, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.esc_data_i_8, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_speed_8, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_v_8, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_temp_8, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_ppm_recv_8, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_v_out_8, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug0_8, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug1_8, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_debug2_8, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_ppm_send, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_cnt_8, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.esc_data_ppm_mode, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 185) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Esc Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Esc Data: Payload size different than expected") end
end

-- Flight log - High Freq Gyro Data 0 - 0x276b

f.high_freq_gyro_data_0_w_x0 = ProtoField.int16 ("dji_mavic_flyrec.high_freq_gyro_data_0_w_x0", "W X0", base.DEC)
f.high_freq_gyro_data_0_w_y0 = ProtoField.int16 ("dji_mavic_flyrec.high_freq_gyro_data_0_w_y0", "W Y0", base.DEC)
f.high_freq_gyro_data_0_w_z0 = ProtoField.int16 ("dji_mavic_flyrec.high_freq_gyro_data_0_w_z0", "W Z0", base.DEC)
f.high_freq_gyro_data_0_cnt0 = ProtoField.uint16 ("dji_mavic_flyrec.high_freq_gyro_data_0_cnt0", "Cnt0", base.HEX)

local function flightrec_high_freq_gyro_data_0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.high_freq_gyro_data_0_w_x0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.high_freq_gyro_data_0_w_y0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.high_freq_gyro_data_0_w_z0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.high_freq_gyro_data_0_cnt0, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"High Freq Gyro Data 0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"High Freq Gyro Data 0: Payload size different than expected") end
end

-- Flight log - High Freq Gyro Data 1 - 0x276c

f.high_freq_gyro_data_1_w_x1 = ProtoField.int16 ("dji_mavic_flyrec.high_freq_gyro_data_1_w_x1", "W X1", base.DEC)
f.high_freq_gyro_data_1_w_y1 = ProtoField.int16 ("dji_mavic_flyrec.high_freq_gyro_data_1_w_y1", "W Y1", base.DEC)
f.high_freq_gyro_data_1_w_z1 = ProtoField.int16 ("dji_mavic_flyrec.high_freq_gyro_data_1_w_z1", "W Z1", base.DEC)
f.high_freq_gyro_data_1_cnt1 = ProtoField.uint16 ("dji_mavic_flyrec.high_freq_gyro_data_1_cnt1", "Cnt1", base.HEX)

local function flightrec_high_freq_gyro_data_1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.high_freq_gyro_data_1_w_x1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.high_freq_gyro_data_1_w_y1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.high_freq_gyro_data_1_w_z1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.high_freq_gyro_data_1_cnt1, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"High Freq Gyro Data 1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"High Freq Gyro Data 1: Payload size different than expected") end
end

-- Flight log - High Freq Gyro Data 2 - 0x276d

f.high_freq_gyro_data_2_w_x2 = ProtoField.int16 ("dji_mavic_flyrec.high_freq_gyro_data_2_w_x2", "W X2", base.DEC)
f.high_freq_gyro_data_2_w_y2 = ProtoField.int16 ("dji_mavic_flyrec.high_freq_gyro_data_2_w_y2", "W Y2", base.DEC)
f.high_freq_gyro_data_2_w_z2 = ProtoField.int16 ("dji_mavic_flyrec.high_freq_gyro_data_2_w_z2", "W Z2", base.DEC)
f.high_freq_gyro_data_2_cnt2 = ProtoField.uint16 ("dji_mavic_flyrec.high_freq_gyro_data_2_cnt2", "Cnt2", base.HEX)

local function flightrec_high_freq_gyro_data_2_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.high_freq_gyro_data_2_w_x2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.high_freq_gyro_data_2_w_y2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.high_freq_gyro_data_2_w_z2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.high_freq_gyro_data_2_cnt2, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"High Freq Gyro Data 2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"High Freq Gyro Data 2: Payload size different than expected") end
end

-- Flight log - Rc Gps Data - 0x276e

f.rc_gps_data_hour = ProtoField.uint8 ("dji_mavic_flyrec.rc_gps_data_hour", "Hour", base.HEX)
f.rc_gps_data_min = ProtoField.uint8 ("dji_mavic_flyrec.rc_gps_data_min", "Min", base.HEX)
f.rc_gps_data_sec = ProtoField.uint8 ("dji_mavic_flyrec.rc_gps_data_sec", "Sec", base.HEX)
f.rc_gps_data_year = ProtoField.uint16 ("dji_mavic_flyrec.rc_gps_data_year", "Year", base.HEX)
f.rc_gps_data_month = ProtoField.uint8 ("dji_mavic_flyrec.rc_gps_data_month", "Month", base.HEX)
f.rc_gps_data_day = ProtoField.uint8 ("dji_mavic_flyrec.rc_gps_data_day", "Day", base.HEX)
f.rc_gps_data_longtitude = ProtoField.int32 ("dji_mavic_flyrec.rc_gps_data_longtitude", "Longtitude", base.DEC)
f.rc_gps_data_latitude = ProtoField.int32 ("dji_mavic_flyrec.rc_gps_data_latitude", "Latitude", base.DEC)
f.rc_gps_data_xv = ProtoField.uint32 ("dji_mavic_flyrec.rc_gps_data_xv", "Xv", base.HEX)
f.rc_gps_data_yv = ProtoField.uint32 ("dji_mavic_flyrec.rc_gps_data_yv", "Yv", base.HEX)
f.rc_gps_data_gps_num = ProtoField.uint8 ("dji_mavic_flyrec.rc_gps_data_gps_num", "Gps Num", base.HEX)
f.rc_gps_data_f_scale = ProtoField.float ("dji_mavic_flyrec.rc_gps_data_f_scale", "F Scale", base.DEC)
f.rc_gps_data_gps_state = ProtoField.int16 ("dji_mavic_flyrec.rc_gps_data_gps_state", "Gps State", base.DEC)

local function flightrec_rc_gps_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.rc_gps_data_hour, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_gps_data_min, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_gps_data_sec, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_gps_data_year, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_gps_data_month, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_gps_data_day, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_gps_data_longtitude, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rc_gps_data_latitude, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rc_gps_data_xv, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rc_gps_data_yv, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rc_gps_data_gps_num, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_gps_data_f_scale, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rc_gps_data_gps_state, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 30) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Rc Gps Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Rc Gps Data: Payload size different than expected") end
end

-- Flight log - Cb Gps - 0x2770

f.cb_gps_date = ProtoField.uint32 ("dji_mavic_flyrec.cb_gps_date", "Date", base.HEX)
f.cb_gps_time = ProtoField.uint32 ("dji_mavic_flyrec.cb_gps_time", "Time", base.HEX)
f.cb_gps_lon = ProtoField.int32 ("dji_mavic_flyrec.cb_gps_lon", "Lon", base.DEC)
f.cb_gps_lat = ProtoField.int32 ("dji_mavic_flyrec.cb_gps_lat", "Lat", base.DEC)
f.cb_gps_hmsl = ProtoField.int32 ("dji_mavic_flyrec.cb_gps_hmsl", "Hmsl", base.DEC)
f.cb_gps_vel_n = ProtoField.float ("dji_mavic_flyrec.cb_gps_vel_n", "Vel N", base.DEC)
f.cb_gps_vel_e = ProtoField.float ("dji_mavic_flyrec.cb_gps_vel_e", "Vel E", base.DEC)
f.cb_gps_vel_d = ProtoField.float ("dji_mavic_flyrec.cb_gps_vel_d", "Vel D", base.DEC)
f.cb_gps_hdop = ProtoField.float ("dji_mavic_flyrec.cb_gps_hdop", "Hdop", base.DEC)
f.cb_gps_pdop = ProtoField.float ("dji_mavic_flyrec.cb_gps_pdop", "Pdop", base.DEC)
f.cb_gps_gps_fix = ProtoField.float ("dji_mavic_flyrec.cb_gps_gps_fix", "Gps Fix", base.DEC)
f.cb_gps_gnss_f = ProtoField.float ("dji_mavic_flyrec.cb_gps_gnss_f", "Gnss F", base.DEC)
f.cb_gps_hacc = ProtoField.float ("dji_mavic_flyrec.cb_gps_hacc", "Hacc", base.DEC)
f.cb_gps_sacc = ProtoField.float ("dji_mavic_flyrec.cb_gps_sacc", "Sacc", base.DEC)
f.cb_gps_gps_used = ProtoField.uint32 ("dji_mavic_flyrec.cb_gps_gps_used", "Gps Used", base.HEX)
f.cb_gps_gln_used = ProtoField.uint32 ("dji_mavic_flyrec.cb_gps_gln_used", "Gln Used", base.HEX)
f.cb_gps_numsv = ProtoField.uint16 ("dji_mavic_flyrec.cb_gps_numsv", "Numsv", base.HEX)
f.cb_gps_gpsstate = ProtoField.uint16 ("dji_mavic_flyrec.cb_gps_gpsstate", "Gpsstate", base.HEX)

local function flightrec_cb_gps_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.cb_gps_date, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.cb_gps_time, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.cb_gps_lon, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.cb_gps_lat, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.cb_gps_hmsl, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.cb_gps_vel_n, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.cb_gps_vel_e, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.cb_gps_vel_d, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.cb_gps_hdop, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.cb_gps_pdop, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.cb_gps_gps_fix, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.cb_gps_gnss_f, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.cb_gps_hacc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.cb_gps_sacc, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.cb_gps_gps_used, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.cb_gps_gln_used, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.cb_gps_numsv, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.cb_gps_gpsstate, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 68) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Cb Gps: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Cb Gps: Payload size different than expected") end
end

-- Flight log - Cb Temp - 0x2771

f.cb_temp_data = ProtoField.int32 ("dji_mavic_flyrec.cb_temp_data", "Data", base.DEC)
f.cb_temp_cnt = ProtoField.uint16 ("dji_mavic_flyrec.cb_temp_cnt", "Cnt", base.HEX)

local function flightrec_cb_temp_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.cb_temp_data, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.cb_temp_cnt, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 6) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Cb Temp: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Cb Temp: Payload size different than expected") end
end

-- Flight log - Cb Press - 0x2772

f.cb_press_press = ProtoField.double ("dji_mavic_flyrec.cb_press_press", "Press", base.DEC)
f.cb_press_temp = ProtoField.double ("dji_mavic_flyrec.cb_press_temp", "Temp", base.DEC)

local function flightrec_cb_press_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.cb_press_press, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.cb_press_temp, payload(offset, 8))
    offset = offset + 8

    if (offset ~= 16) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Cb Press: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Cb Press: Payload size different than expected") end
end

-- Flight log - Air Compensate Data - 0x2774

f.air_compensate_data_air_vbx = ProtoField.float ("dji_mavic_flyrec.air_compensate_data_air_vbx", "Air Vbx", base.DEC)
f.air_compensate_data_air_vby = ProtoField.float ("dji_mavic_flyrec.air_compensate_data_air_vby", "Air Vby", base.DEC)
f.air_compensate_data_comp_alti = ProtoField.float ("dji_mavic_flyrec.air_compensate_data_comp_alti", "Comp Alti", base.DEC)
f.air_compensate_data_wind_spd = ProtoField.float ("dji_mavic_flyrec.air_compensate_data_wind_spd", "Wind Spd", base.DEC)
f.air_compensate_data_wind_x = ProtoField.float ("dji_mavic_flyrec.air_compensate_data_wind_x", "Wind X", base.DEC)
f.air_compensate_data_wind_y = ProtoField.float ("dji_mavic_flyrec.air_compensate_data_wind_y", "Wind Y", base.DEC)
f.air_compensate_data_motorspd = ProtoField.float ("dji_mavic_flyrec.air_compensate_data_motorspd", "Motorspd", base.DEC)
f.air_compensate_data_vel_level = ProtoField.uint8 ("dji_mavic_flyrec.air_compensate_data_vel_level", "Vel Level", base.HEX)

local function flightrec_air_compensate_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.air_compensate_data_air_vbx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.air_compensate_data_air_vby, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.air_compensate_data_comp_alti, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.air_compensate_data_wind_spd, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.air_compensate_data_wind_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.air_compensate_data_wind_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.air_compensate_data_motorspd, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.air_compensate_data_vel_level, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 29) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Air Compensate Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Air Compensate Data: Payload size different than expected") end
end

-- Flight log - Vision Tof - 0x2775

f.vision_tof_s_f = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s_f", "S F", base.HEX)
f.vision_tof_s00_dis = ProtoField.uint16 ("dji_mavic_flyrec.vision_tof_s00_dis", "S00 Dis", base.HEX)
f.vision_tof_s00_t = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s00_t", "S00 T", base.HEX)
f.vision_tof_s00_f = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s00_f", "S00 F", base.HEX)
f.vision_tof_s00_cnt = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s00_cnt", "S00 Cnt", base.HEX)
f.vision_tof_s01_dis = ProtoField.uint16 ("dji_mavic_flyrec.vision_tof_s01_dis", "S01 Dis", base.HEX)
f.vision_tof_s01_t = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s01_t", "S01 T", base.HEX)
f.vision_tof_s01_f = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s01_f", "S01 F", base.HEX)
f.vision_tof_s01_cnt = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s01_cnt", "S01 Cnt", base.HEX)
f.vision_tof_s02_dis = ProtoField.uint16 ("dji_mavic_flyrec.vision_tof_s02_dis", "S02 Dis", base.HEX)
f.vision_tof_s02_t = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s02_t", "S02 T", base.HEX)
f.vision_tof_s02_f = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s02_f", "S02 F", base.HEX)
f.vision_tof_s02_cnt = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s02_cnt", "S02 Cnt", base.HEX)
f.vision_tof_s03_dis = ProtoField.uint16 ("dji_mavic_flyrec.vision_tof_s03_dis", "S03 Dis", base.HEX)
f.vision_tof_s03_t = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s03_t", "S03 T", base.HEX)
f.vision_tof_s03_f = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s03_f", "S03 F", base.HEX)
f.vision_tof_s03_cnt = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s03_cnt", "S03 Cnt", base.HEX)
f.vision_tof_s04_dis = ProtoField.uint16 ("dji_mavic_flyrec.vision_tof_s04_dis", "S04 Dis", base.HEX)
f.vision_tof_s04_t = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s04_t", "S04 T", base.HEX)
f.vision_tof_s04_f = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s04_f", "S04 F", base.HEX)
f.vision_tof_s04_cnt = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s04_cnt", "S04 Cnt", base.HEX)
f.vision_tof_s05_dis = ProtoField.uint16 ("dji_mavic_flyrec.vision_tof_s05_dis", "S05 Dis", base.HEX)
f.vision_tof_s05_t = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s05_t", "S05 T", base.HEX)
f.vision_tof_s05_f = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s05_f", "S05 F", base.HEX)
f.vision_tof_s05_cnt = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_s05_cnt", "S05 Cnt", base.HEX)
f.vision_tof_cnt = ProtoField.uint8 ("dji_mavic_flyrec.vision_tof_cnt", "Cnt", base.HEX)

local function flightrec_vision_tof_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.vision_tof_s_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_s00_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.vision_tof_s00_t, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_s00_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_s00_cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_s01_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.vision_tof_s01_t, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_s01_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_s01_cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_s02_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.vision_tof_s02_t, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_s02_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_s02_cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_s03_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.vision_tof_s03_t, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_s03_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_s03_cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_s04_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.vision_tof_s04_t, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_s04_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_s04_cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_s05_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.vision_tof_s05_t, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_s05_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_s05_cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vision_tof_cnt, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 32) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Vision Tof: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Vision Tof: Payload size different than expected") end
end

-- Flight log - Gs Rtk Data - 0x2776

f.gs_rtk_data_hrz_lati = ProtoField.double ("dji_mavic_flyrec.gs_rtk_data_hrz_lati", "Hrz Lati", base.DEC)
f.gs_rtk_data_hrz_long = ProtoField.double ("dji_mavic_flyrec.gs_rtk_data_hrz_long", "Hrz Long", base.DEC)
f.gs_rtk_data_vert_pos = ProtoField.float ("dji_mavic_flyrec.gs_rtk_data_vert_pos", "Vert Pos", base.DEC)
f.gs_rtk_data_hrz_f = ProtoField.uint8 ("dji_mavic_flyrec.gs_rtk_data_hrz_f", "Hrz F", base.HEX)
f.gs_rtk_data_vert_f = ProtoField.uint8 ("dji_mavic_flyrec.gs_rtk_data_vert_f", "Vert F", base.HEX)
f.gs_rtk_data_gs_hrz_la = ProtoField.double ("dji_mavic_flyrec.gs_rtk_data_gs_hrz_la", "Gs Hrz La", base.DEC)
f.gs_rtk_data_gs_hrz_lo = ProtoField.double ("dji_mavic_flyrec.gs_rtk_data_gs_hrz_lo", "Gs Hrz Lo", base.DEC)
f.gs_rtk_data_gs_vert_p = ProtoField.float ("dji_mavic_flyrec.gs_rtk_data_gs_vert_p", "Gs Vert P", base.DEC)
f.gs_rtk_data_hrz_off0 = ProtoField.float ("dji_mavic_flyrec.gs_rtk_data_hrz_off0", "Hrz Off0", base.DEC)
f.gs_rtk_data_hrz_off1 = ProtoField.float ("dji_mavic_flyrec.gs_rtk_data_hrz_off1", "Hrz Off1", base.DEC)
f.gs_rtk_data_vert_off = ProtoField.float ("dji_mavic_flyrec.gs_rtk_data_vert_off", "Vert Off", base.DEC)
f.gs_rtk_data_to_alti = ProtoField.float ("dji_mavic_flyrec.gs_rtk_data_to_alti", "To Alti", base.DEC)
f.gs_rtk_data_r_to_al = ProtoField.float ("dji_mavic_flyrec.gs_rtk_data_r_to_al", "R To Al", base.DEC)
f.gs_rtk_data_r_to_al_f = ProtoField.uint8 ("dji_mavic_flyrec.gs_rtk_data_r_to_al_f", "R To Al F", base.HEX)
f.gs_rtk_data_r_cnct = ProtoField.uint8 ("dji_mavic_flyrec.gs_rtk_data_r_cnct", "R Cnct", base.HEX)
f.gs_rtk_data_gs_rtk_f = ProtoField.uint8 ("dji_mavic_flyrec.gs_rtk_data_gs_rtk_f", "Gs Rtk F", base.HEX)
f.gs_rtk_data_sim_mvo_f = ProtoField.uint16 ("dji_mavic_flyrec.gs_rtk_data_sim_mvo_f", "Sim Mvo F", base.HEX)

local function flightrec_gs_rtk_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.gs_rtk_data_hrz_lati, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.gs_rtk_data_hrz_long, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.gs_rtk_data_vert_pos, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gs_rtk_data_hrz_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gs_rtk_data_vert_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gs_rtk_data_gs_hrz_la, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.gs_rtk_data_gs_hrz_lo, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.gs_rtk_data_gs_vert_p, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gs_rtk_data_hrz_off0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gs_rtk_data_hrz_off1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gs_rtk_data_vert_off, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gs_rtk_data_to_alti, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gs_rtk_data_r_to_al, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gs_rtk_data_r_to_al_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gs_rtk_data_r_cnct, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gs_rtk_data_gs_rtk_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gs_rtk_data_sim_mvo_f, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 67) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gs Rtk Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gs Rtk Data: Payload size different than expected") end
end

-- Flight log - Ex Raw Baro1 - 0x2777

f.ex_raw_baro1_press = ProtoField.float ("dji_mavic_flyrec.ex_raw_baro1_press", "Press", base.DEC)
f.ex_raw_baro1_temp = ProtoField.float ("dji_mavic_flyrec.ex_raw_baro1_temp", "Temp", base.DEC)

local function flightrec_ex_raw_baro1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ex_raw_baro1_press, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ex_raw_baro1_temp, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ex Raw Baro1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ex Raw Baro1: Payload size different than expected") end
end

-- Flight log - Ex Raw Baro2 - 0x2778

f.ex_raw_baro2_press = ProtoField.float ("dji_mavic_flyrec.ex_raw_baro2_press", "Press", base.DEC)
f.ex_raw_baro2_temp = ProtoField.float ("dji_mavic_flyrec.ex_raw_baro2_temp", "Temp", base.DEC)

local function flightrec_ex_raw_baro2_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ex_raw_baro2_press, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ex_raw_baro2_temp, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ex Raw Baro2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ex Raw Baro2: Payload size different than expected") end
end

-- Flight log - Ex Raw Compass - 0x2779

f.ex_raw_compass_x = ProtoField.int16 ("dji_mavic_flyrec.ex_raw_compass_x", "X", base.DEC)
f.ex_raw_compass_y = ProtoField.int16 ("dji_mavic_flyrec.ex_raw_compass_y", "Y", base.DEC)
f.ex_raw_compass_z = ProtoField.int16 ("dji_mavic_flyrec.ex_raw_compass_z", "Z", base.DEC)
f.ex_raw_compass_cnt = ProtoField.uint16 ("dji_mavic_flyrec.ex_raw_compass_cnt", "Cnt", base.HEX)

local function flightrec_ex_raw_compass_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ex_raw_compass_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ex_raw_compass_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ex_raw_compass_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ex_raw_compass_cnt, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ex Raw Compass: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ex Raw Compass: Payload size different than expected") end
end

-- Flight log - Gear Status - 0x27d8

f.gear_status_gr_mode = ProtoField.uint8 ("dji_mavic_flyrec.gear_status_gr_mode", "Gr Mode", base.HEX)
f.gear_status_gr_sta = ProtoField.uint8 ("dji_mavic_flyrec.gear_status_gr_sta", "Gr Sta", base.HEX)
f.gear_status_gr_cmd = ProtoField.uint8 ("dji_mavic_flyrec.gear_status_gr_cmd", "Gr Cmd", base.HEX)
f.gear_status_gr_wk_f = ProtoField.uint8 ("dji_mavic_flyrec.gear_status_gr_wk_f", "Gr Wk F", base.HEX)
f.gear_status_nt_safe2ld = ProtoField.uint8 ("dji_mavic_flyrec.gear_status_nt_safe2ld", "Nt Safe2Ld", base.HEX)
f.gear_status_gr_sh_unab = ProtoField.uint32 ("dji_mavic_flyrec.gear_status_gr_sh_unab", "Gr Sh Unab", base.HEX)
f.gear_status_gr_sh_t = ProtoField.float ("dji_mavic_flyrec.gear_status_gr_sh_t", "Gr Sh T", base.DEC)
f.gear_status_gr_sh_req = ProtoField.uint8 ("dji_mavic_flyrec.gear_status_gr_sh_req", "Gr Sh Req", base.HEX)

local function flightrec_gear_status_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.gear_status_gr_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gear_status_gr_sta, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gear_status_gr_cmd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gear_status_gr_wk_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gear_status_nt_safe2ld, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gear_status_gr_sh_unab, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gear_status_gr_sh_t, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gear_status_gr_sh_req, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 14) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gear Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gear Status: Payload size different than expected") end
end

-- Flight log - Radar Bottom - 0x4ef2

f.radar_bottom_dis = ProtoField.uint16 ("dji_mavic_flyrec.radar_bottom_dis", "Dis", base.HEX)
f.radar_bottom_fix_agl = ProtoField.uint16 ("dji_mavic_flyrec.radar_bottom_fix_agl", "Fix Agl", base.HEX)
f.radar_bottom_raw_dis = ProtoField.uint16 ("dji_mavic_flyrec.radar_bottom_raw_dis", "Raw Dis", base.HEX)
f.radar_bottom_valid_flg = ProtoField.uint8 ("dji_mavic_flyrec.radar_bottom_valid_flg", "Valid Flg", base.HEX)
f.radar_bottom_type = ProtoField.uint8 ("dji_mavic_flyrec.radar_bottom_type", "Type", base.HEX)
f.radar_bottom_health_flag = ProtoField.uint8 ("dji_mavic_flyrec.radar_bottom_health_flag", "Health Flag", base.HEX)
f.radar_bottom_cnt = ProtoField.uint8 ("dji_mavic_flyrec.radar_bottom_cnt", "Cnt", base.HEX)

local function flightrec_radar_bottom_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.radar_bottom_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.radar_bottom_fix_agl, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.radar_bottom_raw_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.radar_bottom_valid_flg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_bottom_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_bottom_health_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_bottom_cnt, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 10) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Radar Bottom: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Radar Bottom: Payload size different than expected") end
end

-- Flight log - Radar Avoid Front - 0x4ef3

f.radar_avoid_front_dis = ProtoField.uint16 ("dji_mavic_flyrec.radar_avoid_front_dis", "Dis", base.HEX)
f.radar_avoid_front_fix_agl = ProtoField.uint16 ("dji_mavic_flyrec.radar_avoid_front_fix_agl", "Fix Agl", base.HEX)
f.radar_avoid_front_raw_dis = ProtoField.uint16 ("dji_mavic_flyrec.radar_avoid_front_raw_dis", "Raw Dis", base.HEX)
f.radar_avoid_front_valid_flg = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_front_valid_flg", "Valid Flg", base.HEX)
f.radar_avoid_front_type = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_front_type", "Type", base.HEX)
f.radar_avoid_front_stop_flg = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_front_stop_flg", "Stop Flg", base.HEX)
f.radar_avoid_front_near_flg = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_front_near_flg", "Near Flg", base.HEX)
f.radar_avoid_front_pm_flag = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_front_pm_flag", "Pm Flag", base.HEX)
f.radar_avoid_front_near_px = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_front_near_px", "Near Px", base.HEX)
f.radar_avoid_front_near_py = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_front_near_py", "Near Py", base.HEX)
f.radar_avoid_front_pm_px = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_front_pm_px", "Pm Px", base.HEX)
f.radar_avoid_front_pm_py = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_front_pm_py", "Pm Py", base.HEX)
f.radar_avoid_front_cur_direciton = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_front_cur_direciton", "Cur Direciton", base.HEX)
f.radar_avoid_front_cnt = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_front_cnt", "Cnt", base.HEX)

local function flightrec_radar_avoid_front_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.radar_avoid_front_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.radar_avoid_front_fix_agl, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.radar_avoid_front_raw_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.radar_avoid_front_valid_flg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_front_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_front_stop_flg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_front_near_flg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_front_pm_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_front_near_px, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_front_near_py, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_front_pm_px, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_front_pm_py, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_front_cur_direciton, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_front_cnt, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 17) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Radar Avoid Front: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Radar Avoid Front: Payload size different than expected") end
end

-- Flight log - Radar Avoid Back - 0x4ef4

f.radar_avoid_back_dis = ProtoField.uint16 ("dji_mavic_flyrec.radar_avoid_back_dis", "Dis", base.HEX)
f.radar_avoid_back_fix_agl = ProtoField.uint16 ("dji_mavic_flyrec.radar_avoid_back_fix_agl", "Fix Agl", base.HEX)
f.radar_avoid_back_raw_dis = ProtoField.uint16 ("dji_mavic_flyrec.radar_avoid_back_raw_dis", "Raw Dis", base.HEX)
f.radar_avoid_back_valid_flg = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_back_valid_flg", "Valid Flg", base.HEX)
f.radar_avoid_back_type = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_back_type", "Type", base.HEX)
f.radar_avoid_back_stop_flg = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_back_stop_flg", "Stop Flg", base.HEX)
f.radar_avoid_back_near_flg = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_back_near_flg", "Near Flg", base.HEX)
f.radar_avoid_back_max_flg = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_back_max_flg", "Max Flg", base.HEX)
f.radar_avoid_back_near_px = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_back_near_px", "Near Px", base.HEX)
f.radar_avoid_back_near_py = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_back_near_py", "Near Py", base.HEX)
f.radar_avoid_back_pm_px = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_back_pm_px", "Pm Px", base.HEX)
f.radar_avoid_back_pm_py = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_back_pm_py", "Pm Py", base.HEX)
f.radar_avoid_back_cnt = ProtoField.uint8 ("dji_mavic_flyrec.radar_avoid_back_cnt", "Cnt", base.HEX)

local function flightrec_radar_avoid_back_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.radar_avoid_back_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.radar_avoid_back_fix_agl, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.radar_avoid_back_raw_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.radar_avoid_back_valid_flg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_back_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_back_stop_flg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_back_near_flg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_back_max_flg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_back_near_px, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_back_near_py, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_back_pm_px, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_back_pm_py, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_avoid_back_cnt, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 16) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Radar Avoid Back: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Radar Avoid Back: Payload size different than expected") end
end

-- Flight log - Radar Predict Front - 0x4ef5

f.radar_predict_front_dis = ProtoField.uint16 ("dji_mavic_flyrec.radar_predict_front_dis", "Dis", base.HEX)
f.radar_predict_front_fix_agl = ProtoField.uint16 ("dji_mavic_flyrec.radar_predict_front_fix_agl", "Fix Agl", base.HEX)
f.radar_predict_front_raw_dis = ProtoField.uint16 ("dji_mavic_flyrec.radar_predict_front_raw_dis", "Raw Dis", base.HEX)
f.radar_predict_front_valid_flg = ProtoField.uint8 ("dji_mavic_flyrec.radar_predict_front_valid_flg", "Valid Flg", base.HEX)
f.radar_predict_front_type = ProtoField.uint8 ("dji_mavic_flyrec.radar_predict_front_type", "Type", base.HEX)
f.radar_predict_front_raw_ok_flg = ProtoField.uint8 ("dji_mavic_flyrec.radar_predict_front_raw_ok_flg", "Raw Ok Flg", base.HEX)
f.radar_predict_front_cnt = ProtoField.uint8 ("dji_mavic_flyrec.radar_predict_front_cnt", "Cnt", base.HEX)

local function flightrec_radar_predict_front_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.radar_predict_front_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.radar_predict_front_fix_agl, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.radar_predict_front_raw_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.radar_predict_front_valid_flg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_predict_front_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_predict_front_raw_ok_flg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_predict_front_cnt, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 10) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Radar Predict Front: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Radar Predict Front: Payload size different than expected") end
end

-- Flight log - Radar Predict Back - 0x4ef6

f.radar_predict_back_dis = ProtoField.uint16 ("dji_mavic_flyrec.radar_predict_back_dis", "Dis", base.HEX)
f.radar_predict_back_fix_agl = ProtoField.uint16 ("dji_mavic_flyrec.radar_predict_back_fix_agl", "Fix Agl", base.HEX)
f.radar_predict_back_raw_dis = ProtoField.uint16 ("dji_mavic_flyrec.radar_predict_back_raw_dis", "Raw Dis", base.HEX)
f.radar_predict_back_valid_flg = ProtoField.uint8 ("dji_mavic_flyrec.radar_predict_back_valid_flg", "Valid Flg", base.HEX)
f.radar_predict_back_type = ProtoField.uint8 ("dji_mavic_flyrec.radar_predict_back_type", "Type", base.HEX)
f.radar_predict_back_raw_ok_flg = ProtoField.uint8 ("dji_mavic_flyrec.radar_predict_back_raw_ok_flg", "Raw Ok Flg", base.HEX)
f.radar_predict_back_cnt = ProtoField.uint8 ("dji_mavic_flyrec.radar_predict_back_cnt", "Cnt", base.HEX)

local function flightrec_radar_predict_back_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.radar_predict_back_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.radar_predict_back_fix_agl, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.radar_predict_back_raw_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.radar_predict_back_valid_flg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_predict_back_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_predict_back_raw_ok_flg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.radar_predict_back_cnt, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 10) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Radar Predict Back: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Radar Predict Back: Payload size different than expected") end
end

-- Flight log - Gyro Raw0 0 - 0x4f4c

f.gyro_raw0_0_gyro_x0_0 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw0_0_gyro_x0_0", "Gyro X0 0", base.DEC)
f.gyro_raw0_0_gyro_y0_0 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw0_0_gyro_y0_0", "Gyro Y0 0", base.DEC)
f.gyro_raw0_0_gyro_z0_0 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw0_0_gyro_z0_0", "Gyro Z0 0", base.DEC)
f.gyro_raw0_0_gyro_temp0_0 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw0_0_gyro_temp0_0", "Gyro Temp0 0", base.DEC)

local function flightrec_gyro_raw0_0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.gyro_raw0_0_gyro_x0_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw0_0_gyro_y0_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw0_0_gyro_z0_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw0_0_gyro_temp0_0, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gyro Raw0 0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gyro Raw0 0: Payload size different than expected") end
end

-- Flight log - Gyro Raw0 1 - 0x4f4d

f.gyro_raw0_1_gyro_x0_1 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw0_1_gyro_x0_1", "Gyro X0 1", base.DEC)
f.gyro_raw0_1_gyro_y0_1 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw0_1_gyro_y0_1", "Gyro Y0 1", base.DEC)
f.gyro_raw0_1_gyro_z0_1 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw0_1_gyro_z0_1", "Gyro Z0 1", base.DEC)
f.gyro_raw0_1_gyro_temp0_1 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw0_1_gyro_temp0_1", "Gyro Temp0 1", base.DEC)

local function flightrec_gyro_raw0_1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.gyro_raw0_1_gyro_x0_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw0_1_gyro_y0_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw0_1_gyro_z0_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw0_1_gyro_temp0_1, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gyro Raw0 1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gyro Raw0 1: Payload size different than expected") end
end

-- Flight log - Gyro Raw0 2 - 0x4f4e

f.gyro_raw0_2_gyro_x0_2 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw0_2_gyro_x0_2", "Gyro X0 2", base.DEC)
f.gyro_raw0_2_gyro_y0_2 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw0_2_gyro_y0_2", "Gyro Y0 2", base.DEC)
f.gyro_raw0_2_gyro_z0_2 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw0_2_gyro_z0_2", "Gyro Z0 2", base.DEC)
f.gyro_raw0_2_gyro_temp0_2 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw0_2_gyro_temp0_2", "Gyro Temp0 2", base.DEC)

local function flightrec_gyro_raw0_2_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.gyro_raw0_2_gyro_x0_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw0_2_gyro_y0_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw0_2_gyro_z0_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw0_2_gyro_temp0_2, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gyro Raw0 2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gyro Raw0 2: Payload size different than expected") end
end

-- Flight log - Gyro Raw1 0 - 0x4f50

f.gyro_raw1_0_gyro_x1_0 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw1_0_gyro_x1_0", "Gyro X1 0", base.DEC)
f.gyro_raw1_0_gyro_y1_0 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw1_0_gyro_y1_0", "Gyro Y1 0", base.DEC)
f.gyro_raw1_0_gyro_z1_0 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw1_0_gyro_z1_0", "Gyro Z1 0", base.DEC)
f.gyro_raw1_0_gyro_temp1_0 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw1_0_gyro_temp1_0", "Gyro Temp1 0", base.DEC)

local function flightrec_gyro_raw1_0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.gyro_raw1_0_gyro_x1_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw1_0_gyro_y1_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw1_0_gyro_z1_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw1_0_gyro_temp1_0, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gyro Raw1 0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gyro Raw1 0: Payload size different than expected") end
end

-- Flight log - Gyro Raw1 1 - 0x4f51

f.gyro_raw1_1_gyro_x1_1 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw1_1_gyro_x1_1", "Gyro X1 1", base.DEC)
f.gyro_raw1_1_gyro_y1_1 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw1_1_gyro_y1_1", "Gyro Y1 1", base.DEC)
f.gyro_raw1_1_gyro_z1_1 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw1_1_gyro_z1_1", "Gyro Z1 1", base.DEC)
f.gyro_raw1_1_gyro_temp1_1 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw1_1_gyro_temp1_1", "Gyro Temp1 1", base.DEC)

local function flightrec_gyro_raw1_1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.gyro_raw1_1_gyro_x1_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw1_1_gyro_y1_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw1_1_gyro_z1_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw1_1_gyro_temp1_1, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gyro Raw1 1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gyro Raw1 1: Payload size different than expected") end
end

-- Flight log - Gyro Raw2 0 - 0x4f54

f.gyro_raw2_0_gyro_x2_0 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw2_0_gyro_x2_0", "Gyro X2 0", base.DEC)
f.gyro_raw2_0_gyro_y2_0 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw2_0_gyro_y2_0", "Gyro Y2 0", base.DEC)
f.gyro_raw2_0_gyro_z2_0 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw2_0_gyro_z2_0", "Gyro Z2 0", base.DEC)
f.gyro_raw2_0_gyro_temp2_0 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw2_0_gyro_temp2_0", "Gyro Temp2 0", base.DEC)

local function flightrec_gyro_raw2_0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.gyro_raw2_0_gyro_x2_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw2_0_gyro_y2_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw2_0_gyro_z2_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw2_0_gyro_temp2_0, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gyro Raw2 0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gyro Raw2 0: Payload size different than expected") end
end

-- Flight log - Gyro Raw2 1 - 0x4f55

f.gyro_raw2_1_gyro_x2_1 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw2_1_gyro_x2_1", "Gyro X2 1", base.DEC)
f.gyro_raw2_1_gyro_y2_1 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw2_1_gyro_y2_1", "Gyro Y2 1", base.DEC)
f.gyro_raw2_1_gyro_z2_1 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw2_1_gyro_z2_1", "Gyro Z2 1", base.DEC)
f.gyro_raw2_1_gyro_temp2_1 = ProtoField.int16 ("dji_mavic_flyrec.gyro_raw2_1_gyro_temp2_1", "Gyro Temp2 1", base.DEC)

local function flightrec_gyro_raw2_1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.gyro_raw2_1_gyro_x2_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw2_1_gyro_y2_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw2_1_gyro_z2_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gyro_raw2_1_gyro_temp2_1, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gyro Raw2 1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gyro Raw2 1: Payload size different than expected") end
end

-- Flight log - Acc Raw0 0 - 0x4f58

f.acc_raw0_0_acc_x0_0 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw0_0_acc_x0_0", "Acc X0 0", base.DEC)
f.acc_raw0_0_acc_y0_0 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw0_0_acc_y0_0", "Acc Y0 0", base.DEC)
f.acc_raw0_0_acc_z0_0 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw0_0_acc_z0_0", "Acc Z0 0", base.DEC)
f.acc_raw0_0_acc_temp0_0 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw0_0_acc_temp0_0", "Acc Temp0 0", base.DEC)

local function flightrec_acc_raw0_0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.acc_raw0_0_acc_x0_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw0_0_acc_y0_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw0_0_acc_z0_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw0_0_acc_temp0_0, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Acc Raw0 0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Acc Raw0 0: Payload size different than expected") end
end

-- Flight log - Acc Raw0 1 - 0x4f59

f.acc_raw0_1_acc_x0_1 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw0_1_acc_x0_1", "Acc X0 1", base.DEC)
f.acc_raw0_1_acc_y0_1 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw0_1_acc_y0_1", "Acc Y0 1", base.DEC)
f.acc_raw0_1_acc_z0_1 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw0_1_acc_z0_1", "Acc Z0 1", base.DEC)
f.acc_raw0_1_acc_temp0_1 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw0_1_acc_temp0_1", "Acc Temp0 1", base.DEC)

local function flightrec_acc_raw0_1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.acc_raw0_1_acc_x0_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw0_1_acc_y0_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw0_1_acc_z0_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw0_1_acc_temp0_1, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Acc Raw0 1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Acc Raw0 1: Payload size different than expected") end
end

-- Flight log - Acc Raw0 2 - 0x4f5a

f.acc_raw0_2_acc_x0_2 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw0_2_acc_x0_2", "Acc X0 2", base.DEC)
f.acc_raw0_2_acc_y0_2 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw0_2_acc_y0_2", "Acc Y0 2", base.DEC)
f.acc_raw0_2_acc_z0_2 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw0_2_acc_z0_2", "Acc Z0 2", base.DEC)
f.acc_raw0_2_acc_temp0_2 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw0_2_acc_temp0_2", "Acc Temp0 2", base.DEC)

local function flightrec_acc_raw0_2_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.acc_raw0_2_acc_x0_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw0_2_acc_y0_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw0_2_acc_z0_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw0_2_acc_temp0_2, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Acc Raw0 2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Acc Raw0 2: Payload size different than expected") end
end

-- Flight log - Acc Raw1 0 - 0x4f5c

f.acc_raw1_0_acc_x1_0 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw1_0_acc_x1_0", "Acc X1 0", base.DEC)
f.acc_raw1_0_acc_y1_0 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw1_0_acc_y1_0", "Acc Y1 0", base.DEC)
f.acc_raw1_0_acc_z1_0 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw1_0_acc_z1_0", "Acc Z1 0", base.DEC)
f.acc_raw1_0_acc_temp1_0 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw1_0_acc_temp1_0", "Acc Temp1 0", base.DEC)

local function flightrec_acc_raw1_0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.acc_raw1_0_acc_x1_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw1_0_acc_y1_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw1_0_acc_z1_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw1_0_acc_temp1_0, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Acc Raw1 0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Acc Raw1 0: Payload size different than expected") end
end

-- Flight log - Acc Raw1 1 - 0x4f5d

f.acc_raw1_1_acc_x1_1 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw1_1_acc_x1_1", "Acc X1 1", base.DEC)
f.acc_raw1_1_acc_y1_1 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw1_1_acc_y1_1", "Acc Y1 1", base.DEC)
f.acc_raw1_1_acc_z1_1 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw1_1_acc_z1_1", "Acc Z1 1", base.DEC)
f.acc_raw1_1_acc_temp1_1 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw1_1_acc_temp1_1", "Acc Temp1 1", base.DEC)

local function flightrec_acc_raw1_1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.acc_raw1_1_acc_x1_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw1_1_acc_y1_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw1_1_acc_z1_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw1_1_acc_temp1_1, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Acc Raw1 1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Acc Raw1 1: Payload size different than expected") end
end

-- Flight log - Acc Raw2 0 - 0x4f60

f.acc_raw2_0_acc_x2_0 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw2_0_acc_x2_0", "Acc X2 0", base.DEC)
f.acc_raw2_0_acc_y2_0 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw2_0_acc_y2_0", "Acc Y2 0", base.DEC)
f.acc_raw2_0_acc_z2_0 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw2_0_acc_z2_0", "Acc Z2 0", base.DEC)
f.acc_raw2_0_acc_temp2_0 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw2_0_acc_temp2_0", "Acc Temp2 0", base.DEC)

local function flightrec_acc_raw2_0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.acc_raw2_0_acc_x2_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw2_0_acc_y2_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw2_0_acc_z2_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw2_0_acc_temp2_0, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Acc Raw2 0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Acc Raw2 0: Payload size different than expected") end
end

-- Flight log - Acc Raw2 1 - 0x4f61

f.acc_raw2_1_acc_x2_1 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw2_1_acc_x2_1", "Acc X2 1", base.DEC)
f.acc_raw2_1_acc_y2_1 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw2_1_acc_y2_1", "Acc Y2 1", base.DEC)
f.acc_raw2_1_acc_z2_1 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw2_1_acc_z2_1", "Acc Z2 1", base.DEC)
f.acc_raw2_1_acc_temp2_1 = ProtoField.int16 ("dji_mavic_flyrec.acc_raw2_1_acc_temp2_1", "Acc Temp2 1", base.DEC)

local function flightrec_acc_raw2_1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.acc_raw2_1_acc_x2_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw2_1_acc_y2_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw2_1_acc_z2_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.acc_raw2_1_acc_temp2_1, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Acc Raw2 1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Acc Raw2 1: Payload size different than expected") end
end

-- Flight log - Sensor Push0 0 - 0x4f64

f.sensor_push0_0_gyro0_0 = ProtoField.int8 ("dji_mavic_flyrec.sensor_push0_0_gyro0_0", "Gyro0 0", base.DEC)
f.sensor_push0_0_acc0_0 = ProtoField.int8 ("dji_mavic_flyrec.sensor_push0_0_acc0_0", "Acc0 0", base.DEC)
f.sensor_push0_0_baro0_0 = ProtoField.int8 ("dji_mavic_flyrec.sensor_push0_0_baro0_0", "Baro0 0", base.DEC)
f.sensor_push0_0_compass0_0 = ProtoField.int8 ("dji_mavic_flyrec.sensor_push0_0_compass0_0", "Compass0 0", base.DEC)

local function flightrec_sensor_push0_0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.sensor_push0_0_gyro0_0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.sensor_push0_0_acc0_0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.sensor_push0_0_baro0_0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.sensor_push0_0_compass0_0, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Sensor Push0 0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Sensor Push0 0: Payload size different than expected") end
end

-- Flight log - Sensor Push0 1 - 0x4f65

f.sensor_push0_1_gyro0_1 = ProtoField.int8 ("dji_mavic_flyrec.sensor_push0_1_gyro0_1", "Gyro0 1", base.DEC)
f.sensor_push0_1_acc0_1 = ProtoField.int8 ("dji_mavic_flyrec.sensor_push0_1_acc0_1", "Acc0 1", base.DEC)
f.sensor_push0_1_baro0_1 = ProtoField.int8 ("dji_mavic_flyrec.sensor_push0_1_baro0_1", "Baro0 1", base.DEC)
f.sensor_push0_1_compass0_1 = ProtoField.int8 ("dji_mavic_flyrec.sensor_push0_1_compass0_1", "Compass0 1", base.DEC)

local function flightrec_sensor_push0_1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.sensor_push0_1_gyro0_1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.sensor_push0_1_acc0_1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.sensor_push0_1_baro0_1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.sensor_push0_1_compass0_1, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Sensor Push0 1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Sensor Push0 1: Payload size different than expected") end
end

-- Flight log - Baro Raw0 - 0x4f6a

f.baro_raw0_baro0 = ProtoField.float ("dji_mavic_flyrec.baro_raw0_baro0", "Baro0", base.DEC)
f.baro_raw0_baro_temp0 = ProtoField.int16 ("dji_mavic_flyrec.baro_raw0_baro_temp0", "Baro Temp0", base.DEC)

local function flightrec_baro_raw0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.baro_raw0_baro0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.baro_raw0_baro_temp0, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 6) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Baro Raw0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Baro Raw0: Payload size different than expected") end
end

-- Flight log - Baro Raw1 - 0x4f6b

f.baro_raw1_baro1 = ProtoField.float ("dji_mavic_flyrec.baro_raw1_baro1", "Baro1", base.DEC)
f.baro_raw1_baro_temp1 = ProtoField.int16 ("dji_mavic_flyrec.baro_raw1_baro_temp1", "Baro Temp1", base.DEC)

local function flightrec_baro_raw1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.baro_raw1_baro1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.baro_raw1_baro_temp1, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 6) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Baro Raw1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Baro Raw1: Payload size different than expected") end
end

-- Flight log - Baro Raw2 - 0x4f6c

f.baro_raw2_baro2 = ProtoField.float ("dji_mavic_flyrec.baro_raw2_baro2", "Baro2", base.DEC)
f.baro_raw2_baro_temp2 = ProtoField.int16 ("dji_mavic_flyrec.baro_raw2_baro_temp2", "Baro Temp2", base.DEC)

local function flightrec_baro_raw2_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.baro_raw2_baro2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.baro_raw2_baro_temp2, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 6) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Baro Raw2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Baro Raw2: Payload size different than expected") end
end

-- Flight log - Baro Raw3 - 0x4f6d

f.baro_raw3_baro3 = ProtoField.float ("dji_mavic_flyrec.baro_raw3_baro3", "Baro3", base.DEC)
f.baro_raw3_baro_temp3 = ProtoField.int16 ("dji_mavic_flyrec.baro_raw3_baro_temp3", "Baro Temp3", base.DEC)

local function flightrec_baro_raw3_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.baro_raw3_baro3, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.baro_raw3_baro_temp3, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 6) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Baro Raw3: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Baro Raw3: Payload size different than expected") end
end

-- Flight log - Compass Raw0 - 0x4f74

f.compass_raw0_r_mx0 = ProtoField.int16 ("dji_mavic_flyrec.compass_raw0_r_mx0", "R Mx0", base.DEC)
f.compass_raw0_r_my0 = ProtoField.int16 ("dji_mavic_flyrec.compass_raw0_r_my0", "R My0", base.DEC)
f.compass_raw0_r_mz0 = ProtoField.int16 ("dji_mavic_flyrec.compass_raw0_r_mz0", "R Mz0", base.DEC)
f.compass_raw0_r_m_cnt0 = ProtoField.uint16 ("dji_mavic_flyrec.compass_raw0_r_m_cnt0", "R M Cnt0", base.HEX)

local function flightrec_compass_raw0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.compass_raw0_r_mx0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.compass_raw0_r_my0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.compass_raw0_r_mz0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.compass_raw0_r_m_cnt0, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Compass Raw0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Compass Raw0: Payload size different than expected") end
end

-- Flight log - Compass Raw1 - 0x4f75

f.compass_raw1_r_mx1 = ProtoField.int16 ("dji_mavic_flyrec.compass_raw1_r_mx1", "R Mx1", base.DEC)
f.compass_raw1_r_my1 = ProtoField.int16 ("dji_mavic_flyrec.compass_raw1_r_my1", "R My1", base.DEC)
f.compass_raw1_r_mz1 = ProtoField.int16 ("dji_mavic_flyrec.compass_raw1_r_mz1", "R Mz1", base.DEC)
f.compass_raw1_r_m_cnt1 = ProtoField.uint16 ("dji_mavic_flyrec.compass_raw1_r_m_cnt1", "R M Cnt1", base.HEX)

local function flightrec_compass_raw1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.compass_raw1_r_mx1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.compass_raw1_r_my1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.compass_raw1_r_mz1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.compass_raw1_r_m_cnt1, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Compass Raw1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Compass Raw1: Payload size different than expected") end
end

-- Flight log - Compass Raw2 - 0x4f76

f.compass_raw2_r_mx2 = ProtoField.int16 ("dji_mavic_flyrec.compass_raw2_r_mx2", "R Mx2", base.DEC)
f.compass_raw2_r_my2 = ProtoField.int16 ("dji_mavic_flyrec.compass_raw2_r_my2", "R My2", base.DEC)
f.compass_raw2_r_mz2 = ProtoField.int16 ("dji_mavic_flyrec.compass_raw2_r_mz2", "R Mz2", base.DEC)
f.compass_raw2_r_m_cnt2 = ProtoField.uint16 ("dji_mavic_flyrec.compass_raw2_r_m_cnt2", "R M Cnt2", base.HEX)

local function flightrec_compass_raw2_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.compass_raw2_r_mx2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.compass_raw2_r_my2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.compass_raw2_r_mz2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.compass_raw2_r_m_cnt2, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Compass Raw2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Compass Raw2: Payload size different than expected") end
end

-- Flight log - Compass Filter0 - 0x4f7e

f.compass_filter0_f_mx0 = ProtoField.int16 ("dji_mavic_flyrec.compass_filter0_f_mx0", "F Mx0", base.DEC)
f.compass_filter0_f_my0 = ProtoField.int16 ("dji_mavic_flyrec.compass_filter0_f_my0", "F My0", base.DEC)
f.compass_filter0_f_mz0 = ProtoField.int16 ("dji_mavic_flyrec.compass_filter0_f_mz0", "F Mz0", base.DEC)

local function flightrec_compass_filter0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.compass_filter0_f_mx0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.compass_filter0_f_my0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.compass_filter0_f_mz0, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 6) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Compass Filter0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Compass Filter0: Payload size different than expected") end
end

-- Flight log - Compass Filter1 - 0x4f7f

f.compass_filter1_f_mx1 = ProtoField.int16 ("dji_mavic_flyrec.compass_filter1_f_mx1", "F Mx1", base.DEC)
f.compass_filter1_f_my1 = ProtoField.int16 ("dji_mavic_flyrec.compass_filter1_f_my1", "F My1", base.DEC)
f.compass_filter1_f_mz1 = ProtoField.int16 ("dji_mavic_flyrec.compass_filter1_f_mz1", "F Mz1", base.DEC)

local function flightrec_compass_filter1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.compass_filter1_f_mx1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.compass_filter1_f_my1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.compass_filter1_f_mz1, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 6) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Compass Filter1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Compass Filter1: Payload size different than expected") end
end

-- Flight log - Compass Filter2 - 0x4f80

f.compass_filter2_f_mx2 = ProtoField.int16 ("dji_mavic_flyrec.compass_filter2_f_mx2", "F Mx2", base.DEC)
f.compass_filter2_f_my2 = ProtoField.int16 ("dji_mavic_flyrec.compass_filter2_f_my2", "F My2", base.DEC)
f.compass_filter2_f_mz2 = ProtoField.int16 ("dji_mavic_flyrec.compass_filter2_f_mz2", "F Mz2", base.DEC)

local function flightrec_compass_filter2_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.compass_filter2_f_mx2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.compass_filter2_f_my2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.compass_filter2_f_mz2, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 6) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Compass Filter2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Compass Filter2: Payload size different than expected") end
end

-- Flight log - Imu Rotated Data - 0x4f88

f.imu_rotated_data_rotated_x = ProtoField.float ("dji_mavic_flyrec.imu_rotated_data_rotated_x", "Rotated X", base.DEC)
f.imu_rotated_data_rotated_y = ProtoField.float ("dji_mavic_flyrec.imu_rotated_data_rotated_y", "Rotated Y", base.DEC)
f.imu_rotated_data_rotated_z = ProtoField.float ("dji_mavic_flyrec.imu_rotated_data_rotated_z", "Rotated Z", base.DEC)

local function flightrec_imu_rotated_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.imu_rotated_data_rotated_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_rotated_data_rotated_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.imu_rotated_data_rotated_z, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 12) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Rotated Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Rotated Data: Payload size different than expected") end
end

-- Flight log - Raw Wristband Data - 0x5014

f.raw_wristband_data_longti = ProtoField.int32 ("dji_mavic_flyrec.raw_wristband_data_longti", "Longti", base.DEC)
f.raw_wristband_data_lati = ProtoField.int32 ("dji_mavic_flyrec.raw_wristband_data_lati", "Lati", base.DEC)
f.raw_wristband_data_height = ProtoField.float ("dji_mavic_flyrec.raw_wristband_data_height", "Height", base.DEC)
f.raw_wristband_data_vel_n = ProtoField.int16 ("dji_mavic_flyrec.raw_wristband_data_vel_n", "Vel N", base.DEC)
f.raw_wristband_data_vel_e = ProtoField.int16 ("dji_mavic_flyrec.raw_wristband_data_vel_e", "Vel E", base.DEC)
f.raw_wristband_data_vel_d = ProtoField.int16 ("dji_mavic_flyrec.raw_wristband_data_vel_d", "Vel D", base.DEC)
f.raw_wristband_data_acc_n = ProtoField.int16 ("dji_mavic_flyrec.raw_wristband_data_acc_n", "Acc N", base.DEC)
f.raw_wristband_data_acc_e = ProtoField.int16 ("dji_mavic_flyrec.raw_wristband_data_acc_e", "Acc E", base.DEC)
f.raw_wristband_data_acc_d = ProtoField.int16 ("dji_mavic_flyrec.raw_wristband_data_acc_d", "Acc D", base.DEC)
f.raw_wristband_data_tilt_x = ProtoField.int16 ("dji_mavic_flyrec.raw_wristband_data_tilt_x", "Tilt X", base.DEC)
f.raw_wristband_data_tilt_y = ProtoField.int16 ("dji_mavic_flyrec.raw_wristband_data_tilt_y", "Tilt Y", base.DEC)
f.raw_wristband_data_torsion = ProtoField.int16 ("dji_mavic_flyrec.raw_wristband_data_torsion", "Torsion", base.DEC)
f.raw_wristband_data_gyro_x = ProtoField.int16 ("dji_mavic_flyrec.raw_wristband_data_gyro_x", "Gyro X", base.DEC)
f.raw_wristband_data_gyro_y = ProtoField.int16 ("dji_mavic_flyrec.raw_wristband_data_gyro_y", "Gyro Y", base.DEC)
f.raw_wristband_data_gyro_z = ProtoField.int16 ("dji_mavic_flyrec.raw_wristband_data_gyro_z", "Gyro Z", base.DEC)
f.raw_wristband_data_flag = ProtoField.uint8 ("dji_mavic_flyrec.raw_wristband_data_flag", "Flag", base.HEX)
f.raw_wristband_data_channel = ProtoField.uint16 ("dji_mavic_flyrec.raw_wristband_data_channel", "Channel", base.HEX)
f.raw_wristband_data_cmd = ProtoField.uint8 ("dji_mavic_flyrec.raw_wristband_data_cmd", "Cmd", base.HEX)
f.raw_wristband_data_cnt = ProtoField.uint8 ("dji_mavic_flyrec.raw_wristband_data_cnt", "Cnt", base.HEX)

local function flightrec_raw_wristband_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.raw_wristband_data_longti, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.raw_wristband_data_lati, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.raw_wristband_data_height, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.raw_wristband_data_vel_n, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.raw_wristband_data_vel_e, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.raw_wristband_data_vel_d, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.raw_wristband_data_acc_n, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.raw_wristband_data_acc_e, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.raw_wristband_data_acc_d, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.raw_wristband_data_tilt_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.raw_wristband_data_tilt_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.raw_wristband_data_torsion, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.raw_wristband_data_gyro_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.raw_wristband_data_gyro_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.raw_wristband_data_gyro_z, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.raw_wristband_data_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.raw_wristband_data_channel, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.raw_wristband_data_cmd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.raw_wristband_data_cnt, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 41) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Raw Wristband Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Raw Wristband Data: Payload size different than expected") end
end

-- Flight log - Wristband - 0x5015

f.wristband_ctrl_pitch = ProtoField.float ("dji_mavic_flyrec.wristband_ctrl_pitch", "Ctrl Pitch", base.DEC)
f.wristband_ctrl_roll = ProtoField.float ("dji_mavic_flyrec.wristband_ctrl_roll", "Ctrl Roll", base.DEC)
f.wristband_ctrl_yaw = ProtoField.float ("dji_mavic_flyrec.wristband_ctrl_yaw", "Ctrl Yaw", base.DEC)
f.wristband_ctrl_thr_wb = ProtoField.float ("dji_mavic_flyrec.wristband_ctrl_thr_wb", "Ctrl Thr Wb", base.DEC)
f.wristband_cmd = ProtoField.uint8 ("dji_mavic_flyrec.wristband_cmd", "Cmd", base.HEX)
f.wristband_disconnect_flag = ProtoField.uint8 ("dji_mavic_flyrec.wristband_disconnect_flag", "Disconnect Flag", base.HEX)
f.wristband_is_hp_set = ProtoField.uint8 ("dji_mavic_flyrec.wristband_is_hp_set", "Is Hp Set", base.HEX)

local function flightrec_wristband_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.wristband_ctrl_pitch, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.wristband_ctrl_roll, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.wristband_ctrl_yaw, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.wristband_ctrl_thr_wb, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.wristband_cmd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.wristband_disconnect_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.wristband_is_hp_set, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 19) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Wristband: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Wristband: Payload size different than expected") end
end

-- Flight log - Ctrl Device - 0x501e

f.ctrl_device_raw_pitch = ProtoField.float ("dji_mavic_flyrec.ctrl_device_raw_pitch", "Raw Pitch", base.DEC)
f.ctrl_device_raw_roll = ProtoField.float ("dji_mavic_flyrec.ctrl_device_raw_roll", "Raw Roll", base.DEC)
f.ctrl_device_raw_yaw = ProtoField.float ("dji_mavic_flyrec.ctrl_device_raw_yaw", "Raw Yaw", base.DEC)
f.ctrl_device_raw_throttle = ProtoField.float ("dji_mavic_flyrec.ctrl_device_raw_throttle", "Raw Throttle", base.DEC)
f.ctrl_device_ctrl_pitch = ProtoField.float ("dji_mavic_flyrec.ctrl_device_ctrl_pitch", "Ctrl Pitch", base.DEC)
f.ctrl_device_ctrl_roll = ProtoField.float ("dji_mavic_flyrec.ctrl_device_ctrl_roll", "Ctrl Roll", base.DEC)
f.ctrl_device_ctrl_yaw = ProtoField.float ("dji_mavic_flyrec.ctrl_device_ctrl_yaw", "Ctrl Yaw", base.DEC)
f.ctrl_device_ctrl_throttle = ProtoField.float ("dji_mavic_flyrec.ctrl_device_ctrl_throttle", "Ctrl Throttle", base.DEC)
f.ctrl_device_cmd = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_device_cmd", "Cmd", base.HEX)
f.ctrl_device_flight_mode = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_device_flight_mode", "Flight Mode", base.HEX)
f.ctrl_device_connected_flag = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_device_connected_flag", "Connected Flag", base.HEX)
f.ctrl_device_is_lost_gh = ProtoField.uint8 ("dji_mavic_flyrec.ctrl_device_is_lost_gh", "Is Lost Gh", base.HEX)

local function flightrec_ctrl_device_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ctrl_device_raw_pitch, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_device_raw_roll, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_device_raw_yaw, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_device_raw_throttle, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_device_ctrl_pitch, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_device_ctrl_roll, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_device_ctrl_yaw, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_device_ctrl_throttle, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ctrl_device_cmd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_device_flight_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_device_connected_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.ctrl_device_is_lost_gh, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 36) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ctrl Device: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ctrl Device: Payload size different than expected") end
end

-- Flight log - Battery Info 2 - 0x4e20

f.battery_info_2_batsop = ProtoField.float ("dji_mavic_flyrec.battery_info_2_batsop", "Batsop", base.DEC)
f.battery_info_2_ad_f = ProtoField.uint16 ("dji_mavic_flyrec.battery_info_2_ad_f", "Ad F", base.HEX)
f.battery_info_2_ad_v = ProtoField.uint16 ("dji_mavic_flyrec.battery_info_2_ad_v", "Ad V", base.HEX)
f.battery_info_2_sop_en = ProtoField.uint8 ("dji_mavic_flyrec.battery_info_2_sop_en", "Sop En", base.HEX)
f.battery_info_2_ilowlimit = ProtoField.int32 ("dji_mavic_flyrec.battery_info_2_ilowlimit", "Ilowlimit", base.DEC)
f.battery_info_2_power = ProtoField.float ("dji_mavic_flyrec.battery_info_2_power", "Power", base.DEC)
f.battery_info_2_current = ProtoField.float ("dji_mavic_flyrec.battery_info_2_current", "Current", base.DEC)
f.battery_info_2_esc_i = ProtoField.float ("dji_mavic_flyrec.battery_info_2_esc_i", "Esc I", base.DEC)
f.battery_info_2_power_err = ProtoField.float ("dji_mavic_flyrec.battery_info_2_power_err", "Power Err", base.DEC)
f.battery_info_2_sop_p = ProtoField.float ("dji_mavic_flyrec.battery_info_2_sop_p", "Sop P", base.DEC)
f.battery_info_2_sop_i = ProtoField.float ("dji_mavic_flyrec.battery_info_2_sop_i", "Sop I", base.DEC)
f.battery_info_2_rawpe = ProtoField.float ("dji_mavic_flyrec.battery_info_2_rawpe", "Rawpe", base.DEC)

local function flightrec_battery_info_2_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.battery_info_2_batsop, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_2_ad_f, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_2_ad_v, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_info_2_sop_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_info_2_ilowlimit, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_2_power, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_2_current, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_2_esc_i, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_2_power_err, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_2_sop_p, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_2_sop_i, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_2_rawpe, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 41) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Battery Info 2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Battery Info 2: Payload size different than expected") end
end

-- Flight log - Pwm Output - 0x4e21

f.pwm_output_m1 = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_m1", "M1", base.HEX)
f.pwm_output_m2 = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_m2", "M2", base.HEX)
f.pwm_output_m3 = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_m3", "M3", base.HEX)
f.pwm_output_m4 = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_m4", "M4", base.HEX)
f.pwm_output_m5 = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_m5", "M5", base.HEX)
f.pwm_output_m6 = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_m6", "M6", base.HEX)
f.pwm_output_m7 = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_m7", "M7", base.HEX)
f.pwm_output_m8 = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_m8", "M8", base.HEX)
f.pwm_output_f1 = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_f1", "F1", base.HEX)
f.pwm_output_f2 = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_f2", "F2", base.HEX)
f.pwm_output_f3 = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_f3", "F3", base.HEX)
f.pwm_output_f4 = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_f4", "F4", base.HEX)
f.pwm_output_f5 = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_f5", "F5", base.HEX)
f.pwm_output_f6 = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_f6", "F6", base.HEX)
f.pwm_output_f7 = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_f7", "F7", base.HEX)
f.pwm_output_f8 = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_f8", "F8", base.HEX)
f.pwm_output_temp_ctrl0 = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_temp_ctrl0", "Temp Ctrl0", base.HEX)
f.pwm_output_temp_ctrl1 = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_temp_ctrl1", "Temp Ctrl1", base.HEX)
f.pwm_output_temp_ctrl = ProtoField.uint32 ("dji_mavic_flyrec.pwm_output_temp_ctrl", "Temp Ctrl", base.HEX)

local function flightrec_pwm_output_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.pwm_output_m1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.pwm_output_m2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.pwm_output_m3, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.pwm_output_m4, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.pwm_output_m5, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.pwm_output_m6, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.pwm_output_m7, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.pwm_output_m8, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.pwm_output_f1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.pwm_output_f2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.pwm_output_f3, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.pwm_output_f4, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.pwm_output_f5, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.pwm_output_f6, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.pwm_output_f7, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.pwm_output_f8, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.pwm_output_temp_ctrl0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.pwm_output_temp_ctrl1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.pwm_output_temp_ctrl, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 76) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Pwm Output: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Pwm Output: Payload size different than expected") end
end

-- Flight log - Temp Ctl Recorde0 - 0x0880

f.temp_ctl_recorde0_struck_t_0 = ProtoField.uint16 ("dji_mavic_flyrec.temp_ctl_recorde0_struck_t_0", "Struck T 0", base.HEX)
f.temp_ctl_recorde0_err_cnt_0 = ProtoField.uint16 ("dji_mavic_flyrec.temp_ctl_recorde0_err_cnt_0", "Err Cnt 0", base.HEX)
f.temp_ctl_recorde0_cmd_tgt_0 = ProtoField.int16 ("dji_mavic_flyrec.temp_ctl_recorde0_cmd_tgt_0", "Cmd Tgt 0", base.DEC)
f.temp_ctl_recorde0_pwm_per_0 = ProtoField.float ("dji_mavic_flyrec.temp_ctl_recorde0_pwm_per_0", "Pwm Per 0", base.DEC)
f.temp_ctl_recorde0_cmd_0 = ProtoField.float ("dji_mavic_flyrec.temp_ctl_recorde0_cmd_0", "Cmd 0", base.DEC)
f.temp_ctl_recorde0_err_0 = ProtoField.int16 ("dji_mavic_flyrec.temp_ctl_recorde0_err_0", "Err 0", base.DEC)
f.temp_ctl_recorde0_fdbk_0 = ProtoField.float ("dji_mavic_flyrec.temp_ctl_recorde0_fdbk_0", "Fdbk 0", base.DEC)
f.temp_ctl_recorde0_p_0 = ProtoField.int16 ("dji_mavic_flyrec.temp_ctl_recorde0_p_0", "P 0", base.DEC)
f.temp_ctl_recorde0_i_0 = ProtoField.int16 ("dji_mavic_flyrec.temp_ctl_recorde0_i_0", "I 0", base.DEC)
f.temp_ctl_recorde0_out_0 = ProtoField.int16 ("dji_mavic_flyrec.temp_ctl_recorde0_out_0", "Out 0", base.DEC)
f.temp_ctl_recorde0_err_lev_0 = ProtoField.uint8 ("dji_mavic_flyrec.temp_ctl_recorde0_err_lev_0", "Err Lev 0", base.HEX)
f.temp_ctl_recorde0_state_0 = ProtoField.uint8 ("dji_mavic_flyrec.temp_ctl_recorde0_state_0", "State 0", base.HEX)
f.temp_ctl_recorde0_status_0 = ProtoField.uint8 ("dji_mavic_flyrec.temp_ctl_recorde0_status_0", "Status 0", base.HEX)
f.temp_ctl_recorde0_reset_0 = ProtoField.uint8 ("dji_mavic_flyrec.temp_ctl_recorde0_reset_0", "Reset 0", base.HEX)

local function flightrec_temp_ctl_recorde0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.temp_ctl_recorde0_struck_t_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde0_err_cnt_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde0_cmd_tgt_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde0_pwm_per_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_recorde0_cmd_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_recorde0_err_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde0_fdbk_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_recorde0_p_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde0_i_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde0_out_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde0_err_lev_0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_recorde0_state_0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_recorde0_status_0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_recorde0_reset_0, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 30) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Temp Ctl Recorde0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Temp Ctl Recorde0: Payload size different than expected") end
end

-- Flight log - Temp Ctl Recorde1 - 0x0881

f.temp_ctl_recorde1_struck_t_1 = ProtoField.uint16 ("dji_mavic_flyrec.temp_ctl_recorde1_struck_t_1", "Struck T 1", base.HEX)
f.temp_ctl_recorde1_err_cnt_1 = ProtoField.uint16 ("dji_mavic_flyrec.temp_ctl_recorde1_err_cnt_1", "Err Cnt 1", base.HEX)
f.temp_ctl_recorde1_cmd_tgt_1 = ProtoField.int16 ("dji_mavic_flyrec.temp_ctl_recorde1_cmd_tgt_1", "Cmd Tgt 1", base.DEC)
f.temp_ctl_recorde1_pwm_per_1 = ProtoField.float ("dji_mavic_flyrec.temp_ctl_recorde1_pwm_per_1", "Pwm Per 1", base.DEC)
f.temp_ctl_recorde1_cmd_1 = ProtoField.float ("dji_mavic_flyrec.temp_ctl_recorde1_cmd_1", "Cmd 1", base.DEC)
f.temp_ctl_recorde1_err_1 = ProtoField.int16 ("dji_mavic_flyrec.temp_ctl_recorde1_err_1", "Err 1", base.DEC)
f.temp_ctl_recorde1_fdbk_1 = ProtoField.float ("dji_mavic_flyrec.temp_ctl_recorde1_fdbk_1", "Fdbk 1", base.DEC)
f.temp_ctl_recorde1_p_1 = ProtoField.int16 ("dji_mavic_flyrec.temp_ctl_recorde1_p_1", "P 1", base.DEC)
f.temp_ctl_recorde1_i_1 = ProtoField.int16 ("dji_mavic_flyrec.temp_ctl_recorde1_i_1", "I 1", base.DEC)
f.temp_ctl_recorde1_out_1 = ProtoField.int16 ("dji_mavic_flyrec.temp_ctl_recorde1_out_1", "Out 1", base.DEC)
f.temp_ctl_recorde1_err_lev_1 = ProtoField.uint8 ("dji_mavic_flyrec.temp_ctl_recorde1_err_lev_1", "Err Lev 1", base.HEX)
f.temp_ctl_recorde1_state_1 = ProtoField.uint8 ("dji_mavic_flyrec.temp_ctl_recorde1_state_1", "State 1", base.HEX)
f.temp_ctl_recorde1_status_1 = ProtoField.uint8 ("dji_mavic_flyrec.temp_ctl_recorde1_status_1", "Status 1", base.HEX)
f.temp_ctl_recorde1_reset_1 = ProtoField.uint8 ("dji_mavic_flyrec.temp_ctl_recorde1_reset_1", "Reset 1", base.HEX)

local function flightrec_temp_ctl_recorde1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.temp_ctl_recorde1_struck_t_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde1_err_cnt_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde1_cmd_tgt_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde1_pwm_per_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_recorde1_cmd_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_recorde1_err_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde1_fdbk_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_recorde1_p_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde1_i_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde1_out_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde1_err_lev_1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_recorde1_state_1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_recorde1_status_1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_recorde1_reset_1, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 30) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Temp Ctl Recorde1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Temp Ctl Recorde1: Payload size different than expected") end
end

-- Flight log - Temp Ctl Recorde2 - 0x0882

f.temp_ctl_recorde2_struck_t_2 = ProtoField.uint16 ("dji_mavic_flyrec.temp_ctl_recorde2_struck_t_2", "Struck T 2", base.HEX)
f.temp_ctl_recorde2_err_cnt_2 = ProtoField.uint16 ("dji_mavic_flyrec.temp_ctl_recorde2_err_cnt_2", "Err Cnt 2", base.HEX)
f.temp_ctl_recorde2_cmd_tgt_2 = ProtoField.int16 ("dji_mavic_flyrec.temp_ctl_recorde2_cmd_tgt_2", "Cmd Tgt 2", base.DEC)
f.temp_ctl_recorde2_pwm_per_2 = ProtoField.float ("dji_mavic_flyrec.temp_ctl_recorde2_pwm_per_2", "Pwm Per 2", base.DEC)
f.temp_ctl_recorde2_cmd_2 = ProtoField.float ("dji_mavic_flyrec.temp_ctl_recorde2_cmd_2", "Cmd 2", base.DEC)
f.temp_ctl_recorde2_err_2 = ProtoField.int16 ("dji_mavic_flyrec.temp_ctl_recorde2_err_2", "Err 2", base.DEC)
f.temp_ctl_recorde2_fdbk_2 = ProtoField.float ("dji_mavic_flyrec.temp_ctl_recorde2_fdbk_2", "Fdbk 2", base.DEC)
f.temp_ctl_recorde2_p_2 = ProtoField.int16 ("dji_mavic_flyrec.temp_ctl_recorde2_p_2", "P 2", base.DEC)
f.temp_ctl_recorde2_i_2 = ProtoField.int16 ("dji_mavic_flyrec.temp_ctl_recorde2_i_2", "I 2", base.DEC)
f.temp_ctl_recorde2_out_2 = ProtoField.int16 ("dji_mavic_flyrec.temp_ctl_recorde2_out_2", "Out 2", base.DEC)
f.temp_ctl_recorde2_err_lev_2 = ProtoField.uint8 ("dji_mavic_flyrec.temp_ctl_recorde2_err_lev_2", "Err Lev 2", base.HEX)
f.temp_ctl_recorde2_state_2 = ProtoField.uint8 ("dji_mavic_flyrec.temp_ctl_recorde2_state_2", "State 2", base.HEX)
f.temp_ctl_recorde2_status_2 = ProtoField.uint8 ("dji_mavic_flyrec.temp_ctl_recorde2_status_2", "Status 2", base.HEX)
f.temp_ctl_recorde2_reset_2 = ProtoField.uint8 ("dji_mavic_flyrec.temp_ctl_recorde2_reset_2", "Reset 2", base.HEX)

local function flightrec_temp_ctl_recorde2_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.temp_ctl_recorde2_struck_t_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde2_err_cnt_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde2_cmd_tgt_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde2_pwm_per_2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_recorde2_cmd_2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_recorde2_err_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde2_fdbk_2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.temp_ctl_recorde2_p_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde2_i_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde2_out_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.temp_ctl_recorde2_err_lev_2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_recorde2_state_2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_recorde2_status_2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.temp_ctl_recorde2_reset_2, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 30) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Temp Ctl Recorde2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Temp Ctl Recorde2: Payload size different than expected") end
end

-- Flight log - Airport Limit Debug Info - 0x4e22

f.airport_limit_debug_info_flg = ProtoField.uint8 ("dji_mavic_flyrec.airport_limit_debug_info_flg", "Flg", base.HEX)
f.airport_limit_debug_info_uid = ProtoField.uint32 ("dji_mavic_flyrec.airport_limit_debug_info_uid", "Uid", base.HEX)
f.airport_limit_debug_info_v_n = ProtoField.int8 ("dji_mavic_flyrec.airport_limit_debug_info_v_n", "V N", base.DEC)
f.airport_limit_debug_info_v_e = ProtoField.int8 ("dji_mavic_flyrec.airport_limit_debug_info_v_e", "V E", base.DEC)
f.airport_limit_debug_info_v_d = ProtoField.int8 ("dji_mavic_flyrec.airport_limit_debug_info_v_d", "V D", base.DEC)
f.airport_limit_debug_info_norm = ProtoField.uint8 ("dji_mavic_flyrec.airport_limit_debug_info_norm", "Norm", base.HEX)

local function flightrec_airport_limit_debug_info_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.airport_limit_debug_info_flg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airport_limit_debug_info_uid, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airport_limit_debug_info_v_n, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airport_limit_debug_info_v_e, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airport_limit_debug_info_v_d, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airport_limit_debug_info_norm, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 9) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Airport Limit Debug Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Airport Limit Debug Info: Payload size different than expected") end
end

-- Flight log - Battery Raw Data 1 - 0x4e23

f.battery_raw_data_1_0 = ProtoField.uint16 ("dji_mavic_flyrec.battery_raw_data_1_0", "0", base.HEX)
f.battery_raw_data_1_1 = ProtoField.uint16 ("dji_mavic_flyrec.battery_raw_data_1_1", "1", base.HEX)
f.battery_raw_data_1_2 = ProtoField.uint16 ("dji_mavic_flyrec.battery_raw_data_1_2", "2", base.HEX)
f.battery_raw_data_1_3 = ProtoField.uint16 ("dji_mavic_flyrec.battery_raw_data_1_3", "3", base.HEX)
f.battery_raw_data_1_4 = ProtoField.uint16 ("dji_mavic_flyrec.battery_raw_data_1_4", "4", base.HEX)
f.battery_raw_data_1_5 = ProtoField.uint16 ("dji_mavic_flyrec.battery_raw_data_1_5", "5", base.HEX)
f.battery_raw_data_1_lowest = ProtoField.uint16 ("dji_mavic_flyrec.battery_raw_data_1_lowest", "Lowest", base.HEX)

local function flightrec_battery_raw_data_1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.battery_raw_data_1_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_raw_data_1_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_raw_data_1_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_raw_data_1_3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_raw_data_1_4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_raw_data_1_5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_raw_data_1_lowest, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 14) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Battery Raw Data 1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Battery Raw Data 1: Payload size different than expected") end
end

-- Flight log - Battery Raw Data 2 - 0x4e24

f.battery_raw_data_2_0 = ProtoField.uint16 ("dji_mavic_flyrec.battery_raw_data_2_0", "0", base.HEX)
f.battery_raw_data_2_1 = ProtoField.uint16 ("dji_mavic_flyrec.battery_raw_data_2_1", "1", base.HEX)
f.battery_raw_data_2_2 = ProtoField.uint16 ("dji_mavic_flyrec.battery_raw_data_2_2", "2", base.HEX)
f.battery_raw_data_2_3 = ProtoField.uint16 ("dji_mavic_flyrec.battery_raw_data_2_3", "3", base.HEX)
f.battery_raw_data_2_4 = ProtoField.uint16 ("dji_mavic_flyrec.battery_raw_data_2_4", "4", base.HEX)
f.battery_raw_data_2_5 = ProtoField.uint16 ("dji_mavic_flyrec.battery_raw_data_2_5", "5", base.HEX)
f.battery_raw_data_2_lowest = ProtoField.uint16 ("dji_mavic_flyrec.battery_raw_data_2_lowest", "Lowest", base.HEX)

local function flightrec_battery_raw_data_2_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.battery_raw_data_2_0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_raw_data_2_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_raw_data_2_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_raw_data_2_3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_raw_data_2_4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_raw_data_2_5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.battery_raw_data_2_lowest, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 14) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Battery Raw Data 2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Battery Raw Data 2: Payload size different than expected") end
end

-- Flight log - Sys Err - 0x4e25

f.sys_err_code_err = ProtoField.uint8 ("dji_mavic_flyrec.sys_err_code_err", "Code Err", base.HEX)
f.sys_err_sn_err1 = ProtoField.uint8 ("dji_mavic_flyrec.sys_err_sn_err1", "Sn Err1", base.HEX)
f.sys_err_sn_err2 = ProtoField.uint8 ("dji_mavic_flyrec.sys_err_sn_err2", "Sn Err2", base.HEX)
f.sys_err_sd_fail = ProtoField.uint8 ("dji_mavic_flyrec.sys_err_sd_fail", "Sd Fail", base.HEX)
f.sys_err_ifv = ProtoField.uint8 ("dji_mavic_flyrec.sys_err_ifv", "Ifv", base.HEX)

local function flightrec_sys_err_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.sys_err_code_err, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.sys_err_sn_err1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.sys_err_sn_err2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.sys_err_sd_fail, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.sys_err_ifv, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Sys Err: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Sys Err: Payload size different than expected") end
end

-- Flight log - Quick Circle Debug - 0x4e27

f.quick_circle_debug_qc_trg_a = ProtoField.uint8 ("dji_mavic_flyrec.quick_circle_debug_qc_trg_a", "Qc Trg A", base.HEX)
f.quick_circle_debug_qc_trg_m = ProtoField.uint8 ("dji_mavic_flyrec.quick_circle_debug_qc_trg_m", "Qc Trg M", base.HEX)
f.quick_circle_debug_qc_trg_f = ProtoField.uint8 ("dji_mavic_flyrec.quick_circle_debug_qc_trg_f", "Qc Trg F", base.HEX)
f.quick_circle_debug_qc_pre_trs = ProtoField.float ("dji_mavic_flyrec.quick_circle_debug_qc_pre_trs", "Qc Pre Trs", base.DEC)
f.quick_circle_debug_qc_cur_trs = ProtoField.float ("dji_mavic_flyrec.quick_circle_debug_qc_cur_trs", "Qc Cur Trs", base.DEC)
f.quick_circle_debug_qc_tgt_trs = ProtoField.float ("dji_mavic_flyrec.quick_circle_debug_qc_tgt_trs", "Qc Tgt Trs", base.DEC)
f.quick_circle_debug_qc_t = ProtoField.float ("dji_mavic_flyrec.quick_circle_debug_qc_t", "Qc T", base.DEC)
f.quick_circle_debug_gmb_mode = ProtoField.uint8 ("dji_mavic_flyrec.quick_circle_debug_gmb_mode", "Gmb Mode", base.HEX)
f.quick_circle_debug_gmb_refyaw = ProtoField.float ("dji_mavic_flyrec.quick_circle_debug_gmb_refyaw", "Gmb Refyaw", base.DEC)

local function flightrec_quick_circle_debug_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.quick_circle_debug_qc_trg_a, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.quick_circle_debug_qc_trg_m, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.quick_circle_debug_qc_trg_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.quick_circle_debug_qc_pre_trs, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.quick_circle_debug_qc_cur_trs, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.quick_circle_debug_qc_tgt_trs, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.quick_circle_debug_qc_t, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.quick_circle_debug_gmb_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.quick_circle_debug_gmb_refyaw, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 24) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Quick Circle Debug: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Quick Circle Debug: Payload size different than expected") end
end

-- Flight log - Battery Info 3 - 0x4e28

f.battery_info_3_avg_i = ProtoField.float ("dji_mavic_flyrec.battery_info_3_avg_i", "Avg I", base.DEC)
f.battery_info_3_fake_sbat = ProtoField.uint8 ("dji_mavic_flyrec.battery_info_3_fake_sbat", "Fake Sbat", base.HEX)
f.battery_info_3_esc_power = ProtoField.float ("dji_mavic_flyrec.battery_info_3_esc_power", "Esc Power", base.DEC)
f.battery_info_3_power_err = ProtoField.float ("dji_mavic_flyrec.battery_info_3_power_err", "Power Err", base.DEC)
f.battery_info_3_is_true = ProtoField.uint8 ("dji_mavic_flyrec.battery_info_3_is_true", "Is True", base.HEX)
f.battery_info_3_m_s_d = ProtoField.uint8 ("dji_mavic_flyrec.battery_info_3_m_s_d", "M S D", base.HEX)
f.battery_info_3_p_r_max = ProtoField.float ("dji_mavic_flyrec.battery_info_3_p_r_max", "P R Max", base.DEC)
f.battery_info_3_p_ave = ProtoField.float ("dji_mavic_flyrec.battery_info_3_p_ave", "P Ave", base.DEC)
f.battery_info_3_p_r_min = ProtoField.float ("dji_mavic_flyrec.battery_info_3_p_r_min", "P R Min", base.DEC)

local function flightrec_battery_info_3_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.battery_info_3_avg_i, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_3_fake_sbat, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_info_3_esc_power, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_3_power_err, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_3_is_true, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_info_3_m_s_d, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.battery_info_3_p_r_max, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_3_p_ave, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.battery_info_3_p_r_min, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 27) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Battery Info 3: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Battery Info 3: Payload size different than expected") end
end

-- Flight log - Rc Func Data - 0x4e29

f.rc_func_data_a = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_a", "A", base.DEC)
f.rc_func_data_e = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_e", "E", base.DEC)
f.rc_func_data_t = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_t", "T", base.DEC)
f.rc_func_data_r = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_r", "R", base.DEC)
f.rc_func_data_u = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_u", "U", base.DEC)
f.rc_func_data_u_f = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_u_f", "U F", base.DEC)
f.rc_func_data_gear = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_gear", "Gear", base.DEC)
f.rc_func_data_gh_sq = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_gh_sq", "Gh Sq", base.DEC)
f.rc_func_data_gh_sw = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_gh_sw", "Gh Sw", base.DEC)
f.rc_func_data_em_mode = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_em_mode", "Em Mode", base.DEC)
f.rc_func_data_em_stop = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_em_stop", "Em Stop", base.DEC)
f.rc_func_data_p_stop = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_p_stop", "P Stop", base.DEC)
f.rc_func_data_ioc = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_ioc", "Ioc", base.DEC)
f.rc_func_data_k1 = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_k1", "K1", base.DEC)
f.rc_func_data_k2 = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_k2", "K2", base.DEC)
f.rc_func_data_k3 = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_k3", "K3", base.DEC)
f.rc_func_data_k4 = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_k4", "K4", base.DEC)
f.rc_func_data_k5 = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_k5", "K5", base.DEC)
f.rc_func_data_k6 = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_k6", "K6", base.DEC)
f.rc_func_data_d1 = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_d1", "D1", base.DEC)
f.rc_func_data_d2 = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_d2", "D2", base.DEC)
f.rc_func_data_d3 = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_d3", "D3", base.DEC)
f.rc_func_data_d4 = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_d4", "D4", base.DEC)
f.rc_func_data_d5 = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_d5", "D5", base.DEC)
f.rc_func_data_d6 = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_d6", "D6", base.DEC)
f.rc_func_data_d7 = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_d7", "D7", base.DEC)
f.rc_func_data_d8 = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_d8", "D8", base.DEC)
f.rc_func_data_f_left = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_f_left", "F Left", base.DEC)
f.rc_func_data_f_right = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_f_right", "F Right", base.DEC)
f.rc_func_data_f_set_a = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_f_set_a", "F Set A", base.DEC)
f.rc_func_data_f_set_b = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_f_set_b", "F Set B", base.DEC)
f.rc_func_data_f_set_ab = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_f_set_ab", "F Set Ab", base.DEC)
f.rc_func_data_f_m_s = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_f_m_s", "F M S", base.DEC)
f.rc_func_data_f_f_s = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_f_f_s", "F F S", base.DEC)
f.rc_func_data_f_mode = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_f_mode", "F Mode", base.DEC)
f.rc_func_data_rc_c1 = ProtoField.int16 ("dji_mavic_flyrec.rc_func_data_rc_c1", "Rc C1", base.DEC)

local function flightrec_rc_func_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.rc_func_data_a, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_e, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_t, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_r, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_u, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_u_f, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_gear, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_gh_sq, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_gh_sw, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_em_mode, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_em_stop, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_p_stop, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_ioc, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_k1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_k2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_k3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_k4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_k5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_k6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_d1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_d2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_d3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_d4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_d5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_d6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_d7, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_d8, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_f_left, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_f_right, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_f_set_a, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_f_set_b, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_f_set_ab, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_f_m_s, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_f_f_s, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_f_mode, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_func_data_rc_c1, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 72) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Rc Func Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Rc Func Data: Payload size different than expected") end
end

-- Flight log - Rc Func State - 0x4e2a

f.rc_func_state_a = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_a", "A", base.HEX)
f.rc_func_state_e = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_e", "E", base.HEX)
f.rc_func_state_t = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_t", "T", base.HEX)
f.rc_func_state_r = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_r", "R", base.HEX)
f.rc_func_state_u = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_u", "U", base.HEX)
f.rc_func_state_u_f = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_u_f", "U F", base.HEX)
f.rc_func_state_gear = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_gear", "Gear", base.HEX)
f.rc_func_state_gh_sq = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_gh_sq", "Gh Sq", base.HEX)
f.rc_func_state_gh_sw = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_gh_sw", "Gh Sw", base.HEX)
f.rc_func_state_em_mode = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_em_mode", "Em Mode", base.HEX)
f.rc_func_state_em_stop = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_em_stop", "Em Stop", base.HEX)
f.rc_func_state_p_stop = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_p_stop", "P Stop", base.HEX)
f.rc_func_state__ioc = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state__ioc", " Ioc", base.HEX)
f.rc_func_state_k1 = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_k1", "K1", base.HEX)
f.rc_func_state_k2 = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_k2", "K2", base.HEX)
f.rc_func_state_k3 = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_k3", "K3", base.HEX)
f.rc_func_state_k4 = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_k4", "K4", base.HEX)
f.rc_func_state_k5 = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_k5", "K5", base.HEX)
f.rc_func_state_k6 = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_k6", "K6", base.HEX)
f.rc_func_state_d1 = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_d1", "D1", base.HEX)
f.rc_func_state_d2 = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_d2", "D2", base.HEX)
f.rc_func_state_d3 = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_d3", "D3", base.HEX)
f.rc_func_state_d4 = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_d4", "D4", base.HEX)
f.rc_func_state_d5 = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_d5", "D5", base.HEX)
f.rc_func_state_d6 = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_d6", "D6", base.HEX)
f.rc_func_state_d7 = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_d7", "D7", base.HEX)
f.rc_func_state_d8 = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_d8", "D8", base.HEX)
f.rc_func_state_f_left = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_f_left", "F Left", base.HEX)
f.rc_func_state_f_right = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_f_right", "F Right", base.HEX)
f.rc_func_state_f_set_a = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_f_set_a", "F Set A", base.HEX)
f.rc_func_state_f_set_b = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_f_set_b", "F Set B", base.HEX)
f.rc_func_state_f_set_ab = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_f_set_ab", "F Set Ab", base.HEX)
f.rc_func_state_f_m_s = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_f_m_s", "F M S", base.HEX)
f.rc_func_state_f_flow_speed = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_f_flow_speed", "F Flow Speed", base.HEX)
f.rc_func_state_f_mode = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_f_mode", "F Mode", base.HEX)
f.rc_func_state_s_rc_c1 = ProtoField.uint8 ("dji_mavic_flyrec.rc_func_state_s_rc_c1", "S Rc C1", base.HEX)

local function flightrec_rc_func_state_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.rc_func_state_a, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_e, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_t, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_r, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_u, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_u_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_gear, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_gh_sq, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_gh_sw, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_em_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_em_stop, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_p_stop, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state__ioc, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_k1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_k2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_k3, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_k4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_k5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_k6, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_d1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_d2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_d3, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_d4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_d5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_d6, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_d7, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_d8, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_f_left, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_f_right, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_f_set_a, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_f_set_b, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_f_set_ab, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_f_m_s, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_f_flow_speed, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_f_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_func_state_s_rc_c1, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 36) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Rc Func State: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Rc Func State: Payload size different than expected") end
end

-- Flight log - Gps Monitor 1 - 0x4e2b

f.gps_monitor_1_le = ProtoField.uint32 ("dji_mavic_flyrec.gps_monitor_1_le", "Le", base.HEX)
f.gps_monitor_1_dysed = ProtoField.uint32 ("dji_mavic_flyrec.gps_monitor_1_dysed", "Dysed", base.HEX)
f.gps_monitor_1_sfe = ProtoField.uint32 ("dji_mavic_flyrec.gps_monitor_1_sfe", "Sfe", base.HEX)
f.gps_monitor_1_dft = ProtoField.uint32 ("dji_mavic_flyrec.gps_monitor_1_dft", "Dft", base.HEX)
f.gps_monitor_1_smc = ProtoField.uint32 ("dji_mavic_flyrec.gps_monitor_1_smc", "Smc", base.HEX)

local function flightrec_gps_monitor_1_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.gps_monitor_1_le, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_monitor_1_dysed, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_monitor_1_sfe, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_monitor_1_dft, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_monitor_1_smc, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gps Monitor 1: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gps Monitor 1: Payload size different than expected") end
end

-- Flight log - Gps Monitor 2 - 0x4e2c

f.gps_monitor_2_le = ProtoField.uint32 ("dji_mavic_flyrec.gps_monitor_2_le", "Le", base.HEX)
f.gps_monitor_2_dysed = ProtoField.uint32 ("dji_mavic_flyrec.gps_monitor_2_dysed", "Dysed", base.HEX)
f.gps_monitor_2_sfe = ProtoField.uint32 ("dji_mavic_flyrec.gps_monitor_2_sfe", "Sfe", base.HEX)
f.gps_monitor_2_dft = ProtoField.uint32 ("dji_mavic_flyrec.gps_monitor_2_dft", "Dft", base.HEX)
f.gps_monitor_2_smc = ProtoField.uint32 ("dji_mavic_flyrec.gps_monitor_2_smc", "Smc", base.HEX)

local function flightrec_gps_monitor_2_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.gps_monitor_2_le, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_monitor_2_dysed, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_monitor_2_sfe, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_monitor_2_dft, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_monitor_2_smc, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gps Monitor 2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gps Monitor 2: Payload size different than expected") end
end

-- Flight log - Gps Monitor 3 - 0x4e2d

f.gps_monitor_3_le = ProtoField.uint32 ("dji_mavic_flyrec.gps_monitor_3_le", "Le", base.HEX)
f.gps_monitor_3_dysed = ProtoField.uint32 ("dji_mavic_flyrec.gps_monitor_3_dysed", "Dysed", base.HEX)
f.gps_monitor_3_sfe = ProtoField.uint32 ("dji_mavic_flyrec.gps_monitor_3_sfe", "Sfe", base.HEX)
f.gps_monitor_3_dft = ProtoField.uint32 ("dji_mavic_flyrec.gps_monitor_3_dft", "Dft", base.HEX)
f.gps_monitor_3_smc = ProtoField.uint32 ("dji_mavic_flyrec.gps_monitor_3_smc", "Smc", base.HEX)

local function flightrec_gps_monitor_3_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.gps_monitor_3_le, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_monitor_3_dysed, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_monitor_3_sfe, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_monitor_3_dft, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gps_monitor_3_smc, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gps Monitor 3: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gps Monitor 3: Payload size different than expected") end
end

-- Flight log - Adaptive Roll - 0x0883

f.adaptive_roll_omega = ProtoField.float ("dji_mavic_flyrec.adaptive_roll_omega", "Omega", base.DEC)
f.adaptive_roll_sigma = ProtoField.float ("dji_mavic_flyrec.adaptive_roll_sigma", "Sigma", base.DEC)
f.adaptive_roll_theta0 = ProtoField.float ("dji_mavic_flyrec.adaptive_roll_theta0", "Theta0", base.DEC)
f.adaptive_roll_theta1 = ProtoField.float ("dji_mavic_flyrec.adaptive_roll_theta1", "Theta1", base.DEC)
f.adaptive_roll_xref0 = ProtoField.float ("dji_mavic_flyrec.adaptive_roll_xref0", "Xref0", base.DEC)
f.adaptive_roll_xref1 = ProtoField.float ("dji_mavic_flyrec.adaptive_roll_xref1", "Xref1", base.DEC)
f.adaptive_roll_u = ProtoField.float ("dji_mavic_flyrec.adaptive_roll_u", "U", base.DEC)

local function flightrec_adaptive_roll_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.adaptive_roll_omega, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adaptive_roll_sigma, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adaptive_roll_theta0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adaptive_roll_theta1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adaptive_roll_xref0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adaptive_roll_xref1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adaptive_roll_u, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 28) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Adaptive Roll: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Adaptive Roll: Payload size different than expected") end
end

-- Flight log - Adaptive Pitch - 0x0884

f.adaptive_pitch_omega = ProtoField.float ("dji_mavic_flyrec.adaptive_pitch_omega", "Omega", base.DEC)
f.adaptive_pitch_sigma = ProtoField.float ("dji_mavic_flyrec.adaptive_pitch_sigma", "Sigma", base.DEC)
f.adaptive_pitch_theta0 = ProtoField.float ("dji_mavic_flyrec.adaptive_pitch_theta0", "Theta0", base.DEC)
f.adaptive_pitch_theta1 = ProtoField.float ("dji_mavic_flyrec.adaptive_pitch_theta1", "Theta1", base.DEC)
f.adaptive_pitch_xref0 = ProtoField.float ("dji_mavic_flyrec.adaptive_pitch_xref0", "Xref0", base.DEC)
f.adaptive_pitch_xref1 = ProtoField.float ("dji_mavic_flyrec.adaptive_pitch_xref1", "Xref1", base.DEC)
f.adaptive_pitch_u = ProtoField.float ("dji_mavic_flyrec.adaptive_pitch_u", "U", base.DEC)

local function flightrec_adaptive_pitch_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.adaptive_pitch_omega, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adaptive_pitch_sigma, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adaptive_pitch_theta0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adaptive_pitch_theta1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adaptive_pitch_xref0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adaptive_pitch_xref1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adaptive_pitch_u, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 28) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Adaptive Pitch: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Adaptive Pitch: Payload size different than expected") end
end

-- Flight log - Fw G Api - 0x0885

f.fw_g_api_tgt_w0 = ProtoField.float ("dji_mavic_flyrec.fw_g_api_tgt_w0", "Tgt W0", base.DEC)
f.fw_g_api_tgt_w1 = ProtoField.float ("dji_mavic_flyrec.fw_g_api_tgt_w1", "Tgt W1", base.DEC)
f.fw_g_api_tgt_w2 = ProtoField.float ("dji_mavic_flyrec.fw_g_api_tgt_w2", "Tgt W2", base.DEC)
f.fw_g_api_yaw_type = ProtoField.uint8 ("dji_mavic_flyrec.fw_g_api_yaw_type", "Yaw Type", base.HEX)
f.fw_g_api_ctrl_mode = ProtoField.uint8 ("dji_mavic_flyrec.fw_g_api_ctrl_mode", "Ctrl Mode", base.HEX)
f.fw_g_api_atti_mode = ProtoField.uint8 ("dji_mavic_flyrec.fw_g_api_atti_mode", "Atti Mode", base.HEX)
f.fw_g_api_cmd_roll = ProtoField.float ("dji_mavic_flyrec.fw_g_api_cmd_roll", "Cmd Roll", base.DEC)
f.fw_g_api_cmd_pitch = ProtoField.float ("dji_mavic_flyrec.fw_g_api_cmd_pitch", "Cmd Pitch", base.DEC)
f.fw_g_api_cmd_yaw = ProtoField.float ("dji_mavic_flyrec.fw_g_api_cmd_yaw", "Cmd Yaw", base.DEC)

local function flightrec_fw_g_api_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.fw_g_api_tgt_w0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fw_g_api_tgt_w1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fw_g_api_tgt_w2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fw_g_api_yaw_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.fw_g_api_ctrl_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.fw_g_api_atti_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.fw_g_api_cmd_roll, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fw_g_api_cmd_pitch, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fw_g_api_cmd_yaw, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 27) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Fw G Api: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Fw G Api: Payload size different than expected") end
end

-- Flight log - Fw Param Ekf - 0x0887

f.fw_param_ekf_energyest = ProtoField.float ("dji_mavic_flyrec.fw_param_ekf_energyest", "Energyest", base.DEC)
f.fw_param_ekf_cd0est = ProtoField.float ("dji_mavic_flyrec.fw_param_ekf_cd0est", "Cd0Est", base.DEC)
f.fw_param_ekf_clest = ProtoField.float ("dji_mavic_flyrec.fw_param_ekf_clest", "Clest", base.DEC)
f.fw_param_ekf_aest = ProtoField.float ("dji_mavic_flyrec.fw_param_ekf_aest", "Aest", base.DEC)
f.fw_param_ekf_best = ProtoField.float ("dji_mavic_flyrec.fw_param_ekf_best", "Best", base.DEC)
f.fw_param_ekf_nest = ProtoField.float ("dji_mavic_flyrec.fw_param_ekf_nest", "Nest", base.DEC)
f.fw_param_ekf_yacc0 = ProtoField.float ("dji_mavic_flyrec.fw_param_ekf_yacc0", "Yacc0", base.DEC)
f.fw_param_ekf_yacc1 = ProtoField.float ("dji_mavic_flyrec.fw_param_ekf_yacc1", "Yacc1", base.DEC)
f.fw_param_ekf_yacc2 = ProtoField.float ("dji_mavic_flyrec.fw_param_ekf_yacc2", "Yacc2", base.DEC)
f.fw_param_ekf_yenergy = ProtoField.float ("dji_mavic_flyrec.fw_param_ekf_yenergy", "Yenergy", base.DEC)
f.fw_param_ekf_yu = ProtoField.float ("dji_mavic_flyrec.fw_param_ekf_yu", "Yu", base.DEC)

local function flightrec_fw_param_ekf_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.fw_param_ekf_energyest, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fw_param_ekf_cd0est, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fw_param_ekf_clest, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fw_param_ekf_aest, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fw_param_ekf_best, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fw_param_ekf_nest, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fw_param_ekf_yacc0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fw_param_ekf_yacc1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fw_param_ekf_yacc2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fw_param_ekf_yenergy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.fw_param_ekf_yu, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 44) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Fw Param Ekf: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Fw Param Ekf: Payload size different than expected") end
end

-- Flight log - Ex Raw Airspeed - 0x27e2

f.ex_raw_airspeed_diff_press = ProtoField.float ("dji_mavic_flyrec.ex_raw_airspeed_diff_press", "Diff Press", base.DEC)
f.ex_raw_airspeed_temp = ProtoField.float ("dji_mavic_flyrec.ex_raw_airspeed_temp", "Temp", base.DEC)
f.ex_raw_airspeed_cnt = ProtoField.uint32 ("dji_mavic_flyrec.ex_raw_airspeed_cnt", "Cnt", base.HEX)

local function flightrec_ex_raw_airspeed_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ex_raw_airspeed_diff_press, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ex_raw_airspeed_temp, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ex_raw_airspeed_cnt, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 12) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ex Raw Airspeed: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ex Raw Airspeed: Payload size different than expected") end
end

-- Flight log - Vibrate Detect Gyro - 0x5000

f.vibrate_detect_gyro_x_amp = ProtoField.float ("dji_mavic_flyrec.vibrate_detect_gyro_x_amp", "X Amp", base.DEC)
f.vibrate_detect_gyro_y_amp = ProtoField.float ("dji_mavic_flyrec.vibrate_detect_gyro_y_amp", "Y Amp", base.DEC)
f.vibrate_detect_gyro_freq = ProtoField.float ("dji_mavic_flyrec.vibrate_detect_gyro_freq", "Freq", base.DEC)
f.vibrate_detect_gyro_len = ProtoField.uint16 ("dji_mavic_flyrec.vibrate_detect_gyro_len", "Len", base.HEX)
f.vibrate_detect_gyro_fs = ProtoField.uint16 ("dji_mavic_flyrec.vibrate_detect_gyro_fs", "Fs", base.HEX)
f.vibrate_detect_gyro_enable = ProtoField.uint8 ("dji_mavic_flyrec.vibrate_detect_gyro_enable", "Enable", base.HEX)
f.vibrate_detect_gyro_flag = ProtoField.uint8 ("dji_mavic_flyrec.vibrate_detect_gyro_flag", "Flag", base.HEX)
f.vibrate_detect_gyro_x0 = ProtoField.float ("dji_mavic_flyrec.vibrate_detect_gyro_x0", "X0", base.DEC)
f.vibrate_detect_gyro_x1 = ProtoField.float ("dji_mavic_flyrec.vibrate_detect_gyro_x1", "X1", base.DEC)
f.vibrate_detect_gyro_x2 = ProtoField.float ("dji_mavic_flyrec.vibrate_detect_gyro_x2", "X2", base.DEC)
f.vibrate_detect_gyro_y0 = ProtoField.float ("dji_mavic_flyrec.vibrate_detect_gyro_y0", "Y0", base.DEC)
f.vibrate_detect_gyro_y1 = ProtoField.float ("dji_mavic_flyrec.vibrate_detect_gyro_y1", "Y1", base.DEC)
f.vibrate_detect_gyro_y2 = ProtoField.float ("dji_mavic_flyrec.vibrate_detect_gyro_y2", "Y2", base.DEC)

local function flightrec_vibrate_detect_gyro_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.vibrate_detect_gyro_x_amp, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vibrate_detect_gyro_y_amp, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vibrate_detect_gyro_freq, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vibrate_detect_gyro_len, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.vibrate_detect_gyro_fs, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.vibrate_detect_gyro_enable, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vibrate_detect_gyro_flag, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.vibrate_detect_gyro_x0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vibrate_detect_gyro_x1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vibrate_detect_gyro_x2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vibrate_detect_gyro_y0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vibrate_detect_gyro_y1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.vibrate_detect_gyro_y2, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 42) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Vibrate Detect Gyro: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Vibrate Detect Gyro: Payload size different than expected") end
end

-- Flight log - Airprot Limit Data - 0x500a

f.airprot_limit_data_ap_disable = ProtoField.uint8 ("dji_mavic_flyrec.airprot_limit_data_ap_disable", "Ap Disable", base.HEX)
f.airprot_limit_data_pos_en = ProtoField.uint8 ("dji_mavic_flyrec.airprot_limit_data_pos_en", "Pos En", base.HEX)
f.airprot_limit_data_wl_en = ProtoField.uint8 ("dji_mavic_flyrec.airprot_limit_data_wl_en", "Wl En", base.HEX)
f.airprot_limit_data_wl_s = ProtoField.uint8 ("dji_mavic_flyrec.airprot_limit_data_wl_s", "Wl S", base.HEX)
f.airprot_limit_data_g_en = ProtoField.uint8 ("dji_mavic_flyrec.airprot_limit_data_g_en", "G En", base.HEX)
f.airprot_limit_data_g_s = ProtoField.uint8 ("dji_mavic_flyrec.airprot_limit_data_g_s", "G S", base.HEX)
f.airprot_limit_data_t_en = ProtoField.uint8 ("dji_mavic_flyrec.airprot_limit_data_t_en", "T En", base.HEX)
f.airprot_limit_data_t_s = ProtoField.uint8 ("dji_mavic_flyrec.airprot_limit_data_t_s", "T S", base.HEX)
f.airprot_limit_data_f_s = ProtoField.uint8 ("dji_mavic_flyrec.airprot_limit_data_f_s", "F S", base.HEX)
f.airprot_limit_data_1f_dir = ProtoField.float ("dji_mavic_flyrec.airprot_limit_data_1f_dir", "1F Dir", base.DEC)
f.airprot_limit_data_1f_dir = ProtoField.float ("dji_mavic_flyrec.airprot_limit_data_1f_dir", "1F Dir", base.DEC)
f.airprot_limit_data_1f_hi_en = ProtoField.uint8 ("dji_mavic_flyrec.airprot_limit_data_1f_hi_en", "1F Hi En", base.HEX)
f.airprot_limit_data_1f_d2hi = ProtoField.float ("dji_mavic_flyrec.airprot_limit_data_1f_d2hi", "1F D2Hi", base.DEC)
f.airprot_limit_data_1f_r_en = ProtoField.uint8 ("dji_mavic_flyrec.airprot_limit_data_1f_r_en", "1F R En", base.HEX)
f.airprot_limit_data_1f_d2r = ProtoField.float ("dji_mavic_flyrec.airprot_limit_data_1f_d2r", "1F D2R", base.DEC)
f.airprot_limit_data_2f_dir = ProtoField.float ("dji_mavic_flyrec.airprot_limit_data_2f_dir", "2F Dir", base.DEC)
f.airprot_limit_data_2f_dir = ProtoField.float ("dji_mavic_flyrec.airprot_limit_data_2f_dir", "2F Dir", base.DEC)
f.airprot_limit_data_2f_hi_en = ProtoField.uint8 ("dji_mavic_flyrec.airprot_limit_data_2f_hi_en", "2F Hi En", base.HEX)
f.airprot_limit_data_2f_d2hi = ProtoField.float ("dji_mavic_flyrec.airprot_limit_data_2f_d2hi", "2F D2Hi", base.DEC)
f.airprot_limit_data_2f_r_en = ProtoField.uint8 ("dji_mavic_flyrec.airprot_limit_data_2f_r_en", "2F R En", base.HEX)
f.airprot_limit_data_2f_d2r = ProtoField.float ("dji_mavic_flyrec.airprot_limit_data_2f_d2r", "2F D2R", base.DEC)
f.airprot_limit_data_3f_dir = ProtoField.float ("dji_mavic_flyrec.airprot_limit_data_3f_dir", "3F Dir", base.DEC)
f.airprot_limit_data_3f_dir = ProtoField.float ("dji_mavic_flyrec.airprot_limit_data_3f_dir", "3F Dir", base.DEC)
f.airprot_limit_data_3f_hi_en = ProtoField.uint8 ("dji_mavic_flyrec.airprot_limit_data_3f_hi_en", "3F Hi En", base.HEX)
f.airprot_limit_data_3f_d2hi = ProtoField.float ("dji_mavic_flyrec.airprot_limit_data_3f_d2hi", "3F D2Hi", base.DEC)
f.airprot_limit_data_3f_r_en = ProtoField.uint8 ("dji_mavic_flyrec.airprot_limit_data_3f_r_en", "3F R En", base.HEX)
f.airprot_limit_data_3f_d2r = ProtoField.float ("dji_mavic_flyrec.airprot_limit_data_3f_d2r", "3F D2R", base.DEC)
f.airprot_limit_data_height_limit = ProtoField.float ("dji_mavic_flyrec.airprot_limit_data_height_limit", "Height Limit", base.DEC)

local function flightrec_airprot_limit_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.airprot_limit_data_ap_disable, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airprot_limit_data_pos_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airprot_limit_data_wl_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airprot_limit_data_wl_s, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airprot_limit_data_g_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airprot_limit_data_g_s, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airprot_limit_data_t_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airprot_limit_data_t_s, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airprot_limit_data_f_s, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airprot_limit_data_1f_dir, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airprot_limit_data_1f_dir, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airprot_limit_data_1f_hi_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airprot_limit_data_1f_d2hi, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airprot_limit_data_1f_r_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airprot_limit_data_1f_d2r, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airprot_limit_data_2f_dir, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airprot_limit_data_2f_dir, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airprot_limit_data_2f_hi_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airprot_limit_data_2f_d2hi, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airprot_limit_data_2f_r_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airprot_limit_data_2f_d2r, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airprot_limit_data_3f_dir, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airprot_limit_data_3f_dir, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airprot_limit_data_3f_hi_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airprot_limit_data_3f_d2hi, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airprot_limit_data_3f_r_en, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.airprot_limit_data_3f_d2r, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.airprot_limit_data_height_limit, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 67) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Airprot Limit Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Airprot Limit Data: Payload size different than expected") end
end

-- Flight log - Adv Fl Limit Data - 0x500b

f.adv_fl_limit_data_rec_cnt = ProtoField.uint32 ("dji_mavic_flyrec.adv_fl_limit_data_rec_cnt", "Rec Cnt", base.HEX)
f.adv_fl_limit_data_num = ProtoField.uint8 ("dji_mavic_flyrec.adv_fl_limit_data_num", "Num", base.HEX)
f.adv_fl_limit_data_in_warn_zone = ProtoField.uint8 ("dji_mavic_flyrec.adv_fl_limit_data_in_warn_zone", "In Warn Zone", base.HEX)
f.adv_fl_limit_data_nearest_nfz_dis = ProtoField.uint16 ("dji_mavic_flyrec.adv_fl_limit_data_nearest_nfz_dis", "Nearest Nfz Dis", base.HEX)
f.adv_fl_limit_data_rsv = ProtoField.uint32 ("dji_mavic_flyrec.adv_fl_limit_data_rsv", "Rsv", base.HEX)
f.adv_fl_limit_data_0uuid = ProtoField.uint32 ("dji_mavic_flyrec.adv_fl_limit_data_0uuid", "0Uuid", base.HEX)
f.adv_fl_limit_data_0in_limt_area = ProtoField.uint8 ("dji_mavic_flyrec.adv_fl_limit_data_0in_limt_area", "0In Limt Area", base.HEX)
f.adv_fl_limit_data_0n = ProtoField.float ("dji_mavic_flyrec.adv_fl_limit_data_0n", "0N", base.DEC)
f.adv_fl_limit_data_0e = ProtoField.float ("dji_mavic_flyrec.adv_fl_limit_data_0e", "0E", base.DEC)
f.adv_fl_limit_data_0hight_limit = ProtoField.uint16 ("dji_mavic_flyrec.adv_fl_limit_data_0hight_limit", "0Hight Limit", base.HEX)
f.adv_fl_limit_data_1uuid = ProtoField.uint32 ("dji_mavic_flyrec.adv_fl_limit_data_1uuid", "1Uuid", base.HEX)
f.adv_fl_limit_data_1in_limt_area = ProtoField.uint8 ("dji_mavic_flyrec.adv_fl_limit_data_1in_limt_area", "1In Limt Area", base.HEX)
f.adv_fl_limit_data_1n = ProtoField.float ("dji_mavic_flyrec.adv_fl_limit_data_1n", "1N", base.DEC)
f.adv_fl_limit_data_1e = ProtoField.float ("dji_mavic_flyrec.adv_fl_limit_data_1e", "1E", base.DEC)
f.adv_fl_limit_data_1hight_limit = ProtoField.uint16 ("dji_mavic_flyrec.adv_fl_limit_data_1hight_limit", "1Hight Limit", base.HEX)
f.adv_fl_limit_data_2uuid = ProtoField.uint32 ("dji_mavic_flyrec.adv_fl_limit_data_2uuid", "2Uuid", base.HEX)
f.adv_fl_limit_data_2in_limt_area = ProtoField.uint8 ("dji_mavic_flyrec.adv_fl_limit_data_2in_limt_area", "2In Limt Area", base.HEX)
f.adv_fl_limit_data_2n = ProtoField.float ("dji_mavic_flyrec.adv_fl_limit_data_2n", "2N", base.DEC)
f.adv_fl_limit_data_2e = ProtoField.float ("dji_mavic_flyrec.adv_fl_limit_data_2e", "2E", base.DEC)
f.adv_fl_limit_data_2hight_limit = ProtoField.uint16 ("dji_mavic_flyrec.adv_fl_limit_data_2hight_limit", "2Hight Limit", base.HEX)
f.adv_fl_limit_data_3uuid = ProtoField.uint32 ("dji_mavic_flyrec.adv_fl_limit_data_3uuid", "3Uuid", base.HEX)
f.adv_fl_limit_data_3in_limt_area = ProtoField.uint8 ("dji_mavic_flyrec.adv_fl_limit_data_3in_limt_area", "3In Limt Area", base.HEX)
f.adv_fl_limit_data_3n = ProtoField.float ("dji_mavic_flyrec.adv_fl_limit_data_3n", "3N", base.DEC)
f.adv_fl_limit_data_3e = ProtoField.float ("dji_mavic_flyrec.adv_fl_limit_data_3e", "3E", base.DEC)
f.adv_fl_limit_data_3hight_limit = ProtoField.uint16 ("dji_mavic_flyrec.adv_fl_limit_data_3hight_limit", "3Hight Limit", base.HEX)
f.adv_fl_limit_data_4uuid = ProtoField.uint32 ("dji_mavic_flyrec.adv_fl_limit_data_4uuid", "4Uuid", base.HEX)
f.adv_fl_limit_data_4in_limt_area = ProtoField.uint8 ("dji_mavic_flyrec.adv_fl_limit_data_4in_limt_area", "4In Limt Area", base.HEX)
f.adv_fl_limit_data_4n = ProtoField.float ("dji_mavic_flyrec.adv_fl_limit_data_4n", "4N", base.DEC)
f.adv_fl_limit_data_4e = ProtoField.float ("dji_mavic_flyrec.adv_fl_limit_data_4e", "4E", base.DEC)
f.adv_fl_limit_data_4hight_limit = ProtoField.uint16 ("dji_mavic_flyrec.adv_fl_limit_data_4hight_limit", "4Hight Limit", base.HEX)

local function flightrec_adv_fl_limit_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.adv_fl_limit_data_rec_cnt, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adv_fl_limit_data_num, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_fl_limit_data_in_warn_zone, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_fl_limit_data_nearest_nfz_dis, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.adv_fl_limit_data_rsv, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adv_fl_limit_data_0uuid, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adv_fl_limit_data_0in_limt_area, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_fl_limit_data_0n, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adv_fl_limit_data_0e, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adv_fl_limit_data_0hight_limit, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.adv_fl_limit_data_1uuid, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adv_fl_limit_data_1in_limt_area, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_fl_limit_data_1n, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adv_fl_limit_data_1e, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adv_fl_limit_data_1hight_limit, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.adv_fl_limit_data_2uuid, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adv_fl_limit_data_2in_limt_area, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_fl_limit_data_2n, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adv_fl_limit_data_2e, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adv_fl_limit_data_2hight_limit, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.adv_fl_limit_data_3uuid, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adv_fl_limit_data_3in_limt_area, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_fl_limit_data_3n, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adv_fl_limit_data_3e, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adv_fl_limit_data_3hight_limit, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.adv_fl_limit_data_4uuid, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adv_fl_limit_data_4in_limt_area, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adv_fl_limit_data_4n, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adv_fl_limit_data_4e, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adv_fl_limit_data_4hight_limit, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 87) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Adv Fl Limit Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Adv Fl Limit Data: Payload size different than expected") end
end

-- Flight log - Db Subscription - 0x0888

f.db_subscription_tick_b = ProtoField.uint32 ("dji_mavic_flyrec.db_subscription_tick_b", "Tick B", base.HEX)
f.db_subscription_sent_gps_lv = ProtoField.uint8 ("dji_mavic_flyrec.db_subscription_sent_gps_lv", "Sent Gps Lv", base.HEX)

local function flightrec_db_subscription_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.db_subscription_tick_b, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.db_subscription_sent_gps_lv, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Db Subscription: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Db Subscription: Payload size different than expected") end
end

-- Flight log - Lost Sats Go Home Send Package - 0x504b

f.lost_sats_go_home_send_package_cmd_type = ProtoField.uint8 ("dji_mavic_flyrec.lost_sats_go_home_send_package_cmd_type", "Cmd Type", base.HEX)
f.lost_sats_go_home_send_package_act_type = ProtoField.uint8 ("dji_mavic_flyrec.lost_sats_go_home_send_package_act_type", "Act Type", base.HEX)
f.lost_sats_go_home_send_package_cnt_down = ProtoField.uint8 ("dji_mavic_flyrec.lost_sats_go_home_send_package_cnt_down", "Cnt Down", base.HEX)
f.lost_sats_go_home_send_package_cmd = ProtoField.uint8 ("dji_mavic_flyrec.lost_sats_go_home_send_package_cmd", "Cmd", base.HEX)
f.lost_sats_go_home_send_package_asap = ProtoField.uint8 ("dji_mavic_flyrec.lost_sats_go_home_send_package_asap", "Asap", base.HEX)
f.lost_sats_go_home_send_package_cancel = ProtoField.uint8 ("dji_mavic_flyrec.lost_sats_go_home_send_package_cancel", "Cancel", base.HEX)
f.lost_sats_go_home_send_package_lost_in_gh = ProtoField.uint8 ("dji_mavic_flyrec.lost_sats_go_home_send_package_lost_in_gh", "Lost In Gh", base.HEX)
f.lost_sats_go_home_send_package_has_req_gh = ProtoField.uint8 ("dji_mavic_flyrec.lost_sats_go_home_send_package_has_req_gh", "Has Req Gh", base.HEX)

local function flightrec_lost_sats_go_home_send_package_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.lost_sats_go_home_send_package_cmd_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.lost_sats_go_home_send_package_act_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.lost_sats_go_home_send_package_cnt_down, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.lost_sats_go_home_send_package_cmd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.lost_sats_go_home_send_package_asap, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.lost_sats_go_home_send_package_cancel, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.lost_sats_go_home_send_package_lost_in_gh, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.lost_sats_go_home_send_package_has_req_gh, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Lost Sats Go Home Send Package: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Lost Sats Go Home Send Package: Payload size different than expected") end
end

-- Flight log - Lost Sats Go Home Recv Package - 0x504c

f.lost_sats_go_home_recv_package_cmd_type = ProtoField.uint8 ("dji_mavic_flyrec.lost_sats_go_home_recv_package_cmd_type", "Cmd Type", base.HEX)
f.lost_sats_go_home_recv_package_act_type = ProtoField.uint8 ("dji_mavic_flyrec.lost_sats_go_home_recv_package_act_type", "Act Type", base.HEX)
f.lost_sats_go_home_recv_package_cnt_down = ProtoField.uint8 ("dji_mavic_flyrec.lost_sats_go_home_recv_package_cnt_down", "Cnt Down", base.HEX)
f.lost_sats_go_home_recv_package_cmd = ProtoField.uint8 ("dji_mavic_flyrec.lost_sats_go_home_recv_package_cmd", "Cmd", base.HEX)

local function flightrec_lost_sats_go_home_recv_package_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.lost_sats_go_home_recv_package_cmd_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.lost_sats_go_home_recv_package_act_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.lost_sats_go_home_recv_package_cnt_down, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.lost_sats_go_home_recv_package_cmd, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Lost Sats Go Home Recv Package: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Lost Sats Go Home Recv Package: Payload size different than expected") end
end

-- Flight log - Adsb Osd Info - 0x504d

f.adsb_osd_info_valid_flg = ProtoField.uint8 ("dji_mavic_flyrec.adsb_osd_info_valid_flg", "Valid Flg", base.HEX)
f.adsb_osd_info_latitude = ProtoField.int32 ("dji_mavic_flyrec.adsb_osd_info_latitude", "Latitude", base.DEC)
f.adsb_osd_info_longitude = ProtoField.int32 ("dji_mavic_flyrec.adsb_osd_info_longitude", "Longitude", base.DEC)
f.adsb_osd_info_alititude = ProtoField.int32 ("dji_mavic_flyrec.adsb_osd_info_alititude", "Alititude", base.DEC)

local function flightrec_adsb_osd_info_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.adsb_osd_info_valid_flg, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.adsb_osd_info_latitude, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adsb_osd_info_longitude, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.adsb_osd_info_alititude, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 13) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Adsb Osd Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Adsb Osd Info: Payload size different than expected") end
end

-- Flight log - Link Host - 0x092a

f.link_host_link_host_tx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.link_host_link_host_tx_bytes", "Link Host Tx Bytes", base.HEX)
f.link_host_link_host_rx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.link_host_link_host_rx_bytes", "Link Host Rx Bytes", base.HEX)
f.link_host_link_host_tx_packets = ProtoField.uint16 ("dji_mavic_flyrec.link_host_link_host_tx_packets", "Link Host Tx Packets", base.HEX)
f.link_host_link_host_rx_packets = ProtoField.uint16 ("dji_mavic_flyrec.link_host_link_host_rx_packets", "Link Host Rx Packets", base.HEX)
f.link_host_link_host_tx_errors = ProtoField.uint16 ("dji_mavic_flyrec.link_host_link_host_tx_errors", "Link Host Tx Errors", base.HEX)
f.link_host_link_host_rx_erros = ProtoField.uint16 ("dji_mavic_flyrec.link_host_link_host_rx_erros", "Link Host Rx Erros", base.HEX)
f.link_host_link_host_recv_route = ProtoField.uint16 ("dji_mavic_flyrec.link_host_link_host_recv_route", "Link Host Recv Route", base.HEX)
f.link_host_link_host_send_route = ProtoField.uint16 ("dji_mavic_flyrec.link_host_link_host_send_route", "Link Host Send Route", base.HEX)

local function flightrec_link_host_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.link_host_link_host_tx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.link_host_link_host_rx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.link_host_link_host_tx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_host_link_host_rx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_host_link_host_tx_errors, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_host_link_host_rx_erros, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_host_link_host_recv_route, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_host_link_host_send_route, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Link Host: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Link Host: Payload size different than expected") end
end

-- Flight log - Link Pc - 0x092b

f.link_pc_link_pc_tx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.link_pc_link_pc_tx_bytes", "Link Pc Tx Bytes", base.HEX)
f.link_pc_link_pc_rx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.link_pc_link_pc_rx_bytes", "Link Pc Rx Bytes", base.HEX)
f.link_pc_link_pc_tx_packets = ProtoField.uint16 ("dji_mavic_flyrec.link_pc_link_pc_tx_packets", "Link Pc Tx Packets", base.HEX)
f.link_pc_link_pc_rx_packets = ProtoField.uint16 ("dji_mavic_flyrec.link_pc_link_pc_rx_packets", "Link Pc Rx Packets", base.HEX)
f.link_pc_link_pc_tx_errors = ProtoField.uint16 ("dji_mavic_flyrec.link_pc_link_pc_tx_errors", "Link Pc Tx Errors", base.HEX)
f.link_pc_link_pc_rx_erros = ProtoField.uint16 ("dji_mavic_flyrec.link_pc_link_pc_rx_erros", "Link Pc Rx Erros", base.HEX)
f.link_pc_link_pc_recv_route = ProtoField.uint16 ("dji_mavic_flyrec.link_pc_link_pc_recv_route", "Link Pc Recv Route", base.HEX)
f.link_pc_link_pc_send_route = ProtoField.uint16 ("dji_mavic_flyrec.link_pc_link_pc_send_route", "Link Pc Send Route", base.HEX)

local function flightrec_link_pc_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.link_pc_link_pc_tx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.link_pc_link_pc_rx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.link_pc_link_pc_tx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_pc_link_pc_rx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_pc_link_pc_tx_errors, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_pc_link_pc_rx_erros, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_pc_link_pc_recv_route, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_pc_link_pc_send_route, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Link Pc: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Link Pc: Payload size different than expected") end
end

-- Flight log - Link Vo - 0x092c

f.link_vo_link_vo_tx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.link_vo_link_vo_tx_bytes", "Link Vo Tx Bytes", base.HEX)
f.link_vo_link_vo_rx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.link_vo_link_vo_rx_bytes", "Link Vo Rx Bytes", base.HEX)
f.link_vo_link_vo_tx_packets = ProtoField.uint16 ("dji_mavic_flyrec.link_vo_link_vo_tx_packets", "Link Vo Tx Packets", base.HEX)
f.link_vo_link_vo_rx_packets = ProtoField.uint16 ("dji_mavic_flyrec.link_vo_link_vo_rx_packets", "Link Vo Rx Packets", base.HEX)
f.link_vo_link_vo_tx_errors = ProtoField.uint16 ("dji_mavic_flyrec.link_vo_link_vo_tx_errors", "Link Vo Tx Errors", base.HEX)
f.link_vo_link_vo_rx_erros = ProtoField.uint16 ("dji_mavic_flyrec.link_vo_link_vo_rx_erros", "Link Vo Rx Erros", base.HEX)
f.link_vo_link_vo_recv_route = ProtoField.uint16 ("dji_mavic_flyrec.link_vo_link_vo_recv_route", "Link Vo Recv Route", base.HEX)
f.link_vo_link_vo_send_route = ProtoField.uint16 ("dji_mavic_flyrec.link_vo_link_vo_send_route", "Link Vo Send Route", base.HEX)

local function flightrec_link_vo_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.link_vo_link_vo_tx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.link_vo_link_vo_rx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.link_vo_link_vo_tx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_vo_link_vo_rx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_vo_link_vo_tx_errors, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_vo_link_vo_rx_erros, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_vo_link_vo_recv_route, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_vo_link_vo_send_route, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Link Vo: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Link Vo: Payload size different than expected") end
end

-- Flight log - Link Sdk - 0x092d

f.link_sdk_link_sdk_tx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.link_sdk_link_sdk_tx_bytes", "Link Sdk Tx Bytes", base.HEX)
f.link_sdk_link_sdk_rx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.link_sdk_link_sdk_rx_bytes", "Link Sdk Rx Bytes", base.HEX)
f.link_sdk_link_sdk_tx_packets = ProtoField.uint16 ("dji_mavic_flyrec.link_sdk_link_sdk_tx_packets", "Link Sdk Tx Packets", base.HEX)
f.link_sdk_link_sdk_rx_packets = ProtoField.uint16 ("dji_mavic_flyrec.link_sdk_link_sdk_rx_packets", "Link Sdk Rx Packets", base.HEX)
f.link_sdk_link_sdk_tx_errors = ProtoField.uint16 ("dji_mavic_flyrec.link_sdk_link_sdk_tx_errors", "Link Sdk Tx Errors", base.HEX)
f.link_sdk_link_sdk_rx_erros = ProtoField.uint16 ("dji_mavic_flyrec.link_sdk_link_sdk_rx_erros", "Link Sdk Rx Erros", base.HEX)
f.link_sdk_link_sdk_recv_route = ProtoField.uint16 ("dji_mavic_flyrec.link_sdk_link_sdk_recv_route", "Link Sdk Recv Route", base.HEX)
f.link_sdk_link_sdk_send_route = ProtoField.uint16 ("dji_mavic_flyrec.link_sdk_link_sdk_send_route", "Link Sdk Send Route", base.HEX)

local function flightrec_link_sdk_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.link_sdk_link_sdk_tx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.link_sdk_link_sdk_rx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.link_sdk_link_sdk_tx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_sdk_link_sdk_rx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_sdk_link_sdk_tx_errors, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_sdk_link_sdk_rx_erros, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_sdk_link_sdk_recv_route, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_sdk_link_sdk_send_route, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Link Sdk: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Link Sdk: Payload size different than expected") end
end

-- Flight log - Link Ofdm - 0x092e

f.link_ofdm_link_ofdm_tx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.link_ofdm_link_ofdm_tx_bytes", "Link Ofdm Tx Bytes", base.HEX)
f.link_ofdm_link_ofdm_rx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.link_ofdm_link_ofdm_rx_bytes", "Link Ofdm Rx Bytes", base.HEX)
f.link_ofdm_link_ofdm_tx_packets = ProtoField.uint16 ("dji_mavic_flyrec.link_ofdm_link_ofdm_tx_packets", "Link Ofdm Tx Packets", base.HEX)
f.link_ofdm_link_ofdm_rx_packets = ProtoField.uint16 ("dji_mavic_flyrec.link_ofdm_link_ofdm_rx_packets", "Link Ofdm Rx Packets", base.HEX)
f.link_ofdm_link_ofdm_tx_errors = ProtoField.uint16 ("dji_mavic_flyrec.link_ofdm_link_ofdm_tx_errors", "Link Ofdm Tx Errors", base.HEX)
f.link_ofdm_link_ofdm_rx_erros = ProtoField.uint16 ("dji_mavic_flyrec.link_ofdm_link_ofdm_rx_erros", "Link Ofdm Rx Erros", base.HEX)
f.link_ofdm_link_ofdm_recv_route = ProtoField.uint16 ("dji_mavic_flyrec.link_ofdm_link_ofdm_recv_route", "Link Ofdm Recv Route", base.HEX)
f.link_ofdm_link_ofdm_send_route = ProtoField.uint16 ("dji_mavic_flyrec.link_ofdm_link_ofdm_send_route", "Link Ofdm Send Route", base.HEX)

local function flightrec_link_ofdm_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.link_ofdm_link_ofdm_tx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.link_ofdm_link_ofdm_rx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.link_ofdm_link_ofdm_tx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_ofdm_link_ofdm_rx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_ofdm_link_ofdm_tx_errors, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_ofdm_link_ofdm_rx_erros, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_ofdm_link_ofdm_recv_route, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_ofdm_link_ofdm_send_route, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Link Ofdm: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Link Ofdm: Payload size different than expected") end
end

-- Flight log - Link Bat - 0x092f

f.link_bat_link_bat_tx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.link_bat_link_bat_tx_bytes", "Link Bat Tx Bytes", base.HEX)
f.link_bat_link_bat_rx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.link_bat_link_bat_rx_bytes", "Link Bat Rx Bytes", base.HEX)
f.link_bat_link_bat_tx_packets = ProtoField.uint16 ("dji_mavic_flyrec.link_bat_link_bat_tx_packets", "Link Bat Tx Packets", base.HEX)
f.link_bat_link_bat_rx_packets = ProtoField.uint16 ("dji_mavic_flyrec.link_bat_link_bat_rx_packets", "Link Bat Rx Packets", base.HEX)
f.link_bat_link_bat_tx_errors = ProtoField.uint16 ("dji_mavic_flyrec.link_bat_link_bat_tx_errors", "Link Bat Tx Errors", base.HEX)
f.link_bat_link_bat_rx_erros = ProtoField.uint16 ("dji_mavic_flyrec.link_bat_link_bat_rx_erros", "Link Bat Rx Erros", base.HEX)
f.link_bat_link_bat_recv_route = ProtoField.uint16 ("dji_mavic_flyrec.link_bat_link_bat_recv_route", "Link Bat Recv Route", base.HEX)
f.link_bat_link_bat_send_route = ProtoField.uint16 ("dji_mavic_flyrec.link_bat_link_bat_send_route", "Link Bat Send Route", base.HEX)

local function flightrec_link_bat_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.link_bat_link_bat_tx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.link_bat_link_bat_rx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.link_bat_link_bat_tx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_bat_link_bat_rx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_bat_link_bat_tx_errors, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_bat_link_bat_rx_erros, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_bat_link_bat_recv_route, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_bat_link_bat_send_route, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Link Bat: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Link Bat: Payload size different than expected") end
end

-- Flight log - Link Auto Cali - 0x0930

f.link_auto_cali_link_auto_cali_tx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.link_auto_cali_link_auto_cali_tx_bytes", "Link Auto Cali Tx Bytes", base.HEX)
f.link_auto_cali_link_auto_cali_rx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.link_auto_cali_link_auto_cali_rx_bytes", "Link Auto Cali Rx Bytes", base.HEX)
f.link_auto_cali_link_auto_cali_tx_packets = ProtoField.uint16 ("dji_mavic_flyrec.link_auto_cali_link_auto_cali_tx_packets", "Link Auto Cali Tx Packets", base.HEX)
f.link_auto_cali_link_auto_cali_rx_packets = ProtoField.uint16 ("dji_mavic_flyrec.link_auto_cali_link_auto_cali_rx_packets", "Link Auto Cali Rx Packets", base.HEX)
f.link_auto_cali_link_auto_cali_tx_errors = ProtoField.uint16 ("dji_mavic_flyrec.link_auto_cali_link_auto_cali_tx_errors", "Link Auto Cali Tx Errors", base.HEX)
f.link_auto_cali_link_auto_cali_rx_erros = ProtoField.uint16 ("dji_mavic_flyrec.link_auto_cali_link_auto_cali_rx_erros", "Link Auto Cali Rx Erros", base.HEX)
f.link_auto_cali_link_auto_cali_recv_route = ProtoField.uint16 ("dji_mavic_flyrec.link_auto_cali_link_auto_cali_recv_route", "Link Auto Cali Recv Route", base.HEX)
f.link_auto_cali_link_auto_cali_send_route = ProtoField.uint16 ("dji_mavic_flyrec.link_auto_cali_link_auto_cali_send_route", "Link Auto Cali Send Route", base.HEX)

local function flightrec_link_auto_cali_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.link_auto_cali_link_auto_cali_tx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.link_auto_cali_link_auto_cali_rx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.link_auto_cali_link_auto_cali_tx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_auto_cali_link_auto_cali_rx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_auto_cali_link_auto_cali_tx_errors, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_auto_cali_link_auto_cali_rx_erros, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_auto_cali_link_auto_cali_recv_route, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_auto_cali_link_auto_cali_send_route, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Link Auto Cali: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Link Auto Cali: Payload size different than expected") end
end

-- Flight log - Link Cali Led - 0x0931

f.link_cali_led_link_cali_led_tx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.link_cali_led_link_cali_led_tx_bytes", "Link Cali Led Tx Bytes", base.HEX)
f.link_cali_led_link_cali_led_rx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.link_cali_led_link_cali_led_rx_bytes", "Link Cali Led Rx Bytes", base.HEX)
f.link_cali_led_link_cali_led_tx_packets = ProtoField.uint16 ("dji_mavic_flyrec.link_cali_led_link_cali_led_tx_packets", "Link Cali Led Tx Packets", base.HEX)
f.link_cali_led_link_cali_led_rx_packets = ProtoField.uint16 ("dji_mavic_flyrec.link_cali_led_link_cali_led_rx_packets", "Link Cali Led Rx Packets", base.HEX)
f.link_cali_led_link_cali_led_tx_errors = ProtoField.uint16 ("dji_mavic_flyrec.link_cali_led_link_cali_led_tx_errors", "Link Cali Led Tx Errors", base.HEX)
f.link_cali_led_link_cali_led_rx_erros = ProtoField.uint16 ("dji_mavic_flyrec.link_cali_led_link_cali_led_rx_erros", "Link Cali Led Rx Erros", base.HEX)
f.link_cali_led_link_cali_led_recv_route = ProtoField.uint16 ("dji_mavic_flyrec.link_cali_led_link_cali_led_recv_route", "Link Cali Led Recv Route", base.HEX)
f.link_cali_led_link_cali_led_send_route = ProtoField.uint16 ("dji_mavic_flyrec.link_cali_led_link_cali_led_send_route", "Link Cali Led Send Route", base.HEX)

local function flightrec_link_cali_led_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.link_cali_led_link_cali_led_tx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.link_cali_led_link_cali_led_rx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.link_cali_led_link_cali_led_tx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_cali_led_link_cali_led_rx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_cali_led_link_cali_led_tx_errors, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_cali_led_link_cali_led_rx_erros, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_cali_led_link_cali_led_recv_route, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_cali_led_link_cali_led_send_route, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Link Cali Led: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Link Cali Led: Payload size different than expected") end
end

-- Flight log - Link Manual Cali - 0x0932

f.link_manual_cali_link_manual_cali_tx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.link_manual_cali_link_manual_cali_tx_bytes", "Link Manual Cali Tx Bytes", base.HEX)
f.link_manual_cali_link_manual_cali_rx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.link_manual_cali_link_manual_cali_rx_bytes", "Link Manual Cali Rx Bytes", base.HEX)
f.link_manual_cali_link_manual_cali_tx_packets = ProtoField.uint16 ("dji_mavic_flyrec.link_manual_cali_link_manual_cali_tx_packets", "Link Manual Cali Tx Packets", base.HEX)
f.link_manual_cali_link_manual_cali_rx_packets = ProtoField.uint16 ("dji_mavic_flyrec.link_manual_cali_link_manual_cali_rx_packets", "Link Manual Cali Rx Packets", base.HEX)
f.link_manual_cali_link_manual_cali_tx_errors = ProtoField.uint16 ("dji_mavic_flyrec.link_manual_cali_link_manual_cali_tx_errors", "Link Manual Cali Tx Errors", base.HEX)
f.link_manual_cali_link_manual_cali_rx_erros = ProtoField.uint16 ("dji_mavic_flyrec.link_manual_cali_link_manual_cali_rx_erros", "Link Manual Cali Rx Erros", base.HEX)
f.link_manual_cali_link_manual_cali_recv_route = ProtoField.uint16 ("dji_mavic_flyrec.link_manual_cali_link_manual_cali_recv_route", "Link Manual Cali Recv Route", base.HEX)
f.link_manual_cali_link_manual_cali_send_route = ProtoField.uint16 ("dji_mavic_flyrec.link_manual_cali_link_manual_cali_send_route", "Link Manual Cali Send Route", base.HEX)

local function flightrec_link_manual_cali_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.link_manual_cali_link_manual_cali_tx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.link_manual_cali_link_manual_cali_rx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.link_manual_cali_link_manual_cali_tx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_manual_cali_link_manual_cali_rx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_manual_cali_link_manual_cali_tx_errors, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_manual_cali_link_manual_cali_rx_erros, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_manual_cali_link_manual_cali_recv_route, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.link_manual_cali_link_manual_cali_send_route, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Link Manual Cali: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Link Manual Cali: Payload size different than expected") end
end

-- Flight log - Ipc0 - 0x0933

f.ipc0_ipc0_tx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.ipc0_ipc0_tx_bytes", "Ipc0 Tx Bytes", base.HEX)
f.ipc0_ipc0_rx_bytes = ProtoField.uint32 ("dji_mavic_flyrec.ipc0_ipc0_rx_bytes", "Ipc0 Rx Bytes", base.HEX)
f.ipc0_ipc0_tx_packets = ProtoField.uint16 ("dji_mavic_flyrec.ipc0_ipc0_tx_packets", "Ipc0 Tx Packets", base.HEX)
f.ipc0_ipc0_rx_packets = ProtoField.uint16 ("dji_mavic_flyrec.ipc0_ipc0_rx_packets", "Ipc0 Rx Packets", base.HEX)
f.ipc0_ipc0_tx_errors = ProtoField.uint16 ("dji_mavic_flyrec.ipc0_ipc0_tx_errors", "Ipc0 Tx Errors", base.HEX)
f.ipc0_ipc0_rx_erros = ProtoField.uint16 ("dji_mavic_flyrec.ipc0_ipc0_rx_erros", "Ipc0 Rx Erros", base.HEX)
f.ipc0_ipc0_recv_route = ProtoField.uint16 ("dji_mavic_flyrec.ipc0_ipc0_recv_route", "Ipc0 Recv Route", base.HEX)
f.ipc0_ipc0_send_route = ProtoField.uint16 ("dji_mavic_flyrec.ipc0_ipc0_send_route", "Ipc0 Send Route", base.HEX)

local function flightrec_ipc0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.ipc0_ipc0_tx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ipc0_ipc0_rx_bytes, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.ipc0_ipc0_tx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ipc0_ipc0_rx_packets, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ipc0_ipc0_tx_errors, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ipc0_ipc0_rx_erros, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ipc0_ipc0_recv_route, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.ipc0_ipc0_send_route, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Ipc0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Ipc0: Payload size different than expected") end
end

-- Flight log - System Monitor - 0xcde0

f.system_monitor_root_max_time = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_root_max_time", "Root Max Time", base.HEX)
f.system_monitor_root_average_time = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_root_average_time", "Root Average Time", base.HEX)
f.system_monitor_root_warn = ProtoField.int16 ("dji_mavic_flyrec.system_monitor_root_warn", "Root Warn", base.DEC)
f.system_monitor_root_pend = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_root_pend", "Root Pend", base.HEX)
f.system_monitor_root_stack = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_root_stack", "Root Stack", base.HEX)
f.system_monitor_root_reserv = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_root_reserv", "Root Reserv", base.HEX)
f.system_monitor_wq_max_time = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_wq_max_time", "Wq Max Time", base.HEX)
f.system_monitor_wq_average_time = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_wq_average_time", "Wq Average Time", base.HEX)
f.system_monitor_wq_warn = ProtoField.int16 ("dji_mavic_flyrec.system_monitor_wq_warn", "Wq Warn", base.DEC)
f.system_monitor_wq_pend = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_wq_pend", "Wq Pend", base.HEX)
f.system_monitor_wq_stack = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_wq_stack", "Wq Stack", base.HEX)
f.system_monitor_wq_reserv = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_wq_reserv", "Wq Reserv", base.HEX)
f.system_monitor_task_c_max_time = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_c_max_time", "Task C Max Time", base.HEX)
f.system_monitor_task_c_average_time = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_c_average_time", "Task C Average Time", base.HEX)
f.system_monitor_task_c_warn = ProtoField.int16 ("dji_mavic_flyrec.system_monitor_task_c_warn", "Task C Warn", base.DEC)
f.system_monitor_task_c_pend = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_c_pend", "Task C Pend", base.HEX)
f.system_monitor_task_c_stack = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_c_stack", "Task C Stack", base.HEX)
f.system_monitor_task_c_reserv = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_c_reserv", "Task C Reserv", base.HEX)
f.system_monitor_task_d_max_time = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_d_max_time", "Task D Max Time", base.HEX)
f.system_monitor_task_d_average_time = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_d_average_time", "Task D Average Time", base.HEX)
f.system_monitor_task_d_warn = ProtoField.int16 ("dji_mavic_flyrec.system_monitor_task_d_warn", "Task D Warn", base.DEC)
f.system_monitor_task_d_pend = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_d_pend", "Task D Pend", base.HEX)
f.system_monitor_task_d_stack = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_d_stack", "Task D Stack", base.HEX)
f.system_monitor_task_d_reserv = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_d_reserv", "Task D Reserv", base.HEX)
f.system_monitor_task_ctrl_max_time = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_ctrl_max_time", "Task Ctrl Max Time", base.HEX)
f.system_monitor_task_ctrl_average_time = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_ctrl_average_time", "Task Ctrl Average Time", base.HEX)
f.system_monitor_task_ctrl_warn = ProtoField.int16 ("dji_mavic_flyrec.system_monitor_task_ctrl_warn", "Task Ctrl Warn", base.DEC)
f.system_monitor_task_ctrl_pend = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_ctrl_pend", "Task Ctrl Pend", base.HEX)
f.system_monitor_task_ctrl_stack = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_ctrl_stack", "Task Ctrl Stack", base.HEX)
f.system_monitor_task_ctrl_reserv = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_ctrl_reserv", "Task Ctrl Reserv", base.HEX)
f.system_monitor_task_a_max_time = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_a_max_time", "Task A Max Time", base.HEX)
f.system_monitor_task_a_average_time = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_a_average_time", "Task A Average Time", base.HEX)
f.system_monitor_task_a_warn = ProtoField.int16 ("dji_mavic_flyrec.system_monitor_task_a_warn", "Task A Warn", base.DEC)
f.system_monitor_task_a_pend = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_a_pend", "Task A Pend", base.HEX)
f.system_monitor_task_a_stack = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_a_stack", "Task A Stack", base.HEX)
f.system_monitor_task_a_reserv = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_a_reserv", "Task A Reserv", base.HEX)
f.system_monitor_task_imu_max_time = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_imu_max_time", "Task Imu Max Time", base.HEX)
f.system_monitor_task_imu_average_time = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_imu_average_time", "Task Imu Average Time", base.HEX)
f.system_monitor_task_imu_warn = ProtoField.int16 ("dji_mavic_flyrec.system_monitor_task_imu_warn", "Task Imu Warn", base.DEC)
f.system_monitor_task_imu_pend = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_imu_pend", "Task Imu Pend", base.HEX)
f.system_monitor_task_imu_stack = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_imu_stack", "Task Imu Stack", base.HEX)
f.system_monitor_task_imu_reserv = ProtoField.uint16 ("dji_mavic_flyrec.system_monitor_task_imu_reserv", "Task Imu Reserv", base.HEX)

local function flightrec_system_monitor_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.system_monitor_root_max_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_root_average_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_root_warn, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_root_pend, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_root_stack, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_root_reserv, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_wq_max_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_wq_average_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_wq_warn, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_wq_pend, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_wq_stack, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_wq_reserv, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_c_max_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_c_average_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_c_warn, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_c_pend, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_c_stack, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_c_reserv, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_d_max_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_d_average_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_d_warn, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_d_pend, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_d_stack, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_d_reserv, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_ctrl_max_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_ctrl_average_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_ctrl_warn, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_ctrl_pend, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_ctrl_stack, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_ctrl_reserv, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_a_max_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_a_average_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_a_warn, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_a_pend, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_a_stack, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_a_reserv, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_imu_max_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_imu_average_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_imu_warn, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_imu_pend, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_imu_stack, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.system_monitor_task_imu_reserv, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 84) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"System Monitor: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"System Monitor: Payload size different than expected") end
end

-- Flight log - Uart Monitor - 0xcddf

f.uart_monitor_uart0_tx = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart0_tx", "Uart0 Tx", base.HEX)
f.uart_monitor_uart0_txlost = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart0_txlost", "Uart0 Txlost", base.HEX)
f.uart_monitor_uart0_rx = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart0_rx", "Uart0 Rx", base.HEX)
f.uart_monitor_uart0_rxlost = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart0_rxlost", "Uart0 Rxlost", base.HEX)
f.uart_monitor_uart0_dbg0 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart0_dbg0", "Uart0 Dbg0", base.DEC)
f.uart_monitor_uart0_dbg1 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart0_dbg1", "Uart0 Dbg1", base.DEC)
f.uart_monitor_uart0_dbg2 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart0_dbg2", "Uart0 Dbg2", base.DEC)
f.uart_monitor_uart0_dbg3 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart0_dbg3", "Uart0 Dbg3", base.DEC)
f.uart_monitor_uart0_dbg4 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart0_dbg4", "Uart0 Dbg4", base.DEC)
f.uart_monitor_uart0_dbg5 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart0_dbg5", "Uart0 Dbg5", base.DEC)
f.uart_monitor_uart2_tx = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart2_tx", "Uart2 Tx", base.HEX)
f.uart_monitor_uart2_txlost = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart2_txlost", "Uart2 Txlost", base.HEX)
f.uart_monitor_uart2_rx = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart2_rx", "Uart2 Rx", base.HEX)
f.uart_monitor_uart2_rxlost = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart2_rxlost", "Uart2 Rxlost", base.HEX)
f.uart_monitor_uart2_dbg0 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart2_dbg0", "Uart2 Dbg0", base.DEC)
f.uart_monitor_uart2_dbg1 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart2_dbg1", "Uart2 Dbg1", base.DEC)
f.uart_monitor_uart2_dbg2 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart2_dbg2", "Uart2 Dbg2", base.DEC)
f.uart_monitor_uart2_dbg3 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart2_dbg3", "Uart2 Dbg3", base.DEC)
f.uart_monitor_uart2_dbg4 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart2_dbg4", "Uart2 Dbg4", base.DEC)
f.uart_monitor_uart2_dbg5 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart2_dbg5", "Uart2 Dbg5", base.DEC)
f.uart_monitor_uart4_tx = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart4_tx", "Uart4 Tx", base.HEX)
f.uart_monitor_uart4_txlost = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart4_txlost", "Uart4 Txlost", base.HEX)
f.uart_monitor_uart4_rx = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart4_rx", "Uart4 Rx", base.HEX)
f.uart_monitor_uart4_rxlost = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart4_rxlost", "Uart4 Rxlost", base.HEX)
f.uart_monitor_uart4_dbg0 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart4_dbg0", "Uart4 Dbg0", base.DEC)
f.uart_monitor_uart4_dbg1 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart4_dbg1", "Uart4 Dbg1", base.DEC)
f.uart_monitor_uart4_dbg2 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart4_dbg2", "Uart4 Dbg2", base.DEC)
f.uart_monitor_uart4_dbg3 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart4_dbg3", "Uart4 Dbg3", base.DEC)
f.uart_monitor_uart4_dbg4 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart4_dbg4", "Uart4 Dbg4", base.DEC)
f.uart_monitor_uart4_dbg5 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart4_dbg5", "Uart4 Dbg5", base.DEC)
f.uart_monitor_uart5_tx = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart5_tx", "Uart5 Tx", base.HEX)
f.uart_monitor_uart5_txlost = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart5_txlost", "Uart5 Txlost", base.HEX)
f.uart_monitor_uart5_rx = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart5_rx", "Uart5 Rx", base.HEX)
f.uart_monitor_uart5_rxlost = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart5_rxlost", "Uart5 Rxlost", base.HEX)
f.uart_monitor_uart5_dbg0 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart5_dbg0", "Uart5 Dbg0", base.DEC)
f.uart_monitor_uart5_dbg1 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart5_dbg1", "Uart5 Dbg1", base.DEC)
f.uart_monitor_uart5_dbg2 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart5_dbg2", "Uart5 Dbg2", base.DEC)
f.uart_monitor_uart5_dbg3 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart5_dbg3", "Uart5 Dbg3", base.DEC)
f.uart_monitor_uart5_dbg4 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart5_dbg4", "Uart5 Dbg4", base.DEC)
f.uart_monitor_uart5_dbg5 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart5_dbg5", "Uart5 Dbg5", base.DEC)
f.uart_monitor_uart7_tx = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart7_tx", "Uart7 Tx", base.HEX)
f.uart_monitor_uart7_txlost = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart7_txlost", "Uart7 Txlost", base.HEX)
f.uart_monitor_uart7_rx = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart7_rx", "Uart7 Rx", base.HEX)
f.uart_monitor_uart7_rxlost = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart7_rxlost", "Uart7 Rxlost", base.HEX)
f.uart_monitor_uart7_dbg0 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart7_dbg0", "Uart7 Dbg0", base.DEC)
f.uart_monitor_uart7_dbg1 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart7_dbg1", "Uart7 Dbg1", base.DEC)
f.uart_monitor_uart7_dbg2 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart7_dbg2", "Uart7 Dbg2", base.DEC)
f.uart_monitor_uart7_dbg3 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart7_dbg3", "Uart7 Dbg3", base.DEC)
f.uart_monitor_uart7_dbg4 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart7_dbg4", "Uart7 Dbg4", base.DEC)
f.uart_monitor_uart7_dbg5 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart7_dbg5", "Uart7 Dbg5", base.DEC)
f.uart_monitor_uart100_tx = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart100_tx", "Uart100 Tx", base.HEX)
f.uart_monitor_uart100_txlost = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart100_txlost", "Uart100 Txlost", base.HEX)
f.uart_monitor_uart100_rx = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart100_rx", "Uart100 Rx", base.HEX)
f.uart_monitor_uart100_rxlost = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart100_rxlost", "Uart100 Rxlost", base.HEX)
f.uart_monitor_uart100_dbg0 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart100_dbg0", "Uart100 Dbg0", base.DEC)
f.uart_monitor_uart100_dbg1 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart100_dbg1", "Uart100 Dbg1", base.DEC)
f.uart_monitor_uart100_dbg2 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart100_dbg2", "Uart100 Dbg2", base.DEC)
f.uart_monitor_uart100_dbg3 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart100_dbg3", "Uart100 Dbg3", base.DEC)
f.uart_monitor_uart100_dbg4 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart100_dbg4", "Uart100 Dbg4", base.DEC)
f.uart_monitor_uart100_dbg5 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart100_dbg5", "Uart100 Dbg5", base.DEC)
f.uart_monitor_uart179_tx = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart179_tx", "Uart179 Tx", base.HEX)
f.uart_monitor_uart179_txlost = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart179_txlost", "Uart179 Txlost", base.HEX)
f.uart_monitor_uart179_rx = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart179_rx", "Uart179 Rx", base.HEX)
f.uart_monitor_uart179_rxlost = ProtoField.uint32 ("dji_mavic_flyrec.uart_monitor_uart179_rxlost", "Uart179 Rxlost", base.HEX)
f.uart_monitor_uart179_dbg0 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart179_dbg0", "Uart179 Dbg0", base.DEC)
f.uart_monitor_uart179_dbg1 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart179_dbg1", "Uart179 Dbg1", base.DEC)
f.uart_monitor_uart179_dbg2 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart179_dbg2", "Uart179 Dbg2", base.DEC)
f.uart_monitor_uart179_dbg3 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart179_dbg3", "Uart179 Dbg3", base.DEC)
f.uart_monitor_uart179_dbg4 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart179_dbg4", "Uart179 Dbg4", base.DEC)
f.uart_monitor_uart179_dbg5 = ProtoField.int16 ("dji_mavic_flyrec.uart_monitor_uart179_dbg5", "Uart179 Dbg5", base.DEC)

local function flightrec_uart_monitor_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.uart_monitor_uart0_tx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart0_txlost, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart0_rx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart0_rxlost, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart0_dbg0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart0_dbg1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart0_dbg2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart0_dbg3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart0_dbg4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart0_dbg5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart2_tx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart2_txlost, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart2_rx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart2_rxlost, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart2_dbg0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart2_dbg1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart2_dbg2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart2_dbg3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart2_dbg4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart2_dbg5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart4_tx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart4_txlost, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart4_rx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart4_rxlost, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart4_dbg0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart4_dbg1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart4_dbg2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart4_dbg3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart4_dbg4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart4_dbg5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart5_tx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart5_txlost, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart5_rx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart5_rxlost, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart5_dbg0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart5_dbg1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart5_dbg2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart5_dbg3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart5_dbg4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart5_dbg5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart7_tx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart7_txlost, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart7_rx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart7_rxlost, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart7_dbg0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart7_dbg1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart7_dbg2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart7_dbg3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart7_dbg4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart7_dbg5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart100_tx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart100_txlost, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart100_rx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart100_rxlost, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart100_dbg0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart100_dbg1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart100_dbg2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart100_dbg3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart100_dbg4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart100_dbg5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart179_tx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart179_txlost, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart179_rx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart179_rxlost, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.uart_monitor_uart179_dbg0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart179_dbg1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart179_dbg2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart179_dbg3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart179_dbg4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.uart_monitor_uart179_dbg5, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 196) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Uart Monitor: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Uart Monitor: Payload size different than expected") end
end

-- Flight log - Can Monitor - 0xcdde

f.can_monitor_can0_tx = ProtoField.uint32 ("dji_mavic_flyrec.can_monitor_can0_tx", "Can0 Tx", base.HEX)
f.can_monitor_can0_txlost = ProtoField.uint32 ("dji_mavic_flyrec.can_monitor_can0_txlost", "Can0 Txlost", base.HEX)
f.can_monitor_can0_rx = ProtoField.uint32 ("dji_mavic_flyrec.can_monitor_can0_rx", "Can0 Rx", base.HEX)
f.can_monitor_can0_rxlost = ProtoField.uint32 ("dji_mavic_flyrec.can_monitor_can0_rxlost", "Can0 Rxlost", base.HEX)
f.can_monitor_can0_dbg0 = ProtoField.int16 ("dji_mavic_flyrec.can_monitor_can0_dbg0", "Can0 Dbg0", base.DEC)
f.can_monitor_can0_dbg1 = ProtoField.int16 ("dji_mavic_flyrec.can_monitor_can0_dbg1", "Can0 Dbg1", base.DEC)
f.can_monitor_can0_dbg2 = ProtoField.int16 ("dji_mavic_flyrec.can_monitor_can0_dbg2", "Can0 Dbg2", base.DEC)
f.can_monitor_can0_dbg3 = ProtoField.int16 ("dji_mavic_flyrec.can_monitor_can0_dbg3", "Can0 Dbg3", base.DEC)
f.can_monitor_can0_dbg4 = ProtoField.int16 ("dji_mavic_flyrec.can_monitor_can0_dbg4", "Can0 Dbg4", base.DEC)
f.can_monitor_can0_dbg5 = ProtoField.int16 ("dji_mavic_flyrec.can_monitor_can0_dbg5", "Can0 Dbg5", base.DEC)
f.can_monitor_can1_tx = ProtoField.uint32 ("dji_mavic_flyrec.can_monitor_can1_tx", "Can1 Tx", base.HEX)
f.can_monitor_can1_txlost = ProtoField.uint32 ("dji_mavic_flyrec.can_monitor_can1_txlost", "Can1 Txlost", base.HEX)
f.can_monitor_can1_rx = ProtoField.uint32 ("dji_mavic_flyrec.can_monitor_can1_rx", "Can1 Rx", base.HEX)
f.can_monitor_can1_rxlost = ProtoField.uint32 ("dji_mavic_flyrec.can_monitor_can1_rxlost", "Can1 Rxlost", base.HEX)
f.can_monitor_can1_dbg0 = ProtoField.int16 ("dji_mavic_flyrec.can_monitor_can1_dbg0", "Can1 Dbg0", base.DEC)
f.can_monitor_can1_dbg1 = ProtoField.int16 ("dji_mavic_flyrec.can_monitor_can1_dbg1", "Can1 Dbg1", base.DEC)
f.can_monitor_can1_dbg2 = ProtoField.int16 ("dji_mavic_flyrec.can_monitor_can1_dbg2", "Can1 Dbg2", base.DEC)
f.can_monitor_can1_dbg3 = ProtoField.int16 ("dji_mavic_flyrec.can_monitor_can1_dbg3", "Can1 Dbg3", base.DEC)
f.can_monitor_can1_dbg4 = ProtoField.int16 ("dji_mavic_flyrec.can_monitor_can1_dbg4", "Can1 Dbg4", base.DEC)
f.can_monitor_can1_dbg5 = ProtoField.int16 ("dji_mavic_flyrec.can_monitor_can1_dbg5", "Can1 Dbg5", base.DEC)

local function flightrec_can_monitor_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.can_monitor_can0_tx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.can_monitor_can0_txlost, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.can_monitor_can0_rx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.can_monitor_can0_rxlost, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.can_monitor_can0_dbg0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.can_monitor_can0_dbg1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.can_monitor_can0_dbg2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.can_monitor_can0_dbg3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.can_monitor_can0_dbg4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.can_monitor_can0_dbg5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.can_monitor_can1_tx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.can_monitor_can1_txlost, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.can_monitor_can1_rx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.can_monitor_can1_rxlost, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.can_monitor_can1_dbg0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.can_monitor_can1_dbg1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.can_monitor_can1_dbg2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.can_monitor_can1_dbg3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.can_monitor_can1_dbg4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.can_monitor_can1_dbg5, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 56) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Can Monitor: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Can Monitor: Payload size different than expected") end
end

-- Flight log - Fly Log - 0x8000

f.fly_log_text = ProtoField.string ("dji_mavic_flyrec.fly_log_text", "Fly Log", base.ASCII)

local function flightrec_fly_log_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add (f.fly_log_text, payload(offset, payload:len() - offset))
end

-- Flight log - Sd Logs - 0xff00

f.sd_logs_text = ProtoField.string ("dji_mavic_flyrec.sd_logs_text", "Sd Logs", base.ASCII)

local function flightrec_sd_logs_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add (f.sd_logs_text, payload(offset, payload:len() - offset))
end

-- Flight log - Sys Cfg - 0xffff

f.sys_cfg_text = ProtoField.string ("dji_mavic_flyrec.sys_cfg_text", "Sys Cfg", base.ASCII)

local function flightrec_sys_cfg_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add (f.sys_cfg_text, payload(offset, payload:len() - offset))
end

-- Flight log - Uno Log - 0xfffe

f.uno_log_text = ProtoField.string ("dji_mavic_flyrec.uno_log_text", "Uno Log", base.ASCII)

local function flightrec_uno_log_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add (f.uno_log_text, payload(offset, payload:len() - offset))
end

-- Flight log - Cfg Log - 0xfffd

f.cfg_log_text = ProtoField.string ("dji_mavic_flyrec.cfg_log_text", "Cfg Log", base.ASCII)

local function flightrec_cfg_log_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add (f.cfg_log_text, payload(offset, payload:len() - offset))
end

-- Flight log - Module Name - 0xfffc

f.module_name_text = ProtoField.string ("dji_mavic_flyrec.module_name_text", "Module Name", base.ASCII)

local function flightrec_module_name_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add (f.module_name_text, payload(offset, payload:len() - offset))
end

DJI_MAVIC_FLIGHT_RECORD_DISSECT = {
    [0x03e8] = flightrec_controller_dissector,
    [0x03e9] = flightrec_aircraft_condition_dissector,
    [0x03ea] = flightrec_serial_api_inputs_dissector,
    [0x03ec] = flightrec_go_home_info_dissector,
    [0x03ed] = flightrec_fmu_devices_run_time_dissector,
    [0x03f0] = flightrec_fmu_sa_run_time_dissector,
    [0x03f1] = flightrec_fmu_write_run_time_dissector,
    [0x03f3] = flightrec_fmu_api_run_time_dissector,
    [0x03f4] = flightrec_cfg_errs_dissector,
    [0x03f5] = flightrec_new_api_err_time_dissector,
    [0x03ee] = flightrec_poi_debug_data_dissector,
    [0x03f6] = flightrec_adv_gh_debug_data_dissector,
    [0x03f7] = flightrec_ahrs_data_dissector,
    [0x0070] = flightrec_err_code_dissector,
    [0x0800] = flightrec_imu_atti_0_dissector,
    [0x0801] = flightrec_imu_atti_1_dissector,
    [0x0802] = flightrec_imu_atti_2_dissector,
    [0x0810] = flightrec_imu_ex_0_dissector,
    [0x0811] = flightrec_imu_ex_1_dissector,
    [0x0812] = flightrec_imu_ex_2_dissector,
    [0x08a0] = flightrec_atti_mini0_dissector,
    [0x08a1] = flightrec_atti_mini1_dissector,
    [0x08a2] = flightrec_atti_mini2_dissector,
    [0x0860] = flightrec_imu_fdi_0_dissector,
    [0x0861] = flightrec_imu_fdi_1_dissector,
    [0x0862] = flightrec_imu_fdi_2_dissector,
    [0x03ef] = flightrec_hl_debug_data_dissector,
    [0x03f2] = flightrec_farm_db_data_dissector,
    [0x4ef7] = flightrec_spray_sys_ctrl_cmd_dissector,
    [0x4ef8] = flightrec_spray_sys_state_dissector,
    [0x04b0] = flightrec_ctrl_vert_debug_dissector,
    [0x04b1] = flightrec_ctrl_pos_vert_debug_dissector,
    [0x04b2] = flightrec_ctrl_vel_vert_debug_dissector,
    [0x04b3] = flightrec_ctrl_acc_vert_debug_dissector,
    [0x0514] = flightrec_ctrl_horiz_debug_dissector,
    [0x0515] = flightrec_ctrl_horiz_pos_debug_dissector,
    [0x0516] = flightrec_ctrl_horiz_vel_debug_dissector,
    [0x0518] = flightrec_ctrl_horiz_atti_debug_dissector,
    [0x0519] = flightrec_ctrl_horiz_ang_vel_debug_dissector,
    [0x051a] = flightrec_ctrl_horiz_ccpm_debug_dissector,
    [0x051b] = flightrec_ctrl_horiz_motor_debug_dissector,
    [0x051c] = flightrec_ctrl_sweep_test_dissector,
    [0x0460] = flightrec_way_debug_info_dissector,
    [0x0461] = flightrec_svo_avoid_dissector,
    [0x0578] = flightrec_simulator_debug_data_dissector,
    [0x0579] = flightrec_simulator_gyro_acc_data_400hz_dissector,
    [0x057c] = flightrec_simulator_press_data_200hz_dissector,
    [0x057a] = flightrec_simulator_mag_data_50hz_dissector,
    [0x057b] = flightrec_simulator_gps_data_5hz_dissector,
    [0x057e] = flightrec_simulator_motor_data_dissector,
    [0x057d] = flightrec_device_change_times_dissector,
    [0x0582] = flightrec_simulator_config_aircraft_param_dissector,
    [0x0583] = flightrec_simulator_config_battery_param_dissector,
    [0x0584] = flightrec_simulator_config_environment_param_dissector,
    [0x0585] = flightrec_simulator_config_motor_param_1_dissector,
    [0x0587] = flightrec_simulator_config_sensor_param_dissector,
    [0xcff2] = flightrec_rtkdata_dissector,
    [0x0640] = flightrec_genral_debug_data_dissector,
    [0x06a4] = flightrec_rc_debug_info_dissector,
    [0x08d0] = flightrec_cali_mag_00_dissector,
    [0x08d1] = flightrec_cali_mag_01_dissector,
    [0x08d2] = flightrec_cali_mag_02_dissector,
    [0x0828] = flightrec_lpf_gyr_acc0_dissector,
    [0x0829] = flightrec_lpf_gyr_acc1_dissector,
    [0x082a] = flightrec_lpf_gyr_acc2_dissector,
    [0x08e6] = flightrec_app_temp_bias0_dissector,
    [0x08e7] = flightrec_app_temp_bias1_dissector,
    [0x08e8] = flightrec_app_temp_bias2_dissector,
    [0x08e4] = flightrec_inner_temp_bias0_dissector,
    [0x08e5] = flightrec_inner_temp_bias1_dissector,
    [0x08e6] = flightrec_inner_temp_bias2_dissector,
    [0x06ae] = flightrec_battery_info_dissector,
    [0x06af] = flightrec_battery_status_dissector,
    [0x06b0] = flightrec_smart_battery_info_dissector,
    [0x0708] = flightrec_statistical_info_dissector,
    [0x2764] = flightrec_ns_sensor_quality_dissector,
    [0x2765] = flightrec_ns_data_debug_dissector,
    [0x2766] = flightrec_ns_data_component_dissector,
    [0x2767] = flightrec_ns_data_residuals_dissector,
    [0x2768] = flightrec_ns_data_posi_ofst_dissector,
    [0x2769] = flightrec_ns_sensor_connect_dissector,
    [0x276a] = flightrec_esc_data_dissector,
    [0x276b] = flightrec_high_freq_gyro_data_0_dissector,
    [0x276c] = flightrec_high_freq_gyro_data_1_dissector,
    [0x276d] = flightrec_high_freq_gyro_data_2_dissector,
    [0x276e] = flightrec_rc_gps_data_dissector,
    [0x2770] = flightrec_cb_gps_dissector,
    [0x2771] = flightrec_cb_temp_dissector,
    [0x2772] = flightrec_cb_press_dissector,
    [0x2774] = flightrec_air_compensate_data_dissector,
    [0x2775] = flightrec_vision_tof_dissector,
    [0x2776] = flightrec_gs_rtk_data_dissector,
    [0x2777] = flightrec_ex_raw_baro1_dissector,
    [0x2778] = flightrec_ex_raw_baro2_dissector,
    [0x2779] = flightrec_ex_raw_compass_dissector,
    [0x27d8] = flightrec_gear_status_dissector,
    [0x4ef2] = flightrec_radar_bottom_dissector,
    [0x4ef3] = flightrec_radar_avoid_front_dissector,
    [0x4ef4] = flightrec_radar_avoid_back_dissector,
    [0x4ef5] = flightrec_radar_predict_front_dissector,
    [0x4ef6] = flightrec_radar_predict_back_dissector,
    [0x4f4c] = flightrec_gyro_raw0_0_dissector,
    [0x4f4d] = flightrec_gyro_raw0_1_dissector,
    [0x4f4e] = flightrec_gyro_raw0_2_dissector,
    [0x4f50] = flightrec_gyro_raw1_0_dissector,
    [0x4f51] = flightrec_gyro_raw1_1_dissector,
    [0x4f54] = flightrec_gyro_raw2_0_dissector,
    [0x4f55] = flightrec_gyro_raw2_1_dissector,
    [0x4f58] = flightrec_acc_raw0_0_dissector,
    [0x4f59] = flightrec_acc_raw0_1_dissector,
    [0x4f5a] = flightrec_acc_raw0_2_dissector,
    [0x4f5c] = flightrec_acc_raw1_0_dissector,
    [0x4f5d] = flightrec_acc_raw1_1_dissector,
    [0x4f60] = flightrec_acc_raw2_0_dissector,
    [0x4f61] = flightrec_acc_raw2_1_dissector,
    [0x4f64] = flightrec_sensor_push0_0_dissector,
    [0x4f65] = flightrec_sensor_push0_1_dissector,
    [0x4f6a] = flightrec_baro_raw0_dissector,
    [0x4f6b] = flightrec_baro_raw1_dissector,
    [0x4f6c] = flightrec_baro_raw2_dissector,
    [0x4f6d] = flightrec_baro_raw3_dissector,
    [0x4f74] = flightrec_compass_raw0_dissector,
    [0x4f75] = flightrec_compass_raw1_dissector,
    [0x4f76] = flightrec_compass_raw2_dissector,
    [0x4f7e] = flightrec_compass_filter0_dissector,
    [0x4f7f] = flightrec_compass_filter1_dissector,
    [0x4f80] = flightrec_compass_filter2_dissector,
    [0x4f88] = flightrec_imu_rotated_data_dissector,
    [0x5014] = flightrec_raw_wristband_data_dissector,
    [0x5015] = flightrec_wristband_dissector,
    [0x501e] = flightrec_ctrl_device_dissector,
    [0x4e20] = flightrec_battery_info_2_dissector,
    [0x4e21] = flightrec_pwm_output_dissector,
    [0x0880] = flightrec_temp_ctl_recorde0_dissector,
    [0x0881] = flightrec_temp_ctl_recorde1_dissector,
    [0x0882] = flightrec_temp_ctl_recorde2_dissector,
    [0x4e22] = flightrec_airport_limit_debug_info_dissector,
    [0x4e23] = flightrec_battery_raw_data_1_dissector,
    [0x4e24] = flightrec_battery_raw_data_2_dissector,
    [0x4e25] = flightrec_sys_err_dissector,
    [0x4e27] = flightrec_quick_circle_debug_dissector,
    [0x4e28] = flightrec_battery_info_3_dissector,
    [0x4e29] = flightrec_rc_func_data_dissector,
    [0x4e2a] = flightrec_rc_func_state_dissector,
    [0x4e2b] = flightrec_gps_monitor_1_dissector,
    [0x4e2c] = flightrec_gps_monitor_2_dissector,
    [0x4e2d] = flightrec_gps_monitor_3_dissector,
    [0x0883] = flightrec_adaptive_roll_dissector,
    [0x0884] = flightrec_adaptive_pitch_dissector,
    [0x0885] = flightrec_fw_g_api_dissector,
    [0x0887] = flightrec_fw_param_ekf_dissector,
    [0x27e2] = flightrec_ex_raw_airspeed_dissector,
    [0x5000] = flightrec_vibrate_detect_gyro_dissector,
    [0x500a] = flightrec_airprot_limit_data_dissector,
    [0x500b] = flightrec_adv_fl_limit_data_dissector,
    [0x0888] = flightrec_db_subscription_dissector,
    [0x504b] = flightrec_lost_sats_go_home_send_package_dissector,
    [0x504c] = flightrec_lost_sats_go_home_recv_package_dissector,
    [0x504d] = flightrec_adsb_osd_info_dissector,
    [0x092a] = flightrec_link_host_dissector,
    [0x092b] = flightrec_link_pc_dissector,
    [0x092c] = flightrec_link_vo_dissector,
    [0x092d] = flightrec_link_sdk_dissector,
    [0x092e] = flightrec_link_ofdm_dissector,
    [0x092f] = flightrec_link_bat_dissector,
    [0x0930] = flightrec_link_auto_cali_dissector,
    [0x0931] = flightrec_link_cali_led_dissector,
    [0x0932] = flightrec_link_manual_cali_dissector,
    [0x0933] = flightrec_ipc0_dissector,
    [0xcde0] = flightrec_system_monitor_dissector,
    [0xcddf] = flightrec_uart_monitor_dissector,
    [0xcdde] = flightrec_can_monitor_dissector,
    [0x8000] = flightrec_fly_log_dissector,
    [0xff00] = flightrec_sd_logs_dissector,
    [0xffff] = flightrec_sys_cfg_dissector,
    [0xfffe] = flightrec_uno_log_dissector,
    [0xfffd] = flightrec_cfg_log_dissector,
    [0xfffc] = flightrec_module_name_dissector,
}

-- [0]  Start of Pkt, always 0x55
f.delimiter = ProtoField.uint8 ("dji_mavic_flyrec.delimiter", "Delimiter", base.HEX)
-- [1]  Length of Pkt 
f.length = ProtoField.uint16 ("dji_mavic_flyrec.length", "Length", base.HEX, nil, 0x3FF)
-- [2]  Protocol version
f.protocol_version = ProtoField.uint16 ("dji_mavic_flyrec.protover", "Protocol Version", base.HEX, nil, 0xFC00)
-- [3]  Data Type
f.datatype = ProtoField.uint8 ("dji_mavic_flyrec.hdr_crc", "Header CRC", base.HEX)

-- Fields for ProtoVer = 0 (Flight Record)

-- [4-5]  Log Entry Type
f.etype = ProtoField.uint16 ("dji_mavic_flyrec.etype", "Log Entry Type", base.HEX, DJI_MAVIC_FLIGHT_RECORD_ENTRY_TYPE)
-- [6-9]  Sequence Ctr
f.seqctr = ProtoField.uint16 ("dji_mavic_flyrec.seqctr", "Seq Counter", base.DEC)
-- [B] Payload (optional)
f.payload = ProtoField.bytes ("dji_mavic_flyrec.payload", "Payload", base.SPACE)

-- [B+Payload] CRC
f.crc = ProtoField.uint16 ("dji_mavic_flyrec.crc", "CRC", base.HEX)

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
function dji_mavic_flyrec_main_dissector(buffer, pinfo, subtree)
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
            local dissector = DJI_MAVIC_FLIGHT_RECORD_DISSECT[etype]

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
function DJI_MAVIC_FLYREC_PROTO.dissector (buffer, pinfo, tree)

    local subtree = tree:add (DJI_MAVIC_FLYREC_PROTO, buffer())

    -- The Pkt start byte
    local offset = 0

    local pkt_type = buffer(offset,1):uint()
    subtree:add (f.delimiter, buffer(offset, 1))
    offset = offset + 1

    if pkt_type == 0x55 then
        dji_mavic_flyrec_main_dissector(buffer, pinfo, subtree)
    end

end

-- A initialization routine
function DJI_MAVIC_FLYREC_PROTO.init ()
end
