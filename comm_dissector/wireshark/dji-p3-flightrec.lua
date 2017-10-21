local f = DJI_P3_PROTO.fields

DJI_P3_FLIGHT_RECORD_ENTRY_TYPE = {
    [0x0000] = 'Rc Func Data',
    [0x0001] = 'Imu Atti 0',
    [0x0007] = 'Imu Data',
    [0x000c] = 'Telemetry',
    [0x000d] = 'unkn0D',
    [0x8000] = 'Fly Log',
    [0xffff] = 'Sys Cfg',
}

-- Flight log - Rc Func Data - 0x0000

f.rec_rc_func_data_a = ProtoField.int16 ("dji_p3.rec_rc_func_data_a", "Aileron", base.DEC)
f.rec_rc_func_data_e = ProtoField.int16 ("dji_p3.rec_rc_func_data_e", "Elevator", base.DEC)
f.rec_rc_func_data_t = ProtoField.int16 ("dji_p3.rec_rc_func_data_t", "Throttle", base.DEC)
f.rec_rc_func_data_r = ProtoField.int16 ("dji_p3.rec_rc_func_data_r", "Rudder", base.DEC)
f.rec_rc_func_data_u = ProtoField.int16 ("dji_p3.rec_rc_func_data_u", "U", base.DEC)
f.rec_rc_func_data_sw_mode = ProtoField.int8 ("dji_p3.rec_rc_func_data_sw_mode", "Mode Switch", base.DEC)
f.rec_rc_func_data_gps_health = ProtoField.int16 ("dji_p3.rec_rc_func_data_gps_health", "GPS Health", base.DEC) -- why would we have gps data here?

local function flightrec_rc_func_data_dissector(payload, pinfo, subtree)
    local offset = 0

    offset = offset + 4

    subtree:add (f.rec_rc_func_data_a, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_rc_func_data_e, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_rc_func_data_t, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_rc_func_data_r, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_rc_func_data_u, payload(offset, 2))
    offset = offset + 2

    offset = offset + 17

    subtree:add (f.rec_rc_func_data_sw_mode, payload(offset, 1))
    offset = offset + 1

    offset = offset + 9

    subtree:add (f.rec_rc_func_data_gps_health, payload(offset, 1))
    offset = offset + 1
end

-- Flight log - Imu Atti 0 - 0x0001

f.rec_imu_atti_0_long0 = ProtoField.double ("dji_p3.rec_imu_atti_0_long0", "Long0", base.DEC)
f.rec_imu_atti_0_lati0 = ProtoField.double ("dji_p3.rec_imu_atti_0_lati0", "Lati0", base.DEC)
f.rec_imu_atti_0_press0 = ProtoField.float ("dji_p3.rec_imu_atti_0_press0", "Press0", base.DEC)
f.rec_imu_atti_0_ax0 = ProtoField.float ("dji_p3.rec_imu_atti_0_ax0", "Accel x0", base.DEC)
f.rec_imu_atti_0_ay0 = ProtoField.float ("dji_p3.rec_imu_atti_0_ay0", "Accel y0", base.DEC)
f.rec_imu_atti_0_az0 = ProtoField.float ("dji_p3.rec_imu_atti_0_az0", "Accel z0", base.DEC)
f.rec_imu_atti_0_wx0 = ProtoField.float ("dji_p3.rec_imu_atti_0_wx0", "Gyro Wx0", base.DEC)
f.rec_imu_atti_0_wy0 = ProtoField.float ("dji_p3.rec_imu_atti_0_wy0", "Gyro Wy0", base.DEC)
f.rec_imu_atti_0_wz0 = ProtoField.float ("dji_p3.rec_imu_atti_0_wz0", "Gyro Wz0", base.DEC)
f.rec_imu_atti_0_alti0 = ProtoField.float ("dji_p3.rec_imu_atti_0_alti0", "Alti0", base.DEC)
f.rec_imu_atti_0_qw0 = ProtoField.float ("dji_p3.rec_imu_atti_0_qw0", "Quat w0", base.DEC)
f.rec_imu_atti_0_qx0 = ProtoField.float ("dji_p3.rec_imu_atti_0_qx0", "Quat x0", base.DEC)
f.rec_imu_atti_0_qy0 = ProtoField.float ("dji_p3.rec_imu_atti_0_qy0", "Quat y0", base.DEC)
f.rec_imu_atti_0_qz0 = ProtoField.float ("dji_p3.rec_imu_atti_0_qz0", "Quat z0", base.DEC)
f.rec_imu_atti_0_agx0 = ProtoField.float ("dji_p3.rec_imu_atti_0_agx0", "Accel gx0", base.DEC)
f.rec_imu_atti_0_agy0 = ProtoField.float ("dji_p3.rec_imu_atti_0_agy0", "Accel gy0", base.DEC)
f.rec_imu_atti_0_agz0 = ProtoField.float ("dji_p3.rec_imu_atti_0_agz0", "Accel gz0", base.DEC)
f.rec_imu_atti_0_vgx0 = ProtoField.float ("dji_p3.rec_imu_atti_0_vgx0", "Vel gx0", base.DEC)
f.rec_imu_atti_0_vgy0 = ProtoField.float ("dji_p3.rec_imu_atti_0_vgy0", "Vel gy0", base.DEC)
f.rec_imu_atti_0_vgz0 = ProtoField.float ("dji_p3.rec_imu_atti_0_vgz0", "Vel gz0", base.DEC)
f.rec_imu_atti_0_gbx0 = ProtoField.float ("dji_p3.rec_imu_atti_0_gbx0", "Gbx0", base.DEC)
f.rec_imu_atti_0_gby0 = ProtoField.float ("dji_p3.rec_imu_atti_0_gby0", "Gby0", base.DEC)
f.rec_imu_atti_0_gbz0 = ProtoField.float ("dji_p3.rec_imu_atti_0_gbz0", "Gbz0", base.DEC)
f.rec_imu_atti_0_mx0 = ProtoField.int16 ("dji_p3.rec_imu_atti_0_mx0", "Mag x0", base.DEC)
f.rec_imu_atti_0_my0 = ProtoField.int16 ("dji_p3.rec_imu_atti_0_my0", "Mag y0", base.DEC)
f.rec_imu_atti_0_mz0 = ProtoField.int16 ("dji_p3.rec_imu_atti_0_mz0", "Mag z0", base.DEC)
f.rec_imu_atti_0_tx0 = ProtoField.int16 ("dji_p3.rec_imu_atti_0_tx0", "Tx0", base.DEC)
f.rec_imu_atti_0_ty0 = ProtoField.int16 ("dji_p3.rec_imu_atti_0_ty0", "Ty0", base.DEC)
f.rec_imu_atti_0_tz0 = ProtoField.int16 ("dji_p3.rec_imu_atti_0_tz0", "Tz0", base.DEC)
f.rec_imu_atti_0_sensor_stat0 = ProtoField.uint16 ("dji_p3.rec_imu_atti_0_sensor_stat0", "Sensor Stat0", base.HEX)
f.rec_imu_atti_0_filter_stat0 = ProtoField.uint16 ("dji_p3.rec_imu_atti_0_filter_stat0", "Filter Stat0", base.HEX)
f.rec_imu_atti_0_svn0 = ProtoField.uint16 ("dji_p3.rec_imu_atti_0_svn0", "SVN Count0", base.DEC) -- Number of positioning satellites
f.rec_imu_atti_0_atti_cnt0 = ProtoField.uint16 ("dji_p3.rec_imu_atti_0_atti_cnt0", "Atti Cnt0", base.HEX)

local function flightrec_imu_atti_0_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add (f.rec_imu_atti_0_long0, payload(offset, 8))
    offset = offset + 8

    subtree:add (f.rec_imu_atti_0_lati0, payload(offset, 8))
    offset = offset + 8

    subtree:add (f.rec_imu_atti_0_press0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_ax0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_ay0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_az0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_wx0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_wy0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_wz0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_alti0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_qw0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_qx0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_qy0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_qz0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_agx0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_agy0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_agz0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_vgx0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_vgy0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_vgz0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_gbx0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_gby0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_gbz0, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_atti_0_mx0, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_imu_atti_0_my0, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_imu_atti_0_mz0, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_imu_atti_0_tx0, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_imu_atti_0_ty0, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_imu_atti_0_tz0, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_imu_atti_0_sensor_stat0, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_imu_atti_0_filter_stat0, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_imu_atti_0_svn0, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_imu_atti_0_atti_cnt0, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 120) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Atti 0: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Atti 0: Payload size different than expected") end
end

-- Flight log - Imu Data - 0x0007

f.rec_imu_data_gyro_tempx = ProtoField.float ("dji_p3.rec_imu_data_gyro_tempx", "Gyro Temp X", base.DEC)
f.rec_imu_data_gyro_tempy = ProtoField.float ("dji_p3.rec_imu_data_gyro_tempy", "Gyro Temp Y", base.DEC)
f.rec_imu_data_gyro_tempz = ProtoField.float ("dji_p3.rec_imu_data_gyro_tempz", "Gyro Temp Z", base.DEC)

local function flightrec_imu_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add (f.rec_imu_data_gyro_tempx, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_data_gyro_tempy, payload(offset, 4))
    offset = offset + 4

    subtree:add (f.rec_imu_data_gyro_tempz, payload(offset, 4))
    offset = offset + 4

    offset = offset + 36

    if (offset ~= 48) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Data: Payload size different than expected") end
end

-- Flight log - Telemetry - 0x000c

f.rec_telemetry_lon = ProtoField.double ("dji_p3.rec_telemetry_lon", "Longitude", base.DEC)
f.rec_telemetry_lat = ProtoField.double ("dji_p3.rec_telemetry_lat", "Latitude", base.DEC)
f.rec_telemetry_height = ProtoField.int16 ("dji_p3.rec_telemetry_height", "Height", base.DEC)
f.rec_telemetry_unkn18 = ProtoField.int16 ("dji_p3.rec_telemetry_unkn18", "Unkn18", base.DEC)
f.rec_telemetry_unkn20 = ProtoField.int16 ("dji_p3.rec_telemetry_unkn20", "Unkn20", base.DEC)
f.rec_telemetry_unkn22 = ProtoField.int16 ("dji_p3.rec_telemetry_unkn22", "Unkn22", base.DEC)
f.rec_telemetry_pitch = ProtoField.int16 ("dji_p3.rec_telemetry_pitch", "Pitch", base.DEC)
f.rec_telemetry_roll = ProtoField.int16 ("dji_p3.rec_telemetry_roll", "Roll", base.DEC)
f.rec_telemetry_yaw = ProtoField.int16 ("dji_p3.rec_telemetry_yaw", "Yaw", base.DEC)
f.rec_telemetry_flyc_st = ProtoField.int16 ("dji_p3.rec_telemetry_flyc_st", "Flight Ctrl State", base.DEC)
f.rec_telemetry_fly_time = ProtoField.int16 ("dji_p3.rec_telemetry_fly_time", "Flight Time", base.DEC)

local function flightrec_telemetry_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add (f.rec_telemetry_lon, payload(offset, 8))
    offset = offset + 8

    subtree:add (f.rec_telemetry_lat, payload(offset, 8))
    offset = offset + 8

    subtree:add (f.rec_telemetry_height, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_telemetry_unkn18, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_telemetry_unkn20, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_telemetry_unkn22, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_telemetry_pitch, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_telemetry_roll, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_telemetry_yaw, payload(offset, 2))
    offset = offset + 2

    subtree:add (f.rec_telemetry_flyc_st, payload(offset, 1))
    offset = offset + 1

    offset = offset + 7

    -- failure info here
    offset = offset + 4

    subtree:add (f.rec_telemetry_fly_time, payload(offset, 2))
    offset = offset + 2

    -- 6 one-byte values
    offset = offset + 6

    if (offset ~= 50) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Telemetry: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Telemetry: Payload size different than expected") end
end

-- Flight log - unkn0D - 0x000d

local function flightrec_unkn0D_dissector(payload, pinfo, subtree)
    local offset = 0

    offset = offset + 34

    if (offset ~= 34) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"unkn0D: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"unkn0D: Payload size different than expected") end
end

-- Flight log - Fly Log - 0x8000

f.rec_fly_log_text = ProtoField.string ("dji_p3.rec_fly_log_text", "Fly Log", base.ASCII)

local function flightrec_fly_log_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add (f.rec_fly_log_text, payload(offset, payload:len() - offset))
end

-- Flight log - Sys Cfg - 0xffff

f.rec_sys_cfg_text = ProtoField.string ("dji_p3.rec_sys_cfg_text", "Sys Cfg", base.ASCII)

local function flightrec_sys_cfg_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add (f.rec_sys_cfg_text, payload(offset, payload:len() - offset))
end

DJI_P3_FLIGHT_RECORD_DISSECT = {
    [0x0000] = flightrec_rc_func_data_dissector,
    [0x0001] = flightrec_imu_atti_0_dissector,
    [0x0007] = flightrec_imu_data_dissector,
    [0x000c] = flightrec_telemetry_dissector,
    [0x000d] = flightrec_unkn0D_dissector,
    [0x8000] = flightrec_fly_log_dissector,
    [0xffff] = flightrec_sys_cfg_dissector,
}
