local f = DJI_P3_PROTO.fields

DJI_P3_FLIGHT_RECORD_ENTRY_TYPE = {
    [0x0000] = 'Rc Func Data',
    [0x0001] = 'Imu Atti 0',
    [0x0007] = 'Imu Data',
    [0x000c] = 'Telemetry',
    [0x000d] = 'unkn0D',
    [0x0011] = 'Battery Info',
    [0x8000] = 'Fly Log',
    [0xff00] = 'RC Log',
    [0xfffa] = 'Tcx Log',
    [0xfffe] = 'MC Log',
    [0xffff] = 'Sys Cfg',
}

-- Flight log - Rc Func Data - 0x0000

f.rec_rc_func_status = ProtoField.int32 ("dji_p3.rec_rc_func_status", "Status", base.DEC)
f.rec_rc_func_data_a = ProtoField.int16 ("dji_p3.rec_rc_func_data_a", "CH0 Aileron", base.DEC)
f.rec_rc_func_data_e = ProtoField.int16 ("dji_p3.rec_rc_func_data_e", "CH1 Elevator", base.DEC)
f.rec_rc_func_data_t = ProtoField.int16 ("dji_p3.rec_rc_func_data_t", "CH2 Throttle", base.DEC)
f.rec_rc_func_data_r = ProtoField.int16 ("dji_p3.rec_rc_func_data_r", "CH3 Rudder", base.DEC)
f.rec_rc_func_data_chmode = ProtoField.int16 ("dji_p3.rec_rc_func_data_chmode", "CH4 Mode", base.DEC)
f.rec_rc_func_data_ioc = ProtoField.int16 ("dji_p3.rec_rc_func_data_ioc", "CH5 IOC", base.DEC)
f.rec_rc_func_data_gohome = ProtoField.int16 ("dji_p3.rec_rc_func_data_gohome", "CH6 GoHome", base.DEC)
f.rec_rc_func_data_d4 = ProtoField.int16 ("dji_p3.rec_rc_func_data_d4", "CH21 D4", base.DEC)
f.rec_rc_func_data_x18 = ProtoField.int16 ("dji_p3.rec_rc_func_data_x18", "CH24 ?", base.DEC)
f.rec_rc_func_data_x17 = ProtoField.int16 ("dji_p3.rec_rc_func_data_x17", "CH23 ?", base.DEC)
f.rec_rc_func_data_x19 = ProtoField.int16 ("dji_p3.rec_rc_func_data_x19", "CH25 ?", base.DEC)
f.rec_rc_func_data_x1A = ProtoField.int16 ("dji_p3.rec_rc_func_data_x1A", "CH26 ?", base.DEC)
f.rec_rc_func_data_cmdmd = ProtoField.int8 ("dji_p3.rec_rc_func_data_cmdmd", "Control Command mode", base.DEC)
f.rec_rc_func_data_realmd = ProtoField.int8 ("dji_p3.rec_rc_func_data_realmd", "Control Real mode", base.DEC)
f.rec_rc_func_data_fld5 = ProtoField.int8 ("dji_p3.rec_rc_func_data_fld5", "Real Status Field5", base.DEC)
f.rec_rc_func_data_rc_state = ProtoField.int8 ("dji_p3.rec_rc_func_data_rc_state", "RC State", base.DEC)
f.rec_rc_func_data_fallow_mot = ProtoField.int8 ("dji_p3.rec_rc_func_data_fallow_mot", "Force Allow Start Motors", base.DEC)
f.rec_rc_func_data_unkn21 = ProtoField.int32 ("dji_p3.rec_rc_func_data_unkn21", "Unknown x21", base.DEC)
f.rec_rc_func_data_mbat_ve = ProtoField.int16 ("dji_p3.rec_rc_func_data_mbat_ve", "Main Battery Voltage", base.DEC)
f.rec_rc_func_data_rctl_out_per = ProtoField.int8 ("dji_p3.rec_rc_func_data_rctl_out_per", "Real Ctl Out Per", base.DEC)
f.rec_rc_func_data_unkn28 = ProtoField.int8 ("dji_p3.rec_rc_func_data_unkn28", "Unknown x28", base.DEC)
f.rec_rc_func_data_hp_gpshl = ProtoField.int8 ("dji_p3.rec_rc_func_data_hp_gpshl", "Home Point GPS Coords Health", base.DEC)
f.rec_rc_func_data_unkn2A = ProtoField.int8 ("dji_p3.rec_rc_func_data_unkn2A", "Unknown x2A", base.DEC)

local function flightrec_rc_func_data_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.rec_rc_func_status, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_rc_func_data_a, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_rc_func_data_e, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_rc_func_data_t, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_rc_func_data_r, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_rc_func_data_chmode, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_rc_func_data_ioc, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_rc_func_data_gohome, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_rc_func_data_d4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_rc_func_data_x18, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_rc_func_data_x17, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_rc_func_data_x19, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_rc_func_data_x1A, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_rc_func_data_cmdmd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_rc_func_data_realmd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_rc_func_data_fld5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_rc_func_data_rc_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_rc_func_data_fallow_mot, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_rc_func_data_unkn21, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_rc_func_data_mbat_ve, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_rc_func_data_rctl_out_per, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_rc_func_data_unkn28, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_rc_func_data_hp_gpshl, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_rc_func_data_unkn2A, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 43) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Rc Func Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Rc Func Data: Payload size different than expected") end
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

    subtree:add_le (f.rec_imu_atti_0_long0, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.rec_imu_atti_0_lati0, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.rec_imu_atti_0_press0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_ax0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_ay0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_az0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_wx0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_wy0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_wz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_alti0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_qw0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_qx0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_qy0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_qz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_agx0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_agy0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_agz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_vgx0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_vgy0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_vgz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_gbx0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_gby0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_gbz0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_atti_0_mx0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_imu_atti_0_my0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_imu_atti_0_mz0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_imu_atti_0_tx0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_imu_atti_0_ty0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_imu_atti_0_tz0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_imu_atti_0_sensor_stat0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_imu_atti_0_filter_stat0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_imu_atti_0_svn0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_imu_atti_0_atti_cnt0, payload(offset, 2))
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

    subtree:add_le (f.rec_imu_data_gyro_tempx, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_data_gyro_tempy, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_imu_data_gyro_tempz, payload(offset, 4))
    offset = offset + 4

    offset = offset + 36

    if (offset ~= 48) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Imu Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Imu Data: Payload size different than expected") end
end

-- Flight log - Telemetry - 0x000c

f.rec_telemetry_lon = ProtoField.double ("dji_p3.rec_telemetry_lon", "Longitude", base.DEC)
f.rec_telemetry_lat = ProtoField.double ("dji_p3.rec_telemetry_lat", "Latitude", base.DEC)
f.rec_telemetry_height = ProtoField.int16 ("dji_p3.rec_telemetry_height", "Height", base.DEC) -- g_real.imu.field_18 * 10
f.rec_telemetry_unkn18 = ProtoField.int16 ("dji_p3.rec_telemetry_unkn18", "Unkn18", base.DEC) -- g_real.imu.field_38 * 10
f.rec_telemetry_unkn20 = ProtoField.int16 ("dji_p3.rec_telemetry_unkn20", "Unkn20", base.DEC) -- g_real.imu.field_3C * 10
f.rec_telemetry_unkn22 = ProtoField.int16 ("dji_p3.rec_telemetry_unkn22", "Unkn22", base.DEC) -- g_real.imu.field_40 * 10
f.rec_telemetry_pitch = ProtoField.int16 ("dji_p3.rec_telemetry_pitch", "Pitch", base.DEC)
f.rec_telemetry_roll = ProtoField.int16 ("dji_p3.rec_telemetry_roll", "Roll", base.DEC)
f.rec_telemetry_yaw = ProtoField.int16 ("dji_p3.rec_telemetry_yaw", "Yaw", base.DEC)
f.rec_telemetry_flyc_st = ProtoField.int8 ("dji_p3.rec_telemetry_flyc_st", "Flight Ctrl State", base.DEC)
f.rec_telemetry_app_func_cmd = ProtoField.int8 ("dji_p3.rec_telemetry_app_func_cmd", "App Function Command", base.DEC)
f.rec_telemetry_flags1 = ProtoField.uint32 ("dji_p3.rec_telemetry_flags1", "Flags1", base.HEX)
f.rec_telemetry_num_sats = ProtoField.int8 ("dji_p3.rec_telemetry_num_sats", "Positioning Satellites Count", base.DEC)
f.rec_telemetry_fld25 = ProtoField.int8 ("dji_p3.rec_telemetry_fld25", "Field25", base.DEC)
f.rec_telemetry_fld26 = ProtoField.int8 ("dji_p3.rec_telemetry_fld26", "Field26", base.DEC)
f.rec_telemetry_fld27 = ProtoField.int8 ("dji_p3.rec_telemetry_fld27", "Field27", base.DEC)
f.rec_telemetry_batt_rmcap = ProtoField.int8 ("dji_p3.rec_telemetry_batt_rmcap", "Battery Remaining Capacity", base.DEC)
f.rec_telemetry_fld29 = ProtoField.int8 ("dji_p3.rec_telemetry_fld29", "Field29", base.DEC)
f.rec_telemetry_fly_time = ProtoField.int16 ("dji_p3.rec_telemetry_fly_time", "Flight Time", base.DEC)
f.rec_telemetry_fld2C = ProtoField.int8 ("dji_p3.rec_telemetry_fld2C", "Field2C", base.DEC)
f.rec_telemetry_lv1_ve = ProtoField.uint8 ("dji_p3.rec_telemetry_lv1_ve", "Level 1 Voltage", base.DEC, nil, 0x7F)
f.rec_telemetry_lv1_fn = ProtoField.uint8 ("dji_p3.rec_telemetry_lv1_fn", "Level 1 Function", base.DEC, nil, 0x80)
f.rec_telemetry_lv2_ve = ProtoField.uint8 ("dji_p3.rec_telemetry_lv2_ve", "Level 2 Voltage", base.DEC, nil, 0x7F)
f.rec_telemetry_lv2_fn = ProtoField.uint8 ("dji_p3.rec_telemetry_lv2_fn", "Level 2 Function", base.DEC, nil, 0x80)
f.rec_telemetry_fld2F = ProtoField.int8 ("dji_p3.rec_telemetry_fld2F", "Field2F", base.DEC)
f.rec_telemetry_fld30 = ProtoField.int8 ("dji_p3.rec_telemetry_fld30", "Field30", base.DEC)
f.rec_telemetry_fld31 = ProtoField.int8 ("dji_p3.rec_telemetry_fld31", "Field31", base.DEC)

local function flightrec_telemetry_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.rec_telemetry_lon, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.rec_telemetry_lat, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.rec_telemetry_height, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_telemetry_unkn18, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_telemetry_unkn20, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_telemetry_unkn22, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_telemetry_pitch, payload(offset, 2))
    offset = offset + 2 -- = 0x1a

    subtree:add_le (f.rec_telemetry_roll, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_telemetry_yaw, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_telemetry_flyc_st, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_telemetry_app_func_cmd, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_telemetry_flags1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_telemetry_num_sats, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_telemetry_fld25, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_telemetry_fld26, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_telemetry_fld27, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_telemetry_batt_rmcap, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_telemetry_fld29, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_telemetry_fly_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_telemetry_fld2C, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_telemetry_lv1_ve, payload(offset, 1))
    subtree:add_le (f.rec_telemetry_lv1_fn, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_telemetry_lv2_ve, payload(offset, 1))
    subtree:add_le (f.rec_telemetry_lv2_fn, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_telemetry_fld2F, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_telemetry_fld30, payload(offset, 1)) -- hard-coded to 2
    offset = offset + 1

    subtree:add_le (f.rec_telemetry_fld31, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 50) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Telemetry: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Telemetry: Payload size different than expected") end
end

-- Flight log - unkn0D - 0x000d

f.rec_unkn0D_lon = ProtoField.double ("dji_p3.rec_unkn0D_lon", "Longitude", base.DEC)
f.rec_unkn0D_lat = ProtoField.double ("dji_p3.rec_unkn0D_lat", "Latitude", base.DEC)

local function flightrec_unkn0D_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.rec_unkn0D_lon, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.rec_unkn0D_lat, payload(offset, 8))
    offset = offset + 8

    offset = offset + 18

    if (offset ~= 34) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"unkn0D: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"unkn0D: Payload size different than expected") end
end

-- Flight log - Battery Info - 0x0011

f.rec_battery_info_dsg_cap = ProtoField.uint16 ("dji_p3.rec_battery_info_dsg_cap", "Design Capacity", base.DEC)
f.rec_battery_info_f_cap = ProtoField.uint16 ("dji_p3.rec_battery_info_f_cap", "Full Charge Cap", base.DEC)
f.rec_battery_info_r_cap = ProtoField.uint16 ("dji_p3.rec_battery_info_r_cap", "Remain Cap", base.DEC)
f.rec_battery_info_pack_ve = ProtoField.uint16 ("dji_p3.rec_battery_info_pack_ve", "Pack Voltage", base.DEC)
f.rec_battery_info_i = ProtoField.int16 ("dji_p3.rec_battery_info_i", "Current", base.DEC)
f.rec_battery_info_life_per = ProtoField.uint8 ("dji_p3.rec_battery_info_life_per", "Life Percentage", base.DEC)
f.rec_battery_info_cap_per = ProtoField.uint8 ("dji_p3.rec_battery_info_cap_per", "Capacity Percentage", base.DEC)
f.rec_battery_info_temp = ProtoField.int16 ("dji_p3.rec_battery_info_temp", "Temperature", base.DEC)
f.rec_battery_info_chrg_cnt = ProtoField.uint16 ("dji_p3.rec_battery_info_chrg_cnt", "Charge Cycle Count", base.DEC)
f.rec_battery_info_sn = ProtoField.uint16 ("dji_p3.rec_battery_info_sn", "Serial Number", base.HEX)
f.rec_battery_info_cell_ve_1 = ProtoField.uint16 ("dji_p3.rec_battery_cell_ve_1", "Cell 1 Voltage", base.DEC)
f.rec_battery_info_cell_ve_2 = ProtoField.uint16 ("dji_p3.rec_battery_cell_ve_2", "Cell 2 Voltage", base.DEC)
f.rec_battery_info_cell_ve_3 = ProtoField.uint16 ("dji_p3.rec_battery_cell_ve_3", "Cell 3 Voltage", base.DEC)
f.rec_battery_info_cell_ve_4 = ProtoField.uint16 ("dji_p3.rec_battery_cell_ve_4", "Cell 4 Voltage", base.DEC)
f.rec_battery_info_cell_ve_5 = ProtoField.uint16 ("dji_p3.rec_battery_cell_ve_5", "Cell 5 Voltage", base.DEC)
f.rec_battery_info_cell_ve_6 = ProtoField.uint16 ("dji_p3.rec_battery_cell_ve_6", "Cell 6 Voltage", base.DEC)
f.rec_battery_info_ave_i = ProtoField.int16 ("dji_p3.rec_battery_info_ave_i", "Average Current", base.DEC)
f.rec_battery_info_right = ProtoField.uint8 ("dji_p3.rec_battery_info_right", "Right", base.HEX)
f.rec_battery_info_err_cnt = ProtoField.uint8 ("dji_p3.rec_battery_info_err_cnt", "Error Count", base.DEC)
f.rec_battery_info_unkn22 = ProtoField.uint8 ("dji_p3.rec_battery_info_unkn22", "Unkn22", base.HEX)
f.rec_battery_info_unkn23 = ProtoField.uint16 ("dji_p3.rec_battery_info_unkn23", "Unkn23", base.HEX)
f.rec_battery_info_disch_cnt = ProtoField.uint32 ("dji_p3.rec_battery_info_disch_cnt", "Discharge Times Count", base.DEC)
f.rec_battery_info_unkn29 = ProtoField.int32 ("dji_p3.rec_battery_info_unkn29", "unkn29", base.DEC)

local function flightrec_battery_info_dissector(payload, pinfo, subtree)
    local offset = 0

    subtree:add_le (f.rec_battery_info_dsg_cap, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_battery_info_f_cap, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_battery_info_r_cap, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_battery_info_pack_ve, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_battery_info_i, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_battery_info_life_per, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_battery_info_cap_per, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_battery_info_temp, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_battery_info_chrg_cnt, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_battery_info_sn, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_battery_info_cell_ve_1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_battery_info_cell_ve_2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_battery_info_cell_ve_3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_battery_info_cell_ve_4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_battery_info_cell_ve_5, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_battery_info_cell_ve_6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_battery_info_ave_i, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_battery_info_right, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_battery_info_err_cnt, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_battery_info_unkn22, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rec_battery_info_unkn23, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rec_battery_info_disch_cnt, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rec_battery_info_unkn29, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 45) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Battery Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Battery Info: Payload size different than expected") end
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
    [0x0011] = flightrec_battery_info_dissector,
    [0x8000] = flightrec_fly_log_dissector,
    [0xff00] = flightrec_sys_cfg_dissector,
    [0xfffa] = flightrec_sys_cfg_dissector,
    [0xfffe] = flightrec_sys_cfg_dissector,
    [0xffff] = flightrec_sys_cfg_dissector,
}
