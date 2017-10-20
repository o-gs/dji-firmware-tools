local f = DJI_P3_PROTO.fields

DJI_P3_FLIGHT_RECORD_ENTRY_TYPE = {
    [0x0000] = 'Rc Func Data',
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
    [0x8000] = flightrec_fly_log_dissector,
    [0xffff] = flightrec_sys_cfg_dissector,
}
