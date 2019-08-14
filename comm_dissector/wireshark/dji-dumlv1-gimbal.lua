-- The definitions in this file are part of DJI DUMLv1 protocol dissector
-- Dissectors for command set 0x04 - Gimbal

local f = DJI_DUMLv1_PROTO.fields
local enums = {}

-- CMD name decode table

GIMBAL_UART_CMD_TEXT = {
    [0x00] = 'Gimbal Reserved',
    [0x01] = 'Gimbal Control',
    [0x02] = 'Gimbal Get Position',
    [0x03] = 'Gimbal Set Param',
    [0x04] = 'Gimbal Get Param',
    [0x05] = 'Gimbal Params Get', -- Push Position
    [0x06] = 'Gimbal Push AETR',
    [0x07] = 'Gimbal Adjust Roll', -- Roll Finetune
    [0x08] = 'Gimbal Calibration', -- AutoCalibration
    [0x09] = 'Gimbal Reserved2',
    [0x0A] = 'Gimbal Ext Ctrl Degree', -- Rotate/Angle Set
    [0x0B] = 'Gimbal Get Ext Ctrl Status', -- Get State
    [0x0C] = 'Gimbal Ext Ctrl Accel', -- Speed Control
    [0x0D] = 'Gimbal Suspend/Resume', -- Set On Or Off
    [0x0E] = 'Gimbal Thirdp Magn',
    [0x0F] = 'Gimbal User Params Set',
    [0x10] = 'Gimbal User Params Get',
    [0x11] = 'Gimbal User Params Save',
    [0x13] = 'Gimbal User Params Reset Default', -- Resume Default Param
    [0x14] = 'Gimbal Abs Angle Control',
    [0x15] = 'Gimbal Movement',
    [0x1C] = 'Gimbal Type Get',
    [0x1E] = 'Gimbal Degree Info Subscription',
    [0x20] = 'Gimbal TBD 20',
    [0x21] = 'Gimbal TBD 21',
    [0x24] = 'Gimbal User Params Get',
    [0x27] = 'Gimbal Abnormal Status Get',
    [0x2b] = 'Gimbal Tutorial Status Get',
    [0x2c] = 'Gimbal Tutorial Step Set',
    [0x30] = 'Gimbal Auto Calibration Status',
    [0x31] = 'Robin Params Set',
    [0x32] = 'Robin Params Get',
    [0x33] = 'Robin Battery Info Push', -- Gimbal Battery Info
    [0x34] = 'Gimbal Handle Params Set',
    [0x36] = 'Gimbal Handle Params Get',
    [0x37] = 'Gimbal Timelapse Params Set',
    [0x38] = 'Gimbal Timelapse Status',
    [0x39] = 'Gimbal Lock',
    [0x3A] = 'Gimbal Rotate Camera X Axis',
    [0x45] = 'Gimbal Get Temp',
    [0x47] = 'Gimbal TBD 47',
    [0x4c] = 'Gimbal Reset And Set Mode',
    [0x56] = 'Gimbal NotiFy Camera Id',
    [0x57] = 'Handheld Stick State Get/Push',
    [0x58] = 'Handheld Stick Control Set', -- Handheld Stick Control Enable
}

-- Gimbal - Gimbal Control - 0x01
-- Description: Sets 3 values from packet within gimbal RAM, each in range 363..1685. On P3X, no ACK possible.
-- Supported in: P3X_FW_V01.11.0030_m0400

f.gimbal_control_unkn0 = ProtoField.uint16 ("dji_dumlv1.gimbal_control_unkn0", "Unknown0", base.DEC, nil, nil, "Accepted values 363..1685")
f.gimbal_control_unkn1 = ProtoField.uint16 ("dji_dumlv1.gimbal_control_unkn1", "Unknown1", base.DEC, nil, nil, "Accepted values 363..1685")
f.gimbal_control_unkn2 = ProtoField.uint16 ("dji_dumlv1.gimbal_control_unkn2", "Unknown2", base.DEC, nil, nil, "Accepted values 363..1685")
f.gimbal_control_padding = ProtoField.bytes ("dji_dumlv1.gimbal_control_padding", "Padding", base.SPACE, nil, nil, "Unused")

local function gimbal_control_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

        subtree:add_le (f.gimbal_control_unkn0, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.gimbal_control_unkn1, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.gimbal_control_unkn2, payload(offset, 2))
        offset = offset + 2

        -- Padding will be used in encrypted payloads
        if (payload:len() >= 8) then
            subtree:add_le (f.gimbal_control_padding, payload(offset, 2))
            offset = offset + 2
        end

    if (offset ~= 6) and (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Control: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Control: Payload size different than expected") end
end

-- Gimbal - Gimbal Get Position - 0x02
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_get_position_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_get_position_unknown0", "Unknown0", base.DEC, nil, nil)

local function gimbal_get_position_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --subtree:add_le (f.gimbal_get_position_unknown0, payload(offset, 1))
    --offset = offset + 1

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Get Position: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Get Position: Payload size different than expected") end
end

-- Gimbal - Gimbal Set Param - 0x03
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_set_param_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_set_param_unknown0", "Unknown0", base.DEC, nil, nil)

local function gimbal_set_param_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --subtree:add_le (f.gimbal_set_param_unknown0, payload(offset, 1))
    --offset = offset + 1

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Set Param: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Set Param: Payload size different than expected") end
end

-- Gimbal - Gimbal Get Param - 0x04
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_get_param_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_get_param_unknown0", "Unknown0", base.DEC, nil, nil)

local function gimbal_get_param_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --subtree:add_le (f.gimbal_get_param_unknown0, payload(offset, 1))
    --offset = offset + 1

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Get Param: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Get Param: Payload size different than expected") end
end

-- Gimbal - Gimbal Params Get / Push Position - 0x05
-- Description: TODO.
-- Supported in: WM620_FW_01.02.0300

enums.GIMBAL_PARAMS_MODE_ENUM = {
    [0x00] = 'YawNoFollow',
    [0x01] = 'FPV',
    [0x02] = 'YawFollow',
    [0x03] = 'AutoCalibrate',
    -- In P3X, higher modes are not visible due to mask applied to the value
    [0x64] = 'OTHER',
}

f.gimbal_params_pitch = ProtoField.int16 ("dji_dumlv1.gimbal_params_pitch", "Gimbal Pitch", base.DEC, nil, nil, "0.1 degree, gimbal angular position, zero is forward, max down..up is about -900..470")
f.gimbal_params_roll = ProtoField.int16 ("dji_dumlv1.gimbal_params_roll", "Gimbal Roll", base.DEC, nil, nil, "0.1 degree, gimbal angular position, zero is parallel to earth, max right..left is about -410..410")
f.gimbal_params_yaw = ProtoField.int16 ("dji_dumlv1.gimbal_params_yaw", "Gimbal Yaw", base.DEC, nil, nil, "0.1 degree, gimbal angular position, -1000 is forward, max right..left is about -1460..-540") -- TODO verify
f.gimbal_params_masked06 = ProtoField.uint8 ("dji_dumlv1.gimbal_params_masked06", "Masked06", base.HEX)
  f.gimbal_params_sub_mode = ProtoField.uint8 ("dji_dumlv1.gimbal_params_sub_mode", "Sub Mode", base.HEX, nil, 0x20, nil)
  f.gimbal_params_mode = ProtoField.uint8 ("dji_dumlv1.gimbal_params_mode", "Mode", base.HEX, enums.GIMBAL_PARAMS_MODE_ENUM, 0xc0, nil)
f.gimbal_params_roll_adjust = ProtoField.int8 ("dji_dumlv1.gimbal_params_roll_adjust", "Roll Adjust", base.DEC)
f.gimbal_params_yaw_angle = ProtoField.uint16 ("dji_dumlv1.gimbal_params_yaw_angle", "Yaw Angle", base.HEX, nil, nil, "Not sure whether Yaw angle or Joytick Direction")
  f.gimbal_params_joystick_ver_direction = ProtoField.uint16 ("dji_dumlv1.gimbal_params_joystick_ver_direction", "Joystick Ver Direction", base.HEX, nil, 0x03, nil)
  f.gimbal_params_joystick_hor_direction = ProtoField.uint16 ("dji_dumlv1.gimbal_params_joystick_hor_direction", "Joystick Hor Direction", base.HEX, nil, 0x0c, nil)
f.gimbal_params_masked0a = ProtoField.uint8 ("dji_dumlv1.gimbal_params_masked0a", "Masked0A", base.HEX)
  f.gimbal_params_pitch_in_limit = ProtoField.uint8 ("dji_dumlv1.gimbal_params_pitch_in_limit", "Pitch In Limit", base.HEX, nil, 0x01, "Pitch arm is beyond its limit positions")
  f.gimbal_params_roll_in_limit = ProtoField.uint8 ("dji_dumlv1.gimbal_params_roll_in_limit", "Roll In Limit", base.HEX, nil, 0x02, "Roll arm is beyond its limit positions")
  f.gimbal_params_yaw_in_limit = ProtoField.uint8 ("dji_dumlv1.gimbal_params_yaw_in_limit", "Yaw In Limit", base.HEX, nil, 0x04, "Yaw arm is beyond its limit positions")
  f.gimbal_params_auto_calibration = ProtoField.uint8 ("dji_dumlv1.gimbal_params_auto_calibration", "Auto Calibration", base.HEX, nil, 0x08, "Auto calibration in progress")
  f.gimbal_params_auto_calibration_result = ProtoField.uint8 ("dji_dumlv1.gimbal_params_auto_calibration_result", "Auto Calibration Result", base.HEX, nil, 0x10, nil)
  f.gimbal_params_stuck = ProtoField.uint8 ("dji_dumlv1.gimbal_params_stuck", "Stuck", base.HEX, nil, 0x40, nil)
f.gimbal_params_masked0b = ProtoField.uint8 ("dji_dumlv1.gimbal_params_masked0b", "Masked0B", base.HEX)
  f.gimbal_params_version = ProtoField.uint8 ("dji_dumlv1.gimbal_params_version", "Version", base.HEX, nil, 0x0f, nil)
  f.gimbal_params_double_click = ProtoField.uint8 ("dji_dumlv1.gimbal_params_double_click", "Double Click", base.HEX, nil, 0x20, nil)
  f.gimbal_params_triple_click = ProtoField.uint8 ("dji_dumlv1.gimbal_params_triple_click", "Triple Click", base.HEX, nil, 0x40, nil)
  f.gimbal_params_single_click = ProtoField.uint8 ("dji_dumlv1.gimbal_params_single_click", "Single Click", base.HEX, nil, 0x80, nil)
f.gimbal_params_unkn0c = ProtoField.uint32 ("dji_dumlv1.gimbal_params_unkn0c", "Unknown0c", base.HEX)
f.gimbal_params_unkn10 = ProtoField.uint32 ("dji_dumlv1.gimbal_params_unkn10", "Unknown10-i32", base.HEX)
f.gimbal_params_unkn10b = ProtoField.bytes ("dji_dumlv1.gimbal_params_unkn10", "Unknown10-bt", base.SPACE)
f.gimbal_params_unkn14 = ProtoField.uint32 ("dji_dumlv1.gimbal_params_unkn14", "Unknown14", base.HEX)

local function gimbal_params_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_params_pitch, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_params_roll, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_params_yaw, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_params_masked06, payload(offset, 1))
    subtree:add_le (f.gimbal_params_sub_mode, payload(offset, 1))
    subtree:add_le (f.gimbal_params_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_params_roll_adjust, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_params_yaw_angle, payload(offset, 2))
    subtree:add_le (f.gimbal_params_joystick_ver_direction, payload(offset, 2))
    subtree:add_le (f.gimbal_params_joystick_hor_direction, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_params_masked0a, payload(offset, 1))
    subtree:add_le (f.gimbal_params_pitch_in_limit, payload(offset, 1))
    subtree:add_le (f.gimbal_params_roll_in_limit, payload(offset, 1))
    subtree:add_le (f.gimbal_params_yaw_in_limit, payload(offset, 1))
    subtree:add_le (f.gimbal_params_auto_calibration, payload(offset, 1))
    subtree:add_le (f.gimbal_params_auto_calibration_result, payload(offset, 1))
    subtree:add_le (f.gimbal_params_stuck, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_params_masked0b, payload(offset, 1))
    subtree:add_le (f.gimbal_params_version, payload(offset, 1))
    subtree:add_le (f.gimbal_params_double_click, payload(offset, 1))
    subtree:add_le (f.gimbal_params_triple_click, payload(offset, 1))
    subtree:add_le (f.gimbal_params_single_click, payload(offset, 1))
    offset = offset + 1

    -- Found additional 12 bytes in packet from WM620
    if (payload:len() >= offset + 12) then

        subtree:add_le (f.gimbal_params_unkn0c, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.gimbal_params_unkn10, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.gimbal_params_unkn14, payload(offset, 4))
        offset = offset + 4

    elseif (payload:len() >= offset + 7) then

        subtree:add_le (f.gimbal_params_unkn0c, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.gimbal_params_unkn10b, payload(offset, 3))
        offset = offset + 3

    end

    if (offset ~= 12) and (offset ~= 19) and (offset ~= 24) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Params: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Params: Payload size different than expected") end
end

-- Gimbal - Gimbal Push AETR - 0x06
-- Description: Sets Aileron, Elevator, Throttle and Rudder, each in range 364..1684. On P3X, no ACK possible.
-- Supported in: P3X_FW_V01.11.0030_m0400

f.gimbal_push_aetr_unkn0 = ProtoField.uint16 ("dji_dumlv1.gimbal_push_aetr_unkn0", "Unknown0", base.DEC, nil, nil, "Accepted values are 364..1684")
f.gimbal_push_aetr_unkn1 = ProtoField.uint16 ("dji_dumlv1.gimbal_push_aetr_unkn1", "Unknown1", base.DEC, nil, nil, "Accepted values are 364..1684")
f.gimbal_push_aetr_unkn2 = ProtoField.uint16 ("dji_dumlv1.gimbal_push_aetr_unkn2", "Unknown2", base.DEC, nil, nil, "Accepted values are 364..1684")
f.gimbal_push_aetr_unkn3 = ProtoField.uint16 ("dji_dumlv1.gimbal_push_aetr_unkn3", "Unknown3", base.DEC, nil, nil, "Accepted values are 364..1684")

local function gimbal_push_aetr_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

        subtree:add_le (f.gimbal_push_aetr_unkn0, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.gimbal_push_aetr_unkn1, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.gimbal_push_aetr_unkn2, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.gimbal_push_aetr_unkn3, payload(offset, 2))
        offset = offset + 2

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Push AETR: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Push AETR: Payload size different than expected") end
end

-- Gimbal - Gimbal Adjust Roll / Roll Finetune - 0x07
-- Description: Receives a value from packet and shifts internal roll adjustment by it. The adjustment is not saved into persistent storage.
-- Supported in: P3X_FW_V01.11.0030_m0400

f.gimbal_adjust_roll_adjustment_val = ProtoField.int8 ("dji_dumlv1.gimbal_adjust_roll_adjustment_val", "Adjustment Value", base.DEC, nil, nil)

local function gimbal_adjust_roll_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

        subtree:add_le (f.gimbal_adjust_roll_adjustment_val, payload(offset, 1))
        offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Adjust Roll: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Adjust Roll: Payload size different than expected") end
end

-- Gimbal - Gimbal Calibration - 0x08
-- Description: On Ph3 starts auto-calibration, the same which can be triggered by mobile app; calibrates only 2 axes.
-- On Spark starts one of given calibration routines.
-- Supported in: P3X_FW_V01.11.0030_m0400 (with no cmd selection)

enums.GIMBAL_CALIBRATE_CMD_ENUM = {
    [0x00] = 'JointCoarse',
    [0x01] = 'LinearHall',
}

f.gimbal_calibrate_cmd = ProtoField.uint8 ("dji_dumlv1.gimbal_calibrate_cmd", "Calib. Command", base.DEC, enums.GIMBAL_CALIBRATE_CMD_ENUM, nil)
f.gimbal_calibrate_status1 = ProtoField.uint8 ("dji_dumlv1.gimbal_calibrate_status1", "Calib. Status1", base.DEC, nil, nil)
f.gimbal_calibrate_status2 = ProtoField.uint8 ("dji_dumlv1.gimbal_calibrate_status2", "Calib. Status2", base.DEC, nil, nil)

local function gimbal_calibrate_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    -- Usually we use pack_type to differentiate between request and respone; on WM100_FW_V01.00.0900 it does not work
    if (payload:len() <= 1) then -- Request
        subtree:add_le (f.gimbal_calibrate_cmd, payload(offset, 1))
        offset = offset + 1

        if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Calibration: Offset does not match - internal inconsistency") end
    else -- Response (but response bit not set)
        subtree:add_le (f.gimbal_calibrate_status1, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.gimbal_calibrate_status2, payload(offset, 1))
        offset = offset + 1

        if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Calibration: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Calibration: Payload size different than expected") end
end

-- Gimbal - Gimbal Reserved2 - 0x09
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_reserved2_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_reserved2_unknown0", "Unknown0", base.DEC, nil, nil)

local function gimbal_reserved2_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --subtree:add_le (f.gimbal_reserved2_unknown0, payload(offset, 1))
    --offset = offset + 1

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Reserved2: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Reserved2: Payload size different than expected") end
end

-- Gimbal - Gimbal Ext Ctrl Degree / Rotate/Angle Set - 0x0a
-- Description: Sets 3 angular values and 3 additional values from packet within gimbal RAM. In P3X, resets values from packet 0x20 to 1 if ACK was requested.
-- Supported in: P3X_FW_V01.11.0030_m0400

f.gimbal_ext_ctrl_degree_unknown0 = ProtoField.int16 ("dji_dumlv1.gimbal_ext_ctrl_degree_unknown0", "Unknown0", base.DEC, nil, nil, "angle in degrees * 10, range -1800..1800")
f.gimbal_ext_ctrl_degree_unknown2 = ProtoField.int16 ("dji_dumlv1.gimbal_ext_ctrl_degree_unknown2", "Unknown2", base.DEC, nil, nil, "angle in degrees * 10, range -1800..1800")
f.gimbal_ext_ctrl_degree_unknown4 = ProtoField.int16 ("dji_dumlv1.gimbal_ext_ctrl_degree_unknown4", "Unknown4", base.DEC, nil, nil, "angle in degrees * 10, range -1800..1800")
f.gimbal_ext_ctrl_degree_unknown6 = ProtoField.int16 ("dji_dumlv1.gimbal_ext_ctrl_degree_unknown6", "Unknown6", base.DEC, nil, nil, "unknown unit * 100")
f.gimbal_ext_ctrl_degree_unknown8 = ProtoField.uint8 ("dji_dumlv1.gimbal_ext_ctrl_degree_unknown8", "Unknown8", base.HEX, nil, nil, "flag fields")
f.gimbal_ext_ctrl_degree_unknown9 = ProtoField.uint8 ("dji_dumlv1.gimbal_ext_ctrl_degree_unknown9", "Unknown9", base.HEX, nil, nil, "unknown unit / 2000, range 1..10")

local function gimbal_ext_ctrl_degree_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_ext_ctrl_degree_unknown0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_ext_ctrl_degree_unknown2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_ext_ctrl_degree_unknown4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_ext_ctrl_degree_unknown6, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_ext_ctrl_degree_unknown8, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_ext_ctrl_degree_unknown9, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 7) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Ext Ctrl Degree: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Ext Ctrl Degree: Payload size different than expected") end
end

-- Gimbal - Gimbal Ext Ctrl Status - 0x0b
-- Description: In response to this request, gimbal returns a flag field and int value representing current ctrl status.
-- Supported in: P3X_FW_V01.11.0030_m0400

f.gimbal_ext_ctrl_status_status = ProtoField.uint8 ("dji_dumlv1.gimbal_ext_ctrl_status_status", "Status", base.HEX, nil, nil, "Request processing status; always 0.")
f.gimbal_ext_ctrl_status_flags = ProtoField.uint8 ("dji_dumlv1.gimbal_ext_ctrl_status_flags", "Flags", base.HEX, nil, nil, "Only the top bit is meaningful, the rest is garbage")
f.gimbal_ext_ctrl_status_unknown2 = ProtoField.int16 ("dji_dumlv1.gimbal_ext_ctrl_status_unknown2", "Unknown2", base.DEC, nil, nil)

local function gimbal_ext_ctrl_status_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request

        -- No payload needed

        if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Ext Ctrl Status: Offset does not match - internal inconsistency") end
    else -- Response

        subtree:add_le (f.gimbal_ext_ctrl_status_status, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.gimbal_ext_ctrl_status_flags, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.gimbal_ext_ctrl_status_unknown2, payload(offset, 2))
        offset = offset + 2

        if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Ext Ctrl Status: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Ext Ctrl Status: Payload size different than expected") end
end

-- Gimbal - Gimbal Ext Ctrl Accel / Speed Control - 0x0c
-- Description: Sets angular accelerations of each gimbal axis.
-- Supported in: P3X_FW_V01.11.0030_m0400

f.gimbal_ext_ctrl_accel_unknown0 = ProtoField.int16 ("dji_dumlv1.gimbal_ext_ctrl_accel_unknown0", "Unknown0", base.DEC, nil, nil, "angle in degrees * 10, range -1800..1800")
f.gimbal_ext_ctrl_accel_unknown2 = ProtoField.int16 ("dji_dumlv1.gimbal_ext_ctrl_accel_unknown2", "Unknown2", base.DEC, nil, nil, "angle in degrees * 10, range -1800..1800")
f.gimbal_ext_ctrl_accel_unknown4 = ProtoField.int16 ("dji_dumlv1.gimbal_ext_ctrl_accel_unknown4", "Unknown4", base.DEC, nil, nil, "angle in degrees * 10, range -1800..1800")
f.gimbal_ext_ctrl_accel_unknown6 = ProtoField.uint8 ("dji_dumlv1.gimbal_ext_ctrl_accel_unknown6", "Unknown6", base.HEX, nil, nil, "flag fields")

local function gimbal_ext_ctrl_accel_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_ext_ctrl_accel_unknown0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_ext_ctrl_accel_unknown2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_ext_ctrl_accel_unknown4, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_ext_ctrl_accel_unknown6, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 7) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Ext Ctrl Accel: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Ext Ctrl Accel: Payload size different than expected") end
end

-- Gimbal - Gimbal Suspend/Resume / Set On Or Off - 0x0d
-- Description: Allows to suspend or resume gimbal motion when correct magic value is provided as payload. Sets a single flag in RAM. No ACK possible.
-- Supported in: P3X_FW_V01.11.0030_m0400

enums.GIMBAL_SUSPEND_RESUME_CMD_ENUM = {
    [0x2AB5]="Resume",
    [0x7EF2]="Suspend",
}

f.gimbal_suspend_resume_cmd = ProtoField.uint16 ("dji_dumlv1.gimbal_suspend_resume_cmd", "Command", base.HEX, enums.GIMBAL_SUSPEND_RESUME_CMD_ENUM, nil)

local function gimbal_suspend_resume_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_suspend_resume_cmd, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Suspend/Resume: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Suspend/Resume: Payload size different than expected") end
end

-- Gimbal - Gimbal Thirdp Magn - 0x0e
-- Description: Sets 3 values from packet; does some processing on the values, influences many values stored in RAM.
-- Maybe calibrates the gimbal for work with third party magnetometer?
-- Supported in: P3X_FW_V01.11.0030_m0400

f.gimbal_thirdp_magn_unknown0 = ProtoField.int16 ("dji_dumlv1.gimbal_thirdp_magn_unknown0", "Unknown0", base.DEC, nil, nil)
f.gimbal_thirdp_magn_unknown2 = ProtoField.int16 ("dji_dumlv1.gimbal_thirdp_magn_unknown2", "Unknown2", base.DEC, nil, nil)
f.gimbal_thirdp_magn_unknown4 = ProtoField.int16 ("dji_dumlv1.gimbal_thirdp_magn_unknown4", "Unknown4", base.DEC, nil, nil)

local function gimbal_thirdp_magn_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_thirdp_magn_unknown0, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_thirdp_magn_unknown2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_thirdp_magn_unknown4, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 6) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Thirdp Magn: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Thirdp Magn: Payload size different than expected") end
end

-- Gimbal - Gimbal User Params Set - 0x0f
-- Description: Allows to set new values of gimbal user params. Index and size of each param must be provided. On Ph3, also resets values from packet 0x20 to 1.
-- Supported in: P3X_FW_V01.11.0030_m0400

f.gimbal_user_params_set_resp_status = ProtoField.uint8 ("dji_dumlv1.gimbal_user_params_set_resp_status", "Status", base.DEC, nil, nil, "Request processing status; non-zero value means error.")
f.gimbal_user_params_set_param_idx = ProtoField.int8 ("dji_dumlv1.gimbal_user_params_set_param_idx", "Param Idx", base.DEC, nil, nil)
f.gimbal_user_params_set_param_size = ProtoField.uint8 ("dji_dumlv1.gimbal_user_params_set_param_size", "Param Size", base.DEC, nil, nil)
f.gimbal_user_params_set_param_value = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_set_param_value", "Param Value", base.SPACE, nil, nil)

local function gimbal_user_params_set_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request

        local i = 0
        while offset < payload:len() do
        i = i + 1

            subtree:add_le (f.gimbal_user_params_set_param_idx, payload(offset, 1))
            offset = offset + 1

            local param_size = payload(offset, 1):uint()
            subtree:add_le (f.gimbal_user_params_set_param_size, payload(offset, 1))
            offset = offset + 1

            if param_size == 8 then
                subtree:add_le (f.gimbal_user_params_set_param_value, payload(offset, 8))
                offset = offset + 8
            elseif param_size == 4 then
                subtree:add_le (f.gimbal_user_params_set_param_value, payload(offset, 4))
                offset = offset + 4
            elseif param_size == 2 then
                subtree:add_le (f.gimbal_user_params_set_param_value, payload(offset, 2))
                offset = offset + 2
            else
                subtree:add_le (f.gimbal_user_params_set_param_value, payload(offset, 1))
                offset = offset + 1
            end

        end

    else -- Response

        subtree:add_le (f.gimbal_user_params_set_resp_status, payload(offset, 1))
        offset = offset + 1

    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal User Params Set: Payload size different than expected") end
end

-- Gimbal - Gimbal User Params Get - 0x10
-- Description: Given indexes of gimbal user params, returns a list of their values. Values have different size depending on their type.
-- On Ph3, there are 12 gimbal user params defined in firmware.
-- Supported in: P3X_FW_V01.11.0030_m0400

f.gimbal_user_params_get_param_idx = ProtoField.int8 ("dji_dumlv1.gimbal_user_params_get_param_idx", "Param Idx", base.DEC, nil, nil)
f.gimbal_user_params_get_resp_status = ProtoField.uint8 ("dji_dumlv1.gimbal_user_params_get_resp_status", "Status", base.DEC, nil, nil, "Request processing status; non-zero value means error.")
f.gimbal_user_params_get_param_size = ProtoField.uint8 ("dji_dumlv1.gimbal_user_params_get_param_size", "Param Size", base.DEC, nil, nil)
f.gimbal_user_params_get_param_value = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_get_param_value", "Param Value", base.SPACE, nil, nil)
f.gimbal_user_params_get_param_err = ProtoField.int8 ("dji_dumlv1.gimbal_user_params_get_param_err", "Param Retrieval Error", base.DEC, nil, nil)

local function gimbal_user_params_get_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request

        local i = 0
        while offset < payload:len() do
        i = i + 1

            subtree:add_le (f.gimbal_user_params_get_param_idx, payload(offset, 1))
            offset = offset + 1

        end

    else -- Response

        subtree:add_le (f.gimbal_user_params_get_resp_status, payload(offset, 1))
        offset = offset + 1

        local i = 0
        while offset < payload:len() do
        i = i + 1

            local param_idx = payload(offset, 1):int()
            if param_idx >= 0 then -- Proper index means parameter retrieved successfully

                subtree:add_le (f.gimbal_user_params_get_param_idx, payload(offset, 1))
                offset = offset + 1

                local param_size = payload(offset, 1):uint()
                subtree:add_le (f.gimbal_user_params_get_param_size, payload(offset, 1))
                offset = offset + 1

                if param_size == 8 then
                    subtree:add_le (f.gimbal_user_params_get_param_value, payload(offset, 8))
                    offset = offset + 8
                elseif param_size == 4 then
                    subtree:add_le (f.gimbal_user_params_get_param_value, payload(offset, 4))
                    offset = offset + 4
                elseif param_size == 2 then
                    subtree:add_le (f.gimbal_user_params_get_param_value, payload(offset, 2))
                    offset = offset + 2
                else
                    subtree:add_le (f.gimbal_user_params_get_param_value, payload(offset, 1))
                    offset = offset + 1
                end

            else -- If index below 0, then it means error code and skip to next param

                subtree:add_le (f.gimbal_user_params_get_param_err, payload(offset, 1))
                offset = offset + 1

            end

        end

    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal User Params Get: Payload size different than expected") end
end

-- Gimbal - Gimbal User Params Save - 0x11
-- Description: Stores values from user_param list, and additional values like the roll adjustment, to persistent storage.
-- On Ph3, requires one byte payload to send an ACK. Also on Ph3, besides returning status code, sets values from packet 0x20 to different numbers on success and on failure.
-- Supported in: P3X_FW_V01.11.0030_m0400

f.gimbal_user_params_save_reserved = ProtoField.int8 ("dji_dumlv1.gimbal_user_params_save_reserved", "Reserved", base.DEC, nil, nil, "Unused value, but must exist in order for gimbal to send back ACK.")
f.gimbal_user_params_save_resp_status = ProtoField.uint8 ("dji_dumlv1.gimbal_user_params_save_resp_status", "Status", base.DEC, nil, nil, "Request processing status; non-zero value means error.")

local function gimbal_user_params_save_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request

        subtree:add_le (f.gimbal_user_params_save_reserved, payload(offset, 1))
        offset = offset + 1

    else -- Response

        subtree:add_le (f.gimbal_user_params_save_resp_status, payload(offset, 1))
        offset = offset + 1

    end

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal User Params Save: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal User Params Save: Payload size different than expected") end
end

-- Gimbal - Gimbal User Params Reset Default / Resume Default Param - 0x13
-- Description: Restores values of all user params to defaults from persistent storage. On Ph3, resets values from packet 0x20 to 1.
-- Supported in: P3X_FW_V01.11.0030_m0400

f.gimbal_user_params_reset_def_resp_status = ProtoField.uint8 ("dji_dumlv1.gimbal_user_params_reset_def_resp_status", "Status", base.DEC, nil, nil, "Request processing status; non-zero value means error.")

local function gimbal_user_params_reset_def_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request

        if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal User Params Reset Default: Offset does not match - internal inconsistency") end
    else -- Response

        subtree:add_le (f.gimbal_user_params_reset_def_resp_status, payload(offset, 1))
        offset = offset + 1

        if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal User Params Reset Default: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal User Params Reset Default: Payload size different than expected") end
end

-- Gimbal - Gimbal Abs Angle Control - 0x14
-- Description: Sets 3 angular values and 1 additional value from packet within gimbal RAM. Also contains flags field which influences which fields are set. No ACK possible.
-- Supported in: P3X_FW_V01.11.0030_m0400

f.gimbal_abs_angle_control_angle1 = ProtoField.int16 ("dji_dumlv1.gimbal_abs_angle_control_angle1", "Angle1", base.DEC, nil, nil, "in degrees * 10")
f.gimbal_abs_angle_control_angle2 = ProtoField.int16 ("dji_dumlv1.gimbal_abs_angle_control_angle2", "Angle2", base.DEC, nil, nil, "in degrees * 10")
f.gimbal_abs_angle_control_angle3 = ProtoField.int16 ("dji_dumlv1.gimbal_abs_angle_control_angle3", "Angle3", base.DEC, nil, nil, "in degrees * 10")
f.gimbal_abs_angle_control_flags = ProtoField.uint8 ("dji_dumlv1.gimbal_abs_angle_control_flags", "Flags", base.HEX, nil, nil)
f.gimbal_abs_angle_control_field7 = ProtoField.uint8 ("dji_dumlv1.gimbal_abs_angle_control_field6", "Field6", base.DEC, nil, nil)

local function gimbal_abs_angle_control_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_abs_angle_control_angle1, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_abs_angle_control_angle2, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_abs_angle_control_angle3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_abs_angle_control_flags, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_abs_angle_control_field7, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Abs Angle Control: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Abs Angle Control: Payload size different than expected") end
end

-- Gimbal - Gimbal Movement - 0x15
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_move_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_move_unknown0", "Unknown0", base.DEC, nil, nil, "0.04 degree")
f.gimbal_move_unknown1 = ProtoField.int8 ("dji_dumlv1.gimbal_move_unknown1", "Unknown1", base.DEC, nil, nil, "0.04 degree")
f.gimbal_move_unknown2 = ProtoField.int8 ("dji_dumlv1.gimbal_move_unknown2", "Unknown2", base.DEC, nil, nil, "0.04 degree")
f.gimbal_move_unknown3 = ProtoField.int8 ("dji_dumlv1.gimbal_move_unknown3", "Unknown3", base.DEC, nil, nil, "0.1 degree")
f.gimbal_move_unknown4 = ProtoField.int8 ("dji_dumlv1.gimbal_move_unknown4", "Unknown4", base.DEC, nil, nil, "0.1 degree")
f.gimbal_move_unknown5 = ProtoField.int8 ("dji_dumlv1.gimbal_move_unknown5", "Unknown5", base.DEC, nil, nil, "0.1 degree")
f.gimbal_move_unknown6 = ProtoField.uint8 ("dji_dumlv1.gimbal_move_unknown6", "Unknown6", base.DEC, nil, nil, "percent")
f.gimbal_move_unknown7 = ProtoField.uint8 ("dji_dumlv1.gimbal_move_unknown7", "Unknown7", base.DEC, nil, nil, "percent")
f.gimbal_move_roll_adjust = ProtoField.uint8 ("dji_dumlv1.gimbal_move_roll_adjust", "Roll Adjust", base.DEC)
f.gimbal_move_reserved = ProtoField.bytes ("dji_dumlv1.gimbal_move_reserved", "Reserved", base.SPACE, nil, nil, "should be zero-filled")

local function gimbal_move_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_move_unknown0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_move_unknown1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_move_unknown2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_move_unknown3, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_move_unknown4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_move_unknown5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_move_unknown6, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_move_unknown7, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_move_roll_adjust, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_move_reserved, payload(offset, 11))
    offset = offset + 11

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Move: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Move: Payload size different than expected") end
end

-- Gimbal - Gimbal Type - 0x1c
-- Description: TODO.
-- Supported in: UNKNOWN

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

f.gimbal_type_type = ProtoField.uint8 ("dji_dumlv1.gimbal_type_type", "Type", base.HEX, enums.GIMBAL_TYPE_TYPE_DJI_GIMBAL_TYPE_ENUM, nil, nil)

local function gimbal_type_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_type_type, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Type: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Type: Payload size different than expected") end
end

-- Gimbal - Gimbal Degree Info Subscription - 0x1e
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_degree_info_subscription_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_degree_info_subscription_unknown0", "Unknown0", base.DEC, nil, nil)

local function gimbal_degree_info_subscription_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --subtree:add_le (f.gimbal_degree_info_subscription_unknown0, payload(offset, 1))
    --offset = offset + 1

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Degree Info Subscription: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Degree Info Subscription: Payload size different than expected") end
end

-- Gimbal - Gimbal TBD 20 - 0x20
-- Description: Sets 3 values from packet within gimbal RAM. No ACK possible.
-- Supported in: P3X_FW_V01.11.0030_m0400

f.gimbal_tbd_20_unknown0 = ProtoField.int32 ("dji_dumlv1gimbal_tbd_20_unknown0", "Unknown0", base.DEC, nil, nil)
f.gimbal_tbd_20_unknown4 = ProtoField.uint8 ("dji_dumlv1gimbal_tbd_20_unknown0", "Unknown4", base.DEC, nil, nil)
f.gimbal_tbd_20_unknown5 = ProtoField.uint8 ("dji_dumlv1gimbal_tbd_20_unknown0", "Unknown5", base.DEC, nil, nil)

local function gimbal_tbd_20_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_tbd_20_unknown0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gimbal_tbd_20_unknown4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_tbd_20_unknown5, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 6) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal TBD 20: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal TBD 20: Payload size different than expected") end
end

-- Gimbal - Gimbal TBD 21 - 0x21
-- Description: Sets values of unknown 3-element list within RAM. Each list entry consists of 3 integers. No ACK possible.
-- Supported in: P3X_FW_V01.11.0030_m0400

f.gimbal_tbd_21_dry_run = ProtoField.int8 ("dji_dumlv1.gimbal_tbd_21_dry_run", "Dry Run", base.DEC, nil, nil, "When not zero, the packet will have no effect")
f.gimbal_tbd_21_unknown1 = ProtoField.int8 ("dji_dumlv1.gimbal_tbd_21_unknown1", "Unknown1", base.DEC, nil, nil)
f.gimbal_tbd_21_arr0_field0 = ProtoField.uint32 ("dji_dumlv1.gimbal_tbd_21_arr0_field0", "Array el0 Field0", base.DEC, nil, nil)
f.gimbal_tbd_21_arr0_field4 = ProtoField.uint8 ("dji_dumlv1.gimbal_tbd_21_arr0_field4", "Array el0 Field4", base.DEC, nil, nil)
f.gimbal_tbd_21_arr0_field5 = ProtoField.uint8 ("dji_dumlv1.gimbal_tbd_21_arr0_field5", "Array el0 Field5", base.DEC, nil, nil)
f.gimbal_tbd_21_arr1_field0 = ProtoField.uint32 ("dji_dumlv1.gimbal_tbd_21_arr1_field0", "Array el1 Field0", base.DEC, nil, nil)
f.gimbal_tbd_21_arr1_field4 = ProtoField.uint8 ("dji_dumlv1.gimbal_tbd_21_arr1_field4", "Array el1 Field4", base.DEC, nil, nil)
f.gimbal_tbd_21_arr1_field5 = ProtoField.uint8 ("dji_dumlv1.gimbal_tbd_21_arr1_field5", "Array el1 Field5", base.DEC, nil, nil)
f.gimbal_tbd_21_arr2_field0 = ProtoField.uint32 ("dji_dumlv1.gimbal_tbd_21_arr2_field0", "Array el2 Field0", base.DEC, nil, nil)
f.gimbal_tbd_21_arr2_field4 = ProtoField.uint8 ("dji_dumlv1.gimbal_tbd_21_arr2_field4", "Array el2 Field4", base.DEC, nil, nil)
f.gimbal_tbd_21_arr2_field5 = ProtoField.uint8 ("dji_dumlv1.gimbal_tbd_21_arr2_field5", "Array el2 Field5", base.DEC, nil, nil)

local function gimbal_tbd_21_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_tbd_21_dry_run, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_tbd_21_unknown1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_tbd_21_arr0_field0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gimbal_tbd_21_arr0_field4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_tbd_21_arr0_field5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_tbd_21_arr1_field0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gimbal_tbd_21_arr1_field4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_tbd_21_arr1_field5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_tbd_21_arr2_field0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.gimbal_tbd_21_arr2_field4, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_tbd_21_arr2_field5, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 20) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal TBD 21: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal TBD 21: Payload size different than expected") end
end

-- Gimbal - Gimbal User Params - 0x24
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_user_params_unknown00 = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_unknown00", "Unknown00", base.SPACE)
f.gimbal_user_params_preset_id = ProtoField.uint8 ("dji_dumlv1.gimbal_user_params_preset_id", "Preset Id", base.HEX)
f.gimbal_user_params_unknown03 = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_unknown03", "Unknown03", base.SPACE)
f.gimbal_user_params_yaw_speed = ProtoField.uint16 ("dji_dumlv1.gimbal_user_params_yaw_speed", "Yaw Speed", base.HEX)
f.gimbal_user_params_unknown0b = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_unknown0b", "Unknown0B", base.SPACE)
f.gimbal_user_params_pitch_speed = ProtoField.uint16 ("dji_dumlv1.gimbal_user_params_pitch_speed", "Pitch Speed", base.HEX)
f.gimbal_user_params_unknown0f = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_unknown0f", "Unknown0F", base.SPACE)
f.gimbal_user_params_yaw_deadband = ProtoField.uint16 ("dji_dumlv1.gimbal_user_params_yaw_deadband", "Yaw Deadband", base.HEX)
f.gimbal_user_params_unknown13 = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_unknown13", "Unknown13", base.SPACE)
f.gimbal_user_params_pitch_deadband = ProtoField.uint16 ("dji_dumlv1.gimbal_user_params_pitch_deadband", "Pitch Deadband", base.HEX)
f.gimbal_user_params_unknown17 = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_unknown17", "Unknown17", base.SPACE)
f.gimbal_user_params_stick_yaw_speed = ProtoField.uint16 ("dji_dumlv1.gimbal_user_params_stick_yaw_speed", "Stick Yaw Speed", base.HEX)
f.gimbal_user_params_unknown1b = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_unknown1b", "Unknown1B", base.SPACE)
f.gimbal_user_params_stick_pitch_speed = ProtoField.uint16 ("dji_dumlv1.gimbal_user_params_stick_pitch_speed", "Stick Pitch Speed", base.HEX)
f.gimbal_user_params_unknown1f = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_unknown1f", "Unknown1F", base.SPACE)
f.gimbal_user_params_stick_yaw_smooth = ProtoField.uint16 ("dji_dumlv1.gimbal_user_params_stick_yaw_smooth", "Stick Yaw Smooth", base.HEX)
f.gimbal_user_params_unknown23 = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_unknown23", "Unknown23", base.SPACE)
f.gimbal_user_params_stick_pitch_smooth = ProtoField.uint16 ("dji_dumlv1.gimbal_user_params_stick_pitch_smooth", "Stick Pitch Smooth", base.HEX)
f.gimbal_user_params_unknown27 = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_unknown27", "Unknown27", base.SPACE)
f.gimbal_user_params_roll_speed = ProtoField.uint16 ("dji_dumlv1.gimbal_user_params_roll_speed", "Roll Speed", base.HEX)
f.gimbal_user_params_unknown31 = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_unknown31", "Unknown31", base.SPACE)
f.gimbal_user_params_roll_deadband = ProtoField.uint16 ("dji_dumlv1.gimbal_user_params_roll_deadband", "Roll Deadband", base.HEX)
f.gimbal_user_params_unknown35 = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_unknown35", "Unknown35", base.SPACE)
f.gimbal_user_params_yaw_accel = ProtoField.uint16 ("dji_dumlv1.gimbal_user_params_yaw_accel", "Yaw Accel", base.HEX)
f.gimbal_user_params_unknown39 = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_unknown39", "Unknown39", base.SPACE)
f.gimbal_user_params_pitch_accel = ProtoField.uint16 ("dji_dumlv1.gimbal_user_params_pitch_accel", "Pitch Accel", base.HEX)
f.gimbal_user_params_unknown3d = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_unknown3d", "Unknown3D", base.SPACE)
f.gimbal_user_params_roll_accel = ProtoField.uint16 ("dji_dumlv1.gimbal_user_params_roll_accel", "Roll Accel", base.HEX)
f.gimbal_user_params_unknown41 = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_unknown41", "Unknown41", base.SPACE)
f.gimbal_user_params_yaw_smooth_track = ProtoField.uint8 ("dji_dumlv1.gimbal_user_params_yaw_smooth_track", "Yaw Smooth Track", base.HEX)
f.gimbal_user_params_unknown44 = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_unknown44", "Unknown44", base.SPACE)
f.gimbal_user_params_pitch_smooth_track = ProtoField.uint8 ("dji_dumlv1.gimbal_user_params_pitch_smooth_track", "Pitch Smooth Track", base.HEX)
f.gimbal_user_params_unknown47 = ProtoField.bytes ("dji_dumlv1.gimbal_user_params_unknown47", "Unknown47", base.SPACE)
f.gimbal_user_params_roll_smooth_track = ProtoField.uint8 ("dji_dumlv1.gimbal_user_params_roll_smooth_track", "Roll Smooth Track", base.HEX)

local function gimbal_user_params_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_user_params_unknown00, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_preset_id, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_user_params_unknown03, payload(offset, 6))
    offset = offset + 6

    subtree:add_le (f.gimbal_user_params_yaw_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_unknown0b, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_pitch_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_unknown0f, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_yaw_deadband, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_unknown13, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_pitch_deadband, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_unknown17, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_stick_yaw_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_unknown1b, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_stick_pitch_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_unknown1f, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_stick_yaw_smooth, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_unknown23, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_stick_pitch_smooth, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_unknown27, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.gimbal_user_params_roll_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_unknown31, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_roll_deadband, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_unknown35, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_yaw_accel, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_unknown39, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_pitch_accel, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_unknown3d, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_roll_accel, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_unknown41, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_yaw_smooth_track, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_user_params_unknown44, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_pitch_smooth_track, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_user_params_unknown47, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.gimbal_user_params_roll_smooth_track, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 74) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal User Params: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal User Params: Payload size different than expected") end
end

-- Gimbal - Gimbal Abnormal Status - 0x27
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_abnormal_status_masked00 = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_masked00", "Masked00", base.HEX)
  f.gimbal_abnormal_status_roll_locked = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_roll_locked", "Roll Locked", base.HEX, nil, 0x01, nil)
  f.gimbal_abnormal_status_pitch_locked = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_pitch_locked", "Pitch Locked", base.HEX, nil, 0x02, nil)
  f.gimbal_abnormal_status_yaw_locked = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_yaw_locked", "Yaw Locked", base.HEX, nil, 0x04, nil)
f.gimbal_abnormal_status_masked01 = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_masked01", "Masked01", base.HEX)
  f.gimbal_abnormal_status_joint_lock_after_startup = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_joint_lock_after_startup", "Joint Lock After Startup", base.HEX, nil, 0x01, nil)
  f.gimbal_abnormal_status_joint_lock_when_startup = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_joint_lock_when_startup", "Joint Lock When Startup", base.HEX, nil, 0x02, nil)
  f.gimbal_abnormal_status_motor_protected = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_motor_protected", "Motor Protected", base.HEX, nil, 0x04, nil)
  f.gimbal_abnormal_status_error_recent_when_start_up = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_error_recent_when_start_up", "Error Recent When Start Up", base.HEX, nil, 0x08, nil)
  f.gimbal_abnormal_status_upgrading = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_upgrading", "Upgrading", base.HEX, nil, 0x10, nil)
  f.gimbal_abnormal_status_yaw_limit = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_yaw_limit", "Yaw Limit", base.HEX, nil, 0x20, nil)
  f.gimbal_abnormal_status_error_recent_or_selfie = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_error_recent_or_selfie", "Error Recent Or Selfie", base.HEX, nil, 0x40, nil)
  f.gimbal_abnormal_status_pano_ready = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_pano_ready", "Pano Ready", base.HEX, nil, 0x80, nil)
f.gimbal_abnormal_status_masked02 = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_masked02", "Masked02", base.HEX)
  f.gimbal_abnormal_status_fan_direction = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_fan_direction", "Fan Direction", base.HEX, nil, 0x02, nil)
  f.gimbal_abnormal_status_vertical_direction = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_vertical_direction", "Vertical Direction", base.HEX, nil, 0x04, nil)
  f.gimbal_abnormal_status_in_flashlight = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_in_flashlight", "In Flashlight", base.HEX, nil, 0x08, nil)
  f.gimbal_abnormal_status_portrait = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_portrait", "Portrait", base.HEX, nil, 0x10, nil)
  f.gimbal_abnormal_status_gimbal_direction_when_vertical = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_gimbal_direction_when_vertical", "Gimbal Direction When Vertical", base.HEX, nil, 0x20, nil)
f.gimbal_abnormal_status_masked03 = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_masked03", "Masked03", base.HEX)
  f.gimbal_abnormal_status_phone_out_gimbal = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_phone_out_gimbal", "Phone Out Gimbal", base.HEX, nil, 0x01, nil)
  f.gimbal_abnormal_status_gimbal_gravity = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_gimbal_gravity", "Gimbal Gravity", base.HEX, nil, 0x06, nil)
  f.gimbal_abnormal_status_yaw_limited_in_tracking = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_yaw_limited_in_tracking", "Yaw Limited In Tracking", base.HEX, nil, 0x20, nil)
  f.gimbal_abnormal_status_pitch_limited_in_tracking = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_pitch_limited_in_tracking", "Pitch Limited In Tracking", base.HEX, nil, 0x40, nil)
f.gimbal_abnormal_status_masked04 = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_masked04", "Masked04", base.HEX)
  f.gimbal_abnormal_status_sleep_mode = ProtoField.uint8 ("dji_dumlv1.gimbal_abnormal_status_sleep_mode", "Sleep Mode", base.HEX, nil, 0x01, nil)

local function gimbal_abnormal_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_abnormal_status_masked00, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_roll_locked, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_pitch_locked, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_yaw_locked, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_abnormal_status_masked01, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_joint_lock_after_startup, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_joint_lock_when_startup, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_motor_protected, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_error_recent_when_start_up, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_upgrading, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_yaw_limit, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_error_recent_or_selfie, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_pano_ready, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_abnormal_status_masked02, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_fan_direction, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_vertical_direction, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_in_flashlight, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_portrait, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_gimbal_direction_when_vertical, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_abnormal_status_masked03, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_phone_out_gimbal, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_gimbal_gravity, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_yaw_limited_in_tracking, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_pitch_limited_in_tracking, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_abnormal_status_masked04, payload(offset, 1))
    subtree:add_le (f.gimbal_abnormal_status_sleep_mode, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Abnormal Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Abnormal Status: Payload size different than expected") end
end

-- Gimbal - Gimbal Tutorial Status - 0x2b
-- Description: TODO.
-- Supported in: UNKNOWN

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

f.gimbal_tutorial_status_cur_step = ProtoField.uint8 ("dji_dumlv1.gimbal_tutorial_status_cur_step", "Cur Step", base.HEX, enums.GIMBAL_TUTORIAL_STATUS_CUR_STEP_TUTORIAL_STATUS_ENUM, nil, nil)
f.gimbal_tutorial_status_step_status = ProtoField.uint32 ("dji_dumlv1.gimbal_tutorial_status_step_status", "Step Status", base.HEX)
  f.gimbal_tutorial_status_is_unlock = ProtoField.uint32 ("dji_dumlv1.gimbal_tutorial_status_is_unlock", "Is Unlock", base.HEX, nil, 0x01, nil)
  f.gimbal_tutorial_status_is_upright = ProtoField.uint32 ("dji_dumlv1.gimbal_tutorial_status_is_upright", "Is Upright", base.HEX, nil, 0x02, nil)
  f.gimbal_tutorial_status_is_follow_finish = ProtoField.uint32 ("dji_dumlv1.gimbal_tutorial_status_is_follow_finish", "Is Follow Finish", base.HEX, nil, 0x04, nil)
  f.gimbal_tutorial_status_is_stick_finish = ProtoField.uint32 ("dji_dumlv1.gimbal_tutorial_status_is_stick_finish", "Is Stick Finish", base.HEX, nil, 0x08, nil)
  f.gimbal_tutorial_status_is_lock_direction_finish = ProtoField.uint32 ("dji_dumlv1.gimbal_tutorial_status_is_lock_direction_finish", "Is Lock Direction Finish", base.HEX, nil, 0x10, nil)
  f.gimbal_tutorial_status_is_recent_finish = ProtoField.uint32 ("dji_dumlv1.gimbal_tutorial_status_is_recent_finish", "Is Recent Finish", base.HEX, nil, 0x20, nil)
  f.gimbal_tutorial_status_is_selfie_finish = ProtoField.uint32 ("dji_dumlv1.gimbal_tutorial_status_is_selfie_finish", "Is Selfie Finish", base.HEX, nil, 0x40, nil)
  f.gimbal_tutorial_status_is_handle_push_finish = ProtoField.uint32 ("dji_dumlv1.gimbal_tutorial_status_is_handle_push_finish", "Is Handle Push Finish", base.HEX, nil, 0x80, nil)
  f.gimbal_tutorial_status_is_app_control_finish = ProtoField.uint32 ("dji_dumlv1.gimbal_tutorial_status_is_app_control_finish", "Is App Control Finish", base.HEX, nil, 0x100, nil)

local function gimbal_tutorial_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_tutorial_status_cur_step, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_tutorial_status_step_status, payload(offset, 4))
    subtree:add_le (f.gimbal_tutorial_status_is_unlock, payload(offset, 4))
    subtree:add_le (f.gimbal_tutorial_status_is_upright, payload(offset, 4))
    subtree:add_le (f.gimbal_tutorial_status_is_follow_finish, payload(offset, 4))
    subtree:add_le (f.gimbal_tutorial_status_is_stick_finish, payload(offset, 4))
    subtree:add_le (f.gimbal_tutorial_status_is_lock_direction_finish, payload(offset, 4))
    subtree:add_le (f.gimbal_tutorial_status_is_recent_finish, payload(offset, 4))
    subtree:add_le (f.gimbal_tutorial_status_is_selfie_finish, payload(offset, 4))
    subtree:add_le (f.gimbal_tutorial_status_is_handle_push_finish, payload(offset, 4))
    subtree:add_le (f.gimbal_tutorial_status_is_app_control_finish, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Tutorial Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Tutorial Status: Payload size different than expected") end
end

-- Gimbal - Gimbal Tutorial Step Set - 0x2c
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_tutorial_step_set_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_tutorial_step_set_unknown0", "Unknown0", base.DEC, nil, nil)

local function gimbal_tutorial_step_set_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --subtree:add_le (f.gimbal_tutorial_step_set_unknown0, payload(offset, 1))
    --offset = offset + 1

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Tutorial Step Set: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Tutorial Step Set: Payload size different than expected") end
end

-- Gimbal - Gimbal Auto Calibration Status - 0x30
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_auto_calibration_status_progress = ProtoField.uint8 ("dji_dumlv1.gimbal_auto_calibration_status_progress", "Progress", base.HEX)
f.gimbal_auto_calibration_status_status = ProtoField.uint8 ("dji_dumlv1.gimbal_auto_calibration_status_status", "Status", base.HEX)

local function gimbal_auto_calibration_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_auto_calibration_status_progress, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_auto_calibration_status_status, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Auto Calibration Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Auto Calibration Status: Payload size different than expected") end
end

-- Gimbal - Robin Params Set - 0x31
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_robin_params_set_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_robin_params_set_unknown0", "Unknown0", base.DEC, nil, nil)

local function gimbal_robin_params_set_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --subtree:add_le (f.gimbal_robin_params_set_unknown0, payload(offset, 1))
    --offset = offset + 1

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Robin Params Set: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Robin Params Set: Payload size different than expected") end
end

-- Gimbal - Robin Params Get - 0x32
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_robin_params_get_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_robin_params_get_unknown0", "Unknown0", base.DEC, nil, nil)

local function gimbal_robin_params_get_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --subtree:add_le (f.gimbal_robin_params_get_unknown0, payload(offset, 1))
    --offset = offset + 1

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Robin Params Get: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Robin Params Get: Payload size different than expected") end
end

-- Gimbal - Robin Battery Info Push / Gimbal Battery Info - 0x33
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_battery_info_a = ProtoField.uint8 ("dji_dumlv1.gimbal_battery_info_a", "A", base.HEX)

local function gimbal_battery_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_battery_info_a, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Battery Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Battery Info: Payload size different than expected") end
end

-- Gimbal - Gimbal Handle Params Set - 0x34
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_handle_params_set_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_handle_params_set_unknown0", "Unknown0", base.DEC, nil, nil)

local function gimbal_handle_params_set_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --subtree:add_le (f.gimbal_handle_params_set_unknown0, payload(offset, 1))
    --offset = offset + 1

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Handle Params Set: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Handle Params Set: Payload size different than expected") end
end

-- Gimbal - Gimbal Handle Params Get - 0x36
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_handle_params_get_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_handle_params_get_unknown0", "Unknown0", base.DEC, nil, nil)

local function gimbal_handle_params_get_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --subtree:add_le (f.gimbal_handle_params_get_unknown0, payload(offset, 1))
    --offset = offset + 1

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Handle Params Get: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Handle Params Get: Payload size different than expected") end
end

-- Gimbal - Gimbal Timelapse Params Set - 0x37
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_timelapse_params_set_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_timelapse_params_set_unknown0", "Unknown0", base.DEC, nil, nil)

local function gimbal_timelapse_params_set_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --subtree:add_le (f.gimbal_timelapse_params_set_unknown0, payload(offset, 1))
    --offset = offset + 1

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Timelapse Params Set: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Timelapse Params Set: Payload size different than expected") end
end

-- Gimbal - Gimbal Timelapse Status - 0x38
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_timelapse_status_masked00 = ProtoField.uint8 ("dji_dumlv1.gimbal_timelapse_status_masked00", "Masked00", base.HEX)
  f.gimbal_timelapse_status_timelapse_status = ProtoField.uint8 ("dji_dumlv1.gimbal_timelapse_status_timelapse_status", "Timelapse Status", base.HEX, nil, 0x03, nil)

local function gimbal_timelapse_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_timelapse_status_masked00, payload(offset, 1))
    subtree:add_le (f.gimbal_timelapse_status_timelapse_status, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Timelapse Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Timelapse Status: Payload size different than expected") end
end

-- Gimbal - Gimbal Lock - 0x39
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_lock_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_lock_unknown0", "Unknown0", base.DEC, nil, nil)

local function gimbal_lock_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --subtree:add_le (f.gimbal_lock_unknown0, payload(offset, 1))
    --offset = offset + 1

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Lock: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Lock: Payload size different than expected") end
end

-- Gimbal - Gimbal Rotate Camera X Axis - 0x3a
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_rotate_camera_x_axis_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_rotate_camera_x_axis_unknown0", "Unknown0", base.DEC, nil, nil)

local function gimbal_rotate_camera_x_axis_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --subtree:add_le (f.gimbal_rotate_camera_x_axis_unknown0, payload(offset, 1))
    --offset = offset + 1

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Rotate Camera X Axis: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Rotate Camera X Axis: Payload size different than expected") end
end

-- Gimbal - Gimbal Get Temp - 0x45
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_get_temp_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_get_temp_unknown0", "Unknown0", base.DEC, nil, nil)

local function gimbal_get_temp_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --subtree:add_le (f.gimbal_get_temp_unknown0, payload(offset, 1))
    --offset = offset + 1

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Get Temp: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Get Temp: Payload size different than expected") end
end

-- Gimbal - Gimbal TBD 47 - 0x47
-- Description: TODO.
-- Supported in: P3X_FW_V01.11.0030_m0400

f.gimbal_tbd_47_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_tbd_47_unknown0", "Unknown0", base.DEC, nil, nil)

local function gimbal_tbd_47_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --subtree:add_le (f.gimbal_tbd_47_unknown0, payload(offset, 1))
    --offset = offset + 1

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal TBD 47: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal TBD 47: Payload size different than expected") end
end

-- Gimbal - Gimbal Reset And Set Mode - 0x4c
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_set_mode_mode = ProtoField.uint8 ("dji_dumlv1.gimbal_set_mode_mode", "Mode", base.HEX)
f.gimbal_set_mode_cmd = ProtoField.uint8 ("dji_dumlv1.gimbal_set_mode_cmd", "Cmd", base.HEX)

local function gimbal_set_mode_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.gimbal_set_mode_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.gimbal_set_mode_cmd, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal Set Mode: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal Set Mode: Payload size different than expected") end
end

-- Gimbal - Gimbal NotiFy Camera Id - 0x56
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_notify_camera_id_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_notify_camera_id_unknown0", "Unknown0", base.DEC, nil, nil)

local function gimbal_notify_camera_id_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --subtree:add_le (f.gimbal_notify_camera_id_unknown0, payload(offset, 1))
    --offset = offset + 1

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Gimbal NotiFy Camera Id: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Gimbal NotiFy Camera Id: Payload size different than expected") end
end

-- Gimbal - Handheld Stick State Get/Push - 0x57
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_handheld_stick_state_get_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_handheld_stick_state_get_unknown0", "Unknown0", base.DEC, nil, nil)

local function gimbal_handheld_stick_state_get_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --subtree:add_le (f.gimbal_handheld_stick_state_get_unknown0, payload(offset, 1))
    --offset = offset + 1

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Handheld Stick State Get/Push: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Handheld Stick State Get/Push: Payload size different than expected") end
end

-- Gimbal - Handheld Stick Control Set / Handheld Stick Control Enable - 0x58
-- Description: TODO.
-- Supported in: UNKNOWN

f.gimbal_handheld_stick_control_set_unknown0 = ProtoField.int8 ("dji_dumlv1.gimbal_handheld_stick_control_set_unknown0", "Unknown0", base.DEC, nil, nil)

local function gimbal_handheld_stick_control_set_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    --subtree:add_le (f.gimbal_handheld_stick_control_set_unknown0, payload(offset, 1))
    --offset = offset + 1

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Handheld Stick Control Set: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Handheld Stick Control Set: Payload size different than expected") end
end

GIMBAL_UART_CMD_DISSECT = {
    [0x01] = gimbal_control_dissector,
    [0x02] = gimbal_get_position_dissector,
    [0x03] = gimbal_set_param_dissector,
    [0x04] = gimbal_get_param_dissector,
    [0x05] = gimbal_params_dissector,
    [0x06] = gimbal_push_aetr_dissector,
    [0x07] = gimbal_adjust_roll_dissector,
    [0x08] = gimbal_calibrate_dissector,
    [0x09] = gimbal_reserved2_dissector,
    [0x0a] = gimbal_ext_ctrl_degree_dissector,
    [0x0b] = gimbal_ext_ctrl_status_dissector,
    [0x0c] = gimbal_ext_ctrl_accel_dissector,
    [0x0d] = gimbal_suspend_resume_dissector,
    [0x0e] = gimbal_thirdp_magn_dissector,
    [0x0f] = gimbal_user_params_set_dissector,
    [0x10] = gimbal_user_params_get_dissector,
    [0x11] = gimbal_user_params_save_dissector,
    [0x13] = gimbal_user_params_reset_def_dissector,
    [0x14] = gimbal_abs_angle_control_dissector,
    [0x15] = gimbal_move_dissector,
    [0x1c] = gimbal_type_dissector,
    [0x1e] = gimbal_degree_info_subscription_dissector,
    [0x20] = gimbal_tbd_20_dissector,
    [0x21] = gimbal_tbd_21_dissector,
    [0x24] = gimbal_user_params_dissector,
    [0x27] = gimbal_abnormal_status_dissector,
    [0x2b] = gimbal_tutorial_status_dissector,
    [0x2c] = gimbal_tutorial_step_set_dissector,
    [0x30] = gimbal_auto_calibration_status_dissector,
    [0x31] = gimbal_robin_params_set_dissector,
    [0x32] = gimbal_robin_params_get_dissector,
    [0x33] = gimbal_battery_info_dissector,
    [0x34] = gimbal_handle_params_set_dissector,
    [0x36] = gimbal_handle_params_get_dissector,
    [0x37] = gimbal_timelapse_params_set_dissector,
    [0x38] = gimbal_timelapse_status_dissector,
    [0x39] = gimbal_lock_dissector,
    [0x3a] = gimbal_rotate_camera_x_axis_dissector,
    [0x45] = gimbal_get_temp_dissector,
    [0x47] = gimbal_tbd_47_dissector,
    [0x4c] = gimbal_set_mode_dissector,
    [0x56] = gimbal_notify_camera_id_dissector,
    [0x57] = gimbal_handheld_stick_state_get_dissector,
    [0x58] = gimbal_handheld_stick_control_set_dissector,
}
