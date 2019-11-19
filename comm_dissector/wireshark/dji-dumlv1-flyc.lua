-- The definitions in this file are part of DJI DUMLv1 protocol dissector
-- Dissectors for command set 0x03 - Flight Control

local f = DJI_DUMLv1_PROTO.fields
local enums = {}

-- CMD name decode table

FLYC_UART_CMD_TEXT = {
    [0x00] = 'FlyC Scan/Test',
    [0x01] = 'FlyC Status Get',
    [0x02] = 'FlyC Params Get',
    [0x03] = 'Origin GPS Set',
    [0x04] = 'Origin GPS Get',
    [0x05] = 'GPS Coordinate Get', -- Sim Command
    [0x06] = 'Fly Limit Param Set',
    [0x07] = 'Fly Limit Param Get',
    [0x08] = 'Nofly Zone Set', -- Set Fly Forbid Area
    [0x09] = 'Nofly Status Get', -- FlyC Forbid Status
    [0x0A] = 'Battery Status Get', -- Nvt Battary Status
    [0x0B] = 'Motor Work Status Set',
    [0x0C] = 'Motor Work Status Get',
    [0x0d] = 'Statistical Info Save', -- Have Checked Struct Set
    [0x0e] = 'Emergency Stop',
    [0x10] = 'A2 Push Commom', -- or FC Config Group Set?
    [0x11] = 'Sim Rc', -- or FC Config Group Get?
    --[0x10] = 'GPS Follow Mode Set', -- on newer platforms
    --[0x11] = 'GPS Follow Mode Get', -- on newer platforms
    --[0x12] = 'GPS Follow Coordinate Get', -- on newer platforms
    [0x16] = 'Sim Status',
    [0x1C] = 'Date and Time Set',
    [0x1D] = 'Initialize Onboard FChannel',
    [0x1E] = 'Get Onboard FChannel Output', -- Get Onboard FChannel Output Value
    [0x1F] = 'Set Onboard FChannel Output', -- Set Onboard FChannel Output Value
    [0x20] = 'Send GPS To Flyc',
    --[0x20] = 'Groundstation On Set', -- on newer platforms
    [0x21] = 'UAV Status Get',
    [0x22] = 'Upload Air Route',
    [0x23] = 'Download Air Route',
    [0x24] = 'Upload Waypoint',
    [0x25] = 'Download Waypoint',
    [0x26] = 'Enable Waypoint',
    [0x27] = 'Exec Fly',
    --[0x27] = 'Suspend Resume Waypoint', -- on newer platforms
    [0x28] = 'One Key Back',
    [0x29] = 'Joystick',
    [0x2A] = 'Function Control', -- sets g_real.wm610_app_command.function_command and function_command_state to 1
    [0x2B] = 'IOC Mode Type Set', -- Intelligent Orientation Control Mode
    [0x2C] = 'IOC Mode Type Get',
    [0x2D] = 'Limit Params Set',
    [0x2E] = 'Limit Params Get',
    [0x2F] = 'Battery Voltage Alarm Set', -- Set Voltage Warnning
    [0x30] = 'Battery Voltage Alarm Get', -- Get Voltage Warnning
    [0x31] = 'UAV Home Point Set',   --AC/RC/APP
    [0x32] = 'FlyC Deform Status Get', -- Push Foot Stool Status
    [0x33] = 'UAV User String Set', -- Set Plane Name
    [0x34] = 'UAV User String Get', -- Get Plane Name
    [0x35] = 'Change Param Ping',
    [0x36] = 'Request SN',
    [0x37] = 'Device Info Get',
    [0x38] = 'Device Info Set',
    [0x39] = 'Enter Flight Data Mode', -- Switches the mode; response contains 1-byte payload - error code, 0 on success
    [0x3a] = 'Ctrl Fly Data Recorder', -- ie Format the recorder
    [0x3b] = 'RC Lost Action Set', -- Set Fs Action
    [0x3c] = 'RC Lost Action Get', -- Get Fs Action
    [0x3d] = 'Time Zone Set', -- for Recorder
    [0x3e] = 'FlyC Request Limit Update',
    [0x3f] = 'Set NoFly Zone Data', -- Set Fly Forbid Area Data
    [0x41] = 'Upload Unlimit Areas', -- Set Whitelist Cmd
    [0x42] = 'FlyC Unlimit State / UAV Posture', -- Push Unlimit Areas (WM220) / Push UAV Posture (P3X)
    [0x43] = 'OSD General Data Get',
    [0x44] = 'OSD Home Point Get',
    [0x45] = 'FlyC GPS SNR Get',
    [0x46] = 'FlyC GPS SNR Set', -- Enable GPS SNR
    [0x47] = 'Enable Unlimit Areas', -- Toggle Whitelist
    [0x49] = 'Push Encrypted Package',
    [0x4A] = 'Push Att IMU Info',
    [0x4B] = 'Push RC Stick Value',
    [0x4C] = 'Push Fussed Pos Speed Data',
    [0x50] = 'Imu Data Status',
    [0x51] = 'FlyC Battery Status Get', -- Smart Battery Status
    [0x52] = 'Smart Low Battery Actn Set', -- Set Battery Alarm Action / Low Bat Departure Cnf Cancel
    [0x53] = 'FlyC Vis Avoidance Param Get', -- Push Visual Avoidance Info
    [0x55] = 'FlyC Limit State Get',
    [0x56] = 'FlyC LED Status Get',
    [0x57] = 'GPS GLNS Info',
    [0x58] = 'Push Att Stick Speed Pos Data',
    [0x59] = 'Push Sdk Data',
    [0x5A] = 'Push FC Data',
    [0x60] = 'SVO API Transfer',
    [0x61] = 'FlyC Activation Info', -- Sdk Activation Info or Request
    [0x62] = 'FlyC Activation Exec', -- Sdk Activation or Activation Result
    [0x63] = 'FlyC On Board Recv',
    [0x64] = 'Send On Board Set', -- SDK Pure Transfer From App To MC
    [0x67] = 'FlyC Power Param Get', -- Motive Power Info
    [0x69] = 'RTK Switch', -- Handle App To Rtk Pack
    [0x6a] = 'FlyC Avoid', -- or Battery Valid State Set?
    [0x6b] = 'Recorder Data Cfg',
    [0x6c] = 'FlyC RTK Location Data Get',
    [0x6d] = 'Upload Hotpoint',
    [0x6e] = 'Download Hotpoint',
    [0x70] = 'Set Product SN',     --Some licensing string check
    [0x71] = 'Get Product SN',     --Some licensing string check
    [0x72] = 'Reset Product SN',
    [0x73] = 'Set Product Id',
    [0x74] = 'Get Product Id',
    [0x75] = 'Write EEPROM FC0',
    [0x76] = 'Read EEPROM FC0',
    [0x80] = 'Navigation Mode Set', -- Mission On/Off
    [0x81] = 'Mission IOC: Set Lock Yaw',
    [0x82] = 'Miss. WP: Upload Mission Info', -- Set WayLine Mission Length, Upload WayPoint Mission Msg
    [0x83] = 'Miss. WP: Download Mission Info', -- Download WayLine Mission Info, Download WayPoint Mission Msg
    [0x84] = 'Upload Waypoint Info By Idx', -- Upload WayPoint Msg By Index
    [0x85] = 'Download Waypoint Info By Idx', -- Download WayPoint Msg By Index
    [0x86] = 'Mission WP: Go/Stop', -- Start Or Cancel WayLine Mission
    [0x87] = 'Mission WP: Pasue/Resume', -- Pause Or Continue WayLine Mission
    [0x88] = 'Push Navigation Status Info', -- FlyC WayPoint Mission Info
    [0x89] = 'Push Navigation Event Info', -- FlyC WayPoint Mission Current Event
    [0x8A] = 'Miss. HotPoint: Start With Info', -- Start HotPoint Mission With Info
    [0x8B] = 'Miss. HotPoint: Cancel', -- Stop HotPoint Mission
    [0x8C] = 'Miss. HotPoint: Pasue/Resume', -- HotPoint Mission Switch
    [0x8D] = 'App Set API Sub Mode',
    [0x8E] = 'App Joystick Data',
    [0x8F] = 'Noe Mission pasue/resume', -- Noe Mission Pause Or Resume
    [0x90] = 'Miss. Follow: Start With Info', -- Start Follow Me With Info
    [0x91] = 'Miss. Follow: Cancel', -- or Stop Follow Me Mission
    [0x92] = 'Miss. Follow: Pasue/Resume', -- Follow Me Mission Switch
    [0x93] = 'Miss. Follow: Get Target Info', -- Send GPS Info on Target
    [0x94] = 'Mission Noe: Start',
    [0x95] = 'Mission Noe: Stop',
    [0x96] = 'Mission HotPoint: Download',
    [0x97] = 'Mission IOC: Start',
    [0x98] = 'Mission IOC: Stop',
    [0x99] = 'Miss. HotPoint: Set Params', -- Set Default Velocity / Speed and Direction
    [0x9a] = 'Miss. HotPoint: Set Radius',
    [0x9b] = 'Miss. HotPoint: Set Head', -- HotPoint Reset Camera
    [0x9c] = 'Miss. WP: Set Idle Veloc', -- Set WayLine Flight Idle Value / Idle Speed
    [0x9d] = 'Miss. WP: Get Idle Veloc', -- Get WayLine Flight Idle Value / Idle Speed
    [0x9e] = 'App Ctrl Mission Yaw Rate',
    [0x9f] = 'Miss. HotPoint: Auto Radius Ctrl',
    [0xa0] = 'Send AGPS Data',
    [0xa1] = 'FlyC AGPS Status Get',
    [0xa2] = 'Race Drone OSD Push',
    [0xa3] = 'Miss. WP: Get BreakPoint Info',
    [0xa4] = 'Miss. WP: Return To Cur Line',
    [0xa5] = 'App Ctrl Fly Sweep Ctrl',
    [0xa6] = 'Set RKT Homepoint',
    [0xaa] = 'Sbus Packet',
    [0xab] = 'Ctrl Attitude Data Send', -- Set Attitude
    [0xac] = 'Ctrl Taillock Data Send', -- Set Tail Lock
    [0xad] = 'FlyC Install Error Get',
    [0xae] = 'Cmd Handler RC App Chl Handler',
    [0xaf] = 'Product Config',
    [0xb0] = 'Get Battery Groups Single Info',
    [0xb5] = 'FlyC Fault Inject Set', -- FIT Set Parameter / Fdi Input
    [0xb6] = 'FlyC Fault Inject Get', -- Change Dev Colour
    [0xb7] = 'Redundancy IMU Index Set and Get', -- RNS Set Parameter
    [0xb8] = 'Redundancy Status', -- RNS Get State
    [0xb9] = 'Push Redundancy Status',
    [0xba] = 'Forearm LED Status Set',
    [0xbb] = 'Open LED Info Get',
    [0xbc] = 'Open Led Action Register',
    [0xbd] = 'Open Led Action Logout',
    [0xbe] = 'Open Led Action Status Set',
    [0xbf] = 'Flight Push', -- Imu Cali Api Handler
    [0xc6] = 'Shell Test',
    [0xcd] = 'Update Nofly Area', -- Update Flyforbid Area
    [0xce] = 'Push Forbid Data Infos', -- FMU Api Get Db Info
    [0xcf] = 'New Nofly Area Get', -- Get New Flyforbid Area
    [0xd4] = 'Additional Info Get', -- Get Moto Speed
    [0xd7] = 'FlyC Flight Record Get', -- Record Log
    [0xd9] = 'Process Sensor Api Data',
    [0xda] = 'FlyC Detection', -- Handler Monitor Cmd Set
    [0xdf] = 'Assistant Unlock Handler',
    [0xe0] = 'Config Table: Get Tbl Attribute',
    [0xe1] = 'Config Table: Get Item Attribute', -- returns parameter name and properties post-mavic
    [0xe2] = 'Config Table: Get Item Value',
    [0xe3] = 'Config Table: Set Item Value',
    [0xe4] = 'Config Table: Reset Def. Item Value',
    [0xe5] = 'Push Config Table: Get Tbl Attribute',
    [0xe6] = 'Push Config Table: Get Item Attribute',
    [0xe7] = 'Push Config Table: Set Item Param',
    [0xe8] = 'Push Config Table: Clear',
    [0xe9] = 'Config Command Table: Get or Exec', -- Cmd Handler/Get Attribute/Set Flyforbid Data?
    [0xea] = 'Register Open Motor Error Action',
    [0xeb] = 'Logout Open Motor Error Action',
    [0xec] = 'Set Open Motor Error Action Status',
    [0xed] = 'ESC Echo Set',
    [0xee] = 'GoHome CountDown Get', -- Ost Sats Go Home Port
    [0xf0] = 'Config Table: Get Param Info by Index', -- aka Update Param; returns parameter name and properties pre-mavic
    [0xf1] = 'Config Table: Read Params By Index', -- aka Query Param
    [0xf2] = 'Config Table: Write Params By Index',
    [0xf3] = 'Config Table: Reset Default Param Val', -- Reset Params By Index/Reset Old Config Table Item Value?
    [0xf4] = 'Config Table: Set Item By Index',
    [0xf5] = 'Ver Phone Set', -- Set/Get Real Name Info
    [0xf6] = 'Push Param PC Log',
    [0xf7] = 'Config Table: Get Param Info By Hash', -- Get Old Config Table Item Info By Hash Value
    [0xf8] = 'Config Table: Read Param By Hash', -- Get Single Param Value By Hash
    [0xf9] = 'Config Table: Write Param By Hash', -- Set Single Param Value By Hash
    [0xfa] = 'Config Table: Reset Params By Hash', -- Reset Old Config Table Item Value By Hash Value
    [0xfb] = 'Config Table: Read Params By Hash',
    [0xfc] = 'Config Table: Write Params By Hash', -- Request Fixed Send Old Config Table Item By Hash Value
    [0xfd] = 'Product Type Get',
    [0xfe] = 'Motor Force Disable Set', -- Motor Force Disable Flag By App Set
    [0xff] = 'Motor Force Disable Get',
}

-- Flight Controller - FlyC Forbid Status - 0x09

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

f.flyc_flyc_forbid_status_flight_limit_area_state = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_forbid_status_flight_limit_area_state", "Flight Limit Area State", base.HEX, enums.FLYC_FORBID_STATUS_FLIGHT_LIMIT_AREA_STATE_DJI_FLIGHT_LIMIT_AREA_STATE_ENUM, nil, nil)
f.flyc_flyc_forbid_status_dji_flight_limit_action_event = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_forbid_status_dji_flight_limit_action_event", "Dji Flight Limit Action Event", base.HEX, enums.FLYC_FORBID_STATUS_DJI_FLIGHT_LIMIT_ACTION_EVENT_ENUM, nil, nil)
f.flyc_flyc_forbid_status_limit_space_num = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_forbid_status_limit_space_num", "Limit Space Num", base.HEX)
f.flyc_flyc_forbid_status_unknown3 = ProtoField.bytes ("dji_dumlv1.flyc_flyc_forbid_status_unknown3", "Unknown3", base.SPACE)

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

    if (offset ~= 7) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Forbid Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Forbid Status: Payload size different than expected") end
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

f.flyc_a2_commom_a = ProtoField.uint8 ("dji_dumlv1.flyc_a2_commom_a", "A", base.HEX)
f.flyc_a2_commom_b = ProtoField.uint8 ("dji_dumlv1.flyc_a2_commom_b", "B", base.HEX)
f.flyc_a2_commom_c = ProtoField.uint32 ("dji_dumlv1.flyc_a2_commom_c", "C", base.HEX)
f.flyc_a2_commom_d = ProtoField.uint32 ("dji_dumlv1.flyc_a2_commom_d", "D", base.HEX)
f.flyc_a2_commom_control_mode = ProtoField.uint8 ("dji_dumlv1.flyc_a2_commom_control_mode", "Control Mode", base.HEX, enums.FLYC_A2_COMMOM_E_DJIA2_CTRL_MODE_ENUM, nil, nil)
f.flyc_a2_commom_f = ProtoField.uint8 ("dji_dumlv1.flyc_a2_commom_f", "F", base.HEX)

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

-- Flight Controller - Function Control - 0x2a
-- sets g_real.wm610_app_command.function_command to value from payload, and function_command_state to 1; does nothing if function_command_state was already non-zero
-- Checked in Ph3 FC firmware 1.08.0080

f.flyc_function_control_function_command = ProtoField.uint8 ("dji_dumlv1.flyc_function_control_function_command", "Function/Command", base.HEX, nil, nil, "New value of g_real.wm610_app_command.function_command")

local function flyc_function_control_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_function_control_function_command, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Function Control: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Function Control: Payload size different than expected") end
end

-- Flight Controller - FlyC Deform Status - 0x32

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

f.flyc_flyc_deform_status_masked00 = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_deform_status_masked00", "Masked00", base.HEX)
  f.flyc_flyc_deform_status_deform_protected = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_deform_status_deform_protected", "Deform Protected", base.HEX, nil, 0x01, nil)
  f.flyc_flyc_deform_status_deform_status = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_deform_status_deform_status", "Deform Status", base.HEX, enums.FLYC_DEFORM_STATUS_DEFORM_STATUS_TRIPOD_STATUS_ENUM, 0x0e, nil)
  f.flyc_flyc_deform_status_deform_mode = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_deform_status_deform_mode", "Deform Mode", base.HEX, enums.FLYC_DEFORM_STATUS_DEFORM_MODE_ENUM, 0x30, nil)

local function flyc_flyc_deform_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_deform_status_masked00, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_deform_status_deform_protected, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_deform_status_deform_status, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_deform_status_deform_mode, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Deform Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Deform Status: Payload size different than expected") end
end

-- Flight Controller - FlyC Request Limit Update - 0x3e

--f.flyc_flyc_request_limit_update_unknown0 = ProtoField.none ("dji_dumlv1.flyc_flyc_request_limit_update_unknown0", "Unknown0", base.NONE)

local function flyc_flyc_request_limit_update_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Request Limit Update: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Request Limit Update: Payload size different than expected") end
end

-- Flight Controller - Set NoFly Zone Data - 0x3f

-- Single transfer should include 100 entries. These entries can be divieded to up to 20 packets(fragments), in any way, as long as the total is correct.
-- First fragment should have index of 0, last one should have num_entries = 0.
-- Recognized by: P3X_FW_V01.07.0060_m0306

f.flyc_set_nofly_zone_data_num_entries = ProtoField.uint8 ("dji_dumlv1.flyc_set_nofly_zone_data_num_entries", "Number of entries", base.DEC, nil, nil, "Amount of entries transfeered it this packet; value of 0 means end of transfer.")
f.flyc_set_nofly_zone_data_frag_num = ProtoField.uint8 ("dji_dumlv1.flyc_set_nofly_zone_data_frag_num", "Transfer fragment index", base.DEC, nil, nil, "Fragment index, incrementing during transfer; proper values are 0-19, where 0 starts a new transfer.")
f.flyc_set_nofly_zone_data_reserved2 = ProtoField.uint8 ("dji_dumlv1.flyc_set_nofly_zone_data_reserved2", "Reserved2", base.HEX, nil, nil, "Should be zeros")

f.flyc_nofly_zone_entry_latitude = ProtoField.uint8 ("dji_dumlv1.flyc_nofly_zone_entry_latitude", "Latitude", base.HEX)
f.flyc_nofly_zone_entry_longitude = ProtoField.uint8 ("dji_dumlv1.flyc_nofly_zone_entry_longitude", "Longitude", base.HEX)
f.flyc_nofly_zone_entry_radius = ProtoField.uint8 ("dji_dumlv1.flyc_nofly_zone_entry_radius", "Radius", base.HEX)
f.flyc_nofly_zone_entry_contry_code = ProtoField.uint8 ("dji_dumlv1.flyc_nofly_zone_entry_contry_code", "Contry Code", base.HEX)
f.flyc_nofly_zone_entry_type = ProtoField.uint8 ("dji_dumlv1.flyc_nofly_zone_entry_type", "Type", base.HEX)
f.flyc_nofly_zone_entry_id = ProtoField.uint8 ("dji_dumlv1.flyc_nofly_zone_entry_id", "Id", base.HEX)

local function flyc_set_nofly_zone_data_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    local num_entries = payload(offset,1):le_uint()
    subtree:add_le (f.flyc_set_nofly_zone_data_num_entries, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_set_nofly_zone_data_frag_num, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_set_nofly_zone_data_reserved2, payload(offset, 3))
    offset = offset + 3

    local num_entries = math.floor((payload:len() - 5) / 17)

    local i = 0
    while i < num_entries do
        i = i + 1

        subtree:add_le (f.flyc_nofly_zone_entry_latitude, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.flyc_nofly_zone_entry_longitude, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.flyc_nofly_zone_entry_radius, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.flyc_nofly_zone_entry_contry_code, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.flyc_nofly_zone_entry_type, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_nofly_zone_entry_id, payload(offset, 4))
        offset = offset + 4

   end

    if (offset ~= 5 + 17 * num_entries) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Set NoFly Zone Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Set NoFly Zone Data: Payload size different than expected") end
end

-- Flight Controller - FlyC Unlimit State / UAV Posture - 0x42
-- On P3X, sent periodically by Flight Controller, contains aircraft posture.
-- Supported in: P3X_FW_V01.11.0030_m0400 (UAV Posture)

f.flyc_flyc_unlimit_state_is_in_unlimit_area = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_unlimit_state_is_in_unlimit_area", "Is In Unlimit Area", base.HEX)
f.flyc_flyc_unlimit_state_unlimit_areas_action = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_unlimit_state_unlimit_areas_action", "Unlimit Areas Action", base.HEX)
f.flyc_flyc_unlimit_state_unlimit_areas_size = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_unlimit_state_unlimit_areas_size", "Unlimit Areas Size", base.HEX)
f.flyc_flyc_unlimit_state_unlimit_areas_enabled = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_unlimit_state_unlimit_areas_enabled", "Unlimit Areas Enabled", base.HEX)

f.flyc_uav_posture_param0 = ProtoField.float ("dji_dumlv1.flyc_uav_posture_param0", "Param0", base.DEC, nil, nil, "Sum of squares of params 0..3 must give 1.0 for the values to be accepted")
f.flyc_uav_posture_param1 = ProtoField.float ("dji_dumlv1.flyc_uav_posture_param1", "Param1", base.DEC)
f.flyc_uav_posture_param2 = ProtoField.float ("dji_dumlv1.flyc_uav_posture_param2", "Param2", base.DEC)
f.flyc_uav_posture_param3 = ProtoField.float ("dji_dumlv1.flyc_uav_posture_param3", "Param3", base.DEC)
f.flyc_uav_posture_param4 = ProtoField.float ("dji_dumlv1.flyc_uav_posture_param4", "Param4", base.DEC)
f.flyc_uav_posture_param5 = ProtoField.float ("dji_dumlv1.flyc_uav_posture_param5", "Param5", base.DEC)
f.flyc_uav_posture_param6 = ProtoField.float ("dji_dumlv1.flyc_uav_posture_param6", "Param6", base.DEC)
f.flyc_uav_posture_param7 = ProtoField.float ("dji_dumlv1.flyc_uav_posture_param7", "Param7", base.DEC)
f.flyc_uav_posture_has8 = ProtoField.uint8 ("dji_dumlv1.flyc_uav_posture_has8", "Has8-unknown", base.HEX)
f.flyc_uav_posture_unkn21 = ProtoField.uint16 ("dji_dumlv1.flyc_uav_posture_unkn21", "Unknown21", base.HEX)

local function flyc_flyc_unlimit_state_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (payload:len() >= 35) then -- UAV Posture

        subtree:add_le (f.flyc_uav_posture_param0, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.flyc_uav_posture_param1, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.flyc_uav_posture_param2, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.flyc_uav_posture_param3, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.flyc_uav_posture_param4, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.flyc_uav_posture_param5, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.flyc_uav_posture_param6, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.flyc_uav_posture_param7, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.flyc_uav_posture_has8, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_uav_posture_unkn21, payload(offset, 2))
        offset = offset + 2

        if (offset ~= 35) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"UAV Posture: Offset does not match - internal inconsistency") end
    else -- FlyC Unlimit State

        subtree:add_le (f.flyc_flyc_unlimit_state_is_in_unlimit_area, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_flyc_unlimit_state_unlimit_areas_action, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_flyc_unlimit_state_unlimit_areas_size, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_flyc_unlimit_state_unlimit_areas_enabled, payload(offset, 1))
        offset = offset + 1

        if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Unlimit State: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Unlimit/Posture: Payload size different than expected") end
end

-- Flight Controller - OSD General Data - 0x43, identical to flight recorder packet 0x000c
-- HD Link - OSD General Data - 0x01 is a second use of the same packet
-- Description: TODO.
-- Supported in: WM620_FW_01.02.0300

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

f.flyc_osd_general_longtitude = ProtoField.double ("dji_dumlv1.flyc_osd_general_longtitude", "Longtitude", base.DEC)
f.flyc_osd_general_latitude = ProtoField.double ("dji_dumlv1.flyc_osd_general_latitude", "Latitude", base.DEC)
f.flyc_osd_general_relative_height = ProtoField.int16 ("dji_dumlv1.flyc_osd_general_relative_height", "Relative Height", base.DEC, nil, nil, "0.1m, altitude to ground")
f.flyc_osd_general_vgx = ProtoField.int16 ("dji_dumlv1.flyc_osd_general_vgx", "Vgx speed", base.DEC, nil, nil, "0.1m/s, to ground")
f.flyc_osd_general_vgy = ProtoField.int16 ("dji_dumlv1.flyc_osd_general_vgy", "Vgy speed", base.DEC, nil, nil, "0.1m/s, to ground")
f.flyc_osd_general_vgz = ProtoField.int16 ("dji_dumlv1.flyc_osd_general_vgz", "Vgz speed", base.DEC, nil, nil, "0.1m/s, to ground")
f.flyc_osd_general_pitch = ProtoField.int16 ("dji_dumlv1.flyc_osd_general_pitch", "Pitch", base.DEC, nil, nil, "0.1")
f.flyc_osd_general_roll = ProtoField.int16 ("dji_dumlv1.flyc_osd_general_roll", "Roll", base.DEC)
f.flyc_osd_general_yaw = ProtoField.int16 ("dji_dumlv1.flyc_osd_general_yaw", "Yaw", base.DEC)
f.flyc_osd_general_ctrl_info = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_ctrl_info", "Control Info", base.HEX)
  f.flyc_osd_general_flyc_state = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_flyc_state", "FC State", base.HEX, enums.FLYC_OSD_GENERAL_FLYC_STATE_ENUM, 0x7F, "Flight Controller state1")
  f.flyc_osd_general_no_rc_state = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_no_rc_state", "No RC State Received", base.HEX, nil, 0x80, nil)
f.flyc_osd_general_latest_cmd = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_latest_cmd", "Latest App Cmd", base.HEX, enums.FLYC_OSD_GENERAL_COMMAND_ENUM, nil, "controller exccute lastest cmd")
f.flyc_osd_general_controller_state = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_controller_state", "Controller State", base.HEX, nil, nil, "Flight Controller state flags")
  f.flyc_osd_general_e_can_ioc_work = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_can_ioc_work", "E Can IOC Work", base.HEX, nil, 0x01, nil)
  f.flyc_osd_general_e_on_ground = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_on_ground", "E On Ground", base.HEX, nil, 0x02, nil)
  f.flyc_osd_general_e_in_air = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_in_air", "E In Air", base.HEX, nil, 0x04, nil)
  f.flyc_osd_general_e_motor_on = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_motor_on", "E Motor On", base.HEX, nil, 0x08, "Force allow start motors ignoring errors")
  f.flyc_osd_general_e_usonic_on = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_usonic_on", "E Usonic On", base.HEX, nil, 0x10, "Ultrasonic wave sonar in use")
  f.flyc_osd_general_e_gohome_state = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_gohome_state", "E Gohome State", base.HEX, enums.FLYC_OSD_GENERAL_GOHOME_STATE_ENUM, 0xe0, nil)
  f.flyc_osd_general_e_mvo_used = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_mvo_used", "E MVO Used", base.HEX, nil, 0x100, "Monocular Visual Odometry is used as horizonal velocity sensor")
  f.flyc_osd_general_e_battery_req_gohome = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_battery_req_gohome", "E Battery Req Gohome", base.HEX, nil, 0x200, nil)
  f.flyc_osd_general_e_battery_req_land = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_battery_req_land", "E Battery Req Land", base.HEX, nil, 0x400, "Landing required due to battery voltage low")
  f.flyc_osd_general_e_still_heating = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_still_heating", "E Still Heating", base.HEX, nil, 0x1000, "IMU Preheating")
  f.flyc_osd_general_e_rc_state = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_rc_state", "E RC Mode Channel", base.HEX, enums.FLYC_OSD_GENERAL_MODE_CHANNEL_RC_MODE_CHANNEL_ENUM, 0x6000, nil)
  f.flyc_osd_general_e_gps_used = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_gps_used", "E GPS Used", base.HEX, nil, 0x8000, "Satellite Positioning System is used as horizonal velocity sensor")
  f.flyc_osd_general_e_compass_over_range = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_compass_over_range", "E Compass Over Range", base.HEX, nil, 0x10000, nil)
  f.flyc_osd_general_e_wave_err = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_wave_err", "E Wave Error", base.HEX, nil, 0x20000, "Ultrasonic sensor error")
  f.flyc_osd_general_e_gps_level = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_gps_level", "E GPS Level", base.HEX, nil, 0x3C0000, "Satellite Positioning System signal level")
  f.flyc_osd_general_e_battery_type = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_battery_type", "E Battery Type", base.HEX, enums.FLYC_OSD_GENERAL_BATT_TYPE_ENUM, 0xC00000, nil)
  f.flyc_osd_general_e_accel_over_range = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_accel_over_range", "E Acceletor Over Range", base.HEX, nil, 0x1000000, nil)
  f.flyc_osd_general_e_is_vibrating = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_is_vibrating", "E Is Vibrating", base.HEX, nil, 0x2000000, nil)
  f.flyc_osd_general_e_press_err = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_press_err", "E Press Err", base.HEX, nil, 0x4000000, "Barometer error")
  f.flyc_osd_general_e_esc_stall = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_esc_stall", "E ESC is stall", base.HEX, nil, 0x8000000, "ESC reports motor blocked")
  f.flyc_osd_general_e_esc_empty = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_esc_empty", "E ESC is empty", base.HEX, nil, 0x10000000, "ESC reports not enough force")
  f.flyc_osd_general_e_propeller_catapult = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_propeller_catapult", "E Propeller Catapult", base.HEX, nil, 0x20000000, nil)
  f.flyc_osd_general_e_gohome_height_mod = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_gohome_height_mod", "E GoHome Height Mod", base.HEX, nil, 0x40000000, "Go Home Height is Modified")
  f.flyc_osd_general_e_out_of_limit = ProtoField.uint32 ("dji_dumlv1.flyc_osd_general_e_out_of_limit", "E Is Out Of Limit", base.HEX, nil, 0x80000000, nil)
f.flyc_osd_general_gps_nums = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_gps_nums", "Gps Nums", base.DEC, nil, nil, "Number of Global Nav System positioning satellites")
f.flyc_osd_general_gohome_landing_reason = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_gohome_landing_reason", "Gohome or Landing Reason", base.HEX, enums.FLYC_OSD_GENERAL_GOHOME_REASON_ENUM, nil, "Reason for automatic GoHome or Landing")
f.flyc_osd_general_start_fail_state = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_start_fail_state", "Motor Start Failure State", base.HEX)
  f.flyc_osd_general_start_fail_reason = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_start_fail_reason", "Motor Start Fail Reason", base.HEX, enums.FLYC_OSD_GENERAL_START_FAIL_REASON_ENUM, 0x7f, "Reason for failure to start motors")
  f.flyc_osd_common_start_fail_happened = ProtoField.uint8 ("dji_dumlv1.flyc_osd_common_start_fail_happened", "Motor Start Fail Happened", base.HEX, nil, 0x80, nil)
f.flyc_osd_general_controller_state_ext = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_controller_state_ext", "Controller State Ext", base.HEX)
  f.flyc_osd_general_e_gps_state = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_e_gps_state", "E Gps State", base.HEX, enums.FLYC_OSD_GENERAL_GPS_STATE_ENUM, 0x0f, "Cause of not being able to switch to GPS mode")
  f.flyc_osd_general_e_wp_limit_md = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_e_wp_limit_md", "E Wp Limit Mode", base.HEX, nil, 0x10, "Waypoint Limit Mode")
f.flyc_osd_general_batt_remain = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_batt_remain", "Battery Remain", base.DEC, nil, nil, "Battery Remaining Capacity")
f.flyc_osd_general_ultrasonic_height = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_ultrasonic_height", "Ultrasonic Height", base.DEC, nil, nil, "Height as reported by ultrasonic wave sensor")
f.flyc_osd_general_motor_startup_time = ProtoField.uint16 ("dji_dumlv1.flyc_osd_general_motor_startup_time", "Motor Started Time", base.DEC, nil, nil, "aka Fly Time")
f.flyc_osd_general_motor_startup_times = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_motor_startup_times", "Motor Starts Count", base.DEC, nil, nil, "aka Motor Revolution")
f.flyc_osd_general_bat_alarm1 = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_bat_alarm1", "Bat Alarm1", base.HEX)
  f.flyc_osd_general_bat_alarm1_ve = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_bat_alarm1_ve", "Alarm Level 1 Voltage", base.DEC, nil, 0x7F)
  f.flyc_osd_general_bat_alarm1_fn = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_bat_alarm1_fn", "Alarm Level 1 Function", base.DEC, nil, 0x80)
f.flyc_osd_general_bat_alarm2 = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_bat_alarm2", "Bat Alarm2", base.HEX)
  f.flyc_osd_general_bat_alarm2_ve = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_bat_alarm2_ve", "Alarm Level 2 Voltage", base.DEC, nil, 0x7F)
  f.flyc_osd_general_bat_alarm2_fn = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_bat_alarm2_fn", "Alarm Level 2 Function", base.DEC, nil, 0x80)
f.flyc_osd_general_version_match = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_version_match", "Version Match", base.HEX, nil, nil, "Flight Controller version")
f.flyc_osd_general_product_type = ProtoField.uint8 ("dji_dumlv1.flyc_osd_general_product_type", "Product Type", base.HEX, enums.FLYC_OSD_GENERAL_PRODUCT_TYPE_ENUM)
f.flyc_osd_general_imu_init_fail_reson = ProtoField.int8 ("dji_dumlv1.flyc_osd_general_imu_init_fail_reson", "IMU init Fail Reason", base.DEC, enums.FLYC_OSD_GENERAL_IMU_INIT_FAIL_RESON_ENUM)
-- Non existing in P3 packets, exist in WM620_FW_01.02.0300
f.flyc_osd_common_motor_fail_reason = ProtoField.uint8 ("dji_dumlv1.flyc_osd_common_motor_fail_reason", "Motor Fail Reason", base.HEX, enums.FLYC_OSD_GENERAL_START_FAIL_REASON_ENUM, nil, nil)
f.flyc_osd_common_motor_start_cause_no_start_action = ProtoField.uint8 ("dji_dumlv1.flyc_osd_common_motor_start_cause_no_start_action", "Motor Start Cause No Start Action", base.HEX, enums.FLYC_OSD_GENERAL_START_FAIL_REASON_ENUM)
f.flyc_osd_common_sdk_ctrl_device = ProtoField.uint8 ("dji_dumlv1.flyc_osd_common_sdk_ctrl_device", "Sdk Ctrl Device", base.HEX, enums.FLYC_OSD_GENERAL_SDK_CTRL_DEVICE_ENUM, nil, nil)
f.flyc_osd_common_unknown35 = ProtoField.uint16 ("dji_dumlv1.flyc_osd_common_unknown35", "Unknown35", base.HEX, nil, nil, nil)

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

    -- On P3X, packet ends here
    -- On WM620, there are additional 5 bytes
    if (payload:len() >= offset + 5) then

        subtree:add_le (f.flyc_osd_common_motor_fail_reason, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_osd_common_motor_start_cause_no_start_action, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_osd_common_sdk_ctrl_device, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_osd_common_unknown35, payload(offset, 2))
        offset = offset + 2

    end

    if (offset ~= 50) and (offset ~= 55) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"OSD General Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"OSD General Data: Payload size different than expected") end
end

-- Flight Controller - OSD Home Point - 0x44, identical to flight recorder packet 0x000d
-- HD Link - HDLnk Push OSD Home Point - 0x02  is a second use of the same packet

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

f.flyc_osd_home_point_osd_lon = ProtoField.double ("dji_dumlv1.flyc_osd_home_point_osd_lon", "OSD Longitude", base.DEC) -- home point coords?
f.flyc_osd_home_point_osd_lat = ProtoField.double ("dji_dumlv1.flyc_osd_home_point_osd_lat", "OSD Latitude", base.DEC) -- home point coords?
f.flyc_osd_home_point_osd_alt = ProtoField.float ("dji_dumlv1.flyc_osd_home_point_osd_alt", "OSD Altitude", base.DEC, nil, nil, "0.1m, altitude")
f.flyc_osd_home_point_osd_home_state = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_osd_home_state", "OSD Home State", base.HEX)
  f.flyc_osd_home_point_e_homepoint_set = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_e_homepoint_set", "E Homepoint Set", base.HEX, nil, 0x01, "Is Home Point Recorded")
  f.flyc_osd_home_point_e_go_home_mode = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_e_go_home_mode", "E Go Home Mode", base.HEX, nil, 0x02, nil)
  f.flyc_osd_home_point_e_heading = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_e_heading", "E Heading", base.HEX, nil, 0x04, "Aircraft Head Direction")
  f.flyc_osd_home_point_e_is_dyn_homepoint = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_e_is_dyn_homepoint", "E Is Dyn Homepoint", base.HEX, nil, 0x08, "Dynamic Home Piont Enable")
  f.flyc_osd_home_point_e_reach_limit_distance = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_e_reach_limit_distance", "E Reach Limit Distance", base.HEX, nil, 0x10, nil)
  f.flyc_osd_home_point_e_reach_limit_height = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_e_reach_limit_height", "E Reach Limit Height", base.HEX, nil, 0x20, nil)
  f.flyc_osd_home_point_e_multiple_mode_open = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_e_multiple_mode_open", "E Multiple Mode Open", base.HEX, nil, 0x40, nil)
  f.flyc_osd_home_point_e_has_go_home = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_e_has_go_home", "E Has Go Home", base.HEX, nil, 0x80, nil)
  f.flyc_osd_home_point_e_compass_cele_status = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_e_compass_cele_status", "E Compass Cele Status", base.HEX, nil, 0x300, nil)
  f.flyc_osd_home_point_e_compass_celeing = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_e_compass_celeing", "E Compass Celeing", base.HEX, nil, 0x400, nil)
  f.flyc_osd_home_point_e_beginner_mode = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_e_beginner_mode", "E Beginner Mode", base.HEX, nil, 0x800, nil)
  f.flyc_osd_home_point_e_ioc_enable = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_e_ioc_enable", "E Ioc Enable", base.HEX, nil, 0x1000, nil)
  f.flyc_osd_home_point_e_ioc_mode = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_e_ioc_mode", "E Ioc Mode", base.HEX, enums.FLYC_OSD_HOME_IOC_MODE_ENUM, 0xe000, nil)
f.flyc_osd_home_point_go_home_height = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_go_home_height", "Go Home Height", base.DEC, nil, nil, "aka Fixed Altitude")
f.flyc_osd_home_point_course_lock_angle = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_course_lock_angle", "Course Lock Angle", base.DEC, nil, nil, "Course Lock Torsion")
f.flyc_osd_home_point_data_recorder_status = ProtoField.uint8 ("dji_dumlv1.flyc_osd_home_point_data_recorder_status", "Data Recorder Status", base.HEX)
f.flyc_osd_home_point_data_recorder_remain_capacity = ProtoField.uint8 ("dji_dumlv1.flyc_osd_home_point_data_recorder_remain_capacity", "Data Recorder Remain Capacity", base.HEX)
f.flyc_osd_home_point_data_recorder_remain_time = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_data_recorder_remain_time", "Data Recorder Remain Time", base.HEX)
f.flyc_osd_home_point_cur_data_recorder_file_index = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_cur_data_recorder_file_index", "Cur Data Recorder File Index", base.HEX)
-- Version of the packet from newer firmwares, 34 bytes long
f.flyc_osd_home_point_ver1_masked20 = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_ver1_masked20", "Masked20", base.HEX)
  f.flyc_osd_home_point_ver1_flyc_in_simulation_mode = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_ver1_flyc_in_simulation_mode", "FlyC In Simulation Mode", base.HEX, nil, 0x01, nil)
  f.flyc_osd_home_point_ver1_flyc_in_navigation_mode = ProtoField.uint16 ("dji_dumlv1.flyc_osd_home_point_ver1_flyc_in_navigation_mode", "FlyC In Navigation Mode", base.HEX, nil, 0x02, nil)
-- Version of the packet from older firmwares, 68 bytes long
f.flyc_osd_home_point_masked20 = ProtoField.uint32 ("dji_dumlv1.flyc_osd_home_point_masked20", "Masked20", base.HEX)
  f.flyc_osd_home_point_flyc_in_simulation_mode = ProtoField.uint32 ("dji_dumlv1.flyc_osd_home_point_flyc_in_simulation_mode", "FlyC In Simulation Mode", base.HEX, nil, 0x01, nil)
  f.flyc_osd_home_point_flyc_in_navigation_mode = ProtoField.uint32 ("dji_dumlv1.flyc_osd_home_point_flyc_in_navigation_mode", "FlyC In Navigation Mode", base.HEX, nil, 0x02, nil)
  f.flyc_osd_home_point_wing_broken = ProtoField.uint32 ("dji_dumlv1.flyc_osd_home_point_wing_broken", "Wing Broken", base.HEX, nil, 0x1000, nil)
  f.flyc_osd_home_point_big_gale = ProtoField.uint32 ("dji_dumlv1.flyc_osd_home_point_big_gale", "Big Gale", base.HEX, nil, 0x4000, nil)
  f.flyc_osd_home_point_big_gale_warning = ProtoField.uint32 ("dji_dumlv1.flyc_osd_home_point_big_gale_warning", "Big Gale Warning", base.HEX, nil, 0x100000, nil)
  f.flyc_osd_home_point_compass_install_err = ProtoField.uint32 ("dji_dumlv1.flyc_osd_home_point_compass_install_err", "Compass Install Err", base.HEX, nil, 0x800000, nil)
  f.flyc_osd_home_point_height_limit_status = ProtoField.uint32 ("dji_dumlv1.flyc_osd_home_point_height_limit_status", "Height Limit Status", base.HEX, enums.FLYC_OSD_HOME_HEIGHT_LIMIT_STATUS_ENUM, 0x1f000000, nil)
  f.flyc_osd_home_point_use_absolute_height = ProtoField.uint32 ("dji_dumlv1.flyc_osd_home_point_use_absolute_height", "Use Absolute Height", base.HEX, nil, 0x20000000, nil)
f.flyc_osd_home_point_height_limit_value = ProtoField.float ("dji_dumlv1.flyc_osd_home_point_height_limit_value", "Height Limit Value", base.DEC)
f.flyc_osd_home_point_unknown28 = ProtoField.bytes ("dji_dumlv1.flyc_osd_home_point_unknown28", "Unknown28", base.SPACE)
f.flyc_osd_home_point_force_landing_height = ProtoField.uint8 ("dji_dumlv1.flyc_osd_home_point_force_landing_height", "Force Landing Height", base.DEC)
f.flyc_osd_home_point_unknown2E = ProtoField.bytes ("dji_dumlv1.flyc_osd_home_point_unknown2E", "Unknown2E", base.SPACE)

local function flyc_osd_home_point_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_osd_home_point_osd_lon, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.flyc_osd_home_point_osd_lat, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.flyc_osd_home_point_osd_alt, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_osd_home_point_osd_home_state, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_point_e_homepoint_set, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_point_e_go_home_mode, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_point_e_heading, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_point_e_is_dyn_homepoint, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_point_e_reach_limit_distance, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_point_e_reach_limit_height, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_point_e_multiple_mode_open, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_point_e_has_go_home, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_point_e_compass_cele_status, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_point_e_compass_celeing, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_point_e_beginner_mode, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_point_e_ioc_enable, payload(offset, 2))
    subtree:add_le (f.flyc_osd_home_point_e_ioc_mode, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_home_point_go_home_height, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_home_point_course_lock_angle, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_home_point_data_recorder_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_home_point_data_recorder_remain_capacity, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_osd_home_point_data_recorder_remain_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_osd_home_point_cur_data_recorder_file_index, payload(offset, 2))
    offset = offset + 2

    -- Before firmware P3X_FW_V01.07.0060, the packet was 68 bytes long
    if (payload:len() < 68) then

        subtree:add_le (f.flyc_osd_home_point_ver1_masked20, payload(offset, 2))
        subtree:add_le (f.flyc_osd_home_point_ver1_flyc_in_simulation_mode, payload(offset, 2))
        subtree:add_le (f.flyc_osd_home_point_ver1_flyc_in_navigation_mode, payload(offset, 2))
        offset = offset + 2

        if (offset ~= 34) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"OSD Home Point: Offset does not match - internal inconsistency") end

    else

        subtree:add_le (f.flyc_osd_home_point_masked20, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_point_flyc_in_simulation_mode, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_point_flyc_in_navigation_mode, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_point_wing_broken, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_point_big_gale, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_point_big_gale_warning, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_point_compass_install_err, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_point_height_limit_status, payload(offset, 4))
        subtree:add_le (f.flyc_osd_home_point_use_absolute_height, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.flyc_osd_home_point_height_limit_value, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.flyc_osd_home_point_unknown28, payload(offset, 5))
        offset = offset + 5

        subtree:add_le (f.flyc_osd_home_point_force_landing_height, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.flyc_osd_home_point_unknown2E, payload(offset, 22))
        offset = offset + 22

        if (offset ~= 68) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"OSD Home Point: Offset does not match - internal inconsistency") end

    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"OSD Home Point: Payload size different than expected") end
end

-- Flight Controller - FlyC Gps Snr - 0x45

--f.flyc_flyc_gps_snr_unknown0 = ProtoField.none ("dji_dumlv1.flyc_flyc_gps_snr_unknown0", "Unknown0", base.NONE)

local function flyc_flyc_gps_snr_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Gps Snr: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Gps Snr: Payload size different than expected") end
end

-- Flight Controller - Imu Data Status - 0x50, identical to flight recorder packet 0x0013

f.flyc_imu_data_status_start_fan = ProtoField.uint8 ("dji_dumlv1.flyc_imu_data_status_start_fan", "Start Fan", base.HEX, nil, nil, "On P3, always 1")
f.flyc_imu_data_status_led_status = ProtoField.uint8 ("dji_dumlv1.flyc_imu_data_status_led_status", "Led Status", base.HEX, nil, nil, "On P3, always 0")

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

-- Flight Controller - FlyC Battery Status - 0x51

enums.FLYC_SMART_BATTERY_GO_HOME_STATUS_SMART_GO_HOME_STATUS_ENUM = {
    [0x00] = 'NON_GOHOME',
    [0x01] = 'GOHOME',
    [0x02] = 'GOHOME_ALREADY',
}

f.flyc_flyc_battery_status_useful_time = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_battery_status_useful_time", "Useful Time", base.DEC)
f.flyc_flyc_battery_status_go_home_time = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_battery_status_go_home_time", "Go Home Time", base.DEC)
f.flyc_flyc_battery_status_land_time = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_battery_status_land_time", "Land Time", base.DEC)
f.flyc_flyc_battery_status_go_home_battery = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_battery_status_go_home_battery", "Go Home Battery", base.DEC)
f.flyc_flyc_battery_status_land_battery = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_battery_status_land_battery", "Land Battery", base.DEC)
f.flyc_flyc_battery_status_safe_fly_radius = ProtoField.float ("dji_dumlv1.flyc_flyc_battery_status_safe_fly_radius", "Safe Fly Radius", base.DEC)
f.flyc_flyc_battery_status_volume_comsume = ProtoField.float ("dji_dumlv1.flyc_flyc_battery_status_volume_comsume", "Volume Comsume", base.DEC)
f.flyc_flyc_battery_status_status = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_battery_status_status", "Status", base.HEX)
f.flyc_flyc_battery_status_go_home_status = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_battery_status_go_home_status", "Go Home Status", base.HEX, enums.FLYC_SMART_BATTERY_GO_HOME_STATUS_SMART_GO_HOME_STATUS_ENUM, nil, nil)
f.flyc_flyc_battery_status_go_home_count_down = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_battery_status_go_home_count_down", "Go Home Count Down", base.HEX)
f.flyc_flyc_battery_status_voltage = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_battery_status_voltage", "Voltage", base.DEC)
f.flyc_flyc_battery_status_battery_percent = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_battery_status_battery_percent", "Battery Percent", base.DEC)
f.flyc_flyc_battery_status_masked1b = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_battery_status_masked1b", "Masked1B", base.HEX)
  f.flyc_flyc_battery_status_low_warning = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_battery_status_low_warning", "Low Warning", base.HEX, nil, 0x7f, nil)
  f.flyc_flyc_battery_status_low_warning_go_home = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_battery_status_low_warning_go_home", "Low Warning Go Home", base.HEX, nil, 0x80, nil)
f.flyc_flyc_battery_status_masked1c = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_battery_status_masked1c", "Masked1C", base.HEX)
  f.flyc_flyc_battery_status_serious_low_warning = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_battery_status_serious_low_warning", "Serious Low Warning", base.HEX, nil, 0x7f, nil)
  f.flyc_flyc_battery_status_serious_low_warning_landing = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_battery_status_serious_low_warning_landing", "Serious Low Warning Landing", base.HEX, nil, 0x80, nil)
f.flyc_flyc_battery_status_voltage_percent = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_battery_status_voltage_percent", "Voltage Percent", base.DEC)

local function flyc_flyc_battery_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_battery_status_useful_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_flyc_battery_status_go_home_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_flyc_battery_status_land_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_flyc_battery_status_go_home_battery, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_flyc_battery_status_land_battery, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_flyc_battery_status_safe_fly_radius, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_flyc_battery_status_volume_comsume, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_flyc_battery_status_status, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_flyc_battery_status_go_home_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_battery_status_go_home_count_down, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_battery_status_voltage, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.flyc_flyc_battery_status_battery_percent, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_battery_status_masked1b, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_battery_status_low_warning, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_battery_status_low_warning_go_home, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_battery_status_masked1c, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_battery_status_serious_low_warning, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_battery_status_serious_low_warning_landing, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_flyc_battery_status_voltage_percent, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 30) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Battery Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Battery Status: Payload size different than expected") end
end

-- Flight Controller - FlyC Vis Avoidance Param - 0x53

f.flyc_flyc_vis_avoid_param_masked00 = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_vis_avoid_param_masked00", "Masked00", base.HEX)
  f.flyc_flyc_vis_avoid_param_avoid_obstacle_enable = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_vis_avoid_param_avoid_obstacle_enable", "Avoid Obstacle Enable", base.HEX, nil, 0x01, nil)
  f.flyc_flyc_vis_avoid_param_user_avoid_enable = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_vis_avoid_param_user_avoid_enable", "User Avoid Enable", base.HEX, nil, 0x02, nil)
  f.flyc_flyc_vis_avoid_param_get_avoid_obstacle_work_flag = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_vis_avoid_param_get_avoid_obstacle_work_flag", "Get Avoid Obstacle Work Flag", base.HEX, nil, 0x04, nil)
  f.flyc_flyc_vis_avoid_param_get_emergency_brake_work_flag = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_vis_avoid_param_get_emergency_brake_work_flag", "Get Emergency Brake Work Flag", base.HEX, nil, 0x08, nil)
  f.flyc_flyc_vis_avoid_param_gohome_avoid_enable = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_vis_avoid_param_gohome_avoid_enable", "Gohome Avoid Enable", base.HEX, nil, 0x10, nil)
  f.flyc_flyc_vis_avoid_param_avoid_ground_force_landing = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_vis_avoid_param_avoid_ground_force_landing", "Avoid Ground Force Landing", base.HEX, nil, 0x20, nil)
  f.flyc_flyc_vis_avoid_param_radius_limit_working = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_vis_avoid_param_radius_limit_working", "Radius Limit Working", base.HEX, nil, 0x40, nil)
  f.flyc_flyc_vis_avoid_param_airport_limit_working = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_vis_avoid_param_airport_limit_working", "Airport Limit Working", base.HEX, nil, 0x80, nil)
  f.flyc_flyc_vis_avoid_param_avoid_obstacle_working = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_vis_avoid_param_avoid_obstacle_working", "Avoid Obstacle Working", base.HEX, nil, 0x100, nil)
  f.flyc_flyc_vis_avoid_param_horiz_near_boundary = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_vis_avoid_param_horiz_near_boundary", "Horiz Near Boundary", base.HEX, nil, 0x200, nil)
  f.flyc_flyc_vis_avoid_param_avoid_overshot_act = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_vis_avoid_param_avoid_overshot_act", "Avoid Overshot Act", base.HEX, nil, 0x400, nil)
  f.flyc_flyc_vis_avoid_param_vert_low_limit_work_flag = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_vis_avoid_param_vert_low_limit_work_flag", "Vert Low Limit Work Flag", base.HEX, nil, 0x800, nil)

local function flyc_flyc_vis_avoid_param_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_vis_avoid_param_masked00, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_vis_avoid_param_avoid_obstacle_enable, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_vis_avoid_param_user_avoid_enable, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_vis_avoid_param_get_avoid_obstacle_work_flag, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_vis_avoid_param_get_emergency_brake_work_flag, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_vis_avoid_param_gohome_avoid_enable, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_vis_avoid_param_avoid_ground_force_landing, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_vis_avoid_param_radius_limit_working, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_vis_avoid_param_airport_limit_working, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_vis_avoid_param_avoid_obstacle_working, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_vis_avoid_param_horiz_near_boundary, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_vis_avoid_param_avoid_overshot_act, payload(offset, 2))
    subtree:add_le (f.flyc_flyc_vis_avoid_param_vert_low_limit_work_flag, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Vis Avoidance Param: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Vis Avoidance Param: Payload size different than expected") end
end

-- Flight Controller - FlyC Limit State - 0x55

f.flyc_flyc_limit_state_latitude = ProtoField.double ("dji_dumlv1.flyc_flyc_limit_state_latitude", "Latitude", base.DEC)
f.flyc_flyc_limit_state_longitude = ProtoField.double ("dji_dumlv1.flyc_flyc_limit_state_longitude", "Longitude", base.DEC)
f.flyc_flyc_limit_state_inner_radius = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_limit_state_inner_radius", "Inner Radius", base.HEX)
f.flyc_flyc_limit_state_outer_radius = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_limit_state_outer_radius", "Outer Radius", base.HEX)
f.flyc_flyc_limit_state_type = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_limit_state_type", "Type", base.HEX)
f.flyc_flyc_limit_state_area_state = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_limit_state_area_state", "Area State", base.HEX)
f.flyc_flyc_limit_state_action_state = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_limit_state_action_state", "Action State", base.HEX)
f.flyc_flyc_limit_state_enable = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_limit_state_enable", "Enable", base.HEX)

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

    if (offset ~= 24) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Limit State: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Limit State: Payload size different than expected") end
end

-- Flight Controller - FlyC Led Status - 0x56

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

f.flyc_flyc_led_status_led_reason = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_led_status_led_reason", "Led Reason", base.HEX, enums.FLYC_LED_STATUS_LED_REASON_ENUM, nil, nil)

local function flyc_flyc_led_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_led_status_led_reason, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Led Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Led Status: Payload size different than expected") end
end

-- Flight Controller - Gps Glns - 0x57, similar to flight recorder packet 0x0005

f.flyc_gps_glns_gps_lon = ProtoField.int32 ("dji_dumlv1.flyc_gps_glns_gps_lon", "Gps Lon", base.DEC)
f.flyc_gps_glns_gps_lat = ProtoField.int32 ("dji_dumlv1.flyc_gps_glns_gps_lat", "Gps Lat", base.DEC)
f.flyc_gps_glns_hmsl = ProtoField.int32 ("dji_dumlv1.flyc_gps_glns_hmsl", "Hmsl", base.DEC)
f.flyc_gps_glns_vel_n = ProtoField.float ("dji_dumlv1.flyc_gps_glns_vel_n", "Vel N", base.DEC)
f.flyc_gps_glns_vel_e = ProtoField.float ("dji_dumlv1.flyc_gps_glns_vel_e", "Vel E", base.DEC)
f.flyc_gps_glns_vel_d = ProtoField.float ("dji_dumlv1.flyc_gps_glns_vel_d", "Vel D", base.DEC)
f.flyc_gps_glns_hdop = ProtoField.float ("dji_dumlv1.flyc_gps_glns_hdop", "Hdop", base.DEC)
f.flyc_gps_glns_numsv = ProtoField.uint16 ("dji_dumlv1.flyc_gps_glns_numsv", "NumSV", base.DEC, nil, nil, "Number of Global Nav System positioning satellites")
f.flyc_gps_glns_gpsglns_cnt = ProtoField.uint16 ("dji_dumlv1.flyc_gps_glns_gpsglns_cnt", "Gps Glns Count", base.DEC, nil, nil, "Sequence counter increased each time the packet of this type is prepared")
f.flyc_gps_glns_unkn20 = ProtoField.uint8 ("dji_dumlv1.flyc_gps_glns_unkn20", "Unknown 20", base.DEC)
f.flyc_gps_glns_homepoint_set = ProtoField.uint8 ("dji_dumlv1.flyc_gps_glns_homepoint_set", "Homepoint Set", base.DEC)

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

-- Flight Controller - FlyC Activation Info - 0x61

f.flyc_flyc_active_request_app_id = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_active_request_app_id", "App Id", base.HEX)
f.flyc_flyc_active_request_app_level = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_active_request_app_level", "App Level", base.HEX)
f.flyc_flyc_active_request_app_version = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_active_request_app_version", "App Version", base.HEX)

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

    if (offset ~= 12) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Activation Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Activation Info: Payload size different than expected") end
end

-- Flight Controller - FlyC Board Recv - 0x63

--f.flyc_flyc_board_recv_unknown0 = ProtoField.none ("dji_dumlv1.flyc_flyc_board_recv_unknown0", "Unknown0", base.NONE)

local function flyc_flyc_board_recv_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Board Recv: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Board Recv: Payload size different than expected") end
end

-- Flight Controller - FlyC Power Param - 0x67

f.flyc_flyc_power_param_esc_average_speed = ProtoField.float ("dji_dumlv1.flyc_flyc_power_param_esc_average_speed", "Esc Average Speed", base.DEC)
f.flyc_flyc_power_param_lift = ProtoField.float ("dji_dumlv1.flyc_flyc_power_param_lift", "Lift", base.DEC)

local function flyc_flyc_power_param_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_power_param_esc_average_speed, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.flyc_flyc_power_param_lift, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Power Param: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Power Param: Payload size different than expected") end
end

-- Flight Controller - FlyC Avoid - 0x6a

f.flyc_flyc_avoid_masked00 = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_avoid_masked00", "Masked00", base.HEX)
  f.flyc_flyc_avoid_visual_sensor_enable = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_avoid_visual_sensor_enable", "Visual Sensor Enable", base.HEX, nil, 0x01, nil)
  f.flyc_flyc_avoid_visual_sensor_work = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_avoid_visual_sensor_work", "Visual Sensor Work", base.HEX, nil, 0x02, nil)
  f.flyc_flyc_avoid_in_stop = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_avoid_in_stop", "In Stop", base.HEX, nil, 0x04, nil)

local function flyc_flyc_avoid_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_avoid_masked00, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_avoid_visual_sensor_enable, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_avoid_visual_sensor_work, payload(offset, 1))
    subtree:add_le (f.flyc_flyc_avoid_in_stop, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Avoid: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Avoid: Payload size different than expected") end
end

-- Flight Controller - FlyC Rtk Location Data - 0x6c

f.flyc_flyc_rtk_location_data_longitude = ProtoField.double ("dji_dumlv1.flyc_flyc_rtk_location_data_longitude", "Longitude", base.DEC)
f.flyc_flyc_rtk_location_data_latitude = ProtoField.double ("dji_dumlv1.flyc_flyc_rtk_location_data_latitude", "Latitude", base.DEC)
f.flyc_flyc_rtk_location_data_height = ProtoField.float ("dji_dumlv1.flyc_flyc_rtk_location_data_height", "Height", base.DEC)
f.flyc_flyc_rtk_location_data_heading = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_rtk_location_data_heading", "Heading", base.HEX)
f.flyc_flyc_rtk_location_data_rtk_connected = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_rtk_location_data_rtk_connected", "Rtk Connected", base.HEX)
f.flyc_flyc_rtk_location_data_rtk_canbe_used = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_rtk_location_data_rtk_canbe_used", "Rtk Can be Used", base.HEX)
f.flyc_flyc_rtk_location_data_unknown18 = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_rtk_location_data_unknown18", "Unknown18", base.HEX)
f.flyc_flyc_rtk_location_data_unknown1C = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_rtk_location_data_unknown1C", "Unknown1C", base.HEX)

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

    if (payload:len() >= offset + 8) then -- Not sure if packets in all platforms have these additional 8 bytes

        subtree:add_le (f.flyc_flyc_rtk_location_data_unknown18, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.flyc_flyc_rtk_location_data_unknown1C, payload(offset, 4))
        offset = offset + 4

    end

    if (offset ~= 24) and (offset ~= 32) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Rtk Location Data: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Rtk Location Data: Payload size different than expected") end
end

-- Flight Controller - FlyC Way Point Mission Info - 0x88

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

f.flyc_flyc_way_point_mission_info_mission_type = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_info_mission_type", "Mission Type", base.HEX, enums.FLYC_WAY_POINT_MISSION_INFO_MISSION_TYPE_ENUM)
-- Way Point mission (unverified)
f.flyc_flyc_way_point_mission_info_target_way_point = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_info_target_way_point", "Target Way Point", base.DEC)
f.flyc_flyc_way_point_mission_info_limited_height = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_way_point_mission_info_limited_height", "Limited Height", base.HEX)
f.flyc_flyc_way_point_mission_info_running_status = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_info_running_status", "Way Point Running Status", base.HEX, enums.FLYC_WAY_POINT_MISSION_INFO_RUNNING_STATUS_ENUM)
f.flyc_flyc_way_point_mission_info_wp_unknown5 = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_info_wp_unknown5", "Way Point Unknown5", base.HEX)
-- Hot Point mission
f.flyc_flyc_way_point_mission_info_hot_point_mission_status = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_info_hot_point_mission_status", "Hot Point Mission Status", base.HEX)
f.flyc_flyc_way_point_mission_info_hot_point_radius = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_way_point_mission_info_hot_point_radius", "Hot Point Radius", base.DEC)
f.flyc_flyc_way_point_mission_info_hot_point_reason = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_info_hot_point_reason", "Hot Point Reason", base.HEX)
f.flyc_flyc_way_point_mission_info_hot_point_speed = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_info_hot_point_speed", "Hot Point Speed", base.DEC)
-- Follow Me mission
f.flyc_flyc_way_point_mission_info_follow_me_flags = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_info_follow_me_flags", "Follow Me Flags", base.HEX)
  f.flyc_flyc_way_point_mission_info_follow_me_status = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_info_follow_me_status", "Follow Me Status", base.HEX, nil, 0x0f, nil)
  f.flyc_flyc_way_point_mission_info_follow_me_gps_level = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_info_follow_me_gps_level", "Follow Me Gps Level", base.HEX, nil, 0xf0, nil)
f.flyc_flyc_way_point_mission_info_follow_me_distance = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_way_point_mission_info_follow_me_distance", "Follow Me Distance", base.Dec)
f.flyc_flyc_way_point_mission_info_follow_me_reason = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_info_follow_me_reason", "Follow Me Reason", base.HEX)
f.flyc_flyc_way_point_mission_info_follow_me_unknown6 = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_info_follow_me_unknown6", "Follow Me Unknown6", base.HEX)
-- Any other mission (unverified)
f.flyc_flyc_way_point_mission_info_mission_flags = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_info_mission_flags", "Mission Flags", base.HEX)
  f.flyc_flyc_way_point_mission_info_mission_status = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_info_mission_status", "Mission Status", base.HEX, nil, 0x03, nil)
  f.flyc_flyc_way_point_mission_info_position_valid = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_info_position_valid", "Position Valid", base.HEX, nil, 0x04, nil)
f.flyc_flyc_way_point_mission_info_current_status = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_info_current_status", "Current Status", base.HEX)
f.flyc_flyc_way_point_mission_info_error_notification = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_info_error_notification", "Error Notification", base.HEX)
f.flyc_flyc_way_point_mission_info_current_height = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_way_point_mission_info_current_height", "Current Height", base.HEX)
-- All types
f.flyc_flyc_way_point_mission_info_is_tracking_enabled = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_info_is_tracking_enabled", "Is Tracking Enabled", base.HEX)

local function flyc_flyc_way_point_mission_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    local mission_type = payload(offset,1):le_uint()
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

    if (offset ~= 7) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Way Point Mission Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Way Point Mission Info: Payload size different than expected") end
end

-- Flight Controller - Push Navigation Event Info - 0x89

enums.FLYC_WAY_POINT_MISSION_CURRENT_EVENT_EVENT_TYPE_ENUM = {
    [0x01] = 'Finish Incident',
    [0x02] = 'Reach Incident',
    [0x03] = 'Upload Incident',
}

f.flyc_flyc_way_point_mission_current_event_event_type = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_current_event_event_type", "Event Type", base.HEX, enums.FLYC_WAY_POINT_MISSION_CURRENT_EVENT_EVENT_TYPE_ENUM)
-- Finish Incident
f.flyc_flyc_way_point_mission_current_event_finish_incident_is_repeat = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_current_event_finish_incident_is_repeat", "Finish Incident Is Repeat", base.HEX)
f.flyc_flyc_way_point_mission_current_event_finish_incident_resrved = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_way_point_mission_current_event_finish_incident_resrved", "Finish Incident Resrved", base.HEX)
-- Reach Incident
f.flyc_flyc_way_point_mission_current_event_reach_incident_way_point_index = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_current_event_reach_incident_way_point_index", "Reach Incident Way Point Index", base.HEX, nil, 0xff, nil)
f.flyc_flyc_way_point_mission_current_event_reach_incident_current_status = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_current_event_reach_incident_current_status", "Reach Incident Current Status", base.HEX, nil, 0xff, nil)
f.flyc_flyc_way_point_mission_current_event_reach_incident_reserved = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_current_event_reach_incident_reserved", "Reach Incident Reserved", base.HEX, nil, 0xff, nil)
-- Upload Incident
f.flyc_flyc_way_point_mission_current_event_upload_incident_is_valid = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_way_point_mission_current_event_upload_incident_is_valid", "Upload Incident Is Valid", base.HEX, nil, 0xff, nil)
f.flyc_flyc_way_point_mission_current_event_upload_incident_estimated_time = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_way_point_mission_current_event_upload_incident_estimated_time", "Upload Incident Estimated Time", base.HEX, nil, 0xffff, nil)
--f.flyc_flyc_way_point_mission_current_event_upload_incident_reserved = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_way_point_mission_current_event_upload_incident_reserved", "Upload Incident Reserved", base.HEX)

local function flyc_flyc_way_point_mission_current_event_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    local event_type = payload(offset,1):le_uint()
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

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Push Navigation Event Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Push Navigation Event Info: Payload size different than expected") end
end

-- Flight Controller - FlyC Agps Status - 0xa1

f.flyc_flyc_agps_status_time_stamp = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_agps_status_time_stamp", "Time Stamp", base.HEX)
f.flyc_flyc_agps_status_data_length = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_agps_status_data_length", "Data Length", base.HEX)
f.flyc_flyc_agps_status_crc16_hash = ProtoField.uint16 ("dji_dumlv1.flyc_flyc_agps_status_crc16_hash", "Crc16 Hash", base.HEX)

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

    if (offset ~= 10) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Agps Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Agps Status: Payload size different than expected") end
end

-- Flight Controller - FlyC Flyc Install Error - 0xad

f.flyc_flyc_flyc_install_error_masked00 = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_flyc_install_error_masked00", "Masked00", base.HEX)
  f.flyc_flyc_flyc_install_error_yaw_install_error_level = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_flyc_install_error_yaw_install_error_level", "Yaw Install Error Level", base.HEX, nil, 0x03, nil)
  f.flyc_flyc_flyc_install_error_roll_install_error_level = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_flyc_install_error_roll_install_error_level", "Roll Install Error Level", base.HEX, nil, 0x0c, nil)
  f.flyc_flyc_flyc_install_error_pitch_install_error_level = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_flyc_install_error_pitch_install_error_level", "Pitch Install Error Level", base.HEX, nil, 0x30, nil)
  f.flyc_flyc_flyc_install_error_gyro_x_install_error_level = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_flyc_install_error_gyro_x_install_error_level", "Gyro X Install Error Level", base.HEX, nil, 0xc0, nil)
  f.flyc_flyc_flyc_install_error_gyro_y_install_error_level = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_flyc_install_error_gyro_y_install_error_level", "Gyro Y Install Error Level", base.HEX, nil, 0x300, nil)
  f.flyc_flyc_flyc_install_error_gyro_z_install_error_level = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_flyc_install_error_gyro_z_install_error_level", "Gyro Z Install Error Level", base.HEX, nil, 0xc00, nil)
  f.flyc_flyc_flyc_install_error_acc_x_install_error_level = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_flyc_install_error_acc_x_install_error_level", "Acc X Install Error Level", base.HEX, nil, 0x3000, nil)
  f.flyc_flyc_flyc_install_error_acc_y_install_error_level = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_flyc_install_error_acc_y_install_error_level", "Acc Y Install Error Level", base.HEX, nil, 0xc000, nil)
  f.flyc_flyc_flyc_install_error_acc_z_install_error_level = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_flyc_install_error_acc_z_install_error_level", "Acc Z Install Error Level", base.HEX, nil, 0x30000, nil)
  f.flyc_flyc_flyc_install_error_thrust_install_error_level = ProtoField.uint32 ("dji_dumlv1.flyc_flyc_flyc_install_error_thrust_install_error_level", "Thrust Install Error Level", base.HEX, nil, 0xc0000, nil)

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

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Flyc Install Error: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Flyc Install Error: Payload size different than expected") end
end

-- Flight Controller - FlyC Fault Inject - 0xb6

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

f.flyc_flyc_fault_inject_status = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_fault_inject_status", "Status", base.HEX, enums.FLYC_FAULT_INJECT_STATUS_ENUM, nil, nil)

local function flyc_flyc_fault_inject_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_flyc_fault_inject_status, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Fault Inject: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Fault Inject: Payload size different than expected") end
end

-- Flight Controller - FlyC Redundancy Status - 0xb9

enums.FLYC_REDUNDANCY_STATUS_CMD_TYPE_ENUM = {
    [0x01] = 'a',
    [0x02] = 'b',
    [0x03] = 'c',
    [0x04] = 'd',
}

f.flyc_flyc_redundancy_status_cmd_type = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_redundancy_status_cmd_type", "Command Type", base.HEX, enums.FLYC_REDUNDANCY_STATUS_CMD_TYPE_ENUM)
f.flyc_flyc_redundancy_status_unknown1 = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_redundancy_status_unknown1", "Unknown1", base.HEX)
f.flyc_flyc_redundancy_status_unknown2 = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_redundancy_status_unknown2", "Unknown2", base.HEX)
f.flyc_flyc_redundancy_status_unknown3 = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_redundancy_status_unknown3", "Unknown3", base.HEX)
f.flyc_flyc_redundancy_status_unknown4 = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_redundancy_status_unknown4", "Unknown4", base.HEX)
f.flyc_flyc_redundancy_status_unknown5 = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_redundancy_status_unknown5", "Unknown5", base.HEX)
f.flyc_flyc_redundancy_status_unknown6 = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_redundancy_status_unknown6", "Unknown6", base.HEX)
f.flyc_flyc_redundancy_status_unknown7 = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_redundancy_status_unknown7", "Unknown7", base.HEX)
f.flyc_flyc_redundancy_status_unknown8 = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_redundancy_status_unknown8", "Unknown8", base.HEX)
f.flyc_flyc_redundancy_status_unknown9 = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_redundancy_status_unknown9", "Unknown9", base.HEX)
f.flyc_flyc_redundancy_status_unknownA = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_redundancy_status_unknownA", "UnknownA", base.HEX)
f.flyc_flyc_redundancy_status_unknownB = ProtoField.uint8 ("dji_dumlv1.flyc_flyc_redundancy_status_unknownB", "UnknownB", base.HEX)

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

    if (offset ~= 12) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FlyC Redundancy Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FlyC Redundancy Status: Payload size different than expected") end
end

-- Flight Controller - Assistant Unlock Handler - 0xdf

f.flyc_assistant_unlock_lock_state = ProtoField.uint32 ("dji_dumlv1.flyc_assistant_unlock_lock_state", "Lock State", base.DEC, nil, nil)
f.flyc_assistant_unlock_status = ProtoField.uint8 ("dji_dumlv1.flyc_assistant_unlock_status", "Status", base.DEC, nil, nil)

local function flyc_assistant_unlock_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request
        subtree:add_le (f.flyc_assistant_unlock_lock_state, payload(offset, 4))
        offset = offset + 4

        if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Assistant Unlock: Offset does not match - internal inconsistency") end
    else -- Response
        subtree:add_le (f.flyc_assistant_unlock_status, payload(offset, 1))
        offset = offset + 1

        if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Assistant Unlock: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Assistant Unlock: Payload size different than expected") end
end

-- Flight Controller - Config Table: Get Tbl Attribute - 0xe0

f.flyc_config_table_get_tbl_attribute_status = ProtoField.uint16 ("dji_dumlv1.flyc_config_table_get_tbl_attribute_status", "Status", base.DEC, nil, nil)
f.flyc_config_table_get_tbl_attribute_table_no = ProtoField.int16 ("dji_dumlv1.flyc_config_table_get_tbl_attribute_table_no", "Table No", base.DEC, nil, nil)
f.flyc_config_table_get_tbl_attribute_entries_crc = ProtoField.uint32 ("dji_dumlv1.flyc_config_table_get_tbl_attribute_entries_crc", "Table Entries Checksum", base.HEX, nil, nil)
f.flyc_config_table_get_tbl_attribute_entries_num = ProtoField.uint32 ("dji_dumlv1.flyc_config_table_get_tbl_attribute_entries_num", "Table Entries Number", base.DEC, nil, nil)

local function flyc_config_table_get_tbl_attribute_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request
        subtree:add_le (f.flyc_config_table_get_tbl_attribute_table_no, payload(offset, 2))
        offset = offset + 2

        if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table Get Tbl Attribute: Offset does not match - internal inconsistency") end
    else -- Response
        subtree:add_le (f.flyc_config_table_get_tbl_attribute_status, payload(offset, 2))
        offset = offset + 2

        if (payload:len() - offset >= 6) then
            subtree:add_le (f.flyc_config_table_get_tbl_attribute_table_no, payload(offset, 2))
            offset = offset + 2

            subtree:add_le (f.flyc_config_table_get_tbl_attribute_entries_crc, payload(offset, 4))
            offset = offset + 4

            subtree:add_le (f.flyc_config_table_get_tbl_attribute_entries_num, payload(offset, 4))
            offset = offset + 4
        end

        if (offset ~= 2) and (offset ~= 12) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table Get Tbl Attribute: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Config Table Get Tbl Attribute: Payload size different than expected") end
end

-- Flight Controller - Config Table: Get Item Attribute - 0xe1

f.flyc_config_table_get_item_attribute_status = ProtoField.uint16 ("dji_dumlv1.flyc_config_table_get_item_attribute_status", "Status", base.DEC, nil, nil)
f.flyc_config_table_get_item_attribute_table_no = ProtoField.int16 ("dji_dumlv1.flyc_config_table_get_item_attribute_table_no", "Table No", base.DEC, nil, nil)
f.flyc_config_table_get_item_attribute_index = ProtoField.int16 ("dji_dumlv1.flyc_config_table_get_item_attribute_index", "Param Index", base.DEC, nil, nil)
f.flyc_config_table_get_item_attribute_type_id = ProtoField.uint16 ("dji_dumlv1.flyc_config_table_get_item_attribute_type_id", "TypeID", base.DEC, nil, nil)
f.flyc_config_table_get_item_attribute_size = ProtoField.int16 ("dji_dumlv1.flyc_config_table_get_item_attribute_size", "Size", base.DEC, nil, nil)
--f.flyc_config_table_get_item_attribute_attribute = ProtoField.uint16 ("dji_dumlv1.flyc_config_table_get_item_attribute_attribute", "Attribute", base.HEX, nil, nil)
f.flyc_config_table_get_item_attribute_limit_i_def = ProtoField.int32 ("dji_dumlv1.flyc_config_table_get_item_attribute_limit_i_def", "LimitI defaultValue", base.DEC, nil, nil)
f.flyc_config_table_get_item_attribute_limit_i_min = ProtoField.int32 ("dji_dumlv1.flyc_config_table_get_item_attribute_limit_i_min", "LimitI minValue", base.DEC, nil, nil)
f.flyc_config_table_get_item_attribute_limit_i_max = ProtoField.int32 ("dji_dumlv1.flyc_config_table_get_item_attribute_limit_i_max", "LimitI maxValue", base.DEC, nil, nil)
f.flyc_config_table_get_item_attribute_limit_u_def = ProtoField.uint32 ("dji_dumlv1.flyc_config_table_get_item_attribute_limit_u_def", "LimitU defaultValue", base.DEC, nil, nil)
f.flyc_config_table_get_item_attribute_limit_u_min = ProtoField.uint32 ("dji_dumlv1.flyc_config_table_get_item_attribute_limit_u_min", "LimitU minValue", base.DEC, nil, nil)
f.flyc_config_table_get_item_attribute_limit_u_max = ProtoField.uint32 ("dji_dumlv1.flyc_config_table_get_item_attribute_limit_u_max", "LimitU maxValue", base.DEC, nil, nil)
f.flyc_config_table_get_item_attribute_limit_f_def = ProtoField.float ("dji_dumlv1.flyc_config_table_get_item_attribute_limit_f_def", "LimitF defaultValue", nil, nil)
f.flyc_config_table_get_item_attribute_limit_f_min = ProtoField.float ("dji_dumlv1.flyc_config_table_get_item_attribute_limit_f_min", "LimitF minValue", nil, nil)
f.flyc_config_table_get_item_attribute_limit_f_max = ProtoField.float ("dji_dumlv1.flyc_config_table_get_item_attribute_limit_f_max", "LimitF maxValue", nil, nil)
f.flyc_config_table_get_item_attribute_name = ProtoField.stringz ("dji_dumlv1.flyc_config_table_get_item_attribute_name", "Name", base.ASCII, nil, nil)

local function flyc_config_table_get_item_attribute_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request
        subtree:add_le (f.flyc_config_table_get_item_attribute_table_no, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.flyc_config_table_get_item_attribute_index, payload(offset, 2))
        offset = offset + 2

        if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table Get Item Attribute: Offset does not match - internal inconsistency") end
    else -- Response
        subtree:add_le (f.flyc_config_table_get_item_attribute_status, payload(offset, 2))
        offset = offset + 2

        -- It is possible that the packet ends here, if there was an issue retrieving the item
        if (payload:len() >= 10) then
            subtree:add_le (f.flyc_config_table_get_item_attribute_table_no, payload(offset, 2))
            offset = offset + 2

            subtree:add_le (f.flyc_config_table_get_item_attribute_index, payload(offset, 2))
            offset = offset + 2

            local type_id = payload(offset,2):le_uint()
            subtree:add_le (f.flyc_config_table_get_item_attribute_type_id, payload(offset, 2))
            offset = offset + 2

            subtree:add_le (f.flyc_config_table_get_item_attribute_size, payload(offset, 2))
            offset = offset + 2

            --subtree:add_le (f.flyc_config_table_get_item_attribute_attribute, payload(offset, 2))
            --offset = offset + 2

            if (type_id <= 3) or (type_id == 10) then
                subtree:add_le (f.flyc_config_table_get_item_attribute_limit_u_def, payload(offset, 4))
                offset = offset + 4

                subtree:add_le (f.flyc_config_table_get_item_attribute_limit_u_min, payload(offset, 4))
                offset = offset + 4

                subtree:add_le (f.flyc_config_table_get_item_attribute_limit_u_max, payload(offset, 4))
                offset = offset + 4
            elseif (type_id >= 4) and (type_id <= 7) then
                subtree:add_le (f.flyc_config_table_get_item_attribute_limit_i_def, payload(offset, 4))
                offset = offset + 4

                subtree:add_le (f.flyc_config_table_get_item_attribute_limit_i_min, payload(offset, 4))
                offset = offset + 4

                subtree:add_le (f.flyc_config_table_get_item_attribute_limit_i_max, payload(offset, 4))
                offset = offset + 4
            elseif (type_id == 8) or (type_id == 9) then
                subtree:add_le (f.flyc_config_table_get_item_attribute_limit_f_def, payload(offset, 4))
                offset = offset + 4

                subtree:add_le (f.flyc_config_table_get_item_attribute_limit_f_min, payload(offset, 4))
                offset = offset + 4

                subtree:add_le (f.flyc_config_table_get_item_attribute_limit_f_max, payload(offset, 4))
                offset = offset + 4
            end

            local name_text = payload(offset, payload:len() - offset)
            subtree:add_le (f.flyc_config_table_get_item_attribute_name, name_text)
            offset = payload:len()
        end

        if (offset ~= 2) and (offset < 22) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table Get Item Attribute: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Config Table Get Item Attribute: Payload size different than expected") end
end

-- Flight Controller - Config Table: Get Item Value - 0xe2

f.flyc_config_table_get_item_value_status = ProtoField.uint16 ("dji_dumlv1.flyc_config_table_get_item_value_status", "Status", base.DEC, nil, nil)
f.flyc_config_table_get_item_value_table_no = ProtoField.int16 ("dji_dumlv1.flyc_config_table_get_item_value_table_no", "Table No", base.DEC, nil, nil)
f.flyc_config_table_get_item_value_unknown1 = ProtoField.int16 ("dji_dumlv1.flyc_config_table_get_item_value_unknown1", "Unknown1", base.DEC, nil, nil)
f.flyc_config_table_get_item_value_index = ProtoField.int16 ("dji_dumlv1.flyc_config_table_get_item_value_index", "Param Index", base.DEC, nil, nil)
f.flyc_config_table_get_item_value_value = ProtoField.bytes ("dji_dumlv1.flyc_config_table_get_item_value_value", "Param Value", base.SPACE, nil, nil, "Flight controller parameter value; size and type depends on parameter")

local function flyc_config_table_get_item_value_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request
        subtree:add_le (f.flyc_config_table_get_item_value_table_no, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.flyc_config_table_get_item_value_unknown1, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.flyc_config_table_get_item_value_index, payload(offset, 2))
        offset = offset + 2

        if (offset ~= 6) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table Get Item Value: Offset does not match - internal inconsistency") end
    else -- Response
        subtree:add_le (f.flyc_config_table_get_item_value_status, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.flyc_config_table_get_item_value_unknown1, payload(offset, 2))
        offset = offset + 2

        -- It is possible that the packet ends here, if there was an issue retrieving the item
        if (payload:len() >= 7) then
            subtree:add_le (f.flyc_config_table_get_item_value_index, payload(offset, 2))
            offset = offset + 2

            if (payload:len() - offset >= 1) then
                local varsize_val = payload(offset, payload:len() - offset)
                subtree:add (f.flyc_config_table_get_item_value_value, varsize_val)
                offset = payload:len()
            end
        end

        --if (offset ~= 2) and (offset < 18) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table Get Item Value: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Config Table Get Item Value: Payload size different than expected") end
end

-- Flight Controller - Config Table: Set Item Value - 0xe3

f.flyc_config_table_set_item_value_status = ProtoField.uint16 ("dji_dumlv1.flyc_config_table_set_item_value_status", "Status", base.DEC, nil, nil)
f.flyc_config_table_set_item_value_table_no = ProtoField.int16 ("dji_dumlv1.flyc_config_table_set_item_value_table_no", "Table No", base.DEC, nil, nil)
f.flyc_config_table_set_item_value_unknown1 = ProtoField.int16 ("dji_dumlv1.flyc_config_table_set_item_value_unknown1", "Unknown1", base.DEC, nil, nil)
f.flyc_config_table_set_item_value_index = ProtoField.int16 ("dji_dumlv1.flyc_config_table_set_item_value_index", "Param Index", base.DEC, nil, nil)
f.flyc_config_table_set_item_value_value = ProtoField.bytes ("dji_dumlv1.flyc_config_table_set_item_value_value", "Param Value", base.SPACE, nil, nil, "Flight controller parameter value; size and type depends on parameter")

local function flyc_config_table_set_item_value_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request
        subtree:add_le (f.flyc_config_table_set_item_value_table_no, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.flyc_config_table_set_item_value_unknown1, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.flyc_config_table_set_item_value_index, payload(offset, 2))
        offset = offset + 2

        if (payload:len() - offset >= 1) then
            local varsize_val = payload(offset, payload:len() - offset)
            subtree:add (f.flyc_config_table_set_item_value_value, varsize_val)
            offset = payload:len()
        end

        if (offset ~= 2) and (offset < 7) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table Set Item Value: Offset does not match - internal inconsistency") end
    else -- Response
        subtree:add_le (f.flyc_config_table_set_item_value_status, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.flyc_config_table_set_item_value_table_no, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.flyc_config_table_set_item_value_index, payload(offset, 2))
        offset = offset + 2

        if (payload:len() - offset >= 1) then
            local varsize_val = payload(offset, payload:len() - offset)
            subtree:add (f.flyc_config_table_set_item_value_value, varsize_val)
            offset = payload:len()
        end

        if (offset ~= 2) and (offset < 7) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table Set Item Value: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Config Table Set Item Value: Payload size different than expected") end
end

-- Flight Controller - Config Command Table: Get or Exec - 0xe9

f.flyc_config_command_table_get_or_exec_cmd_type = ProtoField.int16 ("dji_dumlv1.flyc_flyc_redundancy_status_cmd_type", "Command Type", base.DEC, nil, nil, "Positive values - exec, negative - get name, -1 - get count")

local function flyc_config_command_table_get_or_exec_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    local cmd = payload(offset,2):le_int()
    local valuestring
    if cmd == -1 then
        valuestring = "Get command count"
    elseif cmd < 0 then
        valuestring = string.format("Get command %d name", 1 - cmd)
    else -- cmd > 0
        valuestring = string.format("Exec command %d", cmd)
    end
    subtree:add_le (f.flyc_config_command_table_get_or_exec_cmd_type, payload(offset, 2), cmd, string.format("%s: %s (0x%02X)", "Command Type", valuestring, cmd))
    offset = offset + 2

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Command Table Get or Exec: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Config Command Table Get or Exec: Payload size different than expected") end
end

-- Flight Controller - Config Table: Get Param Info by Index - 0xf0
-- returns parameter name and properties

f.flyc_config_table_get_param_info_by_index_index = ProtoField.int16 ("dji_dumlv1.flyc_config_table_get_param_info_by_index_index", "Param Index", base.DEC, nil, nil)

f.flyc_config_table_get_param_info_by_index_status = ProtoField.uint8 ("dji_dumlv1.flyc_config_table_get_param_info_by_index_status", "Status", base.DEC, nil, nil)
f.flyc_config_table_get_param_info_by_index_type_id = ProtoField.uint16 ("dji_dumlv1.flyc_config_table_get_param_info_by_index_type_id", "TypeID", base.DEC, nil, nil)
f.flyc_config_table_get_param_info_by_index_size = ProtoField.int16 ("dji_dumlv1.flyc_config_table_get_param_info_by_index_size", "Size", base.DEC, nil, nil)
f.flyc_config_table_get_param_info_by_index_attribute = ProtoField.uint16 ("dji_dumlv1.flyc_config_table_get_param_info_by_index_attribute", "Attribute", base.HEX, nil, nil)
f.flyc_config_table_get_param_info_by_index_limit_i_min = ProtoField.int32 ("dji_dumlv1.flyc_config_table_get_param_info_by_index_limit_i_min", "LimitI minValue", base.DEC, nil, nil)
f.flyc_config_table_get_param_info_by_index_limit_i_max = ProtoField.int32 ("dji_dumlv1.flyc_config_table_get_param_info_by_index_limit_i_max", "LimitI maxValue", base.DEC, nil, nil)
f.flyc_config_table_get_param_info_by_index_limit_i_def = ProtoField.int32 ("dji_dumlv1.flyc_config_table_get_param_info_by_index_limit_i_def", "LimitI defaultValue", base.DEC, nil, nil)
f.flyc_config_table_get_param_info_by_index_limit_u_min = ProtoField.uint32 ("dji_dumlv1.flyc_config_table_get_param_info_by_index_limit_u_min", "LimitU minValue", base.DEC, nil, nil)
f.flyc_config_table_get_param_info_by_index_limit_u_max = ProtoField.uint32 ("dji_dumlv1.flyc_config_table_get_param_info_by_index_limit_u_max", "LimitU maxValue", base.DEC, nil, nil)
f.flyc_config_table_get_param_info_by_index_limit_u_def = ProtoField.uint32 ("dji_dumlv1.flyc_config_table_get_param_info_by_index_limit_u_def", "LimitU defaultValue", base.DEC, nil, nil)
f.flyc_config_table_get_param_info_by_index_limit_f_min = ProtoField.float ("dji_dumlv1.flyc_config_table_get_param_info_by_index_limit_f_min", "LimitF minValue", nil, nil)
f.flyc_config_table_get_param_info_by_index_limit_f_max = ProtoField.float ("dji_dumlv1.flyc_config_table_get_param_info_by_index_limit_f_max", "LimitF maxValue", nil, nil)
f.flyc_config_table_get_param_info_by_index_limit_f_def = ProtoField.float ("dji_dumlv1.flyc_config_table_get_param_info_by_index_limit_f_def", "LimitF defaultValue", nil, nil)
f.flyc_config_table_get_param_info_by_index_name = ProtoField.stringz ("dji_dumlv1.flyc_config_table_get_param_info_by_index_name", "Name", base.ASCII, nil, nil)

local function flyc_config_table_get_param_info_by_index_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request
        subtree:add_le (f.flyc_config_table_get_param_info_by_index_index, payload(offset, 2))
        offset = offset + 2

        if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table Get Param Info by Index: Offset does not match - internal inconsistency") end
    else -- Response
        -- Payload has 19 bytes + null-terminated name on P3X_FW_V01.07.0060
        subtree:add_le (f.flyc_config_table_get_param_info_by_index_status, payload(offset, 1))
        offset = offset + 1

        -- It is possible that the packet ends here, if there was an issue retrieving the item
        if (payload:len() >= 8) then
            local type_id = payload(offset,2):le_uint()
            subtree:add_le (f.flyc_config_table_get_param_info_by_index_type_id, payload(offset, 2))
            offset = offset + 2

            subtree:add_le (f.flyc_config_table_get_param_info_by_index_size, payload(offset, 2))
            offset = offset + 2

            subtree:add_le (f.flyc_config_table_get_param_info_by_index_attribute, payload(offset, 2))
            offset = offset + 2

            if (type_id <= 3) or (type_id == 10) then
                subtree:add_le (f.flyc_config_table_get_param_info_by_index_limit_u_min, payload(offset, 4))
                offset = offset + 4

                subtree:add_le (f.flyc_config_table_get_param_info_by_index_limit_u_max, payload(offset, 4))
                offset = offset + 4

                subtree:add_le (f.flyc_config_table_get_param_info_by_index_limit_u_def, payload(offset, 4))
                offset = offset + 4
            elseif (type_id >= 4) and (type_id <= 7) then
                subtree:add_le (f.flyc_config_table_get_param_info_by_index_limit_i_min, payload(offset, 4))
                offset = offset + 4

                subtree:add_le (f.flyc_config_table_get_param_info_by_index_limit_i_max, payload(offset, 4))
                offset = offset + 4

                subtree:add_le (f.flyc_config_table_get_param_info_by_index_limit_i_def, payload(offset, 4))
                offset = offset + 4
            elseif (type_id == 8) or (type_id == 9) then
                subtree:add_le (f.flyc_config_table_get_param_info_by_index_limit_f_min, payload(offset, 4))
                offset = offset + 4

                subtree:add_le (f.flyc_config_table_get_param_info_by_index_limit_f_max, payload(offset, 4))
                offset = offset + 4

                subtree:add_le (f.flyc_config_table_get_param_info_by_index_limit_f_def, payload(offset, 4))
                offset = offset + 4
            end

            local name_text = payload(offset, payload:len() - offset)
            subtree:add_le (f.flyc_config_table_get_param_info_by_index_name, name_text)
            offset = payload:len()
        end

        --if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table Get Param Info by Index: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Config Table Get Param Info by Index: Payload size different than expected") end
end

-- Flight Controller - Config Table: Read Params By Index - 0xf1

f.flyc_config_table_read_param_by_index_index = ProtoField.int16 ("dji_dumlv1.flyc_config_table_read_param_by_index_index", "Param Index", base.DEC, nil, nil)

local function flyc_config_table_read_param_by_index_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request
        subtree:add_le (f.flyc_config_table_read_param_by_index_index, payload(offset, 2))
        offset = offset + 2

        if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table Read Params By Index: Offset does not match - internal inconsistency") end
    else -- Response
        -- Payload unfinished
        subtree:add_le (f.flyc_config_table_read_param_by_index_index, payload(offset, 2))
        offset = offset + 2

        if (offset ~= 19) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table Read Params By Index: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Config Table Read Params By Index: Payload size different than expected") end
end


-- Flight Controller - Config Table: Get Param Info By Hash - 0xf7

enums.FLYC_PARAMETER_BY_HASH_ENUM = {
    [0x4d5c7a3d] = 'cfg_var_table_size_0',
    [0x153d84bc] = 'global.status',
    [0xdd08bb88] = 'fix_send_index[ 0]_0',
    [0xde08bb88] = 'fix_send_index[ 1]_0',
    [0xdf08bb88] = 'fix_send_index[ 2]_0',
    [0xe008bb88] = 'fix_send_index[ 3]_0',
    [0xe108bb88] = 'fix_send_index[ 4]_0',
    [0xe208bb88] = 'fix_send_index[ 5]_0',
    [0xe308bb88] = 'fix_send_index[ 6]_0',
    [0xe408bb88] = 'fix_send_index[ 7]_0',
    [0xe508bb88] = 'fix_send_index[ 8]_0',
    [0xe608bb88] = 'fix_send_index[ 9]_0',
    [0xdd08bbdd] = 'fix_send_index[10]_0',
    [0xde08bbdd] = 'fix_send_index[11]_0',
    [0xdf08bbdd] = 'fix_send_index[12]_0',
    [0xe008bbdd] = 'fix_send_index[13]_0',
    [0xe108bbdd] = 'fix_send_index[14]_0',
    [0xe208bbdd] = 'fix_send_index[15]_0',
    [0xe308bbdd] = 'fix_send_index[16]_0',
    [0xe408bbdd] = 'fix_send_index[17]_0',
    [0xe508bbdd] = 'fix_send_index[18]_0',
    [0xe608bbdd] = 'fix_send_index[19]_0',
    [0xdd08bbe2] = 'fix_send_index[20]_0',
    [0xde08bbe2] = 'fix_send_index[21]_0',
    [0xdf08bbe2] = 'fix_send_index[22]_0',
    [0xe008bbe2] = 'fix_send_index[23]_0',
    [0xe108bbe2] = 'fix_send_index[24]_0',
    [0xe208bbe2] = 'fix_send_index[25]_0',
    [0xe308bbe2] = 'fix_send_index[26]_0',
    [0xe408bbe2] = 'fix_send_index[27]_0',
    [0xe508bbe2] = 'fix_send_index[28]_0',
    [0xe608bbe2] = 'fix_send_index[29]_0',
    [0xdd08bbe7] = 'fix_send_index[30]_0',
    [0xde08bbe7] = 'fix_send_index[31]_0',
    [0xdf08bbe7] = 'fix_send_index[32]_0',
    [0xe008bbe7] = 'fix_send_index[33]_0',
    [0xe108bbe7] = 'fix_send_index[34]_0',
    [0xe208bbe7] = 'fix_send_index[35]_0',
    [0xe308bbe7] = 'fix_send_index[36]_0',
    [0xe408bbe7] = 'fix_send_index[37]_0',
    [0xe508bbe7] = 'fix_send_index[38]_0',
    [0xe608bbe7] = 'fix_send_index[39]_0',
    [0xdd08bbec] = 'fix_send_index[40]_0',
    [0xde08bbec] = 'fix_send_index[41]_0',
    [0xdf08bbec] = 'fix_send_index[42]_0',
    [0xe008bbec] = 'fix_send_index[43]_0',
    [0xe108bbec] = 'fix_send_index[44]_0',
    [0xe208bbec] = 'fix_send_index[45]_0',
    [0xe308bbec] = 'fix_send_index[46]_0',
    [0xe408bbec] = 'fix_send_index[47]_0',
    [0x45f0eea6] = 'fix_send[0].send_frequency_0',
    [0x087312bc] = 'fix_send[0].send_start_index_0',
    [0xe4ee4283] = 'fix_send[0].send_size_0',
    [0x4861eea6] = 'fix_send[1].send_frequency_0',
    [0x08731ef1] = 'fix_send[1].send_start_index_0',
    [0xe4eebf83] = 'fix_send[1].send_size_0',
    [0x4ad2eea6] = 'fix_send[2].send_frequency_0',
    [0x08732b26] = 'fix_send[2].send_start_index_0',
    [0xe4ef3c83] = 'fix_send[2].send_size_0',
    [0x4d43eea6] = 'fix_send[3].send_frequency_0',
    [0x0873375b] = 'fix_send[3].send_start_index_0',
    [0xe4efb983] = 'fix_send[3].send_size_0',
    [0xa34b7f1f] = 'standard_range_min_0',
    [0x9b557f1f] = 'standard_range_max_0',
    [0x0cda8e11] = 'config_parameter.assistant_timeout_0',
    [0x2a02a5df] = 'config_parameter.motor_stop_lock_0',
    [0xa99b69e5] = 'g_config.device.is_locked_0',
    [0x92003629] = 'g_config.system_command.mapper[COMMAND_AILERON]_0',
    [0x4a43be60] = 'g_config.system_command.mapper[COMMAND_ELEVATOR]_0',
    [0x1c195b96] = 'g_config.system_command.mapper[COMMAND_THROTTLE]_0',
    [0xa478fe6d] = 'g_config.system_command.mapper[COMMAND_RUDDER]_0',
    [0x20d8934b] = 'g_config.system_command.mapper[COMMAND_MODE]_0',
    [0x9e38c661] = 'g_config.system_command.mapper[COMMAND_IOC]_0',
    [0xe80fbdb5] = 'g_config.system_command.mapper[COMMAND_GO_HOME]_0',
    [0x1f80d3b8] = 'g_config.system_command.mapper[COMMAND_AUTO_TAKE_OFF]_0',
    [0x83f271d3] = 'g_config.system_command.mapper[COMMAND_KNOB_X1]_0',
    [0x84f271d3] = 'g_config.system_command.mapper[COMMAND_KNOB_X2]_0',
    [0x85f271d3] = 'g_config.system_command.mapper[COMMAND_KNOB_X3]_0',
    [0x86f271d3] = 'g_config.system_command.mapper[COMMAND_KNOB_X4]_0',
    [0x87f271d3] = 'g_config.system_command.mapper[COMMAND_KNOB_X5]_0',
    [0x88f271d3] = 'g_config.system_command.mapper[COMMAND_KNOB_X6]_0',
    [0x7a85de27] = 'g_config.system_command.mapper[COMMAND_PANTILT_PITCH]_0',
    [0xd499a583] = 'g_config.system_command.mapper[COMMAND_PANTILT_ROLL]_0',
    [0x82e5be2e] = 'g_config.system_command.mapper[COMMAND_PANTILT_YAW]_0',
    [0x7c2e22e2] = 'g_config.system_command.mapper[COMMAND_H3_2D_TILT]_0',
    [0x1fb83a7d] = 'g_config.system_command.mapper[COMMAND_D1]_0',
    [0x20b83a7d] = 'g_config.system_command.mapper[COMMAND_D2]_0',
    [0x21b83a7d] = 'g_config.system_command.mapper[COMMAND_D3]_0',
    [0x22b83a7d] = 'g_config.system_command.mapper[COMMAND_D4]_0',
    [0x2dba613c] = 'g_config.system_command.mapper[COMMAND_GEAR]_0',
    [0xf8c3b05a] = 'g_config.system_command.reverse_input_0',
    [0x63eb115b] = 'g_config.aircraft.aircraft_type_0',
    [0x9bb356f8] = 'g_config.aircraft.custom_mix[0][0]_0',
    [0x9cb356f8] = 'g_config.aircraft.custom_mix[0][1]_0',
    [0x9db356f8] = 'g_config.aircraft.custom_mix[0][2]_0',
    [0x9eb356f8] = 'g_config.aircraft.custom_mix[0][3]_0',
    [0x9bb856f8] = 'g_config.aircraft.custom_mix[1][0]_0',
    [0x9cb856f8] = 'g_config.aircraft.custom_mix[1][1]_0',
    [0x9db856f8] = 'g_config.aircraft.custom_mix[1][2]_0',
    [0x9eb856f8] = 'g_config.aircraft.custom_mix[1][3]_0',
    [0x9bbd56f8] = 'g_config.aircraft.custom_mix[2][0]_0',
    [0x9cbd56f8] = 'g_config.aircraft.custom_mix[2][1]_0',
    [0x9dbd56f8] = 'g_config.aircraft.custom_mix[2][2]_0',
    [0x9ebd56f8] = 'g_config.aircraft.custom_mix[2][3]_0',
    [0x9bc256f8] = 'g_config.aircraft.custom_mix[3][0]_0',
    [0x9cc256f8] = 'g_config.aircraft.custom_mix[3][1]_0',
    [0x9dc256f8] = 'g_config.aircraft.custom_mix[3][2]_0',
    [0x9ec256f8] = 'g_config.aircraft.custom_mix[3][3]_0',
    [0x9bc756f8] = 'g_config.aircraft.custom_mix[4][0]_0',
    [0x9cc756f8] = 'g_config.aircraft.custom_mix[4][1]_0',
    [0x9dc756f8] = 'g_config.aircraft.custom_mix[4][2]_0',
    [0x9ec756f8] = 'g_config.aircraft.custom_mix[4][3]_0',
    [0x9bcc56f8] = 'g_config.aircraft.custom_mix[5][0]_0',
    [0x9ccc56f8] = 'g_config.aircraft.custom_mix[5][1]_0',
    [0x9dcc56f8] = 'g_config.aircraft.custom_mix[5][2]_0',
    [0x9ecc56f8] = 'g_config.aircraft.custom_mix[5][3]_0',
    [0x9bd156f8] = 'g_config.aircraft.custom_mix[6][0]_0',
    [0x9cd156f8] = 'g_config.aircraft.custom_mix[6][1]_0',
    [0x9dd156f8] = 'g_config.aircraft.custom_mix[6][2]_0',
    [0x9ed156f8] = 'g_config.aircraft.custom_mix[6][3]_0',
    [0x9bd656f8] = 'g_config.aircraft.custom_mix[7][0]_0',
    [0x9cd656f8] = 'g_config.aircraft.custom_mix[7][1]_0',
    [0x9dd656f8] = 'g_config.aircraft.custom_mix[7][2]_0',
    [0x9ed656f8] = 'g_config.aircraft.custom_mix[7][3]_0',
    [0x3d18e504] = 'g_config.aircraft.custom_num_of_motor_0',
    [0x9f472a88] = 'g_config.imu_gps.imu_offset_x_0',
    [0x9f482a88] = 'g_config.imu_gps.imu_offset_y_0',
    [0x9f492a88] = 'g_config.imu_gps.imu_offset_z_0',
    [0x6d4631ff] = 'g_config.imu_gps.gps_offset_x_0',
    [0x6d4731ff] = 'g_config.imu_gps.gps_offset_y_0',
    [0x6d4831ff] = 'g_config.imu_gps.gps_offset_z_0',
    [0x094922ed] = 'g_config.imu_gps.mvo_offset_x_0',
    [0x094a22ed] = 'g_config.imu_gps.mvo_offset_y_0',
    [0x094b22ed] = 'g_config.imu_gps.mvo_offset_z_0',
    [0x3718ae88] = 'g_config.imu_gps.imu_dir_0',
    [0x5a082d3d] = 'g_config.imu_dir[0][0]_0',
    [0x5b082d3d] = 'g_config.imu_dir[0][1]_0',
    [0x5c082d3d] = 'g_config.imu_dir[0][2]_0',
    [0x5a0d2d3d] = 'g_config.imu_dir[1][0]_0',
    [0x5b0d2d3d] = 'g_config.imu_dir[1][1]_0',
    [0x5c0d2d3d] = 'g_config.imu_dir[1][2]_0',
    [0x5a122d3d] = 'g_config.imu_dir[2][0]_0',
    [0x5b122d3d] = 'g_config.imu_dir[2][1]_0',
    [0x5c122d3d] = 'g_config.imu_dir[2][2]_0',
    [0xa7e5f3c9] = 'g_config.receiver.type_0',
    [0x25b4d7f7] = 'g_config.receiver.calibration_type_0',
    [0xa6eb2915] = 'g_config.receiver.travel_min[ 0]_0',
    [0xa7eb2915] = 'g_config.receiver.travel_min[ 1]_0',
    [0xa8eb2915] = 'g_config.receiver.travel_min[ 2]_0',
    [0xa9eb2915] = 'g_config.receiver.travel_min[ 3]_0',
    [0xaaeb2915] = 'g_config.receiver.travel_min[ 4]_0',
    [0xabeb2915] = 'g_config.receiver.travel_min[ 5]_0',
    [0xaceb2915] = 'g_config.receiver.travel_min[ 6]_0',
    [0xadeb2915] = 'g_config.receiver.travel_min[ 7]_0',
    [0xaeeb2915] = 'g_config.receiver.travel_min[ 8]_0',
    [0xafeb2915] = 'g_config.receiver.travel_min[ 9]_0',
    [0xa6eb296a] = 'g_config.receiver.travel_min[10]_0',
    [0xa7eb296a] = 'g_config.receiver.travel_min[11]_0',
    [0xa8eb296a] = 'g_config.receiver.travel_min[12]_0',
    [0xa9eb296a] = 'g_config.receiver.travel_min[13]_0',
    [0xaaeb296a] = 'g_config.receiver.travel_min[14]_0',
    [0xabeb296a] = 'g_config.receiver.travel_min[15]_0',
    [0x7f1d2915] = 'g_config.receiver.travel_max[ 0]_0',
    [0x801d2915] = 'g_config.receiver.travel_max[ 1]_0',
    [0x811d2915] = 'g_config.receiver.travel_max[ 2]_0',
    [0x821d2915] = 'g_config.receiver.travel_max[ 3]_0',
    [0x831d2915] = 'g_config.receiver.travel_max[ 4]_0',
    [0x841d2915] = 'g_config.receiver.travel_max[ 5]_0',
    [0x851d2915] = 'g_config.receiver.travel_max[ 6]_0',
    [0x861d2915] = 'g_config.receiver.travel_max[ 7]_0',
    [0x871d2915] = 'g_config.receiver.travel_max[ 8]_0',
    [0x881d2915] = 'g_config.receiver.travel_max[ 9]_0',
    [0x7f1d296a] = 'g_config.receiver.travel_max[10]_0',
    [0x801d296a] = 'g_config.receiver.travel_max[11]_0',
    [0x811d296a] = 'g_config.receiver.travel_max[12]_0',
    [0x821d296a] = 'g_config.receiver.travel_max[13]_0',
    [0x831d296a] = 'g_config.receiver.travel_max[14]_0',
    [0x841d296a] = 'g_config.receiver.travel_max[15]_0',
    [0x21599b36] = 'g_config.device.dbus_adapter_0',
    [0x267697ec] = 'g_config.control.basic_craft_roll_0',
    [0x6d96fe16] = 'g_config.control.basic_craft_pitch_0',
    [0x7e316989] = 'g_config.control.basic_craft_yaw_0',
    [0xb60e3dab] = 'g_config.control.basic_craft_thrust_0',
    [0xcd725af3] = 'g_config.control.basic_roll_0',
    [0x695a0859] = 'g_config.control.basic_pitch_0',
    [0x19d8654e] = 'g_config.control.basic_yaw_0',
    [0x79188097] = 'g_config.control.basic_thrust_0',
    [0xc7801bfc] = 'g_config.control.tilt_atti_gain_0',
    [0xe61698ca] = 'g_config.control.tilt_gyro_gain_0',
    [0xc993ee5d] = 'g_config.control.tilt_gyro_acc_gain_0',
    [0xdb5352b4] = 'g_config.control.torsion_atti_gain_0',
    [0xf9e9cf82] = 'g_config.control.torsion_gyro_gain_0',
    [0x2cb3fffa] = 'g_config.control.torsion_gyro_acc_gain_0',
    [0xc33ea011] = 'g_config.control.horiz_pos_gain_0',
    [0xa03f3517] = 'g_config.control.horiz_vel_gain_0',
    [0x78a91cbc] = 'g_config.control.horiz_vel_damping_gain_0',
    [0x2e22b2d4] = 'g_config.control.horiz_atti_damping_gain_0',
    [0x1eea7d09] = 'g_config.control.horiz_i_gain_0',
    [0x60941e3e] = 'g_config.control.vert_pos_gain_0',
    [0x3d94b344] = 'g_config.control.vert_vel_gain_0',
    [0x1092a612] = 'g_config.control.vert_acc_gain_0',
    [0x04f31a5f] = 'g_config.control.vert_i_gain_0',
    [0x16330043] = 'g_config.control.multi_control_mode_enable_0',
    [0xde3b160b] = 'g_config.control.control_mode[0]_0',
    [0xdf3b160b] = 'g_config.control.control_mode[1]_0',
    [0xe03b160b] = 'g_config.control.control_mode[2]_0',
    [0x89d49b2a] = 'g_config.advanced_function.fail_safe_protection_enabled_0',
    [0xe5155514] = 'g_config.advanced_function.one_key_go_home_enabled_0',
    [0xee98369f] = 'g_config.advanced_function.voltage_protection_enabled_0',
    [0x80f73ae7] = 'g_config.advanced_function.intelligence_orientation_enabled_0',
    [0xcb5f61b5] = 'g_config.advanced_function.pantilt_enabled_0',
    [0xae52d19a] = 'g_config.advanced_function.height_limit_enabled_0',
    [0xbf372921] = 'g_config.advanced_function.avoid_ground_enabled_0',
    [0x7ece6d19] = 'g_config.advanced_function.radius_limit_enabled_0',
    [0xaaf942e2] = 'g_config.advanced_function.intelligence_gear_enabled_0',
    [0xcb653d71] = 'g_config.fail_safe.protect_action_0',
    [0x97fbc173] = 'g_config.go_home.go_home_method_0',
    [0x38cc63dc] = 'g_config.go_home.fixed_go_home_altitude_0',
    [0x6e280d61] = 'g_config.go_home.go_home_heading_option_0',
    [0xdc5c00af] = 'g_config.go_home.go_home_when_running_gs_0',
    [0xb502df25] = 'g_config.pantilt.output_frequency_0',
    [0xef56a152] = 'g_config.pantilt.roll_travel.travel_min_0',
    [0xe760a152] = 'g_config.pantilt.roll_travel.travel_max_0',
    [0x5a0b10be] = 'g_config.pantilt.roll_travel.travel_center_0',
    [0x8f90baac] = 'g_config.pantilt.pitch_travel.travel_min_0',
    [0x879abaac] = 'g_config.pantilt.pitch_travel.travel_max_0',
    [0xb22c333b] = 'g_config.pantilt.pitch_travel.travel_center_0',
    [0xbba240f9] = 'g_config.pantilt.yaw_travel.travel_min_0',
    [0xb3ac40f9] = 'g_config.pantilt.yaw_travel.travel_max_0',
    [0x00088ade] = 'g_config.pantilt.yaw_travel.travel_center_0',
    [0x4d81490f] = 'g_config.pantilt.roll_gain_0',
    [0x769b24a8] = 'g_config.pantilt.pitch_gain_0',
    [0xd212479b] = 'g_config.pantilt.yaw_gain_0',
    [0xd8a04994] = 'g_config.pantilt.reverse_output_0',
    [0x788a8a9d] = 'g_config.pantilt.roll_speed_0',
    [0x9266246a] = 'g_config.pantilt.pitch_speed_0',
    [0x09891936] = 'g_config.pantilt.yaw_speed_0',
    [0xa2a389c2] = 'g_config.intelligence_orientation.app_ioc_type_0',
    [0x163fda61] = 'g_config.intelligence_orientation.control_mode[0]_0',
    [0x173fda61] = 'g_config.intelligence_orientation.control_mode[1]_0',
    [0x183fda61] = 'g_config.intelligence_orientation.control_mode[2]_0',
    [0x425c0a94] = 'g_config.flying_limit.max_radius_0',
    [0x0371238a] = 'g_config.flying_limit.max_height_0',
    [0x0438298a] = 'g_config.flying_limit.min_height_0',
    [0x0000e114] = 'g_config.flying_limit.auto_landing_enabled_0',
    [0xaf4431b1] = 'g_config.knob.control_channel[KNOB_BASIC_ROLL]_0',
    [0x25120b6e] = 'g_config.knob.control_channel[KNOB_BASIC_PITCH]_0',
    [0x58c068bb] = 'g_config.knob.control_channel[KNOB_BASIC_YAW]_0',
    [0x03fff884] = 'g_config.knob.control_channel[KNOB_BASIC_THRUST]_0',
    [0xc42309e3] = 'g_config.knob.control_channel[KNOB_ATTI_GAIN]_0',
    [0x5a9fd87e] = 'g_config.knob.control_channel[KNOB_GYRO_GAIN]_0',
    [0x370e35f7] = 'g_config.knob.enabled_bits_0',
    [0xfb29d937] = 'g_config.voltage.level_1_protect_0',
    [0xfb42d937] = 'g_config.voltage.level_2_protect_0',
    [0x3ecd7d52] = 'g_config.voltage.line_loss_0',
    [0x8c006935] = 'g_config.voltage.calibrate_scale_0',
    [0x41a4e115] = 'g_config.voltage.level_1_protect_type_0',
    [0xbea4e115] = 'g_config.voltage.level_2_protect_type_0',
    [0x58b4c372] = 'g_config.voltage.battery_cell_0',
    [0x5aae5bcd] = 'g_config.voltage2.level_1_voltage_0',
    [0xc214cd92] = 'g_config.voltage2.level_1_function_0',
    [0x5ac75bcd] = 'g_config.voltage2.level_2_voltage_0',
    [0xdb14cd92] = 'g_config.voltage2.level_2_function_0',
    [0xe2c0cd6f] = 'g_config.voltage2.user_set_smart_bat_0',
    [0xbc18a2a4] = 'g_config.voltage2.level1_smart_battert_gohome_0',
    [0x79e5fb9b] = 'g_config.voltage2.level2_smart_battert_land_0',
    [0xd2184d1f] = 'g_config.voltage2.judge_smart_battery_communite_0',
    [0xbbb39539] = 'g_config.voltage2.vol_ceof_0',
    [0x800de80e] = 'g_config.output_servo.reverse_bits_0',
    [0x3615bc7b] = 'g_config.output_servo.center_offset[0]_0',
    [0x3715bc7b] = 'g_config.output_servo.center_offset[1]_0',
    [0x3815bc7b] = 'g_config.output_servo.center_offset[2]_0',
    [0x3915bc7b] = 'g_config.output_servo.center_offset[3]_0',
    [0x3a15bc7b] = 'g_config.output_servo.center_offset[4]_0',
    [0x3b15bc7b] = 'g_config.output_servo.center_offset[5]_0',
    [0x3c15bc7b] = 'g_config.output_servo.center_offset[6]_0',
    [0x3d15bc7b] = 'g_config.output_servo.center_offset[7]_0',
    [0x9b913bbd] = 'g_config.output_servo.min_limit[0]_0',
    [0x9c913bbd] = 'g_config.output_servo.min_limit[1]_0',
    [0x9d913bbd] = 'g_config.output_servo.min_limit[2]_0',
    [0x9e913bbd] = 'g_config.output_servo.min_limit[3]_0',
    [0x9f913bbd] = 'g_config.output_servo.min_limit[4]_0',
    [0xa0913bbd] = 'g_config.output_servo.min_limit[5]_0',
    [0xa1913bbd] = 'g_config.output_servo.min_limit[6]_0',
    [0xa2913bbd] = 'g_config.output_servo.min_limit[7]_0',
    [0x959137da] = 'g_config.output_servo.max_limit[0]_0',
    [0x969137da] = 'g_config.output_servo.max_limit[1]_0',
    [0x979137da] = 'g_config.output_servo.max_limit[2]_0',
    [0x989137da] = 'g_config.output_servo.max_limit[3]_0',
    [0x999137da] = 'g_config.output_servo.max_limit[4]_0',
    [0x9a9137da] = 'g_config.output_servo.max_limit[5]_0',
    [0x9b9137da] = 'g_config.output_servo.max_limit[6]_0',
    [0x9c9137da] = 'g_config.output_servo.max_limit[7]_0',
    [0x2f449a05] = 'g_config.output_servo.pwm_min_0',
    [0x274e9a05] = 'g_config.output_servo.pwm_max_0',
    [0xe91b9571] = 'g_config.engine.lower_bound_0',
    [0x016c99db] = 'g_config.engine.upper_bound_0',
    [0x53141284] = 'g_config.engine.idle_level_0',
    [0x3b532ef6] = 'g_config.engine.idle_time_0',
    [0x4c5635f5] = 'g_config.engine.stand_by_level_0',
    [0x88a90e16] = 'g_config.engine.prop_auto_preload_0',
    [0xb36410a7] = 'g_config.engine.motor_fc_0',
    [0x482bd8e2] = 'g_config.craft_model.volt_max_0',
    [0xbdd98742] = 'g_config.craft_model.kv_0',
    [0xa4d08742] = 'g_config.craft_model.Rm_0',
    [0x76832c19] = 'g_config.craft_model.I_max_0',
    [0x7e792c19] = 'g_config.craft_model.I_min_0',
    [0x88092911] = 'g_config.craft_model.Inertia_motor_0',
    [0x95cf8742] = 'g_config.craft_model.Cl_0',
    [0x95d48742] = 'g_config.craft_model.Cq_0',
    [0x28890508] = 'g_config.craft_model.Inertia_prop_0',
    [0x14a1485e] = 'g_config.craft_model.motor_tilt_angle_0',
    [0xe372dfc7] = 'g_config.control.vel_smooth_time_0',
    [0xbbf0287c] = 'g_config.control.vel_braking_threshold_0',
    [0xde0fff00] = 'g_config.control.horiz_vel_atti_range_0',
    [0x3d833d3a] = 'g_config.control.horiz_emergency_brake_tilt_max_0',
    [0x9f9646e9] = 'g_config.control.atti_limit_0',
    [0x9da51eee] = 'g_config.control.atti_range_0',
    [0x93005d68] = 'g_config.control.avoid_atti_range_0',
    [0x4fd745a0] = 'g_config.control.atti_tilt_w_rate_0',
    [0x4fb63745] = 'g_config.control.atti_torsion_w_rate_0',
    [0x75b33314] = 'g_config.control.manual_tilt_w_rate_0',
    [0xc47382e6] = 'g_config.control.manual_torsion_w_rate_0',
    [0x3d45f2c8] = 'g_config.control.vert_up_vel_0',
    [0x70dbcaa7] = 'g_config.control.vert_down_vel_0',
    [0xe9d8b514] = 'g_config.control.thr_exp_mid_point_0',
    [0xf5fcaa49] = 'g_config.control.yaw_exp_mid_point_0',
    [0x2b53609f] = 'g_config.control.tilt_exp_mid_point_0',
    [0xbdc6ae31] = 'g_config.control.dyn_safe_thrust_0',
    [0xc956d11c] = 'g_config.control.dyn_tilt_min_0',
    [0x34f043ac] = 'g_config.control.rotor_fault_test_type_0',
    [0xdfb7fbd6] = 'g_config.control.rotor_fault_detection_time_0',
    [0x9eeedfaa] = 'g_config.control.brake_sensitivity_0',
    [0x43224470] = 'g_config.control.rc_tilt_sensitivity_0',
    [0x424799b9] = 'g_config.control.rc_yaw_sensitivity_0',
    [0x4de15af5] = 'g_config.control.rc_throttle_sensitivity_0',
    [0xe6e339fa] = 'g_config.control.torsion_ang_vel_cmd_slope_0',
    [0xdca13b95] = 'g_config.control.torsion_ang_acc_cmd_slope_0',
    [0x7778ce09] = 'g_config.control.throttle_output_max_0',
    [0xfb0448a7] = 'g_config.control.yaw_output_max_0',
    [0x54412dac] = 'g_config.control.atti_bat_limit_0',
    [0xbfa51130] = 'g_config.control.torsion_w_rate_bat_limit_0',
    [0x4ef3060f] = 'g_config.control.vert_vel_up_bat_limit_0',
    [0x5d1cda43] = 'g_config.control.vert_vel_down_bat_limit_0',
    [0x41478a8a] = 'g_config.imu_para_cfg.baro_cfg.pos_baro_gain_0',
    [0x4430a51f] = 'g_config.imu_para_cfg.baro_cfg.vel_baro_gain_0',
    [0x39eea6ba] = 'g_config.imu_para_cfg.baro_cfg.acc_baro_gain_0',
    [0x08c8dc53] = 'g_config.imu_para_cfg.baro_cfg.acc_bias_baro_p_gain_0',
    [0xe5c8dc4e] = 'g_config.imu_para_cfg.baro_cfg.acc_bias_baro_i_gain_0',
    [0x30acd64b] = 'g_config.imu_para_cfg.imu_para_filter.w_fc_0',
    [0x30ac684b] = 'g_config.imu_para_cfg.imu_para_filter.a_fc_0',
    [0x7f0bab81] = 'g_config.imu_para_cfg.imu_para_filter.w_a_fc1_0',
    [0x7f0cab81] = 'g_config.imu_para_cfg.imu_para_filter.w_a_fc2_0',
    [0xd89d7078] = 'g_config.imu_para_cfg.imu_para_filter.vel_fc_0',
    [0x6f934378] = 'g_config.imu_para_cfg.imu_para_filter.acc_fc_0',
    [0x8b525fe9] = 'g_config.imu_para_cfg.imu_adv_func.fuse_with_usonic_0',
    [0xf0318606] = 'g_config.imu_para_cfg.imu_adv_func.fuse_with_vo_z_0',
    [0x4ef39e97] = 'g_config.imu_para_cfg.imu_adv_func.vo_source_type_0',
    [0x74b5b183] = 'g_config.imu_para_cfg.imu_adv_func.vo_vel_with_large_tilt_deny_0',
    [0x7a8e3c44] = 'g_config.imu_para_cfg.imu_adv_func.vo_vel_strong_outlier_deny_0',
    [0xf62ed066] = 'g_config.imu_para_cfg.imu_adv_func.vo_vel_with_3m_deny_0',
    [0xb64b78e5] = 'g_config.imu_para_cfg.imu_adv_func.vo_vel_pg_flag_couple_0',
    [0x5b317388] = 'g_config.imu_para_cfg.imu_adv_func.vo_delay_tick_0',
    [0x63fc1641] = 'g_config.imu_para_cfg.imu_adv_func.fuse_with_rtk_0',
    [0xde9b1b7b] = 'g_config.novice_cfg.novice_func_enabled_0',
    [0xd9ab9f79] = 'g_config.novice_cfg.max_height_0',
    [0x18968688] = 'g_config.novice_cfg.max_radius_0',
    [0x81b81491] = 'g_config.novice_cfg.atti_range_0',
    [0x1c038b7b] = 'g_config.novice_cfg.atti_tilt_w_rate_0',
    [0x29b314a3] = 'g_config.novice_cfg.atti_torsion_w_rate_0',
    [0x503b953c] = 'g_config.novice_cfg.vert_up_vel_0',
    [0x13502975] = 'g_config.novice_cfg.vert_down_vel_0',
    [0xb9a37abd] = 'g_config.led_cfg.new_led_enable_0',
    [0xc5429582] = 'g_config.gps_cfg.gps_enable_0',
    [0xde346e72] = 'g_config.gps_cfg.super_svn_0',
    [0xaafda7b2] = 'g_config.gps_cfg.fix_svn_0',
    [0xd8cf9a09] = 'g_config.gps_cfg.good_svn_0',
    [0x357f6e2c] = 'g_config.gps_cfg.super_hdop_0',
    [0xfeb8ad28] = 'g_config.gps_cfg.fix_hdop_0',
    [0xd0ab050e] = 'g_config.gps_cfg.good_hdop_0',
    [0x97723ffc] = 'g_config.gear_cfg.gear_speed_0',
    [0xa67353e8] = 'g_config.gear_cfg.gear_state_0',
    [0x3679c82d] = 'g_config.gear_cfg.pack_flag_0',
    [0x45780e6e] = 'g_config.gear_cfg.pack_type_0',
    [0xd6b8ed23] = 'g_config.gear_cfg.pack_height_up_0',
    [0x05653bc8] = 'g_config.gear_cfg.pack_height_down_0',
    [0x5d45e217] = 'g_config.gear_cfg.auto_control_enable_0',
    [0x60393030] = 'g_config.esc_cfg.communicate_check_0',
    [0x97be0658] = 'g_config.mvo_cfg.mvo_func_en_0',
    [0xe79ce1ec] = 'g_config.serial_api_cfg.advance_function_enable_0',
    [0xf644897d] = 'g_config.serial_api_cfg.input_pitch_limit_0',
    [0xabd7594c] = 'g_config.serial_api_cfg.input_roll_limit_0',
    [0xd09ebbe4] = 'g_config.serial_api_cfg.input_yaw_rate_limit_0',
    [0x4a9c9a1a] = 'g_config.serial_api_cfg.input_vertical_velocity_limit_0',
    [0x80b4731b] = 'g_config.api_entry_cfg.channel_0',
    [0x8511d8d1] = 'g_config.api_entry_cfg.comp_sign_0',
    [0x02261c5a] = 'g_config.api_entry_cfg.value_sign_0',
    [0x7da9bac9] = 'g_config.api_entry_cfg.enable_mode_0',
    [0x3e483a76] = 'g_config.api_entry_cfg.abs_value_0',
    [0x55ee7671] = 'g_config.api_entry_cfg.baud_rate_0',
    [0x8682a34d] = 'g_config.api_entry_cfg.enable_api_0',
    [0xc325cbaa] = 'g_config.api_entry_cfg.enable_time_stamp_0',
    [0x41ef63e8] = 'g_config.api_entry_cfg.acc_data_type_0',
    [0x800f815c] = 'g_config.api_entry_cfg.gyro_data_type_0',
    [0x8bb7785f] = 'g_config.api_entry_cfg.alti_data_type_0',
    [0x96a0a2cf] = 'g_config.api_entry_cfg.height_data_type_0',
    [0x9266280c] = 'g_config.api_entry_cfg.std_msg_frq[0]_0',
    [0x9366280c] = 'g_config.api_entry_cfg.std_msg_frq[1]_0',
    [0x9466280c] = 'g_config.api_entry_cfg.std_msg_frq[2]_0',
    [0x9566280c] = 'g_config.api_entry_cfg.std_msg_frq[3]_0',
    [0x9666280c] = 'g_config.api_entry_cfg.std_msg_frq[4]_0',
    [0x9766280c] = 'g_config.api_entry_cfg.std_msg_frq[5]_0',
    [0x9866280c] = 'g_config.api_entry_cfg.std_msg_frq[6]_0',
    [0x9966280c] = 'g_config.api_entry_cfg.std_msg_frq[7]_0',
    [0x9a66280c] = 'g_config.api_entry_cfg.std_msg_frq[8]_0',
    [0x9b66280c] = 'g_config.api_entry_cfg.std_msg_frq[9]_0',
    [0x39263e0f] = 'g_config.api_entry_cfg.std_msg_frq[10]_0',
    [0x3a263e0f] = 'g_config.api_entry_cfg.std_msg_frq[11]_0',
    [0x3b263e0f] = 'g_config.api_entry_cfg.std_msg_frq[12]_0',
    [0x3c263e0f] = 'g_config.api_entry_cfg.std_msg_frq[13]_0',
    [0x3d263e0f] = 'g_config.api_entry_cfg.std_msg_frq[14]_0',
    [0x3e263e0f] = 'g_config.api_entry_cfg.std_msg_frq[15]_0',
    [0x7b24ba4b] = 'g_config.api_entry_cfg.authority_level_0',
    [0x9987e879] = 'g_config.api_entry_cfg.cheat_backdoor_0',
    [0xfe3c446d] = 'g_config.api_entry_cfg.api_authority_group[0]_0',
    [0xff3c446d] = 'g_config.api_entry_cfg.api_authority_group[1]_0',
    [0x003c4472] = 'g_config.api_entry_cfg.api_authority_group[2]_0',
    [0x013c4472] = 'g_config.api_entry_cfg.api_authority_group[3]_0',
    [0x3b46ca92] = 'g_config.airport_limit_cfg.cfg_search_radius_0',
    [0x8fb32a2d] = 'g_config.airport_limit_cfg.cfg_disable_airport_fly_limit_0',
    [0x5a552edf] = 'g_config.airport_limit_cfg.cfg_debug_airport_enable_0',
    [0xb04ab3bb] = 'g_config.airport_limit_cfg.cfg_limit_data_0',
    [0x3454b6b5] = 'g_config.airport_limit_cfg.cfg_sim_disable_limit_0',
    [0x5eedfa54] = 'g_config.airport_limit_cfg.cfg_enable[FLY_LIMIT_TYPE_AIRPORT]_0',
    [0x15ae9eae] = 'g_config.airport_limit_cfg.cfg_enable[FLY_LIMIT_TYPE_SPECIAL]_0',
    [0xc2fc569a] = 'g_config.airport_limit_cfg.cfg_r1[FLY_LIMIT_TYPE_AIRPORT]_0',
    [0x79bcfaf4] = 'g_config.airport_limit_cfg.cfg_r1[FLY_LIMIT_TYPE_SPECIAL]_0',
    [0x68fc4ab0] = 'g_config.airport_limit_cfg.cfg_h1[FLY_LIMIT_TYPE_AIRPORT]_0',
    [0x1fbcef0a] = 'g_config.airport_limit_cfg.cfg_h1[FLY_LIMIT_TYPE_SPECIAL]_0',
    [0xc7e8efa5] = 'g_config.airport_limit_cfg.cfg_angle[FLY_LIMIT_TYPE_AIRPORT]_0',
    [0x7ea993ff] = 'g_config.airport_limit_cfg.cfg_angle[FLY_LIMIT_TYPE_SPECIAL]_0',
    [0x60fd01df] = 'g_config.avoid_obstacle_limit_cfg.avoid_obstacle_enable_0',
    [0x74bfebe1] = 'g_config.avoid_obstacle_limit_cfg.a_dec_max_0',
    [0xd0d1ec13] = 'g_config.avoid_obstacle_limit_cfg.v_fwd_max_0',
    [0x6cf4ebaf] = 'g_config.avoid_obstacle_limit_cfg.v_bck_max_0',
    [0x3bc09f07] = 'g_config.avoid_obstacle_limit_cfg.gain_dv2acc_0',
    [0xc3885504] = 'g_config.avoid_obstacle_limit_cfg.safe_dis_0',
    [0x73eab199] = 'g_config.avoid_obstacle_limit_cfg.damping_dis_0',
    [0x55d30cfc] = 'g_config.misc_cfg.imu_temp_ctrl_slope_0',
    [0xedce59a2] = 'g_config.misc_cfg.forearm_lamp_ctrl_0',
    [0x7813de1c] = 'g_config.misc_cfg.auto_takeoff_height_0',
    [0x249a7c63] = 'g_config.misc_cfg.auto_landing_vel_L1_0',
    [0x249b7c63] = 'g_config.misc_cfg.auto_landing_vel_L2_0',
    [0x78eac90c] = 'g_config.hotpoint_cfg.battery_low_go_home_enable_0',
    [0x25c9b281] = 'g_config.hotpoint_cfg.enable_mode_0',
    [0x5d5ca5b8] = 'g_config.hotpoint_cfg.free_yaw_0',
    [0xc3d57cfd] = 'g_config.hotpoint_cfg.auto_recover_0',
    [0x2652c2fb] = 'g_config.hotpoint_cfg.limit_height_0',
    [0x290f6811] = 'g_config.hotpoint_cfg.yaw_change_range_0',
    [0x8f2ce62c] = 'g_config.hotpoint_cfg.max_yaw_rate_0',
    [0x639d9233] = 'g_config.hotpoint_cfg.max_angle_rate_0',
    [0xa457e66b] = 'g_config.hotpoint_cfg.max_tangent_vel_0',
    [0xc8a52125] = 'g_config.hotpoint_cfg.min_radius_0',
    [0xc7de1b25] = 'g_config.hotpoint_cfg.max_radius_0',
    [0x679c3cf9] = 'g_config.hotpoint_cfg.max_vert_vel_0',
    [0x4cc2e85b] = 'g_config.hotpoint_cfg.max_radius_vel_0',
    [0x89ba3a1b] = 'g_config.hotpoint_cfg.min_height_0',
    [0x7dbe272b] = 'g_config.hotpoint_cfg.max_acc_0',
    [0x6a938535] = 'g_config.hotpoint_cfg.max_distance_0',
    [0xab36c6f5] = 'g_config.hotpoint_cfg.pos_gain_0',
    [0x88375bfb] = 'g_config.hotpoint_cfg.vel_gain_0',
    [0x86ec719e] = 'g_config.hotpoint_cfg.centripetal_gain_0',
    [0x37c42b2e] = 'g_config.hotpoint_cfg.cmd_slope_0',
    [0xb13a6a0c] = 'g_config.hotpoint_cfg.output_slope_0',
    [0xaa95c15e] = 'g_config.home_lock_cfg.max_horiz_vel_0',
    [0x3ae9db81] = 'g_config.home_lock_cfg.min_fence_0',
    [0x85ad69b4] = 'g_config.home_lock_cfg.max_angle_rate_0',
    [0xb42f6815] = 'g_config.home_lock_cfg.max_tangent_vel_0',
    [0x6ed2bfdc] = 'g_config.home_lock_cfg.max_radius_vel_0',
    [0x7c536f10] = 'g_config.home_lock_cfg.fence_buffer_0',
    [0xb6dd496e] = 'g_config.followme_cfg.enable_mode_0',
    [0xd76c6cd2] = 'g_config.followme_cfg.auto_recover_0',
    [0x9236d151] = 'g_config.followme_cfg.enable_change_homepoint_0',
    [0x1b924425] = 'g_config.followme_cfg.auto_gimbal_pitch_0',
    [0x52f2b315] = 'g_config.followme_cfg.enter_gps_level_0',
    [0xd478b274] = 'g_config.followme_cfg.horiz_vel_limit_0',
    [0x861949f4] = 'g_config.followme_cfg.min_init_height_0',
    [0xf0275086] = 'g_config.followme_cfg.min_us_limit_height_0',
    [0xc9f98b88] = 'g_config.followme_cfg.min_press_limit_height_0',
    [0xfaf5edda] = 'g_config.followme_cfg.p_horiz_vel_ctrl_0',
    [0x19c60181] = 'g_config.followme_cfg.slop_horiz_vel_0',
    [0x69983853] = 'g_config.followme_cfg.max_drone_to_drone_dist_0',
    [0x2a9eca5c] = 'g_config.followme_cfg.max_phone_to_phone_dist_0',
    [0xd3ed109f] = 'g_config.followme_cfg.set_circle_0',
    [0xbe269781] = 'g_config.followme_cfg.min_limit_radius_0',
    [0xa0268412] = 'g_config.followme_cfg.max_limit_radius_0',
    [0xce187431] = 'g_config.followme_cfg.cmd_yaw_factor_0',
    [0x43326f8e] = 'g_config.followme_cfg.follow_me_wait_0',
    [0x4ef6fd0f] = 'g_config.followme_cfg.follow_me_with_rc_cmd_0',
    [0x4862b6b9] = 'g_config.followme_cfg.test_yaw_mode_0',
    [0x42d36fc1] = 'g_config.followme_cfg.estimate_vel_filter_fc_0',
    [0x3fea552c] = 'g_config.followme_cfg.estimate_pos_filter_fc_0',
    [0xca79f23d] = 'g_config.followme_cfg.brakes_pos_filter_fc_0',
    [0x49994564] = 'g_config.followme_cfg.vel_front_feed_para_0',
    [0x3259e434] = 'g_config.waypoint_cfg.enable_mode_0',
    [0xf7cdf035] = 'g_config.waypoint_cfg.max_vert_vel_0',
    [0x8f26f058] = 'g_config.waypoint_cfg.max_horiz_vel_0',
    [0x29dee7de] = 'g_config.waypoint_cfg.max_auto_yaw_rate_0',
    [0xe178f630] = 'g_config.waypoint_cfg.max_line_acc_0',
    [0xcd3885ef] = 'g_config.waypoint_cfg.max_curve_acc_0',
    [0xaca9d874] = 'g_config.fdi.min_compass_mod_value_0',
    [0xac48aa86] = 'g_config.fdi.max_compass_mod_value_0',
    [0x974a7e91] = 'g_config.fdi.min_compass_mod_stdvar_0',
    [0x361c9091] = 'g_config.fdi.max_compass_mod_stdvar_0',
    [0x0eea9bff] = 'g_config.fdi.max_compass_mod_over_count_0',
    [0x38dee89b] = 'g_config.fdi.max_acc_compass_angle_over_count_0',
    [0x9d559c75] = 'g_config.fdi.max_acc_mod_deviate_for_detect_0',
    [0xacc07101] = 'g_config.fdi.max_acc_mod_deviate_for_calibration_0',
    [0xd1996aec] = 'g_config.fdi.max_acc_compass_angle_deviate_0',
    [0xb41780a7] = 'g_config.fdi.min_acc_compass_angle_time_0',
    [0x40056ccd] = 'g_config.fdi.max_mag_stdvar_for_angle_detection_0',
    [0xd21e6aeb] = 'g_config.fdi.gps_intergrate_predict_time_0',
    [0x8e6aefb4] = 'g_config.fdi.gps_max_pos_predict_error_0',
    [0x9cf8749d] = 'g_config.fdi.gps_max_vel_predict_error_0',
    [0xf9409015] = 'g_config.fdi.gps_max_horizontal_vel_mod_0',
    [0x6b4f8819] = 'g_config.fdi.gps_min_horizontal_vel_stdvar_0',
    [0x42971bef] = 'g_config.fdi.gps_max_horizontal_vel_diff_0',
    [0x0f6bf56e] = 'g_config.fdi.gps_max_horizontal_vel_over_count_0',
    [0x2b638f84] = 'g_config.fdi.gps_max_horizontal_pos_mod_0',
    [0xd64a3714] = 'g_config.fdi.gps_min_horizontal_pos_stdvar_0',
    [0x659686e9] = 'g_config.fdi.gps_max_horizontal_pos_diff_0',
    [0x2651605f] = 'g_config.fdi.gps_max_horizontal_pos_over_count_0',
    [0x1350cfaf] = 'g_config.fdi.max_gyro_mod_value_0',
    [0xadd7b6f3] = 'g_config.fdi.min_gyro_mod_stdvar_0',
    [0x3e41b694] = 'g_config.fdi.max_gyro_mod_stdvar_0',
    [0xad03f0c5] = 'g_config.fdi.max_gyro_mod_diff_0',
    [0x37a45a0e] = 'g_config.fdi.max_gyro_mod_over_count_0',
    [0x11eebcff] = 'g_config.fdi.min_acc_mod_value_0',
    [0x11db4d69] = 'g_config.fdi.max_acc_mod_value_0',
    [0xdc2f068a] = 'g_config.fdi.min_acc_mod_stdvar_0',
    [0xc8bf708a] = 'g_config.fdi.max_acc_mod_stdvar_0',
    [0x9f027b43] = 'g_config.fdi.max_acc_mod_diff_0',
    [0xec18fbe6] = 'g_config.fdi.max_acc_mod_over_count_0',
    [0x87091f9a] = 'g_config.fdi.min_baro_value_0',
    [0x8326019a] = 'g_config.fdi.max_baro_value_0',
    [0xf691a3d3] = 'g_config.fdi.min_baro_stdvar_0',
    [0xdc73c5f6] = 'g_config.fdi.max_baro_diff_0',
    [0x619dfbf9] = 'g_config.fdi.max_baro_over_count_0',
    [0xaf7a5241] = 'g_config.fdi.history_tick_k_0',
    [0xa6d56a37] = 'g_config.fdi.pwm_delay_tick_0',
    [0x069ac154] = 'g_config.fdi.max_horizontal_vel_fusion_error_0',
    [0x495356c8] = 'g_config.fdi.max_ctrl_frequency_power_0',
    [0xa3d90924] = 'g_config.fdi.min_ctrl_frequency_interesting_0',
    [0x73a901f4] = 'g_config.fdi.max_ahrs_init_gyro_bias_0',
    [0xa1350bcb] = 'g_config.fdi.max_ahrs_init_acc_bias_0',
    [0xf4d27cd0] = 'g_config.fdi.max_ahrs_init_magn_x_noise_0',
    [0x957e3d65] = 'g_config.fdi.max_ahrs_init_magn_yz_noise_0',
    [0x72414223] = 'g_config.fdi.max_ahrs_init_trans_acc_0',
    [0x754332bf] = 'g_config.fdi.max_ahrs_init_wz_integral_0',
    [0x0c3b3b4d] = 'g_config.fdi.max_ahrs_init_wxy_integral_0',
    [0x4c4ccb3a] = 'g_config.fdi.max_static_acc_stdvar_0',
    [0x5ea6a219] = 'g_config.fdi.max_static_gyro_stdvar_0',
    [0xac683df4] = 'g_config.fdi_open.compass_fdi_open_0',
    [0x06341ff8] = 'g_config.fdi_open.gps_fdi_open_0',
    [0xec34b890] = 'g_config.fdi_open.gyro_fdi_open_0',
    [0x76312b95] = 'g_config.fdi_open.acc_fdi_open_0',
    [0xe9b80090] = 'g_config.fdi_open.baro_fdi_open_0',
    [0x20e7ea9f] = 'g_config.fdi_open.motor_fdi_open_0',
    [0xe2fb9c75] = 'g_config.fdi_open.motor_kf_fdi_open_0',
    [0x17b04351] = 'g_config.fdi_open.motor_rls_fdi_open_0',
    [0x87a9edb2] = 'g_config.fdi_open.motor_esc_fdi_open_0',
    [0x160494ea] = 'g_config.fdi_open.motor_ctrl_fdi_open_0',
    [0x4d3e6b95] = 'g_config.fdi_open.ahrs_fdi_open_0',
    [0x7506fff3] = 'g_config.fdi_open.ahrs_bias_fdi_open_0',
    [0x4662b8b4] = 'g_config.fdi_open.ahrs_vel_fdi_open_0',
    [0x917474db] = 'g_config.fdi_open.ahrs_init_fdi_open_0',
    [0x6c079662] = 'g_config.fdi_open.ahrs_motor_fdi_open_0',
    [0x9f3e4790] = 'g_config.fdi_open.ctrl_fdi_open_0',
    [0x2fadd570] = 'g_config.fdi_open.ctrl_impact_fdi_open_0',
    [0x9e5185f3] = 'g_config.fdi_open.ctrl_vibrate_fdi_open_0',
    [0x19c6eb09] = 'g_config.fdi_inject.imu_0',
    [0xfe2e4bbc] = 'g_config.fdi_inject.compass_0',
    [0x25789feb] = 'g_raw.input.channel[ 0]_0',
    [0x26789feb] = 'g_raw.input.channel[ 1]_0',
    [0x27789feb] = 'g_raw.input.channel[ 2]_0',
    [0x28789feb] = 'g_raw.input.channel[ 3]_0',
    [0x29789feb] = 'g_raw.input.channel[ 4]_0',
    [0x2a789feb] = 'g_raw.input.channel[ 5]_0',
    [0x2b789feb] = 'g_raw.input.channel[ 6]_0',
    [0x2c789feb] = 'g_raw.input.channel[ 7]_0',
    [0x2d789feb] = 'g_raw.input.channel[ 8]_0',
    [0x2e789feb] = 'g_raw.input.channel[ 9]_0',
    [0x2578a040] = 'g_raw.input.channel[10]_0',
    [0x2678a040] = 'g_raw.input.channel[11]_0',
    [0x2778a040] = 'g_raw.input.channel[12]_0',
    [0x2878a040] = 'g_raw.input.channel[13]_0',
    [0x2978a040] = 'g_raw.input.channel[14]_0',
    [0x2a78a040] = 'g_raw.input.channel[15]_0',
    [0x8f8bcb1c] = 'g_real.input.channel[COMMAND_AILERON]_0',
    [0xd5d8b151] = 'g_real.input.channel[COMMAND_ELEVATOR]_0',
    [0xa7ae4e87] = 'g_real.input.channel[COMMAND_THROTTLE]_0',
    [0x3b768a04] = 'g_real.input.channel[COMMAND_RUDDER]_0',
    [0x3cc32a48] = 'g_real.input.channel[COMMAND_MODE]_0',
    [0x3754b0fa] = 'g_real.input.channel[COMMAND_IOC]_0',
    [0xe59b52a8] = 'g_real.input.channel[COMMAND_GO_HOME]_0',
    [0x083f965a] = 'g_real.input.channel[COMMAND_AUTO_TAKE_OFF]_0',
    [0x817e06c6] = 'g_real.input.channel[COMMAND_KNOB_X1]_0',
    [0x827e06c6] = 'g_real.input.channel[COMMAND_KNOB_X2]_0',
    [0x837e06c6] = 'g_real.input.channel[COMMAND_KNOB_X3]_0',
    [0x847e06c6] = 'g_real.input.channel[COMMAND_KNOB_X4]_0',
    [0x857e06c6] = 'g_real.input.channel[COMMAND_KNOB_X5]_0',
    [0x867e06c6] = 'g_real.input.channel[COMMAND_KNOB_X6]_0',
    [0x6344a0c9] = 'g_real.input.channel[COMMAND_PANTILT_PITCH]_0',
    [0x8e826447] = 'g_real.input.channel[COMMAND_PANTILT_ROLL]_0',
    [0x769fa6ed] = 'g_real.input.channel[COMMAND_PANTILT_YAW]_0',
    [0x6f21dccb] = 'g_real.input.channel[COMMAND_H3_2D_TILT]_0',
    [0xa4515665] = 'g_real.input.channel[COMMAND_D1]_0',
    [0xa5515665] = 'g_real.input.channel[COMMAND_D2]_0',
    [0xa6515665] = 'g_real.input.channel[COMMAND_D3]_0',
    [0xa7515665] = 'g_real.input.channel[COMMAND_D4]_0',
    [0x49a4f839] = 'g_real.input.channel[COMMAND_GEAR]_0',
    [0x8998d47a] = 'g_real.imu.ax_0',
    [0x8999d47a] = 'g_real.imu.ay_0',
    [0x899ad47a] = 'g_real.imu.az_0',
    [0x9f98d47a] = 'g_real.imu.wx_0',
    [0x9f99d47a] = 'g_real.imu.wy_0',
    [0x9f9ad47a] = 'g_real.imu.wz_0',
    [0x9598d47a] = 'g_real.imu.mx_0',
    [0x9599d47a] = 'g_real.imu.my_0',
    [0x959ad47a] = 'g_real.imu.mz_0',
    [0x9950d47a] = 'g_real.imu.q0_0',
    [0x9951d47a] = 'g_real.imu.q1_0',
    [0x9952d47a] = 'g_real.imu.q2_0',
    [0x9953d47a] = 'g_real.imu.q3_0',
    [0x7e18ef84] = 'g_raw.gps_snr.snr[0]_0',
    [0x7f18ef84] = 'g_raw.gps_snr.snr[1]_0',
    [0x8018ef84] = 'g_raw.gps_snr.snr[2]_0',
    [0x8118ef84] = 'g_raw.gps_snr.snr[3]_0',
    [0x8218ef84] = 'g_raw.gps_snr.snr[4]_0',
    [0x8318ef84] = 'g_raw.gps_snr.snr[5]_0',
    [0x8418ef84] = 'g_raw.gps_snr.snr[6]_0',
    [0x8518ef84] = 'g_raw.gps_snr.snr[7]_0',
    [0x8618ef84] = 'g_raw.gps_snr.snr[8]_0',
    [0x8718ef84] = 'g_raw.gps_snr.snr[9]_0',
    [0xebedb5a6] = 'g_raw.gps_snr.snr[10]_0',
    [0xecedb5a6] = 'g_raw.gps_snr.snr[11]_0',
    [0xededb5a6] = 'g_raw.gps_snr.snr[12]_0',
    [0xeeedb5a6] = 'g_raw.gps_snr.snr[13]_0',
    [0xefedb5a6] = 'g_raw.gps_snr.snr[14]_0',
    [0xf0edb5a6] = 'g_raw.gps_snr.snr[15]_0',
    [0xf1edb5a6] = 'g_raw.gps_snr.snr[16]_0',
    [0xf2edb5a6] = 'g_raw.gps_snr.snr[17]_0',
    [0xf3edb5a6] = 'g_raw.gps_snr.snr[18]_0',
    [0xf4edb5a6] = 'g_raw.gps_snr.snr[19]_0',
    [0xebedb5ab] = 'g_raw.gps_snr.snr[20]_0',
    [0xecedb5ab] = 'g_raw.gps_snr.snr[21]_0',
    [0xededb5ab] = 'g_raw.gps_snr.snr[22]_0',
    [0xeeedb5ab] = 'g_raw.gps_snr.snr[23]_0',
    [0xefedb5ab] = 'g_raw.gps_snr.snr[24]_0',
    [0xf0edb5ab] = 'g_raw.gps_snr.snr[25]_0',
    [0xf1edb5ab] = 'g_raw.gps_snr.snr[26]_0',
    [0xf2edb5ab] = 'g_raw.gps_snr.snr[27]_0',
    [0xf3edb5ab] = 'g_raw.gps_snr.snr[28]_0',
    [0xf4edb5ab] = 'g_raw.gps_snr.snr[29]_0',
    [0xebedb5b0] = 'g_raw.gps_snr.snr[30]_0',
    [0xecedb5b0] = 'g_raw.gps_snr.snr[31]_0',
    [0xededb5b0] = 'g_raw.gps_snr.snr[32]_0',
    [0xeeedb5b0] = 'g_raw.gps_snr.snr[33]_0',
    [0xefedb5b0] = 'g_raw.gps_snr.snr[34]_0',
    [0xf0edb5b0] = 'g_raw.gps_snr.snr[35]_0',
    [0xf1edb5b0] = 'g_raw.gps_snr.snr[36]_0',
    [0xf2edb5b0] = 'g_raw.gps_snr.snr[37]_0',
    [0xf3edb5b0] = 'g_raw.gps_snr.snr[38]_0',
    [0xf4edb5b0] = 'g_raw.gps_snr.snr[39]_0',
    [0xebedb5b5] = 'g_raw.gps_snr.snr[40]_0',
    [0xecedb5b5] = 'g_raw.gps_snr.snr[41]_0',
    [0xededb5b5] = 'g_raw.gps_snr.snr[42]_0',
    [0xeeedb5b5] = 'g_raw.gps_snr.snr[43]_0',
    [0xefedb5b5] = 'g_raw.gps_snr.snr[44]_0',
    [0xf0edb5b5] = 'g_raw.gps_snr.snr[45]_0',
    [0xf1edb5b5] = 'g_raw.gps_snr.snr[46]_0',
    [0xf2edb5b5] = 'g_raw.gps_snr.snr[47]_0',
    [0xf3edb5b5] = 'g_raw.gps_snr.snr[48]_0',
    [0xf4edb5b5] = 'g_raw.gps_snr.snr[49]_0',
    [0xebedb5ba] = 'g_raw.gps_snr.snr[50]_0',
    [0xecedb5ba] = 'g_raw.gps_snr.snr[51]_0',
    [0xededb5ba] = 'g_raw.gps_snr.snr[52]_0',
    [0xeeedb5ba] = 'g_raw.gps_snr.snr[53]_0',
    [0xefedb5ba] = 'g_raw.gps_snr.snr[54]_0',
    [0xf0edb5ba] = 'g_raw.gps_snr.snr[55]_0',
    [0xf1edb5ba] = 'g_raw.gps_snr.snr[56]_0',
    [0xf2edb5ba] = 'g_raw.gps_snr.snr[57]_0',
    [0xf3edb5ba] = 'g_raw.gps_snr.snr[58]_0',
    [0xf4edb5ba] = 'g_raw.gps_snr.snr[59]_0',
    [0xebedb5bf] = 'g_raw.gps_snr.snr[60]_0',
    [0xecedb5bf] = 'g_raw.gps_snr.snr[61]_0',
    [0xededb5bf] = 'g_raw.gps_snr.snr[62]_0',
    [0xeeedb5bf] = 'g_raw.gps_snr.snr[63]_0',
    [0x1c071f19] = 'AttiData_200Hz.press_0',
    [0x201d2a3b] = 'g_raw.battery_info.design_capacity_0',
    [0x9159c556] = 'g_raw.battery_info.full_charge_capacity_0',
    [0x5f07e38d] = 'g_raw.battery_info.remaining_capacity_0',
    [0x80c2365c] = 'g_raw.battery_info.pack_voltage_0',
    [0x8821f3f2] = 'g_raw.battery_info.current_0',
    [0xfc8711ea] = 'g_raw.battery_info.life_percentage_0',
    [0x8b0b3187] = 'g_raw.battery_info.capacity_percentage_0',
    [0x9e336395] = 'g_raw.battery_info.temperature_0',
    [0x2e51de52] = 'g_raw.battery_info.cycle_count_0',
    [0x9bf8c95a] = 'g_raw.battery_info.serial_number_0',
    [0x57468777] = 'g_raw.battery_info.cell_voltage[0]_0',
    [0x58468777] = 'g_raw.battery_info.cell_voltage[1]_0',
    [0x59468777] = 'g_raw.battery_info.cell_voltage[2]_0',
    [0x5a468777] = 'g_raw.battery_info.cell_voltage[3]_0',
    [0x5b468777] = 'g_raw.battery_info.cell_voltage[4]_0',
    [0x5c468777] = 'g_raw.battery_info.cell_voltage[5]_0',
    [0xcb316c3b] = 'g_raw.battery_info.average_current_0',
    [0xadb43ca3] = 'g_raw.battery_info.right_0',
    [0x80c92b8c] = 'g_raw.battery_info.error_count_0',
    [0x0a8fc2af] = 'g_raw.battery_info.n_discharge_times_0',
    [0x875d3035] = 'g_real.status.main_battery_voltage_0',
    [0xe593b02e] = 'g_real.config_status.voltage_temp_for_calibrate_0',
    [0x3db22c00] = 'g_real.config_status.voltage_calibrate_state_0',
    [0xcbbf0f97] = 'IMU_Data.gyro_tempX_0',
    [0xcbc00f97] = 'IMU_Data.gyro_tempY_0',
    [0xcbc10f97] = 'IMU_Data.gyro_tempZ_0',
    [0x14468f84] = 'imu_temp.dst_value_0',
    [0x6bf1a5d0] = 'imu_temp.ctl_out_value_0',
    [0x73f19d57] = 'imu_temp.real_ctl_out_value_0',
    [0xdd415d9a] = 'imu_temp.real_ctl_out_per_0',
    [0x6702128d] = 'g_real.status.control_command_mode_0',
    [0x8721693b] = 'g_real.status.control_real_mode_0',
    [0xe163241e] = 'g_real.status.last_control_real_mode_0',
    [0x1e029e37] = 'g_real.status.rc_state_0',
    [0x1364e450] = 'g_real.status.motor_status_0',
    [0xf3eace45] = 'g_real.config_status.need_check_stick_channel_mapping_0',
    [0xec170d5f] = 'g_real.config_status.need_send_imu_start_flag_0',
    [0xac1efd58] = 'g_real.config_status.stick_calibrate_state_0',
    [0x3b7da88e] = 'g_real.config_status.config_debug_0',
    [0xbb4cf13c] = 'imu_type_0',
    [0xce6d445d] = 'g_real.force_on.ignore_compass_error_0',
    [0x10782937] = 'g_navi_data.horiz_vel_sensor_id_0',
    [0x0ad46d4c] = 'g_real.knob.scales[KNOB_BASIC_ROLL]_0',
    [0xb54da335] = 'g_real.knob.scales[KNOB_BASIC_PITCH]_0',
    [0x771bf8f6] = 'g_real.knob.scales[KNOB_BASIC_YAW]_0',
    [0x3f97c254] = 'g_real.knob.scales[KNOB_BASIC_THRUST]_0',
    [0xe27e9a1e] = 'g_real.knob.scales[KNOB_ATTI_GAIN]_0',
    [0x78fb68b9] = 'g_real.knob.scales[KNOB_GYRO_GAIN]_0',
    [0xc46223b9] = 'imu_app_temp_cali.start_flag_0',
    [0x43d19856] = 'imu_app_temp_cali.state_0',
    [0xcc8ec761] = 'imu_app_temp_cali.cali_cnt_0',
    [0x765d4a50] = 'imu_app_temp_cali.temp_ready_0',
    [0x723fcb67] = 'imu_app_temp_cali.step_0',
    [0x074049d5] = 'imu_app_temp_cali.dst_cali_temp_0',
    [0x7139b60b] = 'imu_app_temp_cali.bias_flag.temp_min_0',
    [0x6943b60b] = 'imu_app_temp_cali.bias_flag.temp_max_0',
    [0xfd2b0778] = 'imu_app_temp_cali.bias_flag.temp_cali_status_0',
    [0xe5a00bc3] = 'imu_app_temp_cali.bias_flag.base_cali_status_0',
    [0x2477f435] = 'imu_app_temp_cali.bias_flag.cfg_temp_cali_fw_version_0',
    [0x6b7b8a5a] = 'imu_app_temp_cali.bias_flag.cur_temp_cali_fw_version_0',
    [0xb765ced5] = 'imu_temp.cur_dst_temp_0',
    [0x44adfb9a] = 'imu_check_status.check_flag_0',
    [0xbaf79df9] = 'imu_check_status.status_0',
    [0xd1339a5c] = 'g_real.config_status.motor_test_output_bit_0',
    [0xa0fc750c] = 'g_real.config_status.motor_test_output_timer_0',
    [0x93cdfcff] = 'g_real.config_status.motor_test_request_bit_0',
    [0x039e4213] = 'g_real.config_status.motor_test_request_timer_0',
    [0xc9a5ad5e] = 'g_real.config_status.factory_output_test_request_0',
    [0x2ca6d420] = 'g_real.config_status.fill_from_simulator_0',
    [0xa7d83fdb] = 'g_real.config_status.simulator_gps_svn_0',
    [0x705d2ccb] = 'local_simulator_0',
    [0x8c4dafd2] = 'run_mode_0',
    [0xc30b18f9] = 'default_gps_svn_0',
    [0xded84280] = 'initial_lati_0',
    [0x58039b5e] = 'initial_longti_0',
    [0x7f393ec9] = 'g_cfg_debug.simulator_initial_lati_0',
    [0x544abd43] = 'g_cfg_debug.simulator_initial_longti_0',
    [0x7b2f4251] = 'g_cfg_debug.simulator_mvo_flag_0',
    [0x9d37b593] = 'g_cfg_debug.simulator_gps_hdop_0',
    [0xf31cd374] = 'g_cfg_debug.simulator_check_motor_0',
    [0x32f915d9] = 'wind_speed[0]_0',
    [0x33f915d9] = 'wind_speed[1]_0',
    [0x34f915d9] = 'wind_speed[2]_0',
    [0xe6d4d9ab] = 'wall_dis_front_0',
    [0xe110ac83] = 'wall_dis_right_0',
    [0x73e3ab53] = 'wall_dis_back_0',
    [0x76ecdd67] = 'wall_dis_left_0',
    [0xda45471c] = 'test_deformation_0',
    [0x821bb377] = 'g_cfg_debug.force_flash_led_0',
    [0xd149173b] = 'g_real.wm610_app_command.function_command_state_0',
    [0x23494583] = 'g_real.wm610_app_command.function_command_0',
    [0xd174d68f] = 'g_debug.sim_flag[0]_0',
    [0xd274d68f] = 'g_debug.sim_flag[1]_0',
    [0xd374d68f] = 'g_debug.sim_flag[2]_0',
    [0xd474d68f] = 'g_debug.sim_flag[3]_0',
    [0x38c7cb6b] = 'g_debug.sim_var[0]_0',
    [0x39c7cb6b] = 'g_debug.sim_var[1]_0',
    [0x3ac7cb6b] = 'g_debug.sim_var[2]_0',
    [0x3bc7cb6b] = 'g_debug.sim_var[3]_0',
    [0x4cf19f15] = 'ioc_type__0',
    [0x5a4ed0a2] = 'wp_setting.length_0',
    [0xc2ac7538] = 'wp_setting.vel_cmd_range_0',
    [0xccd56ee3] = 'wp_setting.idle_vel_0',
    [0xc8841923] = 'wp_setting.action_on_finish_0',
    [0xc2d65cd5] = 'wp_setting.mission_exec_num_0',
    [0x02b2447a] = 'wp_setting.yaw_mode_0',
    [0xa606743b] = 'wp_setting.trace_mode_0',
    [0x70e36630] = 'wp_setting.action_on_rc_lost_0',
    [0x93770711] = 'range.control.control_mode[0]',
    [0x93770811] = 'range.control.control_mode[1]',
    [0x93770911] = 'range.control.control_mode[2]',
    [0x10989b1d] = 'range.go_home.standby',
    [0x0b5414a8] = 'range.go_home.start',
    [0x68b3d1a8] = 'range.ioc.mode[0]',
    [0x68b3d2a8] = 'range.ioc.mode[1]',
    [0x68b3d3a8] = 'range.ioc.mode[2]',
    [0xd73e5289] = 'g_config.bat_limit.limit_delt_vol.min_0',
    [0xcf485289] = 'g_config.bat_limit.limit_delt_vol.max_0',
    [0xf7947df2] = 'g_config.bat_limit.limit_delt_vol.weight_0',
    [0x8379f3d2] = 'g_config.bat_limit.limit_vol.min_0',
    [0x7b83f3d2] = 'g_config.bat_limit.limit_vol.max_0',
    [0x3ef1a81c] = 'g_config.bat_limit.limit_vol.weight_0',
    [0x10bfe511] = 'g_config.bat_limit.limit_max_power.min_0',
    [0x08c9e511] = 'g_config.bat_limit.limit_max_power.max_0',
    [0x7bb405d1] = 'g_config.bat_limit.limit_max_power.weight_0',
    [0x7b4b95d9] = 'g_config.bat_limit.limit_temp.min_0',
    [0x735595d9] = 'g_config.bat_limit.limit_temp.max_0',
    [0x45c8c046] = 'g_config.bat_limit.limit_temp.weight_0',
    [0x339d9c7f] = 'g_config.bat_limit.limit_scale.min_0',
    [0x2ba79c7f] = 'g_config.bat_limit.limit_scale.max_0',
    [0xea625a64] = 'g_config.bat_limit.limit_scale.weight_0',
    [0x4e4d8780] = 'g_config.bat_limit.limit_power_rate_capacity.min_0',
    [0x46578780] = 'g_config.bat_limit.limit_power_rate_capacity.max_0',
    [0xebe7c9fb] = 'g_config.bat_limit.limit_power_rate_capacity.weight_0',
    [0xe0d3d946] = 'g_config.bat_limit.limit_power_rate_temp.min_0',
    [0xd8ddd946] = 'g_config.bat_limit.limit_power_rate_temp.max_0',
    [0xb4c46995] = 'g_config.bat_limit.limit_power_rate_temp.weight_0',
    [0x06c97ca2] = 'g_config.bat_limit.limit_bat_current_after_overflow_0',
    [0x9331477d] = 'g_config.bat_limit.limit_up_rate_0',
    [0x47021e69] = 'g_config.bat_limit.limit_down_rate_0',
    -- Now old hashes, mapped to new names in Phantom 3
    [0x0ADE273D] = 'g_real.knob.scales[KNOB_BASIC_YAW]_0',
    [0x13F1189B] = 'g_config.control.horiz_i_gain_0',
    [0x36C21143] = 'g_config.control.basic_thrust_0',
    [0x3B304CCD] = 'g_config.knob.control_channel[KNOB_ATTI_GAIN]_0',
    [0x401F69E9] = 'g_config.knob.control_channel[KNOB_BASIC_THRUST]_0',
    [0x96C08863] = 'g_real.knob.scales[KNOB_ATTI_GAIN]_0',
    [0xAF4DEBA2] = 'g_config.knob.control_channel[KNOB_BASIC_YAW]_0',
    [0xC25A4FF2] = 'g_config.knob.control_channel[KNOB_GYRO_GAIN]_0',
    [0xCA7264AD] = 'g_config.control.basic_yaw_0',
    [0xD2E6EE01] = 'g_config.control.vert_i_gain_0',
    [0xD2EDEE01] = 'g_config.control.vert_pos_gain_0',
    [0xD2F3EE01] = 'g_config.control.vert_vel_gain_0',
    [0xD7E93B10] = 'g_real.knob.scales[KNOB_BASIC_THRUST]_0',
    [0xE0B5E02D] = 'g_real.knob.scales[KNOB_GYRO_GAIN]_0',
    [0xE22D1DE2] = 'g_config.control.torsion_gyro_gain_0',
}

f.flyc_config_table_get_param_info_by_hash_name_hash = ProtoField.uint32 ("dji_dumlv1.flyc_config_table_get_param_info_by_hash_name_hash", "Param Name Hash", base.HEX, enums.FLYC_PARAMETER_BY_HASH_ENUM, nil, "Hash of a flight controller parameter name string")

f.flyc_config_table_get_param_info_by_hash_status = ProtoField.uint8 ("dji_dumlv1.flyc_config_table_get_param_info_by_hash_status", "Status", base.DEC, nil, nil)
f.flyc_config_table_get_param_info_by_hash_type_id = ProtoField.uint16 ("dji_dumlv1.flyc_config_table_get_param_info_by_hash_type_id", "TypeID", base.DEC, nil, nil)
f.flyc_config_table_get_param_info_by_hash_size = ProtoField.int16 ("dji_dumlv1.flyc_config_table_get_param_info_by_hash_size", "Size", base.DEC, nil, nil)
f.flyc_config_table_get_param_info_by_hash_attribute = ProtoField.uint16 ("dji_dumlv1.flyc_config_table_get_param_info_by_hash_attribute", "Attribute", base.HEX, nil, nil)
f.flyc_config_table_get_param_info_by_hash_limit_i_min = ProtoField.int32 ("dji_dumlv1.flyc_config_table_get_param_info_by_hash_limit_i_min", "LimitI minValue", base.DEC, nil, nil)
f.flyc_config_table_get_param_info_by_hash_limit_i_max = ProtoField.int32 ("dji_dumlv1.flyc_config_table_get_param_info_by_hash_limit_i_max", "LimitI maxValue", base.DEC, nil, nil)
f.flyc_config_table_get_param_info_by_hash_limit_i_def = ProtoField.int32 ("dji_dumlv1.flyc_config_table_get_param_info_by_hash_limit_i_def", "LimitI defaultValue", base.DEC, nil, nil)
f.flyc_config_table_get_param_info_by_hash_limit_u_min = ProtoField.uint32 ("dji_dumlv1.flyc_config_table_get_param_info_by_hash_limit_u_min", "LimitU minValue", base.DEC, nil, nil)
f.flyc_config_table_get_param_info_by_hash_limit_u_max = ProtoField.uint32 ("dji_dumlv1.flyc_config_table_get_param_info_by_hash_limit_u_max", "LimitU maxValue", base.DEC, nil, nil)
f.flyc_config_table_get_param_info_by_hash_limit_u_def = ProtoField.uint32 ("dji_dumlv1.flyc_config_table_get_param_info_by_hash_limit_u_def", "LimitU defaultValue", base.DEC, nil, nil)
f.flyc_config_table_get_param_info_by_hash_limit_f_min = ProtoField.float ("dji_dumlv1.flyc_config_table_get_param_info_by_hash_limit_f_min", "LimitF minValue", nil, nil)
f.flyc_config_table_get_param_info_by_hash_limit_f_max = ProtoField.float ("dji_dumlv1.flyc_config_table_get_param_info_by_hash_limit_f_max", "LimitF maxValue", nil, nil)
f.flyc_config_table_get_param_info_by_hash_limit_f_def = ProtoField.float ("dji_dumlv1.flyc_config_table_get_param_info_by_hash_limit_f_def", "LimitF defaultValue", nil, nil)
f.flyc_config_table_get_param_info_by_hash_name = ProtoField.stringz ("dji_dumlv1.flyc_config_table_get_param_info_by_hash_name", "Name", base.ASCII, nil, nil)

local function flyc_config_table_get_param_info_by_hash_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request
        subtree:add_le (f.flyc_config_table_get_param_info_by_hash_name_hash, payload(offset, 4))
        offset = offset + 4

        if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table Get Param Info By Hash: Offset does not match - internal inconsistency") end
    else -- Response is identical to getting param info by index
        -- Payload has 19 bytes + null-terminated name on P3X_FW_V01.07.0060
        subtree:add_le (f.flyc_config_table_get_param_info_by_hash_status, payload(offset, 1))
        offset = offset + 1

        -- It is possible that the packet ends here, if there was an issue retrieving the item
        if (payload:len() >= 8) then
            local type_id = payload(offset,2):le_uint()
            subtree:add_le (f.flyc_config_table_get_param_info_by_hash_type_id, payload(offset, 2))
            offset = offset + 2

            subtree:add_le (f.flyc_config_table_get_param_info_by_hash_size, payload(offset, 2))
            offset = offset + 2

            subtree:add_le (f.flyc_config_table_get_param_info_by_hash_attribute, payload(offset, 2))
            offset = offset + 2

            if (type_id <= 3) or (type_id == 10) then
                subtree:add_le (f.flyc_config_table_get_param_info_by_hash_limit_u_min, payload(offset, 4))
                offset = offset + 4

                subtree:add_le (f.flyc_config_table_get_param_info_by_hash_limit_u_max, payload(offset, 4))
                offset = offset + 4

                subtree:add_le (f.flyc_config_table_get_param_info_by_hash_limit_u_def, payload(offset, 4))
                offset = offset + 4
            elseif (type_id >= 4) and (type_id <= 7) then
                subtree:add_le (f.flyc_config_table_get_param_info_by_hash_limit_i_min, payload(offset, 4))
                offset = offset + 4

                subtree:add_le (f.flyc_config_table_get_param_info_by_hash_limit_i_max, payload(offset, 4))
                offset = offset + 4

                subtree:add_le (f.flyc_config_table_get_param_info_by_hash_limit_i_def, payload(offset, 4))
                offset = offset + 4
            elseif (type_id == 8) or (type_id == 9) then
                subtree:add_le (f.flyc_config_table_get_param_info_by_hash_limit_f_min, payload(offset, 4))
                offset = offset + 4

                subtree:add_le (f.flyc_config_table_get_param_info_by_hash_limit_f_max, payload(offset, 4))
                offset = offset + 4

                subtree:add_le (f.flyc_config_table_get_param_info_by_hash_limit_f_def, payload(offset, 4))
                offset = offset + 4
            end

            local name_text = payload(offset, payload:len() - offset)
            subtree:add_le (f.flyc_config_table_get_param_info_by_hash_name, name_text)
            offset = payload:len()
        end

        --if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table Get Param Info By Hash: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Config Table Get Param Info By Hash: Payload size different than expected") end
end

-- Flight Controller - Config Table: Read Param By Hash - 0xf8

f.flyc_config_table_read_param_by_hash_status = ProtoField.uint8 ("dji_dumlv1.flyc_config_table_read_param_by_hash_status", "Status", base.DEC, nil, nil)
f.flyc_config_table_read_param_by_hash_name_hash = ProtoField.uint32 ("dji_dumlv1.flyc_config_table_read_param_by_hash_name_hash", "Param Name Hash", base.HEX, enums.FLYC_PARAMETER_BY_HASH_ENUM, nil, "Hash of a flight controller parameter name string")
f.flyc_config_table_read_param_by_hash_value = ProtoField.bytes ("dji_dumlv1.flyc_config_table_read_param_by_hash_value", "Param Value", base.SPACE, nil, nil, "Flight controller parameter value; size and type depends on parameter")

f.flyc_config_table_read_param_by_hash_rq_num = ProtoField.uint8 ("dji_dumlv1.flyc_config_table_read_param_by_hash_rq_num", "Request Number", base.DEC, nil, nil)

local function flyc_config_table_read_param_by_hash_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request

        local num_entries = math.floor((payload:len() - offset) / 4)

        local i = 0
        while i < num_entries do
            i = i + 1

            subtree:add_le (f.flyc_config_table_read_param_by_hash_rq_num, i) -- Add request number detached, without related byte within packet (it is just index of the value)

            subtree:add_le (f.flyc_config_table_read_param_by_hash_name_hash, payload(offset, 4))
            offset = offset + 4
        end

        if (offset ~= 4 * i) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table Read Param By Hash: Offset does not match - internal inconsistency") end
    else -- Response

        subtree:add_le (f.flyc_config_table_read_param_by_hash_status, payload(offset, 1))
        offset = offset + 1

        -- There can be multiple values in the packet; but without knowing size for each hash, we have no way of knowing where first value ends
        -- This is why everything beyond the first hash is thrown to one value
        if (payload:len() >= offset + 5) then

            subtree:add_le (f.flyc_config_table_read_param_by_hash_name_hash, payload(offset, 4))
            offset = offset + 4

            local varsize_val = payload(offset, payload:len() - offset)
            subtree:add (f.flyc_config_table_read_param_by_hash_value, varsize_val)
            offset = payload:len()
        end

        --if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table Read Param By Hash: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Config Table Read Param By Hash: Payload size different than expected") end
end

-- Flight Controller - Config Table: Write Param By Hash - 0xf9

f.flyc_config_table_write_param_by_hash_status = ProtoField.uint8 ("dji_dumlv1.flyc_config_table_write_param_by_hash_status", "Status", base.DEC, nil, nil)
f.flyc_config_table_write_param_by_hash_name_hash = ProtoField.uint32 ("dji_dumlv1.flyc_config_table_write_param_by_hash_name_hash", "Param Name Hash", base.HEX, enums.FLYC_PARAMETER_BY_HASH_ENUM, nil, "Hash of a flight controller parameter name string")
f.flyc_config_table_write_param_by_hash_value = ProtoField.bytes ("dji_dumlv1.flyc_config_table_write_param_by_hash_value", "Param Value", base.SPACE, nil, nil, "Flight controller parameter value; size and type depends on parameter")

local function flyc_config_table_write_param_by_hash_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request
        subtree:add_le (f.flyc_config_table_write_param_by_hash_name_hash, payload(offset, 4))
        offset = offset + 4

        local varsize_val = payload(offset, payload:len() - offset)
        subtree:add (f.flyc_config_table_write_param_by_hash_value, varsize_val)
        offset = payload:len()

        --if (offset ~= 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table Write Param By Hash: Offset does not match - internal inconsistency") end
    else -- Response
        subtree:add_le (f.flyc_config_table_write_param_by_hash_status, payload(offset, 1))
        offset = offset + 1

        if (payload:len() - offset >= 5) then
            subtree:add_le (f.flyc_config_table_write_param_by_hash_name_hash, payload(offset, 4))
            offset = offset + 4

            local varsize_val = payload(offset, payload:len() - offset)
            subtree:add (f.flyc_config_table_write_param_by_hash_value, varsize_val)
            offset = payload:len()
        end

        --if (offset ~= 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table Write Param By Hash: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Config Table Write Param By Hash: Payload size different than expected") end
end

-- Flight Controller - Config Table: Read Params By Hash - 0xfb

f.flyc_config_table_read_params_by_hash_unknown00 = ProtoField.uint8 ("dji_dumlv1.flyc_config_table_read_params_by_hash_unknown00", "Unknown00", base.HEX)
f.flyc_config_table_read_params_by_hash_first_name_hash = ProtoField.uint32 ("dji_dumlv1.flyc_config_table_read_params_by_hash_first_name_hash", "Param Name Hash", base.HEX, enums.FLYC_PARAMETER_BY_HASH_ENUM, nil, "Hash of a flight controller parameter name string")

local function flyc_config_table_read_params_by_hash_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.flyc_config_table_read_params_by_hash_unknown00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.flyc_config_table_read_params_by_hash_first_name_hash, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Config Table: Read Params By Hash: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Config Table: Read Params By Hash: Payload size different than expected") end
end

FLYC_UART_CMD_DISSECT = {
    [0x09] = flyc_flyc_forbid_status_dissector,
    [0x10] = flyc_a2_commom_dissector,
    [0x32] = flyc_flyc_deform_status_dissector,
    [0x2a] = flyc_function_control_dissector,
    [0x3e] = flyc_flyc_request_limit_update_dissector,
    [0x3f] = flyc_set_nofly_zone_data_dissector,
    [0x42] = flyc_flyc_unlimit_state_dissector,
    [0x43] = flyc_osd_general_dissector,
    [0x44] = flyc_osd_home_point_dissector,
    [0x45] = flyc_flyc_gps_snr_dissector,
    [0x51] = flyc_flyc_battery_status_dissector,
    [0x53] = flyc_flyc_vis_avoid_param_dissector,
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
    [0xdf] = flyc_assistant_unlock_dissector,
    [0xe0] = flyc_config_table_get_tbl_attribute_dissector,
    [0xe1] = flyc_config_table_get_item_attribute_dissector,
    [0xe2] = flyc_config_table_get_item_value_dissector,
    [0xe3] = flyc_config_table_set_item_value_dissector,
    [0xe9] = flyc_config_command_table_get_or_exec_dissector,
    [0xf0] = flyc_config_table_get_param_info_by_index_dissector,
    [0xf1] = flyc_config_table_read_param_by_index_dissector,
    [0xf7] = flyc_config_table_get_param_info_by_hash_dissector,
    [0xf8] = flyc_config_table_read_param_by_hash_dissector,
    [0xf9] = flyc_config_table_write_param_by_hash_dissector,
    [0xfb] = flyc_config_table_read_params_by_hash_dissector,
}
