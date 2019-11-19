-- The definitions in this file are part of DJI DUMLv1 protocol dissector
-- Dissectors for command set 0x00 - General

local f = DJI_DUMLv1_PROTO.fields
local enums = {}

-- CMD name decode table

GENERAL_UART_CMD_TEXT = {
    [0x00] = 'Ping',
    [0x01] = 'Version Inquiry',
    [0x02] = 'Push Param Set',
    [0x03] = 'Push Param Get',
    [0x04] = 'Push Param Start',
    [0x05] = 'Multi Param Set', -- Multiple prarams set at once
    [0x06] = 'Multi Param Get', -- Multiple prarams get at once
    [0x07] = 'Enter Loader', -- Enter Upgrade Mode / Firmware Upgrade Entry
    [0x08] = 'Update Confirm', -- Upgrade Prepare / Firmware Upgrade Procedure Start
    [0x09] = 'Update Transmit', -- Firmware Upgrade Data Transmission
    [0x0a] = 'Update Finish', -- Firmware Upgrade Verify
    [0x0b] = 'Reboot Chip',
    [0x0c] = 'Get Device State', -- get run status(loader, app)
    [0x0d] = 'Set Device Version', -- HardwareId
    [0x0e] = 'Heartbeat/Log Message', -- It can transmit text messages from FC, but is usually empty
    [0x0f] = 'Upgrade Self Request', -- Upgrade Consistency / Check Upgrade Compatibile
    [0x10] = 'Set SDK Std Msgs Frequency',
    [0x20] = 'File List',
    [0x21] = 'File Info',
    [0x22] = 'File Send',
    [0x23] = 'File Receive', -- See m0101 sys partiton for payload info
    [0x24] = 'File Sending',
    [0x25] = 'File Segment Err', -- File Receive Segment Fail
    [0x26] = 'FileTrans App 2 Camera', -- See m0101 sys partiton for payload info
    [0x27] = 'FileTrans Camera 2 App',
    [0x28] = 'FileTrans Delete',
    [0x2a] = 'FileTrans General Trans',
    [0x30] = 'Encrypt Config',
    [0x32] = 'Activate Config', -- Activation Action
    [0x33] = 'MFi Cert',
    [0x34] = 'Safe Communication',
    [0x40] = 'Fw Update Desc Push',
    [0x41] = 'Fw Update Push Control',
    [0x42] = 'Fw Upgrade Push Status',
    [0x43] = 'Fw Upgrade Finish',
    [0x45] = 'Sleep Control',
    [0x46] = 'Shutdown Notification', -- aka Disconnect Notifiation
    [0x47] = 'Power State', -- aka Reboot Status
    [0x48] = 'LED Control',
    [0x4a] = 'Set Date/Time',
    [0x4b] = 'Get Date/Time',
    [0x4c] = 'Get Module Sys Status', -- Get Aging Test Status
    [0x4d] = 'Set RT',
    [0x4e] = 'Get RT',
    [0x4f] = 'Get Cfg File',
    [0x50] = 'Set Serial Number',
    [0x51] = 'Get Serial Number',
    [0x52] = 'Set Gps Push Config',
    [0x53] = 'Push Gps Info',
    [0x54] = 'Get Temperature Info',
    [0x55] = 'Get Alive Time',
    [0x56] = 'Over Temperature', -- Push Temperature Warning
    [0x57] = 'Send Network Info',
    [0x58] = 'Time Sync', -- Get Ack Of Timestamp
    [0x59] = 'Test Mode',
    [0x5a] = 'Play Sound',
    [0x5c] = 'UAV Fly Info',
    [0x60] = 'Auto Test Info',
    [0x61] = 'Set Product Newest Ver',
    [0x62] = 'Get Product Newest Ver',
    [0xef] = 'Send Reserved Key',
    [0xf0] = 'Log Push',
    [0xf1] = 'Component Self Test State', -- The component is identified by sender field
    [0xf2] = 'Log Control Global',
    [0xf3] = 'Log Control Module',
    [0xf4] = 'Test Start',
    [0xf5] = 'Test Stop',
    [0xf6] = 'Test Query Result',
    [0xf7] = 'Push Test Result',
    [0xf8] = 'Get Metadata',
    [0xfa] = 'Log Control',
    [0xfb] = 'Selftest State',
    [0xfc] = 'Selftest State Count',
    [0xfd] = 'Dump Frame Buffer', -- or Autotest Error Inject?
    [0xfe] = 'Self Define', -- Pure Transfer From Mc To App
    [0xff] = 'Query Device Info', -- Asks a component for identification string / Build Info(Date, Time, Type)
}

-- General - Version Inquiry - 0x01
-- When a component receives this request, it responds with a packet containing hardware and software versions.
-- Supported in: P3X_FW_V01.11.0030_m0400, WM620_FW_01.02.0300_m0800

f.general_version_inquiry_rq_unknown0 = ProtoField.uint8 ("dji_dumlv1.general_version_inquiry_rq_unknown0", "RqUnknown0", base.HEX, nil, nil, "Some kind of request type/flags?")

f.general_version_inquiry_unknown0 = ProtoField.uint8 ("dji_dumlv1.general_version_inquiry_unknown0", "Unknown0", base.HEX, nil, nil, "On Ph3 DM36x, hard coded to 0")
f.general_version_inquiry_unknown1 = ProtoField.uint8 ("dji_dumlv1.general_version_inquiry_unknown1", "Unknown1", base.HEX, nil, nil, "On Ph3 DM36x, hard coded to 0")
f.general_version_inquiry_hw_version = ProtoField.string ("dji_dumlv1.general_version_inquiry_hw_version", "Hardware Version", base.NONE, nil, nil)
f.general_version_inquiry_ldr_version = ProtoField.string ("dji_dumlv1.general_version_inquiry_ldr_version", "Firmware Loader Version", base.NONE, nil, nil, "On Ph3 DM36x, hard coded to 0x2000000")
f.general_version_inquiry_app_version = ProtoField.string ("dji_dumlv1.general_version_inquiry_app_version", "Firmware App Version", base.NONE, nil, nil, "Standard 4-byte version number")
f.general_version_inquiry_unknown1A = ProtoField.uint32 ("dji_dumlv1.general_version_inquiry_unknown1A", "Unknown1A", base.HEX, nil, nil, "On Ph3 DM36x, hard coded to 0x3FF; bit 31=isProduction, 30=isSupportSafeUpgrade")
f.general_version_inquiry_unknown1E_bt = ProtoField.uint8 ("dji_dumlv1.general_version_inquiry_unknown1E", "Unknown1E", base.HEX, nil, nil, "On Ph3 DM36x, hard coded to 1")
f.general_version_inquiry_unknown1E_dw = ProtoField.uint32 ("dji_dumlv1.general_version_inquiry_unknown1E", "Unknown1E", base.HEX, nil, nil, "On Ph3 DM36x, hard coded to 1")

local function general_version_inquiry_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request

        if (payload:len() >= 1) then

            subtree:add_le (f.general_version_inquiry_rq_unknown0, payload(offset, 1))
            offset = offset + 1

        end

        if (offset ~= 0) and (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Version Inquiry: Offset does not match - internal inconsistency") end
    else -- Response

        -- Written based on DM36x module and its Update_Fill_Version() function used by `usbclient` binary

        subtree:add_le (f.general_version_inquiry_unknown0, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.general_version_inquiry_unknown1, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.general_version_inquiry_hw_version, payload(offset, 16))
        offset = offset + 16

        -- using string ProtoField instead of uint32 to allow easier formatting of the value
        local ldr_ver_1 = payload(offset+0, 1):le_uint()
        local ldr_ver_2 = payload(offset+1, 1):le_uint()
        local ldr_ver_3 = payload(offset+2, 1):le_uint()
        local ldr_ver_4 = payload(offset+3, 1):le_uint()
        subtree:add_le (f.general_version_inquiry_ldr_version, payload(offset, 4), string.format("%02d.%02d.%02d.%02d",ldr_ver_4,ldr_ver_3,ldr_ver_2,ldr_ver_1))
        offset = offset + 4

        -- using string ProtoField instead of uint32 to allow easier formatting of the value
        local app_ver_1 = payload(offset+0, 1):le_uint()
        local app_ver_2 = payload(offset+1, 1):le_uint()
        local app_ver_3 = payload(offset+2, 1):le_uint()
        local app_ver_4 = payload(offset+3, 1):le_uint()
        subtree:add_le (f.general_version_inquiry_app_version, payload(offset, 4), string.format("%02d.%02d.%02d.%02d",app_ver_4,app_ver_3,app_ver_2,app_ver_1))
        offset = offset + 4

        subtree:add_le (f.general_version_inquiry_unknown1A, payload(offset, 4))
        offset = offset + 4

        if (payload:len() >= 34) then -- 34-byte packet spotted on P3X_FW_V01.11
            subtree:add_le (f.general_version_inquiry_unknown1E_dw, payload(offset, 4))
            offset = offset + 4
        elseif (payload:len() >= 31) then -- 31-byte packet exists on P3X_FW_V01.08 and all older versions
            subtree:add_le (f.general_version_inquiry_unknown1E_bt, payload(offset, 1))
            offset = offset + 1
        end -- 30-byte version exists on WM620_FW_01.02

        if (offset ~= 30) and (offset ~= 31) and (offset ~= 34) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Version Inquiry: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Version Inquiry: Payload size different than expected") end
end

-- General - Enter Loader - 0x07
-- When a component receives this request, it sets startup parameters to boot into bootloader mode, and reboots the chip.
-- Supported in: P3X_FW_V01.11.0030_m0400

--f.general_enter_loader_unknown0 = ProtoField.none ("dji_dumlv1.general_enter_loader_unknown0", "Unknown0", base.NONE)

local function general_enter_loader_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    -- Details from DM36x could be decoded using func Dec_Serial_Enter_Loader from `usbclient` binary

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Enter Loader: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Enter Loader: Payload size different than expected") end
end

-- General - Update Confirm / Upgrade Prepare / Firmware Upgrade Procedure Start - 0x08
-- Supported in: P3X_FW_V01.11.0030_m0400

--f.general_update_confirm_unknown0 = ProtoField.none ("dji_dumlv1.general_update_confirm_unknown0", "Unknown0", base.NONE)

local function general_update_confirm_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    -- TODO

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Update Confirm: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Update Confirm: Payload size different than expected") end
end

-- General - Update Transmit / Firmware Upgrade Data Transmission - 0x09
-- Supported in: P3X_FW_V01.11.0030_m0400

--f.general_update_transmit_unknown0 = ProtoField.none ("dji_dumlv1.general_update_transmit_unknown0", "Unknown0", base.NONE)

local function general_update_transmit_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    -- TODO

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Update Transmit: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Update Transmit: Payload size different than expected") end
end

-- General - Update Finish / Firmware Upgrade Verify - 0x0a
-- Supported in: P3X_FW_V01.11.0030_m0400

--f.general_update_finish_unknown0 = ProtoField.none ("dji_dumlv1.general_update_finish_unknown0", "Unknown0", base.NONE)

local function general_update_finish_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    -- TODO

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Update Finish: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Update Finish: Payload size different than expected") end
end

-- General - Reboot Chip - 0x0b
-- When a component receives this request, it reboots itself.
-- Supported in: P3X_FW_V01.11.0030_m0400

f.general_reboot_chip_response = ProtoField.uint8 ("dji_dumlv1.general_reboot_chip_response", "Response", base.HEX, nil, nil, "Non-zero if request was rejected")

f.general_reboot_chip_unknown0 = ProtoField.uint16 ("dji_dumlv1.general_reboot_chip_unknown0", "Unknown0", base.HEX)
f.general_reboot_chip_sleep_time = ProtoField.uint32 ("dji_dumlv1.general_reboot_chip_sleep_time", "Reboot Sleep Time", base.DEC)

local function general_reboot_chip_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (payload:len() >= 6) then
        -- Details from DM36x could be decoded using func Dec_Serial_Reboot from `usbclient` binary
        subtree:add_le (f.general_reboot_chip_unknown0, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.general_reboot_chip_sleep_time, payload(offset, 4))
        offset = offset + 4

        if (offset ~= 6) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Reboot Chip: Offset does not match - internal inconsistency") end
    elseif (payload:len() >= 1) then
        -- Details from P3 Flight controller firmware binary
        subtree:add_le (f.general_reboot_chip_response, payload(offset, 1))
        offset = offset + 1

        if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Reboot Chip: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Reboot Chip: Payload size different than expected") end
end

-- General - Get Device State - 0x0c
-- When a component receives this request, it responds with two integer values representing device state.
-- Supported in: P3X_FW_V01.11.0030_m0400

f.general_get_device_state_status = ProtoField.uint8 ("dji_dumlv1.general_get_device_state_status", "Status", base.HEX)
f.general_get_device_state_unknown1 = ProtoField.uint8 ("dji_dumlv1.general_get_device_state_unknown1", "Unknown1", base.HEX)
f.general_get_device_state_state = ProtoField.uint32 ("dji_dumlv1.general_get_device_state_state", "Device State", base.HEX)

local function general_get_device_state_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request

        if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Get Device State: Offset does not match - internal inconsistency") end

    else -- Response

        -- Checked with P3X DM36x func Dec_Serial_Get_Device_State from `usbclient` binary
        -- Checked with P3X_FW_V01.11.0030_m0400

        subtree:add_le (f.general_get_device_state_status, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.general_get_device_state_unknown1, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.general_get_device_state_state, payload(offset, 4))
        offset = offset + 4

        if (offset ~= 6) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Get Device State: Offset does not match - internal inconsistency") end

    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Get Device State: Payload size different than expected") end
end

-- General - Set Device Version - 0x0d
-- Sets version numbers which the component should report. Not all values are really used in most components.
-- P3X Gimbal firmware contains additional functionality, triggered when specific magic values are used instead of firmware versions to set.
-- Supported in: P3X_FW_V01.11.0030_m0400

f.general_set_device_version_unknown0 = ProtoField.uint8 ("dji_dumlv1.general_set_device_version_unknown0", "Unknown0", base.HEX)
f.general_set_device_version_hw_ver = ProtoField.bytes ("dji_dumlv1.general_set_device_version_hw_ver", "HW Version", base.SPACE)
f.general_set_device_version_ldr_ver = ProtoField.bytes ("dji_dumlv1.general_set_device_version_ldr_ver", "Loader Version", base.SPACE)
f.general_set_device_version_app_ver = ProtoField.bytes ("dji_dumlv1.general_set_device_version_app_ver", "App Version", base.SPACE)
f.general_set_device_version_unk4_ver = ProtoField.bytes ("dji_dumlv1.general_set_device_version_unk4_ver", "Unk4 Version", base.SPACE)

f.general_set_device_version_status = ProtoField.uint8 ("dji_dumlv1.general_set_device_version_status", "Status", base.HEX)
f.general_set_device_version_flags1 = ProtoField.uint8 ("dji_dumlv1.general_set_device_version_flags1", "Flags1", base.HEX)
f.general_set_device_version_unknown2 = ProtoField.bytes ("dji_dumlv1.general_set_device_version_unknown2", "Unknown2", base.SPACE)

local function general_set_device_version_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request

        -- Details from DM36x could be decoded using func Dec_Serial_Set_Device_Version from `usbclient` binary
        -- Checked with P3X_FW_V01.11.0030_m0400

        subtree:add_le (f.general_set_device_version_unknown0, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.general_set_device_version_hw_ver, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.general_set_device_version_ldr_ver, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.general_set_device_version_app_ver, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.general_set_device_version_unk4_ver, payload(offset, 4))
        offset = offset + 4

        if (offset ~= 17) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Set Device Version: Offset does not match - internal inconsistency") end
    else -- Response

        -- Details from DM36x could be decoded using func Dec_Serial_Set_Device_Version from `usbclient` binary
        -- Checked with P3X_FW_V01.11.0030_m0400

        subtree:add_le (f.general_set_device_version_status, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.general_set_device_version_flags1, payload(offset, 1))
        offset = offset + 1

        -- This may be either chip state (10 bytes) or 4 versions (16 bytes).. strange - maybe a mistake in m0400 firmware
        subtree:add_le (f.general_set_device_version_unknown2, payload(offset, 16))
        offset = offset + 16

        if (offset ~= 18) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Set Device Version: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Set Device Version: Payload size different than expected") end
end

-- General - Heartbeat/Log Message - 0x0e
-- Description: It can transmit text messages from FC (when sent as Request by FC), but is usually empty (when Requested by PC, or answering to such request).
--   Text message seen on P3X_FW_V01.07.0060 when trying to read non-existing flyc_param (cmd=0xf8).
--   Text message also seen on WM620_FW_01.02.0300 when capturing FC startup.
-- Supported in: P3X, WM620

f.general_heartbeat_log_message_group = ProtoField.uint8 ("dji_dumlv1.general_heartbeat_log_message_group", "Group", base.DEC, nil, nil)
f.general_heartbeat_log_message_text = ProtoField.string ("dji_dumlv1.general_heartbeat_log_message_text", "Text", base.ASCII)

local function general_heartbeat_log_message_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    -- Group is not present in Heartbeat requests
    if (payload:len() > 0) then

        subtree:add_le (f.general_heartbeat_log_message_group, payload(offset, 1))
        offset = offset + 1

    end

    -- Log message is not present in responses to Heartbeat requests
    if (payload:len() > 1) then

        local log_text = payload(offset, payload:len() - offset)
        subtree:add (f.general_heartbeat_log_message_text, log_text)
        offset = payload:len()

    end

    --if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Heartbeat Log Message: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Heartbeat Log Message: Payload size different than expected") end
end

-- General - Upgrade Self Request - 0x0f

f.general_upgrade_self_request_unknown0 = ProtoField.uint8 ("dji_dumlv1.general_upgrade_self_request_unknown0", "Unknown0", base.HEX)
f.general_upgrade_self_request_unknown1 = ProtoField.uint8 ("dji_dumlv1.general_upgrade_self_request_unknown1", "Unknown1", base.HEX)

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

-- General - File Sending - 0x24

f.general_file_sending_index = ProtoField.int32 ("dji_dumlv1.general_file_sending_index", "Index", base.DEC)
f.general_file_sending_data = ProtoField.bytes ("dji_dumlv1.general_file_sending_data", "Data", base.SPACE)

local function general_file_sending_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.general_file_sending_index, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.general_file_sending_data, payload(offset, 495))
    offset = offset + 495


    if (offset ~= 499) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"File Sending: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"File Sending: Payload size different than expected") end
end

-- General - Camera File - 0x27

--f.general_camera_file_unknown0 = ProtoField.none ("dji_dumlv1.general_camera_file_unknown0", "Unknown0", base.NONE)

local function general_camera_file_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera File: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera File: Payload size different than expected") end
end

-- General - FileTrans General Trans - 0x2a
-- Description: Used to transfer files from PC to m0801, ie. Inspire software licenses.
-- Supported in: WM620_FW_01.02.0300_m0800

enums.COMMON_FILETRANS_GENERAL_TRANS_PHASE_ENUM = {
    [1]="Begin transfer",
    [2]="Data part",
    [3]="Finish transfer",
}

f.general_filetrans_general_trans_phase = ProtoField.uint8 ("dji_dumlv1.general_filetrans_general_trans_phase", "Transfer Phase", base.DEC, enums.COMMON_FILETRANS_GENERAL_TRANS_PHASE_ENUM, nil, nil)
f.general_filetrans_general_trans_datalen = ProtoField.uint32 ("dji_dumlv1.general_filetrans_general_trans_datalen", "Total Length", base.DEC, nil, nil, "File size in bytes")
f.general_filetrans_general_trans_partno = ProtoField.uint32 ("dji_dumlv1.general_filetrans_general_trans_partno", "Part No", base.DEC)
f.general_filetrans_general_trans_unknown1 = ProtoField.bytes ("dji_dumlv1.general_filetrans_general_trans_unknown1", "Unknown1", base.SPACE, nil, nil, "After file transfer, 16 bytes? MD5?")
f.general_filetrans_general_trans_data = ProtoField.bytes ("dji_dumlv1.general_filetrans_general_trans_data", "Data", base.SPACE)
f.general_filetrans_general_trans_fname_len = ProtoField.uint8 ("dji_dumlv1.general_filetrans_general_trans_fname", "File Name Length", base.DEC)
f.general_filetrans_general_trans_fname = ProtoField.string ("dji_dumlv1.general_filetrans_general_trans_fname", "File Name", base.NONE, nil, nil)

f.general_filetrans_general_trans_resp_phase = ProtoField.uint8 ("dji_dumlv1.general_filetrans_general_trans_resp_phase", "Response for Transfer Phase", base.DEC, enums.COMMON_FILETRANS_GENERAL_TRANS_PHASE_ENUM, nil, nil)
f.general_filetrans_general_trans_status = ProtoField.uint8 ("dji_dumlv1.general_filetrans_general_trans_status", "Status", base.HEX)
f.general_filetrans_general_trans_res_unknown0 = ProtoField.bytes ("dji_dumlv1.general_filetrans_general_trans_res_unknown0", "RespUnknown0", base.SPACE)

local function general_filetrans_general_trans_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request

        local phase = payload(offset,1):le_uint()
        subtree:add_le (f.general_filetrans_general_trans_phase, payload(offset, 1))
        offset = offset + 1

        if phase == 1 then

            subtree:add_le (f.general_filetrans_general_trans_datalen, payload(offset, 4))
            offset = offset + 4

            local fname_len = payload(offset,1):le_uint()
            subtree:add_le (f.general_filetrans_general_trans_fname_len, payload(offset, 1))
            offset = offset + 1

            subtree:add_le (f.general_filetrans_general_trans_fname, payload(offset, fname_len))
            offset = offset + fname_len

        elseif phase == 2 then

            subtree:add_le (f.general_filetrans_general_trans_partno, payload(offset, 4))
            offset = offset + 4

            local data_len = payload:len() - offset
            subtree:add_le (f.general_filetrans_general_trans_data, payload(offset, data_len))
            offset = offset + data_len

        elseif phase == 3 then

            subtree:add_le (f.general_filetrans_general_trans_unknown1, payload(offset, 16))
            offset = offset + 16

        end

        --if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FileTrans General Trans: Offset does not match - internal inconsistency") end
    else -- Response

        if (payload:len() >= 6) then

            subtree:add_le (f.general_filetrans_general_trans_resp_phase, 1) -- Add response type detached, without related byte within packet (type is recognized by size, not by field)

            subtree:add_le (f.general_filetrans_general_trans_status, payload(offset, 1))
            offset = offset + 1

            subtree:add_le (f.general_filetrans_general_trans_res_unknown0, payload(offset, 5))
            offset = offset + 5

        elseif (payload:len() >= 5) then

            subtree:add_le (f.general_filetrans_general_trans_resp_phase, 2)

            subtree:add_le (f.general_filetrans_general_trans_status, payload(offset, 1))
            offset = offset + 1

            subtree:add_le (f.general_filetrans_general_trans_partno, payload(offset, 4))
            offset = offset + 4

        else

            subtree:add_le (f.general_filetrans_general_trans_resp_phase, 3)

            subtree:add_le (f.general_filetrans_general_trans_status, payload(offset, 1))
            offset = offset + 1

        end

        if (offset ~= 1) and (offset ~= 5) and (offset ~= 6) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"FileTrans General Trans: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"FileTrans General Trans: Payload size different than expected") end
end

-- General - Encrypt Config - 0x30
-- Used for factory encryption pairing, and for encryption verification at startup.
-- Failing encryption verification in some components sets Authority Level to 0, which makes the device ignore most commands.
-- Supported in: P3X_FW_V01.11.0030_m0400 (without DoEncrypt)

enums.COMMON_ENCRYPT_CONFIG_CMD_TYPE_ENUM = {
    [1]="GetChipState", -- Returns At88 chip state flags and factory info
    [2]="GetModuleState", -- Returns At88 module state flags
    [3]="Config", -- Configures the decryption, storing new key.txt and factory info
    [4]="DoEncrypt", -- Encrypts and returns data buffer given in the packet
}

enums.COMMON_ENCRYPT_CONFIG_OPER_TYPE_ENUM = {
    [0]="Write to target chip",
    [1]="Write to SH204 storage",
    [2]="Write both target and SH204",
}

f.general_encrypt_config_cmd_type = ProtoField.uint8 ("dji_dumlv1.general_encrypt_config_cmd_type", "Cmd Type", base.DEC, enums.COMMON_ENCRYPT_CONFIG_CMD_TYPE_ENUM, nil, nil)

f.general_encrypt_config_oper_type = ProtoField.uint8 ("dji_dumlv1.general_encrypt_config_oper_type", "Oper Type", base.DEC, enums.COMMON_ENCRYPT_CONFIG_OPER_TYPE_ENUM, nil, nil)
f.general_encrypt_config_magic = ProtoField.bytes ("dji_dumlv1.general_encrypt_config_magic", "Magic value", base.SPACE, nil, nil, "Should be `F0 BD E3 06 81 3E 85 CB`")
f.general_encrypt_config_mod_type = ProtoField.uint8 ("dji_dumlv1.general_encrypt_config_mod_type", "Module Type", base.DEC, nil, nil, "Type of the module; selects encryption key to use; Camera supports keys 1, 4 and 8; gimbal accepts only 4 and DM3xx only 8.")
f.general_encrypt_config_board_sn = ProtoField.bytes ("dji_dumlv1.general_encrypt_config_board_sn", "Board SN", base.SPACE, nil, nil, "Factory Serial Number of the Board")
f.general_encrypt_config_key = ProtoField.bytes ("dji_dumlv1.general_encrypt_config_key", "Encrypt Key", base.SPACE, nil, nil, "New AES encryption key")
f.general_encrypt_config_secure_num = ProtoField.bytes ("dji_dumlv1.general_encrypt_config_secure_num", "Security Num", base.SPACE, nil, nil, "MD5 of Board SN and Encrypt Key")

f.general_encrypt_config_buf_data = ProtoField.bytes ("dji_dumlv1.general_encrypt_config_buf_data", "Buffer data", base.SPACE, nil, nil)

f.general_encrypt_config_resp_type = ProtoField.uint8 ("dji_dumlv1.general_encrypt_config_resp_type", "Response To Cmd Type", base.DEC, enums.COMMON_ENCRYPT_CONFIG_CMD_TYPE_ENUM, nil, nil)

f.general_encrypt_config_resp_status = ProtoField.uint8 ("dji_dumlv1.general_encrypt_config_resp_status", "Status", base.HEX, nil, nil, "Packet processing status; non-zero value means error. On error, packet content may be meaningless.")
f.general_encrypt_config_resp_chip_state_flags = ProtoField.uint8 ("dji_dumlv1.general_encrypt_config_resp_chip_state_flags", "Chip State Flags", base.HEX, nil, nil)
  f.general_encrypt_config_resp_chip_state_conf_zone_unlock = ProtoField.uint8 ("dji_dumlv1.general_encrypt_config_resp_chip_state_conf_zone_unlock", "Config Zone Unlocked", base.DEC, nil, 0x01)
  f.general_encrypt_config_resp_chip_state_data_zone_unlock = ProtoField.uint8 ("dji_dumlv1.general_encrypt_config_resp_chip_state_data_zone_unlock", "Data and&otp Zone Unlocked", base.DEC, nil, 0x06)
f.general_encrypt_config_resp_modl_state_flags = ProtoField.uint8 ("dji_dumlv1.general_encrypt_config_resp_modl_state_flags", "Module State Flags", base.HEX, nil, nil)
  f.general_encrypt_config_resp_modl_state_module_ready = ProtoField.uint8 ("dji_dumlv1.general_encrypt_config_resp_modl_state_module_ready", "Module reports ready / Key file exists", base.DEC, nil, 0x01, "On P3X: When sent to Camera, returns SH204 status; when sent to DM3xx, returns if key.bin exists")
  f.general_encrypt_config_resp_modl_state_verify_pass = ProtoField.uint8 ("dji_dumlv1.general_encrypt_config_resp_modl_state_verify_pass", "Module/KeyFile verification passed", base.DEC, nil, 0x02, "On P3X: When sent to Camera, returns SH204 verification status;  when sent to DM3xx, it returns whrther DoEncrypt sent to Camera gives same result as encryption using local key.bin")
f.general_encrypt_config_resp_m01_boardsn = ProtoField.bytes ("dji_dumlv1.general_encrypt_config_resp_m01_boardsn", "Module 01 Board SN", base.SPACE, nil, nil, "Board number for camera module")
f.general_encrypt_config_resp_m04_boardsn = ProtoField.bytes ("dji_dumlv1.general_encrypt_config_resp_m04_boardsn", "Module 04 Board SN", base.SPACE, nil, nil, "Board number for gimbal module")
f.general_encrypt_config_resp_m08_boardsn = ProtoField.bytes ("dji_dumlv1.general_encrypt_config_resp_m08_boardsn", "Module 08 Board SN", base.SPACE, nil, nil, "Board number for dm3xx module")

f.general_encrypt_config_resp_mac = ProtoField.bytes ("dji_dumlv1.general_encrypt_config_resp_mac", "MAC", base.SPACE, nil, nil)
f.general_encrypt_config_resp_brdnum = ProtoField.bytes ("dji_dumlv1.general_encrypt_config_resp_brdnum", "Board Num", base.SPACE, nil, nil)
f.general_encrypt_config_resp_sn = ProtoField.bytes ("dji_dumlv1.general_encrypt_config_resp_sn", "SN", base.SPACE, nil, nil)

local function general_encrypt_config_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request
        local cmd_type = payload(offset,1):le_uint()
        subtree:add_le (f.general_encrypt_config_cmd_type, payload(offset, 1))
        offset = offset + 1

        if cmd_type == 1 then
            -- Answer could be decoded using func Dec_Serial_Encrypt_GetChipState from `usbclient` binary
            if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Encrypt type 1: Offset does not match - internal inconsistency") end
        elseif cmd_type == 2 then
            -- Answer could be decoded using func Dec_Serial_Encrypt_GetModuleState from `usbclient` binary
            if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Encrypt type 2: Offset does not match - internal inconsistency") end
        elseif cmd_type == 3 then
            -- Decoded using func Dec_Serial_Encrypt_Config from `usbclient` binary
            subtree:add_le (f.general_encrypt_config_oper_type, payload(offset, 1))
            offset = offset + 1

            subtree:add_le (f.general_encrypt_config_magic, payload(offset, 8))
            offset = offset + 8

            subtree:add_le (f.general_encrypt_config_mod_type, payload(offset, 1))
            offset = offset + 1

            subtree:add_le (f.general_encrypt_config_board_sn, payload(offset, 10))
            offset = offset + 10

            subtree:add_le (f.general_encrypt_config_key, payload(offset, 32))
            offset = offset + 32

            subtree:add_le (f.general_encrypt_config_secure_num, payload(offset, 16))
            offset = offset + 16

            if (offset ~= 69) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Encrypt type 3: Offset does not match - internal inconsistency") end
        elseif cmd_type == 4 then
            -- Answer could be decoded using func Encrypt_Request from `encode_usb` binary
            local buf_len = payload(offset,1):le_uint()
            subtree:add_le (f.general_encrypt_config_mod_type, payload(offset, 1))
            offset = offset + 1

            subtree:add_le (f.general_encrypt_config_buf_data, payload(offset, 32))
            offset = offset + 32

            if (offset ~= 33) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Encrypt type 4: Offset does not match - internal inconsistency") end
        end
    else -- Response
        subtree:add_le (f.general_encrypt_config_resp_status, payload(offset, 1))
        offset = offset + 1

        if (payload:len() >= 59) then
            subtree:add_le (f.general_encrypt_config_resp_type, 4) -- Add response type detached, without related byte within packet (type is recognized by size, not by field)

            subtree:add_le (f.general_encrypt_config_resp_mac, payload(offset, 32))
            offset = offset + 32

            subtree:add_le (f.general_encrypt_config_resp_brdnum, payload(offset, 10))
            offset = offset + 10

            subtree:add_le (f.general_encrypt_config_resp_sn, payload(offset, 16))
            offset = offset + 16

            if (offset ~= 59) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Encrypt reply: Offset does not match - internal inconsistency") end
        elseif (payload:len() >= 32) then
            subtree:add_le (f.general_encrypt_config_resp_type, 1)

            subtree:add_le (f.general_encrypt_config_resp_chip_state_flags, payload(offset, 1))
            subtree:add_le (f.general_encrypt_config_resp_chip_state_conf_zone_unlock, payload(offset, 1))
            subtree:add_le (f.general_encrypt_config_resp_chip_state_data_zone_unlock, payload(offset, 1))
            offset = offset + 1

            subtree:add_le (f.general_encrypt_config_resp_m01_boardsn, payload(offset, 10))
            offset = offset + 10

            subtree:add_le (f.general_encrypt_config_resp_m04_boardsn, payload(offset, 10))
            offset = offset + 10

            subtree:add_le (f.general_encrypt_config_resp_m08_boardsn, payload(offset, 10))
            offset = offset + 10

            if (offset ~= 32) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Encrypt reply: Offset does not match - internal inconsistency") end
        elseif (payload:len() >= 2) then
            subtree:add_le (f.general_encrypt_config_resp_type, 2)

            subtree:add_le (f.general_encrypt_config_resp_modl_state_flags, payload(offset, 1))
            subtree:add_le (f.general_encrypt_config_resp_modl_state_module_ready, payload(offset, 1))
            subtree:add_le (f.general_encrypt_config_resp_modl_state_verify_pass, payload(offset, 1))
            offset = offset + 1

            if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Encrypt reply: Offset does not match - internal inconsistency") end
        elseif (payload:len() >= 1) then
            subtree:add_le (f.general_encrypt_config_resp_type, 3)

            if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Encrypt reply: Offset does not match - internal inconsistency") end
        end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Encrypt: Payload size different than expected") end
end

-- General - Activate Config / Activation Action - 0x32

f.general_activation_actn_action = ProtoField.uint8 ("dji_dumlv1.general_activation_actn_action", "Action", base.HEX)
f.general_activation_actn_state = ProtoField.uint8 ("dji_dumlv1.general_activation_actn_state", "State", base.HEX)
f.general_activation_actn_year = ProtoField.uint16 ("dji_dumlv1.general_activation_actn_year", "Year", base.DEC)
f.general_activation_actn_month = ProtoField.uint8 ("dji_dumlv1.general_activation_actn_month", "Month", base.DEC)
f.general_activation_actn_day = ProtoField.uint8 ("dji_dumlv1.general_activation_actn_day", "Day", base.DEC)
f.general_activation_actn_hour = ProtoField.uint8 ("dji_dumlv1.general_activation_actn_hour", "Hour", base.DEC)
f.general_activation_actn_min = ProtoField.uint8 ("dji_dumlv1.general_activation_actn_min", "Minute", base.DEC)
f.general_activation_actn_sec = ProtoField.uint8 ("dji_dumlv1.general_activation_actn_sec", "Second", base.DEC)
f.general_activation_actn_ts = ProtoField.bytes ("dji_dumlv1.general_activation_actn_ts", "Timestamp", base.NONE)
f.general_activation_actn_mc_serial_len = ProtoField.uint8 ("dji_dumlv1.general_activation_actn_mc_serial_len", "MC Serial length", base.DEC)
f.general_activation_actn_mc_serial = ProtoField.string ("dji_dumlv1.general_activation_actn_mc_serial", "MC Serial", base.ASCII)

local function general_activation_actn_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request

    -- TODO

    else -- Response
        subtree:add_le (f.general_activation_actn_action, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.general_activation_actn_state, payload(offset, 1))
        offset = offset + 1

        local mc_serial_len = 0

        if (payload:len() >= 10) then

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

            mc_serial_len = payload(offset,1):uint()
            subtree:add_le (f.general_activation_actn_mc_serial_len, payload(offset, 1))
            offset = offset + 1

            if (offset + mc_serial_len > payload:len()) then -- the sn length seem to sometimes be wrong?
                subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Activation Action: SN length exceeds payload size")
                mc_serial_len = payload:len() - offset
            end

            subtree:add (f.general_activation_actn_mc_serial, payload(offset, mc_serial_len))
            offset = offset + mc_serial_len
        end

        if (offset ~= 2) and (offset ~= 10 + mc_serial_len) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Activation Action: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Activation Action: Payload size different than expected") end
end

-- General - MFi Cert - 0x33
-- In case of DM36x, the certificate is handled by IOCTL operations on "/dev/applecp".

enums.COMMON_MFI_CERT_CMD_TYPE_ENUM = {
    [1]="Get_Cert",
    [2]="Challenge_Response",
}

f.general_mfi_cert_cmd_type = ProtoField.uint8 ("dji_dumlv1.general_mfi_cert_cmd_type", "Cmd Type", base.DEC, enums.COMMON_MFI_CERT_CMD_TYPE_ENUM, nil, "'Made For iPod' concerns Apple devices only.")
f.general_mfi_cert_part_sn = ProtoField.uint8 ("dji_dumlv1.general_mfi_cert_part_sn", "Part SN", base.DEC, nil, nil, "Selects which 128-byte part of certificate to return")
--f.general_mfi_cert_unknown0 = ProtoField.none ("dji_dumlv1.general_mfi_cert_unknown0", "Unknown0", base.NONE)

local function general_mfi_cert_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    local cmd_type = payload(offset,1):le_uint()
    subtree:add_le (f.general_mfi_cert_cmd_type, payload(offset, 1))
    offset = offset + 1

    if cmd_type == 1 then
        -- Decoded using func Dec_Serial_MFI_Cert_Get_Cert from `usbclient` binary
        subtree:add_le (f.general_mfi_cert_part_sn, payload(offset, 1))
        offset = offset + 1

        if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"MFI Cert Get: Offset does not match - internal inconsistency") end
    elseif cmd_type == 2 then
        -- Decoded using func Dec_Serial_MFI_Cert_Challenge_Response from `usbclient` binary
        if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"MFI Cert Challenge: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"MFI Cert: Payload size different than expected") end
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

f.general_common_upgrade_status_upgrade_state = ProtoField.uint8 ("dji_dumlv1.general_common_upgrade_status_upgrade_state", "Upgrade State", base.DEC, enums.COMMON_UPGRADE_STATUS_UPGRADE_STATE_ENUM, nil, nil)
f.general_common_upgrade_status_user_time = ProtoField.uint8 ("dji_dumlv1.general_common_upgrade_status_user_time", "User Time", base.DEC, nil, nil, "For upgrade_state==2")
f.general_common_upgrade_status_user_reserve = ProtoField.uint8 ("dji_dumlv1.general_common_upgrade_status_user_reserve", "User Reserve", base.HEX, nil, nil, "For upgrade_state==2")
f.general_common_upgrade_status_upgrade_process = ProtoField.uint8 ("dji_dumlv1.general_common_upgrade_status_upgrade_process", "Upgrade Process", base.DEC, nil, nil, "For upgrade_state==3")
f.general_common_upgrade_status_cur_upgrade_index = ProtoField.uint8 ("dji_dumlv1.general_common_upgrade_status_cur_upgrade_index", "Cur Upgrade Index", base.DEC, nil, 0xe0, "For upgrade_state==3")
f.general_common_upgrade_status_upgrade_times_3 = ProtoField.uint8 ("dji_dumlv1.general_common_upgrade_status_upgrade_times", "Upgrade Times", base.DEC, nil, 0x1f, "For upgrade_state==3")
f.general_common_upgrade_status_upgrade_result = ProtoField.uint8 ("dji_dumlv1.general_common_upgrade_status_upgrade_result", "Upgrade Result", base.HEX, enums.COMMON_UPGRADE_STATUS_UPGRADE_COMPLETE_REASON_ENUM, nil, "For upgrade_state==4")
f.general_common_upgrade_status_upgrade_times_4 = ProtoField.uint8 ("dji_dumlv1.general_common_upgrade_status_upgrade_times", "Upgrade Times", base.HEX, nil, nil, "For upgrade_state==4")

local function general_common_upgrade_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    local upgrade_state = payload(offset,1):le_uint()
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

-- General - Power State - 0x47

f.general_power_state_a = ProtoField.uint8 ("dji_dumlv1.general_power_state_a", "A", base.DEC, nil, nil, "TODO values from enum P3.DataNotifyDisconnect")
f.general_power_state_b = ProtoField.uint16 ("dji_dumlv1.general_power_state_b", "B", base.DEC)

local function general_power_state_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.general_power_state_a, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.general_power_state_b, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 3) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Power State: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Power State: Payload size different than expected") end
end

-- General - Set Gps Push Config - 0x52

f.general_set_gps_push_config_is_start = ProtoField.uint8 ("dji_dumlv1.general_set_gps_push_config_is_start", "Is Start", base.DEC)
f.general_set_gps_push_config_get_push_interval = ProtoField.uint32 ("dji_dumlv1.general_set_gps_push_config_get_push_interval", "Get Push Interval", base.DEC)

local function general_set_gps_push_config_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.general_set_gps_push_config_is_start, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.general_set_gps_push_config_get_push_interval, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Set Gps Push Config: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Set Gps Push Config: Payload size different than expected") end
end

-- General - Component Self Test State - 0xf1

f.general_compn_state_current_state = ProtoField.uint32 ("dji_dumlv1.general_compn_state_current_state", "Current state", base.HEX)
  -- Component state packet flags for OFDM
  f.general_compn_state_ofdm_curr_state_fpga_boot = ProtoField.uint32 ("dji_dumlv1.general_compn_state_ofdm_curr_state_fpga_boot", "E FPGA Boot error", base.HEX, nil, 0x01, "Error in FPGA boot state, final state not reached")
  f.general_compn_state_ofdm_curr_state_fpga_conf = ProtoField.uint32 ("dji_dumlv1.general_compn_state_ofdm_curr_state_fpga_conf", "E FPGA Config error", base.HEX, nil, 0x02, nil)
  f.general_compn_state_ofdm_curr_state_exec_fail1 = ProtoField.uint32 ("dji_dumlv1.general_compn_state_ofdm_curr_state_exec_fail1", "E Exec fail 1", base.HEX, nil, 0x04, "Meaning uncertain")
  f.general_compn_state_ofdm_curr_state_exec_fail2 = ProtoField.uint32 ("dji_dumlv1.general_compn_state_ofdm_curr_state_exec_fail2", "E Exec fail 2", base.HEX, nil, 0x08, "Meaning uncertain")
  f.general_compn_state_ofdm_curr_state_ver_match = ProtoField.uint32 ("dji_dumlv1.general_compn_state_ofdm_curr_state_ver_match", "E RC vs OFDM version mismatch?", base.HEX, nil, 0x20, "Meaning uncertain")
  f.general_compn_state_ofdm_curr_state_tcx_reg = ProtoField.uint32 ("dji_dumlv1.general_compn_state_ofdm_curr_state_tcx_reg", "E Transciever Register error", base.HEX, nil, 0x40, "Error in either ad9363 reg 0x17 or ar8003 reg 0x7C")
  f.general_compn_state_ofdm_curr_state_rx_bad_crc = ProtoField.uint32 ("dji_dumlv1.general_compn_state_ofdm_curr_state_rx_bad_crc", "E Received data CRC fail", base.HEX, nil, 0x400, "Meaning uncertain")
  f.general_compn_state_ofdm_curr_state_rx_bad_seq = ProtoField.uint32 ("dji_dumlv1.general_compn_state_ofdm_curr_state_rx_bad_seq", "E Received data sequence fail", base.HEX, nil, 0x800, "Meaning uncertain")

local function general_compn_state_dissector(pkt_length, buffer, pinfo, subtree)
    local sender = buffer(4,1):uint()

    local offset = 11
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

-- General - Query Device Info - 0xff

--f.general_query_device_info_unknown0 = ProtoField.none ("dji_dumlv1.general_query_device_info_unknown0", "Unknown0", base.NONE)

local function general_query_device_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Query Device Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Query Device Info: Payload size different than expected") end
end

GENERAL_UART_CMD_DISSECT = {
    [0x01] = general_version_inquiry_dissector,
    [0x07] = general_enter_loader_dissector,
    [0x08] = general_update_confirm_dissector,
    [0x09] = general_update_transmit_dissector,
    [0x0a] = general_update_finish_dissector,
    [0x0b] = general_reboot_chip_dissector,
    [0x0c] = general_get_device_state_dissector,
    [0x0d] = general_set_device_version_dissector,
    [0x0e] = general_heartbeat_log_message_dissector,
    [0x0f] = general_upgrade_self_request_dissector,
    [0x24] = general_file_sending_dissector,
    [0x27] = general_camera_file_dissector,
    [0x2a] = general_filetrans_general_trans_dissector,
    [0x30] = general_encrypt_config_dissector,
    [0x32] = general_activation_actn_dissector,
    [0x33] = general_mfi_cert_dissector,
    [0x42] = general_common_upgrade_status_dissector,
    [0x47] = general_power_state_dissector,
    [0x52] = general_set_gps_push_config_dissector,
    [0xf1] = general_compn_state_dissector,
    [0xff] = general_query_device_info_dissector,
}
