-- Create a new dissector
DJI_P3_BATT_PROTO = Proto ("dji_p3_batt", "DJI_P3_BATT", "Dji Ph3 battery communication protocol")

local f = DJI_P3_BATT_PROTO.fields
local enums = {}

DJI_P3_BATTERY_UART_CMDS = {
    [0x21] = 'Get Battery Type',
    [0x22] = 'Get Battery Status',
    [0x23] = 'DRM ?',
    [0x24] = 'DRM ?',
    [0x25] = 'Get Battery Warning Flags',
    [0x31] = 'Get Battery Settings',
    [0x34] = 'Unknown',
    [0x38] = 'Get Battery Barcode',
}


--Battery barcode
f.batt_barcode = ProtoField.bytes("dji_p3_batt.barcode", "Barcode", base.SPACE)

local function battery_barcode_dissector(batt_length, buffer, pinfo, subtree)
    local offset = 5
    if batt_length ~= 14 then
        subtree:add(f.batt_barcode, buffer(offset, (batt_length - offset - 1)))

    end
end

-- Battery Status
f.status_temp = ProtoField.uint16 ("dji_p3_batt.status_temp", "Temp", base.DEC)
f.status_total_v = ProtoField.uint16 ("dji_p3_batt.status_total_v", "Total mV", base.DEC)
f.status_current = ProtoField.int32 ("dji_p3_batt.status_current", "Current", base.DEC)
f.status_ave_current = ProtoField.int32 ("dji_p3_batt.status_ave_current", "Average Current", base.DEC)
f.status_state_of_charge = ProtoField.uint16 ("dji_p3_batt.status_charge", "Charge (%)", base.DEC)
f.status_cell_v = ProtoField.uint16 ("dji_p3_batt.status_cell_v", "Cell mV", base.DEC)
f.status_cell_eol = ProtoField.uint16 ("dji_p3_batt.status_cell_eol", "EOL", base.HEX)
f.status_power_status = ProtoField.string("dji_p3_batt.status_status", "Power Status")

local function battery_status_dissector(batt_length, buffer, pinfo, subtree)
    local offset = 5
--    local cell 
    if batt_length ~= 14 then
        subtree:add_le (f.status_temp, buffer(offset, 2))
        offset = offset + 2
        subtree:add_le (f.status_total_v, buffer(offset, 2))
        offset = offset + 2
        subtree:add_le (f.status_current, buffer(offset, 2))
        offset = offset + 4
        subtree:add_le (f.status_ave_current, buffer(offset, 2))
        offset = offset + 4
        subtree:add_le (f.status_state_of_charge, buffer(offset, 2))
        offset = offset + 2

        for cell = 1, 5 do
            subtree:add_le (f.status_cell_v, buffer(offset, 2))
            offset = offset + 2
        end
        
        subtree:add_le (f.status_cell_eol, buffer(offset, 2))
        offset = offset + 2

        local pstatus = buffer(offset,1):uint()
        if pstatus == 0x00 then
            subtree:add(f.status_power_status, "On")
        elseif pstatus == 0xFF then
            subtree:add(f.status_power_status, "Powering Off")
        else
            subtree:add(f.status_power_status, "Unknown")
        end
        
    end

end

-- Battery Info 
f.info_total_capacity = ProtoField.uint16 ("dji_p3_batt.info_total_capacity", "Total Cap", base.DEC)
f.info_discharge_count = ProtoField.uint16 ("dji_p3_batt.info_discharge_count", "Discharge Count", base.DEC)
f.info_nominal_capacity = ProtoField.uint16 ("dji_p3_batt.info_nominal_capacity", "Nominal Cap", base.DEC)
f.info_nominal_voltage = ProtoField.uint16 ("dji_p3_batt.info_nominal_voltage", "Nominal V", base.DEC)
f.info_battery_spec = ProtoField.uint16 ("dji_p3_batt.info_battery_spec", "Battery Spec", base.DEC)
f.info_mfr_date = ProtoField.string ("dji_p3_batt.info_mfr_date", "Mfr Date")
f.info_serial_number = ProtoField.uint16 ("dji_p3_batt.info_serial_number", "Serial Number", base.HEX)
f.info_name = ProtoField.string("dji_p3_batt.info_name", "Name")
f.info_unk1 = ProtoField.uint16 ("dji_p3_batt.info_unknown1", "Unknown", base.HEX)
f.info_unk2 = ProtoField.uint16 ("dji_p3_batt.info_unknown2", "Unknown", base.HEX)
f.info_fw_version = ProtoField.string ("dji_p3_batt.info_fw_version", "FW Version", base.ASCII)
f.info_life = ProtoField.uint16 ("dji_p3_batt.info_life", "Battery Life", base.DEC)

local function battery_type_dissector(batt_length, buffer, pinfo, subtree)
    local offset = 5

    if batt_length ~= 14 then
        subtree:add_le (f.info_total_capacity, buffer(offset, 2))
        offset = offset + 2
        subtree:add_le (f.info_discharge_count, buffer(offset, 2))
        offset = offset + 2
        subtree:add_le (f.info_nominal_capacity, buffer(offset, 2))
        offset = offset + 2
        subtree:add_le (f.info_nominal_voltage, buffer(offset, 2))
        offset = offset + 2
        subtree:add_le (f.info_battery_spec, buffer(offset, 2))
        offset = offset + 2

        local md = buffer(offset, 2):le_uint()
        local year = bit32.arshift(md,9) + 1980
        local month = bit32.band(bit32.arshift(md,5), 0x0F)
        local day = bit32.band(md, 0x01F)
        local date = string.format("%02d/%02d/%04d", day, month, year)
        subtree:add(f.info_mfr_date, date)
        offset = offset + 2

        subtree:add_le (f.info_serial_number, buffer(offset, 2))
        offset = offset + 2

        subtree:add(f.info_name, buffer(offset, 15))
        offset = offset + 15

        subtree:add_le (f.info_unk1, buffer(offset, 2))
        offset = offset + 2

        subtree:add_le (f.info_unk2, buffer(offset, 2))
        offset = offset + 2
        
        local version = string.format("%02d.%02d.%02d.%02d", buffer(offset,1):uint(), buffer(offset+1,1):uint(), buffer(offset+2,1):uint(), buffer(offset+3,1):uint())
        subtree:add(f.info_fw_version, version)
        offset = offset + 4

        subtree:add_le (f.info_life, buffer(offset, 2))
        offset = offset + 2

    end
end

DJI_P3_BATTERY_UART_DISSECT = {
    [0x21] = battery_type_dissector,
    [0x22] = battery_status_dissector,
    [0x38] = battery_barcode_dissector,
}

-- Top level packet fields

-- [0]  Start of Pkt, always 0xAB
f.delimiter = ProtoField.uint8 ("dji_p3_batt.delimiter", "Delimiter", base.HEX)
-- [1]  Length of Pkt 
f.length = ProtoField.uint16 ("dji_p3_batt.length", "Length", base.HEX, nil, 0x3FF)
-- [2]  
f.protocol_version = ProtoField.uint16 ("dji_p3_batt.protover", "Protocol Version", base.HEX, nil, 0xFC00)
-- [3] Cmd ID
f.cmd = ProtoField.uint8('dji_p3_batt.cmd', 'Battery Cmd', base.HEX, DJI_P3_BATTERY_UART_CMDS)

f.payload = ProtoField.bytes ("dji_p3_batt.payload", "Payload", base.NONE)

f.crc = ProtoField.uint8 ("dji_p3_batt.crc", "CRC", base.HEX)

-- Dissector top level function; is called within this dissector, but can also be called from outsude
function dji_p3_batt_main_dissector(buffer, pinfo, subtree)
    local offset = 1

    local batt_length = buffer(offset,2):le_uint()
    -- bit32 lib requires LUA 5.2
    batt_length = bit32.band(batt_length,  0x03FF)
    
    subtree:add_le (f.length, buffer(offset, 2))
    subtree:add_le (f.protocol_version, buffer(offset, 2))
    offset = offset + 2

    batt_cmd = buffer(offset, 1):uint()
    subtree:add (f.cmd, buffer(offset, 1))
    offset = offset + 1

    if batt_length > offset+1 then
        payload_tree = subtree:add(f.payload, buffer(offset, batt_length - offset - 1))

        -- If we have a dissector for this kind of command, run it
        local dissector = DJI_P3_BATTERY_UART_DISSECT[batt_cmd]

        if dissector ~= nil then
            dissector(batt_length, buffer, pinfo, payload_tree)
        end

    end 

    subtree:add(f.crc, buffer(batt_length - 1, 1))
end

-- The protocol dissector itself
function DJI_P3_BATT_PROTO.dissector (buffer, pinfo, tree)

    local subtree = tree:add (DJI_P3_BATT_PROTO, buffer())

    -- The Pkt start byte
    local offset = 0

    local pkt_type = buffer(offset,1):uint()
    subtree:add (f.delimiter, buffer(offset, 1))
    offset = offset + 1

    if pkt_type == 0xAB then
        dji_p3_batt_main_dissector(buffer, pinfo, subtree)
    end

end

-- A initialization routine
function DJI_P3_BATT_PROTO.init ()
end
