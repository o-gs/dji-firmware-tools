-- Create a new dissector
DJI_P3_PROTO = Proto ("dji_p3", "DJI_P3","Dji Ph3 DUPC / UART protocol")

dofile('dji-p3-flightrec.lua')

dofile('dji-p3-fcuart.lua')

local f = DJI_P3_PROTO.fields
-- [0]  Start of Pkt, always 0x55
f.delimiter = ProtoField.uint8 ("dji_p3.delimiter", "Delimiter", base.HEX)
-- [1]  Length of Pkt 
f.length = ProtoField.uint16 ("dji_p3.length", "Length", base.HEX, nil, 0x3FF)
-- [2]  Protocol version
f.protocol_version = ProtoField.uint16 ("dji_p3.protover", "Protocol Version", base.HEX, nil, 0xFC00)
-- [3]  Data Type
f.datatype = ProtoField.uint8 ("dji_p3.hdr_crc", "Header CRC", base.HEX)

-- Fields for ProtoVer = 0 (Flight Record)

-- [4-5]  Log Entry Type
f.rec_etype = ProtoField.uint16 ("dji_p3.rec_etype", "Log Entry Type", base.HEX, DJI_P3_FLIGHT_RECORD_ENTRY_TYPE)
-- [6-9]  Sequence Ctr
f.rec_seqctr = ProtoField.uint16 ("dji_p3.rec_seqctr", "Seq Counter", base.DEC)

-- Fields for ProtoVer = 1 (UART communication)

-- [4]  Sender
f.sender = ProtoField.uint8 ("dji_p3.sender", "Sender", base.DEC, DJI_P3_FLIGHT_CONTROL_UART_SRC_DEST, 0x1F)
-- [5]  Receiver
f.receiver = ProtoField.uint8 ("dji_p3.receiver", "Receiver", base.DEC, DJI_P3_FLIGHT_CONTROL_UART_SRC_DEST, 0x1F)
-- [6-7]  Sequence Ctr
f.seqctr = ProtoField.uint16 ("dji_p3.seqctr", "Seq Counter", base.DEC)
-- [8] Encryption
f.encrypt = ProtoField.uint8 ("dji_p3.encrypt", "Encryption Type", base.DEC, DJI_P3_FLIGHT_CONTROL_UART_ENCRYPT_TYPE, 0x0F)
-- [8] Ack (to be improved)
f.ack = ProtoField.uint8 ("dji_p3.ack", "Ack", base.HEX, DJI_P3_FLIGHT_CONTROL_UART_ACK_POLL, 0x60)
-- [9] Cmd Set
f.cmdset = ProtoField.uint8 ('dji_p3.cmdset', "Cmd Set", base.DEC, DJI_P3_FLIGHT_CONTROL_UART_CMD_SET, 0xFF)
-- [A] Cmd
f.cmd = ProtoField.uint8 ('dji_p3.cmd', "Cmd", base.HEX)
-- [B] Payload (optional)
f.payload = ProtoField.bytes ("dji_p3.payload", "Payload", base.SPACE)

-- [B+Payload] CRC
f.crc = ProtoField.uint16 ("dji_p3.crc", "CRC", base.HEX)

local function set_info(cmd, pinfo, valuestring)
    pinfo.cols.info = ""
    if valuestring[cmd] == nil then
        pinfo.cols.info:append(string.format("%s (0x%02X)", "Unknown", cmd))
    else
        pinfo.cols.info:append(valuestring[cmd])
    end
end

-- Sets text of a subtree which ProtoType had no valuestring like it had a valuestring
local function set_valuestring(cmd, subtree, valuestring)
    if valuestring[cmd] ~= nil then
        local subtree_name = string.match(subtree.text, "(.*):")
        subtree:set_text(string.format("%s: %s (0x%02X)", subtree_name, valuestring[cmd], cmd));
    end
end

local function bytearray_to_string(bytes)
  s = {}
  for i = 0, bytes:len() - 1 do
    s[i+1] = string.char(bytes:get_index(i))
  end
  return table.concat(s)
end

local function bytearray_to_hexstr(bytes)
  s = {}
  for i = 0, bytes:len() - 1 do
    s[i+1] = string.format("%02X",bytes:get_index(i))
  end
  return table.concat(s," ")
end

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

local function main_dissector(buffer, pinfo, subtree)
    local offset = 1

    -- [1-2] The Pkt length | protocol version?
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
        subtree:add_le (f.rec_etype, buffer(offset, 2))
        offset = offset + 2

        -- [6] Sequence Counter
        subtree:add_le (f.rec_seqctr, buffer(offset, 4))
        offset = offset + 4

        assert(offset == 10, "Offset shifted - dissector internal inconsistency")

        -- [A] Payload    
        if pkt_length > offset+2 then
            local payload_buf = flightrec_decrypt_payload(pkt_length, buffer)
            local payload_tree = subtree:add(f.payload, buffer(offset, pkt_length - offset - 2))
            payload_tree:set_text("Payload: " .. bytearray_to_hexstr(payload_buf));
            local payload_tvb = ByteArray.tvb(payload_buf, "Payload")

            -- If we have a dissector for this kind of command, run it
            local dissector = nil

            dissector = DJI_P3_FLIGHT_RECORD_DISSECT[etype]

            if dissector ~= nil then
                dissector(payload_tvb, pinfo, payload_tree)
            end

        end

    else

        -- [4] Sender
        subtree:add (f.sender, buffer(offset, 1))
        offset = offset + 1

        -- [5] Receiver
        subtree:add (f.receiver, buffer(offset, 1))
        offset = offset + 1

        -- [6] Sequence Counter
        subtree:add_le (f.seqctr, buffer(offset, 2))
        offset = offset + 2

        -- [8] Encrypt | Ack
        subtree:add (f.encrypt, buffer(offset, 1))
        subtree:add (f.ack, buffer(offset, 1))
        offset = offset + 1

        -- [9] Cmd Set
        local cmdset = buffer(offset,1):uint()
        subtree:add (f.cmdset, buffer(offset, 1))
        offset = offset + 1

        -- [A] Cmd
        local cmd = buffer(offset,1):uint()
        local cmd_tree = subtree:add (f.cmd, buffer(offset, 1))
        set_valuestring(cmd, cmd_tree, DJI_P3_FLIGHT_CONTROL_UART_CMD_TYPE[cmdset])
        offset = offset + 1

        set_info(cmd, pinfo, DJI_P3_FLIGHT_CONTROL_UART_CMD_TYPE[cmdset])

        assert(offset == 11, "Offset shifted - dissector internal inconsistency")

        -- [B] Payload    
        if pkt_length > offset+2 then
            payload_tree = subtree:add(f.payload, buffer(offset, pkt_length - offset - 2))

            -- If we have a dissector for this kind of command, run it
            local dissector = nil
            local dissector_group = DJI_P3_FLIGHT_CONTROL_UART_DISSECT[cmdset]
            if dissector_group ~= nil then
                dissector = dissector_group[cmd]
            end
            if dissector ~= nil then
                dissector(pkt_length, buffer, pinfo, payload_tree)
            end

        end

    end

    -- CRC
    subtree:add_le(f.crc, buffer(pkt_length - 2, 2))
    offset = offset + 2
end



-- Top level battery dissector
local BATTERY_CMDS = {      [0x21] = 'Get Battery Type',
                                                [0x22] = 'Get Battery Status',
                                                [0x23] = 'DRM ?',
                                                [0x24] = 'DRM ?',
                                                [0x25] = 'Get Battery Warning Flags',
                                                [0x31] = 'Get Battery Settings',
                                                [0x34] = 'Unknown',
                                                [0x38] = 'Get Battery Barcode'  }


-- [1]  Length of Pkt 
f.batt_length = ProtoField.uint16 ("dji_p3.batt_length", "Length", base.HEX, nil, 0x3FF)
-- [2]  
f.batt_protocol_version = ProtoField.uint16 ("dji_p3.batt_protover", "Protocol Version", base.HEX, nil, 0xFC00)
-- [3] Cmd ID
f.batt_cmd = ProtoField.uint8('dji_p3.batt_cmd', 'Battery Cmd', base.HEX, BATTERY_CMDS)

f.batt_payload = ProtoField.bytes ("dji_p3.batt_payload", "Payload", base.NONE)

f.batt_crc = ProtoField.uint8 ("dji_p3.batt_crc", "CRC", base.HEX)

-- Battery Info 
f.batt_total_capacity = ProtoField.uint16 ("dji_p3.batt_total_capacity", "Total Cap", base.DEC)
f.batt_discharge_count = ProtoField.uint16 ("dji_p3.batt_discharge_count", "Discharge Count", base.DEC)
f.batt_nominal_capacity = ProtoField.uint16 ("dji_p3.batt_nominal_capacity", "Nominal Cap", base.DEC)
f.batt_nominal_voltage = ProtoField.uint16 ("dji_p3.batt_nominal_voltage", "Nominal V", base.DEC)
f.batt_battery_spec = ProtoField.uint16 ("dji_p3.batt_battery_spec", "Battery Spec", base.DEC)
f.batt_mfr_date = ProtoField.string ("dji_p3.batt_mfr_date", "Mfr Date")
f.batt_serial_number = ProtoField.uint16 ("dji_p3.batt_serial_number", "Serial Number", base.HEX)
f.batt_name = ProtoField.string("dji_p3.batt_name", "Name")
f.batt_unk1 = ProtoField.uint16 ("dji_p3.batt_unknown1", "Unknown", base.HEX)
f.batt_unk2 = ProtoField.uint16 ("dji_p3.batt_unknown2", "Unknown", base.HEX)
f.batt_fw_version = ProtoField.string ("dji_p3.batt_fw_version", "FW Version", base.ASCII)
f.batt_life = ProtoField.uint16 ("dji_p3.batt_life", "Battery Life", base.DEC)

-- Battery Status
f.batt_temp = ProtoField.uint16 ("dji_p3.batt_temp", "Temp", base.DEC)
f.batt_total_v = ProtoField.uint16 ("dji_p3.batt_total_v", "Total mV", base.DEC)
f.batt_current = ProtoField.int32 ("dji_p3.batt_current", "Current", base.DEC)
f.batt_ave_current = ProtoField.int32 ("dji_p3.batt_ave_current", "Average Current", base.DEC)
f.batt_state_of_charge = ProtoField.uint16 ("dji_p3.batt_charge", "Charge (%)", base.DEC)
f.batt_cell_v = ProtoField.uint16 ("dji_p3.batt_cell_v", "Cell mV", base.DEC)
f.batt_cell_eol = ProtoField.uint16 ("dji_p3.batt_cell_eol", "EOL", base.HEX)
f.batt_power_status = ProtoField.string("dji_p3.batt_status", "Power Status")

--Battery barcode
f.batt_barcode = ProtoField.bytes("dji_p3.batt_barcode", "Barcode", base.SPACE)

local function battery_barcode_dissector(batt_length, buffer, pinfo, subtree)
    local offset = 5
    if batt_length ~= 14 then
        subtree:add(f.batt_barcode, buffer(offset, (batt_length -6)))

    end
end

local function battery_status_dissector(batt_length, buffer, pinfo, subtree)
    local offset = 5
--    local cell 
    if batt_length ~= 14 then
        subtree:add_le (f.batt_temp, buffer(offset, 2))
        offset = offset + 2
        subtree:add_le (f.batt_total_v, buffer(offset, 2))
        offset = offset + 2
        subtree:add_le (f.batt_current, buffer(offset, 2))
        offset = offset + 4
        subtree:add_le (f.batt_ave_current, buffer(offset, 2))
        offset = offset + 4
        subtree:add_le (f.batt_state_of_charge, buffer(offset, 2))
        offset = offset + 2

        for cell = 1, 5 do
            subtree:add_le (f.batt_cell_v, buffer(offset, 2))
            offset = offset + 2
        end
        
        subtree:add_le (f.batt_cell_eol, buffer(offset, 2))
        offset = offset + 2

        local pstatus = buffer(offset,1):uint()
        if pstatus == 0x00 then
            subtree:add(f.batt_power_status, "On")
        elseif pstatus == 0xFF then
            subtree:add(f.batt_power_status, "Powering Off")
        else
            subtree:add(f.batt_power_status, "Unknown")
        end
        
    end

end

local function battery_type_dissector(batt_length, buffer, pinfo, subtree)
    local offset = 5

    if batt_length ~= 14 then
        subtree:add_le (f.batt_total_capacity, buffer(offset, 2))
        offset = offset + 2
        subtree:add_le (f.batt_discharge_count, buffer(offset, 2))
        offset = offset + 2
        subtree:add_le (f.batt_nominal_capacity, buffer(offset, 2))
        offset = offset + 2
        subtree:add_le (f.batt_nominal_voltage, buffer(offset, 2))
        offset = offset + 2
        subtree:add_le (f.batt_battery_spec, buffer(offset, 2))
        offset = offset + 2

        local md = buffer(offset, 2):le_uint()
        local year = bit32.arshift(md,9) + 1980
        local month = bit32.band(bit32.arshift(md,5), 0x0F)
        local day = bit32.band(md, 0x01F)
        local date = string.format("%02d/%02d/%04d", day, month, year)
        subtree:add(f.batt_mfr_date, date)
        offset = offset + 2

        subtree:add_le (f.batt_serial_number, buffer(offset, 2))
        offset = offset + 2

        subtree:add(f.batt_name, buffer(offset, 15))
        offset = offset + 15

        subtree:add_le (f.batt_unk1, buffer(offset, 2))
        offset = offset + 2

        subtree:add_le (f.batt_unk2, buffer(offset, 2))
        offset = offset + 2
        
        local version = string.format("%02d.%02d.%02d.%02d", buffer(offset,1):uint(), buffer(offset+1,1):uint(), buffer(offset+2,1):uint(), buffer(offset+3,1):uint())
        subtree:add(f.batt_fw_version, version)
        offset = offset + 4

        subtree:add_le (f.batt_life, buffer(offset, 2))
        offset = offset + 2

    end
end

local function battery_dissector(buffer, pinfo, subtree)
    local offset = 1

    local batt_length = buffer(offset,2):le_uint()
    -- bit32 lib requires LUA 5.2
    batt_length = bit32.band(batt_length,  0x03FF)
    
    subtree:add_le (f.batt_length, buffer(offset, 2))
    subtree:add_le (f.batt_protocol_version, buffer(offset, 2))
    offset = offset + 2

    batt_cmd = buffer(offset, 1):uint()
    subtree:add (f.batt_cmd, buffer(offset, 1))
    offset = offset + 1

    if batt_length > 5 then
        payload_tree = subtree:add(f.batt_payload, buffer(4, batt_length - 5))

        if batt_cmd == 0x21 then
            battery_type_dissector(batt_length, buffer, pinfo, payload_tree)
        elseif batt_cmd == 0x22 then
            battery_status_dissector(batt_length, buffer, pinfo, payload_tree)

        elseif batt_cmd == 0x38 then
            battery_barcode_dissector(batt_length, buffer, pinfo, payload_tree)
        else

        end

    end 

    subtree:add(f.batt_crc, buffer(batt_length - 1, 1))
end

-- The protocol dissector itself
function DJI_P3_PROTO.dissector (buffer, pinfo, tree)
    local subtree = tree:add (DJI_P3_PROTO, buffer())

    -- The Pkt start byte (0x55 or 0xAB determines the pkt type)
    local offset = 0

    local pkt_type = buffer(offset,1):uint()
    subtree:add (f.delimiter, buffer(offset, 1))
    offset = offset + 1

    if pkt_type == 0xAB then
        battery_dissector(buffer, pinfo, subtree)
    else
        main_dissector(buffer, pinfo, subtree)
    end
    
end

-- A initialization routine
local packet_counter

function DJI_P3_PROTO.init ()
    packet_counter = 0
end

