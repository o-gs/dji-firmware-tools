-- Create a new dissector
DJI_P3_PROTO = Proto ("dji_p3", "DJI_P3","Dji Ph3 DUPC / UART protocol")

dofile('dji-p3-flightrec.lua')

dofile('dji-p3-fcuart.lua')

dofile('dji-p3-batuart.lua')

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
            local dissector = DJI_P3_FLIGHT_RECORD_DISSECT[etype]

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

        -- [A] Cmd (has variable valuestring)
        local cmd = buffer(offset,1):uint()
        local valuestring = DJI_P3_FLIGHT_CONTROL_UART_CMD_TYPE[cmdset] or {}
        subtree:add (f.cmd, buffer(offset, 1), cmd, string.format("%s: %s (0x%02X)", "Cmd", valuestring[cmd] or "Unknown", cmd))
        offset = offset + 1

        set_info(cmd, pinfo, DJI_P3_FLIGHT_CONTROL_UART_CMD_TYPE[cmdset])

        assert(offset == 11, "Offset shifted - dissector internal inconsistency")

        -- [B] Payload    
        if pkt_length > offset+2 then
            payload_tree = subtree:add(f.payload, buffer(offset, pkt_length - offset - 2))

            -- If we have a dissector for this kind of command, run it
            local dissector_group = DJI_P3_FLIGHT_CONTROL_UART_DISSECT[cmdset] or {}
            local dissector = dissector_group[cmd]

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

-- [1]  Length of Pkt 
f.batt_length = ProtoField.uint16 ("dji_p3.batt_length", "Length", base.HEX, nil, 0x3FF)
-- [2]  
f.batt_protocol_version = ProtoField.uint16 ("dji_p3.batt_protover", "Protocol Version", base.HEX, nil, 0xFC00)
-- [3] Cmd ID
f.batt_cmd = ProtoField.uint8('dji_p3.batt_cmd', 'Battery Cmd', base.HEX, DJI_P3_BATTERY_UART_CMDS)

f.batt_payload = ProtoField.bytes ("dji_p3.batt_payload", "Payload", base.NONE)

f.batt_crc = ProtoField.uint8 ("dji_p3.batt_crc", "CRC", base.HEX)

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

    if batt_length > offset+1 then
        payload_tree = subtree:add(f.batt_payload, buffer(offset, batt_length - offset - 1))

        -- If we have a dissector for this kind of command, run it
        local dissector = DJI_P3_BATTERY_UART_DISSECT[batt_cmd]

        if dissector ~= nil then
            dissector(batt_length, buffer, pinfo, payload_tree)
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
    elseif pkt_type == 0x55 then
        main_dissector(buffer, pinfo, subtree)
    end
    
end

-- A initialization routine
local packet_counter

function DJI_P3_PROTO.init ()
    packet_counter = 0
end

