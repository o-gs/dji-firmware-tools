-- Create a new dissector
DJI_SPARK_PROTO = Proto ("dji_spark", "DJI_SPARK","Dji Spark DUPC / UART protocol")

local SRC_DEST = {  [0] = 'Invalid',
                    [1] = 'Camera',
                    [2] = 'App',
                    [3] = 'Flight Controller',
                    [4] = 'Gimbal',
                    [5] = 'Center Board',
                    [6] = 'Remote Control',
                    [7] = 'Wi-Fi air side',
                    [8] = 'DM36x transcoder air side',
                    [9] = 'HD transmission MCU air side',
                    [10] = 'PC',
                    [11] = 'Battery',
                    [12] = 'ESC',
                    [13] = 'DM36x transcoder gnd side',
                    [14] = 'HD transmission MCU gnd side',
                    [15] = 'Serial-to-parallel (USB ctrl.) air side',
                    [16] = 'Serial-to-parallel (USB ctrl.) gnd side',
                    [17] = 'Monocular',
                    [18] = 'Binocular',
                    [19] = 'HD transmission FPGA air side',
                    [20] = 'HD transmission FPGA gnd side',
                    [21] = 'Simulator',
                    [22] = 'Base Station',
                    [23] = 'Airborne computing platform',
                    [24] = 'RC battery',
                    [25] = 'IMU',
                    [26] = 'GPS/RTK',
                    [27] = 'Wi-Fi gnd side',
                    [28] = 'Sig_cvt',
                    [29] = 'PMU',
                    [30] = 'Unknown',
                    [31] = 'Last'   }

local ENCRYPT_TYPE = {[0]='None',
                    [2]='SeqHash2' }

local ACK_POLL = {  [0]="RSP",[1]="CMD",[2]="CMD",[3]="????"}

local CMD_SET = {   [0] = 'General',
                    [1] = 'Special',
                    [2] = 'Camera',
                    [3] = 'Flight Control',
                    [4] = 'Gimbal',
                    [5] = 'Center Board',
                    [6] = 'Remote Control',
                    [7] = 'Wi-Fi',
                    [8] = 'DM36x',
                    [9] = 'HD Link',
                    [10] = 'Mono/Binocular',
                    [11] = 'Simulator',
                    [12] = 'ESC',
                    [13] = 'Battery',
                    [14] = 'Data Logger',
                    [15] = 'RTK',
                    [16] = 'Automation' }

-- Add Flight Record Packets dissectors
dofile('dji-spark-flightrec.lua')

local f = DJI_SPARK_PROTO.fields
-- [0]  Start of Pkt, always 0x55
f.delimiter = ProtoField.uint8 ("dji_spark.delimiter", "Delimiter", base.HEX)
-- [1]  Length of Pkt 
f.length = ProtoField.uint16 ("dji_spark.length", "Length", base.HEX, nil, 0x3FF)
-- [2]  Protocol version
f.protocol_version = ProtoField.uint16 ("dji_spark.protover", "Protocol Version", base.HEX, nil, 0xFC00)
-- [3]  Data Type
f.datatype = ProtoField.uint8 ("dji_spark.hdr_crc", "Header CRC", base.HEX)

-- Fields for ProtoVer = 0 (Flight Record)

-- [4-5]  Log Entry Type
f.rec_etype = ProtoField.uint16 ("dji_spark.rec_etype", "Log Entry Type", base.HEX, DJI_SPARK_FLIGHT_RECORD_ENTRY_TYPE)
-- [6-9]  Sequence Ctr
f.rec_seqctr = ProtoField.uint16 ("dji_spark.rec_seqctr", "Seq Counter", base.DEC)

-- Fields for ProtoVer = 1

-- [4]  Sender
f.sender = ProtoField.uint8 ("dji_spark.sender", "Sender", base.DEC, SRC_DEST, 0x1F)
-- [5]  Receiver
f.receiver = ProtoField.uint8 ("dji_spark.receiver", "Receiver", base.DEC, SRC_DEST, 0x1F)
-- [6-7]  Sequence Ctr
f.seqctr = ProtoField.uint16 ("dji_spark.seqctr", "Seq Counter", base.DEC)
-- [8] Encryption
f.encrypt = ProtoField.uint8 ("dji_spark.encrypt", "Encryption Type", base.DEC, ENCRYPT_TYPE, 0x0F)
-- [8] Ack (to be improved)
f.ack = ProtoField.uint8 ("dji_spark.ack", "Ack", base.HEX, ACK_POLL, 0x60)
-- [9] Cmd Set
f.cmdset = ProtoField.uint8('dji_spark.cmdset', 'Cmd Set', base.DEC, CMD_SET, 0xFF)

-- [A] Cmd
f.cmd       = ProtoField.uint8('dji_spark.cmd',      'Cmd',          base.HEX)

-- [B] Payload (optional)
f.payload = ProtoField.bytes ("dji_spark.payload", "Payload", base.SPACE)

-- [B+Payload] CRC
f.crc = ProtoField.uint16 ("dji_spark.crc", "CRC", base.HEX)

local function set_info(cmd, pinfo, decodes)
    pinfo.cols.info = ""
    if decodes[cmd] == nil then
        pinfo.cols.info:append(string.format("Unknown [0x%02X]", cmd))
    else
        pinfo.cols.info:append(decodes[cmd])
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

            dissector = DJI_SPARK_FLIGHT_RECORD_DISSECT[etype]

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

        set_info(buffer(offset,1):uint(), pinfo, CMD_CMD_SET[cmdset])

        -- [A] Cmd
        local cmd = buffer(offset,1):uint()
        subtree:add (f.cmd, buffer(offset, 1))
        offset = offset + 1

        assert(offset == 11, "Offset shifted - dissector internal inconsistency")

        -- [B] Payload    
        if pkt_length > offset+2 then
            payload_tree = subtree:add(f.payload, buffer(offset, pkt_length - offset - 2))

            -- If we have a dissector for this kind of command, run it
            local dissector = nil

            if dissector ~= nil then
                dissector(pkt_length, buffer, pinfo, payload_tree)
            end

        end

    end

    -- CRC
    subtree:add_le(f.crc, buffer(pkt_length - 2, 2))
    offset = offset + 2
end

-- The protocol dissector itself
function DJI_SPARK_PROTO.dissector (buffer, pinfo, tree)
    local subtree = tree:add (DJI_SPARK_PROTO, buffer())

    -- The Pkt start byte determines the pkt type
    local offset = 0

    local pkt_type = buffer(offset,1):uint()
    subtree:add (f.delimiter, buffer(offset, 1))
    offset = offset + 1

    main_dissector(buffer, pinfo, subtree)
    
end

-- A initialization routine
local packet_counter

function DJI_SPARK_PROTO.init ()
    packet_counter = 0
end

