-- Create a new dissector
DJI_P3_PROTO = Proto ("dji_p3", "DJI_P3","dji p3 UART protocol")

local CMD_SET = {   [0] = 'General', 
                    [1] = 'Special',
                    [2] = 'Camera',
                    [3] = 'Flight Controller',
                    [4] = 'Gimbal',
                    [5] = 'Central Board',
                    [6] = 'RC',
                    [7] = 'WiFi',
                    [8] = 'DM386',
                    [9] = 'HD Link',
                    [10] = 'Mono/Binocular',
                    [11] = 'Simulator',
                    [12] = 'ESC',
                    [13] = 'Battery',
                    [14] = 'Data Rec',
                    [15] = 'RTK',
                    [16] = 'Automation' }

local SRC_DEST = {  [0] = 'Invalid',
                    [1] = 'Camera',
                    [2] = 'Unknown',
                    [3] = 'Flight Controller',
                    [4] = 'Gimbal',
                    [5] = 'Central Board',
                    [6] = 'Unknown',
                    [7] = 'OSMO',
                    [8] = 'Unknown',
                    [9] = 'HW Button',
                    [10] = 'Unknown',
                    [11] = 'Battery',
                    [12] = 'ESC',
                    [13] = 'Unknown',
                    [14] = 'Unknown',
                    [15] = 'Unknown',
                    [16] = 'Unknown',
                    [17] = 'Unknown',
                    [18] = 'Unknown',
                    [19] = 'Unknown',
                    [20] = 'Unknown',
                    [21] = 'Unknown',
                    [22] = 'Unknown',
                    [23] = 'Unknown',
                    [24] = 'Unknown',
                    [25] = 'Unknown',
                    [26] = 'Unknown',
                    [27] = 'Unknown',
                    [28] = 'Unknown',
                    [29] = 'Unknown',
                    [30] = 'Unknown',
                    [31] = 'Unknown'   }

local ACK_POLL = {  [0]="RSP",[1]="CMD",[2]="CMD",[3]="????"}

local f = DJI_P3_PROTO.fields
-- [0]  Start of Pkt, always 0x55
f.delimiter = ProtoField.uint8 ("dji_p3.delimiter", "Delimiter", base.HEX, nil, 0xFF)
-- [1]  Length of Pkt 
f.length = ProtoField.uint8 ("dji_p3.length", "Length", base.HEX, nil, 0xFF)
-- [2]  Always 4
f.always4 = ProtoField.uint8 ("dji_p3.always4", "Always 4", base.HEX, nil, 0xFF)
-- [3]  Data Type
f.datatype = ProtoField.uint8 ("dji_p3.datatype", "Data Type", base.HEX, nil, 0xFF)
-- [4]  Sender
f.sender = ProtoField.uint8 ("dji_p3.sender", "Sender", base.DEC, SRC_DEST, 0x1F)
-- [5]  Receiver
f.receiver = ProtoField.uint8 ("dji_p3.receiver", "Receiver", base.DEC, SRC_DEST, 0x1F)
-- [6-7]  Sequence Ctr
f.seqctr = ProtoField.uint16 ("dji_p3.seqctr", "Seq Counter", base.DEC, nil, 0xFFFF)
-- [8] Ack (to be improved)
f.ack = ProtoField.uint8 ("dji_p3.ack", "Ack", base.HEX, ACK_POLL, 0x60)
-- [9] Cmd Set
f.cmdset = ProtoField.uint8('dji_p3.cmdset', 'Cmd Set', base.DEC, CMD_SET, 0xFF)
-- [A] Cmd
f.cmd = ProtoField.uint8('dji_p3.cmd', 'Cmd', base.HEX, nil, 0xFF)

-- [B] Payload (optional)
f.payload = ProtoField.bytes ("dji_p3.payload", "Payload", base.HEX)

-- [B+Payload] CRC
f.crc = ProtoField.uint16 ("dji_p3.crc", "CRC", base.HEX, nill, 0xFFFF)


-- The protocol dissector itself
function DJI_P3_PROTO.dissector (buffer, pinfo, tree)
    

    local subtree = tree:add (DJI_P3_PROTO, buffer())
    local offset = 0

    -- The Pkt start byte (0x55)
    subtree:add (f.delimiter, buffer(offset, 1))
    offset = offset + 1

    -- The Pkt length
    local pkt_length = buffer(offset,1):uint()
    subtree:add (f.length, buffer(offset, 1))
    offset = offset + 1

    -- Always 4 (protocol version maybe?)
    subtree:add (f.always4, buffer(offset, 1))
    offset = offset + 1

    -- Data Type
    subtree:add (f.datatype, buffer(offset, 1))
    offset = offset + 1

    -- Sender
    subtree:add (f.sender, buffer(offset, 1))
    offset = offset + 1

    -- Receiver
    subtree:add (f.receiver, buffer(offset, 1))
    offset = offset + 1

    -- Sequence Counter
    subtree:add_le (f.seqctr, buffer(offset, 2))
    offset = offset + 2

    -- Ack
    subtree:add (f.ack, buffer(offset, 1))
    offset = offset + 1

    -- Cmd Set
    subtree:add (f.cmdset, buffer(offset, 1))
    offset = offset + 1

    -- Cmd
    subtree:add (f.cmd, buffer(offset, 1))
    offset = offset + 1
    
    if pkt_length > 13 then
        subtree:add(f.payload, buffer(offset, pkt_length - 13))
    end

    -- CRC
    subtree:add_le(f.crc, buffer(pkt_length - 2, 2))
    offset = offset + 2
end

-- A initialization routine
local packet_counter
function DJI_P3_PROTO.init ()
packet_counter = 0
end
