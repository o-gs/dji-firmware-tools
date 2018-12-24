-- Create the aggeregate dissector
DJI_MAVIC_PROTO = Proto ("dji_mavic", "DJI_MAVIC", "Dji Mavic protocols aggregate")

local f = DJI_MAVIC_PROTO.fields

-- [0]  Start of Pkt, always 0x55
f.delimiter = ProtoField.uint8 ("dji_mavic.delimiter", "Delimiter", base.HEX)

-- The protocol dissector itself
function DJI_MAVIC_PROTO.dissector (buffer, pinfo, tree)

    local subtree = tree:add (DJI_MAVIC_PROTO, buffer())

    -- The Pkt start byte determines the pkt type
    local offset = 0

    local pkt_type = buffer(offset,1):uint()
    subtree:add (f.delimiter, buffer(offset, 1))
    offset = offset + 1

    if pkt_type == 0x55 then
        local pkt_protover = buffer(offset,2):le_uint()
        pkt_protover = bit32.rshift(bit32.band(pkt_protover, 0xFC00), 10)
        if pkt_protover == 0 then
            dji_mavic_flyrec_main_dissector(buffer, pinfo, subtree)
        else
            dji_dumlv1_main_dissector(buffer, pinfo, subtree)
        end
    end
    
end

-- A initialization routine
function DJI_MAVIC_PROTO.init ()
end

