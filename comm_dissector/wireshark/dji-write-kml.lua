-- dji-write-kml.lua
--------------------------------------------------------------------------------
--[[
    This is a Wireshark Lua-based KML file exporter for DJI packets.
--]]
--------------------------------------------------------------------------------

local wireshark_name = "Wireshark"
if not GUI_ENABLED then
    wireshark_name = "Tshark"
end

-- verify Wireshark is new enough
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 1 and ((tonumber(minor) <= 10) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
        error(  "Sorry, but your " .. wireshark_name .. " version (" .. get_version() .. ") is too old for this script!\n" ..
                "This script needs " .. wireshark_name .. "version 1.11.3 or higher.\n" )
end

-- verify we have the FileHandler class in wireshark
assert(register_menu, wireshark_name .. " does not have the register_menu func!")

-- Default settings to be stored within private_table
local default_settings =
{
    packets = {},
    path_type       = 0,
}

----------------------------------------
-- in Lua, we have access to encapsulation types in the 'wtap_encaps' table,
-- but those numbers don't actually necessarily match the numbers in pcap files
-- for the encapsulation type. We'll use this table to map selected encaps;
-- these are taken from wiretap/pcap-common.c
local pcap2wtap = {
    [0]   = wtap_encaps.NULL,
    [1]   = wtap_encaps.ETHERNET,
    [6]   = wtap_encaps.TOKEN_RING,
    [8]   = wtap_encaps.SLIP,
    [9]   = wtap_encaps.PPP,
    [101] = wtap_encaps.RAW_IP,
    [105] = wtap_encaps.IEEE_802_11,
    [127] = wtap_encaps.IEEE_802_11_RADIOTAP,
    [140] = wtap_encaps.MTP2,
    [141] = wtap_encaps.MTP3,
    [143] = wtap_encaps.DOCSIS,
    [147] = wtap_encaps.USER0,
    [148] = wtap_encaps.USER1,
    [149] = wtap_encaps.USER2,
    [150] = wtap_encaps.USER3,
    [151] = wtap_encaps.USER4,
    [152] = wtap_encaps.USER5,
    [153] = wtap_encaps.USER6,
    [154] = wtap_encaps.USER7,
    [155] = wtap_encaps.USER8,
    [156] = wtap_encaps.USER9,
    [157] = wtap_encaps.USER10,
    [158] = wtap_encaps.USER11,
    [159] = wtap_encaps.USER12,
    [160] = wtap_encaps.USER13,
    [161] = wtap_encaps.USER14,
    [162] = wtap_encaps.USER15,
    [186] = wtap_encaps.USB,
    [187] = wtap_encaps.BLUETOOTH_H4,
    [189] = wtap_encaps.USB_LINUX,
    [195] = wtap_encaps.IEEE802_15_4,
}

-- Makes a copy of the default settings per file
local function new_settings()
    debug("creating new file_settings")
    local file_settings = {}
    for k,v in pairs(default_settings) do
        file_settings[k] = v
    end
    return file_settings
end

-- A simple function for backward mapping of the pcap2wtap array.
local function wtap2pcap(encap)
    for k,v in pairs(pcap2wtap) do
        if v == encap then
            return k
        end
    end
    return 0
end

-- Create our ExportCaptureInfo class which will behave like CaptureInfo
local ExportCaptureInfo = {}
ExportCaptureInfo.__index = ExportCaptureInfo

function ExportCaptureInfo:create()
   local acnt = {}             -- our new object
   setmetatable(acnt,ExportCaptureInfo)  -- make ExportCaptureInfo handle lookup
   -- initialize attribs
   acnt.user_app = wireshark_name
   acnt.private_table = {}
   return acnt
end

-- Go though packets and interpolate missing values
local function process_packets(packets, til_end)
    local start_pkt = {
        typ = 0,
    }
    for key,pkt in pairs(packets) do
        --pkt.lon
        --pkt.lat
        --pkt.alt
    end
end

--------------------------------------------------------------------------------
-- high-level file writer handling functions for Wireshark to use
--------------------------------------------------------------------------------

-- file encaps we can handle writing
local canwrite = {
    [ wtap_encaps.USER0 ]       = true,
    [ wtap_encaps.USER1 ]       = true,
    [ wtap_encaps.USER2 ]       = true,
    [ wtap_encaps.USER3 ]       = true,
    [ wtap_encaps.USER4 ]       = true,
    [ wtap_encaps.USER5 ]       = true,
    [ wtap_encaps.USER6 ]       = true,
    [ wtap_encaps.USER7 ]       = true,
    [ wtap_encaps.USER8 ]       = true,
    [ wtap_encaps.USER9 ]       = true,
    [ wtap_encaps.USER10 ]       = true,
    [ wtap_encaps.USER11 ]       = true,
    [ wtap_encaps.USER12 ]       = true,
    [ wtap_encaps.USER13 ]       = true,
    [ wtap_encaps.USER14 ]       = true,
    [ wtap_encaps.USER15 ]       = true,
    -- etc., etc.
}

-- we can't reuse the variables we used in the reader, because this script might be used to both
-- open a file for reading and write it out, at the same time, so we cerate another file_settings
-- instance.
local function create_writer_file_settings()
    debug("create_writer_file_settings called")

    local file_settings = new_settings()

    return file_settings
end

----------------------------------------
-- The can_write_encap() function is called by Wireshark when it wants to write out a file,
-- and needs to see if this file writer can handle the packet types in the window.
-- We need to return true if we can handle it, else false
local function can_write_encap(encap)
    debug("can_write_encap() called with encap=" .. encap)
    return canwrite[encap] or false
end

local function write_open(fh, capture)
    debug("write_open() called")

    local file_settings = create_writer_file_settings()

    -- write out file header
    local hdr = [[<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>Dji Flight Log - FILENAME</name>
    <open>1</open>
    <description>Path configuration: TODO</description>
    <Style id="purpleLineGreenPoly">
      <LineStyle>
        <color>7fff00ff</color>
        <width>4</width>
      </LineStyle>
      <PolyStyle>
        <color>7f00ff00</color>
      </PolyStyle>
    </Style>
    <Style id="yellowLineGreenPoly">
      <LineStyle>
        <color>7f00ffff</color>
        <width>4</width>
      </LineStyle>
      <PolyStyle>
        <color>7f00ff00</color>
      </PolyStyle>
    </Style>
]]
    if not hdr then
        info("write_open: error generating file header")
        return false
    end

    debug("write_open generating:" .. Struct.tohex(hdr))

    if not fh:write(hdr) then
        info("write_open: error writing file header to file")
        return false
    end

    -- save settings
    capture.private_table = file_settings

    return true
end

-- declare some field extractors
local dji_p3_rec_etype = Field.new("dji_p3.rec_etype")
local dji_p3_rec_osd_general_longtitude = Field.new("dji_p3.rec_osd_general_longtitude")
local dji_p3_rec_osd_general_latitude = Field.new("dji_p3.rec_osd_general_latitude")
local dji_p3_rec_osd_general_relative_height = Field.new("dji_p3.rec_osd_general_relative_height")

local function write(fh, capture, pinfo)
    debug("write() called")

    -- get file settings
    local file_settings = capture.private_table
    if not file_settings then
        info("write() failed to get private table file settings")
        return false
    end

    --local tvbrange = fldinfo.range
    --fh:write( tobinary( tostring( tvbrange:bytes() ) ) )
    --fh:flush()

    -- Get fields from new packet
    local curr_pkt = {
        typ = 0,
    }

    local pkt_rec_etype = { dji_p3_rec_etype() }

    if (pkt_rec_etype[1].value == 0x000c) then
        local new_air_longtitude = { dji_p3_rec_osd_general_longtitude() }
        local new_air_latitude = { dji_p3_rec_osd_general_latitude() }
        local new_air_rel_altitude = { dji_p3_rec_osd_general_relative_height() }

        curr_pkt.lon = (new_air_longtitude[1].value * 180.0 / math.pi)
        curr_pkt.lat = (new_air_latitude[1].value * 180.0 / math.pi)
        curr_pkt.alt = new_air_rel_altitude[1].value * 0.1
        curr_pkt.typ = 1
    end

    if (curr_pkt.typ ~= 0) then
        table.insert(file_settings.packets, curr_pkt)
    end

    --warn("aaa" .. tostring(new_air_longtitude))
    -- first get times
    --local nstime = fldinfo.time

    -- pcap format is in usecs, but wireshark's internal is nsecs
    --local nsecs = nstime.nsecs

    return true
end

local function write_close(fh, capture)
    debug("write_close() called")

    -- get file settings
    local file_settings = capture.private_table
    if not file_settings then
        info("write() failed to get private table file settings")
        return false
    end

    process_packets(file_settings.packets, true)

    local pathblk_head = [[    <Folder>
      <name>Paths</name>
      <visibility>0</visibility>
      <description>Flight path.</description>
      <Placemark>
        <name>Absolute Extruded</name>
        <visibility>0</visibility>
        <description>Transparent green wall with yellow outlines</description>
        <LookAt>
          <longitude>-112.2643334742529</longitude>
          <latitude>36.08563154742419</latitude>
          <altitude>0</altitude>
          <heading>-125.7518698668815</heading>
          <tilt>44.61038665812578</tilt>
          <range>4451.842204068102</range>
        </LookAt>
        <styleUrl>#yellowLineGreenPoly</styleUrl>
        <LineString>
          <extrude>1</extrude>
          <tessellate>1</tessellate>
          <!-- <altitudeMode>absolute</altitudeMode> -->
          <altitudeMode>relativeToGround</altitudeMode>
          <coordinates>
]]
    if not fh:write(pathblk_head) then
        info("write: error writing path block head to file")
        return false
    end

    for key,pkt in pairs(file_settings.packets) do
        local pathblk_line = "            " .. pkt.lon .. "," .. pkt.lat .. "," .. pkt.alt .. "\n"
        if not fh:write(pathblk_line) then
            info("write: error writing path block line to file")
            return false
        end
    end

    local pathblk_tail = [[          </coordinates>
        </LineString>
      </Placemark>
    </Folder>
]]
    if not fh:write(pathblk_tail) then
        info("write: error writing path block tail to file")
        return false
    end

    local footer = [[  </Document>
</kml>
]]
    if not fh:write(footer) then
        info("write: error writing file footer")
        return false
    end

    debug("Good night, and good luck")
    return true
end

-- do a payload dump when prompted by the user
local function init_payload_dump(filename, path_style)

    local packet_count = 0
    -- Osd General
    local filter = "dji_p3.rec_etype == 0x000c"
    local tap = Listener.new(nil,filter)
    local fh = assert(io.open(filename, "w+"))

    capture = ExportCaptureInfo:create()
    write_open(fh, capture)
    
    -- this function is going to be called once each time our filter matches
    function tap.packet(pinfo,tvb)

        if ( true ) then
            packet_count = packet_count + 1

            -- there can be multiple packets in a given frame, so get them all into a table
            --local contents = { dji_p3_pkt() }

            --for i,fldinfo in ipairs(contents) do
                write(fh, capture, pinfo)
            --end
        end
    end
    
    -- re-inspect all the packets that are in the current capture, thereby
    -- triggering the above tap.packet function
    retap_packets()

    -- prepare for cleanup
    write_close(fh, capture)
    -- cleanup
    fh:close()
    tap:remove()
    info("Dumped packets: " .. packet_count )
end

-- show this dialog when the user select "Export" from the Tools menu
local function begin_dialog_menu()    
    new_dialog("KML path of DJI drone flight writer", init_payload_dump,
      "Output file\n(type KML file name)",
      "Path style\n(flat, line, wall)")
end

register_menu("Export KML from DJI drone flight", begin_dialog_menu, MENU_TOOLS_UNSORTED)

debug("Tools Menu Handler registered")
