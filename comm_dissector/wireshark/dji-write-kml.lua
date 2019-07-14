-- dji-write-kml.lua
--------------------------------------------------------------------------------
--[[
    This is a Wireshark Lua-based KML file exporter for DJI packets.

    To enable debug output in LUA console, set `console.log.level: 252` in
    Wireshark `preferences` file.
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

-- Enums
local TYP_NULL, -- no packet
    TYP_AIR_POS_GPS, -- raw position data from GPS, with absolute altitude included
    TYP_AIR_POS_ACC, -- position data extended and averaged from all data sources
    TYP_AIR_ROTAT, -- aircraft rotation angles
    TYP_RC_STAT, -- Remote Controller status
    TYP_FLYC_STAT, -- Flight Controller status
    TYP_MOTOR_STAT -- ESCs and motors status
       = 0, 1, 2, 3, 4, 5, 6

local CONDTN_NONE, -- unconditional
    CONDTN_MOTOR_ON, -- show only when motors on
    CONDTN_MOTOR_OFF -- show only when motors not running
       = 0, 1, 2

-- Default settings to be stored within private_table
local default_settings =
{
    packets = {},
    lookat = { lon = 0.0, lat = 0.0, rel_alt = 0.0, abs_alt = 0.0, rng = 1.0, },
    path_type = 0,
    min_dist_shift = 0.012,
    ground_altitude = nil,
    model_detail_lv = 2,
    air_pos_pkt_typ = TYP_AIR_POS_ACC,
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

-- Multiply two matrices; m1 columns must be equal to m2 rows
-- e.g. #m1[1] == #m2
function matrix_mul( m1, m2 )
	-- multiply rows with columns
	local mtx = {}
	for i = 1,#m1 do
		mtx[i] = {}
		for j = 1,#m2[1] do
			local num = m1[i][1] * m2[1][j]
			for n = 2,#m1[1] do
				num = num + m1[i][n] * m2[n][j]
			end
			mtx[i][j] = num
		end
	end
	return mtx
end

-- Makes a copy of the default settings per file
local function new_settings()
    print("debug: creating new file_settings")
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
    acnt.user_options = {}
    return acnt
end

-- Shifts given WGS84+Z coordinates by (x,y,z) shift given in meters
local function geom_wgs84_coords_shift_xyz(ocoord, icoord, shift_meters_x, shift_meters_y, shift_meters_z)
    -- one degree of longitude on the Earth surface equals 111320 meters (at the equator)
    local angular_lat = math.rad(icoord.lat)
    local delta_longitude = shift_meters_x / (111320.0 * math.cos(angular_lat))
    -- one degree of latitude on the Earth surface equals 110540 meters
    local delta_latitude = shift_meters_y / 110540.0
    ocoord.lon = icoord.lon + delta_longitude
    ocoord.lat = icoord.lat + delta_latitude
    ocoord.abs_alt = icoord.abs_alt + shift_meters_z
    ocoord.rel_alt = icoord.rel_alt + shift_meters_z
end

local function geom_wgs84_coords_distance_meters(icoord1, icoord2)
    local R = 6378137.0 -- Radius of earth in meters
    local lon_dt = math.rad(icoord2.lon) - math.rad(icoord1.lon)
    local lat_dt = math.rad(icoord2.lat) - math.rad(icoord1.lat)

    local a = math.sin(lat_dt/2) * math.sin(lat_dt/2) +
               math.cos(math.rad(icoord1.lat)) * math.cos(math.rad(icoord2.lat)) *
               math.sin(lon_dt/2) * math.sin(lon_dt/2)

    local c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return (R * c)
end

-- Creates rotation matrix from Euler angles in order: yaw,pitch,roll
local function geom_make_transform_matrix_from_yaw_pitch_roll(rot_vec)
    local y = rot_vec.yaw
    local p = rot_vec.pitch
    local r = rot_vec.roll
    -- Matrix created by multiplying yaw x pitch x roll single rotation matrices
    local Row1 = { math.cos(y)*math.cos(p), math.cos(y)*math.sin(p)*math.sin(r) - math.sin(y)*math.cos(r), math.cos(y)*math.sin(p)*math.cos(r) + math.sin(y)*math.sin(r) }
    local Row2 = { math.sin(y)*math.cos(p), math.sin(y)*math.sin(p)*math.sin(r) + math.cos(y)*math.cos(r), math.sin(y)*math.sin(p)*math.cos(r) - math.cos(y)*math.sin(r) }
    local Row3 = { -math.sin(p), math.cos(p)*math.sin(r), math.cos(p)*math.cos(r) }
    return {Row1, Row2, Row3}
end

-- Creates Euler angles with given order from a rotation matrix
local function geom_make_euler_from_transform_matrix(mx, rorder)
    local thetaX, thetaY, thetaZ = nil, nil, nil
    local thetaX0, thetaY0, thetaZ0 = nil, nil, nil
    local thetaX1, thetaY1, thetaZ1 = nil, nil, nil

    if (rorder == "XYZ") then

        thetaY = math.asin(mx[1][3])
        if (0.99999 > math.abs(mx[1][3])) then
            thetaX = math.atan2(-mx[2][3], mx[3][3])
            thetaZ = math.atan2(-mx[1][2], mx[1][1])
        else
            thetaX = math.atan2(mx[3][2], mx[2][2])
            thetaZ = 0
        end

    elseif (rorder == "YXZ") then

        thetaX = math.asin(-mx[2][3])
        if (0.99999 > math.abs(mx[2][3])) then
            thetaY = math.atan2(mx[1][3], mx[3][3])
            thetaZ = math.atan2(mx[2][1], mx[2][2])
        else
            thetaY = math.atan2(-mx[3][1], mx[1][1])
            thetaZ = 0
        end

    elseif (rorder == "ZXY") then

        thetaX = math.asin(mx[3][2])
        if (0.99999 > math.abs(mx[3][2])) then
            thetaY = math.atan2(-mx[3][1], mx[3][3])
            thetaZ = math.atan2(-mx[1][2], mx[2][2])
        else
            thetaY = 0
            thetaZ = math.atan2(mx[2][1], mx[1][1])
        end

    elseif (rorder == "ZYX") then

        thetaY = math.asin(-mx[3][1])
        if (0.99999 > math.abs(mx[3][1])) then
            thetaX = math.atan2(mx[3][2], mx[3][3])
            thetaZ = math.atan2(mx[2][1], mx[1][1])
        else
            thetaX = 0
            thetaZ = math.atan2(-mx[1][2], mx[2][2])
        end

    elseif (rorder == "YZX") then

        thetaZ = math.asin(mx[2][1])
        if (0.99999 > math.abs(mx[2][1])) then
            thetaX = math.atan2(-mx[2][3], mx[2][2])
            thetaY = math.atan2(-mx[3][1], mx[1][1])
        else
            thetaX = 0
            thetaY = math.atan2(mx[1][3], mx[3][3])
        end

    elseif (rorder == "XZY") then

        thetaZ = math.asin(-mx[1][2])
        if (0.99999 > math.abs(mx[1][2])) then
            thetaX = math.atan2(mx[3][2], mx[2][2])
            thetaY = math.atan2(mx[1][3], mx[1][1])
        else
            thetaX = math.atan2(-mx[2][3], mx[3][3])
            thetaY = 0
        end

    elseif (rorder == "XYX") then

        if (0.99999 < mx[1][1]) then
            -- Not a unique solution: thetaX1 + thetaX0 = atan2(-mx[2][3] , mx[2][2] )
            thetaY = 0
            thetaX0 = math.atan2(-mx[2][3], mx[2][2])
            thetaX1 = 0
        elseif (-0.99999 > mx[1][1]) then
            -- Not a unique solution: thetaX1 - thetaX0 = atan2(-mx[2][3] , mx[2][2] )
            thetaY = math.pi
            thetaX0 = -math.atan2(-mx[2][3], mx[2][2])
            thetaX1 = 0
        else
            thetaY = math.acos(mx[1][1])
            thetaX0 = math.atan2(mx[2][1], -mx[3][1])
            thetaX1 = math.atan2(mx[1][2], mx[1][3])
        end

    elseif (rorder == "XZX") then

        if (0.99999 < mx[1][1]) then
            -- Not a unique solution: thetaX1 + thetaX0 = math.atan2(mx[3][2], mx[3][3])
            thetaZ = 0
            thetaX0 = math.atan2(mx[3][2], mx[3][3])
            thetaX1 = 0
        elseif (-0.99999 > mx[1][1]) then
            -- Not a unique solution: thetaX1 - thetaX0 = math.atan2(mx[3][2], mx[3][3])
            thetaZ = math.pi
            thetaX0 = -math.atan2(mx[3][2], mx[3][3])
            thetaX1 = 0
        else
            thetaZ = math.acos(mx[1][1])
            thetaX0 = math.atan2(mx[3][1], mx[2][1])
            thetaX1 = math.atan2(mx[1][3], -mx[1][2])
        end

    elseif (rorder == "YXY") then

        if (0.99999 < mx[2][2]) then
            -- Not a unique solution: thetaY1 + thetaY0 = math.atan2(mx[1][3], mx[1][1])
            thetaX = 0
            thetaY0 = math.atan2(mx[1][3], mx[1][1])
            thetaY1 = 0
        elseif (-0.99999 > mx[2][2]) then
            -- Not a unique solution: thetaY1 - thetaY0 = math.atan2(mx[1][3], mx[1][1])
            thetaX = math.pi
            thetaY0 = -math.atan2(mx[1][3], mx[1][1])
            thetaY1 = 0
        else
            thetaX = math.acos(mx[2][2])
            thetaY0 = math.atan2(mx[1][2], mx[3][2])
            thetaY1 = math.atan2(mx[2][1], -mx[2][3])
        end

    elseif (rorder == "YZY") then

        if (0.99999 < mx[2][2]) then
            -- Not a unique solution: thetaY1 + thetaY0 = atan2(-mx[3][1], mx[3][3])
            thetaZ = 0
            thetaY0 = math.atan2(-mx[3][1], mx[3][3])
            thetaY1 = 0
        elseif (-0.99999 > mx[2][2]) then
            -- Not a unique solution: thetaY1 - thetaY0 = atan2(-mx[3][1], mx[3][3])
            thetaZ = math.pi
            thetaY0 = -math.atan2(-mx[3][1], mx[3][3])
            thetaY1 = 0
        else
            thetaZ = math.acos(mx[2][2])
            thetaY0 = math.atan2(mx[3][2], -mx[1][2])
            thetaY1 = math.atan2(mx[2][3], mx[2][1])
        end

    elseif (rorder == "ZXZ") then

        if (0.99999 < mx[3][3]) then
            -- Not a unique solution: thetaZ1 + thetaZ0 = atan2(-mx[1][2], mx[1][1])
            thetaX = 0
            thetaZ0 = atan2(-mx[1][2], mx[1][1])
            thetaZ1 = 0
        elseif (-0.99999 > mx[3][3]) then
            -- Not a unique solution: thetaZ1 - thetaZ0 = atan2(-mx[1][2], mx[1][1])
            thetaX = math.pi
            thetaZ0 = -atan2(-mx[1][2], mx[1][1])
            thetaZ1 = 0
        else
            thetaX = math.acos(mx[3][3] )
            thetaZ0 = math.atan2(mx[1][3], -mx[2][3])
            thetaZ1 = math.atan2(mx[3][1], mx[3][2])
        end

    elseif (rorder == "ZYZ") then

        if (0.99999 < mx[3][3]) then
            -- Not a unique solution: thetaZ1 + thetaZ0 = math.atan2(mx[2][1], mx[2][2])
            thetaY = 0
            thetaZ0 = math.atan2(mx[2][1], mx[2][2])
            thetaZ1 = 0
        elseif (-0.99999 > mx[3][3]) then
            -- Not a unique solution: thetaZ1 - thetaZ0 = math.atan2(mx[2][1], mx[2][2])
            thetaY = math.pi
            thetaZ0 = -math.atan2(mx[2][1], mx[2][2])
            thetaZ1 = 0
        else
            thetaY = math.acos(mx[3][3] )
            thetaZ0 = math.atan2(mx[2][3], mx[1][3])
            thetaZ1 = math.atan2(mx[3][2], -mx[3][1])
        end

    else
        thetaZ = 0
        thetaY = 0
        thetaX = 0
    end

    return {x=thetaX, y=thetaY, z=thetaZ, x0=thetaX0, y0=thetaY0, z0=thetaZ0, x1=thetaX1, y1=thetaY1, z1=thetaZ1}
end

-- Creates Euler angles with order: yaw,pitch,roll from a rotation matrix
local function geom_make_yaw_pitch_roll_from_transform_matrix(mx)
    rot = geom_make_euler_from_transform_matrix(mx, "ZYX")
    rot.yaw = rot.z
    rot.pitch = rot.y
    rot.roll = rot.x
    return rot
end

-- Adjusts rotation angles so that crappy Google Earth rotation implementation won't glitch
local function geom_google_earth_incompetent_rotation_fix(model_info, rot)
    -- Google Earth does crazy things if angle is around 90/-90, and even crazier at exact value
    if (math.abs(model_info.roll + rot.roll - math.rad(90)) < math.rad(3.7)) then
          if (model_info.roll + rot.roll - math.rad(90)) > 0 then
              rot.roll = math.rad(90.0001) - model_info.roll
          else
              rot.roll = math.rad(89.9999) - model_info.roll
          end
    end
    if (math.abs(model_info.roll + rot.roll + math.rad(90)) < math.rad(3.7)) then
          if (model_info.roll + rot.roll + math.rad(90)) < 0 then
              rot.roll = -math.rad(90.0001) - model_info.roll
          else
              rot.roll = -math.rad(89.9999) - model_info.roll
          end
    end
    return rot
end

-- Go though packets and interpolate missing values
local function process_packets(file_settings, packets, til_end)
    print("debug: process_packets() called")

    -- Timestamp precision increase
    -- Find groups with the same timestamp, and make it increasing miliseconds
    local last_pkt_pos = 0 -- Total number of packets - we will need it sometimes
    local start_tmstamp = -1 -- Position of the packet which starts the group being currently updated
    local count_tmstamp = 0 -- Amount of same timestamps in thr group
    for pos,pkt in pairs(packets) do
        if (pkt.tmstamp ~= nil) then
            local spkt = {}
            if (start_tmstamp >= 0) then
                spkt = packets[start_tmstamp]
            else
                spkt = {tmstamp=pkt.tmstamp-1.0}
            end
            -- When the timestamp has changed, go through all from last change, and make them increasing
            if (pkt.tmstamp > spkt.tmstamp) then
                if (start_tmstamp < 0) then
                    start_tmstamp = 0
                end
                local tmstamp_dt = pkt.tmstamp - spkt.tmstamp
                local count_cpkt = 1
                if (count_tmstamp > 1) then
                    for cpos = start_tmstamp+1, pos-1, 1 do
                        local cpkt = packets[cpos]
                        -- Only update packets which already have a timestamp set; other we will set in next pass
                        -- Since packets with timestamps are periodic, this should increase accuracy
                        if (cpkt.tmstamp ~= nil) then
                            cpkt.tmstamp = spkt.tmstamp + tmstamp_dt * count_cpkt / count_tmstamp
                            count_cpkt = count_cpkt+1
                        end
                    end
                end
                start_tmstamp = pos
                count_tmstamp = 0
            end
            count_tmstamp = count_tmstamp+1
        end
        last_pkt_pos = pos
    end
    -- For packets with same timestamps at end, make the spacing of 250ms
    if (start_tmstamp >= 0) and (last_pkt_pos > start_tmstamp+1) then
        if (count_tmstamp > 1) then
            local spkt = packets[start_tmstamp]
            local count_cpkt = 1
            for cpos = start_tmstamp+1, last_pkt_pos, 1 do
                local cpkt = packets[cpos]
                if (cpkt.tmstamp ~= nil) then
                    cpkt.tmstamp = spkt.tmstamp + 0.25 * count_cpkt
                    count_cpkt = count_cpkt+1
                end
            end
        end
    end
    -- Replace starting timestamps which are older that 12 hours than last timestamp - drone can't run that long
    -- This will remove any bad timestamps recorded before we get proper one from GPS
    if (start_tmstamp >= 0) then
        local spkt = packets[start_tmstamp]
        local limit_tmstamp = math.max(spkt.tmstamp - 12*60*60, 1.0)
        local min_tmstamp = spkt.tmstamp
        local count_cpkt = 1
        for cpos = start_tmstamp, 1, -1 do
            local cpkt = packets[cpos]
            if (cpkt.tmstamp ~= nil) then
                if (cpkt.tmstamp < limit_tmstamp) then
                    cpkt.tmstamp = min_tmstamp - 0.25 * count_cpkt
                    count_cpkt = count_cpkt+1
                else
                    min_tmstamp = cpkt.tmstamp
                    count_cpkt = 1
                end
            end
        end
    end

    -- Interpolate timestamp for entries without it
    local start_tmstamp = -1 -- Position of the packet which starts the group being currently updated
    for pos,pkt in pairs(packets) do
        if (pkt.tmstamp ~= nil) then
            local spkt = {}
            if (start_tmstamp >= 0) then
                spkt = packets[start_tmstamp]
            else
                spkt = {tmstamp=pkt.tmstamp-1.0}
                start_tmstamp = 0
            end
            local tmstamp_dt = pkt.tmstamp - spkt.tmstamp
            -- make sure we have enough milisecs to make each packet separated by no less than 2ms
            tmstamp_dt = math.max(tmstamp_dt, (pos - start_tmstamp) / 500)
            -- set timestamps in a rage of packets which don't have them
            for cpos = start_tmstamp+1, pos-1, 1 do
                local cpkt = packets[cpos]
                cpkt.tmstamp = spkt.tmstamp + tmstamp_dt * (cpos - start_tmstamp) / (pos - start_tmstamp)
            end
            start_tmstamp = pos
        end
    end
    -- For packets with same timestamps at end, make the spacing of 10ms
    if (start_tmstamp >= 0) and (last_pkt_pos > start_tmstamp+1) then
        if true then
            spkt = packets[start_tmstamp]
            for cpos = start_tmstamp+1, last_pkt_pos, 1 do
                local cpkt = packets[cpos]
                cpkt.tmstamp = spkt.tmstamp + 0.01 * (cpos - start_tmstamp)
            end
        end
    else
        --TODO support no timestamps situation
        error("No timestamps defined in the input packets. Aborting due to lack of time reference.")
    end

    -- Final updates for the timestamp - first and last packet must be on a full second
    if (last_pkt_pos > 3) then
        pkt = packets[1]
        pkt.tmstamp = math.floor(pkt.tmstamp)
        pkt = packets[last_pkt_pos]
        pkt.tmstamp = math.ceil(pkt.tmstamp)
    end

    -- Compute height above ground levels, by averaging all the measurements
    -- (difference between GPS altitude and baro altitude)
    if (file_settings.ground_altitude == nil) then
        local gnd_alt_sum = 0
        local gnd_alt_num = 0
        local curr_rel_alt = 0
        for pos,pkt in pairs(packets) do
            if (pkt.typ == TYP_AIR_POS_GPS) or (pkt.typ == TYP_AIR_POS_ACC) then
                if (pkt.rel_alt ~= nil) then
                    curr_rel_alt = pkt.rel_alt
                elseif (pkt.abs_alt ~= nil) then
                    gnd_alt_sum = gnd_alt_sum + (pkt.abs_alt - curr_rel_alt)
                    gnd_alt_num = gnd_alt_num + 1
                end
            end
        end
        average_gnd_alt = 0
        if (gnd_alt_num > 0) then
            -- Automatically compute altitude as 105% of average ground level
            file_settings.ground_altitude = (gnd_alt_sum / gnd_alt_num) * 1.05
        else
            file_settings.ground_altitude = 0.0
        end
        print("info: Ground height at start point computed: " .. file_settings.ground_altitude)
    end

    -- Compute missing relative heights (in abssolute-only packets) and absolute heights (in relative-only packets)
    local prev_rel_pkt = { rel_alt=0.0, tmstamp=1.0 }
    local start_abs_pos = -1
    for pos,pkt in pairs(packets) do
        if (pkt.typ == TYP_AIR_POS_GPS) or (pkt.typ == TYP_AIR_POS_ACC) then
            -- The packet has either only relative or only absolute altitude set
            if (pkt.rel_alt ~= nil) then
                -- if we've seen absolute packets before this one, update them
                if (start_abs_pos >= 0) then
                    -- We have two relative alts, and one or more absolute alt between; replace with linear change
                    for cpos = start_abs_pos, pos-1, 1 do
                        local cpkt = packets[cpos]
                        if (cpkt.typ == TYP_AIR_POS_GPS) or (cpkt.typ == TYP_AIR_POS_ACC) then
                            if (cpkt.rel_alt == nil) then
                                local tmstamp_dt1 = cpkt.tmstamp - prev_rel_pkt.tmstamp
                                local tmstamp_dt2 = pkt.tmstamp - cpkt.tmstamp
                                cpkt.rel_alt = (prev_rel_pkt.rel_alt * tmstamp_dt1 + pkt.rel_alt * tmstamp_dt2) / (tmstamp_dt1 + tmstamp_dt2)
                                -- absolute alt from GPS is inaccurate, but we will not mix
                                -- GPS and ACC coords in one path anyway, so set only if empty
                                if (cpkt.abs_alt == nil) then
                                    cpkt.abs_alt = cpkt.rel_alt + file_settings.ground_altitude
                                end
                            end
                        end
                    end
                    start_abs_pos = -1
                end
                pkt.abs_alt = pkt.rel_alt + file_settings.ground_altitude
                prev_rel_pkt = pkt
            elseif (pkt.abs_alt ~= nil) then
                -- store position of first absolute packet encoured
                if (start_abs_pos < 0) then
                    start_abs_pos = pos
                end
            else
                error("Impossible condition reached in relative alt computation")
            end
        end
    end
    -- If we have remaining absolute alt at end, set last known good relative there
    if (start_abs_pos >= 0) then
        for cpos = start_abs_pos, last_pkt_pos, 1 do
            local cpkt = packets[cpos]
            if (cpkt.typ == TYP_AIR_POS_GPS) or (cpkt.typ == TYP_AIR_POS_ACC) then
                if (cpkt.rel_alt == nil) then
                    cpkt.rel_alt = prev_rel_pkt.rel_alt
                    -- absolute alt from GPS is inaccurate, but we will not mix
                    -- GPS and ACC coords in one path anyway, so set only if empty
                    if (cpkt.abs_alt == nil) then
                        cpkt.abs_alt = cpkt.rel_alt + file_settings.ground_altitude
                    end
                else
                    error("Impossible condition reached in relative alt finisher")
                end
            end
        end
    end

    -- Now we can use timestamps as spacers for interpolating other params
    local start_air_pos = -1
    min_lon = 180.0
    max_lon = -180.0
    min_lat = 180.0
    max_lat = -180.0
    min_rel_alt = 999999999.0
    max_rel_alt = -999999999.0
    min_abs_alt = 999999999.0
    max_abs_alt = -999999999.0
    for pos,pkt in pairs(packets) do
        if (pkt.typ == TYP_AIR_POS_GPS) or (pkt.typ == TYP_AIR_POS_ACC) then
            if (pkt.lon ~= 0.0) or (pkt.lat ~= 0.0) then
                -- Add the value to limits
                if (pkt.lon < min_lon) then
                    min_lon = pkt.lon
                end
                if (pkt.lon > max_lon) then
                    max_lon = pkt.lon
                end
                if (pkt.lat < min_lat) then
                    min_lat = pkt.lat
                end
                if (pkt.lat > max_lat) then
                    max_lat = pkt.lat
                end
                if (pkt.rel_alt ~= nil) then
                    if (pkt.rel_alt < min_rel_alt) then
                        min_rel_alt = pkt.rel_alt
                    end
                    if (pkt.rel_alt > max_rel_alt) then
                        max_rel_alt = pkt.rel_alt
                    end
                else
                    if (pkt.abs_alt < min_abs_alt) then
                        min_abs_alt = pkt.abs_alt
                    end
                    if (pkt.abs_alt > max_abs_alt) then
                        max_abs_alt = pkt.abs_alt
                    end
                end
                if (pos - start_air_pos > 1) then
                    -- We've reached the end of a block with unset air_pos inside
                    local spkt = {}
                    if (start_air_pos >= 0) then
                        spkt = packets[start_air_pos]
                    else
                        spkt = packets[pos]
                        start_air_pos = 0
                    end
                    -- set coords in a rage of packets which don't have them
                    local tmstamp_span = math.max(pkt.tmstamp - spkt.tmstamp, 0.002)
                    for cpos = start_air_pos+1, pos-1, 1 do
                        local cpkt = packets[cpos]
                        local tmstamp_dt = pkt.tmstamp - spkt.tmstamp
                        cpkt.lon = spkt.lon + (pkt.lon - spkt.lon) * tmstamp_dt / tmstamp_span
                        cpkt.lat = spkt.lat + (pkt.lat - spkt.lat) * tmstamp_dt / tmstamp_span
                        -- mark the packet as fixed in postprocessing, not from real measurement
                        cpkt.fixd = true
                        -- mark the packet as processed
                        cpkt.proc = true
                    end
                end
                start_air_pos = pos
                -- mark the packet as processed
                pkt.proc = true
            end
        end
    end
    if (file_settings.lookat.lon == 0.0) or (file_settings.lookat.lat == 0.0) then
        if (min_lon < 0) and (max_lon > 0) then
            local max_tmp = max_lon
            max_lon = 180.0 - min_lon
            min_lon = max_tmp
        end
        if (min_lat < 0) and (max_lat > 0) then
            local max_tmp = max_lat
            max_lat = 180.0 - min_lat
            min_lat = max_tmp
        end
        file_settings.lookat.lon = min_lon + (max_lon - min_lon)/2
        file_settings.lookat.lat = min_lat + (max_lat - min_lat)/2
        file_settings.lookat.rel_alt = min_rel_alt + (max_rel_alt - min_rel_alt)/2
        file_settings.lookat.abs_alt = min_abs_alt + (max_abs_alt - min_abs_alt)/2
        
        local lonlat_dist = geom_wgs84_coords_distance_meters({lon=min_lon, lat=min_lat}, {lon=max_lon, lat=max_lat})
        -- Compute range as path dimensions but not lower than 10 m
        file_settings.lookat.rng = math.max(lonlat_dist, 10.0)
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
    print("debug: create_writer_file_settings() called")

    local file_settings = new_settings()

    return file_settings
end

----------------------------------------
-- The can_write_encap() function is called by Wireshark when it wants to write out a file,
-- and needs to see if this file writer can handle the packet types in the window.
-- We need to return true if we can handle it, else false
local function can_write_encap(encap)
    print("debug: can_write_encap() called with encap=" .. encap)
    return canwrite[encap] or false
end

local function write_open(fh, capture)
    print("debug: write_open() called")

    local file_settings = create_writer_file_settings()

    -- It would be nice to keep altitude relative to ground. Unfortunately, one
    -- of KML restrictions is that there is no way to make a path relative to
    -- one specific point on the ground. Relative path is relative in every point.
    -- Obviously this is not what we want, so the only solution is to use absolute
    -- positions. Without that, even parts of the drone model would have different
    -- positions on different coordinates.
    local tmp_val = tonumber(capture.user_options.ground_alt, 10)
    if (tmp_val ~= nil) then
        file_settings.ground_altitude = tmp_val
    end

    local tmp_val = tonumber(capture.user_options.dist_shift, 10)
    if (tmp_val ~= nil) then
        file_settings.min_dist_shift = tmp_val/1000
    end

    local tmp_val = tonumber(capture.user_options.model_detail, 10)
    if (tmp_val ~= nil) then
        file_settings.model_detail_lv = math.floor(tmp_val)
    end

    local tmp_val = capture.user_options.path_style
    if (tmp_val ~= nil and tmp_val ~= '') then
        file_settings.path_style = tmp_val
    end

    local tmp_val = capture.user_options.pos_typ
    if (tmp_val ~= nil and tmp_val ~= '') then
        if (tmp_val == 'g') or (tmp_val == 'G') then
            file_settings.air_pos_pkt_typ = TYP_AIR_POS_GPS
        else
            -- This is default, so no need to set
            --file_settings.air_pos_pkt_typ = TYP_AIR_POS_ACC
        end
    end

    -- write out file header
    local hdr = [[<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2" xmlns:gx="http://www.google.com/kml/ext/2.2">
  <Document>
    <name>Dji Flight Log - FILENAME</name>
    <open>1</open>
    <!-- For best viewing experience, select "Do not automatically tilt while zooming"
         option in Google Earth "Navigation" config tab. -->
    <Style id="purpleLineGreenPoly">
      <IconStyle>
        <Icon>
          <href>res/one_px_transparent.png</href>
        </Icon>
        <scale>0</scale>
      </IconStyle>
      <LabelStyle>
        <scale>0</scale>
      </LabelStyle>
      <LineStyle>
        <color>7fff00ff</color>
        <width>4</width>
      </LineStyle>
      <PolyStyle>
        <color>7f00ff00</color>
      </PolyStyle>
    </Style>
    <Style id="yellowLineGreenPoly">
      <IconStyle>
        <Icon>
          <href>res/one_px_transparent.png</href>
        </Icon>
        <scale>0</scale>
      </IconStyle>
      <LabelStyle>
        <scale>0</scale>
      </LabelStyle>
      <LineStyle>
        <color>7f00ffff</color>
        <width>4</width>
      </LineStyle>
      <PolyStyle>
        <color>7f00ff00</color>
      </PolyStyle>
    </Style>
    <Style id="noLineNoPoly">
      <IconStyle>
        <Icon>
          <href>res/one_px_transparent.png</href>
        </Icon>
        <scale>0</scale>
      </IconStyle>
      <LabelStyle>
        <scale>0</scale>
      </LabelStyle>
      <LineStyle>
        <color>00ffffff</color>
        <width>0</width>
      </LineStyle>
      <PolyStyle>
        <color>00ffffff</color>
        <fill>0</fill>
        <outline>0</outline>
      </PolyStyle>
    </Style>
]]
    if not hdr then
        print("info: write_open: error generating file header")
        return false
    end

    if not fh:write(hdr) then
        print("info: write_open: error writing file header to file")
        return false
    end

    -- save settings
    capture.private_table = file_settings

    return true
end

-- declare some field extractors
local dji_p3_rec_etype = Field.new("dji_p3_flyrec.etype")
-- P3 flight record packet 0x000c
local dji_p3_rec_osd_general_longtitude = Field.new("dji_p3_flyrec.osd_general_longtitude")
local dji_p3_rec_osd_general_latitude = Field.new("dji_p3_flyrec.osd_general_latitude")
local dji_p3_rec_osd_general_relative_height = Field.new("dji_p3_flyrec.osd_general_relative_height")
local dji_p3_rec_osd_general_gps_nums = Field.new("dji_p3_flyrec.osd_general_gps_nums")
local dji_p3_rec_osd_general_pitch = Field.new("dji_p3_flyrec.osd_general_pitch")
local dji_p3_rec_osd_general_roll = Field.new("dji_p3_flyrec.osd_general_roll")
local dji_p3_rec_osd_general_yaw = Field.new("dji_p3_flyrec.osd_general_yaw")
local dji_p3_rec_osd_general_mode1 = Field.new("dji_p3_flyrec.osd_general_mode1")

local dji_p3_rec_osd_general_e_motor_on = Field.new("dji_p3_flyrec.osd_general_e_motor_on")
local dji_p3_rec_osd_general_e_usonic_on = Field.new("dji_p3_flyrec.osd_general_e_usonic_on")
local dji_p3_rec_osd_general_e_gohome_state = Field.new("dji_p3_flyrec.osd_general_e_gohome_state")
local dji_p3_rec_osd_general_e_mvo_used = Field.new("dji_p3_flyrec.osd_general_e_mvo_used")
local dji_p3_rec_osd_general_e_battery_req_gohome = Field.new("dji_p3_flyrec.osd_general_e_battery_req_gohome")
local dji_p3_rec_osd_general_e_battery_req_land = Field.new("dji_p3_flyrec.osd_general_e_battery_req_land")
local dji_p3_rec_osd_general_e_rc_state = Field.new("dji_p3_flyrec.osd_general_e_rc_state")
local dji_p3_rec_osd_general_e_compass_over_range = Field.new("dji_p3_flyrec.osd_general_e_compass_over_range")
local dji_p3_rec_osd_general_e_wave_err = Field.new("dji_p3_flyrec.osd_general_e_wave_err")
local dji_p3_rec_osd_general_e_gps_level = Field.new("dji_p3_flyrec.osd_general_e_gps_level")
local dji_p3_rec_osd_general_e_battery_type = Field.new("dji_p3_flyrec.osd_general_e_battery_type")
local dji_p3_rec_osd_general_e_accel_over_range = Field.new("dji_p3_flyrec.osd_general_e_accel_over_range")
local dji_p3_rec_osd_general_e_is_vibrating = Field.new("dji_p3_flyrec.osd_general_e_is_vibrating")
local dji_p3_rec_osd_general_e_press_err = Field.new("dji_p3_flyrec.osd_general_e_press_err")
local dji_p3_rec_osd_general_e_esc_stall = Field.new("dji_p3_flyrec.osd_general_e_esc_stall")
local dji_p3_rec_osd_general_e_esc_empty = Field.new("dji_p3_flyrec.osd_general_e_esc_empty")
local dji_p3_rec_osd_general_e_propeller_catapult = Field.new("dji_p3_flyrec.osd_general_e_propeller_catapult")
local dji_p3_rec_osd_general_e_gohome_height_mod = Field.new("dji_p3_flyrec.osd_general_e_gohome_height_mod")
local dji_p3_rec_osd_general_e_out_of_limit = Field.new("dji_p3_flyrec.osd_general_e_out_of_limit")
local dji_p3_rec_osd_general_gohome_landing_reason = Field.new("dji_p3_flyrec.osd_general_gohome_landing_reason")
local dji_p3_rec_osd_general_start_fail_reason = Field.new("dji_p3_flyrec.osd_general_start_fail_reason")
-- P3 flight record packet 0x0000
local dji_p3_rec_controller_g_real_input_channel_command_aileron = Field.new("dji_p3_flyrec.controller_g_real_input_channel_command_aileron")
local dji_p3_rec_controller_g_real_input_channel_command_elevator = Field.new("dji_p3_flyrec.controller_g_real_input_channel_command_elevator")
local dji_p3_rec_controller_g_real_input_channel_command_throttle = Field.new("dji_p3_flyrec.controller_g_real_input_channel_command_throttle")
local dji_p3_rec_controller_g_real_input_channel_command_rudder = Field.new("dji_p3_flyrec.controller_g_real_input_channel_command_rudder")
local dji_p3_rec_controller_g_real_input_channel_command_mode = Field.new("dji_p3_flyrec.controller_g_real_input_channel_command_mode")
local dji_p3_rec_controller_g_real_status_control_real_mode = Field.new("dji_p3_flyrec.controller_g_real_status_control_real_mode")
local dji_p3_rec_controller_g_real_status_ioc_control_command_mode = Field.new("dji_p3_flyrec.controller_g_real_status_ioc_control_command_mode")
local dji_p3_rec_controller_g_real_status_rc_state = Field.new("dji_p3_flyrec.controller_g_real_status_rc_state")
local dji_p3_rec_controller_g_real_status_motor_status = Field.new("dji_p3_flyrec.controller_g_real_status_motor_status")
local dji_p3_rec_controller_g_real_status_main_batery_voltage = Field.new("dji_p3_flyrec.controller_g_real_status_main_batery_voltage")
-- P3 flight record packet 0x0005
local dji_p3_rec_gps_glns_gps_date = Field.new("dji_p3_flyrec.gps_glns_gps_date")
local dji_p3_rec_gps_glns_gps_time = Field.new("dji_p3_flyrec.gps_glns_gps_time")
local dji_p3_rec_gps_glns_gps_lon = Field.new("dji_p3_flyrec.gps_glns_gps_lon")
local dji_p3_rec_gps_glns_gps_lat = Field.new("dji_p3_flyrec.gps_glns_gps_lat")
local dji_p3_rec_gps_glns_hmsl = Field.new("dji_p3_flyrec.gps_glns_hmsl")
local dji_p3_rec_gps_glns_hdop = Field.new("dji_p3_flyrec.gps_glns_hdop")
local dji_p3_rec_gps_glns_pdop = Field.new("dji_p3_flyrec.gps_glns_pdop")
local dji_p3_rec_gps_glns_numsv = Field.new("dji_p3_flyrec.gps_glns_numsv")

local function write(fh, capture, pinfo)
    print("debug: write() called")

    -- get file settings
    local file_settings = capture.private_table
    if not file_settings then
        print("info: write() failed to get private table file settings")
        return false
    end

    --local tvbrange = fldinfo.range
    --fh:write( tobinary( tostring( tvbrange:bytes() ) ) )
    --fh:flush()

    -- Get fields from new packet
    local curr_pkt = {
        typ = TYP_NULL,
        tmstamp = nil,
        proc = false,
        fixd = false,
    }

    local pkt_rec_etype = { dji_p3_rec_etype() }

    if (pkt_rec_etype[1].value == 0x000c) then
        -- TODO fill FC mode packet
        local new_fc_mode1 = { dji_p3_rec_osd_general_mode1() }
        curr_pkt.mode1 = new_fc_mode1[1].value
        curr_pkt.mode1_text = new_fc_mode1[1].display
        curr_pkt.typ = TYP_FLYC_STAT
        table.insert(file_settings.packets, curr_pkt)

        curr_pkt = {
            typ = TYP_NULL,
            tmstamp = nil,
            proc = false,
            fixd = false,
        }

        local new_air_pitch = { dji_p3_rec_osd_general_pitch() }
        local new_air_roll = { dji_p3_rec_osd_general_roll() }
        local new_air_yaw = { dji_p3_rec_osd_general_yaw() }
        curr_pkt.pitch = new_air_pitch[1].value * 0.1
        curr_pkt.roll = new_air_roll[1].value * 0.1
        curr_pkt.yaw = new_air_yaw[1].value * 0.1
        curr_pkt.typ = TYP_AIR_ROTAT
        table.insert(file_settings.packets, curr_pkt)

        curr_pkt = {
            typ = TYP_NULL,
            tmstamp = nil,
            proc = false,
            fixd = false,
        }
        local new_air_longtitude = { dji_p3_rec_osd_general_longtitude() }
        local new_air_latitude = { dji_p3_rec_osd_general_latitude() }
        local new_air_rel_altitude = { dji_p3_rec_osd_general_relative_height() }
        local new_gps_nums = { dji_p3_rec_osd_general_gps_nums() }

        curr_pkt.lon = (new_air_longtitude[1].value * 180.0 / math.pi)
        curr_pkt.lat = (new_air_latitude[1].value * 180.0 / math.pi)
        curr_pkt.rel_alt = new_air_rel_altitude[1].value * 0.1
        curr_pkt.numsv = new_gps_nums[1].value
        curr_pkt.typ = TYP_AIR_POS_ACC

    elseif (pkt_rec_etype[1].value == 0x0000) then
        local new_motor_status = { dji_p3_rec_controller_g_real_status_motor_status() }
        curr_pkt.motor_status = new_motor_status[1].value
        curr_pkt.typ = TYP_MOTOR_STAT
        table.insert(file_settings.packets, curr_pkt)

        --local new_batery_voltage = { dji_p3_rec_controller_g_real_status_main_batery_voltage() }

        curr_pkt = {
            typ = TYP_NULL,
            tmstamp = nil,
            proc = false,
            fixd = false,
        }
        local new_input_aileron = { dji_p3_rec_controller_g_real_input_channel_command_aileron() }
        local new_input_elevator = { dji_p3_rec_controller_g_real_input_channel_command_elevator() }
        local new_input_throttle = { dji_p3_rec_controller_g_real_input_channel_command_throttle() }
        local new_input_rudder = { dji_p3_rec_controller_g_real_input_channel_command_rudder() }
        local new_input_mode = { dji_p3_rec_controller_g_real_input_channel_command_mode() }
        local new_control_real_mode = { dji_p3_rec_controller_g_real_status_control_real_mode() }
        local new_ioc_control_mode = { dji_p3_rec_controller_g_real_status_ioc_control_command_mode() }
        local new_rc_state = { dji_p3_rec_controller_g_real_status_rc_state() }
        curr_pkt.aileron = new_input_aileron[1].value
        curr_pkt.elevator = new_input_elevator[1].value
        curr_pkt.throttle = new_input_throttle[1].value
        curr_pkt.rudder = new_input_rudder[1].value
        curr_pkt.input_mode = new_input_mode[1].value
        curr_pkt.real_mode = new_control_real_mode[1].value
        curr_pkt.control_mode = new_ioc_control_mode[1].value
        curr_pkt.rc_state = new_rc_state[1].value
        curr_pkt.typ = TYP_RC_STAT
    elseif (pkt_rec_etype[1].value == 0x0005) then
        local new_gps_date = { dji_p3_rec_gps_glns_gps_date() }
        local new_gps_time = { dji_p3_rec_gps_glns_gps_time() }
        local gps_date_int = new_gps_date[1].value
        local gps_time_int = new_gps_time[1].value
        local tm = os.time{
            year=math.floor(gps_date_int/10000),
            month=math.floor(gps_date_int/100)%100,
            day=math.floor(gps_date_int)%100,
            hour=math.floor(gps_time_int/10000),
            min=math.floor(gps_time_int/100)%100,
            sec=math.floor(gps_time_int)%100 }
        -- Accept only valid timestamps
        if (tm ~= nil) and (tm > 1.0) then
            curr_pkt.tmstamp = tm
        end

        local new_gps_lon = { dji_p3_rec_gps_glns_gps_lon() }
        local new_gps_lat = { dji_p3_rec_gps_glns_gps_lat() }
        local new_hmsl = { dji_p3_rec_gps_glns_hmsl() }
        --local new_hdop = { dji_p3_rec_gps_glns_hdop() }
        --local new_pdop = { dji_p3_rec_gps_glns_pdop() }
        local new_numsv = { dji_p3_rec_gps_glns_numsv() }

        curr_pkt.lon = (new_gps_lon[1].value / 10000000)
        curr_pkt.lat = (new_gps_lat[1].value / 10000000)
        curr_pkt.abs_alt = new_hmsl[1].value * 0.001
        curr_pkt.numsv = new_numsv[1].value
        curr_pkt.typ = TYP_AIR_POS_GPS
    end

    if (curr_pkt.typ ~= TYP_NULL) then
        table.insert(file_settings.packets, curr_pkt)
    end

    -- It would be nice to store packets when we're starting to keep too much of them;
    -- but with all the features we have, that probably won't be possible
    --if table.getn(file_settings.packets) > 1024 then
    --    process_packets(file_settings, file_settings.packets, false)
    --    ...
    --end

    return true
end

-- Writes LookAt block with given data
local function write_lookat(fh, indent, file_settings, lookat, head, tilt, altmode)
    local altval = 0
    -- Use either GPS data or ACC data to set the altitude
    if (file_settings.air_pos_pkt_typ == TYP_AIR_POS_ACC) then
        if (altmode == "absolute") then
            altval = lookat.rel_alt + file_settings.ground_altitude
        else
            altval = lookat.rel_alt
        end
    else
        if (altmode == "absolute") then
            altval = lookat.abs_alt
        else
            altval = lookat.abs_alt - file_settings.ground_altitude
        end
    end
    local blk = indent .. [[<LookAt>
]] .. indent .. [[  <longitude>]] .. lookat.lon .. [[</longitude>
]] .. indent .. [[  <latitude>]] .. lookat.lat .. [[</latitude>
]] .. indent .. [[  <altitude>]] .. altval .. [[</altitude>
]] .. indent .. [[  <heading>]] .. head .. [[</heading>
]] .. indent .. [[  <tilt>]] .. tilt .. [[</tilt>
]] .. indent .. [[  <range>]] .. lookat.rng .. [[</range>
]] .. indent .. [[  <altitudeMode>]] .. altmode .. [[</altitudeMode>
]] .. indent .. [[</LookAt>
]]
    return fh:write(blk)
end

-- Writes informational comments with given data
local function write_info(fh, indent, file_settings)
    local pos_type_str = "Accurate"
    if (file_settings.pos_typ == TYP_AIR_POS_GPS) then
        pos_type_str = "Gps only"
    end

    local blk = indent .. [[<description>Path configuration:
 Ground level altitude at start point: ]] .. file_settings.ground_altitude .. [[ m
 Positioning type: ]] .. pos_type_str .. [[
 Minimal position difference: ]] .. file_settings.min_dist_shift .. [[ m</description>
]]
    return fh:write(blk)
end


local function write_static_paths_folder(fh, file_settings)
    print("debug: write_static_paths_folder() called")
    local blk = [[    <Folder>
      <name>Static paths</name>
      <visibility>1</visibility>
      <description>Flight path.</description>
      <Placemark>
        <name>Whole path</name>
        <visibility>1</visibility>
        <description>Flight path line</description>
        <styleUrl>#purpleLineGreenPoly</styleUrl>
]]

    if not fh:write(blk) then
        print("info: write: error writing path block head to file")
        return false
    end

    -- Write folder LookAt block
    if not write_lookat(fh, "        ", file_settings, file_settings.lookat, -45.0, 30.0, "relativeToGround") then
        print("info: write: error writing lookat block to file")
        return false
    end

    local blk = [[        <LineString>
          <extrude>0</extrude>
          <tessellate>0</tessellate>
          <!-- <altitudeMode>absolute</altitudeMode> -->
          <!-- <altitudeMode>relativeToGround</altitudeMode> -->
          <altitudeMode>clampToGround</altitudeMode>
          <coordinates>
]]
    if not fh:write(blk) then
        print("info: write: error writing path block head to file")
        return false
    end

    local min_shift = {}
    geom_wgs84_coords_shift_xyz(min_shift, file_settings.lookat, file_settings.min_dist_shift/2, file_settings.min_dist_shift/2, file_settings.min_dist_shift/2)
    min_shift.lat = math.abs(min_shift.lat - file_settings.lookat.lat)
    min_shift.lon = math.abs(min_shift.lon - file_settings.lookat.lon)
    min_shift.rel_alt = math.abs(min_shift.rel_alt - file_settings.lookat.rel_alt)
    local prev_pkt = {lat=0, lon=0, rel_alt=-999999}
    for pos,pkt in pairs(file_settings.packets) do
        if (pkt.typ == file_settings.air_pos_pkt_typ) then
            -- only add points which have coordinates changed
            if (math.abs(pkt.lat - prev_pkt.lat) > min_shift.lat) or
               (math.abs(pkt.lon - prev_pkt.lon) > min_shift.lon) or
               (math.abs(pkt.rel_alt - prev_pkt.rel_alt) > min_shift.rel_alt) then
                -- For angular coords, 8 digits after dot is enough fo achieve 1.1mm accuracy
                local blk_line = string.format("            %.8f,%.8f,%.3f\n", pkt.lon, pkt.lat, pkt.rel_alt)
                if not fh:write(blk_line) then
                    print("info: write: error writing path block line to file")
                    return false
                end
                prev_pkt = pkt
            end
        end
    end

    local blk = [[          </coordinates>
        </LineString>
      </Placemark>
    </Folder>
]]
    if not fh:write(blk) then
        print("info: write: error writing path block tail to file")
        return false
    end
end

local function write_dynamic_path_element(fh, model_info, tmstamp, pkt, curr_rot_pkt)

    local rot_len = math.sqrt(model_info.shift_x * model_info.shift_x + model_info.shift_y * model_info.shift_y + model_info.shift_z * model_info.shift_z)
    if (rot_len == 0) then
        rot_len = 1e-30 -- small enough to not get into formatting accuracy
    end
    -- Create rotation matrix
    local rad_yaw = math.atan2(model_info.shift_y,model_info.shift_x)
    local rad_pitch = math.asin(-model_info.shift_z / rot_len)
    local rot_mx1 = geom_make_transform_matrix_from_yaw_pitch_roll({yaw=rad_yaw, pitch=rad_pitch, roll=0})
    local rot_mx2 = geom_make_transform_matrix_from_yaw_pitch_roll({yaw=math.rad(curr_rot_pkt.yaw+180), pitch=math.rad(curr_rot_pkt.pitch), roll=math.rad(curr_rot_pkt.roll)})
    rot_mx1 = matrix_mul(rot_mx2, rot_mx1)
    -- To shift world coordinates, we will use the standard yaw-pitch-roll angles
    local rot_qt1 = geom_make_yaw_pitch_roll_from_transform_matrix(rot_mx1)
    -- Rotation angles for inserting into KML have different apply order
    local rot_qt2 = geom_make_yaw_pitch_roll_from_transform_matrix(rot_mx2)
    rot_qt2 = geom_google_earth_incompetent_rotation_fix(model_info, rot_qt2)
    -- Prepare shifted world coordinates
    local rot_shift_x = rot_len * math.sin(rot_qt1.yaw) * math.cos(rot_qt1.pitch)
    local rot_shift_y = rot_len * math.cos(rot_qt1.yaw) * math.cos(rot_qt1.pitch)
    local rot_shift_z = -rot_len * math.sin(rot_qt1.pitch)
    local coord = {}
    geom_wgs84_coords_shift_xyz(coord, pkt, rot_shift_x, rot_shift_y, rot_shift_z)

    local blk_line = "          <when>" .. os.date('!%Y-%m-%dT%H:%M:%S', tmstamp) .. string.format(".%03dZ", (tmstamp * 1000) % 1000) .. "</when>"
    -- Precision of our angular coords is up to "%.12f", but 8 digits after dot is enough fo achieve 1.1mm accuracy
    blk_line = blk_line .. "<gx:coord>" .. string.format("%.8f %.8f %.3f", coord.lon, coord.lat, coord.abs_alt + model_info.shift_up) .. "</gx:coord>"
    blk_line = blk_line .. "<gx:angles>" .. string.format("%.1f %.1f %.1f", math.deg(rot_qt2.yaw), math.deg(rot_qt2.pitch), math.deg(rot_qt2.roll)) .. "</gx:angles>\n"
    if not fh:write(blk_line) then
        print("info: write: error writing path block line to file")
        return false
    end
    return true
end

-- Check if the condition to make model visible is met (or is just switching from met to unmet)
local function is_model_condition_met(model_info, pos_pkt, rot_pkt, mot_pkt, visible_switch)

    return ((model_info.condtn == CONDTN_MOTOR_ON) and ((mot_pkt.motor_status ~= 0) or
            (mot_pkt.motor_status == 0) and (visible_switch))) or
           ((model_info.condtn == CONDTN_MOTOR_OFF) and ((mot_pkt.motor_status == 0) or
            (mot_pkt.motor_status ~= 0) and (visible_switch))) or
           (model_info.condtn == CONDTN_NONE)
end

-- Checks if the condition to make model visible was met for the last time (visibility is switching and previous was visible).
local function is_model_condition_last_met(model_info, pos_pkt, rot_pkt, mot_pkt, visible_switch)

    return ((model_info.condtn == CONDTN_MOTOR_ON) and (mot_pkt.motor_status == 0) and (visible_switch)) or
           ((model_info.condtn == CONDTN_MOTOR_OFF) and (mot_pkt.motor_status ~= 0) and (visible_switch))
end

local function write_dynamic_paths_placemark(fh, file_settings, model_info)
    print("debug: write_dynamic_paths_placemark() called")
    local packets = file_settings.packets

    local full_fname = string.format("res/%s_det%d.dae",model_info.fname,file_settings.model_detail_lv)

    local blk_head = [[      <Placemark>
        <name>Aircraft ]] .. model_info.part_name .. [[ path</name>
        <visibility>1</visibility>
        <styleUrl>#]] .. model_info.line_style .. [[</styleUrl>
        <gx:Track>
          <extrude>0</extrude>
          <altitudeMode>absolute</altitudeMode>
          <!-- <altitudeMode>relativeToGround</altitudeMode> -->
          <Model id="aircraft]] .. model_info.part_name .. [[">
            <Orientation>
              <heading>]] .. model_info.head .. [[</heading>
              <tilt>]] .. model_info.tilt .. [[</tilt>
              <roll>]] .. model_info.roll .. [[</roll>
            </Orientation>
            <Scale>
              <x>]] .. model_info.scale .. [[</x>
              <y>]] .. model_info.scale .. [[</y>
              <z>]] .. model_info.scale .. [[</z>
            </Scale>
            <Link>
              <href>]] .. full_fname .. [[</href>
              <refreshMode>once</refreshMode>
            </Link>
          </Model>
]]
    local blk_tail = [[        </gx:Track>
      </Placemark>
]]

    local min_shift = {}
    geom_wgs84_coords_shift_xyz(min_shift, file_settings.lookat, file_settings.min_dist_shift/2, file_settings.min_dist_shift/2, file_settings.min_dist_shift/2)
    min_shift.lat = math.abs(min_shift.lat - file_settings.lookat.lat)
    min_shift.lon = math.abs(min_shift.lon - file_settings.lookat.lon)
    min_shift.rel_alt = math.abs(min_shift.rel_alt - file_settings.lookat.rel_alt)
    min_shift.rot = 2.0 -- Two degrees rotation is not much for the small drone
    min_shift.tmstamp = 0.99 -- if there was no packet in last second, leave it even if no coords change
    local pkt_num_total = 0
    local pkt_num_pos = 0
    local pkt_num_add = 0
    local curr_rot_pkt = { pitch=0, roll=0, yaw=0 } -- current (not necessarily added) rotation packet
    local prev_rot_pkt = curr_rot_pkt -- previous added rotation packet
    local curr_mot_pkt = { motor_status=0 }
    local visible_switch = false -- set to true when visibility of the model is to be changed
    local block_is_open = false -- set to true if a block is open in the file
    local prev_pkt = {lat=0, lon=0, rel_alt=-999999, tmstamp=1.0} -- previous added pos packet
    local curr_pkt = prev_pkt -- current (not necessarily added) pos packet
    for pos,pkt in pairs(packets) do
        if (pkt.typ == file_settings.air_pos_pkt_typ) then
            -- only add points which have coordinates changed
            if (math.abs(pkt.lat - prev_pkt.lat) > min_shift.lat) or
               (math.abs(pkt.lon - prev_pkt.lon) > min_shift.lon) or
               (math.abs(pkt.rel_alt - prev_pkt.rel_alt) > min_shift.rel_alt) or
               (math.abs(curr_rot_pkt.yaw - prev_rot_pkt.yaw) > min_shift.rot) or
               (math.abs(curr_rot_pkt.pitch - prev_rot_pkt.pitch) > min_shift.rot) or
               (math.abs(curr_rot_pkt.roll - prev_rot_pkt.roll) > min_shift.rot) or
               (math.abs(pkt.tmstamp - prev_pkt.tmstamp) > min_shift.tmstamp) or
               (visible_switch) then

                if (is_model_condition_met(model_info, pkt, curr_rot_pkt, curr_mot_pkt, visible_switch)) then

                    local tmstamp
                    if (pkt_num_add == 0) then
                        local fpkt = packets[1]
                        tmstamp = fpkt.tmstamp
                    else
                        tmstamp = pkt.tmstamp
                    end

                    if not block_is_open then
                        if not fh:write(blk_head) then
                            print("info: write: error writing path block head to file")
                            return false
                        end
                        block_is_open = true
                    end

                    write_dynamic_path_element(fh, model_info, tmstamp, pkt, curr_rot_pkt)

                    if is_model_condition_last_met(model_info, pkt, curr_rot_pkt, curr_mot_pkt, visible_switch) and (block_is_open) then
                        if not fh:write(blk_tail) then
                            print("info: write: error writing path block tail to file")
                            return false
                        end
                        block_is_open = false
                    end

                end

                prev_pkt = pkt
                prev_rot_pkt = curr_rot_pkt
                visible_switch = false
                pkt_num_add = pkt_num_add + 1
            end
            curr_pkt = pkt
            pkt_num_pos = pkt_num_pos + 1
        elseif (pkt.typ == TYP_AIR_ROTAT) then
            curr_rot_pkt = pkt
        elseif (pkt.typ == TYP_MOTOR_STAT) then
            if (curr_mot_pkt.motor_status ~= 0) ~= (pkt.motor_status ~= 0) then
                visible_switch = true
            end
            curr_mot_pkt = pkt
        end
        pkt_num_total = pkt_num_total + 1
    end
    -- Make sure the track does not end before timestamp of last packet
    if (prev_pkt.tmstamp > 1.0) then
        local lpkt = packets[#packets]
        if (lpkt.tmstamp > prev_pkt.tmstamp) and (block_is_open) then
            -- write previous match packet one more time, but with timestamp from very last packet
            write_dynamic_path_element(fh, model_info, lpkt.tmstamp, curr_pkt, curr_rot_pkt)
        end
    end

    if (block_is_open) then
        if not fh:write(blk_tail) then
            print("info: write: error writing path block tail to file")
            return false
        end
        block_is_open = false
    end

    debug(string.format("processed %d packets, %d stored path data, added to track %d of them",pkt_num_total,pkt_num_pos,pkt_num_add))
    return true
end

local function write_dynamic_paths_folder(fh, file_settings)
    print("debug: write_dynamic_paths_folder() called")
    local blk = [[    <Folder>
      <name>Dynamic paths</name>
      <visibility>1</visibility>
      <description>Flight path over time.</description>
]]
    if not fh:write(blk) then
        print("info: write: error writing path block head to file")
        return false
    end

    -- Write folder LookAt block
    if not write_lookat(fh, "      ", file_settings, file_settings.lookat, -45.0, 60.0, "absolute") then
        print("info: write: error writing lookat block to file")
        return false
    end

    local model_info = { head=0.0, tilt=0.0, roll=0.0, scale=0.005, line_style = "yellowLineGreenPoly",
        part_name="Body", fname="phantom_3_pro_body",  condtn=CONDTN_NONE,
        shift_up=0.1, shift_x=0.0, shift_y=0.0, shift_z=0.0 }
    write_dynamic_paths_placemark(fh, file_settings, model_info)

    local model_info = { head=0.0, tilt=0.0, roll=0.0, scale=0.005, line_style = "noLineNoPoly",
        part_name="Prop1Stat", fname="phantom_3_pro_prop_stat", condtn=CONDTN_MOTOR_OFF,
        shift_up=0.1, shift_x=0.624, shift_y=0.624, shift_z=0.1 }
    write_dynamic_paths_placemark(fh, file_settings, model_info)

    local model_info = { head=0.0, tilt=0.0, roll=0.0, scale=0.005, line_style = "noLineNoPoly",
        part_name="Prop1Spin", fname="phantom_3_pro_prop_spin", condtn=CONDTN_MOTOR_ON,
        shift_up=0.1, shift_x=0.624, shift_y=0.624, shift_z=0.1 }
    write_dynamic_paths_placemark(fh, file_settings, model_info)

    local model_info = { head=0.0, tilt=0.0, roll=0.0, scale=0.005, line_style = "noLineNoPoly",
        part_name="Prop2Stat", fname="phantom_3_pro_prop_stat", condtn=CONDTN_MOTOR_OFF,
        shift_up=0.1, shift_x=0.624, shift_y=-0.624, shift_z=0.1 }
    write_dynamic_paths_placemark(fh, file_settings, model_info)

    local model_info = { head=0.0, tilt=0.0, roll=0.0, scale=0.005, line_style = "noLineNoPoly",
        part_name="Prop2Spin", fname="phantom_3_pro_prop_spin", condtn=CONDTN_MOTOR_ON,
        shift_up=0.1, shift_x=0.624, shift_y=-0.624, shift_z=0.1 }
    write_dynamic_paths_placemark(fh, file_settings, model_info)

    local model_info = { head=0.0, tilt=0.0, roll=0.0, scale=0.005, line_style = "noLineNoPoly",
        part_name="Prop3Stat", fname="phantom_3_pro_prop_stat", condtn=CONDTN_MOTOR_OFF,
        shift_up=0.1, shift_x=-0.624, shift_y=-0.624, shift_z=0.1 }
    write_dynamic_paths_placemark(fh, file_settings, model_info)

    local model_info = { head=0.0, tilt=0.0, roll=0.0, scale=0.005, line_style = "noLineNoPoly",
        part_name="Prop3Spin", fname="phantom_3_pro_prop_spin", condtn=CONDTN_MOTOR_ON,
        shift_up=0.1, shift_x=-0.624, shift_y=-0.624, shift_z=0.1 }
    write_dynamic_paths_placemark(fh, file_settings, model_info)

    local model_info = { head=0.0, tilt=0.0, roll=0.0, scale=0.005, line_style = "noLineNoPoly",
        part_name="Prop4Stat", fname="phantom_3_pro_prop_stat", condtn=CONDTN_MOTOR_OFF,
        shift_up=0.1, shift_x=-0.624, shift_y=0.624, shift_z=0.1 }
    write_dynamic_paths_placemark(fh, file_settings, model_info)

    local model_info = { head=0.0, tilt=0.0, roll=0.0, scale=0.005, line_style = "noLineNoPoly",
        part_name="Prop4Spin", fname="phantom_3_pro_prop_spin", condtn=CONDTN_MOTOR_ON,
        shift_up=0.1, shift_x=-0.624, shift_y=0.624, shift_z=0.1 }
    write_dynamic_paths_placemark(fh, file_settings, model_info)

    -- TODO make support of independent gimbal arm movement
    -- while there's no support, we can keep all gimbal arms as one
    local model_info = { head=0.0, tilt=0.0, roll=0.0, scale=0.005, line_style = "noLineNoPoly",
        part_name="GimbalYaw", fname="phantom_3_pro_gimbal_arms", condtn=CONDTN_NONE,
        shift_up=0.1, shift_x=-0.109, shift_y=0.0, shift_z=-0.442 }
    write_dynamic_paths_placemark(fh, file_settings, model_info)

    local blk = [[    </Folder>
]]
    if not fh:write(blk) then
        print("info: write: error writing path block tail to file")
        return false
    end
    return true
end

local function write_screen_overlay_left_stick(fh, beg_tmstamp, end_tmstamp, pkt)
    local throttle = -4.5 - pkt.throttle * 4.5/10000
    local rudder = -4.5 - pkt.rudder * 4.5/10000
    local blk = [[      <ScreenOverlay>
        <name>Controller left knob</name>
        <visibility>1</visibility>
        <TimeSpan><begin>]] .. os.date('!%Y-%m-%dT%H:%M:%S', beg_tmstamp) .. string.format(".%03dZ", (beg_tmstamp * 1000) % 1000) .. [[</begin><end>]] .. os.date('!%Y-%m-%dT%H:%M:%S', end_tmstamp) .. string.format(".%03dZ", (end_tmstamp * 1000) % 1000) .. [[</end></TimeSpan>
        <Icon><href>res/virtual_control_stick_knob.png</href></Icon>
        <overlayXY x="]] .. rudder .. [[" y="]] .. throttle .. [[" xunits="fraction" yunits="fraction"/>
        <screenXY x="0" y="0" xunits="fraction" yunits="fraction"/>
        <rotationXY x="0" y="0" xunits="fraction" yunits="fraction"/>
        <size x="0.02" y="0" xunits="fraction" yunits="fraction"/>
      </ScreenOverlay>
]]
    if not fh:write(blk) then
        print("info: write: error writing screen overlays to file")
        return false
    end
    return true
end

local function write_screen_overlay_right_stick(fh, beg_tmstamp, end_tmstamp, pkt)
    local aileron = 5.5 + pkt.aileron * 4.5/10000
    local elevator = -4.5 - pkt.elevator * 4.5/10000
    local blk = [[      <ScreenOverlay>
        <name>Controller right knob</name>
        <visibility>1</visibility>
        <TimeSpan><begin>]] .. os.date('!%Y-%m-%dT%H:%M:%S', beg_tmstamp) .. string.format(".%03dZ", (beg_tmstamp * 1000) % 1000) .. [[</begin><end>]] .. os.date('!%Y-%m-%dT%H:%M:%S', end_tmstamp) .. string.format(".%03dZ", (end_tmstamp * 1000) % 1000) .. [[</end></TimeSpan>
        <Icon><href>res/virtual_control_stick_knob.png</href></Icon>
        <overlayXY x="]] .. aileron .. [[" y="]] .. elevator .. [[" xunits="fraction" yunits="fraction"/>
        <screenXY x="1" y="0" xunits="fraction" yunits="fraction"/>
        <rotationXY x="0" y="0" xunits="fraction" yunits="fraction"/>
        <size x="0.02" y="0" xunits="fraction" yunits="fraction"/>
      </ScreenOverlay>
]]
    if not fh:write(blk) then
        print("info: write: error writing screen overlays to file")
        return false
    end
    return true
end

local function write_screen_overlay_flyc_mode1(fh, beg_tmstamp, end_tmstamp, pkt)
    local blk = [[      <ScreenOverlay>
        <name>FlyC mode1</name>
        <visibility>1</visibility>
        <TimeSpan><begin>]] .. os.date('!%Y-%m-%dT%H:%M:%S', beg_tmstamp) .. string.format(".%03dZ", (beg_tmstamp * 1000) % 1000) .. [[</begin><end>]] .. os.date('!%Y-%m-%dT%H:%M:%S', end_tmstamp) .. string.format(".%03dZ", (end_tmstamp * 1000) % 1000) .. [[</end></TimeSpan>
        <Icon><href>]] .. string.format("<![CDATA[http://chart.apis.google.com/chart?chst=d_text_outline&chld=DDDDFF|36|h|0000BB|b|%s]]>",pkt.mode1_text) .. [[</href></Icon>
        <overlayXY x="0.5" y="0.5" xunits="fraction" yunits="fraction"/>
        <screenXY x="0.1" y="0.2" xunits="fraction" yunits="fraction"/>
        <size x="0" y="0.03" xunits="fraction" yunits="fraction"/>
      </ScreenOverlay>
]]
    if not fh:write(blk) then
        print("info: write: error writing screen overlays to file")
        return false
    end
    return true
end

local function overlay_stick_needs_refersh(file_settings, val, prev_val, tmstamp, prev_tmstamp)
    local min_delta_time = 0.05
    local min_delta_stick = 50

    if (tmstamp - prev_tmstamp) <= min_delta_time then
        return false
    end

    if (math.abs(val - prev_val) > min_delta_stick) then
        return true
    end

    if (tmstamp - prev_tmstamp) <= 4*min_delta_time then
        return false
    end

    if (math.abs(val - prev_val) > min_delta_stick/4) then
        return true
    end

    if (tmstamp - prev_tmstamp) <= 8*min_delta_time then
        return false
    end

    -- Register even smallest changes near central position
    if (math.abs(val - prev_val) > 1) and (val < min_delta_stick) then
        return true
    end

    return false
end

local function overlay_int_switch_needs_refersh(file_settings, val, prev_val, tmstamp, prev_tmstamp)
    local min_delta_time = 0.02

    if (tmstamp - prev_tmstamp) <= min_delta_time then
        return false
    end

    if (val ~= prev_val) then
        return true
    end

    return false
end

local function write_screen_overlays_folder(fh, file_settings)
    print("debug: write_dynamic_paths_folder() called")
    local packets = file_settings.packets

    if (packets[1] == nil) then
        print("info: no packets, skipping")
        return false
    end
    local blk = [[    <Folder>
      <name>Screen Overlays</name>
      <visibility>1</visibility>
      <description>Overlays showing controller state.</description>
      <ScreenOverlay>
        <name>Controller left scale</name>
        <visibility>1</visibility>
        <Icon>
          <href>res/virtual_control_stick_back.png</href>
        </Icon>
        <overlayXY x="0" y="0" xunits="fraction" yunits="fraction"/>
        <screenXY x="0" y="0" xunits="fraction" yunits="fraction"/>
        <rotationXY x="0" y="0" xunits="fraction" yunits="fraction"/>
        <size x="0.2" y="0" xunits="fraction" yunits="fraction"/>
      </ScreenOverlay>
      <ScreenOverlay>
        <name>Controller right scale</name>
        <visibility>1</visibility>
        <Icon>
          <href>res/virtual_control_stick_back.png</href>
        </Icon>
        <overlayXY x="1" y="0" xunits="fraction" yunits="fraction"/>
        <screenXY x="1" y="0" xunits="fraction" yunits="fraction"/>
        <rotationXY x="0" y="0" xunits="fraction" yunits="fraction"/>
        <size x="0.2" y="0" xunits="fraction" yunits="fraction"/>
      </ScreenOverlay>
]]
    if not fh:write(blk) then
        print("info: write: error writing screen overlays to file")
        return false
    end

    local pkt_num_total = 0
    local pkt_num_ctrl = 0
    local pkt_num_flyc = 0
    local prev_left_pkt = { elevator = 0, rudder = 0,  aileron = 0, throttle = 0, tmstamp=packets[1].tmstamp }
    local prev_right_pkt = prev_left_pkt
    local curr_rc_pkt = prev_left_pkt
    local prev_mode1_pkt = { mode1 = 0, mode1_text = "Startup", tmstamp=packets[1].tmstamp }
    for pos,pkt in pairs(packets) do

        if (pkt.typ == TYP_RC_STAT) then

            if (overlay_stick_needs_refersh(file_settings, pkt.throttle, prev_left_pkt.throttle, pkt.tmstamp, prev_left_pkt.tmstamp)) or
               (overlay_stick_needs_refersh(file_settings, pkt.rudder, prev_left_pkt.rudder, pkt.tmstamp, prev_left_pkt.tmstamp)) then

                write_screen_overlay_left_stick(fh, prev_left_pkt.tmstamp, pkt.tmstamp, prev_left_pkt)
                prev_left_pkt = pkt
            end

            if (overlay_stick_needs_refersh(file_settings, pkt.aileron, prev_right_pkt.aileron, pkt.tmstamp, prev_right_pkt.tmstamp)) or
               (overlay_stick_needs_refersh(file_settings, pkt.elevator, prev_right_pkt.elevator, pkt.tmstamp, prev_right_pkt.tmstamp)) then

                write_screen_overlay_right_stick(fh, prev_right_pkt.tmstamp, pkt.tmstamp, prev_right_pkt)
                prev_right_pkt = pkt
            end
            curr_rc_pkt = pkt
            pkt_num_ctrl = pkt_num_ctrl + 1

        elseif (pkt.typ == TYP_FLYC_STAT) then

            if (overlay_int_switch_needs_refersh(file_settings, pkt.mode1, prev_mode1_pkt.mode1, pkt.tmstamp, prev_mode1_pkt.tmstamp)) then
                write_screen_overlay_flyc_mode1(fh, prev_mode1_pkt.tmstamp, pkt.tmstamp, prev_mode1_pkt)
                prev_mode1_pkt = pkt
            end
            pkt_num_flyc = pkt_num_flyc + 1

        end
        pkt_num_total = pkt_num_total + 1
    end
    -- Make sure the track does not end before timestamp of last packet
    if (true) then
        local lpkt = packets[#packets]
        -- write previous match packets one more time, but with timestamp from very last packet
        if (lpkt.tmstamp > prev_left_pkt.tmstamp) then
            write_screen_overlay_left_stick(fh, prev_left_pkt.tmstamp, lpkt.tmstamp, curr_rc_pkt)
        end
        if (lpkt.tmstamp > prev_right_pkt.tmstamp) then
            write_screen_overlay_right_stick(fh, prev_right_pkt.tmstamp, lpkt.tmstamp, curr_rc_pkt)
        end
        if (lpkt.tmstamp > prev_mode1_pkt.tmstamp) then
            write_screen_overlay_flyc_mode1(fh, prev_mode1_pkt.tmstamp, lpkt.tmstamp, prev_mode1_pkt)
        end
    end
    debug(string.format("processed %d packets, %d radio controller data, %d flight controller data",pkt_num_total,pkt_num_ctrl,pkt_num_flyc))

    local blk = [[    </Folder>
]]
    if not fh:write(blk) then
        print("info: write: error writing screen overlays to file")
        return false
    end
    return true
end


local function write_close(fh, capture)
    print("debug: write_close() called")

    -- get file settings
    local file_settings = capture.private_table
    if not file_settings then
        print("info: write() failed to get private table file settings")
        return false
    end

    process_packets(file_settings, file_settings.packets, true)

    if not write_info(fh, "  ", file_settings) then
        print("info: write: error writing info block to file")
        return false
    end

    -- Write global LookAt block
    if not write_lookat(fh, "    ", file_settings, file_settings.lookat, -45.0, 45.0, "absolute") then
        print("info: write: error writing lookat block to file")
        return false
    end

    -- Write static paths (without time dependencies)
    write_static_paths_folder(fh, file_settings)

    -- Write the more interesting, dynamic paths
    write_dynamic_paths_folder(fh, file_settings)

    -- Write screen overlays
    write_screen_overlays_folder(fh, file_settings)

    local footer = [[  </Document>
</kml>
]]
    if not fh:write(footer) then
        print("info: write: error writing file footer")
        return false
    end

    print("debug: Good night, and good luck")
    return true
end

-- do a payload dump when prompted by the user
local function init_payload_dump(filename, ground_alt_val, pos_typ_val, min_dist_shift_val, model_detail_val, path_style_val)

    local packet_count = 0
    os.setlocale("C") -- this is to avoid country-specific number conventions
    -- Osd General
    local filter = "dji_p3_flyrec.etype == 0x0000 or dji_p3_flyrec.etype == 0x0005 or dji_p3_flyrec.etype == 0x000c"
    local tap = Listener.new(nil,filter)
    local fh = assert(io.open(filename, "w+"))

    capture = ExportCaptureInfo:create()
    capture.user_options = { ground_alt=ground_alt_val, pos_typ=pos_typ_val, dist_shift=min_dist_shift_val, model_detail=model_detail_val, path_style=path_style_val }
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
    print("info: Dumped packets: " .. packet_count )
end

-- show this dialog when the user select "Export" from the Tools menu
local function begin_dialog_menu()    
    new_dialog("KML path of DJI drone flight writer", init_payload_dump,
      "Output file\n(type KML file name)",
      "Ground level altitude\n(altitude above sea at the starting point, in meters;\nif empty, measurements average will be used)",
      "Positioning type\n('a' for accurate, using combined data from all sensors\n'g' for GNSS, using data only from satellites;\nif empty, 'a' will be used)",
      "Minimal registered position difference\n(distance in milimeters below which\na path point will be optimized out;\nif empty, 12 will be used)",
      "3D Model detail level\n(controls amount of faces in aircraft model:\n0 - max complexity,\n1 - up to 20k faces,\n2 - up to 2k faces, default)",
      "Path style\n(flat, line, wall) UNUSED")
end

register_menu("Export KML from DJI drone flight", begin_dialog_menu, MENU_TOOLS_UNSORTED)

print("debug: Tools Menu Handler registered")
