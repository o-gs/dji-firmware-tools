local f = DJI_P3_PROTO.fields

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
f.batt_barcode = ProtoField.bytes("dji_p3.batt_barcode", "Barcode", base.SPACE)

local function battery_barcode_dissector(batt_length, buffer, pinfo, subtree)
    local offset = 5
    if batt_length ~= 14 then
        subtree:add(f.batt_barcode, buffer(offset, (batt_length - offset - 1)))

    end
end

-- Battery Status
f.batt_temp = ProtoField.uint16 ("dji_p3.batt_temp", "Temp", base.DEC)
f.batt_total_v = ProtoField.uint16 ("dji_p3.batt_total_v", "Total mV", base.DEC)
f.batt_current = ProtoField.int32 ("dji_p3.batt_current", "Current", base.DEC)
f.batt_ave_current = ProtoField.int32 ("dji_p3.batt_ave_current", "Average Current", base.DEC)
f.batt_state_of_charge = ProtoField.uint16 ("dji_p3.batt_charge", "Charge (%)", base.DEC)
f.batt_cell_v = ProtoField.uint16 ("dji_p3.batt_cell_v", "Cell mV", base.DEC)
f.batt_cell_eol = ProtoField.uint16 ("dji_p3.batt_cell_eol", "EOL", base.HEX)
f.batt_power_status = ProtoField.string("dji_p3.batt_status", "Power Status")

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

DJI_P3_BATTERY_UART_DISSECT = {
    [0x21] = battery_type_dissector,
    [0x22] = battery_status_dissector,
    [0x38] = battery_barcode_dissector,
}
