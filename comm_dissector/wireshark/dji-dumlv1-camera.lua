-- The definitions in this file are part of DJI DUMLv1 protocol dissector
-- Dissectors for command set 0x01 - Camera

local f = DJI_DUMLv1_PROTO.fields
local enums = {}

-- CMD name decode table

CAMERA_UART_CMD_TEXT = {
    [0x01] = 'Do Capture Photo',
    [0x02] = 'Do Record',
    [0x03] = 'HeartBeat',
    [0x04] = 'Set Usb Switch', -- Usb Connect
    [0x05] = 'Virtual Key Send',
    [0x06] = 'Get Usb Switch',
    [0x10] = 'Camera Work Mode Set',
    [0x11] = 'Camera Work Mode Get',
    [0x12] = 'Photo Format Set',
    [0x13] = 'Photo Format Get',
    [0x14] = 'Photo Quality Set',
    [0x15] = 'Photo Quality Get',
    [0x16] = 'Photo Storage Fmt Set',
    [0x17] = 'Photo Storage Fmt Get',
    [0x18] = 'Video Format Set',
    [0x19] = 'Video Format Get',
    [0x1A] = 'Video Quality Set',
    [0x1B] = 'Video Quality Get',
    [0x1C] = 'Video Storage Fmt Set',
    [0x1D] = 'Video Storage Fmt Get',
    [0x1E] = 'Exposure Mode Set',
    [0x1F] = 'Exposure Mode Get',
    [0x20] = 'Scene Mode Set',
    [0x21] = 'Scene Mode Get',
    [0x22] = 'AE Meter Set',
    [0x23] = 'AE Meter Get',
    [0x24] = 'Focus Mode Set',
    [0x25] = 'Focus Mode Get',
    [0x26] = 'Aperture Size Set',
    [0x27] = 'Aperture Size Get',
    [0x28] = 'Shutter Speed Set',
    [0x29] = 'Shutter Speed Get',
    [0x2A] = 'ISO Set',
    [0x2B] = 'ISO Get',
    [0x2C] = 'White Balance Env Set',
    [0x2D] = 'White Balance Env Get',
    [0x2E] = 'Exposition Bias Set', -- Ev Bias Set
    [0x2F] = 'Exposition Bias Get',
    [0x30] = 'Focus Region Set',
    [0x31] = 'Focus Region Get',
    [0x32] = 'AE Meter Region Set', -- Auto Exposition (Ev) Meter Region Set
    [0x33] = 'AE Meter Region Get',
    [0x34] = 'Zoom Param Set',
    [0x35] = 'Zoom Param Get',
    [0x36] = 'Flash Mode Set',
    [0x37] = 'Flash Mode Get',
    [0x38] = 'Sharpeness Set',
    [0x39] = 'Sharpeness Get',
    [0x3A] = 'Contrast Set',
    [0x3B] = 'Contrast Get',
    [0x3C] = 'Saturation Set',
    [0x3D] = 'Saturation Get',
    [0x3E] = 'Hue Set', -- Color Tonal Set
    [0x3F] = 'Hue Get',
    [0x40] = 'Face Detect Set',
    [0x41] = 'Face Detect Get',
    [0x42] = 'Digital Effect Set', -- Digital Filter Set
    [0x43] = 'Digital Effect Get',
    [0x44] = 'Digital Denoise Set',
    [0x45] = 'Digital Denoise Get',
    [0x46] = 'Anti Flicker Set',
    [0x47] = 'Anti Flicker Get',
    [0x48] = 'Multi Cap Param Set', -- Continuous Shoot Set
    [0x49] = 'Multi Cap Param Get',
    [0x4A] = 'Conti Cap Param Set', -- Continuous Shoot Time Options Set
    [0x4B] = 'Conti Cap Param Get',
    [0x4C] = 'Hdmi Output Param Set', -- LCD/HDMI video output (Vout) format set
    [0x4D] = 'Hdmi Output Param Get',
    [0x4E] = 'Quickview Param Set', -- Quick Playback Options Set
    [0x4F] = 'Quickview Param Get',
    [0x50] = 'OSD Param Set',
    [0x51] = 'OSD Param Get',
    [0x52] = 'Preview OSD Param Set',
    [0x53] = 'Preview OSD Param Get',
    [0x54] = 'Camera Date/Time Set',
    [0x55] = 'Camera Date/Time Get',
    [0x56] = 'Language Param Set',
    [0x57] = 'Language Param Get',
    [0x58] = 'Camera GPS Set',
    [0x59] = 'Camera GPS Get',
    [0x5A] = 'Discon State Set',
    [0x5B] = 'Discon State Get',
    [0x5C] = 'File Index Mode Set',
    [0x5D] = 'File Index Mode Get',
    [0x5E] = 'AE bCap Param Set',
    [0x5F] = 'AE bCap Param Get',
    [0x60] = 'Histogram Set', -- Push Chart Set
    [0x61] = 'Histogram Get',
    [0x62] = 'Video Subtitles Set', -- Video Caption Set
    [0x63] = 'Video Subtitles Get',
    [0x64] = 'Video Subtitles Log Set',
    [0x65] = 'Mgear Shutter Speed Set', -- Shutter Speed Limit Set
    [0x66] = 'Video Standard Set',
    [0x67] = 'Video Standard Get',
    [0x68] = 'AE Lock Status Set', -- Auto Exposure Preserve Set
    [0x69] = 'AE Lock Status Get',
    [0x6A] = 'Photo Capture Type Set', -- Photo Mode Set
    [0x6B] = 'Photo Capture Type Get',
    [0x6C] = 'Video Record Mode Set',
    [0x6D] = 'Video Record Mode Get',
    [0x6E] = 'Panorama Mode Set',
    [0x6F] = 'Panorama Mode Get',
    [0x70] = 'System State Get',
    [0x71] = 'SDcard Info Get',
    [0x72] = 'SDcard Do Format',
    [0x73] = 'SDcard Format Progress Get',
    [0x74] = 'Fw Upgrade Progress Get',
    [0x75] = 'Photo Sync Progress Get',
    [0x76] = 'Camera Power Info Get',
    [0x77] = 'Settings Save', -- Save Preferences
    [0x78] = 'Settings Load',
    [0x79] = 'File Delete', -- Photo Erase
    [0x7A] = 'Video Play Control',
    [0x7B] = 'Thumbnail 2 Single Ctrl', -- Single Play Choice
    [0x7c] = 'Camera Shutter Cmd', -- Telectrl Action
    [0x7D] = 'PB Zoom Ctrl', -- Scale Gesture
    [0x7E] = 'PB Pic Drag Ctrl', -- Drag Gesture
    [0x80] = 'Camera State Info', -- Camera Status Push
    [0x81] = 'Camera Shot Params', -- Cap Params Push
    [0x82] = 'Camera PlayBack Params',
    [0x83] = 'Camera Chart Info', -- Histogram Params Push
    [0x84] = 'Camera Recording Name', -- Video Name Push
    [0x85] = 'Camera Raw Params', -- Raw Camera Status Push
    [0x86] = 'Camera Cur Pano Status', -- Panorama FileName Push
    [0x87] = 'Camera Shot Info', -- Lens Info Push
    [0x88] = 'Camera Timelapse Parms', -- TimeLapse Info Push
    [0x89] = 'Camera Tracking Status', -- Camera Tracking Params Push
    [0x8A] = 'Camera FOV Param',
    [0x8B] = 'Racing Liveview Format Set',
    [0x8C] = 'Racing Liveview Format Get',
    [0x90] = 'Sensor Calibrate Test', -- Check Sensor Test
    [0x91] = 'Sensor Calibrate Complete', -- If Cali
    [0x92] = 'Video Clip Info Get', -- Video Params Get
    [0x93] = 'TransCode Control', -- Xcode Ctrl
    [0x94] = 'Focus Range Get',
    [0x95] = 'Focus Stroke Set', -- VCM Pos Set
    [0x96] = 'Focus Stroke Get',
    [0x98] = 'FileSystem Info Get', -- File Params Get
    [0x99] = 'Shot Info Get',
    [0x9A] = 'Focus Aid Set',
    [0x9B] = 'Video Adaptive Gamma Set', -- Video Contrast Enhance Set
    [0x9C] = 'Video Adaptive Gamma Get',
    [0x9D] = 'Awb Meter Region Set', -- White Balance Area Set
    [0x9E] = 'Awb Meter Region Get',
    [0x9F] = 'Audio Param Set',
    [0xA0] = 'Audio Param Get',
    [0xA1] = 'Format Raw SSD',
    [0xA2] = 'Focus Distance Set',
    [0xA3] = 'Calibration Control Set',
    [0xA4] = 'Focus Window Set',
    [0xA5] = 'Tracking Region Get',
    [0xA6] = 'Tracking Region Set',
    [0xA7] = 'Iris Set',
    [0xA8] = 'AE Unlock Mode Set',
    [0xA9] = 'AE Unlock Mode Get',
    [0xAA] = 'Pano File Params Get',
    [0xAB] = 'Video Encode Set',
    [0xAC] = 'Video Encode Get',
    [0xAD] = 'MCTF Set',
    [0xAE] = 'MCTF Get',
    [0xAF] = 'SSD Video Format Set',
    [0xB0] = 'SSD Video Format Get',
    [0xB1] = 'Record Fan Set',
    [0xB2] = 'Record Fan Get',
    [0xB3] = 'Request IFrame', -- Request key frame; useful if some video data was dropped
    [0xB4] = 'Camera Prepare Open Fan',
    [0xB5] = 'Camera Sensor Id Get',
    [0xB6] = 'Forearm Lamp Config Set', -- ForeArm LED Set
    [0xB7] = 'Forearm Lamp Config Get',
    [0xB8] = 'Camera Optics Zoom Mode',
    [0xB9] = 'Image Rotation Set', -- Set Camera Rotation Mode
    [0xBA] = 'Image Rotation Get',
    [0xBB] = 'Gimbal Lock Config Set', -- Lock Gimbal When Shot Set
    [0xBC] = 'Gimbal Lock Config Get',
    [0xBD] = 'Old Cam LCD Format Set', -- Raw Video Format Set
    [0xBE] = 'Old Cam LCD Format Get',
    [0xBF] = 'File Star Flag Set',
    [0xC0] = 'MFDemarcate',
    [0xC1] = 'Log Mode Set',
    [0xC2] = 'Param Name Set',
    [0xC3] = 'Param Name Get',
    [0xC4] = 'Camera Tap Zoom Set',
    [0xC5] = 'Camera Tap Zoom Get',
    [0xC6] = 'Camera Tap Zoom Target Set',
    [0xC7] = 'Camera Tap Zoom State Info',
    [0xC8] = 'Defog Enabled Set',
    [0xC9] = 'Defog Enabled Get',
    [0xCA] = 'Raw Equip Info Set',
    [0xCC] = 'SSD Raw Video Digital Filter Set',
    [0xCE] = 'Calibration Control Get',
    [0xCF] = 'Mechanical Shutter Set',
    [0xD0] = 'Mechanical Shutter Get',
    [0xD1] = 'Cam DCF Abstract Push', -- Push DFC Info Get
    [0xD2] = 'Dust Reduction State Set',
    [0xD3] = 'Camera UnknownD3',
    [0xDD] = 'ND Filter Set',
    [0xDE] = 'Raw New Param Set',
    [0xDF] = 'Raw New Param Get',
    [0xE0] = 'Capture Sound', -- Capability Range Get
    [0xE1] = 'Capture Config Set',
    [0xE2] = 'Capture Config Get',
    [0xF0] = 'Camera TBD F0', -- Supported in P3X
    [0xF1] = 'Camera Tau Param',
    [0xF2] = 'Camera Tau Param Get', -- Push Tau Factor Get
    [0xF9] = 'Focus Infinite Get',
    [0xFA] = 'Focus Infinite Set',
}

-- Camera - Camera Shutter Cmd - 0x7c

f.camera_camera_shutter_cmd_shutter_type = ProtoField.uint8 ("dji_dumlv1.camera_camera_shutter_cmd_shutter_type", "Shutter Type", base.DEC)

local function camera_camera_shutter_cmd_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_shutter_cmd_shutter_type, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Shutter Cmd: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Shutter Cmd: Payload size different than expected") end
end

-- Camera - Camera State Info - 0x80

enums.CAMERA_STATE_INFO_FIRM_UPGRADE_ERROR_STATE_FIRM_ERROR_TYPE_ENUM = {
    [0x00] = 'NO',
    [0x01] = 'Nomatch',
    [0x02] = 'UpgradeError',
    [0x06] = 'OTHER',
}

enums.CAMERA_STATE_INFO_PHOTO_STATE_ENUM = {
    [0x00] = 'NO',
    [0x01] = 'Single',
    [0x02] = 'Multiple',
    [0x03] = 'Hdr',
    [0x04] = 'FullView',
    [0x06] = 'OTHER',
}

enums.CAMERA_STATE_INFO_SD_CARD_STATE_ENUM = {
    [0x00] = 'Normal',
    [0x01] = 'None',
    [0x02] = 'Invalid',
    [0x03] = 'WriteProtection',
    [0x04] = 'Unformat',
    [0x05] = 'Formating',
    [0x06] = 'Illegal',
    [0x07] = 'Busy',
    [0x08] = 'Full',
    [0x09] = 'Slow',
    [0x0a] = 'Unknow',
    [0x0b] = 'IndexMax',
    [0x0c] = 'Initialzing',
    [0x0d] = 'ToFormat',
    [0x0e] = 'TryToRecoverFile',
    [0x0f] = 'BecomeSlow',
    [0x63] = 'USBConnected',
    [0x64] = 'OTHER',
}

enums.CAMERA_STATE_INFO_MODE_ENUM = {
    [0x00] = 'TAKEPHOTO',
    [0x01] = 'RECORD',
    [0x02] = 'PLAYBACK',
    [0x03] = 'TRANSCODE',
    [0x04] = 'TUNING',
    [0x05] = 'SAVEPOWER',
    [0x06] = 'DOWNLOAD',
    [0x07] = 'NEW_PLAYBACK',
    [0x64] = 'OTHER',
}

enums.CAMERA_STATE_INFO_FILE_INDEX_MODE_ENUM = {
    [0x00] = 'Reset',
    [0x01] = 'Sequence',
}

enums.CAMERA_STATE_INFO_CAMERA_TYPE_ENUM = {
    [0x00] = 'DJICameraTypeFC350',
    [0x01] = 'DJICameraTypeFC550',
    [0x02] = 'DJICameraTypeFC260',
    [0x03] = 'DJICameraTypeFC300S',
    [0x04] = 'DJICameraTypeFC300X',
    [0x05] = 'DJICameraTypeFC550Raw',
    [0x06] = 'DJICameraTypeFC330X',
    [0x07] = 'DJICameraTypeTau640',
    [0x08] = 'DJICameraTypeTau336',
    [0x09] = 'DJICameraTypeFC220',
    [0x0a] = 'DJICameraTypeFC300XW',
    [0x0b] = 'DJICameraTypeCV600',
    [0x0d] = 'DJICameraTypeFC6310',
    [0x0e] = 'DJICameraTypeFC6510',
    [0x0f] = 'DJICameraTypeFC6520',
    [0x12] = 'DJICameraTypeFC220S',
    [0x14] = 'DJICameraTypeGD600',
    [0xff] = 'OTHER',
}

f.camera_camera_state_info_masked00 = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_masked00", "Masked00", base.HEX)
  f.camera_camera_state_info_connect_state = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_connect_state", "Connect State", base.HEX, nil, 0x0001, nil)
  f.camera_camera_state_info_usb_state = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_usb_state", "Usb State", base.HEX, nil, 0x0002, nil)
  f.camera_camera_state_info_time_sync_state = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_time_sync_state", "Time Sync State", base.HEX, nil, 0x0004, nil)
  f.camera_camera_state_info_photo_state = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_photo_state", "Photo State", base.HEX, enums.CAMERA_STATE_INFO_PHOTO_STATE_ENUM, 0x0038, nil)
  f.camera_camera_state_info_record_state = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_record_state", "Record State", base.HEX, nil, 0x00c0, "TODO values from enum P3.DataCameraGetPushStateInfo")
  f.camera_camera_state_info_sensor_state = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_sensor_state", "Sensor State", base.HEX, nil, 0x0100, nil)
  f.camera_camera_state_info_sd_card_insert_state = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_sd_card_insert_state", "Sd Card Insert State", base.HEX, nil, 0x0200, nil)
  f.camera_camera_state_info_sd_card_state = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_sd_card_state", "Sd Card State", base.HEX, enums.CAMERA_STATE_INFO_SD_CARD_STATE_ENUM, 0x3c00, nil)
  f.camera_camera_state_info_firm_upgrade_state = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_firm_upgrade_state", "Firm Upgrade State", base.HEX, nil, 0x4000, nil)
  f.camera_camera_state_info_firm_upgrade_error_state = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_firm_upgrade_error_state", "Firm Upgrade Error State", base.HEX, enums.CAMERA_STATE_INFO_FIRM_UPGRADE_ERROR_STATE_FIRM_ERROR_TYPE_ENUM, 0x18000, nil)
  f.camera_camera_state_info_hot_state = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_hot_state", "Hot State", base.HEX, nil, 0x020000, nil)
  f.camera_camera_state_info_not_enabled_photo = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_not_enabled_photo", "Not Enabled Photo", base.HEX, nil, 0x040000, nil)
  f.camera_camera_state_info_is_storing = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_is_storing", "Is Storing", base.HEX, nil, 0x080000, nil)
  f.camera_camera_state_info_is_time_photoing = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_is_time_photoing", "Is Time Photoing", base.HEX, nil, 0x100000, nil)
  f.camera_camera_state_info_encrypt_status = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_encrypt_status", "Encrypt Status", base.HEX, nil, 0xc00000, "TODO values from enum P3.DataCameraGetPushStateInfo")
  f.camera_camera_state_info_is_gimbal_busy = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_is_gimbal_busy", "Is Gimbal Busy", base.HEX, nil, 0x08000000, nil)
  f.camera_camera_state_info_in_tracking_mode = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_in_tracking_mode", "In Tracking Mode", base.HEX, nil, 0x10000000, nil)
f.camera_camera_state_info_mode = ProtoField.uint8 ("dji_dumlv1.camera_camera_state_info_mode", "Camera Mode", base.HEX, enums.CAMERA_STATE_INFO_MODE_ENUM, nil, nil)
f.camera_camera_state_info_sd_card_total_size = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_sd_card_total_size", "Sd Card Total Size", base.DEC)
f.camera_camera_state_info_sd_card_free_size = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_sd_card_free_size", "Sd Card Free Size", base.DEC)
f.camera_camera_state_info_remained_shots = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_remained_shots", "Remained Shots", base.DEC)
f.camera_camera_state_info_remained_time = ProtoField.uint32 ("dji_dumlv1.camera_camera_state_info_remained_time", "Remained Time", base.DEC)
f.camera_camera_state_info_file_index_mode = ProtoField.uint8 ("dji_dumlv1.camera_camera_state_info_file_index_mode", "File Index Mode", base.DEC, enums.CAMERA_STATE_INFO_FILE_INDEX_MODE_ENUM, nil, nil)
f.camera_camera_state_info_fast_play_back_info = ProtoField.uint8 ("dji_dumlv1.camera_camera_state_info_fast_play_back_info", "Fast Play Back Info", base.HEX)
  f.camera_camera_state_info_fast_play_back_enabled = ProtoField.uint8 ("dji_dumlv1.camera_camera_state_info_fast_play_back_enabled", "Fast Play Back Enabled", base.HEX, nil, 0x80, nil)
  f.camera_camera_state_info_fast_play_back_time = ProtoField.uint8 ("dji_dumlv1.camera_camera_state_info_fast_play_back_time", "Fast Play Back Time", base.DEC, nil, 0x7f, nil)
f.camera_camera_state_info_photo_osd_info = ProtoField.uint16 ("dji_dumlv1.camera_camera_state_info_photo_osd_info", "Photo Osd Info", base.HEX)
  f.camera_camera_state_info_photo_osd_time_is_show = ProtoField.uint16 ("dji_dumlv1.camera_camera_state_info_photo_osd_time_is_show", "Photo Osd Time Is Show", base.HEX, nil, 0x01, nil)
  f.camera_camera_state_info_photo_osd_aperture_is_show = ProtoField.uint16 ("dji_dumlv1.camera_camera_state_info_photo_osd_aperture_is_show", "Photo Osd Aperture Is Show", base.HEX, nil, 0x02, nil)
  f.camera_camera_state_info_photo_osd_shutter_is_show = ProtoField.uint16 ("dji_dumlv1.camera_camera_state_info_photo_osd_shutter_is_show", "Photo Osd Shutter Is Show", base.HEX, nil, 0x04, nil)
  f.camera_camera_state_info_photo_osd_iso_is_show = ProtoField.uint16 ("dji_dumlv1.camera_camera_state_info_photo_osd_iso_is_show", "Photo Osd Iso Is Show", base.HEX, nil, 0x08, nil)
  f.camera_camera_state_info_photo_osd_exposure_is_show = ProtoField.uint16 ("dji_dumlv1.camera_camera_state_info_photo_osd_exposure_is_show", "Photo Osd Exposure Is Show", base.HEX, nil, 0x10, nil)
  f.camera_camera_state_info_photo_osd_sharpe_is_show = ProtoField.uint16 ("dji_dumlv1.camera_camera_state_info_photo_osd_sharpe_is_show", "Photo Osd Sharpe Is Show", base.HEX, nil, 0x20, nil)
  f.camera_camera_state_info_photo_osd_contrast_is_show = ProtoField.uint16 ("dji_dumlv1.camera_camera_state_info_photo_osd_contrast_is_show", "Photo Osd Contrast Is Show", base.HEX, nil, 0x40, nil)
  f.camera_camera_state_info_photo_osd_saturation_is_show = ProtoField.uint16 ("dji_dumlv1.camera_camera_state_info_photo_osd_saturation_is_show", "Photo Osd Saturation Is Show", base.HEX, nil, 0x80, nil)
f.camera_camera_state_info_unknown19 = ProtoField.bytes ("dji_dumlv1.camera_camera_state_info_unknown19", "Unknown19", base.SPACE)
f.camera_camera_state_info_in_debug_mode = ProtoField.uint8 ("dji_dumlv1.camera_camera_state_info_in_debug_mode", "In Debug Mode", base.HEX)
f.camera_camera_state_info_unknown1c = ProtoField.uint8 ("dji_dumlv1.camera_camera_state_info_unknown1c", "Unknown1C", base.HEX)
f.camera_camera_state_info_video_record_time = ProtoField.uint16 ("dji_dumlv1.camera_camera_state_info_video_record_time", "Video Record Time", base.DEC)
f.camera_camera_state_info_max_photo_num = ProtoField.uint8 ("dji_dumlv1.camera_camera_state_info_max_photo_num", "Max Photo Num", base.DEC)
f.camera_camera_state_info_masked20 = ProtoField.uint8 ("dji_dumlv1.camera_camera_state_info_masked20", "Masked20", base.HEX)
  f.camera_camera_state_info_histogram_enable = ProtoField.uint8 ("dji_dumlv1.camera_camera_state_info_histogram_enable", "Histogram Enable", base.HEX, nil, 0x01, nil)
f.camera_camera_state_info_camera_type = ProtoField.uint8 ("dji_dumlv1.camera_camera_state_info_camera_type", "Camera Type", base.HEX, enums.CAMERA_STATE_INFO_CAMERA_TYPE_ENUM, nil, nil)
f.camera_camera_state_info_unknown22 = ProtoField.bytes ("dji_dumlv1.camera_camera_state_info_unknown22", "Unknown22", base.SPACE)
f.camera_camera_state_info_version = ProtoField.uint8 ("dji_dumlv1.camera_camera_state_info_version", "Version", base.DEC)
f.camera_camera_state_info_padding = ProtoField.bytes ("dji_dumlv1.camera_camera_state_info_padding", "Padding", base.SPACE)

local function camera_camera_state_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_state_info_masked00, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_connect_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_usb_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_time_sync_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_photo_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_record_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_sensor_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_sd_card_insert_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_sd_card_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_firm_upgrade_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_firm_upgrade_error_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_hot_state, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_not_enabled_photo, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_is_storing, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_is_time_photoing, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_encrypt_status, payload(offset, 4))
    subtree:add_le (f.camera_camera_state_info_is_gimbal_busy, payload(offset, 4))

    subtree:add_le (f.camera_camera_state_info_in_tracking_mode, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_state_info_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_state_info_sd_card_total_size, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_state_info_sd_card_free_size, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_state_info_remained_shots, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_state_info_remained_time, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_state_info_file_index_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_state_info_fast_play_back_info, payload(offset, 1))
    subtree:add_le (f.camera_camera_state_info_fast_play_back_enabled, payload(offset, 1))
    subtree:add_le (f.camera_camera_state_info_fast_play_back_time, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_state_info_photo_osd_info, payload(offset, 2))
    subtree:add_le (f.camera_camera_state_info_photo_osd_aperture_is_show, payload(offset, 2))
    subtree:add_le (f.camera_camera_state_info_photo_osd_shutter_is_show, payload(offset, 2))
    subtree:add_le (f.camera_camera_state_info_photo_osd_iso_is_show, payload(offset, 2))
    subtree:add_le (f.camera_camera_state_info_photo_osd_exposure_is_show, payload(offset, 2))
    subtree:add_le (f.camera_camera_state_info_photo_osd_sharpe_is_show, payload(offset, 2))
    subtree:add_le (f.camera_camera_state_info_photo_osd_contrast_is_show, payload(offset, 2))
    subtree:add_le (f.camera_camera_state_info_photo_osd_saturation_is_show, payload(offset, 2))
    subtree:add_le (f.camera_camera_state_info_photo_osd_time_is_show, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_state_info_unknown19, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_state_info_in_debug_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_state_info_unknown1c, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_state_info_video_record_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_state_info_max_photo_num, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_state_info_masked20, payload(offset, 1))
    subtree:add_le (f.camera_camera_state_info_histogram_enable, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_state_info_camera_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_state_info_unknown22, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_state_info_version, payload(offset, 1))
    offset = offset + 1

    if (payload:len() >= offset + 2) then -- On some platforms, packet ends with 2 byte padding

        subtree:add_le (f.camera_camera_state_info_padding, payload(offset, 2))
        offset = offset + 2

    end

    if (offset ~= 37) and (offset ~= 39) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera State Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera State Info: Payload size different than expected") end
end

-- Camera - Camera Shot Params - 0x81

enums.CAMERA_SHOT_PARAMS_ISO_TYPE_ENUM = {
    [0x00] = 'AUTO',
    [0x01] = 'AUTOHIGH',
    [0x02] = 'ISO50',
    [0x03] = 'ISO100',
    [0x04] = 'ISO200',
    [0x05] = 'ISO400',
    [0x06] = 'ISO800',
    [0x07] = 'ISO1600',
    [0x08] = 'ISO3200',
    [0x09] = 'ISO6400',
    [0x0a] = 'ISO12800',
    [0x0b] = 'ISO25600',
}

enums.CAMERA_SHOT_PARAMS_IMAGE_SIZE_SIZE_TYPE_ENUM = {
    [0x00] = 'DEFAULT',
    [0x01] = 'SMALLEST',
    [0x02] = 'SMALL',
    [0x03] = 'MIDDLE',
    [0x04] = 'LARGE',
    [0x05] = 'LARGEST',
    [0x06] = 'OTHER',
}

enums.CAMERA_SHOT_PARAMS_IMAGE_RATIO_TYPE_ENUM = {
    [0x00] = 'R 4:3',
    [0x01] = 'R 16:9',
    [0x02] = 'R 3:2',
    [0x06] = 'R OTHER',
}

enums.CAMERA_SHOT_PARAMS_EXPOSURE_MODE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'Program',
    [0x02] = 'ShutterPriority',
    [0x03] = 'AperturePriority',
    [0x04] = 'Manual',
    [0x05] = 'f',
    [0x06] = 'g',
    [0x07] = 'Cine',
    [0x64] = 'i',
}

enums.CAMERA_SHOT_PARAMS_PHOTO_TYPE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x02] = 'c',
    [0x03] = 'd',
    [0x04] = 'e',
    [0x05] = 'f',
    [0x06] = 'g',
    [0x07] = 'h',
    [0x0a] = 'i',
}

enums.CAMERA_SHOT_PARAMS_VIDEO_ENCODE_TYPE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x64] = 'c',
}

f.camera_camera_shot_params_aperture_size = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_params_aperture_size", "Aperture Size", base.HEX)
f.camera_camera_shot_params_user_shutter = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_params_user_shutter", "User Shutter", base.HEX)
  f.camera_camera_shot_params_reciprocal = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_params_reciprocal", "Reciprocal", base.HEX, nil, 0x8000, nil)
f.camera_camera_shot_params_shutter_speed_decimal = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_shutter_speed_decimal", "Shutter Speed Decimal", base.DEC)
f.camera_camera_shot_params_iso = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_iso", "Iso", base.HEX, enums.CAMERA_SHOT_PARAMS_ISO_TYPE_ENUM, nil, nil)
f.camera_camera_shot_params_exposure_compensation = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_exposure_compensation", "Exposure Compensation", base.HEX)
f.camera_camera_shot_params_ctr_object_for_one = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_ctr_object_for_one", "Ctr Object For One", base.HEX)
f.camera_camera_shot_params_ctr_object_for_two = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_ctr_object_for_two", "Ctr Object For Two", base.HEX)
f.camera_camera_shot_params_image_size = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_image_size", "Image Size", base.HEX, enums.CAMERA_SHOT_PARAMS_IMAGE_SIZE_SIZE_TYPE_ENUM, nil, nil)
f.camera_camera_shot_params_image_ratio = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_image_ratio", "Image Ratio", base.HEX, enums.CAMERA_SHOT_PARAMS_IMAGE_RATIO_TYPE_ENUM, nil, nil)
f.camera_camera_shot_params_image_quality = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_image_quality", "Image Quality", base.HEX)
f.camera_camera_shot_params_image_format = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_image_format", "Image Format", base.HEX)
f.camera_camera_shot_params_video_format = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_video_format", "Video Format", base.HEX)
f.camera_camera_shot_params_video_fps = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_video_fps", "Video Fps", base.HEX)
f.camera_camera_shot_params_video_fov = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_video_fov", "Video Fov", base.HEX)
f.camera_camera_shot_params_video_second_open = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_video_second_open", "Video Second Open", base.HEX)
f.camera_camera_shot_params_video_second_ratio = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_video_second_ratio", "Video Second Ratio", base.HEX)
f.camera_camera_shot_params_video_quality = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_video_quality", "Video Quality", base.HEX)
f.camera_camera_shot_params_video_store_format = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_video_store_format", "Video Store Format", base.HEX)
f.camera_camera_shot_params_exposure_mode = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_exposure_mode", "Exposure Mode", base.HEX, enums.CAMERA_SHOT_PARAMS_EXPOSURE_MODE_ENUM, nil, nil)
f.camera_camera_shot_params_scene_mode = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_scene_mode", "Scene Mode", base.HEX)
f.camera_camera_shot_params_metering = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_metering", "Metering", base.HEX)
f.camera_camera_shot_params_white_balance = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_white_balance", "White Balance", base.HEX)
f.camera_camera_shot_params_color_temp = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_color_temp", "Color Temp", base.HEX)
f.camera_camera_shot_params_mctf_enable = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_mctf_enable", "Mctf Enable", base.HEX)
f.camera_camera_shot_params_mctf_strength = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_mctf_strength", "Mctf Strength", base.HEX)
f.camera_camera_shot_params_sharpe = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_sharpe", "Sharpe", base.HEX)
f.camera_camera_shot_params_contrast = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_contrast", "Contrast", base.HEX)
f.camera_camera_shot_params_saturation = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_saturation", "Saturation", base.HEX)
f.camera_camera_shot_params_tonal = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_tonal", "Tonal", base.HEX)
f.camera_camera_shot_params_digital_filter = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_digital_filter", "Digital Filter", base.HEX)
f.camera_camera_shot_params_anti_flicker = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_anti_flicker", "Anti Flicker", base.HEX)
f.camera_camera_shot_params_continuous = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_continuous", "Continuous", base.HEX)
f.camera_camera_shot_params_time_params_type = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_time_params_type", "Time Params Type", base.HEX)
f.camera_camera_shot_params_time_params_num = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_time_params_num", "Time Params Num", base.HEX)
f.camera_camera_shot_params_time_params_period = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_params_time_params_period", "Time Params Period", base.HEX)
f.camera_camera_shot_params_real_aperture_size = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_params_real_aperture_size", "Real Aperture Size", base.HEX)
f.camera_camera_shot_params_real_shutter = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_params_real_shutter", "Real Shutter", base.HEX)
  f.camera_camera_shot_params_rel_reciprocal = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_params_rel_reciprocal", "Rel Reciprocal", base.HEX, nil, 0x8000, nil)
f.camera_camera_shot_params_rel_shutter_speed_decimal = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_rel_shutter_speed_decimal", "Real Shutter Speed Decimal", base.DEC)
f.camera_camera_shot_params_rel_iso = ProtoField.uint32 ("dji_dumlv1.camera_camera_shot_params_rel_iso", "Real Iso", base.HEX)
f.camera_camera_shot_params_rel_exposure_compensation = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_rel_exposure_compensation", "Real Exposure Compensation", base.HEX)
f.camera_camera_shot_params_time_countdown = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_time_countdown", "Time Countdown", base.HEX)
f.camera_camera_shot_params_cap_min_shutter = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_params_cap_min_shutter", "Cap Min Shutter", base.HEX)
  f.camera_camera_shot_params_cap_min_shutter_reciprocal = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_params_cap_min_shutter_reciprocal", "Cap Min Shutter Reciprocal", base.HEX, nil, 0x8000, nil)
f.camera_camera_shot_params_cap_min_shutter_decimal = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_cap_min_shutter_decimal", "Cap Min Shutter Decimal", base.DEC)
f.camera_camera_shot_params_cap_max_shutter = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_params_cap_max_shutter", "Cap Max Shutter", base.HEX)
  f.camera_camera_shot_params_cap_max_shutter_reciprocal = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_params_cap_max_shutter_reciprocal", "Cap Max Shutter Reciprocal", base.HEX, nil, 0x8000, nil)
f.camera_camera_shot_params_cap_max_shutter_decimal = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_cap_max_shutter_decimal", "Cap Max Shutter Decimal", base.DEC)
f.camera_camera_shot_params_video_standard = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_video_standard", "Video Standard", base.HEX)
f.camera_camera_shot_params_ae_lock = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_ae_lock", "Ae Lock", base.HEX)
f.camera_camera_shot_params_photo_type = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_photo_type", "Photo Type", base.HEX, enums.CAMERA_SHOT_PARAMS_PHOTO_TYPE_ENUM, nil, nil)
f.camera_camera_shot_params_spot_area_bottom_right_pos = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_spot_area_bottom_right_pos", "Spot Area Bottom Right Pos", base.HEX)
f.camera_camera_shot_params_unknown3b = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_unknown3b", "Unknown3B", base.HEX)
f.camera_camera_shot_params_aeb_number = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_aeb_number", "Aeb Number", base.HEX)
f.camera_camera_shot_params_pano_mode = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_pano_mode", "Pano Mode", base.HEX, nil, nil, "TODO values from enum P3.DataCameraGetPushShotParams")
f.camera_camera_shot_params_cap_min_aperture = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_params_cap_min_aperture", "Cap Min Aperture", base.HEX)
f.camera_camera_shot_params_cap_max_aperture = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_params_cap_max_aperture", "Cap Max Aperture", base.HEX)
f.camera_camera_shot_params_masked42 = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_masked42", "Masked42", base.HEX)
  f.camera_camera_shot_params_auto_turn_off_fore_led = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_auto_turn_off_fore_led", "Auto Turn Off Fore Led", base.HEX, nil, 0x01, nil)
f.camera_camera_shot_params_exposure_status = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_exposure_status", "Exposure Status", base.HEX)
f.camera_camera_shot_params_locked_gimbal_when_shot = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_locked_gimbal_when_shot", "Locked Gimbal When Shot", base.HEX)
f.camera_camera_shot_params_encode_types = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_encode_types", "Video Encode Types", base.HEX)
  f.camera_camera_shot_params_primary_video_encode_type = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_primary_video_encode_type", "Primary Video Encode Type", base.HEX, enums.CAMERA_SHOT_PARAMS_VIDEO_ENCODE_TYPE_ENUM, 0x0f, nil)
  f.camera_camera_shot_params_secondary_video_encode_type = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_secondary_video_encode_type", "Secondary Video Encode Type", base.HEX, enums.CAMERA_SHOT_PARAMS_VIDEO_ENCODE_TYPE_ENUM, 0xf0, nil)
f.camera_camera_shot_params_not_auto_ae_unlock = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_not_auto_ae_unlock", "Not Auto Ae Unlock", base.HEX)
f.camera_camera_shot_params_unknown47 = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_unknown47", "Unknown47", base.HEX)
f.camera_camera_shot_params_constrast_ehance = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_constrast_ehance", "Constrast Ehance", base.HEX)
f.camera_camera_shot_params_video_record_mode = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_video_record_mode", "Video Record Mode", base.HEX)
f.camera_camera_shot_params_timelapse_save_type = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_params_timelapse_save_type", "Timelapse Save Type", base.HEX)
f.camera_camera_shot_params_video_record_interval_time = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_params_video_record_interval_time", "Video Record Interval Time", base.HEX)
f.camera_camera_shot_params_timelapse_duration = ProtoField.uint32 ("dji_dumlv1.camera_camera_shot_params_timelapse_duration", "Timelapse Duration", base.HEX)
f.camera_camera_shot_params_timelapse_time_count_down = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_params_timelapse_time_count_down", "Timelapse Time Count Down", base.HEX)
f.camera_camera_shot_params_timelapse_recorded_frame = ProtoField.uint32 ("dji_dumlv1.camera_camera_shot_params_timelapse_recorded_frame", "Timelapse Recorded Frame", base.HEX)
f.camera_camera_shot_params_optics_scale = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_params_optics_scale", "Optics Scale", base.HEX)
f.camera_camera_shot_params_digital_zoom_scale = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_params_digital_zoom_scale", "Digital Zoom Scale", base.HEX)

local function camera_camera_shot_params_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_shot_params_aperture_size, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_user_shutter, payload(offset, 2))
    subtree:add_le (f.camera_camera_shot_params_reciprocal, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_shutter_speed_decimal, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_iso, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_exposure_compensation, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_ctr_object_for_one, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_ctr_object_for_two, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_image_size, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_image_ratio, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_image_quality, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_image_format, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_format, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_fps, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_fov, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_second_open, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_second_ratio, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_quality, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_store_format, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_exposure_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_scene_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_metering, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_white_balance, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_color_temp, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_mctf_enable, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_mctf_strength, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_sharpe, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_contrast, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_saturation, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_tonal, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_digital_filter, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_anti_flicker, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_continuous, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_time_params_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_time_params_num, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_time_params_period, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_real_aperture_size, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_real_shutter, payload(offset, 2))
    subtree:add_le (f.camera_camera_shot_params_rel_reciprocal, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_rel_shutter_speed_decimal, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_rel_iso, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_shot_params_rel_exposure_compensation, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_time_countdown, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_cap_min_shutter, payload(offset, 2))
    subtree:add_le (f.camera_camera_shot_params_cap_min_shutter_reciprocal, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_cap_min_shutter_decimal, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_cap_max_shutter, payload(offset, 2))
    subtree:add_le (f.camera_camera_shot_params_cap_max_shutter_reciprocal, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_cap_max_shutter_decimal, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_standard, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_ae_lock, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_photo_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_spot_area_bottom_right_pos, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_unknown3b, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_aeb_number, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_pano_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_cap_min_aperture, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_cap_max_aperture, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_masked42, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_params_auto_turn_off_fore_led, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_exposure_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_locked_gimbal_when_shot, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_encode_types, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_params_primary_video_encode_type, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_params_secondary_video_encode_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_not_auto_ae_unlock, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_unknown47, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_constrast_ehance, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_record_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_timelapse_save_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_params_video_record_interval_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_timelapse_duration, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_shot_params_timelapse_time_count_down, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_timelapse_recorded_frame, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_shot_params_optics_scale, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_params_digital_zoom_scale, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 91) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Shot Params: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Shot Params: Payload size different than expected") end
end

-- Camera - Camera Play Back Params - 0x82

enums.CAMERA_PLAY_BACK_PARAMS_MODE_ENUM = {
    [0x00] = 'Single',
    [0x01] = 'SingleLarge',
    [0x02] = 'SinglePlay',
    [0x03] = 'SinglePause',
    [0x04] = 'MultipleDel',
    [0x05] = 'Multiple',
    [0x06] = 'Download',
    [0x07] = 'SingleOver',
    [0x64] = 'OTHER',
}

enums.CAMERA_PLAY_BACK_PARAMS_FILE_TYPE_ENUM = {
    [0x00] = 'JPEG',
    [0x01] = 'DNG',
    [0x02] = 'VIDEO',
    [0x64] = 'OTHER',
}

enums.CAMERA_PLAY_BACK_PARAMS_DEL_FILE_STATUS_ENUM = {
    [0x00] = 'NORMAL',
    [0x02] = 'DELETING',
    [0x03] = 'COMPLETED',
}

f.camera_camera_play_back_params_mode = ProtoField.uint8 ("dji_dumlv1.camera_camera_play_back_params_mode", "Mode", base.HEX, enums.CAMERA_PLAY_BACK_PARAMS_MODE_ENUM, nil, nil)
f.camera_camera_play_back_params_file_type = ProtoField.uint16 ("dji_dumlv1.camera_camera_play_back_params_file_type", "File Type", base.HEX, enums.CAMERA_PLAY_BACK_PARAMS_FILE_TYPE_ENUM, nil, nil)
f.camera_camera_play_back_params_file_num = ProtoField.uint8 ("dji_dumlv1.camera_camera_play_back_params_file_num", "File Num", base.DEC)
f.camera_camera_play_back_params_total_num = ProtoField.uint16 ("dji_dumlv1.camera_camera_play_back_params_total_num", "Total Num", base.DEC)
f.camera_camera_play_back_params_index = ProtoField.uint16 ("dji_dumlv1.camera_camera_play_back_params_index", "Index", base.DEC)
f.camera_camera_play_back_params_progress = ProtoField.uint8 ("dji_dumlv1.camera_camera_play_back_params_progress", "Progress", base.HEX)
f.camera_camera_play_back_params_total_time = ProtoField.uint16 ("dji_dumlv1.camera_camera_play_back_params_total_time", "Total Time", base.HEX)
f.camera_camera_play_back_params_current = ProtoField.uint16 ("dji_dumlv1.camera_camera_play_back_params_current", "Current", base.HEX)
f.camera_camera_play_back_params_delete_chioce_num = ProtoField.uint16 ("dji_dumlv1.camera_camera_play_back_params_delete_chioce_num", "Delete Chioce Num", base.HEX)
f.camera_camera_play_back_params_zoom_size = ProtoField.uint16 ("dji_dumlv1.camera_camera_play_back_params_zoom_size", "Zoom Size", base.HEX)
f.camera_camera_play_back_params_total_photo_num = ProtoField.uint16 ("dji_dumlv1.camera_camera_play_back_params_total_photo_num", "Total Photo Num", base.HEX)
f.camera_camera_play_back_params_total_video_num = ProtoField.uint16 ("dji_dumlv1.camera_camera_play_back_params_total_video_num", "Total Video Num", base.HEX)
f.camera_camera_play_back_params_photo_width = ProtoField.uint32 ("dji_dumlv1.camera_camera_play_back_params_photo_width", "Photo Width", base.HEX)
f.camera_camera_play_back_params_photo_height = ProtoField.uint32 ("dji_dumlv1.camera_camera_play_back_params_photo_height", "Photo Height", base.HEX)
f.camera_camera_play_back_params_center_x = ProtoField.uint32 ("dji_dumlv1.camera_camera_play_back_params_center_x", "Center X", base.HEX)
f.camera_camera_play_back_params_center_y = ProtoField.uint32 ("dji_dumlv1.camera_camera_play_back_params_center_y", "Center Y", base.HEX)
f.camera_camera_play_back_params_cur_page_selected = ProtoField.uint8 ("dji_dumlv1.camera_camera_play_back_params_cur_page_selected", "Cur Page Selected", base.HEX)
f.camera_camera_play_back_params_del_file_status = ProtoField.uint8 ("dji_dumlv1.camera_camera_play_back_params_del_file_status", "Del File Status", base.HEX, enums.CAMERA_PLAY_BACK_PARAMS_DEL_FILE_STATUS_ENUM, nil, nil)
f.camera_camera_play_back_params_not_select_file_valid = ProtoField.uint8 ("dji_dumlv1.camera_camera_play_back_params_not_select_file_valid", "Not Select File Valid", base.HEX)
f.camera_camera_play_back_params_single_downloaded = ProtoField.uint8 ("dji_dumlv1.camera_camera_play_back_params_single_downloaded", "Single Downloaded", base.HEX)

local function camera_camera_play_back_params_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_play_back_params_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_play_back_params_file_type, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_play_back_params_file_num, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_play_back_params_total_num, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_play_back_params_index, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_play_back_params_progress, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_play_back_params_total_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_play_back_params_current, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_play_back_params_delete_chioce_num, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_play_back_params_zoom_size, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_play_back_params_total_photo_num, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_play_back_params_total_video_num, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_play_back_params_photo_width, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_play_back_params_photo_height, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_play_back_params_center_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_play_back_params_center_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_play_back_params_cur_page_selected, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_play_back_params_del_file_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_play_back_params_not_select_file_valid, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_play_back_params_single_downloaded, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 41) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Play Back Params: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Play Back Params: Payload size different than expected") end
end

-- Camera - Camera Chart Info - 0x83

f.camera_camera_chart_info_light_values = ProtoField.bytes ("dji_dumlv1.camera_camera_chart_info_light_values", "Light Values", base.NONE)

local function camera_camera_chart_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_chart_info_light_values, payload(offset, 4)) -- size not known
    offset = offset + 4

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Chart Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Chart Info: Payload size different than expected") end
end

-- Camera - Camera Recording Name - 0x84

enums.CAMERA_RECORDING_FILE_TYPE_ENUM = {
    [0x00] = 'JPEG',
    [0x01] = 'DNG',
    [0x02] = 'VIDEO',
    [0x64] = 'OTHER',
}

f.camera_camera_recording_name_file_type = ProtoField.uint8 ("dji_dumlv1.camera_camera_recording_name_file_type", "File Type", base.HEX, enums.CAMERA_RECORDING_FILE_TYPE_ENUM, nil, nil)
f.camera_camera_recording_name_index = ProtoField.uint32 ("dji_dumlv1.camera_camera_recording_name_index", "Index", base.HEX)
f.camera_camera_recording_name_size = ProtoField.uint64 ("dji_dumlv1.camera_camera_recording_name_size", "Size", base.HEX)
f.camera_camera_recording_name_time = ProtoField.uint32 ("dji_dumlv1.camera_camera_recording_name_time", "Time", base.HEX)

local function camera_camera_recording_name_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_recording_name_file_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_recording_name_index, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_recording_name_size, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.camera_camera_recording_name_time, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 17) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Recording Name: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Recording Name: Payload size different than expected") end
end

-- Camera - Camera Raw Params - 0x85

enums.CAMERA_RAW_PARAMS_DISK_STATUS_ENUM = {
    [0x00] = 'NA',
    [0x01] = 'WAITING',
    [0x02] = 'STORING',
    [0x03] = 'LOW_FORMATING',
    [0x04] = 'FAST_FORMATING',
    [0x05] = 'INITIALIZING',
    [0x06] = 'DEVICE_ERROR',
    [0x07] = 'VERIFY_ERROR',
    [0x08] = 'FULL',
    [0x09] = 'OTHER',
}

f.camera_camera_raw_params_masked00 = ProtoField.uint8 ("dji_dumlv1.camera_camera_raw_params_masked00", "Masked00", base.HEX)
  f.camera_camera_raw_params_disk_status = ProtoField.uint8 ("dji_dumlv1.camera_camera_raw_params_disk_status", "Disk Status", base.HEX, enums.CAMERA_RAW_PARAMS_DISK_STATUS_ENUM, 0x0f, nil)
  f.camera_camera_raw_params_disk_connected = ProtoField.uint8 ("dji_dumlv1.camera_camera_raw_params_disk_connected", "Disk Connected", base.HEX, nil, 0x10, nil)
  f.camera_camera_raw_params_disk_capacity = ProtoField.uint8 ("dji_dumlv1.camera_camera_raw_params_disk_capacity", "Disk Capacity", base.HEX, nil, 0x60, nil)
f.camera_camera_raw_params_disk_available_time = ProtoField.uint16 ("dji_dumlv1.camera_camera_raw_params_disk_available_time", "Disk Available Time", base.HEX)
f.camera_camera_raw_params_available_capacity = ProtoField.uint32 ("dji_dumlv1.camera_camera_raw_params_available_capacity", "Available Capacity", base.HEX)
f.camera_camera_raw_params_resolution = ProtoField.uint8 ("dji_dumlv1.camera_camera_raw_params_resolution", "Resolution", base.HEX)
f.camera_camera_raw_params_fps = ProtoField.uint8 ("dji_dumlv1.camera_camera_raw_params_fps", "Fps", base.HEX)
f.camera_camera_raw_params_ahci_status = ProtoField.uint8 ("dji_dumlv1.camera_camera_raw_params_ahci_status", "Ahci Status", base.HEX)

local function camera_camera_raw_params_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_raw_params_masked00, payload(offset, 1))
    subtree:add_le (f.camera_camera_raw_params_disk_status, payload(offset, 1))
    subtree:add_le (f.camera_camera_raw_params_disk_connected, payload(offset, 1))
    subtree:add_le (f.camera_camera_raw_params_disk_capacity, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_raw_params_disk_available_time, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_raw_params_available_capacity, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_raw_params_resolution, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_raw_params_fps, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_raw_params_ahci_status, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 10) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Raw Params: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Raw Params: Payload size different than expected") end
end

-- Camera - Camera Cur Pano File Name - 0x86

f.camera_camera_cur_pano_file_name_index = ProtoField.uint32 ("dji_dumlv1.camera_camera_cur_pano_file_name_index", "Index", base.HEX)
f.camera_camera_cur_pano_file_name_unknown04 = ProtoField.bytes ("dji_dumlv1.camera_camera_cur_pano_file_name_unknown04", "Unknown04", base.SPACE)
f.camera_camera_cur_pano_file_name_pano_create_time = ProtoField.uint32 ("dji_dumlv1.camera_camera_cur_pano_file_name_pano_create_time", "Pano Create Time", base.HEX)
f.camera_camera_cur_pano_file_name_cur_saved_number = ProtoField.uint8 ("dji_dumlv1.camera_camera_cur_pano_file_name_cur_saved_number", "Cur Saved Number", base.HEX)
f.camera_camera_cur_pano_file_name_cur_taken_number = ProtoField.uint8 ("dji_dumlv1.camera_camera_cur_pano_file_name_cur_taken_number", "Cur Taken Number", base.HEX)
f.camera_camera_cur_pano_file_name_total_number = ProtoField.uint8 ("dji_dumlv1.camera_camera_cur_pano_file_name_total_number", "Total Number", base.HEX)
f.camera_camera_cur_pano_file_name_unknown13 = ProtoField.uint8 ("dji_dumlv1.camera_camera_cur_pano_file_name_unknown13", "Unknown13", base.HEX)
f.camera_camera_cur_pano_file_name_file_size = ProtoField.uint64 ("dji_dumlv1.camera_camera_cur_pano_file_name_file_size", "File Size", base.HEX)
f.camera_camera_cur_pano_file_name_create_time = ProtoField.uint32 ("dji_dumlv1.camera_camera_cur_pano_file_name_create_time", "Create Time", base.HEX)

local function camera_camera_cur_pano_file_name_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_cur_pano_file_name_index, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_cur_pano_file_name_unknown04, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.camera_camera_cur_pano_file_name_pano_create_time, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_cur_pano_file_name_cur_saved_number, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_cur_pano_file_name_cur_taken_number, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_cur_pano_file_name_total_number, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_cur_pano_file_name_unknown13, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_cur_pano_file_name_file_size, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.camera_camera_cur_pano_file_name_create_time, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 32) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Cur Pano File Name: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Cur Pano File Name: Payload size different than expected") end
end

-- Camera - Camera Shot Info - 0x87


enums.CAMERA_SHOT_INFO_FUSELAGE_FOCUS_MODE_ENUM = {
    [0x00] = 'Manual',
    [0x01] = 'OneAuto',
    [0x02] = 'ContinuousAuto',
    [0x03] = 'ManualFine',
    [0x06] = 'OTHER',
}

f.camera_camera_shot_info_masked00 = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_masked00", "Masked00", base.HEX)
  f.camera_camera_shot_info_fuselage_focus_mode = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_fuselage_focus_mode", "Fuselage Focus Mode", base.HEX, enums.CAMERA_SHOT_INFO_FUSELAGE_FOCUS_MODE_ENUM, 0x03, nil)
  f.camera_camera_shot_info_shot_focus_mode = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_shot_focus_mode", "Shot Focus Mode", base.HEX, nil, 0x0c, "TODO values from enum P3.DataCameraGetPushShotInfo")
  f.camera_camera_shot_info_zoom_focus_type = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_zoom_focus_type", "Zoom Focus Type", base.HEX, nil, 0x10, nil)
  f.camera_camera_shot_info_shot_type = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_shot_type", "Shot Type", base.HEX, nil, 0x20, "TODO values from enum P3.DataCameraGetPushShotInfo")
  f.camera_camera_shot_info_shot_fd_type = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_shot_fd_type", "Shot Fd Type", base.HEX, nil, 0x40, "TODO values from enum P3.DataCameraGetPushShotInfo")
  f.camera_camera_shot_info_shot_connected = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_shot_connected", "Shot Connected", base.HEX, nil, 0x80, nil)
f.camera_camera_shot_info_shot_focus_max_stroke = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_info_shot_focus_max_stroke", "Shot Focus Max Stroke", base.HEX)
f.camera_camera_shot_info_shot_focus_cur_stroke = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_info_shot_focus_cur_stroke", "Shot Focus Cur Stroke", base.HEX)
f.camera_camera_shot_info_obj_distance = ProtoField.float ("dji_dumlv1.camera_camera_shot_info_obj_distance", "Obj Distance", base.DEC)
f.camera_camera_shot_info_min_aperture = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_info_min_aperture", "Min Aperture", base.HEX)
f.camera_camera_shot_info_max_aperture = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_info_max_aperture", "Max Aperture", base.HEX)
f.camera_camera_shot_info_spot_af_axis_x = ProtoField.float ("dji_dumlv1.camera_camera_shot_info_spot_af_axis_x", "Spot Af Axis X", base.DEC)
f.camera_camera_shot_info_spot_af_axis_y = ProtoField.float ("dji_dumlv1.camera_camera_shot_info_spot_af_axis_y", "Spot Af Axis Y", base.DEC)
f.camera_camera_shot_info_masked15 = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_masked15", "Masked15", base.HEX)
  f.camera_camera_shot_info_focus_status = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_focus_status", "Focus Status", base.HEX, nil, 0x03, nil)
f.camera_camera_shot_info_mf_focus_probability = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_mf_focus_probability", "Mf Focus Probability", base.HEX)
f.camera_camera_shot_info_min_focus_distance = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_info_min_focus_distance", "Min Focus Distance", base.HEX)
f.camera_camera_shot_info_max_focus_distance = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_info_max_focus_distance", "Max Focus Distance", base.HEX)
f.camera_camera_shot_info_cur_focus_distance = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_info_cur_focus_distance", "Cur Focus Distance", base.HEX)
f.camera_camera_shot_info_min_focus_distance_step = ProtoField.uint16 ("dji_dumlv1.camera_camera_shot_info_min_focus_distance_step", "Min Focus Distance Step", base.HEX)
f.camera_camera_shot_info_masked1f = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_masked1f", "Masked1F", base.HEX)
  f.camera_camera_shot_info_digital_focus_m_enable = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_digital_focus_m_enable", "Digital Focus M Enable", base.HEX, nil, 0x01, nil)
  f.camera_camera_shot_info_digital_focus_a_enable = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_digital_focus_a_enable", "Digital Focus A Enable", base.HEX, nil, 0x02, nil)
f.camera_camera_shot_info_x_axis_focus_window_num = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_x_axis_focus_window_num", "X Axis Focus Window Num", base.HEX)
f.camera_camera_shot_info_y_axis_focus_window_num = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_y_axis_focus_window_num", "Y Axis Focus Window Num", base.HEX)
f.camera_camera_shot_info_mf_focus_status = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_mf_focus_status", "Mf Focus Status", base.HEX)
f.camera_camera_shot_info_focus_window_start_x = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_focus_window_start_x", "Focus Window Start X", base.HEX)
f.camera_camera_shot_info_focus_window_real_num_x = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_focus_window_real_num_x", "Focus Window Real Num X", base.HEX)
f.camera_camera_shot_info_focus_window_start_y = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_focus_window_start_y", "Focus Window Start Y", base.HEX)
f.camera_camera_shot_info_focus_window_real_num_y = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_focus_window_real_num_y", "Focus Window Real Num Y", base.HEX)
f.camera_camera_shot_info_support_type = ProtoField.uint8 ("dji_dumlv1.camera_camera_shot_info_support_type", "Support Type", base.HEX)

local function camera_camera_shot_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_shot_info_masked00, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_info_fuselage_focus_mode, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_info_shot_focus_mode, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_info_zoom_focus_type, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_info_shot_type, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_info_shot_fd_type, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_info_shot_connected, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_shot_focus_max_stroke, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_info_shot_focus_cur_stroke, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_info_obj_distance, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_shot_info_min_aperture, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_info_max_aperture, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_info_spot_af_axis_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_shot_info_spot_af_axis_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_shot_info_masked15, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_info_focus_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_mf_focus_probability, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_min_focus_distance, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_info_max_focus_distance, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_info_cur_focus_distance, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_info_min_focus_distance_step, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_shot_info_masked1f, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_info_digital_focus_m_enable, payload(offset, 1))
    subtree:add_le (f.camera_camera_shot_info_digital_focus_a_enable, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_x_axis_focus_window_num, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_y_axis_focus_window_num, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_mf_focus_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_focus_window_start_x, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_focus_window_real_num_x, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_focus_window_start_y, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_focus_window_real_num_y, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_shot_info_support_type, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 40) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Shot Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Shot Info: Payload size different than expected") end
end

-- Camera - Camera Timelapse Parms - 0x88

f.camera_camera_timelapse_parms_masked00 = ProtoField.uint8 ("dji_dumlv1.camera_camera_timelapse_parms_masked00", "Masked00", base.HEX)
  f.camera_camera_timelapse_parms_control_mode = ProtoField.uint8 ("dji_dumlv1.camera_camera_timelapse_parms_control_mode", "Control Mode", base.HEX, nil, 0x03, nil)
  f.camera_camera_timelapse_parms_gimbal_point_count = ProtoField.uint8 ("dji_dumlv1.camera_camera_timelapse_parms_gimbal_point_count", "Gimbal Point Count", base.HEX, nil, 0xfc, nil)
-- for i=0..point_count, each entry 12 bytes
f.camera_camera_timelapse_parms_interval = ProtoField.uint16 ("dji_dumlv1.camera_camera_timelapse_parms_interval", "Point Interval", base.HEX)
f.camera_camera_timelapse_parms_duration = ProtoField.uint32 ("dji_dumlv1.camera_camera_timelapse_parms_duration", "Point Duration", base.HEX)
f.camera_camera_timelapse_parms_yaw = ProtoField.uint16 ("dji_dumlv1.camera_camera_timelapse_parms_yaw", "Point Yaw", base.HEX, nil, nil)
f.camera_camera_timelapse_parms_roll = ProtoField.uint16 ("dji_dumlv1.camera_camera_timelapse_parms_roll", "Point Roll", base.HEX, nil, nil)
f.camera_camera_timelapse_parms_pitch = ProtoField.uint16 ("dji_dumlv1.camera_camera_timelapse_parms_pitch", "Point Pitch", base.HEX, nil, nil)

local function camera_camera_timelapse_parms_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_timelapse_parms_masked00, payload(offset, 1))
    subtree:add_le (f.camera_camera_timelapse_parms_control_mode, payload(offset, 1))
    local point_count = bit.band(payload(offset,1):le_uint(), 0xfc)
    subtree:add_le (f.camera_camera_timelapse_parms_gimbal_point_count, payload(offset, 1))
    offset = offset + 1

    local i = 0
    while i < point_count do
        i = i + 1

        subtree:add_le (f.camera_camera_timelapse_parms_interval, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.camera_camera_timelapse_parms_duration, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.camera_camera_timelapse_parms_yaw, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.camera_camera_timelapse_parms_roll, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.camera_camera_timelapse_parms_pitch, payload(offset, 2))
        offset = offset + 2

    end

    if (offset ~= 1 + 12 * point_count) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Timelapse Parms: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Timelapse Parms: Payload size different than expected") end
end

-- Camera - Camera Tracking Status - 0x89

f.camera_camera_tracking_status_masked00 = ProtoField.uint8 ("dji_dumlv1.camera_camera_tracking_status_masked00", "Masked00", base.HEX)
  f.camera_camera_tracking_status_get_status = ProtoField.uint8 ("dji_dumlv1.camera_camera_tracking_status_status", "Status", base.HEX, nil, 0x01, nil)
f.camera_camera_tracking_status_x_coord = ProtoField.uint16 ("dji_dumlv1.camera_camera_tracking_status_x_coord", "X Coord", base.DEC)
f.camera_camera_tracking_status_y_coord = ProtoField.uint16 ("dji_dumlv1.camera_camera_tracking_status_y_coord", "Y Coord", base.DEC)

local function camera_camera_tracking_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_tracking_status_masked00, payload(offset, 1))
    subtree:add_le (f.camera_camera_tracking_status_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tracking_status_x_coord, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tracking_status_y_coord, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 5) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Tracking Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Tracking Status: Payload size different than expected") end
end

-- Camera - Camera Fov Param - 0x8a

f.camera_camera_fov_param_image_width = ProtoField.uint32 ("dji_dumlv1.camera_camera_fov_param_image_width", "Image Width", base.DEC)
f.camera_camera_fov_param_image_height = ProtoField.uint32 ("dji_dumlv1.camera_camera_fov_param_image_height", "Image Height", base.DEC)
f.camera_camera_fov_param_image_ratio = ProtoField.uint32 ("dji_dumlv1.camera_camera_fov_param_image_ratio", "Image Ratio", base.HEX)
f.camera_camera_fov_param_lens_focal_length = ProtoField.uint32 ("dji_dumlv1.camera_camera_fov_param_lens_focal_length", "Lens Focal Length", base.DEC)

local function camera_camera_fov_param_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_fov_param_image_width, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_fov_param_image_height, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_fov_param_image_ratio, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_fov_param_lens_focal_length, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 16) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Fov Param: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Fov Param: Payload size different than expected") end
end

-- Camera - Camera Prepare Open Fan - 0xb4

f.camera_camera_prepare_open_fan_left_seconds = ProtoField.uint8 ("dji_dumlv1.camera_camera_prepare_open_fan_left_seconds", "Left Seconds", base.DEC)

local function camera_camera_prepare_open_fan_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_prepare_open_fan_left_seconds, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Prepare Open Fan: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Prepare Open Fan: Payload size different than expected") end
end

-- Camera - Camera Optics Zoom Mode - 0xb8

enums.CAMERA_OPTICS_ZOOM_MODE_ZOOM_MODE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
}

enums.CAMERA_OPTICS_ZOOM_MODE_ZOOM_SPEED_ENUM = {
    [0x78] = 'a',
    [0x79] = 'b',
    [0x7a] = 'c',
    [0x7b] = 'd',
    [0x7c] = 'e',
    [0x7d] = 'f',
    [0x7e] = 'g',
}

f.camera_camera_optics_zoom_mode_optics_zomm_mode = ProtoField.uint8 ("dji_dumlv1.camera_camera_optics_zoom_mode_optics_zomm_mode", "Optics Zomm Mode", base.HEX, enums.CAMERA_OPTICS_ZOOM_MODE_ZOOM_MODE_ENUM, nil, nil)
f.camera_camera_optics_zoom_mode_zoom_speed = ProtoField.uint8 ("dji_dumlv1.camera_camera_optics_zoom_mode_zoom_speed", "Zoom Speed", base.HEX, enums.CAMERA_OPTICS_ZOOM_MODE_ZOOM_SPEED_ENUM, nil, nil)
f.camera_camera_optics_zoom_mode_c = ProtoField.uint8 ("dji_dumlv1.camera_camera_optics_zoom_mode_c", "C", base.HEX)
f.camera_camera_optics_zoom_mode_d = ProtoField.uint8 ("dji_dumlv1.camera_camera_optics_zoom_mode_d", "D", base.HEX)

local function camera_camera_optics_zoom_mode_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_optics_zoom_mode_optics_zomm_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_optics_zoom_mode_zoom_speed, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_optics_zoom_mode_c, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_optics_zoom_mode_d, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Optics Zoom Mode: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Optics Zoom Mode: Payload size different than expected") end
end

-- Camera - Camera Tap Zoom State Info - 0xc7

enums.CAMERA_TAP_ZOOM_STATE_INFO_WORKING_STATE_ENUM = {
    [0x00] = 'IDLE',
    [0x01] = 'ZOOM_IN',
    [0x02] = 'ZOOM_OUT',
    [0xff] = 'Unknown',
}

f.camera_camera_tap_zoom_state_info_working_state = ProtoField.uint8 ("dji_dumlv1.camera_camera_tap_zoom_state_info_working_state", "Working State", base.HEX, enums.CAMERA_TAP_ZOOM_STATE_INFO_WORKING_STATE_ENUM, nil, nil)
f.camera_camera_tap_zoom_state_info_gimbal_state = ProtoField.uint8 ("dji_dumlv1.camera_camera_tap_zoom_state_info_gimbal_state", "Gimbal State", base.HEX)
f.camera_camera_tap_zoom_state_info_multiplier = ProtoField.uint8 ("dji_dumlv1.camera_camera_tap_zoom_state_info_multiplier", "Multiplier", base.HEX)

local function camera_camera_tap_zoom_state_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_tap_zoom_state_info_working_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tap_zoom_state_info_gimbal_state, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tap_zoom_state_info_multiplier, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 3) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Tap Zoom State Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Tap Zoom State Info: Payload size different than expected") end
end

-- Camera - Camera UnknownD3 - 0xd3

f.camera_camera_camera_unknownD3_field0 = ProtoField.bytes ("dji_dumlv1.camera_camera_camera_unknownD3_field0", "Field0", base.SPACE)

local function camera_camera_unknownD3_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request

        if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera UnknownD3: Offset does not match - internal inconsistency") end
    else -- Response

        subtree:add_le (f.camera_camera_camera_unknownD3_field0, payload(offset, 67))
        offset = offset + 67

        if (offset ~= 67) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera UnknownD3: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera UnknownD3: Payload size different than expected") end
end

-- Camera - Camera Tau Param - 0xf2

enums.CAMERA_TAU_PARAM_ZOOM_MODE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x02] = 'c',
}

enums.CAMERA_TAU_PARAM_AGC_AGC_TYPE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x02] = 'c',
    [0x03] = 'd',
    [0x04] = 'e',
    [0x05] = 'f',
    [0x06] = 'g',
    [0x07] = 'h',
    [0x08] = 'i',
    [0x64] = 'j',
}

enums.CAMERA_TAU_PARAM_ROI_TYPE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x02] = 'c',
    [0x64] = 'd',
}

enums.CAMERA_TAU_PARAM_THERMOMETRIC_TYPE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x02] = 'c',
    [0x63] = 'd',
}

enums.CAMERA_TAU_PARAM_GAIN_MODE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x02] = 'c',
    [0x64] = 'd',
}

enums.CAMERA_TAU_PARAM_VIDEO_RESOLUTION_ENUM = {
    [0x00] = 'VR_640',
    [0x01] = 'VR_336',
    [0xff] = 'UNKNOWN',
}

enums.CAMERA_TAU_PARAM_LEN_FOCUS_LENGTH_ENUM = {
    [0x00] = 'LFL_68',
    [0x01] = 'LFL_75',
    [0x02] = 'LFL_90',
    [0x03] = 'LFL_130',
    [0x04] = 'LFL_190',
    [0xff] = 'UNKNOWN',
}

enums.CAMERA_TAU_PARAM_LEN_FPS_ENUM = {
    [0x00] = 'FPS_LESS_9',
    [0x04] = 'FPS_30',
    [0xff] = 'UNKNOWN',
}

enums.CAMERA_TAU_PARAM_FFC_MODE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x64] = 'c',
}

enums.CAMERA_TAU_PARAM_EXTER_PARAM_TYPE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x02] = 'c',
    [0x63] = 'd',
}

f.camera_camera_tau_param_image_format = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_image_format", "Image Format", base.HEX)
f.camera_camera_tau_param_video_format = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_video_format", "Video Format", base.HEX)
f.camera_camera_tau_param_video_fps = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_video_fps", "Video Fps", base.HEX)
f.camera_camera_tau_param_zoom_mode = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_zoom_mode", "Zoom Mode", base.HEX, enums.CAMERA_TAU_PARAM_ZOOM_MODE_ENUM, nil, nil)
f.camera_camera_tau_param_zoom_scale = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_zoom_scale", "Zoom Scale", base.HEX)
f.camera_camera_tau_param_digital_filter = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_digital_filter", "Digital Filter", base.HEX)
f.camera_camera_tau_param_agc = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_agc", "Agc", base.HEX, enums.CAMERA_TAU_PARAM_AGC_AGC_TYPE_ENUM, nil, nil)
f.camera_camera_tau_param_dde = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_dde", "Dde", base.HEX)
f.camera_camera_tau_param_ace = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_ace", "Ace", base.HEX)
f.camera_camera_tau_param_sso = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_sso", "Sso", base.HEX)
f.camera_camera_tau_param_contrast = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_contrast", "Contrast", base.HEX)
f.camera_camera_tau_param_brightness = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_brightness", "Brightness", base.HEX)
f.camera_camera_tau_param_thermometric_x_axis = ProtoField.float ("dji_dumlv1.camera_camera_tau_param_thermometric_x_axis", "Thermometric X Axis", base.DEC)
f.camera_camera_tau_param_thermometric_y_axis = ProtoField.float ("dji_dumlv1.camera_camera_tau_param_thermometric_y_axis", "Thermometric Y Axis", base.DEC)
f.camera_camera_tau_param_thermometric_temp = ProtoField.float ("dji_dumlv1.camera_camera_tau_param_thermometric_temp", "Thermometric Temp", base.DEC)
f.camera_camera_tau_param_shot_count_down = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_shot_count_down", "Shot Count Down", base.HEX)
f.camera_camera_tau_param_roi_type = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_roi_type", "Roi Type", base.HEX, enums.CAMERA_TAU_PARAM_ROI_TYPE_ENUM, nil, nil)
f.camera_camera_tau_param_masked1f = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_masked1f", "Masked1F", base.HEX)
  f.camera_camera_tau_param_isotherm_enable = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_isotherm_enable", "Isotherm Enable", base.HEX, nil, 0x01, nil)
f.camera_camera_tau_param_isotherm_unit = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_isotherm_unit", "Isotherm Unit", base.HEX)
f.camera_camera_tau_param_isotherm_lower = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_isotherm_lower", "Isotherm Lower", base.HEX)
f.camera_camera_tau_param_isotherm_middle = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_isotherm_middle", "Isotherm Middle", base.HEX)
f.camera_camera_tau_param_isotherm_upper = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_isotherm_upper", "Isotherm Upper", base.HEX)
f.camera_camera_tau_param_thermometric_type = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_thermometric_type", "Thermometric Type", base.HEX, enums.CAMERA_TAU_PARAM_THERMOMETRIC_TYPE_ENUM, nil, nil)
f.camera_camera_tau_param_object_control = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_object_control", "Object Control", base.HEX)
f.camera_camera_tau_param_gain_mode = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_gain_mode", "Gain Mode", base.HEX, enums.CAMERA_TAU_PARAM_GAIN_MODE_ENUM, nil, nil)
f.camera_camera_tau_param_video_resolution = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_video_resolution", "Video Resolution", base.HEX, enums.CAMERA_TAU_PARAM_VIDEO_RESOLUTION_ENUM, nil, nil)
f.camera_camera_tau_param_len_focus_length = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_len_focus_length", "Len Focus Length", base.HEX, enums.CAMERA_TAU_PARAM_LEN_FOCUS_LENGTH_ENUM, nil, nil)
f.camera_camera_tau_param_len_fps = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_len_fps", "Len Fps", base.HEX, enums.CAMERA_TAU_PARAM_LEN_FPS_ENUM, nil, nil)
f.camera_camera_tau_param_photo_interval = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_photo_interval", "Photo Interval", base.HEX)
f.camera_camera_tau_param_unknown2e = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_unknown2e", "Unknown2E", base.HEX)
f.camera_camera_tau_param_ffc_mode = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_ffc_mode", "Ffc Mode", base.HEX, enums.CAMERA_TAU_PARAM_FFC_MODE_ENUM, nil, nil)
f.camera_camera_tau_param_masked30 = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_masked30", "Masked30", base.HEX)
  f.camera_camera_tau_param_support_spot_thermometric = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_support_spot_thermometric", "Support Spot Thermometric", base.HEX, nil, 0x01, nil)
  f.camera_camera_tau_param_thermometric_valid = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_thermometric_valid", "Thermometric Valid", base.HEX, nil, 0x80, nil)
f.camera_camera_tau_param_exter_param_type = ProtoField.uint8 ("dji_dumlv1.camera_camera_tau_param_exter_param_type", "Exter Param Type", base.HEX, enums.CAMERA_TAU_PARAM_EXTER_PARAM_TYPE_ENUM, nil, nil)
f.camera_camera_tau_param_target_emissivity = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_target_emissivity", "Target Emissivity", base.HEX)
f.camera_camera_tau_param_atmosphere_transmission = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_atmosphere_transmission", "Atmosphere Transmission", base.HEX)
f.camera_camera_tau_param_atmosphere_temperature = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_atmosphere_temperature", "Atmosphere Temperature", base.HEX)
f.camera_camera_tau_param_background_temperature = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_background_temperature", "Background Temperature", base.HEX)
f.camera_camera_tau_param_window_transmission = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_window_transmission", "Window Transmission", base.HEX)
f.camera_camera_tau_param_window_temperature = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_window_temperature", "Window Temperature", base.HEX)
f.camera_camera_tau_param_window_reflection = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_window_reflection", "Window Reflection", base.HEX)
f.camera_camera_tau_param_window_reflected_temperature = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_window_reflected_temperature", "Window Reflected Temperature", base.HEX)
f.camera_camera_tau_param_area_thermometric_left = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_area_thermometric_left", "Area Thermometric Left", base.HEX)
f.camera_camera_tau_param_area_thermometric_top = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_area_thermometric_top", "Area Thermometric Top", base.HEX)
f.camera_camera_tau_param_area_thermometric_right = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_area_thermometric_right", "Area Thermometric Right", base.HEX)
f.camera_camera_tau_param_area_thermometric_bottom = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_area_thermometric_bottom", "Area Thermometric Bottom", base.HEX)
f.camera_camera_tau_param_area_thermometric_average = ProtoField.float ("dji_dumlv1.camera_camera_tau_param_area_thermometric_average", "Area Thermometric Average", base.DEC)
f.camera_camera_tau_param_area_thermometric_min = ProtoField.float ("dji_dumlv1.camera_camera_tau_param_area_thermometric_min", "Area Thermometric Min", base.DEC)
f.camera_camera_tau_param_area_thermometric_max = ProtoField.float ("dji_dumlv1.camera_camera_tau_param_area_thermometric_max", "Area Thermometric Max", base.DEC)
f.camera_camera_tau_param_area_thermometric_min_x = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_area_thermometric_min_x", "Area Thermometric Min X", base.HEX)
f.camera_camera_tau_param_area_thermometric_min_y = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_area_thermometric_min_y", "Area Thermometric Min Y", base.HEX)
f.camera_camera_tau_param_area_thermometric_max_x = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_area_thermometric_max_x", "Area Thermometric Max X", base.HEX)
f.camera_camera_tau_param_area_thermometric_max_y = ProtoField.uint16 ("dji_dumlv1.camera_camera_tau_param_area_thermometric_max_y", "Area Thermometric Max Y", base.HEX)

local function camera_camera_tau_param_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.camera_camera_tau_param_image_format, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_video_format, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_video_fps, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_zoom_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_zoom_scale, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_digital_filter, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_agc, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_dde, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_ace, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_sso, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_contrast, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_brightness, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_thermometric_x_axis, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_tau_param_thermometric_y_axis, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_tau_param_thermometric_temp, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_tau_param_shot_count_down, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_roi_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_masked1f, payload(offset, 1))
    subtree:add_le (f.camera_camera_tau_param_isotherm_enable, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_isotherm_unit, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_isotherm_lower, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_isotherm_middle, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_isotherm_upper, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_thermometric_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_object_control, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_gain_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_video_resolution, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_len_focus_length, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_len_fps, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_photo_interval, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_unknown2e, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_ffc_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_masked30, payload(offset, 1))
    subtree:add_le (f.camera_camera_tau_param_support_spot_thermometric, payload(offset, 1))
    subtree:add_le (f.camera_camera_tau_param_thermometric_valid, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_exter_param_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.camera_camera_tau_param_target_emissivity, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_atmosphere_transmission, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_atmosphere_temperature, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_background_temperature, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_window_transmission, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_window_temperature, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_window_reflection, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_window_reflected_temperature, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_left, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_top, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_right, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_bottom, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_average, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_min, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_max, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_min_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_min_y, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_max_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.camera_camera_tau_param_area_thermometric_max_y, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 94) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Camera Tau Param: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Camera Tau Param: Payload size different than expected") end
end

CAMERA_UART_CMD_DISSECT = {
    [0x7c] = camera_camera_shutter_cmd_dissector,
    [0x80] = camera_camera_state_info_dissector,
    [0x81] = camera_camera_shot_params_dissector,
    [0x82] = camera_camera_play_back_params_dissector,
    [0x83] = camera_camera_chart_info_dissector,
    [0x84] = camera_camera_recording_name_dissector,
    [0x85] = camera_camera_raw_params_dissector,
    [0x86] = camera_camera_cur_pano_file_name_dissector,
    [0x87] = camera_camera_shot_info_dissector,
    [0x88] = camera_camera_timelapse_parms_dissector,
    [0x89] = camera_camera_tracking_status_dissector,
    [0x8a] = camera_camera_fov_param_dissector,
    [0xb4] = camera_camera_prepare_open_fan_dissector,
    [0xb8] = camera_camera_optics_zoom_mode_dissector,
    [0xc7] = camera_camera_tap_zoom_state_info_dissector,
    [0xd3] = camera_camera_unknownD3_dissector,
    [0xf2] = camera_camera_tau_param_dissector,
}
