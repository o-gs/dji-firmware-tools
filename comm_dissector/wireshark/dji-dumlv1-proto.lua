-- Create a new dissector
DJI_DUMLv1_PROTO = Proto ("dji_dumlv1", "DJI_DUMLv1", "Dji DUML v1 communication protocol")

local f = DJI_DUMLv1_PROTO.fields
local enums = {}

DJI_DUMLv1_SRC_DEST_TEXT = {
    [0] = 'Invalid/Any',
    [1] = 'Camera (Ambarella)',
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
    [31] = 'Last',
}

DJI_DUMLv1_ACK_TYPE_TEXT = {
    [0] = 'No ACK Needed', -- No returning packet requested
    [1] = 'ACK Before Exec', -- also called PUSH
    [2] = 'ACK After Exec', -- Acknowledge and return result code
}

DJI_DUMLv1_ENCRYPT_TYPE_TEXT = {
    [0] = 'None',
    [1] = 'AES 128',
    [2] = 'Self Def',
    [3] = 'Xor',
    [4] = 'DES 56',
    [5] = 'DES 112',
    [6] = 'AES 192',
    [7] = 'AES 256',
}

DJI_DUMLv1_PACKET_TYPE_TEXT = {
    [0] = 'Request',
    [1] = 'Response',
}

DJI_DUMLv1_CMD_SET_TEXT = {
    [0] = 'General',
    [1] = 'Special',
    [2] = 'Camera',
    [3] = 'Flight Control',
    [4] = 'Gimbal',
    [5] = 'Center Board',
    [6] = 'Remote Control',
    [7] = 'Wi-Fi',
    [8] = 'DM36x',
    [9] = 'HD Link',
    [10] = 'Mono/Binocular', -- aka Vision
    [11] = 'Simulator',
    [12] = 'ESC',
    [13] = 'Battery',
    [14] = 'Data Logger', -- aka HD Link Ground 1765
    [15] = 'RTK', -- S-to-P Air
    [16] = 'Automation', -- S-to-P Ground
    [17] = 'ADSB',
    [18] = 'BVision',
    [19] = 'FPGA Air',
    [20] = 'FPGA Ground',
    [21] = 'Glass',
    [22] = 'MavLink',
    [23] = 'Watch',
    [28] = 'RM',
    [33] = 'MAX',
}

-- CMD name decode tables

local SPECIAL_UART_CMD_TEXT = {
    [0x00] = 'Sdk Ctrl Mode Open/Close Nav',
    [0x01] = 'Old Special App Control', -- Try To Exec V1 Special Function
    [0x02] = 'Old Special Remote Control',
    [0x03] = 'New Special App Control', -- Try To Exec V2 Special Function
    [0x04] = 'New Special Remote Control', -- ie. Ctrl Mode Emergency Brake
    [0x05] = 'SDK Ctrl Mode Arm/Disarm',
    [0x1a] = 'SDK Ctrl Gimbal Speed Ctrl',
    [0x1b] = 'SDK Ctrl Gimbal Angle Ctrl',
    [0x20] = 'SDK Ctrl Camera Shot Ctrl',
    [0x21] = 'SDK Ctrl Camera Start Video Ctrl',
    [0x22] = 'SDK Ctrl Camera Stop Video Ctrl',
    [0xff] = 'UAV Loopback',
}

local CENTER_BRD_UART_CMD_TEXT = {
    [0x00] = 'Center Open/Close Virtual RC',
    [0x01] = 'Center Virtual RC Data',
    --[0x01] = 'Center Req Batt Info Confirm', -- on newer platforms
    [0x02] = 'Center Push Batt Dynamic Info',
    [0x03] = 'Center Control Uav Status Led',
    [0x04] = 'Center Transform Control',
    [0x05] = 'Center Req Push Bat Normal Data',
    [0x06] = 'Center Battery Common', -- Center Push Bat Normal Data
    [0x07] = 'Center Query Bat Status',
    [0x08] = 'Center Query Bat Hisoty Status',
    [0x09] = 'Center Bat SelfDischarge Days',
    [0x0a] = 'Center Bat Storage Info',
    [0x21] = 'Center Req Bat Static Data',
    [0x22] = 'Center Req Bat Dynamic Data',
    [0x23] = 'Center Req Bat Auth Data',
    [0x24] = 'Center Req Bat Auth Result',
    [0x31] = 'Center Req Bat SelfDischarge Time',
    [0x32] = 'Center Set Bat SelfDischarge Time',
    [0x33] = 'Center Req Bat Barcode',
}

local RC_UART_CMD_TEXT = {
    [0x01] = 'RC Channel Params Get', -- includes Logic Channel Mapping
    [0x02] = 'RC Channel Params Set',
    [0x03] = 'RC Calibiration Set',
    [0x04] = 'RC Physical Channel Parameter Get',
    [0x05] = 'RC Parameter Get/Push',
    [0x06] = 'RC Master/Slave Mode Set',
    [0x07] = 'RC Master/Slave Mode Get',
    [0x08] = 'RC Name Set',
    [0x09] = 'RC Name Get',
    [0x0a] = 'RC Password Set',
    [0x0b] = 'RC Password Get',
    [0x0c] = 'RC Connected Master Id Set',
    [0x0d] = 'RC Connected Master Id Get',
    [0x0e] = 'RC Available Master Id Get',
    [0x0f] = 'RC Search Mode Set',
    [0x10] = 'RC Search Mode Get',
    [0x11] = 'RC Master/Slave Switch Set',
    [0x12] = 'RC Master/Slave Switch Conf Get',
    [0x13] = 'RC Request Join By Slave',
    [0x14] = 'RC List Request Join Slave',
    [0x15] = 'RC Delete Slave',
    [0x16] = 'RC Delete Master',
    [0x17] = 'RC Slave Control Right Set',
    [0x18] = 'RC Slave Control Right Get',
    [0x19] = 'RC Control Mode Set',
    [0x1a] = 'RC Control Mode Get',
    [0x1b] = 'RC GPS Info Get/Push',
    [0x1c] = 'RC RTC Info Get/Push',
    [0x1d] = 'RC Temperature Info Get/Push',
    [0x1e] = 'RC Battery Info Get/Push',
    [0x1f] = 'RC Master/Slave Conn Info Get/Push',
    [0x20] = 'RC Power Mode CE/FCC Set',
    [0x21] = 'RC Power Mode CE/FCC Get',
    [0x22] = 'RC Gimbal Ctr Permission Request',
    [0x23] = 'RC Gimbal Ctr Permission Ack',
    [0x24] = 'RC Simulate Flight Mode Set',
    [0x25] = 'RC Simulate Flight Mode Get',
    [0x26] = 'RC AETR Value Push', -- Get Sim Push Params
    [0x27] = 'RC Detection Info Get',
    [0x28] = 'RC Gimbal Control Access Right Get',
    [0x29] = 'RC Slave Control Mode Set',
    [0x2a] = 'RC Slave Control Mode Get',
    [0x2b] = 'RC Gimbal Control Speed Set',
    [0x2c] = 'RC Gimbal Control Speed Get',
    [0x2d] = 'RC Self Defined Key Func Set', -- Custom Fuction Set
    [0x2e] = 'RC Self Defined Key Func Get',
    [0x2f] = 'RC Pairing', -- Frequency Set
    [0x30] = 'RC Test GPS',
    [0x31] = 'RC RTC Clock Set',
    [0x32] = 'RC RTC Clock Get', -- See m0101 sys partiton for payload info
    [0x33] = 'RC Gimbal Control Sensitivity Set', -- Wheel Gain Set
    [0x34] = 'RC Gimbal Control Sensitivity Get',
    [0x35] = 'RC Gimbal Control Mode Set',
    [0x36] = 'RC Gimbal Control Mode Get',
    [0x37] = 'RC Enter App Mode Request',
    [0x38] = 'RC Calibration Value Get',
    [0x39] = 'RC Master Slave Connect Status Push',
    [0x3a] = 'RC 2014 Usb Mode Set',
    [0x3b] = 'RC Id Set',
    [0x3c] = 'RC Coach Mode',
    [0x3f] = 'RC Mater/Slave Id',
    [0x42] = 'RC Follow Focus Get/Push',
    [0x47] = 'RC App Special Control',
    [0x48] = 'RC Freq Mode Info Get', -- RC Param Get
    [0x4c] = 'RC Pro Custom Buttons Status Get/Push',
    [0x50] = 'RC Push Rmc Key Info', -- MCU407 Set
    [0x51] = 'RC Push To Glass', -- RC Custom Buttons Status Get/Push
    [0x52] = 'RC Push LCD To MCU',
    [0x53] = 'RC Unit Language Get',
    [0x54] = 'RC Unit Language Set',
    [0x55] = 'RC Test Mode Set',
    [0x56] = 'RC Quiry Role', -- RC Role Get
    [0x57] = 'RC Quiry Ms Link Status', -- FD Push Connect Status Get
    [0x58] = 'RC Work Function Set', -- New Control Function Set
    [0x59] = 'RC Work Function Get',
	[0x98] = 'Follow Focus2 Get/Push',
    [0x99] = 'Follow Focus Info Set',
    [0xf0] = 'RC RF Cert Config Set', -- Set Transciever Pwr Mode
    [0xf5] = 'RC Test Stick Value',
    [0xf6] = 'RC Factory Get Board Id',
    [0xf7] = 'RC Push Buzzer To MCU',
    [0xf8] = 'RC Stick Verification Data Get', -- FD Rc Calibration Statue Get
    [0xf9] = 'RC Post Calibiration Set',
    [0xfa] = 'RC Stick Middle Value Get',
}

local WIFI_UART_CMD_TEXT = {
    [0x00] = 'WiFi Reserved',
    [0x01] = 'WiFi Ap Scan Results Push',
    [0x02] = 'WiFi Ap Channel SNR Get',
    [0x03] = 'WiFi Ap Channel Set',
    [0x04] = 'WiFi Ap Channel Get',
    [0x05] = 'WiFi Ap Tx Pwr Set',
    [0x06] = 'WiFi Ap Tx Pwr Get',
    [0x07] = 'WiFi Ap SSID Get',
    [0x08] = 'WiFi Ap SSID Set',
    [0x09] = 'WiFi Ap RSSI Push',
    [0x0a] = 'WiFi Ap Ant RSSI Get',
    [0x0b] = 'WiFi Ap Mac Addr Set',
    [0x0c] = 'WiFi Ap Mac Addr Get',
    [0x0d] = 'WiFi Ap Passphrase Set',
    [0x0e] = 'WiFi Ap Passphrase Get', -- Get PSK/Password
    [0x0f] = 'WiFi Ap Factory Reset',
    [0x10] = 'WiFi Ap Band Set', -- Wifi Frequency Set
    [0x11] = 'WiFi Ap Sta MAC Push', -- First App Mac Get/Push
    [0x12] = 'WiFi Ap Phy Param Get', -- Electric Signal Get/Push
    [0x13] = 'WiFi Ap Power Mode Set',
    [0x14] = 'WiFi Ap Calibrate',
    [0x15] = 'WiFi Ap Wifi Restart',
    [0x16] = 'WiFi Ap Selection Mode Set',
    [0x17] = 'WiFi Ap Selection Mode Get',
    [0x18] = 'WiFi Ap 18',
    [0x19] = 'WiFi Ap 19',
    [0x1a] = 'WiFi Ap 1A',
    [0x1b] = 'WiFi Ap 1B',
    [0x1c] = 'WiFi Ap 1C',
    [0x1d] = 'WiFi Ap 1D',
    [0x1e] = 'WiFi SSID Get', -- older variant?
    [0x1f] = 'WiFi Ap 1F',
    [0x20] = 'WiFi Ap Wifi Frequency Get',
    [0x21] = 'WiFi Ap Set Bw',
    [0x22] = 'WiFi Ap 22',
    [0x23] = 'WiFi Ap 23',
    [0x24] = 'WiFi Ap 24',
    [0x25] = 'WiFi Ap 25',
    [0x26] = 'WiFi Ap Realtime Acs', -- Noise Check Adapt Set
    [0x27] = 'WiFi Ap Manual Switch SDR',
    [0x28] = 'WiFi Ap Channel List Get/Push',
    [0x29] = 'WiFi Ap Channel Noise/SNR Req',
    [0x2a] = 'WiFi Ap Channel Noise/SNR Push', -- Wifi Sweep Frequency Get
    [0x2b] = 'WiFi Ap Set Hw Mode', -- Wifi Mode Channel Set
    [0x2c] = 'Wifi Ap Code Rate Set',
    [0x2d] = 'Wifi Ap Cur Code Rate Get',
    [0x2e] = 'WiFi Ap Set Usr Pref', -- Wifi Freq 5G Mode Set
    [0x2f] = 'WiFi Ap Get Usr Pref', -- Wifi Freq Mode Get
    [0x30] = 'WiFi Ap Set Country Code', -- Set Region
    [0x31] = 'WiFi Ap Reset Freq',
    [0x32] = 'WiFi Ap Del Country Code',
    [0x33] = 'WiFi Ap Verify Cc', -- Is Country Code Supported
    [0x39] = 'WiFi Get Work Mode',
    [0x3a] = 'WiFi Set Work Mode',
    [0x3b] = 'WiFi Config By Qrcode',
    [0x80] = 'WiFi Push Mac Stat', -- Log Get/Push
    [0x82] = 'WiFi Master/Slave Status Get/Push',
    [0x83] = 'WiFi Master/Slave AuthCode Set',
    [0x84] = 'WiFi Scan Master List',
    [0x85] = 'WiFi Connect Master With Id AuthCode',
    [0x89] = 'WiFi AuthCode Get',
    [0x8B] = 'WiFi MS Error Info Get/Push',
    [0x91] = 'WiFi Rc Info Set',
    [0x92] = 'WiFi Update Sw State',
}

local DM36X_UART_CMD_TEXT = {
    [0x00] = 'DM36x Reserved',
    [0x01] = 'DM36x Gnd Ctrl Info Send',
    [0x02] = 'DM36x Gnd Ctrl Info Recv',
    [0x03] = 'DM36x UAV Ctrl Info Send',
    [0x04] = 'DM36x UAV Ctrl Info Recv',
    [0x05] = 'DM36x Gnd Stat Info Send',
    [0x06] = 'DM36x UAV Stat Info Send',
    [0x05] = 'DM36x Gnd Stat Info Recv',
    [0x0e] = 'DM36x App Connect Stat Get',
    [0x0f] = 'DM36x Recycle Vision Frame Info',
    [0x20] = 'DM36x Bitrate Set', -- Wifi Code Rate Set
    [0x21] = 'DM36x Bitrate Get',
    [0x30] = 'DM36x Foresight Showed Set', -- Status Push
    [0x31] = 'DM36x Foresight Showed Get', -- Send Vmem Fd To Vision
    [0x60] = 'Active Track Camera Set',
}

local HD_LINK_UART_CMD_TEXT = {
    [0x01] = 'HDLnk OSD General Data Get/Push',
    [0x02] = 'HDLnk OSD Home Point Get/Push',
    [0x03] = 'HDLnk Baseband State Get/Push',
    [0x04] = 'HDLnk FPGA Write',
    [0x05] = 'HDLnk FPGA Read',
    [0x06] = 'HDLnk TCX Hardware Reg Write', -- Set register in AD9363
    [0x07] = 'HDLnk TCX Hardware Reg Read', -- Get register from AD9363
    [0x08] = 'HDLnk VT Signal Quality Push', -- Video transmission signal strength
    [0x09] = 'HDLnk Sweep Frequency Set', -- Req Freq Energy
    [0x0a] = 'HDLnk Sweep Frequency Get/Push',
    [0x0b] = 'HDLnk Device Status Get/Push',
    [0x0c] = 'HDLnk VT Config Info Get/Push', -- Video transmission config info
    [0x0d] = 'HDLnk VT Config Info Set',
    [0x0e] = 'HDLnk USB Iface Change', -- Usb Transform Set; See m0101 sys partiton for payload info
    [0x0f] = 'HDLnk Reset Cy68013', -- See m0101 sys partiton for payload info
    [0x10] = 'HDLnk Upgrade Tip Set',
    [0x11] = 'HDLnk Wl Env Quality Get/Push',
    [0x12] = 'HDLnk Factory Test Set', -- Set Transciever Config to test
    [0x13] = 'HDLnk Factory Test Get',
    [0x14] = 'HDLnk Max Video Bandwidth Set', -- Set Max Mcs
    [0x15] = 'HDLnk Max Video Bandwidth Get/Push',
    [0x16] = 'HDLnk Debug Info Push',
    [0x20] = 'HDLnk SDR Downward Sweep Frequency', -- SDR Dl Freq Energy Get/Push
    [0x21] = 'HDLnk SDR Vt Config Info Get',
    [0x22] = 'HDLnk SDR Dl Auto Vt Info Get/Push',
    [0x23] = 'HDLnk SDR Rt Status Set',
    [0x24] = 'HDLnk SDR UAV Rt Status Get/Push',
    [0x25] = 'HDLnk SDR Gnd Rt Status Get/Push', -- SDR Status Ground Info
    [0x26] = 'HDLnk SDR Debug/Assitant Read',
    [0x27] = 'HDLnk SDR Debug/Assitant Write',
    [0x28] = 'HDLnk SDR Start Log Set',
    [0x29] = 'HDLnk SDR Upward Sweep Frequency', -- SDR Ul Freq Energy Push
    [0x2a] = 'HDLnk SDR Upward Select Channel', -- SDR Ul Auto Vt Info Push
    [0x2b] = 'HDLnk SDR Revert Role',
    [0x2c] = 'HDLnk SDR Amt Process',
    [0x2d] = 'HDLnk SDR LBT Status Get',
    [0x2e] = 'HDLnk SDR LBT Status Set',
    [0x2f] = 'HDLnk SDR Link Test',
    [0x30] = 'HDLnk SDR Wireless Env State', -- Wireless Status Get/Push
    [0x31] = 'HDLnk SDR Scan Freq Cfg',
    [0x32] = 'HDLnk SDR Factory Mode Set',
    [0x33] = 'HDLnk Tracking State Ind',
    [0x34] = 'HDLnk SDR Liveview Mode Set', -- SDR Image Transmission Mode Set
    [0x35] = 'HDLnk SDR Liveview Mode Get',
    [0x36] = 'HDLnk SDR Liveview Rate Ind', -- SDR Push Custom Code Rate
    [0x37] = 'HDLnk Abnormal Event Ind', -- aka HDTV Exception
    [0x38] = 'HDLnk SDR Set Rate',
    [0x39] = 'HDLnk Liveview Config Set', -- SDR Config Info Set
    [0x3a] = 'HDLnk Dl Freq Energy Push', -- SDR Nf Params
    [0x3b] = 'HDLnk SDR Tip Interference', -- SDR Bar Disturb Get/Push
    [0x3c] = 'HDLnk SDR Upgrade Rf Power', -- SDR Force Boost Set
    [0x3e] = 'HDLnk Slave RT Status Push',
    [0x3f] = 'HDLnk RC Conn Status Push',
    [0x41] = 'HDLnk Racing Set Modem Info',
    [0x42] = 'HDLnk Racing Get Modem Info',
    [0x50] = 'HDLnk LED Set',
    [0x51] = 'HDLnk Power Set', -- Robomaster Cnfg Set
    --[0x51] = 'HDLnk Robomaster Cnfg Set', -- only for robomaster, or only newer platforms
    [0x52] = 'HDLnk Power Status Get/Push',
    --[0x52] = 'HDLnk Robomaster Info Get', -- only for robomaster, or only newer platforms
    [0x53] = 'HDLnk SDR Cp Status Get',
    --[0x53] = 'Osmo Calibration Set', -- on osmo
    [0x54] = 'Osmo Calibration Push',
    [0x57] = 'HDLnk Mic Gain Set',
    [0x58] = 'HDLnk Mic Gain Get',
    [0x59] = 'HDLnk Mic Info Get/Push',
    [0x62] = 'HDLnk Mic Enable Get',
    [0x63] = 'HDLnk Mic Enable Set',
    [0x71] = 'HDLnk Main Camera Bandwidth Percent Set',
    [0x72] = 'HDLnk Main Camera Bandwidth Percent Get',
}

local MBINO_UART_CMD_TEXT = {
    [0x01] = 'Eye Bino Info', -- log
    [0x02] = 'Eye Mono Info',
    [0x03] = 'Eye Ultrasonic Info',
    [0x04] = 'Eye Oa Info',
    [0x05] = 'Eye Relitive Pos',
    [0x06] = 'Eye Avoidance Param', -- Avoidance Warn Parameters
    [0x07] = 'Eye Obstacle Info', -- Front Obstacle Avoidance
    [0x08] = 'Eye TapGo Obst Avo Info', -- Obstacle Avoidance during Go To Point / Point To Fly
    [0x0a] = 'Eye Push Vision Debug Info',
    [0x0b] = 'Eye Push Control Debug Info',
    [0x0d] = 'Eye Track Log',
    [0x0e] = 'Eye Point Log',
    [0x0f] = 'Eye Push SDK Control Cmd',
    [0x10] = 'Eye Enable Tracking Taptogo',
    [0x11] = 'Eye Push Target Speed Pos Info',
    [0x12] = 'Eye Push Target Pos Info',
    [0x13] = 'Eye Push Trajectory',
    [0x14] = 'Eye Push Expected Speed Angle',
    [0x15] = 'Eye Receive Frame Info',
    [0x19] = 'Eye Flat Check',
    [0x1d] = 'Eye Fixed Wing Ctrl',
    [0x1e] = 'Eye Fixed Wing Status Push',
    [0x20] = 'Eye Marquee Push',
    [0x21] = 'Eye Tracking Cnf Cancel',
    [0x22] = 'Eye Move Marquee Push',
    [0x23] = 'Eye Tracking Status Push',
    [0x24] = 'Eye Position Push',
    [0x25] = 'Eye Fly Ctl Push',
    [0x26] = 'Eye TapGo Status Push', -- Status of Go To Point / Point To Fly
    [0x27] = 'Eye Common Ctl Cmd',
    [0x28] = 'Eye Get Para Cmd',
    [0x29] = 'Eye Set Para Cmd',
    [0x2a] = 'Eye Com Status Update', -- The update basically means Exception
    [0x2c] = 'Eye Ta Lock Update',
    [0x2d] = 'Eye Smart Landing',
    [0x2e] = 'Eye Function List Push',
    [0x2f] = 'Eye Sensor Status Push', -- Informs of Sensor Exceptions
    [0x30] = 'Eye Self Calibration',
    [0x32] = 'Eye Easy Self Calib State',
    [0x37] = 'Eye QRCode Mode',
    [0x39] = 'Eye Vision Tip',
    [0x3a] = 'Eye Precise Landing Energy',
    [0x46] = 'Eye RC Packet',
    [0x47] = 'Eye Set Buffer Config',
    [0x48] = 'Eye Get Buffer Config',
    [0xa3] = 'Eye Enable SDK Func',
    [0xa4] = 'Eye Detection Msg Push',
    [0xa5] = 'Eye Get SDK Func',
}

local SIM_UART_CMD_TEXT = {
    [0x01] = 'Simu Connect Heart Packet',
    [0x02] = 'Simu IMU Status Push', -- Main Controller Params Request
    [0x03] = 'Simu SDR Status Push', -- Main Controller Return Params Get/Push
    [0x04] = 'Simu Get Headbelt SN', -- Simulate Flight Commend
    [0x06] = 'Simu Flight Status Params',
    [0x07] = 'Simu GetWind Set',
    [0x08] = 'Simu GetArea Set',
    [0x09] = 'Simu GetAirParams Set',
    [0x0a] = 'Simu Force Moment',
    [0x0b] = 'Simu GetTemperature Set',
    [0x0c] = 'Simu GetGravity Set',
    [0x0d] = 'Simu Crash ShutDown',
    [0x0e] = 'Simu Ctrl Motor',
    [0x0f] = 'Simu Momentum',
    [0x10] = 'Simu GetArmLength Set',
    [0x11] = 'Simu GetMassInertia Set',
    [0x12] = 'Simu GetMotorSetting Set',
    [0x13] = 'Simu GetBatterySetting Set',
    [0x14] = 'Simu Frequency Get',
    [0x1a] = 'Simu Set Sim Vision Mode',
    [0x1b] = 'Simu Get Sim Vision Mode',
}

local ESC_UART_CMD_TEXT = {
}

local BATTERY_UART_CMD_TEXT = {
    [0x01] = 'Battery Static Data Get',
    [0x02] = 'Battery Dynamic Data Get/Push',
    [0x03] = 'Battery Cell Voltage Get/Push', -- Get Single Core Volt
    [0x04] = 'Battery BarCode Data Get',
    [0x05] = 'Battery History Get',
    [0x06] = 'Battery Push Common Info',
    [0x11] = 'Battery SetSelfDischargeDays Get',
    [0x12] = 'Battery ShutDown',
    [0x13] = 'Battery Force ShutDown',
    [0x14] = 'Battery StartUp',
    [0x15] = 'Battery Pair Get',
    [0x16] = 'Battery Pair Set',
    [0x22] = 'Battery Data Record Control',
    [0x23] = 'Battery Authentication',
    [0x31] = 'Battery Re-Arrangement Get/Push',
    [0x32] = 'Battery Mult Battery Info Get',
}

local DATA_LOG_UART_CMD_TEXT = {
    [0x22] = 'DLog Battery Data',
    [0x23] = 'DLog Battery Message',
}

local RTK_UART_CMD_TEXT = {
    [0x09] = 'Rtk Status',
}

local AUTO_UART_CMD_TEXT = {
}

local ADSB_UART_CMD_TEXT = {
}

dofile('dji-dumlv1-general.lua')
dofile('dji-dumlv1-camera.lua')
dofile('dji-dumlv1-flyc.lua')
dofile('dji-dumlv1-gimbal.lua')

DJI_DUMLv1_CMD_TEXT = {
    [0x00] = GENERAL_UART_CMD_TEXT,
    [0x01] = SPECIAL_UART_CMD_TEXT,
    [0x02] = CAMERA_UART_CMD_TEXT,
    [0x03] = FLYC_UART_CMD_TEXT,
    [0x04] = GIMBAL_UART_CMD_TEXT,
    [0x05] = CENTER_BRD_UART_CMD_TEXT,
    [0x06] = RC_UART_CMD_TEXT,
    [0x07] = WIFI_UART_CMD_TEXT,
    [0x08] = DM36X_UART_CMD_TEXT,
    [0x09] = HD_LINK_UART_CMD_TEXT,
    [0x0a] = MBINO_UART_CMD_TEXT,
    [0x0b] = SIM_UART_CMD_TEXT,
    [0x0c] = ESC_UART_CMD_TEXT,
    [0x0d] = BATTERY_UART_CMD_TEXT,
    [0x0e] = DATA_LOG_UART_CMD_TEXT,
    [0x0f] = RTK_UART_CMD_TEXT,
    [0x10] = AUTO_UART_CMD_TEXT,
    [0x11] = ADSB_UART_CMD_TEXT,
}

local function set_info(cmd, pinfo, valuestring)
    if tostring(pinfo.cols.info) ~= "" then
        pinfo.cols.info:append(", ")
    end
    if valuestring[cmd] == nil then
        pinfo.cols.info:append(string.format("%s (0x%02X)", "Unknown", cmd))
    else
        pinfo.cols.info:append(valuestring[cmd])
    end
end

-- Special - Old Special App Control - 0x01
-- Supported in: P3X_FW_V01.11.0030_m0400

f.special_old_special_app_control_unknown0 = ProtoField.uint8 ("dji_dumlv1.special_old_special_app_control_unknown0", "Unknown0", base.HEX)
f.special_old_special_app_control_unknown1 = ProtoField.uint8 ("dji_dumlv1.special_old_special_app_control_unknown1", "Unknown1", base.HEX)
f.special_old_special_app_control_unknown2 = ProtoField.uint8 ("dji_dumlv1.special_old_special_app_control_unknown2", "Unknown2", base.HEX)
f.special_old_special_app_control_unknown4 = ProtoField.uint8 ("dji_dumlv1.special_old_special_app_control_unknown4", "Unknown4", base.HEX)
f.special_old_special_app_control_unknown5 = ProtoField.uint8 ("dji_dumlv1.special_old_special_app_control_unknown5", "Unknown5", base.HEX)
f.special_old_special_app_control_unknown6 = ProtoField.uint8 ("dji_dumlv1.special_old_special_app_control_unknown6", "Unknown6", base.HEX)
f.special_old_special_app_control_unknown7 = ProtoField.uint8 ("dji_dumlv1.special_old_special_app_control_unknown7", "Unknown7", base.HEX)
f.special_old_special_app_control_checksum = ProtoField.uint8 ("dji_dumlv1.special_old_special_app_control_checksum", "Checksum", base.HEX, nil, nil, "Previous payload bytes xor'ed together with initial seed 0.")

f.special_old_special_app_control_status = ProtoField.uint8 ("dji_dumlv1.special_old_special_app_control_status", "Status", base.HEX)

local function special_old_special_app_control_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request

        subtree:add_le (f.special_old_special_app_control_unknown0, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.special_old_special_app_control_unknown1, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.special_old_special_app_control_unknown2, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.special_old_special_app_control_unknown4, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.special_old_special_app_control_unknown5, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.special_old_special_app_control_unknown6, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.special_old_special_app_control_unknown7, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.special_old_special_app_control_checksum, payload(offset, 1))
        offset = offset + 1

        if (offset ~= 10) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Old Special App Control: Offset does not match - internal inconsistency") end
    else -- Response

        subtree:add_le (f.special_old_special_app_control_status, payload(offset, 1))
        offset = offset + 1

        if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Old Special App Control: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Old Special App Control: Payload size different than expected") end
end

-- Special - New Special App Control - 0x03

f.special_new_special_app_control_unknown0 = ProtoField.bytes ("dji_dumlv1.special_new_special_app_control_unknown0", "Unknown0", base.SPACE)

local function special_new_special_app_control_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.special_new_special_app_control_unknown0, payload(offset, 24))
    offset = offset + 24

    if (offset ~= 24) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"New Special App Control: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"New Special App Control: Payload size different than expected") end
end

local SPECIAL_UART_CMD_DISSECT = {
    [0x01] = special_old_special_app_control_dissector,
    [0x03] = special_new_special_app_control_dissector,
}

-- Center Board - Center Battery Common - 0x06

enums.CENTER_BRD_CENTER_BATTERY_COMMON_CONN_STATUS_ENUM = {
    [0x00] = 'NORMAL',
    [0x01] = 'INVALID',
    [0x02] = 'EXCEPTION',
    [0x64] = 'OTHER',
}

f.center_brd_center_battery_common_relative_capacity = ProtoField.uint8 ("dji_dumlv1.center_brd_center_battery_common_relative_capacity", "Relative Capacity", base.DEC, nil, nil, "Remaining Capacity percentage")
f.center_brd_center_battery_common_current_pv = ProtoField.uint16 ("dji_dumlv1.center_brd_center_battery_common_current_pv", "Current Pv", base.DEC, nil, nil, "Current Pack Voltage")
f.center_brd_center_battery_common_current_capacity = ProtoField.uint16 ("dji_dumlv1.center_brd_center_battery_common_current_capacity", "Current Capacity", base.DEC, nil, nil, "Current Remaining Capacity")
f.center_brd_center_battery_common_full_capacity = ProtoField.uint16 ("dji_dumlv1.center_brd_center_battery_common_full_capacity", "Full Capacity", base.DEC, nil, nil, "Full Charge Capacity")
f.center_brd_center_battery_common_life = ProtoField.uint8 ("dji_dumlv1.center_brd_center_battery_common_life", "Life", base.DEC, nil, nil, "Life Percentage")
f.center_brd_center_battery_common_loop_num = ProtoField.uint16 ("dji_dumlv1.center_brd_center_battery_common_loop_num", "Loop Num", base.DEC, nil, nil, "Cycle Count")
f.center_brd_center_battery_common_error_type = ProtoField.uint32 ("dji_dumlv1.center_brd_center_battery_common_error_type", "Error Type", base.HEX)
f.center_brd_center_battery_common_current = ProtoField.uint16 ("dji_dumlv1.center_brd_center_battery_common_current", "Current", base.DEC)
f.center_brd_center_battery_common_cell_voltage_0 = ProtoField.uint32 ("dji_dumlv1.center_brd_center_battery_common_cell_voltage_0", "Cell Voltage 0", base.DEC)
f.center_brd_center_battery_common_cell_voltage_1 = ProtoField.uint32 ("dji_dumlv1.center_brd_center_battery_common_cell_voltage_1", "Cell Voltage 1", base.DEC)
f.center_brd_center_battery_common_cell_voltage_2 = ProtoField.uint32 ("dji_dumlv1.center_brd_center_battery_common_cell_voltage_2", "Cell Voltage 2", base.DEC)
f.center_brd_center_battery_common_serial_no = ProtoField.uint16 ("dji_dumlv1.center_brd_center_battery_common_serial_no", "Serial No", base.HEX, nil, nil, "Battery Serial Number")
f.center_brd_center_battery_common_unknown1e = ProtoField.bytes ("dji_dumlv1.center_brd_center_battery_common_unknown1e", "Unknown1E", base.SPACE)
f.center_brd_center_battery_common_temperature = ProtoField.uint16 ("dji_dumlv1.center_brd_center_battery_common_temperature", "Temperature", base.DEC, nil, nil, "In Degrees Celcius x100?")
f.center_brd_center_battery_common_conn_status = ProtoField.uint8 ("dji_dumlv1.center_brd_center_battery_common_conn_status", "Conn Status", base.HEX, enums.CENTER_BRD_CENTER_BATTERY_COMMON_CONN_STATUS_ENUM, nil, nil)
f.center_brd_center_battery_common_total_study_cycle = ProtoField.uint16 ("dji_dumlv1.center_brd_center_battery_common_total_study_cycle", "Total Study Cycle", base.HEX)
f.center_brd_center_battery_common_last_study_cycle = ProtoField.uint16 ("dji_dumlv1.center_brd_center_battery_common_last_study_cycle", "Last Study Cycle", base.HEX)
f.center_brd_center_battery_common_battery_on_charge = ProtoField.uint16 ("dji_dumlv1.center_brd_center_battery_common_battery_on_charge", "Battery On Charge", base.HEX)

local function center_brd_center_battery_common_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.center_brd_center_battery_common_relative_capacity, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.center_brd_center_battery_common_current_pv, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.center_brd_center_battery_common_current_capacity, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.center_brd_center_battery_common_full_capacity, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.center_brd_center_battery_common_life, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.center_brd_center_battery_common_loop_num, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.center_brd_center_battery_common_error_type, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.center_brd_center_battery_common_current, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.center_brd_center_battery_common_cell_voltage_0, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.center_brd_center_battery_common_cell_voltage_1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.center_brd_center_battery_common_cell_voltage_2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.center_brd_center_battery_common_serial_no, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.center_brd_center_battery_common_unknown1e, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.center_brd_center_battery_common_temperature, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.center_brd_center_battery_common_conn_status, payload(offset, 1))
    offset = offset + 1

    -- This is where packets from FW v1.07.0060 end; newer battery packets are longer
    if (payload:len() >= offset+6) then
        subtree:add_le (f.center_brd_center_battery_common_total_study_cycle, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.center_brd_center_battery_common_last_study_cycle, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.center_brd_center_battery_common_battery_on_charge, payload(offset, 2))
        offset = offset + 2
    end

    if (offset ~= 35) and (offset ~= 41) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Center Battery Common: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Center Battery Common: Payload size different than expected") end
end

local CENTER_BRD_UART_CMD_DISSECT = {
    [0x06] = center_brd_center_battery_common_dissector,
}

-- Remote Control - Generic fields used in many packets

f.rc_opertation_status_byte = ProtoField.uint8 ("dji_dumlv1.rc_opertation_status_byte", "Operation status", base.HEX, nil, nil, "Returned error code of the operation; 0 means success")

-- Remote Control - RC Push Parameter - 0x05

f.rc_push_param_aileron = ProtoField.uint16 ("dji_dumlv1.rc_push_param_aileron", "Aileron", base.HEX)
f.rc_push_param_elevator = ProtoField.uint16 ("dji_dumlv1.rc_push_param_elevator", "Elevator", base.HEX)
f.rc_push_param_throttle = ProtoField.uint16 ("dji_dumlv1.rc_push_param_throttle", "Throttle", base.HEX)
f.rc_push_param_rudder = ProtoField.uint16 ("dji_dumlv1.rc_push_param_rudder", "Rudder", base.HEX)
f.rc_push_param_gyro_value = ProtoField.uint16 ("dji_dumlv1.rc_push_param_gyro_value", "Gyro Value", base.HEX)
f.rc_push_param_wheel_info = ProtoField.uint8 ("dji_dumlv1.rc_push_param_wheel_info", "Wheel Info", base.HEX)
  f.rc_push_param_wheel_click_status = ProtoField.uint8 ("dji_dumlv1.rc_push_param_wheel_click_status", "Wheel Click Status", base.HEX, nil, 0x01, nil)
  f.rc_push_param_wheel_offset = ProtoField.uint8 ("dji_dumlv1.rc_push_param_wheel_offset", "Wheel Offset", base.HEX, nil, 0x3e, nil)
  f.rc_push_param_not_wheel_positive = ProtoField.uint8 ("dji_dumlv1.rc_push_param_not_wheel_positive", "Not Wheel Positive", base.HEX, nil, 0x40, nil)
  f.rc_push_param_wheel_changed = ProtoField.uint8 ("dji_dumlv1.rc_push_param_wheel_changed", "Wheel Changed", base.HEX, nil, 0x80, nil)
f.rc_push_param_masked0b = ProtoField.uint8 ("dji_dumlv1.rc_push_param_masked0b", "Masked0B", base.HEX)
  f.rc_push_param_go_home_button_pressed = ProtoField.uint8 ("dji_dumlv1.rc_push_param_go_home_button_pressed", "Go Home Button Pressed", base.HEX, nil, 0x08, nil)
  f.rc_push_param_mode = ProtoField.uint8 ("dji_dumlv1.rc_push_param_mode", "Mode", base.HEX, nil, 0x30, nil)
  f.rc_push_param_get_foot_stool = ProtoField.uint8 ("dji_dumlv1.rc_push_param_get_foot_stool", "Get Foot Stool", base.HEX, nil, 0xc0, nil)
f.rc_push_param_masked0c = ProtoField.uint8 ("dji_dumlv1.rc_push_param_masked0c", "Masked0C", base.HEX)
  f.rc_push_param_custom2 = ProtoField.uint8 ("dji_dumlv1.rc_push_param_custom2", "Custom2", base.HEX, nil, 0x08, nil)
  f.rc_push_param_custom1 = ProtoField.uint8 ("dji_dumlv1.rc_push_param_custom1", "Custom1", base.HEX, nil, 0x10, nil)
  f.rc_push_param_playback_status = ProtoField.uint8 ("dji_dumlv1.rc_push_param_playback_status", "PlayBack Status", base.HEX, nil, 0x20, nil)
  f.rc_push_param_shutter_status = ProtoField.uint8 ("dji_dumlv1.rc_push_param_shutter_status", "Shutter Status", base.HEX, nil, 0x40, nil)
  f.rc_push_param_record_status = ProtoField.uint8 ("dji_dumlv1.rc_push_param_record_status", "Record Status", base.HEX, nil, 0x80, nil)
f.rc_push_param_band_width = ProtoField.uint8 ("dji_dumlv1.rc_push_param_band_width", "Band Width", base.HEX)

local function rc_push_param_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.rc_push_param_aileron, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_push_param_elevator, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_push_param_throttle, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_push_param_rudder, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_push_param_gyro_value, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_push_param_wheel_info, payload(offset, 1))
    subtree:add_le (f.rc_push_param_wheel_click_status, payload(offset, 1))
    subtree:add_le (f.rc_push_param_wheel_offset, payload(offset, 1))
    subtree:add_le (f.rc_push_param_not_wheel_positive, payload(offset, 1))
    subtree:add_le (f.rc_push_param_wheel_changed, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_push_param_masked0b, payload(offset, 1))
    subtree:add_le (f.rc_push_param_go_home_button_pressed, payload(offset, 1))
    subtree:add_le (f.rc_push_param_mode, payload(offset, 1))
    subtree:add_le (f.rc_push_param_get_foot_stool, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_push_param_masked0c, payload(offset, 1))
    subtree:add_le (f.rc_push_param_custom2, payload(offset, 1))
    subtree:add_le (f.rc_push_param_custom1, payload(offset, 1))
    subtree:add_le (f.rc_push_param_playback_status, payload(offset, 1))
    subtree:add_le (f.rc_push_param_shutter_status, payload(offset, 1))
    subtree:add_le (f.rc_push_param_record_status, payload(offset, 1))
    offset = offset + 1

    if (payload:len() >= offset+1) then -- only exists on some platforms

        subtree:add_le (f.rc_push_param_band_width, payload(offset, 1))
        offset = offset + 1

    end

    if (offset ~= 13) and (offset ~= 14) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"RC Push Parameter: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"RC Push Parameter: Payload size different than expected") end
end

-- Remote Control - RC Set RF Cert Config - 0xF0

f.rc_set_rf_cert_config_field0 = ProtoField.uint8 ("dji_dumlv1.rc_set_rf_cert_config_field0", "Field 0", base.HEX)
f.rc_set_rf_cert_config_field1 = ProtoField.uint8 ("dji_dumlv1.rc_set_rf_cert_config_field1", "Field 1", base.HEX)
f.rc_set_rf_cert_config_field2 = ProtoField.uint8 ("dji_dumlv1.rc_set_rf_cert_config_field2", "Field 2", base.HEX)
f.rc_set_rf_cert_config_field3 = ProtoField.uint16 ("dji_dumlv1.rc_set_rf_cert_config_field3", "Field 3", base.HEX)
f.rc_set_rf_cert_config_field5 = ProtoField.uint8 ("dji_dumlv1.rc_set_rf_cert_config_field5", "Field 5", base.HEX)
f.rc_set_rf_cert_config_field6 = ProtoField.uint8 ("dji_dumlv1.rc_set_rf_cert_config_field6", "Field 6", base.HEX)
f.rc_set_rf_cert_config_field7 = ProtoField.uint8 ("dji_dumlv1.rc_set_rf_cert_config_field7", "Field 7", base.HEX)

local function rc_set_rf_cert_config_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.rc_set_rf_cert_config_field0, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_set_rf_cert_config_field1, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_set_rf_cert_config_field2, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_set_rf_cert_config_field3, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.rc_set_rf_cert_config_field5, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_set_rf_cert_config_field6, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rc_set_rf_cert_config_field7, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"RC Set RF Cert Config: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"RC Set RF Cert Config: Payload size different than expected") end
end

local RC_UART_CMD_DISSECT = {
    [0x05] = rc_push_param_dissector,
    [0xF0] = rc_set_rf_cert_config_dissector,
}

-- Wi-Fi - WiFi Ap Push RSSI - 0x09

f.wifi_ap_push_rssi_signal = ProtoField.uint8 ("dji_dumlv1.wifi_ap_push_rssi_signal", "Signal", base.HEX)

local function wifi_ap_push_rssi_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.wifi_ap_push_rssi_signal, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"WiFi Ap Push RSSI: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"WiFi Ap Push RSSI: Payload size different than expected") end
end

-- Wi-Fi - WiFi Ap Push Sta MAC - 0x11

f.wifi_ap_push_sta_mac_mac = ProtoField.ether ("dji_dumlv1.wifi_ap_push_sta_mac_mac", "Mac")

local function wifi_ap_push_sta_mac_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.wifi_ap_push_sta_mac_mac, payload(offset, 6))
    offset = offset + 6

    if (offset ~= 6) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"WiFi Ap Push Sta MAC: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"WiFi Ap Push Sta MAC: Payload size different than expected") end
end

-- Wi-Fi - WiFi Ap Get Phy Param - 0x12

enums.WIFI_ELEC_SIGNAL_SIGNAL_STATUS_ENUM = {
    [0x00] = 'Good',
    [0x01] = 'Medium',
    [0x02] = 'Poor',
    [0x64] = 'OTHER',
}

f.wifi_ap_get_phy_param_signal_status = ProtoField.uint8 ("dji_dumlv1.wifi_ap_get_phy_param_signal_status", "Signal Status", base.HEX, enums.WIFI_ELEC_SIGNAL_SIGNAL_STATUS_ENUM, nil, nil)

local function wifi_ap_get_phy_param_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.wifi_ap_get_phy_param_signal_status, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"WiFi Ap Get Phy Param: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"WiFi Ap Get Phy Param: Payload size different than expected") end
end

-- Wi-Fi - WiFi Ap Push Chan Noise - 0x2a

f.wifi_ap_push_chan_noise_total = ProtoField.uint32 ("dji_dumlv1.wifi_ap_push_chan_noise_total", "Total", base.HEX)

local function wifi_ap_push_chan_noise_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.wifi_ap_push_chan_noise_total, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"WiFi Ap Push Chan Noise: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"WiFi Ap Push Chan Noise: Payload size different than expected") end
end

-- Wi-Fi - WiFi Ap Set Country Code - 0x30
-- Used by Mobile App to set country code on RC; for country "US", RC then enters FCC mode and asks the AC to change mode as well.

f.wifi_set_country_code_str1 = ProtoField.string ("dji_spark.wifi_set_country_code_str1", "Region Str1", base.NONE)
f.wifi_set_country_code_str2 = ProtoField.string ("dji_spark.wifi_set_country_code_str2", "Region Str2", base.NONE)
f.wifi_set_country_code_unkn8 = ProtoField.uint16 ("dji_spark.wifi_set_country_code_unkn8", "Unknown8", base.HEX)

local function wifi_ap_set_country_code_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.wifi_set_country_code_str1, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.wifi_set_country_code_str2, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.wifi_set_country_code_unkn8, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 10) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Set Country Code: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Set Country Code: Payload size different than expected") end
end


local WIFI_UART_CMD_DISSECT = {
    [0x09] = wifi_ap_push_rssi_dissector,
    [0x11] = wifi_ap_push_sta_mac_dissector,
    [0x12] = wifi_ap_get_phy_param_dissector,
    [0x2a] = wifi_ap_push_chan_noise_dissector,
    [0x30] = wifi_ap_set_country_code_dissector,
}

-- DM36x proc. - DM36x Send Gnd Ctrl Info - 0x01

f.dm36x_gnd_ctrl_info_param_id = ProtoField.uint8 ("dji_dumlv1.dm36x_gnd_ctrl_info_param_id", "Param ID", base.DEC)
f.dm36x_gnd_ctrl_info_param_len = ProtoField.uint8 ("dji_dumlv1.dm36x_gnd_ctrl_info_param_len", "Param Len", base.DEC)
f.dm36x_gnd_ctrl_info_param_val8 = ProtoField.uint8 ("dji_dumlv1.dm36x_gnd_ctrl_info_param_val8", "Param 8-bit Val", base.DEC)

local function dm36x_send_gnd_ctrl_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    -- Decoded using func Dec_Serial_Set_GS_Ctrl from `usbclient` binary
    local num_entries = math.floor(payload:len() / 3)

    local i = 0
    while i < num_entries do
        i = i + 1

        subtree:add_le (f.dm36x_gnd_ctrl_info_param_id, payload(offset, 1))
        offset = offset + 1

        local param_len = payload(offset,1):le_uint()
        subtree:add_le (f.dm36x_gnd_ctrl_info_param_len, payload(offset, 1))
        offset = offset + 1

        --if (param_len == 1) then -- only support one param_len
        subtree:add_le (f.dm36x_gnd_ctrl_info_param_val8, payload(offset, 1))
        offset = offset + param_len

    end

    if (offset ~= 3 * num_entries) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"DM36x Send Gnd Ctrl Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"DM36x Send Gnd Ctrl Info: Payload size different than expected") end
end

-- DM36x proc. - DM36x Recv Gnd Ctrl Info - 0x02

local function dm36x_recv_gnd_ctrl_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    -- Decoded using func Dec_Serial_Get_GS_Ctrl from `usbclient` binary
    local num_entries = math.floor(payload:len() / 1)

    local i = 0
    while i < num_entries do
        i = i + 1

        subtree:add_le (f.dm36x_gnd_ctrl_info_param_id, payload(offset, 1))
        offset = offset + 1

    end

    if (offset ~= 1 * num_entries) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"DM36x Recv Gnd Ctrl Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"DM36x Recv Gnd Ctrl Info: Payload size different than expected") end
end

-- DM36x proc. - DM36x Send UAV Stat Info - 0x06

f.dm36x_uav_stat_info_unknown00 = ProtoField.bytes ("dji_dumlv1.dm36x_uav_stat_info_unknown00", "Unknown00", base.SPACE)
f.dm36x_uav_stat_info_disable_liveview = ProtoField.uint8 ("dji_dumlv1.dm36x_uav_stat_info_disable_liveview", "Disable Liveview", base.HEX)
f.dm36x_uav_stat_info_encode_mode = ProtoField.uint8 ("dji_dumlv1.dm36x_uav_stat_info_encode_mode", "Encode Mode", base.HEX)
f.dm36x_uav_stat_info_dual_encode_mode_percentage = ProtoField.uint8 ("dji_dumlv1.dm36x_uav_stat_info_dual_encode_mode_percentage", "Dual Encode Mode Percentage", base.HEX)

local function dm36x_send_uav_stat_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.dm36x_uav_stat_info_unknown00, payload(offset, 3))
    offset = offset + 3

    subtree:add_le (f.dm36x_uav_stat_info_disable_liveview, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.dm36x_uav_stat_info_encode_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.dm36x_uav_stat_info_dual_encode_mode_percentage, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 6) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"DM36x Send UAV Stat Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"DM36x Send UAV Stat Info: Payload size different than expected") end
end

-- DM36x proc. - DM36x Recv Gnd Stat Info - 0x07

local function dm36x_recv_gnd_stat_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    -- Answer could be decoded using func Dec_Serial_Get_GS_Config from `usbclient` binary

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"DM36x Recv Gnd Stat Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"DM36x Recv Gnd Stat Info: Payload size different than expected") end
end

-- DM36x proc. - DM36x Get App Connect Stat - 0x0e

--f.dm36x_get_app_conn_stat_unknown0 = ProtoField.none ("dji_dumlv1.dm36x_get_app_conn_stat_unknown0", "Unknown0", base.NONE)

local function dm36x_get_app_conn_stat_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"DM36x Get App Connect Stat: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"DM36x Get App Connect Stat: Payload size different than expected") end
end

local DM36X_UART_CMD_DISSECT = {
    [0x01] = dm36x_send_gnd_ctrl_info_dissector,
    [0x02] = dm36x_recv_gnd_ctrl_info_dissector,
    [0x06] = dm36x_send_uav_stat_info_dissector,
    [0x07] = dm36x_recv_gnd_stat_info_dissector,
    [0x0e] = dm36x_get_app_conn_stat_dissector,
}

-- HD Link - Generic fields used in many packets

f.hd_link_opertation_status_byte = ProtoField.uint8 ("dji_dumlv1.hd_link_opertation_status_byte", "Operation status", base.HEX, nil, nil, "Returned error code of the operation; 0 means success")

-- HD Link - HDLnk Write Hardware Register packet - 0x06

f.hd_link_hardware_reg_addr = ProtoField.uint16 ("dji_dumlv1.hd_link_hardware_reg_set", "Register addr", base.HEX, nil, nil, "Address within AD9363, FPGA or special value recognized by Lightbridge MCU")
f.hd_link_hardware_reg_val = ProtoField.uint8 ("dji_dumlv1.hd_link_hardware_reg_val", "Register value", base.HEX, nil, nil, "Value of the hardware register")

local function hd_link_write_hardware_reg_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request

        subtree:add_le (f.hd_link_hardware_reg_addr, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.hd_link_hardware_reg_val, payload(offset, 1))
        offset = offset + 1

        if (offset ~= 3) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Write Hardware Reg: Offset does not match - internal inconsistency") end

    else -- Response

        subtree:add_le (f.hd_link_opertation_status_byte, payload(offset, 1))
        offset = offset + 1

        if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Read Hardware Reg: Offset does not match - internal inconsistency") end

    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Write Hardware Reg: Payload size different than expected") end
end

-- HD Link - HDLnk Read Hardware Register packet - 0x07

local function hd_link_read_hardware_reg_dissector(pkt_length, buffer, pinfo, subtree)
    local pack_type = bit32.rshift(bit32.band(buffer(8,1):uint(), 0x80), 7)

    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if pack_type == 0 then -- Request

        subtree:add_le (f.hd_link_hardware_reg_addr, payload(offset, 2))
        offset = offset + 2

        if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Read Hardware Reg: Offset does not match - internal inconsistency") end

    else -- Response

        subtree:add_le (f.hd_link_hardware_reg_val, payload(offset, 1))
        offset = offset + 1

        if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Read Hardware Reg: Offset does not match - internal inconsistency") end

    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Read Hardware Reg: Payload size different than expected") end
end

-- HD Link - HDLnk Push VT Signal Quality - 0x08

f.hd_link_push_vt_signal_quality_masked00 = ProtoField.uint8 ("dji_dumlv1.hd_link_push_vt_signal_quality_masked00", "Masked00", base.HEX)
  f.hd_link_push_vt_signal_quality_up_signal_quality = ProtoField.uint8 ("dji_dumlv1.hd_link_push_vt_signal_quality_up_signal_quality", "Up Signal Quality", base.HEX, nil, 0x7f, nil)

local function hd_link_push_vt_signal_quality_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_push_vt_signal_quality_masked00, payload(offset, 1))
    subtree:add_le (f.hd_link_push_vt_signal_quality_up_signal_quality, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Push VT Signal Quality: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Push VT Signal Quality: Payload size different than expected") end
end

-- HD Link - HDLnk Push Freq Energy - 0x0a

f.hd_link_push_freq_energy_unknown0 = ProtoField.bytes ("dji_dumlv1.hd_link_push_freq_energy_unknown0", "Unknown0", base.SPACE)

local function hd_link_push_freq_energy_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_push_freq_energy_unknown0, payload(offset, 32))
    offset = offset + 32

    if (offset ~= 32) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Push Freq Energy: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Push Freq Energy: Payload size different than expected") end
end

-- HD Link - HDLnk Push Device Status - 0x0b

f.hd_link_push_device_status_unknown0 = ProtoField.uint8 ("dji_dumlv1.hd_link_push_device_status_unknown0", "Unknown0", base.HEX)
f.hd_link_push_device_status_unknown1 = ProtoField.uint32 ("dji_dumlv1.hd_link_push_device_status_unknown1", "Unknown1", base.DEC)

local function hd_link_push_device_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    local num_entries = math.floor(payload:len() / 5)

    local i = 0
    while i < num_entries do
        i = i + 1

        subtree:add_le (f.hd_link_push_device_status_unknown0, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.hd_link_push_device_status_unknown1, payload(offset, 4))
        offset = offset + 4

    end

    if (offset ~= 5 * num_entries) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Push Device Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Push Device Status: Payload size different than expected") end
end

-- HD Link - HDLnk Get VT Config Info - 0x0c

f.hd_link_get_vt_config_info_channel = ProtoField.uint8 ("dji_dumlv1.hd_link_get_vt_config_info_channel", "Channel", base.HEX)
f.hd_link_get_vt_config_info_unknown01 = ProtoField.uint8 ("dji_dumlv1.hd_link_get_vt_config_info_unknown01", "Unknown01", base.HEX)
f.hd_link_get_vt_config_info_get_is_auto = ProtoField.uint8 ("dji_dumlv1.hd_link_get_vt_config_info_get_is_auto", "Get Is Auto", base.HEX)
f.hd_link_get_vt_config_info_get_is_master = ProtoField.uint8 ("dji_dumlv1.hd_link_get_vt_config_info_get_is_master", "Get Is Master", base.HEX)
f.hd_link_get_vt_config_info_unknown04 = ProtoField.bytes ("dji_dumlv1.hd_link_get_vt_config_info_unknown04", "Unknown04", base.SPACE)
f.hd_link_get_vt_config_info_mcs = ProtoField.uint8 ("dji_dumlv1.hd_link_get_vt_config_info_mcs", "Mcs", base.HEX)
f.hd_link_get_vt_config_info_single_or_double = ProtoField.uint8 ("dji_dumlv1.hd_link_get_vt_config_info_single_or_double", "Single Or Double", base.HEX, nil, nil)
f.hd_link_get_vt_config_info_band_width_percent = ProtoField.uint8 ("dji_dumlv1.hd_link_get_vt_config_info_band_width_percent", "Band Width Percent", base.DEC)
f.hd_link_get_vt_config_info_unknown0c = ProtoField.bytes ("dji_dumlv1.hd_link_get_vt_config_info_unknown0c", "Unknown0C", base.SPACE)
f.hd_link_get_vt_config_info_working_freq = ProtoField.uint8 ("dji_dumlv1.hd_link_get_vt_config_info_working_freq", "Working Freq", base.HEX)

local function hd_link_get_vt_config_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_get_vt_config_info_channel, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_get_vt_config_info_unknown01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_get_vt_config_info_get_is_auto, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_get_vt_config_info_get_is_master, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_get_vt_config_info_unknown04, payload(offset, 5))
    offset = offset + 5

    subtree:add_le (f.hd_link_get_vt_config_info_mcs, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_get_vt_config_info_single_or_double, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_get_vt_config_info_band_width_percent, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_get_vt_config_info_unknown0c, payload(offset, 3))
    offset = offset + 3

    subtree:add_le (f.hd_link_get_vt_config_info_working_freq, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 16) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Get VT Config Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Get VT Config Info: Payload size different than expected") end
end

-- HD Link - HDLnk Push Wl Env Quality - 0x11

enums.HD_LINK_WL_ENV_QUALITY_CHANNEL_STATUS_ENUM = {
    [0x00] = 'Excellent',
    [0x01] = 'Good',
    [0x02] = 'Medium',
    [0x03] = 'Poor',
    [0x64] = 'OTHER',
}

f.hd_link_push_wl_env_quality_channel_status = ProtoField.uint8 ("dji_dumlv1.hd_link_push_wl_env_quality_channel_status", "Channel Status", base.HEX, enums.HD_LINK_WL_ENV_QUALITY_CHANNEL_STATUS_ENUM, nil, nil)

local function hd_link_push_wl_env_quality_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_push_wl_env_quality_channel_status, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Push Wl Env Quality: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Push Wl Env Quality: Payload size different than expected") end
end

-- HD Link - HDLnk Set Factory Test - 0x12

f.hd_link_set_factory_test_flag_20001A28_D_E = ProtoField.uint8 ("dji_dumlv1.hd_link_set_factory_test_flag_20001A28_D_E", "flag 20001A28 D and E", base.HEX, nil, nil, nil)
f.hd_link_set_factory_test_flag_20001A28_A_B = ProtoField.uint8 ("dji_dumlv1.hd_link_set_factory_test_flag_20001A28_A_B", "flag 20001A28 A and B", base.HEX, nil, nil, nil)
f.hd_link_set_factory_test_attenuation = ProtoField.uint8 ("dji_dumlv1.hd_link_set_factory_test_attenuation", "Tcx Attenuation", base.HEX, nil, nil, "dB; attenuation set to REG_TXn_ATTEN_0 register of AD9363")
f.hd_link_set_factory_test_flag_20001A28_C = ProtoField.uint8 ("dji_dumlv1.hd_link_set_factory_test_flag_20001A28_C", "flag 20001A28 C", base.HEX, nil, nil, nil)

local function hd_link_set_factory_test_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_set_factory_test_flag_20001A28_D_E, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_set_factory_test_flag_20001A28_A_B, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_set_factory_test_attenuation, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_set_factory_test_flag_20001A28_C, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Set Factory Test: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Set Factory Test: Payload size different than expected") end
end

-- HD Link - HDLnk Push Max Video Bandwidth - 0x15

f.hd_link_push_max_video_bandwidth_max_mcs = ProtoField.uint8 ("dji_dumlv1.hd_link_push_max_video_bandwidth_max_mcs", "Max Mcs", base.HEX)

local function hd_link_push_max_video_bandwidth_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_push_max_video_bandwidth_max_mcs, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Push Max Video Bandwidth: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Push Max Video Bandwidth: Payload size different than expected") end
end

-- HD Link - HDLnk Push Debug Info - 0x16

f.hd_link_push_debug_info_type = ProtoField.uint8 ("dji_dumlv1.hd_link_push_debug_info_type", "Type", base.HEX, nil, nil, "TODO values from enum P3.DataOsdGetPushDebugInfo")

local function hd_link_push_debug_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_push_debug_info_type, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Push Debug Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Push Debug Info: Payload size different than expected") end
end

-- HD Link - HDLnk Push SDR Dl Freq Energy - 0x20

--f.hd_link_push_sdr_dl_freq_energy_unknown0 = ProtoField.none ("dji_dumlv1.hd_link_push_sdr_dl_freq_energy_unknown0", "Unknown0", base.NONE)

local function hd_link_push_sdr_dl_freq_energy_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Push SDR Dl Freq Energy: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Push SDR Dl Freq Energy: Payload size different than expected") end
end

-- HD Link - HDLnk Push SDR Dl Auto Vt Info - 0x22

f.hd_link_push_sdr_dl_auto_vt_info_nf = ProtoField.uint16 ("dji_dumlv1.hd_link_push_sdr_dl_auto_vt_info_nf", "NF", base.DEC)
f.hd_link_push_sdr_dl_auto_vt_info_band = ProtoField.uint8 ("dji_dumlv1.hd_link_push_sdr_dl_auto_vt_info_band", "Band", base.DEC)
f.hd_link_push_sdr_dl_auto_vt_info_unknown3 = ProtoField.uint8 ("dji_dumlv1.hd_link_push_sdr_dl_auto_vt_info_unknown3", "Unknown3", base.HEX)
f.hd_link_push_sdr_dl_auto_vt_info_auto_mcs = ProtoField.float ("dji_dumlv1.hd_link_push_sdr_dl_auto_vt_info_auto_mcs", "Auto Mcs", base.DEC)
f.hd_link_push_sdr_dl_auto_vt_info_mcs_type = ProtoField.uint8 ("dji_dumlv1.hd_link_push_sdr_dl_auto_vt_info_mcs_type", "Mcs Type", base.HEX)

local function hd_link_push_sdr_dl_auto_vt_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_push_sdr_dl_auto_vt_info_nf, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.hd_link_push_sdr_dl_auto_vt_info_band, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_push_sdr_dl_auto_vt_info_unknown3, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_push_sdr_dl_auto_vt_info_auto_mcs, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hd_link_push_sdr_dl_auto_vt_info_mcs_type, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 9) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Push SDR Dl Auto Vt Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Push SDR Dl Auto Vt Info: Payload size different than expected") end
end

-- HD Link - HDLnk Push SDR UAV Rt Status - 0x24
-- HD Link - HDLnk Push SDR Gnd Rt Status - 0x25

f.hd_link_push_sdr_rt_status_name = ProtoField.string ("dji_dumlv1.hd_link_push_sdr_rt_status_name", "Name", base.NONE)
f.hd_link_push_sdr_rt_status_value = ProtoField.float ("dji_dumlv1.hd_link_push_sdr_rt_status_value", "Value", base.DEC)

local function hd_link_push_sdr_rt_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    local num_entries = math.floor(payload:len() / 12)

    local i = 0
    while i < num_entries do
        i = i + 1

        subtree:add_le (f.hd_link_push_sdr_rt_status_name, payload(offset, 8))
        offset = offset + 8

        subtree:add_le (f.hd_link_push_sdr_rt_status_value, payload(offset, 4))
        offset = offset + 4

    end

    if (offset ~= 12 * num_entries) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Push SDR Rt Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Push SDR Rt Status: Payload size different than expected") end
end

-- HD Link - HDLnk Push SDR Ul Freq Energy - 0x29

--f.hd_link_push_sdr_ul_freq_energy_unknown0 = ProtoField.none ("dji_dumlv1.hd_link_push_sdr_ul_freq_energy_unknown0", "Unknown0", base.NONE)

local function hd_link_push_sdr_ul_freq_energy_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Push SDR Ul Freq Energy: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Push SDR Ul Freq Energy: Payload size different than expected") end
end

-- HD Link - HDLnk Push SDR Ul Auto Vt Info - 0x2a

f.hd_link_push_sdr_ul_auto_vt_info_channel_type = ProtoField.float ("dji_dumlv1.hd_link_push_sdr_ul_auto_vt_info_channel_type", "Select Channel Type", base.DEC)
f.hd_link_push_sdr_ul_auto_vt_info_get_select_channel_count = ProtoField.uint32 ("dji_dumlv1.hd_link_push_sdr_ul_auto_vt_info_get_select_channel_count", "Get Select Channel Count", base.HEX)

local function hd_link_push_sdr_ul_auto_vt_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_push_sdr_ul_auto_vt_info_channel_type, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.hd_link_push_sdr_ul_auto_vt_info_get_select_channel_count, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 8) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Push SDR Ul Auto Vt Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Push SDR Ul Auto Vt Info: Payload size different than expected") end
end

-- HD Link - HDLnk SDR Wireless Env - 0x30

enums.HD_LINK_SDR_WIRELESS_ENV_EVENT_CODE_SDR_WIRELESS_STATE_ENUM = {
    [0x00] = 'STRONG_DISTURBANCE',
    [0x01] = 'VIDEO_DISTURBANCE',
    [0x02] = 'RC_DISTURBANCE',
    [0x03] = 'LOW_SIGNAL_POWER',
    [0x04] = 'CUSTOM_SIGNAL_DISTURBANCE',
    [0x05] = 'RC_TO_GLASS_DIST',
    [0x06] = 'UAV_HAL_RESTART',
    [0x07] = 'GLASS_DIST_RC_ANTENNA',
    [0x08] = 'DISCONNECT_RC_DISTURB',
    [0x09] = 'DISCONNECT_UAV_DISTURB',
    [0x0a] = 'DISCONNECT_WEEK_SIGNAL',
    [0xff] = 'INTERNAL_EVENT',
    [0x100] = 'NONE',
}

f.hd_link_sdr_wireless_env_event_code = ProtoField.uint16 ("dji_dumlv1.hd_link_sdr_wireless_env_event_code", "Event Code", base.HEX, enums.HD_LINK_SDR_WIRELESS_ENV_EVENT_CODE_SDR_WIRELESS_STATE_ENUM, nil, nil)

local function hd_link_sdr_wireless_env_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_sdr_wireless_env_event_code, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk SDR Wireless Env: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk SDR Wireless Env: Payload size different than expected") end
end

-- HD Link - HDLnk SDR Liveview Rate Ind - 0x36

f.hd_link_sdr_liveview_rate_ind_code_rate = ProtoField.float ("dji_dumlv1.hd_link_sdr_liveview_rate_ind_code_rate", "Code Rate", base.DEC)

local function hd_link_sdr_liveview_rate_ind_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_sdr_liveview_rate_ind_code_rate, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk SDR Liveview Rate Ind: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk SDR Liveview Rate Ind: Payload size different than expected") end
end

-- HD Link - HDLnk Abnormal Event Ind - 0x37

f.hd_link_abnormal_event_ind_masked00 = ProtoField.uint8 ("dji_dumlv1.hd_link_abnormal_event_ind_masked00", "Masked00", base.HEX)
  f.hd_link_abnormal_event_ind_post = ProtoField.uint8 ("dji_dumlv1.hd_link_abnormal_event_ind_post", "Post", base.HEX, nil, 0x01, nil)

local function hd_link_abnormal_event_ind_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_abnormal_event_ind_masked00, payload(offset, 1))
    subtree:add_le (f.hd_link_abnormal_event_ind_post, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Abnormal Event Ind: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Abnormal Event Ind: Payload size different than expected") end
end

-- HD Link - HDLnk Push Dl Freq Energy - 0x3a

enums.HD_LINK_PUSH_DL_FREQ_ENERGY_DIS_LOSS_EVENT_ENUM = {
    [0x00] = 'NONE',
    [0x01] = 'GROUND_INTERFERED',
    [0x02] = 'UAV_INTERFERED',
    [0x03] = 'SIGNAL_BLOCK',
}

f.hd_link_push_dl_freq_energy_1_km_offset = ProtoField.uint8 ("dji_dumlv1.hd_link_push_dl_freq_energy_1_km_offset", "1 Km Offset", base.HEX, nil, nil, "value bias  - 256")
f.hd_link_push_dl_freq_energy_path_loss_offset = ProtoField.uint8 ("dji_dumlv1.hd_link_push_dl_freq_energy_path_loss_offset", "Path Loss Offset", base.HEX)
f.hd_link_push_dl_freq_energy_rc_link_offset = ProtoField.uint8 ("dji_dumlv1.hd_link_push_dl_freq_energy_rc_link_offset", "Rc Link Offset", base.HEX)
f.hd_link_push_dl_freq_energy_tx_power_offset = ProtoField.uint8 ("dji_dumlv1.hd_link_push_dl_freq_energy_tx_power_offset", "Tx Power Offset", base.HEX)
f.hd_link_push_dl_freq_energy_dis_loss_ind = ProtoField.uint8 ("dji_dumlv1.hd_link_push_dl_freq_energy_dis_loss_ind", "Dis Loss Ind", base.HEX, enums.HD_LINK_PUSH_DL_FREQ_ENERGY_DIS_LOSS_EVENT_ENUM, nil, nil)
f.hd_link_push_dl_freq_energy_sig_bar_ind = ProtoField.uint8 ("dji_dumlv1.hd_link_push_dl_freq_energy_sig_bar_ind", "Sig Bar Ind", base.HEX)
f.hd_link_push_dl_freq_energy_dl_pwr_accu = ProtoField.uint8 ("dji_dumlv1.hd_link_push_dl_freq_energy_dl_pwr_accu", "Dl Pwr Accu", base.HEX)
f.hd_link_push_dl_freq_energy_max_nf20_m = ProtoField.uint16 ("dji_dumlv1.hd_link_push_dl_freq_energy_max_nf20_m", "Max Nf20 M", base.HEX)
f.hd_link_push_dl_freq_energy_min_nf20_m = ProtoField.uint16 ("dji_dumlv1.hd_link_push_dl_freq_energy_min_nf20_m", "Min Nf20 M", base.HEX)
f.hd_link_push_dl_freq_energy_max_nf10_m = ProtoField.uint16 ("dji_dumlv1.hd_link_push_dl_freq_energy_max_nf10_m", "Max Nf10 M", base.HEX)
f.hd_link_push_dl_freq_energy_min_nf10_m = ProtoField.uint16 ("dji_dumlv1.hd_link_push_dl_freq_energy_min_nf10_m", "Min Nf10 M", base.HEX)

local function hd_link_push_dl_freq_energy_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_push_dl_freq_energy_1_km_offset, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_push_dl_freq_energy_path_loss_offset, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_push_dl_freq_energy_rc_link_offset, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_push_dl_freq_energy_tx_power_offset, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_push_dl_freq_energy_dis_loss_ind, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_push_dl_freq_energy_sig_bar_ind, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_push_dl_freq_energy_dl_pwr_accu, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_push_dl_freq_energy_max_nf20_m, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.hd_link_push_dl_freq_energy_min_nf20_m, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.hd_link_push_dl_freq_energy_max_nf10_m, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.hd_link_push_dl_freq_energy_min_nf10_m, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 15) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Push Dl Freq Energy: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Push Dl Freq Energy: Payload size different than expected") end
end

-- HD Link - HDLnk SDR Tip Interference - 0x3b

f.hd_link_sdr_tip_interference_be_interfered = ProtoField.uint8 ("dji_dumlv1.hd_link_sdr_tip_interference_be_interfered", "Be Interfered", base.HEX)

local function hd_link_sdr_tip_interference_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_sdr_tip_interference_be_interfered, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk SDR Tip Interference: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk SDR Tip Interference: Payload size different than expected") end
end

-- HD Link - HDLnk Power Status - 0x52

f.hd_link_power_status_info_power_status = ProtoField.uint8 ("dji_dumlv1.hd_link_power_status_info_power_status", "Power Status", base.HEX)
f.hd_link_power_status_info_get_is_power_off = ProtoField.uint8 ("dji_dumlv1.hd_link_power_status_info_get_is_power_off", "Get Is Power Off", base.HEX)

local function hd_link_power_status_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_power_status_info_power_status, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_power_status_info_get_is_power_off, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Power Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Power Status: Payload size different than expected") end
end

-- HD Link - HDLnk Osmo Calibration - 0x54

f.hd_link_osmo_calibration_a = ProtoField.uint8 ("dji_dumlv1.hd_link_osmo_calibration_a", "A", base.HEX)
f.hd_link_osmo_calibration_b = ProtoField.uint8 ("dji_dumlv1.hd_link_osmo_calibration_b", "B", base.HEX)

local function hd_link_osmo_calibration_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_osmo_calibration_a, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.hd_link_osmo_calibration_b, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Osmo Calibration: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Osmo Calibration: Payload size different than expected") end
end

-- HD Link - HDLnk Mic Info - 0x59

enums.HD_LINK_OSD_MIC_INFO_MIC_TYPE_ENUM = {
    [0x00] = 'IN',
    [0x01] = 'OUT',
    [0x02] = 'OTHER',
}

f.hd_link_mic_info_masked00 = ProtoField.uint8 ("dji_dumlv1.hd_link_mic_info_masked00", "Masked00", base.HEX)
  f.hd_link_mic_info_mic_type = ProtoField.uint8 ("dji_dumlv1.hd_link_mic_info_mic_type", "Mic Type", base.HEX, enums.HD_LINK_OSD_MIC_INFO_MIC_TYPE_ENUM, 0x01, nil)
  f.hd_link_mic_info_mic_volume = ProtoField.uint8 ("dji_dumlv1.hd_link_mic_info_mic_volume", "Mic Volume", base.HEX, nil, 0xfe, nil)

local function hd_link_mic_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.hd_link_mic_info_masked00, payload(offset, 1))
    subtree:add_le (f.hd_link_mic_info_mic_type, payload(offset, 1))
    subtree:add_le (f.hd_link_mic_info_mic_volume, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"HDLnk Mic Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"HDLnk Mic Info: Payload size different than expected") end
end

local HD_LINK_UART_CMD_DISSECT = {
    [0x01] = flyc_osd_general_dissector,
    [0x02] = flyc_osd_home_point_dissector,
    [0x06] = hd_link_write_hardware_reg_dissector,
    [0x07] = hd_link_read_hardware_reg_dissector,
    [0x08] = hd_link_push_vt_signal_quality_dissector,
    [0x0a] = hd_link_push_freq_energy_dissector,
    [0x0b] = hd_link_push_device_status_dissector,
    [0x0c] = hd_link_get_vt_config_info_dissector,
    [0x11] = hd_link_push_wl_env_quality_dissector,
    [0x12] = hd_link_set_factory_test_dissector,
    [0x15] = hd_link_push_max_video_bandwidth_dissector,
    [0x16] = hd_link_push_debug_info_dissector,
    [0x20] = hd_link_push_sdr_dl_freq_energy_dissector,
    [0x22] = hd_link_push_sdr_dl_auto_vt_info_dissector,
    [0x24] = hd_link_push_sdr_rt_status_dissector,
    [0x25] = hd_link_push_sdr_rt_status_dissector, -- Ground version is the same as air version
    [0x29] = hd_link_push_sdr_ul_freq_energy_dissector,
    [0x2a] = hd_link_push_sdr_ul_auto_vt_info_dissector,
    [0x30] = hd_link_sdr_wireless_env_dissector,
    [0x36] = hd_link_sdr_liveview_rate_ind_dissector,
    [0x37] = hd_link_abnormal_event_ind_dissector,
    [0x3a] = hd_link_push_dl_freq_energy_dissector,
    [0x3b] = hd_link_sdr_tip_interference_dissector,
    [0x52] = hd_link_power_status_info_dissector,
    [0x54] = hd_link_osmo_calibration_dissector,
    [0x59] = hd_link_mic_info_dissector,
}

-- Mono/Binocular - Eye Bino Info - 0x01

--f.mbino_bino_info_unknown0 = ProtoField.none ("dji_dumlv1.mbino_bino_info_unknown0", "Unknown0", base.NONE)

local function mbino_bino_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Eye Bino Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Eye Bino Info: Payload size different than expected") end
end

-- Mono/Binocular - Eye Avoidance Param - 0x06

f.mbino_avoidance_param_masked00 = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_masked00", "Masked00", base.HEX)
  f.mbino_avoidance_param_braking = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_braking", "Braking", base.HEX, nil, 0x01, nil)
  f.mbino_avoidance_param_visual_sensor_working = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_visual_sensor_working", "Visual Sensor Working", base.HEX, nil, 0x02, nil)
  f.mbino_avoidance_param_avoid_open = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_avoid_open", "Avoid Open", base.HEX, nil, 0x04, nil)
  f.mbino_avoidance_param_be_shuttle_mode = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_be_shuttle_mode", "Be Shuttle Mode", base.HEX, nil, 0x08, nil)
  f.mbino_avoidance_param_avoid_front_work = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_avoid_front_work", "Avoid Front Work", base.HEX, nil, 0x10, nil)
  f.mbino_avoidance_param_avoid_right_work = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_avoid_right_work", "Avoid Right Work", base.HEX, nil, 0x20, nil)
  f.mbino_avoidance_param_avoid_behind_work = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_avoid_behind_work", "Avoid Behind Work", base.HEX, nil, 0x40, nil)
  f.mbino_avoidance_param_avoid_left_work = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_avoid_left_work", "Avoid Left Work", base.HEX, nil, 0x80, nil)
f.mbino_avoidance_param_masked01 = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_masked01", "Masked01", base.HEX)
  f.mbino_avoidance_param_avoid_front_distance_level = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_avoid_front_distance_level", "Avoid Front Distance Level", base.HEX, nil, 0x0f, nil)
  f.mbino_avoidance_param_avoid_front_alert_level = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_avoid_front_alert_level", "Avoid Front Alert Level", base.HEX, nil, 0xf0, nil)
f.mbino_avoidance_param_masked02 = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_masked02", "Masked02", base.HEX)
  f.mbino_avoidance_param_avoid_right_distance_level = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_avoid_right_distance_level", "Avoid Right Distance Level", base.HEX, nil, 0x0f, nil)
  f.mbino_avoidance_param_avoid_right_alert_level = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_avoid_right_alert_level", "Avoid Right Alert Level", base.HEX, nil, 0xf0, nil)
f.mbino_avoidance_param_masked03 = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_masked03", "Masked03", base.HEX)
  f.mbino_avoidance_param_avoid_behind_distance_level = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_avoid_behind_distance_level", "Avoid Behind Distance Level", base.HEX, nil, 0x0f, nil)
  f.mbino_avoidance_param_avoid_behind_alert_level = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_avoid_behind_alert_level", "Avoid Behind Alert Level", base.HEX, nil, 0xf0, nil)
f.mbino_avoidance_param_masked04 = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_masked04", "Masked04", base.HEX)
  f.mbino_avoidance_param_avoid_left_distance_level = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_avoid_left_distance_level", "Avoid Left Distance Level", base.HEX, nil, 0x0f, nil)
  f.mbino_avoidance_param_avoid_left_alert_level = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_avoid_left_alert_level", "Avoid Left Alert Level", base.HEX, nil, 0xf0, nil)
f.mbino_avoidance_param_masked05 = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_masked05", "Masked05", base.HEX)
  f.mbino_avoidance_param_allow_front = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_allow_front", "Allow Front", base.HEX, nil, 0x01, nil)
  f.mbino_avoidance_param_allow_right = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_allow_right", "Allow Right", base.HEX, nil, 0x02, nil)
  f.mbino_avoidance_param_allow_back = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_allow_back", "Allow Back", base.HEX, nil, 0x04, nil)
  f.mbino_avoidance_param_allow_left = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_allow_left", "Allow Left", base.HEX, nil, 0x08, nil)
f.mbino_avoidance_param_index = ProtoField.uint8 ("dji_dumlv1.mbino_avoidance_param_index", "Index", base.HEX)

local function mbino_avoidance_param_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.mbino_avoidance_param_masked00, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_braking, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_visual_sensor_working, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_avoid_open, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_be_shuttle_mode, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_avoid_front_work, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_avoid_right_work, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_avoid_behind_work, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_avoid_left_work, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_avoidance_param_masked01, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_avoid_front_distance_level, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_avoid_front_alert_level, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_avoidance_param_masked02, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_avoid_right_distance_level, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_avoid_right_alert_level, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_avoidance_param_masked03, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_avoid_behind_distance_level, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_avoid_behind_alert_level, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_avoidance_param_masked04, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_avoid_left_distance_level, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_avoid_left_alert_level, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_avoidance_param_masked05, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_allow_front, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_allow_right, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_allow_back, payload(offset, 1))
    subtree:add_le (f.mbino_avoidance_param_allow_left, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_avoidance_param_index, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 7) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Eye Avoidance Param: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Eye Avoidance Param: Payload size different than expected") end
end

-- Mono/Binocular - Eye Obstacle Info - 0x07

enums.MBINO_OBSTACLE_INFO_SENSOR_TYPE_ENUM = {
    [0x00] = 'Front',
    [0x01] = 'Back',
    [0x02] = 'Right',
    [0x03] = 'Left',
    [0x04] = 'Top',
    [0x05] = 'Bottom',
    [0x64] = 'OTHER',
}

f.mbino_obstacle_info_masked00 = ProtoField.uint8 ("dji_dumlv1.mbino_obstacle_info_masked00", "Masked00", base.HEX)
  f.mbino_obstacle_info_observe_count = ProtoField.uint8 ("dji_dumlv1.mbino_obstacle_info_observe_count", "Observe Count", base.HEX, nil, 0x1f, nil)
  f.mbino_obstacle_info_sensor_type = ProtoField.uint8 ("dji_dumlv1.mbino_obstacle_info_sensor_type", "Sensor Type", base.HEX, enums.MBINO_OBSTACLE_INFO_SENSOR_TYPE_ENUM, 0xe0, nil)

local function mbino_obstacle_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.mbino_obstacle_info_masked00, payload(offset, 1))
    subtree:add_le (f.mbino_obstacle_info_observe_count, payload(offset, 1))
    subtree:add_le (f.mbino_obstacle_info_sensor_type, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Eye Obstacle Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Eye Obstacle Info: Payload size different than expected") end
end

-- Mono/Binocular - Eye TapGo Obst Avo Info - 0x08

f.mbino_tapgo_obst_avo_info_alert_level = ProtoField.uint8 ("dji_dumlv1.mbino_tapgo_obst_avo_info_alert_level", "Alert Level", base.HEX)
f.mbino_tapgo_obst_avo_info_observe_count = ProtoField.uint8 ("dji_dumlv1.mbino_tapgo_obst_avo_info_observe_count", "Observe Count", base.DEC)

local function mbino_tapgo_obst_avo_info_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.mbino_tapgo_obst_avo_info_alert_level, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_tapgo_obst_avo_info_observe_count, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Eye TapGo Obst Avo Info: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Eye TapGo Obst Avo Info: Payload size different than expected") end
end

-- Mono/Binocular - Eye Track Log - 0x0d

f.mbino_track_log_text = ProtoField.string ("dji_dumlv1.mbino_track_log_text", "Track Log", base.ASCII)

local function mbino_track_log_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    local log_text = payload(offset, payload:len() - offset)
    subtree:add (f.mbino_track_log_text, log_text)
    offset = payload:len()

    --if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Eye Track Log: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Eye Track Log: Payload size different than expected") end
end

-- Mono/Binocular - Eye Point Log - 0x0e

f.mbino_point_log_text = ProtoField.string ("dji_dumlv1.mbino_point_log_text", "Point Log", base.ASCII)

local function mbino_point_log_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    local log_text = payload(offset, payload:len() - offset)
    subtree:add (f.mbino_point_log_text, log_text)
    offset = payload:len()

    --if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Eye Point Log: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Eye Point Log: Payload size different than expected") end
end

-- Mono/Binocular - Eye Flat Check - 0x19

f.mbino_flat_check_tink_count = ProtoField.uint8 ("dji_dumlv1.mbino_flat_check_tink_count", "Tink Count", base.HEX)

local function mbino_flat_check_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.mbino_flat_check_tink_count, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Eye Flat Check: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Eye Flat Check: Payload size different than expected") end
end

-- Mono/Binocular - Eye Tracking Status Push - 0x23

enums.MBINO_TRACK_STATUS_RECT_MODE_TRACK_MODE_ENUM = {
    [0x00] = 'LOST',
    [0x01] = 'NORMAL',
    [0x02] = 'WEAK',
    [0x03] = 'DETECT_AFTER_LOST',
    [0x04] = 'TRACKING',
    [0x05] = 'CONFIRM',
    [0x06] = 'PERSON',
    [0x64] = 'OTHER',
}

enums.MBINO_TRACK_STATUS_TRACKING_MODE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x02] = 'c',
    [0x03] = 'd',
    [0x04] = 'e',
    [0x05] = 'f',
    [0xff] = 'g',
}

enums.MBINO_TRACK_STATUS_TARGET_TYPE_TARGET_OBJ_TYPE_ENUM = {
    [0x00] = 'UNKNOWN',
    [0x01] = 'PERSON',
    [0x02] = 'CAR',
    [0x03] = 'VAN',
    [0x04] = 'BIKE',
    [0x05] = 'ANIMAL',
    [0x06] = 'BOAT',
    [0x64] = 'OTHER',
}

enums.MBINO_TRACK_STATUS_TARGET_ACTION_ENUM = {
    [0x00] = 'Non',
    [0x01] = 'JUMP',
    [0x64] = 'OTHER',
}

f.mbino_tracking_status_push_rect_mode = ProtoField.uint8 ("dji_dumlv1.mbino_tracking_status_push_rect_mode", "Rect Mode", base.HEX, enums.MBINO_TRACK_STATUS_RECT_MODE_TRACK_MODE_ENUM, nil, nil)
f.mbino_tracking_status_push_center_x = ProtoField.float ("dji_dumlv1.mbino_tracking_status_push_center_x", "Center X", base.DEC)
f.mbino_tracking_status_push_center_y = ProtoField.float ("dji_dumlv1.mbino_tracking_status_push_center_y", "Center Y", base.DEC)
f.mbino_tracking_status_push_width = ProtoField.float ("dji_dumlv1.mbino_tracking_status_push_width", "Width", base.DEC)
f.mbino_tracking_status_push_height = ProtoField.float ("dji_dumlv1.mbino_tracking_status_push_height", "Height", base.DEC)
f.mbino_tracking_status_push_unknown11 = ProtoField.uint8 ("dji_dumlv1.mbino_tracking_status_push_unknown11", "Unknown11", base.HEX)
f.mbino_tracking_status_push_session_id = ProtoField.uint16 ("dji_dumlv1.mbino_tracking_status_push_session_id", "Session Id", base.HEX)
f.mbino_tracking_status_push_masked14 = ProtoField.uint8 ("dji_dumlv1.mbino_tracking_status_push_masked14", "Masked14", base.HEX)
  f.mbino_tracking_status_push_human_target = ProtoField.uint8 ("dji_dumlv1.mbino_tracking_status_push_human_target", "Human Target", base.HEX, nil, 0x01, nil)
  f.mbino_tracking_status_push_head_lock = ProtoField.uint8 ("dji_dumlv1.mbino_tracking_status_push_head_lock", "Head Lock", base.HEX, nil, 0x02, nil)
f.mbino_tracking_status_push_tracking_mode = ProtoField.uint8 ("dji_dumlv1.mbino_tracking_status_push_tracking_mode", "Tracking Mode", base.HEX, enums.MBINO_TRACK_STATUS_TRACKING_MODE_ENUM, nil, nil)
f.mbino_tracking_status_push_target_type = ProtoField.uint8 ("dji_dumlv1.mbino_tracking_status_push_target_type", "Target Type", base.HEX, enums.MBINO_TRACK_STATUS_TARGET_TYPE_TARGET_OBJ_TYPE_ENUM, nil, nil)
f.mbino_tracking_status_push_target_action = ProtoField.uint8 ("dji_dumlv1.mbino_tracking_status_push_target_action", "Target Action", base.HEX, enums.MBINO_TRACK_STATUS_TARGET_ACTION_ENUM, nil, nil)

local function mbino_tracking_status_push_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.mbino_tracking_status_push_rect_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_tracking_status_push_center_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.mbino_tracking_status_push_center_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.mbino_tracking_status_push_width, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.mbino_tracking_status_push_height, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.mbino_tracking_status_push_unknown11, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_tracking_status_push_session_id, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.mbino_tracking_status_push_masked14, payload(offset, 1))
    subtree:add_le (f.mbino_tracking_status_push_human_target, payload(offset, 1))
    subtree:add_le (f.mbino_tracking_status_push_head_lock, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_tracking_status_push_tracking_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_tracking_status_push_target_type, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_tracking_status_push_target_action, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 24) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Eye Tracking Status Push: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Eye Tracking Status Push: Payload size different than expected") end
end

-- Mono/Binocular - Eye TapGo Status Push - 0x26

enums.MBINO_TAPGO_STATUS_PUSH_TRAGET_MODE_POINT_MODE_ENUM = {
    [0x00] = 'HIDE',
    [0x01] = 'CANT_FLY',
    [0x02] = 'FLYING',
    [0x64] = 'OTHER',
}

enums.MBINO_TAPGO_STATUS_PUSH_TAP_MODE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x02] = 'c',
    [0x03] = 'd',
    [0x64] = 'e',
}

f.mbino_tapgo_status_push_traget_mode = ProtoField.uint8 ("dji_dumlv1.mbino_tapgo_status_push_traget_mode", "Traget Mode", base.HEX, enums.MBINO_TAPGO_STATUS_PUSH_TRAGET_MODE_POINT_MODE_ENUM, nil, nil)
f.mbino_tapgo_status_push_masked01 = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_masked01", "Masked01", base.HEX)
  f.mbino_tapgo_status_push_rc_not_in_f_mode = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_rc_not_in_f_mode", "Rc Not In F Mode", base.HEX, nil, 0x01, nil)
  f.mbino_tapgo_status_push_cant_detour = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_cant_detour", "Cant Detour", base.HEX, nil, 0x02, nil)
  f.mbino_tapgo_status_push_braked_by_collision = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_braked_by_collision", "Braked By Collision", base.HEX, nil, 0x04, nil)
  f.mbino_tapgo_status_push_detour_up = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_detour_up", "Detour Up", base.HEX, nil, 0x08, nil)
  f.mbino_tapgo_status_push_detour_left = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_detour_left", "Detour Left", base.HEX, nil, 0x10, nil)
  f.mbino_tapgo_status_push_detour_right = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_detour_right", "Detour Right", base.HEX, nil, 0x20, nil)
  f.mbino_tapgo_status_push_stick_add = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_stick_add", "Stick Add", base.HEX, nil, 0x40, nil)
  f.mbino_tapgo_status_push_out_of_range = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_out_of_range", "Out Of Range", base.HEX, nil, 0x80, nil)
  f.mbino_tapgo_status_push_user_quick_pull_pitch = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_user_quick_pull_pitch", "User Quick Pull Pitch", base.HEX, nil, 0x100, nil)
  f.mbino_tapgo_status_push_in_low_flying = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_in_low_flying", "In Low Flying", base.HEX, nil, 0x200, nil)
  f.mbino_tapgo_status_push_running_delay = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_running_delay", "Running Delay", base.HEX, nil, 0x400, nil)
  f.mbino_tapgo_status_push_in_pointing = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_in_pointing", "In Pointing", base.HEX, nil, 0x800, nil)
  f.mbino_tapgo_status_push_terrian_follow = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_terrian_follow", "Terrian Follow", base.HEX, nil, 0x1000, nil)
  f.mbino_tapgo_status_push_paused = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_paused", "Paused", base.HEX, nil, 0x2000, nil)
  f.mbino_tapgo_status_push_front_image_over_exposure = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_front_image_over_exposure", "Front Image Over Exposure", base.HEX, nil, 0x10000, nil)
  f.mbino_tapgo_status_push_front_image_under_exposure = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_front_image_under_exposure", "Front Image Under Exposure", base.HEX, nil, 0x20000, nil)
  f.mbino_tapgo_status_push_front_image_diff = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_front_image_diff", "Front Image Diff", base.HEX, nil, 0x40000, nil)
  f.mbino_tapgo_status_push_front_demark_error = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_front_demark_error", "Front Demark Error", base.HEX, nil, 0x80000, nil)
  f.mbino_tapgo_status_push_non_in_flying = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_non_in_flying", "Non In Flying", base.HEX, nil, 0x100000, nil)
  f.mbino_tapgo_status_push_had_tap_stop = ProtoField.uint24 ("dji_dumlv1.mbino_tapgo_status_push_had_tap_stop", "Had Tap Stop", base.HEX, nil, 0x200000, nil)
f.mbino_tapgo_status_push_axis_x = ProtoField.float ("dji_dumlv1.mbino_tapgo_status_push_axis_x", "Axis X", base.DEC)
f.mbino_tapgo_status_push_axis_y = ProtoField.float ("dji_dumlv1.mbino_tapgo_status_push_axis_y", "Axis Y", base.DEC)
f.mbino_tapgo_status_push_axis_z = ProtoField.float ("dji_dumlv1.mbino_tapgo_status_push_axis_z", "Axis Z", base.DEC)
f.mbino_tapgo_status_push_max_speed = ProtoField.uint16 ("dji_dumlv1.mbino_tapgo_status_push_max_speed", "Max Speed", base.HEX)
f.mbino_tapgo_status_push_session_id = ProtoField.uint16 ("dji_dumlv1.mbino_tapgo_status_push_session_id", "Session Id", base.HEX)
f.mbino_tapgo_status_push_tap_mode = ProtoField.uint8 ("dji_dumlv1.mbino_tapgo_status_push_tap_mode", "Tap Mode", base.HEX, enums.MBINO_TAPGO_STATUS_PUSH_TAP_MODE_ENUM, nil, nil)

local function mbino_tapgo_status_push_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.mbino_tapgo_status_push_traget_mode, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_tapgo_status_push_masked01, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_rc_not_in_f_mode, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_cant_detour, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_braked_by_collision, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_detour_up, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_detour_left, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_detour_right, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_stick_add, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_out_of_range, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_user_quick_pull_pitch, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_in_low_flying, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_running_delay, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_in_pointing, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_terrian_follow, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_paused, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_front_image_over_exposure, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_front_image_under_exposure, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_front_image_diff, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_front_demark_error, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_non_in_flying, payload(offset, 3))
    subtree:add_le (f.mbino_tapgo_status_push_had_tap_stop, payload(offset, 3))
    offset = offset + 3

    subtree:add_le (f.mbino_tapgo_status_push_axis_x, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.mbino_tapgo_status_push_axis_y, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.mbino_tapgo_status_push_axis_z, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.mbino_tapgo_status_push_max_speed, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.mbino_tapgo_status_push_session_id, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.mbino_tapgo_status_push_tap_mode, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 21) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Eye TapGo Status Push: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Eye TapGo Status Push: Payload size different than expected") end
end

-- Mono/Binocular - Eye Com Status Update - 0x2a

enums.MBINO_COM_STATUS_UPDATE_TRACK_EXCEPTION_STATUS_ENUM = {
    [0x00] = 'NORMAL',
    [0x01] = 'LOST_TIMEOUT',
    [0x02] = 'INVALID_SPEED',
    [0x03] = 'NONE_IMAGE',
    [0x04] = 'LOW_FRAME',
    [0x05] = 'NFZ',
    [0x06] = 'RCCONN_TIMEOUT',
    [0x07] = 'APPCONN_TIMEOUT',
    [0x09] = 'LOST_CONTROL',
    [0x64] = 'OTHER',
}

enums.MBINO_COM_STATUS_UPDATE_ADVANCE_GO_HOME_STATE_ENUM = {
    [0x00] = 'NO_ACTION',
    [0x01] = 'TURNING_YAW',
    [0x02] = 'EXECUTING_GO_HOME',
    [0x03] = 'HOVERING_AT_SAFE_POINT',
    [0x04] = 'PLANING',
    [0x64] = 'OTHER',
}

enums.MBINO_COM_STATUS_UPDATE_ADVANCE_GO_HOME_STRATEGY_ENUM = {
    [0x00] = 'NO_STRATEGY',
    [0x01] = 'SAFE_STRATEGY',
    [0x02] = 'EXPLORE_STRATEGY',
    [0x64] = 'OTHER',
}

enums.MBINO_COM_STATUS_UPDATE_PRECISE_LANDING_STATE_ENUM = {
    [0x00] = 'NO_ACTION',
    [0x01] = 'TURNING_YAW',
    [0x02] = 'LANDING',
    [0x64] = 'OTHER',
}

f.mbino_com_status_update_masked00 = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_masked00", "Masked00", base.HEX)
  f.mbino_com_status_update_track_system_abnormal = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_track_system_abnormal", "Track System Abnormal", base.HEX, nil, 0x01, nil)
  f.mbino_com_status_update_point_system_abnormal = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_point_system_abnormal", "Point System Abnormal", base.HEX, nil, 0x02, nil)
  f.mbino_com_status_update_disparity_pack_lost = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_disparity_pack_lost", "Disparity Pack Lost", base.HEX, nil, 0x04, nil)
  f.mbino_com_status_update_imu_pack_lost = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_imu_pack_lost", "Imu Pack Lost", base.HEX, nil, 0x08, nil)
  f.mbino_com_status_update_gimbal_pack_lost = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_gimbal_pack_lost", "Gimbal Pack Lost", base.HEX, nil, 0x10, nil)
  f.mbino_com_status_update_rc_pack_lost = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_rc_pack_lost", "Rc Pack Lost", base.HEX, nil, 0x20, nil)
  f.mbino_com_status_update_visual_data_abnormal = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_visual_data_abnormal", "Visual Data Abnormal", base.HEX, nil, 0x40, nil)
  f.mbino_com_status_update_fron_image_over_exposure = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_fron_image_over_exposure", "Fron Image Over Exposure", base.HEX, nil, 0x100, nil)
  f.mbino_com_status_update_fron_image_under_exposure = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_fron_image_under_exposure", "Fron Image Under Exposure", base.HEX, nil, 0x200, nil)
  f.mbino_com_status_update_front_image_diff = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_front_image_diff", "Front Image Diff", base.HEX, nil, 0x400, nil)
  f.mbino_com_status_update_front_sensor_demark_abnormal = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_front_sensor_demark_abnormal", "Front Sensor Demark Abnormal", base.HEX, nil, 0x800, nil)
  f.mbino_com_status_update_non_flying = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_non_flying", "Non Flying", base.HEX, nil, 0x1000, nil)
  f.mbino_com_status_update_user_tap_stop = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_user_tap_stop", "User Tap Stop", base.HEX, nil, 0x2000, nil)
  f.mbino_com_status_update_tripod_folded = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_tripod_folded", "Tripod Folded", base.HEX, nil, 0x4000, nil)
f.mbino_com_status_update_masked02 = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_masked02", "Masked02", base.HEX)
  f.mbino_com_status_update_rc_disconnect = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_rc_disconnect", "Rc Disconnect", base.HEX, nil, 0x1, nil)
  f.mbino_com_status_update_app_disconnect = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_app_disconnect", "App Disconnect", base.HEX, nil, 0x2, nil)
  f.mbino_com_status_update_out_of_control = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_out_of_control", "Out Of Control", base.HEX, nil, 0x4, nil)
  f.mbino_com_status_update_in_non_fly_zone = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_in_non_fly_zone", "In Non Fly Zone", base.HEX, nil, 0x8, nil)
  f.mbino_com_status_update_fusion_data_abnormal = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_fusion_data_abnormal", "Fusion Data Abnormal", base.HEX, nil, 0x10, nil)
f.mbino_com_status_update_masked03 = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_masked03", "Masked03", base.HEX)
  f.mbino_com_status_update_in_tracking = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_in_tracking", "In Tracking", base.HEX, nil, 0x01, nil)
  f.mbino_com_status_update_in_tap_fly = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_in_tap_fly", "In Tap Fly", base.HEX, nil, 0x02, nil)
  f.mbino_com_status_update_in_advance_homing = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_in_advance_homing", "In Advance Homing", base.HEX, nil, 0x04, nil)
  f.mbino_com_status_update_in_precise_landing = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_in_precise_landing", "In Precise Landing", base.HEX, nil, 0x08, nil)
  f.mbino_com_status_update_face_detect_enable = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_face_detect_enable", "Face Detect Enable", base.HEX, nil, 0x10, nil)
  f.mbino_com_status_update_moving_object_detect_enable = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_moving_object_detect_enable", "Moving Object Detect Enable", base.HEX, nil, 0x20, nil)
  f.mbino_com_status_update_gps_tracking_enable = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_gps_tracking_enable", "Gps Tracking Enable", base.HEX, nil, 0x40, nil)
f.mbino_com_status_update_masked04 = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_masked04", "Masked04", base.HEX)
  -- Not sure how to choose between this and alternate content
  f.mbino_com_status_update_gps_error = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_gps_error", "Gps Error", base.HEX, nil, 0x01, nil)
  f.mbino_com_status_update_front_visoin_error = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_front_visoin_error", "Front Visoin Error", base.HEX, nil, 0x02, nil)
  f.mbino_com_status_update_advance_go_home_state = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_advance_go_home_state", "Advance Go Home State", base.HEX, enums.MBINO_COM_STATUS_UPDATE_ADVANCE_GO_HOME_STATE_ENUM, 0x1c, nil)
  f.mbino_com_status_update_advance_go_home_strategy = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_advance_go_home_strategy", "Advance Go Home Strategy", base.HEX, enums.MBINO_COM_STATUS_UPDATE_ADVANCE_GO_HOME_STRATEGY_ENUM, 0x60, nil)
  -- Alternate content of the masked04 field
  f.mbino_com_status_update_track_status = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_track_status", "Track Status", base.HEX, enums.MBINO_COM_STATUS_UPDATE_TRACK_EXCEPTION_STATUS_ENUM, 0x0f, nil)
  f.mbino_com_status_update_aircraft_gps_abnormal = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_aircraft_gps_abnormal", "Aircraft Gps Abnormal", base.HEX, nil, 0x10, nil)
  f.mbino_com_status_update_phone_gps_abnormal = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_phone_gps_abnormal", "Phone Gps Abnormal", base.HEX, nil, 0x20, nil)
  f.mbino_com_status_update_gps_tracking_flusion_abnormal = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_gps_tracking_flusion_abnormal", "Gps Tracking Flusion Abnormal", base.HEX, nil, 0x40, nil)
f.mbino_com_status_update_masked05 = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_masked05", "Masked05", base.HEX)
  f.mbino_com_status_update_avoid_ok_in_tracking = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_avoid_ok_in_tracking", "Avoid Ok In Tracking", base.HEX, nil, 0x01, nil)
  f.mbino_com_status_update_cant_detour_in_tracking = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_cant_detour_in_tracking", "Cant Detour In Tracking", base.HEX, nil, 0x02, nil)
  f.mbino_com_status_update_decelerating_in_tracking = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_decelerating_in_tracking", "Decelerating In Tracking", base.HEX, nil, 0x04, nil)
  f.mbino_com_status_update_braked_by_collision_in_tracking = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_braked_by_collision_in_tracking", "Braked By Collision In Tracking", base.HEX, nil, 0x08, nil)
  f.mbino_com_status_update_detour_up_in_tracking = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_detour_up_in_tracking", "Detour Up In Tracking", base.HEX, nil, 0x10, nil)
  f.mbino_com_status_update_detour_down_in_tracking = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_detour_down_in_tracking", "Detour Down In Tracking", base.HEX, nil, 0x20, nil)
  f.mbino_com_status_update_detour_left_in_tracking = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_detour_left_in_tracking", "Detour Left In Tracking", base.HEX, nil, 0x40, nil)
  f.mbino_com_status_update_detour_right_in_tracking = ProtoField.uint8 ("dji_dumlv1.mbino_com_status_update_detour_right_in_tracking", "Detour Right In Tracking", base.HEX, nil, 0x80, nil)
f.mbino_com_status_update_masked06 = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_masked06", "Masked06", base.HEX)
  -- Not sure how to choose between this and alternate content (again)
  f.mbino_com_status_update_effected_by_obstacle = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_effected_by_obstacle", "Effected By Obstacle", base.HEX, nil, 0x01, nil)
  f.mbino_com_status_update_cant_detour = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_cant_detour", "Cant Detour", base.HEX, nil, 0x02, nil)
  f.mbino_com_status_update_braked_by_collision = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_braked_by_collision", "Braked By Collision", base.HEX, nil, 0x04, nil)
  f.mbino_com_status_update_detour_up = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_detour_up", "Detour Up", base.HEX, nil, 0x08, nil)
  f.mbino_com_status_update_detour_left = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_detour_left", "Detour Left", base.HEX, nil, 0x10, nil)
  f.mbino_com_status_update_detour_right = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_detour_right", "Detour Right", base.HEX, nil, 0x20, nil)
  f.mbino_com_status_update_stick_add = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_stick_add", "Stick Add", base.HEX, nil, 0x40, nil)
  f.mbino_com_status_update_out_of_range = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_out_of_range", "Out Of Range", base.HEX, nil, 0x80, nil)
  -- Alternate content of the masked04 field
  f.mbino_com_status_update_rc_not_in_f_mode = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_rc_not_in_f_mode", "Rc Not In F Mode", base.HEX, nil, 0x01, nil)
  f.mbino_com_status_update_precise_landing_state = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_precise_landing_state", "Precise Landing State", base.HEX, enums.MBINO_COM_STATUS_UPDATE_PRECISE_LANDING_STATE_ENUM, 0x06, nil)
  f.mbino_com_status_update_adjusting_precise_landing = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_adjusting_precise_landing", "Adjusting Precise Landing", base.HEX, nil, 0x08, nil)
  f.mbino_com_status_update_executing_precise_landing = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_executing_precise_landing", "Executing Precise Landing", base.HEX, nil, 0x10, nil)
  -- Back to one path
  f.mbino_com_status_update_user_quick_pull_pitch = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_user_quick_pull_pitch", "User Quick Pull Pitch", base.HEX, nil, 0x100, nil)
  f.mbino_com_status_update_in_low_flying = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_in_low_flying", "In Low Flying", base.HEX, nil, 0x200, nil)
  f.mbino_com_status_update_running_delay = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_running_delay", "Running Delay", base.HEX, nil, 0x400, nil)
  f.mbino_com_status_update_in_pointing = ProtoField.uint16 ("dji_dumlv1.mbino_com_status_update_in_pointing", "In Pointing", base.HEX, nil, 0x800, nil)
f.mbino_com_status_update_vision_version = ProtoField.uint32 ("dji_dumlv1.mbino_com_status_update_vision_version", "Vision Version", base.HEX)

local function mbino_com_status_update_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.mbino_com_status_update_masked00, payload(offset, 2))
    subtree:add_le (f.mbino_com_status_update_track_system_abnormal, payload(offset, 2))
    subtree:add_le (f.mbino_com_status_update_point_system_abnormal, payload(offset, 2))
    subtree:add_le (f.mbino_com_status_update_disparity_pack_lost, payload(offset, 2))
    subtree:add_le (f.mbino_com_status_update_imu_pack_lost, payload(offset, 2))
    subtree:add_le (f.mbino_com_status_update_gimbal_pack_lost, payload(offset, 2))
    subtree:add_le (f.mbino_com_status_update_rc_pack_lost, payload(offset, 2))
    subtree:add_le (f.mbino_com_status_update_visual_data_abnormal, payload(offset, 2))
    subtree:add_le (f.mbino_com_status_update_fron_image_over_exposure, payload(offset, 2))
    subtree:add_le (f.mbino_com_status_update_fron_image_under_exposure, payload(offset, 2))
    subtree:add_le (f.mbino_com_status_update_front_image_diff, payload(offset, 2))
    subtree:add_le (f.mbino_com_status_update_front_sensor_demark_abnormal, payload(offset, 2))
    subtree:add_le (f.mbino_com_status_update_non_flying, payload(offset, 2))
    subtree:add_le (f.mbino_com_status_update_user_tap_stop, payload(offset, 2))
    subtree:add_le (f.mbino_com_status_update_tripod_folded, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.mbino_com_status_update_masked02, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_rc_disconnect, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_app_disconnect, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_out_of_control, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_in_non_fly_zone, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_fusion_data_abnormal, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_com_status_update_masked03, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_in_tracking, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_in_tap_fly, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_in_advance_homing, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_in_precise_landing, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_face_detect_enable, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_moving_object_detect_enable, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_gps_tracking_enable, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_com_status_update_masked04, payload(offset, 1))
    if (true) then -- it is not known what the condition should be
        subtree:add_le (f.mbino_com_status_update_gps_error, payload(offset, 1))
        subtree:add_le (f.mbino_com_status_update_front_visoin_error, payload(offset, 1))
        subtree:add_le (f.mbino_com_status_update_advance_go_home_state, payload(offset, 1))
        subtree:add_le (f.mbino_com_status_update_advance_go_home_strategy, payload(offset, 1))
    else
        subtree:add_le (f.mbino_com_status_update_track_status, payload(offset, 1))
        subtree:add_le (f.mbino_com_status_update_aircraft_gps_abnormal, payload(offset, 1))
        subtree:add_le (f.mbino_com_status_update_phone_gps_abnormal, payload(offset, 1))
        subtree:add_le (f.mbino_com_status_update_gps_tracking_flusion_abnormal, payload(offset, 1))
    end
    offset = offset + 1

    subtree:add_le (f.mbino_com_status_update_masked05, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_avoid_ok_in_tracking, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_cant_detour_in_tracking, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_decelerating_in_tracking, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_braked_by_collision_in_tracking, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_detour_up_in_tracking, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_detour_down_in_tracking, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_detour_left_in_tracking, payload(offset, 1))
    subtree:add_le (f.mbino_com_status_update_detour_right_in_tracking, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_com_status_update_masked06, payload(offset, 2))
    if (true) then -- it is not known what the condition should be
        subtree:add_le (f.mbino_com_status_update_effected_by_obstacle, payload(offset, 2))
        subtree:add_le (f.mbino_com_status_update_cant_detour, payload(offset, 2))
        subtree:add_le (f.mbino_com_status_update_braked_by_collision, payload(offset, 2))
        subtree:add_le (f.mbino_com_status_update_detour_up, payload(offset, 2))
        subtree:add_le (f.mbino_com_status_update_detour_left, payload(offset, 2))
        subtree:add_le (f.mbino_com_status_update_detour_right, payload(offset, 2))
        subtree:add_le (f.mbino_com_status_update_stick_add, payload(offset, 2))
        subtree:add_le (f.mbino_com_status_update_out_of_range, payload(offset, 2))
    else
        subtree:add_le (f.mbino_com_status_update_rc_not_in_f_mode, payload(offset, 2))
        subtree:add_le (f.mbino_com_status_update_precise_landing_state, payload(offset, 2))
        subtree:add_le (f.mbino_com_status_update_adjusting_precise_landing, payload(offset, 2))
        subtree:add_le (f.mbino_com_status_update_executing_precise_landing, payload(offset, 2))
    end
    subtree:add_le (f.mbino_com_status_update_user_quick_pull_pitch, payload(offset, 2))
    subtree:add_le (f.mbino_com_status_update_in_low_flying, payload(offset, 2))
    subtree:add_le (f.mbino_com_status_update_running_delay, payload(offset, 2))
    subtree:add_le (f.mbino_com_status_update_in_pointing, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.mbino_com_status_update_vision_version, payload(offset, 4))
    offset = offset + 4

    if (offset ~= 12) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Eye Com Status Update: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Eye Com Status Update: Payload size different than expected") end
end

-- Mono/Binocular - Eye Function List Push - 0x2e

f.mbino_function_list_tink_count = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_tink_count", "Tink Count", base.HEX)
f.mbino_function_list_masked01 = ProtoField.uint32 ("dji_dumlv1.mbino_function_list_masked01", "Masked01", base.HEX)
  f.mbino_function_list_support_self_cal = ProtoField.uint32 ("dji_dumlv1.mbino_function_list_support_self_cal", "Support Self Cal", base.HEX, nil, 0x01, nil)
  f.mbino_function_list_sensor_status_source = ProtoField.uint32 ("dji_dumlv1.mbino_function_list_sensor_status_source", "Sensor Status Source", base.HEX, nil, 0x02, nil)
f.mbino_function_list_front_disable = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_front_disable", "Front Disable", base.HEX)
  f.mbino_function_list_front_disable_when_auto_landing = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_front_disable_when_auto_landing", "Front Disable When Auto Landing", base.HEX, nil, 0x01, nil)
  f.mbino_function_list_front_disable_by_tripod = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_front_disable_by_tripod", "Front Disable By Tripod", base.HEX, nil, 0x02, nil)
  f.mbino_function_list_front_disable_by_switch_sensor = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_front_disable_by_switch_sensor", "Front Disable By Switch Sensor", base.HEX, nil, 0x04, nil)
  f.mbino_function_list_front_atti_too_large = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_front_atti_too_large", "Front Atti Too Large", base.HEX, nil, 0x08, nil)
f.mbino_function_list_back_disable = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_back_disable", "Back Disable", base.HEX)
  f.mbino_function_list_back_disable_when_auto_landing = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_back_disable_when_auto_landing", "Back Disable When Auto Landing", base.HEX, nil, 0x01, nil)
  f.mbino_function_list_back_disable_by_tripod = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_back_disable_by_tripod", "Back Disable By Tripod", base.HEX, nil, 0x02, nil)
  f.mbino_function_list_back_disable_by_switch_sensor = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_back_disable_by_switch_sensor", "Back Disable By Switch Sensor", base.HEX, nil, 0x04, nil)
  f.mbino_function_list_back_atti_too_large = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_back_atti_too_large", "Back Atti Too Large", base.HEX, nil, 0x08, nil)
f.mbino_function_list_right_disable = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_right_disable", "Right Disable", base.HEX)
  f.mbino_function_list_right_disable_when_auto_landing = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_right_disable_when_auto_landing", "Right Disable When Auto Landing", base.HEX, nil, 0x01, nil)
  f.mbino_function_list_right_disable_by_tripod = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_right_disable_by_tripod", "Right Disable By Tripod", base.HEX, nil, 0x02, nil)
  f.mbino_function_list_right_atti_too_large = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_right_atti_too_large", "Right Atti Too Large", base.HEX, nil, 0x08, nil)
f.mbino_function_list_left_disable = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_left_disable", "Left Disable", base.HEX)
  f.mbino_function_list_left_disable_when_auto_landing = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_left_disable_when_auto_landing", "Left Disable When Auto Landing", base.HEX, nil, 0x01, nil)
  f.mbino_function_list_left_disable_by_tripod = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_left_disable_by_tripod", "Left Disable By Tripod", base.HEX, nil, 0x02, nil)
  f.mbino_function_list_left_atti_too_large = ProtoField.uint8 ("dji_dumlv1.mbino_function_list_left_atti_too_large", "Left Atti Too Large", base.HEX, nil, 0x08, nil)

local function mbino_function_list_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.mbino_function_list_tink_count, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_function_list_masked01, payload(offset, 4))
    subtree:add_le (f.mbino_function_list_support_self_cal, payload(offset, 4))
    subtree:add_le (f.mbino_function_list_sensor_status_source, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.mbino_function_list_front_disable, payload(offset, 1))
    subtree:add_le (f.mbino_function_list_front_disable_when_auto_landing, payload(offset, 1))
    subtree:add_le (f.mbino_function_list_front_disable_by_tripod, payload(offset, 1))
    subtree:add_le (f.mbino_function_list_front_disable_by_switch_sensor, payload(offset, 1))
    subtree:add_le (f.mbino_function_list_front_atti_too_large, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_function_list_back_disable, payload(offset, 1))
    subtree:add_le (f.mbino_function_list_back_disable_when_auto_landing, payload(offset, 1))
    subtree:add_le (f.mbino_function_list_back_disable_by_tripod, payload(offset, 1))
    subtree:add_le (f.mbino_function_list_back_disable_by_switch_sensor, payload(offset, 1))
    subtree:add_le (f.mbino_function_list_back_atti_too_large, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_function_list_right_disable, payload(offset, 1))
    subtree:add_le (f.mbino_function_list_right_disable_when_auto_landing, payload(offset, 1))
    subtree:add_le (f.mbino_function_list_right_disable_by_tripod, payload(offset, 1))
    subtree:add_le (f.mbino_function_list_right_atti_too_large, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_function_list_left_disable, payload(offset, 1))
    subtree:add_le (f.mbino_function_list_left_disable_when_auto_landing, payload(offset, 1))
    subtree:add_le (f.mbino_function_list_left_disable_by_tripod, payload(offset, 1))
    subtree:add_le (f.mbino_function_list_left_atti_too_large, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 9) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Eye Function List Push: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Eye Function List Push: Payload size different than expected") end
end

-- Mono/Binocular - Eye Sensor Status Push - 0x2f

f.mbino_sensor_status_push_cnt_index = ProtoField.uint8 ("dji_dumlv1.mbino_sensor_status_push_cnt_index", "Cnt Index", base.HEX)
f.mbino_sensor_status_push_masked01 = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_masked01", "Masked01", base.HEX)
  f.mbino_sensor_status_push_bottom_image_exposure_too_long = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_bottom_image_exposure_too_long", "Bottom Image Exposure Too Long", base.HEX, nil, 0x08, nil)
  f.mbino_sensor_status_push_bottom_image_diff = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_bottom_image_diff", "Bottom Image Diff", base.HEX, nil, 0x10, nil)
  f.mbino_sensor_status_push_bottom_under_exposure = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_bottom_under_exposure", "Bottom Under Exposure", base.HEX, nil, 0x20, nil)
  f.mbino_sensor_status_push_bottom_over_exposure = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_bottom_over_exposure", "Bottom Over Exposure", base.HEX, nil, 0x40, nil)
  f.mbino_sensor_status_push_bottom_image_exception = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_bottom_image_exception", "Bottom Image Exception", base.HEX, nil, 0x80, nil)
f.mbino_sensor_status_push_masked03 = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_masked03", "Masked03", base.HEX)
  f.mbino_sensor_status_push_front_image_exposure_too_long = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_front_image_exposure_too_long", "Front Image Exposure Too Long", base.HEX, nil, 0x08, nil)
  f.mbino_sensor_status_push_front_image_diff = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_front_image_diff", "Front Image Diff", base.HEX, nil, 0x10, nil)
  f.mbino_sensor_status_push_front_under_exposure = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_front_under_exposure", "Front Under Exposure", base.HEX, nil, 0x20, nil)
  f.mbino_sensor_status_push_front_over_exposure = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_front_over_exposure", "Front Over Exposure", base.HEX, nil, 0x40, nil)
  f.mbino_sensor_status_push_front_image_exception = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_front_image_exception", "Front Image Exception", base.HEX, nil, 0x80, nil)
f.mbino_sensor_status_push_masked05 = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_masked05", "Masked05", base.HEX)
  f.mbino_sensor_status_push_back_image_exposure_too_long = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_back_image_exposure_too_long", "Back Image Exposure Too Long", base.HEX, nil, 0x08, nil)
  f.mbino_sensor_status_push_back_image_diff = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_back_image_diff", "Back Image Diff", base.HEX, nil, 0x10, nil)
  f.mbino_sensor_status_push_back_under_exposure = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_back_under_exposure", "Back Under Exposure", base.HEX, nil, 0x20, nil)
  f.mbino_sensor_status_push_back_over_exposure = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_back_over_exposure", "Back Over Exposure", base.HEX, nil, 0x40, nil)
  f.mbino_sensor_status_push_back_image_exception = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_back_image_exception", "Back Image Exception", base.HEX, nil, 0x80, nil)
f.mbino_sensor_status_push_masked07 = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_masked07", "Masked07", base.HEX)
  f.mbino_sensor_status_push_right3_dtof_abnormal = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_right3_dtof_abnormal", "Right3 Dtof Abnormal", base.HEX, nil, 0x01, nil)
  f.mbino_sensor_status_push_right_image_exposure_too_long = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_right_image_exposure_too_long", "Right Image Exposure Too Long", base.HEX, nil, 0x08, nil)
  f.mbino_sensor_status_push_right_image_diff = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_right_image_diff", "Right Image Diff", base.HEX, nil, 0x10, nil)
  f.mbino_sensor_status_push_right_under_exposure = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_right_under_exposure", "Right Under Exposure", base.HEX, nil, 0x20, nil)
  f.mbino_sensor_status_push_right_over_exposure = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_right_over_exposure", "Right Over Exposure", base.HEX, nil, 0x40, nil)
  f.mbino_sensor_status_push_right_image_exception = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_right_image_exception", "Right Image Exception", base.HEX, nil, 0x80, nil)
f.mbino_sensor_status_push_masked09 = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_masked09", "Masked09", base.HEX)
  f.mbino_sensor_status_push_left3_dtof_abnormal = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_left3_dtof_abnormal", "Left3 Dtof Abnormal", base.HEX, nil, 0x01, nil)
  f.mbino_sensor_status_push_left_image_exposure_too_long = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_left_image_exposure_too_long", "Left Image Exposure Too Long", base.HEX, nil, 0x08, nil)
  f.mbino_sensor_status_push_left_image_diff = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_left_image_diff", "Left Image Diff", base.HEX, nil, 0x10, nil)
  f.mbino_sensor_status_push_left_under_exposure = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_left_under_exposure", "Left Under Exposure", base.HEX, nil, 0x20, nil)
  f.mbino_sensor_status_push_left_over_exposure = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_left_over_exposure", "Left Over Exposure", base.HEX, nil, 0x40, nil)
  f.mbino_sensor_status_push_left_image_exception = ProtoField.uint16 ("dji_dumlv1.mbino_sensor_status_push_left_image_exception", "Left Image Exception", base.HEX, nil, 0x80, nil)

local function mbino_sensor_status_push_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.mbino_sensor_status_push_cnt_index, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_sensor_status_push_masked01, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_bottom_image_exposure_too_long, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_bottom_image_diff, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_bottom_under_exposure, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_bottom_over_exposure, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_bottom_image_exception, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.mbino_sensor_status_push_masked03, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_front_image_exposure_too_long, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_front_image_diff, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_front_under_exposure, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_front_over_exposure, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_front_image_exception, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.mbino_sensor_status_push_masked05, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_back_image_exposure_too_long, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_back_image_diff, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_back_under_exposure, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_back_over_exposure, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_back_image_exception, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.mbino_sensor_status_push_masked07, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_right3_dtof_abnormal, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_right_image_exposure_too_long, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_right_image_diff, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_right_under_exposure, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_right_over_exposure, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_right_image_exception, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.mbino_sensor_status_push_masked09, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_left3_dtof_abnormal, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_left_image_exposure_too_long, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_left_image_diff, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_left_under_exposure, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_left_over_exposure, payload(offset, 2))
    subtree:add_le (f.mbino_sensor_status_push_left_image_exception, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 11) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Eye Sensor Status Push: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Eye Sensor Status Push: Payload size different than expected") end
end

-- Mono/Binocular - Eye Easy Self Calib State - 0x32

enums.MBINO_EASY_SELF_CALIB_STATE_VISION_SENSOR_TYPE_ENUM = {
    [0x00] = 'None',
    [0x01] = 'Bottom',
    [0x02] = 'Forward',
    [0x03] = 'Right',
    [0x04] = 'Backward',
    [0x05] = 'Left',
    [0x06] = 'Top',
    [0x64] = 'OTHER',
}

f.mbino_easy_self_calib_state_tink_count = ProtoField.uint8 ("dji_dumlv1.mbino_easy_self_calib_state_tink_count", "Tink Count", base.HEX)
f.mbino_easy_self_calib_state_unknown01 = ProtoField.uint8 ("dji_dumlv1.mbino_easy_self_calib_state_unknown01", "Unknown01", base.HEX)
f.mbino_easy_self_calib_state_sensor_type = ProtoField.uint8 ("dji_dumlv1.mbino_easy_self_calib_state_sensor_type", "Sensor Type", base.HEX, enums.MBINO_EASY_SELF_CALIB_STATE_VISION_SENSOR_TYPE_ENUM, nil, nil)

local function mbino_easy_self_calib_state_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.mbino_easy_self_calib_state_tink_count, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_easy_self_calib_state_unknown01, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_easy_self_calib_state_sensor_type, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 3) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Eye Easy Self Calib State: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Eye Easy Self Calib State: Payload size different than expected") end
end

-- Mono/Binocular - Eye Vision Tip - 0x39

enums.MBINO_VISION_TIP_B_TRACKING_TIP_TYPE_ENUM = {
    [0x00] = 'a',
    [0x01] = 'b',
    [0x02] = 'c',
    [0x03] = 'd',
    [0x04] = 'e',
    [0x05] = 'f',
    [0x06] = 'g',
}

f.mbino_vision_tip_a = ProtoField.uint8 ("dji_dumlv1.mbino_vision_tip_a", "A", base.HEX)
f.mbino_vision_tip_b = ProtoField.uint8 ("dji_dumlv1.mbino_vision_tip_b", "B", base.HEX, enums.MBINO_VISION_TIP_B_TRACKING_TIP_TYPE_ENUM, nil, nil)
f.mbino_vision_tip_c = ProtoField.uint8 ("dji_dumlv1.mbino_vision_tip_c", "C", base.HEX)
f.mbino_vision_tip_d = ProtoField.uint8 ("dji_dumlv1.mbino_vision_tip_d", "D", base.HEX)

local function mbino_vision_tip_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.mbino_vision_tip_a, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_vision_tip_b, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_vision_tip_c, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.mbino_vision_tip_d, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Eye Vision Tip: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Eye Vision Tip: Payload size different than expected") end
end

-- Mono/Binocular - Eye Precise Landing Energy - 0x3a

f.mbino_precise_landing_energy_enery = ProtoField.uint8 ("dji_dumlv1.mbino_precise_landing_energy_enery", "Enery", base.HEX)

local function mbino_precise_landing_energy_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.mbino_precise_landing_energy_enery, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Eye Precise Landing Energy: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Eye Precise Landing Energy: Payload size different than expected") end
end

local MBINO_UART_CMD_DISSECT = {
    [0x01] = mbino_bino_info_dissector,
    [0x06] = mbino_avoidance_param_dissector,
    [0x07] = mbino_obstacle_info_dissector,
    [0x08] = mbino_tapgo_obst_avo_info_dissector,
    [0x0d] = mbino_track_log_dissector,
    [0x0e] = mbino_point_log_dissector,
    [0x19] = mbino_flat_check_dissector,
    [0x23] = mbino_tracking_status_push_dissector,
    [0x26] = mbino_tapgo_status_push_dissector,
    [0x2a] = mbino_com_status_update_dissector,
    [0x2e] = mbino_function_list_dissector,
    [0x2f] = mbino_sensor_status_push_dissector,
    [0x32] = mbino_easy_self_calib_state_dissector,
    [0x39] = mbino_vision_tip_dissector,
    [0x3a] = mbino_precise_landing_energy_dissector,
}

-- Simulation - Simu Connect Heart Packet - 0x01

f.sim_connect_heart_packet_unknown00 = ProtoField.uint8 ("dji_dumlv1.sim_connect_heart_packet_unknown00", "Unknown00", base.HEX)
f.sim_connect_heart_packet_result = ProtoField.uint8 ("dji_dumlv1.sim_connect_heart_packet_result", "Result", base.HEX)

local function sim_connect_heart_packet_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.sim_connect_heart_packet_unknown00, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.sim_connect_heart_packet_result, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Simu Connect Heart Packet: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Simu Connect Heart Packet: Payload size different than expected") end
end

-- Simulation - Simu SDR Status Push - 0x03

f.sim_sdr_status_push_drone_type = ProtoField.uint8 ("dji_dumlv1.sim_sdr_status_push_drone_type", "Drone Type", base.HEX)

local function sim_sdr_status_push_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.sim_sdr_status_push_drone_type, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 1) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Simu SDR Status Push: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Simu SDR Status Push: Payload size different than expected") end
end

-- Simulation - Simu Flight Status Params - 0x06

f.sim_flight_status_params_length = ProtoField.uint8 ("dji_dumlv1.sim_flight_status_params_length", "Length", base.HEX)
f.sim_flight_status_params_masked01 = ProtoField.uint8 ("dji_dumlv1.sim_flight_status_params_masked01", "Masked01", base.HEX)
  f.sim_flight_status_params_has_motor_turned_on = ProtoField.uint8 ("dji_dumlv1.sim_flight_status_params_has_motor_turned_on", "Has Motor Turned On", base.HEX, nil, 0x01, nil)
  f.sim_flight_status_params_in_the_air = ProtoField.uint8 ("dji_dumlv1.sim_flight_status_params_in_the_air", "In The Air", base.HEX, nil, 0x02, nil)

local function sim_flight_status_params_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.sim_flight_status_params_length, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.sim_flight_status_params_masked01, payload(offset, 1))
    subtree:add_le (f.sim_flight_status_params_has_motor_turned_on, payload(offset, 1))
    subtree:add_le (f.sim_flight_status_params_in_the_air, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Simu Flight Status Params: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Simu Flight Status Params: Payload size different than expected") end
end

-- Simulation - Simu Wind - 0x07

f.sim_wind_wind_speed_x = ProtoField.uint16 ("dji_dumlv1.sim_wind_wind_speed_x", "Wind Speed X", base.HEX)
f.sim_wind_wind_speed_y = ProtoField.uint16 ("dji_dumlv1.sim_wind_wind_speed_y", "Wind Speed Y", base.HEX)

local function sim_wind_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.sim_wind_wind_speed_x, payload(offset, 2))
    offset = offset + 2

    subtree:add_le (f.sim_wind_wind_speed_y, payload(offset, 2))
    offset = offset + 2

    if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Simu Wind: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Simu Wind: Payload size different than expected") end
end

local SIM_UART_CMD_DISSECT = {
    [0x01] = sim_connect_heart_packet_dissector,
    [0x03] = sim_sdr_status_push_dissector,
    [0x06] = sim_flight_status_params_dissector,
    [0x07] = sim_wind_dissector,
}

local ESC_UART_CMD_DISSECT = {
}

-- Battery - Battery Static Data - 0x01

f.battery_static_data_unk1 = ProtoField.bytes ("dji_dumlv1.battery_static_data_unknown1", "Unknown", base.SPACE)
f.battery_static_data_design_capacity = ProtoField.uint32 ("dji_dumlv1.battery_static_data_design_capacity", "Design Capacity [mAh]", base.DEC)
f.battery_static_data_discharge_count = ProtoField.uint16 ("dji_dumlv1.battery_static_data_discharge_count", "Discharge Count", base.DEC)
f.battery_static_data_design_voltage = ProtoField.uint32 ("dji_dumlv1.battery_static_data_design_voltage", "Design Voltage [mV]", base.DEC)
f.battery_static_data_manufacture_date = ProtoField.uint16 ("dji_dumlv1.battery_static_data_manufacture_date", "Manufacture Date (packed)", base.BIN)
f.battery_static_data_serial_number = ProtoField.uint16 ("dji_dumlv1.battery_static_data_serial_number", "Serial Number", base.DEC)
f.battery_static_data_manufacturer_name = ProtoField.string ("dji_dumlv1.battery_static_data_manufacturer_name", "Manufacturer Name", base.ASCII)
f.battery_static_data_unk2 = ProtoField.bytes ("dji_dumlv1.battery_static_data_unknown2", "Unknown", base.SPACE)
f.battery_static_data_device_name = ProtoField.string ("dji_dumlv1.battery_static_data_device_name", "Device Name", base.ASCII)
f.battery_static_data_loader_version = ProtoField.string ("dji_dumlv1.battery_static_data_loader_version", "Loader Version", base.ASCII)
f.battery_static_data_app_version = ProtoField.string ("dji_dumlv1.battery_static_data_firmware_version", "App Version", base.ASCII)
f.battery_static_data_state_of_health = ProtoField.uint8 ("dji_dumlv1.battery_static_data_state_of_health", "State of Health (%)", base.DEC)

local function battery_static_data_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (payload:len() >= 40) then -- full packet
        subtree:add (f.battery_static_data_unk1, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.battery_static_data_design_capacity, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.battery_static_data_discharge_count, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.battery_static_data_design_voltage, payload(offset, 4))
        offset = offset + 4

        local manufacture_date = payload(offset, 2):le_uint()
        offset = offset + 2

        local manufacture_date_day = bit.band(manufacture_date, 0x001F)
        manufacture_date = bit.rshift(manufacture_date, 5)
        local manufacture_date_month = bit.band(manufacture_date, 0x000F)
        manufacture_date = bit.rshift(manufacture_date, 4)
        local manufacture_date_year = bit.band(manufacture_date, 0x007F) + 1980

        local manufacture_date_str = string.format("Manufacture Date: %d-%02d-%02d", manufacture_date_year, manufacture_date_month, manufacture_date_day)
        subtree:add (f.battery_static_data_manufacture_date, payload(offset-2, 2), 0, manufacture_date_str)

        subtree:add_le (f.battery_static_data_serial_number, payload(offset, 2))
        offset = offset + 2

        subtree:add (f.battery_static_data_manufacturer_name, payload(offset, 8))
        offset = offset + 8

        subtree:add (f.battery_static_data_unk2, payload(offset, 2))
        offset = offset + 2

        subtree:add (f.battery_static_data_device_name, payload(offset, 5))
        offset = offset + 5

        local loader_version = string.format("%02d.%02d.%02d.%02d", payload(offset+3,1):uint(), payload(offset+2,1):uint(), payload(offset+1,1):uint(), payload(offset,1):uint())
        subtree:add(f.battery_static_data_loader_version, loader_version)
        offset = offset + 4

        local app_version = string.format("%02d.%02d.%02d.%02d", payload(offset+3,1):uint(), payload(offset+2,1):uint(), payload(offset+1,1):uint(), payload(offset,1):uint())
        subtree:add(f.battery_static_data_app_version, app_version)
        offset = offset + 4

        subtree:add_le (f.battery_static_data_state_of_health, payload(offset, 1))
        offset = offset + 1

        if (offset ~= 40) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Battery Static Data: Offset does not match - internal inconsistency") end
    else -- status only


    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Battery Static Data: Payload size different than expected") end
end

-- Battery - Battery Dynamic Data - 0x02

f.battery_dynamic_data_index = ProtoField.uint8 ("dji_dumlv1.battery_dynamic_data_index", "Index", base.HEX, nil, nil, "Offset shifted by unknown value this.dataOffset")
  f.battery_dynamic_data_result = ProtoField.uint8 ("dji_dumlv1.battery_dynamic_data_result", "Result", base.HEX, nil, 0xff, nil)
f.battery_dynamic_data_unk1 = ProtoField.bytes ("dji_dumlv1.battery_dynamic_data_unknown1", "Unknown", base.SPACE)
f.battery_dynamic_data_voltage = ProtoField.uint32 ("dji_dumlv1.battery_dynamic_data_voltage", "Pack Voltage [mV]", base.DEC, nil, nil, "Offset shifted by unknown value this.dataOffset")
f.battery_dynamic_data_current = ProtoField.int32 ("dji_dumlv1.battery_dynamic_data_current", "Current [mA]", base.DEC, nil, nil, "Signed; Offset shifted by unknown value this.dataOffset")
f.battery_dynamic_data_full_capacity = ProtoField.uint32 ("dji_dumlv1.battery_dynamic_data_full_capacity", "Full Charge Capacity [mAh]", base.DEC, nil, nil, "Offset shifted by unknown value this.dataOffset")
f.battery_dynamic_data_remain_capacity = ProtoField.uint32 ("dji_dumlv1.battery_dynamic_data_remain_capacity", "Current Remain Capacity [mAh]", base.DEC, nil, nil, "Offset shifted by unknown value this.dataOffset")
f.battery_dynamic_data_temperature = ProtoField.uint16 ("dji_dumlv1.battery_dynamic_data_temperature", "Temperature", base.DEC, nil, nil, "Offset shifted by unknown value this.dataOffset")
f.battery_dynamic_data_cell_size = ProtoField.uint8 ("dji_dumlv1.battery_dynamic_data_cell_size", "Cell Size", base.DEC, nil, nil, "Offset shifted by unknown value this.dataOffset")
f.battery_dynamic_data_state_of_charge = ProtoField.uint8 ("dji_dumlv1.battery_dynamic_data_state_of_charge", "Relative Capacity / State of Charge [%]", base.DEC, nil, nil, "Offset shifted by unknown value this.dataOffset")
f.battery_dynamic_data_status = ProtoField.uint64 ("dji_dumlv1.battery_dynamic_data_status", "Status", base.HEX, nil, nil, "Offset shifted by unknown value this.dataOffset")
f.battery_dynamic_data_version = ProtoField.uint8 ("dji_dumlv1.battery_dynamic_data_version", "Version", base.HEX, nil, nil, "Offset shifted by unknown value this.dataOffset")
f.battery_dynamic_data_unk2 = ProtoField.bytes ("dji_dumlv1.battery_dynamic_data_unknown2", "Unknown", base.SPACE)

local function battery_dynamic_data_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (payload:len() >= 30) then -- full packet

        if (payload:len() == 32) then -- Two bytes before voltage; is this real? on which platform? this shifts all later fields.
            subtree:add (f.battery_dynamic_data_unk1, payload(offset, 2))
            offset = offset + 2
        else -- One byte before voltage; seen in the capture "Startup-FCCswitch" where payload len is 38, origin unknown
            subtree:add_le (f.battery_dynamic_data_index, payload(offset, 1))
            subtree:add_le (f.battery_dynamic_data_result, payload(offset, 1))
            offset = offset + 1
        end

        subtree:add_le (f.battery_dynamic_data_voltage, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.battery_dynamic_data_current, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.battery_dynamic_data_full_capacity, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.battery_dynamic_data_remain_capacity, payload(offset, 4))
        offset = offset + 4

        subtree:add_le (f.battery_dynamic_data_temperature, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.battery_dynamic_data_cell_size, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.battery_dynamic_data_state_of_charge, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.battery_dynamic_data_status, payload(offset, 8))
        offset = offset + 8

        if (payload:len() >= 37) then -- seen in the capture "Startup-FCCswitch"
            subtree:add (f.battery_dynamic_data_unk2, payload(offset, 9))
            offset = offset + 9
        elseif (payload:len() >= 31) then
            subtree:add (f.battery_dynamic_data_unk2, payload(offset, 2))
            offset = offset + 2
        else
            subtree:add_le (f.battery_dynamic_data_version, payload(offset, 1))
            offset = offset + 1
        end

        if (offset ~= 30) and (offset ~= 31) and (offset ~= 32) and (offset ~= 38) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Battery Dynamic Data: Offset does not match - internal inconsistency") end
    else -- status only

        if (payload:len() >= 2) then
            subtree:add (f.battery_dynamic_data_unk1, payload(offset, 2))
            offset = offset + 2
        else
            subtree:add_le (f.battery_dynamic_data_index, payload(offset, 1))
            subtree:add_le (f.battery_dynamic_data_result, payload(offset, 1))
            offset = offset + 1
        end

        if (offset ~= 2) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Battery Dynamic Data: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Battery Dynamic Data: Payload size different than expected") end
end

-- Battery - Battery Cell Voltage - 0x03

f.battery_cell_voltage_index = ProtoField.uint8 ("dji_dumlv1.battery_cell_voltage_index", "Index", base.HEX, nil, nil, "Offset shifted by unknown value this.dataOffset")
  f.battery_cell_voltage_result = ProtoField.uint8 ("dji_dumlv1.battery_cell_voltage_result", "Result", base.HEX, nil, 0xff, nil)
f.battery_cell_voltage_unk1 = ProtoField.bytes ("dji_dumlv1.battery_cell_voltage_unknown1", "Unknown", base.SPACE)
f.battery_cell_voltage_cell_count = ProtoField.uint8 ("dji_dumlv1.battery_cell_voltage_cell_count", "Number of Cells", base.DEC)
f.battery_cell_voltage_cell1_voltage = ProtoField.uint16 ("dji_dumlv1.battery_cell_voltage_cell1_voltage", "Cell 1 Voltage [mV]", base.DEC)
f.battery_cell_voltage_cell2_voltage = ProtoField.uint16 ("dji_dumlv1.battery_cell_voltage_cell2_voltage", "Cell 2 Voltage [mV]", base.DEC)
f.battery_cell_voltage_cell3_voltage = ProtoField.uint16 ("dji_dumlv1.battery_cell_voltage_cell3_voltage", "Cell 3 Voltage [mV]", base.DEC)

local function battery_cell_voltage_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (payload:len() >= 8) then -- full packet

        if (payload:len() >= 9) then
            subtree:add (f.battery_cell_voltage_unk1, payload(offset, 2))
            offset = offset + 2
        else
            subtree:add_le (f.battery_cell_voltage_index, payload(offset, 1))
            subtree:add_le (f.battery_cell_voltage_result, payload(offset, 1))
            offset = offset + 1
        end

        subtree:add_le (f.battery_cell_voltage_cell_count, payload(offset, 1))
        offset = offset + 1

        subtree:add_le (f.battery_cell_voltage_cell1_voltage, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.battery_cell_voltage_cell2_voltage, payload(offset, 2))
        offset = offset + 2

        subtree:add_le (f.battery_cell_voltage_cell3_voltage, payload(offset, 2))
        offset = offset + 2

        if (offset ~= 8) and (offset ~= 9) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Battery Cell Voltage: Offset does not match - internal inconsistency") end
    else -- status only

        subtree:add (f.battery_dynamic_data_unk1, payload(offset, 4))
        offset = offset + 4

        if (offset ~= 4) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Battery Cell Voltage: Offset does not match - internal inconsistency") end
    end

    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Battery Cell Voltage: Payload size different than expected") end
end

-- Battery - Barcode Data - 0x31

f.battery_barcode_data_unk1 = ProtoField.bytes ("dji_dumlv1.battery_barcode_data_unknown1", "Unknown", base.SPACE)
f.battery_barcode_data_length = ProtoField.uint8 ("dji_dumlv1.battery_barcode_data_length", "Data Length", base.DEC)
f.battery_barcode_data_string = ProtoField.string ("dji_dumlv1.battery_barcode_data_string", "Barcode String", base.ASCII)

local function battery_barcode_data_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (payload:len() > 9) then
        subtree:add (f.battery_barcode_data_unk1, payload(offset, 2))
        offset = offset + 2

        local data_length = payload(offset, 1):uint()
        subtree:add (f.battery_barcode_data_length, payload(offset, 1))
        offset = offset + 1

        if ((payload:len() - offset) == data_length) then
            subtree:add_le (f.battery_barcode_data_string, payload(offset, data_length))
            offset = offset + data_length
        end
    end
end

-- Battery - Battery Re-Arrangement - 0x31

--f.battery_re_arrangement_unknown0 = ProtoField.none ("dji_dumlv1.battery_re_arrangement_unknown0", "Unknown0", base.NONE)

local function battery_re_arrangement_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (offset ~= 0) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Battery Re-Arrangement: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Battery Re-Arrangement: Payload size different than expected") end
end

local BATTERY_UART_CMD_DISSECT = {
    [0x01] = battery_static_data_dissector,
    [0x02] = battery_dynamic_data_dissector,
    [0x03] = battery_cell_voltage_dissector,
    [0x04] = battery_barcode_data_dissector,
    [0x31] = battery_re_arrangement_dissector,
}

-- Data Logger - Battery Data packet - 0x22

f.datlog_battery_data_block_id = ProtoField.uint16 ("dji_dumlv1.datlog_battery_data_block_id", "Block ID", base.DEC)
f.datlog_battery_data_length = ProtoField.uint8 ("dji_dumlv1.datlog_battery_data_length", "Data Length", base.DEC)
f.datlog_battery_data_voltage = ProtoField.uint16 ("dji_dumlv1.datlog_battery_data_voltage", "Pack Voltage [mV]", base.DEC)
f.datlog_battery_data_current = ProtoField.int32 ("dji_dumlv1.datlog_battery_data_current", "Current [mA]", base.DEC)
f.datlog_battery_data_full_charge_capacity = ProtoField.uint16 ("dji_dumlv1.datlog_battery_data_full_charge_capacity", "Full Charge Capacity [mAh]", base.DEC)
f.datlog_battery_data_current_capacity = ProtoField.uint16 ("dji_dumlv1.datlog_battery_data_current_capacity", "Current Capacity [mAh]", base.DEC)
f.datlog_battery_data_temperature = ProtoField.int16 ("dji_dumlv1.datlog_battery_data_temperature", "Temperature [deg C]", base.DEC)
f.datlog_battery_data_state_of_charge = ProtoField.uint16 ("dji_dumlv1.datlog_battery_data_state_of_charge", "State of Charge [%]", base.DEC)
f.datlog_battery_data_status1 = ProtoField.uint8 ("dji_dumlv1.datlog_battery_data_status1", "Status 1", base.HEX)
f.datlog_battery_data_status2 = ProtoField.uint8 ("dji_dumlv1.datlog_battery_data_status1", "Status 2", base.HEX)
f.datlog_battery_data_status3 = ProtoField.uint8 ("dji_dumlv1.datlog_battery_data_status1", "Status 3", base.HEX)
f.datlog_battery_data_status4 = ProtoField.uint8 ("dji_dumlv1.datlog_battery_data_status1", "Status 4", base.HEX)
f.datlog_battery_data_cell1_voltage = ProtoField.uint16 ("dji_dumlv1.datlog_battery_data_cell1_voltage", "Cell 1 Voltage [mV]", base.DEC)
f.datlog_battery_data_cell2_voltage = ProtoField.uint16 ("dji_dumlv1.datlog_battery_data_cell2_voltage", "Cell 2 Voltage [mV]", base.DEC)
f.datlog_battery_data_cell3_voltage = ProtoField.uint16 ("dji_dumlv1.datlog_battery_data_cell3_voltage", "Cell 2 Voltage [mV]", base.DEC)

local function datlog_battery_data_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (payload:len() > 4) then
        subtree:add_le (f.datlog_battery_data_block_id, payload(offset, 2))
        offset = offset + 2

        local data_length = payload(offset, 1): uint()
        subtree:add (f.datlog_battery_data_length, payload(offset, 1))
        offset = offset + 1

        if(payload:len() - offset == data_length) then
            subtree:add_le (f.datlog_battery_data_voltage, payload(offset, 2))
            offset = offset + 2

            subtree:add_le (f.datlog_battery_data_current, payload(offset, 4))
            offset = offset + 4

            subtree:add_le (f.datlog_battery_data_full_charge_capacity, payload(offset, 2))
            offset = offset + 2

            subtree:add_le (f.datlog_battery_data_current_capacity, payload(offset, 2))
            offset = offset + 2

            subtree:add_le (f.datlog_battery_data_temperature, payload(offset, 2))
            offset = offset + 2

            subtree:add_le (f.datlog_battery_data_state_of_charge, payload(offset, 2))
            offset = offset + 2

            subtree:add_le (f.datlog_battery_data_status1, payload(offset, 1))
            offset = offset + 1

            subtree:add_le (f.datlog_battery_data_status2, payload(offset, 1))
            offset = offset + 1

            subtree:add_le (f.datlog_battery_data_status3, payload(offset, 1))
            offset = offset + 1

            subtree:add_le (f.datlog_battery_data_status4, payload(offset, 1))
            offset = offset + 1

            subtree:add_le (f.datlog_battery_data_cell1_voltage, payload(offset, 2))
            offset = offset + 2

            subtree:add_le (f.datlog_battery_data_cell2_voltage, payload(offset, 2))
            offset = offset + 2

            subtree:add_le (f.datlog_battery_data_cell2_voltage, payload(offset, 2))
            offset = offset + 2
        end
    end
end

-- Data Logger - Battery Message packet - 0x23

f.datlog_battery_msg_message = ProtoField.string ("dji_dumlv1.datlog_battery_msg_message", "Message", base.ASCII)

local function datlog_battery_msg_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    if (payload:len() > 2) then
        local message_len = payload:len() - offset
        subtree:add_le (f.datlog_battery_msg_message, payload(offset, message_len))
    end
end

local DATA_LOG_UART_CMD_DISSECT = {
    [0x22] = datlog_battery_data_dissector,
    [0x23] = datlog_battery_msg_dissector,
}

-- RTK - Rtk Status - 0x09

f.rtk_rtk_status_a = ProtoField.uint8 ("dji_dumlv1.rtk_rtk_status_a", "A", base.HEX)
f.rtk_rtk_status_b = ProtoField.uint8 ("dji_dumlv1.rtk_rtk_status_b", "B", base.HEX)
f.rtk_rtk_status_c = ProtoField.uint8 ("dji_dumlv1.rtk_rtk_status_c", "C", base.HEX)
f.rtk_rtk_status_d = ProtoField.uint8 ("dji_dumlv1.rtk_rtk_status_d", "D", base.HEX)
f.rtk_rtk_status_e = ProtoField.uint8 ("dji_dumlv1.rtk_rtk_status_e", "E", base.HEX)
f.rtk_rtk_status_f = ProtoField.uint8 ("dji_dumlv1.rtk_rtk_status_f", "F", base.HEX)
f.rtk_rtk_status_g = ProtoField.uint8 ("dji_dumlv1.rtk_rtk_status_g", "G", base.HEX)
f.rtk_rtk_status_h = ProtoField.uint8 ("dji_dumlv1.rtk_rtk_status_h", "H", base.HEX)
f.rtk_rtk_status_i = ProtoField.uint8 ("dji_dumlv1.rtk_rtk_status_i", "I", base.HEX)
f.rtk_rtk_status_j = ProtoField.uint8 ("dji_dumlv1.rtk_rtk_status_j", "J", base.HEX)
f.rtk_rtk_status_k = ProtoField.uint8 ("dji_dumlv1.rtk_rtk_status_k", "K", base.HEX)
f.rtk_rtk_status_l = ProtoField.double ("dji_dumlv1.rtk_rtk_status_l", "L", base.DEC)
f.rtk_rtk_status_m = ProtoField.double ("dji_dumlv1.rtk_rtk_status_m", "M", base.DEC)
f.rtk_rtk_status_n = ProtoField.float ("dji_dumlv1.rtk_rtk_status_n", "N", base.DEC)
f.rtk_rtk_status_o = ProtoField.double ("dji_dumlv1.rtk_rtk_status_o", "O", base.DEC)
f.rtk_rtk_status_p = ProtoField.double ("dji_dumlv1.rtk_rtk_status_p", "P", base.DEC)
f.rtk_rtk_status_q = ProtoField.float ("dji_dumlv1.rtk_rtk_status_q", "Q", base.DEC)
f.rtk_rtk_status_r = ProtoField.float ("dji_dumlv1.rtk_rtk_status_r", "R", base.DEC)
f.rtk_rtk_status_s = ProtoField.uint8 ("dji_dumlv1.rtk_rtk_status_s", "S", base.HEX)
f.rtk_rtk_status_t = ProtoField.uint8 ("dji_dumlv1.rtk_rtk_status_t", "T", base.HEX)

local function rtk_rtk_status_dissector(pkt_length, buffer, pinfo, subtree)
    local offset = 11
    local payload = buffer(offset, pkt_length - offset - 2)
    offset = 0

    subtree:add_le (f.rtk_rtk_status_a, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtk_rtk_status_b, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtk_rtk_status_c, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtk_rtk_status_d, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtk_rtk_status_e, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtk_rtk_status_f, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtk_rtk_status_g, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtk_rtk_status_h, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtk_rtk_status_i, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtk_rtk_status_j, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtk_rtk_status_k, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtk_rtk_status_l, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.rtk_rtk_status_m, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.rtk_rtk_status_n, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtk_rtk_status_o, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.rtk_rtk_status_p, payload(offset, 8))
    offset = offset + 8

    subtree:add_le (f.rtk_rtk_status_q, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtk_rtk_status_r, payload(offset, 4))
    offset = offset + 4

    subtree:add_le (f.rtk_rtk_status_s, payload(offset, 1))
    offset = offset + 1

    subtree:add_le (f.rtk_rtk_status_t, payload(offset, 1))
    offset = offset + 1

    if (offset ~= 57) then subtree:add_expert_info(PI_MALFORMED,PI_ERROR,"Rtk Status: Offset does not match - internal inconsistency") end
    if (payload:len() ~= offset) then subtree:add_expert_info(PI_PROTOCOL,PI_WARN,"Rtk Status: Payload size different than expected") end
end

local RTK_UART_CMD_DISSECT = {
    [0x09] = rtk_rtk_status_dissector,
}

local AUTO_UART_CMD_DISSECT = {
}

DJI_DUMLv1_CMD_DISSECT = {
    [0x00] = GENERAL_UART_CMD_DISSECT,
    [0x01] = SPECIAL_UART_CMD_DISSECT,
    [0x02] = CAMERA_UART_CMD_DISSECT,
    [0x03] = FLYC_UART_CMD_DISSECT,
    [0x04] = GIMBAL_UART_CMD_DISSECT,
    [0x05] = CENTER_BRD_UART_CMD_DISSECT,
    [0x06] = RC_UART_CMD_DISSECT,
    [0x07] = WIFI_UART_CMD_DISSECT,
    [0x08] = DM36X_UART_CMD_DISSECT,
    [0x09] = HD_LINK_UART_CMD_DISSECT,
    [0x0a] = MBINO_UART_CMD_DISSECT,
    [0x0b] = SIM_UART_CMD_DISSECT,
    [0x0c] = ESC_UART_CMD_DISSECT,
    [0x0d] = BATTERY_UART_CMD_DISSECT,
    [0x0e] = DATA_LOG_UART_CMD_DISSECT,
    [0x0f] = RTK_UART_CMD_DISSECT,
    [0x10] = AUTO_UART_CMD_DISSECT,
}

-- Top level packet fields

-- [0]  Start of Pkt, always 0x55
f.delimiter = ProtoField.uint8 ("dji_dumlv1.delimiter", "Delimiter", base.HEX)
-- [1]  Length of Pkt 
f.length = ProtoField.uint16 ("dji_dumlv1.length", "Length", base.HEX, nil, 0x3FF)
-- [2]  Protocol version
f.protocol_version = ProtoField.uint16 ("dji_dumlv1.protover", "Protocol Version", base.HEX, nil, 0xFC00)
-- [3]  Data Type
f.datatype = ProtoField.uint8 ("dji_dumlv1.hdr_crc", "Header CRC", base.HEX)

-- Fields for ProtoVer = 1 (DUML v1)

-- [4]  Sender
f.sender_idx = ProtoField.uint8 ("dji_dumlv1.sender_idx", "Sender Index", base.DEC, nil, 0xE0)
f.sender = ProtoField.uint8 ("dji_dumlv1.sender", "Sender Type", base.DEC, DJI_DUMLv1_SRC_DEST_TEXT, 0x1F)
-- [5]  Receiver
f.receiver_idx = ProtoField.uint8 ("dji_dumlv1.receiver_idx", "Receiver Index", base.DEC, nil, 0xE0)
f.receiver = ProtoField.uint8 ("dji_dumlv1.receiver", "Receiver Type", base.DEC, DJI_DUMLv1_SRC_DEST_TEXT, 0x1F)
-- [6-7]  Sequence Ctr
f.seqctr = ProtoField.uint16 ("dji_dumlv1.seqctr", "Seq Counter", base.DEC, nil, nil, "Used for re-transmission - if known seqctr is detected, cached answer may be re-transmitted")
-- [8] Encryption
f.encrypt = ProtoField.uint8 ("dji_dumlv1.encrypt", "Encryption Type", base.DEC, DJI_DUMLv1_ENCRYPT_TYPE_TEXT, 0x07)
-- [8] Ack
f.ack = ProtoField.uint8 ("dji_dumlv1.ack", "Ack", base.HEX, DJI_DUMLv1_ACK_TYPE_TEXT, 0x60)
-- [8] Packet type
f.pack_type = ProtoField.uint8 ('dji_dumlv1.pack_type', "Packet Type", base.DEC, DJI_DUMLv1_PACKET_TYPE_TEXT, 0x80)
-- [9] Cmd Set
f.cmdset = ProtoField.uint8 ('dji_dumlv1.cmdset', "Cmd Set", base.DEC, DJI_DUMLv1_CMD_SET_TEXT, 0xFF)
-- [A] Cmd
f.cmd = ProtoField.uint8 ('dji_dumlv1.cmd', "Cmd", base.HEX)
-- [B] Payload (optional)
f.payload = ProtoField.bytes ("dji_dumlv1.payload", "Payload", base.SPACE)

-- [B+Payload] CRC
f.crc = ProtoField.uint16 ("dji_dumlv1.crc", "CRC", base.HEX)

-- Dissector top level function; is called within this dissector, but can also be called from outsude
function dji_dumlv1_main_dissector(buffer, pinfo, subtree)
    local offset = 1

    -- [1-2] The Pkt length | protocol version
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

    if pkt_protover == 1 then

        -- [4] Sender
        subtree:add (f.sender, buffer(offset, 1))
        subtree:add (f.sender_idx, buffer(offset, 1))
        offset = offset + 1

        -- [5] Receiver
        subtree:add (f.receiver, buffer(offset, 1))
        subtree:add (f.receiver_idx, buffer(offset, 1))
        offset = offset + 1

        -- [6] Sequence Counter
        subtree:add_le (f.seqctr, buffer(offset, 2))
        offset = offset + 2

        -- [8] Encrypt | Ack | Pack_Type
        subtree:add (f.encrypt, buffer(offset, 1))
        subtree:add (f.ack, buffer(offset, 1))
        subtree:add (f.pack_type, buffer(offset, 1))
        offset = offset + 1

        -- [9] Cmd Set
        local cmdset = buffer(offset,1):uint()
        subtree:add (f.cmdset, buffer(offset, 1))
        offset = offset + 1

        -- [A] Cmd (has variable valuestring)
        local cmd = buffer(offset,1):uint()
        local valuestring = DJI_DUMLv1_CMD_TEXT[cmdset] or {}
        subtree:add (f.cmd, buffer(offset, 1), cmd, string.format("%s: %s (0x%02X)", "Cmd", valuestring[cmd] or "Unknown", cmd))
        offset = offset + 1

        set_info(cmd, pinfo, DJI_DUMLv1_CMD_TEXT[cmdset])

        assert(offset == 11, "Offset shifted - dissector internal inconsistency")

        -- [B] Payload    
        if pkt_length > offset+2 then
            payload_tree = subtree:add(f.payload, buffer(offset, pkt_length - offset - 2))

            -- If we have a dissector for this kind of command, run it
            local dissector_group = DJI_DUMLv1_CMD_DISSECT[cmdset] or {}
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

-- The protocol dissector itself
function DJI_DUMLv1_PROTO.dissector (buffer, pinfo, tree)

    local subtree = tree:add (DJI_DUMLv1_PROTO, buffer())

    -- The Pkt start byte
    local offset = 0

    local pkt_type = buffer(offset,1):uint()
    subtree:add (f.delimiter, buffer(offset, 1))
    offset = offset + 1

    if pkt_type == 0x55 then
        dji_dumlv1_main_dissector(buffer, pinfo, subtree)
    end

end

-- Heuritstic version, checks if packet is correct
local function heuristic_dissector(buffer, pinfo, tree)

    -- The Pkt start byte
    local num_packets = 0
    local offset = 0

    local i = 0
    while (buffer:len() > offset) do

        if (buffer:len() < 0xa) then break end

        local pkt_type = buffer(offset,1):uint()
        if (pkt_type ~= 0x55) then break end

        -- [1-2] The Pkt length | protocol version
        local pkt_length = buffer(offset+1,2):le_uint()
        local pkt_protover = pkt_length
        -- bit32 lib requires LUA 5.2
        pkt_length = bit32.band(pkt_length, 0x03FF)
        pkt_protover = bit32.rshift(bit32.band(pkt_protover, 0xFC00), 10)

        if (pkt_length > buffer:len()) then break end
        if (pkt_protover > 2) then break end

        num_packets = num_packets + 1
        local subtree = tree:add (DJI_DUMLv1_PROTO, buffer())
        subtree:add (f.delimiter, buffer(offset, 1))

        dji_dumlv1_main_dissector(buffer(offset,pkt_length), pinfo, subtree)
        offset = offset + pkt_length

    end

    return (num_packets > 0)
end


-- A initialization routine
function DJI_DUMLv1_PROTO.init ()
    -- Non-heuristic USB dissector registration would look like this
    --DissectorTable.get("usb.bulk"):add(0xffff, DJI_DUMLv1_PROTO)
end

DJI_DUMLv1_PROTO:register_heuristic("usb.bulk", heuristic_dissector)
DJI_DUMLv1_PROTO:register_heuristic("tcp", heuristic_dissector)
