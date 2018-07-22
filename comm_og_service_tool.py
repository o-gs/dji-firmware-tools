#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" OGs Service Tool for Dji products.

 The script allows to trigger a few service functions of Dji drones.
"""

# Copyright (C) 2018 Mefistotelis <mefistotelis@gmail.com>
# Copyright (C) 2018 Original Gangsters <https://dji-rev.slack.com/>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

__version__ = "0.0.1"
__author__ = "Mefistotelis @ Original Gangsters"
__license__ = "GPL"

import os
import sys
import time
import enum
import types
import struct
import serial
import select
import binascii
import argparse
from ctypes import *

sys.path.insert(0, './')
from comm_serialtalk import (
  do_send_request, do_receive_reply,
)
from comm_mkdupc import *

def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

class PRODUCT_CODE(DecoratedEnum):
    P3X = 0
    P3S = 1
    P3C = 2
    WM100 = 3
    WM220 = 4

ALT_PRODUCT_CODE = {
    'PH3PRO': 'P3X',
    'PH3ADV': 'P3S',
    'PH3STD': 'P3C',
    'SPARK': 'WM100',
    'MAVIC': 'WM220',
}

class SERVICE_CMD(DecoratedEnum):
    FlycParam = 0
    GimbalCalib = 1

class FLYC_PARAM_CMD(DecoratedEnum):
    LIST = 0
    GET = 1
    SET = 2

def detect_serial_port(po):
    """ Detects the serial port device name of a Dji product.
    """
    import serial.tools.list_ports
    #TODO: detection unfinished
    for comport in serial.tools.list_ports.comports():
        print(comport.device)
    return ''

def open_serial_port(po):
    # Open serial port
    if po.port == 'auto':
        port_name = detect_serial_port(po)
    else:
        port_name = po.port
    if not po.dry_test:
        ser = serial.Serial(port_name, baudrate=po.baudrate, timeout=0)
    else:
        ser = open(os.devnull,"rb+")
        ser.port = port_name
        ser.baudrate=po.baudrate
        ser.reset_input_buffer = types.MethodType(lambda x: None, ser)
        ser.in_waiting = 0
    if (po.verbose > 0):
        print("Opened {} at {}".format(ser.port, ser.baudrate))
    return ser

def get_unique_sequence_number(po):
    """ Returns a sequence number for packet.
    """
    # This will be unique as long as we do 10ms delay between packets
    return int(time.time()*100) & 0xffff

def send_request_and_receive_reply(po, ser, receiver_type, receiver_index, ack_type, cmd_set, cmd_id, payload):
    global last_seq_num
    if not 'last_seq_num' in globals():
        last_seq_num = get_unique_sequence_number(po)

    pktprop = PacketProperties()
    pktprop.sender_type = COMM_DEV_TYPE.PC
    pktprop.sender_index = 0
    pktprop.receiver_type = receiver_type
    pktprop.receiver_index = receiver_index
    pktprop.seq_num = last_seq_num
    pktprop.pack_type = PACKET_TYPE.REQUEST
    pktprop.ack_type = ack_type
    pktprop.encrypt_type = ENCRYPT_TYPE.NO_ENC
    pktprop.cmd_set = cmd_set
    pktprop.cmd_id = cmd_id
    if hasattr(payload, '__len__'):
        pktprop.payload = (c_ubyte * len(payload)).from_buffer_copy(payload)
    else:
        pktprop.payload = (c_ubyte * sizeof(payload)).from_buffer_copy(payload)

    for nretry in range(0, 3):
        pktreq = do_send_request(po, ser, pktprop)

        pktrpl = do_receive_reply(po, ser, pktreq)

        if pktrpl is not None:
            break

    last_seq_num += 1

    if (po.verbose > 1):
        if pktrpl is not None:
            print("Received response packet:")
        else:
            print("No response received.")

    if (po.verbose > 0):
        if pktrpl is not None:
            print(' '.join('{:02x}'.format(x) for x in pktrpl))

    return pktrpl

def send_assistant_unlock(po, ser, val):
    if (po.verbose > 0):
        print("Sending Assistant Unlock command")
    pktrpl = send_request_and_receive_reply(po, ser,
      COMM_DEV_TYPE.FLYCONTROLLER, 0,
      ACK_TYPE.ACK_AFTER_EXEC,
      CMD_SET_TYPE.FLYCONTROLLER, 0xdf,
      struct.pack("<I", val))
    if pktrpl is None:
        return False
    #TODO we might want to check status in the reply
    return True

def flyc_param_request_get_param_info_by_index(po, ser, param_idx):
    payload = DJIPayload_FlyController_GetParamInfoByIndex2015Rq()
    payload.param_index = param_idx

    if (po.verbose > 2):
        print("Prepared request - {:s}:".format(type(payload).__name__))
        print(payload)

    pktrpl = send_request_and_receive_reply(po, ser,
      COMM_DEV_TYPE.FLYCONTROLLER, 0,
      ACK_TYPE.ACK_AFTER_EXEC,
      CMD_SET_TYPE.FLYCONTROLLER, 0xf0,
      payload)

    if po.dry_test:
        # use to test the code without a drone
        pktrpl = bytes.fromhex("55 2e 04 a7 03 0a 77 45 80 03 f0 00 0a 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 67 6c 6f 62 61 6c 2e 73 74 61 74 75 73 00 79 ac")

    if pktrpl is None:
        raise ConnectionError("No response on parameter {:d} info by index request.".format(param_idx))

    rplhdr = DJICmdV1Header.from_buffer_copy(pktrpl)
    paraminfo = get_known_payload(rplhdr, pktrpl[sizeof(DJICmdV1Header):-2])

    if (paraminfo is None):
        raise ConnectionError("Unrecognized response to parameter {:d} info by index request.".format(param_idx))

    if (po.verbose > 2):
        print("Parsed response  - {:s}:".format(type(paraminfo).__name__))
        print(paraminfo)

    return paraminfo

def flyc_param_request_get_param_info_by_hash(po, ser, param_name):
    payload = DJIPayload_FlyController_GetParamInfoByHash2015Rq()
    payload.param_hash = flyc_parameter_compute_hash(po,param_name)

    if (po.verbose > 2):
        print("Prepared request - {:s}:".format(type(payload).__name__))
        print(payload)

    pktrpl = send_request_and_receive_reply(po, ser,
      COMM_DEV_TYPE.FLYCONTROLLER, 0,
      ACK_TYPE.ACK_AFTER_EXEC,
      CMD_SET_TYPE.FLYCONTROLLER, 0xf7,
      payload)

    if po.dry_test:
        # use to test the code without a drone
        pktrpl = bytes.fromhex("55 43 04 74 03 0a ff 7c 80 03 f7 00 01 00 02 00 0b 00 14 00 00 00 f4 01 00 00 78 00 00 00 67 5f 63 6f 6e 66 69 67 2e 66 6c 79 69 6e 67 5f 6c 69 6d 69 74 2e 6d 61 78 5f 68 65 69 67 68 74 5f 30 00 5d 71")

    if pktrpl is None:
        raise ConnectionError("No response on parameter info by hash request.")

    rplhdr = DJICmdV1Header.from_buffer_copy(pktrpl)
    paraminfo = get_known_payload(rplhdr, pktrpl[sizeof(DJICmdV1Header):-2])

    if (paraminfo is None):
        raise LookupError("Unrecognized response to parameter info by hash request.")

    if (po.verbose > 2):
        print("Parsed response  - {:s}:".format(type(paraminfo).__name__))
        print(paraminfo)

    return paraminfo

def flyc_param_request_read_param_value_by_hash(po, ser, param_name):
    payload = DJIPayload_FlyController_ReadParamValByHash2015Rq()
    payload.param_hash = flyc_parameter_compute_hash(po,param_name)

    if (po.verbose > 2):
        print("Prepared request - {:s}:".format(type(payload).__name__))
        print(payload)

    pktrpl = send_request_and_receive_reply(po, ser,
      COMM_DEV_TYPE.FLYCONTROLLER, 0,
      ACK_TYPE.ACK_AFTER_EXEC,
      CMD_SET_TYPE.FLYCONTROLLER, 0xf8,
      payload)

    if po.dry_test:
        # use to test the code without a drone
        pktrpl = bytes.fromhex("55 14 04 6d 03 0a 00 7d 80 03 f8 00 8a 23 71 03 f4 01 57 ee")

    if pktrpl is None:
        raise ConnectionError("No response on read parameter value by hash request.")

    rplhdr = DJICmdV1Header.from_buffer_copy(pktrpl)
    rplpayload = get_known_payload(rplhdr, pktrpl[sizeof(DJICmdV1Header):-2])

    if (rplpayload is None):
        raise LookupError("Unrecognized response to read parameter value by hash request.")

    if sizeof(rplpayload) <= 4:
        raise ValueError("Response indicates parameter does not exist or has no retrievable value.")

    if (po.verbose > 2):
        print("Parsed response  - {:s}:".format(type(rplpayload).__name__))
        print(rplpayload)

    return rplpayload

def flyc_param_request_write_param_value_by_hash(po, ser, param_name, param_val):
    if len(param_val) > 16:
        payload = DJIPayload_FlyController_WriteParamValAnyByHash2015Rq()
    elif len(param_val) > 8:
        payload = DJIPayload_FlyController_WriteParamVal16ByHash2015Rq()
    elif len(param_val) > 4:
        payload = DJIPayload_FlyController_WriteParamVal8ByHash2015Rq()
    elif len(param_val) > 2:
        payload = DJIPayload_FlyController_WriteParamVal4ByHash2015Rq()
    elif len(param_val) > 1:
        payload = DJIPayload_FlyController_WriteParamVal2ByHash2015Rq()
    else:
        payload = DJIPayload_FlyController_WriteParamVal1ByHash2015Rq()
    payload.param_hash = flyc_parameter_compute_hash(po,param_name)
    payload.param_value = param_val

    if (po.verbose > 2):
        print("Prepared request - {:s}:".format(type(payload).__name__))
        print(payload)

    pktrpl = send_request_and_receive_reply(po, ser,
      COMM_DEV_TYPE.FLYCONTROLLER, 0,
      ACK_TYPE.ACK_AFTER_EXEC,
      CMD_SET_TYPE.FLYCONTROLLER, 0xf9,
      payload)

    if po.dry_test:
        # use to test the code without a drone
        pktrpl = bytes.fromhex("55 14 04 6d 03 0a 37 c6 80 03 f9 00 8a 23 71 03 f3 01 dd dd")

    if pktrpl is None:
        raise ConnectionError("No response on write parameter value by hash request.")

    rplhdr = DJICmdV1Header.from_buffer_copy(pktrpl)
    rplpayload = get_known_payload(rplhdr, pktrpl[sizeof(DJICmdV1Header):-2])

    if (rplpayload is None):
        raise LookupError("Unrecognized response to write parameter value by hash request.")

    if sizeof(rplpayload) <= 4:
        raise ValueError("Response indicates parameter does not exist or is not writeable.")

    if (po.verbose > 2):
        print("Parsed response  - {:s}:".format(type(rplpayload).__name__))
        print(rplpayload)

    return rplpayload

def flyc_param_info_limits_to_str(po, paraminfo):
    if isinstance(paraminfo, DJIPayload_FlyController_GetParamInfoU2015Re):
        limit_min = '{:d}'.format(paraminfo.limit_min)
        limit_max = '{:d}'.format(paraminfo.limit_max)
        limit_def = '{:d}'.format(paraminfo.limit_def)
    elif isinstance(paraminfo, DJIPayload_FlyController_GetParamInfoI2015Re):
        limit_min = '{:d}'.format(paraminfo.limit_min)
        limit_max = '{:d}'.format(paraminfo.limit_max)
        limit_def = '{:d}'.format(paraminfo.limit_def)
    elif isinstance(paraminfo, DJIPayload_FlyController_GetParamInfoF2015Re):
        limit_min = '{:f}'.format(paraminfo.limit_min)
        limit_max = '{:f}'.format(paraminfo.limit_max)
        limit_def = '{:f}'.format(paraminfo.limit_def)
    else:
        limit_min = "n/a"
        limit_max = "n/a"
        limit_def = "n/a"
    return (limit_min, limit_max, limit_def)

def flyc_param_value_to_str(po, paraminfo, param_value):
    if (paraminfo.type_id == DJIPayload_FlyController_ParamType.ubyte.value):
        value_str = "{:d}".format(struct.unpack("<B", param_value)[0])
    elif (paraminfo.type_id == DJIPayload_FlyController_ParamType.ushort.value):
        value_str = "{:d}".format(struct.unpack("<H", param_value)[0])
    elif (paraminfo.type_id == DJIPayload_FlyController_ParamType.ulong.value):
        value_str = "{:d}".format(struct.unpack("<L", param_value)[0])
    elif (paraminfo.type_id == DJIPayload_FlyController_ParamType.ulonglong.value):
        value_str = "{:d}".format(struct.unpack("<Q", param_value)[0])
    elif (paraminfo.type_id == DJIPayload_FlyController_ParamType.byte.value):
        value_str = "{:d}".format(struct.unpack("<b", param_value)[0])
    elif (paraminfo.type_id == DJIPayload_FlyController_ParamType.short.value):
        value_str = "{:d}".format(struct.unpack("<h", param_value)[0])
    elif (paraminfo.type_id == DJIPayload_FlyController_ParamType.long.value):
        value_str = "{:d}".format(struct.unpack("<l", param_value)[0])
    elif (paraminfo.type_id == DJIPayload_FlyController_ParamType.longlong.value):
        value_str = "{:d}".format(struct.unpack("<q", param_value)[0])
    elif (paraminfo.type_id == DJIPayload_FlyController_ParamType.float.value):
        value_str = "{:f}".format(struct.unpack("<f", param_value)[0])
    elif (paraminfo.type_id == DJIPayload_FlyController_ParamType.double.value):
        value_str = "{:f}".format(struct.unpack("<d", param_value)[0])
    else: # array or future type
        value_str = ' '.join('{:02x}'.format(x) for x in param_value)
    return value_str

def flyc_param_str_to_value(po, paraminfo, value_str):
    if (paraminfo.type_id == DJIPayload_FlyController_ParamType.ubyte.value):
        param_val = struct.pack("<B", int(value_str,0))
    elif (paraminfo.type_id == DJIPayload_FlyController_ParamType.ushort.value):
        param_val = struct.pack("<H", int(value_str,0))
    elif (paraminfo.type_id == DJIPayload_FlyController_ParamType.ulong.value):
        param_val = struct.pack("<L", int(value_str,0))
    elif (paraminfo.type_id == DJIPayload_FlyController_ParamType.ulonglong.value):
        param_val = struct.pack("<Q", int(value_str,0))
    elif (paraminfo.type_id == DJIPayload_FlyController_ParamType.byte.value):
        param_val = struct.pack("<b", int(value_str,0))
    elif (paraminfo.type_id == DJIPayload_FlyController_ParamType.short.value):
        param_val = struct.pack("<h", int(value_str,0))
    elif (paraminfo.type_id == DJIPayload_FlyController_ParamType.long.value):
        param_val = struct.pack("<l", int(value_str,0))
    elif (paraminfo.type_id == DJIPayload_FlyController_ParamType.longlong.value):
        param_val = struct.pack("<q", int(value_str,0))
    elif (paraminfo.type_id == DJIPayload_FlyController_ParamType.float.value):
        param_val = struct.pack("<f", float(value_str))
    elif (paraminfo.type_id == DJIPayload_FlyController_ParamType.double.value):
        param_val = struct.pack("<d", float(value_str))
    else: # array or future type
        param_val = bytes.fromhex(value_str)
    return param_val

def flyc_param_request_print_response(po, idx, paraminfo, rplpayload):
    if paraminfo is None:
        # Print headers
        if rplpayload is None:
            param_val = ""
        else:
            param_val = "value"
        if idx is None:
            ident_str = "hash"
        else:
            ident_str = "idx"
        if po.fmt == '2line':
            print("{:10s} {:60s}".format(ident_str, "name"))
            print("{:6s} {:4s} {:6s} {:7s} {:7s} {:7s} {:7s}".format(
              "typeId", "size", "attr", "min", "max", "deflt", param_val))
        elif po.fmt == 'tab':
            print("{:s}\t{:s}\t{:s}\t{:s}\t{:s}\t{:s}\t{:s}\t{:s}\t{:s}".format(
              ident_str, "name", "typeId", "size", "attr", "min", "max", "deflt", param_val))
        elif po.fmt == 'csv':
            print("{:s};{:s};{:s};{:s};{:s};{:s};{:s};{:s};{:s}".format(
              ident_str, "name", "typeId", "size", "attr", "min", "max", "deflt", param_val))
        elif po.fmt == '1line':
            print("{:10s} {:60s} {:6s} {:4s} {:6s} {:7s} {:7s} {:7s} {:7s}".format(
              ident_str, "name", "typeId", "size", "attr", "min", "max", "deflt", param_val))
        else: # po.fmt == 'simple':
            pass
    else:
        # Print actual data
        if rplpayload is None:
            param_val = ""
        else:
            param_val = flyc_param_value_to_str(po, paraminfo, rplpayload.param_value)
        if idx is None:
            if rplpayload is not None:
                ident_str = "0x{:08x}".format(rplpayload.param_hash)
            else:
                ident_str = "n/a"
        else:
            ident_str = "{:d}".format(idx)
        # Convert limits to string before, so we can handle all types in the same way
        (limit_min, limit_max, limit_def) = flyc_param_info_limits_to_str(po, paraminfo)

        if po.fmt == '2line':
            print("{:10s} {:60s}".format(ident_str, paraminfo.name.decode("utf-8")))
            print("{:6d} {:4d} 0x{:04x} {:7s} {:7s} {:7s} {:7s}".format(
              paraminfo.type_id, paraminfo.size, paraminfo.attribute,
              limit_min, limit_max, limit_def, param_val))
        elif po.fmt == 'tab':
            print("{:s}\t{:s}\t{:d}\t{:d}\t0x{:04x}\t{:s}\t{:s}\t{:s}\t{:s}".format(
              ident_str, paraminfo.name.decode("utf-8"),
              paraminfo.type_id, paraminfo.size, paraminfo.attribute,
              limit_min, limit_max, limit_def, param_val))
        elif po.fmt == 'csv':
            print("{:s};{:s};{:d};{:d};0x{:04x};{:s};{:s};{:s};{:s}".format(
              ident_str, paraminfo.name.decode("utf-8"),
              paraminfo.type_id, paraminfo.size, paraminfo.attribute,
              limit_min, limit_max, limit_def, param_val))
        #elif po.fmt == 'json': #TODO maybe output format similar to flyc_param_infos?
        elif po.fmt == '1line':
            print("{:10s} {:60s} {:6d} {:4d} 0x{:04x} {:7s} {:7s} {:7s} {:7s}".format(
              ident_str, paraminfo.name.decode("utf-8"),
              paraminfo.type_id, paraminfo.size, paraminfo.attribute,
              limit_min, limit_max, limit_def, param_val))
        else: # po.fmt == 'simple':
            if rplpayload is None:
                print("{:s} default = {:s} range = < {:s} .. {:s} >".format(paraminfo.name.decode("utf-8"), limit_def, limit_min, limit_max))
            else:
                print("{:s} = {:s} range = < {:s} .. {:s} >".format(paraminfo.name.decode("utf-8"), param_val, limit_min, limit_max))

def do_flyc_param_request_list(po, ser):

    if ((po.product == PRODUCT_CODE.P3X) or
      (po.product == PRODUCT_CODE.P3S) or
      (po.product == PRODUCT_CODE.P3C)):
        unlock_status = True # No Assistant Unlock needed on pre-2017 platforms
    else:
        unlock_status = send_assistant_unlock(po, ser, 1)
    if not unlock_status:
        eprint("Assistant Unlock command failed; further commands may not work because of this.")
    # Print result data header
    flyc_param_request_print_response(po, True, None, None)

    for idx in range(po.start, po.start+po.count):
        rplpayload = flyc_param_request_get_param_info_by_index(po, ser, idx)

        if sizeof(rplpayload) <= 4:
            if (po.verbose > 0):
                print("Response on parameter {:d} indicates end of list.".format(idx))
            break
        # Print the result data
        flyc_param_request_print_response(po, idx, rplpayload, None)

def do_flyc_param_request_get(po, ser):
    # Get param info first, so we know type and size
    paraminfo = flyc_param_request_get_param_info_by_hash(po, ser, po.param_name)
    # Now get the parameter value
    rplpayload = flyc_param_request_read_param_value_by_hash(po, ser, po.param_name)
    # Print the result data
    flyc_param_request_print_response(po, None, None, True)
    flyc_param_request_print_response(po, None, paraminfo, rplpayload)

def do_flyc_param_request_set(po, ser):
    # Get param info first, so we know type and size
    paraminfo = flyc_param_request_get_param_info_by_hash(po, ser, po.param_name)
    # Now set the parameter value
    param_val = flyc_param_str_to_value(po, paraminfo, po.param_value)
    rplpayload = flyc_param_request_write_param_value_by_hash(po, ser, po.param_name, param_val)
    # Print the result data
    flyc_param_request_print_response(po, None, None, True)
    flyc_param_request_print_response(po, None, paraminfo, rplpayload)

def do_flyc_param_request(po):
    ser = open_serial_port(po)

    if po.subcmd == FLYC_PARAM_CMD.LIST:
        do_flyc_param_request_list(po, ser)
    elif po.subcmd == FLYC_PARAM_CMD.GET:
        do_flyc_param_request_get(po, ser)
    elif po.subcmd == FLYC_PARAM_CMD.SET:
        do_flyc_param_request_set(po, ser)
    else:
        raise ValueError("Unrecognized {:s} command: {:s}.".format(po.svcmd.name, po.subcmd.name))

    ser.close()

def do_gimbal_calib_request(po):
    ser = open_serial_port(po)

    eprint("Unimplemented command: {:s}.".format(po.svcmd.name))

    ser.close()


def parse_product_code(s):
    """ Parses product code string in known formats.
    """
    s = s.upper()
    if s in ALT_PRODUCT_CODE:
        s = ALT_PRODUCT_CODE[s]
    return s

def main():
    """ Main executable function.

      Its task is to parse command line options and call a function which performs serial communication.
    """
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument('port', type=str,
            help="the serial port to write to and read from")

    parser.add_argument('product', choices=[i.name for i in PRODUCT_CODE], type=parse_product_code,
            help="target product code name")

    parser.add_argument('-b', '--baudrate', default=9600, type=int,
            help="the baudrate to use for the serial port (default is %(default)s)")

    parser.add_argument('-w', '--timeout', default=500, type=int,
            help="how long to wait for answer, in miliseconds (default is %(default)s)")

    parser.add_argument('--dry-test', action='store_true',
            help='Internal testing mode; do not use real serial interface and use template answers from the drone.')

    parser.add_argument('-v', '--verbose', action='count', default=0,
            help="increases verbosity level; max level is set by -vvv")

    parser.add_argument('--version', action='version', version="%(prog)s {version} by {author}"
              .format(version=__version__,author=__author__),
            help="display version information and exit")

    subparsers = parser.add_subparsers(dest='svcmd',
            help="service command")

    subpar_flycpar = subparsers.add_parser('FlycParam',
            help="Flight Controller Parameters handling")

    subpar_gimbcal = subparsers.add_parser('GimbalCalib',
            help="Gimbal Calibration options")

    subpar_flycpar_subcmd = subpar_flycpar.add_subparsers(dest='subcmd',
            help="Flyc Param Command")

    subpar_flycpar_list = subpar_flycpar_subcmd.add_parser('list',
            help="list FlyC Parameters")
    subpar_flycpar_list.add_argument('-s', '--start', default=0, type=int,
            help="starting index")
    subpar_flycpar_list.add_argument('-c', '--count', default=100, type=int,
            help="amount of entries to show")
    subpar_flycpar_list.add_argument('-f', '--fmt', default='simple', type=str,
            choices=['simple', '1line', '2line', 'tab', 'csv'],
            help="output format")

    subpar_flycpar_get = subpar_flycpar_subcmd.add_parser('get',
            help="get value of FlyC Param")
    subpar_flycpar_get.add_argument('param_name', type=str,
            help="name string of the requested parameter")
    subpar_flycpar_get.add_argument('-f', '--fmt', default='simple', type=str,
            choices=['simple', '1line', '2line', 'tab', 'csv'],
            help="output format")

    subpar_flycpar_set = subpar_flycpar_subcmd.add_parser('set',
            help="update value of FlyC Param")
    subpar_flycpar_set.add_argument('param_name', type=str,
            help="name string of the parameter")
    subpar_flycpar_set.add_argument('param_value', type=str,
            help="new value of the parameter")
    subpar_flycpar_set.add_argument('-f', '--fmt', default='simple', type=str,
            choices=['simple', '1line', '2line', 'tab', 'csv'],
            help="output format")

    po = parser.parse_args()

    po.product = PRODUCT_CODE.from_name(po.product)
    po.svcmd = SERVICE_CMD.from_name(po.svcmd)

    if po.svcmd == SERVICE_CMD.FlycParam:
        po.subcmd = FLYC_PARAM_CMD.from_name(po.subcmd.upper())
        do_flyc_param_request(po)
    elif po.svcmd == SERVICE_CMD.GimbalCalib:
        do_gimbal_calib_request(po)

if __name__ == '__main__':
    try:
        main()
    except Exception as ex:
        print("Error: "+str(ex))
        raise
