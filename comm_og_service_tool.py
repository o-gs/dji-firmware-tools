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
import struct
import serial
import select
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

def do_flyc_param_request_list(po, ser):

    if ((po.product == PRODUCT_CODE.P3X) or
      (po.product == PRODUCT_CODE.P3S) or
      (po.product == PRODUCT_CODE.P3C)):
        unlock_status = True # No Assistant Unlock needed on pre-2017 platforms
    else:
        unlock_status = send_assistant_unlock(po, ser, 1)
    if not unlock_status:
        print("Assistant Unlock command failed; further commands may not work because of this.")

    payload = DJIPayload_FlyController_GetParamDefinition2015Rq()

    if po.fmt == '2line':
        print("{:4s} {:60s}".format("idx", "name"))
        print("{:6s} {:4s} {:6s} {:7s} {:7s} {:7s}".format(
          "typeId", "size", "attr", "min", "max", "deflt"))
    elif po.fmt == 'tab':
        print("{:s}\t{:s}\t{:s}\t{:s}\t{:s}\t{:s}\t{:s}\t{:s}".format(
          "idx", "name", "typeId", "size", "attr", "min", "max", "deflt"))
    elif po.fmt == 'csv':
        print("{:s};{:s};{:s};{:s};{:s};{:s};{:s};{:s}".format(
          "idx", "name", "typeId", "size", "attr", "min", "max", "deflt"))
    else: # po.fmt == '1line':
        print("{:4s} {:60s} {:6s} {:4s} {:6s} {:7s} {:7s} {:7s}".format(
          "idx", "name", "typeId", "size", "attr", "min", "max", "deflt"))

    for idx in range(po.start, po.start+po.count):
        payload.param_index = idx
        pktrpl = send_request_and_receive_reply(po, ser,
          COMM_DEV_TYPE.FLYCONTROLLER, 0,
          ACK_TYPE.ACK_AFTER_EXEC,
          CMD_SET_TYPE.FLYCONTROLLER, 0xf0,
          payload)

        #DEBUG - use to test the code without a drone
        #pktrpl = bytes.fromhex("55 2e 04 a7 03 0a 77 45 80 03 f0 00 0a 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 67 6c 6f 62 61 6c 2e 73 74 61 74 75 73 00 79 ac")

        if pktrpl is None:
            eprint("No response on parameter {:d} definition request.".format(idx))
            break

        rplhdr = DJICmdV1Header.from_buffer_copy(pktrpl)
        rplpayload = get_known_payload(rplhdr, pktrpl[sizeof(DJICmdV1Header):-2])

        if (rplpayload is None):
            eprint("Unrecognized response to parameter {:d} definition request.".format(idx))
            break

        if sizeof(rplpayload) <= 4:
            if (po.verbose > 0):
                print("Response on parameter {:d} indicates end of list.".format(idx))
            break

        if (po.verbose > 2):
            print("Parsed response  - {:s}:".format(type(rplpayload).__name__))
            print(rplpayload)

        # Convert limits to string before, so we can handle all types in the same way
        limit_min = ""
        limit_max = ""
        limit_def = ""
        if isinstance(rplpayload, DJIPayload_FlyController_GetParamDefinitionU2015Re):
            limit_min = '{:d}'.format(rplpayload.limit_min)
            limit_max = '{:d}'.format(rplpayload.limit_max)
            limit_def = '{:d}'.format(rplpayload.limit_def)
        elif isinstance(rplpayload, DJIPayload_FlyController_GetParamDefinitionI2015Re):
            limit_min = '{:d}'.format(rplpayload.limit_min)
            limit_max = '{:d}'.format(rplpayload.limit_max)
            limit_def = '{:d}'.format(rplpayload.limit_def)
        elif isinstance(rplpayload, DJIPayload_FlyController_GetParamDefinitionF2015Re):
            limit_min = '{:f}'.format(rplpayload.limit_min)
            limit_max = '{:f}'.format(rplpayload.limit_max)
            limit_def = '{:f}'.format(rplpayload.limit_def)


        if po.fmt == '2line':
            print("{:4d} {:60s}".format(idx, rplpayload.name.decode("utf-8")))
            print("{:6d} {:4d} 0x{:04x} {:7s} {:7s} {:7s}".format(
              rplpayload.type_id, rplpayload.size, rplpayload.attribute,
              limit_min, limit_max, limit_def))
        elif po.fmt == 'tab':
            print("{:d}\t{:s}\t{:d}\t{:d}\t0x{:04x}\t{:s}\t{:s}\t{:s}".format(idx,
              rplpayload.name.decode("utf-8"),
              rplpayload.type_id, rplpayload.size, rplpayload.attribute,
              limit_min, limit_max, limit_def))
        elif po.fmt == 'csv':
            print("{:d};{:s};{:d};{:d};0x{:04x};{:s};{:s};{:s}".format(idx,
              rplpayload.name.decode("utf-8"),
              rplpayload.type_id, rplpayload.size, rplpayload.attribute,
              limit_min, limit_max, limit_def))
        #elif po.fmt == 'json': #TODO maybe output format similar to flyc_param_infos?
        else: # po.fmt == '1line':
            print("{:4d} {:60s} {:6d} {:4d} 0x{:04x} {:7s} {:7s} {:7s}".format(idx,
              rplpayload.name.decode("utf-8"),
              rplpayload.type_id, rplpayload.size, rplpayload.attribute,
              limit_min, limit_max, limit_def))

def do_flyc_param_request(po):
    # Open serial port
    ser = serial.Serial(po.port, baudrate=po.baudrate, timeout=0)
    if (po.verbose > 0):
        print("Opened {} at {}".format(ser.port, ser.baudrate))

    if po.subcmd == FLYC_PARAM_CMD.LIST:
        do_flyc_param_request_list(po, ser)
    elif po.subcmd == FLYC_PARAM_CMD.GET:
        eprint("Unimplemented {:s} command: {:s}.".format(po.svcmd.name, po.subcmd.name))
    elif po.subcmd == FLYC_PARAM_CMD.SET:
        eprint("Unimplemented {:s} command: {:s}.".format(po.svcmd.name, po.subcmd.name))
    else:
        eprint("Unrecognized {:s} command: {:s}.".format(po.svcmd.name, po.subcmd.name))

    ser.close()

def do_gimbal_calib_request(po):
    # Open serial port
    ser = serial.Serial(po.port, baudrate=po.baudrate, timeout=0)
    if (po.verbose > 0):
        print("Opened {} at {}".format(ser.port, ser.baudrate))

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

    subpar_flycpar_list.add_argument('-f', '--fmt', default='2line', type=str,
            choices=['2line', '1line', 'tab', 'csv'],
            help="output format")

    subpar_flycpar_get = subpar_flycpar_subcmd.add_parser('get',
            help="get value of FlyC Param")

    subpar_flycpar_set = subpar_flycpar_subcmd.add_parser('set',
            help="update value of FlyC Param")

    po = parser.parse_args()

    po.product = PRODUCT_CODE.from_name(po.product)
    po.svcmd = SERVICE_CMD.from_name(po.svcmd)

    if po.port == 'auto':
        po.port = detect_serial_port(po)

    if po.svcmd == SERVICE_CMD.FlycParam:
        po.subcmd = FLYC_PARAM_CMD.from_name(po.subcmd.upper())
        do_flyc_param_request(po)
    elif po.svcmd == SERVICE_CMD.GimbalCalib:
        do_gimbal_calib_request(po)

if __name__ == '__main__':
    main()
