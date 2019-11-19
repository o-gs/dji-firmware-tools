#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Utility to talk to DJI product via DUPC packets on serial interface.

 This script takes header fields and payload, and builds a proper DUPC
 packet from them. Then it sends it via given serial port and waits for an answer.
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

__version__ = "0.5.0"
__author__ = "Mefistotelis @ Original Gangsters"
__license__ = "GPL"

import os
import io
import sys
import time
import serial
import select
import argparse
from ctypes import *

sys.path.insert(0, './')
from comm_dat2pcap import (
  do_packetise_byte, store_packet, drop_packet,
  is_packet_ready, is_packet_damaged, is_packet_at_finish,
  Formatter, PktInfo, PktState,
  eprint,
)
from comm_mkdupc import (
  parse_module_ident, parse_module_type, parse_ack_type,
  parse_encrypt_type, parse_packet_type, parse_cmd_set, 
  encode_command_packet_en, get_known_payload,
  DJICmdV1Header, PACKET_TYPE, COMM_DEV_TYPE,
)

class ListFormatter():
    def __init__(self):
        self.pktlist = []

    def write_header(self):
        pass

    def write_packet(self, data, dtime=None):
        self.pktlist.append(data)

class SerialMock(io.RawIOBase):
    def __init__( self, port='COM1', baudrate = 19200, timeout=1,
                  bytesize = 8, parity = 'N', stopbits = 1, xonxoff=0,
                  rtscts = 0):
        self.name     = port
        self.port     = port
        self.timeout  = timeout
        self.parity   = parity
        self.baudrate = baudrate
        self.bytesize = bytesize
        self.stopbits = stopbits
        self.xonxoff  = xonxoff
        self.rtscts   = rtscts
        self.is_open  = True
        self._rxData = []
        self._txData = []
        self._wait_time = time.time()

    def write( self, btarr ):
        self._txData.append(btarr)

    def read( self, n=1 ):
        if time.time() < self._wait_time: return  b""
        self._wait_time = time.time() + 0.05
        if len(self._rxData) < 1: return b""
        btarr = self._rxData[0][0:n]
        if len(btarr) >= len(self._rxData[0]):
            del self._rxData[0]
        else:
            self._rxData[0] = self._rxData[0][n:]
        return btarr

    def mock_data_for_read( self, btarr ):
        self._rxData.append(btarr)

    def reset_input_buffer(self):
        pass

    @property
    def in_waiting(self):
        if time.time() < self._wait_time: return 0
        if len(self._rxData) < 1: return 0
        return len(self._rxData[0])

def do_read_packets(ser, state, info):
    out = ListFormatter()
    num_bytes = ser.in_waiting
    while (num_bytes > 0):
        # The read() function in Python is ridiculously slow; instead of using it
        # many times to read one byte, let's call it once for considerable buffer
        btarr = ser.read(min(num_bytes,4096))
        for bt in btarr:
            state, info = do_packetise_byte(bt, state, info)
            if (is_packet_ready(state)):
                state = store_packet(out, state)
            elif (is_packet_damaged(state)):
                state = drop_packet(state)
        if (is_packet_at_finish(state)):
            break;
        num_bytes = ser.in_waiting
    return state, out.pktlist, info

def packet_header_is_reply_for_request(rplhdr, reqhdr, responsebit_check=False, seqnum_check=True):
    if (rplhdr.version != 1):
        return False
    if (rplhdr.cmd_set != reqhdr.cmd_set):
        return False
    if (rplhdr.cmd_id != reqhdr.cmd_id):
        return False
    if (rplhdr.sender_info != reqhdr.receiver_info):
        return False
    if (rplhdr.receiver_info != reqhdr.sender_info):
        return False
    if (rplhdr.seq_num != reqhdr.seq_num) and seqnum_check:
        return False
    # Many responses don't have the RESPONSE bit set
    if (rplhdr.packet_type != PACKET_TYPE.RESPONSE) and responsebit_check:
        return False
    # Ack types should be different - respone should have NO_ACK; but in practice this varies
    #if (rplhdr.ack_type != reqhdr.ack_type):
    #    return False
    return True

def find_reply_for_request(po, pktlist, pktreq, seqnum_check=True):
    if len(pktlist) == 0:
        return None
    reqhdr = DJICmdV1Header.from_buffer_copy(pktreq)
    for pktrpl in pktlist:
        rplhdr = DJICmdV1Header.from_buffer_copy(pktrpl)
        if packet_header_is_reply_for_request(rplhdr, reqhdr, seqnum_check=seqnum_check):
            return pktrpl
        if (po.verbose > 2):
            print("Received unrelated packet:")
            print(' '.join('{:02x}'.format(x) for x in pktrpl))
    return None

def do_send_request(po, ser, pktprop):
    pktreq = encode_command_packet_en(pktprop.sender_type, pktprop.sender_index,
      pktprop.receiver_type, pktprop.receiver_index, pktprop.seq_num,
      pktprop.pack_type, pktprop.ack_type, pktprop.encrypt_type, pktprop.cmd_set,
      pktprop.cmd_id, pktprop.payload)
    if (po.verbose > 1):
        print("Prepared binary packet:")
        print(' '.join('{:02x}'.format(x) for x in pktreq))

    if (po.verbose > 0):
        print("Sending packet...")

    ser.write(pktreq)

    return pktreq

def do_receive_reply(po, ser, pktreq, seqnum_check=True):
    """ Receive reply after sending packet pktreq to interface ser.
    """
    ser.reset_input_buffer()
    if (po.verbose > 1):
        print("Waiting for reply...")

    info = PktInfo()

    state = PktState();
    state.verbose = po.verbose
    state.pname = ser.port
    pktrpl = None
    show_stats = False
    loop_end = False
    timeout_time = time.time() + po.timeout / 1000

    while not loop_end:
        # Wait for something to do
        if time.time() > timeout_time:
            if (po.verbose > 0):
                print("Timeout while waiting for reply.")
            show_stats = True
            loop_end = True

        if True:
            state, pktlist, info = do_read_packets(ser, state, info)
            pktrpl = find_reply_for_request(po, pktlist, pktreq, seqnum_check=seqnum_check)

        if pktrpl is not None:
            show_stats = True
            loop_end = True

        if (show_stats):
            if (po.verbose > 0):
                print("Retrieved {:d} packets ({:d}b), dropped {:d} fragments ({:d}b)".format(
                    info.count_ok, info.bytes_ok, info.count_bad, info.bytes_bad))
            show_stats = False

    return pktrpl

def do_send_request_receive_reply(po):
    # Open serial port
    ser = serial.Serial(po.port, baudrate=po.baudrate, timeout=0)
    if (po.verbose > 0):
        print("Opened {} at {}".format(ser.port, ser.baudrate))

    pktreq = do_send_request(po, ser, po)

    pktrpl = do_receive_reply(po, ser, pktreq, seqnum_check=(not po.loose_response))

    if (po.verbose > 0):
        if pktrpl is not None:
            print("Received response packet:")
        else:
            print("No response received.")
    if pktrpl is not None:
        print(' '.join('{:02x}'.format(x) for x in pktrpl))

        if (po.verbose > 0):
            rplhdr = DJICmdV1Header.from_buffer_copy(pktrpl)
            rplpayload = get_known_payload(rplhdr, pktrpl[sizeof(DJICmdV1Header):-2])
            if (rplpayload is not None):
                print("Parsed response  - {:s}:".format(type(rplpayload).__name__))
                print(rplpayload)

    ser.close()

def main():
    """ Main executable function.

      Its task is to parse command line options and call a function which performs serial communication.
    """
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument('port', type=str,
            help='the serial port to write to and read from')

    parser.add_argument('-b', '--baudrate', default=9600, type=int,
            help='the baudrate to use for the serial port (default is %(default)s)')

    parser.add_argument('-n', '--seq_num', default=0, type=int,
            help='Sequence number of the packet (default is %(default)s)')

    parser.add_argument('-u', '--pack_type', default="Request", type=parse_packet_type,
            help='Packet Type, either name or number (default is %(default)s)')

    parser.add_argument('-a', '--ack_type', default="No_ACK_Needed", type=parse_ack_type,
            help='Acknowledgement type, either name or number (default is %(default)s)')

    parser.add_argument('-e', '--encrypt_type', default="NO_ENC", type=parse_encrypt_type,
            help='Encryption type, either name or number (default is %(default)s)')

    parser.add_argument('-s', '--cmd_set', default="GENERAL", type=parse_cmd_set,
            help='Command Set, either name or number (default is %(default)s)')

    parser.add_argument('-i', '--cmd_id', default=0, type=int,
            help='Command ID (default is %(default)s)')

    parser.add_argument('-w', '--timeout', default=2000, type=int,
            help='how long to wait for answer, in miliseconds (default is %(default)s)')

    parser.add_argument('--loose-response', action="store_true",
            help='use loosen criteria when searching for response to the packet')

    parser.add_argument('-v', '--verbose', action='count', default=0,
            help='increases verbosity level; max level is set by -vvv')

    parser.add_argument("--version", action='version', version="%(prog)s {version} by {author}"
              .format(version=__version__,author=__author__),
            help="display version information and exit")

    subparser = parser.add_mutually_exclusive_group()

    subparser.add_argument('-t', '--sender', type=parse_module_ident,
            help='Sender Type and Index, in TTII form')

    subparser.add_argument('-tt', '--sender_type', default="PC", type=parse_module_type,
            help='Sender(transmitter) Type, either name or number (default is %(default)s)')

    parser.add_argument('-ti', '--sender_index', default=0, type=int,
            help='Sender(transmitter) Index (default is %(default)s)')

    subparser = parser.add_mutually_exclusive_group()

    subparser.add_argument('-r', '--receiver', type=parse_module_ident,
            help='Receiver Type and Index, in TTII form (ie. 0300)')

    subparser.add_argument('-rt', '--receiver_type', default="ANY", type=parse_module_type,
            help='Receiver Type, either name or number (default is %(default)s)')

    parser.add_argument('-ri', '--receiver_index', default=0, type=int,
            help='Receiver index (default is %(default)s)')

    subparser = parser.add_mutually_exclusive_group()

    subparser.add_argument('-x', '--payload_hex', type=str,
            help='provide payload as hex string')

    subparser.add_argument('-p', '--payload_bin', default="", type=str,
            help='provide binary payload directly (default payload is empty)')

    po = parser.parse_args();

    if (po.payload_hex is not None):
        po.payload = bytes.fromhex(po.payload_hex)
    else:
        po.payload = bytes(po.payload_bin, 'utf-8')

    if (po.sender is not None):
        po.sender_type = COMM_DEV_TYPE(int(po.sender.group(1), 10))
        po.sender_index = int(po.sender.group(2), 10)

    if (po.receiver is not None):
        po.receiver_type = COMM_DEV_TYPE(int(po.receiver.group(1), 10))
        po.receiver_index = int(po.receiver.group(2), 10)

    do_send_request_receive_reply(po)

if __name__ == '__main__':
    try:
        main()
    except Exception as ex:
        eprint("Error: "+str(ex))
        #raise
        sys.exit(10)
