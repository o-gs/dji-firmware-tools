#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" DJI serial bus -> pcap utility.

 This script captures data from two UARTs and attempts to packetise the
 streams. CRC is checked before the packet is passed to the pcap file/fifo.
"""

# Derived from:
#
# AVR / Arduino dynamic memory log analyis script.
#
# Copyright 2014 Matthijs Kooijman <matthijs@stdin.nl>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# This script is intended to read raw packets (currently only 802.15.4
# packets prefixed by a length byte) from a serial port and output them
# in pcap format.

import os
import sys
import time
import errno
import serial
import struct
import select
import binascii
import datetime
import argparse
import enum

class RxState(enum.Enum):
    NO_PACKET = 0
    IN_HEAD = 1
    IN_BODY = 2
    IN_TRAIL = 3

class CaptureStats:
  count_ok = 0
  count_bad = 0
  bytes_ok = 0
  bytes_bad = 0

def calc_pkt55_checksum(packet, plength):
    crc =[0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
     0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
     0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
     0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
     0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
     0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
     0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
     0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
     0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
     0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
     0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
     0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
     0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
     0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
     0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
     0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
     0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
     0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
     0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
     0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
     0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
     0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
     0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
     0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
     0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
     0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
     0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
     0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
     0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
     0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
     0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
     0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78]

    v = 0x3692	#P3

    for i in range(0, plength):
        vv = v >> 8
        v = vv ^ crc[((packet[i] ^ v) & 0xFF)]
    return v


def calc_pkt55_hdr_checksum(seed, packet, plength):
    arr_2A103 = [0x00,0x5E,0xBC,0xE2,0x61,0x3F,0xDD,0x83,0xC2,0x9C,0x7E,0x20,0xA3,0xFD,0x1F,0x41,
        0x9D,0xC3,0x21,0x7F,0xFC,0xA2,0x40,0x1E,0x5F,0x01,0xE3,0xBD,0x3E,0x60,0x82,0xDC,
        0x23,0x7D,0x9F,0xC1,0x42,0x1C,0xFE,0xA0,0xE1,0xBF,0x5D,0x03,0x80,0xDE,0x3C,0x62,
        0xBE,0xE0,0x02,0x5C,0xDF,0x81,0x63,0x3D,0x7C,0x22,0xC0,0x9E,0x1D,0x43,0xA1,0xFF,
        0x46,0x18,0xFA,0xA4,0x27,0x79,0x9B,0xC5,0x84,0xDA,0x38,0x66,0xE5,0xBB,0x59,0x07,
        0xDB,0x85,0x67,0x39,0xBA,0xE4,0x06,0x58,0x19,0x47,0xA5,0xFB,0x78,0x26,0xC4,0x9A,
        0x65,0x3B,0xD9,0x87,0x04,0x5A,0xB8,0xE6,0xA7,0xF9,0x1B,0x45,0xC6,0x98,0x7A,0x24,
        0xF8,0xA6,0x44,0x1A,0x99,0xC7,0x25,0x7B,0x3A,0x64,0x86,0xD8,0x5B,0x05,0xE7,0xB9,
        0x8C,0xD2,0x30,0x6E,0xED,0xB3,0x51,0x0F,0x4E,0x10,0xF2,0xAC,0x2F,0x71,0x93,0xCD,
        0x11,0x4F,0xAD,0xF3,0x70,0x2E,0xCC,0x92,0xD3,0x8D,0x6F,0x31,0xB2,0xEC,0x0E,0x50,
        0xAF,0xF1,0x13,0x4D,0xCE,0x90,0x72,0x2C,0x6D,0x33,0xD1,0x8F,0x0C,0x52,0xB0,0xEE,
        0x32,0x6C,0x8E,0xD0,0x53,0x0D,0xEF,0xB1,0xF0,0xAE,0x4C,0x12,0x91,0xCF,0x2D,0x73,
        0xCA,0x94,0x76,0x28,0xAB,0xF5,0x17,0x49,0x08,0x56,0xB4,0xEA,0x69,0x37,0xD5,0x8B,
        0x57,0x09,0xEB,0xB5,0x36,0x68,0x8A,0xD4,0x95,0xCB,0x29,0x77,0xF4,0xAA,0x48,0x16,
        0xE9,0xB7,0x55,0x0B,0x88,0xD6,0x34,0x6A,0x2B,0x75,0x97,0xC9,0x4A,0x14,0xF6,0xA8,
        0x74,0x2A,0xC8,0x96,0x15,0x4B,0xA9,0xF7,0xB6,0xE8,0x0A,0x54,0xD7,0x89,0x6B,0x35]

    chksum = seed
    for i in range(0, plength):
        chksum = arr_2A103[((packet[i] ^ chksum) & 0xFF)];
    return chksum

def calc_pktAB_checksum(cnst, packet, length): 

    result = packet[0]

    for byte_ctr in range(1,(length )):
        byte = packet[byte_ctr]
        for bit_ctr in range(0, 8):
            msb = result & 0x80
            result = ((result << 1) | (byte >> 7)) & 0xFF
            if msb == 0x80:
                result = result ^ cnst
            byte = (byte << 1) & 0xFF

    for bit_ctr in range(0, 8):
        msb = result & 0x80
        result = (result << 1) & 0xFF
        if msb == 0x80:
            result = result ^ cnst
    return result


class Formatter:
    def __init__(self, out):
        self.out = out

    def fileno(self):
        return self.out.fileno()

    def close(self):
        self.out.close()

class PcapFormatter(Formatter):
    def write_header(self):
        self.out.write(struct.pack("=IHHiIII",
            0xa1b2c3d4,   # magic number
            2,            # major version number
            4,            # minor version number
            0,            # GMT to local correction
            0,            # accuracy of timestamps
            65535,        # max length of captured packets, in octets
            147,          # data link type (DLT) - USER_0
        ))
        self.out.flush()

    def write_packet(self, data):
        now = datetime.datetime.now()
        timestamp = int(time.mktime(now.timetuple()))
        self.out.write(struct.pack("=IIII",
            timestamp,        # timestamp seconds
            now.microsecond,  # timestamp microseconds
            len(data),        # number of octets of packet saved in file
            len(data),        # actual length of packet
        ))
        self.out.write(data)
        self.out.flush()

class HumanFormatter(Formatter):
    def write_header(self):
        pass

    def write_packet(self, data):
        self.out.write(binascii.hexlify(data).decode())
        self.out.write("\n")
        self.out.flush()

def open_fifo(options, name):
    try:
        os.mkfifo(name);
    except FileExistsError:
        pass
    except:
        raise

    if not options.quiet:
        print("Waiting for fifo to be openend...")
    # This blocks until the other side of the fifo is opened
    return open(name, 'wb')

def setup_output(options):
    if options.fifo:
        return PcapFormatter(open_fifo(options, options.fifo))
    elif options.write_file:
        return PcapFormatter(open(options.write_file, 'wb'))
    else:
        return HumanFormatter(sys.stdout)

def main():
    """ Main executable function.

      Its task is to parse command line options and call a function which performs sniffing.
    """
    parser = argparse.ArgumentParser(description='Convert DJI P3 packets sniffed from a serial link into pcap format')

    parser.add_argument('port1',
                        help='The serial port to read from')

    parser.add_argument('port2',
                        help='The serial port to read from')


    parser.add_argument('-b', '--baudrate', default=115200, type=int,
                        help='The baudrate to use for the serial port (defaults to %(default)s)')

    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Do not output any informational messages')

    output = parser.add_mutually_exclusive_group()

    output.add_argument('-F', '--fifo',
                        help='Write output to a fifo instead of stdout. The fifo is created if needed and capturing does not start until the other side of the fifo is opened.')

    output.add_argument('-w', '--write-file',
                        help='Write output to a file instead of stdout')

    options = parser.parse_args();

    try:
        # If the fifo got closed, just start over again
        while True:
            do_sniff_once(options)
    except KeyboardInterrupt:
        pass


def do_packetiser(ser, state, packet, out, cstat):
    while ser.inWaiting():
        byte = ord(ser.read(1))

        if state == RxState.NO_PACKET:	# expect ideftifier - 55 or AB
            if byte == 0x55 or byte == 0xAB:
                if len(packet) > 0:
                    cstat.count_bad += 1
                    cstat.bytes_bad += len(packet)
                packet = bytearray()
                packet.append(byte)
                state = RxState.IN_HEAD
            else:
                packet.append(byte)
                # Make sure we do not gather too much rubbish
                if len(packet) > 255:
                    cstat.count_bad += 1
                    cstat.bytes_bad += len(packet)
                    packet = bytearray()

        elif state == RxState.IN_HEAD:
            packet.append(byte)
            # If got whole header for given packet type, switch to reading body
            if packet[0] == 0x55 and len(packet) == 4:
                # type 55 packet header has its own checksum
                hdr_ccrc = calc_pkt55_hdr_checksum(0x77, packet, 3)
                hdr_crc_pkt = struct.unpack("B", packet[3:4])[0]
                if hdr_ccrc == hdr_crc_pkt:
                    state = RxState.IN_BODY
                else:
                    # stats will be updated later, just change state
                    state = RxState.NO_PACKET
            elif packet[0] == 0xAB and len(packet) == 4:
                state = RxState.IN_BODY

        elif state == RxState.IN_BODY:
            packet.append(byte)
            if len(packet) == packet[1]-1:
                state = RxState.IN_TRAIL

        elif state == RxState.IN_TRAIL:
            packet.append(byte)

            if packet[0] == 0x55:
                ccrc = calc_pkt55_checksum(packet, len(packet) - 2)
                crc_pkt = struct.unpack("<H", packet[-2:])[0]
                if ccrc == crc_pkt:
                    try:
                        cstat.count_ok += 1
                        cstat.bytes_ok += len(packet)
                        out.write_packet(packet)
                    except OSError as e:
                        # SIGPIPE indicates the fifo was closed
                        if e.errno == errno.SIGPIPE:
                            break
                else:
                    cstat.count_bad += 1
                    cstat.bytes_bad += len(packet)
                                           
            elif packet[0] == 0xAB:
                ccrc = calc_pktAB_checksum(7, packet, len(packet) - 1)
                crc_pkt = struct.unpack("B", packet[-1:])[0]
                if ccrc == crc_pkt:
                    try:
                        cstat.count_ok += 1
                        cstat.bytes_ok += len(packet)
                        out.write_packet(packet)
                    except OSError as e:
                        # SIGPIPE indicates the fifo was closed
                        if e.errno == errno.SIGPIPE:
                            break
                else:
                    cstat.count_bad += 1
                    cstat.bytes_bad += len(packet)

            packet = bytearray()
            state = RxState.NO_PACKET
    return state, packet, cstat

def do_sniff_once(options):
    # This might block until the other side of the fifo is opened
    out = setup_output(options)
    out.write_header()

    ser1 = serial.Serial(options.port1, options.baudrate)
    print("Opened {} at {}".format(options.port1, options.baudrate))

    ser2 = serial.Serial(options.port2, options.baudrate)
    print("Opened {} at {}".format(options.port2, options.baudrate))

    if not options.quiet:
        print("Waiting for packets...")

    cstat = CaptureStats()

    poll = select.poll()
    # Wait to read data from serial, or until the fifo is closed
    poll.register(ser1, select.POLLIN)
    poll.register(ser2, select.POLLIN)
    poll.register(sys.stdin, select.POLLIN)
    poll.register(out, select.POLLERR)

    packet1 = bytearray()
    packet2 = bytearray()
    state1 = RxState.NO_PACKET
    state2 = RxState.NO_PACKET


    while True:
        # Wait for something to do
        events = poll.poll()

        fds = [fd for (fd, evt) in events]
        if out.fileno() in fds:
            # Error on output, e.g. fifo closed on the other end
            break

        elif ser1.fileno() in fds:
            state1, packet1, cstat = do_packetiser(ser1, state1, packet1, out, cstat)

        elif ser2.fileno() in fds:
            state2, packet2, cstat = do_packetiser(ser2, state2, packet2, out, cstat)

        elif sys.stdin.fileno() in fds:
            input()
            print("Captured {} packets ({}b), dropped {} fragments ({}b)".format(cstat.count_ok,
                cstat.bytes_ok, cstat.count_bad, cstat.bytes_bad))

    ser1.close()
    ser2.close()
    out.close()

    if not options.quiet:
        print("Captured {} packets ({}b), dropped {} fragments ({}b)".format(cstat.count_ok,
            cstat.bytes_ok, cstat.count_bad, cstat.bytes_bad))

if __name__ == '__main__':
    main()
