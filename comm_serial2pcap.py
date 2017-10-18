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
import serial
import select
import argparse

sys.path.insert(0, './')
from comm_dat2pcap import do_packetise_byte, is_packet_ready, is_packet_at_finish, store_packet, PcapFormatter, HumanFormatter, PktInfo, PktState

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

def do_packetiser(ser, state, out, info):
    while ser.inWaiting():
        chr = ser.read(1)
        state, info = do_packetise_byte(ord(chr), state, info)
        if (is_packet_ready(state)):
            state = store_packet(out, state)
        if (is_packet_at_finish(state)):
            break;
    return state, info

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

    info = PktInfo()

    poll = select.poll()
    # Wait to read data from serial, or until the fifo is closed
    poll.register(ser1, select.POLLIN)
    poll.register(ser2, select.POLLIN)
    if not options.quiet:
        poll.register(sys.stdin, select.POLLIN)
    poll.register(out, select.POLLERR)

    state1 = PktState();
    state1.verbose = 0 if options.quiet else 1
    state1.pname = options.port1
    state2 = PktState();
    state2.verbose = 0 if options.quiet else 1
    state2.pname = options.port2

    while True:
        # Wait for something to do
        events = poll.poll()

        fds = [fd for (fd, evt) in events]
        if out.fileno() in fds:
            # Error on output, e.g. fifo closed on the other end
            break

        if ser1.fileno() in fds:
            state1, info = do_packetiser(ser1, state1, out, info)

        if ser2.fileno() in fds:
            state2, info = do_packetiser(ser2, state2, out, info)

        if sys.stdin.fileno() in fds:
            input()
            print("Captured {:d} packets ({:d}b), dropped {:d} fragments ({:d}b)".format(info.count_ok,
                info.bytes_ok, info.count_bad, info.bytes_bad))

    ser1.close()
    ser2.close()
    out.close()

    if not options.quiet:
        print("Captured {:d} packets ({:d}b), dropped {:d} fragments ({:d}b)".format(info.count_ok,
            info.bytes_ok, info.count_bad, info.bytes_bad))

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

if __name__ == '__main__':
    main()
