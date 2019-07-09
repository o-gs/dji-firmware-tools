#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" DJI serial bus sniffer with PCap output.

 This script captures data from two UARTs and attempts to packetise the
 streams. CRC is checked before the packet is passed to the PCap file/fifo.

 If the packets you are trying to capture are not compatible, you may capture
 the plain binary data instead (though you won't be able to interleave two streams):

 ```
 stty -F /dev/ttyS1 115200 cs8 -parenb -cstopb; cat /dev/ttyS1 | pv | cat > output.dat
 ```

"""

# Copyright (C) 2017 GlovePuppet <https://github.com/glovepuppet>
# Copyright (C) 2017 Mefistotelis <mefistotelis@gmail.com>
# Copyright (C) 2018 Original Gangsters <https://dji-rev.slack.com/>
#
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

__version__ = "0.5.0"
__author__ = "GlovePuppet, Mefistotelis @ Original Gangsters"
__license__ = "GPL"

import os
import sys
import serial
import select
import argparse

sys.path.insert(0, './')
from comm_dat2pcap import (
  do_packetise_byte, store_packet, drop_packet,
  is_packet_ready, is_packet_damaged, is_packet_at_finish,
  PcapFormatter, HumanFormatter, PktInfo, PktState,
  eprint,
)

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
    num_bytes = ser.inWaiting()
    while (num_bytes > 0):
        # The read() function in Python is ridiculously slow; instead of using it
        # many times to read one byte, let's call it once for considerable buffer
        btarr = ser.read(min(num_bytes,4096))
        for bt in btarr:
            state, info = do_packetise_byte(bt, state, info)
            if (is_packet_ready(state)):
                state = store_packet(out, state)
            elif (is_packet_damaged(state)):
                if (out.storebad):
                    state = store_packet(out, state)
                else:
                    state = drop_packet(state)
        if (is_packet_at_finish(state)):
            break;
        num_bytes = ser.inWaiting()
    return state, info

def do_sniff_once(options):
    # This might block until the other side of the fifo is opened
    out = setup_output(options)
    out.userdlt = options.userdlt
    out.storebad = options.storebad
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
    state1.verbose = 0 if options.quiet else max(options.verbose,1)
    state1.pname = options.port1
    state2 = PktState();
    state2.verbose = 0 if options.quiet else max(options.verbose,1)
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
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument('port1', type=str,
            help='The first serial port to read from')

    parser.add_argument('port2', type=str,
            help='The second serial port to read from')

    parser.add_argument('-b', '--baudrate', default=115200, type=int,
            help='The baudrate to use for both serial ports (defaults to %(default)s)')

    parser.add_argument('-u', '--userdlt', default=0, type=int,
            help='The data link type of the PCap DLT_USER protocol (defaults to %(default)s)')

    parser.add_argument('-e', '--storebad', action='store_true',
            help='Enables storing bad packets (ie. with bad checksums)')

    subparser = parser.add_mutually_exclusive_group()

    subparser.add_argument('-q', '--quiet', action='store_true',
            help='Do not output any informational messages')

    subparser.add_argument('-v', '--verbose', action='count', default=0,
            help='Increases verbosity level; max level is set by -vvv')

    subparser = parser.add_mutually_exclusive_group()

    subparser.add_argument('-F', '--fifo',
            help='Write output to a fifo instead of stdout. The fifo is created if needed and capturing does not start until the other side of the fifo is opened.')

    subparser.add_argument('-w', '--write-file',
            help='Write output to a file instead of stdout')

    subparser.add_argument("--version", action='version', version="%(prog)s {version} by {author}"
              .format(version=__version__,author=__author__),
            help="Display version information and exit")

    options = parser.parse_args();

    try:
        # If the fifo got closed, just start over again
        while True:
            do_sniff_once(options)
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    try:
        main()
    except Exception as ex:
        eprint("Error: "+str(ex))
        #raise
        sys.exit(10)
