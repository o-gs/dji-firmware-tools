#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Raw DUPC packets to PCap converter.

This tool parses Dji Unified Packet Container packets from input file,
and puts the results into PCap file. Checksums within the packets are checked
and only valid packets are accepted.

The script can also behave as a library to use the parser for other tasks.

PCap files can be used with WireShark and other tools for packets analysis.
"""

# Copyright (C) 2017 Mefistotelis <mefistotelis@gmail.com>
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

from __future__ import print_function
__version__ = "0.2.1"
__author__ = "Mefistotelis @ Original Gangsters"
__license__ = "GPL"

import sys
import argparse
import os
import enum
import struct
import time
import datetime
import binascii

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

class StateId(enum.Enum):
    NO_PACKET = 0
    IN_HEAD = 1
    IN_BODY = 2
    IN_TRAIL = 3
    READY = 4
    DAMAGED = 5 # No longer used - packet is damaged when done_packet is set
    FINISH = 6

class PktInfo:
    count_ok = 0
    count_bad = 0
    bytes_ok = 0
    bytes_bad = 0

class PktState:
    id = StateId.NO_PACKET
    packet = bytearray()
    done_packet = None
    verbose = 0
    pname = "2pcap"

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

    # Seeds
    #v = 0x1012 # Naza M
    #v = 0x1013 # Phantom 2
    #v = 0x7000 # Naza M V2
    v = 0x3692 # P3/P4/Mavic

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
    def __init__(self, out):
        Formatter.__init__(self, out)
        self.userdlt = 0

    def write_header(self):
        self.out.write(struct.pack("=IHHiIII",
            0xa1b2c3d4,   # magic number
            2,            # major version number
            4,            # minor version number
            0,            # GMT to local correction
            0,            # accuracy of timestamps
            65535,        # max length of captured packets, in octets
            147+self.userdlt, # data link type (DLT) - USER_0
        ))
        self.out.flush()

    def write_packet(self, data, dtime=None):
        if dtime is None:
            dtime = datetime.datetime.now()
        timestamp = int(time.mktime(dtime.timetuple()))
        self.out.write(struct.pack("=IIII",
            timestamp,        # timestamp seconds
            dtime.microsecond, # timestamp microseconds
            len(data),        # number of octets of packet saved in file
            len(data),        # actual length of packet
        ))
        self.out.write(data)
        self.out.flush()

class HumanFormatter(Formatter):
    def write_header(self):
        pass

    def write_packet(self, data, dtime=None):
        self.out.write(binascii.hexlify(data).decode())
        self.out.write("\n")
        self.out.flush()

def is_packet_ready(state):
    """ Returns whether a packet within the state is ready for storing.
    """
    return (state.id == StateId.READY) and (len(state.packet) > 0);

def is_packet_damaged(state):
    """ Returns whether a packet within the state is ready but damaged.
    """
    return (state.done_packet is not None)

def is_packet_at_finish(state):
    """ Returns whether the state informs processing should finish.
    """
    return (state.id == StateId.FINISH);

def store_packet(out, state):
    """ Write packet from given state into given output stream.

        This function can be called when packet stored within the state
        is ready. The packet is written to stream and removed from the state.
    """
    if state.done_packet is None:
        state.done_packet = state.packet
        state.id = StateId.NO_PACKET
        state.packet = bytearray()
    try:
        out.write_packet(state.done_packet)
    except OSError as e:
        # SIGPIPE indicates the fifo was closed
        if e.errno == errno.SIGPIPE:
            state.id = StateId.FINISH
    state.done_packet = None
    return state

def drop_packet(state):
    """ Drop packet from given state without storing it.

        This function can be called when packet stored within the state
        should be removed.
    """
    if state.done_packet is None:
        state.id = StateId.NO_PACKET
        state.packet = bytearray()
    else:
        state.done_packet = None
    return state

def do_packetise_byte(byte, state, info):
  """ Add byte to the packetize effort represented by state

    The function adds byte to the packet contained within state,
    or drops the byte if applicable. The processing of a new byte
    is also reflected in statistics.

    If state.id changes to READY or DAMAGED, the function expects caller
    to remove existing packet before the next call.
  """

  if state.id == StateId.NO_PACKET:	# expect ideftifier - 55 or AB
      if byte == 0x55 or byte == 0xAB:
          if len(state.packet) > 0:
              info.count_bad += 1
              info.bytes_bad += len(state.packet)
              if (state.verbose > 1):
                  print("{}: Packet type {:02X} damaged - no data recognized; {} bytes".format(state.pname,state.packet[0],len(state.packet)))
              state.done_packet = state.packet
          state.packet = bytearray()
          state.packet.append(byte)
          state.id = StateId.IN_HEAD
      else:
          state.packet.append(byte)
          # Make sure we do not gather too much rubbish
          if len(state.packet) > 0x3ff:
              info.count_bad += 1
              info.bytes_bad += len(state.packet)
              if (state.verbose > 1):
                  print("{}: Packet type {:02X} damaged - no data recognized; {} bytes".format(state.pname,state.packet[0],len(state.packet)))
              state.done_packet = state.packet
              state.packet = bytearray()

  elif state.id == StateId.IN_HEAD:
      state.packet.append(byte)
      # If got whole header for given packet type, switch to reading body
      if state.packet[0] == 0x55 and len(state.packet) == 4:
          # type 55 packet header has its own checksum
          hdr_ccrc = calc_pkt55_hdr_checksum(0x77, state.packet, 3)
          hdr_crc_pkt = struct.unpack("B", state.packet[3:4])[0]
          if hdr_ccrc == hdr_crc_pkt:
              state.id = StateId.IN_BODY
          else:
              if (state.verbose > 1):
                  print("{}: Packet type {:02X} skipped - bad head crc; {} bytes".format(state.pname,state.packet[0],len(state.packet)))
              # stats will be updated later, just change state
              state.id = StateId.NO_PACKET
      elif state.packet[0] == 0xAB and len(state.packet) == 4:
          state.id = StateId.IN_BODY

  elif state.id == StateId.IN_BODY:
      state.packet.append(byte)
      # for packet type 0x55, 2 bits of size are in packet[2]
      if state.packet[0] == 0x55:
          len_pkt = struct.unpack("<H", state.packet[1:3])[0] & 0x3ff
      else:
          len_pkt = state.packet[1]
      if len(state.packet) == len_pkt-1:
          state.id = StateId.IN_TRAIL
      elif (len(state.packet) >= len_pkt):
          if (state.verbose > 1):
              print("{}: Packet type {:02X} skipped - shorter than header; {} bytes".format(state.pname,state.packet[0],len(state.packet)))
          state.id = StateId.NO_PACKET

  elif state.id == StateId.IN_TRAIL:
      state.packet.append(byte)
      if state.packet[0] == 0x55:
          ccrc = calc_pkt55_checksum(state.packet, len(state.packet) - 2)
          crc_pkt = struct.unpack("<H", state.packet[-2:])[0]
          if ccrc == crc_pkt:
              info.count_ok += 1
              info.bytes_ok += len(state.packet)
              state.id = StateId.READY
          else:
              info.count_bad += 1
              info.bytes_bad += len(state.packet)
              if (state.verbose > 1):
                  print("{}: Packet type {:02X} damaged - bad crc; {} bytes".format(state.pname,state.packet[0],len(state.packet)))
              state.done_packet = state.packet
              state.packet = bytearray()
              state.id = StateId.NO_PACKET
      elif state.packet[0] == 0xAB:
          ccrc = calc_pktAB_checksum(7, state.packet, len(state.packet) - 1)
          crc_pkt = struct.unpack("B", state.packet[-1:])[0]
          if ccrc == crc_pkt:
              info.count_ok += 1
              info.bytes_ok += len(state.packet)
              state.id = StateId.READY
          else:
              info.count_bad += 1
              info.bytes_bad += len(state.packet)
              if (state.verbose > 1):
                  print("{}: Packet type {:02X} damaged - bad crc; {} bytes".format(state.pname,state.packet[0],len(state.packet)))
              state.done_packet = state.packet
              state.packet = bytearray()
              state.id = StateId.NO_PACKET

  else:
      print("{}: Invalid packetise state {}".format(state.pname,state.id))
      state.id = StateId.FINISH

  return state, info

def do_dat2pcap(po, datfile, pcapfile):
  """ Reads raw packets from datfile and writes them into pcapfile with proper headers.
  """
  # This might block until the other side of the fifo is opened
  out = PcapFormatter(pcapfile)
  out.userdlt = po.userdlt
  out.write_header()

  if (po.verbose > 1):
    print("{}: Copying packets into {} ...".format(po.datfile,po.pcapfile))

  info = PktInfo()
  state = PktState()
  state.verbose = po.verbose
  state.pname = po.datfile
  count = 0

  while True:
      # The read() function in Python is ridiculously slow; instead of using it
      # many times to read one byte, let's call it once for considerable buffer
      btarr = datfile.read(4096)
      if len(btarr) < 1: # eof
          break
      for bt in btarr:
          count += 1
          state, info = do_packetise_byte(bt, state, info)
          if (is_packet_ready(state)):
              state = store_packet(out, state)
          elif (is_packet_damaged(state)):
              if (po.storebad):
                  state = store_packet(out, state)
              else:
                  state = drop_packet(state)
      if (is_packet_at_finish(state)):
          break;
      if (po.verbose > 2) and (count & 0xffff) == 0:
          print("{}: Packets encountered: {:d} valid ({:d}b), {:d} damaged ({:d}b)".format(
              state.pname, info.count_ok, info.bytes_ok, info.count_bad, info.bytes_bad))

  if (po.verbose > 0):
      print("{}: Packets encountered: {:d} valid ({:d}b), {:d} damaged ({:d}b)".format(
          state.pname, info.count_ok, info.bytes_ok, info.count_bad, info.bytes_bad))

def main():
  """ Main executable function.

  Its task is to parse command line options and call a function which performs requested command.
  """
  # Parse command line options

  parser = argparse.ArgumentParser(description=__doc__)

  parser.add_argument("-p", "--pcapfile", default="", type=str,
          help="Output to pcap file of given name")

  parser.add_argument("-u", "--userdlt", default=0, type=int,
          help="Sets specific data link type of the DLT_USER protocol (default is %(default)d; change it for complex wireshark configs)")

  parser.add_argument("-e", "--storebad", action="store_true",
          help="Enables storing bad packets (ie. with bad checksums)")

  parser.add_argument("-v", "--verbose", action="count", default=0,
          help="Increases verbosity level; max level is set by -vvv")

  subparser = parser.add_mutually_exclusive_group()

  parser.add_argument("-d", "--datfile", default="", type=str, required=True,
          help="Input from dat file (Raw DUPC) of given name")

  subparser.add_argument("--version", action='version', version="%(prog)s {version} by {author}"
            .format(version=__version__,author=__author__),
          help="Display version information and exit")

  po = parser.parse_args();

  if po.userdlt > 15:
      raise ValueError("There are only 15 DLT_USER slots.")

  po.command = ''
  if len(po.datfile) > 0:
      po.command = 'd'

  po.basename = os.path.splitext(os.path.basename(po.datfile))[0]
  if len(po.datfile) > 0 and len(po.pcapfile) == 0:
      po.pcapfile = po.basename + ".pcap"

  if (po.command == 'd'):

      if (po.verbose > 0):
         print("{}: Opening Raw DUPC for conversion to PCap".format(po.datfile))
      datfile = open(po.datfile, "rb")
      pcapfile = open(po.pcapfile, "wb")

      do_dat2pcap(po,datfile,pcapfile)

      datfile.close();
      pcapfile.close();

  else:

      raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        eprint("Error: "+str(ex))
        #raise
        sys.exit(10)
