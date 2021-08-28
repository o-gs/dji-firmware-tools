#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" DJI Firmware IMaH Un-signer and Decryptor tool.

Allows to decrypt and un-sign module from `.sig` file which starts with
`IM*H`. Use this tool after untarring single modules from a firmware package,
to decrypt its content.

"""

# Copyright (C) 2017  Freek van Tienen <freek.v.tienen@gmail.com>
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
__version__ = "0.3.1"
__author__ = "Freek van Tienen, Jan Dumon, Mefistotelis @ Original Gangsters"
__license__ = "GPL"

import sys
import re
import os
import argparse
import binascii
import configparser
import itertools
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Signature import pss
from ctypes import *
from collections import OrderedDict
from time import gmtime, strftime, strptime
from calendar import timegm
from copy import copy
from os.path import basename

# All found keys
keys = {
    # Encryption keys
    "RREK-2017-01":  bytes([ # RR Encryption Key v1; published 2017-06-27 by Freek van Tienen
        # This key is used for protecting storage of development keys, it typically encrypts a container
        # with plaintext RIEK key inside.
        # used for: WM330 FW V00.01.0000-V01.02.0499, WM220 FW V00.01.0000-V01.03.0600
        0x37, 0xD6, 0xD9, 0x13, 0xE5, 0xD0, 0x80, 0x17, 0xE5, 0x12, 0x15, 0x45, 0x0C, 0x1E, 0x16, 0xE7
    ]),
    "RIEK-2017-01":  bytes([ # R&D Image Encryption Key v1; published 2017-06-27 by Freek van Tienen
        # This key is used on many platforms, for pre-production development and engineering images;
        # it is used as pre-production version of IAEK key
        # used for: WM330 FW V00.01.0000-V01.02.0499, WM220 FW V00.01.0000-V01.03.0600
        0xF1, 0x69, 0xC0, 0xF3, 0x8B, 0x2D, 0x9A, 0xDC, 0x65, 0xEE, 0x0C, 0x57, 0x83, 0x32, 0x94, 0xE9
    ]),
    "RUEK":  bytes([ # RU Encryption Key v1; published 2017-06-27 by Freek van Tienen
        0x9C, 0xDA, 0xF6, 0x27, 0x4E, 0xCB, 0x78, 0xF3, 0xED, 0xDC, 0xE5, 0x26, 0xBC, 0xEC, 0x66, 0xF8
    ]),
    "DRAK":  bytes([ # DR Auth Key v1; published 2017-06-27 by Freek van Tienen
        0x6f, 0x70, 0x7f, 0x29, 0x62, 0x35, 0x1d, 0x75, 0xbc, 0x08, 0x9a, 0xc3, 0x4d, 0xa1, 0x19, 0xfa
    ]),
    "SAAK":  bytes([ # SDR_Auth Auth Key v1; published 2017-06-27 by Freek van Tienen
        0x6f, 0x40, 0x2f, 0xb8, 0x62, 0x52, 0x05, 0xce, 0x9b, 0xdd, 0x58, 0x02, 0x17, 0xd2, 0x18, 0xd8
    ]),
    # There are multiple PUEK keys, as DJI tried changing them as soon as they are published,
    # without fixing vulnerabilities which allowed to read them
    "PUEK-2017-07":  bytes([ # Programming Update Enc Key whitebox AES v1; published 2017-10-25 by Freek van Tienen
        # first use on 2017-07-28; used for: WM335 FW V01.00.1000-V01.00.5200,
        # WM220 FW V01.04.0000-V01.04.0500, PM420 FW V01.01.0450-V01.01.0590,
        0x63, 0xc4, 0x8e, 0x83, 0x26, 0x7e, 0xee, 0xc0, 0x3f, 0x33, 0x30, 0xad, 0xb2, 0x38, 0xdd, 0x6b
    ]),
    "PUEK-2017-01": bytes([ # Programming Update Enc Key Old Non-whitebox v1; published 2017-06-27 by Freek van Tienen
        # used for: WM330 FW V00.01.0000-V01.02.0499, WM220 FW V00.01.0000-V01.03.0600
        0x70, 0xe0, 0x03, 0x08, 0xe0, 0x4b, 0x0a, 0xe2, 0xce, 0x8e, 0x07, 0xd4, 0xd6, 0x21, 0x4b, 0xb6
    ]),
    "TRIE-2021-06":  bytes([ # TR Image Encryption key; published 2021-08-26 by OGs
        # first use on 2021-06-15; used for: WM1605 FW
        0xcb, 0x14, 0x0c, 0x12, 0x71, 0x03, 0x88, 0x34, 0xec, 0x0c, 0x0c, 0x3c, 0x2b, 0x69, 0x9d, 0xc2
    ]),
    "TRIE-2019-11":  bytes([ # TR Image Encryption key; published 2021-03-26 by Felix Domke
        # first use on 2019-11-07; used for: WM160 FW, WM161 FW
        0xf1, 0xe6, 0x30, 0x6d, 0x6c, 0x84, 0xf0, 0x9e, 0xd5, 0x59, 0x0f, 0x94, 0x73, 0xb1, 0x55, 0x26
    ]),
    "TKIE-2021-06":  bytes([ # Trusted Kernel Image Encryption key; published 2021-08-26 by OGs
        # This key is used for images within m0100 module which store kernel and device tree
        # first use on 2021-06-15; used for: WM1605 FW V01.00.0000-V01.01.0000,
        0xf8, 0xb4, 0x3c, 0x6b, 0x0d, 0xcd, 0x3f, 0x5e, 0x90, 0xfc, 0x08, 0xd4, 0xdd, 0xea, 0xf3, 0x58
    ]),
    "TKIE-2019-11":  bytes([ # Trusted Kernel Image Encryption key; published 2021-03-26 by Felix Domke
        # This key is used for images within m0100 module which store kernel and device tree
        # first use on 2019-11-07; used for:
        # WM160 FW V01.00.0200-V01.00.0500, WM161 FW V01.00.0000-V01.02.0300
        0xb6, 0x28, 0x6a, 0x05, 0xfc, 0x3a, 0x02, 0xf0, 0x36, 0x51, 0x11, 0xf0, 0x20, 0x45, 0x03, 0xa3
    ]),
    "TBIE-2021-06":  bytes([ # Trusted Boot Image Encryption key; published 2021-06-25 by OGs
        # first use on 2021-06-15; used for: WM1605 FW V01.00.0000-V01.01.0000,
        0x06, 0xdc, 0x7b, 0x70, 0x7f, 0xc1, 0xdb, 0x86, 0x49, 0x8c, 0xaa, 0xda, 0xde, 0xdf, 0x56, 0xa1
    ]),
    "TBIE-2020-04":  bytes([ # Trusted Boot Image Encryption key; published 2021-06-25 by OGs
        # first use on 2020-04-23; used for:
        # RCS231 FW V01.00.0108-V02.00.1200,
        # RC-N1-WM161B FW V04.11.0016,
        # RCJS170 FW V01.01.0000,
        # RCSS170 FW V01.01.0000,
        0x48, 0xd6, 0xe8, 0xff, 0x1b, 0x7f, 0x20, 0x6e, 0x2d, 0xa7, 0x99, 0xc2, 0x7e, 0x5a, 0xd7, 0x0d
    ]),
    "TBIE-2019-11":  bytes([ # Trusted Boot Image Encryption key; published 2021-03-26 by Felix Domke
        # first use on 2019-11-07; used for:
        # WM160 FW V01.00.0200-V01.00.0500, WM161 FW V01.00.0000-V01.02.0300
        0x54, 0xb8, 0xb9, 0xd7, 0x4c, 0x2b, 0x41, 0x46, 0x9c, 0x4d, 0xac, 0x3d, 0x16, 0xcc, 0x6f, 0x47
    ]),
    "TBIE-2018-07":  bytes([ # Trusted Boot Image Encryption key; published 2021-06-23 by fpv.wtf team
        # first use on 2018-07-13; used for:
        # WM240 FW V00.06.0000-V01.00.0670,
        # WM245 FW V01.01.0000-V01.01.0800,
        # WM246 FW V01.00.0000-V01.01.0800,
        # GL150 FW V01.00.0600, LT150 FW V01.00.0600,
        0xff, 0x94, 0x76, 0xf7, 0x8a, 0x89, 0xb9, 0x44, 0x9b, 0x6a, 0x90, 0x55, 0x64, 0x13, 0xb9, 0xc3
    ]),
    "UFIE-2021-06":  bytes([ # Update Firmware Image Encryption key; published 2021-08-26 by OGs
        # first use on 2021-06-15; used for: WM1605 FW V01.00.0000-V01.01.0000,
        0x84, 0x63, 0xf7, 0xb1, 0xa6, 0xaa, 0xa5, 0xec, 0xa3, 0x8a, 0x9a, 0xbc, 0x7b, 0x3d, 0x4b, 0xe2
    ]),
    "UFIE-2020-04":  bytes([ # UFI Encryption key; published 2021-06-20 by OGs
        # first use on 2020-04-24; used for:
        # WM170 FW V00.04.1009-V01.01.0000,
        # GL170 FW V01.01.0000,
        # WM231 FW V01.00.0113-V09.09.0902,
        # WM232 FW V02.04.1640,
        # PM430 FW, AG500 FW
        0xba, 0xb3, 0xcd, 0x72, 0x36, 0xb2, 0xe1, 0xd8, 0x66, 0x49, 0x35, 0xc9, 0xc2, 0x58, 0x8f, 0x3c
    ]),
    "UFIE-2019-11":  bytes([ # Update Firmware Image Encryption key; published 2021-03-26 by Felix Domke
        # first use on 2019-11-07; used for:
        # WM160 FW V01.00.0200-V01.00.0500, WM161 FW V01.00.0000-V01.02.0300
        0xad, 0x45, 0xcd, 0x82, 0x13, 0xfb, 0x7e, 0x25, 0x5d, 0xbe, 0x45, 0x41, 0x70, 0xbc, 0x11, 0xa0
    ]),
    "UFIE-2018-07":  bytes([ # Update Firmware Image Encryption key; published 2021-06-20 by OGs
        # first use on 2018-07-13; used for:
        # WM240 FW V00.06.0000-V01.00.0670, RC240 FW V01.00.0640, WM241 FW,
        # WM150 FW V01.01.0000, GL150 FW V01.00.0600, LT150 FW,
        0x78, 0x09, 0x39, 0xe1, 0xbe, 0x11, 0x7a, 0x66, 0xd3, 0x58, 0x41, 0xe9, 0x5b, 0x06, 0xaa, 0xc0
    ]),
    "UFIE-2018-01":  bytes([ # Update Firmware Image Encryption key; published 2021-06-19 by OGs
        # first use on 2018-01-26; used for: WM230 FW V00.02.0026-V01.00.0500,
        # RC230 FW V01.00.0000-V01.00.0200,
        0xcd, 0x3a, 0xa5, 0x72, 0x2a, 0x41, 0x0b, 0x6d, 0xba, 0x3d, 0xaf, 0x2e, 0x99, 0xf3, 0xd9, 0x6d
    ]),
    "SLEK":  bytes([ # Slack community Encryption Key; generated 2018-01-19 by Jan Dumon
        0x56, 0x79, 0x6C, 0x0E, 0xEE, 0x0F, 0x38, 0x05, 0x20, 0xE0, 0xBE, 0x70, 0xF2, 0x77, 0xD9, 0x0B
    ]),

    # RSA authentication keys
    "PRAK-2019-09":  bytes.fromhex(( # Provisioning RSA Auth Key v3; published 2021-04-02 by Felix Domke
        # first use on 2020-06-09; used for: WM161 FW V01.00.0000
        "40000000a1f987bf9fd539732277b64b32f178d7a62106d20336f2888292ee28"
        "3790524565232831d245919a3a88d92a754cafbb1b8ccaed67dec3a29e0f425b"
        "28cda10838a170227343eec744f78f3b5d19e9823a08fe6ee539fa7c0538e498"
        "5e5d7a281f6854a2f511541649f190defcc3c7cf614a45c798076306c0f5ae34"
        "d9f54da1adfc8d1585e47d4ba363b8289e48c8337fc4e9e1749d84a86ca5139b"
        "552a89657a4844d2b8c497989608746a95252479dd468298671e6c42dfbf5828"
        "bde4f669b9553ee86e5189df3f3bc86ef7277bffc71cb824fd705e86296a671f"
        "959ed1add22a1ad22818fdfbf3cc4ffc1547f29da481c9472805896456aeac5f"
        "eaf6113e34ec07b8a297b1278aaf546a24ecc42479b6284eebc7b6450bc0c979"
        "b0ed4a5d13dd035a4464125c838a8f0b34c53978dbc4e7280b6bc41d5f4f3d86"
        "8f585fc161113460de573421469fdfd112e1890dd2aae587c3204022f2fbeda4"
        "1dc324a125ae15adc5c14ff2c39d98e7e3b114d4c75474437732dde3cbdb7b02"
        "20320a9fd46e2284d2dadf2b53b10cf1644bb470cdab38863601e80566960679"
        "a4c4402454b3d7d97f6ee15bf7caea26f36888150485d38e598e21ac2e164e1b"
        "5d27e62d254ffa520e6cc0ff61a7ac756f597a82474881578ffa47b8ce579d22"
        "ce0b43a199f27a59f8a80b7cb9c0f9c3cf168f9095b5f5d862f2e174e30ed61e"
        "4992e6594045d58001000100"
    )),
    "PRAK-2018-01":  bytes.fromhex(( # Provisioning RSA Auth Key v2; published 2021-04-02 by Mefistotelis
        # first use on 2018-01-26; used for: WM230 FW V00.02.0032,
        # WM150 FW V01.00.0100, GL150 V01.00.0100-V01.00.0600,
        # LT150 V01.00.0600
        "40000000dbe15b5badcde418e2dbd9e253d2b9aded7f187824b5677f0ee6a6c3"
        "fcd2ea329421a5b0252c63af6df81ac0c6416ec926e2558f4f4460a4b3af3ecb"
        "7fd4db4741c3602b900c495acff5f8651da895f4a60030b3be640f8382222793"
        "a17c510a34a25f7ddb371a45f6bfce5b74e1d1fc63213e13190b515cde9066de"
        "4253ced7bf8ff9d10bf63235d8717eda922e17e60cc61d652a05d84f0c04e61b"
        "8b2098275c1bc4a571b7fc957dd6da62696b64ac0c2060566df583df5838bd4a"
        "bb1acc762f53f23efbda511e38d47e212e875bbddc183b479d0322cb9d604399"
        "f88c72a95365af728e783d1721750d8774b1752d65be4d2c4d2aa4c1e94f10c2"
        "98890cf780c322c93a57b3e94512de8fdb48e0c0eeeb1bb0f2aa47a322471f19"
        "41f1ba93daceac32d28134e7697c9913db1dbb9c021f7a72d6f361c235cca6d8"
        "e6551300256958bc1ae469d6560acdcbf396b2a3de5b9c9c3098650795274119"
        "23dc5eaa4e07882bf44deb8148cf0166999fae7d3dbb44a48e7d60405f8fc5c8"
        "a16ffc979007dcbf6a8438b3e91d57602bffe994138bb34c8a0363fcb873556f"
        "bbd17ffda86650c7dc4d7dc567a3c97ac1c3bdd6e803761352e2722e0da477c0"
        "41782ef66cec1d8277ee0bc8e868b8a243b1ddee4409880d7e02ede5f1247d52"
        "1820917aba93369e96f326c65fba2370ffc9db17aa3aefa062cc45e93e81d9cb"
        "36748cd95224988901000100"
    )),
    "PRAK-2017-01":  bytes([ # Provisioning RSA Auth Key v1; published 2017-06-27 by Freek van Tienen
        # used for: WM335 FW V01.00.1000-V01.00.5200,
        # WM220 FW V01.04.0000-V01.04.0500, PM420 FW V01.01.0450-V01.01.0590,
        # WM100 FW V01.00.0000-V01.00.1000, WM620 FW V01.00.0000-V01.02.0500,
        0x40, 0x00, 0x00, 0x00, 0xC3, 0x15, 0x16, 0x41, 0x15, 0x7D, 0x30, 0x44, 0x8F, 0xEE, 0x89, 0x58, 0xD6, 0x84, 0x33, 0x2E, 0x8B, 0x28, 0x21, 0x3C, 0xDB, 0x05, 0xC9, 0x23, 0xE0, 0x6A, 0xFE, 0x2D, 0x13, 0x37, 0x1B, 0x48, 0x87, 0xC2, 0x87, 0x2F, 0x7F, 0xD6, 0x74, 0x49, 0x0E, 0x25, 0x00, 0x17, 0x18, 0x3A, 0x9F, 0xCF, 0xB4, 0x10, 0x9F, 0xDD, 0xD8, 0x6A, 0x55, 0x5F, 0xC8, 0x74, 0xB0, 0x8D,
        0x64, 0x19, 0xC4, 0xB7, 0xFA, 0x7E, 0x03, 0xB8, 0xF1, 0x06, 0xA0, 0x8F, 0x57, 0x1E, 0x8C, 0x26, 0xA5, 0x32, 0xFC, 0x23, 0xE1, 0xDD, 0x0D, 0x7F, 0xE4, 0xD4, 0x96, 0x52, 0x3B, 0x08, 0xBC, 0x50, 0xD9, 0x23, 0x8A, 0x6B, 0xAA, 0xB5, 0x7D, 0x37, 0xA1, 0x3F, 0x3A, 0xFD, 0x91, 0x28, 0x4C, 0x8B, 0x98, 0xE2, 0xB4, 0x5E, 0xCB, 0x87, 0xBD, 0xCB, 0xE6, 0x91, 0xD8, 0x76, 0x4F, 0x90, 0x77, 0x29,
        0x0B, 0x23, 0x6C, 0x0D, 0x8D, 0xF4, 0xB2, 0xEB, 0x3B, 0xA2, 0xF3, 0x66, 0x71, 0x96, 0x7A, 0xEE, 0xFB, 0x4E, 0xC2, 0x63, 0xC9, 0xE4, 0xD7, 0x50, 0x06, 0xD9, 0x7F, 0x60, 0xA5, 0xEB, 0x88, 0x48, 0x4B, 0x42, 0x70, 0x7D, 0x0A, 0x28, 0xB9, 0xA1, 0x16, 0x52, 0x6A, 0xCF, 0x8B, 0xC9, 0x8E, 0x7E, 0x97, 0xAA, 0xA0, 0x9A, 0xA5, 0xE2, 0xC8, 0xB6, 0xAA, 0xAB, 0x7A, 0x2C, 0x21, 0x28, 0x3C, 0x73,
        0xD6, 0x68, 0xEC, 0xD7, 0xF0, 0x24, 0xB8, 0xEB, 0xBA, 0xF2, 0x78, 0xA5, 0x87, 0xB6, 0xA0, 0x64, 0x52, 0x5D, 0x07, 0x03, 0xC5, 0xB6, 0x2E, 0x8D, 0xF7, 0xB6, 0x56, 0x59, 0x13, 0xCB, 0x87, 0xFF, 0xB9, 0x6E, 0xE5, 0x78, 0xD8, 0xA5, 0x32, 0x9C, 0x93, 0x83, 0x1C, 0xC1, 0x85, 0x71, 0x04, 0xA4, 0xF2, 0xBA, 0x9D, 0x5B, 0x00, 0x55, 0xA5, 0x03, 0x05, 0xC4, 0x6F, 0x46, 0x9A, 0xD4, 0x64, 0x1A,
        0x1F, 0xA9, 0x8F, 0x94, 0x92, 0xBD, 0xFD, 0x94, 0xE0, 0x94, 0xCB, 0xFC, 0xD9, 0x5A, 0xB0, 0x4B, 0xD7, 0xF3, 0x40, 0x00, 0x10, 0xDE, 0xED, 0x20, 0xCF, 0xCD, 0x36, 0x1D, 0xDB, 0x2F, 0x5F, 0xDA, 0x87, 0xAD, 0xA7, 0x28, 0x5A, 0xFB, 0x9C, 0xD7, 0x52, 0x19, 0x53, 0xDA, 0xDB, 0x73, 0xB2, 0x88, 0xED, 0xFB, 0x00, 0xEC, 0xDD, 0x76, 0x9E, 0x78, 0xD2, 0xCA, 0x42, 0x94, 0x64, 0x65, 0x90, 0xC1,
        0x8D, 0x59, 0x54, 0xB8, 0x46, 0xD0, 0x0B, 0xFD, 0x68, 0x2E, 0x30, 0xF9, 0x70, 0xE1, 0x0D, 0x1F, 0xE9, 0x60, 0xE7, 0x24, 0x02, 0x3A, 0x05, 0x47, 0x4E, 0xA6, 0x8C, 0xD9, 0x73, 0x8D, 0x58, 0x2F, 0xCB, 0x39, 0x18, 0x56, 0x3A, 0xC8, 0x5B, 0xA6, 0x41, 0x79, 0x64, 0xFF, 0xFA, 0xF1, 0x71, 0x0A, 0x3D, 0x2F, 0x5D, 0x87, 0x0B, 0x50, 0x24, 0x76, 0x48, 0x12, 0xC2, 0xAB, 0x6F, 0xF2, 0x4C, 0xF8,
        0x0E, 0xE6, 0xD2, 0x20, 0xC7, 0x16, 0xA3, 0x37, 0xA4, 0xBC, 0xD9, 0xC9, 0x04, 0xE1, 0x7B, 0x5E, 0x9F, 0x22, 0x6E, 0xF6, 0x99, 0x4A, 0x35, 0x06, 0x35, 0xEE, 0x8C, 0x7A, 0x6F, 0x13, 0xD8, 0x20, 0xF9, 0xB8, 0x7C, 0x1E, 0xF8, 0xBA, 0x20, 0x6E, 0x78, 0x56, 0xE1, 0x7E, 0x1D, 0x9A, 0x7E, 0xD6, 0xB7, 0xB2, 0x3C, 0x7C, 0x14, 0x00, 0x9D, 0x96, 0x22, 0xA7, 0x75, 0xDE, 0x57, 0x5F, 0xDC, 0x1D,
        0xD1, 0x9E, 0x57, 0xDF, 0x90, 0xC6, 0x5C, 0x81, 0xA8, 0x0C, 0xB0, 0x5F, 0xA7, 0x31, 0x80, 0x80, 0xA6, 0x1D, 0xFF, 0x9B, 0x0D, 0x85, 0x22, 0x67, 0xD6, 0xE8, 0xC6, 0xFD, 0x53, 0x1E, 0x27, 0x87, 0xBA, 0xB7, 0xFF, 0x29, 0x81, 0x8A, 0x38, 0xF2, 0xE6, 0xC2, 0xB4, 0x16, 0x98, 0xF1, 0x1C, 0x3B, 0x2A, 0x0C, 0x4A, 0xC6, 0x6A, 0x96, 0x6A, 0x42, 0xCE, 0x3B, 0xCE, 0x7C, 0x8D, 0x5F, 0x1E, 0xCC,
        0x95, 0x43, 0xFF, 0x55, 0xF3, 0x09, 0xDF, 0x3B, 0x01, 0x00, 0x01, 0x00,
    ]),
    "RRAK":  bytes([ # R RSA Auth Key v1; published 2017-06-27 by Freek van Tienen
        0x40, 0x00, 0x00, 0x00, 0x0F, 0x63, 0x6A, 0x50, 0x11, 0xD4, 0xA9, 0x36, 0xEB, 0x03, 0x47, 0xA6, 0xC5, 0xBF, 0xDE, 0x36, 0x64, 0xF7, 0x9B, 0xB8, 0xA5, 0x98, 0x50, 0xDA, 0x53, 0xB4, 0x11, 0xBA, 0x24, 0x4C, 0xDB, 0x21, 0xD2, 0x3D, 0xB4, 0x98, 0xF5, 0x60, 0xAC, 0xDE, 0xB8, 0x14, 0x3B, 0xED, 0x38, 0x6B, 0x52, 0xF7, 0x8A, 0xA7, 0xB5, 0xF3, 0x84, 0xDA, 0x5C, 0xF2, 0x33, 0xAD, 0x2A, 0xE4,
        0x6B, 0xA4, 0xC9, 0xF2, 0xBA, 0x5B, 0x34, 0x8E, 0xA1, 0xB9, 0xB9, 0x3E, 0x38, 0x0E, 0x6E, 0x03, 0xC6, 0x27, 0xBE, 0x7E, 0xA5, 0xE1, 0x1E, 0x5B, 0x25, 0x7D, 0x15, 0x43, 0x7A, 0x15, 0xD4, 0x1E, 0xC3, 0x9A, 0x74, 0xFB, 0xAB, 0x06, 0x41, 0x2B, 0x8F, 0x87, 0x99, 0x1D, 0x4F, 0x16, 0x8D, 0x8F, 0x29, 0x2C, 0x25, 0x3A, 0x3E, 0x5C, 0x97, 0x30, 0x4D, 0x62, 0x5B, 0xE3, 0x5D, 0xFD, 0x8A, 0x14,
        0x79, 0xE7, 0xDE, 0xA4, 0x0B, 0x46, 0xE4, 0xC3, 0x70, 0xDF, 0x36, 0x5A, 0x25, 0xEA, 0x15, 0x9C, 0x71, 0x90, 0xD9, 0x89, 0xC9, 0x90, 0xAB, 0xB8, 0x66, 0x91, 0xC8, 0x14, 0xEE, 0xD2, 0xD4, 0x5C, 0xD9, 0xED, 0x2F, 0x4E, 0x69, 0x38, 0x3A, 0xB7, 0xA0, 0x54, 0xCC, 0xDE, 0x6A, 0x78, 0x45, 0xBC, 0xD7, 0xA3, 0x86, 0xB1, 0xCF, 0x3D, 0x8C, 0xDB, 0xF7, 0xCE, 0x86, 0x98, 0x9B, 0x30, 0xB1, 0x1F,
        0x2D, 0x38, 0x24, 0x35, 0x52, 0x8C, 0xC7, 0xD3, 0xE5, 0x29, 0x3E, 0x2A, 0xFE, 0xAC, 0xD9, 0x10, 0xBC, 0x59, 0x3B, 0x3A, 0xAB, 0x2B, 0xAA, 0xBF, 0x87, 0x80, 0x8B, 0x81, 0xC9, 0x34, 0xF8, 0x77, 0x08, 0x55, 0x7E, 0x37, 0x10, 0xE2, 0x67, 0x40, 0x13, 0xD5, 0xEB, 0x59, 0x0C, 0x83, 0xF4, 0x62, 0x85, 0x80, 0xD2, 0x71, 0x14, 0xD1, 0xB6, 0x1C, 0x5E, 0x6E, 0x6A, 0x33, 0x53, 0x89, 0xD4, 0x56,
        0xE2, 0x47, 0xF4, 0xB8, 0x1A, 0x86, 0x58, 0xD0, 0xA5, 0xDC, 0xF2, 0x3A, 0xC8, 0xBD, 0x86, 0x7A, 0x1F, 0x25, 0x29, 0x71, 0x54, 0xAB, 0xF0, 0x6C, 0xE9, 0x95, 0x4B, 0x4D, 0xB5, 0xBF, 0xC0, 0x63, 0x04, 0x73, 0xD9, 0x85, 0xF5, 0x05, 0x9C, 0xD9, 0x09, 0x51, 0x6A, 0xD6, 0x89, 0x77, 0x39, 0xF3, 0x61, 0x1F, 0xEC, 0xE7, 0xA6, 0xC2, 0xDD, 0xCE, 0x9C, 0x8F, 0x41, 0x86, 0x14, 0xFF, 0x2C, 0x64,
        0x11, 0x43, 0xE6, 0xE2, 0x38, 0xAE, 0x15, 0xE9, 0x53, 0xB0, 0x81, 0xD3, 0x1A, 0x35, 0xB9, 0x85, 0x52, 0x1D, 0x3E, 0x96, 0x51, 0xD7, 0xB3, 0x72, 0x2D, 0xCC, 0xFB, 0x04, 0x78, 0xDC, 0xDA, 0x36, 0x93, 0xA7, 0xB8, 0xBE, 0x0D, 0x69, 0x75, 0x75, 0x91, 0x41, 0x51, 0x88, 0xC1, 0x2A, 0x1D, 0xD9, 0x9C, 0x53, 0xC7, 0x1A, 0xFA, 0x75, 0x25, 0x94, 0xB5, 0xED, 0xB3, 0xC5, 0xCC, 0x64, 0xBD, 0x6F,
        0x4D, 0xAF, 0x68, 0x1A, 0xFE, 0x17, 0xD4, 0xC1, 0xC4, 0x8C, 0x82, 0xEF, 0x5B, 0x1C, 0x71, 0x06, 0x97, 0x25, 0x03, 0xE9, 0xDE, 0xF3, 0xFE, 0x93, 0xF2, 0xDF, 0x77, 0xBE, 0xC5, 0xB5, 0x80, 0xA6, 0x19, 0xFF, 0x16, 0xB5, 0x36, 0x09, 0xC3, 0xE0, 0xFC, 0x74, 0x71, 0x9D, 0xB7, 0x60, 0x4D, 0x3D, 0x57, 0x66, 0xB1, 0x4A, 0x08, 0xBE, 0x33, 0x54, 0x3C, 0x86, 0xE2, 0x19, 0xDD, 0x09, 0x83, 0x2E,
        0xEB, 0xEB, 0x4B, 0x8A, 0x13, 0xF7, 0x8F, 0xE3, 0x4A, 0x1C, 0x51, 0x22, 0x29, 0x35, 0xCC, 0x4B, 0xCF, 0x05, 0x71, 0x7A, 0x36, 0x62, 0x1B, 0x43, 0x21, 0x74, 0xC7, 0x09, 0x77, 0xF7, 0x18, 0x8A, 0xCB, 0x2E, 0x37, 0x3D, 0xCD, 0xFF, 0xCC, 0x71, 0x90, 0x19, 0xFD, 0x14, 0x8E, 0xF2, 0x63, 0xFC, 0x21, 0x72, 0xD1, 0x00, 0x2B, 0x80, 0x0C, 0xC5, 0xC2, 0x39, 0x52, 0x24, 0xEF, 0x23, 0xBA, 0xF4,
        0x4A, 0xD5, 0x1B, 0xD6, 0x47, 0x40, 0x71, 0xAB, 0x01, 0x00, 0x01, 0x00,
    ]),
    "GFAK":  bytes([ # Geofence Auth Key v1; published 2017-06-27 by Freek van Tienen
        0x40, 0x00, 0x00, 0x00, 0x9B, 0x57, 0xA8, 0x88, 0x6D, 0xC9, 0x3E, 0x04, 0x1E, 0x14, 0x80, 0x8E, 0x38, 0xD8, 0x10, 0x37, 0x6D, 0x97, 0x69, 0x48, 0xE8, 0x78, 0x4B, 0x4A, 0xC0, 0x46, 0x48, 0x81, 0xFC, 0xC3, 0xAB, 0x99, 0xC6, 0x12, 0x75, 0x39, 0x1E, 0xC9, 0x63, 0xEB, 0xD5, 0x8E, 0x3D, 0x6A, 0x4E, 0xC4, 0x60, 0xFC, 0x1A, 0xE1, 0xDB, 0x27, 0x0D, 0x9C, 0xF8, 0x70, 0xFC, 0x87, 0x9E, 0x63,
        0x3B, 0x71, 0x99, 0xE6, 0xA2, 0xF4, 0x87, 0x2E, 0xFA, 0xFC, 0x1D, 0xF2, 0x73, 0x74, 0xB3, 0x02, 0x19, 0x35, 0x3F, 0x21, 0xD8, 0x97, 0x2E, 0x75, 0xFE, 0xB5, 0x04, 0x0A, 0x50, 0xB2, 0x48, 0x2F, 0x25, 0x65, 0x91, 0xDF, 0x63, 0xC6, 0xAA, 0x56, 0xA6, 0x33, 0x06, 0xB2, 0x96, 0xCE, 0x11, 0x8F, 0xB4, 0x3A, 0x2E, 0x15, 0x92, 0xA3, 0x5A, 0x45, 0x79, 0x04, 0x49, 0x13, 0xA4, 0x7F, 0xA1, 0xC6,
        0x84, 0x3F, 0xFA, 0x05, 0x7F, 0xB4, 0x1B, 0x7D, 0x09, 0xE4, 0xA9, 0x5D, 0x21, 0x8A, 0xBC, 0x39, 0xC6, 0x6C, 0xE2, 0x96, 0x86, 0x25, 0xE8, 0xA8, 0x42, 0x65, 0xFE, 0xF9, 0x51, 0xBA, 0xB8, 0xAA, 0x23, 0xB2, 0x85, 0x9F, 0xDF, 0xFC, 0x26, 0x42, 0x6A, 0xCE, 0x8D, 0xC9, 0x3F, 0xDD, 0x4C, 0x63, 0x84, 0xF5, 0x68, 0x74, 0x40, 0xDD, 0x3B, 0xC8, 0xC7, 0x18, 0x9E, 0xD6, 0xD4, 0x63, 0xA9, 0xB5,
        0x46, 0x8F, 0x4D, 0x70, 0xD5, 0x4D, 0xFD, 0x76, 0xE6, 0x80, 0xAD, 0xC8, 0xFF, 0x84, 0xC3, 0x94, 0x41, 0x6E, 0x7D, 0x1F, 0x3A, 0x23, 0x78, 0xF9, 0x93, 0xEF, 0xC4, 0x8A, 0x29, 0x99, 0x5A, 0xCD, 0x17, 0x58, 0x30, 0x06, 0x74, 0xA2, 0x70, 0xC3, 0x0C, 0xEA, 0xCC, 0x1D, 0xF6, 0x8A, 0x3F, 0x52, 0xCA, 0x67, 0x12, 0xE8, 0xEA, 0xBA, 0xCF, 0x44, 0xF1, 0x05, 0x19, 0xB9, 0xE3, 0x20, 0x31, 0x90,
        0xC4, 0xE8, 0xE8, 0xA9, 0xBF, 0x87, 0xF1, 0xC9, 0x49, 0x28, 0x38, 0xF0, 0xE7, 0xA4, 0x2C, 0x66, 0x51, 0x73, 0x14, 0x4D, 0x03, 0xD4, 0x75, 0xF1, 0xD9, 0x47, 0x94, 0x93, 0x7B, 0xB2, 0xDA, 0x80, 0x97, 0xB6, 0xCE, 0xD0, 0xF9, 0xD3, 0x70, 0xAA, 0x57, 0x8A, 0xA9, 0x2C, 0x29, 0x7A, 0x19, 0xCD, 0x5A, 0x08, 0x54, 0xE9, 0x7C, 0xF5, 0xA9, 0xD3, 0x5F, 0x66, 0x45, 0x81, 0x9A, 0x16, 0x07, 0x18,
        0xF6, 0xC2, 0x07, 0x02, 0xD3, 0x5D, 0x42, 0x40, 0xAE, 0x9B, 0x0D, 0x24, 0x84, 0x06, 0x59, 0x73, 0x89, 0x0E, 0xDD, 0xB4, 0xA8, 0xB4, 0xBE, 0x19, 0xA8, 0xCD, 0xD7, 0xCC, 0x52, 0x55, 0x71, 0x07, 0xA6, 0x5D, 0x2F, 0xC1, 0xBF, 0xE3, 0xC8, 0x7A, 0x16, 0x5D, 0x68, 0xAD, 0x2F, 0x59, 0x01, 0x39, 0x01, 0x41, 0xC0, 0xFB, 0xF1, 0xAE, 0xF7, 0xB2, 0xA8, 0x9E, 0xDD, 0x75, 0x07, 0x57, 0x9B, 0x64,
        0x83, 0x87, 0xB9, 0x4E, 0xBA, 0xE2, 0xF1, 0x5C, 0x96, 0xFE, 0x1E, 0x5E, 0xCF, 0xF8, 0xCC, 0x85, 0xCE, 0x73, 0xA6, 0xF6, 0x7C, 0xD7, 0x26, 0x0B, 0xC7, 0x38, 0x98, 0x07, 0xEC, 0xBA, 0xED, 0xBA, 0x05, 0x93, 0x16, 0x8A, 0x03, 0xEE, 0xBB, 0x48, 0x05, 0xFC, 0xC2, 0xB5, 0xB7, 0x2B, 0x16, 0xE3, 0xFD, 0x8E, 0x97, 0x62, 0xFC, 0x7B, 0xE1, 0x0B, 0x74, 0x85, 0xD9, 0x8D, 0x09, 0x86, 0xA8, 0x13,
        0xD7, 0x77, 0xFE, 0xA8, 0x08, 0x24, 0x6D, 0x7E, 0x1A, 0x2A, 0x59, 0x87, 0x17, 0xDD, 0xDD, 0xC2, 0x51, 0x01, 0x3D, 0x68, 0x78, 0x5E, 0x30, 0x8E, 0x36, 0xD4, 0x62, 0x13, 0x9F, 0xD3, 0xA0, 0x6A, 0xD0, 0xC7, 0x49, 0x3B, 0x1A, 0x1A, 0x95, 0x82, 0xDE, 0xD7, 0x96, 0x55, 0x88, 0xFD, 0x39, 0x55, 0x56, 0xEA, 0x91, 0x13, 0xA8, 0x14, 0x7C, 0x47, 0xED, 0xAF, 0xE4, 0x5A, 0x30, 0xA8, 0xB7, 0xDA,
        0xCE, 0x0D, 0xED, 0x9E, 0x47, 0x32, 0x93, 0x80, 0x01, 0x00, 0x01, 0x00,
    ]),
    "SLAK": # Slack community Auth Key; generated 2018-01-19 by Jan Dumon
"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7AF5tZo4gtcUG
n//Vmk8XnDn2LadzEjZhTbs9h0X674aBqsri+EXPU+oBvpNvoyeisfX0Sckcg2xI
D6CUQJeUD4PijT9tyhis2PRU40xEK7snEecAK25PMo12eHtFYZN8eZVeySmnlNyU
bytlUrXEfRXXKzYq+cHVlOS2IQo2OXptWB4Ovd05C4fgi4DFblIBVjE/HzW6WJCP
IDf53bnzxXW0ZTH2QGdnQVe0uYT5Bvjp8IU3HRSy1pLZ35u9f+kVLnLpRRhlHOmt
xipIl1kxSGGkBkJJB76HdtcoOJC/O95Fl/qxSKzHjlg7Ku/gcUxmMZfvBi6Qih78
krJW0A+zAgMBAAECggEBALYZbtqj8qWBvGJuLkiIYprARGUpIhXZV2E7u6j38Lqi
w13Dvpx1Xi2+LnMSbSpaO/+fwr3nmFMO28P0i8+ycqj4ztov5+N22L6A6rU7Popn
93DdaxBsOpgex0jlnEz87w1YrI9H3ytUt9RHyX96ooy7rigA6VfCLPJacrm0xOf1
OIoJeMnGTeMSQlAFR+JzU5qdHHTcWi1WFNekzBgmxIXp6zZUkep/9+mxD7V8kGT2
MsJ/6IICe4euHA9lCpctYOPEs48yZBDljQfKD5FxVMUWBbXOhoCff99HeuW/4uVj
AO2mFp293nnGIV0Ya5PyDtGd+w/n8kcehFcfbfTvzZkCgYEA4woDn+WBXCdAfxzP
yUnMXEHB6189R9FTzoDwv7q3K48gH7ptJo9gq0+eycrMjlIGRiIkgyuukXD4FHvk
kkYoQ51Xgvo6eTpADu1CffwvyTi/WBuaYqIBH/HMUvFOLZu/jmSEsusXMTDmZxb+
Wpox17h1qMtNlyIqOBLyHcmTsy8CgYEA0trrk6kwmZC2IjMLswX9uSc5t3CYuN6V
g8OsES/68jmJxPYZTj0UidXms5P+V1LauFZelBcLaQjUSSmh1S95qYwM5ooi5bjJ
HnVH/aaIJlKH2MBqMAkBx6EtXqzo/yqyyfEZvt8naM8OnqrKrvxUCfdVx0yf7M7v
wECxxcgOGr0CgYBo198En781BwtJp8xsb5/nmpYqUzjBSXEiE3kZkOe1Pcrf2/87
p0pE0efJ19TOhCJRkMK7sBhVIY3uJ6hNxAgj8SzQVy1ZfgTG39msxCBtE7+IuHZ6
xcUvM0Hfq38moJ286747wURcevBq+rtKq5oIvC3ZXMjf2e8VJeqYxtVmEQKBgAhf
75lmz+pZiBJlqqJKq6AuAanajAZTuOaJ4AyytinmxSUQjULBRE6RM1+QkjqPrOZD
b/A71hUu55ecUrQv9YoZaO3DMM2lAD/4coqNkbzL7F9cjRspUGvIaA/pmDuCS6Wf
sOEW5e7QwojkybYXiZL3wu1uiq+SLI2bRDRR1NWVAoGANAp7zUGZXc1TppEAXhdx
jlzAas7J21vSgjyyY0lM3wHLwXlQLjzl3PgIAcHEyFGH1Vo0w9d1dPRSz81VSlBJ
vzP8A7eBQVSGj/N5GXvARxUswtD0vQrJ3Ys0bDSVoiG4uLoEFihIN0y5Ln+6LZJQ
RwjPBAdCSsU/99luMlK77z0=
-----END PRIVATE KEY-----""",
}

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

class PlainCopyCipher:
    def encrypt(self, plaintext):
        return plaintext
    def decrypt(self, ciphertext):
        return ciphertext

class ImgPkgHeader(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('magic', c_char * 4),              #0 'IM*H'
                ('header_version', c_uint),         #4
                ('size', c_uint),                   #8
                ('reserved', c_ubyte * 4),          #12
                ('header_size', c_uint),            #16 Length of this header and following chunk headers
                ('signature_size', c_uint),         #20 Length of RSA signature located after chunk headers
                ('payload_size', c_uint),           #24 Length of the area after signature which contains data of all chunks
                ('target_size', c_uint),            #28
                ('os', c_ubyte),                    #32
                ('arch', c_ubyte),                  #33
                ('compression', c_ubyte),           #34
                ('anti_version', c_ubyte),          #35
                ('auth_alg', c_uint),               #36
                ('auth_key', c_char * 4),           #40 Auth key identifier
                ('enc_key', c_char * 4),            #44 Encryption key identifier
                ('scram_key', c_ubyte * 16),        #48 Encrypted Scramble key; used in versions > 0
                ('name', c_char * 32),              #64 Target Module name
                ('type', c_char * 4),               #96 Target Module type identifier; used in versions > 1
                ('version', c_uint),                #100
                ('date', c_uint),                   #104
                ('encr_cksum', c_uint),             #108 Checksum of encrypted data; used in versions > 1
                ('reserved2', c_ubyte * 16),        #112
                ('userdata', c_char * 16),          #128
                ('entry', c_ubyte * 8),             #144
                ('plain_cksum', c_uint),            #152 Checksum of decrypted (plaintext) data; used in versions > 1
                ('chunk_num', c_uint),              #156 Amount of chunks
                ('payload_digest', c_ubyte * 32),   #160 SHA256 of the payload
               ]                                    #192 is the end; chunk headers start after that

    def get_format_version(self):
        if self.magic != bytes("IM*H", "utf-8"):
            return 0
        if self.header_version == 0x0000:
            return 2016
        elif self.header_version == 0x0001:
            return 2017
        elif self.header_version == 0x0002:
            return 2018
        else:
            return 0

    def set_format_version(self, ver):
        if ver == 2016:
            self.magic = bytes("IM*H", "utf-8")
            self.header_version = 0x0000
        elif ver == 2017:
            self.magic = bytes("IM*H", "utf-8")
            self.header_version = 0x0001
        elif ver == 2018:
            self.magic = bytes("IM*H", "utf-8")
            self.header_version = 0x0002
        else:
            raise ValueError("Unsupported image format version.")

    def update_payload_size(self, payload_size):
        self.payload_size = payload_size
        self.target_size = self.header_size + self.signature_size + self.payload_size
        self.size = self.target_size

    def dict_export(self):
        d = OrderedDict()
        for (varkey, vartype) in self._fields_:
            if varkey.startswith('unk'):
                continue
            v = getattr(self, varkey)
            if isinstance(v, Array) and v._type_ == c_ubyte:
                d[varkey] = bytes(v)
            else:
                d[varkey] = v
        varkey = 'name'
        d[varkey] = d[varkey].decode("utf-8")
        varkey = 'auth_key'
        d[varkey] = d[varkey].decode("utf-8")
        varkey = 'enc_key'
        d[varkey] = d[varkey].decode("utf-8")
        varkey = 'type'
        d[varkey] = d[varkey].decode("utf-8")
        return d

    def ini_export(self, fp):
        d = self.dict_export()
        fp.write("# DJI Firmware Signer main header file.\n")
        fp.write(strftime("# Generated on %Y-%m-%d %H:%M:%S\n", gmtime()))
        varkey = 'name'
        fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
        varkey = 'pkg_format'
        fp.write("{:s}={:d}\n".format(varkey,self.get_format_version()))
        varkey = 'version'
        fp.write("{:s}={:02d}.{:02d}.{:02d}.{:02d}\n".format(varkey, (d[varkey]>>24)&255, (d[varkey]>>16)&255, (d[varkey]>>8)&255, (d[varkey])&255))
        varkey = 'anti_version'
        fp.write("{:s}={:02d}.{:02d}.{:02d}.{:02d}\n".format(varkey, (d[varkey]>>24)&255, (d[varkey]>>16)&255, (d[varkey]>>8)&255, (d[varkey])&255))
        varkey = 'date'
        fp.write("{:s}={:s}\n".format(varkey,strftime("%Y-%m-%d",strptime("{:x}".format(d[varkey]), '%Y%m%d'))))
        varkey = 'enc_key'
        fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
        varkey = 'auth_alg'
        fp.write("{:s}={:d}\n".format(varkey,d[varkey]))
        varkey = 'auth_key'
        fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
        varkey = 'os'
        fp.write("{:s}={:d}\n".format(varkey,d[varkey]))
        varkey = 'arch'
        fp.write("{:s}={:d}\n".format(varkey,d[varkey]))
        varkey = 'compression'
        fp.write("{:s}={:d}\n".format(varkey,d[varkey]))
        varkey = 'type'
        fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
        varkey = 'userdata'
        fp.write("{:s}={:s}\n".format(varkey,d[varkey].decode("utf-8"))) # not sure if string or binary
        varkey = 'entry'
        fp.write("{:s}={:s}\n".format(varkey,''.join("{:02X}".format(x) for x in d[varkey])))
        #varkey = 'scram_key' # we will add the key later, as this one is encrypted
        #fp.write("{:s}={:s}\n".format(varkey,"".join("{:02X}".format(x) for x in d[varkey])))

    def __repr__(self):
        d = self.dict_export()
        from pprint import pformat
        return pformat(d, indent=0, width=160)


class ImgChunkHeader(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('id', c_char * 4),          #0
                ('offset', c_uint),          #4
                ('size', c_uint),            #8
                ('attrib', c_uint),          #12
                ('address', c_ulonglong),    #16
                ('reserved', c_ubyte * 8),   #24
               ]                             #32 is the end

    def dict_export(self):
        d = OrderedDict()
        for (varkey, vartype) in self._fields_:
            if varkey.startswith('unk'):
                continue
            v = getattr(self, varkey)
            if isinstance(v, Array) and v._type_ == c_ubyte:
                d[varkey] = bytes(v)
            else:
                d[varkey] = v
        varkey = 'id'
        d[varkey] = d[varkey].decode("utf-8")
        return d

    def ini_export(self, fp):
        d = self.dict_export()
        fp.write("# DJI Firmware Signer chunk header file.\n")
        fp.write(strftime("# Generated on %Y-%m-%d %H:%M:%S\n", gmtime()))
        varkey = 'id'
        fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
        varkey = 'attrib'
        fp.write("{:s}={:04X}\n".format(varkey,d[varkey]))
        #varkey = 'offset'
        #fp.write("{:s}={:04X}\n".format(varkey,d[varkey]))
        varkey = 'address'
        fp.write("{:s}={:08X}\n".format(varkey,d[varkey]))

    def __repr__(self):
        d = self.dict_export()
        from pprint import pformat
        return pformat(d, indent=0, width=160)


class ImgRSAPublicKey(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('len', c_int),      # 0: Length of n[] in number of uint32_t
                ('n0inv', c_uint),   # 4: -1 / n[0] mod 2^32
                ('n', c_uint * 64),  # 8: modulus as little endian array
                ('rr', c_uint * 64), # 264: R^2 as little endian array
                ('exponent', c_int)] # 520: 3 or 65537


def raise_or_warn(po, ex):
    """ Raise exception, unless force-continue parameter was used.
    """
    if (po.force_continue):
        eprint("{:s}: Warning: {:s} Continuing anyway.".format(po.sigfile,str(ex)))
    else:
        raise ex


def combine_int_array(int_arr, bits_per_entry):
    """ Makes one big numer out of an array of numbers.

    Allows to make pythonic big number out of little endian number stored in parts
    as a list.
    """
    ans = 0
    for i, val in enumerate(int_arr):
        ans += (val << i*bits_per_entry)
    return ans


def get_key_data(po, pkghead, enc_k_fourcc):
    """ Returns encryption/authentication key array for given FourCC.

    Accepts both string and variants of bytes.
    """
    if hasattr(enc_k_fourcc, 'decode'):
        enc_k_str = enc_k_fourcc.decode("utf-8")
    else:
        enc_k_str = str(enc_k_fourcc)
    enc_k_select = None

    for kstr in po.key_select:
        if enc_k_str == kstr[:4]:
            enc_k_select = kstr
            break

    key_list = []
    if enc_k_select is None:
        if enc_k_str in keys:
            enc_k_select = enc_k_str
        else:
            for kstr in keys:
                if enc_k_str == kstr[:4]:
                    key_list.append(kstr)

    if enc_k_select is not None:
        # Key selection was already made
        pass
    elif len(key_list) == 1:
        # There is only one key to choose from
        enc_k_select = key_list[0]
    elif len(key_list) > 1:
        # We have multiple matching keys; we do not have enough information to auto-choose correct one
        # (the key needs to be selected based of FW package version, we only have FW module version)
        enc_k_select = key_list[0]
        if (po.show_multiple_keys_warn):
            eprint("{}: Warning: '{:s}' matches multiple keys; using first, '{:s}'".format(po.sigfile,enc_k_str,enc_k_select))
            eprint("{}: Key choices: {:s}".format(po.sigfile,", ".join(key_list)))
            po.show_multiple_keys_warn = False

    if enc_k_select in keys.keys():
        enc_key = keys[enc_k_select]
    else:
        enc_key = None
    return enc_key

def imah_get_crypto_params(po, pkghead):
    # Get the encryption key
    enc_k_str = pkghead.enc_key.decode("utf-8")
    enc_key = get_key_data(po, pkghead, enc_k_str)
    if enc_key is None:
        eprint("{}: Warning: Cannot find enc_key '{:s}'".format(po.sigfile,enc_k_str))
        return (None, None, None)
    # Prepare initial values for AES
    if   pkghead.header_version == 2:
        if (po.verbose > 3):
            print("Key encryption key:\n{:s}".format(' '.join("{:02X}".format(x) for x in enc_key)))
        crypt_mode = AES.MODE_CTR
        cipher = AES.new(enc_key, AES.MODE_ECB)
        if (po.verbose > 3):
            print("Encrypted Scramble key:\n{:s}".format(' '.join("{:02X}".format(x) for x in pkghead.scram_key)))
        crypt_key = cipher.decrypt(bytes(pkghead.scram_key))
        # For CTR mode, 12 bytes of crypt_iv will be interpreted as nonce, and remaining 4 will be initial value of counter
        crypt_iv = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    elif pkghead.header_version == 1:
        if (po.verbose > 3):
            print("Key encryption key:\n{:s}".format(' '.join("{:02X}".format(x) for x in enc_key)))
        crypt_mode = AES.MODE_CBC
        cipher = AES.new(enc_key, AES.MODE_CBC, bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
        if (po.verbose > 3):
            print("Encrypted Scramble key:\n{:s}".format(' '.join("{:02X}".format(x) for x in pkghead.scram_key)))
        crypt_key = cipher.decrypt(bytes(pkghead.scram_key))
        crypt_iv = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    else:
        crypt_mode = AES.MODE_CBC
        crypt_key = enc_key
        crypt_iv = bytes(pkghead.scram_key)
    return (crypt_key, crypt_mode, crypt_iv)

def imah_get_auth_params(po, pkghead):
    # Get the key
    auth_k_str = pkghead.auth_key.decode("utf-8")
    auth_key_data = get_key_data(po, pkghead, auth_k_str)
    if auth_key_data is None:
        eprint("{}: Warning: Cannot find auth_key '{:s}'".format(po.sigfile,auth_k_str))
        return (None)
    if isinstance(auth_key_data, str):
        auth_key = RSA.importKey(auth_key_data)
    elif len(auth_key_data) == sizeof(ImgRSAPublicKey):
        auth_key_struct = ImgRSAPublicKey()
        memmove(addressof(auth_key_struct), auth_key_data, sizeof(auth_key_struct))
        auth_key_n = combine_int_array(auth_key_struct.n, 32)
        auth_key = RSA.construct( (auth_key_n, auth_key_struct.exponent, ) )
    else:
        eprint("{}: Warning: Unrecognized format of auth_key '{:s}'".format(po.sigfile,auth_k_str))
        return (None)
    return (auth_key)

def imah_compute_checksum(po, buf, start = 0):
    cksum = start
    for i in range(0, len(buf) // 4):
        v = int.from_bytes(buf[i*4:i*4+4], byteorder='little')
        cksum += v
    # last dword
    i = len(buf) // 4
    if i*4 < len(buf):
        last_buf = buf[i*4:i*4+4] + bytes(3 * [0])
        v = int.from_bytes(last_buf[:4], byteorder='little')
        cksum += v
    return (cksum) & ((2 ** 32) - 1)

def imah_write_fwsig_head(po, pkghead, minames):
    fname = "{:s}_head.ini".format(po.mdprefix)
    fwheadfile = open(fname, "w")
    pkghead.ini_export(fwheadfile)
    # Prepare initial values for AES
    if pkghead.header_version == 0: # Scramble key is used as initial vector
        fwheadfile.write("{:s}={:s}\n".format('scramble_iv',' '.join("{:02X}".format(x) for x in pkghead.scram_key)))
    else:
        crypt_key, _, _ = imah_get_crypto_params(po, pkghead)
        if crypt_key is None: # Scramble key is used, but we cannot decrypt it
            eprint("{}: Warning: Storing encrypted scramble key due to missing crypto config.".format(po.sigfile))
            fwheadfile.write("{:s}={:s}\n".format('scramble_key_encrypted',' '.join("{:02X}".format(x) for x in pkghead.scram_key)))
        else: # Store the decrypted scrable key
            fwheadfile.write("{:s}={:s}\n".format('scramble_key',' '.join("{:02X}".format(x) for x in crypt_key)))
    # Store list of modules/chunks to include
    fwheadfile.write("{:s}={:s}\n".format('modules',' '.join(minames)))
    fwheadfile.close()

def imah_read_fwsig_head(po):
    pkghead = ImgPkgHeader()
    fname = "{:s}_head.ini".format(po.mdprefix)
    parser = configparser.ConfigParser()

    with open(fname, "r") as lines:
        lines = itertools.chain(("[asection]",), lines)  # This line adds section header to ini
        parser.read_file(lines)
    # Set magic fields properly
    pkgformat = int(parser.get("asection", "pkg_format"))
    pkghead.set_format_version(pkgformat)
    # Set the rest of the fields
    pkghead.name = bytes(parser.get("asection", "name"), "utf-8")
    pkghead.userdata = bytes(parser.get("asection", "userdata"), "utf-8")
    # The only person at Dji who knew how to store dates must have been fired
    date_val = strptime(parser.get("asection", "date"),"%Y-%m-%d")
    pkghead.date = ((date_val.tm_year // 1000) << 28) | (((date_val.tm_year % 1000) // 100) << 24) | \
            (((date_val.tm_year % 100) // 10) << 20) | ((date_val.tm_year % 10) << 16) | \
            ((date_val.tm_mon // 10) << 12) | ((date_val.tm_mon % 10) << 8) | \
            ((date_val.tm_mday // 10) << 4) | (date_val.tm_mday % 10)
    version_s = parser.get("asection", "version")
    version_m = re.search('(?P<major>[0-9]+)[.](?P<minor>[0-9]+)[.](?P<build>[0-9]+)[.](?P<rev>[0-9]+)', version_s)
    pkghead.version = ((int(version_m.group("major"),10)&0xff)<<24) + ((int(version_m.group("minor"),10)&0xff)<<16) + \
            ((int(version_m.group("build"),10)&0xff)<<8) + ((int(version_m.group("rev"),10)&0xff))
    anti_version_s = parser.get("asection", "anti_version")
    anti_version_m = re.search('(?P<major>[0-9]+)[.](?P<minor>[0-9]+)[.](?P<build>[0-9]+)[.](?P<rev>[0-9]+)', anti_version_s)
    pkghead.anti_version = ((int(anti_version_m.group("major"),10)&0xff)<<24) + ((int(anti_version_m.group("minor"),10)&0xff)<<16) + \
            ((int(anti_version_m.group("build"),10)&0xff)<<8) + ((int(anti_version_m.group("rev"),10)&0xff))
    pkghead.enc_key = bytes(parser.get("asection", "enc_key"), "utf-8")
    pkghead.auth_key = bytes(parser.get("asection", "auth_key"), "utf-8")
    pkghead.auth_alg = int(parser.get("asection", "auth_alg"))
    pkghead.os = int(parser.get("asection", "os"))
    pkghead.arch = int(parser.get("asection", "arch"))
    pkghead.compression = int(parser.get("asection", "compression"))
    pkghead.type = bytes(parser.get("asection", "type"), "utf-8")
    entry_bt = bytes.fromhex(parser.get("asection", "entry"))
    pkghead.entry = (c_ubyte * len(entry_bt)).from_buffer_copy(entry_bt)

    if po.random_scramble:
        scramble_needs_encrypt = (pkghead.header_version != 0)
        scramble_key = os.urandom(16)
        pkghead.scram_key = (c_ubyte * len(scramble_key)).from_buffer_copy(scramble_key)

    elif pkghead.header_version == 0: # Scramble key is used as initial vector
        scramble_needs_encrypt = False
        scramble_iv = bytes.fromhex(parser.get("asection", "scramble_iv"))
        pkghead.scram_key = (c_ubyte * len(scramble_iv)).from_buffer_copy(scramble_iv)

    else: # Scrable key should be encrypted
        if parser.has_option("asection", "scramble_key"):
            scramble_needs_encrypt = True
            scramble_key = bytes.fromhex(parser.get("asection", "scramble_key"))
        else: # Maybe we have pre-encrypted version?
            scramble_needs_encrypt = False
            scramble_key = bytes.fromhex(parser.get("asection", "scramble_key_encrypted"))

        if scramble_key is not None:
            pkghead.scram_key = (c_ubyte * len(scramble_key)).from_buffer_copy(scramble_key)
        else:
            eprint("{}: Warning: Scramble key not found in header and not set to ramdom; zeros will be used.".format(po.sigfile))

    minames_s = parser.get("asection", "modules")
    minames = minames_s.split(' ')
    pkghead.chunk_num = len(minames)
    pkghead.header_size = sizeof(pkghead) + sizeof(ImgChunkHeader)*pkghead.chunk_num
    pkghead.signature_size = 256
    pkghead.update_payload_size(0)

    del parser

    if scramble_needs_encrypt:
        # Get the encryption key
        enc_k_str = pkghead.enc_key.decode("utf-8")
        enc_key = get_key_data(po, pkghead, enc_k_str)
        if enc_key is None:
            eprint("{}: Warning: Cannot find enc_key '{:s}'; scramble key left unencrypted.".format(fwsigfile.name,enc_k_str))
        else:
            cipher = AES.new(enc_key, AES.MODE_CBC, bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
            crypt_key_enc = cipher.encrypt(bytes(pkghead.scram_key))
            pkghead.scram_key = (c_ubyte * 16)(*list(crypt_key_enc))

    return (pkghead, minames, pkgformat)

def imah_write_fwentry_head(po, i, e, miname, can_decrypt):
    fname = "{:s}_{:s}.ini".format(po.mdprefix,miname)
    fwheadfile = open(fname, "w")
    e.ini_export(fwheadfile)
    if not can_decrypt: # If we're exporting without decryption, we must retain decrypted size
        fwheadfile.write("{:s}={:s}\n".format('size',"{:d}".format(e.size)))
    fwheadfile.close()

def imah_read_fwentry_head(po, i, miname):
    chunk = ImgChunkHeader()
    fname = "{:s}_{:s}.ini".format(po.mdprefix,miname)
    parser = configparser.ConfigParser()
    with open(fname, "r") as lines:
        lines = itertools.chain(("[asection]",), lines)  # This line adds section header to ini
        parser.read_file(lines)
    id_s = parser.get("asection", 'id')
    chunk.id = bytes(id_s, "utf-8")
    attrib_s = parser.get("asection", 'attrib')
    chunk.attrib = int(attrib_s, 16)
    size_s = parser.get("asection", 'size',fallback="0")
    chunk.size = int(size_s,0)
    #offset_s = parser.get("asection", 'offset')
    #chunk.offset = int(offset_s, 16)
    address_s = parser.get("asection", 'address')
    chunk.address = int(address_s, 16)
    del parser
    return (chunk)

def imah_unsign(po, fwsigfile):

    # Decode the image header
    pkghead = ImgPkgHeader()
    if fwsigfile.readinto(pkghead) != sizeof(pkghead):
        raise EOFError("Could not read signed image file header.")

    # Check the magic
    pkgformat = pkghead.get_format_version()
    if pkgformat == 0:
        raise_or_warn(po, ValueError("Unexpected magic value in main header; input file is not a signed image."))

    if pkghead.size != pkghead.target_size:
        eprint("{}: Warning: Header field 'size' is different that 'target_size'; the tool is not designed to handle this.".format(fwsigfile.name))

    if not all(v == 0 for v in pkghead.reserved):
        eprint("{}: Warning: Header field 'reserved' is non-zero; the tool is not designed to handle this.".format(fwsigfile.name))

    if not all(v == 0 for v in pkghead.reserved2):
        eprint("{}: Warning: Header field 'reserved2' is non-zero; the tool is not designed to handle this.".format(fwsigfile.name))

    if pkgformat < 2018:
        if pkghead.encr_cksum != 0:
            eprint("{}: Warning: Header field 'encr_cksum' is non-zero; this is only allowed in newer formats.".format(fwsigfile.name))

        if pkghead.plain_cksum != 0:
            eprint("{}: Warning: Header field 'plain_cksum' is non-zero; this is only allowed in newer formats.".format(fwsigfile.name))

    if (po.verbose > 0):
        print("{}: Unpacking image...".format(fwsigfile.name))
    if (po.verbose > 1):
        print(pkghead)

    # Read chunk headers of the image
    chunks = []
    for i in range(0, pkghead.chunk_num):
        chunk = ImgChunkHeader()
        if fwsigfile.readinto(chunk) != sizeof(chunk):
            raise EOFError("Could not read signed image chunk {:d} header.".format(i))
        chunks.append(chunk)

    # Compute header hash and checksum; for checksum, we need a header without checksum stored
    pkghead_nosum = copy(pkghead)
    pkghead_nosum.encr_cksum = 0
    checksum_enc = imah_compute_checksum(po, bytes(pkghead_nosum))
    header_digest = SHA256.new()
    header_digest.update(bytes(pkghead))
    for i, chunk in enumerate(chunks):
        header_digest.update(bytes(chunk))
        checksum_enc = imah_compute_checksum(po, bytes(chunk), checksum_enc)
    if (po.verbose > 2):
        print("Computed header checksum 0x{:08X} and digest:\n{:s}".format(checksum_enc, ' '.join("{:02X}".format(x) for x in header_digest.digest())))

    if pkghead.signature_size != 256: # 2048 bit key length
        raise_or_warn(po, ValueError("Signed image file head signature has unexpected size."))
    head_signature = fwsigfile.read(pkghead.signature_size)
    if len(head_signature) != pkghead.signature_size:
        raise EOFError("Could not read signature of signed image file head.")

    auth_key = imah_get_auth_params(po, pkghead)
    try:
        if pkgformat >= 2018:
            mgf = lambda x, y: pss.MGF1(x, y, SHA256)
            salt_bytes = header_digest.digest_size
            header_signer = pss.new(auth_key, mask_func=mgf, salt_bytes=salt_bytes)
            # The PSS signer does not return value, just throws exception of a fail
            header_signer.verify(header_digest, head_signature)
            signature_match = True
        else:
            header_signer = PKCS1_v1_5.new(auth_key)
            signature_match = header_signer.verify(header_digest, head_signature)
    except Exception as ex:
        print("{}: Warning: Image file head signature verification caused cryptographic exception: {}".format(fwsigfile.name,str(ex)))
        signature_match = False
    if signature_match:
        if (po.verbose > 1):
            print("{}: Image file head signature verification passed.".format(fwsigfile.name))
    else:
        raise_or_warn(po, ValueError("Image file head signature verification failed."))

    # Finish computing encrypted data checksum; cannot do that during decryption as we would
    # likely miss some padding, which is also included in the checksum
    remain_enc_n = pkghead.payload_size
    while remain_enc_n > 0:
        copy_buffer = fwsigfile.read(min(1024 * 1024, remain_enc_n))
        checksum_enc = imah_compute_checksum(po, copy_buffer, checksum_enc)
        remain_enc_n -= 1024 * 1024
    checksum_enc = (2 ** 32) - checksum_enc

    if pkgformat < 2018:
        pass # No checksums are used in these formats
    elif pkghead.encr_cksum == checksum_enc:
        if (po.verbose > 1):
            print("{}: Encrypted data checksum 0x{:08X} matches.".format(fwsigfile.name, checksum_enc))
    else:
        if (po.verbose > 1):
            print("{}: Encrypted data checksum 0x{:08X}, expected 0x{:08X}.".format(fwsigfile.name, checksum_enc, pkghead.encr_cksum))
        raise_or_warn(po, ValueError("Encrypted data checksum verification failed."))

    # Prepare array of names; "0" will mean empty index
    minames = ["0"]*len(chunks)
    # Name the modules after target component
    for i, chunk in enumerate(chunks):
        if chunk.size > 0:
            d = chunk.dict_export()
            minames[i] = "{:s}".format(d['id'])
    # Rename targets in case of duplicates
    minames_seen = set()
    for i in range(len(minames)):
        miname = minames[i]
        if miname in minames_seen:
            # Add suffix a..z to multiple uses of the same module
            for miname_suffix in range(97,110):
                if miname+chr(miname_suffix) not in minames_seen:
                    break
            # Show warning the first time duplicate is found
            if (miname_suffix == 97):
                eprint("{}: Warning: Found multiple chunks '{:s}'; invalid signed image.".format(fwsigfile.name,miname))
            minames[i] = miname+chr(miname_suffix)
        minames_seen.add(minames[i])
    minames_seen = None

    imah_write_fwsig_head(po, pkghead, minames)

    crypt_key, crypt_mode, crypt_iv = imah_get_crypto_params(po, pkghead)
    if (crypt_key is not None) and (po.verbose > 2):
        print("Scramble key:\n{:s}".format(' '.join("{:02X}".format(x) for x in crypt_key)))

    # Output the chunks
    checksum_dec = 0
    num_skipped = 0
    single_cipher = None # IMaH v1 creates a new cipher for each chunk, IMaH v2 reuses a single cipher
    for i, chunk in enumerate(chunks):

        chunk_fname= "{:s}_{:s}.bin".format(po.mdprefix,minames[i])

        if (chunk.attrib & 0x01) or (pkghead.enc_key == b''): # Not encrypted chunk
            cipher = PlainCopyCipher()
            pad_cnt = 0
            if (po.verbose > 0):
                print("{}: Unpacking plaintext chunk '{:s}'...".format(fwsigfile.name,minames[i]))
            can_decrypt = True

        elif crypt_key is not None: # Encrypted chunk (have key as well)
            if crypt_mode == AES.MODE_CTR:
                if single_cipher is None:
                    init_cf = int.from_bytes(crypt_iv[12:16], byteorder='big')
                    countf = Counter.new(32, crypt_iv[:12], initial_value=init_cf)
                    cipher = AES.new(crypt_key, crypt_mode, counter=countf)
                    single_cipher = cipher
                else:
                    cipher = single_cipher
                dji_block_size = 32
            else:
                cipher = AES.new(crypt_key, crypt_mode, iv=crypt_iv)
                # the data is really padded to 32, but we do not care as we reset state for every chunk
                dji_block_size = AES.block_size
            pad_cnt = (dji_block_size - chunk.size % dji_block_size) % dji_block_size
            if (po.verbose > 0):
                print("{}: Unpacking encrypted chunk '{:s}'...".format(fwsigfile.name,minames[i]))
            can_decrypt = True

        else: # Missing encryption key
            eprint("{}: Warning: Cannot decrypt chunk '{:s}'; crypto config missing.".format(fwsigfile.name,minames[i]))
            if (not po.force_continue):
                num_skipped += 1
                continue
            if (po.verbose > 0):
                print("{}: Copying still encrypted chunk '{:s}'...".format(fwsigfile.name,minames[i]))
            cipher = PlainCopyCipher()
            pad_cnt = (AES.block_size - chunk.size % AES.block_size) % AES.block_size
            can_decrypt = False

        imah_write_fwentry_head(po, i, chunk, minames[i], can_decrypt)

        if (po.verbose > 1):
            print(str(chunk))

        # Decrypt and write the data
        fwsigfile.seek(pkghead.header_size + pkghead.signature_size + chunk.offset, 0)
        fwitmfile = open(chunk_fname, "wb")
        remain_enc_n = chunk.size + pad_cnt
        remain_dec_n = chunk.size
        if not can_decrypt: # If storing encrypted, include padding
            remain_dec_n += pad_cnt
        while remain_enc_n > 0:
            # read block limit must be a multiplication of encryption block size
            # ie AES.block_size is fixed at 16 bytes
            copy_buffer = fwsigfile.read(min(1024 * 1024, remain_enc_n))
            if not copy_buffer:
                eprint("{}: Warning: Chunk '{:s}' truncated.".format(fwsigfile.name,minames[i]))
                num_skipped += 1
                break
            remain_enc_n -= len(copy_buffer)
            copy_buffer = cipher.decrypt(copy_buffer)
            checksum_dec = imah_compute_checksum(po, copy_buffer, checksum_dec)
            if remain_dec_n >= len(copy_buffer):
                fwitmfile.write(copy_buffer)
                remain_dec_n -= len(copy_buffer)
            else:
                if (po.verbose > 2):
                    print("Chunk padding: {:s}".format(str(copy_buffer[-len(copy_buffer)+remain_dec_n:])))
                fwitmfile.write(copy_buffer[:remain_dec_n])
                remain_dec_n = 0
        fwitmfile.close()

    print("{}: Un-signed {:d} chunks, skipped/truncated {:d} chunks.".format(fwsigfile.name,len(chunks)-num_skipped, num_skipped))
    if pkgformat < 2018:
        pass # No checksums are used in these formats
    elif pkghead.plain_cksum == checksum_dec:
        if (po.verbose > 1):
            print("{}: Decrypted chunks checksum 0x{:08X} matches.".format(fwsigfile.name, checksum_dec))
    else:
        if (po.verbose > 1):
            print("{}: Decrypted chunks checksum 0x{:08X}, expected 0x{:08X}.".format(fwsigfile.name, checksum_dec, pkghead.plain_cksum))
        raise_or_warn(po, ValueError("Decrypted chunks checksum verification failed."))

def imah_sign(po, fwsigfile):
    # Read headers from INI files
    (pkghead, minames, pkgformat) = imah_read_fwsig_head(po)
    chunks = []
    # Create header entry for each chunk
    for i, miname in enumerate(minames):
        if miname == "0":
            chunk = ImgChunkHeader()
        else:
            chunk = imah_read_fwentry_head(po, i, miname)
        chunks.append(chunk)
    # Write the unfinished headers
    fwsigfile.write(bytes(pkghead))
    for chunk in chunks:
        fwsigfile.write(bytes(chunk))
    fwsigfile.write(b"\0" * pkghead.signature_size)
    # prepare encryption
    crypt_key, crypt_mode, crypt_iv = imah_get_crypto_params(po, pkghead)
    # Write module data
    checksum_dec = 0
    single_cipher = None # IMaH v1 creates a new cipher for each chunk, IMaH v2 reuses a single cipher
    payload_digest = SHA256.new()
    for i, miname in enumerate(minames):
        chunk = chunks[i]
        chunk.offset = fwsigfile.tell() - pkghead.header_size - pkghead.signature_size
        if miname == "0":
            if (po.verbose > 0):
                print("{}: Empty chunk index {:d}".format(fwsigfile.name,i))
            continue

        if (chunk.attrib & 0x01) or (pkghead.enc_key == b''): # Not encrypted chunk
            cipher = PlainCopyCipher()
            if (po.verbose > 0):
                print("{}: Packing plaintext chunk '{:s}'...".format(fwsigfile.name,minames[i]))
            can_decrypt = True

        elif crypt_key != None: # Encrypted chunk (have key as well)
            if crypt_mode == AES.MODE_CTR:
                if single_cipher is None:
                    init_cf = int.from_bytes(crypt_iv[12:16], byteorder='big')
                    countf = Counter.new(32, crypt_iv[:12], initial_value=init_cf)
                    cipher = AES.new(crypt_key, crypt_mode, counter=countf)
                    single_cipher = cipher
                else:
                    cipher = single_cipher
            else:
                cipher = AES.new(crypt_key, crypt_mode, iv=crypt_iv)
            if (po.verbose > 0):
                print("{}: Packing and encrypting chunk '{:s}'...".format(fwsigfile.name,minames[i]))
            can_decrypt = True

        else: # Missing encryption key
            eprint("{}: Warning: Cannot encrypt chunk '{:s}'; crypto config missing.".format(fwsigfile.name,minames[i]))
            raise_or_warn(po, ValueError("Unsupported encryption configuration."))
            if (po.verbose > 0):
                print("{}: Copying already encrypted chunk '{:s}'...".format(fwsigfile.name,minames[i]))
            cipher = PlainCopyCipher()
            can_decrypt = False

        if (po.verbose > 1):
            print(str(chunk))

        chunk_fname= "{:s}_{:s}.bin".format(po.mdprefix,miname)
        # Copy chunk data and compute digest
        fwitmfile = open(chunk_fname, "rb")
        # Chunks in new formats are padded with zeros and then encrypted; for older formats,
        # the padding rules are more convoluted, and also change slightly between platforms
        if pkgformat >= 2018:
            dji_block_size = 32
        else:
            dji_block_size = AES.block_size
        decrypted_n = 0
        while True:
            # read block limit must be a multiplication of encryption block size
            # ie AES.block_size is fixed at 16 bytes
            copy_buffer = fwitmfile.read(1024 * 1024)
            if not copy_buffer:
                break
            decrypted_n += len(copy_buffer)
            # Pad the payload to AES.block_size = 16
            if (len(copy_buffer) % dji_block_size) != 0:
                pad_cnt = dji_block_size - (len(copy_buffer) % dji_block_size)
                pad_buffer = b"\0" * pad_cnt
                copy_buffer += pad_buffer
            checksum_dec = imah_compute_checksum(po, copy_buffer, checksum_dec)
            copy_buffer = cipher.encrypt(copy_buffer)
            payload_digest.update(copy_buffer)
            fwsigfile.write(copy_buffer)
        fwitmfile.close()
        # Pad with zeros at end, for no real reason
        dji_block_size = 32
        if (fwsigfile.tell() - chunk.offset) % dji_block_size != 0:
            pad_cnt = dji_block_size - ((fwsigfile.tell() - chunk.offset) % dji_block_size)
            pad_buffer = b"\0" * pad_cnt
            payload_digest.update(pad_buffer) # why Dji includes padding in digest?
            fwsigfile.write(pad_buffer)
        # Update size of the chunk in header; skip that if the chunk was pre-encrypted and correct size was stored in INI
        if can_decrypt or chunk.size == 0:
            chunk.size = decrypted_n
        elif  (decrypted_n <= chunk.size) or (decrypted_n >= chunk.size + dji_block_size):
            eprint("{}: Warning: Chunk '{:s}' size from INI is incorrect, ignoring".format(fwsigfile.name,minames[i]))
            chunk.size = decrypted_n
        chunks[i] = chunk

    pkghead.update_payload_size(fwsigfile.tell() - pkghead.header_size - pkghead.signature_size)
    if pkgformat >= 2018:
        pkghead.plain_cksum = checksum_dec
        if (po.verbose > 1):
            print("{}: Decrypted chunks checksum 0x{:08X} stored".format(fwsigfile.name, checksum_dec))
    pkghead.payload_digest = (c_ubyte * 32)(*list(payload_digest.digest()))
    if (po.verbose > 2):
        print("{}: Computed payload digest:\n{:s}".format(fwsigfile.name, ' '.join("{:02X}".format(x) for x in pkghead.payload_digest)))

    # Compute encrypted data checksum; cannot do that during encryption as we
    # need header with all fields filled, except of the checksum ofc.
    checksum_enc = imah_compute_checksum(po, bytes(pkghead))
    for i, chunk in enumerate(chunks):
        checksum_enc = imah_compute_checksum(po, bytes(chunk), checksum_enc)
    if (po.verbose > 2):
        print("{}: Computed header checksum 0x{:08X}".format(fwsigfile.name, checksum_enc))

    if pkgformat >= 2018:
        fwsigfile.seek(pkghead.header_size + pkghead.signature_size, os.SEEK_SET)
        remain_enc_n = pkghead.payload_size
        while remain_enc_n > 0:
            copy_buffer = fwsigfile.read(min(1024 * 1024, remain_enc_n))
            checksum_enc = imah_compute_checksum(po, copy_buffer, checksum_enc)
            remain_enc_n -= 1024 * 1024
        checksum_enc = (2 ** 32) - checksum_enc
        pkghead.encr_cksum = checksum_enc
        if (po.verbose > 1):
            print("{}: Encrypted data checksum 0x{:08X} stored".format(fwsigfile.name, checksum_enc))

    # Write all headers again
    fwsigfile.seek(0, os.SEEK_SET)
    fwsigfile.write(bytes(pkghead))
    if (po.verbose > 1):
        print(str(pkghead))
    for chunk in chunks:
        fwsigfile.write(bytes(chunk))
        if (po.verbose > 1):
            print(str(chunk))

    # Compute header hash, and use it to sign the header
    header_digest = SHA256.new()
    header_digest.update(bytes(pkghead))
    for i, chunk in enumerate(chunks):
        header_digest.update(bytes(chunk))
    if (po.verbose > 2):
        print("{}: Computed header digest:\n{:s}".format(fwsigfile.name, ' '.join("{:02X}".format(x) for x in header_digest.digest())))

    auth_key = imah_get_auth_params(po, pkghead)
    if not hasattr(auth_key, 'd'):
        raise ValueError("Cannot compute image file head signature, auth key '{:s}' has no private part.".format(pkghead.auth_key.decode("utf-8")))

    if pkgformat >= 2018:
        mgf = lambda x, y: pss.MGF1(x, y, SHA256)
        salt_bytes = header_digest.digest_size
        header_signer = pss.new(auth_key, mask_func=mgf, salt_bytes=salt_bytes)
    else:
        header_signer = PKCS1_v1_5.new(auth_key)
    head_signature = header_signer.sign(header_digest)
    fwsigfile.write(head_signature)

def main():
    """ Main executable function.

    Its task is to parse command line options and call a function which performs requested command.
    """

    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument("-i", "--sigfile", default="", type=str,
          help="signed and encrypted IM*H firmware module file")

    parser.add_argument("-m", "--mdprefix", default="", type=str,
          help="file name prefix for the single un-signed and unencrypted " \
           "firmware module (defaults to base name of signed firmware file)")

    parser.add_argument("-f", "--force-continue", action="store_true",
          help="force continuing execution despite warning signs of issues")

    parser.add_argument("-r", "--random-scramble", action="store_true",
          help="while signing, use random scramble vector instead of from INI")

    parser.add_argument("-k", "--key-select", default=[], action='append',
          help=("select a specific key to be used for given four character code, "
          "if multiple keys match this fourcc"))

    parser.add_argument("-v", "--verbose", action="count", default=0,
          help="increases verbosity level; max level is set by -vvv")

    subparser = parser.add_mutually_exclusive_group(required=True)

    subparser.add_argument("-u", "--unsign", action="store_true",
          help="un-sign and decrypt the firmware module")

    subparser.add_argument("-s", "--sign", action="store_true",
          help="sign and encrypt the firmware module")

    subparser.add_argument("--version", action='version', version="%(prog)s {version} by {author}"
            .format(version=__version__,author=__author__),
          help="display version information and exit")

    po = parser.parse_args()

    if len(po.sigfile) > 0 and len(po.mdprefix) == 0:
        po.mdprefix = os.path.splitext(os.path.basename(po.sigfile))[0]
    elif len(po.mdprefix) > 0 and len(po.sigfile) == 0:
        po.sigfile = po.mdprefix + ".sig"
    po.show_multiple_keys_warn = True

    if po.unsign:

        if (po.verbose > 0):
            print("{}: Opening for extraction and un-signing".format(po.sigfile))
        fwsigfile = open(po.sigfile, "rb")

        imah_unsign(po, fwsigfile)

        fwsigfile.close();

    elif po.sign:

        if (po.verbose > 0):
            print("{}: Opening for creation and signing".format(po.sigfile))
        fwsigfile = open(po.sigfile, "w+b")

        imah_sign(po, fwsigfile)

        fwsigfile.close();

    else:

        raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        eprint("Error: "+str(ex))
        #raise
        sys.exit(10)
