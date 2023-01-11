# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, file diff helpers.

    Helper functions used in tests.
"""

# Copyright (C) 2023 Mefistotelis <mefistotelis@gmail.com>
# Copyright (C) 2023 Original Gangsters <https://dji-rev.slack.com/>
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

BUFSIZE = 8*1024

def diffcount(f1, f2):
    bufsize = BUFSIZE
    c = 0
    with open(f1, 'rb') as fp1, open(f2, 'rb') as fp2:
        while True:
            b1 = fp1.read(bufsize)
            b2 = fp2.read(bufsize)
            if (not b1) or (not b2):
                c += len(b1)
                c += len(b2)
                # We will lose size differences beyond BUFSIZE, but that's ok
                break
            for bb1, bb2 in zip(b1, b2):
                if bb1 != bb2:
                    c += 1
    return c
