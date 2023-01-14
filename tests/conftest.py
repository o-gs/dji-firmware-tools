# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, general configuration script.

    This configures pytest and contains common fixtures used in tests.
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

import sys
import pytest

# Allow importing the unpackaged python scripts to test
sys.path.insert(0, './')

BUFSIZE = 8*1024

def pytest_addoption(parser):
    parser.addoption(
        "--full-scope", action="store_true", default=False, help="run all tests in scope rather than a selection for CI"
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: mark test as slow to run")


def pytest_collection_modifyitems(config, items):
    if not config.getoption("full_scope"):
        # Skip tests marked for execution only in full scope
        skip_marker = pytest.mark.skip(reason="runs only when full scope is executed")
        for item in items:
            if "full_scope" in item.keywords:
                item.add_marker(skip_marker)
    pass

def pytest_generate_tests(metafunc):
    if "test_nth" in metafunc.fixturenames:
        if metafunc.config.getoption("full_scope"):
            # Exec full scope - mark any tests with selective n-th case run to instead enable all cases
            for marker in metafunc.definition.iter_markers(name="parametrize"):
                args_names = marker.args[0]
                args_values_sets = marker.args[1]
                if "test_nth" in args_names:
                    n = args_names.split(",").index("test_nth")
                    for index, values in enumerate(args_values_sets):
                        vals = list(values)
                        vals[n] = 1
                        args_values_sets[index] = tuple(vals)
                    print(n,marker.args)

def filecmp_diffcount(f1, f2):
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
