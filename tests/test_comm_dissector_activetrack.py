# -*- coding: utf-8 -*-
"""Decode synthetic Eye packets without publishing flight captures."""

import shutil
import struct
import subprocess
from pathlib import Path

import pytest
from comm_dat2pcap import calc_pkt55_checksum, calc_pkt55_hdr_checksum


LUA = Path(__file__).resolve().parents[1] / "comm_dissector/wireshark/dji-dumlv1-proto.lua"


def packet(command, payload, *, response=False):
    length = 13 + len(payload)
    header = b"\x55" + struct.pack("<H", length | 0x0400)
    header += bytes((calc_pkt55_hdr_checksum(0x77, header, 3),))
    body = (header + b"\x02\x12\x01\x00"
            + bytes((0x80 if response else 0x40, 0x0a, command)) + payload)
    return body + struct.pack("<H", calc_pkt55_checksum(body, len(body)))


def write_pcap(path, packets):
    with path.open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 150))
        for i, data in enumerate(packets):
            out.write(struct.pack("<IIII", i, 0, len(data), len(data)))
            out.write(data)


@pytest.mark.comm
def test_mavic2_activetrack_eye_fields(tmp_path):
    if shutil.which("tshark") is None:
        pytest.skip("tshark is required")

    selection = bytes((10,)) + struct.pack("<ffff", .52, .48, .06, .33) + b"\x00\x03\x00\x00"
    target = lambda index: bytes((index, 5)) + struct.pack("<ffff", .52, .48, .06, .33) + b"\x01"
    frames = [
        packet(0x20, selection),
        packet(0x95, bytes((2,)) + target(0) + target(1)),
        packet(0x96, bytes((2, 2, 0, 10, 0, 0, 0, 1, 0, 0))),
        packet(0x95, b"\x00", response=True),  # ACK must not appear as a target list
        packet(0x95, b"\x01\x00"),              # truncated target list
    ]
    capture = tmp_path / "synthetic-activetrack.pcap"
    write_pcap(capture, frames)

    # Wireshark 4.6 loads dofile() in a fresh environment. Keep the upstream
    # dissector's child Lua files in the same environment for this test.
    bootstrap = tmp_path / "load-duml.lua"
    bootstrap.write_text(
        "local shared = _ENV\n"
        "dofile = function(path) return assert(loadfile(path, 't', shared))() end\n"
        f"assert(loadfile('{LUA.as_posix()}', 't', shared))()\n"
    )
    fields = ("mbino_track_select_session_id", "mbino_multi_targets_count",
              "mbino_multi_target_index", "mbino_multi_state", "mbino_multi_state_mode")
    command = ["tshark", "-r", str(capture), "-X", f"lua_script:{bootstrap}",
               "-o", 'uat:user_dlts:"User 3 (DLT=150)","dji_dumlv1","","","",""',
               "-T", "fields", "-E", "separator=|", "-E", "occurrence=a"]
    for field in fields:
        command += ["-e", f"dji_dumlv1.{field}"]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    assert "Lua: Error" not in result.stderr
    rows = [line.split("|") for line in result.stdout.splitlines()]
    assert len(rows) == len(frames)
    assert rows[0][0] == "3"
    assert rows[1][1:3] == ["2", "0,1"]
    assert rows[2][3:] == ["2", "10"]
    assert rows[3][1] == ""
    assert rows[4][1:3] == ["1", ""]
