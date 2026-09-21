# -*- coding: utf-8 -*-

"""Exercise framed DUML streams with combined and fragmented USB reads.

Packets are synthesized using observed header/payload variants; these are not
captures from a new hardware test of the cleaned implementation.
"""

from collections import deque
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import comm_mkdupc as m
import comm_serialtalk as serialtalk
import comm_og_service_tool as service


pytestmark = pytest.mark.comm


def make_packet(cmd_id=0x30, payload=b'\x64\x00',
                packet_type=m.PACKET_TYPE.REQUEST,
                seq=42, sender=m.COMM_DEV_TYPE.GIMBAL):
    return bytes(m.encode_command_packet_en(
        sender, 0, m.COMM_DEV_TYPE.PC, 0, seq, packet_type,
        m.ACK_TYPE.NO_ACK_NEEDED, m.ENCRYPT_TYPE.NO_ENC,
        m.CMD_SET_TYPE.ZENMUSE, cmd_id, payload))


def request_properties():
    return SimpleNamespace(
        sender_type=m.COMM_DEV_TYPE.PC, sender_index=0,
        receiver_type=m.COMM_DEV_TYPE.GIMBAL, receiver_index=0,
        seq_num=42, pack_type=m.PACKET_TYPE.REQUEST,
        ack_type=m.ACK_TYPE.ACK_BEFORE_EXEC,
        encrypt_type=m.ENCRYPT_TYPE.NO_ENC,
        cmd_set=m.CMD_SET_TYPE.ZENMUSE, cmd_id=0x08, payload=b'\x01')


class Stream:
    name = 'BULK'
    port = None

    def __init__(self, chunks=(), on_write=()):
        self.chunks = deque(chunks)
        self.on_write = on_write
        self.events = []

    def reset_input_buffer(self):
        self.events.append('reset')
        self.chunks.clear()

    def write(self, data):
        self.events.append('write')
        self.chunks.extend(self.on_write)

    @property
    def in_waiting(self):
        return int(bool(self.chunks))

    def read(self, length):
        self.events.append('read')
        return self.chunks.popleft()


@pytest.fixture
def options(monkeypatch):
    ticks = iter(i / 1000 for i in range(10000))
    monkeypatch.setattr(serialtalk.time, 'monotonic', lambda: next(ticks))
    return SimpleNamespace(verbose=0, timeout=50, dry_test=False)


def start(options, chunks):
    stream = Stream(on_write=chunks)
    request = serialtalk.do_send_request(options, stream, request_properties())
    return stream, request


def receive(options, stream, request):
    return serialtalk.do_receive_reply(
        options, stream, request, seqnum_check=False, extra_cmd_ids=(0x30,))


def test_progress_and_terminal_in_one_read_are_both_returned(options):
    progress = make_packet(payload=b'\x52\x01')
    terminal = make_packet()
    stream, request = start(options, [progress + terminal])
    assert receive(options, stream, request) == progress
    assert receive(options, stream, request) == terminal
    assert stream.events == ['reset', 'write', 'read']


def test_partial_next_packet_survives_return_of_first_reply(options):
    progress = make_packet(payload=b'\x52\x01')
    terminal = make_packet()
    stream, request = start(options, [progress + terminal[:7], terminal[7:]])
    assert receive(options, stream, request) == progress
    assert receive(options, stream, request) == terminal


def test_partial_packet_survives_receive_timeout(options):
    terminal = make_packet()
    stream, request = start(options, [terminal[:7]])
    assert receive(options, stream, request) is None
    stream.chunks.append(terminal[7:])
    assert receive(options, stream, request) == terminal


def test_unrelated_and_bad_crc_frames_do_not_hide_terminal(options):
    unrelated = make_packet(sender=m.COMM_DEV_TYPE.CAMERA)
    bad_crc = bytearray(make_packet())
    bad_crc[-1] ^= 0xff
    terminal = make_packet()
    stream, request = start(options, [unrelated + bytes(bad_crc) + terminal])
    assert receive(options, stream, request) == terminal


def test_new_request_discards_old_pending_packets(options):
    progress = make_packet(payload=b'\x52\x01')
    terminal = make_packet()
    stream, request = start(options, [progress + terminal])
    assert receive(options, stream, request) == progress
    stream.on_write = []
    request = serialtalk.do_send_request(options, stream, request_properties())
    assert receive(options, stream, request) is None


@pytest.mark.parametrize(
    'packet_type', [m.PACKET_TYPE.REQUEST, m.PACKET_TYPE.RESPONSE])
def test_ack_and_async_completion_share_one_read(options, packet_type, capsys):
    ack = make_packet(cmd_id=0x08, payload=b'\x01',
                      packet_type=m.PACKET_TYPE.RESPONSE)
    terminal = make_packet(packet_type=packet_type)
    stream = Stream(on_write=[ack + terminal])
    first, request = service.gimbal_calib_request_spark(
        options, stream, m.DJIPayload_Gimbal_CalibCmd.JointCoarse)
    assert first is None
    service.gimbal_calib_request_spark_monitor_progress(
        options, stream, first, request, 15000, [16, 1])
    assert 'result: PASS' in capsys.readouterr().out
    assert stream.events == ['reset', 'write', 'read']


def test_bulk_timeout_is_idle_but_other_usb_errors_propagate():
    core = pytest.importorskip('usb.core')
    endpoint = SimpleNamespace(wMaxPacketSize=64, read=Mock())
    stream = serialtalk.SerialBulkWrap(None, endpoint, None)
    endpoint.read.side_effect = core.USBTimeoutError('timed out')
    assert stream.read() == b''
    error = core.USBError('Disconnected')
    endpoint.read.side_effect = error
    with pytest.raises(core.USBError) as caught:
        stream.read()
    assert caught.value is error
