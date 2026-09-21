# -*- coding: utf-8 -*-

"""Tests for newer gimbal calibration protocol variants."""

import pytest

from comm_mkdupc import (
    CMD_SET_TYPE,
    COMM_DEV_TYPE,
    DJICmdV1Header,
    DJIPayload_Gimbal_CalibProgressRe,
    DJIPayload_Gimbal_CalibRq,
    PACKET_TYPE,
    get_known_payload,
)
from comm_serialtalk import packet_header_is_reply_for_request
from comm_og_service_tool import gimbal_calib_report_is_success


pytestmark = pytest.mark.comm


def make_calibration_header(packet_type, cmd_id):
    header = DJICmdV1Header()
    header.sender_type = COMM_DEV_TYPE.GIMBAL.value
    header.receiver_type = COMM_DEV_TYPE.PC.value
    header.seq_num = 42
    header.packet_type = packet_type.value
    header.cmd_set = CMD_SET_TYPE.ZENMUSE.value
    header.cmd_id = cmd_id
    return header


def test_one_byte_calibration_response_is_parsed_as_ack():
    header = make_calibration_header(PACKET_TYPE.RESPONSE, 0x08)

    payload = get_known_payload(header, bytes([0x01]))

    assert isinstance(payload, DJIPayload_Gimbal_CalibRq)
    assert payload.command == 0x01


@pytest.mark.parametrize(
    'packet_type', [PACKET_TYPE.REQUEST, PACKET_TYPE.RESPONSE])
def test_async_calibration_completion_report_is_parsed(packet_type):
    header = make_calibration_header(packet_type, 0x30)

    payload = get_known_payload(header, bytes([0x64, 0x00]))

    assert isinstance(payload, DJIPayload_Gimbal_CalibProgressRe)
    assert payload.value == 0x64
    assert payload.state == 0x00
    assert gimbal_calib_report_is_success(payload, [40, 1])


def test_nonterminal_async_report_is_not_success():
    header = make_calibration_header(PACKET_TYPE.RESPONSE, 0x30)

    payload = get_known_payload(header, bytes([0x52, 0x01]))

    assert not gimbal_calib_report_is_success(payload, [40, 1])


def test_alternate_command_id_must_be_explicitly_allowed():
    request = DJICmdV1Header()
    request.sender_type = COMM_DEV_TYPE.PC.value
    request.receiver_type = COMM_DEV_TYPE.GIMBAL.value
    request.seq_num = 42
    request.packet_type = PACKET_TYPE.REQUEST.value
    request.cmd_set = CMD_SET_TYPE.ZENMUSE.value
    request.cmd_id = 0x08

    report = make_calibration_header(PACKET_TYPE.RESPONSE, 0x30)

    assert not packet_header_is_reply_for_request(report, request)
    assert packet_header_is_reply_for_request(
        report, request, extra_cmd_ids=(0x30,)
    )


@pytest.mark.parametrize('payload', [b'', b'\x64'])
def test_truncated_async_report_is_not_completion(payload):
    header = make_calibration_header(PACKET_TYPE.REQUEST, 0x30)
    assert get_known_payload(header, payload) is None


@pytest.mark.parametrize(
    'field', ['sender_index', 'receiver_index', 'cmd_set', 'seq_num'])
def test_alternate_command_does_not_bypass_other_header_checks(field):
    request = DJICmdV1Header()
    request.sender_type = COMM_DEV_TYPE.PC.value
    request.receiver_type = COMM_DEV_TYPE.GIMBAL.value
    request.seq_num = 42
    request.cmd_set = CMD_SET_TYPE.ZENMUSE.value
    request.cmd_id = 0x08
    report = make_calibration_header(PACKET_TYPE.REQUEST, 0x30)
    setattr(report, field, getattr(report, field) + 1)
    assert not packet_header_is_reply_for_request(
        report, request, extra_cmd_ids=(0x30,))


@pytest.mark.parametrize('pass_values', [[16, 1], [40, 1]])
def test_legacy_completion_remains_supported(pass_values):
    header = make_calibration_header(PACKET_TYPE.REQUEST, 0x08)
    payload = get_known_payload(header, bytes(pass_values))
    assert gimbal_calib_report_is_success(payload, pass_values)


@pytest.mark.parametrize('mode', ['complete', 'stall', 'never_complete'])
def test_linear_hall_monitor_deadlines(monkeypatch, capsys, mode):
    from types import SimpleNamespace
    import comm_og_service_tool as service

    elapsed = [0.0]
    monkeypatch.setattr(service.time, 'monotonic', lambda: elapsed[0])
    header = make_calibration_header(PACKET_TYPE.REQUEST, 0x30)
    active = get_known_payload(header, b'\x52\x01')
    terminal = get_known_payload(header, b'\x64\x00')
    monkeypatch.setattr(service, 'gimbal_calib_request_spark',
                        lambda *args: (None, b''))

    def next_report(*args):
        elapsed[0] += 1
        if mode == 'stall':
            return None
        if mode == 'complete' and elapsed[0] == 55:
            elapsed[0] = 54.7
            return terminal
        return active

    monkeypatch.setattr(service, 'gimbal_calib_request_spark_receive_progress',
                        next_report)
    service.do_gimbal_calib_request_spark_linear_hall(
        SimpleNamespace(verbose=0, dry_test=False), None)
    output = capsys.readouterr().out
    if mode == 'complete':
        assert 'took 54.7 sec' in output
        assert 'result: PASS' in output
    else:
        assert 'completion unconfirmed' in output
        assert 'result: UNSURE' in output
        assert 'must have ended' not in output
        if mode == 'stall':
            assert elapsed[0] == 8
        else:
            assert elapsed[0] == 121
