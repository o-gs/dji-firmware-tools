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


def test_async_calibration_completion_report_is_parsed():
    header = make_calibration_header(PACKET_TYPE.RESPONSE, 0x30)

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
