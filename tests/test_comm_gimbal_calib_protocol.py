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


@pytest.mark.parametrize(
    'packet_type', [PACKET_TYPE.REQUEST, PACKET_TYPE.RESPONSE])
def test_one_byte_calibration_response_is_parsed_as_ack(packet_type):
    header = make_calibration_header(packet_type, 0x08)

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
@pytest.mark.parametrize(
    'packet_type', [PACKET_TYPE.REQUEST, PACKET_TYPE.RESPONSE])
def test_legacy_completion_remains_supported(pass_values, packet_type):
    header = make_calibration_header(packet_type, 0x08)
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
        SimpleNamespace(verbose=0, dry_test=False,
                        product=service.PRODUCT_CODE.AIR3), None)
    output = capsys.readouterr().out
    if mode == 'complete':
        assert 'took 54.7 sec' in output
        assert 'result: PASS' in output
    else:
        assert 'completion unconfirmed' in output
        assert 'result: UNSURE' in output
        assert 'must have ended' not in output
        if mode == 'stall':
            assert elapsed[0] == 14
        else:
            assert elapsed[0] == 121


@pytest.mark.parametrize('transport', ['--bulk', '--port'])
@pytest.mark.parametrize('model,routine,seconds', [
    ('SPARK', 'JointCoarse', 15), ('SPARK', 'LinearHall', 30),
    ('AIR3', 'JointCoarse', 15), ('AIR3', 'LinearHall', 55),
    ('MINI3', 'JointCoarse', 15), ('MINI3', 'LinearHall', 55),
])
def test_model_calibration_dry_run(
        monkeypatch, capsys, model, routine, seconds, transport):
    import sys
    import comm_og_service_tool as service

    import serial

    def unexpected_open(*args, **kwargs):
        pytest.fail('dry test attempted to open hardware')

    monkeypatch.setattr(service, 'open_usb', unexpected_open)
    monkeypatch.setattr(service, 'detect_serial_port', unexpected_open)
    monkeypatch.setattr(serial, 'Serial', unexpected_open)
    connection = ['--bulk'] if transport == '--bulk' else ['--port', 'auto']
    monkeypatch.setattr(sys, 'argv', [
        'comm_og_service_tool.py', '-vvv', '--dry-test', *connection,
        model, 'GimbalCalib', routine])
    service.main()
    output = capsys.readouterr().out
    assert 'around {:d} seconds'.format(seconds) in output
    assert 'result: PASS' in output
    if model in ('AIR3', 'MINI3'):
        assert 'Parsed one-byte calibration ACK' in output
        assert 'DJIPayload_Gimbal_CalibProgressRe' in output
        assert 'received 4 reports' in output
    else:
        assert 'DJIPayload_Gimbal_CalibRe' in output


@pytest.mark.parametrize('model', ['AIR3', 'MINI3'])
@pytest.mark.parametrize('service_args', [
    ['CameraCalib', 'EncryptPair'], ['FlycParam', 'list'],
])
def test_newer_gimbal_selector_rejects_unvalidated_services(
        monkeypatch, model, service_args):
    import sys
    import comm_og_service_tool as service

    def unexpected_open(*args):
        pytest.fail('unsupported {:s} service opened the connection'.format(model))

    monkeypatch.setattr(service, 'open_serial_port', unexpected_open)
    monkeypatch.setattr(sys, 'argv', [
        'comm_og_service_tool.py', '--port', '/dev/ttyUSB1', model,
        *service_args])
    with pytest.raises(SystemExit) as exc:
        service.main()
    assert exc.value.code == 2


@pytest.mark.parametrize('model,expected,ceiling', [
    ('WM100', 30000, None), ('WM260', 30000, None), ('AIR3', 55000, 120000),
    ('WM163', 55000, 120000),
])
def test_linear_hall_model_deadlines(monkeypatch, model, expected, ceiling):
    from types import SimpleNamespace
    from unittest.mock import Mock
    import comm_og_service_tool as service

    monkeypatch.setattr(service, 'gimbal_calib_request_spark',
                        lambda *args: (None, b''))
    monitor = Mock()
    monkeypatch.setattr(service, 'gimbal_calib_request_spark_monitor_progress',
                        monitor)
    service.do_gimbal_calib_request_spark_linear_hall(
        SimpleNamespace(product=service.PRODUCT_CODE[model]), None)
    assert monitor.call_args.args[4] == expected
    assert monitor.call_args.kwargs['max_duration'] == ceiling


def make_mini3_options(**kwargs):
    from types import SimpleNamespace
    import comm_og_service_tool as service

    options = dict(verbose=0, timeout=10, dry_test=True, bulk=False,
                   port='/dev/ttyACM0', baudrate=9600,
                   product=service.PRODUCT_CODE.WM163)
    options.update(kwargs)
    return SimpleNamespace(**options)


def test_mini3_keep_serial_mode_request_matches_dji_assistant():
    import comm_og_service_tool as service
    from comm_serialtalk import SerialMock

    service.last_seq_num = 0x1234
    po = make_mini3_options()
    ser = SerialMock(po.port, baudrate=po.baudrate, timeout=0)
    service.mini3_keep_serial_mode_request(po, ser)
    # Request captured from DJI Assistant: PC index 1 to type 31, seq 0x2710
    assert [bytes(pkt) for pkt in ser._txData] == [
        bytes.fromhex("55 0d 04 33 2a 1f 10 27 40 00 01 c2 4a")]
    # The fixed number must not leak into following requests
    assert service.last_seq_num == 0x1234


class FakeMini3Link:
    """Main module which answers only after a given number of requests."""

    def __init__(self, monkeypatch, answer_after=None):
        import comm_og_service_tool as service

        self.now = 0.0
        self.answer_after = answer_after
        self.events = []
        monkeypatch.setattr(service.time, 'monotonic', lambda: self.now)
        monkeypatch.setattr(service.time, 'sleep', self.sleep)
        monkeypatch.setattr(service, 'send_request_and_receive_reply', self.request)

    def sleep(self, seconds):
        self.now += seconds

    def request(self, po, ser, *args, **kwargs):
        self.events.append(('request', kwargs['seq_num'], kwargs['sender_index']))
        self.now += po.timeout / 1000
        requests = sum(1 for e in self.events if e[0] == 'request')
        if self.answer_after is not None and requests > self.answer_after:
            return b'reply', b''
        return None, b''

    def close(self):
        self.events.append(('close',))

    def open(self):
        self.events.append(('open',))


def test_mini3_keep_serial_mode_request_reopens_once_then_fails(monkeypatch):
    import comm_og_service_tool as service

    link = FakeMini3Link(monkeypatch)
    po = make_mini3_options(dry_test=False, timeout=500)
    with pytest.raises(ConnectionError):
        service.mini3_keep_serial_mode_request(po, link)
    requests = [e for e in link.events if e[0] == 'request']
    assert [e[1] for e in requests] == list(range(0x2710, 0x2710 + len(requests)))
    assert all(e[2] == 1 for e in requests)
    assert link.events.count(('close',)) == 1
    # Reopened after 3.5 sec without answer, i.e. after the 8th request
    assert link.events.index(('close',)) == 8
    assert link.now <= service.MINI3_KEEP_SERIAL_WINDOW + 0.5 + 0.1


def test_mini3_keep_serial_mode_request_answered_after_reopen(monkeypatch):
    import comm_og_service_tool as service

    link = FakeMini3Link(monkeypatch, answer_after=9)
    po = make_mini3_options(dry_test=False, timeout=500)
    service.mini3_keep_serial_mode_request(po, link)
    assert link.events[8:10] == [('close',), ('open',)]
    assert link.events[-1] == ('request', 0x2710 + 9, 1)


def test_mini3_port_is_waited_for_and_opened_like_dji_assistant(monkeypatch):
    import serial
    import comm_og_service_tool as service

    opened = []

    class FakeSerial:
        attempts = 0

        def open(self):
            FakeSerial.attempts += 1
            if FakeSerial.attempts < 3:
                raise serial.SerialException("port not present yet")
            opened.append((self.port, self.dtr, self.rts))

    monkeypatch.setattr(serial, 'Serial', FakeSerial)
    monkeypatch.setattr(service.time, 'sleep', lambda s: None)
    po = make_mini3_options(dry_test=False)
    ser, waited = service.open_serial_port_wait(po, '/dev/ttyACM0', 5)
    assert waited
    assert opened == [('/dev/ttyACM0', False, True)]
