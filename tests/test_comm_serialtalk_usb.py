# -*- coding: utf-8 -*-

"""Backend discovery tests; native libraries and USB hardware are not used."""

import os
from ctypes import sizeof, c_void_p
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import comm_serialtalk as serialtalk


pytestmark = pytest.mark.comm


@pytest.fixture
def usb_backends(monkeypatch):
    core = pytest.importorskip('usb.core')
    import usb.backend.libusb0 as libusb0
    import usb.backend.libusb1 as libusb1
    import usb.backend.openusb as openusb

    for backend in (libusb0, libusb1, openusb):
        monkeypatch.setattr(backend, 'get_backend', Mock(return_value=None))
    monkeypatch.setattr(serialtalk.sys, 'platform', 'win32')
    monkeypatch.setattr(serialtalk.os.path, 'isfile', lambda _: False)
    return SimpleNamespace(core=core, legacy=libusb0, modern=libusb1)


def backend_without_devices():
    return SimpleNamespace(enumerate_devices=Mock(return_value=iter([])))


def test_system_libusb0_remains_preferred(usb_backends):
    backend = backend_without_devices()
    usb_backends.legacy.get_backend.return_value = backend

    assert list(serialtalk.find_usb_devices()) == []
    backend.enumerate_devices.assert_called_once_with()
    usb_backends.modern.get_backend.assert_not_called()


def test_pyusb_fallback_when_only_libusb1_is_available(usb_backends):
    backend = backend_without_devices()
    usb_backends.modern.get_backend.return_value = backend

    assert list(serialtalk.find_usb_devices()) == []
    backend.enumerate_devices.assert_called_once_with()


def test_local_dll_is_relative_to_script_not_cwd(
        usb_backends, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(serialtalk.os.path, 'isfile', lambda _: True)
    backend = backend_without_devices()
    paths = []

    def load(find_library=None):
        if find_library:
            paths.append(find_library('usb-0.1'))
            return backend
        return None

    usb_backends.legacy.get_backend.side_effect = load
    assert list(serialtalk.find_usb_devices()) == []
    assert paths == [os.path.join(
        os.path.dirname(os.path.abspath(serialtalk.__file__)), 'libusb0.dll')]


def test_explicit_path_overrides_system_backend(usb_backends):
    backend = backend_without_devices()
    usb_backends.legacy.get_backend.return_value = backend

    assert list(serialtalk.find_usb_devices('vendor/libusb0.dll')) == []
    callback = usb_backends.legacy.get_backend.call_args.kwargs['find_library']
    assert callback('usb-0.1') == os.path.abspath('vendor/libusb0.dll')
    usb_backends.modern.get_backend.assert_not_called()


def test_invalid_override_does_not_silently_fall_back(usb_backends):
    usb_backends.modern.get_backend.return_value = backend_without_devices()
    with pytest.raises(usb_backends.core.NoBackendError) as error:
        serialtalk.find_usb_devices('bad/libusb0.dll')
    assert os.path.abspath('bad/libusb0.dll') in str(error.value)
    assert '{}-bit'.format(sizeof(c_void_p) * 8) in str(error.value)
    usb_backends.modern.get_backend.assert_not_called()


@pytest.mark.parametrize('dll_exists', [False, True])
def test_windows_missing_or_unloadable_dll_has_actionable_error(
        usb_backends, monkeypatch, dll_exists):
    monkeypatch.setattr(serialtalk.os.path, 'isfile', lambda _: dll_exists)
    with pytest.raises(usb_backends.core.NoBackendError) as error:
        serialtalk.find_usb_devices()
    message = str(error.value)
    assert 'No backend available' in message
    assert 'libusb0.dll' in message
    assert '{}-bit'.format(sizeof(c_void_p) * 8) in message
    assert '--libusb-path' in message
    assert serialtalk.LIBUSB_WIN32_DOWNLOAD_URL in message


def test_non_windows_does_not_try_dll_or_offer_windows_advice(
        usb_backends, monkeypatch):
    monkeypatch.setattr(serialtalk.sys, 'platform', 'linux')
    isfile = Mock(return_value=True)
    monkeypatch.setattr(serialtalk.os.path, 'isfile', isfile)
    with pytest.raises(usb_backends.core.NoBackendError) as error:
        serialtalk.find_usb_devices()
    isfile.assert_not_called()
    assert 'system package manager' in str(error.value)
    assert 'libusb0.dll' not in str(error.value)
    assert 'sourceforge' not in str(error.value)


def test_device_access_error_is_not_reported_as_missing_library(usb_backends):
    error = usb_backends.core.USBError('Access denied')
    backend = SimpleNamespace(enumerate_devices=Mock(side_effect=error))
    usb_backends.legacy.get_backend.return_value = backend
    with pytest.raises(usb_backends.core.USBError) as caught:
        list(serialtalk.find_usb_devices())
    assert caught.value is error
