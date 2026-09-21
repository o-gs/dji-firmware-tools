# -*- coding: utf-8 -*-

"""Tests for USB backend discovery."""

import os

import pytest

import comm_serialtalk


pytestmark = pytest.mark.comm


class FakeLibusbBackendLoader:
    def __init__(self, default_backend=None, path_backend=None):
        self.default_backend = default_backend
        self.path_backend = path_backend
        self.paths = []

    def get_backend(self, find_library=None):
        if find_library is None:
            return self.default_backend
        self.paths.append(find_library('usb-0.1'))
        return self.path_backend


def test_libusb_uses_system_backend_first():
    expected = object()
    loader = FakeLibusbBackendLoader(default_backend=expected)

    backend = comm_serialtalk.get_libusb_backend(loader)

    assert backend is expected
    assert loader.paths == []


def test_libusb_falls_back_to_dll_in_project_root(monkeypatch):
    expected = object()
    loader = FakeLibusbBackendLoader(path_backend=expected)
    monkeypatch.setattr(comm_serialtalk.os.path, 'isfile', lambda _: True)

    backend = comm_serialtalk.get_libusb_backend(loader)

    assert backend is expected
    assert loader.paths == [os.path.join(
      os.path.dirname(os.path.abspath(comm_serialtalk.__file__)),
      'libusb0.dll')]


def test_libusb_explicit_path_overrides_discovery():
    expected = object()
    loader = FakeLibusbBackendLoader(
      default_backend=object(), path_backend=expected)

    backend = comm_serialtalk.get_libusb_backend(
      loader, os.path.join('vendor', 'libusb0.dll'))

    assert backend is expected
    assert loader.paths == [os.path.abspath(
      os.path.join('vendor', 'libusb0.dll'))]


def test_libusb_error_explains_installation_options(monkeypatch):
    loader = FakeLibusbBackendLoader()
    monkeypatch.setattr(comm_serialtalk.os.path, 'isfile', lambda _: False)

    with pytest.raises(RuntimeError) as exinfo:
        comm_serialtalk.get_libusb_backend(loader)

    message = str(exinfo.value)
    assert 'No backend available' in message
    assert 'libusb0.dll' in message
    assert '--libusb-path' in message
    assert comm_serialtalk.LIBUSB_WIN32_DOWNLOAD_URL in message
