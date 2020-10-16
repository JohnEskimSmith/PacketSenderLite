import os

import pytest

from lib.core.loading import *
import pathlib


@pytest.fixture
def payloads_file() -> str:
    return os.path.join(pathlib.Path(__file__).parent.absolute(), 'data', 'payloads.py')


@pytest.fixture
def payloads_module() -> str:
    return 'lib.tests.data'


@pytest.fixture(params=['payloads_file', 'payloads_module'])
def module_or_file(request):
    return request.getfixturevalue(request.param)


@pytest.fixture
def generator_name() -> str:
    return 'generator_http_get'


def test_payload_generator_from_py_file(payloads_file, generator_name):
    generator = payload_generator_from_py_file(payloads_file, generator_name)
    payloads = list(generator('127.0.0.1', {}))
    assert payloads
    assert payloads[0]['payload']
    assert payloads[0]['data_payload']


def test_payload_generator_from_py_module(payloads_module, generator_name):
    generator = payload_generator_from_py_module(payloads_module, generator_name)
    payloads = list(generator('127.0.0.1', {}))
    assert payloads
    assert payloads[0]['payload']
    assert payloads[0]['data_payload']


def test_load_python_generator_payloads_from_file(module_or_file, generator_name):
    generator = load_python_generator_payloads_from_file(module_or_file, generator_name)
    payloads = list(generator('127.0.0.1', {}))
    assert payloads
    assert payloads[0]['payload']
    assert payloads[0]['data_payload']
