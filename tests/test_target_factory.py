import pytest

from lib.core import TargetConfig, Target
from lib.workers import create_targets_tcp_protocol


@pytest.fixture
def settings():
    return TargetConfig(**{
        'port': 80,
        'ssl_check': False,
        'conn_timeout': 7,
        'read_timeout': 7,
        'ssl_timeout': 7,
        'list_payloads': [],
        'search_values': [],
        'max_size': 1024,
        'python_payloads': [],
        'generator_payloads': [],
        'mode': 'single',
        'without_hexdump': False
    })


@pytest.mark.parametrize('target_address,length', [
    ('192.168.0.1', 1),
    ('192.168.0.1/24', 256),
])
def test_targets_factory_ip(settings, target_address, length):
    iterator = create_targets_tcp_protocol(target_address, settings)
    listed = list(iterator)
    assert len(listed) == length  # assert network expands correctly
    target = listed[0]

    attributes = list(settings.__dict__)

    assert isinstance(target, Target)
    for attribute in attributes:  # assert all necessary attributes exist
        assert hasattr(target, attribute)
