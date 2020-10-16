import pytest

from lib.util import is_ip, is_network


@pytest.mark.parametrize('func,addr,expected', [
    (is_ip, '127.0.0.1', True),
    (is_ip, '1.1.1.1', True),
    (is_ip, 12345678, True),
    (is_ip, '::1', True),
    (is_ip, '', False),
    (is_ip, 'example.com', False),

    (is_network, '127.0.0.1', True),
    (is_network, '8.8.8.8', True),
    (is_network, '192.168.0.1/32', True),
    (is_network, '::1', True),
    (is_ip, '', False),
    (is_ip, 'example.com', False),

])
def test_is_ip(func, addr, expected):
    assert func(addr) == expected
