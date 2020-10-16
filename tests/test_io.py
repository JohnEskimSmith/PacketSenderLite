from collections import namedtuple

import pytest

from lib.util import filter_bytes, decode_base64_string

BytesTarget = namedtuple('FakeTarget', 'search_values')


@pytest.mark.parametrize('outcome,have,want', [
    (True, b'123', [b'123']),
    (True, b'123', [b'456', b'123']),
    (True, b'1234', [b'456', b'123']),
    (False, b'1234', [b'456', b'789']),
    (False, b'12', [b'456', b'123']),
    (True, b'', []),
    (True, b'', [b''])
])
def test_filter_bytes(outcome, have, want):
    target = BytesTarget(search_values=want)
    assert filter_bytes(have, target) == outcome


@pytest.mark.parametrize('raw,expected', [
    ('aGk=', b'hi'),
    ('', b''),
    ('definitely not base64', None)
])
def test_decode_base64_string(raw, expected):
    assert decode_base64_string(raw) == expected
