import pytest

from lib.util import access_dot_path


@pytest.fixture
def some_dict():
    return {
        'abc': {
            'def':
                'some value'
        },
        '123': {
            '456':
                1337

        }
    }


@pytest.mark.parametrize('path,expected', [
    ('abc.def', 'some value'),
    ('123.456', 1337),
    ('nothing.here', None)
])
def test_access_dot_path(some_dict, path, expected):
    assert access_dot_path(some_dict, path) == expected

