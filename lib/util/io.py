import asyncio
from base64 import b64decode
from typing import Any, Tuple

from lib.core import create_error_template, Target

__all__ = ['single_read', 'multi_read', 'write_to_stdout', 'write_to_file', 'decode_base64_string',
           'filter_bytes']


async def single_read(reader: asyncio.StreamReader,
                      target: Target,
                      custom_max_size: int = 0,
                      operation_description: str = '') -> Tuple[bool, Any]:
    # region old
    if not custom_max_size:
        future_reader = reader.read(target.max_size)
    else:
        future_reader = reader.read(custom_max_size)
    try:
        # через asyncio.wait_for - задаем время на чтение из соединения
        data = await asyncio.wait_for(future_reader, timeout=target.read_timeout)
        return True, data
    except Exception as e:
        result = create_error_template(target, type(e).__name__, description=operation_description)
        return False, result


# noinspection PyBroadException
async def multi_read(reader: asyncio.StreamReader, target: Target) -> Tuple[bool, Any]:
    count_size = target.max_size
    try:
        data = b''
        while True:
            try:
                future_reader = reader.read(count_size)
                _data = await asyncio.wait_for(future_reader, timeout=0.5)
                if _data:
                    data += _data
                    count_size = count_size - len(data)
                else:
                    break
                if count_size <= 0:
                    break
            except Exception:
                break

        if len(data) == 0:
            return False, create_error_template(target, 'empty')
        else:
            return True, data
    except Exception as e:
        return False, create_error_template(target, str(e))


async def write_to_stdout(io, record: str):
    """
    Write in 'wb' mode to io, input string in utf-8
    """
    return await io.write(record.encode('utf-8') + b'\n')


async def write_to_file(io, record: str):
    """
    Write in 'text' mode to io
    """
    return await io.write(record + '\n')


# noinspection PyBroadException
def decode_base64_string(string: str, encoding='utf-8') -> bytes:
    """
    Tries to decode base64 string
    """
    try:
        return b64decode(string.encode(encoding))
    except Exception:
        pass


def filter_bytes(buffer: bytes, target: Target) -> bool:
    """
    Checks given bytes for matches across target's search_values field.
    Returns True if there are not search_values
    """
    return not target.search_values or any(x in buffer for x in target.search_values)
