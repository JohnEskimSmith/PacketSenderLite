from lib.workers import TargetWorker
from lib.util import single_read, access_dot_path
from lib.core import create_error_template, make_document_from_response, Target

from random import randint # from researcher
from struct import pack, unpack # from researcher
from binascii import hexlify # from researcher
from ujson import dumps as ujson_dumps
import asyncio

# region data from researcher
class KeyStream:
    def __init__(self, key_data):
        self._key_data = key_data
        self._encrypt_pos = 0
        self._decrypt_pos = 0

    @property
    def key_data(self):
        return self._key_data

    def encrypt(self, data) -> bytes:
        result = []
        for x in data:
            result.append(x ^ self._key_data[self._encrypt_pos])
            self._encrypt_pos = (self._encrypt_pos + 1) % len(self._key_data)
        return bytes(result)

    def decrypt(self, data) -> bytes:
        result = []
        for x in data:
            result.append(x ^ self._key_data[self._decrypt_pos])
            self._decrypt_pos = (self._decrypt_pos + 1) % len(self._key_data)
        return bytes(result)

COMMANDS = [0x200, 0x400, 0x700, 0x800, 0x500, 0x300, 0x600, 0x100, 3, 2, 0, 1]
SECRET = [i for i in range(28)]
FULL_SIZE = 0x20
TLS_ClientHello = [0x16,
                   0xFF, 0xFE,  # <---- Invalid ProtocolVersion
                   0x00, 0x41, 0x01,
                   0x00, 0x00, 0x3D,
                   0xFF, 0xFE,  # <---- Invalid ProtocolVersion
                   0xAA, 0xBB, 0xCC, 0xDD,  # <---- Invalid TimeStamp
                   0x1C, 0x15, 0x23, 0x05, 0x59,
                   0xC5, 0x03, 0xE9, 0x52, 0x7C, 0xD8, 0x27, 0xF7, 0xC7, 0x04,
                   0x00, 0x9F, 0x6D, 0x52, 0x3C, 0x4C, 0xAD, 0xD3, 0xF0, 0xFA,
                   0xD1, 0x54, 0x64, 0x00, 0x00, 0x16, 0x00, 0x04, 0x00, 0x05,
                   0x00, 0x0A, 0x00, 0x09, 0x00, 0x64, 0x00, 0x62, 0x00, 0x03,
                   0x00, 0x06, 0x00, 0x13, 0x00, 0x12, 0x00, 0x63, 0x01, 0x00]
TLS_HelloRequest = [0x16,
                    0xFF, 0xFE,  # <---- Invalid ProtocolVersion
                    0x01, 0x06, 0x10,
                    0x00, 0x01, 0x02, 0x01,
                    0x00, 0x23, 0xBB, 0xF5, 0xEC, 0xE5, 0xCB, 0x6D, 0x76, 0x50,
                    0x9F, 0x1D, 0x37, 0x64, 0x81, 0x93, 0x3A, 0x04, 0xA1, 0x90,
                    0x1F, 0x90, 0x86, 0x42, 0xD7, 0xD2, 0xA9, 0x46, 0x9C, 0xA9,
                    0x4D, 0x87, 0x40, 0x11, 0xBD, 0xAB, 0xF1, 0x43, 0xE8, 0x19,
                    0xCD, 0xE1, 0xD5, 0xAB, 0x05, 0xD2, 0xB4, 0x4E, 0xCB, 0x06,
                    0x61, 0xFD, 0x43, 0x7B, 0xCB, 0xD8, 0x7D, 0x7E, 0x33, 0x36,
                    0x6E, 0x01, 0x37, 0x9A, 0x37, 0x6E, 0xD5, 0xD9, 0x38, 0x93,
                    0x1E, 0x8C, 0x13, 0x40, 0x7C, 0x29, 0xD4, 0xCF, 0x1A, 0xBE,
                    0xC2, 0x9E, 0xD2, 0x11, 0x59, 0xDF, 0xE3, 0xE4, 0xE6, 0x31,
                    0xA4, 0x2D, 0x84, 0x13, 0x41, 0x7E, 0x8C, 0x36, 0x21, 0x16,
                    0xDF, 0xB9, 0x1B, 0xF6, 0x79, 0xCF, 0xD2, 0xE6, 0x55, 0xAD,
                    0xA9, 0x16, 0x0D, 0xB9, 0xDC, 0x57, 0x34, 0x8F, 0x24, 0x68,
                    0x20, 0x35, 0x37, 0xEE, 0xF7, 0xA5, 0x0E, 0x46, 0x21, 0x74,
                    0x5C, 0x14, 0x0A, 0x3F, 0x24, 0x8A, 0xCB, 0x86, 0x63, 0xC1,
                    0xDC, 0x15, 0x57, 0xB0, 0xD9, 0xF8, 0x76, 0xFA, 0xC6, 0x65,
                    0xE6, 0x66, 0x96, 0x79, 0xCA, 0xE5, 0x82, 0x30, 0xDB, 0x70,
                    0x16, 0xB7, 0xA4, 0xA0, 0x7E, 0xC5, 0x0D, 0xDE, 0x41, 0xC0,
                    0xB7, 0x45, 0x43, 0x4C, 0xE5, 0x4B, 0x58, 0x50, 0x03, 0xE0,
                    0xF8, 0x28, 0x7F, 0xEA, 0x9A, 0xE8, 0xE0, 0xD9, 0xA2, 0x7E,
                    0x59, 0x01, 0x4F, 0xE9, 0xAE, 0xC2, 0xA0, 0x9B, 0xFB, 0x4F,
                    0x24, 0xE3, 0x6C, 0x22, 0xDF, 0x5D, 0xCB, 0x9D, 0x07, 0xA7,
                    0x03, 0xBD, 0x36, 0x20, 0x31, 0x76, 0x34, 0x11, 0x45, 0x2A,
                    0x06, 0xBB, 0x7B, 0x93, 0x3E, 0xE5, 0x04, 0x93, 0x03, 0x81,
                    0x36, 0xEB, 0x4F, 0x18, 0x9D, 0x6C, 0x54, 0x51, 0x1A, 0x6C,
                    0xD4, 0x57, 0x5B, 0xB4, 0x7D, 0xB3, 0x77, 0xEC, 0x80, 0x61,
                    0x14, 0xCE, 0x4F, 0xFA, 0xF7, 0x9D, 0xD1, 0x14, 0x03, 0x01,
                    0x00, 0x01, 0x01, 0x16, 0x03, 0x01,
                    0x00, 0x38,
                    0xF8, 0x2A, 0xE2, 0x2B, 0xB9, 0x09, 0xDF, 0x14, 0xFC, 0x68,
                    0xB9, 0x30, 0xBD, 0x8A, 0x01, 0xC7, 0x65, 0x02, 0x8D, 0x21,
                    0xCE, 0x59, 0xFF, 0xFE, 0x92, 0x37, 0xAD, 0x12, 0x2A, 0xDD,
                    0xE2, 0x14, 0xFF, 0xFE, 0x92, 0x37, 0xAD, 0x12, 0x2A, 0xDD,
                    0xE2, 0x14, 0xFF, 0xFE, 0x92, 0x37, 0xAD, 0x12, 0x2A, 0xDD,
                    0xE2, 0x14, 0x11, 0x22, 0x33, 0x44]


def pack_payload(key: KeyStream, data: bytes) -> bytes:
    return b"\x17\x03\x01" + pack(">H", len(data)) + key.encrypt(data)


def derive_key(secret: bytes) -> KeyStream:
    key_data = []
    for i in range(len(secret)):
        b = (secret[i] ^ SECRET[i] ^ (i ^ 0xFF)) & 0xff
        if not b:
            b = (i ^ 0xFF)
        key_data.append(b)
    return KeyStream(bytes(key_data))
# endregion


class CustomWorker(TargetWorker):
    async def do(self, target: Target):
        async with self.semaphore:
            result = None
            future_connection = asyncio.open_connection(target.ip, target.port)
            try:
                reader, writer = await asyncio.wait_for(future_connection, timeout=target.conn_timeout)
            except Exception as e:
                await asyncio.sleep(0.005)
                try:
                    future_connection.close()
                    del future_connection
                except Exception as e:
                    pass
                result = create_error_template(target, str(e))
            else:
                try:
                    for i in range(15, 43):
                        TLS_ClientHello[i] = (TLS_ClientHello[i] ^ randint(0, 4294967294)) & 0xFF
                    writer.write(bytes(TLS_ClientHello))
                    await writer.drain()
                    await asyncio.sleep(0.05)
                    desc_text = '1 step: read 65535 bytes'
                    status_data, answer = await single_read(reader, target,
                                                            custom_max_size=65535,
                                                            operation_description=desc_text)
                    if status_data:
                        if answer[0] != 0x16:
                            message_error_text = "Not a C2. TLS ContentType state"
                            raise AssertionError(message_error_text)
                        if answer[5] != 0x02:
                            message_error_text = f"Not a C2. Expected ServerHello (02) got ({answer[5]:02X})"
                            raise AssertionError(message_error_text)

                        for i in range(15, 267):
                            TLS_HelloRequest[i] = (TLS_HelloRequest[i] ^ randint(0, 4294967294)) & 0xFF

                        packed_size = pack(">H", FULL_SIZE)
                        for i, j in enumerate(range(276, 278)):
                            TLS_HelloRequest[j] = packed_size[i]

                        for i, j in enumerate(range(278, 278 + len(SECRET))):
                            TLS_HelloRequest[j] = SECRET[i]

                        for i in range(278 + len(SECRET), 278 + FULL_SIZE):
                            TLS_HelloRequest[i] = (TLS_HelloRequest[i] ^ randint(0, 4294967294)) & 0xFF

                        writer.write(bytes(TLS_HelloRequest))
                        await writer.drain()
                        await asyncio.sleep(0.05)
                        desc_text = f'2 step: read 5 bytes, timeout={target.read_timeout}'
                        status_data, answer = await single_read(reader,
                                                                target,
                                                                custom_max_size=5,
                                                                operation_description=desc_text)
                        if status_data:
                            if answer[0] != 0x14:
                                message_error_text = f"Not a C2. Expected ChangeCipherSpec (0x14) got ({answer[0]:02X})"
                                raise AssertionError(message_error_text)
                            length = unpack(">H", bytes(answer[3:]))[0]
                            if length > 0x3ff9:
                                message_error_text = f"Not a C2. ChangeCipherSpec too big"
                                raise AssertionError(message_error_text)
                            await asyncio.sleep(0.05)
                            desc_text = f'3 step: read {length}+5 bytes, timeout={target.read_timeout}'
                            status_data, _answer = await single_read(reader,
                                                                     target,
                                                                     custom_max_size=length+5,
                                                                     operation_description=desc_text)
                            await asyncio.sleep(0.05)
                            if status_data:
                                answer = _answer[-5:]
                                if answer[0] != 0x16:
                                    message_error_text = f"Not a C2. Expected Handshake (0x16) got ({answer[0]:02X})"
                                    raise AssertionError(message_error_text)

                                length = unpack(">H", bytes(answer[3:]))[0]
                                if length > 0x3ff9:
                                    message_error_text = f"Not a C2. Handshake too big"
                                    raise AssertionError(message_error_text)
                                desc_text = f'4 step: read {length} bytes, timeout={target.read_timeout}'
                                status_data, answer = await single_read(reader,
                                                                        target,
                                                                        custom_max_size=length,
                                                                        operation_description=desc_text)
                                if status_data:
                                    server_secret = answer[:len(SECRET)]
                                    key_stream = derive_key(server_secret)
                                    need_payload = pack_payload(key_stream,
                                                                  pack("<H", 0x200) + \
                                                                  pack("<H", 0x03) + \
                                                                  b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
                                    writer.write(need_payload)
                                    await writer.drain()
                                    await asyncio.sleep(0.05)
                                    desc_text = f'5 step: read 5 bytes, timeout={target.read_timeout}'
                                    status_data, answer = await single_read(reader,
                                                                            target,
                                                                            custom_max_size=5,
                                                                            operation_description=desc_text)
                                    length = unpack(">H", bytes(answer[3:]))[0]
                                    desc_text = f'6 step: read {length} bytes, timeout={target.read_timeout}'
                                    status_data, answer = await single_read(reader,
                                                                            target,
                                                                            custom_max_size=length,
                                                                            operation_description=desc_text)
                                    c2_answer = key_stream.decrypt(answer)
                                    command_id = unpack("<H", c2_answer[:2])[0]
                                    module_id = unpack("<H", c2_answer[2:4])[0]
                                    if command_id not in COMMANDS:
                                        message_error_text = f"Not a C2. Invalid response command id"
                                        raise AssertionError(message_error_text)
                                    if module_id != 3:
                                        message_error_text = f"Not a C2. Invalid response module id"
                                        raise AssertionError(message_error_text)
                                    result = make_document_from_response(b'C2 found', target)
                                    await asyncio.sleep(0.005)
                                else:
                                    result = answer
                            else:
                                result = _answer
                        else:
                            result = answer
                    else:
                        result = answer  # get errors
                    try:
                        writer.close()
                    except BaseException:
                        pass
                except AssertionError as e:
                    result = create_error_template(target, str(e))
                    try:
                        future_connection.close()
                    except Exception:
                        pass
                    await asyncio.sleep(0.005)
                    try:
                        writer.close()
                    except Exception:
                        pass
                except Exception as e:
                    result = create_error_template(target, str(e))
                    try:
                        future_connection.close()
                    except Exception:
                        pass
                    await asyncio.sleep(0.005)
                    try:
                        writer.close()
                    except Exception:
                        pass

            if result:
                try:
                    success = access_dot_path(result, 'data.tcp.status')
                except:
                    success = 'unknown-error'
                try:
                    content_length = int(access_dot_path(result, 'data.tcp.result.response.content_length'))
                except:
                    content_length = 0

                if self.stats:
                    if success == 'success':
                        self.stats.count_good += 1
                    else:
                        self.stats.count_error += 1

                line = None
                line_out = None
                try:
                    if self.success_only:
                        if success == 'success':
                            line = result
                    else:
                        line = result
                except Exception:
                    pass

                if line:
                    if self.body_not_empty:
                        if content_length > 0:
                            line_out = ujson_dumps(line)
                    else:
                        line_out = ujson_dumps(line)

                if line_out:
                    await self.output_queue.put(line_out)
