from lib.workers import TargetWorker
from lib.util import single_read, multi_read
from lib.core import create_error_template, make_document_from_response, Target
import asyncio

from pathlib import Path
from typing import Dict, Optional
from ipaddress import ip_address

CONST_REG_SESSION_65 = bytes.fromhex('65000400000000000000000000000000000000000000000001000000')
CONST_LIST_IDENTITY = bytes.fromhex('630000000000000000000000000000000000000000000000')


def unpack_list_identity(response: bytes) -> Optional[Dict]:
    try:
        length = int.from_bytes(response[2:4], 'little')
        session_id = int.from_bytes(response[4:8], 'little')
        status_int = int.from_bytes(response[8:12], 'little')
        if status_int != 0:
            status = 'failed'
        else:
            status = 'success'

        update_payload = response[len(response)-length:]
        item_count = int.from_bytes(update_payload[0:2], 'little')
        type_id = bytes(reversed(update_payload[2:4])).hex()
        encapsulation_protocol_version = int.from_bytes(update_payload[6:8], 'little')
        sin_family = int.from_bytes(update_payload[8:10], 'big')
        sin_port = int.from_bytes(update_payload[10:12], 'big')
        try:
            sin_address = str(ip_address(int.from_bytes(update_payload[12:16], 'big')))
        except:
            sin_address = ''
        sin_zero = update_payload[16:24].hex()
        socket_address = {'sin_family': sin_family,
                          'sin_port': sin_port,
                           'sin_address': sin_address,
                          'sin_zero': sin_zero}

        vendor_id = int.from_bytes(update_payload[24:26], 'little')
        if vendor_id == 1:
            vendor_info = 'Rockwell Automation/Allen-Bradley'
        else:
            vendor_info = 'unknown'
        vendor = {'id': vendor_id,
                  'info': vendor_info}
        device_type_id = int.from_bytes(update_payload[26:28], 'little')
        if device_type_id == 14:
            device_type_info = 'Programmable Logic Controller'
        else:
            device_type_info = 'unknown'
        product_code = int.from_bytes(update_payload[28:30], 'little')
        product_revision = int.from_bytes(update_payload[30:32], 'little')
        status_code = bytes(reversed(update_payload[32:34])).hex()
        serial_code_hex = bytes(reversed(update_payload[34:38])).hex()
        serial_code_int = int.from_bytes(update_payload[34:38], 'little')
        len_productname = int(update_payload[38])
        product_name = update_payload[39: 39+len_productname].decode('ascii')
        state = int.from_bytes(update_payload[39+len_productname:], 'little')
        result = {'status':{'value': status_int,
                            'text': status},
                  'item_count': item_count,
                  'type_id': type_id,
                  'protocol_version': encapsulation_protocol_version,
                  'socket_address': socket_address,
                  'vendor': vendor,
                  'device': {'id': device_type_id,
                             'text': device_type_info},
                  'product_code': product_code,
                  'product_revision': product_revision,
                  'status_code': status_code,
                  'serial': {'hex':serial_code_hex,
                             'value': serial_code_int},
                  'product_name': product_name,
                  'state': state
                  }
        return result
    except:
        pass

class CustomWorker(TargetWorker):
    async def do(self, target: Target):
        protocol_name_like_filename = Path(__file__).stem
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
                    # 1. register Session
                    payload_register_session: bytes = CONST_REG_SESSION_65
                    writer.write(payload_register_session)
                    await writer.drain()
                    await asyncio.sleep(0.001)
                    desc_text = "try register"
                    status_data, answer = await single_read(reader, target,
                                                            custom_max_size=2000,
                                                            operation_description=desc_text)
                    if status_data:
                        session_bytes = CONST_LIST_IDENTITY[0:4]+answer[4:8]+CONST_LIST_IDENTITY[8:]
                        writer.write(session_bytes)
                        await writer.drain()
                        await asyncio.sleep(0.001)
                        desc_text = "list identity"
                        status_data, answer = await single_read(reader, target,
                                                                custom_max_size=2000,
                                                                operation_description=desc_text)
                        if status_data:
                            if answer[:2] == bytes.fromhex('6300'):
                            # -----------------------------------------------------
                                upack_value = unpack_list_identity(answer)
                                result = make_document_from_response(answer,
                                                                     target,
                                                                     addition_dict=upack_value,
                                                                     protocol=protocol_name_like_filename)
                            else:
                                result = make_document_from_response(answer,
                                                                     target,
                                                                     addition_dict={'strange': True},
                                                                     protocol=protocol_name_like_filename)
                except Exception as exp:
                    result = create_error_template(target, str(exp))
                    try:
                        future_connection.close()
                    except Exception:
                        pass
                    await asyncio.sleep(0.005)
                    try:
                        writer.close()
                    except Exception:
                        pass
            await self.send_result(result)


