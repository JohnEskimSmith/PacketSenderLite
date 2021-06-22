from lib.workers import TargetWorker
from lib.util import single_read, multi_read
from lib.core import create_error_template, make_document_from_response, Target
from bson.json_util import dumps as bson_json_dumps
import asyncio
from ujson import loads as ujson_loads
from bson import encode as bson_encode
from bson import decode as bson_decode
from bson import decode_all as bson_decode_all
from pathlib import Path
from typing import Dict

MSGHEADER_LEN = 16
OP_QUERY = 2004
QUERY_RESP_FAILED = 2
OP_COMMAND = 2010
OP_MSG = 2013


# copied function from zgrab2
def get_op_query(collname: str, query: bytes) -> bytes:
    flagslen = 4
    collname_len = len(collname) + 1
    nskiplen = 4
    nretlen = 4
    qlen = len(query)
    msglen = MSGHEADER_LEN + flagslen + collname_len + nskiplen + nretlen + qlen
    out = bytearray(msglen)
    _bytes = msglen.to_bytes(4, byteorder='little')
    for i, b in enumerate(_bytes):
        out[i] = b
    _bytes = OP_QUERY.to_bytes(4, byteorder='little')
    positiion = 12
    for i, b in enumerate(_bytes):
        out[i + positiion] = b
    idx = MSGHEADER_LEN + flagslen
    _bytes = bytearray(collname, encoding='utf-8')
    out[idx:idx + collname_len] = _bytes
    idx += collname_len + nskiplen
    v = 1
    _bytes = v.to_bytes(4, byteorder='little')
    out[idx:idx + nretlen] = _bytes
    idx += nretlen
    out[idx:idx + qlen] = query
    return out


# copied function from zgrab2
# getCommandMsg returns a mongodb message containing the specified BSON-encoded command.
# metdata and commandArgs expected to be BSON byte arrays.
def get_command_msg(database: str, command_name: str, metadata: bytes, command_args: bytes) -> bytes:
    dblen = len(database) + 1
    cnlen = len(command_name) + 1
    mdlen = len(metadata)
    calen = len(command_args)
    msglen = MSGHEADER_LEN + dblen + cnlen + len(metadata) + len(command_args)
    out = bytearray(msglen)
    # msg header
    _bytes = msglen.to_bytes(4, byteorder='little')
    for i, b in enumerate(_bytes):
        out[i] = b
    _bytes = OP_COMMAND.to_bytes(4, byteorder='little')
    for i, b in enumerate(_bytes):
        out[12 + i] = b
    idx = MSGHEADER_LEN
    _bytes = bytearray(database, encoding='utf-8')
    out[idx:idx + dblen] = bytearray(database, encoding='utf-8')
    idx += dblen
    out[idx:idx + cnlen] = bytearray(command_name, encoding='utf-8')
    idx += cnlen
    out[idx:idx + mdlen] = metadata
    idx += mdlen
    out[idx:idx + calen] = command_args
    return out


# copied function from zgrab2
def get_is_master_msg() -> bytes:
    query = bson_encode({'isMaster': 1})
    query_msg = get_op_query("admin.$cmd", query)
    return query_msg


# copied function from zgrab2
def get_build_info_command_msg() -> bytes:
    meta_data = bson_encode({'buildInfo': 1})
    command_args = bson_encode({})
    # "test" collection gleaned from tshark
    command_msg = get_command_msg("test", "buildInfo", meta_data, command_args)
    return command_msg


# copied function from zgrab2
# getOpMsg returns a mongodb OP_MSG message containing the specified BSON-encoded command.
# section expected to be BSON byte array.
def get_op_msg(section: bytes) -> bytes:
    flagslen = 4
    slen = len(section)
    msglen = MSGHEADER_LEN + flagslen + slen
    out = bytearray(msglen)
    _bytes = msglen.to_bytes(4, byteorder='little')
    for i, b in enumerate(_bytes):
        out[i] = b
    _bytes = OP_MSG.to_bytes(4, byteorder='little')
    for i, b in enumerate(_bytes):
        out[12 + i] = b
    idx = MSGHEADER_LEN + flagslen
    out[idx:idx + slen] = section
    return out


# copied function from zgrab2: getBuildInfoOpMsg
# gleaned from tshark
def get_build_info_op_msg() -> bytes:
    section_payload = bson_encode({"buildinfo": 1, "$db": "admin"})
    section = bytearray(len(section_payload) + 1)
    section[1:] = section_payload
    op_msg = get_op_msg(section)
    return op_msg


# add example function - return List DBs
def get_list_db_op_msg() -> bytes:
    section_payload = bson_encode({"listDatabases": 1, "$db": "admin"})
    section = bytearray(len(section_payload) + 1)
    section[1:] = section_payload
    op_msg = get_op_msg(section)
    return op_msg


# add example function - return List DBs
def get_logs_db_op_msg() -> bytes:
    section_payload = bson_encode({"getLog": "global", "$db": "admin"})
    section = bytearray(len(section_payload) + 1)
    section[1:] = section_payload
    op_msg = get_op_msg(section)
    return op_msg


def read_logs(document: Dict):
    try:
        for line in document['log']:
            print(line)
    except Exception as exp:
        print(exp)


class CustomError(Exception):
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
                    # 1. getIsMaster
                    message_out_is_master: bytes = get_is_master_msg()
                    writer.write(message_out_is_master)
                    await writer.drain()
                    await asyncio.sleep(0.001)
                    desc_text = "check isMaster"
                    status_data, answer = await single_read(reader, target,
                                                            custom_max_size=65535,
                                                            operation_description=desc_text)
                    if status_data:
                        doc_offset = MSGHEADER_LEN + 20
                        if len(answer) < doc_offset + 4:
                            error_message = f'Server truncated message - no query reply ' \
                                            f'({len(answer)} bytes: {answer.hex()})'
                            raise CustomError(error_message)
                        resp_flags = int.from_bytes(answer[MSGHEADER_LEN: MSGHEADER_LEN + 4], byteorder='little')
                        if resp_flags & QUERY_RESP_FAILED != 0:
                            error_message = "isMaster query failed"
                            raise CustomError(error_message)
                        doclen = int.from_bytes(answer[doc_offset: doc_offset + 4], byteorder='little')
                        if len(answer[doc_offset:]) < doclen:
                            error_message = f'Server truncated BSON reply doc ' \
                                            f'({len(answer[doc_offset:])} bytes: {answer.hex()})'
                            raise CustomError(error_message)
                        try:
                            decoded_doc = bson_decode(answer[doc_offset:])
                        except Exception as exp:
                            error_message = f'Server sent invalid BSON reply doc ' \
                                            f'({len(answer[doc_offset:])} bytes: {answer.hex()})'
                            raise CustomError(error_message)
                        else:
                            if decoded_doc:
                                addition_info = {}
                                _document_is_master = bson_json_dumps(decoded_doc)
                                result_payload = _document_is_master.encode('utf-8')
                                addition_info['is_master'] = ujson_loads(_document_is_master)
                                # Gleaned from wireshark - if "MaxWireVersion" is less than 7, then
                                # "build info" command should be sent in an OP_COMMAND with the query sent
                                # and response retrieved at "metadata" offset. At 7 and above, should
                                # be sent as an OP_MSG in the "section" field, and response is at "body" offset
                                if decoded_doc['maxWireVersion'] < 7:
                                    query: bytes = get_build_info_command_msg()
                                    resplen_offset = 4
                                    resp_offset = 0
                                else:
                                    query = get_build_info_op_msg()
                                    resplen_offset = 5
                                    resp_offset = 5
                                writer.write(query)
                                await writer.drain()
                                await asyncio.sleep(0.001)
                                status_data, answer = await single_read(reader, target,
                                                                        custom_max_size=65535,
                                                                        operation_description=desc_text)
                                if status_data:
                                    if len(answer) < MSGHEADER_LEN + resplen_offset:
                                        error_message = f'Server truncated message - no metadata doc ' \
                                                        f'({len(answer)} bytes: {answer.hex()})'
                                        raise CustomError(error_message)
                                    _tmp_value = answer[MSGHEADER_LEN: MSGHEADER_LEN + resplen_offset]
                                    responselen = int.from_bytes(_tmp_value, byteorder='little')
                                    if len(answer[MSGHEADER_LEN:]) < responselen:
                                        error_message = f'Server truncated BSON response doc ' \
                                                        f'({len(answer[MSGHEADER_LEN:])} bytes: {answer.hex()})'
                                        raise CustomError(error_message)
                                    try:
                                        _document_bytes = answer[MSGHEADER_LEN+resp_offset:]
                                        _data_buildinfo = bson_decode_all(_document_bytes)
                                    except Exception as exp:
                                        error_message = f'Server sent invalid BSON reply doc ' \
                                                        f'({len(answer[doc_offset:])} bytes: {answer.hex()})'
                                        raise CustomError(error_message)
                                    else:
                                        _document_buildinfo = bson_json_dumps(_data_buildinfo)
                                        try:
                                            addition_info['build_info'] = ujson_loads(_document_buildinfo)
                                            _document_buildinfo_str_bytes = _document_buildinfo.encode('utf-8')
                                        except:
                                            pass
                                        result_payload = result_payload + b'\n'+_document_buildinfo_str_bytes

                                # try return list databases
                                query: bytes = get_list_db_op_msg()
                                resplen_offset = 5
                                resp_offset = 5
                                writer.write(query)
                                await writer.drain()
                                await asyncio.sleep(0.001)
                                status_data, answer = await single_read(reader, target,
                                                                        custom_max_size=65535,
                                                                        operation_description=desc_text)
                                if status_data:
                                    if len(answer) < MSGHEADER_LEN + resplen_offset:
                                        error_message = f'Server truncated message - no metadata doc ' \
                                                        f'({len(answer)} bytes: {answer.hex()})'
                                        raise CustomError(error_message)
                                    responselen = int.from_bytes(answer[MSGHEADER_LEN: MSGHEADER_LEN + resplen_offset],
                                                                 byteorder='little')
                                    if len(answer[MSGHEADER_LEN:]) < responselen:
                                        error_message = f'Server truncated BSON response doc ' \
                                                        f'({len(answer[MSGHEADER_LEN:])} bytes: {answer.hex()})'
                                        raise CustomError(error_message)
                                    try:
                                        _data_listdb = bson_decode_all(answer[MSGHEADER_LEN + resp_offset:])
                                    except Exception as exp:
                                        error_message = f'Server sent invalid BSON reply doc ' \
                                                        f'({len(answer[doc_offset:])} bytes: {answer.hex()})'
                                        raise CustomError(error_message)
                                    else:
                                        _document_listdb = bson_json_dumps(_data_listdb)
                                        try:
                                            _dbs = ujson_loads(_document_listdb)
                                            if len(_dbs) == 1:
                                                addition_info['list_db'] = {'databases': _dbs[0]['databases'],
                                                                            'total_size': _dbs[0]['totalSize']}
                                            else:
                                                addition_info['list_dbs'] = _dbs
                                            _document_listdb_str_bytes = _document_listdb.encode('utf-8')
                                        except:
                                            pass
                                        result_payload = result_payload + b'\n' + _document_buildinfo_str_bytes

                                # try return logs mongodb
                                query: bytes = get_logs_db_op_msg()
                                resplen_offset = 5
                                resp_offset = 5
                                writer.write(query)
                                await writer.drain()
                                await asyncio.sleep(0.001)
                                status_data, answer = await multi_read(reader, target)
                                if status_data:
                                    try:
                                        print(len(answer))
                                        _data_logs_mongodb = bson_decode(answer[MSGHEADER_LEN + resp_offset:])
                                    except Exception as exp:
                                        print(exp)
                                    else:
                                        read_logs(_data_logs_mongodb)

                                # -----------------------------------------------------
                                result = make_document_from_response(result_payload,
                                                                     target,
                                                                     addition_dict=addition_info,
                                                                     protocol=protocol_name_like_filename)
                                await asyncio.sleep(0.005)
                        try:
                            writer.close()
                        except BaseException:
                            pass
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

