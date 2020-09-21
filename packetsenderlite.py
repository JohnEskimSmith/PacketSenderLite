#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "SAI"
__license__ = "GPLv3"
__status__ = "Dev"

from aioconsole import ainput
from ipaddress import ip_address, ip_network
from ssl import _create_unverified_context as ssl_create_unverified_context
from collections import namedtuple
from aiofiles import open as aiofiles_open

from pathlib import Path
from os import pathsep
from os import path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from ujson import dumps as ujson_dumps

from hashlib import sha256, sha1, md5
from hexdump import hexdump
import asyncio
import argparse
import datetime
import copy
import importlib
import uvloop

from base64 import (standard_b64encode as base64_standard_b64encode,
                    b64encode as base64_b64encode,
                    b64decode as base64_b64decode,
                    )


from typing import (Any,
                    Callable,
                    Iterable,
                    NamedTuple,
                    Iterator,
                    List,
                    BinaryIO,
                    TextIO,
                    Tuple)


def dict_paths(some_dict: dict,
               path: set = ()):
    """
    Итератор по ключам в словаре
    :param some_dict:
    :param path:
    :return:
    """
    for key, value in some_dict.items():
        key_path = path + (key,)
        yield key_path
        if hasattr(value, 'items'):
            yield from dict_paths(value, key_path)


def check_path(some_dict: dict,
               path_sting: str) -> bool:
    """
    Проверяет наличие ключа
    :param some_dict:
    :param path_sting:
    :return:
    """
    if isinstance(some_dict, dict):
        all_paths = set(['.'.join(p) for p in dict_paths(some_dict)])
        if path_sting in all_paths:
            return True


def return_value_from_dict(some_dict: dict,
                           path_string: str) -> Any:
    """
    Возвращает значение ключа в словаре по пути ключа "key.subkey.subsubkey"
    :param some_dict:
    :param path_string:
    :return:
    """
    if check_path(some_dict, path_string):
        keys = path_string.split('.')
        _c = some_dict.copy()
        for k in keys:
            _c = _c[k]
        return _c


def check_ip(ip_str: str) -> bool:
    """
    Проверка строки на ip адрес
    :param ip_str:
    :return:
    """
    try:
        ip_address(ip_str)
        return True
    except BaseException:
        return False


def check_network(net_str: str) -> bool:
    """
    Проверка строки на ip адрес сети
    :param net_str:
    :return:
    """
    try:
        ip_network(net_str)
        return True
    except BaseException:
        return False


def load_python_generator_payloads(
        name_module: str,
        name_function: str) -> Callable[[], Iterable]:
    """
    Загрузка модуля и функции из него, которая будет генерировать payloads.
    :param path_to_module:
    :param name_function:
    :return:
    """
    _mod = importlib.import_module(name_module)
    need_function = getattr(_mod, name_function)
    return need_function


def load_python_file(_path_to_module_py,
                     name_function: str) -> Callable[[], Iterable]:
    module_name_like_filename_py = str(_path_to_module_py).rstrip('.py')
    spec = importlib.util.spec_from_file_location(module_name_like_filename_py, _path_to_module_py)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    need_function = getattr(m, name_function)
    return need_function


def load_python_generator_payloads_from_file(
        _path_to_module_py: str,
        _name_function: str) -> Callable[[], Iterable]:
    if _path_to_module_py.endswith('.py'):
        if pathsep in _path_to_module_py:
            _path_to_file = Path(_path_to_module_py)
        else:
            PROJECT_ROOT = Path(__file__).parent
            _path_to_file = PROJECT_ROOT / _path_to_module_py
        try:
            if _path_to_file.exists() and _path_to_file.is_file():
                return load_python_file(_path_to_file, _name_function)
        except Exception as e:
            pass
    else:
        try:
            return load_python_generator_payloads(_path_to_module_py, _name_function)
        except Exception as e:
            pass


def create_target_tcp_protocol(ip_str: str,
                               settings: dict) -> Iterator:
    """
    На основании ip адреса и настроек возвращает через yield
    экзэмпляр namedtuple - Target.
    Каждый экземпляр Target содержит всю необходимую информацию(настройки и параметры) для функции worker.
    :param ip_str:
    :param settings:
    :return:
    """
    current_settings = copy.copy(settings)

    if current_settings['max_size'] != -1:
        # remember - in bytes, not kb
        current_settings['max_size'] = current_settings['max_size']

    key_names = list(current_settings.keys())
    key_names.extend(['ip', 'payload', 'additions'])
    Target = namedtuple('Target', key_names)
    current_settings['ip'] = ip_str
    if current_settings['list_payloads']:
        for payload in current_settings['list_payloads']:
            tmp_settings = copy.copy(current_settings)
            tmp_settings['payload'] = payload
            _payload_base64 = base64_standard_b64encode(
                payload).decode('utf-8')
            # _additions - необходимы для информации, какой payload был
            # направлен
            _additions = {'data_payload':
                              {'payload_raw': _payload_base64,
                               'variables': []}
                          }
            tmp_settings['additions'] = _additions
            target = Target(**tmp_settings)
            yield target
    elif current_settings['python_payloads']:
        name_function = 'generator_payloads'  # function name, default
        if current_settings['generator_payloads']:
            name_function = current_settings['generator_payloads'].strip('"').strip("'")
        path_to_module = current_settings['python_payloads'].strip('"').strip("'")
        generator_payloads = load_python_generator_payloads_from_file(
            path_to_module, name_function)
        for payload in generator_payloads(ip_str, settings):
            tmp_settings = copy.copy(current_settings)
            tmp_settings['payload'] = payload['payload']
            tmp_settings['additions'] = payload['data_payload']
            target = Target(**tmp_settings)
            yield target
    else:
        # отсутствует payload - фактически означает, "считывать баннеры
        # сервисов"
        current_settings['payload'] = None
        current_settings['additions'] = None
        target = Target(**current_settings)
        yield target


def create_targets_tcp_protocol(ip_str: str,
                                settings: dict) -> Iterator[NamedTuple]:
    """
    Функция для обработки "подсетей" и создания "целей"
    :param ip_str:
    :param settings:
    :return:
    """
    hosts = ip_network(ip_str, strict=False)
    for host in hosts:
        for target in create_target_tcp_protocol(str(host), settings):
            yield target


def create_template_struct(target: NamedTuple) -> dict:
    """
    вспомогательная функция, создает шаблон словаря заданной в коде структуры
    :return:
    """
    result = {'data':
                  {'tcp':
                       {'status': 'tcp',
                        'result':
                            {'response':
                                 {'request': {}
                                  }
                             }
                        }
                   }
              }
    if target.sslcheck:
        _tls_log = {'tls_log':
                        {'handshake_log':
                             {'server_certificates':
                                  {'certificate': {'parsed': {},
                                                   'raw': ''}}
                              }
                         }
                    }
        result['data']['tcp']['result']['response']['request'].update(_tls_log)
    return result


def create_template_error(target: NamedTuple,
                          error_str: str) -> dict:
    """
    функция создает шаблон ошибочной записи(результата), добавляет строку error_str
    :param target:
    :param error_str:
    :return:
    """
    _tmp = {'ip': target.ip,
            'port': target.port,
            'data': {}}
    _tmp['data']['tcp'] = {'status': 'unknown-error',
                           'error': error_str}
    return _tmp


def make_document_from_response(buffer: bytes,
                                target: NamedTuple) -> dict:
    """
    Обработка результата чтения байт из соединения
    - buffer - байты полученные от сервиса(из соединения)
    - target - информация о цели (какой порт, ip, payload и так далее)
    результат - словарь с результатом, который будет отправлен в stdout
    :param buffer:
    :param target:
    :return:
    """

    def update_line(json_record: dict,
                    target: NamedTuple) -> dict:
        """
        обновление записи (вспомогательная)
        :param json_record:
        :param target:
        :return:
        """
        json_record['ip'] = target.ip
        json_record['port'] = int(target.port)
        return json_record

    _default_record = create_template_struct(target)
    _default_record['data']['tcp']['status'] = "success"
    _default_record['data']['tcp']['result']['response']['content_length'] = len(
        buffer)
    # _default_record['data']['tcp']['result']['response']['body'] = ''
    try:
        _default_record['data']['tcp']['options'] = target.additions
    except BaseException:
        pass
    # region ADD DESC.
    # отказался от попыток декодировать данные
    # поля data.tcp.result.response.body - не будет, так лучше
    # (в противном случае могут возникать проблемы при создании json
    # из данных с декодированным body)
    # try:
    #     _default_record['data']['tcp']['result']['response']['body'] = buffer.decode()
    # except Exception as e:
    #     pass
    # endregion
    try:
        _base64_data = base64_b64encode(buffer).decode('utf-8')
        _default_record['data']['tcp']['result']['response']['body_raw'] = _base64_data
        # _base64_data - содержит байты в base64 - для того чтоб их удобно было
        # отправлять в stdout
    except Exception as e:
        pass
    try:
        # функции импортированные из hashlib для подсчета хэшей
        # sha256, sha1, md5
        hashs = {'sha256': sha256,
                 'sha1': sha1,
                 'md5': md5
                 }
        for namehash, func in hashs.items():
            hm = func()
            hm.update(buffer)
            _default_record['data']['tcp']['result']['response'][f'body_{namehash}'] = hm.hexdigest(
            )
    except Exception as e:
        pass
    _default_record['data']['tcp']['result']['response']['body_hexdump'] = ''
    try:
        # еще одно представление результата(байт)
        # Transform binary data to the hex dump text format:
        # 00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  .........
        # для этого и необходим модуль hexdump
        hdump = hexdump(buffer, result='return')
        _output = base64_b64encode(bytes(hdump, 'utf-8'))
        output = _output.decode('utf-8')
        _default_record['data']['tcp']['result']['response']['body_hexdump'] = output
    except Exception as e:
        pass
    return update_line(_default_record, target)


def filter_bytes(buffer: bytes,
                 target: NamedTuple) -> bool:
    """
    функция принимает на вход байты, и проверяет на вхождение в эти байты
    элементов из списка, который содержится в Target в search_values
    если search_values пустой - то сразу ответ True
    :param buffer:
    :param target:
    :return:
    """
    if not target.search_values:
        return True
    else:
        checks = list(map(lambda x: x in buffer, target.search_values))
        return any(checks)


def convert_bytes_to_cert(bytes_cert):
    cert = None
    try:
        cert = x509.load_der_x509_certificate(bytes_cert, default_backend())
    except BaseException:
        try:
            cert = x509.load_pem_x509_certificate(
                bytes_cert, default_backend())
        except BaseException:
            pass

    if cert:
        try:
            # alg_hash_name = cert.signature_hash_algorithm.name
            alg_hash = cert.signature_hash_algorithm
            # tp = cert.fingerprint(alg_hash)
            # alg_hash_value = ''.join('{:02x}'.format(x) for x in tp)
        except BaseException:
            pass

        # region block not used
        # signature_hash_algorithm = cert.signature_hash_algorithm
        # subject = cert.subject
        # not_valid_after = cert.not_valid_after
        # alg_hash = cert.signature_hash_algorithm
        # tp = cert.fingerprint(alg_hash)
        # alg_hash_value = ''.join('{:02x}'.format(x) for x in tp)
        # endregion

        result = {}
        serial_number = cert.serial_number
        issuer = cert.issuer
        try:
            result['validity'] = {}
            result['validity']['end_datetime'] = cert.not_valid_after
            result['validity']['start_datetime'] = cert.not_valid_before
            result['validity']['end'] = result['validity']['end_datetime'].strftime(
                '%Y-%m-%dT%H:%M:%SZ')
            result['validity']['start'] = result['validity']['start_datetime'].strftime(
                '%Y-%m-%dT%H:%M:%SZ')
        except Exception as e:
            pass
        result['issuer'] = {}
        dict_replace = {'countryName': 'country',
                        'organizationName': 'organization',
                        'commonName': 'common_name'}
        try:
            for n in issuer.rdns:
                z = n._attributes[0]
                name_k = z.oid._name
                value = z.value
                if name_k in dict_replace:
                    result['issuer'][dict_replace[name_k]] = [value]
        except Exception as e:
            pass
        try:
            if 'v' in cert.version.name:
                result['version'] = cert.version.name.split('v')[1].strip()
        except BaseException:
            result['version'] = str(cert.version.value)
        dnss = get_certificate_domains(cert)
        atr = cert.subject._attributes
        result['subject'] = {}
        for i in atr:
            for q in i._attributes:
                result['subject'][q.oid._name] = [q.value]
        if 'serialNumber' in list(result.keys()):
            if len(result['serialNumber']) == 16:
                result['serialNumber'] = '00' + result['serialNumber']
        try:
            result['serialNumber_int'] = int('0x' + result['serialNumber'], 16)
            result['serial_number'] = str(result['serialNumber_int'])
        except BaseException:
            result['serialNumber_int'] = 0
        result['names'] = dnss
        if result['serialNumber_int'] == 0:
            result['serial_number'] = str(serial_number)
            result['serial_number_hex'] = str(hex(serial_number))
        result['raw_serial'] = str(serial_number)
        # result['fingerprint_sha256'] = alg_hash_value
        hashs = {'fingerprint_sha256': sha256,
                 'fingerprint_sha1': sha1,
                 'fingerprint_md5': md5
                 }
        for namehash, func in hashs.items():
            hm = func()
            hm.update(bytes_cert)
            result[namehash] = hm.hexdigest()
        remove_keys = ['serialNumber_int']
        for key in remove_keys:
            result.pop(key)
        return result


def get_certificate_domains(cert):
    """
    Gets a list of all Subject Alternative Names in the specified certificate.
    """
    try:
        for ext in cert.extensions:
            ext = ext.value
            if isinstance(ext, x509.SubjectAlternativeName):
                return ext.get_values_for_type(x509.DNSName)
    except BaseException:
        return []


async def single_read(reader: asyncio.StreamReader,
                      target: NamedTuple) -> Tuple[bool, Any]:
    # region old
    future_reader = reader.read(target.max_size)
    try:
        # через asyncio.wait_for - задаем время на чтение из
        # соединения
        data = await asyncio.wait_for(future_reader, timeout=target.timeout_read)
        return True, data
    except Exception as e:
        result = create_template_error(target, str(e))
        return False, result


async def multi_read(reader: asyncio.StreamReader,
                     target: NamedTuple) -> Tuple[bool, Any]:
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
            except Exception as e:
                break

        if len(data) == 0:
            return False, create_template_error(target, 'empty')
        else:
            return True, data
    except Exception as e:
        return False, create_template_error(target, str(e))


async def worker_single(target: NamedTuple,
                        semaphore: asyncio.Semaphore,
                        queue_out: asyncio.Queue) -> dict:
    """
    сопрограмма, осуществляет подключение к Target,
    отправку и прием данных, формирует результата в виде dict
    :param target:
    :param semaphore:
    :return:
    """
    global count_good
    global count_error
    async with semaphore:
        result = None
        certificate_dict = None
        cert_bytes_base64 = None

        if target.sslcheck:  # если при запуске в настройках указано --use-ssl - то контекст ssl
            ssl_context = ssl_create_unverified_context()
            future_connection = asyncio.open_connection(
                target.ip,
                target.port,
                ssl=ssl_context,
                ssl_handshake_timeout=target.timeout_ssl)
        else:
            future_connection = asyncio.open_connection(
                target.ip, target.port)
        try:
            reader, writer = await asyncio.wait_for(future_connection, timeout=target.timeout_connection)
            if target.sslcheck:
                try:
                    _sub_ssl = writer._transport.get_extra_info('ssl_object')
                    cert_bytes = _sub_ssl.getpeercert(binary_form=True)
                    cert_bytes_base64 = base64_standard_b64encode(
                        cert_bytes).decode('utf-8')
                    certificate_dict = convert_bytes_to_cert(cert_bytes)
                except BaseException:
                    pass
        except Exception as e:
            await asyncio.sleep(0.005)
            try:
                future_connection.close()
                del future_connection
            except Exception as e:
                pass
            result = create_template_error(target, str(e))
        else:
            try:
                status_data = False
                if target.payload:  # если указан payload - то он и отправляется в первую очередь
                    writer.write(target.payload)
                    await writer.drain()
                if target.mode == 'single':
                    status_data, data_or_error_result = await single_read(reader, target)
                elif target.mode == 'multi':
                    status_data, data_or_error_result = await asyncio.wait_for(
                        multi_read(reader, target),
                        timeout=target.timeout_read)
                if status_data:
                    check_filter = filter_bytes(data_or_error_result, target)
                    if check_filter:
                        result = make_document_from_response(
                            data_or_error_result, target)  # создать результат
                        if target.sslcheck:
                            if cert_bytes_base64:
                                result['data']['tcp']['result']['response']['request']['tls_log']['handshake_log'][
                                    'server_certificates']['certificate']['raw'] = cert_bytes_base64
                            if certificate_dict:
                                result['data']['tcp']['result']['response']['request']['tls_log'][
                                    'handshake_log'][
                                    'server_certificates']['certificate']['parsed'] = certificate_dict

                    else:
                        # TODO: добавить статус success-not-contain
                        # TODO: для обозначения того, что сервис найдет, но не
                        # попал под фильтр
                        pass
                    await asyncio.sleep(0.005)
                else:
                    result = data_or_error_result  # get errors
                try:
                    writer.close()
                except BaseException:
                    pass
            except Exception as e:
                result = create_template_error(target, str(e))
                try:
                    future_connection.close()
                except Exception as e:
                    pass
                await asyncio.sleep(0.005)
                try:
                    writer.close()
                except Exception as e:
                    pass
        if result:
            success = return_value_from_dict(result, "data.tcp.status")
            if success == "success":
                count_good += 1
            else:
                count_error += 1
            line = None
            try:
                if args.show_only_success:
                    if success == "success":
                        line = ujson_dumps(result)
                else:
                    line = ujson_dumps(result)
            except Exception as e:
                pass
            if line:
                await queue_out.put(line)


async def write_to_stdout(object_file: BinaryIO,
                          record_str: str):
    """
    write in 'wb' mode to object_file, input string in utf-8
    :param object_file:
    :param record_str:
    :return:
    """
    await object_file.write(record_str.encode('utf-8') + b'\n')


async def write_to_file(object_file: TextIO,
                        record_str: str):
    """
    write in 'text' mode to object_file
    :param object_file:
    :param record_str:
    :return:
    """
    await object_file.write(record_str + '\n')


async def work_with_create_tasks_queue(queue_with_input: asyncio.Queue,
                                      queue_with_tasks: asyncio.Queue,
                                      queue_out: asyncio.Queue,
                                      count: int) -> None:
    """

    :param queue_with_input:
    :param queue_with_tasks:
    :param queue_out:
    :param count:
    :return:
    """
    semaphore = asyncio.Semaphore(count)
    while True:
        # wait for an item from the "start_application"
        item = await queue_with_input.get()
        if item == b"check for end":
            await queue_with_tasks.put(b"check for end")
            break
        if item:
            task = asyncio.create_task(
                worker_single(item, semaphore, queue_out))
            await queue_with_tasks.put(task)


async def work_with_queue_tasks(queue_results: asyncio.Queue,
                                queue_prints: asyncio.Queue) -> None:
    """

    :param queue_results:
    :param queue_prints:
    :return:
    """
    while True:
        # wait for an item from the "start_application"
        task = await queue_results.get()
        if task == b"check for end":
            await queue_prints.put(b"check for end")
            break
        if task:
            await task


async def work_with_queue_result(queue_out: asyncio.Queue,
                                 filename,
                                 mode_write) -> None:
    """

    :param queue_out:
    :param filename:
    :param mode_write:
    :return:
    """
    if mode_write == 'a':
        method_write_result = write_to_file
    else:
        method_write_result = write_to_stdout
    async with aiofiles_open(filename, mode=mode_write) as file_with_results:
        while True:
            line = await queue_out.get()
            if line == b"check for end":
                break
            if line:
                await method_write_result(file_with_results, line)
    await asyncio.sleep(0.5)
    # region dev
    if args.statistics:
        stop_time = datetime.datetime.now()
        _delta_time = stop_time - start_time
        duration_time_sec = _delta_time.total_seconds()
        statistics = {'duration': duration_time_sec,
                      'valid targets': count_input,
                      'success': count_good,
                      'fails': count_error}
        async with aiofiles_open('/dev/stdout', mode='wb') as stats:
            await stats.write(ujson_dumps(statistics).encode('utf-8') + b'\n')
    # endregion


async def read_input_file(queue_input: asyncio.Queue,
                          settings: dict,
                          path_to_file: str) -> None:
    """
    посредством модуля aiofiles функция "асинхронно" читает из файла записи, представляющие собой
    обязательно или ip адрес или запись подсети в ipv4
    из данной записи формируется экзэмпляр NamedTuple - Target, который отправляется в Очередь
    :param queue_results:
    :param settings:
    :param path_to_file:
    :return:
    """
    global count_input
    async with aiofiles_open(path_to_file, mode='rt') as f:  # read str
        async for line in f:
            linein = line.strip()
            if any([check_ip(linein), check_network(linein)]):
                targets = create_targets_tcp_protocol(linein, settings) # generator
                if targets:
                    for target in targets:
                        check_queue = True
                        while check_queue:
                            size_queue = queue_input.qsize()
                            if size_queue < queue_limit_targets-1:
                                count_input += 1  # statistics
                                queue_input.put_nowait(target)
                                check_queue = False
                            else:
                                await asyncio.sleep(sleep_duration_queue_full)


    await queue_input.put(b"check for end")


async def read_input_stdin(queue_input: asyncio.Queue,
                           settings: dict,
                           path_to_file: str = None) -> None:
    """
        посредством модуля aioconsole функция "асинхронно" читает из stdin записи, представляющие собой
        обязательно или ip адрес или запись подсети в ipv4
        из данной записи формируется экзэмпляр NamedTuple - Target, который отправляется в Очередь
        TODO: использовать один модуль - или aioconsole или aiofiles
        :param queue_results:
        :param settings:
        :param path_to_file:
        :return:
        """
    global count_input
    while True:
        try:
            _tmp_input = await ainput()  # read str from stdin
            linein = _tmp_input.strip()
            if any([check_ip(linein), check_network(linein)]):
                targets = create_targets_tcp_protocol(linein, settings)
                if targets:
                    for target in targets:
                        check_queue = True
                        while check_queue:
                            size_queue = queue_input.qsize()
                            if size_queue < queue_limit_targets - 1:
                                count_input += 1  # statistics
                                queue_input.put_nowait(target)
                                check_queue = False
                            else:
                                await asyncio.sleep(sleep_duration_queue_full)
        except EOFError:
            await queue_input.put(b"check for end")
            break


def checkfile(path_to_file: str) -> bool:
    return path.isfile(path_to_file)


def parse_payloads_files(payload_files: List[str]) -> List[str]:
    """
    функция проверяет наличие файлов, переданных в настройках
    :param payload_files:
    :return:
    """
    result = [
        path_to_file for path_to_file in payload_files if checkfile(path_to_file)]
    return result


def return_payloads_from_files(payload_files: List[str]) -> List[bytes]:
    """
    функция считывает их файлов байты и формирует список с payloads
    :param payload_files:
    :return:
    """
    payloads = []
    files = parse_payloads_files(payload_files)
    for payloadfile in files:
        with open(payloadfile, 'rb') as f:
            payload = f.read()
            payloads.append(payload)
    return payloads


def return_bytes_from_single_payload(string_base64: str) -> bytes:
    """
    функция принимает строку(str) base64 - в которой закодирован bytes payload, который она  возвращает
    :param string_base64:
    :return:
    """
    try:
        _payload = string_base64.encode('utf-8')
        payload = base64_b64decode(_payload)
        return payload
    except Exception as e:
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Packet sender lite(asyncio)')
    parser.add_argument(
        "-settings",
        type=str,
        help="path to file with settings(yaml)")

    parser.add_argument(
        "-m",
        "--mode",
        dest='mode',
        type=str,
        default='single',
        help="type of read mode from connections:single, multi (default: single)")

    parser.add_argument(
        "-f",
        "--input-file",
        dest='input_file',
        type=str,
        help="path to file with targets")

    parser.add_argument(
        "-o",
        "--output-file",
        dest='output_file',
        type=str,
        help="path to file with results")

    parser.add_argument(
        "-s",
        "--senders",
        dest='senders',
        type=int,
        default=1024,
        help="Number of send coroutines to use (default: 1024)")

    parser.add_argument(
        "--queue-sleep",
        dest='queue_sleep',
        type=int,
        default=1,
        help='Sleep duration if the queue is full, default 1 sec. Size queue == senders')

    parser.add_argument(
        "--max-size",
        dest='max_size',
        type=int,
        default=1024,
        help='Maximum total bytes(!) to read for a single host (default 1024)')

    parser.add_argument(
        "-tconnect",
        "--timeout-connection",
        dest='timeout_connection',
        type=int,
        default=7,
        help='Set connection timeout for open_connection (default: 7)')

    parser.add_argument(
        "-tread",
        "--timeout-read",
        dest='timeout_read',
        type=int,
        default=7,
        help='Set connection timeout for reader from connection (default: 7)')

    parser.add_argument(
        "-tssl",
        "--timeout-ssl",
        dest='timeout_ssl',
        type=int,
        default=7,
        help='Set connection timeout for reader from ssl connection (default: 7)')

    parser.add_argument(
        "-p",
        "--port",
        type=int,
        help='Specify port (default: 80)')

    parser.add_argument('--use-ssl', dest='sslcheck', action='store_true')

    # region filters
    parser.add_argument(
        "--single-contain",
        dest='single_contain',
        type=str,
        help='trying to find a substring in a response(set in base64)')

    parser.add_argument(
        "--single-contain-hex",
        dest='single_contain_hex',
        type=str,
        help='trying to find a substring in a response bytes (set in bytes(hex))')

    parser.add_argument(
        "--single-contain-string",
        dest='single_contain_string',
        type=str,
        help='trying to find a substring in a response(set in str)')

    parser.add_argument(
        '--show-only-success',
        dest='show_only_success',
        action='store_true')
    # endregion

    parser.add_argument(
        '--list-payloads',
        nargs='*',
        dest='list_payloads',
        help='list payloads(bytes stored in files): file1 file2 file2',
        required=False)

    parser.add_argument("--single-payload", dest='single_payload', type=str,
                        help='single payload in BASE64 from bytes')

    parser.add_argument(
        "--single-payload-hex",
        dest='single_payload_hex',
        type=str,
        help='single payload in hex(bytes)')

    # region python payloads
    parser.add_argument(
        "--python-payloads",
        dest='python_payloads',
        type=str,
        help='path to Python module')

    parser.add_argument(
        "--generator-payloads",
        dest='generator_payloads',
        type=str,
        help='name function of gen.payloads from Python module')
    # endregion

    parser.add_argument(
        '--show-statistics',
        dest='statistics',
        action='store_true')

    path_to_file_targets = None  # set default None to inputfile
    args = parser.parse_args()

    if args.settings:
        pass  # TODO реализовать позднее чтение настроек из файла
    else:
        # region parser ARGs
        if not args.port:
            print('Exit, port?')
            exit(1)
        if args.mode not in ('single', 'multi'):
            print('Exit, type of read mode from connections?')
            exit(1)
        # в method_create_targets - метод, которые или читает из stdin или из
        # файла
        if not args.input_file:
            # set method - async read from stdin (str)
            method_create_targets = read_input_stdin
        else:
            # set method - async read from file(txt, str)
            method_create_targets = read_input_file

            path_to_file_targets = args.input_file
            if not checkfile(path_to_file_targets):
                print(f'ERROR: file not found: {path_to_file_targets}')
                exit(1)

        if not args.output_file:
            output_file, mode_write = '/dev/stdout', 'wb'
        else:
            output_file, mode_write = args.output_file, 'a'

        payloads = []
        if args.list_payloads:
            payloads = return_payloads_from_files(args.list_payloads)
        # endregion

        search_values = []
        if args.single_contain:
            try:
                search_value = return_bytes_from_single_payload(
                    args.single_contain)
                assert search_value is not None
                search_values.append(search_value)
            except Exception as e:
                print(e)
                print('errors with --single-contain options')
                exit(1)
        elif args.single_contain_string:
            try:
                search_value = str(args.single_contain_string).encode('utf-8')
                assert search_value is not None
                search_values.append(search_value)
            except Exception as e:
                print(e)
                print('errors with --single-contain-string options')
                exit(1)
        elif args.single_contain_hex:
            try:
                search_value = bytes.fromhex(args.single_contain_hex)
                assert search_value is not None
                search_values.append(search_value)
            except Exception as e:
                print(e)
                print('errors with --single-contain-hex options')
                exit(1)

        single_payload = None
        if args.single_payload:
            single_payload = return_bytes_from_single_payload(
                args.single_payload)
        elif args.single_payload_hex:
            try:
                single_payload = bytes.fromhex(args.single_payload_hex)
            except BaseException:
                pass
        if single_payload:
            payloads.append(single_payload)

    time_out_for_connection = args.timeout_connection
    settings = {'port': args.port,
                'sslcheck': args.sslcheck,
                'timeout_connection': args.timeout_connection,
                'timeout_read': args.timeout_read,
                'timeout_ssl': args.timeout_ssl,
                'list_payloads': payloads,
                'search_values': search_values,
                'max_size': args.max_size,
                'python_payloads': args.python_payloads,
                'generator_payloads': args.generator_payloads,
                'mode': args.mode
                }

    count_cor = args.senders
    # region limits input Queue
    queue_limit_targets = count_cor
    sleep_duration_queue_full = args.queue_sleep
    # endregion
    count_input = 0
    count_good = 0
    count_error = 0
    start_time = datetime.datetime.now()
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    loop = asyncio.get_event_loop()
    queue_input = asyncio.Queue()
    queue_results = asyncio.Queue()
    queue_prints = asyncio.Queue()
    read_input = method_create_targets(queue_input, settings, path_to_file_targets)  # create targets
    create_tasks = work_with_create_tasks_queue(queue_input, queue_results, queue_prints, count_cor)  # execution
    execute_tasks = work_with_queue_tasks(queue_results, queue_prints)
    print_output = work_with_queue_result(queue_prints, output_file, mode_write)
    loop.run_until_complete(
        asyncio.gather(
            read_input,
            create_tasks,
            execute_tasks,
            print_output))
    loop.close()
