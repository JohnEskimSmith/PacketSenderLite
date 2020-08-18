#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "SAI"
__license__ = "GPLv3"
__status__ = "Dev"

from aioconsole import ainput
from ipaddress import ip_address, ip_network
import ssl
from collections import namedtuple
import asyncio
import ujson
import base64
from hashlib import sha256, sha1, md5
from hexdump import hexdump
import argparse
import datetime
import aiofiles
import copy
from os import path
import importlib
import async_timeout
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

from typing import (Any,
                    Callable,
                    Iterable,
                    NamedTuple,
                    Iterator,
                    List,
                    BinaryIO,
                    TextIO,
                    )


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
    except:
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
    except:
        return False


def load_python_generator_payloads(path_to_module: str,
                                   name_function: str) -> Callable[[], Iterable]:
    """
    Загрузка модуля и функции из него, которая будет генерировать payloads.
    :param path_to_module:
    :param name_function:
    :return:
    """
    _mod = importlib.import_module(path_to_module)
    need_function = getattr(_mod, name_function)
    return need_function


def create_target_tcp_protocol(ip_str: str,
                               settings: dict) -> Iterator:
    """
    На основании ip адреса и настроек возвращает через yield
    экзэмпляр namedtuple - Target.
    Target содержит всю информацию необходимую для worker.
    :param ip_str:
    :param settings:
    :return:
    """
    current_settings = copy.copy(settings)

    if current_settings['max_size'] != -1:
        current_settings['max_size'] = current_settings['max_size']  # remember - in bytes, not kb

    key_names = list(current_settings.keys())
    key_names.extend(['ip', 'payload', 'additions'])
    Target = namedtuple('Target', key_names)
    current_settings['ip'] = ip_str
    if current_settings['list_payloads']:
        for payload in current_settings['list_payloads']:
            tmp_settings = copy.copy(current_settings)
            tmp_settings['payload'] = payload
            _payload_base64 = base64.standard_b64encode(payload).decode('utf-8')
            # _additions - необходимы для информации, какой payload был направлен
            _additions = {'data_payload':
                              {'payload_raw': _payload_base64,
                               'variables': []}
                          }
            tmp_settings['additions'] = _additions
            target = Target(**tmp_settings)
            yield target
    elif current_settings['python_payloads']:
        name_function = 'generator_payloads'  # имя функции, генерирующей payloads по-умолчанию
        if current_settings['generator_payloads']:
            name_function = current_settings['generator_payloads']
        path_to_module = current_settings['python_payloads']
        generator_payloads = load_python_generator_payloads(path_to_module, name_function)
        for payload in generator_payloads():
            tmp_settings = copy.copy(current_settings)
            tmp_settings['payload'] = payload['payload']
            tmp_settings['additions'] = payload['data_payload']
            target = Target(**tmp_settings)
            yield target
    else:
        # отсутствует payload - фактически означает, "считывать баннеры сервисов"
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


def create_template_struct() -> dict:
    """
    вспомогательная функция, создает шаблон словаря заданной в коде структуры
    :return:
    """
    result = {'data':
                  {'tcp':
                       {'status': 'tcp',
                        'result':
                            {'response':
                                {
                                }
                            }
                       }
                  }
              }
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


    _default_record = create_template_struct()
    _default_record['data']['tcp']['status'] = "success"
    _default_record['data']['tcp']['result']['response']['content_length'] = len(buffer)
    # _default_record['data']['tcp']['result']['response']['body'] = ''
    try:
        _default_record['data']['tcp']['options'] = target.additions
    except:
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
        _base64_data = base64.b64encode(buffer).decode('utf-8')
        _default_record['data']['tcp']['result']['response']['body_raw'] = _base64_data
        # _base64_data - содержит байты в base64 - для того чтоб их удобно было отправлять в stdout
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
            _default_record['data']['tcp']['result']['response'][f'body_{namehash}'] = hm.hexdigest()
    except Exception as e:
        pass
    _default_record['data']['tcp']['result']['response']['body_hexdump'] = ''
    try:
        # еще одно представление результата(байт)
        # Transform binary data to the hex dump text format:
        # 00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
        # для этого и необходим модуль hexdump
        hdump = hexdump(buffer, result='return')
        _output = base64.b64encode(bytes(hdump, 'utf-8'))
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


async def worker_single(target: NamedTuple) -> dict:
    """
    сопрограмма, осуществляет подключение к Target,
    отправку и прием данных, формирует результата в виде dict
    :param target:
    :return:
    """
    result = None
    if target.sslcheck:  # если при запуске в настройках указано --use-ssl - то контекст ssl
        ssl_context = ssl._create_unverified_context()
        future_connection = asyncio.open_connection(
            target.ip, target.port, ssl=ssl_context, ssl_handshake_timeout=target.timeout_ssl)
    else:
        future_connection = asyncio.open_connection(
            target.ip, target.port)
    try:
        reader, writer = await asyncio.wait_for(future_connection, timeout=target.timeout_connection)
    except Exception as e:
        await asyncio.sleep(0.02)
        future_connection.close()
        del future_connection
        result = create_template_error(target, str(e))
    else:
        try:
            if target.payload:  # если указан payload - то он и отправляется в первую очередь
                writer.write(target.payload)
            future_reader = reader.read(target.max_size)
            try:
                # через asyncio.wait_for - задаем время на чтение из соединения
                data = await asyncio.wait_for(future_reader, timeout=target.timeout_read)
            except Exception as e:
                result = create_template_error(target, str(e))
            else:
                check_filter = filter_bytes(data, target)
                if check_filter:
                    result = make_document_from_response(data, target)  # создать результат
                else:
                    # TODO: добавить статус success-not-contain
                    # TODO: для обозначения того, что сервис найдет, но не попал под фильтр
                    pass
                await asyncio.sleep(0.02)
            try:
                writer.close()
            except:
                pass
        except Exception as e:
            result = create_template_error(target, str(e))
            future_connection.close()
            await asyncio.sleep(0.02)
            try:
                writer.close()
            except:
                pass
    return result


async def worker_group(block: List[NamedTuple]) -> None:
    """
    block - содержит в списке цели(Target)
    в цикле каждая цель отправляется в worker_single
    который в свою очередь в список tasks
    далее в контексте async_timeout.timeout(timeouts) с "глобальным" timeouts
    ожидается исполенние всех сопрограмм в списке tasks
    результаты(dict) записываются в responses - список
    в контексте async with aiofiles.open('/dev/stdout', mode='wb')
    в stdout пишется ujson.dumps(dict_line) - где dict_line как раз результат сопрограммы worker_single
    используется модуль ujson - потому как быстрый, причем необходим версии 1.35
    :param block:
    :return:
    """
    global count_good  # счет удачных соединений(результатов)
    global count_error # счет неудачных соединений(результатов)
    tasks = []
    responses = None

    for target in block:
        task = asyncio.ensure_future(worker_single(target))
        tasks.append(task)
    timeouts = len(block)*time_out_for_connection   #  TODO:
    async with async_timeout.timeout(timeouts):
        responses = await asyncio.gather(*tasks)
    await asyncio.sleep(0.02)
    if responses:
        method_write_result = write_to_stdout
        if mode_write == 'a':
            method_write_result = write_to_file
        async with aiofiles.open(output_file, mode=mode_write) as file_with_results:
            for dict_line in responses:
                if dict_line:
                    success = return_value_from_dict(dict_line, "data.tcp.status")
                    if success == "success":
                        count_good += 1
                    else:
                        count_error += 1
                    line = ujson.dumps(dict_line)
                    await method_write_result(file_with_results, line)


async def write_to_stdout(object_file: BinaryIO,
                          record_str: str):
    await object_file.write(record_str.encode('utf-8') + b'\n')


async def write_to_file(object_file: TextIO,
                        record_str: str):
    await object_file.write(record_str + '\n')


async def work_with_queue(queue_results: asyncio.Queue,
                          count: int) -> None:
    """
     - queue_results - очередь, в которую попадают цели типа NamedTuple - target
     - count - количество целей, которые за 1 раз будут "паралелльно"(асинхронно) исполняться
    концепт функции простой:
    1. чтение из очереди queue_results элемента
    2. при наличии элемента помещение его в список block
    3. при достижении длины списка block равной count вызывает worker_group
    4. внутри worker_group отрабатывают "сопрограммы"
    5. список block удаляется создается
    6. в завершении функции идет проверка не пустой ли список, и вызывает worker_group на остатках целей
    :param queue_results:
    :param count:
    :return:
    """
    count_elements = 0
    block = []

    while True:
        # wait for an item from the "start_application"
        item = await queue_results.get()
        if item == b"check for end":
            # TODO send statistics
            break
        if item:
            block.append(item)
            count_elements += 1
            if count_elements % (int(count)) == 0:
                await worker_group(block)
                del block
                block = []
                await asyncio.sleep(0.02)  # magic number :)

    if block:
        await worker_group(block)


async def read_input_file(queue_results: asyncio.Queue,
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
    async with aiofiles.open(path_to_file, mode='rt') as f:  # read str
        async for line in f:
            linein = line.strip()
            if any([check_ip(linein), check_network(linein)]):
                targets = create_targets_tcp_protocol(linein, settings)
                if targets:
                    for target in targets:
                        count_input += 1  # statistics
                        queue_results.put_nowait(target)
    queue_results.put_nowait(b"check for end")


async def read_input_stdin(queue_results: asyncio.Queue,
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
                        count_input += 1
                        queue_results.put_nowait(target)
        except EOFError:
            queue_results.put_nowait(b"check for end")
            break


def checkfile(path_to_file: str) -> bool:
    return path.isfile(path_to_file)


def parse_payloads_files(payload_files: List[str]) -> List[str]:
    """
    функция проверяет наличие файлов, переданных в настройках
    :param payload_files:
    :return:
    """
    result = [path_to_file for path_to_file in payload_files if checkfile(path_to_file)]
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
        payload = base64.b64decode(_payload)
        return payload
    except Exception as e:
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Packet sender lite(asyncio)')
    parser.add_argument("-settings", type=str, help="path to file with settings(yaml)")

    parser.add_argument("-f", "--input-file", dest='input_file', type=str, help="path to file with targets")

    parser.add_argument("-o", "--output-file", dest='output_file', type=str, help="path to file with results")

    parser.add_argument("-s", "--senders", dest='senders', type=int,
                        default=1024, help=' Number of send coroutines to use (default: 1024)')

    parser.add_argument("--max-size", dest='max_size', type=int,
                        default=1024, help='Maximum total bytes(!) to read for a single host (default 1024)')

    parser.add_argument("-tconnect", "--timeout-connection", dest='timeout_connection', type=int,
                        default=3, help='Set connection timeout for open_connection (default: 3)')

    parser.add_argument("-tread", "--timeout-read", dest='timeout_read', type=int,
                        default=3, help='Set connection timeout for reader from connection (default: 3)')

    parser.add_argument("-tssl", "--timeout-ssl", dest='timeout_ssl', type=int,
                        default=3, help='Set connection timeout for reader from connection (default: 3)')

    parser.add_argument("-p", "--port", type=int, help='Specify port (default: 80)')

    parser.add_argument('--use-ssl', dest='sslcheck', action='store_true')

    parser.add_argument("--single-contain", dest='single_contain', type=str,
                        help='trying to find a substring in a response(set in base64)')

    parser.add_argument("--single-contain-hex", dest='single_contain_hex', type=str,
                        help='trying to find a substring in a response bytes (set in bytes(hex))')

    parser.add_argument("--single-contain-string", dest='single_contain_string', type=str,
                        help='trying to find a substring in a response(set in str)')

    parser.add_argument('--list-payloads', nargs='*', dest='list_payloads',
                        help='list payloads(bytes stored in files): file1 file2 file2', required=False)

    parser.add_argument("--single-payload", dest='single_payload', type=str,
                        help='single payload in BASE64 from bytes')

    parser.add_argument("--single-payload-hex", dest='single_payload_hex', type=str,
                        help='single payload in hex(bytes)')

    parser.add_argument("--python-payloads", dest='python_payloads', type=str,
                        help='path to Python module')

    parser.add_argument("--generator-payloads", dest='generator_payloads', type=str,
                        help='name function of gen.payloads from Python module')

    parser.add_argument('--show-statistics', dest='statistics', action='store_true')

    path_to_file_targets = None  # set default None to inputfile
    args = parser.parse_args()

    if args.settings:
        pass  # TODO реализовать позднее чтение настроек из файла
    else:
        # region parser ARGs
        if not args.port:
            print('Exit, port?')
            exit(1)
        # в method_create_targets - метод, которые или читает из stdin или из файла
        if not args.input_file:
            method_create_targets = read_input_stdin  # set method - async read from stdin (str)
        else:
            method_create_targets = read_input_file  # set method - async read from file(txt, str)

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
                search_value = return_bytes_from_single_payload(args.single_contain)
                assert search_value is not None
                search_values.append(search_value)
            except Exception as e:
                print('errors with --single-contain options')
                exit(1)
        elif args.single_contain_string:
            try:
                search_value = str(args.single_contain_string).encode('utf-8')
                assert search_value is not None
                search_values.append(search_value)
            except Exception as e:
                print('errors with --single-contain-string options')
                exit(1)
        elif args.single_contain_hex:
            try:
                search_value = bytes.fromhex(args.single_contain_hex)
                assert search_value is not None
                search_values.append(search_value)
            except Exception as e:
                print('errors with --single-contain-hex options')
                exit(1)

        single_payload = None
        if args.single_payload:
            single_payload = return_bytes_from_single_payload(args.single_payload)
        elif args.single_payload_hex:
            try:
                single_payload = bytes.fromhex(args.single_payload_hex)
            except:
                pass
        if single_payload:
            payloads.append(single_payload)

    time_out_for_connection = args.timeout_connection + 1  # TODO: rethink
    settings = {'port': args.port,
                'sslcheck': args.sslcheck,
                'timeout_connection': args.timeout_connection,
                'timeout_read': args.timeout_read,
                'timeout_ssl': args.timeout_ssl,
                'list_payloads': payloads,
                'search_values': search_values,
                'max_size': args.max_size,
                'python_payloads': args.python_payloads,
                'generator_payloads': args.generator_payloads
                }

    count_cor = args.senders

    count_input = 0
    count_good = 0
    count_error = 0
    start_time = datetime.datetime.now()

    loop = asyncio.get_event_loop()
    queue_results = asyncio.Queue()

    producer_coro = method_create_targets(queue_results, settings, path_to_file_targets)
    consumer_coro = work_with_queue(queue_results, count_cor)
    loop.run_until_complete(asyncio.gather(producer_coro, consumer_coro))
    loop.close()

    stop_time = datetime.datetime.now()
    _delta_time = stop_time - start_time
    duration_time_sec = _delta_time.total_seconds()
    if args.statistics:
        statistics = {'duration': duration_time_sec,
                      'valid targets': count_input,
                      'success': count_good,
                      'fails': count_error}
        print(ujson.dumps(statistics))
