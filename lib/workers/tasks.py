import abc
import asyncio
from abc import ABC
from asyncio import Queue
from base64 import b64encode
# noinspection PyUnresolvedReferences,PyProtectedMember
from ssl import _create_unverified_context as ssl_create_unverified_context
from typing import Optional, Callable, Any, Coroutine

from aioconsole import ainput
from aiofiles import open as aiofiles_open
from ujson import dumps as ujson_dumps

from lib.core import convert_bytes_to_cert, create_error_template, make_document_from_response, Stats, AppConfig, \
    Target, TargetConfig
from lib.util import access_dot_path, is_ip, is_network, single_read, multi_read, \
    filter_bytes, write_to_file, write_to_stdout
from .factories import create_targets_tcp_protocol

__all__ = ['QueueWorker', 'TargetReader', 'TargetFileReader', 'TargetStdinReader', 'TaskProducer', 'Executor',
           'OutputPrinter', 'TargetWorker', 'create_io_reader', 'get_async_writer']

STOP_SIGNAL = b'check for end'


class QueueWorker(metaclass=abc.ABCMeta):
    def __init__(self, stats: Optional[Stats] = None):
        self.stats = stats

    @abc.abstractmethod
    async def run(self):
        pass


class InputProducer:
    """
    Produces raw messages for workers
    """

    def __init__(self, stats: Stats, input_queue: Queue, target_conf: TargetConfig, send_limit: int, queue_sleep: int):
        self.stats = stats
        self.input_queue = input_queue
        self.target_conf = target_conf
        self.send_limit = send_limit
        self.queue_sleep = queue_sleep

    async def send(self, linein):
        if any([is_ip(linein), is_network(linein)]):
            targets = create_targets_tcp_protocol(linein, self.target_conf)  # generator
            if targets:
                for target in targets:
                    check_queue = True
                    while check_queue:
                        size_queue = self.input_queue.qsize()
                        if size_queue < self.send_limit:
                            if self.stats:
                                self.stats.count_input += 1
                            self.input_queue.put_nowait(target)
                            check_queue = False
                        else:
                            await asyncio.sleep(self.queue_sleep)

    async def send_stop(self):
        await self.input_queue.put(STOP_SIGNAL)


class TargetReader(QueueWorker, ABC):
    """
    Reads raw input messages from any source ans sends them to workers via producer
    """

    def __init__(self, stats: Stats, input_queue: Queue, producer: InputProducer):
        super().__init__(stats)
        self.input_queue = input_queue
        self.producer = producer


class TargetFileReader(TargetReader):
    """
    Reads raw input messages from text file
    """

    def __init__(self, stats: Stats, input_queue: Queue, producer: InputProducer, file_path: str):
        super().__init__(stats, input_queue, producer)
        self.file_path = file_path

    async def run(self):
        async with aiofiles_open(self.file_path, mode='rt') as f:
            async for line in f:
                linein = line.strip()
                await self.producer.send(linein)

        await self.producer.send_stop()


class TargetSingleReader(TargetReader):
    """
    Reads --target input messages from args
    """

    def __init__(self, stats: Stats, input_queue: Queue, producer: InputProducer, single_targets: str):
        super().__init__(stats, input_queue, producer)
        self.single_targets = single_targets

    async def run(self):
        for single_target in self.single_targets:
            linein = single_target.strip()
            if linein:
                await self.producer.send(linein)
        await self.producer.send_stop()


class TargetStdinReader(TargetReader):
    """
    Reads raw input messages from STDIN
    """

    async def run(self):
        """
        посредством модуля aioconsole функция "асинхронно" читает из stdin записи, представляющие собой
        обязательно или ip адрес или запись подсети в ipv4
        из данной записи формируется экзэмпляр Target, который отправляется в Очередь
        TODO: использовать один модуль - или aioconsole или aiofiles
        """
        while True:
            try:
                linein = (await ainput()).strip()
                await self.producer.send(linein)
            except EOFError:
                await self.producer.send_stop()
                break


class TaskProducer(QueueWorker):
    """
    Creates tasks for tasks queue
    """

    def __init__(self, stats: Stats, in_queue: Queue, tasks_queue: Queue, worker: 'TargetWorker'):
        super().__init__(stats)
        self.in_queue = in_queue
        self.tasks_queue = tasks_queue
        self.worker = worker

    async def run(self):
        while True:
            # wait for an item from the "start_application"
            target = await self.in_queue.get()
            if target == STOP_SIGNAL:
                await self.tasks_queue.put(STOP_SIGNAL)
                break
            if target:
                coro = self.worker.do(target)
                task = asyncio.create_task(coro)
                await self.tasks_queue.put(task)


class Executor(QueueWorker):
    """
    Gets tasks from tasks queue and launch execution for each of them
    """

    def __init__(self, stats: Stats, tasks_queue: Queue, out_queue: Queue):
        super().__init__(stats)
        self.tasks_queue = tasks_queue
        self.out_queue = out_queue

    async def run(self):
        while True:
            # wait for an item from the "start_application"
            task = await self.tasks_queue.get()
            if task == STOP_SIGNAL:
                await self.out_queue.put(STOP_SIGNAL)
                break
            if task:
                await task


class OutputPrinter(QueueWorker):
    """
    Takes results from results queue and put them to output
    """

    def __init__(self, output_file:str, stats: Stats, in_queue: Queue, io, async_writer) -> None:
        super().__init__(stats)
        self.in_queue = in_queue
        self.async_writer = async_writer
        self.io = io
        self.output_file = output_file

    async def run(self):
        while True:
            line = await self.in_queue.get()
            if line == STOP_SIGNAL:
                break
            if line:
                await self.async_writer(self.io, line)

        await asyncio.sleep(0.5)
        if self.stats:
            statistics = self.stats.dict()
            if self.output_file == '/dev/stdout':
                await self.io.write(ujson_dumps(statistics).encode('utf-8') + b'\n')
            else:
                async with aiofiles_open('/dev/stdout', mode='wb') as stats:
                    await stats.write(ujson_dumps(statistics).encode('utf-8') + b'\n')


class TargetWorker:
    """
    Runs payload against target
    """

    def __init__(self, stats: Stats, semaphore: asyncio.Semaphore, output_queue: asyncio.Queue, success_only: bool):
        self.stats = stats
        self.semaphore = semaphore
        self.output_queue = output_queue
        self.success_only = success_only

    # noinspection PyBroadException
    async def do(self, target: Target):
        """
        сопрограмма, осуществляет подключение к Target, отправку и прием данных, формирует результата в виде dict
        """
        async with self.semaphore:
            result = None
            certificate_dict = None
            cert_bytes_base64 = None

            if target.ssl_check:  # если при запуске в настройках указано --use-ssl - то контекст ssl
                ssl_context = ssl_create_unverified_context()
                future_connection = asyncio.open_connection(
                    target.ip,
                    target.port,
                    ssl=ssl_context,
                    ssl_handshake_timeout=target.ssl_timeout)
            else:
                future_connection = asyncio.open_connection(target.ip, target.port)
            try:
                reader, writer = await asyncio.wait_for(future_connection, timeout=target.conn_timeout)
                if target.ssl_check:
                    try:
                        # noinspection PyProtectedMember
                        _sub_ssl = writer._transport.get_extra_info('ssl_object')
                        cert_bytes = _sub_ssl.getpeercert(binary_form=True)
                        cert_bytes_base64 = b64encode(cert_bytes).decode('utf-8')
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
                result = create_error_template(target, str(e))
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
                            multi_read(reader, target), timeout=target.read_timeout)
                    if status_data:
                        check_filter = filter_bytes(data_or_error_result, target)
                        if check_filter:
                            result = make_document_from_response(data_or_error_result, target)
                            if target.ssl_check:
                                if cert_bytes_base64:
                                    result['data']['tcp']['result']['response']['request']['tls_log']['handshake_log'][
                                        'server_certificates']['certificate']['raw'] = cert_bytes_base64
                                if certificate_dict:
                                    result['data']['tcp']['result']['response']['request']['tls_log'][
                                        'handshake_log'][
                                        'server_certificates']['certificate']['parsed'] = certificate_dict

                        else:
                            # TODO: добавить статус success-not-contain для обозначения того,
                            #  что сервис найден, но не попал под фильтр
                            pass
                        await asyncio.sleep(0.005)
                    else:
                        result = data_or_error_result  # get errors
                    try:
                        writer.close()
                    except BaseException:
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
                success = access_dot_path(result, "data.tcp.status")
                if self.stats:
                    if success == "success":
                        self.stats.count_good += 1
                    else:
                        self.stats.count_error += 1
                line = None
                try:
                    if self.success_only:
                        if success == "success":
                            line = ujson_dumps(result)
                    else:
                        line = ujson_dumps(result)
                except Exception:
                    pass
                if line:
                    await self.output_queue.put(line)


def create_io_reader(stats: Stats, queue_input: Queue, target: TargetConfig, app_config: AppConfig) -> TargetReader:
    message_producer = InputProducer(stats, queue_input, target, app_config.senders - 1, app_config.queue_sleep)
    if app_config.input_stdin:
        return TargetStdinReader(stats, queue_input, message_producer)
    if app_config.single_targets:
        return TargetSingleReader(stats, queue_input, message_producer, app_config.single_targets)
    elif app_config.input_file:
        return TargetFileReader(stats, queue_input, message_producer, app_config.input_file)
    else:
        # TODO : rethink...
        print("""errors, set input source:
         --stdin read targets from stdin;
         -t,--targets set targets, see -h;
         -f,--input-file read from file with targets, see -h""")
        exit(1)


def get_async_writer(app_settings: AppConfig) -> Callable[[Any, str], Coroutine]:
    if app_settings.write_mode == 'a':
        return write_to_file
    return write_to_stdout
