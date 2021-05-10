#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "SAI"
__license__ = "GPLv3"
__status__ = "Dev"

import asyncio

import uvloop
from aiofiles import open as aiofiles_open

from lib.workers import get_async_writer, create_io_reader, TargetReader, TaskProducer, Executor, OutputPrinter, \
    TargetWorker
from lib.util import parse_settings, parse_args
from lib.core import Stats


async def main():
    arguments = parse_args()
    target_settings, config = parse_settings(arguments)

    queue_input = asyncio.Queue()
    queue_tasks = asyncio.Queue()
    queue_prints = asyncio.Queue()

    task_semaphore = asyncio.Semaphore(config.senders)
    statistics = Stats() if config.statistics else None

    async with aiofiles_open(config.output_file, mode=config.write_mode) as file_with_results:
        writer_coroutine = get_async_writer(config)
        target_worker = TargetWorker(statistics,
                                     task_semaphore,
                                     queue_prints,
                                     config.show_only_success,
                                     config.body_not_empty)
        input_reader: TargetReader = create_io_reader(statistics, queue_input, target_settings, config)
        task_producer = TaskProducer(statistics, queue_input, queue_tasks, target_worker)
        executor = Executor(statistics, queue_tasks, queue_prints)
        printer = OutputPrinter(config.output_file, statistics, queue_prints, file_with_results, writer_coroutine)

        await asyncio.wait([
            worker.run() for worker in [input_reader, task_producer, executor, printer]
        ])

if __name__ == '__main__':
    uvloop.install()
    asyncio.run(main())
