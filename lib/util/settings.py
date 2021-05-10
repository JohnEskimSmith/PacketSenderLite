import argparse
from os import path
from sys import stderr
from typing import Tuple

from .io import decode_base64_string
from lib.core import return_payloads_from_files, AppConfig, TargetConfig

__all__ = ['parse_args', 'parse_settings']


def parse_args():
    parser = argparse.ArgumentParser(description='Packet sender lite(asyncio)')
    parser.add_argument('-settings', type=str, help='path to file with settings (yaml)')
    parser.add_argument('-m', '--mode', dest='mode', type=str, default='single',
                        help='type of read mode from connections:single, multi (default: single)')
    parser.add_argument('--stdin', dest='input_stdin', action='store_true', help='Read targets from stdin')
    parser.add_argument('-t', '--targets', nargs='+', type=str, default='', dest='single_targets',
                        help='Single targets: ipv4, CIDRs')
    parser.add_argument('-f', '--input-file', dest='input_file', type=str, help='path to file with targets')
    parser.add_argument('-o', '--output-file', dest='output_file', type=str, help='path to file with results')
    parser.add_argument('-s', '--senders', dest='senders', type=int, default=1024,
                        help='Number of send coroutines to use (default: 1024)')
    parser.add_argument('--queue-sleep', dest='queue_sleep', type=int, default=1,
                        help='Sleep duration if the queue is full, default 1 sec. Queue size == senders')
    parser.add_argument('--max-size', dest='max_size', type=int, default=1024,
                        help='Maximum total bytes(!) to read for a single host (default 1024)')
    parser.add_argument('-tconnect', '--timeout-connection', dest='conn_timeout', type=int, default=7,
                        help='Set connection timeout for open_connection, seconds (default: 7)')
    parser.add_argument('-tread', '--timeout-read', dest='read_timeout', type=int, default=7,
                        help='Set connection timeout for reader from connection, seconds (default: 7)')
    parser.add_argument('-tssl', '--timeout-ssl', dest='ssl_timeout', type=int, default=7,
                        help='Set connection timeout for reader from ssl connection, seconds (default: 7)')
    parser.add_argument('-p', '--port', type=int, help='Specify port (default: 80)', default=80, required=True)
    parser.add_argument('--use-ssl', dest='ssl_check', action='store_true')
    # region filters
    parser.add_argument('--single-contain', dest='single_contain', type=str,
                        help='trying to find a substring in a response(set in base64)')
    parser.add_argument('--single-contain-hex', dest='single_contain_hex', type=str,
                        help='trying to find a substring in a response bytes (set in bytes(hex))')
    parser.add_argument('--single-contain-string', dest='single_contain_string', type=str,
                        help='trying to find a substring in a response(set in str)')
    parser.add_argument('--without-hexdump', dest='without_hexdump', action='store_true',
                        help='without hexdump in result record')
    parser.add_argument('--body-not-empty', dest='body_not_empty', action='store_true',
                        help='if set, check that content_length > 0 (field "body_raw" not empty)')
    parser.add_argument('--show-only-success', dest='show_only_success', action='store_true')
    # endregion
    parser.add_argument('--list-payloads', nargs='*', dest='list_payloads',
                        help='list payloads(bytes stored in files): file1 file2 file2', required=False)
    parser.add_argument('--single-payload', dest='single_payload', type=str, help='single payload in BASE64 from bytes')
    parser.add_argument('--single-payload-hex', dest='single_payload_hex', type=str,
                        help='single payload in hex(bytes)')
    parser.add_argument('--python-payloads', dest='python_payloads', type=str, help='path to Python module')
    parser.add_argument('--generator-payloads', dest='generator_payloads', type=str,
                        help='name function of gen.payloads from Python module')
    parser.add_argument('--show-statistics', dest='statistics', action='store_true')
    return parser.parse_args()


# noinspection PyBroadException
def parse_settings(args: argparse.Namespace) -> Tuple[TargetConfig, AppConfig]:
    if args.settings:
        return parse_settings_file(args.settings)

    if not args.input_stdin and not args.input_file and not args.single_targets:
        print("""errors, set input source:
         --stdin read targets from stdin;
         -t,--targets set targets, see -h;
         -f,--input-file read from file with targets, see -h""")
        exit(1)

    payloads = []
    search_values = []
    input_file = None

    if args.mode not in ('single', 'multi'):
        abort('Exit, type of read mode from connections?')

    if args.input_file:
        input_file = args.input_file
        if not path.isfile(input_file):
            abort(f'ERROR: file not found: {input_file}')

    if not args.output_file:
        output_file, write_mode = '/dev/stdout', 'wb'
    else:
        output_file, write_mode = args.output_file, 'a'

    if args.list_payloads:
        payloads = list(return_payloads_from_files(args.list_payloads))
    # endregion

    if args.single_contain:
        try:
            search_value = decode_base64_string(args.single_contain)
            assert search_value is not None
            search_values.append(search_value)
        except Exception as e:
            abort('errors with --single-contain options', e)
    elif args.single_contain_string:
        try:
            search_value = str(args.single_contain_string).encode('utf-8')
            assert search_value is not None
            search_values.append(search_value)
        except Exception as e:
            abort('errors with --single-contain-string options', e)
    elif args.single_contain_hex:
        try:
            search_value = bytes.fromhex(args.single_contain_hex)
            assert search_value is not None
            search_values.append(search_value)
        except Exception as e:
            abort('errors with --single-contain-hex options', e)

    single_payload = None
    if args.single_payload:
        single_payload = decode_base64_string(args.single_payload)
    elif args.single_payload_hex:
        try:
            single_payload = bytes.fromhex(args.single_payload_hex)
        except BaseException:
            pass
    if single_payload:
        payloads.append(single_payload)

    target_settings = TargetConfig(**{
        'port': args.port,
        'ssl_check': args.ssl_check,
        'conn_timeout': args.conn_timeout,
        'read_timeout': args.read_timeout,
        'ssl_timeout': args.ssl_timeout,
        'list_payloads': payloads,
        'search_values': search_values,
        'max_size': args.max_size,
        'python_payloads': args.python_payloads,
        'generator_payloads': args.generator_payloads,
        'mode': args.mode,
        'without_hexdump': args.without_hexdump
    })

    app_settings = AppConfig(**{
        'senders': args.senders,
        'queue_sleep': args.queue_sleep,
        'statistics': args.statistics,
        'input_file': input_file,
        'input_stdin': args.input_stdin,
        'single_targets': args.single_targets,
        'output_file': output_file,
        'write_mode': write_mode,
        'show_only_success': args.show_only_success,
        'body_not_empty': args.body_not_empty
    })


    return target_settings, app_settings


def abort(message: str, exc: Exception = None, exit_code: int = 1):
    print(message, file=stderr)
    if exc:
        print(exc, file=stderr)
    exit(exit_code)


def parse_settings_file(file_path: str) -> Tuple[TargetConfig, AppConfig]:
    raise NotImplementedError('config read')
