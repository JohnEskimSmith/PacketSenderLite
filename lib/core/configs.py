from collections import namedtuple
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class AppConfig:
    senders: int
    queue_sleep: int
    statistics: bool
    input_file: str
    output_file: str
    write_mode: str
    show_only_success: bool


@dataclass(frozen=True)
class TargetConfig:
    port: int
    ssl_check: bool
    conn_timeout: int
    read_timeout: int
    ssl_timeout: int
    list_payloads: List[bytes]
    python_payloads: str
    generator_payloads: str
    mode: str  # TODO: enum
    search_values: List[bytes]
    max_size: int

    def as_dict(self):
        return {
            'port': self.port,
            'ssl_check': self.ssl_check,
            'conn_timeout': self.conn_timeout,
            'read_timeout': self.read_timeout,
            'ssl_timeout': self.ssl_timeout,
            'list_payloads': self.list_payloads,
            'python_payloads': self.python_payloads,
            'generator_payloads': self.generator_payloads,
            'mode': self.mode,
            'search_values': self.search_values,
            'max_size': self.max_size,
        }


Target = namedtuple('Target', ['port', 'ssl_check', 'conn_timeout', 'read_timeout', 'ssl_timeout', 'list_payloads',
                               'python_payloads', 'generator_payloads', 'search_values', 'mode', 'max_size', 'ip',
                               'payload', 'additions'])
