from base64 import b64encode
from ipaddress import ip_network
from typing import Iterator, Generator, Optional

from lib.core import Target, load_python_generator_payloads_from_file, TargetConfig, PayloadGenerator


# noinspection PyArgumentList


def create_target_tcp_protocol(ip_str: str, target_config: TargetConfig) -> Iterator[Target]:
    """
    На основании ip адреса и настроек возвращает через yield экзэмпляр Target.
    Каждый экземпляр Target содержит всю необходимую информацию(настройки и параметры) для функции worker.
    """
    kwargs = target_config.as_dict()

    if target_config.list_payloads:
        for payload in target_config.list_payloads:
            additions = {'data_payload': {'payload_raw': b64encode(payload).decode('utf-8'), 'variables': []}}
            yield Target(ip=ip_str, payload=payload, additions=additions, **kwargs)
    elif target_config.python_payloads:
        payloads_generator = get_generator(target_config)
        for _payload in payloads_generator(ip_str, kwargs):
            payload = _payload['payload']
            additions = _payload['data_payload']
            yield Target(ip=ip_str, payload=payload, additions=additions, **kwargs)
    else:
        # No payload means 'just read the service banners'
        yield Target(ip=ip_str, payload=None, additions=None, **kwargs)


def get_generator(target_config: TargetConfig) -> Optional[PayloadGenerator]:
    func_name = 'generator_payloads'
    if target_config.generator_payloads:
        func_name = target_config.generator_payloads.strip('"').strip("'")
    path_to_module = target_config.python_payloads.strip('"').strip("'")
    payloads_generator = load_python_generator_payloads_from_file(path_to_module, func_name)
    return payloads_generator


def create_targets_tcp_protocol(ip_str: str, settings: TargetConfig) -> Generator[Target, None, None]:
    """
    Функция для обработки "подсетей" и создания "целей"
    """
    hosts = ip_network(ip_str, strict=False)
    for host in hosts:
        for target in create_target_tcp_protocol(str(host), settings):
            yield target
