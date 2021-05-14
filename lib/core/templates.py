from base64 import b64encode
from hashlib import sha256, sha1, md5

from hexdump import hexdump

from .configs import Target

__all__ = ['create_result_template', 'create_error_template', 'make_document_from_response']


def create_result_template(target: Target) -> dict:
    """
    Creates result dictionary skeleton
    """
    result = {'data': {'tcp': {'status': 'tcp', 'result': {'response': {'request': {}}}}}}
    if target.ssl_check:
        tls_log = {'handshake_log': {'server_certificates': {'certificate': {'parsed': {}, 'raw': ''}}}}
        result['data']['tcp']['result']['response']['request']['tls_log'] = tls_log
    return result


def create_error_template(target: Target,
                          error_str: str,
                          description: str = ''
                          ) -> dict:
    """
    Creates skeleton of error result dictionary
    """
    if not description:
        return {
            'ip': target.ip,
            'port': target.port,
            'data': {
                'tcp': {
                    'status': 'unknown-error',
                    'error': error_str
                }
            }
        }
    else:
        return {
            'ip': target.ip,
            'port': target.port,
            'data': {
                'tcp': {
                    'status': 'unknown-error',
                    'error': error_str,
                    'description': description
                }
            }
        }


# noinspection PyBroadException
def make_document_from_response(buffer: bytes, target: Target) -> dict:
    """
    Обработка результата чтения байт из соединения
    - buffer - байты полученные от сервиса(из соединения)
    - target - информация о цели (какой порт, ip, payload и так далее)
    результат - словарь с результатом, который будет отправлен в stdout
    """

    result = create_result_template(target)
    result['data']['tcp']['status'] = 'success'
    result['data']['tcp']['result']['response']['content_length'] = len(buffer)
    try:
        result['data']['tcp']['options'] = target.additions
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
        result['data']['tcp']['result']['response']['body_raw'] = b64encode(buffer).decode('utf-8')
        # _base64_data - содержит байты в base64 - для того чтоб их удобно было
        # отправлять в stdout
    except Exception:
        pass
    try:
        # функции импортированные из hashlib для подсчета хэшей
        # sha256, sha1, md5
        hashes = {'sha256': sha256, 'sha1': sha1, 'md5': md5}
        for algo, func in hashes.items():
            hm = func()
            hm.update(buffer)
            result['data']['tcp']['result']['response'][f'body_{algo}'] = hm.hexdigest()
    except Exception:
        pass
    if not target.without_hexdump:
        result['data']['tcp']['result']['response']['body_hexdump'] = ''
        try:
            # еще одно представление результата(байт)
            # Transform binary data to the hex dump text format:
            # 00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  .........
            # для этого и необходим модуль hexdump
            hdump = hexdump(buffer, result='return')
            output = b64encode(bytes(hdump, 'utf-8')).decode('utf-8')
            result['data']['tcp']['result']['response']['body_hexdump'] = output
        except Exception:
            pass
    result['ip'] = target.ip
    result['port'] = int(target.port)
    return result
