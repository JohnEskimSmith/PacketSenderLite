#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "SAI"
__license__ = "GPLv3"
__status__ = "Dev"


def generator_http_get() -> list:
    """
    example gen. bytes payload - for http - b'GET / HTTP/1.0\r\n\r\nUser-Agent: curl/7.68.0\r\n\r\nAccept: */*\r\n\r\n'
    :return:
    """
    from inspect import currentframe
    from pickle import dumps as dump_variable
    from base64 import standard_b64encode

    def retrieve_name(var):
        try:
            callers_local_vars = currentframe().f_back.f_locals.items()
            name_var = [var_name for var_name, var_val in callers_local_vars if var_val is var][0]
            value = None
            try:
                _bytes_value = dump_variable(var)
                value = standard_b64encode(_bytes_value).decode('utf-8')
            except:
                pass
            return {name_var: value}
        except:
            pass
    payloads = []  # will be result for function
    _payload = b'GET / HTTP/1.0\r\n\r\nUser-Agent: curl/7.68.0\r\n\r\nAccept: */*\r\n\r\n'
    _payload_base64 = ''
    if isinstance(_payload, bytes):
        _payload_base64 = standard_b64encode(_payload).decode('utf-8')
    example_variable_1, example_variable_2 = '1', b'2'  # will be base64 string from python object "pickled"
    need_values = [example_variable_1, example_variable_2]
    payload = {'payload' : _payload,
               'data_payload': {'payload_raw': _payload_base64,
                               'variables': []
                               }
               }
    for v in need_values:
        _v = retrieve_name(v)
        if _v:
            payload['data_payload']['variables'].append(_v)
    payloads.append(payload)
    return payloads

# print(generator_http_get())