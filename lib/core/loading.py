import importlib
from os import path, pathsep
from pathlib import Path
from typing import Callable, Iterable, Generator, Optional

__all__ = ['payload_generator_from_py_module', 'payload_generator_from_py_file',
           'load_python_generator_payloads_from_file', 'filter_files', 'return_payloads_from_files',
           'PayloadGenerator']


PayloadGenerator = Callable[[str, dict], Iterable]  # Payloads factory for given IP


def payload_generator_from_py_module(module_name: str, function_name: str) -> PayloadGenerator:
    """
    Imports generator function from required module
    """
    _mod = importlib.import_module(module_name)
    return getattr(_mod, function_name)


# noinspection PyUnresolvedReferences
def payload_generator_from_py_file(py_module_path, function_name: str) -> PayloadGenerator:
    """
    Imports generator function from single .py file
    """
    module_name_like_filename_py = str(py_module_path).rstrip('.py')
    spec = importlib.util.spec_from_file_location(module_name_like_filename_py, py_module_path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return getattr(m, function_name)


# noinspection PyBroadException
def load_python_generator_payloads_from_file(py_module_path: str, _name_function: str) -> Optional[PayloadGenerator]:
    """
    Imports generator from python file OR module
    """
    if py_module_path.endswith('.py'):
        if pathsep in py_module_path:
            _path_to_file = Path(py_module_path)
        else:
            _path_to_file = Path(__file__).parent / py_module_path
        try:
            if _path_to_file.exists() and _path_to_file.is_file():
                return payload_generator_from_py_file(_path_to_file, _name_function)
        except Exception as exp:
            print(exp)  # костыль
    else:
        try:
            return payload_generator_from_py_module(py_module_path, _name_function)
        except Exception:
            pass


def filter_files(payload_files: Iterable[str]) -> Generator[str, None, None]:
    """
    Leaves only file entries from list of paths
    """
    return (path_to_file for path_to_file in payload_files if path.isfile(path_to_file))


def return_payloads_from_files(payload_files: Iterable[str]) -> Generator[bytes, None, None]:
    """
    Yields byte payloads from given files
    """
    for payloadfile in filter_files(payload_files):
        with open(payloadfile, 'rb') as f:
            payload = f.read()
            yield payload
