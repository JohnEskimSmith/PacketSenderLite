__all__ = ['access_dot_path']

from typing import Optional, Any


def access_dot_path(dictionary: dict, path: str) -> Optional[Any]:
    """
    Access dot-separated path in dictionary or return None
    """
    dot_index = path.find('.')
    if dot_index == -1:  # no more dots in path
        return dictionary[path]
    previous = path[:dot_index]  # key before first dot
    if previous not in dictionary:
        return None
    element = dictionary[previous]
    if isinstance(element, dict):
        return access_dot_path(element, path[dot_index + 1:])
