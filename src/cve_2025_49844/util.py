from __future__ import annotations
import struct
from typing import Callable, Optional, TypeVar

T = TypeVar('T')
U = TypeVar('U')

def optional_map(value: Optional[T], f: Callable[[T], Optional[U]]) -> Optional[U]:
    if value is None:
        return None
    return f(value)

def u32_le(value: int) -> bytes:
    return struct.pack('<I', value)

def u64_le(value: int) -> bytes:
    return struct.pack('<Q', value)
