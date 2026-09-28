"""Process hardening so secrets in memory cannot be read out of the process.

Python cannot reliably wipe passwords or keys from memory, so instead we make
sure that memory never leaves the process:

* Core dumps are disabled (RLIMIT_CORE = 0). A crash can no longer write a copy
  of memory, including keys, to disk via systemd-coredump or a core file.
* The process is marked non-dumpable (PR_SET_DUMPABLE = 0). Other programs
  running as the same user can no longer attach a debugger, read
  /proc/<pid>/mem or /proc/<pid>/environ, and the kernel will not dump it
  either. Only root can still inspect it.

Trade-off: the desktop portal refuses requests from non-dumpable processes, so
Locksmith uses its own file dialogs and asks the desktop for its colour scheme
through a short-lived child process (see locksmith/ui/host.py).

No network: ``block_network()`` installs a seccomp filter on every thread so the
process cannot create internet (or any non-local) sockets at all. Only Unix
sockets (Wayland, X11, D-Bus) and netlink stay allowed. 32-bit system calls and
io_uring, which could sidestep the filter, are refused too. Programs Locksmith
opens are started by systemd (ui/host.py), outside this sandbox.

Windows: only protections that can be applied and verified are attempted. Two
process mitigation policies block DLL injection (extension points such as
AppInit DLLs and global hooks are disabled; libraries are never loaded from
network shares or low-integrity files). Both are read back after being set.
Core-dump, memory-reading and network protections have no reliable unprivileged
equivalent on Windows and are reported as unavailable.

Swap is left to the OS: Fedora swaps to compressed RAM (zram) by default, and
full-disk encryption covers disk swap and hibernation images.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import platform
import struct
import sys
from dataclasses import dataclass, field

PR_SET_DUMPABLE = 4
PR_GET_DUMPABLE = 3
PR_SET_NO_NEW_PRIVS = 38

# Per-architecture constants for the network filter.
_ARCH = {
    #          audit arch    socket  seccomp  io_uring_setup  has x32 ABI
    "x86_64": (0xC000003E, 41, 317, 425, True),
    "aarch64": (0xC00000B7, 198, 277, 425, False),
}
AF_UNIX, AF_NETLINK = 1, 16
SECCOMP_SET_MODE_FILTER = 1
SECCOMP_FILTER_FLAG_TSYNC = 1
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000


@dataclass
class HardeningStatus:
    core_dumps_disabled: bool = False
    non_dumpable: bool = False
    network_blocked: bool = False
    injection_blocked: bool = False   # Windows mitigation policies
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        if sys.platform == "win32":
            return self.injection_blocked
        return self.core_dumps_disabled and self.non_dumpable


status = HardeningStatus()


def _libc():
    name = ctypes.util.find_library("c") or "libc.so.6"
    return ctypes.CDLL(name, use_errno=True)


def harden() -> HardeningStatus:
    """Apply protections. Safe to call more than once; never raises."""
    if sys.platform == "win32":
        return _harden_windows()
    if not sys.platform.startswith("linux"):
        status.problems.append("Memory protection is only implemented on Linux and Windows.")
        return status

    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        status.core_dumps_disabled = resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
    except (OSError, ValueError) as e:
        status.problems.append(f"Could not disable core dumps: {e}")

    try:
        libc = _libc()
        libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        libc.prctl.restype = ctypes.c_int
        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE) failed")
        status.non_dumpable = libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0
    except (OSError, AttributeError) as e:
        status.problems.append(f"Could not protect process memory: {e}")

    return status


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte),
                ("k", ctypes.c_uint)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter))]


def _network_filter(machine: str) -> list[tuple[int, int, int, int]]:
    """Classic BPF program for seccomp. Offsets into struct seccomp_data:
    nr at 0, arch at 4, args[0] (low 32 bits, little endian) at 16."""
    audit_arch, nr_socket, _, nr_io_uring, has_x32 = _ARCH[machine]
    LD, JEQ, JGE, RET = 0x20, 0x15, 0x35, 0x06
    allow = ("ret", SECCOMP_RET_ALLOW)
    prog = [
        ("insn", LD, 0, 0, 4),                                   # A = arch
        ("jump", JEQ, audit_arch, "native", None),               # other ABIs (e.g. i386 socketcall)
        ("ret", SECCOMP_RET_ERRNO | errno.EPERM),
        ("label", "native"),
        ("insn", LD, 0, 0, 0),                                   # A = syscall number
    ]
    if has_x32:
        prog += [("jump", JGE, 0x40000000, "deny", None)]        # x32 ABI
    prog += [
        ("jump", JEQ, nr_io_uring, "enosys", None),              # io_uring can open sockets too
        ("jump", JEQ, nr_socket, "socket", None),
        allow,
        ("label", "socket"),
        ("insn", LD, 0, 0, 16),                                  # A = domain (args[0])
        ("jump", JEQ, AF_UNIX, "allow", None),
        ("jump", JEQ, AF_NETLINK, "allow", None),
        ("ret", SECCOMP_RET_ERRNO | errno.EAFNOSUPPORT),
        ("label", "deny"),
        ("ret", SECCOMP_RET_ERRNO | errno.EPERM),
        ("label", "enosys"),
        ("ret", SECCOMP_RET_ERRNO | errno.ENOSYS),
        ("label", "allow"),
        allow,
    ]
    # Resolve labels into relative jump offsets.
    positions, pc = {}, 0
    for item in prog:
        if item[0] == "label":
            positions[item[1]] = pc
        else:
            pc += 1
    out, pc = [], 0
    for item in prog:
        if item[0] == "label":
            continue
        if item[0] == "insn":
            out.append(item[1:])
        elif item[0] == "ret":
            out.append((RET, 0, 0, item[1]))
        else:
            _, code, k, target, _ = item
            offset = positions[target] - pc - 1
            if not 0 <= offset <= 255:
                raise ValueError("BPF jump out of range")
            out.append((code, offset, 0, k))
        pc += 1
    return out


def block_network() -> bool:
    """Forbid creating non-local sockets for this process, all its threads and any
    child it starts directly. Irreversible. Never raises."""
    if sys.platform == "win32":
        status.problems.append("The network block is not available on Windows.")
        return False
    machine = platform.machine()
    if not sys.platform.startswith("linux") or machine not in _ARCH or struct.pack("=H", 1) != b"\x01\x00":
        status.problems.append(f"The network block is not available on {machine}.")
        return False
    try:
        libc = _libc()
        libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")
        insns = _network_filter(machine)
        arr = (_SockFilter * len(insns))(*[_SockFilter(*i) for i in insns])
        prog = _SockFprog(len(insns), arr)
        libc.syscall.restype = ctypes.c_long
        rc = libc.syscall(ctypes.c_long(_ARCH[machine][2]), ctypes.c_long(SECCOMP_SET_MODE_FILTER),
                          ctypes.c_long(SECCOMP_FILTER_FLAG_TSYNC), ctypes.byref(prog))
        if rc != 0:
            raise OSError(ctypes.get_errno(), f"seccomp failed (thread {rc} could not be synchronised)"
                          if rc > 0 else "seccomp failed")
        status.network_blocked = True
    except (OSError, ValueError, AttributeError) as e:
        status.problems.append(f"Could not block network access: {e}")
    return status.network_blocked


# ── Windows ──────────────────────────────────────────────────────────────────

_ProcessExtensionPointDisablePolicy = 6
_ProcessImageLoadPolicy = 10
_EXTENSION_POINTS_DISABLED = 0x1          # DisableExtensionPoints
_IMAGE_LOAD_RESTRICTED = 0x1 | 0x2        # NoRemoteImages | NoLowMandatoryLabelImages


def _harden_windows() -> HardeningStatus:
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        setp, getp = k32.SetProcessMitigationPolicy, k32.GetProcessMitigationPolicy
        setp.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
        getp.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
        setp.restype = getp.restype = ctypes.c_int
        k32.GetCurrentProcess.restype = ctypes.c_void_p
        applied = True
        for policy, flags in ((_ProcessExtensionPointDisablePolicy, _EXTENSION_POINTS_DISABLED),
                              (_ProcessImageLoadPolicy, _IMAGE_LOAD_RESTRICTED)):
            value = ctypes.c_uint32(flags)
            setp(policy, ctypes.byref(value), ctypes.sizeof(value))
            # Trust only what the OS reports back, not the setter's return value.
            readback = ctypes.c_uint32(0)
            ok = getp(k32.GetCurrentProcess(), policy, ctypes.byref(readback), ctypes.sizeof(readback))
            applied = applied and bool(ok) and (readback.value & flags) == flags
        status.injection_blocked = applied
        if not applied:
            status.problems.append("This version of Windows did not accept the DLL-injection protections.")
    except (OSError, AttributeError) as e:
        status.problems.append(f"Could not apply Windows protections: {e}")
    status.problems.append("Crash-dump and memory-reading protection are not available on Windows.")
    return status
