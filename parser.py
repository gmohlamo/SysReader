#!/usr/bin/env python3
"""
SyscallDatabaseBuilder
Generates a comprehensive Linux syscall & flag database for the SysReader radare2 plugin.
Leverages `gcc -dM -E <header>` to preprocess and extract macros across host system headers,
resolving constants, bitwise expressions, and nested struct fields.
"""

import os
import re
import sys
import json
import argparse
import subprocess
import tempfile


class SyscallDatabaseBuilder:
    def __init__(self, extra_headers=None):
        self.raw_macros = {}
        self.constants = {}
        self.structs = {}

        # Default header files to scan dynamically using GCC preprocessor
        self.header_paths = [
            # File and VFS headers
            "/usr/include/asm-generic/fcntl.h",
            "/usr/include/fcntl.h",
            "/usr/include/linux/fcntl.h",
            "/usr/include/linux/fs.h",
            "/usr/include/linux/openat2.h",
            "/usr/include/linux/falloc.h",
            "/usr/include/sys/stat.h",
            "/usr/include/linux/stat.h",
            "/usr/include/sys/mount.h",
            "/usr/include/linux/mount.h",
            "/usr/include/poll.h",
            "/usr/include/sys/epoll.h",
            "/usr/include/linux/eventpoll.h",
            "/usr/include/sys/inotify.h",
            "/usr/include/sys/eventfd.h",
            "/usr/include/sys/signalfd.h",
            "/usr/include/sys/timerfd.h",
            # Memory headers
            "/usr/include/asm-generic/mman.h",
            "/usr/include/asm-generic/mman-common.h",
            "/usr/include/sys/mman.h",
            "/usr/include/linux/mman.h",
            "/usr/include/linux/memfd.h",
            "/usr/include/linux/userfaultfd.h",
            # Process & IPC headers
            "/usr/include/linux/sched.h",
            "/usr/include/sched.h",
            "/usr/include/signal.h",
            "/usr/include/sys/wait.h",
            "/usr/include/linux/wait.h",
            "/usr/include/linux/prctl.h",
            "/usr/include/sys/prctl.h",
            "/usr/include/sys/ptrace.h",
            "/usr/include/linux/ptrace.h",
            "/usr/include/linux/futex.h",
            "/usr/include/linux/pidfd.h",
            "/usr/include/linux/reboot.h",
            "/usr/include/linux/bpf.h",
            "/usr/include/linux/random.h",
            "/usr/include/linux/io_uring.h",
            "/usr/include/linux/kexec.h",
            # Networking headers
            "/usr/include/sys/socket.h",
            "/usr/include/linux/socket.h",
            "/usr/include/netinet/in.h",
            "/usr/include/linux/in.h",
            "/usr/include/unistd.h",
        ]

        if extra_headers:
            for eh in extra_headers:
                if eh not in self.header_paths:
                    self.header_paths.append(eh)

        # Blacklist of macro names that are not valid flags/options
        self.macro_blacklist = {
            "MAP_FAILED",
            "MAP_HUGE_SHIFT",
            "MAP_HUGE_MASK",
            "CLONE_ARGS_SIZE_VER0",
            "CLONE_ARGS_SIZE_VER1",
            "CLONE_ARGS_SIZE_VER2",
            "SIGSTKSZ",
            "SIGRTMIN",
            "SIGRTMAX",
            "SIGUNUSED",
            "SIG_BLOCK",
            "SIG_UNBLOCK",
            "SIG_SETMASK",
            "SIG_DFL",
            "SIG_IGN",
            "SIG_ERR",
            "O_ACCMODE",
            "AF_MAX",
            "SOCK_IOC_TYPE",
            "SOCK_TXREHASH_ENABLED",
            "SOCK_TXREHASH_DISABLED",
            "SOCK_TXREHASH_DEFAULT",
            "SOCK_SNDBUF_LOCK",
            "SOCK_RCVBUF_LOCK",
            "SOCK_BUF_LOCK_MASK",
        }

        # Canonical names for aliases (preferred name over alias)
        self.preferred_names = {
            "MAP_ANON": "MAP_ANONYMOUS",
            "O_NDELAY": "O_NONBLOCK",
            "O_FSYNC": "O_SYNC",
            "O_RSYNC": "O_SYNC",
            "SIGCLD": "SIGCHLD",
            "SIGIOT": "SIGABRT",
            "SIGPOLL": "SIGIO",
            "SIGUNUSED": "SIGSYS",
        }

        # Prefix routing table: defines which macro prefixes/names route to which argument
        self.prefix_routing = {
            "open": {
                "flags": ["O_"],
                "mode": ["S_IR", "S_IW", "S_IX", "S_IRWX"],
            },
            "openat": {
                "dfd": ["AT_FDCWD"],
                "flags": ["O_"],
                "mode": ["S_IR", "S_IW", "S_IX", "S_IRWX"],
            },
            "openat2": {
                "dfd": ["AT_FDCWD"],
                "struct_fields": {
                    "flags": ["O_"],
                    "mode": ["S_IR", "S_IW", "S_IX", "S_IRWX"],
                    "resolve": ["RESOLVE_"],
                },
            },
            "creat": {
                "mode": ["S_IR", "S_IW", "S_IX", "S_IRWX"],
            },
            "mmap": {
                "prot": ["PROT_"],
                "flags": ["MAP_"],
            },
            "mprotect": {
                "prot": ["PROT_"],
            },
            "pkey_mprotect": {
                "prot": ["PROT_"],
            },
            "mremap": {
                "flags": ["MREMAP_"],
            },
            "msync": {
                "flags": ["MS_ASYNC", "MS_SYNC", "MS_INVALIDATE"],
            },
            "madvise": {
                "behavior": ["MADV_"],
            },
            "fadvise64": {
                "advice": ["POSIX_FADV_"],
            },
            "mlock2": {
                "flags": ["MLOCK_", "MCL_"],
            },
            "mlockall": {
                "flags": ["MCL_"],
            },
            "memfd_create": {
                "flags": ["MFD_"],
            },
            "userfaultfd": {
                "flags": ["UFFD_", "O_CLOEXEC", "O_NONBLOCK"],
            },
            "clone": {
                "flags": {
                    "flags": ["CLONE_"],
                    "signals": ["SIG"],
                },
            },
            "clone3": {
                "struct_fields": {
                    "flags": ["CLONE_"],
                    "exit_signal": {
                        "signals": ["SIG"],
                    },
                },
            },
            "execveat": {
                "dfd": ["AT_FDCWD"],
                "flags": ["AT_"],
            },
            "fchmodat": {
                "dfd": ["AT_FDCWD"],
                "mode": ["S_IR", "S_IW", "S_IX", "S_IRWX"],
                "flags": ["AT_"],
            },
            "fchownat": {
                "dfd": ["AT_FDCWD"],
                "flags": ["AT_"],
            },
            "linkat": {
                "olddfd": ["AT_FDCWD"],
                "newdfd": ["AT_FDCWD"],
                "flags": ["AT_"],
            },
            "unlinkat": {
                "dfd": ["AT_FDCWD"],
                "flags": ["AT_"],
            },
            "readlinkat": {
                "dfd": ["AT_FDCWD"],
            },
            "symlinkat": {
                "newdfd": ["AT_FDCWD"],
            },
            "utimensat": {
                "dfd": ["AT_FDCWD"],
                "flags": ["AT_"],
            },
            "renameat2": {
                "olddfd": ["AT_FDCWD"],
                "newdfd": ["AT_FDCWD"],
                "flags": ["RENAME_"],
            },
            "access": {
                "mode": ["R_OK", "W_OK", "X_OK", "F_OK"],
            },
            "faccessat": {
                "dfd": ["AT_FDCWD"],
                "mode": ["R_OK", "W_OK", "X_OK", "F_OK"],
            },
            "faccessat2": {
                "dfd": ["AT_FDCWD"],
                "mode": ["R_OK", "W_OK", "X_OK", "F_OK"],
                "flags": ["AT_"],
            },
            "chmod": {
                "mode": ["S_IR", "S_IW", "S_IX", "S_IRWX"],
            },
            "fchmod": {
                "mode": ["S_IR", "S_IW", "S_IX", "S_IRWX"],
            },
            "umask": {
                "mask": ["S_IR", "S_IW", "S_IX", "S_IRWX"],
            },
            "statx": {
                "dfd": ["AT_FDCWD"],
                "flags": ["AT_"],
                "mask": ["STATX_"],
            },
            "lseek": {
                "whence": ["SEEK_"],
            },
            "fcntl": {
                "cmd": ["F_"],
                "arg": ["FD_CLOEXEC", "O_", "LOCK_", "F_SEAL_"],
            },
            "flock": {
                "operation": ["LOCK_"],
            },
            "fallocate": {
                "mode": ["FALLOC_FL_"],
            },
            "pipe2": {
                "flags": ["O_CLOEXEC", "O_NONBLOCK", "O_DIRECT"],
            },
            "dup3": {
                "flags": ["O_CLOEXEC"],
            },
            "socket": {
                "family": ["AF_"],
                "type": ["SOCK_"],
                "protocol": ["IPPROTO_"],
            },
            "socketpair": {
                "family": ["AF_"],
                "type": ["SOCK_"],
                "protocol": ["IPPROTO_"],
            },
            "sendto": {
                "flags": ["MSG_"],
            },
            "sendmsg": {
                "flags": ["MSG_"],
            },
            "sendmmsg": {
                "flags": ["MSG_"],
            },
            "recvfrom": {
                "flags": ["MSG_"],
            },
            "recvmsg": {
                "flags": ["MSG_"],
            },
            "recvmmsg": {
                "flags": ["MSG_"],
            },
            "shutdown": {
                "how": ["SHUT_"],
            },
            "poll": {
                "events": ["POLL"],
            },
            "ppoll": {
                "events": ["POLL"],
            },
            "epoll_create1": {
                "flags": ["EPOLL_CLOEXEC"],
            },
            "epoll_ctl": {
                "op": ["EPOLL_CTL_"],
            },
            "eventfd2": {
                "flags": ["EFD_"],
            },
            "signalfd": {
                "flags": ["SFD_"],
            },
            "signalfd4": {
                "flags": ["SFD_"],
            },
            "timerfd_create": {
                "clockid": ["CLOCK_"],
                "flags": ["TFD_"],
            },
            "timerfd_settime": {
                "flags": ["TFD_TIMER_"],
            },
            "inotify_init1": {
                "flags": ["IN_CLOEXEC", "IN_NONBLOCK"],
            },
            "inotify_add_watch": {
                "mask": ["IN_"],
            },
            "futex": {
                "op": ["FUTEX_"],
            },
            "prctl": {
                "option": ["PR_"],
            },
            "arch_prctl": {
                "code": ["ARCH_"],
            },
            "ptrace": {
                "request": ["PTRACE_"],
            },
            "wait4": {
                "options": ["WNOHANG", "WUNTRACED", "WCONTINUED", "__WCLONE", "__WALL", "__WNOTHREAD"],
            },
            "waitid": {
                "which": ["P_PID", "P_PGID", "P_ALL", "P_PIDFD"],
                "options": ["WNOHANG", "WNOWAIT", "WEXITED", "WSTOPPED", "WCONTINUED"],
            },
            "kill": {
                "sig": {
                    "signals": ["SIG"],
                },
            },
            "tkill": {
                "sig": {
                    "signals": ["SIG"],
                },
            },
            "tgkill": {
                "sig": {
                    "signals": ["SIG"],
                },
            },
            "rt_sigprocmask": {
                "how": ["SIG_BLOCK", "SIG_UNBLOCK", "SIG_SETMASK"],
            },
            "mount": {
                "flags": ["MS_RDONLY", "MS_NOSUID", "MS_NODEV", "MS_NOEXEC", "MS_SYNCHRONOUS",
                          "MS_REMOUNT", "MS_MANDLOCK", "MS_DIRSYNC", "MS_NOSYMFOLLOW", "MS_NOATIME",
                          "MS_NODIRATIME", "MS_BIND", "MS_MOVE", "MS_REC", "MS_SILENT", "MS_POSIXACL",
                          "MS_UNBINDABLE", "MS_PRIVATE", "MS_SLAVE", "MS_SHARED", "MS_RELATIME",
                          "MS_KERNMOUNT", "MS_I_VERSION", "MS_STRICTATIME", "MS_LAZYTIME", "MS_ACTIVE"],
            },
            "umount2": {
                "flags": ["MNT_"],
            },
            "reboot": {
                "magic1": ["LINUX_REBOOT_MAGIC1"],
                "magic2": ["LINUX_REBOOT_MAGIC2"],
                "cmd": ["LINUX_REBOOT_CMD_"],
            },
            "bpf": {
                "cmd": ["BPF_"],
            },
            "sync_file_range": {
                "flags": ["SYNC_FILE_RANGE_"],
            },
            "splice": {
                "flags": ["SPLICE_F_"],
            },
            "tee": {
                "flags": ["SPLICE_F_"],
            },
            "vmsplice": {
                "flags": ["SPLICE_F_"],
            },
            "getrandom": {
                "flags": ["GRND_"],
            },
            "pidfd_open": {
                "flags": ["PIDFD_"],
            },
            "pidfd_send_signal": {
                "sig": {
                    "signals": ["SIG"],
                },
                "flags": ["PIDFD_"],
            },
            "sched_setscheduler": {
                "policy": ["SCHED_"],
            },
            "kexec_load": {
                "flags": ["KEXEC_"],
            },
            "kexec_file_load": {
                "flags": ["KEXEC_"],
            },
            "io_uring_enter": {
                "flags": ["IORING_ENTER_"],
            },
        }

    def scan_header_with_gcc(self, header_path):
        """Runs gcc -dM -E on the specified header to retrieve preprocessed macro definitions."""
        if not os.path.exists(header_path):
            print(f"[-] Skipping missing header: {header_path}")
            return {}

        cmd = ["gcc", "-dM", "-E", header_path]
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[-] Error running '{' '.join(cmd)}': {e.stderr.strip()[:100]}")
            return {}

        macros = {}
        for line in res.stdout.splitlines():
            # Match #define NAME VALUE (skip function-like macros #define NAME(...))
            m = re.match(r'^#define\s+([A-Za-z0-9_]+)\s+(.+)$', line)
            if m:
                name, val = m.groups()
                macros[name] = val.strip()

        print(f"[*] Parsed {len(macros):>4} macros from: {header_path}")
        return macros

    def scan_all_headers(self):
        """Scans all configured headers using gcc -dM -E and extracts raw macro definitions."""
        print("[*] Gathering macros via 'gcc -dM -E' across host system headers...")
        for path in self.header_paths:
            header_macros = self.scan_header_with_gcc(path)
            self.raw_macros.update(header_macros)
        print(f"[+] Total collected unique macro definitions: {len(self.raw_macros)}")

    def scan_structs(self):
        """Scans header files for struct declarations (e.g. clone_args, open_how)."""
        struct_pattern = re.compile(r'struct\s+([a-zA-Z0-9_]+)\s*\{([^}]+)\};', re.DOTALL)
        field_pattern = re.compile(
            r'^\s*([a-zA-Z0-9_*]+(?:\s+[a-zA-Z0-9_*]+)*)\s+([a-zA-Z0-9_]+)\s*(?:\[\s*\d*\s*\])?\s*;',
            re.MULTILINE
        )

        for path in self.header_paths:
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            for match in struct_pattern.finditer(content):
                s_name, s_body = match.groups()
                fields = []
                for f_match in field_pattern.finditer(s_body):
                    f_type, f_name = f_match.groups()
                    fields.append({"name": f_name, "type": f_type.strip()})

                if fields and s_name not in self.structs:
                    self.structs[s_name] = fields

        print(f"[+] Discovered {len(self.structs)} C structs from headers ({', '.join(sorted(self.structs.keys()))})")

    @staticmethod
    def sanitize_c_expression(expr):
        """Cleans C macro expressions to make them valid Python arithmetic/bitwise expressions."""
        # Strip comments
        expr = re.sub(r'/\*.*?\*/', '', expr)
        expr = re.sub(r'//.*$', '', expr)
        # Strip C-style type casts, e.g. (mode_t), (unsigned long), (__u64)
        expr = re.sub(
            r'\(\s*(?:const\s+)?(?:unsigned\s+|signed\s+)?'
            r'(?:int|long|short|char|mode_t|size_t|loff_t|uint\d+_t|int\d+_t|__u\d+|__s\d+|__aligned_u\d+)\s*\)',
            '',
            expr
        )
        # Strip integer suffixes, e.g. 1ULL, 0x10UL, 2U, 5L
        expr = re.sub(r'(?i)\b(0x[0-9a-f]+|\d+)[ul]+\b', r'\1', expr)
        # Convert C octals, e.g. 0100 -> 0o100, 00 -> 0o0, but leave 0 and hex intact
        expr = re.sub(r'\b0([0-7]+)\b', r'0o\1', expr)
        return expr.strip()

    def evaluate_macros(self):
        """Iteratively evaluates macro expressions into integer constants."""
        print("[*] Evaluating macro expressions and resolving dependencies...")
        evaluated = {}

        # 1. Fast path: Direct integer parsing
        for k, v in self.raw_macros.items():
            if k in self.macro_blacklist:
                continue
            try:
                val = int(v, 0)
                evaluated[k] = val
            except (ValueError, SyntaxError):
                pass

        # 2. Iterative evaluation with Python eval
        changed = True
        iterations = 0
        while changed and iterations < 15:
            changed = False
            iterations += 1
            for k, v in self.raw_macros.items():
                if k in evaluated or k in self.macro_blacklist:
                    continue
                clean_expr = self.sanitize_c_expression(v)
                try:
                    val = eval(clean_expr, {"__builtins__": None}, evaluated)
                    if isinstance(val, int):
                        evaluated[k] = val
                        changed = True
                except Exception:
                    pass

        # 3. Fallback for unresolved target symbols via GCC
        needed_symbols = set()
        all_target_prefixes = set()
        for sc in self.prefix_routing.values():
            for item in sc.values():
                if isinstance(item, list):
                    all_target_prefixes.update(item)
                elif isinstance(item, dict):
                    for sub in item.values():
                        if isinstance(sub, list):
                            all_target_prefixes.update(sub)

        for sym, raw_val in self.raw_macros.items():
            if sym not in evaluated and sym not in self.macro_blacklist:
                if any(sym.startswith(p) for p in all_target_prefixes):
                    needed_symbols.add(sym)

        if needed_symbols:
            gcc_evaluated = self._evaluate_with_gcc(list(needed_symbols))
            evaluated.update(gcc_evaluated)

        self.constants = evaluated
        print(f"[+] Successfully evaluated {len(self.constants)} integer constants!")

    def _evaluate_with_gcc(self, symbols):
        """Compiles a small C program to evaluate macros/enums that could not be parsed statically."""
        if not symbols:
            return {}

        includes = [
            "#include <stdio.h>",
            "#include <fcntl.h>",
            "#include <sys/mman.h>",
            "#include <sys/socket.h>",
            "#include <sys/mount.h>",
            "#include <linux/sched.h>",
            "#include <poll.h>",
            "#include <signal.h>",
        ]
        body = []
        for s in symbols:
            body.append(f"#ifdef {s}\n    printf(\"{s}=%llu\\n\", (unsigned long long)({s}));\n#endif")

        code = "\n".join(includes) + "\nint main() {\n" + "\n".join(body) + "\n    return 0;\n}\n"

        out = {}
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
                f.write(code)
                src_path = f.name
            bin_path = src_path + ".bin"
            p = subprocess.run(["gcc", "-w", "-o", bin_path, src_path],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if p.returncode == 0:
                res = subprocess.run([bin_path], stdout=subprocess.PIPE, text=True, check=True)
                for line in res.stdout.splitlines():
                    if "=" in line:
                        k, v = line.split("=", 1)
                        out[k] = int(v)
            subprocess.run(["rm", "-f", src_path, bin_path], check=False)
        except Exception:
            pass

        return out

    def _filter_flags(self, matched_flags, target_arg_name=""):
        """Filters out non-flag helper constants and resolves preferred canonical names."""
        filtered = {}
        for name, val in matched_flags.items():
            if name in self.macro_blacklist:
                continue
            # Internal glibc/kernel macros starting with double underscore
            if name.startswith("__") and not name.startswith("__W"):
                continue
            # Filter signal names to standard signal range (1..32)
            if name.startswith("SIG"):
                if name.startswith("SIG_") or name.startswith("SIGEV_") or name.startswith("SIGRT"):
                    continue
                if val < 1 or val > 32:
                    continue
            # If target argument is 'flags', exclude AT_FDCWD (-100) which belongs in dfd
            if target_arg_name == "flags" and name == "AT_FDCWD":
                continue
            # De-duplicate aliases in favor of preferred canonical names
            if name in self.preferred_names and self.preferred_names[name] in matched_flags:
                continue
            filtered[name] = val
        return filtered

    def build_database(self):
        """Builds the complete syscall database structure."""
        self.scan_all_headers()
        self.scan_structs()
        self.evaluate_macros()

        database = {
            "open": {
                "args": 3,
                "arguments": {
                    "0": {"name": "filename", "type": "const char *", "param_index": 0},
                    "1": {"name": "flags", "type": "int", "param_index": 1},
                    "2": {"name": "mode", "type": "mode_t", "param_index": 2},
                }
            },
            "openat": {
                "args": 4,
                "arguments": {
                    "0": {"name": "dfd", "type": "int", "param_index": 0},
                    "1": {"name": "filename", "type": "const char *", "param_index": 1},
                    "2": {"name": "flags", "type": "int", "param_index": 2},
                    "3": {"name": "mode", "type": "mode_t", "param_index": 3},
                }
            },
            "openat2": {
                "args": 4,
                "arguments": {
                    "0": {"name": "dfd", "type": "int", "param_index": 0},
                    "1": {"name": "filename", "type": "const char *", "param_index": 1},
                    "2": {
                        "name": "how",
                        "type": "struct open_how *",
                        "param_index": 2,
                        "is_struct": True,
                        "struct_name": "open_how"
                    },
                    "3": {"name": "usize", "type": "size_t", "param_index": 3},
                }
            },
            "creat": {
                "args": 2,
                "arguments": {
                    "0": {"name": "pathname", "type": "const char *", "param_index": 0},
                    "1": {"name": "mode", "type": "mode_t", "param_index": 1},
                }
            },
            "mmap": {
                "args": 6,
                "arguments": {
                    "0": {"name": "addr", "type": "unsigned long", "param_index": 0},
                    "1": {"name": "len", "type": "unsigned long", "param_index": 1},
                    "2": {"name": "prot", "type": "int", "param_index": 2},
                    "3": {"name": "flags", "type": "int", "param_index": 3},
                    "4": {"name": "fd", "type": "int", "param_index": 4},
                    "5": {"name": "off", "type": "unsigned long", "param_index": 5},
                }
            },
            "mprotect": {
                "args": 3,
                "arguments": {
                    "0": {"name": "start", "type": "unsigned long", "param_index": 0},
                    "1": {"name": "len", "type": "size_t", "param_index": 1},
                    "2": {"name": "prot", "type": "unsigned long", "param_index": 2},
                }
            },
            "pkey_mprotect": {
                "args": 4,
                "arguments": {
                    "0": {"name": "start", "type": "unsigned long", "param_index": 0},
                    "1": {"name": "len", "type": "size_t", "param_index": 1},
                    "2": {"name": "prot", "type": "unsigned long", "param_index": 2},
                    "3": {"name": "pkey", "type": "int", "param_index": 3},
                }
            },
            "mremap": {
                "args": 5,
                "arguments": {
                    "0": {"name": "addr", "type": "unsigned long", "param_index": 0},
                    "1": {"name": "old_len", "type": "unsigned long", "param_index": 1},
                    "2": {"name": "new_len", "type": "unsigned long", "param_index": 2},
                    "3": {"name": "flags", "type": "unsigned long", "param_index": 3},
                    "4": {"name": "new_addr", "type": "unsigned long", "param_index": 4},
                }
            },
            "msync": {
                "args": 3,
                "arguments": {
                    "0": {"name": "start", "type": "unsigned long", "param_index": 0},
                    "1": {"name": "len", "type": "size_t", "param_index": 1},
                    "2": {"name": "flags", "type": "int", "param_index": 2},
                }
            },
            "madvise": {
                "args": 3,
                "arguments": {
                    "0": {"name": "start", "type": "unsigned long", "param_index": 0},
                    "1": {"name": "len_in", "type": "size_t", "param_index": 1},
                    "2": {"name": "behavior", "type": "int", "param_index": 2},
                }
            },
            "fadvise64": {
                "args": 4,
                "arguments": {
                    "0": {"name": "fd", "type": "int", "param_index": 0},
                    "1": {"name": "offset", "type": "loff_t", "param_index": 1},
                    "2": {"name": "len", "type": "size_t", "param_index": 2},
                    "3": {"name": "advice", "type": "int", "param_index": 3},
                }
            },
            "mlock2": {
                "args": 3,
                "arguments": {
                    "0": {"name": "start", "type": "unsigned long", "param_index": 0},
                    "1": {"name": "len", "type": "size_t", "param_index": 1},
                    "2": {"name": "flags", "type": "int", "param_index": 2},
                }
            },
            "mlockall": {
                "args": 1,
                "arguments": {
                    "0": {"name": "flags", "type": "int", "param_index": 0},
                }
            },
            "memfd_create": {
                "args": 2,
                "arguments": {
                    "0": {"name": "uname", "type": "const char *", "param_index": 0},
                    "1": {"name": "flags", "type": "unsigned int", "param_index": 1},
                }
            },
            "userfaultfd": {
                "args": 1,
                "arguments": {
                    "0": {"name": "flags", "type": "int", "param_index": 0},
                }
            },
            "clone": {
                "args": 5,
                "arguments": {
                    "0": {"name": "flags", "type": "unsigned long", "param_index": 0},
                    "1": {"name": "newsp", "type": "unsigned long", "param_index": 1},
                    "2": {"name": "parent_tidptr", "type": "int *", "param_index": 2},
                    "3": {"name": "child_tidptr", "type": "int *", "param_index": 3},
                    "4": {"name": "tls", "type": "unsigned long", "param_index": 4},
                }
            },
            "clone3": {
                "args": 2,
                "arguments": {
                    "0": {
                        "name": "uargs",
                        "type": "struct clone_args *",
                        "param_index": 0,
                        "is_struct": True,
                        "struct_name": "clone_args"
                    },
                    "1": {"name": "size", "type": "size_t", "param_index": 1}
                }
            },
            "execveat": {
                "args": 5,
                "arguments": {
                    "0": {"name": "dfd", "type": "int", "param_index": 0},
                    "1": {"name": "filename", "type": "const char *", "param_index": 1},
                    "2": {"name": "argv", "type": "const char *const *", "param_index": 2},
                    "3": {"name": "envp", "type": "const char *const *", "param_index": 3},
                    "4": {"name": "flags", "type": "int", "param_index": 4},
                }
            },
            "fchmodat": {
                "args": 4,
                "arguments": {
                    "0": {"name": "dfd", "type": "int", "param_index": 0},
                    "1": {"name": "filename", "type": "const char *", "param_index": 1},
                    "2": {"name": "mode", "type": "mode_t", "param_index": 2},
                    "3": {"name": "flags", "type": "int", "param_index": 3},
                }
            },
            "fchownat": {
                "args": 5,
                "arguments": {
                    "0": {"name": "dfd", "type": "int", "param_index": 0},
                    "1": {"name": "filename", "type": "const char *", "param_index": 1},
                    "2": {"name": "user", "type": "uid_t", "param_index": 2},
                    "3": {"name": "group", "type": "gid_t", "param_index": 3},
                    "4": {"name": "flags", "type": "int", "param_index": 4},
                }
            },
            "linkat": {
                "args": 5,
                "arguments": {
                    "0": {"name": "olddfd", "type": "int", "param_index": 0},
                    "1": {"name": "oldname", "type": "const char *", "param_index": 1},
                    "2": {"name": "newdfd", "type": "int", "param_index": 2},
                    "3": {"name": "newname", "type": "const char *", "param_index": 3},
                    "4": {"name": "flags", "type": "int", "param_index": 4},
                }
            },
            "unlinkat": {
                "args": 3,
                "arguments": {
                    "0": {"name": "dfd", "type": "int", "param_index": 0},
                    "1": {"name": "pathname", "type": "const char *", "param_index": 1},
                    "2": {"name": "flags", "type": "int", "param_index": 2},
                }
            },
            "readlinkat": {
                "args": 4,
                "arguments": {
                    "0": {"name": "dfd", "type": "int", "param_index": 0},
                    "1": {"name": "pathname", "type": "const char *", "param_index": 1},
                    "2": {"name": "buf", "type": "char *", "param_index": 2},
                    "3": {"name": "bufsiz", "type": "int", "param_index": 3},
                }
            },
            "symlinkat": {
                "args": 3,
                "arguments": {
                    "0": {"name": "oldname", "type": "const char *", "param_index": 0},
                    "1": {"name": "newdfd", "type": "int", "param_index": 1},
                    "2": {"name": "newname", "type": "const char *", "param_index": 2},
                }
            },
            "utimensat": {
                "args": 4,
                "arguments": {
                    "0": {"name": "dfd", "type": "int", "param_index": 0},
                    "1": {"name": "filename", "type": "const char *", "param_index": 1},
                    "2": {"name": "utimes", "type": "struct timespec *", "param_index": 2},
                    "3": {"name": "flags", "type": "int", "param_index": 3},
                }
            },
            "renameat2": {
                "args": 5,
                "arguments": {
                    "0": {"name": "olddfd", "type": "int", "param_index": 0},
                    "1": {"name": "oldname", "type": "const char *", "param_index": 1},
                    "2": {"name": "newdfd", "type": "int", "param_index": 2},
                    "3": {"name": "newname", "type": "const char *", "param_index": 3},
                    "4": {"name": "flags", "type": "unsigned int", "param_index": 4},
                }
            },
            "access": {
                "args": 2,
                "arguments": {
                    "0": {"name": "filename", "type": "const char *", "param_index": 0},
                    "1": {"name": "mode", "type": "int", "param_index": 1},
                }
            },
            "faccessat": {
                "args": 3,
                "arguments": {
                    "0": {"name": "dfd", "type": "int", "param_index": 0},
                    "1": {"name": "filename", "type": "const char *", "param_index": 1},
                    "2": {"name": "mode", "type": "int", "param_index": 2},
                }
            },
            "faccessat2": {
                "args": 4,
                "arguments": {
                    "0": {"name": "dfd", "type": "int", "param_index": 0},
                    "1": {"name": "filename", "type": "const char *", "param_index": 1},
                    "2": {"name": "mode", "type": "int", "param_index": 2},
                    "3": {"name": "flags", "type": "int", "param_index": 3},
                }
            },
            "chmod": {
                "args": 2,
                "arguments": {
                    "0": {"name": "filename", "type": "const char *", "param_index": 0},
                    "1": {"name": "mode", "type": "mode_t", "param_index": 1},
                }
            },
            "fchmod": {
                "args": 2,
                "arguments": {
                    "0": {"name": "fd", "type": "int", "param_index": 0},
                    "1": {"name": "mode", "type": "mode_t", "param_index": 1},
                }
            },
            "umask": {
                "args": 1,
                "arguments": {
                    "0": {"name": "mask", "type": "mode_t", "param_index": 0},
                }
            },
            "statx": {
                "args": 5,
                "arguments": {
                    "0": {"name": "dfd", "type": "int", "param_index": 0},
                    "1": {"name": "filename", "type": "const char *", "param_index": 1},
                    "2": {"name": "flags", "type": "int", "param_index": 2},
                    "3": {"name": "mask", "type": "unsigned int", "param_index": 3},
                    "4": {"name": "buffer", "type": "struct statx *", "param_index": 4},
                }
            },
            "lseek": {
                "args": 3,
                "arguments": {
                    "0": {"name": "fd", "type": "int", "param_index": 0},
                    "1": {"name": "offset", "type": "off_t", "param_index": 1},
                    "2": {"name": "whence", "type": "int", "param_index": 2},
                }
            },
            "fcntl": {
                "args": 3,
                "arguments": {
                    "0": {"name": "fd", "type": "int", "param_index": 0},
                    "1": {"name": "cmd", "type": "int", "param_index": 1},
                    "2": {"name": "arg", "type": "unsigned long", "param_index": 2},
                }
            },
            "flock": {
                "args": 2,
                "arguments": {
                    "0": {"name": "fd", "type": "int", "param_index": 0},
                    "1": {"name": "operation", "type": "int", "param_index": 1},
                }
            },
            "fallocate": {
                "args": 4,
                "arguments": {
                    "0": {"name": "fd", "type": "int", "param_index": 0},
                    "1": {"name": "mode", "type": "int", "param_index": 1},
                    "2": {"name": "offset", "type": "loff_t", "param_index": 2},
                    "3": {"name": "len", "type": "loff_t", "param_index": 3},
                }
            },
            "pipe2": {
                "args": 2,
                "arguments": {
                    "0": {"name": "fildes", "type": "int *", "param_index": 0},
                    "1": {"name": "flags", "type": "int", "param_index": 1},
                }
            },
            "dup3": {
                "args": 3,
                "arguments": {
                    "0": {"name": "oldfd", "type": "int", "param_index": 0},
                    "1": {"name": "newfd", "type": "int", "param_index": 1},
                    "2": {"name": "flags", "type": "int", "param_index": 2},
                }
            },
            "socket": {
                "args": 3,
                "arguments": {
                    "0": {"name": "family", "type": "int", "param_index": 0},
                    "1": {"name": "type", "type": "int", "param_index": 1},
                    "2": {"name": "protocol", "type": "int", "param_index": 2},
                }
            },
            "socketpair": {
                "args": 4,
                "arguments": {
                    "0": {"name": "family", "type": "int", "param_index": 0},
                    "1": {"name": "type", "type": "int", "param_index": 1},
                    "2": {"name": "protocol", "type": "int", "param_index": 2},
                    "3": {"name": "usockvec", "type": "int *", "param_index": 3},
                }
            },
            "sendto": {
                "args": 6,
                "arguments": {
                    "0": {"name": "fd", "type": "int", "param_index": 0},
                    "1": {"name": "buff", "type": "void *", "param_index": 1},
                    "2": {"name": "len", "type": "size_t", "param_index": 2},
                    "3": {"name": "flags", "type": "unsigned int", "param_index": 3},
                    "4": {"name": "addr", "type": "struct sockaddr *", "param_index": 4},
                    "5": {"name": "addr_len", "type": "int", "param_index": 5},
                }
            },
            "sendmsg": {
                "args": 3,
                "arguments": {
                    "0": {"name": "fd", "type": "int", "param_index": 0},
                    "1": {"name": "msg", "type": "struct user_msghdr *", "param_index": 1},
                    "2": {"name": "flags", "type": "unsigned int", "param_index": 2},
                }
            },
            "sendmmsg": {
                "args": 4,
                "arguments": {
                    "0": {"name": "fd", "type": "int", "param_index": 0},
                    "1": {"name": "mmsg", "type": "struct mmsghdr *", "param_index": 1},
                    "2": {"name": "vlen", "type": "unsigned int", "param_index": 2},
                    "3": {"name": "flags", "type": "unsigned int", "param_index": 3},
                }
            },
            "recvfrom": {
                "args": 6,
                "arguments": {
                    "0": {"name": "fd", "type": "int", "param_index": 0},
                    "1": {"name": "ubuf", "type": "void *", "param_index": 1},
                    "2": {"name": "size", "type": "size_t", "param_index": 2},
                    "3": {"name": "flags", "type": "unsigned int", "param_index": 3},
                    "4": {"name": "addr", "type": "struct sockaddr *", "param_index": 4},
                    "5": {"name": "addr_len", "type": "int *", "param_index": 5},
                }
            },
            "recvmsg": {
                "args": 3,
                "arguments": {
                    "0": {"name": "fd", "type": "int", "param_index": 0},
                    "1": {"name": "msg", "type": "struct user_msghdr *", "param_index": 1},
                    "2": {"name": "flags", "type": "unsigned int", "param_index": 2},
                }
            },
            "recvmmsg": {
                "args": 5,
                "arguments": {
                    "0": {"name": "fd", "type": "int", "param_index": 0},
                    "1": {"name": "mmsg", "type": "struct mmsghdr *", "param_index": 1},
                    "2": {"name": "vlen", "type": "unsigned int", "param_index": 2},
                    "3": {"name": "flags", "type": "unsigned int", "param_index": 3},
                    "4": {"name": "tmo", "type": "struct timespec *", "param_index": 4},
                }
            },
            "shutdown": {
                "args": 2,
                "arguments": {
                    "0": {"name": "fd", "type": "int", "param_index": 0},
                    "1": {"name": "how", "type": "int", "param_index": 1},
                }
            },
            "epoll_create1": {
                "args": 1,
                "arguments": {
                    "0": {"name": "flags", "type": "int", "param_index": 0},
                }
            },
            "epoll_ctl": {
                "args": 4,
                "arguments": {
                    "0": {"name": "epfd", "type": "int", "param_index": 0},
                    "1": {"name": "op", "type": "int", "param_index": 1},
                    "2": {"name": "fd", "type": "int", "param_index": 2},
                    "3": {"name": "event", "type": "struct epoll_event *", "param_index": 3},
                }
            },
            "eventfd": {
                "args": 1,
                "arguments": {
                    "0": {"name": "count", "type": "unsigned int", "param_index": 0},
                }
            },
            "eventfd2": {
                "args": 2,
                "arguments": {
                    "0": {"name": "count", "type": "unsigned int", "param_index": 0},
                    "1": {"name": "flags", "type": "int", "param_index": 1},
                }
            },
            "signalfd": {
                "args": 3,
                "arguments": {
                    "0": {"name": "ufd", "type": "int", "param_index": 0},
                    "1": {"name": "user_mask", "type": "sigset_t *", "param_index": 1},
                    "2": {"name": "sizemask", "type": "size_t", "param_index": 2},
                }
            },
            "signalfd4": {
                "args": 4,
                "arguments": {
                    "0": {"name": "ufd", "type": "int", "param_index": 0},
                    "1": {"name": "user_mask", "type": "sigset_t *", "param_index": 1},
                    "2": {"name": "sizemask", "type": "size_t", "param_index": 2},
                    "3": {"name": "flags", "type": "int", "param_index": 3},
                }
            },
            "timerfd_create": {
                "args": 2,
                "arguments": {
                    "0": {"name": "clockid", "type": "int", "param_index": 0},
                    "1": {"name": "flags", "type": "int", "param_index": 1},
                }
            },
            "timerfd_settime": {
                "args": 4,
                "arguments": {
                    "0": {"name": "ufd", "type": "int", "param_index": 0},
                    "1": {"name": "flags", "type": "int", "param_index": 1},
                    "2": {"name": "utmr", "type": "const struct itimerspec *", "param_index": 2},
                    "3": {"name": "otmr", "type": "struct itimerspec *", "param_index": 3},
                }
            },
            "inotify_init1": {
                "args": 1,
                "arguments": {
                    "0": {"name": "flags", "type": "int", "param_index": 0},
                }
            },
            "inotify_add_watch": {
                "args": 3,
                "arguments": {
                    "0": {"name": "fd", "type": "int", "param_index": 0},
                    "1": {"name": "pathname", "type": "const char *", "param_index": 1},
                    "2": {"name": "mask", "type": "uint32_t", "param_index": 2},
                }
            },
            "futex": {
                "args": 6,
                "arguments": {
                    "0": {"name": "uaddr", "type": "uint32_t *", "param_index": 0},
                    "1": {"name": "op", "type": "int", "param_index": 1},
                    "2": {"name": "val", "type": "uint32_t", "param_index": 2},
                    "3": {"name": "utime", "type": "const struct timespec *", "param_index": 3},
                    "4": {"name": "uaddr2", "type": "uint32_t *", "param_index": 4},
                    "5": {"name": "val3", "type": "uint32_t", "param_index": 5},
                }
            },
            "prctl": {
                "args": 5,
                "arguments": {
                    "0": {"name": "option", "type": "int", "param_index": 0},
                    "1": {"name": "arg2", "type": "unsigned long", "param_index": 1},
                    "2": {"name": "arg3", "type": "unsigned long", "param_index": 2},
                    "3": {"name": "arg4", "type": "unsigned long", "param_index": 3},
                    "4": {"name": "arg5", "type": "unsigned long", "param_index": 4},
                }
            },
            "arch_prctl": {
                "args": 2,
                "arguments": {
                    "0": {"name": "code", "type": "int", "param_index": 0},
                    "1": {"name": "addr", "type": "unsigned long", "param_index": 1},
                }
            },
            "ptrace": {
                "args": 4,
                "arguments": {
                    "0": {"name": "request", "type": "long", "param_index": 0},
                    "1": {"name": "pid", "type": "long", "param_index": 1},
                    "2": {"name": "addr", "type": "unsigned long", "param_index": 2},
                    "3": {"name": "data", "type": "unsigned long", "param_index": 3},
                }
            },
            "wait4": {
                "args": 4,
                "arguments": {
                    "0": {"name": "upid", "type": "pid_t", "param_index": 0},
                    "1": {"name": "stat_addr", "type": "int *", "param_index": 1},
                    "2": {"name": "options", "type": "int", "param_index": 2},
                    "3": {"name": "ru", "type": "struct rusage *", "param_index": 3},
                }
            },
            "waitid": {
                "args": 5,
                "arguments": {
                    "0": {"name": "which", "type": "int", "param_index": 0},
                    "1": {"name": "upid", "type": "pid_t", "param_index": 1},
                    "2": {"name": "infop", "type": "struct siginfo *", "param_index": 2},
                    "3": {"name": "options", "type": "int", "param_index": 3},
                    "4": {"name": "ru", "type": "struct rusage *", "param_index": 4},
                }
            },
            "kill": {
                "args": 2,
                "arguments": {
                    "0": {"name": "pid", "type": "pid_t", "param_index": 0},
                    "1": {"name": "sig", "type": "int", "param_index": 1},
                }
            },
            "tkill": {
                "args": 2,
                "arguments": {
                    "0": {"name": "tid", "type": "pid_t", "param_index": 0},
                    "1": {"name": "sig", "type": "int", "param_index": 1},
                }
            },
            "tgkill": {
                "args": 3,
                "arguments": {
                    "0": {"name": "tgid", "type": "pid_t", "param_index": 0},
                    "1": {"name": "tid", "type": "pid_t", "param_index": 1},
                    "2": {"name": "sig", "type": "int", "param_index": 2},
                }
            },
            "rt_sigprocmask": {
                "args": 4,
                "arguments": {
                    "0": {"name": "how", "type": "int", "param_index": 0},
                    "1": {"name": "nset", "type": "sigset_t *", "param_index": 1},
                    "2": {"name": "oset", "type": "sigset_t *", "param_index": 2},
                    "3": {"name": "sigsetsize", "type": "size_t", "param_index": 3},
                }
            },
            "mount": {
                "args": 5,
                "arguments": {
                    "0": {"name": "dev_name", "type": "char *", "param_index": 0},
                    "1": {"name": "dir_name", "type": "char *", "param_index": 1},
                    "2": {"name": "type", "type": "char *", "param_index": 2},
                    "3": {"name": "flags", "type": "unsigned long", "param_index": 3},
                    "4": {"name": "data", "type": "void *", "param_index": 4},
                }
            },
            "umount2": {
                "args": 2,
                "arguments": {
                    "0": {"name": "name", "type": "char *", "param_index": 0},
                    "1": {"name": "flags", "type": "int", "param_index": 1},
                }
            },
            "reboot": {
                "args": 4,
                "arguments": {
                    "0": {"name": "magic1", "type": "int", "param_index": 0},
                    "1": {"name": "magic2", "type": "int", "param_index": 1},
                    "2": {"name": "cmd", "type": "unsigned int", "param_index": 2},
                    "3": {"name": "arg", "type": "void *", "param_index": 3},
                }
            },
            "bpf": {
                "args": 3,
                "arguments": {
                    "0": {"name": "cmd", "type": "int", "param_index": 0},
                    "1": {"name": "uattr", "type": "union bpf_attr *", "param_index": 1},
                    "2": {"name": "size", "type": "unsigned int", "param_index": 2},
                }
            },
            "sync_file_range": {
                "args": 4,
                "arguments": {
                    "0": {"name": "fd", "type": "int", "param_index": 0},
                    "1": {"name": "offset", "type": "loff_t", "param_index": 1},
                    "2": {"name": "nbytes", "type": "loff_t", "param_index": 2},
                    "3": {"name": "flags", "type": "unsigned int", "param_index": 3},
                }
            },
            "splice": {
                "args": 6,
                "arguments": {
                    "0": {"name": "fd_in", "type": "int", "param_index": 0},
                    "1": {"name": "off_in", "type": "loff_t *", "param_index": 1},
                    "2": {"name": "fd_out", "type": "int", "param_index": 2},
                    "3": {"name": "off_out", "type": "loff_t *", "param_index": 3},
                    "4": {"name": "len", "type": "size_t", "param_index": 4},
                    "5": {"name": "flags", "type": "unsigned int", "param_index": 5},
                }
            },
            "tee": {
                "args": 4,
                "arguments": {
                    "0": {"name": "fdin", "type": "int", "param_index": 0},
                    "1": {"name": "fdout", "type": "int", "param_index": 1},
                    "2": {"name": "len", "type": "size_t", "param_index": 2},
                    "3": {"name": "flags", "type": "unsigned int", "param_index": 3},
                }
            },
            "vmsplice": {
                "args": 4,
                "arguments": {
                    "0": {"name": "fd", "type": "int", "param_index": 0},
                    "1": {"name": "iov", "type": "const struct iovec *", "param_index": 1},
                    "2": {"name": "nr_segs", "type": "unsigned long", "param_index": 2},
                    "3": {"name": "flags", "type": "unsigned int", "param_index": 3},
                }
            },
            "getrandom": {
                "args": 3,
                "arguments": {
                    "0": {"name": "buf", "type": "char *", "param_index": 0},
                    "1": {"name": "count", "type": "size_t", "param_index": 1},
                    "2": {"name": "flags", "type": "unsigned int", "param_index": 2},
                }
            },
            "pidfd_open": {
                "args": 2,
                "arguments": {
                    "0": {"name": "pid", "type": "pid_t", "param_index": 0},
                    "1": {"name": "flags", "type": "unsigned int", "param_index": 1},
                }
            },
            "pidfd_send_signal": {
                "args": 4,
                "arguments": {
                    "0": {"name": "pidfd", "type": "int", "param_index": 0},
                    "1": {"name": "sig", "type": "int", "param_index": 1},
                    "2": {"name": "info", "type": "siginfo_t *", "param_index": 2},
                    "3": {"name": "flags", "type": "unsigned int", "param_index": 3},
                }
            },
            "sched_setscheduler": {
                "args": 3,
                "arguments": {
                    "0": {"name": "pid", "type": "pid_t", "param_index": 0},
                    "1": {"name": "policy", "type": "int", "param_index": 1},
                    "2": {"name": "param", "type": "struct sched_param *", "param_index": 2},
                }
            },
            "kexec_load": {
                "args": 4,
                "arguments": {
                    "0": {"name": "entry", "type": "unsigned long", "param_index": 0},
                    "1": {"name": "nr_segments", "type": "unsigned long", "param_index": 1},
                    "2": {"name": "segments", "type": "struct kexec_segment *", "param_index": 2},
                    "3": {"name": "flags", "type": "unsigned long", "param_index": 3},
                }
            },
            "kexec_file_load": {
                "args": 5,
                "arguments": {
                    "0": {"name": "kernel_fd", "type": "int", "param_index": 0},
                    "1": {"name": "initrd_fd", "type": "int", "param_index": 1},
                    "2": {"name": "cmdline_len", "type": "unsigned long", "param_index": 2},
                    "3": {"name": "cmdline_ptr", "type": "const char *", "param_index": 3},
                    "4": {"name": "flags", "type": "unsigned long", "param_index": 4},
                }
            },
            "io_uring_enter": {
                "args": 6,
                "arguments": {
                    "0": {"name": "fd", "type": "unsigned int", "param_index": 0},
                    "1": {"name": "to_submit", "type": "uint32_t", "param_index": 1},
                    "2": {"name": "min_complete", "type": "uint32_t", "param_index": 2},
                    "3": {"name": "flags", "type": "uint32_t", "param_index": 3},
                    "4": {"name": "arg", "type": "const void *", "param_index": 4},
                    "5": {"name": "argsz", "type": "size_t", "param_index": 5},
                }
            },
        }

        # 1. Process standard argument flags and signals
        for sc_name, sc_data in database.items():
            if sc_name in self.prefix_routing and "arguments" in sc_data:
                for arg_name, routing_spec in self.prefix_routing[sc_name].items():
                    if arg_name == "struct_fields":
                        continue
                    for arg_idx, arg_meta in sc_data["arguments"].items():
                        if arg_meta["name"] == arg_name:
                            if isinstance(routing_spec, list):
                                matched = {}
                                for k, v in self.constants.items():
                                    if any(k == p or k.startswith(p) for p in routing_spec):
                                        matched[k] = v
                                clean_matched = self._filter_flags(matched, target_arg_name=arg_meta["name"])
                                if clean_matched:
                                    arg_meta["flags"] = clean_matched
                            elif isinstance(routing_spec, dict):
                                if "flags" in routing_spec:
                                    prefixes = routing_spec["flags"]
                                    matched = {}
                                    for k, v in self.constants.items():
                                        if any(k == p or k.startswith(p) for p in prefixes):
                                            matched[k] = v
                                    clean_matched = self._filter_flags(matched, target_arg_name=arg_meta["name"])
                                    if clean_matched:
                                        arg_meta["flags"] = clean_matched
                                if "signals" in routing_spec:
                                    prefixes = routing_spec["signals"]
                                    matched = {}
                                    for k, v in self.constants.items():
                                        if any(k == p or k.startswith(p) for p in prefixes):
                                            matched[k] = v
                                    clean_matched = self._filter_flags(matched, target_arg_name=arg_meta["name"])
                                    if clean_matched:
                                        arg_meta["signals"] = clean_matched

        # 2. Process nested struct fields (e.g., clone3 -> clone_args, openat2 -> open_how)
        for sc_name, sc_data in database.items():
            if sc_name in self.prefix_routing and "struct_fields" in self.prefix_routing[sc_name]:
                routing_fields = self.prefix_routing[sc_name]["struct_fields"]
                for arg_idx, arg_meta in sc_data["arguments"].items():
                    if arg_meta.get("is_struct"):
                        s_name = arg_meta["struct_name"]
                        struct_fields_dict = {}

                        # Fallback definitions if kernel headers omit struct body in user space
                        discovered_fields = self.structs.get(s_name)
                        if not discovered_fields:
                            if s_name == "clone_args":
                                discovered_fields = [
                                    {"name": "flags", "type": "__aligned_u64"},
                                    {"name": "pidfd", "type": "__aligned_u64"},
                                    {"name": "child_tid", "type": "__aligned_u64"},
                                    {"name": "parent_tid", "type": "__aligned_u64"},
                                    {"name": "exit_signal", "type": "__aligned_u64"},
                                    {"name": "stack", "type": "__aligned_u64"},
                                    {"name": "stack_size", "type": "__aligned_u64"},
                                    {"name": "tls", "type": "__aligned_u64"},
                                    {"name": "set_tid", "type": "__aligned_u64"},
                                    {"name": "set_tid_size", "type": "__aligned_u64"},
                                    {"name": "cgroup", "type": "__aligned_u64"},
                                ]
                            elif s_name == "open_how":
                                discovered_fields = [
                                    {"name": "flags", "type": "__u64"},
                                    {"name": "mode", "type": "__u64"},
                                    {"name": "resolve", "type": "__u64"},
                                ]

                        if discovered_fields:
                            for idx, field in enumerate(discovered_fields):
                                field_entry = {
                                    "name": field["name"],
                                    "type": field["type"],
                                    "field_index": idx
                                }
                                if field["name"] in routing_fields:
                                    f_spec = routing_fields[field["name"]]
                                    if isinstance(f_spec, list):
                                        matched = {}
                                        for k, v in self.constants.items():
                                            if any(k == p or k.startswith(p) for p in f_spec):
                                                matched[k] = v
                                        clean_matched = self._filter_flags(matched, target_arg_name=field["name"])
                                        if clean_matched:
                                            field_entry["flags"] = clean_matched
                                    elif isinstance(f_spec, dict):
                                        if "flags" in f_spec:
                                            matched = {}
                                            for k, v in self.constants.items():
                                                if any(k == p or k.startswith(p) for p in f_spec["flags"]):
                                                    matched[k] = v
                                            clean_matched = self._filter_flags(matched, target_arg_name=field["name"])
                                            if clean_matched:
                                                field_entry["flags"] = clean_matched
                                        if "signals" in f_spec:
                                            matched = {}
                                            for k, v in self.constants.items():
                                                if any(k == p or k.startswith(p) for p in f_spec["signals"]):
                                                    matched[k] = v
                                            clean_matched = self._filter_flags(matched, target_arg_name=field["name"])
                                            if clean_matched:
                                                field_entry["signals"] = clean_matched

                                struct_fields_dict[str(idx)] = field_entry

                            arg_meta["struct_fields"] = struct_fields_dict

        return database

    def save_to_json(self, output_path="data/syscalls.json"):
        """Generates and writes the database to the specified JSON file."""
        db = self.build_database()
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=4)
        print(f"[+] Successfully generated robust syscall database at {output_path} with {len(db)} syscall mappings!")
        return db


def main():
    parser = argparse.ArgumentParser(
        description="SysReader Syscall Database Builder using GCC preprocessor extraction"
    )
    parser.add_argument(
        "-o", "--output",
        default="data/syscalls.json",
        help="Path to output JSON file (default: data/syscalls.json)"
    )
    parser.add_argument(
        "--header",
        action="append",
        dest="extra_headers",
        help="Additional C header file(s) to scan with gcc -dM -E"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all supported syscalls"
    )
    parser.add_argument(
        "--show",
        metavar="SYSCALL",
        help="Display the JSON schema and parsed flags for a specific syscall"
    )

    args = parser.parse_args()

    builder = SyscallDatabaseBuilder(extra_headers=args.extra_headers)

    if args.list:
        db = builder.build_database()
        print(f"\nSupported system calls ({len(db)} total):")
        for sc in sorted(db.keys()):
            arg_count = db[sc]["args"]
            flagged = [
                meta["name"]
                for meta in db[sc].get("arguments", {}).values()
                if "flags" in meta or "struct_fields" in meta
            ]
            flag_info = f" [flags on: {', '.join(flagged)}]" if flagged else ""
            print(f"  - {sc:<18} ({arg_count} args){flag_info}")
        return

    if args.show:
        db = builder.build_database()
        if args.show in db:
            print(json.dumps(db[args.show], indent=2))
        else:
            print(f"[-] Syscall '{args.show}' not found in database.")
            sys.exit(1)
        return

    builder.save_to_json(args.output)


if __name__ == "__main__":
    main()
