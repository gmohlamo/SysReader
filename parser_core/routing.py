"""
Prefix routing definitions for SysReader parser.
Maps macro prefixes and names to specific syscall arguments and nested struct fields.
"""

PREFIX_ROUTING = {
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
        "flags": [
            "MS_RDONLY", "MS_NOSUID", "MS_NODEV", "MS_NOEXEC", "MS_SYNCHRONOUS",
            "MS_REMOUNT", "MS_MANDLOCK", "MS_DIRSYNC", "MS_NOSYMFOLLOW", "MS_NOATIME",
            "MS_NODIRATIME", "MS_BIND", "MS_MOVE", "MS_REC", "MS_SILENT", "MS_POSIXACL",
            "MS_UNBINDABLE", "MS_PRIVATE", "MS_SLAVE", "MS_SHARED", "MS_RELATIME",
            "MS_KERNMOUNT", "MS_I_VERSION", "MS_STRICTATIME", "MS_LAZYTIME", "MS_ACTIVE"
        ],
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
