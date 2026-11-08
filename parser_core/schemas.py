"""
Base syscall schemas and argument metadata definitions for SysReader parser.
Contains standard argument positions, names, types, and struct associations for 83+ Linux syscalls.
"""
import copy

SYSCALL_SCHEMAS = {

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

FALLBACK_STRUCTS = {
    "clone_args": [
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
    ],
    "open_how": [
        {"name": "flags", "type": "__u64"},
        {"name": "mode", "type": "__u64"},
        {"name": "resolve", "type": "__u64"},
    ],
}

def get_base_syscall_schemas():
    """Returns a fresh copy of the base syscall schemas."""
    return copy.deepcopy(SYSCALL_SCHEMAS)
