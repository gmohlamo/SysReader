#include "../include/readsys.h"

typedef struct {
  const char *name;
  const char *desc;
} FlagDescription;

static const FlagDescription FLAG_DESCRIPTIONS[] = {
    // Clone flags
    {"CLONE_VM", "Share virtual memory"},
    {"CLONE_FS", "Share filesystem info"},
    {"CLONE_FILES", "Share open file descriptors"},
    {"CLONE_SIGHAND", "Share signal handlers"},
    {"CLONE_PIDFD", "Return child pidfd in parent"},
    {"CLONE_PTRACE", "Continue tracing child"},
    {"CLONE_VFORK", "Wake parent on exec/exit"},
    {"CLONE_PARENT", "Same parent as caller"},
    {"CLONE_THREAD", "Place in same thread group"},
    {"CLONE_NEWNS", "New mount namespace"},
    {"CLONE_SYSVSEM", "Share System V SEM_UNDO"},
    {"CLONE_SETTLS", "Set TLS descriptor"},
    {"CLONE_PARENT_SETTID", "Store TID in parent"},
    {"CLONE_CHILD_CLEARTID", "Clear TID in child on exit"},
    {"CLONE_DETACHED", "Detached (unused/ignored)"},
    {"CLONE_UNTRACED", "Prevent ptrace tracing"},
    {"CLONE_CHILD_SETTID", "Store TID in child"},
    {"CLONE_NEWCGROUP", "New cgroup namespace"},
    {"CLONE_NEWUTS", "New UTS namespace (hostname/domain)"},
    {"CLONE_NEWIPC", "New IPC namespace"},
    {"CLONE_NEWUSER", "New user namespace"},
    {"CLONE_NEWPID", "New PID namespace"},
    {"CLONE_NEWNET", "New network namespace"},
    {"CLONE_IO", "Share I/O context"},
    {"CLONE_CLEAR_SIGHAND", "Clear signal handlers to SIG_DFL"},
    {"CLONE_INTO_CGROUP", "Spawn directly into cgroup"},
    {"CLONE_NEWTIME", "New time namespace"},

    // Signals
    {"SIGHUP", "Terminal hangup"},
    {"SIGINT", "Terminal interrupt (Ctrl+C)"},
    {"SIGQUIT", "Terminal quit (Ctrl+\\)"},
    {"SIGILL", "Illegal instruction"},
    {"SIGTRAP", "Trace/breakpoint trap"},
    {"SIGABRT", "Process abort"},
    {"SIGIOT", "IOT trap / abort"},
    {"SIGBUS", "Memory bus error"},
    {"SIGFPE", "Floating point exception"},
    {"SIGKILL", "Kill signal (uncatchable)"},
    {"SIGUSR1", "User-defined signal 1"},
    {"SIGSEGV", "Segmentation fault"},
    {"SIGUSR2", "User-defined signal 2"},
    {"SIGPIPE", "Broken pipe"},
    {"SIGALRM", "Alarm timer expired"},
    {"SIGTERM", "Termination signal"},
    {"SIGSTKFLT", "Stack fault on coprocessor"},
    {"SIGCHLD", "Child process status changed"},
    {"SIGCLD", "Child process status changed (SysV)"},
    {"SIGCONT", "Continue executing if stopped"},
    {"SIGSTOP", "Stop executing (uncatchable)"},
    {"SIGTSTP", "Terminal stop signal (Ctrl+Z)"},
    {"SIGTTIN", "Background read from tty"},
    {"SIGTTOU", "Background write to tty"},
    {"SIGURG", "Urgent socket condition"},
    {"SIGXCPU", "CPU time limit exceeded"},
    {"SIGXFSZ", "File size limit exceeded"},
    {"SIGVTALRM", "Virtual timer expired"},
    {"SIGPROF", "Profiling timer expired"},
    {"SIGWINCH", "Window size changed"},
    {"SIGIO", "I/O now possible"},
    {"SIGPOLL", "Pollable event occurred"},
    {"SIGPWR", "Power supply failure"},
    {"SIGSYS", "Bad system call"},

    // Open / file flags
    {"O_RDONLY", "Open read-only"},
    {"O_WRONLY", "Open write-only"},
    {"O_RDWR", "Open read/write"},
    {"O_CREAT", "Create file if nonexistent"},
    {"O_EXCL", "Exclusive creation error if exists"},
    {"O_NOCTTY", "Do not assign controlling tty"},
    {"O_TRUNC", "Truncate file length to 0"},
    {"O_APPEND", "Append writes to end of file"},
    {"O_NONBLOCK", "Non-blocking I/O mode"},
    {"O_NDELAY", "Non-blocking I/O mode"},
    {"O_DSYNC", "Synchronize data only"},
    {"O_SYNC", "Synchronous writes"},
    {"O_FSYNC", "Synchronous writes"},
    {"O_ASYNC", "Signal-driven I/O"},
    {"O_DIRECT", "Direct I/O bypassing page cache"},
    {"O_LARGEFILE", "Allow files > 2GB"},
    {"O_DIRECTORY", "Must be a directory"},
    {"O_NOFOLLOW", "Do not follow symlinks"},
    {"O_NOATIME", "Do not update access time"},
    {"O_CLOEXEC", "Close file descriptor on exec"},
    {"O_PATH", "Open for path resolution only"},
    {"O_TMPFILE", "Create unnamed temporary file"},
    {"O_EMPTYPATH", "Allow empty path"},

    // Memory protection & mapping
    {"PROT_NONE", "Page cannot be accessed"},
    {"PROT_READ", "Page can be read"},
    {"PROT_WRITE", "Page can be written"},
    {"PROT_EXEC", "Page can be executed"},
    {"PROT_SEM", "Page may be used for atomic ops"},
    {"PROT_GROWSDOWN", "Extend mapping downward"},
    {"PROT_GROWSUP", "Extend mapping upward"},

    {"MAP_SHARED", "Share changes"},
    {"MAP_PRIVATE", "Private copy-on-write mapping"},
    {"MAP_SHARED_VALIDATE", "Share changes & validate flags"},
    {"MAP_FIXED", "Interpret address exactly"},
    {"MAP_ANONYMOUS", "Anonymous memory (not backed by file)"},
    {"MAP_ANON", "Anonymous memory (not backed by file)"},
    {"MAP_GROWSDOWN", "Stack-like downward growth"},
    {"MAP_DENYWRITE", "ETXTBSY (ignored)"},
    {"MAP_EXECUTABLE", "Mark executable (ignored)"},
    {"MAP_LOCKED", "Lock pages into memory"},
    {"MAP_NORESERVE", "Do not reserve swap space"},
    {"MAP_POPULATE", "Pre-populate page tables"},
    {"MAP_NONBLOCK", "Do not block on I/O"},
    {"MAP_STACK", "Allocate suitable stack"},
    {"MAP_HUGETLB", "Use huge pages"},
    {"MAP_SYNC", "Perform synchronous page faults"},
    {"MAP_FIXED_NOREPLACE", "Fail if address is already mapped"},
    {"MAP_UNINITIALIZED", "Do not clear anonymous pages"},

    // AT_* flags
    {"AT_FDCWD", "Use current working directory"},
    {"AT_SYMLINK_NOFOLLOW", "Do not follow symlinks"},
    {"AT_REMOVEDIR", "Remove directory instead of file"},
    {"AT_SYMLINK_FOLLOW", "Follow symlink"},
    {"AT_NO_AUTOMOUNT", "Suppress terminal automount"},
    {"AT_EMPTY_PATH", "Allow empty path string"},
    {"AT_STATX_SYNC_AS_STAT", "Stat-like sync behavior"},
    {"AT_STATX_FORCE_SYNC", "Force sync attributes with server"},
    {"AT_STATX_DONT_SYNC", "Do not sync attributes with server"},

    // SEEK_* flags
    {"SEEK_SET", "Seek from beginning of file"},
    {"SEEK_CUR", "Seek from current position"},
    {"SEEK_END", "Seek from end of file"},
    {"SEEK_DATA", "Seek to next data"},
    {"SEEK_HOLE", "Seek to next hole"},

    // FCNTL commands & flags
    {"F_DUPFD", "Duplicate file descriptor"},
    {"F_GETFD", "Get file descriptor flags"},
    {"F_SETFD", "Set file descriptor flags"},
    {"F_GETFL", "Get file status flags"},
    {"F_SETFL", "Set file status flags"},
    {"F_GETLK", "Get record locking info"},
    {"F_SETLK", "Set record locking info"},
    {"F_SETLKW", "Set record locking info (blocking)"},
    {"F_SETOWN", "Set process/pgrp receiving SIGIO"},
    {"F_GETOWN", "Get process/pgrp receiving SIGIO"},
    {"F_SETSIG", "Set signal sent on I/O availability"},
    {"F_GETSIG", "Get signal sent on I/O availability"},
    {"F_DUPFD_CLOEXEC", "Duplicate fd with close-on-exec"},
    {"FD_CLOEXEC", "Close-on-exec flag"},

    // POLL / EPOLL
    {"POLLIN", "Data available to read"},
    {"POLLPRI", "Urgent data available to read"},
    {"POLLOUT", "Writing now will not block"},
    {"POLLERR", "Error condition occurred"},
    {"POLLHUP", "Hangup occurred"},
    {"POLLNVAL", "Invalid polling request"},
    {"EPOLLIN", "Associated fd available for read"},
    {"EPOLLOUT", "Associated fd available for write"},
    {"EPOLLRDHUP", "Stream socket peer closed connection"},
    {"EPOLLPRI", "Exceptional condition occurred"},
    {"EPOLLERR", "Error condition occurred"},
    {"EPOLLHUP", "Hangup occurred"},
    {"EPOLLET", "Set edge-triggered behavior"},
    {"EPOLLONESHOT", "Disable event after notification"},
    {"EPOLLWAKEUP", "Ensure system stays awake"},
    {"EPOLLEXCLUSIVE", "Wake single waiter only"},

    // File modes
    {"S_IRWXU", "User read, write, execute"},
    {"S_IRUSR", "User read permission"},
    {"S_IWUSR", "User write permission"},
    {"S_IXUSR", "User execute permission"},
    {"S_IRWXG", "Group read, write, execute"},
    {"S_IRGRP", "Group read permission"},
    {"S_IWGRP", "Group write permission"},
    {"S_IXGRP", "Group execute permission"},
    {"S_IRWXO", "Others read, write, execute"},
    {"S_IROTH", "Others read permission"},
    {"S_IWOTH", "Others write permission"},
    {"S_IXOTH", "Others execute permission"},
    {"S_ISUID", "Set-UID on execution"},
    {"S_ISGID", "Set-GID on execution"},
    {"S_ISVTX", "Sticky bit"},

    // Mount / Umount
    {"MS_RDONLY", "Mount read-only"},
    {"MS_NOSUID", "Ignore suid and sgid bits"},
    {"MS_NODEV", "Disallow device access"},
    {"MS_NOEXEC", "Disallow program execution"},
    {"MS_SYNCHRONOUS", "Writes are synced immediately"},
    {"MS_REMOUNT", "Alter existing mount flags"},
    {"MS_MANDLOCK", "Allow mandatory locks"},
    {"MS_DIRSYNC", "Directory updates are synchronous"},
    {"MS_NOATIME", "Do not update access times"},
    {"MS_NODIRATIME", "Do not update directory access times"},
    {"MS_BIND", "Create a bind mount"},
    {"MS_MOVE", "Move mount subtree"},
    {"MS_REC", "Recursive mount operation"},
    {"MS_SILENT", "Suppress kernel log messages"},
    {"MS_POSIXACL", "Support POSIX ACLs"},
    {"MS_UNBINDABLE", "Change to unbindable mount"},
    {"MS_PRIVATE", "Change to private mount"},
    {"MS_SLAVE", "Change to slave mount"},
    {"MS_SHARED", "Change to shared mount"},
    {"MS_RELATIME", "Update atime relative to mtime/ctime"},
    {"MS_STRICTATIME", "Always update atime"},
    {"MS_LAZYTIME", "Update atime/mtime in memory only"},
    {"MNT_FORCE", "Force unmount"},
    {"MNT_DETACH", "Lazy unmount (detach immediately)"},
    {"MNT_EXPIRE", "Mark mount as expired"},
    {"UMOUNT_NOFOLLOW", "Do not follow symlinks"},

    // Others
    {"PIDFD_NONBLOCK", "Non-blocking pidfd"},
    {"GRND_NONBLOCK", "Non-blocking random read"},
    {"GRND_RANDOM", "Use /dev/random source"},
    {"GRND_INSECURE", "Return unseeded data"},
    {"MFD_CLOEXEC", "Close on exec"},
    {"MFD_ALLOW_SEALING", "Allow sealing operations"},
    {"MFD_HUGETLB", "Use huge pages"},
    {"RENAME_NOREPLACE", "Do not overwrite destination"},
    {"RENAME_EXCHANGE", "Exchange source and destination atomically"},
    {"RENAME_WHITEOUT", "Create whiteout object"},
    {NULL, NULL}};

const char *get_flag_description(const char *name) {
  if (!name) {
    return NULL;
  }
  for (size_t i = 0; FLAG_DESCRIPTIONS[i].name != NULL; i++) {
    if (strcmp(FLAG_DESCRIPTIONS[i].name, name) == 0) {
      return FLAG_DESCRIPTIONS[i].desc;
    }
  }
  return NULL;
}

static const RJson *get_arg_node(const RJson *root, const char *syscall_name,
                                 int param_index) {
  if (!root || !syscall_name) {
    return NULL;
  }

  const RJson *syscall_node = r_json_get(root, syscall_name);
  if (!syscall_node) {
    return NULL;
  }

  const RJson *args_node = r_json_get(syscall_node, "arguments");
  if (!args_node) {
    return NULL;
  }

  char param_idx_str[16];
  snprintf(param_idx_str, sizeof(param_idx_str), "%d", param_index);

  return r_json_get(args_node, param_idx_str);
}

static flag_entry *parse_flag_entries_from_json(const RJson *obj_node) {
  if (!obj_node || obj_node->type != R_JSON_OBJECT) {
    return NULL;
  }

  flag_entry *head_flag = NULL;
  const RJson *item;
  for (item = obj_node->children.first; item; item = item->next) {
    if (!item->key) {
      continue;
    }
    flag_entry *new_flag = calloc(1, sizeof(flag_entry));
    if (!new_flag) {
      break;
    }
    new_flag->name = strdup(item->key);
    if (item->type == R_JSON_INTEGER) {
      new_flag->value = (uint64_t)item->num.u_value;
    } else if (item->type == R_JSON_OBJECT) {
      const RJson *val_node = r_json_get(item, "value");
      if (val_node && val_node->type == R_JSON_INTEGER) {
        new_flag->value = (uint64_t)val_node->num.u_value;
      }
      const RJson *desc_node = r_json_get(item, "desc");
      if (desc_node && desc_node->type == R_JSON_STRING) {
        new_flag->desc = strdup(desc_node->str_value);
      }
    }

    if (!new_flag->desc) {
      const char *builtin_desc = get_flag_description(new_flag->name);
      if (builtin_desc) {
        new_flag->desc = strdup(builtin_desc);
      }
    }

    new_flag->next = head_flag;
    head_flag = new_flag;
  }

  return head_flag;
}

flag_entry *get_flags_for_arg(const RJson *root, const char *syscall_name,
                              int param_index) {
  const RJson *arg_node = get_arg_node(root, syscall_name, param_index);
  if (!arg_node) {
    return NULL;
  }

  const RJson *flags_node = r_json_get(arg_node, "flags");
  return parse_flag_entries_from_json(flags_node);
}

flag_entry *get_signals_for_arg(const RJson *root, const char *syscall_name,
                                int param_index) {
  const RJson *arg_node = get_arg_node(root, syscall_name, param_index);
  if (!arg_node) {
    return NULL;
  }

  const RJson *signals_node = r_json_get(arg_node, "signals");
  return parse_flag_entries_from_json(signals_node);
}

const char *get_arg_name_from_db(const RJson *root, const char *syscall_name,
                                 int param_index) {
  const RJson *arg_node = get_arg_node(root, syscall_name, param_index);
  if (!arg_node) {
    return NULL;
  }

  const RJson *name_node = r_json_get(arg_node, "name");
  if (!name_node || name_node->type != R_JSON_STRING) {
    return NULL;
  }

  return name_node->str_value;
}

const char *get_arg_type_from_db(const RJson *root, const char *syscall_name,
                                 int param_index) {
  const RJson *arg_node = get_arg_node(root, syscall_name, param_index);
  if (!arg_node) {
    return NULL;
  }

  const RJson *type_node = r_json_get(arg_node, "type");
  if (!type_node || type_node->type != R_JSON_STRING) {
    return NULL;
  }

  return type_node->str_value;
}

static void print_single_flag(RStrBuf *sb, const flag_entry *flag) {
  if (!sb || !flag || !flag->name) {
    return;
  }
  const char *desc = flag->desc ? flag->desc : get_flag_description(flag->name);
  if (desc && *desc) {
    r_strbuf_appendf(sb, "%s /* %s */", flag->name, desc);
  } else {
    r_strbuf_append(sb, flag->name);
  }
}

void print_flag_details(RStrBuf *sb, uint64_t value, flag_entry *flags,
                        flag_entry *signals) {
  if (!sb) {
    return;
  }
  if (!flags && !signals) {
    r_strbuf_appendf(sb, "0x%" PRIx64, value);
    return;
  }

  r_strbuf_appendf(sb, "0x%" PRIx64 " (", value);
  int first = 1;

  // 1. Handle exact 0 matches (e.g. O_RDONLY = 0, PROT_NONE = 0)
  if (value == 0) {
    flag_entry *curr = flags ? flags : signals;
    while (curr != NULL) {
      if (curr->value == 0) {
        print_single_flag(sb, curr);
        first = 0;
        break;
      }
      curr = curr->next;
    }
    if (first) {
      r_strbuf_append(sb, "0");
      first = 0;
    }
    r_strbuf_append(sb, ")");
    return;
  }

  uint64_t val_to_check = value;

  // 2. Both flags and signals present (e.g. clone(2): low 8 bits is signal)
  if (flags && signals) {
    uint64_t sig = value & 0xffULL;
    val_to_check = value & ~0xffULL;

    // Check bitwise clone flags first
    flag_entry *curr = flags;
    uint64_t matched_bits = 0;
    while (curr != NULL) {
      if (curr->value != 0 && (val_to_check & curr->value) == curr->value) {
        if ((matched_bits & curr->value) != curr->value) {
          if (!first) {
            r_strbuf_append(sb, " | ");
          }
          print_single_flag(sb, curr);
          first = 0;
          matched_bits |= curr->value;
        }
      }
      curr = curr->next;
    }

    // Check exact signal on low 8 bits
    if (sig != 0) {
      flag_entry *scurr = signals;
      bool sig_found = false;
      while (scurr != NULL) {
        if (scurr->value == sig) {
          if (!first) {
            r_strbuf_append(sb, " | ");
          }
          print_single_flag(sb, scurr);
          first = 0;
          sig_found = true;
          break;
        }
        scurr = scurr->next;
      }
      if (!sig_found) {
        if (!first) {
          r_strbuf_append(sb, " | ");
        }
        r_strbuf_appendf(sb, "SIG(0x%" PRIx64 ")", sig);
        first = 0;
      }
    }
  } else if (signals && !flags) {
    // Pure signal argument (e.g. kill, tkill, tgkill) -> exact match
    flag_entry *curr = signals;
    while (curr != NULL) {
      if (curr->value == value) {
        print_single_flag(sb, curr);
        first = 0;
        break;
      }
      curr = curr->next;
    }
  } else if (flags) {
    // Standard bitwise flags
    flag_entry *curr = flags;
    uint64_t matched_bits = 0;
    while (curr != NULL) {
      if (curr->value != 0 && (val_to_check & curr->value) == curr->value) {
        if ((matched_bits & curr->value) != curr->value) {
          if (!first) {
            r_strbuf_append(sb, " | ");
          }
          print_single_flag(sb, curr);
          first = 0;
          matched_bits |= curr->value;
        }
      }
      curr = curr->next;
    }
  }

  if (first && value != 0) {
    r_strbuf_append(sb, "UNKNOWN");
  }
  r_strbuf_append(sb, ")");
}
