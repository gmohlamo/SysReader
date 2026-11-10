/* radare - Copyright 2025 - Gladwin Tshepo Mohlamonyane */

#ifndef SYSREADER_H
#define SYSREADER_H

#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define R_LOG_ORIGIN "core.readsys"

#include <r_core.h>
#include <r_lib.h>
#include <r_syscall.h>
#include <r_util.h>
#include <r_util/r_json.h>

#define MAX_STRING_PREVIEW 32
#define SYSCALL_REG_COUNT 6

typedef struct {
  const char *name;
  const char *syscall_reg;
  const char *alt_syscall_reg;
  const char *arg_regs[SYSCALL_REG_COUNT];
} SyscallConvention;

const SyscallConvention *get_syscall_convention(RCore *core);

extern const char *help_msg_p[];

typedef struct flag_entry {
  char *name;
  uint64_t value;
  char *desc;
  struct flag_entry *next;
} flag_entry;

typedef struct argument {
  unsigned int pos;
  char type;
  char *name;
  uint64_t value;
  flag_entry *flags;   // Pointer to parsed bitwise flags for this argument
  flag_entry *signals; // Pointer to parsed signals (for clone or signal args)
  struct argument *next;
} argument;

typedef struct {
  size_t length;
  argument *args;
} args;

void iterate_argument_string(RCore *core, const SyscallConvention *conv, RStrBuf *sb,
                             const RJson *db_json, const char *name,
                             size_t arg_count, char *arg_str);
char *remove_newline(const char *str);
void free_flags(flag_entry *flags);
void free_args(args *arg_head);
RJson *load_syscall_db(void);
flag_entry *get_flags_for_arg(const RJson *root, const char *syscall_name,
                              int param_index);
flag_entry *get_signals_for_arg(const RJson *root, const char *syscall_name,
                                int param_index);
const char *get_arg_name_from_db(const RJson *root, const char *syscall_name,
                                 int param_index);
const char *get_arg_type_from_db(const RJson *root, const char *syscall_name,
                                 int param_index);
const char *get_flag_description(const char *name);
void print_flag_details(RStrBuf *sb, uint64_t value, flag_entry *flags,
                        flag_entry *signals);
void argument_detail(RCore *core, const SyscallConvention *conv, argument *arg);
char *read_string_from_target(RCore *core, uint64_t addr, size_t max_len);
void find_syscall(RCore *core, const SyscallConvention *conv, int callnum,
                  ut64 current_addr, bool add_comment);
bool is_syscall(RCorePluginSession *cps, bool add_comment);
bool read_sys_call(RCorePluginSession *cps, const char *input);

#endif
