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

// x86-64 syscall convention: first 6 args in registers
// Index 0 = arg 1, Index 1 = arg 2, etc.
extern const char *syscall_regs[];

#define SYSCALL_REG_COUNT 6

extern const char *help_msg_p[];

typedef struct flag_entry {
  char *name;
  uint64_t value;
  struct flag_entry *next;
} flag_entry;

typedef struct argument {
  unsigned int pos;
  char type;
  char *name;
  uint64_t value;
  flag_entry *flags; // Pointer to parsed flags for this argument
  struct argument *next;
} argument;

typedef struct {
  size_t length;
  argument *args;
} args;

void iterate_argument_string(RCore *core, const RJson *db_json,
                             const char *name, size_t arg_count, char *arg_str);
char *remove_newline(const char *str);
void free_flags(flag_entry *flags);
void free_args(args *arg_head);
RJson *load_syscall_db(void);
flag_entry *get_flags_for_arg(const RJson *root, const char *syscall_name,
                              int param_index);
void print_flag_details(RCore *core, uint64_t value, flag_entry *flags);
void argument_detail(RCore *core, argument *arg);
char *read_string_from_target(RCore *core, uint64_t addr, size_t max_len);
void find_syscall(RCore *core, int callnum);
bool is_syscall(RCorePluginSession *cps, const char *input);
bool read_sys_call(RCorePluginSession *cps, const char *input);

#endif
