#include "../include/readsys.h"

// x86-64 syscall convention: first 6 args in registers
// Index 0 = arg 1, Index 1 = arg 2, etc.
const char *syscall_regs[] = {
    "rdi", // arg 1
    "rsi", // arg 2
    "rdx", // arg 3
    "r10", // arg 4 (note: r10 for syscalls, NOT rcx)
    "r8",  // arg 5
    "r9"   // arg 6
};

const char *help_msg_p[] = {
    "psy", "",
    "If rip is on a systemcall, add function call and arguments as comment",
    NULL};

char *remove_newline(const char *str) {
  if (!str) {
    return NULL;
  }
  char *newline = strchr(str, '\n');
  if (newline) {
    return r_str_ndup(str, newline - str);
  }
  return strdup(str);
}

void free_flags(flag_entry *flags) {
  while (flags) {
    flag_entry *next = flags->next;
    free(flags->name);
    free(flags);
    flags = next;
  }
}

void free_args(args *arg_head) {
  if (!arg_head) {
    return;
  }
  argument *curr = arg_head->args;
  while (curr) {
    argument *next = curr->next;
    free(curr->name);
    free_flags(curr->flags);
    free(curr);
    curr = next;
  }
  free(arg_head);
}

RJson *load_syscall_db(void) {
  char *home_dir = r_sys_getenv(R_SYS_HOME);
  if (!home_dir) {
    return NULL;
  }
  char *filepath =
      r_str_newf("%s/.local/share/radare2/plugins/syscalls.json", home_dir);
  free(home_dir);
  if (!filepath) {
    return NULL;
  }

  char *json_data = r_file_slurp(filepath, NULL);
  free(filepath);
  if (!json_data) {
    return NULL;
  }

  RJson *root = r_json_parsedup(json_data);
  free(json_data);
  return root;
}

void argument_detail(RCore *core, argument *arg) {
  if (!core || !core->anal || !core->anal->reg || !arg) {
    return;
  }
  if (arg->pos >= 1 && arg->pos <= SYSCALL_REG_COUNT) {
    const char *reg_name = syscall_regs[arg->pos - 1];
    RRegItem *item = r_reg_get(core->anal->reg, reg_name, -1);
    if (item) {
      arg->value = r_reg_get_value(core->anal->reg, item);
    }
  }
}

/**
 * Read a null-terminated string from target process memory via RCore
 * Returns a newly allocated string (caller must free) or NULL on error
 */
char *read_string_from_target(RCore *core, uint64_t addr, size_t max_len) {
  if (addr == 0 || !core) {
    return NULL;
  }

  char *buffer = malloc(max_len + 1);
  if (!buffer) {
    return NULL;
  }

  // Use radare2's IO interface to read memory
  int bytes_read = r_io_read_at(core->io, addr, (uint8_t *)buffer, max_len);

  if (bytes_read <= 0) {
    free(buffer);
    return NULL;
  }

  // Ensure null termination
  buffer[bytes_read] = '\0';

  return buffer;
}

void find_syscall(RCore *core, int callnum) {
  if (!core) {
    return;
  }

  RSyscallItem *si;
  if (callnum > 0 && callnum < 0xFFFF)
    si = r_syscall_get(core->anal->syscall, callnum, -1);

  const char *arguments_raw = r_core_cmd_strf(core, "ask %s", si->name);
  r_cons_printf(core->cons, "%s( ", si->name);

  if (arguments_raw) {
    RJson *db_json = load_syscall_db();
    iterate_argument_string(core, db_json, si->name, (size_t)si->args,
                            si->sargs);
    if (db_json) {
      r_json_free(db_json);
    }
    free((void *)arguments_raw);
  }
  r_syscall_item_free(si);
}

bool is_syscall(RCorePluginSession *cps, const char *input) {
  if (!cps || !cps->core) {
    return false;
  }
  RCore *core = cps->core;
  if (!core->anal || !core->anal->reg) {
    r_cons_printf(core->cons, "Error: Register profile is not initialised.\n");
    return false;
  }
  if (core->dbg) {
    r_debug_reg_sync(core->dbg, R_REG_TYPE_GPR, false);
  }

  RAnalOp op = {0};
  ut8 buf[64];
  ut64 current_addr = r_reg_get_value_by_role(core->anal->reg, R_REG_ALIAS_PC);
  r_io_read_at(core->io, current_addr, buf, sizeof(buf));
  int ret = r_anal_op(core->anal, &op, current_addr, buf, sizeof(buf),
                      R_ARCH_OP_MASK_DISASM);

  if (ret > 0) {
    if (!r_str_eq(op.mnemonic, "syscall") &&
        !r_str_eq(op.mnemonic, "int 0x80") &&
        !r_str_eq(op.mnemonic, "sysenter")) {
      r_cons_printf(core->cons, "Place holder for something smarter\n");
      r_anal_op_fini(&op);
      r_cons_flush(core->cons);
      return true;
    }
  } else {
    r_cons_printf(core->cons,
                  "Failed to decode instruction at 0x%08" PFMT64x "\n",
                  current_addr);
    r_anal_op_fini(&op);
    r_cons_flush(core->cons);
    return false;
  }

  // need to change this to get the digit directly, rest of this is useless for
  // me. The problem is getting this to be somewhat architecture agnostic
  // "SN" doesn't work, we'll need to make another function
  ut64 syscall_number = r_reg_getv(core->anal->reg, "rax");
  if (syscall_number)
    find_syscall(core, (int)syscall_number);
  else
    r_cons_printf(core->cons, "Could not find syscall numnber register\n");

  r_anal_op_fini(&op);
  r_cons_flush(core->cons);
  return true;
}

bool read_sys_call(RCorePluginSession *cps, const char *input) {
  if (!cps || !cps->core) {
    return false;
  }
  r_core_autocomplete_add(cps->core->autocomplete, "ps psy",
                          R_CORE_AUTOCMPLT_DFLT, true);
  RCore *core = cps->core;
  if (r_str_eq(input, "psy")) {
    return is_syscall(cps, input);
  } else if (r_str_eq(input, "ps?")) {
    r_core_cmd_help(core, help_msg_p);
    return false;
  } else if (r_str_eq(input, "psy?")) {
    r_core_cmd_help(core, help_msg_p);
    return true;
  }
  return false;
}

// PLUGIN Definition Info
RCorePlugin r_core_plugin_sysreader = {
    .meta =
        {
            .name = "sysreader",
            .desc = "Reads symbols at runtime to give you syscall names and "
                    "arguments",
            .author = "Fredd0Bangz",
            .license = "MIT",
        },
    .call = read_sys_call,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {.type = R_LIB_TYPE_CORE,
                                  .data = &r_core_plugin_sysreader,
                                  .version = R2_VERSION,
                                  .abiversion = R2_ABIVERSION};
#endif
